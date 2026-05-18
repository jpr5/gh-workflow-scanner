#!/usr/bin/env ruby

require "optparse"
require "json"
require "yaml"
require "securerandom"
require "uri"
require "time"
require_relative "../lib/scanner"
require_relative "../lib/auto_fix"
require_relative "../lib/sha_resolver"
require_relative "config"
require_relative "github_app_auth"
require_relative "search"
require_relative "state"
require_relative "pr_writer"
require_relative "queue"
require_relative "audit"
require_relative "sync"

module Bot
    class ScannerBot
        def initialize(token: nil, pattern: "rotate", dry_run: false, limit: nil, queue_mode: false)
            if ENV["GITHUB_APP_ID"] && ENV["GITHUB_APP_PRIVATE_KEY"]
                @auth = GitHubAppAuth.new
                @token = token || ENV["GITHUB_TOKEN"]
                $stderr.puts "Using GitHub App authentication (sentinel-ci-scanner)"
            else
                @auth = nil
                @token = token || ENV["GITHUB_TOKEN"]
                $stderr.puts "Using PAT authentication"
            end

            # Search and scanner always use the PAT (GitHub Code Search requires user auth)
            @search = Search.new(token: @token)
            @state = State.new
            @pr_writer = PrWriter.new(token: @token)
            @queue = Queue.new
            @scanner = build_scanner
            @pattern = pattern
            @dry_run = dry_run
            @queue_mode = queue_mode
            @limit = limit
            @audit = Audit.new
            @summary = { scanned: 0, findings: 0, prs_opened: 0, queued: 0, skipped: 0, errors: 0 }
        end

        def run
            sync_pr_statuses

            query = select_query
            @audit.run_start(query[:pattern], @dry_run, @limit)
            $stderr.puts "Bot run: pattern=#{query[:pattern]} dry_run=#{@dry_run}"
            $stderr.puts "Query: #{query[:query]}"

            candidates = @search.find_candidates(query)
            $stderr.puts "Found #{candidates.length} candidate repos"

            candidates.each do |repo|
                break if @limit && @summary[:scanned] >= @limit

                if @state.rate_limit_reached?
                    @audit.skip(repo[:full_name], "rate_limit_reached")
                    $stderr.puts "Daily PR limit reached (#{Config::MAX_PRS_PER_DAY}), stopping"
                    break
                end

                if @state.already_processed?(repo[:full_name], query[:pattern])
                    @audit.skip(repo[:full_name], "already_processed")
                    @summary[:skipped] += 1
                    next
                end

                if @state.opted_out?(repo[:full_name])
                    @audit.skip(repo[:full_name], "opted_out")
                    @summary[:skipped] += 1
                    next
                end

                scan_and_fix(repo, query[:pattern])
            end

            @state.save

            # Automatic backup (non-fatal)
            if ENV["GITHUB_TOKEN"] && (ENV["SENTINEL_BACKUP_GIST_ID"] || ENV["SENTINEL_BACKUP_AUTO"])
                begin
                    require_relative "backup"
                    backup = Backup.new(token: ENV["GITHUB_TOKEN"], state_path: @state.instance_variable_get(:@path))
                    backup.save
                rescue => e
                    $stderr.puts "Backup failed (non-fatal): #{e.message}"
                end
            end

            @audit.run_end(@summary)
            print_summary
        end

        private

        def repo_requires_dco?(repo_name)
            gh_client = GitHubClient.new(token: @token)

            # Check for DCO GitHub App config
            dco_config = gh_client.file_exists?(repo_name, ".github/dco.yml")
            return true if dco_config

            # Check CONTRIBUTING.md for DCO references
            contributing = gh_client.fetch_file_content(repo_name, "CONTRIBUTING.md")
            return true if contributing&.match?(/DCO|sign.off|Signed-off-by/i)

            # Check CONTRIBUTING (no extension)
            contributing = gh_client.fetch_file_content(repo_name, "CONTRIBUTING")
            return true if contributing&.match?(/DCO|sign.off|Signed-off-by/i)

            false
        end

        def build_scanner
            formatter = Formatter::Json.new
            Scanner.new(client: GitHubClient.new(token: @token), formatter: formatter, min_severity: :critical)
        end

        # Per-repo token: prefer GitHub App installation token, fall back to PAT
        def pr_token_for(repo)
            if @auth
                @auth.token_for(repo) || @token
            else
                @token
            end
        end

        def scan_and_fix(repo, pattern)
            $stderr.puts "Scanning #{repo[:full_name]} (#{repo[:stars]} stars)..."
            @audit.scan(repo[:full_name], 0) # initial scan entry; updated below with findings count
            @summary[:scanned] += 1

            begin
                result = @scanner.scan(repo[:full_name])
                findings = result[:findings]
            rescue => e
                @audit.error(repo[:full_name], e.message)
                $stderr.puts "  Error scanning: #{e.message}"
                @summary[:errors] += 1
                return
            end

            # Skip repos that already use Sentinel
            gh_client = GitHubClient.new(token: @token)
            sentinel_config = gh_client.file_exists?(repo[:full_name], ".github/.sentinel-ci.yml")
            workflows = gh_client.fetch_workflows(repo[:full_name])
            sentinel_workflow = workflows.any? { |w| w[:content]&.match?(/uses:\s*jpr5\/sentinel/) }
            if sentinel_config || sentinel_workflow
                @audit.skip(repo[:full_name], "already_uses_sentinel")
                $stderr.puts "  Already uses Sentinel, skipping"
                @summary[:skipped] += 1
                return
            end

            # Filter to critical/high findings matching fixable rules
            critical_findings = findings.select { |f|
                Config::CRITICAL_RULES.include?(f.rule) && (f.critical? || f.high?)
            }

            @state.record_scan(repo[:full_name], critical_findings)

            if critical_findings.empty?
                $stderr.puts "  No critical findings"
                return
            end

            @summary[:findings] += critical_findings.length
            $stderr.puts "  Found #{critical_findings.length} critical findings"

            # Check for opt-out file
            if gh_client.file_exists?(repo[:full_name], Config::OPT_OUT_FILE)
                opt_out_content = gh_client.fetch_file_content(repo[:full_name], Config::OPT_OUT_FILE)
                if opt_out_content
                    begin
                        opt_out_config = YAML.safe_load(opt_out_content)
                        if opt_out_config.is_a?(Hash) && opt_out_config["enabled"] == false
                            @audit.skip(repo[:full_name], "opt_out_file")
                            $stderr.puts "  Repo has opted out"
                            @state.record_opt_out(repo[:full_name])
                            @summary[:skipped] += 1
                            return
                        end
                    rescue
                        # Ignore YAML parse errors in opt-out file
                    end
                end
            end

            # Collect all fixes into one PR
            sha_resolver = ShaResolver.new(token: @token)

            signoff = if repo_requires_dco?(repo[:full_name])
                Config::SIGNOFF_IDENTITY
            else
                nil
            end

            fixed_files = {}
            fixed_findings = []    # findings that were auto-fixed
            advisory_findings = [] # findings that need manual review

            critical_findings.group_by(&:file).each do |file, file_findings|
                content = gh_client.fetch_file_content(repo[:full_name], ".github/workflows/#{file}")
                next unless content

                patched = content
                file_findings.sort_by { |f| -(f.line || 0) }.each do |finding|
                    if AutoFix.can_fix?(finding)
                        result = AutoFix.apply(finding, patched, sha_resolver: sha_resolver)
                        if result && result != patched
                            patched = result
                            fixed_findings << finding
                        else
                            advisory_findings << finding
                        end
                    else
                        advisory_findings << finding
                    end
                end

                if patched != content
                    fixed_files[".github/workflows/#{file}"] = patched
                end
            end

            # Nothing to do
            if fixed_files.empty? && advisory_findings.empty?
                $stderr.puts "  No actionable findings"
                return
            end

            # Build consolidated PR
            total = fixed_findings.length + advisory_findings.length
            branch = "sentinel/security-fixes"
            title = "Security: Fix #{total} finding#{"s" if total != 1} in GitHub Actions workflows"

            body = build_consolidated_pr_body(
                repo: repo[:full_name],
                fixed_findings: fixed_findings,
                advisory_findings: advisory_findings
            )

            if @dry_run
                $stderr.puts "  [DRY RUN] Would create consolidated PR: #{title}"
                fixed_findings.each { |f| $stderr.puts "    [fix] #{f.file}:#{f.line} #{f.rule}" }
                advisory_findings.each { |f| $stderr.puts "    [advisory] #{f.file}:#{f.line} #{f.rule}" }
                return
            end

            if @queue_mode
                all_findings = fixed_findings + advisory_findings
                @queue.add(
                    repo: repo[:full_name],
                    title: title,
                    body: body,
                    files: fixed_files.empty? ? advisory_only_files(advisory_findings) : fixed_files,
                    findings: all_findings,
                    signoff: signoff
                )
                @queue.save
                @audit.log("QUEUED", repo: repo[:full_name], details: "title=#{title}")
                $stderr.puts "  Queued for review: #{title}"
                @summary[:queued] += 1
                return
            end

            repo_token = pr_token_for(repo[:full_name])
            writer = PrWriter.new(token: repo_token)
            pr = writer.create_pr(
                repo: repo[:full_name],
                branch: branch,
                title: title,
                body: body,
                files: fixed_files.empty? ? advisory_only_files(advisory_findings) : fixed_files,
                signoff: signoff
            )

            if pr
                @audit.pr_created(repo[:full_name], pr["html_url"])
                $stderr.puts "  Opened PR: #{pr["html_url"]}"
                # Record one PR per rule for state tracking
                (fixed_findings + advisory_findings).map(&:rule).uniq.each do |rule|
                    @state.record_pr(repo[:full_name], pr["html_url"], rule, pr["number"])
                end
                @summary[:prs_opened] += 1
            else
                @audit.pr_failed(repo[:full_name], "create_pr_returned_nil")
                $stderr.puts "  Failed to create PR"
                @summary[:errors] += 1
            end
        end

        def build_consolidated_pr_body(repo:, fixed_findings:, advisory_findings:)
            opt_out_token = generate_token(repo, "opt-out")
            adopt_token = generate_token(repo, "adopt")
            encoded_repo = URI.encode_www_form_component(repo)
            opt_out_url = "#{Config::BOT_URL}/opt-out?repo=#{encoded_repo}&token=#{opt_out_token}"
            adopt_url = "#{Config::BOT_URL}/adopt?repo=#{encoded_repo}&token=#{adopt_token}"

            total = fixed_findings.length + advisory_findings.length
            rules_hit = (fixed_findings + advisory_findings).map(&:rule).uniq

            body = "## Security: #{total} finding#{"s" if total != 1} across #{rules_hit.length} rule#{"s" if rules_hit.length != 1}\n\n"

            if fixed_findings.any?
                body += "### Fixed (deterministic, no AI)\n\n"
                fixed_findings.group_by(&:rule).each do |rule, findings|
                    body += "**#{rule}** — [What is this?](#{Config::BOT_URL}/rules/#{rule})\n"
                    findings.each { |f| body += "- `#{f.file}` line #{f.line}: #{f.message}\n" }
                    body += "\n"
                end
            end

            if advisory_findings.any?
                body += "### Requires manual review\n\n"
                advisory_findings.group_by(&:rule).each do |rule, findings|
                    body += "**#{rule}** — [What is this?](#{Config::BOT_URL}/rules/#{rule})\n"
                    findings.each do |f|
                        body += "- `#{f.file}` line #{f.line}: #{f.message}\n"
                        body += "  - Fix: #{f.fix}\n" if f.fix
                    end
                    body += "\n"
                end
            end

            body += "### How this was detected\n\n"
            body += "This finding was identified by deterministic pattern matching — no AI or machine learning "
            body += "was used in the detection. Sentinel uses static analysis rules that match known-vulnerable "
            body += "YAML patterns against a database of documented exploit vectors. Every finding maps to a "
            body += "specific, reproducible pattern. [Source code](https://github.com/jpr5/sentinel) is open for inspection.\n\n"

            body += "---\n"
            body += "<sub>&#x1f6e1;&#xfe0f; This PR was generated by [Sentinel](https://sentinel.copilotkit.dev), "
            body += "an open-source security scanner. "
            body += "[Why this PR?](https://medium.com/@jordanritter/security-hardening-github-workflows-at-scale-d291a33774e1) · "
            body += "Free, no tracking</sub>\n\n"
            body += "[&#x2705; Add Sentinel to this repo](#{adopt_url}) · "
            body += "[&#x1f6ab; Opt out of future PRs](#{opt_out_url})\n"

            body
        end

        def advisory_only_files(findings)
            content = "# Security Advisory\n\n"
            content += "Sentinel detected #{findings.length} security finding#{"s" if findings.length != 1} "
            content += "in your GitHub Actions workflows that require manual review.\n\n"

            findings.group_by(&:rule).each do |rule, rule_findings|
                content += "## #{rule}\n\n"
                rule_findings.each do |f|
                    content += "### #{f.file} (line #{f.line})\n\n"
                    content += "**Severity:** #{f.severity}\n"
                    content += "**Issue:** #{f.message}\n"
                    content += "**Fix:** #{f.fix}\n\n" if f.fix
                end
            end

            { ".github/SECURITY_ADVISORY.md" => content }
        end

        def generate_token(repo, action)
            token = SecureRandom.uuid
            @state.record_token(token, repo, action)
            token
        end

        def select_query
            queries = Config::SEARCH_QUERIES

            if @pattern == "rotate"
                # Rotate through queries based on day-of-week
                index = Time.now.wday % queries.length
                queries[index]
            else
                match = queries.find { |q| q[:pattern] == @pattern }
                match || queries.find { |q| q[:pattern].start_with?(@pattern) } || queries.first
            end
        end

        def sync_pr_statuses
            sync = Sync.new(token: @token, state: @state)
            result = sync.sync_all
            $stderr.puts "Pre-scan sync: #{result[:synced]} PRs checked, #{result[:updated]} updated"
        rescue => e
            $stderr.puts "PR sync failed (non-fatal): #{e.message}"
        end

        def print_summary
            s = @summary
            $stderr.puts
            $stderr.puts "=== Bot Run Summary ==="
            $stderr.puts "  Repos scanned: #{s[:scanned]}"
            $stderr.puts "  Critical findings: #{s[:findings]}"
            $stderr.puts "  PRs opened: #{s[:prs_opened]}"
            $stderr.puts "  Queued for review: #{s[:queued]}" if s[:queued] > 0
            $stderr.puts "  Skipped (processed/opted-out): #{s[:skipped]}"
            $stderr.puts "  Errors: #{s[:errors]}"

            state_summary = @state.summary
            $stderr.puts
            $stderr.puts "  Lifetime: #{state_summary[:total_repos]} repos tracked, " \
                "#{state_summary[:total_prs]} PRs opened, #{state_summary[:opt_outs]} opt-outs"
            $stderr.puts "  Today: #{state_summary[:prs_today]}/#{Config::MAX_PRS_PER_DAY} PRs"
        end
    end
end

def format_time_pacific(iso_string)
    return "-" unless iso_string
    utc = Time.parse(iso_string).utc
    # Determine if PDT or PST applies using US DST rules
    # DST: second Sunday in March to first Sunday in November
    year = utc.year
    mar_second_sun = Time.utc(year, 3, 8) + ((7 - Time.utc(year, 3, 8).wday) % 7) * 86400
    nov_first_sun = Time.utc(year, 11, 1) + ((7 - Time.utc(year, 11, 1).wday) % 7) * 86400
    # DST transitions at 2:00 AM local = 10:00 AM UTC (PDT start) / 9:00 AM UTC (PST start)
    pdt_start = mar_second_sun + 10 * 3600
    pst_start = nov_first_sun + 9 * 3600
    offset = (utc >= pdt_start && utc < pst_start) ? "-07:00" : "-08:00"
    t = utc.getlocal(offset)
    hour = t.hour % 12
    hour = 12 if hour == 0
    ampm = t.hour < 12 ? "a" : "p"
    t.strftime("%b %-d ") + "#{hour}:#{"%02d" % t.min}#{ampm}"
end

STATUS_SORT_ORDER = { "blocked" => 0, "open" => 1, "closed" => 2, "merged" => 3 }.freeze

def print_dashboard(state)
    prs = state.all_tracked_prs

    if prs.empty?
        puts "No tracked PRs. Run --bootstrap to seed from GitHub."
        return
    end

    # Sort by status priority (blocked, open, closed, merged),
    # then by last_updated_at descending within each group
    prs.sort! { |a, b|
        sa = STATUS_SORT_ORDER.fetch(a[:pr]["status"] || "open", 99)
        sb = STATUS_SORT_ORDER.fetch(b[:pr]["status"] || "open", 99)
        if sa != sb
            sa <=> sb
        else
            (b[:pr]["last_updated_at"] || "") <=> (a[:pr]["last_updated_at"] || "")
        end
    }

    puts "Sentinel PR Tracker"
    puts

    # Column widths
    repo_w = [prs.map { |e| e[:repo].length }.max, 4].max
    pr_w = [prs.map { |e| "##{e[:pr]["number"]}".length }.max, 2].max
    status_w = [prs.map { |e| (e[:pr]["status"] || "open").length }.max, 6].max
    time_w = 16

    header = "%-#{repo_w}s  %-#{pr_w}s  %-#{status_w}s  %-#{time_w}s  %-#{time_w}s  %s" %
        ["REPO", "PR", "STATUS", "CREATED", "UPDATED", "NOTE"]
    puts header
    puts "─" * [header.length, 80].max

    prs.each do |entry|
        repo = entry[:repo]
        pr = entry[:pr]
        pr_num = "##{pr["number"]}"
        status = pr["status"] || "open"
        created = format_time_pacific(pr["created_at"])
        updated = format_time_pacific(pr["last_updated_at"])
        note = pr["note"] || ""

        line = "%-#{repo_w}s  %-#{pr_w}s  %-#{status_w}s  %-#{time_w}s  %-#{time_w}s" %
            [repo, pr_num, status, created, updated]
        line += "  #{note}" unless note.empty?
        puts line
    end

    # Summary counts
    counts = Hash.new(0)
    prs.each { |e| counts[e[:pr]["status"] || "open"] += 1 }
    summary_parts = ["merged", "open", "blocked", "closed"]
        .select { |s| counts[s] > 0 }
        .map { |s| "#{counts[s]} #{s}" }
    puts
    puts "Summary: #{summary_parts.join(", ")}"
end

# CLI entry point
if __FILE__ == $0
    options = { pattern: "rotate", dry_run: true, limit: nil }

    OptionParser.new do |opts|
        opts.banner = "Usage: ruby bot/scanner_bot.rb [options]"
        opts.separator ""
        opts.separator "Scan popular repos and open fix PRs for critical findings."
        opts.separator ""

        opts.on("--pattern PATTERN", "Vulnerability pattern to search (default: rotate)") do |p|
            options[:pattern] = p
        end

        opts.on("--dry-run", "Don't create PRs, just log what would happen") do
            options[:dry_run] = true
        end

        opts.on("--queue", "Generate fixes and queue for review (don't submit PRs)") do
            options[:queue] = true
        end

        opts.on("--review", "Review pending approval queue") do
            options[:review] = true
        end

        opts.on("--approve ID", "Approve and submit a queued PR") do |id|
            options[:approve] = id
        end

        opts.on("--reject ID", "Reject a queued PR") do |id|
            options[:reject] = id
        end

        opts.on("--reason REASON", "Reason for rejection (use with --reject)") do |r|
            options[:reason] = r
        end

        opts.on("--dashboard", "Show PR lifecycle dashboard") do
            options[:dashboard] = true
        end

        opts.on("--sync", "Sync PR statuses from GitHub") do
            options[:sync] = true
        end

        opts.on("--bootstrap", "Discover and track existing Sentinel PRs from GitHub") do
            options[:bootstrap] = true
        end

        opts.on("--backup", "Manually trigger a state backup to GitHub Gist") do
            options[:backup] = true
        end

        opts.on("--restore", "Restore state from backup gist") do
            options[:restore] = true
        end

        opts.on("--limit N", Integer, "Max repos to scan (default: unlimited)") do |n|
            options[:limit] = n
        end

        opts.on("-h", "--help", "Show this help message") do
            puts opts
            exit 0
        end
    end.parse!

    # Queue management commands don't need a GitHub token
    if options[:review]
        queue = Bot::Queue.new
        pending = queue.pending
        if pending.empty?
            puts "No pending PRs in the queue."
        else
            puts "Pending PRs (#{pending.length}):"
            puts
            pending.each do |item|
                id_short = item["id"][0, 8]
                findings_summary = item["findings"].map { |f| "  #{f["rule"]}: #{f["file"]}:#{f["line"]}" }
                puts "[#{id_short}] #{item["repo"]} — #{item["title"]}"
                findings_summary.each { |line| puts line }
                puts "  Queued: #{item["queued_at"]}"
                puts
            end
            puts "sentinel bot --approve <id>"
            puts "sentinel bot --reject <id> --reason \"reason\""
        end
        exit 0
    end

    if options[:approve]
        id = options[:approve]
        queue = Bot::Queue.new

        # Support short IDs (prefix match)
        match = queue.pending.find { |i| i["id"].start_with?(id) }
        unless match
            abort("No pending item found matching '#{id}'")
        end

        token = ENV["GITHUB_TOKEN"]
        unless token || (ENV["GITHUB_APP_ID"] && ENV["GITHUB_APP_PRIVATE_KEY"])
            abort("Either GITHUB_TOKEN or GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY required")
        end

        item = queue.approve(match["id"])
        queue.save

        audit = Bot::Audit.new
        audit.log("QUEUE_APPROVE", repo: item["repo"], details: "id=#{match["id"][0, 8]}")

        writer = Bot::PrWriter.new(token: token)
        pr = writer.create_pr(
            repo: item["repo"],
            branch: "sentinel/security-fixes",
            title: item["title"],
            body: item["body"],
            files: item["files"],
            signoff: item["signoff"]
        )

        if pr
            audit.pr_created(item["repo"], pr["html_url"])
            puts "PR created: #{pr["html_url"]}"
            state = Bot::State.new
            item["findings"].each do |f|
                state.record_pr(item["repo"], pr["html_url"], f["rule"], pr["number"])
            end
            state.save
        else
            audit.pr_failed(item["repo"], "create_pr_returned_nil")
            $stderr.puts "Failed to create PR for #{item["repo"]}"
            exit 1
        end
        exit 0
    end

    if options[:reject]
        id = options[:reject]
        queue = Bot::Queue.new

        # Support short IDs (prefix match)
        match = queue.pending.find { |i| i["id"].start_with?(id) }
        unless match
            abort("No pending item found matching '#{id}'")
        end

        item = queue.reject(match["id"], reason: options[:reason])
        queue.save
        audit = Bot::Audit.new
        audit.log("QUEUE_REJECT", repo: item["repo"], details: "id=#{match["id"][0, 8]} reason=#{options[:reason] || 'none'}")
        puts "Rejected: [#{match["id"][0, 8]}] #{item["repo"]} — #{item["title"]}"
        puts "  Reason: #{options[:reason]}" if options[:reason]
        exit 0
    end

    if options[:dashboard]
        state = Bot::State.new
        print_dashboard(state)
        exit 0
    end

    if options[:sync]
        token = ENV["GITHUB_TOKEN"]
        abort("GITHUB_TOKEN required for sync") unless token
        state = Bot::State.new
        sync = Bot::Sync.new(token: token, state: state)
        result = sync.sync_all
        state.save
        print_dashboard(state)
        exit 0
    end

    if options[:bootstrap]
        require_relative "bootstrap"
        token = ENV["GITHUB_TOKEN"]
        abort("GITHUB_TOKEN required for bootstrap") unless token
        state = Bot::State.new
        bootstrap = Bot::Bootstrap.new(token: token, state: state)
        bootstrap.run
        state.save
        print_dashboard(state)
        exit 0
    end

    if options[:backup]
        token = ENV["GITHUB_TOKEN"]
        abort("GITHUB_TOKEN required for backup") unless token
        require_relative "backup"
        backup = Bot::Backup.new(token: token)
        success = backup.save
        exit(success ? 0 : 1)
    end

    if options[:restore]
        token = ENV["GITHUB_TOKEN"]
        abort("GITHUB_TOKEN required for restore") unless token
        require_relative "backup"
        backup = Bot::Backup.new(token: token)
        success = backup.restore
        exit(success ? 0 : 1)
    end

    token = ENV["GITHUB_TOKEN"]
    unless token || (ENV["GITHUB_APP_ID"] && ENV["GITHUB_APP_PRIVATE_KEY"])
        abort("Either GITHUB_TOKEN or GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY required")
    end
    Bot::ScannerBot.new(token: token, pattern: options[:pattern], dry_run: options[:dry_run], limit: options[:limit], queue_mode: options[:queue]).run
end

# TEMPORARY KILL SWITCH — remove when bot is ready for production
# Added 2026-05-18 after uncontrolled PR spam incident
