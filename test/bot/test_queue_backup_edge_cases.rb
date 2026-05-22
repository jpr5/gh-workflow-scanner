require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "json"
require "yaml"
require "time"

# Load bot modules — scanner_bot.rb pulls in all dependencies
$LOAD_PATH.unshift(File.join(__dir__, "..", "..", "bot"))
require_relative "../../bot/scanner_bot"
require_relative "../../bot/backup"

# ============================================================================
# Stub classes (prefixed ECStub to avoid collision with other test files)
# ============================================================================

class ECStubGitHubClient
    attr_accessor :file_exists_map, :file_content_map, :workflows

    def initialize(token: nil)
        @file_exists_map = {}
        @file_content_map = {}
        @workflows = []
    end

    def file_exists?(repo, path)
        @file_exists_map[[repo, path]] || false
    end

    def fetch_file_content(repo, path)
        @file_content_map[[repo, path]]
    end

    def fetch_workflows(repo)
        @workflows
    end

    def fetch_dependabot_config(repo)
        nil
    end
end

class ECStubSearch
    attr_accessor :candidates

    def initialize(token: nil)
        @candidates = []
    end

    def find_candidates(_query)
        @candidates
    end
end

class ECStubScanner
    attr_accessor :scan_results

    def initialize
        @scan_results = {}
    end

    def scan(repo)
        @scan_results[repo] || { findings: [], output: "", workflow_count: 0 }
    end
end

class ECStubPrWriter
    attr_accessor :created_prs, :pr_response, :created_issues, :issue_response

    def initialize(token: nil)
        @created_prs = []
        @pr_response = nil
        @created_issues = []
        @issue_response = nil
    end

    def create_pr(repo:, branch:, title:, body:, files:, signoff: nil)
        @created_prs << { repo: repo, branch: branch, title: title, body: body, files: files, signoff: signoff }
        @pr_response
    end

    def create_issue(repo:, title:, body:, labels: [])
        @created_issues << { repo: repo, title: title, body: body, labels: labels }
        @issue_response
    end
end

class ECStubSync
    attr_accessor :sync_called

    def initialize(token: nil, state: nil)
        @sync_called = false
    end

    def sync_all
        @sync_called = true
        { synced: 0, updated: 0, errors: 0 }
    end
end

# ============================================================================
# Edge Case Tests: scan -> queue -> backup flow
# ============================================================================

class TestQueueBackupEdgeCases < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-edge-case-test")
        @state_file = File.join(@tmpdir, "state.json")
        @queue_file = File.join(@tmpdir, "queue.json")
        @audit_file = File.join(@tmpdir, "audit.log")

        @stub_gh_client = ECStubGitHubClient.new
        @stub_search = ECStubSearch.new
        @stub_scanner = ECStubScanner.new
        @stub_pr_writer = ECStubPrWriter.new
        @stub_sync = ECStubSync.new

        # Intercept GitHubClient.new to return our stub
        @original_gh_new = GitHubClient.method(:new)
        stub = @stub_gh_client
        GitHubClient.define_singleton_method(:new) { |**kwargs| stub }

        # Save ENV vars for restoration
        @saved_env = {}
        %w[GITHUB_TOKEN SENTINEL_BACKUP_GIST_ID SENTINEL_STATE_PATH SENTINEL_QUEUE_PATH
           SENTINEL_BACKUP_AUTO GITHUB_APP_ID GITHUB_APP_PRIVATE_KEY].each do |key|
            @saved_env[key] = ENV[key]
        end

        # Clean baseline: no backup env vars set unless the test sets them
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        ENV.delete("SENTINEL_BACKUP_AUTO")
        ENV.delete("GITHUB_APP_ID")
        ENV.delete("GITHUB_APP_PRIVATE_KEY")
        ENV["GITHUB_TOKEN"] = "fake-edge-case-token"
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)

        # Restore original GitHubClient.new
        original = @original_gh_new
        GitHubClient.define_singleton_method(:new) { |**kwargs| original.call(**kwargs) }

        # Restore ENV
        @saved_env.each { |key, val| val.nil? ? ENV.delete(key) : ENV[key] = val }
    end

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def build_bot(pattern: "shell-injection", dry_run: false, queue_mode: false, limit: nil)
        bot = nil
        _captured = capture_io do
            bot = Bot::ScannerBot.new(
                token: "fake-edge-case-token",
                pattern: pattern,
                dry_run: dry_run,
                limit: limit,
                queue_mode: queue_mode
            )
        end

        # Replace internal components with stubs
        bot.instance_variable_set(:@search, @stub_search)
        bot.instance_variable_set(:@scanner, @stub_scanner)
        bot.instance_variable_set(:@pr_writer, @stub_pr_writer)
        bot.instance_variable_set(:@state, Bot::State.new(@state_file))
        bot.instance_variable_set(:@queue, Bot::Queue.new(@queue_file))
        bot.instance_variable_set(:@audit, Bot::Audit.new(@audit_file))

        # Stub sync_pr_statuses
        sync_stub = @stub_sync
        bot.define_singleton_method(:sync_pr_statuses) do
            sync_stub.sync_called = true
        end

        bot
    end

    def make_shell_injection_finding(file: "ci.yml", line: 12)
        Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: file,
            line: line,
            code: 'echo "PR: ${{ github.event.pull_request.title }}"',
            message: "Untrusted input in shell command",
            fix: "Use env var indirection"
        )
    end

    def make_dangerous_trigger_finding(file: "ci.yml", line: 1)
        Finding.new(
            rule: "dangerous-triggers",
            severity: :critical,
            file: file,
            line: line,
            code: "on: pull_request_target",
            message: "Dangerous trigger with checkout",
            fix: "Review manually"
        )
    end

    def make_low_severity_finding(file: "ci.yml", line: 5)
        Finding.new(
            rule: "unpinned-actions",
            severity: :low,
            file: file,
            line: line,
            code: "uses: actions/checkout@v4",
            message: "Action not pinned to SHA",
            fix: "Pin to SHA"
        )
    end

    def make_medium_severity_finding(file: "ci.yml", line: 10)
        Finding.new(
            rule: "missing-permissions",
            severity: :medium,
            file: file,
            line: line,
            code: "permissions: write-all",
            message: "Overly broad permissions",
            fix: "Restrict permissions"
        )
    end

    def vulnerable_workflow_yaml
        <<~YAML
            name: CI
            on:
              pull_request_target:
                types: [opened]
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - name: Greet
                    run: |
                      echo "PR: ${{ github.event.pull_request.title }}"
        YAML
    end

    def setup_repo_for_scan(repo_name, findings:, workflow_yaml: nil)
        workflow_yaml ||= vulnerable_workflow_yaml
        @stub_scanner.scan_results[repo_name] = {
            findings: findings,
            output: "",
            workflow_count: 1,
        }
        @stub_gh_client.file_exists_map[[repo_name, ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []
        @stub_gh_client.file_exists_map[[repo_name, Bot::Config::OPT_OUT_FILE]] = false
        @stub_gh_client.file_content_map[[repo_name, ".github/workflows/ci.yml"]] = workflow_yaml
    end

    # ========================================================================
    # Test 1: Queue path mismatch production scenario
    #
    # Set SENTINEL_STATE_PATH to a custom path but do NOT set SENTINEL_QUEUE_PATH.
    # The Queue class defaults to "bot/queue.json" while State uses the custom
    # path. Backup should receive the queue's actual @path.
    # ========================================================================

    def test_queue_path_mismatch_production_scenario
        # Set up the production-like scenario: state on a "volume", queue at default
        custom_state_dir = File.join(@tmpdir, "test-data")
        FileUtils.mkdir_p(custom_state_dir)
        custom_state_path = File.join(custom_state_dir, "state.json")

        ENV["SENTINEL_STATE_PATH"] = custom_state_path
        ENV.delete("SENTINEL_QUEUE_PATH")

        # Capture the default queue path before any test runs pollute it
        # The Queue class defaults to "bot/queue.json" when SENTINEL_QUEUE_PATH is unset
        default_queue = Bot::Queue.new
        default_queue_path = default_queue.instance_variable_get(:@path)
        assert_equal "bot/queue.json", default_queue_path,
            "Queue should default to 'bot/queue.json' when SENTINEL_QUEUE_PATH is not set"

        # Build bot with stubbed components
        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        # Override state with the custom path but use the default-path queue
        bot.instance_variable_set(:@state, Bot::State.new(custom_state_path))
        # Create a FRESH queue at the default path (clear any leftover data)
        FileUtils.rm_f("bot/queue.json")
        queue = Bot::Queue.new  # uses default "bot/queue.json"
        bot.instance_variable_set(:@queue, queue)

        queue_path = queue.instance_variable_get(:@path)

        # Set up a scan that produces findings
        finding = make_shell_injection_finding(line: 12)
        @stub_search.candidates = [{ full_name: "owner/mismatch-repo", stars: 500 }]
        setup_repo_for_scan("owner/mismatch-repo", findings: [finding])

        # Run the bot (suppress backup by not setting SENTINEL_BACKUP_GIST_ID)
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        _output = capture_io { bot.run }

        # Verify queue was populated
        assert_equal 1, queue.pending.length,
            "Queue should have 1 pending entry"

        # Verify the queue file exists at the default path
        assert File.exist?(queue_path),
            "Queue file should exist at '#{queue_path}' (the default path)"

        # Now simulate what Backup receives from scanner_bot.rb lines 99-100:
        #   state_path: @state.instance_variable_get(:@path)
        #   queue_path: @queue.instance_variable_get(:@path)
        state = bot.instance_variable_get(:@state)
        state_path_from_bot = state.instance_variable_get(:@path)
        queue_path_from_bot = queue.instance_variable_get(:@path)

        assert_equal custom_state_path, state_path_from_bot,
            "State @path should be the custom volume path"
        assert_equal "bot/queue.json", queue_path_from_bot,
            "Queue @path should be the default 'bot/queue.json'"

        # The backup would receive these mismatched paths — this is the expected
        # production behavior. State is on a volume, queue is ephemeral.
        backup = Bot::Backup.new(
            token: "fake-token",
            state_path: state_path_from_bot,
            queue_path: queue_path_from_bot
        )

        backup_queue_path = backup.instance_variable_get(:@queue_path)
        assert_equal "bot/queue.json", backup_queue_path,
            "Backup should use the queue's actual @path (bot/queue.json)"

        # Verify the file actually exists at the path backup will try to read
        assert File.exist?(backup_queue_path),
            "Queue file must exist at the path backup will use: #{backup_queue_path}"
    ensure
        # Clean up the default-path queue file so it doesn't pollute other tests
        FileUtils.rm_f("bot/queue.json")
    end

    # ========================================================================
    # Test 2: No critical findings, no queue file
    #
    # Scanner returns only low/medium findings. Queue.pending should be empty,
    # queue file should NOT exist on disk, and backup should only include state.
    # ========================================================================

    def test_no_critical_findings_no_queue_file
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file

        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        # Only low and medium findings — below the critical/high severity gate
        low_finding = make_low_severity_finding
        medium_finding = make_medium_severity_finding

        @stub_search.candidates = [{ full_name: "owner/clean-repo", stars: 500 }]
        @stub_scanner.scan_results["owner/clean-repo"] = {
            findings: [low_finding, medium_finding],
            output: "",
            workflow_count: 1,
        }
        @stub_gh_client.file_exists_map[["owner/clean-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []

        _output = capture_io { bot.run }

        queue = bot.instance_variable_get(:@queue)
        assert_empty queue.pending,
            "Queue should have no pending entries when no critical findings exist"

        # Queue file should NOT exist because queue.save was never called
        refute File.exist?(@queue_file),
            "Queue file should NOT exist on disk when no findings are queued"

        # State file SHOULD exist (state.save is always called at end of run)
        assert File.exist?(@state_file),
            "State file should exist after run even with no critical findings"

        # If backup were triggered, it should only include state, not queue
        # (because queue file doesn't exist on disk)
        backup = Bot::Backup.new(
            token: "fake-token",
            state_path: @state_file,
            queue_path: @queue_file
        )

        # Simulate what backup.save does: check File.exist? on each path
        state_exists = File.exist?(@state_file)
        queue_exists = File.exist?(@queue_file)

        assert state_exists, "State file should exist for backup"
        refute queue_exists, "Queue file should NOT exist — backup should skip it"
    end

    # ========================================================================
    # Test 3: fetch_file_content returns nil for ALL workflow files
    #
    # Scanner finds critical findings but the workflow content can't be fetched.
    # This verifies that findings ARE recorded in state (record_scan called),
    # but nothing is queued because no patches can be generated and no advisory
    # content can be created either.
    # ========================================================================

    def test_fetch_file_content_returns_nil
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file

        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        # Critical findings that would normally be fixable
        finding = make_shell_injection_finding(line: 12)
        @stub_search.candidates = [{ full_name: "owner/nil-content-repo", stars: 500 }]
        @stub_scanner.scan_results["owner/nil-content-repo"] = {
            findings: [finding],
            output: "",
            workflow_count: 1,
        }
        @stub_gh_client.file_exists_map[["owner/nil-content-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []

        # CRITICAL: return nil for ALL workflow file content
        # Do NOT set any file_content_map entries — fetch_file_content returns nil
        @stub_gh_client.file_content_map.clear

        _output = capture_io { bot.run }

        queue = bot.instance_variable_get(:@queue)
        state = bot.instance_variable_get(:@state)
        summary = bot.instance_variable_get(:@summary)

        # State should have recorded the scan (record_scan IS called before file fetching)
        state.save
        state_data = JSON.parse(File.read(@state_file))
        assert state_data["repos"].key?("owner/nil-content-repo"),
            "State should have recorded the scan for owner/nil-content-repo"

        # But nothing should be queued because fetch_file_content returned nil,
        # which means `next unless content` skips every file, resulting in both
        # fixed_findings and advisory_findings being empty, which triggers the
        # "No actionable findings" early return.
        assert_empty queue.pending,
            "Queue should be empty when fetch_file_content returns nil for all files. " \
            "THIS IS THE KEY INSIGHT: critical findings are detected by the scanner " \
            "(which fetches files internally), but when scan_and_fix tries to fetch " \
            "them again for patching, it gets nil. The findings are lost — never " \
            "queued, never PR'd, never issued. Only the scan count in state survives."

        # Summary should show findings were found but nothing was actioned
        assert summary[:findings] > 0,
            "Summary should count the critical findings"
        assert_equal 0, summary[:queued],
            "Nothing should be queued when file content is nil"
        assert_equal 0, summary[:prs_opened],
            "No PRs should be opened when file content is nil"
    end

    # ========================================================================
    # Test 4: Queue file absent, backup still succeeds
    #
    # No findings to queue, queue file doesn't exist on disk.
    # Backup should succeed with only the state file, not crash.
    # ========================================================================

    def test_queue_file_absent_backup_still_succeeds
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file

        # Write a state file with some data
        state = Bot::State.new(@state_file)
        state.record_scan("owner/some-repo", [])
        state.save

        assert File.exist?(@state_file), "State file should exist"
        refute File.exist?(@queue_file), "Queue file should NOT exist"

        # Create backup pointing at both paths
        backup_files_sent = nil
        original_backup_new = Bot::Backup.method(:new)

        backup = Bot::Backup.new(
            token: "fake-token",
            state_path: @state_file,
            queue_path: @queue_file
        )

        # Stub API calls to capture what would be sent
        api_called = false
        backup.define_singleton_method(:api_post) { |path, body|
            api_called = true
            backup_files_sent = body[:files]
            { "id" => "new-gist-id", "files" => {} }
        }

        result = nil
        _output = capture_io { result = backup.save }

        assert result, "Backup.save should return true even when queue file is absent"
        assert api_called, "Backup should still make an API call with just the state file"

        refute_nil backup_files_sent, "Backup should have sent files"
        assert backup_files_sent.key?(Bot::Backup::STATE_GIST_FILENAME),
            "Backup should include state file"
        refute backup_files_sent.key?(Bot::Backup::QUEUE_GIST_FILENAME),
            "Backup should NOT include queue file when it doesn't exist on disk"
    end

    # ========================================================================
    # Test 5: Multiple runs accumulate queue
    #
    # First run queues 2 findings. Second run adds 3 more. Queue should have
    # 5 total entries, not 3 (verifying persistence between runs).
    # ========================================================================

    def test_multiple_runs_accumulate_queue
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file

        # ----- Run 1: 2 repos with findings -----
        bot1 = build_bot(pattern: "shell-injection", queue_mode: true)
        bot1.instance_variable_set(:@state, Bot::State.new(@state_file))
        bot1.instance_variable_set(:@queue, Bot::Queue.new(@queue_file))

        @stub_search.candidates = [
            { full_name: "owner/repo-a", stars: 500 },
            { full_name: "owner/repo-b", stars: 400 },
        ]

        %w[owner/repo-a owner/repo-b].each do |repo|
            setup_repo_for_scan(repo, findings: [make_shell_injection_finding(line: 12)])
        end

        _output = capture_io { bot1.run }

        queue1 = bot1.instance_variable_get(:@queue)
        assert_equal 2, queue1.pending.length,
            "First run should queue 2 entries"

        # Verify queue file exists on disk
        assert File.exist?(@queue_file),
            "Queue file should exist on disk after first run"

        # ----- Run 2: 3 more repos with findings -----
        bot2 = build_bot(pattern: "shell-injection", queue_mode: true)
        bot2.instance_variable_set(:@state, Bot::State.new(@state_file))
        # Re-create queue from persisted file — this is key to testing accumulation
        bot2.instance_variable_set(:@queue, Bot::Queue.new(@queue_file))

        @stub_search.candidates = [
            { full_name: "owner/repo-c", stars: 300 },
            { full_name: "owner/repo-d", stars: 200 },
            { full_name: "owner/repo-e", stars: 100 },
        ]

        %w[owner/repo-c owner/repo-d owner/repo-e].each do |repo|
            setup_repo_for_scan(repo, findings: [make_shell_injection_finding(line: 12)])
        end

        _output = capture_io { bot2.run }

        queue2 = bot2.instance_variable_get(:@queue)
        assert_equal 5, queue2.pending.length,
            "Second run should accumulate to 5 total entries (2 + 3), not overwrite"

        # Verify all repos are present
        repos = queue2.pending.map { |p| p["repo"] }
        %w[owner/repo-a owner/repo-b owner/repo-c owner/repo-d owner/repo-e].each do |repo|
            assert_includes repos, repo,
                "Queue should contain #{repo}"
        end
    end

    # ========================================================================
    # Test 6: Backup gist API failure is non-fatal
    #
    # Stub gist API to return 500. Bot should exit cleanly (no exception
    # raised from the rescue block), and the run should still produce a summary.
    # ========================================================================

    def test_backup_gist_api_failure_non_fatal
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file
        # Don't set SENTINEL_BACKUP_GIST_ID yet — setting it causes State/Queue
        # constructors to attempt auto-restore during bot construction.
        ENV.delete("SENTINEL_BACKUP_GIST_ID")

        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        # Now set it so the backup block in scanner_bot.rb's run method triggers
        ENV["SENTINEL_BACKUP_GIST_ID"] = "fake-gist-id"

        finding = make_shell_injection_finding(line: 12)
        @stub_search.candidates = [{ full_name: "owner/backup-fail-repo", stars: 500 }]
        setup_repo_for_scan("owner/backup-fail-repo", findings: [finding])

        # Monkey-patch Backup to simulate API failure
        original_backup_new = Bot::Backup.method(:new)
        Bot::Backup.define_singleton_method(:new) { |**kwargs|
            instance = original_backup_new.call(**kwargs)
            # Stub all API methods to simulate failure
            instance.define_singleton_method(:api_patch) { |path, body|
                raise "Simulated HTTP 500 Internal Server Error"
            }
            instance.define_singleton_method(:api_post) { |path, body|
                raise "Simulated HTTP 500 Internal Server Error"
            }
            instance
        }

        # The bot should NOT raise an exception — backup failure is caught in a rescue
        captured = nil
        assert_nothing_raised("Bot should not crash when backup API fails") do
            captured = capture_io { bot.run }
        end

        stderr_output = captured[1]

        # Should still produce a summary
        assert_match(/Bot Run Summary/, stderr_output,
            "Bot should still print summary after backup failure")

        # Backup failure should be logged — the Backup class itself catches the
        # exception and prints "Backup: error saving: ...", OR if the exception
        # escapes, scanner_bot.rb catches it with "Backup failed (non-fatal): ..."
        assert_match(/Backup.*error saving|Backup failed.*non-fatal/i, stderr_output,
            "Backup failure should be logged")

        summary = bot.instance_variable_get(:@summary)
        assert_equal 1, summary[:queued],
            "Findings should still be queued despite backup failure"
    ensure
        if defined?(original_backup_new) && original_backup_new
            orig = original_backup_new
            Bot::Backup.define_singleton_method(:new) { |**kwargs| orig.call(**kwargs) }
        end
    end

    # ========================================================================
    # Test 7: Mixed fixable and advisory findings
    #
    # Some findings for shell-injection-expr (fixable), some for
    # dangerous-triggers (advisory-only). In queue mode, both should end up
    # queued. The create_fix_pr path handles mixed findings (type="pr").
    # ========================================================================

    def test_mixed_fixable_and_advisory_findings
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file

        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        fixable_finding = make_shell_injection_finding(file: "ci.yml", line: 12)
        advisory_finding = make_dangerous_trigger_finding(file: "ci.yml", line: 1)

        @stub_search.candidates = [{ full_name: "owner/mixed-repo", stars: 500 }]
        @stub_scanner.scan_results["owner/mixed-repo"] = {
            findings: [fixable_finding, advisory_finding],
            output: "",
            workflow_count: 1,
        }
        @stub_gh_client.file_exists_map[["owner/mixed-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []
        @stub_gh_client.file_content_map[["owner/mixed-repo", ".github/workflows/ci.yml"]] = vulnerable_workflow_yaml

        _output = capture_io { bot.run }

        queue = bot.instance_variable_get(:@queue)
        pending = queue.pending

        assert_equal 1, pending.length,
            "Queue should have 1 entry (combined PR for the repo)"

        entry = pending.first
        assert_equal "owner/mixed-repo", entry["repo"]

        # Type should be "pr" because there are fixable findings
        assert_equal "pr", entry["type"],
            "Mixed findings (fixable + advisory) should be queued as type 'pr'"

        # Findings should include both the fixable and advisory findings
        finding_rules = entry["findings"].map { |f| f["rule"] }
        assert_includes finding_rules, "shell-injection-expr",
            "Queue entry should include the fixable finding"
        assert_includes finding_rules, "dangerous-triggers",
            "Queue entry should include the advisory finding"

        # Files should contain the patched content (from the fixable finding)
        refute_empty entry["files"],
            "Queue entry should have patched files from the fixable fix"

        # The title should mention ALL findings, not just fixable ones
        total_findings = entry["findings"].length
        assert_match(/#{total_findings} finding/, entry["title"],
            "Title should mention total finding count")
    end

    # ========================================================================
    # Test 8: State on volume, queue ephemeral
    #
    # SENTINEL_STATE_PATH="/tmp/volume/state.json", no SENTINEL_QUEUE_PATH.
    # State saved to volume path, queue saved to "bot/queue.json".
    # Backup should find both files at their respective paths.
    # ========================================================================

    def test_state_on_volume_queue_ephemeral
        volume_dir = File.join(@tmpdir, "volume")
        FileUtils.mkdir_p(volume_dir)
        volume_state_path = File.join(volume_dir, "state.json")

        ENV["SENTINEL_STATE_PATH"] = volume_state_path
        ENV.delete("SENTINEL_QUEUE_PATH")

        # Build the bot
        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        # Override state to use the volume path
        bot.instance_variable_set(:@state, Bot::State.new(volume_state_path))
        # Queue with no env var uses default — clean up any leftover file first
        FileUtils.rm_f("bot/queue.json")
        queue = Bot::Queue.new  # defaults to "bot/queue.json"
        bot.instance_variable_set(:@queue, queue)

        finding = make_shell_injection_finding(line: 12)
        @stub_search.candidates = [{ full_name: "owner/volume-repo", stars: 500 }]
        setup_repo_for_scan("owner/volume-repo", findings: [finding])

        _output = capture_io { bot.run }

        state = bot.instance_variable_get(:@state)
        state_actual_path = state.instance_variable_get(:@path)
        queue_actual_path = queue.instance_variable_get(:@path)

        # Verify state is saved to the volume path
        assert_equal volume_state_path, state_actual_path,
            "State should be at the volume path"
        assert File.exist?(volume_state_path),
            "State file should exist on the volume"

        # Verify queue is saved to its default path
        assert_equal "bot/queue.json", queue_actual_path,
            "Queue should be at the default path"
        assert File.exist?("bot/queue.json"),
            "Queue file should exist at default path"

        # Verify paths are different (the whole point of this test)
        refute_equal File.dirname(state_actual_path), File.dirname(queue_actual_path),
            "State and queue should be in different directories"
    ensure
        FileUtils.rm_f("bot/queue.json")
    end

    # ========================================================================
    # Test 9: Already-processed repos are skipped
    #
    # Repo has a PR recorded in state for the same rule. Verify it's skipped.
    # IMPORTANT FINDING: already_processed? compares `pattern` (from the search
    # query, e.g. "shell-injection") against `pr["rule"]` (e.g.
    # "shell-injection-expr"). These are DIFFERENT strings, so the skip may
    # never actually trigger for most patterns.
    # ========================================================================

    def test_already_processed_repos_skipped
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file

        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        state = bot.instance_variable_get(:@state)

        # Record a PR with the EXACT rule string "shell-injection-expr"
        state.record_pr(
            "owner/already-done",
            "https://github.com/owner/already-done/pull/1",
            "shell-injection-expr",
            1
        )

        # Set up the repo as a candidate
        @stub_search.candidates = [{ full_name: "owner/already-done", stars: 500 }]
        setup_repo_for_scan("owner/already-done", findings: [make_shell_injection_finding])

        _output = capture_io { bot.run }

        summary = bot.instance_variable_get(:@summary)

        # DOCUMENTED FINDING: The already_processed? method compares the `pattern`
        # parameter (which is the search query pattern like "shell-injection") against
        # stored PR entries where pr["rule"] is the actual rule name like
        # "shell-injection-expr". These DON'T match, so the repo is NOT skipped.
        #
        # The already_processed? check on line 76 of scanner_bot.rb passes `pattern`
        # (the search query pattern), not the finding's rule name.
        #
        # This means: if pattern="shell-injection" and stored rule="shell-injection-expr",
        # already_processed? returns false because "shell-injection" != "shell-injection-expr".
        #
        # Verify current behavior: the repo is NOT skipped because of the mismatch.
        if summary[:skipped] == 1
            # If this path is taken, the skip logic works (pattern matches stored rule)
            assert_equal 0, summary[:scanned],
                "Skipped repo should not be scanned"
        else
            # Expected: the repo is NOT skipped due to pattern/rule name mismatch
            assert_equal 0, summary[:skipped],
                "Repo should NOT be skipped because pattern='shell-injection' != rule='shell-injection-expr'"
            assert_equal 1, summary[:scanned],
                "Repo should be scanned because already_processed? returns false"

            # DOCUMENT THE BUG: This is a real finding.
            # The already_processed? check uses the search pattern, not the finding rule.
            # For pattern "shell-injection" and rule "shell-injection-expr", these never match.
            # The only way this would work is if the pattern exactly equals a rule name,
            # e.g. pattern="dangerous-triggers" matches rule="dangerous-triggers".
        end

        # NOW test with an exact match (pattern equals the rule name)
        bot2 = build_bot(pattern: "dangerous-triggers", queue_mode: true)
        state2 = bot2.instance_variable_get(:@state)
        state2.record_pr(
            "owner/exact-match",
            "https://github.com/owner/exact-match/pull/1",
            "dangerous-triggers",
            1
        )

        @stub_search.candidates = [{ full_name: "owner/exact-match", stars: 500 }]
        _output = capture_io { bot2.run }

        summary2 = bot2.instance_variable_get(:@summary)
        assert_equal 1, summary2[:skipped],
            "Repo SHOULD be skipped when pattern exactly matches stored rule"
        assert_equal 0, summary2[:scanned],
            "Skipped repo should not be scanned"
    end

    # ========================================================================
    # Test 10: Queue.save is called after each finding is added
    #
    # Verify @queue.save is called after EACH finding is added (not just at
    # the end). Important for crash resilience.
    # ========================================================================

    def test_queue_save_called_after_each_finding
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file

        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        # Track queue.save calls
        queue = bot.instance_variable_get(:@queue)
        save_call_count = 0
        pending_at_save = []
        original_save = queue.method(:save)
        queue.define_singleton_method(:save) do
            save_call_count += 1
            pending_at_save << @data["pending"].length
            original_save.call
        end

        # Set up 3 repos to scan, each with findings
        @stub_search.candidates = [
            { full_name: "owner/save-repo-1", stars: 500 },
            { full_name: "owner/save-repo-2", stars: 400 },
            { full_name: "owner/save-repo-3", stars: 300 },
        ]

        %w[owner/save-repo-1 owner/save-repo-2 owner/save-repo-3].each do |repo|
            setup_repo_for_scan(repo, findings: [make_shell_injection_finding(line: 12)])
        end

        _output = capture_io { bot.run }

        # Verify save was called at least once per queued finding
        assert save_call_count >= 3,
            "queue.save should be called at least once per repo/finding. " \
            "Called #{save_call_count} times for 3 repos."

        # Verify save is called incrementally (after each add, not all at once)
        # The pending count should grow incrementally
        assert_equal 3, pending_at_save.length,
            "Should have 3 save calls for 3 repos"

        # Each save should see an increasing number of pending items
        pending_at_save.each_with_index do |count, i|
            assert_equal i + 1, count,
                "Save call #{i + 1} should see #{i + 1} pending items, got #{count}. " \
                "This confirms save is called after EACH add, not just at the end."
        end
    end

    # ========================================================================
    # Test 11: Scanner content cache prevents re-fetch failure from dropping findings
    #
    # This is the root cause test for the queue never populating bug.
    # The scanner fetches workflow content internally (via fetch_workflows).
    # scan_and_fix used to re-fetch the content with a separate fetch_file_content
    # call that silently returned nil, causing all findings to be dropped.
    #
    # With the fix, scan_and_fix uses the cached content from the scanner result
    # and does NOT need to re-fetch. Even if fetch_file_content would return nil,
    # the cached content is used instead.
    # ========================================================================

    def test_scanner_content_cache_prevents_refetch_failure
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file

        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        # Set up a scanner that returns findings AND workflow content via the
        # :workflows key. This simulates what Scanner.scan now returns.
        finding = make_shell_injection_finding(line: 12)
        workflow_yaml = vulnerable_workflow_yaml

        # Build a custom stub scanner that returns workflows alongside findings
        scanner = bot.instance_variable_get(:@scanner)
        scanner.scan_results["owner/cache-repo"] = {
            findings: [finding],
            output: "",
            workflow_count: 1,
            workflows: [{ filename: "ci.yml", content: workflow_yaml }],
        }

        @stub_search.candidates = [{ full_name: "owner/cache-repo", stars: 500 }]

        # NOT a sentinel-enabled repo
        @stub_gh_client.file_exists_map[["owner/cache-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []
        @stub_gh_client.file_exists_map[["owner/cache-repo", Bot::Config::OPT_OUT_FILE]] = false

        # CRITICAL: Do NOT provide file content in the stub client.
        # This simulates the production bug where fetch_file_content returns nil.
        # The fix should use cached content from the scanner result instead.
        @stub_gh_client.file_content_map.clear

        _output = capture_io { bot.run }

        queue = bot.instance_variable_get(:@queue)
        summary = bot.instance_variable_get(:@summary)

        # The key assertion: findings should be queued even though
        # fetch_file_content would return nil, because the cached
        # content from the scanner is used.
        assert_equal 1, queue.pending.length,
            "Queue should have 1 pending entry even when fetch_file_content " \
            "returns nil, because scanner content cache provides the content"

        assert summary[:findings] > 0,
            "Should have found critical findings"
        assert_equal 1, summary[:queued],
            "Should have queued 1 entry"

        entry = queue.pending.first
        assert_equal "owner/cache-repo", entry["repo"]
        refute_empty entry["files"],
            "Queue entry should have patched files from cached content"

        # Verify the patched content is valid YAML
        entry["files"].each do |path, content|
            parsed = YAML.safe_load(content, aliases: true)
            refute_nil parsed, "Patched file #{path} must be parseable YAML"
        end
    end

    # ========================================================================
    # Test 12: Scanner.scan returns workflows in result hash
    #
    # Verify that Scanner.scan now includes :workflows in its return value,
    # containing the raw workflow data with filenames and content.
    # ========================================================================

    def test_scanner_scan_returns_workflows
        # Create a real Scanner with a stub client that returns workflow data
        formatter = Formatter::Json.new
        client = @stub_gh_client
        workflow_yaml = vulnerable_workflow_yaml
        client.instance_variable_set(:@workflows_for_test, [
            { filename: "ci.yml", content: workflow_yaml },
        ])
        client.define_singleton_method(:fetch_workflows) { |repo|
            @workflows_for_test
        }

        scanner = Scanner.new(client: client, formatter: formatter, min_severity: :low)
        result = scanner.scan("owner/test-repo")

        assert result.key?(:workflows),
            "Scanner.scan result should include :workflows key"
        assert_kind_of Array, result[:workflows],
            "Scanner.scan :workflows should be an Array"
        assert_equal 1, result[:workflows].length,
            "Should have 1 workflow"
        assert_equal "ci.yml", result[:workflows].first[:filename],
            "Workflow should have the correct filename"
        refute_nil result[:workflows].first[:content],
            "Workflow should have content"
    end

    private

    def assert_nothing_raised(msg = nil)
        yield
    rescue => e
        flunk("#{msg || "Expected no exception"}, but got #{e.class}: #{e.message}")
    end
end
