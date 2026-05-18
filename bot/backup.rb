require "net/http"
require "json"
require "uri"
require "time"

module Bot
    class Backup
        API_BASE = "https://api.github.com"
        GIST_FILENAME = "sentinel-state-backup.json"

        def initialize(token:, state_path: Config::STATE_FILE)
            @token = token
            @state_path = state_path
            @gist_id = ENV["SENTINEL_BACKUP_GIST_ID"]
        end

        def save
            unless File.exist?(@state_path)
                $stderr.puts "Backup: state file not found at #{@state_path}"
                return false
            end

            content = File.read(@state_path)
            description = "Sentinel bot state backup — #{Time.now.utc.iso8601}"
            files = { GIST_FILENAME => { "content" => content } }

            if @gist_id
                result = api_patch("/gists/#{@gist_id}", {
                    description: description,
                    files: files,
                })
            else
                result = api_post("/gists", {
                    description: description,
                    public: false,
                    files: files,
                })

                if result
                    @gist_id = result["id"]
                    $stderr.puts "Backup: created gist #{result["id"]}"
                    $stderr.puts "  Set SENTINEL_BACKUP_GIST_ID=#{result["id"]} to update this gist in future runs"
                end
            end

            if result
                $stderr.puts "Backup: state saved to gist"
                true
            else
                $stderr.puts "Backup: failed to save state"
                false
            end
        rescue => e
            $stderr.puts "Backup: error saving state: #{e.message}"
            false
        end

        def restore
            unless @gist_id
                $stderr.puts "Backup: SENTINEL_BACKUP_GIST_ID not set, cannot restore"
                return false
            end

            data = api_get("/gists/#{@gist_id}")
            unless data
                $stderr.puts "Backup: failed to fetch gist #{@gist_id}"
                return false
            end

            content = data.dig("files", GIST_FILENAME, "content")
            unless content
                $stderr.puts "Backup: gist does not contain #{GIST_FILENAME}"
                return false
            end

            tmp = "#{@state_path}.tmp"
            File.write(tmp, content)
            File.rename(tmp, @state_path)

            $stderr.puts "Backup: state restored from gist"
            true
        rescue => e
            $stderr.puts "Backup: error restoring state: #{e.message}"
            false
        end

        private

        def api_get(path)
            uri = URI("#{API_BASE}#{path}")
            req = Net::HTTP::Get.new(uri)
            set_headers(req)
            execute(uri, req)
        end

        def api_post(path, body)
            uri = URI("#{API_BASE}#{path}")
            req = Net::HTTP::Post.new(uri)
            set_headers(req)
            req.body = JSON.generate(body)
            execute(uri, req)
        end

        def api_patch(path, body)
            uri = URI("#{API_BASE}#{path}")
            req = Net::HTTP::Patch.new(uri)
            set_headers(req)
            req.body = JSON.generate(body)
            execute(uri, req)
        end

        def set_headers(req)
            req["Accept"] = "application/vnd.github+json"
            req["Authorization"] = "Bearer #{@token}" if @token
            req["X-GitHub-Api-Version"] = "2022-11-28"
            req["Content-Type"] = "application/json"
        end

        def execute(uri, req)
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = true
            http.open_timeout = 10
            http.read_timeout = 30

            resp = http.request(req)

            case resp.code.to_i
            when 200, 201, 202
                JSON.parse(resp.body)
            when 204
                true
            when 404
                nil
            when 403
                $stderr.puts "Rate limited or forbidden: #{req.path}"
                nil
            when 422
                $stderr.puts "Validation error: #{resp.body}"
                nil
            else
                $stderr.puts "API error #{resp.code}: #{req.path}"
                nil
            end
        end
    end
end
