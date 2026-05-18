require "minitest/autorun"
require "tmpdir"
require "fileutils"
require "json"

require_relative "../../bot/config"
require_relative "../../bot/backup"

class TestBotBackup < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-backup-test")
        @state_file = File.join(@tmpdir, "state.json")
        @token = "test-token"
        @sample_state = {"repos" => {"owner/repo" => {"scans" => [], "prs" => []}}, "opt_outs" => []}
        File.write(@state_file, JSON.pretty_generate(@sample_state))
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    def stub_api(backup, responses = {})
        backup.define_singleton_method(:api_get) { |path| responses[path] }
        backup.define_singleton_method(:api_post) { |path, body|
            responses["POST:#{path}"] || responses[:post]
        }
        backup.define_singleton_method(:api_patch) { |path, body|
            responses["PATCH:#{path}"] || responses[:patch]
        }
    end

    def test_save_creates_gist_when_no_gist_id
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        created_gist = {"id" => "abc123", "files" => {}}
        stub_api(backup, { post: created_gist })

        assert backup.save
    end

    def test_save_updates_existing_gist_when_gist_id_set
        ENV["SENTINEL_BACKUP_GIST_ID"] = "existing-gist-id"
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        updated_gist = {"id" => "existing-gist-id", "files" => {}}
        stub_api(backup, { "PATCH:/gists/existing-gist-id" => updated_gist })

        assert backup.save
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_restore_fetches_and_writes_state
        ENV["SENTINEL_BACKUP_GIST_ID"] = "restore-gist-id"
        restore_path = File.join(@tmpdir, "restored-state.json")
        backup = Bot::Backup.new(token: @token, state_path: restore_path)

        gist_content = JSON.pretty_generate(@sample_state)
        gist_response = {
            "id" => "restore-gist-id",
            "files" => {
                "sentinel-state-backup.json" => { "content" => gist_content },
            },
        }
        stub_api(backup, { "/gists/restore-gist-id" => gist_response })

        assert backup.restore
        assert File.exist?(restore_path)
        assert_equal @sample_state, JSON.parse(File.read(restore_path))
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_save_handles_network_errors_gracefully
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        stub_api(backup, { post: nil })

        refute backup.save
    end

    def test_restore_handles_network_errors_gracefully
        ENV["SENTINEL_BACKUP_GIST_ID"] = "error-gist-id"
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        stub_api(backup, { "/gists/error-gist-id" => nil })

        refute backup.restore
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_restore_fails_gracefully_when_no_gist_id
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        refute backup.restore
    end

    def test_save_with_missing_state_file
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        missing_path = File.join(@tmpdir, "nonexistent.json")
        backup = Bot::Backup.new(token: @token, state_path: missing_path)

        refute backup.save
    end
end
