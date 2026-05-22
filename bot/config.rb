module Bot
    module Config
        MIN_STARS = 100
        MAX_PRS_PER_DAY = 300
        FIXABLE_RULES = %w[unpinned-actions shell-injection-expr missing-persist-credentials workflow-dispatch-injection missing-permissions missing-timeouts].freeze
        SEARCH_QUERIES = [
            # Shell injection vectors
            { pattern: "shell-injection", query: '"${{ github.event.pull_request.title }}" path:.github/workflows language:YAML' },
            { pattern: "shell-injection-body", query: '"${{ github.event.issue.body }}" path:.github/workflows language:YAML' },
            { pattern: "shell-injection-headref", query: '"${{ github.head_ref }}" run path:.github/workflows language:YAML' },
            { pattern: "shell-injection-actor", query: '"${{ github.actor }}" run path:.github/workflows language:YAML' },
            # Dangerous triggers
            { pattern: "dangerous-triggers", query: 'pull_request_target checkout path:.github/workflows language:YAML' },
            # Hardcoded secrets
            { pattern: "hardcoded-secrets", query: '"AKIA" path:.github/workflows language:YAML' },
            { pattern: "hardcoded-secrets-ghp", query: '"ghp_" path:.github/workflows language:YAML' },
            # GitHub script injection
            { pattern: "github-script-injection", query: '"actions/github-script" "github.event" path:.github/workflows language:YAML' },
        ].freeze

        OPT_OUT_FILE = ".github/.sentinel-ci.yml"
        STATE_FILE = ENV["SENTINEL_STATE_PATH"] || "bot/state.json"
        BOT_URL = ENV["SENTINEL_BOT_URL"] || "https://sentinel-bot.copilotkit.dev"
        SIGNOFF_IDENTITY = "Jordan Ritter <jpr5@darkridge.com>"
    end
end
