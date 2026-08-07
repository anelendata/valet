# Sandbox hardening

The agent runtime should be hardened before Valet is added. Treat Valet as the
privileged broker, not as the only safety control: run agents in a sandbox,
prefer read-only or scoped default permissions, require explicit approval for
mutating or cross-boundary actions, constrain network egress, keep credentials
least-privileged, and preserve logs that explain both what ran and why.

This matches the direction of current agent safety guidance: Claude Code documents
permission evaluation with hooks, deny rules, ask rules, permission modes, allow
rules, and runtime callbacks; Anthropic's auto-mode writeup emphasizes
real-world impact, trust boundaries, exfiltration risk, and conservative
authorization; OpenAI's Codex safety guidance combines sandboxing, command
rules, managed configuration, approvals, network policy, and agent-aware
telemetry.

## Claude Code setting example

For Claude Code on macOS, put the local hardening baseline in
`~/.claude/settings.json`. Keep the secret denials in place, enable the Bash
sandbox, make sandbox startup fail closed, and allow only the exact valet Unix
socket so sandboxed commands can reach the broker without gaining access to
secret files:

```json
{
  "permissions": {
    "deny": [
      "Read(//**/.env)",
      "Read(//**/.env/**)",
      "Edit(//**/.env)",
      "Edit(//**/.env/**)",
      "Bash(//**/.env)",
      "Bash(//**/.env/**)",
      "Read(//**/.secrets)",
      "Read(//**/.secrets/**)",
      "Edit(//**/.secrets)",
      "Edit(//**/.secrets/**)",
      "Bash(//**/.secrets)",
      "Bash(//**/.secrets/**)",
      "Read(~/.aws)",
      "Read(~/.aws/**)",
      "Edit(~/.aws)",
      "Edit(~/.aws/**)",
      "Bash(~/.aws)",
      "Bash(~/.aws/**)"
    ]
  },
  "disableBypassPermissionsMode": "disable",
  "sandbox": {
    "enabled": true,
    "autoAllowBashIfSandboxed": false,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "denyRead": [
        "/**/.env",
        "/**/.env/**",
        "/**/.secrets",
        "/**/.secrets/**",
        "/**/.*secrets*",
        "/**/.*secrets*/**",
        "~/.aws",
        "~/.aws/**"
      ]
    },
    "network": {
      "allowUnixSockets": [
        "~/.valet/broker.sock"
      ]
    },
    "credentials": {
      "files": [
        { "path": "~/.aws", "mode": "deny" }
      ]
    }
  },
  "agentPushNotifEnabled": true
}
```

Do not remove the `sandbox.filesystem.denyRead` rules when you add
`sandbox.network.allowUnixSockets`: they protect different boundaries.
`denyRead` keeps `.env`, `.secrets`, and `~/.aws` unreadable to Bash and child
processes; `allowUnixSockets` only lets the sandbox connect to valet's broker
socket. Avoid `allowAllUnixSockets` unless your platform requires it and you
understand the blast radius. On Linux/WSL2, Claude Code's current docs say
path-specific Unix socket filtering is not available, so use extra caution.

Keep Claude Code's permission modes conservative, require approval for
mutating or cross-boundary commands, and avoid broad allow rules for shells,
interpreters, package managers, network tools, or `valet` itself. Claude Code
configuration changes over time, so read Anthropic's official settings,
permissions, and sandboxing documentation for the complete and current settings
before using this in a production or high-risk environment. For a team or
company baseline, prefer Claude Code managed settings over user settings so the
agent cannot weaken the policy locally.

## Codex setting example

For Codex, put non-negotiable local requirements in
`/etc/codex/requirements.toml` on macOS/Linux (or the equivalent managed
configuration channel for your environment). Use your normal Codex
`config.toml`, usually `~/.codex/config.toml`, for user defaults such as the
preferred sandbox, approval policy, and telemetry settings; requirements are the
part users should not be able to weaken.

Example `/etc/codex/requirements.toml` baseline:

```toml
allowed_approval_policies = ["untrusted", "on-request"]
allowed_sandbox_modes = ["read-only", "workspace-write"]
allowed_web_search_modes = ["cached"]

[permissions.filesystem]
deny_read = [
  "/**/.env",
  "/**/.env/**",
  "/**/.secrets",
  "/**/.secrets/**",
  "/**/.*secrets*",
  "/**/.*secrets*/**",
  "/**/.aws",
  "/**/.aws/**",
]
```

For commands that deserve a second look even when they otherwise fit the
sandbox, add restrictive managed command rules. For example:

```toml
[rules]
prefix_rules = [
  { pattern = [{ any_of = ["bash", "sh", "zsh"] }], decision = "prompt", justification = "Require explicit approval for shell entry points." },
  { pattern = [{ token = "valet" }], decision = "prompt", justification = "valet can run privileged host-side commands." },
]
```

If you enable command network access for Codex, keep it constrained with a
managed allowlist rather than broad outbound access. If you use Codex permission
profiles instead of legacy sandbox modes, enforce an allowlist that omits
`:danger-full-access`. Also prefer narrow command rules and prompts around
`valet`, shell entry points, interpreters, package-manager scripts, and commands
that can mutate infrastructure or publish data.

In `~/.codex/config.toml`, prefer OS keyring storage for local Codex and MCP
OAuth credentials:

```toml
cli_auth_credentials_store = "keyring"
mcp_oauth_credentials_store = "keyring"
```

Codex configuration changes over time. Read OpenAI's official Codex
documentation for the complete and current settings before using this in a
production or high-risk environment.

## References

- [Claude Code Agent SDK permissions](https://code.claude.com/docs/en/agent-sdk/permissions)
- [How Anthropic built Claude Code auto mode](https://www.anthropic.com/engineering/claude-code-auto-mode)
- [Running Codex safely at OpenAI](https://openai.com/index/running-codex-safely/)


