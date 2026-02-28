# Damage Control

Security guardrails for [OpenClaw](https://github.com/openclaw/openclaw) — blocks dangerous commands and protects sensitive files via `before_tool_call` hooks.

## Features

**Four protection layers:**

1. **bashToolPatterns** — Regex patterns to block dangerous shell commands
2. **zeroAccessPaths** — Paths blocked for ALL operations (read/write/exec) — secrets, SSH keys, credentials
3. **readOnlyPaths** — Paths that can be read but not modified — system dirs, lock files, build artifacts
4. **noDeletePaths** — Paths that can be read/written but not deleted — `.git/`, `LICENSE`, CI configs

## Installation

### Option 1: Clone to extensions directory

```bash
cd ~/.openclaw/extensions
git clone https://github.com/syndg/openclaw-damage-control.git damage-control
cd damage-control
npm install  # or pnpm/bun
```

### Option 2: Manual copy

Copy the files to `~/.openclaw/extensions/damage-control/`:

```
damage-control/
├── index.ts
├── openclaw.plugin.json
├── package.json
└── patterns.yaml
```

Then install dependencies:

```bash
cd ~/.openclaw/extensions/damage-control
npm install
```

## Configuration

Edit `patterns.yaml` to customize the security rules for your setup.

### Blocked Commands (bashToolPatterns)

Regex patterns that block dangerous shell commands like:
- Recursive/force file deletion
- Dangerous git operations (force push, reset hard, etc.)
- Database destructive commands (DROP, TRUNCATE, FLUSHALL)
- Infrastructure destruction commands

### Zero Access Paths

Files the agent should never touch:

```yaml
zeroAccessPaths:
  - ".env"
  - "~/.ssh/"
  - "~/.aws/"
  - "*.pem"
  - "*.tfstate"
```

### Read-Only Paths

Can be read but not modified:

```yaml
readOnlyPaths:
  - /etc/
  - ~/.bashrc
  - package-lock.json
  - node_modules/
```

### No-Delete Paths

Can be read and modified but not deleted:

```yaml
noDeletePaths:
  - ~/.openclaw/
  - .git/
  - LICENSE
  - README.md
  - .github/
```

## How It Works

The plugin hooks into OpenClaw's `before_tool_call` event with high priority (100). It intercepts:

- **`exec` / `Bash` tools** — Checks commands against bash patterns and path rules
- **`read` / `write` / `edit` tools** — Checks file paths against access rules

When a blocked operation is detected, the tool call is rejected with a clear reason.

## Glob Patterns

Both path lists support glob patterns:

```yaml
zeroAccessPaths:
  - "*.env"           # Matches any .env file
  - ".env.*"          # Matches .env.local, .env.production, etc.
  - "*credentials*"   # Matches anything with "credentials" in the name
```

## Enabling/Disabling

In your `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "damage-control": {
        "enabled": true
      }
    }
  }
}
```

Set `enabled: false` to disable without removing the plugin.

## License

MIT

## Agent Installation

Already using OpenClaw? Just ask your agent:

> Install the damage-control security plugin from https://github.com/the-synclaw/openclaw-damage-control

Or give it this instruction:

```
Clone https://github.com/the-synclaw/openclaw-damage-control to ~/.openclaw/extensions/damage-control/
Run `npm install` in that directory, then `openclaw gateway restart`.
```

See [INSTALL.agent.md](./INSTALL.agent.md) for detailed agent-friendly instructions.
