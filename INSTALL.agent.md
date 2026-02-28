# INSTALL.agent.md

This file contains instructions for OpenClaw agents to install the damage-control plugin.

## Installation Steps

1. Clone this repository to the OpenClaw extensions directory:
   ```bash
   git clone https://github.com/the-synclaw/openclaw-damage-control ~/.openclaw/extensions/damage-control
   ```

2. Install dependencies:
   ```bash
   cd ~/.openclaw/extensions/damage-control && npm install
   ```

3. Restart the OpenClaw gateway to load the plugin:
   ```bash
   openclaw gateway restart
   ```

4. Verify the plugin loaded:
   ```bash
   openclaw doctor 2>&1 | grep -A5 "Plugins"
   ```

## Post-Installation

- Edit `~/.openclaw/extensions/damage-control/patterns.yaml` to customize security rules
- The plugin is enabled by default; disable in `~/.openclaw/openclaw.json` under `plugins.entries.damage-control.enabled`

## Troubleshooting

If the plugin doesn't load, check:
- Dependencies installed: `ls ~/.openclaw/extensions/damage-control/node_modules/yaml`
- Gateway logs: `tail -50 /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log | grep damage-control`
