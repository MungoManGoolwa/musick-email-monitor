# musick-email-monitor

Small service for **musick.com.au**: poll a dedicated Gmail inbox for forwarded errors/alerts, analyze with **Claude** (Anthropic API), and email back a structured brief including **Claude Code**-style remediation commands.

## Requirements

- **Python 3.10+** (stdlib only — no `pip install`)
- Gmail **App Password** if 2FA is on ([Google help](https://support.google.com/accounts/answer/185833))
- Anthropic access, one of:
  - **Console API key** (`sk-ant-api03-…`) from [console.anthropic.com](https://console.anthropic.com/) — set `anthropic_api_key` or `ANTHROPIC_API_KEY`, or `anthropic_api_key_file` pointing at a file that contains only the key.
  - **Same login as OpenClaw / Claude Code** (`claude auth login --claudeai`): the monitor checks `~/.claude/.credentials.json` for a **non-expired** OAuth access token. Analysis then runs through the **`claude -p`** CLI (same subscription as Claude Code), because direct `curl`/Python calls to the Messages API with OAuth tokens are brittle. Ensure `claude` is on `PATH` for cron, or set `claude_cli_path` in `.secrets.json`.

## Setup

```bash
cd musick-email-monitor
cp .secrets.example.json .secrets.json
chmod 600 .secrets.json
# Edit .secrets.json: smtp_*, and either anthropic_api_key OR anthropic_api_key_file OR rely on Claude Code OAuth
# Optional: "claude_model" (default claude-opus-4-6)
# Optional: openclaw_auth_profiles_path, openclaw_anthropic_profile_id (only if that profile stores sk-ant-api03… inline)
```

## Usage

```bash
python3 email_monitor.py status   # show monitor addresses + DB stats
python3 email_monitor.py check    # fetch unread → analyze → reply to brendan@faulds.au
python3 email_monitor.py test     # send a self-test to the +monitor address
```

Forward mail **To** `au.musick.com@gmail.com` or `au.musick.com+monitor@gmail.com`. Unread messages matching either address are processed once (tracked in `email_monitor.sqlite`).

## Automation (OpenClaw)

Example cron payload (every 15 minutes):

```text
Run this command and report the result: /usr/bin/python3 /home/brendan/repos/musick-email-monitor/email_monitor.py check
```

## Related

- [musick-seo-engine](https://github.com/MungoManGoolwa/musick-seo-engine) — daily SEO reports (separate repo; shares the same Gmail account for SMTP in many setups, but **secrets files are separate**).
