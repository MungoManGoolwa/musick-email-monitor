# musick-email-monitor

Small service for **musick.com.au**: poll a dedicated Gmail inbox for forwarded errors/alerts, analyze with **Claude** (Anthropic API), and email back a structured brief including **Claude Code**-style remediation commands.

## Requirements

- **Python 3.10+** (stdlib only — no `pip install`)
- Gmail **App Password** if 2FA is on ([Google help](https://support.google.com/accounts/answer/185833))
- An [Anthropic API key](https://console.anthropic.com/) (`sk-ant-api03-…`). Optional: set `ANTHROPIC_API_KEY` in the environment instead of putting the key in `.secrets.json`.

## Setup

```bash
cd musick-email-monitor
cp .secrets.example.json .secrets.json
chmod 600 .secrets.json
# Edit .secrets.json: smtp_*, anthropic_api_key
# Optional: "claude_model" (default claude-opus-4-6 — override e.g. for Sonnet if you prefer cost/latency)
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
