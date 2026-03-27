#!/usr/bin/env python3
"""
musick.com.au Email Monitor
============================
Monitors a Gmail inbox (via IMAP) for forwarded emails, analyzes them
with Claude (Anthropic Console API or Claude Code CLI for subscription OAuth), and sends back actionable instructions.

Usage:
    python3 email_monitor.py check       # Check for new emails and process them
    python3 email_monitor.py status      # Show monitor status
    python3 email_monitor.py test        # Send a test email to yourself

Forward error/alert emails to au.musick.com@gmail.com (or au.musick.com+monitor@gmail.com).
Replies go to response_to in .secrets.json (default brendan@faulds.com).
"""

import argparse
import email
import html
import email.header
import email.utils
import imaplib
import json
import logging
import os
import re
import shutil
import subprocess
import time
import smtplib
import sqlite3
import sys
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
SECRETS_PATH = SCRIPT_DIR / ".secrets.json"
DB_PATH = SCRIPT_DIR / "email_monitor.sqlite"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

# IMAP config for Gmail
IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993

# Where analysis replies are sent (override with response_to in .secrets.json or RESPONSE_TO env)
DEFAULT_RESPONSE_TO = "brendan@faulds.com"

# Anthropic Messages API (default model: strongest general model for careful triage)
ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
# Same OAuth beta stack OpenClaw uses for Claude subscription / Claude Code tokens (sk-ant-oat…)
ANTHROPIC_OAUTH_BETA = "claude-code-20250219,oauth-2025-04-20"
DEFAULT_OPENCLAW_AUTH_PROFILES = Path.home() / ".openclaw/agents/main/agent/auth-profiles.json"
DEFAULT_CLAUDE_CREDENTIALS = Path.home() / ".claude/.credentials.json"
DEFAULT_CLAUDE_MODEL = "claude-opus-4-6"

logger = logging.getLogger("email_monitor")


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")


def load_secrets() -> dict:
    if not SECRETS_PATH.exists():
        logger.error(f"Secrets file not found: {SECRETS_PATH}")
        sys.exit(1)
    with open(SECRETS_PATH) as f:
        return json.load(f)


def _classify_anthropic_credential(value: str) -> str | None:
    """Return auth style for Anthropic Messages API, or None if unusable."""
    if not value or not str(value).strip():
        return None
    s = str(value).strip()
    if s.startswith("sk-ant-api"):
        return "api_key"
    if "sk-ant-oat" in s:
        return "oauth"
    return None


def _profile_raw_secret(profile: dict) -> str | None:
    """Inline secret only (OpenClaw keyRef resolution is not duplicated here)."""
    ptype = profile.get("type")
    if ptype == "api_key":
        k = profile.get("key")
        return str(k).strip() if k else None
    if ptype == "token":
        t = profile.get("token")
        return str(t).strip() if t else None
    return None


def _load_openclaw_anthropic_secret(secrets: dict) -> tuple[str | None, str]:
    """Read Anthropic credential from OpenClaw's auth-profiles.json (inline secrets only — not keyRef)."""
    raw_path = (
        secrets.get("openclaw_auth_profiles_path")
        or os.environ.get("OPENCLAW_AUTH_PROFILES")
        or str(DEFAULT_OPENCLAW_AUTH_PROFILES)
    )
    path = Path(raw_path).expanduser()
    if not path.is_file():
        return None, ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not read OpenClaw auth profiles %s: %s", path, e)
        return None, ""
    profile_id = secrets.get("openclaw_anthropic_profile_id")
    if not profile_id:
        profile_id = (data.get("lastGood") or {}).get("anthropic")
    if not profile_id:
        return None, str(path)
    profile = (data.get("profiles") or {}).get(profile_id)
    if not profile:
        return None, str(path)
    secret = _profile_raw_secret(profile)
    if not secret:
        return None, str(path)
    return secret, str(path)


def _load_claude_code_oauth_access_token() -> str | None:
    """Claude Code stores subscription OAuth beside OpenClaw; token is often fresher after `claude login`."""
    if not DEFAULT_CLAUDE_CREDENTIALS.is_file():
        return None
    try:
        data = json.loads(DEFAULT_CLAUDE_CREDENTIALS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    oauth = data.get("claudeAiOauth") or {}
    token = oauth.get("accessToken")
    if not token:
        return None
    exp_ms = oauth.get("expiresAt")
    if exp_ms is not None:
        try:
            if int(exp_ms) < int(time.time() * 1000):
                logger.warning(
                    "Claude Code OAuth token in ~/.claude/.credentials.json is expired; run `claude login` "
                    "or set anthropic_api_key / ANTHROPIC_API_KEY."
                )
                return None
        except (TypeError, ValueError):
            pass
    return str(token).strip() or None


def resolve_anthropic_auth(secrets: dict) -> tuple[str | None, str | None, str]:
    """
    Resolve credential for Anthropic Messages API.
    Returns (credential, auth_mode, source_label).
    auth_mode is 'api_key' (x-api-key) or 'oauth' (Bearer + beta headers).

    OpenClaw typically stores Claude *subscription* OAuth (sk-ant-oat…) in auth-profiles.json.
    That value is not a Console API key; for REST calls the refreshed access token in
    ~/.claude/.credentials.json (Claude Code / same login) is used when still valid.
    """
    merged = dict(secrets)
    key_file = merged.get("anthropic_api_key_file")
    key_file_resolved: str | None = None
    if key_file:
        p = Path(str(key_file).strip()).expanduser()
        if p.is_file():
            try:
                from_file = p.read_text(encoding="utf-8").strip()
                if from_file:
                    merged["anthropic_api_key"] = from_file
                    key_file_resolved = str(p)
            except OSError as e:
                logger.warning("Could not read anthropic_api_key_file %s: %s", p, e)

    explicit = merged.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
    if explicit:
        s = str(explicit).strip()
        mode = _classify_anthropic_credential(s)
        if mode:
            src = (
                f"anthropic_api_key_file ({key_file_resolved})"
                if key_file_resolved
                else "anthropic_api_key or ANTHROPIC_API_KEY"
            )
            return s, mode, src
        logger.error(
            "anthropic_api_key / ANTHROPIC_API_KEY is not a valid Anthropic secret "
            "(expected sk-ant-api03… for Console API, or sk-ant-oat… for OAuth)."
        )
        return None, None, ""

    # Same OAuth pool as Claude Code — token is refreshed by the Claude CLI / IDE integration.
    cc = _load_claude_code_oauth_access_token()
    if cc and _classify_anthropic_credential(cc) == "oauth":
        return cc, "oauth", f"Claude Code OAuth ({DEFAULT_CLAUDE_CREDENTIALS})"

    oc_secret, oc_path = _load_openclaw_anthropic_secret(merged)
    if oc_secret:
        mode = _classify_anthropic_credential(oc_secret)
        if mode == "api_key":
            return oc_secret, "api_key", f"OpenClaw auth-profiles ({oc_path})"
        if mode == "oauth":
            logger.debug(
                "Skipping OpenClaw auth-profiles OAuth (sk-ant-oat…); prefer Claude Code credentials or Console API key."
            )

    return None, None, ""


def response_to_address(secrets: dict) -> str:
    r = secrets.get("response_to") or os.environ.get("RESPONSE_TO")
    if r and str(r).strip():
        return str(r).strip()
    return DEFAULT_RESPONSE_TO


def claude_model_id(secrets: dict) -> str:
    m = secrets.get("claude_model") or DEFAULT_CLAUDE_MODEL
    return str(m).strip() or DEFAULT_CLAUDE_MODEL


def monitor_inbox_addresses(secrets: dict) -> list[str]:
    """Addresses that should trigger the monitor (base Gmail + optional +monitor alias)."""
    base = secrets["smtp_user"].strip()
    plus = base.replace("@", "+monitor@")
    extra = secrets.get("monitor_extra_addresses") or []
    out = [base, plus]
    if isinstance(extra, str):
        extra = [extra]
    out.extend(str(x).strip() for x in extra if str(x).strip())
    # De-dupe preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for a in out:
        k = a.lower()
        if k not in seen:
            seen.add(k)
            uniq.append(a)
    return uniq


def decode_subject(msg: email.message.Message) -> str:
    raw = msg.get("Subject", "(no subject)")
    if not raw:
        return "(no subject)"
    try:
        return str(email.header.make_header(email.header.decode_header(raw)))
    except Exception:
        return raw if isinstance(raw, str) else str(raw)


# ---------------------------------------------------------------------------
# Database — tracks processed emails to avoid duplicates
# ---------------------------------------------------------------------------

def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed_emails (
            message_id  TEXT PRIMARY KEY,
            subject     TEXT,
            sender      TEXT,
            received_at TEXT,
            processed_at TEXT NOT NULL DEFAULT (datetime('now')),
            response_sent INTEGER NOT NULL DEFAULT 0,
            summary     TEXT
        )
    """)
    conn.commit()
    return conn


def is_processed(conn, message_id: str) -> bool:
    cur = conn.execute("SELECT 1 FROM processed_emails WHERE message_id=?", (message_id,))
    return cur.fetchone() is not None


def mark_processed(conn, message_id: str, subject: str, sender: str, received_at: str, summary: str, response_sent: bool):
    conn.execute(
        """INSERT OR REPLACE INTO processed_emails
           (message_id, subject, sender, received_at, summary, response_sent)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (message_id, subject, sender, received_at, summary, 1 if response_sent else 0),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# IMAP — fetch unread mail to the monitor inbox (base or +monitor)
# ---------------------------------------------------------------------------

def extract_text_from_email(msg) -> str:
    """Extract plain text body from an email message."""
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if content_type == "text/plain" and "attachment" not in disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_parts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        body_parts.append(payload.decode("utf-8", errors="replace"))

            elif content_type == "text/html" and not body_parts and "attachment" not in disposition:
                # Fallback: strip HTML tags if no plain text found
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html = payload.decode(charset, errors="replace")
                    # Basic HTML strip
                    text = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
                    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
                    text = re.sub(r'<[^>]+>', ' ', text)
                    text = re.sub(r'\s+', ' ', text).strip()
                    body_parts.append(text)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            body_parts.append(payload.decode(charset, errors="replace"))

    return "\n".join(body_parts)[:8000]  # Cap at 8K chars for API


def message_is_for_monitor(msg: email.message.Message, monitor_addrs: list[str]) -> bool:
    """
    True if any monitor address appears in recipient-related headers.
    Gmail IMAP SEARCH TO "..." misses some forwards / Bcc / mailing-list shapes; this is the fallback.
    """
    want = [a.lower().strip() for a in monitor_addrs if a and str(a).strip()]
    if not want:
        return False
    headers = (
        "To",
        "Cc",
        "Delivered-To",
        "X-Delivered-To",
        "X-Original-To",
        "Envelope-To",
        "X-Forwarded-To",
        "X-Forwarded-For",
    )
    blob = ""
    for h in headers:
        for v in msg.get_all(h, []) or []:
            blob += " " + str(v)
    blob_l = blob.lower()
    return any(a in blob_l for a in want)


def fetch_monitor_emails(secrets: dict) -> list[dict]:
    """Connect to Gmail IMAP and fetch unread mail to the monitor inbox addresses."""
    emails = []

    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        mail.login(secrets["smtp_user"], secrets["smtp_pass"])
        mailbox = (secrets.get("imap_mailbox") or "INBOX").strip() or "INBOX"
        mail.select(mailbox)

        addrs = monitor_inbox_addresses(secrets)

        # Prefer tight TO search; fall back to all UNSEEN + header filter (catches awkward forwards)
        or_clauses = " ".join(f'TO "{a}"' for a in addrs)
        tight_query = f"(UNSEEN (OR {or_clauses}))"
        status, data = mail.search(None, tight_query)
        if status != "OK":
            logger.warning(f"IMAP search failed: {status}")
            return emails

        message_ids = data[0].split()
        if not message_ids:
            status, data = mail.search(None, "UNSEEN")
            if status == "OK" and data and data[0]:
                candidate_ids = data[0].split()
                unseen_total = len(candidate_ids)
                try:
                    scan_max = int(secrets.get("imap_unseen_header_scan_max") or 200)
                except (TypeError, ValueError):
                    scan_max = 200
                scan_max = max(1, min(scan_max, 2000))
                if len(candidate_ids) > scan_max:
                    candidate_ids = candidate_ids[-scan_max:]
                    logger.debug(
                        "Scanning newest %s of %s UNSEEN for monitor headers",
                        scan_max,
                        unseen_total,
                    )
                message_ids = []
                for num in candidate_ids:
                    st, msg_data = mail.fetch(num, "(RFC822)")
                    if st != "OK":
                        continue
                    msg = email.message_from_bytes(msg_data[0][1])
                    if message_is_for_monitor(msg, addrs):
                        message_ids.append(num)
                if message_ids:
                    logger.info(
                        "Matched %s unread message(s) via recipient headers (TO search had 0 hits)",
                        len(message_ids),
                    )

        logger.info(f"Found {len(message_ids)} unread monitor emails")

        for num in message_ids:
            status, msg_data = mail.fetch(num, "(RFC822)")
            if status != "OK":
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            if not message_is_for_monitor(msg, addrs):
                continue

            message_id = msg.get("Message-ID", f"unknown-{num.decode()}")
            subject = decode_subject(msg)
            sender = msg.get("From", "unknown")
            date_str = msg.get("Date", "")
            body = extract_text_from_email(msg)

            emails.append({
                "message_id": message_id,
                "subject": subject,
                "sender": sender,
                "date": date_str,
                "body": body,
                "imap_num": num,
            })

        mail.logout()

    except imaplib.IMAP4.error as e:
        logger.error(f"IMAP error: {e}")
    except Exception as e:
        logger.error(f"Email fetch error: {e}")

    return emails


def imap_mark_seen(secrets: dict, imap_num) -> None:
    """Mark a message as read so UNSEEN searches do not keep returning it."""
    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        mail.login(secrets["smtp_user"], secrets["smtp_pass"])
        mailbox = (secrets.get("imap_mailbox") or "INBOX").strip() or "INBOX"
        mail.select(mailbox)
        mail.store(imap_num, "+FLAGS", "\\Seen")
        mail.logout()
    except Exception as e:
        logger.warning(f"Could not mark message as read: {e}")


# ---------------------------------------------------------------------------
# Anthropic (Claude) — analyze the email content
# ---------------------------------------------------------------------------

ANALYSIS_PROMPT = """You are an expert SEO and web operations advisor for musick.com.au (Australian live music discovery).

You have been forwarded ONE email below. Produce a concise, unique analysis for THIS message only.

**Reference context (use only when relevant to this email — do not copy it into your answer as filler):**
- Stack: PHP / MySQL / OpenLiteSpeed on VPS; deploy often via rsync; repo commonly ~/repos/musick
- Revenue mix includes AdSense and affiliates; SEO matters for traffic

**Anti-repetition (critical):**
- Do NOT restate the whole reference context as boilerplate in every section.
- Each section must add NEW information grounded in this email's subject/body (quote error strings, URLs, ticket IDs, product names from the body where applicable).
- If two sections would repeat the same sentences, merge them or drop the redundant one.
- "Email Summary" must lead with what is specific about THIS alert (not generic site description).

**Output format (Markdown):**

## Email summary
One tight paragraph on what this specific email is about.

## Impact
Only if different from the summary: effect on site, users, revenue, or SEO. If nothing substantive, write "None beyond the summary above."

## Recommended actions
Numbered list. Concrete steps; include file paths or commands only when justified by this email.

## Urgency
One line: Low / Medium / High and one short reason tied to THIS email.

## Claude Code
If fixes need a coding agent: one ```bash fenced block with commands, or the exact sentence: No code changes required.

---
Forwarded email:

From: {sender}
Subject: {subject}
Date: {date}

Body:
{body}
"""


def claude_cli_model_alias(model_id: str) -> str:
    """Map API-style model id to `claude -p --model` alias (subscription CLI)."""
    m = (model_id or "").strip().lower()
    if "haiku" in m:
        return "haiku"
    if "sonnet" in m:
        return "sonnet"
    if "opus" in m:
        return "opus"
    return "opus"


def resolve_claude_cli_bin(secrets: dict) -> str | None:
    for candidate in (
        secrets.get("claude_cli_path"),
        os.environ.get("CLAUDE_CODE_CLI"),
        os.environ.get("CLAUDE_BIN"),
    ):
        if candidate:
            p = Path(str(candidate).strip()).expanduser()
            if p.is_file():
                return str(p)
    w = shutil.which("claude")
    if w:
        return w
    home = Path.home()
    for rel in (".nvm/current/bin/claude", ".local/bin/claude"):
        p = home / rel
        if p.is_file():
            return str(p)
    return None


def _anthropic_assistant_text(result: dict) -> str | None:
    blocks = result.get("content") or []
    parts: list[str] = []
    for b in blocks:
        if isinstance(b, dict) and b.get("type") == "text":
            t = b.get("text")
            if t:
                parts.append(t)
    return "\n".join(parts) if parts else None


def analyze_with_claude_http(email_data: dict, credential: str, model: str, auth_mode: str) -> str | None:
    """Send email content to Claude via the Anthropic Messages API (Console API key)."""
    prompt = ANALYSIS_PROMPT.format(
        sender=email_data["sender"],
        subject=email_data["subject"],
        date=email_data["date"],
        body=email_data["body"],
    )

    payload = json.dumps(
        {
            "model": model,
            "max_tokens": 4096,
            "temperature": 0.3,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "anthropic-version": ANTHROPIC_VERSION,
    }
    if auth_mode == "oauth":
        headers["Authorization"] = f"Bearer {credential}"
        headers["anthropic-beta"] = ANTHROPIC_OAUTH_BETA
    else:
        headers["x-api-key"] = credential

    req = urllib.request.Request(
        ANTHROPIC_MESSAGES_URL,
        data=payload,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            result = json.loads(response.read().decode("utf-8"))
            text = _anthropic_assistant_text(result)
            if text:
                return text
            logger.warning("Claude returned no text blocks")
            return None

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        logger.error(f"Anthropic API error {e.code}: {body[:800]}")
        return None
    except Exception as e:
        logger.error(f"Anthropic API call failed: {e}")
        return None


def analyze_with_claude_code_cli(email_data: dict, model: str, secrets: dict) -> str | None:
    """
    Run analysis via `claude -p` (Claude Code CLI). Uses the same Claude subscription / OAuth
    session as `claude auth login --claudeai` — direct Messages API OAuth from Python is unreliable.
    """
    cli = resolve_claude_cli_bin(secrets)
    if not cli:
        logger.error("Claude Code CLI not found; install Claude Code or set claude_cli_path in .secrets.json")
        return None

    prompt = ANALYSIS_PROMPT.format(
        sender=email_data["sender"],
        subject=email_data["subject"],
        date=email_data["date"],
        body=email_data["body"],
    )
    alias = claude_cli_model_alias(model)
    timeout_sec = int(secrets.get("claude_cli_timeout_sec") or 600)

    try:
        result = subprocess.run(
            [
                cli,
                "-p",
                prompt,
                "--model",
                alias,
                "--permission-mode",
                "dontAsk",
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(SCRIPT_DIR),
        )
    except subprocess.TimeoutExpired:
        logger.error("Claude Code CLI timed out after %ss", timeout_sec)
        return None
    except OSError as e:
        logger.error("Could not run Claude Code CLI: %s", e)
        return None

    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        logger.error("Claude Code CLI exited %s: %s", result.returncode, err[:800])
        return None

    out = (result.stdout or "").strip()
    return out or None


def analyze_forwarded_email(
    email_data: dict, credential: str, model: str, auth_mode: str, secrets: dict
) -> str | None:
    if auth_mode == "oauth":
        return analyze_with_claude_code_cli(email_data, model, secrets)
    return analyze_with_claude_http(email_data, credential, model, auth_mode)


# ---------------------------------------------------------------------------
# Send response email
# ---------------------------------------------------------------------------

# High-contrast palette for HTML mail (many clients ignore gradients; purple-on-lavender looked "washed out")
_HTML_TEXT = "#0f172a"
_HTML_MUTED = "#475569"
_HTML_BORDER = "#cbd5e1"
_HTML_ACCENT_BG = "#eef2ff"
_HTML_ACCENT_BORDER = "#4f46e5"
_HTML_CODE_BG = "#1e293b"
_HTML_CODE_FG = "#f8fafc"


def _stash_fenced_code(text: str) -> tuple[str, list[str]]:
    """Replace ```…``` blocks with placeholders so later newline→<br> does not break <pre>."""
    blocks: list[str] = []

    def repl(m: re.Match) -> str:
        raw = m.group(2)
        esc = html.escape(raw.rstrip("\n"))
        styled = (
            f'<pre style="margin:16px 0;padding:14px 16px;background:{_HTML_CODE_BG};color:{_HTML_CODE_FG};'
            f"border:1px solid #334155;border-radius:8px;overflow-x:auto;font-family:ui-monospace,Consolas,monospace;"
            f'font-size:13px;line-height:1.5;white-space:pre;word-wrap:break-word;">{esc}</pre>'
        )
        i = len(blocks)
        blocks.append(styled)
        return f"\n__CODE_BLOCK_{i}__\n"

    # Optional language on first line: ```bash, ```text, ```
    t = re.sub(r"```([^\n`]*)\n(.*?)```", repl, text, flags=re.DOTALL)
    return t, blocks


def analysis_markdown_to_html(analysis: str) -> str:
    """Subset of Markdown → HTML safe for email; escapes text; preserves code fences."""
    if not analysis.strip():
        return ""

    t, code_blocks = _stash_fenced_code(analysis)

    def esc_repl(pattern: str, fn, s: str, flags: int = 0) -> str:
        def inner(m: re.Match) -> str:
            return fn(m)

        return re.sub(pattern, inner, s, flags=flags)

    # ## headings (strip leading emoji spacing ok)
    t = esc_repl(
        r"^## (.+)$",
        lambda m: (
            f'<h2 style="margin:22px 0 10px 0;font-size:18px;font-weight:700;color:{_HTML_TEXT};'
            f"border-left:4px solid {_HTML_ACCENT_BORDER};padding:0 0 0 12px;line-height:1.3;\">"
            f"{html.escape(m.group(1).strip())}</h2>"
        ),
        t,
        flags=re.MULTILINE,
    )

    # **bold** (non-greedy; after headings)
    t = esc_repl(
        r"\*\*(.+?)\*\*",
        lambda m: "<strong>" + html.escape(m.group(1)) + "</strong>",
        t,
    )

    # `inline code` — avoid matching inside placeholders
    t = esc_repl(
        r"`([^`]+)`",
        lambda m: (
            f'<code style="background:#f1f5f9;color:{_HTML_TEXT};padding:2px 6px;border-radius:4px;'
            f'font-family:ui-monospace,Consolas,monospace;font-size:0.9em;border:1px solid #e2e8f0;">'
            f"{html.escape(m.group(1))}</code>"
        ),
        t,
    )

    # Simple lists: consecutive lines starting with - or *
    lines = t.split("\n")
    out_lines: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^\s*[-*]\s+", line):
            items: list[str] = []
            while i < len(lines) and re.match(r"^\s*[-*]\s+", lines[i]):
                item = re.sub(r"^\s*[-*]\s+", "", lines[i])
                items.append(f'<li style="margin:6px 0;line-height:1.55;color:{_HTML_MUTED};">{item}</li>')
                i += 1
            out_lines.append(
                f'<ul style="margin:12px 0;padding-left:20px;">{"".join(items)}</ul>'
            )
            continue
        if re.match(r"^\s*\d+\.\s+", line):
            items = []
            while i < len(lines) and re.match(r"^\s*\d+\.\s+", lines[i]):
                item = re.sub(r"^\s*\d+\.\s+", "", lines[i])
                items.append(f'<li style="margin:6px 0;line-height:1.55;color:{_HTML_MUTED};">{item}</li>')
                i += 1
            out_lines.append(
                f'<ol style="margin:12px 0;padding-left:22px;">{"".join(items)}</ol>'
            )
            continue
        out_lines.append(line)
        i += 1

    t = "\n".join(out_lines)
    t = t.replace("\n", "<br>\n")

    for i, block in enumerate(code_blocks):
        t = t.replace(f"<br>\n__CODE_BLOCK_{i}__<br>\n", block)
        t = t.replace(f"__CODE_BLOCK_{i}__", block)

    return f'<div style="color:{_HTML_MUTED};font-size:15px;line-height:1.6;">{t}</div>'


def send_response(email_data: dict, analysis: str, secrets: dict) -> bool:
    """Send the analysis back as a formatted HTML email."""
    subject = f"[musick.com.au Monitor] RE: {email_data['subject']}"

    safe_sender = html.escape(str(email_data.get("sender", "")))
    safe_subject = html.escape(str(email_data.get("subject", "")))
    safe_date = html.escape(str(email_data.get("date", "")))

    html_body = analysis_markdown_to_html(analysis)

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>{html.escape(subject)}</title>
</head>
<body style="margin:0;padding:0;background:#f8fafc;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" style="max-width:640px;border-collapse:collapse;background:#ffffff;border:1px solid {_HTML_BORDER};border-radius:12px;overflow:hidden;">
<tr>
<td style="background:{_HTML_ACCENT_BORDER};padding:18px 22px;">
<p style="margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.06em;color:#e0e7ff;text-transform:uppercase;">musick.com.au monitor</p>
<h1 style="margin:6px 0 0 0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:20px;font-weight:700;color:#ffffff;line-height:1.25;">Alert analysis</h1>
</td>
</tr>
<tr>
<td style="padding:22px 24px;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;">
<table role="presentation" width="100%" style="border-collapse:collapse;background:{_HTML_ACCENT_BG};border:1px solid #c7d2fe;border-radius:8px;margin:0 0 20px 0;">
<tr><td style="padding:14px 16px;font-size:14px;line-height:1.5;color:{_HTML_TEXT};">
<strong style="color:{_HTML_TEXT};">From</strong><br><span style="color:{_HTML_MUTED};">{safe_sender}</span><br><br>
<strong style="color:{_HTML_TEXT};">Subject</strong><br><span style="color:{_HTML_MUTED};">{safe_subject}</span><br><br>
<strong style="color:{_HTML_TEXT};">Date</strong><br><span style="color:{_HTML_MUTED};">{safe_date}</span>
</td></tr></table>
{html_body}
<p style="margin:24px 0 0 0;padding-top:16px;border-top:1px solid {_HTML_BORDER};font-size:12px;color:#94a3b8;text-align:center;">
Generated {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M'))} · musick-email-monitor
</p>
</td>
</tr>
</table>
</td></tr>
</table>
</body>
</html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = secrets["smtp_user"]
        to_addr = response_to_address(secrets)
        msg["To"] = to_addr

        msg.attach(MIMEText(analysis, "plain", "utf-8"))
        msg.attach(MIMEText(full_html, "html", "utf-8"))

        with smtplib.SMTP(secrets["smtp_host"], secrets["smtp_port"], timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(secrets["smtp_user"], secrets["smtp_pass"])
            server.sendmail(secrets["smtp_user"], [to_addr], msg.as_string())

        logger.info("Response sent to %s", to_addr)
        return True

    except Exception as e:
        logger.error(f"Failed to send response: {e}")
        return False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_check(args, secrets):
    """Check for new emails and process them."""
    conn = init_db()

    emails = fetch_monitor_emails(secrets)
    if not emails:
        logger.info("No new monitor emails found.")
        return

    credential, auth_mode, auth_src = resolve_anthropic_auth(secrets)
    if not credential or not auth_mode:
        logger.error(
            "No Anthropic credential found. Options: set anthropic_api_key or ANTHROPIC_API_KEY; "
            "or use OpenClaw's ~/.openclaw/agents/main/agent/auth-profiles.json; "
            "or refresh Claude Code OAuth (~/.claude/.credentials.json via `claude login`)."
        )
        return

    model = claude_model_id(secrets)
    logger.info(
        "Using Anthropic auth from %s (%s)%s",
        auth_src,
        auth_mode,
        " → Claude Code CLI" if auth_mode == "oauth" else "",
    )
    processed = 0
    for em in emails:
        mid = em["message_id"]

        if is_processed(conn, mid):
            logger.info(f"Skipping already processed: {em['subject']}")
            imap_mark_seen(secrets, em["imap_num"])
            continue

        logger.info(f"Analyzing with {model}: {em['subject']}")
        analysis = analyze_forwarded_email(em, credential, model, auth_mode, secrets)

        if not analysis:
            logger.error(f"Analysis failed for: {em['subject']} — will retry on next run")
            continue

        sent = send_response(em, analysis, secrets)
        mark_processed(conn, mid, em["subject"], em["sender"], em["date"], analysis[:500], sent)
        imap_mark_seen(secrets, em["imap_num"])
        processed += 1

    logger.info(f"Processed {processed} email(s)")
    conn.close()


def cmd_status(args, secrets):
    """Show monitor status."""
    conn = init_db()

    print(f"\n{'='*55}")
    print(f"  Email Monitor Status — musick.com.au")
    print(f"{'='*55}\n")

    for addr in monitor_inbox_addresses(secrets):
        print(f"  Monitor address: {addr}")
    print(f"  Responses to:    {response_to_address(secrets)}")
    print(f"  Claude model:    {claude_model_id(secrets)}")
    cred, mode, src = resolve_anthropic_auth(secrets)
    if cred and mode:
        via = " (analysis via Claude Code CLI)" if mode == "oauth" else ""
        print(f"  Anthropic auth:  {mode} ← {src}{via}")
    else:
        print("  Anthropic auth:  (not configured)")
    print(f"  Database:        {DB_PATH}")

    cur = conn.execute("SELECT COUNT(*) FROM processed_emails")
    total = cur.fetchone()[0]
    print(f"\n  Total processed:  {total}")

    cur = conn.execute("SELECT COUNT(*) FROM processed_emails WHERE response_sent=1")
    sent = cur.fetchone()[0]
    print(f"  Responses sent:   {sent}")

    cur = conn.execute(
        "SELECT subject, sender, processed_at FROM processed_emails ORDER BY processed_at DESC LIMIT 5"
    )
    rows = cur.fetchall()
    if rows:
        print(f"\n  Recent emails:")
        for r in rows:
            print(f"    {r[2]} | {r[0][:50]}")

    print(f"\n{'='*55}\n")
    conn.close()


def cmd_retry(args, secrets):
    """Re-analyze and resend for emails where the response was never sent."""
    conn = init_db()

    credential, auth_mode, auth_src = resolve_anthropic_auth(secrets)
    if not credential or not auth_mode:
        logger.error("No Anthropic credential configured.")
        return

    model = claude_model_id(secrets)
    cur = conn.execute(
        "SELECT message_id, subject, sender, received_at, summary FROM processed_emails WHERE response_sent=0"
    )
    failed = cur.fetchall()
    if not failed:
        print("No failed emails to retry.")
        return

    print(f"Found {len(failed)} email(s) to retry.\n")
    retried = 0
    for mid, subject, sender, received_at, _summary in failed:
        logger.info(f"Retrying: {subject}")
        email_data = {
            "message_id": mid,
            "subject": subject,
            "sender": sender,
            "date": received_at,
            "body": _summary if _summary and _summary != "Analysis failed" else f"(Original body unavailable — subject was: {subject})",
        }

        analysis = analyze_forwarded_email(email_data, credential, model, auth_mode, secrets)
        if not analysis:
            logger.error(f"Analysis still failing for: {subject}")
            continue

        sent = send_response(email_data, analysis, secrets)
        if sent:
            conn.execute(
                "UPDATE processed_emails SET response_sent=1, summary=? WHERE message_id=?",
                (analysis[:500], mid),
            )
            conn.commit()
            retried += 1

    print(f"\nRetried {retried}/{len(failed)} email(s).")
    conn.close()


def cmd_test(args, secrets):
    """Send a test email to the monitor address."""
    monitor_addr = secrets["smtp_user"].replace("@", "+monitor@")

    try:
        msg = MIMEText(
            "This is a test email for the musick.com.au email monitor.\n\n"
            "Subject: Google Search Console detected a coverage issue on musick.com.au.\n"
            "Pages affected: /gig/ pages returning 404 errors.\n"
            "First detected: 2026-03-19\n"
            "Pages affected: 12\n\n"
            "This is a simulated alert for testing purposes.",
            "plain", "utf-8"
        )
        msg["Subject"] = "Test: GSC Coverage Issue Alert"
        msg["From"] = secrets["smtp_user"]
        msg["To"] = monitor_addr

        with smtplib.SMTP(secrets["smtp_host"], secrets["smtp_port"], timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(secrets["smtp_user"], secrets["smtp_pass"])
            server.sendmail(secrets["smtp_user"], [monitor_addr], msg.as_string())

        logger.info(f"Test email sent to {monitor_addr}")
        print(f"✅ Test email sent to {monitor_addr}")
        print(f"   Run 'python3 email_monitor.py check' in a minute to process it.")

    except Exception as e:
        logger.error(f"Failed to send test email: {e}")
        print(f"❌ Failed: {e}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="musick.com.au Email Monitor")
    parser.add_argument("-v", "--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("check", help="Check and process new emails")
    subparsers.add_parser("status", help="Show monitor status")
    subparsers.add_parser("test", help="Send a test email to the monitor")
    subparsers.add_parser("retry", help="Re-analyze and resend failed emails")

    args = parser.parse_args()
    setup_logging(args.verbose)
    secrets = load_secrets()

    commands = {
        "check": cmd_check,
        "status": cmd_status,
        "test": cmd_test,
        "retry": cmd_retry,
    }
    fn = commands.get(args.command)
    if fn:
        fn(args, secrets)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
