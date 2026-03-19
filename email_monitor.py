#!/usr/bin/env python3
"""
musick.com.au Email Monitor
============================
Monitors a Gmail inbox (via IMAP) for forwarded emails, analyzes them
with Claude (Anthropic API), and sends back actionable instructions.

Usage:
    python3 email_monitor.py check       # Check for new emails and process them
    python3 email_monitor.py status      # Show monitor status
    python3 email_monitor.py test        # Send a test email to yourself

Forward error/alert emails to au.musick.com@gmail.com (or au.musick.com+monitor@gmail.com).
Responses are sent to brendan@faulds.au.
"""

import argparse
import email
import email.header
import email.utils
import imaplib
import json
import logging
import os
import re
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

# Response recipient
RESPONSE_TO = "brendan@faulds.au"

# Anthropic Messages API (default model: strongest general model for careful triage)
ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
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


def anthropic_api_key(secrets: dict) -> str | None:
    k = secrets.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
    if not k:
        return None
    k = str(k).strip()
    return k or None


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


def fetch_monitor_emails(secrets: dict) -> list[dict]:
    """Connect to Gmail IMAP and fetch unread emails to the +monitor alias."""
    emails = []

    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        mail.login(secrets["smtp_user"], secrets["smtp_pass"])
        mail.select("INBOX")

        # Unread mail To the monitor inbox (base address or +monitor alias — both are valid)
        addrs = monitor_inbox_addresses(secrets)
        or_clauses = " ".join(f'TO "{a}"' for a in addrs)
        search_query = f"(UNSEEN (OR {or_clauses}))"
        status, data = mail.search(None, search_query)

        if status != "OK":
            logger.warning(f"IMAP search failed: {status}")
            return emails

        message_ids = data[0].split()
        logger.info(f"Found {len(message_ids)} unread monitor emails")

        for num in message_ids:
            status, msg_data = mail.fetch(num, "(RFC822)")
            if status != "OK":
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

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
        mail.select("INBOX")
        mail.store(imap_num, "+FLAGS", "\\Seen")
        mail.logout()
    except Exception as e:
        logger.warning(f"Could not mark message as read: {e}")


# ---------------------------------------------------------------------------
# Anthropic (Claude) — analyze the email content
# ---------------------------------------------------------------------------

ANALYSIS_PROMPT = """You are an expert SEO and web operations advisor for musick.com.au, an Australian live music discovery platform.

You have been forwarded an email. Analyze it and provide actionable advice.

**Context about musick.com.au:**
- Stack: PHP 8.1 / MySQL 8.0 / OpenLiteSpeed on BinaryLane VPS (IP: 103.249.236.144)
- Revenue: Google AdSense, Amazon Affiliates, Impact Affiliates
- SEO is critical — the site relies on organic traffic
- Deployment: rsync-based via deploy.sh
- Local repo: /home/brendan/repos/musick

**Your response MUST follow this format:**

## 📧 Email Summary
(One paragraph summary of what the email is about)

## 🎯 What This Means
(What impact does this have on the site, traffic, or revenue?)

## ✅ Recommended Actions
(Numbered list of specific, actionable steps. If code changes are needed, include the exact commands or code snippets to run. Be specific about file paths.)

## 🔥 Urgency
(Rate: 🟢 Low | 🟡 Medium | 🔴 High — and explain why)

## 💻 Claude Code Commands
(If any code changes are needed, provide exact commands that can be copy-pasted into a terminal on the Xeon dev machine. Format as a bash code block. If no code changes needed, say "No code changes required.")

---
Here is the forwarded email:

**From:** {sender}
**Subject:** {subject}
**Date:** {date}

**Body:**
{body}
"""


def _anthropic_assistant_text(result: dict) -> str | None:
    blocks = result.get("content") or []
    parts: list[str] = []
    for b in blocks:
        if isinstance(b, dict) and b.get("type") == "text":
            t = b.get("text")
            if t:
                parts.append(t)
    return "\n".join(parts) if parts else None


def analyze_with_claude(email_data: dict, api_key: str, model: str) -> str | None:
    """Send email content to Claude via the Anthropic Messages API."""
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

    req = urllib.request.Request(
        ANTHROPIC_MESSAGES_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        },
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


# ---------------------------------------------------------------------------
# Send response email
# ---------------------------------------------------------------------------

def send_response(email_data: dict, analysis: str, secrets: dict) -> bool:
    """Send the analysis back as a formatted HTML email."""
    subject = f"[musick.com.au Monitor] RE: {email_data['subject']}"

    # Convert markdown-ish analysis to basic HTML
    html_body = analysis
    # Headers
    html_body = re.sub(r'^## (.+)$', r'<h2 style="color:#6b21a8; border-bottom:2px solid #e9d5ff; padding-bottom:6px; margin-top:24px;">\1</h2>', html_body, flags=re.MULTILINE)
    # Bold
    html_body = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_body)
    # Code blocks
    html_body = re.sub(r'```bash\n(.*?)```', r'<pre style="background:#1a1a2e; color:#e2e8f0; padding:16px; border-radius:8px; overflow-x:auto; font-family:monospace; font-size:13px; line-height:1.5;">\1</pre>', html_body, flags=re.DOTALL)
    html_body = re.sub(r'```\n?(.*?)```', r'<pre style="background:#f1f5f9; padding:12px; border-radius:6px; overflow-x:auto; font-size:13px;">\1</pre>', html_body, flags=re.DOTALL)
    # Inline code
    html_body = re.sub(r'`([^`]+)`', r'<code style="background:#f1f5f9; padding:2px 6px; border-radius:3px; font-size:13px;">\1</code>', html_body)
    # Line breaks
    html_body = html_body.replace("\n", "<br>\n")

    full_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width:700px; margin:0 auto; padding:20px; color:#1a1a2e;">
    <div style="background: linear-gradient(135deg, #6b21a8, #9333ea); border-radius:12px 12px 0 0; padding:20px; text-align:center;">
        <h1 style="color:#fff; margin:0; font-size:20px;">🎵 musick.com.au — Email Monitor</h1>
        <p style="color:rgba(255,255,255,0.8); margin:4px 0 0 0; font-size:13px;">Automated analysis of forwarded email</p>
    </div>
    <div style="background:#fff; padding:24px; border-radius:0 0 12px 12px; box-shadow:0 2px 12px rgba(107,33,168,0.08);">
        <div style="background:#faf5ff; border:1px solid #e9d5ff; border-radius:8px; padding:12px; margin-bottom:20px; font-size:13px;">
            <strong>Original email from:</strong> {email_data['sender']}<br>
            <strong>Subject:</strong> {email_data['subject']}<br>
            <strong>Date:</strong> {email_data['date']}
        </div>
        {html_body}
    </div>
    <p style="text-align:center; font-size:11px; color:#999; margin-top:16px;">
        Generated by email_monitor.py on {datetime.now().strftime('%Y-%m-%d %H:%M')}
    </p>
</body>
</html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = secrets["smtp_user"]
        msg["To"] = RESPONSE_TO

        msg.attach(MIMEText(analysis, "plain", "utf-8"))
        msg.attach(MIMEText(full_html, "html", "utf-8"))

        with smtplib.SMTP(secrets["smtp_host"], secrets["smtp_port"], timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(secrets["smtp_user"], secrets["smtp_pass"])
            server.sendmail(secrets["smtp_user"], [RESPONSE_TO], msg.as_string())

        logger.info(f"Response sent to {RESPONSE_TO}")
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

    api_key = anthropic_api_key(secrets)
    if not api_key:
        logger.error("No anthropic_api_key in .secrets.json (or ANTHROPIC_API_KEY in the environment)")
        return

    model = claude_model_id(secrets)
    processed = 0
    for em in emails:
        mid = em["message_id"]

        if is_processed(conn, mid):
            logger.info(f"Skipping already processed: {em['subject']}")
            imap_mark_seen(secrets, em["imap_num"])
            continue

        logger.info(f"Analyzing with {model}: {em['subject']}")
        analysis = analyze_with_claude(em, api_key, model)

        if not analysis:
            logger.error(f"Analysis failed for: {em['subject']}")
            mark_processed(conn, mid, em["subject"], em["sender"], em["date"], "Analysis failed", False)
            imap_mark_seen(secrets, em["imap_num"])
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
    print(f"  Responses to:    {RESPONSE_TO}")
    print(f"  Claude model:    {claude_model_id(secrets)}")
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

    args = parser.parse_args()
    setup_logging(args.verbose)
    secrets = load_secrets()

    if args.command == "check":
        cmd_check(args, secrets)
    elif args.command == "status":
        cmd_status(args, secrets)
    elif args.command == "test":
        cmd_test(args, secrets)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
