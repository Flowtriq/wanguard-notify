#!/usr/bin/env python3
"""
wanguard-notify — Modern alert bridge for Andrisoft Wanguard.

Forwards Wanguard attack notifications to Slack, Discord, PagerDuty,
Telegram, Microsoft Teams, email, and generic webhooks.

Configure as Wanguard's notification script. When an attack is detected,
Wanguard calls this script with attack details. This script formats a
rich alert and delivers it to all configured channels.

Usage as Wanguard script:
    /opt/wanguard-notify/wanguard-notify.py "$ANOMALY_ID" "$IP" "$DIRECTION" \
        "$ATTACK_TYPE" "$MBPS" "$PPS" "$STATUS"

Standalone test:
    python3 wanguard-notify.py --test

Built by Flowtriq Networks Inc. (https://flowtriq.com)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import smtplib
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path

VERSION = "1.0.0"
CONFIG_PATH = os.environ.get(
    "WANGUARD_NOTIFY_CONFIG",
    str(Path(__file__).parent / "config.json"),
)


def load_config() -> dict:
    """Load configuration from config.json."""
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config not found: {CONFIG_PATH}", file=sys.stderr)
        print("Copy config.example.json to config.json and edit it.", file=sys.stderr)
        sys.exit(1)


def _post_json(url: str, payload: dict, headers: dict = None) -> bool:
    """POST JSON to a URL. Returns True on success."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        ctx = ssl.create_default_context()
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        return 200 <= resp.status < 300
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        print(f"  [error] POST {url}: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Channel handlers
# ---------------------------------------------------------------------------

def send_slack(cfg: dict, alert: dict) -> bool:
    """Send alert to Slack via webhook."""
    url = cfg.get("webhook_url", "")
    if not url:
        return False

    color = "#ff3b52" if alert["status"] == "start" else "#00d97e"
    status_text = "Attack Detected" if alert["status"] == "start" else "Attack Ended"

    payload = {
        "username": cfg.get("username", "Wanguard Alert"),
        "icon_emoji": cfg.get("icon", ":shield:"),
        "attachments": [{
            "color": color,
            "title": f"{status_text}: {alert['ip']}",
            "fields": [
                {"title": "IP", "value": alert["ip"], "short": True},
                {"title": "Direction", "value": alert["direction"], "short": True},
                {"title": "Attack Type", "value": alert["attack_type"], "short": True},
                {"title": "Status", "value": alert["status"].upper(), "short": True},
                {"title": "Traffic", "value": f"{alert['mbps']} Mbps / {alert['pps']} PPS", "short": True},
                {"title": "Anomaly ID", "value": alert["anomaly_id"], "short": True},
            ],
            "footer": "wanguard-notify by Flowtriq | flowtriq.com",
            "ts": int(datetime.now(tz=timezone.utc).timestamp()),
        }],
    }
    channel = cfg.get("channel")
    if channel:
        payload["channel"] = channel
    return _post_json(url, payload)


def send_discord(cfg: dict, alert: dict) -> bool:
    """Send alert to Discord via webhook."""
    url = cfg.get("webhook_url", "")
    if not url:
        return False

    color = 0xFF3B52 if alert["status"] == "start" else 0x00D97E
    status_text = "Attack Detected" if alert["status"] == "start" else "Attack Ended"

    payload = {
        "username": cfg.get("username", "Wanguard Alert"),
        "embeds": [{
            "title": f"{status_text}: {alert['ip']}",
            "color": color,
            "fields": [
                {"name": "IP", "value": alert["ip"], "inline": True},
                {"name": "Direction", "value": alert["direction"], "inline": True},
                {"name": "Attack Type", "value": alert["attack_type"], "inline": True},
                {"name": "Traffic", "value": f"{alert['mbps']} Mbps / {alert['pps']} PPS", "inline": True},
                {"name": "Anomaly ID", "value": alert["anomaly_id"], "inline": True},
                {"name": "Status", "value": alert["status"].upper(), "inline": True},
            ],
            "footer": {"text": "wanguard-notify by Flowtriq | flowtriq.com"},
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }],
    }
    return _post_json(url, payload)


def send_pagerduty(cfg: dict, alert: dict) -> bool:
    """Send alert to PagerDuty Events API v2."""
    routing_key = cfg.get("routing_key", "")
    if not routing_key:
        return False

    event_action = "trigger" if alert["status"] == "start" else "resolve"
    severity = cfg.get("severity", "critical" if alert["status"] == "start" else "info")

    payload = {
        "routing_key": routing_key,
        "event_action": event_action,
        "dedup_key": f"wanguard-{alert['anomaly_id']}-{alert['ip']}",
        "payload": {
            "summary": f"DDoS {alert['status']}: {alert['ip']} ({alert['mbps']} Mbps, {alert['pps']} PPS)",
            "source": cfg.get("source", "wanguard"),
            "severity": severity,
            "custom_details": {
                "ip": alert["ip"],
                "direction": alert["direction"],
                "attack_type": alert["attack_type"],
                "mbps": alert["mbps"],
                "pps": alert["pps"],
                "anomaly_id": alert["anomaly_id"],
            },
        },
    }
    return _post_json("https://events.pagerduty.com/v2/enqueue", payload)


def send_telegram(cfg: dict, alert: dict) -> bool:
    """Send alert to Telegram via Bot API."""
    token = cfg.get("bot_token", "")
    chat_id = cfg.get("chat_id", "")
    if not token or not chat_id:
        return False

    icon = "🔴" if alert["status"] == "start" else "🟢"
    status_text = "Attack Detected" if alert["status"] == "start" else "Attack Ended"

    text = (
        f"{icon} *{status_text}*\n"
        f"*IP:* `{alert['ip']}`\n"
        f"*Direction:* {alert['direction']}\n"
        f"*Type:* {alert['attack_type']}\n"
        f"*Traffic:* {alert['mbps']} Mbps / {alert['pps']} PPS\n"
        f"*Anomaly ID:* {alert['anomaly_id']}\n"
        f"\n_wanguard-notify by Flowtriq_"
    )

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    return _post_json(url, {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    })


def send_teams(cfg: dict, alert: dict) -> bool:
    """Send alert to Microsoft Teams via webhook."""
    url = cfg.get("webhook_url", "")
    if not url:
        return False

    color = "FF3B52" if alert["status"] == "start" else "00D97E"
    status_text = "Attack Detected" if alert["status"] == "start" else "Attack Ended"

    payload = {
        "@type": "MessageCard",
        "themeColor": color,
        "summary": f"{status_text}: {alert['ip']}",
        "sections": [{
            "activityTitle": f"{status_text}: {alert['ip']}",
            "facts": [
                {"name": "IP", "value": alert["ip"]},
                {"name": "Direction", "value": alert["direction"]},
                {"name": "Attack Type", "value": alert["attack_type"]},
                {"name": "Traffic", "value": f"{alert['mbps']} Mbps / {alert['pps']} PPS"},
                {"name": "Anomaly ID", "value": alert["anomaly_id"]},
            ],
            "markdown": True,
        }],
    }
    return _post_json(url, payload)


def send_webhook(cfg: dict, alert: dict) -> bool:
    """Send alert to a generic webhook endpoint."""
    url = cfg.get("url", "")
    if not url:
        return False

    payload = {
        "event": "ddos_" + alert["status"],
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "alert": alert,
        "source": "wanguard-notify",
    }
    headers = cfg.get("headers", {})
    return _post_json(url, payload, headers)


def send_email(cfg: dict, alert: dict) -> bool:
    """Send alert via SMTP email."""
    to_addr = cfg.get("to", "")
    smtp_host = cfg.get("smtp_host", "localhost")
    smtp_port = cfg.get("smtp_port", 25)
    from_addr = cfg.get("from", f"wanguard-notify@{smtp_host}")
    username = cfg.get("username", "")
    password = cfg.get("password", "")
    use_tls = cfg.get("tls", smtp_port == 587)

    if not to_addr:
        return False

    status_text = "DETECTED" if alert["status"] == "start" else "ENDED"
    subject = f"[Wanguard] DDoS {status_text}: {alert['ip']} ({alert['mbps']} Mbps)"

    body = (
        f"DDoS Attack {status_text}\n"
        f"{'=' * 40}\n\n"
        f"IP:          {alert['ip']}\n"
        f"Direction:   {alert['direction']}\n"
        f"Attack Type: {alert['attack_type']}\n"
        f"Traffic:     {alert['mbps']} Mbps / {alert['pps']} PPS\n"
        f"Anomaly ID:  {alert['anomaly_id']}\n"
        f"Time:        {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"---\nSent by wanguard-notify (Flowtriq | flowtriq.com)"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr

    try:
        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.starttls(context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        if username:
            server.login(username, password)
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"  [error] Email: {e}", file=sys.stderr)
        return False


CHANNEL_HANDLERS = {
    "slack": send_slack,
    "discord": send_discord,
    "pagerduty": send_pagerduty,
    "telegram": send_telegram,
    "teams": send_teams,
    "webhook": send_webhook,
    "email": send_email,
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def dispatch(alert: dict, config: dict) -> None:
    """Send alert to all configured channels."""
    channels = config.get("channels", {})
    for name, cfg in channels.items():
        if not cfg.get("enabled", True):
            continue
        ch_type = cfg.get("type", name)
        handler = CHANNEL_HANDLERS.get(ch_type)
        if not handler:
            print(f"  [warn] Unknown channel type: {ch_type}", file=sys.stderr)
            continue
        ok = handler(cfg, alert)
        status = "OK" if ok else "FAILED"
        print(f"  [{status}] {name} ({ch_type})")


def parse_args_as_alert(args: list) -> dict:
    """Parse Wanguard script arguments into an alert dict."""
    # Wanguard passes: anomaly_id, ip, direction, attack_type, mbps, pps, status
    return {
        "anomaly_id": args[0] if len(args) > 0 else "0",
        "ip": args[1] if len(args) > 1 else "0.0.0.0",
        "direction": args[2] if len(args) > 2 else "incoming",
        "attack_type": args[3] if len(args) > 3 else "unknown",
        "mbps": args[4] if len(args) > 4 else "0",
        "pps": args[5] if len(args) > 5 else "0",
        "status": args[6] if len(args) > 6 else "start",
        "time": datetime.now(tz=timezone.utc).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="wanguard-notify: Modern alert bridge for Andrisoft Wanguard",
    )
    parser.add_argument("args", nargs="*", help="Wanguard script arguments")
    parser.add_argument("--test", action="store_true", help="Send a test alert to all channels")
    parser.add_argument("--config", default=None, help="Path to config.json")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parsed = parser.parse_args()

    if parsed.config:
        global CONFIG_PATH
        CONFIG_PATH = parsed.config

    config = load_config()

    if parsed.test:
        print(f"wanguard-notify v{VERSION} -- test mode")
        alert = {
            "anomaly_id": "TEST-001",
            "ip": "192.0.2.100",
            "direction": "incoming",
            "attack_type": "UDP Flood (test)",
            "mbps": "1500",
            "pps": "2000000",
            "status": "start",
            "time": datetime.now(tz=timezone.utc).isoformat(),
        }
        print(f"Sending test alert to {len(config.get('channels', {}))} channel(s)...")
        dispatch(alert, config)
        return

    if not parsed.args:
        # Try reading from stdin (pipe mode)
        if not sys.stdin.isatty():
            raw = sys.stdin.read().strip()
            if raw:
                try:
                    alert = json.loads(raw)
                except json.JSONDecodeError:
                    alert = parse_args_as_alert(raw.split())
            else:
                parser.print_help()
                sys.exit(1)
        else:
            parser.print_help()
            sys.exit(1)
    else:
        alert = parse_args_as_alert(parsed.args)

    dispatch(alert, config)


if __name__ == "__main__":
    main()
