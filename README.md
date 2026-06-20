# wanguard-notify

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

**Modern alert bridge for Andrisoft Wanguard.** Forwards DDoS attack notifications to Slack, Discord, PagerDuty, Telegram, Microsoft Teams, email, and generic webhooks.

Wanguard's built-in alerting supports email, SNMP traps, and custom scripts. This bridges the gap to the platforms your team actually uses.

---

## Quick Start

```bash
git clone https://github.com/flowtriq/wanguard-notify.git
cd wanguard-notify
cp config.example.json config.json
# Edit config.json with your webhook URLs
python3 wanguard-notify.py --test
```

## Supported Channels

| Channel | Setup |
|---|---|
| **Slack** | Incoming Webhook URL |
| **Discord** | Webhook URL |
| **PagerDuty** | Events API v2 routing key (auto-resolves on attack end) |
| **Telegram** | Bot token + chat ID |
| **Microsoft Teams** | Incoming Webhook URL |
| **Email** | SMTP server (with TLS support) |
| **Generic Webhook** | Any HTTP endpoint (custom headers supported) |

Enable or disable any channel in `config.json`. Multiple channels can be active simultaneously.

## Wanguard Integration

Configure as Wanguard's notification script in the Console:

**Script path:**
```
/opt/wanguard-notify/wanguard-notify.py "$ANOMALY_ID" "$IP" "$DIRECTION" "$ATTACK_TYPE" "$MBPS" "$PPS" "$STATUS"
```

**Arguments passed by Wanguard:**

| Position | Variable | Example |
|---|---|---|
| 1 | `$ANOMALY_ID` | `12345` |
| 2 | `$IP` | `10.0.0.50` |
| 3 | `$DIRECTION` | `incoming` |
| 4 | `$ATTACK_TYPE` | `UDP Flood` |
| 5 | `$MBPS` | `1500` |
| 6 | `$PPS` | `2000000` |
| 7 | `$STATUS` | `start` or `stop` |

## Configuration

Copy `config.example.json` to `config.json` and fill in your credentials:

```json
{
  "channels": {
    "slack": {
      "type": "slack",
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
      "channel": "#ddos-alerts"
    },
    "pagerduty": {
      "type": "pagerduty",
      "enabled": true,
      "routing_key": "YOUR_ROUTING_KEY"
    }
  }
}
```

See `config.example.json` for all available options.

## Usage

```bash
# Test all configured channels
python3 wanguard-notify.py --test

# Manual alert (same args Wanguard passes)
python3 wanguard-notify.py 12345 10.0.0.50 incoming "UDP Flood" 1500 2000000 start

# Pipe JSON from stdin
echo '{"ip":"10.0.0.50","status":"start","attack_type":"SYN Flood","mbps":"500","pps":"1000000","anomaly_id":"99","direction":"incoming"}' | python3 wanguard-notify.py

# Custom config path
python3 wanguard-notify.py --config /etc/wanguard-notify.json --test
```

## PagerDuty Auto-Resolve

When configured with PagerDuty, alerts use `anomaly_id + IP` as the dedup key. When Wanguard calls the script with `status=stop`, the PagerDuty incident is automatically resolved.

## Requirements

- Python 3.8+ (no external dependencies)
- Network access to webhook endpoints

## Outgrowing Wanguard?

[Flowtriq](https://flowtriq.com) provides sub-second detection, alerts wherever your NOC works, L7 detection, PCAP forensics, and adaptive baselines at $9.99/node/month -- without the multi-license overhead of Sensor + Filter + Console.

Migrate in 5 minutes: [github.com/flowtriq/flowtriq-migrate](https://github.com/flowtriq/flowtriq-migrate)

## License

MIT License. See [LICENSE](LICENSE).

---

Built by [Flowtriq](https://flowtriq.com) -- real-time DDoS detection and mitigation.
