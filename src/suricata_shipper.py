#!/usr/local/bin/python3
"""
AI-Assisted SOC Alert Triage Pipeline - Suricata EVE JSON Shipper Daemon
Tails /var/log/suricata/eve.json on OPNsense (FreeBSD) with inode tracking
across log rotations, filters high/medium severity alerts, and forwards
structured payloads to an n8n + Ollama LLM triage workflow over Tailscale/LAN.
"""

import time
import json
import urllib.request
import os

EVE_LOG_PATH = os.environ.get("EVE_LOG_PATH", "/var/log/suricata/eve.json")
N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL", "http://100.x.y.z:5678/webhook/soc-alert")
MIN_SEVERITY = int(os.environ.get("MIN_SEVERITY", "2"))  # Filter: 1 (High), 2 (Medium)


def tail_eve_log(filepath):
    """Generator that tails a log file and seamlessly handles FreeBSD newsyslog/Suricata rotation via inode tracking."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                try:
                    if os.stat(filepath).st_ino != inode:
                        f.close()
                        f = open(filepath, "r", encoding="utf-8", errors="replace")
                        inode = os.fstat(f.fileno()).st_ino
                except FileNotFoundError:
                    pass
                continue
            yield line


def ship_alert(payload):
    """Ships filtered alert JSON payload via HTTP POST to the n8n webhook endpoint."""
    req = urllib.request.Request(
        N8N_WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except Exception as e:
        print(f"[ERROR] Webhook delivery failed: {e}")
        return None


def main():
    for raw_line in tail_eve_log(EVE_LOG_PATH):
        try:
            event = json.loads(raw_line)
            if event.get("event_type") == "alert":
                severity = event.get("alert", {}).get("severity", 3)
                if severity <= MIN_SEVERITY:
                    ship_alert({
                        "timestamp": event.get("timestamp"),
                        "src_ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "proto": event.get("proto"),
                        "signature": event["alert"].get("signature"),
                        "category": event["alert"].get("category"),
                        "severity": severity
                    })
        except json.JSONDecodeError:
            continue


if __name__ == "__main__":
    main()
