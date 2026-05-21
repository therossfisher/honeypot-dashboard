#!/usr/bin/env python3
"""
Honeypot Dashboard Data Collector
Reads Cowrie, Suricata, and DShield logs and outputs data.json
for the honeypot-dashboard GitHub Pages site.
"""
 
import json
import re
import os
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict
 
# Log file paths
COWRIE_JSON = "/srv/cowrie/var/log/cowrie/cowrie.json"
SURICATA_JSON = "/var/log/suricata/eve.json"
DSHIELD_LOG = "/var/log/dshield.log"
OUTPUT_FILE = "/home/admin/honeypot-dashboard/data.json"
 
def parse_cowrie():
    """Parse Cowrie JSON log for SSH honeypot stats."""
    stats = {
        "total_connections": 0,
        "total_login_attempts": 0,
        "successful_logins": 0,
        "unique_ips": set(),
        "top_usernames": Counter(),
        "top_passwords": Counter(),
        "top_ips": Counter(),
        "attacker_sessions": [],
        "recent_attempts": []
    }
 
    if not os.path.exists(COWRIE_JSON):
        return stats
 
    today = datetime.now().date()
    sessions = defaultdict(lambda: {"ip": "", "commands": [], "login": None})
 
    try:
        with open(COWRIE_JSON, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
 
                ts = event.get("timestamp", "")
                try:
                    event_date = datetime.fromisoformat(
                        ts.replace("Z", "+00:00")
                    ).date()
                    if event_date != today:
                        continue
                except Exception:
                    continue
 
                eid = event.get("eventid", "")
                src_ip = event.get("src_ip", "")
                session = event.get("session", "")
 
                if eid == "cowrie.session.connect":
                    stats["total_connections"] += 1
                    stats["unique_ips"].add(src_ip)
                    stats["top_ips"][src_ip] += 1
                    sessions[session]["ip"] = src_ip
 
                elif eid in ("cowrie.login.failed", "cowrie.login.success"):
                    stats["total_login_attempts"] += 1
                    username = event.get("username", "")
                    password = event.get("password", "")
                    stats["top_usernames"][username] += 1
                    stats["top_passwords"][password] += 1
 
                    if eid == "cowrie.login.success":
                        stats["successful_logins"] += 1
                        sessions[session]["login"] = {
                            "username": username,
                            "password": password,
                            "ip": src_ip,
                            "time": ts
                        }
 
                    stats["recent_attempts"].append({
                        "time": ts[11:19],
                        "ip": src_ip,
                        "username": username,
                        "password": password,
                        "success": eid == "cowrie.login.success"
                    })
 
                elif eid == "cowrie.command.input":
                    cmd = event.get("input", "")
                    sessions[session]["commands"].append(cmd)
 
    except Exception as e:
        print(f"Error parsing Cowrie log: {e}")
 
    # Build attacker sessions (those who got in)
    for sid, sdata in sessions.items():
        if sdata.get("login") and sdata.get("commands"):
            stats["attacker_sessions"].append({
                "ip": sdata["login"]["ip"],
                "username": sdata["login"]["username"],
                "password": sdata["login"]["password"],
                "time": sdata["login"]["time"][11:19],
                "commands": sdata["commands"][:10]
            })
 
    stats["unique_ips"] = len(stats["unique_ips"])
    stats["top_usernames"] = stats["top_usernames"].most_common(10)
    stats["top_passwords"] = stats["top_passwords"].most_common(10)
    stats["top_ips"] = stats["top_ips"].most_common(10)
    stats["recent_attempts"] = stats["recent_attempts"][-20:]
 
    return stats
 
 
def parse_suricata():
    """Parse Suricata eve.json for IDS alert stats."""
    stats = {
        "total_alerts": 0,
        "alerts_by_severity": Counter(),
        "top_signatures": Counter(),
        "top_src_ips": Counter(),
        "recent_alerts": []
    }
 
    if not os.path.exists(SURICATA_JSON):
        return stats
 
    cutoff = datetime.now() - timedelta(hours=24)
    alert_count = 0
 
    try:
        with open(SURICATA_JSON, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
 
                if event.get("event_type") != "alert":
                    continue
                alert_count += 1
                ts = event.get("timestamp", "")
                try:
                    event_dt = datetime.fromisoformat(ts).replace(tzinfo=None)
                    if event_dt < cutoff:
                        continue
                except Exception:
                    continue
 
                alert = event.get("alert", {})
                severity = alert.get("severity", 3)
                signature = alert.get("signature", "Unknown")
                src_ip = event.get("src_ip", "")
 
                stats["total_alerts"] += 1
                stats["alerts_by_severity"][str(severity)] += 1
                stats["top_signatures"][signature] += 1
                stats["top_src_ips"][src_ip] += 1
 
                stats["recent_alerts"].append({
                    "time": ts[11:19],
                    "severity": severity,
                    "signature": signature,
                    "src_ip": src_ip,
                    "dest_port": event.get("dest_port", "")
                })
 
    except Exception as e:
        print(f"Error parsing Suricata log: {e}")
 
    stats["alerts_by_severity"] = dict(stats["alerts_by_severity"])
    stats["top_signatures"] = stats["top_signatures"].most_common(10)
    stats["top_src_ips"] = stats["top_src_ips"].most_common(10)
    stats["recent_alerts"] = stats["recent_alerts"][-20:]
 
    return stats
 
 
def parse_dshield():
    """Parse DShield firewall log for connection stats."""
    stats = {
        "total_connections": 0,
        "unique_ips": set(),
        "top_src_ips": Counter(),
        "top_dest_ports": Counter(),
        "recent_connections": []
    }
 
    if not os.path.exists(DSHIELD_LOG):
        return stats
 
    # DShield log format: timestamp hostname kernel: DSHIELDINPUT ... SRC=x DST=x ... DPT=x
    src_re = re.compile(r'SRC=(\S+)')
    dpt_re = re.compile(r'DPT=(\d+)')
    ts_re = re.compile(r'^(\d+)')
 
    try:
        with open(DSHIELD_LOG, "r") as f:
            for line in f:
                if "DSHIELDINPUT" not in line:
                    continue
 
                src_match = src_re.search(line)
                dpt_match = dpt_re.search(line)
 
                if not src_match:
                    continue
 
                src_ip = src_match.group(1)
                dest_port = dpt_match.group(1) if dpt_match else "?"
 
                stats["total_connections"] += 1
                stats["unique_ips"].add(src_ip)
                stats["top_src_ips"][src_ip] += 1
                stats["top_dest_ports"][dest_port] += 1
 
                stats["recent_connections"].append({
                    "src_ip": src_ip,
                    "dest_port": dest_port
                })
 
    except Exception as e:
        print(f"Error parsing DShield log: {e}")
 
    stats["unique_ips"] = len(stats["unique_ips"])
    stats["top_src_ips"] = stats["top_src_ips"].most_common(10)
    stats["top_dest_ports"] = stats["top_dest_ports"].most_common(10)
    stats["recent_connections"] = stats["recent_connections"][-20:]
 
    return stats
 
 
def main():
    print(f"Collecting data at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
 
    data = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "last_updated_local": datetime.now().strftime("%Y-%m-%d %H:%M:%S PDT"),
        "cowrie": parse_cowrie(),
        "suricata": parse_suricata(),
        "dshield": parse_dshield()
    }
 
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
 
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
 
    print(f"Data written to {OUTPUT_FILE}")
    print(f"  Cowrie: {data['cowrie']['total_login_attempts']} login attempts today")
    print(f"  Suricata: {data['suricata']['total_alerts']} alerts today")
    print(f"  DShield: {data['dshield']['total_connections']} firewall hits today")
 
 
if __name__ == "__main__":
    main()
 
