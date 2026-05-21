# Honeypot Threat Intelligence Dashboard

Live dashboard: https://dashboard.therossfisher.xyz

## Overview
Real-time threat intelligence dashboard powered by an internet-facing 
Raspberry Pi 4 honeypot stack. Data updates every 5 minutes.

## Stack
- **Raspberry Pi 4** — Raspberry Pi OS Lite 64-bit
- **Cowrie 2.3** — SSH/Telnet honeypot capturing attacker credentials 
  and commands
- **Suricata 7** — IDS with Emerging Threats ruleset (50,000+ signatures)
- **DShield/ISC** — SANS Internet Storm Center honeypot sensor
- **GitHub Pages** — Dashboard hosting with auto-push via cron

## Data Sources
- `cowrie.json` — SSH login attempts, credentials tried, commands run
- `eve.json` — Suricata IDS alerts by severity and signature
- `dshield.log` — Raw firewall connection logs

## How It Works
A Python collector script runs every 5 minutes via cron, reads all 
three log sources, outputs `data.json`, and pushes to GitHub. 
GitHub Pages serves the static dashboard which fetches the JSON 
and renders live stats.

## Related
- [homelab-suricata-ids](https://github.com/therossfisher/homelab-suricata-ids) 
  — Full stack documentation and setup notes
