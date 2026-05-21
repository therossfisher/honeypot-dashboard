#!/bin/bash
cd /home/admin/honeypot-dashboard
sudo python3 collect_data.py
git add data.json
git commit -m "Auto update $(date '+%Y-%m-%d %H:%M')"
git push origin main
