#!/bin/bash
cd /home/admin/honeypot-dashboard
sudo python3 collect_data.py
git add data.json
git commit -m "Auto update $(date '+%Y-%m-%d %H:%M')"
git push origin main
# Keep log file from growing too large
tail -100 /home/admin/honeypot-dashboard/update.log > /tmp/update.log.tmp && mv /tmp/update.log.tmp /home/admin/honeypot-dashboard/update.log
