#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /home/admin/honeypot-dashboard

# Keep log manageable
tail -100 /home/admin/honeypot-dashboard/update.log > /tmp/update.log.tmp && mv -f /tmp/update.log.tmp /home/admin/honeypot-dashboard/update.log

# Collect data
/usr/bin/sudo /usr/bin/python3 /home/admin/honeypot-dashboard/collect_data.py

# Push to GitHub
git add data.json update.log update_dashboard.sh
git stash
git pull --rebase origin main
git stash pop
git add data.json update.log update_dashboard.sh
git commit -m "Auto update $(date '+%Y-%m-%d %H:%M')" || true
git push origin main
