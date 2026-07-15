#!/bin/bash
set -e

echo "[target] Starting services..."

# Start SSH
service ssh start

# Start Nginx
nginx -g "daemon off;" &

echo "[target] SSH on port 22, Nginx on port 80"
echo "[target] Logs → /var/log/nginx/access.log (JSON)"

# Keep container alive and tail logs
tail -f /var/log/nginx/access.log /var/log/auth.log 2>/dev/null
