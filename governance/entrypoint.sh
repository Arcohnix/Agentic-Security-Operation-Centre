#!/bin/bash
set -e

echo "=========================================="
echo "  Agentic Governance — Real Traffic Mode"
echo "=========================================="
echo "TARGET_IP        : ${TARGET_IP}"
echo "NETWORK_INTERFACE: ${NETWORK_INTERFACE}"
echo "DASHBOARD_PORT   : ${DASHBOARD_PORT}"
echo ""

# Wait for target server to be reachable
echo "[entrypoint] Waiting for target server at ${TARGET_IP}..."
for i in $(seq 1 15); do
    if curl -sf "http://${TARGET_IP}/" > /dev/null 2>&1; then
        echo "[entrypoint] Target reachable."
        break
    fi
    echo "[entrypoint] Attempt $i/15 — target not ready yet, waiting..."
    sleep 2
done

echo "[entrypoint] Starting real traffic bridge..."
exec python -u /app/real_traffic_bridge.py
