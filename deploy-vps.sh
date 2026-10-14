#!/usr/bin/env bash
set -e

VPS_IP="${VPS_IP:-144.202.25.12}"
VPS_USER="${VPS_USER:-root}"
DEST_PATH="/opt/railpay/railpay-server"
TEMP_PATH="/tmp/railpay-server-new"

echo "==> 1. Cross-compiling railpay-server for Linux amd64..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o railpay-server-linux ./cmd/arcpay

echo "==> 2. Uploading binary to VPS (${VPS_USER}@${VPS_IP}:${TEMP_PATH})..."
# Uploading to /tmp first prevents "Text file busy" error while railpay service is active
scp railpay-server-linux "${VPS_USER}@${VPS_IP}:${TEMP_PATH}"

echo "==> 3. Moving binary and restarting railpay service..."
ssh "${VPS_USER}@${VPS_IP}" "mv ${TEMP_PATH} ${DEST_PATH} && chmod +x ${DEST_PATH} && systemctl restart railpay && systemctl status railpay --no-pager"

echo "==> 4. Verifying health check..."
sleep 1
curl -fsS "http://${VPS_IP}:8080/healthz" && echo " - Online!"
echo "==> Deployment completed successfully!"
