#!/bin/sh
set -e

CREDS_FILE="/etc/netmind-camera-creds"
if [ ! -f "$CREDS_FILE" ]; then
    echo "admin" > "$CREDS_FILE"
fi

/start_camera.sh

exec tail -f /dev/null
