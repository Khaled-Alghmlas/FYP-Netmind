#!/bin/sh
if [ -f /var/run/camera.pid ]; then
    kill "$(cat /var/run/camera.pid)" 2>/dev/null || true
    rm -f /var/run/camera.pid
fi
