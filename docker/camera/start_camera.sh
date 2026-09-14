#!/bin/sh
nohup python3 /camera_server.py > /var/log/camera.log 2>&1 &
echo $! > /var/run/camera.pid
