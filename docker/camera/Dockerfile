FROM alpine:latest
RUN apk add --no-cache python3
COPY camera_server.py /camera_server.py
COPY start_camera.sh /start_camera.sh
COPY stop_camera.sh /stop_camera.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /start_camera.sh /stop_camera.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
