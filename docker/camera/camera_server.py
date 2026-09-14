#!/usr/bin/env python3
"""Minimal fake IP-camera HTTP service for NetMind's camera-realism demo.
Not a real video stream or real RTSP - just enough of an HTTP surface
(/stream and /snapshot endpoints) to make "is this camera actually
serving anything" a meaningfully different question from "is the
container running"."""
import http.server
import socketserver

PORT = 8080

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(b"FAKE-CAMERA-STREAM-DATA")
        elif self.path == "/snapshot":
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.end_headers()
            self.wfile.write(b"FAKE-JPEG-BYTES")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # keep container logs quiet

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()
