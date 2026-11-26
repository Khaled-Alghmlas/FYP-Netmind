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

class Server(socketserver.TCPServer):
    # The server closes every connection itself, so each request leaves a socket in TIME_WAIT on
    # port 8080 for about a minute. NetMind's collector checks /snapshot every few seconds, so
    # without this a stream that is stopped and started again could not bind the port and stayed
    # down ("Address already in use").
    allow_reuse_address = True


if __name__ == "__main__":
    with Server(("", PORT), Handler) as httpd:
        httpd.serve_forever()
