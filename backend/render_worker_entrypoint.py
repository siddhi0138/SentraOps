"""Render's free tier only bills/monitors "Web Services" that bind to
$PORT and answer health checks - it has no free tier for a plain
background worker. This runs the real Celery worker (+ embedded Beat,
same as the Helm chart's command) as the actual process, with a minimal
HTTP server on the side purely to satisfy Render's health check. Nothing
about the Celery worker itself changes - this is deployment plumbing, not
a feature cut.
"""

import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # keep Render's log output to the actual worker, not health pings


def _serve_health_check() -> None:
    port = int(os.environ.get("PORT", "10000"))
    HTTPServer(("0.0.0.0", port), _HealthHandler).serve_forever()


if __name__ == "__main__":
    threading.Thread(target=_serve_health_check, daemon=True).start()

    result = subprocess.run(
        ["celery", "-A", "app.celery_app", "worker", "--loglevel=info", "--pool=solo", "-B"]
    )
    sys.exit(result.returncode)
