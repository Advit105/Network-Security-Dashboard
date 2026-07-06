#!/usr/bin/env python3
"""SentinelX static dev server.

Same as `python3 -m http.server` but with explicit cache headers:
  * HTML is never cached (no-store) — you always get the current markup.
  * JS/CSS/assets must revalidate (no-cache) — combined with the ?v= version
    query on every asset reference, a plain reload always picks up changes.
Plain http.server sends no Cache-Control at all, which lets browsers serve
stale copies from their heuristic cache — the source of every
"I don't see my changes" moment.

Usage:  python3 serve.py [port]      (default 8741)
"""
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler


class NoStaleHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        if self.path in ("/", "") or self.path.split("?")[0].endswith(".html"):
            self.send_header("Cache-Control", "no-store")
        else:
            self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def log_message(self, fmt, *args):  # quieter: one line, no timestamps
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8741
    print(f"SentinelX frontend on http://localhost:{port}")
    HTTPServer(("", port), NoStaleHandler).serve_forever()
