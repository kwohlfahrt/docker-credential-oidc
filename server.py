#!/usr/bin/env python3

import json
import signal
import ssl
import sys
from threading import Thread
from argparse import ArgumentParser
from functools import cached_property
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urlunparse
from urllib.request import urlopen


ssl_ctx = ssl.create_default_context()

# FIXME: This is for testing, remove
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


class Server(HTTPServer):
    def __init__(self, realm: str, *args, **kwargs):
        self.realm = urlparse(realm)
        super().__init__(*args, **kwargs)


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.log_message("HEAD %s %s", self.path, self.headers)

    def do_POST(self):
        self.log_message("POST %s %s", self.path, self.headers)

    def do_GET(self):
        path = urlparse(self.path)
        if path.path == "/auth/.well-known/openid-configuration":
            self.send_response(303)
            redirect = self.server.realm._replace(
                path="/".join([self.server.realm.path, ".well-known", "openid-configuration"])
            )
            self.send_header("Location", urlunparse(redirect))
            self.end_headers()
        else:
            self.log_message("GET %s %s", self.path, self.headers)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = ArgumentParser()
    parser.add_argument("realm", type=str)
    args = parser.parse_args(argv)

    httpd = Server(args.realm, ('', 80), Handler)
    signal.signal(signal.SIGTERM, lambda *args: httpd.shutdown())

    t = Thread(target=httpd.serve_forever)
    t.start()
    t.join()

if __name__ == "__main__":
    main()
