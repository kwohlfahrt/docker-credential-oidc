#!/usr/bin/env python3

import json
import signal
import ssl
import sys
import io
from base64 import b64decode
from threading import Thread
from argparse import ArgumentParser
from functools import cached_property
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urlunparse
from urllib.request import urlopen


ssl_ctx = ssl.create_default_context()


def parse_prefix(s, prefix):
    if not s.startswith(prefix):
        raise ValueError(f"Expected string starting with {prefix}, got {s}")
    return s[len(prefix):]


class Server(HTTPServer):
    def __init__(self, realm: str, *args, **kwargs):
        self.realm = urlparse(realm)
        super().__init__(*args, **kwargs)


class Handler(BaseHTTPRequestHandler):
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
            self.send_response(200)
            self.end_headers()
            authorization = parse_prefix(self.headers["authorization"], "Basic ")
            _, token = b64decode(authorization).decode().split(":")

            f = io.TextIOWrapper(self.wfile)
            json.dump({"access_token": token}, f)
            f.detach()  # The HTTP server closes the file, so we must not


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
