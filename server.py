#!/usr/bin/env python3

import sys
from argparse import ArgumentParser
from http.server import HTTPServer, BaseHTTPRequestHandler


class Server(HTTPServer):
    def __init__(self, upstream: str, *args, **kwargs):
        self.upstream = upstream
        super().__init__(*args, **kwargs)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write("Hello, world!".encode())


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = ArgumentParser()
    parser.add_argument("upstream", type=str)
    args = parser.parse_args(argv)

    httpd = Server(args.upstream, ('', 80), Handler)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
