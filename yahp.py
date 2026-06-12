#!/usr/bin/env python3
"""
YAHP - Yet Another HTTP Proxy

A small HTTP proxy server that routes requests to configurable remote HTTP(S) servers
and logs all requests and responses in a structured way.
"""

import argparse
import logging
import sys
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests

from yahp_common import (
    Config, FakeResponse, Rule,
    match_rule, read_chunked_body,
    resolve_logs_path, log_http_request, log_http_response, forward_request,
)

# Global variables
VERY_VERBOSE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger('yahp')


def create_request_handler(config: Config) -> type:
    class YAHPRequestHandler(BaseHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            self.rule_matched: Rule | None = None
            self.config: Config = config
            super().__init__(*args, **kwargs)

        def do_method(self, method: str) -> None:
            if VERY_VERBOSE:
                print(f"\nREQUEST RECEIVED: {method} {self.path}")

            request_time = datetime.now().astimezone().isoformat()
            request_id = int(time.time() * 1000)

            url = self.path
            headers: dict[str, str] = {k: v for k, v in self.headers.items()}

            headers[':path'] = url
            headers[':method'] = method

            content_length = int(self.headers.get('Content-Length', 0))
            transfer_encoding = self.headers.get('Transfer-Encoding', '').lower()

            if 'chunked' in transfer_encoding:
                body = read_chunked_body(self.rfile)
            else:
                body = self.rfile.read(content_length) if content_length > 0 else b''

            if VERY_VERBOSE:
                print(f"BEFORE MATCH_RULE - path: {headers.get(':path', 'unknown')}")

            matched_rule, target_host, target_protocol, modified_headers = match_rule(self.config, headers)

            if VERY_VERBOSE:
                print(f"AFTER MATCH_RULE - matched: {matched_rule is not None}")

            if matched_rule:
                rule_id = self.config.get_rule_id(matched_rule)
                self.rule_matched = matched_rule
                logger.info(f"rule: {matched_rule.get('name', rule_id)}")

                forwarded_headers = modified_headers.copy()

                for special_header in [':path', ':method', 'Host', 'Connection', 'Transfer-Encoding']:
                    if special_header in forwarded_headers:
                        if VERY_VERBOSE:
                            logger.debug(f"Removing header: {special_header}")
                        del forwarded_headers[special_header]

                if body:
                    forwarded_headers['Content-Length'] = str(len(body))

                if target_host:
                    forwarded_headers['Host'] = target_host
                    if VERY_VERBOSE:
                        logger.debug(f"Set Host header to: {target_host}")
                else:
                    logger.warning("No host specified for forwarding request")

                logs_path = resolve_logs_path(self.config, headers)
                log_http_request(request_time, rule_id, original_headers=headers, forwarded_headers=forwarded_headers, path=modified_headers[':path'], body=body, logs_path=logs_path)

                response = forward_request(method, target_host, target_protocol, modified_headers, forwarded_headers, body)

                log_http_response(request_time, rule_id, response, logs_path=logs_path)

                is_chunked = 'Transfer-Encoding' in response.headers and 'chunked' in response.headers['Transfer-Encoding'].lower()
                is_event_stream = 'Content-Type' in response.headers and 'text/event-stream' in response.headers['Content-Type'].lower()

                if is_chunked or is_event_stream:
                    self.send_response(response.status_code)
                    self.send_header('Transfer-Encoding', 'chunked')

                    for key, value in response.headers.items():
                        if key.lower() != 'content-length':
                            self.send_header(key, value)

                    self.end_headers()

                    if isinstance(response, requests.Response) and hasattr(response, 'raw') and response.raw:
                        for chunk in response.iter_content(chunk_size=4096):
                            if chunk:
                                self.wfile.write(f"{len(chunk):X}\r\n".encode())
                                self.wfile.write(chunk + b"\r\n")
                        self.wfile.write(b"0\r\n\r\n")
                    else:
                        chunk_size = 4096
                        content = response.content
                        for i in range(0, len(content), chunk_size):
                            chunk = content[i:i+chunk_size]
                            self.wfile.write(f"{len(chunk):X}\r\n".encode())
                            self.wfile.write(chunk + b"\r\n")
                        self.wfile.write(b"0\r\n\r\n")
                else:
                    self.send_response(response.status_code)
                    for key, value in response.headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(response.content)
            else:
                logger.warning(f"No rule matched for request: {headers}")
                self.send_response(404)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'No matching rule found')

        def do_GET(self) -> None:
            self.do_method('GET')

        def do_POST(self) -> None:
            self.do_method('POST')

        def do_PUT(self) -> None:
            self.do_method('PUT')

        def do_DELETE(self) -> None:
            self.do_method('DELETE')

        def do_PATCH(self) -> None:
            self.do_method('PATCH')

        def do_HEAD(self) -> None:
            self.do_method('HEAD')

        def do_OPTIONS(self) -> None:
            self.do_method('OPTIONS')

    return YAHPRequestHandler


def main() -> None:
    parser = argparse.ArgumentParser(description='YAHP - Yet Another HTTP Proxy')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-p', '--port', type=int, default=6666, help='Port to listen on')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-vv', '--very-verbose', action='store_true', help='Enable very verbose logging with rule matching details')

    args = parser.parse_args()

    if args.very_verbose:
        logger.setLevel(logging.DEBUG)
        global VERY_VERBOSE
        VERY_VERBOSE = True
        logger.debug("Very verbose logging enabled")
        print("VERY VERBOSE MODE ENABLED - DEBUG LOGS WILL SHOW")
    elif args.verbose:
        logger.setLevel(logging.DEBUG)

    config = Config(args.config)

    handler_class = create_request_handler(config)
    server = HTTPServer(('0.0.0.0', args.port), handler_class)

    logger.info(f"Starting YAHP on port {args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down YAHP")
        server.server_close()


if __name__ == "__main__":
    main()
