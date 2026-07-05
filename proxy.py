#!/usr/bin/env python3
"""proxy — universal translating proxy backed by a canonical hub.

Routes requests between LLM protocols declared explicitly in config:
`when.protocol` (inbound) and `then.protocol` (outbound, defaulting to inbound).
When inbound and outbound protocols are equal, bytes pass through verbatim.
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
from requests.exceptions import ChunkedEncodingError

from yahp_common import (
    Config,
    match_rule, read_chunked_body,
    get_system_ca_bundle,
)
from conversation_logger import ConversationLogger
from strategies import (
    REGISTRY, get_strategy, available_protocols,
    resolve_protocols, validate_rules, ConfigError,
)
from strategies.base import OP_MESSAGES, OP_MODELS, OP_OTHER, MalformedRequestError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr,
)
logger = logging.getLogger('proxy')

VERY_VERBOSE = False

HOP_BY_HOP = {'connection', 'transfer-encoding', 'content-length', 'host', 'keep-alive'}


# --- header / path helpers ------------------------------------------------

def strip_pseudo_and_hop(headers: dict[str, str]) -> dict[str, str]:
    """Drop HTTP/2 pseudo-headers and hop-by-hop headers."""
    return {
        k: v for k, v in headers.items()
        if not k.startswith(':') and k.lower() not in HOP_BY_HOP
    }


def extract_credential(headers: dict[str, str]) -> str | None:
    """Pull the API credential from either Anthropic or OpenAI style headers."""
    for k, v in headers.items():
        lower = k.lower()
        if lower == 'x-api-key':
            return v
        if lower == 'authorization' and v.lower().startswith('bearer '):
            return v[len('bearer '):]
    return None


def build_translated_headers(raw_headers: dict[str, str], outbound_name: str,
                             target_host: str, body_len: int) -> dict[str, str]:
    """Build forwarded headers, normalizing auth to the outbound protocol's style."""
    forwarded = {
        k: v for k, v in strip_pseudo_and_hop(raw_headers).items()
        if k.lower() not in ('x-api-key', 'authorization', 'anthropic-version',
                             'anthropic-beta', 'content-type')
    }
    credential = extract_credential(raw_headers)
    if credential:
        if outbound_name == 'anthropic':
            forwarded['x-api-key'] = credential
            forwarded.setdefault('anthropic-version',
                                 raw_headers.get('anthropic-version', '2023-06-01'))
            logger.debug(f"[HEADER ADD] x-api-key: {credential!r}")
            if 'anthropic-version' in forwarded:
                logger.debug(f"[HEADER ADD] anthropic-version: {forwarded['anthropic-version']!r}")
        else:
            forwarded['Authorization'] = f'Bearer {credential}'
            logger.debug(f"[HEADER ADD] Authorization: Bearer {credential!r}")
    forwarded['Host'] = target_host
    forwarded['Content-Type'] = 'application/json'
    forwarded['Content-Length'] = str(body_len)
    logger.debug(f"[HEADER SET] Host: {target_host!r}, Content-Length: {body_len!r}")
    return forwarded


def build_upstream_path(rewritten_path: str, inbound, outbound, operation: str) -> str:
    """Map the (prefix-rewritten) inbound path to the outbound protocol's endpoint.

    For same-protocol routing the path is returned unchanged. Otherwise the
    inbound endpoint suffix is replaced by the outbound protocol's suffix.
    """
    if inbound.name == outbound.name or operation == OP_OTHER:
        return rewritten_path

    base, sep, query = rewritten_path.partition('?')
    in_suffix = inbound.endpoint_suffix(operation)
    out_suffix = outbound.endpoint_suffix(operation)
    if in_suffix and base.endswith(in_suffix):
        base = base[: -len(in_suffix)] + out_suffix
    return base + (sep + query if sep else '')


# --- dispatcher -----------------------------------------------------------

def create_request_handler(config: Config, conv_logger: ConversationLogger) -> type:

    class Handler(BaseHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            self.config = config
            super().__init__(*args, **kwargs)

        # --- HTTP verb entrypoints ------------------------------------

        def do_POST(self):
            self._dispatch('POST')

        def do_GET(self):
            self._dispatch('GET')

        def do_PUT(self):
            self._dispatch('PUT')

        def do_DELETE(self):
            self._dispatch('DELETE')

        def do_PATCH(self):
            self._dispatch('PATCH')

        def log_message(self, fmt, *args):
            logger.info(fmt % args)

        # --- request reading ------------------------------------------

        def _raw_headers(self, method: str) -> dict[str, str]:
            raw = {k: v for k, v in self.headers.items()}
            raw[':path'] = self.path
            raw[':method'] = method
            return raw

        def _read_body(self) -> bytes:
            content_length = int(self.headers.get('Content-Length', 0))
            transfer_encoding = self.headers.get('Transfer-Encoding', '').lower()
            if 'chunked' in transfer_encoding:
                return read_chunked_body(self.rfile)
            return self.rfile.read(content_length) if content_length > 0 else b''

        # --- dispatch core --------------------------------------------

        def _dispatch(self, method: str):
            request_time = datetime.now().astimezone().isoformat()
            raw_headers = self._raw_headers(method)
            body_bytes = self._read_body() if method == 'POST' else b''

            inbound_model = self._peek_model(body_bytes)
            matched = match_rule(self.config, raw_headers, model=inbound_model)
            matched_rule, target_host, target_scheme, modified_headers = matched
            if not matched_rule:
                self._send_error(404, "No matching rule found")
                return

            inbound_name, outbound_name = resolve_protocols(matched_rule)
            inbound = get_strategy(inbound_name)
            outbound = get_strategy(outbound_name)
            operation = inbound.classify(self.path)
            rule_id = self.config.get_rule_id(matched_rule)
            rule_name = matched_rule.get('name', '')
            logger.info(f"Matched rule: {rule_name} "
                        f"[{inbound_name}->{outbound_name}] op={operation}")
            self._log_model_for_routing(inbound_model, matched_rule, rule_name)

            ctx = _ExchangeContext(
                request_time=request_time, rule_id=rule_id,
                raw_headers=raw_headers, modified_headers=modified_headers,
                target_host=target_host, target_scheme=target_scheme,
                inbound=inbound, outbound=outbound, operation=operation,
                body_bytes=body_bytes, matched_rule=matched_rule,
                rule_name=rule_name,
            )

            if inbound_name == outbound_name:
                self._handle_verbatim(ctx)
            else:
                self._handle_translated(ctx)

        def _peek_model(self, body_bytes: bytes):
            if not body_bytes:
                return None
            try:
                model = json.loads(body_bytes).get('model')
                if model:
                    logger.info(f"[INBOUND] model={model}")
                return model
            except (json.JSONDecodeError, AttributeError):
                return None

        def _log_model_for_routing(self, model: str | None, matched_rule: dict, rule_name: str) -> None:
            """Log the model only when it actually drove the routing decision.

            A rule's `when.model` makes the model a matching condition; that is the
            only case where the model participated in choosing this rule.
            """
            if model and matched_rule.get('when', {}).get('model'):
                logger.info(f"[ROUTING] model={model} matched rule={rule_name}")

        # --- verbatim same-protocol fast-path -------------------------

        def _handle_verbatim(self, ctx: '_ExchangeContext'):
            upstream_path = ctx.modified_headers.get(':path', self.path)
            forwarded = strip_pseudo_and_hop(ctx.modified_headers)
            forwarded['Host'] = ctx.target_host

            conv_logger.log_request(
                ctx.request_time, ctx.rule_id,
                original_headers={':method': ctx.raw_headers[':method'],
                                  'Content-Type': self.headers.get('Content-Type', '')},
                forwarded_headers=forwarded, path=upstream_path,
                body=ctx.body_bytes, raw_headers=ctx.raw_headers,
                rule_name=ctx.rule_name,
            )

            try:
                response = self._forward(ctx, upstream_path, forwarded)
            except Exception as e:
                logger.error(f"Failed to forward request: {e}")
                self._send_error(502, f"Failed to forward request: {e}")
                return

            if self._is_event_stream(response):
                self._relay_stream_verbatim(response, ctx)
            else:
                self._relay_unary_verbatim(response, ctx)

        def _relay_unary_verbatim(self, response, ctx):
            response.content  # trigger read
            conv_logger.log_response(ctx.request_time, ctx.rule_id, response, ctx.raw_headers, ctx.rule_name)
            self.send_response(response.status_code)
            for k, v in response.headers.items():
                if k.lower() not in ('transfer-encoding', 'content-encoding'):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(response.content)

        def _relay_stream_verbatim(self, response, ctx):
            raw_lines = []
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            try:
                for raw_line in response.iter_lines(decode_unicode=True):
                    if raw_line:
                        raw_lines.append(raw_line)
                    line_bytes = (raw_line + '\n').encode()
                    self.wfile.write(f"{len(line_bytes):X}\r\n".encode())
                    self.wfile.write(line_bytes + b"\r\n")
            except ChunkedEncodingError as e:
                logger.warning(f"[STREAM] upstream closed early: {e}")
            self.wfile.write(b"0\r\n\r\n")

            self._log_stream_response(response, raw_lines, ctx)

        # --- cross-protocol translated path (Slices 2-5) --------------

        def _handle_translated(self, ctx: '_ExchangeContext'):
            if ctx.operation == OP_OTHER:
                self._handle_verbatim(ctx)
                return
            if ctx.operation == OP_MODELS:
                self._handle_translated_models(ctx)
                return
            try:
                inbound_body = json.loads(ctx.body_bytes)
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON request body")
                return

            try:
                out_bytes, want_stream = self._translate_request(ctx, inbound_body)
            except MalformedRequestError as e:
                self._send_error(400, f"Malformed request: {e}")
                return
            ctx.body_bytes = out_bytes
            upstream_path = build_upstream_path(
                ctx.modified_headers.get(':path', self.path),
                ctx.inbound, ctx.outbound, ctx.operation,
            )
            forwarded = build_translated_headers(
                ctx.modified_headers, ctx.outbound.name, ctx.target_host, len(out_bytes)
            )

            conv_logger.log_request(
                ctx.request_time, ctx.rule_id,
                original_headers={':method': 'POST', 'Content-Type': 'application/json'},
                forwarded_headers=forwarded, path=upstream_path,
                body=out_bytes, raw_headers=ctx.raw_headers,
                rule_name=ctx.rule_name,
            )

            try:
                response = self._forward(ctx, upstream_path, forwarded, method='POST')
            except Exception as e:
                logger.error(f"Failed to forward request: {e}")
                self._send_error(502, f"Failed to forward request: {e}")
                return

            if want_stream:
                self._handle_translated_stream(response, ctx)
            else:
                self._handle_translated_unary(response, ctx)

        def _handle_translated_models(self, ctx: '_ExchangeContext'):
            upstream_path = build_upstream_path(
                ctx.modified_headers.get(':path', self.path),
                ctx.inbound, ctx.outbound, ctx.operation,
            )
            forwarded = strip_pseudo_and_hop(ctx.modified_headers)
            for h in ('x-api-key', 'authorization', 'anthropic-version',
                      'anthropic-beta', 'content-type', 'content-length'):
                forwarded = {k: v for k, v in forwarded.items() if k.lower() != h}
            credential = extract_credential(ctx.modified_headers)
            if credential:
                if ctx.outbound.name == 'anthropic':
                    forwarded['x-api-key'] = credential
                    forwarded.setdefault('anthropic-version', '2023-06-01')
                    logger.debug(f"[HEADER ADD] x-api-key: {credential!r}")
                else:
                    forwarded['Authorization'] = f'Bearer {credential}'
                    logger.debug(f"[HEADER ADD] Authorization: Bearer {credential!r}")
            forwarded['Host'] = ctx.target_host
            logger.debug(f"[HEADER SET] Host: {ctx.target_host!r}")

            conv_logger.log_request(
                ctx.request_time, ctx.rule_id,
                original_headers={':method': 'GET'},
                forwarded_headers=forwarded, path=upstream_path,
                body=b'', raw_headers=ctx.raw_headers,
                rule_name=ctx.rule_name,
            )
            try:
                response = self._forward(ctx, upstream_path, forwarded)
            except Exception as e:
                logger.error(f"Failed to forward request: {e}")
                self._send_error(502, f"Failed to forward request: {e}")
                return

            response.content  # trigger read
            conv_logger.log_response(ctx.request_time, ctx.rule_id, response, ctx.raw_headers, ctx.rule_name)

            if response.status_code != 200:
                self.send_response(response.status_code)
                for k, v in response.headers.items():
                    if k.lower() not in ('transfer-encoding', 'content-encoding'):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(response.content)
                return

            try:
                canonical = ctx.outbound.parse_model_list(json.loads(response.content))
                out_body = ctx.inbound.serialize_model_list(canonical)
                out_bytes = json.dumps(out_body).encode()
            except Exception as e:
                logger.error(f"Failed to translate model list: {e}")
                self._send_error(502, f"Failed to translate model list: {e}")
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(out_bytes)))
            self.end_headers()
            self.wfile.write(out_bytes)

        def _translate_request(self, ctx, inbound_body: dict) -> tuple[bytes, bool]:
            """Parse inbound body into canonical, apply model override, serialize outbound."""
            canonical_req = ctx.inbound.parse_request(inbound_body)
            if canonical_req.extra:
                logger.warning(f"[EXTRA-FIELDS] forwarding unknown fields: {sorted(canonical_req.extra)}")
            override = ctx.matched_rule.get('then', {}).get('model')
            if override:
                logger.info(f"[MODEL-OVERRIDE] {canonical_req.model} -> {override}")
                canonical_req.model = override
            out_body = ctx.outbound.serialize_request(canonical_req)
            return json.dumps(out_body).encode(), canonical_req.stream

        def _handle_translated_unary(self, response, ctx):
            response.content  # trigger read
            conv_logger.log_response(ctx.request_time, ctx.rule_id, response, ctx.raw_headers, ctx.rule_name)

            if response.status_code != 200:
                self.send_response(response.status_code)
                for k, v in response.headers.items():
                    if k.lower() not in ('transfer-encoding', 'content-encoding'):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(response.content)
                return
            try:
                canonical_resp = ctx.outbound.parse_response(json.loads(response.content))
                inbound_body = ctx.inbound.serialize_response(canonical_resp)
                out_bytes = json.dumps(inbound_body).encode()
            except Exception as e:
                logger.error(f"Failed to translate response: {e}")
                self._send_error(502, f"Failed to translate response: {e}")
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(out_bytes)))
            self.end_headers()
            self.wfile.write(out_bytes)

        def _handle_translated_stream(self, response, ctx):
            if response.status_code != 200:
                self._relay_unary_verbatim(response, ctx)
                return

            raw_lines = []

            def _tee_lines():
                for line in response.iter_lines(decode_unicode=True):
                    if line:
                        raw_lines.append(line)
                    yield line

            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            try:
                events = ctx.outbound.iter_parse_stream(_tee_lines())
                for sse_bytes in ctx.inbound.iter_serialize_stream(events):
                    self.wfile.write(f"{len(sse_bytes):X}\r\n".encode())
                    self.wfile.write(sse_bytes + b"\r\n")
            except ChunkedEncodingError as e:
                logger.warning(f"[STREAM] upstream closed early: {e}")
            self.wfile.write(b"0\r\n\r\n")

            self._log_stream_response(response, raw_lines, ctx)

        # --- forwarding -----------------------------------------------

        def _forward(self, ctx, upstream_path: str, forwarded: dict, method: str = None):
            method = method or ctx.raw_headers[':method']
            url = f"{ctx.target_scheme}://{ctx.target_host}{upstream_path}"
            logger.info(f"path: {self.path} -> {upstream_path} on {ctx.target_host}")
            ca_bundle = get_system_ca_bundle()
            send_headers = {k: v for k, v in forwarded.items() if k.lower() != 'host'}
            return requests.request(
                method=method, url=url, headers=send_headers,
                data=ctx.body_bytes if method == 'POST' else None,
                allow_redirects=False, timeout=120, stream=True,
                verify=ca_bundle if ca_bundle else True,
            )

        @staticmethod
        def _is_event_stream(response) -> bool:
            ct = response.headers.get('Content-Type', '').lower()
            te = response.headers.get('Transfer-Encoding', '').lower()
            return 'text/event-stream' in ct or 'chunked' in te

        def _log_stream_response(self, response, raw_lines, ctx):
            raw_body = '\n'.join(raw_lines).encode()

            class _FakeStreamResponse:
                status_code = response.status_code
                headers = dict(response.headers)
                content = raw_body

            conv_logger.log_response(ctx.request_time, ctx.rule_id, _FakeStreamResponse(), ctx.raw_headers, ctx.rule_name)

        # --- error response -------------------------------------------

        def _send_error(self, code: int, msg: str):
            body = msg.encode()
            self.send_response(code)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


class _ExchangeContext:
    """Bundles per-request state passed between handler methods."""

    def __init__(self, request_time, rule_id, raw_headers, modified_headers,
                 target_host, target_scheme, inbound, outbound, operation,
                 body_bytes, matched_rule, rule_name):
        self.request_time = request_time
        self.rule_id = rule_id
        self.raw_headers = raw_headers
        self.modified_headers = modified_headers
        self.target_host = target_host
        self.target_scheme = target_scheme
        self.inbound = inbound
        self.outbound = outbound
        self.operation = operation
        self.body_bytes = body_bytes
        self.matched_rule = matched_rule
        self.rule_name = rule_name


def main():
    parser = argparse.ArgumentParser(description='universal translating proxy')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-p', '--port', type=int, default=6666, help='Port to listen on')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-vv', '--very-verbose', action='store_true', help='Verbose + headers')
    args = parser.parse_args()

    if args.very_verbose:
        logger.setLevel(logging.DEBUG)
        global VERY_VERBOSE
        VERY_VERBOSE = True
    elif args.verbose:
        logger.setLevel(logging.DEBUG)

    config = Config(args.config)
    try:
        validate_rules(config.rules)
    except ConfigError as e:
        logger.error(str(e))
        sys.exit(1)

    conv_logger = ConversationLogger(config.logs_path)
    handler_class = create_request_handler(config, conv_logger)
    server = HTTPServer(('0.0.0.0', args.port), handler_class)
    logger.info(f"Starting universal proxy on port {args.port} "
                f"(protocols: {', '.join(available_protocols())})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.server_close()


if __name__ == '__main__':
    main()
