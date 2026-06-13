#!/usr/bin/env python3
"""
proxy-antropi-openai — Anthropic-to-OpenAI translating proxy.

Accepts Anthropic Messages API requests, translates to OpenAI Chat Completions,
forwards to a configured OpenAI-compatible backend, and translates responses back.
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests

from yahp_common import (
    Config, Rule,
    match_rule, read_chunked_body,
    resolve_logs_path, log_http_request, log_http_response,
    get_system_ca_bundle,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger('proxy-antropi-openai')

FINISH_REASON_MAP = {
    'stop': 'end_turn',
    'tool_calls': 'tool_use',
    'length': 'max_tokens',
}


def translate_anthropic_to_openai(body: dict) -> dict:
    """Translate Anthropic Messages API request body to OpenAI Chat Completions format."""
    messages = []

    system = body.get('system')
    if system:
        messages.append({'role': 'system', 'content': system})

    for msg in body.get('messages', []):
        role = msg['role']
        content = msg['content']

        if role == 'user':
            if isinstance(content, str):
                messages.append({'role': 'user', 'content': content})
            else:
                tool_results = [b for b in content if b.get('type') == 'tool_result']
                text_blocks = [b for b in content if b.get('type') == 'text']

                if tool_results:
                    for tr in tool_results:
                        tr_content = tr.get('content', '')
                        if isinstance(tr_content, list):
                            tr_content = ''.join(b.get('text', '') for b in tr_content if b.get('type') == 'text')
                        messages.append({
                            'role': 'tool',
                            'tool_call_id': tr['tool_use_id'],
                            'content': tr_content,
                        })
                else:
                    text = ''.join(b.get('text', '') for b in text_blocks)
                    messages.append({'role': 'user', 'content': text})

        elif role == 'assistant':
            if isinstance(content, str):
                messages.append({'role': 'assistant', 'content': content})
            else:
                tool_use_blocks = [b for b in content if b.get('type') == 'tool_use']
                text_blocks = [b for b in content if b.get('type') == 'text']

                oai_msg: dict = {'role': 'assistant'}
                if text_blocks:
                    oai_msg['content'] = ''.join(b.get('text', '') for b in text_blocks)
                else:
                    oai_msg['content'] = None

                if tool_use_blocks:
                    oai_msg['tool_calls'] = [
                        {
                            'id': b['id'],
                            'type': 'function',
                            'function': {
                                'name': b['name'],
                                'arguments': json.dumps(b.get('input', {})),
                            },
                        }
                        for b in tool_use_blocks
                    ]

                messages.append(oai_msg)

    result = {k: v for k, v in body.items()
              if k not in ('system', 'messages', 'tools', 'tool_choice', 'stop_sequences')}
    result['messages'] = messages

    if 'tools' in body:
        result['tools'] = [
            {
                'type': 'function',
                'function': {
                    'name': t['name'],
                    'description': t.get('description', ''),
                    'parameters': t.get('input_schema', {}),
                },
            }
            for t in body['tools']
        ]

    if 'tool_choice' in body:
        tc = body['tool_choice']
        tc_type = tc.get('type')
        if tc_type == 'auto':
            result['tool_choice'] = 'auto'
        elif tc_type == 'none':
            result['tool_choice'] = 'none'
        elif tc_type == 'tool':
            result['tool_choice'] = {'type': 'function', 'function': {'name': tc['name']}}

    if 'stop_sequences' in body:
        result['stop'] = body['stop_sequences']

    return result


def translate_openai_to_anthropic(body: dict) -> dict:
    """Translate OpenAI Chat Completions response to Anthropic Messages API format."""
    choice = body['choices'][0]
    message = choice['message']
    finish_reason = choice.get('finish_reason', 'stop')

    content = []
    if message.get('content'):
        content.append({'type': 'text', 'text': message['content']})

    if message.get('tool_calls'):
        for tc in message['tool_calls']:
            fn = tc['function']
            content.append({
                'type': 'tool_use',
                'id': tc['id'],
                'name': fn['name'],
                'input': json.loads(fn['arguments']),
            })

    usage_raw = body.get('usage', {})
    usage = {
        'input_tokens': usage_raw.get('prompt_tokens', 0),
        'output_tokens': usage_raw.get('completion_tokens', 0),
    }

    return {
        'id': body.get('id', ''),
        'type': 'message',
        'role': 'assistant',
        'model': body.get('model', ''),
        'content': content,
        'stop_reason': FINISH_REASON_MAP.get(finish_reason, finish_reason),
        'stop_sequence': None,
        'usage': usage,
    }


class StreamingTranslator:
    """Translates OpenAI SSE stream to Anthropic SSE stream."""

    def __init__(self):
        self._started = False
        self._msg_id = ''
        self._model = ''
        self._input_tokens = 0
        self._output_tokens = 0
        self._current_block_index = -1
        self._current_block_type = None  # 'text' or 'tool_use'
        self._tool_call_index_map: dict[int, int] = {}  # oai tool index → anthropic block index

    def _sse(self, event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    def feed(self, data_line: str) -> list[str]:
        """Feed one OpenAI SSE data line; return list of Anthropic SSE strings to emit."""
        if data_line.strip() == '[DONE]':
            return []

        try:
            chunk = json.loads(data_line)
        except json.JSONDecodeError:
            return []

        out = []
        choices = chunk.get('choices', [])

        usage = chunk.get('usage')
        if usage:
            self._input_tokens = usage.get('prompt_tokens', self._input_tokens)
            self._output_tokens = usage.get('completion_tokens', self._output_tokens)

        if not choices:
            return out

        choice = choices[0]
        delta = choice.get('delta', {})
        finish_reason = choice.get('finish_reason')

        # First chunk: role delta
        if not self._started and delta.get('role') == 'assistant':
            self._started = True
            self._msg_id = chunk.get('id', '')
            self._model = chunk.get('model', '')
            if self._model:
                logger.info(f"[OUTBOUND-STREAM] model={self._model}")
            out.append(self._sse('message_start', {
                'type': 'message_start',
                'message': {
                    'id': self._msg_id,
                    'type': 'message',
                    'role': 'assistant',
                    'model': self._model,
                    'content': [],
                    'stop_reason': None,
                    'stop_sequence': None,
                    'usage': {'input_tokens': self._input_tokens, 'output_tokens': 0},
                },
            }))
            out.append(self._sse('ping', {'type': 'ping'}))

            # If there's also text content in this first chunk, open a text block
            if delta.get('content'):
                self._current_block_index += 1
                self._current_block_type = 'text'
                out.append(self._sse('content_block_start', {
                    'type': 'content_block_start',
                    'index': self._current_block_index,
                    'content_block': {'type': 'text', 'text': ''},
                }))
                out.append(self._sse('content_block_delta', {
                    'type': 'content_block_delta',
                    'index': self._current_block_index,
                    'delta': {'type': 'text_delta', 'text': delta['content']},
                }))

            return out

        # Text delta
        if delta.get('content') is not None and delta.get('content') != '':
            if self._current_block_type != 'text':
                if self._current_block_type is not None:
                    out.append(self._sse('content_block_stop', {
                        'type': 'content_block_stop',
                        'index': self._current_block_index,
                    }))
                self._current_block_index += 1
                self._current_block_type = 'text'
                out.append(self._sse('content_block_start', {
                    'type': 'content_block_start',
                    'index': self._current_block_index,
                    'content_block': {'type': 'text', 'text': ''},
                }))
            out.append(self._sse('content_block_delta', {
                'type': 'content_block_delta',
                'index': self._current_block_index,
                'delta': {'type': 'text_delta', 'text': delta['content']},
            }))

        # Tool call deltas
        for tc_delta in delta.get('tool_calls') or []:
            oai_idx = tc_delta.get('index', 0)

            if oai_idx not in self._tool_call_index_map:
                # New tool call block
                if self._current_block_type is not None:
                    out.append(self._sse('content_block_stop', {
                        'type': 'content_block_stop',
                        'index': self._current_block_index,
                    }))
                self._current_block_index += 1
                self._tool_call_index_map[oai_idx] = self._current_block_index
                self._current_block_type = 'tool_use'

                fn = tc_delta.get('function', {})
                out.append(self._sse('content_block_start', {
                    'type': 'content_block_start',
                    'index': self._current_block_index,
                    'content_block': {
                        'type': 'tool_use',
                        'id': tc_delta.get('id', ''),
                        'name': fn.get('name', ''),
                        'input': {},
                    },
                }))

            block_idx = self._tool_call_index_map[oai_idx]
            args_fragment = tc_delta.get('function', {}).get('arguments', '')
            if args_fragment:
                out.append(self._sse('content_block_delta', {
                    'type': 'content_block_delta',
                    'index': block_idx,
                    'delta': {'type': 'input_json_delta', 'partial_json': args_fragment},
                }))

        # Final chunk
        if finish_reason is not None:
            if self._current_block_type is not None:
                out.append(self._sse('content_block_stop', {
                    'type': 'content_block_stop',
                    'index': self._current_block_index,
                }))
            out.append(self._sse('message_delta', {
                'type': 'message_delta',
                'delta': {
                    'stop_reason': FINISH_REASON_MAP.get(finish_reason, finish_reason),
                    'stop_sequence': None,
                },
                'usage': {'output_tokens': self._output_tokens},
            }))
            out.append(self._sse('message_stop', {'type': 'message_stop'}))

        return out


def unwrap_upstream(body: dict) -> dict:
    """Unwrap upstream envelope if present (e.g. {response: {...}, ...})."""
    if 'response' in body and isinstance(body['response'], dict):
        return body['response']
    return body


def translate_openai_models_to_anthropic(body: dict) -> dict:
    """Translate OpenAI GET /v1/models response to Anthropic format."""
    models = []
    for m in body.get('data', []):
        created_unix = m.get('created', 0)
        created_at = datetime.fromtimestamp(created_unix, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        models.append({
            'type': 'model',
            'id': m['id'],
            'display_name': m['id'],
            'created_at': created_at,
        })
    data = sorted(models, key=lambda m: m['created_at'], reverse=True)
    return {
        'data': data,
        'has_more': False,
        'first_id': data[0]['id'] if data else None,
        'last_id': data[-1]['id'] if data else None,
    }


def translate_headers(headers: dict[str, str]) -> dict[str, str]:
    """Translate Anthropic request headers to OpenAI-compatible headers."""
    result = {}
    api_key = None

    for k, v in headers.items():
        lower = k.lower()
        if lower == 'x-api-key':
            api_key = v
        elif lower in ('anthropic-version', 'anthropic-beta'):
            pass  # drop
        else:
            result[k] = v

    if api_key:
        result['Authorization'] = f'Bearer {api_key}'

    return result


def create_request_handler(config: Config) -> type:
    class Handler(BaseHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            self.config = config
            super().__init__(*args, **kwargs)

        def do_POST(self):
            path_without_query = self.path.split('?')[0]
            if not path_without_query.endswith('/v1/messages'):
                self._404(f"Only paths ending in /v1/messages are supported; got POST {self.path}")
                return
            self._handle()

        def do_GET(self):
            if self.path.endswith('/v1/models'):
                self._handle_models()
            else:
                self._404(f"Unsupported path: GET {self.path}")

        def do_PUT(self): self._404(f"Only POST /v1/messages is supported")
        def do_DELETE(self): self._404(f"Only POST /v1/messages is supported")
        def do_PATCH(self): self._404(f"Only POST /v1/messages is supported")
        def do_HEAD(self): self._404(f"Only POST /v1/messages is supported")
        def do_OPTIONS(self): self._404(f"Only POST /v1/messages is supported")

        def _404(self, msg: str):
            body = msg.encode()
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> bytes:
            content_length = int(self.headers.get('Content-Length', 0))
            transfer_encoding = self.headers.get('Transfer-Encoding', '').lower()
            if 'chunked' in transfer_encoding:
                return read_chunked_body(self.rfile)
            return self.rfile.read(content_length) if content_length > 0 else b''

        def _build_outbound(self, anthropic_body: dict, matched_rule: dict, modified_headers: dict) -> tuple[str, bytes]:
            """Return (upstream_path, outbound_body_bytes)."""
            rewritten_path = modified_headers[':path']
            then = matched_rule.get('then', {})
            if 'protocol' in then:
                target_api_protocol = then['protocol']
            else:
                target_api_protocol = 'anthropic' if 'anthropic' in rewritten_path else 'openai'
            rewritten_path_base, _, rewritten_query = rewritten_path.partition('?')
            override_model = matched_rule.get('then', {}).get('model')

            if target_api_protocol == 'openai':
                upstream_path = rewritten_path_base[:-len('/v1/messages')] + '/v1/chat/completions'
                if rewritten_query:
                    upstream_path += '?' + rewritten_query
                outbound_body = translate_anthropic_to_openai(anthropic_body)
                if override_model:
                    print(f"[MODEL-OVERRIDE] {outbound_body.get('model')} -> {override_model}", file=sys.stderr, flush=True)
                    outbound_body['model'] = override_model
            else:
                upstream_path = rewritten_path
                outbound_body = dict(anthropic_body)
                if override_model:
                    print(f"[MODEL-OVERRIDE] {outbound_body.get('model')} -> {override_model}", file=sys.stderr, flush=True)
                    outbound_body['model'] = override_model

            return upstream_path, json.dumps(outbound_body).encode(), target_api_protocol

        def _build_forwarded_headers(self, raw_headers: dict, target_host: str, body_bytes: bytes) -> dict:
            forwarded_headers = translate_headers(raw_headers)
            for h in [':path', ':method', 'Host', 'Connection', 'Transfer-Encoding', 'Content-Length']:
                forwarded_headers.pop(h, None)
            forwarded_headers['Host'] = target_host
            forwarded_headers['Content-Type'] = 'application/json'
            forwarded_headers['Content-Length'] = str(len(body_bytes))
            return forwarded_headers

        def _post_upstream(self, target_protocol: str, target_host: str, upstream_path: str,
                           forwarded_headers: dict, body_bytes: bytes):
            upstream_url = f"{target_protocol}://{target_host}{upstream_path}"
            ca_bundle = get_system_ca_bundle()
            return requests.post(
                upstream_url,
                headers={k: v for k, v in forwarded_headers.items() if k != 'Host'},
                data=body_bytes,
                allow_redirects=False,
                timeout=120,
                stream=True,
                verify=ca_bundle if ca_bundle else True,
            )

        def _handle(self):
            request_time = datetime.now().astimezone().isoformat()

            raw_headers: dict[str, str] = {k: v for k, v in self.headers.items()}
            raw_headers[':path'] = self.path
            raw_headers[':method'] = 'POST'

            try:
                anthropic_body = json.loads(self._read_body())
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON request body")
                return

            inbound_model = anthropic_body.get('model')
            if inbound_model:
                logger.info(f"[INBOUND] model={inbound_model}")

            if VERY_VERBOSE:
                logger.debug("[INBOUND HEADERS]")
                for k, v in raw_headers.items():
                    logger.debug(f"  {k}: {v}")

            matched_rule, target_host, target_protocol, modified_headers = match_rule(
                self.config, raw_headers, model=inbound_model
            )
            if not matched_rule:
                self._404("No matching rule found")
                return

            rule_id = self.config.get_rule_id(matched_rule)
            logger.info(f"Matched rule: {matched_rule['name']}")

            upstream_path, outbound_body_bytes, target_api_protocol = self._build_outbound(anthropic_body, matched_rule, modified_headers)
            logger.info(f"path: {self.path} -> {upstream_path} on {target_host}")

            forwarded_headers = self._build_forwarded_headers(raw_headers, target_host, outbound_body_bytes)

            if VERY_VERBOSE:
                logger.debug("[OUTBOUND HEADERS]")
                for k, v in forwarded_headers.items():
                    logger.debug(f"  {k}: {v}")

            logs_path = resolve_logs_path(self.config, raw_headers)
            log_http_request(
                request_time, rule_id,
                original_headers={':method': 'POST', 'Content-Type': 'application/json'},
                forwarded_headers=forwarded_headers,
                path=upstream_path,
                body=outbound_body_bytes,
                logs_path=logs_path,
            )

            try:
                response = self._post_upstream(target_protocol, target_host, upstream_path,
                                               forwarded_headers, outbound_body_bytes)
            except Exception as e:
                logger.error(f"Failed to forward request: {e}")
                self._send_error(502, f"Failed to forward request: {e}")
                return

            is_streaming = anthropic_body.get('stream', False)
            if target_api_protocol == 'openai':
                if is_streaming:
                    self._handle_streaming(response, request_time, rule_id, logs_path)
                else:
                    self._handle_nonstreaming(response, request_time, rule_id, logs_path)
            else:
                if is_streaming:
                    self._handle_streaming_passthrough(response, request_time, rule_id, logs_path)
                else:
                    self._handle_nonstreaming_passthrough(response, request_time, rule_id, logs_path)

        def _handle_models(self):
            request_time = datetime.now().astimezone().isoformat()
            raw_headers: dict[str, str] = {k: v for k, v in self.headers.items()}
            raw_headers[':path'] = self.path
            raw_headers[':method'] = 'GET'

            matched_rule, target_host, target_protocol, modified_headers = match_rule(self.config, raw_headers)
            if not matched_rule:
                self._404("No matching rule found")
                return

            rule_id = self.config.get_rule_id(matched_rule)

            # Derive upstream path: replace /v1/models suffix, keeping any prefix rewrite
            rewritten_path = modified_headers[':path']
            upstream_path = rewritten_path[:-len('/v1/models')] + '/v1/models'
            logger.info(f"path: {self.path} -> {upstream_path} on {target_host}")

            forwarded_headers = translate_headers(raw_headers)
            for h in [':path', ':method', 'Host', 'Connection', 'Transfer-Encoding', 'Content-Length']:
                forwarded_headers.pop(h, None)
            forwarded_headers['Host'] = target_host

            logs_path = resolve_logs_path(self.config, raw_headers)
            log_http_request(
                request_time, rule_id,
                original_headers={':method': 'GET', 'Content-Type': 'application/json'},
                forwarded_headers=forwarded_headers,
                path=upstream_path,
                body=b'',
                logs_path=logs_path,
            )

            upstream_url = f"{target_protocol}://{target_host}{upstream_path}"
            try:
                ca_bundle = get_system_ca_bundle()
                response = requests.get(
                    upstream_url,
                    headers={k: v for k, v in forwarded_headers.items() if k != 'Host'},
                    timeout=30,
                    verify=ca_bundle if ca_bundle else True,
                )
            except Exception as e:
                logger.error(f"Failed to fetch models: {e}")
                self._send_error(502, f"Failed to fetch models: {e}")
                return

            log_http_response(request_time, rule_id, response, logs_path)
            logger.info(f"upstream models response: {response.status_code}")
            for k, v in response.headers.items():
                logger.info(f"  {k}: {v}")

            if response.status_code != 200:
                self.send_response(response.status_code)
                self.end_headers()
                self.wfile.write(response.content)
                return

            try:
                anthropic_body = translate_openai_models_to_anthropic(unwrap_upstream(response.json()))
                body_bytes = json.dumps(anthropic_body).encode()
            except Exception as e:
                self._send_error(502, f"Failed to translate models response: {e}")
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)

        def _handle_nonstreaming_passthrough(self, response, request_time, rule_id, logs_path):
            response.content
            log_http_response(request_time, rule_id, response, logs_path)
            self.send_response(response.status_code)
            for k, v in response.headers.items():
                if k.lower() not in ('transfer-encoding', 'content-encoding'):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(response.content)

        def _handle_streaming_passthrough(self, response, request_time, rule_id, logs_path):
            raw_lines = []
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            for raw_line in response.iter_lines(decode_unicode=True):
                if raw_line:
                    raw_lines.append(raw_line)
                line_bytes = (raw_line + '\n').encode()
                self.wfile.write(f"{len(line_bytes):X}\r\n".encode())
                self.wfile.write(line_bytes + b"\r\n")

            self.wfile.write(b"0\r\n\r\n")

            raw_body = '\n'.join(raw_lines).encode()

            class _FakeStreamResponse:
                status_code = response.status_code
                headers = dict(response.headers)
                content = raw_body

            log_http_response(request_time, rule_id, _FakeStreamResponse(), logs_path)

        def _handle_nonstreaming(self, response, request_time, rule_id, logs_path):
            # Read full response
            response.content  # trigger read

            log_http_response(request_time, rule_id, response, logs_path)

            if response.status_code != 200:
                self.send_response(response.status_code)
                for k, v in response.headers.items():
                    if k.lower() not in ('transfer-encoding', 'content-encoding'):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(response.content)
                return

            try:
                openai_response = unwrap_upstream(json.loads(response.content))
                anthropic_response = translate_openai_to_anthropic(openai_response)
                anthropic_bytes = json.dumps(anthropic_response).encode()
            except Exception as e:
                logger.error(f"Failed to translate response: {e}")
                self._send_error(502, f"Failed to translate response: {e}")
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(anthropic_bytes)))
            self.end_headers()
            self.wfile.write(anthropic_bytes)

        def _handle_streaming(self, response, request_time, rule_id, logs_path):
            # Collect raw SSE lines for logging while translating
            raw_lines = []
            translator = StreamingTranslator()

            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            for raw_line in response.iter_lines(decode_unicode=True):
                if raw_line:
                    raw_lines.append(raw_line)

                if raw_line.startswith('data: '):
                    data_content = raw_line[6:]
                    events = translator.feed(data_content)
                    for ev in events:
                        ev_bytes = ev.encode()
                        self.wfile.write(f"{len(ev_bytes):X}\r\n".encode())
                        self.wfile.write(ev_bytes + b"\r\n")

            self.wfile.write(b"0\r\n\r\n")

            # Log the raw upstream response
            raw_body = '\n'.join(raw_lines).encode()

            class _FakeStreamResponse:
                status_code = response.status_code
                headers = dict(response.headers)
                content = raw_body

            log_http_response(request_time, rule_id, _FakeStreamResponse(), logs_path)

        def _send_error(self, code: int, msg: str):
            body = msg.encode()
            self.send_response(code)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            logger.info(fmt % args)

    return Handler


VERY_VERBOSE = False


def main():
    parser = argparse.ArgumentParser(description='proxy-antropi-openai — Anthropic-to-OpenAI translating proxy')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-p', '--port', type=int, default=6666, help='Port to listen on')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-vv', '--very-verbose', action='store_true', help='Enable very verbose logging with headers')

    args = parser.parse_args()

    if args.very_verbose:
        logger.setLevel(logging.DEBUG)
        global VERY_VERBOSE
        VERY_VERBOSE = True
        logger.debug("Very verbose logging enabled")
        print("VERY VERBOSE MODE ENABLED - HEADERS WILL BE LOGGED")
    elif args.verbose:
        logger.setLevel(logging.DEBUG)

    config = Config(args.config)
    handler_class = create_request_handler(config)
    server = HTTPServer(('0.0.0.0', args.port), handler_class)

    logger.info(f"Starting proxy-antropi-openai on port {args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.server_close()


if __name__ == '__main__':
    main()
