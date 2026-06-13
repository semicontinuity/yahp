#!/usr/bin/env python3
"""Anthropic Messages API strategy."""

import json
from typing import Iterator

from canonical import (
    CanonicalRequest, CanonicalResponse, CanonicalStreamEvent, CanonicalModelList, CanonicalModel,
    CanonicalMessage, CanonicalUsage, ToolDef, TextBlock, ToolUseBlock, ToolResultBlock,
    StreamStart, TextDelta, ToolCallStart, ToolCallDelta, UsageDelta, StreamDone,
)
from strategies.base import Strategy, MalformedRequestError, OP_MESSAGES, OP_MODELS, OP_OTHER


def _sse_bytes(event: str, data: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()

# Top-level request fields the canonical model owns; everything else is "extra".
_KNOWN_REQUEST_FIELDS = {
    'model', 'system', 'messages', 'tools', 'tool_choice', 'stop_sequences',
    'max_tokens', 'temperature', 'stream',
}


class AnthropicStrategy(Strategy):
    name = 'anthropic'

    def classify(self, path: str) -> str:
        base = path.split('?')[0]
        if base.endswith('/v1/messages'):
            return OP_MESSAGES
        if base.endswith('/v1/models'):
            return OP_MODELS
        return OP_OTHER

    def endpoint_suffix(self, operation: str) -> str:
        if operation == OP_MESSAGES:
            return '/v1/messages'
        if operation == OP_MODELS:
            return '/v1/models'
        return ''

    # --- non-streaming request -------------------------------------------

    def parse_request(self, body: dict) -> CanonicalRequest:
        if not isinstance(body, dict):
            raise MalformedRequestError("request body must be a JSON object")
        if not isinstance(body.get('messages', []), list):
            raise MalformedRequestError("'messages' must be a list")
        messages = [self._parse_message(m) for m in body.get('messages', [])]
        extra = {k: v for k, v in body.items() if k not in _KNOWN_REQUEST_FIELDS}
        tools = [
            ToolDef(name=t.get('name', ''), description=t.get('description', ''),
                    input_schema=t.get('input_schema', {}))
            for t in body.get('tools', [])
        ]
        return CanonicalRequest(
            model=body.get('model', ''),
            messages=messages,
            system=body.get('system'),
            tools=tools,
            tool_choice=body.get('tool_choice'),
            stop_sequences=list(body.get('stop_sequences', [])),
            max_tokens=body.get('max_tokens'),
            temperature=body.get('temperature'),
            stream=body.get('stream', False),
            extra=extra,
        )

    def _parse_message(self, msg: dict) -> CanonicalMessage:
        content = msg['content']
        if isinstance(content, str):
            blocks = [TextBlock(content)]
        else:
            blocks = [b for b in (self._parse_block(c) for c in content) if b is not None]
        return CanonicalMessage(role=msg['role'], content=blocks)

    def _parse_block(self, block: dict):
        kind = block.get('type')
        if kind == 'text':
            return TextBlock(block.get('text', ''))
        if kind == 'tool_use':
            return ToolUseBlock(id=block.get('id', ''), name=block.get('name', ''),
                                input=block.get('input', {}))
        if kind == 'tool_result':
            content = block.get('content', '')
            if isinstance(content, list):
                content = ''.join(b.get('text', '') for b in content if b.get('type') == 'text')
            return ToolResultBlock(tool_use_id=block.get('tool_use_id', ''), content=content)
        return None

    def serialize_request(self, req: CanonicalRequest) -> dict:
        body = dict(req.extra)
        body['model'] = req.model
        if req.system is not None:
            body['system'] = req.system
        body['messages'] = [self._serialize_message(m) for m in req.messages]
        if req.tools:
            body['tools'] = [{'name': t.name, 'description': t.description,
                               'input_schema': t.input_schema} for t in req.tools]
        if req.tool_choice is not None:
            body['tool_choice'] = req.tool_choice
        if req.stop_sequences:
            body['stop_sequences'] = req.stop_sequences
        if req.max_tokens is not None:
            body['max_tokens'] = req.max_tokens
        if req.temperature is not None:
            body['temperature'] = req.temperature
        body['stream'] = req.stream
        return body

    def _serialize_message(self, msg: CanonicalMessage) -> dict:
        return {'role': msg.role, 'content': [self._serialize_block(b) for b in msg.content]}

    def _serialize_block(self, block) -> dict:
        if isinstance(block, TextBlock):
            return {'type': 'text', 'text': block.text}
        if isinstance(block, ToolUseBlock):
            return {'type': 'tool_use', 'id': block.id, 'name': block.name, 'input': block.input}
        if isinstance(block, ToolResultBlock):
            return {'type': 'tool_result', 'tool_use_id': block.tool_use_id, 'content': block.content}
        raise ValueError(f"Unsupported content block: {block!r}")

    # --- non-streaming response ------------------------------------------

    def parse_response(self, body: dict) -> CanonicalResponse:
        content = [b for b in (self._parse_block(c) for c in body.get('content', []))
                   if b is not None]
        usage_raw = body.get('usage', {})
        return CanonicalResponse(
            id=body.get('id', ''),
            model=body.get('model', ''),
            content=content,
            stop_reason=body.get('stop_reason'),
            stop_sequence=body.get('stop_sequence'),
            usage=CanonicalUsage(
                input_tokens=usage_raw.get('input_tokens', 0),
                output_tokens=usage_raw.get('output_tokens', 0),
            ),
        )

    def serialize_response(self, resp: CanonicalResponse) -> dict:
        return {
            'id': resp.id,
            'type': 'message',
            'role': 'assistant',
            'model': resp.model,
            'content': [self._serialize_block(b) for b in resp.content],
            'stop_reason': resp.stop_reason,
            'stop_sequence': resp.stop_sequence,
            'usage': {
                'input_tokens': resp.usage.input_tokens,
                'output_tokens': resp.usage.output_tokens,
            },
        }

    # --- streaming (Slice 3) ---------------------------------------------

    def iter_parse_stream(self, lines: Iterator[str]) -> Iterator[CanonicalStreamEvent]:
        """Parse Anthropic SSE lines into canonical stream events."""
        current_event = None
        for line in lines:
            if line.startswith('event: '):
                current_event = line[7:].strip()
            elif line.startswith('data: '):
                try:
                    chunk = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                yield from self._handle_anthropic_sse(current_event, chunk)

    def _handle_anthropic_sse(self, event_type, chunk):
        if event_type == 'message_start':
            msg = chunk.get('message', {})
            usage = msg.get('usage', {})
            yield StreamStart(
                id=msg.get('id', ''),
                model=msg.get('model', ''),
                usage=CanonicalUsage(
                    input_tokens=usage.get('input_tokens', 0),
                    output_tokens=usage.get('output_tokens', 0),
                ),
            )
        elif event_type == 'content_block_start':
            block = chunk.get('content_block', {})
            if block.get('type') == 'tool_use':
                yield ToolCallStart(
                    index=chunk.get('index', 0),
                    id=block.get('id', ''),
                    name=block.get('name', ''),
                )
        elif event_type == 'content_block_delta':
            delta = chunk.get('delta', {})
            if delta.get('type') == 'text_delta':
                yield TextDelta(text=delta.get('text', ''))
            elif delta.get('type') == 'input_json_delta':
                yield ToolCallDelta(index=chunk.get('index', 0),
                                    partial_json=delta.get('partial_json', ''))
        elif event_type == 'message_delta':
            delta = chunk.get('delta', {})
            usage = chunk.get('usage', {})
            yield UsageDelta(CanonicalUsage(
                input_tokens=0,
                output_tokens=usage.get('output_tokens', 0),
            ))
            yield StreamDone(
                stop_reason=delta.get('stop_reason'),
                stop_sequence=delta.get('stop_sequence'),
            )

    def iter_serialize_stream(self, events: Iterator[CanonicalStreamEvent]) -> Iterator[bytes]:
        """Emit Anthropic SSE bytes from canonical stream events."""
        block_index = -1
        block_type = None
        output_tokens = 0
        tool_index_map: dict[int, int] = {}

        for event in events:
            if isinstance(event, StreamStart):
                yield _sse_bytes('message_start', {
                    'type': 'message_start',
                    'message': {
                        'id': event.id,
                        'type': 'message',
                        'role': 'assistant',
                        'model': event.model,
                        'content': [],
                        'stop_reason': None,
                        'stop_sequence': None,
                        'usage': {'input_tokens': event.usage.input_tokens, 'output_tokens': 0},
                    },
                })
                yield _sse_bytes('ping', {'type': 'ping'})

            elif isinstance(event, TextDelta):
                if block_type != 'text':
                    if block_type is not None:
                        yield _sse_bytes('content_block_stop',
                                         {'type': 'content_block_stop', 'index': block_index})
                    block_index += 1
                    block_type = 'text'
                    yield _sse_bytes('content_block_start', {
                        'type': 'content_block_start',
                        'index': block_index,
                        'content_block': {'type': 'text', 'text': ''},
                    })
                yield _sse_bytes('content_block_delta', {
                    'type': 'content_block_delta',
                    'index': block_index,
                    'delta': {'type': 'text_delta', 'text': event.text},
                })

            elif isinstance(event, ToolCallStart):
                if block_type is not None and event.index not in tool_index_map:
                    yield _sse_bytes('content_block_stop',
                                     {'type': 'content_block_stop', 'index': block_index})
                block_index += 1
                tool_index_map[event.index] = block_index
                block_type = 'tool_use'
                yield _sse_bytes('content_block_start', {
                    'type': 'content_block_start',
                    'index': block_index,
                    'content_block': {'type': 'tool_use', 'id': event.id, 'name': event.name,
                                      'input': {}},
                })

            elif isinstance(event, ToolCallDelta):
                bi = tool_index_map.get(event.index, block_index)
                yield _sse_bytes('content_block_delta', {
                    'type': 'content_block_delta',
                    'index': bi,
                    'delta': {'type': 'input_json_delta', 'partial_json': event.partial_json},
                })

            elif isinstance(event, UsageDelta):
                output_tokens = event.usage.output_tokens

            elif isinstance(event, StreamDone):
                if block_type is not None:
                    yield _sse_bytes('content_block_stop',
                                     {'type': 'content_block_stop', 'index': block_index})
                yield _sse_bytes('message_delta', {
                    'type': 'message_delta',
                    'delta': {'stop_reason': event.stop_reason, 'stop_sequence': event.stop_sequence},
                    'usage': {'output_tokens': output_tokens},
                })
                yield _sse_bytes('message_stop', {'type': 'message_stop'})

    # --- model listing (Slice 5) -----------------------------------------

    def parse_model_list(self, body: dict) -> CanonicalModelList:
        models = [CanonicalModel(id=m.get('id', '')) for m in body.get('data', [])]
        return CanonicalModelList(models=models)

    def serialize_model_list(self, model_list: CanonicalModelList) -> dict:
        data = [{'type': 'model', 'id': m.id, 'display_name': m.id, 'created_at': ''}
                for m in model_list.models]
        return {
            'data': data,
            'has_more': False,
            'first_id': model_list.models[0].id if model_list.models else None,
            'last_id': model_list.models[-1].id if model_list.models else None,
        }
