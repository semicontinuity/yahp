#!/usr/bin/env python3
"""OpenAI Chat Completions API strategy."""

from typing import Iterator

import json

from canonical import (
    CanonicalRequest, CanonicalResponse, CanonicalStreamEvent, CanonicalModelList, CanonicalModel,
    CanonicalMessage, CanonicalUsage, ToolDef, TextBlock, ToolUseBlock, ToolResultBlock,
    StreamStart, TextDelta, ToolCallStart, ToolCallDelta, UsageDelta, StreamDone,
)
from strategies.base import Strategy, MalformedRequestError, OP_MESSAGES, OP_MODELS, OP_OTHER

# OpenAI finish_reason <-> canonical (Anthropic-shaped) stop_reason.
FINISH_TO_CANONICAL = {'stop': 'end_turn', 'tool_calls': 'tool_use', 'length': 'max_tokens'}
CANONICAL_TO_FINISH = {
    'end_turn': 'stop', 'tool_use': 'tool_calls',
    'max_tokens': 'length', 'stop_sequence': 'stop',
}

_KNOWN_REQUEST_FIELDS = {
    'model', 'messages', 'tools', 'tool_choice', 'stop',
    'max_tokens', 'temperature', 'stream',
}


def _join_text(blocks) -> str:
    return ''.join(b.text for b in blocks if isinstance(b, TextBlock))


def _parse_oai_tool_choice(tc):
    if tc is None:
        return None
    if isinstance(tc, str):
        return {'type': 'any'} if tc == 'required' else {'type': 'auto'}
    if isinstance(tc, dict) and tc.get('type') == 'function':
        return {'type': 'tool', 'name': tc.get('function', {}).get('name', '')}
    return {'type': 'auto'}


def _serialize_oai_tool_choice(tc):
    if tc is None:
        return None
    kind = tc.get('type')
    if kind == 'any':
        return 'required'
    if kind == 'tool':
        return {'type': 'function', 'function': {'name': tc.get('name', '')}}
    return 'auto'


def _oai_sse(data: dict) -> bytes:
    return f"data: {json.dumps(data)}\n\n".encode()


class OpenAIStrategy(Strategy):
    name = 'openai'

    def classify(self, path: str) -> str:
        base = path.split('?')[0]
        if base.endswith('/v1/chat/completions'):
            return OP_MESSAGES
        if base.endswith('/v1/models'):
            return OP_MODELS
        return OP_OTHER

    def endpoint_suffix(self, operation: str) -> str:
        if operation == OP_MESSAGES:
            return '/v1/chat/completions'
        if operation == OP_MODELS:
            return '/v1/models'
        return ''

    # --- non-streaming request -------------------------------------------

    def parse_request(self, body: dict) -> CanonicalRequest:
        if not isinstance(body, dict):
            raise MalformedRequestError("request body must be a JSON object")
        if not isinstance(body.get('messages', []), list):
            raise MalformedRequestError("'messages' must be a list")
        system = None
        messages = []
        for msg in body.get('messages', []):
            role = msg.get('role')
            if role == 'system':
                system = msg.get('content', '')
                continue
            if role == 'tool':
                content = [ToolResultBlock(tool_use_id=msg.get('tool_call_id', ''),
                                           content=msg.get('content', ''))]
                messages.append(CanonicalMessage(role='user', content=content))
                continue
            content = []
            for tc in msg.get('tool_calls') or []:
                fn = tc.get('function', {})
                try:
                    args = json.loads(fn.get('arguments', '{}'))
                except (json.JSONDecodeError, ValueError):
                    args = {}
                content.append(ToolUseBlock(id=tc.get('id', ''), name=fn.get('name', ''),
                                            input=args))
            if msg.get('content'):
                content.append(TextBlock(msg['content']))
            if not content:
                content = [TextBlock('')]
            messages.append(CanonicalMessage(role=role, content=content))

        tools = [
            ToolDef(name=t.get('function', {}).get('name', ''),
                    description=t.get('function', {}).get('description', ''),
                    input_schema=t.get('function', {}).get('parameters', {}))
            for t in body.get('tools', [])
        ]
        extra = {k: v for k, v in body.items() if k not in _KNOWN_REQUEST_FIELDS}
        return CanonicalRequest(
            model=body.get('model', ''),
            messages=messages,
            system=system,
            tools=tools,
            tool_choice=_parse_oai_tool_choice(body.get('tool_choice')),
            stop_sequences=self._as_list(body.get('stop')),
            max_tokens=body.get('max_tokens'),
            temperature=body.get('temperature'),
            stream=body.get('stream', False),
            extra=extra,
        )

    @staticmethod
    def _as_list(stop) -> list[str]:
        if stop is None:
            return []
        return stop if isinstance(stop, list) else [stop]

    def serialize_request(self, req: CanonicalRequest) -> dict:
        body = dict(req.extra)
        body['model'] = req.model
        body['messages'] = self._serialize_messages(req)
        if req.tools:
            body['tools'] = [
                {'type': 'function', 'function': {'name': t.name, 'description': t.description,
                                                   'parameters': t.input_schema}}
                for t in req.tools
            ]
        if req.tool_choice is not None:
            body['tool_choice'] = _serialize_oai_tool_choice(req.tool_choice)
        if req.stop_sequences:
            body['stop'] = req.stop_sequences
        if req.max_tokens is not None:
            body['max_tokens'] = req.max_tokens
        if req.temperature is not None:
            body['temperature'] = req.temperature
        body['stream'] = req.stream
        return body

    def _serialize_messages(self, req: CanonicalRequest) -> list[dict]:
        messages = []
        if req.system:
            messages.append({'role': 'system', 'content': req.system})
        for msg in req.messages:
            tool_uses = [b for b in msg.content if isinstance(b, ToolUseBlock)]
            tool_results = [b for b in msg.content if isinstance(b, ToolResultBlock)]
            if tool_results:
                for tr in tool_results:
                    messages.append({'role': 'tool', 'tool_call_id': tr.tool_use_id,
                                     'content': tr.content})
            elif tool_uses:
                tool_calls = [
                    {'id': tu.id, 'type': 'function',
                     'function': {'name': tu.name, 'arguments': json.dumps(tu.input)}}
                    for tu in tool_uses
                ]
                messages.append({'role': msg.role, 'content': _join_text(msg.content) or None,
                                  'tool_calls': tool_calls})
            else:
                messages.append({'role': msg.role, 'content': _join_text(msg.content)})
        return messages

    # --- non-streaming response ------------------------------------------

    def parse_response(self, body: dict) -> CanonicalResponse:
        if 'response' in body and isinstance(body['response'], dict):
            body = body['response']
        choice = body['choices'][0]
        message = choice.get('message', {})
        content = []
        if message.get('content'):
            content.append(TextBlock(message['content']))
        for tc in message.get('tool_calls') or []:
            fn = tc.get('function', {})
            try:
                args = json.loads(fn.get('arguments', '{}'))
            except (json.JSONDecodeError, ValueError):
                args = {}
            content.append(ToolUseBlock(id=tc.get('id', ''), name=fn.get('name', ''), input=args))

        finish = choice.get('finish_reason', 'stop')
        usage_raw = body.get('usage', {})
        return CanonicalResponse(
            id=body.get('id', ''),
            model=body.get('model', ''),
            content=content,
            stop_reason=FINISH_TO_CANONICAL.get(finish, finish),
            usage=CanonicalUsage(
                input_tokens=usage_raw.get('prompt_tokens', 0),
                output_tokens=usage_raw.get('completion_tokens', 0),
            ),
        )

    def serialize_response(self, resp: CanonicalResponse) -> dict:
        tool_uses = [b for b in resp.content if isinstance(b, ToolUseBlock)]
        message = {'role': 'assistant', 'content': _join_text(resp.content) or None}
        if tool_uses:
            message['tool_calls'] = [
                {'id': tu.id, 'type': 'function',
                 'function': {'name': tu.name, 'arguments': json.dumps(tu.input)}}
                for tu in tool_uses
            ]
        finish = CANONICAL_TO_FINISH.get(resp.stop_reason, resp.stop_reason or 'stop')
        return {
            'id': resp.id,
            'object': 'chat.completion',
            'model': resp.model,
            'choices': [{'index': 0, 'message': message, 'finish_reason': finish}],
            'usage': {
                'prompt_tokens': resp.usage.input_tokens,
                'completion_tokens': resp.usage.output_tokens,
                'total_tokens': resp.usage.input_tokens + resp.usage.output_tokens,
            },
        }

    # --- streaming (Slice 3) ---------------------------------------------

    def iter_parse_stream(self, lines: Iterator[str]) -> Iterator[CanonicalStreamEvent]:
        """Parse OpenAI SSE lines into canonical stream events."""
        started = False
        for line in lines:
            if not line.startswith('data: '):
                continue
            data = line[6:].strip()
            if data == '[DONE]':
                return
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            yield from self._handle_openai_chunk(chunk, started)
            choices = chunk.get('choices', [])
            if choices and not started and choices[0].get('delta', {}).get('role') == 'assistant':
                started = True

    def _handle_openai_chunk(self, chunk, started):
        choices = chunk.get('choices', [])
        usage = chunk.get('usage')

        if not choices:
            if usage:
                yield UsageDelta(CanonicalUsage(
                    input_tokens=usage.get('prompt_tokens', 0),
                    output_tokens=usage.get('completion_tokens', 0),
                ))
            return

        choice = choices[0]
        delta = choice.get('delta', {})
        finish_reason = choice.get('finish_reason')

        if not started and delta.get('role') == 'assistant':
            input_tokens = usage.get('prompt_tokens', 0) if usage else 0
            yield StreamStart(
                id=chunk.get('id', ''),
                model=chunk.get('model', ''),
                usage=CanonicalUsage(input_tokens=input_tokens, output_tokens=0),
            )

        content = delta.get('content')
        if content:
            yield TextDelta(text=content)

        for tc_delta in delta.get('tool_calls') or []:
            oai_idx = tc_delta.get('index', 0)
            fn = tc_delta.get('function', {})
            if fn.get('name') is not None:
                yield ToolCallStart(index=oai_idx, id=tc_delta.get('id', ''),
                                    name=fn.get('name', ''))
            args = fn.get('arguments', '')
            if args:
                yield ToolCallDelta(index=oai_idx, partial_json=args)

        if usage:
            yield UsageDelta(CanonicalUsage(
                input_tokens=usage.get('prompt_tokens', 0),
                output_tokens=usage.get('completion_tokens', 0),
            ))

        if finish_reason is not None:
            yield StreamDone(stop_reason=FINISH_TO_CANONICAL.get(finish_reason, finish_reason))

    def iter_serialize_stream(self, events: Iterator[CanonicalStreamEvent]) -> Iterator[bytes]:
        """Emit OpenAI SSE bytes from canonical stream events."""
        msg_id = ''
        model = ''

        for event in events:
            if isinstance(event, StreamStart):
                msg_id = event.id
                model = event.model
                yield _oai_sse({'id': msg_id, 'object': 'chat.completion.chunk', 'model': model,
                                 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': ''},
                                              'finish_reason': None}]})
            elif isinstance(event, TextDelta):
                yield _oai_sse({'id': msg_id, 'object': 'chat.completion.chunk', 'model': model,
                                 'choices': [{'index': 0, 'delta': {'content': event.text},
                                              'finish_reason': None}]})
            elif isinstance(event, ToolCallStart):
                yield _oai_sse({'id': msg_id, 'object': 'chat.completion.chunk', 'model': model,
                                 'choices': [{'index': 0, 'delta': {
                                     'tool_calls': [{'index': event.index, 'id': event.id,
                                                     'type': 'function',
                                                     'function': {'name': event.name,
                                                                  'arguments': ''}}]
                                 }, 'finish_reason': None}]})
            elif isinstance(event, ToolCallDelta):
                yield _oai_sse({'id': msg_id, 'object': 'chat.completion.chunk', 'model': model,
                                 'choices': [{'index': 0, 'delta': {
                                     'tool_calls': [{'index': event.index,
                                                     'function': {'arguments': event.partial_json}}]
                                 }, 'finish_reason': None}]})
            elif isinstance(event, StreamDone):
                finish = CANONICAL_TO_FINISH.get(event.stop_reason, event.stop_reason or 'stop')
                yield _oai_sse({'id': msg_id, 'object': 'chat.completion.chunk', 'model': model,
                                 'choices': [{'index': 0, 'delta': {}, 'finish_reason': finish}]})
                yield b"data: [DONE]\n\n"

    # --- model listing (Slice 5) -----------------------------------------

    def parse_model_list(self, body: dict) -> CanonicalModelList:
        models = [CanonicalModel(id=m.get('id', ''), created_unix=m.get('created', 0))
                  for m in body.get('data', [])]
        return CanonicalModelList(models=models)

    def serialize_model_list(self, model_list: CanonicalModelList) -> dict:
        return {
            'object': 'list',
            'data': [{'id': m.id, 'object': 'model', 'created': m.created_unix,
                      'owned_by': 'unknown'}
                     for m in model_list.models],
        }
