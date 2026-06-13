import logging
import os

import requests

from yahp_common import FakeResponse

logger = logging.getLogger('yahp')


class ConversationLogger:
    def __init__(self, base_logs_path: str):
        self.base_logs_path = base_logs_path
        self._session_timestamps: dict[str, str] = {}

    def _session_ts(self, session_id: str, request_time: str) -> str:
        """Get or create timestamp for a session (first request wins)."""
        if session_id not in self._session_timestamps:
            self._session_timestamps[session_id] = request_time.replace('-', '').replace(':', '')[:15]
        return self._session_timestamps[session_id]

    def _resolve(self, headers: dict[str, str], rule_name: str, request_time: str) -> tuple[str, str | None]:
        """Resolve per-conversation logs path and agent id from request headers."""
        session_id = headers.get('x-claude-code-session-id', headers.get('X-Claude-Code-Session-Id', ''))
        agent_id = headers.get('x-claude-code-agent-id', headers.get('X-Claude-Code-Agent-Id', ''))

        if session_id:
            ts = self._session_ts(session_id, request_time)
            path = os.path.join(self.base_logs_path, f"{ts}-{session_id}")
        else:
            path = os.path.join(self.base_logs_path, rule_name)

        os.makedirs(path, exist_ok=True)
        return path, agent_id

    def log_request(self, timestamp: str, rule_id: str, original_headers: dict[str, str],
                    forwarded_headers: dict[str, str], path: str, body: bytes,
                    raw_headers: dict[str, str], rule_name: str) -> None:
        logs_path, agent_id = self._resolve(raw_headers, rule_name, timestamp)
        ts = timestamp.replace(':', '').replace('+', 'Z+').replace('-', '')
        file_suffix = f"-{agent_id}" if agent_id else ""

        header_file = os.path.join(logs_path, f"{ts}{file_suffix}.req.h.txt")
        with open(header_file, 'w') as f:
            f.write(f"{original_headers[':method']} {path} HTTP/1.1\n")
            for key, value in forwarded_headers.items():
                f.write(f"{key}: {value}\n")

        logger.info(f"> {original_headers[':method']} {path}")
        if logger.isEnabledFor(logging.DEBUG):
            for key, value in forwarded_headers.items():
                logger.debug(f">   {key}: {value}")

        if body:
            content_type = original_headers.get('content-type', original_headers.get('Content-Type', '')).lower()
            if 'application/json' in content_type or content_type.endswith('+json'):
                body_file = os.path.join(logs_path, f"{ts}{file_suffix}.req.p.json")
            elif content_type.startswith('text/'):
                body_file = os.path.join(logs_path, f"{ts}{file_suffix}.req.p.txt")
            else:
                body_file = os.path.join(logs_path, f"{ts}{file_suffix}.req.p.bin")
            with open(body_file, 'wb') as f:
                f.write(body)

    def log_response(self, timestamp: str, rule_id: str,
                     response: 'requests.Response | FakeResponse',
                     raw_headers: dict[str, str], rule_name: str) -> None:
        logs_path, agent_id = self._resolve(raw_headers, rule_name, timestamp)
        ts = timestamp.replace(':', '').replace('+', 'Z+').replace('-', '')
        file_suffix = f"-{agent_id}" if agent_id else ""

        header_file = os.path.join(logs_path, f"{ts}{file_suffix}.res.h.txt")
        with open(header_file, 'w') as f:
            f.write(f"HTTP/1.1 {response.status_code}\n")
            for key, value in response.headers.items():
                f.write(f"{key}: {value}\n")

        if response.content:
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/json' in content_type or content_type.endswith('+json'):
                body_file = os.path.join(logs_path, f"{ts}{file_suffix}.res.p.json")
            elif content_type.startswith('text/'):
                body_file = os.path.join(logs_path, f"{ts}{file_suffix}.res.p.txt")
            else:
                body_file = os.path.join(logs_path, f"{ts}{file_suffix}.res.p.bin")
            with open(body_file, 'wb') as f:
                f.write(response.content)
