#!/usr/bin/env python3
"""Shared utilities for YAHP proxies."""

import hashlib
import logging
import os
import ssl
import sys
from pathlib import Path
from typing import TypedDict

import requests
import yaml

logger = logging.getLogger('yahp')


def get_system_ca_bundle() -> str | None:
    ssl_paths = ssl.get_default_verify_paths()
    if ssl_paths.openssl_capath:
        return ssl_paths.openssl_capath
    if ssl_paths.openssl_cafile:
        return ssl_paths.openssl_cafile
    return None


class RuleCondition(TypedDict, total=False):
    path_prefix: str    # required; rule matches only if request path starts with this
    model: str          # optional; if set, rule matches only if request model equals this exactly


class RuleHeaderSet(TypedDict):
    name: str
    value: str


class RuleThen(TypedDict, total=False):
    protocol: str           # high-level: 'anthropic', 'openai', etc.
    secure: bool            # True -> https, False -> http; omit to auto-detect from host
    host: str               # required
    path_prefix: str        # replace when.path_prefix with this in the request path
    headers: list[RuleHeaderSet]
    model: str | None       # if set, override the model in the outbound request


class Rule(TypedDict, total=False):
    name: str
    when: RuleCondition
    then: RuleThen


class Config:
    def __init__(self, config_path: str | None = None):
        self.config_path: str = config_path or os.path.expanduser("~/.config/yahp/config.yaml")
        self.rules: list[Rule] = []
        self.logs_path: str = ""
        self.load_config()

    def load_config(self) -> None:
        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.error(f"Configuration file not found: {self.config_path}")
                sys.exit(1)

            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)

            self.rules = config.get('rules', [])
            self.logs_path = os.path.expanduser(config.get('logs-path', '~/.local/state/yahp/logs'))

            Path(self.logs_path).mkdir(parents=True, exist_ok=True)

            logger.info(f"Loaded configuration with {len(self.rules)} rules")
            logger.info(f"Logs will be stored in {self.logs_path}")

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)

    def get_rule_id(self, rule: Rule) -> str:
        rule_str = str(rule)
        return hashlib.md5(rule_str.encode()).hexdigest()[:8]


class FakeResponse:
    def __init__(self, status_code: int = 502, content_type: str = 'text/plain', content: str = ""):
        self.status_code = status_code
        self.headers = {'Content-Type': content_type}
        self.content = content.encode() if content else b""
        self.raw = None


def match_rule(config: Config, headers: dict[str, str], model: str | None = None) -> tuple[Rule | None, str | None, str | None, dict[str, str]]:
    for rule in config.rules:
        when = rule.get('when', {})
        then = rule.get('then', {})

        path_prefix = when.get('path_prefix', '')
        if not headers.get(':path', '').startswith(path_prefix):
            continue

        rule_model = when.get('model')
        if rule_model and model != rule_model:
            continue

        modified_headers = headers.copy()
        target_host = then.get('host')

        if 'secure' in then:
            target_scheme = 'https' if then['secure'] else 'http'
        elif target_host and ('localhost' in target_host or '127.0.0.1' in target_host):
            target_scheme = 'http'
        else:
            target_scheme = 'https'

        then_path_prefix = then.get('path_prefix')
        if then_path_prefix is not None:
            path = modified_headers.get(':path', '')
            modified_headers[':path'] = then_path_prefix + path[len(path_prefix):]

        for header_set in then.get('headers', []):
            name = header_set.get('name')
            value = header_set.get('value')
            if name and value is not None:
                modified_headers[name] = value

        return rule, target_host, target_scheme, modified_headers

    return None, None, None, headers


def read_chunked_body(rfile) -> bytes:
    body = b''
    while True:
        chunk_size_line = b''
        while True:
            byte = rfile.read(1)
            if byte == b'\n':
                break
            if byte:
                chunk_size_line += byte
            else:
                return body

        chunk_size_str = chunk_size_line.decode('ascii').strip()
        if ';' in chunk_size_str:
            chunk_size_str = chunk_size_str.split(';')[0]
        chunk_size = int(chunk_size_str, 16)

        if chunk_size == 0:
            while True:
                line = rfile.read(2)
                if line == b'\r\n' or not line:
                    break
            return body

        chunk_data = rfile.read(chunk_size)
        body += chunk_data
        rfile.read(2)


def forward_request(method: str, host: str | None, protocol: str | None,
                    headers: dict[str, str], forwarded_headers: dict[str, str],
                    body: bytes) -> requests.Response | FakeResponse:
    if not host:
        return FakeResponse(status_code=400, content_type='text/plain', content="No target host specified in rule")

    if not protocol:
        protocol = 'https' if 'localhost' not in host and '127.0.0.1' not in host else 'http'

    url = f"{protocol}://{host}{headers[':path']}"

    try:
        ca_bundle = get_system_ca_bundle()
        response = requests.request(
            method=method,
            url=url,
            headers=forwarded_headers,
            data=body,
            allow_redirects=False,
            timeout=30,
            stream=True,
            verify=ca_bundle if ca_bundle else True
        )

        is_chunked = 'Transfer-Encoding' in response.headers and 'chunked' in response.headers['Transfer-Encoding'].lower()
        is_event_stream = 'Content-Type' in response.headers and 'text/event-stream' in response.headers['Content-Type'].lower()

        if not (is_chunked or is_event_stream):
            response.content

        return response
    except Exception as e:
        logger.error(f"Failed to forward request: {e} headers={headers}")
        return FakeResponse(status_code=502, content_type='text/plain', content=f"Failed to forward request: {e}")
