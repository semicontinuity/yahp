# YAHP - Yet Another HTTP Proxy

`proxy.py` is a universal translating proxy for LLM APIs. It routes requests between configurable backends and translates between protocols (Anthropic ↔ OpenAI) through a protocol-agnostic canonical representation. When inbound and outbound protocols are the same, bytes pass through verbatim.

## Features

- Protocol translation: Anthropic ↔ OpenAI and same-protocol passthrough
- Translates non-streaming and streaming (SSE) requests and responses
- Translates `/v1/models` endpoint between protocol formats
- Configurable routing based on HTTP headers and path prefixes: routing using the first matched rule
- Model override via `then.model` in the rule
- Unknown request fields forwarded best-effort with a logged warning
- Structurally malformed input rejected (400) without forwarding
- Unrecognized endpoints passed through verbatim

## Installation

### Prerequisites

- Python 3.10 or higher

### Install Dependencies

```bash
pip install pyyaml requests
```

## Usage

```bash
./proxy.py [-c config.yaml] [-p port] [-v] [-vv]
```

- `-c, --config`: Path to the configuration file (default: `~/.config/yahp/config.yaml`)
- `-p, --port`: Port to listen on (default: 6666)
- `-v, --verbose`: Enable verbose logging
- `-vv, --very-verbose`: Enable very verbose logging

## Configuration

Configuration is a YAML file. Each rule must declare `when.protocol`; `then.protocol` defaults to `when.protocol`.

### Example: Anthropic → OpenAI translation for specific model

```yaml
rules:
  - name: anthropic-to-openai
    when:
      path_prefix: /proxy/anthropic/
      protocol: anthropic
      model: haiku
    then:
      host: api.openai.com
      path_prefix: /
      protocol: openai
      model: gpt-4o          # optional: override the forwarded model name
logs-path: /home/user/.local/state/yahp/logs
```

### Same-protocol passthrough for other models

```yaml
rules:
  - name: anthropic-direct
    when:
      path_prefix: /proxy/anthropic/
      protocol: anthropic
    then:
      host: api.anthropic.com
      path_prefix: /
logs-path: /home/user/.local/state/yahp/logs
```

## Log Files

All requests and responses are logged under `logs-path`:

- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req.head.txt`: Request headers
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req.data.json`: Request body (if JSON)
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req.data.bin`: Request body (if binary)
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.res.head.txt`: Response headers
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.res.data.json`: Response body (if JSON)
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.res.data.bin`: Response body (if binary)

`abcd0123` is a consistent ID derived from the matched rule.

## License

This project is open source and available under the [MIT License](LICENSE).
