# YAHP - Yet Another HTTP Proxy

YAHP is a small Python program that proxies HTTP requests to a set of configurable remote HTTP(S) servers, mainly LLMs. It logs all HTTP requests and responses in a structured way into a set of files for easy examination.

## Features

- Proxies HTTP requests to configurable remote HTTP(S) servers
- Logs all HTTP requests and responses in a structured way
- Configurable routing based on HTTP headers
- Support for Transfer-Encoding: chunked and streaming responses
- Support for Content-Type: text/event-stream responses
- Command-line interface for easy usage

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package installer)

### Install Dependencies

```bash
pip install pyyaml requests
```

### Make the Script Executable

```bash
chmod +x yahp.py
```

## Configuration

YAHP is configured using a YAML file located at `~/.config/yahp/config.yaml`. The configuration file specifies:

1. Routing rules for HTTP requests
2. Path for storing logs

### Example Configuration

```yaml
rules:
  -
    when:
      -
        header: :path
        prefix: /proxy/raw/anthropic
    then:
      -
        host: api.anthropic.com
        protocol: https  # Optional, defaults to https for non-localhost hosts
      -
        header: :path
        prefix: /raw/anthropic
logs-path: /home/user/.local/state/yahp/logs
```

### Configuration Format

- `rules`: List of routing rules
  - `when`: Conditions for matching a request
    - `header`: HTTP header to match
    - `prefix`: Prefix to match in the header value
  - `then`: Actions to take when a rule matches
    - `host`: Target host to forward the request to
    - `protocol`: Protocol to use (http or https). Defaults to https for non-localhost hosts and http for localhost
    - `header`: HTTP header to modify
    - `prefix`: New prefix to replace the matched prefix with
- `logs-path`: Path to store log files

## Usage

### Basic Usage

```bash
./yahp.py
```

This will start the proxy server on the default port (6666) and load the configuration from the default path (`~/.config/yahp/config.yaml`).

### Command-line Options

```bash
./yahp.py --help
```

This will display the available command-line options:

- `-c, --config`: Path to the configuration file
- `-p, --port`: Port to listen on (default: 6666)
- `-v, --verbose`: Enable verbose logging
- `-vv, --very-verbose`: Enable very verbose logging with rule matching details

### Examples

Start the proxy server on the default port:

```bash
./yahp.py
```

Start the proxy server on a custom port:

```bash
./yahp.py -p 8080
```

Use a custom configuration file:

```bash
./yahp.py -c /path/to/config.yaml
```

Enable verbose logging:

```bash
./yahp.py -v
```

## Log Files

YAHP logs all HTTP requests and responses in a structured way into files inside the configured log folder. The log files are named using the following format:

- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req.head.txt`: Request headers
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req.data.json`: Request body (if JSON)
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req.data.bin`: Request body (if not JSON)
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.res.head.txt`: Response headers
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.res.data.json`: Response body (if JSON)
- `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.res.data.bin`: Response body (if not JSON)

Where:
- `YYYY-MM-ddTHH:mm:ss.SSSZ` is the timestamp of the request
- `abcd0123` is a consistent ID derived from the matched rule

Note:
- If a request or response has no body, no body file will be created.
- For chunked or streaming responses, the proxy will stream the response to the client as it arrives from the server.

## Proxy

The `proxy-antropic-openai.py` script is an Anthropic-to-OpenAI translating proxy. It accepts Anthropic Messages API requests, translates them to OpenAI Chat Completions format, forwards to a configured OpenAI-compatible backend, and translates responses back.

### Features

- Translates Anthropic Messages API to OpenAI Chat Completions
- Translates OpenAI responses back to Anthropic format
- Supports streaming responses (SSE) with real-time translation
- Supports `/v1/models` endpoint with format translation
- Protocol auto-detection: when `protocol` is not specified in the rule, it defaults to `anthropic` if the path contains "anthropic", otherwise `openai`

### Usage

```bash
./proxy-antropic-openai.py
```

Command-line options:

- `-c, --config`: Path to the configuration file
- `-p, --port`: Port to listen on (default: 6666)
- `-v, --verbose`: Enable verbose logging
- `-vv, --very-verbose`: Enable very verbose logging

### Example Configuration

```yaml
rules:
  - name: anthropic-to-openai
    when:
      - header: :path
        prefix: /v1/messages
    then:
      - host: api.openai.com
        protocol: https
      - header: :path
        prefix: /openai/v1
logs-path: /home/user/.local/state/yahp/logs
```

## Testing

YAHP includes a comprehensive test suite. To run the tests:

```bash
python -m unittest test_yahp.py
```

## License

This project is open source and available under the [MIT License](LICENSE).