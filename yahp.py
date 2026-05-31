#!/usr/bin/env python3
"""
YAHP - Yet Another HTTP Proxy

A small HTTP proxy server that routes requests to configurable remote HTTP(S) servers
and logs all requests and responses in a structured way.
"""

import argparse
import hashlib
import logging
import os
import ssl
import sys
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import TypedDict

import requests
import yaml

# Global variables
VERY_VERBOSE = False


def get_system_ca_bundle() -> str | None:
    """Get the system CA bundle path for SSL verification.

    Returns:
        Path to system CA bundle, or None to use default verification.
    """
    # Try to get system CA paths from ssl module
    ssl_paths = ssl.get_default_verify_paths()

    # Prefer capath (directory of individual certs) over cafile (bundle file)
    # This uses /usr/lib/ssl/certs instead of /usr/lib/ssl/cert.pem
    if ssl_paths.openssl_capath:
        return ssl_paths.openssl_capath
    if ssl_paths.openssl_cafile:
        return ssl_paths.openssl_cafile
    return None


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger('yahp')


class RuleCondition(TypedDict):
    header: str
    prefix: str  # Make prefix required for simplicity in tests


class RuleAction(TypedDict, total=False):  # total=False makes all fields optional
    host: str
    protocol: str  # Protocol to use (http or https)
    header: str
    prefix: str


class Rule(TypedDict):
    when: list[RuleCondition]
    then: list[RuleAction]


class Config:
    """Configuration handler for YAHP."""
    
    def __init__(self, config_path: str | None = None):
        """Initialize configuration handler.
        
        Args:
            config_path: Path to the configuration file. If None, use default path.
        """
        self.config_path: str = config_path or os.path.expanduser("~/.config/yahp/config.yaml")
        self.rules: list[Rule] = []
        self.logs_path: str = ""
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from YAML file."""
        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.error(f"Configuration file not found: {self.config_path}")
                sys.exit(1)
            
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            self.rules = config.get('rules', [])
            self.logs_path = os.path.expanduser(config.get('logs-path', '~/.local/state/yahp/logs'))
            
            # Create logs directory if it doesn't exist
            Path(self.logs_path).mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Loaded configuration with {len(self.rules)} rules")
            logger.info(f"Logs will be stored in {self.logs_path}")
        
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    def get_rule_id(self, rule: Rule) -> str:
        """Generate a consistent ID for a rule.
        
        Args:
            rule: The rule to generate an ID for.
            
        Returns:
            A hex string representing the rule.
        """
        # Convert rule to string and hash it
        rule_str = str(rule)
        return hashlib.md5(rule_str.encode()).hexdigest()[:8]


class FakeResponse:
    """Fake response object for error cases."""
    
    def __init__(self, status_code: int = 502, content_type: str = 'text/plain', content: str = ""):
        self.status_code = status_code
        self.headers = {'Content-Type': content_type}
        self.content = content.encode() if content else b""
        self.raw = None  # Add raw attribute for compatibility with requests.Response


def create_request_handler(config: Config) -> type:
    """Create a request handler class with the given configuration.
    
    Args:
        config: Configuration object.
        
    Returns:
        A request handler class.
    """
    class YAHPRequestHandler(BaseHTTPRequestHandler):
        """HTTP request handler for YAHP."""
        
        def __init__(self, *args, **kwargs):
            self.rule_matched: Rule | None = None
            self.config: Config = config  # Store config as an instance variable
            super().__init__(*args, **kwargs)
        
        def do_method(self, method: str) -> None:
            """Handle HTTP request with any method.

            Args:
                method: HTTP method (GET, POST, etc.)
            """
            if VERY_VERBOSE:
                print(f"\nREQUEST RECEIVED: {method} {self.path}")

            request_time = datetime.now().astimezone().isoformat()
            request_id = int(time.time() * 1000)

            # Parse request
            url = self.path
            headers: dict[str, str] = {k: v for k, v in self.headers.items()}

            # Add special headers for routing
            headers[':path'] = url
            headers[':method'] = method

            # Get request body
            content_length = int(self.headers.get('Content-Length', 0))
            transfer_encoding = self.headers.get('Transfer-Encoding', '').lower()
            
            # Handle chunked transfer encoding
            if 'chunked' in transfer_encoding:
                # For chunked encoding, read until we hit the end of chunked stream
                body = self.read_chunked_body()
            else:
                body = self.rfile.read(content_length) if content_length > 0 else b''
            
            # Match rule
            if VERY_VERBOSE:
                print(f"BEFORE MATCH_RULE - path: {headers.get(':path', 'unknown')}")
                
            matched_rule, target_host, target_protocol, modified_headers = self.match_rule(headers)
            
            if VERY_VERBOSE:
                print(f"AFTER MATCH_RULE - matched: {matched_rule is not None}")
            
            if matched_rule:
                rule_id = self.config.get_rule_id(matched_rule)
                self.rule_matched = matched_rule

                # Prepare headers for forwarding - do this before logging
                forwarded_headers = modified_headers.copy()

                # Remove special headers and old Host header
                for special_header in [':path', ':method', 'Host', 'Connection', 'Transfer-Encoding']:
                    if special_header in forwarded_headers:
                        if VERY_VERBOSE:
                            logger.debug(f"Removing header: {special_header}")
                        del forwarded_headers[special_header]

                # Set Content-Length header for the body we're sending
                if body:
                    forwarded_headers['Content-Length'] = str(len(body))

                # Set new Host header to the value from the config file
                if target_host:
                    forwarded_headers['Host'] = target_host
                    if VERY_VERBOSE:
                        logger.debug(f"Set Host header to: {target_host}")
                else:
                    logger.warning("No host specified for forwarding request")
                
                # Log request with headers as they will be sent to the upstream server
                logs_path = self.resolve_logs_path(headers)
                self.log_http_request(request_time, rule_id, original_headers=headers, forwarded_headers=forwarded_headers, path=modified_headers[':path'], body=body, logs_path=logs_path)

                # Forward request
                response = self.forward_request(method, target_host, target_protocol, modified_headers, forwarded_headers, body)

                # Log response
                self.log_http_response(request_time, rule_id, response, logs_path=logs_path)
                
                # Check if response is chunked or event-stream
                is_chunked = 'Transfer-Encoding' in response.headers and 'chunked' in response.headers['Transfer-Encoding'].lower()
                is_event_stream = 'Content-Type' in response.headers and 'text/event-stream' in response.headers['Content-Type'].lower()
                
                if is_chunked or is_event_stream:
                    # Handle streaming response
                    self.send_response(response.status_code)
                    
                    # Set chunked transfer encoding
                    self.send_header('Transfer-Encoding', 'chunked')
                    
                    # Copy all other headers except Content-Length (which is incompatible with chunked encoding)
                    for key, value in response.headers.items():
                        if key.lower() != 'content-length':
                            self.send_header(key, value)
                    
                    self.end_headers()
                    
                    # Stream the response content
                    if isinstance(response, requests.Response) and hasattr(response, 'raw') and response.raw:
                        # For requests.Response with raw attribute, use iter_content for safer streaming
                        for chunk in response.iter_content(chunk_size=4096):
                            if chunk:  # Filter out keep-alive new chunks
                                # Write chunk length in hex followed by CRLF
                                self.wfile.write(f"{len(chunk):X}\r\n".encode())
                                # Write chunk data followed by CRLF
                                self.wfile.write(chunk + b"\r\n")
                        
                        # Write final empty chunk to signal the end
                        self.wfile.write(b"0\r\n\r\n")
                    else:
                        # If raw is not available (e.g., FakeResponse), write the content as a single chunk
                        chunk_size = 4096  # 4KB chunks
                        content = response.content
                        for i in range(0, len(content), chunk_size):
                            chunk = content[i:i+chunk_size]
                            # Write chunk length in hex followed by CRLF
                            self.wfile.write(f"{len(chunk):X}\r\n".encode())
                            # Write chunk data followed by CRLF
                            self.wfile.write(chunk + b"\r\n")
                        
                        # Write final empty chunk to signal the end
                        self.wfile.write(b"0\r\n\r\n")
                else:
                    # Regular response
                    self.send_response(response.status_code)
                    for key, value in response.headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(response.content)
            else:
                # No rule matched
                logger.warning(f"No rule matched for request: {headers}")
                self.send_response(404)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'No matching rule found')
        
        def match_rule(self, headers: dict[str, str]) -> tuple[Rule | None, str | None, str | None, dict[str, str]]:
            """Match request against rules.
            
            Args:
                headers: Request headers.
                
            Returns:
                Tuple of (matched_rule, target_host, modified_headers).
            """
            for rule in self.config.rules:
                conditions = rule.get('when', [])
                actions = rule.get('then', [])
                
                # Check if all conditions match
                if all(self.check_condition(condition, headers) for condition in conditions):
                    # Apply actions
                    modified_headers = headers.copy()
                    target_host = None
                    
                    target_protocol = None
                    
                    for action in actions:
                        if 'host' in action:
                            target_host = action['host']
                            # Default protocol is https for non-localhost hosts
                            if 'protocol' in action:
                                target_protocol = action['protocol']
                            elif 'localhost' in target_host or '127.0.0.1' in target_host:
                                target_protocol = 'http'
                            else:
                                target_protocol = 'https'
                        elif 'header' in action and 'prefix' in action:
                            header_name = action['header']
                            new_prefix = action['prefix']
                            
                            # Find the matching condition to get the old prefix
                            for condition in conditions:
                                if condition.get('header') == header_name and 'prefix' in condition:
                                    old_prefix = condition['prefix']
                                    if header_name in modified_headers and modified_headers[header_name].startswith(old_prefix):
                                        modified_headers[header_name] = new_prefix + modified_headers[header_name][len(old_prefix):]
                    
                    return rule, target_host, target_protocol, modified_headers
            
            return None, None, None, headers
        
        def check_condition(self, condition: RuleCondition, headers: dict[str, str]) -> bool:
            """Check if a condition matches.

            Args:
                condition: Condition to check.
                headers: Request headers.

            Returns:
                True if condition matches, False otherwise.
            """
            if 'header' in condition:
                header_name = condition['header']
                if header_name not in headers:
                    return False

                header_value = headers[header_name]

                if 'prefix' in condition:
                    return header_value.startswith(condition['prefix'])

            return False

        def read_chunked_body(self) -> bytes:
            """Read chunked transfer encoding body.

            Returns:
                The complete body as bytes.
            """
            body = b''
            while True:
                # Read chunk size line
                chunk_size_line = b''
                while True:
                    byte = self.rfile.read(1)
                    if byte == b'\n':
                        break
                    if byte:
                        chunk_size_line += byte
                    else:
                        # EOF reached
                        return body
                
                # Parse chunk size (may include chunk extensions after ;)
                chunk_size_str = chunk_size_line.decode('ascii').strip()
                if ';' in chunk_size_str:
                    chunk_size_str = chunk_size_str.split(';')[0]
                chunk_size = int(chunk_size_str, 16)
                
                if chunk_size == 0:
                    # Final chunk - read trailing headers and final CRLF
                    while True:
                        line = self.rfile.read(2)
                        if line == b'\r\n' or not line:
                            break
                    return body
                
                # Read chunk data
                chunk_data = self.rfile.read(chunk_size)
                body += chunk_data
                
                # Read CRLF after chunk
                self.rfile.read(2)  # Skip \r\n
        
        def forward_request(self, method: str, host: str | None, protocol: str | None, 
                           headers: dict[str, str], forwarded_headers: dict[str, str], 
                           body: bytes) -> requests.Response | FakeResponse:
            """Forward request to target host.
            
            Args:
                method: HTTP method.
                host: Target host.
                protocol: Protocol to use (http or https).
                headers: Original request headers.
                forwarded_headers: Headers to send to the upstream server.
                body: Request body.
                
            Returns:
                Response from target host.
            """
            if not host:
                # Create a fake response if no host is specified
                return FakeResponse(
                    status_code=400,
                    content_type='text/plain',
                    content="No target host specified in rule"
                )
            
            if not protocol:
                # Default to https for non-localhost hosts
                protocol = 'https' if 'localhost' not in host and '127.0.0.1' not in host else 'http'
            
            url = f"{protocol}://{host}{headers[':path']}"
            if VERY_VERBOSE:
                print(f"FINAL TARGET URL: {url}")
            
            try:
                if VERY_VERBOSE:
                    print(f"FORWARDING REQUEST TO: {url}")
                    print(f"WITH HEADERS: {forwarded_headers}")
                
                # Check if we need to handle streaming responses
                is_streaming_request = False
                
                # Get system CA bundle for SSL verification
                ca_bundle = get_system_ca_bundle()
                if VERY_VERBOSE and ca_bundle:
                    logger.debug(f"Using system CA bundle: {ca_bundle}")

                # For streaming responses, we need to use stream=True
                response = requests.request(
                    method=method,
                    url=url,
                    headers=forwarded_headers,
                    data=body,
                    allow_redirects=False,
                    timeout=30,
                    stream=True,  # Enable streaming for all requests
                    verify=ca_bundle if ca_bundle else True  # Use system certs or default verification
                )
                
                # Check if response is chunked or event-stream
                is_chunked = 'Transfer-Encoding' in response.headers and 'chunked' in response.headers['Transfer-Encoding'].lower()
                is_event_stream = 'Content-Type' in response.headers and 'text/event-stream' in response.headers['Content-Type'].lower()
                
                if is_chunked or is_event_stream:
                    if VERY_VERBOSE:
                        print(f"STREAMING RESPONSE DETECTED: chunked={is_chunked}, event-stream={is_event_stream}")
                    # For streaming responses, don't read the content yet
                    # It will be streamed directly to the client
                    pass
                else:
                    # For non-streaming responses, read the content now
                    # This is needed because we access response.content in other parts of the code
                    response.content  # This will read the content
                
                if VERY_VERBOSE:
                    print(f"RESPONSE FROM TARGET: {response.status_code}")
                return response
            except Exception as e:
                logger.error(f"Failed to forward request: {e} headers={headers}")
                # Create a fake response
                return FakeResponse(
                    status_code=502,
                    content_type='text/plain',
                    content=f"Failed to forward request: {e}"
                )
        
        def resolve_logs_path(self, headers: dict[str, str]) -> str:
            session_id = headers.get('x-claude-code-session-id', headers.get('X-Claude-Code-Session-Id', ''))
            if session_id:
                path = os.path.join(self.config.logs_path, session_id)
                os.makedirs(path, exist_ok=True)
                return path
            return self.config.logs_path

        def log_http_request(self, timestamp: str, rule_id: str, original_headers: dict[str, str],
                            forwarded_headers: dict[str, str], path: str, body: bytes, logs_path: str = None) -> None:
            """Log HTTP request to files.
            
            Args:
                timestamp: Request timestamp.
                rule_id: Rule ID.
                original_headers: Original request headers.
                forwarded_headers: Headers sent to upstream server.
                path: The path sent to upstream server.
                body: Request body.
            """
            # Format timestamp for filename
            if logs_path is None:
                logs_path = self.config.logs_path
            ts = timestamp.replace(':', '').replace('+', 'Z+').replace('-', '')

            # Log headers - use forwarded headers to show what was sent to upstream server
            header_file = os.path.join(logs_path, f"{ts}-{rule_id}.req.h.txt")
            with open(header_file, 'w') as f:
                f.write(f"{original_headers[':method']} {path} HTTP/1.1\n")
                # Log the forwarded headers, including the Host header
                for key, value in forwarded_headers.items():
                    f.write(f"{key}: {value}\n")

            # Log body only if it's not empty
            if body and len(body) > 0:
                # Determine content type from headers and trust it
                content_type = original_headers.get('content-type', original_headers.get('Content-Type', '')).lower()

                if 'application/json' in content_type or content_type.endswith('+json'):
                    body_file = os.path.join(logs_path, f"{ts}-{rule_id}.req.p.json")
                    with open(body_file, 'wb') as f:
                        f.write(body)
                elif content_type.startswith('text/'):
                    body_file = os.path.join(logs_path, f"{ts}-{rule_id}.req.p.txt")
                    with open(body_file, 'wb') as f:
                        f.write(body)
                else:
                    body_file = os.path.join(logs_path, f"{ts}-{rule_id}.req.p.bin")
                    with open(body_file, 'wb') as f:
                        f.write(body)
        
        def log_http_response(self, timestamp: str, rule_id: str, response: requests.Response | FakeResponse, logs_path: str = None) -> None:
            """Log HTTP response to files."""
            if logs_path is None:
                logs_path = self.config.logs_path
            ts = timestamp.replace(':', '').replace('+', 'Z+').replace('-', '')

            # Log headers
            header_file = os.path.join(logs_path, f"{ts}-{rule_id}.res.h.txt")
            with open(header_file, 'w') as f:
                f.write(f"HTTP/1.1 {response.status_code}\n")
                for key, value in response.headers.items():
                    f.write(f"{key}: {value}\n")

            # Log body only if it's not empty
            if response.content and len(response.content) > 0:
                content_type = response.headers.get('Content-Type', '').lower()

                if 'application/json' in content_type or content_type.endswith('+json'):
                    body_file = os.path.join(logs_path, f"{ts}-{rule_id}.res.p.json")
                    with open(body_file, 'wb') as f:
                        f.write(response.content)
                elif content_type.startswith('text/'):
                    body_file = os.path.join(logs_path, f"{ts}-{rule_id}.res.p.txt")
                    with open(body_file, 'wb') as f:
                        f.write(response.content)
                else:
                    body_file = os.path.join(logs_path, f"{ts}-{rule_id}.res.p.bin")
                    with open(body_file, 'wb') as f:
                        f.write(response.content)
        
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
    """Main entry point."""
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
        print("VERY VERBOSE MODE ENABLED - DEBUG LOGS WILL SHOW")  # Add print to confirm
    elif args.verbose:
        logger.setLevel(logging.DEBUG)
    
    config = Config(args.config)
    
    handler_class = create_request_handler(config)
    # Use 0.0.0.0 to listen on all interfaces
    server = HTTPServer(('0.0.0.0', args.port), handler_class)
    
    logger.info(f"Starting YAHP on port {args.port}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down YAHP")
        server.server_close()


if __name__ == "__main__":
    main()