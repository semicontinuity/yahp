#!/usr/bin/env python3
"""
Anthropic Log Parser

This script parses HTTP logs of communication with Anthropic LLM API produced by YAHP.
It reads log files, extracts information from HTTP requests and responses,
and outputs them in a more human-readable JSON lines format.

Usage:
    ./log-parser-anthropic.py [--logs-path PATH] [--output FILE] [--verbose]

Examples:
    # Parse logs from default location and output to stdout
    ./log-parser-anthropic.py
    
    # Parse logs from a specific directory and output to a file
    ./log-parser-anthropic.py --logs-path /path/to/logs --output parsed_logs.jsonl
    
    # Enable verbose output
    ./log-parser-anthropic.py --verbose
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


@dataclass
class TextBlock:
    """A block of text with a type (text or thoughts)."""
    type: str
    text: str


@dataclass
class ContentBlock:
    """A content block from the Anthropic API response."""
    type: str
    data: List[TextBlock] = field(default_factory=list)


@dataclass
class Message:
    """Message information from the Anthropic API response."""
    id: str = ""


@dataclass
class AnthropicResponse:
    """Parsed response from the Anthropic API."""
    message: Message = field(default_factory=Message)
    content: List[ContentBlock] = field(default_factory=list)


@dataclass
class AnthropicRequest:
    """Parsed request to the Anthropic API."""
    system: str = ""
    messages: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class LogEntry:
    """A log entry containing information from a request-response pair."""
    ts: str
    request: AnthropicRequest
    response: AnthropicResponse


@dataclass
class LogFiles:
    """Paths to log files for a single request-response pair."""
    req_header: Optional[str] = None
    req_payload: Optional[str] = None
    res_header: Optional[str] = None
    res_payload: Optional[str] = None


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Parse Anthropic API logs from YAHP')
    parser.add_argument('--logs-path', type=str, default=os.path.expanduser('~/.local/state/yahp/logs'),
                        help='Path to YAHP logs directory (default: ~/.local/state/yahp/logs)')
    parser.add_argument('--output', type=str, default='-',
                        help='Output file path (default: stdout)')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output')
    return parser.parse_args()


def find_log_files(logs_path: str) -> Dict[str, LogFiles]:
    """
    Find all log files in the specified directory and group them by timestamp and rule_id.
    
    This function scans the logs directory for YAHP log files, which follow the pattern:
    YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req/res.h/p.txt/json/bin
    
    It groups related files (request headers, request body, response headers, response body)
    for the same HTTP transaction together based on their timestamp and rule_id.
    
    Args:
        logs_path: Path to the directory containing YAHP log files
        
    Returns:
        A dictionary where keys are "{timestamp}-{rule_id}" and values are LogFiles objects
        containing paths to the corresponding log files.
        
    Raises:
        SystemExit: If the logs directory does not exist or is not a directory
    """
    log_files_groups = {}
    logs_dir = Path(logs_path)
    
    if not logs_dir.exists() or not logs_dir.is_dir():
        print(f"Error: Logs directory {logs_path} does not exist or is not a directory", file=sys.stderr)
        sys.exit(1)
    
    # YAHP log files follow this pattern: YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req/res.h/p.txt/json/bin
    for file_path in logs_dir.glob('*'):
        # Parse filename to extract timestamp, rule_id, and file type
        match = re.match(r'(.+?)-([^.]+)\.([^.]+)\.([^.]+)\.([^.]+)', file_path.name)
        if match:
            timestamp, rule_id, req_res, head_payload, file_type = match.groups()
            key = f"{timestamp}-{rule_id}"
            
            if key not in log_files_groups:
                log_files_groups[key] = LogFiles()
            
            # Map file to the appropriate field in LogFiles
            if req_res == 'req' and head_payload == 'h':
                log_files_groups[key].req_header = str(file_path)
            elif req_res == 'req' and head_payload == 'p':
                log_files_groups[key].req_payload = str(file_path)
            elif req_res == 'res' and head_payload == 'h':
                log_files_groups[key].res_header = str(file_path)
            elif req_res == 'res' and head_payload == 'p':
                log_files_groups[key].res_payload = str(file_path)
    
    return log_files_groups


def is_anthropic_api_request(log_files: LogFiles) -> bool:
    """
    Check if the log files correspond to a request to the Anthropic API messages endpoint.
    
    This function checks if the request is to /raw/anthropic/v1/messages but not to
    /raw/anthropic/v1/messages/count_tokens, as per the requirements.
    
    Args:
        log_files: LogFiles object containing paths to log files for a single request/response.
        
    Returns:
        True if the request is to /raw/anthropic/v1/messages (excluding count_tokens), False otherwise.
    """
    if not log_files.req_header:
        return False
    
    with open(log_files.req_header, 'r') as f:
        headers = f.read()
        # Check if the request is to /raw/anthropic/v1/messages but not to /raw/anthropic/v1/messages/count_tokens
        return '/raw/anthropic/v1/messages' in headers and '/raw/anthropic/v1/messages/count_tokens' not in headers


def parse_request(log_files: LogFiles) -> AnthropicRequest:
    """
    Parse the HTTP request from log files.
    
    Args:
        log_files: LogFiles object containing paths to log files for a single request/response.
        
    Returns:
        AnthropicRequest object containing parsed request information.
    """
    request = AnthropicRequest()
    
    # Parse request body (JSON)
    if log_files.req_payload:
        with open(log_files.req_payload, 'r') as f:
            try:
                body = json.load(f)
                # Extract system and messages fields
                if 'system' in body:
                    request.system = body['system']
                if 'messages' in body:
                    request.messages = body['messages']
            except json.JSONDecodeError:
                print(f"Error: Failed to parse request body as JSON: {log_files.req_payload}", file=sys.stderr)
    else:
        print(f"Warning: No request body file found for request", file=sys.stderr)
    
    return request


def parse_event_stream(content: str) -> AnthropicResponse:
    """
    Parse text/event-stream format content from Anthropic API responses.
    
    This function processes the Server-Sent Events (SSE) format used by Anthropic's
    streaming API. It extracts the message ID from the 'message_start' event and
    builds content blocks from 'content_block_start' and 'content_block_delta' events.
    
    It also processes the text content to identify and separate <thinking> blocks
    from regular text.
    
    Args:
        content: The content in text/event-stream format.
        
    Returns:
        AnthropicResponse object containing:
        - message: Message object with ID
        - content: List of ContentBlock objects, each with:
          - type: Content type (e.g., 'text')
          - data: List of TextBlock objects, each with:
            - type: 'thoughts' for content in <thinking> tags, 'text' otherwise
            - text: The actual text content
    """
    response = AnthropicResponse()
    
    # Split content into events
    events = []
    current_event = {'event': '', 'data': ''}
    
    for line in content.splitlines():
        line = line.strip()
        if not line:
            # Empty line marks the end of an event
            if current_event['event'] or current_event['data']:
                events.append(current_event)
                current_event = {'event': '', 'data': ''}
        elif line.startswith('event:'):
            current_event['event'] = line[6:].strip()
        elif line.startswith('data:'):
            current_event['data'] = line[5:].strip()
    
    # Add the last event if it's not empty
    if current_event['event'] or current_event['data']:
        events.append(current_event)
    
    # Process events
    content_blocks = {}
    
    for event in events:
        event_type = event['event']
        data = event['data']
        
        try:
            data_json = json.loads(data)
        except json.JSONDecodeError:
            continue
        
        if event_type == 'message_start':
            if 'message' in data_json and 'id' in data_json['message']:
                message_id = data_json['message']['id']
                response.message.id = message_id
        
        elif event_type == 'content_block_start':
            if 'index' in data_json and 'content_block' in data_json:
                index = data_json['index']
                content_block = data_json['content_block']
                
                if index not in content_blocks:
                    content_blocks[index] = {
                        'type': content_block.get('type', ''),
                        'text': content_block.get('text', '')
                    }
        
        elif event_type == 'content_block_delta':
            if 'index' in data_json and 'delta' in data_json:
                index = data_json['index']
                delta = data_json['delta']
                
                if index not in content_blocks:
                    content_blocks[index] = {'type': 'text', 'text': ''}
                
                if 'type' in delta and delta['type'] == 'text_delta' and 'text' in delta:
                    content_blocks[index]['text'] += delta['text']
    
    # Process content blocks to extract thoughts and text
    for index, block in content_blocks.items():
        content_type = block.get('type', 'text')
        text = block.get('text', '')
        
        # Create a content block entry
        content_block = ContentBlock(type=content_type)
        
        # Use regex to find <thinking>...</thinking> blocks
        thinking_pattern = re.compile(r'<thinking>(.*?)</thinking>', re.DOTALL)
        
        # Find all thinking blocks
        thinking_matches = list(thinking_pattern.finditer(text))
        
        if thinking_matches:
            # Process text with thinking blocks
            last_end = 0
            
            for match in thinking_matches:
                # Add text before thinking block
                if match.start() > last_end:
                    before_text = text[last_end:match.start()]
                    if before_text.strip():
                        content_block.data.append(TextBlock(
                            type='text',
                            text=before_text.strip()
                        ))
                
                # Add thinking block
                thinking_text = match.group(1).strip()
                if thinking_text:
                    content_block.data.append(TextBlock(
                        type='thoughts',
                        text=thinking_text
                    ))
                
                last_end = match.end()
            
            # Add remaining text after last thinking block
            if last_end < len(text):
                remaining_text = text[last_end:]
                if remaining_text.strip():
                    content_block.data.append(TextBlock(
                        type='text',
                        text=remaining_text.strip()
                    ))
        else:
            # No thinking blocks, just add the text
            if text.strip():
                content_block.data.append(TextBlock(
                    type='text',
                    text=text.strip()
                ))
        
        # Add content block to response
        if content_block.data:
            response.content.append(content_block)
    
    return response


def parse_response(log_files: LogFiles) -> AnthropicResponse:
    """
    Parse the HTTP response from log files.
    
    Args:
        log_files: LogFiles object containing paths to log files for a single request/response.
        
    Returns:
        AnthropicResponse object containing parsed response information.
    """
    response = AnthropicResponse()
    
    # Parse response body (text/event-stream)
    if log_files.res_payload:
        with open(log_files.res_payload, 'r') as f:
            response_text = f.read()
            response = parse_event_stream(response_text)
    else:
        print(f"Warning: No response body file found for response", file=sys.stderr)
    
    return response


def process_log_files(log_files_groups: Dict[str, LogFiles]) -> List[LogEntry]:
    """
    Process all log file groups and extract information from Anthropic API requests.
    
    This function filters log files for Anthropic API requests, extracts the timestamp,
    parses the request and response, and creates a structured result for each request.
    
    Args:
        log_files_groups: Dictionary where keys are "{timestamp}-{rule_id}" and values are
                         LogFiles objects containing paths to the corresponding log files.
        
    Returns:
        List of LogEntry objects containing:
        - ts: Timestamp from the log file name
        - request: Parsed request information (system and messages)
        - response: Parsed response information (message ID and content blocks)
    """
    results = []

    for key, log_files in log_files_groups.items():
        # Check if this is an Anthropic API request
        if not is_anthropic_api_request(log_files):
            continue
        
        # Extract timestamp from the key
        timestamp = key.split('-')[0]
        
        # Parse request and response
        request = parse_request(log_files)
        response = parse_response(log_files)
        
        # Create log entry
        log_entry = LogEntry(
            ts=timestamp,
            request=request,
            response=response
        )
        
        results.append(log_entry)
    
    return results


class EnhancedJSONEncoder(json.JSONEncoder):
    """JSON encoder that can handle dataclasses."""
    def default(self, o):
        if hasattr(o, '__dataclass_fields__'):
            return asdict(o)
        return super().default(o)


def main():
    """Main entry point."""
    args = None
    try:
        args = parse_args()
        
        if args.verbose:
            print(f"Parsing logs from: {args.logs_path}", file=sys.stderr)
            print(f"Output destination: {args.output if args.output != '-' else 'stdout'}", file=sys.stderr)
        
        # Find and group log files
        log_files_groups = find_log_files(args.logs_path)
        
        if args.verbose:
            print(f"Found {len(log_files_groups)} log file groups", file=sys.stderr)
        
        # Process log files
        results = process_log_files(log_files_groups)
        
        if args.verbose:
            print(f"Processed {len(results)} Anthropic API requests", file=sys.stderr)
        
        if not results:
            print("Warning: No Anthropic API requests found in the logs", file=sys.stderr)
        
        # Output results
        if args.output == '-':
            # Write to stdout
            for result in results:
                print(json.dumps(result, cls=EnhancedJSONEncoder))
        else:
            # Write to file
            try:
                with open(args.output, 'w') as f:
                    for result in results:
                        f.write(json.dumps(result, cls=EnhancedJSONEncoder) + '\n')
                if args.verbose:
                    print(f"Results written to {args.output}", file=sys.stderr)
            except IOError as e:
                print(f"Error writing to output file {args.output}: {e}", file=sys.stderr)
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args and args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()