# Anthropic log parser

## Overview

Parser of HTTP logs of communication with Anthropic LLM API.

## Objectives

The primary objective of Parser is to read log files, and transform them to another log, which is more human-readable.

## Functional Requirements

### Core Functionality

Parser shall be implemented as a Python application `log-parser-anthropic.py` with the following core functionality:

- Run on Ubuntu-based systems
- Be able to read and parse logs produced by YAHP
- Collect back various parts of HTTP request+response (HTTP request header, body, HTTP response header, body), that were written by YAHP as separate files.
- By default, read all log files from YAHP `logs-path`
- Process only requests to `/raw/anthropic/v1/messages`, ignore other URLs

### Logging Requirements

The primary goal of `log-parser-anthropic` is re-shape logs into structured format for easy examination.
Output must be produced in JSON lines format, where every line is JSON with information, extracted from HTTP request and response.

Every line, in JSON format, must contain these fields:
*`ts`: timestamp (prefix of log file name)
*`request`: object with fields `system` and `messages`, copied from request
*`response`: restructured contents of response (which is of type `text/event-stream`):
  * `message` field:
    * `id` sub-field: taken from `message_start` event
  * `content` field: is array of objects, corresponding to `content_block_start`, `content_block_delta` messages; `index` identifies the particular content object
    * `type` sub-field: taken from `type` of `content_block_start`.
    * `data` sub-field: is an array, encapsulating (text) content
      * text is taken from all `content_block_start`, `content_block_delta` events and concatenated
      * then, it is split into 'blocks':
        * if there is a part of text, enclosed in `<thinking>` and `</thinking>`, it becomes `thoughts` block
        * otherwise, it is `text` block
        
Here is the example of HTTP response to be parsed:

```
event: message_start
data: {"type":"message_start","message":{"id":"msg_018dSxFH9nFU1QaPVuXdUoXF","type":"message","role":"assistant","model":"claude-3-7-sonnet-20250219","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":4,"cache_creation_input_tokens":22100,"cache_read_input_tokens":0,"cache_creation":{"ephemeral_5m_input_tokens":22100,"ephemeral_1h_input_tokens":0},"output_tokens":1,"service_tier":"standard"}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}        }

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"<thinking>\nI need to understan"}}

event: ping
data: {"type": "ping"}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"d the issue"}           }

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\n</thinking>"}               }

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\nOK"}         }

event: content_block_stop
data: {"type":"content_block_stop","index":0              }

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"input_tokens":4,"cache_creation_input_tokens":22100,"cache_read_input_tokens":0,"output_tokens":151}             }

event: message_stop
data: {"type":"message_stop"       }
```

Here is the example of restructured HTTP response at the output:

```{"response":{"message":{"id":20250816T140740"}, "content":[{"type":"text","data":[{"type":"thoughts","text":"I need to understand the issue"}, {"type":"text","text":"OK"}]}]  }}```

