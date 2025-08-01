# YAHP: Yet Another HTTP Proxy

## Product Requirements Document

**Version:** 1.0  
**Date:** July 31, 2025  
**Author:** Product Team

## Table of Contents

1. [Overview](#overview)
2. [Objectives](#objectives)
3. [Functional Requirements](#functional-requirements)
   - [Core Functionality](#core-functionality)
   - [Logging Requirements](#logging-requirements)
   - [Configuration](#configuration)
   - [Routing Rules](#routing-rules)
4. [Technical Specifications](#technical-specifications)

## Overview

YAHP (Yet Another HTTP Proxy) is a lightweight HTTP proxy server designed to facilitate the logging and examination of HTTP requests and responses, particularly for interactions with Language Model APIs and other HTTP/HTTPS services.

## Objectives

The primary objective of YAHP is to provide a transparent proxy that logs all HTTP traffic in a structured, easily analyzable format, while allowing flexible routing rules to direct traffic to various remote services.

## Functional Requirements

### Core Functionality

YAHP shall be implemented as a Python application with the following core functionality:

- Run on Ubuntu-based systems
- Listen on localhost at a configurable port (6666 by default)
- Proxy HTTP requests to configurable remote HTTP/HTTPS servers
- Support for proxying requests to Language Model APIs
- Provide comprehensive logging of all requests and responses

### Logging Requirements

The primary goal of YAHP is to log all HTTP requests and responses in a structured format for easy examination:

- All HTTP requests and responses shall be written to separate files inside a configurable log directory
- Log files shall follow this naming convention:
  - `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req.head.txt` - Request headers
  - `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.req.data.json` - Request body (JSON payload)
  - `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.res.head.txt` - Response headers
  - `YYYY-MM-ddTHH:mm:ss.SSSZ-abcd0123.res.data.json` - Response body (JSON payload)
- For non-JSON payloads, the file extension shall be `.data.bin` instead of `.data.json`
- The timestamp in the filename shall correspond to the request timestamp for all related files
- The `abcd0123` portion shall be replaced with a consistent ID corresponding to the matched rule (e.g., hexadecimal representation of murmur32 hash of the matched rule)
- No body files shall be created for bodyless requests or responses

### Configuration

YAHP shall be configured using a YAML file located at `~/.config/yahp/config.yaml` with the following structure:

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

### Routing Rules

The routing mechanism shall operate according to these principles:

- Routing shall be based on rules that match HTTP headers
- Multiple conditions within a rule shall be combined using logical AND
- The first matching rule shall be applied; subsequent rules shall be ignored
- If no rule matches, a warning shall be printed to stderr with the HTTP header information

Rule actions shall support the following operations:

- `host`: Specifies which HTTP host will be contacted to serve the request
- `protocol`: Specifies the protocol to use (http or https). Defaults to https for non-localhost hosts and http for localhost
- `header` + `prefix`: Replaces a prefix (previously matched in condition) with a new one

## Technical Specifications

- Implementation Language: Python 3.10+
- Target Platform: Ubuntu Linux
- Default Port: 6666
- Configuration Format: YAML
- Logging Format: Structured text files (headers) and JSON/binary files (bodies)
- Support for Transfer-Encoding: chunked and Content-Type: text/event-stream responses
- Streaming of responses as they arrive from the server
