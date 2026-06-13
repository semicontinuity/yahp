#!/usr/bin/env python3
"""Canonical hub representation for protocol-agnostic translation.

A neutral, vendor-independent schema shaped after Anthropic's richer model
(content blocks, tool_use/tool_result, explicit stop reasons) so that no
vendor's quirks leak into the hub. Every protocol strategy maps its wire
format to and from these types.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


# --- Content blocks -------------------------------------------------------

@dataclass
class TextBlock:
    text: str


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class ToolResultBlock:
    tool_use_id: str
    content: str


ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock


# --- Messages / requests --------------------------------------------------

@dataclass
class CanonicalMessage:
    role: str                       # 'user' | 'assistant'
    content: list[ContentBlock]


@dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class CanonicalRequest:
    model: str
    messages: list[CanonicalMessage]
    system: Optional[str] = None
    tools: list[ToolDef] = field(default_factory=list)
    tool_choice: Optional[dict[str, Any]] = None
    stop_sequences: list[str] = field(default_factory=list)
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    stream: bool = False
    # Best-effort carrier for protocol fields the hub does not model.
    extra: dict[str, Any] = field(default_factory=dict)


# --- Responses ------------------------------------------------------------

@dataclass
class CanonicalUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class CanonicalResponse:
    id: str
    model: str
    content: list[ContentBlock]
    stop_reason: Optional[str] = None       # canonical: 'end_turn'|'tool_use'|'max_tokens'|'stop_sequence'
    stop_sequence: Optional[str] = None
    usage: CanonicalUsage = field(default_factory=CanonicalUsage)


# --- Streaming events (tagged union) --------------------------------------

@dataclass
class StreamStart:
    id: str
    model: str
    usage: CanonicalUsage = field(default_factory=CanonicalUsage)


@dataclass
class TextDelta:
    text: str


@dataclass
class ToolCallStart:
    index: int
    id: str
    name: str


@dataclass
class ToolCallDelta:
    index: int
    partial_json: str


@dataclass
class UsageDelta:
    usage: CanonicalUsage


@dataclass
class StreamDone:
    stop_reason: Optional[str] = None
    stop_sequence: Optional[str] = None
    usage: CanonicalUsage = field(default_factory=CanonicalUsage)


CanonicalStreamEvent = (
    StreamStart | TextDelta | ToolCallStart | ToolCallDelta | UsageDelta | StreamDone
)


# --- Model listing --------------------------------------------------------

@dataclass
class CanonicalModel:
    id: str
    created_unix: int = 0


@dataclass
class CanonicalModelList:
    models: list[CanonicalModel]
