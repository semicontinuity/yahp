#!/usr/bin/env python3
"""Strategy ABC: the contract every protocol implements against the canonical hub."""

from abc import ABC, abstractmethod
from typing import Iterator

from canonical import (
    CanonicalRequest, CanonicalResponse, CanonicalStreamEvent, CanonicalModelList,
)

# Logical operation a request path maps to.
OP_MESSAGES = 'messages'
OP_MODELS = 'models'
OP_OTHER = 'other'


class MalformedRequestError(ValueError):
    """Raised when a request body is structurally invalid for the declared protocol."""


class Strategy(ABC):
    """Maps one protocol's wire format to and from the canonical representation.

    Streaming accumulation state, if any, is held in instance fields, so a
    fresh strategy instance is used per streaming exchange where needed.
    """

    name: str = ''

    # --- endpoint classification & routing --------------------------------

    @abstractmethod
    def classify(self, path: str) -> str:
        """Map an inbound path to OP_MESSAGES | OP_MODELS | OP_OTHER."""

    @abstractmethod
    def endpoint_suffix(self, operation: str) -> str:
        """Return this protocol's path suffix for a logical operation."""

    # --- non-streaming request/response -----------------------------------

    @abstractmethod
    def parse_request(self, body: dict) -> CanonicalRequest:
        """Parse a wire request body into the canonical request."""

    @abstractmethod
    def serialize_request(self, req: CanonicalRequest) -> dict:
        """Serialize a canonical request into this protocol's wire body."""

    @abstractmethod
    def parse_response(self, body: dict) -> CanonicalResponse:
        """Parse a wire response body into the canonical response."""

    @abstractmethod
    def serialize_response(self, resp: CanonicalResponse) -> dict:
        """Serialize a canonical response into this protocol's wire body."""

    # --- streaming --------------------------------------------------------

    @abstractmethod
    def iter_parse_stream(self, lines: Iterator[str]) -> Iterator[CanonicalStreamEvent]:
        """Parse upstream SSE lines into canonical stream events."""

    @abstractmethod
    def iter_serialize_stream(self, events: Iterator[CanonicalStreamEvent]) -> Iterator[bytes]:
        """Serialize canonical stream events into this protocol's SSE byte chunks."""

    # --- model listing ----------------------------------------------------

    @abstractmethod
    def parse_model_list(self, body: dict) -> CanonicalModelList:
        """Parse a wire model-list response into the canonical model list."""

    @abstractmethod
    def serialize_model_list(self, models: CanonicalModelList) -> dict:
        """Serialize a canonical model list into this protocol's wire body."""
