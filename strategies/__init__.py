#!/usr/bin/env python3
"""Explicit strategy registry. Adding a protocol = write the file + one line here."""

import re

from strategies.anthropic import AnthropicStrategy
from strategies.openai import OpenAIStrategy

RULE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]+$')

# protocol name -> strategy instance
REGISTRY: dict[str, object] = {
    'anthropic': AnthropicStrategy(),
    'openai': OpenAIStrategy(),
}


def get_strategy(protocol: str):
    """Return the registered strategy instance for a protocol, or None."""
    return REGISTRY.get(protocol)


def available_protocols() -> list[str]:
    return sorted(REGISTRY.keys())


class ConfigError(Exception):
    """Raised when a rule declares a missing or unknown protocol."""


def resolve_protocols(rule: dict) -> tuple[str, str]:
    """Return (inbound, outbound) protocols. then.protocol defaults to when.protocol."""
    inbound = rule.get('when', {}).get('protocol')
    outbound = rule.get('then', {}).get('protocol', inbound)
    return inbound, outbound


def validate_rules(rules: list[dict]) -> None:
    """Validate inbound/outbound protocols of every rule and rule name format.

    Raises ConfigError on the first violation:
      - a rule missing when.protocol;
      - a when/then protocol with no registered strategy;
      - a rule name that is empty or contains invalid characters.
    """
    available = ', '.join(available_protocols())
    for rule in rules:
        name = rule.get('name', '<unnamed>')
        inbound, outbound = resolve_protocols(rule)

        if not inbound:
            raise ConfigError(f"Rule '{name}' is missing required when.protocol")
        if inbound not in REGISTRY:
            raise ConfigError(
                f"Rule '{name}' when.protocol '{inbound}' has no registered "
                f"strategy. Available protocols: {available}"
            )
        if outbound not in REGISTRY:
            raise ConfigError(
                f"Rule '{name}' then.protocol '{outbound}' has no registered "
                f"strategy. Available protocols: {available}"
            )

        # Validate rule name format
        if not name or name == '<unnamed>':
            raise ConfigError("Rule name is missing or empty")
        if not RULE_NAME_PATTERN.match(name):
            raise ConfigError(
                f"Rule name '{name}' contains invalid characters. "
                f"Only alphanumeric, underscore, hyphen, and dot are allowed (^[a-zA-Z0-9_.-]+$)"
            )
