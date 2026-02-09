"""Criterion evaluation engine for declarative conditions."""

from typing import Any

from suricata_rule_parser import SuricataRule

from .config import ConditionConfig

# Attributes directly available on RuleOptions (not stored in other_options)
RULE_OPTIONS_ATTRS = frozenset({
    "msg", "sid", "rev", "classtype", "priority",
    "reference", "metadata", "content", "content_modifiers", "flow",
})

# Aliases for header fields — flat names usable in YAML conditions
HEADER_ALIASES: dict[str, str] = {
    "source_address": "source_ip",
    "destination_address": "dest_ip",
    "source_port": "source_port",
    "destination_port": "dest_port",
    "protocol": "protocol",
    "action": "action",
    "direction": "direction",
}


def resolve_field(rule: SuricataRule, field_path: str) -> Any:
    """Resolve a dotted field path against a parsed SuricataRule.

    Resolution tiers:
    1. Header aliases — flat names like "source_address", "protocol"
    2. "options.<attr>" — direct RuleOptions attributes (content, flow, etc.)
    3. "options.<key>" — falls through to other_options dict

    The |count suffix returns the length of a list-valued field.
    """
    # Handle |count suffix
    count_mode = False
    if field_path.endswith("|count"):
        count_mode = True
        field_path = field_path[:-6]  # strip "|count"

    value = _resolve_raw(rule, field_path)

    if count_mode:
        if isinstance(value, (list, tuple)):
            return len(value)
        if isinstance(value, dict):
            return len(value)
        if value is None:
            return 0
        # Single value counts as 1
        return 1

    return value


def _resolve_raw(rule: SuricataRule, field_path: str) -> Any:
    """Resolve the raw value without |count processing."""
    # Tier 1: Header aliases (flat names without dots)
    if field_path in HEADER_ALIASES:
        attr_name = HEADER_ALIASES[field_path]
        return getattr(rule.header, attr_name, None)

    # Tier 2 & 3: options.* paths
    if field_path.startswith("options."):
        remainder = field_path[8:]  # strip "options."
        return _resolve_options(rule.options, remainder)

    # Direct attribute on the rule object (e.g., "sid", "msg" via properties)
    if hasattr(rule, field_path):
        return getattr(rule, field_path)

    return None


def _resolve_options(options: Any, remainder: str) -> Any:
    """Resolve a path within RuleOptions.

    Strategy: check if the first segment is a known RuleOptions attribute.
    If so, traverse into it. Otherwise, treat the full remainder as an
    other_options key (handles dotted Suricata keywords like tls.cert_subject).
    """
    # Split on first dot to check the first segment
    if "." in remainder:
        first_segment, rest = remainder.split(".", 1)
    else:
        first_segment = remainder
        rest = None

    # Check if first segment is a known attribute on RuleOptions
    if first_segment in RULE_OPTIONS_ATTRS:
        value = getattr(options, first_segment, None)
        if rest is not None:
            # Traverse deeper into the value (e.g., options.metadata.some_key)
            return _traverse(value, rest)
        return value

    # Fall through: treat full remainder as other_options key
    # This handles dotted keywords like "tls.cert_subject", "dns.query", "ja3.hash"
    # For flag-style keywords the parser stores "" or True; presence in the dict
    # means the keyword exists in the rule, so return a sentinel True for empty values.
    if remainder in options.other_options:
        value = options.other_options[remainder]
        return value if value else True
    return None


def _traverse(obj: Any, path: str) -> Any:
    """Traverse into a nested object/dict by dotted path."""
    for segment in path.split("."):
        if obj is None:
            return None
        if isinstance(obj, dict):
            obj = obj.get(segment)
        elif hasattr(obj, segment):
            obj = getattr(obj, segment)
        else:
            return None
    return obj


def evaluate_condition(rule: SuricataRule, condition: ConditionConfig) -> bool:
    """Evaluate a condition tree against a parsed rule."""
    op = condition.operator

    # Compound operators
    if op == "all":
        return all(evaluate_condition(rule, c) for c in condition.conditions)
    if op == "any":
        return any(evaluate_condition(rule, c) for c in condition.conditions)
    if op == "not":
        return not evaluate_condition(rule, condition.condition)

    # Leaf operators — resolve the field
    value = resolve_field(rule, condition.field)

    if op == "exists":
        return _check_exists(value)
    if op == "not_exists":
        return not _check_exists(value)

    # Comparison operators
    if op == "eq":
        return value == condition.value
    if op == "neq":
        return value != condition.value
    if op == "in":
        return value in condition.value
    if op == "not_in":
        return value not in condition.value
    if op == "contains":
        if isinstance(value, (list, tuple)):
            return condition.value in value
        if isinstance(value, str):
            return condition.value in value
        return False

    # Numeric comparisons
    if op == "gt":
        return _numeric(value) > _numeric(condition.value)
    if op == "gte":
        return _numeric(value) >= _numeric(condition.value)
    if op == "lt":
        return _numeric(value) < _numeric(condition.value)
    if op == "lte":
        return _numeric(value) <= _numeric(condition.value)

    raise ValueError(f"Unknown operator: {op!r}")


def _check_exists(value: Any) -> bool:
    """Check if a value 'exists' — truthy for most types.

    None, empty string, 0, empty list/dict all count as not existing.
    """
    if value is None:
        return False
    if isinstance(value, (str, list, dict, tuple)):
        return len(value) > 0
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return True


def _numeric(value: Any) -> float:
    """Coerce a value to float for numeric comparison."""
    if value is None:
        return 0.0
    return float(value)
