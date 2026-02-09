"""Tests for the plugin system and built-in plugins."""

import pytest
from suricata_rule_parser import parse_rule

from suricata_rule_scoring.plugin import (
    builtin_few_content_matches,
    builtin_generic_protocol,
    builtin_tiny_payload,
    compute_content_bytes,
    load_plugin,
)


class TestComputeContentBytes:
    def test_literal_only(self):
        assert compute_content_bytes("GET") == 3

    def test_hex_only(self):
        assert compute_content_bytes("|DE AD BE EF|") == 4

    def test_mixed(self):
        # "GET" (3) + hex 20 (1) + "/" (1) = 5
        assert compute_content_bytes("GET|20|/") == 5

    def test_empty(self):
        assert compute_content_bytes("") == 0

    def test_hex_with_spaces(self):
        assert compute_content_bytes("|00 01 02 03 04|") == 5

    def test_multiple_hex_blocks(self):
        # "A" (1) + hex 00 01 (2) + "BC" (2) + hex FF (1) = 6
        assert compute_content_bytes("A|00 01|BC|FF|") == 6


class TestBuiltinTinyPayload:
    def test_tiny_payload_triggers(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"Tiny"; content:"AB"; flow:established; '
            'sid:1; rev:1; classtype:misc-activity;)'
        )
        result = builtin_tiny_payload(rule)
        assert result is not None
        assert result.dimension == "quality"
        assert result.delta == -10

    def test_normal_payload_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"Normal"; content:"GET /index.html"; flow:established; '
            'sid:2; rev:1; classtype:misc-activity;)'
        )
        result = builtin_tiny_payload(rule)
        assert result is None

    def test_no_content_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"No content"; sid:3; rev:1;)'
        )
        result = builtin_tiny_payload(rule)
        assert result is None


class TestBuiltinFewContentMatches:
    def test_single_short_content(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"Few"; content:"AB"; flow:established; '
            'sid:1; rev:1; classtype:misc-activity;)'
        )
        result = builtin_few_content_matches(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == 8

    def test_single_long_content(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"Long"; content:"ABCDE"; flow:established; '
            'sid:2; rev:1; classtype:misc-activity;)'
        )
        result = builtin_few_content_matches(rule)
        assert result is None

    def test_multiple_contents_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"Multi"; content:"AB"; content:"CD"; flow:established; '
            'sid:3; rev:1; classtype:misc-activity;)'
        )
        result = builtin_few_content_matches(rule)
        assert result is None


class TestBuiltinGenericProtocol:
    def test_generic_ip_triggers(self):
        rule = parse_rule(
            'alert ip any any -> any any '
            '(msg:"Generic"; content:"test"; sid:1; rev:1;)'
        )
        result = builtin_generic_protocol(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == 5

    def test_generic_tcp_triggers(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Generic TCP"; content:"test"; flow:established; '
            'sid:2; rev:1; classtype:misc-activity;)'
        )
        result = builtin_generic_protocol(rule)
        assert result is not None

    def test_http_protocol_no_trigger(self):
        rule = parse_rule(
            'alert http any any -> any any '
            '(msg:"HTTP"; content:"GET"; sid:3; rev:1;)'
        )
        result = builtin_generic_protocol(rule)
        assert result is None

    def test_tcp_with_app_layer_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"TCP with HTTP"; content:"GET"; http_method; '
            'flow:established; sid:4; rev:1; classtype:misc-activity;)'
        )
        result = builtin_generic_protocol(rule)
        assert result is None


class TestLoadPlugin:
    def test_load_builtin_colon_syntax(self):
        func = load_plugin("suricata_rule_scoring.plugin:builtin_tiny_payload")
        assert callable(func)
        assert func is builtin_tiny_payload

    def test_load_builtin_dot_syntax(self):
        func = load_plugin("suricata_rule_scoring.plugin.builtin_tiny_payload")
        assert callable(func)

    def test_load_nonexistent_raises(self):
        with pytest.raises((ModuleNotFoundError, AttributeError)):
            load_plugin("nonexistent.module:func")
