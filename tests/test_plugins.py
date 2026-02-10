"""Tests for the plugin system and built-in plugins."""

from datetime import date
from unittest.mock import patch

import pytest
from suricata_rule_parser import parse_rule

from suricata_rule_scoring.plugin import (
    builtin_few_content_matches,
    builtin_generic_protocol,
    builtin_ip_ioc_rule,
    builtin_rule_age,
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


class TestBuiltinIpIocRule:
    def test_specific_ip_and_port_gives_15(self):
        rule = parse_rule(
            'alert tcp $HOME_NET any -> [91.99.89.71] 443 '
            '(msg:"ThreatFox IP"; sid:1; rev:1;)'
        )
        result = builtin_ip_ioc_rule(rule)
        assert result is not None
        assert result.dimension == "quality"
        assert result.delta == 15

    def test_specific_ip_any_port_gives_10(self):
        rule = parse_rule(
            'alert tcp 10.0.0.1 any -> any any '
            '(msg:"Source IP"; sid:2; rev:1;)'
        )
        result = builtin_ip_ioc_rule(rule)
        assert result is not None
        assert result.dimension == "quality"
        assert result.delta == 10

    def test_bracketed_ip_group_with_port(self):
        rule = parse_rule(
            'alert tcp $HOME_NET any -> [10.0.0.1,10.0.0.2] 443 '
            '(msg:"IP group"; sid:3; rev:1;)'
        )
        result = builtin_ip_ioc_rule(rule)
        assert result is not None
        assert result.delta == 15

    def test_any_both_sides_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"Any"; sid:4; rev:1;)'
        )
        result = builtin_ip_ioc_rule(rule)
        assert result is None

    def test_variables_no_trigger(self):
        rule = parse_rule(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"Vars"; sid:5; rev:1;)'
        )
        result = builtin_ip_ioc_rule(rule)
        assert result is None


class TestBuiltinRuleAge:
    """All tests pin today to 2026-01-15 for deterministic age calculations."""

    FIXED_TODAY = date(2026, 1, 15)

    def _rule_with_metadata(self, meta_str: str) -> object:
        return parse_rule(
            'alert tcp any any -> any 80 '
            f'(msg:"Age test"; metadata: {meta_str}; sid:1; rev:1;)'
        )

    @patch("suricata_rule_scoring.plugin.date")
    def test_under_one_year_gets_bonus(self, mock_date):
        mock_date.today.return_value = self.FIXED_TODAY
        rule = self._rule_with_metadata("created_at 2025_09_28")
        result = builtin_rule_age(rule)
        assert result is not None
        assert result.delta == 5

    @patch("suricata_rule_scoring.plugin.date")
    def test_just_under_one_year_still_gets_bonus(self, mock_date):
        mock_date.today.return_value = self.FIXED_TODAY
        rule = self._rule_with_metadata("created_at 2025_03_01")
        result = builtin_rule_age(rule)
        assert result is not None
        assert result.delta == 5

    @patch("suricata_rule_scoring.plugin.date")
    def test_two_year_old_is_neutral(self, mock_date):
        mock_date.today.return_value = self.FIXED_TODAY
        rule = self._rule_with_metadata("created_at 2024_06_01")
        result = builtin_rule_age(rule)
        assert result is None

    @patch("suricata_rule_scoring.plugin.date")
    def test_three_year_old_is_neutral(self, mock_date):
        mock_date.today.return_value = self.FIXED_TODAY
        rule = self._rule_with_metadata("created_at 2023_06_01")
        result = builtin_rule_age(rule)
        assert result is None

    @patch("suricata_rule_scoring.plugin.date")
    def test_four_year_old_gets_penalty(self, mock_date):
        mock_date.today.return_value = self.FIXED_TODAY
        rule = self._rule_with_metadata("created_at 2022_01_01")
        result = builtin_rule_age(rule)
        assert result is not None
        assert result.delta == -3

    @patch("suricata_rule_scoring.plugin.date")
    def test_over_five_years_gets_max_penalty(self, mock_date):
        mock_date.today.return_value = self.FIXED_TODAY
        rule = self._rule_with_metadata("created_at 2018_01_01")
        result = builtin_rule_age(rule)
        assert result is not None
        assert result.delta == -5

    @patch("suricata_rule_scoring.plugin.date")
    def test_updated_at_preferred_over_created_at(self, mock_date):
        mock_date.today.return_value = self.FIXED_TODAY
        # created_at is old but updated_at is recent
        rule = self._rule_with_metadata("created_at 2018_01_01, updated_at 2025_12_01")
        result = builtin_rule_age(rule)
        assert result is not None
        assert result.delta == 5

    def test_no_metadata_returns_none(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"No meta"; sid:1; rev:1;)'
        )
        result = builtin_rule_age(rule)
        assert result is None

    def test_no_date_fields_returns_none(self):
        rule = self._rule_with_metadata("confidence Medium")
        result = builtin_rule_age(rule)
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
