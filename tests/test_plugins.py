"""Tests for the plugin system and built-in plugins."""

from datetime import date
from unittest.mock import patch

import pytest
from suricata_rule_parser import parse_rule

from suricata_rule_scoring.plugin import (
    builtin_few_content_matches,
    builtin_flowbits_isset,
    builtin_generic_protocol,
    builtin_ip_ioc_fp,
    builtin_ip_ioc_rule,
    builtin_long_content_match,
    builtin_null_heavy_content,
    builtin_port_specificity,
    builtin_rule_age,
    builtin_single_content_http_method,
    builtin_tiny_payload,
    builtin_weak_multi_content,
    compute_content_bytes,
    compute_content_null_bytes,
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


class TestComputeContentNullBytes:
    def test_no_null_bytes(self):
        assert compute_content_null_bytes("GET") == 0

    def test_all_null_bytes(self):
        assert compute_content_null_bytes("|00 00 00|") == 3

    def test_mixed_hex(self):
        # |DE 00 AD 00| has 2 null bytes
        assert compute_content_null_bytes("|DE 00 AD 00|") == 2

    def test_literal_and_hex(self):
        # "AB" (0 nulls) + |00| (1 null) = 1
        assert compute_content_null_bytes("AB|00|") == 1

    def test_empty(self):
        assert compute_content_null_bytes("") == 0

    def test_concatenated_hex(self):
        # |0000FF00| = 00, 00, FF, 00 → 3 null bytes
        assert compute_content_null_bytes("|0000FF00|") == 3

    def test_no_hex_blocks(self):
        assert compute_content_null_bytes("Hello World") == 0


class TestBuiltinLongContentMatch:
    def test_10_plus_bytes_gives_minus_10(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Long"; content:"aqlKZ7wjzg0iKM00E1WB"; '
            'flow:established; sid:1; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == -10

    def test_5_to_9_bytes_gives_minus_5(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Medium"; content:"|09 22 33 30 28 35 2c|"; '
            'flow:established; sid:2; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == -5

    def test_under_5_bytes_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Short"; content:"GET"; '
            'flow:established; sid:3; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is None

    def test_exactly_5_bytes_gives_minus_5(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Exact 5"; content:"ABCDE"; '
            'flow:established; sid:4; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is not None
        assert result.delta == -5

    def test_exactly_10_bytes_gives_minus_10(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Exact 10"; content:"ABCDEFGHIJ"; '
            'flow:established; sid:5; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is not None
        assert result.delta == -10

    def test_multiple_contents_combined(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"Multi"; content:"1234567890"; content:"1234567890"; '
            'flow:established; sid:6; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is not None
        assert result.delta == -10

    def test_no_content_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"None"; sid:7; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is None

    def test_hex_content_long(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Hex long"; content:"|554b30303736305337473130 554b30303736305337473130|"; '
            'flow:established; sid:8; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is not None
        assert result.delta == -10


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


class TestBuiltinPortSpecificity:
    def test_specific_port_gives_minus_3(self):
        rule = parse_rule(
            'alert tcp any any -> any 443 '
            '(msg:"Specific port"; content:"test"; flow:established; sid:1; rev:1;)'
        )
        result = builtin_port_specificity(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == -3

    def test_port_range_gives_minus_1(self):
        rule = parse_rule(
            'alert tcp any any -> any 5800:5820 '
            '(msg:"Port range"; content:"test"; flow:established; sid:2; rev:1;)'
        )
        result = builtin_port_specificity(rule)
        assert result is not None
        assert result.delta == -1

    def test_both_specific_ports(self):
        rule = parse_rule(
            'alert tcp any 80 -> any 443 '
            '(msg:"Both ports"; content:"test"; flow:established; sid:3; rev:1;)'
        )
        result = builtin_port_specificity(rule)
        assert result is not None
        assert result.delta == -6

    def test_any_ports_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Any"; content:"test"; flow:established; sid:4; rev:1;)'
        )
        result = builtin_port_specificity(rule)
        assert result is None

    def test_variable_port_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any $HTTP_PORTS '
            '(msg:"Variable"; content:"test"; flow:established; sid:5; rev:1;)'
        )
        result = builtin_port_specificity(rule)
        assert result is None

    def test_negated_port_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any !80 '
            '(msg:"Negated"; content:"test"; flow:established; sid:6; rev:1;)'
        )
        result = builtin_port_specificity(rule)
        assert result is None


class TestBuiltinFlowbitsIsset:
    def test_isset_triggers(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Flowbits isset"; flowbits:isset,ET.http.javaclient; '
            'content:"test"; flow:established; sid:1; rev:1;)'
        )
        result = builtin_flowbits_isset(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == -8

    def test_set_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Flowbits set"; flowbits:set,ET.http.javaclient; '
            'content:"test"; flow:established; sid:2; rev:1;)'
        )
        result = builtin_flowbits_isset(rule)
        assert result is None

    def test_no_flowbits_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"No flowbits"; content:"test"; flow:established; sid:3; rev:1;)'
        )
        result = builtin_flowbits_isset(rule)
        assert result is None

    def test_toggle_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Flowbits toggle"; flowbits:toggle,some_bit; '
            'content:"test"; flow:established; sid:4; rev:1;)'
        )
        result = builtin_flowbits_isset(rule)
        assert result is None


class TestBuiltinIpIocFp:
    def test_specific_ip_returns_fp_reduction(self):
        rule = parse_rule(
            'alert tcp $HOME_NET any -> [91.99.89.71] 443 '
            '(msg:"ThreatFox IP"; sid:1; rev:1;)'
        )
        result = builtin_ip_ioc_fp(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == -5

    def test_no_specific_ip_no_trigger(self):
        rule = parse_rule(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"Variables"; sid:2; rev:1;)'
        )
        result = builtin_ip_ioc_fp(rule)
        assert result is None

    def test_any_ip_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any 80 '
            '(msg:"Any"; sid:3; rev:1;)'
        )
        result = builtin_ip_ioc_fp(rule)
        assert result is None


class TestBuiltinSingleContentHttpMethod:
    def test_single_get_triggers(self):
        rule = parse_rule(
            'alert http any any -> any any '
            '(msg:"GET only"; content:"GET"; http_method; '
            'flow:established,to_server; sid:1; rev:1;)'
        )
        result = builtin_single_content_http_method(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == 8

    def test_post_triggers(self):
        rule = parse_rule(
            'alert http any any -> any any '
            '(msg:"POST only"; content:"POST"; http_method; '
            'flow:established,to_server; sid:2; rev:1;)'
        )
        result = builtin_single_content_http_method(rule)
        assert result is not None
        assert result.delta == 8

    def test_method_plus_uri_no_trigger(self):
        rule = parse_rule(
            'alert http any any -> any any '
            '(msg:"GET with URI"; content:"GET"; http_method; '
            'content:"/malware"; http_uri; '
            'flow:established,to_server; sid:3; rev:1;)'
        )
        result = builtin_single_content_http_method(rule)
        assert result is None

    def test_no_content_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"No content"; sid:4; rev:1;)'
        )
        result = builtin_single_content_http_method(rule)
        assert result is None

    def test_non_method_content_no_trigger(self):
        rule = parse_rule(
            'alert http any any -> any any '
            '(msg:"Specific content"; content:"evil-payload.exe"; '
            'flow:established,to_server; sid:5; rev:1;)'
        )
        result = builtin_single_content_http_method(rule)
        assert result is None


class TestBuiltinLongContentMatchNullDiscount:
    def test_null_heavy_content_discounted(self):
        """16 bytes total but 14 null → 2 effective → no reward."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Null heavy"; content:"|00 00 00 00 00 00 00 00 00 00 00 00 00 00 DE AD|"; '
            'flow:established; sid:100; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is None  # 2 effective bytes < 5

    def test_mixed_null_still_rewards(self):
        """10 bytes total, 3 null → 7 effective → -5 reward."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Mixed"; content:"|00 00 00|ABCDEFG"; '
            'flow:established; sid:101; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is not None
        assert result.delta == -5

    def test_no_null_bytes_unchanged(self):
        """Pure ASCII 10+ bytes still gets -10."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Clean"; content:"ABCDEFGHIJ"; '
            'flow:established; sid:102; rev:1;)'
        )
        result = builtin_long_content_match(rule)
        assert result is not None
        assert result.delta == -10


class TestBuiltinNullHeavyContent:
    def test_mostly_null_triggers(self):
        """14/16 null bytes → 87.5% → triggers +5."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Null heavy"; content:"|00 00 00 00 00 00 00 00 00 00 00 00 00 00 DE AD|"; '
            'flow:established; sid:200; rev:1;)'
        )
        result = builtin_null_heavy_content(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == 5

    def test_exactly_half_no_trigger(self):
        """2/4 null = 50% — not strictly greater than 50%."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Half"; content:"|00 00 DE AD|"; '
            'flow:established; sid:201; rev:1;)'
        )
        result = builtin_null_heavy_content(rule)
        assert result is None

    def test_no_null_bytes_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Clean"; content:"ABCDEFGHIJ"; '
            'flow:established; sid:202; rev:1;)'
        )
        result = builtin_null_heavy_content(rule)
        assert result is None

    def test_no_content_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"None"; sid:203; rev:1;)'
        )
        result = builtin_null_heavy_content(rule)
        assert result is None


class TestBuiltinWeakMultiContent:
    def test_all_tiny_contents_triggers(self):
        """3 content matches, all 1 byte → triggers +10."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Weak multi"; content:"|22|"; content:"|00|"; content:"|5c|"; '
            'flow:established; sid:300; rev:1;)'
        )
        result = builtin_weak_multi_content(rule)
        assert result is not None
        assert result.dimension == "false_positive"
        assert result.delta == 10

    def test_two_byte_contents_triggers(self):
        """2 content matches, both 2 bytes → triggers."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Two byte"; content:"|DE AD|"; content:"|BE EF|"; '
            'flow:established; sid:301; rev:1;)'
        )
        result = builtin_weak_multi_content(rule)
        assert result is not None
        assert result.delta == 10

    def test_one_long_content_no_trigger(self):
        """2 matches but one is 3 bytes → no trigger."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"One long"; content:"|22|"; content:"ABC"; '
            'flow:established; sid:302; rev:1;)'
        )
        result = builtin_weak_multi_content(rule)
        assert result is None

    def test_single_content_no_trigger(self):
        """Only 1 content match → no trigger (needs 2+)."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Single"; content:"|22|"; '
            'flow:established; sid:303; rev:1;)'
        )
        result = builtin_weak_multi_content(rule)
        assert result is None

    def test_no_content_no_trigger(self):
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"None"; sid:304; rev:1;)'
        )
        result = builtin_weak_multi_content(rule)
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
