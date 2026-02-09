"""Tests for the criteria evaluation engine."""

import pytest
from suricata_rule_parser import parse_rule

from suricata_rule_scoring.config import ConditionConfig
from suricata_rule_scoring.criteria import evaluate_condition, resolve_field


# -- Fixtures: reusable parsed rules --

@pytest.fixture
def basic_rule():
    return parse_rule(
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
        '(msg:"Test rule"; content:"GET"; content:"/index.html"; '
        'flow:established,to_server; classtype:web-application-attack; '
        'reference:url,example.com; sid:1000001; rev:3; '
        'metadata:created_at 2024_01_01;)'
    )


@pytest.fixture
def minimal_rule():
    return parse_rule(
        'alert ip any any -> any any (msg:"Minimal"; sid:1000002; rev:1;)'
    )


@pytest.fixture
def pcre_rule():
    return parse_rule(
        'alert tcp any any -> any any '
        '(msg:"PCRE only"; pcre:"/test/i"; flow:established; '
        'sid:1000003; rev:1; classtype:misc-activity;)'
    )


@pytest.fixture
def fast_pattern_rule():
    return parse_rule(
        'alert http $HOME_NET any -> $EXTERNAL_NET any '
        '(msg:"Fast pattern"; content:"malware"; fast_pattern; '
        'flow:established,to_server; sid:1000004; rev:1;)'
    )


# -- Field resolver tests --

class TestResolveField:
    def test_header_alias_protocol(self, basic_rule):
        assert resolve_field(basic_rule, "protocol") == "tcp"

    def test_header_alias_source_address(self, basic_rule):
        assert resolve_field(basic_rule, "source_address") == "$HOME_NET"

    def test_header_alias_destination_address(self, basic_rule):
        assert resolve_field(basic_rule, "destination_address") == "$EXTERNAL_NET"

    def test_header_alias_source_port(self, basic_rule):
        assert resolve_field(basic_rule, "source_port") == "any"

    def test_header_alias_destination_port(self, basic_rule):
        assert resolve_field(basic_rule, "destination_port") == "80"

    def test_options_content(self, basic_rule):
        val = resolve_field(basic_rule, "options.content")
        assert isinstance(val, list)
        assert len(val) == 2

    def test_options_content_count(self, basic_rule):
        assert resolve_field(basic_rule, "options.content|count") == 2

    def test_options_flow(self, basic_rule):
        val = resolve_field(basic_rule, "options.flow")
        assert isinstance(val, list)
        assert "established" in val

    def test_options_classtype(self, basic_rule):
        assert resolve_field(basic_rule, "options.classtype") == "web-application-attack"

    def test_options_sid(self, basic_rule):
        assert resolve_field(basic_rule, "options.sid") == 1000001

    def test_options_rev(self, basic_rule):
        assert resolve_field(basic_rule, "options.rev") == 3

    def test_options_reference(self, basic_rule):
        val = resolve_field(basic_rule, "options.reference")
        assert isinstance(val, list)
        assert len(val) >= 1

    def test_options_metadata(self, basic_rule):
        val = resolve_field(basic_rule, "options.metadata")
        assert isinstance(val, dict)

    def test_options_pcre_in_other_options(self, pcre_rule):
        val = resolve_field(pcre_rule, "options.pcre")
        assert val is not None

    def test_options_fast_pattern(self, fast_pattern_rule):
        val = resolve_field(fast_pattern_rule, "options.fast_pattern")
        assert val is not None

    def test_missing_field_returns_none(self, minimal_rule):
        assert resolve_field(minimal_rule, "options.nonexistent_field") is None

    def test_count_of_empty_list(self, minimal_rule):
        assert resolve_field(minimal_rule, "options.content|count") == 0

    def test_count_of_none(self, minimal_rule):
        assert resolve_field(minimal_rule, "options.fast_pattern|count") == 0

    def test_direct_rule_property(self, basic_rule):
        assert resolve_field(basic_rule, "sid") == 1000001


# -- Condition evaluation tests --

class TestEvaluateCondition:
    def test_exists_true(self, basic_rule):
        cond = ConditionConfig(operator="exists", field="options.content")
        assert evaluate_condition(basic_rule, cond) is True

    def test_exists_false(self, minimal_rule):
        cond = ConditionConfig(operator="exists", field="options.content")
        assert evaluate_condition(minimal_rule, cond) is False

    def test_not_exists(self, minimal_rule):
        cond = ConditionConfig(operator="not_exists", field="options.content")
        assert evaluate_condition(minimal_rule, cond) is True

    def test_eq_true(self, basic_rule):
        cond = ConditionConfig(operator="eq", field="protocol", value="tcp")
        assert evaluate_condition(basic_rule, cond) is True

    def test_eq_false(self, basic_rule):
        cond = ConditionConfig(operator="eq", field="protocol", value="udp")
        assert evaluate_condition(basic_rule, cond) is False

    def test_neq(self, basic_rule):
        cond = ConditionConfig(operator="neq", field="protocol", value="ip")
        assert evaluate_condition(basic_rule, cond) is True

    def test_in_true(self, basic_rule):
        cond = ConditionConfig(operator="in", field="protocol", value=["tcp", "udp"])
        assert evaluate_condition(basic_rule, cond) is True

    def test_in_false(self, basic_rule):
        cond = ConditionConfig(operator="in", field="protocol", value=["http", "dns"])
        assert evaluate_condition(basic_rule, cond) is False

    def test_gte(self, basic_rule):
        cond = ConditionConfig(operator="gte", field="options.content|count", value=2)
        assert evaluate_condition(basic_rule, cond) is True

    def test_gt(self, basic_rule):
        cond = ConditionConfig(operator="gt", field="options.content|count", value=1)
        assert evaluate_condition(basic_rule, cond) is True

    def test_lt(self, basic_rule):
        cond = ConditionConfig(operator="lt", field="options.content|count", value=5)
        assert evaluate_condition(basic_rule, cond) is True

    def test_lte(self, basic_rule):
        cond = ConditionConfig(operator="lte", field="options.content|count", value=2)
        assert evaluate_condition(basic_rule, cond) is True

    def test_contains_list(self, basic_rule):
        cond = ConditionConfig(operator="contains", field="options.flow", value="established")
        assert evaluate_condition(basic_rule, cond) is True

    def test_not_operator(self, minimal_rule):
        inner = ConditionConfig(operator="exists", field="options.content")
        cond = ConditionConfig(operator="not", condition=inner)
        assert evaluate_condition(minimal_rule, cond) is True

    def test_all_operator(self, basic_rule):
        cond = ConditionConfig(
            operator="all",
            conditions=[
                ConditionConfig(operator="exists", field="options.content"),
                ConditionConfig(operator="exists", field="options.flow"),
            ],
        )
        assert evaluate_condition(basic_rule, cond) is True

    def test_all_operator_false(self, basic_rule):
        cond = ConditionConfig(
            operator="all",
            conditions=[
                ConditionConfig(operator="exists", field="options.content"),
                ConditionConfig(operator="eq", field="protocol", value="udp"),
            ],
        )
        assert evaluate_condition(basic_rule, cond) is False

    def test_any_operator(self, basic_rule):
        cond = ConditionConfig(
            operator="any",
            conditions=[
                ConditionConfig(operator="eq", field="protocol", value="udp"),
                ConditionConfig(operator="eq", field="protocol", value="tcp"),
            ],
        )
        assert evaluate_condition(basic_rule, cond) is True

    def test_any_operator_false(self, basic_rule):
        cond = ConditionConfig(
            operator="any",
            conditions=[
                ConditionConfig(operator="eq", field="protocol", value="udp"),
                ConditionConfig(operator="eq", field="protocol", value="http"),
            ],
        )
        assert evaluate_condition(basic_rule, cond) is False

    def test_nested_not_all(self, basic_rule):
        """Test pcre_without_content pattern: pcre exists AND NOT content exists."""
        cond = ConditionConfig(
            operator="all",
            conditions=[
                ConditionConfig(operator="exists", field="options.content"),
                ConditionConfig(
                    operator="not",
                    condition=ConditionConfig(operator="exists", field="options.pcre"),
                ),
            ],
        )
        # basic_rule has content but no pcre
        assert evaluate_condition(basic_rule, cond) is True

    def test_sid_exists_via_options(self, basic_rule):
        """SID is a direct attribute (int), exists means != 0."""
        cond = ConditionConfig(operator="exists", field="options.sid")
        assert evaluate_condition(basic_rule, cond) is True
