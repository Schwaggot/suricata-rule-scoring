"""Tests for the RuleScorer class."""

import pytest
from suricata_rule_parser import parse_rule

from suricata_rule_scoring import RuleScorer, RuleScore
from suricata_rule_scoring.models import ScoringResult


@pytest.fixture
def scorer():
    return RuleScorer()


@pytest.fixture
def custom_scorer():
    return RuleScorer.from_config("tests/fixtures/test_profile.yaml")


@pytest.fixture
def high_quality_rule():
    return parse_rule(
        'alert http $HOME_NET any -> $EXTERNAL_NET 443 '
        '(msg:"High quality"; flow:established,to_server; '
        'content:"GET"; http_method; content:"/malware"; http_uri; fast_pattern; '
        'content:"Host|3a 20|evil.com"; http_header; '
        'reference:url,example.com; classtype:trojan-activity; '
        'sid:2000001; rev:3; metadata:created_at 2024_01_01;)'
    )


@pytest.fixture
def poor_quality_rule():
    return parse_rule(
        'alert ip any any -> any any (msg:"Poor quality"; sid:2000002; rev:1;)'
    )


@pytest.fixture
def pcre_only_rule():
    return parse_rule(
        'alert tcp any any -> any any '
        '(msg:"PCRE only"; pcre:"/test/i"; '
        'sid:2000003; rev:1; classtype:misc-activity;)'
    )


class TestRuleScorer:
    def test_high_quality_scores_high(self, scorer, high_quality_rule):
        result = scorer.score(high_quality_rule)
        assert isinstance(result, RuleScore)
        assert result.sid == 2000001
        assert result.rev == 3
        assert result.quality > 20  # Should be significantly positive

    def test_poor_quality_scores_low(self, scorer, poor_quality_rule):
        result = scorer.score(poor_quality_rule)
        assert result.quality < 0  # Should be negative

    def test_poor_quality_high_fp(self, scorer, poor_quality_rule):
        """Poor rule with any/any should have high FP score."""
        result = scorer.score(poor_quality_rule)
        assert result.false_positive > 10

    def test_pcre_only_penalty(self, scorer, pcre_only_rule):
        """PCRE-only rule should get quality penalty and FP increase."""
        result = scorer.score(pcre_only_rule)
        # Should have pcre_without_content matched
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "pcre_without_content" in ids or "pcre_only" in ids

    def test_matched_criteria_populated(self, scorer, high_quality_rule):
        result = scorer.score(high_quality_rule)
        assert len(result.matched_criteria) > 0
        for cr in result.matched_criteria:
            assert cr.criterion_id
            assert cr.dimension in ("quality", "false_positive")

    def test_score_many(self, scorer, high_quality_rule, poor_quality_rule):
        results = scorer.score_many([high_quality_rule, poor_quality_rule])
        assert len(results) == 2
        assert results[0].sid == 2000001
        assert results[1].sid == 2000002

    def test_custom_config(self, custom_scorer, high_quality_rule):
        result = custom_scorer.score(high_quality_rule)
        # Custom profile starts quality at base=10
        # has_content criterion adds 20
        assert result.quality >= 30

    def test_custom_config_clamping(self, custom_scorer, poor_quality_rule):
        result = custom_scorer.score(poor_quality_rule)
        # FP min is 0 in custom config
        assert result.false_positive >= 0
        # Quality min is -50
        assert result.quality >= -50

    def test_register_plugin(self, scorer, high_quality_rule):
        def my_plugin(rule):
            return ScoringResult(dimension="quality", delta=-100, reason="Custom penalty")

        scorer.register_plugin("my_plugin", my_plugin)
        result = scorer.score(high_quality_rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "my_plugin" in ids

    def test_plugin_returning_none(self, scorer, high_quality_rule):
        """Plugin that returns None should not affect score."""
        def noop_plugin(rule):
            return None

        scorer.register_plugin("noop", noop_plugin)
        result = scorer.score(high_quality_rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "noop" not in ids

    def test_plugin_exception_handled(self, scorer, high_quality_rule):
        """Plugin that raises should be silently skipped."""
        def bad_plugin(rule):
            raise RuntimeError("broken")

        scorer.register_plugin("bad", bad_plugin)
        # Should not raise
        result = scorer.score(high_quality_rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "bad" not in ids

    def test_content_position_modifiers(self, scorer):
        """Rule with depth/offset should get quality bonus and FP reduction."""
        rule = parse_rule(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
            '(msg:"Positioned content"; content:"GET"; depth:3; offset:0; '
            'flow:established,to_server; sid:3000001; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "content_position_modifiers" in ids
        assert "positioned_content" in ids

    def test_has_flowbits(self, scorer):
        """Rule with flowbits should get quality bonus."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Flowbits"; flowbits:set,ET.test; content:"test"; '
            'flow:established; sid:3000002; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "has_flowbits" in ids

    def test_has_byte_operations(self, scorer):
        """Rule with byte_test should get quality bonus and FP reduction."""
        rule = parse_rule(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
            '(msg:"Byte test"; content:"|00 01|"; byte_test:2,=,0x0100,0; '
            'flow:established; sid:3000003; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "has_byte_operations" in ids
        assert "byte_operations_precision" in ids

    def test_has_dsize(self, scorer):
        """Rule with dsize should get quality bonus and FP reduction."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Dsize"; content:"test"; dsize:>100; '
            'flow:established; sid:3000004; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "has_dsize" in ids
        assert "dsize_constraint" in ids

    def test_content_anchoring(self, scorer):
        """Rule with endswith should get quality bonus."""
        rule = parse_rule(
            'alert dns any any -> any any '
            '(msg:"DNS anchored"; dns.query; content:".evil.com"; endswith; '
            'sid:3000005; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "content_anchoring" in ids

    def test_bidirectional_rule(self, scorer):
        """Bidirectional rule should get quality penalty and FP increase."""
        rule = parse_rule(
            'alert tcp any any <> any any '
            '(msg:"Bidir"; content:"test"; flow:established; '
            'sid:3000006; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "bidirectional_rule" in ids
        assert "bidirectional_fp" in ids

    def test_has_bsize(self, scorer):
        """Rule with bsize should get FP reduction."""
        rule = parse_rule(
            'alert http any any -> any any '
            '(msg:"Bsize"; content:"test"; http.uri; bsize:>200; '
            'flow:established,to_server; sid:3000007; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "has_bsize" in ids

    def test_flowbits_isset_plugin(self, scorer):
        """Rule with flowbits:isset should get FP reduction via plugin."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Flowbits isset"; flowbits:isset,ET.test; '
            'content:"evil"; flow:established; sid:3000008; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "flowbits_isset" in ids

    def test_ip_ioc_fp_plugin(self, scorer):
        """Rule with specific IP should get FP reduction via plugin."""
        rule = parse_rule(
            'alert tcp $HOME_NET any -> [91.99.89.71] 443 '
            '(msg:"IP IoC"; sid:3000009; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "ip_ioc_fp" in ids
        # Should also have the quality plugin
        assert "ip_ioc_rule" in ids

    def test_single_content_http_method_plugin(self, scorer):
        """Rule with only GET content should get FP increase via plugin."""
        rule = parse_rule(
            'alert http any any -> any any '
            '(msg:"GET only"; content:"GET"; http_method; '
            'flow:established,to_server; sid:3000010; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "single_content_http_method" in ids

    def test_has_isdataat(self, scorer):
        """Rule with isdataat should get quality bonus."""
        rule = parse_rule(
            'alert tcp any any -> any any '
            '(msg:"Isdataat"; content:"test"; isdataat:50; '
            'flow:established; sid:3000011; rev:1;)'
        )
        result = scorer.score(rule)
        ids = {c.criterion_id for c in result.matched_criteria}
        assert "has_isdataat" in ids
