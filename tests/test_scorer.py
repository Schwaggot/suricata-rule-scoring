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
