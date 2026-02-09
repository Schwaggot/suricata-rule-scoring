"""Tests for data models."""

from suricata_rule_scoring.models import CriterionResult, RuleScore, ScoringResult, SummaryStats


class TestCriterionResult:
    def test_creation(self):
        cr = CriterionResult(
            criterion_id="test",
            criterion_name="Test Criterion",
            dimension="quality",
            delta=10.0,
            reason="Test reason",
        )
        assert cr.criterion_id == "test"
        assert cr.criterion_name == "Test Criterion"
        assert cr.dimension == "quality"
        assert cr.delta == 10.0
        assert cr.reason == "Test reason"

    def test_frozen(self):
        cr = CriterionResult("id", "name", "quality", 5.0, "reason")
        try:
            cr.delta = 20.0
            assert False, "Should not be able to mutate frozen dataclass"
        except AttributeError:
            pass


class TestRuleScore:
    def test_creation(self):
        rs = RuleScore(sid=1000, rev=1, quality=25.0, false_positive=10.0)
        assert rs.sid == 1000
        assert rs.rev == 1
        assert rs.quality == 25.0
        assert rs.false_positive == 10.0
        assert rs.matched_criteria == []

    def test_with_criteria(self):
        cr = CriterionResult("id", "name", "quality", 5.0, "reason")
        rs = RuleScore(sid=1, rev=1, quality=5.0, false_positive=0.0, matched_criteria=[cr])
        assert len(rs.matched_criteria) == 1


class TestScoringResult:
    def test_creation(self):
        sr = ScoringResult(dimension="false_positive", delta=-5.0, reason="test")
        assert sr.dimension == "false_positive"
        assert sr.delta == -5.0

    def test_frozen(self):
        sr = ScoringResult("quality", 3.0, "reason")
        try:
            sr.delta = 10.0
            assert False, "Should not be able to mutate frozen dataclass"
        except AttributeError:
            pass


class TestSummaryStats:
    def test_creation(self):
        stats = SummaryStats(
            total_rules=100,
            mean_quality=15.0,
            median_quality=12.0,
            min_quality=-10.0,
            max_quality=50.0,
            mean_false_positive=8.0,
            median_false_positive=6.0,
            min_false_positive=-5.0,
            max_false_positive=30.0,
        )
        assert stats.total_rules == 100
        assert stats.quality_histogram == {}
        assert stats.false_positive_histogram == {}
