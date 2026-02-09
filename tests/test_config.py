"""Tests for config loading and validation."""

import pytest

from suricata_rule_scoring.config import (
    ScoringProfile,
    _parse_condition,
    _validate_profile,
    load_default_profile,
    load_profile,
)

FIXTURES_DIR = "tests/fixtures"


class TestLoadProfile:
    def test_load_custom_profile(self):
        profile = load_profile(f"{FIXTURES_DIR}/test_profile.yaml")
        assert profile.quality.base == 10
        assert profile.quality.min == -50
        assert profile.quality.max == 100
        assert profile.false_positive.base == 5
        assert profile.false_positive.min == 0
        assert profile.false_positive.max == 50
        assert len(profile.criteria) == 2
        assert profile.criteria[0].id == "has_content"
        assert profile.criteria[1].id == "broad_scope"

    def test_load_default_profile(self):
        profile = load_default_profile()
        assert profile.quality.base == 0
        assert profile.false_positive.base == 0
        # Default profile has many criteria
        assert len(profile.criteria) >= 20
        # Has plugins configured
        assert len(profile.plugins) == 3

    def test_default_profile_criterion_ids(self):
        profile = load_default_profile()
        ids = {c.id for c in profile.criteria}
        assert "has_content_match" in ids
        assert "has_fast_pattern" in ids
        assert "specific_protocol" in ids
        assert "pcre_without_content" in ids
        assert "broad_network_scope" in ids

    def test_default_profile_dimensions_valid(self):
        profile = load_default_profile()
        for c in profile.criteria:
            assert c.dimension in ("quality", "false_positive")


class TestParseCondition:
    def test_leaf_condition(self):
        cond = _parse_condition({"field": "options.content", "operator": "exists"})
        assert cond.operator == "exists"
        assert cond.field == "options.content"

    def test_not_condition(self):
        cond = _parse_condition({
            "operator": "not",
            "condition": {"field": "options.content", "operator": "exists"},
        })
        assert cond.operator == "not"
        assert cond.condition.operator == "exists"

    def test_all_condition(self):
        cond = _parse_condition({
            "operator": "all",
            "conditions": [
                {"field": "options.content", "operator": "exists"},
                {"field": "options.flow", "operator": "exists"},
            ],
        })
        assert cond.operator == "all"
        assert len(cond.conditions) == 2

    def test_missing_operator_raises(self):
        with pytest.raises(ValueError, match="missing 'operator'"):
            _parse_condition({"field": "options.content"})

    def test_not_without_condition_raises(self):
        with pytest.raises(ValueError, match="requires a 'condition'"):
            _parse_condition({"operator": "not"})

    def test_all_without_conditions_raises(self):
        with pytest.raises(ValueError, match="requires a 'conditions' list"):
            _parse_condition({"operator": "all"})


class TestValidation:
    def test_duplicate_criterion_id(self):
        from suricata_rule_scoring.config import CriterionConfig, ConditionConfig

        profile = ScoringProfile(
            criteria=[
                CriterionConfig(
                    id="dup", name="Dup", description="", dimension="quality",
                    weight=1, condition=ConditionConfig(operator="exists", field="options.content"),
                ),
                CriterionConfig(
                    id="dup", name="Dup2", description="", dimension="quality",
                    weight=2, condition=ConditionConfig(operator="exists", field="options.flow"),
                ),
            ],
        )
        with pytest.raises(ValueError, match="Duplicate criterion id"):
            _validate_profile(profile)

    def test_invalid_dimension(self):
        from suricata_rule_scoring.config import CriterionConfig, ConditionConfig

        profile = ScoringProfile(
            criteria=[
                CriterionConfig(
                    id="bad", name="Bad", description="", dimension="invalid",
                    weight=1, condition=ConditionConfig(operator="exists", field="options.content"),
                ),
            ],
        )
        with pytest.raises(ValueError, match="invalid dimension"):
            _validate_profile(profile)

    def test_invalid_operator(self):
        from suricata_rule_scoring.config import CriterionConfig, ConditionConfig

        profile = ScoringProfile(
            criteria=[
                CriterionConfig(
                    id="bad", name="Bad", description="", dimension="quality",
                    weight=1, condition=ConditionConfig(operator="bad_op", field="options.content"),
                ),
            ],
        )
        with pytest.raises(ValueError, match="invalid operator"):
            _validate_profile(profile)
