"""YAML scoring profile loading and validation."""

import importlib.resources
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ScoreDimensionConfig:
    """Configuration for a single score dimension (quality or false_positive)."""

    base: float = 0.0
    min: float | None = None
    max: float | None = None


@dataclass
class ConditionConfig:
    """A declarative condition to evaluate against a parsed rule.

    Supports leaf conditions (field + operator + value), negation (not + condition),
    and compound conditions (all/any + conditions list).
    """

    operator: str
    field: str | None = None
    value: Any = None
    condition: "ConditionConfig | None" = None  # for "not"
    conditions: "list[ConditionConfig] | None" = None  # for "all" / "any"


@dataclass
class CriterionConfig:
    """A single scoring criterion from the profile."""

    id: str
    name: str
    description: str
    dimension: str  # "quality" or "false_positive"
    weight: float
    condition: ConditionConfig


@dataclass
class PluginConfig:
    """A plugin reference from the profile."""

    id: str
    name: str
    callable: str  # dotted Python path


@dataclass
class ScoringProfile:
    """Complete scoring profile loaded from YAML."""

    quality: ScoreDimensionConfig = field(default_factory=ScoreDimensionConfig)
    false_positive: ScoreDimensionConfig = field(default_factory=ScoreDimensionConfig)
    criteria: list[CriterionConfig] = field(default_factory=list)
    plugins: list[PluginConfig] = field(default_factory=list)


VALID_OPERATORS = {"exists", "not_exists", "eq", "neq", "in", "not_in", "gt", "gte", "lt", "lte", "contains", "not", "all", "any"}
VALID_DIMENSIONS = {"quality", "false_positive"}


def load_profile(path: str | Path) -> ScoringProfile:
    """Load a scoring profile from a YAML file."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return _build_profile(data)


def load_default_profile() -> ScoringProfile:
    """Load the bundled default scoring profile."""
    pkg = importlib.resources.files("suricata_rule_scoring") / "scoring_profiles" / "default.yaml"
    text = pkg.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return _build_profile(data)


def _build_profile(data: dict) -> ScoringProfile:
    """Build a ScoringProfile from parsed YAML data."""
    scoring_data = data.get("scoring", {})
    quality_cfg = _parse_dimension(scoring_data.get("quality", {}))
    fp_cfg = _parse_dimension(scoring_data.get("false_positive", {}))

    criteria = []
    for c in data.get("criteria", []):
        criteria.append(_parse_criterion(c))

    plugins = []
    for p in data.get("plugins", []):
        plugins.append(PluginConfig(
            id=p["id"],
            name=p.get("name", p["id"]),
            callable=p["callable"],
        ))

    profile = ScoringProfile(
        quality=quality_cfg,
        false_positive=fp_cfg,
        criteria=criteria,
        plugins=plugins,
    )
    _validate_profile(profile)
    return profile


def _parse_dimension(data: dict) -> ScoreDimensionConfig:
    """Parse a score dimension configuration block."""
    return ScoreDimensionConfig(
        base=float(data.get("base", 0)),
        min=float(data["min"]) if data.get("min") is not None else None,
        max=float(data["max"]) if data.get("max") is not None else None,
    )


def _parse_criterion(data: dict) -> CriterionConfig:
    """Parse a single criterion from YAML data."""
    required = {"id", "name", "dimension", "weight", "condition"}
    missing = required - set(data.keys())
    if missing:
        raise ValueError(f"Criterion missing required fields: {missing}")

    return CriterionConfig(
        id=data["id"],
        name=data["name"],
        description=data.get("description", ""),
        dimension=data["dimension"],
        weight=float(data["weight"]),
        condition=_parse_condition(data["condition"]),
    )


def _parse_condition(data: dict) -> ConditionConfig:
    """Recursively parse a condition tree from YAML data."""
    operator = data.get("operator")
    if not operator:
        raise ValueError(f"Condition missing 'operator': {data}")

    if operator in ("not",):
        inner = data.get("condition")
        if not inner:
            raise ValueError("'not' operator requires a 'condition' field")
        return ConditionConfig(
            operator=operator,
            condition=_parse_condition(inner),
        )

    if operator in ("all", "any"):
        inner_list = data.get("conditions")
        if not inner_list:
            raise ValueError(f"'{operator}' operator requires a 'conditions' list")
        return ConditionConfig(
            operator=operator,
            conditions=[_parse_condition(c) for c in inner_list],
        )

    # Leaf condition
    return ConditionConfig(
        operator=operator,
        field=data.get("field"),
        value=data.get("value"),
    )


def _validate_profile(profile: ScoringProfile) -> None:
    """Validate a scoring profile for correctness."""
    seen_ids = set()
    for c in profile.criteria:
        if c.id in seen_ids:
            raise ValueError(f"Duplicate criterion id: {c.id!r}")
        seen_ids.add(c.id)

        if c.dimension not in VALID_DIMENSIONS:
            raise ValueError(
                f"Criterion {c.id!r} has invalid dimension {c.dimension!r}. "
                f"Must be one of: {VALID_DIMENSIONS}"
            )
        _validate_condition(c.condition, c.id)

    seen_plugin_ids = set()
    for p in profile.plugins:
        if p.id in seen_plugin_ids:
            raise ValueError(f"Duplicate plugin id: {p.id!r}")
        seen_plugin_ids.add(p.id)


def _validate_condition(cond: ConditionConfig, criterion_id: str) -> None:
    """Recursively validate a condition tree."""
    if cond.operator not in VALID_OPERATORS:
        raise ValueError(
            f"Criterion {criterion_id!r}: invalid operator {cond.operator!r}. "
            f"Must be one of: {VALID_OPERATORS}"
        )

    if cond.operator == "not":
        if cond.condition is None:
            raise ValueError(f"Criterion {criterion_id!r}: 'not' requires 'condition'")
        _validate_condition(cond.condition, criterion_id)
    elif cond.operator in ("all", "any"):
        if not cond.conditions:
            raise ValueError(f"Criterion {criterion_id!r}: '{cond.operator}' requires 'conditions'")
        for sub in cond.conditions:
            _validate_condition(sub, criterion_id)
    else:
        # Leaf operators need a field
        if not cond.field:
            raise ValueError(
                f"Criterion {criterion_id!r}: operator {cond.operator!r} requires 'field'"
            )
