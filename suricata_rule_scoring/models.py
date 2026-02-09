"""Data models for suricata-rule-scoring."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CriterionResult:
    """Result of evaluating a single criterion against a rule."""

    criterion_id: str
    criterion_name: str
    dimension: str  # "quality" or "false_positive"
    delta: float
    reason: str


@dataclass
class RuleScore:
    """Complete scoring result for a single rule."""

    sid: int
    rev: int
    quality: float
    false_positive: float
    matched_criteria: list[CriterionResult] = field(default_factory=list)


@dataclass(frozen=True)
class ScoringResult:
    """Result returned by plugin callables."""

    dimension: str  # "quality" or "false_positive"
    delta: float
    reason: str


@dataclass
class SummaryStats:
    """Aggregate statistics over a collection of scored rules."""

    total_rules: int
    mean_quality: float
    median_quality: float
    min_quality: float
    max_quality: float
    mean_false_positive: float
    median_false_positive: float
    min_false_positive: float
    max_false_positive: float
    quality_histogram: dict[str, int] = field(default_factory=dict)
    false_positive_histogram: dict[str, int] = field(default_factory=dict)
