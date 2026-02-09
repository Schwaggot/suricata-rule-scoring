"""suricata-rule-scoring: Evaluate Suricata IDS rules against configurable scoring criteria."""

from .models import CriterionResult, RuleScore, ScoringResult, SummaryStats
from .scorer import RuleScorer
from .stats import summarize

__all__ = [
    "RuleScorer",
    "RuleScore",
    "CriterionResult",
    "ScoringResult",
    "SummaryStats",
    "summarize",
]
