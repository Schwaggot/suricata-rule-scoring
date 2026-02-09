"""Core scoring orchestration."""

from pathlib import Path
from typing import Callable, Self

from suricata_rule_parser import SuricataRule

from .config import ScoringProfile, load_default_profile, load_profile
from .criteria import evaluate_condition
from .models import CriterionResult, RuleScore, ScoringResult
from .plugin import load_plugin


class RuleScorer:
    """Scores Suricata rules against a configurable profile of criteria and plugins."""

    def __init__(self, profile: ScoringProfile | None = None) -> None:
        self._profile = profile or load_default_profile()
        self._plugins: dict[str, Callable[[SuricataRule], ScoringResult | None]] = {}
        self._load_configured_plugins()

    @classmethod
    def from_config(cls, path: str | Path) -> Self:
        """Create a scorer from a YAML config file."""
        profile = load_profile(path)
        return cls(profile=profile)

    def register_plugin(
        self,
        plugin_id: str,
        func: Callable[[SuricataRule], ScoringResult | None],
    ) -> None:
        """Register a plugin callable programmatically."""
        self._plugins[plugin_id] = func

    def score(self, rule: SuricataRule) -> RuleScore:
        """Score a single parsed rule."""
        quality = self._profile.quality.base
        false_positive = self._profile.false_positive.base
        matched: list[CriterionResult] = []

        # Evaluate declarative criteria
        for criterion in self._profile.criteria:
            if evaluate_condition(rule, criterion.condition):
                result = CriterionResult(
                    criterion_id=criterion.id,
                    criterion_name=criterion.name,
                    dimension=criterion.dimension,
                    delta=criterion.weight,
                    reason=criterion.description,
                )
                matched.append(result)
                if criterion.dimension == "quality":
                    quality += criterion.weight
                else:
                    false_positive += criterion.weight

        # Run plugins
        for plugin_id, func in self._plugins.items():
            try:
                result = func(rule)
            except Exception:
                continue
            if result is not None:
                cr = CriterionResult(
                    criterion_id=plugin_id,
                    criterion_name=plugin_id,
                    dimension=result.dimension,
                    delta=result.delta,
                    reason=result.reason,
                )
                matched.append(cr)
                if result.dimension == "quality":
                    quality += result.delta
                else:
                    false_positive += result.delta

        # Apply clamping
        quality = self._clamp(quality, self._profile.quality)
        false_positive = self._clamp(false_positive, self._profile.false_positive)

        return RuleScore(
            sid=rule.options.sid,
            rev=rule.options.rev,
            quality=quality,
            false_positive=false_positive,
            matched_criteria=matched,
        )

    def score_many(self, rules: list[SuricataRule]) -> list[RuleScore]:
        """Score a list of parsed rules."""
        return [self.score(rule) for rule in rules]

    def _load_configured_plugins(self) -> None:
        """Load plugins declared in the profile."""
        for plugin_cfg in self._profile.plugins:
            func = load_plugin(plugin_cfg.callable)
            self._plugins[plugin_cfg.id] = func

    @staticmethod
    def _clamp(value: float, cfg) -> float:
        """Clamp a score within optional min/max bounds."""
        if cfg.min is not None and value < cfg.min:
            value = cfg.min
        if cfg.max is not None and value > cfg.max:
            value = cfg.max
        return value
