"""Summary statistics for scored rules."""

import statistics

from .models import RuleScore, SummaryStats

HISTOGRAM_BUCKETS = ["<0", "0-10", "11-25", "26-50", ">50"]


def summarize(results: list[RuleScore]) -> SummaryStats:
    """Compute aggregate statistics over a list of scored rules."""
    if not results:
        return SummaryStats(
            total_rules=0,
            mean_quality=0.0,
            median_quality=0.0,
            min_quality=0.0,
            max_quality=0.0,
            mean_false_positive=0.0,
            median_false_positive=0.0,
            min_false_positive=0.0,
            max_false_positive=0.0,
            quality_histogram={b: 0 for b in HISTOGRAM_BUCKETS},
            false_positive_histogram={b: 0 for b in HISTOGRAM_BUCKETS},
        )

    quality_scores = [r.quality for r in results]
    fp_scores = [r.false_positive for r in results]

    return SummaryStats(
        total_rules=len(results),
        mean_quality=round(statistics.mean(quality_scores), 1),
        median_quality=round(statistics.median(quality_scores), 1),
        min_quality=min(quality_scores),
        max_quality=max(quality_scores),
        mean_false_positive=round(statistics.mean(fp_scores), 1),
        median_false_positive=round(statistics.median(fp_scores), 1),
        min_false_positive=min(fp_scores),
        max_false_positive=max(fp_scores),
        quality_histogram=_build_histogram(quality_scores),
        false_positive_histogram=_build_histogram(fp_scores),
    )


def _build_histogram(values: list[float]) -> dict[str, int]:
    """Bucket values into a histogram."""
    buckets = {b: 0 for b in HISTOGRAM_BUCKETS}
    for v in values:
        if v < 0:
            buckets["<0"] += 1
        elif v <= 10:
            buckets["0-10"] += 1
        elif v <= 25:
            buckets["11-25"] += 1
        elif v <= 50:
            buckets["26-50"] += 1
        else:
            buckets[">50"] += 1
    return buckets
