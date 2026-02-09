"""CLI entry point for suricata-rule-scorer."""

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from suricata_rule_parser import parse_file

from .scorer import RuleScorer
from .stats import summarize


def main(argv: list[str] | None = None) -> None:
    """Suricata Rule Scorer — evaluate rules against configurable scoring criteria."""
    parser = argparse.ArgumentParser(
        prog="suricata-rule-scorer",
        description="Evaluate Suricata IDS rules against configurable scoring criteria.",
    )
    subparsers = parser.add_subparsers(dest="command")

    score_parser = subparsers.add_parser("score", help="Score Suricata rules from a .rules file.")
    score_parser.add_argument("rules_file", help="Path to a .rules file.")
    score_parser.add_argument("--config", dest="config_path", default=None, help="Path to custom YAML scoring profile.")
    score_parser.add_argument("--format", dest="output_format", choices=["json", "csv"], default="json", help="Output format (default: json).")
    score_parser.add_argument("--output", dest="output_path", default=None, help="Write results to file instead of stdout.")
    score_parser.add_argument("--stats", dest="show_stats", action="store_true", default=False, help="Print summary statistics to stderr.")
    score_parser.add_argument("--sort-by", dest="sort_by", choices=["quality", "false_positive"], default=None, help="Sort output by a score dimension.")
    score_parser.add_argument("--min-quality", type=float, default=None, help="Only output rules with quality >= n.")
    score_parser.add_argument("--max-fp", type=float, default=None, help="Only output rules with false_positive <= n.")
    score_parser.add_argument("--verbose", action="store_true", default=False, help="Include matched criteria details in output.")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "score":
        _cmd_score(args)


def _cmd_score(args: argparse.Namespace) -> None:
    """Execute the score subcommand."""
    # Validate input file exists
    if not Path(args.rules_file).is_file():
        print(f"Error: File not found: {args.rules_file}", file=sys.stderr)
        sys.exit(2)

    # Load scorer
    if args.config_path:
        if not Path(args.config_path).is_file():
            print(f"Error: Config file not found: {args.config_path}", file=sys.stderr)
            sys.exit(2)
        scorer = RuleScorer.from_config(args.config_path)
    else:
        scorer = RuleScorer()

    # Parse and score rules
    rules = parse_file(args.rules_file)
    results = scorer.score_many(rules)

    # Filter
    if args.min_quality is not None:
        results = [r for r in results if r.quality >= args.min_quality]
    if args.max_fp is not None:
        results = [r for r in results if r.false_positive <= args.max_fp]

    # Sort
    if args.sort_by == "quality":
        results.sort(key=lambda r: r.quality, reverse=True)
    elif args.sort_by == "false_positive":
        results.sort(key=lambda r: r.false_positive)

    # Format output
    if args.output_format == "json":
        output_text = _format_json(results, args.verbose)
    else:
        output_text = _format_csv(results, args.verbose)

    # Write output
    if args.output_path:
        with open(args.output_path, "w", encoding="utf-8") as f:
            f.write(output_text)
    else:
        print(output_text)

    # Statistics
    if args.show_stats:
        stats = summarize(results)
        _print_stats(stats)


def _format_json(results, verbose: bool) -> str:
    """Format results as JSON."""
    records = []
    for r in results:
        record = {
            "sid": r.sid,
            "rev": r.rev,
            "quality": r.quality,
            "false_positive": r.false_positive,
        }
        if verbose:
            record["matched_criteria"] = [
                {
                    "id": c.criterion_id,
                    "dimension": c.dimension,
                    "delta": c.delta,
                    "reason": c.reason,
                }
                for c in r.matched_criteria
            ]
        records.append(record)
    return json.dumps(records, indent=2)


def _format_csv(results, verbose: bool) -> str:
    """Format results as CSV."""
    buf = io.StringIO()
    if verbose:
        fieldnames = ["sid", "rev", "quality", "false_positive", "matched_criteria"]
    else:
        fieldnames = ["sid", "rev", "quality", "false_positive"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        row = {
            "sid": r.sid,
            "rev": r.rev,
            "quality": r.quality,
            "false_positive": r.false_positive,
        }
        if verbose:
            row["matched_criteria"] = json.dumps([
                {"id": c.criterion_id, "delta": c.delta}
                for c in r.matched_criteria
            ])
        writer.writerow(row)
    return buf.getvalue()


def _print_stats(stats) -> None:
    """Print summary statistics to stderr."""
    print("\n=== Scoring Summary ===", file=sys.stderr)
    print(f"Rules scored: {stats.total_rules:,}", file=sys.stderr)
    print("", file=sys.stderr)
    print("Quality:", file=sys.stderr)
    print(
        f"  Mean: {stats.mean_quality}  |  Median: {stats.median_quality}  "
        f"|  Min: {stats.min_quality}  |  Max: {stats.max_quality}",
        file=sys.stderr,
    )
    hist = stats.quality_histogram
    print(
        f"  Distribution:  <0: {hist.get('<0', 0)}  |  0-10: {hist.get('0-10', 0)}  "
        f"|  11-25: {hist.get('11-25', 0)}  |  26-50: {hist.get('26-50', 0)}  "
        f"|  >50: {hist.get('>50', 0)}",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("False Positive Likelihood:", file=sys.stderr)
    print(
        f"  Mean: {stats.mean_false_positive}  |  Median: {stats.median_false_positive}  "
        f"|  Min: {stats.min_false_positive}  |  Max: {stats.max_false_positive}",
        file=sys.stderr,
    )
    hist = stats.false_positive_histogram
    print(
        f"  Distribution:  <0: {hist.get('<0', 0)}  |  0-10: {hist.get('0-10', 0)}  "
        f"|  11-25: {hist.get('11-25', 0)}  |  26-50: {hist.get('26-50', 0)}  "
        f"|  >50: {hist.get('>50', 0)}",
        file=sys.stderr,
    )
