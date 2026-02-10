"""Tests for the CLI."""

import json
import subprocess
import sys

import pytest

SAMPLE_RULES = "tests/fixtures/sample_rules.rules"
TEST_PROFILE = "tests/fixtures/test_profile.yaml"


def run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run the CLI via subprocess and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "suricata_rule_scoring", *args],
        capture_output=True,
        text=True,
    )


class TestCLIScore:
    def test_json_output(self):
        result = run_cli(SAMPLE_RULES)
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) > 0
        assert "sid" in data[0]
        assert "quality" in data[0]
        assert "false_positive" in data[0]

    def test_csv_output(self):
        result = run_cli(SAMPLE_RULES, "--format", "csv")
        assert result.returncode == 0, result.stderr
        lines = result.stdout.strip().splitlines()
        assert lines[0].strip() == "sid,rev,quality,false_positive"
        assert len(lines) > 1

    def test_verbose_json(self):
        result = run_cli(SAMPLE_RULES, "--verbose")
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert "matched_criteria" in data[0]

    def test_stats_output(self):
        result = run_cli(SAMPLE_RULES, "--stats")
        assert result.returncode == 0
        assert "Scoring Summary" in result.stderr

    def test_custom_config(self):
        result = run_cli(SAMPLE_RULES, "--config", TEST_PROFILE)
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert len(data) > 0

    def test_sort_by_quality(self):
        result = run_cli(SAMPLE_RULES, "--sort-by", "quality")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        qualities = [r["quality"] for r in data]
        assert qualities == sorted(qualities, reverse=True)

    def test_sort_by_false_positive(self):
        result = run_cli(SAMPLE_RULES, "--sort-by", "false_positive")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        fps = [r["false_positive"] for r in data]
        assert fps == sorted(fps)

    def test_min_quality_filter(self):
        result = run_cli(SAMPLE_RULES, "--min-quality", "20")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        for r in data:
            assert r["quality"] >= 20

    def test_max_fp_filter(self):
        result = run_cli(SAMPLE_RULES, "--max-fp", "5")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        for r in data:
            assert r["false_positive"] <= 5

    def test_output_to_file(self, tmp_path):
        out_file = str(tmp_path / "results.json")
        result = run_cli(SAMPLE_RULES, "--output", out_file)
        assert result.returncode == 0
        with open(out_file) as f:
            data = json.load(f)
        assert isinstance(data, list)

    def test_nonexistent_file(self):
        result = run_cli("nonexistent.rules")
        assert result.returncode != 0

    def test_no_args_shows_help(self):
        result = run_cli()
        assert result.returncode != 0
