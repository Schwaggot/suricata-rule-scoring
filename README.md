# suricata-rule-scoring

A library and CLI tool that evaluates Suricata IDS rules against configurable scoring criteria, producing two numerical
scores per rule: a **quality score** (how well-written and effective the rule is) and a **false-positive score** (how
likely the rule is to generate false positives).

## Installation

Requires Python 3.10+.

```bash
# Install the parser submodule first
pip install -e suricata-rule-parser/

# Install the scorer
pip install -e .
```

## Quick Start

### CLI

```bash
# Score a rules file (JSON output)
suricata-rule-scorer score rules/et-open/emerging-malware.rules

# CSV output with summary statistics
suricata-rule-scorer score rules/et-open/emerging-malware.rules --format csv --stats

# Filter and sort
suricata-rule-scorer score rules/et-open/emerging-malware.rules --min-quality 20 --max-fp 10 --sort-by quality

# Verbose output (includes matched criteria)
suricata-rule-scorer score rules/et-open/emerging-malware.rules --verbose

# Use a custom scoring profile
suricata-rule-scorer score rules/et-open/emerging-malware.rules --config my_profile.yaml

# Write results to file
suricata-rule-scorer score rules/et-open/emerging-malware.rules --output results.json
```

### Library API

```python
from suricata_rule_scoring import RuleScorer, summarize
from suricata_rule_parser import parse_file, parse_rule

# Score a file of rules
scorer = RuleScorer()
rules = parse_file("rules/et-open/emerging-malware.rules")
results = scorer.score_many(rules)

# Inspect individual results
for r in results[:3]:
    print(f"SID {r.sid}: quality={r.quality}, fp={r.false_positive}")

# Summary statistics
stats = summarize(results)
print(f"Rules: {stats.total_rules}")
print(f"Quality — mean: {stats.mean_quality}, median: {stats.median_quality}")
print(f"FP      — mean: {stats.mean_false_positive}, median: {stats.median_false_positive}")

# Score a single rule
rule = parse_rule(
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Example"; content:"GET"; flow:established; sid:1; rev:1;)')
result = scorer.score(rule)
print(result.quality, result.false_positive)

# Custom scoring profile
scorer = RuleScorer.from_config("my_profile.yaml")

# Register a plugin programmatically
from suricata_rule_scoring.models import ScoringResult


def my_check(rule):
    if len(rule.options.content) == 0:
        return ScoringResult(dimension="quality", delta=-20, reason="No content")
    return None


scorer.register_plugin("my_check", my_check)
```

## Scoring Model

Each rule receives two independent scores:

| Score              | Meaning                                            | Direction              |
|--------------------|----------------------------------------------------|------------------------|
| **quality**        | How well-constructed and effective the rule is     | Higher = better        |
| **false_positive** | How likely the rule is to generate false positives | Higher = more FP-prone |

Both scores start at a configurable base value (default: 0) and are modified by criteria that add or subtract weighted
points.

### Default Quality Criteria

| ID                           | Weight   | Condition                                     | Reasoning                                                           |
|------------------------------|----------|-----------------------------------------------|---------------------------------------------------------------------|
| `has_content_match`          | +10      | Has at least one `content` keyword            | Content matches are the foundation of effective signature detection |
| `has_fast_pattern`           | +5       | Uses `fast_pattern`                           | Enables the multi-pattern matcher for efficient pre-filtering       |
| `specific_protocol`          | +5       | Protocol is not ip/tcp/udp/tcp-pkt/tcp-stream | App-layer protocols narrow evaluation to specific traffic types     |
| `has_flow_direction`         | +5       | Specifies `flow` keyword                      | Flow tracking ensures the rule fires at the right stage             |
| `content_position_modifiers` | +5       | Uses depth/offset/distance/within             | Position-constrained content shows protocol structure awareness     |
| `has_flowbits`               | +5       | Uses `flowbits` keyword                       | Flowbits implement multi-stage/correlated detection chains          |
| `has_dsize`                  | +3       | Uses `dsize` keyword                          | Payload size constraints improve performance and precision          |
| `content_anchoring`          | +3       | Uses `startswith` or `endswith`               | Anchors content to buffer boundaries for precise matching           |
| `has_isdataat`               | +2       | Uses `isdataat` keyword                       | Verifies data exists at offset before matching proceeds             |
| `tls_fingerprint`            | +15      | Matches TLS cert/JA3/JA4 fingerprint fields   | Cryptographic fingerprints are highly specific indicators           |
| `has_byte_operations`        | +8       | Uses byte_test/byte_jump/byte_extract         | Byte-level operations represent surgical binary protocol parsing    |
| `deep_content`               | +8       | 3+ content matches                            | Multiple content matches greatly increase detection specificity     |
| `pcre_without_content`       | -10      | PCRE with no content anchor                   | Unanchored PCRE forces full payload regex scans, hurting perf       |
| `no_content_match`           | -10      | No content, pcre, or app-layer match          | No payload inspection means the rule relies solely on headers       |
| `ip_ioc_rule`                | +10/+15  | Targets a specific IP; +15 with port (plugin) | Literal IP/port IoCs are valid detection even without content       |
| `tiny_payload`               | -10      | Matches fewer than 3 bytes total (plugin)     | Very short patterns match too broadly and lack uniqueness           |
| `rule_age`                   | -5 to +5 | Age from metadata date fields (plugin)        | Stale rules may target obsolete threats; fresh rules are relevant   |
| `bidirectional_rule`         | -5       | Direction is `<>` instead of `->`             | Bidirectional rules double evaluation cost and indicate imprecision |
| `any_any_source`             | -3       | Source address and port are both `any`        | Unrestricted source widens the rule's attack surface                |
| `any_any_dest`               | -3       | Destination address and port are both `any`   | Unrestricted destination means every packet is a candidate          |

### Default False-Positive Criteria

| ID                           | Weight | Condition                                                         | Reasoning                                                            |
|------------------------------|--------|-------------------------------------------------------------------|----------------------------------------------------------------------|
| `broad_network_scope`        | +8     | Both src and dst addresses are `any`                              | Monitoring all traffic in both directions maximises false matches    |
| `single_content_http_method` | +8     | Only content is a common HTTP method (plugin)                     | GET/POST alone matches virtually all HTTP traffic                    |
| `few_content_matches`        | +8     | Single content match under 5 bytes (plugin)                       | A short, single pattern is likely to collide with benign traffic     |
| `pcre_only`                  | +7     | PCRE-only detection, no content anchor                            | Regex-only rules are slow and prone to partial/accidental matches    |
| `any_ports`                  | +3     | Both src and dst ports are `any`                                  | No port restriction means every connection is evaluated              |
| `generic_protocol`           | +5     | ip/tcp/udp/tcp-pkt/tcp-stream with no app-layer keywords (plugin) | Without app-layer narrowing the rule matches raw transport traffic   |
| `no_flow_state`              | +3     | No `flow` keyword                                                 | Without flow state the rule fires on every packet, not just sessions |
| `bidirectional_fp`           | +5     | Direction is `<>` instead of `->`                                 | Evaluating both directions doubles the volume of inspected packets   |
| `long_content_match`         | -10    | Total content >= 10 bytes (plugin)                                | Long unique content has near-zero chance of matching benign traffic  |
| `specific_tls_match`         | -10    | Matches specific TLS/cert/JA3/JA4 attributes                      | Cryptographic fingerprints rarely appear in legitimate traffic       |
| `flowbits_isset`             | -8     | Uses `flowbits:isset` (plugin)                                    | Requires a prior rule to match first — two-stage AND logic           |
| `specific_dns_query`         | -8     | Matches specific DNS query                                        | Exact domain matches are unlikely to collide with normal lookups     |
| `positioned_content`         | -5     | Uses depth/offset/distance/within                                 | Position-constrained content dramatically reduces coincidental hits  |
| `byte_operations_precision`  | -5     | Uses byte_test/byte_jump/byte_extract                             | Byte-level validation virtually never matches benign traffic         |
| `multi_content`              | -5     | 3+ content matches                                                | Multiple patterns must all match, greatly reducing coincidences      |
| `has_threshold`              | -5     | Uses `threshold` or `detection_filter`                            | Rate-limiting suppresses repeated alerts from noisy matches          |
| `ip_ioc_fp`                  | -5     | Targets a specific literal IP (plugin)                            | Literal IP match has near-zero false-positive risk                   |
| `port_specificity`           | -1/-3  | Port range: -1, specific port: -3, per side (plugin)              | Narrower port targeting limits evaluation to relevant services       |
| `dsize_constraint`           | -3     | Uses `dsize` keyword                                              | Size constraints eliminate matches on wrong-sized packets            |
| `has_bsize`                  | -3     | Uses `bsize` keyword                                              | Buffer size constraints reduce coincidental matches on normal data   |
| `scoped_source_address`      | -1     | Source address is not `any`                                       | Network variable or literal narrows the evaluated traffic            |
| `scoped_dest_address`        | -1     | Destination address is not `any`                                  | Network variable or literal narrows the evaluated traffic            |

## Custom Scoring Profiles

Override the defaults with a YAML file:

```yaml
scoring:
  quality:
    base: 0
    min: null   # null = unclamped
    max: null
  false_positive:
    base: 0
    min: 0
    max: 50

criteria:
  - id: has_content
    name: "Has content"
    description: "Rule contains at least one content keyword"
    dimension: quality
    weight: 20
    condition:
      field: "options.content"
      operator: "exists"

  - id: broad_scope
    name: "Broad scope"
    description: "Source and dest are both any"
    dimension: false_positive
    weight: 15
    condition:
      operator: "all"
      conditions:
        - field: "source_address"
          operator: "eq"
          value: "any"
        - field: "destination_address"
          operator: "eq"
          value: "any"

plugins:
  - id: my_plugin
    name: "My custom check"
    callable: "my_module.my_function"
```

### Condition Operators

| Operator                 | Description                           | Example                    |
|--------------------------|---------------------------------------|----------------------------|
| `exists`                 | Field is truthy (not null/empty/zero) | `field: "options.content"` |
| `not_exists`             | Field is falsy                        | `field: "options.pcre"`    |
| `eq` / `neq`             | Equality / inequality                 | `value: "tcp"`             |
| `in` / `not_in`          | Set membership                        | `value: ["tcp", "udp"]`    |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison                    | `value: 3`                 |
| `contains`               | Value in list/string                  | `value: "established"`     |
| `not`                    | Negate a sub-condition                | `condition: { ... }`       |
| `all` / `any`            | All/any sub-conditions match          | `conditions: [...]`        |

### Field Paths

| Pattern                                         | Resolves to                                 |
|-------------------------------------------------|---------------------------------------------|
| `protocol`, `action`, `direction`               | `rule.header.*`                             |
| `source_address`, `destination_address`         | `rule.header.source_ip` / `dest_ip`         |
| `source_port`, `destination_port`               | `rule.header.source_port` / `dest_port`     |
| `options.content`, `options.flow`, etc.         | Direct `RuleOptions` attributes             |
| `options.pcre`, `options.fast_pattern`          | `RuleOptions.other_options` dict            |
| `options.tls.cert_subject`, `options.dns.query` | Dotted Suricata keywords in `other_options` |
| `options.tls_cert_fingerprint`                  | Flag-style keywords (presence = truthy)     |
| `options.content\|count`                        | `len()` of the content list                 |

## Plugin System

Plugins handle scoring logic too complex for declarative YAML conditions (e.g., computing content byte lengths,
cross-referencing multiple fields).

```python
from suricata_rule_scoring.models import ScoringResult


def my_plugin(rule):
    """Return ScoringResult or None if criterion doesn't apply."""
    total_bytes = sum(len(c) for c in rule.options.content)
    if total_bytes < 5:
        return ScoringResult(
            dimension="quality",
            delta=-12,
            reason=f"Rule matches only {total_bytes} bytes",
        )
    return None
```

Register via YAML (`callable: "my_module:my_plugin"`) or programmatically (`scorer.register_plugin("id", my_plugin)`).

Ten built-in plugins ship with the default profile: `long_content_match`, `tiny_payload`, `few_content_matches`,
`ip_ioc_rule`, `rule_age`, `generic_protocol`, `flowbits_isset`, `ip_ioc_fp`, `single_content_http_method`,
and `port_specificity`.

## CLI Reference

```
suricata-rule-scorer score <rules_file> [options]
```

| Option                              | Description                        | Default           |
|-------------------------------------|------------------------------------|-------------------|
| `--config PATH`                     | Custom YAML scoring profile        | built-in defaults |
| `--format json\|csv`                | Output format                      | `json`            |
| `--output PATH`                     | Write to file instead of stdout    | stdout            |
| `--stats`                           | Print summary statistics to stderr | off               |
| `--sort-by quality\|false_positive` | Sort output                        | unsorted          |
| `--min-quality FLOAT`               | Filter: quality >= n               | none              |
| `--max-fp FLOAT`                    | Filter: false_positive <= n        | none              |
| `--verbose`                         | Include matched criteria in output | off               |

## Testing

```bash
pip install pytest
pytest tests/ -v
```

## License

MIT
