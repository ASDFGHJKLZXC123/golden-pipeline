#!/usr/bin/env python3
"""Evaluate normalized security scanner reports for Golden Pipeline policy."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple


REPORT_FILES = {
    "semgrep": "semgrep.sarif",
    "gitleaks": "gitleaks.json",
    "trivy-fs": "trivy-fs.json",
    "trivy-image": "trivy-image.json",
    "zap": "report_json.json",
}
SARIF_LEVELS = {"none", "note", "warning", "error"}

FAIL_ROWS = (
    ("gitleaks", "non-allowlisted findings"),
    ("semgrep", "ERROR findings"),
    ("trivy", "fixable HIGH/CRITICAL vulnerabilities"),
    ("zap", "High alerts"),
)

WARN_ROWS = (
    ("semgrep", "warning findings"),
    ("trivy", "misconfigurations"),
    ("trivy", "MEDIUM vulnerabilities"),
    ("trivy", "unfixed HIGH/CRITICAL vulnerabilities"),
    ("zap", "Medium alerts"),
    ("zap", "Low alerts"),
)


class EvaluationError(Exception):
    """A report or evaluator I/O failure that must fail closed."""


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-dir", required=True, type=Path)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument("--github-output", action="store_true")
    return parser.parse_args(argv)


def expected_scanners(raw: str) -> List[str]:
    scanners = [item.strip() for item in raw.split(",") if item.strip()]
    if not scanners:
        raise EvaluationError("expected scanner manifest is empty")

    unknown = sorted(set(scanners) - set(REPORT_FILES))
    if unknown:
        raise EvaluationError("unknown expected scanner(s): {}".format(", ".join(unknown)))
    if len(scanners) != len(set(scanners)):
        raise EvaluationError("expected scanner manifest contains duplicates")
    return scanners


def load_json(path: Path, scanner: str) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EvaluationError("{} report is missing or unreadable: {}".format(scanner, path.name)) from exc

    if not raw.strip():
        raise EvaluationError("{} report is empty: {}".format(scanner, path.name))

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EvaluationError("{} report is malformed JSON: {}".format(scanner, path.name)) from exc


def require_mapping(value: Any, defect: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationError(defect)
    return value


def require_list(value: Any, defect: str) -> List[Any]:
    if not isinstance(value, list):
        raise EvaluationError(defect)
    return value


def require_sarif_level(value: Any, location: str) -> str:
    if not isinstance(value, str) or value not in SARIF_LEVELS:
        raise EvaluationError(
            "{} must be one of error, warning, note, or none".format(location)
        )
    return value


def count_semgrep(document: Any) -> Tuple[Dict[Tuple[str, str], int], Dict[Tuple[str, str], int]]:
    root = require_mapping(document, "semgrep report must be a JSON object")
    runs = require_list(root.get("runs"), "semgrep report must contain runs[]")
    failures = {("semgrep", "ERROR findings"): 0}
    warnings = {("semgrep", "warning findings"): 0}

    for run_number, run_value in enumerate(runs):
        run = require_mapping(run_value, "semgrep runs[{}] must be an object".format(run_number))
        tool = require_mapping(
            run.get("tool"), "semgrep runs[{}].tool must be an object".format(run_number)
        )
        driver = require_mapping(
            tool.get("driver"),
            "semgrep runs[{}].tool.driver must be an object".format(run_number),
        )
        rules = require_list(
            driver.get("rules"),
            "semgrep runs[{}].tool.driver must contain rules[]".format(run_number),
        )
        rule_levels: Dict[str, str] = {}
        for rule_number, rule_value in enumerate(rules):
            rule_location = "semgrep runs[{}].tool.driver.rules[{}]".format(
                run_number, rule_number
            )
            rule = require_mapping(
                rule_value, "{} must be an object".format(rule_location)
            )
            rule_id = rule.get("id")
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise EvaluationError("{}.id must be a non-empty string".format(rule_location))
            if rule_id in rule_levels:
                raise EvaluationError("{} duplicates an earlier rule id".format(rule_location))
            default_configuration = require_mapping(
                rule.get("defaultConfiguration"),
                "{}.defaultConfiguration must be an object".format(rule_location),
            )
            rule_levels[rule_id] = require_sarif_level(
                default_configuration.get("level"),
                "{}.defaultConfiguration.level".format(rule_location),
            )

        results = require_list(
            run.get("results"), "semgrep runs[{}] must contain results[]".format(run_number)
        )
        for result_number, result_value in enumerate(results):
            result = require_mapping(
                result_value,
                "semgrep runs[{}].results[{}] must be an object".format(run_number, result_number),
            )
            result_location = "semgrep runs[{}].results[{}]".format(run_number, result_number)
            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise EvaluationError(
                    "{}.ruleId must be a non-empty string".format(result_location)
                )
            if rule_id not in rule_levels:
                raise EvaluationError(
                    "{} references a ruleId absent from driver rules".format(result_location)
                )
            level = rule_levels[rule_id]
            if "level" in result:
                level = require_sarif_level(
                    result.get("level"), "{}.level".format(result_location)
                )
            if level == "error":
                failures[("semgrep", "ERROR findings")] += 1
            elif level == "warning":
                warnings[("semgrep", "warning findings")] += 1
    return failures, warnings


def count_gitleaks(document: Any) -> Tuple[Dict[Tuple[str, str], int], Dict[Tuple[str, str], int]]:
    findings = require_list(document, "gitleaks report must be a JSON array")
    for finding_number, finding in enumerate(findings):
        require_mapping(finding, "gitleaks finding {} must be an object".format(finding_number))
    return {("gitleaks", "non-allowlisted findings"): len(findings)}, {}


def optional_report_list(result: Mapping[str, Any], field: str, location: str) -> List[Any]:
    value = result.get(field)
    if value is None:
        return []
    return require_list(value, "{} must be an array when present".format(location))


def count_trivy(
    document: Any, scanner: str
) -> Tuple[Dict[Tuple[str, str], int], Dict[Tuple[str, str], int]]:
    root = require_mapping(document, "{} report must be a JSON object".format(scanner))
    results = require_list(root.get("Results"), "{} report must contain Results[]".format(scanner))
    failures = {("trivy", "fixable HIGH/CRITICAL vulnerabilities"): 0}
    warnings = {
        ("trivy", "misconfigurations"): 0,
        ("trivy", "MEDIUM vulnerabilities"): 0,
        ("trivy", "unfixed HIGH/CRITICAL vulnerabilities"): 0,
    }

    for result_number, result_value in enumerate(results):
        result = require_mapping(
            result_value, "{} Results[{}] must be an object".format(scanner, result_number)
        )
        vulnerabilities = optional_report_list(
            result, "Vulnerabilities", "{} Results[{}].Vulnerabilities".format(scanner, result_number)
        )
        misconfigurations = optional_report_list(
            result,
            "Misconfigurations",
            "{} Results[{}].Misconfigurations".format(scanner, result_number),
        )
        warnings[("trivy", "misconfigurations")] += len(misconfigurations)

        for misconfiguration_number, misconfiguration in enumerate(misconfigurations):
            require_mapping(
                misconfiguration,
                "{} Results[{}].Misconfigurations[{}] must be an object".format(
                    scanner, result_number, misconfiguration_number
                ),
            )

        for vulnerability_number, vulnerability_value in enumerate(vulnerabilities):
            vulnerability = require_mapping(
                vulnerability_value,
                "{} Results[{}].Vulnerabilities[{}] must be an object".format(
                    scanner, result_number, vulnerability_number
                ),
            )
            severity = str(vulnerability.get("Severity", "")).upper()
            fixed_version = vulnerability.get("FixedVersion")
            fix_available = bool(str(fixed_version).strip()) if fixed_version is not None else False
            if severity in {"HIGH", "CRITICAL"}:
                if fix_available:
                    failures[("trivy", "fixable HIGH/CRITICAL vulnerabilities")] += 1
                else:
                    warnings[("trivy", "unfixed HIGH/CRITICAL vulnerabilities")] += 1
            elif severity == "MEDIUM":
                warnings[("trivy", "MEDIUM vulnerabilities")] += 1
    return failures, warnings


def count_zap(document: Any) -> Tuple[Dict[Tuple[str, str], int], Dict[Tuple[str, str], int]]:
    root = require_mapping(document, "zap report must be a JSON object")
    sites = require_list(root.get("site"), "zap report must contain site[]")
    failures = {("zap", "High alerts"): 0}
    warnings = {("zap", "Medium alerts"): 0, ("zap", "Low alerts"): 0}

    for site_number, site_value in enumerate(sites):
        site = require_mapping(site_value, "zap site[{}] must be an object".format(site_number))
        alerts = require_list(site.get("alerts"), "zap site[{}] must contain alerts[]".format(site_number))
        for alert_number, alert_value in enumerate(alerts):
            alert = require_mapping(
                alert_value, "zap site[{}].alerts[{}] must be an object".format(site_number, alert_number)
            )
            riskcode = str(alert.get("riskcode", ""))
            if riskcode == "3":
                failures[("zap", "High alerts")] += 1
            elif riskcode == "2":
                warnings[("zap", "Medium alerts")] += 1
            elif riskcode == "1":
                warnings[("zap", "Low alerts")] += 1
    return failures, warnings


def merge_counts(target: MutableMapping[Tuple[str, str], int], source: Mapping[Tuple[str, str], int]) -> None:
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


def evaluate(reports_dir: Path, scanners: Iterable[str]) -> Tuple[Dict[Tuple[str, str], int], Dict[Tuple[str, str], int]]:
    failures: Dict[Tuple[str, str], int] = {}
    warnings: Dict[Tuple[str, str], int] = {}
    for scanner in scanners:
        document = load_json(reports_dir / REPORT_FILES[scanner], scanner)
        if scanner == "semgrep":
            scanner_failures, scanner_warnings = count_semgrep(document)
        elif scanner == "gitleaks":
            scanner_failures, scanner_warnings = count_gitleaks(document)
        elif scanner in {"trivy-fs", "trivy-image"}:
            scanner_failures, scanner_warnings = count_trivy(document, scanner)
        elif scanner == "zap":
            scanner_failures, scanner_warnings = count_zap(document)
        else:  # Guarded by expected_scanners; retained as a fail-closed invariant.
            raise EvaluationError("no evaluator is registered for {}".format(scanner))
        merge_counts(failures, scanner_failures)
        merge_counts(warnings, scanner_warnings)
    return failures, warnings


def markdown_summary(
    scanners: Iterable[str],
    failures: Mapping[Tuple[str, str], int],
    warnings: Mapping[Tuple[str, str], int],
) -> str:
    expected = set(scanners)
    lines = ["# Golden Pipeline policy summary", "", "## Fail tier", "", "| Scanner | Finding class | Count |", "|---|---|---:|"]
    for scanner, label in FAIL_ROWS:
        applies = scanner in expected or (scanner == "trivy" and bool({"trivy-fs", "trivy-image"} & expected))
        if applies:
            lines.append("| {} | {} | {} |".format(scanner, label, failures.get((scanner, label), 0)))

    lines.extend(["", "## Warn tier", "", "| Scanner | Finding class | Count |", "|---|---|---:|"])
    for scanner, label in WARN_ROWS:
        applies = scanner in expected or (scanner == "trivy" and bool({"trivy-fs", "trivy-image"} & expected))
        if applies:
            lines.append("| {} | {} | {} |".format(scanner, label, warnings.get((scanner, label), 0)))
    return "\n".join(lines) + "\n"


def write_text(path: Path, content: str, purpose: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise EvaluationError("could not write {}".format(purpose)) from exc


def write_github_output(would_fail: bool) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise EvaluationError("--github-output requires GITHUB_OUTPUT")
    try:
        with Path(output_path).open("a", encoding="utf-8") as output:
            output.write("would_fail={}\n".format(str(would_fail).lower()))
    except OSError as exc:
        raise EvaluationError("could not write GITHUB_OUTPUT") from exc


def main(argv: Sequence[str] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        scanners = expected_scanners(args.expected)
        failures, warnings = evaluate(args.reports_dir, scanners)
        would_fail = any(failures.values())
        summary = markdown_summary(scanners, failures, warnings)
        if args.summary_out:
            write_text(args.summary_out, summary, "markdown summary")
        if args.github_output:
            write_github_output(would_fail)

        # The summary contains only scanner names, finding classes, and aggregate counts.
        print(summary, end="")
        print("would_fail={}".format(str(would_fail).lower()))
        return 1 if args.enforce and would_fail else 0
    except EvaluationError as exc:
        print("Golden Pipeline infrastructure error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
