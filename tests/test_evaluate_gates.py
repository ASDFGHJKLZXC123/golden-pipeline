import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_gates.py"
FIXTURES = ROOT / "tests" / "fixtures"


class EvaluatorCommandTests(unittest.TestCase):
    def run_evaluator(self, fixture, expected, enforce=False, github_output=True):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "github-output.txt"
            summary_path = Path(temp_dir) / "summary.md"
            command = [
                sys.executable,
                str(SCRIPT),
                "--reports-dir",
                str(FIXTURES / fixture),
                "--expected",
                expected,
                "--summary-out",
                str(summary_path),
            ]
            if enforce:
                command.append("--enforce")
            if github_output:
                command.append("--github-output")

            environment = os.environ.copy()
            environment["GITHUB_OUTPUT"] = str(output_path)
            result = subprocess.run(command, capture_output=True, text=True, env=environment, check=False)
            github_text = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
            summary_text = summary_path.read_text(encoding="utf-8") if summary_path.exists() else ""
            return result, github_text, summary_text

    def assert_gate_trip(self, fixture, expected):
        report_only, report_output, _ = self.run_evaluator(fixture, expected, enforce=False)
        enforcing, enforce_output, _ = self.run_evaluator(fixture, expected, enforce=True)
        self.assertEqual(report_only.returncode, 0, report_only.stderr)
        self.assertEqual(enforcing.returncode, 1, enforcing.stderr)
        self.assertIn("would_fail=true", report_output)
        self.assertIn("would_fail=true", enforce_output)

    def assert_fail_closed(self, fixture):
        for enforce in (False, True):
            with self.subTest(fixture=fixture, enforce=enforce):
                result, github_output, summary = self.run_evaluator(
                    fixture, "semgrep", enforce=enforce
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(github_output, "")
                self.assertEqual(summary, "")
                self.assertIn("Golden Pipeline infrastructure error", result.stderr)

    def test_semgrep_error_trips_gate_alone(self):
        self.assert_gate_trip("semgrep-error", "semgrep")

    def test_semgrep_rule_table_warning_surfaces_without_failing(self):
        for enforce in (False, True):
            with self.subTest(enforce=enforce):
                result, github_output, summary = self.run_evaluator(
                    "warnings", "semgrep", enforce=enforce
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("would_fail=false", github_output)
                self.assertIn("| semgrep | ERROR findings | 0 |", summary)
                self.assertIn("| semgrep | warning findings | 1 |", summary)

    def test_semgrep_informational_levels_remain_non_failing(self):
        for enforce in (False, True):
            with self.subTest(enforce=enforce):
                result, github_output, summary = self.run_evaluator(
                    "semgrep-informational", "semgrep", enforce=enforce
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("would_fail=false", github_output)
                self.assertIn("| semgrep | ERROR findings | 0 |", summary)
                self.assertIn("| semgrep | warning findings | 0 |", summary)

    def test_semgrep_result_level_overrides_rule_default_deterministically(self):
        report_only, report_output, report_summary = self.run_evaluator(
            "semgrep-overrides", "semgrep", enforce=False
        )
        enforcing, enforce_output, enforce_summary = self.run_evaluator(
            "semgrep-overrides", "semgrep", enforce=True
        )

        self.assertEqual(report_only.returncode, 0, report_only.stderr)
        self.assertEqual(enforcing.returncode, 1, enforcing.stderr)
        self.assertIn("would_fail=true", report_output)
        self.assertIn("would_fail=true", enforce_output)
        for summary in (report_summary, enforce_summary):
            self.assertIn("| semgrep | ERROR findings | 1 |", summary)
            self.assertIn("| semgrep | warning findings | 1 |", summary)

    def test_semgrep_missing_or_malformed_severity_metadata_fails_closed(self):
        for fixture in ("semgrep-missing-severity", "semgrep-invalid-result-level"):
            self.assert_fail_closed(fixture)

    def test_semgrep_absent_rule_or_malformed_rule_table_fails_closed(self):
        for fixture in (
            "semgrep-absent-rule",
            "semgrep-invalid-rule",
            "semgrep-malformed-rule-table",
        ):
            self.assert_fail_closed(fixture)

    def test_gitleaks_finding_trips_gate_alone(self):
        self.assert_gate_trip("gitleaks-finding", "gitleaks")

    def test_trivy_filesystem_fixable_high_trips_gate_alone(self):
        self.assert_gate_trip("trivy-fixable", "trivy-fs")

    def test_trivy_image_fixable_critical_trips_gate_alone(self):
        self.assert_gate_trip("trivy-image-fixable", "trivy-image")

    def test_synthetic_zap_high_trips_gate_alone(self):
        self.assert_gate_trip("zap-high", "zap")

    def test_clean_set_passes_both_modes(self):
        expected = "semgrep,gitleaks,trivy-fs,trivy-image,zap"
        for enforce in (False, True):
            with self.subTest(enforce=enforce):
                result, github_output, _ = self.run_evaluator("clean", expected, enforce=enforce)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("would_fail=false", github_output)

    def test_expected_but_missing_report_exits_two_in_both_modes(self):
        for enforce in (False, True):
            with self.subTest(enforce=enforce):
                result, github_output, _ = self.run_evaluator(
                    "missing-report", "semgrep,gitleaks,trivy-fs", enforce=enforce
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(github_output, "")
                self.assertIn("trivy-fs report is missing or unreadable", result.stderr)

    def test_malformed_json_exits_two_in_both_modes(self):
        for enforce in (False, True):
            with self.subTest(enforce=enforce):
                result, _, _ = self.run_evaluator("malformed-json", "gitleaks", enforce=enforce)
                self.assertEqual(result.returncode, 2)
                self.assertIn("gitleaks report is malformed JSON", result.stderr)

    def test_truncated_sarif_exits_two_in_both_modes(self):
        for enforce in (False, True):
            with self.subTest(enforce=enforce):
                result, _, _ = self.run_evaluator("truncated-sarif", "semgrep", enforce=enforce)
                self.assertEqual(result.returncode, 2)
                self.assertIn("semgrep report is malformed JSON", result.stderr)

    def test_unexpected_extra_report_is_ignored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            copied = Path(temp_dir) / "reports"
            shutil.copytree(FIXTURES / "clean", copied)
            (copied / "unexpected.json").write_text("not-json", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--reports-dir",
                    str(copied),
                    "--expected",
                    "semgrep,gitleaks,trivy-fs",
                    "--enforce",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("would_fail=false", result.stdout)

    def test_warn_tier_is_surfaced_without_failing(self):
        result, github_output, summary = self.run_evaluator(
            "warnings", "semgrep,gitleaks,trivy-fs,zap", enforce=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("would_fail=false", github_output)
        for row in (
            "| semgrep | warning findings | 1 |",
            "| trivy | misconfigurations | 1 |",
            "| trivy | MEDIUM vulnerabilities | 1 |",
            "| trivy | unfixed HIGH/CRITICAL vulnerabilities | 1 |",
            "| zap | Medium alerts | 1 |",
            "| zap | Low alerts | 1 |",
        ):
            self.assertIn(row, summary)

    def test_wrong_top_level_shapes_fail_closed(self):
        invalid_documents = {
            "semgrep.sarif": ("semgrep", "[]"),
            "gitleaks.json": ("gitleaks", "{}"),
            "trivy-fs.json": ("trivy-fs", "[]"),
            "report_json.json": ("zap", "[]"),
        }
        for filename, (scanner, content) in invalid_documents.items():
            with self.subTest(scanner=scanner), tempfile.TemporaryDirectory() as temp_dir:
                report_dir = Path(temp_dir)
                (report_dir / filename).write_text(content, encoding="utf-8")
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        "--reports-dir",
                        str(report_dir),
                        "--expected",
                        scanner,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
