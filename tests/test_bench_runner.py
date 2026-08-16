"""Unit tests for the coverage benchmark harness (tests/bench/runner.py).

Run with the rest of the suite: python -m unittest discover -s tests

The bench *cases* need Docker and are not run here. The harness itself does not:
a case with no `compose` key points at a target that is already up, so the whole
run-and-judge path is exercised end to end against a local socket. What Docker
would add is `docker compose up` — the one step these tests skip.

The properties locked in are the ones that decide whether the benchmark measures
anything at all: a case without a negative control is rejected, a control that
expects `confirmed` is rejected, and a run that never tested anything is never
reported as a clean negative.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
# Repo root for `rcekit`, this directory for `test_generator`'s local_target
# helper, and bench/ for the harness itself. Spelled out so the module imports
# the same way under `unittest discover -s tests` and `-m unittest tests....`.
sys.path.insert(0, str(TESTS_DIR.parent))
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TESTS_DIR / "bench"))

import runner  # noqa: E402
from test_generator import local_target  # noqa: E402

BENCH_ROOT = Path(__file__).resolve().parent / "bench"


def minimal_case(**overrides):
    case = {
        "name": "example",
        "rce_class": "OS command injection",
        "target": "Example 1.0",
        "invocation": ["--verify-url", "http://127.0.0.1:1/?x=FUZZ", "--methods", "reflected"],
        "expect": "confirmed",
        "negative_control": {"invocation": ["--verify-url", "http://127.0.0.1:1/?y=FUZZ",
                                            "--methods", "reflected"],
                             "expect": "negative"},
    }
    case.update(overrides)
    return case


class CaseValidationTestCase(unittest.TestCase):
    """A malformed case must fail loudly. A benchmark that quietly skips cases
    reports fewer failures than reality — the one thing it must never do."""

    def test_a_well_formed_case_validates(self):
        self.assertEqual(runner.validate_case(minimal_case())["name"], "example")

    def test_every_required_key_is_enforced(self):
        for key in runner.REQUIRED_KEYS:
            case = minimal_case()
            del case[key]
            with self.assertRaises(runner.CaseError, msg=f"missing {key} must be rejected") as ctx:
                runner.validate_case(case)
            self.assertIn(key, str(ctx.exception))

    def test_a_case_without_a_negative_control_is_rejected(self):
        case = minimal_case()
        del case["negative_control"]
        with self.assertRaises(runner.CaseError):
            runner.validate_case(case)

    def test_a_control_that_reuses_the_vulnerable_invocation_is_rejected(self):
        # A "control" that runs the identical command against the identical
        # target measures nothing; it just doubles the runtime.
        case = minimal_case(negative_control={"expect": "negative"})
        with self.assertRaises(runner.CaseError) as ctx:
            runner.validate_case(case)
        self.assertIn("measures nothing", str(ctx.exception))

    def test_an_explicitly_copied_control_invocation_is_rejected_too(self):
        # Key presence is not the test — what the control would actually run is.
        # Spelling the vulnerable invocation out again is the same non-control as
        # omitting it, and this case expects `needs-review`, where a duplicated
        # control would otherwise pass and prove nothing.
        case = minimal_case(
            expect="needs-review",
            negative_control={"invocation": list(minimal_case()["invocation"]),
                              "expect": "needs-review"})
        with self.assertRaises(runner.CaseError) as ctx:
            runner.validate_case(case)
        self.assertIn("measures nothing", str(ctx.exception))

    def test_the_same_invocation_against_a_different_build_is_a_valid_control(self):
        # The patched-build control: identical command, different target. That is
        # the strongest control there is, so the duplication check must not
        # mistake it for a duplicate.
        case = minimal_case(vulhub_path="webmin/CVE-2019-15107",
                            negative_control={"vulhub_path": "webmin/patched",
                                              "expect": "negative"})
        self.assertEqual(runner.validate_case(case)["name"], "example")

    def test_a_control_may_not_expect_an_outcome_that_never_reached_the_target(self):
        # `error` and `nothing-tested` mean nothing was exercised, so such a
        # control would stay green with the detection engine entirely broken.
        for expectation in ("error", "nothing-tested"):
            case = minimal_case(negative_control={"invocation": ["--bogus"],
                                                  "expect": expectation})
            with self.assertRaises(runner.CaseError, msg=expectation) as ctx:
                runner.validate_case(case)
            self.assertIn("never exercised", str(ctx.exception))

    def test_a_control_may_expect_any_exercised_outcome(self):
        for expectation in runner.CONTROL_EXPECTATIONS:
            case = minimal_case(negative_control={"invocation": ["--other"],
                                                  "expect": expectation})
            self.assertEqual(runner.validate_case(case)["name"], "example", expectation)

    def test_the_vulnerable_half_may_still_expect_error(self):
        # Narrowing control expectations must not narrow the case's own: "an
        # unreachable target reports error, not negative" is worth pinning.
        self.assertEqual(runner.validate_case(minimal_case(expect="error"))["name"], "example")

    def test_validation_and_execution_read_the_same_control_plan(self):
        # The duplication the validator rejects must be the duplication the
        # runner would have run, so both go through control_plan.
        case = minimal_case(compose=["docker", "compose", "up", "-d"],
                            negative_control={"invocation": ["--other"], "expect": "negative"})
        invocation, setup = runner.control_plan(case)
        self.assertEqual(invocation, ["--other"])
        self.assertEqual(runner.target_setup(setup), runner.target_setup(case))

    def test_a_control_expecting_confirmed_is_rejected(self):
        case = minimal_case(negative_control={"invocation": ["--x"], "expect": "confirmed"})
        with self.assertRaises(runner.CaseError) as ctx:
            runner.validate_case(case)
        self.assertIn("contradiction", str(ctx.exception))

    def test_an_unknown_expectation_is_rejected(self):
        with self.assertRaises(runner.CaseError):
            runner.validate_case(minimal_case(expect="vulnerable"))

    def test_shipped_cases_all_validate(self):
        paths = runner.discover_cases(BENCH_ROOT / "cases")
        self.assertTrue(paths, "no bench cases found")
        for path in paths:
            runner.load_case(path)

    def test_shipped_cases_reference_files_that_exist(self):
        # A case pointing at a missing captured request fails only once someone
        # has waited for a container to boot. Catch it here instead.
        for path in runner.discover_cases(BENCH_ROOT / "cases"):
            case = runner.load_case(path)
            invocations = [case["invocation"], case["negative_control"].get("invocation", [])]
            for invocation in invocations:
                for arg in runner.expand_paths(invocation):
                    if arg.startswith(str(BENCH_ROOT)):
                        self.assertTrue(Path(arg).exists(), f"{path.name} references {arg}")


class ReportCheckingTestCase(unittest.TestCase):
    """Turning one RCEKit run into pass/fail."""

    def test_matching_verdict_passes(self):
        ok, detail = runner.check_report({"verdict": "confirmed", "counts": {"confirmed": 2}},
                                         "confirmed")
        self.assertTrue(ok)
        self.assertIn("confirmed", detail)

    def test_mismatched_verdict_fails_with_the_counts(self):
        ok, detail = runner.check_report(
            {"verdict": "negative", "counts": {"negative": 9}}, "confirmed")
        self.assertFalse(ok)
        self.assertIn("expected confirmed, got negative", detail)
        self.assertIn("negative=9", detail)

    def test_nothing_tested_is_not_a_negative(self):
        # The distinction the whole harness rests on: a run that built no probes
        # tested nothing, and must not satisfy a case expecting `negative`.
        ok, _ = runner.check_report({"verdict": "nothing-tested", "counts": {}}, "negative")
        self.assertFalse(ok)

    def test_expect_method_pins_the_method_that_confirmed(self):
        report = {"verdict": "confirmed", "counts": {"confirmed": 1},
                  "probes": [{"verdict": "confirmed", "method": "eval",
                              "environment": "unix", "context": "raw"}]}
        self.assertTrue(runner.check_report(report, "confirmed", "eval")[0])
        self.assertTrue(runner.check_report(report, "confirmed", "eval/unix/raw")[0])
        ok, detail = runner.check_report(report, "confirmed", "reflected")
        self.assertFalse(ok, "a confirmation from the wrong method must not satisfy the case")
        self.assertIn("not 'reflected'", detail)


class MarkdownTableTestCase(unittest.TestCase):
    def test_table_shows_verdict_control_and_result(self):
        table = runner.render_markdown([
            {"name": "a", "rce_class": "OS command injection", "target": "Webmin 1.910",
             "verdict": "confirmed", "control_verdict": "needs-review",
             "methods": ["reflected", "reflected/unix/raw"], "passed": True},
            {"name": "b", "rce_class": "Expression injection", "target": "Struts2",
             "verdict": "negative", "control_verdict": "negative",
             "methods": [], "passed": False},
        ])
        self.assertIn("| Webmin 1.910 | `reflected` | **`confirmed`** | `needs-review` | pass |",
                      table)
        self.assertIn("**FAIL**", table)
        # The composite signature is detail for a failure message, not for the
        # README table.
        self.assertNotIn("reflected/unix/raw", table)


class HarnessEndToEndTestCase(unittest.TestCase):
    """The run-and-judge path against a real socket, with no Docker involved.

    A case with no `compose` key targets something already running, which is
    what makes this possible — and is also a real mode for anyone benchmarking
    a target they started by hand."""

    def _case(self, base, **overrides):
        return minimal_case(
            invocation=["--verify-url", f"{base}/?host=FUZZ", "--methods", "reflected"],
            negative_control={"invocation": ["--verify-url", f"{base}/safe?host=FUZZ",
                                             "--methods", "reflected"],
                              "expect": "negative"},
            **overrides)

    def test_a_vulnerable_target_with_a_clean_control_passes(self):
        import os

        def route(method, path, params, headers, body):
            if path.startswith("/safe"):
                return 200, "<html>nothing executes here</html>"
            pipe = os.popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            outcome = runner.run_case(self._case(base))
        self.assertTrue(outcome["vulnerable_ok"], outcome["vulnerable_detail"])
        self.assertTrue(outcome["control_ok"], outcome["control_detail"])
        self.assertTrue(outcome["passed"])
        self.assertEqual(outcome["verdict"], "confirmed")
        self.assertIn("reflected", outcome["methods"])

    def test_a_control_that_starts_confirming_fails_the_case(self):
        # The failure mode negative controls exist to catch: if the "clean"
        # endpoint also confirms, the case must fail even though the vulnerable
        # half is perfect.
        import os

        def route(method, path, params, headers, body):
            pipe = os.popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            outcome = runner.run_case(self._case(base))
        self.assertTrue(outcome["vulnerable_ok"], outcome["vulnerable_detail"])
        self.assertFalse(outcome["control_ok"])
        self.assertFalse(outcome["passed"], "a confirming control must fail the case")

    def test_a_patched_target_fails_the_vulnerable_half(self):
        with local_target(lambda *a: (200, "<html>patched</html>")) as base:
            outcome = runner.run_case(self._case(base))
        self.assertFalse(outcome["vulnerable_ok"])
        self.assertTrue(outcome["control_ok"])
        self.assertFalse(outcome["passed"])

    def test_an_unreachable_target_is_an_error_not_a_negative(self):
        # Reporting a dead target as `negative` would read as "not vulnerable",
        # which is the misreport this whole project exists to avoid.
        case = minimal_case(
            invocation=["--verify-url", "http://127.0.0.1:9/?x=FUZZ", "--methods", "reflected"],
            expect="error")
        outcome = runner.run_case(case)
        self.assertEqual(outcome["verdict"], "error")
        self.assertTrue(outcome["vulnerable_ok"], outcome["vulnerable_detail"])


class RunnerCLITestCase(unittest.TestCase):
    def test_list_prints_the_shipped_cases(self):
        import contextlib
        import io
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = runner.main(["--list", "--cases-dir", str(BENCH_ROOT / "cases")])
        self.assertEqual(code, 0)
        self.assertIn("webmin-cve-2019-15107", buffer.getvalue())

    def test_an_unknown_case_name_is_an_error(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            code = runner.main(["--case", "no-such-case", "--cases-dir",
                                str(BENCH_ROOT / "cases")])
        self.assertEqual(code, 2)

    def test_no_selection_is_refused(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runner.main(["--cases-dir", str(BENCH_ROOT / "cases")])


class DetectJsonTestCase(unittest.TestCase):
    """--detect-json is the channel the harness reads. Its contract is tested
    here rather than in the harness, because the harness only trusts it."""

    def test_overall_verdict_prefers_the_finding_over_the_majority(self):
        import rcekit
        many_negatives = [{"verdict": "negative"}] * 99
        self.assertEqual(
            rcekit.overall_detection_verdict(many_negatives + [{"verdict": "confirmed"}]),
            "confirmed")
        self.assertEqual(
            rcekit.overall_detection_verdict(many_negatives + [{"verdict": "needs-review"}]),
            "needs-review")

    def test_no_probes_is_nothing_tested_not_negative(self):
        import rcekit
        self.assertEqual(rcekit.overall_detection_verdict([]), "nothing-tested")

    def test_error_only_when_nothing_reached_the_target(self):
        import rcekit
        self.assertEqual(rcekit.overall_detection_verdict([{"verdict": "error"}] * 3), "error")
        # Some probes errored but others landed and came back clean: that is a
        # real negative, not an untested run.
        self.assertEqual(
            rcekit.overall_detection_verdict([{"verdict": "error"}, {"verdict": "negative"}]),
            "negative")

    def test_written_file_carries_the_verdict_counts_and_probes(self):
        import rcekit
        probes = [{"verdict": "confirmed", "method": "reflected", "environment": "unix",
                   "context": "raw", "payload": "; id", "detail": "computed"},
                  {"verdict": "negative", "method": "reflected", "environment": "unix",
                   "context": "raw", "payload": "| id", "detail": ""}]
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "out.json")
            rcekit.write_detection_json(path, probes, "http://t/FUZZ", ["reflected"])
            with open(path, encoding="utf-8") as handle:
                written = json.load(handle)
        self.assertEqual(written["verdict"], "confirmed")
        self.assertEqual(written["counts"], {"confirmed": 1, "negative": 1})
        self.assertEqual(written["target"], "http://t/FUZZ")
        self.assertEqual(written["methods"], ["reflected"])
        self.assertEqual(len(written["probes"]), 2)
        self.assertEqual(written["rcekit_version"], rcekit.__version__)

    def test_a_payload_containing_a_newline_survives_the_round_trip(self):
        # The reason this channel exists: line-oriented parsing of the text
        # report splits such a payload in half.
        import rcekit
        payload = "\necho RKABCDE$((1+2))RKFGHIJ"
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "out.json")
            rcekit.write_detection_json(
                path, [{"verdict": "confirmed", "method": "reflected", "environment": "unix",
                        "context": "raw", "payload": payload, "detail": ""}],
                "http://t", ["reflected"])
            with open(path, encoding="utf-8") as handle:
                written = json.load(handle)
        self.assertEqual(written["probes"][0]["payload"], payload)


if __name__ == "__main__":
    unittest.main()
