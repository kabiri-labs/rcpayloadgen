#!/usr/bin/env python3
"""RCEKit coverage benchmark — run the tool against real vulnerable targets.

The unit tests prove RCEKit builds the right payloads and reaches the right
verdict from a given response. They cannot prove it confirms *Webmin*. This
harness closes that gap: each case points at a real vulnerable build, runs the
tool exactly as an operator would, and checks the verdict against what the
README claims.

Every case carries a **negative control** — a build or an endpoint that is not
vulnerable and must come back clean. That is not paperwork. A benchmark without
negative controls measures nothing: a tool that shouted `confirmed` at every
target would score full marks on the vulnerable half and the harness would call
it progress. A case passes only when both halves land.

Not part of ``python -m unittest discover -s tests``: cases need Docker and pull
real images, so they are opt-in and run by hand or in a dedicated job.

    python tests/bench/runner.py --list
    python tests/bench/runner.py --case webmin-cve-2019-15107
    python tests/bench/runner.py --all --markdown coverage.md

Cases whose target is already running (no ``compose`` key) need no Docker at
all, which is also how the harness itself is tested.

Only point cases at infrastructure you own or are authorised to test. The runner
passes ``--acknowledge-consent`` on your behalf, because a bench case is a
target you started yourself moments earlier.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BENCH_ROOT = Path(__file__).resolve().parent
CASES_DIR = BENCH_ROOT / "cases"
REPO_ROOT = BENCH_ROOT.parent.parent
RCEKIT = REPO_ROOT / "rcekit.py"

# A case must say what it expects, where to point the tool, and how to prove the
# result is not just an over-eager scanner. The negative control is required by
# design -- see the module docstring.
REQUIRED_KEYS = ("name", "rce_class", "target", "invocation", "expect", "negative_control")
VALID_EXPECTATIONS = ("confirmed", "needs-review", "negative", "inconclusive",
                      "error", "nothing-tested")


class CaseError(Exception):
    """A case file that cannot be trusted to measure anything."""


def validate_case(case: Dict[str, Any], source: str = "<case>") -> Dict[str, Any]:
    """Reject a case that cannot produce a meaningful result.

    Loud and early: a benchmark that silently skips a malformed case reports a
    smaller number of failures than reality, which is the one failure mode a
    benchmark must not have."""
    missing = [key for key in REQUIRED_KEYS if key not in case]
    if missing:
        raise CaseError(f"{source}: missing required key(s): {', '.join(missing)}")
    if not isinstance(case["invocation"], list) or not case["invocation"]:
        raise CaseError(f"{source}: 'invocation' must be a non-empty list of CLI arguments")
    if case["expect"] not in VALID_EXPECTATIONS:
        raise CaseError(f"{source}: 'expect' must be one of {', '.join(VALID_EXPECTATIONS)}, "
                        f"got {case['expect']!r}")
    control = case["negative_control"]
    if not isinstance(control, dict):
        raise CaseError(f"{source}: 'negative_control' must be an object")
    if "invocation" not in control and "compose" not in control:
        raise CaseError(f"{source}: 'negative_control' needs its own 'invocation' or 'compose' — "
                        "a control that reuses the vulnerable target's is not a control")
    control_expect = control.get("expect", "negative")
    if control_expect == "confirmed":
        raise CaseError(f"{source}: a negative control expecting 'confirmed' is a contradiction")
    if control_expect not in VALID_EXPECTATIONS:
        raise CaseError(f"{source}: negative_control 'expect' must be one of "
                        f"{', '.join(VALID_EXPECTATIONS)}, got {control_expect!r}")
    return case


def load_case(path: Path) -> Dict[str, Any]:
    """Read and validate one case file."""
    try:
        with open(path, encoding="utf-8") as handle:
            case = json.load(handle)
    except ValueError as exc:
        raise CaseError(f"{path}: not valid JSON ({exc})")
    return validate_case(case, str(path))


def discover_cases(cases_dir: Path = CASES_DIR) -> List[Path]:
    return sorted(cases_dir.glob("*.json"))


def wait_for_target(url: str, status: int = 200, timeout: float = 120.0,
                    interval: float = 2.0, insecure: bool = True) -> bool:
    """Poll ``url`` until it answers with ``status``, or ``timeout`` elapses.

    A container that is up is not a container that is ready, and running the
    tool against a half-started service produces an `error` verdict that looks
    like a benchmark regression. Any HTTP answer counts as reachable — a 401 or
    500 still means the server is listening — but the case's expected status is
    what ends the wait."""
    context = None
    if insecure and url.lower().startswith("https"):
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10, context=context) as response:
                if response.status == status:
                    return True
        except urllib.error.HTTPError as exc:
            if exc.code == status:
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def expand_paths(invocation: List[str]) -> List[str]:
    """Resolve ``{bench}`` / ``{repo}`` in a case's arguments.

    A case that references a captured request file has to name it somehow, and
    both a bare relative path (which breaks the moment the runner is invoked
    from elsewhere) and an absolute one (which breaks on every other machine)
    are wrong. The tokens make the anchor explicit."""
    return [arg.replace("{bench}", str(BENCH_ROOT)).replace("{repo}", str(REPO_ROOT))
            for arg in invocation]


def run_rcekit(invocation: List[str], python: Optional[str] = None,
               timeout: float = 900.0) -> Dict[str, Any]:
    """Run RCEKit once with the case's arguments and return its JSON results.

    ``--detect-json`` is appended by the harness rather than written into each
    case: the outcome must come from the tool's own machine-readable channel,
    not from scraping a report whose payload lines can contain literal
    newlines."""
    handle, results_path = tempfile.mkstemp(prefix="rcekit-bench-", suffix=".json")
    os.close(handle)
    command = [python or sys.executable, str(RCEKIT), "--acknowledge-consent",
               *expand_paths(invocation), "--detect-json", results_path]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                   cwd=str(REPO_ROOT))
        try:
            with open(results_path, encoding="utf-8") as results_file:
                report = json.load(results_file)
        except (OSError, ValueError):
            # No JSON means the run never got as far as detecting anything --
            # a bad invocation, a refused consent gate, a crash. Reporting that
            # as `negative` would read as "target not vulnerable".
            return {"verdict": "nothing-tested", "counts": {}, "probes": [],
                    "stdout": completed.stdout, "stderr": completed.stderr,
                    "exit_code": completed.returncode, "command": command}
        report["stdout"] = completed.stdout
        report["stderr"] = completed.stderr
        report["exit_code"] = completed.returncode
        report["command"] = command
        return report
    except subprocess.TimeoutExpired:
        return {"verdict": "error", "counts": {}, "probes": [],
                "stdout": "", "stderr": f"rcekit timed out after {timeout}s",
                "exit_code": None, "command": command}
    finally:
        try:
            os.unlink(results_path)
        except OSError:
            pass


def method_signatures(report: Dict[str, Any], verdict: str) -> List[str]:
    """The method identifiers behind every probe that reached ``verdict``.

    Both the bare method (``reflected``) and the full carrier
    (``reflected/unix/raw``) are returned, so a case can pin the exact break-out
    that worked or stay at the method level."""
    signatures: List[str] = []
    for probe in report.get("probes", []):
        if probe.get("verdict") != verdict:
            continue
        method = probe.get("method", "")
        signatures.append(method)
        signatures.append("{}/{}/{}".format(method, probe.get("environment", ""),
                                            probe.get("context", "")))
    return signatures


def check_report(report: Dict[str, Any], expect: str,
                 expect_method: Optional[str] = None) -> Tuple[bool, str]:
    """Whether one run matched what the case expected, and why not if it did not."""
    observed = report.get("verdict", "nothing-tested")
    if observed != expect:
        counts = report.get("counts") or {}
        detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no probes"
        return False, f"expected {expect}, got {observed} ({detail})"
    if expect_method:
        signatures = method_signatures(report, expect)
        if expect_method not in signatures:
            return False, (f"verdict {observed} came from "
                           f"{sorted(set(signatures)) or 'no method'}, not {expect_method!r}")
    return True, f"{observed} as expected"


def compose_command(case: Dict[str, Any], action: str) -> Optional[List[str]]:
    """The compose command for a case, or ``None`` when it manages no containers.

    A case may give ``compose`` as a ready-made argv list (full control) or rely
    on ``vulhub_path``, in which case the standard compose invocation is run in
    that directory under ``--vulhub-root``."""
    if "compose" in case:
        argv = list(case["compose"])
        return argv if action == "up" else list(case.get("compose_down", []))
    if "vulhub_path" not in case:
        return None
    if action == "up":
        return ["docker", "compose", "up", "-d"]
    return ["docker", "compose", "down", "-v"]


def run_one(case: Dict[str, Any], invocation: List[str], expect: str,
            expect_method: Optional[str], wait_for: Optional[Dict[str, Any]],
            compose_case: Dict[str, Any], vulhub_root: Optional[Path],
            keep_up: bool = False, verbose: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
    """Bring a target up, run RCEKit against it, tear it down, and judge."""
    cwd = None
    if "vulhub_path" in compose_case:
        if not vulhub_root:
            return False, "case needs --vulhub-root (it declares a vulhub_path)", {}
        cwd = vulhub_root / compose_case["vulhub_path"]
        if not cwd.is_dir():
            return False, f"vulhub path not found: {cwd}", {}
    up = compose_command(compose_case, "up")
    started = False
    try:
        if up:
            if verbose:
                print(f"    $ {' '.join(up)}" + (f"  (in {cwd})" if cwd else ""))
            started = subprocess.run(up, cwd=str(cwd) if cwd else None,
                                     capture_output=True, text=True).returncode == 0
            if not started:
                return False, "compose up failed", {}
        if wait_for:
            ready = wait_for_target(wait_for["url"], wait_for.get("status", 200),
                                    wait_for.get("timeout", 120))
            if not ready:
                return False, f"target never became ready at {wait_for['url']}", {}
        report = run_rcekit(invocation)
        ok, detail = check_report(report, expect, expect_method)
        return ok, detail, report
    finally:
        down = compose_command(compose_case, "down")
        if started and down and not keep_up:
            if verbose:
                print(f"    $ {' '.join(down)}")
            subprocess.run(down, cwd=str(cwd) if cwd else None,
                           capture_output=True, text=True)


def run_case(case: Dict[str, Any], vulhub_root: Optional[Path] = None,
             keep_up: bool = False, verbose: bool = False) -> Dict[str, Any]:
    """Run a case's vulnerable half and its negative control.

    The control runs even when the vulnerable half already failed. A case whose
    vulnerable target stopped confirming *and* whose control started confirming
    is a different problem from either alone, and only running both tells them
    apart."""
    outcome: Dict[str, Any] = {"name": case["name"], "rce_class": case["rce_class"],
                               "target": case["target"]}
    ok, detail, report = run_one(
        case, case["invocation"], case["expect"], case.get("expect_method"),
        case.get("wait_for"), case, vulhub_root, keep_up, verbose)
    outcome["vulnerable_ok"] = ok
    outcome["vulnerable_detail"] = detail
    outcome["verdict"] = report.get("verdict", "nothing-tested")
    outcome["methods"] = sorted(set(method_signatures(report, outcome["verdict"])))

    control = case["negative_control"]
    control_case = dict(case)
    control_case.update({k: v for k, v in control.items() if k in ("vulhub_path", "compose",
                                                                   "compose_down")})
    if "vulhub_path" in control and "compose" not in control:
        control_case.pop("compose", None)
    control_ok, control_detail, control_report = run_one(
        control_case, control.get("invocation", case["invocation"]),
        control.get("expect", "negative"), control.get("expect_method"),
        control.get("wait_for", case.get("wait_for")), control_case, vulhub_root,
        keep_up, verbose)
    outcome["control_ok"] = control_ok
    outcome["control_detail"] = control_detail
    outcome["control_verdict"] = control_report.get("verdict", "nothing-tested")
    outcome["passed"] = bool(ok and control_ok)
    return outcome


def render_markdown(outcomes: List[Dict[str, Any]]) -> str:
    """The coverage table, ready to paste into the README.

    The control column is part of the table on purpose: a reader can see that
    every confirmed row was checked against something that must stay clean,
    rather than taking the claim on trust."""
    lines = ["| RCE class | Target | Method | Verdict | Control | Result |",
             "|---|---|---|---|---|---|"]
    for outcome in outcomes:
        methods = ", ".join(f"`{m}`" for m in outcome.get("methods", []) if "/" not in m) or "—"
        verdict = outcome.get("verdict", "—")
        cell = f"**`{verdict}`**" if verdict == "confirmed" else f"`{verdict}`"
        control = f"`{outcome.get('control_verdict', '—')}`"
        result = "pass" if outcome.get("passed") else "**FAIL**"
        lines.append(f"| {outcome['rce_class']} | {outcome['target']} | {methods} | "
                     f"{cell} | {control} | {result} |")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run RCEKit against real vulnerable targets and check the verdicts.")
    parser.add_argument("--case", action="append", default=[],
                        help="Case name (file stem) to run; repeatable.")
    parser.add_argument("--all", action="store_true", help="Run every case.")
    parser.add_argument("--list", action="store_true", help="List available cases and exit.")
    parser.add_argument("--vulhub-root", default=os.environ.get("VULHUB_ROOT"),
                        help="Path to a vulhub checkout; required by cases with a vulhub_path.")
    parser.add_argument("--cases-dir", default=str(CASES_DIR))
    parser.add_argument("--markdown", default=None,
                        help="Write the coverage table to this file as well as stdout.")
    parser.add_argument("--keep-up", action="store_true",
                        help="Leave containers running after the case (for debugging).")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    cases_dir = Path(args.cases_dir)
    paths = discover_cases(cases_dir)
    if args.list:
        for path in paths:
            print(path.stem)
        return 0
    if args.case:
        wanted = set(args.case)
        paths = [p for p in paths if p.stem in wanted]
        unknown = wanted - {p.stem for p in paths}
        if unknown:
            print(f"[!] unknown case(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
    elif not args.all:
        parser.error("choose --case NAME, --all, or --list")
    if not paths:
        print("[!] no cases to run", file=sys.stderr)
        return 2

    vulhub_root = Path(args.vulhub_root) if args.vulhub_root else None
    outcomes: List[Dict[str, Any]] = []
    for path in paths:
        try:
            case = load_case(path)
        except CaseError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2
        print(f"[bench] {case['name']}: {case['target']}")
        outcome = run_case(case, vulhub_root, args.keep_up, args.verbose)
        outcomes.append(outcome)
        mark = "pass" if outcome["passed"] else "FAIL"
        print(f"[bench]   vulnerable: {outcome['vulnerable_detail']}")
        print(f"[bench]   control:    {outcome['control_detail']}")
        print(f"[bench]   -> {mark}")

    table = render_markdown(outcomes)
    print("\n" + table)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(table + "\n")
        print(f"\n[bench] table written to {args.markdown}")
    failed = [o for o in outcomes if not o["passed"]]
    print(f"\n[bench] {len(outcomes) - len(failed)}/{len(outcomes)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
