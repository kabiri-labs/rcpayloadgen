# Reference

Every flag and every taxonomy, grouped by what you are trying to do. If you are
looking for *how to use these together*, the [field guide](guide.md) is the better
starting point — this page is for looking things up once you know what you want.

**Contents**

- [Choosing the target](#choosing-the-target)
- [Detection methods](#detection-methods)
- [Sink shape](#sink-shape)
- [Safety &amp; consent](#safety--consent)
- [Out-of-band listener](#out-of-band-listener)
- [Generation &amp; output](#generation--output)
- [Diagnostics](#diagnostics)
- [Environments](#environments)
- [Categories](#categories)
- [Contexts](#contexts)
- [Encodings](#encodings)
- [Code-execution sinks](#code-execution-sinks)
- [Exit codes](#exit-codes)

---

## Choosing the target

| Option | Description | Default |
|---|---|---|
| `--verify-url` | Authorised target URL with a `FUZZ` marker | None |
| `--verify-method` | HTTP method for `--verify-url` | `GET`, or `POST` with `--verify-data` |
| `--verify-data` | Request body; put `FUZZ` where the payload goes | None |
| `--verify-header` | Header `'Name: value'` (repeatable); may contain `FUZZ` | None |
| `-r`, `--request-file` | Raw HTTP request to inject into (mark with `FUZZ`/`*` or `-p`) | None |
| `-p`, `--param` | Parameter/field/header/cookie to inject into for `-r` (query → body → header → cookie) | None |
| `--request-scheme` | `http` / `https` for the URL built from `-r` | auto |
| `--verify-url-location` | Where `FUZZ` sits in the URL: `query_value`, `url_path`, `raw` | `query_value` |
| `--verify-body-location` | How to encode `FUZZ` in the body: `json_string`, `form_value`, `raw` | auto |
| `--verify-delay` | Seconds between verification requests (rate limiting) | `0` |
| `--verify-timeout` | Per-request timeout in seconds | `8` |
| `--insecure` | Skip TLS certificate verification, like `curl -k` | Off |
| `--verify-chain` | JSON chain profile for multi-step, session-aware verification | None |

## Detection methods

| Option | Description | Default |
|---|---|---|
| `--methods` | Comma-separated: `reflected`, `eval`, `file`, `time` | None |
| `--webroot` | (`file`) server-side directory the target writes and serves | None |
| `--web-base-url` | (`file`) base URL that serves `--webroot` | None |
| `--time-base` | (`time`) base delay `N`; the regression fires `0/N/2N` | `2.0` |
| `--separators` | Break-out separators for shell probes; `\n` = newline | `; `, `\| `, `\|\| `, `&& `, newline |
| `--evade` | WAF posture: `none`, or `low` for minimal `${IFS}`-for-spaces | `none` |

| `--methods` value | Confirms | Tier it can reach |
|---|---|---|
| `reflected` | OS command injection, via computed arithmetic | `confirmed` |
| `eval` | SSTI / SpEL / OGNL / Groovy / raw `eval()`, via a computed product | `confirmed` |
| `file` | Execution + a write primitive, via write-and-fetch | `confirmed` |
| `time` | Blind execution, via a linear `0/N/2N` regression | `needs-review` only |

## Sink shape

| Option | Description | Default |
|---|---|---|
| `--sink-raw` | Sink runs the input as the whole command — send bare probes, no leading separator | Off |
| `--sink-needs-separator` | Input is concatenated mid-command — keep only separator-led payloads | Off |
| `--sink-blind` | Sink returns no output — keep only OOB/timing-confirmable payloads | Off |
| `--sink-decodes` | Encodings the sink decodes before use (e.g. `base64`) | None |
| `--deny-chars` | Drop payloads containing any of these characters | None |
| `--max-length` | Drop payloads longer than this | None |
| `--target-profile` | JSON profile supplying the above as defaults | None |

## Safety &amp; consent

| Option | Description | Default |
|---|---|---|
| `--acknowledge-consent` | Required to generate or fire exploitation payloads | Off |
| `--verify-active-risk` | Highest safety tier verification may fire: `safe`, `intrusive`, `stateful` | `safe` |
| `--verify-allow-destructive` | Allow destructive payloads (persistence, backdoors) | Off |
| `--max-safety` | Highest safety tier to include in **file output** | `safe`–`intrusive` |
| `--include-blocking` | Include blocking or timing-based payloads excluded by default | Off |
| `--watermark` | Embed a traceable token in each exploitation payload | Off |

`--verify-active-risk` governs what is **fired**; `--max-safety` governs what is
**written**. They are independent on purpose.

## Out-of-band listener

| Option | Description | Default |
|---|---|---|
| `--listen` | Run the built-in HTTP+DNS listener | Off |
| `--correlate` | `.map.jsonl` manifest mapping received tokens back to payloads | None |
| `--listen-http-port` | HTTP port for the listener | `8080` |
| `--listen-dns-port` | UDP DNS port (use `53` for real DNS — needs root + NS delegation) | `5335` |
| `--listen-answer-ip` | IP returned by the listener's DNS answers | `127.0.0.1` |
| `--listen-log` | Append received hits to this file as JSONL | None |
| `--oob-domain` | Collaborator/interactsh domain; each payload gets a unique subdomain token | None |

## Generation &amp; output

| Option | Description | Default |
|---|---|---|
| `-o`, `--output` | Output file, or base directory for `burp`/`nuclei` | `rce_payloads.txt` |
| `--output-format` | `text`, `jsonl`, `burp`, `ffuf`, `nuclei` | `text` |
| `--environments` | Restrict generation to these environments | All |
| `--categories` | Restrict generation to these categories | All |
| `--contexts` | Restrict generation to these contexts | All compatible |
| `--encodings` | Restrict generation to these encodings | mode-specific |
| `--max-payloads` | Cap payloads (balanced round-robin sample) | Unlimited |
| `--detection-only` | Benign canary/timing probes for safe validation (no consent needed) | Off |
| `--include-metadata` | Write a `.meta.jsonl` sidecar (indicators, tiers, notes) | Off |
| `--template-file` | Custom JSON payload corpus | `templates/payloads.json` |
| `--attacker-ip` | Substituted into reverse-shell payloads | `192.168.1.100` |
| `--attacker-domain` | Substituted into download-execute payloads | `attacker.com` |

## Diagnostics

| Option | Description |
|---|---|
| `--doctor` | Check corpus integrity (found, parses, payload counts); exits non-zero if missing or empty |
| `--version` | Print the version and exit |

---

## Environments

`unix`, `windows`, `nodejs`, `python`, `php`, `java`, `dotnet`, `ruby`, `perl`,
`go`, `docker`, `kubernetes`, `graphql`, `mongodb`.

The shell methods (`reflected`, `file`, `time`) apply to the shell environments
and to the language runtimes, since each hands its string to `/bin/sh`. The
data-layer environments (`sql`, `graphql`, `mongodb`) are excluded from those
methods — `eval` is what applies there.

## Categories

`basic_enum`, `file_operations`, `network_operations`, `code_execution`,
`download_execute`, `reverse_shells`, `credential_access`, `privilege_escalation`,
`persistence`, `cloud_metadata`, `database_enumeration`, `lateral_movement`,
`container_escape`, `waf_bypass`, `oob`, `nosql_injection`, `graphql_injection`.

## Contexts

Each context carries an escape rule, so the payload survives the container it is
delivered in.

**Language / structural break-outs** (default): `raw`, `html`, `attribute`,
`attribute_unquoted`, `javascript`, `sql`, `php`, `unix_shell`, `windows_cmd`,
`powershell`, `shell_single_quoted`, `shell_double_quoted`, `graphql_string`.

**Transport / serialization** (opt-in): `json`, `graphql_variable`, `xml`,
`xml_cdata`, `yaml`, `http_header`.

## Encodings

**Self-contained** (default set) — run as-is on the sink: `none`, `url_encode`,
`double_url_encode`, `random_case` (for case-insensitive runners),
`base64_decode_exec` (carries its own `base64 -d | sh`).

**Decoder-required** (opt-in) — only valid where the sink itself decodes the
input, via `--sink-decodes`: `base64`, `hex`, `base64_then_url`, `double_base64`.

## Code-execution sinks

For `--categories code_execution`:

| Environment | Sinks |
|---|---|
| Node | `child_process_exec`, `*_ssti`, `vm_eval`, `deserialization`, `expression_template` |
| Python | `os_system`, `subprocess`, `jinja2_ssti`, `exec_ast` |
| PHP | `exec_system`, `eval`, `deserialize` |
| Java | `runtime_exec`, `freemarker/velocity/thymeleaf_ssti`, `spel`, `ognl`, `groovy`, `deserialization` |
| .NET | `process_start`, `deserialize` |
| Ruby | `kernel_system`, `erb_ssti` |
| Perl | `system_backticks` |
| Go | `os_exec` |
| Postgres | `psql_meta_command` |
| Mongo | `operator_injection`, `where_js`, `server_side_js` |
| GraphQL | `introspection`, `injection`, `batching` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The run completed. For verification this includes a clean `negative` — the target was tested and no evidence was found. |
| non-zero | The run did not produce a trustworthy result: the payload corpus is missing or unparseable, `--doctor` failed, or the filters built no probes at all. |

A run that tested nothing is never reported as a clean result.
