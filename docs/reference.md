# Reference

Every flag and every taxonomy, grouped by what you are trying to do. If you are
looking for *how to use these together*, the [field guide](guide.md) is the better
starting point — this page is for looking things up once you know what you want.

**Contents**

- [Choosing the target](#choosing-the-target)
- [Detection methods](#detection-methods)
- [Sink shape](#sink-shape)
- [The sink shell](#the-sink-shell)
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
| `--methods` | Comma-separated: `reflected`, `eval`, `file`, `oob`, `time` | None |
| `--file-write-path` | (`file`) server-side directory the target can write to, e.g. `/tmp` | None |
| `--file-read-url` | (`file`) URL template that reads it back: `{name}`, `{path}`, `{path_enc}` | None |
| `--webroot` | (`file`) web-root alias for `--file-write-path` | None |
| `--web-base-url` | (`file`) web-root alias for `--file-read-url '<base>/{name}'` | None |
| `--oob-host` | (`oob`) host the **target** calls back to; required for `oob` | None |
| `--time-base` | (`time`) base delay `N`; the regression fires `0/N/2N` | `2.0` |
| `--separators` | Break-out separators for shell probes; `\n` = newline | `; `, `\| `, `\|\| `, `&& `, newline |
| `--evade` | WAF posture: `none`, or `low` for minimal `${IFS}`-for-spaces | `none` |
| `--probe-depth` | `full` (also the substitution-free and comment-terminated shapes) or `quick` | `full` |
| `--detect-json` | Also write the run to this path as JSON: overall verdict, counts, every probe | None |
| `--sink-shape` | Sink shapes the shell probes try: `auto`, or any of `sep`, `raw`, `chain`, `newline`, `dq`, `sq`, `subshell` | `auto` |
| `--sink-env` | Shell that runs the injected command: `auto`, `unix`, `windows`, `powershell` | `auto` |
| `--eval-engines` | (`eval`) Engine carriers to add to the bare expression probes: `auto`, or names from `eval_carriers` | `auto` |
| `--auto-params` | (`-r` with `--methods`) Enumerate injection points: kinds from `query`, `json`, `form`, `cookie`, `header`, `path`, or `all`. Implied by `-p all` | off |
| `--point-order` | (enumeration) `fast` (curated high-yield headers) or `thorough` (every non-hop-by-hop header) | `fast` |
| `--max-points` | (enumeration) Stop after N candidates; the run reports how many it dropped | `40` |
| `--include-path-segments` | (enumeration) Also inject into URL path segments | off |

| `--methods` value | Confirms | Tier it can reach |
|---|---|---|
| `reflected` | OS command injection, via computed arithmetic | `confirmed` |
| `eval` | SSTI / SpEL / OGNL / Groovy / raw `eval()`, via a computed product | `confirmed` |
| `file` | Execution + a write primitive, via write-and-fetch | `confirmed` |
| `oob` | Blind execution, via a DNS/HTTP callback carrying a per-probe token | `confirmed` |
| `time` | Blind execution, via a `0/N/2N` regression | `needs-review` only |

### Probe depth

One extra shape is sent at **both** depths, because it costs a single shape and
closes a whole filter class:

- **space-free** (`echo${IFS}…`) — stripping spaces looks like it disarms
  command injection and does not, since `${IFS}` is a space to the shell. Every
  other probe carries a space, so this one filter silenced all of them. The
  separator's trailing space is trimmed too (`;echo…`, not `; echo…`), and the
  newline separator survives unchanged.

`full` sends three further shapes per sink, each aimed at a filter that silences
the canonical probes:

- **substitution-free** (`awk`, bare `expr`) — both canonical probes route the
  arithmetic through `$((…))` or a backtick, so a sink that strips `$(` blocks
  them while remaining exploitable through a plain `;`. The `awk` shape carries
  double quotes, so it is not sent into a context that *wraps* the payload in
  them (`attribute`): the quote would close early and the probe could only ever
  come back negative. Break-out contexts such as `shell_double_quoted` close the
  sink's quote and comment its tail, so they still get it.
- **keyword-diverse** (`awk` again) — a filter on `echo`/`expr` blocks both
  canonical probes; `awk` is not on those blocklists.
- **comment-terminated** (`… #`) — comments out whatever the application appends
  after the injection point. A trailing redirect or pipe (`ping <input> 2>/dev/null`,
  `<cmd> <input> | grep …`) otherwise swallows the probe's output, so the probe
  executes and still reads as negative.

`quick` sends only the canonical probes — roughly half the requests, for
rate-limited targets or when the sink's shape is already known.

**All of these shapes are Unix.** `cmd.exe` has no `#` comment, no `${IFS}`, and
no `awk`, so `--environments windows` gets the one `set /a` probe at either
depth and `--probe-depth` changes nothing for it.

`--probe-depth` governs probe *shapes* only. It does not narrow the separator
sweep, and it does not narrow the separator screen `--methods time` runs: both
depths try every candidate break-out, because dropping one is not a saving in
requests but a blind spot. Use `--separators` to narrow that deliberately.

### File-based confirmation, and what counts as read-back

`--methods file` makes the target write a random token to a file and then
fetches it back. The token is present only if the command executed *and* the
write landed somewhere readable — the confirmation channel is the target's own
read-back path, so no external listener is needed.

That path **does not have to be a web root**. Name the two halves directly:

```bash
# An LFI / download / export handler that takes a server-side path
python rcekit.py --acknowledge-consent --verify-url "https://target/lookup?host=FUZZ" \
  --methods file \
  --file-write-path /tmp \
  --file-read-url "https://target/download?f={path_enc}"
```

| Placeholder | Expands to | Suits |
|---|---|---|
| `{name}` | the generated filename | a handler that takes a filename |
| `{path}` | the full server-side path | an LFI-style parameter |
| `{path_enc}` | that path, percent-encoded | a handler that rejects raw separators |

Only those three are substituted, so a URL that legitimately contains braces
survives unchanged.

`--webroot` + `--web-base-url` remain as the **web-root alias** — a web root is
just the case where the read URL is the base plus the filename, so
`--webroot DIR --web-base-url BASE` is exactly
`--file-write-path DIR --file-read-url 'BASE/{name}'`. Existing command lines
are unaffected. The alias and the general form are resolved in one place, so
they cannot drift.

Why it matters: requiring a writable web root ruled out the LFI endpoint, the
download handler, the attachment fetcher and the `/tmp`-backed preview — on
exactly the internal, no-egress targets this method exists for. Measured against
a target with a download handler and nothing serving the write directory, the
web-root form confirms 0 and the general form confirms 7.

This method changes target state (one file per confirmed probe), so it stays
gated on the operator naming both halves, and **every finding prints its own
cleanup command**.

### Enumerating injection points

`-p NAME` needs you to already know which parameter is the sink. A real capture
carries ten to forty candidates, and some of the highest-value classes inject
through a **header** — Shellshock through `User-Agent`, Struts2 S2-045 through
`Content-Type` — or through a JSON leaf several levels down that no top-level
parameter name addresses.

```bash
python rcekit.py --acknowledge-consent -r request.txt -p all --methods reflected
```

Candidates are tried in expected-yield order, each rewritten in **its own**
serialization rather than blanket-encoded:

| Kind | Addressed as | Rewritten by |
|---|---|---|
| `query` | parameter name | the `a=1&b=2` encoder |
| `json` | path — `user.profile.name`, `tags[1]` | the JSON encoder, re-serialised |
| `form` | field name | the `a=1&b=2` encoder |
| `cookie` | crumb name | the `Cookie` header, other crumbs untouched |
| `header` | header name | single-line header escaping |
| `path` | segment index | the URL path (opt-in, see below) |

A JSON leaf is only *replaced*, never created: assigning to a missing key would
test a field the application never sends.

`Host`, `Content-Length`, `Cookie` and the hop-by-hop headers are never
candidates — injecting into those changes the request's plumbing rather than
testing the app, and two of them are rebuilt by the delivery layer.

Path segments are off by default (`--include-path-segments`): rewriting one
usually just produces a 404, which costs a request and proves nothing.

**The cost is printed before the traffic**, because enumeration multiplies an
already-laddered probe count by the number of candidates:

```
[detect] enumerating 6 injection point(s) x 1 method(s)
[detect] cost: 6 points x ~61 probes = at least 372 requests (each point carries its own payload-free control)
[detect]   query param 'view': negative (61 probes)
[detect]   header 'User-Agent': confirmed (61 probes)  <-- CONFIRMED
```

Each candidate gets **its own** payload-free control: differencing a header
probe against a query probe's control would compare two different responses and
prove nothing. Use `--max-points` and `--max-payloads` to bound a run, and
`--verify-delay` to pace it — the delay applies across the whole enumeration.

Cheap methods run first per candidate. `reflected` and `eval` cost one response
each; `time` sleeps and `oob` waits for a callback. Once a candidate has proven
execution, the slow methods on *that* candidate are skipped — they would buy a
second name for a finding already made. Candidates that stay clean still get
every method. Single-point runs (`-p NAME`, or a `FUZZ` marker) are unchanged
and still run every method.

### Expression-engine carriers

The `eval` method injects a product of two random operands in each common
template syntax and confirms that the **product** comes back. Most engines need
nothing more than that. Three do, and `--eval-engines` controls the extra probes
for them.

A carrier exists for exactly one reason: **the engine evaluates the expression
perfectly but does not put the bare product in the response**, so the oracle
cannot see it and a vulnerable target reads as `negative`.

| Engine | Bare `${a*b}` returns | Carrier | Carrier returns |
|---|---|---|---|
| Freemarker | `2,070,761,401` — grouped by locale | `${(a*b)?c}` | `2070761401` |
| Velocity | `${a*b}` verbatim — it is a *reference*, not an expression | `#set($rk=a*b)$rk` | `2070761401` |
| Thymeleaf | `${a*b}` verbatim — needs its inlining brackets | `[[${a*b}]]` | `2070761401` |

Measured against freemarker 2.3.32, velocity-engine-core 2.3 and thymeleaf
3.1.2; each corpus entry records what it was verified against.

**A sandbox is not what carriers are for.** A member-access sandbox restricts
method and field access; arithmetic and string concatenation need neither, so
the bare probe survives one. Measured:

| Engine | Bare `a*b` | `Runtime`-class member access |
|---|---|---|
| OGNL, member access denied for *everything* | evaluates | blocked |
| SpEL `SimpleEvaluationContext` (restricted) | evaluates | blocked |
| Jinja2 `SandboxedEnvironment` | evaluates | blocked |
| Groovy, ERB, JS `eval`, Python `eval` | evaluates | — |

So the bare probes already cover the sandboxed engines, and narrowing
`--eval-engines` saves little — there are only three carriers, and they are the
cheap part of the run.

Carriers live in `eval_carriers` in `templates/payloads.json`, so a new one is a
JSON entry, not a code change. Each records `notes` (why it exists) and
`verified` (what it was measured against); a carrier without measured evidence
that the bare probe fails is a probe that can only waste a request.

### The sink-shape ladder

An injected value lands in a *shape*, and the shape decides what can reach it.
`--sink-shape` names which ones to try; `auto` tries the whole ladder.

| Rung | Probe looks like | Sink shape |
|---|---|---|
| `sep` | `; cmd` | mid-command concatenation |
| `raw` | `cmd` | the input **is** the whole command (`qx/$input/`) |
| `chain` | `\| cmd`, `\|\| cmd`, `&& cmd` | pipes and conditional chains |
| `newline` | newline + `cmd` | line-oriented sinks (CGI, config writers) |
| `dq` | `"; cmd #` | value inside double quotes |
| `sq` | `'; cmd #` | value inside single quotes |
| `subshell` | `$(cmd)`, `` `cmd` `` | value inside quotes, reached **without closing them** |

`subshell` is the rung that is easy to mis-explain, so here is what it is
actually for. Against `system("echo PING \"$input\"")`, with the app filtering
one metacharacter:

| app strips | `dq` | `subshell` |
|---|---|---|
| `"` | inert | **executes** |
| `$` | executes | inert (backtick form still executes) |

Both substitution forms ship because they survive different filters.

And the rung matters **per method**, which is the counter-intuitive part.
`reflected`'s core is `$((a+b))`, which the shell expands inside double quotes
anyway — so that method already confirmed on a quoted sink without this rung.
The methods whose core has to actually *run* something are the ones that were
blind there:

| Core | Inside `"…"` | Inside `$( )` |
|---|---|---|
| `$((a+b))` — `reflected` | expands | expands |
| `sleep 5` — `time` | inert | sleeps |
| `echo TOKEN > file` — `file` | no write | writes |
| `curl …` — `oob` | no request | fetches |

Narrow the ladder once the sink's shape is known — it is the request-count
control. `--sink-raw` is the narrowing alias for `--sink-shape raw`, and naming
`--separators` implies the sink is separator-led, so the `raw` rung is dropped
unless you name it explicitly. A profile with `sink_needs_separator` drops it
too. The plan is printed before anything is sent:

```
[detect] sink shapes: auto (full ladder)
[detect]   sep       '; ' -- mid-command concatenation
[detect]   raw       input is the whole command (no separator)
...
```

`eval` does not ride the ladder: its probes are template/expression syntax, not
shell, so no separator or quote break-out applies to them.

### The sink shell

The ladder says *where the value lands*; `--sink-env` says *which shell reads
it*. Every part of a shell probe is dialect-specific, so the two questions are
independent and both have to be right:

| | `unix` | `windows` (cmd.exe) | `powershell` |
|---|---|---|---|
| computed value | `$((a+b))` | `for /f … ('set /a a+b')` | `Write-Output T1$(a*b)T2` |
| delay | `sleep N` | `ping 127.0.0.1 -n k >nul` | `Start-Sleep -Milliseconds N` |
| write | `echo TOK > path` | `echo TOK>path` | `Set-Content -Path path -Value TOK` |
| call back | `curl`, `nslookup`, `host` | `certutil`, `nslookup` | `iwr -useb`, `nslookup` |
| separators | `;` `\|` `\|\|` `&&` newline | `&` `\|` `\|\|` `&&` | `;` newline `&&` `\|\|` |
| break-out contexts | `sq` `dq` `subshell` (`$( )` and backtick) | none | `sq` `dq` `subshell` (`$( )` only) |

A probe written for the wrong shell costs a request and can only come back
negative — `$((a+b))` is inert text on cmd.exe, and `sleep 5` is not a command
there at all. Three of those rows are worth stating outright because they are
not symmetric:

- **cmd.exe has no comment character and no command substitution**, so the `sq`,
  `dq` and `subshell` rungs have no shape it can execute and no carriers are
  built for them. Narrowing to `--sink-env windows` therefore also narrows the
  ladder, and the pre-flight plan says so.
- **PowerShell has no pipe break-out.** `cmd | Start-Sleep -Milliseconds 500` is
  a parameter-binding error, not a fresh command with stdin attached, and it
  fails that way for every cmdlet the probes use. `;`, a newline and (on
  PowerShell 7) `&&`/`||` are the working ones.
- **The backtick is PowerShell's escape character**, not a substitution, so the
  `subshell` rung is `$( )` alone there.

`auto` infers the dialect per carrier: the `powershell` context takes the
PowerShell shape, `windows_cmd` and the rest of the `windows` environment take
cmd.exe, everything else takes POSIX. Pin it when the corpus environment names
the *application runtime* rather than the OS — `--environments php --sink-env
windows` is a PHP application on IIS, which `auto` cannot see. The `dotnet`
environment is the one runtime that also gets cmd.exe and PowerShell carriers
under `auto`; every other runtime keeps the POSIX shape, since a language does
not say which OS it runs on.

```
[detect] sink shell: auto (per carrier)
[detect] sink shapes: auto (full ladder)
```

### Machine-readable results

`--detect-json PATH` writes the run as JSON alongside the usual text report:

```json
{
  "rcekit_version": "2.25.0",
  "target": "https://target.example/lookup?host=FUZZ",
  "methods": ["reflected"],
  "verdict": "confirmed",
  "counts": {"confirmed": 4, "negative": 9},
  "probes": [{"verdict": "confirmed", "method": "reflected", "environment": "unix",
              "context": "raw", "payload": "...", "detail": "target computed ..."}]
}
```

Use it instead of parsing stdout. Two things make the text report unsafe to
scrape: a probe payload may contain a literal newline — the newline separator is
a real one — so line-oriented parsing splits a payload in half, and the
detection path exits 0 whether it confirmed or came back clean.

The top-level `verdict` collapses the run, ordered by what you must not miss
rather than by what is most frequent: one `confirmed` among a hundred negatives
is the finding. `error` appears only when *nothing* reached the target, and a run
that built no probes is `nothing-tested` — never `negative`, which would read as
"not vulnerable".

This is the channel [`tests/bench/`](../tests/bench/README.md) reads to check
verdicts against real vulnerable targets.

### Out-of-band detection

`--methods oob` starts the built-in HTTP+DNS listener in-process and asks the
target to resolve or fetch `<token>.<oob-host>`. It is the only `confirmed`-tier
method for a sink that returns nothing and has no writable web root — `time`
tops out at `needs-review` by design, and `file` needs somewhere to write that
the target also serves.

Each probe carries its own token, so the finding names the break-out that
actually worked rather than every one that was tried. The DNS shapes matter
most: egress filtering that blocks outbound HTTP usually still lets the resolver
out. One shape goes further and puts a computed value in the label
(`$((a+b)).<token>.<host>`), so the callback proves the shell evaluated
arithmetic rather than merely resolving a name it was handed.

`--oob-host` must be an address the *target* can reach that arrives at this
listener: an IP on a routable interface, or a domain whose NS records are
delegated here. With a bare IP the token rides in the URL path instead of a DNS
label, and the DNS shapes are skipped rather than sent as probes that could
never call back.

**The DNS shapes need port 53.** A DNS callback travels the real resolver
hierarchy, so it only arrives if this listener *is* the authority for the OOB
domain — `--listen-dns-port 53` (needs root) plus NS records delegating the
domain here. On any other port the DNS probes are still sent and can never call
back; RCEKit says so at startup rather than leaving you to infer it from
silence.

This makes the target open outbound connections, so it is held back at the
default safety tier — the same tier that holds back the corpus OOB payloads —
and needs `--verify-active-risk intrusive` as well as `--oob-host`.

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
| `--template-file` | Custom JSON payload corpus; authoritative — never falls back | `templates/payloads.json`, else the built-in copy |
| `--attacker-ip` | Substituted into reverse-shell payloads | `192.168.1.100` |
| `--attacker-domain` | Substituted into download-execute payloads | `attacker.com` |

## Diagnostics

| Option | Description |
|---|---|
| `--doctor` | Report which corpus is in use and check its integrity (parses, payload counts); exits non-zero if unusable |
| `--version` | Print the version and exit |

### Corpus resolution

RCEKit looks for its payload corpus in this order:

1. `--template-file`, when given — **authoritative**: if it is missing or
   unparseable, the run fails. It never silently becomes the built-in corpus.
2. `templates/payloads.json` beside the script — the source of truth in a
   repository checkout, so an edit to it takes effect immediately.
3. The copy embedded in `rcekit.py` — so a single file copied onto a jump box or
   fetched with `curl` still runs. Using it prints a notice.

A corpus that exists but fails to parse is always an error, at every step. Only
an *absent* default file falls through to the built-in copy.

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
