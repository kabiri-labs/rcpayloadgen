# Changelog

All notable changes to RCEKit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and RCEKit follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): PATCH for fixes,
MINOR for new capabilities, MAJOR for breaking changes to the CLI, output
formats, or the template schema.

## [Unreleased]

## [2.24.0] — 2026-08-16

The computed value is no longer looked for in the response body alone. A sink
whose output surfaces anywhere else in the response was reported `negative` — a
false negative on a class RCEKit already claims to cover, which is worse than a
missing class. The oracle, the random operands and the control differential are
unchanged; only the set of places searched is wider.

### Added

- **Whole-response evidence search.** Every confirmation now sweeps the response
  body, the application response headers, individual cookie values, the redirect
  target RCEKit actually landed on, the HTTP reason phrase, and each leaf of a
  parsed JSON body. Real sinks put command output in a debug header or a
  `Set-Cookie`, and API targets surface an evaluator's result inside a nested
  error envelope — `{"error": {"detail": "cannot render 2058898001"}}` — where a
  substring search of the serialised body misses a value the encoder escaped.
- **The evidence line names the channel that carried the value**, e.g.
  `target computed 'RK…' in header X-Cmd-Out (random operands, absent from
  control)`, so the finding stays reproducible by hand. A body-carried
  confirmation reads exactly as it did before.

### Changed

- **The control differential now covers every channel, not just the body.** A
  value present anywhere in the payload-free control is not attributable to
  execution, so it yields `inconclusive` wherever it turned up. This is stricter
  than comparing only the channel that matched, and it is what keeps a wider
  search from becoming a looser verdict.
- **The `file` method's control check covers every channel too**, on the same
  reasoning: its token is random, so its presence in any control channel means
  it did not get there by being written and served.

### Security

- **A deeply nested JSON response can no longer silence detection.** Channels are
  built inside the delivery `try`/`except`, so a `RecursionError` while parsing
  or walking the body escaped as a network failure: a response that arrived
  perfectly well was reported "request never reached the target". Measured:
  every one of the 46 probes in a default `reflected` run turned into `error`,
  which a target could induce deliberately to hide a live sink behind a thousand
  nested arrays. Version-independent, though the source moves — CPython 3.12
  raised the C recursion limit its JSON scanner runs under, so on 3.12/3.13 the
  parser survives a depth that breaks it on 3.8–3.11 and the recursive leaf walk
  hit the ordinary Python limit instead. The walk is now iterative and
  depth-capped, `RecursionError` from the parser costs the JSON channels only,
  and building channels can never turn a delivered response into a delivery
  failure.
- **Transport headers are excluded from the sweep.** `Content-Length`, `Date`,
  `Age`, `ETag` and their neighbours are generated below the application and can
  never carry a computed value, but they *are* numeric — and the `expr` probe's
  expected value is a bare boundary-fenced number. Searching them would let a
  byte count collide with an arithmetic result and read as execution. Locked in
  by a test that puts the expected value in `Content-Length` and requires
  `negative`.

## [2.23.3] — 2026-08-04

Four items from the same review: requests and seconds spent on work that could
not produce a result. No verdict changes — the lab still confirms 15 of 15
vulnerable sinks with nothing on the clean five — the run just stops paying for
probes that were structurally unable to confirm.

### Changed

- **The `awk` probe is no longer sent into a context that wraps the payload in
  quotes.** It carries double quotes, so in `attribute` the quote closed early
  and the rest was not a command: 5 requests per carrier that could only ever
  come back negative. Measured on a verbose shell sink, that shape confirmed 8
  times in `raw` and 0 times in `attribute`. Break-out contexts such as
  `shell_double_quoted` *close* the sink's quote and comment its tail, so they
  still get it. The same guard covers the PowerShell out-of-band shape.
- **The timing screen runs in two waves.** Every delayed screen probe costs a
  real sleep, so screening all five separators up front spent `5 × base` seconds
  on every carrier, including the ones that cannot break out at all. `; ` and
  `| ` are screened first and the rest only if neither delayed — a sink that
  filters both is still swept, it is just no longer the price everyone pays.
- **The out-of-band callback window is no longer paid per carrier.** Callbacks
  land in a burst once the channel works, so a target that has not produced one
  across every probe fired so far is not going to. The first carrier still gets
  the full window, so a target that does call back is never cut short before its
  first hit. On a clean target with the default carriers this was 30s of pure
  waiting; it is now ~12s.
- **`--probe-depth` documents what it does on Windows**, which is nothing:
  `cmd.exe` has no `#` comment, no `${IFS}` and no `awk`, so both depths send
  the single `set /a` probe. The docs promised three extra shapes per sink
  without that caveat.

## [2.23.2] — 2026-08-04

Three findings from a review of the detection work in 2.22.0 and 2.23.0. All
three are the same shape: the run said something that was not true — about what
it had done, about what it had looked for, or about which channel was live.

### Fixed

- **`--methods oob` ignored `--verify-active-risk`.** Detection methods build
  their own probes and so bypass every corpus-level safety filter. That was
  harmless while every method was inert, but this one makes the target open
  outbound connections — and the same run printed *"low-impact (safe) payloads
  only; pass `--verify-active-risk intrusive` to also fire … OOB"* and then fired
  OOB anyway. It now needs `--verify-active-risk intrusive`, the same tier that
  holds back the corpus OOB payloads, and refuses before the listener binds.
- **`--probe-depth quick` silently narrowed the timing separator screen to
  `; `.** That put back the exact blind spot the screen was added to remove, so
  a sink that merely filters `;` reported negative — and only for the operator
  who chose `quick` to be gentle on a rate-limited target. Both depths now screen
  every candidate separator; `--probe-depth` governs probe *shapes* only, and
  `--separators` remains the way to narrow break-outs deliberately.
- **The DNS out-of-band probes could not call back on the default port, and
  nothing said so.** A DNS callback travels the real resolver hierarchy, so it
  only arrives if the listener *is* the authority for the OOB domain — port 53
  plus NS delegation. On `--listen-dns-port 5335` the DNS shapes were still sent,
  never fired, and the startup line reported `DNS :5335` with no caveat. Since
  most of the shapes are DNS ones — a resolver is often the only egress a
  hardened target has — the silence was expensive. RCEKit now says which channel
  is live.
- The blind-sink advice added in 2.23.0 suggested an `oob` command without the
  risk flag, which the gate above would refuse. Naming a command the tool then
  declines to run is a small version of the same problem, so it now spells out
  `--verify-active-risk intrusive`.

## [2.23.1] — 2026-08-03

### Added

- **[Verify it yourself](docs/verify-it-yourself.md)** — reproduce the README's
  confirmations locally against dockerised [vulhub](https://github.com/vulhub/vulhub)
  targets. Webmin CVE-2019-15107 driven from a captured request (`reflected` →
  `confirmed`, then `time` → `needs-review` on the *same* sink, which is the
  clearest demonstration that the tiers are not merged), and Struts2 S2-001
  (`eval` confirms, `reflected` does not, on a target where both were tried).

  Log4Shell is documented as an advanced case rather than a five-minute one: its
  sink is a JNDI lookup inside a logging library, so `--methods oob` does not
  apply — that method builds shell probes for shell-capable environments. The
  `${jndi:…}` payloads come from the `oob` *category* with the listener
  correlating the callback, and the token rides in a DNS label, which needs a
  delegated domain. Saying so is cheaper than a reader discovering it mid-demo.

## [2.23.0] — 2026-08-03

The three sinks v2.22.0 still could not reach. One was a real gap in the probe
set; the other two were a reporting problem, not a detection one. With both
closed, a single `--methods reflected,eval,oob` run confirms **all fifteen**
vulnerable sinks in the lab and still reports nothing on any of the five clean
ones.

### Added

- **A space-free probe, sent at both probe depths.** Stripping spaces is a filter
  of the same family as stripping `;` — it looks like it disarms command
  injection and does not, because `${IFS}` is a space as far as the shell is
  concerned. Every other probe carries a space, so that one filter silenced all
  of them and the sink was only reachable if the operator thought to pass
  `--evade low`. The separator's trailing space is trimmed with it (`;echo…`, not
  `; echo…`); the newline separator is unaffected. It costs one shape, so it is
  not part of the `--probe-depth` trade-off, and it is skipped under
  `--evade low`, which already applies the same transform everywhere.
- **Guidance when every in-band probe comes back negative.** A results-based
  method cannot confirm a sink that returns no output — there is nowhere for the
  computed value to appear — so that negative is not evidence the target is
  clean. A run of `reflected`/`eval` alone that confirms nothing now says exactly
  that and names the methods that could still reach a blind sink, with the flags
  each one needs. It is suppressed once a blind-capable method has already run,
  and the `file` line is dropped once a web root is known.

## [2.22.0] — 2026-08-03

Detection coverage. Measured against a lab of twenty sinks — fifteen genuinely
vulnerable, five deliberately clean — the results-based methods went from
confirming 8 of the 15 to confirming 12, with no new false positives on any of
the clean ones.

### ⚠️ A blind-timing candidate could be pure latency drift

`--methods time` fired its probes in a fixed ascending delay order
(`0,0,N,N,2N,2N`), which makes the injected delay collinear with the request
index. A target that simply gets **slower during the run** — progressive load, a
rate limiter backing off, a filling log — therefore produced a textbook-perfect
linear fit while being entirely un-injectable. In the lab this reproduced on 8
of 8 runs against a sink with no command execution anywhere in it.

The probe order is now randomised, and the request index enters the regression
as a nuisance term, so drift loads onto a drift coefficient instead of
masquerading as a sleep. The same lab sink now reports negative on 9 of 9 runs,
with every genuine timing detection preserved. If you have a `needs-review`
timing candidate from an earlier version against a target that was under load,
it is worth re-running.

### Added

- **`--methods oob`** — out-of-band detection, the first `confirmed`-tier method
  for a sink that returns nothing *and* has no writable web root. Starts the
  built-in HTTP+DNS listener in-process and asks the target to resolve or fetch
  `<token>.<oob-host>`; a callback carrying a token the target could only have
  learned by running the command is proof of execution. Each probe gets its own
  token, so the finding names the break-out that actually worked. One shape puts
  a computed value in the DNS label, so the callback proves the shell evaluated
  arithmetic rather than merely resolving a name. Requires `--oob-host`, since
  it makes the target open outbound connections.
- **`--probe-depth quick|full`** (default `full`) — trades requests for
  coverage. `full` adds three probe shapes, each aimed at a filter that silenced
  the canonical ones: substitution-free (`awk`, bare `expr`) for sinks that strip
  `$(` and backticks; keyword-diverse (`awk`) for filters on `echo`/`expr`; and
  comment-terminated (`… #`) for applications that append a redirect, extra
  arguments or a pipe after the injection point. `quick` keeps the old probe set
  at roughly half the requests.

### Fixed

- **A `ping '<input>'` sink could not be detected at all.** The
  `shell_single_quoted`/`shell_double_quoted` contexts exist precisely for input
  interpolated inside quotes, but they are not in `default_contexts`, so no
  record carried them and the detection engine never tried them — the one sink
  shape they exist for was the one shape that always reported clean. They are now
  probed by default, and skipped when `--contexts` names a selection explicitly.
- **`--methods time` reported a `;`-filtering sink as negative.** A regression
  blends its probes into one measurement, so it could not sweep separators the
  way the results-based methods do and was locked to `; ` alone — while
  `| sleep 3` delayed on the same sink. It now screens every candidate separator
  with one cheap probe each, then runs the regression through whichever one
  actually delayed.
- **A trailing redirect or pipe in the sink hid a working probe.**
  `<cmd> <input> 2>/dev/null` and `<cmd> <input> | grep …` swallow the probe's
  output, so it executed and still read as negative. The comment-terminated
  shapes comment that tail out.

## [2.21.1] — 2026-08-02

First release since v2.15.2. The headline is not a new feature — it is that
detection is now correct in cases where it previously was not.

### ⚠️ Re-check findings from v2.15.2 and earlier

**A reflection could be reported as `confirmed`.** The paired same-token control
in `run_verification` was gated on a plain `re.search`, while the verdict itself
used the encoding-aware search. A target that only echoes input but wraps its
output — base64, hex, URL- or HTML-encoded — skipped the control entirely and was
reported as proven execution: precisely the case the encoding-aware search was
added for. If you ran an earlier version against a target that encodes its
responses, a `confirmed` verdict from that run is worth re-testing.

### Fixed — false negatives on exploitable targets

- **Separator sweep.** Shell probes always broke out with a single hardcoded
  `; `, so a sink that strips `;` — the most common partial mitigation there is,
  and one that stops nothing on its own — defeated every probe. Measured against
  nine deliberately vulnerable local sinks, detection was correct on 5 of 9;
  three of the four misses were exploitable targets reported clean. Probes now
  sweep `; `, `| `, `|| `, `&& ` and a newline, narrowable with `--separators`.
- **Language runtimes.** An environment names what runs the application, not what
  executes the injected command: PHP's `system()`, Python's `os.system()`,
  Node's `child_process.exec()`, Ruby's `system()`, Perl's backticks and Go's
  `os/exec` all hand the string to `/bin/sh`. Scoping a run to the language the
  application is written in — the natural thing to do — used to send no shell
  probes at all.
- **Whole-command sinks.** `--sink-raw` sends probes as bare commands for sinks
  that execute the input as the entire command (`qx/$input/`, `sh -c "$input"`),
  where a leading `;` is a syntax error that guaranteed a false negative.
- **Captured requests.** A trailing newline in a saved request body is no longer
  sent as part of the body.

### Fixed — a failed request is not a clean result

- A request that never reached the target is reported `error`, not `negative`.
- Runs that build no probes at all exit non-zero and say so, instead of ending
  in silence and exit 0 — which read exactly like a target that came back clean.
- The OOB DNS listener no longer dies on a malformed query, and write failures
  surface instead of being swallowed.

### Fixed — safety and audit

- **Multi-step chains now carry the same safeguards as single requests.** The
  chain path delivered to live targets without sink-shape filters, destructive
  hold-back or a pre-flight plan, so `--verify-active-risk stateful` fired
  persistence and irreversible file operations that `--verify-url` refuses to
  send without `--verify-allow-destructive`. Both paths now share one hold-back
  and print the same plan.
- **The audit trail redacts credentials** — it records that a credential header
  was sent, never its value.
- A capture carrying `Authorization` or `Cookie` over plain `http` is flagged
  before anything is sent.

### Added

- **The payload corpus is embedded in `rcekit.py`**, so the single file runs on
  its own — a jump box, an air-gapped host, a bare `curl` of the raw script.
  Resolution order is `--template-file` → `templates/payloads.json` beside the
  script → the built-in copy, and falling back to the built-in copy is
  announced. A corpus that exists but does not parse still hard-fails: that
  check exists for truncated and tampered corpora. `tools/embed_corpus.py`
  regenerates the embedded copy, and the test suite fails if the two drift.
- **`--insecure`** skips TLS verification for internal targets with self-signed
  or mismatched certificates — opt-in and explicit, like `curl -k`.
- **`--sink-raw`** for whole-command injection sinks, also readable from a
  target profile.
- **`--separators`** to narrow the break-out sweep once the sink's shape is
  known.
- **Documentation split into a task-oriented tree.** The README is half its
  former length and now leads with what RCEKit is for:
  [field guide](docs/guide.md) (worked examples by situation),
  [payload generation & exports](docs/generation.md), and
  [reference](docs/reference.md) (every flag grouped by task, plus the full
  taxonomies and exit codes).
- **A "How RCEKit compares" section** covering commix, SSTImap, Nuclei and
  interactsh, with every claim traceable to that project's own documentation.
- Four confirmation demos against real, publicly documented CVEs (Webmin
  CVE-2019-15107, Struts2 S2-001, Log4Shell CVE-2021-44228).

### Changed

- **Expect more requests per run.** The separator sweep and the language-runtime
  fix both widen the probe set. Narrow with `--separators`, `--contexts` and
  `--environments` once the sink's shape is known.
- **`--doctor` output.** Its first line now names the corpus in use
  (`corpus: …`) rather than a path (`template: …`), since the corpus is no
  longer necessarily a file, and `[ok] file loaded and parsed` is now
  `[ok] corpus loaded and parsed`.

No breaking changes to the CLI, output formats, or the template schema.
Standard library only, Python 3.8–3.13.

## Earlier releases

Release notes for these live on the
[Releases page](https://github.com/kabiri-labs/rcekit/releases); they predate
this file and have not been restated here.

- **[2.15.2]** — Multi-method RCE detection &amp; confirmation
- **[2.7.0]**
- **[2.1.0]**

[Unreleased]: https://github.com/kabiri-labs/rcekit/compare/v2.24.0...HEAD
[2.24.0]: https://github.com/kabiri-labs/rcekit/compare/v2.23.3...v2.24.0
[2.23.3]: https://github.com/kabiri-labs/rcekit/compare/v2.23.2...v2.23.3
[2.23.2]: https://github.com/kabiri-labs/rcekit/compare/v2.23.1...v2.23.2
[2.23.1]: https://github.com/kabiri-labs/rcekit/compare/v2.23.0...v2.23.1
[2.23.0]: https://github.com/kabiri-labs/rcekit/compare/v2.22.0...v2.23.0
[2.22.0]: https://github.com/kabiri-labs/rcekit/compare/v2.21.1...v2.22.0
[2.21.1]: https://github.com/kabiri-labs/rcekit/compare/v2.15.2...v2.21.1
[2.15.2]: https://github.com/kabiri-labs/rcekit/releases/tag/v2.15.2
[2.7.0]: https://github.com/kabiri-labs/rcekit/releases/tag/v2.7.0
[2.1.0]: https://github.com/kabiri-labs/rcekit/releases/tag/v2.1.0
