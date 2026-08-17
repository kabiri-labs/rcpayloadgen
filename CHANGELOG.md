# Changelog

All notable changes to RCEKit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and RCEKit follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): PATCH for fixes,
MINOR for new capabilities, MAJOR for breaking changes to the CLI, output
formats, or the template schema.

## [Unreleased]

## [2.32.0] — 2026-08-17

The second-order oracle. Execution frequently happens on a **different request**
than injection — stored SSTI rendered on a profile page, a payload written to a
log a template engine later renders, a queued job run asynchronously. The engine
diffs the response it injected into, so every one of those read `negative`
however exploitable the target was.

### Added

- **`--observe-url URL`** names the endpoint where the execution surfaces. It is
  read after each probe and then polled after the batch, and a probe whose
  computed value turns up there is upgraded to `confirmed`.

  It stays fully differential, which is why it reaches `confirmed` rather than
  `needs-review`: the value was computed locally from operands random to that
  probe, it must be absent from a snapshot of the endpoint taken **before any
  probe was sent**, and — the rule that carries the weight — a probe's value is
  looked for there **only when the probe's own payload does not contain it**.

  Without that last rule the oracle would be a false-positive generator: `file`
  and `oob` expect a random token that sits verbatim in the payload, so a target
  that merely stores the payload and renders it back would hand that token
  straight to the observed page and every such probe would confirm without
  executing anything. Measured against a store-and-echo target: **0**
  confirmations. The computed-value methods pass the same rule for the opposite
  reason — reflection returns `$((a+b))`, never the sum — so it selects them
  without naming them, and a method added later inherits the right answer.

- **`--observe-request FILE`** takes a captured request instead, for the common
  case where the page a stored payload renders on is behind a login. It needs no
  `FUZZ` marker: the observed endpoint is read, never injected into.

- **`--observe-poll` / `--observe-timeout`** control the polling window
  (defaults 5s and 60s). One poll always happens, even at a zero timeout.

- Every probe result carries an `observe_status` in `--detect-json`:
  `confirmed`, `polled` (read, value not there), `in-control`, `not-observed`
  (not eligible) or `unreachable`. When the endpoint never answered, the run
  says so outright — negatives decided without ever reading the observed channel
  are not second-order negatives.

### Changed

- The observed channel is read once after **each** probe as well as polled after
  the batch, so a run with `--observe-url` sends roughly twice the requests.
  Batch-then-poll alone is only correct for a channel that *accumulates* (a log,
  a comment list); where the store overwrites — a profile field, which is the
  shape this oracle most exists for — every probe but the last is gone by the
  time the batch poll runs, and the oracle confirmed nothing. The extra read is
  skipped for probes that are already confirmed in-band or not eligible, so
  `file` and `oob` add none.

Observing is additive throughout: the in-band verdict is computed exactly as
before and only a non-`confirmed` one can be upgraded, so a run without the flag
is byte-for-byte unchanged and a run with it can only gain findings.

## [2.31.0] — 2026-08-17

The `write` method: a write primitive proven to be RCE by executing what it
wrote. A whole family of targets was invisible — `tomcat/CVE-2017-12615` (PUT a
JSP), `activemq/CVE-2016-3088`, `weblogic/CVE-2018-2894` — because the vulnerable
request *stores a file* rather than evaluating anything. Nothing is computed in
its response, so `reflected` and `eval` correctly returned `negative` on targets
that are fully exploitable.

### Added

- **`--methods write`** — the inverse of `file`. `file` assumes execution exists
  and uses a write as proof of it; `write` assumes a write primitive exists and
  uses execution of the written file as proof of RCE. The probe is the file's
  *content*: a one-liner computing a product on random operands, delivered
  through the ordinary injection point.

  The fetched file is read in three tiers, and the middle one is the reason the
  method exists:

  | fetched file contains | verdict | means |
  |---|---|---|
  | the product | `confirmed` | written **and** executed |
  | the one-liner, verbatim | `needs-review` | arbitrary file write, not interpreted |
  | neither | `negative` | no write, or not served there |

  An upload directory that is served but not interpreted is a real finding and
  is not remote code execution, so the tiers are never merged.

- **`--write-url-template URL`** names where the stored file is served — the
  channel the proof comes back on, and the flag the method is gated on.

- **`--write-lang`** picks the file types: `auto` (default) reads the extension
  off the read-back URL, or name any of `jsp`, `jspx`, `php`, `aspx`, `erb`.
  `jsp`/`aspx`/`erb` share the `<%= %>` delimiters, so their probes are
  byte-identical and cost one request between them; with no extension to read,
  `auto` writes all five in three requests.

### Changed

- **A `needs-review` finding now prints its cleanup line too.** It used to
  appear only under `confirmed`, which was already thin and is wrong for this
  method: a `write` reaching `needs-review` means the file *is* on the target,
  just not interpreted, so the artifact would have been left there unmentioned.

- The write method's operands are drawn once per run rather than once per
  carrier, so the file is written once instead of once for each of the ~13
  `(environment, context)` carriers. For a state-changing method that is not a
  request-count saving, it is a blast radius. Still fresh per run, which is what
  makes the product unforgeable.

- The write method declines the break-out contexts (`sql`, `javascript`,
  `shell_*`, …) and keeps the transport ones. Its payload is a whole file body:
  there is nothing to break out of, and wrapping it in `'; … -- ` would write a
  broken file. A run narrowed past `raw` and the transport contexts is told so
  rather than reporting a clean negative.

## [2.30.0] — 2026-08-17

Per-dialect shell probes. `$((a+b))`, `sleep` and `$(echo TAG)` are POSIX
constructs: on a cmd.exe or PowerShell sink they are inert literal text. The
dialect was inferred from the corpus environment alone, so a run could send a
probe no shell on the target would ever execute — including on the carrier whose
context is literally named `powershell`.

### Added

- **`--sink-env auto|unix|windows|powershell`** states which shell runs the
  injected command. The computed-value core, the separators and the break-out
  contexts are all chosen from it. `auto` (the default) infers it per carrier;
  pin it when the corpus environment names the *application runtime* rather than
  the OS — `--environments php --sink-env windows` is a PHP application on IIS,
  which no inference can see.

- **A PowerShell probe shape for every shell method**, validated against
  pwsh 7.4: `Write-Output T1$(a*b)T2` for `reflected` (an unquoted argument is an
  expandable string, so the core carries no quote and the quote-wrapping
  contexts can still carry it), `Start-Sleep -Milliseconds N` for `time`,
  `Set-Content` for `file` and `iwr -useb` for `oob`. PowerShell was previously
  reachable by no probe in any method.

- **cmd.exe and PowerShell carriers for the `dotnet` environment.** It is the
  one corpus environment that names a platform, and it was taking the POSIX
  shape — so .NET on Windows, the case the environment exists for, was the case
  it could not confirm on. Every other runtime keeps the POSIX shape: a language
  does not say which OS it runs on.

### Fixed

- **The `powershell` carrier was written in cmd.exe.** Every `windows` carrier
  took the `for /f ... ('set /a a+b')` core regardless of context, so the one
  carrier explicitly shaped for PowerShell sent a payload PowerShell cannot
  execute. The dialect now follows the carrier's context first, and a carrier's
  break-out variants stay in its dialect rather than re-deriving from the
  environment.

- **`Set-Content`, not `>`, for the PowerShell write.** In Windows PowerShell
  5.1 the redirect is `Out-File`, whose default encoding is UTF-16LE: the write
  lands and the read-back still does not find the token, so the probe reports
  negative on a target it owns.

### Changed

- **cmd.exe no longer gets the `sq`, `dq` and `subshell` carriers.** It has
  neither a comment character to swallow the sink's tail nor a
  command-substitution syntax, so those four carriers per Windows run were
  requests that could only come back negative. PowerShell takes the quote
  break-outs and `$( )` — both measured — but not the backtick, which is its
  escape character rather than a substitution.

- **PowerShell's separator sweep carries no pipe.** `cmd | Start-Sleep
  -Milliseconds 500` is a parameter-binding error, not a fresh command with
  stdin attached the way a POSIX pipe is, and it fails that way for every cmdlet
  the probes use. `;`, a newline and (on PowerShell 7) `&&`/`||` remain.

- The pre-flight plan prints the sink shell alongside the sink shapes, and a
  pinned dialect narrows the printed ladder to the rungs it has syntax for.

## [2.29.0] — 2026-08-17

Generalised read-back for the `file` method. It required a writable **web root**
the tester already knew, which ruled out every other way a target can hand a
file back — on exactly the internal, no-egress targets the method exists for.

### Added

- **`--file-write-path DIR` + `--file-read-url URL`** name the two halves of the
  read-back channel directly, so an LFI endpoint, a download or export handler,
  an attachment fetcher or a `/tmp`-backed preview all work. The template takes
  `{name}` (the filename), `{path}` (the full server-side path) and `{path_enc}`
  (that path percent-encoded); only those three are substituted, so a URL that
  legitimately contains braces survives unchanged.

  Measured against a target with a download handler and nothing serving the
  write directory: the web-root form confirms **0** — reporting an exploitable
  target clean — and the general form confirms **7**.

### Fixed

- **The read-back fetch now carries the run's headers**, so an authenticated
  download, export, attachment or LFI handler can actually be read. It went out
  bare, which barely mattered while the channel had to be a web root — static
  file serving is rarely authenticated — and became the likely case the moment
  the channel could be an application endpoint. Measured against a handler
  behind a bearer token: the write executed on every probe and the verdict was
  `negative`, "token absent from the fetched file". Now 7 confirmations on the
  same target.
- **Credentials are carried only to the same origin.** A read-back URL on
  another host is someone else's server, and replaying the target's session
  cookie or bearer token to it would leak the credential, so those headers are
  dropped there while the rest still go — and the run says so, because the
  symptom would otherwise look like a clean target. `Content-Type` and
  `Content-Length` are dropped from the fetch too: they describe a body the GET
  does not have.

### Changed

- **`--webroot` / `--web-base-url` are now the web-root alias** for the general
  form: a web root is just the case where the read URL is the base plus the
  filename. Existing command lines are unaffected. Both are resolved in one
  place inside the method, so the alias and the general form cannot drift — and
  the gate, the pre-flight banner and the blind-sink advice all ask that same
  resolver instead of testing for the webroot pair.
- `blind_sink_advice` reads its flags defensively, so an args-like object
  missing a newer field costs a line of advice rather than a traceback.

## [2.28.0] — 2026-08-17

Injection-point enumeration. `-p NAME` needed the tester to already know which
parameter was the sink, so a capture's other candidates — including the headers
and nested JSON leaves that carry some of the highest-value classes — were never
tried.

### Added

- **`-p all` / `--auto-params KINDS`** expands one captured request into every
  candidate injection point and runs the selected `--methods` against each.
  Query values, JSON leaves addressed by path (`user.profile.name`, `tags[1]`),
  form fields, cookie crumbs and headers, each rewritten in **its own**
  serialization rather than blanket-encoded. Verified end to end: a sink
  reachable only through `User-Agent` is confirmed from `-r request.txt -p all`
  with no manual header selection.
- **`--point-order fast|thorough`** — `fast` tries a curated high-yield header
  list (the headers real published RCEs inject through); `thorough` adds every
  remaining non-hop-by-hop header. **`--max-points N`** bounds the run and
  reports what it dropped. **`--include-path-segments`** is opt-in, because
  rewriting a path segment usually just produces a 404.
- **The run states its cost before sending it** —
  `6 points x ~61 probes = at least 372 requests` — via a new
  `estimate_detection_probes`, which builds the probes and counts them without
  firing any. Enumeration multiplies an already-laddered probe count by the
  candidate count, and an operator on a monitored engagement has to see that
  before it happens rather than infer it from the traffic.
- **Findings name the point they came from**: `[reflected/unix/raw] at header
  'User-Agent' ...`.

### Changed

- **Each candidate carries its own payload-free control.** Differencing a header
  probe against a query probe's control would compare two different responses
  and prove nothing.
- **Cheap methods run first per candidate, and a candidate stops at its first
  confirmation.** `reflected` and `eval` cost one response each; `time` sleeps
  and `oob` waits for a callback, and on a candidate that has already proven
  execution those buy a second name for the same finding. Candidates that stay
  clean still get every method, and single-point runs are unchanged.
- A JSON leaf is **replaced, never created**. Assigning to a missing key would
  have injected into a field the application never sends — a probe that cannot
  say anything about the parameter that does exist. Caught by its own test.
- **JSON points are addressed by tokens, not by a joined path string.** A key may
  itself contain the separator: `{"user.name": ..., "user": {"name": ...}}`
  rendered *both* leaves as `user.name`, so the literal key was never probed and
  both candidates mutated the nested field — a false negative and a misattributed
  finding at once. Tokens remove the ambiguity, and the display form
  bracket-quotes such a key (`["user.name"]`) so the two stay distinguishable on
  screen.
- **A deeply nested captured body no longer ends `-p all` with a traceback.**
  `json.loads` recurses in C, so `RecursionError` joins the caught exceptions in
  both the enumerator and the placer, as it already had in the response-channel
  parser. The body yields no candidates; the rest of the request still enumerates.
- **The cost estimate honours `--max-payloads`.** It counted every probe the
  carriers could produce while the run stops at the cap, so the figure was wrong
  exactly when the operator had reached for the budget guard.
- `Host`, `Content-Length`, `Cookie` and the hop-by-hop headers are never
  candidates: injecting into those changes the request's plumbing rather than
  testing the application, and two of them are rebuilt by the delivery layer.

## [2.27.0] — 2026-08-17

Engine carriers for the `eval` probe. Three template engines evaluate the
injected expression perfectly and still made RCEKit report `negative`, because
what came back was not the bare product the oracle searches for.

### Added

- **`eval_carriers` in the corpus**, and `--eval-engines auto|<names>` to select
  them. A carrier wraps the same random-operand arithmetic in an engine-specific
  form; it never changes the oracle, and the bare probes still run first. Each
  entry records `notes` (why it exists) and `verified` (what it was measured
  against). Declarative, so a new carrier is a JSON entry rather than a code
  change.

  | Engine | Bare `${a*b}` returned | Carrier | Carrier returned |
  |---|---|---|---|
  | Freemarker | `2,070,761,401` (locale grouping) | `${(a*b)?c}` | `2070761401` |
  | Velocity | `${a*b}` verbatim — a *reference*, not an expression | `#set($rk=a*b)$rk` | `2070761401` |
  | Thymeleaf | `${a*b}` verbatim — needs inlining brackets | `[[${a*b}]]` | `2070761401` |

  Measured against freemarker 2.3.32, velocity-engine-core 2.3 and thymeleaf
  3.1.2, running RCEKit's own generated probes through each engine: bare form
  `CONFIRMS=no`, carrier `CONFIRMS=YES`, for all three.
- **The evidence line names the carrier** — `target computed '3979016' via the
  freemarker carrier` — so a finding says which engine quirk it worked around.
  A bare confirmation reads exactly as before.

### Notes

- **Carriers are not sandbox escapes, and no sandbox-escape carrier ships.** The
  premise that a sandboxed engine blocks the arithmetic probe did not survive
  measurement: a member-access sandbox restricts method and field access, and
  arithmetic needs neither. With OGNL member access denied for *everything*,
  `40277*51413` still returned `2070761401` while `@java.lang.Math@max(1,2)` was
  blocked; SpEL's restricted `SimpleEvaluationContext` and Jinja2's
  `SandboxedEnvironment` behaved the same way. The bare probes already cover
  those engines.
- The frequently-cited OGNL escape `(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)`
  additionally targets a field that **no longer exists in OGNL 3.3.4**, so on a
  current engine it is a probe that can only come back negative.

## [2.26.0] — 2026-08-16

The sink-shape ladder. An injected value lands in a *shape* — mid-command,
inside quotes, as the whole command — and the shape decides what can reach it.
Two shapes had no probe that fitted, so a genuinely exploitable target reported
clean.

### Added

- **`--sink-shape auto|sep|raw|chain|newline|dq|sq|subshell`** (comma-separated)
  names which shapes the shell probes try. `auto` is the whole ladder and the
  default. Underneath it selects the existing separator sweep and break-out
  contexts, so naming a rung narrows a supported run rather than switching on a
  parallel path. The plan is printed before anything is sent, because the ladder
  multiplies request count and an operator on a monitored engagement needs to
  see the cost first.
- **The `subshell` rung — `$(...)` and backticks.** Reaches a value sitting
  inside double quotes *without closing the quote*, which is the one case a
  quoted break-out loses to a filter on the quote character itself. Measured
  against `system("echo PING \"$input\"")`: with `"` stripped, `dq` is inert and
  both substitution forms execute; with `$` stripped, `dq` executes and the
  backtick form still does. Both ship because they survive different filters.

  **Which method it helps is the counter-intuitive part.** `reflected`'s core is
  `$((a+b))`, which the shell expands inside double quotes anyway, so that
  method already confirmed there. The methods whose core must actually *run* —
  `time` (a sleep), `file` (a redirect), `oob` (a fetch) — are completely inert
  inside those quotes. On a quote-filtering sink, `--methods file` went from **0
  confirmations to 2**: it had been reporting an exploitable target as clean.
- **The `raw` rung is now part of `auto`, for every shell method.** A
  `qx/$input/`-style sink, where the input is the whole command, previously
  needed `--sink-raw` — so it reported clean unless the operator already
  suspected the shape. One extra probe per carrier buys it. `--sink-raw` keeps
  its meaning as the narrowing alias for `--sink-shape raw`, and no existing
  command line changes behaviour. `reflected`, `file`, `time` and `oob` all
  build their candidates through one `_separator_candidates` helper, so a rung
  cannot reach some methods and not others; `time` screens it in its second
  wave, alongside the separators it holds back.

### Fixed

- **A method that builds no probes no longer reports `negative`.** An aggregate
  method asked to judge zero samples answers honestly — "no delay was observed",
  "no callback arrived" — and that reads as "not vulnerable" from a run that
  tested nothing. The engine now emits no row for a carrier that produced no
  probes, which lets its own loud nothing-tested path fire instead. Reachable
  through any narrowing that leaves a carrier with nothing to send.

### Changed

- **The pre-flight sink-shape plan is computed from the effective run**, not
  from the `--sink-shape` value. `--separators`, `--contexts` and `--sink-raw`
  each narrow the ladder, so printing the flag described a run that would not
  happen — and this output is presented as an audit of the traffic about to be
  sent. `effective_sink_shapes` is the single source of truth the engine and the
  plan both read.
- **The backtick context drops probe shapes that carry their own backtick.**
  Backticks do not nest, so such a probe closes the outer substitution early and
  could only ever come back negative. `$( )` does nest and keeps every shape.
- **Naming `--separators` now implies the sink is separator-led**, so the `raw`
  rung is dropped unless `--sink-shape` names it explicitly. A profile with
  `sink_needs_separator` drops it for the same reason. Both keep an explicitly
  narrowed run from being widened behind the operator's back.

## [2.25.0] — 2026-08-16

A coverage benchmark, so a claim about what RCEKit confirms can be checked
instead of asserted. The unit suite proves the tool reaches the right verdict
from a given response; it cannot prove it confirms Webmin.

### Added

- **`--detect-json PATH`** writes a detection run as JSON: the run's overall
  verdict, per-verdict counts, and every probe with its payload, method, context
  and evidence. Text output is unchanged. This is the supported way to consume a
  run programmatically — scraping stdout cannot be made reliable, because a
  probe payload may contain a literal newline (the newline separator is a real
  one, so line-oriented parsing splits a payload in half) and the detection path
  exits 0 whether it confirmed or came back clean.
- **`tests/bench/` — the coverage benchmark harness.** Each case brings a real
  vulnerable build up, runs RCEKit as an operator would, checks the verdict, and
  tears it down; `--markdown` emits the coverage table. Not part of
  `python -m unittest discover -s tests` — cases need Docker and pull real
  images — so it runs by hand or in a dedicated job, and exits non-zero if any
  case fails. Two cases ship, transcribed from `docs/verify-it-yourself.md`:
  Webmin CVE-2019-15107 and Struts2 S2-001.
- **A negative control is a required key.** A benchmark without controls measures
  nothing: a tool that shouted `confirmed` at every target would score full marks
  on the vulnerable half. Three kinds are supported — a patched build, the same
  target probed for the wrong class, and a weaker method that must stay below
  `confirmed` on a target where it happens to be right. The runner refuses four
  shapes of non-control: no control at all; one expecting `confirmed`; one that
  runs the identical invocation against an identical target (judged on what it
  would actually run, so an explicit copy of the vulnerable invocation is caught
  as well as an omitted one); and one expecting `error` or `nothing-tested`,
  since both mean the target was never exercised and such a control would stay
  green with the detection engine entirely broken. Validation and execution
  share one `control_plan` so they cannot drift.
- **`overall_detection_verdict`** collapses a run to one verdict, ordered by what
  an operator must not miss rather than by frequency: one `confirmed` among a
  hundred negatives is the finding. `error` is reported only when *nothing*
  reached the target, and a run that built no probes is `nothing-tested` —
  never `negative`, which would read as "not vulnerable".

### Changed

- `CONTRIBUTING.md` asks for a bench case alongside new detection coverage, and
  for the README table to state the tier the case actually reached.

### Notes

- The two shipped cases have **not yet been executed through the harness** — it
  was written where no Docker daemon was available. Their invocations come from
  a documented, reproduced guide, but the case files themselves are unvalidated;
  `tests/bench/README.md` says so and flags the one field that is a guess. No
  README claim was changed to assert benchmark results.

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

[Unreleased]: https://github.com/kabiri-labs/rcekit/compare/v2.32.0...HEAD
[2.32.0]: https://github.com/kabiri-labs/rcekit/compare/v2.31.0...v2.32.0
[2.31.0]: https://github.com/kabiri-labs/rcekit/compare/v2.30.0...v2.31.0
[2.30.0]: https://github.com/kabiri-labs/rcekit/compare/v2.29.0...v2.30.0
[2.29.0]: https://github.com/kabiri-labs/rcekit/compare/v2.28.0...v2.29.0
[2.28.0]: https://github.com/kabiri-labs/rcekit/compare/v2.27.0...v2.28.0
[2.27.0]: https://github.com/kabiri-labs/rcekit/compare/v2.26.0...v2.27.0
[2.26.0]: https://github.com/kabiri-labs/rcekit/compare/v2.25.0...v2.26.0
[2.25.0]: https://github.com/kabiri-labs/rcekit/compare/v2.24.0...v2.25.0
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
