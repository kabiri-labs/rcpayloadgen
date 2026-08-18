# RCEKit

**`confirmed` means the target executed the input. `negative` means the probes reached it.**

**Version 2.34.1** · MIT · Python 3.8+ · zero third-party dependencies

RCEKit is an **RCE detection &amp; confirmation toolkit** for authorised penetration
testing, red teaming and security research. Point it at a target you are allowed
to test — a URL or a captured HTTP request — and every finding comes back with
the tier it earned.

Every `confirmed` rests on a value RCEKit generated at random for that probe and
that reflection cannot produce: a computed result present in the response and
absent from a payload-free control, or an out-of-band callback carrying a token
only the target ever held. Weaker signals keep their own tiers and are never
promoted into it. And a run that could not test something never reports it as
clean.

---

## Proof, not "maybe"

RCEKit confirms RCE through **multiple methods** under one CLI. Below it is pointed
at **real, publicly-documented CVEs** in production software — each verdict
differenced against a payload-free control:

| RCE class | `--methods` | Real-world target | Verdict |
|---|---|---|---|
| OS command injection (results-based) | `reflected` | Webmin 1.910 — CVE-2019-15107 | **`confirmed`** |
| Expression injection (OGNL) | `eval` | Apache Struts2 — S2-001 | **`confirmed`** |
| Blind / out-of-band (Log4Shell/JNDI) | *OOB listener* | Log4Shell — CVE-2021-44228 | **`confirmed`** |
| Blind command injection (no output) | `time` | Webmin 1.910 — CVE-2019-15107 | `needs-review` |

<details open>
<summary><b><code>reflected</code> — OS command injection, Webmin CVE-2019-15107 → <code>confirmed</code></b></summary>

<br>

![RCEKit confirming OS command injection on Webmin 1.910 (CVE-2019-15107): the shell computes arithmetic on random operands, the result is reflected in the response and absent from a payload-free control](confirmation-gifs/reflected-webmin-cve-2019-15107.gif)

</details>

<details>
<summary><b><code>eval</code> — OGNL expression injection, Apache Struts2 S2-001 → <code>confirmed</code></b></summary>

<br>

![RCEKit confirming OGNL expression injection on Apache Struts2 (S2-001): the payload %{a*b} evaluates to the product in the response while the literal a*b does not](confirmation-gifs/eval-struts2-s2-001.gif)

</details>

<details>
<summary><b>out-of-band — blind Log4Shell (CVE-2021-44228) via a DNS callback → <code>confirmed</code></b></summary>

<br>

![RCEKit auto-confirming a blind Log4Shell RCE (CVE-2021-44228) via an OOB DNS callback, correlating the DNS hit back to the exact payload](confirmation-gifs/oob-log4shell-cve-2021-44228.gif)

</details>

<details>
<summary><b><code>time</code> — blind command injection, Webmin CVE-2019-15107 → <code>needs-review</code></b></summary>

<br>

![RCEKit measuring a linear timing response on Webmin 1.910 (CVE-2019-15107): response time tracks a controlled 0/N/2N delay series — a needs-review timing candidate, never confirmed on its own](confirmation-gifs/time-webmin-cve-2019-15107.gif)

</details>

---

## Quick start

```bash
git clone https://github.com/kabiri-labs/rcekit.git
cd rcekit                    # Python 3.8+, standard library only — nothing to install
```

Or take **just the one file** — the payload corpus is built in, so `rcekit.py`
runs on its own with nothing beside it. On a client jump box, an air-gapped host,
or anywhere `pip install` is not an option:

```bash
curl -O https://raw.githubusercontent.com/kabiri-labs/rcekit/main/rcekit.py
python rcekit.py --doctor    # confirms the corpus it will run with
```

Put a `FUZZ` marker where your input lands (or select a parameter with `-p` when
using a captured request), and ask RCEKit to prove RCE:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/lookup?host=FUZZ" \
  --methods reflected,eval
```

```
[detect] methods: reflected, eval
[detect] sent 13 probes: confirmed=4, negative=9

[detect] CONFIRMED execution (4):
  [reflected/unix/raw] ; echo RKYZRIP$((540141+314681))RKFWVFS$(echo RKBWOOC)RKYZRIP
      (target computed 'RKYZRIP854822RKFWVFSRKBWOOCRKYZRIP' — random operands, absent from control)
```

No external infrastructure, no config file.

**Don't take the GIFs on trust** — [reproduce them yourself](docs/verify-it-yourself.md)
against dockerised Webmin and Struts2 targets in about five minutes.

**Next:** the [**field guide**](docs/guide.md) walks the real situations — captured
requests, WAFs, filtered separators, quoted sinks, blind and no-egress targets —
one worked example each.

---

## What a verdict means

Finding an RCE *candidate* is easy. Reporting one that survives someone else's
retest is the hard part, and it fails in two directions: a "possibly vulnerable"
that turns out to be reflection, and a "not vulnerable" from a run that never
actually tested anything.

RCEKit answers with **seven verdicts that are never collapsed into each other**:

| Verdict | What it asserts |
|---|---|
| **`confirmed`** | The target executed the input. It returned a value it could not produce otherwise — computed from operands random to that probe — and that value is absent from a payload-free control. |
| **`deserialization-sink`** | The target reconstructed an attacker-supplied object graph. Proven, but about a *different property*: reaching RCE from there depends on classpath gadgets, so it is never called RCE. |
| **`needs-review`** | A real signal that is not proof on its own — a linear timing regression, a parser fingerprint. Worth your time, never worth the word "confirmed". |
| **`inconclusive`** | The evidence appeared, but could not be attributed to execution — the payload-free control carried it too. |
| **`negative`** | Probes were built, reached the target, and found nothing. |
| **`error`** | Nothing reached the target. |
| **`nothing-tested`** | No probes were built at all. |

The moment `confirmed` and `maybe` blur, `confirmed` stops meaning anything — so
nothing is ever promoted upward. A timing regression stays `needs-review` however
clean the slope. A deserialization callback stays `deserialization-sink` however
certain you are that the classpath is exploitable.

### The other half: a run that tested nothing is never clean

The last two rows are the ones other tools do not have, and they matter more than
they look. A scanner that could not reach the target, or built no probes because
your flags excluded every one of them, has learned **nothing** about the target —
and printing `negative` there is a lie that reads exactly like safety.

So `error` and `nothing-tested` are first-class verdicts, the run exits non-zero,
and RCEKit says which of them happened and why:

```
[!] No probes were built, so NOTHING WAS TESTED — this is not a negative result.
[!] None of the selected methods (reflected, file) apply to environment(s): sql.
```

It fires wherever a run can quietly become empty: a method that does not apply to
the selected environments, a `--sink-shape` rung the chosen shell has no syntax
for, a `--bridges` selection entirely held back by the safety ceiling, a request
body that broke delivery before it arrived.

A run that was only *partly* blinded gets the same treatment one level down. If
you asked for a second-order oracle and the observed endpoint never answered, the
probe verdicts still stand — but the run tells you they were decided without ever
reading the channel you pointed it at, rather than letting them pass for a
second-order negative.

---

## What it confirms

One CLI, one `--methods` flag, covering the main paths to RCE:

| RCE class | `--methods` | How RCEKit proves it |
|-----------|-------------|----------------------|
| **OS command injection** | `reflected` | Makes the shell compute `$((a+b))` on random operands and collapse `$(echo TAG)`; confirms the *result*, never the literal expression. Written in the sink's own dialect — POSIX, `cmd.exe` or PowerShell. |
| **Code / expression injection** — SSTI, SpEL, OGNL, Groovy, `eval()` (CWE-94) | `eval` | Injects `a*b` in every common template syntax (`${…}` `{{…}}` `#{…}` `%{…}` `<%=…%>` `@(…)`, bare); confirms the **product** appears while the literal `a*b` does not. |
| **Blind command injection** (no output) | `time` | Fires a controlled `0/N/2N` delay series and confirms the response time tracks the delay **linearly**; reported `needs-review` — jitter can't fake it, but timing isn't a computed value. |
| **Internal / no-egress** targets | `file` | Writes a random token and fetches it back through *any* read-back path — a web root, an LFI parameter, a download or export handler, a `/tmp`-backed preview. Proves execution **plus** a write primitive, with no external listener. |
| **Upload / write primitive** — PUT-a-JSP, unchecked upload (CWE-434) | `write` | Writes a one-liner that *computes* a product through your own upload request, then fetches the file: the product is `confirmed` RCE, the source coming back verbatim is `needs-review` — arbitrary file write, served but not interpreted. |
| **Deserialization sinks** — fastjson, shiro, weblogic (CWE-502) | `deser` | Proves the endpoint **deserializes** attacker data, via a non-executing DNS gadget or an error-shape differential. Reported as `deserialization-sink`, **never** as RCE. |
| **Blind / out-of-band** — Log4Shell/JNDI, exfil, async | *(OOB listener)* | Built-in HTTP/DNS listener receives callbacks and correlates each to the exact payload. |

Three things widen where those methods can reach, without changing what any of
them will call `confirmed`:

- **Second-order execution** (`--observe-url`) — when the payload lands on one
  request and runs on another: stored SSTI rendered on a profile page, a payload
  written to a log a template engine later renders, a queued job. The observed
  endpoint is differenced against a snapshot taken *before* any probe was sent.
- **Query-language bridges** (`--bridges`) — `COPY … FROM PROGRAM`,
  `xp_cmdshell`, `expect://`. A bridge is a carrier, not an oracle: it wraps the
  command the methods already build, so the same tiers apply through it.
- **Injection-point enumeration** (`-p all`) — query, JSON leaves, form fields,
  cookies, headers and path segments, each encoded for where it lands, with the
  probe cost printed before anything fires.

Mix methods freely: `--methods reflected,eval,time` runs all three and reports each
tier separately.

> **Honest scope.** RCEKit confirms RCE that is reachable by **injecting into a
> request** and interpreted by a shell or an evaluator. It does **not** cover
> memory-corruption bugs (buffer overflow, UAF) or argument injection into a
> no-shell `argv` array — those are different problems. **Deserialization gadget
> chains stay out of scope too**: `--methods deser` proves an endpoint
> *deserializes* attacker data and says so in its own tier, but which gadget (if
> any) turns that into execution depends on the target's classpath, and RCEKit
> does not claim to know. It aims to be excellent at the injection-driven RCE
> classes above rather than mediocre at everything.

---

## How RCEKit compares

The other tools in this space are built to get you **in**. RCEKit is built so the
finding **survives someone else's scrutiny** — the client's retest, the triage
queue, the report review. That difference shows up three times.

### 1. One injection point, every class, one run

You rarely know the class before you test. Covering an unknown sink with
single-class tools means running each in turn and rebuilding the request for each
one:

| Can confirm | RCEKit | [commix](https://github.com/commixproject/commix) | [SSTImap](https://github.com/vladko312/SSTImap) | [Nuclei](https://github.com/projectdiscovery/nuclei) |
|---|---|---|---|---|
| OS command injection | ✅ | ✅ *(its whole scope)* | — | per template |
| Expression injection / SSTI | ✅ | via its eval-based technique | ✅ *(its whole scope)* | per template |
| Blind — timing | ✅ *as a separate tier* | ✅ | ✅ | — |
| Blind — out-of-band | ✅ *built-in listener* | — | — | via [interactsh](https://github.com/projectdiscovery/interactsh) |
| No-egress — write &amp; fetch back | ✅ *any read-back path* | ✅ *(web root)* | — | — |
| `cmd.exe` and PowerShell sinks | ✅ *per-dialect probes* | ✅ *(cmd)* | — | per template |
| Upload → write-then-execute | ✅ *write vs. execute, separate tiers* | — | — | per template |
| Second-order — lands here, runs there | ✅ | — | — | — |
| Query-language bridge to the OS | ✅ | — | — | per template |
| Deserialization sink | ✅ *own tier, never called RCE* | — | — | per template |
| **All of the above, one CLI, one run** | **✅** | — | — | — |

<sub>Coverage per each project's own documented technique list. SSTImap is the
maintained successor to <a href="https://github.com/epinna/tplmap">tplmap</a>,
which its author has marked unmaintained.</sub>

```bash
# Command injection, expression injection and blind timing against the same
# parameter, in one pass, with zero infrastructure
python rcekit.py --acknowledge-consent -r request.txt -p host --methods reflected,eval,time
```

### 2. It argues with its own results

A tool reports what it found. RCEKit also reports **what it refused to believe** —
`inconclusive` is a verdict of its own, for evidence that showed up but could not
be attributed to execution:

```
[detect] methods: reflected, eval
[detect] sent 13 probes: confirmed=0, inconclusive=2, negative=11
```

Those two would have been someone else's finding. Five mechanisms produce that
verdict, and they run on every confirmation:

- **A payload-free control request.** Evidence must be present *with* the payload
  and absent *without* it. Anything in both is `inconclusive`, not a finding.
- **A same-token inert control.** A second request carries the identical random
  token in a non-executing form. A target that merely echoes input fails here —
  which is how a reflection is separated from an execution.
- **Random operands, never fixed strings.** The oracle is a tag-wrapped sum or a
  boundary-fenced product computed fresh each run. Echoing the payload returns
  the literal `$((a+b))`; only execution returns the value.
- **Encoding-aware evidence search.** A sink that base64-, hex-, URL-, HTML- or
  unicode-escapes its output still confirms — the raw body is checked first, so
  decoding only ever turns a missed hit into a hit, never the reverse.
- **Whole-response evidence search.** The computed value is looked for in every
  channel of the response — body, application headers, cookie values, the
  redirect target, the HTTP reason phrase, and each leaf of a JSON error
  envelope — and the finding names the channel that carried it. The control
  differential is applied to every channel too, so widening where RCEKit looks
  does not widen what it will call `confirmed`.

The same instinct runs the other way. Timing **never self-confirms**, a
deserialization callback is **never** called RCE, and a run that built no probes
is **never** called negative.

### 3. It is built for an authorised engagement, not a lab

The controls a client's rules of engagement actually ask about, in the tool
rather than in your notes:

| | |
|---|---|
| **Consent gate** | Nothing exploitative generates or fires without `--acknowledge-consent`. |
| **Execution plan** | Prints the exact probe count, sink shapes, safety tiers and any outbound callback destinations **before** the first request goes out. |
| **Safe by default** | Reverse shells, credential access, cloud metadata, lateral movement and container escape are held back until you raise `--verify-active-risk`; persistence and backdoors need a second flag on top. Bridges that create an object on the target are held to the same ceiling. |
| **Cleanup commands** | `file`, `write` and the stateful bridges change target state, so every finding — including a `needs-review` — prints what to run to undo it. |
| **Credentials stay put** | The `file` read-back fetch carries the run's `Authorization`/`Cookie` headers only to the *same origin*, and says so out loud when it withholds them. The observed-channel fetch sends none at all unless you hand it a request with `--observe-request`. |
| **Redacted audit trail** | Every run lands in `exploit_audit.log`, recording that a credential header was sent, never its value. |
| **Watermarking** | `--watermark` stamps a traceable token into each payload, so a payload found in the client's logs months later is attributable to your run. |
| **No third-party callbacks** | The OOB listener is yours. Nothing is routed through a public interaction server, which some engagements forbid outright. |
| **One stdlib file** | `rcekit.py` runs alone — jump box, air-gapped host, anywhere `pip install` is not an option. |

### When to reach for something else

Want a shell rather than a verdict? commix and SSTImap continue into
post-exploitation; RCEKit stops at proof by design. Sweeping thousands of hosts
for known CVEs? That is Nuclei's job — and RCEKit *writes* Nuclei templates
(`--output-format nuclei`), so it feeds your scanner instead of competing with it.
Already know the injection is SQL and want the database itself?
[sqlmap](https://github.com/sqlmapproject/sqlmap) owns that ground — RCEKit's
bridges exist to prove the **OS** is reachable from a text parameter, not to
exploit the database.

---

## Find your situation

Each row is a worked example in the [field guide](docs/guide.md) — the command,
what it sends, and how to read what comes back.

| Situation | Go to |
|---|---|
| I have a URL and a parameter | [Point at a URL](docs/guide.md#point-at-a-url) |
| I have a request saved from Burp | [Point at a captured request](docs/guide.md#point-at-a-captured-request) |
| The app is JSON / the payload keeps getting mangled | [Landing the payload intact](docs/guide.md#landing-the-payload-intact) |
| I don't know which class it is | [Choosing methods](docs/guide.md#choosing-methods) |
| The sink strips `;` | [When the sink filters separators](docs/guide.md#when-the-sink-filters-separators) |
| My input lands inside `'quotes'` | [Injecting inside quotes](docs/guide.md#injecting-inside-quotes) |
| The sink runs my input as the whole command | [Whole-command sinks](docs/guide.md#whole-command-sinks) |
| The target is Windows or the sink is PowerShell | [Windows and PowerShell sinks](docs/guide.md#windows-and-powershell-sinks) |
| There's a WAF | [Working around a WAF](docs/guide.md#working-around-a-waf) |
| No output comes back at all | [Blind targets](docs/guide.md#blind-targets) |
| No output *and* no egress | [No-egress targets](docs/guide.md#no-egress-targets) |
| The request stores a file instead of running anything | [Upload and write-primitive targets](docs/guide.md#upload-and-write-primitive-targets) |
| The payload runs later, on a different request | [When execution happens on another request](docs/guide.md#when-execution-happens-on-another-request) |
| The injection point is SQL and the sink is the database host | [Query-language bridges](docs/reference.md#query-language-bridges) |
| The endpoint takes a serialized object | [Deserialization sinks](docs/reference.md#deserialization-sinks-and-the-verdict-that-is-not-rce) |
| The sink is behind a login or a file upload | [Multi-step chains](docs/guide.md#multi-step-chains) |
| I got `needs-review` / `inconclusive` / `error` | [Reading the results](docs/guide.md#reading-the-results) |
| It says the corpus is unusable | [Troubleshooting](docs/guide.md#troubleshooting) |

---

## Documentation

| | |
|---|---|
| [**Verify it yourself**](docs/verify-it-yourself.md) | Reproduce the confirmations above on your own machine, against dockerised vulnerable targets. **Five minutes.** |
| [**Field guide**](docs/guide.md) | Example-driven walkthrough of every real situation, from a first probe to multi-step chains. **Start here.** |
| [**Payload generation &amp; exports**](docs/generation.md) | RCEKit as a payload generator: target profiles, and Burp / ffuf / Nuclei exports. |
| [**Reference**](docs/reference.md) | Every flag, environment, category, context, encoding and code-execution sink. |
| [**CHANGELOG.md**](CHANGELOG.md) | What changed in each release, and what to re-check when upgrading. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add sinks, categories, encodings and detection methods. |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability in RCEKit itself. |

---

## Safety &amp; ethics

- **Consent gate** — exploitation generation and verification require
  `--acknowledge-consent`; `--detection-only` is benign and does not.
- **Safe by default** — verification fires only low-impact proofs; reverse shells,
  download-execute, credential access, lateral movement, container escape,
  cloud-metadata and OOB payloads are held back until you raise
  `--verify-active-risk`. Destructive payloads (persistence, backdoors) are never
  fired without `--verify-allow-destructive`. An **execution plan** prints exactly
  what will be sent before anything fires.
- **Safety tiers** — `safe` / `intrusive` / `stateful`, filtered by `--max-safety`.
  A method or bridge that leaves something behind is held to the same ordering as
  every corpus payload, and the pre-flight names the tier each held-back item
  actually needs.
- **Audit &amp; logging** — every exploitation/verification run is recorded in
  `exploit_audit.log`; `--watermark` embeds a traceable token; execution logs go to
  `rcekit.log`.
- **Corpus integrity** — a corpus that is corrupt, or an explicit
  `--template-file` that is missing, makes RCEKit refuse to run and exit non-zero
  rather than silently generate nothing (`--doctor` checks it). Only an absent
  *default* corpus file falls back to the built-in copy, and it says so when it
  does.

This toolkit is intended for authorised penetration testing, security research,
education, and defensive training only. **Never use it against systems without
explicit permission** — unauthorized testing is illegal.

## Development

```bash
python -m unittest discover -s tests   # dependency-free test suite
```

Contributions welcome — new sinks/categories, encodings, environments, detection
methods, bug fixes, and docs. Payload bases live in editable JSON templates
(`templates/payloads.json`), so most coverage extends without touching the Python
source. After changing the corpus, refresh the built-in copy that ships inside
`rcekit.py`:

```bash
python tools/embed_corpus.py    # --check verifies it is current
```

The test suite fails if the two ever drift. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
