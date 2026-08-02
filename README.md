# RCEKit — prove RCE, don't guess it

**Version 2.21.0** · MIT · Python 3.8+ · zero third-party dependencies

RCEKit is an **RCE detection &amp; confirmation toolkit** for authorised penetration
testing, red teaming, and security research. Point it at a target you are allowed
to test — a URL or a captured HTTP request — and it tells you what **actually
executed**, backed by proof, not a "maybe".

A **`confirmed`** verdict means the target *computed or executed a value only
execution could produce* — random arithmetic, a template evaluation, a written
token — checked against a payload-free control. Reflection, coincidence, and
jitter can't fake it, so `confirmed` is something you can put in a report.

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

No external infrastructure, no config file. If nothing is vulnerable you get a
clean `negative`, not a false alarm. That's the whole idea.

**Next:** the [**field guide**](docs/guide.md) walks the real situations — captured
requests, WAFs, filtered separators, quoted sinks, blind and no-egress targets —
one worked example each.

---

## Why RCEKit

Finding an RCE *candidate* is easy. **Proving it** — reliably, without crying
wolf — is the hard part:

- Scanners flag "possibly vulnerable" and bury the real finding under false positives.
- Blind RCE usually forces you to stand up interactsh/Collaborator just to confirm.
- Each RCE class (command injection, SSTI, code injection) needs a different confirmation trick.
- A report full of "maybe" findings wastes triage time and burns your credibility.

RCEKit answers with **two verdict tiers that are never merged**:

| Tier | Meaning |
|------|---------|
| **`confirmed`** | Execution proven — the target returned a value it could only produce by executing your input, and that value is absent from a payload-free control. |
| **`needs-review`** | A real candidate worth a look (e.g. a blind timing signal), but not proof on its own. |

Anything else is `negative` or `inconclusive`. The moment "confirmed" and "maybe"
blur together, "confirmed" loses its meaning — so RCEKit keeps them apart, by design.

---

## How RCEKit compares

The tools below are good at what they do, and RCEKit does not replace them. The
difference is **where each one stops**:

| | What it's built for | RCE classes it covers | Infrastructure | Ends at |
|---|---|---|---|---|
| [**commix**](https://github.com/commixproject/commix) | exploiting OS command injection | OS command injection (classic, eval-based, time-based, file-based, shellshock) | none | an interactive shell |
| [**SSTImap**](https://github.com/vladko312/SSTImap) *(successor to the unmaintained [tplmap](https://github.com/epinna/tplmap))* | exploiting SSTI / code injection | SSTI + code injection, 30+ template engines | none | an interactive shell |
| [**Nuclei**](https://github.com/projectdiscovery/nuclei) | scanning at scale for *known* issues | whatever a template already exists for | [interactsh](https://github.com/projectdiscovery/interactsh) for OAST templates | a template match |
| **interactsh / Burp Collaborator** | providing an out-of-band channel | blind variants of any class | an external (or self-hosted) server | a callback |
| **RCEKit** | **proving execution across classes** | **command injection + SSTI/eval + blind + no-egress** | **none** | **a proof-backed verdict** |

**Use the other tool when:**

- **You want a shell.** commix and SSTImap take you from "vulnerable" to
  post-exploitation. RCEKit deliberately stops at proof and will never hand you a
  shell — that is a scope decision, not a missing feature.
- **You are sweeping thousands of hosts for known CVEs.** That is Nuclei's job.
  RCEKit is per-target — and it *exports* Nuclei templates
  (`--output-format nuclei`), so the two compose rather than compete.
- **You already run Burp Pro.** Then you already have Collaborator. RCEKit's
  built-in listener matters when you don't, or when the engagement forbids
  third-party OOB infrastructure.

**Use RCEKit when:**

- **You don't yet know the class.** One run of `--methods reflected,eval,time`
  covers command injection, expression injection and blind timing against the same
  injection point, instead of reaching for a different tool per hypothesis.
- **The finding has to survive triage.** Every confirmation is differenced against
  a payload-free control, and timing evidence is reported in its own
  `needs-review` tier — never merged into "vulnerable". commix pioneered
  randomised results-based heuristics for command injection; RCEKit carries that
  rigour across expression injection, blind and no-egress paths, and refuses to
  let a timing signal masquerade as proof.
- **There is no egress and no infrastructure to lean on.** The `file` method
  proves execution through a write-and-fetch on the target's own web root, with no
  listener at all — and the tool itself is one standard-library Python file you
  can copy onto a locked-down host.

---

## What it confirms

One CLI, one `--methods` flag, covering the main paths to RCE:

| RCE class | `--methods` | How RCEKit proves it |
|-----------|-------------|----------------------|
| **OS command injection** | `reflected` | Makes the shell compute `$((a+b))` on random operands and collapse `$(echo TAG)`; confirms the *result*, never the literal expression. |
| **Code / expression injection** — SSTI, SpEL, OGNL, Groovy, `eval()` (CWE-94) | `eval` | Injects `a*b` in every common template syntax (`${…}` `{{…}}` `#{…}` `%{…}` `<%=…%>` `@(…)`, bare); confirms the **product** appears while the literal `a*b` does not. |
| **Blind command injection** (no output) | `time` | Fires a controlled `0/N/2N` delay series and confirms the response time tracks the delay **linearly**; reported `needs-review` (jitter can't fake it, but timing isn't a computed value). |
| **Internal / no-egress** targets | `file` | Writes a random token to a web-reachable file and fetches it back — proving execution **plus** a write primitive, with no external listener. |
| **Blind / out-of-band** — Log4Shell/JNDI, exfil, async | *(OOB listener)* | Built-in HTTP/DNS listener receives callbacks and correlates each to the exact payload. |

Mix them freely: `--methods reflected,eval,time` runs all three and reports each
tier separately. If a combination builds no probes at all, RCEKit says so and
exits non-zero — a run that tested nothing is never reported as a clean result.

> **Honest scope.** RCEKit confirms RCE that is reachable by **injecting into a
> request** and interpreted by a shell or an evaluator. It does **not** cover
> memory-corruption bugs (buffer overflow, UAF), argument injection into a
> no-shell `argv` array, or confirm deserialization gadget chains beyond a timing
> signal — those are different problems. It aims to be excellent at the
> injection-driven RCE classes above rather than mediocre at everything.

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
| There's a WAF | [Working around a WAF](docs/guide.md#working-around-a-waf) |
| No output comes back at all | [Blind targets](docs/guide.md#blind-targets) |
| No output *and* no egress | [No-egress targets](docs/guide.md#no-egress-targets) |
| The sink is behind a login or a file upload | [Multi-step chains](docs/guide.md#multi-step-chains) |
| I got `needs-review` / `inconclusive` / `error` | [Reading the results](docs/guide.md#reading-the-results) |
| It says the corpus is unusable | [Troubleshooting](docs/guide.md#troubleshooting) |

---

## Documentation

| | |
|---|---|
| [**Field guide**](docs/guide.md) | Example-driven walkthrough of every real situation, from a first probe to multi-step chains. **Start here.** |
| [**Payload generation &amp; exports**](docs/generation.md) | RCEKit as a payload generator: target profiles, and Burp / ffuf / Nuclei exports. |
| [**Reference**](docs/reference.md) | Every flag, environment, category, context, encoding and code-execution sink. |
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
