# Reference

Every flag and every taxonomy, grouped by what you are trying to do. If you are
looking for *how to use these together*, the [field guide](guide.md) is the better
starting point — this page is for looking things up once you know what you want.

**Contents**

- [Choosing the target](#choosing-the-target)
- [Detection methods](#detection-methods)
- [Sink shape](#sink-shape)
- [The sink shell](#the-sink-shell)
- [Deserialization sinks](#deserialization-sinks-and-the-verdict-that-is-not-rce)
- [Query-language bridges](#query-language-bridges)
- [Second-order execution](#second-order-execution-the-observed-channel)
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
| `--verify-body-location` | How to encode `FUZZ` in the body: `json_string`, `form_value`, `xml_text`, `xml_attr`, `xml_cdata`, `multipart_filename`, `raw` | auto |
| `--verify-delay` | Seconds between verification requests (rate limiting) | `0` |
| `--verify-timeout` | Per-request timeout in seconds | `8` |
| `--insecure` | Drop every TLS assurance: no certificate or hostname check, and OpenSSL's security level and minimum protocol version lowered so a legacy stack still completes a handshake | Off |
| `--verify-chain` | JSON chain profile for multi-step, session-aware verification | None |

## Detection methods

| Option | Description | Default |
|---|---|---|
| `--methods` | Comma-separated: `reflected`, `eval`, `file`, `write`, `oob`, `lookup`, `time`, `deser`, `boolean` | None |
| `--file-write-path` | (`file`) server-side directory the target can write to, e.g. `/tmp` | None |
| `--file-read-url` | (`file`) URL template that reads it back: `{name}`, `{path}`, `{path_enc}` | None |
| `--webroot` | (`file`) web-root alias for `--file-write-path` | None |
| `--web-base-url` | (`file`) web-root alias for `--file-read-url '<base>/{name}'` | None |
| `--write-url-template` | (`write`) URL the file your request stores is served at; required for `write` | None |
| `--write-lang` | (`write`) File types to write: `auto`, or any of `jsp`, `jspx`, `php`, `aspx`, `erb` | `auto` |
| `--deser-formats` | (`deser`) Serialization ecosystems to probe: `auto`, or corpus names | `auto` |
| `--bridges` | Query-language bridges the command probes ride: `none` (default), `auto`, or corpus names | `none` |
| `--observe-url` | Second-order: endpoint polled for the computed value after the probes | None |
| `--observe-request` | Raw HTTP request for that endpoint instead of `--observe-url` (no marker) | None |
| `--observe-poll` | Seconds between polls of the observed endpoint | `5` |
| `--observe-timeout` | Stop polling after this many seconds; one poll always happens | `60` |
| `--oob-host` | (`oob`) host the **target** calls back to; required for `oob` | None |
| `--time-base` | (`time`) base delay `N`; the regression fires `0/N/2N` | `2.0` |
| `--separators` | Break-out separators for shell probes; `\n` = newline | `; `, `\| `, `\|\| `, `&& `, newline |
| `--evade` | How far a REFUSED probe may climb: `none`, `low` (`${IFS}`), `high` (also `ec$@ho`) | `high` |
| `--probe-depth` | `full` (also the substitution-free and comment-terminated shapes) or `quick` | `full` |
| `--confirm-depth` | Once a carrier confirms: `first` (stop that carrier) or `every` (map every shape it accepts) | `first` |
| `--detect-json` | Also write the run to this path as JSON: overall verdict, counts, every probe | None |
| `--sink-shape` | Sink shapes the shell probes try: `auto`, or any of `sep`, `raw`, `chain`, `newline`, `dq`, `sq`, `subshell` | `auto` |
| `--sink-env` | Shell that runs the injected command: `auto`, `unix`, `windows`, `powershell` | `auto` |
| `--eval-engines` | (`eval`) Engine carriers to add to the bare expression probes: `auto`, or names from `eval_carriers` | `auto` |
| `--auto-params` | (`-r` with `--methods`) Enumerate injection points: kinds from `query`, `json`, `form`, `multipart`, `cookie`, `header`, `path`, or `all`. Implied by `-p all` | off |
| `--point-order` | (enumeration) `fast` (curated high-yield headers) or `thorough` (every non-hop-by-hop header) | `fast` |
| `--max-points` | (enumeration) Stop after N candidates; the run reports how many it dropped | `40` |
| `--include-path-segments` | (enumeration) Also inject into URL path segments | off |

| `--methods` value | Confirms | Rung | Tier it can reach |
|---|---|---|---|
| `reflected` | OS command injection, via computed arithmetic | `safe` | `executed` |
| `eval` | SSTI / SpEL / OGNL / Groovy / raw `eval()`, via a computed product | `safe` | `executed` |
| `file` | Execution + a write primitive, via write-and-fetch | `stateful` † | `executed` |
| `write` | A write primitive proven to be RCE, by executing the written file | `stateful` † | `executed`, or `file-write` for a write that is served but not interpreted |
| `oob` | Blind execution, via a DNS/HTTP callback carrying a per-probe token | `intrusive` | `executed` |
| `lookup` | An **expression-lookup** sink (Log4Shell's shape): the sink resolves a `${jndi:…}` URI rather than running a command, and calls back carrying a per-probe token. Sends `dns://` at `intrusive`, and `ldap://` / `rmi://` as well at `stateful`. Needs a **name** for `--oob-host`; an address literal carries no token, so it builds nothing | `intrusive` | `lookup-sink` |
| `time` | Blind execution, via a `0/N/2N` regression | `safe` | `timing-sink` only — proven, and not execution |
| `deser` | That the endpoint **deserializes** attacker data — never RCE | `safe` | `deserialization-sink`, or `needs-review` for the shape fingerprint |
| `boolean` | A sink that **evaluates a predicate and renders nothing of it** (MongoDB `$where`, filter and rule expressions), via a response-shape differential across randomised true/false comparisons. The `OR` connectives need `stateful`; everything else is inert | `safe` | `evaluation-sink` only — proven, and not execution |

**Rung** is the `--verify-active-risk` tier a method needs. A method above the
run's tier is refused **by name** rather than skipped, because a run that
quietly tested nothing reads exactly like a clean target. Within a method, a
probe *shape* may need a higher rung than the method does -- `lookup` resolves a
name at `intrusive` and can also fetch from an address it did not choose at
`stateful` -- and the run reports how many shapes it held back and which flag
would send them.

† `file` and `write` change the target, and their own configuration is what
gates them: neither does anything until a directory to write into and a URL to
read it back from are named, which says more than a tier would. Running them
does not need the flag.

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

- **substitution-free** (`awk`) — both canonical probes route the
  arithmetic through `$((…))` or a backtick, so a sink that strips `$(` blocks
  them while remaining exploitable through a plain `;`. The `awk` shape carries
  double quotes, so it is not sent into a context that *wraps* the payload in
  them (`attribute`): the quote would close early and the probe could only ever
  come back negative. Break-out contexts such as `shell_double_quoted` close the
  sink's quote and comment its tail, so they still get it.
- **keyword-diverse** (`awk` again) — a filter on `echo`/`expr` blocks both
  canonical probes; `awk` is not on those blocklists. A bare `expr a + b` used
  to share both roles and was removed in 3.0.1: its expected value was the sum
  alone, which anything evaluating arithmetic satisfies, so it reported
  `executed` under `reflected`'s shell class against targets where no command
  ran. A sink filtering `$(`, backticks *and* `awk` is therefore out of
  `reflected`'s reach, and stays reachable through `time`, `oob` and `file`.
- **comment-terminated** (`… #`) — comments out whatever the application appends
  after the injection point. A trailing redirect or pipe (`ping <input> 2>/dev/null`,
  `<cmd> <input> | grep …`) otherwise swallows the probe's output, so the probe
  executes and still reads as negative.

`quick` sends only the canonical probes — roughly half the requests, for
rate-limited targets or when the sink's shape is already known.

**All of these shapes are Unix**, and `--probe-depth` therefore means something
different per [sink shell](#the-sink-shell):

- **cmd.exe** has no `#` comment, no `${IFS}` and no `awk`, so it gets the one
  `set /a` probe at either depth — `--probe-depth` changes nothing for it.
- **PowerShell** takes the comment terminator (`#` comments to end of line there
  too), and `full` adds a second shape that names no cmdlet at all — a bare
  expandable string, whose value PowerShell writes to the output stream — so a
  filter on `Write-Output`/`echo` does not silence the method.

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

### Deserialization sinks, and the verdict that is not RCE

Deserialization RCE (fastjson, shiro, weblogic, jenkins) cannot be confirmed by
the value-oracle model: the payload is a serialized object graph and gadget
selection is classpath-specific, so whether execution is reachable depends on
jars RCEKit cannot see. That stays out of scope. What is *in* scope is the
honest middle step — showing the endpoint parses the data at all, which is a
real finding and the prerequisite for every gadget chain.

`--methods deser` therefore **never emits `executed`**. Its strongest outcome
is its own verdict:

```
[detect] 1 DESERIALIZATION SINK(S) — NOT proof of execution:
  [deser/raw] rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...   (java: the target resolved
      rk7f2a91c3b8.oob.example, so it reconstructed an attacker-supplied object graph …)
  → the endpoint reconstructs attacker-supplied object graphs. Reaching RCE from
    here depends on gadgets in the target's classpath, which is outside what
    RCEKit confirms.
```

`deserialization-sink` sits below `executed` in the collapsed verdict: it is
*proven*, and `executed` stays reserved for execution.

It used to sit below `needs-review` too, on the argument that a suspected
RCE outranks a proven non-RCE in triage. That argument held while `time`,
`boolean` and `write`'s uninterpreted file all reported `needs-review`. Since
3.0.0 each of those has its own tier, and the one verdict left under
`needs-review` is this method's own shape fingerprint — a suspected
*deserialization*. So `deserialization-sink` now outranks it: the proof of a
thing outranks the guess at the same thing.

Two oracles, of deliberately different strength:

| Oracle | Needs | Reaches |
|---|---|---|
| **shape** | nothing | `needs-review` |
| **dns** | a delegated `--oob-host` name and a listener | `deserialization-sink` |

**shape** sends **four** payloads per ecosystem — a well-formed object stream,
the same stream truncated, and the format's magic bytes followed by random noise
of the same length, that last one sent **twice** so it brackets the pair — and
asks whether the endpoint answers the well-formed one differently from *both*
others. A parser does; a parameter that is merely stored treats all of them as
opaque text. With the five ecosystems the corpus ships that is **20 requests per
carrier**, not 15; `--deser-formats` narrows it.

The two noise payloads are one body sent twice, byte for byte, and they bracket
the pair because the differential is read *across* requests: anything that
changes with the request index rather than with the payload — a rate limiter
backing off, a filling log — lands on whichever form goes last. An endpoint that
answers the same probe two different ways did not hold still, and that carrier is
reported `inconclusive` rather than read. A response carrying the probe back is
`inconclusive` for the same reason, decided against the payload-free control so
that page content merely containing a format's magic is not mistaken for it. The
magic is looked for as the transport context sent it — escaped for JSON, XML,
YAML or GraphQL where that applies — and through base64, hex, URL and HTML
wrappings, so an endpoint that hands the probe back inside its own encoding is
still read as an echo.

Response signatures drop long digit and hex runs, so request ids and timestamps
on an otherwise identical error page do not make every endpoint look like a
parser. It is a fingerprint, not proof, and it never gets promoted.

**dns** sends a gadget whose only side effect is a name lookup. For Java that is
URLDNS — a `HashMap` holding one `java.net.URL`, where `HashMap.readObject`
hashes the key, `URL.hashCode` asks for the host address and the JVM resolves the
name. It references no class outside `java.util`/`java.net`, so there is nothing
in it that can run. For polymorphic JSON it is a `java.net.Inet4Address`
autotype. A callback proves the object graph was reconstructed — and only that.

The Java stream is built in Python rather than declared in the corpus because
the URL host is length-prefixed *inside* the stream and changes per probe, so
there is no static string to declare. Its constant parts are the exact bytes
OpenJDK's own `ObjectOutputStream` produces for that graph, and the generated
stream was verified against OpenJDK 21: it deserializes to
`HashMap{http://<host>/=rk}` and issues a DNS query for `<host>`, with no code
execution.

Ecosystems ship in the corpus (`deser_probes`): `java`, `php`, `dotnet`,
`python_pickle`, `fastjson`. Only `java` and `fastjson` have a non-executing DNS
gadget — PHP and .NET chains all run through magic methods or type confusion, so
there is no honest DNS-only probe for them and the shape oracle is all they get.

### Query-language bridges

Several RCEs pass through a query language before reaching the OS: Postgres
`COPY … FROM PROGRAM`, MSSQL `xp_cmdshell`, XXE `expect://`. A bridge is a
**carrier, not an oracle** — it wraps the command the methods already build, so
`reflected`, `time` and `oob` prove execution through it and inherit every tier
guarantee rather than re-deriving one.

| Bridge | Shell it reaches | Safety | Needs |
|---|---|---|---|
| `postgres_copy_program` | `/bin/sh` | `stateful` | superuser, or a role in `pg_execute_server_program` |
| `mssql_xp_cmdshell` | `cmd.exe` | `intrusive` | sysadmin, and `xp_cmdshell` enabled |
| `xxe_expect` | `/bin/sh` | `intrusive` | PHP with the `expect` extension, external entities enabled |

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target/search?name=FUZZ" --contexts sql \
  --methods time,oob --bridges auto \
  --verify-active-risk stateful --oob-host oob.example
```

**Off by default**, and that is design rather than caution: a bridge payload is
SQL or XML syntax, so on an ordinary shell sink it is a request that cannot
confirm.

Three things follow from bridges being carriers:

- **A bridge only ever gets a core written in its own dialect.** `xp_cmdshell`
  hands its argument to `cmd.exe`, so it takes the cmd core; `COPY FROM PROGRAM`
  takes the POSIX one. Pairing them the other way sends an inert `$((a+b))` into
  `cmd.exe` — the exact failure the [sink shell](#the-sink-shell) split exists to
  stop.
- **No separator.** Inside `COPY … FROM PROGRAM '…'` there is no running command
  to break out of, so the bare core is the probe. The record's *context* still
  applies, which is what makes `--contexts sql` and a bridge compose rather than
  each reinventing the other.
- **The safety ordering governs them** exactly as it governs every corpus
  payload. A `stateful` bridge creates an object and needs
  `--verify-active-risk stateful`; the pre-flight names the tier each held-back
  bridge actually requires, and every finding through a stateful bridge carries
  the statement that removes what it made — including on the `time` method,
  whose one result covers a whole probe series.

**Which oracle to reach for.** `reflected` needs the program's *output* to reach
the response, and a statement injected alongside the application's own query
returns through a cursor the application never reads — so it ships (one request,
and some drivers do return the last result set) but it is the weakest of the
three. `time` and `oob` work with nothing rendered: `COPY FROM PROGRAM` and
`xp_cmdshell` both block until the program exits, and a callback is made by the
target itself.

**Not built, deliberately.** MySQL UDF execution is a multi-stage chain — write a
shared object into the plugin directory, then `CREATE FUNCTION` — not something a
single probe can carry, so there is no stub for it. MongoDB `$where` is a
boolean-only channel (its JS sandbox cannot reach a shell), so it needs a
different oracle rather than this one — which is what [`--methods boolean`](#when-the-sink-answers-yes-or-no-and-nothing-else) is;
`mongo-express/CVE-2019-10758` is a plain JS `eval` sink that `--methods eval`
already covers.

### When the sink answers yes or no and nothing else

Some sinks evaluate an expression and render none of it. MongoDB `$where` is the
canonical one: a JS sandbox with no shell, no egress and no value in the
response — only a document set that a predicate narrows. Every other oracle in
this tool is structurally blind to that. `reflected` and `eval` need the computed
value rendered; `time` needs a sleep; `oob` needs egress. Measured against
exactly that sink:

```
[detect] methods: reflected, eval, time
[detect] sent 2883 probes (2426 result(s)): negative=2426
```

2883 requests and a clean negative on a target that evaluates whatever it is
handed. `--methods boolean` reads the one channel that is left — whether the
*shape* of the response changed:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url 'https://target.example/search?q=FUZZ' --methods boolean
```

**It is reported `evaluation-sink` and it will never reach `executed`.** Not because
the signal is weak — it is the strongest weak signal in the tool — but because of
what it cannot distinguish. Against a sandboxed `eval` sink and against a plain
SQLite comparison, this oracle produced an identical clean differential in 40
runs each. A query engine comparing two numbers is not remote code execution, and
nothing in the response says which of the two answered. Extracting a locally
computed product bit by bit through the channel does not fix that either: it
recovers the product through both sinks alike, for about 80 requests and a string
function a sandbox may well deny.

**The naive form of this oracle is unusable**, which is why none of it is naive.
Sending `1==1` against `1==2` and calling a changed response a finding reported
"vulnerable" in 40 of 40 runs against a target that only *reflected* its input,
and in 32 of 40 against one whose response merely wobbled. Four guards, each one
a measured false-finding rate rather than a precaution:

| Guard | What it removes | Measured without it |
|---|---|---|
| Compare response **structure**, not the body or its length | A reflected payload changes the text between tags, and the text between tags is what the signature throws away | A length-based signature claimed a differential in 13 of 25 runs against a reflect-only target; comparing raw bodies was unusable outright, reading `unstable` in 25 of 25 runs against a target that *was* vulnerable |
| Several **independently randomised** true/false pairs | A response that varies on its own | One pair claimed a differential in 46 of 200 runs against a noisy target; two claimed none in 200 |
| **Randomised firing order** | A target that never reads the payload but degrades part-way through the run — a rate limiter, a filling log | An ordered true-then-false series claimed a differential in 100 runs of 100 |
| An **anchor before and after** the series, each a *different* true predicate | The same, structurally rather than probabilistically | Shuffling alone still left 2 in 100, which is just the chance a shuffle lands separable. Repeating one anchor payload instead of varying it is worse than weakening the guard — a cache keyed on the query string replays the opening answer, and the check measures the cache: 36 catches in 39 runs live, **0 in 39** behind a cache |

With every guard on, a genuinely evaluating target still read as a differential
in 100 runs of 100 — the guards cost nothing they were not meant to cost.

**A channel it cannot read is `inconclusive`, never `negative`.** If the same
probe draws two different shapes, or the shape moves while the series is being
fired, the run says so. `negative` asserts the probes reached the target and
found nothing; here they reached it and no answer could be read out of them,
which is the same false clean `blocked` and `nothing-tested` exist to prevent.

**`AND` is safe, `OR` is not, and both are needed.** The probe breaks out of a
condition the application already wrote, and the connective is this method's
equivalent of a command separator:

| Connective | Differentiates when | Rung |
|---|---|---|
| bare (the value *is* the predicate) | the sink takes the whole value | `safe` |
| `&&`, `and` | the application's own predicate is **true** | `safe` |
| `\|\|`, `or` | the application's own predicate is **false** | `stateful` |

They are complements, not alternatives — dropping `OR` is a blind spot and not a
saving. It is held at the top rung because a true predicate `OR`-ed into a
`DELETE … WHERE` took a table from 3 rows to 0, where the same predicate `AND`-ed
into it left all 3. The run names every shape it held back and the flag that
sends it, so this is a decision the operator makes rather than one made for them.

**Cost.** One series per *context*, not per carrier — a predicate carries no
shell dialect, so the same context under `unix` and under `windows` would be the
same bytes asking the same question. At `--probe-depth full` that is 27 requests
per context and at `quick` it is 15; `quick` halves the pairs and never goes
below two, because one pair is the rung the measurement rejected. During
injection-point enumeration it runs in the second execution wave, with `time` and
for the same reason: none of its probes means anything on its own, so it is worth
paying for once the cheap results-based methods have found nothing.

**What it is not offered.** Contexts that carry the injected value as *code*
rather than as a value — `sql`, `javascript`, `php`, the shell break-out
contexts, and the three shell dialects where the value simply is the command —
are skipped. A bare comparison has no observable effect in any of them, so the
probe would be spent asking nothing; the break-out this method needs is the
connective above, which it supplies itself. Contexts that *wrap* the value stay
on the predicate side however elaborate their delimiters are, `xml_cdata` and
`yaml` included.

**A known limit, against a JSON API that emits a byte-order mark.** The oracle
compares what a response *is*, and it reads a JSON body by its keys, nesting and
list lengths — every scalar dropped, so a request id or a timestamp cannot make
two identical answers look different. `json.loads` rejects a leading U+FEFF
outright, so a marked response takes the fallback reading instead: one marker
per whitespace-separated word, per line. A differential can still appear there,
but in a word count rather than in a key structure, which is the weaker of the
two guards. Against such a target `boolean`'s resistance to a false
`evaluation-sink` is lower than it is against the same API without the mark.

The mark is stripped on the **request** side, everywhere RCEKit decides what a
body is. It is deliberately not stripped on the response side, because this
reading is the input to a detection method's verdict and that is not a change
this project settles on a fixture — and `boolean` is the one method with no
bench case, so there is nothing live to validate it against. The same mark also
costs a marked JSON response its per-leaf channels; what that does and does not
cost a confirmation is in `RCEKit._json_leaf_channels`.

### When a filter answers instead of the target

A run whose payloads are refused has learned nothing about the sink. Measured
against a real command injection sitting behind a filter that 403s a space or a
separator, RCEKit used to report:

```
[detect] sent 10 probes (10 result(s)): negative=10
[detect] No execution proven. The target may be patched...
```

`negative` asserts that the probes **reached** the target. They reached a
filter. That is the same false clean `nothing-tested` exists to prevent, one
level further in — so a refused probe gets its own verdict:

```
[detect] sent 10 probes (10 result(s)): blocked=10
[detect] 10 of 10 probe(s) WERE REFUSED BY A FILTER (HTTP 403 x10) — the
         payload-free control got through and these did not, so what was
         rejected is the payload and the sink never saw it.
[detect] Nothing was put in front of the sink, so this run says nothing about
         whether the target is vulnerable.
```

### Climbing only where something was refused

A refused probe is retried up the evasion rungs before anything is concluded
from it — the filter answered, so the sink has not had its say yet. Only a
refused one, which is the whole design:

| | measured |
|---|---|
| a rung applied to **every** probe | broke 8 probe shapes the canonical form executes, improved none |
| a rung applied to a **refused** probe | turned 1 confirmation into 5 against a whitespace filter |
| an unfiltered target | zero retries, zero extra requests |

So `--evade` is a **ceiling**, not a posture. Every probe goes out canonical;
`low` removes whitespace (`${IFS}`), `high` also splits the command word
(`ec$@ho`) for the other measured class of filter — the one matching command
names — and `none` never retries. The run says how many retries it made and
which rung got through, because extra traffic the operator did not ask for has
to be visible.

Cost is bounded by construction: at most one request per rung per refused
probe. A shape whose command uses a redirect is never retried, because `${IFS}`
around `>` yields an ambiguous redirect.

**The substitution stops at a quote.** It used to not, and that was the whole
of the 8 lost shapes: `awk 'BEGIN{print "RK" a+b "RK"}'` became
`awk${IFS}'BEGIN{print${IFS}"RK"...`, where `${IFS}` is literal text rather
than an expansion and awk answers with a syntax error. Double quotes are left
alone from the other side — `${IFS}` *does* expand inside them, so substituting
there would change the string the target computes rather than the spacing
around it.

**The signal is differential**, like everything else this tool decides: the
payload-free control got through and the probe did not, so what was refused is
the payload. An endpoint that answers 403 to everything — an auth wall, a path
that does not exist for this session — refuses the control too and is not
mistaken for a WAF.

4xx only. A 5xx is as likely to be the payload *breaking* the application,
which means it reached something, and reading that as blocked would hide the
one response saying the sink is live. There is no vendor list and no block-page
fingerprint: a status the control did not get is the whole signal.

A run where **some** probes got through stays a real `negative` — the sink saw
those and did nothing — and the refusals are still reported, because a ladder
that shrinks quietly is indistinguishable from a target with nothing to find.

### Second-order execution: the observed channel

Execution frequently happens on a **different request** than injection — stored
SSTI rendered on a profile page, a payload written to a log a template engine
later renders, a queued job run asynchronously. The engine diffs the response it
injected into, so every one of those reads `negative` however exploitable the
target is.

**A run that finds nothing says so.** Against a target that stores on one
endpoint and renders through a shell on another, every method is `negative` —
including `time`, `oob`, `lookup` and `file`, because the execution does not
happen on the request being measured. So a run with no confirmation names this
flag, and unlike the blind-sink list it is not gated on which methods have
already run: no method rules out *the execution happens elsewhere*, and the
operator who has tried the expensive ones is the one with nothing else left to
hear.

The wording follows what the run **observed**, which is recorded rather than
guessed:

| What came back | What the run says |
|---|---|
| the input, verbatim | the target reflects and does not execute; if that value is rendered elsewhere, the execution would show there |
| none of the input | the target accepted it and returned nothing, so this response cannot show what became of it |
| not observed | only aggregate methods ran, so the run claims neither |

A swallowed input is equally a blind sink or a stored one — `ping <input>
>/dev/null` returns nothing either — so both possibilities are named and neither
is picked.

`--observe-url` names the endpoint where the execution surfaces:

```bash
python rcekit.py --acknowledge-consent \
  --verify-url "https://target/bio?bio=FUZZ" --methods eval \
  --observe-url "https://target/profile/42"

# ...or a captured request, when that page needs a session
python rcekit.py --acknowledge-consent \
  --verify-url "https://target/bio?bio=FUZZ" --methods eval \
  --observe-request profile.txt --observe-poll 10 --observe-timeout 120
```

**It is still fully differential**, which is why it can legitimately reach
`executed` rather than a weaker tier:

- the value was computed by RCEKit from operands random to this probe;
- it is absent from a snapshot of that endpoint taken **before any probe was
  sent** — after would already contain what the control is meant to rule out;
- and a probe's value is looked for there **only when the probe's own payload
  does not contain it**.

That last rule is the one that matters. `file` and `oob` expect a random *token*
that sits verbatim in the payload, so a target that merely stores the payload
and renders it back would hand that token straight to the observed page and every
such probe would confirm without executing anything. The computed-value methods
are safe for the opposite reason — reflection returns `$((a+b))`, never the sum —
so the rule selects them without naming them, and a method added later inherits
the right answer.

The channel is read **twice**, because the two real shapes need different
things:

| Store shape | Example | Read by |
|---|---|---|
| overwrite | a profile field, a single setting | one read after **each** probe |
| append / async | a log, a comment list, a queued job | the polling loop after the batch |

Without the per-probe read, an overwriting store keeps only the last probe by the
time a batch poll runs, so the oracle would confirm nothing on the shape it most
exists for. The cost is one extra request per probe — and only for probes that
are eligible at all and not already confirmed in-band, so `file` and `oob` add
nothing.

Observing is **additive**: the in-band verdict is computed exactly as before and
only a non-`executed` one can be upgraded, so a run without the flag is
unchanged and a run with it can only gain findings. Each probe's result carries
an `observe_status` in `--detect-json` — `executed`, `polled` (read, value not
there), `in-control`, `not-observed` (not eligible) or `unreachable`. If the
endpoint never answered, the run says so outright: negatives decided without ever
reading the observed channel are not second-order negatives.

### Write-then-execute: proving a write primitive is RCE

`--methods write` is the **inverse** of `file`, and it covers a class the others
are structurally blind to. `file` assumes execution exists and uses a write as
proof of it. `write` assumes a **write primitive** exists — the vulnerable
request *stores* a file rather than evaluating anything — and uses execution of
the written file as proof of RCE. `tomcat/CVE-2017-12615` (PUT a JSP),
`activemq/CVE-2016-3088` and `weblogic/CVE-2018-2894` are all in this family.
Nothing in the vulnerable response is computed, so `reflected` and `eval`
correctly return `negative` on a target that is fully exploitable.

The probe is the file's *content*: a one-liner that computes a product on random
operands, delivered through the ordinary injection point. RCEKit then fetches the
file and reads the answer in three tiers:

| The fetched file contains | Verdict | Means |
|---|---|---|
| the product | `executed` | the file was written **and** executed |
| the one-liner, verbatim | `file-write` | arbitrary file write; the directory is served but not interpreted |
| neither | `negative` | no write, or the file is not served at that URL |

The middle row is the reason the method exists, and it is never merged into
either neighbour: an upload directory that is served but not interpreted is a
real finding and is not remote code execution.

```bash
# Your own request writes the file; --write-url-template says where it lands
python rcekit.py --acknowledge-consent \
  -r put-jsp.txt --methods write \
  --write-url-template "https://target/uploads/rcekit-probe.jsp"
```

**The filename is yours, not RCEKit's.** Delivery substitutes one injection
point, and every target in this class needs two locations — the name in the
request line or a form field, the content in the body — so RCEKit writes the
content into whatever file your own request already names. That also means one
artifact per run rather than one per probe, which is the right trade for a
method that changes target state.

`--write-lang` picks the file types; `auto` reads the extension off the read-back
URL. `jsp`, `aspx` and `erb` share the `<%= %>` delimiters, so their probes are
byte-identical and cost one request between them; `php` is `<?= ?>`; `jspx` is
XML (`<jsp:expression>`) because a `.jspx` container parses the file as a
document and never sees scriptlet delimiters. With no extension to read, `auto`
writes all five — three requests.

The content carries **no whitespace** — `<?=a*b?>`, not `<?= a*b ?>` — because
the injection point is yours and some of them tokenise before they write.
RRDtool is the case that settled it: reached through Cacti's `right_axis_label`,
it builds the file from a `LINE1:out:<content>` argument, writes the spaceless
form whole, and rejects the spaced one outright with
`ERROR: 'a*b' is not a valid function name`. Whitespace inside those delimiters
is optional, so nothing is given up. `jspx` is the exception: it is an XML
document whose root element carries namespace attributes, and a sink that splits
on spaces was never going to carry one.

Like `file`, this method changes target state, so it stays gated on the read-back
URL being named, prints what it is about to do first, and attaches a cleanup line
to **both** the `executed` and the `file-write` tiers — a `file-write` here
means the file is on the target, just not interpreted.

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
| `xml` | path — `soap:Body/getUser/name`, `getUser/@id`, `note/cdata()` | the document spliced at the value's offsets, XML-escaped for its position |
| `form` | field name | the `a=1&b=2` encoder |
| `multipart` | part name from `Content-Disposition` | the part's own body, re-serialised with CRLF delimiters |
| `filename` | the field whose part declares it | the `filename="…"` parameter in the part *header*, quoted-string escaped |
| `cookie` | crumb name | the `Cookie` header, other crumbs untouched |
| `header` | header name | single-line header escaping |
| `path` | segment index | the URL path (opt-in, see below) |

A JSON leaf is only *replaced*, never created: assigning to a missing key would
test a field the application never sends.

A **byte-order mark** on either a JSON or an XML body is tolerated, at the branch
and at the parse alike — `str.strip()` leaves U+FEFF in place and `json.loads`
rejects it outright, so a marked capture used to yield no body point at all. The
mark is removed *and then* whitespace, so `U+FEFF` followed by a newline is read
as the JSON or XML it is.

Because the JSON path re-serialises, the mark is put back on the body that goes
to the target: the capture carried it and the application accepted it, and the
payload-free control is rendered the same way, so probe and control still differ
in the field under test and in nothing else.

On a **form** body the mark lands in front of the first key, where it is an
encoding artefact and not part of the field name. The point is named without it,
so a finding does not print an invisible character and `-p NAME` addresses what
you can read — and the key still goes on the wire exactly as captured, because
the application's own parser sees the mark too.

A **multipart** body is recognised from `Content-Type`, and each part is a
candidate — including a file part, whose content is the value under test while
its `Content-Type` stays as captured. The body is re-serialised
with the CRLF delimiters RFC 2046 requires, which a capture loses: `-r` reads
the whole request with its line endings normalised. Part *content* is left
character for character, so a lone newline inside an uploaded text file
survives. The payload-free control is rendered the same way, so it differs from
the probe in the field under test and in nothing else.

A **filename** point is the inverse of that, and the two are separate kinds
because they are separate values: the content is what an upload *contains*, and
the filename is what the application is told it is called. The second is where a
traversal, a double extension, or a name a converter shells out with has to go,
and those are the routes from an upload to execution. Only parts that declare a
`filename` are candidates — a part without one is an ordinary form field — and
each is addressed by part index and verified by its field name, exactly as the
content points are. The part header is rewritten and the content left alone;
every other parameter, every other header and every byte outside the quotes stay
as captured, because a parser on the far side reads them too.

Three characters cannot reach a part header as themselves, and the reasons
differ. The quote and the backslash are syntax: RFC 7578's quoted-string form
needs them escaped or the name is truncated at the payload's own quote, and the
backslash is escaped first so it does not escape the escape the quote just
gained. **CR and LF are replaced with a space, and that is a safety decision
rather than a syntactic one** — a newline in a part header does not corrupt the
request, it *forges a new part*, which is a different vulnerability and one no
notice afterwards can undo. A payload that needs a newline there is testing
header injection, not a filename sink. A traversal or a double extension
contains none of the three and goes on the wire unchanged.

`Content-Disposition` parameter order is free, and both spellings are read:
`name="f"; filename="a.txt"` and `filename="a.txt"; name="f"` resolve to the same
field. Unquoted parameters are not read, as before — RFC 7578 requires the
quotes and every library that writes a multipart body emits them.

An **XML or SOAP** body is recognised from its first character, byte-order mark
and all, and every element's character data, every attribute value and every
CDATA section is a candidate. A repeated sibling is indexed from the second
occurrence — `items/item`, `items/item[2]` — so the later ones are reachable
rather than counted as covered; `xmlns` declarations are not candidates, because
a payload in a namespace URI renames the element instead of reaching anything
that reads its value.

An element with no element children is a candidate **even when it is empty or
holds only whitespace**: `<cmd></cmd>` and `<cmd>   </cmd>` are the ordinary
shape of a field in a SOAP template, and a JSON `""` leaf and a form `key=` are
candidates already. Whitespace between two *elements* is still formatting and
yields nothing — the test is whether the element had an element child, not
whether its text is blank, because the blank test answers the same for a
placeholder field and for the indentation of a pretty-printed envelope. A
self-closing `<cmd/>` is not a candidate, for the reason a missing JSON key is
not: it has no text node, so rewriting it would test a shape the application
never sends.

The document is **spliced at the value's offsets**, never parsed and re-emitted.
Two reasons, and the second is the one that decided it. A signed envelope
(WS-Security / XML-DSig) covers its own bytes with a digest, and parse-then-emit
loses attribute order, insignificant whitespace and the prolog's quoting style —
none of which XML requires preserved and all of which the digest covers. And a
capture aimed at an **XXE** sink carries a DOCTYPE with an external entity,
because that is exactly what the operator is trying to prove the *target*
resolves; a real parser would resolve it here instead, turning the tool into the
thing it is testing for. A scanner interprets no entity, so there is nothing to
resolve and no retrieval to disable.

A signed body is therefore not probed at all, and the run says so rather than
reporting zero points: every probe would come back refused for a reason that has
nothing to do with the sink, which reads exactly like a filter. Capture the
request before it is signed, or name a point outside the body.

"Signed" means a `Signature` element **in** the XML-DSig namespace, and both
halves are required. The namespace URI on its own appears wherever a schema
predeclares the prefix without signing anything, and an element named
`Signature` is ordinary in plenty of schemas — so either test alone would
suppress every point in a document that is perfectly testable. Comments and
CDATA sections do not count either way: a tag or a declaration written inside
one is an example or a payload, not markup.

The payload is escaped for the position it lands in — `xml_text` for character
data, `xml_attr` which also escapes both quotes, `xml_cdata` which leaves the
payload alone except for the one sequence that would end the section. The
target's parser undoes the escaping, so the sink receives `a && b` from
`a &amp;&amp; b`, for the same reason `json_string` escapes rather than
percent-encodes. An application that scrapes the envelope with a regex instead of
parsing it needs `--verify-body-location raw`.

Each enumerated point carries the shape of its own value, so the escaping is
never worked out by looking for the marker in the body. For a hand-written
`--verify-data` envelope the marker is still located, and where its occurrences
fall in values of more than one shape there is no single right escaping — the
body falls through to `raw` rather than a silent guess, and
`--verify-body-location` settles it.

**A capture that already contains the literal `FUZZ`** is marked with a token of
its own, and the run says so. The delivery layer replaces *every* occurrence of
the marker, which is what an operator writing `FUZZ` twice asks for and the wrong
thing for a marker RCEKit inserted: the payload would land in a field nobody
selected, and the confirmation could not be attributed to the point under test.
The captured `FUZZ` goes to the target as the value it is. `-p NAME` is
unaffected — a pre-existing marker sends it down the inline path before the
parameter is placed, so there is never a second marker to collide with.

Before this, an XML body fell through to the **form** branch — which it reaches,
because a prolog and every attribute contain `=`. Splitting it on `&` produced
one point named `<?xml version`, and every probe for it rewrote the prolog. The
run printed a point and a probe count while nothing in the document was tested.

A **GraphQL** body is enumerated as JSON, then reordered. `variables` carries
the values the operation is called with, and those reach resolvers; `query` is
the operation document itself, so a payload there *replaces* it and the server
answers with a parse error before a resolver runs. `operationName` then names an
operation that is no longer in the document. Both are moved behind the
variables, **not dropped** — a server that logs the query document before
parsing it is reachable through exactly that field, which is the route
Log4Shell took through access logs — so `--max-points` cuts the least likely to
pay first. A plain `{"query": ...}` body with no `variables` is left alone: it
is as likely to be a search API, and there the query field is the one worth
testing.

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
[detect]   header 'User-Agent': executed (61 probes)  <-- EXECUTED
```

Each candidate gets **its own** payload-free control: differencing a header
probe against a query probe's control would compare two different responses and
prove nothing. Use `--max-points` and `--max-payloads` to bound a run, and
`--verify-delay` to pace it — the delay applies across the whole enumeration.

### Stopping once something is proven

Two stops, and they answer different questions.

**A method that would only rename a finding is skipped.** Cheap methods run
first per candidate — `reflected` and `eval` cost one response each, `time`
sleeps and `oob` waits for a callback — and once a candidate has proven
execution, the slow ones are not paid for.

Which methods those are comes from the tier each one declares, not from a list
of names. `reflected`, `eval`, `file`, `write`, `oob` and `time` all answer *did
this target execute my input* and differ only in how hard they look, so a second
one is a second name for one finding. **`lookup` and `deser` answer something
else** — a lookup sink and a deserialization sink, each with its own
remediation — and are never skipped for this, however thoroughly execution is
proven. They used to be, for sitting on the expensive side of a hand-written
list, so a candidate that confirmed RCE was never asked whether it was also one
of those.

**A carrier that has confirmed stops there** (`--confirm-depth first`, the
default). One carrier is one method in one environment and context. Every other
carrier still runs in full, so a sink reachable only as `nodejs` is never missed
because `unix` answered first — the stop is per carrier and never per candidate.

This is not a saving. Measured against an executing target, one candidate spent
115 of its 120 probes after the first confirmation and printed 32 confirmations,
29 of them duplicates inside a single carrier. Those probes were not idle: they
were spent instead of reaching carriers never examined at all. At the same
budget the run went from 4 carriers examined to 23, and from 4 environments
reached to 9.

Pass `--confirm-depth every` to map every shape a sink accepts, which is what
writing a proof of concept by hand needs. Either way the run reports how many
shapes it held back and which carriers stopped.

`--max-payloads` is spent **per question**, not per wave and not per candidate.
Per wave it quietly doubled — a run capped at 5 sent 10 probes to every
candidate that did not confirm. Per candidate it starves the different
question: the cheap methods eat the whole allowance and `deser` never runs. So
every method asking about execution shares one allowance, each different
property gets its own, and the cost line says how many questions are being
asked.

**It is spent in requests, and it used to be counted in findings.** For a
method that answers from each probe those are the same number, so nothing
showed. An aggregate method reports one row however many probes it cost, so the
whole series went out and the cap noticed afterwards — at `--max-payloads 1`,
`time` sent 12 requests, `deser` 15 and `boolean` 27, while the cost line
printed before any traffic said 1.

What the budget may do about a series depends on where the method's answer
lives, which the class already knows:

| The method answers | Example | A budget that runs out |
|---|---|---|
| from each probe | `deser`, `lookup`, `oob` | stops the series; the probes already sent keep their verdicts |
| only from the whole series | `time`, `boolean` | declines the measurement **by name** and reports nothing for it |

The second row is not caution. `time` reports `negative` from a screen with no
regression behind it, and from a regression short of four samples — honest
answers to "no separator delayed", and false cleans when the real reason was
that the budget ran out. A `boolean` series whose anchors never went out reads
the same way. So a wave that does not fit abandons the measurement, and the run
names it and the flag that bounded it:

```
[detect] sent 0 probes (1 result(s)): inconclusive=1
[detect] --max-payloads held back 1 measurement(s) that could not have reached a
         verdict within the budget:
[detect]   1 x boolean/raw could not finish its series within --max-payloads
           (needed 27 requests, budget 3)
```

The summary counts what the target received, not how many rows came back. They
are the same number only while every method answers from each probe: an
aggregate method reports one row for a whole series, so a `time` run that put 20
requests on a target used to announce 5. An evasion retry is a request too, and
is charged to the same budget -- checked per rung, because one refused probe can
be retried at `low` and again at `high`.

**An abandoned measurement leaves a row, not a silence.** Dropping it quietly
let the *other* carriers describe the run, and the other carriers are the ones
with nothing to find: measured at `--max-payloads 12` against a sink that
honours an injected sleep, the unix carrier's regression was abandoned and a
windows carrier's honest "no separator delayed" became the run's verdict —
`negative`, for a target that was vulnerable. The row is `inconclusive`, which
is what an abandoned measurement is in the word the tool already uses, and it
outranks `negative`, so one held-back measurement stops the whole run reading
clean.

Single-point runs (`-p NAME`, or a `FUZZ` marker) get the per-carrier stop too;
the method skip is enumeration-only, because there is no next candidate to
spend the budget on.

### Expression-engine carriers

The `eval` method injects a product of two random operands in each common
template syntax and confirms that the **product** comes back. Most engines need
nothing more than that. Five do, and `--eval-engines` controls the extra probes
for them.

A carrier exists for exactly one reason: **the engine is vulnerable and the
bare probe cannot see it**, so a target that really does evaluate the template
reads as `negative`. That happens two ways — the engine computes the product
but does not print it bare, or it has no arithmetic operator at all and
multiplies some other way.

| Engine | Every bare form returns | Carrier | Carrier returns |
|---|---|---|---|
| Freemarker | `2,070,761,401` — grouped by locale | `${(a*b)?c}` | `2070761401` |
| Velocity | `${a*b}` verbatim — it is a *reference*, not an expression | `#set($rk=a*b)$rk` | `2070761401` |
| Thymeleaf | `${a*b}` verbatim — needs its inlining brackets | `[[${a*b}]]` | `2070761401` |
| Liquid | nothing — there is no `*` operator, and `{{a*b}}` will not even parse | `{{ a \| times: b }}` | `2070102857` |
| Django | nothing — `{{a*b}}` is a `TemplateSyntaxError`, by design | `{% widthratio a 1 b %}` | `2070102857` |

Measured against freemarker 2.3.32, velocity-engine-core 2.3, thymeleaf 3.1.2,
Django 6.1.1, and Liquid on both implementations — liquid 5.14.0 on ruby 3.3.12,
which is what Shopify and Jekyll run, and liquidjs 10.29.0. Each corpus entry
records what it was verified against.

**The last two take the operands apart.** Liquid multiplies with a filter and
Django with a tag, so neither can be written as one expression. A carrier
template may therefore use `__A__` and `__B__` as well as `__EXPR__`. A
template that is not parameterised by **both** operands is skipped rather than
sent: with no token it renders the same constant every probe, and with only one
operand the target is never handed the other, so nothing it can compute is the
product RCEKit is looking for.

**What was measured and did not produce a carrier** is recorded too, in
`eval_carrier_survey`, so the survey is not repeated: nunjucks 3.2.4, tornado
6.5.10, mako 1.4.1, chameleon 4.6.0, smarty 5.8.4 and Ruby's ERB are all
covered by a bare form already.

Two engines are the other outcome — every bare form fails and **no carrier can
be written**:

- **Handlebars 4.7.9** is logic-less and has no built-in arithmetic helper, so
  no template text computes a product without a helper the application itself
  registered.
- **Go `text/template` 1.23** has no arithmetic operator and no multiplying
  builtin (`mul` comes from sprig, which the application must register). The
  only forms that do return the product — `{{printf "%d" <product>}}` and
  `{{<product>}}` — **hand the target the answer**, so a target that merely
  echoed them would read as `executed`.

That last one is the rule a carrier lives under: **a carrier may not carry its
own result.** A test holds every shipped carrier to it. An evaluating target on
either engine is out of reach of this oracle, and recording that is worth more
than a carrier that cannot work.

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
`--eval-engines` saves little — there are only five carriers, and they are the
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
  "verdict": "executed",
  "counts": {"executed": 4, "negative": 9},
  "probes": [{"verdict": "executed", "method": "reflected", "environment": "unix",
              "context": "raw", "payload": "...", "detail": "target computed ..."}]
}
```

Use it instead of parsing stdout. Two things make the text report unsafe to
scrape: a probe payload may contain a literal newline — the newline separator is
a real one — so line-oriented parsing splits a payload in half, and the
detection path exits 0 whether it confirmed or came back clean.

The top-level `verdict` collapses the run, ordered by what you must not miss
rather than by what is most frequent: one `executed` among a hundred negatives
is the finding. `error` appears only when *nothing* reached the target, and a run
that built no probes is `nothing-tested` — never `negative`, which would read as
"not vulnerable".

This is the channel [`tests/bench/`](../tests/bench/README.md) reads to check
verdicts against real vulnerable targets.

### Out-of-band detection

`--methods oob` starts the built-in HTTP+DNS listener in-process and asks the
target to resolve or fetch `<token>.<oob-host>`. For a sink that returns nothing
it is the `executed`-tier method that asks nothing of the target's filesystem —
`time` tops out at `timing-sink` by design, `file` needs somewhere writable that
the target also [reads back](#file-based-confirmation-and-what-counts-as-read-back), and `write` needs
the request itself to be what stores a file. When the target has egress, this is
the cheapest of the three.

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

That second channel is `oob`'s alone. `lookup` resolves an expression and
`deser` reconstructs an object graph; neither has anywhere but a DNS label to
put a token, so a bare IP strands them — `lookup` builds nothing at all and
`deser` is left with its listener-free shape oracle. Both skip the probes
rather than send ones that cannot call back, and the run says which methods an
address stranded and which tier that puts out of reach, so a capped verdict is
not read as a result.

Naming a host is also what starts the listener for them. `deser` does not
*require* `--oob-host` — its shape oracle proves something without one — so a
`deser`-only run used to start no listener at all and send its gadgets to a
target with nothing to receive the callback, however well the host was
delegated. The listener now starts for any selected method that calls back when
a host is named, which `oob`, `lookup` and `deser` all do.

For `deser` that depends on `--deser-formats`: only `java` and `fastjson` ship
a DNS gadget, so a run narrowed to `php`, `dotnet` or `python_pickle` builds no
callback probe, starts no listener, and is not reported as stranded by an
address — the limit there belongs to the format, not to the host.

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
| `--deny-chars` | Drop payloads *and detection probes* containing any of these characters | None |
| `--max-length` | Drop payloads *and detection probes* longer than this | None |
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
| `--max-payloads` | Cap payloads (balanced round-robin sample). With `--methods` it bounds **requests** per question, and a measurement that cannot finish inside it is declined by name rather than cut short | Unlimited |
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
