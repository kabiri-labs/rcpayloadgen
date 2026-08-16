# Coverage benchmark

The unit suite proves RCEKit builds the right payloads and reaches the right
verdict from a given response. It cannot prove RCEKit confirms **Webmin**.

This harness closes that gap. Each case points at a real vulnerable build, runs
the tool the way an operator would, and checks the verdict against what the
README claims. It is what makes a coverage claim checkable instead of asserted.

## Running it

Cases that declare a `vulhub_path` need Docker and a
[vulhub](https://github.com/vulhub/vulhub) checkout:

```bash
git clone https://github.com/vulhub/vulhub.git ~/vulhub

python tests/bench/runner.py --list
python tests/bench/runner.py --case webmin-cve-2019-15107 --vulhub-root ~/vulhub
python tests/bench/runner.py --all --vulhub-root ~/vulhub --markdown coverage.md
```

Exit status is 0 only when every case passed, so this drops into CI as-is.

> These are deliberately vulnerable services. Run them on a machine you control
> and tear them down afterwards. The runner passes `--acknowledge-consent` for
> you, because a bench target is one you started yourself moments earlier — only
> point cases at infrastructure you own.

It is **not** part of `python -m unittest discover -s tests`. Cases pull real
images and take minutes; the default suite must stay fast and dependency-free.
The harness's own tests do run there (`tests/test_bench_runner.py`) and need no
Docker.

## Every case has a control

A benchmark without negative controls measures nothing. A tool that shouted
`confirmed` at every target would score full marks on the vulnerable half, and
the harness would report that as progress. So a case passes only when **both**
halves land, and `negative_control` is a required key.

The runner refuses to load a case whose control cannot measure anything:

- **No control at all.**
- **A control that expects `confirmed`** — a contradiction.
- **A control that runs the identical invocation against an identical target.**
  Judged on what it would actually run, not on which keys it declares: copying
  the vulnerable `invocation` into the control is the same non-control as
  omitting it. Vary the invocation (a different method or injection point) or
  the target (a patched build). Reusing the *same* target with a *different*
  invocation is the normal case and is fine.
- **A control that expects `error` or `nothing-tested`.** Both mean the run never
  exercised the target, so such a control would stay green with the detection
  engine entirely broken — exactly what a control exists to catch. A control may
  expect `negative`, `inconclusive`, or `needs-review`. (The vulnerable half may
  still expect `error`: "an unreachable target reports `error`, not `negative`"
  is a real property worth pinning.)

Controls come in three kinds. All three share one invariant: the control must
not reach `confirmed`.

| Kind | What it proves | Example |
|---|---|---|
| `patched-build` | The tool does not confirm on a fixed version | same case against a patched image |
| `class-attribution` | The tool names the class, rather than flagging the parameter | S2-001 probed with `reflected` → `negative` |
| `tier-ceiling` | A weaker signal is not promoted on a target where it happens to be right | Webmin probed with `time` → `needs-review` |

The third is the one people skip, and it is the one that protects the tool's
central promise. Timing produces no computed value; if it were ever promoted to
`confirmed` on a genuinely vulnerable sink, the erosion would look like a
success.

## Case format

```json
{
  "name": "webmin-cve-2019-15107",
  "rce_class": "OS command injection (results-based)",
  "target": "Webmin 1.910 — CVE-2019-15107",
  "vulhub_path": "webmin/CVE-2019-15107",
  "wait_for": {"url": "https://127.0.0.1:10000/", "status": 200, "timeout": 180},
  "invocation": ["-r", "{bench}/requests/webmin.txt", "-p", "old", "--methods", "reflected"],
  "expect": "confirmed",
  "expect_method": "reflected",
  "negative_control": {"kind": "tier-ceiling", "invocation": ["..."], "expect": "needs-review"}
}
```

| Key | Meaning |
|---|---|
| `vulhub_path` | Directory under `--vulhub-root`; the runner runs `docker compose up -d` there |
| `compose` / `compose_down` | Explicit argv, when the standard compose commands are not enough |
| `wait_for` | Poll until the target answers, so a slow boot is not read as a regression |
| `invocation` | RCEKit arguments; `--acknowledge-consent` and `--detect-json` are added by the runner |
| `expect` | `confirmed`, `needs-review`, `negative`, `inconclusive`, `error`, `nothing-tested` |
| `expect_method` | Optional. `reflected`, or the full carrier `reflected/unix/raw` |
| `negative_control` | Required. Its own `invocation` and/or `compose`, plus its `expect` |

`{bench}` and `{repo}` in an `invocation` expand to this directory and the repo
root, so a case can reference a captured request without a fragile relative path.

Omit `vulhub_path` and `compose` to benchmark a target that is **already
running** — useful for a target you brought up by hand, and how the harness's
own tests run without Docker.

## Why the runner reads JSON, not stdout

The runner appends `--detect-json` and reads the result from there. Scraping the
text report cannot be made reliable: a probe payload may contain a literal
newline — the newline separator is a real one — so line-oriented parsing splits
a payload in half, and the detection path exits 0 whether it confirmed or came
back clean.

The overall verdict follows what an operator must not miss, not what is most
frequent: one `confirmed` among a hundred negatives is the finding. `error` is
reported only when *nothing* reached the target, and a run that built no probes
is `nothing-tested` — never `negative`, which would read as "not vulnerable".

## Adding a case

New detection coverage should arrive with a bench case. Write the case, run it
against the real target, and paste the generated table row into the README next
to the claim it supports. If a class only reaches `needs-review`, say so — the
README table must not outrun the engine.

## Status

The two shipped cases are transcribed from
[`docs/verify-it-yourself.md`](../../docs/verify-it-yourself.md), whose
reproductions are documented as verified against vulhub. **They have not yet been
executed through this harness** — it was written in an environment with no Docker
daemon — so treat the first run as validation of the case files themselves. The
`struts2-s2-001` case in particular guesses `/login.action` and `username` from
vulhub's defaults, where that document deliberately tells the operator to read
the form off the running app; its `notes` say so and how to check.

Nothing in the repository's README has been changed to claim benchmark results.
The coverage table becomes generated output once these cases have actually run.
