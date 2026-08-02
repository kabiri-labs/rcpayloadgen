# Changelog

All notable changes to RCEKit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and RCEKit follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): PATCH for fixes,
MINOR for new capabilities, MAJOR for breaking changes to the CLI, output
formats, or the template schema.

## [Unreleased]

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

[Unreleased]: https://github.com/kabiri-labs/rcekit/compare/v2.21.1...HEAD
[2.21.1]: https://github.com/kabiri-labs/rcekit/compare/v2.15.2...v2.21.1
[2.15.2]: https://github.com/kabiri-labs/rcekit/releases/tag/v2.15.2
[2.7.0]: https://github.com/kabiri-labs/rcekit/releases/tag/v2.7.0
[2.1.0]: https://github.com/kabiri-labs/rcekit/releases/tag/v2.1.0
