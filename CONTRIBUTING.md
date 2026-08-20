# Contributing to RCEKit

Thanks for your interest in improving RCEKit! This document explains how
to contribute effectively and the standards the project holds itself to.

## Scope & ethics

RCEKit is an **RCE testing toolkit for authorised security testing**.
Contributions are welcome, but by opening a pull request you agree that your
change is intended for lawful, authorised use only (penetration testing,
security research, education, and defensive tooling).

Please **do not** submit:

- payloads or features designed for mass targeting, worming/self-propagation,
  or destruction of data as an end in itself;
- anything that weakens the built-in safety controls (consent gate, safety
  tiers, audit logging, the destructive-payload guard) without a clear,
  authorised-testing rationale.

## What we're looking for

- New payload **categories**, **sinks**, or **environments**
- Additional **contexts** (with correct escaping) or **encodings** (that stay
  executable — see below)
- Bug fixes and correctness improvements
- Better **oracles** / success signatures for auto-verification
- Documentation and test improvements

## Development setup

```bash
git clone https://github.com/kabiri-labs/rcekit.git
cd rcekit        # Python 3.8+, standard library only — no dependencies
python -m unittest discover -s tests
```

## Versioning and releases

`__version__` in `rcekit.py` is **the** release version. Nothing else declares
one: `pyproject.toml` reads it with `version = { attr = "rcekit.__version__" }`,
and the README badge and the newest `CHANGELOG.md` entry are held to it by tests.
Bump it in the same commit as the change it describes — PATCH for a fix, MINOR
for a new capability, MAJOR for a breaking change to the CLI, the output formats
or the template schema.

Keep it a plain string literal. setuptools reads it statically where it can, so
an f-string or a computed value would work today and break the moment the build
backend takes that path — a test pins the literal form.

Releases are cut by tagging `v<version>` on `main` — `v2.34.1` for
`__version__ = "2.34.1"` — and publishing a GitHub release. Publishing to PyPI
runs off `release: published`, not off the tag push, and the workflow refuses to
build when the tag and the module disagree. That check is deliberate: PyPI never
allows a version to be re-uploaded, so a mismatch would burn that version number
permanently.

## Adding a detection method

The `--methods` engine confirms RCE by proving the target *computed or executed*
a value RCEKit chose — never a literal the payload already carried. Methods live
in the clearly separated **Detection methods** section of `rcekit.py`
(`Probe` / `Verdict` / `Observation` / `DetectionMethod` and its subclasses).

To add one:

1. Subclass `DetectionMethod`: set `name` and `tier` (`confirmed` for
   execution-proven methods, `needs-review` for candidates — the two tiers are
   never merged), then implement `applicable`, `build_probes`, and `confirm`.
2. Compute the expected value **locally** with random inputs and compare it
   against the payload-free control (reuse `self._search`, which is
   encoding-aware). A verdict is `confirmed` only when the computed value is
   present and absent from the control.
3. Register the class in `DETECTION_METHODS`.
4. Add a `/vuln` (executes) vs `/reflect` (echoes) test to
   `DetectionMethodTestCase`: the method must `confirm` on `/vuln` and stay
   unconfirmed on `/reflect`. No third-party deps; keep the suite green on 3.8+.
5. Add a **bench case** (see below). A unit test proves the method reaches the
   right verdict from a given response; only a bench case proves it reaches that
   verdict against the real software.

## Adding a bench case

`tests/bench/` runs RCEKit against real vulnerable targets and checks the
verdicts, so a coverage claim can be checked rather than asserted. It needs
Docker and a [vulhub](https://github.com/vulhub/vulhub) checkout, so it is
deliberately **not** part of `python -m unittest discover -s tests`:

```bash
python tests/bench/runner.py --list
python tests/bench/runner.py --all --vulhub-root ~/vulhub --markdown coverage.md
```

New detection coverage should arrive with a case. Every case needs a **negative
control** — the runner refuses to load one without it — because a benchmark with
no controls rewards aggressive probing instead of measuring accuracy. The
control may be a patched build, the same target probed for the wrong class, or a
weaker method that must stay below `confirmed` on a target where it happens to
be right.

Run your case against the real target before submitting, and update the README
table with the verdict tier it **actually** reached. A README claim the bench
cannot reproduce is worse than a missing feature.
[`tests/bench/README.md`](tests/bench/README.md) documents the case format.
