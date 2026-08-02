# Payload generation &amp; exports

Under the detection engine, RCEKit is also a strong payload **generator**. It
builds context- and sink-aware payloads across 14 environments and exports them to
the tools you already use, so the corpus that proves an RCE is the same corpus you
fuzz with.

For confirming RCE against a live target, see the [field guide](guide.md); for the
full taxonomy of environments, categories, contexts and encodings, see
[reference.md](reference.md).

**Contents**

- [Generating payloads](#generating-payloads)
- [Target profiles](#target-profiles)
- [Exports](#exports)
- [Why generated payloads actually run](#why-generated-payloads-actually-run)

---

## Generating payloads

```bash
# Benign probes (no consent needed) — does your input even reach a sink?
python rcekit.py --detection-only --output detect.txt

# Targeted payloads for an engagement
python rcekit.py --acknowledge-consent \
  --environments unix --categories basic_enum file_operations waf_bypass \
  --output payloads.txt

# Machine-readable, with indicators and safety tiers alongside
python rcekit.py --acknowledge-consent --environments php \
  --output-format jsonl --include-metadata --output payloads.jsonl
```

Narrowing is what makes the output usable. Every one of `--environments`,
`--categories`, `--contexts` and `--encodings` cuts the corpus; `--max-payloads`
caps it with a balanced round-robin sample so you don't end up with 200 variants
of the same idea.

`--watermark` embeds a traceable token in each payload, which is worth turning on
whenever generated payloads leave your machine — if one shows up in a client's
logs later, you can prove which run produced it.

---

## Target profiles

Describe the target once in a small JSON file and generate only what could
actually reach the sink. The profile supplies defaults; explicit CLI flags always
override it.

```json
{
  "name": "shell-concat-noquotes",
  "environments": ["unix"],
  "contexts": ["raw"],
  "categories": ["basic_enum", "file_operations", "waf_bypass"],
  "deny_chars": ["'", "\""],
  "sink_needs_separator": true
}
```

```bash
python rcekit.py --acknowledge-consent --target-profile profiles/shell-concat-noquotes.json
```

Example profiles ship in [`profiles/`](../profiles/).

**Character and length filters** apply to the **final** payload, after encoding —
so a URL-encoded quote survives a `deny_chars` quote filter, because the literal
character is no longer there.

**Sink shape** is the higher-leverage knob:

| Key / flag | Meaning |
|---|---|
| `sink_needs_separator` / `--sink-needs-separator` | Input is concatenated mid-command → keep only separator-led break-outs |
| `sink_blind` / `--sink-blind` | Sink returns no output → keep only OOB- and timing-confirmable payloads |
| `sink_decodes` / `--sink-decodes` | Sink decodes input before use → those encodings become valid and are generated |

Against a mid-command sink, `sink_needs_separator` dropped ~20% of payloads
*without losing a single confirmed hit*.

A profile may also carry a `request` block (URL, method, headers, body with
`FUZZ`), which shapes the Burp/ffuf/Nuclei exports to the real endpoint instead of
a generic placeholder.

---

## Exports

```bash
python rcekit.py --acknowledge-consent --categories code_execution \
  --output-format nuclei --output run
```

| `--output-format` | What you get |
|---|---|
| `text` | One payload per line. The default. |
| `jsonl` | One JSON object per payload; pair with `--include-metadata` for indicators, safety tiers and notes. |
| `burp` | Deduplicated, watermark-free wordlists split per context, plus a combined list. A `request.txt` with Burp's `§…§` marker is written when a profile supplies a real request. |
| `ffuf` | The same wordlists and — with a profile `request` block — a ready-to-run `request.txt` plus an executable `run.sh`. |
| `nuclei` | Runnable templates grouped by environment and oracle (OOB / time-based / reflection). |

For the fullest Nuclei pack, generate from the benign corpus:

```bash
python rcekit.py --detection-only --output-format nuclei --output run
```

For `burp` and `nuclei`, `--output` is a **base directory** rather than a single
file.

---

## Why generated payloads actually run

Every generated payload either runs as-is on its sink or carries its own decoder.
Transforms that would produce a non-runnable string are removed, and
decoder-required blobs (`base64`, `hex`, `base64_then_url`, `double_base64`) are
opt-in — they are only generated when you tell RCEKit the sink decodes its input,
via `--sink-decodes` or a profile's `sink_decodes`.

The practical consequence: you never copy a payload out of the output that
silently does nothing. A payload that appears in the list is one that fires on the
sink it was generated for.
