# Changelog

All notable changes to RCEKit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and RCEKit follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): PATCH for fixes,
MINOR for new capabilities, MAJOR for breaking changes to the CLI, output
formats, or the template schema.

## [Unreleased]

### Added

- **A coverage ledger, so a measured result and a reproduced one stop looking
  alike.** The README's CVE table had four rows and two columns that mattered,
  and no way to say what stood behind any of them. It gained seven columns and
  five more rows, and the two on the right are the point: `Bench case` says
  whether `tests/bench/` reproduces the row under Docker with its negative
  control, and `Recording` says whether a file in `confirmation-gifs/` shows it.

  Five rows are new, measured against vulhub builds during this work: OpenTSDB
  2.4.1 (CVE-2023-25826) reaching `confirmed` through `oob` and `needs-review`
  through `time`; HugeGraph 1.2.0 reaching `confirmed` through both `eval` and
  `reflected`; and a Spring Boot application on fastjson 1.2.83 reaching
  `deserialization-sink`. All five landed saying `not yet` under `Bench case`,
  which was the honest state at the time and the reason that column exists; each
  has a case now. The 4 rows that predate this work had last been executed as a
  set at 2.36.0, and none of them regressed. The ledger carries the figures for
  the whole set, because a running total written here rots on the next change
  rather than the next release.

  `Advisory` is empty on three of them, deliberately. HugeGraph 1.3.0 answers
  the arithmetic exactly as 1.2.0 does -- its Gremlin API evaluates Groovy
  unauthenticated by design -- and fastjson resolving an `Inet4Address` is
  documented autoType behaviour. Those rows prove a *method* against real
  software, which is worth recording; calling them CVE reproductions would be
  the overclaim the table exists to avoid. Both facts were measured rather than
  assumed: the patched HugeGraph image was pulled and run.

  Three tests hold the ledger to the repository: a row claiming a bench case
  must have one, a row claiming a recording must have one, and the capability
  rows must stay distinguishable from the CVE rows. Each was checked by making
  the false claim and watching it fail. The tier check now reads *every* row
  rather than only those naming an advisory, and its parser is keyed on column
  headings rather than position -- the old one was hard-coded to four columns
  and found nothing at all once the table grew.

- **A bench case for `write`, the last tier-1 method without one.**
  `tomcat-cve-2017-12615` -- `PUT /rcekit-probe.jsp/` with the content in the
  body, which is the shape the method's own docstring names. Its control runs
  `reflected` against the same point and must stay `negative`: the target is
  exploitable and `write` confirms on it, but a PUT answers 204 with an empty
  body, so nothing in the vulnerable response is computed. Measured at 959
  probes, every one answered 204.

  It is the first case here that may not share a target between its halves --
  both write a file into the web root -- which turned up a harness bug: under
  `--keep-up` the teardown *between* the halves was skipped too, and compose
  handed the control the container the vulnerable half had just written to. That
  teardown is mandatory now wherever the halves would land on the same
  container, which is decided from what *starts* a target -- its `vulhub_path`
  and `compose` -- and not from what stops it. A control overriding only
  `compose_down`, to keep its volumes say, still meets the container the
  vulnerable half brought up. A control that brings up its own target has
  nothing to contaminate, so `--keep-up` leaves the vulnerable one running
  there, which is the environment worth looking at after a failure. The
  teardown after the last half stays the flag's to skip either way.

  The case is also what caught the two `write` defects fixed in 2.45.6 and
  2.45.7, neither of which a fixture could have found.

### Fixed

- **The comparison table named seven of the nine registered methods.** `lookup`
  and `boolean` had no row in "How RCEKit compares", although `lookup` is the
  Log4Shell row the CVE table directly above it already carries, and `boolean`
  shipped two releases ago. The table's claim is coverage -- "every class, one
  run" -- so a method missing from it is that claim understating itself.

  The drift was structural, not an oversight anyone could have caught by
  reading. `docs/reference.md`, the `--methods` help, the CVE rows and the demo
  headings are each pinned to `DETECTION_METHODS` by a test. The comparison
  table was pinned by nothing, so it was the one place a new method could fail
  to appear without anything going red.

  Two tests now hold it, in both directions: every registered method has a row,
  and the table names no method the CLI would reject -- because a one-way check
  rots. A method *removed* from the registry would otherwise leave its row
  behind, advertising a `--methods` value that no longer exists, while the
  completeness test went on passing.

  Each row now names its method in backticks, which is what makes the check
  possible and also answers the question the table used to leave hanging: a
  reader who wants the row they just read has the flag in front of them. Rows
  that are not methods name none on purpose -- second-order execution, the
  query-language bridges and the per-dialect Windows probes are things the
  methods run *through*, not entries in `--methods`.

  Both checks read the capability table alone, and identify a method label
  structurally: the last backtick in the leading cell, after an em-dash. The
  first attempt did neither, and both shortcuts cost it the guarantee it stated.
  Reading every table in the section meant a deleted capability row kept passing
  on a mention elsewhere -- the engagement-controls table names `file` and
  `write` under "Cleanup commands" -- which was confirmed by deleting the `file`
  row and watching the check stay green. And filtering labels on lowercase
  letters exempted exactly the spellings a typo or a rename produces:
  `boolean2`, `second-order`, `reflected_v2` all walked past the phantom check,
  while `cmd.exe` is the legitimate backtick in that column that the filter had
  been reaching for. Structure separates them; a character class does not.

  No version bump -- this is documentation and tests only.

### Added

- **A tier correction has to reach the prose, not only the class.** Four tests
  now read the tier from `DETECTION_METHODS[name].tier` and hold the sentences
  an operator actually sees against it.

  `lookup` moved from `confirmed` to `lookup-sink` on the class, and the move
  was made in the README's CVE table -- but `blind_sink_advice` went on
  offering `--methods lookup` as a method that "confirms", in the list where
  `oob` and `file` do mean confirmed execution, and the README's Log4Shell demo
  heading still said `confirmed` over alt text calling the run
  "auto-confirming a blind Log4Shell RCE". Three places, one correction, and
  nothing compared them: the existing test pinned the one line it was written
  for (`time` is marked needs-review only) rather than asking every line the
  same question.

  So: every `blind_sink_advice` line naming a method must state that method's
  tier and no other; every CVE row must state the tier its method reports;
  every demo heading must match its row in that table; and a recording below
  `confirmed` may not be described as confirming, alt text included, since
  that is the sentence a screen reader reads out.

  The wording checks match stems rather than words, and denials such as
  "never confirmed" are removed before they are applied. "confirms" alone
  would have readmitted the overclaim through "confirming RCE" or "confirmed
  execution" -- an assertion answering the same way for the right reason and
  the broken one, which is the defect being guarded against. Each test was
  checked by reintroducing the defect it exists for, and each carries a floor
  on how much it inspected: a parser that quietly stopped matching would
  otherwise pass exactly as a clean README does.

  Test-only: no version bump, and nothing about a run changes.

- **The same check, for the two tables under `docs/`.** They were left out when
  the README's were pinned, and they carry the same claim:
  `docs/reference.md` names the tier each method can reach, and
  `docs/guide.md` tells an operator which method to reach for next.

  `reference.md` states a ceiling, so its rule is a subset rather than an
  equality -- a cell may also name a weaker tier the method really emits, as
  `write` and `deser` both do -- and every registered method must have a row,
  so a capability cannot land unlookupable. `guide.md` has no tier column and
  so is held only to the negative: a row recommending a method that cannot
  confirm may not describe confirmation.

  Rows are read by column heading rather than by position. Reading the whole
  row made the `guide.md` check skip the one row it was written for, because
  that row's prose names `oob` -- which confirms -- while recommending
  `lookup`, which does not.

  A reference row naming something that is not a registered method fails rather
  than being passed over. Skipping it left the completeness check one-way: a
  method *removed* from `DETECTION_METHODS` would leave its row behind, every
  remaining row would still match, and the page would go on offering a
  `--methods` value the CLI rejects.

  Rows split on *unescaped* pipes. Markdown writes a literal pipe in a cell as
  `\|`, which `docs/reference.md` already does in three tables, and splitting
  on every pipe invents a cell: zipping against the header then drops the last
  column outright, so a claim there stops being examined and every one of these
  checks passes without looking at it.

  A disclaimer is not read as a claim. "never confirmed" was already removed
  before the `confirm` stem was looked for; "without confirmation" and
  "unconfirmed" were not, and the second carries its negation inside the word
  where a rule about preceding words cannot see it. Documentation saying the
  honest thing would have failed the suite. One parser and one denial rule now,
  where there were two of each here and a third in the generator tests.

### Changed

- **A bench case may bring its target up once for both halves**, with
  `"share_target": true`. Bringing the container up twice is the largest fixed
  cost in a case and both halves usually hit the same one, so on a fast case it
  is most of the wall clock.

  It is opt-in, and the default is unchanged, because the teardown between the
  halves is `down -v`: today's control meets a **fresh** target. A case whose
  vulnerable half writes a file, plants a shell or changes a setting would hand
  its control a target it had already altered, and a control measured against a
  contaminated target measures nothing -- which is the one failure a benchmark
  may not have. Validation rejects the key on a case whose control brings up a
  different target, since there is then nothing to share and leaving it set
  would read as though there were.

  A shared `up` that fails falls back to per-half management rather than
  carrying on, so the run reports `compose up failed` instead of two readiness
  timeouts naming the wrong cause.

  Both shipped cases set it, because neither half writes anything. Measured on
  `struts2-s2-001` against vulhub on Docker: 33.8s to 22.9s, with both halves
  reaching the same verdicts either way.

- **The benchmark reaches a callback method**, with a case for Log4Shell
  (Apache Solr 8.11.0, Log4j 2.14.1). `python tests/bench/runner.py --all` is
  3/3.

  Every case until now was in-band, so the listener, the token correlation and
  `confirm_each` had never run against real software -- the area that produced
  three P1 findings while `lookup` was being written.

  Two things had to give. A JNDI lookup resolves through the system resolver,
  which asks UDP 53, and a developer machine rarely has that port free; a bare
  `--oob-host` IP is no way around it, because a lookup has no second channel
  to carry the token. So a case may now name `run_in`, and the run happens in a
  container on the target's own network at a fixed address, with an override
  pointing the service's `dns:` at it. The repository is mounted read-only and
  the image is a stock Python.

  The other was the harness's own vocabulary. `VALID_EXPECTATIONS` and
  `CONTROL_EXPECTATIONS` were written out by hand and had drifted: neither
  `lookup-sink` nor `deserialization-sink` was in either, so a case for `lookup`
  or `deser` could not be *loaded*, let alone run. Both are read from
  `DETECTION_METHODS` now.

  The control is the case: `oob` against the same Solr comes back `negative`
  **although it is exploitable**, because every probe it builds is a shell
  command and a `${jndi:...}` sink runs none of them. That is the gap `lookup`
  was added to close, and until this case ran it rested on a fixture.

  `{bench}` / `{repo}` now expand in a case's compose argv as well as its
  invocation, and resolve to the mount point when the run is containerised.

  The results file is created before the container starts, and it rather than
  its directory is made writable. Under Docker's user-namespace remapping,
  container root is a subordinate host UID, so a `mkdtemp` owned by the runner
  at 0700 is not writable from inside: the file would never appear and the case
  would report `nothing-tested`, as though detection had found nothing rather
  than as though the channel had been shut. Granting the one file and not the
  directory keeps anyone else from creating, replacing or unlinking entries
  there.

  Test-only: no version bump, and nothing about a run changes.

### Fixed

- **`--methods` enumerated only some of the methods it accepts.** `write`,
  `lookup` and `deser` were registered in `DETECTION_METHODS` and had never
  once been named in the help, so `--help` described a whole target class as
  out of reach -- an upload that stores a file, a `${jndi:...}` sink, an
  endpoint that deserializes what it is handed -- while the method for it was
  already shipping and documented everywhere else. Each now carries the tier
  its class declares: `confirmed` for `write`, with `needs-review` for a write
  that is served but not interpreted; `lookup-sink` for `lookup`;
  `deserialization-sink` for `deser`; and neither of the last two ever
  `confirmed`.

  `oob` also called itself "the only confirmed-tier method for a fully blind
  sink". The tier is right, but an exclusivity claim is the kind that goes
  stale without anything failing, so the line now says what the class itself
  says: it confirms a sink with no output channel and no writable web root.

  A new test in `CLIDocumentationTestCase` holds the list to the registry, the
  way `--eval-engines` is already held to the corpus. It reads the `--methods`
  help alone rather than the whole page, because every one of these names also
  occurs inside some other flag -- `file` in `--request-file`, `write` in
  `--file-write-path`, `time` in `--time-base` -- and it looks for the name
  followed by the parenthesis that opens its description, because the old help
  carried the word `write` inside `file`'s "write+read-back" and a looser
  match would have counted that as documentation.

  A second pass corrected what `--oob-host` promises those two methods. Its
  help offered "an IP it can reach or a domain delegated to this listener" and
  was scoped `(--methods oob)`, which was true when `oob` was the only caller.
  It is not true now: `LookupCallback.build_probes` returns no probes at all
  for an address literal, so `lookup` reports `nothing-tested`, and `DeserSink`
  builds `<token>.<IP>`, which resolves nowhere, so its DNS gadget can never
  reach `deserialization-sink`. An operator who satisfied the stated
  prerequisite got silence from one method and a capped tier from the other.
  The flag's help, the `--methods` entries for `lookup` and `deser`, the
  message printed when a callback method is selected without a host, and the
  `deser` oracle table in `docs/reference.md` now all say the same thing: an IP
  serves `oob` alone, because only `oob` can put its token in a URL path.

  `boolean` landed on `main` while this branch was open. It was named in the
  help but left out of the `--methods` row in `docs/reference.md` -- the same
  drift, one table over. Both carry it now, and the new test covered it without
  being told to, which is the point of reading the registry instead of a list.

  No version bump -- this is documentation and tests only.

## [3.1.2] — 2026-10-17

### Fixed

- **A JSON body with a byte-order mark yielded no injection point at all.** The
  same U+FEFF that used to send an XML body down the form branch sent a JSON body
  nowhere: `str.strip()` leaves the mark, so the test on the first character said
  "not JSON", and `-p NAME` could not reach a JSON field either. .NET clients
  emit a mark routinely.

  Fixing that test alone would not have been enough, and that is the shape of the
  bug worth recording: `json.loads` **rejects** the mark outright
  (`Unexpected UTF-8 BOM`), so the branch and the parse had to agree. Five
  request-side sites did not — two branch tests, a third in `-p NAME`'s own path,
  and three parses behind them.

  The mark is now stripped through one shared helper wherever RCEKit decides what
  a body *is*, which is also where the XML branch already asked, so the two
  carriers cannot drift apart again. The constant moved out of the XML block and
  lost its `_XML_` prefix, since both now use it.

  Because the JSON path re-serialises, **the mark is put back on** the body that
  goes to the target: the capture carried it and the application accepted it, so
  sending it back is the faithful answer, and the payload-free control is rendered
  through the same path, so probe and control still differ in the field under test
  and in nothing else.

  A mark is not a licence to guess. A body that is still neither JSON nor XML once
  it is stripped goes down exactly the paths it did before.

  The mark is removed **and then** whitespace, in that order, and the order is
  the whole of it: `str.strip()` stops at a mark, so a body whose mark is
  followed by a newline still has that newline in front of its delimiter after
  stripping — and every test on the first character then says "not JSON" about a
  document `json.loads` accepts, and "not XML" about one the scanner reads. That
  is the same branch-disagrees-with-parse failure this entry is about, reached by
  writing the rule correctly and the order backwards. One helper named for the
  order now owns it, and a test fails if the two are swapped.

- **A form key behind a byte-order mark was addressable only as an invisible
  name.** A mark sits in front of the *first* key, where it is an artefact of how
  the body was encoded rather than part of the field name, so enumeration
  reported `<mark>cmd` — a report with an invisible character in it — and
  `-p cmd` could not find the field at all. The point is now named without the
  mark, while the body keeps its own bytes: the key is written back exactly as
  captured, because a urlencoded parser on the far side sees the mark too, and a
  key RCEKit rewrote is a key it changed.

## [3.1.1] — 2026-10-17

### Fixed

- **A capture carrying its own `FUZZ` had the payload put in two places.** The
  delivery layer substitutes at *every* occurrence of the marker, which is right
  for a marker the operator wrote — two `FUZZ` in a request mean both — and wrong
  for one RCEKit inserted. Enumeration places its own marker at a chosen point,
  and a point wins over an inline marker by design, so a capture containing the
  literal `FUZZ` ended up with two markers: the payload landed in a field nobody
  selected, and a confirmation could not be attributed to the point under test.
  Measured for `xml`, `json`, `form` and `query` alike, so it was not specific to
  any one carrier.

  Enumeration now marks each point with a token of its own whenever — and only
  when — the capture already contains the default marker, and the run says so.
  The captured `FUZZ` then goes to the target as the value it is. The swap is
  conditional because `FUZZ` is what the exports, the documentation and the
  inline path all name, so it is left alone wherever it cannot collide; the token
  keeps the `FUZZ` prefix so a marked request still reads as marked.

  **`-p NAME` never reached this, and is deliberately unchanged.** A pre-existing
  marker sends it down the *inline* path before the parameter is ever placed, so
  giving it a marker of its own would change which place the run tests. The
  unbounded substitution is also unchanged: the operator-written case needs it,
  and this only stops RCEKit's own marker colliding with theirs.

  What this does not change: nothing differs on the wire for a capture without a
  literal `FUZZ` in it, which is every capture the test suite and the docs use.

  Threading the marker to the delivery layer **appends** it to every signature it
  touches — `run_detection`, `run_verification`, `_fire`, `_fire_channels`,
  `_escalate` and `_detect_body_location` — so no existing parameter moves. In
  `run_detection` that puts it after `config` and `rng` rather than beside
  `body_location` where it belongs by meaning, and deliberately: inserting it in
  the obvious place shifted those two along by one, so a caller passing `config`
  positionally bound a dict to `mark` and the first delivery raised `TypeError`
  from `str.replace`. A test pins the ordering per signature, because the fix
  looks like untidiness and the next tidy-up would reintroduce the break.

## [3.1.0] — 2026-10-17

### Added

- **An XML or SOAP body is enumerated, and until now it had one injection point
  that could not confirm anything.** No branch recognised XML, so an envelope
  fell through to the **form** branch — which it reaches, because a prolog and
  every attribute contain `=`. Splitting it on `&` produced exactly one point,
  named `<?xml version`, and every probe for it rewrote the prolog. The run
  printed a point and a probe count while no element, attribute or CDATA section
  in the document was ever tested. That is the failure that matters: coverage
  reported and not delivered reads exactly like a clean target.

  The new `xml` kind addresses every element's character data, every attribute
  value and every CDATA section by path — `soap:Body/getUser/name`,
  `getUser/@id`, `note/cdata()`. A repeated sibling is indexed from the second
  occurrence (`items/item`, `items/item[2]`), the same way a repeated multipart
  field is labelled, so the later ones are reachable rather than counted as
  covered. `xmlns` declarations are not candidates: a payload in a namespace URI
  renames the element instead of reaching anything that reads its value.

  An element with no element children is a candidate **even when it is empty or
  holds only whitespace**, because `<cmd></cmd>` and `<cmd>   </cmd>` are the
  ordinary shape of a field in a SOAP template, and a JSON `""` leaf and a form
  `key=` were candidates already — XML would have been the one carrier that
  dropped them, so an envelope of placeholders could report no body injection
  point at all. Whitespace between two *elements* is still formatting and yields
  nothing: the test is whether the element had an element child, not whether its
  text is blank, because the blank test answers the same for a placeholder field
  and for the indentation of a pretty-printed envelope. A self-closing `<cmd/>`
  is not a candidate, for the reason a missing JSON key is not.

  The body is recognised **byte-order mark and all**. `str.strip()` does not
  remove U+FEFF, and the cost of missing it is not a missed point but the wrong
  branch: a body with a prolog contains `=`, so a marked envelope would have
  fallen through to the form branch and produced the single bogus point this
  kind exists to replace. .NET clients emit a mark routinely.

  The document is **spliced at the value's offsets**, never parsed and
  re-emitted. Two reasons, and the second decided it. A signed envelope
  (WS-Security / XML-DSig) covers its own bytes with a digest, and
  parse-then-emit loses attribute order, insignificant whitespace and the
  prolog's quoting style — none of which XML requires preserved and all of which
  the digest covers. And a capture aimed at an **XXE** sink carries a DOCTYPE
  with an external entity, because that is exactly what the operator is trying to
  prove the *target* resolves; a real parser resolves it here instead, which
  turns the tool into the thing it is testing for. A scanner interprets no
  entity, so there is nothing to resolve, no billion laughs to expand and no
  retrieval to disable.

  A signed body is therefore not probed, and the run **says so** rather than
  reporting zero points — every probe would come back refused for a reason that
  has nothing to do with the sink, which reads exactly like a filter. "Signed"
  means a `Signature` element **in** the XML-DSig namespace, and both halves are
  required: the namespace URI alone appears wherever a schema predeclares the
  prefix without signing anything, and an element named `Signature` is ordinary
  in plenty of schemas, so either test on its own would suppress every point in
  a document that is perfectly testable. Comments and CDATA sections count
  neither way — a tag or a declaration written inside one is an example or a
  payload, not markup, and a commented-out `<!-- <ds:Signature> -->` reached the
  same wrong answer by a second route.

- **`--verify-body-location` gained `xml_text`, `xml_attr` and `xml_cdata`**, and
  the automatic choice now reads the marker's *position* rather than the body's
  type. The escaping an XML payload needs is not a property of the body: a
  payload in an attribute has to escape the quote that delimits it, one in
  character data does not, and one inside CDATA must not be escaped at all or the
  sink receives `&amp;&amp;` literally. The target's parser undoes the escaping,
  so the sink receives `a && b` from `a &amp;&amp; b` — the same reason
  `json_string` escapes rather than percent-encodes. Sent raw, a single `&` or
  `<` makes the body not-well-formed and the request is rejected before anything
  reads the value, which is a whole class of sink answering `negative` for a
  reason that has nothing to do with the sink. An application that scrapes the
  envelope with a regex instead of parsing it still needs
  `--verify-body-location raw`, and can now say so.

  `xml_cdata` leaves the payload alone except for the one sequence that would end
  the section, which it splits across a section boundary — the bytes the sink
  receives are unchanged.

  Each enumerated point **carries the shape of its own value**, so the escaping
  is never recovered by locating the marker. The delivery layer replaces every
  occurrence of `FUZZ`, so a capture that already contains a literal `FUZZ` of
  its own has two, and reading the first one picked the other span's shape: a
  probe aimed at element text was escaped as CDATA, its `&` went on the wire
  bare, and the target refused to parse the document — a whole sink answering
  `negative` for a reason that has nothing to do with the sink. For a
  hand-written `--verify-data` envelope the marker is still located, and where
  its occurrences fall in values of more than one shape the body falls through
  to `raw` rather than a silent guess.

### Changed

- **`--auto-params form` against an XML body now finds no body point**, where it
  used to find the one that tested nothing. The branch is chosen by the body's
  own shape and the kind filter is applied inside it, so an envelope can no
  longer be read as `a=1&b=2`.

## [3.0.1] — 2026-10-01

### Fixed

- **`reflected` named a shell it had not proved.** One of its probe shapes — a
  bare `expr a + b` at `--probe-depth full`, whose expected value was the sum
  alone, matched digit-fenced — reported `executed` under
  `[reflected/<environment>/...]` against targets where nothing executed a
  command. Groovy reads `expr 548286 + 675041` as the command expression
  `expr(548286 + 675041)`: it computes the sum, fails to resolve the method, and
  echoes the result in its error.

  The tier was never wrong. The target did compute a value reflection cannot
  forge, and `eval` reaches `executed` on such an endpoint honestly. What was
  wrong is the **class**: a finding printed under `reflected/unix` asserts a
  POSIX shell ran the input, and in a report a correct proof filed under the
  wrong class is worse than a miss.

  Measured against a plain Apache HugeGraph 1.2.0 Gremlin endpoint with every
  shape mapped (`--confirm-depth every`): 42 probes, `executed=3`, all three
  that one shape, and 0 of 36 tagged probes confirming. Measured against the
  same build's ProcessBuilder body, where a real `sh -c` runs: 4 tagged shapes
  confirm — the canonical `$(( ))` plus `$(echo TAG)` collapse, the backtick
  `expr`, the `${IFS}` space-free form and the comment-terminated collapse — so
  removing the shape costs nothing on a genuine shell. The remaining shapes all
  require the target to place RCEKit's random tags *around* the value it
  computed, which an expression evaluator handed the payload cannot do.

  The shape is removed rather than repaired: `expr` has no portable string
  concatenation, so there is no way to bracket its result in a tag without
  reintroducing the `$(` or the `echo` keyword the shape existed to avoid. The
  substitution-free coverage it shared is carried by `awk` alone, which is
  unaffected. A sink that filters `$(`, backticks and `awk` at once is now out
  of `reflected`'s reach and stays reachable through `time`, `oob` and `file`.

  `--probe-depth quick` never sent the shape, so a `quick` run is unchanged.
  Two guards hold the invariant over every environment, context and depth: no
  probe's expected value may be the arithmetic alone, and none may match
  digit-fenced. Both were run against the restored shape and both fail on it,
  as does a new bench case whose control runs `reflected` against the same
  Gremlin endpoint and requires `negative` — with the shape restored it reports
  `executed=30`.

  One second-order effect worth knowing: the retired shape was also the
  shortest probe `reflected` built, so the shortest is now 41 characters rather
  than about 20. A `--max-length` below 41 therefore leaves the method with no
  probe at all. That fails loudly rather than quietly — the run prints
  `NOTHING WAS TESTED — this is not a negative result`, names
  `--max-length` as what removed all 36 probes, and says to relax it or treat
  the sink as one the probe vocabulary cannot reach.

## [3.0.0] — 2026-09-30

### Changed

- **BREAKING: `confirmed` is now `executed`, and three settled measurements
  stopped reporting as `needs-review`.** Every verdict is now named for what the
  *target* did, never for how sure RCEKit is.

  Two problems, one vocabulary. `confirmed` was the only verdict that described
  RCEKit's own confidence while every sibling described the target's behaviour,
  and next to it a `lookup-sink` -- proven on a callback carrying a token only
  that probe held -- read as something unconfirmed. And `needs-review` had four
  users, of which three had measured their answer:

  | Verdict | Was | What it says |
  |---|---|---|
  | `executed` | `confirmed` | the target executed the input |
  | `timing-sink` | `needs-review` | the target honoured a delay RCEKit injected |
  | `file-write` | `needs-review` | the target stored a file at a path RCEKit chose and serves it back uninterpreted |
  | `evaluation-sink` | `needs-review` | an evaluator consumed the input and partitioned on it; which evaluator is not shown |
  | `needs-review` | `needs-review` | unchanged, and now with one user: `deser`'s parser fingerprint, the one signal that really is a candidate |

  `write`'s middle verdict is the clearest case: its evidence line opened with
  the words "ARBITRARY FILE WRITE confirmed" under a status that said
  `needs-review`. The tool's own prose contradicted the tool's own status,
  because the status was naming a confidence the measurement did not have a
  reason to lack -- the file was on the target and RCEKit had read it back.

  Nothing was promoted. `executed` still rests on exactly the three channels it
  did before, and none of the five weaker tiers has a path into it. `time` in
  particular stays out: a delay honoured is not necessarily a *shell* honouring
  it, since a sandbox that implements `sleep` answers the regression the same
  way. What changed is the direction of the reporting error -- three proven
  findings were being under-reported.

- **`overall_detection_verdict` ranks `needs-review` last instead of second.**
  Its position was argued from "a suspected RCE outranks a proven non-RCE in
  triage", which held while `time`, `boolean` and `write`'s uninterpreted file
  all reported there. The one verdict left under it is a suspected
  *deserialization*, so ranking it above `deserialization-sink` put the guess
  above the proof of the same thing. The full order is now `executed`,
  `timing-sink`, `file-write`, `evaluation-sink`, `deserialization-sink`,
  `lookup-sink`, `needs-review`.

  That order is stated once, in `NON_EXECUTION_SECTIONS`, and both the
  collapsed verdict and the text report read it from there. They used to state
  it separately -- one as a tuple, the other as the order of print statements
  in `main()` -- and they disagreed: `deserialization-sink` and `lookup-sink`
  were hand-written blocks above the table holding the rest, so a run
  reporting both `timing-sink` and `deserialization-sink` collapsed to the
  first and led the report with the second. A statement order is not data and
  cannot be checked against anything.

  Folding those two in unifies their heading with the others: `NOT proof of
  RCE` becomes `NOT proof of execution`, which is what the other four already
  said. Their rows keep the compact form they had -- truncated payload, no
  `environment` -- because they carry base64 object streams and JNDI URIs.

- The classic `--verify-url` path renamed its `confirmed` verdict too, and its
  section headings with it. It has no sinks and no `needs-review`, so nothing
  there was mis-tiered; a tool printing `[verify] CONFIRMED` beside `[detect]
  EXECUTED` would just be two vocabularies. That path has no machine-readable
  output, so this is text only.

### Benchmark

**`runner.py --all`: 9/9, in 55m50s**, against the same vulhub builds. Every
case's expected verdict changed in this release, and a rename applied to a
stored result proves nothing about what the tool now reports, so all 9 ran:

| Case | Method | Vulnerable half | Negative control |
|---|---|---|---|
| `fastjson-1.2.83` | `deser` | `deserialization-sink` | `negative` |
| `hugegraph-gremlin-eval` | `eval` | `executed` | `negative` |
| `hugegraph-gremlin-shell` | `reflected` | `executed` | `negative` |
| `log4shell-cve-2021-44228` | `lookup` | `lookup-sink` | `negative` |
| `opentsdb-cve-2023-25826` | `oob` | `executed` | `timing-sink` |
| `struts2-s2-001` | `eval` | `executed` | `negative` |
| `tomcat-cve-2017-12615` | `write` | `executed` | `negative` |
| `webmin-cve-2019-15107-file` | `file` | `executed` | `negative` |
| `webmin-cve-2019-15107` | `reflected` | `executed` | `timing-sink` |

The two `timing-sink` controls carry the weight. On a Webmin 1.910 and an
OpenTSDB 2.4.1 that are genuinely vulnerable, `time` reaches its own proven
tier and still does not reach `executed` -- the retier holding against real
software and not against a fixture.

Two tiers this release introduced are **not** in that table: `file-write` and
`evaluation-sink`. The Tomcat `write` case reaches `executed`, and `boolean`
has no case at all. Both are covered by unit tests only.

### Migration

`--detect-json` changes values, not keys. `verdict`, the keys of `counts`, each
probe's `verdict`, and `observe_status` take the new names per the table above.
A consumer keyed on `"confirmed"` must read `"executed"`; one keyed on
`"needs-review"` should decide which of the four it actually meant. No CLI flag,
no JSON key, no template-schema field and no exit code changed.

No backward-compatible alias is shipped. Two accepted spellings for one field is
a second source of truth, and the point of this release is that there is one.

### Fixed

- **A method's question was derived from its tier, which does not determine
  it.** `detection_question` decided whether a method asks *did the target
  execute my input* by looking up its tier in a set of two names. A tier says
  how strong an answer a method can reach; `time` asks the execution question
  and cannot reach the strongest answer to it, while `lookup` reaches a
  definitive answer to a different question.

  Left alone, renaming `time`'s tier in this release would have moved it out of
  the execution group and out of the dedup that skips it on a candidate
  `reflected` has already proven -- so the most expensive method in the tool
  would have run to put a second name on a finding. `question` is now declared
  on the class, `EXECUTION_TIERS` is gone, and the partition is unchanged.

  The test covering this recomputed the derivation rule it was checking, so it
  agreed with the rule whatever the rule became. Three tests replace it: the
  partition written out, the one case where question and tier disagree, and the
  `time`-leaves-the-group regression by name.

## [2.45.7] — 2026-09-26

### Fixed

- **The `write` product overflowed a 32-bit int, so the method reported
  `negative` on more than half of the targets it was built for.** RCEKit
  computes `a*b` in Python, where integers do not overflow. The interpreter on
  the other side usually is not Python: JSP and ASPX are 3 of the 5 languages
  this method writes, and both evaluate the expression as a signed 32-bit int.
  A product past 2**31-1 therefore came back wrapped, disagreed with the value
  RCEKit had computed, and the run reported `negative` against a target that is
  fully exploitable -- the one failure this tool exists not to produce.

  Measured against Tomcat 8.5.19 (CVE-2017-12615), writing the probe by PUT and
  fetching it back. `97233*38786` was served as `-523688158` where RCEKit
  expected `3771279138`; `4721*8093` came back as `38207053`, exactly. The
  operand range drew a pair whose product overflows in **56%** of runs, and the
  operands are drawn once per run, so there was no second probe to recover: more
  than half of all runs against a JVM or .NET target lost.

  The operands are now 4 digits apiece, which caps the product at 99,980,001 --
  the range `eval` has always used against these same targets. Nothing about the
  oracle changes: the product is still bracketed by two random tags and still
  differenced against a payload-free control, which is what makes it unforgeable
  rather than its magnitude.

  The same run confirms now. `RKYBRDH<%=3253*8793%>RKICSMR` came back as
  `RKYBRDH28603629RKICSMR` from the fetched file, and `write` reached
  `confirmed` against real software for the first time.

  Two tests, both written first and watched to fail: the drawn operands multiply
  to something a signed 32-bit int can hold, across 400 seeds; and a store whose
  evaluator wraps to 32 bits the way a JVM does reaches `confirmed` rather than
  `negative`. A third test had pinned the operand width with a hard-coded
  `\d{5}`; it reads the declared range now and asserts the operands fall inside
  it, which the digit count had only implied.

## [2.45.6] — 2026-09-26

### Fixed

- **The `write` probe carried whitespace, and some sinks tokenise before they
  write.** The file content this method delivers is a language one-liner, and
  its templates spelled the expression with spaces around it -- `<?= a*b ?>`,
  `<%= a*b %>`. The content goes through the operator's own injection point, and
  a sink that splits its input on whitespace never writes a valid file.

  Measured against RRDtool 1.7.2, reached through Cacti 1.2.28's
  `right_axis_label` (CVE-2025-24367), which builds the file from a
  `LINE1:out:<content>` argument. `RKAAA<?=7*6?>RKBBB` wrote a 47-byte file with
  the content intact. `RKAAA<?= 7*6 ?>RKBBB` wrote no file at all and answered
  `ERROR: '7*6' is not a valid function name in 7*6`. The whitespace was the
  whole difference.

  Whitespace inside `<?= ?>` and `<%= %>` is optional, so the templates drop it:
  nothing is lost and every sink of that shape is gained. Verified end to end
  against the real sink rather than a fixture -- RCEKit generated
  `RKYOOQS<?=69294*83370?>RKGFZQP`, RRDtool wrote it whole, and PHP answered
  `RKYOOQS5777040780RKGFZQP`, which is the value RCEKit had computed for that
  probe.

  `jspx` keeps its spaces: it is an XML document whose root element carries
  namespace attributes, and a sink that tokenises on whitespace was never going
  to carry one. Two tests pin the rest -- the generated probe and the templates
  themselves -- both written first and watched to fail.

## [2.45.5] — 2026-09-25

### Fixed

- **The `deser` shape differential answered from evidence it had not
  validated.** Three ways, each found by pointing the method at a live
  fastjson 1.2.83 endpoint under vulhub and asking why it said what it said.

  **Drift landed on whichever form went last.** The differential is read across
  requests, so anything changing with the request *index* rather than with the
  payload -- a rate limiter backing off, a filling log, a warming cache -- fell
  on the form sent last, and noise was sent last every time. There are two
  noise probes now, first and last, bracketing the structured pair. They are
  one noise body sent twice, byte for byte, because the bracket asks whether
  the endpoint answered *the same probe* alike and anything the target can see
  a difference in it may answer a difference to: a tail beginning `n` made
  fastjson say "error parse new" where every other tail said "syntax error".
  A carrier whose two ends disagree is held at `inconclusive`. The engine
  de-duplicates by payload on the per-probe path but not on the aggregate path
  where `deser` lives, which is what makes one body twice possible; a test pins
  that, because the bracket becomes a single request if it ever changes and a
  drift check comparing an answer with itself passes forever.

  **An endpoint echoing its input looked like a parser.** A response carrying a
  fragment of the payload that begins at the format's magic, and not carrying
  it in the payload-free control, is an echo and the shape channel cannot be
  read through it -- `inconclusive`, not `negative`, because the channel was
  unreadable rather than empty. The sentinels are anchored on the magic's
  position in the payload rather than its start, since a probe is wrapped for
  its injection context first and some wrappers are longer than the magic: an
  `xml_cdata` pickle probe begins `<![CDATA[gASV`. They are matched raw, case
  folded (because `_signature` folds case and the two halves of one oracle must
  agree), and encoded -- base64 aligned on bytes rather than characters and
  read from the first three-byte boundary at or past the magic, hex from the
  magic itself.

  **A format declaring no magic got a verdict anyway.** Without a magic there
  is no sentinel, so an echoing endpoint cannot be told from a parsing one --
  and the differential answers regardless, because the noise form is random
  where a structured pair is not. Every shipped format declares one; a
  `--template-file` need not, and the answer to a control that cannot be
  validated is to say so.

- **The page an operator plans traffic from still described three payloads.**
  The bracket makes the shape oracle send four per ecosystem -- 20 requests per
  carrier rather than 15, with the five the corpus ships -- and
  `docs/reference.md` and the method's own docstring both still said three.
  README advertises an execution plan that prints the exact probe count before
  anything fires, so a page that undercounts it breaks that promise in the one
  place someone reads before a monitored engagement.

  Both now state four, and the arithmetic, and what the repeated probe is for.
  A test holds the page to `SHAPE_FORMS` and to the ecosystem count, in both
  directions: adding a form without updating the page fails it, and reverting
  the page without touching the code fails it too. Nothing compared the two
  before, which is how the count drifted the moment the form was added.

- **The `negative` evidence line described a comparison it had not made.** "The
  endpoint answers all three forms alike" was asserted rather than observed.
  It now names what actually collapsed: every form alike, a truncated stream
  answered as a complete one, or the noise form answered as a structured one.

### Withdrawn before release

- **A second route through the differential, reading noise as the control.** It
  was written for the shape fastjson has -- a format resolving its type name
  before the parse finishes answers a truncated stream exactly as it answers a
  complete one, which collapses the original comparison on the very endpoints
  it exists to find -- and it did reach `needs-review` there.

  It is not in this release. "Noise differs from the structured pair" has too
  many explanations that are not a parser. Drift and echo are closed above. The
  third is not: a filter that refuses the random payload while letting the
  structured ones through produces the same differential, no repetition exposes
  it because the refusal is stable, and this verdict cannot see it -- refusal
  is judged against the probe the verdict is anchored to, and that is the
  well-formed one.

  A format of that shape is reported `negative` by the shape differential and
  reaches `deserialization-sink` through the DNS gadget instead, which is this
  method's real oracle and rests on a callback rather than on the shape of a
  response. Measured on the same target: 14 callbacks, each carrying a token it
  could only have learned by resolving the name it was handed.

## [2.45.4] — 2026-09-25

### Fixed

- **A compressed response body is a body the oracles cannot read, so a target
  that executed the probe was reported `negative`.** Every in-band oracle --
  `reflected`, `eval`, `file`, `write`, `boolean` -- confirms by finding a
  value the target computed in the response. Nothing in the delivery layer
  undid `Content-Encoding`, so a gzipped body arrived as bytes that *contain*
  the computed value and do not spell it, and the search for a decimal number
  came back empty. The verdict was `negative`: not "could not read this", but
  "the probes reached the target and it is not vulnerable".

  Measured against Apache HugeGraph 1.2.0 under vulhub. The probe
  `echo RKPDSWY$((258675+956113))RKIEMTB$(echo RKLUQKL)RKPDSWY`, delivered
  through the Gremlin API, came back HTTP 200 carrying
  `RKPDSWY1214788RKIEMTBRKLUQKLRKPDSWY` -- the sum and the substitution
  collapse, both of `ReflectedMath`'s proofs. Present after gunzip, absent in
  the raw bytes, and the run reported `negative` across 620 probes.

  What made it survive this long is that the same target confirmed on the same
  run's *other* probes: HugeGraph gzips its 200s and leaves its 4xx errors
  plain, so `eval` confirmed through a 400 that carried a Groovy exception
  message while the 200 that carried real command execution was invisible. A
  run that finds something is a run nobody rereads.

  Both HTTP entry points decode now -- the verification/detection path and the
  `--verify-chain` path -- through one helper, on the success body and the
  `HTTPError` body alike, since an evaluator surfacing its value in a 500 is
  the case that path exists for. The header is honoured whether or not RCEKit
  asked for it, because HugeGraph compresses a response to a request that sent
  no `Accept-Encoding` at all.

  `gzip` and `deflate` only, both from the standard library, and `deflate`
  tries the zlib wrapper before the raw stream because servers disagree about
  which one that name means. `br` and `zstd` need a third-party module and this
  tool has none to add; a body in either is returned as its raw bytes. Nothing
  here raises: a body that claims an encoding it is not in comes back
  undecompressed rather than ending a run that has already spent hundreds of
  probes.

  This does not widen what `confirmed` means. The oracle is unchanged -- a
  computed value present in the response and absent from a payload-free
  control -- and nothing is promoted into it. What changes is that the response
  the oracle reads is the response the target sent.

- **Decompression is bounded, because compression is where the target chooses
  how much memory RCEKit allocates.** Reading a body at all is new here, and
  one-shot decompression handed a blank cheque to the one party in the exchange
  that is untrusted by definition -- the thing being tested. Measured: 130,478
  bytes of gzip expand to 134,217,728, and 203,860 bytes hold 200 MB of zeros,
  a ratio of 1:1028. This path runs once per probe.

  The ceiling is 32 MiB per encoding step. Whatever was produced before it is
  kept rather than discarded: the value the oracle wants is short, so searching
  32 MB is a far better answer than searching nothing, and the only risk the
  ceiling carries is a false negative -- never a false `confirmed`. A truncated
  read is logged rather than passed off as a clean one, since a `negative`
  decided on a partial body is not the same claim as a `negative` decided on
  the whole of it.

  Multi-member streams are still followed. `gzip.decompress` followed them, and
  a ceiling that quietly became a truncation for a server that concatenates
  members would be the same false negative in a new place.

## [2.45.3] — 2026-09-24

### Fixed

- **A `deser`-only run started no listener, so its gadgets went out with
  nothing to receive them.** `--methods deser --oob-host <delegated-name>`,
  with neither `oob` nor `lookup` selected, built its two DNS-gadget probes and
  sent them to a target while no listener was running -- with the host
  configured perfectly. `deser` reached `deserialization-sink` only when it
  happened to be selected beside a method that required a host; run on its own,
  the way the docs present it, its strongest oracle was structurally dead and
  it capped at `needs-review` without saying so.

  The gate read `needs_oob_host`, which was answering two questions at once:
  "should the run stop when no host is named" and "does this run need a
  listener". Every other method answers both the same way. `deser` is where
  they come apart -- its shape oracle proves something with no listener at all,
  so a missing host must not stop the run, while its DNS gadget does call back
  and needs one.

  So the second question gets its own attribute, `uses_oob_host`, and the
  listener starts for any selected method that calls back once a host is named.
  It is declared rather than derived: `needs_oob_host or oob_needs_dns_label`
  gives the right answer for every method shipping today and would miss one
  that called back over HTTP without requiring a host -- which is the shape
  `oob` itself would have if its host were optional.

  Two notices could now reach a run with no HTTP shape in it, and said "only
  the HTTP shapes are live" as though `oob`'s channel were the only one. They
  say "only the shapes that need no DNS are live", which is true of `oob`'s
  HTTP probes and of `deser`'s shape oracle alike. The message for an
  unbindable HTTP port no longer names `lookup` as the reason a run continues.

  `uses_oob_host` is the default answer rather than the answer. Whether a
  method calls back can depend on its own flags: `--deser-formats` selects the
  ecosystems, and three of the five -- `php`, `dotnet`, `python_pickle` --
  ship no DNS gadget at all. So both callers ask `builds_callback_probes()` on
  a configured instance instead of reading the class. `--deser-formats php`
  with an address no longer draws a notice blaming the address, because there
  was no callback probe to lose and a delegated domain could not have helped;
  and it no longer starts a listener that nothing would reach.

  Whether the host's *form* is one a method can use is a second question,
  `can_use_oob_host()`, and only the gate asks it. A listener bound for
  `--methods deser --oob-host 10.0.0.9` receives nothing -- `build_probes`
  drops an address and sends no gadget -- and the run announced "the target
  will open outbound connections" directly beneath the notice saying those
  probes are not sent. It stays out of `builds_callback_probes()`, because the
  stranded notice is *about* the address and an address test there would
  silence it for the one case it exists to report.

  `lookup` with an address stops getting a listener too. It built no probes
  with one either way, so nothing is lost, and the stranded notice says more
  about that run than the port-53 warnings it no longer reaches.

  A flaky test met on the way, fixed here because it would have bitten CI
  sooner or later: the fake parsing endpoint behind the `deser` shape
  differential sniffed one byte (`raw[4:5] not in (b"t", b"s")`) to decide
  whether a stream was well-formed. The `noise` form is the format's magic
  followed by random characters, so it passed that check about once in 500
  runs -- measured at 398 in 200,000 -- all three forms answered alike, and
  the oracle's correct `negative` failed a test that wanted `needs-review`.
  The endpoint now reads TC_STRING the way a parser does, a two-byte length
  followed by exactly that many bytes: 0 collisions in 500,000 seeds. Seeding
  the test's RNG would have hidden it instead, and would have gone on hiding a
  real regression in how the noise form is built.

  This is the second half of #94, found while fixing the first and reported as
  #98 rather than folded into #97: same defect -- probes sent that no callback
  could follow -- reached by a different route. The format-dependent part came
  from an automated review of #97 and the host-form part from one of this
  change, both verified before being accepted.

## [2.45.2] — 2026-09-24

### Fixed

- **`deser` fired DNS gadgets at a host that could not resolve, and the warning
  built for exactly that stayed quiet.** `--oob-host` takes a delegated name or
  an address. `oob` uses either: given an address it drops its DNS shapes and
  carries the token in a URL path instead. `lookup` refuses an address
  outright, because a lookup expression has nowhere else to put one.
  `DeserSink` had neither behaviour -- it built `<token>.10.0.0.9` and sent it,
  a real request the target answered from which no callback could follow by
  construction, and then capped at `needs-review` without saying why.

  `oob_channel_warnings` is the function that exists to say a DNS channel is
  structurally dead. It returned early on an address literal, reasoning that
  such a run "never builds DNS probes and has nothing to warn about" -- true of
  `oob`, and written when `oob` was the only method taking the flag. So the one
  mechanism that could have reported this was the one place it was ruled out.

  Both halves are fixed together, because either alone still ships the problem.
  `deser` treats an address as no host and sends its shape oracle alone, which
  is what it can prove without a listener anyway. The notice moves into
  `oob_address_strands`, which names the methods an address stranded and the
  tier that puts out of reach, read off each class.

  It is a separate function rather than another branch of
  `oob_channel_warnings` because the two answer different questions at
  different times. "Can the DNS shapes reach this listener" is only worth
  asking once a listener exists, and that block runs only for a method that
  *requires* a callback host. `deser` does not require one, so it never
  reaches that block -- a notice left there could not have fired for the
  method that prompted it. The new check runs on every verification run that
  names a host.

  Which methods those are is a class attribute now, `oob_needs_dns_label`,
  declared beside `needs_oob_host`. Deciding it at the one place that asked is
  how the two drifted apart to begin with.

  The test that pinned the old silence asserted "no DNS shape is ever built" --
  a claim about `oob` wearing the shape of a claim about the flag. Its scope
  narrows to `oob`, and the stranded case gets tests of its own.

  Found while verifying an automated review finding on #93; reported as #94 and
  deliberately kept out of that documentation-only PR.

## [2.45.1] — 2026-09-24

### Fixed

- **`--max-payloads` is a bound on requests, and it was being checked after
  they had been sent.** The cap was measured against the number of result
  *rows*. For a method that answers from each probe those are the same number,
  so nothing showed. An aggregate method reports one row however many probes it
  cost, so the whole series went out and the cap noticed afterwards:

  | `--max-payloads 1` | the cost line said | requests sent |
  |---|---|---|
  | `reflected`, `eval` | 1 | 1 |
  | `time` | 1 | **12** |
  | `deser` | 1 | **15** |
  | `boolean` | 1 | **27** |

  A clean split: every aggregate method overran and no per-probe method did.
  That line is the only thing an operator bounding a monitored engagement has
  to go on before the traffic starts, and it was wrong in the direction that
  matters — under, not over.

  Rows were the wrong meter in a second way, which the first fix exposed. A
  series the budget declines costs requests and produces no row at all, so the
  next carrier recomputed the same allowance and fired again — `time` at
  `--max-payloads 5` sent 4 requests per carrier with the cap never moving. And
  in a mixed run, a per-probe method never saw what an aggregate one had
  already spent: `boolean,eval` at 30 sent 56. The budget is counted in
  requests for the whole call now. Swept across every method this build can run
  without a callback host, alone and in combination, at seven caps: 63
  combinations, worst overrun 0.

- **A measurement that cannot be finished is no longer started.** What a budget
  may do to a series depends on where the method's answer lives, and the class
  already knows: `DetectionMethod.decides_per_probe()` reads it from whether
  the class overrides `confirm_each`, rather than from a list of names that
  would go stale like every other one in this repository.

  Where each probe answers — `deser`, `lookup`, `oob` — running out of budget
  stops the series and the probes already sent keep their verdicts. Where only
  the series answers — `time`, `boolean` — a part of one is not a weaker answer
  but a wrong one: `time` reports `negative` from a screen with no regression
  behind it and from a regression short of four samples, and a `boolean` series
  whose anchors never went out reads the same way. Both are false cleans, and
  the budget would have been manufacturing them. So a wave that does not fit
  abandons the measurement rather than cutting it short.

- **An abandoned measurement leaves an `inconclusive` row, not a silence.**
  Dropping it quietly let the *other* carriers describe the run, and the other
  carriers are the ones with nothing to find: measured at `--max-payloads 12`
  against a sink that honours an injected sleep, the unix carrier's regression
  was abandoned for budget and a windows carrier's honest "no separator
  delayed" was the only row left — so the run reported `negative` for a target
  that was vulnerable. `inconclusive` is what an abandoned measurement is in
  the word the tool already uses, and it outranks `negative` in the run
  verdict. Swept across 31 caps against a sink that really does delay: no cap
  reports it clean, and none overruns.

- **What the budget declined is reported by name**, in a sixth run-wide tally
  beside the profile drops, the safety holds, the reach notes, the settled
  carriers and the refusals. A ladder that shrinks quietly is indistinguishable
  from a target with nothing to find:

  ```
  [detect] --max-payloads held back 1 measurement(s) that could not have reached a
           verdict within the budget:
  [detect]   1 x boolean/raw needs 7 requests to reach a verdict and --max-payloads left 3
  [!] No probes were built, so NOTHING WAS TESTED - this is not a negative result.
  ```

- **The cost line and the run make the same decision.** `estimate_detection_probes`
  applies the same all-or-nothing rule, so under a cap the figure printed before
  the traffic is the traffic. Uncapped it stays a floor by documented design — a
  wave a method picks after seeing its own timings cannot be predicted from
  there.

- **`sent N probes` is a claim about what the target received**, and it was
  counting result rows. Those are the same number for a method that answers
  from each probe, which is why it read true for so long -- but an aggregate
  method reports one row for a whole series, so a `time` run that put 20
  requests on a target announced 5, and a measurement this release declines
  would have announced one probe for traffic that never left. Both the run
  summary and the per-point line report deliveries now, with the result count
  beside them.

  One figure in the 2.45.0 entry below came from that line and was mislabelled
  with it. Re-measured against the same sink: `--methods reflected,eval,time`
  put **2883** requests on the target, not 2426, which was the number of
  results. Every one of them was still `negative`, so the claim stands; the
  number did not.

- **An evasion retry is a request, and the meter could not see it.** `_escalate`
  fired without incrementing `delivered_probes`, so retries were traffic
  outside the bound this release makes real: measured at `--max-payloads 5
  --evade high` against a filter that refuses whitespace, the target received
  12 requests and the run recorded 5. Counting them was half the fix. The other
  half is that the budget is checked *per rung* rather than once before the
  ladder -- one refused probe is retried at `low` and again at `high`, so it
  can cost three requests, and a check at the call site alone still overshot by
  one at `--max-payloads 10 --evade high`. Swept over caps 1 to 25 at all three
  evasion settings: 75 combinations, no overrun, and the counter equal to the
  requests the target actually received in every one.

### Security

No authorization, deny-by-default or matrix-evaluation boundary moves, and
nothing widens `confirmed`. The effect is one-way: fewer requests than before,
and a run that could not afford to test something now says so instead of
reporting it clean.

## [2.45.0] — 2026-09-23

### Added

- **`--methods boolean` — a sink that evaluates a predicate and renders nothing
  of it.** MongoDB `$where` is the shape, and this repository has carried the
  note for two releases: a JS sandbox with no shell, no egress and no value in
  the response, only a document set that a predicate narrows. Every shipped
  oracle is structurally blind to it. Measured against exactly that sink:

  ```
  [detect] methods: reflected, eval, time
  [detect] sent 2426 probes: negative=2426
  ```

  2426 requests and a clean negative on a target that evaluates whatever it is
  handed. The new method reads the one channel left — whether the *shape* of the
  response changed between a true predicate and a false one.

  **It is `needs-review` and there is no path from here to `confirmed`.** Not
  because the signal is weak, but because of what it cannot distinguish: against
  a sandboxed `eval` sink and against a plain SQLite comparison it produced an
  identical clean differential in 40 runs each, and a query engine comparing two
  numbers is not remote code execution. Extracting a locally computed product
  bit by bit through the channel was tried and does not fix it — it recovers the
  product through both sinks alike, for about 80 requests and a string function
  a sandbox may well deny.

  **The naive form of this oracle is unusable**, which is why none of it is.
  `1==1` against `1==2`, with a changed response read as a finding, called a
  target that only *reflected* its input vulnerable in 40 runs out of 40, and
  one whose response merely wobbled in 32 of 40. Four guards, each a measured
  false-finding rate rather than a precaution:

  - **Compare structure, not the body and not its length.** A reflected payload
    lands in the text between two tags, and the text between two tags is what
    the signature throws away. A length-based signature claimed a differential
    in 13 of 25 runs against a reflect-only target; comparing raw bodies was
    unusable outright, reading `unstable` in 25 of 25 runs against a target that
    *was* vulnerable, because one CSRF token makes every response unique.
  - **Several independently randomised pairs, not one.** Against a target whose
    response varies on its own, one pair claimed a differential in 46 of 200
    runs; two claimed none in 200. `--probe-depth quick` trades four pairs for
    two and never for one.
  - **Randomised firing order.** A target that never reads the payload but
    degrades part-way through a run splits an ordered true-then-false series
    perfectly: at the worst point of a swept degradation, 100 false findings out
    of 100.
  - **An anchor before and after the series, each a different true predicate.**
    Shuffling alone still left 2 in 100, which is just the chance a shuffle
    lands separable. Re-measuring the channel afterwards caught it 100 times in
    100, because a target that moved during the series cannot answer the
    closing anchor the way it answered the opening one. Sending *one* anchor
    payload three times does not merely weaken that: a cache keyed on the query
    string answers the repeats from its store, so the closing anchor agrees
    with the opening one whatever the target did in between. Measured against
    an input-blind target that degrades mid-series, identical anchors caught it
    in 36 of 39 runs live and in 0 of 39 behind a cache. Every probe payload is
    unique, so nothing else in the series is replayable.

  With every guard on, a genuinely evaluating target still read as a
  differential in 100 runs of 100.

- **A channel that cannot carry one bit is `inconclusive`, never `negative`.**
  If the same probe draws two different shapes, or the shape moves while the
  series is being fired, the run says so. `negative` asserts the probes reached
  the target and found nothing; here they reached it and no answer could be read
  out of them, which is the same false clean `blocked` and `nothing-tested`
  exist to prevent, one oracle further in. No new verdict: there are still nine.

- **`response_shape()`** — a response reduced to its structure, with everything
  it said removed. Three readings, because a response is one of three things and
  the wrong reading is not a near miss: a JSON document keeps its keys, nesting
  and list lengths and drops every scalar; markup keeps its tag skeleton;
  anything else keeps one marker per word per line. Measured on a JSON sink, the
  markup reading was unusable — `unstable` in 25 of 25 runs — and the shape tree
  read the differential in 25 of 25.

### Changed

- **`CODE_POSITION_CONTEXTS`** names the contexts that carry the injected value
  as code rather than as a value, and `boolean` is offered every other one. The
  first cut of this asked whether the context had a break-out prefix at all, and
  got both halves wrong: it refused `attribute`, `attribute_unquoted`,
  `xml_cdata` and `yaml`, whose delimiters open and close *around* the value and
  leave a predicate exactly where a predicate belongs, and it offered
  `unix_shell`, `windows_cmd` and `powershell`, which have no delimiters at all
  and run the value as a command. The suite enumerates both sides, so a context
  added to the corpus fails until somebody decides which one it is on.

- **`costly` now asks whether one probe buys an *answer*, not whether it costs
  more than one response.** The two were the same question while every method's
  probe was also its unit of information. `boolean` is the first where they come
  apart: each of its probes is one ordinary request and none of them means
  anything alone, because the answer is the partition across the whole series.
  Read the old way it would have landed in the wave the enumeration driver runs
  *first* — the one that exists to be answered cheaply — ahead of `reflected`
  and `eval` and spending the same per-question budget, at 27 requests before it
  could say a word. It sits with `time` instead, and the suite now holds every
  aggregate method to that.

### Security

- **The `OR` connectives ship behind `--verify-active-risk stateful`.** A
  predicate probe breaks out of a condition the application already wrote, and
  the connective is this method's command separator. `AND` differentiates only
  where the application's own predicate is true and `OR` only where it is false,
  so they are complements and dropping `OR` is a blind spot rather than a
  saving. But a true predicate `OR`-ed into a `DELETE … WHERE` took a table from
  3 rows to 0, where the same predicate `AND`-ed into it left all 3 — so it goes
  at the top rung, held back by default, with the run naming every shape it held
  and the flag that sends it. `AND` and the bare form stay `safe` and change
  nothing.

- **Nothing widens `confirmed`.** The new method's ceiling is one tier below it
  and the suite holds that as behaviour, not as an attribute: `confirm_series`
  is driven across 200 series including the perfect one, and none of them
  reaches `confirmed`.

## [2.44.0] — 2026-09-23

### Fixed

- **`--evade low` substituted inside quoted programs and broke them.** Every
  space became `${IFS}`, including the ones inside `awk 'BEGIN{print "RK" a+b
  "RK"}'` — and inside single quotes `${IFS}` is literal text, not an
  expansion, so awk was handed `BEGIN{print${IFS}"RK"...` and answered with a
  syntax error.

  Measured shape by shape against an unfiltered target: **8 probe shapes that
  the canonical form executes broke at the rung, and none improved.** The
  substitution stops at a quote now. Double quotes are left alone from the
  other side — `${IFS}` *does* expand inside them, so substituting there would
  change the string the target computes rather than the spacing around it.

### Changed

- **A rung is a retry for a refused probe, not a posture for the run.** It was
  applied to every probe regardless of whether anything was being filtered,
  which is a pure loss on a target with no filter. Against a filter that blocks
  whitespace it turned 1 confirmation into 5; against an unfiltered target it
  now costs **zero** extra requests, because nothing was refused.

  `--evade` is therefore a **ceiling**. Every probe goes out canonical, and
  only a refused one is retried, up to that ceiling — at most one request per
  rung. The ladder a run builds no longer depends on the rung at all: all three
  settings build the same 42 probes, of which the same 32 execute. Before, the
  rung built a smaller ladder and 13 fewer of its probes ran.

  The run reports how many retries it made and which rung got through, whatever
  it concluded — including a run that confirmed, where the retry is the reason
  it did.

### Added

- **A second evasion rung, `high`.** The measurement turned up two classes of
  filter and the shipped rung only addressed one. `low` removes whitespace;
  `high` also splits the command word with an expansion that vanishes
  (`ec$@ho`), for a filter matching command names. It is applied before the
  whitespace substitution, because afterwards the split lands inside `${IFS}`
  and makes `${I$@FS}` — neither an expansion nor a command.

  Four boundaries the retry has to respect, each of which was a way to turn a
  vulnerable target into a `negative` — worse than the `blocked` the rung sits
  beside, because `blocked` at least says the run learned nothing:

  - **Unix shell probes only.** `${IFS}` and `$@` are POSIX. A cmd.exe probe
    rewritten with them loses its spaces, so a whitespace filter answers 200
    and the retry counts as a win while cmd.exe cannot run it.
  - **A break-out context opens by *closing* a quote.** Reading that leading
    quote as an opener left `'; echo …` untouched, so the rung did nothing on
    exactly the contexts a filter is most likely to sit in front of.
  - **A followup is read again after a retry that lands.** `file` writes its
    token on the request that arrives, so a body read before the retry is a
    read of a file that did not exist yet.
  - **A redirect is never retried.** The build-time transform took an explicit
    `evade=False` for these, and that parameter stopped doing anything when the
    rung became a retry — a guard lost in the move, restored where the retry
    now happens.

  The aggregate methods escalate too. `time`, `oob`, `lookup` and `deser` take a
  different branch, and leaving it out meant the documented ceiling did nothing
  for four of the eight methods — the same branch, and the same omission, as the
  refusal check one change earlier.

## [2.43.0] — 2026-09-23

### Added

- **A ninth verdict: `blocked`.** A run whose payloads a filter refuses has
  learned nothing about the sink, and it used to say otherwise. Measured
  against a real command injection behind a filter that 403s a space or a
  separator:

  ```
  before:  sent 10 probes: negative=10
  after:   sent 10 probes: blocked=10
  ```

  `negative` asserts that the probes **reached** the target — the project's own
  tier rule says so. They reached a filter. That is the same false clean
  `nothing-tested` exists to prevent, one level further in.

  **The signal is differential**, like everything else this tool decides: the
  payload-free control got through and the probe did not, so what was refused
  is the payload. An endpoint answering 403 to everything — an auth wall, a
  path that does not exist for this session — refuses the control too and is
  not mistaken for a filter. Verified against exactly that case.

  4xx only. A 5xx is as likely to be the payload *breaking* the application,
  which means it reached something, and reading that as blocked would hide the
  one response saying the sink is live. No vendor list and no block-page
  fingerprints: a status the control did not get is the whole signal.

  A run where **some** probes got through stays a real `negative` — the sink
  saw those — and the refusals are reported either way.

  **A refusal never unmakes evidence.** Only a `negative` is replaced, because
  it is the only verdict a refusal contradicts. An application can execute the
  payload and then answer 400 with the output in its body, and the oracle has
  already proven execution from a value random to that probe; overwriting that
  would turn demonstrated RCE into a false negative, which is worse than the
  false clean this verdict removes.

  **Every method is covered, including the three that decide per probe from a
  series.** `oob`, `lookup` and `deser` take a different branch, which returned
  before refusal was considered — so a callback run whose every probe was
  refused reported `negative` for each of them, because no callback arrived.

  Refusals are counted in **requests**, like the status tally beside them: an
  aggregate method fires a whole ladder and reports one row, so counting rows
  described the same run with different arithmetic and hid a partly filtered
  series entirely.

### Fixed

- **The advice on a filtered run pointed at the wrong thing entirely.** "The
  target may be patched" reads as a clean bill of health for a target that was
  never reached; the blind-sink list names methods a filter refuses in exactly
  the same way; and the second-order line said the target *accepted* an input
  it had in fact rejected with a 403. None of the three fires on a refused run
  now. It is replaced by what was actually observed, with the flags that change
  the payload's shape.

## [2.42.0] — 2026-09-23

### Added

- **A run that confirms nothing now names the second-order oracle.** Measured
  against a target that stores on one endpoint and renders through a shell on
  another — a real RCE — every probe read `negative`, and the run answered with
  four methods that are all negative there too, because the execution does not
  happen on the request being measured:

  ```
  --methods time   -> negative=4
  --observe-url    -> confirmed, first run
  ```

  The one flag that works was named nowhere. It is named now, and **not gated
  on which methods have run**: the blind-sink list is, so an operator who had
  already tried the expensive methods — exactly the one with nothing left but
  second order — was told only that the target might be patched.

  The wording follows what the run observed rather than what it assumes. Input
  returned verbatim means a sink that reflects without executing; input that
  never came back means this response cannot show what became of it; and a run
  of aggregate methods alone, which record no per-probe observation, claims
  neither. A swallowed input is equally a blind sink or a stored one — `ping
  <input> >/dev/null` returns nothing either — so both are named and neither is
  picked.

- **Whether the target returned the input is recorded on every probe.** It was
  already computed on the confirmed path, where it becomes "target also
  reflects the payload verbatim"; a negative probe never looked, and the
  negative run is the one that has to say what it saw.

  Measured against the payload that actually went out. A carrier that
  multiplies through a filter never spells the joined `a*b` out — Liquid sends
  `{{ a | times: b }}` and Django `{% widthratio a 1 b %}` — so an endpoint
  echoing the whole payload recorded a measured `False`, and a target profile
  filtering the `*` shapes leaves only those, at which point the run would
  report "returned none of it" about a target that returned everything.

  Recorded only when there was a response to look at. A delivery error is not
  an observation, and a `False` for one would put an unmeasured claim exactly
  where the unobserved branch belongs.

## [2.41.0] — 2026-09-23

### Fixed

- **A candidate that confirmed RCE was never asked whether it was also a
  deserialization or lookup sink.** The enumeration driver split the methods
  into a cheap wave and an expensive one and skipped the expensive wave once
  execution was proven — reasonable for `time` and `oob`, which would only put
  a second name on one finding, and wrong for `lookup` and `deser`, which
  report *different properties* with their own remediation. They sat on the
  expensive side of a hand-written set of names, so the answer was never asked
  for and never reported.

  The split now comes from the tier each method declares. Anything reporting
  `confirmed` or `needs-review` is answering *did this target execute my
  input*; anything else is a different question and is never skipped for an
  answer to that one.

- **`--max-payloads` is spent per question, not per wave and not per
  candidate.** Per wave it quietly doubled: a run capped at 5 sent 10 probes to
  every candidate that did not confirm, while the cost line printed before any
  traffic said 5. Bounding the candidate instead starves the different
  question — the cheap methods eat the whole allowance and `deser` never runs,
  which is the same finding lost by another route. Every method asking about
  execution now shares one allowance, each different property gets its own, and
  the cost line names how many questions are being asked — and **sums** the
  estimate across them. Counting the cap once while the run grants it per
  question advertised 44 requests for a run that sent 80, which is wrong in
  the direction that matters for the operator bounding a monitored engagement.

- **A second-order confirmation settles its carrier too.** With `--observe-url`
  a probe can read negative in the response it drew and `confirmed` on the
  observed channel a moment later. The stop was decided from the pre-poll
  verdict, so the carrier kept probing after it had in fact confirmed —
  spending the budget the stop exists to hand to carriers not yet examined,
  which is the coverage loss this change was written to remove, reappearing on
  the one oracle that needs a second request to answer.

### Changed

- **A carrier that has confirmed stops there** (`--confirm-depth first`, the
  new default). One carrier is one method in one environment and context, and
  once it has confirmed every further shape of it can only say the same thing
  again.

  Measured against an executing target: one candidate spent 115 of its 120
  probes after the first confirmation, and printed 32 confirmations of which 29
  were duplicates inside a single carrier. Those probes were not idle — they
  were spent instead of reaching carriers never examined at all. At the same
  budget the run went from **4 carriers examined to 23**, and from **4
  environments reached to 9**. This buys coverage rather than saving requests.

  The stop is per carrier and **never** per candidate: a candidate may confirm
  as `unix` while a later `nodejs` carrier is the only thing a different target
  would have shown. `--confirm-depth every` maps every shape a sink accepts,
  which is what writing a proof of concept by hand needs, and the run reports
  how many shapes it held back and which carriers stopped — a fourth tally
  beside the profile drops, the safety holds and the reach notes, because it
  says a fourth thing: the probe could have been sent and had nothing left to
  establish.

- **A method declares what one of its probes costs.** `CHEAP_DETECTION_METHODS`
  was a set literal; it is now derived from a `costly` attribute each class sets
  for its own reason — a real sleep, a wait for a callback, a second fetch.
  Every hand-written list naming methods in this repository has gone stale, and
  this one had put `lookup` and `deser` where being skipped cost findings.

## [2.40.0] — 2026-09-22

### Added

- **A carrier may take the operands apart, and two engines need it.** Every
  expression carrier until now substituted `__EXPR__` — the joined `a*b` —
  which quietly assumed the engine has an arithmetic operator. Two widely
  deployed ones do not, and both were measured as false negatives:

  ```
  liquid    every bare form missing; {{ 45013 | times: 45989 }}     -> 2070102857
  django    every bare form missing; {% widthratio 45013 1 45989 %} -> 2070102857
  ```

  Liquid multiplies with a filter and Django with a tag, so neither form can be
  written as a single expression — an application that really does evaluate the
  template was reported `negative`, which is the same shape as `oob` against a
  `${jndi:...}` sink: probes that reach the target and cannot speak its
  language. A carrier template may now use `__A__` and `__B__` as well as
  `__EXPR__`.

  Neither payload contains the product, so a target that merely echoes the
  payload still cannot read as `confirmed`. A test pins that for every shipped
  carrier.

### Changed

- **A carrier template not parameterised by both operands is skipped, not
  sent.** With no token at all it renders the same constant every probe; with
  only one operand the target is never handed the other, so nothing it can
  compute is the product RCEKit is looking for. Either way the product would
  not be evidence the target computed anything — and a probe that cannot
  confirm still counts toward the coverage a run reports, which is the part
  that matters more than the wasted request.

- **`--eval-engines` names every carrier the corpus ships.** Its help listed
  three engines by hand and two were added. An operator narrowing that flag
  reads the list and nothing else, so a stale one says an engine needs no
  carrier when it does, and they cut the only probe that could have confirmed
  it. A test now holds the help text to the corpus.

- **What the survey measured and did not ship is recorded too.**
  `eval_carrier_survey` in the corpus now names the engines that need no
  carrier — nunjucks 3.2.4, tornado 6.5.10, mako 1.4.1, chameleon 4.6.0,
  smarty 5.8.4 and Ruby's ERB all return the product from a bare form — and
  those that are
  out of reach. Handlebars 4.7.9 fails every bare form and, being logic-less
  with no built-in arithmetic helper, has no template text that computes a
  product at all. Go `text/template` 1.23 fails every bare form too, and the
  only forms that do return the product — `{{printf "%d" <product>}}` and
  `{{<product>}}` — hand the target the answer, so a target that merely echoed
  them would read as `confirmed`. That is the rule a carrier lives under: **a
  carrier may not carry its own result.**

  Saying so is worth more than a carrier that cannot work, and it stops the
  next person re-running the same survey — or shipping the Go form, which the
  survey itself produced and which looks like a carrier until you ask what an
  echoing target would return.

## [2.39.0] — 2026-09-22

### Added

- **Every part of a multipart body is an injection point.** None of them were
  before. The form branch matched on `=` appearing anywhere in the body, so a
  `multipart/form-data` capture was split on `&` and yielded exactly one
  candidate, named after a `Content-Disposition` line:

  ```
  form | '--X\r\nContent-Disposition: form-data; name' | body param '...'
  ```

  Every probe for that point rewrote a *part header*, so it could confirm
  nothing, while `user`, `avatar` and `note` — the fields the form actually
  posts — were never reached. The run still printed a point and a probe count,
  which is the part that matters: coverage reported and not delivered reads
  exactly like a clean target.

  Several parts may post under one name — a multi-file input and a checkbox
  array both do — so a part is addressed by its **index**, as a JSON leaf is
  addressed by its token path. Addressing by name alone rewrote the first part
  for every candidate, which is the same failure one level further in: three
  files, three points, the first file probed three times and the other two
  never touched.

  `multipart` is now its own kind, recognised from `Content-Type` and decided
  before the form branch can see the body. A file part is a candidate too — its
  content is the value under test, while its `filename` and `Content-Type` stay
  as captured. Verified end to end against a target that parses with the
  standard library's MIME parser: `multipart field 'note': confirmed`, with the
  non-vulnerable `user` field `negative` beside it.

### Changed

- **A GraphQL request is ordered by what can actually confirm.** Its variables
  were already enumerated — they are JSON leaves — but they were tried in
  document order alongside `query` and `operationName`, and those two cannot
  confirm anything. A payload in `query` *replaces* the operation document, so
  the server answers with a parse error before a resolver runs, and
  `operationName` then names an operation that is no longer there. On the
  capture this was measured against they were two points of five, each one a
  full probe ladder.

  They are moved behind the variables, **not dropped**. A server that logs the
  query document before parsing it is reachable through exactly that field,
  which is the route Log4Shell took through access logs, so a full run still
  tests both and `--max-points` now cuts the least likely to pay first. A plain
  `{"query": ...}` body with no `variables` is left in document order: it is as
  likely to be a search API, and there the query field is the one worth testing.
  Carrying both keys is not enough either — the `query` string has to open like
  a GraphQL document, so `{"query": "red shoes", "variables": {...}}` keeps its
  real injection point where a bounded `--max-points` run will still reach it.

### Fixed

- **The verdict table was missing a verdict.** The README said "seven verdicts
  that are never collapsed into each other" and listed seven, while the tool
  reports eight: `lookup-sink` was absent from the one table whose whole job is
  to enumerate them — in a README that uses the word two tables higher, in the
  Log4Shell CVE row, and again in the methods table. The sentence counted the
  rows the table had rather than the verdicts there are, so the omission never
  contradicted itself and nothing failed.

  Found by reading the README end to end for this change. A test now reads the
  table against `DETECTION_METHODS`, so a verdict a method declares and the
  table does not carry is a failure rather than a silence.

- **A multipart body now goes out with the line endings it needs.** `-r`
  normalises the whole request to LF, so the CRLF delimiters RFC 2046 requires
  were gone by the time anything was sent. Bodies rendered for a multipart point
  are re-serialised canonically — probe and payload-free control alike, so the
  two differ in the field under test and in nothing else. Part content is left
  character for character, so a lone newline inside an uploaded text file
  survives.

## [2.38.0] — 2026-09-21

### Added

- **A probe shape may reach past the run's tier and be sent anyway**, when its
  effect is one the run undoes by saying it happened. `reaches_past` is that
  declaration, beside `safety`, which stays for an effect a notice cannot take
  back.

  Reach wins where the two pull against each other. Detection the tool could
  have done and did not is a false negative wearing a safety label, and it
  costs more than the noise it saves.

  `deser`'s DNS gadget is the first of these, and closes an inconsistency
  recorded a version ago: it makes the target resolve a name -- the very thing
  `oob` and `lookup` are refused for at `safe` -- while its only gate was
  `--oob-host`. Holding it back would have sent fewer probes at the default
  tier. It goes, and the run reports how far it reached.

  Three tallies now, because they say three different things and one number
  would state the wrong one about all of them: the profile dropped it (it could
  not have reached the sink), the tier held it (it could, and was not sent), or
  it reached past the tier (it was sent, further than asked).

  `lookup`'s `ldap://` and `rmi://` are the edge the rule has, and stay at
  `stateful`: a class fetched from an address RCEKit did not choose is not
  something a notice takes back.

- **Two worked examples in the README's Quick start**, because the fullest run
  RCEKit can make was not shown anywhere near the front.

  The first is a captured request: most sinks worth testing sit behind a POST
  with a session cookie, a content type and a body, and `--verify-url` carries
  none of that. The second is everything the tool has -- injection-point
  enumeration across every value in that request, every method, callbacks, the
  top rung -- with a table of what each flag opens up and the cost line that
  prints before it fires.

  Both were run before being written down. The point the Quick start never
  made: `--auto-params` needs `-r`, so the fullest run is not reachable from a
  URL at all, which is worth knowing before concluding a target is clean.

## [2.37.0] — 2026-09-20

### Added

- **A detection method declares the risk rung it needs**, and the engine reads
  it. `SAFETY_ORDER` has labelled corpus payloads `safe` / `intrusive` /
  `stateful` from the start and the query-language bridges followed; detection
  methods did not. Each risky one was gated by a hand-written branch in
  `main()` naming it, so a new method meant remembering to add another -- and a
  probe shape with nowhere to declare its rung was deleted rather than gated.

  | method | rung | |
  |---|---|---|
  | `reflected`, `eval`, `time`, `deser` | `safe` | compute, delay, or parse |
  | `oob`, `lookup` | `intrusive` | makes the target open outbound connections |
  | `file`, `write` | `stateful` | writes to the target |

  `file` and `write` are gated by their own configuration rather than by the
  rung: neither does anything until a directory to write into and a URL to read
  it back from are named, which says more than a tier would, and asking for the
  flag as well would refuse a command that works today. Nothing that runs today
  stops running.

- **A probe shape may need a higher rung than its method**, so coverage that
  only makes sense at the top tier has somewhere to live instead of being
  deleted. **`--methods lookup` sends `ldap://` and `rmi://` again**, at
  `stateful`.

  They were removed in 2.36.0 on the argument that `dns://` resolves wherever
  `ldap://` would. That claim was too strong -- a filter catching the string
  `dns:` and not `ldap:`, or a trimmed runtime without the DNS provider,
  defeats it -- and a sink that takes one scheme and not the other is exactly
  the sink this method is for. The reason they were removed was real: they
  continue *past* resolution and connect to whatever address the answer named,
  which is not an address RCEKit chose. That is a rung, not a reason to drop
  coverage.

- **The run says what the rung held back**, counted apart from the target
  profile's drops and with the flag that would send it. The two say different
  things: a profile drop means the probe *could not have* reached the sink,
  while this means it could and the operator chose not to send it. Reporting
  them together would state the first about the second.

- **A method declares the weaker tiers it really reports**, not only its
  ceiling. `write` reports `needs-review` for a file that is served but not
  interpreted and `deser` for a shape fingerprint, and three separate places
  had to know that -- the documentation tests, the benchmark's expectation
  whitelist, and the advice printed after a clean in-band run. Each kept its
  own answer; the docs test exempted `needs-review` for *every* method, so
  `lookup` could name a verdict it never emits and pass.

### Changed

- **`--methods file` and `--methods write` with nothing configured now say
  so by name.** They were simply not applicable before, so the run built no
  probes and reported `nothing-tested` -- which is the quietest way this tool
  can fail and reads much like a clean target.

- **`docs/reference.md` carries a `Rung` column**, held against the class by a
  test. The tier column already was; this is the same claim one column over.

### Fixed

- **A config-gated method is not re-gated by the rung at runtime.** The
  pre-flight lets `--methods file --webroot ... --web-base-url ...` through
  because the configuration is the gate, but the probe filter read the run's
  default `safe` ceiling and held every probe inheriting the method's
  `stateful` rung. The CLI accepted a documented invocation and then reported
  `nothing-tested` -- the quietest way this tool can fail, and the thing the
  rung work was supposed to remove rather than add.

  Nothing caught it because every `file` test builds the method's config
  directly, without `max_safety`, so the ceiling fell back to the method's own
  rung and the probes went out. A run through the CLI with the channel
  configured is the one thing that would have, and there is one now.

- **The cost estimate applies the risk tier as well as the target profile.** It
  counted every shape a method built, so once a rung could narrow a method the
  pre-flight figure over-counted -- three times over for `lookup` at the
  default tier, which is exactly the operator who narrowed the run on purpose.
  Both paths share one predicate now, and it counts nothing, so an estimate
  never moves the numbers the report prints.

## [2.36.0] — 2026-09-19

### Added

- **`--methods lookup`: confirmation for an expression-lookup sink**, the shape
  Log4Shell has, where the sink resolves a URI instead of running a command.

  `oob` could not reach one. Its `applicable` does admit `java` -- a Java
  application can shell out, so the environment is genuinely shell-capable --
  but every probe it builds is a shell command: `nslookup`, `curl`, `certutil`,
  `iwr`. A sink that interpolates `${jndi:...}` runs none of them, so the method
  applied, sent its whole ladder, and came back `negative` on a target that is
  exploitable. The README's Log4Shell row rested on the standalone listener and
  a generated payload file, which produce no verdict row at all, so nothing in
  the engine could reproduce that claim.

  The probes are lookups and nothing else, and they depend on the injection
  context rather than the environment, exactly as `eval`'s do. The oracle is the
  one `oob` already uses: a token the target could only have learned by
  resolving what it was handed. The expression resolves `<token>.<host>`, so
  the in-process DNS listener is the entire apparatus -- no LDAP or RMI server
  is needed, and none is started.

  **It reports `lookup-sink`, never `confirmed`.** A callback proves the sink
  resolved a URI RCEKit chose -- that it evaluated the expression it was handed.
  It does not prove the target ran attacker code: Log4Shell becomes RCE when the
  LDAP server answers with a loadable class. So the method gets its own
  proven-sink tier beside `deserialization-sink`, with its own section in the
  report, and `confirmed` keeps meaning executed.

  **Only `jndi:dns://` is sent, and that is the security property rather than a
  shortcut.** A name lookup can be nothing else. `ldap://` and `rmi://` continue
  *past* resolution and open a connection to whatever address the answer named
  -- by default `127.0.0.1`, which is the target's own loopback. Whatever
  replies on :389 or :1099 is not RCEKit, so a reference could come back and a
  class be instantiated: the tool would have crossed the line this method exists
  to stop short of, having promised it had not. Dropping the two schemes also
  costs no coverage -- `DnsContextFactory` ships in the JDK, so `dns://`
  resolves wherever `ldap://` would, and on 2.15.0 it still resolves where
  `ldap://` no longer does. The proof is the callback and the finding is "this
  sink resolved a URI I chose" -- the same line `deser` draws, drawn here before
  it can be crossed.

  Behind the same two gates as `oob`, and sharing its listener: it needs
  `--oob-host`, and it is held back at the default safety tier because it makes
  the target open outbound connections. Without `--oob-host` it builds no probes
  at all, which the engine reports as `nothing-tested` -- never `negative`. An
  address literal is a literal whichever family it is from: `::1` and `[::1]`
  build nothing, the same as `10.0.0.1`, because a token can only ride in a DNS
  label. `blind_sink_advice` names the method as proving a lookup sink and not
  execution, in a list where `oob` and `file` mean confirmed execution, and the
  README's Log4Shell demo heading says `lookup-sink` rather than `confirmed` --
  it was left claiming execution beside the table row that no longer does.

## [2.35.5] — 2026-09-19

### Fixed

- **The `--insecure` notice describes the run it is in.** It was printed as
  soon as the flag was seen, so a generation-only run, `--doctor`, or a plain
  HTTP target all announced a TLS downgrade that never happened -- and it named
  both downgrade rungs even on an OpenSSL build that had refused one of them.
  Reporting a downgrade on a run that opened no TLS connection is the same
  defect as reporting a probe that was never sent, in the one line written to
  be an audit of the run.

  Building the context and saying so are now separate questions. The context is
  built whatever the target's scheme is -- urllib follows a redirect with the
  handler it was given, so an `http://` target that lands on a self-signed or
  legacy `https://` one needs it as much as a direct HTTPS target does. The
  notice fires once, when a connection has actually reached TLS, and lists only
  the rungs that took.

- **A benchmark case may set `timeout` to zero.** `timeout or 900.0` replaced
  an explicit `0` with the fifteen-minute default, so a case deliberately
  bounded to no time at all ran for much longer than it asked for.

## [2.35.4] — 2026-09-19

### Fixed

- **A wave the declared profile emptied is no longer read as a finished
  method.** The probe filter drops probes between the method and the wire, and
  when it emptied an adaptive method's *first* screening wave the engine took
  the empty batch for "nothing left to send" and stopped before asking for the
  next wave at all.

  An adaptive method holds separators back in waves precisely because a filter
  is expected: `time` screens two of them first and keeps `||`, `&&`, the
  newline and the bare command for a second wave. A sink that strips `;` and
  `|` removes exactly the first wave and leaves the rest intact -- and the rest
  were never sent. Measured against a sink reachable only through `&&`, the run
  reported **`negative`**: "the probes reached the target and found nothing",
  about probes that were never sent. Worse than `nothing-tested`, which is at
  least true.

  The loop now tracks what the method offered separately from what the profile
  allows to be sent, and ends only when the method itself is done. The round cap
  still bounds it, so a method whose every wave is filtered cannot spin the
  engine.

- **The unit suite runs off Linux.** The fake vulnerable sinks in the tests are
  POSIX command-injection points and every probe built for them is POSIX, but
  they were executed through `os.popen` — which is `cmd.exe` on Windows. The
  sink the test says executes did not execute, so the oracle correctly reported
  no execution and five tests failed for a reason unrelated to the code under
  test. Worse, the tests asserting a *negative* stayed green throughout: a
  broken fixture that keeps its controls passing is the failure this project
  takes seriously everywhere else. The sinks now name a POSIX `sh` explicitly;
  on Linux and macOS that is the `/bin/sh` they always used.

- **A deliberately dead target no longer costs minutes.** A closed loopback port
  answers with a RST on Linux and is silently dropped on Windows, where each
  probe waits out the SYN retry instead — measured at ~2s per probe. The
  benchmark harness's own unreachable-target case paid that for the full ladder
  twice, once for the vulnerable half and once for the control: 1800s for one
  test, longer than the other 534 together. Bounded to three probes it measures
  9.1s, and three probes prove "nothing reached the target" exactly as well as
  forty do.

- **A captured-request fixture reaches disk byte for byte.** The cleartext-capture
  tests write a raw HTTP request whose text already spells its own CRLF line
  endings, through `Path.write_text` — which on Windows translates the newline of
  each one again. The file on disk held a doubled carriage return, the parser
  found no headers, and two tests failed against a fixture that had stopped being
  an HTTP request at all.

  The third test in that class passed throughout, for the wrong reason: it
  asserts that a notice is *absent*, and a request that cannot be built prints no
  notice either. A control that stays green while its fixture rots is precisely
  what this project refuses to accept from a benchmark case, so the fixture now
  has a guard of its own. The capture is written as bytes; the `newline` argument
  that would say the same thing arrived in Python 3.10, and this project
  supports 3.8.

## [2.35.3] — 2026-09-18

The target profile an operator declares now reaches the probe ladder, not just
the corpus.

### Fixed

- **`--deny-chars` / `--max-length` reach the detection probes.** They were
  applied by `_filter_by_profile`, which drops *corpus records* — and stopped
  there. The probes a detection method builds from those records went out
  regardless, so a run that had been told "this target strips quotes" still paid
  for every quote-carrying rung of the ladder, on requests structurally unable
  to confirm. Those requests are not free: on a captured request with `-p all`
  they are the budget the next injection point never got. The filter now sits at
  the engine, where every probe passes through it — deliberately not inside
  `_wrap_variants`, because `_space_free_probes`, the query-language bridges,
  `eval`, `oob` and `deser` each build payloads without going through that
  helper, and a gate that reaches some methods and not others is the side path
  that once left `file`/`time`/`oob` unable to send the raw rung.

  Denying a character narrows the ladder rather than emptying it: a target that
  strips `;` is still probed through `|`, `||`, `&&` and the newline, which is
  what the separator table has always been for.

  Checked on the literal payload, before the delivery layer percent-encodes it
  for its injection point. That is stricter than the corpus check, which is
  applied to the encoded payload and so lets a URL-encoded quote through a quote
  filter. The layers genuinely differ: transport encoding is undone by the
  server before the value reaches the sink, so a percent-encoded quote is still
  a quote when the application's own filter sees it.

- **A profile strict enough to remove every probe reports `nothing-tested`.**
  Not `negative`, which would read as "not vulnerable" from a run that sent
  nothing. The message names the profile as the cause and the characters a probe
  would have to avoid, instead of the generic advice to widen `--environments` —
  which is not what emptied the run.

- **The cost estimate follows the profile.** `[detect] cost:` builds the probes
  and counts them, so it now counts the ones that will actually be sent. An
  estimate that ignores a filter is wrong precisely for the operator who
  narrowed the run on purpose.

### Changed

- A run that dropped probes says so, with the reason and a count per reason. A
  ladder that shrinks quietly is the one way this filter could manufacture a
  false negative, so the removal is stated rather than left to be inferred from
  the traffic.

## [2.35.2] — 2026-09-18

### Fixed

- **`--insecure` now reaches a legacy TLS stack, not just an untrusted one.**
  Turning certificate verification off is not the same as completing a
  handshake. OpenSSL 3.x ships security level 2, which refuses the key sizes and
  signature algorithms that software of the era this tool gets pointed at still
  offers — Webmin 1.910, the build the README's `reflected` row rests on,
  answers a default client with `SSLV3_ALERT_HANDSHAKE_FAILURE` and nothing
  else. Every probe then came back `error`: correct, and useless. The run was
  honest about having measured nothing, and the sink behind that handshake was
  never tested at all. Found by running the coverage benchmark, which failed at
  its readiness gate against a container that was up and answering.

  `--insecure` now also lowers the security level and the minimum protocol
  version. This does not widen exposure: with `check_hostname = False` and
  `CERT_NONE` the connection is already unauthenticated, so an active attacker
  is already unconstrained — accepting a 1024-bit key or a SHA-1 signature on
  top of that gives away nothing that was still being held. What it buys is the
  difference between testing the target and reporting that it could not be
  reached. A run without the flag is untouched and still verifies certificates.

- **The benchmark's readiness gate is as permissive as the tool it gates.**
  `wait_for_target` built its own strict context, so a case against deliberately
  old software reported "target never became ready" about a container that was
  up — a case failure with nothing wrong in it.

### Changed

- A run that passes `--insecure` states the full extent of the downgrade on its
  first line. The flag gives up more than certificate identity now, and an
  operator on a monitored engagement should read that in the transcript rather
  than infer it from the help text.

## [2.35.1] — 2026-08-21

A robustness pass over error handling: no new capability, four ways the tool
could crash or mislead on input it did not choose.

### Fixed

- **A truncated error response no longer ends the run.** Reading an
  `HTTPError`'s body happens *inside* the `except` handler, where the sibling
  `except Exception` cannot reach it — so a target that promised a
  `Content-Length` it never delivered raised `ConnectionResetError` straight out
  of `main()`, taking every probe already fired with it. The read is now
  guarded: the status still comes back, an unreadable body is reported empty.
  A body that *does* arrive is still returned in full — the 500-stack-trace
  confirmations that branch exists for are unaffected.
- **A `--target-profile` is checked before it is used.** A profile is written by
  hand, so a typo in one is ordinary; it surfaced as a traceback. A top level
  that is not a JSON object, `deny_chars` that is not text, a `max_length` that
  is not a number, a selector field that is not a list of names — each is now an
  operator-readable `[!]` message and exit 1, the same way the sink-shape fields
  already behaved. Twelve inputs that produced an `AttributeError` or a
  `TypeError` now produce a sentence.
- **A selector field given as one string means one name.** `"environments":
  "unix"` in a profile was iterated character by character, matched nothing, and
  the empty run that followed was reported as a success. A string is now split
  on commas: `"unix"` is `["unix"]`, `"raw, html"` is `["raw", "html"]`.
- **Unknown `--environments` and `--encodings` are named.** Both were silent, so
  `--environments linux` — the corpus calls it `unix` — produced an empty file
  and exit 0, indistinguishable from a target with no payloads for it. Both now
  warn and list the names that exist, as unknown contexts and categories already
  did. An empty result is also no longer announced as "Successfully generated 0
  payloads"; it says the selection matched nothing and points at the filters.
- **A callback cannot rewrite the operator's terminal.** The host and path of an
  OOB callback are chosen by the target. Printed raw, an ESC byte let that
  target colour, erase and rewrite lines — hiding a genuine `[HIT]` behind
  `\x1b[2K\r`, or forging one that never arrived. Control characters are now
  escaped for display as `\xNN`; the recorded hit and the `--listen-log` JSONL
  keep the bytes verbatim.

## [2.35.0] — 2026-08-20

### Added

- **RCEKit is installable from PyPI**: `pipx install rcekit` (or
  `pip install rcekit`) puts an `rcekit` command on PATH. Published through PyPI
  Trusted Publishing from a GitHub release — no API token, no repository secret.

  It ships as a **single-module distribution**, not a package tree. `rcekit.py`
  stays one file at the repo root and still runs alone from a `curl` on a jump
  box or an air-gapped host; installing is a second supported shape, not a
  replacement for the first.

### Changed

- **`import rcekit` no longer has side effects.** Logging was configured at
  module scope, and `logging.FileHandler` opens its file when it is constructed,
  so merely importing the module wrote `rcekit.log` into whatever directory the
  interpreter happened to be in. Handler setup moved into `configure_logging()`,
  called from `main()`. Running the CLI still writes `rcekit.log` exactly as
  before.

- **`main()` takes an optional `argv`** and returns an explicit `int`, so the
  console-script entry point is a plain zero-argument call and tests can drive
  the CLI in-process. Every exit code is unchanged.

- **The built-in corpus is no longer reported as a missing file.** With nothing
  but `rcekit.py` — an installed wheel, or the single-file copy — there is no
  `templates/` directory, the embedded corpus *is* the corpus, and the run is
  now silent about it; `--doctor` names it `built-in (embedded in rcekit.py)`
  and reports OK. A `templates/` directory that exists *without* its
  `payloads.json` still prints the notice, because that one is a real finding.
  A corpus that is present but corrupt, and an explicit `--template-file` that
  is missing or corrupt, still refuse to run and exit non-zero.

- The log file handler now runs at `DEBUG` while the console stays at `INFO`, so
  detail worth having when reconstructing a run no longer lands on the
  operator's terminal.

## [2.34.1] — 2026-08-17

Documentation only; no behaviour change.

### Changed

- **New tagline: "`confirmed` means the target executed the input. `negative`
  means the probes reached it."** The old one — "prove RCE, don't guess it" —
  claimed the tool always proves. It does not, and does not need to: the value
  is that each verdict has a mechanical meaning, in both directions. A promise
  can be broken; a definition cannot.

  Both halves name their actor and object on purpose. "Executed" alone reads as
  though *RCEKit* executed something; the claim is about the target. And
  `confirmed`/`negative` are the verdict values as the code spells them, not
  looser words like "clean".

- **The README caught up with the engine.** It still described "two verdict
  tiers" when there are seven, and the comparison table predated the last five
  releases. Rewritten around what a verdict asserts, with the tier table as the
  centrepiece and a section on the half no other tool has: `error` and
  `nothing-tested` exist so a run that tested nothing is never reported as
  clean.

  The comparison table gains the classes added since it was written — Windows
  `cmd.exe`/PowerShell sinks, upload → write-then-execute, second-order
  execution, query-language bridges and deserialization sinks — and the "reach
  for something else" note now says plainly that sqlmap owns the database and
  RCEKit's bridges only prove the OS is reachable from a text parameter.

### Fixed

- Two claims in the engagement-controls table were wrong and are now accurate:
  the observed-channel fetch sends **no** credentials unless given a request with
  `--observe-request` (only the `file` read-back inherits them, same-origin), and
  an unanswered `--observe-url` is a warning about a partly blinded run rather
  than a `nothing-tested` verdict.
- The "mechanisms that produce `inconclusive`" list said four and listed five.

## [2.34.0] — 2026-08-17

Deserialization **sink** detection, and a verdict that is deliberately not RCE.

Deserialization RCE (fastjson, shiro, weblogic, jenkins) cannot be confirmed by
the value-oracle model: the payload is a serialized object graph and gadget
selection is classpath-specific, so whether execution is reachable depends on
jars RCEKit cannot see. That stays out of scope. The honest middle step is
showing the endpoint parses the data at all — a real finding, and the
prerequisite for every gadget chain.

### Added

- **`--methods deser`**, which **never emits `confirmed`**. Its strongest
  outcome is a new verdict, `deserialization-sink`, reported in its own section
  that states outright that reaching RCE from there depends on classpath
  gadgets. Collapsing it into `confirmed` would break the one guarantee the tool
  rests on; collapsing it into `needs-review` would throw away a proven finding.

  `deserialization-sink` sits below both RCE tiers in the collapsed verdict: it
  is proven, but a *suspected* RCE outranks a proven non-RCE in triage.

- **Two oracles of deliberately different strength.** `shape` (no listener
  needed) sends a well-formed object stream, the same stream truncated, and the
  format's magic bytes plus random noise of the same length, and asks whether
  the endpoint answers the well-formed one differently from both — a
  fingerprint, so `needs-review` only, never promoted. `dns` (needs
  `--oob-host`) sends a gadget whose only side effect is a name lookup.

- **A URLDNS builder for Java serialization.** A `HashMap` holding one
  `java.net.URL`: `HashMap.readObject` hashes the key, `URL.hashCode` asks for
  the host address, the JVM resolves the name. It references no class outside
  `java.util`/`java.net`, so there is nothing in it that can run — the callback
  proves the object graph was reconstructed and no more.

  Built in Python rather than declared in the corpus because the URL host is
  length-prefixed *inside* the stream and changes per probe. Its constant parts
  are the exact bytes OpenJDK's own `ObjectOutputStream` emits for that graph,
  and the result was **verified against OpenJDK 21**: it deserializes to
  `HashMap{http://<host>/=rk}` and issues a DNS query for `<host>`, with no code
  execution.

- **A `deser_probes` corpus section** with `java`, `php`, `dotnet`,
  `python_pickle` and `fastjson`, plus `--deser-formats` to narrow it. Only
  `java` and `fastjson` carry a DNS gadget: PHP and .NET chains all run through
  magic methods or type confusion, so there is no honest DNS-only probe for them
  and they get the shape oracle alone.

- Response signatures for the shape differential drop long digit and hex runs,
  so request ids and timestamps on an otherwise identical error page do not make
  every endpoint fingerprint as a parser.

### Changed

- The README's scope note now says precisely what changed and what did not:
  deserialization **gadget chains** remain out of scope, while the **sink** is
  now reported in its own tier.

## [2.33.0] — 2026-08-17

Query-language bridges. Several RCEs pass through a query language before
reaching the OS — Postgres `COPY … FROM PROGRAM`, MSSQL `xp_cmdshell`, XXE
`expect://` — and the injection point is an ordinary text value, so the oracle
model already fitted. Only the carriers were missing.

### Added

- **A `bridges` section in the corpus**, declared like `eval_carriers` so
  coverage grows without touching Python. Each bridge names the shell it
  reaches, its safety tier, its prerequisites and, where it creates something,
  the statement that removes it: `postgres_copy_program` (`/bin/sh`,
  `stateful`), `mssql_xp_cmdshell` (`cmd.exe`, `intrusive`) and `xxe_expect`
  (`/bin/sh`, `intrusive`).

- **`--bridges none|auto|NAMES`** rides the command probes through them. A
  bridge is a **carrier, not an oracle**: it wraps the command `reflected`,
  `time` and `oob` already build, so those methods prove execution through it
  and inherit every tier guarantee rather than re-deriving one. Off by default,
  because a bridge payload is SQL or XML syntax and on an ordinary shell sink it
  is a request that cannot confirm.

  Three properties follow from that framing. A bridge only gets a core written
  in its own dialect — `xp_cmdshell` hands its argument to `cmd.exe`, so pairing
  it with a POSIX `$((a+b))` would send inert text. No separator is prepended:
  inside `COPY … FROM PROGRAM '…'` there is no running command to break out of.
  And the record's context still applies, so `--contexts sql` and a bridge
  compose instead of each reinventing the other.

- **The safety ordering governs bridges** exactly as it governs every corpus
  payload: a `stateful` bridge needs `--verify-active-risk stateful`, and the
  pre-flight names the tier each held-back bridge actually requires rather than
  sending the operator to raise the ceiling further than the run needs.

### Changed

- **An aggregate method's result now carries its cleanup line.** `time` reports
  one row for a whole probe series, so a stateful bridge on the one oracle that
  reliably proves a query-language sink was the one that never said how to clean
  up after itself.

### Not built, deliberately

- **MySQL UDF execution** is a multi-stage chain — write a shared object into the
  plugin directory, then `CREATE FUNCTION` — not something a single probe can
  carry. There is no stub for it.
- **MongoDB `$where`** is a boolean-only channel (its JS sandbox cannot reach a
  shell), so it needs a different oracle rather than this one.
  `mongo-express/CVE-2019-10758` is a plain JS `eval` sink that `--methods eval`
  already covers.

The three shipped bridges are documented syntax but **not validated against live
databases here** — this build environment has no container runtime. Each corpus
entry says so in its `verified` field rather than implying a test that did not
happen.

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



[Unreleased]: https://github.com/kabiri-labs/rcekit/compare/v2.36.0...HEAD
[3.1.2]: https://github.com/kabiri-labs/rcekit/compare/v3.1.1...v3.1.2
[3.1.1]: https://github.com/kabiri-labs/rcekit/compare/v3.1.0...v3.1.1
[3.1.0]: https://github.com/kabiri-labs/rcekit/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/kabiri-labs/rcekit/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/kabiri-labs/rcekit/compare/v2.45.7...v3.0.0
[2.45.7]: https://github.com/kabiri-labs/rcekit/compare/v2.45.6...v2.45.7
[2.45.6]: https://github.com/kabiri-labs/rcekit/compare/v2.45.5...v2.45.6
[2.45.5]: https://github.com/kabiri-labs/rcekit/compare/v2.45.4...v2.45.5
[2.45.4]: https://github.com/kabiri-labs/rcekit/compare/v2.45.3...v2.45.4
[2.45.3]: https://github.com/kabiri-labs/rcekit/compare/v2.45.2...v2.45.3
[2.45.2]: https://github.com/kabiri-labs/rcekit/compare/v2.45.1...v2.45.2
[2.45.1]: https://github.com/kabiri-labs/rcekit/compare/v2.45.0...v2.45.1
[2.45.0]: https://github.com/kabiri-labs/rcekit/compare/v2.44.0...v2.45.0
[2.44.0]: https://github.com/kabiri-labs/rcekit/compare/v2.43.0...v2.44.0
[2.43.0]: https://github.com/kabiri-labs/rcekit/compare/v2.42.0...v2.43.0
[2.42.0]: https://github.com/kabiri-labs/rcekit/compare/v2.41.0...v2.42.0
[2.41.0]: https://github.com/kabiri-labs/rcekit/compare/v2.40.0...v2.41.0
[2.40.0]: https://github.com/kabiri-labs/rcekit/compare/v2.39.0...v2.40.0
[2.39.0]: https://github.com/kabiri-labs/rcekit/compare/v2.38.0...v2.39.0
[2.38.0]: https://github.com/kabiri-labs/rcekit/compare/v2.37.0...v2.38.0
[2.37.0]: https://github.com/kabiri-labs/rcekit/compare/v2.36.0...v2.37.0
[2.36.0]: https://github.com/kabiri-labs/rcekit/compare/v2.35.5...v2.36.0
[2.35.5]: https://github.com/kabiri-labs/rcekit/compare/v2.35.4...v2.35.5
[2.35.4]: https://github.com/kabiri-labs/rcekit/compare/v2.35.3...v2.35.4
[2.35.3]: https://github.com/kabiri-labs/rcekit/compare/v2.35.2...v2.35.3
[2.35.2]: https://github.com/kabiri-labs/rcekit/compare/v2.35.1...v2.35.2
[2.35.1]: https://github.com/kabiri-labs/rcekit/compare/v2.35.0...v2.35.1
[2.35.0]: https://github.com/kabiri-labs/rcekit/compare/v2.34.1...v2.35.0
[2.34.1]: https://github.com/kabiri-labs/rcekit/compare/v2.34.0...v2.34.1
[2.34.0]: https://github.com/kabiri-labs/rcekit/compare/v2.33.0...v2.34.0
[2.33.0]: https://github.com/kabiri-labs/rcekit/compare/v2.32.0...v2.33.0
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
