#!/usr/bin/env python3
"""boundary-check.py — the harness/learnings boundary gate (issue #47 AC6).

Runs the six conditions in the boundary classification document against a
release tree and fails closed: any violation means a non-zero exit and no push.

Conditions 1 and 2 derive their path sets from that document's classification
tables at run time, and condition 3 reads its term list from the document's
`boundary-terms` block. None of the three is hand-copied into this file, because
a hand-copied pattern goes stale the first time a path moves and it fails open —
silently. Conditions 4 and 5 are the two hand-maintained lists the document says
cannot be derived (an agent instruction is syntax, and a learning marker is a
heuristic); condition 6 is a manifest rather than a list.

Usage:
    python3 scripts/boundary-check.py TREE
        [--doc PATH]        classification document (default: this repo's)
        [--manifest PATH]   approved-asset manifest (default: the landing one)
        [--assets-dir DIR]  directory the manifest governs (default: images/reports)
        [--json PATH]       also write the findings as JSON
        [--quiet]           summary lines only

Exit codes:
    0  clean — the tree may be released
    1  violation(s) found — do not push
    2  the check could not run (missing tree or document, empty derivation)

Environment:
    PORTSHIM_BOUNDARY_ALLOW_MISSING_MANIFEST=1
        Downgrades condition 6's missing-manifest failure to a warning, for the
        window before AC9 produces the manifest. The failure is the correct
        posture, so the override prints on every run it is in force.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import json
import os
import re
import sys
import zipfile
import zlib
from itertools import islice
from pathlib import Path

# The document this gate reads, and the manifest condition 6 checks. Both are
# named here rather than taken from the document, and both carry an allow
# marker: the gate has to know these paths, and neither file is itself shipped.
DOC_RELPATH = "references/release-boundary.md"  # boundary:allow — the gate reads it; it never ships
MANIFEST_RELPATH = "portshim-landing/approved-assets.json"  # boundary:allow — a landing source path the gate reads

# ── The two hand-maintained lists: conditions 4 and 5 ────────────────────────
# Condition 4: agent instructions that cannot resolve in a release tree. This is
# syntax, not paths, so no run-time read of the document can produce it. Keep it
# short and by hand; the slash-skill form is its entire contents today.
AGENT_INSTRUCTIONS = [
    "/skill ",  # boundary:allow — the term definition itself
]

# Condition 5: learning markers in shipped text. A heuristic, and the terms are
# anchored where a looser match would fire on innocent words: the unanchored
# three capital letters of the house initials match the middle of "password",
# which is why the document insists on the word boundary.
# Each line carries an allow marker, because the definition names the marker.
MARKERS = [
    ("key learnings", re.IGNORECASE),  # boundary:allow — the term definition itself
    ("pitfall", re.IGNORECASE),  # boundary:allow — the term definition itself
    ("cal-met", re.IGNORECASE),  # boundary:allow — the term definition itself
    # Case-insensitive, because the document's step-2 command greps with -i: with
    # the word boundary it still cannot reach the middle of an innocent word,
    # and without -i it would miss the mixed-case forms the document means to
    # catch.
    (r"\bSSW\b", re.IGNORECASE),  # boundary:allow — the term definition itself
    ("partial on phase 3", re.IGNORECASE),  # boundary:allow — the term definition itself
]

# Condition 3: shipped files that legitimately have to name a private path, keyed
# by (file, term) rather than by file. A file-wide exemption would hide any *new*
# private-path reference added to that file later, which is the hole a reviewer
# would have to be told about; a term-scoped one only pardons the known lines.
# Each is owned by an open issue and printed on every run.
#   AC7 — this test leaves with the curated public subset; until that lands it is
#   the one line step 4a reports. The pair for tests/test_skill_consistency.py
#   went with that module on 2026-09-25, when its checks moved into
#   tests/test_skill_trees.py and it left the tree.
COND3_EXEMPT = {
    ("tests/test_uat_wired.py", "tests/fixtures/"): "AC7 — leaves with the curated public subset",  # boundary:allow — the exemption's own key
}

# The inline escape hatch, so an unavoidable mention does not force a code change.
ALLOW_MARKER = "boundary:allow"

# A runtime-assembled path — the parent directory and the leaf joined at run
# time instead of written as one string, in either of the two shapes the
# document records — never matches a plain literal, which is step 4a's first
# blind spot. This scan allows non-word separators between the segments, but
# only when the separator carries punctuation: otherwise ordinary prose that
# happens to mention both words would fire, because " and " is a non-word run
# too.
ASSEMBLY_SEPARATOR = re.compile(r"[^\w\n]{1,20}")
ASSEMBLY_PUNCT = re.compile(r"[/'\"+(),]")

# Binaries after the same treatment: a .docx is a zip, so its XML is read member
# by member; a .pdf hides its text in zlib streams and a .png in zTXt/iTXt
# chunks, so those are inflated; anything else gets its printable runs,
# including UTF-16LE. That closes step 4a's second blind spot, where
# --binary-files=without-match skips binaries outright.
#
# What this does not claim: arbitrary compression or encryption, and pixels. A
# path rendered into an image is invisible to every text match and is condition
# 6's problem, not this one's.
ZIP_MEMBER_LIMIT = 512
ZIP_OPEN_MEMBER_CAP = 20000
ARCHIVE_START_LIMIT = 32
# How many candidate ends to try for each candidate start: the next few archive starts,
# then the end of the file. A false local-header signature inside a member's bytes makes
# a candidate that validates nothing, and the real end is the start after it.
ARCHIVE_END_TRIES = 4
ZIP64_LOCATOR = b"PK"
ZIP64_EOCD = b"PK"
ZIP_NESTING_LIMIT = 3
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ZIP_LOCAL_HEADER = b"PK\x03\x04"
# The shortest run of printable characters the raw-byte readers will report. Six, not the three
# a shortest-term rule would give: measured on the release tree, a three-character filter turned
# one byte sequence inside a PNG's compressed pixel data into a condition-5 marker, and a
# fail-closed gate that blocks releases on coincidences is worse than useless. Coverage for
# shorter terms comes from the readers and from the sweep over the file's own bytes, which
# requires the match to sit in text rather than in compressed bytes.
RUN_MINIMUM = 6
ZIP_CENTRAL_HEADER = b"PK\x01\x02"
ZIP_EOCD = b"PK\x05\x06"
ZIP_EOCD_LEN = 22  # the record is this signature plus eighteen fixed bytes


def _looks_like_zip(data: bytes) -> bool:
    """A zip container — including one with bytes prepended before its first header.

    `zipfile` finds an archive by its end-of-central-directory record and applies the
    offset, so a `.docx` with a byte or two in front still opens; but that only happens
    if the check decides to try. Requiring the signature at offset 0 instead hands such
    a file to the printable-run scan, which reads the member names out of the clear-text
    directory and none of the deflated content behind them.
    """
    if data[:4] == ZIP_LOCAL_HEADER:
        return True
    # No artificial window on either search: a container with a megabyte of bytes in front
    # of its first header is still a container, and a bounded search called it a plain
    # binary, which left every deflated member inside it unread. Both signatures are
    # needed for a container, which is what keeps ordinary text mentioning neither from
    # being read as one.
    return ZIP_LOCAL_HEADER in data and ZIP_EOCD in data
# The newline before `endstream` is optional: the specification asks for one, real files
# omit it, and requiring it meant the stream was never found and its compressed content was
# read by nothing — a private path inside it cleared with no finding and no reason.
PDF_STREAM = re.compile(rb"stream\r?\n(.*?)(?:\r?\n)?endstream", re.DOTALL)
INFLATE_STREAM_LIMIT = 64
INFLATE_BYTES_LIMIT = 8 * 1024 * 1024

# Files the check cannot read in full fail rather than passing unexamined. The
# caps are generous but finite: without them a single huge asset would turn every
# release into a minutes-long scan, and a silent truncation is the worse failure.
TEXT_READ_CAP = 16 * 1024 * 1024
BINARY_READ_CAP = 32 * 1024 * 1024
PATHISH = re.compile(r"^[^\s|]+$")
PARENS = re.compile(r"\([^()]*\)")


class DerivationError(Exception):
    """The document yielded something the check cannot derive from safely."""


class Finding:
    __slots__ = ("condition", "location", "detail", "kind")

    def __init__(self, condition: str, location: str, detail: str, kind: str = "violation") -> None:
        self.condition = condition
        self.location = location
        self.detail = detail
        self.kind = kind

    @property
    def is_violation(self) -> bool:
        return self.kind == "violation"

    def as_dict(self) -> dict:
        return {"condition": self.condition, "location": self.location, "detail": self.detail, "kind": self.kind}

    def __str__(self) -> str:
        return f"[{self.condition}] {self.location}: {self.detail}"


# ── Derivation: the classification tables and the term block ─────────────────


class Classification:
    """The private and Ships path sets, read from the document's tables."""

    def __init__(self) -> None:
        self.private: list[str] = []
        self.ships: list[str] = []
        self.translations: dict[str, str] = {}
        self.rows = 0

    def derived_from(self) -> str:
        return f"{len(self.private)} private paths, {len(self.ships)} Ships paths, from {self.rows} table rows"


def _cells(line: str) -> list[str]:
    return [p.strip() for p in line.strip().strip("|").split("|")]


def _backticked(cell: str) -> list[str]:
    return [t for t in re.findall(r"`([^`]+)`", cell) if t and PATHISH.match(t)]


def _is_separator_row(cells: list[str]) -> bool:
    return bool(cells) and all(set(c) <= set("-: ") for c in cells if c)


def _path_tokens(paths_cell: str) -> list[str]:
    """The paths a classification cell lists.

    A cell may list several paths in one row, and it may carry a parenthetical
    that names files *inside* the path it lists. Those inner names are not
    classifications of their own — the tree glob is one, a file named inside its
    parenthetical is not — so the
    parentheticals come out before the tokens do.
    """
    return _backticked(PARENS.sub(" ", paths_cell))


def parse_classification(doc: str) -> Classification:
    """Read the three 'Classification —' tables out of the boundary document."""
    c = Classification()
    section = None
    for line in doc.splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if section is None or not section.startswith("Classification"):
            continue
        if not line.lstrip().startswith("|"):
            continue
        cells = _cells(line)
        if len(cells) < 3 or _is_separator_row(cells):
            continue
        paths_cell, class_cell, why_cell = cells[0], cells[1], cells[2]
        klass = class_cell.replace("*", "").strip().lower()
        if not klass or klass == "class":
            continue
        c.rows += 1
        # One cell may carry an 'except' clause; an excepted path is classified
        # by its own row, so only the part before it is Ships.
        ships_part, _, _excepted = paths_cell.partition(" except ")
        # A row may state the path it takes in a release tree, which is what must
        # be matched: the landing merge relocates those files.
        tokens = _path_tokens(paths_cell)
        m = re.search(r"release-tree path(?: is|:)?\s*`([^`]+)`", why_cell, re.IGNORECASE)
        if m and tokens:
            # A row that states one release-tree path and lists several source
            # paths is ambiguous: the check cannot tell which path the stated one
            # replaces, and guessing would silently skip the others. Refuse and
            # make the author split the row.
            if len(tokens) > 1:
                raise DerivationError(
                    f"row lists {len(tokens)} paths ({', '.join(tokens)}) and also states a "
                    f"release-tree path ({m.group(1)}) — split the row so each path can be matched"
                )
            c.translations[tokens[0]] = m.group(1)
        if "private" in klass:
            c.private.extend(_path_tokens(ships_part))
        elif klass == "ships":
            c.ships.extend(_path_tokens(ships_part))
    c.private = list(dict.fromkeys(c.private))
    c.ships = list(dict.fromkeys(c.ships))
    return c


def parse_reference_terms(doc: str) -> list[str]:
    """Read condition 3's term list from the document's `boundary-terms` block."""
    terms: list[str] = []
    inside = False
    for line in doc.splitlines():
        if line.strip().startswith("```boundary-terms"):
            inside = True
            continue
        if inside and line.strip().startswith("```"):
            break
        if inside:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                terms.append(stripped.split()[0])
    return list(dict.fromkeys(terms))


# ── Pattern semantics ────────────────────────────────────────────────────────


def matches(path: str, pattern: str) -> bool:
    """Does a release-tree path match a classification pattern?

    `X/**` and `X/*` mean 'anything under X/', and both also match the directory
    itself, because for a tree that must not be there at all the directory's
    presence is the violation. A trailing glob is fnmatch; anything else is an
    exact path.
    """
    if pattern.endswith("/**") or pattern.endswith("/*"):
        base = pattern[:-2].rstrip("/")
        return path == base or path.startswith(base + "/")
    return path == pattern or fnmatch.fnmatch(path, pattern)


def translate(pattern: str, c: Classification) -> str:
    return c.translations.get(pattern, pattern)


# ── Tree reading ─────────────────────────────────────────────────────────────


def iter_files(tree: Path) -> list[str]:
    out = []
    for root, dirs, files in os.walk(tree):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            out.append(os.path.relpath(os.path.join(root, f), tree))
    return sorted(out)


def looks_text(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return False
    try:
        data[:8192].decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def printable_runs(data: bytes, minimum: int = 6) -> str:
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
    return "\n".join(r.decode("ascii", "replace") for r in runs)


def printable_runs_joined(data: bytes, minimum: int = 6) -> str:
    """The printable runs with nothing between them.

    Two runs separated by one non-printable byte hold a term split across them: each half is
    long enough to be read, neither contains the term, and the sweep cannot help — it matches a
    term that is *contiguous in the bytes* and crosses a declared edge, while here the bytes are
    not contiguous at all. The file was cleared with the path sitting in it in two pieces a
    reader printed side by side. Joining the runs makes that shape visible to the literal scan,
    which is the only reader that can see it: a term is a term whether or not a stray byte was
    dropped into it.
    """
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
    joined = b"".join(runs)
    if not joined:
        return ""
    return joined.decode("ascii", "replace")


def _printable_run_spans(data: bytes, minimum: int = 6) -> list[tuple[int, int]]:
    """Where the printable runs are, so a caller can declare the boundaries between them.

    `printable_runs` returns text and nothing else, and for a long time that was all the run
    pass produced — while the comment in `read_textish` claimed the runs were declared. The
    declaration is what gives the crossing sweep an edge to find: two runs separated by a
    single non-printable byte hold a term split across them, and with no edges the sweep
    reports nothing and the file is cleared with no reason.
    """
    return [(m.start(), m.end()) for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data)]


def _is_one_character_shift(a: str, b: str) -> bool:
    """Whether one of these lines is the other with a single character dropped from an end.

    That is exactly what reading the same bytes one byte along produces: the pairs are taken
    from a different starting byte, so one character falls off one end and a byte joins the
    other. Comparing for containment in general is wrong in both directions — a garbage decode
    can be longer and contain the true line, which would drop the line carrying the term —
    where this relation only ever pairs a line with its own shifted view, and a shift at
    either end leaves the term itself intact on the line that is kept.
    """
    if a == b:
        return True
    return a[1:] == b or b[1:] == a or a[:-1] == b or b[:-1] == a


def _utf16_views(data: bytes) -> str:
    """The four ways a byte range can hold UTF-16 text, without the shifted views.

    Two alignments and two endiannesses, because a path at an odd offset decodes to garbage
    when the pairs are taken from byte zero and the offset of a path inside a binary is not
    a number this check gets to choose. Read that way, the same bytes also decode *again* one
    character along: little-endian text read as big-endian from the next byte gives the same
    string with its first character gone, so the term is reported twice — once against a line
    that is a mis-decode of the bytes that already produced it. A view whose line is contained
    in a line from an earlier view is dropped, and that cannot lose a finding: a line contained
    in another one puts its term in the line that contains it, and that line is still reported.
    Only lines of a similar length are compared, because a shifted view differs by one
    character and every other pairing is a coincidence, not an alignment.
    """
    views: list[tuple[int, list[str]]] = []
    for index, (start, enc) in enumerate(((0, "utf-16-le"), (0, "utf-16-be"), (1, "utf-16-le"), (1, "utf-16-be"))):
        try:
            # Three characters, not `RUN_MINIMUM`: what comes out of a UTF-16 decode is text,
            # not a run of printable bytes in binary, and the shortest marker this check
            # searches for is three characters. Holding this pass to the binary filter dropped
            # every short marker written in UTF-16 — in a gap, in a member, anywhere.
            decoded = printable_runs(data[start:].decode(enc, "ignore").encode("utf-8", "replace"), 3)
        except Exception:
            continue
        views.append((index, [line for line in decoded.split("\n") if line]))
    # Longest first, so the line that survives a shift family is the longest one in it — a
    # shift at either end leaves the term itself intact, so the longest line carries every
    # term the shorter ones do, and the order the four views happen to be tried in stops
    # deciding what gets reported. Length is also the tie-break a garbage decode loses:
    # reading the wrong alignment of real text yields nothing printable, not something longer.
    kept: list[str] = []
    for line in sorted((line for _, lines in views for line in lines), key=len, reverse=True):
        if any(_is_one_character_shift(line, other) for other in kept):
            continue
        kept.append(line)
    return "\n".join(kept)


def _inflate_local_headers(
    data: bytes,
    depth: int = 0,
    budget: int = INFLATE_BYTES_LIMIT,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
) -> tuple[str, str | None]:
    """Text behind local headers that no member reader accounted for.

    A zip member's payload is *raw* deflate, not zlib, so the zlib reader cannot see it.
    That leaves a hole exactly as wide as a header with no directory record behind it: a
    decoy end record, an appended stub, or a member the believed directory does not list
    hides a private path inside a stream nothing decompresses, and the file is cleared
    with no reason. Every local header in these bytes is inflated the way `zipfile` would
    inflate it — the header's own fields are trusted only for the offsets they give, and
    the read is capped, so a stream that inflates to something enormous stops at the cap
    rather than in memory.
    """
    pieces: list[str] = []
    reasons: list[str] = []
    remaining = budget
    over_limit = False
    for index, m in enumerate(islice(re.finditer(re.escape(ZIP_LOCAL_HEADER), data), ZIP_MEMBER_LIMIT + 1)):
        if index >= ZIP_MEMBER_LIMIT:
            # A bound that stops work reports itself, the same rule the member and stream
            # bounds follow: the headers past this one are read by nothing, and silence here
            # would clear a file whose only readers are these.
            over_limit = True
            break
        at = m.start()
        head = data[at:at + 30]
        if len(head) < 30:
            continue
        flags = int.from_bytes(head[6:8], "little")
        method = int.from_bytes(head[8:10], "little")
        csize = int.from_bytes(head[18:22], "little")
        name_len = int.from_bytes(head[26:28], "little")
        extra_len = int.from_bytes(head[28:30], "little")
        if method != 8 or remaining <= 0:
            continue  # stored, or nothing left of the budget
        body = at + 30 + name_len + extra_len
        if body >= len(data):
            continue
        # A header whose sizes are in a trailing data descriptor claims 0 compressed
        # bytes; the stream is still there, so it is read to the cap in that case.
        declared_stop = body + csize if csize > 0 else body + INFLATE_BYTES_LIMIT
        # Read to the next structure rather than to the size the header declares. A header whose
        # declared size understates its own deflate stream stops the decompression mid-content,
        # and the bytes past that point were read by nothing while every reader reported the file
        # read: a private path parked after the cut was cleared with no reason. zlib raises
        # nothing for a truncated stream — it simply stops — so the region is taken to the next
        # signature and the disagreement is reported rather than passed over, which is the same
        # rule the member path follows for a directory that understates a member's size.
        next_structure = len(data)
        for signature in (ZIP_LOCAL_HEADER, b"PK\x01\x02", ZIP_EOCD):
            candidate = data.find(signature, body)
            if candidate >= 0:
                next_structure = min(next_structure, candidate)
        read_past_the_declared_size = next_structure > declared_stop
        stop = next_structure if read_past_the_declared_size else declared_stop
        blob = data[body:stop][:INFLATE_BYTES_LIMIT]
        # Successive streams, not just the first: a blob can hold two raw-deflate streams
        # back to back, and `unused_data` is where the second one sits. Reading only the first
        # left the rest unread while the file was reported read in full — the same shape the
        # payload reader had, fixed the same way.
        stream_pieces: list[bytes] = []
        payload_bytes = blob
        decompressor = zlib.decompressobj(-15)
        try:
            for _ in range(16):
                piece = decompressor.decompress(payload_bytes, min(remaining, INFLATE_BYTES_LIMIT))
                stream_pieces.append(piece)
                remaining -= len(piece)
                if decompressor.unused_data and remaining > 0:
                    payload_bytes = decompressor.unused_data
                    decompressor = zlib.decompressobj(-15)
                    continue
                break
        except zlib.error:
            continue
        raw = b"".join(stream_pieces)
        if decompressor.unused_data:
            reasons.append(
                "a local header no directory record lists holds more compressed streams than were read"
            )
        if read_past_the_declared_size:
            reasons.append(
                f"a local header no directory record lists declares {csize} byte(s) where its stream "
                "holds more, so the bytes past that point were read beyond the size it declares"
            )
        remaining -= len(raw)
        # The same reading a listed member gets, not the printable-run pass alone: these
        # bytes are a member payload that no directory record lists, and the bytes *inside*
        # them can be anything a member's can — a nested container, UTF-16 text, a PDF
        # stream. Inflating them and scanning for printable runs left every one of those
        # unread, because the readers that follow a container or decode another encoding
        # were never called. The depth bound is the same one the member path uses, so a
        # container chain cannot be extended by parking it behind a stray header.
        if depth >= ZIP_NESTING_LIMIT:
            pieces.append(printable_runs(raw))
            reasons.append(
                f"content {ZIP_NESTING_LIMIT} containers deep behind a local header no directory record lists "
                "was searched only for printable text"
            )
        else:
            nested, nested_reason = _scan_member_blob(raw, depth + 1, runs=True, spaces_out=spaces_out)
            pieces.append(nested)
            if nested_reason:
                reasons.append(nested_reason)
    if over_limit:
        reasons.append(f"more than {ZIP_MEMBER_LIMIT} local headers in bytes no member reader accounted for; the rest were not searched")
    if remaining <= 0:
        reasons.append(f"the {INFLATE_BYTES_LIMIT // 1048576} MB inflate budget was reached in the bytes outside every member; what came after it was not searched in full")
    return "\n".join(p for p in pieces if p), "; ".join(reasons) if reasons else None


def _binary_readers(
    data: bytes,
    runs: bool = True,
    depth: int = 0,
    spans_out: list[tuple[int, int]] | None = None,
    origin: int = -1,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
) -> tuple[str, str | None]:
    """The readers every non-text file gets: printable runs, PNG text chunks,
    PDF-style zlib payloads and the raw deflate behind a local header. One definition,
    four callers.

    `runs=False` drops the printable-run pass for bytes a caller has already decoded as
    UTF-8 text. The decode is a superset of that pass for anything a boundary term can be
    written in, so dropping it changes no finding — except that it stops a member's own
    text being discovered a second time, at a line number that exists in the concatenated
    report and nowhere in the member.
    """
    # `RUN_MINIMUM` is six and *stays* six. Lowering it to three — the length of condition 5's
    # shortest marker — was tried, and measured against the real release tree it turned a
    # three-character byte sequence inside `logo-light.png`'s compressed pixel data into a
    # marker. The short-marker case is covered where it actually occurs instead: every fixed
    # field a short term can hide in is read as text by the reader that owns it — a member's
    # local header, a directory record, the end record, the zip64 records. A docstring here
    # claiming three was covered while the constant was six is the kind of comment this file
    # is not allowed to carry: `test_run_minimum_is_no_wider_than_the_shortest_marker` pins
    # the relationship between the constant and the term list, and the readers pin the rest
    # to the document's lists, so the constant cannot silently become a blind spot.
    parts: list[str] = []
    run_spans: list[tuple[int, int]] = []
    if runs:
        parts.append(printable_runs(data, RUN_MINIMUM))
        run_spans = _printable_run_spans(data, RUN_MINIMUM)
        # And again with the separators removed, swept as a space of its own rather than added to
        # the text: a term split by one non-printable byte is readable in two pieces and
        # invisible to every other reader here. The joined bytes are contiguous — that is the
        # whole point of joining them — so the sweep finds the term, and the edges are the joins,
        # which is exactly the boundary it straddles. Adding the joined text instead would report
        # the same occurrence twice, once from the literal scan and once from the sweep.
        joined = printable_runs_joined(data, RUN_MINIMUM)
        if joined and spaces_out is not None:
            at = 0
            joins: list[int] = []
            for start, end in run_spans[:-1]:
                at += end - start
                joins.append(at)
            if joins:
                spaces_out.append((joined.encode("ascii", "replace"), joins))
    # Declare the runs, in the coordinates the caller gave: file offsets when `origin` is a
    # real position in the file, a space of their own when the bytes were produced rather than
    # found (a compressed member's body exists nowhere in the file). This parameter was dead
    # code: nothing in this function touched `spans_out`, so a plain binary file — or a
    # container's unaccounted-for gap bytes — came back with no declared edges at all, and a
    # private path split by one non-printable byte, both halves well past RUN_MINIMUM, was
    # cleared with no finding and `reason=None`.
    if run_spans:
        if origin >= 0 and spans_out is not None:
            spans_out.extend((origin + start, origin + end) for start, end in run_spans)
        elif origin < 0 and spaces_out is not None:
            spaces_out.append((data, sorted({edge for start, end in run_spans for edge in (start, end)})))
    parts.append(_utf16_views(data))
    inflated, zlib_reason = _inflate_zlib_payloads(data, depth=depth, spaces_out=spaces_out)
    parts.append(inflated)
    # Raw deflate behind a local header: the shape a member payload has, and the one the
    # zlib reader above cannot read.
    deflated, header_reason = _inflate_local_headers(data, depth=depth, spaces_out=spaces_out)
    parts.append(deflated)
    reason = "; ".join(r for r in (zlib_reason, header_reason) if r) or None
    return "\n".join(p for p in parts if p), reason


def _scan_outside(
    data: bytes,
    spans: list[tuple[int, int]],
    runs: bool = True,
    depth: int = 0,
    spans_out: list[tuple[int, int]] | None = None,
    origin: int = 0,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
) -> tuple[str, str | None]:
    """Scan the container's bytes that no other reader has accounted for.

    Everything else in a container is read on purpose: member content through the member
    readers, names, comments and extra fields as text, the end record's comment explicitly.
    What remains is what nobody looks at — bytes prepended before the first header, bytes
    appended after the end record, a local header with no directory record behind it, the
    gaps between structures — and scanning *those* is what keeps a container's own bytes
    read without searching every member a second time and reporting each occurrence twice,
    at a line number that exists only in the concatenation.
    """
    covered: list[tuple[int, int]] = []
    for start, end in spans:
        if 0 <= start < end <= len(data):
            covered.append((start, end))
    covered.sort()
    parts: list[str] = []
    reasons: list[str] = []
    at = 0
    for start, end in covered + [(len(data), len(data))]:
        if start > at:
            gap = data[at:start]
            # The gap decoded as text, not only its printable runs. A container's own bytes are
            # structure and text, and a short term — condition 5's markers are three characters
            # — sits in a gap in the clear while the run pass's six-character minimum drops it;
            # with the run pass as the gap's only reader, a marker prepended to a `.docx` or
            # appended after its end record was covered by nothing and the file cleared with no
            # reason. Decoding the gap whole is safe where a whole *file* decoded whole is not:
            # a gap is bounded by structure, and a file whose bytes are arbitrary is gated by
            # `looks_text` at the file level.
            parts.append(_decode_text(gap))
            if spans_out is not None and origin >= 0:
                # Declared, because it was read: the decode above is this region's reader.
                spans_out.append((origin + at, origin + start))
            text, reason = _binary_readers(
                gap,
                runs=False,
                depth=depth,
                spans_out=spans_out,
                origin=origin + at if origin >= 0 else -1,
                spaces_out=spaces_out,
            )
            parts.append(text)
            if reason:
                reasons.append(reason)
        at = max(at, end)
    return "\n".join(p for p in parts if p), "; ".join(reasons) or None


def _scan_member_blob(
    data: bytes,
    depth: int = 0,
    runs: bool = True,
    spans_out: list[tuple[int, int]] | None = None,
    origin: int = -1,
    local_spans_out: list[tuple[int, int]] | None = None,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
) -> tuple[str, str | None]:
    """Read a zip member the way the file-level scan reads a file.

    Every reader the file-level scan applies is applied here, because a member is just
    a file in a box: printable runs including UTF-16LE, PNG text chunks (handled inside
    `_inflate_zlib_payloads`, which owns the compression budget), PDF-style zlib streams,
    and a further container if the member is one. The name of the member does not decide
    this — a container or an image saved as `payload.xml` is still read as what it is,
    because the bytes are the evidence and the extension is a claim. `depth` bounds the
    nesting, so a container inside a container inside a container stops being followed
    rather than recursing without end.
    """
    parts: list[str] = []
    reasons: list[str] = []
    if _looks_like_zip(data):
        # The depth bound guards container extraction, not reading: a flat file reached
        # at the deepest allowed level is still a file, and returning early on depth
        # alone would leave every PNG, PDF and text member inside it unread.
        if depth >= ZIP_NESTING_LIMIT:
            # The bound stops *descending*, not reading: the container's own bytes still
            # need the binary readers, exactly as a container this check refuses to open
            # does, or a UTF-16 path inside it is invisible.
            text, reason = _binary_readers(
                data, runs=runs, depth=depth, spans_out=spans_out, origin=origin, spaces_out=spaces_out
            )
            return text, "; ".join(r for r in (f"container nested deeper than {ZIP_NESTING_LIMIT} levels was not searched", reason) if r)
        # A nested container is read through the container reader, not scanned as bytes
        # twice: the caller decodes this member's own bytes as text already, which is
        # where a nested archive's member names and comment live, and this call adds the
        # deflated content behind them.
        nested_spans: list[tuple[int, int]] = [] if local_spans_out is None else local_spans_out
        text, reason = _inflate_zip(
            data, depth + 1, runs=runs, spans_out=spans_out, origin=origin, spaces_out=spaces_out, local_spans_out=nested_spans
        )
        # A container whose bytes are nowhere in the file — it was decompressed, so `origin` is
        # negative — has internal reader boundaries that no sweep over the file's own bytes can
        # visit: an inner member's name is read by one call and its payload by another, and a
        # term split across the two is invisible to a literal scan of either. Its boundaries
        # become a space of its own, swept in their own coordinates. This registration lives
        # *here*, where the container is recognised, rather than at each caller: the member path
        # had it, and the ghost-header path and the decoded-payload path did not, which is the
        # same missing registration found three rounds running at three different call sites.
        if spaces_out is not None and origin < 0 and nested_spans:
            entry = (data, sorted({edge for start, end in nested_spans for edge in (start, end)}))
            if entry not in spaces_out:
                spaces_out.append(entry)
        return text, reason
    return _binary_readers(data, runs=runs, depth=depth, spans_out=spans_out, origin=origin, spaces_out=spaces_out)


def _find_local_header_by_name(data: bytes, name: str) -> int:
    """The offset of the first local header in the file whose name is `name`, or -1.

    A search rather than a table: it exists for the case where the central directory's offset
    for a member does not point at a local header at all, so the header has to be found by the
    one field the directory and the header are supposed to agree on.
    """
    for m in islice(re.finditer(re.escape(ZIP_LOCAL_HEADER), data), ARCHIVE_START_LIMIT):
        start = m.start()
        head = data[start + 26:start + 28]
        if len(head) < 2:
            continue
        name_len = int.from_bytes(head, "little")
        if _decode_text(data[start + 30:start + 30 + name_len]) == name:
            return start
    return -1


def _compressed_leftover(data: bytes, info: zipfile.ZipInfo) -> bytes:
    """The bytes inside a member's declared compressed region that its own content does not cover.

    A deflated member declares a compressed size; the deflate stream inside those bytes can end
    before they do, and `zipfile`'s `read()` returns only the decompressed content, so the rest
    is read by nothing while the member's span claims it read. The same holds for a stored member
    whose directory overstates its size. Whatever is left is returned raw, to be decoded as text
    with the member it belongs to and reported, rather than left inside a span with no reader.
    """
    at = info.header_offset
    head = data[at:at + 30]
    if at < 0 or len(head) < 30 or head[0:4] != ZIP_LOCAL_HEADER:
        return b""
    name_len = int.from_bytes(head[26:28], "little")
    extra_len = int.from_bytes(head[28:30], "little")
    body = at + 30 + name_len + extra_len
    region = data[body:body + info.compress_size]
    if info.compress_type == zipfile.ZIP_STORED:
        # A stored member's payload *is* its declared region, so only a directory that
        # overstates the size leaves bytes behind it.
        return region[info.file_size:] if len(region) > info.file_size else b""
    if info.compress_type != zipfile.ZIP_DEFLATED:
        return b""
    # No length comparison against `file_size` here: a deflated region is *normally* smaller
    # than the content it produces — 41 bytes of stream for a 480-byte member is ordinary — so
    # the guard that used to sit above this line returned early on exactly the case this
    # function exists for, and the clear bytes after a deflate stream stayed unread.
    try:
        stream = zlib.decompressobj(-15)
        # `max_length` must exceed the content, or the decompressor stops at the limit with the
        # stream still open and reports the bytes after it as nothing: the member's own read is
        # what bounds the work here, and the budget bounds it for a container that lies about
        # its size.
        stream.decompress(region, max(INFLATE_BYTES_LIMIT, info.file_size + 1))
    except zlib.error:
        return b""
    return stream.unused_data


def _local_header_at(data: bytes, info: zipfile.ZipInfo, names: set[str]) -> tuple[int, str]:
    """Where this member's local header really is, and whether the directory's offset was right.

    The span of a member is recorded from the offset the *central directory* gives, and a
    container whose directory offset is wrong (a malformed or hostile one) had its span
    recorded at those bytes instead of at its real header: the real header then fell outside
    every span, the complement scan read its name, and the same path was reported twice. So
    the offset is checked for a local header signature before it is believed, and the header is
    located by name when it is not — with the malformation reported either way, since a
    container that cannot say where its own member is has not been read to the end.
    """
    at = info.header_offset
    if 0 <= at <= len(data) - 30 and data[at:at + 4] == ZIP_LOCAL_HEADER:
        # A signature is not enough: another member's header has one too, and believing an
        # offset that points at *its* header read that member's name as this one's and
        # reported it twice. The name at the offset decides — equal to the directory's is
        # this member's header; a different name that belongs to another member in this
        # container is that member's header, and this member's own is found by name; a
        # different name that is nobody's is the member whose local and directory names
        # disagree, which `zipfile` refuses to read and which is reported.
        name_len = int.from_bytes(data[at + 26:at + 28], "little")
        local_name = _decode_text(data[at + 30:at + 30 + name_len])
        if local_name == info.filename or local_name not in names:
            return at, ""
    found = _find_local_header_by_name(data, info.filename)
    if found < 0:
        return -1, (
            f"{info.filename!r}: the central directory's offset for this member points at no local "
            "header and no local header of that name was found, so its header was not accounted for"
        )
    return found, (
        f"{info.filename!r}: the central directory's offset for this member points at no local header, "
        "so its header was located by name"
    )


def _member_structural_text(data: bytes, info: zipfile.ZipInfo, at: int) -> str:
    """Everything the container's own structures say about one member, read once.

    The name, the entry's comment, the entry's extra field and the local header's own copy of
    its name and extra field. One function for every member, because these channels belong to
    the *member* rather than to the branch that happens to read a payload: reading them in the
    branch that reads content left a directory entry's comment and extra field read by nothing
    at all, and left an unreadable member's header to the complement scan, which read its name
    a second time. The member's span covers all of these bytes, so no other reader reaches
    them.
    """
    parts = [f"\nZIPMEMBER:{info.filename}:\n"]
    if info.comment:
        parts.append("\n" + info.comment.decode("utf-8", "replace"))
        # A comment is bytes like any other: UTF-16 text decoded as UTF-8 is mojibake, and
        # because the comment's bytes are inside a declared span the complement scan skips
        # them, so a private path written in UTF-16 here was read by nothing.
        parts.append("\n" + _utf16_views(info.comment))
    if info.extra:
        parts.append("\n" + info.extra.decode("utf-8", "replace"))
    local = _local_header_text(data, info, at)
    if local:
        parts.append("\n" + local)
    return "".join(parts)


def _local_header_text(data: bytes, info: zipfile.ZipInfo, at: int) -> str:
    """The local header's own bytes: its fixed fields, and its name and extra field when they differ.

    `info.extra` comes from the central directory; the local header carries its own copy, and
    a container can put different bytes in the two — a private path in a local extra field
    whose directory copy is empty is read by nothing else, because those bytes sit inside the
    member's span and the complement scan does not reach them. They are read here, once, and
    only when they differ: reading an identical copy would report the same bytes twice.

    The name is read here too, and that is not dead code: `zipfile` refuses a member whose
    local and directory names differ, which is exactly the case this read exists for — and the
    member's span now covers its header for every member, including an unreadable one, so the
    complement scan no longer reaches those bytes. It is read only when it decodes to
    something other than the directory's name, since reading an identical copy would report
    the same name twice.
    """
    head = data[at:at + 30]
    if at < 0 or len(head) < 30 or head[0:4] != ZIP_LOCAL_HEADER:
        return ""
    name_len = int.from_bytes(head[26:28], "little")
    extra_len = int.from_bytes(head[28:30], "little")
    local_name = data[at + 30:at + 30 + name_len]
    local_extra = data[at + 30 + name_len:at + 30 + name_len + extra_len]
    # The header's fixed fields — the version, flags, method, times, checksum and sizes at bytes
    # 4 to 30, before the name. They are inside the member's span, so no other reader in this
    # module reaches them, and a marker short enough to fit in one of them (condition 5's terms
    # include three-character ones) was read by nothing at all and cleared.
    out: list[str] = [_decode_text(head[4:30])]
    if local_name and _decode_text(local_name) != info.filename:
        out.append(_decode_text(local_name))
    if local_extra and local_extra != info.extra:
        out.append(_decode_text(local_extra))
    return "\n".join(o for o in out if o)


def _member_body_at(data: bytes, at: int) -> int:
    """Where a local header's fixed fields, name and extra field end and its payload begins.

    One function because two callers need the same arithmetic and a second copy of it is how
    one of them drifts: the span recorder splits the member here, and the nested read has to
    know the payload's offset in the file to say where its bytes are.
    """
    head = data[at:at + 30]
    if len(head) < 30:
        return at
    return at + 30 + int.from_bytes(head[26:28], "little") + int.from_bytes(head[28:30], "little")


def _account_member_span(data: bytes, info: zipfile.ZipInfo, spans: list[tuple[int, int]], at: int) -> None:
    """Record the bytes of one member: its local header, its name, its extra field, its payload.

    One function for both branches — a member with a body and a directory entry without one —
    because a rule added to one branch and not its mirror is how a directory entry's name came
    to be read twice: the file branch accounted for its local header and the directory branch
    did not, so the complement scan read the directory's name again and reported it twice.
    """
    if at < 0:
        # The directory's offset points at no local header and none of that name was found:
        # accounting the bytes it names would hide bytes no reader has read, so nothing is
        # accounted for and the complement scan reads whatever is there.
        return
    body = _member_body_at(data, at)
    if body <= at:
        return
    head = data[at:at + 30]
    name_len = int.from_bytes(head[26:28], "little") if len(head) == 30 else 0
    name_at = min(body, at + 30)
    extra_at = min(body, max(name_at, at + 30 + name_len))
    # Two spans, not one: the header (fixed fields, name and extra field, read by the
    # structural reader) and the payload (read by the member's own decode). The boundary
    # between them is where a term can be split and seen by neither reader, and the sweep can
    # only find it if that boundary is an edge — with the member recorded as one range, a term
    # split across the name and the body was contiguous in the file's bytes and reported
    # nowhere. Recorded from the offset the header was *found* at, not the one the directory
    # claims, or a wrong claim hides the real header.
    # Four parts, so each boundary inside the header is an edge: the fixed fields (read by the
    # local-header reader), the name and the extra field (read as the member's own, or read as
    # a copy of the directory's — either way accounted for), and the payload. One range over the
    # header hid the name/extra boundary the same way one range over the record hid the
    # name/comment boundary.
    spans.extend(
        (start, stop)
        for start, stop in ((at, name_at), (name_at, extra_at), (extra_at, body), (body, body + info.compress_size))
        if stop > start
    )


def _zip_member_text(
    zf: zipfile.ZipFile,
    depth: int,
    data: bytes,
    runs: bool = True,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
) -> tuple[str, str | None, list[tuple[int, int]]]:
    """Text of a container's members, read member by member.

    Two rules decide what happens here, and the member's *name* is not one of them in
    the way it looks: every member gets the full set of readers, and every member's name
    is itself searchable text. A private path is just as hidden in
    `word/media/<path>/image.png` as in the bytes behind that name, and a member the
    readers find nothing in would otherwise contribute nothing at all.

    Returns the text, the reasons, and the byte spans this pass accounted for — member
    regions, the directory and the end record. The caller scans the complement of all of
    them once over the whole file.
    """
    chunks: list[str] = []
    reasons: list[str] = []
    skipped: list[str] = []
    payload: list[tuple[int, int]] = []
    over_limit = False
    # The archive comment is text in the container, and it is read before any member:
    # nothing else in this module looks at it, and a container with ordinary member
    # content returns from the file-level scan before any raw-byte fallback could.
    if zf.comment:
        chunks.append(f"\nZIPCOMMENT:{zf.comment.decode('utf-8', 'replace')}")
        # See the member-comment reader: UTF-16 in a comment is text this file is meant to catch.
        chunks.append("\n" + _utf16_views(zf.comment))
    # `islice` bounds the work done here, not the memory `zipfile` already spent: opening
    # the container parses its central directory. `_inflate_zip` refuses to open one whose
    # end-of-central-directory record declares more members than ZIP_OPEN_MEMBER_CAP, and
    # this bound is what stops the loop long before processing them all.
    # The directory's list, materialised once: the names are needed before a member is read —
    # to tell this member's own local header from another member's at the same offset.
    members = list(islice(zf.infolist(), ZIP_MEMBER_LIMIT + 1))
    member_names = {m.filename for m in members}
    for index, info in enumerate(members):
        if index >= ZIP_MEMBER_LIMIT:
            # The same rule as the stream and byte bounds: stopping early leaves
            # members unread, and members that were never read cannot be cleared.
            over_limit = True
            break
        # Where the header really is, resolved once per member and used by every branch below:
        # the central directory's offset is believed only when a local header signature is
        # there, and a member whose offset points elsewhere is located by name and reported.
        header_at, header_reason = _local_header_at(data, info, member_names)
        if header_reason:
            skipped.append(header_reason)
        # Read for every member, before any branch decides whether its payload is readable:
        # a directory entry, an unreadable member and a member too big to read carry a name,
        # a comment and an extra field just as a readable one does, and reading them only in
        # the branch that reads content left two of those channels read by nothing.
        structural = _member_structural_text(data, info, header_at)
        if info.is_dir() and info.compress_size == 0:
            # A directory entry with no payload: its name, comment, extra field and
            # local header are text in the container like any other member's:
            # `word/media/<private path>/` is a place a private path can be written, and
            # skipping the entry outright made it invisible.
            chunks.append(structural)
            _account_member_span(data, info, payload, header_at)
            continue
        # A directory entry *with* a payload is read like any other member: the entry's span
        # covers the payload, so taking this branch on `is_dir()` alone put those bytes inside
        # a span and read by nothing — a private path in a directory entry's body was cleared
        # with no reason, and the entry's own name was the only thing read.
        if info.file_size > TEXT_READ_CAP:
            # Same rule as the file caps: a member too big to read is reported, not
            # skipped in silence. Its name is still searched.
            chunks.append(structural)
            skipped.append(info.filename)
            # Its span, like a readable member's: its header's bytes were just read here, and
            # its payload is reported as unsearched rather than cleared, which is what the
            # claim asks for. Leaving the span unaccounted made the complement read the
            # header again and report the same name twice.
            _account_member_span(data, info, payload, header_at)
            continue
        try:
            # Read at most the declared size: zipfile caps read() at the header's
            # file_size, so a member that *understates* its size cannot be read past
            # it (zipfile validates the decompressed length against the header and
            # raises instead, which lands in the handler below).
            with zf.open(info) as member:
                body_bytes = member.read()
        except Exception:
            # An unreadable member cannot be cleared, so it is reported rather than
            # skipped: unknown content is the one thing a boundary check must not wave through.
            chunks.append(structural)
            skipped.append(f"{info.filename} (unreadable)")
            # Accounting the span is what keeps the name from being reported twice: it was
            # read here, and the complement scan reads whatever no span covers.
            _account_member_span(data, info, payload, header_at)
            continue
        # The decode is for line-accurate reporting, not for detection: the runs scan
        # inside `_scan_member_blob` sees the same literal paths, but it collapses lines,
        # so a finding would always point at line 1 of the member. Detection is the runs
        # scan's, the container readers', and the member name above.
        # A member that is itself a container is read by the container reader, and by that
        # reader alone: its member names, comments and extra fields are read there with the
        # member they belong to, so decoding the same bytes here as text would find every
        # one of them a second time, one concatenated line further down.
        # The member's declared compressed region can hold bytes the stream never consumed:
        # `read()` returns the *decompressed* length, so anything after the end of the deflate
        # stream — or after the payload of a stored member, when the directory overstates its
        # size — sits inside the member's span and is read by no reader at all. A private path
        # written in the clear there was cleared with no reason, and the sweep cannot see it
        # either, because those bytes are inside a span rather than across one.
        # A member whose sizes are declared to live in a data descriptor can meet a directory
        # that never received them — a streamed archive whose central record kept a placeholder.
        # `zipfile` believes the placeholder, returns an empty member for content that is sitting
        # in the file, and the term inside the real deflate stream is then read by nothing while
        # every reader reports the member read. So when the flag is set, the bytes from this
        # member's body to the next structure are inflated too, and a disagreement with the
        # declared sizes is reported rather than passed over.
        stop = len(data)
        body_at = _member_body_at(data, header_at)
        for signature in (ZIP_LOCAL_HEADER, b"PK\x01\x02", ZIP_EOCD):
            found_next = data.find(signature, body_at)
            if found_next >= 0:
                stop = min(stop, found_next)
        beyond = data[body_at:stop][:BINARY_READ_CAP]
        # What the member's own stream actually holds, read from its body to the next structure
        # rather than to the size it declares. A directory that understates a member's
        # compressed size — a placeholder a data descriptor never filled in, an edited field —
        # leaves the real stream outside the member's span: it falls into a gap, where a
        # decompressed term is invisible to every reader, and `zipfile` returns an empty member
        # for content that is in the file. So the region is inflated here too, raw deflate first
        # and the zlib wrapper second, and a disagreement with the declared sizes is reported
        # rather than passed over.
        stream_bytes = b""
        # A stored member's payload *is* its content — there is no stream to read past a size —
        # and inflating those bytes anyway produced a false reason on a member whose text merely
        # happened to look like deflate.
        if beyond and info.compress_type != zipfile.ZIP_STORED:
            for wbits in (-15, 15):
                try:
                    stream_bytes = zlib.decompressobj(wbits).decompress(beyond, INFLATE_BYTES_LIMIT)
                except zlib.error:
                    stream_bytes = b""
                if stream_bytes:
                    break
        if stream_bytes and len(stream_bytes) > info.file_size:
            chunks.append(stream_bytes.decode("utf-8", "replace"))
            skipped.append(
                f"{info.filename}: its declared sizes do not account for the bytes its stream "
                "holds, so they were read beyond them"
            )
        leftover = _compressed_leftover(data, info)
        is_container = _looks_like_zip(body_bytes)
        # The decode is what detection of *short* text depends on: the runs scan requires
        # a printable run of at least six characters, and condition 5's markers include
        # three-character ones, so a member holding nothing but such a marker is invisible
        # to the runs scan and visible only here.
        text = "" if is_container else body_bytes.decode("utf-8", "replace")
        # `runs=False`: this member's bytes were just decoded above, and the printable-run
        # pass over the same bytes would find the same text again, one concatenated line
        # further down, and report every occurrence twice.
        nested_spans: list[tuple[int, int]] = []
        extra, extra_reason = _scan_member_blob(
            body_bytes,
            depth,
            runs=is_container,
            spans_out=payload if info.compress_type == 0 else None,
            local_spans_out=nested_spans,
            spaces_out=spaces_out,
            # The payload's bytes are in the file only when the member stores them raw. An
            # inflated payload exists nowhere in the file, so an edge inside it would be a
            # boundary in text no sweep over the file's own bytes could ever visit, and
            # reporting one would claim coverage for bytes that are not there.
            origin=_member_body_at(data, header_at) if info.compress_type == 0 else -1,
        )
        # The space this container's boundaries need is registered in `_scan_member_blob`, where
        # the container is recognised, so that every caller gets it — this one, a local header no
        # directory record lists, and a decoded PDF or PNG payload. Registering it here as well
        # would add the same space twice.
        if extra:
            text += "\n" + extra
        if leftover:
            # Inside the member's declared compressed region but after the end of the bytes its
            # own content occupies: read here, with the member, and reported — the file is not
            # fully read in the sense the claim means, since a container that overstates a
            # member's size is describing bytes no directory record accounts for.
            text += "\n" + _decode_text(leftover)
            skipped.append(f"{info.filename} ({len(leftover)} bytes after the end of its declared compressed region)")
        # The structural channels first, then the payload: `structural` carries the name, the
        # entry's comment and extra field and the local header's own copies, read once for
        # every member by the same function.
        chunks.append(structural + text)
        if extra_reason:
            skipped.append(f"{info.filename} ({extra_reason})")
        # The bytes of this member, so the complement scan below does not search them a
        # second time.
        _account_member_span(data, info, payload, header_at)
    # The container's own bytes: everything the readers above have not accounted for. The
    # directory itself is covered — every record's name, comment and extra field was read —
    # and so is the end record and its comment, so both are spans too.
    at, cd_at, cd_size, _, _ = _directory_window(data)
    if at is not None:
        # The end record's fixed fields — the disk numbers, the counts and the offsets at bytes
        # 4 to 22 — are read here as text and spanned, the rule the directory records follow and
        # for the same reason. Left to the complement instead, their only reader is the
        # printable-run pass, whose six-character minimum is longer than a marker: a container
        # carrying one in a count field was cleared with no reason, and its bytes were in the
        # clear. Reading them without spanning them would report each of them twice.
        fixed = _decode_text(data[at:at + 22])
        if fixed.strip("\x00"):
            chunks.append("\nZIPEOCD:\n" + fixed)
        payload.append((at, min(len(data), at + 22)))
        # The zip64 end record and its locator are the same shape of hole and are read and
        # spanned the same way: fixed fields, no other reader, and a three-character marker
        # fits in any of them.
        locator = data.rfind(ZIP64_LOCATOR)
        if locator >= 0:
            payload.append((locator, min(len(data), locator + 20)))
            chunks.append("\nZIP64LOCATOR:\n" + _decode_text(data[locator:locator + 20]))
            zip64_at = int.from_bytes(data[locator + 8:locator + 16], "little")
            if zip64_at >= 0:
                payload.append((zip64_at, min(len(data), zip64_at + 56)))
                chunks.append("\nZIP64EOCD:\n" + _decode_text(data[zip64_at:zip64_at + 56]))
        comment_len = int.from_bytes(data[at + 20:at + 22], "little")
        if comment_len:
            payload.append((at + 22, min(len(data), at + 22 + comment_len)))
        if cd_at + cd_size <= len(data):
            # From the shared window rather than from the end record's own two 32-bit
            # fields: in a zip64 container those hold sentinels, the span they give is
            # nonsense, and dropping it left the directory in the complement — every member
            # name found a second time by the raw scan.
            #
            # Each record is read whole — its fixed fields here, its name, extra field and
            # comment with the member they belong to — and each record is spanned whole, so
            # the complement scan can read none of it twice.
            record_text, record_spans = _directory_record_text(data, cd_at, cd_size)
            if record_text:
                chunks.append("\nZIPDIRECTORY:\n" + record_text)
            for span in record_spans:
                payload.append(span)
    if skipped:
        shown = ", ".join(sorted(skipped)[:4]) + (" …" if len(skipped) > 4 else "")
        reasons.append(f"zip member(s) that could not be read to the end were not searched: {shown}")
    if over_limit:
        # The same rule as the stream, byte and nesting bounds: a bound that stops work
        # reports itself, and it reports *itself* rather than joining a compound sentence
        # that leaves a reader guessing which of three causes fired.
        reasons.append(f"more than {ZIP_MEMBER_LIMIT} members in one container; the rest were not searched")
    # The spans go back to the caller rather than being scanned here: the caller holds the
    # whole file, and the complement of *every* archive in it is what has to be read once.
    # Scanning here would read the same gap twice for a file with two archives in it.
    return "".join(chunks), "; ".join(reasons) if reasons else None, payload


def _directory_record_text(data: bytes, cd_at: int, cd_size: int) -> tuple[str, list[tuple[int, int]]]:
    """Each central-directory record's fixed fields as text, and the span of each record.

    A record is 46 fixed bytes, then its name, its extra field and its comment. The three
    written channels are read with the member they belong to (`info.filename`, `info.extra`,
    `info.comment`); the fixed fields — version, flags, method, times, checksum, sizes,
    attributes and the local-header offset — are read here. Both are spanned, and the span is
    the whole record, so the complement scan cannot read either a second time.

    Read *and* spanned, rather than spanned alone: a span is a claim that a reader read those
    bytes, and marking the fixed fields read while reading them nowhere is how a
    three-character marker in an attributes field came to be cleared with no reason. The same
    rule as a member's local header, which is spanned and read for the same purpose.
    """
    texts: list[str] = []
    spans: list[tuple[int, int]] = []
    at = cd_at
    end = cd_at + cd_size
    for _ in range(ZIP_MEMBER_LIMIT):
        if at + 46 > end:
            break
        name_len = int.from_bytes(data[at + 28:at + 30], "little")
        extra_len = int.from_bytes(data[at + 30:at + 32], "little")
        comment_len = int.from_bytes(data[at + 32:at + 34], "little")
        written = at + 46
        written_end = min(end, written + name_len + extra_len + comment_len)
        texts.append(_decode_text(data[at + 4:at + 46]))
        # Spanned by part, not as one record: the fixed fields are read here, the name, extra
        # field and comment are read with the member they belong to, and a boundary between two
        # readers is where a term held in the clear gets split and seen by neither — the record
        # is contiguous in the file, so a path whose two halves are the name and the comment was
        # found by nothing while every reader reported the record read.
        name_end = min(end, written + name_len)
        extra_end = min(end, name_end + extra_len)
        spans.extend(
            (start, stop)
            for start, stop in ((at, written), (written, name_end), (name_end, extra_end), (extra_end, written_end))
            if stop > start
        )
        at = written_end
    return "\n".join(t for t in texts if t), spans


def _eocd_offset(data: bytes) -> int | None:
    """Where the end-of-central-directory record starts, found the way `zipfile` finds it.

    Searching backwards is not a detail. The record's own length is fixed and its comment
    is free bytes, so a comment can hold a well-formed `PK\x05\x06` with any count it
    likes; a count read from *that* record is the attacker's number, and `zipfile` would
    go on to open the real one. `zipfile` accepts only a record whose comment length
 accounts for the bytes to the end of the file. That rule is right and it is not enough on
 its own: a digitally-signed or merely padded container has bytes *after* the record — a
 signature blob appended by a signing tool, a newline from a transfer — and demanding that
 the record reach the very end made this check refuse a container every real reader opens,
 then say so with a reason that was false about the file. So a record is also accepted when
 its comment length accounts for the bytes up to some trailing remainder, and the last such
 record wins: the strict match is returned first because it is the one a comment cannot
 manufacture, and a loose candidate still has to survive the slice validation downstream,
    which reads a directory only when its own offsets and sizes land on real records.
    """
    at = len(data) - 22
    floor = max(0, len(data) - 22 - 0xFFFF)
    loose: int | None = None
    while at >= floor:
        if data[at:at + 4] == ZIP_EOCD:
            comment_len = int.from_bytes(data[at + 20:at + 22], "little")
            end = at + 22 + comment_len
            if end == len(data):
                return at
            if end < len(data) and loose is None:
                loose = at
        at -= 1
    return loose


def _directory_window(data: bytes) -> tuple[int | None, int, int, int, str | None]:
    """(record offset, directory offset, directory size, offset the directory must end at,
    why they cannot be read).

    The fourth value is where the directory has to end for the record's offsets to mean what
    they say: at the end record itself, or at the zip64 end record when there is one, since
    a zip64 container lays the directory out before that record rather than before the
    record that carries the sentinels.

    The zip64 override lives here so every reader of these two fields gets the same
    answer: in a zip64 container the 32-bit fields hold sentinels, and read as offsets
    they point the directory past the end of the file. Reading them in one function is
    what stops three callers from disagreeing about where the directory is.
    """
    at = _eocd_offset(data)
    if at is None:
        return None, 0, 0, 0, "no end-of-central-directory record this check can read"
    cd_at = int.from_bytes(data[at + 16:at + 20], "little")
    cd_size = int.from_bytes(data[at + 12:at + 16], "little")
    anchor = at
    locator = at - 20
    if locator >= 0 and data[locator:locator + 4] == ZIP64_LOCATOR:
        zip64_at = int.from_bytes(data[locator + 8:locator + 16], "little")
        if zip64_at < 0 or zip64_at + 56 > len(data) or data[zip64_at:zip64_at + 4] != ZIP64_EOCD:
            return at, 0, 0, at, "its zip64 end-of-central-directory record could not be read"
        cd_size = int.from_bytes(data[zip64_at + 40:zip64_at + 48], "little")
        cd_at = int.from_bytes(data[zip64_at + 48:zip64_at + 56], "little")
        anchor = zip64_at
    return at, cd_at, cd_size, anchor, None


def _describes_itself(data: bytes) -> str | None:
    """None when the end record describes *this* byte range, a reason when it does not.

    A container is laid out [local headers and payloads][central directory][end record],
    so the directory has to end exactly where the record begins. When it ends earlier, the
    record is describing an archive that starts that many bytes into this slice — which is
    how a file with bytes prepended, or two archives concatenated, or a decoy record
    appended after the real one, presents itself. Believing such a record is what lets a
    real container be read as a smaller, self-consistent, empty one: the count agrees with
    an empty directory, `zipfile` opens it, and every member the real directory lists is
    read by nothing, with no reason reported.
    """
    _, cd_at, cd_size, anchor, problem = _directory_window(data)
    if problem:
        return problem
    start = anchor - (cd_at + cd_size)
    if start < 0:
        return f"its directory ends {-start} bytes past the record that declares it"
    if start == 0:
        return None
    if data[start:start + 4] == ZIP_LOCAL_HEADER:
        return (
            f"its record describes an archive starting at byte {start} of these bytes, not this range: "
            f"the directory ends at byte {cd_at + cd_size} and its record is expected at byte {anchor}"
        )
    return (
        f"its directory ends at byte {cd_at + cd_size} while the record it describes sits at byte {anchor}, "
        "and no archive starts where that leaves the file"
    )


def _declared_member_count(data: bytes) -> tuple[int | None, str | None]:
    """(members the container claims, why the claim cannot be read).

    `zipfile` parses the whole central directory into memory when a container is opened,
    so a bound applied *after* opening bounds only the processing, not the allocation.
    Reading the count first is what makes `ZIP_OPEN_MEMBER_CAP` a real limit — and it is
    also where the two ways of getting the count wrong live: a 16-bit field that is a
    zip64 *sentinel* rather than a count, and a count that is not the count.
    """
    at, _, _, _, problem = _directory_window(data)
    if problem:
        return None, problem
    assert at is not None
    total = int.from_bytes(data[at + 10:at + 12], "little")
    locator = at - 20
    has_locator = locator >= 0 and data[locator:locator + 4] == ZIP64_LOCATOR
    if total == 0xFFFF or has_locator:
        # A zip64 container's real count is 8 bytes wide and lives in the zip64 record the
        # locator points at. Reading the 16-bit field instead would read a sentinel as a
        # count: 65,536 members arrive as 0, which is under every cap there is.
        if not has_locator:
            return None, "declares a zip64 member count with no locator this check can read"
        zip64_at = int.from_bytes(data[locator + 8:locator + 16], "little")
        if zip64_at < 0 or zip64_at + 40 > len(data) or data[zip64_at:zip64_at + 4] != ZIP64_EOCD:
            return None, "declares a zip64 member count with no record this check can read"
        return int.from_bytes(data[zip64_at + 32:zip64_at + 40], "little"), None
    return total, None


def _unopenable(data: bytes, reason: str, depth: int = 0) -> tuple[str, str | None]:
    """A container this check will not open: its own bytes are still bytes.

    Refusing to open a container is not a reason to stop reading it. The members stay
    unread, and that is reported, but the bytes that belong to no member are read by the
    binary readers: a private path can sit in front of a header, behind the end record, or
    in a local header no directory record lists, in a container nobody will open.
    """
    text, scanned_reason = _binary_readers(data, depth=depth)
    return text, "; ".join(r for r in (reason, scanned_reason) if r)


def _directory_matches(data: bytes, declared: int) -> tuple[bool, str | None]:
    """Whether the directory holds the number of records the count claims.

    A record that declares *fewer* members than the directory holds is the dangerous
    direction: `zipfile` iterates the declared number, so the members past it are never
    inflated, and a private path inside them is read by nothing while every bound here sees
    a small, comfortable number. Counting the records is the only way to know the count is
    the count.
    """
    at, cd_at, cd_size, _, problem = _directory_window(data)
    if problem:
        return False, problem
    if cd_at + cd_size > len(data):
        return False, f"the record points its central directory at bytes {cd_at}..{cd_at + cd_size}, outside the file"
    at = cd_at
    end = cd_at + cd_size
    records = 0
    while at + 46 <= end:
        if data[at:at + 4] != ZIP_CENTRAL_HEADER:
            return False, f"the directory's record {records + 1} does not start with a record signature"
        # The record's own field lengths say where the next one starts. Counting the
        # signature bytes instead would be spoofed by a comment or extra field that
        # contains them — the same four bytes, in bytes nobody parses.
        name_len = int.from_bytes(data[at + 28:at + 30], "little")
        extra_len = int.from_bytes(data[at + 30:at + 32], "little")
        comment_len = int.from_bytes(data[at + 32:at + 34], "little")
        at += 46 + name_len + extra_len + comment_len
        records += 1
    if at != end:
        return False, f"the directory's records reach byte {at} while the record declares it ends at {end}"
    if records != declared:
        return False, f"the record declares {declared} members while the central directory holds {records} records"
    return True, None


def _inflate_zip(
    data: bytes,
    depth: int = 0,
    runs: bool = True,
    spans_out: list[tuple[int, int]] | None = None,
    origin: int = 0,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
    local_spans_out: list[tuple[int, int]] | None = None,
) -> tuple[str, str | None]:
    """Text of every zip container in these bytes, and of the bytes around them.

    A file can hold more than one archive: bytes prepended to one shift every offset inside
    it, two archives can be concatenated into one file, and a record can be appended after
    the real one. So an archive is read as a *slice its own record endorses* — the slice
    whose record describes it, which for a shifted or concatenated file starts part way in.
    Believing a record that describes some other range is how a real container gets opened
    as a smaller, self-consistent, empty one and cleared in silence, so the endorsement is
    the gate. Whatever the accepted slices do not account for is read once, at the end, by
    the binary readers: bytes in front of the first archive, bytes between two of them,
    bytes behind the last record, and local headers no directory record lists.

    `runs=False` for a container that is itself a member whose bytes a caller has already
    decoded as text: the printable-run pass over the same bytes would find that text again.
    """
    problem = _structural_problem(data)
    if problem is None:
        # The ordinary case, and the only one worth a fast path: the whole range is one
        # archive, opened once, with one complement scan at the end.
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                text, reason, spans = _zip_member_text(zf, depth, data, runs=runs, spaces_out=spaces_out)
        except Exception as exc:
            problem = f"looks like a zip container but would not open ({exc.__class__.__name__})"
        else:
            return _with_the_complement(
                data, [(0, text, reason, spans)], runs, depth, spans_out, origin, spaces_out, local_spans_out
            )
    signatures = list(islice(re.finditer(re.escape(ZIP_LOCAL_HEADER), data), ARCHIVE_START_LIMIT))
    starts = sorted({0} | {m.start() for m in signatures})
    # Where a slice can end: at the next archive's first local header, or at the end of an
    # end record. A record appended after a complete archive is not a local header, and the
    # slice that archive describes is the one ending exactly where that record begins.
    ends_pool = sorted(
        {m.start() for m in signatures}
        | {m.start() + ZIP_EOCD_LEN for m in islice(re.finditer(re.escape(ZIP_EOCD), data), ARCHIVE_START_LIMIT)}
    )
    accepted: list[tuple[int, str, str | None, list[tuple[int, int]]]] = []
    covered_to = 0
    for index, start in enumerate(starts):
        if start < covered_to:
            continue
        # The candidates after this one are the plausible ends: the next archive starts
        # there. A local-header signature *inside* a member's bytes is a candidate too, and
        # trying it costs one structural check that fails, which is why a few are tried
        # rather than only the next one.
        ends = [end for end in ends_pool if end > start][:ARCHIVE_END_TRIES] + [len(data)]
        for end in ends:
            if _structural_problem(data[start:end]) is not None:
                continue
            try:
                with zipfile.ZipFile(io.BytesIO(data[start:end])) as zf:
                    text, reason, member_spans = _zip_member_text(zf, depth, data[start:end], runs=runs, spaces_out=spaces_out)
            except Exception:
                continue
            accepted.append((start, text, reason, [(start + s, start + e) for s, e in member_spans]))
            covered_to = end
            break
    if not accepted:
        return _unopenable(data, f"{problem}, so its members cannot be listed and the container was not opened", depth)
    return _with_the_complement(data, accepted, runs, depth, spans_out, origin, spaces_out, local_spans_out)


def _with_the_complement(
    data: bytes,
    accepted: list[tuple[int, str, str | None, list[tuple[int, int]]]],
    runs: bool,
    depth: int = 0,
    spans_out: list[tuple[int, int]] | None = None,
    origin: int = 0,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
    local_spans_out: list[tuple[int, int]] | None = None,
) -> tuple[str, str | None]:
    """The accepted archives' text, plus one scan of every byte they did not account for.

    One scan for the whole file, not one per archive: two archives concatenated into one
    file share a complement, and scanning per archive would read the bytes between them
    twice and report the same occurrence at two line numbers.
    """
    texts = [text for _, text, _, _ in accepted]
    reasons = [reason for _, _, reason, _ in accepted if reason]
    spans = [span for _, _, _, member_spans in accepted for span in member_spans]
    if local_spans_out is not None:
        # The same ranges in the coordinates they were found in. `spans_out` filters by origin
        # because an offset that means nothing in the file must not become an edge there; a
        # caller with a place for them — the bytes of a compressed member that is itself a
        # container — needs them unfiltered, or that place has no edges to sweep against.
        local_spans_out.extend(spans)
    if spans_out is not None and origin >= 0:
        # Translated into the file's own coordinates: `data` is a slice or a member's bytes, and
        # a span means nothing to a sweep over the file unless it says where those bytes are.
        # `origin` is -1 when the bytes are not in the file at all — an inflated member — which
        # is why a container inside a deflated member contributes no edges.
        spans_out.extend((origin + start, origin + end) for start, end in spans)
    own, own_reason = _scan_outside(data, spans, runs, depth, spans_out, origin, spaces_out)
    if own:
        texts.append(own)
    if own_reason:
        reasons.append(own_reason)
    return "\n".join(t for t in texts if t), "; ".join(reasons) or None


def _structural_problem(data: bytes) -> str | None:
    """Why this container's own records do not support opening it, or None if they do.

    Three separate questions, asked in the order that costs least and refuses earliest: can
    the member count be read at all, is it inside the open cap, and does the directory bear
    it out. The cap comes before the directory check because a count past the cap is reason
    enough on its own, and the work of counting records is not worth doing for a container
    this check will not open.
    """
    declared, problem = _declared_member_count(data)
    if problem:
        return problem
    if declared > ZIP_OPEN_MEMBER_CAP:
        return f"container declares {declared} members, past the {ZIP_OPEN_MEMBER_CAP}-member open cap"
    ok, problem = _directory_matches(data, declared)
    if not ok:
        return problem
    # Last, because it is the cheapest question and the one that only matters for a
    # container whose records are otherwise consistent.
    return _describes_itself(data)


def _inflate_bounded(blob: bytes, limit: int) -> tuple[bytes | None, bool]:
    """Decompress at most `limit` bytes of a zlib stream.

    Returns (raw, partial). `partial` is true when the stream was not read to its
    end — either the output cap stopped it (`unconsumed_tail` left over) or the
    input was cut short (`eof` never reached, which is what a payload truncated by a
    chance `endstream` inside the compressed bytes looks like). A payload that
    cannot be read in full must be reported, not scanned as if it were whole.

    The cap is passed *into* the decompressor, not checked after it: one well-formed
    deflate stream can inflate to something enormous, and a budget decremented after
    the fact would only stop the *next* payload.
    """
    if limit <= 0:
        return None, True
    pieces: list[bytes] = []
    data = blob
    budget = limit
    obj = zlib.decompressobj()
    for _ in range(16):
        try:
            piece = obj.decompress(data, budget)
        except zlib.error:
            # Not a zlib stream at all if nothing came out of it; if a stream already produced
            # content, what follows it could not be read and the payload is partial.
            return (None, False) if not pieces else (b"".join(pieces), True)
        pieces.append(piece)
        budget -= len(piece)
        if obj.unused_data:
            # More compressed bytes follow the stream that just ended cleanly. `eof` is already
            # true here, so the old check — `bool(obj.unconsumed_tail) or not obj.eof` — called
            # this payload read in full while dropping everything after the first stream: a
            # whole second stream, with a private path in it, was never inflated, never
            # flagged, and carried no reason. `_compressed_leftover` reads `unused_data` for the
            # member case and is pinned; this is that rule at the payload reader.
            data = obj.unused_data
            if budget <= 0:
                return b"".join(pieces), True
            obj = zlib.decompressobj()
            continue
        if obj.unconsumed_tail or not obj.eof:
            return b"".join(pieces), True
        break
    else:
        return b"".join(pieces), True
    return b"".join(pieces), False


def _looks_deflate(blob: bytes) -> bool:
    """A zlib wrapper header, which is what a FlateDecode stream starts with."""
    return len(blob) >= 2 and blob[0] == 0x78 and blob[1] in (0x01, 0x5E, 0x9C, 0xDA)


def _read_a_decoded_payload(
    raw: bytes,
    depth: int,
    spaces_out: list[tuple[bytes, list[int]]] | None,
) -> tuple[str, str | None]:
    """Bytes a reader *produced* — not bytes in the file — read with the readers a member gets.

    An inflated PDF stream or PNG text chunk can hold a whole container: an Office document
    saved inside a PDF, or carried in a PNG's compressed metadata. Its members' own deflate
    streams are invisible to a printable-run pass, so a private path in one was cleared with
    no reason. The bytes exist nowhere in the file, so their boundaries cannot be edges in
    the file's coordinates: they are read as a space of their own, the same rule a compressed
    member that is itself a container gets.
    """
    if depth >= ZIP_NESTING_LIMIT:
        text, _ = printable_runs(raw), None
        return text, "a decoded payload was not searched as a container: past the nesting limit"
    if _looks_like_zip(raw):
        return _scan_member_blob(raw, depth + 1, runs=True, spaces_out=spaces_out)
    return _binary_readers(raw, runs=True, depth=depth + 1, origin=-1, spaces_out=spaces_out)


def _inflate_zlib_payloads(
    data: bytes,
    depth: int = 0,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
) -> tuple[str, str | None]:
    """Text inside zlib-compressed payloads a text scan cannot see.

    Two real containers: PDF content streams (`stream ... endstream`, which
    FlateDecode compresses) and PNG text chunks (zTXt compressed, iTXt when its
    flag says so). Bounded on purpose — a stream count, a per-payload cap and a
    total byte budget — so a hostile or merely huge file cannot turn a release
    check into a hang or an allocation bomb.

    Every way of not reading a payload to its end is reported, and the reason names the
    bound that actually fired rather than listing them: stopping early for either bound
    leaves matches unprocessed, an inflate that fails on a payload that *looks* like
    deflate means the stream could not be read (a compressed payload truncated by a chance
    `endstream` inside it reads exactly like this), and a payload cut off by its own cap
    comes back partial. A stream that simply is not
    deflate — an embedded JPEG, an uncompressed stream — is skipped in silence on
    purpose: its bytes are in the file and the printable-run scan already covers
    them, so reporting it would fail every PDF that carries an image.
    """
    chunks: list[str] = []
    reasons: list[str] = []
    stream_limit_hit = False
    budget_hit = False
    partial_payload = False
    cut = False
    unreadable: list[int] = []
    budget = INFLATE_BYTES_LIMIT
    # The matches are consumed lazily, never materialised: a 32 MB file of empty
    # `stream ... endstream` markers would otherwise build millions of match objects
    # before the stream bound could stop anything, which is an allocation bomb in the
    # middle of a release check. One lookahead past the bound is what tells us that
    # matches remain un-inflated.
    matches = PDF_STREAM.finditer(data)
    for i, m in enumerate(islice(matches, INFLATE_STREAM_LIMIT)):
        if budget <= 0:
            # Either bound stopping the loop means the remaining matches were never
            # inflated, which is precisely what must be reported — and the reason has to
            # name the bound that actually fired, or it is a false statement about the file.
            budget_hit = True
            break
        blob = m.group(1)
        raw, partial = _inflate_bounded(blob, min(budget, INFLATE_BYTES_LIMIT))
        if raw is None:
            if _looks_deflate(blob):
                unreadable.append(i + 1)
            continue
        budget -= len(raw)
        cut = cut or partial
        # A payload cut short *because the budget ran out* is the budget's story, not a
        # second cause, and reporting both for one cause is what a reviewer asked to stop.
        # So the two are tracked apart: `cut` is any partial payload, `partial_payload` is
        # one cut short with budget to spare, which is its own cause.
        if partial and budget > 0:
            partial_payload = True
        chunk, chunk_reason = _read_a_decoded_payload(raw, depth, spaces_out)
        if chunk:
            chunks.append(chunk)
        if chunk_reason:
            reasons.append(chunk_reason)
    if not budget_hit and next(islice(matches, 0, 1), None) is not None:
        # Only when the loop ran out of *matches*: a loop cut short by the budget leaves
        # matches behind too, and reporting that as the stream count would name a bound
        # that never fired.
        stream_limit_hit = True
    png_chunks, png_reasons, budget = _png_text_chunks(data, budget, depth, spaces_out)
    chunks.extend(png_chunks)
    reasons.extend(png_reasons)
    if budget <= 0:
        budget_hit = True  # spent here or in a PNG: either way the file was not read in full
    if unreadable:
        shown = ", ".join(f"#{n}" for n in unreadable[:4]) + (" …" if len(unreadable) > 4 else "")
        reasons.insert(0, f"PDF stream(s) {shown} look like deflate but did not decompress and were not searched")
    if stream_limit_hit:
        reasons.append(f"more than {INFLATE_STREAM_LIMIT} compressed streams in one file; the rest were not searched")
    if budget_hit or (budget <= 0 and cut):
        reasons.append(f"the {INFLATE_BYTES_LIMIT // 1048576} MB inflate budget was reached; what came after it was not searched in full")
    if partial_payload:
        reasons.append("a compressed payload was cut short and was searched only in part")
    return "\n".join(c for c in chunks if c), "; ".join(reasons) if reasons else None


def _png_text_chunks(
    data: bytes,
    budget: int,
    depth: int = 0,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
) -> tuple[list[str], list[str], int]:
    """tEXt (raw), zTXt and iTXt (zlib) chunks of a PNG, split by keyword.

    Returns (chunks, reasons, remaining budget). A compressed chunk that will not
    read is a reason, not a silent skip: the text is inside the zlib payload and
    nowhere else, so a raw scan of the chunk finds nothing.
    """
    at = data.find(PNG_SIGNATURE)
    if at < 0:
        return [], [], budget
    out: list[str] = []
    reasons: list[str] = []
    partial = False
    # From the signature wherever it sits: a PNG with bytes prepended, or one embedded in
    # another file, still has its zTXt and iTXt text inside a deflate payload that a raw
    # scan cannot read, and `startswith` alone made both invisible.
    offset = at + 8
    while offset + 12 <= len(data) and budget > 0:
        length = int.from_bytes(data[offset:offset + 4], "big")
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        offset += 12 + length
        # Every clear-text field of a chunk gets the same short-run read as its text: a keyword is
        # text, and so are an iTXt's language tag and translated keyword. The runs pass carries
        # anything of six characters or more and condition 5's shortest marker is three, so a
        # three-character keyword alone was read by nothing — and what did reach the runs pass was
        # glued to the chunk type, where the word boundary in the marker pattern cannot match.
        # The payload of a compressed chunk is deliberately not read this way: it is binary, and
        # its short printable runs are noise.
        fields = [body.split(b"\x00", 1)[0]]
        if kind == b"iTXt" and b"\x00" in body:
            fields += body.split(b"\x00", 1)[1].split(b"\x00")[:4]  # flag, method, language, translated
        short_fields = [s for field in fields if (s := _short_runs(field))]
        if short_fields:
            out.append("\n".join(short_fields))
        if kind == b"tEXt":
            # The text, not only the keyword. The runs pass carries an uncompressed chunk's
            # long text already, but its minimum run is six characters while condition 5's
            # shortest marker is three: a run that short, after a keyword NUL, was read by
            # nothing at all — in a file that reported itself fully read. The duplicate this
            # used to cause is handled where all findings meet, not by refusing to read the
            # chunk. (This comment named the marker itself until AC9; a shipped file that
            # spells out the term its own check exists to catch fails condition 5, which is
            # how it was found. AC9 records the reword in the classification document.)
            _, _, chunk_text = body.partition(b"\x00")
            # Only the runs the runs pass cannot carry. Its minimum is six characters and
            # condition 5's shortest marker is three, so a short run inside an uncompressed
            # chunk was read by nothing; the long runs are already in the text, and adding them
            # again would report the same bytes twice.
            short = _short_runs(chunk_text)
            if short:
                out.append(short)
        elif kind == b"zTXt":
            _, _, compressed = body.partition(b"\x00")
            raw, cut = _inflate_bounded(compressed[1:], min(budget, INFLATE_BYTES_LIMIT))  # byte 0 is the method
            if raw is None:
                reasons.append("a compressed zTXt chunk did not decompress and was not searched")
                continue
            budget -= len(raw)
            partial = partial or (cut and budget > 0)
            chunk, chunk_reason = _read_a_decoded_payload(raw, depth, spaces_out)
            out.append(chunk or _decode_text(raw))
            if chunk_reason:
                reasons.append(chunk_reason)
        elif kind == b"iTXt":
            # Layout after the keyword NUL: compression flag byte, compression
            # method byte, language tag + NUL, translated keyword + NUL, text.
            # The flag is the first of those two bytes, not the second.
            head, _, rest = body.partition(b"\x00")
            if len(rest) >= 2 and rest[0:1] == b"\x01":  # compressed flag
                key_end = rest.find(b"\x00", 2)
                target = rest[key_end + 1:] if key_end >= 0 else rest
                _, _, payload = target.partition(b"\x00")
                raw, cut = _inflate_bounded(payload, min(budget, INFLATE_BYTES_LIMIT))
                if raw is None:
                    reasons.append("a compressed iTXt chunk did not decompress and was not searched")
                    continue
                budget -= len(raw)
                partial = partial or (cut and budget > 0)
                chunk, chunk_reason = _read_a_decoded_payload(raw, depth, spaces_out)
                out.append(chunk or _decode_text(raw))
                if chunk_reason:
                    reasons.append(chunk_reason)
            else:
                # An uncompressed iTXt body is in the clear like a tEXt body, and gets the same
                # short-run read for the same reason: the runs pass carries everything of six
                # characters or more, condition 5's shortest marker is three, and a marker in
                # the text of a chunk that reported itself fully read was read by nothing. The
                # text is the last field: keyword NUL, compression flag, compression method,
                # language tag NUL, translated keyword NUL, then the text itself.
                after_flag = rest[2:] if len(rest) >= 2 else b""
                first_nul = after_flag.find(b"\x00")
                after_lang = after_flag[first_nul + 1:] if first_nul >= 0 else after_flag
                second_nul = after_lang.find(b"\x00")
                text_bytes = after_lang[second_nul + 1:] if second_nul >= 0 else after_lang
                short = _short_runs(text_bytes)
                if short:
                    out.append(short)
        if kind == b"IEND":
            # Not the end of the search: a file can hold several PNGs — a report with two
            # images, a PDF with an embedded screenshot — and stopping at the first one
            # leaves every later image's compressed text unread. Start again from the byte
            # after this signature.
            following = data.find(PNG_SIGNATURE, offset)
            if following < 0:
                break
            offset = following + 8
    # The budget running out inside a PNG is the budget's story, and the caller owns that
    # budget: it reports the exhaustion once, for the file, rather than twice.
    if partial:
        reasons.append("a PNG text payload was searched only in part")
    return out, reasons, budget


def _short_runs(raw: bytes) -> str:
    """The printable runs of a chunk's text that the runs pass cannot carry.

    That pass has a six-character minimum and condition 5's shortest marker is three, so a
    marker in the clear inside a chunk is visible only here. Both uncompressed chunk kinds read
    their text through this one function: the same rule written twice is how the second of them
    came to be missing it.
    """
    return "\n".join(
        run.decode("ascii", "replace")
        for run in re.findall(rb"[\x20-\x7e]+", raw)
        if len(run) < RUN_MINIMUM
    )


def _decode_text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def read_textish(
    path: Path,
    spans_out: list[tuple[int, int]] | None = None,
    spaces_out: list[tuple[bytes, list[int]]] | None = None,
) -> tuple[str, bool, str | None]:
    """Return (searchable text, is_binaryish, unscanned_reason).

    A file the check cannot read in full comes back with a reason, and the caller
    reports it as a failure: an unread file that quietly passes is the one
    outcome worse than a false positive.

    `spans_out`, when given, collects the byte ranges the container reader accounted for. They
    are what tells a later sweep where the boundaries between the regions a reader saw are —
    the points a term in the clear can straddle and be seen by nothing.

    `spaces_out`, when given, collects the places that are *not* the file's own bytes: a member
    that is itself a container and was stored compressed has no offsets in the file at all, so
    its internal boundaries cannot be edges in the file's sweep, and its members' names and
    payloads are read in different calls. Each entry is (those bytes, the edges of the ranges
    read inside them), and each is swept like the file's own bytes are.
    """
    try:
        size = path.stat().st_size
        if size == 0:
            return "", False, None
        if size > BINARY_READ_CAP:
            return "", True, f"{size / 1048576:.1f} MB exceeds the {BINARY_READ_CAP // 1048576} MB scan cap"
        data = path.read_bytes()
    except OSError as exc:
        # A file that cannot be read cannot be cleared — a broken symlink or a
        # permission problem must not become a silent pass for conditions 3, 4 and 5.
        return "", False, f"could not be read ({exc.__class__.__name__}: {exc.strerror or exc})"
    if _looks_like_zip(data):
        text, reason = _inflate_zip(data, spans_out=spans_out, spaces_out=spaces_out)
        if text or reason:
            return text, True, reason
    if looks_text(data):
        if len(data) > TEXT_READ_CAP:
            head = data[:TEXT_READ_CAP].decode("utf-8", "replace")
            tail = data[-TEXT_READ_CAP:].decode("utf-8", "replace")
            return head + "\n" + tail, False, (
                f"text file is {len(data) / 1048576:.1f} MB, past the {TEXT_READ_CAP // 1048576} MB read cap — "
                "only its head and tail were searched"
            )
        if spans_out is not None:
            # This file's own bytes are one region and the decode above read all of them, so it
            # declares that: every occurrence of a term *in those bytes* is inside a range a
            # reader read. That is not the same as having read the file. A PDF is mostly
            # printable text and carries its content streams deflated; a PNG's text chunks are
            # compressed the same way. Reading only the decoded bytes cleared a private path
            # that was recoverable by inflating the stream it sat in, and report it as read in
            # full. The compressed payloads are read here with the readers a member gets, and
            # because those bytes exist nowhere in the file their boundaries become a space of
            # their own rather than edges in the file's coordinates.
            spans_out.append((0, len(data)))
        inflated, inflate_reason = _inflate_zlib_payloads(data, depth=0, spaces_out=spaces_out)
        text = data.decode("utf-8", "replace")
        if inflated:
            text += "\n" + inflated
        # The same bytes read as UTF-16, and for the same reason the binary path reads them that
        # way. A text file's whole content is one span here, so the sweep has no interior edge to
        # cross and *no* reader below this line looks at those bytes again: a private path written
        # in UTF-16 past the point where `looks_text` stops looking — it reads the first eight
        # kilobytes for a null byte, and a UTF-16 tail is invisible to that — was cleared on a
        # release tree with the whole file reported as read in full. The ASCII reasoning that made
        # the whole-file span safe ("a term split across two runs has to straddle a byte that is
        # not part of it") is about terms in the clear; a UTF-16 encoding of ASCII text is itself
        # full of the null bytes it assumes away.
        text += "\n" + _utf16_views(data)
        return text, False, inflate_reason
    if spans_out is not None:
        # Binary bytes are not decoded whole, so no range is claimed for them here: the run
        # pass inside `_binary_readers` declares the runs it produced, and a term those runs
        # do not cover — a short one, or one split between two of them — is reported by the
        # sweep precisely because no declared range contains it.
        # `spaces_out` travels with `spans_out`: the binary readers inflate the compressed
        # payloads this file carries — a PDF content stream, a PNG text chunk — and those bytes
        # exist nowhere in the file, so the boundaries inside them have to be registered where
        # they are. Passing the span list alone left every compressed payload at the file level
        # unread: a private path parked in a PDF stream was cleared with no finding and no
        # reason, while the same bytes inside a member of a container were caught, because the
        # member path passes both lists.
        scanned, reason = _binary_readers(data, spans_out=spans_out, origin=0, spaces_out=spaces_out)
        return scanned, True, reason
    scanned, reason = _binary_readers(data, spaces_out=spaces_out)
    return scanned, True, reason


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _line_is_allowed(text: str, line: int) -> bool:
    lines = text.splitlines()
    return 0 < line <= len(lines) and ALLOW_MARKER in lines[line - 1]


def _finding(condition: str, rel: str, line: int, detail: str, text: str, exempt: str | None) -> Finding:
    """Classify a hit: a violation, an issue-owned exemption, or an allowed line."""
    if _line_is_allowed(text, line):
        return Finding(condition + "-ALLOW", f"{rel}:{line}", detail + " — cleared by an inline boundary:allow", "allowed")
    if exempt:
        return Finding(condition + "-EXEMPT", f"{rel}:{line}", detail + f" — {exempt}", "exempt")
    return Finding(condition, f"{rel}:{line}", detail)


# ── The six conditions ───────────────────────────────────────────────────────


def check_1_private_absent(files: list[str], c: Classification) -> list[Finding]:
    """1. A private-classified path is present in the release tree."""
    findings: list[Finding] = []
    for pattern in c.private:
        # The document's one exemption: README.md is private as a file (the dev
        # README), but the landing merge overwrites that release-tree path, so a
        # correct tree always has one. Built straight off the private column,
        # this condition would fail every release forever.
        if pattern == "README.md":
            continue
        target = translate(pattern, c)
        for hit in (f for f in files if matches(f, target)):
            detail = f"private path present — matches `{pattern}`"
            if target != pattern:
                detail += f" (release-tree path `{target}`)"
            findings.append(Finding("1", hit, detail))
    return findings


def check_2_harness_present(files: list[str], c: Classification) -> list[Finding]:
    """2. An expected harness path is missing from the release tree."""
    findings: list[Finding] = []
    for pattern in c.ships:
        target = translate(pattern, c)
        hits = [f for f in files if matches(f, target)]
        if not hits:
            findings.append(Finding("2", pattern, f"classified Ships but absent from the release tree (looked for `{target}`)"))
    return findings


def _raw_line(data: bytes, at: int) -> int:
    """The line number, in the file's own bytes, of an offset into them."""
    return data.count(b"\n", 0, at) + 1


def _sweep_hits(
    data: bytes,
    term: str,
    edges: list[int],
    fold: bool = False,
    bounded: bool = False,
) -> list[int]:
    """Offsets where a term lies in the file's own bytes *across* a region boundary.

    Every reader here is scoped to a region — a member's payload, a gap, a container's own
    bytes — so a term the file holds contiguously but a boundary splits is in the clear and
    invisible to all of them. This is where such a term is found.

    Restricted to matches that cross an edge, which is what makes the sweep safe: it cannot
    duplicate what a reader reported, because a match crossing an edge is in no region any
    reader read whole; and it cannot turn binary noise into a finding, because noise does not
    straddle a boundary — a filter narrow enough to catch a three-character marker inside a
    PNG's compressed bytes was measured doing exactly that on the real release tree.

    Every encoding a reader could have decoded is tried, since the text on either side of a
    boundary is as likely to be UTF-16 as UTF-8; `_utf16_views` exists on the reader side for
    the same reason.
    """
    hits: list[int] = []
    needles = {
        term.encode("utf-8", "replace"),
        term.encode("utf-16-le", "replace"),
        term.encode("utf-16-be", "replace"),
    }
    for needle in needles:
        if not needle:
            continue
        if fold:
            # The text scan for a marker is case-insensitive, so the sweep over the bytes has to
            # be as well, or a marker held in the clear in another case is found by neither: the
            # halves are separated in the concatenated text, so only this can reach it.
            for match in re.finditer(re.escape(needle), data, re.IGNORECASE):
                if not any(match.start() < edge < match.end() for edge in edges):
                    continue
                if bounded and not _at_a_word_boundary(data, match.start(), match.end()):
                    # The marker's own definition is word-bounded, because the bare initials
                    # match the middle of an innocent word: the text scan honours that, so the
                    # sweep has to as well, or `password` becomes a learning marker.
                    continue
                hits.append(match.start())
            continue
        at = data.find(needle)
        while at >= 0:
            end = at + len(needle)
            if any(at < edge < end for edge in edges) and (
                not bounded or _at_a_word_boundary(data, at, end)
            ):
                hits.append(at)
            at = data.find(needle, at + 1)
    return sorted(hits)


def _at_a_word_boundary(data: bytes, start: int, end: int) -> bool:
    """Whether a match in the file's bytes is a whole word there, the way the pattern asks.

    The text scan is anchored and the sweep is not, so a marker shape inside a longer word was
    reported as a marker — `password` carrying the initials this check looks for. What counts as
    a word character is deliberately the same rough class the pattern used: letters, digits and
    the underscore, in ASCII, with the file's own edge counting as a boundary.
    """
    word = __import__("re").compile(rb"[0-9A-Za-z_]")
    before = data[start - 1:start] if start > 0 else b""
    after = data[end:end + 1]
    return not (before and word.match(before)) and not (after and word.match(after))


def check_3_no_private_paths(
    files: list[str],
    terms: list[str],
    text_of: dict[str, str],
    unscanned: dict[str, str] | None = None,
    bytes_of: dict[str, bytes] | None = None,
    edges_of: dict[str, list[int]] | None = None,
    spaces_of: dict[str, list[tuple[bytes, list[int]]]] | None = None,
) -> list[Finding]:
    """3. A shipped file names a private path — literally, or assembled at runtime.

    The last sweep is over the file's own bytes, and it is what makes the readers' picture
    safe to trust: a term can be split across two regions a reader sees separately — two bytes
    at the end of one member's payload and one in the next gap — and no per-region reader can
    see a term that crosses its edge. A term's bytes present in the file at all is the ground
    truth; the readers exist to find terms whose bytes are not there to be found (deflated,
    encoded, wrapped), and this sweep runs only where they reported nothing for that term, so
    it can add a finding but never a duplicate.
    """
    findings: list[Finding] = []
    assembled: dict[str, re.Pattern[str]] = {}
    for term in terms:
        stem = term.rstrip("/")
        parts = stem.split("/") if "/" in stem else []
        if len(parts) < 2 or any(not p for p in parts):
            continue
        # Every separator between the segments has to look like a join, not like
        # prose: 'a' / 'b' / 'c' and os.path.join(a, b, c) both do, and a sentence
        # that merely mentions the words does not. Splitting on the first slash
        # alone would miss a three-segment path assembled in three parts.
        assembled[term] = re.compile(r"([^\w\n]{1,20})".join(re.escape(p) for p in parts))
    for rel in files:
        if unscanned and rel in unscanned:
            findings.append(
                Finding("3", rel, f"not fully scanned — {unscanned[rel]}; conditions 3, 4 and 5 cannot clear a file the check has not read in full")
            )
        text = text_of.get(rel)
        if not text:
            continue
        seen: set[tuple[str, int]] = set()
        for term in terms:
            exempt = COND3_EXEMPT.get((rel, term))
            for m in re.finditer(re.escape(term), text):
                line = line_of(text, m.start())
                if (term, line) in seen:
                    continue
                seen.add((term, line))
                findings.append(_finding("3", rel, line, f"names private path `{term}`", text, exempt))
        data = (bytes_of or {}).get(rel)
        # Every crossing occurrence, not the first: two occurrences split by two different
        # boundaries are two leaks, and a term already reported inside a region must not
        # suppress the ones no region-scoped reader can see — which is exactly what gating this
        # on "the term was seen somewhere" did, including when the seen occurrence was an
        # allowed line.
        if data is not None:
            for term in terms:
                exempt = COND3_EXEMPT.get((rel, term))
                for at in _sweep_hits(data, term, (edges_of or {}).get(rel, [])):
                    line = _raw_line(data, at)
                    detail = (
                        f"names private path `{term}` — its bytes are in the file itself, "
                        "split across two regions no reader saw it in"
                    )
                    if exempt:
                        findings.append(Finding("3-EXEMPT", f"{rel}:{line}", detail + f" — {exempt}", "exempt"))
                    else:
                        findings.append(Finding("3", f"{rel}:{line}", detail))
        for space, space_edges in (spaces_of or {}).get(rel, []):
            # A member that is itself a container and was stored compressed: its inner
            # boundaries are boundaries between two readers, and its bytes have no offsets in
            # the file, so they are swept where they are.
            for term in terms:
                exempt = COND3_EXEMPT.get((rel, term))
                for at in _sweep_hits(space, term, space_edges):
                    line = _raw_line(space, at)
                    detail = (
                        f"names private path `{term}` — its bytes are inside a member that is itself a "
                        "container, split across two regions no reader saw it in"
                    )
                    if exempt:
                        findings.append(Finding("3-EXEMPT", f"{rel}:{line}", detail + f" — {exempt}", "exempt"))
                    else:
                        findings.append(Finding("3", f"{rel}:{line}", detail))
        for term, rx in assembled.items():
            exempt = COND3_EXEMPT.get((rel, term))
            for m in rx.finditer(text):
                if not all(ASSEMBLY_PUNCT.search(sep) for sep in m.groups()):
                    continue  # a non-word run with no punctuation is prose
                if (term, line_of(text, m.start())) in seen:
                    # The literal scan already reported this occurrence on this line: the
                    # assembled-path pattern matches a written-out path too, and reporting it
                    # again claimed the path was assembled at run time when it is not.
                    continue
                findings.append(
                    _finding(
                        "3",
                        rel,
                        line_of(text, m.start()),
                        f"assembles private path `{term}` at runtime (separators {list(m.groups())})",
                        text,
                        exempt,
                    )
                )
    return findings


def _without_duplicates(findings: list[Finding]) -> list[Finding]:
    """One finding per file, condition and detail.

    Two readers can now see the same term: the literal scan over a run-joined view and the sweep
    over the bytes a member holds both report a private path that a stray byte had split in two,
    and a report that counts the same hit twice overstates what the file contains.
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.condition, finding.location, finding.detail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def check_4_no_instructions(files: list[str], text_of: dict[str, str]) -> list[Finding]:
    """4. A shipped file carries an agent instruction that cannot resolve."""
    findings: list[Finding] = []
    for rel in files:
        text = text_of.get(rel, "")
        for token in AGENT_INSTRUCTIONS:
            for m in re.finditer(re.escape(token), text):
                findings.append(_finding("4", rel, line_of(text, m.start()), f"agent instruction `{token}` cannot resolve in a release tree", text, None))
    return findings


def _pattern_literals(pattern: str) -> list[str]:
    """The literal strings a marker pattern matches, for searching raw bytes.

    The patterns are anchored word matches around a literal — `\bSSW\b` — and the sweep needs
    the literal itself, in the encodings a reader could have decoded. Anything not of that shape
    is skipped rather than guessed at, and it stays covered by the readers.
    """
    body = pattern
    for affix in ("\\b", "^", "$"):
        body = body.replace(affix, "")
    if not body or re.search(r"[^A-Za-z0-9 _/.-]", body):
        return []
    return [body] if body == body.strip() else []


def check_5_no_markers(
    files: list[str],
    text_of: dict[str, str],
    bytes_of: dict[str, bytes] | None = None,
    edges_of: dict[str, list[int]] | None = None,
    spaces_of: dict[str, list[tuple[bytes, list[int]]]] | None = None,
) -> list[Finding]:
    """5. A learning marker appears in shipped text.

    As in condition 3, the file's own bytes are swept after the text, and only for matches that
    cross a region boundary: a three-character marker split across a reader's edge is invisible
    to every per-region reader, and the bytes are where it can still be seen.
    """
    findings: list[Finding] = []
    for rel in files:
        text = text_of.get(rel, "")
        for pattern, flags in MARKERS:
            for m in re.finditer(pattern, text, flags):
                findings.append(_finding("5", rel, line_of(text, m.start()), f"learning marker {m.group(0)!r} in shipped text", text, None))
        data = (bytes_of or {}).get(rel)
        if data is None:
            continue
        # A marker is a literal string, so the crossing sweep is run on its text rather than on
        # its pattern: `_sweep_hits` tries the encodings a reader could have decoded, and a
        # regex compiled for one of them would report a match the bytes do not hold.
        for pattern, flags in MARKERS:
            for literal in _pattern_literals(pattern):
                for at in _sweep_hits(
                    data,
                    literal,
                    (edges_of or {}).get(rel, []),
                    fold=bool(flags & re.IGNORECASE),
                    bounded=pattern.startswith(r"\b") and pattern.endswith(r"\b"),
                ):
                    findings.append(
                        Finding(
                            "5",
                            f"{rel}:{_raw_line(data, at)}",
                            f"learning marker {literal!r} in the file's own bytes, "
                            "split across two regions no reader saw it in",
                        )
                    )
        for space, space_edges in (spaces_of or {}).get(rel, []):
            for pattern, flags in MARKERS:
                for literal in _pattern_literals(pattern):
                    for at in _sweep_hits(
                        space,
                        literal,
                        space_edges,
                        fold=bool(flags & re.IGNORECASE),
                        bounded=pattern.startswith(r"\b") and pattern.endswith(r"\b"),
                    ):
                        findings.append(
                            Finding(
                                "5",
                                f"{rel}:{_raw_line(space, at)}",
                                f"learning marker {literal!r} inside a member that is itself a "
                                "container, split across two regions no reader saw it in",
                            )
                        )
    return findings


def check_tag(tag: str, terms: list[str]) -> list[Finding]:
    """The release tag is shipped text, and nothing else in the run reads it.

    It becomes the tag name, the commit message on the public repository and the GitHub
    Release title — three places a private path or a learning marker can be written by
    naming a release. The tree can be spotless while the release says anything at all, so
    the tag is scanned with the same term list and the same markers.

    Runtime assembly is not possible in a tag (it is one literal string), so only the
    literal term scan applies here.
    """
    findings: list[Finding] = []
    for term in terms:
        # A directory term ends in a slash and a tag name cannot, so the stem is the form a
        # tag would carry: a tag naming the benchmarks directory without its trailing slash
        # names the same directory the document's term does.  # boundary:allow — the term
        # list's own example, in the code that exists to match it
        if term in tag or term.rstrip("/") in tag:
            findings.append(Finding("3", f"release tag {tag!r}", f"names private path `{term}`"))
    for token in AGENT_INSTRUCTIONS:
        if token in tag:
            findings.append(Finding("4", f"release tag {tag!r}", f"agent instruction `{token}` cannot resolve in a release tree"))
    for pattern, flags in MARKERS:
        for m in re.finditer(pattern, tag, flags):
            findings.append(Finding("5", f"release tag {tag!r}", f"learning marker {m.group(0)!r} in shipped text"))
    return findings


def check_6_manifest(tree: Path, files: list[str], manifest_path: Path, assets_dir: str) -> tuple[list[Finding], str | None]:
    """6. An asset in the release tree is not in the approved asset manifest."""
    if not manifest_path.is_file():
        note = (
            f"no approved-asset manifest at {manifest_path} — AC9 has not produced it. A directory "
            "that legitimately holds files cannot be guarded by name, so this condition fails closed "
            "rather than passing silently."
        )
        return [Finding("6", str(manifest_path), note)], note
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [Finding("6", str(manifest_path), f"manifest unreadable: {exc}")], None
    approved = manifest.get("assets", []) if isinstance(manifest, dict) else manifest
    by_name: dict[str, str | None] = {}
    for entry in approved:
        if isinstance(entry, dict) and "path" in entry:
            by_name[entry["path"]] = entry.get("sha256")
        elif isinstance(entry, str):
            by_name[entry] = None
    findings: list[Finding] = []
    prefix = assets_dir.rstrip("/") + "/"
    present = [f for f in files if f.startswith(prefix)]
    for rel in present:
        if rel not in by_name:
            findings.append(Finding("6", rel, "present in the release tree but not in the approved-asset manifest"))
            continue
        want = by_name[rel]
        if want:
            got = hashlib.sha256((tree / rel).read_bytes()).hexdigest()
            if got != want:
                findings.append(Finding("6", rel, f"sha256 {got[:12]}… does not match the approved {want[:12]}…"))
    for rel in by_name:
        if rel not in present:
            findings.append(Finding("6", rel, "listed in the manifest but absent from the release tree"))
    return findings, None


# ── Driver ───────────────────────────────────────────────────────────────────


def run(tree: Path, doc_path: Path, manifest: Path, assets_dir: str, quiet: bool = False, tag: str | None = None) -> tuple[int, list[Finding], list[Finding], str]:
    """Run all six conditions. Returns (exit code, violations, cleared, summary)."""
    doc = doc_path.read_text()
    try:
        c = parse_classification(doc)
    except DerivationError as exc:
        return 2, [], [], f"the document's classification tables could not be derived from safely: {exc}"
    terms = parse_reference_terms(doc)
    if not c.private or not c.ships or not terms:
        return 2, [], [], "the document yielded no classification or no term list — refusing to pass on an empty set"
    files = iter_files(tree)
    text_of: dict[str, str] = {}
    bytes_of: dict[str, bytes] = {}
    edges_of: dict[str, list[int]] = {}
    spaces_of: dict[str, list[tuple[bytes, list[int]]]] = {}
    binaryish: list[str] = []
    unscanned: dict[str, str] = {}
    for rel in files:
        spans: list[tuple[int, int]] = []
        spaces: list[tuple[bytes, list[int]]] = []
        text, is_bin, reason = read_textish(tree / rel, spans, spaces)
        text_of[rel] = text
        # The points a term can straddle: every edge of every byte range a container reader
        # accounted for. A file with none is read whole by one reader, so the sweep has nothing
        # to add there.
        edges_of[rel] = sorted({edge for start, end in spans for edge in (start, end)})
        # The same for the bytes that are not the file's: a compressed member that is itself a
        # container has boundaries of its own and no offsets in the file.
        spaces_of[rel] = spaces
        # Capped like every other read here: the sweep below is over what a reader could have
        # been given, and a file past the scan cap is already reported as unscanned rather than
        # half-read, so no bytes are collected for it.
        path = tree / rel
        try:
            if path.stat().st_size <= BINARY_READ_CAP:
                bytes_of[rel] = path.read_bytes()
        except OSError:
            # Unopenable: `read_textish` above already reported it rather than clearing it.
            pass
        if is_bin:
            binaryish.append(rel)
        if reason:
            unscanned[rel] = reason

    results: list[tuple[str, str, list[Finding]]] = [
        ("1", "no private path present in the tree", check_1_private_absent(files, c)),
        ("2", "every Ships path present", check_2_harness_present(files, c)),
        ("3", "no shipped file names a private path", check_3_no_private_paths(files, terms, text_of, unscanned, bytes_of, edges_of, spaces_of)),
        ("4", "no unresolvable agent instruction", check_4_no_instructions(files, text_of)),
        ("5", "no learning marker in shipped text", check_5_no_markers(files, text_of, bytes_of, edges_of, spaces_of)),
    ]
    tag_findings = check_tag(tag, terms) if tag else []
    for cond, _, fs in results:
        fs.extend(f for f in tag_findings if f.condition == cond)
    c6, manifest_note = check_6_manifest(tree, files, manifest, assets_dir)
    results.append(("6", "every asset in the approved manifest", c6))
    if manifest_note and os.environ.get("PORTSHIM_BOUNDARY_ALLOW_MISSING_MANIFEST") == "1":
        print("  WARNING: condition 6 unresolved — " + manifest_note)
        print("  WARNING: PORTSHIM_BOUNDARY_ALLOW_MISSING_MANIFEST=1 in force; a release must not ship unnoticed behind it.")
        results[-1] = ("6", "every asset in the approved manifest (override in force)", [])

    violations = [f for _, _, fs in results for f in fs if f.is_violation]
    clears = [f for _, _, fs in results for f in fs if not f.is_violation]

    print(f"boundary-check: {tree}")
    print(f"  derived {c.derived_from()} and {len(terms)} reference-forbidden terms, in {doc_path}")
    print(f"  release tree: {len(files)} files, {len(binaryish)} scan-through (zip members or printable runs)")
    if tag:
        print(f"  release tag: {tag!r} scanned with {len(terms)} reference-forbidden terms and {len(MARKERS)} markers")
    for cond, label, fs in results:
        bad = [f for f in fs if f.is_violation]
        print(f"  condition {cond}: {'PASS' if not bad else f'FAIL ({len(bad)})'} — {label}")
        if not quiet:
            for f in bad:
                print(f"      {f.location}: {f.detail}")
            for f in fs:
                if f.kind == "exempt":
                    print(f"      EXEMPT {f.location}: {f.detail}")
            grouped: dict[str, list[Finding]] = {}
            for f in fs:
                if f.kind == "allowed":
                    grouped.setdefault(f.location.rsplit(":", 1)[0], []).append(f)
            for rel, items in grouped.items():
                conds = sorted({i.condition.split("-")[0] for i in items})
                plural = "s" if len(conds) > 1 else ""
                print(f"      ALLOWED {rel}: {len(items)} line(s) cleared by an inline boundary:allow (condition{plural} {', '.join(conds)})")
    if clears and not quiet:
        print(f"  {len(clears)} cleared line(s): each is owned by an open issue or carries an inline allow, and none is silent")
    return (1 if violations else 0), violations, clears, f"{c.derived_from()}, {len(terms)} terms"


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="Boundary gate for a PortShim release tree (issue #47 AC6).")
    ap.add_argument("tree", help="release tree to check")
    ap.add_argument("--doc", type=Path, default=None, help="classification document")
    ap.add_argument("--manifest", type=Path, default=None, help="approved-asset manifest")
    ap.add_argument("--assets-dir", default="images/reports", help="directory the manifest governs")
    ap.add_argument("--json", type=Path, default=None, help="write the findings as JSON")
    ap.add_argument("--quiet", action="store_true", help="summary lines only")
    ap.add_argument(
        "--tag",
        default=None,
        help="release tag about to be published; it becomes public text, so it is scanned too",
    )
    args = ap.parse_args(argv)

    doc_path = args.doc or (repo_root / DOC_RELPATH)
    manifest = args.manifest or (repo_root / MANIFEST_RELPATH)
    if not str(args.tree).strip():
        # An unset variable in a calling script arrives here as an empty string, and
        # Path("") is the current directory — which for the release script is the private
        # repository this gate exists to keep out of a release. Refuse it rather than
        # checking a tree nobody named.
        print("boundary-check: the tree argument is empty; refusing to check another directory", file=sys.stderr)
        return 2
    tree = Path(args.tree)
    if not tree.is_dir():
        print(f"boundary-check: no release tree at {tree}", file=sys.stderr)
        return 2
    if not doc_path.is_file():
        print(f"boundary-check: no classification document at {doc_path}", file=sys.stderr)
        return 2

    code, violations, clears, summary = run(tree, doc_path, manifest, args.assets_dir, args.quiet, args.tag)
    if code == 2:
        print(f"boundary-check: {summary}", file=sys.stderr)
        return 2
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "tree": str(tree),
                    "doc": str(doc_path),
                    "derived": summary,
                    "violations": [f.as_dict() for f in violations],
                    "cleared": [f.as_dict() for f in clears],
                },
                indent=2,
            )
            + "\n"
        )
    if violations:
        print(f"BOUNDARY CHECK: FAIL — {len(violations)} violation(s); do not push this tree")
        return 1
    print("BOUNDARY CHECK: PASS — all six conditions clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
