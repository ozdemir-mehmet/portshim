#!/usr/bin/env python3
"""
make-sample-report-images.py — regenerate the landing page's sample report images.

The samples on the reports page are rendered from `sample-findings.json` through the report
generator, converted to page images, and labelled as synthetic. The run also writes
`approved-assets.json`, the manifest the release boundary check reads before a release is
published: every file in the assets directory has to be listed there with its hash, so a substituted
image is a visible diff against a regenerated one rather than a silent one. It is a drift guard, not
a defence against an editor who replaces an image and rewrites the manifest in the same change.

The sample data is invented. Hosts are names under a reserved suffix (RFC 2606), the reports print a
documentation range for the scan line (TEST-NET-1, RFC 5737) and no host address falls in it — there
are no host addresses; the CVE identifiers are real and carry their NVD CVSS v3.1 base scores, which
a test compares against the API and skips when the API does not answer; and the mapping from a CVE to
a host exists only in that file. Nothing in this directory comes from a live engagement.

Usage, from the directory holding this directory's parent (its root):

    ../.venv/bin/python tools/make-sample-report-images.py
    ../.venv/bin/python tools/make-sample-report-images.py --work-dir /tmp/sample-render

Requirements: the report generator in `scripts/`, LibreOffice (`soffice`), poppler's `pdftoppm`,
Pillow, python-docx, python-pptx and WeasyPrint — the same dependencies the release suite needs,
and the reason `weasyprint` is declared in pyproject.toml's `report` extra.

The date printed on the deliverables is pinned to SAMPLE_DATE, because the published images are
pinned by hash: a render that stamps the day it ran cannot be reproduced tomorrow. A caller who sets
PORTSHIM_REPORT_DATE overrides it, and the manifest then records the date the images actually carry.
"""

from __future__ import annotations

import argparse
import re
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from PIL import Image, ImageDraw  # noqa: F401 — imported here so importing this module is enough

# ── Where things live, all relative to this file ──────────────────────────────
# The landing page's own directory is `parents[0]`'s parent; nothing in this file spells out its
# name, because a shipped file may not name the source directory it is copied out of.
_TOOLS_DIR = Path(__file__).resolve().parent
_LANDING_DIR = _TOOLS_DIR.parent
_REPO_ROOT = _LANDING_DIR.parent

# The date the samples are dated. Fixed, because the manifest pins their bytes: a report that
# stamps the day it was rendered cannot be regenerated tomorrow, and `--check` could never pass.
# Set in main(), not at import: importing this module must not change the environment a caller
# is using, and a test that imported it for its constants used to do exactly that.
SAMPLE_DATE = "2026-01-15"

FINDINGS_JSON = _TOOLS_DIR / "sample-findings.json"
IMAGES_DIR = _LANDING_DIR / "images" / "reports"
MANIFEST = _LANDING_DIR / "approved-assets.json"

# Drawn under each page image so a screenshot lifted out of this page still says what it is.
LABEL = "Synthetic sample data — example findings and a documentation range, not a live network"
LABEL_HEIGHT = 30
# The label is drawn in a real font, and the published hashes depend on which one: a silent
# fallback to Pillow's bitmap default redraws every image and leaves the manifest describing
# different bytes. Arch keeps DejaVu here, Debian and Ubuntu there; anything else is an error.
LABEL_FONT_CANDIDATES = (
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
)
# The label's own ink. Named here so the test can require it by value: it must not be a colour
# report-gen draws with (DARK_GRAY 333333, MED_GRAY 797979 — 121,121,121, a near neighbour of
# this one — or BRAND_RED CC4141), or a band of the page's own grey text would satisfy the check.
LABEL_INK = (120, 120, 120)
# The strip's canvas, which the test reads back off the published band.
LABEL_FILL = (245, 245, 245)

# Release-tree paths, which is what the gate matches: the landing directory is merged into the
# release tree without its own prefix, so the images live under `images/reports/` there.
RELEASE_ASSETS_PREFIX = "images/reports"

OUTPUT_WIDTH = 800

# One entry per image to produce: the rendered format it comes from, and which page of it. The
# counts are the findings-table pages for the fixture in this directory — the landing copy beside
# each image calls it "findings table", so it has to be the table and not the page of key risks
# or the severity classification that precede it. The page number is stated rather than guessed
# from ink or word counts, both of which picked the wrong page on this very fixture, and the run
# fails loudly if that page stops looking like a table of findings, which is what a changed
# fixture does to it.
PLAN = [
    ("sample-docx-cover.png", "docx", "cover"),
    ("sample-docx-content.png", "docx", 3),
    ("sample-pdf-cover.png", "pdf", "cover"),
    ("sample-pdf-content.png", "pdf", 3),
    ("sample-pptx-slide1.png", "pptx", 1),
    ("sample-pptx-slide2.png", "pptx", 2),
]

# A findings table names severities and finding identifiers in the same block of text; the pages
# that precede it carry one or the other. Below these floors, the page is not the table.
TABLE_SEVERITY_FLOOR = 3
TABLE_ID_FLOOR = 1
SEVERITY_TOKEN = re.compile(r"\b(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", re.IGNORECASE)


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise SystemExit(f"error: {tool} is not installed (or not on PATH)")
    return path


def _load_report_gen():
    """Import the report generator, whose file name is not a Python identifier.

    Two layouts have to work. In this repository the landing directory is a subdirectory, so the
    generator is at `_REPO_ROOT/scripts`. In a release tree the landing directory's CONTENTS are
    merged to the root, so `_LANDING_DIR` IS the root and the generator is at
    `_LANDING_DIR/scripts`. Resolving only the first is how this file shipped un-runnable: from a
    public clone it looked for the generator one directory above the clone, and rendered from
    whatever it found there.
    """
    for base in (_LANDING_DIR, _REPO_ROOT):
        path = base / "scripts" / "report-gen.py"
        if path.is_file():
            break
    else:
        raise SystemExit(
            "error: report generator not found. Looked in "
            + " and ".join(str(b / "scripts" / "report-gen.py") for b in (_LANDING_DIR, _REPO_ROOT))
            + " — run this from the repository, or from the root of a release tree."
        )
    spec = importlib.util.spec_from_file_location("report_gen", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"error: could not load {path} as a module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _render(findings: list[dict], work: Path, fmt: str, gen) -> Path:
    """Render one format and return the PDF its pages are read from."""
    out = work / f"sample-{fmt}.{fmt}"
    if fmt == "docx":
        result = gen.generate_docx(findings, str(out))
        source = out
    elif fmt == "pdf":
        result = gen.generate_pdf(findings, str(out), engagement_profile="Synthetic sample")
        source = out
    else:
        result = gen.generate_pptx(findings, str(out), engagement_profile="Synthetic sample")
        source = out
    if not isinstance(result, str) or result.startswith("ERROR") or not source.is_file():
        raise SystemExit(f"error: report generator refused the {fmt} sample: {result}")
    if fmt == "pdf":
        return source
    # Office formats: LibreOffice turns the document into a PDF, which is what gets rasterised.
    subprocess.run(
        [_require("soffice"), "--headless", "--convert-to", "pdf", "--outdir", str(work), str(source)],
        check=True, capture_output=True, timeout=300,
    )
    pdf = work / f"sample-{fmt}.pdf"
    if not pdf.is_file():
        raise SystemExit(f"error: LibreOffice produced no PDF for the {fmt} sample")
    return pdf


def _pages(pdf: Path, work: Path, tag: str) -> list[Path]:
    """Rasterise every page of a PDF to PNG at the landing page's width."""
    prefix = work / f"page-{tag}"
    subprocess.run(
        [_require("pdftoppm"), "-png", "-r", "150", "-scale-to-x", str(OUTPUT_WIDTH),
         "-scale-to-y", "-1", str(pdf), str(prefix)],
        check=True, capture_output=True, timeout=600,
    )
    page_files = sorted(prefix.parent.glob(prefix.name + "-*.png"))
    if not page_files:
        raise SystemExit(f"error: no pages rasterised from {pdf}")
    return page_files


def _ink(path: Path) -> float:
    """Fraction of the page that is not near-white — used to find the page with the table."""
    from PIL import Image

    with Image.open(path) as im:
        small = im.convert("L").resize((80, 50))
        data = small.tobytes()
    return sum(1 for value in data if value < 200) / len(data)


def _finding_ids(page_png: Path, pdf: Path, number: int) -> int:
    """How many finding identifiers a page carries.

    The page with the most of them is the findings table: every other page holds one finding, the
    table holds all of them. Reading the text is what makes the choice about the content rather
    than about how much ink a page happens to have, which picked a page of bullet points.
    """
    text = subprocess.run(
        [_require("pdftotext"), "-f", str(number), "-l", str(number), str(pdf), "-"],
        capture_output=True, text=True, timeout=120, check=False,
    ).stdout
    return len(re.findall(r"FIND-\d+", text))


def _assert_table_page(pdf: Path, number: int, name: str) -> None:
    """Refuse to publish a page that does not look like a findings table.

    The landing copy beside these two images says "findings table". If the fixture grows a page or
    the report layout moves, the stated page number silently starts pointing at something else —
    a page of key risks or the severity key — and the published image is then misdescribed. This
    turns that into a failed run with the numbers that caused it.
    """
    text = subprocess.run(
        [_require("pdftotext"), "-f", str(number), "-l", str(number), str(pdf), "-"],
        capture_output=True, text=True, timeout=120, check=False,
    ).stdout
    severities = len(SEVERITY_TOKEN.findall(text))
    ids = len(re.findall(r"FIND-\d+", text))
    if severities < TABLE_SEVERITY_FLOOR or ids < TABLE_ID_FLOOR:
        raise SystemExit(
            f"error: {name} is stated as page {number} of the {pdf.name} render, but that page "
            f"holds {severities} severity token(s) and {ids} finding identifier(s) — not a findings "
            "table. Update PLAN, or the fixture it was measured against."
        )


def _pick(pages: list[Path], which, pdf: Path) -> Path:
    if isinstance(which, int):
        if len(pages) < which:
            raise SystemExit(f"error: asked for page {which} of a {len(pages)}-page render")
        return pages[which - 1]
    if which == "cover":
        return pages[0]
    if which == "content":
        if len(pages) < 2:
            raise SystemExit("error: a one-page render has no content page to take")
        counts = [(_finding_ids(pages[i], pdf, i + 1), _ink(pages[i])) for i in range(1, len(pages))]
        best = max(range(len(counts)), key=lambda i: counts[i])
        if counts[best][0] == 0:
            # No page names a finding: fall back to the densest page rather than to a blank one.
            best = max(range(len(counts)), key=lambda i: counts[i][1])
        return pages[best + 1]
    raise SystemExit(f"error: unknown page selector {which!r}")


def _label_font(size: int = 12):
    """The label's font, or a hard failure. Never Pillow's bitmap default: see the constants."""
    from PIL import ImageFont

    for candidate in LABEL_FONT_CANDIDATES:
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, size)
    raise SystemExit(
        "error: no DejaVu Sans font found at " + ", ".join(LABEL_FONT_CANDIDATES)
        + " — the label is drawn in it, and falling back to another font would change every "
        "published image and every hash in approved-assets.json."
    )


def _label(page: Path, dest: Path) -> None:
    """Copy a page image to its destination, with the synthetic-sample label drawn underneath."""
    from PIL import Image, ImageDraw

    with Image.open(page) as im:
        body = im.convert("RGB")
    canvas = Image.new("RGB", (body.width, body.height + LABEL_HEIGHT), LABEL_FILL)
    canvas.paste(body, (0, 0))
    draw = ImageDraw.Draw(canvas)
    draw.text((8, body.height + 8), LABEL, fill=LABEL_INK, font=_label_font())
    canvas.save(dest, format="PNG", optimize=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_note(date: str) -> str:
    """The manifest's note. Single-sourced, so --check can compare it against the file on disk."""
    return (f"Synthetic sample data, dated {date}, regenerated by tools/make-sample-report-images.py. "
            "The release boundary check fails if any file in the assets directory is not listed here "
            "or does not match its hash. The label drawn under every image reads: " + LABEL + ".")


def _check_asset(name: str, want: str, have: str | None, listed: str | None) -> list[str]:
    """What is wrong with one image, as a list of sentences. Empty means it matches a fresh render.

    Three separate facts, because they fail for different reasons: the file on disk, the manifest
    entry for it, and the two against each other. A check that only printed them and returned 0
    would pass in CI on six mismatched images, which is what this used to do.
    """
    problems = []
    if have is None:
        problems.append(f"{name}: no image on disk")
    elif have != want:
        problems.append(f"{name}: on disk {have[:12]}…, a fresh render is {want[:12]}…")
    if listed is None:
        problems.append(f"{name}: not listed in approved-assets.json")
    elif listed != want:
        problems.append(f"{name}: approved {listed[:12]}…, a fresh render is {want[:12]}…")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="regenerate the landing sample report images")
    parser.add_argument("--work-dir", default=None,
                        help="directory for the intermediate renders (default: a temporary one)")
    parser.add_argument("--check", action="store_true",
                        help="render and report the hashes without writing the images or the manifest")
    args = parser.parse_args()

    # The date the deliverables are dated, pinned for the whole render. `setdefault`, so a caller
    # who set PORTSHIM_REPORT_DATE explicitly still wins.
    os.environ.setdefault("PORTSHIM_REPORT_DATE", SAMPLE_DATE)
    # The date actually used, which a caller may have overridden. The manifest note records THIS,
    # not the constant: a note that states SAMPLE_DATE while the images were stamped with something
    # else is a manifest that contradicts the bytes it pins, and the test that reads the note
    # would still pass because the note is a string this file writes about itself.
    render_date = os.environ["PORTSHIM_REPORT_DATE"]

    findings = json.loads(FINDINGS_JSON.read_text())
    if not isinstance(findings, list) or not findings:
        raise SystemExit(f"error: {FINDINGS_JSON} does not hold a list of findings")
    gen = _load_report_gen()

    # A per-run directory under --work-dir, never the directory itself: pdftoppm pads page numbers
    # to the width of the page count, so a 12-page run leaves `page-pdf-01…12.png` and a later
    # 9-page run writes `page-pdf-1…9.png`. Sharing a directory, the glob returns both runs' pages
    # and the page selected can come from the render before this one.
    base = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="sample-render-"))
    work = base / f"run-{time.time_ns()}"
    work.mkdir(parents=True, exist_ok=True)
    if not args.check:
        IMAGES_DIR.mkdir(parents=True, exist_ok=True)

    rendered: dict[str, list[Path]] = {}
    for fmt in ("docx", "pdf", "pptx"):
        pdf = _render(findings, work, fmt, gen)
        rendered[fmt] = _pages(pdf, work, fmt)
        print(f"  {fmt}: {len(rendered[fmt])} page(s) from {pdf.name}")

    listed = {}
    if MANIFEST.is_file():
        try:
            listed = {a["path"]: a["sha256"] for a in json.loads(MANIFEST.read_text())["assets"]}
        except (KeyError, TypeError, ValueError) as exc:
            raise SystemExit(f"error: {MANIFEST.name} is not a manifest this file can read: {exc}")

    assets = []
    drift: list[str] = []
    for name, fmt, which in PLAN:
        page = _pick(rendered[fmt], which, work / f"sample-{fmt}.pdf")
        if isinstance(which, int) and "-content" in name:
            _assert_table_page(work / f"sample-{fmt}.pdf", which, name)
        dest = IMAGES_DIR / name
        if args.check:
            with tempfile.NamedTemporaryFile(suffix=".png") as tmp:
                _label(page, Path(tmp.name))
                want = _sha256(Path(tmp.name))
            have = _sha256(dest) if dest.is_file() else None
            problems = _check_asset(name, want, have, listed.get(f"{RELEASE_ASSETS_PREFIX}/{name}"))
            drift += problems
            print(f"  [check] {name}: {want[:12]}… {'OK' if not problems else 'DRIFT'}")
            for problem in problems:
                print(f"          {problem}")
            continue
        _label(page, dest)
        digest = _sha256(dest)
        assets.append({"path": f"{RELEASE_ASSETS_PREFIX}/{name}", "sha256": digest})
        with Image.open(dest) as im:
            print(f"  {name}: {im.size[0]}x{im.size[1]} {digest[:12]}…")

    if args.check:
        # The loop above compares the six images in PLAN against a fresh render. Two things it cannot
        # see on its own: a file in the assets directory that PLAN does not name, and a listed file
        # whose bytes no longer match the manifest. So the directory is compared with the manifest in
        # both directions, and every listed file that exists is hashed against its entry. What remains
        # outside this check is a file added to the directory AND to the manifest in the same edit:
        # nothing here can re-derive a render for an image PLAN does not name, so such a file is the
        # manifest's own claim — which is what the classification document says the manifest is, a
        # drift guard rather than a defence against an editor who rewrites both.
        on_disk = {f"{RELEASE_ASSETS_PREFIX}/{p.relative_to(IMAGES_DIR)}"
                   for p in IMAGES_DIR.rglob("*") if p.is_file()} if IMAGES_DIR.is_dir() else set()
        for extra in sorted(on_disk - set(listed)):
            drift.append(f"{extra}: in the assets directory but not listed in approved-assets.json")
        for missing in sorted(set(listed) - on_disk):
            drift.append(f"{missing}: listed in approved-assets.json but not in the assets directory")
        for path in sorted(on_disk & set(listed)):
            actual = _sha256(IMAGES_DIR / Path(path).relative_to(RELEASE_ASSETS_PREFIX))
            if actual != listed[path]:
                drift.append(f"{path}: on disk {actual[:12]}…, approved {listed[path][:12]}…")
        if not MANIFEST.is_file():
            drift.append("approved-assets.json is absent")
        elif json.loads(MANIFEST.read_text()).get("note") != _manifest_note(render_date):
            drift.append("approved-assets.json states a note this run would not write")
        print("check only — nothing written")
        if drift:
            print(f"check FAILED — {len(drift)} difference(s) from a fresh render:")
            for problem in drift:
                print(f"  {problem}")
            return 1
        print("check PASSED — every image and the manifest match a fresh render")
        return 0

    MANIFEST.write_text(json.dumps({
        "note": _manifest_note(render_date),
        "assets": assets,
    }, indent=2) + "\n")
    print(f"  manifest: {MANIFEST.name} lists {len(assets)} asset(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
