"""The synthetic report samples: the fixture's reserved names, the manifest, and the label strip.

AC9 replaced six engagement screenshots with images rendered from invented findings. What can go
wrong quietly is pinned here, because the boundary gate cannot see it: a host in the fixture that
stops being a documentation address, an image edited or swapped without the manifest being
regenerated (the gate catches that one only against a release tree that has to be built first), a
sample that loses the strip saying what it is, an invented hostname leaking into prose that ships,
a pin that stops being honoured, and a number in the published copy that no longer matches the
fixture.

What these tests cannot do, stated so nobody reads them as more: they cannot prove a published
image is not a real page. `report-gen.py` shades table rows in the same grey the strip's canvas
uses, so the artefact assertions are (a) the width, (b) the strip's own ink colour appearing in
the last band, and (c) the drawn label being the documented string — enforced where the label is
drawn, on a page of the test's own, not by reading the published pixels. A substituted image that
is a genuine report-gen page and carries a label drawn by the generator's own code satisfies all of
them, which is why the manifest is described in the classification document
as a drift guard and the substantive guards are named there as the fixture, the label and review.

The pixel-level proof that a page render matches what the generator produces is the sample
generator's `--check` mode (`tools/make-sample-report-images.py`), which re-renders and compares
hashes; that takes about a minute, so it runs when the samples are regenerated, not here.
"""
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
from pathlib import Path

import pytest

Image = pytest.importorskip("PIL.Image", reason="the report extra (Pillow) is not installed")


def _root() -> Path:
    """The landing directory, in a working tree or in a release tree.

    The release merge copies the landing directory's contents to the tree root, so the fixture
    sits under a directory of its own in a working tree, and at the tree root in a release tree —
    the translation the classification document records for that directory. This module ships, so
    it has to pass in both trees, and a shipped file that spells that directory out fails
    condition 3. So it is found by what it holds rather than by its name, which is how the
    generator beside it resolves the same directory (positionally, from its own file). The docstring
    says this because the code has to do it: an earlier version named the directory and cleared the
    condition only because the term list carries a trailing slash the string did not.
    """
    anchor = Path(__file__).resolve().parent.parent
    if (anchor / "tools" / "sample-findings.json").is_file():
        return anchor
    for child in sorted(anchor.iterdir()):
        if (child / "tools" / "sample-findings.json").is_file():
            return child
    raise AssertionError(f"no directory holding tools/sample-findings.json under {anchor}")


REPO = Path(__file__).resolve().parent.parent
LANDING = _root()
FIXTURE = LANDING / "tools" / "sample-findings.json"
MANIFEST = LANDING / "approved-assets.json"
SAMPLES = LANDING / "images" / "reports"
GENERATOR = LANDING / "tools" / "make-sample-report-images.py"
REPORT_GEN = REPO / "scripts" / "report-gen.py"

def _shipped_copy() -> str:
    """The landing copy that ships beside the samples: the readme and the reports page.

    Both numbers pinned below — how many example findings the samples hold, and which documentation
    range the copy names — are only pins if they are read from the copy. As bare literals they were
    two constants whose comments asserted they matched a file nothing opened; the label pin a few
    lines further down reads its file, and this is the same pattern.
    """
    return (LANDING / "README.md").read_text() + (LANDING / "pages" / "reports.html").read_text()


COPY = _shipped_copy()

# The published copy states this number ("six example findings"), and the fixture is what a reader
# counts. The assertion that the copy states it lives with the fixture's own count, below.
SAMPLE_COUNT = 6
COUNT_WORDS = {6: "six"}

# Floors for the band assertions. The generator's own OUTPUT_WIDTH, LABEL_HEIGHT, LABEL_FILL and
# LABEL_INK are read from it in the tests rather than restated here: a literal under a comment
# saying where it comes from is a comment, not a pin, which is the defect this module has now been
# reviewed for twice.
LABEL_MINIMUM_PIXELS = 1000
LABEL_MINIMUM_INK = 100

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# TEST-NET-1, RFC 5737 — the range the published copy names, asserted against the copy below.
DOC_V4 = ipaddress.ip_network("192.0.2.0/24")
DOC_V6 = ipaddress.ip_network("2001:db8::/32")  # RFC 3849
RESERVED_SUFFIXES = (".example", ".test", ".invalid")
SKIP_DIRS = {".git", ".venv", "outputs", "logs", "__pycache__", ".pytest_cache", "images",
             "node_modules", ".mypy_cache", ".ruff_cache"}


def _load(path: Path, name: str):
    """Import a hyphenated script by path, skipping if its report extras are absent."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError) as exc:
        # ImportError for python-docx/python-pptx; OSError for WeasyPrint, whose import fails that
        # way when the wheel is present and the native stack (libgobject/libpango) is not. Either
        # way this is a missing report extra: a skip, not an error in a module that ships.
        pytest.skip(f"{path.name} needs the report extra: {exc}")
    return module


def _sample_generator():
    """The generator module, imported for its constants and its labelling helper."""
    return _load(GENERATOR, "sample_generator")


def _report_gen():
    return _load(REPORT_GEN, "report_gen_under_test")


def findings() -> list[dict]:
    return json.loads(FIXTURE.read_text())


def manifest_assets() -> list[dict]:
    return json.loads(MANIFEST.read_text())["assets"]


def cves(finding: dict) -> list[str]:
    value = finding.get("cve")
    if not value:
        return []
    return [value] if isinstance(value, str) else list(value)


def test_every_host_is_a_documentation_address():
    """A real range or a resolvable name would make an invented sample point somewhere."""
    for f in findings():
        host = f["host"]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None  # not an address at all: a name, and it must be a reserved one
        if address is not None:
            assert address in DOC_V4 or address in DOC_V6, f"{host} is not a documentation address"
        else:
            assert host.endswith(RESERVED_SUFFIXES), f"{host} is not under a reserved name (RFC 2606)"


def test_every_identifier_is_a_cve_identifier():
    for f in findings():
        for cve in cves(f):
            assert CVE.match(cve), f"{cve} is not a CVE identifier"


def test_the_fixture_is_the_only_place_the_invented_hosts_appear():
    """The hosts are invented; in shipping prose one would read as a real target."""
    hosts = {f["host"] for f in findings()}
    binary = {".png", ".pdf", ".docx", ".pptx", ".zip", ".cap", ".pcapng", ".xml"}
    offenders = []
    for path in sorted(REPO.rglob("*")):
        rel = path.relative_to(REPO)
        # This module names a host of its own to pin the network derivation, and the fixture is
        # where the hosts are defined: everything else has to be free of them.
        if path in (FIXTURE, Path(__file__).resolve()):
            continue
        if SKIP_DIRS & set(rel.parts) or not path.is_file():
            continue
        if path.suffix in binary:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        offenders += [f"{rel}: {host}" for host in hosts if host in text]
    assert not offenders, offenders


def test_the_manifest_lists_every_file_the_assets_directory_holds():
    """Not a `*.png` glob: condition 6 governs the directory, so an added file of any kind is one
    the manifest has to name — and a file it does not name is what the gate then fails on."""
    listed = {a["path"] for a in manifest_assets()}
    # rglob, not iterdir: condition 6 matches any file whose path starts with `images/reports/`,
    # so a capture one directory down is in the gate's scope and has to be in the manifest too.
    on_disk = {f"images/reports/{p.relative_to(SAMPLES)}" for p in sorted(SAMPLES.rglob("*")) if p.is_file()}
    assert listed == on_disk, sorted(listed ^ on_disk)
    assert len(on_disk) == SAMPLE_COUNT


def test_every_listed_hash_matches_the_file():
    for asset in manifest_assets():
        digest = hashlib.sha256((LANDING / asset["path"]).read_bytes()).hexdigest()
        assert digest == asset["sha256"], f"{asset['path']} has changed since the manifest was written"


def test_every_anchor_the_copy_links_to_exists_on_the_target_page():
    """The readme points at the samples page's fragment three times; that `id` did not exist."""
    page = (LANDING / "pages" / "reports.html").read_text()
    ids = set(re.findall(r'id="([^"]+)"', page))
    linked = set(re.findall(r"reports\.html#([\w-]+)", COPY))
    assert linked, "no copy links to a section of the reports page any more"
    missing = sorted(anchor for anchor in linked if anchor not in ids)
    assert not missing, f"the copy links to #{', #'.join(missing)}, which the page does not define"


def test_the_generator_draws_the_label_it_documents(tmp_path, monkeypatch):
    """The strip is the generator's own label, drawn with the documented wording.

    A page of this test's own, so the assertion is about the mechanism rather than about the
    published pixels: the canvas grows by exactly LABEL_HEIGHT rows, and the string handed to
    the drawing call is the generator's LABEL — the one the manifest's note and the landing copy
    also describe as synthetic.
    """
    generator = _sample_generator()
    page = tmp_path / "page.png"
    Image.new("RGB", (generator.OUTPUT_WIDTH, 200), (255, 255, 255)).save(page)

    drawn: list[str] = []
    import PIL.ImageDraw as image_draw

    draw_module = image_draw.ImageDraw
    real_text = draw_module.text
    monkeypatch.setattr(
        draw_module, "text",
        lambda self, xy, text, *a, **kw: (drawn.append(text), real_text(self, xy, text, *a, **kw))[1],
    )

    dest = tmp_path / "labelled.png"
    generator._label(page, dest)
    assert drawn == [generator.LABEL], "the strip is not the generator's own label"
    # And the wording is the one the shipped copy publishes, so the two cannot drift apart: a
    # label changed in the generator alone leaves the README quoting something no image carries.
    readme = (LANDING / "README.md").read_text()
    assert generator.LABEL in readme, "the landing copy does not quote the label the images carry"
    assert "synthetic" in generator.LABEL.lower(), "the label must say what the image is"

    with Image.open(dest) as image:
        assert image.size == (generator.OUTPUT_WIDTH, 200 + generator.LABEL_HEIGHT)
        strip = image.crop((0, 200, generator.OUTPUT_WIDTH, 200 + generator.LABEL_HEIGHT))
    strip_pixels = sum(count for count, colour in (strip.getcolors(1 << 20) or [])
                       if colour == tuple(generator.LABEL_FILL))
    assert strip_pixels >= LABEL_MINIMUM_PIXELS, "the strip is not the canvas colour the test expects"


def test_the_generator_finds_the_report_generator_in_a_release_tree(tmp_path):
    """The shipped generator has to work in the tree it ships into.

    In this repository the landing directory is a subdirectory, so the report generator is one
    level above it. In a release tree the landing directory's CONTENTS are merged to the root, so
    the generator sits beside `tools/`. A resolution written for the first layout only looks one
    directory ABOVE a public clone — and renders from whatever it finds there. So: copy the
    generator into a release-shaped root and require it to find that root's own copy.
    """
    root = tmp_path / "release-tree"
    (root / "tools").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "tools" / "make-sample-report-images.py").write_text(GENERATOR.read_text())
    (root / "scripts" / "report-gen.py").write_text("# the release tree's own copy\n")
    module = _load(root / "tools" / "make-sample-report-images.py", "generator_in_release_tree")
    loaded = module._load_report_gen()
    assert loaded.__file__ == str(root / "scripts" / "report-gen.py"), \
        f"resolved {loaded.__file__}, which is not the tree's own generator"


def test_check_mode_reports_every_way_an_image_can_drift(monkeypatch):
    """`--check` compares; a check that only prints hashes returns 0 on six mismatched images."""
    generator = _sample_generator()
    want, other = "a" * 64, "b" * 64

    assert generator._check_asset("s.png", want, want, want) == []
    assert "no image on disk" in generator._check_asset("s.png", want, None, want)[0]
    assert "a fresh render" in generator._check_asset("s.png", want, other, want)[0]
    assert "not listed" in generator._check_asset("s.png", want, want, None)[0]
    assert "approved" in generator._check_asset("s.png", want, want, other)[0]
    assert len(generator._check_asset("s.png", want, other, other)) == 2


def test_the_label_font_is_required_not_defaulted(monkeypatch):
    """A silent fallback font redraws every image and leaves the manifest describing other bytes."""
    generator = _sample_generator()
    monkeypatch.setattr(generator, "LABEL_FONT_CANDIDATES", ("/nonexistent/DejaVuSans.ttf",))
    with pytest.raises(SystemExit) as exc:
        generator._label_font()
    assert "DejaVu" in str(exc.value)


def test_every_sample_carries_the_label_band():
    """Every published image ends in a band holding the label's own ink colour.

    Not proof that the band is a label rather than page content — see the module docstring — but
    a capture whose bottom rows are page matter does not carry grey label text down there.
    """
    generator = _sample_generator()
    report_gen = _report_gen()
    ink = tuple(generator.LABEL_INK)
    # The ink has to be a colour the page cannot produce by itself. MED_GRAY is 797979 — (121,
    # 121, 121), one unit from a naive choice — so this is checked rather than assumed, and the
    # count below matches the ink EXACTLY, which is what keeps anti-aliased edges of the page's
    # own black or grey text from counting as label glyphs.
    palette = {tuple(report_gen.hex_to_rgb(c)) for c in
               (report_gen.DARK_GRAY, report_gen.MED_GRAY, report_gen.BRAND_RED)}
    assert ink not in palette, f"the label ink {ink} is a colour report-gen draws with"
    assert ink not in {(0, 0, 0), (255, 255, 255)}, "the label ink must not be page black or white"

    for png in sorted(SAMPLES.iterdir()):
        if not png.is_file():
            continue
        with Image.open(png) as image:
            assert image.width == generator.OUTPUT_WIDTH, f"{png.name} is {image.size}"
            band = image.crop((0, image.height - generator.LABEL_HEIGHT, image.width, image.height))
        colours = {colour: count for count, colour in (band.getcolors(1 << 20) or [])}
        assert colours.get(tuple(generator.LABEL_FILL), 0) >= LABEL_MINIMUM_PIXELS, \
            f"{png.name} has no label canvas"
        assert colours.get(ink, 0) >= LABEL_MINIMUM_INK, \
            f"{png.name} carries no label text in its band (checked for exactly {ink})"


def _report_gen_path() -> Path:
    """The report generator's source, in either layout — the two roots the generator itself tries."""
    for base in (LANDING, REPO):
        if (base / "scripts" / "report-gen.py").is_file():
            return base / "scripts" / "report-gen.py"
    raise AssertionError("no scripts/report-gen.py beside the landing directory or the repository")


def test_the_readme_does_not_claim_a_format_the_report_generator_cannot_write():
    """The readme's report-gen example listed `checklist.xlsx`, which that tool does not produce.

    The Excel checklist comes from a different script, so the line documenting one tool's outputs
    was advertising another tool's file — the class an external round found by reading the copy
    against the code. Pinned against the generator's own source, not against a second copy of the
    claim: every file name in the line has to appear in that source.
    """
    example = re.search(r"Produces:([^\n]*)", COPY)
    assert example, "the readme no longer documents the report generator's outputs"
    produced = [name.strip() for name in example.group(1).split(",") if name.strip()]
    assert len(produced) >= 3, f"the Produces line names {produced}, which is fewer than it did"
    source = _report_gen_path().read_text()
    for name in produced:
        extension = name.rsplit(".", 1)[-1].strip().lower()
        # The generator's own entry point for a format is what makes the claim true: `generate_docx`,
        # `generate_pdf`, `generate_pptx`. Asserting on the file's stem instead would pass for a name
        # whose extension the tool has no code for, whenever the stem happened to appear in a comment.
        assert f"generate_{extension}" in source, \
            f"the readme says the generator writes {name}; its source has no generate_{extension}"


def test_the_fixture_reads_as_a_sample_not_an_engagement():
    """Exactly the number the published copy states, across several severities."""
    fs = findings()
    assert len(fs) == SAMPLE_COUNT, "the fixture holds a different number of findings than the copy"
    stated = f"{COUNT_WORDS[SAMPLE_COUNT]} example findings"
    assert stated in COPY, f"the published copy does not state '{stated}'"
    assert {f["severity"].lower() for f in fs} >= {"critical", "high", "medium"}
    assert all(f.get("remediation") for f in fs), "every sample finding needs a remediation line"


def test_no_finding_carries_a_private_path():
    """The fixture ships, so it must not name anything the classification makes private."""
    text = FIXTURE.read_text()
    for private in ("references/benchmarks", "references/comparisons", "references/exec-summary",  # boundary:allow — the terms this module asserts absent from the fixture
                    "references/operator-guide", "skills/", "tests/fixtures", "configs/", "outputs/"):  # boundary:allow — the terms this module asserts absent from the fixture
        assert private not in text, private


# The four CVE rows as NVD publishes them: the product, the version the advisory affects, and the
# CVSS v3.1 base score of the metric NVD marks Primary (for CVE-2021-41773 that is 9.8; 7.5 is the
# CNA's Secondary metric for the same identifier). Verified against the live API on 2026-09-25, and
# re-checked by the network test below whenever NVD answers.
PUBLISHED = {
    "CVE-2021-44228": ("Apache Log4j2", "2.14.1", 10.0),
    "CVE-2021-41773": ("Apache httpd", "2.4.49", 9.8),
    "CVE-2017-0144": ("Microsoft Windows SMB", "SMBv1", 8.8),
    "CVE-2021-23017": ("nginx", "1.18.0", 7.7),
}
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DOCUMENTATION_NETWORKS = [ipaddress.ip_network(n) for n in
                          ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def test_the_cve_rows_are_the_published_ones():
    """The fixture against the transcribed advisory values — a pin on drift.

    This detects the fixture changing, not the transcription being wrong: the network test below
    is the one that proves the transcription, and it is the reason both exist.
    """
    rows = {f["cve"]: (f["service"], f["version"], f["cvss_score"]) for f in findings() if f.get("cve")}
    assert set(rows) == set(PUBLISHED)
    for cve, (service, version, score) in rows.items():
        assert (service, version, score) == PUBLISHED[cve], cve


def test_the_fixture_declares_a_documentation_network():
    """The reports print this line, and the published copy names it as TEST-NET-1.

    So the declared range is pinned to the one the copy states, and it must hold the fixture's
    own hosts — a declared range that contains none of them is a line about somewhere else.
    """
    declared = [f["network"] for f in findings() if f.get("network")]
    assert declared, "the fixture must declare the network the report prints"
    for value in declared:
        network = ipaddress.ip_network(value)
        assert network in DOCUMENTATION_NETWORKS, value
        assert network == DOC_V4, f"{value} is not the TEST-NET-1 range the published copy names"
        assert "TEST-NET-1" in COPY, "the published copy does not name TEST-NET-1"
    for f in findings():
        try:
            address = ipaddress.ip_address(f["host"])
        except ValueError:
            continue
        assert address in DOC_V4, f"{f['host']} is outside the declared {DOC_V4}"


@pytest.mark.network
def test_the_cve_rows_still_match_nvd():
    """The one claim in the fixture that a reader can check: real identifiers, real scores.

    Skipped, not failed, when NVD is unreachable — the offline pin above is what holds in CI.
    NVD rate-limits to a few requests per 30 seconds without an API key, so the loop pauses
    between calls; set NVD_API_KEY in the environment to lift that.
    """
    import time

    import requests

    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    for index, (cve, (_, version, score)) in enumerate(PUBLISHED.items()):
        if index:
            time.sleep(7)
        try:
            response = requests.get(f"{NVD}?cveId={cve}", timeout=30, headers=headers)
            response.raise_for_status()
        except requests.RequestException as exc:
            # Transport only. A response NVD returns is parsed below and, if it does not
            # look like the API's shape, this test fails rather than quietly skipping.
            pytest.skip(f"NVD unreachable: {exc}")
        records = response.json().get("vulnerabilities") or []
        if not records:
            # A 200 with no record is NVD's shape for a rate-limited or unknown query, not a
            # verdict on the score: the offline pin above is what holds in that case.
            pytest.skip(f"NVD returned no record for {cve} (rate limit or unknown identifier)")
        metrics = records[0]["cve"].get("metrics", {})
        entries = metrics.get("cvssMetricV31") or []
        assert entries, f"{cve} carries no CVSS v3.1 metric at NVD; the pin documents a v3.1 score"
        # The metric NVD marks Primary, and the same metric family the pin documents: comparing a
        # v3.0 or v2 score against a v3.1 number would be a cross-scale comparison reported as a
        # fixture disagreement.
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        published = primary["cvssData"]["baseScore"]
        assert published == score, f"{cve} scores {published} at NVD (v3.1), the fixture says {score}"


def test_the_assessment_date_pin_is_honoured_and_a_bad_one_is_loud(monkeypatch):
    """The manifest pins pixels by hash, so the date has to be an input, not a clock reading.

    Behavioural rather than a grep for the pin's name: a docstring mentioning
    `PORTSHIM_REPORT_DATE` would satisfy the weaker test while the render stamped today.
    """
    report_gen = _report_gen()
    monkeypatch.setenv("PORTSHIM_REPORT_DATE", "2026-01-15")
    assert report_gen._assessment_date() == "January 15, 2026"

    generator = _sample_generator()
    monkeypatch.setenv("PORTSHIM_REPORT_DATE", generator.SAMPLE_DATE)
    assert report_gen._assessment_date().endswith(f", {generator.SAMPLE_DATE[:4]}"), \
        "the generator's pin and the renderer's date disagree"

    for malformed in ("jan-15", "", "2026/01/15"):
        monkeypatch.setenv("PORTSHIM_REPORT_DATE", malformed)
        with pytest.raises(ValueError):
            report_gen._assessment_date()

    # And the pin the deliverables were rendered under is the one the manifest publishes: a
    # changed SAMPLE_DATE that was not regenerated leaves the manifest stating the old date.
    manifest_note = json.loads(MANIFEST.read_text())["note"]
    assert generator.SAMPLE_DATE in manifest_note, "the manifest does not state the render date"
    assert generator.LABEL in manifest_note, "the manifest does not state the label the images carry"


def test_the_target_network_is_declared_or_derived_from_an_address_only():
    """`app-01.lab.example` must never become `app-01.lab.0/24` — that range describes nobody."""
    report_gen = _report_gen()
    declared = [{"host": "app-01.lab.example", "network": "192.0.2.0/24"}]
    assert report_gen._target_network(declared) == "192.0.2.0/24"

    named = [{"host": "app-01.lab.example"}]
    assert "/" not in report_gen._target_network(named), "a hostname is not a network"

    addressed = [{"host": "192.0.2.7"}]
    assert report_gen._target_network(addressed) == "192.0.2.0/24"
