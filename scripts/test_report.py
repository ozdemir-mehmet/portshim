#!/usr/bin/env python3
"""
PortShim — save test suite results to outputs/reports/.

Runs pytest with --junitxml, parses the XML output, and saves structured
JSON + human-readable summary to outputs/reports/{category}-{timestamp}/.

Usage:
    python scripts/test_report.py tests/test_wireless_*.py
    python scripts/test_report.py tests/ --ignore=tests/test_wireless_*
    python scripts/test_report.py --junit-xml /tmp/results.xml

Category is auto-detected from test file paths:
- test_wireless_*.py → wireless/
- everything else → wired/
"""

import argparse
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "outputs" / "reports"


def parse_junit_xml(xml_content: str) -> dict:
    """Parse JUnit XML into structured test results dict.

    Returns {pass_count, fail_count, skip_count, total, duration, tests}.
    """
    root = ET.fromstring(xml_content)

    total = 0
    failures = 0
    errors = 0
    skipped = 0
    total_time = 0.0
    tests = []

    for suite in root.iter("testsuite"):
        total += int(suite.get("tests", 0))
        failures += int(suite.get("failures", 0))
        errors += int(suite.get("errors", 0))
        skipped += int(suite.get("skipped", 0))
        total_time += float(suite.get("time", 0))

        for case in suite.iter("testcase"):
            name = case.get("name", "unknown")
            classname = case.get("classname", "")
            duration = float(case.get("time", 0))

            status = "passed"
            message = None

            fail_elem = case.find("failure")
            error_elem = case.find("error")
            skip_elem = case.find("skipped")

            if fail_elem is not None:
                status = "failed"
                message = fail_elem.get("message", "") or fail_elem.text or ""
            elif error_elem is not None:
                status = "failed"
                message = error_elem.get("message", "") or error_elem.text or ""
            elif skip_elem is not None:
                status = "skipped"
                message = skip_elem.get("message", "") or ""

            # Derive file path from classname
            path = classname.replace(".", "/") + ".py" if classname else ""

            tests.append({
                "name": name,
                "status": status,
                "duration": duration,
                "path": path,
                "message": message.strip() if message else None,
            })

    pass_count = total - failures - errors - skipped

    return {
        "pass_count": pass_count,
        "fail_count": failures + errors,
        "skip_count": skipped,
        "total": total,
        "duration": round(total_time, 2),
        "tests": tests,
    }


def detect_category(tests: list[dict]) -> str:
    """Determine wired vs wireless from test paths."""
    wireless_count = sum(
        1 for t in tests if "test_wireless_" in t.get("path", "")
    )
    total = len(tests) or 1
    return "wireless" if wireless_count > total / 2 else "wired"


def save_report(
    result: dict,
    category: str,
    timestamp: str,
    base_dir: Path | None = None,
) -> Path:
    """Save test results to the report directory.

    Creates {base_dir}/{category}-{timestamp}/ with results.json and summary.txt.
    Returns the report directory path.
    """
    base = base_dir or OUTPUT_DIR
    report_dir = base / f"{category}-{timestamp}"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Structured JSON
    output = {
        "category": category,
        "timestamp": timestamp,
        "pass_count": result["pass_count"],
        "fail_count": result["fail_count"],
        "skip_count": result["skip_count"],
        "total": result["total"],
        "duration": result.get("duration", 0),
        "tests": result.get("tests", []),
    }

    (report_dir / "results.json").write_text(json.dumps(output, indent=2))

    # Human-readable summary
    summary = [
        f"PortShim Test Report — {category}",
        f"Timestamp: {timestamp}",
        f"",
        f"{result['total']} tests: {result['pass_count']} passed, "
        f"{result['fail_count']} failed, {result['skip_count']} skipped",
        f"Duration: {result.get('duration', 0):.2f}s",
        f"",
    ]

    if result.get("tests"):
        summary.append("─" * 60)
        for t in result["tests"]:
            icon = {"passed": "✓", "failed": "✗", "skipped": "○"}.get(t["status"], "?")
            line = f"  {icon} {t['name']} ({t['duration']:.3f}s)"
            if t.get("message"):
                line += f"  — {t['message'][:80]}"
            summary.append(line)

    (report_dir / "summary.txt").write_text("\n".join(summary) + "\n")

    return report_dir


def run_pytest(args: list[str]) -> tuple[str, int]:
    """Run pytest with --junitxml and return (xml_output, exit_code)."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    cmd = [
        sys.executable, "-m", "pytest",
        "--junitxml=" + xml_path,
        "-q",
    ] + args

    try:
        result = subprocess.run(cmd, capture_output=False)
        rc = result.returncode
    except FileNotFoundError:
        rc = 1

    xml_content = ""
    try:
        xml_content = Path(xml_path).read_text()
    except (OSError, FileNotFoundError):
        pass
    finally:
        try:
            Path(xml_path).unlink()
        except (OSError, FileNotFoundError):
            pass

    return xml_content, rc


# ── CLI ──


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PortShim — run tests and save structured report",
    )
    parser.add_argument(
        "pytest_args", nargs="*",
        help="Arguments to pass to pytest (e.g., tests/test_wireless_*.py)",
    )
    parser.add_argument(
        "--junit-xml", type=Path,
        help="Parse existing JUnit XML instead of running pytest",
    )
    parser.add_argument(
        "--category", choices=["wired", "wireless", "auto"],
        default="auto",
        help="Report category (default: auto-detect)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=OUTPUT_DIR,
        help="Base output directory (default: outputs/reports/)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ── Get test results ──
    if args.junit_xml:
        xml_content = args.junit_xml.read_text()
        result = parse_junit_xml(xml_content)
    else:
        pytest_args = args.pytest_args if args.pytest_args else ["tests/"]
        xml_content, rc = run_pytest(pytest_args)
        if not xml_content:
            print("Error: pytest produced no JUnit XML output", file=sys.stderr)
            return 1
        result = parse_junit_xml(xml_content)

    # ── Detect category ──
    category = args.category
    if category == "auto":
        category = detect_category(result.get("tests", []))

    # ── Save report ──
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    report_dir = save_report(result, category, timestamp, args.output_dir)

    print(f"Report saved: {report_dir}")
    print(f"  {result['total']} tests: {result['pass_count']} passed, "
          f"{result['fail_count']} failed, {result['skip_count']} skipped")

    return 0 if result["fail_count"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
