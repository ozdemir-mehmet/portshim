#!/usr/bin/env python3
"""
scan_db.py — SQLite database for cross-engagement scan history.

Schema:
    engagements  — one row per assessment
    hosts        — discovered hosts per engagement
    findings     — vulnerabilities found, with status tracking
    retests      — retest results (FIXED/STILL_OPEN/NEW/REGRESSION)

Usage as module:
    from scan_db import ScanDB
    db = ScanDB()
    db.save_engagement("acme-july", "10.0.0.0/22", "surgical", "hybrid")
    db.save_findings("acme-july", findings_list)

Config:
    PD_DB_PATH env var — path to SQLite file
    Default: ~/.portshim/scan-history.db
"""

import json, os, sqlite3, time
from pathlib import Path
from datetime import datetime

DEFAULT_DB_PATH = Path.home() / ".portshim" / "scan-history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id              TEXT PRIMARY KEY,
    client          TEXT,
    target_cidr     TEXT NOT NULL,
    started_at      TEXT,
    completed_at    TEXT,
    stealth_profile TEXT,
    llm_mode        TEXT,
    total_hosts     INTEGER,
    findings_count  INTEGER,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   TEXT NOT NULL,
    ip              TEXT NOT NULL,
    hostname        TEXT,
    os              TEXT,
    device_role     TEXT,
    ports_open      INTEGER,
    high_risk       INTEGER DEFAULT 0,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id),
    UNIQUE(engagement_id, ip)
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT NOT NULL,
    engagement_id   TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INTEGER,
    service         TEXT,
    version         TEXT,
    cve             TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    severity        TEXT,   -- critical, high, medium, low, limitation
    title           TEXT,
    description     TEXT,
    remediation     TEXT,
    status          TEXT DEFAULT 'open',  -- open, fixed, accepted_risk, false_positive
    fixed_at        TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (engagement_id, id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS retests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   TEXT NOT NULL,
    finding_id      TEXT NOT NULL,
    result          TEXT NOT NULL,  -- FIXED, STILL_OPEN, NEW, REGRESSION
    retest_date     TEXT,
    notes           TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_hosts_engagement ON hosts(engagement_id);
"""

class ScanDB:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path or os.environ.get("PD_DB_PATH", DEFAULT_DB_PATH))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # ── Engagements ──

    def save_engagement(self, engagement_id, target_cidr, stealth=None, llm_mode=None,
                        client=None, started_at=None, total_hosts=0):
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO engagements (id, client, target_cidr, stealth_profile, llm_mode, started_at, total_hosts)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (engagement_id, client, target_cidr, stealth, llm_mode,
                  started_at or datetime.now().isoformat(), total_hosts))
            conn.commit()

    def complete_engagement(self, engagement_id, findings_count=0,
                            critical=0, high=0, medium=0, low=0):
        with self._conn() as conn:
            conn.execute("""
                UPDATE engagements SET completed_at = ?, findings_count = ?,
                    critical_count = ?, high_count = ?, medium_count = ?, low_count = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), findings_count, critical, high, medium, low, engagement_id))
            conn.commit()

    # ── Hosts ──

    def save_hosts(self, engagement_id, hosts):
        """hosts: list of {ip, hostname, os, device_role, ports_open, high_risk}"""
        with self._conn() as conn:
            for h in hosts:
                conn.execute("""
                    INSERT OR REPLACE INTO hosts (engagement_id, ip, hostname, os, device_role, ports_open, high_risk)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (engagement_id, h.get("ip"), h.get("hostname"), h.get("os"),
                      h.get("device_role"), h.get("ports_open", 0), h.get("high_risk", 0)))
            conn.commit()

    # ── Findings ──

    def save_findings(self, engagement_id, findings):
        """findings: list of {id, host, port, service, version, cve, cvss_score, cvss_vector,
                              severity, title, description, remediation}"""
        with self._conn() as conn:
            for f in findings:
                conn.execute("""
                    INSERT OR REPLACE INTO findings
                        (id, engagement_id, host, port, service, version, cve, cvss_score,
                         cvss_vector, severity, title, description, remediation, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                """, (f.get("id"), engagement_id, f.get("host"), f.get("port"),
                      f.get("service"), f.get("version"), f.get("cve"),
                      f.get("cvss_score"), f.get("cvss_vector"), f.get("severity"),
                      f.get("title"), f.get("description"), f.get("remediation")))
            conn.commit()

    def update_finding_status(self, engagement_id, finding_id, status):
        with self._conn() as conn:
            conn.execute("""
                UPDATE findings SET status = ?, fixed_at = CASE WHEN ? = 'fixed' THEN datetime('now') ELSE fixed_at END
                WHERE engagement_id = ? AND id = ?
            """, (status, status, engagement_id, finding_id))
            conn.commit()

    # ── Retests ──

    def save_retest(self, engagement_id, finding_id, result, notes=None):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO retests (engagement_id, finding_id, result, retest_date, notes)
                VALUES (?, ?, ?, ?, ?)
            """, (engagement_id, finding_id, result, datetime.now().isoformat(), notes))
            # Also update finding status
            status_map = {"FIXED": "fixed", "STILL_OPEN": "open", "NEW": "open", "REGRESSION": "open"}
            new_status = status_map.get(result, "open")
            conn.execute("""
                UPDATE findings SET status = ? WHERE engagement_id = ? AND id = ?
            """, (new_status, engagement_id, finding_id))
            conn.commit()

    # ── Queries ──

    def list_engagements(self):
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM engagements ORDER BY started_at DESC").fetchall()
            return [dict(r) for r in rows]

    def query_findings(self, engagement_id=None, severity=None, status=None, limit=100):
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if engagement_id:
            query += " AND engagement_id = ?"
            params.append(engagement_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY cvss_score DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def compare_engagements(self, engagement_a, engagement_b):
        """Return findings present in A but not B (new), present in both (still open),
           present in B but not A (fixed)."""
        with self._conn() as conn:
            # Findings in A
            a_findings = {r["id"]: dict(r) for r in conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ?", (engagement_a,)).fetchall()}
            # Findings in B
            b_findings = {r["id"]: dict(r) for r in conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ?", (engagement_b,)).fetchall()}

        fixed = [f for fid, f in a_findings.items() if fid not in b_findings]
        still_open = [f for fid, f in a_findings.items() if fid in b_findings]
        new_findings = [f for fid, f in b_findings.items() if fid not in a_findings]

        return {"fixed": fixed, "still_open": still_open, "new": new_findings}

    def stats(self):
        """Aggregate stats across all engagements."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM engagements").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            fixed = conn.execute("SELECT COUNT(*) FROM findings WHERE status = 'fixed'").fetchone()[0]
            fix_rate = (fixed / total_findings * 100) if total_findings > 0 else 0

            severity_counts = {}
            for sev in ["critical", "high", "medium", "low"]:
                count = conn.execute("SELECT COUNT(*) FROM findings WHERE severity = ?", (sev,)).fetchone()[0]
                severity_counts[sev] = count

        return {
            "total_engagements": total,
            "total_findings": total_findings,
            "fixed": fixed,
            "fix_rate": round(fix_rate, 1),
            "severity_counts": severity_counts,
        }
