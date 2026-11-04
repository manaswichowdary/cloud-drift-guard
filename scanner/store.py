"""A tiny findings table in SQLite. It lets us alert only on findings we have not seen before."""
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    rule_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    PRIMARY KEY (rule_id, resource)
)"""


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.execute(SCHEMA)

    def record(self, findings, kinds=None, now=None):
        """Save a scan. Returns (new, resolved): findings seen for the first time, and keys that went away.

        `kinds` says which kinds of finding this scan covers, for example {"drift"}. Only findings of those
        kinds can be marked resolved, so a drift run cannot close out the findings from a security scan.
        """
        now = (now or datetime.now(timezone.utc)).isoformat()
        current = {(f.rule_id, f.resource) for f in findings}
        new = []
        for f in findings:
            row = self.db.execute(
                "SELECT resolved_at FROM findings WHERE rule_id=? AND resource=?",
                (f.rule_id, f.resource)).fetchone()
            if row is None or row[0] is not None:
                new.append(f)  # first time, or it came back after being fixed
                self.db.execute(
                    "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,NULL)",
                    (f.rule_id, f.resource, f.severity, f.kind, f.message, now, now))
            else:
                self.db.execute(
                    "UPDATE findings SET last_seen=?, message=? WHERE rule_id=? AND resource=?",
                    (now, f.message, f.rule_id, f.resource))
        resolved = []
        covered = set(kinds) if kinds else {f.kind for f in findings}
        for rule_id, resource, kind in self.db.execute(
                "SELECT rule_id, resource, kind FROM findings WHERE resolved_at IS NULL").fetchall():
            if kind in covered and (rule_id, resource) not in current:
                resolved.append((rule_id, resource))
                self.db.execute("UPDATE findings SET resolved_at=? WHERE rule_id=? AND resource=?",
                                (now, rule_id, resource))
        self.db.commit()
        return new, resolved
