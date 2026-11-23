"""Share live lookup results and request budgets across local app processes."""

import json
import os
import sqlite3
from contextlib import closing, contextmanager
from hashlib import sha256
from pathlib import Path
from time import time

STATE_PATH = Path(__file__).resolve().parents[1] / ".cache" / "lookups.sqlite3"
CACHE_TTL = {"Found": 900, "No record": 300}
WINDOWS = {"VirusTotal": ((60, 4), (86400, 500)), "AbuseIPDB": ((86400, 1000),)}


def _digest(*parts):
    return sha256(json.dumps(parts).encode()).hexdigest()


class LookupState:
    def __init__(self, provider, api_key):
        self.provider = provider
        self.scope = _digest(provider, api_key)

    @contextmanager
    def _transaction(self):
        path = Path(os.environ.get("SOC_TRIAGE_LOOKUP_DB") or STATE_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path, timeout=3)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS results (id TEXT PRIMARY KEY, expires REAL, payload TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS requests (scope TEXT, started REAL)")
            db.execute("CREATE INDEX IF NOT EXISTS requests_by_scope ON requests (scope, started)")
            db.execute("CREATE TABLE IF NOT EXISTS cooldowns (scope TEXT PRIMARY KEY, expires REAL)")
            yield db

    def reserve(self, kind, indicator, *, within_alert_limit):
        """Return a cached result or skip reason, or reserve one outbound request."""
        with self._transaction() as db:
            now = time()
            db.execute("DELETE FROM results WHERE expires <= ?", (now,))
            db.execute("DELETE FROM cooldowns WHERE expires <= ?", (now,))
            db.execute("DELETE FROM requests WHERE started <= ?", (now - 86400,))
            row = db.execute("SELECT payload FROM results WHERE id = ?",
                             (_digest(self.scope, kind, indicator),)).fetchone()
            if row:
                return tuple(json.loads(row[0])), None
            if db.execute("SELECT 1 FROM cooldowns WHERE scope = ?", (self.scope,)).fetchone():
                return None, "Provider cooldown"
            if not within_alert_limit:
                return None, "Lookup limit reached"
            windows = WINDOWS.get(self.provider, ())
            for seconds, limit in windows:
                count = db.execute("SELECT COUNT(*) FROM requests WHERE scope = ? AND started > ?",
                                   (self.scope, now - seconds)).fetchone()[0]
                if count >= limit:
                    return None, "Local rate limit reached"
            if windows:
                db.execute("INSERT INTO requests VALUES (?, ?)", (self.scope, now))
            return None, None

    def record(self, kind, indicator, result, retry_after):
        status = result[0]
        if status not in CACHE_TTL and status != "Rate limited":
            return
        with self._transaction() as db:
            now = time()
            if status == "Rate limited":
                db.execute("INSERT INTO cooldowns VALUES (?, ?) ON CONFLICT(scope) DO UPDATE "
                           "SET expires = MAX(cooldowns.expires, excluded.expires)", (self.scope, now + retry_after))
            else:
                db.execute("INSERT OR REPLACE INTO results VALUES (?, ?, ?)",
                           (_digest(self.scope, kind, indicator), now + CACHE_TTL[status], json.dumps(result)))
