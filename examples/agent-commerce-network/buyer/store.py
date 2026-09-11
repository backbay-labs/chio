"""Durable procurement state, reservations and balanced settlement entries."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import RLock


class ProcurementStore:
    def __init__(self, path: str, budget_minor: int):
        if budget_minor < 0:
            raise ValueError("The operator budget must be nonnegative")
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = RLock()
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS configuration(id INTEGER PRIMARY KEY CHECK(id=1), budget INTEGER NOT NULL CHECK(budget>=0));
          CREATE TABLE IF NOT EXISTS quotes(id TEXT PRIMARY KEY, body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, quote_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS positions(job_id TEXT PRIMARY KEY, amount INTEGER NOT NULL CHECK(amount>=0), status TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS allocations(id TEXT PRIMARY KEY, amount INTEGER NOT NULL CHECK(amount>0), reason TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
          CREATE TABLE IF NOT EXISTS ledger(job_id TEXT NOT NULL, account TEXT NOT NULL, amount INTEGER NOT NULL, PRIMARY KEY(job_id,account));
        """)
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO configuration VALUES(1,?)", (budget_minor,))
            if db.execute("SELECT budget FROM configuration").fetchone()[0] != budget_minor:
                raise ValueError(
                    "The retained ledger has a different operator budget; do not reset it implicitly"
                )

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    @staticmethod
    def load(db, table, identity):
        if table not in {"jobs", "quotes"}:
            raise ValueError("Unknown record kind")
        row = db.execute(f"SELECT body FROM {table} WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise KeyError(identity)
        return json.loads(row[0])

    @staticmethod
    def save_job(db, job):
        db.execute("UPDATE jobs SET body=? WHERE id=?", (json.dumps(job), job["job_id"]))

    @staticmethod
    def capacity(db):
        return (
            db.execute("SELECT budget FROM configuration").fetchone()[0]
            + db.execute("SELECT COALESCE(SUM(amount),0) FROM allocations").fetchone()[0]
        )

    @staticmethod
    def available(db):
        budget = ProcurementStore.capacity(db)
        committed = db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM positions WHERE status IN ('reserved','settled')"
        ).fetchone()[0]
        return budget - committed
