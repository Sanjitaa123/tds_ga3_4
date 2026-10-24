"""SQLite persistence for the GA5 incident agent."""
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager, closing
from pathlib import Path

DB_NAME = os.getenv("GA5_DB_PATH", str(Path(__file__).with_name("incidents.db")))


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def connect():
    db = sqlite3.connect(DB_NAME, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 10000")
    return db


@contextmanager
def transaction():
    db = connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize():
    with closing(connect()) as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                run_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                initial_response_json TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                run_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (run_id, receipt_id),
                FOREIGN KEY (run_id) REFERENCES incidents(run_id)
            )
        """)


def get_incident(run_id):
    with closing(connect()) as db:
        row = db.execute(
            "SELECT run_id, request_hash, initial_response_json, state_json FROM incidents WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    return dict(row) if row else None


def create_incident(run_id, request_hash, initial_response, state):
    with transaction() as db:
        db.execute(
            "INSERT INTO incidents(run_id, request_hash, initial_response_json, state_json) VALUES(?,?,?,?)",
            (run_id, request_hash, canonical_json(initial_response), canonical_json(state)),
        )


def update_state(db, run_id, state):
    db.execute(
        "UPDATE incidents SET state_json = ?, updated_at = CURRENT_TIMESTAMP WHERE run_id = ?",
        (canonical_json(state), run_id),
    )


def get_receipt(run_id, receipt_id):
    with closing(connect()) as db:
        row = db.execute(
            "SELECT receipt_hash, response_json FROM receipts WHERE run_id = ? AND receipt_id = ?",
            (run_id, receipt_id),
        ).fetchone()
    return dict(row) if row else None


def save_receipt_and_state(run_id, receipt_id, receipt_hash, response, state):
    """Atomically store the receipt replay response and the resulting incident state."""
    with transaction() as db:
        existing = db.execute(
            "SELECT receipt_hash, response_json FROM receipts WHERE run_id = ? AND receipt_id = ?",
            (run_id, receipt_id),
        ).fetchone()
        if existing:
            return dict(existing)
        db.execute(
            "INSERT INTO receipts(run_id, receipt_id, receipt_hash, response_json) VALUES(?,?,?,?)",
            (run_id, receipt_id, receipt_hash, canonical_json(response)),
        )
        update_state(db, run_id, state)
    return None
