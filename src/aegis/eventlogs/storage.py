"""Opt-in additive schema v3, with an SQLite backup before migration."""
import os
from pathlib import Path
import sqlite3
import tempfile

from aegis.storage.sqlite import connect

SCHEMA = '''
CREATE TABLE analysis_runs (
 id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collections(id),
 run_key TEXT NOT NULL UNIQUE, engine TEXT NOT NULL, engine_version TEXT NOT NULL,
 manifest_json TEXT NOT NULL, parameters_json TEXT NOT NULL,
 created_at_utc TEXT NOT NULL, finished_at_utc TEXT,
 status TEXT NOT NULL, master_zip TEXT NOT NULL, output_dir TEXT NOT NULL,
 diagnostics_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE eventlog_files (
 id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES analysis_runs(id),
 source_member TEXT NOT NULL, file_sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
 status TEXT NOT NULL, diagnostics_json TEXT NOT NULL,
 UNIQUE(run_id, source_member)
);
CREATE TABLE eventlog_events (
 evidence_id TEXT PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collections(id),
 source_member TEXT NOT NULL, file_sha256 TEXT NOT NULL, byte_offset INTEGER NOT NULL,
 record_id TEXT NOT NULL, channel TEXT NOT NULL, computer TEXT NOT NULL,
 event_id TEXT NOT NULL, timestamp_utc TEXT NOT NULL, raw_xml TEXT NOT NULL,
 UNIQUE(collection_id, source_member, byte_offset)
);
CREATE TABLE analysis_findings (
 id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES analysis_runs(id),
 file_id INTEGER NOT NULL REFERENCES eventlog_files(id), finding_key TEXT NOT NULL,
 rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
 reference_status TEXT NOT NULL, raw_json TEXT NOT NULL,
 UNIQUE(run_id, finding_key)
);
CREATE TABLE analysis_finding_evidence (
 finding_id INTEGER NOT NULL REFERENCES analysis_findings(id),
 evidence_id TEXT NOT NULL REFERENCES eventlog_events(evidence_id),
 PRIMARY KEY(finding_id, evidence_id)
);
CREATE INDEX idx_analysis_collection ON analysis_runs(collection_id);
CREATE INDEX idx_eventlog_collection ON eventlog_events(collection_id);
'''


def connect_eventlogs(path: Path):
    db = connect(path)
    try:
        if db.execute('PRAGMA user_version').fetchone()[0] == 3:
            return db
        fd, name = tempfile.mkstemp(prefix=path.name + '.before-m6-', suffix='.sqlite', dir=path.parent)
        os.close(fd)
        backup = sqlite3.connect(name)
        try:
            db.backup(backup)
        finally:
            backup.close()
        # Recheck while holding the writer lock to avoid concurrent migrations.
        db.execute('BEGIN IMMEDIATE')
        if db.execute('PRAGMA user_version').fetchone()[0] != 3:
            for statement in SCHEMA.split(';'):
                if statement.strip():
                    db.execute(statement)
            db.execute('PRAGMA user_version=3')
        db.commit()
        return db
    except Exception:
        db.rollback()
        db.close()
        raise
