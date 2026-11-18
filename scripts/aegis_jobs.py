"""Small durable queue. Interrupted paid requests are never automatically repeated."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone


class Jobs:
    def __init__(self, path):
        self.path = str(path)

    @contextmanager
    def connect(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, fingerprint TEXT, status TEXT, created TEXT, payload TEXT, events TEXT, result TEXT)')
        try:
            with c:
                yield c
        finally:
            c.close()

    def recover(self):
        with self.connect() as c:
            c.execute("UPDATE jobs SET status='interrupted' WHERE status='running'")

    def submit(self, fingerprint, payload):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute("SELECT id FROM jobs WHERE fingerprint=? AND status IN ('queued','running')", (fingerprint,)).fetchone()
            if row:
                return row['id']
            if c.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0] >= 10:
                raise ValueError('Investigation queue is full')
            job_id = str(uuid4())
            c.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?)', (job_id, fingerprint, 'queued', datetime.now(timezone.utc).isoformat(), json.dumps(payload), '[]', None))
            return job_id

    def list(self):
        with self.connect() as c:
            return [self.decode(row) for row in c.execute('SELECT * FROM jobs ORDER BY created DESC LIMIT 20')]

    def get(self, job_id):
        with self.connect() as c:
            row = c.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            return self.decode(row) if row else None

    def decode(self, row):
        return {**dict(row), 'payload': json.loads(row['payload']), 'events': json.loads(row['events']), 'result': json.loads(row['result']) if row['result'] else None}

    def claim(self):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if row:
                c.execute("UPDATE jobs SET status='running' WHERE id=?", (row['id'],))
                return self.decode(row)

    def event(self, job_id, event):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            events = json.loads(c.execute('SELECT events FROM jobs WHERE id=?', (job_id,)).fetchone()[0])
            c.execute('UPDATE jobs SET events=? WHERE id=?', (json.dumps(events+[event]), job_id))

    def finish(self, job_id, status, result):
        with self.connect() as c:
            c.execute('UPDATE jobs SET status=?,result=? WHERE id=?', (status, json.dumps(result), job_id))
