"""Bounded alert correlation and a durable, hash-linked investigation journal.

Independent implementation inspired by AiSOC's correlation/ledger concepts.
No LLM or response actions are performed by this module.
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def correlate(hits, window_minutes=30):
    groups, skipped = {}, []
    for hit in hits:
        alert = hit["_source"]
        ref = {"index": hit["_index"], "id": hit["_id"]}
        # Detection time must not move historical events into today's incident.
        timestamp = alert.get("source_event", {}).get("timestamp")
        try:
            moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                raise ValueError("Timestamp requires timezone")
        except (AttributeError, TypeError, ValueError):
            skipped.append({**ref, "reason": "missing_or_invalid_source_timestamp"})
            continue
        host = alert.get("host", {})
        entity = host.get("id") or host.get("name") or host.get("hostname")
        entity_field = "host.id" if host.get("id") else "host.name" if host.get("name") else "host.hostname"
        # Missing entities are isolated, never grouped into a shared 'unknown'.
        entity_key = ["host.id" if host.get("id") else "host.name", entity] if entity else ["alert", ref]
        provenance = alert.get("aegis", {}).get("provenance", "unknown")
        bucket = int(moment.timestamp()) // (window_minutes * 60)
        key = digest([entity_key, provenance, bucket, window_minutes])
        group = groups.setdefault(key, {
            "id": key, "entity": entity, "entity_field": entity_field, "provenance": provenance,
            "host_name": host.get("name") or host.get("hostname") or entity,
            "window_minutes": window_minutes, "window_start": datetime.fromtimestamp(
                bucket * window_minutes * 60, timezone.utc).isoformat(),
            "alerts": [], "techniques": [], "severity": "unknown",
        })
        if ref in [item["reference"] for item in group["alerts"]]:
            continue
        severity = alert.get("kibana", {}).get("alert", {}).get("severity", "unknown")
        ranks = {"unknown": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}
        if ranks.get(severity, -1) > ranks.get(group["severity"], -1):
            group["severity"] = severity
        technique = alert.get("threat", {}).get("technique", {}).get("id")
        if technique and technique not in group["techniques"]:
            group["techniques"].append(technique)
        process = alert.get("process", {})
        group["alerts"].append({"reference": ref, "source_event": alert.get("source_event", {}),
                                "siem":alert.get('siem'), "risk_score":alert.get('rule',{}).get('risk_score'),
                                "rule": alert.get("rule", {}), "severity": severity,
                                "observed": {"host_name": host.get("name") or host.get("hostname"),
                                             "process_name": process.get("name"),
                                             "parent_process": process.get("parent", {}).get("name"),
                                             "registry_path": alert.get('registry', {}).get('path'),
                                             "task_command_path": alert.get('aegis', {}).get('task', {}).get('command_path'),
                                             "task_name": alert.get('aegis', {}).get('task', {}).get('name')},
                                "technique": alert.get("threat", {}).get("technique", {})})
    incidents = sorted(groups.values(), key=lambda row: (row["window_start"], row["id"]), reverse=True)
    for incident in incidents:
        incident["alerts"].sort(key=lambda row: (row['source_event']['timestamp'], row["reference"]["index"], row["reference"]["id"]))
        incident["techniques"].sort()
        incident["alert_count"] = len(incident["alerts"])
    return incidents, skipped


def triage(incident):
    return {
        "engine": "deterministic-v1", "model": None, "verdict": "needs_review",
        "priority": incident["severity"], "incident_id": incident["id"],
        "supporting_evidence": [row["reference"] for row in incident["alerts"]],
        "rationale": f"{incident['alert_count']} rule matches on {incident.get('host_name') or incident['entity'] or 'an unidentified host'}. Review the observed activity and its context before deciding whether this needs escalation.",
        "limitations": ["A rule match alone does not establish compromise or malicious intent.",
                         "Time-based grouping does not establish an attack chain.",
                         "Authorization and endpoint corroboration still need review."],
        "response": {"mode": "preview_only", "executed": False,
                     "suggested_checks": ["Review the process, parent process and event time in the source log.",
                                          "Confirm whether this activity was expected on this host."]},
    }


class InvestigationLedger:
    def __init__(self, path):
        self.path = str(path)

    def connect(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE IF NOT EXISTS ledger (seq INTEGER PRIMARY KEY, incident_id TEXT NOT NULL, payload TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL)")
        return conn

    def append(self, incident, decision):
        payload = {"timestamp": datetime.now(timezone.utc).isoformat(),
                   "incident": incident, "decision": decision}
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            last = conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
            seq, previous = (last["seq"] + 1, last["hash"]) if last else (1, "0" * 64)
            entry_hash = digest([seq, incident["id"], previous, payload])
            conn.execute("INSERT INTO ledger VALUES (?, ?, ?, ?, ?)",
                         (seq, incident["id"], json.dumps(payload, ensure_ascii=False), previous, entry_hash))
            conn.commit()
            return {"seq": seq, "previous_hash": previous, "hash": entry_hash, **payload}
        finally:
            conn.close()

    def read(self, incident_id, limit=100):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM ledger WHERE incident_id=? ORDER BY seq DESC LIMIT ?",
                                (incident_id, limit)).fetchall()
            return [{"seq": row["seq"], "previous_hash": row["previous_hash"], "hash": row["hash"],
                     **json.loads(row["payload"])} for row in rows]
        finally:
            conn.close()

    def verify(self):
        conn = self.connect()
        try:
            previous, count = "0" * 64, 0
            for row in conn.execute("SELECT * FROM ledger ORDER BY seq"):
                try:
                    expected = digest([row["seq"], row["incident_id"], previous, json.loads(row["payload"])])
                except (ValueError, TypeError):
                    return {"valid": False, "checked_entries": count, "failed_seq": row["seq"]}
                if row["seq"] != count + 1 or row["previous_hash"] != previous or row["hash"] != expected:
                    return {"valid": False, "checked_entries": count, "failed_seq": row["seq"]}
                previous, count = row["hash"], count + 1
            return {"valid": True, "checked_entries": count, "head_hash": previous}
        finally:
            conn.close()
