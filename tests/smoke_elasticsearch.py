"""Opt-in integration check against a disposable Elasticsearch container.

Run: python tests/smoke_elasticsearch.py
Uses no Aegis volumes or local credentials. Removes only its own container.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, stderr=subprocess.STDOUT).strip()


def main():
    name = "aegis-smoke-" + uuid.uuid4().hex[:12]
    container = None
    try:
        container = docker("run", "-d", "--name", name, "--memory", "1g",
                           "-p", "127.0.0.1::9200", "-e", "discovery.type=single-node",
                           "-e", "xpack.security.enabled=false", "-e", "ES_JAVA_OPTS=-Xms512m -Xmx512m",
                           "docker.elastic.co/elasticsearch/elasticsearch:8.12.0")
        port = docker("port", container, "9200/tcp").rsplit(":", 1)[1]
        url = f"http://127.0.0.1:{port}"
        ready = False
        for attempt in range(90):
            try:
                ready = httpx.get(url, timeout=2).status_code == 200
            except httpx.HTTPError:
                pass
            if ready:
                break
            if attempt % 15 == 0:
                print("Waiting for disposable Elasticsearch...", flush=True)
            time.sleep(2)
        if not ready:
            raise RuntimeError("Elasticsearch did not become ready")
        os.environ["ES_URL"] = url
        os.environ["AEGIS_GATEWAY_TOKEN"] = "smoke-token"
        os.environ["AEGIS_ALERT_INDEX"] = "aegis-smoke-alerts"
        from fastapi.testclient import TestClient
        from scripts import aegis_ai_gateway as gateway
        from scripts.aegis_investigation import InvestigationLedger
        from scripts.aegis_simulator import SCENARIOS
        with tempfile.TemporaryDirectory() as directory:
            gateway.ledger = InvestigationLedger(Path(directory) / "ledger.db")
            with TestClient(gateway.app, headers={"Authorization": "Bearer smoke-token"}) as client:
                def post(path, payload):
                    response = client.post(path, json=payload)
                    response.raise_for_status()
                    return response.json()

                events = [event for scenario in SCENARIOS for event in scenario()]
                for i, event in enumerate(events):
                    event["@timestamp"] = "2026-11-17T01:01:00Z"
                    event["aegis"] = {"synthetic": True}
                    response = httpx.put(f"{url}/logs-aegis-simulation-smoke/_doc/{i}?op_type=create", json=event)
                    if response.status_code >= 300:
                        raise RuntimeError(response.text)
                    response.raise_for_status()
                httpx.post(f"{url}/logs-aegis-simulation-smoke/_refresh").raise_for_status()
                first = post("/tools/rules/run", {})
                assert sum(row["alerts_created"] for row in first["results"]) == 4, first
                second = post("/tools/rules/run", {})
                assert sum(row["alerts_created"] for row in second["results"]) == 0, second
                httpx.post(f"{url}/aegis-smoke-alerts/_refresh").raise_for_status()
                scope = {"start": "2026-11-17T01:00:00Z", "end": "2026-11-17T02:00:00Z"}
                result = post("/tools/incidents/correlate", scope)
                assert result["incident_count"] == 3, result
                assert result["coverage"]["partial"] is False, result
                assert all(row["provenance"] == "synthetic" for row in result["incidents"])
                incident = next(row for row in result["incidents"] if row["alert_count"] == 2)
                entry = post("/tools/incidents/triage", {**scope, "incident_id": incident["id"]})
                assert len(entry["decision"]["supporting_evidence"]) == 2, entry
                saved = client.get(f"/tools/incidents/{incident['id']}/ledger").json()
                assert len(saved["entries"]) == 1, saved
                assert client.get("/tools/ledger/verify").json()["valid"]
                print(json.dumps({"result": "PASS", "events": len(events), "alerts": 4,
                                  "incidents": 3, "repeat_alerts_created": 0,
                                  "ledger_verified": True}), flush=True)
            if "--serve" in sys.argv:
                import uvicorn
                print("Disposable smoke console: http://127.0.0.1:18081 (token: smoke-token)", flush=True)
                uvicorn.run(gateway.app, host="127.0.0.1", port=18081)
    finally:
        if container:
            docker("rm", "-f", container)


if __name__ == "__main__":
    main()
