"""Verify guest install, local Atomic observation, ingestion and actual rule match separately."""
import asyncio
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import ssl
import sys

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.prepare_windows_lab import read_env, ROOT, RUNTIME, INDEX


def exact_keyword(field, value):
    # Existing lab indices may have dynamically mapped text + keyword fields.
    return {"bool": {"should": [{"term": {field: value}}, {"term": {field + ".keyword": value}}], "minimum_should_match": 1}}


def fetch_status_records(directory):
    """Fall back to the same Windows event collector if SMB guest sharing is unavailable."""
    values = read_env()
    with httpx.Client(base_url=f"https://localhost:{values.get('ES_PORT', '9200')}",
                      auth=("elastic", values["ELASTIC_PASSWORD"]),
                      verify=ssl.create_default_context(cafile=str(RUNTIME / "oem" / "ca.crt")), timeout=30) as client:
        response = client.post(f"/{INDEX}/_search", json={"size": 20, "sort": [{"@timestamp": "desc"}],
            "query": exact_keyword("winlog.provider_name", "AegisLab")})
        if response.status_code == 404:
            return
        response.raise_for_status()
        for hit in response.json().get("hits", {}).get("hits", []):
            source = hit["_source"]
            candidates = [source.get("message", ""), *source.get("winlog", {}).get("event_data", {}).values()]
            record = None
            for text in candidates:
                if not isinstance(text, str) or "{" not in text:
                    continue
                try:
                    record, _ = json.JSONDecoder().raw_decode(text[text.index("{"):])
                    break
                except ValueError:
                    continue
            if not isinstance(record, dict):
                continue
            if str(source.get("event", {}).get("code")) == "100":
                path = directory / "bootstrap-result.json"
                previous = json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else {}
                if record.get("time", "") > previous.get("time", ""):
                    path.write_text(json.dumps(record))
            run_id = record.get("run_id", "")
            if str(source.get("event", {}).get("code")) == "101" and len(run_id) == 36 and all(ch in "0123456789abcdef-" for ch in run_id):
                path = directory / f"atomic-{run_id}.json"
                if not path.exists():
                    path.write_text(json.dumps(record))


def main():
    result = {"guest_install": "not_verified", "atomic_execution": "not_verified",
              "ingestion": "not_verified", "detection": "not_verified"}
    directory = RUNTIME / "share" / "results"
    directory.mkdir(parents=True, exist_ok=True)
    fetch_status_records(directory)
    bootstrap = directory / "bootstrap-result.json"
    if bootstrap.exists():
        record = json.loads(bootstrap.read_text(encoding="utf-8-sig"))
        result["guest_install"] = record.get("status", "unknown")
        if record.get("status") == "failed":
            print(json.dumps(result, indent=2))
            print("Guest bootstrap failed; inspect lab/runtime/share/results/bootstrap.log locally.")
            return 1
    runs = sorted(directory.glob("atomic-*.json"), key=lambda p: json.loads(p.read_text(encoding="utf-8-sig")).get("start", ""), reverse=True)
    if not runs:
        print(json.dumps(result, indent=2))
        print("No guest Atomic run record yet. Installation may still be in progress.")
        return 2
    run = json.loads(runs[0].read_text(encoding="utf-8-sig"))
    result["run_id"] = run["run_id"]
    result["atomic_execution"] = run["status"]
    if not run.get("sysmon_record_ids"):
        print(json.dumps(result, indent=2))
        return 2
    values = read_env()
    os.environ.update({"ES_URL": f"https://localhost:{values.get('ES_PORT', '9200')}",
                       "ES_USER": "elastic", "ES_PASSWORD": values["ELASTIC_PASSWORD"],
                       "CA_CERT": str(RUNTIME / "oem" / "ca.crt")})
    context = ssl.create_default_context(cafile=os.environ["CA_CERT"])
    with httpx.Client(base_url=os.environ["ES_URL"], auth=("elastic", values["ELASTIC_PASSWORD"]), verify=context, timeout=30) as client:
        query = {"bool": {"filter": [
            {"terms": {"winlog.record_id": run["sysmon_record_ids"]}},
            exact_keyword("winlog.provider_name", "Microsoft-Windows-Sysmon"),
            {"term": {"event.code": "1"}}, {"term": {"process.name": "tasklist.exe"}},
            {"range": {"@timestamp": {"gte": run["start"], "lte": (datetime.fromisoformat(run["end"]) + timedelta(seconds=30)).isoformat()}}},
            {"bool": {"should": [{"term": {field: name}} for field in ["host.name", "host.hostname", "winlog.computer_name"] for name in [run["computer"], run["computer"].lower()]], "minimum_should_match": 1}},
        ]}}
        response = client.post(f"/{INDEX}/_search", json={"size": 100, "query": query})
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
        if not hits:
            print(json.dumps(result, indent=2))
            print("Local Sysmon records exist, but no corresponding events were found in Elasticsearch yet.")
            return 2
        result["ingestion"] = "verified"
        result["source_events"] = [{"index": h["_index"], "id": h["_id"], "record_id": h["_source"]["winlog"]["record_id"]} for h in hits]
        from scripts import aegis_ai_gateway as gateway
        async def detect():
            return await gateway.run_detection_rules(gateway.RuleRunRequest(rule_ids=["aegis-windows-lab-process-discovery-tasklist"], size=1000))
        detection = asyncio.run(detect())
        if detection["results"] and detection["results"][0]["matches"]:
            client.post(f"/{gateway.ALERT_INDEX}/_refresh").raise_for_status()
            expected = [gateway.alert_id("aegis-windows-lab-process-discovery-tasklist", h["_id"], h["_index"]) for h in hits]
            alerts = client.post(f"/{gateway.ALERT_INDEX}/_mget", json={"ids": expected})
            alerts.raise_for_status()
            if all(row.get("found") and row["_source"].get("aegis", {}).get("provenance") == "endpoint_lab" for row in alerts.json()["docs"]):
                result["detection"] = "verified"
                result["alert_ids"] = expected
    (directory / "verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["detection"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
