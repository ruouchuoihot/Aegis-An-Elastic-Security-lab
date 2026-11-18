import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from scripts import aegis_ai_gateway as gateway
from scripts.aegis_investigation import InvestigationLedger, correlate, triage


def hit(identifier="1", host="host-a", timestamp="2026-11-17T01:01:00Z", provenance="synthetic"):
    return {"_id": identifier, "_index": "aegis-alerts-default", "_source": {
        "source_event": {"timestamp": timestamp, "index": "logs-test", "id": identifier},
        "host": {"name": host} if host else {},
        "aegis": {"provenance": provenance}, "rule": {"id": "r1"},
        "kibana": {"alert": {"severity": "high"}},
        "threat": {"technique": {"id": "T1490"}},
    }}


SCOPE = {"start": "2026-11-17T01:00:00Z", "end": "2026-11-17T02:00:00Z"}


class CorrelationTests(unittest.TestCase):
    def test_grouping_isolation_and_evidence(self):
        rows = [hit(), hit("2"), hit("3", "host-b"), hit("4", provenance="unknown"),
                hit("5", timestamp="2026-11-17T01:31:00Z"), hit("6", host=None), hit("7", host=None)]
        incidents, skipped = correlate(rows)
        self.assertEqual(len(incidents), 6)
        self.assertEqual(skipped, [])
        group = next(i for i in incidents if i["alert_count"] == 2)
        decision = triage(group)
        self.assertEqual(len(decision["supporting_evidence"]), 2)
        self.assertEqual(decision["verdict"], "needs_review")
        self.assertFalse(decision["response"]["executed"])

    def test_invalid_time_skipped_and_order_stable(self):
        rows = [hit(), hit("2"), hit("3", timestamp=None)]
        forward, skipped = correlate(rows)
        backward, _ = correlate(list(reversed(rows)))
        self.assertEqual(forward, backward)
        self.assertEqual(len(skipped), 1)
        self.assertEqual(len(correlate([hit(), hit()])[0][0]["alerts"]), 1)

    def test_event_identity_includes_index(self):
        self.assertNotEqual(gateway.alert_id("rule", "1", "logs-a"), gateway.alert_id("rule", "1", "logs-b"))


class LedgerTests(unittest.TestCase):
    def test_restart_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.sqlite3"
            incident = correlate([hit()])[0][0]
            ledger = InvestigationLedger(path)
            ledger.append(incident, triage(incident))
            restarted = InvestigationLedger(path)
            restarted.append(incident, triage(incident))
            self.assertEqual(restarted.verify()["checked_entries"], 2)
            self.assertEqual(len(restarted.read(incident["id"])), 2)
            with sqlite3.connect(path) as conn:
                conn.execute("UPDATE ledger SET payload=? WHERE seq=1", (json.dumps({"changed": True}),))
            conn.close()
            self.assertFalse(restarted.verify()["valid"])


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.ledger_patch = patch.object(gateway, "ledger", InvestigationLedger(Path(self.directory.name) / "ledger.db"))
        self.ledger_patch.start()
        self.token_patch = patch.object(gateway, "GATEWAY_TOKEN", "test-token")
        self.token_patch.start()
        self.client = TestClient(gateway.app)
        self.headers = {"Authorization": "Bearer test-token"}

    def tearDown(self):
        self.client.close()
        self.ledger_patch.stop()
        self.token_patch.stop()
        self.directory.cleanup()

    def post(self, path, payload):
        return self.client.post(path, json=payload, headers=self.headers)

    def test_auth_validation_and_no_path_injection(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/assets/app.js").status_code, 200)
        self.assertEqual(self.client.get("/mcp/tools").status_code, 401)
        self.assertEqual(self.post("/tools/search", {"query": "*", "size": 0}).status_code, 422)
        self.assertEqual(self.post("/tools/search", {"query": "*", "index": "logs-*/../../_security"}).status_code, 422)
        self.assertEqual(self.post("/tools/incidents/correlate", {**SCOPE, "start": "2026-11-17T01:00:00"}).status_code, 422)

    def test_investigation_fallback_is_saved_and_transport_error_is_clear(self):
        incident = correlate([hit()])[0][0]
        data = {"hits": {"hits": [hit()], "total": {"value": 1, "relation": "eq"}}}
        with patch.dict("os.environ", {"AEGIS_LLM_MODEL": ""}), patch.object(gateway, "es_request", AsyncMock(return_value=data)):
            result = self.post("/tools/incidents/investigate", {**SCOPE, "incident_id": incident["id"]})
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()["decision"]["agent_status"], "not_configured")
            self.assertEqual(gateway.ledger.verify()["checked_entries"], 1)
        import httpx
        with patch.object(gateway, "es_request", AsyncMock(side_effect=httpx.ConnectError("unavailable"))):
            self.assertEqual(self.post("/tools/incidents/correlate", SCOPE).status_code, 503)

    def test_rest_and_mcp_investigation_roundtrip(self):
        data = {"hits": {"hits": [hit(), hit("2")], "total": {"value": 2, "relation": "eq"}}}
        with patch.object(gateway, "es_request", AsyncMock(return_value=data)) as es:
            result = self.post("/tools/incidents/correlate", SCOPE)
            self.assertEqual(result.status_code, 200)
            incident = result.json()["incidents"][0]
            result = self.post("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                        "params": {"name": "triage_incident", "arguments": {**SCOPE, "incident_id": incident["id"]}}})
            self.assertNotIn("error", result.json())
            entry = json.loads(result.json()["result"]["content"][0]["text"])
            self.assertEqual(entry["decision"]["engine"], "deterministic-v1")
            self.assertEqual(entry["incident"]["alert_count"], 2)
            self.assertIn("source_event.timestamp", es.call_args.kwargs["json"]["query"]["range"])
        saved = self.client.get(f"/tools/incidents/{incident['id']}/ledger", headers=self.headers).json()
        self.assertEqual(len(saved["entries"]), 1)
        self.assertTrue(self.client.get("/tools/ledger/verify", headers=self.headers).json()["valid"])

    def test_partial_results_cannot_be_triaged(self):
        incident = correlate([hit()])[0][0]
        for extra in [{"hits": {"hits": [hit()], "total": {"value": 2, "relation": "eq"}}},
                      {"hits": {"hits": [hit()], "total": {"value": 1, "relation": "eq"}}, "timed_out": True},
                      {"hits": {"hits": [hit()], "total": {"value": 1, "relation": "eq"}}, "_shards": {"failed": 1}}]:
            with patch.object(gateway, "es_request", AsyncMock(return_value=extra)):
                self.assertEqual(self.post("/tools/incidents/triage", {**SCOPE, "incident_id": incident["id"]}).status_code, 409)
        self.assertEqual(gateway.ledger.verify()["checked_entries"], 0)

    def test_rule_dry_run_is_read_only(self):
        with patch.object(gateway, "es_request", AsyncMock(return_value={"hits": {"hits": []}})) as es:
            self.assertEqual(self.post("/tools/rules/run", {"create_alerts": False}).status_code, 200)
            self.assertTrue(all(call.args[1].endswith("/_search") for call in es.call_args_list))

    def test_alert_feed_uses_evidence_time_and_rejects_partial_bounds(self):
        with patch.object(gateway, "es_request", AsyncMock(return_value={"hits": {"hits": [], "total": {"value": 0}}})) as es:
            self.assertEqual(self.post("/tools/alerts", {**SCOPE, "size": 20}).status_code, 200)
            filters = es.call_args.kwargs["json"]["query"]["bool"]["filter"]
            self.assertEqual(filters[1]["range"]["source_event.timestamp"]["lt"], "2026-11-17T02:00:00+00:00")
        self.assertEqual(self.post("/tools/alerts", {"start": SCOPE["start"]}).status_code, 422)

    def test_agent_context_query_is_projected_and_scoped(self):
        incident = correlate([hit()])[0][0]
        data = {"hits": {"hits": [hit()], "total": {"value": 1, "relation": "eq"}}}
        async def inspect_context(selected, read_context):
            context = await read_context()
            self.assertEqual(context["limit"], 20)
            return triage(selected)
        with patch.object(gateway, "es_request", AsyncMock(return_value=data)) as es, patch.object(gateway, "investigate", inspect_context):
            result = self.post("/tools/incidents/investigate", {**SCOPE, "incident_id": incident["id"]})
            self.assertEqual(result.status_code, 200)
            self.assertEqual(es.call_args.args[1], "/logs-*/_search")
            payload = es.call_args.kwargs["json"]
            self.assertEqual(payload["size"], 20)
            self.assertNotIn("process.command_line", payload["_source"])
            self.assertNotIn("message", payload["_source"])
            filters = payload["query"]["bool"]["filter"]
            self.assertEqual(filters[0]["range"]["@timestamp"]["gte"], "2026-11-17T01:00:00+00:00")
            self.assertEqual(filters[1]["bool"]["should"][0], {"term": {"host.name": "host-a"}})

    def test_detection_conflicts_preserve_existing_alert_and_failures_surface(self):
        rule = {"id": "r", "name": "test", "query": "*"}
        event = {"_id": "1", "_index": "logs-aegis-simulation-default", "_source": {"@timestamp": "2026-11-17T01:00:00Z"}}
        for status, expected in [(201, 200), (409, 200), (403, 502)]:
            responses = [{}, {"hits": {"hits": [event]}}, {"items": [{"create": {"status": status, "result": "created" if status == 201 else None}}]}]
            with patch.object(gateway, "load_rules", return_value=[rule]), patch.object(gateway, "es_request", AsyncMock(side_effect=responses)) as es:
                self.assertEqual(self.post("/tools/rules/run", {}).status_code, expected)
                body = es.call_args.kwargs["content"].splitlines()
                self.assertIn("create", json.loads(body[0]))
                self.assertEqual(json.loads(body[1])["aegis"]["provenance"], "synthetic")


if __name__ == "__main__":
    unittest.main()
