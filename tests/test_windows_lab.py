import unittest
from unittest.mock import AsyncMock, patch

from scripts import aegis_ai_gateway as gateway
from fastapi.testclient import TestClient


class WindowsLabTests(unittest.TestCase):
    def test_real_lab_provenance_and_synthetic_isolation(self):
        rule = {"id": "r", "name": "tasklist"}
        hit = {"_id": "event-1", "_index": "logs-aegis.windows-default", "_source": {
            "@timestamp": "2026-11-17T00:00:00Z", "aegis": {"provenance": "endpoint_lab", "synthetic": False}}}
        self.assertEqual(gateway.build_alert(rule, hit)["aegis"]["provenance"], "endpoint_lab")
        hit["_source"]["aegis"]["synthetic"] = True
        self.assertEqual(gateway.build_alert(rule, hit)["aegis"]["provenance"], "synthetic")
        hit["_source"]["aegis"] = {}
        self.assertEqual(gateway.build_alert(rule, hit)["aegis"]["provenance"], "unknown")

    def test_rule_search_allows_optional_indices(self):
        rules = [{"id": "windows", "name": "windows", "index": "logs-aegis.windows-*", "query": "*"}]
        with patch.object(gateway, "load_rules", return_value=rules), patch.object(gateway, "GATEWAY_TOKEN", ""), patch.object(gateway, "es_request", AsyncMock(return_value={"hits": {"hits": []}})) as es:
            with TestClient(gateway.app) as client:
                result = client.post("/tools/rules/run", json={"create_alerts": False})
                self.assertEqual(result.status_code, 200)
            self.assertEqual(es.call_args.kwargs["params"]["allow_no_indices"], "true")

    def test_adapted_rule_executes_dsl_without_query_string_conversion(self):
        dsl = {'bool':{'filter':[{'term':{'event.code':'13'}}]}}
        rules = [{'id':'aisoc-run','name':'Run key','index':'logs-aegis.windows-*','query_dsl':dsl}]
        with patch.object(gateway,'load_rules',return_value=rules), patch.object(gateway,'GATEWAY_TOKEN',''), patch.object(gateway,'es_request',AsyncMock(return_value={'hits':{'hits':[]}})) as es:
            with TestClient(gateway.app) as client:
                result = client.post('/tools/rules/run',json={'create_alerts':False})
                self.assertEqual(result.status_code,200)
            self.assertEqual(es.call_args.kwargs['json']['query'],dsl)
