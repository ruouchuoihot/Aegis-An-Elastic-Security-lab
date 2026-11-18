import json
import unittest
from unittest.mock import AsyncMock, patch
from scripts.aegis_agent import endpoint_context, investigate
from scripts.aegis_investigation import correlate
from scripts import aegis_ai_gateway as gateway
from test_investigation import hit, SCOPE


class TelemetryContextTests(unittest.IsolatedAsyncioTestCase):
    def context(self):
        return {'lab_runs':[{'run_id':'SIMULATOR_SECRET'}], 'schedule':{'name':'SIMULATOR_SECRET'},
                'evidence':[{'evidence_id':'logs-test:1','event':{'process':{'name':'whoami.exe'}}},
                            {'evidence_id':'runner:1','recorded_lab_run':{'name':'SIMULATOR_SECRET'}},
                            {'evidence_id':'runner:2','event':{'winlog':{'provider_name':'AegisLab'}}}]}

    def test_context_excludes_simulator_records_and_metadata(self):
        context = endpoint_context(self.context())
        self.assertEqual([r['evidence_id'] for r in context['evidence']], ['logs-test:1'])
        self.assertNotIn('SIMULATOR_SECRET',json.dumps(context))
        self.assertNotIn('AegisLab',json.dumps(context))

    async def test_legacy_agent_never_supplies_runner_metadata_even_via_context_tool(self):
        incident = correlate([hit()])[0][0]
        messages_seen = []
        async def complete(messages, tools):
            messages_seen.append(json.dumps(messages))
            if len(messages_seen)==1:
                return {'choices':[{'message':{'tool_calls':[{'id':'call1','function':{'name':'read_host_context','arguments':'{}'}}]}}]}
            return {'choices':[{'message':{'content':json.dumps({'assessment':'inconclusive','summary':'Review endpoint behavior.',
                'evidence_ids':['logs-test:1'],'missing_evidence':[],'recommended_checks':[]})}}]}
        with patch.dict('os.environ',{'AEGIS_LLM_BASE_URL':'http://test/v1','AEGIS_LLM_MODEL':'test'}):
            result = await investigate(incident,AsyncMock(return_value=self.context()),complete)
        self.assertEqual(result['agent_status'],'completed')
        self.assertEqual(result['analysis_policy'],'telemetry-only-v1')
        self.assertNotIn('SIMULATOR_SECRET',''.join(messages_seen))

    async def test_gateway_does_not_query_runner_markers_and_filters_them_from_context(self):
        incident = correlate([hit(provenance='endpoint_lab')])[0][0]
        request = gateway.TriageRequest(**SCOPE,incident_id=incident['id'])
        es = AsyncMock(side_effect=[{'docs':[]},{'hits':{'hits':[
            {'_index':'logs-test','_id':'runner','_source':{'winlog':{'provider_name':'AegisLab'}}}],
            'total':{'value':1,'relation':'eq'}}}])
        with patch.object(gateway,'es_request',es):
            context = await gateway.collect_incident_context(incident,request)
        self.assertEqual(es.await_count,2)
        self.assertEqual(context['evidence'],[])
        self.assertNotIn('lab_runs',context)
        query = es.call_args.kwargs['json']['query']['bool']
        self.assertIn({'term':{'winlog.provider_name':'AegisLab'}},query['must_not'])
