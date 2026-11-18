import json
import unittest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from scripts import aegis_ai_gateway as gateway
from scripts.aegis_siem import rule_payload, rule_view
from test_investigation import hit, SCOPE


class NativeRuleTests(unittest.TestCase):
    def test_dsl_is_editable_native_query_with_index_patterns(self):
        rule={'id':'aegis-test','name':'Run key','severity':'high','risk_score':70,'index':'logs-aegis.windows-*',
              'query_dsl':{'term':{'event.code':'13'}}}
        payload=rule_payload(rule)
        self.assertEqual(payload['filters'][0]['query'],rule['query_dsl'])
        self.assertEqual(payload['filters'][0]['meta']['type'],'custom')
        self.assertEqual(payload['index'],['logs-aegis.windows-*'])
        self.assertTrue(payload['enabled'])
        self.assertNotIn('data_view_id',payload)

    def test_siem_edits_override_bootstrap_name_severity_query_enabled_and_mitre(self):
        row={'rule_id':'aegis-test','id':'native-uuid','name':'Edited in SIEM','enabled':False,'severity':'critical',
             'risk_score':95,'query':'process.name:updated.exe','threat':[]}
        view=rule_view(row,{'name':'Bootstrap','severity':'low','query':'old','mitre':{'technique_id':'T1057'}})
        self.assertEqual(view['name'],'Edited in SIEM')
        self.assertEqual(view['severity'],'critical')
        self.assertFalse(view['enabled'])
        self.assertEqual(view['query'],row['query'])
        self.assertEqual(view['mitre'],{})
        self.assertIn('/app/security/rules/id/native-uuid',view['siem']['url'])

    def test_high_counter_counts_alerts_not_incident_groups(self):
        rows=[hit('1'),hit('2'),hit('3')]
        rows[2]['_source']['kibana']['alert']['severity']='low'
        data={'hits':{'hits':rows,'total':{'value':3,'relation':'eq'}}}
        with patch.object(gateway,'GATEWAY_TOKEN',''),patch.object(gateway,'es_request',AsyncMock(return_value=data)):
            with TestClient(gateway.app) as client:
                result=client.post('/tools/incidents/correlate',json=SCOPE).json()
        self.assertEqual(result['incident_count'],1)
        self.assertEqual(result['severity_counts']['high'],2)


class NativeProjectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_projection_preserves_original_event_and_deduplicates_existing_alert_id(self):
        native={'_index':'.internal.alerts-security.alerts-default-000001','_id':'native-alert','_source':{
            '@timestamp':'2026-11-17T01:02:00Z','kibana.alert.ancestors':[{'depth':0,'index':'logs-aegis.windows-default','id':'event-1'}],
            'kibana.alert.rule.rule_id':'aegis-test','kibana.alert.rule.uuid':'rule-uuid','kibana.alert.rule.name':'Native rule',
            'kibana.alert.severity':'high','kibana.alert.risk_score':70,'kibana.alert.rule.parameters':{}}}
        original={'_index':'logs-aegis.windows-default','_id':'event-1','found':True,'_source':{
            '@timestamp':'2026-11-17T01:01:00Z','host':{'name':'host'},'aegis':{'provenance':'endpoint_lab'}}}
        es=AsyncMock(side_effect=[{'hits':{'hits':[native],'total':{'value':1}}},{'docs':[original]}, {},
                                 {'items':[{'update':{'status':201,'result':'created'}}]}])
        with patch.object(gateway,'es_request',es):
            result=await gateway.sync_native_alerts()
        body=es.call_args.kwargs['content'].splitlines()
        self.assertEqual(json.loads(body[0])['update']['_id'],gateway.alert_id('aegis-test','event-1','logs-aegis.windows-default'))
        doc=json.loads(body[1])
        self.assertEqual(doc['upsert']['source_event']['timestamp'],'2026-11-17T01:01:00Z')
        self.assertEqual(doc['doc']['siem']['alert_id'],'native-alert')
        self.assertNotIn('@timestamp',doc['doc'])
        self.assertEqual(result['alerts_created'],1)
