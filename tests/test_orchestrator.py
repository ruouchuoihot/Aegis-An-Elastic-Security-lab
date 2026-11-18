import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from scripts.aegis_jobs import Jobs
from scripts.aegis_orchestrator import orchestrate


class JobTests(unittest.TestCase):
    def test_dedup_claim_restart_and_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Jobs(Path(tmp)/'jobs.db')
            first = jobs.submit('same-evidence', {'incident': 1})
            self.assertEqual(first, jobs.submit('same-evidence', {'incident': 1}))
            self.assertEqual(jobs.claim()['id'], first)
            self.assertIsNone(jobs.claim())
            jobs.event(first, {'stage': 'Analyst', 'status': 'running'})
            jobs.recover()
            self.assertEqual(jobs.get(first)['status'], 'interrupted')
            self.assertEqual(len(jobs.get(first)['events']), 1)
            self.assertNotEqual(first, jobs.submit('same-evidence', {'incident': 1}))


class OrchestratorTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, assessments, bad_ref=False):
        incident = {'id':'abc','entity':'h','host_name':'lab','severity':'low','alert_count':1,'provenance':'endpoint_lab',
                    'alerts':[{'reference':{'index':'alerts','id':'a'}, 'source_event':{'index':'logs','id':'b'},
                               'rule':{'id':'discovery'}, 'severity':'low'}]}
        calls = []
        async def complete(messages, tools):
            index = len(calls); calls.append(messages)
            await asyncio.sleep(0)
            result = {'assessment': assessments[index], 'summary':'Observed discovery; review authorization.',
                      'evidence_ids':['invented' if bad_ref else 'alerts:a'], 'missing_evidence':[], 'recommended_checks':[]}
            return {'choices':[{'message':{'content':json.dumps(result)}}], 'model':'test', 'usage':{'total_tokens':12}}
        events = []
        async def emit(event): events.append(event)
        result = await orchestrate(incident, {'evidence':[{'evidence_id':'runner:1','recorded_lab_run':{'test':'SIMULATOR_SECRET'}}],
                                             'lab_runs':[{'run_id':'SIMULATOR_SECRET'}]}, emit, complete)
        return result, calls, events

    async def test_parallel_reviews_disagree_and_report_cannot_override_join(self):
        result, calls, events = await self.run_case(['likely_benign','suspicious','suspicious'])
        self.assertEqual(len(calls),3)
        self.assertEqual(result['assessment'],'inconclusive')
        self.assertTrue(result['disagreement'])
        running = [e['stage'] for e in events if e['status']=='running']
        self.assertEqual(running[:2],['Detection analyst','Evidence critic'])
        self.assertNotIn('SIMULATOR_SECRET',json.dumps(calls))
        self.assertNotIn('lab_runs',json.dumps(calls))
        self.assertNotIn('Lab correlation',[e['stage'] for e in events])
        self.assertEqual(result['analysis_policy'],'telemetry-only-v1')

    async def test_unknown_references_fail_without_report_call(self):
        result, calls, _ = await self.run_case(['suspicious','suspicious','suspicious'], True)
        self.assertEqual(len(calls),3)
        self.assertEqual(result['agent_status'],'failed')
        self.assertEqual(result['assessment'],'inconclusive')

    async def test_truncated_output_gets_one_bounded_repair_with_short_references(self):
        incident = {'id':'abc','entity':'h','host_name':'host','severity':'low','alert_count':1,'provenance':'endpoint_lab',
                    'alerts':[{'reference':{'index':'alerts','id':'a'},'source_event':{'index':'logs','id':'b'},
                               'rule':{'id':'discovery'},'severity':'low'}]}
        calls, events = [], []
        async def complete(messages, tools):
            calls.append(messages)
            if len(calls)==1:
                return {'choices':[{'finish_reason':'length','message':{'content':'{"summary":"unfinished'}}]}
            return {'choices':[{'finish_reason':'stop','message':{'content':json.dumps({'assessment':'inconclusive',
                'summary':'Discovery observed. Check related activity.','evidence_ids':['E1'],
                'missing_evidence':[],'recommended_checks':[]})}}]}
        async def emit(event): events.append(event)
        result = await orchestrate(incident,{'evidence':[]},emit,complete)
        self.assertEqual(len(calls),4)
        self.assertEqual(result['agent_status'],'completed')
        self.assertEqual(result['evidence_ids'],['alerts:a'])
        self.assertEqual(len([e for e in events if e['status']=='repairing']),1)
