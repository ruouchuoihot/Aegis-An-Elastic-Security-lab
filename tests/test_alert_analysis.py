import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from scripts import aegis_ai_gateway as gateway
from scripts.aegis_investigation import correlate
from scripts.aegis_jobs import Jobs
from test_investigation import hit, SCOPE

class AlertAnalysisTests(unittest.IsolatedAsyncioTestCase):
    async def test_selected_alert_snapshot_and_scope_rejection(self):
        incident=correlate([hit('one'),hit('two')])[0][0]
        result={'incidents':[incident],'coverage':{'partial':False}}
        request=gateway.TriageRequest(**SCOPE,incident_id=incident['id'],alert_id='two')
        with patch.object(gateway,'correlate_alerts',AsyncMock(return_value=result)):
            snapshot,_=await gateway.scoped_incident(request)
            self.assertEqual([a['reference']['id'] for a in snapshot['alerts']],['two'])
            self.assertEqual(snapshot['alert_count'],1)
            self.assertNotEqual(snapshot['id'],incident['id'])
            self.assertEqual(len(incident['alerts']),2)
            request.alert_id='foreign'
            with self.assertRaises(HTTPException) as failure:
                await gateway.scoped_incident(request)
            self.assertEqual(failure.exception.status_code,404)

    async def test_active_alert_dedup_survives_scope_refresh_and_targets_are_public(self):
        incident=correlate([hit('one'),hit('two')])[0][0]
        with tempfile.TemporaryDirectory() as directory:
            queue=Jobs(Path(directory)/'jobs.db')
            with patch.object(gateway,'jobs',queue),patch.object(gateway,'configuration',return_value=('url','key','model')),patch.dict(gateway.detector_state,enabled=True),patch.object(gateway,'correlate_alerts',AsyncMock(return_value={'incidents':[incident],'coverage':{'partial':False}})):
                req=gateway.TriageRequest(**SCOPE,incident_id=incident['id'],alert_id='one')
                first=await gateway.submit_investigation(req)
                req.end=req.end.replace(hour=3)
                self.assertEqual(first,await gateway.submit_investigation(req))
                req.alert_id='two'
                self.assertNotEqual(first,await gateway.submit_investigation(req))
                public=await gateway.get_job(first['job_id'])
                self.assertNotIn('payload',public)
                self.assertEqual(public['target']['reference']['id'],'one')
                self.assertEqual(public['target']['type'],'alert')
