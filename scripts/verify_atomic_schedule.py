"""Check runner observations against ingested Sysmon and managed detection alerts."""
import json
import ssl
from pathlib import Path
import httpx
try:
    from .prepare_windows_lab import read_env, RUNTIME
    from .aegis_context import CATALOG
    from .aegis_ai_gateway import alert_id
except ImportError:
    from prepare_windows_lab import read_env, RUNTIME
    from aegis_context import CATALOG
    from aegis_ai_gateway import alert_id


def main():
    values = read_env()
    root = RUNTIME/'share/results'
    snapshot = json.loads((root/'atomic-schedule.json').read_text(encoding='utf-8-sig'))
    records = [json.loads(p.read_text(encoding='utf-8-sig')) for p in root.glob('atomic-*.json') if p.name != 'atomic-schedule.json']
    records = [r for r in records if r.get('batch_id') == snapshot['batch_id']]
    catalog = json.loads((Path(__file__).resolve().parents[1]/'lab/windows/atomic_catalog.json').read_text(encoding='utf-8'))
    by_case = {case['id']:case for case in catalog}
    rules = {rule['id']:rule for rule in json.loads((Path(__file__).resolve().parents[1]/'rules/aegis_detection_rules.json').read_text(encoding='utf-8'))}
    report = {'batch_id': snapshot['batch_id'], 'schedule_snapshot': snapshot, 'cases': []}
    with httpx.Client(base_url='https://localhost:'+values['ES_PORT'], auth=('elastic',values['ELASTIC_PASSWORD']),
                      verify=ssl.create_default_context(cafile=str(RUNTIME/'oem/ca.crt')), timeout=30) as client:
        for r in records:
            case = by_case.get(r.get('case_id')) or CATALOG[r['test_guid']]
            rule_id = case.get('rule_id') or 'aegis-windows-lab-' + ('process-discovery-tasklist' if case['id']=='process-discovery' else case['id'])
            query = rules[rule_id].get('query_dsl') or {'bool':{'filter':[{'term':{'event.code':'1'}},
                {'terms':{'winlog.record_id':r['sysmon_record_ids']}}, {'terms':{'process.name':case['processes']}}]}}
            response = client.post('/logs-aegis.windows-*/_search', json={'size':100, 'query':{'bool':{'filter':[
                {'range':{'@timestamp':{'gte':r['start'],'lte':r['end']}}},
                {'term':{'host.name':r['computer'].lower()}}, query]}}})
            response.raise_for_status()
            sources = response.json()['hits']['hits']
            observed = bool(sources)
            ids = [alert_id(rule_id,s['_id'],s['_index']) for s in sources]
            alerts = client.post('/'+values.get('AEGIS_ALERT_INDEX','aegis-alerts-default')+'/_mget',json={'ids':ids}) if ids else None
            if alerts is not None:
                alerts.raise_for_status()
            created = sum(d.get('found',False) for d in alerts.json()['docs']) if alerts is not None else 0
            report['cases'].append({'name':case['name'],'technique':case['technique'],'runner_status':r['status'],
                                    'ingested_native_events':len(sources),'native_behavior_observed':observed,'managed_alerts':created})
    report['verified'] = len(records)==len(catalog) and all(c['native_behavior_observed'] and c['managed_alerts'] and c['runner_status']=='process_observed' for c in report['cases'])
    (root/'schedule-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    return 0 if report['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
