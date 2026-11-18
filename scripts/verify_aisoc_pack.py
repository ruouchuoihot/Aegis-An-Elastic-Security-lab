"""Verify live native Windows evidence and deduplicated alerts for the new pack."""
import hashlib
import json
import ssl
from pathlib import Path
import httpx
try:
    from .prepare_windows_lab import read_env, ROOT, RUNTIME
except ImportError:
    from prepare_windows_lab import read_env, ROOT, RUNTIME


def main():
    v = read_env()
    rules = [r for r in json.loads((ROOT/'rules/aegis_detection_rules.json').read_text(encoding='utf-8')) if r['id'].startswith('aegis-aisoc-')]
    report = []
    with httpx.Client(base_url='https://localhost:'+v['ES_PORT'],auth=('elastic',v['ELASTIC_PASSWORD']),
                      verify=ssl.create_default_context(cafile=str(RUNTIME/'oem/ca.crt')),timeout=30) as c:
        for rule in rules:
            response = c.post('/logs-aegis.windows-*/_search',json={'size':100,'query':{'bool':{'filter':[
                rule['query_dsl'],{'range':{'@timestamp':{'gte':'now-20m'}}}]}},'sort':[{'@timestamp':'desc'}]})
            response.raise_for_status()
            hits = response.json()['hits']['hits']
            ids = [hashlib.sha256(json.dumps([rule['id'],h['_index'],h['_id']]).encode()).hexdigest() for h in hits]
            alerts = c.post('/'+v.get('AEGIS_ALERT_INDEX','aegis-alerts-default')+'/_mget',json={'ids':ids}) if ids else None
            if alerts is not None:
                alerts.raise_for_status()
            found = [h for h in alerts.json()['docs'] if h.get('found')] if alerts is not None else []
            row = {'rule':rule['name'],'technique':rule['mitre']['technique_id'],
                   'native_events':len(hits),'managed_alerts':len(found),
                   'sample_source': {'index':hits[0]['_index'],'id':hits[0]['_id'],'timestamp':hits[0]['_source']['@timestamp'],
                                     'event_code':hits[0]['_source'].get('event',{}).get('code')} if hits else None}
            report.append(row)
    output = {'verified':all(r['native_events'] and r['managed_alerts'] for r in report),'rules':report}
    (RUNTIME/'share/results/aisoc-pack-verification.json').write_text(json.dumps(output,indent=2),encoding='utf-8')
    print(json.dumps(output,indent=2))
    return 0 if output['verified'] else 1


if __name__=='__main__':
    raise SystemExit(main())
