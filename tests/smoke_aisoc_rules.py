"""Replay raw native-event fixtures through real ES ingest and each adapted rule.

Fixtures are indexed only in a temporary aegis-rule-test-* index, never logs-*.
"""
import json
import ssl
import sys
from pathlib import Path
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import httpx
from scripts.prepare_windows_lab import read_env, RUNTIME, PIPELINE, detection_mappings


def event(code, data, provider='Microsoft-Windows-Sysmon'):
    return {'@timestamp':'2026-11-17T00:00:00Z', 'host':{'name':'fixture-only'},
            'event':{'code':str(code)}, 'winlog':{'provider_name':provider,'event_data':data}}


def fixtures():
    security = 'Microsoft-Windows-Security-Auditing'
    xml = lambda command,args='':f'<Task><Actions><Exec><Command>{command}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>'
    return {
        'encoded-powershell': [
            event(1,{'Image':r'C:\Windows\powershell.exe','CommandLine':'powershell.exe -ENC ZQBjAGgAbwA='}),
            event(1,{'Image':r'C:\Windows\powershell.exe','CommandLine':'powershell.exe -Command Get-Date'})],
        'registry-run-key': [
            event(13,{'TargetObject':r'HKU\S-1-5-18\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater'}),
            event(13,{'TargetObject':r'HKU\S-1-5-18\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\Updater'})],
        'task-suspicious-path': [
            event(4698,{'TaskContent':xml(r'C:\Windows\Temp\updater.cmd')},security),
            event(4698,{'TaskContent':xml(r'C:\Windows\System32\cmd.exe',r'/c C:\Windows\Temp\updater.cmd')},security)],
        'task-encoded-command': [
            event(4698,{'TaskContent':xml('powershell.exe','-EncodedCommand ZQBjAGgAbwA=')},security),
            event(4699,{'TaskContent':xml('powershell.exe','-EncodedCommand ZQBjAGgAbwA=')},security)],
        'certutil-decode': [
            event(1,{'Image':r'C:\Windows\System32\certutil.exe','CommandLine':'certutil.exe -decode input.txt output.txt'}),
            event(1,{'Image':r'C:\Windows\System32\certutil.exe','CommandLine':'certutil.exe -encode input.txt output.txt'})],
    }


def main(provider_type='keyword'):
    v = read_env()
    rules = {r['id']:r for r in json.loads(Path('rules/aegis_detection_rules.json').read_text(encoding='utf-8'))}
    index = 'aegis-rule-test-' + uuid4().hex
    results = []
    with httpx.Client(base_url='https://localhost:'+v['ES_PORT'],auth=('elastic',v['ELASTIC_PASSWORD']),
                      verify=ssl.create_default_context(cafile=str(RUNTIME/'oem/ca.crt')),timeout=30) as c:
        try:
            response = c.put('/'+index,json={'settings':{'index.default_pipeline':PIPELINE,'number_of_replicas':0},
                'mappings':{'properties':{'event':{'properties':{'code':{'type':'keyword'}}},
                    'winlog':{'properties':{'provider_name':({'type':'keyword'} if provider_type=='keyword' else {'type':'text','fields':{'keyword':{'type':'keyword'}}})}},
                    'process':{'properties':{'name':{'type':'keyword'},'command_line':{'type':'wildcard'}}},
                    'aegis':{'properties':detection_mappings()}}}})
            response.raise_for_status()
            for slug, docs in fixtures().items():
                for label, doc in zip(['positive','negative'], docs):
                    response = c.put(f'/{index}/_doc/{slug}-{label}',json=doc)
                    response.raise_for_status()
            c.post('/'+index+'/_refresh').raise_for_status()
            for slug in fixtures():
                rule = rules['aegis-aisoc-'+slug]
                response = c.post('/'+index+'/_search',json={'query':rule['query_dsl'],'size':100})
                response.raise_for_status()
                found = {h['_id'] for h in response.json()['hits']['hits']}
                assert slug+'-positive' in found, (slug,'positive missed',response.text)
                assert slug+'-negative' not in found, (slug,'negative matched',response.text)
                results.append({'rule_id':rule['id'],'positive':True,'negative_rejected':True})
            print(json.dumps({'provider_mapping':provider_type,'passed':len(results),'results':results},indent=2))
        finally:
            assert index.startswith('aegis-rule-test-') and len(index)==len('aegis-rule-test-')+32
            c.delete('/'+index).raise_for_status()
    return results


if __name__=='__main__':
    main()
    main('legacy_text')
