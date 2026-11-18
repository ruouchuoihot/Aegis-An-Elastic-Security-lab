"""Seed missing native Security rules; never overwrite edits or re-enable existing rules."""
import argparse
import json
import secrets
from pathlib import Path
import httpx
try:
    from .prepare_windows_lab import ROOT, read_env
    from .aegis_siem import rule_payload
except ImportError:
    from prepare_windows_lab import ROOT, read_env
    from aegis_siem import rule_payload


def set_env(values):
    path = ROOT/'.env'
    lines = path.read_text(encoding='utf-8-sig').splitlines()
    for key,value in values.items():
        for index,line in enumerate(lines):
            if line.startswith(key+'='):
                lines[index]=key+'='+value
                break
        else:
            lines.append(key+'='+value)
    path.write_text('\n'.join(lines)+'\n',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--prepare',action='store_true')
    args=parser.parse_args()
    v=read_env()
    if not v.get('AEGIS_KIBANA_ENCRYPTION_KEY'):
        set_env({'AEGIS_KIBANA_ENCRYPTION_KEY':secrets.token_hex(32)})
    if args.prepare:
        print('Persistent Kibana encryption key prepared in ignored .env; no key printed.')
        return
    rules=json.loads((ROOT/'rules/aegis_detection_rules.json').read_text(encoding='utf-8'))
    summary=[]
    with httpx.Client(base_url='http://localhost:'+v.get('KIBANA_PORT','5601'),auth=('elastic',v['ELASTIC_PASSWORD']),
                      headers={'kbn-xsrf':'aegis-native-setup'},timeout=60) as client:
        privileges=client.get('/api/detection_engine/privileges')
        privileges.raise_for_status()
        if not privileges.json().get('has_encryption_key'):
            raise RuntimeError('Restart Kibana with its persistent encryption key before seeding rules.')
        initialized=client.post('/api/detection_engine/index')
        if initialized.is_error:
            raise RuntimeError(f'Security alert index initialization failed: HTTP {initialized.status_code}')
        for rule in rules:
            existing=client.get('/api/detection_engine/rules',params={'rule_id':rule['id']})
            if existing.status_code==404:
                response=client.post('/api/detection_engine/rules',json=rule_payload(rule))
                if response.is_error:
                    raise RuntimeError(f"Rule seed failed for {rule['id']}: HTTP {response.status_code}, {response.text[:1000]}")
                row=response.json();action='created'
            else:
                existing.raise_for_status();row=existing.json();action='preserved'
            summary.append({'rule_id':row['rule_id'],'id':row['id'],'name':row['name'],'enabled':row['enabled'],'action':action})
    set_env({'AEGIS_NATIVE_SIEM':'1'})
    output=ROOT/'lab/runtime/native-siem-rules.json'
    output.write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps({'native_rules':len(summary),'enabled':sum(r['enabled'] for r in summary),'rules':summary},indent=2))


if __name__=='__main__':
    main()
