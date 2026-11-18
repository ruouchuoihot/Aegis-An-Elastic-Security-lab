"""Native Elastic Security rule definitions and portal projections."""
import os
import json
from urllib.parse import quote


def native_enabled():
    return os.environ.get('AEGIS_NATIVE_SIEM','0') == '1'


def rule_url(identifier):
    return os.environ.get('KIBANA_PUBLIC_URL','http://localhost:5601').rstrip('/') + '/app/security/rules/id/' + quote(identifier,safe='')


def native_threat(mitre):
    identifier=mitre.get('technique_id')
    if not identifier:
        return []
    parent=identifier.split('.')[0]
    names={'T1059':'Command and Scripting Interpreter','T1547':'Boot or Logon Autostart Execution',
           'T1053':'Scheduled Task/Job','T1021':'Remote Services','T1490':'Inhibit System Recovery',
           'T1057':'Process Discovery','T1033':'System Owner/User Discovery','T1082':'System Information Discovery',
           'T1016':'System Network Configuration Discovery','T1140':'Deobfuscate/Decode Files or Information'}
    subs={'T1059.001':'PowerShell','T1547.001':'Registry Run Keys / Startup Folder','T1053.005':'Scheduled Task',
          'T1053.003':'Cron','T1021.002':'SMB/Windows Admin Shares'}
    tactics={'Execution':'TA0002','Persistence':'TA0003','Discovery':'TA0007','Lateral Movement':'TA0008',
             'Impact':'TA0040','Defense Evasion':'TA0005'}
    tactic=mitre.get('tactic','Execution')
    technique={'id':parent,'name':names.get(parent,mitre.get('technique_name',parent)),
               'reference':'https://attack.mitre.org/techniques/'+parent+'/'}
    if '.' in identifier:
        technique['subtechnique']=[{'id':identifier,'name':subs.get(identifier,mitre.get('technique_name',identifier)),
            'reference':'https://attack.mitre.org/techniques/'+identifier.replace('.','/')+'/'}]
    return [{'framework':'MITRE ATT&CK','tactic':{'id':tactics.get(tactic,'TA0002'),'name':tactic,
        'reference':'https://attack.mitre.org/tactics/'+tactics.get(tactic,'TA0002')+'/'},'technique':[technique]}]


def threat_view(threat):
    if not threat:
        return {}
    technique=(threat[0].get('technique') or [{}])[0]
    selected=(technique.get('subtechnique') or [technique])[0]
    return {'tactic':threat[0].get('tactic',{}).get('name'),'technique_id':selected.get('id'),'technique_name':selected.get('name')}


def rule_payload(rule):
    provenance = rule.get('provenance') or {}
    source = provenance.get('repository')
    reference = f"{source}/blob/{provenance['revision']}/{provenance['path']}" if source else None
    payload = {'rule_id':rule['id'], 'name':rule['name'], 'description':rule.get('description') or rule['name'],
               'type':'query','severity':rule.get('severity','low'),'risk_score':rule.get('risk_score',21),
               'index':[rule['index']], 'enabled':rule.get('enabled',True) and rule['index']=='logs-aegis.windows-*',
               'interval':'1m','from':'now-15m','to':'now','max_signals':1000,
               'query':rule.get('query','*'),'language':'lucene' if rule.get('query') else 'kuery',
               'filters':[{'query':rule['query_dsl'],'meta':{'alias':'Detection conditions','disabled':False,'negate':False,
                    'type':'custom','key':'query','value':json.dumps(rule['query_dsl'],separators=(',',':'))}}] if rule.get('query_dsl') else [],
               'tags':['aegis','managed-in-siem'] + ([provenance['pack']] if provenance.get('pack') else []),
               'false_positives':rule.get('false_positives',[]), 'references':[reference] if reference else [],
               'meta':{'aegis':{'provenance':provenance,'mitre':rule.get('mitre',{})}},
               'threat':native_threat(rule.get('mitre',{})),
               'note':'Review endpoint behavior and evidence gaps. Simulator schedules and test-run metadata are not investigation evidence.'}
    return payload


def rule_view(row, original=None):
    original = original or {}
    metadata = row.get('meta',{}).get('aegis',{})
    provenance = metadata.get('provenance') or original.get('provenance')
    return {'id':row['rule_id'], 'name':row['name'], 'description':row.get('description',''),
            'enabled':row['enabled'], 'severity':row['severity'], 'risk_score':row['risk_score'],
            'index':','.join(row.get('index',[])), 'query':row.get('query'), 'filters':row.get('filters',[]),
            'mitre':(threat_view(row.get('threat')) if 'threat' in row else metadata.get('mitre') or original.get('mitre',{})), 'provenance':provenance,
            'siem':{'id':row['id'],'url':rule_url(row['id']),'edit_url':rule_url(row['id'])+'/edit',
                    'updated_at':row.get('updated_at'),'version':row.get('version'), 'execution_summary':row.get('execution_summary')}}
