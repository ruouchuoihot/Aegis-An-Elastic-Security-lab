"""Reproducible, reviewed adaptations of five native AiSOC endpoint rules."""
import argparse
import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
REVISION = '2a0d550165b9f82108a3fe1c487c44aa96ed1b24'
PACK = 'aisoc-windows-v1'


def wildcard(field, value):
    return {'wildcard': {field: {'value': value.replace('\\','\\\\'), 'case_insensitive': True}}}


def either(*clauses):
    return {'bool': {'should': list(clauses), 'minimum_should_match': 1}}


def all_of(*clauses):
    return {'bool': {'filter': list(clauses)}}


def provider(name):
    # The original index predates the current template and uses text + keyword.
    return either({'term':{'winlog.provider_name':name}}, {'term':{'winlog.provider_name.keyword':name}})


def process(name, *conditions):
    return all_of(provider('Microsoft-Windows-Sysmon'),
                  {'term': {'event.code': '1'}}, {'term': {'process.name': name}}, *conditions)


def adaptations():
    return [
        ('powershell-encoded-command.yaml', 'encoded-powershell', 'Encoded PowerShell execution', 'medium',
         'T1059.001', 'Execution', process('powershell.exe', either(*[
             wildcard('process.command_line', f'* {flag} *') for flag in ['-e','-en','-enc','-encodedcommand']])),
         'Broadened from upstream encoded + execution-policy bypass to encoded execution alone, including supported short flags. Severity lowered to medium.'),
        ('registry-runkey-write.yaml', 'registry-run-key', 'Registry Run key value set', 'high',
         'T1547.001', 'Persistence', all_of(provider('Microsoft-Windows-Sysmon'),
             {'term': {'event.code':'13'}}, {'terms': {'aegis.registry.key': [
                 r'hklm\software\microsoft\windows\currentversion\run',
                 r'hkcu\software\microsoft\windows\currentversion\run',
                 r'hklm\software\microsoft\windows\currentversion\runonce']}}),
         'RegistryValueSet maps to Sysmon 13. Sysmon HKU\\SID roots normalize to HKCU; value name is removed before comparing the exact parent key.'),
        ('scheduled-task-create-suspicious.yaml', 'task-suspicious-path', 'Scheduled task action in writable directory', 'high',
         'T1053.005', 'Persistence', all_of({'term':{'event.code':'4698'}},
             provider('Microsoft-Windows-Security-Auditing'), either(*[
                 wildcard('aegis.task.command_path', path+'\\*') for path in [r'C:\Users\Public',r'C:\ProgramData',r'C:\Windows\Temp']])),
         'ScheduledTaskCreate maps to Security 4698; action Command is extracted from TaskContent XML. Task creation is distinct from action execution.'),
        ('win-task-runs-encoded-powershell.yaml', 'task-encoded-command', 'Scheduled task contains encoded PowerShell command', 'high',
         'T1053.005', 'Execution', all_of({'term':{'event.code':'4698'}},
             provider('Microsoft-Windows-Security-Auditing'),
             wildcard('aegis.task.command','*-encodedcommand*')),
         'Upstream task_command maps to combined action Command + Arguments from Security 4698 TaskContent XML. This detects task configuration, not proof of execution.'),
        ('win-certutil-decode.yaml', 'certutil-decode', 'Certutil decode or URL cache operation', 'high',
         'T1140', 'Defense Evasion', process('certutil.exe', either(*[
             wildcard('process.command_line','*'+value+'*') for value in ['-decode','-decodehex','-urlcache -split -f']])),
         'Sysmon event_id/process_name/process_command_line map to event.code/process.name/process.command_line. Upstream URL-cache branch is retained; a match does not prove decoding or execution succeeded.'),
    ]


def build(reference):
    rules = []
    for filename, slug, title, severity, technique, tactic, query, note in adaptations():
        path = 'detections/endpoint/' + filename
        source = yaml.safe_load((reference/path).read_text(encoding='utf-8'))
        rules.append({'id':'aegis-aisoc-'+slug, 'name':'AiSOC: '+title, 'enabled':True,
            'description':note, 'severity':severity, 'risk_score':70 if severity=='high' else 50,
            'index':'logs-aegis.windows-*', 'query_dsl':query,
            'mitre':{'tactic':tactic,'technique_id':technique,'technique_name':title},
            'false_positives':source.get('false_positives',[]),
            'provenance':{'pack':PACK,'repository':'https://github.com/beenuar/AiSOC','revision':REVISION,
                          'path':path,'upstream_id':source['id'],'upstream_name':source['name'],
                          'upstream_severity':source['severity'],'license':'MIT','adaptation':note}})
    return rules


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reference',type=Path,default=ROOT/'rules/upstream/aisoc')
    args = parser.parse_args()
    path = ROOT/'rules/aegis_detection_rules.json'
    existing = json.loads(path.read_text(encoding='utf-8'))
    generated = build(args.reference)
    existing = [r for r in existing if r.get('provenance',{}).get('pack') != PACK]
    path.write_text(json.dumps(existing+generated,indent=2)+'\n',encoding='utf-8')
    print(f'Installed {len(generated)} adapted native AiSOC rules; kept {len(existing)} existing rules.')


if __name__=='__main__':
    main()
