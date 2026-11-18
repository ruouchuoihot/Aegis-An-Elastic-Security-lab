"""Stage only the guest bootstrap and a restricted telemetry key; never execute tests on the host."""
import argparse
import json
import os
from pathlib import Path
import secrets
import re
import shutil
import ssl
import subprocess
import time

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "lab" / "runtime"
INDEX = "logs-aegis.windows-default"
PIPELINE = "aegis-windows-v1"


def preload_winlogbeat_pipelines(request, version):
    """Winlogbeat checks its built-ins on connect, even with a custom output pipeline.

    Load the version-matched vendor definitions with host admin credentials, so
    the guest writer needs only pipeline-read metadata rights.
    """
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("STACK_VERSION must be a release version")
    modules = {"powershell": ["powershell", "powershell_operational"],
               "security": ["security"], "sysmon": ["sysmon"], "routing": ["routing"]}
    for module, names in modules.items():
        for name in names:
            pipeline_id = f"winlogbeat-{version}-{name}"
            existing = request("GET", f"/_ingest/pipeline/{pipeline_id}", allow_missing=True)
            if existing is not None:
                continue
            url = f"https://raw.githubusercontent.com/elastic/beats/v{version}/x-pack/winlogbeat/module/{module}/ingest/{name}.yml"
            response = httpx.get(url, timeout=30)
            response.raise_for_status()
            text = re.sub(r'\{<\s*IngestPipeline\s+"([^"\n]+)"\s*>\}',
                          lambda match: f"winlogbeat-{version}-{match.group(1)}", response.text)
            if "{<" in text:
                raise ValueError(f"Unsupported vendor pipeline template: {name}")
            request("PUT", f"/_ingest/pipeline/{pipeline_id}", json=yaml.safe_load(text))


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()


def read_env():
    values = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8-sig").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    values.update({k: v for k, v in os.environ.items() if k in values})
    return values


def pipeline():
    return {"description": "Normalize actual Windows lab event data; retains original winlog fields.", "processors": [
        {"set": {"field": "event.ingested", "value": "{{{_ingest.timestamp}}}"}},
        {"set": {"field": "aegis.provenance", "value": "endpoint_lab"}},
        {"set": {"field": "aegis.synthetic", "value": False}},
        {"script": {"lang": "painless", "params": {"separator": "\\", "task_fields": {"command_path":"Command", "arguments":"Arguments"}}, "source": """
            if (ctx.winlog == null || ctx.winlog.event_data == null) return;
            def d = ctx.winlog.event_data;
            if (ctx.process == null) ctx.process = [:];
            def image = d.Image != null ? d.Image : d.NewProcessName;
            if (image != null) {
                ctx.process.executable = image;
                int slash = image.lastIndexOf(params.separator);
                ctx.process.name = image.substring(slash + 1).toLowerCase();
            }
            if (d.CommandLine != null) ctx.process.command_line = d.CommandLine;
            if (d.ProcessGuid != null) ctx.process.entity_id = d.ProcessGuid;
            if (d.ParentImage != null) {
                ctx.process.parent = ['executable': d.ParentImage,
                    'name': d.ParentImage.substring(d.ParentImage.lastIndexOf(params.separator) + 1).toLowerCase()];
            }
            if (d.TargetObject != null) {
                def target = d.TargetObject;
                int last = target.lastIndexOf(params.separator);
                if (last > 0) {
                    def key = target.substring(0, last).toLowerCase();
                    if (key.startsWith('hku' + params.separator)) {
                        int sidEnd = key.indexOf(params.separator, 4);
                        if (sidEnd > 0) key = 'hkcu' + key.substring(sidEnd);
                    }
                    ctx.aegis.registry = ['key': key, 'path':target];
                    if (ctx.registry == null) ctx.registry = [:];
                    ctx.registry.path = target;
                }
            }
            if (d.TaskContent != null) {
                def xml = d.TaskContent;
                def task = [:];
                for (def field : params.task_fields.entrySet()) {
                    def open = '<' + field.getValue() + '>';
                    def close = '</' + field.getValue() + '>';
                    int begin = xml.indexOf(open);
                    int end = xml.indexOf(close);
                    if (begin >= 0 && end > begin) {
                        task[field.getKey()] = xml.substring(begin + open.length(), end).replace('&quot;', '\u0022').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>');
                    }
                }
                task.command = (task.command_path != null ? task.command_path : '') + ' ' + (task.arguments != null ? task.arguments : '');
                if (d.TaskName != null) task.name = d.TaskName;
                ctx.aegis.task = task;
            }
        """}},
    ]}


def detection_mappings():
    return {'registry': {'properties': {'key': {'type':'keyword'}, 'path': {'type':'keyword'}}},
            'task': {'properties': {'command_path': {'type':'wildcard'}, 'arguments': {'type':'wildcard'},
                                     'command': {'type':'wildcard'}, 'name': {'type':'keyword'}}}}


def collector_config(api_key):
    return f"""# Generated for the Windows guest only. Contains a restricted write credential.
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 1h
  - name: Security
    event_id: 4688,4698,4699,4702
    ignore_older: 1h
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103,4104
    ignore_older: 1h
  - name: Application
    provider: [AegisLab]
    event_id: 100,101
    ignore_older: 1h
processors:
  - add_host_metadata: ~
tags: [aegis, windows-lab]
output.elasticsearch:
  hosts: ["https://es01:9200"]
  api_key: {json.dumps(api_key)}
  ssl.certificate_authorities: ['C:\\AegisLab\\ca.crt']
  ssl.verification_mode: full
  index: "{INDEX}"
  pipeline: "{PIPELINE}"
setup.ilm.enabled: false
setup.template.enabled: false
queue.mem:
  events: 512
  flush.min_events: 128
  flush.timeout: 1s
logging.to_files: true
logging.files:
  path: 'C:\\AegisLab\\collector-logs'
  keepfiles: 3
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", action="store_true", help="Start the Docker-managed guest after staging")
    parser.add_argument("--run-smoke", action="store_true", help="Run only Atomic T1057 tasklist inside the guest after provisioning")
    args = parser.parse_args()
    values = read_env()
    oem = RUNTIME / "oem"
    oem.mkdir(parents=True, exist_ok=True)
    (RUNTIME / "share" / "results").mkdir(parents=True, exist_ok=True)
    es_id = command("docker", "compose", "ps", "-q", "es01")
    if not es_id:
        raise RuntimeError("Start Elasticsearch first: docker compose up -d es01")
    command("docker", "cp", f"{es_id}:/usr/share/elasticsearch/config/certs/ca/ca.crt", str(oem / "ca.crt"))
    inspection = json.loads(command("docker", "inspect", es_id))[0]
    networks = inspection["NetworkSettings"]["Networks"]
    es_ip = next(iter(networks.values()))["IPAddress"]
    context = ssl.create_default_context(cafile=str(oem / "ca.crt"))
    with httpx.Client(base_url=f"https://localhost:{values.get('ES_PORT', '9200')}",
                      auth=(values.get("ES_USER", "elastic"), values["ELASTIC_PASSWORD"]), verify=context, timeout=30) as client:
        def request(method, path, allow_missing=False, **kwargs):
            response = client.request(method, path, **kwargs)
            if allow_missing and response.status_code == 404:
                return None
            if response.is_error:
                # Error bodies may include submitted configuration; never print credentials.
                raise RuntimeError(f"Elasticsearch request failed: {method} {path}, HTTP {response.status_code}")
            return response.json()
        for attempt in range(60):
            try:
                request("GET", "/")
                break
            except (httpx.HTTPError, RuntimeError):
                if attempt == 59:
                    raise
                time.sleep(2)
        request("PUT", f"/_ingest/pipeline/{PIPELINE}", json=pipeline())
        preload_winlogbeat_pipelines(request, values.get("STACK_VERSION", "8.12.0"))
        request("PUT", "/_index_template/aegis-windows", json={
            "index_patterns": ["logs-aegis.windows-*"], "priority": 501,
            "template": {"settings": {"index.default_pipeline": PIPELINE, "number_of_replicas": 0},
                         "mappings": {"properties": {"@timestamp": {"type": "date"},
                             "host": {"properties": {"name": {"type": "keyword"}, "id": {"type": "keyword"}}},
                             "event": {"properties": {"code": {"type": "keyword"}, "ingested": {"type": "date"}}},
                             "process": {"properties": {"name": {"type": "keyword"}, "command_line": {"type": "wildcard"}}},
                             "winlog": {"properties": {"provider_name": {"type": "keyword"}, "computer_name": {"type": "keyword"}, "record_id": {"type": "long"}}},
                             "aegis": {"properties": {"provenance": {"type": "keyword"}, "synthetic": {"type": "boolean"},
                                 **detection_mappings()}}}}}})
        if client.head(f"/{INDEX}").status_code == 404:
            request("PUT", f"/{INDEX}")
        key_path = RUNTIME / "telemetry-key.json"
        if key_path.exists():
            key = json.loads(key_path.read_text())
        else:
            key = request("POST", "/_security/api_key", json={"name": "aegis-windows-lab", "expiration": "90d",
                "role_descriptors": {"telemetry": {"cluster": ["monitor", "read_pipeline"], "indices": [
                    {"names": ["logs-aegis.windows-*"], "privileges": ["auto_configure", "create_doc"]}]}}})
            key_path.write_text(json.dumps(key), encoding="utf-8")
        request("PUT", f"/_security/api_key/{key['id']}", json={"role_descriptors": {
            "telemetry": {"cluster": ["monitor", "read_pipeline"], "indices": [
                {"names": ["logs-aegis.windows-*"], "privileges": ["auto_configure", "create_doc"]}]}}})
        encoded = f"{key['id']}:{key['api_key']}"
        (oem / "winlogbeat.yml").write_text(collector_config(encoded), encoding="utf-8")
        # Exercise the production normalization path without indexing a fabricated event.
        simulation = request("POST", f"/_ingest/pipeline/{PIPELINE}/_simulate", json={"docs": [{"_source": {
            "winlog": {"event_data": {"Image": "C:\\Windows\\System32\\tasklist.exe", "CommandLine": "tasklist"}}}}]})
        assert simulation["docs"][0]["doc"]["_source"]["process"]["name"] == "tasklist.exe"
    source = ROOT / "lab" / "windows"
    for name in ("install.bat", "Install-AegisLab.ps1", "Run-AegisAtomic.ps1", "sysmon.xml", "atomic_catalog.json", "Install-AegisSchedule.ps1", "Run-AegisAtomicBatch.ps1"):
        shutil.copyfile(source / name, oem / name)
    for name in ("Install-AegisLab.ps1", "Run-AegisAtomic.ps1", "Collect-AegisDiagnostics.ps1", "Show-AegisStatus.ps1", "atomic_catalog.json", "Install-AegisSchedule.ps1", "Run-AegisAtomicBatch.ps1", "Install-AegisDetectionPack.ps1", "sysmon.xml"):
        shutil.copyfile(source / name, RUNTIME / "share" / name)
    refs = json.loads((source / "sources.json").read_text())
    (oem / "settings.json").write_text(json.dumps({**refs, "es_ip": es_ip, "run_smoke": args.run_smoke,
                                                   "stack_version": values.get("STACK_VERSION", "8.12.0")}), encoding="utf-8")
    env_path = RUNTIME / "windows.env"
    if not env_path.exists():
        env_path.write_text("WINDOWS_PASSWORD=" + secrets.token_urlsafe(20) + "Aa1!\n", encoding="utf-8")
    print("Guest bootstrap prepared; restricted credentials stored only in ignored lab/runtime.")
    print("Normalization pipeline simulation passed; no fabricated event indexed.")
    if args.start:
        subprocess.run(["docker", "compose", "--env-file", ".env", "--env-file", "lab/runtime/windows.env",
                        "-f", "docker-compose.yml", "-f", "compose.windows.yml", "--profile", "windows-lab",
                        "up", "-d", "windows-lab"], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
