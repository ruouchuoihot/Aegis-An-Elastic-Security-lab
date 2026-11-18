from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import os
import asyncio
from pathlib import Path
import httpx
import json
import hashlib
import re
import secrets
import ssl
from datetime import datetime, timezone, timedelta
from typing import List, Optional
try:
    from .aegis_investigation import correlate, triage, InvestigationLedger
    from .aegis_agent import investigate, configuration
    from .aegis_orchestrator import orchestrate
    from .aegis_jobs import Jobs
    from .aegis_siem import native_enabled, rule_view, rule_url, threat_view
except ImportError:
    from aegis_investigation import correlate, triage, InvestigationLedger
    from aegis_agent import investigate, configuration
    from aegis_orchestrator import orchestrate
    from aegis_jobs import Jobs
    from aegis_siem import native_enabled, rule_view, rule_url, threat_view

app = FastAPI(title="Project Aegis AI Gateway", version="0.4.0")

# --- Configuration ---
ES_URL = os.environ.get("ES_URL", "https://es01:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "changeme")
RULES_PATH = os.environ.get("AEGIS_RULES_PATH", os.path.join(os.path.dirname(__file__), "..", "rules", "aegis_detection_rules.json"))
ALERT_INDEX = os.environ.get("AEGIS_ALERT_INDEX", "aegis-alerts-default")
GATEWAY_TOKEN = os.environ.get("AEGIS_GATEWAY_TOKEN", "")
CA_CERT = os.environ.get("CA_CERT")
ledger = InvestigationLedger(os.environ.get("AEGIS_LEDGER_PATH", "data/investigations.sqlite3"))
jobs = Jobs(str(Path(ledger.path).with_name('jobs.sqlite3')))
detector_state = {'enabled': os.environ.get('AEGIS_BACKGROUND_ENABLED') == '1', 'interval_seconds': 30, 'last_success': None, 'last_error': None}
background_tasks = []
STATIC_PATH = os.path.join(os.path.dirname(__file__), "..", "static")
app.mount("/assets", StaticFiles(directory=STATIC_PATH), name="assets")


@app.exception_handler(httpx.HTTPError)
async def elastic_transport_error(request: Request, exc):
    return JSONResponse(status_code=503, content={"detail": "Elasticsearch unavailable. Check ES_URL, service health and CA_CERT."})


@app.middleware("http")
async def authenticate(request: Request, call_next):
    public_shell = request.url.path in ("/", "/health", "/kibana", "/siem", "/siem/rules") or request.url.path.startswith("/assets/")
    if GATEWAY_TOKEN and not public_shell:
        if not secrets.compare_digest(request.headers.get("authorization", ""), f"Bearer {GATEWAY_TOKEN}"):
            return JSONResponse(status_code=401, content={"detail": "Bearer token required"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response


def validate_index(index):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.*,-]*", index) or ".." in index:
        raise HTTPException(status_code=422, detail="Invalid index pattern")
    return index

# --- Schemas ---
class QueryRequest(BaseModel):
    query: str
    index: str = "logs-*"
    size: int = Field(default=10, ge=1, le=1000)

class QueryResponse(BaseModel):
    hits: list
    total: int

class RuleRunRequest(BaseModel):
    rule_ids: Optional[List[str]] = None
    index: Optional[str] = None
    size: int = Field(default=100, ge=1, le=1000)
    create_alerts: bool = True
    lookback_minutes: Optional[int] = Field(default=None, ge=1, le=1440)

class AlertSearchRequest(BaseModel):
    query: str = "*"
    size: int = Field(default=20, ge=1, le=200)
    start: Optional[datetime] = None
    end: Optional[datetime] = None


class InvestigationRequest(BaseModel):
    # Absolute UTC bounds make the evidence scope reviewable and reproducible.
    start: datetime
    end: datetime
    window_minutes: int = Field(default=30, ge=1, le=1440)
    size: int = Field(default=500, ge=1, le=5000)


class TriageRequest(InvestigationRequest):
    incident_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    alert_id: Optional[str] = Field(default=None, min_length=1, max_length=512)

class EsStatus(BaseModel):
    cluster_name: Optional[str] = None
    license_type: Optional[str] = None
    license_status: Optional[str] = None
    simulation_events: int = 0
    aegis_alerts: int = 0


MCP_TOOL_DEFINITIONS = [
    {
        "name": "search_siem",
        "description": "Search Elasticsearch/Kibana SIEM data with a query_string query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "index": {"type": "string", "default": "logs-*"},
                "size": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_security_status",
        "description": "Return Elastic cluster name, license, simulation event count, and Aegis alert count.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_detection_rules",
        "description": "List Aegis detection rules and MITRE mappings.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_detection_rules",
        "description": "Run Aegis detection rules and optionally create alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_ids": {"type": "array", "items": {"type": "string"}},
                "index": {"type": "string"},
                "size": {"type": "integer", "default": 100},
                "create_alerts": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "list_aegis_alerts",
        "description": "Search lab-managed Aegis alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "default": "*"},
                "size": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "get_attack_surface",
        "description": "Summarize hosts and users seen in simulation data.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

for name, description, schema in [
    ("correlate_alerts", "Group alerts by host, provenance and fixed UTC time bucket; reports incomplete coverage.", InvestigationRequest.model_json_schema()),
    ("triage_incident", "Deterministic evidence-cited review, persisted in the investigation ledger. No LLM or response execution.", TriageRequest.model_json_schema()),
    ("investigate_incident", "Run a bounded read-only LLM investigation; record model/tool steps in the ledger. Requires configured provider.", TriageRequest.model_json_schema()),
    ("get_investigation_ledger", "Read saved incident snapshots and decisions.", {"type": "object", "properties": {"incident_id": {"type": "string", "pattern": "^[a-f0-9]{64}$"}}, "required": ["incident_id"]}),
    ("verify_investigation_ledger", "Verify the local ledger hash chain; does not prove authenticity against database administrators.", {"type": "object", "properties": {}}),
]:
    MCP_TOOL_DEFINITIONS.append({"name": name, "description": description, "inputSchema": schema})


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_rules():
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            return [rule for rule in json.load(f) if rule.get('enabled', True)]
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Invalid rules file: {e}")


def alert_id(rule_id, event_id, event_index=""):
    raw = json.dumps([rule_id, event_index, event_id]).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


async def es_request(method, path, **kwargs):
    headers = {"Content-Type": "application/json"}
    headers.update(kwargs.pop("headers", {}))
    verify = ssl.create_default_context(cafile=CA_CERT) if CA_CERT else True
    async with httpx.AsyncClient(verify=verify, timeout=30.0) as client:
        response = await client.request(
            method,
            f"{ES_URL}{path}",
            auth=(ES_USER, ES_PASSWORD),
            headers=headers,
            **kwargs,
        )

    if response.status_code >= 300:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    if not response.text:
        return {}
    return response.json()


async def es_count(index, query="*"):
    payload = {"query": {"query_string": {"query": query}}}
    try:
        data = await es_request("POST", f"/{index}/_count", json=payload)
    except HTTPException as e:
        if e.status_code == 404:
            return 0
        raise
    return data.get("count", 0)


async def ensure_alert_index():
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "source_event": {"properties": {"timestamp": {"type": "date"}, "id": {"type": "keyword"}, "index": {"type": "keyword"}}},
                "aegis": {"properties": {"provenance": {"type": "keyword"}}},
                "event": {"properties": {"kind": {"type": "keyword"}, "module": {"type": "keyword"}}},
                "rule": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
                "kibana": {"properties": {"alert": {"properties": {"severity": {"type": "keyword"}}}}},
                "threat": {"properties": {"technique": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}}}},
                "host": {"properties": {"name": {"type": "keyword"}, "hostname": {"type": "keyword"}}},
                "source": {"properties": {"ip": {"type": "ip"}}},
                "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            }
        }
    }
    try:
        await es_request("PUT", f"/{ALERT_INDEX}", json=mapping)
    except HTTPException as e:
        if e.status_code != 400 or "resource_already_exists_exception" not in str(e.detail):
            raise


def build_alert(rule, hit):
    source = hit.get("_source", {})
    mitre = rule.get("mitre", {})
    source_index = hit.get("_index", "")
    if source_index.startswith(("logs-aegis-simulation-", ".ds-logs-aegis-simulation-")) or source.get("aegis", {}).get("synthetic") is True:
        provenance = "synthetic"
    elif source_index.startswith("logs-aegis.windows-") and source.get("aegis", {}).get("provenance") == "endpoint_lab":
        provenance = "endpoint_lab"
    else:
        provenance = "unknown"
    return {
        "@timestamp": utc_now(),
        "event": {"kind": "signal", "module": "aegis", "action": "aegis-rule-match"},
        "message": f"{rule['name']} matched event {hit.get('_id')}",
        "rule": {
            "id": rule["id"],
            "name": rule["name"],
            "description": rule.get("description", ""),
            "provenance": rule.get("provenance"),
            "false_positives": rule.get("false_positives", []),
            "risk_score": rule.get("risk_score", 0),
        },
        "kibana": {"alert": {"severity": rule.get("severity", "low"), "reason": rule.get("query", rule.get("description", ""))}},
        "threat": {
            "tactic": {"name": mitre.get("tactic")},
            "technique": {"id": mitre.get("technique_id"), "name": mitre.get("technique_name")},
        },
        "source_event": {
            "id": hit.get("_id"),
            "index": hit.get("_index"),
            "timestamp": source.get("@timestamp"),
        },
        "host": source.get("host", {}),
        "process": source.get("process", {}),
        "source": source.get("source", {}),
        "destination": source.get("destination", {}),
        "user": source.get("user", {}),
        "aegis": {"provenance": provenance, "task": source.get("aegis", {}).get("task", {}), "registry": source.get("aegis", {}).get("registry", {})},
        "registry": source.get("registry", {}),
    }

# --- MCP Tooling Logic ---
# In a full MCP implementation, this would follow the Model Context Protocol spec.
# For this lab, we provide an "AI Gateway" that exposes SIEM tools to an agent.

@app.get("/health")
async def health():
    return {"status": "Aegis AI Gateway is online"}


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(os.path.join(STATIC_PATH, "index.html"))


@app.get("/kibana", include_in_schema=False)
async def open_kibana():
    return RedirectResponse(os.environ.get("KIBANA_PUBLIC_URL", "http://localhost:5601").rstrip("/") + "/app/discover")


@app.get('/siem',include_in_schema=False)
async def open_siem():
    return RedirectResponse(os.environ.get('KIBANA_PUBLIC_URL','http://localhost:5601').rstrip('/')+'/app/security/alerts')


@app.get('/siem/rules',include_in_schema=False)
async def open_siem_rules():
    return RedirectResponse(os.environ.get('KIBANA_PUBLIC_URL','http://localhost:5601').rstrip('/')+'/app/security/rules')


@app.get("/tools/agent/status")
async def agent_status():
    base, model = configuration()
    return {"configured": bool(base and model), "model": model or None,
            "mode": "read_only", "max_model_calls": 4, "response_execution": False}

@app.get("/mcp/tools")
async def list_mcp_tools():
    return {
        "tools": MCP_TOOL_DEFINITIONS,
        "rest_endpoints": {
            "search_siem": "POST /tools/search",
            "get_security_status": "GET /tools/security/status",
            "list_detection_rules": "GET /tools/rules",
            "run_detection_rules": "POST /tools/rules/run",
            "list_aegis_alerts": "POST /tools/alerts",
            "get_attack_surface": "GET /tools/get_attack_surface",
            "correlate_alerts": "POST /tools/incidents/correlate",
            "triage_incident": "POST /tools/incidents/triage",
            "investigate_incident": "POST /tools/incidents/investigate",
            "get_investigation_ledger": "GET /tools/incidents/{incident_id}/ledger",
            "verify_investigation_ledger": "GET /tools/ledger/verify",
        },
    }

@app.post("/mcp")
async def mcp_json_rpc(payload: dict):
    request_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params", {})

    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "project-aegis-ai-gateway", "version": "0.3.0"},
            }
        elif method == "tools/list":
            result = {"tools": MCP_TOOL_DEFINITIONS}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            output = await call_mcp_tool(name, arguments)
            result = {"content": [{"type": "text", "text": json.dumps(output, ensure_ascii=False)}]}
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"Unsupported method: {method}"},
            }

        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except HTTPException as e:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": e.status_code, "message": str(e.detail)}}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(e)}}


async def call_mcp_tool(name, arguments):
    if name == "correlate_alerts":
        return await correlate_alerts(InvestigationRequest(**arguments))
    if name == "triage_incident":
        return await triage_incident(TriageRequest(**arguments))
    if name == "investigate_incident":
        return await investigate_incident(TriageRequest(**arguments))
    if name == "get_investigation_ledger":
        return await get_investigation_ledger(arguments.get("incident_id", ""))
    if name == "verify_investigation_ledger":
        return ledger.verify()
    if name == "search_siem":
        return (await search_siem(QueryRequest(**arguments))).model_dump()
    if name == "get_security_status":
        return (await get_security_status()).model_dump()
    if name == "list_detection_rules":
        return await list_detection_rules()
    if name == "run_detection_rules":
        return await run_detection_rules(RuleRunRequest(**arguments))
    if name == "list_aegis_alerts":
        return (await list_aegis_alerts(AlertSearchRequest(**arguments))).model_dump()
    if name == "get_attack_surface":
        return await get_attack_surface()
    raise HTTPException(status_code=404, detail=f"Unknown MCP tool: {name}")

@app.post("/tools/search", response_model=QueryResponse)
async def search_siem(request: QueryRequest):
    """
    Executes a raw Elasticsearch query. This tool can be used by an AI agent 
    to retrieve context from logs.
    """
    validate_index(request.index)
    
    # Payload for ES search
    # Elasticsearch query_string syntax, not KQL or raw DSL.
    payload = {
        "query": {
            "query_string": {
                "query": request.query
            }
        },
        "size": request.size,
        "sort": [{"@timestamp": "desc"}]
    }

    try:
        data = await es_request("POST", f"/{request.index}/_search", json=payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
    total = data.get("hits", {}).get("total", {}).get("value", 0)
    return QueryResponse(hits=hits, total=total)

@app.get("/tools/security/status", response_model=EsStatus)
async def get_security_status():
    root = await es_request("GET", "/")
    license_data = await es_request("GET", "/_license")
    simulation_events = await es_count("logs-aegis-simulation-*")
    aegis_alerts = await es_count(ALERT_INDEX)
    license_body = license_data.get("license", {})
    return EsStatus(
        cluster_name=root.get("cluster_name"),
        license_type=license_body.get("type"),
        license_status=license_body.get("status"),
        simulation_events=simulation_events,
        aegis_alerts=aegis_alerts,
    )

@app.get("/tools/rules")
async def list_detection_rules():
    rules = await managed_rules()
    return {"count": len(rules), "enabled_count":sum(r.get('enabled',True) for r in rules),
            "management":"elastic_security" if native_enabled() else 'local_bootstrap', "rules": rules}


async def kibana_request(method, path, **kwargs):
    async with httpx.AsyncClient(timeout=30) as client:
        response=await client.request(method,os.environ.get('KIBANA_URL','http://kibana:5601').rstrip('/')+path,
            auth=(ES_USER,ES_PASSWORD),headers={'kbn-xsrf':'aegis'},**kwargs)
    if response.is_error:
        raise HTTPException(503, f'Elastic Security API unavailable (HTTP {response.status_code})')
    return response.json()


async def managed_rules():
    local={r['id']:r for r in load_rules()}
    if not native_enabled():
        return list(local.values())
    rows=[]
    for page in range(1,11):
        data=await kibana_request('GET','/api/detection_engine/rules/_find',params={
            'per_page':100,'page':page,'filter':'alert.attributes.tags:"aegis"'})
        rows.extend(data.get('data',[]))
        if len(rows)>=data.get('total',0):
            break
    return [rule_view(row,local.get(row['rule_id'])) for row in rows]


def field(data,path,default=None):
    if path in data:
        return data[path]
    value=data
    for part in path.split('.'):
        if not isinstance(value,dict) or part not in value:
            return default
        value=value[part]
    return value


async def sync_native_alerts():
    # Elastic Security executes detection. This only projects its saved alerts.
    data=await es_request('POST','/.alerts-security.alerts-default/_search',params={'ignore_unavailable':'true'},json={
        'size':1000,'track_total_hits':True,'sort':[{'@timestamp':'desc'}],
        'query':{'bool':{'filter':[{'term':{'kibana.alert.rule.tags':'aegis'}},
                                          {'range':{'@timestamp':{'gte':'now-60m'}}}]}}})
    hits=data.get('hits',{}).get('hits',[])
    pending=[]
    for hit in hits:
        source=hit['_source']
        ancestors=field(source,'kibana.alert.ancestors',[]) or []
        parent=next((a for a in ancestors if a.get('depth')==0 and a.get('index','').startswith(('logs-','.ds-logs-'))),None)
        if parent and field(source,'kibana.alert.rule.rule_id'):
            pending.append((hit,parent))
    if not pending:
        return {'alerts_created':0,'native_alerts_examined':len(hits),'coverage_limited':data.get('hits',{}).get('total',{}).get('value',0)>len(hits)}
    docs=await es_request('POST','/_mget',json={'docs':[{'_index':p['index'],'_id':p['id']} for _,p in pending]})
    actions=[]
    for (hit,parent),original in zip(pending,docs.get('docs',[])):
        if not original.get('found'):
            continue
        native=hit['_source'];identifier=field(native,'kibana.alert.rule.rule_id');uuid=field(native,'kibana.alert.rule.uuid')
        parameters=field(native,'kibana.alert.rule.parameters',{}) or {}
        rule={'id':identifier,'name':field(native,'kibana.alert.rule.name',identifier),
              'description':field(native,'kibana.alert.rule.description','Native Elastic Security detection'),
              'severity':field(native,'kibana.alert.severity','low'),'risk_score':field(native,'kibana.alert.risk_score',0),
              'provenance':parameters.get('meta',{}).get('aegis',{}).get('provenance'),
              'false_positives':parameters.get('false_positives',[]),
              'mitre':threat_view(parameters.get('threat')) if 'threat' in parameters else parameters.get('meta',{}).get('aegis',{}).get('mitre',{})}
        document=build_alert(rule,original)
        document['@timestamp']=native.get('@timestamp',utc_now())
        siem={'engine':'elastic_security','alert_id':hit['_id'],'alert_index':hit['_index'],
              'rule_uuid':uuid,'rule_url':rule_url(uuid) if uuid else None,
              'workflow_status':field(native,'kibana.alert.workflow_status','open')}
        document['siem']=siem
        actions.extend([json.dumps({'update':{'_index':ALERT_INDEX,'_id':alert_id(identifier,parent['id'],parent['index'])}}),
            json.dumps({'doc':{'siem':siem,'rule':document['rule'],'kibana':document['kibana']},'upsert':document})])
    if not actions:
        return {'alerts_created':0,'native_alerts_examined':len(hits),'coverage_limited':False}
    await ensure_alert_index()
    response=await es_request('POST','/_bulk',content='\n'.join(actions)+'\n',headers={'Content-Type':'application/x-ndjson'})
    items=[row.get('update',{}) for row in response.get('items',[])]
    if any(row.get('status',500)>=300 for row in items) or len(items)!=len(actions)//2:
        raise HTTPException(502,'Native alert projection failed; retry is safe')
    return {'alerts_created':sum(row.get('result')=='created' for row in items),'native_alerts_examined':len(hits),
            'coverage_limited':data.get('hits',{}).get('total',{}).get('value',0)>len(hits)}

@app.post("/tools/rules/run")
async def run_detection_rules(request: RuleRunRequest):
    if native_enabled():
        if not request.create_alerts:
            raise HTTPException(409,'Detection is managed by Elastic Security. Use rule preview in SIEM.')
        result=await sync_native_alerts()
        return {'engine':'elastic_security','rules_evaluated':0,'alert_index':ALERT_INDEX,
                'results':[],'sync':result,'note':'Synced native alerts. Rule execution and edits are managed in SIEM.'}
    rules = load_rules()
    if request.rule_ids:
        wanted = set(request.rule_ids)
        rules = [rule for rule in rules if rule.get("id") in wanted]

    if request.create_alerts:
        await ensure_alert_index()
    results = []

    for rule in rules:
        index = request.index or rule.get("index", "logs-*")
        validate_index(index)
        payload = {
            "query": rule.get("query_dsl") or {"query_string": {"query": rule["query"]}},
            "size": request.size,
            "track_total_hits": True,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        }
        if request.lookback_minutes:
            payload["query"] = {"bool": {"filter": [payload["query"], {"range": {"@timestamp": {"gte": f"now-{request.lookback_minutes}m"}}}]}}
        data = await es_request("POST", f"/{index}/_search", json=payload,
                                params={"ignore_unavailable": "true", "allow_no_indices": "true"})
        hits = data.get("hits", {}).get("hits", [])
        created = 0

        if request.create_alerts and hits:
            actions = []
            for hit in hits:
                doc_id = alert_id(rule["id"], hit["_id"], hit["_index"])
                actions.append(json.dumps({"create": {"_index": ALERT_INDEX, "_id": doc_id}}))
                actions.append(json.dumps(build_alert(rule, hit)))

            bulk_body = "\n".join(actions) + "\n"
            bulk_data = await es_request(
                "POST",
                "/_bulk",
                content=bulk_body,
                headers={"Content-Type": "application/x-ndjson"},
            )
            items = [item.get("create", {}) for item in bulk_data.get("items", [])]
            failures = [item for item in items if item.get("status", 500) >= 300 and item.get("status") != 409]
            if failures or len(items) != len(hits):
                raise HTTPException(status_code=502, detail="Alert bulk write failed; retry is safe")
            created = sum(1 for item in items if item.get("result") == "created")

        results.append({
            "rule_id": rule["id"],
            "name": rule["name"],
            "matches": len(hits),
            "coverage_limited": data.get('hits', {}).get('total', {}).get('value', 0) > len(hits) or bool(data.get('timed_out')) or data.get('_shards', {}).get('failed', 0) > 0,
            "alerts_created": created,
            "severity": rule.get("severity", "low"),
            "risk_score": rule.get("risk_score", 0),
        })

    return {
        "rules_evaluated": len(rules),
        "alert_index": ALERT_INDEX,
        "results": results,
    }

@app.post("/tools/alerts", response_model=QueryResponse)
async def list_aegis_alerts(request: AlertSearchRequest):
    payload = {
        "query": {"query_string": {"query": request.query}},
        "size": request.size,
        "sort": [{"@timestamp": "desc"}],
    }
    if request.start is not None or request.end is not None:
        if request.start is None or request.end is None or request.start.tzinfo is None or request.end.tzinfo is None or request.start >= request.end:
            raise HTTPException(status_code=422, detail="Use timezone-aware start < end")
        payload["query"] = {"bool": {"filter": [payload["query"], {"range": {"source_event.timestamp": {
            "gte": request.start.isoformat(), "lt": request.end.isoformat()}}}]}}
    try:
        data = await es_request("POST", f"/{ALERT_INDEX}/_search", json=payload)
    except HTTPException as e:
        if e.status_code == 404:
            return QueryResponse(hits=[], total=0)
        raise

    hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
    total = data.get("hits", {}).get("total", {}).get("value", 0)
    return QueryResponse(hits=hits, total=total)

@app.post("/tools/incidents/correlate")
async def correlate_alerts(request: InvestigationRequest):
    if request.start.tzinfo is None or request.end.tzinfo is None or request.start >= request.end:
        raise HTTPException(status_code=422, detail="Use timezone-aware start < end")
    payload = {
        "query": {"range": {"source_event.timestamp": {
            "gte": request.start.isoformat(), "lt": request.end.isoformat()}}},
        "size": request.size, "track_total_hits": True,
        "sort": [{"source_event.timestamp": "asc"}],
    }
    try:
        data = await es_request("POST", f"/{ALERT_INDEX}/_search", json=payload)
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
        data = {"hits": {"hits": [], "total": {"value": 0, "relation": "eq"}}}
    hits = data.get("hits", {}).get("hits", [])
    total = data.get("hits", {}).get("total", {})
    incidents, skipped = correlate(hits, request.window_minutes)
    partial = (total.get("relation") != "eq" or total.get("value", 0) > len(hits)
               or bool(data.get("timed_out")) or data.get("_shards", {}).get("failed", 0) > 0)
    return {"incidents": incidents, "incident_count": len(incidents),
            "severity_counts": {severity:sum(a['severity']==severity for i in incidents for a in i['alerts']) for severity in ['critical','high','medium','low','unknown']},
            "coverage": {"start": request.start.isoformat(), "end": request.end.isoformat(),
                         "matched_alerts": total.get("value", 0), "examined_alerts": len(hits),
                         "partial": partial, "skipped": skipped,
                         "note": "Alerts without a source timestamp are outside this time-scoped query; fixed buckets do not bridge boundaries."}}


@app.post("/tools/incidents/triage")
async def triage_incident(request: TriageRequest):
    incident, coverage = await scoped_incident(request)
    decision = triage(incident)
    decision["coverage"] = coverage
    return ledger.append(incident, decision)


async def scoped_incident(request):
    result = await correlate_alerts(request)
    if result["coverage"]["partial"]:
        raise HTTPException(status_code=409, detail="Incomplete alert coverage; narrow the time range or increase size")
    incident = next((row for row in result["incidents"] if row["id"] == request.incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found in this evidence scope")
    if request.alert_id is not None:
        alert = next((a for a in incident['alerts'] if a['reference']['id'] == request.alert_id), None)
        if alert is None:
            raise HTTPException(404, 'Alert not found in this incident and evidence scope')
        identity = json.dumps(alert['reference'], sort_keys=True)
        incident = {**incident, 'id': hashlib.sha256(('alert:' + identity).encode()).hexdigest(),
                    'alerts': [alert], 'alert_count': 1, 'severity': alert['severity'],
                    'techniques': [alert['technique']['id']] if alert.get('technique', {}).get('id') else [],
                    'analysis_scope': {'type': 'alert', 'reference': alert['reference'],
                                       'parent_incident_id': request.incident_id}}
    return incident, result["coverage"]


@app.post("/tools/incidents/investigate")
async def investigate_incident(request: TriageRequest):
    incident, coverage = await scoped_incident(request)

    async def read_context():
        return await collect_incident_context(incident, request)

    decision = await investigate(incident, read_context)
    decision["coverage"] = coverage
    return ledger.append(incident, decision)


async def collect_incident_context(incident, request):
    # No model-generated queries or arbitrary index selection.
    if not incident["entity"]:
        return {"evidence": [], "reason": "No host entity"}
    moments = [datetime.fromisoformat(a["source_event"]["timestamp"].replace("Z", "+00:00")) for a in incident["alerts"]]
    context_start = max(request.start, min(moments) - timedelta(minutes=2))
    context_end = min(request.end, max(moments) + timedelta(minutes=2))
    projection = ["@timestamp", "host.name", "host.id", "process.name", "process.parent.name", "event.action", "event.code", "destination.port", "aegis.synthetic", "winlog.record_id", "winlog.provider_name"]
    host_filter = {"bool": {"should": [
        {"term": {field: incident["entity"]}} for field in [incident["entity_field"], incident["entity_field"] + ".keyword"]
    ], "minimum_should_match": 1}}
    time_filter = {"range": {"@timestamp": {"gte": context_start.isoformat(), "lt": context_end.isoformat()}}}
    refs = [a["source_event"] for a in incident["alerts"] if a["source_event"].get("index", "").startswith(("logs-", ".ds-logs-")) and a["source_event"].get("id")]
    sources = []
    if refs:
        representatives = {}
        for alert in reversed(incident['alerts']):
            observed = alert.get('observed', {})
            key = (alert['rule'].get('id'), observed.get('process_name'), observed.get('parent_process'))
            ref = alert['source_event']
            if ref in refs:
                representatives.setdefault(key, ref)
        sampled_refs = []
        for ref in list(representatives.values()) + list(reversed(refs)):
            if ref not in sampled_refs and len(sampled_refs) < 20:
                sampled_refs.append(ref)
        retrieved = await es_request("POST", "/_mget", json={"docs": [
            {"_index": ref["index"], "_id": ref["id"], "_source": projection} for ref in sampled_refs]})
        sources = [row for row in retrieved.get("docs", []) if row.get("found") and row.get("_source")]
    payload = {"size": 20, "track_total_hits": True,
               "_source": projection,
               "query": {"bool": {"filter": [
                   time_filter, host_filter
               ], "must_not": [{"term": {field: "AegisLab"}} for field in ["winlog.provider_name", "winlog.provider_name.keyword"]]}}, "sort": [{"@timestamp": "asc"}]}
    try:
        data = await es_request("POST", "/logs-*/_search", json=payload)
    except HTTPException as exc:
        if exc.status_code == 404:
            return {"evidence": [], "reason": "No log indices"}
        return {"evidence": [], "reason": "Context query unavailable", "status_code": exc.status_code}
    hits = data.get("hits", {}).get("hits", [])
    total = data.get("hits", {}).get("total", {})
    evidence = []
    seen = {row["evidence_id"] for row in evidence}
    for row in sources + hits:
        evidence_id = f"{row['_index']}:{row['_id']}"
        if evidence_id not in seen and len(evidence) < 20 and row.get("_source", {}).get("winlog", {}).get("provider_name") != "AegisLab":
            evidence.append({"evidence_id": evidence_id, "event": row.get("_source", {})})
            seen.add(evidence_id)
    return {"evidence": evidence,
            "source_events_found": len(sources), "source_events_total": len(refs),
            "matched_events": total.get("value", 0),
            "start": context_start.isoformat(), "end": context_end.isoformat(),
            "partial": bool(data.get("timed_out")) or data.get("_shards", {}).get("failed", 0) > 0 or total.get("relation") != "eq" or total.get("value", 0) > len(hits) or len(sources) < len(refs),
            "limit": 20, "note": "Bounded event projection from the same host around the matched activity; partial means the event budget was reached or retrieval was incomplete, not that the events are synthetic."}


@app.get("/tools/incidents/{incident_id}/ledger")
async def get_investigation_ledger(incident_id: str):
    if not re.fullmatch(r"[a-f0-9]{64}", incident_id):
        raise HTTPException(status_code=422, detail="Invalid incident ID")
    return {"entries": ledger.read(incident_id), "limit": 100, "order": "newest_first"}


@app.post('/tools/investigations', status_code=202)
async def submit_investigation(request: TriageRequest):
    if not detector_state['enabled']:
        raise HTTPException(503, 'Background worker is disabled')
    if not all(configuration()):
        raise HTTPException(409, 'Configure a model before investigating')
    incident, coverage = await scoped_incident(request)
    payload = {'request': request.model_dump(mode='json'), 'incident': incident, 'coverage': coverage}
    fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    if request.alert_id is not None:
        # One active run per alert, even if live refresh advances the query window.
        fingerprint = hashlib.sha256(('alert:' + incident['id']).encode()).hexdigest()
    try:
        job_id = jobs.submit(fingerprint, payload)
    except ValueError as exc:
        raise HTTPException(429, str(exc))
    return {'job_id': job_id}


@app.get('/tools/investigations')
async def list_jobs():
    return {'jobs': [public_job(row) for row in jobs.list()]}


def public_job(row):
    incident = row.get('payload', {}).get('incident', {})
    scope = incident.get('analysis_scope', {})
    alert = next(iter(incident.get('alerts', [])), {})
    return {**{k: v for k, v in row.items() if k != 'payload'},
            'target': {'type': scope.get('type', 'incident'), 'reference': scope.get('reference'),
                       'name': alert.get('rule', {}).get('name', 'Investigation'),
                       'host': incident.get('host_name') or incident.get('entity')}}


@app.get('/tools/investigations/{job_id}')
async def get_job(job_id: str):
    row = jobs.get(job_id)
    if not row:
        raise HTTPException(404, 'Investigation job not found')
    return public_job(row)


async def detection_loop():
    while True:
        try:
            if native_enabled():
                result=await sync_native_alerts()
                detector_state.update(last_success=utc_now(),last_error=None,engine='elastic_security',**result)
            else:
                rule_ids = [r['id'] for r in load_rules() if r.get('index') == 'logs-aegis.windows-*']
                result = await run_detection_rules(RuleRunRequest(rule_ids=rule_ids, size=1000, lookback_minutes=15))
                detector_state.update(last_success=utc_now(), last_error=None, results=result['results'],
                                      alerts_created=sum(r['alerts_created'] for r in result['results']))
        except Exception as exc:
            detector_state['last_error'] = type(exc).__name__
        await asyncio.sleep(30)


async def investigation_worker():
    while True:
        row = jobs.claim()
        if not row:
            await asyncio.sleep(1)
            continue
        try:
            payload = row['payload']
            request = TriageRequest(**payload['request'])
            context = await collect_incident_context(payload['incident'], request)
            async def emit(event):
                jobs.event(row['id'], event)
            decision = await orchestrate(payload['incident'], context, emit)
            decision['coverage'] = payload['coverage']
            entry = ledger.append(payload['incident'], decision)
            jobs.finish(row['id'], decision['agent_status'], entry)
        except Exception as exc:
            jobs.finish(row['id'], 'failed', {'failure_type': type(exc).__name__})


@app.on_event('startup')
async def start_workers():
    if detector_state['enabled']:
        jobs.recover()
        background_tasks.extend([asyncio.create_task(detection_loop()), asyncio.create_task(investigation_worker())])


@app.on_event('shutdown')
async def stop_workers():
    for task in background_tasks:
        task.cancel()
    await asyncio.gather(*background_tasks, return_exceptions=True)
    background_tasks.clear()


@app.post('/tools/operations')
async def operations(request: InvestigationRequest):
    if request.start.tzinfo is None or request.end.tzinfo is None or request.start >= request.end:
        raise HTTPException(422, 'Use timezone-aware start < end')
    data = await es_request('POST', '/logs-aegis.windows-*/_search', params={'ignore_unavailable': 'true'}, json={
        'size': 0, 'track_total_hits': True,
        'query': {'range': {'@timestamp': {'gte': request.start.isoformat(), 'lt': request.end.isoformat()}}},
        'aggs': {'last_event': {'max': {'field': '@timestamp'}},
                 'processes': {'terms': {'field': 'process.name', 'size': 12}},
                 'timeline': {'date_histogram': {'field': '@timestamp', 'fixed_interval': '5m', 'min_doc_count': 1}}}})
    schedule = None
    root = Path(os.environ.get('AEGIS_LAB_RESULTS', 'lab/runtime/share/results'))
    try:
        schedule = json.loads((root/'atomic-schedule.json').read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        pass
    runs = []
    for path in sorted(root.glob('atomic-*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:40]:
        if path.name == 'atomic-schedule.json':
            continue
        try:
            r = json.loads(path.read_text(encoding='utf-8-sig'))
            when = datetime.fromisoformat(r['start'].replace('Z','+00:00'))
            if request.start <= when < request.end:
                runs.append({k: r.get(k) for k in ['run_id','batch_id','test_name','technique','start','end','status','sysmon_record_ids']})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return {'telemetry': {'count': data.get('hits',{}).get('total',{}).get('value',0), **data.get('aggregations',{})},
            'detector': detector_state, 'schedule': schedule, 'runs': runs,
            'note': 'Telemetry and recent runner records use the selected time scope. Scheduler status is a last-batch snapshot, not live Task Scheduler state. Recent run list capped at 39 files.'}


@app.get("/tools/ledger/verify")
async def verify_investigation_ledger():
    return ledger.verify()


@app.get("/tools/get_attack_surface")
async def get_attack_surface():
    """
    Returns a summary of unique hosts and users seen in the simulation index.
    Useful for an AI to understand the lab environment.
    """
    url = f"{ES_URL}/logs-aegis-simulation-*/_search"
    payload = {
        "size": 0,
        "aggs": {
            "hosts": {"terms": {"field": "host.hostname.keyword"}},
            "users": {"terms": {"field": "user.name.keyword"}}
        }
    }
    
    data = await es_request("POST", "/logs-aegis-simulation-*/_search", json=payload)

    hosts = [b["key"] for b in data.get("aggregations", {}).get("hosts", {}).get("buckets", [])]
    users = [b["key"] for b in data.get("aggregations", {}).get("users", {}).get("buckets", [])]

    return {"active_hosts": hosts, "active_users": users}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("AEGIS_GATEWAY_HOST", "127.0.0.1"), port=int(os.environ.get("AEGIS_GATEWAY_PORT", "8000")))
