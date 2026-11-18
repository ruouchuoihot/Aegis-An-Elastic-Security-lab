"""Generate the editable SVG architecture set using only the Python standard library.

Run from any directory: python scripts/render_architecture.py
PNG export is optional and handled by render_architecture.mjs (docs-only tooling).
"""
from html import escape
from math import hypot
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'docs' / 'assets'
BG, PANEL, LINE = '#0b1420', '#132334', '#365269'
TEXT, MUTED, GREEN, BLUE, GOLD = '#ecf3fa', '#b1c5d7', '#79e2c2', '#8ecbff', '#f2c780'


class Diagram:
    def __init__(self, title, subtitle, height=1080):
        self.height = height
        self.parts = [f'''<svg xmlns="http://www.w3.org/2000/svg" width="1500" height="{height}" viewBox="0 0 1500 {height}" role="img" aria-labelledby="title desc">
<title id="title">{escape(title)}</title><desc id="desc">{escape(subtitle)}</desc>
<defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto-start-reverse"><path d="M0 0 L9 4.5 L0 9 Z" fill="{GREEN}"/></marker></defs>
<rect width="1500" height="{height}" fill="{BG}"/>
<g font-family="Segoe UI,Arial,sans-serif">''']
        self.text(50, 47, 'PROJECT AEGIS / TECHNICAL ARCHITECTURE', 13, GREEN, '600')
        self.text(50, 93, title, 32, TEXT, '700')
        self.text(50, 125, subtitle, 17, MUTED)

    def text(self, x, y, value, size=16, color=TEXT, weight='400'):
        self.parts.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}">{escape(value)}</text>')

    def panel(self, x, y, w, h, label=None, color=LINE, dashed=False):
        dash = ' stroke-dasharray="7 5"' if dashed else ''
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{PANEL}" stroke="{color}" stroke-width="1.5"{dash}/>')
        if label:
            self.text(x+20, y+30, label, 15, color, '600')

    def box(self, x, y, w, h, title, lines, color=GREEN):
        self.panel(x, y, w, h, color=LINE)
        self.parts.append(f'<rect x="{x}" y="{y+12}" width="4" height="{h-24}" rx="2" fill="{color}"/>')
        self.text(x+22, y+34, title, 20, color, '650')
        for i, line in enumerate(lines):
            self.text(x+22, y+64+i*25, line, 16, MUTED)

    def arrow(self, points, label=None, lx=None, ly=None, dashed=False, both=False):
        path = 'M' + ' L'.join(f'{x} {y}' for x, y in points)
        dash = ' stroke-dasharray="6 5"' if dashed else ''
        self.parts.append(f'<path d="{path}" fill="none" stroke="{GREEN}" stroke-width="2"{dash}/>')
        # Explicit geometry keeps direction correct across SVG/PNG renderers.
        ends = [(points[-2], points[-1])]
        if both:
            ends.append((points[1], points[0]))
        for (x0, y0), (x1, y1) in ends:
            length = hypot(x1-x0, y1-y0)
            ux, uy = (x1-x0)/length, (y1-y0)/length
            bx, by = x1-14*ux, y1-14*uy
            vertices = [(x1,y1), (bx-7*uy,by+7*ux), (bx+7*uy,by-7*ux)]
            encoded = ' '.join(f'{x},{y}' for x,y in vertices)
            self.parts.append(f'<polygon points="{encoded}" fill="{GREEN}"/>')
        if label:
            self.text(lx, ly, label, 13, GREEN)

    def save(self, stem):
        self.text(50, self.height-25, 'SOURCE BASELINE 0.4.0 / 2026-11-18   |   Logical flow; intervals are configuration, not an end-to-end SLA.', 13, MUTED)
        self.parts.append('</g></svg>')
        ASSETS.mkdir(parents=True, exist_ok=True)
        (ASSETS / f'{stem}.svg').write_text('\n'.join(self.parts)+'\n', encoding='utf-8')


def overview():
    try:
        from .draw_architecture_overview import render
    except ImportError:
        from draw_architecture_overview import render
    render(ASSETS / 'AEGIS-Design.svg')


def telemetry():
    d=Diagram('Telemetry and native detection', 'Real Windows activity and source references; Atomic identifiers are not detection conditions',1040)
    xs=[50,425,800,1175]; w=275
    d.box(xs[0],180,w,175,'01 / Guest activity',['Pinned Atomic recipes','Native Windows Event Logs','Sysmon 1 / 13; Security','4688 / 4698 / 4699 / 4702'])
    d.box(xs[1],180,w,175,'02 / Winlogbeat',['Standalone guest service','Restricted write API key','HTTPS + CA verification','No Fleet hop for this guest'])
    d.box(xs[2],180,w,175,'03 / Ingest pipeline',['aegis-windows-v1','Process / registry / task fields','event.ingested timestamp','Original winlog data retained'])
    d.box(xs[3],180,w,175,'04 / Source index',['logs-aegis.windows-default','Regular index, not data stream','Activity time: @timestamp','ILM disabled in collector'])
    for a,b,label in [(325,425,'ship'),(700,800,'normalize'),(1075,1175,'index')]:
        d.arrow([(a,270),(b,270)],label,a+12,250)
    d.box(xs[3],470,w,175,'05 / Native rules',['Elastic Security in Kibana','SIEM query + enabled state','Tag aegis; native scheduling','Behavioral conditions only'])
    d.arrow([(1312,355),(1312,470)],'query source',1326,414)
    d.box(xs[2],470,w,175,'06 / Native alerts',['Security alert alias','Depth-zero source ancestor','Detection time + rule UUID','Retained independently of UI'])
    d.arrow([(1175,555),(1075,555)],'signal',1094,537)
    d.box(xs[1],470,w,175,'07 / Projection',['Gateway poll / source _mget','60m lookback; cap 1,000','Hash rule + source index + ID','Idempotent bulk upsert'])
    d.arrow([(800,555),(700,555)],'poll 30s',711,537)
    d.box(xs[0],470,w,175,'08 / Portal alert',['aegis-alerts-default','Source + native alert refs','Group for scope verification','Select one alert to investigate'])
    d.arrow([(425,555),(325,555)],'upsert',345,537)
    d.panel(50,740,680,205)
    d.text(72,774,'TIME AND IDENTITY',18,GREEN,'650')
    for i,line in enumerate(['Source @timestamp ≠ event.ingested ≠ detection time.','Portal scope uses source_event.timestamp, not job creation time.','Native alert ID ≠ portal alert ID ≠ source event ID.','Ledger snapshots do not change when live SIEM rules change.']):
        d.text(72,808+i*30,line,16,MUTED)
    d.panel(770,740,680,205)
    d.text(792,774,'COVERAGE BOUNDARIES',18,GOLD,'650')
    for i,line in enumerate(['A rule hit does not prove execution success or compromise.','No durable bridge cursor; long outages may need backfill.','Source deletion / unsupported ancestry can prevent projection.','Runner records and schedules are excluded from AI evidence.']):
        d.text(792,808+i*30,line,16,MUTED)
    d.save('Telemetry-Detection')


def investigation():
    d=Diagram('AI investigation: bounded fork / join', 'One selected alert; same external model, different role prompts; no autonomous response execution',1170)
    d.box(50,180,400,150,'01 / Analyst selects an alert',['POST /tools/investigations','Absolute scope + incident_id + alert_id','Server verifies membership and coverage'])
    d.box(550,180,400,150,'02 / Durable job + snapshot',['Exactly one alert; independent identity','Dedup active alert jobs; cap 10 active','One worker; queued jobs survive restart'])
    d.box(1050,180,400,150,'03 / Server evidence retrieval',['Same host; selected activity ±2 minutes','Source-first merge; max 20 records','AegisLab / runner metadata excluded'])
    d.arrow([(450,255),(550,255)],'persist',470,237)
    d.arrow([(950,255),(1050,255)],'claim',972,237)
    d.box(1050,420,400,150,'04 / Compact model bundle',['Alert facts + matched source projection','E1… aliases; max 12 behavior groups','Other nearby records remain in audit'])
    d.arrow([(1250,330),(1250,420)],'project',1265,380)
    d.box(550,390,400,125,'05a / Detection analyst · LLM',['Explain observed behavior and rule hit','Cite evidence; distinguish hypotheses'],BLUE)
    d.box(550,570,400,125,'05b / Evidence critic · LLM',['Independently challenge the same facts','Identify gaps and alternatives'],BLUE)
    d.arrow([(1050,470),(1000,470),(1000,450),(950,450)])
    d.arrow([(1000,470),(1000,630),(950,630)])
    d.text(970,549,'parallel',13,GREEN)
    d.box(50,470,400,180,'06 / Validate + join · Server',['All cited IDs must be supplied','Agreement only if both reviews validate','Otherwise final assessment inconclusive','One shared JSON repair budget'])
    d.arrow([(550,450),(495,450),(495,520),(450,520)])
    d.arrow([(550,630),(495,630),(495,600),(450,600)])
    d.box(50,770,400,150,'07 / Report writer · LLM',['Runs only if at least one review validates','Same evidence + valid reviews','Server join remains authoritative'],BLUE)
    d.arrow([(250,650),(250,770)],'valid reviews',265,711)
    d.box(550,770,400,150,'08 / Assemble · Server',['Writer validation; fallback if needed','completed / partial / failed status','Observed facts separated from narrative'])
    d.arrow([(450,845),(550,845)],'validate',466,827)
    d.box(1050,770,400,150,'09 / Persist and show report',['Snapshot + trace → SQLite ledger','Job result → portal report dialog','Close dialog does not cancel the job'])
    d.arrow([(950,845),(1050,845)],'save',980,827)
    d.panel(50,985,1400,110,color=LINE,dashed=True)
    d.text(72,1018,'BUDGET AND FAILURE SEMANTICS',14,GOLD,'650')
    d.text(72,1048,'3 normal model requests; at most 4 with one shared format repair. Timeout 90s per request; no transport retry.',16,MUTED)
    d.text(72,1074,'Raw command lines are excluded. Retrieved records ≠ model-visible records. No tool calls in this orchestration path.',16,MUTED)
    d.save('AI-Investigation')


def deployment():
    d=Diagram('Deployment, network and durable state', 'Logical boundaries and default ports; secrets and runtime artifacts are not documentation assets',1130)
    d.box(50,170,390,140,'Analyst browser',['Portal HTTP :8000 (lab may use :18080)','Optional gateway Bearer token','Kibana login is separate'])
    d.box(1060,170,390,140,'External LLM gateway',['Operator-provided URL / model / key','OpenAI-compatible chat completions','Outside the Docker stack'],BLUE)
    d.panel(30,360,1440,690,'DOCKER COMPOSE HOST / ONE LOCAL LAB',BLUE)
    d.box(550,415,400,140,'FastAPI gateway container',['Single Uvicorn process; two async loops','Container :8000; loopback host publish','ES / Kibana / LLM credentials on server'])
    d.arrow([(440,235),(750,235),(750,415)],'local HTTP / REST',487,219)
    d.arrow([(950,480),(1255,480),(1255,310)],'outbound HTTP(S)',1010,463)
    d.box(550,635,400,150,'Elasticsearch container',['HTTPS :9200 + CA verification','Original logs / projections / native alerts','Host publish is not loopback-only'])
    d.arrow([(750,555),(750,635)],'verified HTTPS',765,600,both=True)
    d.box(50,635,390,150,'Windows VM in launcher container',['QEMU + KVM; 2 CPU / 2 GB default','Standalone Winlogbeat → ES','Web :18006; RDP :13389 loopback'])
    d.arrow([(440,710),(550,710)],'HTTPS',467,692)
    d.box(1060,635,390,150,'Kibana container',['HTTP :5601; native rule management','ES connection uses verified HTTPS','Persistent encryption key required'])
    d.arrow([(1060,710),(950,710)],'HTTPS',971,692)
    d.arrow([(950,535),(1010,535),(1010,610),(1255,610),(1255,635)],'internal HTTP API',1030,590)
    d.panel(50,850,1390,155,color=LINE,dashed=True)
    columns=[(72,'certs / esdata01',['CA + node certificates','Logs, rules and alerts']),
             (415,'investigation_data',['jobs.sqlite3','investigations.sqlite3']),
             (758,'windows_storage',['QEMU guest disk','Stop VM before backup']),
             (1101,'.env / lab/runtime',['Secrets + guest staging','Keep out of publication'])]
    for x,title,lines in columns:
        d.text(x,888,title,17,GREEN,'650')
        for i,line in enumerate(lines):
            d.text(x,922+i*28,line,16,MUTED)
    d.text(50,1080,'Fleet / Elastic Agent and advanced-profile services are separate extension paths, omitted from the primary telemetry topology.',15,MUTED)
    d.save('Deployment-Architecture')


if __name__ == '__main__':
    for build in (overview, telemetry, investigation, deployment):
        build()
    print('Generated 4 SVG architecture diagrams in docs/assets.')
