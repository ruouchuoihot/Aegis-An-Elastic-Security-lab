"""Editable architecture overview following the supplied three-column design."""
from html import escape
from math import hypot
from pathlib import Path

TEAL = '#087d89'
BLUE = '#093c84'
PURPLE = '#63339a'
INK = '#101828'


def render(output):
    out = ['''<svg xmlns="http://www.w3.org/2000/svg" width="1840" height="1040" viewBox="0 0 1840 1040" role="img" aria-labelledby="title desc">
<title id="title">Project Aegis Architecture</title>
<desc id="desc">Three-column architecture: Atomic Red Team simulates activity on Windows, Winlogbeat sends endpoint events to Elasticsearch, Elastic Security produces native SIEM alerts, and Aegis pulls alerts via API for parallel analyst and critic reviews, server join, report writing and SQLite audit storage. The LLM gateway is external.</desc>
<defs>
  <linearGradient id="tealHead" x2="1" y2="1"><stop stop-color="#087d89"/><stop offset="1" stop-color="#086773"/></linearGradient>
  <linearGradient id="blueHead" x2="1" y2="1"><stop stop-color="#073e8b"/><stop offset="1" stop-color="#08316b"/></linearGradient>
  <linearGradient id="purpleHead" x2="1" y2="1"><stop stop-color="#693aa0"/><stop offset="1" stop-color="#542788"/></linearGradient>
  <linearGradient id="cardFill" x2="0" y2="1"><stop stop-color="#ffffff"/><stop offset="1" stop-color="#f9fbfd"/></linearGradient>
  <filter id="shadow" x="-10%" y="-15%" width="125%" height="135%"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#15334d" flood-opacity="0.10"/></filter>
</defs>
<rect width="1840" height="1040" fill="white"/>
<g font-family="Arial,Segoe UI,sans-serif">''']

    def text(x, y, value, size=18, color=INK, bold=False, anchor='start', italic=False):
        style = ' font-style="italic"' if italic else ''
        out.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{700 if bold else 400}" text-anchor="{anchor}"{style}>{escape(value)}</text>')

    def rect(x, y, w, h, color, dashed=False, fill='url(#cardFill)', radius=12):
        dash = ' stroke-dasharray="9 6"' if dashed else ''
        out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{color}" stroke-width="2.3" filter="url(#shadow)"{dash}/>')

    def panel(x, y, w, h, title, color, gradient):
        rect(x,y,w,h,color,fill='white',radius=17)
        out.append(f'<path d="M{x+17} {y} H{x+w-17} Q{x+w} {y} {x+w} {y+17} V{y+55} H{x} V{y+17} Q{x} {y} {x+17} {y} Z" fill="url(#{gradient})"/>')
        text(x+w/2,y+37,title,26,'white',True,'middle')

    def edge(points, color=INK, dashed=False, both=False, arrow=True):
        d = 'M'+' L'.join(f'{x} {y}' for x,y in points)
        out.append(f'<path d="{d}" fill="none" stroke="white" stroke-width="7"/>')
        dash=' stroke-dasharray="8 6"' if dashed else ''
        out.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2.2"{dash}/>')
        if not arrow:
            return
        ends=[(points[-2],points[-1])]
        if both:
            ends.append((points[1],points[0]))
        for (x0,y0),(x,y) in ends:
            length=hypot(x-x0,y-y0)
            ux,uy=(x-x0)/length,(y-y0)/length
            bx,by=x-12*ux,y-12*uy
            out.append(f'<polygon points="{x},{y} {bx-6*uy},{by+6*ux} {bx+6*uy},{by-6*ux}" fill="{color}"/>')

    def icon(kind,x,y,size,color):
        out.append(f'<g transform="translate({x},{y}) scale({size/64})" fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">')
        if kind=='database':
            out.append('<ellipse cx="32" cy="12" rx="23" ry="9"/><path d="M9 12 V50 C9 62 55 62 55 50 V12 M9 30 C9 42 55 42 55 30 M9 44 C9 56 55 56 55 44"/>')
        elif kind=='monitor':
            out.append('<rect x="6" y="7" width="52" height="36" rx="3"/><path d="M32 43 V55 M19 56 H45"/>')
        elif kind=='windows':
            out.append(f'<path d="M6 10 L29 7 V29 H6 Z M35 6 L59 3 V29 H35 Z M6 35 H29 V57 L6 54 Z M35 35 H59 V61 L35 58 Z" fill="{color}" stroke="none"/>')
        elif kind=='atomic':
            out.append(f'<path d="M10 52 L38 24 L46 32 L18 60 Z" fill="{color}"/><path d="M17 8 V22 M10 15 H24 M48 4 V20 M40 12 H56 M52 41 V55 M45 48 H59"/>')
        elif kind=='events':
            out.append('<path d="M32 3 L55 13 V32 Q55 48 32 60 Q9 48 9 32 V13 Z"/><path d="M21 23 H43 M21 32 H43 M21 41 H35"/>')
        elif kind=='beat':
            out.append('<path d="M4 34 H14 L21 13 L31 52 L42 20 L49 34 H60"/>')
        elif kind=='server':
            for yy in [5,25,45]:
                out.append(f'<rect x="8" y="{yy}" width="48" height="14" rx="3" fill="{color}" stroke="none"/><circle cx="46" cy="{yy+7}" r="2" fill="white" stroke="none"/><circle cx="39" cy="{yy+7}" r="2" fill="white" stroke="none"/>')
        elif kind=='elastic':
            out.append('<path d="M9 17 C19 0 48 0 58 17 L48 24 H17 Z" fill="#fecb19" stroke="none"/><path d="M8 26 H43 Q56 32 43 38 H8 Z" fill="#0873b8" stroke="none"/><path d="M7 26 H24 V38 H7 Z" fill="#232f3e" stroke="none"/><path d="M10 42 H48 L58 49 C45 66 19 64 9 47 Z" fill="#00b6ad" stroke="none"/>')
        elif kind=='kibana':
            out.append('<path d="M7 4 H57 L7 54 Z" fill="#ef287e" stroke="none"/><path d="M7 32 Q44 32 57 58 H7 Z" fill="#00a59e" stroke="none"/><path d="M7 32 L30 32 L7 54 Z" fill="#007a85" stroke="none"/>')
        elif kind=='network':
            out.append('<path d="M32 10 L10 24 L10 47 L32 58 L54 45 L54 23 Z M32 10 V58 M10 24 L54 45 M54 23 L10 47"/>')
            for xx,yy in [(32,10),(10,24),(10,47),(32,58),(54,45),(54,23),(32,34)]:
                out.append(f'<circle cx="{xx}" cy="{yy}" r="5" fill="white"/>')
        elif kind=='analyst':
            out.append('<circle cx="24" cy="16" r="10"/><path d="M6 49 Q6 30 24 30 Q34 30 39 37"/><circle cx="45" cy="43" r="11"/><path d="M53 51 L61 60"/>')
        elif kind=='critic':
            out.append('<path d="M32 4 L54 14 V32 Q54 48 32 60 Q10 48 10 32 V14 Z"/><path d="M22 24 Q22 14 32 14 Q44 14 42 25 Q42 30 32 34 V40"/><circle cx="32" cy="48" r="1.5" fill="currentColor"/>')
        elif kind=='join':
            out.append('<path d="M10 6 V23 Q10 32 32 37 M54 6 V23 Q54 32 32 37 M32 37 V58 M24 50 L32 58 L40 50"/>')
        elif kind=='document':
            out.append('<path d="M13 3 H41 L54 16 V61 H13 Z M41 3 V17 H54 M23 29 H44 M23 38 H44 M23 47 H39"/>')
        elif kind=='sync':
            out.append('<path d="M13 25 A22 22 0 0 1 52 18 M52 7 V20 H39 M51 39 A22 22 0 0 1 12 46 M12 57 V44 H25"/>')
        out.append('</g>')

    def card(x,y,w,h,title,lines,kind,color,dashed=False,head_size=23,body_size=17,icon_size=52):
        rect(x,y,w,h,color,dashed)
        icon(kind,x+18,y+(h-icon_size)/2,icon_size,color)
        tx=x+icon_size+34
        text(tx,y+36,title,head_size,INK,True)
        for i,line in enumerate(lines):
            text(tx,y+64+i*24,line,body_size,INK)

    text(920,62,'Project Aegis Architecture',48,'#080e21',True,'middle')
    panel(45,100,350,840,'Telemetry & Simulation',TEAL,'tealHead')
    panel(425,100,765,840,'Elastic 8.x Core',BLUE,'blueHead')
    panel(1220,100,575,840,'AI & Investigation',PURPLE,'purpleHead')

    card(75,225,290,145,'Atomic Red Team',['ATT&CK test execution','Scheduled simulation','Test cleanup'],'atomic',TEAL,head_size=21,body_size=16)
    card(75,445,290,145,'Windows Endpoint',['Sysmon · Security','PowerShell event logging','Process · registry · tasks'],'events',TEAL,head_size=20,body_size=15)
    card(75,665,290,145,'Winlogbeat',['Collect Windows channels','Buffer · retry delivery','HTTPS + scoped API key'],'beat',TEAL,body_size=15)
    text(220,921,'Atomic metadata stays outside AI evidence',14,TEAL,anchor='middle')
    edge([(220,370),(220,445)],TEAL)
    text(235,412,'native activity',15,INK)
    edge([(220,590),(220,665)],TEAL)
    text(235,632,'collect events',15,INK)

    rect(460,225,350,585,BLUE)
    icon('elastic',480,253,54,BLUE)
    text(547,280,'Elasticsearch',27,INK,True)
    text(635,335,'Ingest pipelines · ECS normalization',16,INK,anchor='middle')
    text(635,361,'Index · store · search · aggregate',16,INK,anchor='middle')
    for yy,label,size in [(425,'logs-aegis.windows-default',16),(560,'.alerts-security.alerts-default',14)]:
        rect(480,yy,310,80,BLUE,fill='#f2f6ff',radius=7)
        icon('database',491,yy+25,27,BLUE)
        text(528,yy+46,label,size,INK)
    text(635,710,'Original endpoint events',16,INK,anchor='middle')
    text(635,736,'Native SIEM alerts · source references',15,INK,anchor='middle')

    rect(875,225,280,585,BLUE)
    icon('kibana',930,249,45,BLUE)
    text(990,282,'Kibana',28,INK,True)
    text(1015,321,'Explore · visualize · investigate · manage',14,INK,anchor='middle')
    for yy,title,lines in [
        (370,'Discover',['Log search · filters · event inspection']),
        (465,'Dashboards / Lens',['Charts · tables · visual analysis']),
        (700,'Stack Management',['Data views · saved objects · access']),
    ]:
        rect(895,yy,240,75,BLUE,fill='#f2f6ff',radius=7)
        text(1015,yy+28,title,20,INK,True,'middle')
        text(1015,yy+54,lines[0],13,INK,anchor='middle')
    rect(895,560,240,120,BLUE,fill='#f2f6ff',radius=7)
    text(1015,588,'Elastic Security',20,INK,True,'middle')
    text(1015,615,'Detection rules · schedules · alerts',14,INK,anchor='middle')
    text(1015,640,'Severity · risk · rule editing',14,INK,anchor='middle')
    text(1015,664,'Timeline · Cases (in Kibana)',14,INK,anchor='middle')

    edge([(365,737),(460,737)])
    text(412,723,'HTTPS',13,INK,anchor='middle')
    edge([(810,390),(875,390)],both=True)
    text(842,364,'queries',12,INK,anchor='middle')
    text(842,380,'results',12,INK,anchor='middle')
    edge([(895,600),(790,600)],TEAL)
    text(842,624,'alerts',12,INK,anchor='middle')

    card(1260,190,225,120,'Aegis Portal',['Priority triage · filters','AI analysis · progress','Reports · operations'],'monitor',PURPLE,head_size=21,body_size=14,icon_size=39)
    card(1530,190,225,120,'External LLM',['OpenAI-compatible API','Model inference','Analyst · critic · writer'],'network',PURPLE,True,head_size=20,body_size=14,icon_size=39)
    card(1260,355,495,120,'AI Gateway / FastAPI',['Pull alerts · retrieve evidence · correlate','Scope checks · queued job orchestration','REST APIs · SIEM integration · MCP adapter'],'network',PURPLE,head_size=26,body_size=17,icon_size=57)
    edge([(1372,310),(1372,355)],PURPLE)
    text(1390,339,'REST',14,INK)
    edge([(1642,355),(1642,310)],PURPLE,True)
    text(1659,339,'chat completions',14,INK)

    # Show the SIEM API boundary without deployment or polling internals.
    edge([(1260,405),(1205,405),(1205,190),(840,190),(840,280),(810,280)],PURPLE,both=True)
    text(1025,180,'Pull alerts via API',17,INK,anchor='middle')

    card(1260,535,225,120,'Detection',['Analyst','Behavior + indicators','Cited assessment'],'analyst',PURPLE,head_size=22,body_size=14,icon_size=42)
    card(1530,535,225,120,'Evidence',['Critic · evidence gaps','Alternative causes','Independent review'],'critic',PURPLE,head_size=22,body_size=14,icon_size=42)
    edge([(1507,475),(1507,510),(1372,510),(1372,535)],PURPLE)
    edge([(1507,510),(1642,510),(1642,535)],PURPLE)
    text(1507,499,'same evidence · parallel reviews',14,INK,anchor='middle')
    card(1385,685,245,100,'Server Join',['Validate evidence + verdict','Resolve review agreement'],'join',PURPLE,head_size=22,body_size=12,icon_size=35)
    edge([(1372,655),(1372,675),(1507,675),(1507,685)],PURPLE)
    edge([(1642,655),(1642,675),(1507,675)],PURPLE,arrow=False)
    card(1260,810,225,105,'Report Writer',['Summarize joined findings','Evidence · gaps · next steps'],'document',PURPLE,head_size=20,body_size=12,icon_size=37)
    card(1530,810,225,105,'SQLite Ledger',['Queue · stages · results','Snapshots · hash chain'],'database',PURPLE,head_size=20,body_size=13,icon_size=37)
    edge([(1507,785),(1507,798),(1372,798),(1372,810)],PURPLE)
    text(1385,794,'valid reviews',12,INK)
    edge([(1485,862),(1530,862)],PURPLE)
    text(1507,846,'save',12,INK,anchor='middle')

    # Compact legend, matching the supplied diagram's border and arrow language.
    edge([(55,1002),(125,1002)])
    text(138,1008,'Primary data / API flow',15,INK)
    edge([(430,1002),(500,1002)],PURPLE,True)
    text(513,1008,'External LLM API',15,INK)
    rect(800,988,46,28,BLUE,fill='white',radius=5)
    text(860,1008,'Elastic components',15,INK)
    rect(1150,988,46,28,PURPLE,fill='white',radius=5)
    text(1210,1008,'Aegis / AI components',15,INK)
    icon('database',1545,986,31,BLUE)
    text(1590,1008,'ES index / alias',15,INK)
    out.append('</g></svg>')
    target=Path(output)
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text('\n'.join(out)+'\n',encoding='utf-8')
