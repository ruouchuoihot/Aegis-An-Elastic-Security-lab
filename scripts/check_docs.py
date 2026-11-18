"""Validate local documentation links, diagram pairs and the source OpenAPI snapshot.

No services, credentials or provider calls are needed. Use --update-openapi after
intentional API changes, then review the resulting JSON diff.
"""
import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STEMS = ('AEGIS-Design', 'Telemetry-Detection', 'AI-Investigation', 'Deployment-Architecture')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--update-openapi', action='store_true')
    args = parser.parse_args()
    from scripts.aegis_ai_gateway import app
    snapshot = ROOT / 'docs/reference/openapi.json'
    current = app.openapi()
    if args.update_openapi:
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    failures = []
    documents = [ROOT/'README.md', *sorted((ROOT/'docs').rglob('*.md'))]
    links = 0
    for document in documents:
        content = document.read_text(encoding='utf-8-sig')
        # Inline links used by this repository. Anchors/external URLs are not fetched.
        for target in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', content):
            target = target.strip().strip('<>')
            if re.match(r'^(?:https?://|mailto:|#)', target):
                continue
            target = unquote(target.split('#', 1)[0].split('?', 1)[0])
            if not target:
                continue
            links += 1
            if not (document.parent / target).exists():
                failures.append(f'{document.relative_to(ROOT)}: missing local link {target}')
    ns = {'s': 'http://www.w3.org/2000/svg'}
    for stem in STEMS:
        svg = ROOT/f'docs/assets/{stem}.svg'
        png = ROOT/f'docs/assets/{stem}.png'
        try:
            tree = ET.parse(svg).getroot()
            if tree.find('s:title', ns) is None or tree.find('s:desc', ns) is None:
                failures.append(f'{stem}: missing accessible title/description')
            header = png.read_bytes()[:24]
            if not header.startswith(b'\x89PNG\r\n\x1a\n'):
                failures.append(f'{stem}: invalid PNG signature')
            elif (int.from_bytes(header[16:20], 'big'), int.from_bytes(header[20:24], 'big')) != (int(tree.attrib['width']), int(tree.attrib['height'])):
                failures.append(f'{stem}: SVG/PNG size mismatch')
        except (OSError, ET.ParseError, KeyError, ValueError) as exc:
            failures.append(f'{stem}: {type(exc).__name__}')
    try:
        if json.loads(snapshot.read_text(encoding='utf-8')) != current:
            failures.append('OpenAPI drift: review API changes and run --update-openapi')
    except (OSError, ValueError):
        failures.append('OpenAPI snapshot missing or invalid: run --update-openapi')
    for failure in failures:
        print(f'ERROR: {failure}')
    if failures:
        return 1
    print(f'OK: {len(documents)} Markdown files, {links} local links, 4 SVG/PNG pairs, OpenAPI {len(current["paths"])} paths.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
