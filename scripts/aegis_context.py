"""Curated simulator catalog for offline pipeline verification only."""
import json
from pathlib import Path

CATALOG = {row['guid']: row for row in json.loads((Path(__file__).resolve().parents[1] / 'lab/windows/atomic_catalog.json').read_text())}
