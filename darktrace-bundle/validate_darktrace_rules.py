#!/usr/bin/env python3
"""Validate the 3 Darktrace-specific detection rules fire on current data."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

c = SDLClient()
print(f"Tenant: {c.base_url}\n")

RULES = [
    ("Darktrace AI Analyst Incident",
     "parser='Darktrace-OCSF' AND finding_title contains 'AI Analyst' "
     "| group n=count() by serverHost, src_ip, finding_title | filter n >= 1"),
    ("Darktrace Antigena Autonomous Response Triggered",
     "parser='Darktrace-OCSF' AND finding_title contains 'Antigena' "
     "| group n=count() by src_ip, dst_ip, action | filter n >= 1"),
    ("Darktrace Model Breach High Score (>=80)",
     "parser='Darktrace-OCSF' AND model_name != null AND score >= '80' "
     "| group n=count() by src_ip, model_name, score | filter n >= 1"),
]

for name, q in RULES:
    try:
        r = c.power_query(query=q, start_time="1d")
        n = int(r.get("matchingEvents", 0) or 0)
        rows = r.get("values") or []
        status = "FIRE" if rows else "no rows"
        print(f"[{status:7s}] {name}")
        for row in rows[:3]:
            print(f"           {row}")
    except Exception as e:
        print(f"[ERR    ] {name} -> {str(e)[:120]}")
