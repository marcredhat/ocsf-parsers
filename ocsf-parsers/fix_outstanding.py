#!/usr/bin/env python3
"""Redeploy Windows + F5 + F5-APM parsers, re-ingest, and validate findings."""
import json, sys, time, requests
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

cfg = json.loads(Path('../config.json').read_text())
client = SDLClient()

PARSERS = [
    ('windows-security.conf', 'WindowsSecurity-OCSF', 'windows-security.log',  'windows-ocsf'),
    ('f5-bigip.conf',         'F5BigIP-OCSF',         'f5-bigip.log',          'f5ltm-ocsf'),
    ('f5-bigip-apm.conf',     'F5APM-OCSF',           'f5-bigip-apm.log',      'f5apm-ocsf'),
]

print("=" * 60)
print("DEPLOY")
print("=" * 60)
for fname, pname, _, _ in PARSERS:
    content = Path(f'parsers/{fname}').read_text()
    r = requests.post(f"{cfg['base_url']}/api/putFile",
                      json={'token': cfg['config_write_key'], 'path': f'/logParsers/{pname}', 'content': content},
                      timeout=30)
    if r.status_code == 200:
        print(f"OK   {pname}")
    else:
        try: err = r.json().get('message', r.text)
        except: err = r.text
        print(f"FAIL {pname}: {err[:200]}")

print("\n" + "=" * 60)
print("INGEST")
print("=" * 60)
for _, pname, sample, host in PARSERS:
    body = Path(f'sample-data/{sample}').read_text()
    client.upload_logs(log_data=body, parser=pname, server_host=host, log_file=sample)
    print(f"OK  {host} via {pname} ({len(body)}b)")

print("\nWaiting 15s for indexing...\n")
time.sleep(15)

print("=" * 60)
print("VALIDATE")
print("=" * 60)
queries = [
    ("Windows findings",
     "serverHost='windows-ocsf' AND class_uid='2004' | group n=count() by finding_title | sort -n"),
    ("F5 LTM findings",
     "serverHost='f5ltm-ocsf' AND class_uid='2004' | group n=count() by finding_title | sort -n"),
    ("F5 APM findings",
     "serverHost='f5apm-ocsf' AND class_uid='2004' | group n=count() by finding_title | sort -n"),
    ("Updated grand total of all Detection Findings",
     "class_uid='2004' | group n=count() by serverHost | sort -n"),
]
for title, q in queries:
    print(f"\n▶ {title}")
    print(f"  PQ: {q}")
    try:
        r = client.power_query(query=q, start_time="1d")
        print(f"  matchingEvents={r.get('matchingEvents', 0)}")
        for row in (r.get('values') or [])[:15]:
            print(f"    {row}")
    except Exception as e:
        print(f"  ERR: {str(e)[:200]}")
