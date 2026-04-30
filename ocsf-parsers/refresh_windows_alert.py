#!/usr/bin/env python3
"""Re-ingest Windows Security sample with fresh timestamps to trigger
the 'Windows New User Account Or Privilege Escalation' detection rule."""
import sys, re, time
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

NOW = datetime.now(timezone.utc)
SAMPLE = Path(__file__).parent / "sample-data" / "windows-security.log"
body = SAMPLE.read_text()

# Stamp each event walking forward in 30s increments, ending at NOW
counter = {"i": 0}
def replace(m):
    counter["i"] += 1
    return ""  # placeholder; we count first

events = len(re.findall(r'<TimeCreated SystemTime="[^"]+"/>', body))
print(f"Events in sample: {events}")

START = NOW - timedelta(minutes=5)
counter["i"] = 0
def stamp(_m):
    t = START + timedelta(seconds=counter["i"] * (300 // max(events, 1)))
    counter["i"] += 1
    return f'<TimeCreated SystemTime="{t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3]}Z"/>'

body = re.sub(r'<TimeCreated SystemTime="[^"]+"/>', stamp, body)
print(f"Stamped {counter['i']} events spread over {START:%H:%M:%S}–{NOW:%H:%M:%S} UTC")

c = SDLClient()
r = c.upload_logs(log_data=body, parser="WindowsSecurity-OCSF",
                  server_host="windows-ocsf", log_file="windows-security.log")
print(f"Ingest response: {r}")

print("\nWaiting 15s for indexing...")
time.sleep(15)

q = ("serverHost='windows-ocsf' AND class_uid='2004' "
     "AND (finding_title contains '4720' OR finding_title contains '4732') "
     "| group n=count(), latest=max(timestamp) by finding_title")
r = c.power_query(query=q, start_time="10m")
print(f"\nLast-10-min query: matchingEvents={r.get('matchingEvents')}")
for row in r.get("values") or []:
    print(f"  {row}")

print("\n" + "=" * 70)
print("Detection rule will fire on its next 5-min eval cycle.")
print("Check: AI SIEM → Detect → Findings  (within 5 min)")
print("=" * 70)
