#!/usr/bin/env python3
"""
Deploy 14 SDL scheduled-alert detection rules + correlation rules to
SentinelOne XDR / AI SIEM.

Rules are stored at the SDL config path /alerts (Scalyr DataSet alert schema).
When a rule's `trigger` PowerQuery returns >0 rows during its `alertTime`
window, an alert event is fired and surfaces in the AI SIEM Alerts/Findings UI.

After deployment, this script:
  1. Re-ingests all sample-data + trigger-detection logs (with fresh timestamps)
     to ensure the rules will trigger on next evaluation cycle.
  2. Validates by running each rule's trigger query directly via PowerQuery
     to confirm the rule WOULD fire right now.

Usage:
    python3 deploy_detection_rules.py
"""

import json, sys, time, re, requests
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

ROOT = Path(__file__).parent
NOW = datetime.now(timezone.utc)


def load_rules() -> dict:
    """Load the rules JSON. Strip non-Scalyr-schema fields (name, description,
    severity) into a separate `comment` and only keep the trigger schema fields."""
    raw = json.loads((ROOT / "detection-rules" / "alerts.json").read_text())
    cleaned = {"alerts": []}
    for r in raw["alerts"]:
        cleaned["alerts"].append({
            "trigger": r["trigger"],
            "alertTime": r.get("alertTime", 300),
            "renotifyPeriodMinutes": r.get("renotifyPeriodMinutes", 60),
            "description": f"[{r.get('severity','Info')}] {r['name']} — {r.get('description','')}",
        })
    return cleaned, raw["alerts"]


def deploy(client_cfg, rules_payload):
    print("=" * 78)
    print("DEPLOY ALERT RULES → /alerts")
    print("=" * 78)
    r = requests.post(
        f"{client_cfg['base_url']}/api/putFile",
        json={
            "token": client_cfg["config_write_key"],
            "path": "/alerts",
            "content": json.dumps(rules_payload, indent=2),
        },
        timeout=30,
    )
    print(f"PUT /alerts → {r.status_code} {r.text[:300]}")
    return r.status_code == 200


def refresh_timestamps_in_json(text: str) -> str:
    iso_z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")
    return iso_z.sub(NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z", text)


# Same ingest mapping as trigger_all_detections.py
INGESTS = [
    ("sample-data/qradar.log",                "QRadar-OCSF",          "qradar-ocsf",     True),
    ("sample-data/fortinet-fortigate.log",    "FortiGate-OCSF",       "fortigate-ocsf",  False),
    ("sample-data/windows-security.log",      "WindowsSecurity-OCSF", "windows-ocsf",    False),
    ("sample-data/checkpoint.log",            "CheckPoint-OCSF",      "checkpoint-ocsf", False),
    ("sample-data/oracle-rdbms-audit.log",    "OracleRDBMS-OCSF",     "oracle-ocsf",     False),
    ("sample-data/paloalto-pa.log",           "PaloAlto-OCSF",        "paloalto-ocsf",   False),
    ("sample-data/microsoft-dns-debug.log",   "MicrosoftDNS-OCSF",    "msdns-ocsf",      False),
    ("sample-data/sim-generic.log",           "SIMGeneric-OCSF",      "sim-ocsf",        False),
    ("sample-data/f5-bigip.log",              "F5BigIP-OCSF",         "f5ltm-ocsf",      False),
    ("sample-data/watchguard-fireware.log",   "WatchGuard-OCSF",      "watchguard-ocsf", False),
    ("sample-data/microsoft-entra-id.log",    "EntraID-OCSF",         "entra-ocsf",      True),
    ("sample-data/microsoft-dhcp.log",        "MicrosoftDHCP-OCSF",   "msdhcp-ocsf",     False),
    ("sample-data/isc-bind.log",              "ISCBIND-OCSF",         "bind-ocsf",       False),
    ("sample-data/f5-bigip-apm.log",          "F5APM-OCSF",           "f5apm-ocsf",      False),
    ("sample-data/linux-os.log",              "LinuxOS-OCSF",         "linux-ocsf",      False),
    ("sample-data/hana-database.log",         "HANADatabase-OCSF",    "hana-ocsf",       True),
    ("trigger-detections/brute-force-attack.log",    "LinuxOS-OCSF",         "linux-ocsf",     False),
    ("trigger-detections/port-scan-lateral.log",     "FortiGate-OCSF",       "fortigate-ocsf", False),
    ("trigger-detections/suspicious-processes.log",  "LinuxOS-OCSF",         "linux-ocsf",     False),
    ("trigger-detections/dns-attacks.log",           "ISCBIND-OCSF",         "bind-ocsf",      False),
    ("trigger-detections/database-attacks.log",      "HANADatabase-OCSF",    "hana-ocsf",      True),
    ("trigger-detections/cloud-identity-attacks.log","EntraID-OCSF",         "entra-ocsf",     True),
    ("trigger-detections/c2-traffic.log",            "FortiGate-OCSF",       "fortigate-ocsf", False),
]


def ingest(client):
    print("\n" + "=" * 78)
    print("INGEST SAMPLE + TRIGGER LOGS")
    print("=" * 78)
    for fpath, parser, host, refresh in INGESTS:
        p = ROOT / fpath
        if not p.exists():
            continue
        body = p.read_text()
        if refresh:
            body = refresh_timestamps_in_json(body)
        try:
            client.upload_logs(log_data=body, parser=parser, server_host=host, log_file=p.name)
            print(f"  OK   {host:18s} ← {parser:22s} ({len(body):>5} bytes)")
        except Exception as e:
            print(f"  FAIL {host:18s}: {str(e)[:100]}")
        time.sleep(0.2)


def validate(client, named_rules):
    print("\n" + "=" * 78)
    print("WAITING 20s FOR INDEXING")
    print("=" * 78)
    time.sleep(20)

    print("\n" + "=" * 78)
    print("VALIDATE RULES — running each trigger query directly")
    print("=" * 78)
    fired = 0
    for r in named_rules:
        print(f"\n▶ [{r['severity']:<8}] {r['name']}")
        print(f"  PQ: {r['trigger']}")
        try:
            resp = client.power_query(query=r["trigger"], start_time="1d")
            total = int(resp.get("matchingEvents", 0))
            rows  = resp.get("values") or []
            ok = "✓ FIRED" if total > 0 else "· quiet"
            print(f"  {ok}  matchingEvents={total} groups={len(rows)}")
            if total > 0:
                fired += 1
        except Exception as e:
            print(f"  ERR: {str(e)[:200]}")

    print("\n" + "=" * 78)
    print(f"SUMMARY: {fired}/{len(named_rules)} rules would fire RIGHT NOW")
    print("=" * 78)
    print("\nThe rules are deployed at /alerts and will be evaluated by SDL on")
    print("their schedule (alertTime seconds). Triggered alerts appear in:")
    print("  AI SIEM Console → Alerts (or Findings)")


def main():
    cfg = json.loads((Path(__file__).parent.parent / "config.json").read_text())
    client = SDLClient()
    print(f"SDL: {cfg['base_url']}\n")

    rules_payload, named_rules = load_rules()
    print(f"Loaded {len(named_rules)} rules from detection-rules/alerts.json\n")

    if not deploy(cfg, rules_payload):
        print("Deploy failed — aborting.")
        sys.exit(1)

    ingest(client)
    validate(client, named_rules)


if __name__ == "__main__":
    main()
