#!/usr/bin/env python3
"""
Trigger every detection across all 16 OCSF parsers and validate via PowerQuery.

For each parser, we:
1. Re-ingest the sample data WITH FRESH TIMESTAMPS (where applicable) so the
   logs land in the recent-events window of XDR.
2. Re-ingest dedicated trigger-detection logs through the correct parsers.
3. Run a PowerQuery to confirm Detection Findings (class_uid=2004) appear.
"""

import json, sys, time, re
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

ROOT = Path(__file__).parent
NOW = datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Mapping: each entry feeds the right parser with the right serverHost
# ─────────────────────────────────────────────────────────────────────────────
INGESTS = [
    # (sample_file_path, parser_name, server_host, refresh_timestamps)
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

    # Dedicated trigger logs (route to the most appropriate parser)
    ("trigger-detections/brute-force-attack.log",    "LinuxOS-OCSF",         "linux-ocsf",     False),
    ("trigger-detections/port-scan-lateral.log",     "FortiGate-OCSF",       "fortigate-ocsf", False),
    ("trigger-detections/suspicious-processes.log",  "LinuxOS-OCSF",         "linux-ocsf",     False),
    ("trigger-detections/dns-attacks.log",           "ISCBIND-OCSF",         "bind-ocsf",      False),
    ("trigger-detections/database-attacks.log",      "HANADatabase-OCSF",    "hana-ocsf",      True),
    ("trigger-detections/cloud-identity-attacks.log","EntraID-OCSF",         "entra-ocsf",     True),
    ("trigger-detections/c2-traffic.log",            "FortiGate-OCSF",       "fortigate-ocsf", False),
]


def refresh_timestamps_in_json(text: str) -> str:
    """Replace any ISO-Z timestamp in JSON logs with NOW so events land in the
    1-day query window."""
    iso_z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")
    return iso_z.sub(NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z", text)


def ingest(client):
    print("=" * 78)
    print("INGESTING SAMPLE + TRIGGER LOGS")
    print("=" * 78)
    for fpath, parser, host, refresh in INGESTS:
        p = ROOT / fpath
        if not p.exists():
            print(f"  SKIP {fpath} (missing)")
            continue
        body = p.read_text()
        if refresh:
            body = refresh_timestamps_in_json(body)
        try:
            client.upload_logs(log_data=body, parser=parser, server_host=host, log_file=p.name)
            print(f"  OK   {host:18s} ← {parser:22s} ({len(body):>5} bytes) {fpath}")
        except Exception as e:
            print(f"  FAIL {host:18s} {parser}: {str(e)[:100]}")
        time.sleep(0.25)


# ─────────────────────────────────────────────────────────────────────────────
# Validation queries — run after ingest, print results
# ─────────────────────────────────────────────────────────────────────────────
VALIDATION_QUERIES = [
    ("01 ─ All Detection Findings by source",
        "class_uid='2004' | group hits=count() by serverHost, finding_title | sort -hits"),
    ("02 ─ Detection Findings by severity",
        "class_uid='2004' | group hits=count() by severity, severity_id | sort -hits"),
    ("03 ─ Critical findings only",
        "class_uid='2004' AND severity_id='5' | group hits=count() by serverHost, finding_title | sort -hits"),
    ("04 ─ HANA database attacks (brute force / mass exfil / privesc)",
        "serverHost='hana-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),
    ("05 ─ FortiGate IPS / suspicious port detections",
        "serverHost='fortigate-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),
    ("06 ─ Linux SSH brute force / sudo failures / credential dumping",
        "serverHost='linux-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),
    ("07 ─ Windows logon failures / new accounts / log clearing",
        "serverHost='windows-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),
    ("08 ─ BIND DNS tunneling / zone transfer / dynamic DNS",
        "serverHost='bind-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),
    ("09 ─ Entra ID risky sign-ins (high risk, Tor, auth failures)",
        "serverHost='entra-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),
    ("10 ─ F5 WAF / SQL injection / MFA bypass",
        "(serverHost='f5ltm-ocsf' OR serverHost='f5apm-ocsf') AND class_uid='2004' | group hits=count() by serverHost, finding_title | sort -hits"),
    ("11 ─ QRadar SIEM correlations promoted to Findings",
        "serverHost='qradar-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),
    ("12 ─ Top attacker IPs across all detections",
        "class_uid='2004' AND src_ip != '' | group hits=count() by src_ip | sort -hits | limit 20"),
    ("13 ─ Authentication failures across IAM-class events",
        "class_uid='3002' AND status_id='2' | group hits=count() by serverHost, user_name | sort -hits"),
    ("14 ─ Cross-source kill chain summary (count by class_name)",
        "class_uid='2004' | group hits=count() by class_name, finding_title | sort -hits | limit 30"),
    ("15 ─ Most active OCSF data sources (event volume)",
        "* | group events=count() by serverHost | sort -events"),
]


def validate(client):
    print("\n" + "=" * 78)
    print("WAITING 20s FOR INDEXING")
    print("=" * 78)
    time.sleep(20)

    print("\n" + "=" * 78)
    print("DETECTION VALIDATION QUERIES")
    print("=" * 78)

    summary = []
    for title, q in VALIDATION_QUERIES:
        print(f"\n▶ {title}")
        print(f"  PQ: {q}")
        try:
            r = client.power_query(query=q, start_time="1d")
            rows = r.get("values", []) or []
            total = int(r.get("matchingEvents", 0))
            print(f"  matchingEvents={total}, rows={len(rows)}")
            for row in rows[:15]:
                print(f"    {row}")
            summary.append((title, total, len(rows)))
        except Exception as e:
            print(f"  ERR: {str(e)[:200]}")
            summary.append((title, -1, 0))

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    for title, total, rows in summary:
        marker = "✓" if total > 0 else "·" if total == 0 else "✗"
        print(f"  {marker} {title:60s} events={total:>6}  groups={rows}")


def main():
    client = SDLClient()
    print(f"SDL: {client.base_url}")
    print(f"NOW: {NOW.isoformat()}\n")
    ingest(client)
    validate(client)


if __name__ == "__main__":
    main()
