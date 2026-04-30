#!/usr/bin/env python3
"""Deploy all 16 OCSF parsers, ingest sample data, validate Detection Findings."""

import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

ROOT = Path(__file__).parent

# (parser_file, parser_name, sample_file, server_host)
PARSERS = [
    ("qradar.conf",              "QRadar-OCSF",          "qradar.log",                "qradar-ocsf"),
    ("fortinet-fortigate.conf",  "FortiGate-OCSF",       "fortinet-fortigate.log",    "fortigate-ocsf"),
    ("windows-security.conf",    "WindowsSecurity-OCSF", "windows-security.log",      "windows-ocsf"),
    ("checkpoint.conf",          "CheckPoint-OCSF",      "checkpoint.log",            "checkpoint-ocsf"),
    ("oracle-rdbms-audit.conf",  "OracleRDBMS-OCSF",     "oracle-rdbms-audit.log",    "oracle-ocsf"),
    ("paloalto-pa.conf",         "PaloAlto-OCSF",        "paloalto-pa.log",           "paloalto-ocsf"),
    ("microsoft-dns-debug.conf", "MicrosoftDNS-OCSF",    "microsoft-dns-debug.log",   "msdns-ocsf"),
    ("sim-generic.conf",         "SIMGeneric-OCSF",      "sim-generic.log",           "sim-ocsf"),
    ("f5-bigip.conf",            "F5BigIP-OCSF",         "f5-bigip.log",              "f5ltm-ocsf"),
    ("watchguard-fireware.conf", "WatchGuard-OCSF",      "watchguard-fireware.log",   "watchguard-ocsf"),
    ("microsoft-entra-id.conf",  "EntraID-OCSF",         "microsoft-entra-id.log",    "entra-ocsf"),
    ("microsoft-dhcp.conf",      "MicrosoftDHCP-OCSF",   "microsoft-dhcp.log",        "msdhcp-ocsf"),
    ("isc-bind.conf",            "ISCBIND-OCSF",         "isc-bind.log",              "bind-ocsf"),
    ("f5-bigip-apm.conf",        "F5APM-OCSF",           "f5-bigip-apm.log",          "f5apm-ocsf"),
    ("linux-os.conf",            "LinuxOS-OCSF",         "linux-os.log",              "linux-ocsf"),
    ("hana-database.conf",       "HANADatabase-OCSF",    "hana-database.log",         "hana-ocsf"),
]


def deploy_all(client):
    print("=" * 70)
    print("DEPLOYING 16 OCSF PARSERS")
    print("=" * 70)
    success = 0
    for fname, pname, _, _ in PARSERS:
        try:
            content = (ROOT / "parsers" / fname).read_text()
            client.put_file(f"/logParsers/{pname}", content=content)
            print(f"  OK   {pname}")
            success += 1
        except Exception as e:
            print(f"  FAIL {pname}: {str(e)[:120]}")
    print(f"\n{success}/{len(PARSERS)} parsers deployed.")


def ingest_all(client):
    print("\n" + "=" * 70)
    print("INGESTING SAMPLE DATA")
    print("=" * 70)
    success = 0
    for _, pname, sfile, host in PARSERS:
        path = ROOT / "sample-data" / sfile
        if not path.exists():
            print(f"  SKIP {pname}: missing sample {sfile}")
            continue
        try:
            log = path.read_text()
            client.upload_logs(log_data=log, parser=pname, server_host=host, log_file=sfile)
            print(f"  OK   {host} via {pname} ({len(log)} bytes)")
            success += 1
            time.sleep(0.3)
        except Exception as e:
            print(f"  FAIL {host}: {str(e)[:120]}")
    print(f"\n{success}/{len(PARSERS)} samples ingested.")


def validate_findings(client):
    print("\n" + "=" * 70)
    print("VALIDATING OCSF FIELD EXTRACTION + DETECTION FINDINGS")
    print("=" * 70)
    print("Waiting 15s for indexing...")
    time.sleep(15)

    # Per-parser smoke checks
    for _, pname, _, host in PARSERS:
        try:
            r = client.power_query(
                query=f"serverHost='{host}' | group n=count() by class_uid, class_name | sort -n",
                start_time="1d",
            )
            rows = r.get("values", [])
            if rows:
                summary = ", ".join(f"{v[1]}={v[2]}" for v in rows[:3] if isinstance(v, list) and len(v) >= 3)
                print(f"  {host:20s} {pname:25s} {int(r.get('matchingEvents', 0))} events: {summary}")
            else:
                print(f"  {host:20s} {pname:25s} (no events yet — may need fresh trigger data)")
        except Exception as e:
            print(f"  {host:20s} {pname:25s} ERR {str(e)[:80]}")

    # Aggregate Detection Findings
    print("\n" + "=" * 70)
    print("CROSS-SOURCE DETECTION FINDINGS (class_uid=2004)")
    print("=" * 70)
    try:
        r = client.power_query(
            query="class_uid='2004' | group hits=count() by serverHost, finding_title | sort -hits",
            start_time="1d",
        )
        for v in r.get("values", [])[:30]:
            print(f"  {v}")
    except Exception as e:
        print(f"FAIL: {str(e)[:200]}")


def main():
    client = SDLClient()
    print(f"Connected: {client.base_url}\n")
    deploy_all(client)
    ingest_all(client)
    validate_findings(client)


if __name__ == "__main__":
    main()
