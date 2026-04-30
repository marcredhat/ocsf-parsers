#!/usr/bin/env python3
"""
Run validation PowerQueries against SDL to confirm OCSF parsers are emitting
Detection Findings. Uses ONLY confirmed-working SDL PowerQuery syntax
(count, count(field), min, max, group, filter, sort, parse, columns, limit).

See POWERQUERY_REFERENCE.md for the full syntax cheat-sheet.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient


QUERIES = [
    ("All Detection Findings — by source",
     "class_uid='2004' | group hits=count() by serverHost, finding_title | sort -hits"),

    ("Severity distribution",
     "class_uid='2004' | group hits=count() by severity, severity_id | sort -hits"),

    ("Critical findings only",
     "class_uid='2004' AND severity_id='5' | group hits=count() by serverHost, finding_title | sort -hits"),

    ("Top attacker IPs",
     "class_uid='2004' AND src_ip != null | group attacks=count() by src_ip | sort -attacks | limit 20"),

    ("HANA database attacks",
     "serverHost='hana-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),

    ("Linux SSH/sudo/credential dumping",
     "serverHost='linux-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),

    ("Windows logon/account/audit findings",
     "serverHost='windows-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),

    ("BIND DNS findings",
     "serverHost='bind-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),

    ("Entra ID risky sign-ins",
     "serverHost='entra-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),

    ("F5 LTM + APM findings",
     "(serverHost='f5ltm-ocsf' OR serverHost='f5apm-ocsf') AND class_uid='2004' "
     "| group hits=count() by serverHost, finding_title | sort -hits"),

    ("FortiGate firewall findings",
     "serverHost='fortigate-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),

    ("Palo Alto threat detections",
     "serverHost='paloalto-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),

    ("QRadar SIEM correlations",
     "serverHost='qradar-ocsf' AND class_uid='2004' | group hits=count() by finding_title | sort -hits"),

    ("Linux SSH brute-force-then-success (per attacker IP)",
     "serverHost='linux-ocsf' "
     "| parse 'Failed password for $f_user$ from $f_ip$' "
     "| parse 'Accepted password for $a_user$ from $a_ip$' "
     "| group fails=count(f_user), success=count(a_user), "
     "first_seen=min(timestamp), last_seen=max(timestamp) by serverHost, f_ip "
     "| filter fails >= 3 and success >= 1 | sort -fails"),

    ("Cross-source Detection Findings event volume",
     "class_uid='2004' | group hits=count() by serverHost | sort -hits"),
]


def main():
    client = SDLClient()
    print(f"SDL: {client.base_url}\n")
    print("=" * 78)
    print("DETECTION VALIDATION — PowerQueries (1d window)")
    print("=" * 78)

    summary = []
    for title, q in QUERIES:
        print(f"\n▶ {title}")
        print(f"  PQ: {q}")
        try:
            r = client.power_query(query=q, start_time="1d")
            total = int(r.get("matchingEvents", 0))
            rows  = r.get("values") or []
            print(f"  matchingEvents={total}, groups={len(rows)}")
            for row in rows[:10]:
                print(f"    {row}")
            summary.append((title, total, len(rows)))
        except Exception as e:
            print(f"  ERR: {str(e)[:200]}")
            summary.append((title, -1, 0))

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    ok = 0
    for t, total, rows in summary:
        marker = "OK " if total > 0 else "·· " if total == 0 else "ERR"
        if total > 0:
            ok += 1
        print(f"  {marker} {t:60s} events={total:>6}  groups={rows}")
    print(f"\n  {ok}/{len(summary)} validation queries returned data.")


if __name__ == "__main__":
    main()
