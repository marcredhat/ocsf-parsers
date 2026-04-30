#!/usr/bin/env python3
"""
Search for unusual / suspicious activity using the SentinelOne LRQ API.

Covers all data sources ingested into the lake, with a deep focus on:
  - Windows Event Logs (WEL)        → serverHost='windows-ocsf'
  - SAP HANA database                → serverHost='hana-ocsf'

Plus full coverage of every other parser in the OCSF skill (Linux, Entra ID,
BIND/MS-DNS, FortiGate, Check Point, Palo Alto, F5, WatchGuard, Oracle,
QRadar, SIM-Generic), and S1 agent telemetry, and cross-source correlation.

Sections:
  1. S1 AGENT TELEMETRY      — process / network / file / DNS hunts
  2. WINDOWS EVENT LOGS      — 4624/4625/4672/4688/4720/4732/1102
  3. SAP HANA                 — SQLi, mass exfil, privileged DDL, off-hours
  4. OTHER OCSF SOURCES      — identity, network, DNS, web, database
  5. CROSS-SOURCE CORRELATION — multi-source attacker IPs, kill-chain
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lrq_client import LRQClient, get_time_range

CONSOLE = os.environ.get("S1_CONSOLE", "usea1-purple.sentinelone.net")
JWT     = os.environ.get("S1_JWT")
HOURS   = int(os.environ.get("S1_HOURS", "168"))   # default 7 days

if not JWT:
    print("Set S1_JWT environment variable")
    sys.exit(1)

client = LRQClient(CONSOLE, JWT)
start, end = get_time_range(HOURS)

print("=" * 78)
print(f"UNUSUAL ACTIVITY HUNT — Last {HOURS}h via LRQ API")
print("=" * 78)
print(f"Console:    {CONSOLE}")
print(f"Time range: {start}  →  {end}\n")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def run(label, query, fmt=None, top=10, hours=None, timeout=90):
    """Execute a hunt and print formatted results.

    Optional `hours` overrides the global lookback window for this hunt only.
    Useful for cross-source aggregations that scan a lot of data.
    """
    print(f"\n[{label}]")
    try:
        s, e = (get_time_range(hours) if hours else (start, end))
        r = client.execute_query(query.strip(), s, e, timeout=timeout)
        vals = r.get("values") or []
        print(f"  Rows: {len(vals)}   Columns: {r.get('columns', [])}")
        if not vals:
            print("  · no results")
            return
        for row in vals[:top]:
            try:
                print("    " + (fmt(row) if fmt else "  ".join(str(c)[:80] for c in row)))
            except Exception:
                print(f"    {row}")
        if len(vals) > top:
            print(f"    … +{len(vals) - top} more")
    except Exception as e:
        print(f"  ERR: {str(e)[:200]}")


def section(title):
    print("\n" + "=" * 78)
    print(f" {title} ".center(78, "="))
    print("=" * 78)


# ===========================================================================
# 1. S1 AGENT TELEMETRY
# ===========================================================================
section("1. S1 AGENT TELEMETRY  (dataSource.name='SentinelOne')")

run("1.1 Event type distribution", """
dataSource.name='SentinelOne' dataSource.category='security'
| group ct=count() by event.type
| sort -ct | limit 30
""", fmt=lambda r: f"{r[0]}: {r[1]:,}")

run("1.2 Rare processes (<10 executions)", """
dataSource.name='SentinelOne' dataSource.category='security' event.type='Process Creation'
| group ct=count() by src.process.name
| filter ct < 10
| sort -ct | limit 20
""", fmt=lambda r: f"{r[0]}: {r[1]} executions")

run("1.3 Recon command-line patterns", """
dataSource.name='SentinelOne' dataSource.category='security'
| filter src.process.cmdline matches ".*(whoami|ipconfig|net user|net group|systeminfo|tasklist|reg query|nltest|net localgroup|quser).*"
| group ct=count() by src.process.name, endpoint.name
| sort -ct | limit 20
""", fmt=lambda r: f"{r[0]} on {r[1]}: {r[2]}")

run("1.4 Unusual network ports (not 80/443/53)", """
dataSource.name='SentinelOne' dataSource.category='security' event.type='IP Connect'
| filter dst.port.number != 80 AND dst.port.number != 443 AND dst.port.number != 53
| group ct=count() by dst.port.number
| sort -ct | limit 20
""", fmt=lambda r: f"Port {r[0]}: {r[1]:,} connections")

run("1.5 Script-engine execution (PowerShell/wscript/mshta/cmd)", """
dataSource.name='SentinelOne' dataSource.category='security'
| filter src.process.name contains ('powershell', 'wscript', 'cscript', 'mshta', 'cmd')
| group ct=count() by src.process.name, endpoint.name
| sort -ct | limit 20
""", fmt=lambda r: f"{r[0]} on {r[1]}: {r[2]}")

run("1.6 Suspicious file creations in Temp/AppData/Startup", r"""
dataSource.name='SentinelOne' dataSource.category='security' event.type='File Creation'
| filter tgt.file.path matches ".*(Temp|AppData|Downloads|Startup).*\\.(exe|dll|ps1|bat|vbs|js)$"
| group ct=count() by tgt.file.path, endpoint.name
| sort -ct | limit 20
""", fmt=lambda r: f"{r[0][:60]}… on {r[1]}: {r[2]}")


# ===========================================================================
# 2. WINDOWS EVENT LOGS — DEEP FOCUS
# ===========================================================================
section("2. WINDOWS EVENT LOGS  (serverHost='windows-ocsf')")

run("2.1 All Windows finding types & counts", """
serverHost='windows-ocsf' AND class_uid='2004'
| group hits=count() by finding_title
| sort -hits
""", fmt=lambda r: f"{r[0]:50s}  {r[1]}")

run("2.2 Failed logons (4625) — top users targeted", """
serverHost='windows-ocsf' AND class_uid='2004' AND finding_title contains '4625'
| group fails=count() by user_name, src_ip
| sort -fails | limit 20
""", fmt=lambda r: f"user={r[0]} src_ip={r[1]} fails={r[2]}")

run("2.3 Failed logon BURST (≥5 fails per src_ip → potential brute force)", """
serverHost='windows-ocsf' AND class_uid='2004' AND finding_title contains '4625'
| group fails=count() by src_ip
| filter fails >= 5
| sort -fails | limit 20
""", fmt=lambda r: f"src_ip={r[0]} fails={r[1]}")

run("2.4 Source IPs with both failed AND successful Windows logons", """
serverHost='windows-ocsf' AND class_uid in ('2004','3002') AND src_ip != null
| group fails=count(finding_title contains '4625'),
        success=count(class_uid='3002' AND status_id='1') by src_ip
| filter fails >= 1 and success >= 1
| sort -fails | limit 20
""", fmt=lambda r: f"ip={r[0]} fails={r[1]} success={r[2]}")

run("2.5 New account creations (4720)", """
serverHost='windows-ocsf' AND class_uid='2004' AND finding_title contains '4720'
| group hits=count() by new_user
| sort -hits | limit 20
""", fmt=lambda r: f"new_user={r[0]} count={r[1]}")

run("2.6 Privileged group additions (4732) — CRITICAL", """
serverHost='windows-ocsf' AND class_uid='2004' AND finding_title contains '4732'
| group hits=count() by group_name, member
| sort -hits | limit 20
""", fmt=lambda r: f"group={r[0]} member={r[1]} count={r[2]}")

run("2.7 Audit log cleared (1102) — anti-forensics indicator", """
serverHost='windows-ocsf' AND class_uid='2004' AND finding_title contains '1102'
| group hits=count() by serverHost
""", fmt=lambda r: f"host={r[0]} clears={r[1]}")

run("2.8 Special-privileges assigned (4672) — admin elevation", """
serverHost='windows-ocsf' AND finding_title contains '4672'
| group hits=count() by user_name
| sort -hits | limit 20
""", fmt=lambda r: f"user={r[0]} count={r[1]}")

run("2.9 Process creations (4688) — top command lines", """
serverHost='windows-ocsf' AND finding_title contains '4688'
| group hits=count() by command_line
| sort -hits | limit 20
""", fmt=lambda r: f"{(r[0] or '')[:70]} count={r[1]}")


# ===========================================================================
# 3. SAP HANA — DEEP FOCUS
# ===========================================================================
section("3. SAP HANA  (serverHost='hana-ocsf')")

run("3.1 All HANA finding types & counts", """
serverHost='hana-ocsf' AND class_uid='2004'
| group hits=count() by finding_title
| sort -hits
""", fmt=lambda r: f"{r[0]:50s} {r[1]}")

run("3.2 SQL injection attempts", """
serverHost='hana-ocsf' AND class_uid='2004' AND finding_title contains 'SQL Injection'
| group hits=count() by user_name, src_ip
| sort -hits | limit 20
""", fmt=lambda r: f"user={r[0]} src_ip={r[1]} hits={r[2]}")

run("3.3 Mass data extraction events", """
serverHost='hana-ocsf' AND class_uid='2004' AND finding_title contains 'Mass Data Extraction'
| group hits=count() by user_name, src_ip
| sort -hits | limit 20
""", fmt=lambda r: f"user={r[0]} src_ip={r[1]} hits={r[2]}")

run("3.4 Failed authentication to HANA", """
serverHost='hana-ocsf' AND class_uid='3002' AND status_id='2'
| group fails=count() by user_name, src_ip
| filter fails >= 3
| sort -fails | limit 20
""", fmt=lambda r: f"user={r[0]} src_ip={r[1]} fails={r[2]}")

run("3.5 Privileged DDL operations (DROP / ALTER / CREATE USER)", """
serverHost='hana-ocsf' AND
(message contains 'DROP TABLE' OR message contains 'ALTER USER' OR message contains 'CREATE USER' OR message contains 'GRANT')
| group hits=count() by user_name
| sort -hits | limit 20
""", fmt=lambda r: f"user={r[0]} ddl_count={r[1]}")

run("3.6 HANA admin / system account activity volume", """
serverHost='hana-ocsf' AND
(user_name contains 'SYSTEM' OR user_name contains 'ADMIN' OR user_name contains 'DBADMIN' OR user_name contains 'SYS')
| group hits=count() by user_name
| sort -hits | limit 20
""", fmt=lambda r: f"user={r[0]} count={r[1]}")


# ===========================================================================
# 4. OTHER OCSF SOURCES
# ===========================================================================
section("4. OTHER OCSF SOURCES  (identity / network / DNS / web / db)")

run("4.1 Linux SSH brute-force (≥3 fails per source IP)", """
serverHost='linux-ocsf' AND message contains 'Failed password'
| parse 'Failed password for $f_user$ from $f_ip$ port '
| group fails=count(f_user) by f_ip
| filter fails >= 3
| sort -fails | limit 20
""", fmt=lambda r: f"src_ip={r[0]} fails={r[1]}")

run("4.2 Linux Brute-Force then SUCCESS (correlation)", """
serverHost='linux-ocsf' AND (message contains 'Failed password' OR message contains 'Accepted password')
| parse 'Failed password for $f_user$ from $f_ip$ port '
| parse 'Accepted password for $a_user$ from $a_ip$ port '
| group fails=count(f_user), success=count(a_user) by f_ip
| filter fails >= 3 and success >= 1
| sort -fails | limit 20
""", fmt=lambda r: f"ip={r[0]} fails={r[1]} success={r[2]}")

run("4.3 Linux reverse shell / credential dumping", """
serverHost='linux-ocsf' AND class_uid='2004'
AND (finding_title contains 'Reverse Shell' OR finding_title contains 'Credential Dumping')
| group hits=count() by finding_title
| sort -hits
""", fmt=lambda r: f"{r[0]:50s} {r[1]}")

run("4.4 Entra ID risky sign-ins / failures", """
serverHost='entra-ocsf' AND class_uid='2004'
| group hits=count() by finding_title
| sort -hits
""", fmt=lambda r: f"{r[0]:50s} {r[1]}")

run("4.5 BIND / MS-DNS suspicious activity (AXFR / dynamic DNS / tunneling)", """
(serverHost='bind-ocsf' OR serverHost='msdns-ocsf') AND class_uid='2004'
| group hits=count() by serverHost, finding_title
| sort -hits
""", fmt=lambda r: f"{r[0]:15s} {r[1]:50s} {r[2]}")

run("4.6 FortiGate firewall deny spike per source IP (≥10)", """
serverHost='fortigate-ocsf' AND class_uid='2004'
| group denies=count() by src_ip
| filter denies >= 10
| sort -denies | limit 20
""", fmt=lambda r: f"src_ip={r[0]} denies={r[1]}")

run("4.7 Palo Alto IPS / threat / spyware detections", """
serverHost='paloalto-ocsf' AND class_uid='2004'
| group hits=count() by finding_title
| sort -hits
""", fmt=lambda r: f"{r[0]:50s} {r[1]}")

run("4.8 Check Point firewall events", """
serverHost='checkpoint-ocsf' AND class_uid='2004'
| group hits=count() by finding_title
| sort -hits
""", fmt=lambda r: f"{r[0]:50s} {r[1]}")

run("4.9 F5 BIG-IP / APM WAF blocks", """
(serverHost='f5ltm-ocsf' OR serverHost='f5apm-ocsf') AND class_uid='2004'
| group hits=count() by serverHost, finding_title
| sort -hits
""", fmt=lambda r: f"{r[0]:15s} {r[1]:50s} {r[2]}")

run("4.10 Oracle / WatchGuard / QRadar / SIM-Generic findings", """
(serverHost='oracle-ocsf' OR serverHost='watchguard-ocsf' OR serverHost='qradar-ocsf' OR serverHost='sim-ocsf')
AND class_uid='2004'
| group hits=count() by serverHost, finding_title
| sort -hits | limit 30
""", fmt=lambda r: f"{r[0]:18s} {r[1]:50s} {r[2]}")


# ===========================================================================
# 5. CROSS-SOURCE CORRELATION
# ===========================================================================
section("5. CROSS-SOURCE CORRELATION")

run("5.1 Source IPs triggering findings across MULTIPLE sources (24h)", """
class_uid='2004' AND src_ip != null
| group attacks=count() by src_ip, serverHost
| sort -attacks | limit 200
""", fmt=lambda r: f"src_ip={r[0]} serverHost={r[1]} attacks={r[2]}", hours=24, timeout=180)

run("5.2 Top attacker IPs across all sources (24h)", """
class_uid='2004' AND src_ip != null
| group hits=count() by src_ip
| sort -hits | limit 25
""", fmt=lambda r: f"src_ip={r[0]} hits={r[1]}", hours=24, timeout=180)

run("5.3 Auth failure burst across ANY source (≥10 per user, 24h)", """
class_uid='3002' AND status_id='2'
| group attempts=count() by user_name
| filter attempts >= 10
| sort -attempts
""", fmt=lambda r: f"user={r[0]} attempts={r[1]}", hours=24, timeout=180)

run("5.4 Source-host volume of Detection Findings (24h)", """
class_uid='2004'
| group hits=count() by serverHost
| sort -hits
""", fmt=lambda r: f"{r[0]:18s} {r[1]:,}", hours=24, timeout=180)

run("5.5 Critical (severity_id=5) findings — WEL + HANA + others (24h)", """
class_uid='2004' AND severity_id='5'
| group hits=count() by serverHost, finding_title
| sort -hits | limit 30
""", fmt=lambda r: f"{r[0]:18s} {r[1]:50s} {r[2]}", hours=24, timeout=180)


print("\n" + "=" * 78)
print("HUNT COMPLETE")
print("=" * 78)
