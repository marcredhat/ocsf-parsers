#!/usr/bin/env python3
"""Live demo runner: walks the kill chain with inline-parsed OCSF fields."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_CYAN = "\033[96m"

DEMO_STAGES = [
    {
        "act": "ACT I — The Threat Surface",
        "narrative": "16 OCSF-normalized sources + 7 attack scenarios ingested.",
        "query": "serverHost matches '(ocsf-.*|attack-target-.*)' | group event_count=count() by serverHost | sort -event_count",
        "mitre": "—",
        "expect": "23 hosts visible",
    },
    {
        "act": "STAGE 1 — Reconnaissance (Port Scan) — OCSF: 4001 Network Activity",
        "narrative": "Attacker scans 12 unique ports from 10.0.1.50.",
        "query": (
            "serverHost='attack-target-02' message contains 'action=\"deny\"' "
            "| parse 'srcip=$src_ip$ ' "
            "| parse 'dstip=$dst_ip$ ' "
            "| parse 'dstport=$dst_port$ ' "
            "| parse 'service=\"$service$\"' "
            "| group hits=count() by src_ip, dst_port "
            "| group unique_ports=count() by src_ip "
            "| filter unique_ports >= 10"
        ),
        "mitre": "T1046",
        "expect": "1 row: src_ip=10.0.1.50, unique_ports=12",
    },
    {
        "act": "STAGE 2 — Initial Access (Brute Force) — OCSF: 3002 Authentication",
        "narrative": "7 failed SSH logins followed by successful auth.",
        "query": (
            "serverHost='attack-target-01' message contains 'Failed password' "
            "| parse 'Failed password for $user_name$ from $src_ip$ port $src_port$' "
            "| group failed_attempts=count() by user_name, src_ip "
            "| filter failed_attempts >= 3 "
            "| sort -failed_attempts"
        ),
        "mitre": "T1110",
        "expect": "user_name=admin, src_ip=192.168.1.100, failed_attempts >= 7",
    },
    {
        "act": "STAGE 3 — Privilege Escalation (sudo abuse) — OCSF: 3005 User Access",
        "narrative": "Unauthorized sudo attempt to read /etc/shadow.",
        "query": (
            "serverHost matches 'attack-target-.*' message contains 'NOT in sudoers' "
            "| parse 'sudo: $user_name$ : user NOT in sudoers' "
            "| parse 'COMMAND=$command$' "
            "| columns timestamp, user_name, command"
        ),
        "mitre": "T1548.003",
        "expect": "user_name=hacker, command=/bin/cat /etc/shadow",
    },
    {
        "act": "STAGE 4 — Execution (Reverse Shell + Mimikatz) — OCSF: 1007 Process Activity",
        "narrative": "Python reverse shell, netcat, and Mimikatz download.",
        "query": (
            "serverHost='attack-target-03' "
            "| filter (message contains 'mimikatz' or message contains 'socket.socket' "
            "       or message contains 'nc -e' or message contains 'curl' or message contains '/tmp/.hidden') "
            "| parse '$user_name$ : ' "
            "| parse 'COMMAND=$command$' "
            "| columns timestamp, user_name, command, message"
        ),
        "mitre": "T1059",
        "expect": "Multiple suspicious commands (Python reverse shell, curl mimikatz, nc -e)",
    },
    {
        "act": "STAGE 5 — Persistence (Backdoor Account) — OCSF: 3001 Account Change",
        "narrative": "Backdoor user 'backdoor' created with UID 0.",
        "query": (
            "serverHost='attack-target-03' message contains 'useradd' "
            "| parse 'new user: name=$new_user$,' "
            "| parse 'UID=$uid$,' "
            "| parse 'GID=$gid$,' "
            "| columns timestamp, new_user, uid, gid, message"
        ),
        "mitre": "T1136",
        "expect": "new_user=backdoor, uid=0, gid=0",
    },
    {
        "act": "STAGE 6 — Lateral Movement (SMB) — OCSF: 4001 Network Activity",
        "narrative": "SMB connections (port 445) from 10.0.1.50 to internal hosts.",
        "query": (
            "serverHost='attack-target-02' message contains 'action=\"allow\"' message contains 'dstport=445' "
            "| parse 'srcip=$src_ip$ ' "
            "| parse 'dstip=$dst_ip$ ' "
            "| parse 'dstport=$dst_port$ ' "
            "| columns timestamp, src_ip, dst_ip, dst_port"
        ),
        "mitre": "T1021.002",
        "expect": "src_ip=10.0.1.50 -> 3 distinct dst_ip on port 445",
    },
    {
        "act": "STAGE 7 — Cloud Identity Attack — OCSF: 3002 Authentication",
        "narrative": "Tor sign-in, MFA bypass, impossible travel from Russia & Japan.",
        "query": (
            "serverHost='attack-target-06' "
            "| parse '\"userPrincipalName\":\"$user_name$\"' "
            "| parse '\"callerIpAddress\":\"$src_ip$\"' "
            "| parse '\"countryOrRegion\":\"$country$\"' "
            "| parse '\"resultType\":\"$result_code$\"' "
            "| parse '\"riskLevelAggregated\":\"$risk_level$\"' "
            "| filter (risk_level='high' or message contains 'Tor exit node' or message contains 'Impossible travel') "
            "| columns timestamp, user_name, src_ip, country, result_code, risk_level"
        ),
        "mitre": "T1078.004 + T1090.003 + T1556.006",
        "expect": "admin@corp from RU/JP, riskLevel=high, Tor IP",
    },
    {
        "act": "STAGE 8 — Database Exfiltration — OCSF: 4001 → 2004 (XDR Detection Finding)",
        "narrative": "HANA parser auto-promotes 5 risky patterns to Detection Finding so they appear in XDR Findings UI.",
        "query": (
            "serverHost='attack-target-05' class_uid='2004' "
            "| group hits=count() by finding_title, severity "
            "| sort -hits"
        ),
        "mitre": "T1190 + T1005 + T1078.004 + T1048",
        "expect": "Auth Failure, Mass Extraction, SQL Injection, Privilege Esc, Suspicious Backup findings",
    },
    {
        "act": "STAGE 9 — Command & Control — OCSF: 4001 Network Activity",
        "narrative": "Cobalt Strike beacon + Meterpreter on port 4444.",
        "query": (
            "serverHost='attack-target-07' "
            "| filter (message contains 'attack=' or message contains 'dstport=4444') "
            "| parse 'srcip=$src_ip$ ' "
            "| parse 'dstip=$dst_ip$ ' "
            "| parse 'dstport=$dst_port$ ' "
            "| parse 'attack=\"$attack_name$\"' "
            "| parse 'severity=\"$severity_label$\"' "
            "| columns timestamp, src_ip, dst_ip, dst_port, attack_name, severity_label"
        ),
        "mitre": "T1571 + T1071",
        "expect": "Cobalt.Strike.Beacon + Meterpreter.Reverse.Shell, dst_port=4444, severity=critical",
    },
    {
        "act": "STAGE 10 — DNS Tunneling & Recon — OCSF: 4003 DNS Activity",
        "narrative": "AXFR zone transfer, base64 DNS tunneling, dyndns C2.",
        "query": (
            "serverHost='attack-target-04' "
            "| filter (message contains 'AXFR' or message matches '[A-Za-z0-9+/=]{60,}' or message contains 'dyndns') "
            "| parse '#$src_port$ ' "
            "| parse ' query: $query_name$ IN $query_type$' "
            "| columns timestamp, query_name, query_type, message"
        ),
        "mitre": "T1590.002 + T1071.004",
        "expect": "AXFR for corp.local, base64 tunnel queries, dyndns C2",
    },
    {
        "act": "STAGE 11 — Attacker IP per Source (Wide View) — OCSF: 4001/3002 Network/Auth",
        "narrative": "Same query parses src_ip from 5 different formats and shows which source captured each IP.",
        "query": (
            "serverHost matches 'attack-target-.*' "
            "| parse 'password for $u$ from $ip_ssh$ port' "
            "| parse 'srcip=$ip_forti$ ' "
            '| parse \'"client_ip":"$ip_db$"\' '
            '| parse \'"callerIpAddress":"$ip_entra$"\' '
            "| parse 'info: client @$h$ $ip_dns$#' "
            "| filter (ip_ssh != null or ip_forti != null or ip_db != null or ip_entra != null or ip_dns != null) "
            "| group events=count() by serverHost, ip_ssh, ip_forti, ip_db, ip_entra, ip_dns "
            "| sort -events"
        ),
        "mitre": "—",
        "expect": "One row per (host, attacker_ip) tuple",
    },
    {
        "act": "FINALE — Cross-Source Correlation: Same IP Across Multiple Sources",
        "narrative": "Find attacker IPs that touched 2+ different security sources (the killer signal).",
        "cross_source": True,
        "mitre": "Multiple",
        "expect": "10.0.1.50 in attack-target-02 (port scan) AND attack-target-04 (DNS); 192.168.1.200 in attack-target-04 (DNS) AND attack-target-05 (DB)",
    },
]


def run_cross_source_correlation(client):
    """Run separate per-format queries, then identify cross-source IPs in Python."""
    per_source_queries = [
        ("attack-target-01 (SSH)",
         "serverHost='attack-target-01' | parse 'password for $u$ from $src_ip$ port' | filter src_ip != null | group n=count() by src_ip"),
        ("attack-target-02 (FortiGate)",
         "serverHost='attack-target-02' | parse 'srcip=$src_ip$ ' | filter src_ip != null | group n=count() by src_ip"),
        ("attack-target-04 (BIND DNS)",
         "serverHost='attack-target-04' | parse 'info: client @$h$ $src_ip$#' | filter src_ip != null | group n=count() by src_ip"),
        ("attack-target-05 (HANA DB)",
         'serverHost=\'attack-target-05\' | parse \'"client_ip":"$src_ip$"\' | filter src_ip != null | group n=count() by src_ip'),
        ("attack-target-06 (Entra ID)",
         'serverHost=\'attack-target-06\' | parse \'"callerIpAddress":"$src_ip$"\' | filter src_ip != null | group n=count() by src_ip'),
        ("attack-target-07 (FortiGate C2)",
         "serverHost='attack-target-07' | parse 'srcip=$src_ip$ ' | filter src_ip != null | group n=count() by src_ip"),
    ]

    # Map ip -> set of sources
    ip_to_sources = {}
    ip_to_total = {}

    for source_name, q in per_source_queries:
        try:
            r = client.power_query(query=q, start_time="1h")
            for row in r.get("values", []):
                if isinstance(row, list) and len(row) >= 2:
                    ip, count = row[0], row[1]
                    if ip:
                        ip_to_sources.setdefault(ip, set()).add(source_name)
                        ip_to_total[ip] = ip_to_total.get(ip, 0) + (count or 0)
        except Exception as e:
            print(f"  [warn] {source_name} query failed: {str(e)[:120]}")

    # Build the correlation table
    correlation = []
    for ip, sources in ip_to_sources.items():
        correlation.append({
            "ip": ip,
            "sources_touched": len(sources),
            "sources": sorted(sources),
            "total_events": ip_to_total.get(ip, 0),
        })

    correlation.sort(key=lambda x: (-x["sources_touched"], -x["total_events"]))
    return correlation


def banner(text, color=C_BOLD):
    bar = "=" * 70
    print(f"\n{color}{bar}{C_RESET}")
    print(f"{color}{text}{C_RESET}")
    print(f"{color}{bar}{C_RESET}\n")


def run_stage(client, stage, idx, total, pause):
    banner(f"[{idx}/{total}] {stage['act']}", C_CYAN)
    print(f"{C_YELLOW}Story:{C_RESET} {stage['narrative']}")
    print(f"{C_YELLOW}MITRE:{C_RESET} {stage['mitre']}")
    print(f"{C_YELLOW}Expected:{C_RESET} {stage['expect']}\n")

    # Special: cross-source correlation (multi-query)
    if stage.get("cross_source"):
        print(f"{C_BLUE}Approach:{C_RESET} Run 6 per-source parsing queries, then identify IPs appearing in 2+ sources.\n")
        correlation = run_cross_source_correlation(client)
        if correlation:
            print(f"{C_GREEN}RESULT: {len(correlation)} unique attacker IPs found{C_RESET}\n")
            print(f"{C_BOLD}{'attacker_ip':<20} {'#sources':<10} {'events':<8} sources_touched{C_RESET}")
            print("-" * 80)
            for c in correlation:
                src_list = ', '.join(s.split(' (')[0] for s in c['sources'])
                marker = "🔥 " if c['sources_touched'] >= 2 else "   "
                color = C_RED if c['sources_touched'] >= 2 else C_RESET
                print(f"{color}{marker}{c['ip']:<17} {c['sources_touched']:<10} {c['total_events']:<8} {src_list}{C_RESET}")
            multi = [c for c in correlation if c['sources_touched'] >= 2]
            if multi:
                print(f"\n{C_BOLD}{C_RED}🎯 KILLER SIGNAL: {len(multi)} IP(s) appear in 2+ sources (cross-source correlation){C_RESET}")
        else:
            print(f"{C_RED}No correlation data found{C_RESET}")
        if pause:
            input(f"\n{C_BOLD}Press ENTER for next stage...{C_RESET}")
        return

    print(f"{C_BLUE}Query:{C_RESET}")
    print(f"  {stage['query']}\n")

    try:
        result = client.power_query(query=stage["query"], start_time="1h")
        events = int(result.get("matchingEvents", 0))
        cols = [c.get("name") for c in result.get("columns", [])]
        values = result.get("values", [])

        if events > 0:
            print(f"{C_GREEN}RESULT: {events} matching events ({len(values)} rows){C_RESET}")
            if cols:
                print(f"\n{C_BOLD}Columns:{C_RESET} {cols}")
            if values:
                print(f"\n{C_BOLD}Top rows:{C_RESET}")
                for row in values[:5]:
                    if isinstance(row, list) and len(row) > 1:
                        # Pretty-print row as col=val pairs
                        pairs = []
                        for c, v in zip(cols, row):
                            sv = str(v)[:80] if v is not None else "null"
                            pairs.append(f"{c}={sv}")
                        print(f"  - {' | '.join(pairs)}")
                    else:
                        print(f"  - {row}")
        else:
            print(f"{C_RED}WARNING: No events matched{C_RESET}")
    except Exception as e:
        print(f"{C_RED}ERROR: {str(e)[:200]}{C_RESET}")

    if pause:
        input(f"\n{C_BOLD}Press ENTER for next stage...{C_RESET}")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--auto", action="store_true", help="Auto-advance without ENTER")
    parser.add_argument("--delay", type=float, default=1.5, help="Auto-mode delay between stages")
    args = parser.parse_args()

    banner("OCSF AI SIEM DEMO — The 'APT-Friday' Breach Investigation", C_BOLD)
    print(f"{C_YELLOW}A 15-minute kill-chain demo across 16 OCSF-normalized sources.{C_RESET}\n")

    client = SDLClient()
    print(f"Connected to: {client.base_url}")
    print(f"Stages: {len(DEMO_STAGES)}")
    print(f"Mode: {'AUTO' if args.auto else 'INTERACTIVE'}\n")

    if not args.auto:
        input(f"{C_BOLD}Press ENTER to begin demo...{C_RESET}")

    for i, stage in enumerate(DEMO_STAGES, 1):
        run_stage(client, stage, i, len(DEMO_STAGES), pause=not args.auto)
        if args.auto:
            time.sleep(args.delay)

    banner("DEMO COMPLETE — 26 detections fired across 7 attack scenarios", C_GREEN)


if __name__ == "__main__":
    main()
