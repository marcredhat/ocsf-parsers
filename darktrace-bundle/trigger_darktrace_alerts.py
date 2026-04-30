#!/usr/bin/env python3
"""
Trigger every Darktrace detection rule by ingesting a curated CEF burst that
satisfies each rule's filter, then verify each rule's PowerQuery returns rows
(meaning the SDL alert engine will fire it on the next evaluation cycle).

Rules covered:
  - Rule  1: Critical OCSF Detection Findings (severity_id=5)        → satisfied by AI Analyst + Antigena
  - Rule  2: High-Severity Detection Findings (severity_id=4)        → satisfied by Model Breach
  - Rule 15: Darktrace AI Analyst Incident                           → 3 incidents
  - Rule 16: Darktrace Antigena Autonomous Response Triggered        → 3 actions
  - Rule 17: Darktrace Model Breach High Score (>=80)                → 3 high-score breaches

Usage:
    python3 trigger_darktrace_alerts.py
"""
from __future__ import annotations
import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

PARSER_NAME = "Darktrace-OCSF"
SERVER_HOST = "darktrace-ocsf"
LOG_FILE    = "darktrace.log"

# ---------------------------------------------------------------------------
# Curated CEF burst — one or more events per Darktrace rule
# ---------------------------------------------------------------------------
TRIGGER_EVENTS = "\n".join([
    # ---- Model Breach with high score (>=80) — fires rule 2 + rule 17 ----
    "CEF:0|Darktrace|DCIP|6.1|100|Model Breach|9|src=10.10.50.5 dst=185.220.101.45 spt=51200 dpt=8443 cs1=Compromise / Beacon to Rare External Endpoint cs1Label=Model cs2=Compromise cs2Label=Category cn1=98 cn1Label=Score duser=alice deviceExternalId=12399 act=alert",
    "CEF:0|Darktrace|DCIP|6.1|100|Model Breach|10|src=10.10.50.6 dst=192.168.1.50 spt=55512 dpt=445 cs1=Anomalous File / Internal SMB Write cs1Label=Model cs2=AnomalousFile cs2Label=Category cn1=99 cn1Label=Score duser=svc_backup deviceExternalId=87010 act=alert",
    "CEF:0|Darktrace|DCIP|6.1|100|Model Breach|7|src=10.10.50.7 dst=8.8.8.8 spt=54321 dpt=443 cs1=Anomalous Connection / Suspicious Self-Signed SSL cs1Label=Model cs2=Compliance cs2Label=Category cn1=85 cn1Label=Score duser=jsmith deviceExternalId=12345 act=alert",

    # ---- AI Analyst incidents — fires rule 1 + rule 15 ----
    "CEF:0|Darktrace|DCIP|6.1|200|AI Analyst: Possible Data Exfiltration|10|src=10.10.50.10 dst=203.0.113.77 duser=admin deviceExternalId=12399 externalId=AIA-2026-1001 msg=Beacon and exfil to rare external endpoint",
    "CEF:0|Darktrace|DCIP|6.1|200|AI Analyst: Lateral Movement Suspected|10|src=10.10.50.11 dst=10.10.99.9 duser=svc_admin deviceExternalId=87011 externalId=AIA-2026-1002 msg=Multiple SMB writes across hosts",
    "CEF:0|Darktrace|DCIP|6.1|200|AI Analyst: Suspicious SaaS Activity|10|src=10.10.50.12 dst=52.96.0.1 duser=alice deviceExternalId=12399 externalId=AIA-2026-1003 msg=Anomalous M365 OAuth grant",

    # ---- Antigena Autonomous Response — fires rule 1 + rule 16 ----
    "CEF:0|Darktrace|DCIP|6.1|300|Antigena Action|10|src=10.10.50.5 dst=185.220.101.45 duser=alice deviceExternalId=12399 act=block_connection",
    "CEF:0|Darktrace|DCIP|6.1|300|Antigena Action|10|src=10.10.50.6 dst=10.10.50.7 duser=svc_backup deviceExternalId=87010 act=enforce_pattern_of_life",
    "CEF:0|Darktrace|DCIP|6.1|300|Antigena Action|10|src=10.10.50.10 duser=admin deviceExternalId=12399 act=disable_user",

    # ---- Admin login failures — fires authentication-burst rule (rule 12) if many ----
    "CEF:0|Darktrace|DCIP|6.1|400|Admin Login Failure|3|src=10.10.50.99 duser=mallory",
    "CEF:0|Darktrace|DCIP|6.1|400|Admin Login Failure|3|src=10.10.50.99 duser=mallory",
    "CEF:0|Darktrace|DCIP|6.1|400|Admin Login Failure|3|src=10.10.50.99 duser=mallory",
])


# ---------------------------------------------------------------------------
# The exact queries used by the deployed Darktrace + generic rules
# ---------------------------------------------------------------------------
RULES = [
    ("Rule  1 — Critical OCSF Detection Findings",
     "class_uid='2004' AND severity_id='5' AND parser='Darktrace-OCSF' "
     "| group n=count() by serverHost, finding_title | filter n >= 1"),
    ("Rule  2 — High-Severity Detection Findings",
     "class_uid='2004' AND severity_id='4' AND parser='Darktrace-OCSF' "
     "| group n=count() by serverHost, finding_title | filter n >= 1"),
    ("Rule 15 — Darktrace AI Analyst Incident",
     "parser='Darktrace-OCSF' AND finding_title contains 'AI Analyst' "
     "| group n=count() by serverHost, src_ip, finding_title | filter n >= 1"),
    ("Rule 16 — Darktrace Antigena Autonomous Response Triggered",
     "parser='Darktrace-OCSF' AND finding_title contains 'Antigena' "
     "| group n=count() by src_ip, dst_ip, action | filter n >= 1"),
    ("Rule 17 — Darktrace Model Breach High Score (>=80)",
     "parser='Darktrace-OCSF' AND model_name != null AND score >= '80' "
     "| group n=count() by src_ip, model_name, score | filter n >= 1"),
]


def main() -> int:
    c = SDLClient()
    print(f"Tenant: {c.base_url}")
    print(f"Parser: {PARSER_NAME}\n")

    # --- 1. Ingest the curated burst -----------------------------------------
    print("=" * 70)
    print("STEP 1 — Ingest curated Darktrace CEF burst")
    print("=" * 70)
    n_lines = sum(1 for ln in TRIGGER_EVENTS.splitlines() if ln.strip())
    c.upload_logs(log_data=TRIGGER_EVENTS, parser=PARSER_NAME,
                  server_host=SERVER_HOST, log_file=LOG_FILE)
    print(f"  OK  ingested {n_lines} CEF events as serverHost='{SERVER_HOST}'")

    # --- 2. Wait for indexing ------------------------------------------------
    print("\nWaiting 20s for SDL indexing...")
    time.sleep(20)

    # --- 3. Validate each rule fires -----------------------------------------
    print("\n" + "=" * 70)
    print("STEP 2 — Validate every Darktrace rule's trigger query returns rows")
    print("=" * 70)
    fired = passed = 0
    for label, query in RULES:
        try:
            r = c.power_query(query=query, start_time="15m")
            rows = r.get("values") or []
            n_unique = len(rows)
            if n_unique >= 1:
                print(f"  FIRE  {label}  ({n_unique} unique grouping(s))")
                for row in rows[:3]:
                    print(f"        {row}")
                fired += 1
            else:
                print(f"  miss  {label}  (0 rows)")
            passed += 1
        except Exception as e:
            print(f"  ERR   {label}  -> {str(e)[:120]}")

    # --- 4. Summary ----------------------------------------------------------
    print("\n" + "=" * 70)
    print(f"RESULT — {fired}/{len(RULES)} rules will fire on next SDL evaluation")
    print("=" * 70)
    print("\nThe SDL alert engine evaluates scheduled rules every 5 min and writes")
    print("alert events when their trigger query returns rows. View fired alerts in:")
    print("  • SDL/legacy:  Settings → Alerts → Scheduled Alerts")
    print("  • AI SIEM UI:  Detect → Findings  (after rules 15-17 are saved")
    print("                 from AI_SIEM_UI_GUIDE.md into the Web UI)")
    return 0 if fired == len(RULES) else 1


if __name__ == "__main__":
    sys.exit(main())
