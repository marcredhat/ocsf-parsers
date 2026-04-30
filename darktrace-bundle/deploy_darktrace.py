#!/usr/bin/env python3
"""
Add Darktrace as a new OCSF log source.

Steps:
  1. Deploy the parser  (PUT  /logParsers/Darktrace-OCSF)
  2. Ingest sample data (POST /api/uploadLogs)
  3. Validate OCSF field extraction via PowerQuery — assert that all
     expected fields (class_uid, severity, src_ip, model_name, etc.)
     are present in the parsed events.

Run:
    python3 deploy_darktrace.py
"""
import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from sdl_client import SDLClient

ROOT         = Path(__file__).parent
PARSER_FILE  = ROOT / "parsers"      / "darktrace.conf"
SAMPLE_FILE  = ROOT / "sample-data"  / "darktrace.log"
PARSER_NAME  = "Darktrace-OCSF"
SERVER_HOST  = "darktrace-ocsf"
LOG_FILE     = "darktrace.log"

# ---------------------------------------------------------------------------
# Field-coverage matrix — each query MUST return ≥1 row to pass
# ---------------------------------------------------------------------------
# Schema follows OCSF v1.3.0 — Detection Finding (2004) and Authentication (3002).
OCSF_CHECKS = [
    # (label,  required field, PowerQuery filter)
    ("metadata.vendor",       "dataSource.vendor",
     f"serverHost='{SERVER_HOST}' AND dataSource.vendor='Darktrace'"),
    ("metadata.product",      "dataSource.name",
     f"serverHost='{SERVER_HOST}' AND dataSource.name='Darktrace'"),
    ("category_uid Findings", "category_uid",
     f"serverHost='{SERVER_HOST}' AND category_uid='2'"),
    ("class_uid 2004",        "class_uid",
     f"serverHost='{SERVER_HOST}' AND class_uid='2004'"),
    ("class_uid 3002 (auth)", "class_uid",
     f"serverHost='{SERVER_HOST}' AND class_uid='3002'"),
    ("type_uid 200401",       "type_uid",
     f"serverHost='{SERVER_HOST}' AND type_uid='200401'"),
    ("severity Critical (id=5)",   "severity_id",
     f"serverHost='{SERVER_HOST}' AND severity_id='5'"),
    ("severity High (id=4)",       "severity_id",
     f"serverHost='{SERVER_HOST}' AND severity_id='4'"),
    ("disposition Blocked",   "disposition",
     f"serverHost='{SERVER_HOST}' AND disposition='Blocked'"),
    ("finding_title",         "finding_title",
     f"serverHost='{SERVER_HOST}' AND finding_title contains 'Darktrace'"),
    ("src_ip extracted",      "src_ip",
     f"serverHost='{SERVER_HOST}' AND src_ip != null"),
    ("dst_ip extracted",      "dst_ip",
     f"serverHost='{SERVER_HOST}' AND dst_ip != null"),
    ("user_name extracted",   "user_name",
     f"serverHost='{SERVER_HOST}' AND user_name != null"),
    ("device_id extracted",   "device_id",
     f"serverHost='{SERVER_HOST}' AND device_id != null"),
    ("score extracted",       "score",
     f"serverHost='{SERVER_HOST}' AND score != null"),
    ("model_name extracted",  "model_name",
     f"serverHost='{SERVER_HOST}' AND model_name != null"),
    ("auth failure status",   "status_id",
     f"serverHost='{SERVER_HOST}' AND class_uid='3002' AND status_id='2'"),
    ("Antigena response",     "action",
     f"serverHost='{SERVER_HOST}' AND finding_title contains 'Antigena'"),
    ("AI Analyst incident",   "finding_title",
     f"serverHost='{SERVER_HOST}' AND finding_title contains 'AI Analyst'"),
]


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def deploy_parser(client) -> bool:
    print("=" * 70)
    print("STEP 1 — Deploy parser")
    print("=" * 70)
    if not PARSER_FILE.exists():
        print(f"  FAIL: missing {PARSER_FILE}")
        return False
    try:
        client.put_file(f"/logParsers/{PARSER_NAME}", content=PARSER_FILE.read_text())
        print(f"  OK   /logParsers/{PARSER_NAME}  ({PARSER_FILE.stat().st_size} bytes)")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False


def ingest_sample(client) -> bool:
    print("\n" + "=" * 70)
    print("STEP 2 — Ingest sample data")
    print("=" * 70)
    if not SAMPLE_FILE.exists():
        print(f"  FAIL: missing {SAMPLE_FILE}")
        return False
    try:
        log = SAMPLE_FILE.read_text()
        client.upload_logs(
            log_data=log, parser=PARSER_NAME,
            server_host=SERVER_HOST, log_file=LOG_FILE,
        )
        n_events = sum(1 for line in log.splitlines() if line.strip())
        print(f"  OK   ingested {n_events} events as serverHost='{SERVER_HOST}'")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False


def validate_fields(client) -> int:
    print("\n" + "=" * 70)
    print("STEP 3 — Validate OCSF field coverage")
    print("=" * 70)
    print("  Waiting 15s for indexing...")
    time.sleep(15)

    passed = failed = 0
    for label, field, query in OCSF_CHECKS:
        try:
            r = client.power_query(query=f"{query} | columns {field} | limit 1",
                                   start_time="1d")
            n = int(r.get("matchingEvents", 0) or 0)
            if n >= 1:
                print(f"  PASS  {label:30s} → {field:20s} ({n} matches)")
                passed += 1
            else:
                print(f"  FAIL  {label:30s} → {field:20s} (0 matches)")
                failed += 1
        except Exception as e:
            print(f"  ERR   {label:30s} → {str(e)[:80]}")
            failed += 1

    print(f"\n  Coverage: {passed}/{passed + failed} OCSF checks passed")
    return failed


def summary_breakdown(client):
    print("\n" + "=" * 70)
    print("STEP 4 — Per-finding-title breakdown")
    print("=" * 70)
    try:
        r = client.power_query(
            query=f"serverHost='{SERVER_HOST}' "
                  "| group hits=count() by class_uid, class_name, finding_title, severity "
                  "| sort -hits",
            start_time="1d",
        )
        cols = [c.get("name") if isinstance(c, dict) else c
                for c in r.get("columns") or []]
        print(f"  Columns: {cols}")
        for row in r.get("values") or []:
            print(f"    {row}")
    except Exception as e:
        print(f"  FAIL: {e}")


def main():
    client = SDLClient()
    print(f"Connected: {client.base_url}\n")

    if not deploy_parser(client):  sys.exit(2)
    if not ingest_sample(client):  sys.exit(3)
    failed = validate_fields(client)
    summary_breakdown(client)

    print("\n" + "=" * 70)
    if failed == 0:
        print("✓ Darktrace log source is fully wired in and OCSF-compliant.")
    else:
        print(f"✗ {failed} OCSF field(s) missing — see FAIL rows above.")
    print("=" * 70)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
