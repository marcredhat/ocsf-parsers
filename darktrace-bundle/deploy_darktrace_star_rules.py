#!/usr/bin/env python3
"""
Deploy Darktrace STAR (Custom Detection) Rules to SentinelOne AI SIEM via the
Management Console API.

These rules — unlike the SDL /alerts entries — DO surface in the Unified Alerts
page (https://*.sentinelone.net/incidents/unified-alerts) and Detect → Findings.

API path:
  POST /web/api/v2.1/cloud-detection/rules           (create)
  PUT  /web/api/v2.1/cloud-detection/rules/enable    (activate)

Notes:
  • Rule s1ql uses PowerQuery 2.0 syntax
  • Rules become Active in the console within ~1 hour of activation
  • Re-running this script is idempotent: existing rules with the same name are
    skipped (the API allows duplicates, but we filter them client-side)

Usage:
    python3 deploy_darktrace_star_rules.py
"""
import os, sys
from pathlib import Path

# Allow importing the management-console S1Client
sys.path.insert(0, str(Path(__file__).parents[2] / "sentinelone-mgmt-console-api" / "scripts"))
from s1_client import S1Client

# ---------------------------------------------------------------------------
# Mgmt console URL (NOT the SDL endpoint).
# The Unified Alerts page lives at https://<your-mgmt-host>.sentinelone.net,
# so the STAR rules API must target the same host.
# Set S1_MGMT_URL env var to your console URL, e.g.
#   export S1_MGMT_URL="https://<your-tenant>.sentinelone.net"
# ---------------------------------------------------------------------------
MGMT_BASE_URL = os.environ.get("S1_MGMT_URL")
SITE_ID       = os.environ.get("S1_SITE_ID")  # optional override

if not MGMT_BASE_URL:
    sys.exit("ERROR: set S1_MGMT_URL env var to your SentinelOne mgmt console URL\n"
             "  e.g. export S1_MGMT_URL='https://<your-tenant>.sentinelone.net'")

# ---------------------------------------------------------------------------
# 3 Darktrace STAR rules — same triggers as in detection-rules/alerts.json
# but rewritten in PowerQuery 2.0 syntax for the cloud-detection API.
# ---------------------------------------------------------------------------
RULES = [
    {
        "name": "Darktrace AI Analyst Incident",
        "description": ("Darktrace AI Analyst raised an incident "
                        "(lateral movement, data exfiltration, suspicious "
                        "SaaS activity, etc.) — top-priority NDR finding."),
        "severity": "Critical",
        "s1ql": ("dataSource.vendor='Darktrace' AND class_uid=2004 "
                 "AND finding_title contains 'AI Analyst'"),
        "queryType": "events",
        "queryLang": "2.0",
        "expirationMode": "Permanent",
        "status": "Active",
    },
    {
        "name": "Darktrace Antigena Autonomous Response Triggered",
        "description": ("Darktrace Antigena autonomously blocked traffic — "
                        "high-confidence threat already mitigated by the system."),
        "severity": "High",
        "s1ql": ("dataSource.vendor='Darktrace' AND class_uid=2004 "
                 "AND finding_title contains 'Antigena'"),
        "queryType": "events",
        "queryLang": "2.0",
        "expirationMode": "Permanent",
        "status": "Active",
    },
    {
        "name": "Darktrace Model Breach",
        "description": ("Darktrace model breach detected — behavioural "
                        "anomaly worth investigating."),
        "severity": "High",
        "s1ql": ("dataSource.vendor='Darktrace' AND class_uid=2004 "
                 "AND finding_title contains 'Model Breach'"),
        "queryType": "events",
        "queryLang": "2.0",
        "expirationMode": "Permanent",
        "status": "Active",
    },
]


# ---------------------------------------------------------------------------
def discover_site_id(c: S1Client) -> str:
    """Pick the first site available to this token."""
    if SITE_ID:
        return SITE_ID
    sites = c.get("/web/api/v2.1/sites", params={"limit": 10})
    items = (sites.get("data") or {}).get("sites") or []
    if not items:
        raise RuntimeError("No sites visible to this API token")
    print("Available sites:")
    for s in items:
        print(f"  • {s.get('name')}  (id={s.get('id')})")
    chosen = items[0]
    print(f"\nUsing first site: {chosen.get('name')}  (id={chosen.get('id')})\n")
    return chosen["id"]


def existing_rule_names(c: S1Client, site_id: str):
    """Return names of STAR rules already in this site to avoid duplicates."""
    names = set()
    try:
        for page in c.paginate("/web/api/v2.1/cloud-detection/rules",
                               params={"siteIds": site_id, "limit": 100}):
            for r in page.get("data") or []:
                if r.get("name"):
                    names.add(r["name"])
    except Exception as e:
        print(f"  WARN: could not list existing rules ({str(e)[:120]})")
    return names


def create_rule(c: S1Client, rule: dict, site_id: str):
    resp = c.post(
        "/web/api/v2.1/cloud-detection/rules",
        json_body={"data": rule, "filter": {"siteIds": [site_id]}},
    )
    rule_id = ((resp.get("data") or {}).get("id")
               or (isinstance(resp.get("data"), list) and resp["data"]
                   and resp["data"][0].get("id"))
               or None)
    return rule_id


def enable_rule(c: S1Client, rule_id: str) -> None:
    c.put("/web/api/v2.1/cloud-detection/rules/enable",
          json_body={"filter": {"ids": [rule_id]}})


def main() -> int:
    c = S1Client(base_url=MGMT_BASE_URL)
    print(f"Console: {c.base_url}\n")

    site_id = discover_site_id(c)
    existing = existing_rule_names(c, site_id)
    if existing:
        print(f"Existing STAR rules in this site: {len(existing)}")

    print("\n" + "=" * 70)
    print("DEPLOY DARKTRACE STAR RULES")
    print("=" * 70)
    created = skipped = errors = 0
    for rule in RULES:
        if rule["name"] in existing:
            print(f"  SKIP  {rule['name']}  (already exists)")
            skipped += 1
            continue
        print(f"  CREATE  {rule['name']}")
        print(f"          severity={rule['severity']}  s1ql={rule['s1ql']}")
        try:
            rid = create_rule(c, rule, site_id)
            if rid:
                enable_rule(c, rid)
                print(f"          OK  id={rid}  enabled")
                created += 1
            else:
                print(f"          WARN  no id returned")
                errors += 1
        except Exception as e:
            print(f"          ERR  {str(e)[:200]}")
            errors += 1

    print("\n" + "=" * 70)
    print(f"RESULT — created={created}  skipped={skipped}  errors={errors}")
    print("=" * 70)
    print("\nRules become Active in the console within ~1 hour of enablement.")
    print("Then matching Darktrace events will produce alerts at:")
    print("  • Detect → Findings")
    print("  • Incidents → Unified Alerts")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
