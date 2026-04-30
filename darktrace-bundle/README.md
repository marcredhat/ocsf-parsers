# Darktrace OCSF Bundle for SentinelOne Singularity AI SIEM

End-to-end bundle that:
1. Parses Darktrace CEF logs into OCSF v1.3.0 (Detection Finding 2004 / Auth 3002)
2. Ingests sample data into Singularity Data Lake (SDL)
3. Creates 3 STAR (Custom Detection) rules in the management console
4. Generates alerts in **Incidents → Unified Alerts**

## Files

| File | Purpose |
|---|---|
| `parsers/darktrace.conf`                | SDL parser — CEF → OCSF mapping |
| `sample-data/darktrace.log`             | 15 sample Darktrace CEF events (4 streams) |
| `detection-rules/alerts.json`           | SDL scheduled-alert rules (legacy) |
| `detection-rules/AI_SIEM_UI_GUIDE.md`   | Web-UI paste-in guide for AI SIEM rules |
| `deploy_darktrace.py`                   | 1️⃣ Deploy parser + ingest sample + validate 19 OCSF fields |
| `deploy_darktrace_star_rules.py`        | 2️⃣ Create + enable 3 STAR rules in mgmt console |
| `trigger_darktrace_alerts.py`           | 3️⃣ Burst-ingest curated CEF events that satisfy every rule |
| `validate_darktrace_rules.py`           | (optional) Confirm SDL rule trigger queries return rows |

## Prerequisites

The bundle expects the standard SDL/Mgmt-console Python clients next to it:

```
shared/sentinelone-sdl-api/scripts/sdl_client.py
shared/sentinelone-sdl-api/config.json                     # SDL keys
shared/sentinelone-mgmt-console-api/scripts/s1_client.py
shared/sentinelone-mgmt-console-api/config.json            # mgmt API token
```

Set the management-console URL via env var before running
`deploy_darktrace_star_rules.py`:

```bash
export S1_MGMT_URL="https://<your-tenant>.sentinelone.net"
```

## Run order (one-time setup)

```bash
# 1. Deploy parser, ingest sample, validate OCSF compliance
python3 deploy_darktrace.py

# 2. Create 3 STAR rules in the management console
python3 deploy_darktrace_star_rules.py

# Wait ~1 hour for STAR rules to become Active
```

## Generate alerts (any time)

```bash
python3 trigger_darktrace_alerts.py
# Refresh Incidents → Unified Alerts within ~5 min
```

## STAR rules created

| Rule | Severity | s1ql |
|---|---|---|
| Darktrace AI Analyst Incident | Critical | `dataSource.vendor='Darktrace' AND class_uid=2004 AND finding_title contains 'AI Analyst'` |
| Darktrace Antigena Autonomous Response Triggered | High | `dataSource.vendor='Darktrace' AND class_uid=2004 AND finding_title contains 'Antigena'` |
| Darktrace Model Breach | High | `dataSource.vendor='Darktrace' AND class_uid=2004 AND finding_title contains 'Model Breach'` |

## OCSF coverage validated

19/19 fields parsed: `class_uid` 2004 + 3002, `category_uid`, `type_uid`, `severity_id`,
`disposition`, `finding_title`, `src_ip`, `dst_ip`, `user_name`, `device_id`, `score`,
`model_name`, `action`, `status_id`.
