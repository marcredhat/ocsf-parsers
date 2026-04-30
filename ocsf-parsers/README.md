# OCSF v1.3.0 Parsers for SentinelOne Singularity Data Lake

16 production-ready SDL log parsers that normalize vendor-specific logs into the
**Open Cybersecurity Schema Framework (OCSF) v1.3.0** and emit **Detection
Findings (`class_uid=2004`)** that surface in the AI SIEM **Detect → Findings**
UI when paired with a Custom Detection Rule.

## What's included

| Parser | OCSF Class | Vendor / Product |
|---|---|---|
| `linux-os.conf` | 2004 / 1007 / 3002 | Linux syslog + auditd |
| `fortinet-fortigate.conf` | 2004 / 4001 | Fortinet FortiGate |
| `windows-security.conf` | 2004 / 3002 | Microsoft Windows Security XML |
| `microsoft-entra-id.conf` | 2004 / 3002 | Microsoft Entra ID (Azure AD) |
| `microsoft-dns-debug.conf` | 2004 / 4003 | Microsoft DNS Server |
| `microsoft-dhcp.conf` | 2004 / 4004 | Microsoft DHCP |
| `isc-bind.conf` | 2004 / 4003 | ISC BIND DNS |
| `paloalto-pa.conf` | 2004 / 4001 / 4002 | Palo Alto PAN-OS |
| `checkpoint.conf` | 2004 / 4001 | Check Point Quantum |
| `watchguard-fireware.conf` | 2004 / 4001 | WatchGuard Fireware |
| `f5-bigip.conf` | 2004 / 4002 | F5 BIG-IP LTM / ASM |
| `f5-bigip-apm.conf` | 2004 / 3002 / 3005 | F5 BIG-IP APM (VPN) |
| `oracle-rdbms-audit.conf` | 2004 / 4001 | Oracle Database |
| `hana-database.conf` | 2004 / 4001 | SAP HANA Database |
| `qradar.conf` | 2004 / 4001 | IBM QRadar |
| `sim-generic.conf` | 2004 / 3002 | Generic syslog application |

## Validated results (last run)

```
Total Detection Findings indexed: 220
Sources producing findings:        13/13
Unique finding titles:             26+
Severity distribution:             Critical=50, High=125, Medium=32
```

| Source | Findings | Top types |
|---|---|---|
| `attack-target-05` (legacy) | 69 | HANA Auth Fail, Mass Exfil, PrivEsc, Backup |
| `linux-ocsf` | 36 | SSH Brute Force, Sudo Privesc, Cred Dump, Reverse Shell |
| `hana-ocsf` | 27 | Auth Failure, SQL Injection, Mass Data Extraction |
| `fortigate-ocsf` | 24 | Firewall Deny |
| `sim-ocsf` | 12 | Application Errors |
| `paloalto-ocsf` | 12 | Vuln Exploit, Spyware/C2, Threat Detected |
| `entra-ocsf` | 11 | Authentication Failure |
| `qradar-ocsf` | 10 | Suspicious Activity, Malware |
| `bind-ocsf` | 6 | Security Warning |
| `msdhcp-ocsf` | 4 | IP Conflict |
| `windows-ocsf` | 4 | 4625 Logon Fail, 4720 New User |
| `f5ltm-ocsf` | 3 | WAF Block, SSL Fail, ASM Attack |
| `f5apm-ocsf` | 2 | Auth Failure, Access Deny |

## Quick start

```bash
# 1. Deploy all 16 parsers + ingest sample data + run validation queries
python3 deploy_all_parsers.py

# 2. Trigger every detection scenario (refreshes timestamps to NOW)
python3 trigger_all_detections.py

# 3. Validate detections via PowerQuery
python3 validate_detections.py
```

Required: `../config.json` containing your SDL `base_url`, `read_key`, `log_write_key`,
and `config_write_key` (parent project's standard config).

## Repository layout

```
ocsf-parsers/
├── parsers/                      # 16 OCSF parsers (.conf files)
├── sample-data/                  # 16 sample logs (one per parser)
├── trigger-detections/           # 7 attack-scenario trigger logs
├── dashboards/                   # JSON dashboards (XDR-ready + native)
├── deploy_all_parsers.py         # Deploy all 16 parsers
├── trigger_all_detections.py     # Re-ingest with fresh timestamps
├── validate_detections.py        # Run validation PowerQueries
├── fix_outstanding.py            # Targeted fix script for 3 parsers
├── DEMO_GUIDE.md                 # Step-by-step demo walkthrough
├── DETECTIONS_AND_HUNTING.md     # All Detection Finding rules / hunts
├── AI_SIEM_DETECTIONS.md         # XDR Findings UI integration guide
└── POWERQUERY_REFERENCE.md       # Confirmed-working SDL PQ syntax
```

## How Detection Findings work

The parsers don't directly create Findings in the AI SIEM UI — they normalize
events into OCSF schema with `class_uid=2004` plus `finding_title`,
`severity`, `severity_id`, `disposition`. To make these appear in
**Detect → Findings**, create a Custom Detection Rule:

1. **AI SIEM Console → Detect → Custom Detection Rules → + New Rule**
2. **Query Language:** PowerQuery
3. **Query:** `class_uid='2004'`
4. **Schedule:** Every 5 min, lookback 15 min
5. Save & enable.

See `AI_SIEM_DETECTIONS.md` for granular per-source rule recipes.

## Sample PowerQueries

```pq
# All detection findings by source
class_uid='2004'
| group hits=count() by serverHost, finding_title
| sort -hits

# Critical findings only
class_uid='2004' AND severity_id='5'
| group hits=count() by serverHost, finding_title
| sort -hits

# Top attacker IPs
class_uid='2004' AND src_ip != ''
| group hits=count() by src_ip
| sort -hits | limit 20

# Linux SSH brute force then successful login
serverHost='linux-ocsf'
| parse 'Failed password for $f_user$ from $f_ip$'
| parse 'Accepted password for $a_user$ from $a_ip$'
| group fails=count(f_user), success=count(a_user) by serverHost, f_ip
| filter fails >= 3 and success >= 1
```

See `POWERQUERY_REFERENCE.md` for the full list of confirmed-working SDL PQ
functions and known limitations (e.g., `if`, `coalesce`, `countif`, `distinctcount`,
`group_to_str` are NOT available — use `count(field)` and basic aggregates).

## Parser DSL gotchas (learned the hard way)

When writing or editing `.conf` parsers:

- **Discard pattern is plain regex outside `$...$`** — do NOT use `$=.*$` (that
  syntax requires a name). Just use `.*` inline.
- **Greedy captures need anchored terminators** — `$x=rest$` (with
  `rest=".*"`) consumes everything; use `$x=word$` (with `word="\\S+"`) when a
  literal follows immediately, or define a non-greedy named pattern like
  `untilLT="[^<]*"` for XML.
- **No `kv` type** — for KV-formatted logs (FortiGate, Check Point) extract
  fields with explicit literals, e.g. `srcip=$src_ip=word$`.
- **Escape regex meta characters** — `[`, `]`, `(`, `)`, `|` inside format
  strings must be backslash-escaped: `auditd\\[$pid=word$\\]`.
- **Alternation goes in named patterns**, not inside `$...$` captures.

## Verifying ingestion

```bash
python3 validate_detections.py
```

Or from the XDR PowerQuery UI:

```pq
class_uid='2004'
| group hits=count() by serverHost, finding_title
| sort -hits
```

You should see all 13 sources reporting findings.
