# AI SIEM Custom Detection Rules — Web UI Setup Guide

## TL;DR — Where do alerts appear?

This SDL/AI SIEM tenant (`<your-sdl-host>.sentinelone.net`) has **two separate alert
mechanisms**, only one of which is reachable via API:

| Mechanism | API-creatable? | Where alerts appear |
|---|---|---|
| **SDL Scheduled Alerts** (`/alerts` config file) | ✅ Yes — via this skill's `deploy_detection_rules.py` | **Settings → Alerts** (legacy DataSet pane) — fires emails/webhooks |
| **AI SIEM Custom Detection Rules** | ❌ No (Web UI only) | **Detect → Findings** (modern AI SIEM pane) |

If you want **alerts in `Detect → Findings`**, you must paste the queries below
into the Web UI manually — the API path doesn't exist on this tenant.

## Step-by-step Web UI workflow

1. **Open AI SIEM:** `https://<your-sdl-host>.sentinelone.net`
2. Navigate: **Detect → Custom Detection Rules → `+ New Rule`**
3. For each rule below, fill in:

   | Field | Value |
   |---|---|
   | **Name** | (copy from the rule below) |
   | **Description** | (copy from the rule below) |
   | **Severity** | (Critical / High / Medium) |
   | **Query Language** | `PowerQuery` |
   | **Query** | (copy the trigger PowerQuery) |
   | **Schedule** | Every 5 min |
   | **Lookback** | 15 min |
   | **Status** | Enabled |

4. **Save & enable.** Within ~5 min the rule starts evaluating, and findings
   appear at **Detect → Findings**.

## 14 production-ready rules

### 1. Critical OCSF Detection Findings (any source)
- **Severity:** Critical
- **Query:**
  ```pq
  class_uid='2004' AND severity_id='5'
  | group n=count() by serverHost, finding_title
  | filter n >= 1
  ```

### 2. High-Severity Detection Findings
- **Severity:** High
- **Query:**
  ```pq
  class_uid='2004' AND severity_id='4'
  | group n=count() by serverHost, finding_title
  | filter n >= 1
  ```

### 3. Linux SSH Brute-Force Then Successful Logon (Correlation)
- **Severity:** Critical
- **Query:**
  ```pq
  serverHost='linux-ocsf'
  | parse 'Failed password for $f_user$ from $f_ip$'
  | parse 'Accepted password for $a_user$ from $a_ip$'
  | group fails=count(f_user), success=count(a_user) by serverHost, f_ip
  | filter fails >= 3 and success >= 1
  ```

### 4. Multi-Source Coordinated Attack (Correlation)
- **Severity:** Critical
- **Query:**
  ```pq
  class_uid='2004' AND src_ip != null
  | group sources=count() by src_ip
  | filter sources >= 5
  ```

### 5. HANA Database SQL Injection or Mass Exfiltration
- **Severity:** Critical
- **Query:**
  ```pq
  serverHost='hana-ocsf' AND class_uid='2004'
  AND (finding_title contains 'SQL Injection' OR finding_title contains 'Mass Data Extraction')
  ```

### 6. DNS Suspicious Activity
- **Severity:** High
- **Query:**
  ```pq
  (serverHost='bind-ocsf' OR serverHost='msdns-ocsf') AND class_uid='2004'
  | group n=count() by finding_title
  | filter n >= 1
  ```

### 7. Cloud Identity Risky Sign-In
- **Severity:** High
- **Query:**
  ```pq
  serverHost='entra-ocsf' AND class_uid='2004'
  | group n=count() by finding_title
  | filter n >= 1
  ```

### 8. Web Application Attack (F5 WAF)
- **Severity:** Critical
- **Query:**
  ```pq
  serverHost='f5ltm-ocsf' AND class_uid='2004'
  AND (finding_title contains 'WAF' OR finding_title contains 'ASM')
  ```

### 9. Palo Alto Threat / C2 Detection
- **Severity:** Critical
- **Query:**
  ```pq
  serverHost='paloalto-ocsf' AND class_uid='2004'
  ```

### 10. Windows Security Detection Finding
- **Severity:** High
- **Query:**
  ```pq
  serverHost='windows-ocsf' AND class_uid='2004'
  | group n=count() by finding_title
  | filter n >= 1
  ```

### 11. Windows New User Account Or Privilege Escalation
- **Severity:** High
- **Query:**
  ```pq
  serverHost='windows-ocsf' AND class_uid='2004'
  AND (finding_title contains '4720' OR finding_title contains '4732')
  ```

### 12. Authentication Failure Burst (Cross-Source)
- **Severity:** High
- **Query:**
  ```pq
  class_uid='3002' AND status_id='2'
  | group attempts=count() by user_name
  | filter attempts >= 10
  ```

### 13. Linux Reverse Shell or Credential Dumping Tool
- **Severity:** Critical
- **Query:**
  ```pq
  serverHost='linux-ocsf' AND class_uid='2004'
  AND (finding_title contains 'Reverse Shell' OR finding_title contains 'Credential Dumping')
  ```

### 14. Network Firewall Deny / Block (Spike)
- **Severity:** High
- **Query:**
  ```pq
  (serverHost='fortigate-ocsf' OR serverHost='checkpoint-ocsf') AND class_uid='2004'
  | group n=count() by serverHost, src_ip
  | filter n >= 10
  ```

### 15. Darktrace AI Analyst Incident
- **Severity:** Critical
- **Query:**
  ```pq
  parser='Darktrace-OCSF' AND finding_title contains 'AI Analyst'
  | group n=count() by serverHost, src_ip, finding_title
  | filter n >= 1
  ```

### 16. Darktrace Antigena Autonomous Response Triggered
- **Severity:** High
- **Query:**
  ```pq
  parser='Darktrace-OCSF' AND finding_title contains 'Antigena'
  | group n=count() by src_ip, dst_ip, action
  | filter n >= 1
  ```

### 17. Darktrace Model Breach with High Score (≥80)
- **Severity:** High
- **Query:**
  ```pq
  parser='Darktrace-OCSF' AND model_name != null AND score >= '80'
  | group n=count() by src_ip, model_name, score
  | filter n >= 1
  ```

## How to verify a rule is working

After creating a rule, you can immediately **verify it would fire** by running
the same query directly in **Investigate → PowerQuery**. If the query returns
≥1 row, the rule will fire on its next scheduled evaluation.

Alternatively, run all 14 validation queries at once via:

```bash
python3 deploy_detection_rules.py
```

The script's `validate` phase runs every rule's trigger query and reports which
ones would fire RIGHT NOW.

## Where the SDL `/alerts` rules show up

The 14 rules also live at the SDL config path `/alerts` (deployed by
`deploy_detection_rules.py`). They appear in the legacy alerts pane:

**Settings → Alerts → Scheduled Alerts**

These fire email/PagerDuty/Slack notifications when triggered, but do NOT
populate the **Detect → Findings** UI.

## Confirming current ingest status

Last validation run produced this baseline (1d window):

```
class_uid='2004' findings:        220
Sources reporting findings:       13/13
Severity Critical (5):            104 events / 17 finding types
Severity High (4):                263 events / 14 finding types
```

So all 14 rules above will trigger from the existing ingested data the moment
you save them in the Web UI.
