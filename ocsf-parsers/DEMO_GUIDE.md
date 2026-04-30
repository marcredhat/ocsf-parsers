# OCSF AI SIEM Demo Playbook

A 15-minute, story-driven demo showing **7 attack scenarios** firing **26 detections** across **16 OCSF-normalized data sources** in SentinelOne SDL / AI SIEM.

> **All queries below extract OCSF-aligned fields inline using `| parse`** so you see structured columns (src_ip, user_name, dst_port, etc.) rather than raw `message`. Every query has been verified live.

---

## Demo Narrative: The "APT-Friday" Breach Investigation

> "Imagine it's Friday at 5pm. Over the next 15 minutes, we'll walk through how an attacker compromises an environment, and how AI SIEM with OCSF-normalized data lets us detect every stage of the kill chain in real time."

---

## Pre-Demo Checklist

```bash
cd /path/to/ocsf-parsers
python3 trigger_and_deploy.py    # 30s — fresh attack data
python3 validate_detections.py    # confirms 26/26 firing
```

In your browser, set time range to **Last 1 hour**.

---

## ACT I — "The Threat Surface" (1 min)

> *"16 OCSF-normalized sources + 7 attack scenarios. Every source uses different vendor formats, but PowerQuery sees them uniformly."*

```
serverHost matches '(ocsf-.*|attack-target-.*)' 
| group event_count=count() by serverHost 
| sort -event_count
```

**Expected:** 23 hosts, ~210 events.

---

## ACT II — "The Kill Chain" (10 min)

Each stage = **one query** that shows OCSF-aligned fields.

---

### 🎯 Stage 1 — Reconnaissance (Port Scan) — *OCSF 4001 Network Activity*

> *"Attacker probes the network for open ports."*

```
serverHost='attack-target-02' message contains 'action="deny"' 
| parse 'srcip=$src_ip$ ' 
| parse 'dstip=$dst_ip$ ' 
| parse 'dstport=$dst_port$ ' 
| group hits=count() by src_ip, dst_port 
| group unique_ports=count() by src_ip 
| filter unique_ports >= 10
```

**Expected fields:**
| src_ip | unique_ports |
|--------|--------------|
| 10.0.1.50 | 12 |

**MITRE T1046 — Network Service Scanning**

---

### 🎯 Stage 2 — Initial Access (Brute Force) — *OCSF 3002 Authentication*

> *"They pivot to credential brute-force against the domain controller."*

```
serverHost='attack-target-01' message contains 'Failed password' 
| parse 'Failed password for $user_name$ from $src_ip$ port $src_port$' 
| group failed_attempts=count() by user_name, src_ip 
| filter failed_attempts >= 3 
| sort -failed_attempts
```

**Expected fields:**
| user_name | src_ip | failed_attempts |
|-----------|--------|-----------------|
| admin | 192.168.1.100 | 7+ |

**MITRE T1110 — Brute Force**

---

### 🎯 Stage 3 — Privilege Escalation (sudo) — *OCSF 3005 User Access*

> *"Once in, they try to read /etc/shadow."*

```
serverHost matches 'attack-target-.*' message contains 'NOT in sudoers' 
| parse 'sudo: $user_name$ : user NOT in sudoers' 
| parse 'COMMAND=$command$' 
| columns timestamp, user_name, command
```

**Expected fields:**
| user_name | command |
|-----------|---------|
| hacker | /bin/cat /etc/shadow |

**MITRE T1548.003 — Abuse Elevation Control**

---

### 🎯 Stage 4 — Execution (Reverse Shell + Mimikatz) — *OCSF 1007 Process Activity*

> *"They drop a Python reverse shell and download Mimikatz."*

```
serverHost='attack-target-03' 
| filter (message contains 'mimikatz' or message contains 'socket.socket' 
       or message contains 'nc -e' or message contains 'curl' 
       or message contains '/tmp/.hidden') 
| parse 'EXECVE argc=$argc$ a0="$proc_name$"' 
| columns timestamp, proc_name, message
```

**Expected:** Python reverse shell to `10.0.0.99:4444`, `wget mimikatz.exe`, netcat backdoor.

**MITRE T1059 — Command and Scripting Interpreter**

---

### 🎯 Stage 5 — Persistence (Backdoor Account) — *OCSF 3001 Account Change*

> *"They create a backdoor user with UID 0."*

```
serverHost='attack-target-03' message contains 'useradd' 
| parse 'new user: name=$new_user$,' 
| parse 'UID=$uid$,' 
| parse 'GID=$gid$,' 
| columns timestamp, new_user, uid, gid
```

**Expected fields:**
| new_user | uid | gid |
|----------|-----|-----|
| backdoor | 0 | 0 |

**MITRE T1136 — Create Account**

---

### 🎯 Stage 6 — Lateral Movement (SMB) — *OCSF 4001 Network Activity*

> *"They start moving laterally via SMB."*

```
serverHost='attack-target-02' message contains 'action="allow"' message contains 'dstport=445' 
| parse 'srcip=$src_ip$ ' 
| parse 'dstip=$dst_ip$ ' 
| parse 'dstport=$dst_port$ ' 
| columns timestamp, src_ip, dst_ip, dst_port
```

**Expected fields:**
| src_ip | dst_ip | dst_port |
|--------|--------|----------|
| 10.0.1.50 | 10.0.1.101 | 445 |
| 10.0.1.50 | 10.0.1.102 | 445 |
| 10.0.1.50 | 10.0.1.103 | 445 |

**MITRE T1021.002 — SMB/Windows Admin Shares**

---

### 🎯 Stage 7 — Cloud Identity Attack — *OCSF 3002 Authentication*

> *"Meanwhile, they're hitting Entra ID from a Tor exit node — and 5 min later, login from Japan."*

```
serverHost='attack-target-06' 
| parse '"userPrincipalName":"$user_name$"' 
| parse '"callerIpAddress":"$src_ip$"' 
| parse '"countryOrRegion":"$country$"' 
| parse '"resultType":"$result_code$"' 
| parse '"riskLevelAggregated":"$risk_level$"' 
| filter (risk_level='high' or message contains 'Tor exit node' or message contains 'Impossible travel') 
| columns timestamp, user_name, src_ip, country, result_code, risk_level
```

**Expected fields:**
| user_name | src_ip | country | result_code | risk_level |
|-----------|--------|---------|-------------|------------|
| admin@corp... | 185.220.101.1 | RU | 50126 | high |
| admin@corp... | 185.220.101.1 | RU | 0 | high |
| admin@corp... | 203.0.113.50 | JP | 0 | high |

**MITRE T1078.004 + T1090.003 + T1556.006**

---

### 🎯 Stage 8 — Database Exfiltration — *OCSF 4001 Database Activity → 2004 Detection Finding*

> *"They pivot to HANA. Watch the parser auto-promote risky events to XDR Detection Findings."*

The `HANADatabase-OCSF` parser extracts native OCSF fields **and** promotes 5 risky patterns to `class_uid=2004` (Detection Finding) so they appear in **XDR Findings UI** alongside SDL search.

```
serverHost='attack-target-05' class_uid='2004' 
| group hits=count() by finding_title, severity 
| sort -hits
```

**Expected fields (Detection Findings only):**

| finding_title | severity | hits |
|---------------|----------|------|
| HANA Authentication Failure | 4 (High) | 7 |
| HANA Mass Data Extraction | 5 (Critical) | 2 |
| HANA SQL Injection Detected | 5 (Critical) | 1 |
| HANA Privilege Escalation | 5 (Critical) | 1 |
| HANA Suspicious Backup Location | 5 (Critical) | 1 |

**Drill into the SQL injection finding:**

```
serverHost='attack-target-05' finding_title='HANA SQL Injection Detected' 
| columns timestamp, src_ip, user_name, statement, severity, disposition
```

**Expected:**
| src_ip | user_name | statement | severity | disposition |
|--------|-----------|-----------|----------|-------------|
| 192.168.1.200 | attacker | SELECT \* FROM USERS WHERE 1=1 OR 'x'='x' | 5 | Blocked |

**MITRE T1190 → T1005 → T1078.004 → T1048**

> **Why this matters:** The parser does the heavy lifting. No need for `| parse` — fields like `src_ip`, `user_name`, `rows_affected`, `statement`, `class_uid`, `finding_title`, `severity`, `disposition` are extracted natively from JSON. Findings appear in **XDR Findings UI**, not just SDL search.

---

### 🎯 Stage 9 — Command & Control — *OCSF 4001 Network Activity*

> *"Throughout the breach, they're beaconing back to their C2."*

```
serverHost='attack-target-07' 
| filter (message contains 'attack=' or message contains 'dstport=4444') 
| parse 'srcip=$src_ip$ ' 
| parse 'dstip=$dst_ip$ ' 
| parse 'dstport=$dst_port$ ' 
| parse 'attack="$attack_name$"' 
| parse 'severity="$severity_label$"' 
| columns timestamp, src_ip, dst_ip, dst_port, attack_name, severity_label
```

**Expected fields:**
| src_ip | dst_ip | dst_port | attack_name | severity_label |
|--------|--------|----------|-------------|----------------|
| 10.0.1.100 | 185.220.101.99 | — | Cobalt.Strike.Beacon | critical |
| 10.0.1.101 | 185.220.101.99 | — | Meterpreter.Reverse.Shell | critical |
| 10.0.1.100 | 185.220.101.99 | 4444 | — | — |

**MITRE T1571 + T1071**

---

### 🎯 Stage 10 — DNS Tunneling & Recon — *OCSF 4003 DNS Activity*

> *"And they're using DNS for both recon and exfil."*

```
serverHost='attack-target-04' 
| filter (message contains 'AXFR' or message matches '[A-Za-z0-9+/=]{60,}' or message contains 'dyndns') 
| parse ' query: $query_name$ IN $query_type$' 
| columns timestamp, query_name, query_type
```

**Expected fields:**
| query_name | query_type |
|------------|------------|
| corp.local | AXFR |
| aGVsbG8td29ybGQ... (base64) | TXT |
| c2VjcmV0LWRhdGE... (base64) | TXT |
| malware.dyndns.org | A |

**MITRE T1590.002 + T1071.004**

---

## ACT III — "Cross-Source Correlation" (2 min)

> *"Same attacker IPs across firewall, endpoint, DNS, database, AND cloud — impossible to spot in siloed tools."*

### Step 1 — Wide-table view: which attacker IP appeared in which source?

This single query parses `src_ip` from **5 different vendor formats** (FortiGate KV, syslog SSH, BIND DNS, HANA JSON, Entra JSON) and groups by source + IP.

```
serverHost matches 'attack-target-.*' 
| parse 'password for $u$ from $ip_ssh$ port' 
| parse 'srcip=$ip_forti$ ' 
| parse '"client_ip":"$ip_db$"' 
| parse '"callerIpAddress":"$ip_entra$"' 
| parse 'info: client @$h$ $ip_dns$#' 
| filter (ip_ssh != null or ip_forti != null or ip_db != null or ip_entra != null or ip_dns != null) 
| group events=count() by serverHost, ip_ssh, ip_forti, ip_db, ip_entra, ip_dns 
| sort -events
```

**Expected (~11 rows):**

| serverHost | ip_ssh | ip_forti | ip_db | ip_entra | ip_dns | events |
|------------|--------|----------|-------|----------|--------|--------|
| attack-target-02 | — | 10.0.1.50 | — | — | — | 32 |
| attack-target-05 | — | — | 192.168.1.200 | — | — | 20 |
| attack-target-04 | — | — | — | — | 10.0.1.50 | 8 |
| attack-target-04 | — | — | — | — | 192.168.1.200 | 4 |
| attack-target-01 | 192.168.1.100 | — | — | — | — | 16 |
| attack-target-06 | — | — | — | 185.220.101.1 | — | 8 |
| attack-target-07 | — | 10.0.1.100 | — | — | — | 14 |

> **Look closely:** `10.0.1.50` appears in **both** attack-target-02 (FortiGate port scan) **and** attack-target-04 (BIND DNS). `192.168.1.200` appears in **both** attack-target-04 (DNS) **and** attack-target-05 (HANA DB). **That's the kill chain.**

### Step 2 — Find IPs that crossed multiple sources (run from CLI)

PowerQuery doesn't have `coalesce()` to merge nullable fields, so the cross-source aggregation is done with multiple per-source queries (`demo_runner.py` does this automatically):

```bash
python3 demo_runner.py --auto
```

Final output (verified live):

```
attacker_ip       #sources  events  sources_touched
--------------------------------------------------------------------
🔥 10.0.1.50      2         36      attack-target-02, attack-target-04
🔥 192.168.1.200  2         22      attack-target-04, attack-target-05
   192.168.1.100  1         16      attack-target-01
   10.0.1.100     1         14      attack-target-07
   185.220.101.1  1         8       attack-target-06

🎯 KILLER SIGNAL: 2 IP(s) appear in 2+ sources
```

> *"Two IPs touched multiple security sources. That's the breach pattern that single-product tools miss entirely."*

### Step 3 — Total event volume per source

```
serverHost matches 'attack-target-.*' 
| group event_count=count() by serverHost 
| sort -event_count
```

**Expected:** All 7 attack-target hosts, ~140 events total.

### Show the dashboards

**Singularity Data Lake → Dashboards** (search for `ocsf-`):

1. **`ocsf-mitre-attack`** — count panel per MITRE technique
2. **`ocsf-threat-detection`** — every detection visualized
3. **`ocsf-security-overview`** — overall posture

---

## ACT IV — "Operationalize" (1 min)

> *"All 26 detections are saved in `AI_SIEM_DETECTIONS.md` ready to paste into AI SIEM Custom Detection Rules."*

For each rule:
1. **AI SIEM** → **Detection Rules** → **Custom Rules** → **Create Rule**
2. Set **Query Type:** PowerQuery
3. Paste the query
4. Set **Severity, Threshold, Window** per the markdown
5. Map MITRE ATT&CK technique
6. Save and enable

---

## Closing Pitch

> "In 15 minutes:
> - **7 attack scenarios** spanning the full kill chain
> - **26 detections** all firing on real data
> - **16 OCSF-normalized sources** queried with one syntax
> - **Inline parsing** extracting OCSF fields (src_ip, user_name, dst_port, etc.) from any vendor format
> - **3 dashboards** visualizing the entire attack
>
> No per-vendor SIEM rules. No format wrangling. Just attacker behavior, detected — across every source."

---

## Demo Cheat Sheet (Print This)

| # | Stage | Host | Key OCSF fields shown | MITRE | Events |
|---|-------|------|------------------------|-------|--------|
| 0 | Surface | all | serverHost, event_count | — | 210 |
| 1 | Recon | attack-target-02 | src_ip, dst_port, unique_ports | T1046 | 12 |
| 2 | Brute Force | attack-target-01 | user_name, src_ip, failed_attempts | T1110 | 7+ |
| 3 | Priv Esc | attack-target-03 | user_name, command | T1548.003 | 1+ |
| 4 | Execution | attack-target-03 | proc_name | T1059 | 4+ |
| 5 | Persistence | attack-target-03 | new_user, uid, gid | T1136 | 1+ |
| 6 | Lateral | attack-target-02 | src_ip, dst_ip, dst_port | T1021.002 | 3+ |
| 7 | Cloud Id | attack-target-06 | user_name, src_ip, country, risk_level | T1078.004 | 6+ |
| 8 | DB Exfil | attack-target-05 | src_ip, statement, rows_affected | T1005 | 4+ |
| 9 | C2 | attack-target-07 | src_ip, dst_ip, attack_name, severity_label | T1571 | 5+ |
| 10 | DNS Tunnel | attack-target-04 | query_name, query_type | T1071.004 | 4+ |

---

## PowerQuery Syntax Tips Used in This Demo

### Inline parsing (key technique)

`| parse 'pattern with $field_name$ markers'` extracts named groups into columns. Multiple `| parse` directives can be chained — each tries to match independently. Failed parses leave the field as `null`.

**Example for FortiGate KV format:**
```
| parse 'srcip=$src_ip$ '
| parse 'dstport=$dst_port$ '
| parse 'action="$action$"'
```

### Distinct counts (no `count_distinct`)

```
| group _=count() by outer_field, inner_field    # dedup by both
| group n=count() by outer_field                  # count dedup'd inner rows
```

### JSON field extraction

```
| parse '"fieldName":"$field_value$"'      # string values
| parse '"fieldName":$field_value$,'        # numeric values (no quotes)
```
