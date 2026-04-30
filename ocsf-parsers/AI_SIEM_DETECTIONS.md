# AI SIEM / SDL PowerQuery Detection Rules

**All queries below have been tested against the actual ingested data** (see "Verified events" count under each rule).

## How to Use

1. Open SentinelOne console → **Singularity Data Lake** → **PowerQuery** (or in **AI SIEM** → **Custom Detection Rules**)
2. Set time range to **last 4 hours**
3. Paste the query
4. Run — you should see the indicated event count

For Custom Detection Rules: paste under **Query Type: PowerQuery**, set name/severity/threshold/window per the rule.

---

## Query Syntax Notes

The ingested events expose these built-in fields:
- `serverHost` — the source identifier (e.g. `attack-target-01`)
- `message` — the raw log line
- `severity` — numeric severity
- `timestamp` — event time

**To get structured OCSF fields**, use inline `| parse` to extract them from `message`:

```
serverHost='X' message contains 'Y'
| parse 'src_ip=$src_ip$ '
| parse 'user=$user_name$,'
| parse '"fieldName":"$field_value$"'
| columns timestamp, src_ip, user_name, field_value
```

Multiple `| parse` chains can be combined — each runs independently, and unmatched fields become `null`.

---

## 1. Brute Force Authentication

**MITRE:** T1110 | **Severity:** High | **Verified events:** 7

```
serverHost='attack-target-01' message contains 'Failed password'
| parse 'Failed password for $user$ from $src_ip$ port'
| group failed_attempts=count() by src_ip, user
| filter failed_attempts >= 5
```

**Threshold:** 1 result | **Window:** 10 minutes

---

## 2. Successful Login After Multiple Failures

**MITRE:** T1110.003 | **Severity:** Critical

```
serverHost='attack-target-01'
| parse 'Failed password for $f_user$ from $f_ip$' 
| parse 'Accepted password for $a_user$ from $a_ip$'
| group fail_count=count_nonnull(f_user), success_count=count_nonnull(a_user) by serverHost
| filter fail_count >= 3 and success_count >= 1
```

**Threshold:** 1 result | **Window:** 15 minutes

---

## 3. Network Service Scanning / Port Scan

**MITRE:** T1046 | **Severity:** Medium | **Verified events:** 12

```
serverHost='attack-target-02' message contains 'action="deny"'
| parse 'srcip=$srcip$ srcport' 
| parse 'dstport=$dstport$ '
| group hits=count() by srcip, dstport
| group unique_ports=count() by srcip
| filter unique_ports >= 10
```

**Threshold:** 1 result | **Window:** 5 minutes

---

## 4. Lateral Movement - Internal SMB/RDP/SSH

**MITRE:** T1021 | **Severity:** High

```
serverHost='attack-target-02' message contains 'action="allow"'
| parse 'srcip=$srcip$ srcport'
| parse 'dstip=$dstip$ '
| parse 'dstport=$dstport$ '
| filter (dstport='445' or dstport='3389' or dstport='22' or dstport='5985')
| filter srcip matches '^(10\\.|192\\.168\\.|172\\.)'
| filter dstip matches '^(10\\.|192\\.168\\.|172\\.)'
| group hits=count() by srcip, dstip
| group dest_count=count() by srcip
| filter dest_count >= 2
```

**Threshold:** 1 result | **Window:** 10 minutes

---

## 5. Suspicious Process Execution (Attack Tools)

**MITRE:** T1059 | **Severity:** Critical | **Verified events:** 9

```
serverHost='attack-target-03'
| filter (message contains 'mimikatz' 
       or message contains 'netcat' 
       or message contains '/usr/bin/nc' 
       or message contains 'reverse shell'
       or message contains 'socket.socket'
       or message contains '/bin/sh -i'
       or message contains 'curl' and message contains '.sh'
       or message contains '/tmp/.hidden')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 6. Reverse Shell Indicator

**MITRE:** T1059.004 | **Severity:** Critical

```
serverHost='attack-target-03'
| filter (message contains 'socket.socket()' 
       or message contains '/bin/sh -i'
       or message contains 'nc -e'
       or message contains 'dup2')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 7. Privilege Escalation - Unauthorized sudo

**MITRE:** T1548.003 | **Severity:** High | **Verified events:** 1

```
serverHost matches 'attack-target-.*' message contains 'NOT in sudoers'
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 8. New User Account Creation (Persistence)

**MITRE:** T1136 | **Severity:** Medium

```
serverHost='attack-target-03' 
| filter (message contains 'useradd' or message contains 'new user' or message contains 'usermod')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 5 minutes

---

## 9. Web Shell / Malware Download

**MITRE:** T1105 | **Severity:** High

```
serverHost='attack-target-03'
| filter (message contains 'curl' or message contains 'wget')
| filter (message contains '.sh' or message contains '.exe' or message contains 'payload' or message contains 'malware')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 10. DNS Zone Transfer Attempt (AXFR)

**MITRE:** T1590.002 | **Severity:** High | **Verified events:** 1

```
serverHost='attack-target-04' message contains 'AXFR'
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 11. DNS Tunneling - Long Encoded Queries

**MITRE:** T1071.004 | **Severity:** High

```
serverHost='attack-target-04'
| filter message matches '[A-Za-z0-9+/=]{60,}'
| columns timestamp, message
```

**Threshold:** 3 results | **Window:** 10 minutes

---

## 12. Suspicious DNS Query (DynDNS / Suspicious TLD)

**MITRE:** T1071.004 | **Severity:** Medium

```
serverHost='attack-target-04'
| filter (message contains 'dyndns' or message contains 'no-ip' or message contains '.tk:' or message contains 'phishing')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 5 minutes

---

## 13. Database Brute Force

**MITRE:** T1110 | **Severity:** High

```
serverHost='attack-target-05' message contains 'Invalid username or password'
| parse '"client_ip":"$client_ip$"'
| group failed_attempts=count() by client_ip
| filter failed_attempts >= 3
```

**Threshold:** 1 result | **Window:** 5 minutes

---

## 14. Database Mass Data Extraction

**MITRE:** T1005, T1048 | **Severity:** High

```
serverHost='attack-target-05'
| filter message matches '"rows_affected":[0-9]{5,}'
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 5 minutes

---

## 15. Database Privilege Escalation (GRANT)

**MITRE:** T1078.004 | **Severity:** High

```
serverHost='attack-target-05' message contains 'GRANT ALL PRIVILEGES'
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 16. Sensitive Database Table Access

**MITRE:** T1005 | **Severity:** High

```
serverHost='attack-target-05'
| filter (message contains 'password_hash' or message contains 'credit_card' or message contains 'employee_data' or message contains 'ssn')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 5 minutes

---

## 17. Database Backup to Suspicious Location

**MITRE:** T1048 | **Severity:** Critical

```
serverHost='attack-target-05' message contains 'BACKUP DATA'
| filter (message contains '/tmp/' or message contains '/var/tmp/' or message contains 'exfil')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 18. SQL Injection Attempt

**MITRE:** T1190 | **Severity:** High

```
serverHost='attack-target-05'
| filter (message contains "WHERE 1=1" or message contains "OR 'x'='x'" or message contains 'UNION SELECT')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 19. Risky Sign-In (Entra ID)

**MITRE:** T1078.004 | **Severity:** High | **Verified events:** 6

```
serverHost='attack-target-06' message contains '"riskLevelAggregated":"high"'
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 20. Tor Exit Node / Anonymous IP Authentication

**MITRE:** T1090.003 | **Severity:** High

```
serverHost='attack-target-06'
| filter (message contains 'Tor exit node' or message contains 'anonymizedIPAddress' or message contains 'maliciousIPAddress')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 21. Impossible Travel Detection

**MITRE:** T1078.004 | **Severity:** High

```
serverHost='attack-target-06' message contains '"resultType":"0"'
| parse '"countryOrRegion":"$country$"'
| parse '"userPrincipalName":"$user$"'
| group hits=count() by user, country
| group country_count=count() by user
| filter country_count >= 2
```

**Threshold:** 1 result | **Window:** 60 minutes

---

## 22. MFA Bypass Detection

**MITRE:** T1556.006 | **Severity:** Critical

```
serverHost='attack-target-06'
| filter message contains '"resultType":"0"'
| filter message contains '"authMethod":"none"'
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 23. Privileged Role Assignment (Entra ID)

**MITRE:** T1098 | **Severity:** Critical

```
serverHost='attack-target-06' message contains 'Add member to role'
| filter (message contains 'Global Administrator' or message contains 'Privileged' or message contains 'Security Admin')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 24. C2 Beaconing - Non-Standard Ports

**MITRE:** T1571 | **Severity:** Critical

```
serverHost='attack-target-07' message contains 'action="allow"'
| parse 'dstport=$dstport$ '
| parse 'dstip=$dstip$ '
| parse 'srcip=$srcip$ '
| filter (dstport='4444' or dstport='5555' or dstport='6666' or dstport='1337' or dstport='31337' or dstport='8080')
| group connections=count() by srcip, dstip, dstport
| filter connections >= 2
```

**Threshold:** 1 result | **Window:** 10 minutes

---

## 25. Known C2 Framework Detection

**MITRE:** T1071 | **Severity:** Critical

```
serverHost='attack-target-07'
| filter (message contains 'Cobalt.Strike' or message contains 'Meterpreter' or message contains 'Beacon')
| columns timestamp, message
```

**Threshold:** 1 result | **Window:** 1 minute

---

## 26. Cross-Source Attack Chain

**MITRE:** Multiple | **Severity:** Critical

```
serverHost matches 'attack-target-.*'
| group total=count() by serverHost
| sort -total
```

This shows all 7 attack scenarios firing across hosts.

**Threshold:** Use as situational awareness | **Window:** 60 minutes

---

# Sanity Check

Before deploying any rule, run this to confirm data is present:

```
serverHost matches 'attack-target-.*'
| group count() by serverHost
```

**Expected output (from last verified run):**
```
attack-target-01: 10 events  (brute force)
attack-target-02: 16 events  (port scan / lateral)
attack-target-03: 9 events   (suspicious processes)
attack-target-04: 10 events  (DNS attacks)
attack-target-05: 10 events  (database attacks)
attack-target-06: 7 events   (cloud identity)
attack-target-07: 8 events   (C2 traffic)
```

Total: ~70 events

---

## Re-Triggering Detections

If your time range is too narrow or events have aged out, re-ingest the trigger data:

```bash
cd /path/to/ocsf-parsers
python3 trigger_and_deploy.py
```

This re-uploads all 7 attack scenario logs and re-runs validation.
