# Detection Rules & Threat Hunting Scenarios

Based on the ingested OCSF-normalized sample data from 16 security sources, this document provides detection rules and threat hunting queries for SentinelOne AI SIEM.

---

## Table of Contents

1. [Authentication & Identity Detections](#authentication--identity-detections)
2. [Network Security Detections](#network-security-detections)
3. [Endpoint Security Detections](#endpoint-security-detections)
4. [Database Security Detections](#database-security-detections)
5. [DNS Security Detections](#dns-security-detections)
6. [Cloud Identity Detections](#cloud-identity-detections)
7. [Threat Hunting Scenarios](#threat-hunting-scenarios)

---

## Authentication & Identity Detections

### 1. Brute Force Attack Detection

**Description**: Detect multiple failed login attempts from the same source IP.

**Sources**: Windows Security, Linux OS, F5 APM, Entra ID, HANA Database

```powerquery
// Brute force detection - 5+ failed logins in 10 minutes
serverHost in ('dc01.corp.local', 'linux-server01', 'f5-apm01', 'entra-id', 'hana-db01')
| parse "Failed|failure|Failure|INVALID_PASSWORD" as failed_indicator
| group count() as failed_attempts by src_endpoint_ip, user_name
| filter failed_attempts >= 5
| columns src_endpoint_ip, user_name, failed_attempts
```

**STAR Rule**:
```yaml
name: Brute Force Authentication Attack
description: Multiple failed authentication attempts from single source
severity: High
query: |
  class_uid=3002 status_id=2
  | group count() as attempts by src_endpoint.ip, user.name
  | filter attempts >= 5
threshold: 1
window: 10m
```

### 2. Successful Login After Multiple Failures

**Description**: Detect successful authentication following multiple failures (potential credential stuffing success).

**Sources**: Windows Security, Linux OS, Entra ID

```powerquery
// Successful login after failures - potential compromised account
serverHost in ('dc01.corp.local', 'linux-server01', 'entra-id')
| parse "Accepted|success|Success" as success_indicator
| join (
    serverHost in ('dc01.corp.local', 'linux-server01', 'entra-id')
    | parse "Failed|failure|Failure" as failed_indicator
    | group count() as prior_failures by src_endpoint_ip, user_name
    | filter prior_failures >= 3
) on src_endpoint_ip, user_name
| columns timestamp, src_endpoint_ip, user_name, prior_failures
```

### 3. Privileged Account Usage

**Description**: Monitor usage of privileged accounts (root, admin, Administrator).

**Sources**: Linux OS, Windows Security, Oracle RDBMS, HANA Database

```powerquery
// Privileged account activity
serverHost in ('linux-server01', 'dc01.corp.local', 'oracle-db01', 'hana-db01')
| parse "root|Administrator|admin|SYSTEM|SYS|SYSDBA" as priv_user
| columns timestamp, serverHost, user_name, activity_name, src_endpoint_ip
| sort -timestamp
```

### 4. Off-Hours Authentication

**Description**: Detect logins outside business hours (potential unauthorized access).

**Sources**: All authentication sources

```powerquery
// Off-hours login detection (before 6 AM or after 8 PM)
serverHost in ('dc01.corp.local', 'linux-server01', 'f5-apm01', 'entra-id')
| parse "Accepted|success|Success|session created" as login_indicator
| let hour = hour(timestamp)
| filter hour < 6 or hour > 20
| columns timestamp, serverHost, user_name, src_endpoint_ip, hour
```

---

## Network Security Detections

### 5. Firewall Deny Spike

**Description**: Detect unusual increase in firewall denies from a single source.

**Sources**: Fortinet FortiGate, Check Point, Palo Alto, WatchGuard

```powerquery
// Firewall deny spike detection
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01', 'watchguard-fw01')
| parse "deny|Deny|DENY|block|Block|drop|Drop" as deny_action
| group count() as deny_count by src_ip
| filter deny_count >= 100
| columns src_ip, deny_count
```

**STAR Rule**:
```yaml
name: Firewall Deny Spike
description: High volume of denied connections from single source
severity: Medium
query: |
  activity_id=2 category_uid=4
  | group count() as denies by src_endpoint.ip
  | filter denies >= 100
threshold: 1
window: 5m
```

### 6. Port Scan Detection

**Description**: Detect potential port scanning activity.

**Sources**: Fortinet FortiGate, Check Point, Palo Alto, WatchGuard

```powerquery
// Port scan detection - many ports from single source
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01', 'watchguard-fw01')
| group hits=count() by src_ip, dst_port
| group unique_ports=count() by src_ip
| filter unique_ports >= 20
| columns src_ip, unique_ports
```

### 7. Suspicious Outbound Connections

**Description**: Detect connections to suspicious ports (C2 common ports).

**Sources**: All firewall sources

```powerquery
// Suspicious outbound ports (common C2 ports)
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01', 'watchguard-fw01')
| parse "allow|Allow|accept|Accept" as allow_action
| filter dst_port in (4444, 5555, 6666, 8080, 8443, 9001, 1337, 31337)
| columns timestamp, src_ip, dst_ip, dst_port, serverHost
```

### 8. IPS/IDS Alert Correlation

**Description**: Correlate IPS alerts with firewall traffic.

**Sources**: Fortinet FortiGate, Check Point, Palo Alto, WatchGuard

```powerquery
// High severity IPS alerts
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01', 'watchguard-fw01')
| parse "attack|Attack|ATTACK|intrusion|Intrusion|signature|Signature" as ips_indicator
| parse "critical|Critical|CRITICAL|high|High|HIGH" as severity_indicator
| columns timestamp, serverHost, src_ip, dst_ip, attack_name, severity
| sort -timestamp
```

### 9. Lateral Movement Detection

**Description**: Detect internal-to-internal traffic on sensitive ports.

**Sources**: All firewall sources

```powerquery
// Lateral movement - internal to internal on admin ports
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01', 'watchguard-fw01')
| filter src_ip matches "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"
| filter dst_ip matches "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"
| filter dst_port in (22, 23, 135, 139, 445, 3389, 5985, 5986)
| columns timestamp, src_ip, dst_ip, dst_port, serverHost
```

---

## Endpoint Security Detections

### 10. Suspicious Process Execution

**Description**: Detect execution of known attack tools or suspicious processes.

**Sources**: Linux OS, Windows Security

```powerquery
// Suspicious process execution
serverHost in ('linux-server01', 'dc01.corp.local')
| parse "cmd_line|CommandLine|command" as cmd_field
| filter cmd_line matches "(mimikatz|psexec|nc\\.exe|ncat|netcat|powershell.*-enc|bash.*-i|python.*-c)"
| columns timestamp, serverHost, user_name, cmd_line
```

**STAR Rule**:
```yaml
name: Suspicious Process Execution
description: Known attack tool or suspicious command detected
severity: Critical
query: |
  class_uid=1007
  process.cmd_line contains_any ('mimikatz', 'psexec', 'nc.exe', 'ncat', 'netcat')
threshold: 1
window: 1m
```

### 11. Privilege Escalation via Sudo

**Description**: Detect sudo usage, especially by non-standard users.

**Sources**: Linux OS

```powerquery
// Sudo privilege escalation
serverHost='linux-server01'
| parse "sudo" as sudo_indicator
| columns timestamp, user_name, target_user, cmd_line
| filter target_user = 'root'
```

### 12. Unauthorized Sudoers Access

**Description**: Detect users attempting sudo who are not in sudoers.

**Sources**: Linux OS

```powerquery
// Unauthorized sudo attempts
serverHost='linux-server01'
| parse "NOT in sudoers" as unauthorized_indicator
| columns timestamp, user_name, cmd_line, src_endpoint_ip
```

**STAR Rule**:
```yaml
name: Unauthorized Sudo Attempt
description: User attempted sudo without authorization
severity: High
query: |
  serverHost='linux-server01' message contains 'NOT in sudoers'
threshold: 1
window: 1m
```

### 13. New User Account Creation

**Description**: Monitor for new user account creation.

**Sources**: Linux OS, Windows Security

```powerquery
// New user account creation
serverHost in ('linux-server01', 'dc01.corp.local')
| parse "useradd|New User|Account Created|4720" as user_creation_indicator
| columns timestamp, serverHost, actor_user_name, new_user_name, new_user_uid
```

### 14. Service Installation/Modification

**Description**: Detect new service installations or modifications.

**Sources**: Linux OS, Windows Security

```powerquery
// Service changes
serverHost in ('linux-server01', 'dc01.corp.local')
| parse "Started|Stopped|service|systemd|4697" as service_indicator
| columns timestamp, serverHost, service_name, activity_name, user_name
```

---

## Database Security Detections

### 15. Database Privilege Escalation

**Description**: Detect GRANT statements that elevate privileges.

**Sources**: Oracle RDBMS, HANA Database

```powerquery
// Database privilege grants
serverHost in ('oracle-db01', 'hana-db01')
| parse "GRANT|grant" as grant_indicator
| columns timestamp, serverHost, user_name, statement, target_user
```

**STAR Rule**:
```yaml
name: Database Privilege Grant
description: Database privileges granted to user
severity: High
query: |
  serverHost in ('oracle-db01', 'hana-db01') activity_name='GRANT'
threshold: 1
window: 5m
```

### 16. Sensitive Table Access

**Description**: Monitor access to sensitive tables (passwords, credentials, PII).

**Sources**: Oracle RDBMS, HANA Database

```powerquery
// Sensitive table access
serverHost in ('oracle-db01', 'hana-db01')
| parse "SELECT|select" as select_indicator
| filter statement matches "(password|credential|ssn|credit_card|salary|dba_users|sys\\.)"
| columns timestamp, serverHost, user_name, statement
```

### 17. Database Login from Unusual Source

**Description**: Detect database connections from unexpected IP addresses.

**Sources**: Oracle RDBMS, HANA Database

```powerquery
// Database login from unusual source
serverHost in ('oracle-db01', 'hana-db01')
| parse "CONNECT|connect|LOGON|logon" as connect_indicator
| filter not src_endpoint_ip matches "^(10\\.0\\.1\\.|192\\.168\\.1\\.)"
| columns timestamp, serverHost, user_name, src_endpoint_ip
```

### 18. Mass Data Export Detection

**Description**: Detect queries returning large result sets (potential data exfiltration).

**Sources**: Oracle RDBMS, HANA Database

```powerquery
// Large data export detection
serverHost in ('oracle-db01', 'hana-db01')
| parse "rows_affected|rows_returned" as rows_field
| filter rows_affected > 10000
| columns timestamp, serverHost, user_name, statement, rows_affected
```

---

## DNS Security Detections

### 19. DNS Zone Transfer Attempt

**Description**: Detect unauthorized zone transfer attempts (AXFR).

**Sources**: Microsoft DNS, ISC BIND

```powerquery
// DNS zone transfer attempts
serverHost in ('dns-server01', 'bind-dns01')
| parse "AXFR|zone transfer" as axfr_indicator
| columns timestamp, serverHost, src_endpoint_ip, query_hostname, status
```

**STAR Rule**:
```yaml
name: DNS Zone Transfer Attempt
description: Unauthorized DNS zone transfer attempt detected
severity: High
query: |
  serverHost in ('dns-server01', 'bind-dns01') query_type='AXFR'
threshold: 1
window: 1m
```

### 20. DNS Tunneling Detection

**Description**: Detect potential DNS tunneling via long domain names or high query volume.

**Sources**: Microsoft DNS, ISC BIND

```powerquery
// DNS tunneling - unusually long domain names
serverHost in ('dns-server01', 'bind-dns01')
| let domain_length = length(query_hostname)
| filter domain_length > 50
| columns timestamp, serverHost, src_endpoint_ip, query_hostname, domain_length
```

### 21. Suspicious DNS Queries

**Description**: Detect queries for known malicious or suspicious domains.

**Sources**: Microsoft DNS, ISC BIND

```powerquery
// Suspicious DNS queries
serverHost in ('dns-server01', 'bind-dns01')
| filter query_hostname matches "(dyndns|no-ip|afraid\\.org|tk$|ml$|ga$|cf$)"
| columns timestamp, serverHost, src_endpoint_ip, query_hostname
```

### 22. DNS Query Spike

**Description**: Detect unusual spike in DNS queries from a single source.

**Sources**: Microsoft DNS, ISC BIND

```powerquery
// DNS query spike detection
serverHost in ('dns-server01', 'bind-dns01')
| group count() as query_count by src_endpoint_ip
| filter query_count >= 1000
| columns src_endpoint_ip, query_count
```

---

## Cloud Identity Detections

### 23. Risky Sign-In Detection

**Description**: Detect sign-ins flagged as risky by Entra ID.

**Sources**: Microsoft Entra ID

```powerquery
// Risky sign-ins from Entra ID
serverHost='entra-id'
| parse "risk|Risk|RISK" as risk_indicator
| filter risk_level in ('high', 'medium')
| columns timestamp, user_name, src_endpoint_ip, risk_level, risk_detail, location_country
```

**STAR Rule**:
```yaml
name: Entra ID Risky Sign-In
description: High or medium risk sign-in detected by Entra ID
severity: High
query: |
  serverHost='entra-id' risk_level in ('high', 'medium')
threshold: 1
window: 1m
```

### 24. Impossible Travel Detection

**Description**: Detect logins from geographically distant locations in short time.

**Sources**: Microsoft Entra ID

```powerquery
// Impossible travel - logins from different countries
serverHost='entra-id'
| parse "success|Success" as success_indicator
| group hits=count() by user_name, location_country
| group country_count=count() by user_name
| filter country_count >= 2
| columns user_name, country_count
```

### 25. MFA Bypass Attempts

**Description**: Detect successful logins without MFA when MFA is required.

**Sources**: Microsoft Entra ID, F5 APM

```powerquery
// MFA bypass detection
serverHost in ('entra-id', 'f5-apm01')
| parse "success|Success" as success_indicator
| filter mfa_required = true and mfa_completed = false
| columns timestamp, user_name, src_endpoint_ip, app_name
```

### 26. Privileged Role Assignment

**Description**: Detect assignment of privileged roles (Global Admin, etc.).

**Sources**: Microsoft Entra ID

```powerquery
// Privileged role assignment
serverHost='entra-id'
| parse "Add member to role|role assignment" as role_indicator
| filter role_name matches "(Global Administrator|Privileged|Security Admin)"
| columns timestamp, actor_user_name, target_user_name, role_name
```

---

## Threat Hunting Scenarios

### Scenario 1: Compromised Credential Investigation

**Objective**: Hunt for signs of credential compromise and lateral movement.

```powerquery
// Step 1: Find failed logins followed by success
serverHost in ('dc01.corp.local', 'linux-server01', 'entra-id')
| parse "Failed|Accepted|success|failure" as auth_result
| group 
    count_if(auth_result matches "Failed|failure") as failures,
    count_if(auth_result matches "Accepted|success") as successes
  by user_name, src_endpoint_ip
| filter failures >= 3 and successes >= 1
| columns user_name, src_endpoint_ip, failures, successes

// Step 2: Check for lateral movement from compromised account
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01')
| filter src_ip = '<compromised_ip>'
| filter dst_port in (22, 135, 445, 3389, 5985)
| columns timestamp, src_ip, dst_ip, dst_port

// Step 3: Check for privilege escalation
serverHost in ('linux-server01', 'dc01.corp.local')
| filter user_name = '<compromised_user>'
| parse "sudo|runas|privilege|admin" as priv_indicator
| columns timestamp, user_name, activity_name, cmd_line
```

### Scenario 2: Data Exfiltration Investigation

**Objective**: Hunt for signs of data exfiltration.

```powerquery
// Step 1: Large database queries
serverHost in ('oracle-db01', 'hana-db01')
| filter rows_affected > 10000
| columns timestamp, user_name, statement, rows_affected, src_endpoint_ip

// Step 2: Unusual outbound traffic volume
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01')
| group sum(bytes_out) as total_bytes by src_ip
| filter total_bytes > 100000000
| columns src_ip, total_bytes

// Step 3: DNS tunneling indicators
serverHost in ('dns-server01', 'bind-dns01')
| let domain_length = length(query_hostname)
| filter domain_length > 50 or query_hostname matches "\\d{10,}"
| columns timestamp, src_endpoint_ip, query_hostname, domain_length
```

### Scenario 3: Insider Threat Investigation

**Objective**: Hunt for signs of malicious insider activity.

```powerquery
// Step 1: Off-hours access patterns
serverHost in ('dc01.corp.local', 'linux-server01', 'oracle-db01', 'hana-db01')
| let hour = hour(timestamp)
| filter hour < 6 or hour > 22
| group count() as off_hours_events by user_name
| filter off_hours_events >= 5
| columns user_name, off_hours_events

// Step 2: Sensitive data access
serverHost in ('oracle-db01', 'hana-db01')
| filter statement matches "(salary|ssn|password|credit_card|employee)"
| columns timestamp, user_name, statement, src_endpoint_ip

// Step 3: Privilege abuse
serverHost in ('linux-server01', 'dc01.corp.local')
| parse "sudo|Administrator|root" as priv_indicator
| group count() as priv_actions by user_name
| filter priv_actions >= 10
| columns user_name, priv_actions
```

### Scenario 4: APT/Advanced Threat Investigation

**Objective**: Hunt for signs of advanced persistent threats.

```powerquery
// Step 1: Reconnaissance - port scanning
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01')
| group hits=count() by src_ip, dst_port
| group unique_ports=count() by src_ip
| filter unique_ports >= 50
| columns src_ip, unique_ports

// Step 2: Initial access - successful auth after recon
serverHost in ('dc01.corp.local', 'linux-server01', 'f5-apm01')
| filter src_endpoint_ip = '<recon_ip>'
| parse "Accepted|success|Success" as success_indicator
| columns timestamp, user_name, src_endpoint_ip

// Step 3: Persistence - new accounts or services
serverHost in ('linux-server01', 'dc01.corp.local')
| parse "useradd|New User|service|systemd" as persistence_indicator
| columns timestamp, user_name, activity_name, target

// Step 4: C2 communication - beaconing
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01')
| filter dst_port in (443, 8443, 8080)
| group count() as connections, collect(timestamp) as times by src_ip, dst_ip
| filter connections >= 10
| columns src_ip, dst_ip, connections
```

### Scenario 5: Ransomware Precursor Investigation

**Objective**: Hunt for early signs of ransomware activity.

```powerquery
// Step 1: Mass file access (encryption preparation)
serverHost in ('dc01.corp.local', 'linux-server01')
| parse "file|File|read|write|modify" as file_indicator
| group count() as file_ops by user_name, process_name
| filter file_ops >= 100
| columns user_name, process_name, file_ops

// Step 2: Shadow copy deletion attempts
serverHost='dc01.corp.local'
| filter cmd_line matches "(vssadmin|wmic.*shadowcopy|bcdedit)"
| columns timestamp, user_name, cmd_line

// Step 3: Lateral movement via SMB
serverHost in ('fortigate-fw01', 'checkpoint-gw01', 'paloalto-fw01')
| filter dst_port = 445
| filter src_ip matches "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"
| group count() as smb_connections by src_ip
| filter smb_connections >= 10
| columns src_ip, smb_connections

// Step 4: Backup system access
serverHost in ('oracle-db01', 'hana-db01')
| parse "BACKUP|backup|restore|RESTORE" as backup_indicator
| columns timestamp, user_name, statement, src_endpoint_ip
```

---

## Detection Summary Matrix

| Detection | Sources | Severity | MITRE ATT&CK |
|-----------|---------|----------|--------------|
| Brute Force Attack | Windows, Linux, Entra ID, F5 APM | High | T1110 |
| Successful Login After Failures | Windows, Linux, Entra ID | High | T1110.001 |
| Privileged Account Usage | All auth sources | Medium | T1078 |
| Off-Hours Authentication | All auth sources | Medium | T1078 |
| Firewall Deny Spike | All firewalls | Medium | T1046 |
| Port Scan Detection | All firewalls | Medium | T1046 |
| Suspicious Outbound Connections | All firewalls | High | T1571 |
| IPS/IDS Alert Correlation | All firewalls | High | Various |
| Lateral Movement | All firewalls | High | T1021 |
| Suspicious Process Execution | Windows, Linux | Critical | T1059 |
| Privilege Escalation via Sudo | Linux | High | T1548.003 |
| Unauthorized Sudoers Access | Linux | High | T1548.003 |
| New User Account Creation | Windows, Linux | Medium | T1136 |
| Service Installation | Windows, Linux | Medium | T1543 |
| Database Privilege Escalation | Oracle, HANA | High | T1078.004 |
| Sensitive Table Access | Oracle, HANA | High | T1005 |
| Database Login from Unusual Source | Oracle, HANA | Medium | T1078 |
| Mass Data Export | Oracle, HANA | High | T1048 |
| DNS Zone Transfer Attempt | DNS servers | High | T1590.002 |
| DNS Tunneling | DNS servers | High | T1071.004 |
| Suspicious DNS Queries | DNS servers | Medium | T1071.004 |
| DNS Query Spike | DNS servers | Medium | T1071.004 |
| Risky Sign-In | Entra ID | High | T1078.004 |
| Impossible Travel | Entra ID | High | T1078.004 |
| MFA Bypass Attempts | Entra ID, F5 APM | Critical | T1556.006 |
| Privileged Role Assignment | Entra ID | High | T1098 |

---

## Implementation Notes

1. **Tune thresholds** based on your environment's baseline
2. **Whitelist known good** IPs, users, and processes
3. **Correlate across sources** for higher confidence detections
4. **Use time-based analysis** to detect anomalies
5. **Integrate with threat intelligence** for IOC matching
