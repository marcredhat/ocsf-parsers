# Threat Hunt Report — Unusual / Suspicious Activity

**Console:** `mgmt-11633.sentinelone.net` (LRQ API)
**Window:**  Last 168h (7 days)  ·  Cross-source section: last 24h
**Method:**  `lrq-string-search/examples/unusual_activity_v2.py`
**Script:**  `python3 lrq-string-search/examples/unusual_activity_v2.py`

---

## Executive summary

| Surface | Status | Key finding |
|---|---|---|
| **S1 Agent Telemetry** | Quiet (Linux/k8s only) | No PowerShell/cmd/recon/sensitive-dir activity. Environment is Linux/Kubernetes (coredns, traefik, netavark). |
| **Windows Event Logs** | **HOT** | 13× failed logons from `203.0.113.45`, 13× new account `newuser`, 3× added to Administrators, 5× **Audit Log Cleared (1102)** — strong attack chain. |
| **SAP HANA** | **HOT** | 7× **SQL Injection**, 7× **Mass Data Extraction**, 7× **Privilege Escalation** — all from `attacker@192.168.1.200`. 59 auth failures. |
| **Linux** | **HOT** | 49 SSH brute-force fails from `192.168.1.100`, 33 from `203.0.113.45`. 7× reverse-shell, 7× cred-dumping. |
| **Identity (Entra ID)** | Active | 31 sign-in failures. |
| **Network (FortiGate / Palo Alto / F5)** | Active | 84 FortiGate denies from `10.0.1.50`. Palo Alto: 9 threat / 9 spyware/C2 / 9 vuln-exploit. F5 ASM/WAF: 6 blocks. |
| **DNS (BIND)** | Active | 16 BIND security warnings. |
| **Cross-source** | **HOT** | Top attacker IP `192.168.1.200` (146 hits) — HANA exfil; `203.0.113.45` (91 hits) — Windows + Linux brute-force. |

---

## Section 1 — S1 Agent Telemetry

| Hunt | Result |
|---|---|
| 1.1 Event type distribution | 11 types · File Creation 83.3K · File Rename 63.8K · Process Creation 57.9K · IP Connect 26.4K · DNS Unresolved 24.5K |
| 1.2 Rare processes (<10) | 20 incl. `coredns`, `controller`, `webhook`, `traefik`, `netavark`, `sshd` |
| 1.3 Recon command-line patterns | 0 |
| 1.4 Unusual ports | 8080 (7.4K), 10250 (2.6K — kubelet), 8181, 6080, 9403, 6443 (k8s API), 22 |
| 1.5 Script-engine execution | 0 |
| 1.6 Sensitive-dir file creations | 0 |

**Verdict:** No suspicious activity from S1 agents. Environment is benign Linux/Kubernetes.

---

## Section 2 — Windows Event Logs (deep focus)

| # | Hunt | Result |
|---|---|---|
| 2.1 | All Windows finding types | 4720 (×13), 4625 (×13), 1102 (×5), 4732 (×3) |
| 2.2 | Failed logon top targets | `administrator` from `203.0.113.45` — **13 fails** |
| 2.3 | Brute-force burst (≥5/IP) | `203.0.113.45` — **13 fails** |
| 2.4 | Failed + Successful from same IP | none |
| 2.5 | New account creations | `newuser` — **13×** |
| 2.6 | Privileged group additions | `newuser` → `Administrators` — **3×** |
| 2.7 | Audit log cleared (1102) | **5 clears** on `windows-ocsf` — anti-forensics |
| 2.8 | Special-privileges (4672) | not parsed (parser doesn't classify 4672 as Detection Finding) |
| 2.9 | Process creations (4688) | not parsed (parser doesn't enrich 4688 with command_line) |

**Verdict — full attack kill-chain visible:**

1. Brute-force on `administrator` from `203.0.113.45` (13 fails)
2. Adversary creates `newuser` (4720)
3. Adds `newuser` to `Administrators` group (4732)
4. Clears Security audit log to cover tracks (1102)

---

## Section 3 — SAP HANA (deep focus)

| # | Hunt | Result |
|---|---|---|
| 3.1 | All HANA finding types | Auth Failure (×59), SQL Injection (×7), Mass Data Extraction (×7), Privilege Escalation (×7), Suspicious Backup Location (×7) |
| 3.2 | SQL injection attempts | `attacker@192.168.1.200` — **7 hits** |
| 3.3 | Mass data extraction | `attacker@192.168.1.200` — **7 hits** |
| 3.4 | Failed authentication (≥3) | none parsed (auth events are class_uid=2004 finding-typed, not 3002) |
| 3.5 | Privileged DDL (DROP/ALTER/CREATE/GRANT) | `SYSTEM` — 10 ops, `attacker` — 7 ops |
| 3.6 | Admin/system account volume | `DBADMIN` (40), `SYSTEM` (10) |

**Verdict — coordinated SAP HANA data-exfil attack:**

- Single source `192.168.1.200` (`attacker`) executed all 4 attack vectors:
  SQLi → priv-esc → mass extract → DDL on the database
- 59 HANA auth failures suggest brute force preceded the successful intrusion
- `DBADMIN` 40 actions warrants review — possibly hijacked privileged account

---

## Section 4 — Other OCSF Sources

| # | Hunt | Result |
|---|---|---|
| 4.1 | Linux SSH brute-force (≥3) | `192.168.1.100` — **49 fails**, `203.0.113.45` — **33 fails** |
| 4.2 | Brute-force then SUCCESS | none observed |
| 4.3 | Linux reverse shell / cred dumping | 7× Reverse Shell, 7× Credential Dumping |
| 4.4 | Entra ID risky sign-ins | 31 auth failures |
| 4.5 | DNS suspicious (BIND/MS-DNS) | BIND security warning ×16 |
| 4.6 | FortiGate deny spike (≥10/IP) | `10.0.1.50` — **84 denies** |
| 4.7 | Palo Alto IPS / threat / spyware | Threat ×9, Spyware/C2 ×9, Vulnerability Exploit ×9 |
| 4.8 | Check Point firewall events | none |
| 4.9 | F5 BIG-IP / APM WAF | LTM: ASM ×6, SSL handshake fail ×6, WAF block ×6 · APM: deny ×6, auth fail ×6 |
| 4.10 | Oracle / WatchGuard / QRadar / SIM | SIM Generic Error ×18, QRadar Malware ×10, QRadar Suspicious Activity ×10, SIM Brute Force ×9 |

---

## Section 5 — Cross-Source Correlation (24h)

| # | Hunt | Result |
|---|---|---|
| 5.1 | IPs across multiple sources | `192.168.1.200` HANA (146), `203.0.113.45` Windows + Linux brute-force, `10.0.1.50` FortiGate denied |
| 5.2 | Top attacker IPs (24h) | `192.168.1.200` (146), `203.0.113.45` (91), `10.0.1.50` (84), `192.168.1.100` (49), `185.220.101.1` Tor (21) |
| 5.3 | Auth failure burst (≥10/user) | not parsed in primary auth class — see 2.2 / 4.1 instead |
| 5.4 | Detection Finding volume per source | full breakdown by `serverHost` |
| 5.5 | Critical (severity=5) findings | concentrated on `hana-ocsf` (SQLi/exfil), `windows-ocsf` (1102/4732), `linux-ocsf` (reverse shell/cred dump) |

---

## Recommended response actions

1. **Block IPs immediately:**
   - `203.0.113.45` (Windows + Linux brute-force)
   - `192.168.1.200` (HANA exfiltration)
   - `192.168.1.100` (Linux brute-force)
   - `185.220.101.1` (Tor exit node)
2. **Investigate Windows DC `windows-ocsf`:**
   - Disable / delete `newuser` account
   - Audit `Administrators` group membership
   - Investigate why audit log was cleared 5 times
3. **Investigate SAP HANA `hana-ocsf`:**
   - Force password reset on `DBADMIN` and `attacker` accounts
   - Review HANA audit trail for DDL ops in last 7 days
   - Look for backups uploaded to suspicious locations (finding 3.1)
4. **Investigate Linux hosts targeted by brute-force**, check for successful logons since the brute-force window
5. **Tune rules** to detect:
   - 4625→4720→4732→1102 sequence within short window
   - HANA SQLi + Mass Extraction from same source IP

---

## How to re-run

```bash
export S1_JWT=$(jq -r .log_read_key config.json)
export S1_CONSOLE=$(python3 -c "
import json, base64
jwt = json.load(open('config.json'))['log_read_key']
p = jwt.split('.')[1]; p += '=' * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p))['sub'].split('@', 1)[1])")
export S1_HOURS=168                # default 7d; set to e.g. 24 for last day

python3 lrq-string-search/examples/unusual_activity_v2.py
```
