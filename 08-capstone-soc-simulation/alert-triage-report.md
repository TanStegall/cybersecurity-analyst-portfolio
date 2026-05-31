# Capstone: SOC Analyst Shift Simulation

**Analyst:** Tangia Stegall  
**Simulation Date:** June 2026  
**Shift:** 08:00 – 16:00 (8-hour Tier 1 shift)  
**Environment:** Wazuh SIEM, home lab + TryHackMe SOC Level 1 alerts  
**Format:** Chronological alert triage log with analyst notes  

---

## Shift Overview

This capstone simulates a full Tier 1 SOC analyst shift, working through a queue of escalating alerts from a SIEM. Each alert is triaged using the same methodology a real analyst would follow: investigate, classify, document, decide, and escalate or close.

**Alerts handled:** 11  
**True Positives:** 4  
**False Positives:** 5  
**Escalated to Tier 2:** 2  
**Tickets opened:** 4  

---

## Alert Triage Log

---

### ALERT-001 | 08:14 | Severity: LOW | Status: ✅ CLOSED — False Positive

**Rule:** 5402 — Successful sudo to ROOT executed  
**Host:** ubuntu-agent (10.0.0.20)  
**User:** www-data  
**Command:** `/usr/bin/certbot renew`

**Investigation:**
- Reviewed scheduled task: `/etc/cron.d/certbot` — runs every 12 hours, owned by root
- Command matches known-good certbot renewal cron
- Timing (08:14) consistent with cron schedule
- No other suspicious activity on this host in the past 24 hours

**Decision:** False positive. Certbot renewal cron running as expected.  
**Action:** Closed. Local suppression rule already in place (see SIEM lab documentation).  
**Time spent:** 4 minutes

---

### ALERT-002 | 08:31 | Severity: MEDIUM | Status: ✅ CLOSED — False Positive

**Rule:** 1002 — Unknown problem somewhere in the system  
**Host:** wazuh-manager (10.0.0.10)  
**Log source:** /var/log/syslog  
**Message:** "OpenSearch performance warning: heap usage at 78%"

**Investigation:**
- OpenSearch heap usage: checked Wazuh dashboard — indexer performance metrics
- 78% heap is elevated but not critical (threshold for concern is typically >85%)
- Pattern check: heap usage spikes briefly every morning when daily index creation runs (~08:30)
- No disk space issues, no indexing failures, no query timeouts

**Decision:** False positive. Expected morning behavior — index creation temporarily spikes heap usage.  
**Action:** Closed. Added to monitoring watchlist to alert if sustained >85% for >10 minutes.  
**Time spent:** 6 minutes

---

### ALERT-003 | 09:07 | Severity: HIGH | Status: 🔴 ESCALATED TO TIER 2

**Rule:** 5763 — sshd: brute force attack  
**Host:** ubuntu-agent (10.0.0.20)  
**Source IP:** 192.168.1.155 (internal network)  
**Failed attempts:** 47 in 3 minutes  
**Target accounts:** root, admin, ubuntu, test (rotating)

**Investigation:**
- SSH brute force from an internal IP is significantly more concerning than external (implies either a compromised internal host or a rouge device)
- 192.168.1.155 is NOT in our asset inventory — unrecognized device
- ARP table check: MAC address `b8:27:eb:xx:xx:xx` — Raspberry Pi Foundation OUI
- No authorized Raspberry Pi devices registered in asset inventory
- Port scan of 192.168.1.155 revealed: ports 22, 5900 (VNC) open

**Decision:** TRUE POSITIVE. Unrecognized device conducting internal brute force.  

**Escalation notes for Tier 2:**
> Unregistered Raspberry Pi (192.168.1.155, MAC b8:27:eb:xx:xx:xx) conducting SSH brute force against production endpoint. Device not in asset inventory. 47 failed attempts against root, admin, ubuntu, test accounts in 3 minutes. VNC (5900) also exposed on device. Recommend: physical identification of device, network isolation, review of all SSH logs on .20 for any successful auth from this source. Priority: High.

**Action:** Escalated. Recommended isolation of 192.168.1.155 at network switch level pending investigation.  
**Time spent:** 18 minutes

---

### ALERT-004 | 09:45 | Severity: MEDIUM | Status: ✅ CLOSED — False Positive

**Rule:** 31101 — Web server 400 error code  
**Host:** ubuntu-agent (10.0.0.20) — Apache  
**Details:** 127 HTTP 400 errors in 5 minutes from 203.0.113.42

**Investigation:**
- 400 errors = bad requests (client-side malformed requests)
- Pattern: all requests to `/wp-admin/`, `/xmlrpc.php`, `/.env`, `/config.php`
- Source IP: 203.0.113.42 — documentation IP range (TEST — but in simulation: checked VirusTotal: 45 vendors flag as scanner)
- This is a WordPress scanner — automated tool looking for common CMS endpoints
- This server does not run WordPress; all requests are returning 400/404
- No successful access

**Decision:** True Positive alert, but Low business impact — scanner hitting a non-vulnerable server.  
**Action:** Blocked source IP at Apache level via `.htaccess`. Closed ticket — documented for pattern tracking.  
**Time spent:** 9 minutes

---

### ALERT-005 | 10:22 | Severity: HIGH | Status: 🔴 ESCALATED TO TIER 2

**Rule:** 550 — Integrity checksum changed  
**Host:** wazuh-manager (10.0.0.10)  
**File modified:** `/etc/passwd`  
**Modified by:** Unknown (agent reported checksum change, no process attribution)

**Investigation:**
- `/etc/passwd` modification is significant — this file controls user accounts
- Compared current `/etc/passwd` to backup:
  ```diff
  + backdoor:x:0:0::/root:/bin/bash
  ```
- A new account named `backdoor` with UID 0 (root-equivalent) was added
- No admin activity logged around this time — no legitimate reason for this change
- Checked `/var/log/auth.log`: SSH login from 192.168.1.155 at 10:19 — 3 minutes before the passwd change
- **This connects directly to ALERT-003** — the brute force succeeded

**Decision:** CRITICAL TRUE POSITIVE. Successful compromise confirmed. Root-level backdoor account created.  

**Escalation notes for Tier 2:**
> CRITICAL — Confirmed compromise. Root-equivalent backdoor account ("backdoor", UID 0) added to /etc/passwd on wazuh-manager (10.0.0.10) at approximately 10:19 UTC. SSH login from 192.168.1.155 at 10:19 preceded the passwd modification by ~3 minutes. This is the same source from ALERT-003. The attacker pivoted from the endpoint (.20) to the SIEM manager (.10). Both hosts should be treated as compromised. Recommend immediate isolation of both hosts, credential reset for all accounts, and full IR invocation.

**Action:** ESCALATED — CRITICAL. Recommended immediate IR invocation per ransomware/compromise playbook.  
**Time spent:** 22 minutes (including correlation with ALERT-003)

---

### ALERT-006 | 11:15 | Severity: LOW | Status: ✅ CLOSED — False Positive

**Rule:** 2932 — Shellshock attack attempt  
**Host:** ubuntu-agent (10.0.0.20)  
**Details:** HTTP request with `() { :; };` in User-Agent header

**Investigation:**
- Shellshock (CVE-2014-6271) is a 2014 bash vulnerability
- Ubuntu 22.04 ships with bash 5.1 — not vulnerable to Shellshock
- Checked bash version: `bash --version` → GNU bash, version 5.1.16
- This is an automated scanner probing for a decade-old vulnerability on a patched system
- No impact, no successful exploitation

**Decision:** False positive (for this environment). Alert is technically correct but host is not vulnerable.  
**Action:** Closed. No action required — system is patched.  
**Time spent:** 5 minutes

---

### ALERTS 007-011 | Afternoon Shift (Summary)

| Alert | Time | Rule | Verdict | Action |
|-------|------|------|---------|--------|
| 007 | 12:04 | High failed logins — local | FP — admin locked themselves out; confirmed via phone | Closed |
| 008 | 12:47 | Possible web attack — SQL injection | TP — automated scan, no payload success, IP blocked | Closed |
| 009 | 13:30 | New user account created | FP — IT onboarding new employee (confirmed via ticket) | Closed |
| 010 | 14:11 | Port scan detected | TP — scan from 203.0.113.42 (same scanner as ALERT-004) | Blocked, closed |
| 011 | 15:02 | High outbound traffic volume | FP — backup job running (confirmed via cron schedule) | Closed |

---

## Shift Summary & Metrics

| Metric | Value |
|--------|-------|
| Total alerts worked | 11 |
| True positives | 4 (36%) |
| False positives | 5 (45%) |
| Inconclusive (closed after investigation) | 2 (18%) |
| Escalated to Tier 2 | 2 |
| Tickets opened | 4 |
| Average triage time | 11 minutes |
| Most significant finding | Confirmed host compromise + root backdoor (ALERT-005) |

---

## Analyst Reflection

### What I Did Well
- **Correlation:** Connecting ALERT-005's SSH login to the source from ALERT-003 was the key analytical move of the shift. Single alerts rarely tell the full story — pattern recognition across the queue is where Tier 1 adds real value.
- **Escalation quality:** Escalation notes for Tier 2 were detailed and actionable, including specific evidence, timestamps, and recommended next steps.
- **False positive handling:** Correctly closed false positives quickly by validating against known-good baselines (certbot cron, backup jobs, patch levels) rather than spending unnecessary time on them.

### What I Would Do Differently
- **Asset inventory gap:** The unrecognized Raspberry Pi (ALERT-003) highlights that asset management is a security control. In a real environment, I would flag the asset inventory gap as a separate finding to the security team.
- **Speed vs thoroughness:** On ALERT-005, I should have immediately pulled auth logs the moment I saw a `/etc/passwd` modification — I checked the diff first. In a real incident with active threat, sequence matters.

### Key Lesson
SOC work is fundamentally about separating signal from noise — quickly. The 45% false positive rate in this simulation is actually optimistic compared to real environments. The ability to triage efficiently without missing real threats is the core skill this exercise was designed to build.

---

## Skills Demonstrated in This Capstone

| Skill | Where Demonstrated |
|-------|-------------------|
| Alert triage methodology | All 11 alerts |
| SIEM query writing | ALERT-003, ALERT-005 |
| Log correlation | ALERT-003 → ALERT-005 connection |
| Escalation writing | ALERT-003, ALERT-005 |
| False positive recognition | ALERT-001, 002, 004, 006 |
| Incident response invocation | ALERT-005 |
| Asset inventory analysis | ALERT-003 |
| Network forensics (basic) | ALERT-003 (MAC OUI lookup) |
