# Incident Response Playbook: Ransomware

**Version:** 1.0  
**Framework:** NIST SP 800-61r2  
**Author:** Tangia Stegall  
**Review Date:** June 2026  
**Classification:** Internal Use  

---

## Purpose

This playbook provides structured, step-by-step guidance for responding to a confirmed or suspected ransomware incident. It follows the NIST Incident Response lifecycle and is designed for use by Tier 1 and Tier 2 SOC analysts.

**Incident Types Covered:**
- File-encrypting ransomware (e.g., LockBit, BlackCat/ALPHV, Ryuk)
- Double extortion (encryption + data theft)
- Ransomware-as-a-Service (RaaS) campaigns

---

## Severity Classification

| Severity | Criteria | Initial SLA |
|----------|----------|------------|
| **P1 — Critical** | Active spread detected; domain controller or backup systems affected | 15 min escalation |
| **P2 — High** | Single system encrypted; no spread detected; no backup impact | 1 hour escalation |
| **P3 — Medium** | Ransomware artifact found but no encryption confirmed | 4 hour escalation |

---

## Phase 1: Preparation (Pre-Incident)

> This phase is completed before any incident occurs. Use it to validate readiness.

### Checklist
- [ ] Incident response contacts documented and accessible offline
- [ ] Out-of-band communication channel established (e.g., personal phones, secondary email)
- [ ] Asset inventory is current (critical systems identified)
- [ ] Backups are confirmed working and stored offline/off-site
- [ ] Network segmentation is in place (can we isolate a VLAN quickly?)
- [ ] IR tools available on jump drive (not dependent on potentially-compromised network)
- [ ] Legal and communications teams aware of IR notification obligations

---

## Phase 2: Detection & Analysis

### 2.1 Initial Alert Sources

Ransomware is commonly first detected through:
- Endpoint alerts (EDR/AV) — encryption activity, mass file rename
- User reports — "my files won't open / have weird extensions"
- SIEM alerts — high-volume file system activity, shadow copy deletion
- Network alerts — lateral movement, SMB scanning

### 2.2 Immediate Triage Questions

Answer these within the first 15 minutes:

```
1. How many systems are affected? (scope)
2. Is encryption actively ongoing or complete?
3. Are backups accessible and confirmed clean?
4. Is the ransomware spreading across the network?
5. Has data exfiltration occurred or been indicated?
6. What is the entry point / patient zero?
```

### 2.3 Indicators of Compromise (Ransomware)

**Behavioral IOCs:**
- Mass file extension changes (`.lockbit`, `.encrypted`, `.ALPHV`, etc.)
- Ransom note files created in multiple directories (`READ_ME.txt`, `HOW_TO_DECRYPT.html`)
- Shadow copy deletion: `vssadmin delete shadows /all /quiet`
- Windows backup catalog deletion: `wbadmin delete catalog -quiet`
- Disabling Windows Defender: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Rapid SMB connections to multiple internal hosts

**SIEM Queries (Wazuh/Splunk):**
```
# Shadow copy deletion
process.name:vssadmin AND process.args:"delete shadows"

# Mass file rename/write (proxy for encryption)
file.extension:(lockbit OR encrypted OR ransom) AND event.action:rename

# Lateral movement via SMB
destination.port:445 AND source.bytes:>1000000
```

### 2.4 Severity Determination → Escalation Decision

```
                 ┌──────────────────────────┐
                 │  Alert/Report Received   │
                 └────────────┬─────────────┘
                              │
                 ┌────────────▼─────────────┐
                 │ Is encryption confirmed? │
                 └──────┬──────────┬────────┘
                        │ YES      │ NO
              ┌─────────▼──┐   ┌──▼───────────────┐
              │ Is spread  │   │ Investigate as   │
              │ detected?  │   │ P3 — artifact    │
              └──┬──────┬──┘   │ found, no impact │
            YES  │   NO │      └──────────────────┘
      ┌──────────▼┐ ┌───▼────────┐
      │ P1 CRIT  │ │ P2 HIGH    │
      │ Escalate │ │ Contain &  │
      │ NOW      │ │ Escalate   │
      └──────────┘ └────────────┘
```

---

## Phase 3: Containment

> **Critical Rule:** Do NOT shut down affected systems immediately — memory forensics may be lost. Isolate from the network first.

### 3.1 Short-Term Containment (First 30 Minutes)

**Step 1 — Network Isolation**
```
☐ Immediately isolate affected host(s) from the network:
    - Disable NIC in VM settings, OR
    - Put switch port into VLAN isolation, OR
    - Remove the physical network cable
    
☐ Isolate, do NOT power off (preserve forensic evidence in RAM)
☐ Document: time of isolation, who performed it, method used
```

**Step 2 — Assess Spread**
```
☐ Identify all hosts with active SMB connections to affected system
☐ Check EDR/SIEM for mass file modification events across other hosts
☐ Query AD: any new accounts created in last 24-48 hours?
☐ Check domain controllers for signs of compromise
```

**Step 3 — Protect Backups**
```
☐ IMMEDIATELY verify backup systems are isolated and unaffected
☐ Take backups offline if they are currently network-accessible
☐ Do NOT attempt restoration yet — confirm backup integrity first
```

### 3.2 Long-Term Containment

```
☐ Block ransomware C2 domains/IPs at perimeter firewall
☐ Reset credentials for any accounts active on compromised hosts
☐ Enable enhanced logging on all remaining hosts
☐ Disable any compromised service accounts
```

---

## Phase 4: Eradication

> Only begin eradication after containment is confirmed and evidence is preserved.

### 4.1 Evidence Preservation (Before Eradication)

```
☐ Capture memory dump of affected system (if still running):
    Windows: winpmem_mini_x64_rc2.exe > memory.dmp
    Linux:   sudo avml /path/to/output.lime

☐ Preserve disk image:
    dd if=/dev/sda of=/external/image.dd bs=4M status=progress

☐ Export all relevant logs:
    - Windows Event Logs (Security, System, Application)
    - SIEM alert exports for the incident timeline
    - EDR telemetry for the affected host
    
☐ Photograph ransom note (preserves metadata)
☐ Document all observed file extensions and affected paths
```

### 4.2 Identify and Remove Malware

```
☐ Identify ransomware variant using ID Ransomware (https://id-ransomware.malwarehunterteam.com/)
☐ Obtain IOCs for confirmed variant (MITRE ATT&CK, any threat intel source)
☐ Search environment for all IOCs — assume more hosts may be infected
☐ Remove ransomware binary from affected hosts
☐ Remove persistence mechanisms:
    - Scheduled tasks
    - Registry run keys
    - Startup folders
    - Newly created accounts
☐ Patch the initial access vector (if identified)
```

### 4.3 Root Cause Analysis

| Question | How to Answer |
|----------|--------------|
| Initial access vector? | Review phishing logs, VPN access logs, EDR process tree |
| First infected host? | Correlate timestamps across SIEM for earliest encryption activity |
| How did it spread? | SMB traffic logs, lateral movement SIEM alerts |
| What data was exfiltrated? | Outbound traffic analysis; DLP logs if available |
| What credentials were compromised? | Active sessions, AD audit logs, Mimikatz indicators |

---

## Phase 5: Recovery

### 5.1 Pre-Recovery Checklist
```
☐ Ransomware completely removed from all affected systems
☐ All persistence mechanisms eliminated
☐ Initial access vector patched or mitigated
☐ Compromised credentials reset
☐ Backup integrity confirmed (test restore on isolated system)
☐ Stakeholder sign-off obtained before restoring systems
```

### 5.2 Recovery Steps
```
☐ Restore from last known-clean backup (verify backup predates compromise)
☐ Restore systems in priority order (critical business systems first)
☐ Test restored systems before reconnecting to production network
☐ Monitor restored systems intensively for 72 hours post-recovery
☐ Validate data integrity after restoration
```

### 5.3 Should We Pay the Ransom?

**Analyst guidance:** This decision belongs to legal counsel, executive leadership, and potentially law enforcement — not the SOC. However, analysts should be prepared to advise:

- Paying does not guarantee decryption
- Payment may be illegal (OFAC sanctions if group is on the list)
- Payment funds further ransomware operations
- Decryptor tools may exist for some variants (check nomoreransom.org)

**Analyst action:** Identify the ransomware variant and immediately check [nomoreransom.org](https://www.nomoreransom.org) for free decryption tools.

---

## Phase 6: Post-Incident Activity

### 6.1 Lessons Learned Meeting

Schedule within 1–2 weeks post-recovery. Attendees: IR team, affected business units, IT leadership.

**Agenda template:**
1. Incident timeline review
2. What detection mechanisms worked?
3. What gaps allowed the initial compromise?
4. Where did containment slow down and why?
5. What controls would have prevented or limited this?
6. Action items with owners and due dates

### 6.2 Metrics to Capture

| Metric | Value |
|--------|-------|
| Time to detect (TTD) | |
| Time to contain (TTC) | |
| Time to recover (TTR) | |
| Systems affected | |
| Data exfiltrated | |
| Estimated business impact | |
| Root cause | |

### 6.3 Required Notifications

| Recipient | Trigger | Timeframe |
|-----------|---------|-----------|
| Executive leadership | Any P1 incident | Immediately |
| Legal counsel | Any data exfiltration | Immediately |
| Law enforcement (FBI IC3) | If paying ransom or significant impact | Per legal guidance |
| Regulatory body (if applicable) | PII exfiltration — varies by regulation | 72 hours (GDPR) / varies |
| Affected customers | If their data was involved | Per breach notification law |

---

## Appendix A: Key Contacts

| Role | Name | Contact |
|------|------|---------|
| IR Lead | | |
| CISO | | |
| Legal Counsel | | |
| Executive Sponsor | | |
| IT Operations Lead | | |
| Law Enforcement Liaison | | |

---

## Appendix B: Quick Reference Tools

| Tool | Purpose | URL |
|------|---------|-----|
| ID Ransomware | Identify variant from ransom note/file extension | https://id-ransomware.malwarehunterteam.com |
| No More Ransom | Free decryptors | https://www.nomoreransom.org |
| CISA Ransomware Guide | Official IR guidance | https://www.cisa.gov/stopransomware |
| OFAC Sanctions List | Confirm payment legality | https://sanctionssearch.ofac.treas.gov |

---

*This playbook is a living document. Review and update after every ransomware incident and at minimum annually.*
