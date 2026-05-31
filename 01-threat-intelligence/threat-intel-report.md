# Threat Intelligence Report: APT29 (Cozy Bear)

**Classification:** TLP:WHITE — Unrestricted Distribution  
**Prepared by:** Tangia Stegall  
**Date:** June 2026  
**Report Type:** Threat Actor Profile  

---

## Executive Summary

APT29, also known as Cozy Bear, Midnight Blizzard, and NOBELIUM, is a Russian state-sponsored threat actor attributed to the SVR (Foreign Intelligence Service). This group is one of the most sophisticated and persistent adversaries tracked by the global cybersecurity community. Their primary mission is espionage — targeting government agencies, think tanks, defense contractors, and critical infrastructure organizations in NATO-aligned countries.

This report profiles APT29's known TTPs, recent campaigns, indicators of compromise, and recommended defensive measures for organizations in targeted sectors.

---

## 1. Threat Actor Profile

| Attribute | Details |
|-----------|---------|
| **Common Names** | APT29, Cozy Bear, Midnight Blizzard, NOBELIUM, The Dukes |
| **Attributed Nation** | Russia (SVR — Foreign Intelligence Service) |
| **Active Since** | ~2008 |
| **Motivation** | Espionage, credential theft, long-term persistence |
| **Primary Targets** | Government, defense, NGOs, technology, healthcare |
| **Sophistication** | Very High — custom tooling, zero-day usage, long dwell times |

---

## 2. MITRE ATT&CK Mapping

The following table maps APT29's documented behaviors to the MITRE ATT&CK framework (Enterprise).

| Tactic | Technique | Technique ID | Notes |
|--------|-----------|-------------|-------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Tailored lure documents targeting specific individuals |
| Initial Access | Supply Chain Compromise | T1195.002 | SolarWinds SUNBURST campaign (2020) |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Obfuscated PowerShell for in-memory execution |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 | Establishing persistence across reboots |
| Persistence | Create Account: Domain Account | T1136.002 | Creating backdoor accounts post-compromise |
| Defense Evasion | Obfuscated Files or Information | T1027 | Encoding payloads to evade signature detection |
| Defense Evasion | Masquerading | T1036 | Naming malicious files after legitimate processes |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Using Mimikatz-style tooling |
| Discovery | Account Discovery | T1087 | Enumerating AD accounts for lateral movement planning |
| Lateral Movement | Pass the Hash | T1550.002 | Using harvested hashes to move without plaintext creds |
| Collection | Email Collection | T1114 | Accessing mailboxes for intelligence gathering |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | C2 over HTTPS to blend with normal traffic |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Data staged and exfiltrated through established C2 |

---

## 3. Notable Campaigns

### 3.1 SolarWinds Supply Chain Attack (2020)
APT29 compromised the SolarWinds Orion build process, inserting a backdoor (SUNBURST) into legitimate software updates. Approximately 18,000 organizations installed the trojanized update; ~100 were selected for active exploitation. The campaign had an estimated 6-month dwell time before discovery.

**Key TTPs:** Supply chain compromise, DLL side-loading, C2 over legitimate cloud services (Cobalt Strike), living-off-the-land techniques.

### 3.2 Microsoft Corporate Email Compromise (2024)
APT29 accessed the email accounts of Microsoft senior leadership and cybersecurity staff using password spray attacks against a legacy non-MFA-enabled test account, then pivoting to production systems. The intrusion targeted intelligence about what Microsoft knew regarding APT29 itself.

**Key TTPs:** Password spraying, OAuth token abuse, lateral movement via cloud services.

---

## 4. Indicators of Compromise (IOCs)

> **Note:** IOCs are time-sensitive. Validate against current threat feeds before defensive use. The following are examples from documented campaigns.

### Network IOCs
```
# C2 domains associated with SUNBURST campaign
avsvmcloud[.]com
databasegalore[.]com
deftsecurity[.]com
freescanonline[.]com
thedoccloud[.]com
websitetheme[.]com
```

### File Hashes (SUNBURST DLL)
```
SHA256: d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600
SHA256: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
```

### Behavioral IOCs
- PowerShell spawning from unexpected parent processes (Word, Excel, Outlook)
- LSASS memory access from non-system processes
- Outbound HTTPS to newly-registered domains or domains with mismatched certificates
- Scheduled tasks created with names mimicking Windows system tasks

---

## 5. Targeted Sectors & Why They Matter

| Sector | APT29 Interest | Example Targets |
|--------|---------------|-----------------|
| Government | Policy intelligence, diplomatic communications | US State Dept, EU agencies |
| Defense / DIB | Military technology, procurement intelligence | Defense contractors |
| Think Tanks / NGOs | Policy influence, early intelligence | Atlantic Council, RAND |
| Technology | Source code, product roadmaps, customer data | Microsoft, SolarWinds |
| Healthcare | COVID-19 vaccine research (2020) | AstraZeneca, research institutions |

---

## 6. Analyst Recommendations

### Immediate Priority (High Risk Sectors)
1. **Enforce MFA universally** — password spray attacks are a primary initial access vector for APT29. MFA eliminates the effectiveness of this technique.
2. **Audit legacy authentication protocols** — disable NTLM and basic auth where possible; APT29 exploits these for credential attacks.
3. **Monitor for LOLBin abuse** — alert on PowerShell, WMI, certutil, mshta executing in unusual contexts.

### Detection Engineering
4. **Deploy LSASS protection** — enable Windows Credential Guard; alert on non-system processes accessing LSASS memory.
5. **Baseline outbound traffic** — detect beaconing patterns (regular interval connections to low-reputation domains).
6. **Email anomaly detection** — alert on bulk email access, forwarding rule creation, or access from unusual IPs/geographies.

### Strategic Controls
7. **Software supply chain review** — implement vendor security assessments; monitor for unexpected DLL loading in trusted software.
8. **Tabletop exercises** — run a scenario simulating APT29's SolarWinds-style supply chain attack to test IR readiness.

---

## 7. Intelligence Sources

| Source | URL |
|--------|-----|
| MITRE ATT&CK — APT29 | https://attack.mitre.org/groups/G0016/ |
| FireEye / Mandiant SUNBURST Report | https://www.mandiant.com/resources/sunburst-additional-technical-details |
| Microsoft Threat Intelligence | https://www.microsoft.com/en-us/security/blog/ |
| CISA Advisory AA21-116A | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a |

---

## Analyst Notes

This report was produced as part of a self-directed cybersecurity portfolio project. All IOCs and TTPs were sourced from publicly available threat intelligence reports. No restricted or proprietary intelligence was used.

**Confidence Level:** Moderate-High (based on multiple corroborating public sources)  
**Next Review:** Recommend refreshing IOCs and campaign information every 90 days given APT29's operational tempo.
