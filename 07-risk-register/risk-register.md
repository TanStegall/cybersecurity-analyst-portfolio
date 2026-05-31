# Risk Register — SMB Security Risk Assessment

**Organization:** Fictional SMB (Retail/E-commerce, ~150 employees)
**Prepared by:** Tangia Stegall
**Date:** June 2026
**Framework:** NIST Risk Management Framework (RMF)
**Classification:** Internal Use

---

## Scoring Methodology

```
Risk Score = Likelihood (1–5) × Impact (1–5)

Score Ranges:
  20–25  →  Critical  (immediate action required)
  15–19  →  High      (address within 30 days)
  8–14   →  Medium    (address within 90 days)
  1–7    →  Low       (monitor or accept)
```

| Likelihood | Definition |
|-----------|-----------|
| 5 | Almost certain — expected to occur |
| 4 | Likely — will probably occur |
| 3 | Possible — might occur |
| 2 | Unlikely — not expected but possible |
| 1 | Rare — only in exceptional circumstances |

| Impact | Definition |
|--------|-----------|
| 5 | Catastrophic — business-threatening, regulatory action, major data breach |
| 4 | Major — significant financial loss, operational disruption >24hrs |
| 3 | Moderate — noticeable disruption, limited data exposure |
| 2 | Minor — minimal disruption, quickly recoverable |
| 1 | Negligible — no meaningful business impact |

---

## Risk Register

| ID | Risk Description | Category | Likelihood | Impact | Inherent Score | Inherent Rating | Existing Controls | Residual Score | Residual Rating | Treatment |
|----|----------------|----------|-----------|--------|---------------|----------------|------------------|---------------|----------------|-----------|
| R-01 | Phishing email leads to credential compromise | People | 5 | 4 | 20 | Critical | Security awareness training (annual) | 12 | Medium | Mitigate — increase training frequency, deploy email filtering |
| R-02 | Ransomware via unpatched system | Technology | 4 | 5 | 20 | Critical | Antivirus, ad-hoc patching | 15 | High | Mitigate — implement formal patch management program |
| R-03 | Insider threat — intentional data exfiltration | People | 2 | 5 | 10 | Medium | Basic access controls | 8 | Medium | Mitigate — implement DLP, least privilege, user activity monitoring |
| R-04 | Third-party vendor breach exposing customer data | Process | 3 | 5 | 15 | High | Vendor contracts with security clauses | 10 | Medium | Mitigate — implement vendor security assessments annually |
| R-05 | Cloud storage misconfiguration exposing PII | Technology | 3 | 5 | 15 | High | Manual config reviews (ad hoc) | 9 | Medium | Mitigate — deploy CSPM tool, implement config baselines |
| R-06 | Weak/reused passwords enabling account takeover | People | 4 | 4 | 16 | High | Password policy (not enforced technically) | 8 | Medium | Mitigate — deploy password manager, enforce MFA |
| R-07 | Lack of MFA on critical systems | Technology | 4 | 4 | 16 | High | None | 4 | Low | Mitigate — enable MFA on all critical systems immediately |
| R-08 | Unencrypted customer data at rest | Technology | 2 | 5 | 10 | Medium | Partial encryption on database | 6 | Low | Mitigate — enforce encryption at rest across all data stores |
| R-09 | Social engineering targeting help desk | People | 3 | 3 | 9 | Medium | No formal verification procedure | 6 | Low | Mitigate — implement caller verification policy |
| R-10 | Shadow IT — unapproved apps handling company data | Process | 4 | 3 | 12 | Medium | No controls | 10 | Medium | Mitigate — implement acceptable use policy, CASB tooling |
| R-11 | Physical security — tailgating into server room | People | 2 | 4 | 8 | Medium | Key card access | 4 | Low | Accept — key card access sufficient for current risk appetite |
| R-12 | DDoS attack disrupting e-commerce operations | Technology | 2 | 4 | 8 | Medium | Basic ISP-level protection | 6 | Low | Transfer — evaluate DDoS protection service (e.g. Cloudflare) |
| R-13 | Failure to meet PCI-DSS compliance requirements | Process | 2 | 5 | 10 | Medium | Annual QSA assessment | 6 | Low | Mitigate — quarterly internal compliance reviews |
| R-14 | Lost or stolen employee laptop with company data | Technology | 3 | 3 | 9 | Medium | No endpoint encryption enforced | 5 | Low | Mitigate — enforce BitLocker/FileVault on all endpoints |
| R-15 | No tested incident response plan | Process | 5 | 4 | 20 | Critical | Informal IR procedures exist | 12 | Medium | Mitigate — formalize IR plan, conduct tabletop exercise |

---

## Top 5 Priority Risks (Executive Summary)

| Priority | Risk | Inherent Score | Recommended Action |
|----------|------|---------------|-------------------|
| 1 | R-02: Ransomware via unpatched systems | 20 — Critical | Implement formal patch management; define SLAs by severity |
| 2 | R-01: Phishing → credential compromise | 20 — Critical | Monthly training + simulated phishing; deploy advanced email filtering |
| 3 | R-15: No tested incident response plan | 20 — Critical | Formalize IR playbook; run tabletop exercise within 60 days |
| 4 | R-07: No MFA on critical systems | 16 — High | Enable MFA immediately — highest ROI security control available |
| 5 | R-06: Weak/reused passwords | 16 — High | Deploy password manager + enforce MFA org-wide |

---

## Control Gap Summary

| Control Domain | Current Maturity | Gap |
|---------------|-----------------|-----|
| Identity & Access Management | Low — passwords only on most systems | MFA, PAM, least privilege not implemented |
| Patch Management | Low — ad hoc, no defined SLAs | No formal program or tracking |
| Security Awareness | Low — annual training only | Needs frequency increase + simulated phishing |
| Incident Response | Low — informal only | No documented, tested IR plan |
| Vendor Risk Management | Low — contracts only | No security assessments of third parties |
| Data Protection | Medium — partial encryption | Gaps in at-rest encryption and DLP |

---

## Analyst Notes

This risk register was produced as part of a self-directed cybersecurity portfolio project. The organization and all associated data are fictional. The methodology follows NIST RMF principles with a simplified likelihood × impact scoring model appropriate for an SMB context.

**Next steps for a real engagement:** Validate risk ratings with business stakeholders, confirm existing control effectiveness through testing, and schedule quarterly risk register reviews.
