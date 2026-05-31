# Phishing Email Analysis Report

**Analyst:** Tangia Stegall  
**Date:** June 2026  
**Ticket ID:** PHI-2024-0042 (simulated)  
**Source:** User-submitted suspicious email  
**Verdict:** ✅ CONFIRMED PHISHING  

---

## Executive Summary

A suspicious email purportedly from "Microsoft Security Team" was submitted by a user who noticed the sender address looked unusual. Full analysis confirmed this is a credential harvesting phishing attempt targeting Microsoft 365 account credentials. The email employs urgency tactics, a spoofed sender domain, and a redirect chain to a convincing fake Microsoft login page.

**Recommended Action:** Block sender domain at email gateway. Add phishing URL to web proxy blocklist. Notify security awareness team for training follow-up.

---

## 1. Email Metadata Analysis

### 1.1 Raw Email Headers (Key Sections)

```
From: "Microsoft Security Team" <security-alert@micros0ft-support[.]com>
Reply-To: noreply@micros0ft-support[.]com
To: john.smith@targetcompany[.]com
Date: Mon, 15 Jan 2024 09:23:41 -0500
Subject: [ACTION REQUIRED] Suspicious sign-in detected on your account
Message-ID: <20240115092341.12345@mail.micros0ft-support.com>
X-Mailer: PHPMailer 6.5.0
X-Originating-IP: 185.220.101.47
Received: from mail.micros0ft-support[.]com (185.220.101.47)
  by mx1.targetcompany.com with ESMTP id x1234567
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
```

### 1.2 Header Analysis Findings

| Header Field | Observed Value | Analyst Finding |
|-------------|----------------|----------------|
| **From domain** | micros0ft-support[.]com | **SPOOFED** — uses zero instead of 'o' in "Microsoft" (typosquatting) |
| **Reply-To** | Same spoofed domain | Reply-To matches From — replies go to attacker |
| **X-Originating-IP** | 185.220.101.47 | **Suspicious** — Tor exit node (see Section 3) |
| **X-Mailer** | PHPMailer 6.5.0 | Bulk mailing tool — not used by Microsoft |
| **Received chain** | Only 1 hop | Legitimate Microsoft email passes through multiple Microsoft servers |
| **DKIM** | None present | **FAIL** — Microsoft always DKIM-signs outbound email |
| **SPF** | FAIL | micros0ft-support[.]com has no SPF record for 185.220.101.47 |
| **DMARC** | FAIL | Domain has no DMARC record |

### 1.3 Authentication Results

```
Authentication-Results: mx1.targetcompany.com;
  dkim=none (no signature found);
  spf=fail (185.220.101.47 not authorized sender for micros0ft-support.com);
  dmarc=fail (policy=none)
```

**Verdict:** All three email authentication mechanisms (DKIM, SPF, DMARC) fail. Legitimate Microsoft email always passes all three.

---

## 2. Email Body Analysis

### 2.1 Social Engineering Techniques Observed

| Technique | Example from Email | Purpose |
|-----------|-------------------|---------|
| **Authority impersonation** | "Microsoft Security Team" branding, Microsoft logo | Establish trust |
| **Urgency creation** | "Your account will be suspended in 24 hours" | Bypass critical thinking |
| **Fear induction** | "Suspicious sign-in from Russia detected" | Trigger emotional response |
| **Action demand** | "Click here to verify your identity immediately" | Drive click-through |

### 2.2 Embedded URL Analysis

**Visible link text:** `https://microsoft.com/security/verify` ← (what the user sees)

**Actual href URL:** `https://secure-login.micros0ft-support[.]com/auth/verify?ref=a1b2c3d4`

**Redirect Chain:**
```
1. https://secure-login.micros0ft-support[.]com/auth/verify?ref=a1b2c3d4
         ↓ (302 redirect)
2. https://bit.ly/3xZ9qR2  ← URL shortener to obscure destination
         ↓ (301 redirect)
3. https://microsoft-account-verify.web[.]app/login  ← Firebase-hosted phishing page
         ↓ (Final landing page)
4. Fake Microsoft 365 login page (credential harvesting)
```

---

## 3. IOC Investigation

### 3.1 Sender Domain — micros0ft-support[.]com

**WHOIS Analysis:**
```
Domain: micros0ft-support.com
Registered: 2024-01-10 (5 days before this email — newly registered)
Registrar: Namecheap
Registrant: REDACTED (privacy protection)
Name Servers: ns1.njalla.net, ns2.njalla.net  ← Privacy-focused DNS known for abuse
```

**Verdict:** Domain registered 5 days before attack, using privacy protection, on a registrar/DNS known for abuse. Classic phishing infrastructure.

### 3.2 Originating IP — 185.220.101.47

**VirusTotal Results:**
- 12/94 vendors flagged as malicious
- Categorized as: Tor exit node, known spam source

**AbuseIPDB Results:**
- 847 reports in last 90 days
- Confidence of abuse: 98%
- Last reported: 2024-01-14 (day before this email)

**Verdict:** Known malicious IP. No legitimate business sends email from Tor exit nodes.

### 3.3 Phishing URL — microsoft-account-verify.web[.]app

**urlscan.io Results:**
- Hosted on Google Firebase (free hosting — low cost to set up)
- Page title: "Microsoft — Sign in to your account" (impersonation)
- DOM analysis: form submits credentials to `185.220.101.47/collect.php`
- Page screenshot: Pixel-perfect Microsoft login clone

**VirusTotal Results:**
- 28/90 vendors flagged as phishing
- Category: Phishing / Social Engineering

---

## 4. Complete IOC List

| Type | Value | Verdict |
|------|-------|---------|
| Sender Domain | micros0ft-support[.]com | MALICIOUS — block |
| Originating IP | 185.220.101.47 | MALICIOUS — block |
| Phishing URL | microsoft-account-verify.web[.]app | MALICIOUS — block |
| Redirect URL | bit.ly/3xZ9qR2 | MALICIOUS — block |
| Credential collection | 185.220.101.47/collect.php | MALICIOUS |
| Subject line | "[ACTION REQUIRED] Suspicious sign-in..." | IOC for email filter |
| X-Mailer | PHPMailer 6.5.0 | Indicator (not definitive alone) |

---

## 5. Triage Verdict & Recommendations

### 5.1 Confidence Level
**Verdict: CONFIRMED PHISHING** (High confidence)

Evidence summary:
- Spoofed sender domain using typosquatting (micros0ft vs microsoft)
- SPF, DKIM, DMARC all fail
- Originating IP is a Tor exit node with 98% abuse confidence score
- Redirect chain terminates at a Firebase-hosted credential harvesting page
- Credential collection endpoint resolves to same malicious IP
- Domain registered 5 days before the attack — classic phishing infrastructure pattern

### 5.2 Recommended Actions

**Immediate (SOC):**
- [ ] Block `micros0ft-support[.]com` at email gateway
- [ ] Block `185.220.101.47` at perimeter firewall
- [ ] Block `microsoft-account-verify.web[.]app` at web proxy
- [ ] Search email gateway logs for any other recipients of this campaign

**Escalation (if any users clicked):**
- [ ] Identify users who clicked via proxy logs or email tracking pixel
- [ ] Force password reset for any users who may have entered credentials
- [ ] Enable MFA review for those accounts (check for authenticator changes)
- [ ] Monitor for suspicious OAuth app authorizations post-click

**Awareness:**
- [ ] Notify security awareness team — candidate for phishing simulation training
- [ ] Consider sending an "alert" email to users about this specific campaign type

---

## 6. Analyst Notes & Methodology

**Tools Used:**

| Tool | How I Used It |
|------|--------------|
| Email header analyzer (mxtoolbox.com) | Parsed and interpreted raw headers |
| VirusTotal | IOC reputation lookup (IP, domain, URL) |
| urlscan.io | URL sandbox — safe page rendering, redirect chain |
| WHOIS (whois.domaintools.com) | Domain registration intelligence |
| AbuseIPDB | IP reputation and abuse reports |
| Google Firebase lookup | Identified phishing page hosting platform |

**Analysis Time:** ~25 minutes  
**Escalation Required:** Yes — notify manager; check for other recipients

---

*Analyst attestation: All URLs in this report have been defanged (brackets replacing dots) to prevent accidental navigation. Never click phishing URLs outside of an isolated sandbox environment.*
