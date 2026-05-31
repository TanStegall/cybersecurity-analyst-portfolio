# Wazuh SIEM Home Lab: Setup & Alert Analysis Guide

**Environment:** VirtualBox on Windows 11 Host  
**Lab Date:** June 2026  
**Analyst:** Tangia Stegall  

---

## Lab Objective

Deploy a functional SIEM environment using Wazuh (open-source), onboard a simulated endpoint, generate real alerts using known attack techniques, and document the process as a Tier 1 analyst would.

---

## Environment Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Host Machine                      │
│                  Windows 11 / macOS                  │
│                                                     │
│   ┌─────────────────────┐   ┌─────────────────────┐ │
│   │   Wazuh Manager VM  │   │   Agent (Ubuntu) VM │ │
│   │   Ubuntu 22.04 LTS  │   │   Ubuntu 22.04 LTS  │ │
│   │   4GB RAM / 2 vCPU  │   │   2GB RAM / 1 vCPU  │ │
│   │   192.168.56.10     │   │   192.168.56.20     │ │
│   └─────────────────────┘   └─────────────────────┘ │
│              │                        │              │
│         [Host-Only Network: 192.168.56.0/24]         │
└─────────────────────────────────────────────────────┘
```

---

## Part 1: Wazuh Manager Installation

### 1.1 Prerequisites
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required dependencies
sudo apt install curl apt-transport-https -y
```

### 1.2 Install Wazuh (All-in-One)
```bash
# Download and run the Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# The installer deploys:
# - Wazuh Manager
# - Wazuh Indexer (Elasticsearch fork)
# - Wazuh Dashboard (Kibana fork)
```

### 1.3 Access the Dashboard
```
URL:      https://192.168.56.10
Username: admin
Password: (generated during install — save this!)
```

**Screenshot placeholder:** `alert-screenshots/01-dashboard-login.png`

---

## Part 2: Agent Deployment (Ubuntu VM)

### 2.1 Install Wazuh Agent
```bash
# On the Ubuntu Agent VM
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update
sudo apt install wazuh-agent -y
```

### 2.2 Configure Agent to Point to Manager
```bash
# Edit the Wazuh agent configuration
sudo nano /var/ossec/etc/ossec.conf

# Set the manager IP address:
# <server>
#   <address>192.168.56.10</address>
# </server>
```

### 2.3 Start and Enable the Agent
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### 2.4 Verify Connection in Dashboard
After a few minutes, the agent should appear as **Active** in:  
`Wazuh Dashboard → Agents → [agent name]`

**Screenshot placeholder:** `alert-screenshots/02-agent-connected.png`

---

## Part 3: Generating & Analyzing Alerts

### 3.1 Alert Test 1 — SSH Brute Force Simulation

**Objective:** Confirm Wazuh detects repeated failed SSH authentication attempts.

```bash
# From a third VM or host terminal — simulate failed SSH logins
for i in {1..20}; do
  ssh wronguser@192.168.56.20 -o ConnectTimeout=2 2>/dev/null
done
```

**Expected Alert:** Rule 5763 — "sshd: brute force attack."  
**Wazuh Rule ID:** 5763  
**Alert Level:** 10 (High)

**Screenshot placeholder:** `alert-screenshots/03-ssh-brute-force-alert.png`

**Analyst Notes:**  
The alert triggered after 8 failed attempts within 120 seconds, consistent with Wazuh's default threshold. In a real environment, I would check if this IP is internal (misconfigured service?) or external (active brute force). For an external IP, immediate firewall block and escalation to Tier 2 would follow.

---

### 3.2 Alert Test 2 — Sudo Command Execution

**Objective:** Confirm Wazuh logs privilege escalation activity on endpoints.

```bash
# On the Agent VM — run a privileged command as a non-root user
sudo cat /etc/shadow
```

**Expected Alert:** Rule 5402 — "Successful sudo to ROOT executed."  
**Alert Level:** 3 (Low — expected behavior, but important for audit trail)

**Analyst Notes:**  
This alert is expected and informational on its own. In an IR context, it becomes meaningful when correlated with: unusual login times, new user accounts, or prior reconnaissance alerts on the same host. This demonstrates the importance of correlation over single-alert triage.

---

### 3.3 Alert Test 3 — File Integrity Monitoring (FIM)

**Objective:** Detect unauthorized changes to monitored files.

**Configuration (ossec.conf on agent):**
```xml
<syscheck>
  <directories check_all="yes" realtime="yes">/etc,/usr/bin</directories>
</syscheck>
```

```bash
# Simulate a file modification in monitored path
sudo touch /etc/test-modification.txt
echo "Unauthorized change" | sudo tee /etc/test-modification.txt
```

**Expected Alert:** Rule 550 — "Integrity checksum changed."  
**Alert Level:** 7 (Medium)

**Screenshot placeholder:** `alert-screenshots/04-fim-alert.png`

**Analyst Notes:**  
FIM alerts on `/etc` warrant attention because configuration files control system behavior. The first question is always: was this a legitimate change (patching, admin action) or unauthorized? In a real SOC, this would prompt a ticket to the endpoint owner for confirmation, with escalation if unconfirmed within the SLA window.

---

## Part 4: Alert Tuning — Suppressing False Positives

A raw Wazuh deployment generates significant noise. Part of a real analyst's job is tuning.

### 4.1 Identified False Positive
During my lab, Wazuh generated repeated alerts for a legitimate cron job running as root every 5 minutes, triggering Rule 5402 at high frequency.

### 4.2 Tuning Decision
Created a local rule override to suppress this specific cron process from triggering the sudo alert:

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="syslog,sudo,">
  <rule id="100001" level="0">
    <if_sid>5402</if_sid>
    <match>COMMAND=/usr/bin/certbot</match>
    <description>Suppress: expected certbot cron running as root</description>
  </rule>
</group>
```

**Lesson:** Tuning is a balance. Suppressing too aggressively creates blind spots. Every suppression decision should be documented with justification.

---

## Part 5: Key Takeaways

| Area | Finding |
|------|---------|
| Deployment | Wazuh all-in-one install takes ~15 minutes; agent onboarding ~5 minutes per host |
| Detection Quality | Default rules cover the most common attack patterns; custom rules needed for environment-specific detections |
| Alert Volume | A single agent generates ~50-200 alerts/day in a lab; production environments require significant tuning |
| FIM Value | File Integrity Monitoring is underutilized — it provides high-value evidence during post-incident analysis |
| Correlation | Single alerts rarely tell the full story; analyst value is in pattern recognition across multiple alerts |

---

## Files in This Folder

| File | Description |
|------|-------------|
| `wazuh-setup-guide.md` | This document — full setup and analysis walkthrough |
| `alert-screenshots/` | Screenshots of key alerts (see folder) |
| `README.md` | Project overview |
