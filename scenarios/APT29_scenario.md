# Incident Response Testing Scenario  
**Target Organisation:** Small Finance / Banking firm (1-50 employees)  
**Threat Actor:** APT-29 (aka *Cozy Bear*)  
**Test Type:** Table-top + Technical Simulation (Enterprise-focused)  
**Date of Exercise:** *To be scheduled*  

---  

## 1. Purpose & Objectives  

| Objective | Success Indicator |
|-----------|-------------------|
| **Validate detection** of APT-29 tactics across the full kill-chain (Recon → Exfiltration). | Alerts generated in SIEM, EDR, and Cloud-security tools for each technique. |
| **Assess response** processes for containment, eradication, and recovery. | Correctly executed playbooks, documented evidence, and service restoration within defined SLAs. |
| **Test communication** channels (internal, management, legal, regulator, customers). | Timely, accurate notifications following the incident-response communication plan. |
| **Identify gaps** in tooling, processes, and staff knowledge. | Findings recorded in a post-exercise report with remediation recommendations. |
| **Exercise regulatory compliance** (e.g., FCA, GDPR) for a financial institution. | Evidence of appropriate data-protection and breach-notification steps. |

---  

## 2. Scope  

| In-Scope | Out-of-Scope |
|----------|--------------|
| All on-prem Windows servers & workstations, domain controllers, and AD infrastructure. | Third-party SaaS applications not owned by the firm (unless they host the public-facing web service). |
| Cloud-based assets (AWS/Azure) used for web-application hosting and backup. | Physical security controls (badge readers, CCTV). |
| Network perimeter devices (firewall, IDS/IPS) and internal segmentation. | Employee personal devices not enrolled in MDM. |
| Incident-response team, SOC analysts, and IT operations staff. | External partners’ incident-response processes (unless they are directly affected). |

---  

## 3. Scenario Narrative (Chronological Flow)

> **Note:** The narrative is presented as a “red-team” simulation. The defenders will receive alerts and artefacts in real-time, but the full story is disclosed at the end for de-brief.

| Phase | MITRE ATT&CK Technique (ID) | Expected Attacker Action | Defender Artefacts / Alerts |
|-------|----------------------------|--------------------------|-----------------------------|
| **1 - Reconnaissance** | Credentials - **T1589.001** | APT-29 harvests employee e-mail addresses and public LinkedIn data, then performs credential-stuffing attempts against the company’s VPN portal. | Multiple failed VPN logins flagged by VPN-auth logs; SIEM alerts for credential-stuffing pattern. |
| **2 - Resource Development** | Cloud Accounts - **T1586.003** | Threat actors create a disposable Azure AD tenant and register a malicious sub-domain (e.g., *updates.fin-svc.com*) for domain-fronting. | Azure AD sign-in alerts for new tenant creation from unfamiliar IP; DNS logs show registration of unknown domain. |
| **3 - Initial Access** | Exploit Public-Facing Application - **T1190** | An unpatched CVE in the company’s public web portal (e.g., CVE-2023-XXXXX) is exploited, giving the attacker a reverse shell on the DMZ web server. | IDS/IPS triggers on anomalous HTTP payload; Web-application firewall (WAF) logs show exploitation attempt; EDR on the server reports a new process (cmd.exe) launched from the web service. |
| **4 - Execution** | Windows Management Instrumentation - **T1047** | Using the compromised web server, the attacker issues WMI commands to a internal Windows workstation (IP 10.0.5.23) to download a second-stage payload. | WMI event logs on the workstation show remote execution; network flow logs capture SMB traffic to the workstation. |
| **5 - Persistence** | Registry Run Keys / Startup Folder - **T1547.001** | The second-stage payload writes a Run-key (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\svchost.exe`) to maintain persistence. | Endpoint logs show registry modification; EDR alerts on suspicious Run-key creation. |
| **6 - Privilege Escalation** | Exploitation for Privilege Escalation - **T1068** | The payload exploits CVE-2022-XXXX in the Windows kernel to obtain SYSTEM rights. | Kernel-mode driver load events; EDR alerts for abnormal privilege escalation. |
| **7 - Defense Evasion** | Software Packing - **T1027.002** | The malicious binary is packed with UPX-like obfuscation to bypass signature-based AV. | AV reports “unknown” file; sandbox analysis shows unpacking behaviour. |
| **8 - Credential Access** | DCSync - **T1003.006** | With SYSTEM, the attacker performs a DCSync request against the domain controller, dumping all password hashes. | DC security logs show `replication` request from a non-replicating DC; LSASS memory dump alerts. |
| **9 - Discovery** | Internet Connection Discovery - **T1016.001** | Malware queries external IP (e.g., `ipinfo.io`) to confirm internet connectivity before exfiltration. | Outbound DNS query to *ipinfo.io*; Proxy logs show HTTPS request to unknown host. |
| **10 - Lateral Movement** | Windows Remote Management - **T1021.006** | Using stolen credentials, the attacker moves laterally to a finance server (10.0.10.45) via WinRM. | WinRM logs show new session from compromised workstation; failed logon attempts on target server. |
| **11 - Collection** | Archive via Utility - **T1560.001** | Files from the “Financial Reports” folder are zipped with `tar.exe`. | File-integrity monitoring flags creation of a large `.tar` archive in a sensitive directory. |
| **12 - Command & Control** | Domain Fronting - **T1090.004** | The packed payload contacts the attacker-controlled domain fronting through `updates.fin-svc.com` using HTTPS over port 443. | TLS inspection (if deployed) shows SNI mismatch; DNS query to malicious domain; outbound traffic to unknown IP ranges. |
| **13 - Exfiltration** | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol - **T1048.002** | Data is encrypted with the attacker’s RSA public key, then exfiltrated via a custom HTTP API that returns a 200 OK “static page”. | Network IDS flags large outbound encrypted payloads; proxy logs show POST to `https://updates.fin-svc.com/api/v1/upload`. |

---  

## 4. Pre-Exercise Set-Up  

1. **Red-Team (Simulated) Actions**  
   * Use a controlled lab environment that mirrors the target network.  
   * Deploy the same tools and techniques listed above (e.g., Metasploit for CVE exploitation, `wmiexec`, `mimikatz` for DCSync, custom Python packer).  
   * Ensure all malicious traffic is routed through a **sinkhole** that records events but does not impact production.  

2. **Blue-Team (Defender) Preparation**  
   * Enable logging on all relevant platforms (Windows Event Logs, Azure AD sign-ins, firewall/IDS, proxy, SIEM).  
   * Ensure the **incident-response playbooks** for each ATT&CK technique are accessible.  
   * Populate the **communication matrix** (who notifies whom, regulatory timelines).  

3. **Tooling**  
   * SIEM (e.g., Splunk, Elastic) - correlation rules for the techniques above.  
   * EDR (e.g., SentinelOne, CrowdStrike) - endpoint detection & containment.  
   * Cloud Security Posture Management (CSPM) - Azure AD monitoring.  
   * Network traffic analysis - Zeek, Suricata.  

---  

## 5. Execution Timeline (Suggested)

| Time | Activity | Owner |
|------|----------|-------|
| **00:00 - 00:15** | Kick-off - brief on scenario objectives, roles, and rules of engagement. | Exercise Lead |
| **00:15 - 00:45** | Red-team initiates Recon (credential-stuffing) - blue-team monitors for alerts. | Red / Blue |
| **00:45 - 01:30** | Exploit public-facing app, deliver reverse shell. | Red |
| **01:30 - 02:15** | Blue-team detects exploit via IDS/WAF, begins triage. | Blue |
| **02:15 - 03:00** | WMI execution, persistence, privilege escalation - blue-team responds to each alert. | Red / Blue |
| **03:00 - 04:00** | DCSync & credential theft - blue-team initiates containment (isolate DC). | Blue |
| **04:00 - 04:45** | Lateral movement via WinRM - blue-team performs network segmentation checks. | Blue |
| **04:45 - 05:30** | Archive creation and C2 domain-fronting - blue-team investigates outbound traffic. | Blue |
| **05:30 - 06:00** | Exfiltration attempt - blue-team blocks traffic, begins forensic capture. | Blue |
| **06:00 - 06:30** | Containment & eradication - remove malicious binaries, rotate secrets. | Blue |
| **06:30 - 07:00** | Recovery - restore services, validate integrity. | Blue |
| **07:00 - 08:00** | Debrief - discuss findings, lessons learned, remediation plan. | All |

*The exact timing can be compressed or expanded depending on the team’s speed.*

---  

## 6. Expected Detection Points & Evidence Collection  

| ATT&CK Step | Primary Log Sources | Sample Alert Rule (SIEM) | Artefacts to Preserve |
|------------|---------------------|--------------------------|-----------------------|
| **T1589.001 - Credentials** | VPN auth logs, Azure AD sign-ins | `failed_logins > 5 within 5m` | Raw auth logs, IP geolocation data |
| **T1586.003 - Cloud Accounts** | Azure AD audit, DNS logs | `new tenant creation from unknown IP` | Tenant creation JSON, DNS zone transfer logs |
| **T1190 - Exploit Public-Facing App** | WAF, IDS/IPS, web server access logs | `http request containing known exploit payload` | Full packet capture (PCAP) of the request |
| **T1047 - WMI** | Windows Event ID 4688, WMI-Activity logs | `process creation via wmi` | Sysmon Event ID 1, WMI query strings |
| **T1547.001 - Registry Run Keys** | Sysmon Event ID 13, Registry audit | `new Run key under HKLM` | Registry hive snapshot, reg.exe export |
| **T1068 - Privilege Escalation** | Kernel driver load events, Sysmon 7 | `unsigned driver loaded as SYSTEM` | Memory dump of affected host |
| **T1027.002 - Software Packing** | AV/EDR alerts, sandbox reports | `file flagged as packed` | Original binary, unpacked version, YARA match |
| **T1003.006 - DCSync** | DC Security Event ID 4662, NetLogon logs | `replication request from non-DC account` | LSASS dump, NTDS.dit copy (if taken) |
| **T1016.001 - Internet Discovery** | Proxy/DNS logs | `outbound request to ipinfo.io` | DNS query logs, HTTP request headers |
| **T1021.006 - WinRM** | Windows Event ID 4624 (logon type 3), WinRM logs | `new remote PowerShell session` | Session IDs, PowerShell transcript |
| **T1560.001 - Archive** | File-integrity monitoring, Sysmon 11 (file create) | `large .tar file created in sensitive path` | Hash of archive, list of archived files |
| **T1090.004 - Domain Fronting** | TLS SNI mismatch detection, DNS logs | `SNI domain != HTTP Host header` | Full TLS handshake capture |
| **T1048.002 - Encrypted Exfil** | NetFlow, IDS (large outbound TLS) | `encrypted payload > 5 MB to unknown IP` | Encrypted payload (if captured), proxy logs |

---  

## 7. Response Playbook Highlights  

### 7.1. Initial Triage  
1. **Acknowledge** the alert in the ticketing system.  
2. **Gather** relevant logs (SIEM, endpoint, network).  
3. **Assign** severity (APT-29 activity = **Critical**).  

### 7.2. Containment  
* **Network:** Quarantine affected hosts (isolation VLAN, block outbound to malicious domain).  
* **Identity:** Reset compromised credentials, enforce MFA for all privileged accounts.  
* **Endpoint:** Deploy EDR kill-chain to terminate malicious processes, delete Run-key entries.  

### 7.3. Eradication  
* Run **offline malware scans** on all endpoints.  
* **Patch** the vulnerable public-facing application (apply CVE-2023-XXXXX fix).  
* Remove any **unauthorised cloud resources** (malicious Azure tenant, DNS records).  

### 7.4. Recovery  
* Restore from **clean backups** (verify backup integrity).  
* **Re-enable** services after confirming no residual artefacts.  
* Conduct **post-recovery validation** (penetration test on the same vector).  

### 7.5. Post-Incident Activities  
* **Root-cause analysis** - map each ATT&CK technique to detection gaps.  
* **Regulatory reporting** - prepare FCA/GDPR breach notice (within 72 h if personal data is impacted).  
* **Update** detection rules, harden configurations, and schedule a **red-team retest**.  

---  

## 8. Evaluation Criteria  

| Category | Metric | Pass / Fail Definition |
|----------|--------|------------------------|
| **Detection** | % of ATT&CK techniques that generated an alert within 5 min of execution. | ≥ 80 % = Pass |
| **Containment Time** | Time from first alert to network isolation of compromised host. | ≤ 30 min = Pass |
| **Evidence Preservation** | Completeness of required artefacts (logs, memory dumps, PCAP). | All mandatory artefacts captured = Pass |
| **Communication** | Initial internal notification within 15 min; regulator notice drafted within 1 h of decision. | Both met = Pass |
| **Recovery** | Services restored to normal operation within 2 h of containment. | ≤ 2 h = Pass |
| **Lessons Learned** | Actionable remediation items identified for ≥ 75 % of gaps. | ≥ 75 % = Pass |

---  

## 9. Roles & Responsibilities  

| Role | Responsibilities |
|------|------------------|
| **Exercise Lead (IR Manager)** | Overall coordination, timeline enforcement, final de-brief. |
| **SOC Analyst** | Monitoring, initial alert triage, escalation. |
| **Forensic Engineer** | Evidence collection, memory imaging, log preservation. |
| **Patch Management Lead** | Apply critical patches, verify remediation. |
| **Legal / Compliance Officer** | Assess regulatory impact, draft breach notifications. |
| **Communications Officer** | Internal and external stakeholder updates, press release (if required). |
| **Red-Team Facilitator** | Simulated attacker actions, ensure safety, provide hints if needed. |
| **Executive Sponsor** | Decision-making on service shutdowns, resource authorisation. |

---  

## 10. Debrief & Reporting  

1. **After-Action Review (AAR) Document** - includes timeline, detection gaps, containment effectiveness, and remediation roadmap.  
2. **Technical Report** - detailed log excerpts, PCAP analysis, forensic findings.  
3. **Executive Summary** - high-level impact, business-continuity implications, regulatory compliance status.  
4. **Remediation Tracker** - tasks assigned, owners, due dates, verification steps.  

---  

## 11. References  

* MITRE ATT&CK® Enterprise Matrix - version 13.0 (2025).  
* FCA Guidance on Operational Resilience (2024).  
* NIST SP 800-61r2 - Computer Security Incident Handling Guide.  
* ISO/IEC 27035-1:2016 - Information Security Incident Management.  

---  

### End of Scenario  

*Prepared by the Incident-Response Exercise Planning Team - 1 February 2026*