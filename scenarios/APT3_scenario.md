# Incident Response Testing Scenario  
**Company:** Small‑scale Aerospace / Defence firm (1‑50 employees)  
**Threat Actor:** APT3 (aka “Gothic Panda”) – known for sophisticated supply‑chain attacks and use of custom tooling.  

---  

## 1. Purpose & Objectives  

| Goal | Success Metric |
|------|----------------|
| **Validate detection** of each ATT&CK technique listed in the threat‑actor kill‑chain. | ≥ 80 % of technique‑specific alerts generated within 5 min of simulated activity. |
| **Assess containment** of a multi‑stage intrusion across Windows workstations and servers. | All compromised assets isolated within 30 min of detection. |
| **Test evidence‑preservation** procedures for forensic artefacts (code‑signing certs, DLLs, scheduled‑task metadata, etc.). | Complete chain‑of‑custody logs for every artefact collected. |
| **Exercise communication** (internal, management, legal, external partners). | All required notifications issued within defined SLAs (e.g., senior management – 1 h, regulator – 24 h). |
| **Evaluate post‑incident processes** – lessons‑learned, mitigation, reporting. | Action‑item list produced and approved within 5 business days. |

---

## 2. Scope  

| Included | Excluded |
|----------|----------|
| All Windows workstations, domain controllers and the central build server used for firmware/flight‑software compilation. | Cloud‑only SaaS services (e.g., Office 365) – not part of this test. |
| Network segments: Corporate LAN, DMZ (web‑gateway), and the isolated “Secure‑Build” VLAN. | Physical security controls (badge readers, CCTV). |
| Logging sources: Windows Event Logs, Sysmon, Endpoint Detection & Response (EDR), SIEM, DNS logs, Proxy logs, and the internal build‑pipeline audit trail. | Third‑party supplier environments (simulated only via artefacts). |

---

## 3. Scenario Narrative (Red‑Team Playbook)

> **Note:** The scenario can be executed as a **live tabletop** with optional **technical injections** (scripts, scheduled tasks, service binaries) on a dedicated test lab that mirrors the production environment.

| Phase | ATT&CK Technique | Red‑Team Action | Expected Blue‑Team Artefacts |
|-------|------------------|----------------|------------------------------|
| **1 – Resource Development** | T1588.003 – Code Signing Certificates | Obtain a fraudulent code‑signing certificate from a compromised CA (simulated by providing a signed `.pfx` file). | New certificate added to Windows Trusted Root store; Event ID 4698 (certificate enrollment). |
| **2 – Initial Access** | T1195 – Supply Chain Compromise | Replace a legitimate build‑tool binary on the “Secure‑Build” server with a malicious, signed version that injects a backdoor DLL. | File hash change (SHA‑256); Windows Defender SmartScreen warning; EDR alerts on unsigned module load. |
| **3 – Execution** | T1053.005 – Scheduled Task (Windows) | Create a **system‑level scheduled task** (`AT-Update`) that runs the malicious binary every 30 min. | Event ID 4698 (task creation); Task XML stored under `C:\Windows\System32\Tasks\AT-Update`. |
| **4 – Persistence** | T1543.003 – Windows Service | Install the backdoor as a **Windows Service** (`DefenderSvc`) that starts automatically. | Event ID 7045 (service install); Service listed in `sc query`. |
| **5 – Privilege Escalation** | T1068 – Exploitation for Privilege Escalation | Exploit a known kernel‑mode vulnerability (e.g., CVE‑2023‑XXXXX) to gain SYSTEM. | Event ID 4624 (logon type 5); LSASS memory dump triggered. |
| **6 – Defense Evasion** | T1027.013 – Encrypted/Encoded File | Payload is packed with a custom XOR‑based encoder; the scheduled‑task command line points to the encoded file. | EDR flags “Suspicious encoded payload”; Sysmon Event ID 1 shows a *hidden* `cmd.exe /c` call. |
| **7 – Credential Access** | T1556.002 – Password Filter DLL | Drop a malicious **Password Filter DLL** (`pwdflt.dll`) that captures clear‑text passwords and writes them to `C:\Temp\creds.log`. | Event ID 5156 (filter DLL load); New file created with restricted ACL. |
| **8 – Discovery** | T1057 – Process Discovery | The backdoor enumerates running processes on each compromised host and exfiltrates the list. | Sysmon Event ID 5 (process termination) showing `tasklist.exe`; network traffic to internal C2 IP. |
| **9 – Lateral Movement** | T1021.001 – Remote Desktop Protocol | Use harvested credentials to open **RDP** sessions to additional workstations. | Event ID 4624 (logon type 10); RDP listener logs; unusual source IP on internal network. |
| **10 – Collection** | T1119 – Automated Collection | Aggregate files from `%APPDATA%`, `C:\ProgramData\`, and the build artefacts into a zip archive. | File creation event for `C:\Temp\collection.zip`; EDR flags high‑entropy file. |
| **11 – Command & Control** | T1573.002 – Asymmetric Cryptography | Communicate with a simulated external C2 server using TLS with RSA‑encrypted payloads. | Proxy/DNS logs show outbound HTTPS to `c2.example.com`; TLS handshake with unusual certificate. |
| **12 – Exfiltration** | T1048.003 – Exfiltration Over Unencrypted Non‑C2 Protocol | Transfer the zip archive via **FTP (clear‑text)** to a malicious external server. | FTP connection in firewall logs; plaintext credentials observed; large outbound data volume. |

---

## 4. Test Execution Plan  

| Step | Activity | Owner | Timing |
|------|----------|-------|--------|
| **A. Preparation** | Build a replica environment, generate the malicious binaries, create the fake code‑signing certificate, configure simulated C2/FTP server. | Red‑Team (external consultant) | Day ‑2 to Day ‑1 |
| **B. Kick‑off Brief** | Explain rules of engagement, safety controls, and communication channels. | Incident Response Manager (IR‑Mgr) | Day 0, 09:00 |
| **C. Injection 1 – Resource Development** | Deploy the signed malicious binary on the build server. | Red‑Team (remote) | 09:30 |
| **D. Detection Checkpoint 1** | Verify alerts from code‑signing certificate change and file‑integrity monitoring. | SOC Analyst | ≤ 05 min |
| **E. Injection 2 – Execution / Persistence** | Create scheduled task and install service. | Red‑Team | 10:00 |
| **F. Detection Checkpoint 2** | Review SIEM for task‑creation and service‑install events. | SOC Analyst | ≤ 05 min |
| **G. Injection 3 – Privilege Escalation & Defense Evasion** | Trigger kernel exploit, run encoded payload. | Red‑Team | 10:45 |
| **H. Detection Checkpoint 3** | Look for anomalous kernel‑mode activity, encoded‑file alerts. | SOC Analyst | ≤ 05 min |
| **I. Injection 4 – Credential Access** | Drop password‑filter DLL and capture credentials. | Red‑Team | 11:30 |
| **J. Detection Checkpoint 4** | Alert on DLL load in LSASS, new file creation with sensitive ACLs. | SOC Analyst | ≤ 05 min |
| **K. Injection 5 – Lateral Movement & Collection** | Use stolen credentials to RDP into a second workstation; collect files. | Red‑Team | 12:15 |
| **L. Detection Checkpoint 5** | Review RDP logs, process‑discovery events, and data‑collection alerts. | SOC Analyst | ≤ 05 min |
| **M. Injection 6 – C2 & Exfiltration** | Initiate TLS‑C2 handshake, then FTP the archive. | Red‑Team | 13:00 |
| **N. Detection Checkpoint 6** | Identify outbound TLS to unknown domain, FTP traffic on port 21. | SOC Analyst | ≤ 05 min |
| **O. Containment Exercise** | Blue‑Team must isolate compromised hosts, revoke certificates, and purge the malicious service. | Incident Response Team (IRT) | Commence as soon as first alert is confirmed. |
| **P. Forensic Capture** | Acquire memory images, disk images, and logs from all affected assets. | Forensics Lead | Immediately after containment. |
| **Q. Debrief & Reporting** | Conduct a structured after‑action review (AAR). | IR‑Mgr & Red‑Team | Day +1, 09:00‑11:00 |
| **R. Remediation Planning** | Produce a remediation roadmap (patching, certificate revocation, supply‑chain hardening). | Security Architect | Day +2 |

---

## 5. Detection & Monitoring Requirements  

| Data Source | Relevant Event IDs / Fields | ATT&CK Mapping |
|-------------|-----------------------------|----------------|
| **Windows Event Logs** | 4698 (Task created), 7045 (Service installed), 4624 (Logon), 5156 (Password filter DLL load) | T1053.005, T1543.003, T1021.001, T1556.002 |
| **Sysmon** | Event 1 (Process creation), Event 5 (Process termination), Event 7 (Image load) | T1068, T1027.013 |
| **EDR** | Behavioural alerts for “Encoded payload”, “Privilege escalation”, “Lateral movement” | T1068, T1027.013, T1021.001 |
| **Endpoint Certificate Store** | New root/intermediate certificate, usage of code‑signing cert | T1588.003 |
| **Network Sensors / Proxy** | TLS handshake to unknown FQDN, FTP traffic on port 21, abnormal data volumes | T1573.002, T1048.003 |
| **Build‑Server CI/CD Logs** | Unexpected binary hash change, unsigned artefact published | T1195 |
| **Active Directory** | New computer object or service principal created, abnormal privileged group additions | T1543.003, T1068 |

*All alerts should be correlated in the SIEM and escalated to the SOC within the defined 5‑minute window.*

---

## 6. Response Playbooks (High‑Level)

### 6.1 Initial Detection & Triage  

1. **Alert Intake** – SOC analyst acknowledges the alert, assigns a ticket, and tags the relevant ATT&CK technique.  
2. **Validate** – Confirm the event is not a false positive (e.g., check the binary signature, task schedule).  
3. **Escalate** – If confirmed, trigger the **“Advanced Persistent Threat”** response plan (IR‑Mgr, Incident Commander, Legal).  

### 6.2 Containment  

| Action | Owner | Time Target |
|--------|-------|-------------|
| Isolate compromised host(s) (network quarantine). | Network Engineer | ≤ 10 min |
| Disable malicious scheduled task & service. | Endpoint Admin | ≤ 15 min |
| Revoke the fraudulent code‑signing certificate (CRL update). | PKI Admin | ≤ 20 min |
| Reset credentials for accounts seen in RDP logs. | IAM Lead | ≤ 30 min |
| Block outbound FTP and unknown TLS destinations at firewall. | Firewall Admin | ≤ 30 min |

### 6.3 Eradication  

* Remove the malicious binaries, DLLs, and any backdoor artefacts.  
* Patch the exploited kernel vulnerability (apply latest Windows update).  
* Re‑image any workstation where integrity cannot be guaranteed.  

### 6.4 Recovery  

* Restore services from known‑good backups.  
* Verify code‑signing chain for all build artefacts.  
* Conduct a **post‑recovery validation** (run a limited scan for any residual indicators).  

### 6.5 Post‑Incident Activities  

* **Forensic Report** – Chain‑of‑custody, artefact hashes, timeline.  
* **Lessons‑Learned Workshop** – Identify gaps (e.g., supply‑chain scanning, certificate monitoring).  
* **Regulatory Notification** – Draft breach notice (if required under Defence‑Sensitive Data Regulations).  

---

## 7. Evaluation Criteria  

| Category | Success Indicator | Minimum Acceptable Score |
|----------|-------------------|--------------------------|
| **Detection** | Number of ATT&CK techniques that generated a timely alert. | ≥ 8 / 12 (66 %) |
| **Triage Speed** | Mean time from alert to ticket creation. | ≤ 5 min |
| **Containment Time** | Time from detection to isolation of all compromised assets. | ≤ 30 min |
| **Evidence Quality** | Completeness of forensic artefacts (memory, logs, binaries). | 100 % of required artefacts captured |
| **Communication** | SLA adherence for internal & external notifications. | All within defined SLA |
| **Recovery** | Systems restored to normal operation with no residual indicators. | 100 % verified |
| **Documentation** | After‑action report delivered, signed off, and remediation plan issued. | Delivered within 5 business days |

A **red‑team scorecard** will be compiled after the exercise, and a **blue‑team scorecard** will be generated from the above metrics. Scores will be reviewed by senior management to decide on follow‑up actions.

---

## 8. Required Preparations (Blue‑Team Checklist)

- [ ] Verify test environment is **segregated** from production (air‑gap or VLAN isolation).  
- [ ] Ensure all logging mechanisms (Event Forwarding, Sysmon, EDR) are **enabled** and forwarding to the SIEM.  
- [ ] Pre‑stage detection rules for the listed ATT&CK techniques (use MITRE ATT&CK STIX patterns).  
- [ ] Create a **communication tree** (who to call, escalation matrix).  
- [ ] Draft a **sample regulator notification** (for the Defence sector).  
- [ ] Assign a **record‑keeper** for evidence chain‑of‑custody.  

---

## 9. References  

- MITRE ATT&CK® Enterprise Matrix – Version 13.1 (2024)  
- NIST SP 800‑61r2 – Computer Security Incident Handling Guide  
- ISO/IEC 27035‑1:2016 – Information security incident management  
- UK Defence Cyber‑Security Policy (2023) – Guidance on supply‑chain security  

---  

**Prepared by:**  
*Cyber‑Security Incident Response Team – Lead Analyst*  
*Date:* 12 February 2026  

*End of scenario document.*