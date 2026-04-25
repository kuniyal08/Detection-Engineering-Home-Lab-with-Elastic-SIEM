This project documents the configuration of a Security Information and Event Management (SIEM) lab using Elastic Cloud. The lab simulates a real-world Security Operations Center (SOC) environment to practice threat detection, log analysis, and detection rule engineering. Two attack scenarios were successfully executed and detected, demonstrating practical skills relevant to an L1 SOC Analyst role.

## Lab Architecture
- **SIEM Platform:** Elastic Cloud Serverless (Security Project)
- **Log Shipper:** Elastic Agent (Fleet-managed)
- **Monitored Endpoint:** Ubuntu Server 22.04 LTS (VirtualBox VM)
- **Attacker Machine:** Kali Linux (VirtualBox VM)

---

## Detection Engineering Exercises

### 1. SSH Brute Force Attack Detection

#### Attack Description
An adversary attempts to gain unauthorized access to a server by systematically trying a list of passwords against a valid username via the SSH service.

#### Simulation Steps
1. Created a test user account on the Ubuntu server with a weak password.
2. Used `hydra` from Kali Linux to launch a dictionary attack:

    ```bash
    hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://<UBUNTU-IP> -t 4
    ```

#### Detection Rule Configuration (Kibana)
- **Rule Type:** Custom Query
- **Rule Name:** `SSH Brute Force Attempt - Home Lab`
- **Query (KQL):**
  ```
  event.dataset : "system.auth" AND system.auth.ssh.event : "Failed"
  ```
- **Threshold:** > 5 failed attempts within 1 minute, grouped by `source.ip`
- **Severity:** Medium
- **MITRE ATT&CK Mapping:**
  - Tactic: Credential Access (TA0006)
  - Technique: T1110.001 - Password Guessing

#### Alert Validation
The rule successfully triggered within minutes of initiating the `hydra` attack. The alert contained the source IP, target user, and count of failed attempts.

#### Screenshots

| Description | Image |
| :--- | :--- |
| Hydra brute force attack in progress | ![](Images/2.x-HydraScreenshot_2026-04-21_02_51_45.png) |
| Failed SSH logs in Kibana Discover | ![](Images/1.3-Brute-Force-Attack-Log.png) |
| Detection rule configuration (General) | ![](Images/2026-04-21_12-36-About-Rule-1.2.png) |
| MITRE ATT&CK Technique Mapping | ![](Images/2026-04-21_12-36-Mitre-Technique.png) |
| Detection rule creation page | ![](Images/1.1Create%20Detection%20Rule.png) |
| Triggered alert in Security > Alerts | ![](Images/2026-04-21_12-40-Alert-Page1.4.png) |

---

### 2. Web Application Scanning Detection

#### Attack Description
An attacker performs reconnaissance against a web server by scanning for open ports, vulnerabilities, and hidden directories—common precursors to exploitation.

#### Simulation Steps
1. Installed and started Apache2 on the Ubuntu server:

    ```bash
    sudo apt install -y apache2
    sudo systemctl start apache2
    ```

2. From the Kali Linux VM, executed the following scanning tools:
   - **Nmap:** `nmap -sV -p 80 <UBUNTU-IP>`
   - **Nikto:** `nikto -h http://<UBUNTU-IP>`
   - **Gobuster:** `gobuster dir -u http://<UBUNTU-IP> -w /usr/share/wordlists/dirb/common.txt`

#### Detection Rule Configuration (Kibana)
- **Rule Type:** Custom Query
- **Rule Name:** `Web Application Scanning Detected`
- **Query (KQL):**
  ```
  (event.dataset : "apache.access" AND http.response.status_code : 404) OR (url.path : ("*wp-admin*" or "*.php*" or "*admin*"))
  ```
- **Threshold:** > 15 events within 2 minutes, grouped by `source.ip`
- **Severity:** Low
- **MITRE ATT&CK Mapping:**
  - Tactic: Reconnaissance (TA0043)
  - Technique: T1595.002 - Vulnerability Scanning

#### Alert Validation
The rule triggered after running `gobuster`, which generated a high volume of 404 responses. The alert correctly identified the scanning source IP and the targeted web paths.

#### Screenshots

| Description | Image |
| :--- | :--- |
| Apache installation and status | ![](Images/2026-04-21_12-44-Create-Apache2.1.png) |
| Apache integration confirmed in Fleet | ![](Images/2026-04-21_12-47-2.2-Apache-integrated.png) |
| Web scanning tools output (nmap, nikto, gobuster) | ![](Images/2.x-Nmap-Nikita-Gobustor-Screenshot_2026-04-21_03_21_30.png) |
| Detection rule creation step 1 | ![](Images/2026-04-21_12-58-2.3-Create-Rule-Vuln-Scan.png) |
| Detection rule creation step 2 | ![](Images/2026-04-21_12-59-2.4-Create-Rule-Vuln-Scan.png) |
| Triggered alert in Security > Alerts | ![](Images/2026-04-21_13-02-2.5-Alerts.png) |

---

## Key Skills Demonstrated
- Deployment and configuration of Elastic Cloud SIEM
- Fleet-managed Elastic Agent installation on Linux
- Log analysis using Kibana Discover and KQL
- Custom detection rule engineering with threshold logic
- MITRE ATT&CK framework application
- Attack simulation using Kali Linux tools
- Technical documentation

Challenges and Lessons Learned


Data View Configuration: Ensuring the correct data view (logs-*) was selected in Kibana Discover was critical for viewing ingested logs.

Future Enhancements

Integrate Windows event logs via Sysmon for cross-platform detection

Deploy Suricata for network-based intrusion detection

Automate alert notifications to Slack or email

Implement cron persistence detection using journald log analysis
