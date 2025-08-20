# 🛡️ Defense Strategy Overview

_**"Align real-world risk to strategic, cost-effective controls. A defense minded approach—maximizing native capabilities before budget expansion."**
 by 0xBrianSec._

---

## 1. Cybersecurity Posture & Identity

The core of any defensive strategy is identity—who can access what, from where, and with what level of trust. For modern hybrid environments, implementing **Zero Trust Architecture (ZTA)** is not optional—it’s foundational.

- **Multi-Factor Authentication (MFA)** should be enforced not just at user login but also at access escalation events (admin login, privilege elevation, or remote RDP/SSH). This aligns with [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) and [NIST 800-53 IA-2](https://nvd.nist.gov/800-53/Rev4/control/IA-2).

- **Privileged Access Workstations (PAWs)** must be isolated VMs or locked devices used only for administrative actions. This mitigates T1078 (Valid Accounts) and T1059 (Command and Scripting Interpreter) from MITRE ATT&CK.

- Implement **identity segmentation** by role and trust tier (NIST PR.AC-4). An admin should never log into internet-facing applications with domain-wide rights.

- Utilize **SSO with conditional access** policies and automatic session revocation (NIST AC-12, AC-14). Monitor cloud identities using Azure AD Sign-In logs or Okta System Log APIs.

- Audit for “dormant admin accounts,” which are frequent targets in APT campaigns, particularly post-compromise (T1087.002 – Domain Accounts).

---

## 2. Realistic Risk vs. CVSS

The Common Vulnerability Scoring System (CVSS) often misleads executives and vulnerability managers alike. CVSS is not threat modeling—it's exposure modeling.

> A CVSS 9.8 RCE requiring email-based social engineering is **less urgent** than a CVSS 6.5 flaw in a public-facing asset with no authentication.

### Executive Perspective:

- **Real-world attackers do not prioritize by CVSS**—they prioritize by ROI and effort. For example, T1190 (Exploit Public-Facing Application) is often chained with T1078 to gain initial access.

- A misconfigured database service running on port 3306 (MySQL) with no firewall boundaries or identity controls offers attackers direct access to sensitive data (CWE-306: Missing Authentication for Critical Function, CVE-2020-25705).

- NIST’s guidance under [RA-5](https://nvd.nist.gov/800-53/Rev4/control/RA-5) mandates risk-based prioritization. That means evaluating asset criticality, exploitability, exposure, and required attacker sophistication—not just the CVSS vector.

### Tactical Application:

- Use the **EPSS (Exploit Prediction Scoring System)** alongside CVSS.
- Add threat context with **CISA KEV** (Known Exploited Vulnerabilities) catalog.
- Overlay MITRE ATT&CK to understand adversarial patterns: is this a local priv-esc used post-compromise, or a public RCE?

---

## 3. Live Services Hardening

Most breaches start by abusing what’s already running.

### Define “Live Services”:

Live services are long-running processes that start automatically (T1543.003), run with elevated privileges, and are exposed through open ports or DCOM-style interactions. This includes:

- Windows Services (`svchost.exe`, `w3wp.exe`)
- Linux daemons (`sshd`, `nginx`, `cron`)
- Agent-based tools (AV, backup, update clients)

### Risks:

- Exploitable binaries with unquoted service paths (CWE-428) → Priv-esc via writable `C:\Program Files\Vendor App\app.exe`.
- Services with weak ACLs on their `ImagePath` registry key (CVE-2022-0847).
- Overprivileged services (SYSTEM/ROOT) running user-triggered code.
- Insecure auto-start extensions (T1547.001).

### Defense:

- Apply CIS Benchmarks and STIGs (NIST CM-6) for all OS and application services.
- Audit service permissions and startup locations using `accesschk`, `winPEAS`, and `seatbelt.exe`.
- Remove unnecessary services and disable Remote Registry (T1021.002).
- Enable process auditing (Event ID 4688) and track parent-child process chains for abnormal spawns (e.g., `spoolsv.exe` launching `cmd.exe`).

---

## 4. File Race Attacks, TOCTOU, and Handle Impersonation

Executives often overlook race-condition-based privilege escalations because they operate in microsecond timeframes—but attackers exploit these with surgical precision.

### What’s a TOCTOU?

Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities happen when a file is validated (check), but then altered or replaced before it is accessed or executed (use). Common when services trust paths or open files with elevated permissions.

- CVE-2022-21907: Windows HTTP.sys Remote Code Execution abused a TOCTOU in request validation.
- CWE-367: TOCTOU Race Condition

### Handle Impersonation

Advanced Windows privilege abuse involves duplicating or hijacking open handles from SYSTEM processes, especially via `SeImpersonatePrivilege`.

- MITRE T1134.001: Token Impersonation/Theft
- Techniques like **PrintSpoofer**, **Juicy Potato**, and **RoguePotato** exploit these mechanics.

### Symlink Abuse

- T1055.003: DLL Side-Loading using symbolic links or junctions.
- Attacker drops symlink to SYSTEM path (`C:\Windows\Temp → C:\Program Files\SomeService`)
- Vulnerable services will follow the link and write as SYSTEM.

### Defense:

- Disable vulnerable privileges unless absolutely required (NIST AC-6(9)).
- Monitor for named pipe creation and impersonation attempts using Sysmon Event ID 17 and 18.
- Block common TOCTOU race vectors using EDR rules and Temp path auditing.
- Apply file integrity monitoring (FIM) to critical execution paths.

---

## 5. Vendor Build / Break / Test

Most enterprise breaches now stem from one of two sources: weak identity boundaries or **vendor-integrated software**. Attackers don’t need zero-days when third-party tools ship with SYSTEM-level services and unverified update mechanisms.

### Key Problem: Trust-by-Default

Most orgs **assume vendor software is secure** because it’s signed, or it's from a “top-tier” provider. That assumption is fatal. Vendors operate on shipping timelines, not adversarial threat models.

- **MITRE T1195.002** – Compromise Software Supply Chain
- **CWE-829** – Inclusion of Functionality from Untrusted Control Sphere
- **NIST SA-12** – Supply Chain Protection

### Red Team Reality

You’ve likely seen it: a vendor MSI installs a service that:

- Runs as SYSTEM
- Starts on boot
- Exposes a REST API with no TLS
- Accepts unvalidated input

That’s not hypothetical—that's **post-exploitation gold**. You reverse the binary, track its processes, handles, dlls, and next thing you know you're writing files as SYSTEM.

### Testing Guidance

To assess vendor builds, don’t just “install and observe.” Break it. Here’s how:

1. **Install in a sandboxed lab** (Airgapped Windows VM).
2. **Run Procmon + Sysmon* + TCPView*: watch for file drops, service installs, registry keys, scheduled tasks, callbacks.
3. **Check digital signatures** with `sigcheck -q -m`. Anything unsigned gets analyzed.
4. **Decompile .NET binaries** using dnSpy, check for hardcoded credentials (CWE-798).
5. **Fuzz local APIs** and look for crashable input or privilege escalation vectors (CVE-2023-27524 – Apache Superset RCE from exposed API key).

### Executive Translation

Every vendor is a potential backdoor. If their code runs as SYSTEM and it’s not validated, you’ve just handed them domain control.

- Create policy: **No external software is installed without sandbox analysis and documented hardening.**
- Block all vendor traffic until explicit firewall allowlisting is in place.
- Don’t let “signed = safe” fool you. **Signed malware exists.** Use **code reputation scoring** and behavior analysis.

---

## 6. Privilege Escalation Defense

Post-compromise, **local privilege escalation** is often the first thing a threat actor attempts. And most environments help them succeed.

- **MITRE T1068** – Exploitation for Privilege Escalation
- **CWE-269** – Improper Privilege Management
- **NIST SI-2, CM-7** – Flaw Remediation & Least Functionality

### Common LPE Scenarios:

- **Writable Service Binary** (T1543.003): Replace a service binary and restart the service.
- **SUID Misconfiguration** (Linux): `/usr/bin/screen` with SUID → Root shell.
- **Cron PATH Abuse**: A script runs from `cron` with insecure `PATH` → write a malicious binary to `/tmp`.

### Real CVEs Used in Field:

- **CVE-2021-4034 (PwnKit)** – Polkit local root on Linux
- **CVE-2021-34484** – Windows User Profile Service privilege escalation via symlink attack
- **CVE-2022-0847 (Dirty Pipe)** – Write arbitrary files as root on Linux

### Mitigations

- Disable unnecessary SUID binaries. Use `find / -perm -4000 -type f` to audit.
- Monitor file permissions and `sticky bits`. Validate all system folders are non-writable.
- Use EDR rules to catch privilege elevation behavior:
  - `SetTokenInformation`
  - `CreateProcessAsUser`
  - Parent process spoofing (cmd → explorer)

### Executive Notes

Priv-esc is not exotic. It’s usually **a writable path, a lazy cron job, or a bad default**.

- **Scan endpoints regularly** with tools like `LinPEAS`, `WinPEAS`, and `Watson`.
- **Ensure devs and ops teams** don’t hardcode sudo rules or leave SUIDs after testing.
- Harden with OS-level policies, not just EDR. Attackers live off the land.

---

## 7. MITRE Defense Map & Final Recommendations

Most organizations misunderstand MITRE ATT&CK. It’s not just an attacker dictionary—it’s **your defense map**.

- Map observed IOCs and TTPs to MITRE phases: Initial Access → Execution → Persistence → Priv-Esc → Defense Evasion → Exfiltration.
- Use **MITRE Shield** to identify how to engage attackers (e.g., `honeypots`, `credential monitoring`, `user deception`).

### Key TTPs to Monitor:

| Phase | TTP | Description |
|-------|-----|-------------|
| Initial Access | T1190 | Exploit public-facing app |
| Persistence | T1547.001 | Registry Run Keys |
| Priv-Esc | T1068 | Exploiting local vulnerability |
| Lateral Movement | T1021.002 | SMB/Remote Service Abuse |
| Defense Evasion | T1140 | Deobfuscate/Decode Files |

### NIST Alignment

Use **NIST CSF** for reporting posture in business terms:

- **ID.RA-1**: Asset and risk visibility
- **PR.AC-1**: Identity managed
- **DE.CM-7**: Continuous monitoring
- **RS.RP-1**: Incident Response Preparedness

### Final Recommendations

- Prioritize **exposure, not CVSS**. Map vulnerabilities to how attackers actually move.
- **Patch based on reachability and attack chain placement**, not just score.
- **Simulate attacks internally**. Red teams don’t just break—they teach.
- **Make vendors prove their software is secure**. No trust without validation.
- **Sandbox everything** and deploy layered monitoring—from host, to user, to network.


---


“These approaches are proven in practice. If it secures the enterprise without added spend, it earns its place in our strategy.”*
– 0xBrianSec



