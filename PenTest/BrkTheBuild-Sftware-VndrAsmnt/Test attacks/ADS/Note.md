### **Alternate Data Streams (ADS) in Penetration Testing**

Alternate Data Streams (ADS) are a feature of the NTFS file system that allow multiple data streams to be associated with a single file. Originally designed for compatibility with macOS, ADS can be leveraged to hide malicious payloads, evade detection, and establish persistence during penetration tests. Understanding how to detect, exploit, and defend against ADS is crucial for effective pentesting.

### **Understanding Alternate Data Streams (ADS)**

- **Multiple Streams, One ne:**  
  - A file on an NTFS partition can have a default data stream (the visible content) and one or more hidden alternate data streams. These streams don't alter the visible size of the file and are not shown in standard file explorers.

- **Hidden Data Storage:**  
  - ADS can store additional data that is invisible to standard user operations. This hidden data might be anything from additional information to malicious code. While not secure, ADS can be an effective way to conceal payloads or exfiltrate data.

- **Not a Symlink:**  
  - Unlike symlinks, which point to another file or directory, ADS are part of the file itself. They store actual data alongside the primary stream, which makes them useful for both legitimate purposes (like storing metadata) and for malicious activities.

- **Side-Chain Data:**  
  - ADS can be thought of as side-chained data streams that exist alongside the main file content. They can only be accessed if you know the stream's ne and specifically request it, making them useful for stealthy operations.

### **Tools to Detect and Analyze ADS**

1. **Sysinternals Streams:**  
   - A command-line tool by Sysinternals (Microsoft) that scans directories for files with ADS and lists them.
   - Usage: 
     ```bash
     streams -s C:\path\to\directory
     ```

2. **PowerShell:**  
   - PowerShell can be used to identify files with ADS by using the `Get-Item` and `Get-Content` cmdlets.
   - Usage:
     ```powershell
     Get-Item -Path C:\path\to\file -Stream *
     ```

3. **ADS Spy:**  
   - A GUI tool that scans for and allows you to manage ADS on your system.

4. **Forensic Tools:**  
   - Tools like EnCase or FTK Imager can be used during forensic investigations to detect ADS in files.

### **Identifying and Exploiting Vulnerable ADS**

- **What Does Vulnerable ADS Look Like?**
  - Files with unexpected or unexplained alternate data streams can be indicators of malicious activity.
  - Vulnerable ADS might contain:
    - Executable code or scripts that can be executed by referencing the ADS.
    - Hidden configuration files or command-and-control instructions.
    - Sensitive information such as passwords or cryptographic keys hidden in plain sight.

- **Exploitation of ADS:**
  - **Persistence:**  
    - Embed a malicious script or executable in ADS and configure a legitimate process to execute it. This method can help maintain persistence on a compromised system.
    - Example:
      ```bash
      echo "malicious code" > legitimatefile.txt:hiddenstream
      ```

  - **Command Execution:**
    - Use the hidden ADS to store a payload that can be executed without altering the visible file.
    - Example:
      ```bash
      notepad.exe legitimatefile.txt:hiddenstream
      ```

  - **Evasion:**  
    - Store sensitive or malicious files in ADS to evade detection by antivirus or file integrity monitoring tools that don’t check for ADS.
    - Example:
      ```bash
      type malicious.exe > file.txt:malicious.exe
      ```

### **Attacking with ADS: Strategies and Tactics**

- **Setting Up an Attack Using ADS:**
  - **Payload Concealment:** Store a malicious executable in an ADS, attach it to an inconspicuous file, and trigger execution via another process or scheduled task.
  - **Stealth Data Exfiltration:** Hide stolen data in ADS before exfiltrating it, making detection harder for standard file monitoring tools.

- **Evading Detection:**
  - **Avoidance:** During a pentest, using ADS can help avoid detection by security products that do not inspect alternate data streams. This includes hiding payloads within seemingly harmless files.
  - **Camouflage:** Use ADS to blend malicious activity with legitimate files and processes, making it harder for security teams to distinguish between normal and abnormal activity.

### **Exploiting ADS in Attack Chains**

- **Attack Chain Example 1: Persistence with ADS**
  1. **Step 1:** Compromise a system and gain initial access.
  2. **Step 2:** Create a hidden payload within an ADS.
     ```bash
     echo "malicious script" > C:\Windows\System32\svchost.exe:hidden
     ```
  3. **Step 3:** Configure a scheduled task or registry key to execute the hidden stream.
     ```bash
     schtasks /create /tn "System Maintenance" /tr "C:\Windows\System32\svchost.exe:hidden" /sc onstart
     ```
  4. **Step 4:** Ensure persistence through reboots and avoid detection.

- **Attack Chain Example 2: Data Exfiltration**
  1. **Step 1:** Gain access to sensitive data.
  2. **Step 2:** Store the data in an ADS attached to a commonly used file.
     ```bash
     type secretdata.txt > C:\Users\Public\documents\report.doc:secretdata
     ```
  3. **Step 3:** Transfer the file to an external server, bypassing standard data loss prevention tools.
  4. **Step 4:** Extract the hidden data from the ADS on the attacker’s system.

### **Quick note for the next sections**
 **System Configuration:**
  - The success of exploiting Alternate Data Streams (ADS) for privilege escalation (priv esc) or remote code execution (RCE) heavily depends on the system's specific configuration. Critical factors include which processes interact with ADS and how file execution is managed. Some systems might unknowingly allow execution from ADS, while others might be more locked down, limiting the attack surface.
  - 
### **Privilege Escalation with ADS**

**1. Exploiting ADS for Privilege Escalation:**

- **Scenario:** You have access to a low-privilege account and can write to a file or directory that is used by a higher-privileged process.
  
- **Attack Vector:** 
  - **Abusing Scheduled Tasks or Services:**
    - If a scheduled task or service running under higher privileges references a file that you can modify, you can embed malicious code in an ADS associated with that file.
    - For instance, if the service or scheduled task reads a configuration file or executes a script, you can add your payload to an ADS of that file.

  - **Example:**
    ```bash
    echo "malicious command" > C:\path\to\file.txt:hiddenstream
    ```
    - Now, if a service running as SYSTEM or Administrator executes `file.txt`, you might be able to escalate privileges if the service mistakenly executes or reads from the ADS.

**2. Hijacking DLLs via ADS:**

- **Scenario:** A legitimate executable or service loads a DLL that you can control.
  
- **Attack Vector:** 
  - **DLL Hijacking via ADS:**
    - You can place a malicious DLL inside an ADS of a legitimate file. When the high-privilege process loads the file, it could potentially load your malicious DLL from the ADS, leading to privilege escalation.

  - **Example:**
    ```bash
    type malicious.dll > C:\path\to\legitimate.exe:malicious.dll
    ```
    - If the executable `legitimate.exe` is designed or tricked into loading the DLL from the ADS, it would execute with the privileges of the calling process.

### **Remote Code Execution (RCE) with ADS**

**1. RCE via File Upload Vulnerabilities:**

- **Scenario:** You have identified a file upload vulnerability on a web server that stores uploaded files on an NTFS file system.
  
- **Attack Vector:**
  - **Hiding Malicious Code in ADS:**
    - Upload a seemingly harmless file and then hide a malicious payload in an ADS attached to that file. This is effective if the application or server subsequently executes or interacts with the ADS.

  - **Example:**
    ```bash
    echo "malicious script" > innocent.jpg:exploit
    ```
    - If you can trigger the server to execute the script in the ADS, you could achieve RCE.

**2. Triggering RCE via Command Injection:**

- **Scenario:** You find a command injection vulnerability in a web application or service running on an NTFS file system.
  
- **Attack Vector:**
  - **Injecting Commands to Execute ADS Payload:**
    - Inject a command that writes malicious code to an ADS and then triggers its execution. This could be used to bypass certain filters or evade detection.

  - **Example:**
    ```bash
    cmd /c "echo malicious code > C:\path\to\file.txt:hiddenstream"
    cmd /c "start C:\path\to\file.txt:hiddenstream"
    ```
    - If the application is vulnerable to command injection, this could be used to execute arbitrary code hidden in the ADS.

### **Practical Considerations and Defenses Against ADS Exploitation**

#### **Challenges:**
- **Detection:**
  - ADS-based attacks can remain undetected if security tools are not configured to scan for them. By default, many antivirus and file integrity monitoring tools do not check for ADS, making these streams a stealthy method for attackers to hide malicious content. However, when properly configured, security tools can identify the presence of ADS and flag them for further investigation.

#### **Defensive Measures:**

- **Regular Scanning for ADS:**
  - Regularly scan your systems, especially critical directories, for the presence of ADS. Tools such as Sysinternals Streams and PowerShell scripts can be employed to detect unauthorized data streams. This proactive measure helps identify any hidden data or malicious payloads before they can be leveraged by an attacker.
  
- **Monitor High-Privilege Processes:**
  - Pay close attention to high-privilege processes and their interactions with files that might contain ADS. Unusual behavior, such as unexpected file access or execution from ADS, can be an indicator of malicious activity. Monitoring these processes closely can help prevent privilege escalation attempts.

- **System Hardening:**
  - Limit or restrict the use of ADS, particularly in directories accessed by high-privilege processes. By configuring systems to minimize the potential for ADS exploitation, you reduce the attack surface. This can include disabling the ability to create ADS in sensitive areas or implementing stricter access controls.

- **Policy Enforcement:**
  - Enforce strict file and process policies that prevent or restrict the execution of files containing ADS. This might involve setting group policies that deny execution from ADS or employing application whitelisting to ensure only approved software runs. By controlling what can execute within your environment, you can prevent ADS from being used as a vector for attacks.

- **Security Monitoring Integration:**
  - Integrate ADS detection into your broader security monitoring strategy. Ensure that your security information and event management (SIEM) systems, as well as endpoint detection and response (EDR) tools, are configured to monitor and alert on the creation and usage of ADS. Any unexpected or unauthorized streams should be flagged for immediate investigation, helping to catch potential attacks in their early stages.
