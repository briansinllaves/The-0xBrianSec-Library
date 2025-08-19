# YARA & Malware Evasion Reference

## 1. YARA Framework & Tools

- **yara** – Command-line tool to scan files, processes, and memory.
- **yarac** – Compiles `.yar` rules into binary format for faster scanning.
- **yara-python** – Python bindings for integrating YARA with scripts.

## 2. Binary & Malware Analysis

- **PEStudio** – Extracts indicators from PE files, shows matched YARA rules.
- **Detect-It-Easy (DIE)** – Identifies packers/obfuscation, integrates YARA.
- **PE-Sieve & HollowsHunter** – Detect process injection, often used with YARA.
- **Capa (by FireEye/Mandiant)** – Identifies malware capabilities, supports YARA scanning.

## 3. Threat Hunting & Reverse Engineering

- **ThreatCheck** – Checks if a file triggers Defender/EDR without submitting it.
- **CyberChef** – Decodes, deobfuscates, and modifies malware for YARA evasion.
- **Strings2** – Extracts meaningful strings for crafting YARA rules.

## 4. Memory & Process Analysis

- **Volatility** – Scans memory dumps with YARA rules to detect malware.
- **Rekall** – Alternative memory forensics tool supporting YARA scanning.

---

## How to Use YARA on FLARE-VM

- **Scan a file:**
    ```sh
    yara myrules.yar malware.exe
    ```
- **Scan a running process:**
    ```sh
    yara -p 1234 myrules.yar
    ```
- **Compile rules for performance:**
    ```sh
    yarac myrules.yar compiled_rules.yarc
    ```

---

## Evasion: Avoiding YARA & AV Detection

### 1. Avoid Static Signatures

- **Break YARA string detections:**
    - Encrypt, obfuscate, or XOR all hardcoded strings.
    - Store function names, URLs, or key strings in runtime-generated variables.
    - Use base64, ROT13, or custom encoding, then decrypt in memory.

### 2. Evade Behavior-Based Detection

- **No direct API calls:**
    - Avoid obvious APIs (e.g., VirtualAlloc, WriteProcessMemory, CreateRemoteThread).
    - Use direct syscalls instead of API functions.
    - Unhook your code from AV/EDR (e.g., patch NtProtectVirtualMemory).
- **Indirect execution:**
    - Reflective DLL injection, NtMapViewOfSection, process hollowing.
    - Use callback-based execution (APC, EnumWindows, NtQueueApcThread).
    - Threadless execution (NtSetContextThread + NtResumeThread).

### 3. Modify Execution Flow

- **Self-modifying code:**
    - Encode your payload and decrypt at runtime.
    - Use JIT shellcode compilation (e.g., Donut-generated shellcode).
    - Resolve functions at runtime via GetProcAddress/hashing.
- **Break pattern-based detection:**
    - Insert dead code (NOPs, junk instructions, opaque predicates).
    - Randomize instruction order or use MOV chains to hide intent.

### 4. Test in Your Lab

- **Check YARA detection locally:**
    ```sh
    yara -r myrules.yar mypayload.exe
    ```
- **Scan with ClamAV/FLARE tools:**
    ```sh
    clamscan --database=mydb mypayload.exe
    ```
- **Use PEStudio, Process Monitor, and API Monitor to detect flagged behaviors.**

### 5. Advanced Techniques

- **Direct syscalls / Unhooking:**
    - Manually resolve and execute syscalls instead of normal API calls.
    - Patch EDR hooks using NtProtectVirtualMemory.
- **Hardware Breakpoints:**
    - Store payloads in DRx registers to avoid memory scans.

---

## Want help writing YARA rules or testing evasions?
- Practice in a controlled lab environment.
- Use open-source malware and YARA rule repositories for testing.
- Continuously update your evasion techniques as detection improves.

---
