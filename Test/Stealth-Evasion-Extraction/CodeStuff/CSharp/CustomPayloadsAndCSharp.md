Compile your payload (e.g., SharpHound, Mimikatz) into a C# executable or convert it to shellcode.

- **C# Inline Loader:** This method involves compiling shellcode into a C# project, which can then be executed as a standalone binary.

- **Donut:** This tool converts PE, EXE, or .NET binaries into shellcode. You can inject the resulting shellcode into memory using a C# application.

**Direct Memory Execution:**

**Syscalls:** Write or use C# tools that rely on syscalls for process injection or DLL injection to load Mimikatz or SharpHound into memory.

**Reflective DLL Injection:** Use tools like `ReflectiveLoader` or `Covenant's Grunt` to inject payloads into memory.

- **Obfuscation/Custom Compilation:**
    
    - **Recompile Mimikatz:** Get the Mimikatz source code and modify it slightly (e.g., change function nes or structure) to evade EDR detection signatures.
    - **PE Patching/Obfuscation:** Use tools like `Chimera`, `Veil`, or `Obsidian` to obfuscate or patch the compiled Mimikatz executable. This can help evade simple EDR detections.
    
- **Mimikatz Execution via Memory Injection:**
    
    - **Run Mimikatz as Shellcode:** Convert Mimikatz into shellcode using tools like `Donut` or `sRDI` (Shellcode Reflective DLL Injection). Once converted to shellcode, you can inject it into a process using a custom C# injector.
    
    - **sRDI (Shellcode Reflective DLL Injection):** This tool can convert a Mimikatz DLL into shellcode and inject it directly into memory. You can load the shellcode using a custom loader without writing anything to disk.