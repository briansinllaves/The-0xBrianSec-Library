Rundll32 can execute a JavaScript or VBScript file via Windows' **script execution** functionality by calling the `vbscript.dll` or `jscript.dll` directly

```
rundll32.exe vbscript.dll,RunScript "path\to\script.vbs"
```

a malicious `.vbs` file might:

- **Download and execute malware** from a remote server.
- **Run system commands** like adding new users or modifying registry keys.
