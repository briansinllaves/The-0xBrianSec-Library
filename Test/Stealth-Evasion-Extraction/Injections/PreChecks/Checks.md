**Prechecks**:

- **Architecture compatibility** (32-bit vs. 64-bit).
- **Sufficient memory availability** in the target process.
- **Valid memory permissions** (writable and executable).
- **Check for security software** that might block injections.

Shellcode Prechecks
**Prechecks**:

- **No null bytes** in the shellcode (unless required).
- **Correct architecture** (32-bit or 64-bit).
- **Size of shellcode** fits allocated memory.
