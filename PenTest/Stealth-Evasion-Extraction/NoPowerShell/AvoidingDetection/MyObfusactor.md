```python
import base64
import random
import re

def obfuscate_string_encoding(code):
    """Obfuscates strings in the code using Base64 encoding."""
    pattern = r'["\'](.*?)["\']'
    encoded_code = re.sub(pattern, lambda match: f'base64.b64decode("{base64.b64encode(match.group(1).encode()).decode()}").decode()', code)
    return f'import base64\n{encoded_code}'

def obfuscate_variable_rening(code):
    """Renes variables to random nes."""
    variables = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', code)
    rened_vars = {var: f"var_{random.randint(1000, 9999)}" for var in variables if not re.match(r'(print|import|base64|def|return|if|else|for|while)', var)}
    for old_var, new_var in rened_vars.items():
        code = re.sub(rf'\b{old_var}\b', new_var, code)
    return code

def obfuscate_control_flow(code):
    """Adds unnecessary conditionals to confuse code flow."""
    obfuscated_code = []
    for line in code.splitlines():
        obfuscated_code.append(f'if True:\n    {line}')
    return "\n".join(obfuscated_code)

def obfuscate_string_concatenation(code):
    """Breaks strings into smaller parts and concatenates them."""
    pattern = r'["\'](.*?)["\']'
    concatenated_code = re.sub(pattern, lambda match: ' + '.join([f'"{c}"' for c in match.group(1)]), code)
    return concatenated_code

def obfuscate_unicode(code):
    """Converts strings to Unicode escape sequences."""
    pattern = r'["\'](.*?)["\']'
    unicode_code = re.sub(pattern, lambda match: ''.join([f'\\u{ord(c):04x}' for c in match.group(1)]), code)
    return unicode_code

def obfuscate_inline_decryption(code):
    """Simulates encrypting code and decrypting it at runtime (using XOR)."""
    obfuscated_code = []
    for line in code.splitlines():
        encrypted = [ord(c) ^ 42 for c in line]
        decrypt_code = f"exec(''.join([chr(c ^ 42) for c in {encrypted}]))"
        obfuscated_code.append(decrypt_code)
    return "\n".join(obfuscated_code)

def obfuscate_with_tool(code):
    """Simulates using an external tool by adding noise to the code."""
    noise = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10))
    return f"# Obfuscated by tool\n{noise}\n{code}\n{noise}"

def obfuscate_code(code):
    """Applies all obfuscation techniques."""
    code = obfuscate_string_encoding(code)
    code = obfuscate_variable_rening(code)
    code = obfuscate_control_flow(code)
    code = obfuscate_string_concatenation(code)
    code = obfuscate_unicode(code)
    code = obfuscate_inline_decryption(code)
    code = obfuscate_with_tool(code)
    return code

# Input source code
source_code = input("Enter the code you want to obfuscate:\n")

# Obfuscate the code
obfuscated_code = obfuscate_code(source_code)

# Output the obfuscated code
print("\nObfuscated Code:\n")
print(obfuscated_code)

```