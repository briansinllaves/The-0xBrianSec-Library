#### **Python Script for Generating NTLM Hashes**

```python
import hashlib
import binascii

def inputs():
    print("-----------------------")
    s = input("Enter input: ")
    print("Input:", s)

    # Generate NTLM hash
    hash = hashlib.new('md4', s.encode('utf-16le')).digest()
    print("NTLM hash:")
    print(binascii.hexlify(hash).decode())
    
    inputs()

inputs()
```
#### **Use Cases in a Pentest:**
- **Pass-the-Hash (PtH) Attacks:**
  - If you have a plaintext password but need the NTLM hash to use in a PtH attack, this script can generate it quickly.
- **Password Cracking:**
  - You can use this script to generate NTLM hashes of common passwords, which can be used to compare against hashes captured during the penetration test.
- **Hash Verification:**
  - When you capture an NTLM hash, you can use this script to generate a hash from a suspected plaintext password and verify if it matches the captured hash.