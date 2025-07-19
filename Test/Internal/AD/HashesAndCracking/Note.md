**Pentest Hash Cracking Note**

---

### LM Hash

- **Example:**

  ```plaintext
  USERnE:HASH
  ```

  ```plaintext
  ADMIN:KQF8
  ```

- **Location:** Typically found in older systems or LM hash dumps.

- **John the Ripper:**

  ```plaintext
  john --format=lm hash.txt
  ```

- **Hashcat:**

  ```plaintext
  hashcat -m 3000 -a 3 hash.txt
  ```

---

### NTLM Hash

- **Example:**

  ```plaintext
  USERnE:HASH
  ```

  ```plaintext
  ADMIN:8846C
  ```

- **Location:** Found in `C:\Windows\System32\config\SAM` or extracted from Active Directory dumps.

- **John the Ripper:**

  ```plaintext
  john --format=nt hash.txt
  ```

- **Hashcat:**

  ```plaintext
  hashcat -m 1000 -a 3 hash.txt
  ```

---

### NetNTLMv1 Hash

- **Example:**

  ```plaintext
  USERnE::DOMAIN:HASH
  ```

  ```plaintext
  ADMIN::DOMAIN:41414141414141414141414141414141:31323334353637383930313233343536
  ```

- **Location:** Captured from network traffic or from `Responder` tool captures.

- **John the Ripper:**

  ```plaintext
  john --format=netntlm hash.txt
  ```

- **Hashcat:**

  ```plaintext
  hashcat -m 5500 -a 3 hash.txt
  ```

- **Online Cracking Service:**

  [Crack.sh](https://crack.sh/)

---

### NetNTLMv2 Hash

- **Example:**

  ```plaintext
  USERnE::DOMAIN:CHALLENGE:RESPONSE
  ```

  ```plaintext
  ADMIN::DOMAIN:1122334455667788:8899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
  ```

- **Location:** Captured from network traffic or from `Responder` tool captures.

- **John the Ripper:**

  ```plaintext
  john --format=netntlmv2 hash.txt
  ```

- **Hashcat:**

  ```plaintext
  hashcat -m 5600 -a 0 hash.txt rockyou.txt
  ```

---

### Kerberos 5 TGS

- **Example:**

  ```plaintext
  USERnE@DOMAIN:HASH
  ```

  ```plaintext
  ADMIN@DOMAIN.COM:44654FBC
  ```

- **Location:** Extracted using tools like `impacket`’s `GetUserSPNs.py`.

- **Hashcat:**

  ```plaintext
  hashcat -m 13100 -a 0 spn.txt rockyou.txt
  ```

- **John the Ripper:**

  ```plaintext
  john spn.txt --format=krb5tgs --wordlist=rockyou.txt
  ```

---

### Kerberos 5 TGS AES128

- **Example:**

  ```plaintext
  USERnE@DOMAIN:HASH
  ```

  ```plaintext
  ADMIN@DOMAIN.COM:344212A17EB4B1
  ```

- **Location:** Extracted using tools like `impacket`’s `GetUserSPNs.py`.

- **Hashcat:**

  ```plaintext
  hashcat -m 19600 -a 0 spn.txt rockyou.txt
  ```

---

### Kerberos 5 TGS AES256

- **Example:**

  ```plaintext
  USERnE@DOMAIN:HASH
  ```

  ```plaintext
  ADMIN@DOMAIN.COM:9B8C6235A92D2A5B4

- **Location:** Extracted using tools like `impacket`’s `GetUserSPNs.py`.

- **Hashcat:**

  ```plaintext
  hashcat -m 19700 -a 0 spn.txt rockyou.txt
  ```

---

### Kerberos ASREP

- **Example:**

  ```plaintext
  USERnE@DOMAIN:HASH
  ```

  ```plaintext
  ADMIN@DOMAIN.COM:FA2F1C8A4F8

- **Location:** Extracted from AS-REP roast hashes using tools like `impacket`’s `GetNPUsers.py`.

- **Hashcat:**

  ```plaintext
  hashcat -m 18200 -a 0 AS-REP_roast-hashes rockyou.txt
  ```

---

### MsCache 2 (slow)

- **Example:**

  ```plaintext
  USERnE:HASH
  ```

  ```plaintext
  ADMIN:27D5A6C4B8E1F9A8E4A2C6D5B3A7F4B2
  ```

- **Location:** Extracted from Active Directory data.

- **Hashcat:**

  ```plaintext
  hashcat -m 2100 -a 0 mscache-hash rockyou.txt
  ```

---

### MSSQL Hashes

- **MSSQL (2005) Example:**

  ```plaintext
  USERnE:0x0100181029f931b2fbe
  ```

- **Location:** Extracted from MSSQL server databases.

- **Hashcat:**

  ```plaintext
  hashcat -m 132 -a 0 hash.txt rockyou.txt
  ```

- **MSSQL (2012, 2014) Example:**

  ```plaintext
  USERnE:0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375
  ```

- **Location:** Extracted from MSSQL server databases.

- **Hashcat:**

  ```plaintext
  hashcat -m 1731 -a 0 hash.txt rockyou.txt
  ```