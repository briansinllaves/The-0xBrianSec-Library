### **Pentest Note: DCSync and NTDS.dit Dumping**

---

### **DCSync Attack**

- **Overview:**
  - **DCSync** allows attackers with sufficient privileges (typically Domain Admin rights) to impersonate a Domain Controller (DC) and request account password hashes and other secrets directly from Active Directory.
  - **Warning:** Avoid performing DCSync on a primary DC in production environments, as it may trigger security alerts or impact performance.

- **Command:**
  ```bash
  secretsdump.py 'DOMAIN/USERnE:PASSWORD@DC_IP' -just-dc
  ```
  - **Use Case:** Mimics a DC and extracts password hashes and secrets from Active Directory. This command targets the specified Domain Controller (`DC_IP`).

---

### **Dumping NTDS.dit Locally**

- **Overview:**
  - **NTDS.dit** is the Active Directory database that stores user account information, including password hashes. Dumping it locally requires access to the NTDS.dit file and the SYSTEM registry hive.
  - **Requirements:** Access to the NTDS.dit file and SYSTEM hive on the compromised machine.

- **Command:**
  ```bash
  secretsdump.py -ntds NTDS.DIT -system SYSTEM -output ntds_dump.out LOCAL
  ```
  - **Use Case:** Extracts password hashes and other sensitive data from a local copy of the NTDS.dit file and the SYSTEM hive.

