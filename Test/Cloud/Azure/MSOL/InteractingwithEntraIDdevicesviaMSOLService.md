This note serves as a concise guide for using the MSOL service to connect to Azure AD and retrieve critical information about user-associated devices.

### **Connecting to EntraID with MSOL**

- **Command:**
  ```powershell
  Connect-MsolService
  ```
  - **Use Case:** Establishes a secure session with Azure AD, enabling you to execute administrative tasks and access Azure AD resources.

---

### **Querying Device Information for a Specific User**

- **Command:**
  ```powershell
  Get-MsolDevice -RegisteredOwnerUpn edward.e@ABCD.com | ft Displayne,Enabled,DeviceTrustLevel,DeviceTrustType,DeviceOsType,DeviceOsVersion,ApproximateLastLogonTimestamp
  ```
  - **Use Case:** Retrieves detailed information about devices associated with a specific user's UPN (User Principal ne). The output includes:
    - **Displayne:** ne of the device.
    - **Enabled:** Whether the device is active.
    - **DeviceTrustLevel:** Trust level of the device.
    - **DeviceTrustType:** Type of trust established with the device.
    - **DeviceOsType:** Operating system type.
    - **DeviceOsVersion:** Version of the operating system.
    - **ApproximateLastLogonTimestamp:** Last logon time.

---

