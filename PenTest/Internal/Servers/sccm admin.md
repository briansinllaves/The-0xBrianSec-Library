**Pentest Note: Abusing SCCM (System Center Configuration Manager)**

---

### Tools for Abusing SCCM

1. **CMPivot**

   CMPivot is a tool used within SCCM to quickly gather data and insights from devices in a collection. It allows you to execute queries and retrieve information in real-time.

   ```plaintext
   # Usage example of CMPivot
   sprokect.exe /query:<query>
   ```

2. **PowerSCCM**

   PowerSCCM is a PowerShell module that provides various cmdlets for interacting with SCCM. It can be used to automate tasks, gather information, and manipulate SCCM configurations.

   ```powershell
   # Import the PowerSCCM module
   Import-Module PowerSCCM

   # Example cmdlet to get SCCM site information
   Get-SCCMSite
   ```

3. **SharpSCCM**

   SharpSCCM is a C# tool used to interact with SCCM. It can be used to enumerate SCCM environments, gather information, and perform various actions within SCCM.

   ```plaintext
   # Usage example of SharpSCCM
   SharpSCCM.exe <action> [options]
   ```

### Example Commands

#### CMPivot

- **Query for Logged-in Users:**
  ```plaintext
  sprokect.exe /query:LoggedOnUser
  ```

- **Query for Installed Software:**
  ```plaintext
  sprokect.exe /query:InstalledSoftware
  ```

#### PowerSCCM

- **List SCCM Clients:**
  ```powershell
  Get-SCCMClient
  ```

- **Deploy an Application:**
  ```powershell
  New-SCCMDeployment -Applicationne "ExampleApp" -CollectionID "ExampleCollection"
  ```

#### SharpSCCM

- **Enumerate SCCM Applications:**
  ```plaintext
  SharpSCCM.exe enum_apps
  ```

- **Deploy a Task Sequence:**
  ```plaintext
  SharpSCCM.exe deploy_task_sequence -ne "ExampleTaskSequence" -collection "ExampleCollection"
  ```

### Summary

Abusing SCCM can provide an attacker with significant control over an enterprise network. The tools mentioned—CMPivot, PowerSCCM, and SharpSCCM—offer different ways to interact with and exploit SCCM environments. Always ensure your activities are authorized and comply with legal and ethical guidelines.