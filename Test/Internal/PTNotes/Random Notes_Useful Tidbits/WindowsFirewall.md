### **1. Check the Status of Windows Firewall**

To check whether the Windows Firewall is enabled or disabled:

```powershell
Get-NetFirewallProfile
```

This command shows the firewall status for the different profiles (Domain, Private, Public):

- **Enabled:** `True` means the firewall is enabled.
- **Disabled:** `False` means the firewall is disabled.

### **2. Check Specific Firewall Rules**

To list all active firewall rules:

```powershell
Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" }
```

This command lists all the firewall rules that are currently enabled.

### **3. Check Rules for a Specific Port**

If you want to check if a specific port is allowed or blocked:

```powershell
Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Profile -eq "Any" } | Get-NetFirewallPortFilter | Where-Object { $_.Protocol -eq "TCP" -and $_.LocalPort -eq "<Your_Port_Number>" }
```

Replace `<Your_Port_Number>` with the port you want to check.

### **4. Check Inbound and Outbound Rules Separately**

- **Check Inbound Rules:**

  ```powershell
  Get-NetFirewallRule -Direction Inbound | Where-Object { $_.Enabled -eq "True" }
  ```

- **Check Outbound Rules:**

  ```powershell
  Get-NetFirewallRule -Direction Outbound | Where-Object { $_.Enabled -eq "True" }
  ```

### **5. Check Specific Application Rules**

To see if a specific application is allowed or blocked:

```powershell
Get-NetFirewallRule | Where-Object { $_.Displayne -like "*<Application_ne>*" }
```

Replace `<Application_ne>` with the ne of the application you want to check.

### **6. Check Firewall Status for a Specific Profile**

If you want to check the firewall status for a specific profile (e.g., Domain, Private, Public):

```powershell
Get-NetFirewallProfile -Profile Domain
```

Replace `Domain` with `Private` or `Public` depending on the profile you want to check.

### **7. View Detailed Information About a Specific Rule**

If you have a specific rule ne and want detailed information about it:

```powershell
Get-NetFirewallRule -ne "<Rule_ne>"
```

Replace `<Rule_ne>` with the ne of the rule.
