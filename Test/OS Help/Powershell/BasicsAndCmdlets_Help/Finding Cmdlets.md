```

### **Finding Cmdlets**

#### **List All Available Cmdlets**
To get a list of all available cmdlets:
```powershell
PS C:\> Get-Command
```

#### **Filter Cmdlets by Verb**
To filter cmdlets based on a specific verb:
```powershell
PS C:\> Get-Command Set* 
```
Or use the `-Verb` parameter:
```powershell
PS C:\> Get-Command -Verb Set
```

#### **Filter Cmdlets by Noun**
To filter cmdlets based on a specific noun:
```powershell
PS C:\> Get-Command *Process
```
Or use the `-Noun` parameter:
```powershell
PS C:\> Get-Command -Noun Process
```
```