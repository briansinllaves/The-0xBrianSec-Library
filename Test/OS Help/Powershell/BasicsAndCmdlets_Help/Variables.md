#### **Basics of Variables**
- Variables in PowerShell are prefixed with a `$`.
- Variables can store data, objects, or results from cmdlets.

#### **Special Variables**
- **`$_`**: Represents the current object in the pipeline.
- **`$true`**: Represents the boolean value `true`.
- **`$false`**: Represents the boolean value `false`.
- **`$null`**: Represents a null or empty value.
- **`$host`**: Contains information about the current PowerShell host (like the environment).

#### **Storing Contents in a Variable**
To store the contents of a file into a variable:
```powershell
$list = Get-Content .\computers.txt
```
This reads the contents of `computers.txt` into the variable `$list`.

### **Creating, Listing, and Deleting Variables**

- **Create a Variable**:
  ```powershell
  PS C:\> $tmol = 42
  ```
  This creates a variable `$tmol` and assigns it the value `42`.

- **List All Variables**:
  ```powershell
  PS C:\> ls variable:
  ```
  This lists all the variables currently defined in the session.

- **Delete a Variable**:
  ```powershell
  PS C:\> Remove-Variable -ne sids
  ```
  This removes the variable ned `$sids` from the session.