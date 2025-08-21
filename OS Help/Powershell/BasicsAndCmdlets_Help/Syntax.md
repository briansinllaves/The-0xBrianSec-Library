### **PowerShell Syntax Overview**

#### **Cmdlets**
Cmdlets are small scripts that follow a verb-noun ning convention, such as "Get-Process". The verb-noun structure clearly defines the action and the target resource.

#### **Common Verbs with Their Actions**
- **New-**: Creates a new resource.
- **Set-**: Modifies an existing resource.
- **Get-**: Retrieves an existing resource.
- **Read-**: Retrieves information from a source, such as a file.
- **Find-**: Searches for an object.
- **Search-**: Locates or references a resource.
- **Start-**: (Asynchronous) Begins an operation, such as starting a process.
- **Invoke-**: (Synchronous) Executes an operation, such as running a command.

#### **Parameters**
Each cmdlet may have multiple parameters that allow you to control its functionality and behavior. Parameters refine how the cmdlet operates, such as specifying input data, defining output behavior, or filtering results.

#### **Objects**
The output of most cmdlets is an object. These objects can be passed (piped) to other cmdlets for further processing. Pipelining cmdlets in this way allows for more complex and powerful scripting capabilities in PowerShell.