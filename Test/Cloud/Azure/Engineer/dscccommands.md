# dscccommands

```powershell
# View DSC configurations
Get-AzAutomationDscConfiguration -AutomationAccountName "<account>" -ResourceGroupName "<rg>"

# Compile a configuration
Start-AzAutomationDscCompilationJob -ConfigurationName "<config-name>" -ResourceGroupName "<rg>" -AutomationAccountName "<account>"
```
