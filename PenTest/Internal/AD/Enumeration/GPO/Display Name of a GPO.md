Display ne of a GPO

This command will retrieve and display the display ne and ne of a specific GPO identified by its ID.
```
Get-DomainGPO -ID '{}' | Select-Object Displayne, ne | Format-List
```
