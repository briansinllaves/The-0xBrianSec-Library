# Software Reconnaissance Queries

## Identify Installed Software  
> **Note:** Query for specific software versions in the last 12 hours.  
```kql
ConfigurationData
| where ConfigDataType == "Software"
| where TimeGenerated > ago(12h)
| where SoftwareName == "Google Chrome"
| extend VersionParts = split(CurrentVersion, ".")
| extend Major = toint(VersionParts[0]), Minor = toint(VersionParts[1]), Build = toint(VersionParts[2]), Revision = toint(VersionParts[3])
| project SoftwareName, CurrentVersion, Computer
```