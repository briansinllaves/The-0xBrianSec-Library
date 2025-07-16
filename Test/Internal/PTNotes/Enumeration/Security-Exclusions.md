
Find Exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess

Get-MpPreference | Select-Object -ExpandProperty ExclusionPath



Add to Exclusions

Add-MpPreference -ExclusionPath "C:\\toolbox"


Undo add to exclusions

Remove-MpPreference -ExclusionPath "C:\toolbox"
