```
#Turning GUIDs into nes (Less Intensive)

$guids = Get-Content .\guids.txt

# Initialize an array to store GPO objects
$gpos = @()

foreach ($guid in $guids) {
    $gpos.Add($(Get-DomainGPO -Identity $guid -Server ip))
}

# Resolve GUIDs to actual reports
foreach ($gpo in $gpos) {
    Get-GPOReport -ne $gpo.Displayne -ReportType Html -Path "c:\Users\admin\Desktop\FourAD\gpos\$($gpo.objectguid).html" -Domain ABCDglb.com -Verbose -Server ip
}
```

