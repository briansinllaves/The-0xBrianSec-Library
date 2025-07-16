https://github.com/dafthack/GraphRunner

https://www.blackhillsinfosec.com/introducing-graphrunner/

https://learn.microsoft.com/en-us/graph/api/application-get?view=graph-rest-1.0&tabs=http#http-request

edit the default detectors
```
$folderne = "SharePointSearch-" + (Get-Date -Format 'yyyyMMddHHmmss') New-Item -Path $folderne -ItemType Directory | Out-Null $spout = "$folderne\interesting-files.csv" $DetectorFile = ".\default_detectors.json" $detectors = Get-Content $DetectorFile $detector = $detectors |ConvertFrom-Json foreach($detect in $detector.Detectors){Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm $detect.SearchQuery -Detectorne $detect.Detectorne -PageResults -ResultCount 500 -ReportOnly -OutFile $spout -GraphRun}

```

