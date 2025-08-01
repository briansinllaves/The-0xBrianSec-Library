

```

Get-WinEvent -FilterHashtable @{Logne='Security'; ID=4672} | Select-Object -First 1 | Format-List  

```

