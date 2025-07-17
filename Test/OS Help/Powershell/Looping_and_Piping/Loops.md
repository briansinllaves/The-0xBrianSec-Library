### **For Loop**
Use a `for` loop to iterate over a range with more control:
```powershell
for ($i = 1; $i -lt 99; $i++) {
   "10.165.1.$i"
}
```
This generates IP addresses from "10.165.1.1" to "10.165.1.98".

### **ForEach Loop**
Use `ForEach` to iterate over a collection of objects:
```powershell
$users = Get-ADUser -filter {department -eq 'Research'}
ForEach($user in $users) {
    $firstne = $user.Givenne
    $lastne = $user.Surne
    "$firstne.$lastne@smith.com"
}
```
This loop iterates over each user in the `Research` department and constructs an email address using their first and last nes.

# Looping and Iteration

## ForEach-Object
Executes a script block for each object in the pipeline.
Example: Output just the `HotfixID` for each installed hotfix:
```powershell
Get-Hotfix | ForEach-Object {$_.HotfixID}
```

