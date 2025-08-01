add accounts with blank passwords into the stats

ntds.dit and system hive.
use secretsdump
toxic rule set hashcat 2 x2080s

pipal stats between which are cracked
https://github.com/digininja/pipal

utility
https://github.com/dionach/NtdsAudit

Red Team Password Assessment Admin Guide 

All below commands should be performed from an Administrator-level Command Prompt. 

1) Prior to the creation of shadow copies of the system's volumes, list out the existing Shadow Copies and ensure these are NOT deleted in the final step. 

To view all shadow copies on the system you can run the below command: 

```
vssadmin list shadows 
```

2) Create a new volume shadow copy 

Note: If the NTDS.dit file is kept on another disk or/partition besides the C: drive, you will need to use the correct Drive Letter, e.g. C:, D:.  

```
vssadmin create shadow /for=<Drive Letter>:  
```

Be sure to note the exact Shadow Copy Volume ID and ne that was created, as this will be used in next steps 

List out shadow copies again to ensure the new copy has been created:  

```
vssadmin list shadows 
```

3) Copy the SYSTEM registry hive and ntds.dit files to the main filesystem (be sure that there is enough space on disk prior to copying). Replace <Shadow Copy Volume ne> with the ne that was noted in the last step. 

5) Encrypt files and send the password to your point of contact 

6) Copy encrypted files to SMB share (details in email) 

net use R: \\<computer_ne>\<share_ne> /user:<userne> <password> 

copy NTDSFOLDER.zip R:\ 

net use R: /delete 

6) Delete the newly created volume shadow copy and leftover files. DO NOT DELETE PRE-EXISTING SHADOW COPIES NOTED IN STEP 1. 

Use the Shadow Copy Volume IDs from step 2 in the below command: 

vssadmin delete shadows /Shadow={<Shadow Copy Volume ID>} 

 