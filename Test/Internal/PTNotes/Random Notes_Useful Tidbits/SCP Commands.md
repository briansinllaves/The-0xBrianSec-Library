SCP Commands

# SCP Commands

### Copy to remote server (using PuttySCP):

```
scp -P 22222 C:\Users\User\<localfile> user@remotehost:/folder/<remote_Directory>
```

### Normal SCP:

Copy to remote server:
`scp -P 22222 user@myhost:\home\user\<file.exe> C:\Users\Victim

scp -P 22 /home/kali/tools/docs/sa.json brian@ip:/home/brian/docs/sa.json
`

Connect

ssh Proxy-1



SCP TRANSFER

recurse from remote to local
```
scp -r Proxy-1:/home/brian/country/ /home/kali/Desktop/
```

```
local to remote

scp -P 22 -r /home/kali/Downloads/Terdo64.tar.gz brian@4.157.64.71:/home/brian/


```
With key file:
`scp -i pkey user@myhost:\home\user\<file> /home/destination/`

recursive
```
scp -r /path/to/local/directory userne@remote_host:/path/to/destination  

```
When you use `**scp**` with the `**-r**` option, it allows you to copy not only individual files but also entire directories and their contents, including subdirectories.

if the list is copy-pasted into your terminal or uploaded via scp, dos2unix ftps.txt should get rid of any issues and extraneous chars that don't translate properly. I wouldn't do that conversion explicitly with iconv because it can make other issues occur if the characters weren't fully in utf-16 in the first place. dos2unix will fix and remove them instead of translating bad chars.
always do a manual inspection after the fact in a console text editor to see if anything was missed though



