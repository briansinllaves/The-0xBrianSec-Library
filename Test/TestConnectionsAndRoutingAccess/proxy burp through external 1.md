
Here's a clearer and more structured version of your note:

---

### **Setting Up SSH with Burp Proxy on Kali Linux**

1. **SSH and Burp Proxy Configuration:**

   - The SSH port should be the same as the Burp Proxy port, directing traffic to the loopback address of your Kali host VM (`127.0.0.1`).

2. **Generate SSH Key Pair:**

   - Use the following command to generate a new RSA SSH key pair with a 4096-bit length:
     ```bash
     ssh-keygen -t rsa -b 4096
     ```

   - After running this command, you will see output similar to the following:
     ```plaintext
     Your identification has been saved in /home/user/.ssh/id_rsa.
     Your public key has been saved in /home/user/.ssh/id_rsa.pub.
     ```

   - The private key is stored in `id_rsa`, and the corresponding public key is stored in `id_rsa.pub` within the `~/.ssh` directory.


![[Pasted image 20230526115744.png]]


![[Pasted image 20230526120051.png]]