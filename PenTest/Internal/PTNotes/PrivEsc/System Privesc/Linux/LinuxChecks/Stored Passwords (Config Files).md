## Exploitation

**Linux VM**

1. Display the contents of the VPN config file:
   ```bash
   cat /home/user/myvpn.ovpn
   ```

2. Make note of the value of the `auth-user-pass` directive.


3. Display the OpenVPN auth file:
   ```bash
   cat /etc/openvpn/auth.txt
   ```

4. Note the clear-text credentials.

5. Display the config file:
   ```bash
   cat /home/user/.irssi/config | grep -i passw
   ```

6. Note the clear-text credentials.
![[Pasted image 20240905001649.png]]