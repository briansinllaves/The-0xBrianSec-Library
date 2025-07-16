### **Responder - Pentest Note**

**Note:** `Multirelay.py` is incompatible with Python 3 due to the deprecation of `UserDict`.

**Source:** [Responder GitHub](https://github.com/lgandx/Responder)

---

### **Configure Responder:**

1. **Edit Configuration:**
   - Disable/enable specific services to tailor responses.
   - **Command:**
     ```bash
     nano /usr/share/responder/Responder.conf
     ```

suspend responder
```
ps aux | grep 'T'
```

Kill the first number above thats in lline
```
kill -9 pid#
```



### **Starting Responder:**

1. **Basic Start (Listen on all interfaces):**
   - **Command:**
     ```bash
     responder -I [Interface] -A
     ```
   - **Use Case:** General network capture for various protocols.
```
responder -I eth0 -wrf

```

The `-e` and `-i` options in Responder are used to specify the IP addresses that Responder will bind to or use during its operation.

### **`-e` Option: External IP Address**

- **Purpose:** Specifies an external IP address that Responder should bind to. This is typically used when you want Responder to respond using a specific IP address that is different from the one associated with the network interface.

- **Example Use Case:** If you have a system with multiple IP addresses (e.g., a public and private IP), you can use the `-e` option to make Responder use a specific external IP address when it sends responses.

- **Command Example:**
  ```bash
  responder -I eth0 -e 192.168.1.100 -wrf
  ```
  - Here, Responder listens on the `eth0` interface but sends responses using the external IP `192.168.1.100`.

### **`-i` Option: Specific IP Address**

- **Purpose:** Specifies the IP address that Responder should bind to for listening. This can be used to restrict Responder to a particular IP address associated with a network interface.

- **Example Use Case:** If your system has multiple IP addresses on a single interface, and you want Responder to only listen on and use a specific one, you would use the `-i` option.

- **Command Example:**
  ```bash
  responder -I eth0 -i 10.0.0.5 -wrf
  ```
  - In this example, Responder listens on the `eth0` interface, but only on the IP address `10.0.0.5`.

### **Key Differences**

- **`-e`:** Tells Responder which IP to use when sending responses.
- **`-i`:** Tells Responder which IP to bind to for listening.

### **Combined Usage Example**

You can use both options together if you want Responder to listen on one IP but send responses from another:

```bash
responder -I eth0 -i 10.0.0.5 -e 192.168.1.100 -wrf
```

- **Explanation:**
  - Responder listens on `10.0.0.5` but sends responses using `192.168.1.100`.

This setup might be useful in complex network environments where you need to control which IP addresses are exposed to the network during your penetration testing activities.


### **Responder Tools:**

- **Location:** `/usr/share/Responder/tools`
- **Use Case:** Additional utilities for post-capture analysis and relay attacks.

### **Check SMB Signing:**

1. **Identify Weak SMB Configurations:**
   - **Command:**
     ```bash
     python3 RunFinger.py -i 172.21.0.0/24
     ```
   - **Use Case:** Locate systems vulnerable to SMB relay attacks.
