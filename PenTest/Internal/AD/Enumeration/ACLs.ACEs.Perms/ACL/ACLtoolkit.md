**Using ACLToolkit to Get Object ACLs**

1. **Command to Get Object ACLs:**

   - Replace `<domain>`, `<user>`, `<password>`, and `<target>` with your specific details.

   ```plaintext
   acltoolkit <domain>/<user>:'<password>@<target>' get-objectacl [-all| -object <object>]
   ```

2. **Options:**

   - `-all`: Get ACLs for all objects.
   - `-object <object>`: Get ACLs for a specific object.

3. **Example Usage:**

   - To get ACLs for all objects:

     ```plaintext
     acltoolkit domain/user:'password@target' get-objectacl -all
     ```

   - To get ACLs for a specific object (e.g., "CN=Users,DC=domain,DC=com"):

     ```plaintext
     acltoolkit domain/user:'password@target' get-objectacl -object "CN=Users,DC=domain,DC=com"
     ```