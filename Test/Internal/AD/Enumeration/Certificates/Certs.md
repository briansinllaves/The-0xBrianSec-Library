We are looking at Cert templates and for ESC 1-8. 

Dont make changes with cert anything in production or without approval. 

Request cert under the context of other users import it into your session. 

Anyone can go to the ca, can you pull it as any user, or what app can?

You can use native tools like certutil and certmgr.msc or custom like certifry. 

**Cert Template Enumeration and Exploitation (Pentest Context in ACL Section)**

We are examining certificate templates and targeting ESC1-8 vulnerabilities. Here is a link to attack ESC1. Do not make any changes to certificate settings in production or without proper approval. The goal is to request certificates under the context of other users and import them into your session. Determine if any user can pull certificates or identify which applications can.

**Tools and Commands:**

1. **Native Tools:**

   - **Certutil:**
   
     Enumerate AD Enterprise CAs:
     ```plaintext
     certutil.exe -config - -ping
     certutil -dump
     ```

     Dump a certificate file that you own:
     ```plaintext
     certutil -dump <path_to_certificate_file>
     ```

   - **Certmgr.msc:**
   
     Request a `PwdloobRuraUser` certificate via the Certificate Manager GUI.

2. **Custom Tools:**

   - **Certify:**
   
     Find vulnerable certificate templates:
     ```plaintext
     Certify.exe find /vulnerable /domain:pdwloob.com
     ```

   - **Certipy:**
   
     Find certificate templates using Certipy:
     ```plaintext
     certipy find -u user@domain -dc-ip 1.1.1.10
     ```

   - **Certifry:**
   
     Find or add the `/vulnerable` switch to identify exploitable certificates:
     ```plaintext
     .\Certifry find /vulnerable
     ```
