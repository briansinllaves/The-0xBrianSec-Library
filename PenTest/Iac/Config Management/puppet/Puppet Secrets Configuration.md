# Puppet Secrets Configuration

## EYAML Configuration and Decryption

### Key Storage
- **EYAML Keys**: Should be available on the Puppet master node.
- **Master Node Requirement**: If `eyaml` is not present, ensure you are on the Puppet master node.
- **Key Locations**: Keys are stored on the Puppet master, and can be used to decrypt files offline.

### Decryption Configuration
- **Necessary Files**:
  - `private_key.pkcs7.pem`: Located at `/etc/puppetlabs/puppet/eyaml/`
  - `public_key.pkcs7.pem`: Located at `/etc/puppetlabs/puppet/eyaml/`
- **Configuration**:
  - Puppet's YAML configuration is required to decrypt files.

### Decrypting Files
Use the following command to decrypt EYAML files with Puppet's PKCS7 keys:

```sh
eyaml decrypt -e common.eyaml \
  --pkcs7-private-key=/etc/puppetlabs/puppet/eyaml/private_key.pkcs7.pem \
  --pkcs7-public-key=/etc/puppetlabs/puppet/eyaml/public_key.pkcs7.pem -v
```

### Explanation
- **`eyaml decrypt -e common.eyaml`**:
  - `decrypt`: Command to decrypt the file.
  - `-e common.eyaml`: Specifies the encrypted file to decrypt.
- **`--pkcs7-private-key`**: Path to the private key used for decryption.
- **`--pkcs7-public-key`**: Path to the public key, required for verification.
- **`-v`**: Verbose mode to provide detailed output.

By following these steps and configurations, you can securely manage and decrypt secrets within Puppet using EYAML.