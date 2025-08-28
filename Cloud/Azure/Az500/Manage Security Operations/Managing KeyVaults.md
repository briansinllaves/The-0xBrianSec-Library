## Creating Key Vault

### What is Azure Key Vault?

* Secure service for storing:

  * Credentials, passwords, database connection strings
  * PKI certificates
  * Secrets used by apps/services
* Supports **centralized secret management**

💡 **Use Case**

* Encrypt VM disks with customer-managed keys
* Keys should be in the same region as the VM

---

### Creating a Key Vault (Portal)

1. Create resource → Search **Key Vault**
2. Select Microsoft Key Vault → **Create**
3. Configure:

   * RG: App1
   * Name: `KVEast1`
   * Region: East US (must match associated service)

🌍 **Common Regions:** East US 2, Germany West Central, France Central, Japan East/West, Korea Central/South

💲 **Pricing Tier**

* Standard: no HSM
* Premium: includes HSM (for tamper-resistant key storage, crypto ops)

🧹 **Soft Delete & Retention**

* Enabled by default (90-day recovery)
* Optional: Purge protection (hard delete disabled until retention expires)

---

### Post-Creation: Access Configuration

* **Access Policies:** Assign to users/services (e.g., IT Demo 5)
* **Templates available:**

  * Key, Secret & Certificate Mgmt
  * Secret-only
  * SQL Connector
  * Storage/Data Lake
  * Exchange/SharePoint Keys
  * AIP BYOK
  * M365 at-rest encryption

👤 **Assigning users/apps:** Example: Abu Adachi

---

### Role-Based Access Control (IAM)

* Roles:

  * Key Vault Administrator (full control)
  * Contributor (manage vault, not contents)
  * Reader (read-only settings)
  * Certificates Officer, Crypto Officer, Crypto User, etc.

---

### Vault Object Management

* Properties → Objects: manage Keys, Secrets, Certificates

---

### Command Line Management

**Azure CLI**

```bash
# Create vault
az keyvault create \
  --name KVEast1 \
  --resource-group App1 \
  --location eastus \
  --sku standard
```

**PowerShell**

```powershell
# Create vault
New-AzKeyVault -Name "KVEast1" -ResourceGroupName "App1" -Location "East US"
# List cmdlets
Get-Command *keyvault*
```

---

## Managing Key Vault Secrets Using the GUI

🗂️ **Accessing Vault**

* Portal → All Resources → Filter: Key vaults → select (e.g., KVEast1)

🌍 **Region Awareness**

* Place vault + resource (e.g., VM) in same region
* Use multiple vaults for regional separation

🔐 **Access Requirements**

* IAM Role assignment + Access Policies
* Permissions may include Key, Secret, Certificate

---

### Managing Keys

* **Generate/Import**

  * Import: existing pair/backup
  * Generate: RSA (2048/3072/4096) or EC
* Optional: Activation/Expiration dates, rotation policy
* Key details:

  * Public key downloadable ✅
  * Private key non-exportable ❌

---

### Managing Secrets

* Generate/Import → Manual
* Use for tokens, DB strings, credentials
* Single-line only in GUI
* Options: Activation, Expiration, Enable/Disable

✅ Example: SecretValue1 created

---

## Managing Key Vault Secrets Using the CLI

📥 **Setup**

* Open Cloud Shell (Bash recommended)

---

### Create Key Vault

```bash
az keyvault create \
  --location eastus \
  --name KVEast2 \
  --resource-group App1 \
  --network-acls-ips <public_IP>
```

---

### List Vaults

```bash
az keyvault list --query [].name
```

---

### Secrets

```bash
# Create secret
az keyvault secret set \
  --name db1connection \
  --value "connectionstringsamplevalue" \
  --vault-name KVEast2

# List secrets
az keyvault secret list --vault-name KVEast2
```

---

### Keys

```bash
# Create RSA key
az keyvault key create \
  --name RSAKeyPair2 \
  --kty RSA \
  --protection software \
  --vault-name KVEast2

# List keys
az keyvault key list --vault-name KVEast2 --query [].name
```

---

## Managing Key Vault Secrets Using PowerShell

### Create Key Vault

```powershell
New-AzKeyVault -Name "KVEast3" -ResourceGroupName "App1" -Location "East US" -EnabledForDeployment
```

### Access Policies

```powershell
Set-AzKeyVaultAccessPolicy -VaultName "KVEast3" -UserPrincipalName "cblackwell@quick24x7testing.onmicrosoft.com" `
  -PermissionsToSecrets all -PermissionsToKeys all -PermissionsToCertificates all -PermissionsToStorage get
```

### Create Secret

```powershell
$secretvalue = ConvertTo-SecureString "MySecurePass!" -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName "KVEast3" -Name "password1" -SecretValue $secretvalue
```

### Create Key

```powershell
Add-AzKeyVaultKey -VaultName "KVEast3" -Name "RSAKeyPair4" -Destination "Software"
```

---

## Managing Key Vault Certificates Using the GUI

* **Options:** Generate or Import
* **CA Types:**

  * Self-signed
  * Integrated CA (DigiCert, GlobalSign)
  * External CA (CSR workflow)

**Example: Self-signed cert**

* CN: [www.webapp1test.com](http://www.webapp1test.com)
* Validity: 12 months
* Auto-renew: 80% lifetime

Advanced: RSA/EC key type, exportable flag, key usages

---

## Managing Key Vault Certificates Using the CLI

### List Vaults & Certs

```bash
az keyvault list --query [].name
az keyvault certificate list --vault-name KVEast3 --query [].name
```

### Create Certificate

```bash
az keyvault certificate create \
  --vault-name KVEast3 \
  --name Cert3 \
  --policy "$(az keyvault certificate get-default-policy)"
```

---

## Managing Key Vault Certificates Using PowerShell

### Define Policy

```powershell
$Policy = New-AzKeyVaultCertificatePolicy `
  -SecretContentType 'application/x-pkcs12' `
  -SubjectName "CN=www.app1testing.com" `
  -IssuerName "Self" `
  -ValidityInMonths 12 `
  -ReuseKeyOnRenewal
```

### Create Cert

```powershell
Add-AzKeyVaultCertificate -VaultName "KVEast3" -Name "App2Cert" -CertificatePolicy $Policy
```

### List Certs

```powershell
Get-AzKeyVaultCertificate -VaultName "KVEast3" | Select-Object Name
```

---

## Working with Azure Key Vault and Hardware Security Modules (HSMs)

🔒 **What is an HSM?**

* Dedicated tamper-resistant hardware appliance
* Performs crypto operations (gen, encrypt/decrypt, sign, auth)
* **FIPS 140-2 Level 3 compliant**
* Often mandatory for PCI DSS, HIPAA, GDPR

🛡️ Use **Premium Key Vault SKU** for HSM-backed keys
