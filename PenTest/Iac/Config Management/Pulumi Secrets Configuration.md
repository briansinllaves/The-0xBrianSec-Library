# Pentesting Note: Pulumi Secrets Configuration

## Objective
Understand and exploit how Pulumi manages secrets in configurations to uncover potential security weaknesses.

## Steps

### 1. Providers for Secret Management
Pulumi supports multiple providers for managing secrets:

- **A. Default**: Uses a local file to store secrets.
- **B. Passphrase**: Encrypts secrets with a passphrase.
- **C. AWS KMS**: Uses AWS Key Management Service.
- **D. Azure Key Vault**: Uses Azure Key Vault for storing secrets.
- **E. GCP KMS**: Uses Google Cloud Key Management Service.
- **F. HashiCorp Vault**: Uses HashiCorp Vault for managing secrets.

### 2. Check Command History for Pulumi Secrets
Grep the bash history to find commands related to Pulumi secrets configuration:

```sh
grep "pulumi config set" ~/.bash_history
```

### 3. Using Pulumi Config for Secrets
Pulumi allows you to manage secrets using its configuration functionalities. Here is an example of setting and using secrets in Pulumi.

#### Setting a Secret Parameter
Using AWS SSM Parameter Store:

```python
import pulumi
import pulumi_aws as aws

cfg = pulumi.Config()

# Setting a parameter in AWS SSM Parameter Store
param = aws.ssm.Parameter("a-secret-param",
                          type="SecureString",
                          value=cfg.require_secret("my-secret-value"))
```

### Explanation
- **Import Pulumi and AWS Module**:
  ```python
  import pulumi
  import pulumi_aws as aws
  ```
- **Create a Config Object**:
  ```python
  cfg = pulumi.Config()
  ```
- **Set a Secure Parameter in SSM**:
  ```python
  param = aws.ssm.Parameter("a-secret-param",
                            type="SecureString",
                            value=cfg.require_secret("my-secret-value"))
  ```

### Mitigation Tips
- **Secure Storage**: Use appropriate providers like AWS KMS, Azure Key Vault, or HashiCorp Vault for storing secrets securely.
- **Audit Command History**: Regularly audit bash history and other logs to ensure secrets are not being exposed.
- **Use Environment Variables**: Instead of hardcoding secrets in scripts, use environment variables to manage sensitive data.
- **Access Controls**: Implement strict access controls to limit who can set, view, or modify secrets in Pulumi configurations.
]