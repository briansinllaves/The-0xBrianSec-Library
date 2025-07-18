### Azure Initial Recon with ROADTools

#### Steps:

1. **Navigate to ROADTools Directory**:
   ```bash
   cd ROADTools
   ```

2. **Activate Python Virtual Environment**:
   ```bash
   pipenv shell
   ```

3. **Authenticate with ROADrecon**:
   ```bash
   roadrecon auth -u test@corp.onmicrosoft.com -p "Welcomepain1342!"
   ```

4. **Gather Information**:
   ```bash
   roadrecon gather
   ```

5. **Launch ROADrecon GUI**:
   ```bash
   roadrecon gui
   ```