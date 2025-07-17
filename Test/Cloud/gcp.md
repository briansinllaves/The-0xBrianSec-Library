
login 

```

sudo snap install google-cloud-sdk --classic

gcloud auth login --cred-file=sa
```

### GCP (Google Cloud Platform) Pentester Cheat Sheet

#### Initial Setup:

1. **Install gcloud CLI**:
   ```bash
   # Download and install the gcloud CLI from https://cloud.google.com/sdk/docs/install
   ```

2. **Authenticate with GCP**:
   ```bash
   gcloud auth login
   gcloud config set project your_project_id
   ```

#### Basic Use:

1. **List Projects**:
   ```bash
   gcloud projects list
   ```

2. **List All Resources in a Project**:
   ```bash
   gcloud asset search-all-resources --scope=projects/your_project_id
   ```

3. **List Compute Engine Instances**:
   ```bash
   gcloud compute instances list
   ```

4. **List Cloud Storage Buckets**:
   ```bash
   gcloud storage buckets list
   ```

5. **List IAM Users**:
   ```bash
   gcloud iam service-accounts list
   ```

#### Enumeration and Reconnaissance:

1. **List GCP Services Enabled**:
   ```bash
   gcloud services list --enabled
   ```

2. **List All Networks and Subnets**:
   ```bash
   gcloud compute networks list
   gcloud compute networks subnets list
   ```

3. **List Firewall Rules**:
   ```bash
   gcloud compute firewall-rules list
   ```

4. **List Cloud SQL Instances**:
   ```bash
   gcloud sql instances list
   ```

5. **List BigQuery Datasets**:
   ```bash
   gcloud bigquery datasets list
   ```

6. **List Kubernetes Clusters**:
   ```bash
   gcloud container clusters list
   ```

#### Authentication and Finding Credentials:

1. **Service Account Keys**:
   ```bash
   gcloud iam service-accounts keys list --iam-account your-service-account@your_project_id.iam.gserviceaccount.com
   ```

2. **Environment Variables**:
   - Check for environment variables that might contain credentials such as `GOOGLE_APPLICATION_CREDENTIALS`.

3. **Check Configuration Files**:
   - Review configuration files for hardcoded credentials. These files are typically located in project directories or home directories (e.g., `~/.config/gcloud/application_default_credentials.json`).

4. **Access Token**:
   ```bash
   gcloud auth print-access-token
   ```

#### Pentest Cheat Sheet:

1. **Enumerate Permissions for a Service Account**:
   ```bash
   gcloud projects get-iam-policy your_project_id --flatten="bindings[].members" --format='table(bindings.role)' --filter="bindings.members:your-service-account@your_project_id.iam.gserviceaccount.com"
   ```

2. **List Active Users**:
   ```bash
   gcloud projects get-iam-policy your_project_id
   ```

3. **Public Bucket Discovery**:
   ```bash
   gsutil ls -L gs://your_bucket_ne
   ```

4. **Network Scanning with Nmap**:
   ```bash
   nmap -p 80,443 your-public-ip-address
   ```

5. **Check for Publicly Exposed VM Instances**:
   ```bash
   gcloud compute instances list --filter="status=RUNNING" --format="get(networkInterfaces[0].accessConfigs[0].natIP)"
   ```

#### Finding Public Information on Company's External Facing Resources:

1. **DNS Reconnaissance**:
   ```bash
   nslookup your_domain.com
   dig your_domain.com
   ```

2. **Google Dorking**:
   - Use specific search queries to find exposed resources or information.
   ```plaintext
   site:your_domain.com "confidential"
   ```

3. **Public Cloud Buckets**:
   ```bash
   gsutil ls -r gs://your_domain.com/
   ```

4. **Shodan**:
   - Use Shodan to find publicly exposed assets.
   ```plaintext
   shodan.io/search?query=your_domain.com
   ```

5. **Censys**:
   - Use Censys to enumerate public assets.
   ```plaintext
   censys.io/domain?q=your_domain.com
   ```

#### GCP Specific Commands:

1. **List All API Services**:
   ```bash
   gcloud services list --enabled
   ```

2. **Get IAM Policy**:
   ```bash
   gcloud projects get-iam-policy your_project_id
   ```

3. **List Cloud Functions**:
   ```bash
   gcloud functions list
   ```

4. **List App Engine Services**:
   ```bash
   gcloud app services list
   ```

5. **List Cloud Pub/Sub Topics**:
   ```bash
   gcloud pubsub topics list
   ```

6. **List Cloud Spanner Instances**:
   ```bash
   gcloud spanner instances list
   ```

