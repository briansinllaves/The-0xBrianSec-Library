# Pentesting Notes for Gaining Environment Information in Kubernetes

## Objective
Explore and gather detailed information about the container and its environment to understand the system better.

## Steps

### 1. Get Container Runtime Information
To determine the container runtime and gather related information, run:

```sh
cat /proc/self/cgroup
```

### 2. Get Container Host Information
Retrieve information about the container host by examining the hosts file:

```sh
cat /etc/hosts
```

### 3. Get Mount Information
Check the mounted file systems to understand how the container interacts with the host file system:

```sh
mount
```

### 4. Explore the File System
List the contents of directories to explore the file system and look for interesting files and directories:

```sh
ls -la /home/
```

### 5. Access Environment Variables
Environment variables often contain useful information such as Kubernetes secrets, service nes, and ports:

```sh
printenv
```

### Additional Useful Commands

#### Checking Network Configuration
View network interfaces and their configurations:

```sh
ifconfig
```
or
```sh
ip a
```

#### Checking Process Information
List running processes to understand the container's activities:

```sh
ps aux
```

#### Inspecting Kubernetes Service Accounts
Kubernetes mounts service account tokens in containers for API access. Check for these tokens:

```sh
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

#### Inspecting ConfigMaps and Secrets
If mounted as volumes, ConfigMaps and Secrets can be inspected directly:

```sh
ls /etc/config
ls /etc/secrets
```

### Example Scenario: Gathering Comprehensive Environment Information
```sh
# Get container runtime information
cat /proc/self/cgroup

# Get container host information
cat /etc/hosts

# Get mount information
mount

# Explore the file system
ls -la /home/

# Access environment variables
printenv

# Check network configuration
ip a

# List running processes
ps aux

# Inspect Kubernetes service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Inspect ConfigMaps and Secrets if available
ls /etc/config
ls /etc/secrets
```

