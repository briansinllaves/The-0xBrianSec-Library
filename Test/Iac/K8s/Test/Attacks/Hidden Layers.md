Effectively inspect and explore hidden layers within Docker images, potentially uncovering sensitive information or security issues.
## Objective
Inspect and explore hidden layers in Docker images to uncover potential security issues or sensitive information.

## Steps

### 1. List Kubernetes Jobs
First, list the Kubernetes jobs to understand the current workloads:

```sh
kubectl get jobs
```

### 2. Inspect Docker Image
Use Docker CLI to inspect the image details:

```sh
docker inspect madhuakula/k8s-goat-hidden-in-layers
```

### 3. Explore Docker Image Layers
Use the Docker history command to explore each layer of the image:

```sh
docker history --no-trunc madhuakula/k8s-goat-hidden-in-layers
```

### 4. Use Dive Tool for Detailed Inspection
Dive is a useful tool for exploring Docker image layers:

- **Install Dive**: Follow the instructions on [Dive GitHub repository](https://github.com/wagoodman/dive) to install.
- **Run Dive**:
  ```sh
  dive madhuakula/k8s-goat-hidden-in-layers
  ```

### 5. Save Docker Image to Tar File
Save the Docker image to a tar file for further exploration:

```sh
docker save madhuakula/k8s-goat-hidden-in-layers -o hidden-in-layers.tar
```

### 6. Extract Tar File
Extract the contents of the tar file to explore individual layers:

```sh
tar -xvf hidden-in-layers.tar
```

### 7. Explore Extracted Layers
Navigate to the extracted directory and inspect each layer:

```sh
cd da73da4359e9edb793ee5472ae3538be8aec57c27efff7dae8873566c865533f
tar -xvf layer.tar
```

### 8. Access Hidden Files
Look for hidden or sensitive files within the layers:

```sh
cat root/secret.txt
```

### Summary of Commands
```sh
# List Kubernetes jobs
kubectl get jobs

# Inspect Docker image
docker inspect madhuakula/k8s-goat-hidden-in-layers

# Explore Docker image layers
docker history --no-trunc madhuakula/k8s-goat-hidden-in-layers

# Save Docker image to tar file
docker save madhuakula/k8s-goat-hidden-in-layers -o hidden-in-layers.tar

# Extract tar file
tar -xvf hidden-in-layers.tar

# Navigate to specific layer directory and extract it
cd da73da4359e9edb793ee5472ae3538be8aec57c27efff7dae8873566c865533f
tar -xvf layer.tar

# Access hidden files
cat root/secret.txt
```

