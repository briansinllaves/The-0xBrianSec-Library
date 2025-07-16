# Attacking Private Docker Registry

## Objective
Gain access to and exploit a private Docker registry by querying its REST API.

## Steps

### 1. Refer to Docker Registry API Documentation
- **Documentation**: Familiarize yourself with the Docker Registry API documentation to understand available endpoints and operations.
  - [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/)

### 2. Querying the REST API
- **List Repositories**: Fetch a list of repositories in the registry.
  ```sh
  curl -X GET https://<registry_url>/v2/_catalog
  ```

- **List Tags in a Repository**: Get a list of tags for a specific repository.
  ```sh
  curl -X GET https://<registry_url>/v2/<repository_ne>/tags/list
  ```

- **Fetch Manifest**: Retrieve the manifest for a specific image and tag.
  ```sh
  curl -X GET https://<registry_url>/v2/<repository_ne>/manifests/<tag>
  ```

- **Delete Image**: Attempt to delete an image by digest (requires proper authentication).
  ```sh
  curl -X DELETE https://<registry_url>/v2/<repository_ne>/manifests/<digest>
  ```

### 3. Authentication and Authorization
- **Check for Anonymous Access**: Test if the registry allows access without authentication.
- **Basic Authentication**: If credentials are required, attempt to use default or known credentials.
  ```sh
  curl -u <userne>:<password> https://<registry_url>/v2/_catalog
  ```

### 4. Exploiting Misconfigurations
- **Default Credentials**: Check for default or weak credentials.
- **Open Access**: Look for misconfigured registries allowing public access.
- **Privilege Escalation**: If you have some access, test if you can escalate privileges.

### 5. MitM Attacks
- **Intercepting Traffic**: Use tools like Burp Suite to intercept and analyze traffic between the Docker client and the registry.
- **Certificate Validation**: Check if the registry uses proper SSL/TLS configurations.

### 6. Additional Tips
- **Check Documentation**: Always refer to the official [Docker Registry HTTP API V2 documentation](https://docs.docker.com/registry/spec/api/) for detailed API usage.
- **Automation Tools**: Use tools like `docker-registry-explorer` or `clair` for automated interaction and vulnerability scanning.

