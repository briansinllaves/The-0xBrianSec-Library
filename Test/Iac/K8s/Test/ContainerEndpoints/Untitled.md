
## Common Container Endpoints

### 1. Kubernetes Endpoints

- **API Server**:
  - `/api/`
  - `/apis/`
  - `/api/v1/nespaces/`
  - `/api/v1/pods/`
  - `/api/v1/services/`
  - `/apis/apps/v1/deployments/`

- **Kubelet**:
  - `/pods`
  - `/metrics`
  - `/runningpods`

- **ETCD**:
  - `/v2/keys/`
  - `/v3/kv/range`

### 2. Docker Endpoints

- **Docker API**:
  - `/containers/json`
  - `/containers/{id}/json`
  - `/containers/{id}/top`
  - `/containers/{id}/logs`
  - `/containers/{id}/stats`
  - `/containers/{id}/start`
  - `/containers/{id}/stop`

### 3. Common Application Endpoints

- **Health Checks**:
  - `/health`
  - `/healthz`
  - `/status`
  - `/alive`

- **Metrics and Monitoring**:
  - `/metrics`
  - `/prometheus`
  - `/stats`

- **Configuration and Management**:
  - `/config`
  - `/settings`
  - `/admin`
  - `/manage`
  - `/debug`

- **Authentication and Authorization**:
  - `/login`
  - `/logout`
  - `/auth`
  - `/token`

- **Data Access**:
  - `/data`
  - `/files`
  - `/storage`

### 4. API Endpoints

- **Swagger/OpenAPI**:
  - `/swagger-ui.html`
  - `/v2/api-docs`
  - `/api-docs`

- **GraphQL**:
  - `/graphql`
  - `/graphiql`

### 5. Additional Endpoints

- **Version Information**:
  - `/version`
  - `/info`
  - `/about`

- **Documentation**:
  - `/docs`
  - `/help`

## Using Burp Suite to Scan Endpoints

### Steps to Configure Burp Suite

1. **Target Scope**:
   - Define your target scope in Burp Suite to include the specific IP addresses or domains of your containerized application.

2. **Spidering**:
   - Use Burp's spidering functionality to automatically discover endpoints within the defined scope.

3. **Active Scanning**:
   - Perform an active scan on the discovered endpoints to identify vulnerabilities.

4. **Intruder**:
   - Use Burp's Intruder tool to fuzz specific endpoints and parameters, leveraging wordlists from SecLists or custom lists.

5. **Repeater**:
   - Manually explore and test endpoints using Burp's Repeater tool to analyze responses and behaviors.

### Example: Configuring Burp Scanner

1. **Add Target URLs**:
   - Manually add the URLs of common container endpoints to the target scope.

2. **Configure Scan**:
   - Set up a scan to include these endpoints, ensuring all relevant HTTP methods (GET, POST, PUT, DELETE) are tested.
