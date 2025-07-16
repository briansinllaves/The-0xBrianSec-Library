# Kubernetes Configuration Examples with Security and Pentest Tips

## Example of External Service Configuration

This service will be accessible externally. Check the `nodePort` and `type: LoadBalancer` attributes:

```yaml
apiVersion: v1
kind: Service
metadata:
  ne: mongo-express-service
spec:
  selector:
    app: mongo-express
  type: LoadBalancer
  ports:
    - protocol: TCP
      port: 8081
      targetPort: 8081
      nodePort: 30000
```

### Security Tips:
- **Check for Open Ports**: Verify that only necessary ports are open and accessible. Use tools like `nmap` to scan for open ports.
- **Secure NodePort**: Ensure `nodePort` values are within the allowed range and not exposing unnecessary services.
- **Monitor Traffic**: Use network monitoring tools to track traffic to the service and detect any suspicious activity.

### Pentest Tips:
- **Port Scanning**: An attacker would scan for open ports to find accessible services. Ensure unnecessary ports are closed.
- **Service Enumeration**: Attackers might enumerate services to identify running applications and their versions for known vulnerabilities.

## Example of Ingress Configuration

This will expose the application at `http://dashboard.com`.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  ne: dashboard-ingress
  nespace: kubernetes-dashboard
spec:
  rules:
  - host: dashboard.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            ne: kubernetes-dashboard
            port:
              number: 80
```

### Security Tips:
- **HTTPS Enforcement**: Ensure Ingress is configured to use HTTPS instead of HTTP to secure data in transit.
- **Host and Path Validation**: Verify that the `host` and `path` fields are correctly configured to prevent unauthorized access.
- **Security Headers**: Add security headers (e.g., `Content-Security-Policy`, `X-Frame-Options`) to protect against common web vulnerabilities.

### Pentest Tips:
- **Man-in-the-Middle Attacks**: Without HTTPS, attackers can intercept traffic. Always enforce HTTPS.
- **Path Traversal**: Attackers may exploit poorly configured paths to access unauthorized resources.

## Example of Secrets Configuration

Note how the passwords are encoded in Base64 (which is not secure on its own).

```yaml
apiVersion: v1
kind: Secret
metadata:
  ne: mongodb-secret
type: Opaque
data:
  mongo-root-userne: dXNlcm5hbWU=
  mongo-root-password: cGFzc3dvcmQ=
```

### Security Tips:
- **Secure Storage**: Ensure secrets are stored securely and not exposed in logs or environment variables.
- **Access Control**: Use RBAC to restrict access to secrets to only those who need it.
- **Rotate Secrets**: Regularly rotate secrets to minimize the impact of potential exposure.

### Pentest Tips:
- **Base64 Decoding**: Attackers can easily decode Base64 secrets. Ensure stronger encryption methods are used.
- **Secret Exposure**: Attackers may gain access to secrets through misconfigured permissions or exposed environment variables.

## Example of ConfigMap

A ConfigMap provides configuration data to pods. In this example, each pod will know that the ne `mongodb-service` refers to the address of a pod running MongoDB.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  ne: mongodb-configmap
data:
  database_url: mongodb-service
```

### Security Tips:
- **Sensitive Data**: Ensure that sensitive data (e.g., credentials) is not stored in ConfigMaps. Use Secrets instead.
- **Validation**: Validate the data in ConfigMaps to prevent misconfigurations that could lead to vulnerabilities.
- **Least Privilege**: Limit the access to ConfigMaps to only those pods and users that require it.

### Pentest Tips:
- **Misconfiguration Exploitation**: Attackers might exploit misconfigurations in ConfigMaps to redirect traffic or access unauthorized services.

## Example of Deployment Configuration

This deployment uses the ConfigMap to configure the `mongo-express` container.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  ne: mongo-express-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mongo-express
  template:
    metadata:
      labels:
        app: mongo-express
    spec:
      containers:
      - ne: mongo-express
        image: mongo-express
        ports:
        - containerPort: 8081
        env:
        - ne: ME_CONFIG_MONGODB_SERVER
          valueFrom: 
            configMapKeyRef:
              ne: mongodb-configmap
              key: database_url
```

### Security Tips:
- **Resource Limits**: Set resource requests and limits to prevent Denial of Service (DoS) attacks.
- **Image Security**: Ensure the container images are from a trusted source and are regularly scanned for vulnerabilities.
- **Environment Variables**: Avoid exposing sensitive information through environment variables. Use secrets where possible.

### Pentest Tips:
- **Resource Exhaustion**: Attackers could launch DoS attacks by exploiting lack of resource limits.
- **Image Vulnerabilities**: Attackers might exploit known vulnerabilities in container images. Regularly scan and update images.
- **Environment Variable Exposure**: Attackers can extract sensitive information if environment variables are not properly secured.