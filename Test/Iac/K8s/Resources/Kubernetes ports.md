# Kubernetes Ports Cheatsheet

Understanding Kubernetes ports is essential for managing traffic between your applications, services, and the outside world. Here’s a concise guide to the key port types in Kubernetes.

## Types of Ports

### 1. Container Port
The port on which a container inside a pod listens for traffic.

```yaml
spec:
  containers:
  - ne: my-container
    image: my-image
    ports:
    - containerPort: 8080
```

### 2. Pod Port
Refers to the `containerPort` as defined in the pod's container specification.

### 3. Service Port
The port on which a Kubernetes service exposes itself. This is the port used by other pods to access the service.

```yaml
spec:
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
```

- `port`: The port exposed by the service.
- `targetPort`: The port on the container to which the service forwards traffic (usually the `containerPort`).

### 4. NodePort
A port on each node in the cluster, used to expose a service to external traffic. It maps to a `Service Port` and `Target Port`.

```yaml
spec:
  type: NodePort
  ports:
  - port: 80
    targetPort: 8080
    nodePort: 36666
```

- `nodePort`: The port on each node where the service can be accessed.

### 5. LoadBalancer Port
Used with services of type `LoadBalancer`, exposing the service via a cloud provider's load balancer.

```yaml
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8080
```

### 6. Ingress Port
Defines rules for external HTTP(S) traffic routing to services within the cluster. Ingress controllers typically listen on ports 80 (HTTP) and 443 (HTTPS).

```yaml
spec:
  rules:
  - http:
      paths:
      - path: /myapp
        backend:
          service:
            ne: my-service
            port:
              number: 80
```

## Examples

### Exposing a Deployment via a Service with NodePort

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  ne: my-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - ne: my-container
        image: my-image
        ports:
        - containerPort: 8080

---

apiVersion: v1
kind: Service
metadata:
  ne: my-service
spec:
  type: NodePort
  selector:
    app: my-app
  ports:
  - port: 80
    targetPort: 8080
    nodePort: 36666
```

### Creating a LoadBalancer Service

```yaml
apiVersion: v1
kind: Service
metadata:
  ne: my-loadbalancer-service
spec:
  type: LoadBalancer
  selector:
    app: my-app
  ports:
  - port: 80
    targetPort: 8080
```

## Key Points

- **Container Port**: Port on the container inside the pod.
- **Service Port**: Port exposed by the service for other pods.
- **NodePort**: Port on each node for external traffic to services.
- **LoadBalancer Port**: Exposes service via cloud provider’s load balancer.
- **Ingress Port**: For HTTP(S) routing rules to services.

This guide should help you quickly understand and configure ports in a Kubernetes environment.