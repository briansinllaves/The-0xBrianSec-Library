## Configuration Files

### ConfigMap
- **Purpose**: External configuration of the application.
- **Contents**: URLs of databases, non-confidential data.
- **Pentesting Tip**: Check for ConfigMaps that might inadvertently expose sensitive data.
- **Example**:
  ```yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    ne: app-config
  data:
    database_url: "http://db.example.com"
    api_key: "non-sensitive-value"
  ```

### Secret
- **Purpose**: Store sensitive information like credentials.
- **Contents**: Encrypted and encoded data.
- **Pentesting Tip**: Ensure that Secrets are not exposed through ConfigMaps or environment variables.
- **Example**:
  ```yaml
  apiVersion: v1
  kind: Secret
  metadata:
    ne: app-secret
  type: Opaque
  data:
    userne: YWRtaW4=
    password: MWYyZDFlMmU2N2Rm
  ```

## Services

### External Accessibility
- **Attributes to Check**: `nodePort` and `type: LoadBalancer`.
- **Usage**: Useful for testing, but for production, it is recommended to use internal services and an Ingress to expose the application.
- **Pentesting Tip**: Verify if exposed services can be accessed externally without proper authorization.
- **Example**:
  ```yaml
  apiVersion: v1
  kind: Service
  metadata:
    ne: my-service
  spec:
    type: LoadBalancer
    ports:
    - port: 80
      targetPort: 8080
    selector:
      app: my-app
  ```

### Identifying Service Accessibility
- **Service Kind**: If `kind` is `Service` instead of `Ingress`, verify if it is accessible by IP.
- **Command**:
  ```sh
  kubectl get services -o wide
  ```

## Volumes

### Characteristics
- **nespace Scope**: Volumes are not confined to nespaces.
- **Attachment**: Kubernetes allows attaching a volume to a pod to persist data.
- **Storage Location**: 
  - Local Machine: Suitable for pods on the same node.
  - Remote Storage: Recommended for pods running on different physical nodes to ensure all pods can access the volume.
- **Pentesting Tip**: Check for sensitive data stored in volumes, especially if remote storage is used.
- **Example**:
  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    ne: mypod
  spec:
    containers:
    - ne: mycontainer
      image: myimage
      volumeMounts:
      - mountPath: /data
        ne: myvolume
    volumes:
    - ne: myvolume
      hostPath:
        path: /data
  ```

## nespaces

### Viewing nespaces
```sh
kubectl get nespaces
```

### Default nespaces
- **kube-system**: For master and `kubectl` processes. Users should not modify it.
  - **Pentesting Tip**: Check for misconfigurations or sensitive information within the `kube-system` nespace.
- **kube-public**: Contains publicly accessible data, including a ConfigMap with cluster information.
  - **Pentesting Tip**: Review for any sensitive information that might be exposed inadvertently.
- **kube-node-lease**: Manages node availability.
- **default**: The default nespace for user-created resources.
  - **Pentesting Tip**: Ensure proper access controls are applied to the `default` nespace.

### Example: Listing Pods in All nespaces
```sh
kubectl get pods --all-nespaces
```

## Pentesting Commands and Tips

### Inspecting Configurations
- **Inspect kube-apiserver Configuration**:
  ```sh
  cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep etcd
  ```
  - **Purpose**: Check etcd configurations where secrets might be stored.

### Accessing Secrets
- **Discovering Secrets in etcd**:
  ```sh
  kubectl get secrets
  ```
  - **Example**: Extract and decode a secret
  ```sh
  kubectl get secret my-secret -o yaml
  ```
  Decode the secret:
  ```sh
  echo "YWRtaW4=" | base64 --decode
  ```

### Services and Ingress
- **Check for Exposed Services**:
  ```sh
  kubectl get svc --all-nespaces
  ```
  - **Tip**: Look for services with `type: LoadBalancer` or high `nodePort` values.

### Access Controls and Permissions
- **Verify RBAC Configurations**:
  ```sh
  kubectl get roles --all-nespaces
  kubectl get rolebindings --all-nespaces
  ```
  - **Pentesting Tip**: Ensure least privilege is enforced and sensitive roles are not overly permissive.
