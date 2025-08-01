A Secret is an object that contains sensitive data such as passwords, tokens, or keys. Such information might otherwise be put in a Pod specification or in an image. Users can create Secrets, and the system also creates Secrets. The ne of a Secret object must be a valid DNS subdomain ne.
## Types of Secrets

### 1. Opaque
Default type, used for arbitrary user-defined data.

### 2. Service Account Token
Used to store a token for accessing the Kubernetes API.

### 3. Docker Config
Used to store Docker registry credentials.

## Creating Secrets

### From Literal Values
```sh
kubectl create secret generic my-secret --from-literal=userne=myuser --from-literal=password=mypassword
```

### From Files
```sh
kubectl create secret generic my-secret --from-file=path/to/userne.txt --from-file=path/to/password.txt
```

### From Environment Files
```sh
kubectl create secret generic my-secret --from-env-file=path/to/envfile
```

## Using Secrets in Pods

### As Environment Variables
```yaml
apiVersion: v1
kind: Pod
metadata:
  ne: mypod
spec:
  containers:
  - ne: mycontainer
    image: myimage
    env:
    - ne: USERnE
      valueFrom:
        secretKeyRef:
          ne: my-secret
          key: userne
    - ne: PASSWORD
      valueFrom:
        secretKeyRef:
          ne: my-secret
          key: password
```

### As Volume
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
    - ne: secret-volume
      mountPath: /etc/secret
  volumes:
  - ne: secret-volume
    secret:
      secretne: my-secret
```

## Accessing Secrets in etcd

Secrets are stored in `etcd`, the Kubernetes backing store. To access and discover secrets in `etcd`, you can inspect the `kube-apiserver` configuration.

### Inspecting kube-apiserver Configuration
```sh
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep etcd
```

For detailed pentesting and security insights, refer to the following resources:

- [Discover Secrets in etcd](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-basics#discover-secrets-in-etcd)
- [Kubernetes Secrets](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-basics#kubernetes-secrets)

## Best Practices

- Avoid hardcoding sensitive data in Pod specs or container images.
- Use RBAC to control access to Secrets.
- Enable encryption at rest for etcd.
- Regularly rotate secrets and credentials.

By following these practices, you can help ensure that your sensitive data remains secure within your Kubernetes cluster.