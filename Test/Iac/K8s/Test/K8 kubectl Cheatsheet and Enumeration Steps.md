By default, `kubectl` will use the default service account in `/var/run/secrets/kubernetes.io/serviceaccount`. This account has some API access but can't see anything outside its nespace.
## Step-by-Step Enumeration

### 1. Get Kubernetes Server Version
```sh
kubectl version
```

### 2. Get Kubernetes Cluster Information
```sh
kubectl cluster-info
```

### 3. Get Node Information
```sh
kubectl get nodes
```

### 4. Get nespace Information
```sh
kubectl get nespaces
```

### 5. Get Resource Information in Current nespace
#### 5.1 Get Pod Details
```sh
kubectl get pods
```
#### 5.2 Get Services
```sh
kubectl get svc
```
#### 5.3 Get Deployments
```sh
kubectl get deploy
```
#### 5.4 Get ReplicaSets
```sh
kubectl get replicaset
```
#### 5.5 Get Ingresses
```sh
kubectl get ing
```
#### 5.6 Get Secrets
```sh
kubectl get secrets
```

### 6. Get Detailed Information on Pods
```sh
kubectl get pods -o wide
```

### 7. Get Descriptive Information of a Pod
```sh
kubectl describe pod <PODnE>
```

### 8. Get Logs of a Pod/Container
```sh
kubectl logs <PODnE>
kubectl logs -f <PODnE>
```

### 9. Get a Shell Inside the Pod Container
```sh
kubectl exec -it <PODnE> sh
```

### 10. Forward Pod Port to Local Machine
```sh
kubectl port-forward <PODnE> 1234:80
```

### 11. Create Simple Deployment
```sh
kubectl run nginxdeployment --image=nginx
```

### 12. Delete a Pod from the Cluster
```sh
kubectl delete pod <PODnE>
```

### 13. Get Resources from Other nespaces
```sh
kubectl get pods -n abc
```

### 14. Get All Available API Resources
```sh
kubectl api-resources
```

### 15. Get Resource Output in YAML Format
```sh
kubectl get pod <PODnE> -o yaml
```

### 16. Get Multiple Commands Output in the Same Command
```sh
kubectl get nodes,pods,svc
```

### 17. Get All Resources in All nespaces
```sh
kubectl get all -A
```

### 18. Impersonate and Authorization
#### 18.1 Check User Permissions
```sh
kubectl auth can-i create pods
```
#### 18.2 List All Permissions
```sh
kubectl auth can-i --list
```
#### 18.3 Check If Can Create Pods in nespace
```sh
kubectl auth can-i create pods
```

### 19. Get Service Endpoints
```sh
kubectl get endpoints
```


## References
- [Docker CLI Reference](https://docs.docker.com/engine/reference/commandline/cli/)
- [Kubernetes `kubectl` Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)