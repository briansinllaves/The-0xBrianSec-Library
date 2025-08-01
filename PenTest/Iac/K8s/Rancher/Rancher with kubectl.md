#### Documentation and Resources
- [Rancher CLI with kubectl Utility](https://docs.ranchermanager.rancher.io/v2.5/reference-guides/cli-with-rancher/kubectl-utility)
- [Managing Kubernetes Secrets using kubectl](https://kubernetes.io/docs/tasks/configmap-secret/managing-secret-using-kubectl/)
- [Kubernetes Basics Tutorial](https://kubernetes.io/docs/tutorials/kubernetes-basics/explore/explore-interactive/)
- [Download Rancher CLI](https://github.com/rancher/cli/releases)
#### 1. Install kubectl
Download and install kubectl:
```bash
curl.exe -LO "https://dl.k8s.io/release/v1.25.0/bin/windows/amd64/kubectl.exe"
```

#### 2. Log in to Rancher
Log in to Rancher using your token and cluster details:
```bash
.\rancher.exe login https://rancher-sandbox.test.com --skip-verify -t token-wv:y7
```

#### 3. List All Projects
```bash
./rancher projects ls
```

#### 4. Switch Context to a Specific Project
```bash
./rancher context switch c-qqqvj:p-zzzmt
```

#### 5. Get Nodes
```bash
kubectl get nodes
```

#### 6. List All nespaces
```bash
kubectl get nespace
```

#### 7. List All Pods in All nespaces
```bash
./rancher kubectl get pods --all-nespaces
```

#### 8. Describe Pods
```bash
kubectl describe pods
```

#### 9. Execute Commands in a Pod's Environment
```bash
./rancher kubectl exec -n $nespace $pod -- env
```

#### 10. Open a Shell in a Pod
```bash
./rancher kubectl exec -n $nespace $pod --stdin --tty -- /bin/bash
```

#### 11. Get Secrets in All nespaces
```bash
./rancher kubectl get --all-nespaces -o wide secrets -o json | jq ".items[].data"
```
