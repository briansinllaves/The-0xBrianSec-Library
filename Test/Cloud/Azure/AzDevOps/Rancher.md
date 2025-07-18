### Install kubectl for Rancher
```shell
curl.exe -LO "https://dl.k8s.io/release/v1.25.0/bin/windows/amd64/kubectl.exe"
```

Reference: [kubectl Utility with Rancher](https://docs.ranchermanager.rancher.io/v2.5/reference-guides/cli-with-rancher/kubectl-utility)

### Rancher CLI Commands

#### Login to Rancher
```shell
./rancher login https://rancher-sandbox.ABCD.com -t token-xxxxx
```

#### List Projects in Rancher
```shell
./rancher projects ls
```

#### Switch to a Project Context
```shell
./rancher context switch $project
```

#### List Pods in All nespaces
```shell
./rancher kubectl get pods --all-nespaces
```

#### Execute a Command in a Pod
```shell
./rancher kubectl exec -n $nespace $pod -- env
```

#### Open a Shell Session in a Pod
```shell
./rancher kubectl exec -n $nespace $pod --stdin --tty -- /bin/bash
```

#### List Secrets in All nespaces
```shell
./rancher kubectl get --all-nespaces -o wide secrets -o json | jq ".items[].data"
```

#### Login to Rancher with Skip-Verify Option
```shell
.\rancher.exe login https://rancher-sandbox.ABCD.com --skip-verify -t token-wv:56
```

Reference: [Rancher CLI](https://docs.ranchermanager.rancher.io/v2.5/reference-guides/cli-with-rancher/rancher-cli)