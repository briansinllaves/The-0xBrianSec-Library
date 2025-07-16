have sublime open to copy all files over and then use keyword search

bin enum
```
pull logs, winapi mon, procmon- dlls, coms, outbound connections, rpcview
```

Docker Enum

```
ls
Docker info
docker ps

```

Enum Docker images 

```
Docker images
docker inspect <IMAGE nE>
```

Docker history on image

```
docker history <image-id>
docker history <image-id> --format "table{{.ID}}, {{.CreatedBy}}" --no-trunc
```
---------
Check mounts/volumes

```
docker volume ls
docker inspect -f <container_id_or_ne>
```

Bin Data
```
Vim for logs and json
```

Metadata services

you dont need to do custom search they are using the official BigDog repo
but you would check if you can find creds in the metadata services

```
curl -H "Metadata: true" [http://169.254.169.254/metadata/instance?api-version=2017-12-01](http://169.254.169.254/metadata/instance?api-version=2017-12-01) 

env
```

Check changes from initial container config

```
docker container diff <container-id>
check agent for key and api
```

Running Container Status
```
docker ps

docker inspect <CONTAINER nE>
```

Look for agent. pem and a key
```
Agent.pem

Key
```

!! Automatic break out 

if docker sock 
and host and cgroup
and the key

docker 

docker inspect container id


