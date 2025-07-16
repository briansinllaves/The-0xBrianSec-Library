Containers running with elevated privileges or mounted sensitive directories are often the targets of such escapes

#### Step-by-Step Process

1. **List Running Docker Containers**
    ```bash
    docker ps
    ```

2. **Identify the Target Container**
    - Look for the agent container.

3. **Note the Container ID**
    - Make a note of the container ID for the agent container.

4. **Check for Potential Escape Points (Mounted Sensitive Directories)**
    ```bash
    docker container diff <agent_container_id>
    ```
    - Look for the following paths in the output:
        - `/var/run/docker.sock`
        - `/host/sys`
        - `/host/sys/fs/cgroup`
    
    - If any of these paths are found, it suggests that sensitive directories are mounted within the container, it indicates a potential breakout point.

5. **Execute Shell in the Container**
    ```bash
    docker exec -it <agent_container_id> /bin/bash
    ```
    Example:
    ```bash
    docker exec -it 4e89c56dbb02 /bin/bash
    ```

6. **Inside the Shell**
    - **Check Environment Variables:**
        ```bash
        env
        ```
        - Look for sensitive information like `DD_API_KEY`, site information, etc.

7. **Inspect Docker Images**
    ```bash
    docker images
    ```
    
    - Check the history of a specific image for potentially sensitive information:
    ```bash
    docker history <image-id> --format "table{{.ID}}, {{.CreatedBy}}" --no-trunc
    ```

