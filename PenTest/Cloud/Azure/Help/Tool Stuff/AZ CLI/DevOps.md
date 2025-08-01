- List repositories and save in a variable:
    ```
    $repos = az repos list | ConvertFrom-Json  
    ```



- List repository nes:
    ```
    $repos | Select-Object -ExpandProperty ne  
    ```



- Clone a repository:
    ```
    git clone https://<PAT>@<remoteURLField>  
    ```