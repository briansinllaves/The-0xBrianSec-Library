1. Install azcopy:
    
  
    ```
    mkdir -p /tmp/customscript  
    cd /tmp/customscript/  
    wget https://aka.ms/downloadazcopy-v10-linux  
    tar -xvf downloadazcopy-v10-linux  
    cp ./azcopy_linux_amd64_*/azcopy /usr/bin/  
    ```
    
2. Copy files:
    

    ```
    azcopy copy "https://p1.blob.core.windows.net/yumreposcript/startup.sh?" "/tmp/customscript/startup.sh" --recursive=true  
    ```

