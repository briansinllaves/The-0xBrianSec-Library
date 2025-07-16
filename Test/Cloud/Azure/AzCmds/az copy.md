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
    azcopy copy "https://pzidp001.blob.core.windows.net/yumreposcript/startup.sh?sv=2018-03-28&ss=bfqt&srt=sco&sp=rlacp&se=2100-07-31T16:41:42Z&st=2019-07-31T08:41:42Z&spr=https&sig=1iM%3D" "/tmp/customscript/startup.sh" --recursive=true  
    ```

