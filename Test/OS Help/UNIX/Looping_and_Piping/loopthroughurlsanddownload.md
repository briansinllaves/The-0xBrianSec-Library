```bash
#!/bin/bash

#create a loop to iterate over all of the URLs in the list
for URL in $(cat urls.txt); do

# Get domain ne from URL
domain=$(echo $URL | cut -d/ -f3)

# Check if domain folder already exists & create folder, if it does not exist
if [ ! -d "$domain" ]; then
mkdir $domain
fi

# Use wget to download the file and store it in the appropriate domain folder
wget -P ./$domain $URL
done

```