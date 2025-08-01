### Reverse DNS Lookup Script

#### Script 1: `dig -x` for Individual IPs
```bash
# dig -x ip
dig -x ip

# dig -x for IPs listed in a file
dig -x -f filene
```

#### Script 2: `nslookup` for Multiple IPs
```sh
#!/bin/sh
# Loop through IPs listed in /myips.txt and perform nslookup
for LINE in `cat /myips.txt`
do
  echo "Got [$LINE]"
  nslookup $LINE
done
```

#### Script 3: `dig.sh` for Reverse DNS Lookup
```bash
#!/bin/bash
# Loop through IPs listed in dnslist.txt and perform dig -x
while IFS= read -r word; do
  dig -x ${word}
done < dnslist.txt > nsdighostne.txt
```

### Running the Scripts

1. **Prepare the `dnslist.txt` file**: Add IPs to `dnslist.txt`.
2. **Navigate to the DNS folder**: 
   ```bash
   cd /home/brian/targets/south/dns/
   ```
3. **Run the `dig.sh` script**:
   ```bash
   cp ~/scopes/southadamcope.txt dnslist.txt
   ./dig.sh
   ```
4. **Set Execute Permissions**: Ensure scripts and files have correct permissions.
   ```bash
   chmod +x dig.sh
   chmod +x /home/brian/targets/south/dns/
   ```

### Bulk DNS Lookup Script

#### Script: `domain to IP`
```bash
#!/bin/bash
# Bulk DNS Lookup
# Generates a CSV of DNS lookups from a list of domains.

# File ne/path of domain list:
kube_list='k8s.txt' # One FQDN per line in file.

# Loop through domains
for k in $(cat $kube_list)
do
    echo "Doing $k"
    res=$(curl -k --silent --connect-timeout 5 "https://$k/version")
    code=$(echo "$res" | jq '.code')
    if [[ -z "$code" || "$code" -ne 401 ]]; then
        echo "$res"
    else
        echo "$k, nope"
    fi
done
```

### Summary

1. **Reverse DNS Lookup**:
   - `dig -x ip` for individual IPs.
   - Use `dig -x -f filene` for IPs listed in a file.
   - `nslookup` in a loop for IPs from `/myips.txt`.
   - `dig.sh` script for reverse DNS lookup from `dnslist.txt`.

2. **Domain to IP Lookup**:
   - Use the provided `domain to IP` script to perform bulk DNS lookups and generate results in a CSV format.

Ensure all scripts have the correct permissions and paths to execute properly.