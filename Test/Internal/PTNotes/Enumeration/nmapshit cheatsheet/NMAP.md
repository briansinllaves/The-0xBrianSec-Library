list alive, and then open, and then service enum

Cat targets.txt | sort -v | grep 10 > targets_internal.txt

sudo nmap -vvv -Pn  -T3 -O --top-10000 --open -iL targets_internal.txt -oA nmap_tcp_all_targets_internal

```
sudo nmap -vv -n -Pn --top-ports 10000 --open -iL targets_internal.txt -oA nmap_tcp_top10000_targets_internal
```