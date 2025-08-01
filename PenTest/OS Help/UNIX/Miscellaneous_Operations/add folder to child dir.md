``` shell
add scope to sub dirs

find kali/Desktop/scoped/ -type d -exec mkdir {}/dns \;  edit

!/bin/bash

par_dir="path/to/parentdir"
for dir in "$par_dir"/*/; do
   mkdir -p "$dir/dns"
done

```

