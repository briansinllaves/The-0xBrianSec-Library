```shell
remove child dir contents or child child 

find ~/targets/global/empt/americas -mindepth 1 -type d -exec bash -c 'rm -r "$1"/*' bash {} \;

```
