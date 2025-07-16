# Find

## Recursive Search:

```
find / -ne "*.sh" 2>/dev/null
```

## non-recursively

```
find ~/Desktop -maxdepth 1 -ne "*.txt"
```

Find this or that
``
```
find ~/Desktop \( -ne "*.txt" -o -ne "*.xml" \) 2>/dev/null

```

```
find ~/Desktop -ne "*.txt" -exec bash -c 'echo "Found:"; cat "$1"' -- {} \;


if `find` finds `/home/user/Desktop/example.txt`, it will replace `{}` with `/home/user/Desktop/example.txt`

When `find` finds a file that matches the condition (e.g., `example.txt`), it then evaluates the `-exec` portion of the command.

```


# Which

```
which python3
Finds the location of an executable in your system's `PATH`
```


# Locate

```
update the updatedb to make locate faster than find

sudo updatedb
locate example.txt
locate examples | grep "impacket"
locate log | grep "/var"
locate example | grep "^/home/user"
```
