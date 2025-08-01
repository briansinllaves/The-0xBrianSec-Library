### **Move a File**

To move or rene a file in Linux, you can use the `mv` command:

```bash
# Move or rene a file
mv src.txt dst.txt
```

### **Show Properties and Methods**

In Linux, displaying the properties and methods of an object isn't as straightforward because Linux primarily deals with text-based data. However, if you're dealing with structured data, you might use tools like `jq` (for JSON) or `xmlstarlet` (for XML). For simple cases, use `ls` or `stat`:

```bash
# List detailed file properties
stat somefile.txt

# List available methods/functions for a command (using man)
man ls
```

### **Download a File via HTTP**

To download a file using HTTP, you can use `wget` or `curl`:

```bash
# Using wget to download a file
wget http://10.10.10.10/nc.exe -O nc.exe

# Or using curl to download a file
curl -o nc.exe http://10.10.10.10/nc.exe
```

- **Explanation:** 
  - `wget http://10.10.10.10/nc.exe -O nc.exe` downloads the file from the given URL and saves it as `nc.exe`.
  - `curl -o nc.exe http://10.10.10.10/nc.exe` performs the same operation using `curl`.

### **List Loaded Functions**

To list all functions currently defined in your Bash session:

```bash
# List all loaded functions
declare -F
```
