### 1. **Using `smbclient`**
`smbclient` is a command-line tool in Linux that allows you to access shared resources on Windows machines using SMB/CIFS protocols.

```bash
smbclient //server/share -U DOMAIN\\userne
```

- **Example:**

  ```bash
  smbclient //192.168.1.10/sharedfolder -U DOMAIN\\john
  ```

After running the command, you will be prompted for the password. This allows you to access shared folders and files on a Windows server.

### 2. **Using `winexe` or `wmiexec.py` (from Impacket)**
These tools allow you to execute commands on a remote Windows machine using valid Windows credentials.

#### **winexe**
`winexe` allows you to run commands on a Windows machine from Linux.

```bash
winexe -U DOMAIN\\userne%password //hostname_or_ip 'command'
```

- **Example:**

  ```bash
  winexe -U DOMAIN\\john%password //192.168.1.10 'cmd.exe /c dir C:\\'
  ```

#### **wmiexec.py** (Impacket)
`wmiexec.py` from the Impacket suite allows you to execute commands on a remote Windows machine over WMI.

```bash
python3 wmiexec.py DOMAIN/userne:password@hostname_or_ip
```

- **Example:**

  ```bash
  python3 wmiexec.py DOMAIN/john:password@192.168.1.10
  ```

This will open an interactive command shell on the remote Windows machine.

### 3. **Using `rdesktop` or `xfreerdp` for Remote Desktop Access**
You can use RDP clients like `rdesktop` or `xfreerdp` to connect to a Windows machine using Windows credentials.

#### **rdesktop**
```bash
rdesktop -u DOMAIN\\userne -p password hostname_or_ip
```

- **Example:**

  ```bash
  rdesktop -u DOMAIN\\john -p password 192.168.1.10
  ```

#### **xfreerdp**
```bash
xfreerdp /u:DOMAIN\\userne /p:password /v:hostname_or_ip
```

- **Example:**

  ```bash
  xfreerdp /u:DOMAIN\\john /p:password /v:192.168.1.10
  ```

### 4. **Using `smbmount` or `mount.cifs`**
You can mount a Windows shared folder on your Linux machine using `mount.cifs` (part of the `cifs-utils` package).

```bash
sudo mount.cifs //server/share /mnt/mountpoint -o user=DOMAIN\\userne
```

- **Example:**

  ```bash
  sudo mount.cifs //192.168.1.10/sharedfolder /mnt/windows_share -o user=DOMAIN\\john
  ```

You will be prompted for the password, and after successful authentication, the share will be mounted to `/mnt/windows_share`.

