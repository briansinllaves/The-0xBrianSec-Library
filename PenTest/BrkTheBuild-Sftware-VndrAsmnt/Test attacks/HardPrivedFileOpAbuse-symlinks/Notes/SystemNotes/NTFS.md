 ```
 NTFS Symbolic Links:

Link one file to another in the filesystem.
Creation requires admin privilege.

NTFS Mount Points or Directory Junctions:

No admin privilege needed for execution.
Used to link directories.
Can link to directories on the same or different filesystem.
Path resolution usually follows the junction.

Example: Accessing C:\Dir\file.txt may actually open C:\Other\file.txt due to junction.

Works across volumes, allowing redirection between different drives (e.g., C:\Dir to D:\OtherDir).

Requirements for creation:
The source directory must be empty.
The user needs write access to the parent directory.
Allows creation of junctions to any target location, regardless of write permissions on the target.

Tools for Directory Junctions:

CreateMountPoint tool (from symboliclink-testing-tools).

Commands like mklink and PowerShell's New-Item -Type Junction can create regular junctions.

	Usage examples for CreateMountPoint:
        createmountpoint.exe vuln/path target
        Createmountpoint.exe vulnpath \\rpccontrol\\
followed by symbolic link from kp31337.tmp to ""C:\Windows\Help\en-US\credits.rtf"" 

```

