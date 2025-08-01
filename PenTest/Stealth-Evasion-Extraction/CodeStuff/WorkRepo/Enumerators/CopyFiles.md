This C# program `CopyFile.exe` enumerates remote or local computers, accesses user directories, and attempts to copy specific files (e.g., PowerShell console history). It reads target computers either from a file or a single input, uses multiple threads for faster processing, and stores results in a specified output directory.

### How to Execute:
1. **Basic execution:**
   ```bash
   Copyfile.exe /target:<Computerne> /out:<OutputDirectory> /threads:<NumberOfThreads>
   ```

2. **Remote execution example:**
   ```bash
   Copyfile.exe /target:192.168.1.10 /out:C:\output /threads:5
   ```

In this example, the program will connect to the remote system at `192.168.1.10`, try to access the `C$` share, and copy the PowerShell console history files for each user into the `C:\output` directory using 5 threads.