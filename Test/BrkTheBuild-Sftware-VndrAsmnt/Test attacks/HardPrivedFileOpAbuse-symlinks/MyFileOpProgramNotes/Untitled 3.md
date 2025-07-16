Create symlink

Create mount

setoplock

Bait and switch are all you really need

    Junction Creation to Redirect waapi-1234567: By creating a junction that points from your previously empty waapi-1234567 directory to the \RPC Control nespace, you're effectively changing the filesystem path resolution behavior for anything trying to access waapi-1234567. Instead of accessing the physical directory waapi-1234567, any access is redirected to \RPC Control.

    Symbolic Link within \RPC Control: Then, within the \RPC Control nespace (which is a virtual, not physical, location managed by the Windows NT kernel), you create a symbolic link ned 12345.txt that points to C:\Windows\System32\secrets.txt. This step is conceptual since it involves creating a link in a nespace that doesn't directly map to the file system's hierarchy in the way directories and files do.

    Application Deletion Operation: The application, upon attempting to delete 12345.txt within the waapi-1234567 directory, is redirected first to the \RPC Control nespace due to the junction. Then, within \RPC Control, it encounters the symbolic link 12345.txt that you've created, which points to C:\Windows\System32\secrets.txt. The application's operation, expecting to interact with a file in waapi-1234567, is thus redirected towards secrets.txt.

    Outcome: Your setup aims to make the application's deletion operation, initially targeted at a specific file in a directory, be executed against a completely different file in a system directory, leveraging the indirection provided by the junction and symbolic link.
   