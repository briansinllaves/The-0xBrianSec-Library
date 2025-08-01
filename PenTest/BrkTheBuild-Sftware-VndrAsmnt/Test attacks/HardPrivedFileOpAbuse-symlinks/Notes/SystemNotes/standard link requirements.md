Junctions

Target Directory Requirement:
        Must target a directory, not a file. like " \rpc control"
	Empty Directory for Junction Point:
        The directory where the junction is created doesn’t need to be empty.
    Permissions:
        User must have appropriate permissions to the target directory.
    Tool:
        Can be created using the mklink /J command or similar tools.

Mount Points
    Volume Mounting:
        Used to mount another volume to a directory.
    Empty Target Directory:
        The directory where the mount point is created must be empty.
    File System Support:
        Both the target and source must be NTFS volumes.
    Permissions:
        Requires administrative privileges.
    Tool:
        Typically managed through Disk Management tool or mountvol command.

Symbolic Links (Symlinks)
    File or Directory Target:
        Can point to either files or directories.
    Local or Remote Targets:
        Can target both local and network paths.
    Permissions:
        Creation typically requires administrative privileges unless Developer Mode is enabled on Windows 10/11 or specific group policies are set.
    Tool:
        Created using the mklink command or similar tools. For directories, use mklink /D; for files, just mklink.

Common to All
    File System:
        Generally, the file system should be NTFS as FAT/FAT32 does not support these features.
    Path Existence:
        The target path must exist at the time of creation.
    No Cyclic Links:
        Windows prevents the creation of cyclic paths (e.g., a symlink or junction that ultimately points to itself through a chain of links).