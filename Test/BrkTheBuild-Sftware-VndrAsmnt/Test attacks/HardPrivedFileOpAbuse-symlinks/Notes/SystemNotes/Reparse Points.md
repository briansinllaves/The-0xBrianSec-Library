Windows Reparse Points are a feature of the Windows operating system that allows for the creation of special links or shortcuts to files or folders located elsewhere on your computer or on the network. These links are called "reparse points" because they are used to "reparse" the location of a file or folder.  can think "reprocess" orsetting a folder to quick access in  file explorer

Example: if you have a folder on your computer with a lot of files in it, you can create a reparse point to the folder. This will allow you to access the files contained within the folder without having to physically move the folder. 

Reparse points are also useful for redirecting access to files or folders between different data storage systems. 

example: if you have a file in one system but want to access it from another system, you can create a reparse point to the file so that it can be accessed from either location. 

for creating shortcuts to files or folders on a network, allowing you to quickly access them from anywhere on the network.

You are user. you create a mount point of the (prived folder living in userland, that has the file operation you would like to abuse  to \\rpc control. then  

------------------------------------------------------------------
There are several types of reparse points, including:

Mount Points: Directories that point to the root of another volume, allowing you to integrate volumes into a single nespace.

Symbolic Links (Symlinks): Pointers that can link to files or directories within the same system or across network locations.

Directory Junctions: A type of mount point that points to directories either on 
the local computer or on a network location.

Volume Mount Points: Directories that act as entry points to entire volumes.