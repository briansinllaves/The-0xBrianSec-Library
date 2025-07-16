 normally used to give an application time to  stop its operations on a file, if another process requests conflicting  access to the file. 

This could for example be a background backup  service backing off during an ongoing file read, if another process attempts to write to the same file. An opportunistic lock can be set up  to block the new process’ access and give the backup service time to  stop its operation and close the file. 

The process trying to open the file for writing will then proceed as normal, not knowing that it has  been temporarily blocked. Without an opportunistic lock, the writing  process would have received a SHARING_VIOLATION and would have needed to  handle this scenario.


