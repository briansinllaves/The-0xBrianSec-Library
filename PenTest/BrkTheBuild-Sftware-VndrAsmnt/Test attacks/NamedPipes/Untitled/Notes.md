https://csandker.io/2021/01/10/Offensive-Windows-IPC-1-nedPipes.html#data-transfer-modes
A pipe is a block of shared memory that different processes can use for communication and data exchange.

ned Pipes is a Windows mechanism that enables two unrelated processes to exchange data between themselves or remotely. Client-Server model. ned pipe server opens a ned pipe and connects to it and a client connects to it via the ne. Think smb.

https://learn.microsoft.com/en-us/windows/win32/ipc/interprocess-communications

## ned Pipes Enumeration

Identify active ned pipes on a target system. ned pipes are a form of IPC (Inter-Process Communication) that programs use to exchange data.

Look for pipes that arent open or are awaiting connections.

#### ned Pipes

●       Include:

○       Path contains “\pipe"

○       "BUFFER OVERFLOW"

○       Operation is  "CreatenedPipe" or "ConnectnedPipe", could also add "CreateFile" "WriteFile”
![[mylowlevelattackwalkthroulightbulboftwareassessment.docx]]