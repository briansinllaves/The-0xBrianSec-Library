Here's the revised version of your content with improved structure and clarity:

---

### **File Streams and File Descriptors**

The system treats any input or output data as a stream of bytes. There are three standard file streams:

1. **Standard Input (stdin):** Used for input operations.
2. **Standard Output (stdout):** Used for output operations.
3. **Standard Error (stderr):** Used for outputting error messages.

**File Descriptor:**
- A file descriptor is a 16-bit integer that acts as an identifier for a file. When a new file is created or an existing file is opened, the file descriptor is used to access the file.
- The file descriptors for the standard streams are:
  - **stdin:** 0
  - **stdout:** 1
  - **stderr:** 2

**File Pointer:**
- A file pointer specifies the location for subsequent read/write operations within the file, measured in bytes from the beginning of the file.
- Each open file has an associated file pointer that is initialized to zero when the file is opened.

### **File Handling System Calls Example**

The following assembly code demonstrates basic file handling using system calls:

```asm
section .text
    global _start         ; Must be declared for using gcc

_start:                   ; Tell linker entry point

    ; Create the file
    mov eax, 8            ; sys_creat system call number
    mov ebx, file_ne    ; File ne
    mov ecx, 0777         ; File permissions (read, write, execute for all)
    int 0x80              ; Call kernel

    mov [fd_out], eax     ; Store file descriptor in fd_out
    
    ; Write into the file
    mov edx, len          ; Number of bytes to write
    mov ecx, msg          ; Message to write
    mov ebx, [fd_out]     ; File descriptor 
    mov eax, 4            ; sys_write system call number
    int 0x80              ; Call kernel
	
    ; Close the file
    mov eax, 6            ; sys_close system call number
    mov ebx, [fd_out]     ; File descriptor
    int 0x80              ; Call kernel
    
    ; Write the message indicating end of file write
    mov eax, 4            ; sys_write system call number
    mov ebx, 1            ; File descriptor for stdout
    mov ecx, msg_done     ; Message to indicate completion
    mov edx, len_done     ; Length of the message
    int 0x80              ; Call kernel
    
    ; Open the file for reading
    mov eax, 5            ; sys_open system call number
    mov ebx, file_ne    ; File ne
    mov ecx, 0            ; Read-only access
    mov edx, 0777         ; Permissions (read, write, execute for all)
    int 0x80              ; Call kernel
	
    mov [fd_in], eax      ; Store file descriptor in fd_in
    
    ; Read from the file
    mov eax, 3            ; sys_read system call number
    mov ebx, [fd_in]      ; File descriptor
    mov ecx, info         ; Buffer to store read data
    mov edx, 26           ; Number of bytes to read
    int 0x80              ; Call kernel
    
    ; Close the file
    mov eax, 6            ; sys_close system call number
    mov ebx, [fd_in]      ; File descriptor
    int 0x80              ; Call kernel
    
    ; Print the read info
    mov eax, 4            ; sys_write system call number
    mov ebx, 1            ; File descriptor for stdout
    mov ecx, info         ; Data to print
    mov edx, 26           ; Length of the data
    int 0x80              ; Call kernel
       
    ; Exit the program
    mov eax, 1            ; sys_exit system call number
    int 0x80              ; Call kernel

section .data
    file_ne db 'myfile.txt'             ; File ne
    msg db 'Welcome to Tutorials Point'   ; Message to write into the file
    len equ $-msg                         ; Calculate the length of the message

    msg_done db 'Written to file', 0xa    ; Message indicating completion
    len_done equ $-msg_done               ; Calculate the length of the completion message

section .bss
    fd_out resb 1          ; Reserve 1 byte for output file descriptor
    fd_in  resb 1          ; Reserve 1 byte for input file descriptor
    info   resb 26         ; Reserve 26 bytes for storing read data
```

### **Explanation of the Code:**

1. **Creating a File:**
   - The program uses `sys_creat` to create a file with the specified ne and permissions.

2. **Writing to the File:**
   - The message `Welcome to Tutorials Point` is written to the file using `sys_write`.

3. **Closing the File:**
   - The file is closed using `sys_close`.

4. **Writing a Completion Message:**
   - A message indicating that the file has been written is output to the console.

5. **Opening the File for Reading:**
   - The file is opened in read-only mode using `sys_open`.

6. **Reading from the File:**
   - The data is read from the file and stored in the buffer `info`.

7. **Printing the Read Data:**
   - The data read from the file is printed to the console using `sys_write`.

8. **Exiting the Program:**
   - The program exits using `sys_exit`.

This example demonstrates the fundamental system calls for file handling in Linux assembly, including creating, writing to, reading from, and closing a file, as well as printing messages to the console.