### **Structure of an Assembly Program**

An assembly program is typically divided into three sections:

1. **Data Section**
2. **BSS Section**
3. **Text Section**

---

### **The Data Section**

- **Purpose:**  
  The data section is used for declaring initialized data or constants. The values declared in this section do not change at runtime. This is where you can declare constant values, file nes, buffer sizes, and similar static data.

- **Syntax:**
  ```asm
  section .data
  ```

- **Example:**
  ```asm
  section .data
  msg db 'Hello, World!', 0x0A  ; A message string
  len equ $ - msg               ; The length of the message
  ```

---

### **The BSS Section**

- **Purpose:**  
  The BSS section is used for declaring variables that are uninitialized at the start of the program. This section is where you define space for variables that will be used during the program’s execution.

- **Syntax:**
  ```asm
  section .bss
  ```

- **Example:**
  ```asm
  section .bss
  num resb 4  ; Reserve 4 bytes for the variable 'num'
  ```

---

### **The Text Section**

- **Purpose:**  
  The text section is where the actual code of the program is written. This section must start with the declaration `global _start`, which tells the linker the entry point of the program (i.e., where execution begins).

- **Syntax:**
  ```asm
  section .text
     global _start
  _start:
  ```

- **Example:**
  ```asm
  section .text
      global _start
  _start:
      mov eax, 1      ; System call number for sys_exit
      xor ebx, ebx    ; Exit code 0
      int 0x80        ; Call kernel
  ```

---

### **Typical Assembly Statements**

Here are some common instructions used in assembly language:

- **INC COUNT:**  
  Increment the memory variable `COUNT`.
  ```asm
  INC COUNT
  ```

- **MOV TOTAL, 48:**  
  Move the value `48` into the memory variable `TOTAL`.
  ```asm
  MOV TOTAL, 48
  ```

- **ADD AH, BH:**  
  Add the contents of the `BH` register to the `AH` register.
  ```asm
  ADD AH, BH
  ```

- **AND MASK1, 128:**  
  Perform an AND operation between the variable `MASK1` and the value `128`.
  ```asm
  AND MASK1, 128
  ```

- **ADD MARKS, 10:**  
  Add `10` to the variable `MARKS`.
  ```asm
  ADD MARKS, 10
  ```

- **MOV AL, 10:**  
  Move the value `10` into the `AL` register.
  ```asm
  MOV AL, 10
  ```

---
