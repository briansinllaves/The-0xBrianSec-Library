```
Here’s a C++ program that performs the shellcode prechecks you're looking for:

### Shellcode Prechecker in C++:
```

```
```cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <windows.h>
#include <psapi.h>
#include <iterator>

// Function to check if the shellcode contains any null bytes
bool CheckNullBytes(const std::vector<unsigned char>& shellcode) {
    for (const auto& byte : shellcode) {
        if (byte == 0x00) {
            std::cerr << "Null byte found in shellcode!" << std::endl;
            return false;
        }
    }
    std::cout << "No null bytes in shellcode." << std::endl;
    return true;
}

// Function to check if the shellcode is for 32-bit or 64-bit architecture
void CheckArchitecture(const std::vector<unsigned char>& shellcode) {
    size_t shellcodeSize = shellcode.size();

    if (shellcodeSize % 8 == 0) {
        std::cout << "Shellcode appears to be for 64-bit architecture." << std::endl;
    } else if (shellcodeSize % 4 == 0) {
        std::cout << "Shellcode appears to be for 32-bit architecture." << std::endl;
    } else {
        std::cerr << "Shellcode size does not align with typical 32-bit or 64-bit architecture." << std::endl;
    }
}

// Function to load shellcode from a binary file
bool LoadShellcodeFromFile(const std::string& filene, std::vector<unsigned char>& shellcode) {
    std::ifstream file(filene, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file " << filene << std::endl;
        return false;
    }

    // Read file content into the vector
    file.unsetf(std::ios::skipws);
    shellcode.insert(shellcode.begin(), std::istream_iterator<unsigned char>(file), std::istream_iterator<unsigned char>());
    return true;
}

// Function to check if the shellcode size fits the available memory
bool CheckShellcodeFits(SIZE_T shellcodeSize, SIZE_T availableMemory) {
    if (shellcodeSize <= availableMemory) {
        std::cout << "Shellcode can fit into allocated memory." << std::endl;
        return true;
    } else {
        std::cerr << "Shellcode size exceeds available memory!" << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: <program.exe> <shellcode_file> <available_memory>" << std::endl;
        return 1;
    }

    std::string filene = argv[1];
    SIZE_T availableMemory = std::stoull(argv[2]);  // Assume available memory is provided as input

    std::vector<unsigned char> shellcode;

    // Load shellcode from the file
    if (!LoadShellcodeFromFile(filene, shellcode)) {
        return 1; // Exit if file could not be loaded
    }

    // Perform null byte check
    if (!CheckNullBytes(shellcode)) {
        return 1; // Exit if null bytes are found
    }

    // Perform architecture check
    CheckArchitecture(shellcode);

    // Perform memory fit check
    if (!CheckShellcodeFits(shellcode.size(), availableMemory)) {
        return 1; // Exit if shellcode doesn't fit in memory
    }

    std::cout << "All prechecks passed." << std::endl;
    return 0;
}
```

### Explanation:
1. **Check for Null Bytes**: The `CheckNullBytes()` function checks the shellcode for null (`0x00`) bytes that can cause issues during injection.
   
2. **Check Architecture**: The `CheckArchitecture()` function estimates whether the shellcode is for a 32-bit or 64-bit system based on its size alignment (8-byte alignment for 64-bit, 4-byte for 32-bit).

3. **Shellcode Fits Memory**: The `CheckShellcodeFits()` function checks if the shellcode's size is less than or equal to the available memory in the process. This ensures that the shellcode can fit in the allocated memory.

4. **Load Shellcode from File**: The `LoadShellcodeFromFile()` function loads the raw shellcode from a binary file into a vector for processing.

**Run**:
   ```bash
   shellcode_prechecker.exe shellcode.bin 2048  # Assuming 2048 bytes of available memory
   ```

   - **`shellcode.bin`**: This is the file containing your raw shellcode.
   - **`2048`**: Replace with the actual available memory in the target process (in bytes).
