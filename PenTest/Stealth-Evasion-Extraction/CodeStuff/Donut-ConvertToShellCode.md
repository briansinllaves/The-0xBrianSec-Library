- https://github.com/TheWover/donut
- **Description**: Donut is a tool that converts PE files, .NET assemblies, and other payloads into shellcode. While it doesn't handle process hollowing directly, it is often used alongside other process hollowing tools to load shellcode into a hollowed process.
- **Hollowing Functionality**: Use Donut to convert your executable into shellcode, which you can inject into a hollowed process.
- **Usage**: Combine Donut with a process hollowing tool (e.g., a custom C++ injector) to load the shellcode into a hollowed-out process.

```
donut -f 1 yourfile.exe

```