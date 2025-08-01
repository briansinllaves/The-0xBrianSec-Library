### **Source Code Assessment & Code Review Guidelines**

#### **Estimated Time Management**

- **File Review Duration:**
  - Spend approximately **1 hour** per file during the review to ensure thoroughness without getting bogged down.

- **Function Review Duration:**
  - Prioritize functions, spending no more than **20 minutes** on each. This helps maintain a balance between depth and breadth during the review.

- **Editing Files:**
  - If you need to make edits, **copy the file** to Visual Studio for modifications. This prevents unintended changes and keeps the original code intact for reference.
#### **Objective**

- **Main Focus:**
  - Identify and understand the primary functions and functionality that stand out.
  - Decipher what the code is doing by mapping out important functions and following their logic and flow.

- **Additional Focus Areas:**
  - Investigate Windows service definitions to understand the interaction with system services.
  - Use Process Explorer to analyze which DLLs are being called and load those into your analysis environment.
  - Utilize Windows utilities to identify other resource interactions that might be relevant to your review.

#### **Checklist for Code Review**

1. **Process Explorer Analysis:**
   - Review services and executable overviews using Process Explorer to get a high-level view of the running processes and their associated DLLs.
   - Identify and isolate the scope by examining the DLLs in use, focusing on those that seem related to critical functionalities.
   - Open interesting DLLs in dnSpy for a deeper dive into the code.

2. **Initial Function Scan:**
   - Write down functions that appear interesting or critical at first glance. These might be entry points, handlers, or functions with security implications.

3. **Key Areas to Review:**
   - **Functions:**
     - Navigate functions using `backspace` or `alt-right arrow` to trace back to their callers or move forward to their callees.
     - Follow function calls and observe the source file and loading behavior to understand the context in which functions operate.
   - **Impersonation and Security:**
     - Look for impersonation logic, hardcoded items, and security controls. 
       - **Keywords for Impersonation:** `Impersonate`, `RunAs`, `Delegate`.
       - **Keywords for Hardcoded Items:** `password`, `key`, `token`, `secret`.
       - **Keywords for Security Controls:** `ACL`, `authentication`, `authorization`, `access`.
     - Determine if the application is hosted. 
       - **Keywords for Cloud Hosting:** `Azure`, `GCP`, `AWS`, `cloud`, `S3`, `Blob`, `storage`, `AppService`, `EC2`.
   - **Keyword Search:**
     - Focus on keywords such as:
       - `admin`, `proxy`, `socket`, `network`, `net`, `web`
       - Approval processes (`Request`)
       - Security-related terms:
         - `locks`, `permissions`, `passwords`, `encrypt`, `decrypt`
         - `getencryptedclientpassword`
         - `uninstall`, `remove`, `security issue`
         - **Identify Security Bypass:** Search for functions that **don’t** call security checks or bypass standard security mechanisms.
	         - Look for Critical Actions: Focus on functions that perform sensitive operations like file access, network communication, or system modifications.
			- Check for Missing or Insufficient Validation: Ensure these functions validate the user's permissions or the safety of inputs before proceeding.
			- Search for Conditional Logic: Pay attention to conditional statements (`if`, `else`, `case`) that might allow the function to skip necessary checks under certain conditions.
		- Keywords to Search For:
			- Terms like `auth`, `role`, `permission`, `validate`, `check`, `security`, `access`, and `bypass`.
			- Look for actions that are performed **without** these checks, especially in functions dealing with:
		    - **File operations:** `delete`, `write`, `create`.
		    - Network operations: `send`, `receive`, `connect`.
		    - **System commands:** `exec`, `run`, `shell`.
   - **Function Flow Analysis:**
     - Trace where functions are called to understand their purpose and impact.
     - Determine what other functions are invoked from within these functions, helping to map out the code’s execution flow and dependencies.

#### **Tips for Effective Review**

- **Editing Files:**
  - Always copy files to Visual Studio for edits. This keeps the original code untouched and allows for easy comparison and version control.

- **Efficient Navigation:**
  - Use `Ctrl + Shift` to search across all open files, enabling quick access to specific code sections or keywords.

- **System Files:**
  - Only review system files if they are relevant to the context, as they usually contain standard libraries and utilities that might not need detailed inspection.

- **String Analysis:**
  - Run `strings` and search extensively within dnSpy to uncover hidden or hardcoded strings, which could reveal sensitive information or critical functionality.