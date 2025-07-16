### Simplified API Overview

#### What Can an API Do?
- **APIs** define rules for how software (like apps or websites) request and use data or services from other software (like databases).
- They enable actions like retrieving data, sending data, or performing tasks within a program.

#### APIs Aren't Just for Web Applications
- **APIs** are used everywhere, not just on the web.
- They work in desktop apps, mobile apps, and even between hardware devices.
- APIs allow different software components to interact, regardless of their platform.

#### Introduction to API Security
- Learn more about API security at the **[OWASP API Security Project](https://owasp.org/www-project-api-security/)**.

#### Payloads and Insecure Direct Object References (IDOR)
- Explore IDOR payloads at **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References)**.

#### REST API Basics
- **HTTP Methods** used in REST APIs:
  - **GET**: Retrieve a resource's state.
  - **POST**: Create a new resource.
  - **PUT**: Update a resource.
  - **DELETE**: Remove a resource.
  - **HEAD**: Get metadata about a resource.
  - **OPTIONS**: List available methods.

#### HTTP Response Status Codes
- **Common status codes** in REST APIs:
  - **200 OK**: Request was successful.
  - **201 Created**: New resource created.
  - **301 Moved Permanently**: Resource permanently redirected.
  - **304 Not Modified**: Cached resource unchanged.
  - **307 Temporary Redirect**: Resource temporarily redirected.
  - **400 Bad Request**: Malformed request.
  - **401 Unauthorized**: Client lacks proper authorization.
  - **403 Forbidden**: Access denied.
  - **404 Not Found**: Resource not found.
  - **405 Method Not Allowed**: Invalid method used.
  - **500 Internal Server Error**: Server error occurred.

#### HTTP Headers
- **HTTP Headers** in API requests often include:
  - **Content-Type**: Typically set to `application/json` for JSON data.

#### Web Authentication Types
- **Common web authentication methods**:
  - **Bearer Tokens**: `Authorization: Bearer <token>` - Used in OAuth 2.0.
  - **HTTP Cookies**: `Cookie: <ne>=<value>` - Used for session management.
  - **Basic HTTP Authentication**: `Authorization: Basic <base64 value>` - Sends userne and password in every request.

#### Testing Steps

1. **Unauthenticated Testing**:
   - Send basic API requests.
   - Use Burp to proxy Postman requests.
   - Inspect the frontend site.
   - Check `runtime-config` for keys and destination URLs.
   - Search for keywords like `apikey`, `key`, `password`, and `token`.
   - Look for "apikey" references in `main.js`.

2. **Handling Invalid Certificates**:
   - Send cookies in Burp requests.

3. **Additional Testing**:
   - Perform an Nmap scan for deeper exploration.