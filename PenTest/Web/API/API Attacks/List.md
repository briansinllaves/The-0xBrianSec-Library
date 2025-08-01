### API Security Testing Checklist

#### Enumerate Unauthenticated Endpoints
- [ ] Identify API endpoints that don't require authentication.
- [ ] Look for security misconfigurations.
- [ ] Check for directory traversal vulnerabilities.

#### API Fuzzing
- [ ] Use `ffuf` to fuzz API endpoints:
  ```bash
  ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u https://example.com:9443/manager/FUZZ -e .txt,.html,.js,.css,.xml,.php
  ```
- [ ] Test for injections and misconfigurations.

#### User Input Validation
- [ ] Ensure user input is validated against common vulnerabilities (XSS, SQL Injection, RCE).

#### Data Validation and Filtering
- [ ] Validate, filter, or sanitize data from external systems.

#### Escape Character Testing
- [ ] Use escape characters to test for vulnerabilities.

#### Content-Type Handling
- [ ] Test various content types and observe API responses.
- [ ] Manipulate Content-Type headers and check for anomalies.

#### Resource and Query String Manipulation
- [ ] Replace resource extensions in requests.
- [ ] Experiment with query string replacements.

#### URL Redirection Testing
- [ ] Check for open redirect vulnerabilities.

#### Authorization Testing
- [ ] Test function-level authorization.
- [ ] Assess access control, encryption, and retry limits.
- [ ] Prioritize areas based on vulnerability.

#### API Enumeration
- [ ] Use enumeration tools (Archive.org, Censys, VirusTotal).
- [ ] Test for object-level authentication.
- [ ] Look for excessive data exposure.
- [ ] Check for command injection and misconfigured permissions.

#### HTTPS and HSTS Verification
- [ ] Ensure all connections use HTTPS.
- [ ] Verify HSTS enforcement.

#### API Version Testing
- [ ] Test each API version independently.

#### Repeated Request Limitation
- [ ] Assess the API's response to repeated requests.

#### Distinct Login Paths
- [ ] Identify and test distinct login paths:
  - [ ] `/api/mobile/login`
  - [ ] `/api/v3/login`
  - [ ] `/api/magic_link`

#### Numeric and Non-Numeric ID Testing
- [ ] Test endpoints with numeric and non-numeric IDs:
  - [ ] `/user_id=111`
  - [ ] `/user_id=user@mail.com`

#### Mobile API Testing
- [ ] Test mobile and web APIs separately.

#### Input Injection
- [ ] Perform input injections on all parameters.

#### Admin Endpoint Testing
- [ ] Locate admin endpoints.
- [ ] Attempt OS command execution, XXE, SSRF, and other injection techniques.

#### Handling Unconventional Input
- [ ] Test with unexpected input types or values (e.g., negative numbers).

#### Bypassing Workflow Sections
- [ ] Attempt to bypass workflow steps.

#### Encryption Oracle Testing
- [ ] Test for vulnerabilities where input is returned as ciphertext.

#### Insecure Direct Object Reference (IDOR)
- [ ] Check for IDOR vulnerabilities by manipulating identifiers.

#### Parameter Removal and Workflow Tampering
- [ ] Remove parameters one at a time.
- [ ] Follow multi-stage processes, tampering with parameters.

#### Domain-Specific Flaws
- [ ] Identify situations where prices or sensitive values are user-dependent.
- [ ] Manipulate application states to expose inconsistencies.

#### Inconsistent Security Controls
- [ ] Test access to resources using arbitrary identifiers (e.g., email).

#### Business Rule Enforcement Testing
- [ ] Manipulate request bodies to deviate from intended actions.
- [ ] Test applying the same or different coupon codes in sequence.

Use this checklist to systematically test API security and uncover potential vulnerabilities.