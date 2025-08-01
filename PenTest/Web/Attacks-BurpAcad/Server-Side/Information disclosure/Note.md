## Examples

- Revealing nes and structure of hidden directories.
- Gaining access to backups and sensitive files.
- Error messages providing too much technical detail to the user.
- Exposing highly sensitive information, like credit cards, in the application logs or GUI.
- Hard-coded credentials in source code.
- 'Fingerprinting' the hosting platform by through server headers.
- Determining underlying existence/absense of resources by observing differences between responses.

## [](https://github.com/patheard/web-security-academy/tree/main/information-disclosure#techniques)

## Techniques

Information disclosure can be triggered and detected by:

- `Fuzzing`: sending a large number of requests with varying inputs to see how the application behaves.
- `Scanning`: using a tool like [Burp Scanner](https://portswigger.net/burp/vulnerability-scanner) to test for and identify information leakage during browsing.
- `Causing errors`: attempting to cause error conditions in the application to see what information is revealed in the error messages.

## [](https://github.com/patheard/web-security-academy/tree/main/information-disclosure#sources-of-information-disclosure)

## Sources of information disclosure

- Web crawler files like `robots.txt` and `sitemap.yml` which can reveal hidden directories.
- Web server automatic directory listings (poorly configured web servers can reveal hidden directories).
- Developer commesn in source code
- Error messages providing too much information
- Debug data in the response
- User account pages with poor authorization controls
- Backup files which can leak the application source code
- Insecure build pipeline or web server configuration
- Version control history