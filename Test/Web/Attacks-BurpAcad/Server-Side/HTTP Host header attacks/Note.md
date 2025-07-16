the Host header is a potential vector for exploiting a range of other vulnerabilities, most notably:

- Web cache poisoning
- Business [logic flaws](https://portswigger.net/web-security/logic-flaws) in specific functionality
- Routing-based SSRF
- Classic server-side vulnerabilities, such as SQL injection

the Host can potentially be overridden by injecting other headers. Sometimes website owners are unaware that these headers are supported by default and, as a result, they may not be treated with the same level of scrutiny.

