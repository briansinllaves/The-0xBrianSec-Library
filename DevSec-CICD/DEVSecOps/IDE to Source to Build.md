## Secret Scanning (One of the Biggest Real‑World Risks)**

- Hard‑coded secrets are one of the most common breach vectors.
- Checks for db pw or api key, etc
- Shows how secrets leak:
    - Accidentally committed to Git
    - Printed in CI logs
    - Stored in plaintext environment variables
- Recommends:
    - Pre‑commit 
	    - secret scanning/ruleset in github repo, stops the commit, with a secscan and stops the dev if rules are broken
	    - linting: make sure the dev is conforming to certain coding practices, good for pipeline and practices
    - CI‑level scanning
    - Repository‑level scanning (GitHub/GitLab built‑ins)
    - Run against source repos and in devs ide 
    - See above: SCA = SCA and SAST
    - Run all static checks in source, build stage of the pipeline

-  attackers actively scan public repos for leaked tokens.
### **SBOM (Software Bill of Materials)**

- A complete inventory of everything, 3rd party libraries in your application.
- especially noted in BUILD stage
- Helps track vulnerabilities over time and meet regulatory requirements.
- Enables downstream consumers to verify what they’re running.
- softcompanal and sast can be ran on sbom- store in a s3 bucket and audit them 
	- ctl-f find log4j and version.

## Test

DAST- checking your code for issues during runtime
- you cant find them through static
- use tools: owasp zap/ burp, depends on your coding library and what your code does
- sqli, xss, auth, session hijacking, 

# Release Stage
- nothing really happens after that release stage
- check your environment, image scanners, vuln scanners, staging environment and image repositories that we send to-dockerhub, or amazon ecr-scanning ability?, azure cr.

The above covers 90% of the above. Most orgs dont use half of the above. 

Dockerhub- Scout for security base

## **Reducing the Attack Surface**
### Why distroless?

- Removes shells, package managers, and debugging tools.
- Reduces the number of CVEs dramatically.
- Limits what an attacker can do if they compromise a container.
- **Typical images**: full OS, hundreds of packages, multiple shells.
- **Distroless images**: only the runtime and your app.

---

## Deep Dive Into Distroless Images**

- attackers use tools like `bash`, `curl`, `wget`, and package managers to escalate.
- distroless images:
    - Remove these tools entirely
    - Reduce lateral movement
    - Reduce the blast radius of a compromise
- distroless is becoming a best practice in modern cloud‑native security.