shift left- sec closer to dev

 [youtube.com](https://www.youtube.com/watch?v=mZoOnWjv_QM).

_(How to Create a DevSecOps CI/CD Pipeline — DevOps Journey)_

---

Context Setting**

-  DevSecOps as the natural evolution of DevOps: _“You can’t ship fast if you’re shipping insecurely.”_
- the goal is to **embed security into every stage** of the pipeline, not bolt it on at the end.
-  the major components: SAST, SCA, SBOM, secret scanning, container hardening, and secure deployment.

---


the three scanning types that form the backbone of DevSecOps:

## static code analysis 
### **SAST (Static Application Security Testing)**

- Scans **your code** for vulnerabilities.
- Detects insecure patterns, injection risks, unsafe functions, and logic flaws.
static code analysis - 
purpose: checks for code vulns; checks sqli, buffer over flows
Tools: tool in ide or runs periodically in source code repo- use a github action
use case: when dev does a pull, can prevent a pr from being merged

### **SCA (Software Composition Analysis)**

- Scans **your dependencies**.
- Identifies vulnerable libraries, outdated packages, and license compliance issues.
- Presenter emphasizes that modern apps are mostly dependencies, not custom code.
- 
	- purpose: checks for code vulns; checks sqli, buffer over flows
	- Tools: tool in ide or runs periodically in source code repo- use a github action
	- use case: when dev does a pull, can prevent a pr from being merged



---

 Why DevSecOps Is Critical**

- The presenter highlights the rise of supply‑chain attacks (SolarWinds, Log4Shell, dependency hijacking) 
- **most vulnerabilities come from reused components**, not developer‑written code.
- Reinforce the “shift‑left” philosophy: security must start at the earliest stages.
- Emphasize automation: manual reviews cannot scale.

---

