
- **SAST (source code scanning)**
    
    - **Goal:** Find code‑level vulnerabilities early.
        
    - **Examples:** Language‑specific SAST (e.g., CodeQL, Semgrep, commercial SAST); IDE plugins for early feedback.
        
- **SCA (dependency and license scanning)**
    
    - **Goal:** Detect vulnerable/open‑source components and license issues.
        
    - **Examples:** Dependency scanners integrated into CI; SBOM‑aware tools that track CVEs over time.
        
- **SBOM generation & management**
    
    - **Goal:** Know exactly what’s in each build and image.
        
    - **Examples:** Tools that output SPDX/CycloneDX; SBOM stored alongside artifacts; SBOM checks in deployment gates.
        
- **Secret scanning & management**
    
    - **Goal:** Prevent hard‑coded secrets and manage them centrally.
        
    - **Examples:** Pre‑commit secret scanners; CI secret scanning; dedicated secret vault; short‑lived, workload‑bound credentials.
        
- **Container/image scanning**
    
    - **Goal:** Identify OS and library vulnerabilities in images.
        
    - **Examples:** Image scanners integrated into CI and registry; policy to block images with critical vulns; distroless/base‑image baselines.
        
- **IaC & configuration scanning**
    
    - **Goal:** Catch misconfigurations before deployment.
        
    - **Examples:** Terraform/Kubernetes/Cloud template scanners; policy‑as‑code (OPA/Conftest, Gatekeeper, Kyverno).
        
- **Runtime & pipeline security**
    
    - **Goal:** Protect CI/CD infrastructure and running workloads.
        
    - **Examples:** Hardening CI runners; admission controllers; runtime security agents; signed pipelines and artifacts.