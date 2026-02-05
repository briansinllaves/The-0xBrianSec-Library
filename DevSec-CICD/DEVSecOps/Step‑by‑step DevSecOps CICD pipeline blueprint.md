1. **Plan & design**
    
    - **Security activities:** Threat modeling, define trust boundaries, classify data, choose security baselines.
        
    - **Controls:** Require security sign‑off for new services; define minimum controls (SAST, SCA, secrets, image scanning, SBOM).
        
2. **Code**
    
    - **Security activities:** Pre‑commit hooks for secrets/SAST on changed files; secure coding guidelines; branch protection.
        
    - **Controls:** Mandatory PR reviews, signed commits, protected main branches, lint + unit tests as gate.
        
3. **Build**
    
    - **Security activities:** Run SAST and SCA on every build; generate SBOM; fail on critical issues.
        
    - **Controls:** Immutable build images; build in isolated runners; no direct internet from build agents where possible.
        
4. **Package**
    
    - **Security activities:** Build minimal/distroless images; sign images and artifacts; embed SBOM.
        
    - **Controls:** Store artifacts in a private, access‑controlled registry; enforce signature verification policies.
        
5. **Test**
    
    - **Security activities:** DAST against test environment; container/image scanning; infra‑as‑code scanning (Terraform, ARM/Bicep, Helm, etc.).
        
    - **Controls:** Block promotion if critical vulns or misconfigurations are found; require risk acceptance for exceptions.
        
6. **Release**
    
    - **Security activities:** Policy checks (e.g., OPA/Conftest, admission controllers) before deployment; verify signatures and SBOM.
        
    - **Controls:** Manual or multi‑party approvals for production; environment‑scoped identities; change management records.
        
7. **Deploy**
    
    - **Security activities:** Enforce mTLS, network policies, and runtime security (e.g., syscall profiles, eBPF‑based monitoring).
        
    - **Controls:** Progressive delivery (blue/green, canary); rollbacks; deployment SLOs tied to security signals.
        
8. **Operate & monitor**
    
    - **Security activities:** Centralized logging, SIEM integration, anomaly detection on CI/CD and runtime; regular secret rotation.
        
    - **Controls:** Incident runbooks; periodic access reviews; continuous compliance checks (CIS, Benchmarks, etc.).
        



