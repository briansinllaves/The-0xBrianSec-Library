**Level 1 – Foundational**

- **Process:**
    
    - **Defined:** Basic SDLC documented; CI/CD exists for main services.
        
    - **Security:** Security is a separate step, mostly manual reviews and ad‑hoc scans.
        
- **Controls:**
    
    - **SAST/SCA:** Run occasionally or only on main branch.
        
    - **Secrets:** Some secrets in CI variables; occasional leaks in repos.
        
    - **Logging:** CI logs exist but are not centralized or monitored.
        

**Level 2 – Integrated**

- **Process:**
    
    - **Shift‑left:** SAST, SCA, and secret scanning run on every PR or build.
        
    - **Gates:** Builds fail on critical vulnerabilities or secret findings.
        
- **Controls:**
    
    - **Branch protection:** Required reviews, status checks, and signed commits for main.
        
    - **Artifacts:** Central artifact registry; basic image scanning; SBOM generated for key services.
        
    - **Access:** CI/CD identities use least privilege; no shared admin accounts.
        

**Level 3 – Advanced**

- **Process:**
    
    - **Policy‑as‑code:** Security and compliance rules enforced automatically (OPA, admission controllers, etc.).
        
    - **Risk‑based:** Severity thresholds tuned; exceptions require documented risk acceptance.
        
- **Controls:**
    
    - **Supply chain:** All artifacts/images are signed; deployments verify signatures and SBOM.
        
    - **Runtime:** mTLS, network policies, and runtime security in place; distroless/minimal images standard.
        
    - **Monitoring:** CI/CD, infra, and app logs centralized; alerts for anomalous pipeline behavior.
        

**Level 4 – Optimized**

- **Process:**
    
    - **Continuous improvement:** Regular red‑teaming/purple‑teaming of CI/CD; lessons fed back into controls.
        
    - **Metrics:** Track MTTR for security issues, % of builds passing security gates, and coverage of SAST/SCA/IaC scans.
        
- **Controls:**
    
    - **Zero Trust:** Strong identity for users and workloads; no implicit trust between stages/environments.
        
    - **Automation:** Auto‑remediation where safe (e.g., auto‑bump safe dependencies, auto‑revoke compromised tokens).
        
    - **Governance:** Periodic access reviews, plugin/3rd‑party governance, and formal supply‑chain risk management.