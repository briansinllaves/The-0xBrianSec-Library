DevSecOps is not a tool — it’s a **workflow**.
- the idea of layering controls at each stage:
    - Code → Build → Package → Test → Release → Deploy → Operate
-
---
# **🔧  Stage 1: Code**

- Developers should run:
    - Pre‑commit hooks (SAST, secrets)
    - IDE‑based SAST
    - Local linting and unit tests
- Branch protection rules:
    - Required PR reviews
    - Required status checks
    - Signed commits
- Emphasizes that catching issues early is cheaper and faster.

---

# **🏗️  Stage 2: Build**

- CI runs:
    - Full SAST
    - Full SCA
    - SBOM generation
- Builds fail on:
    - Critical vulnerabilities
    - Secret leaks
    - Policy violations
- Presenter notes that many organizations still skip SCA or SBOM, which is dangerous.

---

# **📦Stage 3: Package**

- Build container images using:
    - Minimal base images
    - Distroless variants
- Sign artifacts (containers, binaries, manifests).
- Store SBOMs alongside artifacts.
- Enforce immutability: builds should be reproducible and tamper‑evident.

---

# **🧪Stage 4: Test**

- Run:
    - DAST (dynamic scanning)
    - IaC scanning (Terraform, Helm, ARM/Bicep)
    - Container image scanning
- Block promotion if:
    - Critical vulnerabilities exist
    - IaC misconfigurations violate policy
- the idea of “security gates” in CI/CD.
# Where PR jobs fit in the CI/CD pipeline

A pull request typically triggers what’s called a **PR Validation Pipeline** or **Pre‑Merge Pipeline**. This sits squarely in the **Test** phase of CI/CD.

---

# **🚀 Stage 5: Release**

- Introduces **policy‑as‑code**:
    - OPA (Open Policy Agent)
    - Conftest
    - Admission controllers
- Enforce:
    - Signature verification
    - SBOM validation
    - Deployment‑time security checks
- Ensures only compliant artifacts reach production.

---

# **🌐Stage 6: Deploy**

- runtime security:
    - mTLS between services
    - Network policies (deny‑by‑default)
    - eBPF‑based runtime monitoring
- Zero Trust principles:
    - No implicit trust between services
    - Identity‑based communication
    - Continuous verification

---

# **📊 Stage 7: Operate & Monitor**

    - Centralized logging
    - SIEM integration
    - CI/CD anomaly detection
    - Continuous compliance scanning
- how to detect:
    - Suspicious pipeline triggers
    - Unexpected image pulls
    - Unauthorized configuration changes
- adopt incremental improvements.
