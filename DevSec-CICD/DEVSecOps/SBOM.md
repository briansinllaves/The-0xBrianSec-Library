**Where SBOM Fits in CI/CD**

## **1. SBOM is _generated_ during Build**

This is the earliest point where the pipeline has a complete view of:

- Dependencies (direct + transitive)
- Package versions
- Licenses
- Build-time components
- Container base images
- OS packages (if containerized)

**Why Build?**  
Because this is the first moment you can produce a trustworthy, reproducible inventory of what’s actually going into the artifact.

**Typical tools:** Syft, CycloneDX, Trivy, ORT, osv-scanner.

---

## **2. SBOM is _validated_ during Build (optional but recommended)**

Many teams run:

- Vulnerability checks
- License compliance checks
- Policy checks (e.g., “no GPL”, “no critical vulns”)

This is the first “shift-left” gate.

---

## **3. SBOM is _signed_ and attached to the artifact**

This is crucial for supply‑chain integrity.

- Sign SBOM (Sigstore/cosign)
- Attach it to the container image or artifact
- Store it in an artifact repository (ACR, GHCR, Artifactory, etc.)

This ensures the SBOM cannot be tampered with later.

---

# **🔐 4. SBOM is checked _again_ at Release**

Yes — this is absolutely correct.

Security performs a second validation at release because:

### **Why re-check?**

- Vulnerability databases change daily
- A dependency that was “clean” at build time may be flagged later
- Release is the last gate before production
- Compliance frameworks (FedRAMP, DoD, PCI) require a final security review

### **What gets checked at Release?**

- SBOM integrity (signature verification)
- Vulnerability drift since build
- Policy enforcement (e.g., no critical CVEs allowed)
- License compliance
- Artifact provenance (SLSA, in-toto attestations)

This is often called **“pre-deployment security gating”**.

---

# **🧩 Putting it together**

|Stage|SBOM Action|Purpose|
|---|---|---|
|**Build**|Generate SBOM|Create accurate inventory|
|**Build/Test**|Scan SBOM|Early detection of issues|
|**Package**|Sign + store SBOM|Provenance + integrity|
|**Release**|Re-scan + enforce policies|Final security gate|
|**Deploy**|Attach SBOM to release artifact|Compliance + traceability|

---

# **💡 The mental model**

**SBOM is created once, but validated multiple times.**  
Think of it like a passport: issued once, checked often.

---

If you want, I can map this into a full CI/CD blueprint with SAST, SCA, SBOM, secrets scanning, image scanning, and release gates — or even align it to SLSA levels.