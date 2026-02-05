PR‑triggered jobs are **standard practice across the industry**, not a Jenkins quirk.


## What happens during PR → Test phase

A PR usually kicks off:

### **1. Build validation**

- Compile/build the app
    
- Run unit tests
    
- Run linting/formatting checks
    

### **2. Security validation (shift‑left)**

This is where your DevSecOps blueprint comes in:

- **SAST** (static analysis)
    
- **SCA** (dependency scanning)
    
- **Secrets scanning**
    
- **SBOM generation**
    
- **Container linting** (if applicable)
    
- **IaC scanning** (Terraform, ARM/Bicep, Helm, etc.)
    

### **3. Policy gates**

- Branch protection rules
    
- Required checks
    
- Code coverage thresholds
    
- Signed commits / provenance checks
    
- Zero Trust controls (e.g., workload identity for pipeline agents)
    

### **4. Optional ephemeral environment**

Some orgs spin up:

- A preview environment
    
- A temporary namespace
    
- A short‑lived container stack
    

This allows integration tests before merge.

# 🧩 Why this is the _test_ phase, not deploy

Because the PR is **not** meant to deploy anything. It’s meant to **prove the code is safe, correct, and compliant before merging**.

Deployment happens only after merge into a protected branch (e.g., `main`, `release/*`).

PR‑triggered jobs are **standard practice across the industry**, not a Jenkins quirk.

## 🛠 Why PRs often trigger jobs

Teams usually want to:

- Run tests before merging
    
- Enforce linting, SAST, SCA, or other DevSecOps checks
    
- Prevent broken code from entering `main`
    
- Provide reviewers with build/test results
    

This is the backbone of “shift‑left” security and quality.

## 🧠 Jenkins specifics

Jenkins _can_ automatically build PRs, but only when:

- You use **Multibranch Pipeline**, **GitHub Branch Source**, or **Bitbucket Branch Source**
    
- Webhooks are configured
    
- Jenkinsfile includes the right conditions (or no conditions at all)