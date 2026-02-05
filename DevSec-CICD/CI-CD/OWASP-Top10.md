Top 10 CI/CD Security Risks — One‑Sentence Summaries
CICD‑SEC‑1: Insufficient Flow Control Mechanisms  
Weak or missing controls allow unauthorized or unintended pipeline stages to run, creating opportunities for attackers to alter the build or deployment flow.

CICD‑SEC‑2: Inadequate Identity and Access Management  
Poorly scoped or overly permissive identities let attackers abuse CI/CD accounts, tokens, or roles to gain elevated access.

CICD‑SEC‑3: Dependency Chain Abuse  
Attackers compromise or manipulate dependencies to inject malicious code into builds or developer environments.

CICD‑SEC‑4: Poisoned Pipeline Execution (PPE)  
An adversary forces the pipeline to execute malicious commands or artifacts by tampering with inputs, configurations, or pipeline logic.

CICD‑SEC‑5: Insufficient PBAC (Pipeline‑Based Access Controls)  
Pipelines lack granular, context‑aware authorization rules, enabling unauthorized jobs or users to trigger sensitive operations.

CICD‑SEC‑6: Insufficient Credential Hygiene  
Secrets, tokens, or credentials are stored insecurely or reused, making them easy for attackers to steal and exploit.

CICD‑SEC‑7: Insecure System Configuration  
Misconfigurations in CI/CD tools, infrastructure, or integrations expose the environment to privilege escalation or unauthorized access.

CICD‑SEC‑8: Ungoverned Usage of 3rd Party Services  
Unvetted external services, plugins, or SaaS integrations introduce unmonitored attack paths into the CI/CD ecosystem.

CICD‑SEC‑9: Improper Artifact Integrity Validation  
Artifacts are not cryptographically verified, allowing tampered or malicious builds to be trusted and deployed.

CICD‑SEC‑10: Insufficient Logging and Visibility  
Lack of comprehensive logs and monitoring prevents detection, investigation, and response to CI/CD‑focused attacks.

