### Identify AI system risks

Begin with your established threat modeling framework (such as STRIDE), then reference AI-specific risk inventories to ensure AI attack techniques are adequately represented:

- **MITRE ATLAS**: Provides a knowledge base of adversary tactics and techniques targeting AI systems, similar to how MITRE ATT&CK covers traditional attacks
	- [ATLAS Matrix | MITRE ATLAS™](https://atlas.mitre.org/matrices/ATLAS)
	
- **OWASP Generative AI risks**: Documents top security risks specific to large language models (LLMs) and generative AI applications
	- [Resources Archive - OWASP Gen AI Security Project](https://genai.owasp.org/resources/?e-filter-3b7adda-resource-item=cheat-sheets)



## OWASP Top 10 for Large Language Model Applications
[OWASP Top 10 for Large Language Model Applications | OWASP Foundation](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

### 2025 Top 10 Risk & Mitigations for LLMs and Gen AI Apps
[LLMRisks Archive - OWASP Gen AI Security Project](https://genai.owasp.org/llm-top-10/)





These frameworks help identify risks like prompt injection, training data poisoning, model theft, and sensitive information disclosure that aren't covered by traditional security assessments.

### Assess AI data risks

Sensitive data in AI workflows increases the risk of insider threats and data leaks. AI systems often process, store, or generate data that requires special protection:

- Training data may contain sensitive information that could be extracted
- Model outputs might inadvertently reveal confidential data
- AI interactions create new data flows that need classification and protection

Assess enterprise-wide AI data risks and prioritize them based on data sensitivity levels. Use data loss prevention techniques tailored for AI workflows.

### Test AI models for security vulnerabilities

AI models contain unique vulnerabilities that attackers can exploit:

- **Prompt injection**: Manipulating inputs to override system instructions or extract unauthorized information
- **Data leakage**: Extracting training data or sensitive information through carefully crafted queries
- **Model inversion**: Reconstructing training data or model parameters from outputs
- **Jailbreaking**: Bypassing safety controls to generate harmful or unauthorized content

Test models using adversarial simulations and red team both generative AI and traditional AI models to simulate real attacks. Static reviews alone can't uncover all AI-specific vulnerabilities.

### Conduct periodic risk assessments

New threats emerge as AI models, usage patterns, and threat actors evolve. Run recurring assessments to identify vulnerabilities in models, data pipelines, and deployment environments. Use assessment findings to guide risk mitigation priorities.

## Monitoring and detecting AI threats

AI systems require specialized monitoring to detect threats that traditional security tools may miss.

### AI-specific threat detection

Implement monitoring that addresses AI-unique attack patterns:

- Detect prompt injection attempts and jailbreak patterns
- Monitor for unusual query patterns that might indicate data extraction
- Track model behavior changes that could indicate compromise
- Alert on unauthorized model access or modification

### Integration with security operations

AI threat detection should feed into your existing security operations:

- Integrate AI alerts with your SIEM for correlation with other security events
- Include AI systems in incident response playbooks
- Train SOC analysts on AI-specific threats and investigation techniques
- Establish escalation paths for AI security incidents