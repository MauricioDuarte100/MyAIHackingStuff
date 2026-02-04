# My AI Hacking Stuff

This repository contains a comprehensive collection of AI agents, skills, rules, and knowledge bases designed for advanced security assessments, penetration testing, and bug bounty hunting. It serves as the central "brain" for an AI-powered security assistant.

## Directory Structure

### 1. Agents
Specialized agent definitions that complement the core skills. These agents act as experts in specific domains:
- **api-security-audit**: Specialist in REST API security, authentication, and authorization flaws.
- **backend-architect**: Expert in system architecture, inferring backend logic and potential design flaws.
- **code-reviewer**: Automated code analysis for security vulnerabilities and secrets.
- **penetration-tester**: Generalist offensive security expert for exploitation and post-exploitation.
- **security-auditor**: Focuses on OWASP compliance, secure coding, and configuration reviews.

### 2. Skills
Executable capabilities and workflows that the AI can trigger to perform specific tasks. This includes 39+ specialized skills such as:
- **Orchestrators**: `main-orchestrator`, `unified-orchestrator`, `owasp-orchestrator`, `api-orchestrator` for coordinating complex assessments.
- **Attack Agents**: `injection-agent`, `xss-agent`, `auth-agent`, `race-condition-agent` for targeted exploitation.
- **Reconnaissance**: `recon-agent`, `network-recon-agent`, `service-enumeration-agent` for attack surface mapping.
- **Validation**: `exploitability-validator`, `supply-chain-agent` for verifying findings and reducing false positives.

### 3. Rules
Operational guidelines and methodologies that govern the AI's behavior and decision-making process:
- **Methodologies**: Bug Bounty Methodology, OWASP Top 10 2025.
- **Scope Rules**: Definitions for defining engagement scope and exclusions.
- **Validation Rules**: Strict criteria for verifying vulnerabilities before reporting (e.g., prohibiting speculation).
- **Auto-Learning**: Rules for updating internal knowledge based on past experiences.

### 4. Orchestrators
High-level logic definitions for coordinating multiple agents and skills to achieve complex objectives, such as a full security assessment or a specific vulnerability scan workflow.

### 5. Knowledge & Writeups
A database of reference material, including:
- **Lessons Learned**: Records of past mistakes, false positives, and corrections to improve future performance.
- **Writeups**: A collection of 180+ CTF and real-world bug bounty writeups indexed by vulnerability type and technology, used for reference and payload adaptation.

## Usage

This repository is designed to be integrated into an AI CLI environment. The components work together to provide a robust, consistent, and methodologically sound security testing framework.