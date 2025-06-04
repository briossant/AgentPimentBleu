# AgentPimentBleu - Project Roadmap

This document outlines the development roadmap for AgentPimentBleu, an AI-powered security scanning agent for Git repositories.

## Guiding Principles
*   **Actionable Insights:** Focus on providing security information that developers can act upon, prioritizing impact.
*   **AI-Driven Intelligence:** Leverage Large Language Models (LLMs) to go beyond traditional scanning and provide contextual understanding.
*   **User-Friendly Interface:** Utilize Gradio to make the tool accessible and easy to use.
*   **Iterative Development:** Start with a core MVP and incrementally add features and improve accuracy.

---

## Phase 1: Hackathon MVP (June 2 - June 8, 2025) 🎯

**Goal:** Deliver a functional Gradio application showcasing the core concept of AI-driven security analysis with impact assessment for dependencies.

**Key Features & Tasks:**

1.  **Gradio UI - Basics:**
    *   [x] Input field for public Git repository URL.
    *   [x] Button to trigger the scan.
    *   [x] Static area for displaying status messages (e.g., "Cloning...", "Analyzing...").
    *   [x] Output area (e.g., `gr.Markdown`) to display the final report.
2.  **Core Agent Logic - Setup:**
    *   [x] Functionality to clone a public Git repository to a temporary local directory.
    *   [x] Basic error handling for invalid URLs or cloning failures.
3.  **SAST Integration - Initial Pass:**
    *   [x] Integrate JavaScript SAST using ESLint with security plugins.
    *   [x] Integrate Python SAST using Bandit.
    *   [x] Parse basic output from the SAST tools.
    *   [x] **LLM Enhancement (Proof of Concept):**
        *   [x] Send a few example SAST findings (code snippets) to an LLM.
        *   [x] Prompt LLM for a human-readable explanation of the risk.
4.  **SCA Integration - Initial Pass:**
    *   [x] Integrate JavaScript SCA using npm audit.
    *   [x] Integrate Python SCA using pip-audit.
    *   [x] Parse basic dependency and CVE information.
5.  **⭐ AI-Powered Dependency Impact Assessment (Core Feature):**
    *   [x] For identified vulnerable dependencies:
        *   [x] Basic code searching mechanism to identify where the dependency is imported/used (e.g., simple string matching for `import library_name`).
        *   [x] Send CVE information + project usage snippets to an LLM.
        *   [x] **Prompt LLM to generate a comprehensive security vulnerability report with five key components:**
            *   [x] **Project Severity Note:** Assessment of the severity of the vulnerability for the specific project.
            *   [x] **Is Project Impacted:** Determination of whether the project is likely impacted by the vulnerability (true/false).
            *   [x] **Potentially Impacted Code:** Identification of code patterns that might be vulnerable.
            *   [x] **Proposed Fix:** Specific suggestions for fixing the vulnerability.
            *   [x] **Human-Readable Explanation:** Clear explanation of the vulnerability and its implications.
6.  **Report Generation & Display:**
    *   [x] Structure the output to clearly differentiate:
        *   [x] SAST findings (with any initial LLM comments).
        *   [x] SCA findings, highlighting those with AI-assessed impact.
    *   [x] Present findings in a readable Markdown format within the Gradio UI.
7.  **Hackathon Submission Requirements:**
    *   [ ] Working Gradio app deployed as a Hugging Face Space.
    *   [ ] `README.md` in the Space with the `agent-demo-track` tag.
    *   [ ] Video overview of the app, its purpose, and a demonstration.

---

## Phase 2: Post-Hackathon Refinements (Short-Term) 🚀

**Goal:** Improve the robustness, accuracy, and usability of the MVP. Expand initial capabilities.

*   **Intelligent Agent for Codebase Exploration: ✓**
    *   [x] Create a dedicated agent class for exploring codebases and analyzing vulnerabilities
    *   [x] Implement project structure analysis (similar to tree command output)
    *   [x] Add file exploration capabilities (reading files, searching for patterns)
    *   [x] Implement a multi-step analysis process: analyze CVE, explore codebase, generate report

*   **Enhanced SAST & SCA: ✓**
    *   [x] Implement modular architecture with standardized scanner interfaces
    *   [x] Support for multiple programming languages (JavaScript and Python)
    *   [x] Integrate JavaScript SAST (ESLint with security plugins) and SCA (npm audit)
    *   [x] Integrate Python SAST (Bandit) and SCA (pip-audit)
    *   [ ] Integrate more SAST/SCA tools (e.g., `Semgrep`, `gitleaks`)
    *   [ ] Support for more dependency file formats (e.g., `Pipfile.lock`, `poetry.lock`, `package-lock.json`)
*   **Project Type Detection: ✓**
    *   [x] Implement language detection to determine project types
    *   [x] Dynamically select appropriate scanners based on detected languages
*   **Improved LLM Integration & Prompt Engineering:**
    *   [x] Refine prompts for better accuracy in impact assessment and code analysis
    *   [x] Develop more sophisticated methods for selecting and sending relevant code context to the LLM
    *   [x] Explore techniques to reduce LLM hallucination and improve consistency
    *   [x] Handle LLM API errors gracefully
*   **Advanced Code Usage Analysis (for SCA Impact):**
    *   [x] Move beyond simple import checking to identify specific function/method calls related to CVEs (implemented through the SecurityAgent's codebase exploration capabilities)
*   **Gradio UI Enhancements:**
    *   [ ] More interactive report display (e.g., collapsible sections, severity filtering, links to CVE details)
    *   [ ] Clearer progress indicators and error messages
    *   [ ] Option to export the report
*   **Configuration Scanning:**
    *   [ ] Specifically target common configuration files (e.g., Dockerfiles, K8s manifests, CI/CD pipeline files, `.env` files) for misconfigurations
*   **Secrets Detection:**
    *   [ ] Integrate a dedicated secrets scanner (e.g., `gitleaks`)
    *   [ ] Use LLM to assess the validity/sensitivity of potential leaked secrets
*   **Performance Optimization:**
    *   [ ] Profile and optimize long-running parts of the scan
    *   [ ] Consider asynchronous operations for UI responsiveness

---

## Phase 3: Long-Term Vision 🌟

**Goal:** Evolve AgentPimentBleu into a comprehensive and highly intelligent security analysis platform.

*   **Deep Contextual Understanding:**
    *   Build a knowledge graph of the codebase for more accurate impact analysis.
    *   Use LLMs to understand the overall architecture and data flow of the application.
*   **Automated Remediation & Suggestions:**
    *   LLM-generated code patches for certain vulnerabilities.
    *   Integration with version control to create Pull/Merge Requests with suggested fixes.
*   **CI/CD Integration:**
    *   Provide mechanisms to run AgentPimentBleu as part of automated build and deployment pipelines.
    *   Fail builds based on configurable severity thresholds.
*   **Support for Private Repositories:**
    *   Implement secure authentication mechanisms.
*   **Customization & Extensibility:**
    *   Allow users to define custom scan rules or policies.
    *   Plugin architecture for adding new scanners or analysis modules.
*   **Advanced AI Capabilities:**
    *   Fine-tune or train specialized LLMs for security code analysis and vulnerability impact assessment.
    *   Explore reinforcement learning for the agent to improve its scanning strategies over time.
*   **Reporting & Dashboards:**
    *   Historical trend analysis of vulnerabilities.
    *   User accounts and team-based reporting.
*   **MCP Server/Tool (Aligning with Hackathon Theme):**
    *   Expose AgentPimentBleu's scanning and assessment capabilities as an MCP tool, allowing other agents or MCP clients to utilize its services.
*   **Community & Open Source Development:**
    *   Foster a community around the project if it gains traction.

---

This roadmap is a living document and will be updated as the project progresses and new ideas emerge. The immediate focus is on delivering a compelling MVP for the Gradio Agents & MCP Hackathon 2025.
