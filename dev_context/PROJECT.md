# AgentPimentBleu - Smart Security Scanner for Git Repositories

**Hackathon:** Gradio Agents & MCP Hackathon 2025
**Track:** 3 - Agentic Demo Showcase
**Individual:** Brieuc Crosson

## 1. Vision & Core Idea

AgentPimentBleu is an AI-powered agent designed to intelligently scan Git repositories for security vulnerabilities. Unlike traditional scanners that often overwhelm users with numerous low-impact findings, AgentPimentBleu focuses on:
1.  Detecting coding mistakes and configuration errors with AI-enhanced context.
2.  Identifying vulnerable dependencies and, crucially, **assessing their actual impact** within the specific project's context, filtering out noise from irrelevant CVEs.

The goal is to provide developers with actionable, prioritized security insights, enabling them to focus on what truly matters.

## 2. Problem Addressed

Current security scanning tools, while valuable, often suffer from:
*   **Alert Fatigue:** Reporting a large volume of potential vulnerabilities, many of which may not be exploitable or relevant in the project's specific usage.
*   **Lack of Context:** SAST tools might flag code patterns without understanding the surrounding logic, leading to false positives.
*   **Superficial Dependency Analysis:** CVE scanners report all known vulnerabilities in a dependency, even if the vulnerable module or function is not used by the project. This makes it hard to prioritize fixes.

AgentPimentBleu aims to address these issues by integrating AI reasoning into the security analysis workflow.

## 3. Solution Overview: AgentPimentBleu

AgentPimentBleu is a Gradio-based application that:
1.  Accepts a public Git repository URL as input.
2.  Orchestrates a multi-stage security analysis:
    *   **Clones** the repository locally.
    *   Performs **Static Application Security Testing (SAST)** to find coding errors and misconfigurations, using an LLM to verify and contextualize findings.
    *   Conducts **Software Composition Analysis (SCA)** to identify dependencies and their known vulnerabilities.
    *   Leverages an **LLM to perform impact analysis** on identified dependency vulnerabilities, determining if the vulnerable parts of the dependency are likely used and what the real-world impact could be for *this* project.
3.  Presents a **clear, prioritized report** through the Gradio interface, highlighting issues with assessed high impact.

## 4. Key Features

*   **Git Repository Ingestion:** Accepts any public Git repository URL.
*   **Contextual SAST:**
    *   Integrates standard SAST tools.
    *   Uses an LLM to validate SAST findings, explain risks in the project's context, and suggest specific fixes.
    *   Detects common misconfigurations (hardcoded secrets, debug modes, etc.).
*   **Intelligent SCA & Impact Assessment:**
    *   Identifies project dependencies and checks for CVEs using established tools/databases.
    *   **AI-Powered Impact Analysis:** For each vulnerable dependency, the agent uses an LLM to:
        *   Analyze how the dependency is used within the project codebase.
        *   Assess the likelihood that the specific CVE is exploitable given the project's usage patterns.
        *   Estimate the potential business/security impact if exploited.
*   **Prioritized Reporting:** Generates a report that distinguishes between raw findings and vulnerabilities with a high likelihood of actual impact.
*   **User-Friendly Gradio Interface:** Provides an intuitive web UI for input, progress tracking, and viewing results.

## 5. High-Level Agent Architecture & Workflow

1.  **Input:** User provides a public Git repository URL via the Gradio UI.
2.  **Agent Initialization:** The main AgentPimentBleu orchestrator is triggered.
3.  **Cloning & Setup:**
    *   The orchestrator clones the specified repository to a temporary, isolated environment using `git_utils.py`.
4.  **Project Type Detection:**
    *   The `project_detector.py` module analyzes the repository to determine which programming languages are used.
    *   Currently detects JavaScript and Python projects by examining file extensions and dependency files.
5.  **Scanner Modules Selection:**
    *   Based on detected languages, the orchestrator dynamically loads appropriate scanner modules from the `scanners/` directory.
    *   Each language has dedicated SAST and SCA scanners with a standardized interface.
6.  **Static Analysis (SAST) - Coding/Configuration Mistakes:**
    *   **JavaScript:** Uses ESLint with security plugins via `scanners/js/sast.py`.
    *   **Python:** Uses Bandit via `scanners/python/sast.py`.
    *   **AI Enhancement:**
        *   Suspicious code snippets/config files can be sent to an LLM via the `llm` module.
        *   LLM prompts: Verify true positives, explain risk in context, suggest fixes, identify misconfigurations.
7.  **Dependency Analysis (SCA):**
    *   **JavaScript:** Uses npm audit via `scanners/js/sca.py`.
    *   **Python:** Uses pip-audit via `scanners/python/sca.py`.
    *   Identifies dependencies and checks for known vulnerabilities.
8.  **AI-Powered Impact Assessment:**
    *   For each vulnerable dependency:
        *   **Code Usage Analysis:** Agent attempts to find where and how the dependency is imported/used.
        *   **LLM Reasoning:** The LLM is provided with CVE details, library information, and code snippets via the `llm` module.
9.  **Report Generation:**
    *   The `reporting` module compiles findings from all scanners into a standardized format.
    *   Uses a modular architecture with a base reporter class and language-specific reporter classes.
    *   Generates a Markdown report with sections for each scanner type and language, with language-specific formatting and recommendations.
10. **Gradio UI Presentation:**
    *   Results are displayed in a structured and readable format through the Gradio interface.

## 6. Technical Stack

*   **Primary Language:** Python
*   **UI Framework:** Gradio
*   **Git Interaction:** `subprocess` module for Git operations.
*   **Project Detection:** Custom logic to identify programming languages and project types.
*   **Modular Scanner Architecture:**
    *   Standardized interfaces for all scanners
    *   Dynamic loading of appropriate scanners based on detected languages
*   **SAST Tools Implemented:**
    *   **JavaScript:** ESLint with security plugins
    *   **Python:** Bandit
*   **SCA Tools Implemented:**
    *   **JavaScript:** npm audit
    *   **Python:** pip-audit
*   **LLM Integration:**
    *   Ollama for local LLM deployment
    *   Modal for cloud-based LLM inference
    *   Configuration system in ~/.config/agent_piment_bleu/
    *   Extensible provider interface for future integrations
*   **Orchestration:** Modular Python architecture with the orchestrator coordinating the scanning process.

## 7. AI "Intelligence" - How AgentPimentBleu Leverages AI

*   **Contextual Understanding:** LLMs interpret code snippets and configuration files to understand their purpose and potential security implications beyond simple pattern matching.
*   **Prioritization & Noise Reduction:** The core AI function is to analyze CVEs in the context of the project's actual usage of a dependency, filtering out vulnerabilities in unused code paths and highlighting truly impactful ones.
*   **Tailored Explanations & Recommendations:** LLMs generate human-readable explanations of risks and suggest fixes relevant to the specific code being analyzed.
*   **Hypothesis Generation (for Impact):** The LLM reasons about how a known CVE in a dependency *could* manifest as a problem in the *host project*.

## 8. Gradio UI Flow (Conceptual)

1.  **Input Screen:**
    *   Title: "AgentPimentBleu: Smart Security Scanner"
    *   `gr.Textbox`: "Enter Public Git Repository URL"
    *   `gr.Button`: "Scan Project with AgentPimentBleu"
    *   `gr.Label` (Status): "Idle"
2.  **Scanning In Progress:**
    *   Status Label updates: "Cloning repository...", "Analyzing code with AI...", "Checking dependencies...", "AI assessing vulnerability impacts..."
    *   Optional: `gr.Progress()` bar.
3.  **Results Screen (using `gr.Markdown` or `gr.HTML`):**
    *   **Summary Section:** Key metrics (e.g., Critical Impact Issues, AI-Verified Issues).
    *   **Coding & Configuration Issues (AI-Enhanced):**
        *   Details: File, line number, code snippet.
        *   AI Assessment: Likelihood, impact explanation, recommended fix.
    *   **Impactful Dependency Vulnerabilities:**
        *   Details: CVE ID, library, severity.
        *   AI Impact Assessment: Explanation of how the project's usage relates to the CVE, likelihood of exploitation, potential impact specific to the project.
    *   (Optional) Raw list of all detected vulnerabilities for full transparency.

## 9. Hackathon Submission Details

*   **Track:** Track 3: Agentic Demo Showcase
*   **README.md Tag:** `agent-demo-track`
*   **Video Requirement:** A video overview explaining the usage/purpose of AgentPimentBleu and demonstrating its capabilities will be included with the submission.

## 10. Potential Challenges

*   **LLM Prompt Engineering:** Crafting effective prompts for accurate impact assessment and code analysis.
*   **Tool Output Parsing:** Reliably processing outputs from diverse security tools.
*   **Execution Time:** Balancing thoroughness of scans with reasonable execution time for a live demo.
*   **Environment Complexity:** Managing dependencies for various security tools (mitigated by focusing on Python-native or easily callable tools first).
*   **Accuracy of AI Assessment:** LLMs can hallucinate; results will be presented as AI-assisted assessments, not infallible judgments.

## 11. Future Ideas (Beyond Hackathon Scope)

*   **Deeper Static/Dynamic Analysis:** More advanced techniques to trace data flow and confirm exploitability of dependency vulnerabilities.
*   **Support for Private Repositories:** Integrating authentication mechanisms.
*   **Automated Fix Suggestions (PRs):** Generating pull requests for simple fixes.
*   **CI/CD Integration:** Allowing AgentPimentBleu to run as part of a development pipeline.
*   **Fine-tuning a specialized LLM:** Training a model specifically for security vulnerability assessment in code.
*   **MCP Integration:** If feasible, explore how AgentPimentBleu could expose its capabilities as an MCP tool.
