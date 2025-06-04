# AgentPimentBleu - Smart Security Scanner for Git Repositories

## 1. Vision & Core Idea

AgentPimentBleu is an AI-powered agent designed to intelligently scan Git repositories for security vulnerabilities. Unlike traditional scanners that often overwhelm users with numerous low-impact findings, AgentPimentBleu focuses on:

1.  Detecting coding mistakes and configuration errors with AI-enhanced context (Future Phase).
2.  Identifying vulnerable dependencies and, crucially, **assessing their actual impact** within the specific project's context, filtering out noise from irrelevant CVEs (Initial Focus).

The goal is to provide developers with actionable, prioritized security insights, enabling them to focus on what truly matters.

## 2. Problem Addressed

Current security scanning tools often suffer from:

*   **Alert Fatigue:** Reporting a large volume of potential vulnerabilities, many of which may not be exploitable or relevant.
*   **Lack of Context (SAST):** Flagging code patterns without understanding surrounding logic, leading to false positives.
*   **Superficial Dependency Analysis:** Reporting all known CVEs in a dependency, even if the vulnerable module/function is not used.

AgentPimentBleu aims to address these by integrating AI reasoning, particularly for contextual impact assessment of dependencies.

## 3. Core Principles

*   **AI-Enhanced Context:** Leverage Large Language Models (LLMs) to understand code, CVE descriptions, and project structure to determine real-world impact.
*   **Modularity:** Design components (services, tools, agent graphs) to be independent for easier development, testing, and scaling.
*   **Actionable Insights:** Focus on providing clear, concise, and prioritized vulnerabilities with suggested fixes.
*   **Developer Experience:** Offer both a user-friendly GUI (Gradio) for interactive scans and an API for CI/CD integration.
*   **Reproducibility:** Utilize Nix (via `flake.nix`) for consistent development environments.

## 4. Technology Stack

*   **LLM Providers:** Gemini API, Ollama (and others, via abstraction)
*   **UI:** Gradio
*   **Agent Framework:** LangGraph (for complex, stateful agent logic)
*   **Underlying SCA Tools**: npm audit, pip audit (or similar like safety), potentially others based on project type.
*   **RAG:** Llama-index
*   **API:** FastAPI
*   **Configuration:** External YAML file
*   **Logging:** Custom Singleton Logger
*   **Development Environment:** NixOS (`flake.nix`)
*   **Deployment:** Hugging Face Spaces

## 5. Project Architecture

```
agentpimentbleu/
├── api/                        # FastAPI for the API interface
│   ├── __init__.py
│   ├── main.py                 # FastAPI app definition
│   ├── routers/
│   │   └── scan.py             # API endpoint for initiating scans
│   └── models/
│       └── scan_models.py      # Pydantic models for API requests/responses
├── app/                        # Gradio UI application
│   ├── __init__.py
│   ├── app.py                  # Main Gradio interface logic
│   └── ui_components/          # Reusable Gradio components
├── core/                       # Core logic and agent orchestration
│   ├── __init__.py
│   ├── agent.py                # Main agent entry point/runner
│   ├── graphs/                 # LangGraph definitions
│   │   └── sca_impact_graph.py # Graph for SCA and CVE impact analysis
│   └── tools/                  # Custom Langchain/LangGraph tools
│       ├── git_cloner_tool.py
│       └── dependency_analyzer_tool.py # Tool to invoke SCA process
├── services/                   # Business logic services
│   ├── __init__.py
│   ├── git_service.py          # Handles Git operations (cloning)
│   ├── dependency_service.py   # Dependency parsing, CVE fetching
│   ├── llm_service.py          # Abstraction for multiple LLM providers
│   └── rag_service.py          # Manages Llama-index RAG operations
├── config/                     # Configuration files
│   ├── __init__.py
│   └── config.py               # Loads and provides configuration settings (config file is under ~/.config/agentpimentbleu/)
├── utils/                      # Utility functions and classes
│   ├── __init__.py
│   ├── logger.py               # Singleton logger implementation
│   └── file_parsers/           # Directory for dependency file parsers
│       ├── __init__.py
│       ├── base_parser.py      # Abstract base class for parsers
│       ├── python_parser.py    # For requirements.txt, Pipfile.lock, etc.
│       └── javascript_parser.py # For package-lock.json, yarn.lock, etc.
├── data/                       # For temporary data, RAG indexes
│   └── rag_indexes/            # Stores Llama-index data per scan
├── examples/                   # Example vulnerable projects for testing
├── tests/                      # Unit and integration tests
│   ├── core/
│   ├── services/
│   └── api/
├── dev_context/                # Documentation for LLMs and agents
├── main.py                     # Main entry point (e.g., for CLI, combined startup)
├── Dockerfile                  # For Hugging Face Spaces deployment
├── requirements.txt            # Python dependencies (for HF Spaces, venv)
├── flake.nix                   # Nix flake for NixOS development and builds
└── README.md                   # This file!
```

## 6. Core Components & Services

### 6.1. `api/` (FastAPI)
*   Provides RESTful endpoints for programmatic interaction (e.g., CI/CD).
*   Primary endpoint: `/scan/repository` (accepts repo URL, returns scan ID or results).
*   Uses Pydantic models (`api/models/scan_models.py`) for request/response validation.

### 6.2. `app/` (Gradio)
*   Provides a web-based GUI for users to input a Git repository URL and view scan results.
*   Interacts with the core agent logic, possibly via the FastAPI backend or directly.

### 6.3. `core/` (Agent Logic - LangGraph)
*   **`agent.py`**: Orchestrates the overall scan process.
*   **`graphs/sca_impact_graph.py`**: A LangGraph defining the stateful, multi-step process for Software Composition Analysis (SCA) and CVE impact assessment.
    *   **State:** Manages `cloned_repo_path`, `project_code_index` (RAG), `current_dependency`, `current_cve_details`, `list_of_identified_vulnerabilities`.
    *   **Nodes (Conceptual):**
        1.  `identify_dependencies_and_cves`: Parses manifests, fetches CVEs.
        2.  `setup_rag_index_for_project`: Indexes the cloned project code using `RAGService`.
        3.  `process_next_cve` (Looping logic for each CVE):
            *   `analyze_cve_description` (LLM): Understands the CVE.
            *   `search_codebase_for_impact` (LLM + RAG): Finds usage of vulnerable code.
            *   `evaluate_impact_and_danger` (LLM): Assesses actual risk in context.
            *   `propose_fix` (LLM): Suggests remediation.
        4.  `compile_final_report`: Aggregates findings.
*   **`tools/`**:
    *   `git_cloner_tool.py`: Clones Git repositories.
    *   `dependency_analyzer_tool.py`: Invokes the `sca_impact_graph`.

### 6.4. `services/`
*   **`git_service.py`**:
    *   Clones remote Git repositories to a temporary local path.
    *   May include functions to list files or get project structure if needed.
    *   Could be adapted to handle local directory paths from `examples/` by skipping the clone step.
*   **`dependency_service.py`**:
    *   Role: Detects project type, invokes the appropriate ecosystem-specific security audit tool (e.g., npm audit --json, pip audit --json), and parses their output to extract identified vulnerabilities (dependency name, version, CVE IDs, advisory links).
    *   It no longer manually parses all dependencies and queries generic CVE databases for each one. Instead, it orchestrates established audit tools.
    *   May still use a generic CVE database (like OSV.dev) to fetch additional details for a CVE ID if the audit tool's output is minimal.
*   **`llm_service.py`**:
    *   Abstracts interactions with different LLM providers (Gemini, Ollama).
    *   Loads provider configurations (API keys, model names, base URLs) from `config/settings.yaml`.
    *   Allows easy switching between providers.
*   **`rag_service.py`**:
    *   Manages Llama-index.
    *   Builds vector indexes from the project's source code.
    *   Provides querying capabilities to search for specific code patterns, function calls, etc., to support impact assessment.

### 6.5. `config/`
*   **`settings.yaml`**: Central configuration for API keys, LLM model preferences, paths, dependency manifest filenames per language, RAG settings.
*   **`config.py`**: Python module to load, validate, and provide easy access to settings from `settings.yaml`.

### 6.6. `utils/`
*   **`logger.py`**: Singleton logger for consistent logging across the application.
*   **`file_parsers/`**:
    *   `base_parser.py`: Defines an abstract base class for dependency parsers.
    *   Language-specific parsers (e.g., `python_parser.py`, `javascript_parser.py`) implement the base class to parse respective manifest files.

### 6.7. `data/`
*   `rag_indexes/`: (Potentially temporary per scan) Directory where Llama-index stores generated vector store indexes for the scanned repository's code.

### 6.8. `examples/` (Example Vulnerable Projects)
*   **Purpose:** This directory houses small, self-contained example projects with known vulnerabilities (e.g., using an outdated library with a specific CVE).
*   **Usage:**
    *   These projects serve as test cases for AgentPimentBleu, allowing developers to quickly verify its scanning capabilities.
    *   They can be used for local testing, demonstrations, and potentially integrated into automated tests.
    *   The `GitService` might be adapted or a utility provided to "clone" these local example directories as if they were remote Git repositories for testing purposes, or the UI/CLI might allow specifying a local path from this directory.
*   **Structure:** Each subdirectory within `examples/` should represent a distinct test case, typically organized by language or vulnerability type (e.g., `python_log4shell_usage/`, `js_specific_cve_project/`). Each example should include:
    *   The necessary dependency manifest files (e.g., `requirements.txt`, `package.json`).
    *   Minimal source code that actually uses the vulnerable part of the dependency, making the vulnerability exploitable or detectable in context.
    *   A `README.md` within each example project briefly describing the intended vulnerability and how to use it for testing AgentPimentBleu.

## 7. Key Workflow: SCA Impact Analysis (per CVE)

1.  **Input:** Git Repository URL or local path (e.g., to an `examples/` project).
2.  **Prepare Repository:**
    *   If URL: `GitService` clones the repo.
    *   If local path: Use the path directly.
3.  **Dependency Identification & CVE Fetching:** `DependencyService` parses manifest files and fetches known CVEs for each dependency.
4.  **RAG Indexing:** `RAGService` indexes the entire source code of the project.
5.  **Iterate Through CVEs (Handled by `sca_impact_graph`):**
    For each identified CVE:
    a.  **Analyze CVE Description (LLM):**
        *   Goal: Understand the vulnerability mechanism, affected functions/modules.
        *   Input: CVE text.
        *   Output: Structured understanding of the CVE.
    b.  **Search Codebase for Impact (LLM + RAG):**
        *   Goal: Determine if the vulnerable part of the dependency is used in the project.
        *   Input: Structured CVE understanding, RAG index of project code.
        *   LLM formulates queries for RAG or directly interprets RAG results based on CVE context.
        *   Output: Code snippets showing usage (or lack thereof).
    c.  **Evaluate Impact & Danger (LLM):**
        *   Goal: Assess if the usage constitutes an actual risk and assign a severity.
        *   Input: CVE understanding, code snippets from the project.
        *   Output: Impact summary, danger rating (e.g., Critical, High, Medium, Low).
    d.  **Propose Fix (LLM):**
        *   Goal: Suggest actionable remediation steps.
        *   Input: CVE details, impact summary.
        *   Output: Fix proposal (e.g., library update, code change).
6.  **Compile Report:** Aggregate all detailed vulnerability findings into a structured format.

## 8. Output Format (API/UI)

The final report will include a list of vulnerabilities, each with:

```json
{
  "cve_id": "CVE-YYYY-NNNNN",
  "cve_link": "https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN",
  "cve_description": "Original CVE description text...",
  "package_name": "example-library",
  "vulnerable_version_range": "<1.2.3",
  "analyzed_project_version": "1.2.0",
  "impact_in_project_summary": "The project uses the vulnerable 'do_evil()' function from 'example-library' in 'src/utils.py', which can be triggered by user-supplied input via the '/process' endpoint.",
  "evidence": [
    "src/utils.py: line 42: call to example_library.do_evil(user_input)"
  ],
  "danger_rating": "High", // Critical, High, Medium, Low, Informational
  "proposed_fix_summary": "Update 'example-library' to version 1.2.3 or higher. Alternatively, sanitize input before passing to 'do_evil()'.",
  "detailed_fix_guidance": "Run 'pip install example-library>=1.2.3'. Ensure comprehensive input validation is applied if immediate update is not possible."
}
```
(This is part of the `VulnerabilityDetail` model in `api/models/scan_models.py`)

## 9. Deployment

*   **Local Development:** `flake.nix` will provide a reproducible Nix shell with all Python dependencies, Git, and potentially Ollama.
*   **Hugging Face Spaces:**
    *   The primary application entry point for Gradio will be `app/app.py`.
    *   Dependencies managed by `requirements.txt`.
    *   A `Dockerfile` can be used for more complex system dependencies if needed.
    *   API keys and sensitive configurations will be managed via Hugging Face Space secrets.

## 10. Future Considerations

*   **SAST Integration:** Add static analysis capabilities, also enhanced with LLM context.
*   **RAG for CVE Knowledge Base:** Index a corpus of security advisories, exploit PoCs, and mitigation strategies to improve the "Analyze CVE Description" step.
*   **Incremental Scans & Caching:** Optimize for rescans of repositories.
*   **Broader Language Support:** Extend `utils/file_parsers/` for more package managers (Maven, Gradle, RubyGems, etc.).
*   **Interactive Fix Suggestions:** Allow users to explore or even apply patches through the UI (advanced).
*   **UI Enhancements:** Dropdown for `examples/` projects, better result visualization.
