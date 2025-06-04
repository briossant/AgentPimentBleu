# AgentPimentBleu - AI Implementation Roadmap

This roadmap outlines the development phases and tasks for an AI agent (LLM) to implement AgentPimentBleu. Each task includes a description and an "LLM Instruction" designed to guide code generation.

## Phase 0: Project Setup & Core Foundation

**Goal:** Establish the basic project structure, development environment, configuration, and logging.

1.  **Task 0.1: Initialize Project Structure**
    *   **Description:** Create the directory structure as outlined in `DOCUMENTATION.md`.
    *   **LLM Instruction:** "Create the following directory structure for the 'agentpimentbleu' project: `api/routers`, `api/models`, `app/ui_components`, `core/graphs`, `core/tools`, `services`, `config`, `utils/file_parsers`, `data/rag_indexes`, `examples/python_example_vulnerable_project_1/src`, `examples/javascript_example_vulnerable_project_1`, `tests/core`, `tests/services`, `tests/api`, `.github/workflows`. Create `__init__.py` files in all Python package directories."

2.  **Task 0.2: Setup `flake.nix`**
    *   **Description:** Create the `flake.nix` file for a reproducible development environment.
    *   **LLM Instruction:** "Generate a `flake.nix` file for a Python 3.10 project. Include `git` as a system dependency. For Python dependencies, initially include `python310Packages.pip`, `python310Packages.fastapi`, `python310Packages.uvicorn`, `python310Packages.gradio`, `python310Packages.langchain`, `python310Packages.langgraph`, `python310Packages.llama-index`, `python310Packages.python-dotenv`, `python310Packages.pyyaml`, `python310Packages.requests`, `python310Packages.ollama` (if available in nixpkgs, else note as external). Provide a default development shell. Ensure the `examples` directory is accessible within the Nix environment."

3.  **Task 0.3: Implement Singleton Logger**
    *   **Description:** Create the singleton logger utility.
    *   **LLM Instruction:** "Generate Python code for `utils/logger.py`. Implement a `LoggerSingleton` class. It should ensure only one logger instance (using `logging.getLogger`) is created for the application. The logger should be named 'AgentPimentBleu' by default and use `logging.INFO` level. Configure a console stream handler with the formatter: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`. Add a method to allow changing the log level if needed."

4.  **Task 0.4: Implement Configuration Loading**
    *   **Description:** Create `config/settings.yaml` (template) and `config/config.py`.
    *   **LLM Instruction:**
        *   "Create a template `config/settings.yaml` file. Include sections for `llm_providers` (with sub-sections for `gemini` and `ollama`, each having `api_key` or `base_url` and `model` fields), `dependency_parsers` (with `python_manifests: ['requirements.txt', 'Pipfile', 'poetry.lock']` and `javascript_manifests: ['package.json', 'package-lock.json', 'yarn.lock']`), and `rag_settings` (with `embedding_model` and `chunk_size`). Use placeholder values like 'YOUR_API_KEY'."
        *   "Generate Python code for `config/config.py`. Implement a class, e.g., `Settings`, that loads configuration from `~/.config/agentpimentbleu/settings.yaml` using PyYAML. It should warn the user if the file is missing and fallback to `config/settings.yml`. Use `python-dotenv` to load environment variables that can override YAML values (e.g., API keys). Provide methods to access configuration values easily (e.g., `settings.get_llm_provider_config('gemini')`). Implement it as a singleton or ensure it's loaded once."

## Phase 1: Basic SCA Mechanics & Services

**Goal:** Implement services for Git operations, dependency parsing (for Python & JS initially), CVE fetching, and create example projects.

1.  **Task 1.1: Implement `GitService`**
    *   **Description:** Service to clone Git repositories. It should also be able to handle local paths (e.g., from `examples/`) by essentially skipping the clone for local paths and just validating their existence.
    *   **LLM Instruction:** "Generate Python code for `services/git_service.py`. Create a `GitService` class. Implement a method `prepare_repository(repo_source: str, local_base_path: str) -> Optional[str]`:
        *   If `repo_source` is a URL, it clones the Git repository into a unique a new temp directory using the `git` command-line tool (via `subprocess`). Ensure it handles potential errors.
        *   If `repo_source` is a local path with a special test url, it should copy the associated example project into a new temp directory.
        *   Return the absolute path to the prepared repository on success, `None` on failure.
        *   Include a method `cleanup_repository(repo_path: str)` that deletes the created directory.
        Use the `tempfile` module for creating unique temporary directory names for clones."

2.  **Task 1.2: Implement `Manifest Identifiers`**
    *   **Description:** Utilities to identify the type of project and main manifest file.
    *   **LLM Instruction:**
        *   "Create `utils/file_parsers/base_identifier.py`. Define an abstract base class `BaseManifestIdentifier` with an abstract method `identify(project_path: str) -> Optional[Tuple[str, str]]` which returns a tuple of (project_type_string, manifest_file_path) or None if not identified."
        *   "Create `utils/file_parsers/python_identifier.py`. Implement `PythonManifestIdentifier(BaseManifestIdentifier)`. It should look for `requirements.txt`, `Pipfile`, `pyproject.toml` (with poetry/pdm markers) in `project_path`. If found, return ('python', path_to_found_file)."
        *   "Create `utils/file_parsers/javascript_identifier.py`. Implement `JavaScriptManifestIdentifier(BaseManifestIdentifier)`. It should look for `package.json` in `project_path`. If found, return ('javascript', path_to_package_json)."
        *   "In `utils/file_parsers/__init__.py`, create a list of available identifier instances."

3.  **Task 1.3: Implement `DependencyService`**
    *   **Description:** Service to orchestrate external audit tools (`npm audit`, `pip audit`) and parse their results.
    *   **LLM Instruction:** "Generate Python code for `services/dependency_service.py`. Create a `DependencyService` class.
        *   Constructor should take `config` (from `config.config.py`) and a list of manifest identifiers from `utils.file_parsers`.
        *   Implement `detect_project_type_and_manifest(project_path: str) -> Optional[Tuple[str, str]]`: Iterates through manifest identifiers to find the project type (e.g., 'python', 'javascript') and the path to the primary manifest file.
        *   Implement `run_security_audit(project_path: str, project_type: str, manifest_path: Optional[str]) -> List[Dict]`:
            *   If `project_type` is 'javascript':
                *   Execute `npm audit --json --prefix {project_path}` (or change directory to `project_path` and run `npm audit --json`) using `subprocess`.
                *   Parse the JSON output. Extract relevant fields for each vulnerability: `name` (of the module), `version` (of the vulnerable module), `via` (source package if transitive), `severity`, `title`/`cve` (or advisory ID/link), `fixAvailable` (true/false/object).
                *   Transform this into a standardized list of dictionaries, each representing a vulnerability: `{'package_name': str, 'vulnerable_version': str, 'cve_ids': List[str], 'advisory_link': Optional[str], 'advisory_title': Optional[str], 'severity': str, 'fix_suggestion_from_tool': Optional[str]}`.
            *   If `project_type` is 'python':
                *   Ensure `manifest_path` is provided and valid (e.g., path to `requirements.txt`).
                *   Execute `pip audit --json -r {manifest_path}` (or other relevant `pip-audit` command if `-r` is not the only way) using `subprocess`.
                *   Parse the JSON output from `pip audit`. Extract similar fields.
                *   Transform into the same standardized list of dictionaries.
            *   Handle errors from subprocess calls and JSON parsing (log errors, return empty list for that audit).
        *   (Optional) Implement `fetch_cve_details(cve_id: str) -> Optional[Dict]`: Uses OSV.dev or similar to get more details if needed, but prioritize info from audit tools.
            The primary output should be a list of vulnerabilities ready for the `sca_impact_graph`."

4.  **Task 1.4: Create Initial Example Vulnerable Projects**
    *   **Description:** Populate the `examples/` directory with a few basic vulnerable projects for Python and JavaScript.
    *   **LLM Instruction:** "For the `examples/` directory:
        *   **For `python_example_vulnerable_project_1`**:
            *   Create `examples/python_example_vulnerable_project_1/requirements.txt` with `Werkzeug==0.10.0`.
            *   Create `examples/python_example_vulnerable_project_1/src/main.py` with a minimal Flask/Werkzeug app that enables the debug console (known to be vulnerable in old Werkzeug versions if the pin is guessable/disabled).
            *   Create `examples/python_example_vulnerable_project_1/README.md` explaining: 'This project uses Werkzeug 0.10.0. An old version of Werkzeug with an improperly secured debugger can lead to RCE. AgentPimentBleu should identify CVE-2016-10149 (or similar related to Werkzeug debugger) and assess its impact if the debugger is enabled and accessible.'
        *   **For `javascript_example_vulnerable_project_1`**:
            *   Create `examples/javascript_example_vulnerable_project_1/package.json` with `{"dependencies": {"lodash": "4.17.10"}}`.
            *   (Manually run `npm install` in this directory to generate `package-lock.json` or instruct the user to do so. For now, the LLM doesn't need to generate the lockfile itself).
            *   Create `examples/javascript_example_vulnerable_project_1/index.js` with: `const _ = require('lodash'); const maliciousInput = '__proto__'; let obj = {}; _.set(obj, maliciousInput + '.isAdmin', true); if (obj.isAdmin) console.log("Vulnerable to prototype pollution!");`.
            *   Create `examples/javascript_example_vulnerable_project_1/README.md` explaining: 'This project uses lodash 4.17.10. It demonstrates prototype pollution (e.g., CVE-2019-10744, CVE-2020-8203). AgentPimentBleu should identify the relevant CVE and highlight the use of vulnerable functions like `_.set`.'
        Focus on clear, minimal examples where the vulnerable function/feature is explicitly used."

## Phase 2: RAG Integration

**Goal:** Integrate Llama-index for indexing project code and enabling semantic search.

1.  **Task 2.1: Implement `RAGService`**
    *   **Description:** Service to manage RAG operations using Llama-index.
    *   **LLM Instruction:** "Generate Python code for `services/rag_service.py`. Create a `RAGService` class.
        *   Constructor should take `config` (from `config.config.py`).
        *   Implement `build_index_from_project(project_path: str, index_storage_path: str) -> Optional[llama_index.core.indices.base.BaseIndex]`: This method should:
            *   Use `SimpleDirectoryReader` from Llama-index to load documents from the `project_path` (recursively, common source code file extensions like .py, .js, .java, .ts, .tsx, .go, .rb, .php, .c, .cpp, .h, .cs, .swift).
            *   Build a `VectorStoreIndex` from these documents.
            *   Persist the index to `index_storage_path` using `storage_context.persist()`.
            *   Return the created index, or `None` on error.
        *   Implement `load_index(index_storage_path: str) -> Optional[llama_index.core.indices.base.BaseIndex]`: Loads a persisted index. Returns `None` if not found or error.
        *   Implement `query_index(index: llama_index.core.indices.base.BaseIndex, query_text: str) -> str`: Creates a query engine from the index and returns the response to the `query_text`.
        *   The service should initialize necessary Llama-index components (like `ServiceContext` or `Settings` for embeddings, potentially using a local embedding model like from `llama-index-embeddings-huggingface` or deferring to an LLM's embedding if using a powerful one like Gemini). Configure embedding model based on `config.rag_settings`. Handle errors gracefully."

## Phase 3: Core AI Agent - SCA Impact Graph (LangGraph)

**Goal:** Implement the LangGraph for detailed, AI-driven SCA and impact analysis.

1.  **Task 3.1: Implement `LLMService`**
    *   **Description:** Abstraction layer for interacting with LLM providers.
    *   **LLM Instruction:** "Generate Python code for `services/llm_service.py`. Create an `LLMService` class.
        *   Constructor should take `config` (from `config.config.py`).
        *   Implement a method `get_llm(provider_name: Optional[str] = None) -> BaseChatModel` (from Langchain). This method should:
            *   Determine the provider: if `provider_name` is given, use it; otherwise, use the default from `config`.
            *   Initialize and return a Langchain chat model instance for the chosen provider (e.g., `ChatGoogleGenerativeAI` for Gemini, `ChatOllama` for Ollama). Load API keys/base URLs from `config`.
            *   Handle cases where a provider is requested but not configured.
        *   Implement a method `invoke_llm(prompt_template: BasePromptTemplate, input_data: Dict, provider_name: Optional[str] = None) -> str`: Gets an LLM, creates a chain with the prompt template, invokes it with `input_data`, and returns the string content of the AIMessage."

### Phase 3: Core AI Agent - SCA Impact Graph (LangGraph)

**Task 3.2: Define State and Nodes for `sca_impact_graph.py`**
*   **LLM Instruction:** "In `core/graphs/sca_impact_graph.py`:
    *   Import necessary services (`GitService`, `DependencyService`, `RAGService`, `LLMService`), config, and logger.
    *   Define a TypedDict `ScaImpactState` to hold: `repo_source: str` (URL or local path), `cloned_repo_path: Optional[str]`, `project_type: Optional[str]`, `project_manifest_path: Optional[str]`, `project_code_index_path: Optional[str]`, `audit_tool_vulnerabilities: List[Dict]` (this replaces `dependencies_with_cves`), `current_vulnerability_idx: int` (replaces `current_cve_idx`), `current_vulnerability_details: Optional[Dict]` (holds one item from `audit_tool_vulnerabilities`), `current_cve_analysis_results: Optional[Dict]`, `final_vulnerabilities: List[Dict]`, `error_message: Optional[str]`.
    *   Implement the following node functions, each taking `ScaImpactState` and returning a `Partial[ScaImpactState]`:
        *   `prepare_scan_environment(state: ScaImpactState) -> Partial[ScaImpactState]`: (Uses `GitService` to prepare repo).
        *   `identify_project_and_run_audit_node(state: ScaImpactState) -> Partial[ScaImpactState]`: (Uses `DependencyService.detect_project_type_and_manifest` and then `DependencyService.run_security_audit`). Store `project_type`, `project_manifest_path`, and `audit_tool_vulnerabilities`.
        *   `build_rag_index_node(state: ScaImpactState) -> Partial[ScaImpactState]`: (Uses `RAGService`). Store RAG index path.
        *   `select_next_vulnerability_node(state: ScaImpactState) -> Partial[ScaImpactState]`: Logic to pick the next item from `audit_tool_vulnerabilities`, update `current_vulnerability_idx`, `current_vulnerability_details`.
        *   `analyze_cve_description_node(state: ScaImpactState) -> Partial[ScaImpactState]`: (Will use `LLMService`). Store analysis in `current_cve_analysis_results`.
        *   `search_codebase_for_impact_node(state: ScaImpactState) -> Partial[ScaImpactState]`: (Will use `RAGService` and `LLMService`). Store findings in `current_cve_analysis_results`.
        *   `evaluate_impact_and_danger_node(state: ScaImpactState) -> Partial[ScaImpactState]`: (Will use `LLMService`). Store rating in `current_cve_analysis_results`.
        *   `propose_fix_node(state: ScaImpactState) -> Partial[ScaImpactState]`: (Will use `LLMService`). Store fix in `current_cve_analysis_results`.
        *   `aggregate_cve_results_node(state: ScaImpactState) -> Partial[ScaImpactState]`: Compiles `current_cve_analysis_results` into the `VulnerabilityDetail` format (from `api.models.scan_models`) and appends to `final_vulnerabilities`.
        *   `cleanup_scan_environment_node(state: ScaImpactState) -> Partial[ScaImpactState]`: (Uses `GitService` to delete repo if cloned, potentially `RAGService` to delete index).
        *   `compile_final_report_node(state: ScaImpactState) -> Partial[ScaImpactState]`: Prepares the final output (e.g., the `final_vulnerabilities` list)."

**Task 3.3: Wire `sca_impact_graph.py` with LangGraph**
*   **LLM Instruction:** "In `core/graphs/sca_impact_graph.py`, using LangGraph:
    *   Create a `StatefulGraph` with the `ScaImpactState`.
    *   Add the nodes defined in Task 3.2.
    *   Set `prepare_scan_environment` as the entry point.
    *   Define conditional edges:
        *   From `prepare_scan_environment`: if error, go to `cleanup_scan_environment_node`; else, to `identify_project_and_run_audit_node`.
        *   From `identify_project_and_run_audit_node`: if no vulnerabilities found by audit or error, go to `compile_final_report_node` (to report no findings or the error); else, to `build_rag_index_node`.
        *   From `build_rag_index_node`: if error building index, go to `compile_final_report_node` (can still report audit findings but note RAG failure); else, to `select_next_vulnerability_node`.
        *   After `select_next_vulnerability_node`: if a vulnerability is selected (more to process), go to `analyze_cve_description_node`; otherwise (all vulnerabilities processed), go to `compile_final_report_node`.
        *   Sequence for vulnerability processing: `analyze_cve_description_node` -> `search_codebase_for_impact_node` -> `evaluate_impact_and_danger_node` -> `propose_fix_node` -> `aggregate_cve_results_node` -> `select_next_vulnerability_node`. Handle potential errors in each of these nodes by logging, perhaps setting an error flag for that specific vulnerability, and then transitioning to `select_next_vulnerability_node` (to skip problematic vulnerability) or `cleanup_scan_environment_node` for critical graph-breaking errors.
    *   Edge from `compile_final_report_node` to `cleanup_scan_environment_node`.
    *   Set `cleanup_scan_environment_node` as an end node (or connect to a final node that returns the state).
    *   Compile the graph. Provide a function `run_sca_scan(repo_source: str, app_config: Settings) -> Dict` that initializes services with `app_config`, sets up the initial state, and invokes the graph using `graph.invoke()`. It should return the relevant part of the final state (e.g., `final_vulnerabilities` or an error message)."

**Task 3.4: Implement LLM Logic in Graph Nodes**
*   **LLM Instruction:** "For each LLM-dependent node in `core/graphs/sca_impact_graph.py` (`analyze_cve_description_node`, `search_codebase_for_impact_node`, `evaluate_impact_and_danger_node`, `propose_fix_node`):
    *   Ensure the node function has access to an `LLMService` instance (passed via state or initialized globally).
    *   Create appropriate `PromptTemplate` instances (e.g., `ChatPromptTemplate.from_messages`).
    *   Use the `LLMService.invoke_llm` method with these prompts and the relevant data from the `current_vulnerability_details` (which comes from the audit tool) and other state fields.
    *   Parse the LLM's JSON response (ensure prompts ask for JSON) and update the `current_cve_analysis_results` field in the state. Handle potential JSON parsing errors.
    *   **Prompt for `analyze_cve_description_node`:** 'Analyze this vulnerability reported for library {package_name} (version {vulnerable_version}): CVEs: {cve_ids_list}, Tool Advisory Title: {tool_advisory_title}, Tool Advisory Details/Link: {tool_advisory_link}. Identify: 1. The core vulnerability type. 2. The specific function(s), module(s), or component(s) likely affected in the library. 3. Key conditions or inputs required for exploitation based on the advisory. Return a structured JSON object with keys: `vulnerability_type`, `affected_components` (list of strings), `exploitation_conditions`.'
    *   **Prompt for `search_codebase_for_impact_node`:** (This node will also use `RAGService`). 'Project Code RAG Query: Based on this CVE analysis for library {package_name}: {cve_analysis_json}. The project uses {package_name} version {vulnerable_version}.
        1. Formulate 1-2 concise search queries for a code vector database to find if the vulnerable component(s) (e.g., `{vulnerable_component_name_from_cve_analysis}`) are used in the project.
        2. Given RAG search results: "{rag_search_results_snippets}", analyze these snippets.
        3. Summarize if direct usage of the vulnerable component is found and provide the file path and a short relevant code snippet as evidence. If no direct usage, state that.
           Return a structured JSON object with keys: `rag_queries_formulated` (list of strings), `usage_found` (boolean), `evidence_snippet` (string or null), `file_path` (string or null), `explanation` (string).'
    *   **Prompt for `evaluate_impact_and_danger_node`:** 'Impact Assessment: Given vulnerability in {package_name} (CVEs: {cve_ids_list}), its analysis: {cve_analysis_json}, and the project's usage context: {code_usage_summary_json}.
        1. Explain if the project's use of {package_name} exposes it to this vulnerability.
        2. Summarize the specific, direct impact on *this* project if it is vulnerable.
        3. Assign a danger rating: "Critical", "High", "Medium", "Low", or "Informational". Justify your rating.
           Return a structured JSON object with keys: `is_exploitable_in_context` (boolean with explanation), `impact_summary` (string), `danger_rating` (string), `rating_justification` (string).'
    *   **Prompt for `propose_fix_node`:** 'Fix Proposal: For vulnerability in {package_name} (version {vulnerable_version_used}, CVEs: {cve_ids_list}) with assessed impact: {impact_summary} and danger: {danger_rating}. The audit tool suggested: "{fix_suggestion_from_tool}".
        1. Elaborate on the primary recommended fix. If the tool suggested an update, confirm the target version.
        2. Are there alternative mitigations or workarounds if an update is not immediately possible?
           Return a structured JSON object with keys: `primary_fix_recommendation` (string), `alternative_mitigations` (list of strings).' "

## Phase 4: Interfaces (API & UI)

**Goal:** Develop the FastAPI and Gradio interfaces.

1.  **Task 4.1: Implement Pydantic Models for API**
    *   **Description:** Define data models for API requests and responses.
    *   **LLM Instruction:** "Generate Python code for `api/models/scan_models.py`.
        *   Create a Pydantic `BaseModel` named `ScanRequest` with a field `repo_source: str` (can be a URL or local path).
        *   Create a Pydantic `BaseModel` named `VulnerabilityDetail` with fields: `cve_id: str`, `cve_link: Optional[HttpUrl] = None`, `cve_description: str`, `package_name: str`, `vulnerable_version_range: str`, `analyzed_project_version: str`, `impact_in_project_summary: str`, `evidence: List[str] = []`, `danger_rating: str`, `proposed_fix_summary: str`, `detailed_fix_guidance: Optional[str] = None`.
        *   Create a Pydantic `BaseModel` named `SCAResult` with fields: `dependency_file_found: Optional[str] = None`, `vulnerabilities: List[VulnerabilityDetail] = []`, `issues_summary: Optional[str] = None`.
        *   Create a Pydantic `BaseModel` named `ScanOutput` with fields: `repo_source: str`, `scan_id: str`, `status: str`, `sca_results: Optional[SCAResult] = None`, `overall_summary: Optional[str] = None`, `error_message: Optional[str] = None`."

2.  **Task 4.2: Implement FastAPI Endpoints**
    *   **Description:** Create the API endpoint to trigger scans.
    *   **LLM Instruction:** "In `api/routers/scan.py`:
        *   Create a FastAPI `APIRouter`.
        *   Define a POST endpoint `/` (or `/repository`) that accepts a `ScanRequest` model.
        *   This endpoint should:
            *   Generate a unique `scan_id` (e.g., using `uuid.uuid4()`).
            *   Call the `run_sca_scan` function from `core.graphs.sca_impact_graph` (you'll need to import it and the `Settings` from `config.config`). Pass `scan_request.repo_source` and the loaded `app_config`.
            *   Construct and return a `ScanOutput` model based on the results from `run_sca_scan`. Set `status` to 'completed' or 'failed'.
        *   In `api/main.py`, create a FastAPI app instance and include this router. Load the global `Settings` once."

3.  **Task 4.3: Implement Gradio UI**
    *   **Description:** Create the basic Gradio interface.
    *   **LLM Instruction:** "Generate Python code for `app/app.py`.
        *   Import `gradio as gr`, `requests`, and `json`.
        *   Define a function `scan_repository(repo_source_input: str)` that will be called by Gradio.
            *   Inside this function, construct the payload for the FastAPI endpoint (`{'repo_source': repo_source_input}`).
            *   Make a POST request to your local FastAPI endpoint (e.g., `http://127.0.0.1:8000/scan/`).
            *   If the request is successful, parse the JSON response and format it nicely for display (e.g., as Markdown or using `gr.JSON`).
            *   If there's an error, return an error message.
        *   Create a Gradio interface: `gr.Interface(fn=scan_repository, inputs=gr.Textbox(label='Repository URL or Local Path (e.g., examples/python_example_vulnerable_project_1)'), outputs=[gr.Markdown(label='Scan Results'), gr.JSON(label='Raw JSON Output')], title='AgentPimentBleu - Smart Security Scanner', description='Enter a Git repository URL or a local path to an example project to scan for vulnerabilities.')`.
        *   Add `if __name__ == '__main__': app.launch()` to run the Gradio app."

## Phase 5: Deployment & Refinement

**Goal:** Prepare for Hugging Face deployment and refine the application.

**Task 5.1: Create `requirements.txt` and `Dockerfile`**
*   **LLM Instruction:**
    *   "`requirements.txt`: List all Python dependencies identified in `flake.nix` and used by the project (e.g., `fastapi`, `uvicorn[standard]`, `gradio`, `langchain`, `langgraph`, `llama-index`, `python-dotenv`, `pyyaml`, `requests`, `GitPython` (if using it instead of subprocess for git), specific `llama-index-embeddings-*`, `langchain-google-genai`, `ollama`, `pydantic<2` if Gradio has issues with Pydantic v2, `pip-audit`). Specify versions if known critical, otherwise let pip resolve."
    *   "`Dockerfile`: Generate a `Dockerfile` for a Python application. Start from a `python:3.10-slim` base image.
        *   Install system dependencies for Git and Node.js/npm: `RUN apt-get update && apt-get install -y --no-install-recommends git nodejs npm && npm install -g npm@latest && apt-get clean && rm -rf /var/lib/apt/lists/*`.
        *   Set `WORKDIR /app`.
        *   Copy `requirements.txt` and run `pip install --no-cache-dir -r requirements.txt`. (This will install `pip-audit`).
        *   Copy the entire `agentpimentbleu` application directory (e.g., `COPY . .`).
        *   Expose port 7860 (for Gradio).
        *   Set the `CMD` to run the Gradio app: `CMD ["python", "app/app.py"]`.
        *   (Note: For a combined FastAPI+Gradio deployment in one container, the CMD might need to run Uvicorn for FastAPI and have Gradio connect to it, or use a process manager. For HF Spaces, running Gradio directly is often simplest if it calls a separate API or embeds the logic)."

2.  **Task 5.2: Implement Main Entry Point (`main.py`)**
    *   **Description:** Create a main script for local execution options.
    *   **LLM Instruction:** "Create `main.py` at the project root. Use `argparse` to allow:
        *   Running the Gradio app: `python main.py ui` (should run `app/app.py`).
        *   Running the FastAPI server: `python main.py api` (should run `uvicorn api.main:app --reload`).
        *   Running a CLI scan: `python main.py scan --repo_source <URL_OR_PATH>` (this would initialize `Settings`, then call `run_sca_scan` from `core.graphs.sca_impact_graph` and print results to console in a readable JSON format).
        Make sure to correctly initialize configurations and services for each mode."

**Task 5.3: Testing Stubs and CI Workflow**
*   **LLM Instruction:**
    *   "In `tests/services/test_dependency_service.py`:
        *   Create a Pytest test function `test_run_npm_audit_mocked` that uses `unittest.mock.patch` to mock `subprocess.run` for the `npm audit --json` command. Provide sample JSON output (can be found online or by running `npm audit --json` on a small project) and assert that the service correctly parses it into the standardized list of vulnerability dictionaries.
        *   Create a similar test `test_run_pip_audit_mocked` for `pip audit --json`."
    *   "In `tests/core/test_sca_impact_graph.py`, create a test `test_run_scan_on_example_project_with_mocked_audit` that:
        *   Mocks `DependencyService.run_security_audit` to return a predefined list of vulnerability dictionaries (as if `npm audit` or `pip audit` found them).
        *   Mocks `LLMService.invoke_llm` to return predefined JSON responses for each LLM step.
        *   Mocks `RAGService.query_index` to return predefined code snippets.
        *   Uses one of the local `examples/` projects as input.
        *   Asserts that the `run_sca_scan` function produces an expected `VulnerabilityDetail` structure in its output based on the mocked audit findings and subsequent LLM processing."
    *   "In `.github/workflows/ci_cd.yml`, create a GitHub Actions workflow that:
        *   Triggers on push to `main` and pull requests.
        *   Sets up Python 3.10.
        *   Sets up Node.js (e.g., `actions/setup-node@v3` with a specific Node version like 18 or 20).
        *   Installs dependencies from `requirements.txt` (which includes `pip-audit`).
        *   Runs a linter (e.g., `ruff check . && ruff format --check .`).
        *   Runs Pytest tests (e.g., `pytest tests/`).
        *   (Optional) Includes a step to validate the Nix flake: `nix flake check .`."

This roadmap provides a structured approach for an AI to incrementally build AgentPimentBleu. Each LLM instruction aims to be specific enough for code generation while allowing the LLM to handle implementation details.
