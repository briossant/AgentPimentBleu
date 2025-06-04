# Agent Rework Plan: Transition to Tool-Based Architecture

## 1. Current State & Problem

The `SecurityAgent` in `agent.py` currently uses a hardcoded, multi-step prompting approach to analyze vulnerabilities. This is:
- **Fragile:** Relies on specific LLM output formats parsed by regex (`_extract_field`).
- **Monolithic:** Prompts are long and try to achieve too much in one go.
- **Hard to Extend:** Adding new analysis steps or codebase interaction methods is cumbersome.
- **Not Truly Agentic:** The `_perform_exploration` method executes a pre-defined script based on LLM suggestions, rather than the LLM dynamically choosing actions.

The goal is to refactor `SecurityAgent` into a more robust, scalable, and maintainable tool-using agent, leveraging the Langchain library.

## 2. Proposed Architecture: Langchain Tool-Using Agent

The new agent will:
1.  Receive a high-level goal (e.g., "Analyze CVE X's impact on this project").
2.  Have access to a well-defined set of "Tools" (e.g., `ReadFile`, `FindFiles`).
3.  Use an LLM as a reasoning engine to decide which tool to use next with what arguments.
4.  Observe tool output and iterate until the goal is achieved.
5.  Produce a final, structured JSON report.

## 3. Detailed Implementation Plan

### Phase 1: Define Tools and Project Context

**Objective:** Abstract existing file system interaction logic into Langchain `Tool` objects.

1.  **Create `ProjectContext` Class:**
    *   Location: Potentially in `agent.py` or a new `agent_tools.py`.
    *   Purpose: To hold shared context like `repo_path`, `logger`, and pre-calculated `.gitignore` spec. This avoids passing `repo_path` to every tool function directly.
    *   Methods:
        *   `__init__(self, repo_path: str, logger)`
        *   `_get_gitignore_spec(self) -> Optional[PathSpec]` (from current `SecurityAgent`)
        *   `read_file_impl(self, file_path: str) -> str` (logic from current `read_file`)
        *   `find_files_impl(self, pattern: str) -> List[str]` (logic from current `find_files`)
        *   `search_in_files_impl(self, search_term: str) -> Dict[str, List[str]]` (logic from current `search_in_files`)
        *   `get_project_structure_impl(self) -> str` (logic from current `get_project_structure`)

2.  **Define Pydantic Schemas for Tool Arguments:**
    *   `ReadFileSchema(BaseModel)`: `file_path: str`
    *   `FindFilesSchema(BaseModel)`: `pattern: str`
    *   `SearchInFilesSchema(BaseModel)`: `search_term: str`

3.  **Create `get_tools(project_ctx: ProjectContext) -> List[Tool]` Function:**
    *   This function will instantiate and return a list of `Tool` objects.
    *   Each `Tool` will have:
        *   `name`: E.g., "GetProjectStructure", "ReadFile", "FindFiles", "SearchInFiles".
        *   `func`: A lambda or function that calls the corresponding `_impl` method on `project_ctx`.
        *   `description`: **Crucial for LLM understanding.** Clearly explain what the tool does, when to use it, and what its inputs/outputs are.
        *   `args_schema` (optional but good practice): Link to the Pydantic schemas defined above.

    *   **Example Tool (ReadFile):**
        ```python
        Tool(
            name="ReadFile",
            func=lambda file_path: project_ctx.read_file_impl(file_path),
            description="Reads the content of a specific file within the repository. Use this to inspect code or configuration. Input should be the relative file path.",
            args_schema=ReadFileSchema,
        )
        ```

### Phase 2: New Agent Implementation (`NewSecurityAgent`)

**Objective:** Create a new agent class using Langchain.

1.  **Location:** Create a new file `agent_v2.py` or refactor `agent.py`. For clarity, `agent_v2.py` might be better initially.
2.  **Class `NewSecurityAgent`:**
    *   `__init__(self, llm_provider_instance, repo_path: str)`:
        *   `llm_provider_instance`: This will be a Langchain-compatible LLM instance (e.g., `ChatOllama`).
        *   Initialize `ProjectContext`.
        *   Call `get_tools()` to get the list of tools.
        *   Create a Langchain agent (e.g., using `create_react_agent` or `create_openai_tools_agent` if using OpenAI models).
            *   Pull a suitable prompt from `langchain_hub` (e.g., "hwchase17/react") or define a custom one.
        *   Create an `AgentExecutor` with the agent, tools, `verbose=True`, and `handle_parsing_errors=True`.
    *   `_format_vulnerability_text(self, vulnerability: Dict[str, Any]) -> str`: (Helper to create consistent vulnerability text input).
    *   `analyze_vulnerability_agentic(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]`:
        *   Prepare the initial prompt for the agent. This prompt should:
            *   Provide the vulnerability information.
            *   State the overall goal (analyze impact, suggest fix).
            *   **Instruct the LLM to use the tools to explore and then conclude with a specific JSON output format.**
            *   Provide the exact JSON structure required for the final report (project_severity, is_project_impacted, impacted_code, proposed_fix, explanation).
        *   Invoke the `agent_executor`.
        *   Parse the final JSON output from the agent's response.
            *   Handle potential errors if the LLM doesn't perfectly adhere to the JSON format (e.g., use regex to find the JSON block, try-except for `json.loads`).
        *   Structure the result to be compatible with the existing `orchestrator.py` (including the nested `llm_analysis` dictionary).
        *   Store intermediate steps (conversation history) from the agent execution if available.

### Phase 3: LLM Integration

1.  **Adapt LLMProvider and Use Langchain Wrappers:**
    *   **Rewrite Ollama provider with langchain:** Use Langchain's built-in LLM wrappers (e.g., `ChatOllama`). The `create_llm_provider` in `llm/factory.py` will need to be able to return these Langchain-compatible instances, or the orchestrator will need to instantiate them directly.
        ```python
        from langchain_community.chat_models import ChatOllama
        llm = ChatOllama(model="your_model_name", base_url="http://localhost:11434", temperature=0) # low temp for tool use
        ```
    *   **Integrate the LLMProvider:** Adapt the existing `LLMProvider` and its subclasses (`OllamaProvider`, `ModalProvider`) to conform to Langchain's `BaseLanguageModel` interface.

### Phase 4: Orchestrator Integration

**Objective:** Update `orchestrator.py` to use `NewSecurityAgent`.

1.  Modify `enhance_sast_with_llm` and `enhance_sca_with_llm` in `orchestrator.py`.
2.  Instead of `SecurityAgent`, instantiate `NewSecurityAgent`.
    *   Ensure the correct Langchain-compatible LLM instance is passed.
3.  Call `agent.analyze_vulnerability_agentic(finding)` instead of `agent.analyze_vulnerability(finding)`.
4.  Update any assumptions about the returned dictionary structure if they changed (though the goal is to keep it compatible).

### Phase 5: Testing and Refinement

1.  **Verbose Logging:** Use `verbose=True` in `AgentExecutor` during development to see the agent's thought process.
2.  **Prompt Engineering:** Iterate heavily on:
    *   Tool descriptions (are they clear enough for the LLM?).
    *   The main agent prompt (does it guide the LLM effectively towards the goal and the final JSON output?).
3.  **Error Handling:** Test with various scenarios, including malformed LLM responses or tool errors.
4.  **Structured Output:** Ensure the final JSON output is consistently produced. If using ReAct, the LLM must be explicitly instructed to use a "Final Answer" that is *only* the JSON. Consider Langchain's `PydanticOutputParser` or `StructuredOutputParser` if direct JSON output is unreliable.
5.  **Memory:** Add conversation memory to the agent if needed for longer, more complex analyses (Langchain provides various memory types).

## 4. Expected Benefits

- **Robustness:** Less reliant on fragile LLM output parsing for intermediate steps.
- **Scalability:** Easier to add new tools/capabilities.
- **Maintainability:** Clearer separation of concerns (tools vs. agent reasoning).
- **Flexibility:** LLM can dynamically decide the best sequence of actions.
- **Improved Debugging:** Langchain's verbose mode provides insight into the agent's decision-making.

## 5. Future Considerations (Post-Rework)

- **LlamaIndex for CVE Details:** Implement a tool using LlamaIndex to retrieve more comprehensive CVE details from an external or local knowledge base.
- **LlamaIndex for Semantic Code Search:** If direct file search proves insufficient, add a LlamaIndex-powered tool for semantic code searching within the repository.
- **Advanced Agent Types:** Explore more sophisticated Langchain agent types (e.g., those designed for OpenAI function/tool calling if applicable models are used).
- **More Specialized Tools:**
    *   `RunCodeTool` (sandboxed, for specific checks - **HIGH RISK, use with extreme caution**).
    *   `DependencyGraphTool` (to analyze dependency relationships).