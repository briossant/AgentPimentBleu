# AgentPimentBleu - Smart Security Scanner for Git Repositories

**Hackathon:** Gradio Agents & MCP Hackathon 2025  
**Track:** 3 - Agentic Demo Showcase  
**Tag:** agent-demo-track

## Overview

AgentPimentBleu is an AI-powered agent designed to intelligently scan Git repositories for security vulnerabilities. Unlike traditional scanners that often overwhelm users with numerous low-impact findings, AgentPimentBleu focuses on:

1. Detecting coding mistakes and configuration errors with AI-enhanced context.
2. Identifying vulnerable dependencies and, crucially, **assessing their actual impact** within the specific project's context, filtering out noise from irrelevant CVEs.
3. Exploring the codebase to understand how vulnerabilities might affect the specific project.

The agent follows a three-step process for each vulnerability:
1. Analyze the vulnerability details (CVE information)
2. Search for potential consequences in the codebase by exploring relevant files
3. Generate a comprehensive report with project-specific severity assessment

The goal is to provide developers with actionable, prioritized security insights, enabling them to focus on what truly matters.

## Current Status

This is the initial implementation of AgentPimentBleu, focusing on Phase 1 of the project roadmap:

- [x] Basic Gradio UI with repository URL input
- [x] Core functionality to clone and analyze Git repositories
- [x] LLM Integration with Ollama and Modal
- [x] SAST Integration with AI-enhanced analysis
- [x] SCA Integration with npm audit and pip-audit
- [x] AI-Powered Dependency Impact Assessment with codebase exploration
- [x] Intelligent agent that explores the codebase to assess vulnerability impact

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/AgentPimentBleu.git
   cd AgentPimentBleu
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. (Optional) Install Ollama for local LLM support:
   ```
   # Follow instructions at https://ollama.ai/download
   ```

4. (Optional) Install Modal for cloud LLM support:
   ```
   pip install modal
   modal token new
   ```

## Usage

1. Run the application:
   ```
   python app.py
   ```

2. Open your web browser and navigate to the URL displayed in the terminal (typically http://127.0.0.1:7860).

3. Enter a public Git repository URL in the input field and click "Scan Repository".

4. The application will clone the repository and display the scan results.

### Testing with Dummy Vulnerable Project

For testing purposes, AgentPimentBleu includes a dummy vulnerable JavaScript project:

1. Go to the "LLM Testing" tab in the UI.
2. Click the "Use Dummy Project" button at the bottom of the left column.
3. This will set the repository URL in the "Repository Scanner" tab to a special test URL.
4. Go back to the "Repository Scanner" tab and click "Scan Repository".
5. The application will use the local dummy project instead of cloning a repository.

This dummy project contains intentional vulnerabilities for testing the agent's analysis capabilities:
- Vulnerable dependencies in package.json
- Code with security issues (XSS, SSRF, command injection, etc.)
- Realistic project structure to test the agent's exploration capabilities

### LLM Configuration

AgentPimentBleu uses a configuration file at `~/.config/agent_piment_bleu/llm_config.json` to store LLM provider settings. The default configuration will be created automatically on first run, but you can modify it to change the default provider or provider-specific settings:

```json
{
  "default_provider": "ollama",
  "providers": {
    "ollama": {
      "base_url": "http://localhost:11434",
      "model": "llama2",
      "timeout": 60
    },
    "modal": {
      "model": "mistral-7b",
      "timeout": 60
    }
  }
}
```

## Using with Nix

If you're using NixOS or have the Nix package manager installed, you can use the provided flake.nix file to run the application or set up a development environment.

### Development Environment

To enter a development shell with all dependencies:

```bash
nix develop
```

This will provide a shell with all required Python packages. You can then run the application with:

```bash
python app.py
```

### Running the Application

To run the application directly:

```bash
nix run
```

### Building the Package

To build the package:

```bash
nix build
```

This will create a result directory with the built package.

## Project Structure

- `app.py`: Main entry point for the application
- `agent_piment_bleu/`: Core package containing the application code
  - `main.py`: Entry point for the application, re-exports main functions
  - `ui.py`: Gradio UI implementation
  - `orchestrator.py`: Main orchestrator that coordinates the scanning process
  - `agent.py`: Intelligent agent for exploring codebases and analyzing vulnerabilities
  - `project_detector.py`: Detects programming languages used in the repository
  - `reporting.py`: Generates formatted reports from scan results
  - `llm/`: LLM integration modules
    - `base.py`: Base LLM provider interface
    - `config.py`: Configuration handling for LLM settings
    - `factory.py`: Factory for creating LLM providers
    - `ollama.py`: Ollama LLM provider implementation
    - `modal_provider.py`: Modal LLM provider implementation
  - `scanners/`: Directory containing language-specific scanners
    - `js/`: JavaScript scanners
      - `sast.py`: JavaScript SAST scanner using ESLint
      - `sca.py`: JavaScript SCA scanner using npm audit
    - `python/`: Python scanners
      - `sast.py`: Python SAST scanner using Bandit
      - `sca.py`: Python SCA scanner using pip-audit
  - `utils/`: Utility functions
    - `git_utils.py`: Git repository handling functions
- `examples/`: Example projects for testing
  - `js_vuln/`: Dummy vulnerable JavaScript project
    - `app.js`: Main application file with intentional vulnerabilities
    - `utils.js`: Utility functions with some vulnerable patterns
    - `package.json`: Dependencies with known vulnerabilities
    - `views/`: Directory containing view templates

## Future Development

See the [ROADMAP.md](ROADMAP.md) file for the planned development roadmap.

## License

[GNU General Public License v3.0](LICENSE)
