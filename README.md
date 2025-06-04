# AgentPimentBleu - Smart Security Scanner for Git Repositories

**Hackathon:** Gradio Agents & MCP Hackathon 2025  
**Track:** 3 - Agentic Demo Showcase  
**Tag:** agent-demo-track

## Overview

AgentPimentBleu is an AI-powered agent designed to intelligently scan Git repositories for security vulnerabilities. Unlike traditional scanners that often overwhelm users with numerous low-impact findings, AgentPimentBleu focuses on:

1. Detecting vulnerable dependencies and assessing their actual impact within the specific project's context
2. Filtering out noise from irrelevant CVEs
3. Providing actionable, prioritized security insights

The goal is to enable developers to focus on what truly matters for their security posture.

## Key Features

- **Intelligent Vulnerability Assessment**: Uses LLMs to understand CVE descriptions and determine real-world impact
- **Context-Aware Analysis**: Leverages RAG (Retrieval Augmented Generation) to search the codebase for actual usage of vulnerable components
- **Multiple Interfaces**: Offers both a user-friendly GUI (Gradio) and an API for CI/CD integration
- **Comprehensive Reporting**: Provides detailed vulnerability reports with impact summaries and fix recommendations
- **Multi-Language Support**: Currently supports Python and JavaScript projects

## Architecture

AgentPimentBleu is built with a modular architecture:

- **Core**: LangGraph-based agent orchestration for vulnerability analysis
- **Services**: Business logic for Git operations, dependency analysis, LLM interactions, and RAG
- **API**: FastAPI endpoints for programmatic interaction
- **UI**: Gradio interface for interactive use
- **Configuration**: External YAML-based configuration with environment variable support

## Installation

### Prerequisites

- Python 3.10+
- Git
- Node.js and npm (for JavaScript project scanning)
- Ollama (optional, for local LLM support)

### Using pip

```bash
# Clone the repository
git clone https://github.com/briossant/AgentPimentBleu.git
cd AgentPimentBleu

# Install dependencies
pip install -r requirements.txt

# Create configuration
mkdir -p ~/.config/agentpimentbleu
cp agentpimentbleu/config/settings.yaml ~/.config/agentpimentbleu/
# Edit ~/.config/agentpimentbleu/settings.yaml to add your API keys
```

### Using Docker

```bash
# Clone the repository
git clone https://github.com/briossant/AgentPimentBleu.git
cd AgentPimentBleu

# Build the Docker image
docker build -t agentpimentbleu .

# Run the container
docker run -p 7860:7860 -v ~/.config/agentpimentbleu:/root/.config/agentpimentbleu agentpimentbleu
```

### Using Nix

```bash
# Clone the repository
git clone https://github.com/briossant/AgentPimentBleu.git
cd AgentPimentBleu

# Enter the Nix shell
nix develop

# Run the application
python main.py ui
```

## Usage

AgentPimentBleu can be used in three ways:

### 1. Gradio UI

```bash
python main.py ui
```

This will start the Gradio web interface at http://localhost:7860, where you can:
- Enter a Git repository URL or local path
- View scan results with detailed vulnerability information
- See impact assessments and fix recommendations

### 2. FastAPI Server

```bash
python main.py api
```

This will start the FastAPI server at http://localhost:8000, with:
- API documentation at http://localhost:8000/docs
- Endpoint at `/scan/` for initiating scans

### 3. Command Line

```bash
python main.py scan --repo_source <URL_OR_PATH>
```

This will scan the specified repository and output the results as JSON.

## Configuration

Configuration is stored in `~/.config/agentpimentbleu/settings.yaml` with the following sections:

- `llm_providers`: Configuration for LLM providers (Gemini, Ollama)
- `dependency_parsers`: File patterns for identifying project types
- `rag_settings`: Configuration for the RAG system

Environment variables prefixed with `APB_` can override configuration values.

## Example Projects

The repository includes example vulnerable projects for testing:

- `examples/python_example_vulnerable_project_1`: Python project with Werkzeug vulnerability
- `examples/javascript_example_vulnerable_project_1`: JavaScript project with lodash vulnerability

To scan an example project:

```bash
python main.py scan --repo_source examples/python_example_vulnerable_project_1
```

## Development

For detailed development information, see:

- [DOCUMENTATION.md](dev_context/DOCUMENTATION.md) for a detailed project explanation and requirements
- [ROADMAP.md](dev_context/ROADMAP.md) for the planned development roadmap

## License

[GNU General Public License v3.0](LICENSE)
