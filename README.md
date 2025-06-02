# AgentPimentBleu - Smart Security Scanner for Git Repositories

**Hackathon:** Gradio Agents & MCP Hackathon 2025  
**Track:** 3 - Agentic Demo Showcase  
**Tag:** agent-demo-track

## Overview

AgentPimentBleu is an AI-powered agent designed to intelligently scan Git repositories for security vulnerabilities. Unlike traditional scanners that often overwhelm users with numerous low-impact findings, AgentPimentBleu focuses on:

1. Detecting coding mistakes and configuration errors with AI-enhanced context.
2. Identifying vulnerable dependencies and, crucially, **assessing their actual impact** within the specific project's context, filtering out noise from irrelevant CVEs.

The goal is to provide developers with actionable, prioritized security insights, enabling them to focus on what truly matters.

## Current Status

This is the initial implementation of AgentPimentBleu, focusing on Phase 1 of the project roadmap:

- [x] Basic Gradio UI with repository URL input
- [x] Core functionality to clone and analyze Git repositories
- [ ] SAST Integration (coming soon)
- [ ] SCA Integration (coming soon)
- [ ] AI-Powered Dependency Impact Assessment (coming soon)

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

## Usage

1. Run the application:
   ```
   python app.py
   ```

2. Open your web browser and navigate to the URL displayed in the terminal (typically http://127.0.0.1:7860).

3. Enter a public Git repository URL in the input field and click "Scan Repository".

4. The application will clone the repository and display the scan results.

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
  - `project_detector.py`: Detects programming languages used in the repository
  - `reporting.py`: Generates formatted reports from scan results
  - `scanners/`: Directory containing language-specific scanners
    - `js/`: JavaScript scanners
      - `sast.py`: JavaScript SAST scanner using ESLint
      - `sca.py`: JavaScript SCA scanner using npm audit
    - `python/`: Python scanners
      - `sast.py`: Python SAST scanner using Bandit
      - `sca.py`: Python SCA scanner using pip-audit
  - `utils/`: Utility functions
    - `git_utils.py`: Git repository handling functions

## Future Development

See the [ROADMAP.md](ROADMAP.md) file for the planned development roadmap.

## License

[GNU General Public License v3.0](LICENSE)
