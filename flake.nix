{
  description = "AgentPimentBleu - Smart Security Scanner for Git Repositories";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        python = pkgs.python3;
        pythonPackages = python.pkgs;

        # Define the Python application with its dependencies
        agentPimentBleu = pythonPackages.buildPythonApplication {
          pname = "agent-piment-bleu";
          version = "0.1.0";
          src = ./.;

          propagatedBuildInputs = with pythonPackages; [
            gradio
            gitpython
            requests
            pathspec
            langchain
            langchain-community
            langchain-ollama
            langchain-google-genai
            langchain-mistralai
            pydantic
            fastapi
            uvicorn
            langgraph
            llama-index
            llama-index-embeddings-huggingface
            python-dotenv
            pyyaml
          ];

          # No need for custom postInstall, entry_points in setup.py handles this
          # The console_scripts entry point will create the executable in $out/bin

          meta = with pkgs.lib; {
            description = "Smart Security Scanner for Git Repositories";
            homepage = "https://github.com/briossant/AgentPimentBleu";
            license = licenses.gpl3;
            maintainers = with maintainers; [ ];
          };
        };
      in
      {
        packages = {
          default = agentPimentBleu;
          agent-piment-bleu = agentPimentBleu;
        };

        # Development shell with all dependencies
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # System dependencies
            git

            # Python and packages
            python
            pythonPackages.gradio
            pythonPackages.gitpython
            pythonPackages.requests
            pythonPackages.pathspec
            pythonPackages.langchain
            pythonPackages.langchain-community
            pythonPackages.langchain-ollama
            pythonPackages.langchain-google-genai
            pythonPackages.langchain-mistralai
            pythonPackages.pydantic
            pythonPackages.fastapi
            pythonPackages.uvicorn
            pythonPackages.langgraph
            pythonPackages.llama-index
            pythonPackages.python-dotenv
            pythonPackages.pyyaml
            # ollama is not typically available in nixpkgs, would need to be added as an external dependency
            pythonPackages.pip
            pythonPackages.setuptools
            pythonPackages.wheel
          ];

          shellHook = ''
            echo "AgentPimentBleu development environment"
            echo "Run 'python main.py ui' to start the Gradio UI"
            echo "Run 'python main.py api' to start the FastAPI server"
            echo "Run 'python main.py scan --repo_source <URL_OR_PATH>' to scan a repository"
          '';
        };
      });
}
