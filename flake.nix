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
            pydantic
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
            python
            pythonPackages.gradio
            pythonPackages.gitpython
            pythonPackages.requests
            pythonPackages.pathspec
            pythonPackages.langchain
            pythonPackages.langchain-community
            pythonPackages.langchain-ollama
            pythonPackages.pydantic
            pythonPackages.pip
            pythonPackages.setuptools
            pythonPackages.wheel
          ];

          shellHook = ''
            echo "AgentPimentBleu development environment"
            echo "Run 'python app.py' to start the application"
            python -m venv venv
            . venv/bin/activate
            pip install modal rich
            pip install "protobuf~=4.21.12"
          '';
        };
      });
}
