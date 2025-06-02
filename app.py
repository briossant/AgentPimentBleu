#!/usr/bin/env python3
"""
AgentPimentBleu - Smart Security Scanner for Git Repositories

This is the main entry point for the AgentPimentBleu application.
It launches the Gradio UI for the security scanner.
"""

from agent_piment_bleu.main import create_ui

def main():
    app = create_ui()
    app.launch(share=False)

if __name__ == "__main__":
    main()
