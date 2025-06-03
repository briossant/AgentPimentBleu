"""
AgentPimentBleu - Main module

This module serves as the entry point for the AgentPimentBleu application.
It re-exports the main functions from their respective modules for backward compatibility.
"""

# Re-export the main functions for backward compatibility
from agent_piment_bleu.orchestrator import analyze_repository
from agent_piment_bleu.ui import create_ui
from agent_piment_bleu.logger import get_logger

if __name__ == "__main__":
    # Initialize the logger
    logger = get_logger()
    logger.info("AgentPimentBleu starting up")

    # Create and launch the UI
    app = create_ui()
    app.launch()
