#!/usr/bin/env python3
"""
AgentPimentBleu - Main Entry Point

This script provides a command-line interface to run different components of AgentPimentBleu:
- UI (Gradio interface)
- API (FastAPI server)
- CLI scan (direct scan of a repository)
"""

import argparse
import sys
import uvicorn
import json
import threading
import time

from agentpimentbleu.config.config import get_settings
from agentpimentbleu.core.graphs.sca_impact_graph import run_sca_scan
from agentpimentbleu.utils.logger import get_logger
from agentpimentbleu.app.api_client import initiate_scan_api, poll_scan_status_api, get_scan_report_api

logger = get_logger()


def run_api_in_thread():
    """Run the FastAPI server in a separate thread."""
    uvicorn.run("agentpimentbleu.api.main:app", host="0.0.0.0", port=8000)


def run_ui():
    """Run the Gradio UI with API running in background."""
    # Start the API in a separate thread
    api_thread = threading.Thread(target=run_api_in_thread, daemon=True)
    api_thread.start()

    # Give the API a moment to start up
    logger.info("Starting FastAPI server in background")
    time.sleep(2)

    # Start the UI
    logger.info("Starting Gradio UI")
    from agentpimentbleu.app.app import app
    app.launch(server_name="0.0.0.0")


def run_api():
    """Run the FastAPI server."""
    logger.info("Starting FastAPI server")
    uvicorn.run("agentpimentbleu.api.main:app", host="0.0.0.0", port=8000, reload=True)


def run_scan_cli(repo_source):
    """
    Run a scan via CLI, interacting with the API.

    Args:
        repo_source (str): URL or local path to the repository
    """
    logger.info(f"CLI: Initiating scan for {repo_source}")

    # Start API if not running - for CLI, we assume API is accessible separately
    # Or, the CLI could directly call execute_full_scan_logic for a synchronous experience
    # For now, let's assume it calls the API like the UI would.

    scan_id, error = initiate_scan_api(repo_source)  # No API keys from CLI for now, could add args
    if error or not scan_id:
        print(json.dumps(error or {"error_message": "Failed to initiate scan"}, indent=2))
        return

    print(f"Scan initiated. ID: {scan_id}. Polling for completion...")

    for progress_update in poll_scan_status_api(scan_id):
        status = progress_update.get('overall_status', 'UNKNOWN')
        step = progress_update.get('current_step_description', '')
        print(f"Status: {status} - {step}")
        if progress_update.get("error_context") or status in ["COMPLETED", "FAILED", "ANALYSIS_DEPTH_LIMITED"]:
            break

    print("Fetching final report...")
    report = get_scan_report_api(scan_id)
    print(json.dumps(report, indent=2))


# Legacy function for backward compatibility
def run_scan(repo_source):
    """
    Run a direct scan of a repository (legacy synchronous version).

    Args:
        repo_source (str): URL or local path to the repository
    """
    logger.info(f"Running legacy scan on {repo_source}")

    # Get the application configuration
    app_config = get_settings()

    # Run the scan
    result = run_sca_scan(repo_source, app_config)

    # Print the results
    print(json.dumps(result, indent=2))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="AgentPimentBleu - Smart Security Scanner for Git Repositories")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # UI command
    ui_parser = subparsers.add_parser("ui", help="Run the Gradio UI")

    # API command
    api_parser = subparsers.add_parser("api", help="Run the FastAPI server")

    # Scan commands
    scan_parser = subparsers.add_parser("scan", help="Run a direct scan of a repository")
    scan_parser.add_argument("--repo_source", required=True, help="URL or local path to the repository")

    scan_async_parser = subparsers.add_parser("scan-async", help="Run a scan via API (asynchronous)")
    scan_async_parser.add_argument("--repo_source", required=True, help="URL or local path to the repository")

    # Parse arguments
    args = parser.parse_args()

    # Run the appropriate command
    if args.command == "ui":
        run_ui()
    elif args.command == "api":
        run_api()
    elif args.command == "scan":
        run_scan(args.repo_source)  # Legacy synchronous scan
    elif args.command == "scan-async":
        run_scan_cli(args.repo_source)  # New asynchronous scan
    else:
        # Default to UI when no command is provided
        run_ui()


if __name__ == "__main__":
    main()
