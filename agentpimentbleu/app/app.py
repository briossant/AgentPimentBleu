"""
AgentPimentBleu - Gradio UI

This module provides a web-based UI for the AgentPimentBleu security scanner.
"""

import gradio as gr
from typing import Tuple, Dict, List, Optional
from PIL import Image

from agentpimentbleu.utils.logger import get_logger
from agentpimentbleu.app.ui_settings import CUSTOM_CSS
from agentpimentbleu.app.ui_components.about_tab import create_about_tab
from agentpimentbleu.app.ui_components.scan_tab import create_scan_tab
from agentpimentbleu.app.report_formatter import (
    format_summary_as_markdown,
    format_details_as_markdown
)
from agentpimentbleu.app.api_client import scan_repository_api
from agentpimentbleu.utils.plotting import create_vulnerability_chart

logger = get_logger()



def scan_repository(repo_source: str, gemini_api_key: Optional[str] = None, mistral_api_key: Optional[str] = None, recursion_limit: Optional[int] = None) -> Tuple[str, str, Dict, str, Optional[Image.Image]]:
    """
    Scan a repository for vulnerabilities.

    Args:
        repo_source (str): URL or local path to the repository
        gemini_api_key (str, optional): Gemini API key to override the one in config
        mistral_api_key (str, optional): Mistral API key to override the one in config
        recursion_limit (int, optional): Max recursion limit for the graph.

    Returns:
        Tuple[str, str, Dict, str, Optional[Image.Image]]: 
            Summary, detailed results as Markdown, raw JSON, status message, and vulnerability chart
    """
    logger.info(f"Scanning repository: {repo_source} with recursion limit: {recursion_limit}")
    if gemini_api_key:
        logger.info("Gemini API key provided from UI.")
    if mistral_api_key:
        logger.info("Mistral API key provided from UI.")

    status_update = "Initializing scan..."

    try:
        status_update = "Sending scan request to API... This may take a moment."

        # Make the API request using the API client
        result = scan_repository_api(repo_source, gemini_api_key, mistral_api_key, recursion_limit)

        # Check if the request was successful
        if result.get('status') != 'failed':
            # Format the results
            status_update = "Parsing scan data..."
            summary_md = format_summary_as_markdown(result)

            status_update = "Generating vulnerability charts..."
            # Create vulnerability chart if vulnerabilities exist
            chart_image = None
            sca_results = result.get('sca_results', {})
            vulnerabilities = sca_results.get('vulnerabilities', [])
            if vulnerabilities:
                chart_image = create_vulnerability_chart(vulnerabilities)

            status_update = "Formatting detailed vulnerability report..."
            details_md = format_details_as_markdown(result)

            # Return the summary, detailed results, the raw JSON, status message, and chart
            status_update = "Scan completed successfully!"
            return summary_md, details_md, result, status_update, chart_image
        else:
            status_update = "Scan failed!"
            error_message = result.get('error_message', 'Unknown error')
            logger.error(error_message)
            error_md = f"## Error\n\n{error_message}"
            return error_md, error_md, result, f"Scan failed: {error_message}", None

    except Exception as e:
        status_update = "Scan failed due to an error!"
        error_message = f"Error scanning repository: {e}"
        logger.error(error_message)
        error_md = f"## Error\n\n{error_message}"
        return error_md, error_md, {}, f"Scan failed: {error_message}", None










# Create the Gradio interface with custom styling
with gr.Blocks(title="AgentPimentBleu - Smart Security Scanner", css=CUSTOM_CSS) as app:
    # Header with logo and title
    with gr.Row(equal_height=True):
        with gr.Column(scale=1):
            gr.HTML("""
            <div style="display: flex; align-items: center; margin-bottom: 1rem;">
                <div style="font-size: 2rem; margin-right: 0.5rem;">🌶️</div>
                <h1 style="margin: 0;">AgentPimentBleu</h1>
            </div>
            <p style="margin-top: 0;">Smart Security Scanner for Git Repositories</p>
            """)

    # Main content area with tabs
    with gr.Tabs() as tabs:
        # About tab
        about_tab = create_about_tab()

        # Scan tab
        (
            scan_tab, 
            repo_input, 
            gemini_api_key_input, 
            mistral_api_key_input, 
            recursion_limit_slider, 
            scan_button, 
            status_box, 
            results_container, 
            vuln_chart, 
            summary_md, 
            details_md, 
            results_json
        ) = create_scan_tab()

    # Handle scan button click
    scan_button.click(
        fn=scan_repository,
        inputs=[repo_input, gemini_api_key_input, mistral_api_key_input, recursion_limit_slider],
        outputs=[summary_md, details_md, results_json, status_box, vuln_chart]
    )

    # Show results container after scan completes
    scan_button.click(
        fn=lambda: gr.update(visible=True),
        inputs=None,
        outputs=results_container
    )

    # Ensure the Scan tab is selected when scan button is clicked
    scan_button.click(
        fn=lambda: 0,  # No-op function
        inputs=None,
        outputs=None,
        js="() => {document.querySelector('button[id^=\"tabitem\"][aria-controls=\"tabpanel\"][value=\"Scan\"]').click(); return []}"
    )


if __name__ == "__main__":
    app.launch(server_name="0.0.0.0", allowed_paths=["/"])
