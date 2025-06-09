"""
AgentPimentBleu - Gradio UI

This module provides a web-based UI for the AgentPimentBleu security scanner.
"""

import gradio as gr
from typing import Tuple, Dict, List, Optional, Generator
from PIL import Image

from agentpimentbleu.utils.logger import get_logger
from agentpimentbleu.app.ui_settings import CUSTOM_CSS
from agentpimentbleu.app.ui_components.about_tab import create_about_tab
from agentpimentbleu.app.ui_components.scan_tab import create_scan_tab
from agentpimentbleu.app.report_formatter import (
    format_summary_as_markdown,
    format_details_as_markdown
)
from agentpimentbleu.app.api_client import (
    initiate_scan_api, poll_scan_status_api, get_scan_report_api,
    scan_repository_api  # Legacy function for backward compatibility
)
from agentpimentbleu.utils.plotting import create_vulnerability_chart

logger = get_logger()


def new_scan_repository_flow(
    repo_source: str, 
    gemini_api_key: Optional[str] = None, 
    mistral_api_key: Optional[str] = None, 
    recursion_limit: Optional[int] = None
) -> Generator[Tuple[str, str, Dict, str, Optional[Image.Image]], None, None]:
    """
    Scan a repository for vulnerabilities using the new asynchronous API.
    This is a generator function that yields updates as the scan progresses.

    Args:
        repo_source (str): URL or local path to the repository
        gemini_api_key (str, optional): Gemini API key to override the one in config
        mistral_api_key (str, optional): Mistral API key to override the one in config
        recursion_limit (int, optional): Max recursion limit for the graph.

    Yields:
        Tuple[str, str, Dict, str, Optional[Image.Image]]: 
            Summary, detailed results as Markdown, raw JSON, status message, and vulnerability chart
    """
    logger.info(f"UI: Initiating scan for repository: {repo_source}")
    yield "", "", {}, "Initiating scan...", None  # Initial update

    scan_id, error = initiate_scan_api(repo_source, gemini_api_key, mistral_api_key, recursion_limit)

    if error or not scan_id:
        error_msg = error.get("error_message", "Failed to initiate scan.") if error else "Failed to initiate scan."
        logger.error(f"UI: Error initiating scan: {error_msg}")
        yield f"## Error\n\n{error_msg}", f"## Error\n\n{error_msg}", error or {}, f"Scan initiation failed: {error_msg}", None
        return

    yield "", "", {}, f"Scan initiated (ID: {scan_id}). Polling for progress...", None

    # Poll for status
    final_status_data = None
    for progress_update in poll_scan_status_api(scan_id):
        final_status_data = progress_update  # Keep last status
        status_message = f"Scan ID: {scan_id}\nStatus: {progress_update.get('overall_status', 'Polling...')}\n" \
                         f"Step: {progress_update.get('current_step_description', 'N/A')}"

        if progress_update.get("error_context"):
            err_ctx = progress_update["error_context"]
            error_code = err_ctx.get('error_code')
            error_message = err_ctx.get('error_message')

            # Add error prefix with warning emoji
            status_message += f"\n⚠️ **ERROR** (`{error_code}`): {error_message}"

            # Add user guidance for specific error codes
            if error_code == "INVALID_LLM_API_KEY":
                status_message += "\n\n**Suggestion**: Please verify your LLM API key and ensure it has the correct permissions."
            elif error_code == "REPOSITORY_PREPARATION_FAILED":
                status_message += "\n\n**Suggestion**: Could not access or clone the repository. Please check the URL/path and your network connection/permissions."
            elif error_code == "ANALYSIS_DEPTH_LIMIT_REACHED":
                status_message += "\n\n**Suggestion**: The scan reached its analysis depth limit. Results shown are partial. Consider re-running with a higher recursion limit if analyzing a very complex project."
            elif error_code == "LLM_PROVIDER_COMMUNICATION_ERROR":
                status_message += "\n\n**Suggestion**: There was an issue communicating with the LLM provider. Please check your internet connection and try again later."

            # If the scan has failed, display the error and stop
            if progress_update.get('overall_status') == "FAILED":
                error_md = f"## Scan Failed\n\n**Error Code:** `{error_code}`\n\n**Details:** {error_message}"
                yield error_md, error_md, progress_update, status_message, None
                return  # Stop here, don't fetch the final report

            yield "", "", progress_update, status_message, None  # Update status box

        else:
            yield "", "", progress_update, status_message, None  # Update status box only

        if progress_update.get("overall_status") in ["COMPLETED", "FAILED", "ANALYSIS_DEPTH_LIMITED"]:
            break  # Exit polling loop

    if not final_status_data:  # Should not happen if poll_scan_status_api yields at least once
        yield "## Error", "## Error", {}, "Polling failed to retrieve status.", None
        return

    # Fetch the final report
    yield "", "", final_status_data, "Polling complete. Fetching final report...", None

    report_result = get_scan_report_api(scan_id)

    if not report_result or report_result.get("error_code") or report_result.get("status") == "FAILED_SCAN":
        # Check if we have a structured error context
        if report_result and report_result.get("error_context"):
            error_context = report_result.get("error_context")
            error_code = error_context.get("error_code")
            error_msg = error_context.get("error_message")
            logger.error(f"UI: Error fetching report: {error_code} - {error_msg}")
            error_md = f"## Scan Failed\n\n**Error Code:** `{error_code}`\n\n**Details:** {error_msg}"
        else:
            # Fallback for unstructured errors
            error_msg = report_result.get("error_message", "Failed to retrieve report or scan failed.") if report_result else "Failed to retrieve report."
            logger.error(f"UI: Error fetching report: {error_msg}")
            error_md = f"## Error Retrieving Report\n\n**Details:** {error_msg}"

        yield error_md, error_md, report_result or {}, f"Failed: {error_msg}", None
        return

    # Successfully got the report
    logger.info(f"UI: Scan report received for {scan_id}")
    summary_md = format_summary_as_markdown(report_result)
    details_md = format_details_as_markdown(report_result)

    chart_image = None
    sca_results = report_result.get('sca_results', {})
    if sca_results:  # sca_results can be None
        vulnerabilities = sca_results.get('vulnerabilities', [])
        if vulnerabilities:
            chart_image = create_vulnerability_chart(vulnerabilities)

    yield summary_md, details_md, report_result, f"Scan {report_result.get('status', 'completed')} for ID: {scan_id}. Report available.", chart_image


# Legacy function for backward compatibility
def scan_repository(repo_source: str, gemini_api_key: Optional[str] = None, mistral_api_key: Optional[str] = None, recursion_limit: Optional[int] = None) -> Tuple[str, str, Dict, str, Optional[Image.Image]]:
    """
    Scan a repository for vulnerabilities (legacy synchronous version).

    Args:
        repo_source (str): URL or local path to the repository
        gemini_api_key (str, optional): Gemini API key to override the one in config
        mistral_api_key (str, optional): Mistral API key to override the one in config
        recursion_limit (int, optional): Max recursion limit for the graph.

    Returns:
        Tuple[str, str, Dict, str, Optional[Image.Image]]: 
            Summary, detailed results as Markdown, raw JSON, status message, and vulnerability chart
    """
    logger.info(f"Scanning repository (legacy): {repo_source} with recursion limit: {recursion_limit}")
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

    # Handle scan button click - now uses the generator
    scan_button.click(
        fn=new_scan_repository_flow,  # Use the new generator function
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
