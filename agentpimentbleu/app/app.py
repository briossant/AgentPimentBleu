"""
AgentPimentBleu - Gradio UI

This module provides a web-based UI for the AgentPimentBleu security scanner.
"""

import gradio as gr
import requests
import json
import os
from typing import Tuple

from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

# API URL - default to localhost, but can be overridden with environment variable
API_URL = os.environ.get("APB_API_URL", "http://127.0.0.1:8000")


def scan_repository(repo_source: str) -> Tuple[str, str]:
    """
    Scan a repository for vulnerabilities.

    Args:
        repo_source (str): URL or local path to the repository

    Returns:
        Tuple[str, str]: Formatted results as Markdown and raw JSON
    """
    logger.info(f"Scanning repository: {repo_source}")

    try:
        # Prepare the payload
        payload = {"repo_source": repo_source}

        # Make the API request
        response = requests.post(f"{API_URL}/scan/", json=payload)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            result = response.json()

            # Format the results as Markdown
            markdown_result = format_results_as_markdown(result)

            # Return both the formatted results and the raw JSON
            return markdown_result, json.dumps(result, indent=2)
        else:
            error_message = f"Error: {response.status_code} - {response.text}"
            logger.error(error_message)
            return f"## Error\n\n{error_message}", "{}"

    except Exception as e:
        error_message = f"Error scanning repository: {e}"
        logger.error(error_message)
        return f"## Error\n\n{error_message}", "{}"


def format_results_as_markdown(result: dict) -> str:
    """
    Format scan results as Markdown.

    Args:
        result (dict): Scan results

    Returns:
        str: Formatted results as Markdown
    """
    # Start with a header
    markdown = f"# Scan Results for {result.get('repo_source', 'Unknown Repository')}\n\n"

    # Add scan status
    markdown += f"**Status:** {result.get('status', 'Unknown')}\n\n"

    # Add overall summary if available
    if result.get('overall_summary'):
        markdown += f"**Summary:** {result['overall_summary']}\n\n"

    # Add error message if available
    if result.get('error_message'):
        markdown += f"**Error:** {result['error_message']}\n\n"
        return markdown

    # Add SCA results if available
    sca_results = result.get('sca_results')
    if sca_results:
        markdown += "## Software Composition Analysis (SCA) Results\n\n"

        # Add dependency file information if available
        if sca_results.get('dependency_file_found'):
            markdown += f"**Dependency File:** {sca_results['dependency_file_found']}\n\n"

        # Add issues summary if available
        if sca_results.get('issues_summary'):
            markdown += f"**Issues Summary:** {sca_results['issues_summary']}\n\n"

        # Add vulnerabilities if available
        vulnerabilities = sca_results.get('vulnerabilities', [])
        if vulnerabilities:
            markdown += f"### Vulnerabilities ({len(vulnerabilities)})\n\n"

            for i, vuln in enumerate(vulnerabilities, 1):
                markdown += f"#### {i}. {vuln.get('package_name', 'Unknown Package')} - {vuln.get('cve_id', 'Unknown CVE')}\n\n"

                # Add CVE link if available
                if vuln.get('cve_link'):
                    markdown += f"**CVE Link:** [{vuln['cve_id']}]({vuln['cve_link']})\n\n"

                # Add CVE description if available
                if vuln.get('cve_description'):
                    markdown += f"**Description:** {vuln['cve_description']}\n\n"

                # Add version information
                markdown += f"**Vulnerable Version Range:** {vuln.get('vulnerable_version_range', 'Unknown')}\n"
                markdown += f"**Analyzed Project Version:** {vuln.get('analyzed_project_version', 'Unknown')}\n\n"

                # Add danger rating
                markdown += f"**Danger Rating:** {vuln.get('danger_rating', 'Unknown')}\n\n"

                # Add impact summary
                if vuln.get('impact_in_project_summary'):
                    markdown += f"**Impact:** {vuln['impact_in_project_summary']}\n\n"

                # Add evidence if available
                if vuln.get('evidence') and vuln['evidence'][0] != 'No evidence available':
                    markdown += "**Evidence:**\n\n"
                    for evidence in vuln['evidence']:
                        markdown += f"```\n{evidence}\n```\n\n"

                # Add fix information
                if vuln.get('proposed_fix_summary'):
                    markdown += f"**Proposed Fix:** {vuln['proposed_fix_summary']}\n\n"

                if vuln.get('detailed_fix_guidance'):
                    markdown += f"**Detailed Guidance:** {vuln['detailed_fix_guidance']}\n\n"

                # Add separator between vulnerabilities
                markdown += "---\n\n"
        else:
            markdown += "No vulnerabilities found.\n\n"

    return markdown


# Create the Gradio interface
with gr.Blocks(title="AgentPimentBleu - Smart Security Scanner") as app:
    gr.Markdown("# AgentPimentBleu - Smart Security Scanner for Git Repositories")
    gr.Markdown("""
    Enter a Git repository URL or a local path to an example project to scan for vulnerabilities.

    Example inputs:
    - `https://github.com/username/repository`
    - `examples/python_example_vulnerable_project_1`
    - `examples/javascript_example_vulnerable_project_1`
    """)

    with gr.Row():
        repo_input = gr.Textbox(
            label="Repository URL or Local Path",
            placeholder="Enter repository URL or local path",
            lines=1
        )
        scan_button = gr.Button("Scan Repository", variant="primary")

    with gr.Row():
        with gr.Column():
            results_md = gr.Markdown(label="Scan Results")
        with gr.Column():
            results_json = gr.JSON(label="Raw JSON Output")

    scan_button.click(
        fn=scan_repository,
        inputs=repo_input,
        outputs=[results_md, results_json]
    )


if __name__ == "__main__":
    app.launch(server_name="0.0.0.0")
