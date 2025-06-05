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


def scan_repository(repo_source: str, progress=gr.Progress()) -> Tuple[str, str, str, str]:
    """
    Scan a repository for vulnerabilities.

    Args:
        repo_source (str): URL or local path to the repository
        progress (gr.Progress, optional): Gradio progress tracker

    Returns:
        Tuple[str, str, str, str]: Summary, detailed results as Markdown, raw JSON, and status message
    """
    logger.info(f"Scanning repository: {repo_source}")

    progress(0, desc="Initializing scan...")

    try:
        # Prepare the payload
        payload = {"repo_source": repo_source}

        progress(0.1, desc="Preparing to scan repository...")

        # Make the API request
        progress(0.2, desc="Sending scan request to API...")
        response = requests.post(f"{API_URL}/scan/", json=payload)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            progress(0.4, desc="Receiving scan results...")
            result = response.json()

            # Format the results
            progress(0.6, desc="Processing vulnerability data...")
            summary_md = format_summary_as_markdown(result)

            progress(0.8, desc="Generating detailed vulnerability report...")
            details_md = format_details_as_markdown(result)

            # Return the summary, detailed results, the raw JSON, and the status message
            progress(1.0, desc="Scan completed successfully!")
            return summary_md, details_md, json.dumps(result, indent=2), "Scan completed successfully!"
        else:
            progress(1.0, desc="Scan failed!")
            error_message = f"Error: {response.status_code} - {response.text}"
            logger.error(error_message)
            error_md = f"## Error\n\n{error_message}"
            return error_md, error_md, "{}", f"Scan failed: {error_message}"

    except Exception as e:
        progress(1.0, desc="Scan failed due to an error!")
        error_message = f"Error scanning repository: {e}"
        logger.error(error_message)
        error_md = f"## Error\n\n{error_message}"
        return error_md, error_md, "{}", f"Scan failed: {error_message}"


def format_summary_as_markdown(result: dict) -> str:
    """
    Format scan summary as Markdown.

    Args:
        result (dict): Scan results

    Returns:
        str: Formatted summary as Markdown
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

        # Add high-level vulnerability summary
        vulnerabilities = sca_results.get('vulnerabilities', [])
        if vulnerabilities:
            # Count vulnerabilities by danger rating
            ratings = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Unknown": 0}
            for vuln in vulnerabilities:
                rating = vuln.get('danger_rating', 'Unknown')
                ratings[rating] = ratings.get(rating, 0) + 1

            # Create a summary with colored counts
            markdown += f"### Vulnerability Summary\n\n"
            markdown += f"Found {len(vulnerabilities)} vulnerabilities:\n\n"

            for rating, count in ratings.items():
                if count > 0:
                    color = get_danger_rating_color(rating)
                    markdown += f"- <span style='color:{color};'>{rating}</span>: {count}\n"

            markdown += "\n*See the Vulnerability Details tab for more information.*\n\n"
        else:
            markdown += "No vulnerabilities found.\n\n"

    return markdown


def format_details_as_markdown(result: dict) -> str:
    """
    Format detailed vulnerability information as Markdown.

    Args:
        result (dict): Scan results

    Returns:
        str: Formatted details as Markdown
    """
    # Start with a header
    markdown = f"# Vulnerability Details for {result.get('repo_source', 'Unknown Repository')}\n\n"

    # Add error message if available
    if result.get('error_message'):
        markdown += f"**Error:** {result['error_message']}\n\n"
        return markdown

    # Add SCA results if available
    sca_results = result.get('sca_results')
    if sca_results:
        # Add vulnerabilities if available
        vulnerabilities = sca_results.get('vulnerabilities', [])
        if vulnerabilities:
            markdown += f"## Vulnerabilities ({len(vulnerabilities)})\n\n"

            for i, vuln in enumerate(vulnerabilities, 1):
                # Get danger rating and assign color
                danger_rating = vuln.get('danger_rating', 'Unknown')
                color = get_danger_rating_color(danger_rating)

                # Create accordion header with colored danger rating
                package_name = vuln.get('package_name', 'Unknown Package')
                cve_id = vuln.get('cve_id', 'Unknown CVE')

                # Start accordion
                markdown += f'<details>\n<summary><h4>{i}. {package_name} - <span style="color:{color};">{danger_rating}</span></h4></summary>\n\n'

                # Key information section
                markdown += '<div style="margin-left: 20px;">\n\n'

                # Add CVE link if available
                if vuln.get('cve_link'):
                    markdown += f"**CVE ID:** [{vuln['cve_id']}]({vuln['cve_link']})\n\n"
                else:
                    markdown += f"**CVE ID:** {cve_id}\n\n"

                # Add version information
                markdown += f"**Vulnerable Version Range:** {vuln.get('vulnerable_version_range', 'Unknown')}\n"
                markdown += f"**Analyzed Project Version:** {vuln.get('analyzed_project_version', 'Unknown')}\n\n"

                # Add CVE description if available
                if vuln.get('cve_description'):
                    markdown += f"### Description\n{vuln['cve_description']}\n\n"
                else:
                    markdown += "### Description\nNo description available.\n\n"

                # Add impact summary
                if vuln.get('impact_in_project_summary'):
                    markdown += f"### Impact Summary\n{vuln['impact_in_project_summary']}\n\n"

                # Add fix information with better formatting
                if vuln.get('proposed_fix_summary'):
                    markdown += f"### Proposed Fix\n"
                    # Format the proposed fix as bullet points if possible
                    fix_text = vuln['proposed_fix_summary']
                    # Check if the text contains sentences that can be converted to bullet points
                    if '. ' in fix_text:
                        sentences = fix_text.split('. ')
                        markdown += "- **Primary:** " + sentences[0] + ".\n"
                        for sentence in sentences[1:]:
                            if sentence:  # Skip empty strings
                                markdown += f"- {sentence}.\n"
                    else:
                        markdown += fix_text + "\n\n"

                # Add detailed guidance in a collapsible section
                if vuln.get('detailed_fix_guidance'):
                    markdown += f"\n<details>\n<summary><strong>Show Detailed Guidance</strong></summary>\n\n"
                    markdown += f"{vuln['detailed_fix_guidance']}\n\n"
                    markdown += "</details>\n\n"

                # Add evidence if available
                if vuln.get('evidence') and vuln['evidence'][0] != 'No evidence available':
                    markdown += "### Evidence\n\n"
                    for evidence in vuln['evidence']:
                        markdown += f"```\n{evidence}\n```\n\n"

                # Close the div and accordion
                markdown += "</div>\n\n"
                markdown += "</details>\n\n"
        else:
            markdown += "No vulnerabilities found.\n\n"

    return markdown


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
                # Get danger rating and assign color
                danger_rating = vuln.get('danger_rating', 'Unknown')
                color = get_danger_rating_color(danger_rating)

                # Create accordion header with colored danger rating
                package_name = vuln.get('package_name', 'Unknown Package')
                cve_id = vuln.get('cve_id', 'Unknown CVE')

                # Start accordion
                markdown += f'<details>\n<summary><h4>{i}. {package_name} - <span style="color:{color};">{danger_rating}</span></h4></summary>\n\n'

                # Key information section
                markdown += '<div style="margin-left: 20px;">\n\n'

                # Add CVE link if available
                if vuln.get('cve_link'):
                    markdown += f"**CVE ID:** [{vuln['cve_id']}]({vuln['cve_link']})\n\n"
                else:
                    markdown += f"**CVE ID:** {cve_id}\n\n"

                # Add version information
                markdown += f"**Vulnerable Version Range:** {vuln.get('vulnerable_version_range', 'Unknown')}\n"
                markdown += f"**Analyzed Project Version:** {vuln.get('analyzed_project_version', 'Unknown')}\n\n"

                # Add CVE description if available
                if vuln.get('cve_description'):
                    markdown += f"### Description\n{vuln['cve_description']}\n\n"
                else:
                    markdown += "### Description\nNo description available.\n\n"

                # Add impact summary
                if vuln.get('impact_in_project_summary'):
                    markdown += f"### Impact Summary\n{vuln['impact_in_project_summary']}\n\n"

                # Add fix information with better formatting
                if vuln.get('proposed_fix_summary'):
                    markdown += f"### Proposed Fix\n"
                    # Format the proposed fix as bullet points if possible
                    fix_text = vuln['proposed_fix_summary']
                    # Check if the text contains sentences that can be converted to bullet points
                    if '. ' in fix_text:
                        sentences = fix_text.split('. ')
                        markdown += "- **Primary:** " + sentences[0] + ".\n"
                        for sentence in sentences[1:]:
                            if sentence:  # Skip empty strings
                                markdown += f"- {sentence}.\n"
                    else:
                        markdown += fix_text + "\n\n"

                # Add detailed guidance in a collapsible section
                if vuln.get('detailed_fix_guidance'):
                    markdown += f"\n<details>\n<summary><strong>Show Detailed Guidance</strong></summary>\n\n"
                    markdown += f"{vuln['detailed_fix_guidance']}\n\n"
                    markdown += "</details>\n\n"

                # Add evidence if available
                if vuln.get('evidence') and vuln['evidence'][0] != 'No evidence available':
                    markdown += "### Evidence\n\n"
                    for evidence in vuln['evidence']:
                        markdown += f"```\n{evidence}\n```\n\n"

                # Close the div and accordion
                markdown += "</div>\n\n"
                markdown += "</details>\n\n"
        else:
            markdown += "No vulnerabilities found.\n\n"

    return markdown


def get_danger_rating_color(rating: str) -> str:
    """
    Get the color for a danger rating.

    Args:
        rating (str): The danger rating

    Returns:
        str: The color for the rating
    """
    colors = {
        "Critical": "#FF0000",  # Red
        "High": "#FF6600",      # Orange
        "Medium": "#FFCC00",    # Yellow
        "Low": "#3366FF",       # Blue
        "Informational": "#00CC00"  # Green
    }
    return colors.get(rating, "#808080")  # Default to gray if rating not found


# Create the Gradio interface
with gr.Blocks(title="AgentPimentBleu - Smart Security Scanner", css="details summary h4 { display: inline; }") as app:
    gr.Markdown("# AgentPimentBleu - Smart Security Scanner for Git Repositories")
    gr.Markdown("""
    Enter a Git repository URL or a local path to an example project to scan for vulnerabilities.

    Example inputs:
    - `https://github.com/username/repository`
    - `examples/python_example_vulnerable_project_1`
    - `examples/javascript_example_vulnerable_project_1`
    """)

    gr.Markdown("""
    ### Supported Languages and Package Managers
    - **Python**: requirements.txt (pip), Pipfile (pipenv), pyproject.toml (poetry, pdm)
    - **JavaScript**: package.json (npm, yarn)
    """)

    with gr.Row():
        repo_input = gr.Textbox(
            label="Repository URL or Local Path",
            placeholder="Enter repository URL or local path",
            lines=1
        )
        scan_button = gr.Button("Scan Repository", variant="primary")

    # Status box to show current progress
    status_box = gr.Textbox(
        label="Status",
        placeholder="Ready to scan...",
        interactive=False
    )

    # Create tabs for different views of the results
    with gr.Tabs() as tabs:
        with gr.Tab("Summary & SCA"):
            summary_md = gr.Markdown(label="Summary")

        with gr.Tab("Vulnerability Details"):
            details_md = gr.Markdown(label="Details")

        with gr.Tab("Raw JSON Output"):
            results_json = gr.JSON(label="Raw JSON")

    scan_button.click(
        fn=scan_repository,
        inputs=repo_input,
        outputs=[summary_md, details_md, results_json, status_box],
        show_progress=True
    )


if __name__ == "__main__":
    app.launch(server_name="0.0.0.0")
