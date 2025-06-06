"""
AgentPimentBleu - Gradio UI

This module provides a web-based UI for the AgentPimentBleu security scanner.
"""

import gradio as gr
import requests
import json
import os
import matplotlib.pyplot as plt
import numpy as np
import io
from typing import Tuple, Dict, List, Optional
from PIL import Image

from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

# API URL - default to localhost, but can be overridden with environment variable
API_URL = os.environ.get("APB_API_URL", "http://127.0.0.1:8000")

# Define a consistent color scheme for the UI
COLORS = {
    "primary": "#3B82F6",  # Blue
    "secondary": "#6B7280",  # Gray
    "success": "#10B981",  # Green
    "warning": "#F59E0B",  # Amber
    "danger": "#EF4444",  # Red
    "info": "#3B82F6",  # Blue
    "light": "#F3F4F6",  # Light gray
    "dark": "#1F2937",  # Dark gray
    "background": "#F9FAFB",  # Very light gray
    "text": "#111827",  # Very dark gray
    # Severity colors
    "Critical": "#FF0000",  # Red
    "High": "#FF6600",      # Orange
    "Medium": "#FFCC00",    # Yellow
    "Low": "#3366FF",       # Blue
    "Informational": "#00CC00"  # Green
}

# Custom CSS for better styling
CUSTOM_CSS = """
/* General styling */
body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #111827;
    background-color: #F9FAFB;
}

/* Header styling */
h1 {
    font-weight: 700;
    color: #1F2937;
    margin-bottom: 1rem;
}

h2 {
    font-weight: 600;
    color: #374151;
    margin-top: 1.5rem;
    margin-bottom: 1rem;
}

h3 {
    font-weight: 600;
    color: #4B5563;
    margin-top: 1.25rem;
    margin-bottom: 0.75rem;
}

/* Card styling */
.card {
    border-radius: 0.5rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    padding: 1rem;
    margin-bottom: 1rem;
    background-color: white;
}

/* Button styling */
button.primary {
    background-color: #3B82F6;
    color: white;
    font-weight: 500;
}

button.primary:hover {
    background-color: #2563EB;
}

/* Accordion styling */
details {
    border: 1px solid #E5E7EB;
    border-radius: 0.375rem;
    padding: 0.5rem;
    margin-bottom: 0.5rem;
}

details summary {
    font-weight: 500;
    cursor: pointer;
    padding: 0.5rem;
}

details summary h4 {
    display: inline;
    margin: 0;
}

/* Badge styling */
.badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    text-align: center;
    white-space: nowrap;
    margin-right: 0.5rem;
}

.badge-critical {
    background-color: #FEE2E2;
    color: #B91C1C;
}

.badge-high {
    background-color: #FFEDD5;
    color: #C2410C;
}

.badge-medium {
    background-color: #FEF3C7;
    color: #92400E;
}

.badge-low {
    background-color: #DBEAFE;
    color: #1E40AF;
}

.badge-info {
    background-color: #D1FAE5;
    color: #065F46;
}

/* Metrics card styling */
.metrics-card {
    text-align: center;
    padding: 1rem;
    border-radius: 0.5rem;
    background-color: white;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.metrics-card .number {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
}

.metrics-card .label {
    font-size: 0.875rem;
    color: #6B7280;
}

/* Progress bar styling */
.progress-container {
    width: 100%;
    height: 0.5rem;
    background-color: #E5E7EB;
    border-radius: 9999px;
    overflow: hidden;
    margin-bottom: 0.5rem;
}

.progress-bar {
    height: 100%;
    border-radius: 9999px;
    transition: width 0.3s ease;
}

/* Vulnerability details styling */
.vuln-details {
    margin-left: 1.5rem;
    padding: 1rem;
    border-left: 3px solid #E5E7EB;
}

/* Code block styling */
pre {
    background-color: #F3F4F6;
    padding: 1rem;
    border-radius: 0.375rem;
    overflow-x: auto;
}

code {
    font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
}

/* Table styling */
table {
    width: 100%;
    border-collapse: collapse;
}

table th, table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid #E5E7EB;
}

table th {
    background-color: #F9FAFB;
    font-weight: 600;
}

/* Responsive adjustments */
@media (max-width: 640px) {
    .metrics-card {
        padding: 0.75rem;
    }

    .metrics-card .number {
        font-size: 1.25rem;
    }
}

/* Fix for details summary h4 */
details summary h4 {
    display: inline;
}
"""


def create_vulnerability_chart(vulnerabilities: List[Dict]) -> Optional[Image.Image]:
    """
    Create a chart showing the distribution of vulnerabilities by severity.

    Args:
        vulnerabilities (List[Dict]): List of vulnerability dictionaries

    Returns:
        Optional[Image.Image]: PIL Image of the chart or None if no vulnerabilities
    """
    if not vulnerabilities:
        return None

    # Count vulnerabilities by danger rating
    ratings = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for vuln in vulnerabilities:
        rating = vuln.get('danger_rating', 'Unknown')
        if rating in ratings:
            ratings[rating] += 1

    # Filter out ratings with zero count
    labels = [rating for rating, count in ratings.items() if count > 0]
    counts = [count for count in ratings.values() if count > 0]
    colors = [COLORS.get(label, "#808080") for label in labels]

    if not labels:  # No valid vulnerabilities
        return None

    # Create the chart
    plt.figure(figsize=(8, 5))

    # Create a pie chart with a donut hole
    plt.pie(
        counts, 
        labels=labels, 
        colors=colors,
        autopct='%1.1f%%',
        startangle=90,
        wedgeprops={'edgecolor': 'white', 'linewidth': 2}
    )

    # Add a circle at the center to create a donut chart
    centre_circle = plt.Circle((0, 0), 0.70, fc='white')
    fig = plt.gcf()
    fig.gca().add_artist(centre_circle)

    # Add title and equal aspect ratio
    plt.title('Vulnerability Severity Distribution', fontsize=16, pad=20)
    plt.axis('equal')

    # Save the chart to a bytes buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
    plt.close()
    buf.seek(0)

    # Convert to PIL Image
    return Image.open(buf)

def scan_repository(repo_source: str, gemini_api_key: str = None) -> Tuple[str, str, str, str, Optional[Image.Image]]:
    """
    Scan a repository for vulnerabilities.

    Args:
        repo_source (str): URL or local path to the repository
        gemini_api_key (str, optional): Gemini API key to override the one in config

    Returns:
        Tuple[str, str, str, str, Optional[Image.Image]]: 
            Summary, detailed results as Markdown, raw JSON, status message, and vulnerability chart
    """
    logger.info(f"Scanning repository: {repo_source}")

    status_update = "Initializing scan..."

    try:
        # Prepare the payload
        payload = {"repo_source": repo_source}

        # Add Gemini API key to payload if provided
        if gemini_api_key and gemini_api_key.strip():
            payload["gemini_api_key"] = gemini_api_key.strip()
            logger.info("Using Gemini API key from UI")

        status_update = "Sending scan request to API... This may take a moment."

        # Make the API request
        response = requests.post(f"{API_URL}/scan/", json=payload)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            status_update = "API response received, processing results..."
            result = response.json()

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
            return summary_md, details_md, json.dumps(result, indent=2), status_update, chart_image
        else:
            status_update = "Scan failed!"
            error_message = f"Error: {response.status_code} - {response.text}"
            logger.error(error_message)
            error_md = f"## Error\n\n{error_message}"
            return error_md, error_md, "{}", f"Scan failed: {response.status_code}", None

    except Exception as e:
        status_update = "Scan failed due to an error!"
        error_message = f"Error scanning repository: {e}"
        logger.error(error_message)
        error_md = f"## Error\n\n{error_message}"
        return error_md, error_md, "{}", f"Scan failed: {error_message}", None


def format_summary_as_markdown(result: dict) -> str:
    """
    Format scan summary as Markdown with improved visual styling.

    Args:
        result (dict): Scan results

    Returns:
        str: Formatted summary as Markdown with enhanced styling
    """
    # Start with a header in a card-like container
    repo_source = result.get('repo_source', 'Unknown Repository')
    status = result.get('status', 'Unknown')
    status_color = COLORS["success"] if status == "completed" else COLORS["danger"]

    markdown = f"""
<div class="card">
    <h1>Scan Results for {repo_source}</h1>
    <p><strong>Status:</strong> <span style="color: {status_color};">{status}</span></p>
"""

    # Add scan timestamp if available
    if result.get('timestamp'):
        markdown += f"<p><strong>Scan Time:</strong> {result['timestamp']}</p>\n"

    # Add overall summary if available
    if result.get('overall_summary'):
        markdown += f"<p><strong>Summary:</strong> {result['overall_summary']}</p>\n"

    markdown += "</div>\n\n"

    # Add error message if available in a styled error box
    if result.get('error_message'):
        markdown += f"""
<div class="card" style="border-left: 4px solid {COLORS['danger']}; background-color: #FEF2F2;">
    <h3>⚠️ Error</h3>
    <p>{result['error_message']}</p>
</div>
"""
        return markdown

    # Add SCA results if available
    sca_results = result.get('sca_results')
    if sca_results:
        markdown += f"""
<div class="card">
    <h2>Software Composition Analysis (SCA) Results</h2>
"""

        # Add dependency file information if available
        if sca_results.get('dependency_file_found'):
            markdown += f"""
    <p><strong>Dependency File:</strong> {sca_results['dependency_file_found']}</p>
"""

        # Add project type if it can be determined from the dependency file
        dep_file = sca_results.get('dependency_file_found', '')
        project_type = "Unknown"
        if "requirements.txt" in dep_file or "Pipfile" in dep_file or "pyproject.toml" in dep_file:
            project_type = "Python"
        elif "package.json" in dep_file:
            project_type = "JavaScript/Node.js"

        markdown += f"""
    <p><strong>Project Type:</strong> {project_type}</p>
"""

        # Add issues summary if available
        if sca_results.get('issues_summary'):
            markdown += f"""
    <p><strong>Issues Summary:</strong> {sca_results['issues_summary']}</p>
"""

        markdown += "</div>\n\n"

        # Add high-level vulnerability summary with styled metrics cards
        vulnerabilities = sca_results.get('vulnerabilities', [])
        if vulnerabilities:
            # Count vulnerabilities by danger rating
            ratings = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            for vuln in vulnerabilities:
                rating = vuln.get('danger_rating', 'Unknown')
                if rating in ratings:
                    ratings[rating] += 1

            # Create a summary with styled metric cards in a grid
            markdown += f"""
<div class="card">
    <h2>Vulnerability Summary</h2>
    <p>Found {len(vulnerabilities)} vulnerabilities across your dependencies.</p>

    <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: 15px;">
"""

            # Add a total vulnerabilities card
            markdown += f"""
        <div class="metrics-card" style="flex: 1; min-width: 120px;">
            <div class="number">{len(vulnerabilities)}</div>
            <div class="label">Total Vulnerabilities</div>
        </div>
"""

            # Add a card for each severity level
            for rating, count in ratings.items():
                if count > 0:
                    color = COLORS.get(rating, "#808080")
                    markdown += f"""
        <div class="metrics-card" style="flex: 1; min-width: 120px; border-top: 3px solid {color};">
            <div class="number" style="color: {color};">{count}</div>
            <div class="label">{rating}</div>
        </div>
"""

            markdown += """
    </div>

    <p style="margin-top: 15px;"><em>See the Vulnerability Details tab for more information.</em></p>
</div>
"""
        else:
            markdown += """
<div class="card" style="border-left: 4px solid #10B981; background-color: #ECFDF5;">
    <h3>✅ No Vulnerabilities Found</h3>
    <p>Great job! No vulnerabilities were detected in your dependencies.</p>
</div>
"""

    return markdown


def format_details_as_markdown(result: dict) -> str:
    """
    Format detailed vulnerability information as Markdown with enhanced styling.

    Args:
        result (dict): Scan results

    Returns:
        str: Formatted details as Markdown with improved visual elements
    """
    repo_source = result.get('repo_source', 'Unknown Repository')

    # Start with a header in a card
    markdown = f"""
<div class="card">
    <h1>Vulnerability Details for {repo_source}</h1>
    <p>Detailed analysis of each detected vulnerability with impact assessment and fix recommendations.</p>
</div>
"""

    # Add error message if available in a styled error box
    if result.get('error_message'):
        markdown += f"""
<div class="card" style="border-left: 4px solid {COLORS['danger']}; background-color: #FEF2F2;">
    <h3>⚠️ Error</h3>
    <p>{result['error_message']}</p>
</div>
"""
        return markdown

    # Add SCA results if available
    sca_results = result.get('sca_results')
    if sca_results:
        # Add vulnerabilities if available
        vulnerabilities = sca_results.get('vulnerabilities', [])
        if vulnerabilities:
            # Add filtering controls
            markdown += f"""
<div class="card">
    <div style="display: flex; align-items: center; margin-bottom: 15px;">
        <h2 style="margin: 0; margin-right: 15px;">Vulnerabilities ({len(vulnerabilities)})</h2>
        <div style="display: flex; gap: 5px;">
            <span class="badge badge-critical">Critical</span>
            <span class="badge badge-high">High</span>
            <span class="badge badge-medium">Medium</span>
            <span class="badge badge-low">Low</span>
            <span class="badge badge-info">Info</span>
        </div>
    </div>
    <p>Click on a vulnerability to expand and see detailed information.</p>
</div>
"""

            # Create styled accordions for each vulnerability
            for i, vuln in enumerate(vulnerabilities, 1):
                # Get danger rating and assign color
                danger_rating = vuln.get('danger_rating', 'Unknown')
                color = COLORS.get(danger_rating, "#808080")
                badge_class = f"badge-{danger_rating.lower()}" if danger_rating in ["Critical", "High", "Medium", "Low"] else "badge-info"

                # Get package information
                package_name = vuln.get('package_name', 'Unknown Package')

                # Create a brief summary for the accordion header
                impact_summary = vuln.get('impact_in_project_summary', '')
                brief_impact = impact_summary[:80] + '...' if len(impact_summary) > 80 else impact_summary

                # Start styled accordion
                markdown += f"""
<details class="card" style="border-left: 4px solid {color};">
    <summary style="display: flex; justify-content: space-between; align-items: center; padding: 10px;">
        <div>
            <span class="badge {badge_class}">{danger_rating}</span>
            <strong>{package_name}</strong>
        </div>
        <div style="color: #6B7280; font-size: 0.9em;">Click to expand</div>
    </summary>

    <div class="vuln-details">
"""

                # Create a two-column layout for key information
                markdown += f"""
        <div style="display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px;">
            <div style="flex: 1; min-width: 300px;">
"""

                # Left column: Identification information
                # Determine which ID to display (CVE or Advisory)
                if vuln.get('cve_id') and vuln.get('cve_id') != 'unknown':
                    id_type = "CVE ID"
                    id_value = vuln['cve_id']
                    id_link = vuln.get('cve_link', '')
                elif vuln.get('primary_advisory_id'):
                    id_type = "Advisory ID"
                    id_value = vuln['primary_advisory_id']
                    id_link = vuln.get('advisory_link', '')
                else:
                    id_type = "ID"
                    id_value = "Unknown"
                    id_link = ""

                markdown += f"""
                <h3>Vulnerability Identification</h3>
"""

                # Add link if available
                if id_link:
                    markdown += f"""
                <p><strong>{id_type}:</strong> <a href="{id_link}" target="_blank">{id_value}</a></p>
"""
                else:
                    markdown += f"""
                <p><strong>{id_type}:</strong> {id_value}</p>
"""

                # Add version information
                markdown += f"""
                <p><strong>Package:</strong> {package_name}</p>
                <p><strong>Vulnerable Version Range:</strong> {vuln.get('vulnerable_version_range', 'Unknown')}</p>
                <p><strong>Analyzed Project Version:</strong> {vuln.get('analyzed_project_version', 'Unknown')}</p>
            </div>

            <div style="flex: 1; min-width: 300px;">
                <h3>AI-Powered Assessment</h3>
                <p><strong>Danger Rating:</strong> <span style="color: {color};">{danger_rating}</span></p>
"""

                # Add AI reasoning if available
                if vuln.get('danger_rating_reason'):
                    markdown += f"""
                <p><strong>Rating Justification:</strong> {vuln.get('danger_rating_reason')}</p>
"""

                markdown += """
            </div>
        </div>
"""

                # Add CVE description if available
                if vuln.get('cve_description'):
                    markdown += f"""
        <div class="card" style="margin-bottom: 15px;">
            <h3>Description</h3>
            <p>{vuln['cve_description']}</p>
        </div>
"""

                # Add impact summary with AI icon to highlight AI-generated content
                if vuln.get('impact_in_project_summary'):
                    markdown += f"""
        <div class="card" style="margin-bottom: 15px; border-left: 4px solid {COLORS['info']};">
            <h3>🤖 AI Impact Assessment</h3>
            <p>{vuln['impact_in_project_summary']}</p>
        </div>
"""

                # Add fix information with better formatting
                if vuln.get('proposed_fix_summary'):
                    markdown += f"""
        <div class="card" style="margin-bottom: 15px; border-left: 4px solid {COLORS['success']};">
            <h3>🛠️ Proposed Fix</h3>
"""

                    # Format the proposed fix as bullet points if possible
                    fix_text = vuln['proposed_fix_summary']
                    if '. ' in fix_text:
                        sentences = fix_text.split('. ')
                        markdown += f"""
            <p><strong>Primary Recommendation:</strong> {sentences[0]}.</p>

            <p><strong>Additional Mitigations:</strong></p>
            <ul>
"""
                        for sentence in sentences[1:]:
                            if sentence:  # Skip empty strings
                                markdown += f"                <li>{sentence}.</li>\n"
                        markdown += "            </ul>\n"
                    else:
                        markdown += f"            <p>{fix_text}</p>\n"

                    # Add detailed guidance in a collapsible section
                    if vuln.get('detailed_fix_guidance'):
                        markdown += f"""
            <details>
                <summary><strong>Show Detailed Guidance</strong></summary>
                <div style="padding: 10px; background-color: #F9FAFB; border-radius: 5px; margin-top: 10px;">
                    {vuln['detailed_fix_guidance']}
                </div>
            </details>
"""

                    markdown += "        </div>\n"

                # Add evidence if available
                if vuln.get('evidence') and vuln['evidence'][0] != 'No evidence available':
                    markdown += f"""
        <div class="card" style="margin-bottom: 15px;">
            <h3>📝 Evidence</h3>
            <p>Code snippets showing where the vulnerability might be exploited:</p>
"""

                    for i, evidence in enumerate(vuln['evidence'], 1):
                        markdown += f"""
            <div style="margin-bottom: 10px;">
                <p><strong>Evidence #{i}:</strong></p>
                <pre><code>{evidence}</code></pre>
            </div>
"""

                    markdown += "        </div>\n"

                # Close the accordion
                markdown += """
    </div>
</details>
"""
        else:
            markdown += """
<div class="card" style="border-left: 4px solid #10B981; background-color: #ECFDF5;">
    <h3>✅ No Vulnerabilities Found</h3>
    <p>Great job! No vulnerabilities were detected in your dependencies.</p>
</div>
"""

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

                # Determine which ID to display (CVE or Advisory)
                display_id_text = "ID Unknown"
                if vuln.get('cve_id') and vuln.get('cve_id') != 'unknown':
                    display_id_text = f"**CVE ID:** {vuln['cve_id']}"
                elif vuln.get('primary_advisory_id'):
                    display_id_text = f"**Advisory ID:** {vuln['primary_advisory_id']}"

                # Add link if available
                if vuln.get('cve_link'):
                    markdown += f"[{display_id_text}]({vuln['cve_link']})\n\n"
                else:
                    markdown += f"{display_id_text}\n\n"

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
        # About tab with information about the project
        with gr.Tab("About"):
            with gr.Row():
                with gr.Column():
                    gr.Markdown("""
                    <div class="card">
                        <h2>Overview</h2>
                        <p>AgentPimentBleu is an AI-powered agent designed to intelligently scan Git repositories for security vulnerabilities. Unlike traditional scanners that often overwhelm users with numerous low-impact findings, AgentPimentBleu focuses on:</p>
                        <ol>
                            <li>Detecting vulnerable dependencies and assessing their actual impact within the specific project's context</li>
                            <li>Filtering out noise from irrelevant CVEs</li>
                            <li>Providing actionable, prioritized security insights</li>
                        </ol>
                        <p>The goal is to enable developers to focus on what truly matters for their security posture.</p>
                    </div>
                    """)

                    gr.Markdown("""
                    <div class="card">
                        <h2>Key Features</h2>
                        <ul>
                            <li><strong>Intelligent Vulnerability Assessment</strong>: Uses LLMs to understand CVE descriptions and determine real-world impact</li>
                            <li><strong>Context-Aware Analysis</strong>: Leverages RAG (Retrieval Augmented Generation) to search the codebase for actual usage of vulnerable components</li>
                            <li><strong>Multiple Interfaces</strong>: Offers both a user-friendly GUI (Gradio) and an API for CI/CD integration</li>
                            <li><strong>Comprehensive Reporting</strong>: Provides detailed vulnerability reports with impact summaries and fix recommendations</li>
                            <li><strong>Multi-Language Support</strong>: Currently supports Python and JavaScript projects</li>
                        </ul>
                    </div>
                    """)

            with gr.Row():
                with gr.Column():
                    gr.Markdown("""
                    <div class="card">
                        <h2>Architecture</h2>
                        <p>AgentPimentBleu is built with a modular architecture:</p>
                        <ul>
                            <li><strong>Core</strong>: LangGraph-based agent orchestration for vulnerability analysis</li>
                            <li><strong>Services</strong>: Business logic for Git operations, dependency analysis, LLM interactions, and RAG</li>
                            <li><strong>API</strong>: FastAPI endpoints for programmatic interaction</li>
                            <li><strong>UI</strong>: Gradio interface for interactive use</li>
                        </ul>
                    </div>
                    """)

                    # Display the SVG image using gr.Image
                    gr.Image(value="dev_context/agent_graph.svg", label="Agent Workflow Graph", show_label=True, width=1000, height=600)

                    gr.Markdown("""
                    <div class="card">
                        <h2>Supported Languages and Package Managers</h2>
                        <ul>
                            <li><strong>Python</strong>: requirements.txt (pip), Pipfile (pipenv), pyproject.toml (poetry, pdm)</li>
                            <li><strong>JavaScript</strong>: package.json (npm, yarn)</li>
                        </ul>
                    </div>
                    """)

        # Main scan tab with repository input and results
        with gr.Tab("Scan"):
            with gr.Row():
                # Left column for input controls
                with gr.Column(scale=1):
                    gr.Markdown("""
                    <div class="card">
                        <h2>Scan a Repository</h2>
                        <p>Enter a Git repository URL or a local path to scan for vulnerabilities.</p>
                    </div>
                    """)

                    # Repository input with examples
                    repo_input = gr.Textbox(
                        label="Repository URL or Local Path",
                        placeholder="Enter repository URL or local path",
                        lines=1
                    )

                    # Example repository inputs
                    gr.Examples(
                        examples=[
                            ["examples/python_example_vulnerable_project_1"],
                            ["examples/javascript_example_vulnerable_project_1"],
                            ["examples/js_vuln"]
                        ],
                        inputs=repo_input,
                        label="Example Projects"
                    )

                    # Settings in a collapsible section
                    with gr.Accordion("Settings", open=True):
                        gemini_api_key = gr.Textbox(
                            label="Gemini API Key",
                            placeholder="Enter your Gemini API key (optional)",
                            lines=1,
                            type="password"
                        )

                        gr.Markdown("""
                        <p><small>The API key can also be configured in settings.yaml or as an environment variable.</small></p>
                        """)

                    # Scan button
                    scan_button = gr.Button("🔍 Scan Repository", variant="primary", scale=1)

                    # Status box with improved styling
                    status_box = gr.Textbox(
                        label="Status",
                        placeholder="Ready to scan...",
                        interactive=False
                    )

            # Results section
            with gr.Row(visible=False) as results_container:
                with gr.Column():
                    # Chart for vulnerability distribution
                    vuln_chart = gr.Image(label="Vulnerability Distribution", show_label=True)

                    # Results tabs
                    with gr.Tabs() as result_tabs:
                        with gr.Tab("Summary"):
                            summary_md = gr.HTML()

                        with gr.Tab("Vulnerability Details"):
                            details_md = gr.HTML()

                        with gr.Tab("Raw JSON"):
                            results_json = gr.JSON()

    # Handle scan button click
    scan_button.click(
        fn=scan_repository,
        inputs=[repo_input, gemini_api_key],
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
