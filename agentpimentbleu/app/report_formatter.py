"""
AgentPimentBleu - Report Formatter

This module contains functions for formatting scan results as Markdown.
"""

from typing import Dict, List
from agentpimentbleu.app.ui_settings import COLORS, get_danger_rating_color

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