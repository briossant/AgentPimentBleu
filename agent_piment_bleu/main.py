import gradio as gr
import os
import tempfile
import shutil
from agent_piment_bleu.utils.git_utils import clone_repository
from agent_piment_bleu.utils.js_sast_utils import run_js_sast_scan
from agent_piment_bleu.utils.js_sca_utils import run_js_sca_scan

def scan_repository(repo_url):
    """
    Main function to scan a Git repository for security vulnerabilities.

    Args:
        repo_url (str): URL of the Git repository to scan

    Returns:
        str: Markdown formatted report of the scan results
    """
    # Create a temporary directory for the repository
    temp_dir = tempfile.mkdtemp()

    try:
        # Clone the repository
        clone_result = clone_repository(repo_url, temp_dir)

        if not clone_result["success"]:
            return f"## Error\n\n{clone_result['message']}"

        # Run JavaScript SAST scan
        sast_result = run_js_sast_scan(temp_dir)

        # Run JavaScript SCA scan
        sca_result = run_js_sca_scan(temp_dir)

        # Generate the report
        report = f"""
        ## Scan Results

        Repository: {repo_url}

        ### Summary

        The repository was successfully scanned for JavaScript security issues.

        - SAST Scan: {sast_result['message']}
        - SCA Scan: {sca_result['message']}
        """

        # Add SAST findings to the report
        if sast_result['findings']:
            report += "\n\n### SAST Findings (JavaScript)\n\n"
            for finding in sast_result['findings']:
                report += f"- **{finding['rule']}** ({finding['severity']})\n"
                report += f"  - File: `{finding['file']}`, Line: {finding['line']}\n"
                report += f"  - {finding['message']}\n\n"
        elif sast_result['success']:
            report += "\n\n### SAST Findings (JavaScript)\n\n"
            report += "No security issues found in JavaScript code.\n"

        # Add SCA findings to the report
        if sca_result['findings']:
            report += "\n\n### SCA Findings (npm dependencies)\n\n"
            for finding in sca_result['findings']:
                report += f"- **{finding['package']}** (version: {finding['version']}, severity: {finding['severity']})\n"
                report += f"  - {finding['title']}\n"
                if finding['cve'] != "N/A":
                    report += f"  - CVE: {finding['cve']}\n"
                if finding['url']:
                    report += f"  - More info: {finding['url']}\n"
                report += f"  - Recommendation: {finding['recommendation']}\n\n"
        elif sca_result['success']:
            report += "\n\n### SCA Findings (npm dependencies)\n\n"
            report += "No vulnerable dependencies found.\n"

        # Add note about AI-powered impact assessments
        report += "\n\n### Future Enhancements\n\n"
        report += "In future versions, this report will include:\n"
        report += "- AI-powered impact assessments for vulnerabilities\n"
        report += "- More detailed analysis of code and dependencies\n"

        return report

    except Exception as e:
        return f"## Error\n\nAn unexpected error occurred: {str(e)}"

    finally:
        # Clean up the temporary directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def create_ui():
    """
    Create the Gradio UI for AgentPimentBleu.

    Returns:
        gr.Blocks: Gradio Blocks interface
    """
    with gr.Blocks(title="AgentPimentBleu: Smart Security Scanner") as app:
        gr.Markdown("# AgentPimentBleu: Smart Security Scanner for Git Repositories")
        gr.Markdown("Enter a public Git repository URL to scan for security vulnerabilities.")

        with gr.Row():
            repo_url = gr.Textbox(
                label="Git Repository URL",
                placeholder="https://github.com/username/repository",
                info="Enter the URL of a public Git repository"
            )

        with gr.Row():
            scan_button = gr.Button("Scan Repository", variant="primary")

        with gr.Row():
            status = gr.Textbox(
                label="Status",
                value="Idle",
                interactive=False
            )

        with gr.Row():
            report = gr.Markdown(
                label="Scan Report",
                value="Scan results will appear here."
            )

        # Update status when scan starts and completes
        scan_button.click(
            fn=lambda: "Scanning...",
            inputs=None,
            outputs=status
        ).then(
            fn=scan_repository,
            inputs=repo_url,
            outputs=report
        ).then(
            fn=lambda: "Idle",
            inputs=None,
            outputs=status
        )

    return app

if __name__ == "__main__":
    app = create_ui()
    app.launch()
