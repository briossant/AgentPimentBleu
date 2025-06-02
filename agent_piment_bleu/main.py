import gradio as gr
import os
import tempfile
import shutil
from agent_piment_bleu.utils.git_utils import clone_repository

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

        # For now, just return a simple success message
        # In future phases, we'll add actual scanning logic here
        return f"""
        ## Scan Results

        Repository: {repo_url}

        ### Summary

        The repository was successfully cloned and is ready for scanning.

        In future versions, this report will include:
        - SAST findings
        - SCA findings
        - AI-powered impact assessments
        """

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
