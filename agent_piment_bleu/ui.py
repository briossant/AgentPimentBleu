import gradio as gr
from agent_piment_bleu.orchestrator import analyze_repository

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
            fn=analyze_repository,
            inputs=repo_url,
            outputs=report
        ).then(
            fn=lambda: "Idle",
            inputs=None,
            outputs=status
        )

    return app
