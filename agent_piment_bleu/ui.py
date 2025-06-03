import gradio as gr
from agent_piment_bleu.orchestrator import analyze_repository
from agent_piment_bleu.llm import get_available_providers, get_default_provider
from agent_piment_bleu.logger import get_logger
import json

def update_logs(log_content):
    """
    Update the logs in the UI.

    Args:
        log_content (str): The log content to display

    Returns:
        str: The log content
    """
    return log_content

def save_url(url):
    """
    Save the URL to be used later.

    This function is a placeholder for the JavaScript localStorage functionality.
    In a real implementation, this would save the URL to a persistent storage.

    Args:
        url (str): The URL to save

    Returns:
        str: The same URL (for chaining)
    """
    return url

def create_ui():
    """
    Create the Gradio UI for AgentPimentBleu.

    Returns:
        gr.Blocks: Gradio Blocks interface
    """
    # Initialize the logger
    logger = get_logger()

    # Define a callback function to update the logs in the UI
    def ui_log_callback(log_content):
        return gr.update(value=log_content)
    with gr.Blocks(title="AgentPimentBleu: Smart Security Scanner") as app:
        gr.Markdown("# AgentPimentBleu: Smart Security Scanner for Git Repositories")
        gr.Markdown("Enter a public Git repository URL to scan for security vulnerabilities.")

        # Note: JavaScript localStorage functionality has been removed
        # due to compatibility issues with the current Gradio version

        with gr.Row():
            repo_url = gr.Textbox(
                label="Git Repository URL",
                placeholder="https://github.com/username/repository",
                info="Enter the URL of a public Git repository",
                value=""
            )

            # Save URL when it changes
            repo_url.change(fn=save_url, inputs=repo_url, outputs=repo_url)

        with gr.Row():
            with gr.Column(scale=1):
                use_llm = gr.Checkbox(
                    label="Use LLM Enhancement",
                    value=True,
                    info="Enable AI-powered analysis of security findings"
                )

                # Get available providers and their status
                providers = get_available_providers()
                available_providers = [provider for provider, available in providers.items() if available]

                # If no providers are available, disable LLM enhancement
                if not available_providers:
                    use_llm.value = False
                    use_llm.interactive = False
                    provider_info = "No LLM providers available. Please install Ollama or Modal."
                elif "modal" not in available_providers and "ollama" in available_providers:
                    provider_info = "Only Ollama is available. Install Modal package with 'pip install modal' to use Modal."
                else:
                    provider_info = "Select the LLM provider to use for analysis"

                # Default to the configured default provider if available
                default_provider = get_default_provider()
                if default_provider not in available_providers:
                    default_provider = available_providers[0] if available_providers else None

                llm_provider = gr.Dropdown(
                    label="LLM Provider",
                    choices=available_providers,
                    value=default_provider,
                    interactive=bool(available_providers),
                    info=provider_info
                )

            with gr.Column(scale=1):
                scan_button = gr.Button("Scan Repository", variant="primary", scale=2)
                status = gr.Textbox(
                    label="Status",
                    value="Idle",
                    interactive=False
                )

            with gr.Column(scale=1):
                logs = gr.Textbox(
                    label="Logs",
                    value="",
                    lines=15,
                    max_lines=15,
                    interactive=False
                )

        with gr.Row():
            report = gr.Markdown(
                label="Scan Report",
                value="Scan results will appear here."
            )

        # Set the UI callback for the logger
        logger.set_ui_callback(ui_log_callback)

        # Log initial message
        logger.info("AgentPimentBleu initialized and ready")

        # Update status when scan starts and completes
        scan_button.click(
            fn=lambda: "Scanning...",
            inputs=None,
            outputs=status
        ).then(
            fn=lambda: (logger.info("Starting repository scan..."), logger.get_logs_text())[1],
            inputs=None,
            outputs=logs
        ).then(
            fn=analyze_repository,
            inputs=[repo_url, use_llm, llm_provider],
            outputs=report
        ).then(
            fn=lambda: (logger.info("Scan completed"), logger.get_logs_text())[1],
            inputs=None,
            outputs=logs
        ).then(
            fn=lambda: "Idle",
            inputs=None,
            outputs=status
        )

        # Disable/enable LLM provider dropdown based on checkbox
        use_llm.change(
            fn=lambda x: gr.update(interactive=x),
            inputs=use_llm,
            outputs=llm_provider
        )

    return app
