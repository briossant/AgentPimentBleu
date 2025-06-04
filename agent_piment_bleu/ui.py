import gradio as gr
from agent_piment_bleu.orchestrator import analyze_repository, TEST_JS_VULN_URL
from agent_piment_bleu.llm import get_available_providers, get_default_provider
from agent_piment_bleu.llm.factory import create_llm_provider
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

def use_dummy_project():
    """
    Set the repository URL to the dummy vulnerable JS project.

    Returns:
        str: The dummy project URL
    """
    logger = get_logger()
    logger.info(f"Using dummy vulnerable JS project for testing: {TEST_JS_VULN_URL}")
    return TEST_JS_VULN_URL

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

    # Function to analyze the dummy project with LLM
    def analyze_cve_with_llm(llm_provider_name):
        try:
            logger.info(f"Analyzing dummy project with {llm_provider_name}...")

            # Use the example project
            result = analyze_repository(TEST_JS_VULN_URL, True, llm_provider_name)

            logger.info("Dummy project analysis completed")
            return result, logger.get_logs_text()
        except Exception as e:
            error_message = f"Error analyzing dummy project: {str(e)}"
            logger.error(error_message)
            return error_message, logger.get_logs_text()

    with gr.Blocks(title="AgentPimentBleu: Smart Security Scanner") as app:
        gr.Markdown("# AgentPimentBleu: Smart Security Scanner for Git Repositories")

        # Get available providers and their status
        providers = get_available_providers()
        available_providers = [provider for provider, available in providers.items() if available]

        # Default to the configured default provider if available
        default_provider = get_default_provider()
        if default_provider not in available_providers:
            default_provider = available_providers[0] if available_providers else None

        # If no providers are available, set provider info
        if not available_providers:
            provider_info = "No LLM providers available. Please install Ollama or Modal."
        elif "modal" not in available_providers and "ollama" in available_providers:
            provider_info = "Only Ollama is available. Install Modal package with 'pip install modal' to use Modal."
        else:
            provider_info = "Select the LLM provider to use for analysis"

        # Create tabs
        with gr.Tabs():
            # Repository Scanner Tab
            with gr.TabItem("Repository Scanner"):
                gr.Markdown("Enter a public Git repository URL to scan for security vulnerabilities.")

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

                        llm_provider = gr.Dropdown(
                            label="LLM Provider",
                            choices=available_providers,
                            value=default_provider,
                            interactive=bool(available_providers) and True,
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

            # LLM Testing Tab
            with gr.TabItem("LLM Testing"):
                gr.Markdown("# Test LLM Functionality")
                gr.Markdown("Test the LLM's ability to analyze vulnerabilities using the dummy vulnerable project.")

                with gr.Row():
                    with gr.Column(scale=2):
                        gr.Markdown("### Dummy Project Analysis")
                        gr.Markdown("The dummy project contains intentional vulnerabilities including:")
                        gr.Markdown("- Vulnerable dependencies (lodash, axios, etc.)")
                        gr.Markdown("- Code with security issues (XSS, SSRF, command injection)")
                        gr.Markdown("- Realistic project structure to test exploration capabilities")

                        llm_test_provider = gr.Dropdown(
                            label="LLM Provider",
                            choices=available_providers,
                            value=default_provider,
                            interactive=bool(available_providers),
                            info=provider_info
                        )

                        analyze_button = gr.Button("Analyze Dummy Project", variant="primary")

                        gr.Markdown("---")
                        gr.Markdown("### Quick Setup for Repository Scanner")
                        gr.Markdown("This button automatically sets the dummy project URL in the Repository Scanner tab, so you can quickly test the full scanning functionality with the vulnerable example project.")

                        use_dummy_button = gr.Button("Use Dummy Project in Scanner Tab", variant="secondary")

                    with gr.Column(scale=2):
                        llm_result = gr.Textbox(
                            label="LLM Analysis Result",
                            lines=15,
                            max_lines=15,
                            interactive=False
                        )

                        llm_test_logs = gr.Textbox(
                            label="Logs",
                            value="",
                            lines=5,
                            max_lines=5,
                            interactive=False
                        )

                # Set up the analyze button click event
                analyze_button.click(
                    fn=analyze_cve_with_llm,
                    inputs=[llm_test_provider],
                    outputs=[llm_result, llm_test_logs]
                )

                # Set up the use dummy project button click event
                use_dummy_button.click(
                    fn=use_dummy_project,
                    inputs=None,
                    outputs=repo_url
                ).then(
                    fn=lambda: (logger.info("Switched to dummy vulnerable JS project"), logger.get_logs_text())[1],
                    inputs=None,
                    outputs=llm_test_logs
                )

        # Set the UI callback for the logger
        logger.set_ui_callback(ui_log_callback)

        # Log initial message
        logger.info("AgentPimentBleu initialized and ready")

    return app
