import gradio as gr
from agent_piment_bleu.orchestrator import analyze_repository
from agent_piment_bleu.llm import get_available_providers, get_default_provider

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
            inputs=[repo_url, use_llm, llm_provider],
            outputs=report
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
