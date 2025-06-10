"""
AgentPimentBleu - Scan Tab UI Components

This module contains functions for creating the Scan tab UI components.
"""

import gradio as gr
from typing import Tuple, Dict, List, Optional
from PIL import Image


def create_results_section():
    """
    Create the results section UI components.

    Returns:
        Tuple: Results container, vulnerability chart, summary markdown, details markdown, results JSON, and filter checkboxes
    """
    with gr.Row(visible=False) as results_container:
        with gr.Column():
            # Chart for vulnerability distribution
            vuln_chart = gr.Image(label="Vulnerability Distribution", show_label=True)

            # Results tabs
            with gr.Tabs() as result_tabs:
                with gr.Tab("Summary"):
                    summary_md = gr.HTML()

                with gr.Tab("Vulnerability Details"):
                    # Add filtering options
                    with gr.Row():
                        with gr.Column(scale=1):
                            gr.Markdown("### Filter by Severity")
                        with gr.Column(scale=3):
                            with gr.Row():
                                filter_critical = gr.Checkbox(label="Critical", value=True)
                                filter_high = gr.Checkbox(label="High", value=True)
                                filter_medium = gr.Checkbox(label="Medium", value=True)
                                filter_low = gr.Checkbox(label="Low", value=True)
                                filter_info = gr.Checkbox(label="Informational", value=True)

                    details_md = gr.HTML()

                with gr.Tab("Raw JSON"):
                    results_json = gr.JSON()

    return results_container, vuln_chart, summary_md, details_md, results_json, filter_critical, filter_high, filter_medium, filter_low, filter_info

def create_scan_tab():
    """
    Create the Scan tab UI components with a two-column layout for inputs/settings.

    Returns:
        Tuple: The Scan tab and all its components
    """
    with gr.Tab("Scan") as scan_tab:
        with gr.Row():  # Main row to hold the two columns for inputs/settings
            # --- Left Column: Settings ---
            with gr.Column(scale=1): # Adjust scale as needed, e.g., scale=1 for smaller left, scale=2 for larger right
                with gr.Accordion("Settings", open=True):
                    with gr.Tabs():
                        with gr.TabItem("LLM API Keys"):
                            with gr.Column(): # Use column for vertical stacking inside the tab
                                gr.Markdown("#### Gemini API Key")
                                gemini_api_key_input = gr.Textbox(
                                    label="Gemini API Key (Override)",
                                    placeholder="Enter your Gemini API key",
                                    lines=1,
                                    type="password"
                                )
                                gr.Markdown("<small>[Get your Gemini API Key](https://aistudio.google.com/app/apikey)</small>", elem_classes="api-key-link")

                                gr.Markdown("#### Mistral API Key")
                                mistral_api_key_input = gr.Textbox(
                                    label="Mistral API Key (Override)",
                                    placeholder="Enter your Mistral API key",
                                    lines=1,
                                    type="password"
                                )
                                gr.Markdown("<small>[Get your Mistral API Key](https://console.mistral.ai/api-keys/)</small>", elem_classes="api-key-link")

                            gr.Markdown("""
                            <br/>
                            <p><small>API keys entered here will override those in <code>settings.yaml</code> or environment variables for this scan.</small></p>
                            """)

                        with gr.TabItem("Analysis Parameters"):
                            recursion_limit_slider = gr.Slider(
                                minimum=50,
                                maximum=500,
                                step=10,
                                value=100,
                                label="Max Graph Recursion Limit",
                                info="Adjusts the maximum number of steps the analysis graph can take. Higher values might allow deeper analysis for complex projects but can take longer."
                            )
                            # You can add other analysis parameters here if needed

            # --- Right Column: Scan Actions ---
            with gr.Column(scale=2): # Adjust scale as needed
                gr.Markdown(
                    """
                    <div class="card">
                        <h2>Scan a Repository</h2>
                        <p>
                            The supported languages are <strong>Python</strong> and <strong>JavaScript</strong>, see the about tab for more information.
                        </p>
                    </div>
                    """
                )
                with gr.Row(): # Row for Repository Input and Examples
                    with gr.Column(scale=3): # Give more space to the repo input
                        repo_input = gr.Textbox(
                            label="Enter a public Git repository URL or use one of the provided examples",
                            placeholder="https://github.com/user/repo",
                            lines=1
                        )
                    with gr.Column(scale=2): # Space for examples
                        gr.Examples(
                            examples=[
                                ["examples/javascript_vulnerable_project"],
                                ["examples/python_vulnerable_project"],
                            ],
                            inputs=repo_input,
                            label="Example Projects",
                            elem_id="scan-example-projects"
                        )

                with gr.Row(): # Row for Scan Button and Status Box
                    with gr.Column(scale=1): 
                        scan_button = gr.Button("🔍 Scan Repository", variant="primary")
                    with gr.Column(scale=3): 
                        status_box = gr.Textbox(
                            label="Status",
                            placeholder="Ready to scan...",
                            interactive=False,
                            lines=1 
                        )

        # --- Bottom Section: Results (Spans full width under the columns) ---
        results_container, vuln_chart, summary_md, details_md, results_json, filter_critical, filter_high, filter_medium, filter_low, filter_info = create_results_section()

    return (
        scan_tab, 
        repo_input, 
        gemini_api_key_input, 
        mistral_api_key_input, 
        recursion_limit_slider, 
        scan_button, 
        status_box, 
        results_container, 
        vuln_chart, 
        summary_md, 
        details_md, 
        results_json,
        filter_critical,
        filter_high,
        filter_medium,
        filter_low,
        filter_info
    )
