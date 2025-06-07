"""
AgentPimentBleu - Scan Tab UI Components

This module contains functions for creating the Scan tab UI components.
"""

import gradio as gr
from typing import Tuple, Dict, List, Optional
from PIL import Image

def create_scan_input_section():
    """
    Create the scan input section UI components.

    Returns:
        Tuple: Repository input, Gemini API key, recursion limit slider, scan button, and status box
    """
    with gr.Column(scale=1) as input_column:
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
                ["examples/javascript_vulnerable_project"],
                ["examples/python_vulnerable_project"],
            ],
            inputs=repo_input,
            label="Example Projects"
        )

        # Settings in a collapsible section
        with gr.Accordion("Settings", open=True):
            gemini_api_key = gr.Textbox(
                label="Gemini API Key (Optional)",
                placeholder="Enter your Gemini API key if you want to override settings",
                lines=1,
                type="password"
            )

            # Add slider for recursion limit
            recursion_limit_slider = gr.Slider(
                minimum=50,
                maximum=500,
                step=10,
                value=100,  # Default value for the slider
                label="Max Graph Recursion Limit",
                info="Adjusts the maximum number of steps the analysis graph can take. Higher values might allow deeper analysis for complex projects but can take longer."
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

    return repo_input, gemini_api_key, recursion_limit_slider, scan_button, status_box

def create_results_section():
    """
    Create the results section UI components.

    Returns:
        Tuple: Results container, vulnerability chart, summary markdown, details markdown, and results JSON
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
                    details_md = gr.HTML()

                with gr.Tab("Raw JSON"):
                    results_json = gr.JSON()

    return results_container, vuln_chart, summary_md, details_md, results_json

def create_scan_tab():
    """
    Create the Scan tab UI components.

    Returns:
        Tuple: The Scan tab and all its components
    """
    with gr.Tab("Scan") as scan_tab:
        with gr.Row():
            # Left column for input controls
            repo_input, gemini_api_key, recursion_limit_slider, scan_button, status_box = create_scan_input_section()

        # Results section
        results_container, vuln_chart, summary_md, details_md, results_json = create_results_section()

    return (
        scan_tab, 
        repo_input, 
        gemini_api_key, 
        recursion_limit_slider, 
        scan_button, 
        status_box, 
        results_container, 
        vuln_chart, 
        summary_md, 
        details_md, 
        results_json
    )