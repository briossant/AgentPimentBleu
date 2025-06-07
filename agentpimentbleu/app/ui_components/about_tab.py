"""
AgentPimentBleu - About Tab UI Components

This module contains functions for creating the About tab UI components.
"""

import gradio as gr

def create_about_tab():
    """
    Create the About tab UI components.

    Returns:
        gr.Tab: The About tab with all its components
    """
    with gr.Tab("About") as about_tab:
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
    
    return about_tab