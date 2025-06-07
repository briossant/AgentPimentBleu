"""
AgentPimentBleu - UI Settings

This module contains UI settings, constants, and styling for the Gradio UI.
"""

# API URL - default to localhost, but can be overridden with environment variable
import os
API_URL = os.environ.get("APB_API_URL", "http://127.0.0.1:8000")

# Define a consistent color scheme for the UI
COLORS = {
    "primary": "#3B82F6",  # Blue
    "secondary": "#6B7280",  # Gray
    "success": "#10B981",  # Green
    "warning": "#F59E0B",  # Amber
    "danger": "#EF4444",  # Red
    "info": "#3B82F6",  # Blue
    "light": "#F3F4F6",  # Light gray
    "dark": "#1F2937",  # Dark gray
    "background": "#F9FAFB",  # Very light gray
    "text": "#111827",  # Very dark gray
    # Severity colors
    "Critical": "#FF0000",  # Red
    "High": "#FF6600",      # Orange
    "Medium": "#FFCC00",    # Yellow
    "Low": "#3366FF",       # Blue
    "Informational": "#00CC00"  # Green
}

# Custom CSS for better styling
CUSTOM_CSS = """
/* General styling */
body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #111827;
    background-color: #F9FAFB;
}

/* Header styling */
h1 {
    font-weight: 700;
    color: #1F2937;
    margin-bottom: 1rem;
}

h2 {
    font-weight: 600;
    color: #374151;
    margin-top: 1.5rem;
    margin-bottom: 1rem;
}

h3 {
    font-weight: 600;
    color: #4B5563;
    margin-top: 1.25rem;
    margin-bottom: 0.75rem;
}

/* Card styling */
.card {
    border-radius: 0.5rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    padding: 1rem;
    margin-bottom: 1rem;
    background-color: white;
}

/* Button styling */
button.primary {
    background-color: #3B82F6;
    color: white;
    font-weight: 500;
}

button.primary:hover {
    background-color: #2563EB;
}

/* Accordion styling */
details {
    border: 1px solid #E5E7EB;
    border-radius: 0.375rem;
    padding: 0.5rem;
    margin-bottom: 0.5rem;
}

details summary {
    font-weight: 500;
    cursor: pointer;
    padding: 0.5rem;
}

details summary h4 {
    display: inline;
    margin: 0;
}

/* Badge styling */
.badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    text-align: center;
    white-space: nowrap;
    margin-right: 0.5rem;
}

.badge-critical {
    background-color: #FEE2E2;
    color: #B91C1C;
}

.badge-high {
    background-color: #FFEDD5;
    color: #C2410C;
}

.badge-medium {
    background-color: #FEF3C7;
    color: #92400E;
}

.badge-low {
    background-color: #DBEAFE;
    color: #1E40AF;
}

.badge-info {
    background-color: #D1FAE5;
    color: #065F46;
}

/* Metrics card styling */
.metrics-card {
    text-align: center;
    padding: 1rem;
    border-radius: 0.5rem;
    background-color: white;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.metrics-card .number {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
}

.metrics-card .label {
    font-size: 0.875rem;
    color: #6B7280;
}

/* Progress bar styling */
.progress-container {
    width: 100%;
    height: 0.5rem;
    background-color: #E5E7EB;
    border-radius: 9999px;
    overflow: hidden;
    margin-bottom: 0.5rem;
}

.progress-bar {
    height: 100%;
    border-radius: 9999px;
    transition: width 0.3s ease;
}

/* Vulnerability details styling */
.vuln-details {
    margin-left: 1.5rem;
    padding: 1rem;
    border-left: 3px solid #E5E7EB;
}

/* Code block styling */
pre {
    background-color: #F3F4F6;
    padding: 1rem;
    border-radius: 0.375rem;
    overflow-x: auto;
}

code {
    font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
}

/* Table styling */
table {
    width: 100%;
    border-collapse: collapse;
}

table th, table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid #E5E7EB;
}

table th {
    background-color: #F9FAFB;
    font-weight: 600;
}

/* Responsive adjustments */
@media (max-width: 640px) {
    .metrics-card {
        padding: 0.75rem;
    }

    .metrics-card .number {
        font-size: 1.25rem;
    }
}

/* Fix for details summary h4 */
details summary h4 {
    display: inline;
}
"""

def get_danger_rating_color(rating: str) -> str:
    """
    Get the color for a danger rating.

    Args:
        rating (str): The danger rating

    Returns:
        str: The color for the rating
    """
    return COLORS.get(rating, "#808080")  # Default to gray if rating not found