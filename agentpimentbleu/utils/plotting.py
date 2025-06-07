"""
AgentPimentBleu - Plotting Utilities

This module contains functions for creating visualizations and charts.
"""

import matplotlib.pyplot as plt
import numpy as np
import io
from typing import Dict, List, Optional
from PIL import Image

from agentpimentbleu.app.ui_settings import COLORS

def create_vulnerability_chart(vulnerabilities: List[Dict]) -> Optional[Image.Image]:
    """
    Create a chart showing the distribution of vulnerabilities by severity.

    Args:
        vulnerabilities (List[Dict]): List of vulnerability dictionaries

    Returns:
        Optional[Image.Image]: PIL Image of the chart or None if no vulnerabilities
    """
    if not vulnerabilities:
        return None

    # Count vulnerabilities by danger rating
    ratings = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for vuln in vulnerabilities:
        rating = vuln.get('danger_rating', 'Unknown')
        if rating in ratings:
            ratings[rating] += 1

    # Filter out ratings with zero count
    labels = [rating for rating, count in ratings.items() if count > 0]
    counts = [count for count in ratings.values() if count > 0]
    colors = [COLORS.get(label, "#808080") for label in labels]

    if not labels:  # No valid vulnerabilities
        return None

    # Create the chart
    plt.figure(figsize=(8, 5))

    # Create a pie chart with a donut hole
    plt.pie(
        counts, 
        labels=labels, 
        colors=colors,
        autopct='%1.1f%%',
        startangle=90,
        wedgeprops={'edgecolor': 'white', 'linewidth': 2}
    )

    # Add a circle at the center to create a donut chart
    centre_circle = plt.Circle((0, 0), 0.70, fc='white')
    fig = plt.gcf()
    fig.gca().add_artist(centre_circle)

    # Add title and equal aspect ratio
    plt.title('Vulnerability Severity Distribution', fontsize=16, pad=20)
    plt.axis('equal')

    # Save the chart to a bytes buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
    plt.close()
    buf.seek(0)

    # Convert to PIL Image
    return Image.open(buf)