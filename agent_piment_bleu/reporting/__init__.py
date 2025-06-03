"""
Reporting Module

This module provides functionality for generating reports from scan results.
It includes a base reporting class and language-specific reporting classes.
"""

from agent_piment_bleu.reporting.base import BaseReporter, generate_markdown_report

__all__ = ['BaseReporter', 'generate_markdown_report']