"""
This module is a compatibility layer for the new reporting architecture.
It imports and uses the new reporting module to maintain backward compatibility.
"""

from agent_piment_bleu.reporting.base import generate_markdown_report

# Re-export the generate_markdown_report function for backward compatibility
__all__ = ['generate_markdown_report']
