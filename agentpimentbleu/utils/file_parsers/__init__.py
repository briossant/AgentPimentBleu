"""
AgentPimentBleu - File Parsers Package

This package provides utilities for identifying and parsing project manifest files.
"""

from agentpimentbleu.utils.file_parsers.python_identifier import PythonManifestIdentifier
from agentpimentbleu.utils.file_parsers.javascript_identifier import JavaScriptManifestIdentifier
from agentpimentbleu.utils.file_parsers.base_identifier import BaseManifestIdentifier

# Create a list of available manifest identifier instances
AVAILABLE_IDENTIFIERS = [
    PythonManifestIdentifier(),
    JavaScriptManifestIdentifier()
]


def get_available_identifiers():
    """
    Get a list of all available manifest identifier instances.
    
    Returns:
        list: List of BaseManifestIdentifier instances
    """
    return AVAILABLE_IDENTIFIERS
