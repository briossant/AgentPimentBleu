"""
Utility functions for JavaScript scanners.
"""

import shutil

def is_npm_installed():
    """
    Check if npm is installed on the system.

    Returns:
        bool: True if npm is installed, False otherwise
    """
    try:
        # Check if npm is in the PATH
        npm_path = shutil.which("npm")
        return npm_path is not None
    except Exception:
        return False