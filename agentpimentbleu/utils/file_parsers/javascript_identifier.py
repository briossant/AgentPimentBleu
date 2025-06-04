"""
AgentPimentBleu - JavaScript Manifest Identifier

This module provides a JavaScript manifest identifier.
"""

import os
from typing import Optional, Tuple

from agentpimentbleu.utils.file_parsers.base_identifier import BaseManifestIdentifier
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()


class JavaScriptManifestIdentifier(BaseManifestIdentifier):
    """
    JavaScript manifest identifier.
    
    Looks for JavaScript project manifest files like package.json.
    """
    
    def identify(self, project_path: str) -> Optional[Tuple[str, str]]:
        """
        Identify if the project is a JavaScript project and find the main manifest file.
        
        Args:
            project_path (str): Path to the project directory
            
        Returns:
            Optional[Tuple[str, str]]: Tuple of ('javascript', manifest_file_path)
                                      or None if not identified as a JavaScript project
        """
        logger.debug(f"Checking for JavaScript manifest files in {project_path}")
        
        # Look for package.json
        package_json_path = os.path.join(project_path, "package.json")
        
        if os.path.isfile(package_json_path):
            logger.info(f"Identified JavaScript project with manifest file: {package_json_path}")
            return ("javascript", package_json_path)
        
        logger.debug(f"No JavaScript manifest files found in {project_path}")
        return None