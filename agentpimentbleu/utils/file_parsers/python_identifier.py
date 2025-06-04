"""
AgentPimentBleu - Python Manifest Identifier

This module provides a Python manifest identifier.
"""

import os
from typing import Optional, Tuple

from agentpimentbleu.utils.file_parsers.base_identifier import BaseManifestIdentifier
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()


class PythonManifestIdentifier(BaseManifestIdentifier):
    """
    Python manifest identifier.
    
    Looks for Python project manifest files like requirements.txt, Pipfile, etc.
    """
    
    def identify(self, project_path: str) -> Optional[Tuple[str, str]]:
        """
        Identify if the project is a Python project and find the main manifest file.
        
        Args:
            project_path (str): Path to the project directory
            
        Returns:
            Optional[Tuple[str, str]]: Tuple of ('python', manifest_file_path)
                                      or None if not identified as a Python project
        """
        logger.debug(f"Checking for Python manifest files in {project_path}")
        
        # List of manifest files to check, in order of preference
        manifest_files = [
            "requirements.txt",
            "Pipfile",
            "pyproject.toml"
        ]
        
        for manifest_file in manifest_files:
            manifest_path = os.path.join(project_path, manifest_file)
            
            if os.path.isfile(manifest_path):
                # For pyproject.toml, check if it's a poetry or pdm project
                if manifest_file == "pyproject.toml":
                    if not self._is_poetry_or_pdm_project(manifest_path):
                        continue
                
                logger.info(f"Identified Python project with manifest file: {manifest_path}")
                return ("python", manifest_path)
        
        logger.debug(f"No Python manifest files found in {project_path}")
        return None
    
    def _is_poetry_or_pdm_project(self, pyproject_path: str) -> bool:
        """
        Check if a pyproject.toml file is for a Poetry or PDM project.
        
        Args:
            pyproject_path (str): Path to the pyproject.toml file
            
        Returns:
            bool: True if it's a Poetry or PDM project, False otherwise
        """
        try:
            with open(pyproject_path, 'r') as f:
                content = f.read()
                
                # Check for Poetry or PDM markers
                if "[tool.poetry]" in content or "[tool.pdm]" in content:
                    return True
                
                return False
        except Exception as e:
            logger.error(f"Error reading pyproject.toml: {e}")
            return False