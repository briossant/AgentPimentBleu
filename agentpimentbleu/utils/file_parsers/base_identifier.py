"""
AgentPimentBleu - Base Manifest Identifier

This module provides an abstract base class for manifest identifiers.
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple


class BaseManifestIdentifier(ABC):
    """
    Abstract base class for manifest identifiers.
    
    Manifest identifiers are responsible for identifying the type of project
    and the main manifest file.
    """
    
    @abstractmethod
    def identify(self, project_path: str) -> Optional[Tuple[str, str]]:
        """
        Identify the type of project and the main manifest file.
        
        Args:
            project_path (str): Path to the project directory
            
        Returns:
            Optional[Tuple[str, str]]: Tuple of (project_type_string, manifest_file_path)
                                      or None if not identified
        """
        pass