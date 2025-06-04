"""
AgentPimentBleu - Git Service

This module provides a GitService class for cloning Git repositories
and handling local paths.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from agentpimentbleu.utils.logger import get_logger

logger = get_logger()


class GitService:
    """
    Service for Git operations, primarily cloning repositories.
    Also handles local paths for example projects.
    """

    def prepare_repository(self, repo_source: str, local_base_path: str = None) -> Optional[str]:
        """
        Prepare a repository for scanning.
        
        If repo_source is a URL, clone the Git repository.
        If repo_source is a local path with a special test URL format, copy the example project.
        
        Args:
            repo_source (str): URL of the Git repository or local path
            local_base_path (str, optional): Base path for local repositories
            
        Returns:
            Optional[str]: Absolute path to the prepared repository, or None on failure
        """
        logger.info(f"Preparing repository from source: {repo_source}")
        
        # Check if it's a local example path with special format
        if repo_source.startswith("examples/") or repo_source.startswith("file://examples/"):
            return self._prepare_local_example(repo_source.replace("file://", ""), local_base_path)
        
        # Check if it's a local path
        if os.path.isdir(repo_source):
            logger.info(f"Using existing local directory: {repo_source}")
            return os.path.abspath(repo_source)
        
        # Assume it's a Git URL
        return self._clone_repository(repo_source)
    
    def _prepare_local_example(self, example_path: str, local_base_path: str = None) -> Optional[str]:
        """
        Copy an example project to a temporary directory.
        
        Args:
            example_path (str): Path to the example project
            local_base_path (str, optional): Base path for local repositories
            
        Returns:
            Optional[str]: Absolute path to the copied example project, or None on failure
        """
        # Determine the source path
        if local_base_path:
            source_path = os.path.join(local_base_path, example_path)
        else:
            # Assume relative to current working directory
            source_path = example_path
        
        if not os.path.isdir(source_path):
            logger.error(f"Example project not found at {source_path}")
            return None
        
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="agentpimentbleu_example_")
        
        try:
            # Copy the example project to the temporary directory
            dest_path = os.path.join(temp_dir, os.path.basename(example_path))
            shutil.copytree(source_path, dest_path)
            logger.info(f"Copied example project from {source_path} to {dest_path}")
            return dest_path
        except Exception as e:
            logger.error(f"Failed to copy example project: {e}")
            self.cleanup_repository(temp_dir)
            return None
    
    def _clone_repository(self, repo_url: str) -> Optional[str]:
        """
        Clone a Git repository to a temporary directory.
        
        Args:
            repo_url (str): URL of the Git repository
            
        Returns:
            Optional[str]: Absolute path to the cloned repository, or None on failure
        """
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="agentpimentbleu_repo_")
        
        try:
            # Clone the repository
            logger.info(f"Cloning repository from {repo_url} to {temp_dir}")
            result = subprocess.run(
                ["git", "clone", repo_url, temp_dir],
                capture_output=True,
                text=True,
                check=True
            )
            logger.debug(f"Git clone output: {result.stdout}")
            return temp_dir
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone repository: {e.stderr}")
            self.cleanup_repository(temp_dir)
            return None
        except Exception as e:
            logger.error(f"Unexpected error during repository cloning: {e}")
            self.cleanup_repository(temp_dir)
            return None
    
    def cleanup_repository(self, repo_path: str) -> None:
        """
        Delete a repository directory.
        
        Args:
            repo_path (str): Path to the repository directory
        """
        if not repo_path or not os.path.exists(repo_path):
            return
        
        try:
            logger.info(f"Cleaning up repository at {repo_path}")
            shutil.rmtree(repo_path)
        except Exception as e:
            logger.error(f"Failed to clean up repository: {e}")