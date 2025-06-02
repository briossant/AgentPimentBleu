import git
import os
import re
from urllib.parse import urlparse

def is_valid_git_url(url):
    """
    Check if the provided URL is a valid Git repository URL.
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if the URL is valid, False otherwise
    """
    # Basic URL validation
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        
        # Check if it's a common Git hosting service
        common_git_hosts = [
            'github.com', 'gitlab.com', 'bitbucket.org', 'dev.azure.com'
        ]
        
        if any(host in result.netloc for host in common_git_hosts):
            return True
        
        # Check if it ends with .git
        if url.endswith('.git'):
            return True
        
        # Additional checks could be added here
        
        return True
    except:
        return False

def clone_repository(repo_url, target_dir):
    """
    Clone a Git repository to a local directory.
    
    Args:
        repo_url (str): URL of the Git repository to clone
        target_dir (str): Local directory to clone the repository to
        
    Returns:
        dict: Result of the cloning operation with keys:
            - success (bool): True if cloning was successful, False otherwise
            - message (str): Error message if cloning failed
            - repo_path (str): Path to the cloned repository if successful
    """
    # Validate the URL
    if not is_valid_git_url(repo_url):
        return {
            "success": False,
            "message": "Invalid Git repository URL. Please provide a valid URL."
        }
    
    # Ensure the target directory exists
    os.makedirs(target_dir, exist_ok=True)
    
    try:
        # Clone the repository
        repo = git.Repo.clone_from(repo_url, target_dir)
        
        return {
            "success": True,
            "message": "Repository cloned successfully.",
            "repo_path": target_dir
        }
    except git.GitCommandError as e:
        # Handle Git command errors (e.g., repository not found, authentication required)
        error_message = str(e)
        
        if "not found" in error_message.lower():
            return {
                "success": False,
                "message": "Repository not found. Please check the URL and try again."
            }
        elif "authentication" in error_message.lower():
            return {
                "success": False,
                "message": "Authentication required. This tool only supports public repositories."
            }
        else:
            return {
                "success": False,
                "message": f"Git error: {error_message}"
            }
    except Exception as e:
        # Handle other exceptions
        return {
            "success": False,
            "message": f"An error occurred while cloning the repository: {str(e)}"
        }