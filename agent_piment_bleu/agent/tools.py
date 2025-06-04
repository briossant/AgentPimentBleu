"""
Agent Tools for Langchain-based Security Agent

This module implements the tools and project context for the Langchain-based security agent.
"""

import os
import subprocess
import pathlib
import sys
from typing import Dict, List, Any, Optional, Tuple
from pathspec import PathSpec
from pathspec.patterns import GitWildMatchPattern
from pydantic import BaseModel, Field

from agent_piment_bleu.logger import get_logger

try:
    from langchain.tools import Tool
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("Error: Required packages not found. Please install the required dependencies:", file=sys.stderr)
    print("  pip install langchain", file=sys.stderr)
    print("This package is required for the Langchain-based agent functionality.", file=sys.stderr)

    # Define a dummy Tool class for type hints when langchain is not available
    class Tool:
        def __init__(self, name=None, func=None, description=None, args_schema=None):
            self.name = name
            self.func = func
            self.description = description
            self.args_schema = args_schema


class ProjectContext:
    """
    Context for a project repository.

    This class holds repository-specific information and implements methods for
    interacting with the filesystem.
    """

    def __init__(self, repo_path: str, logger=None):
        """
        Initialize the project context.

        Args:
            repo_path (str): Path to the repository
            logger: Logger instance (optional)
        """
        self.repo_path = repo_path
        self.logger = logger or get_logger()
        self._gitignore_spec = self._get_gitignore_spec()

    def _get_gitignore_spec(self) -> Optional[PathSpec]:
        """
        Get a PathSpec object from the .gitignore file in the repository.

        Returns:
            Optional[PathSpec]: PathSpec object from the .gitignore file, or None if no .gitignore file is found
        """
        try:
            gitignore_path = os.path.join(self.repo_path, '.gitignore')
            if not os.path.isfile(gitignore_path):
                return None

            with open(gitignore_path, 'r', encoding='utf-8', errors='replace') as f:
                gitignore_content = f.read()

            # Parse .gitignore content
            patterns = []
            for line in gitignore_content.splitlines():
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                patterns.append(line)

            return PathSpec.from_lines(GitWildMatchPattern, patterns)
        except Exception as e:
            self.logger.error(f"Error reading .gitignore file: {e}")
            return None

    def read_file_impl(self, file_path: str) -> str:
        """
        Read the contents of a file.

        Args:
            file_path (str): Path to the file to read

        Returns:
            str: Contents of the file
        """
        try:
            # Make sure the file path is within the repository
            full_path = os.path.join(self.repo_path, file_path)
            if not os.path.abspath(full_path).startswith(os.path.abspath(self.repo_path)):
                return f"Error: Attempted to access file outside repository: {file_path}. Please provide a path relative to the repository root."

            if not os.path.isfile(full_path):
                return f"Error: File not found: {file_path}. Please check if the file exists and the path is correct."

            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                if not content:
                    return f"Warning: File {file_path} is empty."
                return content
        except UnicodeDecodeError as e:
            error_msg = f"Error reading file {file_path}: The file appears to be a binary file or uses an unsupported encoding."
            self.logger.error(f"{error_msg} Original error: {e}")
            return f"Error: {error_msg}"
        except PermissionError:
            error_msg = f"Error reading file {file_path}: Permission denied. The file may be protected or require elevated privileges."
            self.logger.error(error_msg)
            return f"Error: {error_msg}"
        except Exception as e:
            error_msg = f"Error reading file {file_path}: {e}"
            self.logger.error(error_msg)
            return f"Error: {error_msg}"

    def find_files_impl(self, pattern: str) -> List[str]:
        """
        Find files matching a pattern in the repository.

        Args:
            pattern (str): Pattern to search for

        Returns:
            List[str]: List of files matching the pattern
        """
        try:
            # Use find command to search for files
            result = subprocess.run(
                ["find", self.repo_path, "-type", "f", "-name", pattern],
                capture_output=True,
                text=True
            )

            # Convert absolute paths to relative paths
            files = []
            for file in result.stdout.strip().split('\n'):
                if file:
                    rel_path = os.path.relpath(file, self.repo_path)
                    files.append(rel_path)

            if not files:
                return ["No files found matching pattern: " + pattern]

            return files
        except Exception as e:
            error_msg = f"Error finding files with pattern '{pattern}': {e}"
            self.logger.error(error_msg)
            return [f"Error: {error_msg}"]

    def search_in_files_impl(self, search_term: str) -> Dict[str, List[str]]:
        """
        Search for a term in all files in the repository.

        Args:
            search_term (str): Term to search for

        Returns:
            Dict[str, List[str]]: Dictionary mapping file paths to lists of matching lines
        """
        try:
            # Use grep to search for the term
            result = subprocess.run(
                ["grep", "-r", "--include=*.*", search_term, self.repo_path],
                capture_output=True,
                text=True
            )

            # Parse the results
            matches = {}
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(':', 1)
                    if len(parts) >= 2:
                        file_path = os.path.relpath(parts[0], self.repo_path)
                        content = parts[1]

                        if file_path not in matches:
                            matches[file_path] = []

                        matches[file_path].append(content.strip())

            if not matches:
                # Return a special message when no matches are found
                return {"_info": ["No matches found for search term: " + search_term]}

            return matches
        except Exception as e:
            error_msg = f"Error searching for term '{search_term}': {e}"
            self.logger.error(error_msg)
            return {"_error": [f"Error: {error_msg}"]}

    def get_project_structure_impl(self) -> str:
        """
        Get the structure of the project as a string (similar to tree command output).
        Respects .gitignore patterns to exclude build directories and other ignored files.

        Returns:
            str: Project structure as a string
        """
        try:
            # Check if tree command is available
            result = subprocess.run(
                ["which", "tree"], 
                capture_output=True, 
                text=True
            )

            if result.returncode == 0 and self._gitignore_spec is None:
                # Use tree command if available and no gitignore spec
                tree_result = subprocess.run(
                    ["tree", "-L", "3", self.repo_path], 
                    capture_output=True, 
                    text=True
                )
                return tree_result.stdout
            else:
                # Fallback to a simple directory listing with gitignore filtering
                structure = []
                repo_path_obj = pathlib.Path(self.repo_path)

                for root, dirs, files in os.walk(self.repo_path):
                    # Limit depth to 3 levels
                    level = root.replace(self.repo_path, '').count(os.sep)
                    if level > 3:
                        continue

                    # Get relative path for gitignore matching
                    rel_root = os.path.relpath(root, self.repo_path)
                    rel_root = '' if rel_root == '.' else rel_root

                    # Filter directories based on gitignore
                    if self._gitignore_spec:
                        # Create a copy of dirs since we'll be modifying it
                        dirs_copy = dirs.copy()
                        for d in dirs_copy:
                            rel_path = os.path.join(rel_root, d)
                            if self._gitignore_spec.match_file(rel_path) or self._gitignore_spec.match_file(f"{rel_path}/"):
                                dirs.remove(d)

                    # Skip the root directory if it's ignored
                    if self._gitignore_spec and rel_root and self._gitignore_spec.match_file(rel_root):
                        continue

                    indent = ' ' * 4 * level
                    structure.append(f"{indent}{os.path.basename(root)}/")

                    # Filter files based on gitignore
                    filtered_files = files
                    if self._gitignore_spec:
                        filtered_files = [
                            f for f in files 
                            if not self._gitignore_spec.match_file(os.path.join(rel_root, f))
                        ]

                    sub_indent = ' ' * 4 * (level + 1)
                    for file in filtered_files:
                        structure.append(f"{sub_indent}{file}")

                if not structure:
                    return "Error: Could not generate project structure. The repository may be empty or all files are excluded by .gitignore."

                return '\n'.join(structure)
        except Exception as e:
            error_msg = f"Error getting project structure: {e}"
            self.logger.error(error_msg)
            return f"Error: {error_msg}. This might be due to permission issues or an invalid repository path."


# Pydantic schemas for tool arguments
class ReadFileSchema(BaseModel):
    file_path: str = Field(description="Path to the file to read, relative to the repository root")


class FindFilesSchema(BaseModel):
    pattern: str = Field(description="Pattern to search for files (e.g., '*.js', 'package.json')")


class SearchInFilesSchema(BaseModel):
    search_term: str = Field(description="Term to search for in all files")


def get_tools(project_ctx: ProjectContext) -> List[Tool]:
    """
    Get a list of tools for the Langchain agent.

    Args:
        project_ctx (ProjectContext): Project context

    Returns:
        List[Tool]: List of Langchain Tool objects
    """
    # Check if Langchain is available
    if not LANGCHAIN_AVAILABLE:
        logger = get_logger()
        logger.error("Cannot create tools: Langchain is not available")
        logger.error("Please install the required dependencies with: pip install langchain")
        return []

    tools = [
        Tool(
            name="GetProjectStructure",
            func=lambda: project_ctx.get_project_structure_impl(),
            description="Get the structure of the project as a string (similar to tree command output). "
                        "This tool helps you understand the overall organization of the repository. "
                        "Use this tool first to get an overview of the project structure.",
        ),
        Tool(
            name="ReadFile",
            func=lambda file_path: project_ctx.read_file_impl(file_path),
            description="Read the content of a specific file within the repository. "
                        "Use this to inspect code or configuration files. "
                        "Input should be the relative file path from the repository root.",
            args_schema=ReadFileSchema,
        ),
        Tool(
            name="FindFiles",
            func=lambda pattern: project_ctx.find_files_impl(pattern),
            description="Find files matching a pattern in the repository. "
                        "Use this to locate files by name pattern (e.g., '*.js', 'package.json'). "
                        "Returns a list of relative file paths.",
            args_schema=FindFilesSchema,
        ),
        Tool(
            name="SearchInFiles",
            func=lambda search_term: project_ctx.search_in_files_impl(search_term),
            description="Search for a term in all files in the repository. "
                        "Use this to find code that uses a specific function, package, or pattern. "
                        "Returns a dictionary mapping file paths to lists of matching lines.",
            args_schema=SearchInFilesSchema,
        ),
    ]

    return tools
