"""
AgentPimentBleu - RAG Service

This module provides a RAGService class for managing RAG operations using Llama-index.
"""

import os
from typing import List, Optional, Set
import pathspec
from pathspec.patterns import GitWildMatchPattern

from llama_index.core import (
    SimpleDirectoryReader,
    VectorStoreIndex,
    StorageContext,
    Settings,
    load_index_from_storage
)
from llama_index.core.indices.base import BaseIndex
from llama_index.core.schema import Document

from agentpimentbleu.config.config import get_settings
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

# Default patterns to ignore during document loading
DEFAULT_APBIGNORE_PATTERNS = [
    # Version Control
    ".git/",
    ".hg/",
    ".svn/",
    # Node.js
    "node_modules/",
    # Python
    "__pycache__/",
    "*.py[cod]",
    "*$py.class",
    "venv/",
    "env/",
    ".env",
    "pip-wheel-metadata/",
    "develop-eggs/",
    "eggs/",
    ".eggs/",
    "sdist/",
    "var/",
    "*.egg-info/",
    ".installed.cfg",
    "*.egg",
    # Build artifacts
    "build/",
    "dist/",
    # OS-specific
    ".DS_Store",
    "Thumbs.db",
    # Logs & Temp
    "*.log",
    "temp/",
    "tmp/",
    # IDE / Editor
    ".idea/",
    ".vscode/",
    "*.swp",
    "*.swo",
    # Cache files
    ".cache/",
    # AgentPimentBleu's own index
    ".agentpimentbleu_index/"
]


class RAGService:
    """
    Service for managing RAG operations using Llama-index.
    """

    def __init__(self, config=None):
        """
        Initialize the RAGService.

        Args:
            config: Configuration object (defaults to get_settings())
        """
        self.config = config or get_settings()
        self._initialize_llama_index()

    def _initialize_llama_index(self):
        """
        Initialize Llama-index components based on configuration.
        """
        rag_settings = self.config.get_rag_settings()
        embedding_model = rag_settings.get('embedding_model', 'local')

        # Configure Llama-index settings based on the specified embedding model
        logger.info(f"Initializing Llama-index with embedding model: {embedding_model}")

        # Explicitly set LLM to None to prevent using OpenAI as default
        Settings.llm = None

        if embedding_model == 'local':
            # Use a local embedding model
            from llama_index.embeddings.huggingface import HuggingFaceEmbedding
            import os
            from pathlib import Path

            # Get cache directory from settings, expand user path if needed
            cache_dir = rag_settings.get('cache_dir', '~/.cache/agentpimentbleu/models')
            cache_dir = os.path.expanduser(cache_dir)

            # Ensure cache directory exists
            os.makedirs(cache_dir, exist_ok=True)

            logger.info(f"Using cache directory for embedding model: {cache_dir}")

            # Initialize embedding model with cache directory
            Settings.embed_model = HuggingFaceEmbedding(
                model_name="BAAI/bge-small-en-v1.5",
                cache_folder=cache_dir
            )
        elif embedding_model == 'openai':
            # Use OpenAI's embedding model if API key is available
            from llama_index.embeddings.openai import OpenAIEmbedding
            Settings.embed_model = OpenAIEmbedding()
        else:
            # Default to a local model if the specified model is not recognized
            logger.warning(f"Unrecognized embedding model: {embedding_model}. Defaulting to local model.")
            from llama_index.embeddings.huggingface import HuggingFaceEmbedding
            import os

            # Get cache directory from settings, expand user path if needed
            cache_dir = rag_settings.get('cache_dir', '~/.cache/agentpimentbleu/models')
            cache_dir = os.path.expanduser(cache_dir)

            # Ensure cache directory exists
            os.makedirs(cache_dir, exist_ok=True)

            logger.info(f"Using cache directory for embedding model: {cache_dir}")

            # Initialize embedding model with cache directory
            Settings.embed_model = HuggingFaceEmbedding(
                model_name="BAAI/bge-small-en-v1.5",
                cache_folder=cache_dir
            )

    def build_index_from_project(self, project_path: str, index_storage_path: str) -> Optional[BaseIndex]:
        """
        Build a vector index from a project's source code.

        Args:
            project_path (str): Path to the project directory
            index_storage_path (str): Path to store the index

        Returns:
            Optional[BaseIndex]: The created index, or None on error
        """
        logger.info(f"Building index from project at {project_path}")

        try:
            # Define file extensions to include
            source_code_extensions = {
                ".py", ".js", ".java", ".ts", ".tsx", ".go", ".rb", 
                ".php", ".c", ".cpp", ".h", ".cs", ".swift"
            }

            # Load documents from the project directory
            documents = self._load_documents_from_directory(
                project_path, 
                source_code_extensions
            )

            if not documents:
                logger.warning(f"No source code files found in {project_path}")
                return None

            logger.info(f"Loaded {len(documents)} documents from {project_path}")

            # Build the index
            index = VectorStoreIndex.from_documents(documents)

            # Persist the index
            os.makedirs(index_storage_path, exist_ok=True)
            index.storage_context.persist(persist_dir=index_storage_path)

            logger.info(f"Index built and persisted to {index_storage_path}")

            return index

        except Exception as e:
            logger.error(f"Error building index from project: {e}")
            return None

    def _get_path_spec(self, project_path: str) -> pathspec.PathSpec:
        """
        Loads ignore patterns from .apbignore in the project_path and combines them
        with default ignore patterns.
        Returns a compiled PathSpec object.

        Args:
            project_path (str): Path to the project directory

        Returns:
            pathspec.PathSpec: Compiled PathSpec object with ignore patterns
        """
        all_patterns = list(DEFAULT_APBIGNORE_PATTERNS)  # Start with defaults

        apbignore_file_path = os.path.join(project_path, ".apbignore")
        if os.path.isfile(apbignore_file_path):
            logger.info(f"Found .apbignore file at: {apbignore_file_path}")
            try:
                with open(apbignore_file_path, 'r', encoding='utf-8') as f:
                    user_patterns = f.read().splitlines()
                    all_patterns.extend(user_patterns)
                    logger.info(f"Loaded {len(user_patterns)} patterns from .apbignore.")
            except Exception as e:
                logger.error(f"Error reading .apbignore file at {apbignore_file_path}: {e}")
        else:
            logger.info(f".apbignore file not found in {project_path}. Using default ignore patterns only.")

        # Use GitWildMatchPattern for .gitignore-style behavior
        # pathspec will automatically handle comments and blank lines
        spec = pathspec.PathSpec.from_lines(GitWildMatchPattern, all_patterns)
        return spec

    def _load_documents_from_directory(self, directory_path: str, extensions: Set[str]) -> List[Document]:
        """
        Load documents from a directory, filtering by file extensions AND .apbignore patterns.

        Args:
            directory_path (str): Path to the directory
            extensions (Set[str]): Set of file extensions to include

        Returns:
            List[Document]: List of loaded documents
        """
        logger.info(f"Loading documents from directory: {directory_path}, applying .apbignore rules.")
        path_spec = self._get_path_spec(directory_path)

        included_files_absolute_paths = []
        total_files_scanned = 0
        ignored_files_count = 0

        for root, dirs, files in os.walk(directory_path, topdown=True):
            # To make pathspec work correctly, we need paths relative to directory_path
            # for matching, but then convert to absolute for SimpleDirectoryReader.

            # Filter directories in-place to prevent os.walk from descending into them
            # if they are matched by a directory pattern in path_spec.
            relative_dirs = [os.path.relpath(os.path.join(root, d), directory_path) for d in dirs]

            # Filter dirs based on pathspec
            original_dirs_count = len(dirs)
            dirs[:] = [
                d for d, rel_d_path_with_slash in zip(dirs, [rd + os.sep for rd in relative_dirs])
                if not path_spec.match_file(rel_d_path_with_slash)
            ]
            ignored_dirs_this_level = original_dirs_count - len(dirs)
            if ignored_dirs_this_level > 0:
                logger.debug(f"Ignored {ignored_dirs_this_level} subdirectories in {root} due to .apbignore patterns.")

            for file_name in files:
                total_files_scanned += 1
                file_path_absolute = os.path.join(root, file_name)
                file_path_relative_to_project = os.path.relpath(file_path_absolute, directory_path)

                # Normalize path separators for cross-platform consistency with pathspec
                file_path_relative_to_project_normalized = file_path_relative_to_project.replace(os.sep, '/')

                if path_spec.match_file(file_path_relative_to_project_normalized):
                    ignored_files_count += 1
                    logger.debug(f"Ignoring file due to .apbignore: {file_path_relative_to_project_normalized}")
                    continue

                # Secondary filter: check file extension
                _, ext = os.path.splitext(file_name)
                if ext.lower() in extensions:
                    included_files_absolute_paths.append(file_path_absolute)
                else:
                    logger.debug(f"Skipping file due to unmatched extension: {file_path_relative_to_project_normalized} (ext: {ext})")

        logger.info(f"Total files encountered: {total_files_scanned}. Files ignored by .apbignore: {ignored_files_count}.")
        logger.info(f"Number of files matching required extensions after .apbignore filtering: {len(included_files_absolute_paths)}.")

        if not included_files_absolute_paths:
            logger.warning(f"No files for RAG indexing found in {directory_path} after filtering.")
            return []

        try:
            # Use SimpleDirectoryReader with the pre-filtered list of absolute file paths
            reader = SimpleDirectoryReader(
                input_files=included_files_absolute_paths,
                required_exts=list(extensions),  # Still useful for SimpleDirectoryReader's internal parsers
                exclude_hidden=True
            )
            documents = reader.load_data()
            logger.info(f"Successfully loaded {len(documents)} documents for RAG indexing.")
            return documents
        except Exception as e:
            logger.error(f"Error loading documents with SimpleDirectoryReader after filtering: {e}")
            return []

    def load_index(self, index_storage_path: str) -> Optional[BaseIndex]:
        """
        Load a persisted index.

        Args:
            index_storage_path (str): Path to the persisted index

        Returns:
            Optional[BaseIndex]: The loaded index, or None if not found or error
        """
        logger.info(f"Loading index from {index_storage_path}")

        try:
            if not os.path.exists(index_storage_path):
                logger.warning(f"Index storage path not found: {index_storage_path}")
                return None

            # Load the storage context
            storage_context = StorageContext.from_defaults(persist_dir=index_storage_path)

            # Load the index
            index = load_index_from_storage(storage_context)

            logger.info(f"Index loaded from {index_storage_path}")

            return index

        except Exception as e:
            logger.error(f"Error loading index: {e}")
            return None

    def query_index(self, index: BaseIndex, query_text: str) -> str:
        """
        Query an index with the given text.

        Args:
            index (BaseIndex): The index to query
            query_text (str): The query text

        Returns:
            str: The response to the query
        """
        logger.info(f"Querying index with: {query_text}")

        try:
            # Create a query engine from the index with explicitly setting llm to None
            query_engine = index.as_query_engine(llm=None)

            # Query the index
            response = query_engine.query(query_text)

            # Return the response as a string
            return str(response)

        except Exception as e:
            logger.error(f"Error querying index: {e}")
            return f"Error querying index: {e}"
