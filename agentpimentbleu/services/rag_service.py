"""
AgentPimentBleu - RAG Service

This module provides a RAGService class for managing RAG operations using Llama-index.
"""

import os
from typing import List, Optional, Set

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

    def _load_documents_from_directory(self, directory_path: str, extensions: Set[str]) -> List[Document]:
        """
        Load documents from a directory, filtering by file extensions.

        Args:
            directory_path (str): Path to the directory
            extensions (Set[str]): Set of file extensions to include

        Returns:
            List[Document]: List of loaded documents
        """
        try:
            # Use SimpleDirectoryReader to load documents
            reader = SimpleDirectoryReader(
                input_dir=directory_path,
                recursive=True,
                required_exts=list(extensions),
                exclude_hidden=True
            )

            return reader.load_data()

        except Exception as e:
            logger.error(f"Error loading documents from directory: {e}")
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
