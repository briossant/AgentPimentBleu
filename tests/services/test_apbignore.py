import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from agentpimentbleu.services.rag_service import RAGService
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

class TestApbignore(unittest.TestCase):
    """Test the .apbignore feature in RAGService."""

    def setUp(self):
        """Set up the test environment."""
        self.rag_service = RAGService()
        self.example_project_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'examples', 'python_vulnerable_project'
        )
        self.temp_dir = tempfile.TemporaryDirectory()
        self.index_storage_path = os.path.join(self.temp_dir.name, 'index')

    def tearDown(self):
        """Clean up after the test."""
        self.temp_dir.cleanup()

    def test_apbignore_filtering(self):
        """Test that .apbignore patterns are correctly applied during indexing."""
        # Build the index
        index = self.rag_service.build_index_from_project(
            self.example_project_path,
            self.index_storage_path
        )
        
        # Verify that the index was created
        self.assertIsNotNone(index, "Index should be created successfully")
        
        # Check that the index storage directory exists
        self.assertTrue(os.path.exists(self.index_storage_path), 
                        "Index storage directory should exist")
        
        # Verify that files specified in .apbignore were not indexed
        # This is a bit tricky to test directly, so we'll query the index
        # to see if content from ignored files is present
        
        # Query for content from data/sample.yaml (should be ignored)
        yaml_query_result = self.rag_service.query_index(index, "sample yaml content")
        self.assertNotIn("sample.yaml", yaml_query_result.lower(), 
                         "Content from ignored YAML file should not be in the index")
        
        # Query for content from static/text_files/ (should be ignored)
        text_query_result = self.rag_service.query_index(index, "notes.txt content")
        self.assertNotIn("notes.txt", text_query_result.lower(), 
                         "Content from ignored text files directory should not be in the index")
        
        logger.info("All .apbignore tests passed successfully!")


if __name__ == '__main__':
    unittest.main()