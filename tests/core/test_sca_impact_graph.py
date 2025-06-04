"""
Tests for the SCA Impact Graph.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import os
from typing import Dict, Any

from agentpimentbleu.core.graphs.sca_impact_graph import run_sca_scan
from agentpimentbleu.services.dependency_service import DependencyService
from agentpimentbleu.services.llm_service import LLMService
from agentpimentbleu.services.rag_service import RAGService


class TestScaImpactGraph(unittest.TestCase):
    """Test cases for the SCA Impact Graph."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock config
        self.mock_config = MagicMock()
        
        # Define the example project path
        self.example_project_path = "examples/python_example_vulnerable_project_1"
        
        # Define predefined vulnerabilities (as if returned by DependencyService.run_security_audit)
        self.predefined_vulnerabilities = [
            {
                "package_name": "werkzeug",
                "vulnerable_version": "0.10.0",
                "cve_ids": ["CVE-2016-10149"],
                "advisory_link": "https://osv.dev/vulnerability/PYSEC-2019-123",
                "advisory_title": "Werkzeug Debugger RCE",
                "severity": "high",
                "fix_suggestion_from_tool": "Update to version 0.11.0 or later"
            }
        ]
        
        # Define predefined LLM responses for each step
        self.predefined_llm_responses = {
            "analyze_cve_description": json.dumps({
                "vulnerability_type": "Remote Code Execution",
                "affected_components": ["werkzeug.debug.console", "werkzeug.debug.DebuggedApplication"],
                "exploitation_conditions": "Debug mode enabled, PIN protection disabled or bypassed"
            }),
            "search_codebase_for_impact": json.dumps({
                "usage_found": True,
                "evidence_snippet": "app.debug = True\napp.config['WERKZEUG_DEBUG_PIN'] = 'off'",
                "file_path": "src/main.py",
                "explanation": "The application explicitly enables debug mode and disables PIN protection"
            }),
            "evaluate_impact_and_danger": json.dumps({
                "is_exploitable_in_context": True,
                "impact_summary": "The application is vulnerable to remote code execution via the Werkzeug debugger",
                "danger_rating": "Critical",
                "rating_justification": "Debug mode is enabled and PIN protection is disabled, allowing unauthenticated RCE"
            }),
            "propose_fix": json.dumps({
                "primary_fix_recommendation": "Update Werkzeug to version 0.11.0 or later",
                "alternative_mitigations": [
                    "Disable debug mode in production",
                    "Enable PIN protection if debug mode is necessary"
                ]
            })
        }
        
        # Define predefined RAG query results
        self.predefined_rag_results = "File: src/main.py\n\n```python\napp = Flask(__name__)\n\n# Deliberately set a weak secret key\napp.secret_key = \"very_predictable_secret_key\"\n\n# Enable debug mode, which activates the Werkzeug debugger\napp.debug = True\n\n# Disable the PIN protection for the debugger (extremely insecure!)\napp.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False\napp.config['WERKZEUG_DEBUG_PIN'] = 'off'\n```"

    @patch.object(DependencyService, 'detect_project_type_and_manifest')
    @patch.object(DependencyService, 'run_security_audit')
    @patch.object(RAGService, 'build_index_from_project')
    @patch.object(RAGService, 'load_index')
    @patch.object(RAGService, 'query_index')
    @patch.object(LLMService, 'invoke_llm')
    def test_run_scan_on_example_project_with_mocked_audit(
        self, 
        mock_invoke_llm, 
        mock_query_index, 
        mock_load_index, 
        mock_build_index, 
        mock_run_security_audit, 
        mock_detect_project
    ):
        """Test running a scan on an example project with mocked services."""
        # Set up the mocks
        mock_detect_project.return_value = ('python', f"{self.example_project_path}/requirements.txt")
        mock_run_security_audit.return_value = self.predefined_vulnerabilities
        mock_build_index.return_value = MagicMock()
        mock_load_index.return_value = MagicMock()
        mock_query_index.return_value = self.predefined_rag_results
        
        # Set up the LLM mock to return different responses based on the prompt
        def mock_llm_side_effect(prompt_template, input_data, provider_name=None):
            # Determine which step we're in based on the input data
            if 'tool_advisory_title' in input_data:
                return self.predefined_llm_responses["analyze_cve_description"]
            elif 'rag_search_results' in input_data:
                return self.predefined_llm_responses["search_codebase_for_impact"]
            elif 'usage_explanation' in input_data:
                return self.predefined_llm_responses["evaluate_impact_and_danger"]
            elif 'fix_suggestion_from_tool' in input_data:
                return self.predefined_llm_responses["propose_fix"]
            else:
                return "{}"
        
        mock_invoke_llm.side_effect = mock_llm_side_effect
        
        # Run the scan
        result = run_sca_scan(self.example_project_path, self.mock_config)
        
        # Assert the result
        self.assertIn('vulnerabilities', result)
        self.assertEqual(len(result['vulnerabilities']), 1)
        
        # Check the vulnerability details
        vuln = result['vulnerabilities'][0]
        self.assertEqual(vuln['package_name'], 'werkzeug')
        self.assertEqual(vuln['cve_id'], 'CVE-2016-10149')
        self.assertEqual(vuln['danger_rating'], 'Critical')
        
        # Verify that all mocks were called
        mock_detect_project.assert_called_once()
        mock_run_security_audit.assert_called_once()
        mock_build_index.assert_called_once()
        mock_load_index.assert_called_once()
        mock_query_index.assert_called()  # Called multiple times
        self.assertGreater(mock_invoke_llm.call_count, 3)  # Called for each LLM step


if __name__ == '__main__':
    unittest.main()