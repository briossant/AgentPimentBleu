"""
Tests for the DependencyService.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import os

from agentpimentbleu.services.dependency_service import DependencyService
from agentpimentbleu.utils.file_parsers.base_identifier import BaseManifestIdentifier


class TestDependencyService(unittest.TestCase):
    """Test cases for the DependencyService."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock config
        self.mock_config = MagicMock()

        # Create a mock manifest identifier
        self.mock_identifier = MagicMock(spec=BaseManifestIdentifier)

        # Create the DependencyService with mocks
        self.dependency_service = DependencyService(
            config=self.mock_config,
            manifest_identifiers=[self.mock_identifier]
        )

    def test_detect_project_type_and_manifest(self):
        """Test detecting project type and manifest."""
        # Set up the mock identifier to return a project type and manifest path
        self.mock_identifier.identify.return_value = ('python', '/path/to/requirements.txt')

        # Call the method
        result = self.dependency_service.detect_project_type_and_manifest('/path/to/project')

        # Assert the result
        self.assertEqual(result, ('python', '/path/to/requirements.txt'))

        # Assert the mock was called
        self.mock_identifier.identify.assert_called_once_with('/path/to/project')

    def test_detect_project_type_and_manifest_not_found(self):
        """Test detecting project type and manifest when not found."""
        # Set up the mock identifier to return None
        self.mock_identifier.identify.return_value = None

        # Call the method
        result = self.dependency_service.detect_project_type_and_manifest('/path/to/project')

        # Assert the result
        self.assertIsNone(result)

        # Assert the mock was called
        self.mock_identifier.identify.assert_called_once_with('/path/to/project')

    @patch('subprocess.run')
    def test_run_npm_audit_mocked(self, mock_run):
        """Test running npm audit with mocked subprocess."""
        # Set up the mock subprocess.run to return a sample npm audit output
        mock_process = MagicMock()
        mock_process.returncode = 1  # npm audit returns non-zero if vulnerabilities found
        mock_process.stdout = json.dumps({
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash",
                    "severity": "high",
                    "via": [
                        {
                            "source": 1065,
                            "name": "lodash",
                            "dependency": "lodash",
                            "title": "Prototype Pollution",
                            "url": "https://npmjs.com/advisories/1065",
                            "severity": "high",
                            "range": "<4.17.11"
                        }
                    ],
                    "effects": [],
                    "range": "<4.17.11",
                    "nodes": ["node_modules/lodash"],
                    "fixAvailable": {
                        "name": "lodash",
                        "version": "4.17.21",
                        "isSemVerMajor": false
                    }
                }
            },
            "metadata": {
                "vulnerabilities": {
                    "info": 0,
                    "low": 0,
                    "moderate": 0,
                    "high": 1,
                    "critical": 0,
                    "total": 1
                }
            }
        })
        mock_run.return_value = mock_process

        # Call the method
        result = self.dependency_service._run_npm_audit('/path/to/project')

        # Assert the result
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['package_name'], 'lodash')
        self.assertEqual(result[0]['severity'], 'high')

        # Assert the new fields added in our enhancement
        self.assertEqual(result[0]['installed_version'], '<4.17.11')  # From vuln_info.get('range')
        self.assertEqual(result[0]['advisory_vulnerable_range'], '<4.17.11')  # From via[0].get('range')
        self.assertEqual(result[0]['cve_ids'], ['CVE-2020-8203'])  # Should now extract the CVE ID
        self.assertEqual(result[0]['advisory_title'], 'Prototype Pollution')  # From via[0].get('title')
        self.assertEqual(result[0]['advisory_link'], 'https://npmjs.com/advisories/1065')  # From via[0].get('url')
        self.assertEqual(result[0]['fix_suggestion_from_tool'], 'Update to version 4.17.21')

        # Assert the mock was called
        mock_run.assert_called_once()

    @patch('subprocess.run')
    def test_run_pip_audit_mocked(self, mock_run):
        """Test running pip-audit with mocked subprocess using the correct JSON structure."""
        # Set up the mock subprocess.run to return a sample pip-audit output
        mock_process = MagicMock()
        mock_process.returncode = 1  # pip-audit returns non-zero if vulnerabilities found
        # THIS IS THE CORRECTED MOCK JSON STRUCTURE
        mock_process.stdout = json.dumps({
            "dependencies": [
                {
                    "name": "werkzeug",
                    "version": "0.16.1",
                    "vulns": [
                        {
                            "id": "PYSEC-2022-203",  # This is the advisory_id
                            "fix_versions": ["2.1.1"],
                            "aliases": ["CVE-2022-29361"],  # CVEs are here
                            "description": "A Werkzeug vulnerability description."
                        }
                    ]
                },
                {
                    "name": "pyyaml",
                    "version": "5.1",
                    "vulns": [
                        {
                            "id": "PYSEC-2020-176",
                            "fix_versions": ["5.2b1"],
                            "aliases": ["CVE-2019-20477", "GHSA-3pqx-4fqf-j49f"],
                            "description": "PyYAML 5.1 insufficient restrictions."
                        }
                    ]
                }
            ],
            "fixes": []
        })
        mock_run.return_value = mock_process

        # Call the method
        result = self.dependency_service._run_pip_audit('/path/to/requirements.txt')

        # Assert the result
        self.assertEqual(len(result), 2)  # Expecting 2 vulnerabilities now

        # Check Werkzeug
        werkzeug_vuln = next(v for v in result if v['package_name'] == 'werkzeug')
        self.assertEqual(werkzeug_vuln['package_name'], 'werkzeug')
        self.assertEqual(werkzeug_vuln['vulnerable_version'], '0.16.1')
        self.assertEqual(werkzeug_vuln['installed_version'], '0.16.1')
        self.assertIn('CVE-2022-29361', werkzeug_vuln['cve_ids'])
        self.assertEqual(werkzeug_vuln['primary_advisory_id'], 'PYSEC-2022-203')  # Or GHSA if preferred
        self.assertEqual(werkzeug_vuln['advisory_link'], 'https://osv.dev/vulnerability/PYSEC-2022-203')
        self.assertEqual(werkzeug_vuln['advisory_title'], 'PYSEC-2022-203 in werkzeug')
        self.assertEqual(werkzeug_vuln['fix_suggestion_from_tool'], 'Update to one of these versions: 2.1.1')

        # Check PyYAML
        pyyaml_vuln = next(v for v in result if v['package_name'] == 'pyyaml')
        self.assertEqual(pyyaml_vuln['package_name'], 'pyyaml')
        self.assertEqual(pyyaml_vuln['vulnerable_version'], '5.1')
        self.assertIn('CVE-2019-20477', pyyaml_vuln['cve_ids'])
        # Prioritize GHSA from aliases if present
        self.assertEqual(pyyaml_vuln['primary_advisory_id'], 'GHSA-3pqx-4fqf-j49f')
        self.assertEqual(pyyaml_vuln['advisory_link'], 'https://osv.dev/vulnerability/GHSA-3pqx-4fqf-j49f')
        self.assertEqual(pyyaml_vuln['advisory_title'], 'GHSA-3pqx-4fqf-j49f in pyyaml')

        # Assert the mock was called
        mock_run.assert_called_once()


if __name__ == '__main__':
    unittest.main()
