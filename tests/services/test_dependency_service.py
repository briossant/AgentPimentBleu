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
        """Test running pip-audit with mocked subprocess."""
        # Set up the mock subprocess.run to return a sample pip-audit output
        mock_process = MagicMock()
        mock_process.returncode = 1  # pip-audit returns non-zero if vulnerabilities found
        mock_process.stdout = json.dumps({
            "vulnerabilities": [
                {
                    "package": {
                        "name": "werkzeug",
                        "version": "0.10.0"
                    },
                    "vulnerability": {
                        "id": "PYSEC-2019-123",
                        "link": "https://osv.dev/vulnerability/PYSEC-2019-123",
                        "aliases": ["CVE-2016-10149"],
                        "description": "The debugger in Werkzeug before 0.11.0 allows remote code execution.",
                        "affected": [
                            {
                                "package": {
                                    "name": "werkzeug",
                                    "ecosystem": "PyPI"
                                },
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "0.11.0"}
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                    "fix": {
                        "versions": ["0.11.0"]
                    }
                }
            ]
        })
        mock_run.return_value = mock_process

        # Call the method
        result = self.dependency_service._run_pip_audit('/path/to/requirements.txt')

        # Assert the result
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['package_name'], 'werkzeug')
        self.assertEqual(result[0]['vulnerable_version'], '0.10.0')
        self.assertEqual(result[0]['installed_version'], '0.10.0')
        self.assertEqual(result[0]['cve_ids'], ['CVE-2016-10149'])
        self.assertEqual(result[0]['primary_advisory_id'], 'PYSEC-2019-123')
        self.assertEqual(result[0]['advisory_link'], 'https://osv.dev/vulnerability/PYSEC-2019-123')
        self.assertEqual(result[0]['advisory_title'], 'PYSEC-2019-123')
        self.assertEqual(result[0]['advisory_vulnerable_range'], '<0.11.0')
        self.assertEqual(result[0]['fix_suggestion_from_tool'], 'Update to one of these versions: 0.11.0')

        # Assert the mock was called
        mock_run.assert_called_once()


if __name__ == '__main__':
    unittest.main()
