"""
AgentPimentBleu - Dependency Service

This module provides a DependencyService class for orchestrating external audit tools
and parsing their results.
"""

import json
import os
import subprocess
from typing import Dict, List, Optional, Tuple

from agentpimentbleu.config.config import get_settings
from agentpimentbleu.utils.file_parsers import get_available_identifiers
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()


class DependencyService:
    """
    Service for orchestrating external audit tools and parsing their results.
    """
    
    def __init__(self, config=None, manifest_identifiers=None):
        """
        Initialize the DependencyService.
        
        Args:
            config: Configuration object (defaults to get_settings())
            manifest_identifiers: List of manifest identifiers (defaults to get_available_identifiers())
        """
        self.config = config or get_settings()
        self.manifest_identifiers = manifest_identifiers or get_available_identifiers()
    
    def detect_project_type_and_manifest(self, project_path: str) -> Optional[Tuple[str, str]]:
        """
        Detect the project type and manifest file.
        
        Args:
            project_path (str): Path to the project directory
            
        Returns:
            Optional[Tuple[str, str]]: Tuple of (project_type, manifest_path) or None if not detected
        """
        logger.info(f"Detecting project type for {project_path}")
        
        for identifier in self.manifest_identifiers:
            result = identifier.identify(project_path)
            if result:
                project_type, manifest_path = result
                logger.info(f"Detected project type: {project_type}, manifest: {manifest_path}")
                return project_type, manifest_path
        
        logger.warning(f"Could not detect project type for {project_path}")
        return None
    
    def run_security_audit(self, project_path: str, project_type: str, manifest_path: Optional[str] = None) -> List[Dict]:
        """
        Run a security audit for the project.
        
        Args:
            project_path (str): Path to the project directory
            project_type (str): Type of project ('javascript', 'python', etc.)
            manifest_path (Optional[str]): Path to the manifest file
            
        Returns:
            List[Dict]: List of vulnerabilities in a standardized format
        """
        logger.info(f"Running security audit for {project_type} project at {project_path}")
        
        if project_type == 'javascript':
            return self._run_npm_audit(project_path)
        elif project_type == 'python':
            if not manifest_path:
                logger.error("Manifest path is required for Python projects")
                return []
            return self._run_pip_audit(manifest_path)
        else:
            logger.warning(f"Unsupported project type: {project_type}")
            return []
    
    def _run_npm_audit(self, project_path: str) -> List[Dict]:
        """
        Run npm audit on a JavaScript project.
        
        Args:
            project_path (str): Path to the project directory
            
        Returns:
            List[Dict]: List of vulnerabilities in a standardized format
        """
        logger.info(f"Running npm audit for project at {project_path}")
        
        try:
            # Change to the project directory and run npm audit
            current_dir = os.getcwd()
            os.chdir(project_path)
            
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                check=False  # Don't raise an exception on non-zero exit code
            )
            
            # Change back to the original directory
            os.chdir(current_dir)
            
            # npm audit returns a non-zero exit code if vulnerabilities are found
            if result.returncode != 0 and not result.stdout:
                logger.error(f"npm audit failed: {result.stderr}")
                return []
            
            # Parse the JSON output
            try:
                audit_data = json.loads(result.stdout)
                return self._parse_npm_audit_results(audit_data)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse npm audit output: {e}")
                logger.debug(f"npm audit output: {result.stdout}")
                return []
            
        except Exception as e:
            logger.error(f"Error running npm audit: {e}")
            return []
    
    def _parse_npm_audit_results(self, audit_data: Dict) -> List[Dict]:
        """
        Parse npm audit results into a standardized format.
        
        Args:
            audit_data (Dict): npm audit output as a dictionary
            
        Returns:
            List[Dict]: List of vulnerabilities in a standardized format
        """
        vulnerabilities = []
        
        # npm audit format can vary between versions
        if 'vulnerabilities' in audit_data:
            # npm 7+ format
            for name, vuln_info in audit_data['vulnerabilities'].items():
                if vuln_info.get('severity') == 'info':
                    continue  # Skip informational findings
                
                # Extract CVE IDs
                cve_ids = []
                if 'via' in vuln_info:
                    if isinstance(vuln_info['via'], list):
                        for via_item in vuln_info['via']:
                            if isinstance(via_item, dict) and 'url' in via_item:
                                # Extract CVE ID from URL or title if possible
                                cve_id = self._extract_cve_id(via_item.get('url', ''))
                                if cve_id:
                                    cve_ids.append(cve_id)
                                elif 'title' in via_item and 'CVE-' in via_item['title']:
                                    cve_id = self._extract_cve_id(via_item['title'])
                                    if cve_id:
                                        cve_ids.append(cve_id)
                
                # Get fix information
                fix_suggestion = None
                if 'fixAvailable' in vuln_info:
                    if isinstance(vuln_info['fixAvailable'], bool):
                        fix_suggestion = "Update to the latest version" if vuln_info['fixAvailable'] else "No fix available"
                    elif isinstance(vuln_info['fixAvailable'], dict):
                        fix_suggestion = f"Update to version {vuln_info['fixAvailable'].get('version', 'latest')}"
                
                vulnerability = {
                    'package_name': name,
                    'vulnerable_version': vuln_info.get('version', 'unknown'),
                    'cve_ids': cve_ids,
                    'advisory_link': vuln_info.get('url', None),
                    'advisory_title': vuln_info.get('title', None),
                    'severity': vuln_info.get('severity', 'unknown'),
                    'fix_suggestion_from_tool': fix_suggestion
                }
                
                vulnerabilities.append(vulnerability)
        elif 'advisories' in audit_data:
            # npm 6 format
            for advisory_id, advisory in audit_data['advisories'].items():
                # Extract CVE IDs
                cve_ids = []
                if 'cves' in advisory:
                    cve_ids = advisory['cves']
                
                # Get fix information
                fix_suggestion = None
                if 'recommendation' in advisory:
                    fix_suggestion = advisory['recommendation']
                
                for finding in advisory.get('findings', []):
                    vulnerability = {
                        'package_name': finding.get('name', advisory.get('module_name', 'unknown')),
                        'vulnerable_version': finding.get('version', 'unknown'),
                        'cve_ids': cve_ids,
                        'advisory_link': advisory.get('url', None),
                        'advisory_title': advisory.get('title', None),
                        'severity': advisory.get('severity', 'unknown'),
                        'fix_suggestion_from_tool': fix_suggestion
                    }
                    
                    vulnerabilities.append(vulnerability)
        
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities in npm audit")
        return vulnerabilities
    
    def _run_pip_audit(self, manifest_path: str) -> List[Dict]:
        """
        Run pip audit on a Python project.
        
        Args:
            manifest_path (str): Path to the manifest file (requirements.txt, etc.)
            
        Returns:
            List[Dict]: List of vulnerabilities in a standardized format
        """
        logger.info(f"Running pip audit for manifest at {manifest_path}")
        
        try:
            result = subprocess.run(
                ["pip", "audit", "--json", "-r", manifest_path],
                capture_output=True,
                text=True,
                check=False  # Don't raise an exception on non-zero exit code
            )
            
            # pip audit returns a non-zero exit code if vulnerabilities are found
            if result.returncode != 0 and not result.stdout:
                logger.error(f"pip audit failed: {result.stderr}")
                return []
            
            # Parse the JSON output
            try:
                audit_data = json.loads(result.stdout)
                return self._parse_pip_audit_results(audit_data)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse pip audit output: {e}")
                logger.debug(f"pip audit output: {result.stdout}")
                return []
            
        except Exception as e:
            logger.error(f"Error running pip audit: {e}")
            return []
    
    def _parse_pip_audit_results(self, audit_data: Dict) -> List[Dict]:
        """
        Parse pip audit results into a standardized format.
        
        Args:
            audit_data (Dict): pip audit output as a dictionary
            
        Returns:
            List[Dict]: List of vulnerabilities in a standardized format
        """
        vulnerabilities = []
        
        # pip audit format
        for vuln in audit_data.get('vulnerabilities', []):
            # Extract package info
            package_info = vuln.get('package', {})
            package_name = package_info.get('name', 'unknown')
            package_version = package_info.get('version', 'unknown')
            
            # Extract vulnerability info
            vuln_info = vuln.get('vulnerability', {})
            advisory_id = vuln_info.get('id', 'unknown')
            advisory_link = vuln_info.get('link', None)
            description = vuln_info.get('description', None)
            
            # Extract fix info
            fix_info = vuln.get('fix', {})
            fix_version = fix_info.get('versions', [])
            fix_suggestion = f"Update to one of these versions: {', '.join(fix_version)}" if fix_version else "No fix available"
            
            # Determine severity (pip audit doesn't provide severity, so we'll use 'unknown')
            severity = 'unknown'
            
            # Extract CVE IDs
            cve_ids = []
            if 'aliases' in vuln_info:
                for alias in vuln_info['aliases']:
                    if alias.startswith('CVE-'):
                        cve_ids.append(alias)
            
            vulnerability = {
                'package_name': package_name,
                'vulnerable_version': package_version,
                'cve_ids': cve_ids,
                'advisory_link': advisory_link,
                'advisory_title': advisory_id,
                'severity': severity,
                'fix_suggestion_from_tool': fix_suggestion
            }
            
            vulnerabilities.append(vulnerability)
        
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities in pip audit")
        return vulnerabilities
    
    def _extract_cve_id(self, text: str) -> Optional[str]:
        """
        Extract a CVE ID from a string.
        
        Args:
            text (str): Text that might contain a CVE ID
            
        Returns:
            Optional[str]: CVE ID if found, None otherwise
        """
        import re
        
        # Look for CVE-YYYY-NNNNN pattern
        match = re.search(r'CVE-\d{4}-\d{4,}', text)
        if match:
            return match.group(0)
        
        return None
    
    def fetch_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch additional details for a CVE from OSV.dev or similar.
        
        Args:
            cve_id (str): CVE ID
            
        Returns:
            Optional[Dict]: Additional details for the CVE, or None if not found
        """
        # This is a placeholder for future implementation
        # Could use OSV.dev API to fetch additional details
        logger.info(f"Fetching details for {cve_id} (not implemented yet)")
        return None