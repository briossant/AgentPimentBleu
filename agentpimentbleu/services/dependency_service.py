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
            # Change to the project directory
            current_dir = os.getcwd()
            os.chdir(project_path)

            # First, install dependencies
            logger.info(f"Installing dependencies for project at {project_path}")
            install_result = subprocess.run(
                ["npm", "install", "--no-fund", "--no-audit"],
                capture_output=True,
                text=True,
                check=False
            )

            if install_result.returncode != 0:
                logger.warning(f"npm install had issues: {install_result.stderr}")
                # Continue anyway, as some dependencies might have been installed

            # Run npm audit
            logger.info(f"Running npm audit for project at {project_path}")
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                check=False  # Don't raise an exception on non-zero exit code
            )

            # Clean up node_modules and package-lock.json to prevent adding noise
            logger.info(f"Cleaning up node_modules and package-lock.json for project at {project_path}")
            try:
                if os.path.exists(os.path.join(project_path, "node_modules")):
                    subprocess.run(["rm", "-rf", os.path.join(project_path, "node_modules")], check=False)
                if os.path.exists(os.path.join(project_path, "package-lock.json")):
                    subprocess.run(["rm", "-f", os.path.join(project_path, "package-lock.json")], check=False)
            except Exception as e:
                logger.warning(f"Error cleaning up after npm audit: {e}")

            # Change back to the original directory
            os.chdir(current_dir)

            # Log the output for debugging
            logger.debug(f"npm audit exit code: {result.returncode}")
            logger.debug(f"npm audit stderr: {result.stderr}")

            # npm audit returns a non-zero exit code if vulnerabilities are found, which is expected
            if not result.stdout:
                logger.error(f"npm audit produced no output: {result.stderr}")
                return []

            # Parse the JSON output
            try:
                audit_data = json.loads(result.stdout)
                vulnerabilities = self._parse_npm_audit_results(audit_data)
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities in npm audit")
                return vulnerabilities
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

                # Initialize with top-level info, but prioritize 'via' items
                initial_advisory_title = vuln_info.get('title')
                initial_advisory_link = vuln_info.get('url')

                # 'range' at vuln_info level often is the installed version or its vulnerable range.
                # This is good for 'analyzed_project_version'.
                installed_version_str = vuln_info.get("version", vuln_info.get("range", "unknown"))

                # This will hold the specific advisory's vulnerable range (e.g., "<4.17.21")
                advisory_vulnerable_range = None

                # Attempt to get CVEs from a direct 'cves' array if present in vuln_info
                extracted_cve_ids = list(vuln_info.get('cves', []))

                # Extract primary advisory ID (could be GHSA, etc.)
                primary_advisory_id = None
                # Check if there's an advisory ID in the name field (common for GHSA)
                if 'name' in vuln_info and isinstance(vuln_info['name'], str):
                    if vuln_info['name'].startswith('GHSA-') or vuln_info['name'].startswith('OSV-'):
                        primary_advisory_id = vuln_info['name']

                # Iterate through 'via' items to get the best details
                best_via_title = None
                best_via_link = None

                if 'via' in vuln_info and isinstance(vuln_info['via'], list) and vuln_info['via']:
                    for item in vuln_info['via']:
                        if isinstance(item, dict):
                            # Prioritize the first found non-empty values or overwrite if a better one is found
                            if item.get('title') and not best_via_title:
                                best_via_title = item.get('title')
                            if item.get('url') and not best_via_link:
                                best_via_link = item.get('url')
                            if item.get('range') and not advisory_vulnerable_range: # Get range from advisory
                                advisory_vulnerable_range = item.get('range')

                            # Extract CVEs from this 'via' item's title or URL
                            if item.get('title'):
                                cve_from_title = self._extract_cve_id(item.get('title', ''))
                                if cve_from_title and cve_from_title not in extracted_cve_ids:
                                    extracted_cve_ids.append(cve_from_title)
                            if item.get('url'): # GHSA URLs are common, _extract_cve_id might not find CVEs here
                                cve_from_url = self._extract_cve_id(item.get('url', ''))
                                if cve_from_url and cve_from_url not in extracted_cve_ids:
                                    extracted_cve_ids.append(cve_from_url)

                                # Check for GHSA or OSV IDs in URL
                                url = item.get('url', '')
                                if 'ghsa' in url.lower() and not primary_advisory_id:
                                    # Extract GHSA-xxxx-xxxx-xxxx pattern
                                    import re
                                    ghsa_match = re.search(r'GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}', url, re.IGNORECASE)
                                    if ghsa_match:
                                        primary_advisory_id = ghsa_match.group(0).upper()

                            # Check for direct 'cves' array in 'via' item (less common but possible)
                            direct_via_cves = item.get('cves', [])
                            for cve in direct_via_cves:
                                if cve not in extracted_cve_ids:
                                    extracted_cve_ids.append(cve)

                            # Check if this item has a source ID that could be an advisory ID
                            if item.get('source') and isinstance(item.get('source'), str) and not primary_advisory_id:
                                source = item.get('source')
                                if source.startswith('GHSA-') or source.startswith('OSV-'):
                                    primary_advisory_id = source

                # Consolidate titles and links
                final_advisory_title = best_via_title if best_via_title else initial_advisory_title
                final_advisory_link = best_via_link if best_via_link else initial_advisory_link

                # Get fix information
                fix_suggestion = None
                if 'fixAvailable' in vuln_info:
                    if isinstance(vuln_info['fixAvailable'], bool):
                        fix_suggestion = "Update to the latest version" if vuln_info['fixAvailable'] else "No fix available"
                    elif isinstance(vuln_info['fixAvailable'], dict):
                        fix_suggestion = f"Update to version {vuln_info['fixAvailable'].get('version', 'latest')}"

                vulnerability = {
                    'package_name': name,
                    'installed_version': installed_version_str, # For 'analyzed_project_version'
                    'cve_ids': list(set(extracted_cve_ids)) if extracted_cve_ids else [], # Deduplicate
                    'primary_advisory_id': primary_advisory_id, # Could be GHSA, OSV, etc.
                    'advisory_link': final_advisory_link,
                    'advisory_title': final_advisory_title,
                    'severity': vuln_info.get('severity', 'unknown'),
                    'fix_suggestion_from_tool': fix_suggestion,
                    'advisory_vulnerable_range': advisory_vulnerable_range # e.g., "<4.17.21"
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
        Run pip-audit on a Python project.

        Args:
            manifest_path (str): Path to the manifest file (requirements.txt, etc.)

        Returns:
            List[Dict]: List of vulnerabilities in a standardized format
        """
        logger.info(f"Running pip-audit for manifest at {manifest_path}")

        try:
            result = subprocess.run(
                ["pip-audit", "-f", "json", "-r", manifest_path],
                capture_output=True,
                text=True,
                check=False  # Don't raise an exception on non-zero exit code
            )

            # pip-audit returns a non-zero exit code if vulnerabilities are found
            if result.returncode != 0 and not result.stdout:
                logger.error(f"pip-audit failed: {result.stderr}")
                return []

            # Parse the JSON output
            try:
                audit_data = json.loads(result.stdout)
                return self._parse_pip_audit_results(audit_data)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse pip-audit output: {e}")
                logger.debug(f"pip-audit output: {result.stdout}")
                return []

        except Exception as e:
            logger.error(f"Error running pip-audit: {e}")
            return []

    def _parse_pip_audit_results(self, audit_data: Dict) -> List[Dict]:
        """
        Parse pip-audit results into a standardized format.
        The JSON output from `pip-audit -f json` has a top-level "dependencies" key.
        Each dependency object has "name", "version", and a "vulns" list.

        Args:
            audit_data (Dict): pip-audit output as a dictionary

        Returns:
            List[Dict]: List of vulnerabilities in a standardized format
        """
        vulnerabilities_found = []  # Renamed to avoid confusion with the 'vulnerabilities' list in the input

        # The actual JSON from `pip-audit -f json` has a "dependencies" list
        for dep_info in audit_data.get('dependencies', []):
            package_name = dep_info.get('name', 'unknown')
            package_version = dep_info.get('version', 'unknown')

            for vuln_detail in dep_info.get('vulns', []):
                advisory_id = vuln_detail.get('id', 'unknown')
                description = vuln_detail.get('description', None)

                # Fix versions are directly in vuln_detail
                fix_versions_list = vuln_detail.get('fix_versions', [])
                fix_suggestion = f"Update to one of these versions: {', '.join(fix_versions_list)}" if fix_versions_list else "No fix available"

                # Extract CVE IDs and primary advisory ID from 'aliases'
                cve_ids = []
                primary_advisory_id_from_aliases = None  # To hold potential GHSA from aliases
                aliases = vuln_detail.get('aliases', [])
                for alias in aliases:
                    if alias.startswith('CVE-'):
                        cve_ids.append(alias)
                    elif not primary_advisory_id_from_aliases and (alias.startswith('GHSA-') or alias.startswith('OSV-')):
                        primary_advisory_id_from_aliases = alias

                # The 'id' from vuln_detail is usually the primary advisory ID (e.g., PYSEC-xxxx-xxx)
                # If 'id' is a PYSEC and we found a GHSA in aliases, GHSA might be more universal.
                # Prioritize GHSA/OSV from aliases if available, otherwise use the main 'id'.
                primary_advisory_id = primary_advisory_id_from_aliases if primary_advisory_id_from_aliases else advisory_id

                # advisory_link can be constructed or looked up if not directly provided.
                # For PYSEC/GHSA, a common pattern is osv.dev/vulnerability/<ID>
                advisory_link_base = "https://osv.dev/vulnerability/"
                advisory_link = f"{advisory_link_base}{primary_advisory_id}"  # Construct a link

                # Severity is not directly provided by pip-audit JSON output. Set to 'unknown' or derive if possible.
                severity = 'unknown'  # pip-audit JSON doesn't include severity per vulnerability

                # advisory_vulnerable_range is not directly in this JSON structure from pip-audit.
                # This was derived in the old parser from an "affected" field which is not in this newer format.
                # We might need to infer it or mark as unknown. For now, let's set to None.
                advisory_vulnerable_range = None 

                vulnerability_entry = {
                    'package_name': package_name,
                    'vulnerable_version': package_version,  # This is the installed version that is vulnerable
                    'installed_version': package_version,   # For 'analyzed_project_version'
                    'cve_ids': sorted(list(set(cve_ids))),  # Ensure unique and sorted
                    'primary_advisory_id': primary_advisory_id,
                    'advisory_link': advisory_link,
                    'advisory_title': f"{primary_advisory_id} in {package_name}",  # Construct a title
                    'severity': severity,
                    'fix_suggestion_from_tool': fix_suggestion,
                    'advisory_vulnerable_range': advisory_vulnerable_range
                }
                vulnerabilities_found.append(vulnerability_entry)

        logger.info(f"Found {len(vulnerabilities_found)} vulnerabilities in pip-audit")
        return vulnerabilities_found

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
