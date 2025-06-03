"""
Default Reporter Module

This module provides a default implementation of the BaseReporter interface.
It is used as a fallback when a language-specific reporter is not available.
"""

from typing import Dict, Any
from agent_piment_bleu.reporting.base import BaseReporter


class Reporter(BaseReporter):
    """
    Default reporter implementation.
    
    This class provides generic reporting functionality that works for any language.
    """

    def __init__(self, **kwargs):
        """
        Initialize the default reporter.

        Args:
            **kwargs: Configuration options (not used in the default reporter)
        """
        pass

    def generate_failed_scan_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for a failed scan.

        Args:
            result (Dict[str, Any]): The failed scan result

        Returns:
            str: The report section for the failed scan
        """
        report = f"- {result['language'].capitalize()} {result['scan_type']} failed: {result['message']}\n"
        
        # Generic error handling for common issues
        if 'npm is not installed' in result['message']:
            report += "  - To fix this, please install Node.js and npm: https://nodejs.org/\n"
        elif 'ESLint' in result['message']:
            report += "  - To fix this, please ensure ESLint is properly configured\n"
        elif 'bandit is not installed' in result['message']:
            report += "  - To fix this, please install bandit with: pip install bandit\n"
        elif 'pip-audit is not installed' in result['message']:
            report += "  - To fix this, please install pip-audit with: pip install pip-audit\n"
        
        return report

    def generate_sast_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for SAST findings.

        Args:
            result (Dict[str, Any]): The SAST scan result

        Returns:
            str: The report section for the SAST findings
        """
        language = result['language'].capitalize()
        report = f"\n\n### SAST Findings ({language})\n\n"

        if result['findings']:
            for finding in result['findings']:
                report += f"- **{finding.get('rule', 'Unknown rule')}** ({finding.get('severity', 'unknown')})\n"
                report += f"  - File: `{finding.get('file', 'unknown')}`, Line: {finding.get('line', 'N/A')}\n"
                report += f"  - {finding.get('message', 'No description available')}\n\n"
        else:
            report += f"No security issues found in {language} code.\n"
        
        return report

    def generate_sca_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for SCA findings.

        Args:
            result (Dict[str, Any]): The SCA scan result

        Returns:
            str: The report section for the SCA findings
        """
        language = result['language'].capitalize()
        report = f"\n\n### SCA Findings ({language} dependencies)\n\n"

        if result['findings']:
            for finding in result['findings']:
                # Handle different formats from different scanners
                if 'package' in finding:  # npm audit format
                    report += f"- **{finding.get('package', 'Unknown package')}** (version: {finding.get('version', 'unknown')}, severity: {finding.get('severity', 'unknown')})\n"
                    report += f"  - {finding.get('title', finding.get('message', 'No description available'))}\n"

                    if finding.get('cve') and finding['cve'] != "N/A":
                        report += f"  - CVE: {finding['cve']}\n"
                        if finding.get('human_readable_description'):
                            report += f"  - Description: {finding['human_readable_description']}\n"

                    if finding.get('url'):
                        report += f"  - More info: {finding['url']}\n"

                    if finding.get('recommendation'):
                        report += f"  - Recommendation: {finding['recommendation']}\n\n"
                else:  # Generic format
                    report += f"- **{finding.get('name', 'Unknown package')}** (severity: {finding.get('severity', 'unknown')})\n"
                    report += f"  - {finding.get('message', 'No description available')}\n"

                    if finding.get('cve'):
                        report += f"  - CVE: {finding['cve']}\n"
                        if finding.get('human_readable_description'):
                            report += f"  - Description: {finding['human_readable_description']}\n"

                    if finding.get('file'):
                        report += f"  - Found in: {finding['file']}\n\n"
        else:
            report += f"No vulnerable dependencies found in {language} packages.\n"
        
        return report