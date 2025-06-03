"""
JavaScript Reporter Module

This module provides a JavaScript-specific implementation of the BaseReporter interface.
"""

from typing import Dict, Any
from agent_piment_bleu.reporting.base import BaseReporter


class Reporter(BaseReporter):
    """
    JavaScript reporter implementation.
    
    This class provides JavaScript-specific reporting functionality.
    """

    def __init__(self, **kwargs):
        """
        Initialize the JavaScript reporter.

        Args:
            **kwargs: Configuration options (not used in this implementation)
        """
        pass

    def generate_failed_scan_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for a failed JavaScript scan.

        Args:
            result (Dict[str, Any]): The failed scan result

        Returns:
            str: The report section for the failed scan
        """
        report = f"- {result['language'].capitalize()} {result['scan_type']} failed: {result['message']}\n"
        
        # JavaScript-specific error handling
        if 'npm is not installed' in result['message']:
            report += "  - To fix this, please install Node.js and npm: https://nodejs.org/\n"
        elif 'ESLint' in result['message']:
            report += "  - To fix this, please ensure ESLint is properly configured\n"
            report += "  - You may need to run: npm install eslint eslint-plugin-security\n"
        
        return report

    def generate_sast_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for JavaScript SAST findings.

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
                
                # Add JavaScript-specific recommendations based on the rule
                if 'eval' in finding.get('rule', '').lower():
                    report += "  - **Recommendation**: Avoid using eval() as it can execute arbitrary code. Use safer alternatives.\n\n"
                elif 'injection' in finding.get('rule', '').lower():
                    report += "  - **Recommendation**: Use parameterized queries or ORM libraries to prevent injection attacks.\n\n"
                elif 'xss' in finding.get('rule', '').lower():
                    report += "  - **Recommendation**: Use context-appropriate escaping and frameworks that automatically escape output.\n\n"
        else:
            report += f"No security issues found in {language} code.\n"
        
        return report

    def generate_sca_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for JavaScript SCA findings.

        Args:
            result (Dict[str, Any]): The SCA scan result

        Returns:
            str: The report section for the SCA findings
        """
        language = result['language'].capitalize()
        report = f"\n\n### SCA Findings ({language} dependencies)\n\n"

        if result['findings']:
            for finding in result['findings']:
                # npm audit format
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
                else:
                    report += f"  - Recommendation: Update to a patched version or use an alternative package.\n\n"
        else:
            report += f"No vulnerable dependencies found in {language} packages.\n"
        
        return report