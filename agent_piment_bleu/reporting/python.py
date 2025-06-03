"""
Python Reporter Module

This module provides a Python-specific implementation of the BaseReporter interface.
"""

from typing import Dict, Any
from agent_piment_bleu.reporting.base import BaseReporter


class Reporter(BaseReporter):
    """
    Python reporter implementation.
    
    This class provides Python-specific reporting functionality.
    """

    def __init__(self, **kwargs):
        """
        Initialize the Python reporter.

        Args:
            **kwargs: Configuration options (not used in this implementation)
        """
        pass

    def generate_failed_scan_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for a failed Python scan.

        Args:
            result (Dict[str, Any]): The failed scan result

        Returns:
            str: The report section for the failed scan
        """
        report = f"- {result['language'].capitalize()} {result['scan_type']} failed: {result['message']}\n"
        
        # Python-specific error handling
        if 'bandit is not installed' in result['message']:
            report += "  - To fix this, please install bandit with: pip install bandit\n"
        elif 'pip-audit is not installed' in result['message']:
            report += "  - To fix this, please install pip-audit with: pip install pip-audit\n"
        elif 'requirements.txt' in result['message']:
            report += "  - Make sure your project has a requirements.txt file or use a virtual environment with the required dependencies installed\n"
        
        return report

    def generate_sast_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for Python SAST findings.

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
                report += f"  - {finding.get('message', 'No description available')}\n"
                
                # Add Python-specific recommendations based on the rule
                rule = finding.get('rule', '').lower()
                if 'exec' in rule or 'eval' in rule:
                    report += "  - **Recommendation**: Avoid using exec() or eval() as they can execute arbitrary code. Use safer alternatives.\n\n"
                elif 'sql' in rule or 'injection' in rule:
                    report += "  - **Recommendation**: Use parameterized queries with libraries like SQLAlchemy or psycopg2.extras.execute_values().\n\n"
                elif 'pickle' in rule or 'marshal' in rule or 'shelve' in rule:
                    report += "  - **Recommendation**: Avoid using pickle/marshal/shelve with untrusted data. Consider using JSON or other safer serialization formats.\n\n"
                elif 'subprocess' in rule or 'os.system' in rule or 'popen' in rule:
                    report += "  - **Recommendation**: When using subprocess, never pass shell=True with untrusted input. Use subprocess.run() with a list of arguments.\n\n"
                elif 'random' in rule:
                    report += "  - **Recommendation**: For security-sensitive operations, use secrets module instead of random module.\n\n"
                elif 'hash' in rule or 'md5' in rule or 'sha1' in rule:
                    report += "  - **Recommendation**: Use strong hashing algorithms from hashlib with appropriate salting, or better yet, use specialized password hashing libraries like passlib.\n\n"
                else:
                    report += "\n"
        else:
            report += f"No security issues found in {language} code.\n"
        
        return report

    def generate_sca_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for Python SCA findings.

        Args:
            result (Dict[str, Any]): The SCA scan result

        Returns:
            str: The report section for the SCA findings
        """
        language = result['language'].capitalize()
        report = f"\n\n### SCA Findings ({language} dependencies)\n\n"

        if result['findings']:
            for finding in result['findings']:
                # Generic format for Python dependencies
                report += f"- **{finding.get('name', 'Unknown package')}** (severity: {finding.get('severity', 'unknown')})\n"
                report += f"  - {finding.get('message', 'No description available')}\n"

                if finding.get('cve'):
                    report += f"  - CVE: {finding['cve']}\n"
                    if finding.get('human_readable_description'):
                        report += f"  - Description: {finding['human_readable_description']}\n"

                # Add Python-specific recommendations
                if finding.get('fix_version'):
                    report += f"  - **Recommendation**: Update to version {finding['fix_version']} or later.\n\n"
                else:
                    report += f"  - **Recommendation**: Update to the latest version or consider using an alternative package.\n"
                    report += f"  - You can update with: pip install --upgrade {finding.get('name', 'package-name')}\n\n"
        else:
            report += f"No vulnerable dependencies found in {language} packages.\n"
        
        return report