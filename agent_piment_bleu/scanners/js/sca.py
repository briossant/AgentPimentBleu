import os
import subprocess
import json
from agent_piment_bleu.scanners.js.utils import is_npm_installed

def run_scan(repo_path):
    """
    Run JavaScript SCA scan on the repository.

    Args:
        repo_path (str): Path to the repository

    Returns:
        dict: Results of the scan with standardized format:
            - success (bool): True if scan was successful, False otherwise
            - tool_name (str): Name of the tool used
            - scan_type (str): "SCA"
            - language (str): "javascript"
            - findings (list): List of findings with standardized format
            - message (str): Status message or error message
            - error_message (str): Detailed error message if success is False
    """
    if not has_package_json(repo_path):
        return {
            "success": True,
            "tool_name": "npm-audit",
            "scan_type": "SCA",
            "language": "javascript",
            "message": "No package.json found in the repository. Skipping JavaScript dependency scanning.",
            "findings": []
        }

    # Run npm audit
    npm_audit_result = run_npm_audit(repo_path)

    # Convert to standardized format
    return {
        "success": npm_audit_result["success"],
        "tool_name": "npm-audit",
        "scan_type": "SCA",
        "language": "javascript",
        "message": npm_audit_result["message"],
        "findings": standardize_findings(npm_audit_result.get("findings", [])),
        "error_message": "" if npm_audit_result["success"] else npm_audit_result["message"]
    }

def standardize_findings(findings):
    """
    Convert npm audit findings to standardized format.

    Args:
        findings (list): List of npm audit findings

    Returns:
        list: List of findings in standardized format with text for AI agent analysis
    """
    standardized = []

    for finding in findings:
        # Create a text representation of the vulnerability for AI agent analysis
        vulnerability_text = f"""
Package: {finding.get('package', 'unknown')}
Version: {finding.get('version', 'unknown')}
Severity: {finding.get('severity', 'medium')}
Title: {finding.get('title', 'Unknown vulnerability')}
CVE: {finding.get('cve', 'N/A')}
URL: {finding.get('url', 'N/A')}
Recommendation: {finding.get('recommendation', 'Update to a patched version')}
"""

        standardized.append({
            "file": "package.json",
            "line": 0,  # npm audit doesn't provide line numbers
            "rule": f"vulnerable-dependency-{finding.get('package', 'unknown')}",
            "severity": finding.get("severity", "medium"),
            "message": finding.get("title", "Unknown vulnerability"),
            "cve": finding.get("cve", "N/A"),
            "vulnerability_text": vulnerability_text,
            "project_severity": "",  # To be filled by AI agent
            "is_project_impacted": None,  # To be filled by AI agent
            "impacted_code": "",  # To be filled by AI agent
            "proposed_fix": "",  # To be filled by AI agent
            "explanation": ""  # To be filled by AI agent
        })

    return standardized

def has_package_json(repo_path):
    """
    Check if the repository has a package.json file.

    Args:
        repo_path (str): Path to the repository

    Returns:
        bool: True if package.json is found, False otherwise
    """
    return os.path.isfile(os.path.join(repo_path, 'package.json'))


def run_npm_audit(repo_path):
    """
    Run npm audit on the repository to find vulnerable dependencies.

    Args:
        repo_path (str): Path to the repository

    Returns:
        dict: Results of the scan with keys:
            - success (bool): True if scan was successful, False otherwise
            - message (str): Error message if scan failed
            - findings (list): List of vulnerable dependencies found
    """
    # Check if npm is installed
    if not is_npm_installed():
        return {
            "success": False,
            "message": "npm is not installed. Please install Node.js and npm to enable JavaScript dependency scanning.",
            "findings": []
        }

    try:
        # Check if package.json exists
        if not has_package_json(repo_path):
            return {
                "success": True,
                "message": "No package.json found. Skipping npm audit.",
                "findings": []
            }

        # Run npm install to ensure dependencies are installed
        npm_install_cmd = ["npm", "install", "--no-fund", "--no-audit"]
        subprocess.run(npm_install_cmd, cwd=repo_path, check=True, capture_output=True)

        # Run npm audit with JSON output, checking all dependencies
        npm_audit_cmd = ["npm", "audit", "--json", "--all"]
        result = subprocess.run(npm_audit_cmd, cwd=repo_path, capture_output=True, text=True)

        # Parse the npm audit output
        findings = []

        if result.stdout:
            try:
                audit_results = json.loads(result.stdout)

                # Extract vulnerabilities from npm audit format
                vulnerabilities = audit_results.get("vulnerabilities", {})

                for pkg_name, vuln_info in vulnerabilities.items():
                    severity = vuln_info.get("severity", "").lower()

                    # Get all advisories for this package
                    via = vuln_info.get("via", [])
                    if not isinstance(via, list):
                        via = [via]

                    for advisory in via:
                        if isinstance(advisory, dict):  # It's an advisory object
                            findings.append({
                                "package": pkg_name,
                                "version": vuln_info.get("version", "unknown"),
                                "severity": severity,
                                "title": advisory.get("title", "Unknown vulnerability"),
                                "url": advisory.get("url", ""),
                                "cve": advisory.get("cve", "N/A"),
                                "recommendation": vuln_info.get("recommendation", "Update to a patched version")
                            })
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "message": "Failed to parse npm audit output.",
                    "findings": []
                }

        return {
            "success": True,
            "message": f"Scan completed. Found {len(findings)} vulnerable dependencies.",
            "findings": findings
        }
    except subprocess.CalledProcessError as e:
        # npm audit returns non-zero exit code when vulnerabilities are found
        # We need to handle this case specially
        if e.stdout:
            try:
                audit_results = json.loads(e.stdout)

                # Extract vulnerabilities from npm audit format
                vulnerabilities = audit_results.get("vulnerabilities", {})
                findings = []

                for pkg_name, vuln_info in vulnerabilities.items():
                    severity = vuln_info.get("severity", "").lower()

                    # Get all advisories for this package
                    via = vuln_info.get("via", [])
                    if not isinstance(via, list):
                        via = [via]

                    for advisory in via:
                        if isinstance(advisory, dict):  # It's an advisory object
                            findings.append({
                                "package": pkg_name,
                                "version": vuln_info.get("version", "unknown"),
                                "severity": severity,
                                "title": advisory.get("title", "Unknown vulnerability"),
                                "url": advisory.get("url", ""),
                                "cve": advisory.get("cve", "N/A"),
                                "recommendation": vuln_info.get("recommendation", "Update to a patched version")
                            })

                return {
                    "success": True,
                    "message": f"Scan completed. Found {len(findings)} vulnerable dependencies.",
                    "findings": findings
                }
            except json.JSONDecodeError:
                pass

        return {
            "success": False,
            "message": f"npm audit failed: {e.stderr.decode('utf-8') if e.stderr else str(e)}",
            "findings": []
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"An error occurred during the npm audit: {str(e)}",
            "findings": []
        }
