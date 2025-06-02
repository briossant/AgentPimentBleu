import os
import subprocess
import json
import tempfile

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
        
        # Run npm audit with JSON output
        npm_audit_cmd = ["npm", "audit", "--json"]
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

def run_js_sca_scan(repo_path):
    """
    Main function to run JavaScript SCA scanning.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        dict: Results of the scan
    """
    if not has_package_json(repo_path):
        return {
            "success": True,
            "message": "No package.json found in the repository. Skipping JavaScript dependency scanning.",
            "findings": []
        }
    
    # Run npm audit
    return run_npm_audit(repo_path)