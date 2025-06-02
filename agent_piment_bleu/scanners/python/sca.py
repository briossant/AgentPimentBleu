import os
import subprocess
import json
import tempfile

def run_scan(repo_path):
    """
    Run Python SCA scan on the repository using pip-audit.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        dict: Results of the scan with standardized format:
            - success (bool): True if scan was successful, False otherwise
            - tool_name (str): Name of the tool used
            - scan_type (str): "SCA"
            - language (str): "python"
            - findings (list): List of findings with standardized format
            - message (str): Status message or error message
            - error_message (str): Detailed error message if success is False
    """
    if not has_python_dependencies(repo_path):
        return {
            "success": True,
            "tool_name": "pip-audit",
            "scan_type": "SCA",
            "language": "python",
            "message": "No Python dependency files found in the repository. Skipping Python dependency scanning.",
            "findings": []
        }
    
    # Run pip-audit scan
    pip_audit_result = run_pip_audit(repo_path)
    
    # Convert to standardized format
    return {
        "success": pip_audit_result["success"],
        "tool_name": "pip-audit",
        "scan_type": "SCA",
        "language": "python",
        "message": pip_audit_result["message"],
        "findings": standardize_findings(pip_audit_result.get("findings", [])),
        "error_message": "" if pip_audit_result["success"] else pip_audit_result["message"]
    }

def standardize_findings(findings):
    """
    Convert pip-audit findings to standardized format.
    
    Args:
        findings (list): List of pip-audit findings
        
    Returns:
        list: List of findings in standardized format
    """
    standardized = []
    
    for finding in findings:
        standardized.append({
            "file": finding.get("dependency_file", "requirements.txt"),
            "line": 0,  # pip-audit doesn't provide line numbers
            "rule": f"vulnerable-dependency-{finding.get('name', 'unknown')}",
            "severity": finding.get("severity", "medium"),
            "message": finding.get("description", "Unknown vulnerability"),
            "cve": finding.get("id", "N/A")
        })
    
    return standardized

def has_python_dependencies(repo_path):
    """
    Check if the repository has Python dependency files.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        bool: True if Python dependency files are found, False otherwise
    """
    dependency_files = [
        'requirements.txt',
        'setup.py',
        'Pipfile',
        'pyproject.toml',
        'poetry.lock'
    ]
    
    for dep_file in dependency_files:
        if os.path.isfile(os.path.join(repo_path, dep_file)):
            return True
    
    return False

def run_pip_audit(repo_path):
    """
    Run pip-audit on the repository to find vulnerable dependencies.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        dict: Results of the scan with keys:
            - success (bool): True if scan was successful, False otherwise
            - message (str): Error message if scan failed
            - findings (list): List of vulnerable dependencies found
    """
    try:
        # Check for requirements.txt first
        requirements_path = os.path.join(repo_path, 'requirements.txt')
        if os.path.isfile(requirements_path):
            return run_pip_audit_on_requirements(requirements_path)
        
        # Check for setup.py
        setup_path = os.path.join(repo_path, 'setup.py')
        if os.path.isfile(setup_path):
            return run_pip_audit_on_setup(setup_path)
        
        # Check for other dependency files
        # For simplicity, we'll just report that we found a dependency file but can't scan it
        # In a real implementation, you would add support for Pipfile, pyproject.toml, etc.
        return {
            "success": True,
            "message": "Found Python dependency files, but they are not supported by this scanner yet.",
            "findings": []
        }
    
    except Exception as e:
        return {
            "success": False,
            "message": f"An error occurred during the pip-audit scan: {str(e)}",
            "findings": []
        }

def run_pip_audit_on_requirements(requirements_path):
    """
    Run pip-audit on a requirements.txt file.
    
    Args:
        requirements_path (str): Path to the requirements.txt file
        
    Returns:
        dict: Results of the scan
    """
    try:
        # Create a temporary file for the JSON output
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            output_file = temp_file.name
        
        # Run pip-audit with JSON output
        pip_audit_cmd = [
            "pip-audit", 
            "-r", 
            requirements_path, 
            "--format", 
            "json", 
            "-o", 
            output_file
        ]
        
        try:
            subprocess.run(pip_audit_cmd, check=True, capture_output=True)
            has_vulnerabilities = False
        except subprocess.CalledProcessError as e:
            # pip-audit returns non-zero exit code when vulnerabilities are found
            # This is expected behavior, so we continue processing
            has_vulnerabilities = True
        
        # Read the JSON output
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                try:
                    pip_audit_output = json.load(f)
                    
                    # Extract findings
                    vulnerabilities = []
                    
                    # The exact format depends on the pip-audit version
                    # This is a simplified example
                    for dep in pip_audit_output:
                        name = dep.get("name", "unknown")
                        for vuln in dep.get("vulnerabilities", []):
                            vulnerabilities.append({
                                "name": name,
                                "version": dep.get("version", "unknown"),
                                "id": vuln.get("id", "N/A"),
                                "description": vuln.get("description", "Unknown vulnerability"),
                                "severity": vuln.get("severity", "medium"),
                                "dependency_file": "requirements.txt"
                            })
                    
                    return {
                        "success": True,
                        "message": f"Scan completed. Found {len(vulnerabilities)} vulnerable dependencies.",
                        "findings": vulnerabilities
                    }
                except json.JSONDecodeError:
                    return {
                        "success": False,
                        "message": "Failed to parse pip-audit output.",
                        "findings": []
                    }
        else:
            # No vulnerabilities found or empty output
            return {
                "success": True,
                "message": "Scan completed. No vulnerable dependencies found.",
                "findings": []
            }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"An error occurred during the pip-audit scan: {str(e)}",
            "findings": []
        }
    finally:
        # Clean up the temporary file
        if 'output_file' in locals() and os.path.exists(output_file):
            os.unlink(output_file)

def run_pip_audit_on_setup(setup_path):
    """
    Run pip-audit on a setup.py file.
    
    Args:
        setup_path (str): Path to the setup.py file
        
    Returns:
        dict: Results of the scan
    """
    try:
        # Get the directory containing setup.py
        setup_dir = os.path.dirname(setup_path)
        
        # Create a temporary file for the JSON output
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            output_file = temp_file.name
        
        # Run pip-audit with JSON output
        pip_audit_cmd = [
            "pip-audit", 
            "-l", 
            setup_dir, 
            "--format", 
            "json", 
            "-o", 
            output_file
        ]
        
        try:
            subprocess.run(pip_audit_cmd, check=True, capture_output=True)
            has_vulnerabilities = False
        except subprocess.CalledProcessError as e:
            # pip-audit returns non-zero exit code when vulnerabilities are found
            # This is expected behavior, so we continue processing
            has_vulnerabilities = True
        
        # Read the JSON output
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                try:
                    pip_audit_output = json.load(f)
                    
                    # Extract findings
                    vulnerabilities = []
                    
                    # The exact format depends on the pip-audit version
                    # This is a simplified example
                    for dep in pip_audit_output:
                        name = dep.get("name", "unknown")
                        for vuln in dep.get("vulnerabilities", []):
                            vulnerabilities.append({
                                "name": name,
                                "version": dep.get("version", "unknown"),
                                "id": vuln.get("id", "N/A"),
                                "description": vuln.get("description", "Unknown vulnerability"),
                                "severity": vuln.get("severity", "medium"),
                                "dependency_file": "setup.py"
                            })
                    
                    return {
                        "success": True,
                        "message": f"Scan completed. Found {len(vulnerabilities)} vulnerable dependencies.",
                        "findings": vulnerabilities
                    }
                except json.JSONDecodeError:
                    return {
                        "success": False,
                        "message": "Failed to parse pip-audit output.",
                        "findings": []
                    }
        else:
            # No vulnerabilities found or empty output
            return {
                "success": True,
                "message": "Scan completed. No vulnerable dependencies found.",
                "findings": []
            }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"An error occurred during the pip-audit scan: {str(e)}",
            "findings": []
        }
    finally:
        # Clean up the temporary file
        if 'output_file' in locals() and os.path.exists(output_file):
            os.unlink(output_file)