import os
import subprocess
import json
import tempfile

def run_scan(repo_path):
    """
    Run Python SAST scan on the repository using bandit.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        dict: Results of the scan with standardized format:
            - success (bool): True if scan was successful, False otherwise
            - tool_name (str): Name of the tool used
            - scan_type (str): "SAST"
            - language (str): "python"
            - findings (list): List of findings with standardized format
            - message (str): Status message or error message
            - error_message (str): Detailed error message if success is False
    """
    if not is_python_project(repo_path):
        return {
            "success": True,
            "tool_name": "bandit",
            "scan_type": "SAST",
            "language": "python",
            "message": "No Python files found in the repository.",
            "findings": []
        }
    
    # Run bandit scan
    bandit_result = run_bandit_scan(repo_path)
    
    # Convert to standardized format
    return {
        "success": bandit_result["success"],
        "tool_name": "bandit",
        "scan_type": "SAST",
        "language": "python",
        "message": bandit_result["message"],
        "findings": standardize_findings(bandit_result.get("findings", [])),
        "error_message": "" if bandit_result["success"] else bandit_result["message"]
    }

def standardize_findings(findings):
    """
    Convert bandit findings to standardized format.
    
    Args:
        findings (list): List of bandit findings
        
    Returns:
        list: List of findings in standardized format
    """
    standardized = []
    
    for finding in findings:
        standardized.append({
            "file": finding.get("filename", "unknown"),
            "line": finding.get("line_number", 0),
            "rule": finding.get("test_id", "unknown"),
            "severity": finding.get("issue_severity", "medium").lower(),
            "message": finding.get("issue_text", "Unknown issue")
        })
    
    return standardized

def is_python_project(repo_path):
    """
    Check if the repository contains Python files.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        bool: True if Python files are found, False otherwise
    """
    # Check for Python dependency files
    python_dependency_files = [
        'requirements.txt',
        'setup.py',
        'Pipfile',
        'pyproject.toml',
        'poetry.lock'
    ]
    
    for dep_file in python_dependency_files:
        if os.path.isfile(os.path.join(repo_path, dep_file)):
            return True
    
    # Check for Python files
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.py'):
                return True
    
    return False

def run_bandit_scan(repo_path):
    """
    Run bandit on Python files in the repository.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        dict: Results of the scan with keys:
            - success (bool): True if scan was successful, False otherwise
            - message (str): Error message if scan failed
            - findings (list): List of security issues found
    """
    try:
        # Create a temporary file for the JSON output
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_file:
            output_file = temp_file.name
        
        # Run bandit with JSON output
        bandit_cmd = [
            "bandit", 
            "-r", 
            repo_path, 
            "-f", 
            "json", 
            "-o", 
            output_file
        ]
        
        try:
            subprocess.run(bandit_cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            # Bandit returns non-zero exit code when issues are found
            # This is expected behavior, so we continue processing
            pass
        
        # Read the JSON output
        with open(output_file, 'r') as f:
            try:
                bandit_output = json.load(f)
                
                # Extract findings
                results = bandit_output.get("results", [])
                
                return {
                    "success": True,
                    "message": f"Scan completed. Found {len(results)} security issues.",
                    "findings": results
                }
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "message": "Failed to parse bandit output.",
                    "findings": []
                }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"An error occurred during the bandit scan: {str(e)}",
            "findings": []
        }
    finally:
        # Clean up the temporary file
        if 'output_file' in locals() and os.path.exists(output_file):
            os.unlink(output_file)