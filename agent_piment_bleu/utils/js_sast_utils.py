import os
import subprocess
import json
import tempfile

def is_js_project(repo_path):
    """
    Check if the repository contains JavaScript files.

    Args:
        repo_path (str): Path to the repository

    Returns:
        bool: True if JavaScript files are found, False otherwise
    """
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.js') or file.endswith('.jsx') or file.endswith('.ts') or file.endswith('.tsx'):
                return True
    return False

def setup_eslint(repo_path):
    """
    Set up ESLint with security plugins in the repository.

    Args:
        repo_path (str): Path to the repository

    Returns:
        dict: Result of the setup operation
    """
    try:
        # Create a temporary ESLint configuration file with security rules
        eslint_config = {
            "env": {
                "browser": True,
                "node": True,
                "es6": True
            },
            "extends": [
                "eslint:recommended"
            ],
            "plugins": [
                "security",
                "security-node"
            ],
            "rules": {
                "security/detect-unsafe-regex": "error",
                "security/detect-buffer-noassert": "error",
                "security/detect-child-process": "error",
                "security/detect-disable-mustache-escape": "error",
                "security/detect-eval-with-expression": "error",
                "security/detect-no-csrf-before-method-override": "error",
                "security/detect-non-literal-fs-filename": "error",
                "security/detect-non-literal-regexp": "error",
                "security/detect-non-literal-require": "error",
                "security/detect-object-injection": "error",
                "security/detect-possible-timing-attacks": "error",
                "security/detect-pseudoRandomBytes": "error",
                "security-node/detect-absence-of-name-option-in-exrpress-session": "error",
                "security-node/detect-buffer-unsafe-allocation": "error",
                "security-node/detect-child-process": "error",
                "security-node/detect-crlf": "error",
                "security-node/detect-dangerous-redirects": "error",
                "security-node/detect-improper-exception-handling": "error",
                "security-node/detect-insecure-cookie": "error",
                "security-node/detect-missing-helmet": "error",
                "security-node/detect-nosql-injection": "error",
                "security-node/detect-option-multiplestatements-in-mysql": "error",
                "security-node/detect-option-rejectunauthorized-in-nodejs-httpsrequest": "error",
                "security-node/detect-possible-timing-attacks": "error",
                "security-node/detect-runinthiscontext-method": "error",
                "security-node/detect-sql-injection": "error",
                "security-node/detect-unhandled-async-errors": "error",
                "security-node/detect-unhandled-event-errors": "error",
                "security-node/detect-weak-crypto-dependency": "error"
            }
        }

        config_path = os.path.join(repo_path, '.eslintrc.json')
        with open(config_path, 'w') as f:
            json.dump(eslint_config, f, indent=2)

        # Install ESLint and security plugins locally
        npm_install_cmd = ["npm", "install", "--no-save", "eslint", "eslint-plugin-security", "eslint-plugin-security-node"]
        subprocess.run(npm_install_cmd, cwd=repo_path, check=True, capture_output=True)

        return {
            "success": True,
            "message": "ESLint with security plugin set up successfully."
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "message": f"Failed to set up ESLint: {e.stderr.decode('utf-8')}"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"An error occurred while setting up ESLint: {str(e)}"
        }

def run_eslint_scan(repo_path):
    """
    Run ESLint with security rules on JavaScript files in the repository.

    Args:
        repo_path (str): Path to the repository

    Returns:
        dict: Results of the scan with keys:
            - success (bool): True if scan was successful, False otherwise
            - message (str): Error message if scan failed
            - findings (list): List of security issues found
    """
    try:
        # Find all JavaScript files
        js_files = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.js') or file.endswith('.jsx') or file.endswith('.ts') or file.endswith('.tsx'):
                    js_files.append(os.path.join(root, file))

        if not js_files:
            return {
                "success": True,
                "message": "No JavaScript files found to scan.",
                "findings": []
            }

        # Run ESLint on the JavaScript files
        eslint_cmd = ["npx", "eslint", "--format", "json", "--no-eslintrc", "-c", ".eslintrc.json"] + js_files
        result = subprocess.run(eslint_cmd, cwd=repo_path, capture_output=True, text=True)

        # Parse the ESLint output
        findings = []

        if result.stdout:
            try:
                eslint_results = json.loads(result.stdout)

                for file_result in eslint_results:
                    file_path = os.path.relpath(file_result["filePath"], repo_path)

                    for message in file_result.get("messages", []):
                        if message.get("ruleId", "").startswith("security/") or message.get("ruleId", "").startswith("security-node/"):
                            findings.append({
                                "file": file_path,
                                "line": message.get("line", 0),
                                "column": message.get("column", 0),
                                "rule": message.get("ruleId", "unknown"),
                                "severity": "high" if message.get("severity", 1) == 2 else "medium",
                                "message": message.get("message", "Unknown issue")
                            })
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "message": "Failed to parse ESLint output.",
                    "findings": []
                }

        return {
            "success": True,
            "message": f"Scan completed. Found {len(findings)} security issues.",
            "findings": findings
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "message": f"ESLint scan failed: {e.stderr.decode('utf-8') if e.stderr else str(e)}",
            "findings": []
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"An error occurred during the ESLint scan: {str(e)}",
            "findings": []
        }

def run_js_sast_scan(repo_path):
    """
    Main function to run JavaScript SAST scanning.

    Args:
        repo_path (str): Path to the repository

    Returns:
        dict: Results of the scan
    """
    if not is_js_project(repo_path):
        return {
            "success": True,
            "message": "No JavaScript files found in the repository.",
            "findings": []
        }

    # Set up ESLint with security plugins
    setup_result = setup_eslint(repo_path)
    if not setup_result["success"]:
        return {
            "success": False,
            "message": setup_result["message"],
            "findings": []
        }

    # Run the ESLint scan
    return run_eslint_scan(repo_path)
