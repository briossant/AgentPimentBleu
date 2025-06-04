import os
import tempfile
import shutil
import importlib
import pkg_resources
import errno
import stat
import subprocess
from typing import Dict, Any, List, Optional

from agent_piment_bleu.utils.git_utils import clone_repository
from agent_piment_bleu.project_detector import detect_project_languages
from agent_piment_bleu.reporting import generate_markdown_report
from agent_piment_bleu.llm import create_llm_provider, get_llm_config
from agent_piment_bleu.logger import get_logger
from agent_piment_bleu.agent.security_agent import SecurityAgent

# Special URL for testing with the dummy vulnerable JS project
TEST_JS_VULN_URL = "test://js-vulnerable-project"

def analyze_repository(repo_url, use_llm=True, llm_provider=None):
    """
    Main function to analyze a Git repository for security vulnerabilities.

    Args:
        repo_url (str): URL of the Git repository to analyze
        use_llm (bool): Whether to use LLM for enhanced analysis
        llm_provider (str, optional): Name of the LLM provider to use

    Returns:
        str: Markdown formatted report of the analysis results
    """
    # Get the logger
    logger = get_logger()
    logger.info(f"Starting analysis of repository: {repo_url}")

    # Create a temporary directory for the repository
    temp_dir = tempfile.mkdtemp()
    logger.info(f"Created temporary directory: {temp_dir}")

    try:
        # Check if this is a test URL for the dummy vulnerable JS project
        if repo_url == TEST_JS_VULN_URL:
            # Use the dummy project instead of cloning
            logger.info(f"Using dummy vulnerable JS project for testing")

            # Try multiple methods to find the examples directory
            dummy_project_path = None

            # Method 1: Try to find it relative to the package
            try:
                dummy_project_path = pkg_resources.resource_filename('agent_piment_bleu', '../examples/js_vuln')
                if os.path.exists(dummy_project_path):
                    logger.info(f"Found dummy project using pkg_resources: {dummy_project_path}")
                else:
                    dummy_project_path = None
            except (ImportError, ModuleNotFoundError):
                logger.debug("Could not find examples using pkg_resources")

            # Method 2: Try to find it relative to the current file
            if not dummy_project_path:
                try:
                    dummy_project_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                                    "examples", "js_vuln")
                    if os.path.exists(dummy_project_path):
                        logger.info(f"Found dummy project relative to package: {dummy_project_path}")
                    else:
                        dummy_project_path = None
                except Exception as e:
                    logger.debug(f"Could not find examples relative to package: {e}")

            # Method 3: Try to find it in the installation directory
            if not dummy_project_path:
                try:
                    import agent_piment_bleu
                    package_dir = os.path.dirname(os.path.dirname(agent_piment_bleu.__file__))
                    dummy_project_path = os.path.join(package_dir, "examples", "js_vuln")
                    if os.path.exists(dummy_project_path):
                        logger.info(f"Found dummy project in installation directory: {dummy_project_path}")
                    else:
                        dummy_project_path = None
                except Exception as e:
                    logger.debug(f"Could not find examples in installation directory: {e}")

            if not dummy_project_path or not os.path.exists(dummy_project_path):
                error_msg = "Dummy project not found. Please ensure the examples/js_vuln directory is included in the package."
                logger.error(error_msg)
                return f"## Error\n\n{error_msg}"

            # Copy the dummy project to the temp directory
            try:
                for item in os.listdir(dummy_project_path):
                    src = os.path.join(dummy_project_path, item)
                    dst = os.path.join(temp_dir, item)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)
            except TypeError as e:
                if "expected str, bytes or os.PathLike object, not NoneType" in str(e):
                    error_msg = "Failed to access dummy project path. Path is None."
                    logger.error(error_msg)
                    return f"## Error\n\n{error_msg}"
                raise

            logger.info(f"Copied dummy project to {temp_dir}")
            clone_result = {"success": True, "message": "Dummy project copied successfully"}
        else:
            # Clone the repository
            logger.info(f"Cloning repository: {repo_url}")
            clone_result = clone_repository(repo_url, temp_dir)

            if not clone_result["success"]:
                logger.error(f"Failed to clone repository: {clone_result['message']}")
                return f"## Error\n\n{clone_result['message']}"

        # Detect languages used in the repository
        logger.info("Detecting project languages")
        languages = detect_project_languages(temp_dir)

        if not languages:
            logger.warning("No supported languages detected in the repository")
            return "## Error\n\nNo supported languages detected in the repository."

        logger.info(f"Detected languages: {', '.join(languages)}")

        # Initialize results container
        scan_results = []

        # Initialize LLM provider if requested
        llm = None
        if use_llm:
            try:
                logger.info(f"Initializing LLM provider: {llm_provider if llm_provider else 'default'}")
                llm = create_llm_provider(llm_provider)
                logger.info(f"Using LLM provider: {llm.provider_name} with model: {llm.model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize LLM provider: {e}")
                logger.info("Continuing without LLM enhancement")

        # Run appropriate scanners for each detected language
        for language in languages:
            # Run SAST scanners
            logger.info(f"Running SAST scan for language: {language}")
            sast_result = run_sast_scan(language, temp_dir)
            if sast_result:
                # Enhance SAST results with LLM if available
                if llm and sast_result.get('success', False) and sast_result.get('findings', []):
                    logger.info(f"Enhancing SAST results with LLM for language: {language}")
                    sast_result = enhance_sast_with_llm(sast_result, llm, language, temp_dir)
                scan_results.append(sast_result)
                logger.info(f"SAST scan for {language} completed with {len(sast_result.get('findings', []))} findings")

            # Run SCA scanners
            logger.info(f"Running SCA scan for language: {language}")
            sca_result = run_sca_scan(language, temp_dir)
            if sca_result:
                # Enhance SCA results with LLM if available
                if llm and sca_result.get('success', False) and sca_result.get('findings', []):
                    logger.info(f"Enhancing SCA results with LLM for language: {language}")
                    sca_result = enhance_sca_with_llm(sca_result, llm, language, temp_dir)
                scan_results.append(sca_result)
                logger.info(f"SCA scan for {language} completed with {len(sca_result.get('findings', []))} findings")

        # Aggregate results
        logger.info("Aggregating scan results")
        aggregated_results = {
            'repo_url': repo_url,
            'languages': languages,
            'scan_results': scan_results,
            'llm_enhanced': llm is not None
        }

        # Generate the report
        logger.info("Generating markdown report")
        report = generate_markdown_report(aggregated_results)
        logger.info("Report generation completed")

        return report

    except Exception as e:
        logger.error(f"An unexpected error occurred during analysis: {str(e)}")
        return f"## Error\n\nAn unexpected error occurred: {str(e)}"

    finally:
        # Clean up the temporary directory
        logger.info(f"Cleaning up temporary directory: {temp_dir}")
        if os.path.exists(temp_dir):
            try:
                # Define error handler for shutil.rmtree
                def handle_remove_readonly(func, path, exc):
                    # Handle read-only files and directories
                    excvalue = exc[1]
                    if func in (os.rmdir, os.remove, os.unlink) and excvalue.errno == errno.EACCES:
                        # Change file/directory permissions
                        os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 0o777
                        # Retry the removal
                        func(path)
                    elif func == os.rmdir and excvalue.errno == errno.ENOTEMPTY:
                        # Handle non-empty directory
                        # First try to remove all contents with forced permissions
                        for item in os.listdir(path):
                            item_path = os.path.join(path, item)
                            if os.path.isdir(item_path):
                                try:
                                    # Use shutil.rmtree with the same error handler
                                    shutil.rmtree(item_path, onerror=handle_remove_readonly)
                                except Exception as e:
                                    logger.warning(f"Could not remove directory {item_path}: {e}")
                            else:
                                try:
                                    os.chmod(item_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 0o777
                                    os.remove(item_path)
                                except Exception as e:
                                    logger.warning(f"Could not remove file {item_path}: {e}")
                        # Try again to remove the directory
                        try:
                            os.rmdir(path)
                        except Exception as e:
                            logger.warning(f"Could not remove directory {path} after clearing contents: {e}")
                    else:
                        # For other errors, just log and continue
                        logger.warning(f"Error removing {path}: {excvalue}")

                # Use shutil.rmtree with our custom error handler
                shutil.rmtree(temp_dir, onerror=handle_remove_readonly)
            except Exception as e:
                logger.warning(f"Error while cleaning up temporary directory: {e}")
                logger.info("Attempting to force remove with system commands...")

                # As a last resort, try using system commands
                try:
                    if os.name == 'nt':  # Windows
                        subprocess.run(['rd', '/s', '/q', temp_dir], check=False, shell=True)
                    else:  # Unix/Linux/Mac
                        subprocess.run(['rm', '-rf', temp_dir], check=False, shell=True)
                except Exception as e:
                    logger.warning(f"Failed to remove directory using system commands: {e}")

                # Final check if the temp directory still exists
                if os.path.exists(temp_dir):
                    logger.warning(f"Temporary directory {temp_dir} may need manual cleanup")

                    # Log specific directories that couldn't be removed
                    try:
                        for root, dirs, files in os.walk(temp_dir, topdown=False):
                            for name in dirs:
                                dir_path = os.path.join(root, name)
                                if os.path.exists(dir_path):
                                    logger.warning(f"Could not remove directory {name}: [Errno 39] Directory not empty: '{dir_path}'")
                            for name in files:
                                file_path = os.path.join(root, name)
                                if os.path.exists(file_path):
                                    logger.warning(f"Could not remove file {name}: [Errno 13] Permission denied: '{file_path}'")
                    except Exception as e:
                        logger.warning(f"Error while logging remaining files: {e}")

def run_sast_scan(language, repo_path):
    """
    Run the appropriate SAST scanner for the given language.

    Args:
        language (str): Language to scan ('javascript', 'python', etc.)
        repo_path (str): Path to the repository

    Returns:
        dict: Results of the scan, or None if scanner not available
    """
    logger = get_logger()
    try:
        # Import the appropriate scanner module
        logger.info(f"Importing SAST scanner module for {language}")
        # Map 'javascript' to 'js' for the import path
        module_language = 'js' if language == 'javascript' else language
        scanner_module = importlib.import_module(f"agent_piment_bleu.scanners.{module_language}.sast")

        # Run the scan
        logger.info(f"Running {language} SAST scan")
        result = scanner_module.run_scan(repo_path)

        # Ensure the result has the standard format
        if 'language' not in result:
            result['language'] = language
        if 'scan_type' not in result:
            result['scan_type'] = 'SAST'

        return result
    except (ImportError, AttributeError):
        # Scanner not available for this language
        logger.warning(f"SAST scanner not available for {language}")
        return None
    except Exception as e:
        # Scanner failed
        logger.error(f"SAST scanner for {language} failed: {str(e)}")
        return {
            'success': False,
            'language': language,
            'scan_type': 'SAST',
            'tool_name': f"{language} SAST scanner",
            'message': f"Scanner failed: {str(e)}",
            'findings': [],
            'error_message': str(e)
        }

def run_sca_scan(language, repo_path):
    """
    Run the appropriate SCA scanner for the given language.

    Args:
        language (str): Language to scan ('javascript', 'python', etc.)
        repo_path (str): Path to the repository

    Returns:
        dict: Results of the scan, or None if scanner not available
    """
    logger = get_logger()
    try:
        # Import the appropriate scanner module
        logger.info(f"Importing SCA scanner module for {language}")
        # Map 'javascript' to 'js' for the import path
        module_language = 'js' if language == 'javascript' else language
        scanner_module = importlib.import_module(f"agent_piment_bleu.scanners.{module_language}.sca")

        # Run the scan
        logger.info(f"Running {language} SCA scan")
        result = scanner_module.run_scan(repo_path)

        # Ensure the result has the standard format
        if 'language' not in result:
            result['language'] = language
        if 'scan_type' not in result:
            result['scan_type'] = 'SCA'

        return result
    except (ImportError, AttributeError):
        # Scanner not available for this language
        logger.warning(f"SCA scanner not available for {language}")
        return None
    except Exception as e:
        # Scanner failed
        logger.error(f"SCA scanner for {language} failed: {str(e)}")
        return {
            'success': False,
            'language': language,
            'scan_type': 'SCA',
            'tool_name': f"{language} SCA scanner",
            'message': f"Scanner failed: {str(e)}",
            'findings': [],
            'error_message': str(e)
        }


def enhance_sast_with_llm(sast_result: Dict[str, Any], llm, language: str, repo_path: str = None) -> Dict[str, Any]:
    """
    Enhance SAST results with LLM analysis.

    Args:
        sast_result (Dict[str, Any]): Original SAST results
        llm: LLM provider instance
        language (str): Programming language
        repo_path (str, optional): Path to the repository for agent-based analysis

    Returns:
        Dict[str, Any]: Enhanced SAST results
    """
    enhanced_findings = []
    logger = get_logger()

    # Create a security agent if repo_path is provided and not None
    agent = None
    if repo_path is not None:
        try:
            # Create the security agent
            agent = SecurityAgent(llm, repo_path)
            logger.info(f"Created SecurityAgent for SAST analysis in {repo_path}")
        except Exception as e:
            logger.error(f"Failed to create security agent: {e}")

    for finding in sast_result.get('findings', []):
        # Skip if no code snippet is available
        if not finding.get('code_snippet'):
            enhanced_findings.append(finding)
            continue

        try:
            # If we have an agent and repo_path, use the agent for more comprehensive analysis
            if repo_path is not None and agent is not None:
                # Prepare the finding for agent analysis by adding vulnerability_text
                code_snippet = finding.get('code_snippet', '')
                finding['vulnerability_text'] = f"""
Type: SAST Finding
Rule: {finding.get('rule', 'Unknown rule')}
Severity: {finding.get('severity', 'medium')}
Message: {finding.get('message', 'Unknown issue')}
File: {finding.get('file', 'Unknown file')}
Line: {finding.get('line', 'Unknown line')}

Code Snippet:
```{language}
{code_snippet}
```
"""

                logger.info(f"Using security agent to analyze SAST finding: {finding.get('rule', 'Unknown rule')}")

                try:
                    # Use the security agent to analyze the finding
                    analyzed_finding = agent.analyze_vulnerability(finding)
                    enhanced_findings.append(analyzed_finding)
                    logger.info(f"Successfully analyzed SAST finding with SecurityAgent")
                except Exception as e:
                    logger.error(f"Error during security agent SAST analysis: {e}")
                    # Fallback to simple analysis if agent fails
                    fallback_analysis = llm.analyze_code(
                        code=code_snippet,
                        language=language,
                        task='security'
                    )

                    # Add LLM analysis to the finding
                    finding['llm_analysis'] = {
                        'summary': fallback_analysis.get('summary', 'No summary provided'),
                        'issues': fallback_analysis.get('issues', []),
                        'provider': llm.provider_name,
                        'model': llm.model_name
                    }

                    enhanced_findings.append(finding)
            else:
                # Use the standard LLM analysis if no agent is available
                code_snippet = finding.get('code_snippet', '')
                analysis = llm.analyze_code(
                    code=code_snippet,
                    language=language,
                    task='security'
                )

                # Add LLM analysis to the finding
                finding['llm_analysis'] = {
                    'summary': analysis.get('summary', 'No summary provided'),
                    'issues': analysis.get('issues', []),
                    'provider': llm.provider_name,
                    'model': llm.model_name
                }

                enhanced_findings.append(finding)
        except Exception as e:
            logger.error(f"Error enhancing SAST finding with LLM: {e}")
            # Keep the original finding if enhancement fails
            enhanced_findings.append(finding)

    # Update the findings in the result
    sast_result['findings'] = enhanced_findings
    sast_result['llm_enhanced'] = True
    if repo_path is not None and agent is not None:
        sast_result['agent_enhanced'] = True  # Mark as enhanced by the agent
        sast_result['agent_type'] = 'langchain'  # Indicate the agent type

    return sast_result


def enhance_sca_with_llm(sca_result: Dict[str, Any], llm, language: str, repo_path: str = None) -> Dict[str, Any]:
    """
    Enhance SCA results with LLM analysis.

    Args:
        sca_result (Dict[str, Any]): Original SCA results
        llm: LLM provider instance
        language (str): Programming language
        repo_path (str, optional): Path to the repository

    Returns:
        Dict[str, Any]: Enhanced SCA results
    """
    enhanced_findings = []
    logger = get_logger()

    # Create a security agent if repo_path is provided and not None
    agent = None
    if repo_path is not None:
        try:
            # Create the security agent
            agent = SecurityAgent(llm, repo_path)
            logger.info(f"Created SecurityAgent for exploring {repo_path}")
        except Exception as e:
            logger.error(f"Failed to create security agent: {e}")

    for finding in sca_result.get('findings', []):
        try:
            # Get vulnerability text for AI agent analysis
            vulnerability_text = finding.get('vulnerability_text', '')
            if not vulnerability_text:
                # Create a text representation if not already present
                package_name = finding.get('package', finding.get('package_name', ''))
                vulnerability_text = f"""
Package: {package_name}
Version: {finding.get('version', 'unknown')}
Severity: {finding.get('severity', 'medium')}
Title: {finding.get('message', finding.get('title', 'Unknown vulnerability'))}
CVE: {finding.get('cve', 'N/A')}
"""
                finding['vulnerability_text'] = vulnerability_text

            logger.info(f"Using security agent to analyze vulnerability: {finding.get('cve', 'Unknown CVE')}")

            # If we have an agent and repo_path, use the agent for more comprehensive analysis
            if repo_path and agent is not None:
                try:
                    # Use the security agent to analyze the vulnerability
                    analyzed_finding = agent.analyze_vulnerability(finding)
                    enhanced_findings.append(analyzed_finding)
                    logger.info(f"Successfully analyzed vulnerability with SecurityAgent")
                except Exception as e:
                    logger.error(f"Error during security agent analysis: {e}")
                    # Fallback to simple analysis if agent fails
                    package_name = finding.get('package', finding.get('package_name', ''))
                    # Continue with fallback analysis below
            else:
                # Use a simpler analysis if no agent is available or it's None
                if agent is None:
                    logger.warning("SecurityAgent is None, using fallback analysis")
                package_name = finding.get('package', finding.get('package_name', ''))

                # Set default values if analysis fails
                finding['project_severity'] = finding.get('severity', 'unknown')
                finding['is_project_impacted'] = True
                finding['impacted_code'] = "Could not determine impacted code."
                finding['proposed_fix'] = f"Update {package_name} to the latest version."
                finding['explanation'] = f"This dependency has a known vulnerability. Please update to a patched version."

                # Keep the original LLM analysis fields for backward compatibility
                finding['llm_analysis'] = {
                    'is_vulnerable': True,
                    'confidence': 'low',
                    'impact': finding.get('severity', 'unknown'),
                    'explanation': "Could not analyze with SecurityAgent.",
                    'remediation': f"Update {package_name} to the latest version.",
                    'provider': llm.provider_name if llm else 'unknown',
                    'model': llm.model_name if llm else 'unknown'
                }

                enhanced_findings.append(finding)
        except Exception as e:
            logger.error(f"Error enhancing SCA finding with SecurityAgent: {e}")
            # Keep the original finding if enhancement fails
            enhanced_findings.append(finding)

    # Update the findings in the result
    sca_result['findings'] = enhanced_findings
    sca_result['llm_enhanced'] = True
    if repo_path is not None and agent is not None:
        sca_result['agent_enhanced'] = True  # Mark as enhanced by the agent
        sca_result['agent_type'] = 'langchain'  # Indicate the agent type

    return sca_result


# Old LLM analysis code removed - now using SecurityAgent for analysis
