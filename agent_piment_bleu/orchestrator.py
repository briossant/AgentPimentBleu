import os
import tempfile
import shutil
import importlib
from typing import Dict, Any, List, Optional

from agent_piment_bleu.utils.git_utils import clone_repository
from agent_piment_bleu.project_detector import detect_project_languages
from agent_piment_bleu.reporting import generate_markdown_report
from agent_piment_bleu.llm import create_llm_provider, get_llm_config
from agent_piment_bleu.logger import get_logger

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
                    sast_result = enhance_sast_with_llm(sast_result, llm, language)
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
            shutil.rmtree(temp_dir)

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


def enhance_sast_with_llm(sast_result: Dict[str, Any], llm, language: str) -> Dict[str, Any]:
    """
    Enhance SAST results with LLM analysis.

    Args:
        sast_result (Dict[str, Any]): Original SAST results
        llm: LLM provider instance
        language (str): Programming language

    Returns:
        Dict[str, Any]: Enhanced SAST results
    """
    enhanced_findings = []

    for finding in sast_result.get('findings', []):
        # Skip if no code snippet is available
        if not finding.get('code_snippet'):
            enhanced_findings.append(finding)
            continue

        try:
            # Analyze the code snippet with LLM
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
            print(f"Error enhancing SAST finding with LLM: {e}")
            # Keep the original finding if enhancement fails
            enhanced_findings.append(finding)

    # Update the findings in the result
    sast_result['findings'] = enhanced_findings
    sast_result['llm_enhanced'] = True

    return sast_result


def enhance_sca_with_llm(sca_result: Dict[str, Any], llm, language: str, repo_path: str) -> Dict[str, Any]:
    """
    Enhance SCA results with LLM analysis.

    Args:
        sca_result (Dict[str, Any]): Original SCA results
        llm: LLM provider instance
        language (str): Programming language
        repo_path (str): Path to the repository

    Returns:
        Dict[str, Any]: Enhanced SCA results
    """
    enhanced_findings = []
    logger = get_logger()

    for finding in sca_result.get('findings', []):
        try:
            # Extract relevant code snippets for the vulnerable dependency
            package_name = finding.get('package', finding.get('package_name', ''))
            code_snippets = find_dependency_usage(
                repo_path=repo_path,
                dependency=package_name,
                language=language
            )

            # Get vulnerability text for AI agent analysis
            vulnerability_text = finding.get('vulnerability_text', '')
            if not vulnerability_text:
                # Create a text representation if not already present
                vulnerability_text = f"""
Package: {package_name}
Version: {finding.get('version', 'unknown')}
Severity: {finding.get('severity', 'medium')}
Title: {finding.get('message', finding.get('title', 'Unknown vulnerability'))}
CVE: {finding.get('cve', 'N/A')}
"""

            # Prepare prompt for LLM analysis
            prompt = f"""
Analyze the following security vulnerability in a {language} dependency:

{vulnerability_text}

Code snippets that might be using this dependency:
{code_snippets if code_snippets else "No specific code snippets found."}

Please provide the following information:
1. Project severity note: Assess the severity of this vulnerability for the project (critical, high, medium, low, or info).
2. Is project impacted: Determine if the project is likely impacted by this vulnerability (true/false).
3. Potentially impacted code: Identify any code patterns that might be vulnerable.
4. Proposed fix: Suggest a specific fix for this vulnerability.
5. Human-readable explanation: Provide a clear explanation of the vulnerability and its implications.

Format your response as follows:
PROJECT_SEVERITY: [Your assessment]
IS_PROJECT_IMPACTED: [true/false]
IMPACTED_CODE: [Your assessment]
PROPOSED_FIX: [Your suggestion]
EXPLANATION: [Your explanation]
"""

            logger.info(f"Sending SCA vulnerability for LLM analysis: {package_name}")

            # Get LLM analysis
            try:
                analysis_response = llm.generate_text(prompt)

                # Parse the response to extract the required fields
                project_severity = extract_field(analysis_response, "PROJECT_SEVERITY")
                is_project_impacted = extract_field(analysis_response, "IS_PROJECT_IMPACTED")
                impacted_code = extract_field(analysis_response, "IMPACTED_CODE")
                proposed_fix = extract_field(analysis_response, "PROPOSED_FIX")
                explanation = extract_field(analysis_response, "EXPLANATION")

                # Convert is_project_impacted to boolean
                is_project_impacted_bool = False
                if is_project_impacted.lower() == "true":
                    is_project_impacted_bool = True

                # Add the analysis to the finding
                finding['project_severity'] = project_severity
                finding['is_project_impacted'] = is_project_impacted_bool
                finding['impacted_code'] = impacted_code
                finding['proposed_fix'] = proposed_fix
                finding['explanation'] = explanation

                # Keep the original LLM analysis fields for backward compatibility
                finding['llm_analysis'] = {
                    'is_vulnerable': is_project_impacted_bool,
                    'confidence': 'medium',
                    'impact': project_severity,
                    'explanation': explanation,
                    'remediation': proposed_fix,
                    'provider': llm.provider_name,
                    'model': llm.model_name
                }

                logger.info(f"Successfully analyzed vulnerability for {package_name}")
            except Exception as e:
                logger.error(f"Error during LLM analysis: {e}")
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
                    'explanation': "Could not analyze with LLM.",
                    'remediation': f"Update {package_name} to the latest version.",
                    'provider': llm.provider_name if llm else 'unknown',
                    'model': llm.model_name if llm else 'unknown'
                }

            enhanced_findings.append(finding)
        except Exception as e:
            logger.error(f"Error enhancing SCA finding with LLM: {e}")
            # Keep the original finding if enhancement fails
            enhanced_findings.append(finding)

    # Update the findings in the result
    sca_result['findings'] = enhanced_findings
    sca_result['llm_enhanced'] = True

    return sca_result


def extract_field(text, field_name):
    """
    Extract a field from the LLM response.

    Args:
        text (str): The LLM response text
        field_name (str): The name of the field to extract

    Returns:
        str: The extracted field value, or a default message if not found
    """
    import re
    pattern = rf"{field_name}:\s*(.*?)(?:\n[A-Z_]+:|$)"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return f"No {field_name.lower()} provided."


def find_dependency_usage(repo_path: str, dependency: str, language: str) -> List[str]:
    """
    Find code snippets that use the specified dependency.

    Args:
        repo_path (str): Path to the repository
        dependency (str): Name of the dependency
        language (str): Programming language

    Returns:
        List[str]: List of code snippets that use the dependency
    """
    # This is a simplified implementation that would need to be expanded
    # for a production system to properly find all usages of a dependency

    # For now, return an empty list as a placeholder
    return []
