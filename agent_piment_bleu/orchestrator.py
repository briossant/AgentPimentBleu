import os
import tempfile
import shutil
import importlib
from typing import Dict, Any, List, Optional

from agent_piment_bleu.utils.git_utils import clone_repository
from agent_piment_bleu.project_detector import detect_project_languages
from agent_piment_bleu.reporting import generate_markdown_report
from agent_piment_bleu.llm import create_llm_provider, get_llm_config

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
    # Create a temporary directory for the repository
    temp_dir = tempfile.mkdtemp()

    try:
        # Clone the repository
        clone_result = clone_repository(repo_url, temp_dir)

        if not clone_result["success"]:
            return f"## Error\n\n{clone_result['message']}"

        # Detect languages used in the repository
        languages = detect_project_languages(temp_dir)

        if not languages:
            return "## Error\n\nNo supported languages detected in the repository."

        # Initialize results container
        scan_results = []

        # Initialize LLM provider if requested
        llm = None
        if use_llm:
            try:
                llm = create_llm_provider(llm_provider)
                print(f"Using LLM provider: {llm.provider_name} with model: {llm.model_name}")
            except Exception as e:
                print(f"Failed to initialize LLM provider: {e}")
                print("Continuing without LLM enhancement")

        # Run appropriate scanners for each detected language
        for language in languages:
            # Run SAST scanners
            sast_result = run_sast_scan(language, temp_dir)
            if sast_result:
                # Enhance SAST results with LLM if available
                if llm and sast_result.get('success', False) and sast_result.get('findings', []):
                    sast_result = enhance_sast_with_llm(sast_result, llm, language)
                scan_results.append(sast_result)

            # Run SCA scanners
            sca_result = run_sca_scan(language, temp_dir)
            if sca_result:
                # Enhance SCA results with LLM if available
                if llm and sca_result.get('success', False) and sca_result.get('findings', []):
                    sca_result = enhance_sca_with_llm(sca_result, llm, language, temp_dir)
                scan_results.append(sca_result)

        # Aggregate results
        aggregated_results = {
            'repo_url': repo_url,
            'languages': languages,
            'scan_results': scan_results,
            'llm_enhanced': llm is not None
        }

        # Generate the report
        report = generate_markdown_report(aggregated_results)

        return report

    except Exception as e:
        return f"## Error\n\nAn unexpected error occurred: {str(e)}"

    finally:
        # Clean up the temporary directory
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
    try:
        # Import the appropriate scanner module
        scanner_module = importlib.import_module(f"agent_piment_bleu.scanners.{language}.sast")

        # Run the scan
        result = scanner_module.run_scan(repo_path)

        # Ensure the result has the standard format
        if 'language' not in result:
            result['language'] = language
        if 'scan_type' not in result:
            result['scan_type'] = 'SAST'

        return result
    except (ImportError, AttributeError):
        # Scanner not available for this language
        return None
    except Exception as e:
        # Scanner failed
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
    try:
        # Import the appropriate scanner module
        scanner_module = importlib.import_module(f"agent_piment_bleu.scanners.{language}.sca")

        # Run the scan
        result = scanner_module.run_scan(repo_path)

        # Ensure the result has the standard format
        if 'language' not in result:
            result['language'] = language
        if 'scan_type' not in result:
            result['scan_type'] = 'SCA'

        return result
    except (ImportError, AttributeError):
        # Scanner not available for this language
        return None
    except Exception as e:
        # Scanner failed
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

    for finding in sca_result.get('findings', []):
        try:
            # Extract relevant code snippets for the vulnerable dependency
            code_snippets = find_dependency_usage(
                repo_path=repo_path,
                dependency=finding.get('package_name', ''),
                language=language
            )

            # Skip LLM analysis if no code snippets found
            if not code_snippets:
                enhanced_findings.append(finding)
                continue

            # Prepare CVE info for LLM
            cve_info = {
                'id': finding.get('vulnerability_id', 'Unknown'),
                'description': finding.get('description', 'No description provided'),
                'component': finding.get('package_name', 'Unknown'),
                'cvss_score': finding.get('severity', 'Unknown')
            }

            # Assess vulnerability impact with LLM
            impact_assessment = llm.assess_vulnerability_impact(
                cve_info=cve_info,
                code_snippets=code_snippets
            )

            # Add LLM analysis to the finding
            finding['llm_analysis'] = {
                'is_vulnerable': impact_assessment.get('is_vulnerable', False),
                'confidence': impact_assessment.get('confidence', 'low'),
                'impact': impact_assessment.get('impact', 'unknown'),
                'explanation': impact_assessment.get('explanation', 'No explanation provided'),
                'remediation': impact_assessment.get('remediation', 'No remediation provided'),
                'provider': llm.provider_name,
                'model': llm.model_name
            }

            enhanced_findings.append(finding)
        except Exception as e:
            print(f"Error enhancing SCA finding with LLM: {e}")
            # Keep the original finding if enhancement fails
            enhanced_findings.append(finding)

    # Update the findings in the result
    sca_result['findings'] = enhanced_findings
    sca_result['llm_enhanced'] = True

    return sca_result


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
