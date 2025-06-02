import os
import tempfile
import shutil
import importlib

from agent_piment_bleu.utils.git_utils import clone_repository
from agent_piment_bleu.project_detector import detect_project_languages
from agent_piment_bleu.reporting import generate_markdown_report

def analyze_repository(repo_url):
    """
    Main function to analyze a Git repository for security vulnerabilities.
    
    Args:
        repo_url (str): URL of the Git repository to analyze
        
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
        
        # Run appropriate scanners for each detected language
        for language in languages:
            # Run SAST scanners
            sast_result = run_sast_scan(language, temp_dir)
            if sast_result:
                scan_results.append(sast_result)
            
            # Run SCA scanners
            sca_result = run_sca_scan(language, temp_dir)
            if sca_result:
                scan_results.append(sca_result)
        
        # Aggregate results
        aggregated_results = {
            'repo_url': repo_url,
            'languages': languages,
            'scan_results': scan_results
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