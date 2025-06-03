"""
Base Reporter Module

This module defines the base reporter class that all language-specific reporters should inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
from agent_piment_bleu.logger import get_logger


class BaseReporter(ABC):
    """
    Abstract base class for report generators.

    This class defines the interface that all report generators must implement.
    """

    @abstractmethod
    def __init__(self, **kwargs):
        """
        Initialize the reporter with configuration options.

        Args:
            **kwargs: Reporter-specific configuration options
        """
        pass

    @abstractmethod
    def generate_failed_scan_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for a failed scan.

        Args:
            result (Dict[str, Any]): The failed scan result

        Returns:
            str: The report section for the failed scan
        """
        pass

    @abstractmethod
    def generate_sast_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for SAST findings.

        Args:
            result (Dict[str, Any]): The SAST scan result

        Returns:
            str: The report section for the SAST findings
        """
        pass

    @abstractmethod
    def generate_sca_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a report section for SCA findings.

        Args:
            result (Dict[str, Any]): The SCA scan result

        Returns:
            str: The report section for the SCA findings
        """
        pass


def generate_markdown_report(aggregated_results: Dict[str, Any]) -> str:
    """
    Generate a Markdown report from the aggregated scan results.

    Args:
        aggregated_results (dict): Aggregated results from all scanners with keys:
            - repo_url (str): URL of the scanned repository
            - languages (list): List of detected languages
            - scan_results (list): List of results from individual scanners

    Returns:
        str: Markdown formatted report
    """
    logger = get_logger()
    logger.info("Starting report generation")

    repo_url = aggregated_results.get('repo_url', 'Unknown repository')
    languages = aggregated_results.get('languages', [])
    scan_results = aggregated_results.get('scan_results', [])

    logger.info(f"Generating report for repository: {repo_url}")
    logger.info(f"Languages: {', '.join(languages) if languages else 'None detected'}")
    logger.info(f"Number of scan results: {len(scan_results)}")

    # Start building the report
    report = f"""
    ## Scan Results

    Repository: {repo_url}

    ### Summary

    The repository was successfully scanned for security issues.

    Detected languages: {', '.join(languages) if languages else 'None detected'}
    """

    # Add scan status for each scanner
    report += "\n\nScan Status:\n"
    for result in scan_results:
        report += f"- {result['language'].capitalize()} {result['scan_type']}: {result['message']}\n"

    # Import language-specific reporters
    logger.info("Importing language-specific reporters")
    language_reporters = {}
    for language in languages:
        try:
            # Dynamically import the language-specific reporter
            module_name = f"agent_piment_bleu.reporting.{language}"
            logger.info(f"Importing reporter for {language} from {module_name}")
            module = __import__(module_name, fromlist=['Reporter'])
            language_reporters[language] = module.Reporter()
            logger.info(f"Successfully imported reporter for {language}")
        except (ImportError, AttributeError) as e:
            # If language-specific reporter is not available, use a default reporter
            logger.warning(f"Failed to import reporter for {language}: {str(e)}")
            logger.info("Using default reporter instead")
            from agent_piment_bleu.reporting.default import Reporter
            language_reporters[language] = Reporter()

    # Report failed scans
    failed_scans = [r for r in scan_results if not r['success']]
    if failed_scans:
        logger.info(f"Processing {len(failed_scans)} failed scans")
        report += "\n\n### Failed Scans\n\n"
        for result in failed_scans:
            language = result['language']
            logger.info(f"Generating failed scan report for {language} {result['scan_type']}")
            if language in language_reporters:
                report += language_reporters[language].generate_failed_scan_report(result)
            else:
                # Fallback to default reporting if no language-specific reporter is available
                logger.warning(f"No reporter found for {language}, using default reporter")
                from agent_piment_bleu.reporting.default import Reporter
                report += Reporter().generate_failed_scan_report(result)
    else:
        logger.info("No failed scans to report")

    # Process SAST findings
    sast_findings = [r for r in scan_results if r['scan_type'] == 'SAST' and r['success']]
    logger.info(f"Processing {len(sast_findings)} successful SAST scans")
    for result in sast_findings:
        language = result['language']
        findings_count = len(result.get('findings', []))
        logger.info(f"Generating SAST report for {language} with {findings_count} findings")
        if language in language_reporters:
            report += language_reporters[language].generate_sast_report(result)
        else:
            # Fallback to default reporting if no language-specific reporter is available
            logger.warning(f"No reporter found for {language}, using default reporter")
            from agent_piment_bleu.reporting.default import Reporter
            report += Reporter().generate_sast_report(result)

    # Process SCA findings
    sca_findings = [r for r in scan_results if r['scan_type'] == 'SCA' and r['success']]
    logger.info(f"Processing {len(sca_findings)} successful SCA scans")
    for result in sca_findings:
        language = result['language']
        findings_count = len(result.get('findings', []))
        logger.info(f"Generating SCA report for {language} with {findings_count} findings")
        if language in language_reporters:
            report += language_reporters[language].generate_sca_report(result)
        else:
            # Fallback to default reporting if no language-specific reporter is available
            logger.warning(f"No reporter found for {language}, using default reporter")
            from agent_piment_bleu.reporting.default import Reporter
            report += Reporter().generate_sca_report(result)

    # Add note about AI-powered features
    logger.info("Adding AI-powered features section to report")
    report += "\n\n### AI-Powered Features\n\n"

    if aggregated_results.get('llm_enhanced', False):
        logger.info("LLM enhancement was enabled for this scan")
        report += "This report includes the following AI-powered features:\n"
        report += "- Human-readable descriptions of CVEs\n"
        report += "\nFuture enhancements will include:\n"
        report += "- AI-powered impact assessments for vulnerabilities\n"
        report += "- More detailed analysis of code and dependencies\n"
    else:
        logger.info("LLM enhancement was not enabled for this scan")
        report += "AI enhancement was not enabled for this scan.\n"
        report += "Enable AI enhancement to get:\n"
        report += "- Human-readable descriptions of CVEs\n"
        report += "- AI-powered impact assessments for vulnerabilities\n"
        report += "- More detailed analysis of code and dependencies\n"

    logger.info("Report generation completed successfully")
    return report
