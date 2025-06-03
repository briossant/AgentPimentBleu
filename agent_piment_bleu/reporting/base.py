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
    report = ""

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

    # Skip failed scans reporting as per requirement
    logger.info("Skipping failed scans reporting as per requirement")

    # Process scan results in a side-by-side layout
    report += "\n\n<div style='display: flex; flex-direction: row; gap: 20px;'>\n"

    # Process Code analysis findings (left side)
    report += "<div style='flex: 1; border: 1px solid #ccc; padding: 10px;'>\n"
    report += "<h3>Code Analysis</h3>\n"

    # Add subbox for command result
    report += "<div style='border: 1px solid #eee; padding: 10px; margin-bottom: 10px;'>\n"
    report += "<h4>Command Result</h4>\n"
    sast_findings = [r for r in scan_results if r['scan_type'] == 'SAST' and r['success']]
    logger.info(f"Processing {len(sast_findings)} successful Code analysis scans")
    for result in sast_findings:
        language = result['language']
        findings_count = len(result.get('findings', []))
        logger.info(f"Generating Code analysis command result for {language} with {findings_count} findings")
        report += f"<p>Found {findings_count} issues in {language} code.</p>\n"
    report += "</div>\n"

    # Add subbox for agent analysis
    report += "<div style='border: 1px solid #eee; padding: 10px; margin-bottom: 10px;'>\n"
    report += "<h4>Agent Analysis</h4>\n"
    for result in sast_findings:
        language = result['language']
        findings_count = len(result.get('findings', []))
        logger.info(f"Generating Code analysis report for {language} with {findings_count} findings")
        if language in language_reporters:
            report += language_reporters[language].generate_sast_report(result)
        else:
            # Fallback to default reporting if no language-specific reporter is available
            logger.warning(f"No reporter found for {language}, using default reporter")
            from agent_piment_bleu.reporting.default import Reporter
            report += Reporter().generate_sast_report(result)
    report += "</div>\n"
    report += "</div>\n"

    # Process Dependency analysis findings (right side)
    report += "<div style='flex: 1; border: 1px solid #ccc; padding: 10px;'>\n"
    report += "<h3>Dependency Analysis</h3>\n"

    # Add subbox for command result
    report += "<div style='border: 1px solid #eee; padding: 10px; margin-bottom: 10px;'>\n"
    report += "<h4>Command Result</h4>\n"
    sca_findings = [r for r in scan_results if r['scan_type'] == 'SCA' and r['success']]
    logger.info(f"Processing {len(sca_findings)} successful Dependency analysis scans")
    for result in sca_findings:
        language = result['language']
        findings_count = len(result.get('findings', []))
        logger.info(f"Generating Dependency analysis command result for {language} with {findings_count} findings")
        report += f"<p>Found {findings_count} vulnerabilities in {language} dependencies.</p>\n"
    report += "</div>\n"

    # Add subbox for agent analysis
    report += "<div style='border: 1px solid #eee; padding: 10px; margin-bottom: 10px;'>\n"
    report += "<h4>Agent Analysis</h4>\n"
    for result in sca_findings:
        language = result['language']
        findings_count = len(result.get('findings', []))
        logger.info(f"Generating Dependency analysis report for {language} with {findings_count} findings")
        if language in language_reporters:
            report += language_reporters[language].generate_sca_report(result)
        else:
            # Fallback to default reporting if no language-specific reporter is available
            logger.warning(f"No reporter found for {language}, using default reporter")
            from agent_piment_bleu.reporting.default import Reporter
            report += Reporter().generate_sca_report(result)
    report += "</div>\n"
    report += "</div>\n"

    report += "</div>"

    # AI-powered features section removed as requested

    logger.info("Report generation completed successfully")
    return report
