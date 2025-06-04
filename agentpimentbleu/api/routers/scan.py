"""
AgentPimentBleu - Scan Router

This module defines the API endpoints for initiating scans.
"""

import uuid
from fastapi import APIRouter, HTTPException

from agentpimentbleu.api.models.scan_models import ScanRequest, ScanOutput, SCAResult
from agentpimentbleu.core.graphs.sca_impact_graph import run_sca_scan
from agentpimentbleu.config.config import get_settings
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

router = APIRouter()


@router.post("/", response_model=ScanOutput)
async def scan_repository(scan_request: ScanRequest) -> ScanOutput:
    """
    Scan a repository for vulnerabilities.

    Args:
        scan_request (ScanRequest): The scan request

    Returns:
        ScanOutput: The scan output
    """
    logger.info(f"Received scan request for {scan_request.repo_source}")

    # Generate a unique scan ID
    scan_id = str(uuid.uuid4())

    try:
        # Get the application configuration
        app_config = get_settings()

        # Run the SCA scan
        scan_result = run_sca_scan(scan_request.repo_source, app_config)

        # Check if there was an error
        if scan_result.get("error_message"):
            logger.error(f"Scan failed: {scan_result['error_message']}")
            return ScanOutput(
                repo_source=scan_request.repo_source,
                scan_id=scan_id,
                status="failed",
                error_message=scan_result["error_message"]
            )

        # Convert the scan result to the API model
        # First try to get the processed vulnerabilities, then fall back to the raw audit tool vulnerabilities
        vulnerabilities = scan_result.get("vulnerabilities", [])

        # If no processed vulnerabilities, use the raw audit tool vulnerabilities
        if not vulnerabilities and scan_result.get("audit_tool_vulnerabilities"):
            raw_vulnerabilities = scan_result.get("audit_tool_vulnerabilities", [])
            logger.info(f"Adapting {len(raw_vulnerabilities)} raw audit tool vulnerabilities")

            # Adapt raw vulnerabilities to match VulnerabilityDetail model
            adapted_vulnerabilities = []
            for vuln in raw_vulnerabilities:
                # Extract CVE ID (use the first one if multiple are available)
                cve_id = vuln.get('cve_ids', ['unknown'])[0] if vuln.get('cve_ids') else "unknown"

                # Create a VulnerabilityDetail-compatible dictionary
                # Ensure cve_link is a valid URL or None
                cve_link = vuln.get('advisory_link')
                if cve_link and not (cve_link.startswith('http://') or cve_link.startswith('https://')):
                    cve_link = None

                adapted_vuln = {
                    "cve_id": cve_id,
                    "cve_link": cve_link,
                    "cve_description": vuln.get('advisory_title', 'No description available'),
                    "package_name": vuln.get('package_name', 'unknown'),
                    "vulnerable_version_range": f"<= {vuln.get('vulnerable_version', 'unknown')}",
                    "analyzed_project_version": vuln.get('vulnerable_version', 'unknown'),
                    "impact_in_project_summary": "Vulnerability detected by audit tool, impact not analyzed",
                    "evidence": ["Detected by dependency audit tool"],
                    "danger_rating": vuln.get('severity', 'Medium'),
                    "proposed_fix_summary": vuln.get('fix_suggestion_from_tool', 'Update to the latest version'),
                    "detailed_fix_guidance": "See package documentation for update instructions"
                }

                adapted_vulnerabilities.append(adapted_vuln)

            vulnerabilities = adapted_vulnerabilities

        # Create the SCA result
        sca_result = SCAResult(
            dependency_file_found=scan_result.get("project_manifest_path"),
            vulnerabilities=vulnerabilities,
            issues_summary=f"Found {len(vulnerabilities)} vulnerabilities"
        )

        # Create the scan output
        scan_output = ScanOutput(
            repo_source=scan_request.repo_source,
            scan_id=scan_id,
            status="completed",
            sca_results=sca_result,
            overall_summary=f"Scan completed successfully. Found {len(vulnerabilities)} vulnerabilities."
        )

        logger.info(f"Scan completed for {scan_request.repo_source}")
        return scan_output

    except Exception as e:
        logger.error(f"Error during scan: {e}")
        raise HTTPException(status_code=500, detail=f"Error during scan: {e}")
