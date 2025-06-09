"""
AgentPimentBleu - Scan Router

This module defines the API endpoints for initiating and monitoring scans.
"""

import uuid
from fastapi import APIRouter, HTTPException, BackgroundTasks, Path as FastAPIPath
from typing import Optional

from agentpimentbleu.api.models.scan_models import (
    ScanRequest, ScanInitiatedResponse, ScanProgressResponse,
    InitialAuditResponse, ProcessedVulnerabilitiesResponse, ScanReportOutput,
    ErrorContext, ErrorCodeEnum, VulnerabilityDetail, RawVulnerabilityFromAudit,
    # Legacy models for backward compatibility
    ScanOutput, SCAResult
)
from agentpimentbleu.core.graphs.sca_impact_graph import execute_full_scan_logic, run_sca_scan
from agentpimentbleu.config.config import get_settings
from agentpimentbleu.utils.logger import get_logger
from agentpimentbleu.api import scan_jobs as job_manager

logger = get_logger()

router = APIRouter()

# Define severity order (most severe to least severe) - used for legacy endpoint
SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
    "Unknown": 5  # Handle unknown or unassigned severity
}

def get_severity_sort_key(vulnerability_dict: dict):
    """Helper function to get the sort key for a vulnerability."""
    severity = vulnerability_dict.get('danger_rating', 'Unknown')
    return SEVERITY_ORDER.get(severity, SEVERITY_ORDER["Unknown"])

# --- Helper to get job or raise 404 ---
def get_job_or_404(scan_id: uuid.UUID):
    """
    Get a scan job by ID or raise a 404 error if not found.

    Args:
        scan_id: The unique identifier for the scan job

    Returns:
        The scan job dictionary

    Raises:
        HTTPException: If the scan job is not found
    """
    job = job_manager.get_scan_job(scan_id)
    if not job:
        raise HTTPException(
            status_code=404,
            detail=ErrorContext(error_code=ErrorCodeEnum.SCAN_NOT_FOUND, error_message="Scan ID not found").model_dump()
        )
    return job

@router.post("/", response_model=ScanInitiatedResponse, status_code=202)
async def initiate_new_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Initiate a new scan for a repository.

    Args:
        scan_request (ScanRequest): The scan request
        background_tasks (BackgroundTasks): FastAPI background tasks

    Returns:
        ScanInitiatedResponse: The scan initiation response
    """
    logger.info(f"Received scan request for {scan_request.repo_source}")

    # Generate a unique scan ID
    scan_id = uuid.uuid4()

    # Create a job for tracking
    job_manager.create_scan_job(scan_id, scan_request.repo_source)

    # Store API key overrides and recursion limit if provided
    app_config_overrides = {}
    if scan_request.gemini_api_key:
        app_config_overrides['gemini_api_key'] = scan_request.gemini_api_key
    if scan_request.mistral_api_key:
        app_config_overrides['mistral_api_key'] = scan_request.mistral_api_key

    if app_config_overrides:  # Only store if there are actual overrides
        job_manager.scan_jobs[scan_id]['app_config_override'] = app_config_overrides
    if scan_request.recursion_limit is not None:
        job_manager.scan_jobs[scan_id]['recursion_limit_override'] = scan_request.recursion_limit

    logger.info(f"[{scan_id}] Initiating scan for {scan_request.repo_source}")
    background_tasks.add_task(
        execute_full_scan_logic,
        scan_id,
        scan_request.repo_source,
        job_manager.scan_jobs[scan_id]['app_config_override'],  # Pass the overrides
        job_manager.scan_jobs[scan_id]['recursion_limit_override']
    )

    return ScanInitiatedResponse(scan_id=scan_id, status="INITIATED")


@router.get("/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress_endpoint(scan_id: uuid.UUID = FastAPIPath(..., description="The unique identifier of the scan.")):
    """
    Get the progress of a scan.

    Args:
        scan_id (uuid.UUID): The unique identifier of the scan

    Returns:
        ScanProgressResponse: The scan progress
    """
    job = get_job_or_404(scan_id)
    return ScanProgressResponse(
        scan_id=scan_id,
        overall_status=job.get("status", "UNKNOWN"),
        current_step_description=job.get("current_step_description"),
        audit_vulnerabilities_found=job.get("audit_vulnerabilities_found"),
        llm_processed_vulnerabilities=job.get("llm_processed_vulnerabilities"),
        error_context=ErrorContext(**job["error_context"]) if job.get("error_context") else None
    )


@router.get("/{scan_id}/initial-audit", response_model=InitialAuditResponse)
async def get_initial_audit_results_endpoint(scan_id: uuid.UUID = FastAPIPath(..., description="The unique identifier of the scan.")):
    """
    Get the initial audit results of a scan.

    Args:
        scan_id (uuid.UUID): The unique identifier of the scan

    Returns:
        InitialAuditResponse: The initial audit results
    """
    job = get_job_or_404(scan_id)
    initial_audit_data = job.get("initial_audit_results")
    if not initial_audit_data:  # Could be InitialAuditResponse model or None
        raise HTTPException(
            status_code=404,  # Or 204 if preferred for "not yet available"
            detail=ErrorContext(error_code=ErrorCodeEnum.RESULTS_NOT_YET_AVAILABLE, error_message="Initial audit results not yet available.").model_dump()
        )
    # initial_audit_data should already be an InitialAuditResponse model instance or dict convertible to it
    if isinstance(initial_audit_data, dict):
        return InitialAuditResponse(**initial_audit_data)
    return initial_audit_data


@router.get("/{scan_id}/processed-vulnerabilities", response_model=ProcessedVulnerabilitiesResponse)
async def get_processed_vulnerabilities_endpoint(scan_id: uuid.UUID = FastAPIPath(..., description="The unique identifier of the scan.")):
    """
    Get the processed vulnerabilities of a scan.

    Args:
        scan_id (uuid.UUID): The unique identifier of the scan

    Returns:
        ProcessedVulnerabilitiesResponse: The processed vulnerabilities
    """
    job = get_job_or_404(scan_id)
    processed_vulns_data = job.get("processed_vulnerabilities", [])  # Should be list of VulnerabilityDetail

    # Data should already be List[VulnerabilityDetail] if add_processed_vulnerability stores them as such
    return ProcessedVulnerabilitiesResponse(
        scan_id=scan_id,
        vulnerabilities=processed_vulns_data
    )


@router.get("/{scan_id}/report", response_model=ScanReportOutput)
async def get_scan_report_endpoint(scan_id: uuid.UUID = FastAPIPath(..., description="The unique identifier of the scan.")):
    """
    Get the final report of a scan.

    Args:
        scan_id (uuid.UUID): The unique identifier of the scan

    Returns:
        ScanReportOutput: The scan report
    """
    job = get_job_or_404(scan_id)
    final_report_data = job.get("final_report")  # Should be ScanReportOutput model or dict convertible

    if not final_report_data:
        # If still in progress, return a report with "IN_PROGRESS" status
        return ScanReportOutput(
            repo_source=job["repo_source"],
            scan_id=scan_id,
            status="IN_PROGRESS",
            overall_summary="Scan is currently in progress. Check /progress for status.",
            error_context=ErrorContext(**job["error_context"]) if job.get("error_context") else None
        )
    if isinstance(final_report_data, dict):
        return ScanReportOutput(**final_report_data)
    return final_report_data


# Legacy endpoint for backward compatibility
@router.post("/legacy", response_model=ScanOutput, tags=["Legacy"])
async def scan_repository_legacy(scan_request: ScanRequest) -> ScanOutput:
    """
    Scan a repository for vulnerabilities (legacy synchronous endpoint).

    This endpoint is maintained for backward compatibility. New clients should use the asynchronous API.

    Args:
        scan_request (ScanRequest): The scan request

    Returns:
        ScanOutput: The scan output
    """
    logger.info(f"Received legacy scan request for {scan_request.repo_source}")

    # Generate a unique scan ID
    scan_id = str(uuid.uuid4())

    try:
        # Get the application configuration
        app_config = get_settings()

        # Check if API keys are provided in the request
        if scan_request.gemini_api_key or scan_request.mistral_api_key:
            # Create a copy of the app_config to avoid modifying the global config
            from copy import deepcopy
            modified_config = deepcopy(app_config)

            # Initialize llm_providers if it doesn't exist
            if 'llm_providers' not in modified_config._config:
                modified_config._config['llm_providers'] = {}

            # Update the Gemini API key and model in the config if provided
            if scan_request.gemini_api_key:
                if 'gemini' not in modified_config._config['llm_providers']:
                    modified_config._config['llm_providers']['gemini'] = {}
                modified_config._config['llm_providers']['gemini']['api_key'] = scan_request.gemini_api_key
                modified_config._config['llm_providers']['gemini']['model'] = 'gemini-2.5-flash-preview-05-20'
                # Set active LLM provider to Gemini
                modified_config._config['active_llm_provider'] = 'gemini'
                logger.info("Using Gemini API key from request with model gemini-2.5-flash-preview-05-20")

            # Update the Mistral API key and model in the config if provided
            if scan_request.mistral_api_key:
                if 'mistral' not in modified_config._config['llm_providers']:
                    modified_config._config['llm_providers']['mistral'] = {}
                modified_config._config['llm_providers']['mistral']['api_key'] = scan_request.mistral_api_key
                modified_config._config['llm_providers']['mistral']['model'] = 'devstral-small-2505'
                # Set active LLM provider to Mistral
                modified_config._config['active_llm_provider'] = 'mistral'
                logger.info("Using Mistral API key from request with model devstral-small-2505")

            # Run the SCA scan with the modified config
            scan_result = run_sca_scan(scan_request.repo_source, modified_config, recursion_limit=scan_request.recursion_limit)
        else:
            # Run the SCA scan with the original config
            scan_result = run_sca_scan(scan_request.repo_source, app_config, recursion_limit=scan_request.recursion_limit)

        # Check if there was an error
        if scan_result.get("error_message"):
            error_detail = scan_result["error_message"]

            # Enhanced Error Handling for API Response
            if error_detail.startswith("LLM_PROVIDER_FAILURE:"):
                logger.error(f"Scan for {scan_request.repo_source} failed due to critical LLM provider issue: {error_detail}")
                return ScanOutput(
                    repo_source=scan_request.repo_source,
                    scan_id=scan_id,
                    status="failed",
                    sca_results=SCAResult( # Can still return any vulns found *before* the LLM failure
                        dependency_file_found=scan_result.get("project_manifest_path"),
                        vulnerabilities=[VulnerabilityDetail(**v) for v in scan_result.get("final_vulnerabilities", [])],
                        issues_summary=(
                            f"Scan failed due to LLM provider error. "
                            f"Found {len(scan_result.get('final_vulnerabilities', []))} vulnerabilities before failure."
                        )
                    ) if scan_result.get("final_vulnerabilities") else None,
                    error_message=error_detail, # Pass the detailed LLM failure message
                    overall_summary=f"Scan failed: Critical LLM provider error. Please check your API key or the provider's status. Details: {error_detail.split(': ', 1)[1] if ': ' in error_detail else error_detail}"
                )
            else:
                # General error from the scan
                logger.error(f"Scan for {scan_request.repo_source} failed or completed with errors: {error_detail}")
                return ScanOutput(
                    repo_source=scan_request.repo_source,
                    scan_id=scan_id,
                    status="failed",
                    sca_results=SCAResult(
                        dependency_file_found=scan_result.get("project_manifest_path"),
                        vulnerabilities=[VulnerabilityDetail(**v) for v in scan_result.get("final_vulnerabilities", [])],
                        issues_summary=f"Scan encountered an error. Partial results might be shown. Found {len(scan_result.get('final_vulnerabilities', []))} vulnerabilities."
                    ) if scan_result.get("final_vulnerabilities") else None,
                    error_message=error_detail,
                    overall_summary=f"Scan for {scan_request.repo_source} encountered an error: {error_detail}. Check details."
                )

        # Convert the scan result to the API model
        # First try to get the processed vulnerabilities, then fall back to the raw audit tool vulnerabilities
        vulnerabilities_data = scan_result.get("final_vulnerabilities", [])  # Use final_vulnerabilities

        # If no processed vulnerabilities, use the raw audit tool vulnerabilities
        if not vulnerabilities_data and scan_result.get("audit_tool_vulnerabilities"):
            raw_vulnerabilities = scan_result.get("audit_tool_vulnerabilities", [])
            logger.info(f"Adapting {len(raw_vulnerabilities)} raw audit tool vulnerabilities as no processed ones were found.")

            # Adapt raw vulnerabilities to match VulnerabilityDetail model
            adapted_vulnerabilities = []
            for vuln in raw_vulnerabilities:
                # Extract CVE ID (use the first one if multiple are available)
                cve_id = vuln.get('cve_ids', ['unknown'])[0] if vuln.get('cve_ids') else "unknown"

                # Get primary advisory ID if available
                primary_advisory_id = vuln.get('primary_advisory_id')

                # Create a VulnerabilityDetail-compatible dictionary
                # Ensure cve_link is a valid URL or None
                cve_link = vuln.get('advisory_link')
                if cve_link and not (cve_link.startswith('http://') or cve_link.startswith('https://')):
                    cve_link = None

                adapted_vuln = {
                    "cve_id": cve_id,
                    "primary_advisory_id": primary_advisory_id,
                    "cve_link": cve_link,
                    "cve_description": vuln.get('advisory_title', 'No description available'),
                    "package_name": vuln.get('package_name', 'unknown'),
                    "vulnerable_version_range": vuln.get('advisory_vulnerable_range', f"<= {vuln.get('vulnerable_version', 'unknown')}"),
                    "analyzed_project_version": vuln.get('installed_version', 'unknown'),
                    "impact_in_project_summary": "Vulnerability detected by audit tool, impact not analyzed by LLM.",
                    "evidence": ["Detected by dependency audit tool"],
                    "danger_rating": vuln.get('severity', 'Medium').capitalize(),  # Capitalize to match SEVERITY_ORDER
                    "proposed_fix_summary": vuln.get('fix_suggestion_from_tool', 'Update to the latest version'),
                    "detailed_fix_guidance": "See package documentation for update instructions"
                }

                adapted_vulnerabilities.append(adapted_vuln)

            vulnerabilities_data = adapted_vulnerabilities

        # Sort vulnerabilities by severity
        # Ensure vulnerabilities_data is a list of dictionaries, not Pydantic models yet for sort
        if isinstance(vulnerabilities_data, list) and all(isinstance(v, dict) for v in vulnerabilities_data):
            vulnerabilities_data.sort(key=get_severity_sort_key)
            logger.info(f"Sorted {len(vulnerabilities_data)} vulnerabilities by severity.")
        else:
            logger.warning("Vulnerabilities data is not in the expected list-of-dicts format for sorting.")

        # Create the SCA result (after sorting)
        sca_result = SCAResult(
            dependency_file_found=scan_result.get("project_manifest_path"),
            vulnerabilities=[VulnerabilityDetail(**v) for v in vulnerabilities_data],  # Convert dicts to Pydantic models
            issues_summary=f"Found {len(vulnerabilities_data)} vulnerabilities"
        )

        # Create the scan output
        scan_output = ScanOutput(
            repo_source=scan_request.repo_source,
            scan_id=scan_id,
            status="completed",
            sca_results=sca_result,
            overall_summary=f"Scan completed successfully. Found {len(vulnerabilities_data)} vulnerabilities."
        )

        logger.info(f"Scan completed for {scan_request.repo_source}")
        return scan_output

    except Exception as e:
        error_message = str(e)
        logger.error(f"Error during scan: {error_message}")  # Log the error

        # Check if this is an LLM provider failure
        if error_message.startswith("LLM_PROVIDER_FAILURE:"):
            # Return a structured response for LLM provider failures
            return ScanOutput(
                repo_source=scan_request.repo_source,
                scan_id=scan_id,
                status="failed",
                sca_results=None,  # No results since the scan was terminated
                error_message=error_message,
                overall_summary=f"Scan failed: Critical LLM provider error. Please check your API key or the provider's status. Details: {error_message.split(': ', 1)[1] if ': ' in error_message else error_message}"
            )
        else:
            # For other errors, raise an HTTP exception
            raise HTTPException(status_code=500, detail=f"Error during scan: {error_message}")
