"""
AgentPimentBleu - Scan Jobs

This module provides functionality for managing asynchronous scan jobs.
It includes functions to create, update, and retrieve scan jobs, as well as
an in-memory dictionary to store the scan state.
"""

import uuid
from typing import Dict, Any, Optional, List
from agentpimentbleu.api.models.scan_models import (
    ScanProgressResponse, ErrorContext, ErrorCodeEnum,
    InitialAuditResponse, RawVulnerabilityFromAudit,
    VulnerabilityDetail, ProcessedVulnerabilitiesResponse,
    ScanReportOutput, SCAResultForReport
)
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

# In-memory store for scan jobs. Replace with Redis/DB for production.
scan_jobs: Dict[uuid.UUID, Dict[str, Any]] = {}

# --- Helper functions to update and retrieve job state ---
def create_scan_job(scan_id: uuid.UUID, repo_source: str):
    """
    Create a new scan job with the given ID and repository source.
    
    Args:
        scan_id: The unique identifier for the scan job
        repo_source: The URL or local path to the repository
    """
    logger.info(f"Creating scan job {scan_id} for {repo_source}")
    scan_jobs[scan_id] = {
        "repo_source": repo_source,
        "status": "PENDING_PREPARATION",
        "current_step_description": "Scan job created and queued.",
        "audit_vulnerabilities_found": None,
        "llm_processed_vulnerabilities": 0,
        "initial_audit_results": None,  # Will be InitialAuditResponse model compatible
        "processed_vulnerabilities": [],  # List of VulnerabilityDetail
        "final_report": None,  # Will be ScanReportOutput model compatible
        "error_context": None,
        "app_config_override": None,  # To store per-scan LLM keys/config
        "recursion_limit_override": None
    }

def update_scan_status(scan_id: uuid.UUID, status: str, description: Optional[str] = None):
    """
    Update the status of a scan job.
    
    Args:
        scan_id: The unique identifier for the scan job
        status: The new status of the scan job
        description: Optional description of the current step
    """
    if scan_id in scan_jobs:
        logger.info(f"Updating scan job {scan_id} status to {status}")
        scan_jobs[scan_id]["status"] = status
        if description:
            scan_jobs[scan_id]["current_step_description"] = description
    else:
        logger.warning(f"Attempted to update non-existent scan job {scan_id}")

def update_with_initial_audit(scan_id: uuid.UUID, manifest_path: Optional[str], raw_vulns: List[Dict]):
    """
    Update a scan job with initial audit results.
    
    Args:
        scan_id: The unique identifier for the scan job
        manifest_path: The path to the project manifest file
        raw_vulns: List of raw vulnerabilities from the audit tool
    """
    if scan_id in scan_jobs:
        logger.info(f"Updating scan job {scan_id} with initial audit results")
        # Adapt raw_vulns to List[RawVulnerabilityFromAudit]
        adapted_raw_vulns = [RawVulnerabilityFromAudit(**v) for v in raw_vulns]
        scan_jobs[scan_id]["initial_audit_results"] = InitialAuditResponse(
            scan_id=scan_id,
            project_manifest_path=manifest_path,
            audit_tool_vulnerabilities=adapted_raw_vulns
        )
        scan_jobs[scan_id]["audit_vulnerabilities_found"] = len(adapted_raw_vulns)
    else:
        logger.warning(f"Attempted to update non-existent scan job {scan_id} with initial audit")

def add_processed_vulnerability(scan_id: uuid.UUID, vuln_detail: Dict):
    """
    Add a processed vulnerability to a scan job.
    
    Args:
        scan_id: The unique identifier for the scan job
        vuln_detail: Dictionary containing vulnerability details
    """
    if scan_id in scan_jobs:
        logger.info(f"Adding processed vulnerability to scan job {scan_id}")
        scan_jobs[scan_id]["processed_vulnerabilities"].append(VulnerabilityDetail(**vuln_detail))
        scan_jobs[scan_id]["llm_processed_vulnerabilities"] = len(scan_jobs[scan_id]["processed_vulnerabilities"])
    else:
        logger.warning(f"Attempted to add vulnerability to non-existent scan job {scan_id}")

def set_final_report(scan_id: uuid.UUID, report_data: Dict):
    """
    Set the final report for a scan job.
    
    Args:
        scan_id: The unique identifier for the scan job
        report_data: Dictionary containing the final report data
    """
    if scan_id in scan_jobs:
        logger.info(f"Setting final report for scan job {scan_id}")
        # Adapt report_data to ScanReportOutput
        scan_jobs[scan_id]["final_report"] = ScanReportOutput(**report_data)
        scan_jobs[scan_id]["status"] = report_data.get("status", "COMPLETED")  # Ensure status is also updated
    else:
        logger.warning(f"Attempted to set final report for non-existent scan job {scan_id}")

def set_scan_error(scan_id: uuid.UUID, error_code: ErrorCodeEnum, error_message: str):
    """
    Set an error for a scan job.
    
    Args:
        scan_id: The unique identifier for the scan job
        error_code: The error code
        error_message: The error message
    """
    if scan_id in scan_jobs:
        logger.info(f"Setting error for scan job {scan_id}: {error_code} - {error_message}")
        scan_jobs[scan_id]["error_context"] = ErrorContext(error_code=error_code, error_message=error_message)
        scan_jobs[scan_id]["status"] = "FAILED"
        # Also update the final_report if it's being compiled progressively
        if scan_jobs[scan_id].get("final_report"):
            scan_jobs[scan_id]["final_report"].error_context = scan_jobs[scan_id]["error_context"]
            scan_jobs[scan_id]["final_report"].status = "FAILED_SCAN"
        else:  # Create a minimal error report
            scan_jobs[scan_id]["final_report"] = ScanReportOutput(
                repo_source=scan_jobs[scan_id]["repo_source"],
                scan_id=scan_id,
                status="FAILED_SCAN",
                error_context=scan_jobs[scan_id]["error_context"]
            )
    else:
        logger.warning(f"Attempted to set error for non-existent scan job {scan_id}")

def get_scan_job(scan_id: uuid.UUID) -> Optional[Dict[str, Any]]:
    """
    Get a scan job by ID.
    
    Args:
        scan_id: The unique identifier for the scan job
        
    Returns:
        The scan job dictionary or None if not found
    """
    if scan_id in scan_jobs:
        return scan_jobs[scan_id]
    logger.warning(f"Attempted to get non-existent scan job {scan_id}")
    return None