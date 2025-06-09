"""
AgentPimentBleu - API Models

This module defines Pydantic models for API requests and responses.
"""

from typing import List, Optional, Literal
from pydantic import BaseModel, HttpUrl, Field
import uuid
from enum import Enum


class ScanRequest(BaseModel):
    """
    Request model for initiating a scan.
    """
    repo_source: str  # URL or local path to the repository
    gemini_api_key: Optional[str] = None  # Optional Gemini API key to override the one in config
    mistral_api_key: Optional[str] = None  # Optional Mistral API key to override the one in config
    recursion_limit: Optional[int] = None  # Optional recursion limit for the graph


class VulnerabilityDetail(BaseModel):
    """
    Model for a vulnerability detail.
    """
    cve_id: str
    primary_advisory_id: Optional[str] = None
    cve_link: Optional[HttpUrl] = None
    cve_description: str
    package_name: str
    vulnerable_version_range: str
    analyzed_project_version: str
    impact_in_project_summary: str
    evidence: List[str] = Field(default_factory=list)
    danger_rating: Literal["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
    proposed_fix_summary: str
    detailed_fix_guidance: Optional[str] = None


class ScanInitiatedResponse(BaseModel):
    """
    Response after successfully initiating a scan.
    """
    scan_id: uuid.UUID
    status: Literal["PENDING_PREPARATION", "INITIATED", "QUEUED"]  # Example initial statuses


class ErrorCodeEnum(str, Enum):
    """
    Enumeration of error codes.
    """
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"
    INVALID_REQUEST_PAYLOAD = "INVALID_REQUEST_PAYLOAD"
    INVALID_LLM_API_KEY = "INVALID_LLM_API_KEY"
    REPOSITORY_PREPARATION_FAILED = "REPOSITORY_PREPARATION_FAILED"
    UNKNOWN_PROJECT_TYPE = "UNKNOWN_PROJECT_TYPE"
    VULNERABILITY_AUDIT_TOOL_FAILED = "VULNERABILITY_AUDIT_TOOL_FAILED"
    RAG_INDEXING_FAILED = "RAG_INDEXING_FAILED"
    LLM_PROVIDER_COMMUNICATION_ERROR = "LLM_PROVIDER_COMMUNICATION_ERROR"
    ANALYSIS_DEPTH_LIMIT_REACHED = "ANALYSIS_DEPTH_LIMIT_REACHED"
    SCAN_NOT_FOUND = "SCAN_NOT_FOUND"
    RESULTS_NOT_YET_AVAILABLE = "RESULTS_NOT_YET_AVAILABLE"


class ErrorContext(BaseModel):
    """
    Provides details about an error that occurred.
    """
    error_code: ErrorCodeEnum
    error_message: str


class ScanProgressResponse(BaseModel):
    """
    Provides the current progress of a scan.
    """
    scan_id: uuid.UUID
    overall_status: Literal[
        "PENDING_PREPARATION",
        "PREPARING_ENVIRONMENT",
        "IDENTIFYING_PROJECT",
        "RUNNING_AUDIT",
        "BUILDING_RAG_INDEX",
        "PROCESSING_VULNERABILITIES",
        "COMPILING_REPORT",
        "CLEANING_UP",
        "COMPLETED",
        "FAILED",
        "ANALYSIS_DEPTH_LIMITED"
    ]
    current_step_description: Optional[str] = None
    audit_vulnerabilities_found: Optional[int] = None  # Made optional as it might not be known early
    llm_processed_vulnerabilities: Optional[int] = None  # Made optional
    error_context: Optional[ErrorContext] = None


class RawVulnerabilityFromAudit(BaseModel):
    """
    Represents a vulnerability as identified by an audit tool, before LLM processing.
    """
    package_name: str
    installed_version: str
    cve_ids: List[str] = Field(default_factory=list)
    primary_advisory_id: Optional[str] = None
    advisory_link: Optional[HttpUrl] = None
    advisory_title: Optional[str] = None
    severity_from_tool: Optional[str] = None
    fix_suggestion_from_tool: Optional[str] = None
    advisory_vulnerable_range: Optional[str] = None


class InitialAuditResponse(BaseModel):
    """
    Raw results from the dependency audit tool.
    """
    scan_id: uuid.UUID
    project_manifest_path: Optional[str] = None
    audit_tool_vulnerabilities: List[RawVulnerabilityFromAudit] = Field(default_factory=list)


class ProcessedVulnerabilitiesResponse(BaseModel):
    """
    Processed vulnerabilities from the LLM.
    """
    scan_id: uuid.UUID
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)


class SCAResultForReport(BaseModel):
    """
    Software Composition Analysis results for the final report.
    """
    dependency_file_found: Optional[str] = None
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)
    issues_summary: Optional[str] = None


class ScanReportOutput(BaseModel):
    """
    The final or current state of the scan report.
    """
    repo_source: str
    scan_id: uuid.UUID
    status: Literal["COMPLETED_SUCCESS", "COMPLETED_WITH_PARTIAL_RESULTS", "FAILED_SCAN", "IN_PROGRESS"]
    sca_results: Optional[SCAResultForReport] = None
    overall_summary: Optional[str] = None
    error_context: Optional[ErrorContext] = None


# Legacy models for backward compatibility
class SCAResult(BaseModel):
    """
    Model for SCA scan results.
    """
    dependency_file_found: Optional[str] = None
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)
    issues_summary: Optional[str] = None


class ScanOutput(BaseModel):
    """
    Model for scan output.
    """
    repo_source: str
    scan_id: str
    status: str  # completed, failed
    sca_results: Optional[SCAResult] = None
    overall_summary: Optional[str] = None
    error_message: Optional[str] = None
