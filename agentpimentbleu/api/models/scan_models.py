"""
AgentPimentBleu - API Models

This module defines Pydantic models for API requests and responses.
"""

from typing import List, Optional
from pydantic import BaseModel, HttpUrl


class ScanRequest(BaseModel):
    """
    Request model for initiating a scan.
    """
    repo_source: str  # URL or local path to the repository
    gemini_api_key: Optional[str] = None  # Optional Gemini API key to override the one in config


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
    evidence: List[str] = []
    danger_rating: str  # Critical, High, Medium, Low, Informational
    proposed_fix_summary: str
    detailed_fix_guidance: Optional[str] = None


class SCAResult(BaseModel):
    """
    Model for SCA scan results.
    """
    dependency_file_found: Optional[str] = None
    vulnerabilities: List[VulnerabilityDetail] = []
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
