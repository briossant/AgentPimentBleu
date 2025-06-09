"""
AgentPimentBleu - API Client

This module contains functions for interacting with the AgentPimentBleu API.
"""

import requests
import json
import time  # For polling
from typing import Dict, Optional, Tuple, Generator

from agentpimentbleu.app.ui_settings import API_URL
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

# Define polling parameters
POLL_INTERVAL = 5  # seconds
MAX_POLLS = 120  # Max 10 minutes (120 * 5s)


def initiate_scan_api(
    repo_source: str,
    gemini_api_key: Optional[str] = None,
    mistral_api_key: Optional[str] = None,
    recursion_limit: Optional[int] = None
) -> Tuple[Optional[str], Optional[Dict]]:
    """
    Initiate a scan and return the scan_id.

    Args:
        repo_source (str): URL or local path to the repository
        gemini_api_key (str, optional): Gemini API key to override the one in config
        mistral_api_key (str, optional): Mistral API key to override the one in config
        recursion_limit (int, optional): Max recursion limit for the graph.

    Returns:
        Tuple[Optional[str], Optional[Dict]]: (scan_id, error_dict)
    """
    logger.info(f"Initiating scan via API for repository: {repo_source}")
    payload = {"repo_source": repo_source}
    if gemini_api_key and gemini_api_key.strip():
        payload["gemini_api_key"] = gemini_api_key.strip()
        logger.info("Using Gemini API key from UI")
    if mistral_api_key and mistral_api_key.strip():
        payload["mistral_api_key"] = mistral_api_key.strip()
        logger.info("Using Mistral API key from UI")
    if recursion_limit is not None:
        payload["recursion_limit"] = int(recursion_limit)  # Ensure it's an int
        logger.info(f"Using recursion limit from UI: {recursion_limit}")

    try:
        response = requests.post(f"{API_URL}/scans/", json=payload)
        if response.status_code == 202:  # Accepted
            data = response.json()
            logger.info(f"Scan initiated successfully. Scan ID: {data['scan_id']}")
            return data['scan_id'], None
        else:
            error_message = f"Error initiating scan: {response.status_code} - {response.text}"
            logger.error(error_message)
            try:
                error_data = response.json()
            except json.JSONDecodeError:
                error_data = {"error_code": "UNKNOWN_CLIENT_ERROR", "error_message": error_message}
            return None, error_data
    except requests.RequestException as e:
        error_message = f"Request error initiating scan: {e}"
        logger.error(error_message)
        return None, {"error_code": "CLIENT_REQUEST_FAILED", "error_message": error_message}


def poll_scan_status_api(scan_id: str) -> Generator[Dict, None, None]:
    """
    Polls the scan progress endpoint and yields status updates.
    This can be used by the UI to show live progress.

    Args:
        scan_id (str): The unique identifier of the scan

    Yields:
        Dict: The scan progress data
    """
    logger.info(f"[{scan_id}] Starting to poll scan status.")
    completed_statuses = ["COMPLETED", "FAILED", "ANALYSIS_DEPTH_LIMITED"]  # From ScanProgressResponse

    for _ in range(MAX_POLLS):
        try:
            response = requests.get(f"{API_URL}/scans/{scan_id}/progress")
            if response.status_code == 200:
                progress_data = response.json()
                logger.debug(f"[{scan_id}] Progress: {progress_data}")
                yield progress_data  # Yield the progress data for UI update

                if progress_data.get("overall_status") in completed_statuses:
                    logger.info(f"[{scan_id}] Polling complete. Final status: {progress_data.get('overall_status')}")
                    return  # Stop polling
            elif response.status_code == 404:
                logger.error(f"[{scan_id}] Scan ID not found during polling.")
                yield {"error_code": "SCAN_NOT_FOUND", "error_message": "Scan ID not found."}
                return
            else:
                logger.warning(f"[{scan_id}] Error polling status: {response.status_code} - {response.text}")
                # Optionally yield an error indication
                yield {"error_code": "POLLING_ERROR", "error_message": f"Error polling status: {response.status_code}"}

            time.sleep(POLL_INTERVAL)
        except requests.RequestException as e:
            logger.error(f"[{scan_id}] Request error during polling: {e}")
            yield {"error_code": "CLIENT_REQUEST_FAILED", "error_message": f"Polling error: {e}"}
            return  # Stop polling on request errors

    logger.warning(f"[{scan_id}] Max polls reached without completion.")
    yield {"error_code": "POLLING_TIMEOUT", "error_message": "Scan timed out."}


def get_initial_audit_api(scan_id: str) -> Optional[Dict]:
    """
    Retrieves the initial audit results.

    Args:
        scan_id (str): The unique identifier of the scan

    Returns:
        Optional[Dict]: The initial audit results or None if not available
    """
    logger.info(f"[{scan_id}] Fetching initial audit results.")
    try:
        response = requests.get(f"{API_URL}/scans/{scan_id}/initial-audit")
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.warning(f"[{scan_id}] Initial audit results not yet available.")
            return None
        else:
            logger.error(f"[{scan_id}] Error fetching initial audit: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:
        logger.error(f"[{scan_id}] Request error fetching initial audit: {e}")
        return None


def get_processed_vulnerabilities_api(scan_id: str) -> Optional[Dict]:
    """
    Retrieves the processed vulnerabilities.

    Args:
        scan_id (str): The unique identifier of the scan

    Returns:
        Optional[Dict]: The processed vulnerabilities or None if not available
    """
    logger.info(f"[{scan_id}] Fetching processed vulnerabilities.")
    try:
        response = requests.get(f"{API_URL}/scans/{scan_id}/processed-vulnerabilities")
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.warning(f"[{scan_id}] Processed vulnerabilities not yet available.")
            return None
        else:
            logger.error(f"[{scan_id}] Error fetching vulnerabilities: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:
        logger.error(f"[{scan_id}] Request error fetching vulnerabilities: {e}")
        return None


def get_scan_report_api(scan_id: str) -> Optional[Dict]:
    """
    Retrieves the final scan report.

    Args:
        scan_id (str): The unique identifier of the scan

    Returns:
        Optional[Dict]: The scan report or None if not available
    """
    logger.info(f"[{scan_id}] Fetching final scan report.")
    try:
        response = requests.get(f"{API_URL}/scans/{scan_id}/report")
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"[{scan_id}] Error fetching report: {response.status_code} - {response.text}")
            try:
                return response.json()  # API should return ErrorContext on failure
            except json.JSONDecodeError:
                return {"error_code": "CLIENT_ERROR", "error_message": f"Failed to fetch report: {response.status_code}"}
    except requests.RequestException as e:
        logger.error(f"[{scan_id}] Request error fetching report: {e}")
        return {"error_code": "CLIENT_REQUEST_FAILED", "error_message": f"Error fetching report: {e}"}


# Legacy function for backward compatibility
def scan_repository_api(
    repo_source: str, 
    gemini_api_key: Optional[str] = None, 
    mistral_api_key: Optional[str] = None,
    recursion_limit: Optional[int] = None
) -> Dict:
    """
    Send a scan request to the API (legacy synchronous version).

    Args:
        repo_source (str): URL or local path to the repository
        gemini_api_key (str, optional): Gemini API key to override the one in config
        mistral_api_key (str, optional): Mistral API key to override the one in config
        recursion_limit (int, optional): Max recursion limit for the graph.

    Returns:
        Dict: The API response as a dictionary, or an error dictionary if the request fails
    """
    logger.info(f"Sending legacy scan request to API for repository: {repo_source}")

    try:
        # Prepare the payload
        payload = {"repo_source": repo_source}

        # Add API keys and recursion limit if provided
        if gemini_api_key and gemini_api_key.strip():
            payload["gemini_api_key"] = gemini_api_key.strip()
        if mistral_api_key and mistral_api_key.strip():
            payload["mistral_api_key"] = mistral_api_key.strip()
        if recursion_limit is not None:
            payload["recursion_limit"] = int(recursion_limit)

        # Make the API request to the legacy endpoint
        response = requests.post(f"{API_URL}/scans/legacy", json=payload)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            result = response.json()
            logger.info("API response received successfully")
            return result
        else:
            error_message = f"Error: {response.status_code} - {response.text}"
            logger.error(error_message)
            return {
                "status": "failed",
                "error_message": error_message,
                "repo_source": repo_source
            }

    except Exception as e:
        error_message = f"Error scanning repository: {e}"
        logger.error(error_message)
        return {
            "status": "failed",
            "error_message": error_message,
            "repo_source": repo_source
        }
