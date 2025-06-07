"""
AgentPimentBleu - API Client

This module contains functions for interacting with the AgentPimentBleu API.
"""

import requests
import json
from typing import Dict, Optional
import logging

from agentpimentbleu.app.ui_settings import API_URL
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()

def scan_repository_api(
    repo_source: str, 
    gemini_api_key: Optional[str] = None, 
    recursion_limit: Optional[int] = None
) -> Dict:
    """
    Send a scan request to the API.

    Args:
        repo_source (str): URL or local path to the repository
        gemini_api_key (str, optional): Gemini API key to override the one in config
        recursion_limit (int, optional): Max recursion limit for the graph.

    Returns:
        Dict: The API response as a dictionary, or an error dictionary if the request fails
    """
    logger.info(f"Sending scan request to API for repository: {repo_source}")
    
    try:
        # Prepare the payload
        payload = {"repo_source": repo_source}

        # Add Gemini API key to payload if provided
        if gemini_api_key and gemini_api_key.strip():
            payload["gemini_api_key"] = gemini_api_key.strip()
            logger.info("Using Gemini API key from UI")

        # Add recursion limit to payload if provided
        if recursion_limit is not None:
            payload["recursion_limit"] = int(recursion_limit)  # Ensure it's an int
            logger.info(f"Using recursion limit from UI: {recursion_limit}")

        # Make the API request
        response = requests.post(f"{API_URL}/scan/", json=payload)

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