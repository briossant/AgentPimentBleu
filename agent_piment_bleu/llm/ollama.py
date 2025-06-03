"""
Ollama LLM Provider

This module implements the LLM provider interface for Ollama.
"""

import json
import requests
from typing import Dict, List, Any, Optional

from agent_piment_bleu.llm.base import LLMProvider
from agent_piment_bleu.llm.config import get_provider_config


class OllamaProvider(LLMProvider):
    """
    LLM provider implementation for Ollama.
    """

    def __init__(self, **kwargs):
        """
        Initialize the Ollama provider.

        Args:
            **kwargs: Provider-specific configuration options
                - base_url (str): Base URL for the Ollama API
                - model (str): Model name to use
                - timeout (int): Request timeout in seconds
        """
        # Get configuration from config file, override with kwargs
        config = get_provider_config("ollama") or {}
        self._base_url = kwargs.get("base_url", config.get("base_url", "http://localhost:11434"))
        self._model = kwargs.get("model", config.get("model", "llama2"))
        self._timeout = kwargs.get("timeout", config.get("timeout", 60))

        # Remove trailing slash from base_url if present
        if self._base_url.endswith("/"):
            self._base_url = self._base_url[:-1]

    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate a response from the LLM based on the given prompt.

        Args:
            prompt (str): The prompt to send to the LLM
            **kwargs: Additional parameters
                - temperature (float): Sampling temperature
                - max_tokens (int): Maximum number of tokens to generate

        Returns:
            str: The generated response
        """
        url = f"{self._base_url}/api/generate"

        # Prepare request payload
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False
        }

        # Add optional parameters
        if "temperature" in kwargs:
            payload["temperature"] = kwargs["temperature"]
        if "max_tokens" in kwargs:
            payload["max_tokens"] = kwargs["max_tokens"]

        try:
            response = requests.post(url, json=payload, timeout=self._timeout)
            response.raise_for_status()
            result = response.json()
            return result.get("response", "")
        except requests.RequestException as e:
            print(f"Error calling Ollama API: {e}")
            return f"Error: {str(e)}"

    def generate_with_context(self, 
                             prompt: str, 
                             context: List[Dict[str, str]], 
                             **kwargs) -> str:
        """
        Generate a response from the LLM with additional context.

        Args:
            prompt (str): The prompt to send to the LLM
            context (List[Dict[str, str]]): List of context items, each with 'role' and 'content'
            **kwargs: Additional parameters

        Returns:
            str: The generated response
        """
        # Format context as a conversation
        messages = []
        for item in context:
            messages.append({
                "role": item.get("role", "user"),
                "content": item.get("content", "")
            })

        # Add the current prompt
        messages.append({
            "role": "user",
            "content": prompt
        })

        url = f"{self._base_url}/api/chat"

        # Prepare request payload
        payload = {
            "model": self._model,
            "messages": messages,
            "stream": False
        }

        # Add optional parameters
        if "temperature" in kwargs:
            payload["temperature"] = kwargs["temperature"]

        try:
            response = requests.post(url, json=payload, timeout=self._timeout)
            response.raise_for_status()
            result = response.json()
            return result.get("message", {}).get("content", "")
        except requests.RequestException as e:
            print(f"Error calling Ollama API: {e}")
            return f"Error: {str(e)}"

    # Using the base class implementation for analyze_code

    # Using the base class implementation for assess_vulnerability_impact

    # Using the base class implementation for generate_cve_description

    @property
    def provider_name(self) -> str:
        """
        Get the name of the LLM provider.

        Returns:
            str: Provider name
        """
        return "ollama"

    @property
    def model_name(self) -> str:
        """
        Get the name of the model being used.

        Returns:
            str: Model name
        """
        return self._model

    def is_available(self) -> bool:
        """
        Check if the Ollama provider is available and properly configured.

        Returns:
            bool: True if available, False otherwise
        """
        try:
            url = f"{self._base_url}/api/version"
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False
