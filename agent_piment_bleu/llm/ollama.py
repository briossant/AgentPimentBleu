"""
Ollama LLM Provider

This module implements the LLM provider interface for Ollama.
"""

import json
import requests
from typing import Dict, List, Any, Optional, Tuple

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
        self._model = kwargs.get("model", config.get("model", "llama3.2:1b"))
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
                - model (str): Override the default model

        Returns:
            str: The generated response
        """
        # Check if Ollama is available
        if not self.is_available():
            return "Error: Ollama is not available. Please ensure Ollama is running and accessible."

        # Get the model to use (either from kwargs or the default)
        model = kwargs.get("model", self._model)

        # Check if the model is available
        is_available, actual_model = self.is_model_available(model)
        if not is_available:
            available_models = self.list_models()
            if available_models:
                # Use the first available model as a fallback
                fallback_model = available_models[0]
                print(f"Warning: Model '{model}' is not available. Using '{fallback_model}' instead.")
                model = fallback_model
            else:
                return f"Error: Model '{model}' is not available and no fallback models were found. Please pull a model using 'ollama pull {model}' or check your Ollama installation."
        elif actual_model and actual_model != model:
            # Use the actual model name (with tag) if it's different from the requested model
            print(f"Using available model '{actual_model}' instead of requested model '{model}'")
            model = actual_model

        url = f"{self._base_url}/api/generate"

        # Prepare request payload
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }

        # Add optional parameters
        if "temperature" in kwargs:
            payload["options"] = payload.get("options", {})
            payload["options"]["temperature"] = kwargs["temperature"]
        if "max_tokens" in kwargs:
            payload["options"] = payload.get("options", {})
            payload["options"]["num_predict"] = kwargs["max_tokens"]

        try:
            print(f"Sending request to Ollama API: {url}")
            print(f"Using model: {model}")
            print(f"Payload: {json.dumps(payload, indent=2)}")
            response = requests.post(url, json=payload, timeout=self._timeout)

            if response.status_code == 404:
                print(f"Error: API endpoint not found. URL: {url}")
                print(f"Please ensure Ollama is running and the API endpoint is correct.")
                return f"Error: API endpoint not found. Please ensure Ollama is running and the API endpoint is correct."

            if response.status_code == 400:
                error_message = response.json().get("error", "Unknown error")
                print(f"Error from Ollama API: {error_message}")
                if "model" in error_message.lower():
                    return f"Error: {error_message}. Please pull the model using 'ollama pull {model}' or use a different model."
                return f"Error from Ollama API: {error_message}"

            response.raise_for_status()
            result = response.json()
            return result.get("response", "")
        except requests.RequestException as e:
            print(f"Error calling Ollama API: {e}")
            print(f"Request URL: {url}")
            print(f"Request payload: {json.dumps(payload, indent=2)}")
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
                - temperature (float): Sampling temperature
                - max_tokens (int): Maximum number of tokens to generate
                - model (str): Override the default model

        Returns:
            str: The generated response
        """
        # Check if Ollama is available
        if not self.is_available():
            return "Error: Ollama is not available. Please ensure Ollama is running and accessible."

        # Get the model to use (either from kwargs or the default)
        model = kwargs.get("model", self._model)

        # Check if the model is available
        is_available, actual_model = self.is_model_available(model)
        if not is_available:
            available_models = self.list_models()
            if available_models:
                # Use the first available model as a fallback
                fallback_model = available_models[0]
                print(f"Warning: Model '{model}' is not available. Using '{fallback_model}' instead.")
                model = fallback_model
            else:
                return f"Error: Model '{model}' is not available and no fallback models were found. Please pull a model using 'ollama pull {model}' or check your Ollama installation."
        elif actual_model and actual_model != model:
            # Use the actual model name (with tag) if it's different from the requested model
            print(f"Using available model '{actual_model}' instead of requested model '{model}'")
            model = actual_model

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
            "model": model,
            "messages": messages,
            "stream": False
        }

        # Add optional parameters
        if "temperature" in kwargs:
            payload["options"] = payload.get("options", {})
            payload["options"]["temperature"] = kwargs["temperature"]
        if "max_tokens" in kwargs:
            payload["options"] = payload.get("options", {})
            payload["options"]["num_predict"] = kwargs["max_tokens"]

        try:
            print(f"Sending request to Ollama API: {url}")
            print(f"Using model: {model}")
            print(f"Payload: {json.dumps(payload, indent=2)}")
            response = requests.post(url, json=payload, timeout=self._timeout)

            if response.status_code == 404:
                print(f"Error: API endpoint not found. URL: {url}")
                print(f"Please ensure Ollama is running and the API endpoint is correct.")
                return f"Error: API endpoint not found. Please ensure Ollama is running and the API endpoint is correct."

            if response.status_code == 400:
                error_message = response.json().get("error", "Unknown error")
                print(f"Error from Ollama API: {error_message}")
                if "model" in error_message.lower():
                    return f"Error: {error_message}. Please pull the model using 'ollama pull {model}' or use a different model."
                return f"Error from Ollama API: {error_message}"

            response.raise_for_status()
            result = response.json()
            return result.get("message", {}).get("content", "")
        except requests.RequestException as e:
            print(f"Error calling Ollama API: {e}")
            print(f"Request URL: {url}")
            print(f"Request payload: {json.dumps(payload, indent=2)}")
            return f"Error: {str(e)}"

    # Using the base class implementation for analyze_code

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
            print(f"Checking Ollama availability at: {url}")
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                print(f"Ollama is available. Version: {response.json().get('version', 'unknown')}")
                return True
            else:
                print(f"Ollama returned status code: {response.status_code}")
                return False
        except requests.RequestException as e:
            print(f"Error checking Ollama availability: {e}")
            return False

    def list_models(self) -> List[str]:
        """
        List available models in Ollama.

        Returns:
            List[str]: List of available model names
        """
        try:
            url = f"{self._base_url}/api/tags"
            print(f"Listing available models from: {url}")
            response = requests.get(url, timeout=self._timeout)

            if response.status_code == 200:
                # Parse the response based on the Ollama API format
                # The response format might be {"models": [...]} or just a list of models
                response_json = response.json()

                # Handle different response formats
                if isinstance(response_json, dict) and "models" in response_json:
                    # Format: {"models": [{"name": "model1"}, {"name": "model2"}]}
                    models = response_json.get("models", [])
                    model_names = [model.get("name") for model in models if isinstance(model, dict)]
                elif isinstance(response_json, dict) and "models" not in response_json:
                    # Format: {"model1": {...}, "model2": {...}}
                    model_names = list(response_json.keys())
                elif isinstance(response_json, list):
                    # Format: [{"name": "model1"}, {"name": "model2"}]
                    model_names = [model.get("name") for model in response_json if isinstance(model, dict) and "name" in model]
                else:
                    model_names = []

                if model_names:
                    print(f"Available models: {', '.join(model_names)}")
                else:
                    print("No models found in Ollama")
                return model_names
            else:
                print(f"Failed to list models. Status code: {response.status_code}")
                return []
        except requests.RequestException as e:
            print(f"Error listing models: {e}")
            return []
        except ValueError as e:
            print(f"Error parsing response from Ollama API: {e}")
            return []

    def is_model_available(self, model_name: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a specific model is available in Ollama.

        Args:
            model_name (str): Name of the model to check

        Returns:
            tuple[bool, Optional[str]]: A tuple containing:
                - bool: True if the model is available, False otherwise
                - Optional[str]: The actual available model name if found, None otherwise
        """
        available_models = self.list_models()

        # Direct match
        if model_name in available_models:
            return True, model_name

        # Check for base model match (without tag)
        # For example, if model_name is "llama2" and available_models includes "llama2:latest"
        base_model = model_name.split(':')[0]
        for available_model in available_models:
            available_base = available_model.split(':')[0]
            if base_model == available_base:
                print(f"Found matching base model: {available_model} for requested model: {model_name}")
                return True, available_model

        return False, None
