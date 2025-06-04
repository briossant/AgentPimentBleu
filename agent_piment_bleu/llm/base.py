"""
Base LLM Provider Interface

This module defines the base interface for LLM providers.
All specific LLM provider implementations should inherit from this class.
"""

import json
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    This class defines the interface that all LLM providers must implement.
    """

    @abstractmethod
    def __init__(self, **kwargs):
        """
        Initialize the LLM provider with provider-specific configuration.

        Args:
            **kwargs: Provider-specific configuration options
        """
        pass

    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """
        Generate a response from the LLM based on the given prompt.

        Args:
            prompt (str): The prompt to send to the LLM
            **kwargs: Additional provider-specific parameters

        Returns:
            str: The generated response
        """
        pass

    @abstractmethod
    def generate_with_context(self, 
                             prompt: str, 
                             context: List[Dict[str, str]], 
                             **kwargs) -> str:
        """
        Generate a response from the LLM with additional context.

        Args:
            prompt (str): The prompt to send to the LLM
            context (List[Dict[str, str]]): List of context items, each with 'role' and 'content'
            **kwargs: Additional provider-specific parameters

        Returns:
            str: The generated response
        """
        pass

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """
        Parse a JSON response from the LLM.

        Args:
            response (str): The response from the LLM

        Returns:
            Dict[str, Any]: Parsed JSON response
        """
        try:
            # Extract JSON from the response (it might be wrapped in markdown code blocks)
            json_str = response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0].strip()

            result = json.loads(json_str)
            return result
        except (json.JSONDecodeError, IndexError):
            # If parsing fails, return a structured response with the raw text
            return {
                "issues": [],
                "summary": "Failed to parse LLM response as JSON",
                "raw_response": response
            }

    def analyze_code(self, 
                    code: str, 
                    language: str, 
                    task: str, 
                    **kwargs) -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities or other issues.

        Args:
            code (str): The code to analyze
            language (str): The programming language of the code
            task (str): The specific analysis task (e.g., 'security', 'quality')
            **kwargs: Additional provider-specific parameters

        Returns:
            Dict[str, Any]: Analysis results
        """
        # Create a prompt for code analysis
        prompt = f"""
        Analyze the following {language} code for {task} issues:

        ```{language}
        {code}
        ```

        Provide a detailed analysis of any {task} issues found in the code.
        Format your response as JSON with the following structure:
        {{
            "issues": [
                {{
                    "description": "Description of the issue",
                    "severity": "high/medium/low",
                    "line_number": "Approximate line number or range",
                    "recommendation": "How to fix the issue"
                }}
            ],
            "summary": "Brief summary of findings"
        }}
        """

        response = self.generate(prompt, **kwargs)
        return self._parse_json_response(response)


    def generate_text(self, prompt: str, **kwargs) -> str:
        """
        Generate a response from the LLM based on the given prompt.
        This is an alias for the generate method to maintain compatibility.

        Args:
            prompt (str): The prompt to send to the LLM
            **kwargs: Additional parameters

        Returns:
            str: The generated response
        """
        return self.generate(prompt, **kwargs)

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Get the name of the LLM provider.

        Returns:
            str: Provider name
        """
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """
        Get the name of the model being used.

        Returns:
            str: Model name
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the LLM provider is available and properly configured.

        Returns:
            bool: True if available, False otherwise
        """
        pass
