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

    def assess_vulnerability_impact(self, 
                                   cve_info: Dict[str, str], 
                                   code_snippets: List[str], 
                                   **kwargs) -> Dict[str, Any]:
        """
        Assess the impact of a vulnerability in the context of specific code.

        Args:
            cve_info (Dict[str, str]): Information about the CVE
            code_snippets (List[str]): Relevant code snippets
            **kwargs: Additional provider-specific parameters

        Returns:
            Dict[str, Any]: Impact assessment results
        """
        # Create a prompt for vulnerability impact assessment
        prompt = f"""
        Assess the impact of the following vulnerability in the context of the provided code snippets:

        CVE ID: {cve_info.get('id', 'Unknown')}
        Description: {cve_info.get('description', 'No description provided')}
        Affected Component: {cve_info.get('component', 'Unknown')}
        CVSS Score: {cve_info.get('cvss_score', 'Unknown')}

        Relevant code snippets:

        """

        for i, snippet in enumerate(code_snippets):
            prompt += f"""
        Snippet {i+1}:
        ```
        {snippet}
        ```
        """

        prompt += """
        Based on the vulnerability details and the code snippets, assess:
        1. Is the vulnerable component being used in a way that exposes the vulnerability?
        2. What is the potential impact if this vulnerability is exploited in this specific context?
        3. How easily could this vulnerability be exploited given the usage pattern?

        Format your response as JSON with the following structure:
        {
            "is_vulnerable": true/false,
            "confidence": "high/medium/low",
            "impact": "critical/high/medium/low/none",
            "explanation": "Detailed explanation of the assessment",
            "remediation": "Recommended steps to address the vulnerability"
        }
        """

        response = self.generate(prompt, **kwargs)

        # Try to parse the response as JSON
        try:
            result = self._parse_json_response(response)
            return result
        except Exception:
            # If parsing fails, return a structured response with the raw text
            return {
                "is_vulnerable": False,
                "confidence": "low",
                "impact": "unknown",
                "explanation": "Failed to parse LLM response as JSON",
                "raw_response": response
            }

    def generate_cve_description(self, 
                               cve_info: Dict[str, str], 
                               **kwargs) -> str:
        """
        Generate a human-readable description of a CVE.

        Args:
            cve_info (Dict[str, str]): Information about the CVE
            **kwargs: Additional provider-specific parameters

        Returns:
            str: Human-readable description of the CVE
        """
        # Create a prompt for generating a human-readable CVE description
        prompt = f"""
        Please provide a clear, concise, human-readable explanation of the following vulnerability:

        CVE ID: {cve_info.get('id', 'Unknown')}
        Technical Description: {cve_info.get('description', 'No description provided')}
        Affected Component: {cve_info.get('component', 'Unknown')}
        CVSS Score: {cve_info.get('cvss_score', 'Unknown')}

        Explain in simple terms:
        1. What this vulnerability is
        2. How it could potentially be exploited
        3. What the impact could be if exploited
        4. General recommendations for addressing this type of vulnerability

        Keep your explanation clear and understandable for developers who may not be security experts.
        """

        # Generate the description
        response = self.generate(prompt, **kwargs)

        # Clean up the response (remove any markdown formatting, etc.)
        description = response.strip()

        return description

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
