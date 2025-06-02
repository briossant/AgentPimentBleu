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
            **kwargs: Additional parameters
            
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
        
        # Try to parse the response as JSON
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
    
    def assess_vulnerability_impact(self, 
                                   cve_info: Dict[str, str], 
                                   code_snippets: List[str], 
                                   **kwargs) -> Dict[str, Any]:
        """
        Assess the impact of a vulnerability in the context of specific code.
        
        Args:
            cve_info (Dict[str, str]): Information about the CVE
            code_snippets (List[str]): Relevant code snippets
            **kwargs: Additional parameters
            
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
                "is_vulnerable": False,
                "confidence": "low",
                "impact": "unknown",
                "explanation": "Failed to parse LLM response as JSON",
                "raw_response": response
            }
    
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