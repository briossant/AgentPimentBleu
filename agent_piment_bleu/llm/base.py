"""
Base LLM Provider Interface

This module defines the base interface for LLM providers.
All specific LLM provider implementations should inherit from this class.
"""

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
    
    @abstractmethod
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
        pass
    
    @abstractmethod
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
        pass
    
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