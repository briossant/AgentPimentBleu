"""
Modal LLM Provider

This module implements the LLM provider interface for Modal.
"""

import json
from typing import Dict, List, Any, Optional

from agent_piment_bleu.llm.base import LLMProvider
from agent_piment_bleu.llm.config import get_provider_config


class ModalProvider(LLMProvider):
    """
    LLM provider implementation for Modal.
    """
    
    def __init__(self, **kwargs):
        """
        Initialize the Modal provider.
        
        Args:
            **kwargs: Provider-specific configuration options
                - model (str): Model name to use
                - timeout (int): Request timeout in seconds
        """
        # Get configuration from config file, override with kwargs
        config = get_provider_config("modal") or {}
        self._model = kwargs.get("model", config.get("model", "mistral-7b"))
        self._timeout = kwargs.get("timeout", config.get("timeout", 60))
        
        # Lazy import Modal to avoid dependency issues if not used
        self._modal = None
        self._stub = None
        self._model_instance = None
        self._initialized = False
    
    def _ensure_initialized(self):
        """
        Ensure Modal is initialized.
        
        Returns:
            bool: True if initialization succeeded, False otherwise
        """
        if self._initialized:
            return True
        
        try:
            # Lazy import Modal
            import modal
            self._modal = modal
            
            # Define Modal stub
            self._stub = modal.Stub("agent-piment-bleu")
            
            # Define Modal image with dependencies
            image = modal.Image.debian_slim().pip_install(["transformers", "torch"])
            
            # Define Modal function for model inference
            @self._stub.function(image=image, gpu="any", timeout=self._timeout)
            async def model(self, prompt: str, **kwargs):
                from transformers import AutoModelForCausalLM, AutoTokenizer
                import torch
                
                # Load model and tokenizer
                model_name = self._model
                tokenizer = AutoTokenizer.from_pretrained(model_name)
                model = AutoModelForCausalLM.from_pretrained(
                    model_name, 
                    torch_dtype=torch.float16, 
                    device_map="auto"
                )
                
                # Set generation parameters
                temperature = kwargs.get("temperature", 0.7)
                max_tokens = kwargs.get("max_tokens", 1024)
                
                # Tokenize input
                inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
                
                # Generate response
                with torch.no_grad():
                    outputs = model.generate(
                        inputs.input_ids,
                        max_new_tokens=max_tokens,
                        temperature=temperature,
                        do_sample=temperature > 0,
                    )
                
                # Decode and return response
                response = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
                return response
            
            self._model_instance = model
            self._initialized = True
            return True
        except ImportError:
            print("Modal package not installed. Please install it with 'pip install modal'.")
            return False
        except Exception as e:
            print(f"Error initializing Modal: {e}")
            return False
    
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
        if not self._ensure_initialized():
            return "Error: Modal not initialized"
        
        try:
            # Call the Modal function
            with self._stub.run():
                response = self._model_instance(prompt, **kwargs)
            return response
        except Exception as e:
            print(f"Error calling Modal: {e}")
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
        formatted_prompt = ""
        
        for item in context:
            role = item.get("role", "user")
            content = item.get("content", "")
            
            if role == "system":
                formatted_prompt += f"System: {content}\n\n"
            elif role == "user":
                formatted_prompt += f"User: {content}\n\n"
            elif role == "assistant":
                formatted_prompt += f"Assistant: {content}\n\n"
        
        # Add the current prompt
        formatted_prompt += f"User: {prompt}\n\nAssistant:"
        
        # Generate response with the formatted prompt
        return self.generate(formatted_prompt, **kwargs)
    
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
        return "modal"
    
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
        Check if the Modal provider is available and properly configured.
        
        Returns:
            bool: True if available, False otherwise
        """
        try:
            return self._ensure_initialized()
        except Exception:
            return False