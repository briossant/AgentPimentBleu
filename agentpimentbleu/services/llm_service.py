"""
AgentPimentBleu - LLM Service

This module provides an LLMService class for interacting with different LLM providers.
"""

from typing import Dict, Any, Optional

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import BasePromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.chains import LLMChain
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.chat_models import ChatOllama

from agentpimentbleu.config.config import get_settings
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()


class LLMService:
    """
    Service for interacting with different LLM providers.
    """
    
    def __init__(self, config=None):
        """
        Initialize the LLMService.
        
        Args:
            config: Configuration object (defaults to get_settings())
        """
        self.config = config or get_settings()
    
    def get_llm(self, provider_name: Optional[str] = None) -> BaseChatModel:
        """
        Get a Langchain chat model instance for the specified provider.
        
        Args:
            provider_name (Optional[str]): Name of the provider (e.g., 'gemini', 'ollama')
                                          If None, uses the default from config
            
        Returns:
            BaseChatModel: Langchain chat model instance
        """
        # If provider_name is not specified, use the default from config
        if provider_name is None:
            # This assumes there's a default_llm_provider in the config
            # If not, you could default to the first provider in the config
            provider_name = self.config.get('default_llm_provider', 'gemini')
        
        logger.info(f"Getting LLM for provider: {provider_name}")
        
        # Get provider config
        provider_config = self.config.get_llm_provider_config(provider_name)
        
        if not provider_config:
            logger.error(f"No configuration found for LLM provider: {provider_name}")
            # Fall back to a default provider if the requested one is not configured
            if provider_name != 'gemini':
                logger.info("Falling back to gemini provider")
                return self.get_llm('gemini')
            else:
                raise ValueError(f"No configuration found for LLM provider: {provider_name}")
        
        # Initialize the appropriate LLM based on the provider
        if provider_name == 'gemini':
            return self._init_gemini(provider_config)
        elif provider_name == 'ollama':
            return self._init_ollama(provider_config)
        else:
            logger.error(f"Unsupported LLM provider: {provider_name}")
            raise ValueError(f"Unsupported LLM provider: {provider_name}")
    
    def _init_gemini(self, config: Dict[str, Any]) -> BaseChatModel:
        """
        Initialize a Gemini chat model.
        
        Args:
            config (Dict[str, Any]): Configuration for the Gemini provider
            
        Returns:
            BaseChatModel: Langchain chat model instance for Gemini
        """
        api_key = config.get('api_key')
        model = config.get('model', 'gemini-pro')
        
        if not api_key:
            logger.error("No API key found for Gemini")
            raise ValueError("No API key found for Gemini")
        
        logger.info(f"Initializing Gemini chat model with model: {model}")
        
        return ChatGoogleGenerativeAI(
            model=model,
            google_api_key=api_key,
            temperature=0.2,  # Lower temperature for more deterministic outputs
            convert_system_message_to_human=True  # Gemini doesn't support system messages natively
        )
    
    def _init_ollama(self, config: Dict[str, Any]) -> BaseChatModel:
        """
        Initialize an Ollama chat model.
        
        Args:
            config (Dict[str, Any]): Configuration for the Ollama provider
            
        Returns:
            BaseChatModel: Langchain chat model instance for Ollama
        """
        base_url = config.get('base_url', 'http://localhost:11434')
        model = config.get('model', 'llama2')
        
        logger.info(f"Initializing Ollama chat model with model: {model}, base_url: {base_url}")
        
        return ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0.2  # Lower temperature for more deterministic outputs
        )
    
    def invoke_llm(self, prompt_template: BasePromptTemplate, input_data: Dict[str, Any], provider_name: Optional[str] = None) -> str:
        """
        Invoke an LLM with a prompt template and input data.
        
        Args:
            prompt_template (BasePromptTemplate): Langchain prompt template
            input_data (Dict[str, Any]): Input data for the prompt template
            provider_name (Optional[str]): Name of the provider (e.g., 'gemini', 'ollama')
            
        Returns:
            str: The content of the LLM's response
        """
        logger.info(f"Invoking LLM with provider: {provider_name or 'default'}")
        
        try:
            # Get the LLM
            llm = self.get_llm(provider_name)
            
            # Create a chain with the prompt template and LLM
            chain = prompt_template | llm | StrOutputParser()
            
            # Invoke the chain with the input data
            response = chain.invoke(input_data)
            
            return response
            
        except Exception as e:
            logger.error(f"Error invoking LLM: {e}")
            raise