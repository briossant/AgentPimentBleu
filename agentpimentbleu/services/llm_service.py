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
from langchain_mistralai import ChatMistralAI

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
        # If provider_name is not specified, check for active_llm_provider first, then fall back to default_llm_provider
        if provider_name is None:
            # First check if there's an active_llm_provider set (typically from API key override)
            provider_name = self.config.get('active_llm_provider')
            if not provider_name:
                # Fall back to default_llm_provider or 'gemini' if neither is set
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
        elif provider_name == 'mistral':
            return self._init_mistral(provider_config)
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

        # Check if the API key is still the placeholder value
        if api_key == 'YOUR_GEMINI_API_KEY':
            logger.error("Gemini API key is set to the default placeholder value. Please set a valid API key.")
            logger.info("You can set the API key using the APB_LLM_PROVIDERS__GEMINI__API_KEY environment variable")
            logger.info("or by creating a configuration file at ~/.config/agentpimentbleu/settings.yaml")
            raise ValueError("Invalid Gemini API key: Using placeholder value. Please set a valid API key.")

        logger.info(f"Initializing Gemini chat model with model: {model}")
        logger.debug(f"API key length: {len(api_key)} characters")

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

    def _init_mistral(self, config: Dict[str, Any]) -> BaseChatModel:
        """
        Initialize a Mistral chat model.

        Args:
            config (Dict[str, Any]): Configuration for the Mistral provider

        Returns:
            BaseChatModel: Langchain chat model instance for Mistral
        """
        api_key = config.get('api_key')
        model = config.get('model', 'devstral-small-2505')

        if not api_key:
            logger.error("No API key found for Mistral")
            raise ValueError("No API key found for Mistral")

        # Check if the API key is still the placeholder value
        if api_key == 'YOUR_MISTRAL_API_KEY':
            logger.error("Mistral API key is set to the default placeholder value. Please set a valid API key.")
            logger.info("You can set the API key using the APB_LLM_PROVIDERS__MISTRAL__API_KEY environment variable")
            logger.info("or by creating a configuration file at ~/.config/agentpimentbleu/settings.yaml")
            raise ValueError("Invalid Mistral API key: Using placeholder value. Please set a valid API key.")

        logger.info(f"Initializing Mistral chat model with model: {model}")
        logger.debug(f"API key length: {len(api_key)} characters")

        return ChatMistralAI(
            model=model,
            mistral_api_key=api_key,
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

        except ValueError as e:
            # Handle configuration errors
            logger.error(f"Configuration error when invoking LLM: {e}")
            if "API key" in str(e):
                logger.error("Please check your API key configuration.")
                logger.info("For Gemini, set the APB_LLM_PROVIDERS__GEMINI__API_KEY environment variable")
                logger.info("or update your ~/.config/agentpimentbleu/settings.yaml file.")
            raise
        except Exception as e:
            # Handle other errors, including API-related errors
            error_msg = str(e)
            logger.error(f"Error invoking LLM: {error_msg}")

            # Add more specific error handling for common API issues
            if "API_KEY_INVALID" in error_msg:
                logger.error("The provided API key is invalid. Please check your API key and ensure it's correct.")
                logger.info("For Gemini, you can get a valid API key from https://ai.google.dev/")
            elif "PERMISSION_DENIED" in error_msg:
                logger.error("Permission denied. Your API key may not have access to the requested model.")
            elif "QUOTA_EXCEEDED" in error_msg:
                logger.error("API quota exceeded. You may need to wait or upgrade your API plan.")
            elif "RESOURCE_EXHAUSTED" in error_msg:
                logger.error("Resource exhausted. You may be rate limited. Try again later.")

            # Log how to parse the LLM response error
            logger.error(f"Error parsing LLM response: {error_msg}")

            raise
