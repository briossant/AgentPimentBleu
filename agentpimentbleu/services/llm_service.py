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


class LLMAuthenticationError(Exception):
    """Custom exception for LLM authentication failures."""
    pass


class LLMConfigurationError(Exception):
    """Custom exception for LLM configuration errors (e.g., placeholder API key)."""
    pass


class LLMConnectionError(Exception):
    """Custom exception for LLM connection or availability issues."""
    pass


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

        Raises:
            LLMConfigurationError: If API key is missing or is a placeholder
        """
        api_key = config.get('api_key')
        model = config.get('model', 'gemini-pro')

        if not api_key:
            msg = "No API key found for Gemini in the configuration."
            logger.error(msg)
            raise LLMConfigurationError(msg)

        # Check if the API key is still the placeholder value
        if api_key == 'YOUR_GEMINI_API_KEY':
            msg = "Gemini API key is set to the default placeholder value. Please set a valid API key."
            logger.error(msg)
            logger.info("You can set the API key using the APB_LLM_PROVIDERS__GEMINI__API_KEY environment variable")
            logger.info("or by creating a configuration file at ~/.config/agentpimentbleu/settings.yaml")
            raise LLMConfigurationError(msg)

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

        Raises:
            LLMConfigurationError: If API key is missing or is a placeholder
        """
        api_key = config.get('api_key')
        model = config.get('model', 'devstral-small-2505')

        if not api_key:
            msg = "No API key found for Mistral in the configuration."
            logger.error(msg)
            raise LLMConfigurationError(msg)

        # Check if the API key is still the placeholder value
        if api_key == 'YOUR_MISTRAL_API_KEY':
            msg = "Mistral API key is set to the default placeholder value. Please set a valid API key."
            logger.error(msg)
            logger.info("You can set the API key using the APB_LLM_PROVIDERS__MISTRAL__API_KEY environment variable")
            logger.info("or by creating a configuration file at ~/.config/agentpimentbleu/settings.yaml")
            raise LLMConfigurationError(msg)

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

        Raises:
            LLMConfigurationError: If there's a configuration error (e.g., missing or placeholder API key)
            LLMAuthenticationError: If there's an authentication error (e.g., invalid API key)
            LLMConnectionError: If there's a connection error (e.g., rate limit exceeded)
        """
        logger.info(f"Invoking LLM with provider: {provider_name or self.config.get('active_llm_provider', 'default')}")
        active_provider = provider_name or self.config.get('active_llm_provider')

        try:
            # Get the LLM
            llm = self.get_llm(active_provider)

            # Create a chain with the prompt template and LLM
            chain = prompt_template | llm | StrOutputParser()

            # Invoke the chain with the input data
            response = chain.invoke(input_data)

            return response

        except LLMConfigurationError as e:
            # Catch our custom config error
            logger.error(f"LLM Configuration Error for provider '{active_provider}': {e}")
            raise  # Re-raise to be caught by graph nodes
        except LLMAuthenticationError as e:
            # Catch our custom auth error
            logger.error(f"LLM Authentication Error for provider '{active_provider}': {e}")
            raise  # Re-raise
        except Exception as e:
            # Catch other Langchain/API errors
            error_msg = str(e)
            logger.error(f"Error invoking LLM provider '{active_provider}': {error_msg}")

            # Categorize the error based on the error message
            if "API key" in error_msg.lower() or "authenticate" in error_msg.lower() or \
               "401" in error_msg or "Unauthorized" in error_msg:
                raise LLMAuthenticationError(f"Authentication failed for {active_provider}: {error_msg}") from e
            elif "rate limit" in error_msg.lower() or "quota" in error_msg.lower() or "429" in error_msg:
                raise LLMConnectionError(f"Rate limit or quota exceeded for {active_provider}: {error_msg}") from e
            elif "permission" in error_msg.lower() or "denied" in error_msg.lower() or "403" in error_msg:
                raise LLMAuthenticationError(f"Permission denied for {active_provider} (check API key permissions for the model): {error_msg}") from e
            # Add more specific error condition checks if needed
            raise LLMConnectionError(f"Generic error with LLM provider {active_provider}: {error_msg}") from e
