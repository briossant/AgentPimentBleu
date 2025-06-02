"""
LLM Provider Factory

This module provides a factory function to create LLM providers based on configuration.
"""

from typing import Optional, Dict, Any

from agent_piment_bleu.llm.base import LLMProvider
from agent_piment_bleu.llm.config import get_default_provider, get_provider_config
from agent_piment_bleu.llm.ollama import OllamaProvider


def create_llm_provider(provider_name: Optional[str] = None, **kwargs) -> LLMProvider:
    """
    Create an LLM provider instance based on the specified provider name.
    
    Args:
        provider_name (Optional[str]): Name of the provider to create.
            If None, the default provider from the configuration will be used.
        **kwargs: Additional provider-specific configuration options
            
    Returns:
        LLMProvider: An instance of the specified LLM provider
        
    Raises:
        ValueError: If the specified provider is not supported
    """
    # If no provider name is specified, use the default from config
    if provider_name is None:
        provider_name = get_default_provider()
    
    # Get provider-specific configuration
    provider_config = get_provider_config(provider_name) or {}
    
    # Merge provider config with kwargs (kwargs take precedence)
    config = {**provider_config, **kwargs}
    
    # Create the appropriate provider instance
    if provider_name == "ollama":
        return OllamaProvider(**config)
    elif provider_name == "modal":
        # Import here to avoid dependency issues if not used
        from agent_piment_bleu.llm.modal_provider import ModalProvider
        return ModalProvider(**config)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")


def get_available_providers() -> Dict[str, bool]:
    """
    Get a dictionary of available LLM providers and their availability status.
    
    Returns:
        Dict[str, bool]: Dictionary mapping provider names to their availability status
    """
    providers = {
        "ollama": False,
        "modal": False
    }
    
    # Check Ollama availability
    try:
        ollama = OllamaProvider()
        providers["ollama"] = ollama.is_available()
    except Exception:
        pass
    
    # Check Modal availability
    try:
        # Import here to avoid dependency issues if not used
        from agent_piment_bleu.llm.modal_provider import ModalProvider
        modal = ModalProvider()
        providers["modal"] = modal.is_available()
    except Exception:
        pass
    
    return providers