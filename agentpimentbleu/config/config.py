"""
AgentPimentBleu - Configuration module

This module provides a Settings class that loads and manages configuration settings
from YAML files and environment variables.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Get logger
from agentpimentbleu.utils.logger import get_logger
logger = get_logger()


class Settings:
    """
    Settings class for loading and managing configuration.
    Implements the singleton pattern to ensure only one instance exists.
    """
    _instance: Optional['Settings'] = None
    _config: Dict[str, Any] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self):
        """
        Load configuration from YAML file.
        First tries to load from ~/.config/agentpimentbleu/settings.yaml,
        then falls back to the template in config/settings.yaml.
        """
        # Try to load from user config directory
        user_config_path = Path.home() / '.config' / 'agentpimentbleu' / 'settings.yaml'
        
        if user_config_path.exists():
            try:
                with open(user_config_path, 'r') as f:
                    self._config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {user_config_path}")
                return
            except Exception as e:
                logger.warning(f"Failed to load configuration from {user_config_path}: {e}")
        else:
            logger.warning(f"User configuration file not found at {user_config_path}")
        
        # Fall back to template config
        template_config_path = Path(__file__).parent / 'settings.yaml'
        
        if template_config_path.exists():
            try:
                with open(template_config_path, 'r') as f:
                    self._config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from template at {template_config_path}")
            except Exception as e:
                logger.error(f"Failed to load template configuration from {template_config_path}: {e}")
                self._config = {}
        else:
            logger.error(f"Template configuration file not found at {template_config_path}")
            self._config = {}
        
        # Override with environment variables
        self._override_from_env()
    
    def _override_from_env(self):
        """
        Override configuration values with environment variables.
        Environment variables should be prefixed with 'APB_' and use double underscores
        to represent nested keys, e.g., APB_LLM_PROVIDERS__GEMINI__API_KEY.
        """
        for env_var, value in os.environ.items():
            if env_var.startswith('APB_'):
                # Remove prefix and split by double underscore
                key_path = env_var[4:].lower().split('__')
                
                # Navigate to the nested dictionary
                current = self._config
                for key in key_path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                
                # Set the value
                current[key_path[-1]] = value
                logger.debug(f"Overrode configuration value from environment variable {env_var}")
    
    def get_llm_provider_config(self, provider_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific LLM provider.
        
        Args:
            provider_name (str): Name of the LLM provider (e.g., 'gemini', 'ollama')
            
        Returns:
            Dict[str, Any]: Configuration for the specified provider
        """
        providers = self._config.get('llm_providers', {})
        return providers.get(provider_name, {})
    
    def get_dependency_parsers_config(self) -> Dict[str, Any]:
        """
        Get configuration for dependency parsers.
        
        Returns:
            Dict[str, Any]: Configuration for dependency parsers
        """
        return self._config.get('dependency_parsers', {})
    
    def get_rag_settings(self) -> Dict[str, Any]:
        """
        Get RAG settings.
        
        Returns:
            Dict[str, Any]: RAG settings
        """
        return self._config.get('rag_settings', {})
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key.
        
        Args:
            key (str): Configuration key
            default (Any, optional): Default value if key is not found
            
        Returns:
            Any: Configuration value
        """
        return self._config.get(key, default)
    
    def get_nested(self, *keys: str, default: Any = None) -> Any:
        """
        Get a nested configuration value.
        
        Args:
            *keys: Sequence of keys to navigate the nested structure
            default (Any, optional): Default value if path is not found
            
        Returns:
            Any: Configuration value
        """
        current = self._config
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return default
            current = current[key]
        return current


# Convenience function to get the settings instance
def get_settings() -> Settings:
    """
    Get the singleton Settings instance.
    
    Returns:
        Settings: The singleton settings instance
    """
    return Settings()