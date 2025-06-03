"""
LLM Configuration Module

This module handles loading and saving LLM configuration from the user's
~/.config/ directory.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

# Configuration constants
CONFIG_DIR = os.path.expanduser("~/.config/agent_piment_bleu")
CONFIG_FILE = os.path.join(CONFIG_DIR, "llm_config.json")

# Default configuration
DEFAULT_CONFIG = {
    "default_provider": "ollama",
    "providers": {
        "ollama": {
            "base_url": "http://localhost:11434",
            "model": "llama3.2:1b",
            "timeout": 60
        },
        "modal": {
            "model": "mistral-7b",
            "timeout": 60
        }
    }
}


def ensure_config_dir():
    """
    Ensure the configuration directory exists.
    """
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR, exist_ok=True)


def get_llm_config() -> Dict[str, Any]:
    """
    Get the LLM configuration from the config file.
    If the config file doesn't exist, create it with default values.
    
    Returns:
        Dict[str, Any]: The LLM configuration
    """
    ensure_config_dir()
    
    if not os.path.exists(CONFIG_FILE):
        # Create default config file
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error loading LLM config: {e}")
        return DEFAULT_CONFIG


def save_llm_config(config: Dict[str, Any]) -> bool:
    """
    Save the LLM configuration to the config file.
    
    Args:
        config (Dict[str, Any]): The configuration to save
        
    Returns:
        bool: True if successful, False otherwise
    """
    ensure_config_dir()
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving LLM config: {e}")
        return False


def get_provider_config(provider_name: str) -> Optional[Dict[str, Any]]:
    """
    Get the configuration for a specific provider.
    
    Args:
        provider_name (str): Name of the provider
        
    Returns:
        Optional[Dict[str, Any]]: Provider configuration or None if not found
    """
    config = get_llm_config()
    providers = config.get("providers", {})
    return providers.get(provider_name)


def get_default_provider() -> str:
    """
    Get the name of the default LLM provider.
    
    Returns:
        str: Name of the default provider
    """
    config = get_llm_config()
    return config.get("default_provider", "ollama")


def set_default_provider(provider_name: str) -> bool:
    """
    Set the default LLM provider.
    
    Args:
        provider_name (str): Name of the provider to set as default
        
    Returns:
        bool: True if successful, False otherwise
    """
    config = get_llm_config()
    
    # Ensure the provider exists in the config
    if provider_name not in config.get("providers", {}):
        return False
    
    config["default_provider"] = provider_name
    return save_llm_config(config)


def update_provider_config(provider_name: str, provider_config: Dict[str, Any]) -> bool:
    """
    Update the configuration for a specific provider.
    
    Args:
        provider_name (str): Name of the provider
        provider_config (Dict[str, Any]): New provider configuration
        
    Returns:
        bool: True if successful, False otherwise
    """
    config = get_llm_config()
    
    if "providers" not in config:
        config["providers"] = {}
    
    config["providers"][provider_name] = provider_config
    return save_llm_config(config)