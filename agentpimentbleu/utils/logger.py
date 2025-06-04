"""
AgentPimentBleu - Logger module

This module provides a LoggerSingleton class that implements the singleton pattern
for consistent logging across the application.
"""

import logging
from typing import Optional


class LoggerSingleton:
    """
    Logger class implementing the singleton pattern.
    Ensures only one logger instance is created for the application.
    """
    _instance: Optional['LoggerSingleton'] = None
    _logger: Optional[logging.Logger] = None

    def __new__(cls, name: str = "AgentPimentBleu", level: int = logging.INFO):
        if cls._instance is None:
            cls._instance = super(LoggerSingleton, cls).__new__(cls)
            cls._instance._initialize_logger(name, level)
        return cls._instance

    def _initialize_logger(self, name: str, level: int):
        """
        Initialize the logger with a console handler and formatter.

        Args:
            name (str): The name of the logger
            level (int): The logging level (e.g., logging.INFO)
        """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)

        # Clear any existing handlers to avoid duplicates
        if self._logger.handlers:
            self._logger.handlers.clear()

        # Create console handler and set level
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)

        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Add formatter to handler
        console_handler.setFormatter(formatter)

        # Add handler to logger
        self._logger.addHandler(console_handler)

    def set_level(self, level: int):
        """
        Change the logging level.

        Args:
            level (int): The new logging level (e.g., logging.DEBUG, logging.INFO)
        """
        if self._logger:
            self._logger.setLevel(level)
            for handler in self._logger.handlers:
                handler.setLevel(level)

    def debug(self, message: str):
        """Log a debug message."""
        if self._logger:
            self._logger.debug(message)

    def info(self, message: str):
        """Log an informational message."""
        if self._logger:
            self._logger.info(message)

    def warning(self, message: str):
        """Log a warning message."""
        if self._logger:
            self._logger.warning(message)

    def error(self, message: str):
        """Log an error message."""
        if self._logger:
            self._logger.error(message)

    def critical(self, message: str):
        """Log a critical message."""
        if self._logger:
            self._logger.critical(message)


# Convenience function to get the logger instance
def get_logger(name: str = "AgentPimentBleu", level: int = logging.INFO) -> LoggerSingleton:
    """
    Get the singleton Logger instance.

    Args:
        name (str): The name of the logger (default: "AgentPimentBleu")
        level (int): The logging level (default: logging.INFO)

    Returns:
        LoggerSingleton: The singleton logger instance
    """
    return LoggerSingleton(name, level)
