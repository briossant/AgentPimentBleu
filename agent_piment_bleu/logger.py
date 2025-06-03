"""
AgentPimentBleu - Logger module

This module provides a Logger class that implements the singleton pattern
for managing a logging box in the UI.
"""

from typing import List, Optional
import datetime


class Logger:
    """
    Logger class implementing the singleton pattern.
    Manages a logging box in the UI and provides methods for logging messages.
    """
    _instance: Optional['Logger'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._logs = []
            cls._instance._ui_callback = None
        return cls._instance

    def __init__(self):
        # The __init__ method will be called every time Logger() is called,
        # but we only want to initialize once, so we check if _logs exists
        if not hasattr(self, '_logs'):
            self._logs = []
            self._ui_callback = None

    def set_ui_callback(self, callback):
        """
        Set the callback function that updates the UI logging box.

        Args:
            callback: Function that takes a string parameter (log content)
        """
        self._ui_callback = callback

    def _format_log(self, message: str, level: str) -> str:
        """Format a log message with timestamp and level."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"[{timestamp}] [{level}] {message}"

    def _update_ui(self):
        """Update the UI logging box if a callback is set."""
        if self._ui_callback:
            log_content = "\n".join(self._logs)
            self._ui_callback(log_content)

    def info(self, message: str):
        """Log an informational message."""
        log_entry = self._format_log(message, "INFO")
        self._logs.insert(0, log_entry)
        self._update_ui()
        return log_entry

    def warning(self, message: str):
        """Log a warning message."""
        log_entry = self._format_log(message, "WARNING")
        self._logs.insert(0, log_entry)
        self._update_ui()
        return log_entry

    def error(self, message: str):
        """Log an error message."""
        log_entry = self._format_log(message, "ERROR")
        self._logs.insert(0, log_entry)
        self._update_ui()
        return log_entry

    def debug(self, message: str):
        """Log a debug message."""
        log_entry = self._format_log(message, "DEBUG")
        self._logs.insert(0, log_entry)
        self._update_ui()
        return log_entry

    def clear(self):
        """Clear all logs."""
        self._logs = []
        self._update_ui()

    def get_logs(self) -> List[str]:
        """Get all logs as a list of strings."""
        return self._logs.copy()

    def get_logs_text(self) -> str:
        """Get all logs as a single string."""
        return "\n".join(self._logs)


# Convenience function to get the logger instance
def get_logger() -> Logger:
    """Get the singleton Logger instance."""
    return Logger()
