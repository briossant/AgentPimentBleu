"""
AgentPimentBleu - Logger module

This module provides a Logger class that implements the singleton pattern
for managing a logging box in the UI.
"""

from typing import List, Optional
import datetime
import inspect
import os


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

    def _format_log(self, message: str, level: str, caller_info=None) -> str:
        """
        Format a log message with timestamp, level, and caller information.

        Args:
            message (str): The log message
            level (str): The log level (INFO, WARNING, ERROR, DEBUG)
            caller_info (tuple, optional): Tuple containing (function_name, filename, line_number)

        Returns:
            str: Formatted log message
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if caller_info:
            function_name, filename, line_number = caller_info
            return f"[{timestamp}] [{level}] [{function_name}] {message}"
        else:
            return f"[{timestamp}] [{level}] {message}"

    def _update_ui(self):
        """Update the UI logging box if a callback is set."""
        if self._ui_callback:
            log_content = "\n".join(self._logs)
            self._ui_callback(log_content)

    def _get_caller_info(self, stack_level=2):
        """
        Get information about the calling function.

        Args:
            stack_level (int): How many levels up the stack to look (2 is the caller of the logging method)

        Returns:
            tuple: (function_name, filename, line_number)
        """
        frame = inspect.currentframe()
        # Go up the stack to the caller of the logging method
        for _ in range(stack_level):
            if frame.f_back is not None:
                frame = frame.f_back
            else:
                break

        function_name = frame.f_code.co_name
        filename = os.path.basename(frame.f_code.co_filename)
        line_number = frame.f_lineno

        return (function_name, filename, line_number)

    def info(self, message: str):
        """Log an informational message."""
        caller_info = self._get_caller_info()
        log_entry = self._format_log(message, "INFO", caller_info)
        self._logs.insert(0, log_entry)
        self._update_ui()
        return log_entry

    def warning(self, message: str):
        """Log a warning message."""
        caller_info = self._get_caller_info()
        log_entry = self._format_log(message, "WARNING", caller_info)
        self._logs.insert(0, log_entry)
        self._update_ui()
        return log_entry

    def error(self, message: str):
        """Log an error message."""
        caller_info = self._get_caller_info()
        log_entry = self._format_log(message, "ERROR", caller_info)
        self._logs.insert(0, log_entry)
        self._update_ui()
        return log_entry

    def debug(self, message: str):
        """Log a debug message."""
        caller_info = self._get_caller_info()
        log_entry = self._format_log(message, "DEBUG", caller_info)
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
