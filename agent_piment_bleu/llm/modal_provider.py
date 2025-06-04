# agent_piment_bleu/llm/modal_provider.py
import json
from typing import Dict, List, Any, Optional
import modal # Make sure modal client is importable

from agent_piment_bleu.llm.base import LLMProvider
from agent_piment_bleu.llm.config import get_provider_config, get_llm_config # Ensure get_llm_config is available
from agent_piment_bleu.logger import get_logger

class ModalProvider(LLMProvider):
    """
    LLM provider implementation for a deployed Modal app.
    """

    def __init__(self, **kwargs):
        self.logger = get_logger()
        config = get_llm_config().get("providers", {}).get("modal", {}) # Get full modal config

        # Configurable via llm_config.json or passed as kwargs
        self._modal_app_name = kwargs.get("modal_app_name", config.get("modal_app_name", "devstral-llm-provider"))
        self._modal_function_name = kwargs.get("modal_function_name", config.get("modal_function_name", "DevstralLLM.generate_chat_completion"))

        # _model here refers to the conceptual model identifier,
        # the actual model (e.g., "mistralai/Devstral-Small-2505") is defined in the Modal app.
        self._model = kwargs.get("model", config.get("model", "devstral-via-modal"))
        self._timeout = kwargs.get("timeout", config.get("timeout", 120)) # Increased timeout for network calls

        self._function_handle = None
        self._initialized = False
        self.logger.info(f"ModalProvider configured for app '{self._modal_app_name}' and function '{self._modal_function_name}'")

    def _ensure_initialized(self):
        if self._initialized and self._function_handle:
            return True
        try:
            self.logger.info(f"Looking up Modal function: {self._modal_app_name} / {self._modal_function_name}")
            # self._function_handle = modal.Function.lookup(self._modal_app_name, self._modal_function_name) # This syntax might be tricky if function_name includes class
            # A more robust way if the function is part of a class deployed with @stub.cls
            # is to look up the class and then access the method.
            # However, for simplicity, we assume the function can be called directly if named appropriately in the config.
            # Let's assume the function is exposed directly or we call the class method handle
            if "." in self._modal_function_name: # e.g. "ClassName.method_name"
                 cls_name, meth_name = self._modal_function_name.split(".", 1)
                 deployed_class = modal.Cls.lookup(self._modal_app_name, cls_name)
                 self._function_handle = getattr(deployed_class, meth_name) # This gives a method handle
            else: # e.g. "my_generate_function"
                 self._function_handle = modal.Function.lookup(self._modal_app_name, self._modal_function_name)


            if self._function_handle:
                self.logger.info("Successfully connected to deployed Modal function.")
                self._initialized = True
                return True
            else:
                self.logger.error("Failed to look up Modal function.")
                return False
        except Exception as e:
            self.logger.error(f"Error initializing Modal connection: {e}")
            self._initialized = False
            return False

    def _prepare_messages(self, prompt: str, context: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, str]]:
        messages = []
        if context:
            messages.extend(context)
        messages.append({"role": "user", "content": prompt})
        return messages

    def generate(self, prompt: str, **kwargs) -> str:
        if not self._ensure_initialized():
            return "Error: Modal Provider not initialized or function not found."

        messages = self._prepare_messages(prompt)
        generation_params = {
            "temperature": kwargs.get("temperature", 0.7),
            "max_new_tokens": kwargs.get("max_tokens", kwargs.get("max_new_tokens", 1024)),
            # Add other relevant params from kwargs if your Modal function supports them
        }
        try:
            self.logger.info(f"Calling Modal function with {len(messages)} messages.")
            # If self._function_handle is a method of a class, it needs to be instantiated first if it's not a static/class method.
            # modal.Cls.lookup(...).method.remote(...) is the pattern if it's a class method
            # If it's just modal.Function.lookup, then self._function_handle.remote(...)
            if isinstance(self._function_handle, modal.functions._FunctionHandle): # It's a plain function
                response = self._function_handle.remote(messages=messages, generation_params=generation_params)
            elif hasattr(self._function_handle, 'remote'): # It's likely a method handle from a Cls
                response = self._function_handle.remote(messages=messages, generation_params=generation_params)
            else:
                self.logger.error("Modal function handle is not callable with .remote().")
                return "Error: Modal function handle misconfiguration."

            self.logger.info("Received response from Modal.")
            return response
        except Exception as e:
            self.logger.error(f"Error calling Modal function: {e}")
            return f"Error calling Modal: {str(e)}"

    def generate_with_context(self,
                             prompt: str,
                             context: List[Dict[str, str]],
                             **kwargs) -> str:
        if not self._ensure_initialized():
            return "Error: Modal Provider not initialized or function not found."

        messages = self._prepare_messages(prompt, context)
        generation_params = {
            "temperature": kwargs.get("temperature", 0.7),
            "max_new_tokens": kwargs.get("max_tokens", kwargs.get("max_new_tokens", 1024)),
        }
        try:
            self.logger.info(f"Calling Modal function with context ({len(messages)} messages).")
            if isinstance(self._function_handle, modal.functions._FunctionHandle):
                response = self._function_handle.remote(messages=messages, generation_params=generation_params)
            elif hasattr(self._function_handle, 'remote'):
                response = self._function_handle.remote(messages=messages, generation_params=generation_params)
            else:
                self.logger.error("Modal function handle is not callable with .remote().")
                return "Error: Modal function handle misconfiguration."
            self.logger.info("Received response with context from Modal.")
            return response
        except Exception as e:
            self.logger.error(f"Error calling Modal function with context: {e}")
            return f"Error calling Modal with context: {str(e)}"

    @property
    def provider_name(self) -> str:
        return "modal"

    @property
    def model_name(self) -> str:
        # This now refers to the conceptual name used in your agent,
        # not necessarily the Hugging Face model name directly.
        return self._model

    def is_available(self) -> bool:
        # Check if we can connect to the deployed Modal function
        return self._ensure_initialized()

    # analyze_code method from base class can be used as is,
    # or you can customize its prompt for Devstral if needed.