# agent_piment_bleu/llm/langchain_modal_chat.py
from typing import Any, List, Optional, Dict
from langchain_core.callbacks.manager import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, AIMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatResult, ChatGeneration

from agent_piment_bleu.llm.modal_provider import ModalProvider # Your existing provider
from agent_piment_bleu.logger import get_logger

class LangchainModalChat(BaseChatModel):
    modal_provider: ModalProvider
    logger = get_logger()

    @property
    def _llm_type(self) -> str:
        return "modal-chat-via-custom-provider"

    def _convert_lc_messages_to_dict(self, messages: List[BaseMessage]) -> List[Dict[str, str]]:
        history = []
        for msg in messages:
            if isinstance(msg, HumanMessage):
                history.append({"role": "user", "content": msg.content})
            elif isinstance(msg, AIMessage):
                history.append({"role": "assistant", "content": msg.content})
            elif isinstance(msg, SystemMessage):
                history.append({"role": "system", "content": msg.content})
            # Add other message types if needed (ToolMessage, etc.)
            else:
                self.logger.warning(f"Unsupported message type: {type(msg)}")
        return history

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None, # Note: stop sequences might be hard to enforce with a generic HF model via transformers
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.logger.info(f"LangchainModalChat: _generate called with {len(messages)} messages.")
        provider_messages = self._convert_lc_messages_to_dict(messages)

        # The actual call to your ModalProvider
        # The ModalProvider's generate_with_context expects prompt and context separately.
        # For a chat model, it's cleaner if ModalProvider's main generation method takes a list of messages.
        # Let's assume we'll adapt ModalProvider or use its generate_with_context appropriately.

        # If provider_messages contains a system message, extract it for context.
        # Langchain agents usually put system messages first.
        system_context = []
        user_prompts_and_responses = []

        current_prompt = ""
        final_context_for_provider = []

        if provider_messages:
            # Separate system, user, assistant messages
            # The modal_provider.generate_with_context takes a final 'prompt' and a 'context' list.
            # We need to format Langchain's list of BaseMessages into that.
            # A simple approach: last user message is 'prompt', everything before is 'context'.

            # Let's simplify: assume the modal provider's `generate_chat_completion` (or similar)
            # directly takes the `provider_messages` list.
            # This requires the ModalProvider's `generate` or `generate_with_context`
            # to be adapted to take a list of message dicts if it doesn't already.
            # The updated ModalProvider above uses `messages` directly.

            response_text = self.modal_provider.generate_with_context(
                prompt="", # This will be ignored if messages are passed directly
                context=provider_messages, # Pass the whole list
                **kwargs
            )
        else:
            response_text = "Error: No messages provided to LangchainModalChat."


        ai_message = AIMessage(content=response_text)
        generation = ChatGeneration(message=ai_message)
        self.logger.info(f"LangchainModalChat: Response received: {response_text[:100]}...")
        return ChatResult(generations=[generation])

    # Implement _astream, _stream if needed for streaming responses.
    # For now, synchronous _generate is sufficient for many agent use cases.