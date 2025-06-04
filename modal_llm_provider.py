# modal_llm_app.py
import modal
import os
import pathlib # For path manipulation

# --- Configuration ---
DEFAULT_MODEL_NAME = "mistralai/Devstral-Small-2505"
DEFAULT_MODEL_CACHE_DIR = "/model_cache" # Inside the Modal container

stub = modal.App(name="devstral-llm-provider")

app_image = (
    modal.Image.debian_slim(python_version="3.10")
    .pip_install(
        "torch",
        "transformers",
        "accelerate",
        "bitsandbytes",
        "sentencepiece",
        "einops",
        "tiktoken",
        "huggingface_hub", # For hf_hub_download
    )
    .env({"HF_HOME": DEFAULT_MODEL_CACHE_DIR, "HF_HUB_CACHE": DEFAULT_MODEL_CACHE_DIR})
)

@stub.cls(
    image=app_image,
    gpu="A10G",
    scaledown_window=300,
    timeout=900, # Increased timeout for potential downloads
    min_containers=0,
    max_containers=3,
)
class DevstralLLM:
    model_name: str
    model_cache_dir: pathlib.Path # Use pathlib.Path for easier joining

    @modal.enter()
    def load_resources(self):
        from transformers import AutoTokenizer, AutoModelForCausalLM
        from huggingface_hub import hf_hub_download, HfFileSystem
        import torch

        self.model_name = DEFAULT_MODEL_NAME
        self.model_cache_dir = pathlib.Path(DEFAULT_MODEL_CACHE_DIR)
        self.model_cache_dir.mkdir(parents=True, exist_ok=True) # Ensure cache dir exists

        print(f"Container starting. Attempting to load resources for model: {self.model_name}")
        print(f"Using cache directory: {self.model_cache_dir}")

        # --- Tokenizer Loading Strategy ---
        print(f"Attempting to load tokenizer for {self.model_name}...")
        tokenizer_path_in_cache = self.model_cache_dir / "tokenizer" / self.model_name.split("/")[-1]
        tokenizer_path_in_cache.mkdir(parents=True, exist_ok=True)
        sentencepiece_model_filename = "tokenizer.model" # Common name for SentencePiece vocab file
        expected_sp_model_path = tokenizer_path_in_cache / sentencepiece_model_filename

        try:
            # Check if tokenizer.model already exists from a previous download by from_pretrained
            # This part is a bit tricky because from_pretrained might put it in a different subfolder.
            # Let's first try to download the specific sentencepiece file if it exists on the hub.
            print(f"Attempting to directly download '{sentencepiece_model_filename}' for {self.model_name} to {expected_sp_model_path}")
            try:
                # See if tokenizer.model is a top-level file for this repo
                hf_hub_download(
                    repo_id=self.model_name,
                    filename=sentencepiece_model_filename,
                    local_dir=tokenizer_path_in_cache,
                    local_dir_use_symlinks=False, # Avoid symlinks inside Modal image
                    cache_dir=self.model_cache_dir / "hub", # Separate hub cache within our main cache
                )
                print(f"Successfully downloaded '{sentencepiece_model_filename}' to {expected_sp_model_path}")
            except Exception as download_err:
                print(f"Could not directly download '{sentencepiece_model_filename}': {download_err}. "
                      f"This is okay if it's part of the main snapshot.")

            # Now try loading the tokenizer from the model_name identifier,
            # which should use the cache_dir where files (including tokenizer.model) are expected.
            # The Transformers library should handle finding tokenizer.model within the snapshot.
            print(f"Attempting AutoTokenizer.from_pretrained for {self.model_name} using cache_dir: {self.model_cache_dir}")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                cache_dir=self.model_cache_dir, # Main cache for the whole model snapshot
                trust_remote_code=True,
                local_files_only=False, # Allow download
                # use_fast=True, # Prefer fast tokenizers
            )
            print(f"AutoTokenizer.from_pretrained for {self.model_name} successful.")
            # Verify the tokenizer has a vocab_file attribute and it's a string
            if hasattr(self.tokenizer, 'vocab_file') and isinstance(self.tokenizer.vocab_file, str):
                print(f"Tokenizer vocab_file: {self.tokenizer.vocab_file}")
            else:
                print(f"Warning: Tokenizer vocab_file attribute missing or not a string. Vocab file: {getattr(self.tokenizer, 'vocab_file', 'N/A')}")


        except Exception as e_tokenizer:
            print(f"CRITICAL: Tokenizer loading failed for {self.model_name}: {e_tokenizer}")
            try:
                print(f"Contents of {self.model_cache_dir}:")
                for item in self.model_cache_dir.rglob('*'): # Recursively list all files
                    print(f"  - {item}")
            except Exception as list_e:
                print(f"Could not list contents of {self.model_cache_dir}: {list_e}")
            raise e_tokenizer


        # --- Model Loading ---
        print(f"Loading model {self.model_name}...")
        try:
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch.bfloat16,
                device_map="auto",
                cache_dir=self.model_cache_dir, # Use the same cache dir
                trust_remote_code=True,
                local_files_only=False,
            )
            print("Model loaded successfully.")
        except Exception as e_model:
            print(f"Error loading model: {e_model}")
            raise e_model
        print("Resources loaded.")

    def _generate_response(self, messages_list: list[dict], generation_kwargs: dict) -> str:
        # ... (This part should be okay if tokenizer and model load)
        if not hasattr(self, 'model') or not self.model or not hasattr(self, 'tokenizer') or not self.tokenizer:
            error_msg = "CRITICAL: Model or tokenizer not loaded in _generate_response!"
            print(error_msg)
            raise RuntimeError(error_msg)

        try:
            tokenized_chat = self.tokenizer.apply_chat_template(
                messages_list, tokenize=True, add_generation_prompt=True, return_tensors="pt"
            ).to(self.model.device)
        except Exception as e_template:
            print(f"Error applying chat template: {e_template}. Falling back to simple concatenation.")
            prompt_text = "\n".join([f"{msg['role']}: {msg['content']}" for msg in messages_list])
            if messages_list and messages_list[-1]["role"] != "assistant":
                 prompt_text += "\nassistant:"
            tokenized_chat = self.tokenizer(prompt_text, return_tensors="pt").input_ids.to(self.model.device)

        default_gen_params = {
            "max_new_tokens": 1024, "temperature": 0.7, "do_sample": True,
            "eos_token_id": self.tokenizer.eos_token_id,
            "pad_token_id": self.tokenizer.eos_token_id
        }
        final_gen_params = {**default_gen_params, **generation_kwargs}

        print(f"Generating response with params: {final_gen_params}")
        output_ids = self.model.generate(tokenized_chat, **final_gen_params)
        response_text = self.tokenizer.decode(output_ids[0][tokenized_chat.shape[-1]:], skip_special_tokens=True)
        print(f"Generated response snippet: {response_text[:150]}...")
        return response_text


    @modal.method()
    async def generate_chat_completion(self, messages: list[dict], generation_params: dict = None) -> str:
        if generation_params is None: generation_params = {}
        print(f"generate_chat_completion called with {len(messages)} messages.")
        return self._generate_response(messages, generation_params)

@stub.local_entrypoint()
async def main_local():
    # ... (local entrypoint remains the same)
    print("Running local entrypoint to test Modal app...")
    messages_example = [
        {"role": "system", "content": "You are a concise and helpful AI assistant specializing in technology."},
        {"role": "user", "content": "Explain the concept of serverless computing in one sentence."},
    ]
    try:
        llm_handle = DevstralLLM()
        response = await llm_handle.generate_chat_completion.remote.aio(messages=messages_example)
        print("\n--- Response from Modal ---")
        print(response)
        print("---------------------------\n")
    except Exception as e:
        print(f"Error during local entrypoint test: {e}")
        import traceback
        traceback.print_exc()