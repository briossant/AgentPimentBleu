"""
Langchain-based Security Agent

This module implements a security agent using Langchain's tool-based agent architecture.
"""

import json
import re
import sys
from typing import Dict, List, Any, Optional

try:
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain.prompts import PromptTemplate
    try:
        from langchain_ollama import ChatOllama
    except ImportError:
        from langchain_community.chat_models import ChatOllama
        print("Warning: Using deprecated ChatOllama from langchain_community. Please install langchain-ollama.", file=sys.stderr)
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("Error: Required packages not found. Please install the required dependencies:", file=sys.stderr)
    print("  pip install langchain langchain-community langchain-ollama", file=sys.stderr)
    print("These packages are required for the Langchain-based agent functionality.", file=sys.stderr)

from agent_piment_bleu.agent.tools import ProjectContext, get_tools
from agent_piment_bleu.logger import get_logger
from agent_piment_bleu.llm.base import LLMProvider
from agent_piment_bleu.llm.langchain_modal_chat import LangchainModalChat # Adjust path if needed


class SecurityAgent:
    """
    Security agent using Langchain's tool-based agent architecture.

    This agent uses an LLM to analyze vulnerabilities by exploring the codebase
    using a set of tools. It follows a more flexible approach, allowing the LLM 
    to decide which tools to use and in what order.
    """

    def __init__(self, llm_provider: LLMProvider, repo_path: str):
        """
        Initialize the security agent.

        Args:
            llm_provider (LLMProvider): LLM provider instance
            repo_path (str): Path to the repository to analyze
        """
        self.logger = get_logger()

        # Check if Langchain is available
        if not LANGCHAIN_AVAILABLE:
            self.logger.error("Langchain is not available. Please install the required dependencies.")
            self.logger.error("  pip install langchain langchain-community")
            self.agent_executor = None
            self.conversation_history = []
            return

        # Initialize project context
        self.project_ctx = ProjectContext(repo_path, self.logger)

        # Get tools for the agent
        self.tools = get_tools(self.project_ctx)

        # Create a Langchain-compatible LLM from the provider
        self.llm = self._create_langchain_llm(llm_provider)

        # Create the agent prompt
        self.prompt = self._create_agent_prompt()

        # If Langchain is not available, we can't create the agent
        if not LANGCHAIN_AVAILABLE or self.prompt is None:
            self.agent = None
            self.agent_executor = None
            return

        # Create the agent
        self.agent = create_react_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=self.prompt
        )

        # Create the agent executor
        self.agent_executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=15  # Limit the number of iterations to prevent infinite loops
        )

        # Store conversation history
        self.conversation_history = []

    def _create_langchain_llm(self, llm_provider: LLMProvider):
        """
        Create a Langchain-compatible LLM from the provider.

        Args:
            llm_provider (LLMProvider): LLM provider instance

        Returns:
            A Langchain-compatible LLM
        """
        # Check if Langchain is available
        if not LANGCHAIN_AVAILABLE:
            self.logger.error("Cannot create Langchain LLM: Langchain is not available")
            return llm_provider

        if hasattr(llm_provider, 'provider_name') and llm_provider.provider_name == 'ollama':
            # Create a ChatOllama instance using the configuration from the provided LLM provider
            self.logger.info(f"Creating ChatOllama instance with model: {llm_provider.model_name}")
            return ChatOllama(
                model=llm_provider.model_name,
                base_url=llm_provider._base_url,
                temperature=0  # Low temperature for tool use
            )
        elif hasattr(llm_provider, 'provider_name') and llm_provider.provider_name == 'modal':
            self.logger.info(f"Creating LangchainModalChat wrapper for Modal provider with model: {llm_provider.model_name}")
            return LangchainModalChat(modal_provider=llm_provider)
        else:
            # For other providers, we would need to implement similar adapters
            # For now, we'll just return the provider and hope it's compatible
            provider_name = getattr(llm_provider, 'provider_name', 'unknown')
            self.logger.warning(
                f"Using provider {provider_name} directly. "
                "This may not be compatible with Langchain. "
                "Consider implementing a Langchain-specific adapter for this provider."
            )
            return llm_provider

    def _create_agent_prompt(self):
        """
        Create the prompt for the agent.

        Returns:
            PromptTemplate: The prompt template for the agent, or None if Langchain is not available
        """
        # Check if Langchain is available
        if not LANGCHAIN_AVAILABLE:
            self.logger.error("Cannot create agent prompt: Langchain is not available")
            return None

        template = """You are a security expert analyzing a codebase to determine if it's affected by a vulnerability.

Your task is to analyze the vulnerability information provided and explore the codebase to determine:
1. If the project is affected by the vulnerability
2. The severity of the vulnerability for this specific project
3. Which parts of the code are impacted
4. How to fix the vulnerability

You have access to the following tools:

{tools}

Thought: Do I need to use a tool? Yes
Action: The action to take. **Should be one of [{tool_names}]**
Action Input: The input to the action
Observation: The result of the action

(This Thought/Action/Action Input/Observation can repeat N times)

When you have gathered enough information, you MUST provide a final answer in the following JSON format:
```json
{{
    "project_severity": "critical|high|medium|low|info",
    "is_project_impacted": true|false,
    "impacted_code": "Description of the impacted code patterns or files",
    "proposed_fix": "Detailed steps to fix the vulnerability",
    "explanation": "Comprehensive explanation of your analysis and findings"
}}
```

Make sure your final answer is ONLY the JSON object, with no additional text before or after.

Vulnerability information:
{vulnerability_text}

Begin!

{agent_scratchpad}
"""

        return PromptTemplate.from_template(template)

    def _format_vulnerability_text(self, vulnerability: Dict[str, Any]) -> str:
        """
        Format the vulnerability information as text.

        Args:
            vulnerability (Dict[str, Any]): Vulnerability information

        Returns:
            str: Formatted vulnerability text
        """
        # Use existing vulnerability_text if available
        if 'vulnerability_text' in vulnerability and vulnerability['vulnerability_text']:
            return vulnerability['vulnerability_text']

        # Create a text representation if not already present
        package_name = vulnerability.get('package', vulnerability.get('package_name', ''))
        vulnerability_text = f"""
Package: {package_name}
Version: {vulnerability.get('version', 'unknown')}
Severity: {vulnerability.get('severity', 'medium')}
Title: {vulnerability.get('message', vulnerability.get('title', 'Unknown vulnerability'))}
CVE: {vulnerability.get('cve', 'N/A')}
"""

        # Add any additional information if available
        if 'description' in vulnerability:
            vulnerability_text += f"Description: {vulnerability.get('description')}\n"

        if 'code_snippet' in vulnerability:
            language = vulnerability.get('language', '')
            vulnerability_text += f"""
Code Snippet:
```{language}
{vulnerability.get('code_snippet')}
```
"""

        return vulnerability_text

    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a vulnerability using the Langchain agent.

        Args:
            vulnerability (Dict[str, Any]): Vulnerability information

        Returns:
            Dict[str, Any]: Analysis results
        """
        self.logger.info(f"Analyzing vulnerability: {vulnerability.get('cve', 'Unknown CVE')}")

        # Check if Langchain is available
        if not LANGCHAIN_AVAILABLE:
            self.logger.error("Cannot analyze vulnerability: Langchain is not available")
            error_message = (
                "Langchain is required for vulnerability analysis but is not installed. "
                "Please install the required dependencies with: "
                "pip install langchain langchain-community"
            )

            # Return a default result indicating the dependency issue
            default_result = {
                'project_severity': vulnerability.get('severity', 'unknown'),
                'is_project_impacted': True,
                'impacted_code': "Could not determine impacted code due to missing dependencies.",
                'proposed_fix': f"Update the affected package to a patched version.",
                'explanation': error_message,
                'llm_analysis': {
                    'is_vulnerable': True,
                    'confidence': 'low',
                    'impact': vulnerability.get('severity', 'unknown'),
                    'explanation': error_message,
                    'remediation': f"Update the affected package to a patched version.",
                    'provider': 'unknown',
                    'model': 'unknown'
                }
            }

            vulnerability.update(default_result)
            return vulnerability

        # Format the vulnerability text
        vulnerability_text = self._format_vulnerability_text(vulnerability)

        # Reset conversation history
        self.conversation_history = []

        # Run the agent
        try:
            self.logger.info("Running Langchain agent for vulnerability analysis")
            result = self.agent_executor.invoke({
                "vulnerability_text": vulnerability_text
            })

            # Store the agent's thought process
            self.conversation_history = result.get('intermediate_steps', [])

            # Extract the final answer
            output = result.get('output', '')

            # Parse the JSON output
            analysis_result = self._parse_json_output(output)

            # Convert is_project_impacted to boolean if it's a string
            if isinstance(analysis_result.get('is_project_impacted'), str):
                is_impacted = analysis_result.get('is_project_impacted', '').lower()
                analysis_result['is_project_impacted'] = is_impacted == 'true'

            # Update the vulnerability with the analysis results
            vulnerability.update(analysis_result)

            # Add llm_analysis field for compatibility with the existing system
            vulnerability['llm_analysis'] = {
                'is_vulnerable': analysis_result.get('is_project_impacted', False),
                'confidence': 'medium',
                'impact': analysis_result.get('project_severity', 'unknown'),
                'explanation': analysis_result.get('explanation', ''),
                'remediation': analysis_result.get('proposed_fix', ''),
                'provider': getattr(self.llm, 'provider_name', 'langchain'),
                'model': getattr(self.llm, 'model_name', str(self.llm))
            }

            self.logger.info("Vulnerability analysis completed successfully")

            return vulnerability

        except Exception as e:
            self.logger.error(f"Error during vulnerability analysis: {e}")

            # Return a default result in case of error
            default_result = {
                'project_severity': vulnerability.get('severity', 'unknown'),
                'is_project_impacted': True,
                'impacted_code': "Could not determine impacted code due to an error.",
                'proposed_fix': f"Update the affected package to a patched version.",
                'explanation': f"An error occurred during analysis: {str(e)}",
                'llm_analysis': {
                    'is_vulnerable': True,
                    'confidence': 'low',
                    'impact': vulnerability.get('severity', 'unknown'),
                    'explanation': f"An error occurred during analysis: {str(e)}",
                    'remediation': f"Update the affected package to a patched version.",
                    'provider': getattr(self.llm, 'provider_name', 'langchain'),
                    'model': getattr(self.llm, 'model_name', str(self.llm))
                }
            }

            vulnerability.update(default_result)
            return vulnerability

    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """
        Parse the JSON output from the agent.

        Args:
            output (str): The output from the agent

        Returns:
            Dict[str, Any]: Parsed JSON output
        """
        # If output is empty or None, return a default result
        if not output:
            self.logger.warning("Empty output from agent")
            return {
                'project_severity': 'unknown',
                'is_project_impacted': True,
                'impacted_code': "Could not determine impacted code.",
                'proposed_fix': "Update the affected package to a patched version.",
                'explanation': "No output was provided by the agent."
            }

        # Try to extract JSON from the output
        json_match = re.search(r'```json\s*(.*?)\s*```', output, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find JSON without the markdown code block
            json_match = re.search(r'({[\s\S]*})', output)
            if json_match:
                json_str = json_match.group(1)
            else:
                self.logger.warning("Could not extract JSON from agent output")
                return {
                    'project_severity': 'unknown',
                    'is_project_impacted': True,
                    'impacted_code': "Could not determine impacted code.",
                    'proposed_fix': "Update the affected package to a patched version.",
                    'explanation': "Could not parse the agent's output."
                }

        # Try to parse the JSON
        try:
            result = json.loads(json_str)
            return result
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing JSON output: {e}")
            return {
                'project_severity': 'unknown',
                'is_project_impacted': True,
                'impacted_code': "Could not determine impacted code.",
                'proposed_fix': "Update the affected package to a patched version.",
                'explanation': f"Could not parse the agent's output as JSON: {str(e)}"
            }
