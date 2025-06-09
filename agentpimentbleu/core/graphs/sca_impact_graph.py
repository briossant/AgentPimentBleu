"""
AgentPimentBleu - SCA Impact Graph

This module defines the LangGraph for SCA and impact analysis.
"""

from typing import Dict, List, Optional, TypedDict, Any, Callable
import os
import json
import re
import inspect

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from agentpimentbleu.services.git_service import GitService
from agentpimentbleu.services.dependency_service import DependencyService
from agentpimentbleu.services.rag_service import RAGService
from agentpimentbleu.services.llm_service import LLMService, LLMAuthenticationError, LLMConfigurationError, LLMConnectionError
from agentpimentbleu.config.config import get_settings, Settings
from agentpimentbleu.utils.logger import get_logger
from agentpimentbleu.core.prompts.sca_impact_prompts import (
    CVE_ANALYSIS_PROMPT,
    RAG_QUERY_FORMULATION_PROMPT,
    RAG_RESULTS_ANALYSIS_PROMPT,
    IMPACT_EVALUATION_PROMPT,
    FIX_PROPOSAL_PROMPT
)

logger = get_logger()


def get_current_node_name():
    """
    Helper function to get the name of the current function (node).

    Returns:
        str: The name of the calling function
    """
    # inspect.currentframe().f_code.co_name gives the name of *this* function
    # f_back gives the caller's frame
    return inspect.currentframe().f_back.f_code.co_name


class ScaImpactState(TypedDict, total=False):
    """
    State for the SCA Impact Graph.
    """
    app_config: Settings  # Application configuration
    repo_source: str  # URL or local path
    cloned_repo_path: Optional[str]  # Path to the cloned repository
    project_type: Optional[str]  # Type of project (e.g., 'python', 'javascript')
    project_manifest_path: Optional[str]  # Path to the manifest file
    project_code_index_path: Optional[str]  # Path to the RAG index
    audit_tool_vulnerabilities: List[Dict]  # Vulnerabilities found by audit tools
    current_vulnerability_idx: int  # Index of the current vulnerability being processed
    current_vulnerability_details: Optional[Dict]  # Details of the current vulnerability
    current_cve_analysis_results: Optional[Dict]  # Results of analyzing the current CVE
    final_vulnerabilities: List[Dict]  # Final list of vulnerabilities with impact assessment
    error_message: Optional[str]  # Error message if any


def prepare_scan_environment(state: ScaImpactState) -> Dict[str, Any]:
    """
    Prepare the scan environment by cloning the repository.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info(f"Preparing scan environment for {state['repo_source']}")

    try:
        git_service = GitService()
        cloned_repo_path = git_service.prepare_repository(state['repo_source'])

        if not cloned_repo_path:
            error_message = f"Failed to prepare repository from {state['repo_source']}"
            logger.error(error_message)
            return {"cloned_repo_path": None, "error_message": error_message}

        logger.info(f"Repository prepared at {cloned_repo_path}")
        return {"cloned_repo_path": cloned_repo_path, "error_message": None}

    except Exception as e:
        error_message = f"Error preparing scan environment: {e}"
        logger.error(error_message)
        return {"cloned_repo_path": None, "error_message": error_message}


def identify_project_and_run_audit_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Identify the project type and run the security audit.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info(f"Identifying project type and running audit for {state['cloned_repo_path']}")

    try:
        if not state['cloned_repo_path']:
            error_message = "No repository path provided"
            logger.error(error_message)
            return {
                "project_type": None,
                "project_manifest_path": None,
                "audit_tool_vulnerabilities": [],
                "error_message": error_message
            }

        dependency_service = DependencyService()

        # Detect project type and manifest
        project_info = dependency_service.detect_project_type_and_manifest(state['cloned_repo_path'])

        if not project_info:
            error_message = f"Could not identify project type for {state['cloned_repo_path']}"
            logger.warning(error_message)
            return {
                "project_type": None,
                "project_manifest_path": None,
                "audit_tool_vulnerabilities": [],
                "error_message": error_message
            }

        project_type, project_manifest_path = project_info

        # Run security audit
        vulnerabilities = dependency_service.run_security_audit(
            state['cloned_repo_path'],
            project_type,
            project_manifest_path
        )

        logger.info(f"Found {len(vulnerabilities)} vulnerabilities")

        return {
            "project_type": project_type,
            "project_manifest_path": project_manifest_path,
            "audit_tool_vulnerabilities": vulnerabilities,
            "error_message": None
        }

    except Exception as e:
        error_message = f"Error identifying project and running audit: {e}"
        logger.error(error_message)
        return {
            "project_type": None,
            "project_manifest_path": None,
            "audit_tool_vulnerabilities": [],
            "error_message": error_message
        }


def build_rag_index_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Build a RAG index for the project code.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info(f"Building RAG index for {state['cloned_repo_path']}")

    try:
        if not state['cloned_repo_path']:
            error_message = "No repository path provided"
            logger.error(error_message)
            return {"project_code_index_path": None, "error_message": error_message}

        # Create a directory for the index
        index_storage_path = os.path.join(
            state['cloned_repo_path'],
            ".agentpimentbleu_index"
        )

        rag_service = RAGService()

        # Build the index
        index = rag_service.build_index_from_project(
            state['cloned_repo_path'],
            index_storage_path
        )

        if not index:
            error_message = f"Failed to build RAG index for {state['cloned_repo_path']}"
            logger.error(error_message)
            return {"project_code_index_path": None, "error_message": error_message}

        logger.info(f"RAG index built at {index_storage_path}")
        return {"project_code_index_path": index_storage_path, "error_message": None}

    except Exception as e:
        error_message = f"Error building RAG index: {e}"
        logger.error(error_message)
        return {"project_code_index_path": None, "error_message": error_message}


def select_next_vulnerability_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Select the next vulnerability to process.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info("Selecting next vulnerability to process")

    try:
        vulnerabilities = state.get('audit_tool_vulnerabilities', [])
        current_idx = state.get('current_vulnerability_idx', -1) + 1

        if not vulnerabilities or current_idx >= len(vulnerabilities):
            logger.info("No more vulnerabilities to process")
            return {
                "current_vulnerability_idx": -1,
                "current_vulnerability_details": None
            }

        current_vulnerability = vulnerabilities[current_idx]
        logger.info(f"Selected vulnerability {current_idx + 1}/{len(vulnerabilities)}: {current_vulnerability.get('package_name', 'unknown')}")

        return {
            "current_vulnerability_idx": current_idx,
            "current_vulnerability_details": current_vulnerability,
            "current_cve_analysis_results": None
        }

    except Exception as e:
        error_message = f"Error selecting next vulnerability: {e}"
        logger.error(error_message)
        return {
            "current_vulnerability_idx": -1,
            "current_vulnerability_details": None,
            "error_message": error_message
        }


def analyze_cve_description_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Analyze the CVE description using LLM.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    node_name = get_current_node_name()
    logger.info(f"Running node: {node_name}")

    try:
        if not state.get('current_vulnerability_details'):
            error_message = f"No current vulnerability details provided in {node_name}"
            logger.error(error_message)
            return {"current_cve_analysis_results": None, "error_message": error_message}

        # Get the current vulnerability details
        vuln_details = state['current_vulnerability_details']

        # Get the scan-specific config from state
        scan_config = state.get('app_config')
        if not scan_config:
            # This should ideally not happen if initial_state is set correctly
            logger.error(f"[{node_name}] App config not found in state. Using global settings.")
            scan_config = get_settings() 

        # Create the LLM service with scan-specific config
        llm_service = LLMService(config=scan_config)

        # Determine active provider based on the scan_config
        active_provider = scan_config.get('active_llm_provider', scan_config.get('default_llm_provider', 'gemini'))

        # Use the imported prompt template
        prompt_template = CVE_ANALYSIS_PROMPT

        # Prepare the input data
        input_data = {
            "package_name": vuln_details.get('package_name', 'unknown'),
            "vulnerable_version": vuln_details.get('vulnerable_version', 'unknown'),
            "cve_ids_list": ", ".join(vuln_details.get('cve_ids', ['unknown'])),
            "tool_advisory_title": vuln_details.get('advisory_title', 'No title available'),
            "tool_advisory_link": vuln_details.get('advisory_link', 'No link available')
        }

        try:
            # Invoke the LLM with the specific provider
            response_str = llm_service.invoke_llm(prompt_template, input_data, provider_name=active_provider)

            # Parse the JSON response
            import json
            import re

            # Extract JSON from the response (in case the LLM adds extra text)
            json_match = re.search(r'({.*})', response_str, re.DOTALL)
            if json_match:
                parsed_response = json.loads(json_match.group(1))
            else:
                # If no JSON found, try to parse the whole response
                parsed_response = json.loads(response_str)

            logger.info(f"[{node_name}] Successfully analyzed CVE for {vuln_details.get('package_name', 'unknown')}")
            return {"current_cve_analysis_results": parsed_response, "error_message": state.get("error_message")}

        except (LLMAuthenticationError, LLMConfigurationError, LLMConnectionError) as llm_critical_error:
            critical_msg = f"LLM_PROVIDER_FAILURE: Critical error in {node_name} with provider '{active_provider}': {llm_critical_error}"
            logger.critical(critical_msg)
            # Return the critical error to halt the graph's LLM processing.
            # Keep any existing critical error if this one is somehow secondary.
            # Get existing error message and check if it's a critical LLM failure
            existing_error = state.get("error_message","")
            return {
                "current_cve_analysis_results": None, 
                "error_message": critical_msg if not (existing_error and existing_error.startswith("LLM_PROVIDER_FAILURE:")) else existing_error
            }
        except json.JSONDecodeError as json_e:
            error_msg_detail = f"Error in {node_name} parsing LLM response: {json_e}. Response was: {response_str[:500]}"
            logger.error(error_msg_detail)
            # This is a parsing error, not a provider failure. Create a fallback.
            # Preserve any existing critical error_message.
            fallback_results = {
                "vulnerability_type": "Unknown (LLM response parsing error)",
                "affected_components": [vuln_details.get('package_name', 'unknown')],
                "exploitation_conditions": f"Could not parse LLM response: {json_e}"
            }
            # To avoid overwriting a critical LLM_PROVIDER_FAILURE with a parsing error message:
            current_overall_error = state.get("error_message")
            if current_overall_error and current_overall_error.startswith("LLM_PROVIDER_FAILURE:"):
                return {"current_cve_analysis_results": fallback_results, "error_message": current_overall_error}
            else:
                # If no critical error yet, we can set a non-critical one for this node or just return fallback.
                # For simplicity, just return fallback and preserve state's error_message.
                return {"current_cve_analysis_results": fallback_results, "error_message": current_overall_error}

    except Exception as e:
        # Generic error within the node
        error_msg_detail = f"Unexpected error in {node_name}: {e}"
        logger.error(error_msg_detail, exc_info=True)
        # Preserve critical error if it exists
        current_overall_error = state.get("error_message")
        if current_overall_error and current_overall_error.startswith("LLM_PROVIDER_FAILURE:"):
            return {"current_cve_analysis_results": None, "error_message": current_overall_error}
        else:
            # If no critical error, set this as the error for the current step/vulnerability
            # This might not halt the entire scan unless made critical.
            return {"current_cve_analysis_results": None, "error_message": error_msg_detail}


def search_codebase_for_impact_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Search the codebase for impact of the vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    node_name = get_current_node_name()
    logger.info(f"Running node: {node_name}")

    try:
        # Check for critical LLM failure from previous nodes
        error_message = state.get("error_message", "")
        if error_message and error_message.startswith("LLM_PROVIDER_FAILURE:"):
            logger.warning(f"[{node_name}] Skipping due to previous LLM provider failure: {state['error_message']}")
            return {"error_message": state.get("error_message")}  # Preserve the error message

        if not state.get('current_vulnerability_details') or not state.get('current_cve_analysis_results'):
            error_message = f"Missing vulnerability details or CVE analysis results in {node_name}"
            logger.error(error_message)
            return {"error_message": error_message}

        if not state.get('project_code_index_path'):
            error_message = f"No RAG index path provided in {node_name}"
            logger.error(error_message)
            return {"error_message": error_message}

        # Get the current vulnerability details and analysis results
        vuln_details = state['current_vulnerability_details']
        cve_analysis = state['current_cve_analysis_results']

        # Get the scan-specific config from state
        scan_config = state.get('app_config')
        if not scan_config:
            logger.error(f"[{node_name}] App config not found in state. Using global settings.")
            scan_config = get_settings()

        # Create the LLM service with scan-specific config and RAG service
        llm_service = LLMService(config=scan_config)
        rag_service = RAGService()

        # Determine active provider based on the scan_config
        active_provider = scan_config.get('active_llm_provider', scan_config.get('default_llm_provider', 'gemini'))

        # Load the RAG index
        index = rag_service.load_index(state['project_code_index_path'])
        if not index:
            error_message = f"Failed to load RAG index from {state['project_code_index_path']}"
            logger.error(error_message)
            return {"error_message": error_message}

        # Use the imported prompt template for formulating RAG queries
        query_formulation_prompt = RAG_QUERY_FORMULATION_PROMPT

        # Prepare the input data for query formulation
        import json

        query_input_data = {
            "package_name": vuln_details.get('package_name', 'unknown'),
            "vulnerable_version": vuln_details.get('vulnerable_version', 'unknown'),
            "cve_analysis_json": json.dumps(cve_analysis)
        }

        # Invoke the LLM to formulate queries
        try:
            query_response = llm_service.invoke_llm(query_formulation_prompt, query_input_data, provider_name=active_provider)

            # Parse the JSON response
            import re

            # Extract JSON from the response (in case the LLM adds extra text)
            json_match = re.search(r'(\[.*\])', query_response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                rag_queries = json.loads(json_str)
            else:
                # If no JSON array found, try to parse the whole response
                rag_queries = json.loads(query_response)

            if not isinstance(rag_queries, list):
                rag_queries = [rag_queries]

            logger.info(f"[{node_name}] Formulated {len(rag_queries)} RAG queries")

        except (LLMAuthenticationError, LLMConfigurationError, LLMConnectionError) as llm_critical_error:
            critical_msg = f"LLM_PROVIDER_FAILURE: Critical error in {node_name} with provider '{active_provider}': {llm_critical_error}"
            logger.critical(critical_msg)
            # Get existing error message and check if it's a critical LLM failure
            existing_error = state.get("error_message","")
            return {
                "current_cve_analysis_results": state.get('current_cve_analysis_results'),
                "error_message": critical_msg if not (existing_error and existing_error.startswith("LLM_PROVIDER_FAILURE:")) else existing_error
            }
        except json.JSONDecodeError as json_e:
            logger.error(f"Error parsing RAG query formulation response: {json_e}")
            # Fallback to basic queries for JSON parsing errors
            package_name = vuln_details.get('package_name', 'unknown')
            affected_components = cve_analysis.get('affected_components', [package_name])
            rag_queries = [f"import {package_name}", f"from {package_name} import"]
            rag_queries.extend([f"using {comp}" for comp in affected_components])
        except Exception as e:
            logger.error(f"Error formulating RAG queries: {e}")
            # Fallback to basic queries for other errors
            package_name = vuln_details.get('package_name', 'unknown')
            affected_components = cve_analysis.get('affected_components', [package_name])
            rag_queries = [f"import {package_name}", f"from {package_name} import"]
            rag_queries.extend([f"using {comp}" for comp in affected_components])

        # Execute RAG queries and collect results
        rag_results = []
        for query in rag_queries:
            try:
                result = rag_service.query_index(index, query)
                rag_results.append(result)
                logger.info(f"Executed RAG query: {query}")
            except Exception as e:
                logger.error(f"Error executing RAG query '{query}': {e}")

        # Use the imported prompt template for analyzing RAG results
        analysis_prompt = RAG_RESULTS_ANALYSIS_PROMPT

        # Prepare the input data for analysis
        analysis_input_data = {
            "package_name": vuln_details.get('package_name', 'unknown'),
            "cve_analysis_json": json.dumps(cve_analysis),
            "rag_queries": json.dumps(rag_queries),
            "rag_search_results": "\n\n".join(rag_results)
        }

        # Invoke the LLM to analyze the RAG results
        try:
            analysis_response = llm_service.invoke_llm(analysis_prompt, analysis_input_data, provider_name=active_provider)

            # Parse the JSON response
            json_match = re.search(r'({.*})', analysis_response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                analysis_results = json.loads(json_str)
            else:
                # If no JSON found, try to parse the whole response
                analysis_results = json.loads(analysis_response)

            logger.info(f"[{node_name}] Successfully analyzed RAG results for {vuln_details.get('package_name', 'unknown')}")

        except (LLMAuthenticationError, LLMConfigurationError, LLMConnectionError) as llm_critical_error:
            critical_msg = f"LLM_PROVIDER_FAILURE: Critical error in {node_name} with provider '{active_provider}': {llm_critical_error}"
            logger.critical(critical_msg)
            # Get existing error message and check if it's a critical LLM failure
            existing_error = state.get("error_message","")
            return {
                "current_cve_analysis_results": state.get('current_cve_analysis_results'),
                "error_message": critical_msg if not (existing_error and existing_error.startswith("LLM_PROVIDER_FAILURE:")) else existing_error
            }
        except json.JSONDecodeError as json_e:
            logger.error(f"Error parsing RAG analysis response: {json_e}")
            # Fallback to a basic analysis for JSON parsing errors
            analysis_results = {
                "usage_found": False,
                "evidence_snippet": None,
                "file_path": None,
                "explanation": f"Error parsing analysis response: {json_e}"
            }
        except Exception as e:
            logger.error(f"Error in RAG analysis: {e}")
            # Fallback to a basic analysis for other errors
            analysis_results = {
                "usage_found": False,
                "evidence_snippet": None,
                "file_path": None,
                "explanation": f"Error analyzing search results: {e}"
            }

        # Update the current_cve_analysis_results
        current_cve_analysis_results = state['current_cve_analysis_results'].copy()
        current_cve_analysis_results.update({
            "rag_queries_formulated": rag_queries,
            "usage_found": analysis_results.get('usage_found', False),
            "evidence_snippet": analysis_results.get('evidence_snippet'),
            "file_path": analysis_results.get('file_path'),
            "explanation": analysis_results.get('explanation', "No explanation provided")
        })

        # Preserve any existing error message that might be critical
        return {
            "current_cve_analysis_results": current_cve_analysis_results,
            "error_message": state.get("error_message")  # Preserve existing error message if any
        }

    except Exception as e:
        error_msg_detail = f"Unexpected error in {node_name}: {e}"
        logger.error(error_msg_detail, exc_info=True)
        # Preserve critical error if it exists
        current_overall_error = state.get("error_message")
        if current_overall_error and current_overall_error.startswith("LLM_PROVIDER_FAILURE:"):
            return {"current_cve_analysis_results": state.get('current_cve_analysis_results'), "error_message": current_overall_error}
        else:
            return {"current_cve_analysis_results": state.get('current_cve_analysis_results'), "error_message": error_msg_detail}


def evaluate_impact_and_danger_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Evaluate the impact and danger of the vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    node_name = get_current_node_name()
    logger.info(f"Running node: {node_name}")

    try:
        # Check for critical LLM failure from previous nodes
        error_message = state.get("error_message", "")
        if error_message and error_message.startswith("LLM_PROVIDER_FAILURE:"):
            logger.warning(f"[{node_name}] Skipping due to previous LLM provider failure: {state['error_message']}")
            return {"error_message": state.get("error_message")}  # Preserve the error message

        if not state.get('current_vulnerability_details') or not state.get('current_cve_analysis_results'):
            error_message = f"Missing vulnerability details or CVE analysis results in {node_name}"
            logger.error(error_message)
            return {"error_message": error_message}

        # Get the current vulnerability details and analysis results
        vuln_details = state['current_vulnerability_details']
        cve_analysis = state['current_cve_analysis_results']

        # Get the scan-specific config from state
        scan_config = state.get('app_config')
        if not scan_config:
            logger.error(f"[{node_name}] App config not found in state. Using global settings.")
            scan_config = get_settings()

        # Create the LLM service with scan-specific config
        llm_service = LLMService(config=scan_config)

        # Determine active provider based on the scan_config
        active_provider = scan_config.get('active_llm_provider', scan_config.get('default_llm_provider', 'gemini'))

        # Use the imported prompt template
        prompt_template = IMPACT_EVALUATION_PROMPT

        # Prepare the input data
        import json

        input_data = {
            "package_name": vuln_details.get('package_name', 'unknown'),
            "cve_ids_list": ", ".join(vuln_details.get('cve_ids', ['unknown'])),
            "cve_analysis_json": json.dumps(cve_analysis),
            "usage_found": cve_analysis.get('usage_found', False),
            "evidence_snippet": cve_analysis.get('evidence_snippet', 'No evidence found'),
            "usage_explanation": cve_analysis.get('explanation', 'No explanation provided')
        }

        # Invoke the LLM
        try:
            response = llm_service.invoke_llm(prompt_template, input_data, provider_name=active_provider)

            # Parse the JSON response
            import re

            # Extract JSON from the response (in case the LLM adds extra text)
            json_match = re.search(r'({.*})', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                impact_assessment = json.loads(json_str)
            else:
                # If no JSON found, try to parse the whole response
                impact_assessment = json.loads(response)

            logger.info(f"[{node_name}] Successfully evaluated impact for {vuln_details.get('package_name', 'unknown')}")

        except (LLMAuthenticationError, LLMConfigurationError, LLMConnectionError) as llm_critical_error:
            critical_msg = f"LLM_PROVIDER_FAILURE: Critical error in {node_name} with provider '{active_provider}': {llm_critical_error}"
            logger.critical(critical_msg)
            # Get existing error message and check if it's a critical LLM failure
            existing_error = state.get("error_message","")
            return {
                "current_cve_analysis_results": state.get('current_cve_analysis_results'),
                "error_message": critical_msg if not (existing_error and existing_error.startswith("LLM_PROVIDER_FAILURE:")) else existing_error
            }
        except json.JSONDecodeError as json_e:
            logger.error(f"Error parsing impact assessment response: {json_e}")
            # Fallback to a basic assessment for JSON parsing errors
            usage_found = cve_analysis.get('usage_found', False)
            impact_assessment = {
                "is_exploitable_in_context": usage_found,
                "impact_summary": "Could not generate impact summary due to parsing error",
                "danger_rating": "Medium" if usage_found else "Low",
                "rating_justification": f"Default rating based on usage detection. Error: {json_e}"
            }
        except Exception as e:
            logger.error(f"Error in impact assessment: {e}")
            # Fallback to a basic assessment for other errors
            usage_found = cve_analysis.get('usage_found', False)
            impact_assessment = {
                "is_exploitable_in_context": usage_found,
                "impact_summary": "Could not generate impact summary due to error",
                "danger_rating": "Medium" if usage_found else "Low",
                "rating_justification": f"Default rating based on usage detection. Error: {e}"
            }

        # Update the current_cve_analysis_results
        current_cve_analysis_results = state['current_cve_analysis_results'].copy()
        current_cve_analysis_results.update({
            "is_exploitable_in_context": impact_assessment.get('is_exploitable_in_context', False),
            "impact_summary": impact_assessment.get('impact_summary', 'No impact summary available'),
            "danger_rating": impact_assessment.get('danger_rating', 'Low'),
            "rating_justification": impact_assessment.get('rating_justification', 'No justification provided')
        })

        # Preserve any existing error message that might be critical
        return {
            "current_cve_analysis_results": current_cve_analysis_results,
            "error_message": state.get("error_message")  # Preserve existing error message if any
        }

    except Exception as e:
        error_msg_detail = f"Unexpected error in {node_name}: {e}"
        logger.error(error_msg_detail, exc_info=True)
        # Preserve critical error if it exists
        current_overall_error = state.get("error_message")
        if current_overall_error and current_overall_error.startswith("LLM_PROVIDER_FAILURE:"):
            return {"current_cve_analysis_results": state.get('current_cve_analysis_results'), "error_message": current_overall_error}
        else:
            return {"current_cve_analysis_results": state.get('current_cve_analysis_results'), "error_message": error_msg_detail}


def propose_fix_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Propose a fix for the vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    node_name = get_current_node_name()
    logger.info(f"Running node: {node_name}")

    try:
        # Check for critical LLM failure from previous nodes
        error_message = state.get("error_message", "")
        if error_message and error_message.startswith("LLM_PROVIDER_FAILURE:"):
            logger.warning(f"[{node_name}] Skipping due to previous LLM provider failure: {state['error_message']}")
            return {"error_message": state.get("error_message")}  # Preserve the error message

        if not state.get('current_vulnerability_details') or not state.get('current_cve_analysis_results'):
            error_message = f"Missing vulnerability details or CVE analysis results in {node_name}"
            logger.error(error_message)
            return {"error_message": error_message}

        # Get the current vulnerability details and analysis results
        vuln_details = state['current_vulnerability_details']
        cve_analysis = state['current_cve_analysis_results']

        # Get the scan-specific config from state
        scan_config = state.get('app_config')
        if not scan_config:
            logger.error(f"[{node_name}] App config not found in state. Using global settings.")
            scan_config = get_settings()

        # Create the LLM service with scan-specific config
        llm_service = LLMService(config=scan_config)

        # Determine active provider based on the scan_config
        active_provider = scan_config.get('active_llm_provider', scan_config.get('default_llm_provider', 'gemini'))

        # Use the imported prompt template
        prompt_template = FIX_PROPOSAL_PROMPT

        # Prepare the input data
        import json

        input_data = {
            "package_name": vuln_details.get('package_name', 'unknown'),
            "vulnerable_version_used": vuln_details.get('vulnerable_version', 'unknown'),
            "cve_ids_list": ", ".join(vuln_details.get('cve_ids', ['unknown'])),
            "impact_summary": cve_analysis.get('impact_summary', 'No impact assessment available'),
            "danger_rating": cve_analysis.get('danger_rating', 'Unknown'),
            "fix_suggestion_from_tool": vuln_details.get('fix_suggestion_from_tool', 'No suggestion available'),
            "cve_analysis_json": json.dumps(cve_analysis)
        }

        # Invoke the LLM
        try:
            response = llm_service.invoke_llm(prompt_template, input_data, provider_name=active_provider)

            # Parse the JSON response
            import re

            # Extract JSON from the response (in case the LLM adds extra text)
            json_match = re.search(r'({.*})', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                fix_proposal = json.loads(json_str)
            else:
                # If no JSON found, try to parse the whole response
                fix_proposal = json.loads(response)

            logger.info(f"[{node_name}] Successfully proposed fix for {vuln_details.get('package_name', 'unknown')}")

        except (LLMAuthenticationError, LLMConfigurationError, LLMConnectionError) as llm_critical_error:
            critical_msg = f"LLM_PROVIDER_FAILURE: Critical error in {node_name} with provider '{active_provider}': {llm_critical_error}"
            logger.critical(critical_msg)
            # Get existing error message and check if it's a critical LLM failure
            existing_error = state.get("error_message","")
            return {
                "current_cve_analysis_results": state.get('current_cve_analysis_results'),
                "error_message": critical_msg if not (existing_error and existing_error.startswith("LLM_PROVIDER_FAILURE:")) else existing_error
            }
        except json.JSONDecodeError as json_e:
            logger.error(f"Error parsing fix proposal response: {json_e}")
            # Fallback to a basic fix proposal for JSON parsing errors
            fix_suggestion = vuln_details.get('fix_suggestion_from_tool', 'Update to the latest version')
            fix_proposal = {
                "primary_fix_recommendation": fix_suggestion,
                "alternative_mitigations": ["Restrict access to the affected component", 
                                           "Monitor for suspicious activity"]
            }
        except Exception as e:
            logger.error(f"Error in fix proposal: {e}")
            # Fallback to a basic fix proposal for other errors
            fix_suggestion = vuln_details.get('fix_suggestion_from_tool', 'Update to the latest version')
            fix_proposal = {
                "primary_fix_recommendation": fix_suggestion,
                "alternative_mitigations": ["Restrict access to the affected component", 
                                           "Monitor for suspicious activity"]
            }

        # Update the current_cve_analysis_results
        current_cve_analysis_results = state['current_cve_analysis_results'].copy()
        current_cve_analysis_results.update({
            "primary_fix_recommendation": fix_proposal.get('primary_fix_recommendation', 'No fix recommendation available'),
            "alternative_mitigations": fix_proposal.get('alternative_mitigations', ['No alternative mitigations available'])
        })

        # Preserve any existing error message that might be critical
        return {
            "current_cve_analysis_results": current_cve_analysis_results,
            "error_message": state.get("error_message")  # Preserve existing error message if any
        }

    except Exception as e:
        error_msg_detail = f"Unexpected error in {node_name}: {e}"
        logger.error(error_msg_detail, exc_info=True)
        # Preserve critical error if it exists
        current_overall_error = state.get("error_message")
        if current_overall_error and current_overall_error.startswith("LLM_PROVIDER_FAILURE:"):
            return {"current_cve_analysis_results": state.get('current_cve_analysis_results'), "error_message": current_overall_error}
        else:
            return {"current_cve_analysis_results": state.get('current_cve_analysis_results'), "error_message": error_msg_detail}


def aggregate_cve_results_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Aggregate the results of the CVE analysis.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info("Aggregating CVE results")

    try:
        if not state.get('current_vulnerability_details') or not state.get('current_cve_analysis_results'):
            error_message = "Missing vulnerability details or CVE analysis results"
            logger.error(error_message)
            return {"error_message": error_message}

        # Get the current vulnerability details and analysis results
        vuln_details = state['current_vulnerability_details']
        analysis_results = state['current_cve_analysis_results']

        # Ensure cve_link is a valid URL or None from the parsed advisory_link
        parsed_advisory_link = vuln_details.get('advisory_link')
        cve_link_url = None
        if parsed_advisory_link and (parsed_advisory_link.startswith('http://') or parsed_advisory_link.startswith('https://')):
            cve_link_url = parsed_advisory_link

        advisory_title = vuln_details.get('advisory_title')
        evidence_snippet = analysis_results.get('evidence_snippet')

        # Determine the best vulnerable_version_range
        # Prioritize the range from the advisory, fall back to constructing from installed_version if necessary
        vulnerable_range = vuln_details.get('advisory_vulnerable_range')
        if not vulnerable_range:
            vulnerable_range = f"<= {vuln_details.get('installed_version', 'unknown')}"

        vulnerability_detail = {
            "cve_id": vuln_details.get('cve_ids', ['unknown'])[0] if vuln_details.get('cve_ids') else "unknown",
            "primary_advisory_id": vuln_details.get('primary_advisory_id'),
            "cve_link": cve_link_url,
            "cve_description": advisory_title if advisory_title is not None else 'No description available',
            "package_name": vuln_details.get('package_name', 'unknown'),
            "vulnerable_version_range": vulnerable_range,
            "analyzed_project_version": vuln_details.get('installed_version', 'unknown'), # Use the parsed installed_version
            "impact_in_project_summary": analysis_results.get('impact_summary', 'No impact assessment available'),
            "evidence": [evidence_snippet if evidence_snippet is not None else 'No evidence available'],
            "danger_rating": analysis_results.get('danger_rating', 'Unknown'),
            "proposed_fix_summary": analysis_results.get('primary_fix_recommendation', 'No fix recommendation available'),
            "detailed_fix_guidance": ", ".join(analysis_results.get('alternative_mitigations', ['No detailed guidance available']))
        }

        # Add the vulnerability detail to the final vulnerabilities list
        final_vulnerabilities = state.get('final_vulnerabilities', []).copy()
        final_vulnerabilities.append(vulnerability_detail)

        logger.info(f"Added vulnerability detail for {vuln_details.get('package_name', 'unknown')}")

        # Preserve any existing error message that might be critical (like API key issues)
        # Only clear node-specific errors that have been handled
        return {
            "final_vulnerabilities": final_vulnerabilities,
            "error_message": state.get("error_message")  # Preserve existing error message if any
        }

    except Exception as e:
        error_message = f"Error aggregating CVE results: {e}"
        logger.error(error_message)
        return {"error_message": error_message}


def cleanup_scan_environment_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Clean up the scan environment.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info("Cleaning up scan environment")

    try:
        if state.get('cloned_repo_path'):
            git_service = GitService()
            git_service.cleanup_repository(state['cloned_repo_path'])
            logger.info(f"Cleaned up repository at {state['cloned_repo_path']}")

        return {"cloned_repo_path": None}

    except Exception as e:
        error_message = f"Error cleaning up scan environment: {e}"
        logger.error(error_message)
        return {"error_message": error_message}


def compile_final_report_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Compile the final report.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info("Compiling final report")

    try:
        # The final report is already in the state as final_vulnerabilities
        # We could add additional summary information here if needed

        final_vulnerabilities = state.get('final_vulnerabilities', [])
        logger.info(f"Final report contains {len(final_vulnerabilities)} vulnerabilities")

        return {}

    except Exception as e:
        error_message = f"Error compiling final report: {e}"
        logger.error(error_message)
        return {"error_message": error_message}


# Router functions for conditional edges

def route_after_prepare_scan_environment(state: ScaImpactState) -> str:
    """
    Route after preparing scan environment.

    Args:
        state (ScaImpactState): Current state

    Returns:
        str: Next node name
    """
    # If app_config itself is missing, that's a setup error.
    if not state.get('app_config'):
        logger.critical("App config missing in state during route_after_prepare_scan_environment. Critical setup error.")
        state['error_message'] = "CRITICAL_SETUP_FAILURE: App configuration missing." # Set a critical error
        return "cleanup_scan_environment_node" # Go straight to cleanup

    error_message = state.get('error_message', '')
    if error_message and (error_message.startswith("LLM_PROVIDER_FAILURE:") or \
       error_message.startswith("CRITICAL_SETUP_FAILURE:")): # Check for critical errors
        logger.warning(f"Critical failure detected early: {state['error_message']}. Proceeding to cleanup.")
        return "cleanup_scan_environment_node"
    if not state.get('cloned_repo_path'): # General error in cloning
        return "cleanup_scan_environment_node"
    return "identify_project_and_run_audit_node"


def route_after_identify_project(state: ScaImpactState) -> str:
    """
    Route after identifying project and running audit.

    Args:
        state (ScaImpactState): Current state

    Returns:
        str: Next node name
    """
    # Check for critical failures first
    error_message = state.get('error_message', '')
    if error_message and (error_message.startswith("LLM_PROVIDER_FAILURE:") or \
       error_message.startswith("CRITICAL_SETUP_FAILURE:")):
        logger.warning(f"Critical failure detected in route_after_identify_project: {state['error_message']}. Skipping to final report.")
        return "compile_final_report_node"

    vulnerabilities = state.get('audit_tool_vulnerabilities', [])
    if not vulnerabilities or state.get('error_message'):
        return "compile_final_report_node"
    else:
        return "build_rag_index_node"


def route_after_build_rag_index(state: ScaImpactState) -> str:
    """
    Route after building RAG index.

    Args:
        state (ScaImpactState): Current state

    Returns:
        str: Next node name
    """
    # Check for critical failures first
    error_message = state.get('error_message', '')
    if error_message and (error_message.startswith("LLM_PROVIDER_FAILURE:") or \
       error_message.startswith("CRITICAL_SETUP_FAILURE:")):
        logger.warning(f"Critical failure detected in route_after_build_rag_index: {state['error_message']}. Skipping to final report.")
        return "compile_final_report_node"

    if state.get('error_message') or not state.get('project_code_index_path'):
        return "compile_final_report_node"
    else:
        return "select_next_vulnerability_node"


def route_after_select_next_vulnerability(state: ScaImpactState) -> str:
    """
    Route after selecting next vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        str: Next node name
    """
    # Check for critical LLM failure from a *previous* vulnerability's processing
    error_message = state.get("error_message", "")
    if error_message and error_message.startswith("LLM_PROVIDER_FAILURE:"):
        logger.critical(f"LLM Provider failure detected: {state['error_message']}. Halting further vulnerability processing.")
        return "compile_final_report_node" # Skip to report compilation

    if state.get('current_vulnerability_idx') == -1 or not state.get('current_vulnerability_details'):
        logger.info("No more vulnerabilities to process or no current vulnerability selected.")
        return "compile_final_report_node"
    else:
        return "analyze_cve_description_node" # Proceed to LLM analysis


def route_after_vulnerability_processing(state: ScaImpactState) -> str:
    """
    Route after processing a vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        str: Next node name
    """
    # This route is hit after aggregate_cve_results_node for one vulnerability.
    # If an LLM_PROVIDER_FAILURE was set by one of the preceding nodes for *this* vulnerability,
    # it will be in state['error_message'].
    error_message = state.get("error_message", "")
    if error_message and error_message.startswith("LLM_PROVIDER_FAILURE:"):
        logger.critical(f"LLM Provider failure detected during processing of current vulnerability: {state['error_message']}. Halting.")
        return "compile_final_report_node" # Go to compile report, which then cleans up

    # If there's a non-critical error, log it but continue with the next vulnerability
    if state.get('error_message'):
        logger.warning(f"Non-critical error during vulnerability processing: {state.get('error_message')}. Moving to next vulnerability.")

    # Otherwise, always try to select the next vulnerability.
    # If all are done, select_next_vulnerability_node will route to compile_final_report_node.
    return "select_next_vulnerability_node"


# Create the graph
def create_sca_impact_graph() -> StateGraph:
    """
    Create the SCA Impact Graph.

    Returns:
        StateGraph: The compiled graph
    """
    # Create a new graph
    graph = StateGraph(ScaImpactState)

    # Add nodes
    graph.add_node("prepare_scan_environment", prepare_scan_environment)
    graph.add_node("identify_project_and_run_audit_node", identify_project_and_run_audit_node)
    graph.add_node("build_rag_index_node", build_rag_index_node)
    graph.add_node("select_next_vulnerability_node", select_next_vulnerability_node)
    graph.add_node("analyze_cve_description_node", analyze_cve_description_node)
    graph.add_node("search_codebase_for_impact_node", search_codebase_for_impact_node)
    graph.add_node("evaluate_impact_and_danger_node", evaluate_impact_and_danger_node)
    graph.add_node("propose_fix_node", propose_fix_node)
    graph.add_node("aggregate_cve_results_node", aggregate_cve_results_node)
    graph.add_node("compile_final_report_node", compile_final_report_node)
    graph.add_node("cleanup_scan_environment_node", cleanup_scan_environment_node)

    # Set the entry point
    graph.set_entry_point("prepare_scan_environment")

    # Add conditional edges
    graph.add_conditional_edges(
        "prepare_scan_environment",
        route_after_prepare_scan_environment,
        {
            "identify_project_and_run_audit_node": "identify_project_and_run_audit_node",
            "cleanup_scan_environment_node": "cleanup_scan_environment_node"
        }
    )

    graph.add_conditional_edges(
        "identify_project_and_run_audit_node",
        route_after_identify_project,
        {
            "build_rag_index_node": "build_rag_index_node",
            "compile_final_report_node": "compile_final_report_node"
        }
    )

    graph.add_conditional_edges(
        "build_rag_index_node",
        route_after_build_rag_index,
        {
            "select_next_vulnerability_node": "select_next_vulnerability_node",
            "compile_final_report_node": "compile_final_report_node"
        }
    )

    graph.add_conditional_edges(
        "select_next_vulnerability_node",
        route_after_select_next_vulnerability,
        {
            "analyze_cve_description_node": "analyze_cve_description_node",
            "compile_final_report_node": "compile_final_report_node"
        }
    )

    # Add sequential edges for vulnerability processing
    graph.add_edge("analyze_cve_description_node", "search_codebase_for_impact_node")
    graph.add_edge("search_codebase_for_impact_node", "evaluate_impact_and_danger_node")
    graph.add_edge("evaluate_impact_and_danger_node", "propose_fix_node")
    graph.add_edge("propose_fix_node", "aggregate_cve_results_node")

    graph.add_conditional_edges(
        "aggregate_cve_results_node",
        route_after_vulnerability_processing,
        {
            "select_next_vulnerability_node": "select_next_vulnerability_node"
        }
    )

    # Add edge from compile_final_report_node to cleanup_scan_environment_node
    graph.add_edge("compile_final_report_node", "cleanup_scan_environment_node")

    # Set cleanup_scan_environment_node as an end node
    graph.add_edge("cleanup_scan_environment_node", END)

    # Compile the graph
    return graph.compile()


# Define a default recursion limit
DEFAULT_RECURSION_LIMIT = 200

# Function to run the SCA scan
def run_sca_scan(repo_source: str, app_config: Settings, recursion_limit: Optional[int] = None) -> Dict:
    """
    Run an SCA scan on a repository.

    Args:
        repo_source (str): URL or local path to the repository
        app_config (Settings): Application configuration
        recursion_limit (Optional[int]): Max recursion limit for the graph. Defaults to DEFAULT_RECURSION_LIMIT.

    Returns:
        Dict: The scan results
    """
    logger.info(f"Running SCA scan for {repo_source}")

    try:
        # Create the graph
        graph = create_sca_impact_graph()

        # Initialize the state
        initial_state: ScaImpactState = {
            "app_config": app_config,  # Pass the potentially modified config
            "repo_source": repo_source,
            "cloned_repo_path": None,
            "project_type": None,
            "project_manifest_path": None,
            "project_code_index_path": None,
            "audit_tool_vulnerabilities": [],
            "current_vulnerability_idx": -1,
            "current_vulnerability_details": None,
            "current_cve_analysis_results": None,
            "final_vulnerabilities": [],
            "error_message": None
        }

        # Use the specified recursion limit or the default
        actual_recursion_limit = recursion_limit if recursion_limit is not None else DEFAULT_RECURSION_LIMIT
        logger.info(f"Using graph recursion limit: {actual_recursion_limit}")

        # Invoke the graph with the specified recursion limit
        result = graph.invoke(initial_state, {"recursion_limit": actual_recursion_limit})

        # Extract the relevant parts of the final state
        # The result from langgraph.invoke() is the final state itself
        final_state = result
        final_vulnerabilities = final_state.get("final_vulnerabilities", [])
        error_message = final_state.get("error_message")

        # Create the result dictionary
        scan_result = {
            "repo_source": repo_source,
            "final_vulnerabilities": final_vulnerabilities,  # Renamed for clarity
            "error_message": error_message,
            "project_manifest_path": final_state.get("project_manifest_path"),
            "audit_tool_vulnerabilities": final_state.get("audit_tool_vulnerabilities", [])
        }

        if error_message and error_message.startswith("LLM_PROVIDER_FAILURE:"):
            logger.critical(f"Scan for {repo_source} terminated due to critical LLM failure: {error_message}")
            # Raise an exception to immediately stop the scan process for API key errors
            raise Exception(error_message)
        elif error_message:
            logger.error(f"Scan for {repo_source} completed or failed with errors: {error_message}")
        else:
            logger.info(f"SCA scan completed for {repo_source}")

        return scan_result

    except Exception as e:
        error_message = str(e)

        # Check if this is an LLM provider failure that we raised earlier
        if error_message.startswith("LLM_PROVIDER_FAILURE:"):
            # Re-raise the exception to be caught by the API router
            raise

        # For other exceptions, log and return a result with the error
        error_message_critical = f"Critical error during SCA scan execution: {e}"
        logger.error(error_message_critical, exc_info=True)  # Add exc_info for traceback
        return {
            "repo_source": repo_source,
            "final_vulnerabilities": [],  # Use consistent key name
            "error_message": error_message_critical,
            "audit_tool_vulnerabilities": initial_state.get("audit_tool_vulnerabilities", [])  # Return what we had
        }
