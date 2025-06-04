"""
AgentPimentBleu - SCA Impact Graph

This module defines the LangGraph for SCA and impact analysis.
"""

from typing import Dict, List, Optional, TypedDict, Any, Callable
import os

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from agentpimentbleu.services.git_service import GitService
from agentpimentbleu.services.dependency_service import DependencyService
from agentpimentbleu.services.rag_service import RAGService
from agentpimentbleu.services.llm_service import LLMService
from agentpimentbleu.config.config import get_settings, Settings
from agentpimentbleu.utils.logger import get_logger

logger = get_logger()


class ScaImpactState(TypedDict, total=False):
    """
    State for the SCA Impact Graph.
    """
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
    logger.info("Analyzing CVE description")

    try:
        if not state.get('current_vulnerability_details'):
            error_message = "No current vulnerability details provided"
            logger.error(error_message)
            return {"current_cve_analysis_results": None, "error_message": error_message}

        # Get the current vulnerability details
        vuln_details = state['current_vulnerability_details']

        # Create the LLM service
        llm_service = LLMService()

        # Create the prompt template
        from langchain_core.prompts import ChatPromptTemplate

        prompt_template = ChatPromptTemplate.from_messages([
            ("system", """You are a security expert analyzing vulnerabilities in software dependencies.
            Your task is to analyze a vulnerability reported for a specific library and extract key information.
            Provide your analysis in a structured JSON format with the following keys:
            - vulnerability_type: The core type of vulnerability (e.g., XSS, SQL Injection, Buffer Overflow)
            - affected_components: A list of specific functions, modules, or components likely affected
            - exploitation_conditions: Key conditions or inputs required for exploitation

            Be specific and technical in your analysis. Focus on the actual vulnerability, not general security advice."""),
            ("human", """Analyze this vulnerability reported for library {package_name} (version {vulnerable_version}):

            CVEs: {cve_ids_list}
            Tool Advisory Title: {tool_advisory_title}
            Tool Advisory Details/Link: {tool_advisory_link}

            Identify:
            1. The core vulnerability type.
            2. The specific function(s), module(s), or component(s) likely affected in the library.
            3. Key conditions or inputs required for exploitation based on the advisory.

            Return a structured JSON object with keys: `vulnerability_type`, `affected_components` (list of strings), `exploitation_conditions`.""")
        ])

        # Prepare the input data
        input_data = {
            "package_name": vuln_details.get('package_name', 'unknown'),
            "vulnerable_version": vuln_details.get('vulnerable_version', 'unknown'),
            "cve_ids_list": ", ".join(vuln_details.get('cve_ids', ['unknown'])),
            "tool_advisory_title": vuln_details.get('advisory_title', 'No title available'),
            "tool_advisory_link": vuln_details.get('advisory_link', 'No link available')
        }

        # Invoke the LLM
        try:
            response = llm_service.invoke_llm(prompt_template, input_data)

            # Parse the JSON response
            import json
            import re

            # Extract JSON from the response (in case the LLM adds extra text)
            json_match = re.search(r'({.*})', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                current_cve_analysis_results = json.loads(json_str)
            else:
                # If no JSON found, try to parse the whole response
                current_cve_analysis_results = json.loads(response)

            logger.info(f"Successfully analyzed CVE for {vuln_details.get('package_name', 'unknown')}")

        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            # Fallback to a basic analysis
            current_cve_analysis_results = {
                "vulnerability_type": "Unknown (parsing error)",
                "affected_components": [vuln_details.get('package_name', 'unknown')],
                "exploitation_conditions": "Unknown due to parsing error"
            }

        return {"current_cve_analysis_results": current_cve_analysis_results}

    except Exception as e:
        error_message = f"Error analyzing CVE description: {e}"
        logger.error(error_message)
        return {"current_cve_analysis_results": None, "error_message": error_message}


def search_codebase_for_impact_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Search the codebase for impact of the vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info("Searching codebase for impact")

    try:
        if not state.get('current_vulnerability_details') or not state.get('current_cve_analysis_results'):
            error_message = "Missing vulnerability details or CVE analysis results"
            logger.error(error_message)
            return {"error_message": error_message}

        if not state.get('project_code_index_path'):
            error_message = "No RAG index path provided"
            logger.error(error_message)
            return {"error_message": error_message}

        # Get the current vulnerability details and analysis results
        vuln_details = state['current_vulnerability_details']
        cve_analysis = state['current_cve_analysis_results']

        # Create the LLM service and RAG service
        llm_service = LLMService()
        rag_service = RAGService()

        # Load the RAG index
        index = rag_service.load_index(state['project_code_index_path'])
        if not index:
            error_message = f"Failed to load RAG index from {state['project_code_index_path']}"
            logger.error(error_message)
            return {"error_message": error_message}

        # Create the prompt template for formulating RAG queries
        from langchain_core.prompts import ChatPromptTemplate

        query_formulation_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a security expert searching for evidence of vulnerability usage in a codebase.
            Your task is to formulate search queries that will help find if vulnerable components are used.
            Focus on specific function names, module imports, or patterns that would indicate usage of the vulnerable component."""),
            ("human", """Based on this CVE analysis for library {package_name}:

            {cve_analysis_json}

            The project uses {package_name} version {vulnerable_version}.

            Formulate 1-2 concise search queries for a code vector database to find if the vulnerable component(s) are used in the project.
            Each query should be specific and focused on finding actual usage of the vulnerable parts.

            Return a JSON array of query strings.""")
        ])

        # Prepare the input data for query formulation
        import json

        query_input_data = {
            "package_name": vuln_details.get('package_name', 'unknown'),
            "vulnerable_version": vuln_details.get('vulnerable_version', 'unknown'),
            "cve_analysis_json": json.dumps(cve_analysis)
        }

        # Invoke the LLM to formulate queries
        try:
            query_response = llm_service.invoke_llm(query_formulation_prompt, query_input_data)

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

            logger.info(f"Formulated {len(rag_queries)} RAG queries")

        except Exception as e:
            logger.error(f"Error formulating RAG queries: {e}")
            # Fallback to basic queries
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

        # Create the prompt template for analyzing RAG results
        analysis_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a security expert analyzing code snippets to determine if a vulnerability is exploitable.
            Your task is to analyze search results from a codebase to determine if a vulnerable component is used.
            Be conservative in your assessment - only confirm usage if there's clear evidence."""),
            ("human", """Based on this CVE analysis for library {package_name}:

            {cve_analysis_json}

            I searched the codebase with these queries: {rag_queries}

            Here are the search results:
            {rag_search_results}

            Analyze these snippets and determine:
            1. Is there direct usage of the vulnerable component found in the code?
            2. If yes, provide the relevant code snippet and explain how it relates to the vulnerability.
            3. If no, explain why the search results don't indicate usage of the vulnerable component.

            Return a structured JSON object with keys:
            - usage_found (boolean)
            - evidence_snippet (string or null)
            - file_path (string or null)
            - explanation (string)""")
        ])

        # Prepare the input data for analysis
        analysis_input_data = {
            "package_name": vuln_details.get('package_name', 'unknown'),
            "cve_analysis_json": json.dumps(cve_analysis),
            "rag_queries": json.dumps(rag_queries),
            "rag_search_results": "\n\n".join(rag_results)
        }

        # Invoke the LLM to analyze the RAG results
        try:
            analysis_response = llm_service.invoke_llm(analysis_prompt, analysis_input_data)

            # Parse the JSON response
            json_match = re.search(r'({.*})', analysis_response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                analysis_results = json.loads(json_str)
            else:
                # If no JSON found, try to parse the whole response
                analysis_results = json.loads(analysis_response)

            logger.info(f"Successfully analyzed RAG results for {vuln_details.get('package_name', 'unknown')}")

        except Exception as e:
            logger.error(f"Error parsing analysis response: {e}")
            # Fallback to a basic analysis
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

        return {"current_cve_analysis_results": current_cve_analysis_results}

    except Exception as e:
        error_message = f"Error searching codebase for impact: {e}"
        logger.error(error_message)
        return {"error_message": error_message}


def evaluate_impact_and_danger_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Evaluate the impact and danger of the vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info("Evaluating impact and danger")

    try:
        if not state.get('current_vulnerability_details') or not state.get('current_cve_analysis_results'):
            error_message = "Missing vulnerability details or CVE analysis results"
            logger.error(error_message)
            return {"error_message": error_message}

        # Get the current vulnerability details and analysis results
        vuln_details = state['current_vulnerability_details']
        cve_analysis = state['current_cve_analysis_results']

        # Create the LLM service
        llm_service = LLMService()

        # Create the prompt template
        from langchain_core.prompts import ChatPromptTemplate

        prompt_template = ChatPromptTemplate.from_messages([
            ("system", """You are a security expert evaluating the real-world impact of vulnerabilities in a specific project context.
            Your task is to determine if a vulnerability is actually exploitable in the project and assess its danger level.
            Be conservative but realistic in your assessment. Consider both the technical details and the usage context."""),
            ("human", """Impact Assessment: Given vulnerability in {package_name} (CVEs: {cve_ids_list}), its analysis:

            {cve_analysis_json}

            And the project's usage context:

            Usage found: {usage_found}
            Evidence snippet: {evidence_snippet}
            Explanation: {usage_explanation}

            Please:
            1. Explain if the project's use of {package_name} exposes it to this vulnerability.
            2. Summarize the specific, direct impact on *this* project if it is vulnerable.
            3. Assign a danger rating: "Critical", "High", "Medium", "Low", or "Informational". Justify your rating.

            Return a structured JSON object with keys:
            - is_exploitable_in_context (boolean)
            - impact_summary (string)
            - danger_rating (string - one of "Critical", "High", "Medium", "Low", "Informational")
            - rating_justification (string)""")
        ])

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
            response = llm_service.invoke_llm(prompt_template, input_data)

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

            logger.info(f"Successfully evaluated impact for {vuln_details.get('package_name', 'unknown')}")

        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            # Fallback to a basic assessment
            usage_found = cve_analysis.get('usage_found', False)
            impact_assessment = {
                "is_exploitable_in_context": usage_found,
                "impact_summary": "Could not generate impact summary due to parsing error",
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

        return {"current_cve_analysis_results": current_cve_analysis_results}

    except Exception as e:
        error_message = f"Error evaluating impact and danger: {e}"
        logger.error(error_message)
        return {"error_message": error_message}


def propose_fix_node(state: ScaImpactState) -> Dict[str, Any]:
    """
    Propose a fix for the vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        Dict[str, Any]: Updated state
    """
    logger.info("Proposing fix")

    try:
        if not state.get('current_vulnerability_details') or not state.get('current_cve_analysis_results'):
            error_message = "Missing vulnerability details or CVE analysis results"
            logger.error(error_message)
            return {"error_message": error_message}

        # Get the current vulnerability details and analysis results
        vuln_details = state['current_vulnerability_details']
        cve_analysis = state['current_cve_analysis_results']

        # Create the LLM service
        llm_service = LLMService()

        # Create the prompt template
        from langchain_core.prompts import ChatPromptTemplate

        prompt_template = ChatPromptTemplate.from_messages([
            ("system", """You are a security expert recommending fixes for vulnerabilities in software dependencies.
            Your task is to provide clear, actionable recommendations for addressing a vulnerability.
            Focus on practical solutions that balance security with implementation effort.
            Consider both immediate fixes and alternative mitigations if an update is not immediately possible."""),
            ("human", """Fix Proposal: For vulnerability in {package_name} (version {vulnerable_version_used}, CVEs: {cve_ids_list}) 
            with assessed impact: {impact_summary} and danger: {danger_rating}.

            The audit tool suggested: "{fix_suggestion_from_tool}"

            Vulnerability details:
            {cve_analysis_json}

            Please:
            1. Elaborate on the primary recommended fix. If the tool suggested an update, confirm the target version.
            2. Suggest alternative mitigations or workarounds if an update is not immediately possible.

            Return a structured JSON object with keys:
            - primary_fix_recommendation (string)
            - alternative_mitigations (list of strings)""")
        ])

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
            response = llm_service.invoke_llm(prompt_template, input_data)

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

            logger.info(f"Successfully proposed fix for {vuln_details.get('package_name', 'unknown')}")

        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            # Fallback to a basic fix proposal
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

        return {"current_cve_analysis_results": current_cve_analysis_results}

    except Exception as e:
        error_message = f"Error proposing fix: {e}"
        logger.error(error_message)
        return {"error_message": error_message}


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

        # Create a VulnerabilityDetail object
        # Ensure cve_link is a valid URL or None
        cve_link = vuln_details.get('advisory_link')
        if cve_link and not (cve_link.startswith('http://') or cve_link.startswith('https://')):
            cve_link = None

        vulnerability_detail = {
            "cve_id": vuln_details.get('cve_ids', ['unknown'])[0] if vuln_details.get('cve_ids') else "unknown",
            "cve_link": cve_link,
            "cve_description": vuln_details.get('advisory_title', 'No description available'),
            "package_name": vuln_details.get('package_name', 'unknown'),
            "vulnerable_version_range": f"<= {vuln_details.get('vulnerable_version', 'unknown')}",
            "analyzed_project_version": vuln_details.get('vulnerable_version', 'unknown'),
            "impact_in_project_summary": analysis_results.get('impact_summary', 'No impact assessment available'),
            "evidence": [analysis_results.get('evidence_snippet', 'No evidence available')],
            "danger_rating": analysis_results.get('danger_rating', 'Unknown'),
            "proposed_fix_summary": analysis_results.get('primary_fix_recommendation', 'No fix recommendation available'),
            "detailed_fix_guidance": ", ".join(analysis_results.get('alternative_mitigations', ['No detailed guidance available']))
        }

        # Add the vulnerability detail to the final vulnerabilities list
        final_vulnerabilities = state.get('final_vulnerabilities', []).copy()
        final_vulnerabilities.append(vulnerability_detail)

        logger.info(f"Added vulnerability detail for {vuln_details.get('package_name', 'unknown')}")

        # Clear any error message to prevent it from affecting the next vulnerability
        return {
            "final_vulnerabilities": final_vulnerabilities,
            "error_message": None
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
    if state.get('error_message') or not state.get('cloned_repo_path'):
        return "cleanup_scan_environment_node"
    else:
        return "identify_project_and_run_audit_node"


def route_after_identify_project(state: ScaImpactState) -> str:
    """
    Route after identifying project and running audit.

    Args:
        state (ScaImpactState): Current state

    Returns:
        str: Next node name
    """
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
    if state.get('current_vulnerability_idx') == -1 or not state.get('current_vulnerability_details'):
        return "compile_final_report_node"
    else:
        return "analyze_cve_description_node"


def route_after_vulnerability_processing(state: ScaImpactState) -> str:
    """
    Route after processing a vulnerability.

    Args:
        state (ScaImpactState): Current state

    Returns:
        str: Next node name
    """
    # Always return to select_next_vulnerability_node to process the next vulnerability
    # If there's an error, log it but continue with the next vulnerability
    if state.get('error_message'):
        logger.warning(f"Error during vulnerability processing: {state.get('error_message')}. Moving to next vulnerability.")

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


# Function to run the SCA scan
def run_sca_scan(repo_source: str, app_config: Settings) -> Dict:
    """
    Run an SCA scan on a repository.

    Args:
        repo_source (str): URL or local path to the repository
        app_config (Settings): Application configuration

    Returns:
        Dict: The scan results
    """
    logger.info(f"Running SCA scan for {repo_source}")

    try:
        # Create the graph
        graph = create_sca_impact_graph()

        # Initialize the state
        initial_state: ScaImpactState = {
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

        # Invoke the graph
        result = graph.invoke(initial_state, {"recursion_limit": 100})

        # Extract the relevant parts of the final state
        final_state = result.get("state", {})
        final_vulnerabilities = final_state.get("final_vulnerabilities", [])
        error_message = final_state.get("error_message")

        # Create the result dictionary
        scan_result = {
            "repo_source": repo_source,
            "vulnerabilities": final_vulnerabilities,
            "error_message": error_message,
            "project_manifest_path": final_state.get("project_manifest_path"),
            "audit_tool_vulnerabilities": final_state.get("audit_tool_vulnerabilities", [])
        }

        logger.info(f"SCA scan completed for {repo_source}")
        return scan_result

    except Exception as e:
        error_message = f"Error running SCA scan: {e}"
        logger.error(error_message)
        return {
            "repo_source": repo_source,
            "vulnerabilities": [],
            "error_message": error_message
        }
