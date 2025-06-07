"""
AgentPimentBleu - SCA Impact Prompts

This module contains prompt templates used by the SCA impact graph nodes.
"""

from langchain_core.prompts import ChatPromptTemplate

# Prompt for analyzing CVE descriptions
CVE_ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
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

# Prompt for formulating RAG queries
RAG_QUERY_FORMULATION_PROMPT = ChatPromptTemplate.from_messages([
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

# Prompt for analyzing RAG results
RAG_RESULTS_ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
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

# Prompt for evaluating impact and danger
IMPACT_EVALUATION_PROMPT = ChatPromptTemplate.from_messages([
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

# Prompt for proposing fixes
FIX_PROPOSAL_PROMPT = ChatPromptTemplate.from_messages([
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