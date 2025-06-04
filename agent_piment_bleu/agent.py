"""
Agent for exploring codebases and analyzing vulnerabilities

This module implements an agent that can explore a codebase to find where CVEs could be an issue.
The agent uses an LLM to analyze CVEs and explore the codebase to find potential vulnerabilities.
"""

import os
import subprocess
from typing import Dict, List, Any, Optional, Tuple

from agent_piment_bleu.llm.base import LLMProvider
from agent_piment_bleu.logger import get_logger


class SecurityAgent:
    """
    Agent for exploring codebases and analyzing vulnerabilities.
    
    This agent uses an LLM to analyze CVEs and explore the codebase to find potential vulnerabilities.
    It follows a three-step process:
    1. Analyze the CVE
    2. Search potential consequences in the codebase (by opening different files)
    3. Make a final report
    """
    
    def __init__(self, llm: LLMProvider, repo_path: str):
        """
        Initialize the security agent.
        
        Args:
            llm (LLMProvider): LLM provider to use for analysis
            repo_path (str): Path to the repository to analyze
        """
        self.llm = llm
        self.repo_path = repo_path
        self.logger = get_logger()
        self.conversation_history = []
        
    def get_project_structure(self) -> str:
        """
        Get the structure of the project as a string (similar to tree command output).
        
        Returns:
            str: Project structure as a string
        """
        try:
            # Check if tree command is available
            result = subprocess.run(
                ["which", "tree"], 
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0:
                # Use tree command if available
                tree_result = subprocess.run(
                    ["tree", "-L", "3", self.repo_path], 
                    capture_output=True, 
                    text=True
                )
                return tree_result.stdout
            else:
                # Fallback to a simple directory listing
                structure = []
                
                for root, dirs, files in os.walk(self.repo_path):
                    # Limit depth to 3 levels
                    level = root.replace(self.repo_path, '').count(os.sep)
                    if level > 3:
                        continue
                        
                    indent = ' ' * 4 * level
                    structure.append(f"{indent}{os.path.basename(root)}/")
                    
                    sub_indent = ' ' * 4 * (level + 1)
                    for file in files:
                        structure.append(f"{sub_indent}{file}")
                
                return '\n'.join(structure)
        except Exception as e:
            self.logger.error(f"Error getting project structure: {e}")
            return f"Error getting project structure: {e}"
    
    def read_file(self, file_path: str) -> str:
        """
        Read the contents of a file.
        
        Args:
            file_path (str): Path to the file to read
            
        Returns:
            str: Contents of the file
        """
        try:
            # Make sure the file path is within the repository
            full_path = os.path.join(self.repo_path, file_path)
            if not os.path.abspath(full_path).startswith(os.path.abspath(self.repo_path)):
                return f"Error: Attempted to access file outside repository: {file_path}"
                
            if not os.path.isfile(full_path):
                return f"Error: File not found: {file_path}"
                
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return f"Error reading file {file_path}: {e}"
    
    def find_files(self, pattern: str) -> List[str]:
        """
        Find files matching a pattern in the repository.
        
        Args:
            pattern (str): Pattern to search for
            
        Returns:
            List[str]: List of files matching the pattern
        """
        try:
            # Use find command to search for files
            result = subprocess.run(
                ["find", self.repo_path, "-type", "f", "-name", pattern],
                capture_output=True,
                text=True
            )
            
            # Convert absolute paths to relative paths
            files = []
            for file in result.stdout.strip().split('\n'):
                if file:
                    rel_path = os.path.relpath(file, self.repo_path)
                    files.append(rel_path)
            
            return files
        except Exception as e:
            self.logger.error(f"Error finding files with pattern {pattern}: {e}")
            return []
    
    def search_in_files(self, search_term: str) -> Dict[str, List[str]]:
        """
        Search for a term in all files in the repository.
        
        Args:
            search_term (str): Term to search for
            
        Returns:
            Dict[str, List[str]]: Dictionary mapping file paths to lists of matching lines
        """
        try:
            # Use grep to search for the term
            result = subprocess.run(
                ["grep", "-r", "--include=*.*", search_term, self.repo_path],
                capture_output=True,
                text=True
            )
            
            # Parse the results
            matches = {}
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(':', 1)
                    if len(parts) >= 2:
                        file_path = os.path.relpath(parts[0], self.repo_path)
                        content = parts[1]
                        
                        if file_path not in matches:
                            matches[file_path] = []
                        
                        matches[file_path].append(content.strip())
            
            return matches
        except Exception as e:
            self.logger.error(f"Error searching for term {search_term}: {e}")
            return {}
    
    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a vulnerability using the agent.
        
        This method implements the three-step process:
        1. Analyze the CVE
        2. Search potential consequences in the codebase
        3. Make a final report
        
        Args:
            vulnerability (Dict[str, Any]): Vulnerability information
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        self.logger.info(f"Analyzing vulnerability: {vulnerability.get('cve', 'Unknown CVE')}")
        
        # Reset conversation history
        self.conversation_history = []
        
        # Step 1: Analyze the CVE
        cve_analysis = self._analyze_cve(vulnerability)
        
        # Step 2: Search potential consequences in the codebase
        codebase_analysis = self._explore_codebase(vulnerability, cve_analysis)
        
        # Step 3: Make the final report
        final_report = self._generate_final_report(vulnerability, cve_analysis, codebase_analysis)
        
        # Update the vulnerability with the analysis results
        vulnerability.update(final_report)
        
        return vulnerability
    
    def _analyze_cve(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a CVE to understand its potential impact.
        
        Args:
            vulnerability (Dict[str, Any]): Vulnerability information
            
        Returns:
            Dict[str, Any]: CVE analysis results
        """
        self.logger.info("Step 1: Analyzing CVE")
        
        # Get vulnerability text
        vulnerability_text = vulnerability.get('vulnerability_text', '')
        if not vulnerability_text:
            # Create a text representation if not already present
            package_name = vulnerability.get('package', vulnerability.get('package_name', ''))
            vulnerability_text = f"""
Package: {package_name}
Version: {vulnerability.get('version', 'unknown')}
Severity: {vulnerability.get('severity', 'medium')}
Title: {vulnerability.get('message', vulnerability.get('title', 'Unknown vulnerability'))}
CVE: {vulnerability.get('cve', 'N/A')}
"""
        
        # Create prompt for CVE analysis
        prompt = f"""
You are a security expert analyzing a vulnerability in a software dependency.

Vulnerability information:
{vulnerability_text}

Please analyze this vulnerability and provide the following information:
1. What is this vulnerability about? Explain in simple terms.
2. What are the potential consequences if this vulnerability is exploited?
3. What types of code patterns or usage might be vulnerable?
4. What should I look for in the codebase to determine if the project is affected?

Format your response in a clear, concise manner.
"""
        
        # Get LLM analysis
        response = self.llm.generate(prompt)
        
        # Add to conversation history
        self.conversation_history.append({
            "role": "user",
            "content": prompt
        })
        self.conversation_history.append({
            "role": "assistant",
            "content": response
        })
        
        # Return the analysis
        return {
            "cve_analysis": response
        }
    
    def _explore_codebase(self, vulnerability: Dict[str, Any], cve_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Explore the codebase to find potential consequences of the vulnerability.
        
        Args:
            vulnerability (Dict[str, Any]): Vulnerability information
            cve_analysis (Dict[str, Any]): Results of CVE analysis
            
        Returns:
            Dict[str, Any]: Codebase exploration results
        """
        self.logger.info("Step 2: Exploring codebase for potential consequences")
        
        # Get project structure
        project_structure = self.get_project_structure()
        
        # Get package name
        package_name = vulnerability.get('package', vulnerability.get('package_name', ''))
        
        # Create prompt for codebase exploration
        prompt = f"""
You are a security expert analyzing a codebase to determine if it's affected by a vulnerability.

Vulnerability information:
{vulnerability.get('vulnerability_text', '')}

Your previous analysis of this vulnerability:
{cve_analysis.get('cve_analysis', '')}

Project structure:
```
{project_structure}
```

Based on the project structure and the vulnerability information, I need you to help me explore this codebase to determine if it's affected by the vulnerability.

Please suggest:
1. Files that might be using the vulnerable package ({package_name})
2. Search terms I should use to find relevant code
3. Specific patterns I should look for

I'll help you explore the codebase based on your suggestions.
"""
        
        # Get LLM suggestions
        response = self.llm.generate_with_context(prompt, self.conversation_history)
        
        # Add to conversation history
        self.conversation_history.append({
            "role": "user",
            "content": prompt
        })
        self.conversation_history.append({
            "role": "assistant",
            "content": response
        })
        
        # Now let's actually explore the codebase based on the suggestions
        exploration_results = self._perform_exploration(response, package_name)
        
        # Create a prompt with the exploration results
        prompt = f"""
Based on your suggestions, I've explored the codebase. Here are the results:

{exploration_results}

Based on these findings, please analyze:
1. Is the project likely affected by the vulnerability?
2. What specific code patterns are concerning?
3. What would you recommend to fix the issue?
"""
        
        # Get LLM analysis of exploration results
        response = self.llm.generate_with_context(prompt, self.conversation_history)
        
        # Add to conversation history
        self.conversation_history.append({
            "role": "user",
            "content": prompt
        })
        self.conversation_history.append({
            "role": "assistant",
            "content": response
        })
        
        # Return the exploration results
        return {
            "exploration_results": exploration_results,
            "exploration_analysis": response
        }
    
    def _perform_exploration(self, suggestions: str, package_name: str) -> str:
        """
        Perform exploration of the codebase based on LLM suggestions.
        
        Args:
            suggestions (str): LLM suggestions for exploration
            package_name (str): Name of the vulnerable package
            
        Returns:
            str: Results of the exploration
        """
        results = []
        
        # Search for the package name in all files
        results.append(f"Searching for package '{package_name}' in all files:")
        matches = self.search_in_files(package_name)
        if matches:
            for file_path, lines in matches.items():
                results.append(f"\nFile: {file_path}")
                for line in lines[:5]:  # Limit to 5 lines per file
                    results.append(f"  {line}")
                if len(lines) > 5:
                    results.append(f"  ... ({len(lines) - 5} more matches)")
        else:
            results.append("  No direct matches found.")
        
        # Look for package.json or requirements.txt to check if the package is declared as a dependency
        dependency_files = self.find_files("package.json") + self.find_files("requirements.txt")
        if dependency_files:
            results.append("\nChecking dependency files:")
            for file_path in dependency_files:
                results.append(f"\nFile: {file_path}")
                content = self.read_file(file_path)
                results.append(f"```\n{content[:1000]}{'...' if len(content) > 1000 else ''}\n```")
        
        # Extract additional search terms from suggestions
        import re
        search_terms = re.findall(r'search for ["\']([^"\']+)["\']', suggestions, re.IGNORECASE)
        search_terms += re.findall(r'search term[s]?:?\s*["\']([^"\']+)["\']', suggestions, re.IGNORECASE)
        search_terms += re.findall(r'search for:?\s*["\']([^"\']+)["\']', suggestions, re.IGNORECASE)
        search_terms += re.findall(r'look for ["\']([^"\']+)["\']', suggestions, re.IGNORECASE)
        
        # Remove duplicates and the package name (already searched)
        search_terms = list(set(search_terms))
        if package_name in search_terms:
            search_terms.remove(package_name)
        
        # Search for additional terms
        if search_terms:
            results.append("\nSearching for additional terms suggested by the analysis:")
            for term in search_terms[:3]:  # Limit to 3 terms to avoid too much output
                results.append(f"\nTerm: '{term}'")
                matches = self.search_in_files(term)
                if matches:
                    for file_path, lines in matches.items():
                        results.append(f"File: {file_path}")
                        for line in lines[:3]:  # Limit to 3 lines per file
                            results.append(f"  {line}")
                        if len(lines) > 3:
                            results.append(f"  ... ({len(lines) - 3} more matches)")
                else:
                    results.append("  No matches found.")
        
        # Extract file patterns from suggestions
        file_patterns = re.findall(r'files? (?:named|called|like) ["\']([^"\']+)["\']', suggestions, re.IGNORECASE)
        file_patterns += re.findall(r'check (?:the )?file[s]? ["\']([^"\']+)["\']', suggestions, re.IGNORECASE)
        
        # Search for specific files
        if file_patterns:
            results.append("\nSearching for specific files suggested by the analysis:")
            for pattern in file_patterns[:3]:  # Limit to 3 patterns
                results.append(f"\nPattern: '{pattern}'")
                files = self.find_files(f"*{pattern}*")
                if files:
                    for file_path in files[:3]:  # Limit to 3 files per pattern
                        results.append(f"File: {file_path}")
                        content = self.read_file(file_path)
                        results.append(f"```\n{content[:500]}{'...' if len(content) > 500 else ''}\n```")
                    if len(files) > 3:
                        results.append(f"... ({len(files) - 3} more files)")
                else:
                    results.append("  No matching files found.")
        
        return "\n".join(results)
    
    def _generate_final_report(self, vulnerability: Dict[str, Any], cve_analysis: Dict[str, Any], codebase_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a final report based on the CVE analysis and codebase exploration.
        
        Args:
            vulnerability (Dict[str, Any]): Vulnerability information
            cve_analysis (Dict[str, Any]): Results of CVE analysis
            codebase_analysis (Dict[str, Any]): Results of codebase exploration
            
        Returns:
            Dict[str, Any]: Final report
        """
        self.logger.info("Step 3: Generating final report")
        
        # Create prompt for final report
        prompt = f"""
Based on our analysis of the vulnerability and exploration of the codebase, please provide a final assessment with the following information:

1. PROJECT_SEVERITY: Assess the severity of this vulnerability for the project (critical, high, medium, low, or info).
2. IS_PROJECT_IMPACTED: Determine if the project is likely impacted by this vulnerability (true/false).
3. IMPACTED_CODE: Identify any code patterns that might be vulnerable.
4. PROPOSED_FIX: Suggest a specific fix for this vulnerability.
5. EXPLANATION: Provide a clear explanation of the vulnerability and its implications for this specific project.

Format your response as follows:
PROJECT_SEVERITY: [Your assessment]
IS_PROJECT_IMPACTED: [true/false]
IMPACTED_CODE: [Your assessment]
PROPOSED_FIX: [Your suggestion]
EXPLANATION: [Your explanation]
"""
        
        # Get LLM final report
        response = self.llm.generate_with_context(prompt, self.conversation_history)
        
        # Add to conversation history
        self.conversation_history.append({
            "role": "user",
            "content": prompt
        })
        self.conversation_history.append({
            "role": "assistant",
            "content": response
        })
        
        # Parse the response to extract the required fields
        import re
        
        project_severity = self._extract_field(response, "PROJECT_SEVERITY")
        is_project_impacted = self._extract_field(response, "IS_PROJECT_IMPACTED")
        impacted_code = self._extract_field(response, "IMPACTED_CODE")
        proposed_fix = self._extract_field(response, "PROPOSED_FIX")
        explanation = self._extract_field(response, "EXPLANATION")
        
        # Convert is_project_impacted to boolean
        is_project_impacted_bool = False
        if is_project_impacted.lower() == "true":
            is_project_impacted_bool = True
        
        # Return the final report
        return {
            "project_severity": project_severity,
            "is_project_impacted": is_project_impacted_bool,
            "impacted_code": impacted_code,
            "proposed_fix": proposed_fix,
            "explanation": explanation,
            "llm_analysis": {
                "is_vulnerable": is_project_impacted_bool,
                "confidence": "medium",
                "impact": project_severity,
                "explanation": explanation,
                "remediation": proposed_fix,
                "provider": self.llm.provider_name,
                "model": self.llm.model_name
            }
        }
    
    def _extract_field(self, text: str, field_name: str) -> str:
        """
        Extract a field from the LLM response.
        
        Args:
            text (str): The LLM response text
            field_name (str): The name of the field to extract
            
        Returns:
            str: The extracted field value, or a default message if not found
        """
        import re
        pattern = rf"{field_name}:\s*(.*?)(?:\n[A-Z_]+:|$)"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return f"No {field_name.lower()} provided."