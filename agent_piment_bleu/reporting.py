def generate_markdown_report(aggregated_results):
    """
    Generate a Markdown report from the aggregated scan results.
    
    Args:
        aggregated_results (dict): Aggregated results from all scanners with keys:
            - repo_url (str): URL of the scanned repository
            - languages (list): List of detected languages
            - scan_results (list): List of results from individual scanners
            
    Returns:
        str: Markdown formatted report
    """
    repo_url = aggregated_results.get('repo_url', 'Unknown repository')
    languages = aggregated_results.get('languages', [])
    scan_results = aggregated_results.get('scan_results', [])
    
    # Start building the report
    report = f"""
    ## Scan Results

    Repository: {repo_url}

    ### Summary

    The repository was successfully scanned for security issues.
    
    Detected languages: {', '.join(languages) if languages else 'None detected'}
    """
    
    # Add scan status for each scanner
    report += "\n\nScan Status:\n"
    for result in scan_results:
        report += f"- {result['language'].capitalize()} {result['scan_type']}: {result['message']}\n"
    
    # Process SAST findings
    sast_findings = [r for r in scan_results if r['scan_type'] == 'SAST' and r['success']]
    for result in sast_findings:
        language = result['language'].capitalize()
        report += f"\n\n### SAST Findings ({language})\n\n"
        
        if result['findings']:
            for finding in result['findings']:
                report += f"- **{finding.get('rule', 'Unknown rule')}** ({finding.get('severity', 'unknown')})\n"
                report += f"  - File: `{finding.get('file', 'unknown')}`, Line: {finding.get('line', 'N/A')}\n"
                report += f"  - {finding.get('message', 'No description available')}\n\n"
        else:
            report += f"No security issues found in {language} code.\n"
    
    # Process SCA findings
    sca_findings = [r for r in scan_results if r['scan_type'] == 'SCA' and r['success']]
    for result in sca_findings:
        language = result['language'].capitalize()
        report += f"\n\n### SCA Findings ({language} dependencies)\n\n"
        
        if result['findings']:
            for finding in result['findings']:
                # Handle different formats from different scanners
                if 'package' in finding:  # npm audit format
                    report += f"- **{finding.get('package', 'Unknown package')}** (version: {finding.get('version', 'unknown')}, severity: {finding.get('severity', 'unknown')})\n"
                    report += f"  - {finding.get('title', finding.get('message', 'No description available'))}\n"
                    
                    if finding.get('cve') and finding['cve'] != "N/A":
                        report += f"  - CVE: {finding['cve']}\n"
                    
                    if finding.get('url'):
                        report += f"  - More info: {finding['url']}\n"
                    
                    if finding.get('recommendation'):
                        report += f"  - Recommendation: {finding['recommendation']}\n\n"
                else:  # Generic format
                    report += f"- **{finding.get('name', 'Unknown package')}** (severity: {finding.get('severity', 'unknown')})\n"
                    report += f"  - {finding.get('message', 'No description available')}\n"
                    
                    if finding.get('cve'):
                        report += f"  - CVE: {finding['cve']}\n"
                    
                    if finding.get('file'):
                        report += f"  - Found in: {finding['file']}\n\n"
        else:
            report += f"No vulnerable dependencies found in {language} packages.\n"
    
    # Add note about AI-powered impact assessments
    report += "\n\n### Future Enhancements\n\n"
    report += "In future versions, this report will include:\n"
    report += "- AI-powered impact assessments for vulnerabilities\n"
    report += "- More detailed analysis of code and dependencies\n"
    
    return report