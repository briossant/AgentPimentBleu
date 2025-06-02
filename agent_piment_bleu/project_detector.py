import os

def detect_project_languages(repo_path):
    """
    Detect programming languages used in the repository.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        list: List of detected languages (e.g., ['javascript', 'python'])
    """
    languages = set()
    
    # Check for JavaScript/TypeScript
    if _is_js_project(repo_path):
        languages.add('javascript')
    
    # Check for Python
    if _is_python_project(repo_path):
        languages.add('python')
    
    # Return as a list
    return list(languages)

def _is_js_project(repo_path):
    """
    Check if the repository contains JavaScript/TypeScript files or has package.json.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        bool: True if JavaScript/TypeScript files or package.json are found, False otherwise
    """
    # Check for package.json
    if os.path.isfile(os.path.join(repo_path, 'package.json')):
        return True
    
    # Check for JavaScript/TypeScript files
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.js') or file.endswith('.jsx') or file.endswith('.ts') or file.endswith('.tsx'):
                return True
    
    return False

def _is_python_project(repo_path):
    """
    Check if the repository contains Python files or has Python dependency files.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        bool: True if Python files or dependency files are found, False otherwise
    """
    # Check for Python dependency files
    python_dependency_files = [
        'requirements.txt',
        'setup.py',
        'Pipfile',
        'pyproject.toml',
        'poetry.lock'
    ]
    
    for dep_file in python_dependency_files:
        if os.path.isfile(os.path.join(repo_path, dep_file)):
            return True
    
    # Check for Python files
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.py'):
                return True
    
    return False