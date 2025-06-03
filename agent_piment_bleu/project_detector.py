import os
from agent_piment_bleu.logger import get_logger

def detect_project_languages(repo_path):
    """
    Detect programming languages used in the repository.

    Args:
        repo_path (str): Path to the repository

    Returns:
        list: List of detected languages (e.g., ['javascript', 'python'])
    """
    logger = get_logger()
    logger.info(f"Detecting programming languages in repository: {repo_path}")

    languages = set()

    # Check for JavaScript/TypeScript
    logger.info("Checking for JavaScript/TypeScript files")
    if _is_js_project(repo_path):
        logger.info("JavaScript/TypeScript detected")
        languages.add('javascript')

    # Check for Python
    logger.info("Checking for Python files")
    if _is_python_project(repo_path):
        logger.info("Python detected")
        languages.add('python')

    # Return as a list
    detected_languages = list(languages)
    logger.info(f"Detected languages: {', '.join(detected_languages) if detected_languages else 'None'}")
    return detected_languages

def _is_js_project(repo_path):
    """
    Check if the repository contains JavaScript/TypeScript files or has package.json.

    Args:
        repo_path (str): Path to the repository

    Returns:
        bool: True if JavaScript/TypeScript files or package.json are found, False otherwise
    """
    logger = get_logger()

    # Check for package.json
    package_json_path = os.path.join(repo_path, 'package.json')
    if os.path.isfile(package_json_path):
        logger.debug(f"Found package.json at {package_json_path}")
        return True

    # Check for JavaScript/TypeScript files
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.js') or file.endswith('.jsx') or file.endswith('.ts') or file.endswith('.tsx'):
                logger.debug(f"Found JavaScript/TypeScript file: {os.path.join(root, file)}")
                return True

    logger.debug("No JavaScript/TypeScript files found")
    return False

def _is_python_project(repo_path):
    """
    Check if the repository contains Python files or has Python dependency files.

    Args:
        repo_path (str): Path to the repository

    Returns:
        bool: True if Python files or dependency files are found, False otherwise
    """
    logger = get_logger()

    # Check for Python dependency files
    python_dependency_files = [
        'requirements.txt',
        'setup.py',
        'Pipfile',
        'pyproject.toml',
        'poetry.lock'
    ]

    for dep_file in python_dependency_files:
        dep_file_path = os.path.join(repo_path, dep_file)
        if os.path.isfile(dep_file_path):
            logger.debug(f"Found Python dependency file: {dep_file_path}")
            return True

    # Check for Python files
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.py'):
                logger.debug(f"Found Python file: {os.path.join(root, file)}")
                return True

    logger.debug("No Python files found")
    return False
