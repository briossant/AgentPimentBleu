# Python Example Vulnerable Project 1

This project uses Werkzeug 0.10.0. An old version of Werkzeug with an improperly secured debugger can lead to Remote Code Execution (RCE).

## Vulnerability Details

This example demonstrates a vulnerability in Werkzeug 0.10.0 (CVE-2016-10149) where the debug console can be exploited for Remote Code Execution if:

1. The application is running in debug mode
2. The debugger PIN is disabled or easily guessable

In this example, we've deliberately:
- Used Werkzeug 0.10.0, which has a known vulnerability
- Enabled debug mode in the Flask application
- Disabled the PIN protection for the debugger
- Created a route that will trigger an error to activate the debugger

## How to Test

1. Install the requirements: `pip install -r requirements.txt`
2. Run the application: `python src/main.py`
3. Visit http://localhost:5000/user/error in your browser
4. You'll see the Werkzeug debugger console, which allows executing arbitrary Python code

## Expected AgentPimentBleu Analysis

AgentPimentBleu should identify CVE-2016-10149 (or similar related to Werkzeug debugger) and assess its impact. It should recognize that:

1. The project uses a vulnerable version of Werkzeug
2. The application explicitly enables the debug mode
3. The application disables the PIN protection
4. This combination creates a high-risk Remote Code Execution vulnerability

The analysis should recommend updating to a newer version of Werkzeug and disabling debug mode in production environments.