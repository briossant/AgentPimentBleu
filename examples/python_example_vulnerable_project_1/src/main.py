"""
Example vulnerable Flask application using Werkzeug 0.10.0.

This application enables the Werkzeug debugger, which is known to be vulnerable
in old versions if the pin is guessable or disabled.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# Deliberately set a weak secret key
app.secret_key = "very_predictable_secret_key"

# Enable debug mode, which activates the Werkzeug debugger
app.debug = True

# Disable the PIN protection for the debugger (extremely insecure!)
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['WERKZEUG_DEBUG_PIN'] = 'off'

@app.route('/')
def index():
    """Render a simple welcome page."""
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Flask App</title>
    </head>
    <body>
        <h1>Welcome to the Vulnerable Flask App</h1>
        <p>This application uses Werkzeug 0.10.0 with the debug console enabled.</p>
        <p>The debug console is vulnerable to Remote Code Execution (RCE) in this version.</p>
        <p>Try accessing a non-existent route to trigger the debugger.</p>
    </body>
    </html>
    """
    return render_template_string(template)

@app.route('/user/<username>')
def user_profile(username):
    """
    A route that will cause an error if accessed with certain usernames.
    This will trigger the Werkzeug debugger.
    """
    # Deliberately cause an error when username is 'error'
    if username == 'error':
        # This will raise an exception and trigger the debugger
        return non_existent_function()
    
    template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Profile</title>
    </head>
    <body>
        <h1>Profile for {username}</h1>
        <p>This is a placeholder for user data.</p>
    </body>
    </html>
    """
    return render_template_string(template)

if __name__ == '__main__':
    # Run the application with the debugger enabled
    app.run(host='0.0.0.0', port=5000, debug=True)