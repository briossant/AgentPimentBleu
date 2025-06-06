import os
import yaml
import requests
import subprocess
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, g, session, make_response

app = Flask(__name__)
app.secret_key = "this_is_not_a_secret"
app.debug = True
os.environ["WERKZEUG_DEBUG_PIN"] = "off"

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
STATIC_TEXT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'text_files')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(':memory:')
        cursor = db.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, bio TEXT)")
        cursor.execute("INSERT INTO users (username, password, bio) VALUES (?, ?, ?)",
                       ('alice', 'alicepass', 'Loves wonderland.'))
        cursor.execute("INSERT INTO users (username, password, bio) VALUES (?, ?, ?)",
                       ('bob', 'bobpass', 'Builds things.'))
        db.commit()
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/trigger_error')
def trigger_error():
    return 1/0

@app.route('/admin/load_data_from_yaml', methods=['GET', 'POST'])
def load_yaml_data():
    message = None
    error = None

    if request.method == 'POST':
        yaml_data = request.form.get('yaml_data', '')
        try:
            parsed_data = yaml.unsafe_load(yaml_data)
            message = f"YAML data loaded successfully: {parsed_data}"
        except Exception as e:
            error = f"Error loading YAML: {str(e)}"

    return render_template('load_yaml_form.html', message=message, error=error)

@app.route('/api/fetch_external_content')
def fetch_external_content():
    url = request.args.get('url', '')
    if not url:
        return "Error: No URL provided", 400

    try:
        response = requests.get(url, timeout=3)
        return response.text
    except Exception as e:
        return f"Error fetching URL: {str(e)}", 500

@app.route('/api/system/lookup')
def system_lookup():
    hostname = request.args.get('hostname', '')
    if not hostname:
        return "Error: No hostname provided", 400

    try:
        output = subprocess.check_output(f"nslookup {hostname}", shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.output.decode('utf-8')}", 500

@app.route('/user/<username>')
def user_profile(username):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT bio FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result:
        bio = result[0]
    else:
        bio = "User not found"

    custom_bio = request.args.get('custom_bio')
    if custom_bio:
        bio = custom_bio
    return render_template('user_profile.html', username=username, bio=bio)

@app.route('/api/user_details')
def user_details():
    username = request.args.get('username', '')
    if not username:
        return "Error: No username provided", 400

    db = get_db()
    cursor = db.cursor()

    try:
        query = f"SELECT id, username, bio FROM users WHERE username = '{username}'"
        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            return {
                "id": result[0],
                "username": result[1],
                "bio": result[2]
            }
        else:
            return "User not found", 404
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/files/view')
def view_file():
    filename = request.args.get('filename', '')
    if not filename:
        return "Error: No filename provided", 400

    try:
        file_path = os.path.join(STATIC_TEXT_FOLDER, filename)
        with open(file_path, 'r') as file:
            content = file.read()

        return render_template('view_file.html', filename=filename, content=content)
    except Exception as e:
        return f"Error reading file: {str(e)}", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
        result = cursor.fetchone()

        if result:
            session['user_id'] = result[0]
            session['username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid credentials"

    return render_template('login.html', error=error)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    return f"Welcome to the admin dashboard, {session.get('username', 'User')}!"

@app.route('/create_home_template')
def create_home_template():
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    home_template_path = os.path.join(template_dir, 'home.html')

    if not os.path.exists(home_template_path):
        with open(home_template_path, 'w') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Python Application</title>
</head>
<body>
    <h1>Vulnerable Python Application</h1>
    <p>This application contains multiple vulnerabilities for testing purposes.</p>
    <h2>Available Routes:</h2>
    <ul>
        <li><a href="/trigger_error">Trigger Error (Werkzeug Debugger RCE)</a></li>
        <li><a href="/admin/load_data_from_yaml">Load YAML Data (Insecure Deserialization)</a></li>
        <li><a href="/api/fetch_external_content?url=https://example.com">Fetch External Content (SSRF)</a></li>
        <li><a href="/api/system/lookup?hostname=example.com">System Lookup (Command Injection)</a></li>
        <li><a href="/user/alice">User Profile - Alice (XSS)</a></li>
        <li><a href="/user/alice?custom_bio=<script>alert('XSS')</script>">User Profile with XSS Payload</a></li>
        <li><a href="/api/user_details?username=alice">User Details - Alice (SQL Injection)</a></li>
        <li><a href="/api/user_details?username=alice' OR '1'='1">User Details with SQL Injection</a></li>
        <li><a href="/files/view?filename=notes.txt">View File - notes.txt (Path Traversal)</a></li>
        <li><a href="/login">Login (Weak Session Management)</a></li>
    </ul>
</body>
</html>""")
        return "Home template created"

    return "Home template already exists"

@app.route('/create_login_template')
def create_login_template():
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    login_template_path = os.path.join(template_dir, 'login.html')

    if not os.path.exists(login_template_path):
        with open(login_template_path, 'w') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    <form method="POST" action="/login">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <input type="submit" value="Login">
    </form>
    <p>Try using alice/alicepass or bob/bobpass</p>
</body>
</html>""")
        return "Login template created"

    return "Login template already exists"

if __name__ == '__main__':
    with app.test_request_context():
        create_home_template()
        create_login_template()

    app.run(host='0.0.0.0', port=5000)
