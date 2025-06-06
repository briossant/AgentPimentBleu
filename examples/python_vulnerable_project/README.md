# Python Vulnerable Project

A comprehensive vulnerable Python Flask application for AgentPimentBleu testing. This project demonstrates multiple vulnerabilities with varying severity ratings.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python app.py
   ```

3. The server will start at http://localhost:5000

## Vulnerabilities

This project contains the following intentional vulnerabilities:

### V1: Werkzeug Debugger RCE (Critical)

* **Route & Method:** `GET /trigger_error`
* **Vulnerable Component / How it Works:** The application is configured with `app.debug = True` and the Werkzeug debugger PIN is disabled with `os.environ["WERKZEUG_DEBUG_PIN"] = "off"`. When an error occurs (deliberately triggered at this endpoint), the Werkzeug debugger is exposed, allowing arbitrary code execution.
* **Affected Dependency & Version:** `Werkzeug==0.16.1`
* **Relevant CVE(s):** While not a specific CVE, this is a well-known vulnerability when Werkzeug debugger is exposed in production.
* **Example Exploitation:**
  ```bash
  curl "http://localhost:5000/trigger_error"
  ```
  This will trigger a ZeroDivisionError. In the browser, you can access the interactive console and execute arbitrary Python code.
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** Should identify the Werkzeug version and debug mode as a critical security risk.
  * **Evidence in Code:** Should highlight `app.debug = True` and `os.environ["WERKZEUG_DEBUG_PIN"] = "off"`.
  * **Danger Rating:** Expected: Critical
  * **Impact Summary:** "The application runs with debug mode enabled and the Werkzeug debugger PIN disabled. This exposes an interactive Python console when errors occur, allowing attackers to execute arbitrary code on the server with the same privileges as the application process."

### V2: Insecure Deserialization (YAML - High)

* **Route & Method:** `POST /admin/load_data_from_yaml` (GET displays a form)
* **Vulnerable Component / How it Works:** The endpoint accepts YAML data from a form submission and processes it using `yaml.unsafe_load()`. This function can execute arbitrary Python code if a specially crafted YAML payload is provided.
* **Affected Dependency & Version:** `PyYAML==5.1`
* **Relevant CVE(s):** While CVE-2017-18342 targets `yaml.load`, the use of `yaml.unsafe_load` is inherently dangerous and allows for similar arbitrary code execution.
* **Example Exploitation:**
  Submit the following YAML payload via the form on `/admin/load_data_from_yaml` or via `curl`:
  ```yaml
  !!python/object/apply:os.system
  args: ["touch /tmp/yaml_exploited_by_agentpimentbleu_test"]
  # Or for Windows: args: ["cmd.exe /c echo pwned > C:\\pwned_yaml.txt"]
  ```
  Or with `curl`:
  ```bash
  curl -X POST -d 'yaml_data=!!python/object/apply:os.system%0Aargs: ["touch /tmp/yaml_pwned_curl"]' http://localhost:5000/admin/load_data_from_yaml
  ```
  Check if the file `/tmp/yaml_exploited_by_agentpimentbleu_test` or `/tmp/yaml_pwned_curl` was created on the server.
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** Should flag PyYAML 5.1 as vulnerable if specific CVEs exist for `unsafe_load` in this version or related to general deserialization risks.
  * **Evidence in Code:** Should pinpoint the `yaml.unsafe_load(request.form.get('yaml_data', ''))` line in `app.py`.
  * **Danger Rating:** Expected: High.
  * **Impact Summary:** "The application uses `yaml.unsafe_load` to process user-supplied YAML data. This can lead to arbitrary code execution on the server if a malicious YAML payload is submitted, granting the attacker full control over the application server."

### V3: Server-Side Request Forgery (SSRF - High)

* **Route & Method:** `GET /api/fetch_external_content`
* **Query Param:** `url`
* **Vulnerable Component / How it Works:** The endpoint uses `requests.get(url)` to fetch content from a URL provided by the user without any validation or restrictions.
* **Affected Dependency & Version:** `Requests==2.20.0`
* **Relevant CVE(s):** N/A (Code-level vulnerability)
* **Example Exploitation:**
  ```bash
  curl "http://localhost:5000/api/fetch_external_content?url=http://localhost:5000"
  ```
  This is a simple example that fetches the application itself. An attacker could target internal services or use file:// URLs.
  ```bash
  curl "http://localhost:5000/api/fetch_external_content?url=file:///etc/passwd"
  ```
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** N/A (Code-level vulnerability)
  * **Evidence in Code:** Should highlight the use of `requests.get(url)` where `url` is from `request.args.get('url', '')`.
  * **Danger Rating:** Expected: High
  * **Impact Summary:** "The application allows attackers to make the server perform HTTP requests to arbitrary destinations, including internal services not normally accessible from the internet. This could lead to internal service enumeration, accessing sensitive internal APIs, or in some cases, reading local files via file:// URLs."

### V4: OS Command Injection (High)

* **Route & Method:** `GET /api/system/lookup`
* **Query Param:** `hostname`
* **Vulnerable Component / How it Works:** The endpoint directly passes user input to `subprocess.check_output()` with `shell=True`, allowing command injection.
* **Affected Dependency & Version:** N/A (Python `subprocess` module)
* **Relevant CVE(s):** N/A (Code-level vulnerability)
* **Example Exploitation:**
  ```bash
  curl "http://localhost:5000/api/system/lookup?hostname=example.com"
  ```
  This is a legitimate use. An attacker might try:
  ```bash
  curl "http://localhost:5000/api/system/lookup?hostname=example.com; id"
  ```
  Or:
  ```bash
  curl "http://localhost:5000/api/system/lookup?hostname=example.com && touch /tmp/pwned"
  ```
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** N/A (Code-level vulnerability)
  * **Evidence in Code:** Should highlight the use of `subprocess.check_output(f"nslookup {hostname}", shell=True)` where `hostname` is from `request.args.get('hostname', '')`.
  * **Danger Rating:** Expected: High
  * **Impact Summary:** "The application executes shell commands with user-controlled input without proper sanitization. This allows attackers to inject arbitrary commands that will be executed on the server with the same privileges as the application process."

### V5: Cross-Site Scripting (XSS) via Jinja2 (Medium)

* **Route & Method:** `GET /user/<username>` and `GET /user/<username>?custom_bio=<payload>`
* **Vulnerable Component / How it Works:** The endpoint renders a template with user-controlled data. The username is passed to the template with the `|safe` filter, which prevents automatic escaping.
* **Affected Dependency & Version:** `Jinja2==2.10.1`, `Flask==1.1.2`
* **Relevant CVE(s):** N/A (Code-level vulnerability)
* **Example Exploitation:**
  ```
  http://localhost:5000/user/<script>alert('XSS')</script>
  ```
  Or:
  ```
  http://localhost:5000/user/alice?custom_bio=<script>alert('XSS')</script>
  ```
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** N/A (Code-level vulnerability)
  * **Evidence in Code:** Should highlight the use of `{{ username | safe }}` in the template and the passing of user-controlled data to the template.
  * **Danger Rating:** Expected: Medium
  * **Impact Summary:** "The application renders user input without proper escaping in the user profile page, allowing attackers to inject malicious JavaScript that executes in victims' browsers. This could lead to session hijacking, credential theft, or other client-side attacks."

### V6: SQL Injection (Medium)

* **Route & Method:** `GET /api/user_details`
* **Query Param:** `username`
* **Vulnerable Component / How it Works:** The endpoint constructs a SQL query using string formatting with user input, allowing SQL injection.
* **Affected Dependency & Version:** N/A (Python `sqlite3` module)
* **Relevant CVE(s):** N/A (Code-level vulnerability)
* **Example Exploitation:**
  ```bash
  curl "http://localhost:5000/api/user_details?username=alice"
  ```
  This is a legitimate use. An attacker might try:
  ```bash
  curl "http://localhost:5000/api/user_details?username=alice' OR '1'='1"
  ```
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** N/A (Code-level vulnerability)
  * **Evidence in Code:** Should highlight the use of `query = f"SELECT id, username, bio FROM users WHERE username = '{username}'"` where `username` is from `request.args.get('username', '')`.
  * **Danger Rating:** Expected: Medium
  * **Impact Summary:** "The application constructs SQL queries using string formatting with user-controlled input. This allows attackers to inject malicious SQL code, potentially leading to unauthorized data access, data manipulation, or in some cases, server-side code execution."

### V7: Path Traversal (File Read - Medium)

* **Route & Method:** `GET /files/view`
* **Query Param:** `filename`
* **Vulnerable Component / How it Works:** The endpoint reads files based on a user-provided filename parameter without proper path validation, allowing attackers to access files outside the intended directory.
* **Affected Dependency & Version:** N/A (Python `os` module)
* **Relevant CVE(s):** N/A (Code-level vulnerability)
* **Example Exploitation:**
  ```bash
  curl "http://localhost:5000/files/view?filename=notes.txt"
  ```
  This is a legitimate use. An attacker might try:
  ```bash
  curl "http://localhost:5000/files/view?filename=../../../etc/passwd"
  ```
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** N/A (Code-level vulnerability)
  * **Evidence in Code:** Should highlight the use of `file_path = os.path.join(STATIC_TEXT_FOLDER, filename)` without sanitization.
  * **Danger Rating:** Expected: Medium
  * **Impact Summary:** "The application allows reading files from the server's filesystem without proper path validation, potentially exposing sensitive files outside the intended directory. Attackers could access configuration files, credentials, or other sensitive information stored on the server."

### V8: Weak Session Management (Medium)

* **Route & Method:** `GET/POST /login` and `GET /admin`
* **Vulnerable Component / How it Works:** The application uses a weak, hardcoded secret key for session management, making it vulnerable to session prediction or tampering.
* **Affected Dependency & Version:** `itsdangerous==0.24`, `Flask==1.1.2`
* **Relevant CVE(s):** N/A (Configuration vulnerability)
* **Example Exploitation:** An attacker with knowledge of the secret key could forge session cookies to impersonate other users.
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** N/A (Configuration vulnerability)
  * **Evidence in Code:** Should highlight the use of `app.secret_key = "this_is_not_a_secret"`.
  * **Danger Rating:** Expected: Medium
  * **Impact Summary:** "The application uses a weak, hardcoded secret key for session management. This could allow attackers to predict or forge session cookies, potentially leading to unauthorized access to user accounts or administrative functions."

## Disclaimer

This project is intentionally vulnerable for educational and testing purposes. Do not deploy it in a production environment or expose it to the internet.