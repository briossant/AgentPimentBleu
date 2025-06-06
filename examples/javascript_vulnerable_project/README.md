# JavaScript Vulnerable Project

A comprehensive vulnerable JavaScript application for AgentPimentBleu testing. This project demonstrates multiple vulnerabilities with varying severity ratings.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Run the application:
   ```bash
   npm start
   ```

3. The server will start at http://localhost:3000

## Vulnerabilities

This project contains the following intentional vulnerabilities:

### V1: Command Injection (Critical)

* **Route & Method:** `GET /api/system/exec`
* **Vulnerable Component / How it Works:** The endpoint directly passes `req.query.cmd` to `child_process.exec()` without any sanitization or validation.
* **Affected Dependency & Version:** N/A (Node.js built-in `child_process`)
* **Relevant CVE(s):** N/A (Code-level vulnerability)
* **Example Exploitation:**
  ```bash
  curl "http://localhost:3000/api/system/exec?cmd=ls"
  ```
  This will list files in the current directory. An attacker could use more malicious commands.
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** N/A (Code-level vulnerability)
  * **Evidence in Code:** Should highlight the use of `child_process.exec(cmd)` where `cmd` is from `req.query`.
  * **Danger Rating:** Expected: Critical
  * **Impact Summary:** "The application allows unauthenticated attackers to execute arbitrary system commands on the server, potentially leading to complete system compromise, data theft, or service disruption."

### V2: Prototype Pollution (High)

* **Route & Method:** `POST /api/config/merge`
* **Vulnerable Component / How it Works:** The endpoint uses `_.merge()` from `lodash@4.17.10` to merge user-supplied JSON data from the request body into a server-side `appConfig` object. This version of `lodash` is vulnerable to prototype pollution, allowing an attacker to modify `Object.prototype`.
* **Affected Dependency & Version:** `lodash@4.17.10`
* **Relevant CVE(s):** CVE-2019-10744, CVE-2020-8203 (and others related to lodash prototype pollution around this version)
* **Example Exploitation:**
  ```bash
  curl -X POST -H "Content-Type: application/json" \
  -d '{"__proto__": {"isAdmin": true}}' \
  http://localhost:3000/api/config/merge
  ```
  After this, `({}).isAdmin` might evaluate to `true` within the application.
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** Should identify relevant lodash CVEs like CVE-2019-10744.
  * **Evidence in Code:** Should pinpoint the `_.merge(appConfig, req.body);` line in `app.js`.
  * **Danger Rating:** Expected: High
  * **Impact Summary:** "The application's use of a vulnerable `lodash.merge` function with untrusted user input from `req.body` allows for prototype pollution. This could lead to modification of global object prototypes, potentially resulting in application logic bypasses, denial of service, or other unexpected behaviors. For instance, an attacker could set properties like `isAdmin` on `Object.prototype`, affecting authorization checks across the application."

### V3: Server-Side Request Forgery (SSRF) (High)

* **Route & Method:** `GET /api/fetch-url`
* **Vulnerable Component / How it Works:** The endpoint uses `axios.get()` to fetch content from a URL provided by the user without proper validation or restrictions.
* **Affected Dependency & Version:** `axios@0.18.0`
* **Relevant CVE(s):** While older axios versions had various issues, this is primarily a code-level SSRF vulnerability.
* **Example Exploitation:**
  ```bash
  curl "http://localhost:3000/api/fetch-url?targetUrl=http://localhost:3000"
  ```
  This is a simple example. An attacker could target internal services or use file:// URLs.
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** May identify axios-related CVEs if present.
  * **Evidence in Code:** Should highlight the use of `axios.get(targetUrl)` where `targetUrl` is from `req.query`.
  * **Danger Rating:** Expected: High
  * **Impact Summary:** "The application allows attackers to make the server perform HTTP requests to arbitrary destinations, including internal services not normally accessible from the internet. This could lead to internal service enumeration, accessing sensitive internal APIs, or in some cases, reading local files via file:// URLs."

### V4: Path Traversal (Medium)

* **Route & Method:** `GET /api/files/read`
* **Vulnerable Component / How it Works:** The endpoint reads files based on a user-provided filename parameter without proper path validation, allowing attackers to access files outside the intended directory.
* **Affected Dependency & Version:** N/A (Node.js built-in `fs`, `path`)
* **Relevant CVE(s):** N/A (Code-level vulnerability)
* **Example Exploitation:**
  ```bash
  curl "http://localhost:3000/api/files/read?filename=welcome.txt"
  ```
  This is a legitimate use. An attacker might try:
  ```bash
  curl "http://localhost:3000/api/files/read?filename=../../../etc/passwd"
  ```
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** N/A (Code-level vulnerability)
  * **Evidence in Code:** Should highlight the use of `path.join(__dirname, 'public_files', filename)` without sanitization.
  * **Danger Rating:** Expected: Medium
  * **Impact Summary:** "The application allows reading files from the server's filesystem without proper path validation, potentially exposing sensitive files outside the intended directory. Attackers could access configuration files, credentials, or other sensitive information stored on the server."

### V5: Reflected XSS via EJS (Medium)

* **Route & Method:** `GET /search`
* **Vulnerable Component / How it Works:** The endpoint renders an EJS template with unescaped user input using the `<%- query %>` syntax.
* **Affected Dependency & Version:** `ejs@2.5.7`
* **Relevant CVE(s):** While specific EJS versions may have had issues, this is primarily a code-level XSS vulnerability due to using unescaped output.
* **Example Exploitation:**
  ```
  http://localhost:3000/search?query=<script>alert('XSS')</script>
  ```
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** May identify EJS-related CVEs if present.
  * **Evidence in Code:** Should highlight the use of `<%- query %>` in the template with user-controlled input.
  * **Danger Rating:** Expected: Medium
  * **Impact Summary:** "The application renders user input without proper escaping in the search results page, allowing attackers to inject malicious JavaScript that executes in victims' browsers. This could lead to session hijacking, credential theft, or other client-side attacks."

### V6: Reflected XSS via Handlebars (Medium)

* **Route & Method:** `GET /content`
* **Vulnerable Component / How it Works:** The endpoint uses Handlebars to render a template with unescaped user input using the `{{{content}}}` triple-stash syntax.
* **Affected Dependency & Version:** `handlebars@4.0.11`
* **Relevant CVE(s):** CVE-2019-19919 and others related to Handlebars XSS vulnerabilities.
* **Example Exploitation:**
  ```
  http://localhost:3000/content?data=<script>alert('XSS')</script>
  ```
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** Should identify Handlebars-related CVEs.
  * **Evidence in Code:** Should highlight the use of `{{{content}}}` in the template with user-controlled input.
  * **Danger Rating:** Expected: Medium
  * **Impact Summary:** "The application renders user input without proper escaping in the content page, allowing attackers to inject malicious JavaScript that executes in victims' browsers. This could lead to session hijacking, credential theft, or other client-side attacks."

### V7: ReDoS in `ms` dependency (Low/Informational)

* **Vulnerable Component / How it Works:** The application includes `ms@2.0.0` which is vulnerable to Regular Expression Denial of Service (ReDoS).
* **Affected Dependency & Version:** `ms@2.0.0`
* **Relevant CVE(s):** CVE-2017-16042
* **Example Exploitation:** While the application uses `ms()` in the homepage, it's with a safe, hardcoded value. A real exploitation would require passing untrusted input to the `ms()` function.
* **Expected AgentPimentBleu Analysis:**
  * **CVE Identification:** Should identify CVE-2017-16042 from `npm audit`.
  * **Evidence in Code:** Should note the import and usage of the vulnerable `ms` package.
  * **Danger Rating:** Expected: Low/Informational (since it's not used with untrusted input)
  * **Impact Summary:** "The application uses a version of the 'ms' package that is vulnerable to Regular Expression Denial of Service (ReDoS). However, since it appears to be used only with trusted input, the actual risk is low. In a worst-case scenario where untrusted input reaches the function, it could cause high CPU usage and temporary service disruption."

## Disclaimer

This project is intentionally vulnerable for educational and testing purposes. Do not deploy it in a production environment or expose it to the internet.