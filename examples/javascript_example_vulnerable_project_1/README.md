# JavaScript Example Vulnerable Project 1

This project uses lodash 4.17.10. It demonstrates prototype pollution (e.g., CVE-2019-10744, CVE-2020-8203). AgentPimentBleu should identify the relevant CVE and highlight the use of vulnerable functions like `_.set`.

## Vulnerability Details

This example demonstrates a prototype pollution vulnerability in lodash 4.17.10 where the `_.set` function can be exploited to modify the Object prototype. This vulnerability is tracked as:

- CVE-2019-10744: Prototype pollution in lodash before 4.17.12
- CVE-2020-8203: Prototype pollution in lodash before 4.17.19

Prototype pollution occurs when an attacker is able to add or modify properties of an object's prototype (e.g., Object.prototype). Since all JavaScript objects inherit from this prototype, this can lead to:

1. Security bypass (as demonstrated in the example)
2. Denial of service
3. In some cases, remote code execution

## How to Test

1. Install dependencies: `npm install`
2. Run the application: `node index.js`
3. Observe how the prototype pollution allows a regular user to gain admin privileges

## Code Explanation

The example demonstrates:

```javascript
const _ = require('lodash');
const obj = {};
const maliciousInput = '__proto__';
_.set(obj, maliciousInput + '.isAdmin', true);
```

This code uses the vulnerable `_.set` function to add an `isAdmin` property to the Object prototype. After this, all JavaScript objects will have `isAdmin: true`, which can bypass security checks.

## Expected AgentPimentBleu Analysis

AgentPimentBleu should:

1. Identify that the project uses lodash 4.17.10, which is vulnerable to prototype pollution
2. Recognize the specific CVEs (CVE-2019-10744, CVE-2020-8203)
3. Highlight that the code explicitly uses the vulnerable `_.set` function with `__proto__`
4. Assess this as a high-risk vulnerability since the code actively exploits the vulnerability
5. Recommend updating to lodash 4.17.19 or later

The analysis should recognize that this is not just a theoretical vulnerability but one that is actively exploited in the code.