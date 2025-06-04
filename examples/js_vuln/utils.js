/**
 * Utility functions for the application
 */

const crypto = require('crypto');

/**
 * Generate a random token
 * @param {number} length - Length of the token
 * @returns {string} Random token
 */
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Validate user input
 * @param {object} input - User input object
 * @param {array} requiredFields - Required fields
 * @returns {object} Validation result
 */
function validateInput(input, requiredFields) {
  const errors = [];
  
  // Check required fields
  for (const field of requiredFields) {
    if (!input[field]) {
      errors.push(`${field} is required`);
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Sanitize user input - VULNERABLE: Incomplete sanitization
 * @param {string} input - User input
 * @returns {string} Sanitized input
 */
function sanitizeInput(input) {
  // This is an incomplete sanitization that doesn't properly handle all XSS vectors
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Parse query parameters - VULNERABLE: Doesn't handle parameter pollution
 * @param {string} queryString - Query string
 * @returns {object} Parsed parameters
 */
function parseQueryParams(queryString) {
  const params = {};
  const pairs = queryString.split('&');
  
  for (const pair of pairs) {
    const [key, value] = pair.split('=');
    params[key] = decodeURIComponent(value || '');
  }
  
  return params;
}

/**
 * Log user activity
 * @param {string} userId - User ID
 * @param {string} action - Action performed
 * @param {object} data - Additional data
 */
function logActivity(userId, action, data = {}) {
  const timestamp = new Date().toISOString();
  console.log(JSON.stringify({
    timestamp,
    userId,
    action,
    data
  }));
}

module.exports = {
  generateToken,
  validateInput,
  sanitizeInput,
  parseQueryParams,
  logActivity
};