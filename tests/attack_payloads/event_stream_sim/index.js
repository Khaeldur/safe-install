/**
 * Simulates the event-stream / flatmap-stream npm attack pattern.
 * Dynamic require with obfuscated module, base64 decoded payload,
 * conditional execution targeting specific environments.
 * HARMLESS: Payload is a no-op string. No real modules loaded.
 */

var Stream = require('stream');

// Obfuscated module name construction (mimics flatmap-stream pattern)
var moduleChunks = ['./tes', 't/', 'dat', 'a'];
var moduleName = moduleChunks.join('');

// Base64-encoded "payload" (just a harmless string for testing)
var encoded = Buffer.from(
    'Y29uc29sZS5sb2coInRlc3QgcGF5bG9hZCAtIG5vdCBtYWxpY2lvdXMiKQ==',
    'base64'
).toString();

// Conditional execution based on environment (targets specific package)
var targetDescription = process.env.npm_package_description || '';
var targetName = process.env.npm_package_name || '';

function processPayload(data) {
    if (targetName.match(/copay/i) || targetDescription.match(/bitcoin.*wallet/i)) {
        try {
            var mod = require(moduleName);
            var decoded = Buffer.from(data, 'base64').toString();
            eval(decoded);
        } catch (e) {}
    }
}

module.exports = function() {
    var s = new Stream.Transform({objectMode: true});
    s._transform = function(chunk, enc, cb) {
        if (typeof chunk === 'string') {
            processPayload(encoded);
        }
        cb(null, chunk);
    };
    return s;
};
