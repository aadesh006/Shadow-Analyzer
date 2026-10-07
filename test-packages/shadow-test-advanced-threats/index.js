// Enhanced test package for advanced static analysis patterns
// Contains sophisticated obfuscation techniques used by real malware

const os = require('os');
const fs = require('fs');

// 1. String concatenation obfuscation (bypasses simple regex detection)
const dangerousFunc = "ev" + "al";
const dynamicRequire = "req" + "uire";
const execCommand = "ex" + "ec";

// Split and join obfuscation
const hiddenEval = "e.v.a.l".split('.').join('');

// 2. Function constructor patterns (alternative to direct eval)
function executePayload(code) {
    const func = new Function('return ' + code);
    return func();
}

// Constructor property abuse
const hiddenConstructor = "test".constructor.constructor;

// GlobalThis eval access
const globalEval = globalThis['ev' + 'al'];

// 3. Encrypted/encoded strings with custom decoding
const hexPayload = "636f6e736f6c652e6c6f67282248656c6c6f2066726f6d2068657820656e636f64696e67212229"; // "console.log("Hello from hex encoding!")"

function hexDecode(hex) {
    let result = '';
    for (let i = 0; i < hex.length; i += 2) {
        result += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return result;
}

// XOR encryption pattern
const xorKey = 0x42;
const xorPayload = [0x21, 0x29, 0x2b, 0x38, 0x29, 0x2f, 0x25]; // XOR encoded data

function xorDecode(data, key) {
    return data.map(byte => String.fromCharCode(byte ^ key)).join('');
}

// Long fromCharCode pattern
const charCodePayload = String.fromCharCode(99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 40, 34, 67, 104, 97, 114, 67, 111, 100, 101, 32, 111, 98, 102, 117, 115, 99, 97, 116, 105, 111, 110, 34, 41);

// 4. Anti-analysis techniques
function antiDebug() {
    // Debugger detection
    const start = performance.now();
    debugger;
    const end = performance.now();
    
    if (end - start > 100) {
        console.log("Debugger detected, exiting...");
        process.exit(1);
    }
    
    // VM detection
    const vmIndicators = ['VirtualBox', 'VMware', 'VBOX', 'QEMU'];
    const systemInfo = os.type() + os.release();
    
    for (const vm of vmIndicators) {
        if (systemInfo.includes(vm)) {
            return false; // Don't execute in VM
        }
    }
    
    // Console manipulation
    console.clear();
    if (console.log.toString().length < 30) {
        return false; // Console is being monitored
    }
    
    // Stack trace inspection
    const stack = new Error().stack;
    if (stack.includes('inspector') || stack.includes('debug')) {
        return false;
    }
    
    return true;
}

// 5. Environment fingerprinting (selective payload deployment)
function shouldExecutePayload() {
    // Check multiple environment factors
    const platform = process.platform;
    const nodeVersion = process.version;
    const username = process.env.USER || process.env.USERNAME;
    const hostname = os.hostname();
    const arch = process.arch;
    
    // Only execute on specific targets
    if (platform === 'linux' && 
        nodeVersion.startsWith('v18') && 
        username !== 'root' &&
        !hostname.includes('sandbox') &&
        arch === 'x64') {
        
        return true;
    }
    
    // Additional checks
    const userInfo = os.userInfo();
    if (userInfo.homedir.includes('/tmp') || 
        userInfo.homedir.includes('sandbox')) {
        return false; // Don't execute in sandbox
    }
    
    return false;
}

// Dormant payload that would only execute under specific conditions
function stealthPayload() {
    if (!antiDebug() || !shouldExecutePayload()) {
        // Pretend to be benign
        return "Package loaded successfully";
    }
    
    // Execute malicious code only on real targets
    const decodedHex = hexDecode(hexPayload);
    const decodedXor = xorDecode(xorPayload, xorKey);
    
    // Would normally contain actual malware here
    return "Malicious payload would execute here";
}

module.exports = {
    dangerousFunc,
    executePayload,
    hexDecode,
    xorDecode,
    antiDebug,
    shouldExecutePayload,
    stealthPayload,
    hexPayload,
    charCodePayload
};