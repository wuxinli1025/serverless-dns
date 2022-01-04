function removeEmptyValues(obj) {
    return Object.fromEntries(Object.entries(obj).filter(([, value])=>{
        if (value === null) return false;
        if (value === undefined) return false;
        if (value === "") return false;
        return true;
    }));
}
function difference(arrA, arrB) {
    return arrA.filter((a)=>arrB.indexOf(a) < 0
    );
}
function parse(rawDotenv) {
    const env = {
    };
    for (const line of rawDotenv.split("\n")){
        if (!isVariableStart(line)) continue;
        const key = line.slice(0, line.indexOf("=")).trim();
        let value = line.slice(line.indexOf("=") + 1).trim();
        if (hasSingleQuotes(value)) {
            value = value.slice(1, -1);
        } else if (hasDoubleQuotes(value)) {
            value = value.slice(1, -1);
            value = expandNewlines(value);
        } else value = value.trim();
        env[key] = value;
    }
    return env;
}
function config(options = {
}) {
    const o = Object.assign({
        path: `.env`,
        export: false,
        safe: false,
        example: `.env.example`,
        allowEmptyValues: false,
        defaults: `.env.defaults`
    }, options);
    const conf = parseFile(o.path);
    if (o.defaults) {
        const confDefaults = parseFile(o.defaults);
        for(const key in confDefaults){
            if (!(key in conf)) {
                conf[key] = confDefaults[key];
            }
        }
    }
    if (o.safe) {
        const confExample = parseFile(o.example);
        assertSafe(conf, confExample, o.allowEmptyValues);
    }
    if (o.export) {
        for(const key in conf){
            if (Deno.env.get(key) !== undefined) continue;
            Deno.env.set(key, conf[key]);
        }
    }
    return conf;
}
function parseFile(filepath) {
    try {
        return parse(new TextDecoder("utf-8").decode(Deno.readFileSync(filepath)));
    } catch (e) {
        if (e instanceof Deno.errors.NotFound) return {
        };
        throw e;
    }
}
function isVariableStart(str) {
    return /^\s*[a-zA-Z_][a-zA-Z_0-9 ]*\s*=/.test(str);
}
function hasSingleQuotes(str) {
    return /^'([\s\S]*)'$/.test(str);
}
function hasDoubleQuotes(str) {
    return /^"([\s\S]*)"$/.test(str);
}
function expandNewlines(str) {
    return str.replaceAll("\\n", "\n");
}
function assertSafe(conf, confExample, allowEmptyValues) {
    const currentEnv = Deno.env.toObject();
    const confWithEnv = Object.assign({
    }, currentEnv, conf);
    const missing = difference(Object.keys(confExample), Object.keys(allowEmptyValues ? confWithEnv : removeEmptyValues(confWithEnv)));
    if (missing.length > 0) {
        const errorMessages = [
            `The following variables were defined in the example file but are not present in the environment:\n  ${missing.join(", ")}`,
            `Make sure to add them to your env file.`,
            !allowEmptyValues && `If you expect any of these variables to be empty, you can set the allowEmptyValues option to true.`, 
        ];
        throw new MissingEnvVarsError(errorMessages.filter(Boolean).join("\n\n"));
    }
}
class MissingEnvVarsError extends Error {
    constructor(message){
        super(message);
        this.name = "MissingEnvVarsError";
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
const hexTable = new TextEncoder().encode("0123456789abcdef");
function errInvalidByte(__byte) {
    return new TypeError(`Invalid byte '${String.fromCharCode(__byte)}'`);
}
function errLength() {
    return new RangeError("Odd length hex string");
}
function fromHexChar(__byte) {
    if (48 <= __byte && __byte <= 57) return __byte - 48;
    if (97 <= __byte && __byte <= 102) return __byte - 97 + 10;
    if (65 <= __byte && __byte <= 70) return __byte - 65 + 10;
    throw errInvalidByte(__byte);
}
function encode(src) {
    const dst = new Uint8Array(src.length * 2);
    for(let i1 = 0; i1 < dst.length; i1++){
        const v = src[i1];
        dst[i1 * 2] = hexTable[v >> 4];
        dst[i1 * 2 + 1] = hexTable[v & 15];
    }
    return dst;
}
function decode(src) {
    const dst = new Uint8Array(src.length / 2);
    for(let i2 = 0; i2 < dst.length; i2++){
        const a = fromHexChar(src[i2 * 2]);
        const b = fromHexChar(src[i2 * 2 + 1]);
        dst[i2] = a << 4 | b;
    }
    if (src.length % 2 == 1) {
        fromHexChar(src[dst.length * 2]);
        throw errLength();
    }
    return dst;
}
const base64abc = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "+",
    "/"
];
function encode1(data) {
    const uint8 = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
    let result = "", i3;
    const l = uint8.length;
    for(i3 = 2; i3 < l; i3 += 3){
        result += base64abc[uint8[i3 - 2] >> 2];
        result += base64abc[(uint8[i3 - 2] & 3) << 4 | uint8[i3 - 1] >> 4];
        result += base64abc[(uint8[i3 - 1] & 15) << 2 | uint8[i3] >> 6];
        result += base64abc[uint8[i3] & 63];
    }
    if (i3 === l + 1) {
        result += base64abc[uint8[i3 - 2] >> 2];
        result += base64abc[(uint8[i3 - 2] & 3) << 4];
        result += "==";
    }
    if (i3 === l) {
        result += base64abc[uint8[i3 - 2] >> 2];
        result += base64abc[(uint8[i3 - 2] & 3) << 4 | uint8[i3 - 1] >> 4];
        result += base64abc[(uint8[i3 - 1] & 15) << 2];
        result += "=";
    }
    return result;
}
function decode1(b64) {
    const binString = atob(b64);
    const size = binString.length;
    const bytes = new Uint8Array(size);
    for(let i4 = 0; i4 < size; i4++){
        bytes[i4] = binString.charCodeAt(i4);
    }
    return bytes;
}
const { Deno: Deno1  } = globalThis;
typeof Deno1?.noColor === "boolean" ? Deno1.noColor : true;
new RegExp([
    "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
    "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))", 
].join("|"), "g");
var DiffType;
(function(DiffType1) {
    DiffType1["removed"] = "removed";
    DiffType1["common"] = "common";
    DiffType1["added"] = "added";
})(DiffType || (DiffType = {
}));
class AssertionError extends Error {
    name = "AssertionError";
    constructor(message){
        super(message);
    }
}
function unreachable() {
    throw new AssertionError("unreachable");
}
function notImplemented(msg) {
    const message = msg ? `Not implemented: ${msg}` : "Not implemented";
    throw new Error(message);
}
function normalizeEncoding(enc) {
    if (enc == null || enc === "utf8" || enc === "utf-8") return "utf8";
    return slowCases(enc);
}
function slowCases(enc) {
    switch(enc.length){
        case 4:
            if (enc === "UTF8") return "utf8";
            if (enc === "ucs2" || enc === "UCS2") return "utf16le";
            enc = `${enc}`.toLowerCase();
            if (enc === "utf8") return "utf8";
            if (enc === "ucs2") return "utf16le";
            break;
        case 3:
            if (enc === "hex" || enc === "HEX" || `${enc}`.toLowerCase() === "hex") {
                return "hex";
            }
            break;
        case 5:
            if (enc === "ascii") return "ascii";
            if (enc === "ucs-2") return "utf16le";
            if (enc === "UTF-8") return "utf8";
            if (enc === "ASCII") return "ascii";
            if (enc === "UCS-2") return "utf16le";
            enc = `${enc}`.toLowerCase();
            if (enc === "utf-8") return "utf8";
            if (enc === "ascii") return "ascii";
            if (enc === "ucs-2") return "utf16le";
            break;
        case 6:
            if (enc === "base64") return "base64";
            if (enc === "latin1" || enc === "binary") return "latin1";
            if (enc === "BASE64") return "base64";
            if (enc === "LATIN1" || enc === "BINARY") return "latin1";
            enc = `${enc}`.toLowerCase();
            if (enc === "base64") return "base64";
            if (enc === "latin1" || enc === "binary") return "latin1";
            break;
        case 7:
            if (enc === "utf16le" || enc === "UTF16LE" || `${enc}`.toLowerCase() === "utf16le") {
                return "utf16le";
            }
            break;
        case 8:
            if (enc === "utf-16le" || enc === "UTF-16LE" || `${enc}`.toLowerCase() === "utf-16le") {
                return "utf16le";
            }
            break;
        default:
            if (enc === "") return "utf8";
    }
}
const kCustomPromisifiedSymbol = Symbol.for("nodejs.util.promisify.custom");
const kCustomPromisifyArgsSymbol = Symbol.for("nodejs.util.promisify.customArgs");
class NodeInvalidArgTypeError extends TypeError {
    code = "ERR_INVALID_ARG_TYPE";
    constructor(argumentName, type, received){
        super(`The "${argumentName}" argument must be of type ${type}. Received ${typeof received}`);
    }
}
function promisify(original) {
    if (typeof original !== "function") {
        throw new NodeInvalidArgTypeError("original", "Function", original);
    }
    if (original[kCustomPromisifiedSymbol]) {
        const fn = original[kCustomPromisifiedSymbol];
        if (typeof fn !== "function") {
            throw new NodeInvalidArgTypeError("util.promisify.custom", "Function", fn);
        }
        return Object.defineProperty(fn, kCustomPromisifiedSymbol, {
            value: fn,
            enumerable: false,
            writable: false,
            configurable: true
        });
    }
    const argumentNames = original[kCustomPromisifyArgsSymbol];
    function fn(...args) {
        return new Promise((resolve, reject)=>{
            original.call(this, ...args, (err, ...values)=>{
                if (err) {
                    return reject(err);
                }
                if (argumentNames !== undefined && values.length > 1) {
                    const obj = {
                    };
                    for(let i5 = 0; i5 < argumentNames.length; i5++){
                        obj[argumentNames[i5]] = values[i5];
                    }
                    resolve(obj);
                } else {
                    resolve(values[0]);
                }
            });
        });
    }
    Object.setPrototypeOf(fn, Object.getPrototypeOf(original));
    Object.defineProperty(fn, kCustomPromisifiedSymbol, {
        value: fn,
        enumerable: false,
        writable: false,
        configurable: true
    });
    return Object.defineProperties(fn, Object.getOwnPropertyDescriptors(original));
}
promisify.custom = kCustomPromisifiedSymbol;
Object.prototype.toString;
const osType = (()=>{
    const { Deno  } = globalThis;
    if (typeof Deno?.build?.os === "string") {
        return Deno.build.os;
    }
    const { navigator  } = globalThis;
    if (navigator?.appVersion?.includes?.("Win") ?? false) {
        return "windows";
    }
    return "linux";
})();
class NodeErrorAbstraction extends Error {
    code;
    constructor(name, code, message){
        super(message);
        this.code = code;
        this.name = name;
        this.stack = this.stack && `${name} [${this.code}]${this.stack.slice(20)}`;
    }
    toString() {
        return `${this.name} [${this.code}]: ${this.message}`;
    }
}
class NodeRangeError extends NodeErrorAbstraction {
    constructor(code, message){
        super(RangeError.prototype.name, code, message);
        Object.setPrototypeOf(this, RangeError.prototype);
    }
}
Number.isSafeInteger;
const DEFAULT_INSPECT_OPTIONS = {
    showHidden: false,
    depth: 2,
    colors: false,
    customInspect: true,
    showProxy: false,
    maxArrayLength: 100,
    maxStringLength: Infinity,
    breakLength: 80,
    compact: 3,
    sorted: false,
    getters: false
};
inspect.defaultOptions = DEFAULT_INSPECT_OPTIONS;
inspect.custom = Symbol.for("nodejs.util.inspect.custom");
function inspect(object, ...opts) {
    if (typeof object === "string" && !object.includes("'")) {
        return `'${object}'`;
    }
    opts = {
        ...DEFAULT_INSPECT_OPTIONS,
        ...opts
    };
    return Deno.inspect(object, {
        depth: opts.depth,
        iterableLimit: opts.maxArrayLength,
        compact: !!opts.compact,
        sorted: !!opts.sorted,
        showProxy: !!opts.showProxy
    });
}
class ERR_OUT_OF_RANGE extends RangeError {
    code = "ERR_OUT_OF_RANGE";
    constructor(str, range, received){
        super(`The value of "${str}" is out of range. It must be ${range}. Received ${received}`);
        const { name  } = this;
        this.name = `${name} [${this.code}]`;
        this.stack;
        this.name = name;
    }
}
class ERR_BUFFER_OUT_OF_BOUNDS extends NodeRangeError {
    constructor(name){
        super("ERR_BUFFER_OUT_OF_BOUNDS", name ? `"${name}" is outside of buffer bounds` : "Attempt to access memory outside buffer bounds");
    }
}
const windows = [
    [
        -4093,
        [
            "E2BIG",
            "argument list too long"
        ]
    ],
    [
        -4092,
        [
            "EACCES",
            "permission denied"
        ]
    ],
    [
        -4091,
        [
            "EADDRINUSE",
            "address already in use"
        ]
    ],
    [
        -4090,
        [
            "EADDRNOTAVAIL",
            "address not available"
        ]
    ],
    [
        -4089,
        [
            "EAFNOSUPPORT",
            "address family not supported"
        ]
    ],
    [
        -4088,
        [
            "EAGAIN",
            "resource temporarily unavailable"
        ]
    ],
    [
        -3000,
        [
            "EAI_ADDRFAMILY",
            "address family not supported"
        ]
    ],
    [
        -3001,
        [
            "EAI_AGAIN",
            "temporary failure"
        ]
    ],
    [
        -3002,
        [
            "EAI_BADFLAGS",
            "bad ai_flags value"
        ]
    ],
    [
        -3013,
        [
            "EAI_BADHINTS",
            "invalid value for hints"
        ]
    ],
    [
        -3003,
        [
            "EAI_CANCELED",
            "request canceled"
        ]
    ],
    [
        -3004,
        [
            "EAI_FAIL",
            "permanent failure"
        ]
    ],
    [
        -3005,
        [
            "EAI_FAMILY",
            "ai_family not supported"
        ]
    ],
    [
        -3006,
        [
            "EAI_MEMORY",
            "out of memory"
        ]
    ],
    [
        -3007,
        [
            "EAI_NODATA",
            "no address"
        ]
    ],
    [
        -3008,
        [
            "EAI_NONAME",
            "unknown node or service"
        ]
    ],
    [
        -3009,
        [
            "EAI_OVERFLOW",
            "argument buffer overflow"
        ]
    ],
    [
        -3014,
        [
            "EAI_PROTOCOL",
            "resolved protocol is unknown"
        ]
    ],
    [
        -3010,
        [
            "EAI_SERVICE",
            "service not available for socket type"
        ]
    ],
    [
        -3011,
        [
            "EAI_SOCKTYPE",
            "socket type not supported"
        ]
    ],
    [
        -4084,
        [
            "EALREADY",
            "connection already in progress"
        ]
    ],
    [
        -4083,
        [
            "EBADF",
            "bad file descriptor"
        ]
    ],
    [
        -4082,
        [
            "EBUSY",
            "resource busy or locked"
        ]
    ],
    [
        -4081,
        [
            "ECANCELED",
            "operation canceled"
        ]
    ],
    [
        -4080,
        [
            "ECHARSET",
            "invalid Unicode character"
        ]
    ],
    [
        -4079,
        [
            "ECONNABORTED",
            "software caused connection abort"
        ]
    ],
    [
        -4078,
        [
            "ECONNREFUSED",
            "connection refused"
        ]
    ],
    [
        -4077,
        [
            "ECONNRESET",
            "connection reset by peer"
        ]
    ],
    [
        -4076,
        [
            "EDESTADDRREQ",
            "destination address required"
        ]
    ],
    [
        -4075,
        [
            "EEXIST",
            "file already exists"
        ]
    ],
    [
        -4074,
        [
            "EFAULT",
            "bad address in system call argument"
        ]
    ],
    [
        -4036,
        [
            "EFBIG",
            "file too large"
        ]
    ],
    [
        -4073,
        [
            "EHOSTUNREACH",
            "host is unreachable"
        ]
    ],
    [
        -4072,
        [
            "EINTR",
            "interrupted system call"
        ]
    ],
    [
        -4071,
        [
            "EINVAL",
            "invalid argument"
        ]
    ],
    [
        -4070,
        [
            "EIO",
            "i/o error"
        ]
    ],
    [
        -4069,
        [
            "EISCONN",
            "socket is already connected"
        ]
    ],
    [
        -4068,
        [
            "EISDIR",
            "illegal operation on a directory"
        ]
    ],
    [
        -4067,
        [
            "ELOOP",
            "too many symbolic links encountered"
        ]
    ],
    [
        -4066,
        [
            "EMFILE",
            "too many open files"
        ]
    ],
    [
        -4065,
        [
            "EMSGSIZE",
            "message too long"
        ]
    ],
    [
        -4064,
        [
            "ENAMETOOLONG",
            "name too long"
        ]
    ],
    [
        -4063,
        [
            "ENETDOWN",
            "network is down"
        ]
    ],
    [
        -4062,
        [
            "ENETUNREACH",
            "network is unreachable"
        ]
    ],
    [
        -4061,
        [
            "ENFILE",
            "file table overflow"
        ]
    ],
    [
        -4060,
        [
            "ENOBUFS",
            "no buffer space available"
        ]
    ],
    [
        -4059,
        [
            "ENODEV",
            "no such device"
        ]
    ],
    [
        -4058,
        [
            "ENOENT",
            "no such file or directory"
        ]
    ],
    [
        -4057,
        [
            "ENOMEM",
            "not enough memory"
        ]
    ],
    [
        -4056,
        [
            "ENONET",
            "machine is not on the network"
        ]
    ],
    [
        -4035,
        [
            "ENOPROTOOPT",
            "protocol not available"
        ]
    ],
    [
        -4055,
        [
            "ENOSPC",
            "no space left on device"
        ]
    ],
    [
        -4054,
        [
            "ENOSYS",
            "function not implemented"
        ]
    ],
    [
        -4053,
        [
            "ENOTCONN",
            "socket is not connected"
        ]
    ],
    [
        -4052,
        [
            "ENOTDIR",
            "not a directory"
        ]
    ],
    [
        -4051,
        [
            "ENOTEMPTY",
            "directory not empty"
        ]
    ],
    [
        -4050,
        [
            "ENOTSOCK",
            "socket operation on non-socket"
        ]
    ],
    [
        -4049,
        [
            "ENOTSUP",
            "operation not supported on socket"
        ]
    ],
    [
        -4048,
        [
            "EPERM",
            "operation not permitted"
        ]
    ],
    [
        -4047,
        [
            "EPIPE",
            "broken pipe"
        ]
    ],
    [
        -4046,
        [
            "EPROTO",
            "protocol error"
        ]
    ],
    [
        -4045,
        [
            "EPROTONOSUPPORT",
            "protocol not supported"
        ]
    ],
    [
        -4044,
        [
            "EPROTOTYPE",
            "protocol wrong type for socket"
        ]
    ],
    [
        -4034,
        [
            "ERANGE",
            "result too large"
        ]
    ],
    [
        -4043,
        [
            "EROFS",
            "read-only file system"
        ]
    ],
    [
        -4042,
        [
            "ESHUTDOWN",
            "cannot send after transport endpoint shutdown"
        ]
    ],
    [
        -4041,
        [
            "ESPIPE",
            "invalid seek"
        ]
    ],
    [
        -4040,
        [
            "ESRCH",
            "no such process"
        ]
    ],
    [
        -4039,
        [
            "ETIMEDOUT",
            "connection timed out"
        ]
    ],
    [
        -4038,
        [
            "ETXTBSY",
            "text file is busy"
        ]
    ],
    [
        -4037,
        [
            "EXDEV",
            "cross-device link not permitted"
        ]
    ],
    [
        -4094,
        [
            "UNKNOWN",
            "unknown error"
        ]
    ],
    [
        -4095,
        [
            "EOF",
            "end of file"
        ]
    ],
    [
        -4033,
        [
            "ENXIO",
            "no such device or address"
        ]
    ],
    [
        -4032,
        [
            "EMLINK",
            "too many links"
        ]
    ],
    [
        -4031,
        [
            "EHOSTDOWN",
            "host is down"
        ]
    ],
    [
        -4030,
        [
            "EREMOTEIO",
            "remote I/O error"
        ]
    ],
    [
        -4029,
        [
            "ENOTTY",
            "inappropriate ioctl for device"
        ]
    ],
    [
        -4028,
        [
            "EFTYPE",
            "inappropriate file type or format"
        ]
    ],
    [
        -4027,
        [
            "EILSEQ",
            "illegal byte sequence"
        ]
    ], 
];
const darwin = [
    [
        -7,
        [
            "E2BIG",
            "argument list too long"
        ]
    ],
    [
        -13,
        [
            "EACCES",
            "permission denied"
        ]
    ],
    [
        -48,
        [
            "EADDRINUSE",
            "address already in use"
        ]
    ],
    [
        -49,
        [
            "EADDRNOTAVAIL",
            "address not available"
        ]
    ],
    [
        -47,
        [
            "EAFNOSUPPORT",
            "address family not supported"
        ]
    ],
    [
        -35,
        [
            "EAGAIN",
            "resource temporarily unavailable"
        ]
    ],
    [
        -3000,
        [
            "EAI_ADDRFAMILY",
            "address family not supported"
        ]
    ],
    [
        -3001,
        [
            "EAI_AGAIN",
            "temporary failure"
        ]
    ],
    [
        -3002,
        [
            "EAI_BADFLAGS",
            "bad ai_flags value"
        ]
    ],
    [
        -3013,
        [
            "EAI_BADHINTS",
            "invalid value for hints"
        ]
    ],
    [
        -3003,
        [
            "EAI_CANCELED",
            "request canceled"
        ]
    ],
    [
        -3004,
        [
            "EAI_FAIL",
            "permanent failure"
        ]
    ],
    [
        -3005,
        [
            "EAI_FAMILY",
            "ai_family not supported"
        ]
    ],
    [
        -3006,
        [
            "EAI_MEMORY",
            "out of memory"
        ]
    ],
    [
        -3007,
        [
            "EAI_NODATA",
            "no address"
        ]
    ],
    [
        -3008,
        [
            "EAI_NONAME",
            "unknown node or service"
        ]
    ],
    [
        -3009,
        [
            "EAI_OVERFLOW",
            "argument buffer overflow"
        ]
    ],
    [
        -3014,
        [
            "EAI_PROTOCOL",
            "resolved protocol is unknown"
        ]
    ],
    [
        -3010,
        [
            "EAI_SERVICE",
            "service not available for socket type"
        ]
    ],
    [
        -3011,
        [
            "EAI_SOCKTYPE",
            "socket type not supported"
        ]
    ],
    [
        -37,
        [
            "EALREADY",
            "connection already in progress"
        ]
    ],
    [
        -9,
        [
            "EBADF",
            "bad file descriptor"
        ]
    ],
    [
        -16,
        [
            "EBUSY",
            "resource busy or locked"
        ]
    ],
    [
        -89,
        [
            "ECANCELED",
            "operation canceled"
        ]
    ],
    [
        -4080,
        [
            "ECHARSET",
            "invalid Unicode character"
        ]
    ],
    [
        -53,
        [
            "ECONNABORTED",
            "software caused connection abort"
        ]
    ],
    [
        -61,
        [
            "ECONNREFUSED",
            "connection refused"
        ]
    ],
    [
        -54,
        [
            "ECONNRESET",
            "connection reset by peer"
        ]
    ],
    [
        -39,
        [
            "EDESTADDRREQ",
            "destination address required"
        ]
    ],
    [
        -17,
        [
            "EEXIST",
            "file already exists"
        ]
    ],
    [
        -14,
        [
            "EFAULT",
            "bad address in system call argument"
        ]
    ],
    [
        -27,
        [
            "EFBIG",
            "file too large"
        ]
    ],
    [
        -65,
        [
            "EHOSTUNREACH",
            "host is unreachable"
        ]
    ],
    [
        -4,
        [
            "EINTR",
            "interrupted system call"
        ]
    ],
    [
        -22,
        [
            "EINVAL",
            "invalid argument"
        ]
    ],
    [
        -5,
        [
            "EIO",
            "i/o error"
        ]
    ],
    [
        -56,
        [
            "EISCONN",
            "socket is already connected"
        ]
    ],
    [
        -21,
        [
            "EISDIR",
            "illegal operation on a directory"
        ]
    ],
    [
        -62,
        [
            "ELOOP",
            "too many symbolic links encountered"
        ]
    ],
    [
        -24,
        [
            "EMFILE",
            "too many open files"
        ]
    ],
    [
        -40,
        [
            "EMSGSIZE",
            "message too long"
        ]
    ],
    [
        -63,
        [
            "ENAMETOOLONG",
            "name too long"
        ]
    ],
    [
        -50,
        [
            "ENETDOWN",
            "network is down"
        ]
    ],
    [
        -51,
        [
            "ENETUNREACH",
            "network is unreachable"
        ]
    ],
    [
        -23,
        [
            "ENFILE",
            "file table overflow"
        ]
    ],
    [
        -55,
        [
            "ENOBUFS",
            "no buffer space available"
        ]
    ],
    [
        -19,
        [
            "ENODEV",
            "no such device"
        ]
    ],
    [
        -2,
        [
            "ENOENT",
            "no such file or directory"
        ]
    ],
    [
        -12,
        [
            "ENOMEM",
            "not enough memory"
        ]
    ],
    [
        -4056,
        [
            "ENONET",
            "machine is not on the network"
        ]
    ],
    [
        -42,
        [
            "ENOPROTOOPT",
            "protocol not available"
        ]
    ],
    [
        -28,
        [
            "ENOSPC",
            "no space left on device"
        ]
    ],
    [
        -78,
        [
            "ENOSYS",
            "function not implemented"
        ]
    ],
    [
        -57,
        [
            "ENOTCONN",
            "socket is not connected"
        ]
    ],
    [
        -20,
        [
            "ENOTDIR",
            "not a directory"
        ]
    ],
    [
        -66,
        [
            "ENOTEMPTY",
            "directory not empty"
        ]
    ],
    [
        -38,
        [
            "ENOTSOCK",
            "socket operation on non-socket"
        ]
    ],
    [
        -45,
        [
            "ENOTSUP",
            "operation not supported on socket"
        ]
    ],
    [
        -1,
        [
            "EPERM",
            "operation not permitted"
        ]
    ],
    [
        -32,
        [
            "EPIPE",
            "broken pipe"
        ]
    ],
    [
        -100,
        [
            "EPROTO",
            "protocol error"
        ]
    ],
    [
        -43,
        [
            "EPROTONOSUPPORT",
            "protocol not supported"
        ]
    ],
    [
        -41,
        [
            "EPROTOTYPE",
            "protocol wrong type for socket"
        ]
    ],
    [
        -34,
        [
            "ERANGE",
            "result too large"
        ]
    ],
    [
        -30,
        [
            "EROFS",
            "read-only file system"
        ]
    ],
    [
        -58,
        [
            "ESHUTDOWN",
            "cannot send after transport endpoint shutdown"
        ]
    ],
    [
        -29,
        [
            "ESPIPE",
            "invalid seek"
        ]
    ],
    [
        -3,
        [
            "ESRCH",
            "no such process"
        ]
    ],
    [
        -60,
        [
            "ETIMEDOUT",
            "connection timed out"
        ]
    ],
    [
        -26,
        [
            "ETXTBSY",
            "text file is busy"
        ]
    ],
    [
        -18,
        [
            "EXDEV",
            "cross-device link not permitted"
        ]
    ],
    [
        -4094,
        [
            "UNKNOWN",
            "unknown error"
        ]
    ],
    [
        -4095,
        [
            "EOF",
            "end of file"
        ]
    ],
    [
        -6,
        [
            "ENXIO",
            "no such device or address"
        ]
    ],
    [
        -31,
        [
            "EMLINK",
            "too many links"
        ]
    ],
    [
        -64,
        [
            "EHOSTDOWN",
            "host is down"
        ]
    ],
    [
        -4030,
        [
            "EREMOTEIO",
            "remote I/O error"
        ]
    ],
    [
        -25,
        [
            "ENOTTY",
            "inappropriate ioctl for device"
        ]
    ],
    [
        -79,
        [
            "EFTYPE",
            "inappropriate file type or format"
        ]
    ],
    [
        -92,
        [
            "EILSEQ",
            "illegal byte sequence"
        ]
    ], 
];
const linux = [
    [
        -7,
        [
            "E2BIG",
            "argument list too long"
        ]
    ],
    [
        -13,
        [
            "EACCES",
            "permission denied"
        ]
    ],
    [
        -98,
        [
            "EADDRINUSE",
            "address already in use"
        ]
    ],
    [
        -99,
        [
            "EADDRNOTAVAIL",
            "address not available"
        ]
    ],
    [
        -97,
        [
            "EAFNOSUPPORT",
            "address family not supported"
        ]
    ],
    [
        -11,
        [
            "EAGAIN",
            "resource temporarily unavailable"
        ]
    ],
    [
        -3000,
        [
            "EAI_ADDRFAMILY",
            "address family not supported"
        ]
    ],
    [
        -3001,
        [
            "EAI_AGAIN",
            "temporary failure"
        ]
    ],
    [
        -3002,
        [
            "EAI_BADFLAGS",
            "bad ai_flags value"
        ]
    ],
    [
        -3013,
        [
            "EAI_BADHINTS",
            "invalid value for hints"
        ]
    ],
    [
        -3003,
        [
            "EAI_CANCELED",
            "request canceled"
        ]
    ],
    [
        -3004,
        [
            "EAI_FAIL",
            "permanent failure"
        ]
    ],
    [
        -3005,
        [
            "EAI_FAMILY",
            "ai_family not supported"
        ]
    ],
    [
        -3006,
        [
            "EAI_MEMORY",
            "out of memory"
        ]
    ],
    [
        -3007,
        [
            "EAI_NODATA",
            "no address"
        ]
    ],
    [
        -3008,
        [
            "EAI_NONAME",
            "unknown node or service"
        ]
    ],
    [
        -3009,
        [
            "EAI_OVERFLOW",
            "argument buffer overflow"
        ]
    ],
    [
        -3014,
        [
            "EAI_PROTOCOL",
            "resolved protocol is unknown"
        ]
    ],
    [
        -3010,
        [
            "EAI_SERVICE",
            "service not available for socket type"
        ]
    ],
    [
        -3011,
        [
            "EAI_SOCKTYPE",
            "socket type not supported"
        ]
    ],
    [
        -114,
        [
            "EALREADY",
            "connection already in progress"
        ]
    ],
    [
        -9,
        [
            "EBADF",
            "bad file descriptor"
        ]
    ],
    [
        -16,
        [
            "EBUSY",
            "resource busy or locked"
        ]
    ],
    [
        -125,
        [
            "ECANCELED",
            "operation canceled"
        ]
    ],
    [
        -4080,
        [
            "ECHARSET",
            "invalid Unicode character"
        ]
    ],
    [
        -103,
        [
            "ECONNABORTED",
            "software caused connection abort"
        ]
    ],
    [
        -111,
        [
            "ECONNREFUSED",
            "connection refused"
        ]
    ],
    [
        -104,
        [
            "ECONNRESET",
            "connection reset by peer"
        ]
    ],
    [
        -89,
        [
            "EDESTADDRREQ",
            "destination address required"
        ]
    ],
    [
        -17,
        [
            "EEXIST",
            "file already exists"
        ]
    ],
    [
        -14,
        [
            "EFAULT",
            "bad address in system call argument"
        ]
    ],
    [
        -27,
        [
            "EFBIG",
            "file too large"
        ]
    ],
    [
        -113,
        [
            "EHOSTUNREACH",
            "host is unreachable"
        ]
    ],
    [
        -4,
        [
            "EINTR",
            "interrupted system call"
        ]
    ],
    [
        -22,
        [
            "EINVAL",
            "invalid argument"
        ]
    ],
    [
        -5,
        [
            "EIO",
            "i/o error"
        ]
    ],
    [
        -106,
        [
            "EISCONN",
            "socket is already connected"
        ]
    ],
    [
        -21,
        [
            "EISDIR",
            "illegal operation on a directory"
        ]
    ],
    [
        -40,
        [
            "ELOOP",
            "too many symbolic links encountered"
        ]
    ],
    [
        -24,
        [
            "EMFILE",
            "too many open files"
        ]
    ],
    [
        -90,
        [
            "EMSGSIZE",
            "message too long"
        ]
    ],
    [
        -36,
        [
            "ENAMETOOLONG",
            "name too long"
        ]
    ],
    [
        -100,
        [
            "ENETDOWN",
            "network is down"
        ]
    ],
    [
        -101,
        [
            "ENETUNREACH",
            "network is unreachable"
        ]
    ],
    [
        -23,
        [
            "ENFILE",
            "file table overflow"
        ]
    ],
    [
        -105,
        [
            "ENOBUFS",
            "no buffer space available"
        ]
    ],
    [
        -19,
        [
            "ENODEV",
            "no such device"
        ]
    ],
    [
        -2,
        [
            "ENOENT",
            "no such file or directory"
        ]
    ],
    [
        -12,
        [
            "ENOMEM",
            "not enough memory"
        ]
    ],
    [
        -64,
        [
            "ENONET",
            "machine is not on the network"
        ]
    ],
    [
        -92,
        [
            "ENOPROTOOPT",
            "protocol not available"
        ]
    ],
    [
        -28,
        [
            "ENOSPC",
            "no space left on device"
        ]
    ],
    [
        -38,
        [
            "ENOSYS",
            "function not implemented"
        ]
    ],
    [
        -107,
        [
            "ENOTCONN",
            "socket is not connected"
        ]
    ],
    [
        -20,
        [
            "ENOTDIR",
            "not a directory"
        ]
    ],
    [
        -39,
        [
            "ENOTEMPTY",
            "directory not empty"
        ]
    ],
    [
        -88,
        [
            "ENOTSOCK",
            "socket operation on non-socket"
        ]
    ],
    [
        -95,
        [
            "ENOTSUP",
            "operation not supported on socket"
        ]
    ],
    [
        -1,
        [
            "EPERM",
            "operation not permitted"
        ]
    ],
    [
        -32,
        [
            "EPIPE",
            "broken pipe"
        ]
    ],
    [
        -71,
        [
            "EPROTO",
            "protocol error"
        ]
    ],
    [
        -93,
        [
            "EPROTONOSUPPORT",
            "protocol not supported"
        ]
    ],
    [
        -91,
        [
            "EPROTOTYPE",
            "protocol wrong type for socket"
        ]
    ],
    [
        -34,
        [
            "ERANGE",
            "result too large"
        ]
    ],
    [
        -30,
        [
            "EROFS",
            "read-only file system"
        ]
    ],
    [
        -108,
        [
            "ESHUTDOWN",
            "cannot send after transport endpoint shutdown"
        ]
    ],
    [
        -29,
        [
            "ESPIPE",
            "invalid seek"
        ]
    ],
    [
        -3,
        [
            "ESRCH",
            "no such process"
        ]
    ],
    [
        -110,
        [
            "ETIMEDOUT",
            "connection timed out"
        ]
    ],
    [
        -26,
        [
            "ETXTBSY",
            "text file is busy"
        ]
    ],
    [
        -18,
        [
            "EXDEV",
            "cross-device link not permitted"
        ]
    ],
    [
        -4094,
        [
            "UNKNOWN",
            "unknown error"
        ]
    ],
    [
        -4095,
        [
            "EOF",
            "end of file"
        ]
    ],
    [
        -6,
        [
            "ENXIO",
            "no such device or address"
        ]
    ],
    [
        -31,
        [
            "EMLINK",
            "too many links"
        ]
    ],
    [
        -112,
        [
            "EHOSTDOWN",
            "host is down"
        ]
    ],
    [
        -121,
        [
            "EREMOTEIO",
            "remote I/O error"
        ]
    ],
    [
        -25,
        [
            "ENOTTY",
            "inappropriate ioctl for device"
        ]
    ],
    [
        -4028,
        [
            "EFTYPE",
            "inappropriate file type or format"
        ]
    ],
    [
        -84,
        [
            "EILSEQ",
            "illegal byte sequence"
        ]
    ], 
];
new Map(osType === "windows" ? windows : osType === "darwin" ? darwin : osType === "linux" ? linux : unreachable());
const notImplementedEncodings = [
    "ascii",
    "binary",
    "latin1",
    "ucs2",
    "utf16le", 
];
function checkEncoding(encoding = "utf8", strict = true) {
    if (typeof encoding !== "string" || strict && encoding === "") {
        if (!strict) return "utf8";
        throw new TypeError(`Unknown encoding: ${encoding}`);
    }
    const normalized = normalizeEncoding(encoding);
    if (normalized === undefined) {
        throw new TypeError(`Unknown encoding: ${encoding}`);
    }
    if (notImplementedEncodings.includes(encoding)) {
        notImplemented(`"${encoding}" encoding`);
    }
    return normalized;
}
const encodingOps = {
    utf8: {
        byteLength: (string1)=>new TextEncoder().encode(string1).byteLength
    },
    ucs2: {
        byteLength: (string2)=>string2.length * 2
    },
    utf16le: {
        byteLength: (string3)=>string3.length * 2
    },
    latin1: {
        byteLength: (string4)=>string4.length
    },
    ascii: {
        byteLength: (string5)=>string5.length
    },
    base64: {
        byteLength: (string6)=>base64ByteLength(string6, string6.length)
    },
    hex: {
        byteLength: (string7)=>string7.length >>> 1
    }
};
function base64ByteLength(str, bytes) {
    if (str.charCodeAt(bytes - 1) === 61) bytes--;
    if (bytes > 1 && str.charCodeAt(bytes - 1) === 61) bytes--;
    return bytes * 3 >>> 2;
}
class Buffer1 extends Uint8Array {
    static alloc(size, fill, encoding = "utf8") {
        if (typeof size !== "number") {
            throw new TypeError(`The "size" argument must be of type number. Received type ${typeof size}`);
        }
        const buf = new Buffer1(size);
        if (size === 0) return buf;
        let bufFill;
        if (typeof fill === "string") {
            const clearEncoding = checkEncoding(encoding);
            if (typeof fill === "string" && fill.length === 1 && clearEncoding === "utf8") {
                buf.fill(fill.charCodeAt(0));
            } else bufFill = Buffer1.from(fill, clearEncoding);
        } else if (typeof fill === "number") {
            buf.fill(fill);
        } else if (fill instanceof Uint8Array) {
            if (fill.length === 0) {
                throw new TypeError(`The argument "value" is invalid. Received ${fill.constructor.name} []`);
            }
            bufFill = fill;
        }
        if (bufFill) {
            if (bufFill.length > buf.length) {
                bufFill = bufFill.subarray(0, buf.length);
            }
            let offset = 0;
            while(offset < size){
                buf.set(bufFill, offset);
                offset += bufFill.length;
                if (offset + bufFill.length >= size) break;
            }
            if (offset !== size) {
                buf.set(bufFill.subarray(0, size - offset), offset);
            }
        }
        return buf;
    }
    static allocUnsafe(size) {
        return new Buffer1(size);
    }
    static byteLength(string8, encoding = "utf8") {
        if (typeof string8 != "string") return string8.byteLength;
        encoding = normalizeEncoding(encoding) || "utf8";
        return encodingOps[encoding].byteLength(string8);
    }
    static concat(list, totalLength) {
        if (totalLength == undefined) {
            totalLength = 0;
            for (const buf of list){
                totalLength += buf.length;
            }
        }
        const buffer = Buffer1.allocUnsafe(totalLength);
        let pos = 0;
        for (const item of list){
            let buf;
            if (!(item instanceof Buffer1)) {
                buf = Buffer1.from(item);
            } else {
                buf = item;
            }
            buf.copy(buffer, pos);
            pos += buf.length;
        }
        return buffer;
    }
    static from(value, offsetOrEncoding, length) {
        const offset = typeof offsetOrEncoding === "string" ? undefined : offsetOrEncoding;
        let encoding = typeof offsetOrEncoding === "string" ? offsetOrEncoding : undefined;
        if (typeof value == "string") {
            encoding = checkEncoding(encoding, false);
            if (encoding === "hex") {
                return new Buffer1(decode(new TextEncoder().encode(value)).buffer);
            }
            if (encoding === "base64") return new Buffer1(decode1(value).buffer);
            return new Buffer1(new TextEncoder().encode(value).buffer);
        }
        return new Buffer1(value, offset, length);
    }
    static isBuffer(obj) {
        return obj instanceof Buffer1;
    }
    static isEncoding(encoding) {
        return typeof encoding === "string" && encoding.length !== 0 && normalizeEncoding(encoding) !== undefined;
    }
    boundsError(value, length, type) {
        if (Math.floor(value) !== value) {
            throw new ERR_OUT_OF_RANGE(type || "offset", "an integer", value);
        }
        if (length < 0) throw new ERR_BUFFER_OUT_OF_BOUNDS();
        throw new ERR_OUT_OF_RANGE(type || "offset", `>= ${type ? 1 : 0} and <= ${length}`, value);
    }
    readUIntBE(offset = 0, byteLength) {
        if (byteLength === 3 || byteLength === 5 || byteLength === 6) {
            notImplemented(`byteLength ${byteLength}`);
        }
        if (byteLength === 4) return this.readUInt32BE(offset);
        if (byteLength === 2) return this.readUInt16BE(offset);
        if (byteLength === 1) return this.readUInt8(offset);
        this.boundsError(byteLength, 4, "byteLength");
    }
    readUIntLE(offset = 0, byteLength) {
        if (byteLength === 3 || byteLength === 5 || byteLength === 6) {
            notImplemented(`byteLength ${byteLength}`);
        }
        if (byteLength === 4) return this.readUInt32LE(offset);
        if (byteLength === 2) return this.readUInt16LE(offset);
        if (byteLength === 1) return this.readUInt8(offset);
        this.boundsError(byteLength, 4, "byteLength");
    }
    copy(targetBuffer, targetStart = 0, sourceStart = 0, sourceEnd = this.length) {
        const sourceBuffer = this.subarray(sourceStart, sourceEnd).subarray(0, Math.max(0, targetBuffer.length - targetStart));
        if (sourceBuffer.length === 0) return 0;
        targetBuffer.set(sourceBuffer, targetStart);
        return sourceBuffer.length;
    }
    equals(otherBuffer) {
        if (!(otherBuffer instanceof Uint8Array)) {
            throw new TypeError(`The "otherBuffer" argument must be an instance of Buffer or Uint8Array. Received type ${typeof otherBuffer}`);
        }
        if (this === otherBuffer) return true;
        if (this.byteLength !== otherBuffer.byteLength) return false;
        for(let i6 = 0; i6 < this.length; i6++){
            if (this[i6] !== otherBuffer[i6]) return false;
        }
        return true;
    }
    readBigInt64BE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigInt64(offset);
    }
    readBigInt64LE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigInt64(offset, true);
    }
    readBigUInt64BE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigUint64(offset);
    }
    readBigUInt64LE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigUint64(offset, true);
    }
    readDoubleBE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset);
    }
    readDoubleLE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat64(offset, true);
    }
    readFloatBE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset);
    }
    readFloatLE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getFloat32(offset, true);
    }
    readInt8(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getInt8(offset);
    }
    readInt16BE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getInt16(offset);
    }
    readInt16LE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getInt16(offset, true);
    }
    readInt32BE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getInt32(offset);
    }
    readInt32LE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getInt32(offset, true);
    }
    readUInt8(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getUint8(offset);
    }
    readUInt16BE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getUint16(offset);
    }
    readUInt16LE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getUint16(offset, true);
    }
    readUInt32BE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getUint32(offset);
    }
    readUInt32LE(offset = 0) {
        return new DataView(this.buffer, this.byteOffset, this.byteLength).getUint32(offset, true);
    }
    slice(begin = 0, end = this.length) {
        return this.subarray(begin, end);
    }
    toJSON() {
        return {
            type: "Buffer",
            data: Array.from(this)
        };
    }
    toString(encoding = "utf8", start = 0, end = this.length) {
        encoding = checkEncoding(encoding);
        const b = this.subarray(start, end);
        if (encoding === "hex") return new TextDecoder().decode(encode(b));
        if (encoding === "base64") return encode1(b);
        return new TextDecoder(encoding).decode(b);
    }
    write(string9, offset = 0, length = this.length) {
        return new TextEncoder().encodeInto(string9, this.subarray(offset, offset + length)).written;
    }
    writeBigInt64BE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setBigInt64(offset, value);
        return offset + 4;
    }
    writeBigInt64LE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setBigInt64(offset, value, true);
        return offset + 4;
    }
    writeBigUInt64BE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setBigUint64(offset, value);
        return offset + 4;
    }
    writeBigUInt64LE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setBigUint64(offset, value, true);
        return offset + 4;
    }
    writeDoubleBE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value);
        return offset + 8;
    }
    writeDoubleLE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat64(offset, value, true);
        return offset + 8;
    }
    writeFloatBE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value);
        return offset + 4;
    }
    writeFloatLE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setFloat32(offset, value, true);
        return offset + 4;
    }
    writeInt8(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setInt8(offset, value);
        return offset + 1;
    }
    writeInt16BE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setInt16(offset, value);
        return offset + 2;
    }
    writeInt16LE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setInt16(offset, value, true);
        return offset + 2;
    }
    writeInt32BE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setUint32(offset, value);
        return offset + 4;
    }
    writeInt32LE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setInt32(offset, value, true);
        return offset + 4;
    }
    writeUInt8(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setUint8(offset, value);
        return offset + 1;
    }
    writeUInt16BE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setUint16(offset, value);
        return offset + 2;
    }
    writeUInt16LE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setUint16(offset, value, true);
        return offset + 2;
    }
    writeUInt32BE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setUint32(offset, value);
        return offset + 4;
    }
    writeUInt32LE(value, offset = 0) {
        new DataView(this.buffer, this.byteOffset, this.byteLength).setUint32(offset, value, true);
        return offset + 4;
    }
}
globalThis.atob;
globalThis.btoa;
function fromBrowser(ua) {
    return ua && ua.startsWith("Mozilla/5.0");
}
function jsonHeaders() {
    return {
        "Content-Type": "application/json"
    };
}
function dnsHeaders() {
    return {
        "Accept": "application/dns-message",
        "Content-Type": "application/dns-message"
    };
}
function corsHeaders() {
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    };
}
function browserHeaders() {
    return Object.assign(jsonHeaders(), corsHeaders());
}
function contentLengthHeader(b) {
    const len = !b || !b.byteLength ? "0" : b.byteLength.toString();
    return {
        "Content-Length": len
    };
}
function concatHeaders(...args) {
    return concatObj(...args);
}
function rxidFromHeader(h) {
    if (!h || !h.get) return null;
    return h.get("x-rethinkdns-rxid");
}
function copyHeaders(request) {
    const headers = {
    };
    if (!request || !request.headers) return headers;
    request.headers.forEach((val, name)=>{
        headers[name] = val;
    });
    return headers;
}
function objOf(map) {
    return map.entries ? Object.fromEntries(map) : {
    };
}
function arrayBufferOf(buf) {
    if (!buf) return null;
    const offset = buf.byteOffset;
    const len = buf.byteLength;
    return buf.buffer.slice(offset, offset + len);
}
function bufferOf(arrayBuf) {
    if (!arrayBuf) return null;
    return Buffer1.from(new Uint8Array(arrayBuf));
}
function timeout(ms, callback) {
    if (typeof callback !== "function") return -1;
    return setTimeout(callback, ms);
}
function uid() {
    return (Math.random() + 1).toString(36).slice(1);
}
function xid() {
    const hi = uid().slice(1);
    const lo = uid();
    return hi + lo;
}
function microtaskBox(...fns) {
    let enqueue = null;
    if (typeof queueMicroTask === "function") {
        enqueue = queueMicroTask;
    } else {
        const p = Promise.resolve();
        enqueue = p.then.bind(p);
    }
    for (const f of fns){
        enqueue(()=>safeBox(f)
        );
    }
}
function safeBox(fn, defaultResponse = null) {
    if (typeof fn !== "function") return defaultResponse;
    try {
        return fn();
    } catch (ignore) {
    }
    return defaultResponse;
}
function isDnsMsg(req) {
    return req.headers.get("Accept") === "application/dns-message" || req.headers.get("Content-Type") === "application/dns-message";
}
function emptyResponse() {
    return {
        isException: false,
        exceptionStack: "",
        exceptionFrom: "",
        data: false
    };
}
function errResponse(id, err) {
    return {
        isException: true,
        exceptionStack: err.stack,
        exceptionFrom: id,
        data: false
    };
}
function mapOf(obj) {
    return new Map(Object.entries(obj));
}
function emptyString(str) {
    if (!str) return true;
    if (typeof str !== "string") return false;
    return str.trim().length === 0;
}
function emptyArray(a) {
    if (!a) return true;
    if (typeof a !== "object") return false;
    return a.length && a.length <= 0;
}
function concatObj(...args) {
    return Object.assign(...args);
}
function emptyObj(x) {
    return !x || Object.keys(x).length <= 0;
}
function respond204() {
    return new Response(null, {
        status: 204,
        headers: corsHeaders()
    });
}
function respond503() {
    return new Response(null, {
        status: 503,
        headers: dnsHeaders()
    });
}
const stickyEvents = new Set([
    "ready",
    "go", 
]);
const events = new Set();
const listeners = new Map();
(()=>{
    for (const e of events){
        listeners.set(e, new Set());
    }
    for (const se of stickyEvents){
        listeners.set(se, new Set());
    }
})();
function pub(event) {
    const eventCallbacks = listeners.get(event);
    if (!eventCallbacks) return;
    if (stickyEvents.has(event)) {
        listeners.delete(event);
    }
    microtaskBox(...eventCallbacks);
}
function sub(event, cb) {
    const callbacks = listeners.get(event);
    if (!callbacks) {
        if (stickyEvents.has(event)) {
            microtaskBox(cb);
            return true;
        }
        return false;
    }
    callbacks.add(cb);
    return true;
}
const _LOG_LEVELS = new Map([
    "error",
    "warn",
    "info",
    "timer",
    "debug"
].reverse().map((l, i7)=>[
        l,
        i7
    ]
));
function _setConsoleLevel(level) {
    switch(level){
        case "error":
            globalThis.console.warn = ()=>null
            ;
        case "warn":
            globalThis.console.info = ()=>null
            ;
        case "info":
            globalThis.console.time = ()=>null
            ;
            globalThis.console.timeEnd = ()=>null
            ;
            globalThis.console.timeLog = ()=>null
            ;
        case "timer":
            globalThis.console.debug = ()=>null
            ;
        case "debug":
            break;
        default:
            console.error("Unknown console level: ", level);
            level = null;
    }
    if (level) {
        console.log("Console level set: ", level);
        globalThis.console.level = level;
    }
    return level;
}
class Log {
    constructor(level, isConsoleLevel){
        if (!_LOG_LEVELS.has(level)) level = "debug";
        if (isConsoleLevel && !console.level) _setConsoleLevel(level);
        this.l = console.log;
        this.log = console.log;
        this.setLevel(level);
    }
    _resetLevel() {
        this.d = ()=>null
        ;
        this.debug = ()=>null
        ;
        this.lapTime = ()=>null
        ;
        this.startTime = ()=>null
        ;
        this.endTime = ()=>null
        ;
        this.i = ()=>null
        ;
        this.info = ()=>null
        ;
        this.w = ()=>null
        ;
        this.warn = ()=>null
        ;
        this.e = ()=>null
        ;
        this.error = ()=>null
        ;
    }
    withTags(...tags) {
        const that = this;
        return {
            lapTime: (n, ...r)=>{
                return that.lapTime(n, ...tags, ...r);
            },
            startTime: (n, ...r)=>{
                const tid = that.startTime(n);
                that.d(that.now(), ...tags, "create timer", tid, ...r);
                return tid;
            },
            endTime: (n, ...r)=>{
                that.d(that.now(), ...tags, "end timer", n, ...r);
                return that.endTime(n);
            },
            d: (...args)=>{
                that.d(that.now(), ...tags, ...args);
            },
            i: (...args)=>{
                that.i(that.now(), ...tags, ...args);
            },
            w: (...args)=>{
                that.w(that.now(), ...tags, ...args);
            },
            e: (...args)=>{
                that.e(that.now(), ...tags, ...args);
            },
            tag: (t)=>{
                tags.push(t);
            }
        };
    }
    now() {
        return new Date().toISOString();
    }
    setLevel(level) {
        if (!_LOG_LEVELS.has(level)) throw new Error(`Unknown log level: ${level}`);
        if (console.level && _LOG_LEVELS.get(level) < _LOG_LEVELS.get(console.level)) {
            throw new Error("Cannot set " + `(log.level='${level}') < (console.level = '${console.level}')`);
        }
        this._resetLevel();
        switch(level){
            default:
            case "debug":
                this.d = console.debug;
                this.debug = console.debug;
            case "timer":
                this.lapTime = console.timeLog;
                this.startTime = function(name) {
                    name += uid();
                    console.time(name);
                    return name;
                };
                this.endTime = console.timeEnd;
            case "info":
                this.i = console.info;
                this.info = console.info;
            case "warn":
                this.w = console.warn;
                this.warn = console.warn;
            case "error":
                this.e = console.error;
                this.error = console.error;
        }
        this.level = level;
    }
}
const _ENV_VAR_MAPPINGS = {
    runTime: {
        name: "RUNTIME",
        type: "string"
    },
    runTimeEnv: {
        name: {
            worker: "WORKER_ENV",
            node: "NODE_ENV",
            deno: "DENO_ENV"
        },
        type: "string"
    },
    cloudPlatform: {
        name: "CLOUD_PLATFORM",
        type: "string"
    },
    logLevel: {
        name: "LOG_LEVEL",
        type: "string"
    },
    blocklistUrl: {
        name: "CF_BLOCKLIST_URL",
        type: "string"
    },
    latestTimestamp: {
        name: "CF_LATEST_BLOCKLIST_TIMESTAMP",
        type: "string"
    },
    dnsResolverUrl: {
        name: "CF_DNS_RESOLVER_URL",
        type: "string"
    },
    onInvalidFlagStopProcessing: {
        name: "CF_ON_INVALID_FLAG_STOPPROCESSING",
        type: "boolean"
    },
    workerTimeout: {
        name: "WORKER_TIMEOUT",
        type: "number"
    },
    fetchTimeout: {
        name: "CF_BLOCKLIST_DOWNLOAD_TIMEOUT",
        type: "number"
    },
    tdNodecount: {
        name: "TD_NODE_COUNT",
        type: "number"
    },
    tdParts: {
        name: "TD_PARTS",
        type: "number"
    },
    isAggCacheReq: {
        name: {
            worker: "IS_AGGRESSIVE_CACHE_REQ"
        },
        type: "boolean"
    }
};
function _getRuntimeEnv(runtime) {
    console.info("Loading env. from runtime:", runtime);
    const env = {
    };
    for (const [key, mappedKey] of Object.entries(_ENV_VAR_MAPPINGS)){
        let name = null;
        let type = null;
        if (typeof mappedKey !== "object") continue;
        if (typeof mappedKey.name === "object") {
            name = mappedKey.name[runtime];
        } else {
            name = mappedKey.name;
        }
        type = mappedKey.type;
        if (!name || !type) {
            console.debug(runtime, "unnamed / untyped env mapping", key, mappedKey);
            continue;
        }
        if (runtime === "node") env[key] = process.env[name];
        else if (runtime === "deno") env[key] = Deno.env.get(name);
        else if (runtime === "worker") env[key] = globalThis[name];
        else throw new Error(`unsupported runtime: ${runtime}`);
        if (type === "boolean") env[key] = !!env[key];
        else if (type === "number") env[key] = Number(env[key]);
        else if (type === "string") env[key] = env[key] || "";
        else throw new Error(`unsupported type: ${type}`);
        console.debug("Added", key, mappedKey, env[key]);
    }
    return env;
}
function _determineRuntimeIfPossible() {
    if (typeof Deno !== "undefined") {
        return Deno.env.get("RUNTIME") || "deno";
    }
    if (typeof process !== "undefined") {
        if (globalThis.RUNTIME) return globalThis.RUNTIME;
        if (process.env) return process.env.RUNTIME || "node";
    }
    return null;
}
class EnvManager {
    constructor(){
        this.runtime = _determineRuntimeIfPossible();
        this.envMap = new Map();
        this.load();
    }
    load() {
        const renv = _getRuntimeEnv(this.runtime);
        globalThis.env = renv;
        for (const [k, v] of Object.entries(renv)){
            this.envMap.set(k, v);
        }
        console.debug("Env loaded: ", JSON.stringify(renv));
    }
    getMap() {
        return this.envMap;
    }
    toObject() {
        return Object.fromEntries(this.envMap);
    }
    get(key) {
        const v = this.envMap.get(key);
        if (v) return v;
        if (this.runtime === "node") {
            return process.env[key];
        } else if (this.runtime === "deno") {
            return Deno.env.get(key);
        } else if (this.runtime === "worker") {
            return globalThis[key];
        }
        return null;
    }
    set(key, value) {
        this.envMap.set(key, value);
        globalThis.env[key] = value;
    }
}
((main)=>{
    if (!Deno) throw new Error("failed loading deno-specific config");
    const isProd = Deno.env.get("DENO_ENV") === "production";
    try {
        config({
            export: true
        });
        Deno.env.set("RUNTIME", "deno");
    } catch (e) {
        console.warn(".env file may not be loaded => ", e.name, ":", e.message);
    }
    window.envManager = new EnvManager();
    window.log = new Log(window.env.logLevel, isProd);
    pub("ready");
})();
function isWorkers() {
    return env && env.runTime === "worker";
}
function isNode() {
    return env && env.runTime === "node";
}
function workersTimeout(defaultValue = 0) {
    return env && env.workerTimeout || defaultValue;
}
function isBlocklistFilterSetup(blf) {
    return blf && blf.t && blf.ft;
}
function doBlock(blf, userBlInfo, dn, cf) {
    const blocklistMap = getBlocklistStampForDomains(dn, blf, cf);
    if (!blocklistMap) return false;
    const dnUint = blocklistMap.get(dn);
    if (!dnUint) return false;
    const r = checkFlagIntersection(userBlInfo.userBlocklistFlagUint, dnUint, userBlInfo.flagVersion);
    if (r && r.isBlocked) return r;
    if (!userBlInfo.userServiceListUint) return r;
    return checkWildcardBlocking(userBlInfo.userServiceListUint, userBlInfo.flagVersion, blocklistMap, dn);
}
function getBlocklistStampForDomains(domain, blf, cf) {
    if (emptyString(domain)) return false;
    if (cf && cf.hasOwnProperty(domain)) {
        return mapOf(cf[domain]);
    }
    if (blf && isBlocklistFilterSetup(blf)) {
        return blf.getDomainInfo(domain).searchResult;
    }
    return false;
}
function checkWildcardBlocking(uint1, flagVersion, blocklistMap, dn) {
    const dnSplit = dn.split(".");
    while(dnSplit.shift() !== undefined){
        const subdomain = dnSplit.join(".");
        const subdomainUint = blocklistMap.get(subdomain);
        if (!subdomainUint) continue;
        const response = checkFlagIntersection(uint1, subdomainUint, flagVersion);
        if (response && response.isBlocked) {
            return response;
        }
    }
    return false;
}
function checkFlagIntersection(uint1, uint2, flagVersion) {
    const response = {
        isBlocked: false,
        blockedB64Flag: ""
    };
    const blockedUint = flagIntersection(uint1, uint2);
    if (blockedUint) {
        response.isBlocked = true;
        response.blockedB64Flag = getB64Flag(blockedUint, flagVersion);
    } else {
        response.isBlocked = false;
        response.blockedB64Flag = getB64Flag(uint2, flagVersion);
    }
    return response;
}
function flagIntersection(flag1, flag2) {
    if (emptyString(flag1) || emptyString(flag2)) return false;
    let flag1Header = flag1[0];
    let flag2Header = flag2[0];
    let intersectHeader = flag1Header & flag2Header;
    if (intersectHeader === 0) {
        return false;
    }
    let flag1Length = flag1.length - 1;
    let flag2Length = flag2.length - 1;
    const intersectBody = [];
    let tmpIntersectHeader = intersectHeader;
    let maskHeaderForBodyEmpty = 1;
    for(; tmpIntersectHeader !== 0;){
        if ((tmpIntersectHeader & 1) === 1) {
            const tmpBodyIntersect = flag1[flag1Length] & flag2[flag2Length];
            if (tmpBodyIntersect === 0) {
                intersectHeader = intersectHeader ^ maskHeaderForBodyEmpty;
            } else {
                intersectBody.push(tmpBodyIntersect);
            }
        }
        if ((flag1Header & 1) === 1) {
            flag1Length = flag1Length - 1;
        }
        if ((flag2Header & 1) === 1) {
            flag2Length = flag2Length - 1;
        }
        flag1Header = flag1Header >>> 1;
        flag2Header = flag2Header >>> 1;
        tmpIntersectHeader = tmpIntersectHeader >>> 1;
        maskHeaderForBodyEmpty = maskHeaderForBodyEmpty << 1;
    }
    if (intersectHeader === 0) {
        return false;
    }
    const out = new Uint16Array(1 + intersectBody.length);
    out.set([
        intersectHeader
    ], 0);
    out.set(intersectBody, 1);
    return out;
}
function getB64Flag(uint16Arr, flagVersion) {
    if (emptyArray(uint16Arr)) return "";
    if (flagVersion === "0") {
        return encodeURIComponent(Buffer.from(uint16Arr).toString("base64"));
    } else if (flagVersion === "1") {
        const flag = encodeURI(btoa(encodeUint16arrToBinary(uint16Arr)).replace(/\//g, "_").replace(/\+/g, "-"));
        return flagVersion + ":" + flag;
    }
}
function encodeUint16arrToBinary(uint16Arr) {
    return String.fromCharCode(...new Uint8Array(uint16Arr.buffer));
}
"use strict";
function toString(type) {
    switch(type){
        case 1:
            return "A";
        case 10:
            return "NULL";
        case 28:
            return "AAAA";
        case 18:
            return "AFSDB";
        case 42:
            return "APL";
        case 257:
            return "CAA";
        case 60:
            return "CDNSKEY";
        case 59:
            return "CDS";
        case 37:
            return "CERT";
        case 5:
            return "CNAME";
        case 49:
            return "DHCID";
        case 32769:
            return "DLV";
        case 39:
            return "DNAME";
        case 48:
            return "DNSKEY";
        case 43:
            return "DS";
        case 55:
            return "HIP";
        case 13:
            return "HINFO";
        case 45:
            return "IPSECKEY";
        case 25:
            return "KEY";
        case 36:
            return "KX";
        case 29:
            return "LOC";
        case 15:
            return "MX";
        case 35:
            return "NAPTR";
        case 2:
            return "NS";
        case 47:
            return "NSEC";
        case 50:
            return "NSEC3";
        case 51:
            return "NSEC3PARAM";
        case 12:
            return "PTR";
        case 46:
            return "RRSIG";
        case 17:
            return "RP";
        case 24:
            return "SIG";
        case 6:
            return "SOA";
        case 99:
            return "SPF";
        case 33:
            return "SRV";
        case 44:
            return "SSHFP";
        case 32768:
            return "TA";
        case 249:
            return "TKEY";
        case 52:
            return "TLSA";
        case 250:
            return "TSIG";
        case 16:
            return "TXT";
        case 252:
            return "AXFR";
        case 251:
            return "IXFR";
        case 41:
            return "OPT";
        case 255:
            return "ANY";
        case 64:
            return "SVCB";
        case 65:
            return "HTTPS";
    }
    return "UNKNOWN_" + type;
}
function toType(name) {
    switch(name.toUpperCase()){
        case "A":
            return 1;
        case "NULL":
            return 10;
        case "AAAA":
            return 28;
        case "AFSDB":
            return 18;
        case "APL":
            return 42;
        case "CAA":
            return 257;
        case "CDNSKEY":
            return 60;
        case "CDS":
            return 59;
        case "CERT":
            return 37;
        case "CNAME":
            return 5;
        case "DHCID":
            return 49;
        case "DLV":
            return 32769;
        case "DNAME":
            return 39;
        case "DNSKEY":
            return 48;
        case "DS":
            return 43;
        case "HIP":
            return 55;
        case "HINFO":
            return 13;
        case "IPSECKEY":
            return 45;
        case "KEY":
            return 25;
        case "KX":
            return 36;
        case "LOC":
            return 29;
        case "MX":
            return 15;
        case "NAPTR":
            return 35;
        case "NS":
            return 2;
        case "NSEC":
            return 47;
        case "NSEC3":
            return 50;
        case "NSEC3PARAM":
            return 51;
        case "PTR":
            return 12;
        case "RRSIG":
            return 46;
        case "RP":
            return 17;
        case "SIG":
            return 24;
        case "SOA":
            return 6;
        case "SPF":
            return 99;
        case "SRV":
            return 33;
        case "SSHFP":
            return 44;
        case "TA":
            return 32768;
        case "TKEY":
            return 249;
        case "TLSA":
            return 52;
        case "TSIG":
            return 250;
        case "TXT":
            return 16;
        case "AXFR":
            return 252;
        case "IXFR":
            return 251;
        case "OPT":
            return 41;
        case "ANY":
            return 255;
        case "*":
            return 255;
        case "SVCB":
            return 64;
        case "HTTPS":
            return 65;
    }
    if (name.toUpperCase().startsWith("UNKNOWN_")) return parseInt(name.slice(8));
    return 0;
}
"use strict";
function toString1(rcode) {
    switch(rcode){
        case 0:
            return "NOERROR";
        case 1:
            return "FORMERR";
        case 2:
            return "SERVFAIL";
        case 3:
            return "NXDOMAIN";
        case 4:
            return "NOTIMP";
        case 5:
            return "REFUSED";
        case 6:
            return "YXDOMAIN";
        case 7:
            return "YXRRSET";
        case 8:
            return "NXRRSET";
        case 9:
            return "NOTAUTH";
        case 10:
            return "NOTZONE";
        case 11:
            return "RCODE_11";
        case 12:
            return "RCODE_12";
        case 13:
            return "RCODE_13";
        case 14:
            return "RCODE_14";
        case 15:
            return "RCODE_15";
    }
    return "RCODE_" + rcode;
}
"use strict";
function toString2(opcode) {
    switch(opcode){
        case 0:
            return "QUERY";
        case 1:
            return "IQUERY";
        case 2:
            return "STATUS";
        case 3:
            return "OPCODE_3";
        case 4:
            return "NOTIFY";
        case 5:
            return "UPDATE";
        case 6:
            return "OPCODE_6";
        case 7:
            return "OPCODE_7";
        case 8:
            return "OPCODE_8";
        case 9:
            return "OPCODE_9";
        case 10:
            return "OPCODE_10";
        case 11:
            return "OPCODE_11";
        case 12:
            return "OPCODE_12";
        case 13:
            return "OPCODE_13";
        case 14:
            return "OPCODE_14";
        case 15:
            return "OPCODE_15";
    }
    return "OPCODE_" + opcode;
}
"use strict";
function toString3(klass) {
    switch(klass){
        case 1:
            return "IN";
        case 2:
            return "CS";
        case 3:
            return "CH";
        case 4:
            return "HS";
        case 255:
            return "ANY";
    }
    return "UNKNOWN_" + klass;
}
function toClass(name) {
    switch(name.toUpperCase()){
        case "IN":
            return 1;
        case "CS":
            return 2;
        case "CH":
            return 3;
        case "HS":
            return 4;
        case "ANY":
            return 255;
    }
    return 0;
}
"use strict";
function toString4(type) {
    switch(type){
        case 1:
            return "LLQ";
        case 2:
            return "UL";
        case 3:
            return "NSID";
        case 5:
            return "DAU";
        case 6:
            return "DHU";
        case 7:
            return "N3U";
        case 8:
            return "CLIENT_SUBNET";
        case 9:
            return "EXPIRE";
        case 10:
            return "COOKIE";
        case 11:
            return "TCP_KEEPALIVE";
        case 12:
            return "PADDING";
        case 13:
            return "CHAIN";
        case 14:
            return "KEY_TAG";
        case 26946:
            return "DEVICEID";
    }
    if (type < 0) {
        return null;
    }
    return `OPTION_${type}`;
}
function toCode(name) {
    if (typeof name === "number") {
        return name;
    }
    if (!name) {
        return -1;
    }
    switch(name.toUpperCase()){
        case "OPTION_0":
            return 0;
        case "LLQ":
            return 1;
        case "UL":
            return 2;
        case "NSID":
            return 3;
        case "OPTION_4":
            return 4;
        case "DAU":
            return 5;
        case "DHU":
            return 6;
        case "N3U":
            return 7;
        case "CLIENT_SUBNET":
            return 8;
        case "EXPIRE":
            return 9;
        case "COOKIE":
            return 10;
        case "TCP_KEEPALIVE":
            return 11;
        case "PADDING":
            return 12;
        case "CHAIN":
            return 13;
        case "KEY_TAG":
            return 14;
        case "DEVICEID":
            return 26946;
        case "OPTION_65535":
            return 65535;
    }
    const m = name.match(/_(\d+)$/);
    if (m) {
        return parseInt(m[1], 10);
    }
    return -1;
}
"use strict";
function toString5(type) {
    switch(type){
        case 0:
            return "mandatory";
        case 1:
            return "alpn";
        case 2:
            return "no-default-alpn";
        case 3:
            return "port";
        case 4:
            return "ipv4hint";
        case 5:
            return "ech";
        case 6:
            return "ipv6hint";
    }
    return "key" + type;
}
function toKey(name) {
    switch(name.toLowerCase()){
        case "mandatory":
            return 0;
        case "alpn":
            return 1;
        case "no-default-alpn":
            return 2;
        case "port":
            return 3;
        case "ipv4hint":
            return 4;
        case "ech":
            return 5;
        case "ipv6hint":
            return 6;
    }
    if (name.toLowerCase().startsWith("key")) return parseInt(name.slice(3));
    throw "Invalid svcparam key";
}
"use strict";
const ip = {
};
ip.toBuffer = function(ip1, buff, offset) {
    offset = ~~offset;
    var result;
    if (this.isV4Format(ip1)) {
        result = buff || new Buffer1(offset + 4);
        ip1.split(/\./g).map(function(__byte) {
            result[offset++] = parseInt(__byte, 10) & 255;
        });
    } else if (this.isV6Format(ip1)) {
        var sections = ip1.split(":", 8);
        var i8;
        for(i8 = 0; i8 < sections.length; i8++){
            var isv4 = this.isV4Format(sections[i8]);
            var v4Buffer;
            if (isv4) {
                v4Buffer = this.toBuffer(sections[i8]);
                sections[i8] = v4Buffer.slice(0, 2).toString("hex");
            }
            if (v4Buffer && ++i8 < 8) {
                sections.splice(i8, 0, v4Buffer.slice(2, 4).toString("hex"));
            }
        }
        if (sections[0] === "") {
            while(sections.length < 8)sections.unshift("0");
        } else if (sections[sections.length - 1] === "") {
            while(sections.length < 8)sections.push("0");
        } else if (sections.length < 8) {
            for(i8 = 0; i8 < sections.length && sections[i8] !== ""; i8++);
            var argv = [
                i8,
                1
            ];
            for(i8 = 9 - sections.length; i8 > 0; i8--){
                argv.push("0");
            }
            sections.splice.apply(sections, argv);
        }
        result = buff || new Buffer1(offset + 16);
        for(i8 = 0; i8 < sections.length; i8++){
            var word = parseInt(sections[i8], 16);
            result[offset++] = word >> 8 & 255;
            result[offset++] = word & 255;
        }
    }
    if (!result) {
        throw Error("Invalid ip address: " + ip1);
    }
    return result;
};
ip.toString = function(buff, offset, length) {
    offset = ~~offset;
    length = length || buff.length - offset;
    var result = [];
    if (length === 4) {
        for(var i9 = 0; i9 < length; i9++){
            result.push(buff[offset + i9]);
        }
        result = result.join(".");
    } else if (length === 16) {
        for(var i9 = 0; i9 < length; i9 += 2){
            result.push(buff.readUInt16BE(offset + i9).toString(16));
        }
        result = result.join(":");
        result = result.replace(/(^|:)0(:0)*:0(:|$)/, "$1::$3");
        result = result.replace(/:{3,4}/, "::");
    }
    return result;
};
var ipv4Regex = /^(\d{1,3}\.){3,3}\d{1,3}$/;
var ipv6Regex = /^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;
ip.isV4Format = function(ip2) {
    return ipv4Regex.test(ip2);
};
ip.isV6Format = function(ip3) {
    return ipv6Regex.test(ip3);
};
function _normalizeFamily(family) {
    return family ? family.toLowerCase() : "ipv4";
}
ip.fromPrefixLen = function(prefixlen, family) {
    if (prefixlen > 32) {
        family = "ipv6";
    } else {
        family = _normalizeFamily(family);
    }
    var len = 4;
    if (family === "ipv6") {
        len = 16;
    }
    var buff = new Buffer1(len);
    for(var i10 = 0, n = buff.length; i10 < n; ++i10){
        var bits = 8;
        if (prefixlen < 8) {
            bits = prefixlen;
        }
        prefixlen -= bits;
        buff[i10] = ~(255 >> bits) & 255;
    }
    return ip.toString(buff);
};
ip.mask = function(addr, mask) {
    addr = ip.toBuffer(addr);
    mask = ip.toBuffer(mask);
    var result = new Buffer1(Math.max(addr.length, mask.length));
    var i11 = 0;
    if (addr.length === mask.length) {
        for(i11 = 0; i11 < addr.length; i11++){
            result[i11] = addr[i11] & mask[i11];
        }
    } else if (mask.length === 4) {
        for(i11 = 0; i11 < mask.length; i11++){
            result[i11] = addr[addr.length - 4 + i11] & mask[i11];
        }
    } else {
        for(var i11 = 0; i11 < result.length - 6; i11++){
            result[i11] = 0;
        }
        result[10] = 255;
        result[11] = 255;
        for(i11 = 0; i11 < addr.length; i11++){
            result[i11 + 12] = addr[i11] & mask[i11 + 12];
        }
        i11 = i11 + 12;
    }
    for(; i11 < result.length; i11++){
        result[i11] = 0;
    }
    return ip.toString(result);
};
ip.cidr = function(cidrString) {
    var cidrParts = cidrString.split("/");
    var addr = cidrParts[0];
    if (cidrParts.length !== 2) {
        throw new Error("invalid CIDR subnet: " + addr);
    }
    var mask = ip.fromPrefixLen(parseInt(cidrParts[1], 10));
    return ip.mask(addr, mask);
};
ip.subnet = function(addr, mask) {
    var networkAddress = ip.toLong(ip.mask(addr, mask));
    var maskBuffer = ip.toBuffer(mask);
    var maskLength = 0;
    for(var i12 = 0; i12 < maskBuffer.length; i12++){
        if (maskBuffer[i12] === 255) {
            maskLength += 8;
        } else {
            var octet = maskBuffer[i12] & 255;
            while(octet){
                octet = octet << 1 & 255;
                maskLength++;
            }
        }
    }
    var numberOfAddresses = Math.pow(2, 32 - maskLength);
    return {
        networkAddress: ip.fromLong(networkAddress),
        firstAddress: numberOfAddresses <= 2 ? ip.fromLong(networkAddress) : ip.fromLong(networkAddress + 1),
        lastAddress: numberOfAddresses <= 2 ? ip.fromLong(networkAddress + numberOfAddresses - 1) : ip.fromLong(networkAddress + numberOfAddresses - 2),
        broadcastAddress: ip.fromLong(networkAddress + numberOfAddresses - 1),
        subnetMask: mask,
        subnetMaskLength: maskLength,
        numHosts: numberOfAddresses <= 2 ? numberOfAddresses : numberOfAddresses - 2,
        length: numberOfAddresses,
        contains: function(other) {
            return networkAddress === ip.toLong(ip.mask(other, mask));
        }
    };
};
ip.cidrSubnet = function(cidrString) {
    var cidrParts = cidrString.split("/");
    var addr = cidrParts[0];
    if (cidrParts.length !== 2) {
        throw new Error("invalid CIDR subnet: " + addr);
    }
    var mask = ip.fromPrefixLen(parseInt(cidrParts[1], 10));
    return ip.subnet(addr, mask);
};
ip.not = function(addr) {
    var buff = ip.toBuffer(addr);
    for(var i13 = 0; i13 < buff.length; i13++){
        buff[i13] = 255 ^ buff[i13];
    }
    return ip.toString(buff);
};
ip.or = function(a, b) {
    a = ip.toBuffer(a);
    b = ip.toBuffer(b);
    if (a.length === b.length) {
        for(var i14 = 0; i14 < a.length; ++i14){
            a[i14] |= b[i14];
        }
        return ip.toString(a);
    } else {
        var buff = a;
        var other = b;
        if (b.length > a.length) {
            buff = b;
            other = a;
        }
        var offset = buff.length - other.length;
        for(var i14 = offset; i14 < buff.length; ++i14){
            buff[i14] |= other[i14 - offset];
        }
        return ip.toString(buff);
    }
};
ip.isEqual = function(a, b) {
    a = ip.toBuffer(a);
    b = ip.toBuffer(b);
    if (a.length === b.length) {
        for(var i15 = 0; i15 < a.length; i15++){
            if (a[i15] !== b[i15]) return false;
        }
        return true;
    }
    if (b.length === 4) {
        var t = b;
        b = a;
        a = t;
    }
    for(var i15 = 0; i15 < 10; i15++){
        if (b[i15] !== 0) return false;
    }
    var word = b.readUInt16BE(10);
    if (word !== 0 && word !== 65535) return false;
    for(var i15 = 0; i15 < 4; i15++){
        if (a[i15] !== b[i15 + 12]) return false;
    }
    return true;
};
ip.isPrivate = function(addr) {
    return /^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) || /^f[cd][0-9a-f]{2}:/i.test(addr) || /^fe80:/i.test(addr) || /^::1$/.test(addr) || /^::$/.test(addr);
};
ip.isPublic = function(addr) {
    return !ip.isPrivate(addr);
};
ip.isLoopback = function(addr) {
    return /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/.test(addr) || /^fe80::1$/.test(addr) || /^::1$/.test(addr) || /^::$/.test(addr);
};
ip.loopback = function(family) {
    family = _normalizeFamily(family);
    if (family !== "ipv4" && family !== "ipv6") {
        throw new Error("family must be ipv4 or ipv6");
    }
    return family === "ipv4" ? "127.0.0.1" : "fe80::1";
};
ip.toLong = function(ip4) {
    var ipl = 0;
    ip4.split(".").forEach(function(octet) {
        ipl <<= 8;
        ipl += parseInt(octet);
    });
    return ipl >>> 0;
};
ip.fromLong = function(ipl) {
    return (ipl >>> 24) + "." + (ipl >> 16 & 255) + "." + (ipl >> 8 & 255) + "." + (ipl & 255);
};
"use strict";
const QUERY_FLAG = 0;
const RESPONSE_FLAG = 1 << 15;
const FLUSH_MASK = 1 << 15;
const NOT_FLUSH_MASK = ~FLUSH_MASK;
const QU_MASK = 1 << 15;
const NOT_QU_MASK = ~QU_MASK;
const name1 = {
};
name1.encode = function(str, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(name1.encodingLength(str));
    if (!offset) offset = 0;
    const oldOffset = offset;
    const n = str.replace(/^\.|\.$/gm, "");
    if (n.length) {
        const list = n.split(".");
        for(let i16 = 0; i16 < list.length; i16++){
            const len = buf.write(list[i16], offset + 1);
            buf[offset] = len;
            offset += len + 1;
        }
    }
    buf[offset++] = 0;
    name1.encode.bytes = offset - oldOffset;
    return buf;
};
name1.encode.bytes = 0;
name1.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const list = [];
    const oldOffset = offset;
    let len = buf[offset++];
    if (len === 0) {
        name1.decode.bytes = 1;
        return ".";
    }
    if (len >= 192) {
        const res = name1.decode(buf, buf.readUInt16BE(offset - 1) - 49152);
        name1.decode.bytes = 2;
        return res;
    }
    while(len){
        if (len >= 192) {
            list.push(name1.decode(buf, buf.readUInt16BE(offset - 1) - 49152));
            offset++;
            break;
        }
        list.push(buf.toString("utf-8", offset, offset + len));
        offset += len;
        len = buf[offset++];
    }
    name1.decode.bytes = offset - oldOffset;
    return list.join(".");
};
name1.decode.bytes = 0;
name1.encodingLength = function(n) {
    if (n === ".") return 1;
    return Buffer1.byteLength(n) + 2;
};
const string = {
};
string.encode = function(s, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(string.encodingLength(s));
    if (!offset) offset = 0;
    const len = buf.write(s, offset + 1);
    buf[offset] = len;
    string.encode.bytes = len + 1;
    return buf;
};
string.encode.bytes = 0;
string.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const len = buf[offset];
    const s = buf.toString("utf-8", offset + 1, offset + 1 + len);
    string.decode.bytes = len + 1;
    return s;
};
string.decode.bytes = 0;
string.encodingLength = function(s) {
    return Buffer1.byteLength(s) + 1;
};
const header = {
};
header.encode = function(h, buf, offset) {
    if (!buf) buf = header.encodingLength(h);
    if (!offset) offset = 0;
    const flags = (h.flags || 0) & 32767;
    const type = h.type === "response" ? RESPONSE_FLAG : QUERY_FLAG;
    buf.writeUInt16BE(h.id || 0, offset);
    buf.writeUInt16BE(flags | type, offset + 2);
    buf.writeUInt16BE(h.questions.length, offset + 4);
    buf.writeUInt16BE(h.answers.length, offset + 6);
    buf.writeUInt16BE(h.authorities.length, offset + 8);
    buf.writeUInt16BE(h.additionals.length, offset + 10);
    return buf;
};
header.encode.bytes = 12;
header.decode = function(buf, offset) {
    if (!offset) offset = 0;
    if (buf.length < 12) throw new Error("Header must be 12 bytes");
    const flags = buf.readUInt16BE(offset + 2);
    return {
        id: buf.readUInt16BE(offset),
        type: flags & RESPONSE_FLAG ? "response" : "query",
        flags: flags & 32767,
        flag_qr: (flags >> 15 & 1) === 1,
        opcode: toString2(flags >> 11 & 15),
        flag_aa: (flags >> 10 & 1) === 1,
        flag_tc: (flags >> 9 & 1) === 1,
        flag_rd: (flags >> 8 & 1) === 1,
        flag_ra: (flags >> 7 & 1) === 1,
        flag_z: (flags >> 6 & 1) === 1,
        flag_ad: (flags >> 5 & 1) === 1,
        flag_cd: (flags >> 4 & 1) === 1,
        rcode: toString1(flags & 15),
        questions: new Array(buf.readUInt16BE(offset + 4)),
        answers: new Array(buf.readUInt16BE(offset + 6)),
        authorities: new Array(buf.readUInt16BE(offset + 8)),
        additionals: new Array(buf.readUInt16BE(offset + 10))
    };
};
header.decode.bytes = 12;
header.encodingLength = function() {
    return 12;
};
const runknown = {
};
runknown.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(runknown.encodingLength(data));
    if (!offset) offset = 0;
    buf.writeUInt16BE(data.length, offset);
    data.copy(buf, offset + 2);
    runknown.encode.bytes = data.length + 2;
    return buf;
};
runknown.encode.bytes = 0;
runknown.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const len = buf.readUInt16BE(offset);
    const data = buf.slice(offset + 2, offset + 2 + len);
    runknown.decode.bytes = len + 2;
    return data;
};
runknown.decode.bytes = 0;
runknown.encodingLength = function(data) {
    return data.length + 2;
};
const rns = {
};
rns.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rns.encodingLength(data));
    if (!offset) offset = 0;
    name1.encode(data, buf, offset + 2);
    buf.writeUInt16BE(name1.encode.bytes, offset);
    rns.encode.bytes = name1.encode.bytes + 2;
    return buf;
};
rns.encode.bytes = 0;
rns.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const len = buf.readUInt16BE(offset);
    const dd = name1.decode(buf, offset + 2);
    rns.decode.bytes = len + 2;
    return dd;
};
rns.decode.bytes = 0;
rns.encodingLength = function(data) {
    return name1.encodingLength(data) + 2;
};
const rsoa = {
};
rsoa.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rsoa.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    name1.encode(data.mname, buf, offset);
    offset += name1.encode.bytes;
    name1.encode(data.rname, buf, offset);
    offset += name1.encode.bytes;
    buf.writeUInt32BE(data.serial || 0, offset);
    offset += 4;
    buf.writeUInt32BE(data.refresh || 0, offset);
    offset += 4;
    buf.writeUInt32BE(data.retry || 0, offset);
    offset += 4;
    buf.writeUInt32BE(data.expire || 0, offset);
    offset += 4;
    buf.writeUInt32BE(data.minimum || 0, offset);
    offset += 4;
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset);
    rsoa.encode.bytes = offset - oldOffset;
    return buf;
};
rsoa.encode.bytes = 0;
rsoa.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    const data = {
    };
    offset += 2;
    data.mname = name1.decode(buf, offset);
    offset += name1.decode.bytes;
    data.rname = name1.decode(buf, offset);
    offset += name1.decode.bytes;
    data.serial = buf.readUInt32BE(offset);
    offset += 4;
    data.refresh = buf.readUInt32BE(offset);
    offset += 4;
    data.retry = buf.readUInt32BE(offset);
    offset += 4;
    data.expire = buf.readUInt32BE(offset);
    offset += 4;
    data.minimum = buf.readUInt32BE(offset);
    offset += 4;
    rsoa.decode.bytes = offset - oldOffset;
    return data;
};
rsoa.decode.bytes = 0;
rsoa.encodingLength = function(data) {
    return 22 + name1.encodingLength(data.mname) + name1.encodingLength(data.rname);
};
const rtxt = {
};
rtxt.encode = function(data, buf, offset) {
    if (!Array.isArray(data)) data = [
        data
    ];
    for(let i17 = 0; i17 < data.length; i17++){
        if (typeof data[i17] === "string") {
            data[i17] = Buffer1.from(data[i17]);
        }
        if (!Buffer1.isBuffer(data[i17])) {
            throw new Error("Must be a Buffer");
        }
    }
    if (!buf) buf = Buffer1.allocUnsafe(rtxt.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    data.forEach(function(d) {
        buf[offset++] = d.length;
        d.copy(buf, offset, 0, d.length);
        offset += d.length;
    });
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset);
    rtxt.encode.bytes = offset - oldOffset;
    return buf;
};
rtxt.encode.bytes = 0;
rtxt.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    let remaining = buf.readUInt16BE(offset);
    offset += 2;
    let data = [];
    while(remaining > 0){
        const len = buf[offset++];
        --remaining;
        if (remaining < len) {
            throw new Error("Buffer overflow");
        }
        data.push(buf.slice(offset, offset + len));
        offset += len;
        remaining -= len;
    }
    rtxt.decode.bytes = offset - oldOffset;
    return data;
};
rtxt.decode.bytes = 0;
rtxt.encodingLength = function(data) {
    if (!Array.isArray(data)) data = [
        data
    ];
    let length = 2;
    data.forEach(function(buf) {
        if (typeof buf === "string") {
            length += Buffer1.byteLength(buf) + 1;
        } else {
            length += buf.length + 1;
        }
    });
    return length;
};
const rnull = {
};
rnull.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rnull.encodingLength(data));
    if (!offset) offset = 0;
    if (typeof data === "string") data = Buffer1.from(data);
    if (!data) data = Buffer1.allocUnsafe(0);
    const oldOffset = offset;
    offset += 2;
    const len = data.length;
    data.copy(buf, offset, 0, len);
    offset += len;
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset);
    rnull.encode.bytes = offset - oldOffset;
    return buf;
};
rnull.encode.bytes = 0;
rnull.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    const len = buf.readUInt16BE(offset);
    offset += 2;
    const data = buf.slice(offset, offset + len);
    offset += len;
    rnull.decode.bytes = offset - oldOffset;
    return data;
};
rnull.decode.bytes = 0;
rnull.encodingLength = function(data) {
    if (!data) return 2;
    return (Buffer1.isBuffer(data) ? data.length : Buffer1.byteLength(data)) + 2;
};
const rhinfo = {
};
rhinfo.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rhinfo.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    string.encode(data.cpu, buf, offset);
    offset += string.encode.bytes;
    string.encode(data.os, buf, offset);
    offset += string.encode.bytes;
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset);
    rhinfo.encode.bytes = offset - oldOffset;
    return buf;
};
rhinfo.encode.bytes = 0;
rhinfo.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    const data = {
    };
    offset += 2;
    data.cpu = string.decode(buf, offset);
    offset += string.decode.bytes;
    data.os = string.decode(buf, offset);
    offset += string.decode.bytes;
    rhinfo.decode.bytes = offset - oldOffset;
    return data;
};
rhinfo.decode.bytes = 0;
rhinfo.encodingLength = function(data) {
    return string.encodingLength(data.cpu) + string.encodingLength(data.os) + 2;
};
const rptr = {
};
const rcname = rptr;
const rdname = rptr;
rptr.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rptr.encodingLength(data));
    if (!offset) offset = 0;
    name1.encode(data, buf, offset + 2);
    buf.writeUInt16BE(name1.encode.bytes, offset);
    rptr.encode.bytes = name1.encode.bytes + 2;
    return buf;
};
rptr.encode.bytes = 0;
rptr.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const data = name1.decode(buf, offset + 2);
    rptr.decode.bytes = name1.decode.bytes + 2;
    return data;
};
rptr.decode.bytes = 0;
rptr.encodingLength = function(data) {
    return name1.encodingLength(data) + 2;
};
const rsrv = {
};
rsrv.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rsrv.encodingLength(data));
    if (!offset) offset = 0;
    buf.writeUInt16BE(data.priority || 0, offset + 2);
    buf.writeUInt16BE(data.weight || 0, offset + 4);
    buf.writeUInt16BE(data.port || 0, offset + 6);
    name1.encode(data.target, buf, offset + 8);
    const len = name1.encode.bytes + 6;
    buf.writeUInt16BE(len, offset);
    rsrv.encode.bytes = len + 2;
    return buf;
};
rsrv.encode.bytes = 0;
rsrv.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const len = buf.readUInt16BE(offset);
    const data = {
    };
    data.priority = buf.readUInt16BE(offset + 2);
    data.weight = buf.readUInt16BE(offset + 4);
    data.port = buf.readUInt16BE(offset + 6);
    data.target = name1.decode(buf, offset + 8);
    rsrv.decode.bytes = len + 2;
    return data;
};
rsrv.decode.bytes = 0;
rsrv.encodingLength = function(data) {
    return 8 + name1.encodingLength(data.target);
};
const rcaa = {
};
rcaa.ISSUER_CRITICAL = 1 << 7;
rcaa.encode = function(data, buf, offset) {
    const len = rcaa.encodingLength(data);
    if (!buf) buf = Buffer1.allocUnsafe(rcaa.encodingLength(data));
    if (!offset) offset = 0;
    if (data.issuerCritical) {
        data.flags = rcaa.ISSUER_CRITICAL;
    }
    buf.writeUInt16BE(len - 2, offset);
    offset += 2;
    buf.writeUInt8(data.flags || 0, offset);
    offset += 1;
    string.encode(data.tag, buf, offset);
    offset += string.encode.bytes;
    buf.write(data.value, offset);
    offset += Buffer1.byteLength(data.value);
    rcaa.encode.bytes = len;
    return buf;
};
rcaa.encode.bytes = 0;
rcaa.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const len = buf.readUInt16BE(offset);
    offset += 2;
    const oldOffset = offset;
    const data = {
    };
    data.flags = buf.readUInt8(offset);
    offset += 1;
    data.tag = string.decode(buf, offset);
    offset += string.decode.bytes;
    data.value = buf.toString("utf-8", offset, oldOffset + len);
    data.issuerCritical = !!(data.flags & rcaa.ISSUER_CRITICAL);
    rcaa.decode.bytes = len + 2;
    return data;
};
rcaa.decode.bytes = 0;
rcaa.encodingLength = function(data) {
    return string.encodingLength(data.tag) + string.encodingLength(data.value) + 2;
};
const rmx = {
};
rmx.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rmx.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    buf.writeUInt16BE(data.preference || 0, offset);
    offset += 2;
    name1.encode(data.exchange, buf, offset);
    offset += name1.encode.bytes;
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset);
    rmx.encode.bytes = offset - oldOffset;
    return buf;
};
rmx.encode.bytes = 0;
rmx.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    const data = {
    };
    offset += 2;
    data.preference = buf.readUInt16BE(offset);
    offset += 2;
    data.exchange = name1.decode(buf, offset);
    offset += name1.decode.bytes;
    rmx.decode.bytes = offset - oldOffset;
    return data;
};
rmx.encodingLength = function(data) {
    return 4 + name1.encodingLength(data.exchange);
};
const ra = {
};
ra.encode = function(host, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(ra.encodingLength(host));
    if (!offset) offset = 0;
    buf.writeUInt16BE(4, offset);
    offset += 2;
    ip.toBuffer(host, buf, offset);
    ra.encode.bytes = 6;
    return buf;
};
ra.encode.bytes = 0;
ra.decode = function(buf, offset) {
    if (!offset) offset = 0;
    offset += 2;
    const host = ip.toString(buf, offset, 4);
    ra.decode.bytes = 6;
    return host;
};
ra.decode.bytes = 0;
ra.encodingLength = function() {
    return 6;
};
const raaaa = {
};
raaaa.encode = function(host, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(raaaa.encodingLength(host));
    if (!offset) offset = 0;
    buf.writeUInt16BE(16, offset);
    offset += 2;
    ip.toBuffer(host, buf, offset);
    raaaa.encode.bytes = 18;
    return buf;
};
raaaa.encode.bytes = 0;
raaaa.decode = function(buf, offset) {
    if (!offset) offset = 0;
    offset += 2;
    const host = ip.toString(buf, offset, 16);
    raaaa.decode.bytes = 18;
    return host;
};
raaaa.decode.bytes = 0;
raaaa.encodingLength = function() {
    return 18;
};
const roption = {
};
roption.encode = function(option, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(roption.encodingLength(option));
    if (!offset) offset = 0;
    const oldOffset = offset;
    const code = toCode(option.code);
    buf.writeUInt16BE(code, offset);
    offset += 2;
    if (option.data) {
        buf.writeUInt16BE(option.data.length, offset);
        offset += 2;
        option.data.copy(buf, offset);
        offset += option.data.length;
    } else {
        switch(code){
            case 8:
                const spl = option.sourcePrefixLength || 0;
                const fam = option.family || (ip.isV4Format(option.ip) ? 1 : 2);
                const ipBuf = ip.toBuffer(option.ip);
                const ipLen = Math.ceil(spl / 8);
                buf.writeUInt16BE(ipLen + 4, offset);
                offset += 2;
                buf.writeUInt16BE(fam, offset);
                offset += 2;
                buf.writeUInt8(spl, offset++);
                buf.writeUInt8(option.scopePrefixLength || 0, offset++);
                ipBuf.copy(buf, offset, 0, ipLen);
                offset += ipLen;
                break;
            case 11:
                if (option.timeout) {
                    buf.writeUInt16BE(2, offset);
                    offset += 2;
                    buf.writeUInt16BE(option.timeout, offset);
                    offset += 2;
                } else {
                    buf.writeUInt16BE(0, offset);
                    offset += 2;
                }
                break;
            case 12:
                const len = option.length || 0;
                buf.writeUInt16BE(len, offset);
                offset += 2;
                buf.fill(0, offset, offset + len);
                offset += len;
                break;
            case 14:
                const tagsLen = option.tags.length * 2;
                buf.writeUInt16BE(tagsLen, offset);
                offset += 2;
                for (const tag of option.tags){
                    buf.writeUInt16BE(tag, offset);
                    offset += 2;
                }
                break;
            default:
                throw new Error(`Unknown roption code: ${option.code}`);
        }
    }
    roption.encode.bytes = offset - oldOffset;
    return buf;
};
roption.encode.bytes = 0;
roption.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const option = {
    };
    option.code = buf.readUInt16BE(offset);
    option.type = toString4(option.code);
    offset += 2;
    const len = buf.readUInt16BE(offset);
    offset += 2;
    option.data = buf.slice(offset, offset + len);
    switch(option.code){
        case 8:
            option.family = buf.readUInt16BE(offset);
            offset += 2;
            option.sourcePrefixLength = buf.readUInt8(offset++);
            option.scopePrefixLength = buf.readUInt8(offset++);
            const padded = Buffer1.alloc(option.family === 1 ? 4 : 16);
            buf.copy(padded, 0, offset, offset + len - 4);
            option.ip = ip.toString(padded);
            break;
        case 11:
            if (len > 0) {
                option.timeout = buf.readUInt16BE(offset);
                offset += 2;
            }
            break;
        case 14:
            option.tags = [];
            for(let i18 = 0; i18 < len; i18 += 2){
                option.tags.push(buf.readUInt16BE(offset));
                offset += 2;
            }
    }
    roption.decode.bytes = len + 4;
    return option;
};
roption.decode.bytes = 0;
roption.encodingLength = function(option) {
    if (option.data) {
        return option.data.length + 4;
    }
    const code = toCode(option.code);
    switch(code){
        case 8:
            const spl = option.sourcePrefixLength || 0;
            return Math.ceil(spl / 8) + 8;
        case 11:
            return typeof option.timeout === "number" ? 6 : 4;
        case 12:
            return option.length + 4;
        case 14:
            return 4 + option.tags.length * 2;
    }
    throw new Error(`Unknown roption code: ${option.code}`);
};
const ropt = {
};
ropt.encode = function(options, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(ropt.encodingLength(options));
    if (!offset) offset = 0;
    const oldOffset = offset;
    const rdlen = encodingLengthList(options, roption);
    buf.writeUInt16BE(rdlen, offset);
    offset = encodeList(options, roption, buf, offset + 2);
    ropt.encode.bytes = offset - oldOffset;
    return buf;
};
ropt.encode.bytes = 0;
ropt.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    const options = [];
    let rdlen = buf.readUInt16BE(offset);
    offset += 2;
    let o = 0;
    while(rdlen > 0){
        options[o++] = roption.decode(buf, offset);
        offset += roption.decode.bytes;
        rdlen -= roption.decode.bytes;
    }
    ropt.decode.bytes = offset - oldOffset;
    return options;
};
ropt.decode.bytes = 0;
ropt.encodingLength = function(options) {
    return 2 + encodingLengthList(options || [], roption);
};
const rdnskey = {
};
rdnskey.PROTOCOL_DNSSEC = 3;
rdnskey.ZONE_KEY = 128;
rdnskey.SECURE_ENTRYPOINT = 32768;
rdnskey.encode = function(key, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rdnskey.encodingLength(key));
    if (!offset) offset = 0;
    const oldOffset = offset;
    const keydata = key.key;
    if (!Buffer1.isBuffer(keydata)) {
        throw new Error("Key must be a Buffer");
    }
    offset += 2;
    buf.writeUInt16BE(key.flags, offset);
    offset += 2;
    buf.writeUInt8(rdnskey.PROTOCOL_DNSSEC, offset);
    offset += 1;
    buf.writeUInt8(key.algorithm, offset);
    offset += 1;
    keydata.copy(buf, offset, 0, keydata.length);
    offset += keydata.length;
    rdnskey.encode.bytes = offset - oldOffset;
    buf.writeUInt16BE(rdnskey.encode.bytes - 2, oldOffset);
    return buf;
};
rdnskey.encode.bytes = 0;
rdnskey.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var key = {
    };
    var length = buf.readUInt16BE(offset);
    offset += 2;
    key.flags = buf.readUInt16BE(offset);
    offset += 2;
    if (buf.readUInt8(offset) !== rdnskey.PROTOCOL_DNSSEC) {
        throw new Error("Protocol must be 3");
    }
    offset += 1;
    key.algorithm = buf.readUInt8(offset);
    offset += 1;
    key.key = buf.slice(offset, oldOffset + length + 2);
    offset += key.key.length;
    rdnskey.decode.bytes = offset - oldOffset;
    return key;
};
rdnskey.decode.bytes = 0;
rdnskey.encodingLength = function(key) {
    return 6 + Buffer1.byteLength(key.key);
};
const rrrsig = {
};
rrrsig.encode = function(sig, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rrrsig.encodingLength(sig));
    if (!offset) offset = 0;
    const oldOffset = offset;
    const signature = sig.signature;
    if (!Buffer1.isBuffer(signature)) {
        throw new Error("Signature must be a Buffer");
    }
    offset += 2;
    buf.writeUInt16BE(toType(sig.typeCovered), offset);
    offset += 2;
    buf.writeUInt8(sig.algorithm, offset);
    offset += 1;
    buf.writeUInt8(sig.labels, offset);
    offset += 1;
    buf.writeUInt32BE(sig.originalTTL, offset);
    offset += 4;
    buf.writeUInt32BE(sig.expiration, offset);
    offset += 4;
    buf.writeUInt32BE(sig.inception, offset);
    offset += 4;
    buf.writeUInt16BE(sig.keyTag, offset);
    offset += 2;
    name1.encode(sig.signersName, buf, offset);
    offset += name1.encode.bytes;
    signature.copy(buf, offset, 0, signature.length);
    offset += signature.length;
    rrrsig.encode.bytes = offset - oldOffset;
    buf.writeUInt16BE(rrrsig.encode.bytes - 2, oldOffset);
    return buf;
};
rrrsig.encode.bytes = 0;
rrrsig.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var sig = {
    };
    var length = buf.readUInt16BE(offset);
    offset += 2;
    sig.typeCovered = toString(buf.readUInt16BE(offset));
    offset += 2;
    sig.algorithm = buf.readUInt8(offset);
    offset += 1;
    sig.labels = buf.readUInt8(offset);
    offset += 1;
    sig.originalTTL = buf.readUInt32BE(offset);
    offset += 4;
    sig.expiration = buf.readUInt32BE(offset);
    offset += 4;
    sig.inception = buf.readUInt32BE(offset);
    offset += 4;
    sig.keyTag = buf.readUInt16BE(offset);
    offset += 2;
    sig.signersName = name1.decode(buf, offset);
    offset += name1.decode.bytes;
    sig.signature = buf.slice(offset, oldOffset + length + 2);
    offset += sig.signature.length;
    rrrsig.decode.bytes = offset - oldOffset;
    return sig;
};
rrrsig.decode.bytes = 0;
rrrsig.encodingLength = function(sig) {
    return 20 + name1.encodingLength(sig.signersName) + Buffer1.byteLength(sig.signature);
};
const rrp = {
};
rrp.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rrp.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    name1.encode(data.mbox || ".", buf, offset);
    offset += name1.encode.bytes;
    name1.encode(data.txt || ".", buf, offset);
    offset += name1.encode.bytes;
    rrp.encode.bytes = offset - oldOffset;
    buf.writeUInt16BE(rrp.encode.bytes - 2, oldOffset);
    return buf;
};
rrp.encode.bytes = 0;
rrp.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    const data = {
    };
    offset += 2;
    data.mbox = name1.decode(buf, offset) || ".";
    offset += name1.decode.bytes;
    data.txt = name1.decode(buf, offset) || ".";
    offset += name1.decode.bytes;
    rrp.decode.bytes = offset - oldOffset;
    return data;
};
rrp.decode.bytes = 0;
rrp.encodingLength = function(data) {
    return 2 + name1.encodingLength(data.mbox || ".") + name1.encodingLength(data.txt || ".");
};
const typebitmap = {
};
typebitmap.encode = function(typelist, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(typebitmap.encodingLength(typelist));
    if (!offset) offset = 0;
    const oldOffset = offset;
    var typesByWindow = [];
    for(var i19 = 0; i19 < typelist.length; i19++){
        var typeid = toType(typelist[i19]);
        if (typesByWindow[typeid >> 8] === undefined) {
            typesByWindow[typeid >> 8] = [];
        }
        typesByWindow[typeid >> 8][typeid >> 3 & 31] |= 1 << 7 - (typeid & 7);
    }
    for(i19 = 0; i19 < typesByWindow.length; i19++){
        if (typesByWindow[i19] !== undefined) {
            var windowBuf = Buffer1.from(typesByWindow[i19]);
            buf.writeUInt8(i19, offset);
            offset += 1;
            buf.writeUInt8(windowBuf.length, offset);
            offset += 1;
            windowBuf.copy(buf, offset);
            offset += windowBuf.length;
        }
    }
    typebitmap.encode.bytes = offset - oldOffset;
    return buf;
};
typebitmap.encode.bytes = 0;
typebitmap.decode = function(buf, offset, length) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var typelist = [];
    while(offset - oldOffset < length){
        var window = buf.readUInt8(offset);
        offset += 1;
        var windowLength = buf.readUInt8(offset);
        offset += 1;
        for(var i20 = 0; i20 < windowLength; i20++){
            var b = buf.readUInt8(offset + i20);
            for(var j = 0; j < 8; j++){
                if (b & 1 << 7 - j) {
                    var typeid = toString(window << 8 | i20 << 3 | j);
                    typelist.push(typeid);
                }
            }
        }
        offset += windowLength;
    }
    typebitmap.decode.bytes = offset - oldOffset;
    return typelist;
};
typebitmap.decode.bytes = 0;
typebitmap.encodingLength = function(typelist) {
    var extents = [];
    for(var i21 = 0; i21 < typelist.length; i21++){
        var typeid = toType(typelist[i21]);
        extents[typeid >> 8] = Math.max(extents[typeid >> 8] || 0, typeid & 255);
    }
    var len = 0;
    for(i21 = 0; i21 < extents.length; i21++){
        if (extents[i21] !== undefined) {
            len += 2 + Math.ceil((extents[i21] + 1) / 8);
        }
    }
    return len;
};
const rnsec = {
};
rnsec.encode = function(record, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rnsec.encodingLength(record));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    name1.encode(record.nextDomain, buf, offset);
    offset += name1.encode.bytes;
    typebitmap.encode(record.rrtypes, buf, offset);
    offset += typebitmap.encode.bytes;
    rnsec.encode.bytes = offset - oldOffset;
    buf.writeUInt16BE(rnsec.encode.bytes - 2, oldOffset);
    return buf;
};
rnsec.encode.bytes = 0;
rnsec.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var record = {
    };
    var length = buf.readUInt16BE(offset);
    offset += 2;
    record.nextDomain = name1.decode(buf, offset);
    offset += name1.decode.bytes;
    record.rrtypes = typebitmap.decode(buf, offset, length - (offset - oldOffset));
    offset += typebitmap.decode.bytes;
    rnsec.decode.bytes = offset - oldOffset;
    return record;
};
rnsec.decode.bytes = 0;
rnsec.encodingLength = function(record) {
    return 2 + name1.encodingLength(record.nextDomain) + typebitmap.encodingLength(record.rrtypes);
};
const rnsec3 = {
};
rnsec3.encode = function(record, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rnsec3.encodingLength(record));
    if (!offset) offset = 0;
    const oldOffset = offset;
    const salt = record.salt;
    if (!Buffer1.isBuffer(salt)) {
        throw new Error("salt must be a Buffer");
    }
    const nextDomain = record.nextDomain;
    if (!Buffer1.isBuffer(nextDomain)) {
        throw new Error("nextDomain must be a Buffer");
    }
    offset += 2;
    buf.writeUInt8(record.algorithm, offset);
    offset += 1;
    buf.writeUInt8(record.flags, offset);
    offset += 1;
    buf.writeUInt16BE(record.iterations, offset);
    offset += 2;
    buf.writeUInt8(salt.length, offset);
    offset += 1;
    salt.copy(buf, offset, 0, salt.length);
    offset += salt.length;
    buf.writeUInt8(nextDomain.length, offset);
    offset += 1;
    nextDomain.copy(buf, offset, 0, nextDomain.length);
    offset += nextDomain.length;
    typebitmap.encode(record.rrtypes, buf, offset);
    offset += typebitmap.encode.bytes;
    rnsec3.encode.bytes = offset - oldOffset;
    buf.writeUInt16BE(rnsec3.encode.bytes - 2, oldOffset);
    return buf;
};
rnsec3.encode.bytes = 0;
rnsec3.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var record = {
    };
    var length = buf.readUInt16BE(offset);
    offset += 2;
    record.algorithm = buf.readUInt8(offset);
    offset += 1;
    record.flags = buf.readUInt8(offset);
    offset += 1;
    record.iterations = buf.readUInt16BE(offset);
    offset += 2;
    const saltLength = buf.readUInt8(offset);
    offset += 1;
    record.salt = buf.slice(offset, offset + saltLength);
    offset += saltLength;
    const hashLength = buf.readUInt8(offset);
    offset += 1;
    record.nextDomain = buf.slice(offset, offset + hashLength);
    offset += hashLength;
    record.rrtypes = typebitmap.decode(buf, offset, length - (offset - oldOffset));
    offset += typebitmap.decode.bytes;
    rnsec3.decode.bytes = offset - oldOffset;
    return record;
};
rnsec3.decode.bytes = 0;
rnsec3.encodingLength = function(record) {
    return 8 + record.salt.length + record.nextDomain.length + typebitmap.encodingLength(record.rrtypes);
};
const rds = {
};
rds.encode = function(digest, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rds.encodingLength(digest));
    if (!offset) offset = 0;
    const oldOffset = offset;
    const digestdata = digest.digest;
    if (!Buffer1.isBuffer(digestdata)) {
        throw new Error("Digest must be a Buffer");
    }
    offset += 2;
    buf.writeUInt16BE(digest.keyTag, offset);
    offset += 2;
    buf.writeUInt8(digest.algorithm, offset);
    offset += 1;
    buf.writeUInt8(digest.digestType, offset);
    offset += 1;
    digestdata.copy(buf, offset, 0, digestdata.length);
    offset += digestdata.length;
    rds.encode.bytes = offset - oldOffset;
    buf.writeUInt16BE(rds.encode.bytes - 2, oldOffset);
    return buf;
};
rds.encode.bytes = 0;
rds.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var digest = {
    };
    var length = buf.readUInt16BE(offset);
    offset += 2;
    digest.keyTag = buf.readUInt16BE(offset);
    offset += 2;
    digest.algorithm = buf.readUInt8(offset);
    offset += 1;
    digest.digestType = buf.readUInt8(offset);
    offset += 1;
    digest.digest = buf.slice(offset, oldOffset + length + 2);
    offset += digest.digest.length;
    rds.decode.bytes = offset - oldOffset;
    return digest;
};
rds.decode.bytes = 0;
rds.encodingLength = function(digest) {
    return 6 + Buffer1.byteLength(digest.digest);
};
const rhttpsvcb = {
};
rhttpsvcb.decode = function(buf, offset) {
    if (!offset) offset = 0;
    let oldOffset = offset;
    const rLen = buf.readUInt16BE(offset) + 2;
    console.log("Rdata length : " + rLen);
    offset += 2;
    let data = {
    };
    data.svcPriority = buf.readUInt16BE(offset);
    offset += 2;
    data.targetName = name1.decode(buf, offset);
    offset += name1.decode.bytes;
    data.svcParams = {
    };
    let svcKeyDecode;
    let svcParamKey;
    let svcKeyStr;
    while(offset != oldOffset + rLen){
        svcParamKey = buf.readUInt16BE(offset);
        svcKeyStr = toString5(svcParamKey);
        svcKeyDecode = svcbKeyObj(svcKeyStr);
        offset += 2;
        data.svcParams[svcKeyStr] = svcKeyDecode.decode(buf, offset);
        offset += svcKeyDecode.decode.bytes;
    }
    rhttpsvcb.decode.bytes = offset - oldOffset;
    return data;
};
rhttpsvcb.decode.bytes = 0;
rhttpsvcb.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(rhttpsvcb.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    buf.writeUInt16BE(data.svcPriority, offset);
    offset += 2;
    name1.encode(data.targetName, buf, offset);
    offset += name1.encode.bytes;
    let svcbObj;
    for (let key of Object.keys(data.svcParams)){
        buf.writeUInt16BE(toKey(key), offset);
        offset += 2;
        svcbObj = svcbKeyObj(key);
        svcbObj.encode(data.svcParams[key], buf, offset);
        offset += svcbObj.encode.bytes;
    }
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset);
    rhttpsvcb.encode.bytes = offset - oldOffset;
    return buf;
};
rhttpsvcb.encode.bytes = 0;
rhttpsvcb.encodingLength = function(data) {
    var encLen = 4 + name1.encodingLength(data.targetName);
    let svcbObj;
    for (let key of Object.keys(data.svcParams)){
        svcbObj = svcbKeyObj(key);
        encLen += 2 + svcbObj.encodingLength(data.svcParams[key]);
    }
    console.log(encLen);
    return encLen;
};
const svcAlpn = {
};
svcAlpn.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var data = [];
    var length = buf.readUInt16BE(offset);
    offset += 2;
    var valueLength = 0;
    while(length != 0){
        valueLength = buf.readUInt8(offset);
        offset += 1;
        length -= 1;
        data.push(buf.toString("utf-8", offset, offset + valueLength));
        offset += valueLength;
        length -= valueLength;
    }
    svcAlpn.decode.bytes = offset - oldOffset;
    return data;
};
svcAlpn.decode.bytes = 0;
svcAlpn.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(svcAlpn.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    for (let value of data){
        buf.writeUInt8(Buffer1.byteLength(value), offset);
        offset += 1;
        offset += buf.write(value, offset);
    }
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset);
    svcAlpn.encode.bytes = offset - oldOffset;
    return buf;
};
svcAlpn.encode.bytes = 0;
svcAlpn.encodingLength = function(data) {
    var encLen = 2;
    for (let value of data){
        encLen += 1 + Buffer1.byteLength(value);
    }
    return encLen;
};
const svcIpv6 = {
};
svcIpv6.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var data = [];
    var length = buf.readUInt16BE(offset);
    offset += 2;
    while(length != 0){
        data.push(ip.toString(buf, offset, 16));
        offset += 16;
        length -= 16;
    }
    svcIpv6.decode.bytes = offset - oldOffset;
    return data;
};
svcIpv6.decode.bytes = 0;
svcIpv6.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(svcIpv6.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    buf.writeUInt16BE(data.length * 16, offset);
    offset += 2;
    for (let value of data){
        ip.toBuffer(value, buf, offset);
        offset += 16;
    }
    svcIpv6.encode.bytes = offset - oldOffset;
    return buf;
};
svcIpv6.encode.bytes = 0;
svcIpv6.encodingLength = function(data) {
    return 2 + data.length * 16;
};
const svcIpv4 = {
};
svcIpv4.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var data = [];
    var length = buf.readUInt16BE(offset);
    offset += 2;
    while(length != 0){
        data.push(ip.toString(buf, offset, 4));
        offset += 4;
        length -= 4;
    }
    svcIpv4.decode.bytes = offset - oldOffset;
    return data;
};
svcIpv4.decode.bytes = 0;
svcIpv4.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(svcIpv4.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    buf.writeUInt16BE(data.length * 4, offset);
    offset += 2;
    for (let value of data){
        ip.toBuffer(value, buf, offset);
        offset += 4;
    }
    svcIpv4.encode.bytes = offset - oldOffset;
    return buf;
};
svcIpv4.encode.bytes = 0;
svcIpv4.encodingLength = function(data) {
    return 2 + data.length * 4;
};
const svcMandatory = {
};
svcMandatory.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var data = [];
    var length = buf.readUInt16BE(offset);
    offset += 2;
    while(length != 0){
        data.push(toString5(buf.readUInt16BE(offset)));
        offset += 2;
        length -= 2;
    }
    svcMandatory.decode.bytes = offset - oldOffset;
    return data;
};
svcMandatory.decode.bytes = 0;
svcMandatory.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(svcMandatory.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    buf.writeUInt16BE(data.length * 2, offset);
    offset += 2;
    for (let value of data){
        buf.writeUInt16BE(toKey(value), offset);
        offset += 2;
    }
    svcMandatory.encode.bytes = offset - oldOffset;
    return buf;
};
svcMandatory.encode.bytes = 0;
svcMandatory.encodingLength = function(data) {
    return 2 + data.length * 2;
};
const svcPort = {
};
svcPort.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var data = [];
    var length = buf.readUInt16BE(offset);
    offset += 2;
    while(length != 0){
        data.push(buf.readUInt16BE(offset));
        offset += 2;
        length -= 2;
    }
    svcPort.decode.bytes = offset - oldOffset;
    return data;
};
svcPort.decode.bytes = 0;
svcPort.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(svcPort.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    buf.writeUInt16BE(data.length * 2, offset);
    offset += 2;
    for (let value of data){
        buf.writeUInt16BE(value, offset);
        offset += 2;
    }
    svcPort.encode.bytes = offset - oldOffset;
    return buf;
};
svcPort.encode.bytes = 0;
svcPort.encodingLength = function(data) {
    return 2 + data.length * 2;
};
const svcEch = {
};
svcEch.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var data;
    var length = buf.readUInt16BE(offset);
    offset += 2;
    data = buf.toString("base64", offset, offset + length);
    offset += length;
    svcEch.decode.bytes = offset - oldOffset;
    return data;
};
svcEch.decode.bytes = 0;
svcEch.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(svcEch.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    offset += 2;
    offset += buf.write(data, offset, "base64");
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset);
    svcEch.encode.bytes = offset - oldOffset;
    return buf;
};
svcEch.encode.bytes = 0;
svcEch.encodingLength = function(data) {
    return 2 + Buffer1.from(data, "base64").byteLength;
};
const svcOther = {
};
svcOther.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    var data;
    var length = buf.readUInt16BE(offset);
    offset += 2;
    data = buf.slice(offset, offset + length);
    offset += length;
    svcOther.decode.bytes = offset - oldOffset;
    return data;
};
svcOther.decode.bytes = 0;
svcOther.encode = function(data, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(svcOther.encodingLength(data));
    if (!offset) offset = 0;
    const oldOffset = offset;
    buf.writeUInt16BE(data.byteLength, offset);
    offset += 2;
    offset += data.copy(buf, offset);
    svcOther.encode.bytes = offset - oldOffset;
    return buf;
};
svcOther.encode.bytes = 0;
svcOther.encodingLength = function(data) {
    return 2 + data.byteLength;
};
const svcbKeyObj = function(type) {
    switch(type.toLowerCase()){
        case "mandatory":
            return svcMandatory;
        case "alpn":
            return svcAlpn;
        case "no-default-alpn":
            return svcAlpn;
        case "port":
            return svcPort;
        case "ipv4hint":
            return svcIpv4;
        case "ech":
            return svcEch;
        case "ipv6hint":
            return svcIpv6;
        default:
            return svcOther;
    }
};
const renc = function(type) {
    switch(type.toUpperCase()){
        case "A":
            return ra;
        case "PTR":
            return rptr;
        case "CNAME":
            return rcname;
        case "DNAME":
            return rdname;
        case "TXT":
            return rtxt;
        case "NULL":
            return rnull;
        case "AAAA":
            return raaaa;
        case "SRV":
            return rsrv;
        case "HINFO":
            return rhinfo;
        case "CAA":
            return rcaa;
        case "NS":
            return rns;
        case "SOA":
            return rsoa;
        case "MX":
            return rmx;
        case "OPT":
            return ropt;
        case "DNSKEY":
            return rdnskey;
        case "RRSIG":
            return rrrsig;
        case "RP":
            return rrp;
        case "NSEC":
            return rnsec;
        case "NSEC3":
            return rnsec3;
        case "DS":
            return rds;
        case "HTTPS":
            return rhttpsvcb;
        case "SVCB":
            return rhttpsvcb;
    }
    return runknown;
};
const answer = {
};
answer.encode = function(a, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(answer.encodingLength(a));
    if (!offset) offset = 0;
    const oldOffset = offset;
    name1.encode(a.name, buf, offset);
    offset += name1.encode.bytes;
    buf.writeUInt16BE(toType(a.type), offset);
    if (a.type.toUpperCase() === "OPT") {
        if (a.name !== ".") {
            throw new Error("OPT name must be root.");
        }
        buf.writeUInt16BE(a.udpPayloadSize || 4096, offset + 2);
        buf.writeUInt8(a.extendedRcode || 0, offset + 4);
        buf.writeUInt8(a.ednsVersion || 0, offset + 5);
        buf.writeUInt16BE(a.flags || 0, offset + 6);
        offset += 8;
        ropt.encode(a.options || [], buf, offset);
        offset += ropt.encode.bytes;
    } else {
        let klass = toClass(a.class === undefined ? "IN" : a.class);
        if (a.flush) klass |= FLUSH_MASK;
        buf.writeUInt16BE(klass, offset + 2);
        buf.writeUInt32BE(a.ttl || 0, offset + 4);
        offset += 8;
        const enc = renc(a.type);
        enc.encode(a.data, buf, offset);
        offset += enc.encode.bytes;
    }
    answer.encode.bytes = offset - oldOffset;
    return buf;
};
answer.encode.bytes = 0;
answer.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const a = {
    };
    const oldOffset = offset;
    a.name = name1.decode(buf, offset);
    offset += name1.decode.bytes;
    a.type = toString(buf.readUInt16BE(offset));
    if (a.type === "OPT") {
        a.udpPayloadSize = buf.readUInt16BE(offset + 2);
        a.extendedRcode = buf.readUInt8(offset + 4);
        a.ednsVersion = buf.readUInt8(offset + 5);
        a.flags = buf.readUInt16BE(offset + 6);
        a.flag_do = (a.flags >> 15 & 1) === 1;
        a.options = ropt.decode(buf, offset + 8);
        offset += 8 + ropt.decode.bytes;
    } else {
        const klass = buf.readUInt16BE(offset + 2);
        a.ttl = buf.readUInt32BE(offset + 4);
        a.class = toString3(klass & NOT_FLUSH_MASK);
        a.flush = !!(klass & FLUSH_MASK);
        const enc = renc(a.type);
        a.data = enc.decode(buf, offset + 8);
        offset += 8 + enc.decode.bytes;
    }
    answer.decode.bytes = offset - oldOffset;
    return a;
};
answer.decode.bytes = 0;
answer.encodingLength = function(a) {
    const data = a.data !== null && a.data !== undefined ? a.data : a.options;
    return name1.encodingLength(a.name) + 8 + renc(a.type).encodingLength(data);
};
const question = {
};
question.encode = function(q, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(question.encodingLength(q));
    if (!offset) offset = 0;
    const oldOffset = offset;
    name1.encode(q.name, buf, offset);
    offset += name1.encode.bytes;
    buf.writeUInt16BE(toType(q.type), offset);
    offset += 2;
    buf.writeUInt16BE(toClass(q.class === undefined ? "IN" : q.class), offset);
    offset += 2;
    question.encode.bytes = offset - oldOffset;
    return q;
};
question.encode.bytes = 0;
question.decode = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    const q = {
    };
    q.name = name1.decode(buf, offset);
    offset += name1.decode.bytes;
    q.type = toString(buf.readUInt16BE(offset));
    offset += 2;
    q.class = toString3(buf.readUInt16BE(offset));
    offset += 2;
    const qu = !!(q.class & QU_MASK);
    if (qu) q.class &= NOT_QU_MASK;
    question.decode.bytes = offset - oldOffset;
    return q;
};
question.decode.bytes = 0;
question.encodingLength = function(q) {
    return name1.encodingLength(q.name) + 4;
};
const encode2 = function(result, buf, offset) {
    if (!buf) buf = Buffer1.allocUnsafe(encodingLength(result));
    if (!offset) offset = 0;
    const oldOffset = offset;
    if (!result.questions) result.questions = [];
    if (!result.answers) result.answers = [];
    if (!result.authorities) result.authorities = [];
    if (!result.additionals) result.additionals = [];
    header.encode(result, buf, offset);
    offset += header.encode.bytes;
    offset = encodeList(result.questions, question, buf, offset);
    offset = encodeList(result.answers, answer, buf, offset);
    offset = encodeList(result.authorities, answer, buf, offset);
    offset = encodeList(result.additionals, answer, buf, offset);
    encode2.bytes = offset - oldOffset;
    return buf;
};
encode2.bytes = 0;
const decode2 = function(buf, offset) {
    if (!offset) offset = 0;
    const oldOffset = offset;
    const result = header.decode(buf, offset);
    offset += header.decode.bytes;
    offset = decodeList(result.questions, question, buf, offset);
    offset = decodeList(result.answers, answer, buf, offset);
    offset = decodeList(result.authorities, answer, buf, offset);
    offset = decodeList(result.additionals, answer, buf, offset);
    decode2.bytes = offset - oldOffset;
    return result;
};
decode2.bytes = 0;
const encodingLength = function(result) {
    return header.encodingLength(result) + encodingLengthList(result.questions || [], question) + encodingLengthList(result.answers || [], answer) + encodingLengthList(result.authorities || [], answer) + encodingLengthList(result.additionals || [], answer);
};
const streamEncode = function(result) {
    const buf = encode2(result);
    const sbuf = Buffer1.allocUnsafe(2);
    sbuf.writeUInt16BE(buf.byteLength);
    const combine = Buffer1.concat([
        sbuf,
        buf
    ]);
    streamEncode.bytes = combine.byteLength;
    return combine;
};
streamEncode.bytes = 0;
const streamDecode = function(sbuf) {
    const len = sbuf.readUInt16BE(0);
    if (sbuf.byteLength < len + 2) {
        return null;
    }
    const result = decode2(sbuf.slice(2));
    streamDecode.bytes = decode2.bytes;
    return result;
};
streamDecode.bytes = 0;
function encodingLengthList(list, enc) {
    let len = 0;
    for(let i22 = 0; i22 < list.length; i22++)len += enc.encodingLength(list[i22]);
    return len;
}
function encodeList(list, enc, buf, offset) {
    for(let i23 = 0; i23 < list.length; i23++){
        enc.encode(list[i23], buf, offset);
        offset += enc.encode.bytes;
    }
    return offset;
}
function decodeList(list, enc, buf, offset) {
    for(let i24 = 0; i24 < list.length; i24++){
        list[i24] = enc.decode(buf, offset);
        offset += enc.decode.bytes;
    }
    return offset;
}
class DNSParserWrap {
    constructor(){
    }
    decode(arrayBuffer) {
        return decode2(bufferOf(arrayBuffer));
    }
    encode(decodedDnsPacket) {
        return encode2(decodedDnsPacket);
    }
}
const minDNSPacketSize = 12 + 5;
const _dnsCloudflareSec = "1.1.1.2";
const dns = new DNSParserWrap();
function dnsIpv4() {
    return _dnsCloudflareSec;
}
function cacheSize() {
    return 10000;
}
function servfail(qid, qs) {
    if (!qid || !qs) return null;
    return encode3({
        id: qid,
        type: "response",
        flags: 4098,
        questions: qs
    });
}
function requestTimeout() {
    const t = workersTimeout(15000);
    return t > 5000 ? Math.min(t, 30000) : 5000;
}
function truncated(ans) {
    if (ans.length < 12) return false;
    const flags = ans.readUInt16BE(2);
    const tc = flags >> 9 & 1;
    return tc === 1;
}
function validResponseSize(r) {
    return r && validateSize(r.byteLength);
}
function validateSize(sz) {
    return sz >= minDNSPacketSize && sz <= 4096;
}
function hasAnswers(packet) {
    return packet && packet.answers && packet.answers.length > 0;
}
function hasSingleQuestion(packet) {
    return packet && packet.questions && packet.questions.length === 1;
}
function rcodeNoError(packet) {
    return packet && packet.rcode === "NOERROR";
}
function dnsqurl(dnsq) {
    return btoa(String.fromCharCode(...new Uint8Array(dnsq))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function optAnswer(a) {
    return a && a.type && a.type.toUpperCase() === "OPT";
}
function encode3(obj) {
    return dns.encode(obj);
}
function decode3(buf) {
    return dns.decode(buf);
}
function isBlockable(packet) {
    return hasSingleQuestion(packet) && (packet.questions[0].type === "A" || packet.questions[0].type === "AAAA" || packet.questions[0].type === "CNAME" || packet.questions[0].type === "HTTPS" || packet.questions[0].type === "SVCB");
}
function isCname(packet) {
    return hasAnswers(packet) && packet.answers[0].type === "CNAME";
}
function isHttps(packet) {
    return hasAnswers(packet) && (packet.answers[0].type === "HTTPS" || packet.answers[0].type === "SVCB");
}
function getCname(answers) {
    const li = [];
    li[0] = answers[0].data.trim().toLowerCase();
    li[1] = answers[answers.length - 1].name.trim().toLowerCase();
    return li;
}
function getTargetName(answers) {
    const tn = answers[0].data.targetName.trim().toLowerCase();
    if (tn === ".") return false;
    return tn;
}
function getQueryName(questions) {
    const qn = questions[0].name.trim().toLowerCase();
    if (qn === "") return false;
    return qn;
}
class DNSQuestionBlock {
    constructor(){
        this.log = log.withTags("DnsQuestionBlock");
    }
    async RethinkModule(param) {
        const response = {
        };
        response.isException = false;
        response.exceptionStack = "";
        response.exceptionFrom = "";
        response.data = false;
        try {
            response.data = this.dnsBlock(param);
        } catch (e) {
            response.isException = true;
            response.exceptionStack = e.stack;
            response.exceptionFrom = "DNSQuestionBlock RethinkModule";
            this.log.e(param.rxid, "main", e);
        }
        return response;
    }
    dnsBlock(param) {
        const response = this.performBlocking(param.userBlocklistInfo, param.requestDecodedDnsPacket, param.blocklistFilter, false);
        if (response && response.isBlocked) {
            this.log.d(param.rxid, "cache block-response");
            putCache(param.dnsCache, param.request.url, param.blocklistFilter, param.requestDecodedDnsPacket, "", param.event);
        }
        return response;
    }
    performBlocking(blockInfo, dnsPacket, blf, cf) {
        if (emptyString(blockInfo.userBlocklistFlagUint) || !isBlockable(dnsPacket)) {
            return false;
        }
        const qn = getQueryName(dnsPacket.questions);
        if (!qn) return false;
        return doBlock(blf, blockInfo, qn, cf);
    }
}
class DNSResolver {
    constructor(){
        this.http2 = null;
        this.nodeUtil = null;
        this.transport = null;
        this.dnsParser = new DNSParserWrap();
        this.log = log.withTags("DnsResolver");
    }
    async lazyInit() {
        if (isNode() && !this.http2) {
            this.http2 = await import("http2");
            this.log.i("created custom http2 client");
        }
        if (isNode() && !this.nodeUtil) {
            this.nodeUtil = await import("../helpers/node/util.js");
            this.log.i("imported node-util");
        }
        if (isNode() && !this.transport) {
            const plainOldDnsIp = dnsIpv4();
            this.transport = new (await import("../helpers/node/dns-transport.js")).Transport(plainOldDnsIp, 53);
            this.log.i("created udp/tcp dns transport", plainOldDnsIp);
        }
    }
    async RethinkModule(param) {
        await this.lazyInit();
        let response = emptyResponse();
        try {
            response.data = await this.resolveDns(param);
        } catch (e) {
            response = errResponse("dnsResolver", e);
            this.log.e(param.rxid, "main", e);
        }
        return response;
    }
    async resolveDns(param) {
        const rxid = param.rxid;
        const upRes = await this.resolveDnsUpstream(rxid, param.request, param.dnsResolverUrl, param.requestBodyBuffer);
        return await this.decodeResponse(rxid, upRes);
    }
    async decodeResponse(rxid, response) {
        if (!response) throw new Error("no upstream result");
        if (!response.ok) {
            const txt = await response.text();
            this.log.d(rxid, "!OK", response.status, response.statusText, txt);
            throw new Error(response.status + " http err: " + response.statusText);
        }
        const dnsBuffer = await response.arrayBuffer();
        if (!validResponseSize(dnsBuffer)) {
            throw new Error("Null / invalid response from upstream");
        }
        const dnsPacket = this.dnsParser.decode(dnsBuffer);
        return {
            dnsPacket: dnsPacket,
            dnsBuffer: dnsBuffer
        };
    }
}
DNSResolver.prototype.resolveDnsUpstream = async function(rxid, request, resolverUrl, requestBodyBuffer) {
    if (this.transport) {
        const q = bufferOf(requestBodyBuffer);
        let ans = await this.transport.udpquery(rxid, q);
        if (ans && truncated(ans)) {
            this.log.w(rxid, "ans truncated, retrying over tcp");
            ans = await this.transport.tcpquery(rxid, q);
        }
        return ans ? new Response(arrayBufferOf(ans)) : respond503();
    }
    const u = new URL(request.url);
    const dnsResolverUrl = new URL(resolverUrl);
    u.hostname = dnsResolverUrl.hostname;
    u.pathname = dnsResolverUrl.pathname;
    u.port = dnsResolverUrl.port;
    u.protocol = dnsResolverUrl.protocol;
    let newRequest = null;
    if (request.method === "GET") {
        u.search = "?dns=" + dnsqurl(requestBodyBuffer);
        newRequest = new Request(u.href, {
            method: "GET"
        });
    } else if (request.method === "POST") {
        newRequest = new Request(u.href, {
            method: "POST",
            headers: concatHeaders(contentLengthHeader(requestBodyBuffer), dnsHeaders()),
            body: requestBodyBuffer
        });
    } else {
        throw new Error("get/post requests only");
    }
    return this.http2 ? this.doh2(rxid, newRequest) : fetch(newRequest);
};
DNSResolver.prototype.doh2 = async function(rxid, request) {
    if (!this.http2 || !this.nodeUtil) {
        throw new Error("h2 / node-util not setup, bailing");
    }
    this.log.d(rxid, "upstream with doh2");
    const http2 = this.http2;
    const transformPseudoHeaders = this.nodeUtil.transformPseudoHeaders;
    const u = new URL(request.url);
    const reqB = bufferOf(await request.arrayBuffer());
    const headers1 = copyHeaders(request);
    return new Promise((resolve, reject)=>{
        const authority = u.origin;
        const c = http2.connect(authority);
        c.on("error", (err)=>{
            reject(err.message);
        });
        const req = c.request({
            [http2.constants.HTTP2_HEADER_METHOD]: request.method,
            [http2.constants.HTTP2_HEADER_PATH]: `${u.pathname}`,
            ...headers1
        });
        req.on("response", (headers)=>{
            const resBuffers = [];
            const resH = transformPseudoHeaders(headers);
            req.on("data", (chunk)=>{
                resBuffers.push(chunk);
            });
            req.on("end", ()=>{
                const resB = Buffer1.concat(resBuffers);
                c.close();
                resolve(new Response(resB, resH));
            });
            req.on("error", (err)=>{
                reject(err.message);
            });
        });
        req.end(reqB);
    });
};
const ttlGraceSec = 30;
function generateQuestionFilter(blf, dnsPacket) {
    const q = dnsPacket.questions[0].name;
    return {
        [q]: objOf(blf.getDomainInfo(q).searchResult)
    };
}
function generateAnswerFilter(blf, dnsPacket) {
    if (isCname(dnsPacket)) {
        const ans = getCname(dnsPacket.answers);
        return newAnswerCacheFilter(blf, ans);
    } else if (isHttps(dnsPacket)) {
        const ans = getTargetName(dnsPacket);
        return newAnswerCacheFilter(blf, ans);
    }
    return {
    };
}
function newAnswerCacheFilter(blf, ans) {
    const f = {
    };
    for (const name of ans){
        f[name] = objOf(blf.getDomainInfo(name).searchResult);
    }
    return f;
}
function isCacheable(dnsPacket) {
    if (!rcodeNoError(dnsPacket)) return false;
    if (!hasAnswers(dnsPacket)) return false;
    return true;
}
function determineCacheExpiry(dnsPacket) {
    if (!hasAnswers(dnsPacket)) return 0;
    let minttl = 1 << 30;
    for (const a of dnsPacket.answers){
        minttl = Math.min(a.ttl || minttl, minttl);
    }
    if (minttl === 1 << 30) return 0;
    minttl = Math.max(minttl + ttlGraceSec, ttlGraceSec);
    const expiry = Date.now() + minttl * 1000;
    return expiry;
}
function makeCacheMetadata(dnsPacket, blf) {
    const af = generateAnswerFilter(blf, dnsPacket);
    const qf = generateQuestionFilter(blf, dnsPacket);
    const ttl = determineCacheExpiry(dnsPacket);
    return {
        ttlEndTime: ttl,
        bodyUsed: hasAnswers(dnsPacket),
        cacheFilter: concatObj(af, qf)
    };
}
function createCacheInput(dnsPacket, blf) {
    return {
        dnsPacket: dnsPacket,
        metaData: makeCacheMetadata(dnsPacket, blf)
    };
}
function updateTtl(decodedDnsPacket, end) {
    const now = Date.now();
    const outttl = Math.max(Math.floor((end - now) / 1000) - 30, 30);
    for (const a of decodedDnsPacket.answers){
        if (!optAnswer(a)) a.ttl = outttl;
    }
}
function cacheKey(packet) {
    if (!hasSingleQuestion(packet)) return null;
    const name = packet.questions[0].name.trim().toLowerCase();
    const type = packet.questions[0].type;
    return name + ":" + type;
}
class DNSResponseBlock {
    constructor(){
        this.log = log.withTags("DnsResponseBlock");
    }
    async RethinkModule(param) {
        const response = {
        };
        response.isException = false;
        response.exceptionStack = "";
        response.exceptionFrom = "";
        response.data = false;
        try {
            response.data = this.performBlocking(param.userBlocklistInfo, param.responseDecodedDnsPacket, param.blocklistFilter, false);
            this.putCache(param.rxid, param.dnsCache, param.request.url, param.blocklistFilter, param.responseDecodedDnsPacket, param.responseBodyBuffer, param.event);
        } catch (e) {
            response.isException = true;
            response.exceptionStack = e.stack;
            response.exceptionFrom = "DNSResponseBlock RethinkModule";
            this.log.e(param.rxid, "main", e);
        }
        return response;
    }
    performBlocking(blockInfo, dnsPacket, blf, cf) {
        if (!hasBlockstamp(blockInfo)) {
            return false;
        } else if (isCname(dnsPacket)) {
            return doCnameBlock(dnsPacket, blf, blockInfo, cf);
        } else if (isHttps(dnsPacket)) {
            return doHttpsBlock(dnsPacket, blf, blockInfo, cf);
        }
        return false;
    }
    putCache(rxid, cache, url, blf, dnsPacket, buf, event) {
        if (!isCacheable(dnsPacket)) return;
        const k = cacheKey(dnsPacket);
        if (!k) return;
        const v = createCacheInput(dnsPacket, blf);
        this.log.d(rxid, "put-cache k/v ", k, v);
        cache.put(k, v, url, buf, event);
    }
}
class DNSCacheResponse {
    constructor(){
        this.log = log.withTags("DnsCacheResponse");
    }
    async RethinkModule(param) {
        const response = {
        };
        response.isException = false;
        response.exceptionStack = "";
        response.exceptionFrom = "";
        response.data = {
        };
        try {
            if (!param.isDnsMsg) {
                return response;
            }
            response.data = await this.resolveFromCache(param);
        } catch (e) {
            response.isException = true;
            response.exceptionStack = e.stack;
            response.exceptionFrom = "DNSAggCache RethinkModule";
            this.log.e(param.rxid, "main", e);
        }
        return response;
    }
    async resolveFromCache(param) {
        const key = cacheKey(param.requestDecodedDnsPacket);
        if (!key) return false;
        const cacheResponse = await param.dnsCache.get(key, param.request.url);
        this.log.d(param.rxid, "resolveFromCache k/v", key, cacheResponse);
        if (!cacheResponse) return false;
        return await this.makeCacheResponse(param.rxid, cacheResponse, param.userBlocklistInfo, param.requestDecodedDnsPacket, param.dnsQuestionBlock, param.dnsResponseBlock);
    }
    async makeCacheResponse(rxid, cr, blockInfo, reqDnsPacket, qb, rb) {
        const qresponse = blockIfNeeded(qb, reqDnsPacket, cr.metaData.cacheFilter, blockInfo);
        this.log.d(rxid, blockInfo, "question block?", qresponse);
        if (qresponse && qresponse.isBlocked) {
            return qresponse;
        }
        const aresponse = blockIfNeeded(rb, cr.dnsPacket, cr.metaData.cacheFilter, blockInfo);
        this.log.d(rxid, blockInfo, "answer block?", aresponse);
        if (aresponse && aresponse.isBlocked) {
            return aresponse;
        }
        return modifyCacheResponse(cr, reqDnsPacket.id);
    }
}
function putCache(cache, url, blf, dnsPacket, buf, event) {
    const key = cacheKey(dnsPacket);
    if (!key) return;
    const value = createCacheInput(dnsPacket, blf);
    cache.put(key, value, url, buf, event);
}
function updateQueryId(decodedDnsPacket, queryId) {
    if (queryId === decodedDnsPacket.id) return false;
    decodedDnsPacket.id = queryId;
    return true;
}
function doHttpsBlock(dnsPacket, blf, blockInfo, cf) {
    const tn = getTargetName(dnsPacket.answers);
    if (!tn) return false;
    return doBlock(blf, blockInfo, tn, cf);
}
function doCnameBlock(dnsPacket, blf, blockInfo, cf) {
    const cn = getCname(dnsPacket.answers);
    let response = false;
    for (const n of cn){
        response = doBlock(blf, blockInfo, n, cf);
        if (response.isBlocked) break;
    }
    return response;
}
function hasBlockstamp(blockInfo) {
    return !emptyString(blockInfo.userBlocklistFlagUint);
}
function blockIfNeeded(blocker, dnsPacket, cf, blockInfo) {
    return blocker.performBlocking(blockInfo, dnsPacket, false, cf);
}
function modifyCacheResponse(cr, qid) {
    if (!cr.metaData.bodyUsed) {
        return false;
    }
    updateQueryId(cr.dnsPacket, qid);
    updateTtl(cr.dnsPacket, cr.metaData.ttlEndTime);
    return {
        dnsPacket: cr.dnsPacket,
        dnsBuffer: encode3(cr.dnsPacket)
    };
}
class CurrentRequest {
    constructor(){
        this.blockedB64Flag = "";
        this.decodedDnsPacket = this.emptyDecodedDnsPacket();
        this.httpResponse = undefined;
        this.isException = false;
        this.exceptionStack = undefined;
        this.exceptionFrom = "";
        this.isDnsParseException = false;
        this.isDnsBlock = false;
        this.isInvalidFlagBlock = false;
        this.stopProcessing = false;
        this.log = log.withTags("CurrentRequest");
    }
    emptyDecodedDnsPacket() {
        return {
            id: 0,
            questions: null
        };
    }
    initDecodedDnsPacketIfNeeded() {
        if (!this.decodedDnsPacket) {
            this.decodedDnsPacket = this.emptyDecodedDnsPacket();
        }
    }
    dnsExceptionResponse() {
        this.initDecodedDnsPacketIfNeeded();
        const qid = this.decodedDnsPacket.id;
        const questions = this.decodedDnsPacket.questions;
        const ex = {
            exceptionFrom: this.exceptionFrom,
            exceptionStack: this.exceptionStack
        };
        const servfail2 = servfail(qid, questions);
        this.httpResponse = new Response(servfail2, {
            headers: concatHeaders(this.headers(), this.additionalHeader(JSON.stringify(ex))),
            status: servfail2 ? 200 : 500
        });
    }
    customResponse(x) {
        this.httpResponse = new Response(null, {
            headers: concatHeaders(this.headers(), this.additionalHeader(JSON.stringify(x)))
        });
    }
    dnsResponse(arrayBuffer) {
        this.httpResponse = new Response(arrayBuffer, {
            headers: this.headers()
        });
    }
    dnsBlockResponse() {
        this.initDecodedDnsPacketIfNeeded();
        try {
            this.decodedDnsPacket.type = "response";
            this.decodedDnsPacket.rcode = "NOERROR";
            this.decodedDnsPacket.flags = 384;
            this.decodedDnsPacket.flag_qr = true;
            this.decodedDnsPacket.answers = [];
            this.decodedDnsPacket.answers[0] = {
            };
            this.decodedDnsPacket.answers[0].name = this.decodedDnsPacket.questions[0].name;
            this.decodedDnsPacket.answers[0].type = this.decodedDnsPacket.questions[0].type;
            this.decodedDnsPacket.answers[0].ttl = 300;
            this.decodedDnsPacket.answers[0].class = "IN";
            this.decodedDnsPacket.answers[0].data = "";
            this.decodedDnsPacket.answers[0].flush = false;
            if (this.decodedDnsPacket.questions[0].type === "A") {
                this.decodedDnsPacket.answers[0].data = "0.0.0.0";
            } else if (this.decodedDnsPacket.questions[0].type === "AAAA") {
                this.decodedDnsPacket.answers[0].data = "::";
            } else if (this.decodedDnsPacket.questions[0].type === "HTTPS" || this.decodedDnsPacket.questions[0].type === "SVCB") {
                this.decodedDnsPacket.answers[0].data = {
                };
                this.decodedDnsPacket.answers[0].data.svcPriority = 0;
                this.decodedDnsPacket.answers[0].data.targetName = ".";
                this.decodedDnsPacket.answers[0].data.svcParams = {
                };
            }
            this.decodedDnsPacket.authorities = [];
            this.httpResponse = new Response(encode3(this.decodedDnsPacket), {
                headers: this.headers()
            });
        } catch (e) {
            this.log.e(JSON.stringify(this.decodedDnsPacket));
            this.isException = true;
            this.exceptionStack = e.stack;
            this.exceptionFrom = "CurrentRequest dnsBlockResponse";
        }
    }
    headers() {
        const xNileFlags = this.isDnsBlock ? {
            "x-nile-flags": this.blockedB64Flag
        } : null;
        const xNileFlagsAllowed = this.blockedB64Flag ? {
            "x-nile-flags-allowed": this.blockedB64Flag
        } : null;
        return concatHeaders(dnsHeaders(), xNileFlags, xNileFlagsAllowed);
    }
    additionalHeader(json) {
        if (!json) return null;
        return {
            "x-nile-add": json
        };
    }
    setCorsHeaders() {
        if (this.httpResponse.ok) {
            for (const [name, value] of Object.entries(corsHeaders())){
                this.httpResponse.headers.set(name, value);
            }
        }
    }
}
const BASE64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";
const config1 = {
    useBinarySearch: true,
    debug: false,
    selectsearch: true,
    fastPos: true
};
const W = 16;
const bufferView = {
    15: Uint16Array,
    16: Uint16Array,
    6: Uint8Array
};
function chr16(ord) {
    return chrm(ord, false);
}
function chrm(ord, b64) {
    return b64 ? BASE64[ord] : String.fromCharCode(ord);
}
const ORD = {
};
for(let i = 0; i < BASE64.length; i++){
    ORD[BASE64[i]] = i;
}
function dec16(chr) {
    return decm(chr, false);
}
function decm(chr, b64) {
    return b64 ? ORD[chr] : chr.charCodeAt(0);
}
const L1 = 32 * 32;
const TxtEnc = new TextEncoder();
const TxtDec = new TextDecoder();
const DELIM = "#";
const ENC_DELIM = TxtEnc.encode(DELIM);
const periodEncVal = TxtEnc.encode(".");
function BitString(str) {
    this.init(str);
}
BitString.MaskTop = {
    16: [
        65535,
        32767,
        16383,
        8191,
        4095,
        2047,
        1023,
        511,
        255,
        127,
        63,
        31,
        15,
        7,
        3,
        1,
        0, 
    ]
};
BitString.MaskBottom = {
    16: [
        65535,
        65534,
        65532,
        65528,
        65520,
        65504,
        65472,
        65408,
        65280,
        65024,
        64512,
        63488,
        61440,
        57344,
        49152,
        32768,
        0, 
    ]
};
const BitsSetTable256 = [];
function initialize() {
    BitsSetTable256[0] = 0;
    for(let i1 = 0; i1 < 256; i1++){
        BitsSetTable256[i1] = (i1 & 1) + BitsSetTable256[Math.floor(i1 / 2)];
    }
}
function countSetBits(n) {
    return BitsSetTable256[n & 255] + BitsSetTable256[n >>> 8 & 255] + BitsSetTable256[n >>> 16 & 255] + BitsSetTable256[n >>> 24];
}
function bit0(n, p, pad) {
    const r = bit0p(n, p);
    if (r.scanned <= 0) return r.scanned;
    if (r.index > 0) return r.scanned;
    if (pad > r.scanned) return r.scanned + 1;
    else return 0;
}
function bit0p(n, p) {
    if (p === 0) return {
        index: 0,
        scanned: 0
    };
    if (n === 0 && p === 1) return {
        index: 1,
        scanned: 1
    };
    let c = 0;
    let i2 = 0;
    const m = n;
    for(c = 0; n > 0 && p > c; n = n >>> 1){
        c = c + (n < (n ^ 1)) ? 1 : 0;
        i2 += 1;
    }
    if (config1.debug) {
        console.log(String.fromCharCode(m).charCodeAt(0).toString(2), m, i2, p, c);
    }
    return {
        index: p === c ? i2 : 0,
        scanned: i2
    };
}
BitString.prototype = {
    init: function(str) {
        this.bytes = str;
        this.length = this.bytes.length * W;
    },
    getData: function() {
        return this.bytes;
    },
    encode: function(n) {
        const e = [];
        for(let i3 = 0; i3 < this.length; i3 += n){
            e.push(this.get(i3, Math.min(this.length, n)));
        }
        return e;
    },
    get: function(p, n, debug = false) {
        if (p % W + n <= W) {
            return (this.bytes[p / W | 0] & BitString.MaskTop[W][p % W]) >> W - p % W - n;
        } else {
            let result = this.bytes[p / W | 0] & BitString.MaskTop[W][p % W];
            let tmpCount = 0;
            const disp1 = this.bytes[p / W | 0];
            const disp2 = BitString.MaskTop[W][p % W];
            const res1 = result;
            const l = W - p % W;
            p += l;
            n -= l;
            while(n >= W){
                tmpCount++;
                result = result << W | this.bytes[p / W | 0];
                p += W;
                n -= W;
            }
            const res2 = result;
            if (n > 0) {
                result = result << n | this.bytes[p / W | 0] >> W - n;
            }
            if (debug) {
                console.log("disp1: " + disp1 + " disp2: " + disp2 + " loopcount: " + tmpCount + " res1: " + res1 + " res2: " + res2 + " r: " + result);
            }
            return result;
        }
    },
    count: function(p, n) {
        let count = 0;
        while(n >= 16){
            count += BitsSetTable256[this.get(p, 16)];
            p += 16;
            n -= 16;
        }
        return count + BitsSetTable256[this.get(p, n)];
    },
    pos0: function(i4, n) {
        if (n < 0) return 0;
        let step = 16;
        let index = i4;
        if (!config1.fastPos) {
            while(n > 0){
                step = n <= 16 ? n : 16;
                const bits0 = step - countSetBits(this.get(i4, step));
                if (config1.debug) {
                    console.log(i4, ":i|step:", step, "get:", this.get(i4, step), "n:", n);
                }
                n -= bits0;
                i4 += step;
                index = i4 - 1;
            }
            return index;
        }
        while(n > 0){
            const d = this.get(i4, step);
            const bits0 = step - countSetBits(d);
            if (config1.debug) {
                console.log(i4, ":i|step:", step, "get:", this.get(i4, step), "n:", n);
            }
            if (n - bits0 < 0) {
                step = Math.max(n, step / 2 | 0);
                continue;
            }
            n -= bits0;
            i4 += step;
            const diff = n === 0 ? bit0(d, 1, step) : 1;
            index = i4 - diff;
        }
        return index;
    },
    rank: function(x) {
        let rank = 0;
        for(let i5 = 0; i5 <= x; i5++){
            if (this.get(i5, 1)) {
                rank++;
            }
        }
        return rank;
    }
};
function RankDirectory(directoryData, bitData, numBits, l1Size, l2Size) {
    this.init(directoryData, bitData, numBits, l1Size, l2Size);
}
RankDirectory.prototype = {
    init: function(directoryData, trieData, numBits, l1Size, l2Size) {
        this.directory = new BitString(directoryData);
        this.data = new BitString(trieData);
        this.l1Size = l1Size;
        this.l2Size = l2Size;
        this.l1Bits = Math.ceil(Math.log2(numBits));
        this.l2Bits = Math.ceil(Math.log2(l1Size));
        this.sectionBits = (l1Size / l2Size - 1) * this.l2Bits + this.l1Bits;
        this.numBits = numBits;
    },
    getData: function() {
        return this.directory.getData();
    },
    rank: function(which, x) {
        if (config1.selectsearch) {
            let rank = -1;
            let sectionPos = 0;
            if (x >= this.l2Size) {
                sectionPos = (x / this.l2Size | 0) * this.l1Bits;
                rank = this.directory.get(sectionPos - this.l1Bits, this.l1Bits);
                x = x % this.l2Size;
            }
            const ans = x > 0 ? this.data.pos0(rank + 1, x) : rank;
            if (config1.debug) {
                console.log("ans: " + ans + " " + rank + ":r, x: " + x + " " + sectionPos + ":s " + this.l1Bits + ": l1");
            }
            return ans;
        }
        if (which === 0) {
            return x - this.rank(1, x) + 1;
        }
        let rank = 0;
        let o = x;
        let sectionPos = 0;
        if (o >= this.l1Size) {
            sectionPos = (o / this.l1Size | 0) * this.sectionBits;
            rank = this.directory.get(sectionPos - this.l1Bits, this.l1Bits);
            if (config1.debug) {
                console.log("o: " + rank + " sec: " + sectionPos);
            }
            o = o % this.l1Size;
        }
        if (o >= this.l2Size) {
            sectionPos += (o / this.l2Size | 0) * this.l2Bits;
            rank += this.directory.get(sectionPos - this.l2Bits, this.l2Bits);
            if (config1.debug) {
                console.log("o2: " + rank + " sec: " + sectionPos);
            }
        }
        rank += this.data.count(x - x % this.l2Size, x % this.l2Size + 1);
        if (config1.debug) {
            console.log("ans:", rank, "x:", o, "s:", sectionPos, "o:", x);
        }
        return rank;
    },
    select: function(which, y) {
        let high = this.numBits;
        let low = -1;
        let val = -1;
        if (config1.selectsearch) {
            return this.rank(0, y);
        }
        while(high - low > 1){
            const probe = (high + low) / 2 | 0;
            const r = this.rank(which, probe);
            if (r === y) {
                val = probe;
                high = probe;
            } else if (r < y) {
                low = probe;
            } else {
                high = probe;
            }
        }
        return val;
    }
};
function Tags(flags) {
    this.init();
    this.setupFlags(flags);
}
Tags.prototype = {
    init: function(flags) {
        this.flags = {
        };
        this.rflags = {
        };
        this.fsize = 0;
    },
    setupFlags: function(flags) {
        let i6 = 0;
        for (const f of flags){
            this.flags[f] = i6++;
        }
        this.rflags = flags;
        this.fsize = Math.ceil(Math.log2(flags.length) / 16) + 1;
    },
    flagsToTag: function(flags) {
        const header1 = flags[0];
        const tagIndices = [];
        const values = [];
        for(let i8 = 0, mask = 32768; i8 < 16; i8++){
            if (header1 << i8 === 0) break;
            if ((header1 & mask) === mask) {
                tagIndices.push(i8);
            }
            mask = mask >>> 1;
        }
        if (tagIndices.length !== flags.length - 1) {
            console.log(tagIndices, flags, "flags and header mismatch (bug in upsert?)");
            return values;
        }
        for(let i7 = 0; i7 < flags.length; i7++){
            const flag = flags[i7 + 1];
            const index = tagIndices[i7];
            for(let j = 0, mask = 32768; j < 16; j++){
                if (flag << j === 0) break;
                if ((flag & mask) === mask) {
                    const pos = index * 16 + j;
                    if (config1.debug) {
                        console.log("pos", pos, "index/tagIndices", index, tagIndices, "j/i", j, i7);
                    }
                    values.push(this.rflags[pos]);
                }
                mask = mask >>> 1;
            }
        }
        return values;
    }
};
function FrozenTrieNode(trie, index) {
    let finCached;
    let whCached;
    let comCached;
    let fcCached;
    let chCached;
    let valCached;
    let flagCached;
    this.trie = trie;
    this.index = index;
    this.final = ()=>{
        if (typeof finCached === "undefined") {
            const extrabits = this.trie.extraBit;
            const bitsize = 1;
            finCached = this.trie.data.get(this.trie.letterStart + index * this.trie.bitslen + extrabits, bitsize) === 1;
        }
        return finCached;
    };
    this.where = ()=>{
        if (typeof whCached === "undefined") {
            const extrabits = 1 + this.trie.extraBit;
            whCached = this.trie.data.get(this.trie.letterStart + index * this.trie.bitslen + extrabits, this.trie.bitslen - extrabits);
        }
        return whCached;
    };
    this.compressed = ()=>{
        const bitsize = 1;
        if (typeof comCached === "undefined") {
            comCached = this.trie.data.get(this.trie.letterStart + index * this.trie.bitslen, bitsize) === 1;
        }
        return comCached;
    };
    this.flag = ()=>{
        if (typeof flagCached === "undefined") {
            flagCached = this.compressed() && this.final();
        }
        return flagCached;
    };
    this.letter = ()=>this.where()
    ;
    this.firstChild = ()=>{
        if (!fcCached) fcCached = this.trie.directory.select(0, index + 1) - index;
        return fcCached;
    };
    this.childOfNextNode = ()=>{
        if (!chCached) {
            chCached = this.trie.directory.select(0, index + 2) - index - 1;
        }
        return chCached;
    };
    this.childCount = ()=>this.childOfNextNode() - this.firstChild()
    ;
    this.value = ()=>{
        if (typeof valCached === "undefined") {
            const value = [];
            let i9 = 0;
            let j = 0;
            if (config1.debug) {
                console.log("thisnode: index/vc/ccount ", this.index, this.letter(), this.childCount());
            }
            while(i9 < this.childCount()){
                const valueChain = this.getChild(i9);
                if (config1.debug) {
                    console.log("vc no-flag end vlet/vflag/vindex/val ", i9, valueChain.letter(), valueChain.flag(), valueChain.index, value);
                }
                if (!valueChain.flag()) {
                    break;
                }
                if (i9 % 2 === 0) {
                    value.push(valueChain.letter() << 8);
                } else {
                    value[j] = value[j] | valueChain.letter();
                    j += 1;
                }
                i9 += 1;
            }
            valCached = value;
        }
        return valCached;
    };
    if (config1.debug) {
        console.log(index + " :i, fc: " + this.firstChild() + " tl: " + this.letter() + " c: " + this.compressed() + " f: " + this.final() + " wh: " + this.where() + " flag: " + this.flag());
    }
}
FrozenTrieNode.prototype = {
    getChildCount: function() {
        return this.childCount();
    },
    getChild: function(index) {
        return this.trie.getNodeByIndex(this.firstChild() + index);
    }
};
function FrozenTrie(data, rdir, nodeCount) {
    this.init(data, rdir, nodeCount);
}
FrozenTrie.prototype = {
    init: function(trieData, rdir, nodeCount) {
        this.data = new BitString(trieData);
        this.directory = rdir;
        this.extraBit = 1;
        this.bitslen = 9 + this.extraBit;
        this.letterStart = nodeCount * 2 + 1;
    },
    getNodeByIndex: function(index) {
        return new FrozenTrieNode(this, index);
    },
    getRoot: function() {
        return this.getNodeByIndex(0);
    },
    lookup: function(word) {
        const index = word.lastIndexOf(ENC_DELIM[0]);
        if (index > 0) word = word.slice(0, index);
        const debug = config1.debug;
        let node = this.getRoot();
        let child;
        let returnValue = false;
        for(let i10 = 0; i10 < word.length; i10++){
            let isFlag = -1;
            let that;
            if (periodEncVal[0] === word[i10]) {
                if (node.final()) {
                    if (!returnValue) returnValue = new Map();
                    returnValue.set(TxtDec.decode(word.slice(0, i10).reverse()), node.value());
                }
            }
            do {
                that = node.getChild(isFlag + 1);
                if (!that.flag()) break;
                isFlag += 1;
            }while (isFlag + 1 < node.getChildCount())
            const minChild = isFlag;
            if (debug) {
                console.log("            count: " + node.getChildCount() + " i: " + i10 + " w: " + word[i10] + " nl: " + node.letter() + " flag: " + isFlag);
            }
            if (node.getChildCount() - 1 <= minChild) {
                if (debug) {
                    console.log("  no more children, remaining word: " + word.slice(i10));
                }
                return returnValue;
            }
            if (config1.useBinarySearch === false) {
                let j = isFlag;
                for(; j < node.getChildCount(); j++){
                    child = node.getChild(j);
                    if (debug) {
                        console.log("it:", j, "tl:", child.letter(), "wl:", word[i10]);
                    }
                    if (child.letter() === word[i10]) {
                        if (debug) console.log("it: " + j + " break ");
                        break;
                    }
                }
                if (j === node.getChildCount()) {
                    if (debug) console.log("j: " + j + " c: " + node.getChildCount());
                    return returnValue;
                }
            } else {
                let high = node.getChildCount();
                let low = isFlag;
                while(high - low > 1){
                    const probe = (high + low) / 2 | 0;
                    child = node.getChild(probe);
                    const prevchild = probe > isFlag ? node.getChild(probe - 1) : null;
                    if (debug) {
                        console.log("        current: " + child.letter() + " l: " + low + " h: " + high + " w: " + word[i10]);
                    }
                    if (child.compressed() || prevchild && prevchild.compressed() && !prevchild.flag()) {
                        const startchild = [];
                        const endchild = [];
                        let start = 0;
                        let end = 0;
                        startchild.push(child);
                        start += 1;
                        do {
                            const temp = node.getChild(probe - start);
                            if (!temp.compressed()) break;
                            if (temp.flag()) break;
                            startchild.push(temp);
                            start += 1;
                        }while (true)
                        if (startchild[start - 1].letter() > word[i10]) {
                            if (debug) {
                                console.log("        shrinkh start: " + startchild[start - 1].letter() + " s: " + start + " w: " + word[i10]);
                            }
                            high = probe - start + 1;
                            if (high - low <= 1) {
                                if (debug) {
                                    console.log("...h-low: " + (high - low) + " c: " + node.getChildCount(), high, low, child.letter(), word[i10], probe);
                                }
                                return returnValue;
                            }
                            continue;
                        }
                        if (child.compressed()) {
                            do {
                                end += 1;
                                const temp = node.getChild(probe + end);
                                endchild.push(temp);
                                if (!temp.compressed()) break;
                            }while (true)
                        }
                        if (startchild[start - 1].letter() < word[i10]) {
                            if (debug) {
                                console.log("        shrinkl start: " + startchild[start - 1].letter() + " s: " + start + " w: " + word[i10]);
                            }
                            low = probe + end;
                            if (high - low <= 1) {
                                if (debug) {
                                    console.log("...h-low: " + (high - low) + " c: " + node.getChildCount(), high, low, child.letter(), word[i10], probe);
                                }
                                return returnValue;
                            }
                            continue;
                        }
                        const nodes = startchild.reverse().concat(endchild);
                        const comp = nodes.map((n)=>n.letter()
                        );
                        const w = word.slice(i10, i10 + comp.length);
                        if (debug) {
                            console.log("i", probe, "s", comp, "w", w, "c", child.letter());
                        }
                        if (w.length < comp.length) return returnValue;
                        for(let i11 = 0; i11 < comp.length; i11++){
                            if (w[i11] !== comp[i11]) return returnValue;
                        }
                        if (debug) console.log("it: " + probe + " break ");
                        child = nodes[nodes.length - 1];
                        i10 += comp.length - 1;
                        break;
                    } else {
                        if (child.letter() === word[i10]) {
                            break;
                        } else if (word[i10] > child.letter()) {
                            low = probe;
                        } else {
                            high = probe;
                        }
                    }
                    if (high - low <= 1) {
                        if (debug) {
                            console.log("h-low: " + (high - low) + " c: " + node.getChildCount(), high, low, child.letter(), word[i10], probe);
                        }
                        return returnValue;
                    }
                }
            }
            if (debug) console.log("        next: " + child.letter());
            node = child;
        }
        if (node.final()) {
            if (!returnValue) returnValue = new Map();
            returnValue.set(TxtDec.decode(word.reverse()), node.value());
        }
        return returnValue;
    }
};
function customTagToFlag(fl, blocklistFileTag) {
    let res = chr16(0);
    for (const flag of fl){
        const val = blocklistFileTag[flag].value;
        const header = 0;
        const index = val / 16 | 0;
        const pos = val % 16;
        let h = 0;
        h = dec16(res[header]);
        const dataIndex = countSetBits(h & BitString.MaskBottom[16][16 - index]) + 1;
        let n = (h >>> 15 - index & 1) !== 1 ? 0 : dec16(res[dataIndex]);
        const upsertData = n !== 0;
        h |= 1 << 15 - index;
        n |= 1 << 15 - pos;
        res = chr16(h) + res.slice(1, dataIndex) + chr16(n) + res.slice(upsertData ? dataIndex + 1 : dataIndex);
    }
    return res;
}
function createBlocklistFilter(tdbuf, rdbuf, blocklistFileTag, blocklistBasicConfig) {
    initialize();
    const tag = {
    };
    const fl = [];
    for(const fileuname in blocklistFileTag){
        if (!blocklistFileTag.hasOwnProperty(fileuname)) continue;
        fl[blocklistFileTag[fileuname].value] = fileuname;
        const v = DELIM + blocklistFileTag[fileuname].uname;
        tag[fileuname] = v.split("").reverse().join("");
    }
    const tags = new Tags(fl);
    const tdv = new bufferView[16](tdbuf);
    const rdv = new bufferView[16](rdbuf);
    const nc = blocklistBasicConfig.nodecount;
    const numbits = blocklistBasicConfig.nodecount * 2 + 1;
    const rd = new RankDirectory(rdv, tdv, numbits, L1, 32);
    const frozentrie = new FrozenTrie(tdv, rd, nc);
    return {
        t: tags,
        ft: frozentrie
    };
}
const minlives = 1;
const maxlives = 2 ** 14;
const mincap = 2 ** 5;
const maxcap = 2 ** 32;
const minslots = 2;
class Clock {
    constructor(cap, slotsperhand = 256, maxlife = 16){
        cap = this.bound(cap, mincap, maxcap);
        this.capacity = 2 ** Math.round(Math.log2(cap));
        this.rb = new Array(this.capacity);
        this.rb.fill(null);
        this.store = new Map();
        this.maxcount = this.bound(maxlife, minlives, maxlives);
        this.totalhands = Math.max(minslots, Math.round(this.capacity / slotsperhand));
        this.hands = new Array(this.totalhands);
        for(let i25 = 0; i25 < this.totalhands; i25++)this.hands[i25] = i25;
    }
    next(i26) {
        const n = i26 + this.totalhands;
        return (this.capacity + n) % this.capacity;
    }
    cur(i27) {
        return (this.capacity + i27) % this.capacity;
    }
    prev(i28) {
        const p = i28 - this.totalhands;
        return (this.capacity + p) % this.capacity;
    }
    bound(i29, min, max) {
        i29 = i29 < min ? min : i29;
        i29 = i29 > max ? max - 1 : i29;
        return i29;
    }
    head(n) {
        n = this.bound(n, 0, this.totalhands);
        const h = this.hands[n];
        return this.cur(h);
    }
    incrHead(n) {
        n = this.bound(n, 0, this.totalhands);
        this.hands[n] = this.next(this.hands[n]);
        return this.hands[n];
    }
    decrHead(n) {
        n = this.bound(n, 0, this.totalhands);
        this.hands[n] = this.prev(this.hands[n]);
        return this.hands[n];
    }
    get size() {
        return this.store.size;
    }
    evict(n, c) {
        logd("evict start, head/num/size", this.head(n), n, this.size);
        const start = this.head(n);
        let h = start;
        do {
            const entry = this.rb[h];
            if (entry === null) return true;
            entry.count -= c;
            if (entry.count <= 0) {
                logd("evict", h, entry);
                this.store.delete(entry.key);
                this.rb[h] = null;
                return true;
            }
            h = this.incrHead(n);
        }while (h !== start)
        return false;
    }
    put(k, v, c = 1) {
        const cached = this.store.get(k);
        if (cached) {
            cached.value = v;
            const at = this.rb[cached.pos];
            at.count = Math.min(at.count + c, this.maxcount);
            return true;
        }
        const num = this.rolldice;
        this.evict(num, c);
        const h = this.head(num);
        const hasSlot = this.rb[h] === null;
        if (!hasSlot) return false;
        const ringv = {
            key: k,
            count: Math.min(c, this.maxcount)
        };
        const storev = {
            value: v,
            pos: h
        };
        this.rb[h] = ringv;
        this.store.set(k, storev);
        this.incrHead(num);
        return true;
    }
    val(k, c = 1) {
        const r = this.store.get(k);
        if (!r) return null;
        const at = this.rb[r.pos];
        at.count = Math.min(at.count + c, this.maxcount);
        return r.value;
    }
    get rolldice() {
        const max = this.totalhands;
        return Math.floor(Math.random() * (max - 0)) + 0;
    }
}
function logd() {
}
class LfuCache {
    constructor(id, capacity){
        this.id = id;
        this.cache = new Clock(capacity);
    }
    Get(key) {
        let val = false;
        try {
            val = this.cache.val(key) || false;
        } catch (e) {
            console.log("Error: " + this.id + " -> Get");
            console.log(e.stack);
        }
        return val;
    }
    Put(key, val) {
        try {
            this.cache.put(key, val);
        } catch (e) {
            console.log("Error: " + this.id + " -> Put");
            console.log(e.stack);
        }
    }
}
class UserCache {
    constructor(size){
        const name = "UserCache";
        this.localCache = new LfuCache(name, size);
        this.log = log.withTags(name);
    }
    get(key) {
        return this.localCache.Get(key);
    }
    put(key, data) {
        try {
            this.localCache.Put(key, data);
        } catch (e) {
            this.log.e("put", e);
        }
    }
}
class DomainNameCache {
    constructor(size){
        const name = "DomainNameCache";
        this.localCache = new LfuCache(name, size);
        this.log = log.withTags(name);
    }
    get(key) {
        return this.localCache.Get(key);
    }
    put(key, data) {
        try {
            this.localCache.Put(key, data);
        } catch (e) {
            this.log.e("put", e);
        }
    }
}
class CacheApi {
    constructor(){
        this.noop = !isWorkers();
        if (this.noop) {
            log.w("not workers, no-op http-cache-api");
        }
    }
    async get(url) {
        if (this.noop) return false;
        if (emptyString(url)) return false;
        return await caches.default.match(url);
    }
    put(url, response) {
        if (this.noop) return false;
        if (emptyString(url) || emptyObj(response)) return false;
        return caches.default.put(url, response);
    }
}
class DnsCache {
    constructor(size){
        this.localCache = new LfuCache("DnsCache", size);
        this.cacheApi = new CacheApi();
        this.log = log.withTags("DnsCache");
    }
    async get(key, url) {
        let entry = this.fromLocalCache(key);
        if (entry) {
            return entry;
        }
        if (!url || !isWorkers()) return false;
        const hKey = makeHttpCacheApiKey(key, url);
        entry = await this.fromHttpCacheApi(hKey);
        this.putLocalCache(key, entry);
        return entry;
    }
    put(key, data, url, buf, event) {
        if (!key) return;
        try {
            this.putLocalCache(key, data);
            if (url && isWorkers() && event && event.waitUntil) {
                this.log.d("put data httpCache", data);
                event.waitUntil(this.putCacheApi(key, url, buf, data.metaData));
            }
        } catch (e) {
            this.log.e("put", e);
        }
    }
    putLocalCache(key, data) {
        if (!key || !data) return;
        try {
            this.localCache.Put(key, data);
        } catch (e) {
            this.log.e("putLocalCache", e);
        }
    }
    fromLocalCache(key) {
        if (!key) return false;
        const v = this.localCache.Get(key);
        return this.isValid(v) ? v : false;
    }
    async fromHttpCacheApi(key) {
        if (!key) return false;
        const cres = await this.cacheApi.get(key);
        return this.parseHttpCacheApiResponse(cres);
    }
    async putCacheApi(key, url, buf, metaData) {
        const k = makeHttpCacheApiKey(key, url);
        const v = makeHttpCacheApiValue(buf, metaData);
        if (!k || !v) return;
        this.cacheApi.put(k, v);
    }
    isValid(v) {
        if (!v) return false;
        const hasMd = this.hasMetadata(v.metaData) && !this.hasAnswer(v.metaData);
        if (hasMd) return true;
        const hasAns = this.isAnswerFresh(v.metaData);
        return hasAns;
    }
    isAnswerFresh(m) {
        return this.hasAnswer(m) && m.ttlEndTime > 0 && Date.now() <= m.ttlEndTime;
    }
    hasAnswer(m) {
        return this.hasMetadata(m) && m.bodyUsed;
    }
    hasMetadata(m) {
        return !!m;
    }
    async parseHttpCacheApiResponse(response) {
        if (!response) return false;
        const metaData = JSON.parse(response.headers.get("x-rethink-metadata"));
        this.log.d("httpCache response metadata", metaData);
        if (!this.isMetadataFresh(metaData)) {
            return false;
        }
        const p = metaData.bodyUsed ? decode3(await response.arrayBuffer()) : {
        };
        const m = metaData;
        return {
            dnsPacket: p,
            metaData: m
        };
    }
}
function makeHttpCacheApiValue(buf, metaData) {
    const headers = {
        headers: concatHeaders({
            "x-rethink-metadata": JSON.stringify(metaData),
            "Cache-Control": "max-age=604800"
        }, contentLengthHeader(buf))
    };
    return new Response(buf, headers);
}
function makeHttpCacheApiKey(key, url) {
    return new URL(new URL(url).origin + "/" + env.latestTimestamp + "/" + key);
}
const ALPHA32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function readChar(chr) {
    chr = chr.toUpperCase();
    const idx = ALPHA32.indexOf(chr);
    if (idx === -1) {
        throw new Error("invalid b32 character: " + chr);
    }
    return idx;
}
function rbase32(input) {
    input = input.replace(/=+$/, "");
    const length = input.length;
    let bits = 0;
    let value = 0;
    let index = 0;
    let output = new Uint8Array(length * 5 / 8 | 0);
    for(var i30 = 0; i30 < length; i30++){
        value = value << 5 | readChar(input[i30]);
        bits += 5;
        if (bits >= 8) {
            output[index++] = value >>> bits - 8 & 255;
            bits -= 8;
        }
    }
    return output;
}
class BlocklistFilter {
    constructor(){
        this.t = null;
        this.ft = null;
        this.blocklistBasicConfig = null;
        this.blocklistFileTag = null;
        this.domainNameCache = null;
        this.wildCardUint = new Uint16Array([
            64544,
            18431,
            8191,
            65535,
            64640,
            1,
            128,
            16320, 
        ]);
    }
    loadFilter(t, ft, blocklistBasicConfig, blocklistFileTag) {
        this.t = t;
        this.ft = ft;
        this.blocklistBasicConfig = blocklistBasicConfig;
        this.blocklistFileTag = blocklistFileTag;
        this.domainNameCache = new DomainNameCache(20000);
    }
    getDomainInfo(domainName) {
        domainName = domainName.trim().toLowerCase();
        let domainNameInfo = this.domainNameCache.get(domainName);
        if (!domainNameInfo) {
            domainNameInfo = {
            };
            domainNameInfo.searchResult = this.hadDomainName(domainName);
            this.domainNameCache.put(domainName, domainNameInfo);
        }
        return domainNameInfo;
    }
    hadDomainName(domainName) {
        const enc = new TextEncoder();
        return this.ft.lookup(enc.encode(domainName).reverse());
    }
    getTag(uintFlag) {
        return this.t.flagsToTag(uintFlag);
    }
    unstamp(flag) {
        return toUint(flag);
    }
    customTagToFlag(tagList) {
        return customTagToFlag(tagList, this.blocklistFileTag);
    }
    getB64FlagFromTag(tagList, flagVersion) {
        if (flagVersion === "0") {
            return encodeURIComponent(Buffer1.from(customTagToFlag(tagList, this.blocklistFileTag)).toString("base64"));
        } else if (flagVersion === "1") {
            return "1:" + encodeURI(btoa(encodeToBinary(customTagToFlag(tagList, this.blocklistFileTag))).replace(/\//g, "_").replace(/\+/g, "-"));
        }
    }
}
function encodeToBinary(s) {
    const codeUnits = new Uint16Array(s.length);
    for(let i31 = 0; i31 < codeUnits.length; i31++){
        codeUnits[i31] = s.charCodeAt(i31);
    }
    return String.fromCharCode(...new Uint8Array(codeUnits.buffer));
}
const b64delim = ":";
const b32delim = "+";
function isB32(s) {
    return s.indexOf(b32delim) > 0;
}
function version(s) {
    if (s && s.length > 1) return s[0];
    else return "0";
}
function toUint(flag) {
    try {
        const response = {
        };
        response.userBlocklistFlagUint = "";
        response.flagVersion = "0";
        flag = flag ? flag.trim() : "";
        if (flag.length <= 0) {
            return response;
        }
        const isFlagB32 = isB32(flag);
        const s = flag.split(isFlagB32 ? b32delim : b64delim);
        let convertor = (x)=>""
        ;
        let f = "";
        const v = version(s);
        if (v === "0") {
            convertor = Base64ToUint;
            f = s[0];
        } else if (v === "1") {
            convertor = isFlagB32 ? Base32ToUintV1 : Base64ToUintV1;
            f = s[1];
        } else {
            throw new Error("unknown blocklist stamp version in " + s);
        }
        response.flagVersion = v;
        response.userBlocklistFlagUint = convertor(f) || "";
        return response;
    } catch (e) {
        throw e;
    }
}
function Base64ToUint(b64Flag) {
    const buff = Buffer1.from(decodeURIComponent(b64Flag), "base64");
    const str = buff.toString("utf-8");
    const uint = [];
    for(let i32 = 0; i32 < str.length; i32++){
        uint[i32] = str.charCodeAt(i32);
    }
    return uint;
}
function Base64ToUintV1(b64Flag) {
    let str = decodeURI(b64Flag);
    str = decodeFromBinary(atob(str.replace(/_/g, "/").replace(/-/g, "+")));
    const uint = [];
    for(let i33 = 0; i33 < str.length; i33++){
        uint[i33] = str.charCodeAt(i33);
    }
    return uint;
}
function Base32ToUintV1(flag) {
    let str = decodeURI(flag);
    str = decodeFromBinaryArray(rbase32(str));
    const uint = [];
    for(let i34 = 0; i34 < str.length; i34++){
        uint[i34] = str.charCodeAt(i34);
    }
    return uint;
}
function decodeFromBinary(b, u8) {
    if (u8) return String.fromCharCode(...new Uint16Array(b.buffer));
    const bytes = new Uint8Array(b.length);
    for(let i35 = 0; i35 < bytes.length; i35++){
        bytes[i35] = b.charCodeAt(i35);
    }
    return String.fromCharCode(...new Uint16Array(bytes.buffer));
}
function decodeFromBinaryArray(b) {
    return decodeFromBinary(b, true);
}
class BlocklistWrapper {
    constructor(){
        this.blocklistFilter = new BlocklistFilter();
        this.startTime;
        this.td = null;
        this.rd = null;
        this.ft = null;
        this.isBlocklistUnderConstruction = false;
        this.exceptionFrom = "";
        this.exceptionStack = "";
        this.log = log.withTags("BlocklistWrapper");
    }
    async RethinkModule(param) {
        const response = {
        };
        response.isException = false;
        response.exceptionStack = "";
        response.exceptionFrom = "";
        response.data = {
        };
        if (this.isBlocklistFilterSetup()) {
            response.data.blocklistFilter = this.blocklistFilter;
            return response;
        }
        try {
            const now = Date.now();
            if (this.isBlocklistUnderConstruction === false) {
                return await this.initBlocklistConstruction(param.rxid, now, param.blocklistUrl, param.latestTimestamp, param.tdNodecount, param.tdParts);
            } else if (now - this.startTime > param.workerTimeout * 2) {
                return await this.initBlocklistConstruction(param.rxid, now, param.blocklistUrl, param.latestTimestamp, param.tdNodecount, param.tdParts);
            } else {
                let totalWaitms = 0;
                const waitms = 50;
                while(totalWaitms < param.fetchTimeout){
                    if (this.blocklistFilter.t !== null) {
                        response.data.blocklistFilter = this.blocklistFilter;
                        return response;
                    }
                    await sleep(50);
                    totalWaitms += waitms;
                }
                response.isException = true;
                response.exceptionStack = this.exceptionStack || "blocklist filter not ready";
                response.exceptionFrom = this.exceptionFrom || "blocklistWrapper.js RethinkModule";
            }
        } catch (e) {
            response.isException = true;
            response.exceptionStack = e.stack;
            response.exceptionFrom = "blocklistWrapper.js RethinkModule";
            log.e(param.rxid, "RethinkModule", e);
        }
        return response;
    }
    isBlocklistFilterSetup() {
        return this.blocklistFilter && this.blocklistFilter.t;
    }
    initBlocklistFilterConstruction(td, rd, ft, config2) {
        this.isBlocklistUnderConstruction = true;
        const filter = createBlocklistFilter(td, rd, ft, config2);
        this.blocklistFilter.loadFilter(filter.t, filter.ft, filter.blocklistBasicConfig, filter.blocklistFileTag);
        this.isBlocklistUnderConstruction = false;
    }
    async initBlocklistConstruction(rxid, when, blocklistUrl, latestTimestamp, tdNodecount, tdParts) {
        this.isBlocklistUnderConstruction = true;
        this.startTime = when;
        const response = {
        };
        response.isException = false;
        response.exceptionStack = "";
        response.exceptionFrom = "";
        response.data = {
        };
        try {
            const bl = await this.downloadBuildBlocklist(rxid, blocklistUrl, latestTimestamp, tdNodecount, tdParts);
            this.blocklistFilter.loadFilter(bl.t, bl.ft, bl.blocklistBasicConfig, bl.blocklistFileTag);
            log.d(rxid, "loaded blocklist-filter");
            response.data.blocklistFilter = this.blocklistFilter;
        } catch (e) {
            response.isException = true;
            response.exceptionStack = e.stack;
            response.exceptionFrom = "blocklistWrapper.js initBlocklistConstruction";
            this.exceptionFrom = response.exceptionFrom;
            this.exceptionStack = response.exceptionStack;
            log.e(rxid, e);
        }
        this.isBlocklistUnderConstruction = false;
        return response;
    }
    async downloadBuildBlocklist(rxid, blocklistUrl, latestTimestamp, tdNodecount, tdParts) {
        !tdNodecount && log.e(rxid, "tdNodecount zero or missing!");
        const resp = {
        };
        const baseurl = blocklistUrl + latestTimestamp;
        const blocklistBasicConfig = {
            nodecount: tdNodecount || -1,
            tdparts: tdParts || -1
        };
        const buf0 = fileFetch(baseurl + "/filetag.json", "json");
        const buf1 = makeTd(baseurl, blocklistBasicConfig.tdparts);
        const buf2 = fileFetch(baseurl + "/rd.txt", "buffer");
        const downloads = await Promise.all([
            buf0,
            buf1,
            buf2
        ]);
        log.d(rxid, "call createBlocklistFilter", blocklistBasicConfig);
        this.td = downloads[1];
        this.rd = downloads[2];
        this.ft = downloads[0];
        const trie = createBlocklistFilter(this.td, this.rd, this.ft, blocklistBasicConfig);
        resp.t = trie.t;
        resp.ft = trie.ft;
        resp.blocklistBasicConfig = blocklistBasicConfig;
        resp.blocklistFileTag = this.ft;
        return resp;
    }
}
async function fileFetch(url, typ) {
    if (typ !== "buffer" && typ !== "json") {
        throw new Error("Unknown conversion type at fileFetch");
    }
    log.d("Start Downloading : " + url);
    const res = await fetch(url, {
        cf: {
            cacheTtl: 1209600
        }
    });
    if (res.status === 200) {
        if (typ === "buffer") {
            return await res.arrayBuffer();
        } else if (typ === "json") {
            return await res.json();
        }
    } else {
        log.e(url, res);
        throw new Error(JSON.stringify([
            url,
            res,
            "fileFetch fail"
        ]));
    }
}
const sleep = (ms)=>{
    return new Promise((resolve)=>{
        setTimeout(resolve, ms);
    });
};
async function makeTd(baseurl, n) {
    log.d("Make Td Starts : Tdparts -> " + n);
    if (n <= -1) {
        return fileFetch(baseurl + "/td.txt", "buffer");
    }
    const tdpromises = [];
    for(let i36 = 0; i36 <= n; i36++){
        const f = baseurl + "/td" + i36.toLocaleString("en-US", {
            minimumIntegerDigits: 2,
            useGrouping: false
        }) + ".txt";
        tdpromises.push(fileFetch(f, "buffer"));
    }
    const tds = await Promise.all(tdpromises);
    log.d("tds downloaded");
    return new Promise((resolve, reject)=>{
        resolve(concat(tds));
    });
}
function concat(arraybuffers) {
    const sz = arraybuffers.reduce((sum, a)=>sum + a.byteLength
    , 0);
    const buf = new ArrayBuffer(sz);
    const cat = new Uint8Array(buf);
    let offset = 0;
    for (const a1 of arraybuffers){
        const v = new Uint8Array(a1);
        cat.set(v, offset);
        offset += a1.byteLength;
    }
    return buf;
}
class CommandControl {
    constructor(){
        this.latestTimestamp = "";
    }
    async RethinkModule(param) {
        this.latestTimestamp = param.latestTimestamp;
        let response = {
        };
        response.isException = false;
        response.exceptionStack = "";
        response.exceptionFrom = "";
        response.data = {
        };
        response.data.stopProcessing = false;
        if (param.request.method === "GET") {
            response = this.commandOperation(param.request.url, param.blocklistFilter, param.isDnsMsg);
        } else if (param.request.method !== "POST") {
            response.data.httpResponse = new Response(null, {
                status: 405,
                statusText: "Method Not Allowed"
            });
        }
        return response;
    }
    isConfigureCmd(s) {
        return s === "configure" || s === "config";
    }
    isDohGetRequest(queryString) {
        return queryString && queryString.has("dns");
    }
    userFlag(url, isDnsCmd = false) {
        const emptyFlag = "";
        const p = url.pathname.split("/");
        const d = url.host.split(".");
        if (this.isConfigureCmd(p[1])) {
            return p.length >= 3 ? p[2] : emptyFlag;
        }
        if (isDnsCmd) return emptyFlag;
        if (p[1]) return p[1];
        return d.length > 1 ? d[0] : emptyFlag;
    }
    commandOperation(url, blocklistFilter, isDnsMsg1) {
        const response = {
            isException: false,
            exceptionStack: "",
            exceptionFrom: "",
            data: {
                httpResponse: null,
                stopProcessing: true
            }
        };
        try {
            const reqUrl = new URL(url);
            const queryString = reqUrl.searchParams;
            const pathSplit = reqUrl.pathname.split("/");
            const isDnsCmd = isDnsMsg1 || this.isDohGetRequest(queryString);
            if (isDnsCmd) {
                response.data.stopProcessing = false;
                return response;
            }
            const command = pathSplit[1];
            const b64UserFlag = this.userFlag(reqUrl, isDnsCmd);
            if (command === "listtob64") {
                response.data.httpResponse = listToB64(queryString, blocklistFilter);
            } else if (command === "b64tolist") {
                response.data.httpResponse = b64ToList(queryString, blocklistFilter);
            } else if (command === "dntolist") {
                response.data.httpResponse = domainNameToList(queryString, blocklistFilter, this.latestTimestamp);
            } else if (command === "dntouint") {
                response.data.httpResponse = domainNameToUint(queryString, blocklistFilter);
            } else if (command === "config" || command === "configure" || !isDnsCmd) {
                response.data.httpResponse = configRedirect(b64UserFlag, reqUrl.origin, this.latestTimestamp, !isDnsCmd);
            } else {
                response.data.httpResponse = new Response(null, {
                    status: 400,
                    statusText: "Bad Request"
                });
            }
        } catch (e) {
            response.isException = true;
            response.exceptionStack = e.stack;
            response.exceptionFrom = "CommandControl commandOperation";
            response.data.httpResponse = jsonResponse(response.exceptionStack);
        }
        return response;
    }
}
function isRethinkDns(hostname) {
    return hostname.indexOf("rethinkdns") >= 0 || hostname.indexOf("bravedns") >= 0;
}
function configRedirect(userFlag, origin, timestamp, highlight) {
    const u = "https://rethinkdns.com/configure";
    let q = "?tstamp=" + timestamp;
    q += !isRethinkDns(origin) ? "&v=ext&u=" + origin : "";
    q += highlight ? "&s=added" : "";
    q += userFlag ? "#" + userFlag : "";
    return Response.redirect(u + q, 302);
}
function domainNameToList(queryString, blocklistFilter, latestTimestamp) {
    const domainName = queryString.get("dn") || "";
    const returndata = {
    };
    returndata.domainName = domainName;
    returndata.version = latestTimestamp;
    returndata.list = {
    };
    const searchResult = blocklistFilter.hadDomainName(domainName);
    if (searchResult) {
        let list;
        let listDetail = {
        };
        for (const entry of searchResult){
            list = blocklistFilter.getTag(entry[1]);
            listDetail = {
            };
            for (const listValue of list){
                listDetail[listValue] = blocklistFilter.blocklistFileTag[listValue];
            }
            returndata.list[entry[0]] = listDetail;
        }
    } else {
        returndata.list = false;
    }
    return jsonResponse(returndata);
}
function domainNameToUint(queryString, blocklistFilter) {
    const domainName = queryString.get("dn") || "";
    const returndata = {
    };
    returndata.domainName = domainName;
    returndata.list = {
    };
    const searchResult = blocklistFilter.hadDomainName(domainName);
    if (searchResult) {
        for (const entry of searchResult){
            returndata.list[entry[0]] = entry[1];
        }
    } else {
        returndata.list = false;
    }
    return jsonResponse(returndata);
}
function listToB64(queryString, blocklistFilter) {
    const list = queryString.get("list") || [];
    const flagVersion = queryString.get("flagversion") || "0";
    const returndata = {
    };
    returndata.command = "List To B64String";
    returndata.inputList = list;
    returndata.flagVersion = flagVersion;
    returndata.b64String = blocklistFilter.getB64FlagFromTag(list.split(","), flagVersion);
    return jsonResponse(returndata);
}
function b64ToList(queryString, blocklistFilter) {
    const b64 = queryString.get("b64") || "";
    const returndata = {
    };
    returndata.command = "Base64 To List";
    returndata.inputB64 = b64;
    const response = blocklistFilter.unstamp(b64);
    if (response.userBlocklistFlagUint.length > 0) {
        returndata.list = blocklistFilter.getTag(response.userBlocklistFlagUint);
        returndata.listDetail = {
        };
        for (const listValue of returndata.list){
            returndata.listDetail[listValue] = blocklistFilter.blocklistFileTag[listValue];
        }
    } else {
        returndata.list = "Invalid B64 String";
    }
    return jsonResponse(returndata);
}
function jsonResponse(obj) {
    return new Response(JSON.stringify(obj), {
        headers: jsonHeaders()
    });
}
class UserOperation {
    constructor(){
        this.userConfigCache = new UserCache(1000);
        this.blocklistFilter = new BlocklistFilter();
        this.log = log.withTags("UserOp");
    }
    async RethinkModule(param) {
        return this.loadUser(param);
    }
    loadUser(param) {
        const response = {
        };
        response.isException = false;
        response.exceptionStack = "";
        response.exceptionFrom = "";
        response.data = {
        };
        response.data.userBlocklistInfo = {
        };
        response.data.userBlocklistInfo.dnsResolverUrl = "";
        if (!param.isDnsMsg) {
            return response;
        }
        try {
            const userBlocklistInfo = {
            };
            let blocklistFlag = getBlocklistFlag(param.request.url);
            let currentUser = this.userConfigCache.get(blocklistFlag);
            if (emptyObj(currentUser)) {
                currentUser = {
                };
                currentUser.userBlocklistFlagUint = "";
                currentUser.flagVersion = 0;
                currentUser.userServiceListUint = false;
                const response = this.blocklistFilter.unstamp(blocklistFlag);
                currentUser.userBlocklistFlagUint = response.userBlocklistFlagUint;
                currentUser.flagVersion = response.flagVersion;
                if (!emptyString(currentUser.userBlocklistFlagUint)) {
                    currentUser.userServiceListUint = flagIntersection(currentUser.userBlocklistFlagUint, this.blocklistFilter.wildCardUint);
                } else {
                    blocklistFlag = "";
                }
                userBlocklistInfo.from = "Generated";
                this.userConfigCache.put(blocklistFlag, currentUser);
            } else {
                userBlocklistInfo.from = "Cache";
            }
            userBlocklistInfo.userBlocklistFlagUint = currentUser.userBlocklistFlagUint;
            userBlocklistInfo.flagVersion = currentUser.flagVersion;
            userBlocklistInfo.userServiceListUint = currentUser.userServiceListUint;
            response.data.userBlocklistInfo = userBlocklistInfo;
            response.data.dnsResolverUrl = param.dnsResolverUrl;
        } catch (e) {
            response.isException = true;
            response.exceptionStack = e.stack;
            response.exceptionFrom = "UserOperation loadUser";
            this.log.e(param.rxid, "loadUser", e);
        }
        return response;
    }
}
function getBlocklistFlag(url) {
    let blocklistFlag = "";
    const reqUrl = new URL(url);
    const tmpsplit = reqUrl.pathname.split("/");
    if (tmpsplit.length > 1) {
        if (tmpsplit[1].toLowerCase() === "dns-query") {
            blocklistFlag = tmpsplit[2] || "";
        } else {
            blocklistFlag = tmpsplit[1] || "";
        }
    }
    return blocklistFlag;
}
const services = {
};
((main)=>{
    sub("ready", systemReady);
})();
async function systemReady() {
    if (services.ready) return;
    log.i("plugin.js: systemReady");
    services.blocklistWrapper = new BlocklistWrapper();
    services.commandControl = new CommandControl();
    services.userOperation = new UserOperation();
    services.dnsQuestionBlock = new DNSQuestionBlock();
    services.dnsResolver = new DNSResolver();
    services.dnsResponseBlock = new DNSResponseBlock();
    services.dnsCacheHandler = new DNSCacheResponse();
    services.dnsCache = new DnsCache(cacheSize());
    if (isNode()) {
        const blocklists = await import("./node/blocklists.js");
        await blocklists.setup(services.blocklistWrapper);
    }
    pub("go");
    services.ready = true;
}
class RethinkPlugin {
    constructor(event){
        this.parameter = new Map(envManager.getMap());
        const rxid = rxidFromHeader(event.request.headers) || xid();
        this.registerParameter("rxid", "[rxid." + rxid + "]");
        this.registerParameter("event", event);
        this.registerParameter("request", event.request);
        this.registerParameter("dnsQuestionBlock", services.dnsQuestionBlock);
        this.registerParameter("dnsResponseBlock", services.dnsResponseBlock);
        this.registerParameter("dnsCache", services.dnsCache);
        this.log = log.withTags("RethinkPlugin");
        this.plugin = [];
        this.registerPlugin("userOperation", services.userOperation, [
            "dnsResolverUrl",
            "request",
            "isDnsMsg"
        ], this.userOperationCallBack, false);
        this.registerPlugin("AggressiveCaching", services.dnsCacheHandler, [
            "rxid",
            "userBlocklistInfo",
            "request",
            "requestDecodedDnsPacket",
            "isDnsMsg",
            "dnsCache",
            "dnsQuestionBlock",
            "dnsResponseBlock", 
        ], this.dnsAggCacheCallBack, false);
        this.registerPlugin("blocklistFilter", services.blocklistWrapper, [
            "rxid",
            "blocklistUrl",
            "latestTimestamp",
            "workerTimeout",
            "tdParts",
            "tdNodecount",
            "fetchTimeout", 
        ], this.blocklistFilterCallBack, false);
        this.registerPlugin("commandControl", services.commandControl, [
            "rxid",
            "request",
            "blocklistFilter",
            "latestTimestamp",
            "isDnsMsg"
        ], this.commandControlCallBack, false);
        this.registerPlugin("dnsQuestionBlock", services.dnsQuestionBlock, [
            "rxid",
            "requestDecodedDnsPacket",
            "blocklistFilter",
            "userBlocklistInfo",
            "event",
            "request",
            "dnsCache", 
        ], this.dnsQuestionBlockCallBack, false);
        this.registerPlugin("dnsResolver", services.dnsResolver, [
            "rxid",
            "requestBodyBuffer",
            "request",
            "dnsResolverUrl",
            "requestDecodedDnsPacket",
            "event",
            "blocklistFilter",
            "dnsCache", 
        ], this.dnsResolverCallBack, false);
        this.registerPlugin("DNSResponseBlock", services.dnsResponseBlock, [
            "rxid",
            "userBlocklistInfo",
            "blocklistFilter",
            "responseDecodedDnsPacket",
            "responseBodyBuffer",
            "event",
            "request",
            "dnsCache", 
        ], this.dnsResponseBlockCallBack, false);
    }
    registerParameter(k, v) {
        this.parameter.set(k, v);
    }
    registerPlugin(pluginName, module, parameter, callBack, continueOnStopProcess) {
        this.plugin.push({
            name: pluginName,
            module: module,
            param: parameter,
            callBack: callBack,
            continueOnStopProcess: continueOnStopProcess
        });
    }
    async executePlugin(req) {
        await setRequest(this.parameter, req);
        const rxid = this.parameter.get("rxid");
        const t = this.log.startTime("exec-plugin-" + rxid);
        for (const p of this.plugin){
            if (req.stopProcessing && !p.continueOnStopProcess) {
                continue;
            }
            this.log.lapTime(t, rxid, p.name, "send-req");
            const res = await p.module.RethinkModule(generateParam(this.parameter, p.param));
            this.log.lapTime(t, rxid, p.name, "got-res");
            if (p.callBack) {
                await p.callBack.call(this, res, req);
            }
            this.log.lapTime(t, rxid, p.name, "post-callback");
        }
        this.log.endTime(t);
    }
    blocklistFilterCallBack(response, currentRequest) {
        const rxid = this.parameter.get("rxid");
        this.log.d(rxid, "In blocklistFilterCallBack");
        if (response.isException) {
            loadException(response, currentRequest);
        } else {
            this.registerParameter("blocklistFilter", response.data.blocklistFilter);
        }
    }
    async commandControlCallBack(response, currentRequest) {
        const rxid = this.parameter.get("rxid");
        this.log.d(rxid, "In commandControlCallBack");
        if (response.data.stopProcessing) {
            currentRequest.httpResponse = response.data.httpResponse;
            currentRequest.stopProcessing = true;
        }
    }
    async userOperationCallBack(response, currentRequest) {
        const rxid = this.parameter.get("rxid");
        this.log.d(rxid, "In userOperationCallBack");
        if (response.isException) {
            loadException(response, currentRequest);
        } else {
            this.registerParameter("userBlocklistInfo", response.data.userBlocklistInfo);
            this.registerParameter("dnsResolverUrl", response.data.dnsResolverUrl);
        }
    }
    dnsAggCacheCallBack(response, currentRequest) {
        const rxid = this.parameter.get("rxid");
        this.log.d(rxid, "In dnsAggCacheCallBack");
        if (response.isException) {
            loadException(response, currentRequest);
        } else if (response.data && response.data.isBlocked) {
            currentRequest.isDnsBlock = response.data.isBlocked;
            currentRequest.blockedB64Flag = response.data.blockedB64Flag;
            currentRequest.stopProcessing = true;
            currentRequest.dnsBlockResponse();
        } else if (response.data && response.data.dnsBuffer) {
            this.registerParameter("responseDecodedDnsPacket", response.data.dnsPacket);
            currentRequest.dnsResponse(response.data.dnsBuffer);
            currentRequest.decodedDnsPacket = response.data.dnsPacket;
            currentRequest.stopProcessing = true;
        }
    }
    dnsQuestionBlockCallBack(response, currentRequest) {
        const rxid = this.parameter.get("rxid");
        this.log.d(rxid, "In dnsQuestionBlockCallBack");
        if (response.isException) {
            loadException(response, currentRequest);
        } else if (response.data) {
            currentRequest.isDnsBlock = response.data.isBlocked;
            currentRequest.blockedB64Flag = response.data.blockedB64Flag;
            if (currentRequest.isDnsBlock) {
                currentRequest.stopProcessing = true;
                currentRequest.dnsBlockResponse();
            }
        }
    }
    dnsResolverCallBack(response, currentRequest) {
        this.log.d(this.parameter.get("rxid"), "In dnsResolverCallBack", JSON.stringify(response.data));
        if (response.isException) {
            loadException(response, currentRequest);
        } else {
            this.registerParameter("responseBodyBuffer", response.data.dnsBuffer);
            this.registerParameter("responseDecodedDnsPacket", response.data.dnsPacket);
        }
    }
    dnsResponseBlockCallBack(response, currentRequest) {
        const rxid = this.parameter.get("rxid");
        this.log.d(rxid, "In dnsResponseBlockCallBack");
        if (response.isException) {
            loadException(response, currentRequest);
        } else if (response.data && response.data.isBlocked) {
            currentRequest.isDnsBlock = response.data.isBlocked;
            currentRequest.blockedB64Flag = response.data.blockedB64Flag !== "" ? response.data.blockedB64Flag : currentRequest.blockedB64Flag;
            currentRequest.stopProcessing = true;
            currentRequest.dnsBlockResponse();
        } else {
            currentRequest.dnsResponse(this.parameter.get("responseBodyBuffer"));
            currentRequest.decodedDnsPacket = this.parameter.get("responseDecodedDnsPacket");
            currentRequest.stopProcessing = true;
        }
    }
}
function loadException(response, currentRequest) {
    log.e(JSON.stringify(response));
    currentRequest.stopProcessing = true;
    currentRequest.isException = true;
    currentRequest.exceptionStack = response.exceptionStack;
    currentRequest.exceptionFrom = response.exceptionFrom;
    currentRequest.dnsExceptionResponse();
}
function generateParam(parameter, list) {
    const param = {
    };
    for (const key of list){
        if (parameter.has(key)) {
            param[key] = parameter.get(key);
        }
    }
    return param;
}
async function setRequest(parameter, currentRequest) {
    const request = parameter.get("request");
    parameter.set("isDnsMsg", isDnsMsg(request));
    const isDnsMsg2 = parameter.get("isDnsMsg");
    if (!isValidRequest(isDnsMsg2, request)) {
        setInvalidResponse(currentRequest);
        return;
    }
    if (!isDnsMsg2) {
        return;
    }
    const buf = await getBodyBuffer(request);
    parameter.set("requestBodyBuffer", buf);
    parameter.set("requestDecodedDnsPacket", decode3(buf));
    currentRequest.decodedDnsPacket = parameter.get("requestDecodedDnsPacket");
}
async function getBodyBuffer(request) {
    if (request.method.toUpperCase() === "GET") {
        const QueryString = new URL(request.url).searchParams;
        return base64ToArrayBuffer(decodeURI(QueryString.get("dns")).replace(/-/g, "+").replace(/_/g, "/"));
    } else {
        return await request.arrayBuffer();
    }
}
function setInvalidResponse(currentRequest) {
    currentRequest.httpResponse = new Response(null, {
        status: 400,
        statusText: "Bad Request"
    });
    currentRequest.stopProcessing = true;
}
function isValidRequest(isDnsMsg3, req) {
    if (!isDnsMsg3 && req.method.toUpperCase() === "POST") return false;
    return true;
}
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for(let i37 = 0; i37 < len; i37++){
        bytes[i37] = binaryString.charCodeAt(i37);
    }
    return bytes.buffer;
}
function handleRequest(event) {
    return Promise.race([
        new Promise((accept, _)=>{
            accept(proxyRequest(event));
        }),
        new Promise((accept, _)=>{
            timeout(requestTimeout(), ()=>accept(servfail1())
            );
        }), 
    ]);
}
async function proxyRequest(event) {
    try {
        if (optionsRequest(event.request)) return respond204();
        const currentRequest = new CurrentRequest();
        const plugin = new RethinkPlugin(event);
        await plugin.executePlugin(currentRequest);
        const ua = event.request.headers.get("User-Agent");
        if (fromBrowser(ua)) currentRequest.setCorsHeaders();
        return currentRequest.httpResponse;
    } catch (err) {
        log.e(err.stack);
        return errorOrServfail(event.request, err);
    }
}
function optionsRequest(request) {
    return request.method === "OPTIONS";
}
function errorOrServfail(request, err) {
    const ua = request.headers.get("User-Agent");
    if (!fromBrowser(ua)) return servfail1();
    const res = new Response(JSON.stringify(err.stack), {
        status: 503,
        headers: browserHeaders()
    });
    return res;
}
function servfail1() {
    return respond503();
}
((main)=>{
    sub("go", systemUp);
})();
async function systemUp() {
    const { TERMINATE_TLS , TLS_CRT_PATH , TLS_KEY_PATH  } = Deno.env.toObject();
    const l = TERMINATE_TLS == "true" ? Deno.listenTls({
        port: 8080,
        certFile: TLS_CRT_PATH,
        keyFile: TLS_KEY_PATH
    }) : Deno.listen({
        port: 8080
    });
    console.log(`deno up at: http://${l.addr.hostname}:${l.addr.port}/`);
    for await (const conn of l){
        handleHttp(conn);
    }
}
async function handleHttp(conn) {
    const httpConn = Deno.serveHttp(conn);
    let requestEvent = null;
    while(true){
        try {
            requestEvent = await httpConn.nextRequest();
        } catch (e) {
            console.warn("error reading http request", e);
        }
        if (requestEvent) {
            try {
                await requestEvent.respondWith(handleRequest(requestEvent));
            } catch (e) {
                console.warn("error handling http request", e);
            }
        }
    }
}
