var $dDec7$fs = require("fs");
var $dDec7$util = require("util");
var $dDec7$crypto = require("crypto");
var $dDec7$stream = require("stream");
var $dDec7$dgram = require("dgram");
var $dDec7$os = require("os");
var $dDec7$path = require("path");
var $dDec7$events = require("events");
var $dDec7$timers = require("timers");
var $dDec7$string_decoder = require("string_decoder");
var $dDec7$buffer = require("buffer");
var $dDec7$domain = require("domain");
var $dDec7$url = require("url");
var $dDec7$querystring = require("querystring");
var $dDec7$child_process = require("child_process");
var $dDec7$https = require("https");
var $dDec7$http = require("http");


function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}

function $parcel$interopDefault(a) {
  return a && a.__esModule ? a.default : a;
}

      var $parcel$global = globalThis;
    
var $parcel$modules = {};
var $parcel$inits = {};

var parcelRequire = $parcel$global["parcelRequire3a8b"];

if (parcelRequire == null) {
  parcelRequire = function(id) {
    if (id in $parcel$modules) {
      return $parcel$modules[id].exports;
    }
    if (id in $parcel$inits) {
      var init = $parcel$inits[id];
      delete $parcel$inits[id];
      var module = {id: id, exports: {}};
      $parcel$modules[id] = module;
      init.call(module.exports, module, module.exports);
      return module.exports;
    }
    var err = new Error("Cannot find module '" + id + "'");
    err.code = 'MODULE_NOT_FOUND';
    throw err;
  };

  parcelRequire.register = function register(id, init) {
    $parcel$inits[id] = init;
  };

  $parcel$global["parcelRequire3a8b"] = parcelRequire;
}

var parcelRegister = parcelRequire.register;
parcelRegister("i3HcT", function(module, exports) {
/* eslint guard-for-in:0 */ var $d25a05cce66b58a0$var$AWS;







/**
 * A set of utility methods for use with the AWS SDK.
 *
 * @!attribute abort
 *   Return this value from an iterator function {each} or {arrayEach}
 *   to break out of the iteration.
 *   @example Breaking out of an iterator function
 *     AWS.util.each({a: 1, b: 2, c: 3}, function(key, value) {
 *       if (key == 'b') return AWS.util.abort;
 *     });
 *   @see each
 *   @see arrayEach
 * @api private
 */ var $d25a05cce66b58a0$var$util = {
    environment: 'nodejs',
    engine: function engine() {
        if ($d25a05cce66b58a0$var$util.isBrowser() && typeof navigator !== 'undefined') return navigator.userAgent;
        else {
            var engine = process.platform + '/' + process.version;
            if (process.env.AWS_EXECUTION_ENV) engine += ' exec-env/' + process.env.AWS_EXECUTION_ENV;
            return engine;
        }
    },
    userAgent: function userAgent() {
        var name = $d25a05cce66b58a0$var$util.environment;
        var agent = 'aws-sdk-' + name + '/' + (parcelRequire("hIq4q")).VERSION;
        if (name === 'nodejs') agent += ' ' + $d25a05cce66b58a0$var$util.engine();
        return agent;
    },
    uriEscape: function uriEscape(string) {
        var output = encodeURIComponent(string);
        output = output.replace(/[^A-Za-z0-9_.~\-%]+/g, escape);
        // AWS percent-encodes some extra non-standard characters in a URI
        output = output.replace(/[*]/g, function(ch) {
            return '%' + ch.charCodeAt(0).toString(16).toUpperCase();
        });
        return output;
    },
    uriEscapePath: function uriEscapePath(string) {
        var parts = [];
        $d25a05cce66b58a0$var$util.arrayEach(string.split('/'), function(part) {
            parts.push($d25a05cce66b58a0$var$util.uriEscape(part));
        });
        return parts.join('/');
    },
    urlParse: function urlParse(url) {
        return $d25a05cce66b58a0$var$util.url.parse(url);
    },
    urlFormat: function urlFormat(url) {
        return $d25a05cce66b58a0$var$util.url.format(url);
    },
    queryStringParse: function queryStringParse(qs) {
        return $d25a05cce66b58a0$var$util.querystring.parse(qs);
    },
    queryParamsToString: function queryParamsToString(params) {
        var items = [];
        var escape1 = $d25a05cce66b58a0$var$util.uriEscape;
        var sortedKeys = Object.keys(params).sort();
        $d25a05cce66b58a0$var$util.arrayEach(sortedKeys, function(name) {
            var value = params[name];
            var ename = escape1(name);
            var result = ename + '=';
            if (Array.isArray(value)) {
                var vals = [];
                $d25a05cce66b58a0$var$util.arrayEach(value, function(item) {
                    vals.push(escape1(item));
                });
                result = ename + '=' + vals.sort().join('&' + ename + '=');
            } else if (value !== undefined && value !== null) result = ename + '=' + escape1(value);
            items.push(result);
        });
        return items.join('&');
    },
    readFileSync: function readFileSync(path) {
        if ($d25a05cce66b58a0$var$util.isBrowser()) return null;
        return $dDec7$fs.readFileSync(path, 'utf-8');
    },
    base64: {
        encode: function encode64(string) {
            if (typeof string === 'number') throw $d25a05cce66b58a0$var$util.error(new Error('Cannot base64 encode number ' + string));
            if (string === null || typeof string === 'undefined') return string;
            var buf = $d25a05cce66b58a0$var$util.buffer.toBuffer(string);
            return buf.toString('base64');
        },
        decode: function decode64(string) {
            if (typeof string === 'number') throw $d25a05cce66b58a0$var$util.error(new Error('Cannot base64 decode number ' + string));
            if (string === null || typeof string === 'undefined') return string;
            return $d25a05cce66b58a0$var$util.buffer.toBuffer(string, 'base64');
        }
    },
    buffer: {
        /**
     * Buffer constructor for Node buffer and buffer pollyfill
     */ toBuffer: function(data, encoding) {
            return typeof $d25a05cce66b58a0$var$util.Buffer.from === 'function' && $d25a05cce66b58a0$var$util.Buffer.from !== Uint8Array.from ? $d25a05cce66b58a0$var$util.Buffer.from(data, encoding) : new $d25a05cce66b58a0$var$util.Buffer(data, encoding);
        },
        alloc: function(size, fill, encoding) {
            if (typeof size !== 'number') throw new Error('size passed to alloc must be a number.');
            if (typeof $d25a05cce66b58a0$var$util.Buffer.alloc === 'function') return $d25a05cce66b58a0$var$util.Buffer.alloc(size, fill, encoding);
            else {
                var buf = new $d25a05cce66b58a0$var$util.Buffer(size);
                if (fill !== undefined && typeof buf.fill === 'function') buf.fill(fill, undefined, undefined, encoding);
                return buf;
            }
        },
        toStream: function toStream(buffer) {
            if (!$d25a05cce66b58a0$var$util.Buffer.isBuffer(buffer)) buffer = $d25a05cce66b58a0$var$util.buffer.toBuffer(buffer);
            var readable = new $d25a05cce66b58a0$var$util.stream.Readable();
            var pos = 0;
            readable._read = function(size) {
                if (pos >= buffer.length) return readable.push(null);
                var end = pos + size;
                if (end > buffer.length) end = buffer.length;
                readable.push(buffer.slice(pos, end));
                pos = end;
            };
            return readable;
        },
        /**
     * Concatenates a list of Buffer objects.
     */ concat: function(buffers) {
            var length = 0, offset = 0, buffer = null, i;
            for(i = 0; i < buffers.length; i++)length += buffers[i].length;
            buffer = $d25a05cce66b58a0$var$util.buffer.alloc(length);
            for(i = 0; i < buffers.length; i++){
                buffers[i].copy(buffer, offset);
                offset += buffers[i].length;
            }
            return buffer;
        }
    },
    string: {
        byteLength: function byteLength(string) {
            if (string === null || string === undefined) return 0;
            if (typeof string === 'string') string = $d25a05cce66b58a0$var$util.buffer.toBuffer(string);
            if (typeof string.byteLength === 'number') return string.byteLength;
            else if (typeof string.length === 'number') return string.length;
            else if (typeof string.size === 'number') return string.size;
            else if (typeof string.path === 'string') return $dDec7$fs.lstatSync(string.path).size;
            else throw $d25a05cce66b58a0$var$util.error(new Error('Cannot determine length of ' + string), {
                object: string
            });
        },
        upperFirst: function upperFirst(string) {
            return string[0].toUpperCase() + string.substr(1);
        },
        lowerFirst: function lowerFirst(string) {
            return string[0].toLowerCase() + string.substr(1);
        }
    },
    ini: {
        parse: function string(ini) {
            var currentSection, map = {};
            $d25a05cce66b58a0$var$util.arrayEach(ini.split(/\r?\n/), function(line) {
                line = line.split(/(^|\s)[;#]/)[0].trim(); // remove comments and trim
                var isSection = line[0] === '[' && line[line.length - 1] === ']';
                if (isSection) {
                    currentSection = line.substring(1, line.length - 1);
                    if (currentSection === '__proto__' || currentSection.split(/\s/)[1] === '__proto__') throw $d25a05cce66b58a0$var$util.error(new Error('Cannot load profile name \'' + currentSection + '\' from shared ini file.'));
                } else if (currentSection) {
                    var indexOfEqualsSign = line.indexOf('=');
                    var start = 0;
                    var end = line.length - 1;
                    var isAssignment = indexOfEqualsSign !== -1 && indexOfEqualsSign !== start && indexOfEqualsSign !== end;
                    if (isAssignment) {
                        var name = line.substring(0, indexOfEqualsSign).trim();
                        var value = line.substring(indexOfEqualsSign + 1).trim();
                        map[currentSection] = map[currentSection] || {};
                        map[currentSection][name] = value;
                    }
                }
            });
            return map;
        }
    },
    fn: {
        noop: function() {},
        callback: function(err) {
            if (err) throw err;
        },
        /**
     * Turn a synchronous function into as "async" function by making it call
     * a callback. The underlying function is called with all but the last argument,
     * which is treated as the callback. The callback is passed passed a first argument
     * of null on success to mimick standard node callbacks.
     */ makeAsync: function makeAsync(fn, expectedArgs) {
            if (expectedArgs && expectedArgs <= fn.length) return fn;
            return function() {
                var args = Array.prototype.slice.call(arguments, 0);
                var callback = args.pop();
                var result = fn.apply(null, args);
                callback(result);
            };
        }
    },
    /**
   * Date and time utility functions.
   */ date: {
        /**
     * @return [Date] the current JavaScript date object. Since all
     *   AWS services rely on this date object, you can override
     *   this function to provide a special time value to AWS service
     *   requests.
     */ getDate: function getDate() {
            if (!$d25a05cce66b58a0$var$AWS) $d25a05cce66b58a0$var$AWS = (parcelRequire("hIq4q"));
            if ($d25a05cce66b58a0$var$AWS.config.systemClockOffset) return new Date(new Date().getTime() + $d25a05cce66b58a0$var$AWS.config.systemClockOffset);
            else return new Date();
        },
        /**
     * @return [String] the date in ISO-8601 format
     */ iso8601: function iso8601(date) {
            if (date === undefined) date = $d25a05cce66b58a0$var$util.date.getDate();
            return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
        },
        /**
     * @return [String] the date in RFC 822 format
     */ rfc822: function rfc822(date) {
            if (date === undefined) date = $d25a05cce66b58a0$var$util.date.getDate();
            return date.toUTCString();
        },
        /**
     * @return [Integer] the UNIX timestamp value for the current time
     */ unixTimestamp: function unixTimestamp(date) {
            if (date === undefined) date = $d25a05cce66b58a0$var$util.date.getDate();
            return date.getTime() / 1000;
        },
        /**
     * @param [String,number,Date] date
     * @return [Date]
     */ from: function format(date) {
            if (typeof date === 'number') return new Date(date * 1000); // unix timestamp
            else return new Date(date);
        },
        /**
     * Given a Date or date-like value, this function formats the
     * date into a string of the requested value.
     * @param [String,number,Date] date
     * @param [String] formatter Valid formats are:
     #   * 'iso8601'
     #   * 'rfc822'
     #   * 'unixTimestamp'
     * @return [String]
     */ format: function format(date, formatter) {
            if (!formatter) formatter = 'iso8601';
            return $d25a05cce66b58a0$var$util.date[formatter]($d25a05cce66b58a0$var$util.date.from(date));
        },
        parseTimestamp: function parseTimestamp(value) {
            if (typeof value === 'number') return new Date(value * 1000);
            else if (value.match(/^\d+$/)) return new Date(value * 1000);
            else if (value.match(/^\d{4}/)) return new Date(value);
            else if (value.match(/^\w{3},/)) return new Date(value);
            else throw $d25a05cce66b58a0$var$util.error(new Error('unhandled timestamp format: ' + value), {
                code: 'TimestampParserError'
            });
        }
    },
    crypto: {
        crc32Table: [
            0x00000000,
            0x77073096,
            0xEE0E612C,
            0x990951BA,
            0x076DC419,
            0x706AF48F,
            0xE963A535,
            0x9E6495A3,
            0x0EDB8832,
            0x79DCB8A4,
            0xE0D5E91E,
            0x97D2D988,
            0x09B64C2B,
            0x7EB17CBD,
            0xE7B82D07,
            0x90BF1D91,
            0x1DB71064,
            0x6AB020F2,
            0xF3B97148,
            0x84BE41DE,
            0x1ADAD47D,
            0x6DDDE4EB,
            0xF4D4B551,
            0x83D385C7,
            0x136C9856,
            0x646BA8C0,
            0xFD62F97A,
            0x8A65C9EC,
            0x14015C4F,
            0x63066CD9,
            0xFA0F3D63,
            0x8D080DF5,
            0x3B6E20C8,
            0x4C69105E,
            0xD56041E4,
            0xA2677172,
            0x3C03E4D1,
            0x4B04D447,
            0xD20D85FD,
            0xA50AB56B,
            0x35B5A8FA,
            0x42B2986C,
            0xDBBBC9D6,
            0xACBCF940,
            0x32D86CE3,
            0x45DF5C75,
            0xDCD60DCF,
            0xABD13D59,
            0x26D930AC,
            0x51DE003A,
            0xC8D75180,
            0xBFD06116,
            0x21B4F4B5,
            0x56B3C423,
            0xCFBA9599,
            0xB8BDA50F,
            0x2802B89E,
            0x5F058808,
            0xC60CD9B2,
            0xB10BE924,
            0x2F6F7C87,
            0x58684C11,
            0xC1611DAB,
            0xB6662D3D,
            0x76DC4190,
            0x01DB7106,
            0x98D220BC,
            0xEFD5102A,
            0x71B18589,
            0x06B6B51F,
            0x9FBFE4A5,
            0xE8B8D433,
            0x7807C9A2,
            0x0F00F934,
            0x9609A88E,
            0xE10E9818,
            0x7F6A0DBB,
            0x086D3D2D,
            0x91646C97,
            0xE6635C01,
            0x6B6B51F4,
            0x1C6C6162,
            0x856530D8,
            0xF262004E,
            0x6C0695ED,
            0x1B01A57B,
            0x8208F4C1,
            0xF50FC457,
            0x65B0D9C6,
            0x12B7E950,
            0x8BBEB8EA,
            0xFCB9887C,
            0x62DD1DDF,
            0x15DA2D49,
            0x8CD37CF3,
            0xFBD44C65,
            0x4DB26158,
            0x3AB551CE,
            0xA3BC0074,
            0xD4BB30E2,
            0x4ADFA541,
            0x3DD895D7,
            0xA4D1C46D,
            0xD3D6F4FB,
            0x4369E96A,
            0x346ED9FC,
            0xAD678846,
            0xDA60B8D0,
            0x44042D73,
            0x33031DE5,
            0xAA0A4C5F,
            0xDD0D7CC9,
            0x5005713C,
            0x270241AA,
            0xBE0B1010,
            0xC90C2086,
            0x5768B525,
            0x206F85B3,
            0xB966D409,
            0xCE61E49F,
            0x5EDEF90E,
            0x29D9C998,
            0xB0D09822,
            0xC7D7A8B4,
            0x59B33D17,
            0x2EB40D81,
            0xB7BD5C3B,
            0xC0BA6CAD,
            0xEDB88320,
            0x9ABFB3B6,
            0x03B6E20C,
            0x74B1D29A,
            0xEAD54739,
            0x9DD277AF,
            0x04DB2615,
            0x73DC1683,
            0xE3630B12,
            0x94643B84,
            0x0D6D6A3E,
            0x7A6A5AA8,
            0xE40ECF0B,
            0x9309FF9D,
            0x0A00AE27,
            0x7D079EB1,
            0xF00F9344,
            0x8708A3D2,
            0x1E01F268,
            0x6906C2FE,
            0xF762575D,
            0x806567CB,
            0x196C3671,
            0x6E6B06E7,
            0xFED41B76,
            0x89D32BE0,
            0x10DA7A5A,
            0x67DD4ACC,
            0xF9B9DF6F,
            0x8EBEEFF9,
            0x17B7BE43,
            0x60B08ED5,
            0xD6D6A3E8,
            0xA1D1937E,
            0x38D8C2C4,
            0x4FDFF252,
            0xD1BB67F1,
            0xA6BC5767,
            0x3FB506DD,
            0x48B2364B,
            0xD80D2BDA,
            0xAF0A1B4C,
            0x36034AF6,
            0x41047A60,
            0xDF60EFC3,
            0xA867DF55,
            0x316E8EEF,
            0x4669BE79,
            0xCB61B38C,
            0xBC66831A,
            0x256FD2A0,
            0x5268E236,
            0xCC0C7795,
            0xBB0B4703,
            0x220216B9,
            0x5505262F,
            0xC5BA3BBE,
            0xB2BD0B28,
            0x2BB45A92,
            0x5CB36A04,
            0xC2D7FFA7,
            0xB5D0CF31,
            0x2CD99E8B,
            0x5BDEAE1D,
            0x9B64C2B0,
            0xEC63F226,
            0x756AA39C,
            0x026D930A,
            0x9C0906A9,
            0xEB0E363F,
            0x72076785,
            0x05005713,
            0x95BF4A82,
            0xE2B87A14,
            0x7BB12BAE,
            0x0CB61B38,
            0x92D28E9B,
            0xE5D5BE0D,
            0x7CDCEFB7,
            0x0BDBDF21,
            0x86D3D2D4,
            0xF1D4E242,
            0x68DDB3F8,
            0x1FDA836E,
            0x81BE16CD,
            0xF6B9265B,
            0x6FB077E1,
            0x18B74777,
            0x88085AE6,
            0xFF0F6A70,
            0x66063BCA,
            0x11010B5C,
            0x8F659EFF,
            0xF862AE69,
            0x616BFFD3,
            0x166CCF45,
            0xA00AE278,
            0xD70DD2EE,
            0x4E048354,
            0x3903B3C2,
            0xA7672661,
            0xD06016F7,
            0x4969474D,
            0x3E6E77DB,
            0xAED16A4A,
            0xD9D65ADC,
            0x40DF0B66,
            0x37D83BF0,
            0xA9BCAE53,
            0xDEBB9EC5,
            0x47B2CF7F,
            0x30B5FFE9,
            0xBDBDF21C,
            0xCABAC28A,
            0x53B39330,
            0x24B4A3A6,
            0xBAD03605,
            0xCDD70693,
            0x54DE5729,
            0x23D967BF,
            0xB3667A2E,
            0xC4614AB8,
            0x5D681B02,
            0x2A6F2B94,
            0xB40BBE37,
            0xC30C8EA1,
            0x5A05DF1B,
            0x2D02EF8D
        ],
        crc32: function crc32(data) {
            var tbl = $d25a05cce66b58a0$var$util.crypto.crc32Table;
            var crc = -1;
            if (typeof data === 'string') data = $d25a05cce66b58a0$var$util.buffer.toBuffer(data);
            for(var i = 0; i < data.length; i++){
                var code = data.readUInt8(i);
                crc = crc >>> 8 ^ tbl[(crc ^ code) & 0xFF];
            }
            return (crc ^ -1) >>> 0;
        },
        hmac: function hmac(key, string, digest, fn) {
            if (!digest) digest = 'binary';
            if (digest === 'buffer') digest = undefined;
            if (!fn) fn = 'sha256';
            if (typeof string === 'string') string = $d25a05cce66b58a0$var$util.buffer.toBuffer(string);
            return $d25a05cce66b58a0$var$util.crypto.lib.createHmac(fn, key).update(string).digest(digest);
        },
        md5: function md5(data, digest, callback) {
            return $d25a05cce66b58a0$var$util.crypto.hash('md5', data, digest, callback);
        },
        sha256: function sha256(data, digest, callback) {
            return $d25a05cce66b58a0$var$util.crypto.hash('sha256', data, digest, callback);
        },
        hash: function(algorithm, data, digest, callback) {
            var hash = $d25a05cce66b58a0$var$util.crypto.createHash(algorithm);
            if (!digest) digest = 'binary';
            if (digest === 'buffer') digest = undefined;
            if (typeof data === 'string') data = $d25a05cce66b58a0$var$util.buffer.toBuffer(data);
            var sliceFn = $d25a05cce66b58a0$var$util.arraySliceFn(data);
            var isBuffer = $d25a05cce66b58a0$var$util.Buffer.isBuffer(data);
            //Identifying objects with an ArrayBuffer as buffers
            if ($d25a05cce66b58a0$var$util.isBrowser() && typeof ArrayBuffer !== 'undefined' && data && data.buffer instanceof ArrayBuffer) isBuffer = true;
            if (callback && typeof data === 'object' && typeof data.on === 'function' && !isBuffer) {
                data.on('data', function(chunk) {
                    hash.update(chunk);
                });
                data.on('error', function(err) {
                    callback(err);
                });
                data.on('end', function() {
                    callback(null, hash.digest(digest));
                });
            } else if (callback && sliceFn && !isBuffer && typeof FileReader !== 'undefined') {
                // this might be a File/Blob
                var index = 0, size = 524288;
                var reader = new FileReader();
                reader.onerror = function() {
                    callback(new Error('Failed to read data.'));
                };
                reader.onload = function() {
                    var buf = new $d25a05cce66b58a0$var$util.Buffer(new Uint8Array(reader.result));
                    hash.update(buf);
                    index += buf.length;
                    reader._continueReading();
                };
                reader._continueReading = function() {
                    if (index >= data.size) {
                        callback(null, hash.digest(digest));
                        return;
                    }
                    var back = index + size;
                    if (back > data.size) back = data.size;
                    reader.readAsArrayBuffer(sliceFn.call(data, index, back));
                };
                reader._continueReading();
            } else {
                if ($d25a05cce66b58a0$var$util.isBrowser() && typeof data === 'object' && !isBuffer) data = new $d25a05cce66b58a0$var$util.Buffer(new Uint8Array(data));
                var out = hash.update(data).digest(digest);
                if (callback) callback(null, out);
                return out;
            }
        },
        toHex: function toHex(data) {
            var out = [];
            for(var i = 0; i < data.length; i++)out.push(('0' + data.charCodeAt(i).toString(16)).substr(-2, 2));
            return out.join('');
        },
        createHash: function createHash(algorithm) {
            return $d25a05cce66b58a0$var$util.crypto.lib.createHash(algorithm);
        }
    },
    /** @!ignore */ /* Abort constant */ abort: {},
    each: function each(object, iterFunction) {
        for(var key in object)if (Object.prototype.hasOwnProperty.call(object, key)) {
            var ret = iterFunction.call(this, key, object[key]);
            if (ret === $d25a05cce66b58a0$var$util.abort) break;
        }
    },
    arrayEach: function arrayEach(array, iterFunction) {
        for(var idx in array)if (Object.prototype.hasOwnProperty.call(array, idx)) {
            var ret = iterFunction.call(this, array[idx], parseInt(idx, 10));
            if (ret === $d25a05cce66b58a0$var$util.abort) break;
        }
    },
    update: function update(obj1, obj2) {
        $d25a05cce66b58a0$var$util.each(obj2, function iterator(key, item) {
            obj1[key] = item;
        });
        return obj1;
    },
    merge: function merge(obj1, obj2) {
        return $d25a05cce66b58a0$var$util.update($d25a05cce66b58a0$var$util.copy(obj1), obj2);
    },
    copy: function copy(object) {
        if (object === null || object === undefined) return object;
        var dupe = {};
        // jshint forin:false
        for(var key in object)dupe[key] = object[key];
        return dupe;
    },
    isEmpty: function isEmpty(obj) {
        for(var prop in obj){
            if (Object.prototype.hasOwnProperty.call(obj, prop)) return false;
        }
        return true;
    },
    arraySliceFn: function arraySliceFn(obj) {
        var fn = obj.slice || obj.webkitSlice || obj.mozSlice;
        return typeof fn === 'function' ? fn : null;
    },
    isType: function isType(obj, type) {
        // handle cross-"frame" objects
        if (typeof type === 'function') type = $d25a05cce66b58a0$var$util.typeName(type);
        return Object.prototype.toString.call(obj) === '[object ' + type + ']';
    },
    typeName: function typeName(type) {
        if (Object.prototype.hasOwnProperty.call(type, 'name')) return type.name;
        var str = type.toString();
        var match = str.match(/^\s*function (.+)\(/);
        return match ? match[1] : str;
    },
    error: function error(err, options) {
        var originalError = null;
        if (typeof err.message === 'string' && err.message !== '') {
            if (typeof options === 'string' || options && options.message) {
                originalError = $d25a05cce66b58a0$var$util.copy(err);
                originalError.message = err.message;
            }
        }
        err.message = err.message || null;
        if (typeof options === 'string') err.message = options;
        else if (typeof options === 'object' && options !== null) {
            $d25a05cce66b58a0$var$util.update(err, options);
            if (options.message) err.message = options.message;
            if (options.code || options.name) err.code = options.code || options.name;
            if (options.stack) err.stack = options.stack;
        }
        if (typeof Object.defineProperty === 'function') {
            Object.defineProperty(err, 'name', {
                writable: true,
                enumerable: false
            });
            Object.defineProperty(err, 'message', {
                enumerable: true
            });
        }
        err.name = String(options && options.name || err.name || err.code || 'Error');
        err.time = new Date();
        if (originalError) err.originalError = originalError;
        for(var key in options || {})if (key[0] === '[' && key[key.length - 1] === ']') {
            key = key.slice(1, -1);
            if (key === 'code' || key === 'message') continue;
            err['[' + key + ']'] = 'See error.' + key + ' for details.';
            Object.defineProperty(err, key, {
                value: err[key] || options && options[key] || originalError && originalError[key],
                enumerable: false,
                writable: true
            });
        }
        return err;
    },
    /**
   * @api private
   */ inherit: function inherit(klass, features) {
        var newObject = null;
        if (features === undefined) {
            features = klass;
            klass = Object;
            newObject = {};
        } else {
            var ctor = function ConstructorWrapper() {};
            ctor.prototype = klass.prototype;
            newObject = new ctor();
        }
        // constructor not supplied, create pass-through ctor
        if (features.constructor === Object) features.constructor = function() {
            if (klass !== Object) return klass.apply(this, arguments);
        };
        features.constructor.prototype = newObject;
        $d25a05cce66b58a0$var$util.update(features.constructor.prototype, features);
        features.constructor.__super__ = klass;
        return features.constructor;
    },
    /**
   * @api private
   */ mixin: function mixin() {
        var klass = arguments[0];
        for(var i = 1; i < arguments.length; i++)// jshint forin:false
        for(var prop in arguments[i].prototype){
            var fn = arguments[i].prototype[prop];
            if (prop !== 'constructor') klass.prototype[prop] = fn;
        }
        return klass;
    },
    /**
   * @api private
   */ hideProperties: function hideProperties(obj, props) {
        if (typeof Object.defineProperty !== 'function') return;
        $d25a05cce66b58a0$var$util.arrayEach(props, function(key) {
            Object.defineProperty(obj, key, {
                enumerable: false,
                writable: true,
                configurable: true
            });
        });
    },
    /**
   * @api private
   */ property: function property(obj, name, value, enumerable, isValue) {
        var opts = {
            configurable: true,
            enumerable: enumerable !== undefined ? enumerable : true
        };
        if (typeof value === 'function' && !isValue) opts.get = value;
        else {
            opts.value = value;
            opts.writable = true;
        }
        Object.defineProperty(obj, name, opts);
    },
    /**
   * @api private
   */ memoizedProperty: function memoizedProperty(obj, name, get, enumerable) {
        var cachedValue = null;
        // build enumerable attribute for each value with lazy accessor.
        $d25a05cce66b58a0$var$util.property(obj, name, function() {
            if (cachedValue === null) cachedValue = get();
            return cachedValue;
        }, enumerable);
    },
    /**
   * TODO Remove in major version revision
   * This backfill populates response data without the
   * top-level payload name.
   *
   * @api private
   */ hoistPayloadMember: function hoistPayloadMember(resp) {
        var req = resp.request;
        var operationName = req.operation;
        var operation = req.service.api.operations[operationName];
        var output = operation.output;
        if (output.payload && !operation.hasEventOutput) {
            var payloadMember = output.members[output.payload];
            var responsePayload = resp.data[output.payload];
            if (payloadMember.type === 'structure') $d25a05cce66b58a0$var$util.each(responsePayload, function(key, value) {
                $d25a05cce66b58a0$var$util.property(resp.data, key, value, false);
            });
        }
    },
    /**
   * Compute SHA-256 checksums of streams
   *
   * @api private
   */ computeSha256: function computeSha256(body, done) {
        if ($d25a05cce66b58a0$var$util.isNode()) {
            var Stream = $d25a05cce66b58a0$var$util.stream.Stream;
            var fs = $dDec7$fs;
            if (typeof Stream === 'function' && body instanceof Stream) {
                if (typeof body.path === 'string') {
                    var settings = {};
                    if (typeof body.start === 'number') settings.start = body.start;
                    if (typeof body.end === 'number') settings.end = body.end;
                    body = fs.createReadStream(body.path, settings);
                } else return done(new Error("Non-file stream objects are not supported with SigV4"));
            }
        }
        $d25a05cce66b58a0$var$util.crypto.sha256(body, 'hex', function(err, sha) {
            if (err) done(err);
            else done(null, sha);
        });
    },
    /**
   * @api private
   */ isClockSkewed: function isClockSkewed(serverTime) {
        if (serverTime) {
            $d25a05cce66b58a0$var$util.property($d25a05cce66b58a0$var$AWS.config, 'isClockSkewed', Math.abs(new Date().getTime() - serverTime) >= 300000, false);
            return $d25a05cce66b58a0$var$AWS.config.isClockSkewed;
        }
    },
    applyClockOffset: function applyClockOffset(serverTime) {
        if (serverTime) $d25a05cce66b58a0$var$AWS.config.systemClockOffset = serverTime - new Date().getTime();
    },
    /**
   * @api private
   */ extractRequestId: function extractRequestId(resp) {
        var requestId = resp.httpResponse.headers['x-amz-request-id'] || resp.httpResponse.headers['x-amzn-requestid'];
        if (!requestId && resp.data && resp.data.ResponseMetadata) requestId = resp.data.ResponseMetadata.RequestId;
        if (requestId) resp.requestId = requestId;
        if (resp.error) resp.error.requestId = requestId;
    },
    /**
   * @api private
   */ addPromises: function addPromises(constructors, PromiseDependency) {
        var deletePromises = false;
        if (PromiseDependency === undefined && $d25a05cce66b58a0$var$AWS && $d25a05cce66b58a0$var$AWS.config) PromiseDependency = $d25a05cce66b58a0$var$AWS.config.getPromisesDependency();
        if (PromiseDependency === undefined && typeof Promise !== 'undefined') PromiseDependency = Promise;
        if (typeof PromiseDependency !== 'function') deletePromises = true;
        if (!Array.isArray(constructors)) constructors = [
            constructors
        ];
        for(var ind = 0; ind < constructors.length; ind++){
            var constructor = constructors[ind];
            if (deletePromises) {
                if (constructor.deletePromisesFromClass) constructor.deletePromisesFromClass();
            } else if (constructor.addPromisesToClass) constructor.addPromisesToClass(PromiseDependency);
        }
    },
    /**
   * @api private
   * Return a function that will return a promise whose fate is decided by the
   * callback behavior of the given method with `methodName`. The method to be
   * promisified should conform to node.js convention of accepting a callback as
   * last argument and calling that callback with error as the first argument
   * and success value on the second argument.
   */ promisifyMethod: function promisifyMethod(methodName, PromiseDependency) {
        return function promise() {
            var self = this;
            var args = Array.prototype.slice.call(arguments);
            return new PromiseDependency(function(resolve, reject) {
                args.push(function(err, data) {
                    if (err) reject(err);
                    else resolve(data);
                });
                self[methodName].apply(self, args);
            });
        };
    },
    /**
   * @api private
   */ isDualstackAvailable: function isDualstackAvailable(service) {
        if (!service) return false;
        var metadata = (parcelRequire("khYer"));
        if (typeof service !== 'string') service = service.serviceIdentifier;
        if (typeof service !== 'string' || !metadata.hasOwnProperty(service)) return false;
        return !!metadata[service].dualstackAvailable;
    },
    /**
   * @api private
   */ calculateRetryDelay: function calculateRetryDelay(retryCount, retryDelayOptions, err) {
        if (!retryDelayOptions) retryDelayOptions = {};
        var customBackoff = retryDelayOptions.customBackoff || null;
        if (typeof customBackoff === 'function') return customBackoff(retryCount, err);
        var base = typeof retryDelayOptions.base === 'number' ? retryDelayOptions.base : 100;
        var delay = Math.random() * (Math.pow(2, retryCount) * base);
        return delay;
    },
    /**
   * @api private
   */ handleRequestWithRetries: function handleRequestWithRetries(httpRequest, options, cb) {
        if (!options) options = {};
        var http = $d25a05cce66b58a0$var$AWS.HttpClient.getInstance();
        var httpOptions = options.httpOptions || {};
        var retryCount = 0;
        var errCallback = function(err) {
            var maxRetries = options.maxRetries || 0;
            if (err && err.code === 'TimeoutError') err.retryable = true;
            // Call `calculateRetryDelay()` only when relevant, see #3401
            if (err && err.retryable && retryCount < maxRetries) {
                var delay = $d25a05cce66b58a0$var$util.calculateRetryDelay(retryCount, options.retryDelayOptions, err);
                if (delay >= 0) {
                    retryCount++;
                    setTimeout(sendRequest, delay + (err.retryAfter || 0));
                    return;
                }
            }
            cb(err);
        };
        var sendRequest = function() {
            var data = '';
            http.handleRequest(httpRequest, httpOptions, function(httpResponse) {
                httpResponse.on('data', function(chunk) {
                    data += chunk.toString();
                });
                httpResponse.on('end', function() {
                    var statusCode = httpResponse.statusCode;
                    if (statusCode < 300) cb(null, data);
                    else {
                        var retryAfter = parseInt(httpResponse.headers['retry-after'], 10) * 1000 || 0;
                        var err = $d25a05cce66b58a0$var$util.error(new Error(), {
                            statusCode: statusCode,
                            retryable: statusCode >= 500 || statusCode === 429
                        });
                        if (retryAfter && err.retryable) err.retryAfter = retryAfter;
                        errCallback(err);
                    }
                });
            }, errCallback);
        };
        $d25a05cce66b58a0$var$AWS.util.defer(sendRequest);
    },
    /**
   * @api private
   */ uuid: {
        v4: function uuidV4() {
            return (parcelRequire("9LCkR")).default();
        }
    },
    /**
   * @api private
   */ convertPayloadToString: function convertPayloadToString(resp) {
        var req = resp.request;
        var operation = req.operation;
        var rules = req.service.api.operations[operation].output || {};
        if (rules.payload && resp.data[rules.payload]) resp.data[rules.payload] = resp.data[rules.payload].toString();
    },
    /**
   * @api private
   */ defer: function defer(callback) {
        if (typeof process === 'object' && typeof process.nextTick === 'function') process.nextTick(callback);
        else if (typeof setImmediate === 'function') setImmediate(callback);
        else setTimeout(callback, 0);
    },
    /**
   * @api private
   */ getRequestPayloadShape: function getRequestPayloadShape(req) {
        var operations = req.service.api.operations;
        if (!operations) return undefined;
        var operation = (operations || {})[req.operation];
        if (!operation || !operation.input || !operation.input.payload) return undefined;
        return operation.input.members[operation.input.payload];
    },
    getProfilesFromSharedConfig: function getProfilesFromSharedConfig(iniLoader, filename) {
        var profiles = {};
        var profilesFromConfig = {};
        if (process.env[$d25a05cce66b58a0$var$util.configOptInEnv]) var profilesFromConfig = iniLoader.loadFrom({
            isConfig: true,
            filename: process.env[$d25a05cce66b58a0$var$util.sharedConfigFileEnv]
        });
        var profilesFromCreds = {};
        try {
            var profilesFromCreds = iniLoader.loadFrom({
                filename: filename || process.env[$d25a05cce66b58a0$var$util.configOptInEnv] && process.env[$d25a05cce66b58a0$var$util.sharedCredentialsFileEnv]
            });
        } catch (error) {
            // if using config, assume it is fully descriptive without a credentials file:
            if (!process.env[$d25a05cce66b58a0$var$util.configOptInEnv]) throw error;
        }
        for(var i = 0, profileNames = Object.keys(profilesFromConfig); i < profileNames.length; i++)profiles[profileNames[i]] = objectAssign(profiles[profileNames[i]] || {}, profilesFromConfig[profileNames[i]]);
        for(var i = 0, profileNames = Object.keys(profilesFromCreds); i < profileNames.length; i++)profiles[profileNames[i]] = objectAssign(profiles[profileNames[i]] || {}, profilesFromCreds[profileNames[i]]);
        return profiles;
        /**
     * Roughly the semantics of `Object.assign(target, source)`
     */ function objectAssign(target, source) {
            for(var i = 0, keys = Object.keys(source); i < keys.length; i++)target[keys[i]] = source[keys[i]];
            return target;
        }
    },
    /**
   * @api private
   */ ARN: {
        validate: function validateARN(str) {
            return str && str.indexOf('arn:') === 0 && str.split(':').length >= 6;
        },
        parse: function parseARN(arn) {
            var matched = arn.split(':');
            return {
                partition: matched[1],
                service: matched[2],
                region: matched[3],
                accountId: matched[4],
                resource: matched.slice(5).join(':')
            };
        },
        build: function buildARN(arnObject) {
            if (arnObject.service === undefined || arnObject.region === undefined || arnObject.accountId === undefined || arnObject.resource === undefined) throw $d25a05cce66b58a0$var$util.error(new Error('Input ARN object is invalid'));
            return 'arn:' + (arnObject.partition || 'aws') + ':' + arnObject.service + ':' + arnObject.region + ':' + arnObject.accountId + ':' + arnObject.resource;
        }
    },
    /**
   * @api private
   */ defaultProfile: 'default',
    /**
   * @api private
   */ configOptInEnv: 'AWS_SDK_LOAD_CONFIG',
    /**
   * @api private
   */ sharedCredentialsFileEnv: 'AWS_SHARED_CREDENTIALS_FILE',
    /**
   * @api private
   */ sharedConfigFileEnv: 'AWS_CONFIG_FILE',
    /**
   * @api private
   */ imdsDisabledEnv: 'AWS_EC2_METADATA_DISABLED'
};
/**
 * @api private
 */ module.exports = $d25a05cce66b58a0$var$util;

});
parcelRegister("hIq4q", function(module, exports) {
/**
 * The main AWS namespace
 */ 
var $ce5ac4bd14015c59$var$AWS = {
    util: (parcelRequire("i3HcT"))
};
/**
 * @api private
 * @!macro [new] nobrowser
 *   @note This feature is not supported in the browser environment of the SDK.
 */ var $ce5ac4bd14015c59$var$_hidden = {};
$ce5ac4bd14015c59$var$_hidden.toString(); // hack to parse macro
/**
 * @api private
 */ module.exports = $ce5ac4bd14015c59$var$AWS;















$ce5ac4bd14015c59$var$AWS.util.update($ce5ac4bd14015c59$var$AWS, {
    /**
   * @constant
   */ VERSION: '2.1693.0',
    /**
   * @api private
   */ Signers: {},
    /**
   * @api private
   */ Protocol: {
        Json: (parcelRequire("4caHz")),
        Query: (parcelRequire("iqzj9")),
        Rest: (parcelRequire("gDGw5")),
        RestJson: (parcelRequire("hQdKL")),
        RestXml: (parcelRequire("2OT3o"))
    },
    /**
   * @api private
   */ XML: {
        Builder: (parcelRequire("6FvXS")),
        Parser: null // conditionally set based on environment
    },
    /**
   * @api private
   */ JSON: {
        Builder: (parcelRequire("1gBXL")),
        Parser: (parcelRequire("fKQ4C"))
    },
    /**
   * @api private
   */ Model: {
        Api: (parcelRequire("g9WzK")),
        Operation: (parcelRequire("lk1Cc")),
        Shape: (parcelRequire("kMCY1")),
        Paginator: (parcelRequire("kBz1Z")),
        ResourceWaiter: (parcelRequire("3uIxQ"))
    },
    /**
   * @api private
   */ apiLoader: (parcelRequire("b4VdT")),
    /**
   * @api private
   */ EndpointCache: (parcelRequire("8JRRk")).EndpointCache
});
parcelRequire("cLHKj");
parcelRequire("bveyz");
parcelRequire("jWuBc");
parcelRequire("jI9el");
parcelRequire("4NP9G");
parcelRequire("dx1SW");
parcelRequire("a4S51");
parcelRequire("3iU3E");
parcelRequire("7KwpD");
parcelRequire("lgvDe");
parcelRequire("eOFpQ");
/**
 * @readonly
 * @return [AWS.SequentialExecutor] a collection of global event listeners that
 *   are attached to every sent request.
 * @see AWS.Request AWS.Request for a list of events to listen for
 * @example Logging the time taken to send a request
 *   AWS.events.on('send', function startSend(resp) {
 *     resp.startTime = new Date().getTime();
 *   }).on('complete', function calculateTime(resp) {
 *     var time = (new Date().getTime() - resp.startTime) / 1000;
 *     console.log('Request took ' + time + ' seconds');
 *   });
 *
 *   new AWS.S3().listBuckets(); // prints 'Request took 0.285 seconds'
 */ $ce5ac4bd14015c59$var$AWS.events = new $ce5ac4bd14015c59$var$AWS.SequentialExecutor();
//create endpoint cache lazily
$ce5ac4bd14015c59$var$AWS.util.memoizedProperty($ce5ac4bd14015c59$var$AWS, 'endpointCache', function() {
    return new $ce5ac4bd14015c59$var$AWS.EndpointCache($ce5ac4bd14015c59$var$AWS.config.endpointCacheSize);
}, true);

});
parcelRegister("4caHz", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");

var $1gBXL = parcelRequire("1gBXL");

var $fKQ4C = parcelRequire("fKQ4C");

var $cwJjn = parcelRequire("cwJjn");
var $30e095917daccbc9$require$populateHostPrefix = $cwJjn.populateHostPrefix;
function $30e095917daccbc9$var$buildRequest(req) {
    var httpRequest = req.httpRequest;
    var api = req.service.api;
    var target = api.targetPrefix + '.' + api.operations[req.operation].name;
    var version = api.jsonVersion || '1.0';
    var input = api.operations[req.operation].input;
    var builder = new $1gBXL();
    if (version === 1) version = '1.0';
    if (api.awsQueryCompatible) {
        if (!httpRequest.params) httpRequest.params = {};
        // because Query protocol does this.
        Object.assign(httpRequest.params, req.params);
    }
    httpRequest.body = builder.build(req.params || {}, input);
    httpRequest.headers['Content-Type'] = 'application/x-amz-json-' + version;
    httpRequest.headers['X-Amz-Target'] = target;
    $30e095917daccbc9$require$populateHostPrefix(req);
}
function $30e095917daccbc9$var$extractError(resp) {
    var error = {};
    var httpResponse = resp.httpResponse;
    error.code = httpResponse.headers['x-amzn-errortype'] || 'UnknownError';
    if (typeof error.code === 'string') error.code = error.code.split(':')[0];
    if (httpResponse.body.length > 0) try {
        var e = JSON.parse(httpResponse.body.toString());
        var code = e.__type || e.code || e.Code;
        if (code) error.code = code.split('#').pop();
        if (error.code === 'RequestEntityTooLarge') error.message = 'Request body must be less than 1 MB';
        else error.message = e.message || e.Message || null;
        // The minimized models do not have error shapes, so
        // without expanding the model size, it's not possible
        // to validate the response shape (members) or
        // check if any are sensitive to logging.
        // Assign the fields as non-enumerable, allowing specific access only.
        for(var key in e || {}){
            if (key === 'code' || key === 'message') continue;
            error['[' + key + ']'] = 'See error.' + key + ' for details.';
            Object.defineProperty(error, key, {
                value: e[key],
                enumerable: false,
                writable: true
            });
        }
    } catch (e) {
        error.statusCode = httpResponse.statusCode;
        error.message = httpResponse.statusMessage;
    }
    else {
        error.statusCode = httpResponse.statusCode;
        error.message = httpResponse.statusCode.toString();
    }
    resp.error = $i3HcT.error(new Error(), error);
}
function $30e095917daccbc9$var$extractData(resp) {
    var body = resp.httpResponse.body.toString() || '{}';
    if (resp.request.service.config.convertResponseTypes === false) resp.data = JSON.parse(body);
    else {
        var operation = resp.request.service.api.operations[resp.request.operation];
        var shape = operation.output || {};
        var parser = new $fKQ4C();
        resp.data = parser.parse(body, shape);
    }
}
/**
 * @api private
 */ module.exports = {
    buildRequest: $30e095917daccbc9$var$buildRequest,
    extractError: $30e095917daccbc9$var$extractError,
    extractData: $30e095917daccbc9$var$extractData
};

});
parcelRegister("1gBXL", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");
function $0ec4bbbcccd8bc94$var$JsonBuilder() {}
$0ec4bbbcccd8bc94$var$JsonBuilder.prototype.build = function(value, shape) {
    return JSON.stringify($0ec4bbbcccd8bc94$var$translate(value, shape));
};
function $0ec4bbbcccd8bc94$var$translate(value, shape) {
    if (!shape || value === undefined || value === null) return undefined;
    switch(shape.type){
        case 'structure':
            return $0ec4bbbcccd8bc94$var$translateStructure(value, shape);
        case 'map':
            return $0ec4bbbcccd8bc94$var$translateMap(value, shape);
        case 'list':
            return $0ec4bbbcccd8bc94$var$translateList(value, shape);
        default:
            return $0ec4bbbcccd8bc94$var$translateScalar(value, shape);
    }
}
function $0ec4bbbcccd8bc94$var$translateStructure(structure, shape) {
    if (shape.isDocument) return structure;
    var struct = {};
    $i3HcT.each(structure, function(name, value) {
        var memberShape = shape.members[name];
        if (memberShape) {
            if (memberShape.location !== 'body') return;
            var locationName = memberShape.isLocationName ? memberShape.name : name;
            var result = $0ec4bbbcccd8bc94$var$translate(value, memberShape);
            if (result !== undefined) struct[locationName] = result;
        }
    });
    return struct;
}
function $0ec4bbbcccd8bc94$var$translateList(list, shape) {
    var out = [];
    $i3HcT.arrayEach(list, function(value) {
        var result = $0ec4bbbcccd8bc94$var$translate(value, shape.member);
        if (result !== undefined) out.push(result);
    });
    return out;
}
function $0ec4bbbcccd8bc94$var$translateMap(map, shape) {
    var out = {};
    $i3HcT.each(map, function(key, value) {
        var result = $0ec4bbbcccd8bc94$var$translate(value, shape.value);
        if (result !== undefined) out[key] = result;
    });
    return out;
}
function $0ec4bbbcccd8bc94$var$translateScalar(value, shape) {
    return shape.toWireFormat(value);
}
/**
 * @api private
 */ module.exports = $0ec4bbbcccd8bc94$var$JsonBuilder;

});

parcelRegister("fKQ4C", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");
function $b7838b9c7bc46d30$var$JsonParser() {}
$b7838b9c7bc46d30$var$JsonParser.prototype.parse = function(value, shape) {
    return $b7838b9c7bc46d30$var$translate(JSON.parse(value), shape);
};
function $b7838b9c7bc46d30$var$translate(value, shape) {
    if (!shape || value === undefined) return undefined;
    switch(shape.type){
        case 'structure':
            return $b7838b9c7bc46d30$var$translateStructure(value, shape);
        case 'map':
            return $b7838b9c7bc46d30$var$translateMap(value, shape);
        case 'list':
            return $b7838b9c7bc46d30$var$translateList(value, shape);
        default:
            return $b7838b9c7bc46d30$var$translateScalar(value, shape);
    }
}
function $b7838b9c7bc46d30$var$translateStructure(structure, shape) {
    if (structure == null) return undefined;
    if (shape.isDocument) return structure;
    var struct = {};
    var shapeMembers = shape.members;
    var isAwsQueryCompatible = shape.api && shape.api.awsQueryCompatible;
    $i3HcT.each(shapeMembers, function(name, memberShape) {
        var locationName = memberShape.isLocationName ? memberShape.name : name;
        if (Object.prototype.hasOwnProperty.call(structure, locationName)) {
            var value = structure[locationName];
            var result = $b7838b9c7bc46d30$var$translate(value, memberShape);
            if (result !== undefined) struct[name] = result;
        } else if (isAwsQueryCompatible && memberShape.defaultValue) {
            if (memberShape.type === 'list') struct[name] = typeof memberShape.defaultValue === 'function' ? memberShape.defaultValue() : memberShape.defaultValue;
        }
    });
    return struct;
}
function $b7838b9c7bc46d30$var$translateList(list, shape) {
    if (list == null) return undefined;
    var out = [];
    $i3HcT.arrayEach(list, function(value) {
        var result = $b7838b9c7bc46d30$var$translate(value, shape.member);
        if (result === undefined) out.push(null);
        else out.push(result);
    });
    return out;
}
function $b7838b9c7bc46d30$var$translateMap(map, shape) {
    if (map == null) return undefined;
    var out = {};
    $i3HcT.each(map, function(key, value) {
        var result = $b7838b9c7bc46d30$var$translate(value, shape.value);
        if (result === undefined) out[key] = null;
        else out[key] = result;
    });
    return out;
}
function $b7838b9c7bc46d30$var$translateScalar(value, shape) {
    return shape.toType(value);
}
/**
 * @api private
 */ module.exports = $b7838b9c7bc46d30$var$JsonParser;

});

parcelRegister("cwJjn", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");

var $hIq4q = parcelRequire("hIq4q");
/**
 * Prepend prefix defined by API model to endpoint that's already
 * constructed. This feature does not apply to operations using
 * endpoint discovery and can be disabled.
 * @api private
 */ function $91eb9f1f6176cbfc$var$populateHostPrefix(request) {
    var enabled = request.service.config.hostPrefixEnabled;
    if (!enabled) return request;
    var operationModel = request.service.api.operations[request.operation];
    //don't marshal host prefix when operation has endpoint discovery traits
    if ($91eb9f1f6176cbfc$var$hasEndpointDiscover(request)) return request;
    if (operationModel.endpoint && operationModel.endpoint.hostPrefix) {
        var hostPrefixNotation = operationModel.endpoint.hostPrefix;
        var hostPrefix = $91eb9f1f6176cbfc$var$expandHostPrefix(hostPrefixNotation, request.params, operationModel.input);
        $91eb9f1f6176cbfc$var$prependEndpointPrefix(request.httpRequest.endpoint, hostPrefix);
        $91eb9f1f6176cbfc$var$validateHostname(request.httpRequest.endpoint.hostname);
    }
    return request;
}
/**
 * @api private
 */ function $91eb9f1f6176cbfc$var$hasEndpointDiscover(request) {
    var api = request.service.api;
    var operationModel = api.operations[request.operation];
    var isEndpointOperation = api.endpointOperation && api.endpointOperation === $i3HcT.string.lowerFirst(operationModel.name);
    return operationModel.endpointDiscoveryRequired !== 'NULL' || isEndpointOperation === true;
}
/**
 * @api private
 */ function $91eb9f1f6176cbfc$var$expandHostPrefix(hostPrefixNotation, params, shape) {
    $i3HcT.each(shape.members, function(name, member) {
        if (member.hostLabel === true) {
            if (typeof params[name] !== 'string' || params[name] === '') throw $i3HcT.error(new Error(), {
                message: 'Parameter ' + name + ' should be a non-empty string.',
                code: 'InvalidParameter'
            });
            var regex = new RegExp('\\{' + name + '\\}', 'g');
            hostPrefixNotation = hostPrefixNotation.replace(regex, params[name]);
        }
    });
    return hostPrefixNotation;
}
/**
 * @api private
 */ function $91eb9f1f6176cbfc$var$prependEndpointPrefix(endpoint, prefix) {
    if (endpoint.host) endpoint.host = prefix + endpoint.host;
    if (endpoint.hostname) endpoint.hostname = prefix + endpoint.hostname;
}
/**
 * @api private
 */ function $91eb9f1f6176cbfc$var$validateHostname(hostname) {
    var labels = hostname.split('.');
    //Reference: https://tools.ietf.org/html/rfc1123#section-2
    var hostPattern = /^[a-zA-Z0-9]{1}$|^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$/;
    $i3HcT.arrayEach(labels, function(label) {
        if (!label.length || label.length < 1 || label.length > 63) throw $i3HcT.error(new Error(), {
            code: 'ValidationError',
            message: 'Hostname label length should be between 1 to 63 characters, inclusive.'
        });
        if (!hostPattern.test(label)) throw $hIq4q.util.error(new Error(), {
            code: 'ValidationError',
            message: label + ' is not hostname compatible.'
        });
    });
}
module.exports = {
    populateHostPrefix: $91eb9f1f6176cbfc$var$populateHostPrefix
};

});


parcelRegister("iqzj9", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");

var $i3HcT = parcelRequire("i3HcT");

var $3W6j2 = parcelRequire("3W6j2");

var $kMCY1 = parcelRequire("kMCY1");

var $cwJjn = parcelRequire("cwJjn");
var $d6a60b16c0b46558$require$populateHostPrefix = $cwJjn.populateHostPrefix;
function $d6a60b16c0b46558$var$buildRequest(req) {
    var operation = req.service.api.operations[req.operation];
    var httpRequest = req.httpRequest;
    httpRequest.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8';
    httpRequest.params = {
        Version: req.service.api.apiVersion,
        Action: operation.name
    };
    // convert the request parameters into a list of query params,
    // e.g. Deeply.NestedParam.0.Name=value
    var builder = new $3W6j2();
    builder.serialize(req.params, operation.input, function(name, value) {
        httpRequest.params[name] = value;
    });
    httpRequest.body = $i3HcT.queryParamsToString(httpRequest.params);
    $d6a60b16c0b46558$require$populateHostPrefix(req);
}
function $d6a60b16c0b46558$var$extractError(resp) {
    var data, body = resp.httpResponse.body.toString();
    if (body.match('<UnknownOperationException')) data = {
        Code: 'UnknownOperation',
        Message: 'Unknown operation ' + resp.request.operation
    };
    else try {
        data = new $hIq4q.XML.Parser().parse(body);
    } catch (e) {
        data = {
            Code: resp.httpResponse.statusCode,
            Message: resp.httpResponse.statusMessage
        };
    }
    if (data.requestId && !resp.requestId) resp.requestId = data.requestId;
    if (data.Errors) data = data.Errors;
    if (data.Error) data = data.Error;
    if (data.Code) resp.error = $i3HcT.error(new Error(), {
        code: data.Code,
        message: data.Message
    });
    else resp.error = $i3HcT.error(new Error(), {
        code: resp.httpResponse.statusCode,
        message: null
    });
}
function $d6a60b16c0b46558$var$extractData(resp) {
    var req = resp.request;
    var operation = req.service.api.operations[req.operation];
    var shape = operation.output || {};
    var origRules = shape;
    if (origRules.resultWrapper) {
        var tmp = $kMCY1.create({
            type: 'structure'
        });
        tmp.members[origRules.resultWrapper] = shape;
        tmp.memberNames = [
            origRules.resultWrapper
        ];
        $i3HcT.property(shape, 'name', shape.resultWrapper);
        shape = tmp;
    }
    var parser = new $hIq4q.XML.Parser();
    // TODO: Refactor XML Parser to parse RequestId from response.
    if (shape && shape.members && !shape.members._XAMZRequestId) {
        var requestIdShape = $kMCY1.create({
            type: 'string'
        }, {
            api: {
                protocol: 'query'
            }
        }, 'requestId');
        shape.members._XAMZRequestId = requestIdShape;
    }
    var data = parser.parse(resp.httpResponse.body.toString(), shape);
    resp.requestId = data._XAMZRequestId || data.requestId;
    if (data._XAMZRequestId) delete data._XAMZRequestId;
    if (origRules.resultWrapper) {
        if (data[origRules.resultWrapper]) {
            $i3HcT.update(data, data[origRules.resultWrapper]);
            delete data[origRules.resultWrapper];
        }
    }
    resp.data = data;
}
/**
 * @api private
 */ module.exports = {
    buildRequest: $d6a60b16c0b46558$var$buildRequest,
    extractError: $d6a60b16c0b46558$var$extractError,
    extractData: $d6a60b16c0b46558$var$extractData
};

});
parcelRegister("3W6j2", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");
function $2ddbae24f2c753f0$var$QueryParamSerializer() {}
$2ddbae24f2c753f0$var$QueryParamSerializer.prototype.serialize = function(params, shape, fn) {
    $2ddbae24f2c753f0$var$serializeStructure('', params, shape, fn);
};
function $2ddbae24f2c753f0$var$ucfirst(shape) {
    if (shape.isQueryName || shape.api.protocol !== 'ec2') return shape.name;
    else return shape.name[0].toUpperCase() + shape.name.substr(1);
}
function $2ddbae24f2c753f0$var$serializeStructure(prefix, struct, rules, fn) {
    $i3HcT.each(rules.members, function(name, member) {
        var value = struct[name];
        if (value === null || value === undefined) return;
        var memberName = $2ddbae24f2c753f0$var$ucfirst(member);
        memberName = prefix ? prefix + '.' + memberName : memberName;
        $2ddbae24f2c753f0$var$serializeMember(memberName, value, member, fn);
    });
}
function $2ddbae24f2c753f0$var$serializeMap(name, map, rules, fn) {
    var i = 1;
    $i3HcT.each(map, function(key, value) {
        var prefix = rules.flattened ? '.' : '.entry.';
        var position = prefix + i++ + '.';
        var keyName = position + (rules.key.name || 'key');
        var valueName = position + (rules.value.name || 'value');
        $2ddbae24f2c753f0$var$serializeMember(name + keyName, key, rules.key, fn);
        $2ddbae24f2c753f0$var$serializeMember(name + valueName, value, rules.value, fn);
    });
}
function $2ddbae24f2c753f0$var$serializeList(name, list, rules, fn) {
    var memberRules = rules.member || {};
    if (list.length === 0) {
        if (rules.api.protocol !== 'ec2') fn.call(this, name, null);
        return;
    }
    $i3HcT.arrayEach(list, function(v, n) {
        var suffix = '.' + (n + 1);
        if (rules.api.protocol === 'ec2') // Do nothing for EC2
        suffix = suffix + ''; // make linter happy
        else if (rules.flattened) {
            if (memberRules.name) {
                var parts = name.split('.');
                parts.pop();
                parts.push($2ddbae24f2c753f0$var$ucfirst(memberRules));
                name = parts.join('.');
            }
        } else suffix = '.' + (memberRules.name ? memberRules.name : 'member') + suffix;
        $2ddbae24f2c753f0$var$serializeMember(name + suffix, v, memberRules, fn);
    });
}
function $2ddbae24f2c753f0$var$serializeMember(name, value, rules, fn) {
    if (value === null || value === undefined) return;
    if (rules.type === 'structure') $2ddbae24f2c753f0$var$serializeStructure(name, value, rules, fn);
    else if (rules.type === 'list') $2ddbae24f2c753f0$var$serializeList(name, value, rules, fn);
    else if (rules.type === 'map') $2ddbae24f2c753f0$var$serializeMap(name, value, rules, fn);
    else fn(name, rules.toWireFormat(value).toString());
}
/**
 * @api private
 */ module.exports = $2ddbae24f2c753f0$var$QueryParamSerializer;

});

parcelRegister("kMCY1", function(module, exports) {

var $4A0gN = parcelRequire("4A0gN");

var $i3HcT = parcelRequire("i3HcT");
function $f2168468902c94ed$var$property(obj, name, value) {
    if (value !== null && value !== undefined) $i3HcT.property.apply(this, arguments);
}
function $f2168468902c94ed$var$memoizedProperty(obj, name) {
    if (!obj.constructor.prototype[name]) $i3HcT.memoizedProperty.apply(this, arguments);
}
function $f2168468902c94ed$var$Shape(shape, options, memberName) {
    options = options || {};
    $f2168468902c94ed$var$property(this, 'shape', shape.shape);
    $f2168468902c94ed$var$property(this, 'api', options.api, false);
    $f2168468902c94ed$var$property(this, 'type', shape.type);
    $f2168468902c94ed$var$property(this, 'enum', shape.enum);
    $f2168468902c94ed$var$property(this, 'min', shape.min);
    $f2168468902c94ed$var$property(this, 'max', shape.max);
    $f2168468902c94ed$var$property(this, 'pattern', shape.pattern);
    $f2168468902c94ed$var$property(this, 'location', shape.location || this.location || 'body');
    $f2168468902c94ed$var$property(this, 'name', this.name || shape.xmlName || shape.queryName || shape.locationName || memberName);
    $f2168468902c94ed$var$property(this, 'isStreaming', shape.streaming || this.isStreaming || false);
    $f2168468902c94ed$var$property(this, 'requiresLength', shape.requiresLength, false);
    $f2168468902c94ed$var$property(this, 'isComposite', shape.isComposite || false);
    $f2168468902c94ed$var$property(this, 'isShape', true, false);
    $f2168468902c94ed$var$property(this, 'isQueryName', Boolean(shape.queryName), false);
    $f2168468902c94ed$var$property(this, 'isLocationName', Boolean(shape.locationName), false);
    $f2168468902c94ed$var$property(this, 'isIdempotent', shape.idempotencyToken === true);
    $f2168468902c94ed$var$property(this, 'isJsonValue', shape.jsonvalue === true);
    $f2168468902c94ed$var$property(this, 'isSensitive', shape.sensitive === true || shape.prototype && shape.prototype.sensitive === true);
    $f2168468902c94ed$var$property(this, 'isEventStream', Boolean(shape.eventstream), false);
    $f2168468902c94ed$var$property(this, 'isEvent', Boolean(shape.event), false);
    $f2168468902c94ed$var$property(this, 'isEventPayload', Boolean(shape.eventpayload), false);
    $f2168468902c94ed$var$property(this, 'isEventHeader', Boolean(shape.eventheader), false);
    $f2168468902c94ed$var$property(this, 'isTimestampFormatSet', Boolean(shape.timestampFormat) || shape.prototype && shape.prototype.isTimestampFormatSet === true, false);
    $f2168468902c94ed$var$property(this, 'endpointDiscoveryId', Boolean(shape.endpointdiscoveryid), false);
    $f2168468902c94ed$var$property(this, 'hostLabel', Boolean(shape.hostLabel), false);
    if (options.documentation) {
        $f2168468902c94ed$var$property(this, 'documentation', shape.documentation);
        $f2168468902c94ed$var$property(this, 'documentationUrl', shape.documentationUrl);
    }
    if (shape.xmlAttribute) $f2168468902c94ed$var$property(this, 'isXmlAttribute', shape.xmlAttribute || false);
    // type conversion and parsing
    $f2168468902c94ed$var$property(this, 'defaultValue', null);
    this.toWireFormat = function(value) {
        if (value === null || value === undefined) return '';
        return value;
    };
    this.toType = function(value) {
        return value;
    };
}
/**
 * @api private
 */ $f2168468902c94ed$var$Shape.normalizedTypes = {
    character: 'string',
    double: 'float',
    long: 'integer',
    short: 'integer',
    biginteger: 'integer',
    bigdecimal: 'float',
    blob: 'binary'
};
/**
 * @api private
 */ $f2168468902c94ed$var$Shape.types = {
    'structure': $f2168468902c94ed$var$StructureShape,
    'list': $f2168468902c94ed$var$ListShape,
    'map': $f2168468902c94ed$var$MapShape,
    'boolean': $f2168468902c94ed$var$BooleanShape,
    'timestamp': $f2168468902c94ed$var$TimestampShape,
    'float': $f2168468902c94ed$var$FloatShape,
    'integer': $f2168468902c94ed$var$IntegerShape,
    'string': $f2168468902c94ed$var$StringShape,
    'base64': $f2168468902c94ed$var$Base64Shape,
    'binary': $f2168468902c94ed$var$BinaryShape
};
$f2168468902c94ed$var$Shape.resolve = function resolve(shape, options) {
    if (shape.shape) {
        var refShape = options.api.shapes[shape.shape];
        if (!refShape) throw new Error('Cannot find shape reference: ' + shape.shape);
        return refShape;
    } else return null;
};
$f2168468902c94ed$var$Shape.create = function create(shape, options, memberName) {
    if (shape.isShape) return shape;
    var refShape = $f2168468902c94ed$var$Shape.resolve(shape, options);
    if (refShape) {
        var filteredKeys = Object.keys(shape);
        if (!options.documentation) filteredKeys = filteredKeys.filter(function(name) {
            return !name.match(/documentation/);
        });
        // create an inline shape with extra members
        var InlineShape = function() {
            refShape.constructor.call(this, shape, options, memberName);
        };
        InlineShape.prototype = refShape;
        return new InlineShape();
    } else {
        // set type if not set
        if (!shape.type) {
            if (shape.members) shape.type = 'structure';
            else if (shape.member) shape.type = 'list';
            else if (shape.key) shape.type = 'map';
            else shape.type = 'string';
        }
        // normalize types
        var origType = shape.type;
        if ($f2168468902c94ed$var$Shape.normalizedTypes[shape.type]) shape.type = $f2168468902c94ed$var$Shape.normalizedTypes[shape.type];
        if ($f2168468902c94ed$var$Shape.types[shape.type]) return new $f2168468902c94ed$var$Shape.types[shape.type](shape, options, memberName);
        else throw new Error('Unrecognized shape type: ' + origType);
    }
};
function $f2168468902c94ed$var$CompositeShape(shape) {
    $f2168468902c94ed$var$Shape.apply(this, arguments);
    $f2168468902c94ed$var$property(this, 'isComposite', true);
    if (shape.flattened) $f2168468902c94ed$var$property(this, 'flattened', shape.flattened || false);
}
function $f2168468902c94ed$var$StructureShape(shape, options) {
    var self = this;
    var requiredMap = null, firstInit = !this.isShape;
    $f2168468902c94ed$var$CompositeShape.apply(this, arguments);
    if (firstInit) {
        $f2168468902c94ed$var$property(this, 'defaultValue', function() {
            return {};
        });
        $f2168468902c94ed$var$property(this, 'members', {});
        $f2168468902c94ed$var$property(this, 'memberNames', []);
        $f2168468902c94ed$var$property(this, 'required', []);
        $f2168468902c94ed$var$property(this, 'isRequired', function() {
            return false;
        });
        $f2168468902c94ed$var$property(this, 'isDocument', Boolean(shape.document));
    }
    if (shape.members) {
        $f2168468902c94ed$var$property(this, 'members', new $4A0gN(shape.members, options, function(name, member) {
            return $f2168468902c94ed$var$Shape.create(member, options, name);
        }));
        $f2168468902c94ed$var$memoizedProperty(this, 'memberNames', function() {
            return shape.xmlOrder || Object.keys(shape.members);
        });
        if (shape.event) {
            $f2168468902c94ed$var$memoizedProperty(this, 'eventPayloadMemberName', function() {
                var members = self.members;
                var memberNames = self.memberNames;
                // iterate over members to find ones that are event payloads
                for(var i = 0, iLen = memberNames.length; i < iLen; i++){
                    if (members[memberNames[i]].isEventPayload) return memberNames[i];
                }
            });
            $f2168468902c94ed$var$memoizedProperty(this, 'eventHeaderMemberNames', function() {
                var members = self.members;
                var memberNames = self.memberNames;
                var eventHeaderMemberNames = [];
                // iterate over members to find ones that are event headers
                for(var i = 0, iLen = memberNames.length; i < iLen; i++)if (members[memberNames[i]].isEventHeader) eventHeaderMemberNames.push(memberNames[i]);
                return eventHeaderMemberNames;
            });
        }
    }
    if (shape.required) {
        $f2168468902c94ed$var$property(this, 'required', shape.required);
        $f2168468902c94ed$var$property(this, 'isRequired', function(name) {
            if (!requiredMap) {
                requiredMap = {};
                for(var i = 0; i < shape.required.length; i++)requiredMap[shape.required[i]] = true;
            }
            return requiredMap[name];
        }, false, true);
    }
    $f2168468902c94ed$var$property(this, 'resultWrapper', shape.resultWrapper || null);
    if (shape.payload) $f2168468902c94ed$var$property(this, 'payload', shape.payload);
    if (typeof shape.xmlNamespace === 'string') $f2168468902c94ed$var$property(this, 'xmlNamespaceUri', shape.xmlNamespace);
    else if (typeof shape.xmlNamespace === 'object') {
        $f2168468902c94ed$var$property(this, 'xmlNamespacePrefix', shape.xmlNamespace.prefix);
        $f2168468902c94ed$var$property(this, 'xmlNamespaceUri', shape.xmlNamespace.uri);
    }
}
function $f2168468902c94ed$var$ListShape(shape, options) {
    var self = this, firstInit = !this.isShape;
    $f2168468902c94ed$var$CompositeShape.apply(this, arguments);
    if (firstInit) $f2168468902c94ed$var$property(this, 'defaultValue', function() {
        return [];
    });
    if (shape.member) $f2168468902c94ed$var$memoizedProperty(this, 'member', function() {
        return $f2168468902c94ed$var$Shape.create(shape.member, options);
    });
    if (this.flattened) {
        var oldName = this.name;
        $f2168468902c94ed$var$memoizedProperty(this, 'name', function() {
            return self.member.name || oldName;
        });
    }
}
function $f2168468902c94ed$var$MapShape(shape, options) {
    var firstInit = !this.isShape;
    $f2168468902c94ed$var$CompositeShape.apply(this, arguments);
    if (firstInit) {
        $f2168468902c94ed$var$property(this, 'defaultValue', function() {
            return {};
        });
        $f2168468902c94ed$var$property(this, 'key', $f2168468902c94ed$var$Shape.create({
            type: 'string'
        }, options));
        $f2168468902c94ed$var$property(this, 'value', $f2168468902c94ed$var$Shape.create({
            type: 'string'
        }, options));
    }
    if (shape.key) $f2168468902c94ed$var$memoizedProperty(this, 'key', function() {
        return $f2168468902c94ed$var$Shape.create(shape.key, options);
    });
    if (shape.value) $f2168468902c94ed$var$memoizedProperty(this, 'value', function() {
        return $f2168468902c94ed$var$Shape.create(shape.value, options);
    });
}
function $f2168468902c94ed$var$TimestampShape(shape) {
    var self = this;
    $f2168468902c94ed$var$Shape.apply(this, arguments);
    if (shape.timestampFormat) $f2168468902c94ed$var$property(this, 'timestampFormat', shape.timestampFormat);
    else if (self.isTimestampFormatSet && this.timestampFormat) $f2168468902c94ed$var$property(this, 'timestampFormat', this.timestampFormat);
    else if (this.location === 'header') $f2168468902c94ed$var$property(this, 'timestampFormat', 'rfc822');
    else if (this.location === 'querystring') $f2168468902c94ed$var$property(this, 'timestampFormat', 'iso8601');
    else if (this.api) switch(this.api.protocol){
        case 'json':
        case 'rest-json':
            $f2168468902c94ed$var$property(this, 'timestampFormat', 'unixTimestamp');
            break;
        case 'rest-xml':
        case 'query':
        case 'ec2':
            $f2168468902c94ed$var$property(this, 'timestampFormat', 'iso8601');
            break;
    }
    this.toType = function(value) {
        if (value === null || value === undefined) return null;
        if (typeof value.toUTCString === 'function') return value;
        return typeof value === 'string' || typeof value === 'number' ? $i3HcT.date.parseTimestamp(value) : null;
    };
    this.toWireFormat = function(value) {
        return $i3HcT.date.format(value, self.timestampFormat);
    };
}
function $f2168468902c94ed$var$StringShape() {
    $f2168468902c94ed$var$Shape.apply(this, arguments);
    var nullLessProtocols = [
        'rest-xml',
        'query',
        'ec2'
    ];
    this.toType = function(value) {
        value = this.api && nullLessProtocols.indexOf(this.api.protocol) > -1 ? value || '' : value;
        if (this.isJsonValue) return JSON.parse(value);
        return value && typeof value.toString === 'function' ? value.toString() : value;
    };
    this.toWireFormat = function(value) {
        return this.isJsonValue ? JSON.stringify(value) : value;
    };
}
function $f2168468902c94ed$var$FloatShape() {
    $f2168468902c94ed$var$Shape.apply(this, arguments);
    this.toType = function(value) {
        if (value === null || value === undefined) return null;
        return parseFloat(value);
    };
    this.toWireFormat = this.toType;
}
function $f2168468902c94ed$var$IntegerShape() {
    $f2168468902c94ed$var$Shape.apply(this, arguments);
    this.toType = function(value) {
        if (value === null || value === undefined) return null;
        return parseInt(value, 10);
    };
    this.toWireFormat = this.toType;
}
function $f2168468902c94ed$var$BinaryShape() {
    $f2168468902c94ed$var$Shape.apply(this, arguments);
    this.toType = function(value) {
        var buf = $i3HcT.base64.decode(value);
        if (this.isSensitive && $i3HcT.isNode() && typeof $i3HcT.Buffer.alloc === 'function') {
            /* Node.js can create a Buffer that is not isolated.
   * i.e. buf.byteLength !== buf.buffer.byteLength
   * This means that the sensitive data is accessible to anyone with access to buf.buffer.
   * If this is the node shared Buffer, then other code within this process _could_ find this secret.
   * Copy sensitive data to an isolated Buffer and zero the sensitive data.
   * While this is safe to do here, copying this code somewhere else may produce unexpected results.
   */ var secureBuf = $i3HcT.Buffer.alloc(buf.length, buf);
            buf.fill(0);
            buf = secureBuf;
        }
        return buf;
    };
    this.toWireFormat = $i3HcT.base64.encode;
}
function $f2168468902c94ed$var$Base64Shape() {
    $f2168468902c94ed$var$BinaryShape.apply(this, arguments);
}
function $f2168468902c94ed$var$BooleanShape() {
    $f2168468902c94ed$var$Shape.apply(this, arguments);
    this.toType = function(value) {
        if (typeof value === 'boolean') return value;
        if (value === null || value === undefined) return null;
        return value === 'true';
    };
}
/**
 * @api private
 */ $f2168468902c94ed$var$Shape.shapes = {
    StructureShape: $f2168468902c94ed$var$StructureShape,
    ListShape: $f2168468902c94ed$var$ListShape,
    MapShape: $f2168468902c94ed$var$MapShape,
    StringShape: $f2168468902c94ed$var$StringShape,
    BooleanShape: $f2168468902c94ed$var$BooleanShape,
    Base64Shape: $f2168468902c94ed$var$Base64Shape
};
/**
 * @api private
 */ module.exports = $f2168468902c94ed$var$Shape;

});
parcelRegister("4A0gN", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");
var $355abbd419f31998$require$memoizedProperty = $i3HcT.memoizedProperty;
function $355abbd419f31998$var$memoize(name, value, factory, nameTr) {
    $355abbd419f31998$require$memoizedProperty(this, nameTr(name), function() {
        return factory(name, value);
    });
}
function $355abbd419f31998$var$Collection(iterable, options, factory, nameTr, callback) {
    nameTr = nameTr || String;
    var self = this;
    for(var id in iterable)if (Object.prototype.hasOwnProperty.call(iterable, id)) {
        $355abbd419f31998$var$memoize.call(self, id, iterable[id], factory, nameTr);
        if (callback) callback(id, iterable[id]);
    }
}
/**
 * @api private
 */ module.exports = $355abbd419f31998$var$Collection;

});



parcelRegister("gDGw5", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");

var $cwJjn = parcelRequire("cwJjn");
var $c1d144c5457c1772$require$populateHostPrefix = $cwJjn.populateHostPrefix;
function $c1d144c5457c1772$var$populateMethod(req) {
    req.httpRequest.method = req.service.api.operations[req.operation].httpMethod;
}
function $c1d144c5457c1772$var$generateURI(endpointPath, operationPath, input, params) {
    var uri = [
        endpointPath,
        operationPath
    ].join('/');
    uri = uri.replace(/\/+/g, '/');
    var queryString = {}, queryStringSet = false;
    $i3HcT.each(input.members, function(name, member) {
        var paramValue = params[name];
        if (paramValue === null || paramValue === undefined) return;
        if (member.location === 'uri') {
            var regex = new RegExp('\\{' + member.name + '(\\+)?\\}');
            uri = uri.replace(regex, function(_, plus) {
                var fn = plus ? $i3HcT.uriEscapePath : $i3HcT.uriEscape;
                return fn(String(paramValue));
            });
        } else if (member.location === 'querystring') {
            queryStringSet = true;
            if (member.type === 'list') queryString[member.name] = paramValue.map(function(val) {
                return $i3HcT.uriEscape(member.member.toWireFormat(val).toString());
            });
            else if (member.type === 'map') $i3HcT.each(paramValue, function(key, value) {
                if (Array.isArray(value)) queryString[key] = value.map(function(val) {
                    return $i3HcT.uriEscape(String(val));
                });
                else queryString[key] = $i3HcT.uriEscape(String(value));
            });
            else queryString[member.name] = $i3HcT.uriEscape(member.toWireFormat(paramValue).toString());
        }
    });
    if (queryStringSet) {
        uri += uri.indexOf('?') >= 0 ? '&' : '?';
        var parts = [];
        $i3HcT.arrayEach(Object.keys(queryString).sort(), function(key) {
            if (!Array.isArray(queryString[key])) queryString[key] = [
                queryString[key]
            ];
            for(var i = 0; i < queryString[key].length; i++)parts.push($i3HcT.uriEscape(String(key)) + '=' + queryString[key][i]);
        });
        uri += parts.join('&');
    }
    return uri;
}
function $c1d144c5457c1772$var$populateURI(req) {
    var operation = req.service.api.operations[req.operation];
    var input = operation.input;
    var uri = $c1d144c5457c1772$var$generateURI(req.httpRequest.endpoint.path, operation.httpPath, input, req.params);
    req.httpRequest.path = uri;
}
function $c1d144c5457c1772$var$populateHeaders(req) {
    var operation = req.service.api.operations[req.operation];
    $i3HcT.each(operation.input.members, function(name, member) {
        var value = req.params[name];
        if (value === null || value === undefined) return;
        if (member.location === 'headers' && member.type === 'map') $i3HcT.each(value, function(key, memberValue) {
            req.httpRequest.headers[member.name + key] = memberValue;
        });
        else if (member.location === 'header') {
            value = member.toWireFormat(value).toString();
            if (member.isJsonValue) value = $i3HcT.base64.encode(value);
            req.httpRequest.headers[member.name] = value;
        }
    });
}
function $c1d144c5457c1772$var$buildRequest(req) {
    $c1d144c5457c1772$var$populateMethod(req);
    $c1d144c5457c1772$var$populateURI(req);
    $c1d144c5457c1772$var$populateHeaders(req);
    $c1d144c5457c1772$require$populateHostPrefix(req);
}
function $c1d144c5457c1772$var$extractError() {}
function $c1d144c5457c1772$var$extractData(resp) {
    var req = resp.request;
    var data = {};
    var r = resp.httpResponse;
    var operation = req.service.api.operations[req.operation];
    var output = operation.output;
    // normalize headers names to lower-cased keys for matching
    var headers = {};
    $i3HcT.each(r.headers, function(k, v) {
        headers[k.toLowerCase()] = v;
    });
    $i3HcT.each(output.members, function(name, member) {
        var header = (member.name || name).toLowerCase();
        if (member.location === 'headers' && member.type === 'map') {
            data[name] = {};
            var location = member.isLocationName ? member.name : '';
            var pattern = new RegExp('^' + location + '(.+)', 'i');
            $i3HcT.each(r.headers, function(k, v) {
                var result = k.match(pattern);
                if (result !== null) data[name][result[1]] = v;
            });
        } else if (member.location === 'header') {
            if (headers[header] !== undefined) {
                var value = member.isJsonValue ? $i3HcT.base64.decode(headers[header]) : headers[header];
                data[name] = member.toType(value);
            }
        } else if (member.location === 'statusCode') data[name] = parseInt(r.statusCode, 10);
    });
    resp.data = data;
}
/**
 * @api private
 */ module.exports = {
    buildRequest: $c1d144c5457c1772$var$buildRequest,
    extractError: $c1d144c5457c1772$var$extractError,
    extractData: $c1d144c5457c1772$var$extractData,
    generateURI: $c1d144c5457c1772$var$generateURI
};

});

parcelRegister("hQdKL", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");

var $i3HcT = parcelRequire("i3HcT");

var $gDGw5 = parcelRequire("gDGw5");

var $4caHz = parcelRequire("4caHz");

var $1gBXL = parcelRequire("1gBXL");

var $fKQ4C = parcelRequire("fKQ4C");
var $cfd1f619c8e8ef71$var$METHODS_WITHOUT_BODY = [
    'GET',
    'HEAD',
    'DELETE'
];
function $cfd1f619c8e8ef71$var$unsetContentLength(req) {
    var payloadMember = $i3HcT.getRequestPayloadShape(req);
    if (payloadMember === undefined && $cfd1f619c8e8ef71$var$METHODS_WITHOUT_BODY.indexOf(req.httpRequest.method) >= 0) delete req.httpRequest.headers['Content-Length'];
}
function $cfd1f619c8e8ef71$var$populateBody(req) {
    var builder = new $1gBXL();
    var input = req.service.api.operations[req.operation].input;
    if (input.payload) {
        var params = {};
        var payloadShape = input.members[input.payload];
        params = req.params[input.payload];
        if (payloadShape.type === 'structure') {
            req.httpRequest.body = builder.build(params || {}, payloadShape);
            $cfd1f619c8e8ef71$var$applyContentTypeHeader(req);
        } else if (params !== undefined) {
            // non-JSON payload
            req.httpRequest.body = params;
            if (payloadShape.type === 'binary' || payloadShape.isStreaming) $cfd1f619c8e8ef71$var$applyContentTypeHeader(req, true);
        }
    } else {
        req.httpRequest.body = builder.build(req.params, input);
        $cfd1f619c8e8ef71$var$applyContentTypeHeader(req);
    }
}
function $cfd1f619c8e8ef71$var$applyContentTypeHeader(req, isBinary) {
    if (!req.httpRequest.headers['Content-Type']) {
        var type = isBinary ? 'binary/octet-stream' : 'application/json';
        req.httpRequest.headers['Content-Type'] = type;
    }
}
function $cfd1f619c8e8ef71$var$buildRequest(req) {
    $gDGw5.buildRequest(req);
    // never send body payload on GET/HEAD/DELETE
    if ($cfd1f619c8e8ef71$var$METHODS_WITHOUT_BODY.indexOf(req.httpRequest.method) < 0) $cfd1f619c8e8ef71$var$populateBody(req);
}
function $cfd1f619c8e8ef71$var$extractError(resp) {
    $4caHz.extractError(resp);
}
function $cfd1f619c8e8ef71$var$extractData(resp) {
    $gDGw5.extractData(resp);
    var req = resp.request;
    var operation = req.service.api.operations[req.operation];
    var rules = req.service.api.operations[req.operation].output || {};
    var parser;
    var hasEventOutput = operation.hasEventOutput;
    if (rules.payload) {
        var payloadMember = rules.members[rules.payload];
        var body = resp.httpResponse.body;
        if (payloadMember.isEventStream) {
            parser = new $fKQ4C();
            resp.data[rules.payload] = $i3HcT.createEventStream($hIq4q.HttpClient.streamsApiVersion === 2 ? resp.httpResponse.stream : body, parser, payloadMember);
        } else if (payloadMember.type === 'structure' || payloadMember.type === 'list') {
            var parser = new $fKQ4C();
            resp.data[rules.payload] = parser.parse(body, payloadMember);
        } else if (payloadMember.type === 'binary' || payloadMember.isStreaming) resp.data[rules.payload] = body;
        else resp.data[rules.payload] = payloadMember.toType(body);
    } else {
        var data = resp.data;
        $4caHz.extractData(resp);
        resp.data = $i3HcT.merge(data, resp.data);
    }
}
/**
 * @api private
 */ module.exports = {
    buildRequest: $cfd1f619c8e8ef71$var$buildRequest,
    extractError: $cfd1f619c8e8ef71$var$extractError,
    extractData: $cfd1f619c8e8ef71$var$extractData,
    unsetContentLength: $cfd1f619c8e8ef71$var$unsetContentLength
};

});

parcelRegister("2OT3o", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");

var $i3HcT = parcelRequire("i3HcT");

var $gDGw5 = parcelRequire("gDGw5");
function $20daf4cdab65d94d$var$populateBody(req) {
    var input = req.service.api.operations[req.operation].input;
    var builder = new $hIq4q.XML.Builder();
    var params = req.params;
    var payload = input.payload;
    if (payload) {
        var payloadMember = input.members[payload];
        params = params[payload];
        if (params === undefined) return;
        if (payloadMember.type === 'structure') {
            var rootElement = payloadMember.name;
            req.httpRequest.body = builder.toXML(params, payloadMember, rootElement, true);
        } else req.httpRequest.body = params;
    } else req.httpRequest.body = builder.toXML(params, input, input.name || input.shape || $i3HcT.string.upperFirst(req.operation) + 'Request');
}
function $20daf4cdab65d94d$var$buildRequest(req) {
    $gDGw5.buildRequest(req);
    // never send body payload on GET/HEAD
    if ([
        'GET',
        'HEAD'
    ].indexOf(req.httpRequest.method) < 0) $20daf4cdab65d94d$var$populateBody(req);
}
function $20daf4cdab65d94d$var$extractError(resp) {
    $gDGw5.extractError(resp);
    var data;
    try {
        data = new $hIq4q.XML.Parser().parse(resp.httpResponse.body.toString());
    } catch (e) {
        data = {
            Code: resp.httpResponse.statusCode,
            Message: resp.httpResponse.statusMessage
        };
    }
    if (data.Errors) data = data.Errors;
    if (data.Error) data = data.Error;
    if (data.Code) resp.error = $i3HcT.error(new Error(), {
        code: data.Code,
        message: data.Message
    });
    else resp.error = $i3HcT.error(new Error(), {
        code: resp.httpResponse.statusCode,
        message: null
    });
}
function $20daf4cdab65d94d$var$extractData(resp) {
    $gDGw5.extractData(resp);
    var parser;
    var req = resp.request;
    var body = resp.httpResponse.body;
    var operation = req.service.api.operations[req.operation];
    var output = operation.output;
    var hasEventOutput = operation.hasEventOutput;
    var payload = output.payload;
    if (payload) {
        var payloadMember = output.members[payload];
        if (payloadMember.isEventStream) {
            parser = new $hIq4q.XML.Parser();
            resp.data[payload] = $i3HcT.createEventStream($hIq4q.HttpClient.streamsApiVersion === 2 ? resp.httpResponse.stream : resp.httpResponse.body, parser, payloadMember);
        } else if (payloadMember.type === 'structure') {
            parser = new $hIq4q.XML.Parser();
            resp.data[payload] = parser.parse(body.toString(), payloadMember);
        } else if (payloadMember.type === 'binary' || payloadMember.isStreaming) resp.data[payload] = body;
        else resp.data[payload] = payloadMember.toType(body);
    } else if (body.length > 0) {
        parser = new $hIq4q.XML.Parser();
        var data = parser.parse(body.toString(), output);
        $i3HcT.update(resp.data, data);
    }
}
/**
 * @api private
 */ module.exports = {
    buildRequest: $20daf4cdab65d94d$var$buildRequest,
    extractError: $20daf4cdab65d94d$var$extractError,
    extractData: $20daf4cdab65d94d$var$extractData
};

});

parcelRegister("6FvXS", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");

var $3NHeH = parcelRequire("3NHeH");
var $4daf5df32e6ad805$require$XmlNode = $3NHeH.XmlNode;

var $lohOn = parcelRequire("lohOn");
var $4daf5df32e6ad805$require$XmlText = $lohOn.XmlText;
function $4daf5df32e6ad805$var$XmlBuilder() {}
$4daf5df32e6ad805$var$XmlBuilder.prototype.toXML = function(params, shape, rootElement, noEmpty) {
    var xml = new $4daf5df32e6ad805$require$XmlNode(rootElement);
    $4daf5df32e6ad805$var$applyNamespaces(xml, shape, true);
    $4daf5df32e6ad805$var$serialize(xml, params, shape);
    return xml.children.length > 0 || noEmpty ? xml.toString() : '';
};
function $4daf5df32e6ad805$var$serialize(xml, value, shape) {
    switch(shape.type){
        case 'structure':
            return $4daf5df32e6ad805$var$serializeStructure(xml, value, shape);
        case 'map':
            return $4daf5df32e6ad805$var$serializeMap(xml, value, shape);
        case 'list':
            return $4daf5df32e6ad805$var$serializeList(xml, value, shape);
        default:
            return $4daf5df32e6ad805$var$serializeScalar(xml, value, shape);
    }
}
function $4daf5df32e6ad805$var$serializeStructure(xml, params, shape) {
    $i3HcT.arrayEach(shape.memberNames, function(memberName) {
        var memberShape = shape.members[memberName];
        if (memberShape.location !== 'body') return;
        var value = params[memberName];
        var name = memberShape.name;
        if (value !== undefined && value !== null) {
            if (memberShape.isXmlAttribute) xml.addAttribute(name, value);
            else if (memberShape.flattened) $4daf5df32e6ad805$var$serialize(xml, value, memberShape);
            else {
                var element = new $4daf5df32e6ad805$require$XmlNode(name);
                xml.addChildNode(element);
                $4daf5df32e6ad805$var$applyNamespaces(element, memberShape);
                $4daf5df32e6ad805$var$serialize(element, value, memberShape);
            }
        }
    });
}
function $4daf5df32e6ad805$var$serializeMap(xml, map, shape) {
    var xmlKey = shape.key.name || 'key';
    var xmlValue = shape.value.name || 'value';
    $i3HcT.each(map, function(key, value) {
        var entry = new $4daf5df32e6ad805$require$XmlNode(shape.flattened ? shape.name : 'entry');
        xml.addChildNode(entry);
        var entryKey = new $4daf5df32e6ad805$require$XmlNode(xmlKey);
        var entryValue = new $4daf5df32e6ad805$require$XmlNode(xmlValue);
        entry.addChildNode(entryKey);
        entry.addChildNode(entryValue);
        $4daf5df32e6ad805$var$serialize(entryKey, key, shape.key);
        $4daf5df32e6ad805$var$serialize(entryValue, value, shape.value);
    });
}
function $4daf5df32e6ad805$var$serializeList(xml, list, shape) {
    if (shape.flattened) $i3HcT.arrayEach(list, function(value) {
        var name = shape.member.name || shape.name;
        var element = new $4daf5df32e6ad805$require$XmlNode(name);
        xml.addChildNode(element);
        $4daf5df32e6ad805$var$serialize(element, value, shape.member);
    });
    else $i3HcT.arrayEach(list, function(value) {
        var name = shape.member.name || 'member';
        var element = new $4daf5df32e6ad805$require$XmlNode(name);
        xml.addChildNode(element);
        $4daf5df32e6ad805$var$serialize(element, value, shape.member);
    });
}
function $4daf5df32e6ad805$var$serializeScalar(xml, value, shape) {
    xml.addChildNode(new $4daf5df32e6ad805$require$XmlText(shape.toWireFormat(value)));
}
function $4daf5df32e6ad805$var$applyNamespaces(xml, shape, isRoot) {
    var uri, prefix = 'xmlns';
    if (shape.xmlNamespaceUri) {
        uri = shape.xmlNamespaceUri;
        if (shape.xmlNamespacePrefix) prefix += ':' + shape.xmlNamespacePrefix;
    } else if (isRoot && shape.api.xmlNamespaceUri) uri = shape.api.xmlNamespaceUri;
    if (uri) xml.addAttribute(prefix, uri);
}
/**
 * @api private
 */ module.exports = $4daf5df32e6ad805$var$XmlBuilder;

});
parcelRegister("3NHeH", function(module, exports) {

var $gxRLb = parcelRequire("gxRLb");
var $2c477c810ecd7edd$require$escapeAttribute = $gxRLb.escapeAttribute;
/**
 * Represents an XML node.
 * @api private
 */ function $2c477c810ecd7edd$var$XmlNode(name, children) {
    if (children === void 0) children = [];
    this.name = name;
    this.children = children;
    this.attributes = {};
}
$2c477c810ecd7edd$var$XmlNode.prototype.addAttribute = function(name, value) {
    this.attributes[name] = value;
    return this;
};
$2c477c810ecd7edd$var$XmlNode.prototype.addChildNode = function(child) {
    this.children.push(child);
    return this;
};
$2c477c810ecd7edd$var$XmlNode.prototype.removeAttribute = function(name) {
    delete this.attributes[name];
    return this;
};
$2c477c810ecd7edd$var$XmlNode.prototype.toString = function() {
    var hasChildren = Boolean(this.children.length);
    var xmlText = '<' + this.name;
    // add attributes
    var attributes = this.attributes;
    for(var i = 0, attributeNames = Object.keys(attributes); i < attributeNames.length; i++){
        var attributeName = attributeNames[i];
        var attribute = attributes[attributeName];
        if (typeof attribute !== 'undefined' && attribute !== null) xmlText += ' ' + attributeName + '=\"' + $2c477c810ecd7edd$require$escapeAttribute('' + attribute) + '\"';
    }
    return xmlText += !hasChildren ? '/>' : '>' + this.children.map(function(c) {
        return c.toString();
    }).join('') + '</' + this.name + '>';
};
/**
 * @api private
 */ module.exports = {
    XmlNode: $2c477c810ecd7edd$var$XmlNode
};

});
parcelRegister("gxRLb", function(module, exports) {
/**
 * Escapes characters that can not be in an XML attribute.
 */ function $c0b96e0a783b7242$var$escapeAttribute(value) {
    return value.replace(/&/g, '&amp;').replace(/'/g, '&apos;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
/**
 * @api private
 */ module.exports = {
    escapeAttribute: $c0b96e0a783b7242$var$escapeAttribute
};

});


parcelRegister("lohOn", function(module, exports) {

var $iHF5l = parcelRequire("iHF5l");
var $f929a7dedbb5ae45$require$escapeElement = $iHF5l.escapeElement;
/**
 * Represents an XML text value.
 * @api private
 */ function $f929a7dedbb5ae45$var$XmlText(value) {
    this.value = value;
}
$f929a7dedbb5ae45$var$XmlText.prototype.toString = function() {
    return $f929a7dedbb5ae45$require$escapeElement('' + this.value);
};
/**
 * @api private
 */ module.exports = {
    XmlText: $f929a7dedbb5ae45$var$XmlText
};

});
parcelRegister("iHF5l", function(module, exports) {
/**
 * Escapes characters that can not be in an XML element.
 */ function $d9dc1ccc577bc166$var$escapeElement(value) {
    return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#x0D;').replace(/\n/g, '&#x0A;').replace(/\u0085/g, '&#x85;').replace(/\u2028/, '&#x2028;');
}
/**
 * @api private
 */ module.exports = {
    escapeElement: $d9dc1ccc577bc166$var$escapeElement
};

});



parcelRegister("g9WzK", function(module, exports) {

var $4A0gN = parcelRequire("4A0gN");

var $lk1Cc = parcelRequire("lk1Cc");

var $kMCY1 = parcelRequire("kMCY1");

var $kBz1Z = parcelRequire("kBz1Z");

var $3uIxQ = parcelRequire("3uIxQ");

var $khYer = parcelRequire("khYer");

var $i3HcT = parcelRequire("i3HcT");
var $0309355ce486d148$var$property = $i3HcT.property;
var $0309355ce486d148$var$memoizedProperty = $i3HcT.memoizedProperty;
function $0309355ce486d148$var$Api(api, options) {
    var self = this;
    api = api || {};
    options = options || {};
    options.api = this;
    api.metadata = api.metadata || {};
    var serviceIdentifier = options.serviceIdentifier;
    delete options.serviceIdentifier;
    $0309355ce486d148$var$property(this, 'isApi', true, false);
    $0309355ce486d148$var$property(this, 'apiVersion', api.metadata.apiVersion);
    $0309355ce486d148$var$property(this, 'endpointPrefix', api.metadata.endpointPrefix);
    $0309355ce486d148$var$property(this, 'signingName', api.metadata.signingName);
    $0309355ce486d148$var$property(this, 'globalEndpoint', api.metadata.globalEndpoint);
    $0309355ce486d148$var$property(this, 'signatureVersion', api.metadata.signatureVersion);
    $0309355ce486d148$var$property(this, 'jsonVersion', api.metadata.jsonVersion);
    $0309355ce486d148$var$property(this, 'targetPrefix', api.metadata.targetPrefix);
    $0309355ce486d148$var$property(this, 'protocol', api.metadata.protocol);
    $0309355ce486d148$var$property(this, 'timestampFormat', api.metadata.timestampFormat);
    $0309355ce486d148$var$property(this, 'xmlNamespaceUri', api.metadata.xmlNamespace);
    $0309355ce486d148$var$property(this, 'abbreviation', api.metadata.serviceAbbreviation);
    $0309355ce486d148$var$property(this, 'fullName', api.metadata.serviceFullName);
    $0309355ce486d148$var$property(this, 'serviceId', api.metadata.serviceId);
    if (serviceIdentifier && $khYer[serviceIdentifier]) $0309355ce486d148$var$property(this, 'xmlNoDefaultLists', $khYer[serviceIdentifier].xmlNoDefaultLists, false);
    $0309355ce486d148$var$memoizedProperty(this, 'className', function() {
        var name = api.metadata.serviceAbbreviation || api.metadata.serviceFullName;
        if (!name) return null;
        name = name.replace(/^Amazon|AWS\s*|\(.*|\s+|\W+/g, '');
        if (name === 'ElasticLoadBalancing') name = 'ELB';
        return name;
    });
    function addEndpointOperation(name, operation) {
        if (operation.endpointoperation === true) $0309355ce486d148$var$property(self, 'endpointOperation', $i3HcT.string.lowerFirst(name));
        if (operation.endpointdiscovery && !self.hasRequiredEndpointDiscovery) $0309355ce486d148$var$property(self, 'hasRequiredEndpointDiscovery', operation.endpointdiscovery.required === true);
    }
    $0309355ce486d148$var$property(this, 'operations', new $4A0gN(api.operations, options, function(name, operation) {
        return new $lk1Cc(name, operation, options);
    }, $i3HcT.string.lowerFirst, addEndpointOperation));
    $0309355ce486d148$var$property(this, 'shapes', new $4A0gN(api.shapes, options, function(name, shape) {
        return $kMCY1.create(shape, options);
    }));
    $0309355ce486d148$var$property(this, 'paginators', new $4A0gN(api.paginators, options, function(name, paginator) {
        return new $kBz1Z(name, paginator, options);
    }));
    $0309355ce486d148$var$property(this, 'waiters', new $4A0gN(api.waiters, options, function(name, waiter) {
        return new $3uIxQ(name, waiter, options);
    }, $i3HcT.string.lowerFirst));
    if (options.documentation) {
        $0309355ce486d148$var$property(this, 'documentation', api.documentation);
        $0309355ce486d148$var$property(this, 'documentationUrl', api.documentationUrl);
    }
    $0309355ce486d148$var$property(this, 'awsQueryCompatible', api.metadata.awsQueryCompatible);
}
/**
 * @api private
 */ module.exports = $0309355ce486d148$var$Api;

});
parcelRegister("lk1Cc", function(module, exports) {

var $kMCY1 = parcelRequire("kMCY1");

var $i3HcT = parcelRequire("i3HcT");
var $f85cb7f70388bd27$var$property = $i3HcT.property;
var $f85cb7f70388bd27$var$memoizedProperty = $i3HcT.memoizedProperty;
function $f85cb7f70388bd27$var$Operation(name, operation, options) {
    var self = this;
    options = options || {};
    $f85cb7f70388bd27$var$property(this, 'name', operation.name || name);
    $f85cb7f70388bd27$var$property(this, 'api', options.api, false);
    operation.http = operation.http || {};
    $f85cb7f70388bd27$var$property(this, 'endpoint', operation.endpoint);
    $f85cb7f70388bd27$var$property(this, 'httpMethod', operation.http.method || 'POST');
    $f85cb7f70388bd27$var$property(this, 'httpPath', operation.http.requestUri || '/');
    $f85cb7f70388bd27$var$property(this, 'authtype', operation.authtype || '');
    $f85cb7f70388bd27$var$property(this, 'endpointDiscoveryRequired', operation.endpointdiscovery ? operation.endpointdiscovery.required ? 'REQUIRED' : 'OPTIONAL' : 'NULL');
    // httpChecksum replaces usage of httpChecksumRequired, but some APIs
    // (s3control) still uses old trait.
    var httpChecksumRequired = operation.httpChecksumRequired || operation.httpChecksum && operation.httpChecksum.requestChecksumRequired;
    $f85cb7f70388bd27$var$property(this, 'httpChecksumRequired', httpChecksumRequired, false);
    $f85cb7f70388bd27$var$memoizedProperty(this, 'input', function() {
        if (!operation.input) return new $kMCY1.create({
            type: 'structure'
        }, options);
        return $kMCY1.create(operation.input, options);
    });
    $f85cb7f70388bd27$var$memoizedProperty(this, 'output', function() {
        if (!operation.output) return new $kMCY1.create({
            type: 'structure'
        }, options);
        return $kMCY1.create(operation.output, options);
    });
    $f85cb7f70388bd27$var$memoizedProperty(this, 'errors', function() {
        var list = [];
        if (!operation.errors) return null;
        for(var i = 0; i < operation.errors.length; i++)list.push($kMCY1.create(operation.errors[i], options));
        return list;
    });
    $f85cb7f70388bd27$var$memoizedProperty(this, 'paginator', function() {
        return options.api.paginators[name];
    });
    if (options.documentation) {
        $f85cb7f70388bd27$var$property(this, 'documentation', operation.documentation);
        $f85cb7f70388bd27$var$property(this, 'documentationUrl', operation.documentationUrl);
    }
    // idempotentMembers only tracks top-level input shapes
    $f85cb7f70388bd27$var$memoizedProperty(this, 'idempotentMembers', function() {
        var idempotentMembers = [];
        var input = self.input;
        var members = input.members;
        if (!input.members) return idempotentMembers;
        for(var name in members){
            if (!members.hasOwnProperty(name)) continue;
            if (members[name].isIdempotent === true) idempotentMembers.push(name);
        }
        return idempotentMembers;
    });
    $f85cb7f70388bd27$var$memoizedProperty(this, 'hasEventOutput', function() {
        var output = self.output;
        return $f85cb7f70388bd27$var$hasEventStream(output);
    });
}
function $f85cb7f70388bd27$var$hasEventStream(topLevelShape) {
    var members = topLevelShape.members;
    var payload = topLevelShape.payload;
    if (!topLevelShape.members) return false;
    if (payload) {
        var payloadMember = members[payload];
        return payloadMember.isEventStream;
    }
    // check if any member is an event stream
    for(var name in members)if (!members.hasOwnProperty(name)) {
        if (members[name].isEventStream === true) return true;
    }
    return false;
}
/**
 * @api private
 */ module.exports = $f85cb7f70388bd27$var$Operation;

});

parcelRegister("kBz1Z", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");
var $f0026fd15877e850$require$property = $i3HcT.property;
function $f0026fd15877e850$var$Paginator(name, paginator) {
    $f0026fd15877e850$require$property(this, 'inputToken', paginator.input_token);
    $f0026fd15877e850$require$property(this, 'limitKey', paginator.limit_key);
    $f0026fd15877e850$require$property(this, 'moreResults', paginator.more_results);
    $f0026fd15877e850$require$property(this, 'outputToken', paginator.output_token);
    $f0026fd15877e850$require$property(this, 'resultKey', paginator.result_key);
}
/**
 * @api private
 */ module.exports = $f0026fd15877e850$var$Paginator;

});

parcelRegister("3uIxQ", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");
var $28b6ba1d84b47dc6$var$property = $i3HcT.property;
function $28b6ba1d84b47dc6$var$ResourceWaiter(name, waiter, options) {
    options = options || {};
    $28b6ba1d84b47dc6$var$property(this, 'name', name);
    $28b6ba1d84b47dc6$var$property(this, 'api', options.api, false);
    if (waiter.operation) $28b6ba1d84b47dc6$var$property(this, 'operation', $i3HcT.string.lowerFirst(waiter.operation));
    var self = this;
    var keys = [
        'type',
        'description',
        'delay',
        'maxAttempts',
        'acceptors'
    ];
    keys.forEach(function(key) {
        var value = waiter[key];
        if (value) $28b6ba1d84b47dc6$var$property(self, key, value);
    });
}
/**
 * @api private
 */ module.exports = $28b6ba1d84b47dc6$var$ResourceWaiter;

});

parcelRegister("khYer", function(module, exports) {
module.exports = JSON.parse("{\"acm\":{\"name\":\"ACM\",\"cors\":true},\"apigateway\":{\"name\":\"APIGateway\",\"cors\":true},\"applicationautoscaling\":{\"prefix\":\"application-autoscaling\",\"name\":\"ApplicationAutoScaling\",\"cors\":true},\"appstream\":{\"name\":\"AppStream\"},\"autoscaling\":{\"name\":\"AutoScaling\",\"cors\":true},\"batch\":{\"name\":\"Batch\"},\"budgets\":{\"name\":\"Budgets\"},\"clouddirectory\":{\"name\":\"CloudDirectory\",\"versions\":[\"2016-05-10*\"]},\"cloudformation\":{\"name\":\"CloudFormation\",\"cors\":true},\"cloudfront\":{\"name\":\"CloudFront\",\"versions\":[\"2013-05-12*\",\"2013-11-11*\",\"2014-05-31*\",\"2014-10-21*\",\"2014-11-06*\",\"2015-04-17*\",\"2015-07-27*\",\"2015-09-17*\",\"2016-01-13*\",\"2016-01-28*\",\"2016-08-01*\",\"2016-08-20*\",\"2016-09-07*\",\"2016-09-29*\",\"2016-11-25*\",\"2017-03-25*\",\"2017-10-30*\",\"2018-06-18*\",\"2018-11-05*\",\"2019-03-26*\"],\"cors\":true},\"cloudhsm\":{\"name\":\"CloudHSM\",\"cors\":true},\"cloudsearch\":{\"name\":\"CloudSearch\"},\"cloudsearchdomain\":{\"name\":\"CloudSearchDomain\"},\"cloudtrail\":{\"name\":\"CloudTrail\",\"cors\":true},\"cloudwatch\":{\"prefix\":\"monitoring\",\"name\":\"CloudWatch\",\"cors\":true},\"cloudwatchevents\":{\"prefix\":\"events\",\"name\":\"CloudWatchEvents\",\"versions\":[\"2014-02-03*\"],\"cors\":true},\"cloudwatchlogs\":{\"prefix\":\"logs\",\"name\":\"CloudWatchLogs\",\"cors\":true},\"codebuild\":{\"name\":\"CodeBuild\",\"cors\":true},\"codecommit\":{\"name\":\"CodeCommit\",\"cors\":true},\"codedeploy\":{\"name\":\"CodeDeploy\",\"cors\":true},\"codepipeline\":{\"name\":\"CodePipeline\",\"cors\":true},\"cognitoidentity\":{\"prefix\":\"cognito-identity\",\"name\":\"CognitoIdentity\",\"cors\":true},\"cognitoidentityserviceprovider\":{\"prefix\":\"cognito-idp\",\"name\":\"CognitoIdentityServiceProvider\",\"cors\":true},\"cognitosync\":{\"prefix\":\"cognito-sync\",\"name\":\"CognitoSync\",\"cors\":true},\"configservice\":{\"prefix\":\"config\",\"name\":\"ConfigService\",\"cors\":true},\"cur\":{\"name\":\"CUR\",\"cors\":true},\"datapipeline\":{\"name\":\"DataPipeline\"},\"devicefarm\":{\"name\":\"DeviceFarm\",\"cors\":true},\"directconnect\":{\"name\":\"DirectConnect\",\"cors\":true},\"directoryservice\":{\"prefix\":\"ds\",\"name\":\"DirectoryService\"},\"discovery\":{\"name\":\"Discovery\"},\"dms\":{\"name\":\"DMS\"},\"dynamodb\":{\"name\":\"DynamoDB\",\"cors\":true},\"dynamodbstreams\":{\"prefix\":\"streams.dynamodb\",\"name\":\"DynamoDBStreams\",\"cors\":true},\"ec2\":{\"name\":\"EC2\",\"versions\":[\"2013-06-15*\",\"2013-10-15*\",\"2014-02-01*\",\"2014-05-01*\",\"2014-06-15*\",\"2014-09-01*\",\"2014-10-01*\",\"2015-03-01*\",\"2015-04-15*\",\"2015-10-01*\",\"2016-04-01*\",\"2016-09-15*\"],\"cors\":true},\"ecr\":{\"name\":\"ECR\",\"cors\":true},\"ecs\":{\"name\":\"ECS\",\"cors\":true},\"efs\":{\"prefix\":\"elasticfilesystem\",\"name\":\"EFS\",\"cors\":true},\"elasticache\":{\"name\":\"ElastiCache\",\"versions\":[\"2012-11-15*\",\"2014-03-24*\",\"2014-07-15*\",\"2014-09-30*\"],\"cors\":true},\"elasticbeanstalk\":{\"name\":\"ElasticBeanstalk\",\"cors\":true},\"elb\":{\"prefix\":\"elasticloadbalancing\",\"name\":\"ELB\",\"cors\":true},\"elbv2\":{\"prefix\":\"elasticloadbalancingv2\",\"name\":\"ELBv2\",\"cors\":true},\"emr\":{\"prefix\":\"elasticmapreduce\",\"name\":\"EMR\",\"cors\":true},\"es\":{\"name\":\"ES\"},\"elastictranscoder\":{\"name\":\"ElasticTranscoder\",\"cors\":true},\"firehose\":{\"name\":\"Firehose\",\"cors\":true},\"gamelift\":{\"name\":\"GameLift\",\"cors\":true},\"glacier\":{\"name\":\"Glacier\"},\"health\":{\"name\":\"Health\"},\"iam\":{\"name\":\"IAM\",\"cors\":true},\"importexport\":{\"name\":\"ImportExport\"},\"inspector\":{\"name\":\"Inspector\",\"versions\":[\"2015-08-18*\"],\"cors\":true},\"iot\":{\"name\":\"Iot\",\"cors\":true},\"iotdata\":{\"prefix\":\"iot-data\",\"name\":\"IotData\",\"cors\":true},\"kinesis\":{\"name\":\"Kinesis\",\"cors\":true},\"kinesisanalytics\":{\"name\":\"KinesisAnalytics\"},\"kms\":{\"name\":\"KMS\",\"cors\":true},\"lambda\":{\"name\":\"Lambda\",\"cors\":true},\"lexruntime\":{\"prefix\":\"runtime.lex\",\"name\":\"LexRuntime\",\"cors\":true},\"lightsail\":{\"name\":\"Lightsail\"},\"machinelearning\":{\"name\":\"MachineLearning\",\"cors\":true},\"marketplacecommerceanalytics\":{\"name\":\"MarketplaceCommerceAnalytics\",\"cors\":true},\"marketplacemetering\":{\"prefix\":\"meteringmarketplace\",\"name\":\"MarketplaceMetering\"},\"mturk\":{\"prefix\":\"mturk-requester\",\"name\":\"MTurk\",\"cors\":true},\"mobileanalytics\":{\"name\":\"MobileAnalytics\",\"cors\":true},\"opsworks\":{\"name\":\"OpsWorks\",\"cors\":true},\"opsworkscm\":{\"name\":\"OpsWorksCM\"},\"organizations\":{\"name\":\"Organizations\"},\"pinpoint\":{\"name\":\"Pinpoint\"},\"polly\":{\"name\":\"Polly\",\"cors\":true},\"rds\":{\"name\":\"RDS\",\"versions\":[\"2014-09-01*\"],\"cors\":true},\"redshift\":{\"name\":\"Redshift\",\"cors\":true},\"rekognition\":{\"name\":\"Rekognition\",\"cors\":true},\"resourcegroupstaggingapi\":{\"name\":\"ResourceGroupsTaggingAPI\"},\"route53\":{\"name\":\"Route53\",\"cors\":true},\"route53domains\":{\"name\":\"Route53Domains\",\"cors\":true},\"s3\":{\"name\":\"S3\",\"dualstackAvailable\":true,\"cors\":true},\"s3control\":{\"name\":\"S3Control\",\"dualstackAvailable\":true,\"xmlNoDefaultLists\":true},\"servicecatalog\":{\"name\":\"ServiceCatalog\",\"cors\":true},\"ses\":{\"prefix\":\"email\",\"name\":\"SES\",\"cors\":true},\"shield\":{\"name\":\"Shield\"},\"simpledb\":{\"prefix\":\"sdb\",\"name\":\"SimpleDB\"},\"sms\":{\"name\":\"SMS\"},\"snowball\":{\"name\":\"Snowball\"},\"sns\":{\"name\":\"SNS\",\"cors\":true},\"sqs\":{\"name\":\"SQS\",\"cors\":true},\"ssm\":{\"name\":\"SSM\",\"cors\":true},\"storagegateway\":{\"name\":\"StorageGateway\",\"cors\":true},\"stepfunctions\":{\"prefix\":\"states\",\"name\":\"StepFunctions\"},\"sts\":{\"name\":\"STS\",\"cors\":true},\"support\":{\"name\":\"Support\"},\"swf\":{\"name\":\"SWF\"},\"xray\":{\"name\":\"XRay\",\"cors\":true},\"waf\":{\"name\":\"WAF\",\"cors\":true},\"wafregional\":{\"prefix\":\"waf-regional\",\"name\":\"WAFRegional\"},\"workdocs\":{\"name\":\"WorkDocs\",\"cors\":true},\"workspaces\":{\"name\":\"WorkSpaces\"},\"lexmodelbuildingservice\":{\"prefix\":\"lex-models\",\"name\":\"LexModelBuildingService\",\"cors\":true},\"marketplaceentitlementservice\":{\"prefix\":\"entitlement.marketplace\",\"name\":\"MarketplaceEntitlementService\"},\"athena\":{\"name\":\"Athena\",\"cors\":true},\"greengrass\":{\"name\":\"Greengrass\"},\"dax\":{\"name\":\"DAX\"},\"migrationhub\":{\"prefix\":\"AWSMigrationHub\",\"name\":\"MigrationHub\"},\"cloudhsmv2\":{\"name\":\"CloudHSMV2\",\"cors\":true},\"glue\":{\"name\":\"Glue\"},\"pricing\":{\"name\":\"Pricing\",\"cors\":true},\"costexplorer\":{\"prefix\":\"ce\",\"name\":\"CostExplorer\",\"cors\":true},\"mediaconvert\":{\"name\":\"MediaConvert\"},\"medialive\":{\"name\":\"MediaLive\"},\"mediapackage\":{\"name\":\"MediaPackage\"},\"mediastore\":{\"name\":\"MediaStore\"},\"mediastoredata\":{\"prefix\":\"mediastore-data\",\"name\":\"MediaStoreData\",\"cors\":true},\"appsync\":{\"name\":\"AppSync\"},\"guardduty\":{\"name\":\"GuardDuty\"},\"mq\":{\"name\":\"MQ\"},\"comprehend\":{\"name\":\"Comprehend\",\"cors\":true},\"iotjobsdataplane\":{\"prefix\":\"iot-jobs-data\",\"name\":\"IoTJobsDataPlane\"},\"kinesisvideoarchivedmedia\":{\"prefix\":\"kinesis-video-archived-media\",\"name\":\"KinesisVideoArchivedMedia\",\"cors\":true},\"kinesisvideomedia\":{\"prefix\":\"kinesis-video-media\",\"name\":\"KinesisVideoMedia\",\"cors\":true},\"kinesisvideo\":{\"name\":\"KinesisVideo\",\"cors\":true},\"sagemakerruntime\":{\"prefix\":\"runtime.sagemaker\",\"name\":\"SageMakerRuntime\"},\"sagemaker\":{\"name\":\"SageMaker\"},\"translate\":{\"name\":\"Translate\",\"cors\":true},\"resourcegroups\":{\"prefix\":\"resource-groups\",\"name\":\"ResourceGroups\",\"cors\":true},\"cloud9\":{\"name\":\"Cloud9\"},\"serverlessapplicationrepository\":{\"prefix\":\"serverlessrepo\",\"name\":\"ServerlessApplicationRepository\"},\"servicediscovery\":{\"name\":\"ServiceDiscovery\"},\"workmail\":{\"name\":\"WorkMail\"},\"autoscalingplans\":{\"prefix\":\"autoscaling-plans\",\"name\":\"AutoScalingPlans\"},\"transcribeservice\":{\"prefix\":\"transcribe\",\"name\":\"TranscribeService\"},\"connect\":{\"name\":\"Connect\",\"cors\":true},\"acmpca\":{\"prefix\":\"acm-pca\",\"name\":\"ACMPCA\"},\"fms\":{\"name\":\"FMS\"},\"secretsmanager\":{\"name\":\"SecretsManager\",\"cors\":true},\"iotanalytics\":{\"name\":\"IoTAnalytics\",\"cors\":true},\"iot1clickdevicesservice\":{\"prefix\":\"iot1click-devices\",\"name\":\"IoT1ClickDevicesService\"},\"iot1clickprojects\":{\"prefix\":\"iot1click-projects\",\"name\":\"IoT1ClickProjects\"},\"pi\":{\"name\":\"PI\"},\"neptune\":{\"name\":\"Neptune\"},\"mediatailor\":{\"name\":\"MediaTailor\"},\"eks\":{\"name\":\"EKS\"},\"dlm\":{\"name\":\"DLM\"},\"signer\":{\"name\":\"Signer\"},\"chime\":{\"name\":\"Chime\"},\"pinpointemail\":{\"prefix\":\"pinpoint-email\",\"name\":\"PinpointEmail\"},\"ram\":{\"name\":\"RAM\"},\"route53resolver\":{\"name\":\"Route53Resolver\"},\"pinpointsmsvoice\":{\"prefix\":\"sms-voice\",\"name\":\"PinpointSMSVoice\"},\"quicksight\":{\"name\":\"QuickSight\"},\"rdsdataservice\":{\"prefix\":\"rds-data\",\"name\":\"RDSDataService\"},\"amplify\":{\"name\":\"Amplify\"},\"datasync\":{\"name\":\"DataSync\"},\"robomaker\":{\"name\":\"RoboMaker\"},\"transfer\":{\"name\":\"Transfer\"},\"globalaccelerator\":{\"name\":\"GlobalAccelerator\"},\"comprehendmedical\":{\"name\":\"ComprehendMedical\",\"cors\":true},\"kinesisanalyticsv2\":{\"name\":\"KinesisAnalyticsV2\"},\"mediaconnect\":{\"name\":\"MediaConnect\"},\"fsx\":{\"name\":\"FSx\"},\"securityhub\":{\"name\":\"SecurityHub\"},\"appmesh\":{\"name\":\"AppMesh\",\"versions\":[\"2018-10-01*\"]},\"licensemanager\":{\"prefix\":\"license-manager\",\"name\":\"LicenseManager\"},\"kafka\":{\"name\":\"Kafka\"},\"apigatewaymanagementapi\":{\"name\":\"ApiGatewayManagementApi\"},\"apigatewayv2\":{\"name\":\"ApiGatewayV2\"},\"docdb\":{\"name\":\"DocDB\"},\"backup\":{\"name\":\"Backup\"},\"worklink\":{\"name\":\"WorkLink\"},\"textract\":{\"name\":\"Textract\"},\"managedblockchain\":{\"name\":\"ManagedBlockchain\"},\"mediapackagevod\":{\"prefix\":\"mediapackage-vod\",\"name\":\"MediaPackageVod\"},\"groundstation\":{\"name\":\"GroundStation\"},\"iotthingsgraph\":{\"name\":\"IoTThingsGraph\"},\"iotevents\":{\"name\":\"IoTEvents\"},\"ioteventsdata\":{\"prefix\":\"iotevents-data\",\"name\":\"IoTEventsData\"},\"personalize\":{\"name\":\"Personalize\",\"cors\":true},\"personalizeevents\":{\"prefix\":\"personalize-events\",\"name\":\"PersonalizeEvents\",\"cors\":true},\"personalizeruntime\":{\"prefix\":\"personalize-runtime\",\"name\":\"PersonalizeRuntime\",\"cors\":true},\"applicationinsights\":{\"prefix\":\"application-insights\",\"name\":\"ApplicationInsights\"},\"servicequotas\":{\"prefix\":\"service-quotas\",\"name\":\"ServiceQuotas\"},\"ec2instanceconnect\":{\"prefix\":\"ec2-instance-connect\",\"name\":\"EC2InstanceConnect\"},\"eventbridge\":{\"name\":\"EventBridge\"},\"lakeformation\":{\"name\":\"LakeFormation\"},\"forecastservice\":{\"prefix\":\"forecast\",\"name\":\"ForecastService\",\"cors\":true},\"forecastqueryservice\":{\"prefix\":\"forecastquery\",\"name\":\"ForecastQueryService\",\"cors\":true},\"qldb\":{\"name\":\"QLDB\"},\"qldbsession\":{\"prefix\":\"qldb-session\",\"name\":\"QLDBSession\"},\"workmailmessageflow\":{\"name\":\"WorkMailMessageFlow\"},\"codestarnotifications\":{\"prefix\":\"codestar-notifications\",\"name\":\"CodeStarNotifications\"},\"savingsplans\":{\"name\":\"SavingsPlans\"},\"sso\":{\"name\":\"SSO\"},\"ssooidc\":{\"prefix\":\"sso-oidc\",\"name\":\"SSOOIDC\"},\"marketplacecatalog\":{\"prefix\":\"marketplace-catalog\",\"name\":\"MarketplaceCatalog\",\"cors\":true},\"dataexchange\":{\"name\":\"DataExchange\"},\"sesv2\":{\"name\":\"SESV2\"},\"migrationhubconfig\":{\"prefix\":\"migrationhub-config\",\"name\":\"MigrationHubConfig\"},\"connectparticipant\":{\"name\":\"ConnectParticipant\"},\"appconfig\":{\"name\":\"AppConfig\"},\"iotsecuretunneling\":{\"name\":\"IoTSecureTunneling\"},\"wafv2\":{\"name\":\"WAFV2\"},\"elasticinference\":{\"prefix\":\"elastic-inference\",\"name\":\"ElasticInference\"},\"imagebuilder\":{\"name\":\"Imagebuilder\"},\"schemas\":{\"name\":\"Schemas\"},\"accessanalyzer\":{\"name\":\"AccessAnalyzer\"},\"codegurureviewer\":{\"prefix\":\"codeguru-reviewer\",\"name\":\"CodeGuruReviewer\"},\"codeguruprofiler\":{\"name\":\"CodeGuruProfiler\"},\"computeoptimizer\":{\"prefix\":\"compute-optimizer\",\"name\":\"ComputeOptimizer\"},\"frauddetector\":{\"name\":\"FraudDetector\"},\"kendra\":{\"name\":\"Kendra\"},\"networkmanager\":{\"name\":\"NetworkManager\"},\"outposts\":{\"name\":\"Outposts\"},\"augmentedairuntime\":{\"prefix\":\"sagemaker-a2i-runtime\",\"name\":\"AugmentedAIRuntime\"},\"ebs\":{\"name\":\"EBS\"},\"kinesisvideosignalingchannels\":{\"prefix\":\"kinesis-video-signaling\",\"name\":\"KinesisVideoSignalingChannels\",\"cors\":true},\"detective\":{\"name\":\"Detective\"},\"codestarconnections\":{\"prefix\":\"codestar-connections\",\"name\":\"CodeStarconnections\"},\"synthetics\":{\"name\":\"Synthetics\"},\"iotsitewise\":{\"name\":\"IoTSiteWise\"},\"macie2\":{\"name\":\"Macie2\"},\"codeartifact\":{\"name\":\"CodeArtifact\"},\"ivs\":{\"name\":\"IVS\"},\"braket\":{\"name\":\"Braket\"},\"identitystore\":{\"name\":\"IdentityStore\"},\"appflow\":{\"name\":\"Appflow\"},\"redshiftdata\":{\"prefix\":\"redshift-data\",\"name\":\"RedshiftData\"},\"ssoadmin\":{\"prefix\":\"sso-admin\",\"name\":\"SSOAdmin\"},\"timestreamquery\":{\"prefix\":\"timestream-query\",\"name\":\"TimestreamQuery\"},\"timestreamwrite\":{\"prefix\":\"timestream-write\",\"name\":\"TimestreamWrite\"},\"s3outposts\":{\"name\":\"S3Outposts\"},\"databrew\":{\"name\":\"DataBrew\"},\"servicecatalogappregistry\":{\"prefix\":\"servicecatalog-appregistry\",\"name\":\"ServiceCatalogAppRegistry\"},\"networkfirewall\":{\"prefix\":\"network-firewall\",\"name\":\"NetworkFirewall\"},\"mwaa\":{\"name\":\"MWAA\"},\"amplifybackend\":{\"name\":\"AmplifyBackend\"},\"appintegrations\":{\"name\":\"AppIntegrations\"},\"connectcontactlens\":{\"prefix\":\"connect-contact-lens\",\"name\":\"ConnectContactLens\"},\"devopsguru\":{\"prefix\":\"devops-guru\",\"name\":\"DevOpsGuru\"},\"ecrpublic\":{\"prefix\":\"ecr-public\",\"name\":\"ECRPUBLIC\"},\"lookoutvision\":{\"name\":\"LookoutVision\"},\"sagemakerfeaturestoreruntime\":{\"prefix\":\"sagemaker-featurestore-runtime\",\"name\":\"SageMakerFeatureStoreRuntime\"},\"customerprofiles\":{\"prefix\":\"customer-profiles\",\"name\":\"CustomerProfiles\"},\"auditmanager\":{\"name\":\"AuditManager\"},\"emrcontainers\":{\"prefix\":\"emr-containers\",\"name\":\"EMRcontainers\"},\"healthlake\":{\"name\":\"HealthLake\"},\"sagemakeredge\":{\"prefix\":\"sagemaker-edge\",\"name\":\"SagemakerEdge\"},\"amp\":{\"name\":\"Amp\",\"cors\":true},\"greengrassv2\":{\"name\":\"GreengrassV2\"},\"iotdeviceadvisor\":{\"name\":\"IotDeviceAdvisor\"},\"iotfleethub\":{\"name\":\"IoTFleetHub\"},\"iotwireless\":{\"name\":\"IoTWireless\"},\"location\":{\"name\":\"Location\",\"cors\":true},\"wellarchitected\":{\"name\":\"WellArchitected\"},\"lexmodelsv2\":{\"prefix\":\"models.lex.v2\",\"name\":\"LexModelsV2\"},\"lexruntimev2\":{\"prefix\":\"runtime.lex.v2\",\"name\":\"LexRuntimeV2\",\"cors\":true},\"fis\":{\"name\":\"Fis\"},\"lookoutmetrics\":{\"name\":\"LookoutMetrics\"},\"mgn\":{\"name\":\"Mgn\"},\"lookoutequipment\":{\"name\":\"LookoutEquipment\"},\"nimble\":{\"name\":\"Nimble\"},\"finspace\":{\"name\":\"Finspace\"},\"finspacedata\":{\"prefix\":\"finspace-data\",\"name\":\"Finspacedata\"},\"ssmcontacts\":{\"prefix\":\"ssm-contacts\",\"name\":\"SSMContacts\"},\"ssmincidents\":{\"prefix\":\"ssm-incidents\",\"name\":\"SSMIncidents\"},\"applicationcostprofiler\":{\"name\":\"ApplicationCostProfiler\"},\"apprunner\":{\"name\":\"AppRunner\"},\"proton\":{\"name\":\"Proton\"},\"route53recoverycluster\":{\"prefix\":\"route53-recovery-cluster\",\"name\":\"Route53RecoveryCluster\"},\"route53recoverycontrolconfig\":{\"prefix\":\"route53-recovery-control-config\",\"name\":\"Route53RecoveryControlConfig\"},\"route53recoveryreadiness\":{\"prefix\":\"route53-recovery-readiness\",\"name\":\"Route53RecoveryReadiness\"},\"chimesdkidentity\":{\"prefix\":\"chime-sdk-identity\",\"name\":\"ChimeSDKIdentity\"},\"chimesdkmessaging\":{\"prefix\":\"chime-sdk-messaging\",\"name\":\"ChimeSDKMessaging\"},\"snowdevicemanagement\":{\"prefix\":\"snow-device-management\",\"name\":\"SnowDeviceManagement\"},\"memorydb\":{\"name\":\"MemoryDB\"},\"opensearch\":{\"name\":\"OpenSearch\"},\"kafkaconnect\":{\"name\":\"KafkaConnect\"},\"voiceid\":{\"prefix\":\"voice-id\",\"name\":\"VoiceID\"},\"wisdom\":{\"name\":\"Wisdom\"},\"account\":{\"name\":\"Account\"},\"cloudcontrol\":{\"name\":\"CloudControl\"},\"grafana\":{\"name\":\"Grafana\"},\"panorama\":{\"name\":\"Panorama\"},\"chimesdkmeetings\":{\"prefix\":\"chime-sdk-meetings\",\"name\":\"ChimeSDKMeetings\"},\"resiliencehub\":{\"name\":\"Resiliencehub\"},\"migrationhubstrategy\":{\"name\":\"MigrationHubStrategy\"},\"appconfigdata\":{\"name\":\"AppConfigData\"},\"drs\":{\"name\":\"Drs\"},\"migrationhubrefactorspaces\":{\"prefix\":\"migration-hub-refactor-spaces\",\"name\":\"MigrationHubRefactorSpaces\"},\"evidently\":{\"name\":\"Evidently\"},\"inspector2\":{\"name\":\"Inspector2\"},\"rbin\":{\"name\":\"Rbin\"},\"rum\":{\"name\":\"RUM\"},\"backupgateway\":{\"prefix\":\"backup-gateway\",\"name\":\"BackupGateway\"},\"iottwinmaker\":{\"name\":\"IoTTwinMaker\"},\"workspacesweb\":{\"prefix\":\"workspaces-web\",\"name\":\"WorkSpacesWeb\"},\"amplifyuibuilder\":{\"name\":\"AmplifyUIBuilder\"},\"keyspaces\":{\"name\":\"Keyspaces\"},\"billingconductor\":{\"name\":\"Billingconductor\"},\"pinpointsmsvoicev2\":{\"prefix\":\"pinpoint-sms-voice-v2\",\"name\":\"PinpointSMSVoiceV2\"},\"ivschat\":{\"name\":\"Ivschat\"},\"chimesdkmediapipelines\":{\"prefix\":\"chime-sdk-media-pipelines\",\"name\":\"ChimeSDKMediaPipelines\"},\"emrserverless\":{\"prefix\":\"emr-serverless\",\"name\":\"EMRServerless\"},\"m2\":{\"name\":\"M2\"},\"connectcampaigns\":{\"name\":\"ConnectCampaigns\"},\"redshiftserverless\":{\"prefix\":\"redshift-serverless\",\"name\":\"RedshiftServerless\"},\"rolesanywhere\":{\"name\":\"RolesAnywhere\"},\"licensemanagerusersubscriptions\":{\"prefix\":\"license-manager-user-subscriptions\",\"name\":\"LicenseManagerUserSubscriptions\"},\"privatenetworks\":{\"name\":\"PrivateNetworks\"},\"supportapp\":{\"prefix\":\"support-app\",\"name\":\"SupportApp\"},\"controltower\":{\"name\":\"ControlTower\"},\"iotfleetwise\":{\"name\":\"IoTFleetWise\"},\"migrationhuborchestrator\":{\"name\":\"MigrationHubOrchestrator\"},\"connectcases\":{\"name\":\"ConnectCases\"},\"resourceexplorer2\":{\"prefix\":\"resource-explorer-2\",\"name\":\"ResourceExplorer2\"},\"scheduler\":{\"name\":\"Scheduler\"},\"chimesdkvoice\":{\"prefix\":\"chime-sdk-voice\",\"name\":\"ChimeSDKVoice\"},\"ssmsap\":{\"prefix\":\"ssm-sap\",\"name\":\"SsmSap\"},\"oam\":{\"name\":\"OAM\"},\"arczonalshift\":{\"prefix\":\"arc-zonal-shift\",\"name\":\"ARCZonalShift\"},\"omics\":{\"name\":\"Omics\"},\"opensearchserverless\":{\"name\":\"OpenSearchServerless\"},\"securitylake\":{\"name\":\"SecurityLake\"},\"simspaceweaver\":{\"name\":\"SimSpaceWeaver\"},\"docdbelastic\":{\"prefix\":\"docdb-elastic\",\"name\":\"DocDBElastic\"},\"sagemakergeospatial\":{\"prefix\":\"sagemaker-geospatial\",\"name\":\"SageMakerGeospatial\"},\"codecatalyst\":{\"name\":\"CodeCatalyst\"},\"pipes\":{\"name\":\"Pipes\"},\"sagemakermetrics\":{\"prefix\":\"sagemaker-metrics\",\"name\":\"SageMakerMetrics\"},\"kinesisvideowebrtcstorage\":{\"prefix\":\"kinesis-video-webrtc-storage\",\"name\":\"KinesisVideoWebRTCStorage\"},\"licensemanagerlinuxsubscriptions\":{\"prefix\":\"license-manager-linux-subscriptions\",\"name\":\"LicenseManagerLinuxSubscriptions\"},\"kendraranking\":{\"prefix\":\"kendra-ranking\",\"name\":\"KendraRanking\"},\"cleanrooms\":{\"name\":\"CleanRooms\"},\"cloudtraildata\":{\"prefix\":\"cloudtrail-data\",\"name\":\"CloudTrailData\"},\"tnb\":{\"name\":\"Tnb\"},\"internetmonitor\":{\"name\":\"InternetMonitor\"},\"ivsrealtime\":{\"prefix\":\"ivs-realtime\",\"name\":\"IVSRealTime\"},\"vpclattice\":{\"prefix\":\"vpc-lattice\",\"name\":\"VPCLattice\"},\"osis\":{\"name\":\"OSIS\"},\"mediapackagev2\":{\"name\":\"MediaPackageV2\"},\"paymentcryptography\":{\"prefix\":\"payment-cryptography\",\"name\":\"PaymentCryptography\"},\"paymentcryptographydata\":{\"prefix\":\"payment-cryptography-data\",\"name\":\"PaymentCryptographyData\"},\"codegurusecurity\":{\"prefix\":\"codeguru-security\",\"name\":\"CodeGuruSecurity\"},\"verifiedpermissions\":{\"name\":\"VerifiedPermissions\"},\"appfabric\":{\"name\":\"AppFabric\"},\"medicalimaging\":{\"prefix\":\"medical-imaging\",\"name\":\"MedicalImaging\"},\"entityresolution\":{\"name\":\"EntityResolution\"},\"managedblockchainquery\":{\"prefix\":\"managedblockchain-query\",\"name\":\"ManagedBlockchainQuery\"},\"neptunedata\":{\"name\":\"Neptunedata\"},\"pcaconnectorad\":{\"prefix\":\"pca-connector-ad\",\"name\":\"PcaConnectorAd\"},\"bedrock\":{\"name\":\"Bedrock\"},\"bedrockruntime\":{\"prefix\":\"bedrock-runtime\",\"name\":\"BedrockRuntime\"},\"datazone\":{\"name\":\"DataZone\"},\"launchwizard\":{\"prefix\":\"launch-wizard\",\"name\":\"LaunchWizard\"},\"trustedadvisor\":{\"name\":\"TrustedAdvisor\"},\"inspectorscan\":{\"prefix\":\"inspector-scan\",\"name\":\"InspectorScan\"},\"bcmdataexports\":{\"prefix\":\"bcm-data-exports\",\"name\":\"BCMDataExports\"},\"costoptimizationhub\":{\"prefix\":\"cost-optimization-hub\",\"name\":\"CostOptimizationHub\"},\"eksauth\":{\"prefix\":\"eks-auth\",\"name\":\"EKSAuth\"},\"freetier\":{\"name\":\"FreeTier\"},\"repostspace\":{\"name\":\"Repostspace\"},\"workspacesthinclient\":{\"prefix\":\"workspaces-thin-client\",\"name\":\"WorkSpacesThinClient\"},\"b2bi\":{\"name\":\"B2bi\"},\"bedrockagent\":{\"prefix\":\"bedrock-agent\",\"name\":\"BedrockAgent\"},\"bedrockagentruntime\":{\"prefix\":\"bedrock-agent-runtime\",\"name\":\"BedrockAgentRuntime\"},\"qbusiness\":{\"name\":\"QBusiness\"},\"qconnect\":{\"name\":\"QConnect\"},\"cleanroomsml\":{\"name\":\"CleanRoomsML\"},\"marketplaceagreement\":{\"prefix\":\"marketplace-agreement\",\"name\":\"MarketplaceAgreement\"},\"marketplacedeployment\":{\"prefix\":\"marketplace-deployment\",\"name\":\"MarketplaceDeployment\"},\"networkmonitor\":{\"name\":\"NetworkMonitor\"},\"supplychain\":{\"name\":\"SupplyChain\"},\"artifact\":{\"name\":\"Artifact\"},\"chatbot\":{\"name\":\"Chatbot\"},\"timestreaminfluxdb\":{\"prefix\":\"timestream-influxdb\",\"name\":\"TimestreamInfluxDB\"},\"codeconnections\":{\"name\":\"CodeConnections\"},\"deadline\":{\"name\":\"Deadline\"},\"controlcatalog\":{\"name\":\"ControlCatalog\"},\"route53profiles\":{\"name\":\"Route53Profiles\"},\"mailmanager\":{\"name\":\"MailManager\"},\"taxsettings\":{\"name\":\"TaxSettings\"},\"applicationsignals\":{\"prefix\":\"application-signals\",\"name\":\"ApplicationSignals\"},\"pcaconnectorscep\":{\"prefix\":\"pca-connector-scep\",\"name\":\"PcaConnectorScep\"},\"apptest\":{\"name\":\"AppTest\"},\"qapps\":{\"name\":\"QApps\"},\"ssmquicksetup\":{\"prefix\":\"ssm-quicksetup\",\"name\":\"SSMQuickSetup\"},\"pcs\":{\"name\":\"PCS\"}}");

});


parcelRegister("b4VdT", function(module, exports) {
function $810c74b89d918657$var$apiLoader(svc, version) {
    if (!$810c74b89d918657$var$apiLoader.services.hasOwnProperty(svc)) throw new Error('InvalidService: Failed to load api for ' + svc);
    return $810c74b89d918657$var$apiLoader.services[svc][version];
}
/**
 * @api private
 *
 * This member of AWS.apiLoader is private, but changing it will necessitate a
 * change to ../scripts/services-table-generator.ts
 */ $810c74b89d918657$var$apiLoader.services = {};
/**
 * @api private
 */ module.exports = $810c74b89d918657$var$apiLoader;

});

parcelRegister("8JRRk", function(module, exports) {
"use strict";
Object.defineProperty(module.exports, "__esModule", {
    value: true
});

var $cp3Yu = parcelRequire("cp3Yu");
var $65cc4dff52d87710$var$CACHE_SIZE = 1000;
/**
 * Inspired node-lru-cache[https://github.com/isaacs/node-lru-cache]
 */ var $65cc4dff52d87710$var$EndpointCache = /** @class */ function() {
    function EndpointCache(maxSize) {
        if (maxSize === void 0) maxSize = $65cc4dff52d87710$var$CACHE_SIZE;
        this.maxSize = maxSize;
        this.cache = new $cp3Yu.LRUCache(maxSize);
    }
    Object.defineProperty(EndpointCache.prototype, "size", {
        get: function() {
            return this.cache.length;
        },
        enumerable: true,
        configurable: true
    });
    EndpointCache.prototype.put = function(key, value) {
        var keyString = typeof key !== 'string' ? EndpointCache.getKeyString(key) : key;
        var endpointRecord = this.populateValue(value);
        this.cache.put(keyString, endpointRecord);
    };
    EndpointCache.prototype.get = function(key) {
        var keyString = typeof key !== 'string' ? EndpointCache.getKeyString(key) : key;
        var now = Date.now();
        var records = this.cache.get(keyString);
        if (records) {
            for(var i = records.length - 1; i >= 0; i--){
                var record = records[i];
                if (record.Expire < now) records.splice(i, 1);
            }
            if (records.length === 0) {
                this.cache.remove(keyString);
                return undefined;
            }
        }
        return records;
    };
    EndpointCache.getKeyString = function(key) {
        var identifiers = [];
        var identifierNames = Object.keys(key).sort();
        for(var i = 0; i < identifierNames.length; i++){
            var identifierName = identifierNames[i];
            if (key[identifierName] === undefined) continue;
            identifiers.push(key[identifierName]);
        }
        return identifiers.join(' ');
    };
    EndpointCache.prototype.populateValue = function(endpoints) {
        var now = Date.now();
        return endpoints.map(function(endpoint) {
            return {
                Address: endpoint.Address || '',
                Expire: now + (endpoint.CachePeriodInMinutes || 1) * 60000
            };
        });
    };
    EndpointCache.prototype.empty = function() {
        this.cache.empty();
    };
    EndpointCache.prototype.remove = function(key) {
        var keyString = typeof key !== 'string' ? EndpointCache.getKeyString(key) : key;
        this.cache.remove(keyString);
    };
    return EndpointCache;
}();
module.exports.EndpointCache = $65cc4dff52d87710$var$EndpointCache;

});
parcelRegister("cp3Yu", function(module, exports) {
"use strict";
Object.defineProperty(module.exports, "__esModule", {
    value: true
});
var $907ae7204cb22e94$var$LinkedListNode = /** @class */ function() {
    function LinkedListNode(key, value) {
        this.key = key;
        this.value = value;
    }
    return LinkedListNode;
}();
var $907ae7204cb22e94$var$LRUCache = /** @class */ function() {
    function LRUCache(size) {
        this.nodeMap = {};
        this.size = 0;
        if (typeof size !== 'number' || size < 1) throw new Error('Cache size can only be positive number');
        this.sizeLimit = size;
    }
    Object.defineProperty(LRUCache.prototype, "length", {
        get: function() {
            return this.size;
        },
        enumerable: true,
        configurable: true
    });
    LRUCache.prototype.prependToList = function(node) {
        if (!this.headerNode) this.tailNode = node;
        else {
            this.headerNode.prev = node;
            node.next = this.headerNode;
        }
        this.headerNode = node;
        this.size++;
    };
    LRUCache.prototype.removeFromTail = function() {
        if (!this.tailNode) return undefined;
        var node = this.tailNode;
        var prevNode = node.prev;
        if (prevNode) prevNode.next = undefined;
        node.prev = undefined;
        this.tailNode = prevNode;
        this.size--;
        return node;
    };
    LRUCache.prototype.detachFromList = function(node) {
        if (this.headerNode === node) this.headerNode = node.next;
        if (this.tailNode === node) this.tailNode = node.prev;
        if (node.prev) node.prev.next = node.next;
        if (node.next) node.next.prev = node.prev;
        node.next = undefined;
        node.prev = undefined;
        this.size--;
    };
    LRUCache.prototype.get = function(key) {
        if (this.nodeMap[key]) {
            var node = this.nodeMap[key];
            this.detachFromList(node);
            this.prependToList(node);
            return node.value;
        }
    };
    LRUCache.prototype.remove = function(key) {
        if (this.nodeMap[key]) {
            var node = this.nodeMap[key];
            this.detachFromList(node);
            delete this.nodeMap[key];
        }
    };
    LRUCache.prototype.put = function(key, value) {
        if (this.nodeMap[key]) this.remove(key);
        else if (this.size === this.sizeLimit) {
            var tailNode = this.removeFromTail();
            var key_1 = tailNode.key;
            delete this.nodeMap[key_1];
        }
        var newNode = new $907ae7204cb22e94$var$LinkedListNode(key, value);
        this.nodeMap[key] = newNode;
        this.prependToList(newNode);
    };
    LRUCache.prototype.empty = function() {
        var keys = Object.keys(this.nodeMap);
        for(var i = 0; i < keys.length; i++){
            var key = keys[i];
            var node = this.nodeMap[key];
            this.detachFromList(node);
            delete this.nodeMap[key];
        }
    };
    return LRUCache;
}();
module.exports.LRUCache = $907ae7204cb22e94$var$LRUCache;

});


parcelRegister("cLHKj", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
/**
 * @api private
 * @!method on(eventName, callback)
 *   Registers an event listener callback for the event given by `eventName`.
 *   Parameters passed to the callback function depend on the individual event
 *   being triggered. See the event documentation for those parameters.
 *
 *   @param eventName [String] the event name to register the listener for
 *   @param callback [Function] the listener callback function
 *   @param toHead [Boolean] attach the listener callback to the head of callback array if set to true.
 *     Default to be false.
 *   @return [AWS.SequentialExecutor] the same object for chaining
 */ $hIq4q.SequentialExecutor = $hIq4q.util.inherit({
    constructor: function SequentialExecutor() {
        this._events = {};
    },
    /**
   * @api private
   */ listeners: function listeners(eventName) {
        return this._events[eventName] ? this._events[eventName].slice(0) : [];
    },
    on: function on(eventName, listener, toHead) {
        if (this._events[eventName]) toHead ? this._events[eventName].unshift(listener) : this._events[eventName].push(listener);
        else this._events[eventName] = [
            listener
        ];
        return this;
    },
    onAsync: function onAsync(eventName, listener, toHead) {
        listener._isAsync = true;
        return this.on(eventName, listener, toHead);
    },
    removeListener: function removeListener(eventName, listener) {
        var listeners = this._events[eventName];
        if (listeners) {
            var length = listeners.length;
            var position = -1;
            for(var i = 0; i < length; ++i)if (listeners[i] === listener) position = i;
            if (position > -1) listeners.splice(position, 1);
        }
        return this;
    },
    removeAllListeners: function removeAllListeners(eventName) {
        if (eventName) delete this._events[eventName];
        else this._events = {};
        return this;
    },
    /**
   * @api private
   */ emit: function emit(eventName, eventArgs, doneCallback) {
        if (!doneCallback) doneCallback = function() {};
        var listeners = this.listeners(eventName);
        var count = listeners.length;
        this.callListeners(listeners, eventArgs, doneCallback);
        return count > 0;
    },
    /**
   * @api private
   */ callListeners: function callListeners(listeners, args, doneCallback, prevError) {
        var self = this;
        var error = prevError || null;
        function callNextListener(err) {
            if (err) {
                error = $hIq4q.util.error(error || new Error(), err);
                if (self._haltHandlersOnError) return doneCallback.call(self, error);
            }
            self.callListeners(listeners, args, doneCallback, error);
        }
        while(listeners.length > 0){
            var listener = listeners.shift();
            if (listener._isAsync) {
                listener.apply(self, args.concat([
                    callNextListener
                ]));
                return; // stop here, callNextListener will continue
            } else {
                try {
                    listener.apply(self, args);
                } catch (err) {
                    error = $hIq4q.util.error(error || new Error(), err);
                }
                if (error && self._haltHandlersOnError) {
                    doneCallback.call(self, error);
                    return;
                }
            }
        }
        doneCallback.call(self, error);
    },
    /**
   * Adds or copies a set of listeners from another list of
   * listeners or SequentialExecutor object.
   *
   * @param listeners [map<String,Array<Function>>, AWS.SequentialExecutor]
   *   a list of events and callbacks, or an event emitter object
   *   containing listeners to add to this emitter object.
   * @return [AWS.SequentialExecutor] the emitter object, for chaining.
   * @example Adding listeners from a map of listeners
   *   emitter.addListeners({
   *     event1: [function() { ... }, function() { ... }],
   *     event2: [function() { ... }]
   *   });
   *   emitter.emit('event1'); // emitter has event1
   *   emitter.emit('event2'); // emitter has event2
   * @example Adding listeners from another emitter object
   *   var emitter1 = new AWS.SequentialExecutor();
   *   emitter1.on('event1', function() { ... });
   *   emitter1.on('event2', function() { ... });
   *   var emitter2 = new AWS.SequentialExecutor();
   *   emitter2.addListeners(emitter1);
   *   emitter2.emit('event1'); // emitter2 has event1
   *   emitter2.emit('event2'); // emitter2 has event2
   */ addListeners: function addListeners(listeners) {
        var self = this;
        // extract listeners if parameter is an SequentialExecutor object
        if (listeners._events) listeners = listeners._events;
        $hIq4q.util.each(listeners, function(event, callbacks) {
            if (typeof callbacks === 'function') callbacks = [
                callbacks
            ];
            $hIq4q.util.arrayEach(callbacks, function(callback) {
                self.on(event, callback);
            });
        });
        return self;
    },
    /**
   * Registers an event with {on} and saves the callback handle function
   * as a property on the emitter object using a given `name`.
   *
   * @param name [String] the property name to set on this object containing
   *   the callback function handle so that the listener can be removed in
   *   the future.
   * @param (see on)
   * @return (see on)
   * @example Adding a named listener DATA_CALLBACK
   *   var listener = function() { doSomething(); };
   *   emitter.addNamedListener('DATA_CALLBACK', 'data', listener);
   *
   *   // the following prints: true
   *   console.log(emitter.DATA_CALLBACK == listener);
   */ addNamedListener: function addNamedListener(name, eventName, callback, toHead) {
        this[name] = callback;
        this.addListener(eventName, callback, toHead);
        return this;
    },
    /**
   * @api private
   */ addNamedAsyncListener: function addNamedAsyncListener(name, eventName, callback, toHead) {
        callback._isAsync = true;
        return this.addNamedListener(name, eventName, callback, toHead);
    },
    /**
   * Helper method to add a set of named listeners using
   * {addNamedListener}. The callback contains a parameter
   * with a handle to the `addNamedListener` method.
   *
   * @callback callback function(add)
   *   The callback function is called immediately in order to provide
   *   the `add` function to the block. This simplifies the addition of
   *   a large group of named listeners.
   *   @param add [Function] the {addNamedListener} function to call
   *     when registering listeners.
   * @example Adding a set of named listeners
   *   emitter.addNamedListeners(function(add) {
   *     add('DATA_CALLBACK', 'data', function() { ... });
   *     add('OTHER', 'otherEvent', function() { ... });
   *     add('LAST', 'lastEvent', function() { ... });
   *   });
   *
   *   // these properties are now set:
   *   emitter.DATA_CALLBACK;
   *   emitter.OTHER;
   *   emitter.LAST;
   */ addNamedListeners: function addNamedListeners(callback) {
        var self = this;
        callback(function() {
            self.addNamedListener.apply(self, arguments);
        }, function() {
            self.addNamedAsyncListener.apply(self, arguments);
        });
        return this;
    }
});
/**
 * {on} is the prefered method.
 * @api private
 */ $hIq4q.SequentialExecutor.prototype.addListener = $hIq4q.SequentialExecutor.prototype.on;
/**
 * @api private
 */ module.exports = $hIq4q.SequentialExecutor;

});

parcelRegister("bveyz", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");

var $g9WzK = parcelRequire("g9WzK");

var $03Joe = parcelRequire("03Joe");
var $85fde194fa4232e2$var$inherit = $hIq4q.util.inherit;
var $85fde194fa4232e2$var$clientCount = 0;

var $gffN3 = parcelRequire("gffN3");
/**
 * The service class representing an AWS service.
 *
 * @class_abstract This class is an abstract class.
 *
 * @!attribute apiVersions
 *   @return [Array<String>] the list of API versions supported by this service.
 *   @readonly
 */ $hIq4q.Service = $85fde194fa4232e2$var$inherit({
    /**
   * Create a new service object with a configuration object
   *
   * @param config [map] a map of configuration options
   */ constructor: function Service(config) {
        if (!this.loadServiceClass) throw $hIq4q.util.error(new Error(), 'Service must be constructed with `new\' operator');
        if (config) {
            if (config.region) {
                var region = config.region;
                if ($gffN3.isFipsRegion(region)) {
                    config.region = $gffN3.getRealRegion(region);
                    config.useFipsEndpoint = true;
                }
                if ($gffN3.isGlobalRegion(region)) config.region = $gffN3.getRealRegion(region);
            }
            if (typeof config.useDualstack === 'boolean' && typeof config.useDualstackEndpoint !== 'boolean') config.useDualstackEndpoint = config.useDualstack;
        }
        var ServiceClass = this.loadServiceClass(config || {});
        if (ServiceClass) {
            var originalConfig = $hIq4q.util.copy(config);
            var svc = new ServiceClass(config);
            Object.defineProperty(svc, '_originalConfig', {
                get: function() {
                    return originalConfig;
                },
                enumerable: false,
                configurable: true
            });
            svc._clientId = ++$85fde194fa4232e2$var$clientCount;
            return svc;
        }
        this.initialize(config);
    },
    /**
   * @api private
   */ initialize: function initialize(config) {
        var svcConfig = $hIq4q.config[this.serviceIdentifier];
        this.config = new $hIq4q.Config($hIq4q.config);
        if (svcConfig) this.config.update(svcConfig, true);
        if (config) this.config.update(config, true);
        this.validateService();
        if (!this.config.endpoint) $03Joe.configureEndpoint(this);
        this.config.endpoint = this.endpointFromTemplate(this.config.endpoint);
        this.setEndpoint(this.config.endpoint);
        //enable attaching listeners to service client
        $hIq4q.SequentialExecutor.call(this);
        $hIq4q.Service.addDefaultMonitoringListeners(this);
        if ((this.config.clientSideMonitoring || $hIq4q.Service._clientSideMonitoring) && this.publisher) {
            var publisher = this.publisher;
            this.addNamedListener('PUBLISH_API_CALL', 'apiCall', function PUBLISH_API_CALL(event) {
                process.nextTick(function() {
                    publisher.eventHandler(event);
                });
            });
            this.addNamedListener('PUBLISH_API_ATTEMPT', 'apiCallAttempt', function PUBLISH_API_ATTEMPT(event) {
                process.nextTick(function() {
                    publisher.eventHandler(event);
                });
            });
        }
    },
    /**
   * @api private
   */ validateService: function validateService() {},
    /**
   * @api private
   */ loadServiceClass: function loadServiceClass(serviceConfig) {
        var config = serviceConfig;
        if (!$hIq4q.util.isEmpty(this.api)) return null;
        else if (config.apiConfig) return $hIq4q.Service.defineServiceApi(this.constructor, config.apiConfig);
        else if (!this.constructor.services) return null;
        else {
            config = new $hIq4q.Config($hIq4q.config);
            config.update(serviceConfig, true);
            var version = config.apiVersions[this.constructor.serviceIdentifier];
            version = version || config.apiVersion;
            return this.getLatestServiceClass(version);
        }
    },
    /**
   * @api private
   */ getLatestServiceClass: function getLatestServiceClass(version) {
        version = this.getLatestServiceVersion(version);
        if (this.constructor.services[version] === null) $hIq4q.Service.defineServiceApi(this.constructor, version);
        return this.constructor.services[version];
    },
    /**
   * @api private
   */ getLatestServiceVersion: function getLatestServiceVersion(version) {
        if (!this.constructor.services || this.constructor.services.length === 0) throw new Error('No services defined on ' + this.constructor.serviceIdentifier);
        if (!version) version = 'latest';
        else if ($hIq4q.util.isType(version, Date)) version = $hIq4q.util.date.iso8601(version).split('T')[0];
        if (Object.hasOwnProperty(this.constructor.services, version)) return version;
        var keys = Object.keys(this.constructor.services).sort();
        var selectedVersion = null;
        for(var i = keys.length - 1; i >= 0; i--){
            // versions that end in "*" are not available on disk and can be
            // skipped, so do not choose these as selectedVersions
            if (keys[i][keys[i].length - 1] !== '*') selectedVersion = keys[i];
            if (keys[i].substr(0, 10) <= version) return selectedVersion;
        }
        throw new Error('Could not find ' + this.constructor.serviceIdentifier + ' API to satisfy version constraint `' + version + '\'');
    },
    /**
   * @api private
   */ api: {},
    /**
   * @api private
   */ defaultRetryCount: 3,
    /**
   * @api private
   */ customizeRequests: function customizeRequests(callback) {
        if (!callback) this.customRequestHandler = null;
        else if (typeof callback === 'function') this.customRequestHandler = callback;
        else throw new Error('Invalid callback type \'' + typeof callback + '\' provided in customizeRequests');
    },
    /**
   * Calls an operation on a service with the given input parameters.
   *
   * @param operation [String] the name of the operation to call on the service.
   * @param params [map] a map of input options for the operation
   * @callback callback function(err, data)
   *   If a callback is supplied, it is called when a response is returned
   *   from the service.
   *   @param err [Error] the error object returned from the request.
   *     Set to `null` if the request is successful.
   *   @param data [Object] the de-serialized data returned from
   *     the request. Set to `null` if a request error occurs.
   */ makeRequest: function makeRequest(operation, params, callback) {
        if (typeof params === 'function') {
            callback = params;
            params = null;
        }
        params = params || {};
        if (this.config.params) {
            var rules = this.api.operations[operation];
            if (rules) {
                params = $hIq4q.util.copy(params);
                $hIq4q.util.each(this.config.params, function(key, value) {
                    if (rules.input.members[key]) {
                        if (params[key] === undefined || params[key] === null) params[key] = value;
                    }
                });
            }
        }
        var request = new $hIq4q.Request(this, operation, params);
        this.addAllRequestListeners(request);
        this.attachMonitoringEmitter(request);
        if (callback) request.send(callback);
        return request;
    },
    /**
   * Calls an operation on a service with the given input parameters, without
   * any authentication data. This method is useful for "public" API operations.
   *
   * @param operation [String] the name of the operation to call on the service.
   * @param params [map] a map of input options for the operation
   * @callback callback function(err, data)
   *   If a callback is supplied, it is called when a response is returned
   *   from the service.
   *   @param err [Error] the error object returned from the request.
   *     Set to `null` if the request is successful.
   *   @param data [Object] the de-serialized data returned from
   *     the request. Set to `null` if a request error occurs.
   */ makeUnauthenticatedRequest: function makeUnauthenticatedRequest(operation, params, callback) {
        if (typeof params === 'function') {
            callback = params;
            params = {};
        }
        var request = this.makeRequest(operation, params).toUnauthenticated();
        return callback ? request.send(callback) : request;
    },
    /**
   * Waits for a given state
   *
   * @param state [String] the state on the service to wait for
   * @param params [map] a map of parameters to pass with each request
   * @option params $waiter [map] a map of configuration options for the waiter
   * @option params $waiter.delay [Number] The number of seconds to wait between
   *                                       requests
   * @option params $waiter.maxAttempts [Number] The maximum number of requests
   *                                             to send while waiting
   * @callback callback function(err, data)
   *   If a callback is supplied, it is called when a response is returned
   *   from the service.
   *   @param err [Error] the error object returned from the request.
   *     Set to `null` if the request is successful.
   *   @param data [Object] the de-serialized data returned from
   *     the request. Set to `null` if a request error occurs.
   */ waitFor: function waitFor(state, params, callback) {
        var waiter = new $hIq4q.ResourceWaiter(this, state);
        return waiter.wait(params, callback);
    },
    /**
   * @api private
   */ addAllRequestListeners: function addAllRequestListeners(request) {
        var list = [
            $hIq4q.events,
            $hIq4q.EventListeners.Core,
            this.serviceInterface(),
            $hIq4q.EventListeners.CorePost
        ];
        for(var i = 0; i < list.length; i++)if (list[i]) request.addListeners(list[i]);
        // disable parameter validation
        if (!this.config.paramValidation) request.removeListener('validate', $hIq4q.EventListeners.Core.VALIDATE_PARAMETERS);
        if (this.config.logger) request.addListeners($hIq4q.EventListeners.Logger);
        this.setupRequestListeners(request);
        // call prototype's customRequestHandler
        if (typeof this.constructor.prototype.customRequestHandler === 'function') this.constructor.prototype.customRequestHandler(request);
        // call instance's customRequestHandler
        if (Object.prototype.hasOwnProperty.call(this, 'customRequestHandler') && typeof this.customRequestHandler === 'function') this.customRequestHandler(request);
    },
    /**
   * Event recording metrics for a whole API call.
   * @returns {object} a subset of api call metrics
   * @api private
   */ apiCallEvent: function apiCallEvent(request) {
        var api = request.service.api.operations[request.operation];
        var monitoringEvent = {
            Type: 'ApiCall',
            Api: api ? api.name : request.operation,
            Version: 1,
            Service: request.service.api.serviceId || request.service.api.endpointPrefix,
            Region: request.httpRequest.region,
            MaxRetriesExceeded: 0,
            UserAgent: request.httpRequest.getUserAgent()
        };
        var response = request.response;
        if (response.httpResponse.statusCode) monitoringEvent.FinalHttpStatusCode = response.httpResponse.statusCode;
        if (response.error) {
            var error = response.error;
            var statusCode = response.httpResponse.statusCode;
            if (statusCode > 299) {
                if (error.code) monitoringEvent.FinalAwsException = error.code;
                if (error.message) monitoringEvent.FinalAwsExceptionMessage = error.message;
            } else {
                if (error.code || error.name) monitoringEvent.FinalSdkException = error.code || error.name;
                if (error.message) monitoringEvent.FinalSdkExceptionMessage = error.message;
            }
        }
        return monitoringEvent;
    },
    /**
   * Event recording metrics for an API call attempt.
   * @returns {object} a subset of api call attempt metrics
   * @api private
   */ apiAttemptEvent: function apiAttemptEvent(request) {
        var api = request.service.api.operations[request.operation];
        var monitoringEvent = {
            Type: 'ApiCallAttempt',
            Api: api ? api.name : request.operation,
            Version: 1,
            Service: request.service.api.serviceId || request.service.api.endpointPrefix,
            Fqdn: request.httpRequest.endpoint.hostname,
            UserAgent: request.httpRequest.getUserAgent()
        };
        var response = request.response;
        if (response.httpResponse.statusCode) monitoringEvent.HttpStatusCode = response.httpResponse.statusCode;
        if (!request._unAuthenticated && request.service.config.credentials && request.service.config.credentials.accessKeyId) monitoringEvent.AccessKey = request.service.config.credentials.accessKeyId;
        if (!response.httpResponse.headers) return monitoringEvent;
        if (request.httpRequest.headers['x-amz-security-token']) monitoringEvent.SessionToken = request.httpRequest.headers['x-amz-security-token'];
        if (response.httpResponse.headers['x-amzn-requestid']) monitoringEvent.XAmznRequestId = response.httpResponse.headers['x-amzn-requestid'];
        if (response.httpResponse.headers['x-amz-request-id']) monitoringEvent.XAmzRequestId = response.httpResponse.headers['x-amz-request-id'];
        if (response.httpResponse.headers['x-amz-id-2']) monitoringEvent.XAmzId2 = response.httpResponse.headers['x-amz-id-2'];
        return monitoringEvent;
    },
    /**
   * Add metrics of failed request.
   * @api private
   */ attemptFailEvent: function attemptFailEvent(request) {
        var monitoringEvent = this.apiAttemptEvent(request);
        var response = request.response;
        var error = response.error;
        if (response.httpResponse.statusCode > 299) {
            if (error.code) monitoringEvent.AwsException = error.code;
            if (error.message) monitoringEvent.AwsExceptionMessage = error.message;
        } else {
            if (error.code || error.name) monitoringEvent.SdkException = error.code || error.name;
            if (error.message) monitoringEvent.SdkExceptionMessage = error.message;
        }
        return monitoringEvent;
    },
    /**
   * Attach listeners to request object to fetch metrics of each request
   * and emit data object through \'ApiCall\' and \'ApiCallAttempt\' events.
   * @api private
   */ attachMonitoringEmitter: function attachMonitoringEmitter(request) {
        var attemptTimestamp; //timestamp marking the beginning of a request attempt
        var attemptStartRealTime; //Start time of request attempt. Used to calculating attemptLatency
        var attemptLatency; //latency from request sent out to http response reaching SDK
        var callStartRealTime; //Start time of API call. Used to calculating API call latency
        var attemptCount = 0; //request.retryCount is not reliable here
        var region; //region cache region for each attempt since it can be updated in plase (e.g. s3)
        var callTimestamp; //timestamp when the request is created
        var self = this;
        var addToHead = true;
        request.on('validate', function() {
            callStartRealTime = $hIq4q.util.realClock.now();
            callTimestamp = Date.now();
        }, addToHead);
        request.on('sign', function() {
            attemptStartRealTime = $hIq4q.util.realClock.now();
            attemptTimestamp = Date.now();
            region = request.httpRequest.region;
            attemptCount++;
        }, addToHead);
        request.on('validateResponse', function() {
            attemptLatency = Math.round($hIq4q.util.realClock.now() - attemptStartRealTime);
        });
        request.addNamedListener('API_CALL_ATTEMPT', 'success', function API_CALL_ATTEMPT() {
            var apiAttemptEvent = self.apiAttemptEvent(request);
            apiAttemptEvent.Timestamp = attemptTimestamp;
            apiAttemptEvent.AttemptLatency = attemptLatency >= 0 ? attemptLatency : 0;
            apiAttemptEvent.Region = region;
            self.emit('apiCallAttempt', [
                apiAttemptEvent
            ]);
        });
        request.addNamedListener('API_CALL_ATTEMPT_RETRY', 'retry', function API_CALL_ATTEMPT_RETRY() {
            var apiAttemptEvent = self.attemptFailEvent(request);
            apiAttemptEvent.Timestamp = attemptTimestamp;
            //attemptLatency may not be available if fail before response
            attemptLatency = attemptLatency || Math.round($hIq4q.util.realClock.now() - attemptStartRealTime);
            apiAttemptEvent.AttemptLatency = attemptLatency >= 0 ? attemptLatency : 0;
            apiAttemptEvent.Region = region;
            self.emit('apiCallAttempt', [
                apiAttemptEvent
            ]);
        });
        request.addNamedListener('API_CALL', 'complete', function API_CALL() {
            var apiCallEvent = self.apiCallEvent(request);
            apiCallEvent.AttemptCount = attemptCount;
            if (apiCallEvent.AttemptCount <= 0) return;
            apiCallEvent.Timestamp = callTimestamp;
            var latency = Math.round($hIq4q.util.realClock.now() - callStartRealTime);
            apiCallEvent.Latency = latency >= 0 ? latency : 0;
            var response = request.response;
            if (response.error && response.error.retryable && typeof response.retryCount === 'number' && typeof response.maxRetries === 'number' && response.retryCount >= response.maxRetries) apiCallEvent.MaxRetriesExceeded = 1;
            self.emit('apiCall', [
                apiCallEvent
            ]);
        });
    },
    /**
   * Override this method to setup any custom request listeners for each
   * new request to the service.
   *
   * @method_abstract This is an abstract method.
   */ setupRequestListeners: function setupRequestListeners(request) {},
    /**
   * Gets the signing name for a given request
   * @api private
   */ getSigningName: function getSigningName() {
        return this.api.signingName || this.api.endpointPrefix;
    },
    /**
   * Gets the signer class for a given request
   * @api private
   */ getSignerClass: function getSignerClass(request) {
        var version;
        // get operation authtype if present
        var operation = null;
        var authtype = '';
        if (request) {
            var operations = request.service.api.operations || {};
            operation = operations[request.operation] || null;
            authtype = operation ? operation.authtype : '';
        }
        if (this.config.signatureVersion) version = this.config.signatureVersion;
        else if (authtype === 'v4' || authtype === 'v4-unsigned-body') version = 'v4';
        else if (authtype === 'bearer') version = 'bearer';
        else version = this.api.signatureVersion;
        return $hIq4q.Signers.RequestSigner.getVersion(version);
    },
    /**
   * @api private
   */ serviceInterface: function serviceInterface() {
        switch(this.api.protocol){
            case 'ec2':
                return $hIq4q.EventListeners.Query;
            case 'query':
                return $hIq4q.EventListeners.Query;
            case 'json':
                return $hIq4q.EventListeners.Json;
            case 'rest-json':
                return $hIq4q.EventListeners.RestJson;
            case 'rest-xml':
                return $hIq4q.EventListeners.RestXml;
        }
        if (this.api.protocol) throw new Error('Invalid service `protocol\' ' + this.api.protocol + ' in API config');
    },
    /**
   * @api private
   */ successfulResponse: function successfulResponse(resp) {
        return resp.httpResponse.statusCode < 300;
    },
    /**
   * How many times a failed request should be retried before giving up.
   * the defaultRetryCount can be overriden by service classes.
   *
   * @api private
   */ numRetries: function numRetries() {
        if (this.config.maxRetries !== undefined) return this.config.maxRetries;
        else return this.defaultRetryCount;
    },
    /**
   * @api private
   */ retryDelays: function retryDelays(retryCount, err) {
        return $hIq4q.util.calculateRetryDelay(retryCount, this.config.retryDelayOptions, err);
    },
    /**
   * @api private
   */ retryableError: function retryableError(error) {
        if (this.timeoutError(error)) return true;
        if (this.networkingError(error)) return true;
        if (this.expiredCredentialsError(error)) return true;
        if (this.throttledError(error)) return true;
        if (error.statusCode >= 500) return true;
        return false;
    },
    /**
   * @api private
   */ networkingError: function networkingError(error) {
        return error.code === 'NetworkingError';
    },
    /**
   * @api private
   */ timeoutError: function timeoutError(error) {
        return error.code === 'TimeoutError';
    },
    /**
   * @api private
   */ expiredCredentialsError: function expiredCredentialsError(error) {
        // TODO : this only handles *one* of the expired credential codes
        return error.code === 'ExpiredTokenException';
    },
    /**
   * @api private
   */ clockSkewError: function clockSkewError(error) {
        switch(error.code){
            case 'RequestTimeTooSkewed':
            case 'RequestExpired':
            case 'InvalidSignatureException':
            case 'SignatureDoesNotMatch':
            case 'AuthFailure':
            case 'RequestInTheFuture':
                return true;
            default:
                return false;
        }
    },
    /**
   * @api private
   */ getSkewCorrectedDate: function getSkewCorrectedDate() {
        return new Date(Date.now() + this.config.systemClockOffset);
    },
    /**
   * @api private
   */ applyClockOffset: function applyClockOffset(newServerTime) {
        if (newServerTime) this.config.systemClockOffset = newServerTime - Date.now();
    },
    /**
   * @api private
   */ isClockSkewed: function isClockSkewed(newServerTime) {
        if (newServerTime) return Math.abs(this.getSkewCorrectedDate().getTime() - newServerTime) >= 300000;
    },
    /**
   * @api private
   */ throttledError: function throttledError(error) {
        // this logic varies between services
        if (error.statusCode === 429) return true;
        switch(error.code){
            case 'ProvisionedThroughputExceededException':
            case 'Throttling':
            case 'ThrottlingException':
            case 'RequestLimitExceeded':
            case 'RequestThrottled':
            case 'RequestThrottledException':
            case 'TooManyRequestsException':
            case 'TransactionInProgressException':
            case 'EC2ThrottledException':
                return true;
            default:
                return false;
        }
    },
    /**
   * @api private
   */ endpointFromTemplate: function endpointFromTemplate(endpoint) {
        if (typeof endpoint !== 'string') return endpoint;
        var e = endpoint;
        e = e.replace(/\{service\}/g, this.api.endpointPrefix);
        e = e.replace(/\{region\}/g, this.config.region);
        e = e.replace(/\{scheme\}/g, this.config.sslEnabled ? 'https' : 'http');
        return e;
    },
    /**
   * @api private
   */ setEndpoint: function setEndpoint(endpoint) {
        this.endpoint = new $hIq4q.Endpoint(endpoint, this.config);
    },
    /**
   * @api private
   */ paginationConfig: function paginationConfig(operation, throwException) {
        var paginator = this.api.operations[operation].paginator;
        if (!paginator) {
            if (throwException) {
                var e = new Error();
                throw $hIq4q.util.error(e, 'No pagination configuration for ' + operation);
            }
            return null;
        }
        return paginator;
    }
});
$hIq4q.util.update($hIq4q.Service, {
    /**
   * Adds one method for each operation described in the api configuration
   *
   * @api private
   */ defineMethods: function defineMethods(svc) {
        $hIq4q.util.each(svc.prototype.api.operations, function iterator(method) {
            if (svc.prototype[method]) return;
            var operation = svc.prototype.api.operations[method];
            if (operation.authtype === 'none') svc.prototype[method] = function(params, callback) {
                return this.makeUnauthenticatedRequest(method, params, callback);
            };
            else svc.prototype[method] = function(params, callback) {
                return this.makeRequest(method, params, callback);
            };
        });
    },
    /**
   * Defines a new Service class using a service identifier and list of versions
   * including an optional set of features (functions) to apply to the class
   * prototype.
   *
   * @param serviceIdentifier [String] the identifier for the service
   * @param versions [Array<String>] a list of versions that work with this
   *   service
   * @param features [Object] an object to attach to the prototype
   * @return [Class<Service>] the service class defined by this function.
   */ defineService: function defineService(serviceIdentifier, versions, features) {
        $hIq4q.Service._serviceMap[serviceIdentifier] = true;
        if (!Array.isArray(versions)) {
            features = versions;
            versions = [];
        }
        var svc = $85fde194fa4232e2$var$inherit($hIq4q.Service, features || {});
        if (typeof serviceIdentifier === 'string') {
            $hIq4q.Service.addVersions(svc, versions);
            var identifier = svc.serviceIdentifier || serviceIdentifier;
            svc.serviceIdentifier = identifier;
        } else {
            svc.prototype.api = serviceIdentifier;
            $hIq4q.Service.defineMethods(svc);
        }
        $hIq4q.SequentialExecutor.call(this.prototype);
        //util.clientSideMonitoring is only available in node
        if (!this.prototype.publisher && $hIq4q.util.clientSideMonitoring) {
            var Publisher = $hIq4q.util.clientSideMonitoring.Publisher;
            var configProvider = $hIq4q.util.clientSideMonitoring.configProvider;
            var publisherConfig = configProvider();
            this.prototype.publisher = new Publisher(publisherConfig);
            if (publisherConfig.enabled) //if csm is enabled in environment, SDK should send all metrics
            $hIq4q.Service._clientSideMonitoring = true;
        }
        $hIq4q.SequentialExecutor.call(svc.prototype);
        $hIq4q.Service.addDefaultMonitoringListeners(svc.prototype);
        return svc;
    },
    /**
   * @api private
   */ addVersions: function addVersions(svc, versions) {
        if (!Array.isArray(versions)) versions = [
            versions
        ];
        svc.services = svc.services || {};
        for(var i = 0; i < versions.length; i++)if (svc.services[versions[i]] === undefined) svc.services[versions[i]] = null;
        svc.apiVersions = Object.keys(svc.services).sort();
    },
    /**
   * @api private
   */ defineServiceApi: function defineServiceApi(superclass, version, apiConfig) {
        var svc = $85fde194fa4232e2$var$inherit(superclass, {
            serviceIdentifier: superclass.serviceIdentifier
        });
        function setApi(api) {
            if (api.isApi) svc.prototype.api = api;
            else svc.prototype.api = new $g9WzK(api, {
                serviceIdentifier: superclass.serviceIdentifier
            });
        }
        if (typeof version === 'string') {
            if (apiConfig) setApi(apiConfig);
            else try {
                setApi($hIq4q.apiLoader(superclass.serviceIdentifier, version));
            } catch (err) {
                throw $hIq4q.util.error(err, {
                    message: 'Could not find API configuration ' + superclass.serviceIdentifier + '-' + version
                });
            }
            if (!Object.prototype.hasOwnProperty.call(superclass.services, version)) superclass.apiVersions = superclass.apiVersions.concat(version).sort();
            superclass.services[version] = svc;
        } else setApi(version);
        $hIq4q.Service.defineMethods(svc);
        return svc;
    },
    /**
   * @api private
   */ hasService: function(identifier) {
        return Object.prototype.hasOwnProperty.call($hIq4q.Service._serviceMap, identifier);
    },
    /**
   * @param attachOn attach default monitoring listeners to object
   *
   * Each monitoring event should be emitted from service client to service constructor prototype and then
   * to global service prototype like bubbling up. These default monitoring events listener will transfer
   * the monitoring events to the upper layer.
   * @api private
   */ addDefaultMonitoringListeners: function addDefaultMonitoringListeners(attachOn) {
        attachOn.addNamedListener('MONITOR_EVENTS_BUBBLE', 'apiCallAttempt', function EVENTS_BUBBLE(event) {
            var baseClass = Object.getPrototypeOf(attachOn);
            if (baseClass._events) baseClass.emit('apiCallAttempt', [
                event
            ]);
        });
        attachOn.addNamedListener('CALL_EVENTS_BUBBLE', 'apiCall', function CALL_EVENTS_BUBBLE(event) {
            var baseClass = Object.getPrototypeOf(attachOn);
            if (baseClass._events) baseClass.emit('apiCall', [
                event
            ]);
        });
    },
    /**
   * @api private
   */ _serviceMap: {}
});
$hIq4q.util.mixin($hIq4q.Service, $hIq4q.SequentialExecutor);
/**
 * @api private
 */ module.exports = $hIq4q.Service;

});
parcelRegister("03Joe", function(module, exports) {

var $i3HcT = parcelRequire("i3HcT");

var $hlfQK = parcelRequire("hlfQK");
function $00b37d6e54aacdf8$var$generateRegionPrefix(region) {
    if (!region) return null;
    var parts = region.split('-');
    if (parts.length < 3) return null;
    return parts.slice(0, parts.length - 2).join('-') + '-*';
}
function $00b37d6e54aacdf8$var$derivedKeys(service) {
    var region = service.config.region;
    var regionPrefix = $00b37d6e54aacdf8$var$generateRegionPrefix(region);
    var endpointPrefix = service.api.endpointPrefix;
    return [
        [
            region,
            endpointPrefix
        ],
        [
            regionPrefix,
            endpointPrefix
        ],
        [
            region,
            '*'
        ],
        [
            regionPrefix,
            '*'
        ],
        [
            '*',
            endpointPrefix
        ],
        [
            region,
            'internal-*'
        ],
        [
            '*',
            '*'
        ]
    ].map(function(item) {
        return item[0] && item[1] ? item.join('/') : null;
    });
}
function $00b37d6e54aacdf8$var$applyConfig(service, config) {
    $i3HcT.each(config, function(key, value) {
        if (key === 'globalEndpoint') return;
        if (service.config[key] === undefined || service.config[key] === null) service.config[key] = value;
    });
}
function $00b37d6e54aacdf8$var$configureEndpoint(service) {
    var keys = $00b37d6e54aacdf8$var$derivedKeys(service);
    var useFipsEndpoint = service.config.useFipsEndpoint;
    var useDualstackEndpoint = service.config.useDualstackEndpoint;
    for(var i = 0; i < keys.length; i++){
        var key = keys[i];
        if (!key) continue;
        var rules = useFipsEndpoint ? useDualstackEndpoint ? $hlfQK.dualstackFipsRules : $hlfQK.fipsRules : useDualstackEndpoint ? $hlfQK.dualstackRules : $hlfQK.rules;
        if (Object.prototype.hasOwnProperty.call(rules, key)) {
            var config = rules[key];
            if (typeof config === 'string') config = $hlfQK.patterns[config];
            // set global endpoint
            service.isGlobalEndpoint = !!config.globalEndpoint;
            if (config.signingRegion) service.signingRegion = config.signingRegion;
            // signature version
            if (!config.signatureVersion) // Note: config is a global object and should not be mutated here.
            // However, we are retaining this line for backwards compatibility.
            // The non-v4 signatureVersion will be set in a copied object below.
            config.signatureVersion = 'v4';
            var useBearer = (service.api && service.api.signatureVersion) === 'bearer';
            // merge config
            $00b37d6e54aacdf8$var$applyConfig(service, Object.assign({}, config, {
                signatureVersion: useBearer ? 'bearer' : config.signatureVersion
            }));
            return;
        }
    }
}
function $00b37d6e54aacdf8$var$getEndpointSuffix(region) {
    var regionRegexes = {
        '^(us|eu|ap|sa|ca|me)\\-\\w+\\-\\d+$': 'amazonaws.com',
        '^cn\\-\\w+\\-\\d+$': 'amazonaws.com.cn',
        '^us\\-gov\\-\\w+\\-\\d+$': 'amazonaws.com',
        '^us\\-iso\\-\\w+\\-\\d+$': 'c2s.ic.gov',
        '^us\\-isob\\-\\w+\\-\\d+$': 'sc2s.sgov.gov',
        '^eu\\-isoe\\-west\\-1$': 'cloud.adc-e.uk',
        '^us\\-isof\\-\\w+\\-\\d+$': 'csp.hci.ic.gov'
    };
    var defaultSuffix = 'amazonaws.com';
    var regexes = Object.keys(regionRegexes);
    for(var i = 0; i < regexes.length; i++){
        var regionPattern = RegExp(regexes[i]);
        var dnsSuffix = regionRegexes[regexes[i]];
        if (regionPattern.test(region)) return dnsSuffix;
    }
    return defaultSuffix;
}
/**
 * @api private
 */ module.exports = {
    configureEndpoint: $00b37d6e54aacdf8$var$configureEndpoint,
    getEndpointSuffix: $00b37d6e54aacdf8$var$getEndpointSuffix
};

});
parcelRegister("hlfQK", function(module, exports) {
module.exports = JSON.parse("{\"rules\":{\"*/*\":{\"endpoint\":\"{service}.{region}.amazonaws.com\"},\"cn-*/*\":{\"endpoint\":\"{service}.{region}.amazonaws.com.cn\"},\"eu-isoe-*/*\":\"euIsoe\",\"us-iso-*/*\":\"usIso\",\"us-isob-*/*\":\"usIsob\",\"us-isof-*/*\":\"usIsof\",\"*/budgets\":\"globalSSL\",\"*/cloudfront\":\"globalSSL\",\"*/sts\":\"globalSSL\",\"*/importexport\":{\"endpoint\":\"{service}.amazonaws.com\",\"signatureVersion\":\"v2\",\"globalEndpoint\":true},\"*/route53\":\"globalSSL\",\"cn-*/route53\":{\"endpoint\":\"{service}.amazonaws.com.cn\",\"globalEndpoint\":true,\"signingRegion\":\"cn-northwest-1\"},\"us-gov-*/route53\":\"globalGovCloud\",\"us-iso-*/route53\":{\"endpoint\":\"{service}.c2s.ic.gov\",\"globalEndpoint\":true,\"signingRegion\":\"us-iso-east-1\"},\"us-isob-*/route53\":{\"endpoint\":\"{service}.sc2s.sgov.gov\",\"globalEndpoint\":true,\"signingRegion\":\"us-isob-east-1\"},\"us-isof-*/route53\":\"globalUsIsof\",\"eu-isoe-*/route53\":\"globalEuIsoe\",\"*/waf\":\"globalSSL\",\"*/iam\":\"globalSSL\",\"cn-*/iam\":{\"endpoint\":\"{service}.cn-north-1.amazonaws.com.cn\",\"globalEndpoint\":true,\"signingRegion\":\"cn-north-1\"},\"us-iso-*/iam\":{\"endpoint\":\"{service}.us-iso-east-1.c2s.ic.gov\",\"globalEndpoint\":true,\"signingRegion\":\"us-iso-east-1\"},\"us-gov-*/iam\":\"globalGovCloud\",\"*/ce\":{\"endpoint\":\"{service}.us-east-1.amazonaws.com\",\"globalEndpoint\":true,\"signingRegion\":\"us-east-1\"},\"cn-*/ce\":{\"endpoint\":\"{service}.cn-northwest-1.amazonaws.com.cn\",\"globalEndpoint\":true,\"signingRegion\":\"cn-northwest-1\"},\"us-gov-*/sts\":{\"endpoint\":\"{service}.{region}.amazonaws.com\"},\"us-gov-west-1/s3\":\"s3signature\",\"us-west-1/s3\":\"s3signature\",\"us-west-2/s3\":\"s3signature\",\"eu-west-1/s3\":\"s3signature\",\"ap-southeast-1/s3\":\"s3signature\",\"ap-southeast-2/s3\":\"s3signature\",\"ap-northeast-1/s3\":\"s3signature\",\"sa-east-1/s3\":\"s3signature\",\"us-east-1/s3\":{\"endpoint\":\"{service}.amazonaws.com\",\"signatureVersion\":\"s3\"},\"us-east-1/sdb\":{\"endpoint\":\"{service}.amazonaws.com\",\"signatureVersion\":\"v2\"},\"*/sdb\":{\"endpoint\":\"{service}.{region}.amazonaws.com\",\"signatureVersion\":\"v2\"},\"*/resource-explorer-2\":\"dualstackByDefault\",\"*/kendra-ranking\":\"dualstackByDefault\",\"*/internetmonitor\":\"dualstackByDefault\",\"*/codecatalyst\":\"globalDualstackByDefault\"},\"fipsRules\":{\"*/*\":\"fipsStandard\",\"us-gov-*/*\":\"fipsStandard\",\"us-iso-*/*\":{\"endpoint\":\"{service}-fips.{region}.c2s.ic.gov\"},\"us-iso-*/dms\":\"usIso\",\"us-isob-*/*\":{\"endpoint\":\"{service}-fips.{region}.sc2s.sgov.gov\"},\"us-isob-*/dms\":\"usIsob\",\"cn-*/*\":{\"endpoint\":\"{service}-fips.{region}.amazonaws.com.cn\"},\"*/api.ecr\":\"fips.api.ecr\",\"*/api.sagemaker\":\"fips.api.sagemaker\",\"*/batch\":\"fipsDotPrefix\",\"*/eks\":\"fipsDotPrefix\",\"*/models.lex\":\"fips.models.lex\",\"*/runtime.lex\":\"fips.runtime.lex\",\"*/runtime.sagemaker\":{\"endpoint\":\"runtime-fips.sagemaker.{region}.amazonaws.com\"},\"*/iam\":\"fipsWithoutRegion\",\"*/route53\":\"fipsWithoutRegion\",\"*/transcribe\":\"fipsDotPrefix\",\"*/waf\":\"fipsWithoutRegion\",\"us-gov-*/transcribe\":\"fipsDotPrefix\",\"us-gov-*/api.ecr\":\"fips.api.ecr\",\"us-gov-*/models.lex\":\"fips.models.lex\",\"us-gov-*/runtime.lex\":\"fips.runtime.lex\",\"us-gov-*/access-analyzer\":\"fipsWithServiceOnly\",\"us-gov-*/acm\":\"fipsWithServiceOnly\",\"us-gov-*/acm-pca\":\"fipsWithServiceOnly\",\"us-gov-*/api.sagemaker\":\"fipsWithServiceOnly\",\"us-gov-*/appconfig\":\"fipsWithServiceOnly\",\"us-gov-*/application-autoscaling\":\"fipsWithServiceOnly\",\"us-gov-*/autoscaling\":\"fipsWithServiceOnly\",\"us-gov-*/autoscaling-plans\":\"fipsWithServiceOnly\",\"us-gov-*/batch\":\"fipsWithServiceOnly\",\"us-gov-*/cassandra\":\"fipsWithServiceOnly\",\"us-gov-*/clouddirectory\":\"fipsWithServiceOnly\",\"us-gov-*/cloudformation\":\"fipsWithServiceOnly\",\"us-gov-*/cloudshell\":\"fipsWithServiceOnly\",\"us-gov-*/cloudtrail\":\"fipsWithServiceOnly\",\"us-gov-*/config\":\"fipsWithServiceOnly\",\"us-gov-*/connect\":\"fipsWithServiceOnly\",\"us-gov-*/databrew\":\"fipsWithServiceOnly\",\"us-gov-*/dlm\":\"fipsWithServiceOnly\",\"us-gov-*/dms\":\"fipsWithServiceOnly\",\"us-gov-*/dynamodb\":\"fipsWithServiceOnly\",\"us-gov-*/ec2\":\"fipsWithServiceOnly\",\"us-gov-*/eks\":\"fipsWithServiceOnly\",\"us-gov-*/elasticache\":\"fipsWithServiceOnly\",\"us-gov-*/elasticbeanstalk\":\"fipsWithServiceOnly\",\"us-gov-*/elasticloadbalancing\":\"fipsWithServiceOnly\",\"us-gov-*/elasticmapreduce\":\"fipsWithServiceOnly\",\"us-gov-*/events\":\"fipsWithServiceOnly\",\"us-gov-*/fis\":\"fipsWithServiceOnly\",\"us-gov-*/glacier\":\"fipsWithServiceOnly\",\"us-gov-*/greengrass\":\"fipsWithServiceOnly\",\"us-gov-*/guardduty\":\"fipsWithServiceOnly\",\"us-gov-*/identitystore\":\"fipsWithServiceOnly\",\"us-gov-*/imagebuilder\":\"fipsWithServiceOnly\",\"us-gov-*/kafka\":\"fipsWithServiceOnly\",\"us-gov-*/kinesis\":\"fipsWithServiceOnly\",\"us-gov-*/logs\":\"fipsWithServiceOnly\",\"us-gov-*/mediaconvert\":\"fipsWithServiceOnly\",\"us-gov-*/monitoring\":\"fipsWithServiceOnly\",\"us-gov-*/networkmanager\":\"fipsWithServiceOnly\",\"us-gov-*/organizations\":\"fipsWithServiceOnly\",\"us-gov-*/outposts\":\"fipsWithServiceOnly\",\"us-gov-*/participant.connect\":\"fipsWithServiceOnly\",\"us-gov-*/ram\":\"fipsWithServiceOnly\",\"us-gov-*/rds\":\"fipsWithServiceOnly\",\"us-gov-*/redshift\":\"fipsWithServiceOnly\",\"us-gov-*/resource-groups\":\"fipsWithServiceOnly\",\"us-gov-*/runtime.sagemaker\":\"fipsWithServiceOnly\",\"us-gov-*/serverlessrepo\":\"fipsWithServiceOnly\",\"us-gov-*/servicecatalog-appregistry\":\"fipsWithServiceOnly\",\"us-gov-*/servicequotas\":\"fipsWithServiceOnly\",\"us-gov-*/sns\":\"fipsWithServiceOnly\",\"us-gov-*/sqs\":\"fipsWithServiceOnly\",\"us-gov-*/ssm\":\"fipsWithServiceOnly\",\"us-gov-*/streams.dynamodb\":\"fipsWithServiceOnly\",\"us-gov-*/sts\":\"fipsWithServiceOnly\",\"us-gov-*/support\":\"fipsWithServiceOnly\",\"us-gov-*/swf\":\"fipsWithServiceOnly\",\"us-gov-west-1/states\":\"fipsWithServiceOnly\",\"us-iso-east-1/elasticfilesystem\":{\"endpoint\":\"elasticfilesystem-fips.{region}.c2s.ic.gov\"},\"us-gov-west-1/organizations\":\"fipsWithServiceOnly\",\"us-gov-west-1/route53\":{\"endpoint\":\"route53.us-gov.amazonaws.com\"},\"*/resource-explorer-2\":\"fipsDualstackByDefault\",\"*/kendra-ranking\":\"dualstackByDefault\",\"*/internetmonitor\":\"dualstackByDefault\",\"*/codecatalyst\":\"fipsGlobalDualstackByDefault\"},\"dualstackRules\":{\"*/*\":{\"endpoint\":\"{service}.{region}.api.aws\"},\"cn-*/*\":{\"endpoint\":\"{service}.{region}.api.amazonwebservices.com.cn\"},\"*/s3\":\"dualstackLegacy\",\"cn-*/s3\":\"dualstackLegacyCn\",\"*/s3-control\":\"dualstackLegacy\",\"cn-*/s3-control\":\"dualstackLegacyCn\",\"ap-south-1/ec2\":\"dualstackLegacyEc2\",\"eu-west-1/ec2\":\"dualstackLegacyEc2\",\"sa-east-1/ec2\":\"dualstackLegacyEc2\",\"us-east-1/ec2\":\"dualstackLegacyEc2\",\"us-east-2/ec2\":\"dualstackLegacyEc2\",\"us-west-2/ec2\":\"dualstackLegacyEc2\"},\"dualstackFipsRules\":{\"*/*\":{\"endpoint\":\"{service}-fips.{region}.api.aws\"},\"cn-*/*\":{\"endpoint\":\"{service}-fips.{region}.api.amazonwebservices.com.cn\"},\"*/s3\":\"dualstackFipsLegacy\",\"cn-*/s3\":\"dualstackFipsLegacyCn\",\"*/s3-control\":\"dualstackFipsLegacy\",\"cn-*/s3-control\":\"dualstackFipsLegacyCn\"},\"patterns\":{\"globalSSL\":{\"endpoint\":\"https://{service}.amazonaws.com\",\"globalEndpoint\":true,\"signingRegion\":\"us-east-1\"},\"globalGovCloud\":{\"endpoint\":\"{service}.us-gov.amazonaws.com\",\"globalEndpoint\":true,\"signingRegion\":\"us-gov-west-1\"},\"globalUsIsof\":{\"endpoint\":\"{service}.csp.hci.ic.gov\",\"globalEndpoint\":true,\"signingRegion\":\"us-isof-south-1\"},\"globalEuIsoe\":{\"endpoint\":\"{service}.cloud.adc-e.uk\",\"globalEndpoint\":true,\"signingRegion\":\"eu-isoe-west-1\"},\"s3signature\":{\"endpoint\":\"{service}.{region}.amazonaws.com\",\"signatureVersion\":\"s3\"},\"euIsoe\":{\"endpoint\":\"{service}.{region}.cloud.adc-e.uk\"},\"usIso\":{\"endpoint\":\"{service}.{region}.c2s.ic.gov\"},\"usIsob\":{\"endpoint\":\"{service}.{region}.sc2s.sgov.gov\"},\"usIsof\":{\"endpoint\":\"{service}.{region}.csp.hci.ic.gov\"},\"fipsStandard\":{\"endpoint\":\"{service}-fips.{region}.amazonaws.com\"},\"fipsDotPrefix\":{\"endpoint\":\"fips.{service}.{region}.amazonaws.com\"},\"fipsWithoutRegion\":{\"endpoint\":\"{service}-fips.amazonaws.com\"},\"fips.api.ecr\":{\"endpoint\":\"ecr-fips.{region}.amazonaws.com\"},\"fips.api.sagemaker\":{\"endpoint\":\"api-fips.sagemaker.{region}.amazonaws.com\"},\"fips.models.lex\":{\"endpoint\":\"models-fips.lex.{region}.amazonaws.com\"},\"fips.runtime.lex\":{\"endpoint\":\"runtime-fips.lex.{region}.amazonaws.com\"},\"fipsWithServiceOnly\":{\"endpoint\":\"{service}.{region}.amazonaws.com\"},\"dualstackLegacy\":{\"endpoint\":\"{service}.dualstack.{region}.amazonaws.com\"},\"dualstackLegacyCn\":{\"endpoint\":\"{service}.dualstack.{region}.amazonaws.com.cn\"},\"dualstackFipsLegacy\":{\"endpoint\":\"{service}-fips.dualstack.{region}.amazonaws.com\"},\"dualstackFipsLegacyCn\":{\"endpoint\":\"{service}-fips.dualstack.{region}.amazonaws.com.cn\"},\"dualstackLegacyEc2\":{\"endpoint\":\"api.ec2.{region}.aws\"},\"dualstackByDefault\":{\"endpoint\":\"{service}.{region}.api.aws\"},\"fipsDualstackByDefault\":{\"endpoint\":\"{service}-fips.{region}.api.aws\"},\"globalDualstackByDefault\":{\"endpoint\":\"{service}.global.api.aws\"},\"fipsGlobalDualstackByDefault\":{\"endpoint\":\"{service}-fips.global.api.aws\"}}}");

});


parcelRegister("gffN3", function(module, exports) {
function $bd3a4bab26c2bcd0$var$isFipsRegion(region) {
    return typeof region === 'string' && (region.startsWith('fips-') || region.endsWith('-fips'));
}
function $bd3a4bab26c2bcd0$var$isGlobalRegion(region) {
    return typeof region === 'string' && [
        'aws-global',
        'aws-us-gov-global'
    ].includes(region);
}
function $bd3a4bab26c2bcd0$var$getRealRegion(region) {
    return [
        'fips-aws-global',
        'aws-fips',
        'aws-global'
    ].includes(region) ? 'us-east-1' : [
        'fips-aws-us-gov-global',
        'aws-us-gov-global'
    ].includes(region) ? 'us-gov-west-1' : region.replace(/fips-(dkr-|prod-)?|-fips/, '');
}
module.exports = {
    isFipsRegion: $bd3a4bab26c2bcd0$var$isFipsRegion,
    isGlobalRegion: $bd3a4bab26c2bcd0$var$isGlobalRegion,
    getRealRegion: $bd3a4bab26c2bcd0$var$getRealRegion
};

});


parcelRegister("jWuBc", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
parcelRequire("f9Kfu");
parcelRequire("f4h1X");
var $e84b2b6bb405e513$var$PromisesDependency;
/**
 * The main configuration class used by all service objects to set
 * the region, credentials, and other options for requests.
 *
 * By default, credentials and region settings are left unconfigured.
 * This should be configured by the application before using any
 * AWS service APIs.
 *
 * In order to set global configuration options, properties should
 * be assigned to the global {AWS.config} object.
 *
 * @see AWS.config
 *
 * @!group General Configuration Options
 *
 * @!attribute credentials
 *   @return [AWS.Credentials] the AWS credentials to sign requests with.
 *
 * @!attribute region
 *   @example Set the global region setting to us-west-2
 *     AWS.config.update({region: 'us-west-2'});
 *   @return [AWS.Credentials] The region to send service requests to.
 *   @see http://docs.amazonwebservices.com/general/latest/gr/rande.html
 *     A list of available endpoints for each AWS service
 *
 * @!attribute maxRetries
 *   @return [Integer] the maximum amount of retries to perform for a
 *     service request. By default this value is calculated by the specific
 *     service object that the request is being made to.
 *
 * @!attribute maxRedirects
 *   @return [Integer] the maximum amount of redirects to follow for a
 *     service request. Defaults to 10.
 *
 * @!attribute paramValidation
 *   @return [Boolean|map] whether input parameters should be validated against
 *     the operation description before sending the request. Defaults to true.
 *     Pass a map to enable any of the following specific validation features:
 *
 *     * **min** [Boolean] &mdash; Validates that a value meets the min
 *       constraint. This is enabled by default when paramValidation is set
 *       to `true`.
 *     * **max** [Boolean] &mdash; Validates that a value meets the max
 *       constraint.
 *     * **pattern** [Boolean] &mdash; Validates that a string value matches a
 *       regular expression.
 *     * **enum** [Boolean] &mdash; Validates that a string value matches one
 *       of the allowable enum values.
 *
 * @!attribute computeChecksums
 *   @return [Boolean] whether to compute checksums for payload bodies when
 *     the service accepts it (currently supported in S3 and SQS only).
 *
 * @!attribute convertResponseTypes
 *   @return [Boolean] whether types are converted when parsing response data.
 *     Currently only supported for JSON based services. Turning this off may
 *     improve performance on large response payloads. Defaults to `true`.
 *
 * @!attribute correctClockSkew
 *   @return [Boolean] whether to apply a clock skew correction and retry
 *     requests that fail because of an skewed client clock. Defaults to
 *     `false`.
 *
 * @!attribute sslEnabled
 *   @return [Boolean] whether SSL is enabled for requests
 *
 * @!attribute s3ForcePathStyle
 *   @return [Boolean] whether to force path style URLs for S3 objects
 *
 * @!attribute s3BucketEndpoint
 *   @note Setting this configuration option requires an `endpoint` to be
 *     provided explicitly to the service constructor.
 *   @return [Boolean] whether the provided endpoint addresses an individual
 *     bucket (false if it addresses the root API endpoint).
 *
 * @!attribute s3DisableBodySigning
 *   @return [Boolean] whether to disable S3 body signing when using signature version `v4`.
 *     Body signing can only be disabled when using https. Defaults to `true`.
 *
 * @!attribute s3UsEast1RegionalEndpoint
 *   @return ['legacy'|'regional'] when region is set to 'us-east-1', whether to send s3
 *     request to global endpoints or 'us-east-1' regional endpoints. This config is only
 *     applicable to S3 client;
 *     Defaults to 'legacy'
 * @!attribute s3UseArnRegion
 *   @return [Boolean] whether to override the request region with the region inferred
 *     from requested resource's ARN. Only available for S3 buckets
 *     Defaults to `true`
 *
 * @!attribute useAccelerateEndpoint
 *   @note This configuration option is only compatible with S3 while accessing
 *     dns-compatible buckets.
 *   @return [Boolean] Whether to use the Accelerate endpoint with the S3 service.
 *     Defaults to `false`.
 *
 * @!attribute retryDelayOptions
 *   @example Set the base retry delay for all services to 300 ms
 *     AWS.config.update({retryDelayOptions: {base: 300}});
 *     // Delays with maxRetries = 3: 300, 600, 1200
 *   @example Set a custom backoff function to provide delay values on retries
 *     AWS.config.update({retryDelayOptions: {customBackoff: function(retryCount, err) {
 *       // returns delay in ms
 *     }}});
 *   @return [map] A set of options to configure the retry delay on retryable errors.
 *     Currently supported options are:
 *
 *     * **base** [Integer] &mdash; The base number of milliseconds to use in the
 *       exponential backoff for operation retries. Defaults to 100 ms for all services except
 *       DynamoDB, where it defaults to 50ms.
 *
 *     * **customBackoff ** [function] &mdash; A custom function that accepts a
 *       retry count and error and returns the amount of time to delay in
 *       milliseconds. If the result is a non-zero negative value, no further
 *       retry attempts will be made. The `base` option will be ignored if this
 *       option is supplied. The function is only called for retryable errors.
 *
 * @!attribute httpOptions
 *   @return [map] A set of options to pass to the low-level HTTP request.
 *     Currently supported options are:
 *
 *     * **proxy** [String] &mdash; the URL to proxy requests through
 *     * **agent** [http.Agent, https.Agent] &mdash; the Agent object to perform
 *       HTTP requests with. Used for connection pooling. Note that for
 *       SSL connections, a special Agent object is used in order to enable
 *       peer certificate verification. This feature is only supported in the
 *       Node.js environment.
 *     * **connectTimeout** [Integer] &mdash; Sets the socket to timeout after
 *       failing to establish a connection with the server after
 *       `connectTimeout` milliseconds. This timeout has no effect once a socket
 *       connection has been established.
 *     * **timeout** [Integer] &mdash; The number of milliseconds a request can
 *       take before automatically being terminated.
 *       Defaults to two minutes (120000).
 *     * **xhrAsync** [Boolean] &mdash; Whether the SDK will send asynchronous
 *       HTTP requests. Used in the browser environment only. Set to false to
 *       send requests synchronously. Defaults to true (async on).
 *     * **xhrWithCredentials** [Boolean] &mdash; Sets the "withCredentials"
 *       property of an XMLHttpRequest object. Used in the browser environment
 *       only. Defaults to false.
 * @!attribute logger
 *   @return [#write,#log] an object that responds to .write() (like a stream)
 *     or .log() (like the console object) in order to log information about
 *     requests
 *
 * @!attribute systemClockOffset
 *   @return [Number] an offset value in milliseconds to apply to all signing
 *     times. Use this to compensate for clock skew when your system may be
 *     out of sync with the service time. Note that this configuration option
 *     can only be applied to the global `AWS.config` object and cannot be
 *     overridden in service-specific configuration. Defaults to 0 milliseconds.
 *
 * @!attribute signatureVersion
 *   @return [String] the signature version to sign requests with (overriding
 *     the API configuration). Possible values are: 'v2', 'v3', 'v4'.
 *
 * @!attribute signatureCache
 *   @return [Boolean] whether the signature to sign requests with (overriding
 *     the API configuration) is cached. Only applies to the signature version 'v4'.
 *     Defaults to `true`.
 *
 * @!attribute endpointDiscoveryEnabled
 *   @return [Boolean|undefined] whether to call operations with endpoints
 *     given by service dynamically. Setting this config to `true` will enable
 *     endpoint discovery for all applicable operations. Setting it to `false`
 *     will explicitly disable endpoint discovery even though operations that
 *     require endpoint discovery will presumably fail. Leaving it to
 *     `undefined` means SDK only do endpoint discovery when it's required.
 *     Defaults to `undefined`
 *
 * @!attribute endpointCacheSize
 *   @return [Number] the size of the global cache storing endpoints from endpoint
 *     discovery operations. Once endpoint cache is created, updating this setting
 *     cannot change existing cache size.
 *     Defaults to 1000
 *
 * @!attribute hostPrefixEnabled
 *   @return [Boolean] whether to marshal request parameters to the prefix of
 *     hostname. Defaults to `true`.
 *
 * @!attribute stsRegionalEndpoints
 *   @return ['legacy'|'regional'] whether to send sts request to global endpoints or
 *     regional endpoints.
 *     Defaults to 'legacy'.
 *
 * @!attribute useFipsEndpoint
 *   @return [Boolean] Enables FIPS compatible endpoints. Defaults to `false`.
 *
 * @!attribute useDualstackEndpoint
 *   @return [Boolean] Enables IPv6 dualstack endpoint. Defaults to `false`.
 */ $hIq4q.Config = $hIq4q.util.inherit({
    /**
   * @!endgroup
   */ /**
   * Creates a new configuration object. This is the object that passes
   * option data along to service requests, including credentials, security,
   * region information, and some service specific settings.
   *
   * @example Creating a new configuration object with credentials and region
   *   var config = new AWS.Config({
   *     accessKeyId: 'AKID', secretAccessKey: 'SECRET', region: 'us-west-2'
   *   });
   * @option options accessKeyId [String] your AWS access key ID.
   * @option options secretAccessKey [String] your AWS secret access key.
   * @option options sessionToken [AWS.Credentials] the optional AWS
   *   session token to sign requests with.
   * @option options credentials [AWS.Credentials] the AWS credentials
   *   to sign requests with. You can either specify this object, or
   *   specify the accessKeyId and secretAccessKey options directly.
   * @option options credentialProvider [AWS.CredentialProviderChain] the
   *   provider chain used to resolve credentials if no static `credentials`
   *   property is set.
   * @option options region [String] the region to send service requests to.
   *   See {region} for more information.
   * @option options maxRetries [Integer] the maximum amount of retries to
   *   attempt with a request. See {maxRetries} for more information.
   * @option options maxRedirects [Integer] the maximum amount of redirects to
   *   follow with a request. See {maxRedirects} for more information.
   * @option options sslEnabled [Boolean] whether to enable SSL for
   *   requests.
   * @option options paramValidation [Boolean|map] whether input parameters
   *   should be validated against the operation description before sending
   *   the request. Defaults to true. Pass a map to enable any of the
   *   following specific validation features:
   *
   *   * **min** [Boolean] &mdash; Validates that a value meets the min
   *     constraint. This is enabled by default when paramValidation is set
   *     to `true`.
   *   * **max** [Boolean] &mdash; Validates that a value meets the max
   *     constraint.
   *   * **pattern** [Boolean] &mdash; Validates that a string value matches a
   *     regular expression.
   *   * **enum** [Boolean] &mdash; Validates that a string value matches one
   *     of the allowable enum values.
   * @option options computeChecksums [Boolean] whether to compute checksums
   *   for payload bodies when the service accepts it (currently supported
   *   in S3 only)
   * @option options convertResponseTypes [Boolean] whether types are converted
   *     when parsing response data. Currently only supported for JSON based
   *     services. Turning this off may improve performance on large response
   *     payloads. Defaults to `true`.
   * @option options correctClockSkew [Boolean] whether to apply a clock skew
   *     correction and retry requests that fail because of an skewed client
   *     clock. Defaults to `false`.
   * @option options s3ForcePathStyle [Boolean] whether to force path
   *   style URLs for S3 objects.
   * @option options s3BucketEndpoint [Boolean] whether the provided endpoint
   *   addresses an individual bucket (false if it addresses the root API
   *   endpoint). Note that setting this configuration option requires an
   *   `endpoint` to be provided explicitly to the service constructor.
   * @option options s3DisableBodySigning [Boolean] whether S3 body signing
   *   should be disabled when using signature version `v4`. Body signing
   *   can only be disabled when using https. Defaults to `true`.
   * @option options s3UsEast1RegionalEndpoint ['legacy'|'regional'] when region
   *   is set to 'us-east-1', whether to send s3 request to global endpoints or
   *   'us-east-1' regional endpoints. This config is only applicable to S3 client.
   *   Defaults to `legacy`
   * @option options s3UseArnRegion [Boolean] whether to override the request region
   *   with the region inferred from requested resource's ARN. Only available for S3 buckets
   *   Defaults to `true`
   *
   * @option options retryDelayOptions [map] A set of options to configure
   *   the retry delay on retryable errors. Currently supported options are:
   *
   *   * **base** [Integer] &mdash; The base number of milliseconds to use in the
   *     exponential backoff for operation retries. Defaults to 100 ms for all
   *     services except DynamoDB, where it defaults to 50ms.
   *   * **customBackoff ** [function] &mdash; A custom function that accepts a
   *     retry count and error and returns the amount of time to delay in
   *     milliseconds. If the result is a non-zero negative value, no further
   *     retry attempts will be made. The `base` option will be ignored if this
   *     option is supplied. The function is only called for retryable errors.
   * @option options httpOptions [map] A set of options to pass to the low-level
   *   HTTP request. Currently supported options are:
   *
   *   * **proxy** [String] &mdash; the URL to proxy requests through
   *   * **agent** [http.Agent, https.Agent] &mdash; the Agent object to perform
   *     HTTP requests with. Used for connection pooling. Defaults to the global
   *     agent (`http.globalAgent`) for non-SSL connections. Note that for
   *     SSL connections, a special Agent object is used in order to enable
   *     peer certificate verification. This feature is only available in the
   *     Node.js environment.
   *   * **connectTimeout** [Integer] &mdash; Sets the socket to timeout after
   *     failing to establish a connection with the server after
   *     `connectTimeout` milliseconds. This timeout has no effect once a socket
   *     connection has been established.
   *   * **timeout** [Integer] &mdash; Sets the socket to timeout after timeout
   *     milliseconds of inactivity on the socket. Defaults to two minutes
   *     (120000).
   *   * **xhrAsync** [Boolean] &mdash; Whether the SDK will send asynchronous
   *     HTTP requests. Used in the browser environment only. Set to false to
   *     send requests synchronously. Defaults to true (async on).
   *   * **xhrWithCredentials** [Boolean] &mdash; Sets the "withCredentials"
   *     property of an XMLHttpRequest object. Used in the browser environment
   *     only. Defaults to false.
   * @option options apiVersion [String, Date] a String in YYYY-MM-DD format
   *   (or a date) that represents the latest possible API version that can be
   *   used in all services (unless overridden by `apiVersions`). Specify
   *   'latest' to use the latest possible version.
   * @option options apiVersions [map<String, String|Date>] a map of service
   *   identifiers (the lowercase service class name) with the API version to
   *   use when instantiating a service. Specify 'latest' for each individual
   *   that can use the latest available version.
   * @option options logger [#write,#log] an object that responds to .write()
   *   (like a stream) or .log() (like the console object) in order to log
   *   information about requests
   * @option options systemClockOffset [Number] an offset value in milliseconds
   *   to apply to all signing times. Use this to compensate for clock skew
   *   when your system may be out of sync with the service time. Note that
   *   this configuration option can only be applied to the global `AWS.config`
   *   object and cannot be overridden in service-specific configuration.
   *   Defaults to 0 milliseconds.
   * @option options signatureVersion [String] the signature version to sign
   *   requests with (overriding the API configuration). Possible values are:
   *   'v2', 'v3', 'v4'.
   * @option options signatureCache [Boolean] whether the signature to sign
   *   requests with (overriding the API configuration) is cached. Only applies
   *   to the signature version 'v4'. Defaults to `true`.
   * @option options dynamoDbCrc32 [Boolean] whether to validate the CRC32
   *   checksum of HTTP response bodies returned by DynamoDB. Default: `true`.
   * @option options useAccelerateEndpoint [Boolean] Whether to use the
   *   S3 Transfer Acceleration endpoint with the S3 service. Default: `false`.
   * @option options clientSideMonitoring [Boolean] whether to collect and
   *   publish this client's performance metrics of all its API requests.
   * @option options endpointDiscoveryEnabled [Boolean|undefined] whether to
   *   call operations with endpoints given by service dynamically. Setting this
   * config to `true` will enable endpoint discovery for all applicable operations.
   *   Setting it to `false` will explicitly disable endpoint discovery even though
   *   operations that require endpoint discovery will presumably fail. Leaving it
   *   to `undefined` means SDK will only do endpoint discovery when it's required.
   *   Defaults to `undefined`
   * @option options endpointCacheSize [Number] the size of the global cache storing
   *   endpoints from endpoint discovery operations. Once endpoint cache is created,
   *   updating this setting cannot change existing cache size.
   *   Defaults to 1000
   * @option options hostPrefixEnabled [Boolean] whether to marshal request
   *   parameters to the prefix of hostname.
   *   Defaults to `true`.
   * @option options stsRegionalEndpoints ['legacy'|'regional'] whether to send sts request
   *   to global endpoints or regional endpoints.
   *   Defaults to 'legacy'.
   * @option options useFipsEndpoint [Boolean] Enables FIPS compatible endpoints.
   *   Defaults to `false`.
   * @option options useDualstackEndpoint [Boolean] Enables IPv6 dualstack endpoint.
   *   Defaults to `false`.
   */ constructor: function Config(options) {
        if (options === undefined) options = {};
        options = this.extractCredentials(options);
        $hIq4q.util.each.call(this, this.keys, function(key, value) {
            this.set(key, options[key], value);
        });
    },
    /**
   * @!group Managing Credentials
   */ /**
   * Loads credentials from the configuration object. This is used internally
   * by the SDK to ensure that refreshable {Credentials} objects are properly
   * refreshed and loaded when sending a request. If you want to ensure that
   * your credentials are loaded prior to a request, you can use this method
   * directly to provide accurate credential data stored in the object.
   *
   * @note If you configure the SDK with static or environment credentials,
   *   the credential data should already be present in {credentials} attribute.
   *   This method is primarily necessary to load credentials from asynchronous
   *   sources, or sources that can refresh credentials periodically.
   * @example Getting your access key
   *   AWS.config.getCredentials(function(err) {
   *     if (err) console.log(err.stack); // credentials not loaded
   *     else console.log("Access Key:", AWS.config.credentials.accessKeyId);
   *   })
   * @callback callback function(err)
   *   Called when the {credentials} have been properly set on the configuration
   *   object.
   *
   *   @param err [Error] if this is set, credentials were not successfully
   *     loaded and this error provides information why.
   * @see credentials
   * @see Credentials
   */ getCredentials: function getCredentials(callback) {
        var self = this;
        function finish(err) {
            callback(err, err ? null : self.credentials);
        }
        function credError(msg, err) {
            return new $hIq4q.util.error(err || new Error(), {
                code: 'CredentialsError',
                message: msg,
                name: 'CredentialsError'
            });
        }
        function getAsyncCredentials() {
            self.credentials.get(function(err) {
                if (err) {
                    var msg = 'Could not load credentials from ' + self.credentials.constructor.name;
                    err = credError(msg, err);
                }
                finish(err);
            });
        }
        function getStaticCredentials() {
            var err = null;
            if (!self.credentials.accessKeyId || !self.credentials.secretAccessKey) err = credError('Missing credentials');
            finish(err);
        }
        if (self.credentials) {
            if (typeof self.credentials.get === 'function') getAsyncCredentials();
            else getStaticCredentials();
        } else if (self.credentialProvider) self.credentialProvider.resolve(function(err, creds) {
            if (err) err = credError('Could not load credentials from any providers', err);
            self.credentials = creds;
            finish(err);
        });
        else finish(credError('No credentials to load'));
    },
    /**
   * Loads token from the configuration object. This is used internally
   * by the SDK to ensure that refreshable {Token} objects are properly
   * refreshed and loaded when sending a request. If you want to ensure that
   * your token is loaded prior to a request, you can use this method
   * directly to provide accurate token data stored in the object.
   *
   * @note If you configure the SDK with static token, the token data should
   *   already be present in {token} attribute. This method is primarily necessary
   *   to load token from asynchronous sources, or sources that can refresh
   *   token periodically.
   * @example Getting your access token
   *   AWS.config.getToken(function(err) {
   *     if (err) console.log(err.stack); // token not loaded
   *     else console.log("Token:", AWS.config.token.token);
   *   })
   * @callback callback function(err)
   *   Called when the {token} have been properly set on the configuration object.
   *
   *   @param err [Error] if this is set, token was not successfully loaded and
   *     this error provides information why.
   * @see token
   */ getToken: function getToken(callback) {
        var self = this;
        function finish(err) {
            callback(err, err ? null : self.token);
        }
        function tokenError(msg, err) {
            return new $hIq4q.util.error(err || new Error(), {
                code: 'TokenError',
                message: msg,
                name: 'TokenError'
            });
        }
        function getAsyncToken() {
            self.token.get(function(err) {
                if (err) {
                    var msg = 'Could not load token from ' + self.token.constructor.name;
                    err = tokenError(msg, err);
                }
                finish(err);
            });
        }
        function getStaticToken() {
            var err = null;
            if (!self.token.token) err = tokenError('Missing token');
            finish(err);
        }
        if (self.token) {
            if (typeof self.token.get === 'function') getAsyncToken();
            else getStaticToken();
        } else if (self.tokenProvider) self.tokenProvider.resolve(function(err, token) {
            if (err) err = tokenError('Could not load token from any providers', err);
            self.token = token;
            finish(err);
        });
        else finish(tokenError('No token to load'));
    },
    /**
   * @!group Loading and Setting Configuration Options
   */ /**
   * @overload update(options, allowUnknownKeys = false)
   *   Updates the current configuration object with new options.
   *
   *   @example Update maxRetries property of a configuration object
   *     config.update({maxRetries: 10});
   *   @param [Object] options a map of option keys and values.
   *   @param [Boolean] allowUnknownKeys whether unknown keys can be set on
   *     the configuration object. Defaults to `false`.
   *   @see constructor
   */ update: function update(options, allowUnknownKeys) {
        allowUnknownKeys = allowUnknownKeys || false;
        options = this.extractCredentials(options);
        $hIq4q.util.each.call(this, options, function(key, value) {
            if (allowUnknownKeys || Object.prototype.hasOwnProperty.call(this.keys, key) || $hIq4q.Service.hasService(key)) this.set(key, value);
        });
    },
    /**
   * Loads configuration data from a JSON file into this config object.
   * @note Loading configuration will reset all existing configuration
   *   on the object.
   * @!macro nobrowser
   * @param path [String] the path relative to your process's current
   *    working directory to load configuration from.
   * @return [AWS.Config] the same configuration object
   */ loadFromPath: function loadFromPath(path) {
        this.clear();
        var options = JSON.parse($hIq4q.util.readFileSync(path));
        var fileSystemCreds = new $hIq4q.FileSystemCredentials(path);
        var chain = new $hIq4q.CredentialProviderChain();
        chain.providers.unshift(fileSystemCreds);
        chain.resolve(function(err, creds) {
            if (err) throw err;
            else options.credentials = creds;
        });
        this.constructor(options);
        return this;
    },
    /**
   * Clears configuration data on this object
   *
   * @api private
   */ clear: function clear() {
        /*jshint forin:false */ $hIq4q.util.each.call(this, this.keys, function(key) {
            delete this[key];
        });
        // reset credential provider
        this.set('credentials', undefined);
        this.set('credentialProvider', undefined);
    },
    /**
   * Sets a property on the configuration object, allowing for a
   * default value
   * @api private
   */ set: function set(property, value, defaultValue) {
        if (value === undefined) {
            if (defaultValue === undefined) defaultValue = this.keys[property];
            if (typeof defaultValue === 'function') this[property] = defaultValue.call(this);
            else this[property] = defaultValue;
        } else if (property === 'httpOptions' && this[property]) // deep merge httpOptions
        this[property] = $hIq4q.util.merge(this[property], value);
        else this[property] = value;
    },
    /**
   * All of the keys with their default values.
   *
   * @constant
   * @api private
   */ keys: {
        credentials: null,
        credentialProvider: null,
        region: null,
        logger: null,
        apiVersions: {},
        apiVersion: null,
        endpoint: undefined,
        httpOptions: {
            timeout: 120000
        },
        maxRetries: undefined,
        maxRedirects: 10,
        paramValidation: true,
        sslEnabled: true,
        s3ForcePathStyle: false,
        s3BucketEndpoint: false,
        s3DisableBodySigning: true,
        s3UsEast1RegionalEndpoint: 'legacy',
        s3UseArnRegion: undefined,
        computeChecksums: true,
        convertResponseTypes: true,
        correctClockSkew: false,
        customUserAgent: null,
        dynamoDbCrc32: true,
        systemClockOffset: 0,
        signatureVersion: null,
        signatureCache: true,
        retryDelayOptions: {},
        useAccelerateEndpoint: false,
        clientSideMonitoring: false,
        endpointDiscoveryEnabled: undefined,
        endpointCacheSize: 1000,
        hostPrefixEnabled: true,
        stsRegionalEndpoints: 'legacy',
        useFipsEndpoint: false,
        useDualstackEndpoint: false,
        token: null
    },
    /**
   * Extracts accessKeyId, secretAccessKey and sessionToken
   * from a configuration hash.
   *
   * @api private
   */ extractCredentials: function extractCredentials(options) {
        if (options.accessKeyId && options.secretAccessKey) {
            options = $hIq4q.util.copy(options);
            options.credentials = new $hIq4q.Credentials(options);
        }
        return options;
    },
    /**
   * Sets the promise dependency the SDK will use wherever Promises are returned.
   * Passing `null` will force the SDK to use native Promises if they are available.
   * If native Promises are not available, passing `null` will have no effect.
   * @param [Constructor] dep A reference to a Promise constructor
   */ setPromisesDependency: function setPromisesDependency(dep) {
        $e84b2b6bb405e513$var$PromisesDependency = dep;
        // if null was passed in, we should try to use native promises
        if (dep === null && typeof Promise === 'function') $e84b2b6bb405e513$var$PromisesDependency = Promise;
        var constructors = [
            $hIq4q.Request,
            $hIq4q.Credentials,
            $hIq4q.CredentialProviderChain
        ];
        if ($hIq4q.S3) {
            constructors.push($hIq4q.S3);
            if ($hIq4q.S3.ManagedUpload) constructors.push($hIq4q.S3.ManagedUpload);
        }
        $hIq4q.util.addPromises(constructors, $e84b2b6bb405e513$var$PromisesDependency);
    },
    /**
   * Gets the promise dependency set by `AWS.config.setPromisesDependency`.
   */ getPromisesDependency: function getPromisesDependency() {
        return $e84b2b6bb405e513$var$PromisesDependency;
    }
});
/**
 * @return [AWS.Config] The global configuration object singleton instance
 * @readonly
 * @see AWS.Config
 */ $hIq4q.config = new $hIq4q.Config();

});
parcelRegister("f9Kfu", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
/**
 * Represents your AWS security credentials, specifically the
 * {accessKeyId}, {secretAccessKey}, and optional {sessionToken}.
 * Creating a `Credentials` object allows you to pass around your
 * security information to configuration and service objects.
 *
 * Note that this class typically does not need to be constructed manually,
 * as the {AWS.Config} and {AWS.Service} classes both accept simple
 * options hashes with the three keys. These structures will be converted
 * into Credentials objects automatically.
 *
 * ## Expiring and Refreshing Credentials
 *
 * Occasionally credentials can expire in the middle of a long-running
 * application. In this case, the SDK will automatically attempt to
 * refresh the credentials from the storage location if the Credentials
 * class implements the {refresh} method.
 *
 * If you are implementing a credential storage location, you
 * will want to create a subclass of the `Credentials` class and
 * override the {refresh} method. This method allows credentials to be
 * retrieved from the backing store, be it a file system, database, or
 * some network storage. The method should reset the credential attributes
 * on the object.
 *
 * @!attribute expired
 *   @return [Boolean] whether the credentials have been expired and
 *     require a refresh. Used in conjunction with {expireTime}.
 * @!attribute expireTime
 *   @return [Date] a time when credentials should be considered expired. Used
 *     in conjunction with {expired}.
 * @!attribute accessKeyId
 *   @return [String] the AWS access key ID
 * @!attribute secretAccessKey
 *   @return [String] the AWS secret access key
 * @!attribute sessionToken
 *   @return [String] an optional AWS session token
 */ $hIq4q.Credentials = $hIq4q.util.inherit({
    /**
   * A credentials object can be created using positional arguments or an options
   * hash.
   *
   * @overload AWS.Credentials(accessKeyId, secretAccessKey, sessionToken=null)
   *   Creates a Credentials object with a given set of credential information
   *   as positional arguments.
   *   @param accessKeyId [String] the AWS access key ID
   *   @param secretAccessKey [String] the AWS secret access key
   *   @param sessionToken [String] the optional AWS session token
   *   @example Create a credentials object with AWS credentials
   *     var creds = new AWS.Credentials('akid', 'secret', 'session');
   * @overload AWS.Credentials(options)
   *   Creates a Credentials object with a given set of credential information
   *   as an options hash.
   *   @option options accessKeyId [String] the AWS access key ID
   *   @option options secretAccessKey [String] the AWS secret access key
   *   @option options sessionToken [String] the optional AWS session token
   *   @example Create a credentials object with AWS credentials
   *     var creds = new AWS.Credentials({
   *       accessKeyId: 'akid', secretAccessKey: 'secret', sessionToken: 'session'
   *     });
   */ constructor: function Credentials() {
        // hide secretAccessKey from being displayed with util.inspect
        $hIq4q.util.hideProperties(this, [
            'secretAccessKey'
        ]);
        this.expired = false;
        this.expireTime = null;
        this.refreshCallbacks = [];
        if (arguments.length === 1 && typeof arguments[0] === 'object') {
            var creds = arguments[0].credentials || arguments[0];
            this.accessKeyId = creds.accessKeyId;
            this.secretAccessKey = creds.secretAccessKey;
            this.sessionToken = creds.sessionToken;
        } else {
            this.accessKeyId = arguments[0];
            this.secretAccessKey = arguments[1];
            this.sessionToken = arguments[2];
        }
    },
    /**
   * @return [Integer] the number of seconds before {expireTime} during which
   *   the credentials will be considered expired.
   */ expiryWindow: 15,
    /**
   * @return [Boolean] whether the credentials object should call {refresh}
   * @note Subclasses should override this method to provide custom refresh
   *   logic.
   */ needsRefresh: function needsRefresh() {
        var currentTime = $hIq4q.util.date.getDate().getTime();
        var adjustedTime = new Date(currentTime + this.expiryWindow * 1000);
        if (this.expireTime && adjustedTime > this.expireTime) return true;
        else return this.expired || !this.accessKeyId || !this.secretAccessKey;
    },
    /**
   * Gets the existing credentials, refreshing them if they are not yet loaded
   * or have expired. Users should call this method before using {refresh},
   * as this will not attempt to reload credentials when they are already
   * loaded into the object.
   *
   * @callback callback function(err)
   *   When this callback is called with no error, it means either credentials
   *   do not need to be refreshed or refreshed credentials information has
   *   been loaded into the object (as the `accessKeyId`, `secretAccessKey`,
   *   and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   */ get: function get(callback) {
        var self = this;
        if (this.needsRefresh()) this.refresh(function(err) {
            if (!err) self.expired = false; // reset expired flag
            if (callback) callback(err);
        });
        else if (callback) callback();
    },
    /**
   * @!method  getPromise()
   *   Returns a 'thenable' promise.
   *   Gets the existing credentials, refreshing them if they are not yet loaded
   *   or have expired. Users should call this method before using {refresh},
   *   as this will not attempt to reload credentials when they are already
   *   loaded into the object.
   *
   *   Two callbacks can be provided to the `then` method on the returned promise.
   *   The first callback will be called if the promise is fulfilled, and the second
   *   callback will be called if the promise is rejected.
   *   @callback fulfilledCallback function()
   *     Called if the promise is fulfilled. When this callback is called, it
   *     means either credentials do not need to be refreshed or refreshed
   *     credentials information has been loaded into the object (as the
   *     `accessKeyId`, `secretAccessKey`, and `sessionToken` properties).
   *   @callback rejectedCallback function(err)
   *     Called if the promise is rejected.
   *     @param err [Error] if an error occurred, this value will be filled
   *   @return [Promise] A promise that represents the state of the `get` call.
   *   @example Calling the `getPromise` method.
   *     var promise = credProvider.getPromise();
   *     promise.then(function() { ... }, function(err) { ... });
   */ /**
   * @!method  refreshPromise()
   *   Returns a 'thenable' promise.
   *   Refreshes the credentials. Users should call {get} before attempting
   *   to forcibly refresh credentials.
   *
   *   Two callbacks can be provided to the `then` method on the returned promise.
   *   The first callback will be called if the promise is fulfilled, and the second
   *   callback will be called if the promise is rejected.
   *   @callback fulfilledCallback function()
   *     Called if the promise is fulfilled. When this callback is called, it
   *     means refreshed credentials information has been loaded into the object
   *     (as the `accessKeyId`, `secretAccessKey`, and `sessionToken` properties).
   *   @callback rejectedCallback function(err)
   *     Called if the promise is rejected.
   *     @param err [Error] if an error occurred, this value will be filled
   *   @return [Promise] A promise that represents the state of the `refresh` call.
   *   @example Calling the `refreshPromise` method.
   *     var promise = credProvider.refreshPromise();
   *     promise.then(function() { ... }, function(err) { ... });
   */ /**
   * Refreshes the credentials. Users should call {get} before attempting
   * to forcibly refresh credentials.
   *
   * @callback callback function(err)
   *   When this callback is called with no error, it means refreshed
   *   credentials information has been loaded into the object (as the
   *   `accessKeyId`, `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @note Subclasses should override this class to reset the
   *   {accessKeyId}, {secretAccessKey} and optional {sessionToken}
   *   on the credentials object and then call the callback with
   *   any error information.
   * @see get
   */ refresh: function refresh(callback) {
        this.expired = false;
        callback();
    },
    /**
   * @api private
   * @param callback
   */ coalesceRefresh: function coalesceRefresh(callback, sync) {
        var self = this;
        if (self.refreshCallbacks.push(callback) === 1) self.load(function onLoad(err) {
            $hIq4q.util.arrayEach(self.refreshCallbacks, function(callback) {
                if (sync) callback(err);
                else // callback could throw, so defer to ensure all callbacks are notified
                $hIq4q.util.defer(function() {
                    callback(err);
                });
            });
            self.refreshCallbacks.length = 0;
        });
    },
    /**
   * @api private
   * @param callback
   */ load: function load(callback) {
        callback();
    }
});
/**
 * @api private
 */ $hIq4q.Credentials.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
    this.prototype.getPromise = $hIq4q.util.promisifyMethod('get', PromiseDependency);
    this.prototype.refreshPromise = $hIq4q.util.promisifyMethod('refresh', PromiseDependency);
};
/**
 * @api private
 */ $hIq4q.Credentials.deletePromisesFromClass = function deletePromisesFromClass() {
    delete this.prototype.getPromise;
    delete this.prototype.refreshPromise;
};
$hIq4q.util.addPromises($hIq4q.Credentials);

});

parcelRegister("f4h1X", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
/**
 * Creates a credential provider chain that searches for AWS credentials
 * in a list of credential providers specified by the {providers} property.
 *
 * By default, the chain will use the {defaultProviders} to resolve credentials.
 * These providers will look in the environment using the
 * {AWS.EnvironmentCredentials} class with the 'AWS' and 'AMAZON' prefixes.
 *
 * ## Setting Providers
 *
 * Each provider in the {providers} list should be a function that returns
 * a {AWS.Credentials} object, or a hardcoded credentials object. The function
 * form allows for delayed execution of the credential construction.
 *
 * ## Resolving Credentials from a Chain
 *
 * Call {resolve} to return the first valid credential object that can be
 * loaded by the provider chain.
 *
 * For example, to resolve a chain with a custom provider that checks a file
 * on disk after the set of {defaultProviders}:
 *
 * ```javascript
 * var diskProvider = new AWS.FileSystemCredentials('./creds.json');
 * var chain = new AWS.CredentialProviderChain();
 * chain.providers.push(diskProvider);
 * chain.resolve();
 * ```
 *
 * The above code will return the `diskProvider` object if the
 * file contains credentials and the `defaultProviders` do not contain
 * any credential settings.
 *
 * @!attribute providers
 *   @return [Array<AWS.Credentials, Function>]
 *     a list of credentials objects or functions that return credentials
 *     objects. If the provider is a function, the function will be
 *     executed lazily when the provider needs to be checked for valid
 *     credentials. By default, this object will be set to the
 *     {defaultProviders}.
 *   @see defaultProviders
 */ $hIq4q.CredentialProviderChain = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new CredentialProviderChain with a default set of providers
   * specified by {defaultProviders}.
   */ constructor: function CredentialProviderChain(providers) {
        if (providers) this.providers = providers;
        else this.providers = $hIq4q.CredentialProviderChain.defaultProviders.slice(0);
        this.resolveCallbacks = [];
    },
    /**
   * @!method  resolvePromise()
   *   Returns a 'thenable' promise.
   *   Resolves the provider chain by searching for the first set of
   *   credentials in {providers}.
   *
   *   Two callbacks can be provided to the `then` method on the returned promise.
   *   The first callback will be called if the promise is fulfilled, and the second
   *   callback will be called if the promise is rejected.
   *   @callback fulfilledCallback function(credentials)
   *     Called if the promise is fulfilled and the provider resolves the chain
   *     to a credentials object
   *     @param credentials [AWS.Credentials] the credentials object resolved
   *       by the provider chain.
   *   @callback rejectedCallback function(error)
   *     Called if the promise is rejected.
   *     @param err [Error] the error object returned if no credentials are found.
   *   @return [Promise] A promise that represents the state of the `resolve` method call.
   *   @example Calling the `resolvePromise` method.
   *     var promise = chain.resolvePromise();
   *     promise.then(function(credentials) { ... }, function(err) { ... });
   */ /**
   * Resolves the provider chain by searching for the first set of
   * credentials in {providers}.
   *
   * @callback callback function(err, credentials)
   *   Called when the provider resolves the chain to a credentials object
   *   or null if no credentials can be found.
   *
   *   @param err [Error] the error object returned if no credentials are
   *     found.
   *   @param credentials [AWS.Credentials] the credentials object resolved
   *     by the provider chain.
   * @return [AWS.CredentialProviderChain] the provider, for chaining.
   */ resolve: function resolve(callback) {
        var self = this;
        if (self.providers.length === 0) {
            callback(new Error('No providers'));
            return self;
        }
        if (self.resolveCallbacks.push(callback) === 1) {
            var index = 0;
            var providers = self.providers.slice(0);
            function resolveNext(err, creds) {
                if (!err && creds || index === providers.length) {
                    $hIq4q.util.arrayEach(self.resolveCallbacks, function(callback) {
                        callback(err, creds);
                    });
                    self.resolveCallbacks.length = 0;
                    return;
                }
                var provider = providers[index++];
                if (typeof provider === 'function') creds = provider.call();
                else creds = provider;
                if (creds.get) creds.get(function(getErr) {
                    resolveNext(getErr, getErr ? null : creds);
                });
                else resolveNext(null, creds);
            }
            resolveNext();
        }
        return self;
    }
});
/**
 * The default set of providers used by a vanilla CredentialProviderChain.
 *
 * In the browser:
 *
 * ```javascript
 * AWS.CredentialProviderChain.defaultProviders = []
 * ```
 *
 * In Node.js:
 *
 * ```javascript
 * AWS.CredentialProviderChain.defaultProviders = [
 *   function () { return new AWS.EnvironmentCredentials('AWS'); },
 *   function () { return new AWS.EnvironmentCredentials('AMAZON'); },
 *   function () { return new AWS.SsoCredentials(); },
 *   function () { return new AWS.SharedIniFileCredentials(); },
 *   function () { return new AWS.ECSCredentials(); },
 *   function () { return new AWS.ProcessCredentials(); },
 *   function () { return new AWS.TokenFileWebIdentityCredentials(); },
 *   function () { return new AWS.EC2MetadataCredentials() }
 * ]
 * ```
 */ $hIq4q.CredentialProviderChain.defaultProviders = [];
/**
 * @api private
 */ $hIq4q.CredentialProviderChain.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
    this.prototype.resolvePromise = $hIq4q.util.promisifyMethod('resolve', PromiseDependency);
};
/**
 * @api private
 */ $hIq4q.CredentialProviderChain.deletePromisesFromClass = function deletePromisesFromClass() {
    delete this.prototype.resolvePromise;
};
$hIq4q.util.addPromises($hIq4q.CredentialProviderChain);

});


parcelRegister("jI9el", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $e599495488260a8c$var$inherit = $hIq4q.util.inherit;
/**
 * The endpoint that a service will talk to, for example,
 * `'https://ec2.ap-southeast-1.amazonaws.com'`. If
 * you need to override an endpoint for a service, you can
 * set the endpoint on a service by passing the endpoint
 * object with the `endpoint` option key:
 *
 * ```javascript
 * var ep = new AWS.Endpoint('awsproxy.example.com');
 * var s3 = new AWS.S3({endpoint: ep});
 * s3.service.endpoint.hostname == 'awsproxy.example.com'
 * ```
 *
 * Note that if you do not specify a protocol, the protocol will
 * be selected based on your current {AWS.config} configuration.
 *
 * @!attribute protocol
 *   @return [String] the protocol (http or https) of the endpoint
 *     URL
 * @!attribute hostname
 *   @return [String] the host portion of the endpoint, e.g.,
 *     example.com
 * @!attribute host
 *   @return [String] the host portion of the endpoint including
 *     the port, e.g., example.com:80
 * @!attribute port
 *   @return [Integer] the port of the endpoint
 * @!attribute href
 *   @return [String] the full URL of the endpoint
 */ $hIq4q.Endpoint = $e599495488260a8c$var$inherit({
    /**
   * @overload Endpoint(endpoint)
   *   Constructs a new endpoint given an endpoint URL. If the
   *   URL omits a protocol (http or https), the default protocol
   *   set in the global {AWS.config} will be used.
   *   @param endpoint [String] the URL to construct an endpoint from
   */ constructor: function Endpoint(endpoint, config) {
        $hIq4q.util.hideProperties(this, [
            'slashes',
            'auth',
            'hash',
            'search',
            'query'
        ]);
        if (typeof endpoint === 'undefined' || endpoint === null) throw new Error('Invalid endpoint: ' + endpoint);
        else if (typeof endpoint !== 'string') return $hIq4q.util.copy(endpoint);
        if (!endpoint.match(/^http/)) {
            var useSSL = config && config.sslEnabled !== undefined ? config.sslEnabled : $hIq4q.config.sslEnabled;
            endpoint = (useSSL ? 'https' : 'http') + '://' + endpoint;
        }
        $hIq4q.util.update(this, $hIq4q.util.urlParse(endpoint));
        // Ensure the port property is set as an integer
        if (this.port) this.port = parseInt(this.port, 10);
        else this.port = this.protocol === 'https:' ? 443 : 80;
    }
});
/**
 * The low level HTTP request object, encapsulating all HTTP header
 * and body data sent by a service request.
 *
 * @!attribute method
 *   @return [String] the HTTP method of the request
 * @!attribute path
 *   @return [String] the path portion of the URI, e.g.,
 *     "/list/?start=5&num=10"
 * @!attribute headers
 *   @return [map<String,String>]
 *     a map of header keys and their respective values
 * @!attribute body
 *   @return [String] the request body payload
 * @!attribute endpoint
 *   @return [AWS.Endpoint] the endpoint for the request
 * @!attribute region
 *   @api private
 *   @return [String] the region, for signing purposes only.
 */ $hIq4q.HttpRequest = $e599495488260a8c$var$inherit({
    /**
   * @api private
   */ constructor: function HttpRequest(endpoint, region) {
        endpoint = new $hIq4q.Endpoint(endpoint);
        this.method = 'POST';
        this.path = endpoint.path || '/';
        this.headers = {};
        this.body = '';
        this.endpoint = endpoint;
        this.region = region;
        this._userAgent = '';
        this.setUserAgent();
    },
    /**
   * @api private
   */ setUserAgent: function setUserAgent() {
        this._userAgent = this.headers[this.getUserAgentHeaderName()] = $hIq4q.util.userAgent();
    },
    getUserAgentHeaderName: function getUserAgentHeaderName() {
        var prefix = $hIq4q.util.isBrowser() ? 'X-Amz-' : '';
        return prefix + 'User-Agent';
    },
    /**
   * @api private
   */ appendToUserAgent: function appendToUserAgent(agentPartial) {
        if (typeof agentPartial === 'string' && agentPartial) this._userAgent += ' ' + agentPartial;
        this.headers[this.getUserAgentHeaderName()] = this._userAgent;
    },
    /**
   * @api private
   */ getUserAgent: function getUserAgent() {
        return this._userAgent;
    },
    /**
   * @return [String] the part of the {path} excluding the
   *   query string
   */ pathname: function pathname() {
        return this.path.split('?', 1)[0];
    },
    /**
   * @return [String] the query string portion of the {path}
   */ search: function search() {
        var query = this.path.split('?', 2)[1];
        if (query) {
            query = $hIq4q.util.queryStringParse(query);
            return $hIq4q.util.queryParamsToString(query);
        }
        return '';
    },
    /**
   * @api private
   * update httpRequest endpoint with endpoint string
   */ updateEndpoint: function updateEndpoint(endpointStr) {
        var newEndpoint = new $hIq4q.Endpoint(endpointStr);
        this.endpoint = newEndpoint;
        this.path = newEndpoint.path || '/';
        if (this.headers['Host']) this.headers['Host'] = newEndpoint.host;
    }
});
/**
 * The low level HTTP response object, encapsulating all HTTP header
 * and body data returned from the request.
 *
 * @!attribute statusCode
 *   @return [Integer] the HTTP status code of the response (e.g., 200, 404)
 * @!attribute headers
 *   @return [map<String,String>]
 *      a map of response header keys and their respective values
 * @!attribute body
 *   @return [String] the response body payload
 * @!attribute [r] streaming
 *   @return [Boolean] whether this response is being streamed at a low-level.
 *     Defaults to `false` (buffered reads). Do not modify this manually, use
 *     {createUnbufferedStream} to convert the stream to unbuffered mode
 *     instead.
 */ $hIq4q.HttpResponse = $e599495488260a8c$var$inherit({
    /**
   * @api private
   */ constructor: function HttpResponse() {
        this.statusCode = undefined;
        this.headers = {};
        this.body = undefined;
        this.streaming = false;
        this.stream = null;
    },
    /**
   * Disables buffering on the HTTP response and returns the stream for reading.
   * @return [Stream, XMLHttpRequest, null] the underlying stream object.
   *   Use this object to directly read data off of the stream.
   * @note This object is only available after the {AWS.Request~httpHeaders}
   *   event has fired. This method must be called prior to
   *   {AWS.Request~httpData}.
   * @example Taking control of a stream
   *   request.on('httpHeaders', function(statusCode, headers) {
   *     if (statusCode < 300) {
   *       if (headers.etag === 'xyz') {
   *         // pipe the stream, disabling buffering
   *         var stream = this.response.httpResponse.createUnbufferedStream();
   *         stream.pipe(process.stdout);
   *       } else { // abort this request and set a better error message
   *         this.abort();
   *         this.response.error = new Error('Invalid ETag');
   *       }
   *     }
   *   }).send(console.log);
   */ createUnbufferedStream: function createUnbufferedStream() {
        this.streaming = true;
        return this.stream;
    }
});
$hIq4q.HttpClient = $e599495488260a8c$var$inherit({});
/**
 * @api private
 */ $hIq4q.HttpClient.getInstance = function getInstance() {
    if (this.singleton === undefined) this.singleton = new this();
    return this.singleton;
};

});

parcelRegister("4NP9G", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");

var $cLHKj = parcelRequire("cLHKj");

var $84mkI = parcelRequire("84mkI");
var $37f36b67f18bbc23$require$DISCOVER_ENDPOINT = $84mkI.discoverEndpoint;
/**
 * The namespace used to register global event listeners for request building
 * and sending.
 */ $hIq4q.EventListeners = {
    /**
   * @!attribute VALIDATE_CREDENTIALS
   *   A request listener that validates whether the request is being
   *   sent with credentials.
   *   Handles the {AWS.Request~validate 'validate' Request event}
   *   @example Sending a request without validating credentials
   *     var listener = AWS.EventListeners.Core.VALIDATE_CREDENTIALS;
   *     request.removeListener('validate', listener);
   *   @readonly
   *   @return [Function]
   * @!attribute VALIDATE_REGION
   *   A request listener that validates whether the region is set
   *   for a request.
   *   Handles the {AWS.Request~validate 'validate' Request event}
   *   @example Sending a request without validating region configuration
   *     var listener = AWS.EventListeners.Core.VALIDATE_REGION;
   *     request.removeListener('validate', listener);
   *   @readonly
   *   @return [Function]
   * @!attribute VALIDATE_PARAMETERS
   *   A request listener that validates input parameters in a request.
   *   Handles the {AWS.Request~validate 'validate' Request event}
   *   @example Sending a request without validating parameters
   *     var listener = AWS.EventListeners.Core.VALIDATE_PARAMETERS;
   *     request.removeListener('validate', listener);
   *   @example Disable parameter validation globally
   *     AWS.EventListeners.Core.removeListener('validate',
   *       AWS.EventListeners.Core.VALIDATE_REGION);
   *   @readonly
   *   @return [Function]
   * @!attribute SEND
   *   A request listener that initiates the HTTP connection for a
   *   request being sent. Handles the {AWS.Request~send 'send' Request event}
   *   @example Replacing the HTTP handler
   *     var listener = AWS.EventListeners.Core.SEND;
   *     request.removeListener('send', listener);
   *     request.on('send', function(response) {
   *       customHandler.send(response);
   *     });
   *   @return [Function]
   *   @readonly
   * @!attribute HTTP_DATA
   *   A request listener that reads data from the HTTP connection in order
   *   to build the response data.
   *   Handles the {AWS.Request~httpData 'httpData' Request event}.
   *   Remove this handler if you are overriding the 'httpData' event and
   *   do not want extra data processing and buffering overhead.
   *   @example Disabling default data processing
   *     var listener = AWS.EventListeners.Core.HTTP_DATA;
   *     request.removeListener('httpData', listener);
   *   @return [Function]
   *   @readonly
   */ Core: {} /* doc hack */ 
};
/**
 * @api private
 */ function $37f36b67f18bbc23$var$getOperationAuthtype(req) {
    if (!req.service.api.operations) return '';
    var operation = req.service.api.operations[req.operation];
    return operation ? operation.authtype : '';
}
/**
 * @api private
 */ function $37f36b67f18bbc23$var$getIdentityType(req) {
    var service = req.service;
    if (service.config.signatureVersion) return service.config.signatureVersion;
    if (service.api.signatureVersion) return service.api.signatureVersion;
    return $37f36b67f18bbc23$var$getOperationAuthtype(req);
}






$hIq4q.EventListeners = {
    Core: new $cLHKj().addNamedListeners(function(add, addAsync) {
        addAsync('VALIDATE_CREDENTIALS', 'validate', function VALIDATE_CREDENTIALS(req, done) {
            if (!req.service.api.signatureVersion && !req.service.config.signatureVersion) return done(); // none
            var identityType = $37f36b67f18bbc23$var$getIdentityType(req);
            if (identityType === 'bearer') {
                req.service.config.getToken(function(err) {
                    if (err) req.response.error = $hIq4q.util.error(err, {
                        code: 'TokenError'
                    });
                    done();
                });
                return;
            }
            req.service.config.getCredentials(function(err) {
                if (err) req.response.error = $hIq4q.util.error(err, {
                    code: 'CredentialsError',
                    message: 'Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1'
                });
                done();
            });
        });
        add('VALIDATE_REGION', 'validate', function VALIDATE_REGION(req) {
            if (!req.service.isGlobalEndpoint) {
                var dnsHostRegex = new RegExp(/^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])$/);
                if (!req.service.config.region) req.response.error = $hIq4q.util.error(new Error(), {
                    code: 'ConfigError',
                    message: 'Missing region in config'
                });
                else if (!dnsHostRegex.test(req.service.config.region)) req.response.error = $hIq4q.util.error(new Error(), {
                    code: 'ConfigError',
                    message: 'Invalid region in config'
                });
            }
        });
        add('BUILD_IDEMPOTENCY_TOKENS', 'validate', function BUILD_IDEMPOTENCY_TOKENS(req) {
            if (!req.service.api.operations) return;
            var operation = req.service.api.operations[req.operation];
            if (!operation) return;
            var idempotentMembers = operation.idempotentMembers;
            if (!idempotentMembers.length) return;
            // creates a copy of params so user's param object isn't mutated
            var params = $hIq4q.util.copy(req.params);
            for(var i = 0, iLen = idempotentMembers.length; i < iLen; i++)if (!params[idempotentMembers[i]]) // add the member
            params[idempotentMembers[i]] = $hIq4q.util.uuid.v4();
            req.params = params;
        });
        add('VALIDATE_PARAMETERS', 'validate', function VALIDATE_PARAMETERS(req) {
            if (!req.service.api.operations) return;
            var rules = req.service.api.operations[req.operation].input;
            var validation = req.service.config.paramValidation;
            new $hIq4q.ParamValidator(validation).validate(rules, req.params);
        });
        add('COMPUTE_CHECKSUM', 'afterBuild', function COMPUTE_CHECKSUM(req) {
            if (!req.service.api.operations) return;
            var operation = req.service.api.operations[req.operation];
            if (!operation) return;
            var body = req.httpRequest.body;
            var isNonStreamingPayload = body && ($hIq4q.util.Buffer.isBuffer(body) || typeof body === 'string');
            var headers = req.httpRequest.headers;
            if (operation.httpChecksumRequired && req.service.config.computeChecksums && isNonStreamingPayload && !headers['Content-MD5']) {
                var md5 = $hIq4q.util.crypto.md5(body, 'base64');
                headers['Content-MD5'] = md5;
            }
        });
        addAsync('COMPUTE_SHA256', 'afterBuild', function COMPUTE_SHA256(req, done) {
            req.haltHandlersOnError();
            if (!req.service.api.operations) return;
            var operation = req.service.api.operations[req.operation];
            var authtype = operation ? operation.authtype : '';
            if (!req.service.api.signatureVersion && !authtype && !req.service.config.signatureVersion) return done(); // none
            if (req.service.getSignerClass(req) === $hIq4q.Signers.V4) {
                var body = req.httpRequest.body || '';
                if (authtype.indexOf('unsigned-body') >= 0) {
                    req.httpRequest.headers['X-Amz-Content-Sha256'] = 'UNSIGNED-PAYLOAD';
                    return done();
                }
                $hIq4q.util.computeSha256(body, function(err, sha) {
                    if (err) done(err);
                    else {
                        req.httpRequest.headers['X-Amz-Content-Sha256'] = sha;
                        done();
                    }
                });
            } else done();
        });
        add('SET_CONTENT_LENGTH', 'afterBuild', function SET_CONTENT_LENGTH(req) {
            var authtype = $37f36b67f18bbc23$var$getOperationAuthtype(req);
            var payloadMember = $hIq4q.util.getRequestPayloadShape(req);
            if (req.httpRequest.headers['Content-Length'] === undefined) try {
                var length = $hIq4q.util.string.byteLength(req.httpRequest.body);
                req.httpRequest.headers['Content-Length'] = length;
            } catch (err) {
                if (payloadMember && payloadMember.isStreaming) {
                    if (payloadMember.requiresLength) //streaming payload requires length(s3, glacier)
                    throw err;
                    else if (authtype.indexOf('unsigned-body') >= 0) {
                        //unbounded streaming payload(lex, mediastore)
                        req.httpRequest.headers['Transfer-Encoding'] = 'chunked';
                        return;
                    } else throw err;
                }
                throw err;
            }
        });
        add('SET_HTTP_HOST', 'afterBuild', function SET_HTTP_HOST(req) {
            req.httpRequest.headers['Host'] = req.httpRequest.endpoint.host;
        });
        add('SET_TRACE_ID', 'afterBuild', function SET_TRACE_ID(req) {
            var traceIdHeaderName = 'X-Amzn-Trace-Id';
            if ($hIq4q.util.isNode() && !Object.hasOwnProperty.call(req.httpRequest.headers, traceIdHeaderName)) {
                var ENV_LAMBDA_FUNCTION_NAME = 'AWS_LAMBDA_FUNCTION_NAME';
                var ENV_TRACE_ID = '_X_AMZN_TRACE_ID';
                var functionName = process.env[ENV_LAMBDA_FUNCTION_NAME];
                var traceId = process.env[ENV_TRACE_ID];
                if (typeof functionName === 'string' && functionName.length > 0 && typeof traceId === 'string' && traceId.length > 0) req.httpRequest.headers[traceIdHeaderName] = traceId;
            }
        });
        add('RESTART', 'restart', function RESTART() {
            var err = this.response.error;
            if (!err || !err.retryable) return;
            this.httpRequest = new $hIq4q.HttpRequest(this.service.endpoint, this.service.region);
            if (this.response.retryCount < this.service.config.maxRetries) this.response.retryCount++;
            else this.response.error = null;
        });
        var addToHead = true;
        addAsync('DISCOVER_ENDPOINT', 'sign', $37f36b67f18bbc23$require$DISCOVER_ENDPOINT, addToHead);
        addAsync('SIGN', 'sign', function SIGN(req, done) {
            var service = req.service;
            var identityType = $37f36b67f18bbc23$var$getIdentityType(req);
            if (!identityType || identityType.length === 0) return done(); // none
            if (identityType === 'bearer') service.config.getToken(function(err, token) {
                if (err) {
                    req.response.error = err;
                    return done();
                }
                try {
                    var SignerClass = service.getSignerClass(req);
                    var signer = new SignerClass(req.httpRequest);
                    signer.addAuthorization(token);
                } catch (e) {
                    req.response.error = e;
                }
                done();
            });
            else service.config.getCredentials(function(err, credentials) {
                if (err) {
                    req.response.error = err;
                    return done();
                }
                try {
                    var date = service.getSkewCorrectedDate();
                    var SignerClass = service.getSignerClass(req);
                    var operations = req.service.api.operations || {};
                    var operation = operations[req.operation];
                    var signer = new SignerClass(req.httpRequest, service.getSigningName(req), {
                        signatureCache: service.config.signatureCache,
                        operation: operation,
                        signatureVersion: service.api.signatureVersion
                    });
                    signer.setServiceClientId(service._clientId);
                    // clear old authorization headers
                    delete req.httpRequest.headers['Authorization'];
                    delete req.httpRequest.headers['Date'];
                    delete req.httpRequest.headers['X-Amz-Date'];
                    // add new authorization
                    signer.addAuthorization(credentials, date);
                    req.signedAt = date;
                } catch (e) {
                    req.response.error = e;
                }
                done();
            });
        });
        add('VALIDATE_RESPONSE', 'validateResponse', function VALIDATE_RESPONSE(resp) {
            if (this.service.successfulResponse(resp, this)) {
                resp.data = {};
                resp.error = null;
            } else {
                resp.data = null;
                resp.error = $hIq4q.util.error(new Error(), {
                    code: 'UnknownError',
                    message: 'An unknown error occurred.'
                });
            }
        });
        add('ERROR', 'error', function ERROR(err, resp) {
            var awsQueryCompatible = resp.request.service.api.awsQueryCompatible;
            if (awsQueryCompatible) {
                var headers = resp.httpResponse.headers;
                var queryErrorCode = headers ? headers['x-amzn-query-error'] : undefined;
                if (queryErrorCode && queryErrorCode.includes(';')) resp.error.code = queryErrorCode.split(';')[0];
            }
        }, true);
        addAsync('SEND', 'send', function SEND(resp, done) {
            resp.httpResponse._abortCallback = done;
            resp.error = null;
            resp.data = null;
            function callback(httpResp) {
                resp.httpResponse.stream = httpResp;
                var stream = resp.request.httpRequest.stream;
                var service = resp.request.service;
                var api = service.api;
                var operationName = resp.request.operation;
                var operation = api.operations[operationName] || {};
                httpResp.on('headers', function onHeaders(statusCode, headers, statusMessage) {
                    resp.request.emit('httpHeaders', [
                        statusCode,
                        headers,
                        resp,
                        statusMessage
                    ]);
                    if (!resp.httpResponse.streaming) {
                        if ($hIq4q.HttpClient.streamsApiVersion === 2) {
                            // if we detect event streams, we're going to have to
                            // return the stream immediately
                            if (operation.hasEventOutput && service.successfulResponse(resp)) {
                                // skip reading the IncomingStream
                                resp.request.emit('httpDone');
                                done();
                                return;
                            }
                            httpResp.on('readable', function onReadable() {
                                var data = httpResp.read();
                                if (data !== null) resp.request.emit('httpData', [
                                    data,
                                    resp
                                ]);
                            });
                        } else httpResp.on('data', function onData(data) {
                            resp.request.emit('httpData', [
                                data,
                                resp
                            ]);
                        });
                    }
                });
                httpResp.on('end', function onEnd() {
                    if (!stream || !stream.didCallback) {
                        if ($hIq4q.HttpClient.streamsApiVersion === 2 && operation.hasEventOutput && service.successfulResponse(resp)) // don't concatenate response chunks when streaming event stream data when response is successful
                        return;
                        resp.request.emit('httpDone');
                        done();
                    }
                });
            }
            function progress(httpResp) {
                httpResp.on('sendProgress', function onSendProgress(value) {
                    resp.request.emit('httpUploadProgress', [
                        value,
                        resp
                    ]);
                });
                httpResp.on('receiveProgress', function onReceiveProgress(value) {
                    resp.request.emit('httpDownloadProgress', [
                        value,
                        resp
                    ]);
                });
            }
            function error(err) {
                if (err.code !== 'RequestAbortedError') {
                    var errCode = err.code === 'TimeoutError' ? err.code : 'NetworkingError';
                    err = $hIq4q.util.error(err, {
                        code: errCode,
                        region: resp.request.httpRequest.region,
                        hostname: resp.request.httpRequest.endpoint.hostname,
                        retryable: true
                    });
                }
                resp.error = err;
                resp.request.emit('httpError', [
                    resp.error,
                    resp
                ], function() {
                    done();
                });
            }
            function executeSend() {
                var http = $hIq4q.HttpClient.getInstance();
                var httpOptions = resp.request.service.config.httpOptions || {};
                try {
                    var stream = http.handleRequest(resp.request.httpRequest, httpOptions, callback, error);
                    progress(stream);
                } catch (err) {
                    error(err);
                }
            }
            var timeDiff = (resp.request.service.getSkewCorrectedDate() - this.signedAt) / 1000;
            if (timeDiff >= 600) this.emit('sign', [
                this
            ], function(err) {
                if (err) done(err);
                else executeSend();
            });
            else executeSend();
        });
        add('HTTP_HEADERS', 'httpHeaders', function HTTP_HEADERS(statusCode, headers, resp, statusMessage) {
            resp.httpResponse.statusCode = statusCode;
            resp.httpResponse.statusMessage = statusMessage;
            resp.httpResponse.headers = headers;
            resp.httpResponse.body = $hIq4q.util.buffer.toBuffer('');
            resp.httpResponse.buffers = [];
            resp.httpResponse.numBytes = 0;
            var dateHeader = headers.date || headers.Date;
            var service = resp.request.service;
            if (dateHeader) {
                var serverTime = Date.parse(dateHeader);
                if (service.config.correctClockSkew && service.isClockSkewed(serverTime)) service.applyClockOffset(serverTime);
            }
        });
        add('HTTP_DATA', 'httpData', function HTTP_DATA(chunk, resp) {
            if (chunk) {
                if ($hIq4q.util.isNode()) {
                    resp.httpResponse.numBytes += chunk.length;
                    var total = resp.httpResponse.headers['content-length'];
                    var progress = {
                        loaded: resp.httpResponse.numBytes,
                        total: total
                    };
                    resp.request.emit('httpDownloadProgress', [
                        progress,
                        resp
                    ]);
                }
                resp.httpResponse.buffers.push($hIq4q.util.buffer.toBuffer(chunk));
            }
        });
        add('HTTP_DONE', 'httpDone', function HTTP_DONE(resp) {
            // convert buffers array into single buffer
            if (resp.httpResponse.buffers && resp.httpResponse.buffers.length > 0) {
                var body = $hIq4q.util.buffer.concat(resp.httpResponse.buffers);
                resp.httpResponse.body = body;
            }
            delete resp.httpResponse.numBytes;
            delete resp.httpResponse.buffers;
        });
        add('FINALIZE_ERROR', 'retry', function FINALIZE_ERROR(resp) {
            if (resp.httpResponse.statusCode) {
                resp.error.statusCode = resp.httpResponse.statusCode;
                if (resp.error.retryable === undefined) resp.error.retryable = this.service.retryableError(resp.error, this);
            }
        });
        add('INVALIDATE_CREDENTIALS', 'retry', function INVALIDATE_CREDENTIALS(resp) {
            if (!resp.error) return;
            switch(resp.error.code){
                case 'RequestExpired':
                case 'ExpiredTokenException':
                case 'ExpiredToken':
                    resp.error.retryable = true;
                    resp.request.service.config.credentials.expired = true;
            }
        });
        add('EXPIRED_SIGNATURE', 'retry', function EXPIRED_SIGNATURE(resp) {
            var err = resp.error;
            if (!err) return;
            if (typeof err.code === 'string' && typeof err.message === 'string') {
                if (err.code.match(/Signature/) && err.message.match(/expired/)) resp.error.retryable = true;
            }
        });
        add('CLOCK_SKEWED', 'retry', function CLOCK_SKEWED(resp) {
            if (!resp.error) return;
            if (this.service.clockSkewError(resp.error) && this.service.config.correctClockSkew) resp.error.retryable = true;
        });
        add('REDIRECT', 'retry', function REDIRECT(resp) {
            if (resp.error && resp.error.statusCode >= 300 && resp.error.statusCode < 400 && resp.httpResponse.headers['location']) {
                this.httpRequest.endpoint = new $hIq4q.Endpoint(resp.httpResponse.headers['location']);
                this.httpRequest.headers['Host'] = this.httpRequest.endpoint.host;
                this.httpRequest.path = this.httpRequest.endpoint.path;
                resp.error.redirect = true;
                resp.error.retryable = true;
            }
        });
        add('RETRY_CHECK', 'retry', function RETRY_CHECK(resp) {
            if (resp.error) {
                if (resp.error.redirect && resp.redirectCount < resp.maxRedirects) resp.error.retryDelay = 0;
                else if (resp.retryCount < resp.maxRetries) resp.error.retryDelay = this.service.retryDelays(resp.retryCount, resp.error) || 0;
            }
        });
        addAsync('RESET_RETRY_STATE', 'afterRetry', function RESET_RETRY_STATE(resp, done) {
            var delay, willRetry = false;
            if (resp.error) {
                delay = resp.error.retryDelay || 0;
                if (resp.error.retryable && resp.retryCount < resp.maxRetries) {
                    resp.retryCount++;
                    willRetry = true;
                } else if (resp.error.redirect && resp.redirectCount < resp.maxRedirects) {
                    resp.redirectCount++;
                    willRetry = true;
                }
            }
            // delay < 0 is a signal from customBackoff to skip retries
            if (willRetry && delay >= 0) {
                resp.error = null;
                setTimeout(done, delay);
            } else done();
        });
    }),
    CorePost: new $cLHKj().addNamedListeners(function(add) {
        add('EXTRACT_REQUEST_ID', 'extractData', $hIq4q.util.extractRequestId);
        add('EXTRACT_REQUEST_ID', 'extractError', $hIq4q.util.extractRequestId);
        add('ENOTFOUND_ERROR', 'httpError', function ENOTFOUND_ERROR(err) {
            function isDNSError(err) {
                return err.errno === 'ENOTFOUND' || typeof err.errno === 'number' && typeof $hIq4q.util.getSystemErrorName === 'function' && [
                    'EAI_NONAME',
                    'EAI_NODATA'
                ].indexOf($hIq4q.util.getSystemErrorName(err.errno) >= 0);
            }
            if (err.code === 'NetworkingError' && isDNSError(err)) {
                var message = 'Inaccessible host: `' + err.hostname + '\' at port `' + err.port + '\'. This service may not be available in the `' + err.region + '\' region.';
                this.response.error = $hIq4q.util.error(new Error(message), {
                    code: 'UnknownEndpoint',
                    region: err.region,
                    hostname: err.hostname,
                    retryable: true,
                    originalError: err
                });
            }
        });
    }),
    Logger: new $cLHKj().addNamedListeners(function(add) {
        add('LOG_REQUEST', 'complete', function LOG_REQUEST(resp) {
            var req = resp.request;
            var logger = req.service.config.logger;
            if (!logger) return;
            function filterSensitiveLog(inputShape, shape) {
                if (!shape) return shape;
                if (inputShape.isSensitive) return '***SensitiveInformation***';
                switch(inputShape.type){
                    case 'structure':
                        var struct = {};
                        $hIq4q.util.each(shape, function(subShapeName, subShape) {
                            if (Object.prototype.hasOwnProperty.call(inputShape.members, subShapeName)) struct[subShapeName] = filterSensitiveLog(inputShape.members[subShapeName], subShape);
                            else struct[subShapeName] = subShape;
                        });
                        return struct;
                    case 'list':
                        var list = [];
                        $hIq4q.util.arrayEach(shape, function(subShape, index) {
                            list.push(filterSensitiveLog(inputShape.member, subShape));
                        });
                        return list;
                    case 'map':
                        var map = {};
                        $hIq4q.util.each(shape, function(key, value) {
                            map[key] = filterSensitiveLog(inputShape.value, value);
                        });
                        return map;
                    default:
                        return shape;
                }
            }
            function buildMessage() {
                var time = resp.request.service.getSkewCorrectedDate().getTime();
                var delta = (time - req.startTime.getTime()) / 1000;
                var ansi = logger.isTTY ? true : false;
                var status = resp.httpResponse.statusCode;
                var censoredParams = req.params;
                if (req.service.api.operations && req.service.api.operations[req.operation] && req.service.api.operations[req.operation].input) {
                    var inputShape = req.service.api.operations[req.operation].input;
                    censoredParams = filterSensitiveLog(inputShape, req.params);
                }
                var params = $dDec7$util.inspect(censoredParams, true, null);
                var message = '';
                if (ansi) message += '\x1B[33m';
                message += '[AWS ' + req.service.serviceIdentifier + ' ' + status;
                message += ' ' + delta.toString() + 's ' + resp.retryCount + ' retries]';
                if (ansi) message += '\x1B[0;1m';
                message += ' ' + $hIq4q.util.string.lowerFirst(req.operation);
                message += '(' + params + ')';
                if (ansi) message += '\x1B[0m';
                return message;
            }
            var line = buildMessage();
            if (typeof logger.log === 'function') logger.log(line);
            else if (typeof logger.write === 'function') logger.write(line + '\n');
        });
    }),
    Json: new $cLHKj().addNamedListeners(function(add) {
        var svc = (parcelRequire("4caHz"));
        add('BUILD', 'build', svc.buildRequest);
        add('EXTRACT_DATA', 'extractData', svc.extractData);
        add('EXTRACT_ERROR', 'extractError', svc.extractError);
    }),
    Rest: new $cLHKj().addNamedListeners(function(add) {
        var svc = (parcelRequire("gDGw5"));
        add('BUILD', 'build', svc.buildRequest);
        add('EXTRACT_DATA', 'extractData', svc.extractData);
        add('EXTRACT_ERROR', 'extractError', svc.extractError);
    }),
    RestJson: new $cLHKj().addNamedListeners(function(add) {
        var svc = (parcelRequire("hQdKL"));
        add('BUILD', 'build', svc.buildRequest);
        add('EXTRACT_DATA', 'extractData', svc.extractData);
        add('EXTRACT_ERROR', 'extractError', svc.extractError);
        add('UNSET_CONTENT_LENGTH', 'afterBuild', svc.unsetContentLength);
    }),
    RestXml: new $cLHKj().addNamedListeners(function(add) {
        var svc = (parcelRequire("2OT3o"));
        add('BUILD', 'build', svc.buildRequest);
        add('EXTRACT_DATA', 'extractData', svc.extractData);
        add('EXTRACT_ERROR', 'extractError', svc.extractError);
    }),
    Query: new $cLHKj().addNamedListeners(function(add) {
        var svc = (parcelRequire("iqzj9"));
        add('BUILD', 'build', svc.buildRequest);
        add('EXTRACT_DATA', 'extractData', svc.extractData);
        add('EXTRACT_ERROR', 'extractError', svc.extractError);
    })
};

});
parcelRegister("84mkI", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");

var $i3HcT = parcelRequire("i3HcT");
var $5e000557f6d51c3e$var$endpointDiscoveryEnabledEnvs = [
    'AWS_ENABLE_ENDPOINT_DISCOVERY',
    'AWS_ENDPOINT_DISCOVERY_ENABLED'
];
/**
 * Generate key (except resources and operation part) to index the endpoints in the cache
 * If input shape has endpointdiscoveryid trait then use
 *   accessKey + operation + resources + region + service as cache key
 * If input shape doesn't have endpointdiscoveryid trait then use
 *   accessKey + region + service as cache key
 * @return [map<String,String>] object with keys to index endpoints.
 * @api private
 */ function $5e000557f6d51c3e$var$getCacheKey(request) {
    var service = request.service;
    var api = service.api || {};
    var operations = api.operations;
    var identifiers = {};
    if (service.config.region) identifiers.region = service.config.region;
    if (api.serviceId) identifiers.serviceId = api.serviceId;
    if (service.config.credentials.accessKeyId) identifiers.accessKeyId = service.config.credentials.accessKeyId;
    return identifiers;
}
/**
 * Recursive helper for marshallCustomIdentifiers().
 * Looks for required string input members that have 'endpointdiscoveryid' trait.
 * @api private
 */ function $5e000557f6d51c3e$var$marshallCustomIdentifiersHelper(result, params, shape) {
    if (!shape || params === undefined || params === null) return;
    if (shape.type === 'structure' && shape.required && shape.required.length > 0) $i3HcT.arrayEach(shape.required, function(name) {
        var memberShape = shape.members[name];
        if (memberShape.endpointDiscoveryId === true) {
            var locationName = memberShape.isLocationName ? memberShape.name : name;
            result[locationName] = String(params[name]);
        } else $5e000557f6d51c3e$var$marshallCustomIdentifiersHelper(result, params[name], memberShape);
    });
}
/**
 * Get custom identifiers for cache key.
 * Identifies custom identifiers by checking each shape's `endpointDiscoveryId` trait.
 * @param [object] request object
 * @param [object] input shape of the given operation's api
 * @api private
 */ function $5e000557f6d51c3e$var$marshallCustomIdentifiers(request, shape) {
    var identifiers = {};
    $5e000557f6d51c3e$var$marshallCustomIdentifiersHelper(identifiers, request.params, shape);
    return identifiers;
}
/**
 * Call endpoint discovery operation when it's optional.
 * When endpoint is available in cache then use the cached endpoints. If endpoints
 * are unavailable then use regional endpoints and call endpoint discovery operation
 * asynchronously. This is turned off by default.
 * @param [object] request object
 * @api private
 */ function $5e000557f6d51c3e$var$optionalDiscoverEndpoint(request) {
    var service = request.service;
    var api = service.api;
    var operationModel = api.operations ? api.operations[request.operation] : undefined;
    var inputShape = operationModel ? operationModel.input : undefined;
    var identifiers = $5e000557f6d51c3e$var$marshallCustomIdentifiers(request, inputShape);
    var cacheKey = $5e000557f6d51c3e$var$getCacheKey(request);
    if (Object.keys(identifiers).length > 0) {
        cacheKey = $i3HcT.update(cacheKey, identifiers);
        if (operationModel) cacheKey.operation = operationModel.name;
    }
    var endpoints = $hIq4q.endpointCache.get(cacheKey);
    if (endpoints && endpoints.length === 1 && endpoints[0].Address === '') //endpoint operation is being made but response not yet received
    //or endpoint operation just failed in 1 minute
    return;
    else if (endpoints && endpoints.length > 0) //found endpoint record from cache
    request.httpRequest.updateEndpoint(endpoints[0].Address);
    else {
        //endpoint record not in cache or outdated. make discovery operation
        var endpointRequest = service.makeRequest(api.endpointOperation, {
            Operation: operationModel.name,
            Identifiers: identifiers
        });
        $5e000557f6d51c3e$var$addApiVersionHeader(endpointRequest);
        endpointRequest.removeListener('validate', $hIq4q.EventListeners.Core.VALIDATE_PARAMETERS);
        endpointRequest.removeListener('retry', $hIq4q.EventListeners.Core.RETRY_CHECK);
        //put in a placeholder for endpoints already requested, prevent
        //too much in-flight calls
        $hIq4q.endpointCache.put(cacheKey, [
            {
                Address: '',
                CachePeriodInMinutes: 1
            }
        ]);
        endpointRequest.send(function(err, data) {
            if (data && data.Endpoints) $hIq4q.endpointCache.put(cacheKey, data.Endpoints);
            else if (err) $hIq4q.endpointCache.put(cacheKey, [
                {
                    Address: '',
                    CachePeriodInMinutes: 1 //not to make more endpoint operation in next 1 minute
                }
            ]);
        });
    }
}
var $5e000557f6d51c3e$var$requestQueue = {};
/**
 * Call endpoint discovery operation when it's required.
 * When endpoint is available in cache then use cached ones. If endpoints are
 * unavailable then SDK should call endpoint operation then use returned new
 * endpoint for the api call. SDK will automatically attempt to do endpoint
 * discovery. This is turned off by default
 * @param [object] request object
 * @api private
 */ function $5e000557f6d51c3e$var$requiredDiscoverEndpoint(request, done) {
    var service = request.service;
    var api = service.api;
    var operationModel = api.operations ? api.operations[request.operation] : undefined;
    var inputShape = operationModel ? operationModel.input : undefined;
    var identifiers = $5e000557f6d51c3e$var$marshallCustomIdentifiers(request, inputShape);
    var cacheKey = $5e000557f6d51c3e$var$getCacheKey(request);
    if (Object.keys(identifiers).length > 0) {
        cacheKey = $i3HcT.update(cacheKey, identifiers);
        if (operationModel) cacheKey.operation = operationModel.name;
    }
    var cacheKeyStr = $hIq4q.EndpointCache.getKeyString(cacheKey);
    var endpoints = $hIq4q.endpointCache.get(cacheKeyStr); //endpoint cache also accepts string keys
    if (endpoints && endpoints.length === 1 && endpoints[0].Address === '') {
        //endpoint operation is being made but response not yet received
        //push request object to a pending queue
        if (!$5e000557f6d51c3e$var$requestQueue[cacheKeyStr]) $5e000557f6d51c3e$var$requestQueue[cacheKeyStr] = [];
        $5e000557f6d51c3e$var$requestQueue[cacheKeyStr].push({
            request: request,
            callback: done
        });
        return;
    } else if (endpoints && endpoints.length > 0) {
        request.httpRequest.updateEndpoint(endpoints[0].Address);
        done();
    } else {
        var endpointRequest = service.makeRequest(api.endpointOperation, {
            Operation: operationModel.name,
            Identifiers: identifiers
        });
        endpointRequest.removeListener('validate', $hIq4q.EventListeners.Core.VALIDATE_PARAMETERS);
        $5e000557f6d51c3e$var$addApiVersionHeader(endpointRequest);
        //put in a placeholder for endpoints already requested, prevent
        //too much in-flight calls
        $hIq4q.endpointCache.put(cacheKeyStr, [
            {
                Address: '',
                CachePeriodInMinutes: 60 //long-live cache
            }
        ]);
        endpointRequest.send(function(err, data) {
            if (err) {
                request.response.error = $i3HcT.error(err, {
                    retryable: false
                });
                $hIq4q.endpointCache.remove(cacheKey);
                //fail all the pending requests in batch
                if ($5e000557f6d51c3e$var$requestQueue[cacheKeyStr]) {
                    var pendingRequests = $5e000557f6d51c3e$var$requestQueue[cacheKeyStr];
                    $i3HcT.arrayEach(pendingRequests, function(requestContext) {
                        requestContext.request.response.error = $i3HcT.error(err, {
                            retryable: false
                        });
                        requestContext.callback();
                    });
                    delete $5e000557f6d51c3e$var$requestQueue[cacheKeyStr];
                }
            } else if (data) {
                $hIq4q.endpointCache.put(cacheKeyStr, data.Endpoints);
                request.httpRequest.updateEndpoint(data.Endpoints[0].Address);
                //update the endpoint for all the pending requests in batch
                if ($5e000557f6d51c3e$var$requestQueue[cacheKeyStr]) {
                    var pendingRequests = $5e000557f6d51c3e$var$requestQueue[cacheKeyStr];
                    $i3HcT.arrayEach(pendingRequests, function(requestContext) {
                        requestContext.request.httpRequest.updateEndpoint(data.Endpoints[0].Address);
                        requestContext.callback();
                    });
                    delete $5e000557f6d51c3e$var$requestQueue[cacheKeyStr];
                }
            }
            done();
        });
    }
}
/**
 * add api version header to endpoint operation
 * @api private
 */ function $5e000557f6d51c3e$var$addApiVersionHeader(endpointRequest) {
    var api = endpointRequest.service.api;
    var apiVersion = api.apiVersion;
    if (apiVersion && !endpointRequest.httpRequest.headers['x-amz-api-version']) endpointRequest.httpRequest.headers['x-amz-api-version'] = apiVersion;
}
/**
 * If api call gets invalid endpoint exception, SDK should attempt to remove the invalid
 * endpoint from cache.
 * @api private
 */ function $5e000557f6d51c3e$var$invalidateCachedEndpoints(response) {
    var error = response.error;
    var httpResponse = response.httpResponse;
    if (error && (error.code === 'InvalidEndpointException' || httpResponse.statusCode === 421)) {
        var request = response.request;
        var operations = request.service.api.operations || {};
        var inputShape = operations[request.operation] ? operations[request.operation].input : undefined;
        var identifiers = $5e000557f6d51c3e$var$marshallCustomIdentifiers(request, inputShape);
        var cacheKey = $5e000557f6d51c3e$var$getCacheKey(request);
        if (Object.keys(identifiers).length > 0) {
            cacheKey = $i3HcT.update(cacheKey, identifiers);
            if (operations[request.operation]) cacheKey.operation = operations[request.operation].name;
        }
        $hIq4q.endpointCache.remove(cacheKey);
    }
}
/**
 * If endpoint is explicitly configured, SDK should not do endpoint discovery in anytime.
 * @param [object] client Service client object.
 * @api private
 */ function $5e000557f6d51c3e$var$hasCustomEndpoint(client) {
    //if set endpoint is set for specific client, enable endpoint discovery will raise an error.
    if (client._originalConfig && client._originalConfig.endpoint && client._originalConfig.endpointDiscoveryEnabled === true) throw $i3HcT.error(new Error(), {
        code: 'ConfigurationException',
        message: 'Custom endpoint is supplied; endpointDiscoveryEnabled must not be true.'
    });
    var svcConfig = $hIq4q.config[client.serviceIdentifier] || {};
    return Boolean($hIq4q.config.endpoint || svcConfig.endpoint || client._originalConfig && client._originalConfig.endpoint);
}
/**
 * @api private
 */ function $5e000557f6d51c3e$var$isFalsy(value) {
    return [
        'false',
        '0'
    ].indexOf(value) >= 0;
}
/**
 * If endpoint discovery should perform for this request when no operation requires endpoint
 * discovery for the given service.
 * SDK performs config resolution in order like below:
 * 1. If set in client configuration.
 * 2. If set in env AWS_ENABLE_ENDPOINT_DISCOVERY.
 * 3. If set in shared ini config file with key 'endpoint_discovery_enabled'.
 * @param [object] request request object.
 * @returns [boolean|undefined] if endpoint discovery config is not set in any source, this
 *  function returns undefined
 * @api private
 */ function $5e000557f6d51c3e$var$resolveEndpointDiscoveryConfig(request) {
    var service = request.service || {};
    if (service.config.endpointDiscoveryEnabled !== undefined) return service.config.endpointDiscoveryEnabled;
    //shared ini file is only available in Node
    //not to check env in browser
    if ($i3HcT.isBrowser()) return undefined;
    // If any of recognized endpoint discovery config env is set
    for(var i = 0; i < $5e000557f6d51c3e$var$endpointDiscoveryEnabledEnvs.length; i++){
        var env = $5e000557f6d51c3e$var$endpointDiscoveryEnabledEnvs[i];
        if (Object.prototype.hasOwnProperty.call(process.env, env)) {
            if (process.env[env] === '' || process.env[env] === undefined) throw $i3HcT.error(new Error(), {
                code: 'ConfigurationException',
                message: 'environmental variable ' + env + ' cannot be set to nothing'
            });
            return !$5e000557f6d51c3e$var$isFalsy(process.env[env]);
        }
    }
    var configFile = {};
    try {
        configFile = $hIq4q.util.iniLoader ? $hIq4q.util.iniLoader.loadFrom({
            isConfig: true,
            filename: process.env[$hIq4q.util.sharedConfigFileEnv]
        }) : {};
    } catch (e) {}
    var sharedFileConfig = configFile[process.env.AWS_PROFILE || $hIq4q.util.defaultProfile] || {};
    if (Object.prototype.hasOwnProperty.call(sharedFileConfig, 'endpoint_discovery_enabled')) {
        if (sharedFileConfig.endpoint_discovery_enabled === undefined) throw $i3HcT.error(new Error(), {
            code: 'ConfigurationException',
            message: 'config file entry \'endpoint_discovery_enabled\' cannot be set to nothing'
        });
        return !$5e000557f6d51c3e$var$isFalsy(sharedFileConfig.endpoint_discovery_enabled);
    }
    return undefined;
}
/**
 * attach endpoint discovery logic to request object
 * @param [object] request
 * @api private
 */ function $5e000557f6d51c3e$var$discoverEndpoint(request, done) {
    var service = request.service || {};
    if ($5e000557f6d51c3e$var$hasCustomEndpoint(service) || request.isPresigned()) return done();
    var operations = service.api.operations || {};
    var operationModel = operations[request.operation];
    var isEndpointDiscoveryRequired = operationModel ? operationModel.endpointDiscoveryRequired : 'NULL';
    var isEnabled = $5e000557f6d51c3e$var$resolveEndpointDiscoveryConfig(request);
    var hasRequiredEndpointDiscovery = service.api.hasRequiredEndpointDiscovery;
    if (isEnabled || hasRequiredEndpointDiscovery) // Once a customer enables endpoint discovery, the SDK should start appending
    // the string endpoint-discovery to the user-agent on all requests.
    request.httpRequest.appendToUserAgent('endpoint-discovery');
    switch(isEndpointDiscoveryRequired){
        case 'OPTIONAL':
            if (isEnabled || hasRequiredEndpointDiscovery) {
                // For a given service; if at least one operation requires endpoint discovery then the SDK must enable endpoint discovery
                // by default for all operations of that service, including operations where endpoint discovery is optional.
                $5e000557f6d51c3e$var$optionalDiscoverEndpoint(request);
                request.addNamedListener('INVALIDATE_CACHED_ENDPOINTS', 'extractError', $5e000557f6d51c3e$var$invalidateCachedEndpoints);
            }
            done();
            break;
        case 'REQUIRED':
            if (isEnabled === false) {
                // For a given operation; if endpoint discovery is required and it has been disabled on the SDK client,
                // then the SDK must return a clear and actionable exception.
                request.response.error = $i3HcT.error(new Error(), {
                    code: 'ConfigurationException',
                    message: 'Endpoint Discovery is disabled but ' + service.api.className + '.' + request.operation + '() requires it. Please check your configurations.'
                });
                done();
                break;
            }
            request.addNamedListener('INVALIDATE_CACHED_ENDPOINTS', 'extractError', $5e000557f6d51c3e$var$invalidateCachedEndpoints);
            $5e000557f6d51c3e$var$requiredDiscoverEndpoint(request, done);
            break;
        case 'NULL':
        default:
            done();
            break;
    }
}
module.exports = {
    discoverEndpoint: $5e000557f6d51c3e$var$discoverEndpoint,
    requiredDiscoverEndpoint: $5e000557f6d51c3e$var$requiredDiscoverEndpoint,
    optionalDiscoverEndpoint: $5e000557f6d51c3e$var$optionalDiscoverEndpoint,
    marshallCustomIdentifiers: $5e000557f6d51c3e$var$marshallCustomIdentifiers,
    getCacheKey: $5e000557f6d51c3e$var$getCacheKey,
    invalidateCachedEndpoint: $5e000557f6d51c3e$var$invalidateCachedEndpoints
};

});


parcelRegister("dx1SW", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");

var $3DIcx = parcelRequire("3DIcx");
var $9d9fd1caa12aabae$var$inherit = $hIq4q.util.inherit;
var $9d9fd1caa12aabae$var$domain = $hIq4q.util.domain;

var $g7UkD = parcelRequire("g7UkD");
/**
 * @api private
 */ var $9d9fd1caa12aabae$var$hardErrorStates = {
    success: 1,
    error: 1,
    complete: 1
};
function $9d9fd1caa12aabae$var$isTerminalState(machine) {
    return Object.prototype.hasOwnProperty.call($9d9fd1caa12aabae$var$hardErrorStates, machine._asm.currentState);
}
var $9d9fd1caa12aabae$var$fsm = new $3DIcx();
$9d9fd1caa12aabae$var$fsm.setupStates = function() {
    var transition = function(_, done) {
        var self = this;
        self._haltHandlersOnError = false;
        self.emit(self._asm.currentState, function(err) {
            if (err) {
                if ($9d9fd1caa12aabae$var$isTerminalState(self)) {
                    if ($9d9fd1caa12aabae$var$domain && self.domain instanceof $9d9fd1caa12aabae$var$domain.Domain) {
                        err.domainEmitter = self;
                        err.domain = self.domain;
                        err.domainThrown = false;
                        self.domain.emit('error', err);
                    } else throw err;
                } else {
                    self.response.error = err;
                    done(err);
                }
            } else done(self.response.error);
        });
    };
    this.addState('validate', 'build', 'error', transition);
    this.addState('build', 'afterBuild', 'restart', transition);
    this.addState('afterBuild', 'sign', 'restart', transition);
    this.addState('sign', 'send', 'retry', transition);
    this.addState('retry', 'afterRetry', 'afterRetry', transition);
    this.addState('afterRetry', 'sign', 'error', transition);
    this.addState('send', 'validateResponse', 'retry', transition);
    this.addState('validateResponse', 'extractData', 'extractError', transition);
    this.addState('extractError', 'extractData', 'retry', transition);
    this.addState('extractData', 'success', 'retry', transition);
    this.addState('restart', 'build', 'error', transition);
    this.addState('success', 'complete', 'complete', transition);
    this.addState('error', 'complete', 'complete', transition);
    this.addState('complete', null, null, transition);
};
$9d9fd1caa12aabae$var$fsm.setupStates();
/**
 * ## Asynchronous Requests
 *
 * All requests made through the SDK are asynchronous and use a
 * callback interface. Each service method that kicks off a request
 * returns an `AWS.Request` object that you can use to register
 * callbacks.
 *
 * For example, the following service method returns the request
 * object as "request", which can be used to register callbacks:
 *
 * ```javascript
 * // request is an AWS.Request object
 * var request = ec2.describeInstances();
 *
 * // register callbacks on request to retrieve response data
 * request.on('success', function(response) {
 *   console.log(response.data);
 * });
 * ```
 *
 * When a request is ready to be sent, the {send} method should
 * be called:
 *
 * ```javascript
 * request.send();
 * ```
 *
 * Since registered callbacks may or may not be idempotent, requests should only
 * be sent once. To perform the same operation multiple times, you will need to
 * create multiple request objects, each with its own registered callbacks.
 *
 * ## Removing Default Listeners for Events
 *
 * Request objects are built with default listeners for the various events,
 * depending on the service type. In some cases, you may want to remove
 * some built-in listeners to customize behaviour. Doing this requires
 * access to the built-in listener functions, which are exposed through
 * the {AWS.EventListeners.Core} namespace. For instance, you may
 * want to customize the HTTP handler used when sending a request. In this
 * case, you can remove the built-in listener associated with the 'send'
 * event, the {AWS.EventListeners.Core.SEND} listener and add your own.
 *
 * ## Multiple Callbacks and Chaining
 *
 * You can register multiple callbacks on any request object. The
 * callbacks can be registered for different events, or all for the
 * same event. In addition, you can chain callback registration, for
 * example:
 *
 * ```javascript
 * request.
 *   on('success', function(response) {
 *     console.log("Success!");
 *   }).
 *   on('error', function(error, response) {
 *     console.log("Error!");
 *   }).
 *   on('complete', function(response) {
 *     console.log("Always!");
 *   }).
 *   send();
 * ```
 *
 * The above example will print either "Success! Always!", or "Error! Always!",
 * depending on whether the request succeeded or not.
 *
 * @!attribute httpRequest
 *   @readonly
 *   @!group HTTP Properties
 *   @return [AWS.HttpRequest] the raw HTTP request object
 *     containing request headers and body information
 *     sent by the service.
 *
 * @!attribute startTime
 *   @readonly
 *   @!group Operation Properties
 *   @return [Date] the time that the request started
 *
 * @!group Request Building Events
 *
 * @!event validate(request)
 *   Triggered when a request is being validated. Listeners
 *   should throw an error if the request should not be sent.
 *   @param request [Request] the request object being sent
 *   @see AWS.EventListeners.Core.VALIDATE_CREDENTIALS
 *   @see AWS.EventListeners.Core.VALIDATE_REGION
 *   @example Ensuring that a certain parameter is set before sending a request
 *     var req = s3.putObject(params);
 *     req.on('validate', function() {
 *       if (!req.params.Body.match(/^Hello\s/)) {
 *         throw new Error('Body must start with "Hello "');
 *       }
 *     });
 *     req.send(function(err, data) { ... });
 *
 * @!event build(request)
 *   Triggered when the request payload is being built. Listeners
 *   should fill the necessary information to send the request
 *   over HTTP.
 *   @param (see AWS.Request~validate)
 *   @example Add a custom HTTP header to a request
 *     var req = s3.putObject(params);
 *     req.on('build', function() {
 *       req.httpRequest.headers['Custom-Header'] = 'value';
 *     });
 *     req.send(function(err, data) { ... });
 *
 * @!event sign(request)
 *   Triggered when the request is being signed. Listeners should
 *   add the correct authentication headers and/or adjust the body,
 *   depending on the authentication mechanism being used.
 *   @param (see AWS.Request~validate)
 *
 * @!group Request Sending Events
 *
 * @!event send(response)
 *   Triggered when the request is ready to be sent. Listeners
 *   should call the underlying transport layer to initiate
 *   the sending of the request.
 *   @param response [Response] the response object
 *   @context [Request] the request object that was sent
 *   @see AWS.EventListeners.Core.SEND
 *
 * @!event retry(response)
 *   Triggered when a request failed and might need to be retried or redirected.
 *   If the response is retryable, the listener should set the
 *   `response.error.retryable` property to `true`, and optionally set
 *   `response.error.retryDelay` to the millisecond delay for the next attempt.
 *   In the case of a redirect, `response.error.redirect` should be set to
 *   `true` with `retryDelay` set to an optional delay on the next request.
 *
 *   If a listener decides that a request should not be retried,
 *   it should set both `retryable` and `redirect` to false.
 *
 *   Note that a retryable error will be retried at most
 *   {AWS.Config.maxRetries} times (based on the service object's config).
 *   Similarly, a request that is redirected will only redirect at most
 *   {AWS.Config.maxRedirects} times.
 *
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *   @example Adding a custom retry for a 404 response
 *     request.on('retry', function(response) {
 *       // this resource is not yet available, wait 10 seconds to get it again
 *       if (response.httpResponse.statusCode === 404 && response.error) {
 *         response.error.retryable = true;   // retry this error
 *         response.error.retryDelay = 10000; // wait 10 seconds
 *       }
 *     });
 *
 * @!group Data Parsing Events
 *
 * @!event extractError(response)
 *   Triggered on all non-2xx requests so that listeners can extract
 *   error details from the response body. Listeners to this event
 *   should set the `response.error` property.
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *
 * @!event extractData(response)
 *   Triggered in successful requests to allow listeners to
 *   de-serialize the response body into `response.data`.
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *
 * @!group Completion Events
 *
 * @!event success(response)
 *   Triggered when the request completed successfully.
 *   `response.data` will contain the response data and
 *   `response.error` will be null.
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *
 * @!event error(error, response)
 *   Triggered when an error occurs at any point during the
 *   request. `response.error` will contain details about the error
 *   that occurred. `response.data` will be null.
 *   @param error [Error] the error object containing details about
 *     the error that occurred.
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *
 * @!event complete(response)
 *   Triggered whenever a request cycle completes. `response.error`
 *   should be checked, since the request may have failed.
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *
 * @!group HTTP Events
 *
 * @!event httpHeaders(statusCode, headers, response, statusMessage)
 *   Triggered when headers are sent by the remote server
 *   @param statusCode [Integer] the HTTP response code
 *   @param headers [map<String,String>] the response headers
 *   @param (see AWS.Request~send)
 *   @param statusMessage [String] A status message corresponding to the HTTP
 *                                 response code
 *   @context (see AWS.Request~send)
 *
 * @!event httpData(chunk, response)
 *   Triggered when data is sent by the remote server
 *   @param chunk [Buffer] the buffer data containing the next data chunk
 *     from the server
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *   @see AWS.EventListeners.Core.HTTP_DATA
 *
 * @!event httpUploadProgress(progress, response)
 *   Triggered when the HTTP request has uploaded more data
 *   @param progress [map] An object containing the `loaded` and `total` bytes
 *     of the request.
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *   @note This event will not be emitted in Node.js 0.8.x.
 *
 * @!event httpDownloadProgress(progress, response)
 *   Triggered when the HTTP request has downloaded more data
 *   @param progress [map] An object containing the `loaded` and `total` bytes
 *     of the request.
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *   @note This event will not be emitted in Node.js 0.8.x.
 *
 * @!event httpError(error, response)
 *   Triggered when the HTTP request failed
 *   @param error [Error] the error object that was thrown
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *
 * @!event httpDone(response)
 *   Triggered when the server is finished sending data
 *   @param (see AWS.Request~send)
 *   @context (see AWS.Request~send)
 *
 * @see AWS.Response
 */ $hIq4q.Request = $9d9fd1caa12aabae$var$inherit({
    /**
   * Creates a request for an operation on a given service with
   * a set of input parameters.
   *
   * @param service [AWS.Service] the service to perform the operation on
   * @param operation [String] the operation to perform on the service
   * @param params [Object] parameters to send to the operation.
   *   See the operation's documentation for the format of the
   *   parameters.
   */ constructor: function Request(service, operation, params) {
        var endpoint = service.endpoint;
        var region = service.config.region;
        var customUserAgent = service.config.customUserAgent;
        if (service.signingRegion) region = service.signingRegion;
        else if (service.isGlobalEndpoint) region = 'us-east-1';
        this.domain = $9d9fd1caa12aabae$var$domain && $9d9fd1caa12aabae$var$domain.active;
        this.service = service;
        this.operation = operation;
        this.params = params || {};
        this.httpRequest = new $hIq4q.HttpRequest(endpoint, region);
        this.httpRequest.appendToUserAgent(customUserAgent);
        this.startTime = service.getSkewCorrectedDate();
        this.response = new $hIq4q.Response(this);
        this._asm = new $3DIcx($9d9fd1caa12aabae$var$fsm.states, 'validate');
        this._haltHandlersOnError = false;
        $hIq4q.SequentialExecutor.call(this);
        this.emit = this.emitEvent;
    },
    /**
   * @!group Sending a Request
   */ /**
   * @overload send(callback = null)
   *   Sends the request object.
   *
   *   @callback callback function(err, data)
   *     If a callback is supplied, it is called when a response is returned
   *     from the service.
   *     @context [AWS.Request] the request object being sent.
   *     @param err [Error] the error object returned from the request.
   *       Set to `null` if the request is successful.
   *     @param data [Object] the de-serialized data returned from
   *       the request. Set to `null` if a request error occurs.
   *   @example Sending a request with a callback
   *     request = s3.putObject({Bucket: 'bucket', Key: 'key'});
   *     request.send(function(err, data) { console.log(err, data); });
   *   @example Sending a request with no callback (using event handlers)
   *     request = s3.putObject({Bucket: 'bucket', Key: 'key'});
   *     request.on('complete', function(response) { ... }); // register a callback
   *     request.send();
   */ send: function send(callback) {
        if (callback) {
            // append to user agent
            this.httpRequest.appendToUserAgent('callback');
            this.on('complete', function(resp) {
                callback.call(resp, resp.error, resp.data);
            });
        }
        this.runTo();
        return this.response;
    },
    /**
   * @!method  promise()
   *   Sends the request and returns a 'thenable' promise.
   *
   *   Two callbacks can be provided to the `then` method on the returned promise.
   *   The first callback will be called if the promise is fulfilled, and the second
   *   callback will be called if the promise is rejected.
   *   @callback fulfilledCallback function(data)
   *     Called if the promise is fulfilled.
   *     @param data [Object] the de-serialized data returned from the request.
   *   @callback rejectedCallback function(error)
   *     Called if the promise is rejected.
   *     @param error [Error] the error object returned from the request.
   *   @return [Promise] A promise that represents the state of the request.
   *   @example Sending a request using promises.
   *     var request = s3.putObject({Bucket: 'bucket', Key: 'key'});
   *     var result = request.promise();
   *     result.then(function(data) { ... }, function(error) { ... });
   */ /**
   * @api private
   */ build: function build(callback) {
        return this.runTo('send', callback);
    },
    /**
   * @api private
   */ runTo: function runTo(state, done) {
        this._asm.runTo(state, done, this);
        return this;
    },
    /**
   * Aborts a request, emitting the error and complete events.
   *
   * @!macro nobrowser
   * @example Aborting a request after sending
   *   var params = {
   *     Bucket: 'bucket', Key: 'key',
   *     Body: Buffer.alloc(1024 * 1024 * 5) // 5MB payload
   *   };
   *   var request = s3.putObject(params);
   *   request.send(function (err, data) {
   *     if (err) console.log("Error:", err.code, err.message);
   *     else console.log(data);
   *   });
   *
   *   // abort request in 1 second
   *   setTimeout(request.abort.bind(request), 1000);
   *
   *   // prints "Error: RequestAbortedError Request aborted by user"
   * @return [AWS.Request] the same request object, for chaining.
   * @since v1.4.0
   */ abort: function abort() {
        this.removeAllListeners('validateResponse');
        this.removeAllListeners('extractError');
        this.on('validateResponse', function addAbortedError(resp) {
            resp.error = $hIq4q.util.error(new Error('Request aborted by user'), {
                code: 'RequestAbortedError',
                retryable: false
            });
        });
        if (this.httpRequest.stream && !this.httpRequest.stream.didCallback) {
            this.httpRequest.stream.abort();
            if (this.httpRequest._abortCallback) this.httpRequest._abortCallback();
            else this.removeAllListeners('send'); // haven't sent yet, so let's not
        }
        return this;
    },
    /**
   * Iterates over each page of results given a pageable request, calling
   * the provided callback with each page of data. After all pages have been
   * retrieved, the callback is called with `null` data.
   *
   * @note This operation can generate multiple requests to a service.
   * @example Iterating over multiple pages of objects in an S3 bucket
   *   var pages = 1;
   *   s3.listObjects().eachPage(function(err, data) {
   *     if (err) return;
   *     console.log("Page", pages++);
   *     console.log(data);
   *   });
   * @example Iterating over multiple pages with an asynchronous callback
   *   s3.listObjects(params).eachPage(function(err, data, done) {
   *     doSomethingAsyncAndOrExpensive(function() {
   *       // The next page of results isn't fetched until done is called
   *       done();
   *     });
   *   });
   * @callback callback function(err, data, [doneCallback])
   *   Called with each page of resulting data from the request. If the
   *   optional `doneCallback` is provided in the function, it must be called
   *   when the callback is complete.
   *
   *   @param err [Error] an error object, if an error occurred.
   *   @param data [Object] a single page of response data. If there is no
   *     more data, this object will be `null`.
   *   @param doneCallback [Function] an optional done callback. If this
   *     argument is defined in the function declaration, it should be called
   *     when the next page is ready to be retrieved. This is useful for
   *     controlling serial pagination across asynchronous operations.
   *   @return [Boolean] if the callback returns `false`, pagination will
   *     stop.
   *
   * @see AWS.Request.eachItem
   * @see AWS.Response.nextPage
   * @since v1.4.0
   */ eachPage: function eachPage(callback) {
        // Make all callbacks async-ish
        callback = $hIq4q.util.fn.makeAsync(callback, 3);
        function wrappedCallback(response) {
            callback.call(response, response.error, response.data, function(result) {
                if (result === false) return;
                if (response.hasNextPage()) response.nextPage().on('complete', wrappedCallback).send();
                else callback.call(response, null, null, $hIq4q.util.fn.noop);
            });
        }
        this.on('complete', wrappedCallback).send();
    },
    /**
   * Enumerates over individual items of a request, paging the responses if
   * necessary.
   *
   * @api experimental
   * @since v1.4.0
   */ eachItem: function eachItem(callback) {
        var self = this;
        function wrappedCallback(err, data) {
            if (err) return callback(err, null);
            if (data === null) return callback(null, null);
            var config = self.service.paginationConfig(self.operation);
            var resultKey = config.resultKey;
            if (Array.isArray(resultKey)) resultKey = resultKey[0];
            var items = $g7UkD.search(data, resultKey);
            var continueIteration = true;
            $hIq4q.util.arrayEach(items, function(item) {
                continueIteration = callback(null, item);
                if (continueIteration === false) return $hIq4q.util.abort;
            });
            return continueIteration;
        }
        this.eachPage(wrappedCallback);
    },
    /**
   * @return [Boolean] whether the operation can return multiple pages of
   *   response data.
   * @see AWS.Response.eachPage
   * @since v1.4.0
   */ isPageable: function isPageable() {
        return this.service.paginationConfig(this.operation) ? true : false;
    },
    /**
   * Sends the request and converts the request object into a readable stream
   * that can be read from or piped into a writable stream.
   *
   * @note The data read from a readable stream contains only
   *   the raw HTTP body contents.
   * @example Manually reading from a stream
   *   request.createReadStream().on('data', function(data) {
   *     console.log("Got data:", data.toString());
   *   });
   * @example Piping a request body into a file
   *   var out = fs.createWriteStream('/path/to/outfile.jpg');
   *   s3.service.getObject(params).createReadStream().pipe(out);
   * @return [Stream] the readable stream object that can be piped
   *   or read from (by registering 'data' event listeners).
   * @!macro nobrowser
   */ createReadStream: function createReadStream() {
        var streams = $hIq4q.util.stream;
        var req = this;
        var stream = null;
        if ($hIq4q.HttpClient.streamsApiVersion === 2) {
            stream = new streams.PassThrough();
            process.nextTick(function() {
                req.send();
            });
        } else {
            stream = new streams.Stream();
            stream.readable = true;
            stream.sent = false;
            stream.on('newListener', function(event) {
                if (!stream.sent && event === 'data') {
                    stream.sent = true;
                    process.nextTick(function() {
                        req.send();
                    });
                }
            });
        }
        this.on('error', function(err) {
            stream.emit('error', err);
        });
        this.on('httpHeaders', function streamHeaders(statusCode, headers, resp) {
            if (statusCode < 300) {
                req.removeListener('httpData', $hIq4q.EventListeners.Core.HTTP_DATA);
                req.removeListener('httpError', $hIq4q.EventListeners.Core.HTTP_ERROR);
                req.on('httpError', function streamHttpError(error) {
                    resp.error = error;
                    resp.error.retryable = false;
                });
                var shouldCheckContentLength = false;
                var expectedLen;
                if (req.httpRequest.method !== 'HEAD') expectedLen = parseInt(headers['content-length'], 10);
                if (expectedLen !== undefined && !isNaN(expectedLen) && expectedLen >= 0) {
                    shouldCheckContentLength = true;
                    var receivedLen = 0;
                }
                var checkContentLengthAndEmit = function checkContentLengthAndEmit() {
                    if (shouldCheckContentLength && receivedLen !== expectedLen) stream.emit('error', $hIq4q.util.error(new Error('Stream content length mismatch. Received ' + receivedLen + ' of ' + expectedLen + ' bytes.'), {
                        code: 'StreamContentLengthMismatch'
                    }));
                    else if ($hIq4q.HttpClient.streamsApiVersion === 2) stream.end();
                    else stream.emit('end');
                };
                var httpStream = resp.httpResponse.createUnbufferedStream();
                if ($hIq4q.HttpClient.streamsApiVersion === 2) {
                    if (shouldCheckContentLength) {
                        var lengthAccumulator = new streams.PassThrough();
                        lengthAccumulator._write = function(chunk) {
                            if (chunk && chunk.length) receivedLen += chunk.length;
                            return streams.PassThrough.prototype._write.apply(this, arguments);
                        };
                        lengthAccumulator.on('end', checkContentLengthAndEmit);
                        stream.on('error', function(err) {
                            shouldCheckContentLength = false;
                            httpStream.unpipe(lengthAccumulator);
                            lengthAccumulator.emit('end');
                            lengthAccumulator.end();
                        });
                        httpStream.pipe(lengthAccumulator).pipe(stream, {
                            end: false
                        });
                    } else httpStream.pipe(stream);
                } else {
                    if (shouldCheckContentLength) httpStream.on('data', function(arg) {
                        if (arg && arg.length) receivedLen += arg.length;
                    });
                    httpStream.on('data', function(arg) {
                        stream.emit('data', arg);
                    });
                    httpStream.on('end', checkContentLengthAndEmit);
                }
                httpStream.on('error', function(err) {
                    shouldCheckContentLength = false;
                    stream.emit('error', err);
                });
            }
        });
        return stream;
    },
    /**
   * @param [Array,Response] args This should be the response object,
   *   or an array of args to send to the event.
   * @api private
   */ emitEvent: function emit(eventName, args, done) {
        if (typeof args === 'function') {
            done = args;
            args = null;
        }
        if (!done) done = function() {};
        if (!args) args = this.eventParameters(eventName, this.response);
        var origEmit = $hIq4q.SequentialExecutor.prototype.emit;
        origEmit.call(this, eventName, args, function(err) {
            if (err) this.response.error = err;
            done.call(this, err);
        });
    },
    /**
   * @api private
   */ eventParameters: function eventParameters(eventName) {
        switch(eventName){
            case 'restart':
            case 'validate':
            case 'sign':
            case 'build':
            case 'afterValidate':
            case 'afterBuild':
                return [
                    this
                ];
            case 'error':
                return [
                    this.response.error,
                    this.response
                ];
            default:
                return [
                    this.response
                ];
        }
    },
    /**
   * @api private
   */ presign: function presign(expires, callback) {
        if (!callback && typeof expires === 'function') {
            callback = expires;
            expires = null;
        }
        return new $hIq4q.Signers.Presign().sign(this.toGet(), expires, callback);
    },
    /**
   * @api private
   */ isPresigned: function isPresigned() {
        return Object.prototype.hasOwnProperty.call(this.httpRequest.headers, 'presigned-expires');
    },
    /**
   * @api private
   */ toUnauthenticated: function toUnauthenticated() {
        this._unAuthenticated = true;
        this.removeListener('validate', $hIq4q.EventListeners.Core.VALIDATE_CREDENTIALS);
        this.removeListener('sign', $hIq4q.EventListeners.Core.SIGN);
        return this;
    },
    /**
   * @api private
   */ toGet: function toGet() {
        if (this.service.api.protocol === 'query' || this.service.api.protocol === 'ec2') {
            this.removeListener('build', this.buildAsGet);
            this.addListener('build', this.buildAsGet);
        }
        return this;
    },
    /**
   * @api private
   */ buildAsGet: function buildAsGet(request) {
        request.httpRequest.method = 'GET';
        request.httpRequest.path = request.service.endpoint.path + '?' + request.httpRequest.body;
        request.httpRequest.body = '';
        // don't need these headers on a GET request
        delete request.httpRequest.headers['Content-Length'];
        delete request.httpRequest.headers['Content-Type'];
    },
    /**
   * @api private
   */ haltHandlersOnError: function haltHandlersOnError() {
        this._haltHandlersOnError = true;
    }
});
/**
 * @api private
 */ $hIq4q.Request.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
    this.prototype.promise = function promise() {
        var self = this;
        // append to user agent
        this.httpRequest.appendToUserAgent('promise');
        return new PromiseDependency(function(resolve, reject) {
            self.on('complete', function(resp) {
                if (resp.error) reject(resp.error);
                else // define $response property so that it is not enumerable
                // this prevents circular reference errors when stringifying the JSON object
                resolve(Object.defineProperty(resp.data || {}, '$response', {
                    value: resp
                }));
            });
            self.runTo();
        });
    };
};
/**
 * @api private
 */ $hIq4q.Request.deletePromisesFromClass = function deletePromisesFromClass() {
    delete this.prototype.promise;
};
$hIq4q.util.addPromises($hIq4q.Request);
$hIq4q.util.mixin($hIq4q.Request, $hIq4q.SequentialExecutor);

});
parcelRegister("3DIcx", function(module, exports) {
function $2a674d109e45cfb6$var$AcceptorStateMachine(states, state) {
    this.currentState = state || null;
    this.states = states || {};
}
$2a674d109e45cfb6$var$AcceptorStateMachine.prototype.runTo = function runTo(finalState, done, bindObject, inputError) {
    if (typeof finalState === 'function') {
        inputError = bindObject;
        bindObject = done;
        done = finalState;
        finalState = null;
    }
    var self = this;
    var state = self.states[self.currentState];
    state.fn.call(bindObject || self, inputError, function(err) {
        if (err) {
            if (state.fail) self.currentState = state.fail;
            else return done ? done.call(bindObject, err) : null;
        } else {
            if (state.accept) self.currentState = state.accept;
            else return done ? done.call(bindObject) : null;
        }
        if (self.currentState === finalState) return done ? done.call(bindObject, err) : null;
        self.runTo(finalState, done, bindObject, err);
    });
};
$2a674d109e45cfb6$var$AcceptorStateMachine.prototype.addState = function addState(name, acceptState, failState, fn) {
    if (typeof acceptState === 'function') {
        fn = acceptState;
        acceptState = null;
        failState = null;
    } else if (typeof failState === 'function') {
        fn = failState;
        failState = null;
    }
    if (!this.currentState) this.currentState = name;
    this.states[name] = {
        accept: acceptState,
        fail: failState,
        fn: fn
    };
    return this;
};
/**
 * @api private
 */ module.exports = $2a674d109e45cfb6$var$AcceptorStateMachine;

});

parcelRegister("g7UkD", function(module, exports) {
(function(exports1) {
    "use strict";
    function isArray(obj) {
        if (obj !== null) return Object.prototype.toString.call(obj) === "[object Array]";
        else return false;
    }
    function isObject(obj) {
        if (obj !== null) return Object.prototype.toString.call(obj) === "[object Object]";
        else return false;
    }
    function strictDeepEqual(first, second) {
        // Check the scalar case first.
        if (first === second) return true;
        // Check if they are the same type.
        var firstType = Object.prototype.toString.call(first);
        if (firstType !== Object.prototype.toString.call(second)) return false;
        // We know that first and second have the same type so we can just check the
        // first type from now on.
        if (isArray(first) === true) {
            // Short circuit if they're not the same length;
            if (first.length !== second.length) return false;
            for(var i = 0; i < first.length; i++){
                if (strictDeepEqual(first[i], second[i]) === false) return false;
            }
            return true;
        }
        if (isObject(first) === true) {
            // An object is equal if it has the same key/value pairs.
            var keysSeen = {};
            for(var key in first)if (hasOwnProperty.call(first, key)) {
                if (strictDeepEqual(first[key], second[key]) === false) return false;
                keysSeen[key] = true;
            }
            // Now check that there aren't any keys in second that weren't
            // in first.
            for(var key2 in second)if (hasOwnProperty.call(second, key2)) {
                if (keysSeen[key2] !== true) return false;
            }
            return true;
        }
        return false;
    }
    function isFalse(obj) {
        // From the spec:
        // A false value corresponds to the following values:
        // Empty list
        // Empty object
        // Empty string
        // False boolean
        // null value
        // First check the scalar values.
        if (obj === "" || obj === false || obj === null) return true;
        else if (isArray(obj) && obj.length === 0) // Check for an empty array.
        return true;
        else if (isObject(obj)) {
            // Check for an empty object.
            for(var key in obj){
                // If there are any keys, then
                // the object is not empty so the object
                // is not false.
                if (obj.hasOwnProperty(key)) return false;
            }
            return true;
        } else return false;
    }
    function objValues(obj) {
        var keys = Object.keys(obj);
        var values = [];
        for(var i = 0; i < keys.length; i++)values.push(obj[keys[i]]);
        return values;
    }
    function merge(a, b) {
        var merged = {};
        for(var key in a)merged[key] = a[key];
        for(var key2 in b)merged[key2] = b[key2];
        return merged;
    }
    var trimLeft;
    if (typeof String.prototype.trimLeft === "function") trimLeft = function(str) {
        return str.trimLeft();
    };
    else trimLeft = function(str) {
        return str.match(/^\s*(.*)/)[1];
    };
    // Type constants used to define functions.
    var TYPE_NUMBER = 0;
    var TYPE_ANY = 1;
    var TYPE_STRING = 2;
    var TYPE_ARRAY = 3;
    var TYPE_OBJECT = 4;
    var TYPE_BOOLEAN = 5;
    var TYPE_EXPREF = 6;
    var TYPE_NULL = 7;
    var TYPE_ARRAY_NUMBER = 8;
    var TYPE_ARRAY_STRING = 9;
    var TYPE_NAME_TABLE = {
        0: 'number',
        1: 'any',
        2: 'string',
        3: 'array',
        4: 'object',
        5: 'boolean',
        6: 'expression',
        7: 'null',
        8: 'Array<number>',
        9: 'Array<string>'
    };
    var TOK_EOF = "EOF";
    var TOK_UNQUOTEDIDENTIFIER = "UnquotedIdentifier";
    var TOK_QUOTEDIDENTIFIER = "QuotedIdentifier";
    var TOK_RBRACKET = "Rbracket";
    var TOK_RPAREN = "Rparen";
    var TOK_COMMA = "Comma";
    var TOK_COLON = "Colon";
    var TOK_RBRACE = "Rbrace";
    var TOK_NUMBER = "Number";
    var TOK_CURRENT = "Current";
    var TOK_EXPREF = "Expref";
    var TOK_PIPE = "Pipe";
    var TOK_OR = "Or";
    var TOK_AND = "And";
    var TOK_EQ = "EQ";
    var TOK_GT = "GT";
    var TOK_LT = "LT";
    var TOK_GTE = "GTE";
    var TOK_LTE = "LTE";
    var TOK_NE = "NE";
    var TOK_FLATTEN = "Flatten";
    var TOK_STAR = "Star";
    var TOK_FILTER = "Filter";
    var TOK_DOT = "Dot";
    var TOK_NOT = "Not";
    var TOK_LBRACE = "Lbrace";
    var TOK_LBRACKET = "Lbracket";
    var TOK_LPAREN = "Lparen";
    var TOK_LITERAL = "Literal";
    // The "&", "[", "<", ">" tokens
    // are not in basicToken because
    // there are two token variants
    // ("&&", "[?", "<=", ">=").  This is specially handled
    // below.
    var basicTokens = {
        ".": TOK_DOT,
        "*": TOK_STAR,
        ",": TOK_COMMA,
        ":": TOK_COLON,
        "{": TOK_LBRACE,
        "}": TOK_RBRACE,
        "]": TOK_RBRACKET,
        "(": TOK_LPAREN,
        ")": TOK_RPAREN,
        "@": TOK_CURRENT
    };
    var operatorStartToken = {
        "<": true,
        ">": true,
        "=": true,
        "!": true
    };
    var skipChars = {
        " ": true,
        "\t": true,
        "\n": true
    };
    function isAlpha(ch) {
        return ch >= "a" && ch <= "z" || ch >= "A" && ch <= "Z" || ch === "_";
    }
    function isNum(ch) {
        return ch >= "0" && ch <= "9" || ch === "-";
    }
    function isAlphaNum(ch) {
        return ch >= "a" && ch <= "z" || ch >= "A" && ch <= "Z" || ch >= "0" && ch <= "9" || ch === "_";
    }
    function Lexer() {}
    Lexer.prototype = {
        tokenize: function(stream) {
            var tokens = [];
            this._current = 0;
            var start;
            var identifier;
            var token;
            while(this._current < stream.length){
                if (isAlpha(stream[this._current])) {
                    start = this._current;
                    identifier = this._consumeUnquotedIdentifier(stream);
                    tokens.push({
                        type: TOK_UNQUOTEDIDENTIFIER,
                        value: identifier,
                        start: start
                    });
                } else if (basicTokens[stream[this._current]] !== undefined) {
                    tokens.push({
                        type: basicTokens[stream[this._current]],
                        value: stream[this._current],
                        start: this._current
                    });
                    this._current++;
                } else if (isNum(stream[this._current])) {
                    token = this._consumeNumber(stream);
                    tokens.push(token);
                } else if (stream[this._current] === "[") {
                    // No need to increment this._current.  This happens
                    // in _consumeLBracket
                    token = this._consumeLBracket(stream);
                    tokens.push(token);
                } else if (stream[this._current] === "\"") {
                    start = this._current;
                    identifier = this._consumeQuotedIdentifier(stream);
                    tokens.push({
                        type: TOK_QUOTEDIDENTIFIER,
                        value: identifier,
                        start: start
                    });
                } else if (stream[this._current] === "'") {
                    start = this._current;
                    identifier = this._consumeRawStringLiteral(stream);
                    tokens.push({
                        type: TOK_LITERAL,
                        value: identifier,
                        start: start
                    });
                } else if (stream[this._current] === "`") {
                    start = this._current;
                    var literal = this._consumeLiteral(stream);
                    tokens.push({
                        type: TOK_LITERAL,
                        value: literal,
                        start: start
                    });
                } else if (operatorStartToken[stream[this._current]] !== undefined) tokens.push(this._consumeOperator(stream));
                else if (skipChars[stream[this._current]] !== undefined) // Ignore whitespace.
                this._current++;
                else if (stream[this._current] === "&") {
                    start = this._current;
                    this._current++;
                    if (stream[this._current] === "&") {
                        this._current++;
                        tokens.push({
                            type: TOK_AND,
                            value: "&&",
                            start: start
                        });
                    } else tokens.push({
                        type: TOK_EXPREF,
                        value: "&",
                        start: start
                    });
                } else if (stream[this._current] === "|") {
                    start = this._current;
                    this._current++;
                    if (stream[this._current] === "|") {
                        this._current++;
                        tokens.push({
                            type: TOK_OR,
                            value: "||",
                            start: start
                        });
                    } else tokens.push({
                        type: TOK_PIPE,
                        value: "|",
                        start: start
                    });
                } else {
                    var error = new Error("Unknown character:" + stream[this._current]);
                    error.name = "LexerError";
                    throw error;
                }
            }
            return tokens;
        },
        _consumeUnquotedIdentifier: function(stream) {
            var start = this._current;
            this._current++;
            while(this._current < stream.length && isAlphaNum(stream[this._current]))this._current++;
            return stream.slice(start, this._current);
        },
        _consumeQuotedIdentifier: function(stream) {
            var start = this._current;
            this._current++;
            var maxLength = stream.length;
            while(stream[this._current] !== "\"" && this._current < maxLength){
                // You can escape a double quote and you can escape an escape.
                var current = this._current;
                if (stream[current] === "\\" && (stream[current + 1] === "\\" || stream[current + 1] === "\"")) current += 2;
                else current++;
                this._current = current;
            }
            this._current++;
            return JSON.parse(stream.slice(start, this._current));
        },
        _consumeRawStringLiteral: function(stream) {
            var start = this._current;
            this._current++;
            var maxLength = stream.length;
            while(stream[this._current] !== "'" && this._current < maxLength){
                // You can escape a single quote and you can escape an escape.
                var current = this._current;
                if (stream[current] === "\\" && (stream[current + 1] === "\\" || stream[current + 1] === "'")) current += 2;
                else current++;
                this._current = current;
            }
            this._current++;
            var literal = stream.slice(start + 1, this._current - 1);
            return literal.replace("\\'", "'");
        },
        _consumeNumber: function(stream) {
            var start = this._current;
            this._current++;
            var maxLength = stream.length;
            while(isNum(stream[this._current]) && this._current < maxLength)this._current++;
            var value = parseInt(stream.slice(start, this._current));
            return {
                type: TOK_NUMBER,
                value: value,
                start: start
            };
        },
        _consumeLBracket: function(stream) {
            var start = this._current;
            this._current++;
            if (stream[this._current] === "?") {
                this._current++;
                return {
                    type: TOK_FILTER,
                    value: "[?",
                    start: start
                };
            } else if (stream[this._current] === "]") {
                this._current++;
                return {
                    type: TOK_FLATTEN,
                    value: "[]",
                    start: start
                };
            } else return {
                type: TOK_LBRACKET,
                value: "[",
                start: start
            };
        },
        _consumeOperator: function(stream) {
            var start = this._current;
            var startingChar = stream[start];
            this._current++;
            if (startingChar === "!") {
                if (stream[this._current] === "=") {
                    this._current++;
                    return {
                        type: TOK_NE,
                        value: "!=",
                        start: start
                    };
                } else return {
                    type: TOK_NOT,
                    value: "!",
                    start: start
                };
            } else if (startingChar === "<") {
                if (stream[this._current] === "=") {
                    this._current++;
                    return {
                        type: TOK_LTE,
                        value: "<=",
                        start: start
                    };
                } else return {
                    type: TOK_LT,
                    value: "<",
                    start: start
                };
            } else if (startingChar === ">") {
                if (stream[this._current] === "=") {
                    this._current++;
                    return {
                        type: TOK_GTE,
                        value: ">=",
                        start: start
                    };
                } else return {
                    type: TOK_GT,
                    value: ">",
                    start: start
                };
            } else if (startingChar === "=") {
                if (stream[this._current] === "=") {
                    this._current++;
                    return {
                        type: TOK_EQ,
                        value: "==",
                        start: start
                    };
                }
            }
        },
        _consumeLiteral: function(stream) {
            this._current++;
            var start = this._current;
            var maxLength = stream.length;
            var literal;
            while(stream[this._current] !== "`" && this._current < maxLength){
                // You can escape a literal char or you can escape the escape.
                var current = this._current;
                if (stream[current] === "\\" && (stream[current + 1] === "\\" || stream[current + 1] === "`")) current += 2;
                else current++;
                this._current = current;
            }
            var literalString = trimLeft(stream.slice(start, this._current));
            literalString = literalString.replace("\\`", "`");
            if (this._looksLikeJSON(literalString)) literal = JSON.parse(literalString);
            else // Try to JSON parse it as "<literal>"
            literal = JSON.parse("\"" + literalString + "\"");
            // +1 gets us to the ending "`", +1 to move on to the next char.
            this._current++;
            return literal;
        },
        _looksLikeJSON: function(literalString) {
            var startingChars = "[{\"";
            var jsonLiterals = [
                "true",
                "false",
                "null"
            ];
            var numberLooking = "-0123456789";
            if (literalString === "") return false;
            else if (startingChars.indexOf(literalString[0]) >= 0) return true;
            else if (jsonLiterals.indexOf(literalString) >= 0) return true;
            else if (numberLooking.indexOf(literalString[0]) >= 0) try {
                JSON.parse(literalString);
                return true;
            } catch (ex) {
                return false;
            }
            else return false;
        }
    };
    var bindingPower = {};
    bindingPower[TOK_EOF] = 0;
    bindingPower[TOK_UNQUOTEDIDENTIFIER] = 0;
    bindingPower[TOK_QUOTEDIDENTIFIER] = 0;
    bindingPower[TOK_RBRACKET] = 0;
    bindingPower[TOK_RPAREN] = 0;
    bindingPower[TOK_COMMA] = 0;
    bindingPower[TOK_RBRACE] = 0;
    bindingPower[TOK_NUMBER] = 0;
    bindingPower[TOK_CURRENT] = 0;
    bindingPower[TOK_EXPREF] = 0;
    bindingPower[TOK_PIPE] = 1;
    bindingPower[TOK_OR] = 2;
    bindingPower[TOK_AND] = 3;
    bindingPower[TOK_EQ] = 5;
    bindingPower[TOK_GT] = 5;
    bindingPower[TOK_LT] = 5;
    bindingPower[TOK_GTE] = 5;
    bindingPower[TOK_LTE] = 5;
    bindingPower[TOK_NE] = 5;
    bindingPower[TOK_FLATTEN] = 9;
    bindingPower[TOK_STAR] = 20;
    bindingPower[TOK_FILTER] = 21;
    bindingPower[TOK_DOT] = 40;
    bindingPower[TOK_NOT] = 45;
    bindingPower[TOK_LBRACE] = 50;
    bindingPower[TOK_LBRACKET] = 55;
    bindingPower[TOK_LPAREN] = 60;
    function Parser() {}
    Parser.prototype = {
        parse: function(expression) {
            this._loadTokens(expression);
            this.index = 0;
            var ast = this.expression(0);
            if (this._lookahead(0) !== TOK_EOF) {
                var t = this._lookaheadToken(0);
                var error = new Error("Unexpected token type: " + t.type + ", value: " + t.value);
                error.name = "ParserError";
                throw error;
            }
            return ast;
        },
        _loadTokens: function(expression) {
            var lexer = new Lexer();
            var tokens = lexer.tokenize(expression);
            tokens.push({
                type: TOK_EOF,
                value: "",
                start: expression.length
            });
            this.tokens = tokens;
        },
        expression: function(rbp) {
            var leftToken = this._lookaheadToken(0);
            this._advance();
            var left = this.nud(leftToken);
            var currentToken = this._lookahead(0);
            while(rbp < bindingPower[currentToken]){
                this._advance();
                left = this.led(currentToken, left);
                currentToken = this._lookahead(0);
            }
            return left;
        },
        _lookahead: function(number) {
            return this.tokens[this.index + number].type;
        },
        _lookaheadToken: function(number) {
            return this.tokens[this.index + number];
        },
        _advance: function() {
            this.index++;
        },
        nud: function(token) {
            var left;
            var right;
            var expression;
            switch(token.type){
                case TOK_LITERAL:
                    return {
                        type: "Literal",
                        value: token.value
                    };
                case TOK_UNQUOTEDIDENTIFIER:
                    return {
                        type: "Field",
                        name: token.value
                    };
                case TOK_QUOTEDIDENTIFIER:
                    var node = {
                        type: "Field",
                        name: token.value
                    };
                    if (this._lookahead(0) === TOK_LPAREN) throw new Error("Quoted identifier not allowed for function names.");
                    return node;
                case TOK_NOT:
                    right = this.expression(bindingPower.Not);
                    return {
                        type: "NotExpression",
                        children: [
                            right
                        ]
                    };
                case TOK_STAR:
                    left = {
                        type: "Identity"
                    };
                    right = null;
                    if (this._lookahead(0) === TOK_RBRACKET) // This can happen in a multiselect,
                    // [a, b, *]
                    right = {
                        type: "Identity"
                    };
                    else right = this._parseProjectionRHS(bindingPower.Star);
                    return {
                        type: "ValueProjection",
                        children: [
                            left,
                            right
                        ]
                    };
                case TOK_FILTER:
                    return this.led(token.type, {
                        type: "Identity"
                    });
                case TOK_LBRACE:
                    return this._parseMultiselectHash();
                case TOK_FLATTEN:
                    left = {
                        type: TOK_FLATTEN,
                        children: [
                            {
                                type: "Identity"
                            }
                        ]
                    };
                    right = this._parseProjectionRHS(bindingPower.Flatten);
                    return {
                        type: "Projection",
                        children: [
                            left,
                            right
                        ]
                    };
                case TOK_LBRACKET:
                    if (this._lookahead(0) === TOK_NUMBER || this._lookahead(0) === TOK_COLON) {
                        right = this._parseIndexExpression();
                        return this._projectIfSlice({
                            type: "Identity"
                        }, right);
                    } else if (this._lookahead(0) === TOK_STAR && this._lookahead(1) === TOK_RBRACKET) {
                        this._advance();
                        this._advance();
                        right = this._parseProjectionRHS(bindingPower.Star);
                        return {
                            type: "Projection",
                            children: [
                                {
                                    type: "Identity"
                                },
                                right
                            ]
                        };
                    }
                    return this._parseMultiselectList();
                case TOK_CURRENT:
                    return {
                        type: TOK_CURRENT
                    };
                case TOK_EXPREF:
                    expression = this.expression(bindingPower.Expref);
                    return {
                        type: "ExpressionReference",
                        children: [
                            expression
                        ]
                    };
                case TOK_LPAREN:
                    var args = [];
                    while(this._lookahead(0) !== TOK_RPAREN){
                        if (this._lookahead(0) === TOK_CURRENT) {
                            expression = {
                                type: TOK_CURRENT
                            };
                            this._advance();
                        } else expression = this.expression(0);
                        args.push(expression);
                    }
                    this._match(TOK_RPAREN);
                    return args[0];
                default:
                    this._errorToken(token);
            }
        },
        led: function(tokenName, left) {
            var right;
            switch(tokenName){
                case TOK_DOT:
                    var rbp = bindingPower.Dot;
                    if (this._lookahead(0) !== TOK_STAR) {
                        right = this._parseDotRHS(rbp);
                        return {
                            type: "Subexpression",
                            children: [
                                left,
                                right
                            ]
                        };
                    }
                    // Creating a projection.
                    this._advance();
                    right = this._parseProjectionRHS(rbp);
                    return {
                        type: "ValueProjection",
                        children: [
                            left,
                            right
                        ]
                    };
                case TOK_PIPE:
                    right = this.expression(bindingPower.Pipe);
                    return {
                        type: TOK_PIPE,
                        children: [
                            left,
                            right
                        ]
                    };
                case TOK_OR:
                    right = this.expression(bindingPower.Or);
                    return {
                        type: "OrExpression",
                        children: [
                            left,
                            right
                        ]
                    };
                case TOK_AND:
                    right = this.expression(bindingPower.And);
                    return {
                        type: "AndExpression",
                        children: [
                            left,
                            right
                        ]
                    };
                case TOK_LPAREN:
                    var name = left.name;
                    var args = [];
                    var expression, node;
                    while(this._lookahead(0) !== TOK_RPAREN){
                        if (this._lookahead(0) === TOK_CURRENT) {
                            expression = {
                                type: TOK_CURRENT
                            };
                            this._advance();
                        } else expression = this.expression(0);
                        if (this._lookahead(0) === TOK_COMMA) this._match(TOK_COMMA);
                        args.push(expression);
                    }
                    this._match(TOK_RPAREN);
                    node = {
                        type: "Function",
                        name: name,
                        children: args
                    };
                    return node;
                case TOK_FILTER:
                    var condition = this.expression(0);
                    this._match(TOK_RBRACKET);
                    if (this._lookahead(0) === TOK_FLATTEN) right = {
                        type: "Identity"
                    };
                    else right = this._parseProjectionRHS(bindingPower.Filter);
                    return {
                        type: "FilterProjection",
                        children: [
                            left,
                            right,
                            condition
                        ]
                    };
                case TOK_FLATTEN:
                    var leftNode = {
                        type: TOK_FLATTEN,
                        children: [
                            left
                        ]
                    };
                    var rightNode = this._parseProjectionRHS(bindingPower.Flatten);
                    return {
                        type: "Projection",
                        children: [
                            leftNode,
                            rightNode
                        ]
                    };
                case TOK_EQ:
                case TOK_NE:
                case TOK_GT:
                case TOK_GTE:
                case TOK_LT:
                case TOK_LTE:
                    return this._parseComparator(left, tokenName);
                case TOK_LBRACKET:
                    var token = this._lookaheadToken(0);
                    if (token.type === TOK_NUMBER || token.type === TOK_COLON) {
                        right = this._parseIndexExpression();
                        return this._projectIfSlice(left, right);
                    }
                    this._match(TOK_STAR);
                    this._match(TOK_RBRACKET);
                    right = this._parseProjectionRHS(bindingPower.Star);
                    return {
                        type: "Projection",
                        children: [
                            left,
                            right
                        ]
                    };
                default:
                    this._errorToken(this._lookaheadToken(0));
            }
        },
        _match: function(tokenType) {
            if (this._lookahead(0) === tokenType) this._advance();
            else {
                var t = this._lookaheadToken(0);
                var error = new Error("Expected " + tokenType + ", got: " + t.type);
                error.name = "ParserError";
                throw error;
            }
        },
        _errorToken: function(token) {
            var error = new Error("Invalid token (" + token.type + "): \"" + token.value + "\"");
            error.name = "ParserError";
            throw error;
        },
        _parseIndexExpression: function() {
            if (this._lookahead(0) === TOK_COLON || this._lookahead(1) === TOK_COLON) return this._parseSliceExpression();
            else {
                var node = {
                    type: "Index",
                    value: this._lookaheadToken(0).value
                };
                this._advance();
                this._match(TOK_RBRACKET);
                return node;
            }
        },
        _projectIfSlice: function(left, right) {
            var indexExpr = {
                type: "IndexExpression",
                children: [
                    left,
                    right
                ]
            };
            if (right.type === "Slice") return {
                type: "Projection",
                children: [
                    indexExpr,
                    this._parseProjectionRHS(bindingPower.Star)
                ]
            };
            else return indexExpr;
        },
        _parseSliceExpression: function() {
            // [start:end:step] where each part is optional, as well as the last
            // colon.
            var parts = [
                null,
                null,
                null
            ];
            var index = 0;
            var currentToken = this._lookahead(0);
            while(currentToken !== TOK_RBRACKET && index < 3){
                if (currentToken === TOK_COLON) {
                    index++;
                    this._advance();
                } else if (currentToken === TOK_NUMBER) {
                    parts[index] = this._lookaheadToken(0).value;
                    this._advance();
                } else {
                    var t = this._lookahead(0);
                    var error = new Error("Syntax error, unexpected token: " + t.value + "(" + t.type + ")");
                    error.name = "Parsererror";
                    throw error;
                }
                currentToken = this._lookahead(0);
            }
            this._match(TOK_RBRACKET);
            return {
                type: "Slice",
                children: parts
            };
        },
        _parseComparator: function(left, comparator) {
            var right = this.expression(bindingPower[comparator]);
            return {
                type: "Comparator",
                name: comparator,
                children: [
                    left,
                    right
                ]
            };
        },
        _parseDotRHS: function(rbp) {
            var lookahead = this._lookahead(0);
            var exprTokens = [
                TOK_UNQUOTEDIDENTIFIER,
                TOK_QUOTEDIDENTIFIER,
                TOK_STAR
            ];
            if (exprTokens.indexOf(lookahead) >= 0) return this.expression(rbp);
            else if (lookahead === TOK_LBRACKET) {
                this._match(TOK_LBRACKET);
                return this._parseMultiselectList();
            } else if (lookahead === TOK_LBRACE) {
                this._match(TOK_LBRACE);
                return this._parseMultiselectHash();
            }
        },
        _parseProjectionRHS: function(rbp) {
            var right;
            if (bindingPower[this._lookahead(0)] < 10) right = {
                type: "Identity"
            };
            else if (this._lookahead(0) === TOK_LBRACKET) right = this.expression(rbp);
            else if (this._lookahead(0) === TOK_FILTER) right = this.expression(rbp);
            else if (this._lookahead(0) === TOK_DOT) {
                this._match(TOK_DOT);
                right = this._parseDotRHS(rbp);
            } else {
                var t = this._lookaheadToken(0);
                var error = new Error("Sytanx error, unexpected token: " + t.value + "(" + t.type + ")");
                error.name = "ParserError";
                throw error;
            }
            return right;
        },
        _parseMultiselectList: function() {
            var expressions = [];
            while(this._lookahead(0) !== TOK_RBRACKET){
                var expression = this.expression(0);
                expressions.push(expression);
                if (this._lookahead(0) === TOK_COMMA) {
                    this._match(TOK_COMMA);
                    if (this._lookahead(0) === TOK_RBRACKET) throw new Error("Unexpected token Rbracket");
                }
            }
            this._match(TOK_RBRACKET);
            return {
                type: "MultiSelectList",
                children: expressions
            };
        },
        _parseMultiselectHash: function() {
            var pairs = [];
            var identifierTypes = [
                TOK_UNQUOTEDIDENTIFIER,
                TOK_QUOTEDIDENTIFIER
            ];
            var keyToken, keyName, value, node;
            for(;;){
                keyToken = this._lookaheadToken(0);
                if (identifierTypes.indexOf(keyToken.type) < 0) throw new Error("Expecting an identifier token, got: " + keyToken.type);
                keyName = keyToken.value;
                this._advance();
                this._match(TOK_COLON);
                value = this.expression(0);
                node = {
                    type: "KeyValuePair",
                    name: keyName,
                    value: value
                };
                pairs.push(node);
                if (this._lookahead(0) === TOK_COMMA) this._match(TOK_COMMA);
                else if (this._lookahead(0) === TOK_RBRACE) {
                    this._match(TOK_RBRACE);
                    break;
                }
            }
            return {
                type: "MultiSelectHash",
                children: pairs
            };
        }
    };
    function TreeInterpreter(runtime) {
        this.runtime = runtime;
    }
    TreeInterpreter.prototype = {
        search: function(node, value) {
            return this.visit(node, value);
        },
        visit: function(node, value) {
            var matched, current, result, first, second, field, left, right, collected, i;
            switch(node.type){
                case "Field":
                    if (value !== null && isObject(value)) {
                        field = value[node.name];
                        if (field === undefined) return null;
                        else return field;
                    }
                    return null;
                case "Subexpression":
                    result = this.visit(node.children[0], value);
                    for(i = 1; i < node.children.length; i++){
                        result = this.visit(node.children[1], result);
                        if (result === null) return null;
                    }
                    return result;
                case "IndexExpression":
                    left = this.visit(node.children[0], value);
                    right = this.visit(node.children[1], left);
                    return right;
                case "Index":
                    if (!isArray(value)) return null;
                    var index = node.value;
                    if (index < 0) index = value.length + index;
                    result = value[index];
                    if (result === undefined) result = null;
                    return result;
                case "Slice":
                    if (!isArray(value)) return null;
                    var sliceParams = node.children.slice(0);
                    var computed = this.computeSliceParams(value.length, sliceParams);
                    var start = computed[0];
                    var stop = computed[1];
                    var step = computed[2];
                    result = [];
                    if (step > 0) for(i = start; i < stop; i += step)result.push(value[i]);
                    else for(i = start; i > stop; i += step)result.push(value[i]);
                    return result;
                case "Projection":
                    // Evaluate left child.
                    var base = this.visit(node.children[0], value);
                    if (!isArray(base)) return null;
                    collected = [];
                    for(i = 0; i < base.length; i++){
                        current = this.visit(node.children[1], base[i]);
                        if (current !== null) collected.push(current);
                    }
                    return collected;
                case "ValueProjection":
                    // Evaluate left child.
                    base = this.visit(node.children[0], value);
                    if (!isObject(base)) return null;
                    collected = [];
                    var values = objValues(base);
                    for(i = 0; i < values.length; i++){
                        current = this.visit(node.children[1], values[i]);
                        if (current !== null) collected.push(current);
                    }
                    return collected;
                case "FilterProjection":
                    base = this.visit(node.children[0], value);
                    if (!isArray(base)) return null;
                    var filtered = [];
                    var finalResults = [];
                    for(i = 0; i < base.length; i++){
                        matched = this.visit(node.children[2], base[i]);
                        if (!isFalse(matched)) filtered.push(base[i]);
                    }
                    for(var j = 0; j < filtered.length; j++){
                        current = this.visit(node.children[1], filtered[j]);
                        if (current !== null) finalResults.push(current);
                    }
                    return finalResults;
                case "Comparator":
                    first = this.visit(node.children[0], value);
                    second = this.visit(node.children[1], value);
                    switch(node.name){
                        case TOK_EQ:
                            result = strictDeepEqual(first, second);
                            break;
                        case TOK_NE:
                            result = !strictDeepEqual(first, second);
                            break;
                        case TOK_GT:
                            result = first > second;
                            break;
                        case TOK_GTE:
                            result = first >= second;
                            break;
                        case TOK_LT:
                            result = first < second;
                            break;
                        case TOK_LTE:
                            result = first <= second;
                            break;
                        default:
                            throw new Error("Unknown comparator: " + node.name);
                    }
                    return result;
                case TOK_FLATTEN:
                    var original = this.visit(node.children[0], value);
                    if (!isArray(original)) return null;
                    var merged = [];
                    for(i = 0; i < original.length; i++){
                        current = original[i];
                        if (isArray(current)) merged.push.apply(merged, current);
                        else merged.push(current);
                    }
                    return merged;
                case "Identity":
                    return value;
                case "MultiSelectList":
                    if (value === null) return null;
                    collected = [];
                    for(i = 0; i < node.children.length; i++)collected.push(this.visit(node.children[i], value));
                    return collected;
                case "MultiSelectHash":
                    if (value === null) return null;
                    collected = {};
                    var child;
                    for(i = 0; i < node.children.length; i++){
                        child = node.children[i];
                        collected[child.name] = this.visit(child.value, value);
                    }
                    return collected;
                case "OrExpression":
                    matched = this.visit(node.children[0], value);
                    if (isFalse(matched)) matched = this.visit(node.children[1], value);
                    return matched;
                case "AndExpression":
                    first = this.visit(node.children[0], value);
                    if (isFalse(first) === true) return first;
                    return this.visit(node.children[1], value);
                case "NotExpression":
                    first = this.visit(node.children[0], value);
                    return isFalse(first);
                case "Literal":
                    return node.value;
                case TOK_PIPE:
                    left = this.visit(node.children[0], value);
                    return this.visit(node.children[1], left);
                case TOK_CURRENT:
                    return value;
                case "Function":
                    var resolvedArgs = [];
                    for(i = 0; i < node.children.length; i++)resolvedArgs.push(this.visit(node.children[i], value));
                    return this.runtime.callFunction(node.name, resolvedArgs);
                case "ExpressionReference":
                    var refNode = node.children[0];
                    // Tag the node with a specific attribute so the type
                    // checker verify the type.
                    refNode.jmespathType = TOK_EXPREF;
                    return refNode;
                default:
                    throw new Error("Unknown node type: " + node.type);
            }
        },
        computeSliceParams: function(arrayLength, sliceParams) {
            var start = sliceParams[0];
            var stop = sliceParams[1];
            var step = sliceParams[2];
            var computed = [
                null,
                null,
                null
            ];
            if (step === null) step = 1;
            else if (step === 0) {
                var error = new Error("Invalid slice, step cannot be 0");
                error.name = "RuntimeError";
                throw error;
            }
            var stepValueNegative = step < 0 ? true : false;
            if (start === null) start = stepValueNegative ? arrayLength - 1 : 0;
            else start = this.capSliceRange(arrayLength, start, step);
            if (stop === null) stop = stepValueNegative ? -1 : arrayLength;
            else stop = this.capSliceRange(arrayLength, stop, step);
            computed[0] = start;
            computed[1] = stop;
            computed[2] = step;
            return computed;
        },
        capSliceRange: function(arrayLength, actualValue, step) {
            if (actualValue < 0) {
                actualValue += arrayLength;
                if (actualValue < 0) actualValue = step < 0 ? -1 : 0;
            } else if (actualValue >= arrayLength) actualValue = step < 0 ? arrayLength - 1 : arrayLength;
            return actualValue;
        }
    };
    function Runtime(interpreter) {
        this._interpreter = interpreter;
        this.functionTable = {
            // name: [function, <signature>]
            // The <signature> can be:
            //
            // {
            //   args: [[type1, type2], [type1, type2]],
            //   variadic: true|false
            // }
            //
            // Each arg in the arg list is a list of valid types
            // (if the function is overloaded and supports multiple
            // types.  If the type is "any" then no type checking
            // occurs on the argument.  Variadic is optional
            // and if not provided is assumed to be false.
            abs: {
                _func: this._functionAbs,
                _signature: [
                    {
                        types: [
                            TYPE_NUMBER
                        ]
                    }
                ]
            },
            avg: {
                _func: this._functionAvg,
                _signature: [
                    {
                        types: [
                            TYPE_ARRAY_NUMBER
                        ]
                    }
                ]
            },
            ceil: {
                _func: this._functionCeil,
                _signature: [
                    {
                        types: [
                            TYPE_NUMBER
                        ]
                    }
                ]
            },
            contains: {
                _func: this._functionContains,
                _signature: [
                    {
                        types: [
                            TYPE_STRING,
                            TYPE_ARRAY
                        ]
                    },
                    {
                        types: [
                            TYPE_ANY
                        ]
                    }
                ]
            },
            "ends_with": {
                _func: this._functionEndsWith,
                _signature: [
                    {
                        types: [
                            TYPE_STRING
                        ]
                    },
                    {
                        types: [
                            TYPE_STRING
                        ]
                    }
                ]
            },
            floor: {
                _func: this._functionFloor,
                _signature: [
                    {
                        types: [
                            TYPE_NUMBER
                        ]
                    }
                ]
            },
            length: {
                _func: this._functionLength,
                _signature: [
                    {
                        types: [
                            TYPE_STRING,
                            TYPE_ARRAY,
                            TYPE_OBJECT
                        ]
                    }
                ]
            },
            map: {
                _func: this._functionMap,
                _signature: [
                    {
                        types: [
                            TYPE_EXPREF
                        ]
                    },
                    {
                        types: [
                            TYPE_ARRAY
                        ]
                    }
                ]
            },
            max: {
                _func: this._functionMax,
                _signature: [
                    {
                        types: [
                            TYPE_ARRAY_NUMBER,
                            TYPE_ARRAY_STRING
                        ]
                    }
                ]
            },
            "merge": {
                _func: this._functionMerge,
                _signature: [
                    {
                        types: [
                            TYPE_OBJECT
                        ],
                        variadic: true
                    }
                ]
            },
            "max_by": {
                _func: this._functionMaxBy,
                _signature: [
                    {
                        types: [
                            TYPE_ARRAY
                        ]
                    },
                    {
                        types: [
                            TYPE_EXPREF
                        ]
                    }
                ]
            },
            sum: {
                _func: this._functionSum,
                _signature: [
                    {
                        types: [
                            TYPE_ARRAY_NUMBER
                        ]
                    }
                ]
            },
            "starts_with": {
                _func: this._functionStartsWith,
                _signature: [
                    {
                        types: [
                            TYPE_STRING
                        ]
                    },
                    {
                        types: [
                            TYPE_STRING
                        ]
                    }
                ]
            },
            min: {
                _func: this._functionMin,
                _signature: [
                    {
                        types: [
                            TYPE_ARRAY_NUMBER,
                            TYPE_ARRAY_STRING
                        ]
                    }
                ]
            },
            "min_by": {
                _func: this._functionMinBy,
                _signature: [
                    {
                        types: [
                            TYPE_ARRAY
                        ]
                    },
                    {
                        types: [
                            TYPE_EXPREF
                        ]
                    }
                ]
            },
            type: {
                _func: this._functionType,
                _signature: [
                    {
                        types: [
                            TYPE_ANY
                        ]
                    }
                ]
            },
            keys: {
                _func: this._functionKeys,
                _signature: [
                    {
                        types: [
                            TYPE_OBJECT
                        ]
                    }
                ]
            },
            values: {
                _func: this._functionValues,
                _signature: [
                    {
                        types: [
                            TYPE_OBJECT
                        ]
                    }
                ]
            },
            sort: {
                _func: this._functionSort,
                _signature: [
                    {
                        types: [
                            TYPE_ARRAY_STRING,
                            TYPE_ARRAY_NUMBER
                        ]
                    }
                ]
            },
            "sort_by": {
                _func: this._functionSortBy,
                _signature: [
                    {
                        types: [
                            TYPE_ARRAY
                        ]
                    },
                    {
                        types: [
                            TYPE_EXPREF
                        ]
                    }
                ]
            },
            join: {
                _func: this._functionJoin,
                _signature: [
                    {
                        types: [
                            TYPE_STRING
                        ]
                    },
                    {
                        types: [
                            TYPE_ARRAY_STRING
                        ]
                    }
                ]
            },
            reverse: {
                _func: this._functionReverse,
                _signature: [
                    {
                        types: [
                            TYPE_STRING,
                            TYPE_ARRAY
                        ]
                    }
                ]
            },
            "to_array": {
                _func: this._functionToArray,
                _signature: [
                    {
                        types: [
                            TYPE_ANY
                        ]
                    }
                ]
            },
            "to_string": {
                _func: this._functionToString,
                _signature: [
                    {
                        types: [
                            TYPE_ANY
                        ]
                    }
                ]
            },
            "to_number": {
                _func: this._functionToNumber,
                _signature: [
                    {
                        types: [
                            TYPE_ANY
                        ]
                    }
                ]
            },
            "not_null": {
                _func: this._functionNotNull,
                _signature: [
                    {
                        types: [
                            TYPE_ANY
                        ],
                        variadic: true
                    }
                ]
            }
        };
    }
    Runtime.prototype = {
        callFunction: function(name, resolvedArgs) {
            var functionEntry = this.functionTable[name];
            if (functionEntry === undefined) throw new Error("Unknown function: " + name + "()");
            this._validateArgs(name, resolvedArgs, functionEntry._signature);
            return functionEntry._func.call(this, resolvedArgs);
        },
        _validateArgs: function(name, args, signature) {
            // Validating the args requires validating
            // the correct arity and the correct type of each arg.
            // If the last argument is declared as variadic, then we need
            // a minimum number of args to be required.  Otherwise it has to
            // be an exact amount.
            var pluralized;
            if (signature[signature.length - 1].variadic) {
                if (args.length < signature.length) {
                    pluralized = signature.length === 1 ? " argument" : " arguments";
                    throw new Error("ArgumentError: " + name + "() " + "takes at least" + signature.length + pluralized + " but received " + args.length);
                }
            } else if (args.length !== signature.length) {
                pluralized = signature.length === 1 ? " argument" : " arguments";
                throw new Error("ArgumentError: " + name + "() " + "takes " + signature.length + pluralized + " but received " + args.length);
            }
            var currentSpec;
            var actualType;
            var typeMatched;
            for(var i = 0; i < signature.length; i++){
                typeMatched = false;
                currentSpec = signature[i].types;
                actualType = this._getTypeName(args[i]);
                for(var j = 0; j < currentSpec.length; j++)if (this._typeMatches(actualType, currentSpec[j], args[i])) {
                    typeMatched = true;
                    break;
                }
                if (!typeMatched) {
                    var expected = currentSpec.map(function(typeIdentifier) {
                        return TYPE_NAME_TABLE[typeIdentifier];
                    }).join(',');
                    throw new Error("TypeError: " + name + "() " + "expected argument " + (i + 1) + " to be type " + expected + " but received type " + TYPE_NAME_TABLE[actualType] + " instead.");
                }
            }
        },
        _typeMatches: function(actual, expected, argValue) {
            if (expected === TYPE_ANY) return true;
            if (expected === TYPE_ARRAY_STRING || expected === TYPE_ARRAY_NUMBER || expected === TYPE_ARRAY) {
                // The expected type can either just be array,
                // or it can require a specific subtype (array of numbers).
                //
                // The simplest case is if "array" with no subtype is specified.
                if (expected === TYPE_ARRAY) return actual === TYPE_ARRAY;
                else if (actual === TYPE_ARRAY) {
                    // Otherwise we need to check subtypes.
                    // I think this has potential to be improved.
                    var subtype;
                    if (expected === TYPE_ARRAY_NUMBER) subtype = TYPE_NUMBER;
                    else if (expected === TYPE_ARRAY_STRING) subtype = TYPE_STRING;
                    for(var i = 0; i < argValue.length; i++){
                        if (!this._typeMatches(this._getTypeName(argValue[i]), subtype, argValue[i])) return false;
                    }
                    return true;
                }
            } else return actual === expected;
        },
        _getTypeName: function(obj) {
            switch(Object.prototype.toString.call(obj)){
                case "[object String]":
                    return TYPE_STRING;
                case "[object Number]":
                    return TYPE_NUMBER;
                case "[object Array]":
                    return TYPE_ARRAY;
                case "[object Boolean]":
                    return TYPE_BOOLEAN;
                case "[object Null]":
                    return TYPE_NULL;
                case "[object Object]":
                    // Check if it's an expref.  If it has, it's been
                    // tagged with a jmespathType attr of 'Expref';
                    if (obj.jmespathType === TOK_EXPREF) return TYPE_EXPREF;
                    else return TYPE_OBJECT;
            }
        },
        _functionStartsWith: function(resolvedArgs) {
            return resolvedArgs[0].lastIndexOf(resolvedArgs[1]) === 0;
        },
        _functionEndsWith: function(resolvedArgs) {
            var searchStr = resolvedArgs[0];
            var suffix = resolvedArgs[1];
            return searchStr.indexOf(suffix, searchStr.length - suffix.length) !== -1;
        },
        _functionReverse: function(resolvedArgs) {
            var typeName = this._getTypeName(resolvedArgs[0]);
            if (typeName === TYPE_STRING) {
                var originalStr = resolvedArgs[0];
                var reversedStr = "";
                for(var i = originalStr.length - 1; i >= 0; i--)reversedStr += originalStr[i];
                return reversedStr;
            } else {
                var reversedArray = resolvedArgs[0].slice(0);
                reversedArray.reverse();
                return reversedArray;
            }
        },
        _functionAbs: function(resolvedArgs) {
            return Math.abs(resolvedArgs[0]);
        },
        _functionCeil: function(resolvedArgs) {
            return Math.ceil(resolvedArgs[0]);
        },
        _functionAvg: function(resolvedArgs) {
            var sum = 0;
            var inputArray = resolvedArgs[0];
            for(var i = 0; i < inputArray.length; i++)sum += inputArray[i];
            return sum / inputArray.length;
        },
        _functionContains: function(resolvedArgs) {
            return resolvedArgs[0].indexOf(resolvedArgs[1]) >= 0;
        },
        _functionFloor: function(resolvedArgs) {
            return Math.floor(resolvedArgs[0]);
        },
        _functionLength: function(resolvedArgs) {
            if (!isObject(resolvedArgs[0])) return resolvedArgs[0].length;
            else // As far as I can tell, there's no way to get the length
            // of an object without O(n) iteration through the object.
            return Object.keys(resolvedArgs[0]).length;
        },
        _functionMap: function(resolvedArgs) {
            var mapped = [];
            var interpreter = this._interpreter;
            var exprefNode = resolvedArgs[0];
            var elements = resolvedArgs[1];
            for(var i = 0; i < elements.length; i++)mapped.push(interpreter.visit(exprefNode, elements[i]));
            return mapped;
        },
        _functionMerge: function(resolvedArgs) {
            var merged = {};
            for(var i = 0; i < resolvedArgs.length; i++){
                var current = resolvedArgs[i];
                for(var key in current)merged[key] = current[key];
            }
            return merged;
        },
        _functionMax: function(resolvedArgs) {
            if (resolvedArgs[0].length > 0) {
                var typeName = this._getTypeName(resolvedArgs[0][0]);
                if (typeName === TYPE_NUMBER) return Math.max.apply(Math, resolvedArgs[0]);
                else {
                    var elements = resolvedArgs[0];
                    var maxElement = elements[0];
                    for(var i = 1; i < elements.length; i++)if (maxElement.localeCompare(elements[i]) < 0) maxElement = elements[i];
                    return maxElement;
                }
            } else return null;
        },
        _functionMin: function(resolvedArgs) {
            if (resolvedArgs[0].length > 0) {
                var typeName = this._getTypeName(resolvedArgs[0][0]);
                if (typeName === TYPE_NUMBER) return Math.min.apply(Math, resolvedArgs[0]);
                else {
                    var elements = resolvedArgs[0];
                    var minElement = elements[0];
                    for(var i = 1; i < elements.length; i++)if (elements[i].localeCompare(minElement) < 0) minElement = elements[i];
                    return minElement;
                }
            } else return null;
        },
        _functionSum: function(resolvedArgs) {
            var sum = 0;
            var listToSum = resolvedArgs[0];
            for(var i = 0; i < listToSum.length; i++)sum += listToSum[i];
            return sum;
        },
        _functionType: function(resolvedArgs) {
            switch(this._getTypeName(resolvedArgs[0])){
                case TYPE_NUMBER:
                    return "number";
                case TYPE_STRING:
                    return "string";
                case TYPE_ARRAY:
                    return "array";
                case TYPE_OBJECT:
                    return "object";
                case TYPE_BOOLEAN:
                    return "boolean";
                case TYPE_EXPREF:
                    return "expref";
                case TYPE_NULL:
                    return "null";
            }
        },
        _functionKeys: function(resolvedArgs) {
            return Object.keys(resolvedArgs[0]);
        },
        _functionValues: function(resolvedArgs) {
            var obj = resolvedArgs[0];
            var keys = Object.keys(obj);
            var values = [];
            for(var i = 0; i < keys.length; i++)values.push(obj[keys[i]]);
            return values;
        },
        _functionJoin: function(resolvedArgs) {
            var joinChar = resolvedArgs[0];
            var listJoin = resolvedArgs[1];
            return listJoin.join(joinChar);
        },
        _functionToArray: function(resolvedArgs) {
            if (this._getTypeName(resolvedArgs[0]) === TYPE_ARRAY) return resolvedArgs[0];
            else return [
                resolvedArgs[0]
            ];
        },
        _functionToString: function(resolvedArgs) {
            if (this._getTypeName(resolvedArgs[0]) === TYPE_STRING) return resolvedArgs[0];
            else return JSON.stringify(resolvedArgs[0]);
        },
        _functionToNumber: function(resolvedArgs) {
            var typeName = this._getTypeName(resolvedArgs[0]);
            var convertedValue;
            if (typeName === TYPE_NUMBER) return resolvedArgs[0];
            else if (typeName === TYPE_STRING) {
                convertedValue = +resolvedArgs[0];
                if (!isNaN(convertedValue)) return convertedValue;
            }
            return null;
        },
        _functionNotNull: function(resolvedArgs) {
            for(var i = 0; i < resolvedArgs.length; i++){
                if (this._getTypeName(resolvedArgs[i]) !== TYPE_NULL) return resolvedArgs[i];
            }
            return null;
        },
        _functionSort: function(resolvedArgs) {
            var sortedArray = resolvedArgs[0].slice(0);
            sortedArray.sort();
            return sortedArray;
        },
        _functionSortBy: function(resolvedArgs) {
            var sortedArray = resolvedArgs[0].slice(0);
            if (sortedArray.length === 0) return sortedArray;
            var interpreter = this._interpreter;
            var exprefNode = resolvedArgs[1];
            var requiredType = this._getTypeName(interpreter.visit(exprefNode, sortedArray[0]));
            if ([
                TYPE_NUMBER,
                TYPE_STRING
            ].indexOf(requiredType) < 0) throw new Error("TypeError");
            var that = this;
            // In order to get a stable sort out of an unstable
            // sort algorithm, we decorate/sort/undecorate (DSU)
            // by creating a new list of [index, element] pairs.
            // In the cmp function, if the evaluated elements are
            // equal, then the index will be used as the tiebreaker.
            // After the decorated list has been sorted, it will be
            // undecorated to extract the original elements.
            var decorated = [];
            for(var i = 0; i < sortedArray.length; i++)decorated.push([
                i,
                sortedArray[i]
            ]);
            decorated.sort(function(a, b) {
                var exprA = interpreter.visit(exprefNode, a[1]);
                var exprB = interpreter.visit(exprefNode, b[1]);
                if (that._getTypeName(exprA) !== requiredType) throw new Error("TypeError: expected " + requiredType + ", received " + that._getTypeName(exprA));
                else if (that._getTypeName(exprB) !== requiredType) throw new Error("TypeError: expected " + requiredType + ", received " + that._getTypeName(exprB));
                if (exprA > exprB) return 1;
                else if (exprA < exprB) return -1;
                else // If they're equal compare the items by their
                // order to maintain relative order of equal keys
                // (i.e. to get a stable sort).
                return a[0] - b[0];
            });
            // Undecorate: extract out the original list elements.
            for(var j = 0; j < decorated.length; j++)sortedArray[j] = decorated[j][1];
            return sortedArray;
        },
        _functionMaxBy: function(resolvedArgs) {
            var exprefNode = resolvedArgs[1];
            var resolvedArray = resolvedArgs[0];
            var keyFunction = this.createKeyFunction(exprefNode, [
                TYPE_NUMBER,
                TYPE_STRING
            ]);
            var maxNumber = -Infinity;
            var maxRecord;
            var current;
            for(var i = 0; i < resolvedArray.length; i++){
                current = keyFunction(resolvedArray[i]);
                if (current > maxNumber) {
                    maxNumber = current;
                    maxRecord = resolvedArray[i];
                }
            }
            return maxRecord;
        },
        _functionMinBy: function(resolvedArgs) {
            var exprefNode = resolvedArgs[1];
            var resolvedArray = resolvedArgs[0];
            var keyFunction = this.createKeyFunction(exprefNode, [
                TYPE_NUMBER,
                TYPE_STRING
            ]);
            var minNumber = Infinity;
            var minRecord;
            var current;
            for(var i = 0; i < resolvedArray.length; i++){
                current = keyFunction(resolvedArray[i]);
                if (current < minNumber) {
                    minNumber = current;
                    minRecord = resolvedArray[i];
                }
            }
            return minRecord;
        },
        createKeyFunction: function(exprefNode, allowedTypes) {
            var that = this;
            var interpreter = this._interpreter;
            var keyFunc = function(x) {
                var current = interpreter.visit(exprefNode, x);
                if (allowedTypes.indexOf(that._getTypeName(current)) < 0) {
                    var msg = "TypeError: expected one of " + allowedTypes + ", received " + that._getTypeName(current);
                    throw new Error(msg);
                }
                return current;
            };
            return keyFunc;
        }
    };
    function compile(stream) {
        var parser = new Parser();
        var ast = parser.parse(stream);
        return ast;
    }
    function tokenize(stream) {
        var lexer = new Lexer();
        return lexer.tokenize(stream);
    }
    function search(data, expression) {
        var parser = new Parser();
        // This needs to be improved.  Both the interpreter and runtime depend on
        // each other.  The runtime needs the interpreter to support exprefs.
        // There's likely a clean way to avoid the cyclic dependency.
        var runtime = new Runtime();
        var interpreter = new TreeInterpreter(runtime);
        runtime._interpreter = interpreter;
        var node = parser.parse(expression);
        return interpreter.search(node, data);
    }
    exports1.tokenize = tokenize;
    exports1.compile = compile;
    exports1.search = search;
    exports1.strictDeepEqual = strictDeepEqual;
})(module.exports);

});


parcelRegister("a4S51", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $75643a40a4544090$var$inherit = $hIq4q.util.inherit;

var $g7UkD = parcelRequire("g7UkD");
/**
 * This class encapsulates the response information
 * from a service request operation sent through {AWS.Request}.
 * The response object has two main properties for getting information
 * back from a request:
 *
 * ## The `data` property
 *
 * The `response.data` property contains the serialized object data
 * retrieved from the service request. For instance, for an
 * Amazon DynamoDB `listTables` method call, the response data might
 * look like:
 *
 * ```
 * > resp.data
 * { TableNames:
 *    [ 'table1', 'table2', ... ] }
 * ```
 *
 * The `data` property can be null if an error occurs (see below).
 *
 * ## The `error` property
 *
 * In the event of a service error (or transfer error), the
 * `response.error` property will be filled with the given
 * error data in the form:
 *
 * ```
 * { code: 'SHORT_UNIQUE_ERROR_CODE',
 *   message: 'Some human readable error message' }
 * ```
 *
 * In the case of an error, the `data` property will be `null`.
 * Note that if you handle events that can be in a failure state,
 * you should always check whether `response.error` is set
 * before attempting to access the `response.data` property.
 *
 * @!attribute data
 *   @readonly
 *   @!group Data Properties
 *   @note Inside of a {AWS.Request~httpData} event, this
 *     property contains a single raw packet instead of the
 *     full de-serialized service response.
 *   @return [Object] the de-serialized response data
 *     from the service.
 *
 * @!attribute error
 *   An structure containing information about a service
 *   or networking error.
 *   @readonly
 *   @!group Data Properties
 *   @note This attribute is only filled if a service or
 *     networking error occurs.
 *   @return [Error]
 *     * code [String] a unique short code representing the
 *       error that was emitted.
 *     * message [String] a longer human readable error message
 *     * retryable [Boolean] whether the error message is
 *       retryable.
 *     * statusCode [Numeric] in the case of a request that reached the service,
 *       this value contains the response status code.
 *     * time [Date] the date time object when the error occurred.
 *     * hostname [String] set when a networking error occurs to easily
 *       identify the endpoint of the request.
 *     * region [String] set when a networking error occurs to easily
 *       identify the region of the request.
 *
 * @!attribute requestId
 *   @readonly
 *   @!group Data Properties
 *   @return [String] the unique request ID associated with the response.
 *     Log this value when debugging requests for AWS support.
 *
 * @!attribute retryCount
 *   @readonly
 *   @!group Operation Properties
 *   @return [Integer] the number of retries that were
 *     attempted before the request was completed.
 *
 * @!attribute redirectCount
 *   @readonly
 *   @!group Operation Properties
 *   @return [Integer] the number of redirects that were
 *     followed before the request was completed.
 *
 * @!attribute httpResponse
 *   @readonly
 *   @!group HTTP Properties
 *   @return [AWS.HttpResponse] the raw HTTP response object
 *     containing the response headers and body information
 *     from the server.
 *
 * @see AWS.Request
 */ $hIq4q.Response = $75643a40a4544090$var$inherit({
    /**
   * @api private
   */ constructor: function Response(request) {
        this.request = request;
        this.data = null;
        this.error = null;
        this.retryCount = 0;
        this.redirectCount = 0;
        this.httpResponse = new $hIq4q.HttpResponse();
        if (request) {
            this.maxRetries = request.service.numRetries();
            this.maxRedirects = request.service.config.maxRedirects;
        }
    },
    /**
   * Creates a new request for the next page of response data, calling the
   * callback with the page data if a callback is provided.
   *
   * @callback callback function(err, data)
   *   Called when a page of data is returned from the next request.
   *
   *   @param err [Error] an error object, if an error occurred in the request
   *   @param data [Object] the next page of data, or null, if there are no
   *     more pages left.
   * @return [AWS.Request] the request object for the next page of data
   * @return [null] if no callback is provided and there are no pages left
   *   to retrieve.
   * @since v1.4.0
   */ nextPage: function nextPage(callback) {
        var config;
        var service = this.request.service;
        var operation = this.request.operation;
        try {
            config = service.paginationConfig(operation, true);
        } catch (e) {
            this.error = e;
        }
        if (!this.hasNextPage()) {
            if (callback) callback(this.error, null);
            else if (this.error) throw this.error;
            return null;
        }
        var params = $hIq4q.util.copy(this.request.params);
        if (!this.nextPageTokens) return callback ? callback(null, null) : null;
        else {
            var inputTokens = config.inputToken;
            if (typeof inputTokens === 'string') inputTokens = [
                inputTokens
            ];
            for(var i = 0; i < inputTokens.length; i++)params[inputTokens[i]] = this.nextPageTokens[i];
            return service.makeRequest(this.request.operation, params, callback);
        }
    },
    /**
   * @return [Boolean] whether more pages of data can be returned by further
   *   requests
   * @since v1.4.0
   */ hasNextPage: function hasNextPage() {
        this.cacheNextPageTokens();
        if (this.nextPageTokens) return true;
        if (this.nextPageTokens === undefined) return undefined;
        else return false;
    },
    /**
   * @api private
   */ cacheNextPageTokens: function cacheNextPageTokens() {
        if (Object.prototype.hasOwnProperty.call(this, 'nextPageTokens')) return this.nextPageTokens;
        this.nextPageTokens = undefined;
        var config = this.request.service.paginationConfig(this.request.operation);
        if (!config) return this.nextPageTokens;
        this.nextPageTokens = null;
        if (config.moreResults) {
            if (!$g7UkD.search(this.data, config.moreResults)) return this.nextPageTokens;
        }
        var exprs = config.outputToken;
        if (typeof exprs === 'string') exprs = [
            exprs
        ];
        $hIq4q.util.arrayEach.call(this, exprs, function(expr) {
            var output = $g7UkD.search(this.data, expr);
            if (output) {
                this.nextPageTokens = this.nextPageTokens || [];
                this.nextPageTokens.push(output);
            }
        });
        return this.nextPageTokens;
    }
});

});

parcelRegister("3iU3E", function(module, exports) {
/**
 * Copyright 2012-2013 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You
 * may not use this file except in compliance with the License. A copy of
 * the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */ 
var $hIq4q = parcelRequire("hIq4q");
var $267e89723280aa27$var$inherit = $hIq4q.util.inherit;

var $g7UkD = parcelRequire("g7UkD");
/**
 * @api private
 */ function $267e89723280aa27$var$CHECK_ACCEPTORS(resp) {
    var waiter = resp.request._waiter;
    var acceptors = waiter.config.acceptors;
    var acceptorMatched = false;
    var state = 'retry';
    acceptors.forEach(function(acceptor) {
        if (!acceptorMatched) {
            var matcher = waiter.matchers[acceptor.matcher];
            if (matcher && matcher(resp, acceptor.expected, acceptor.argument)) {
                acceptorMatched = true;
                state = acceptor.state;
            }
        }
    });
    if (!acceptorMatched && resp.error) state = 'failure';
    if (state === 'success') waiter.setSuccess(resp);
    else waiter.setError(resp, state === 'retry');
}
/**
 * @api private
 */ $hIq4q.ResourceWaiter = $267e89723280aa27$var$inherit({
    /**
   * Waits for a given state on a service object
   * @param service [Service] the service object to wait on
   * @param state [String] the state (defined in waiter configuration) to wait
   *   for.
   * @example Create a waiter for running EC2 instances
   *   var ec2 = new AWS.EC2;
   *   var waiter = new AWS.ResourceWaiter(ec2, 'instanceRunning');
   */ constructor: function constructor(service, state) {
        this.service = service;
        this.state = state;
        this.loadWaiterConfig(this.state);
    },
    service: null,
    state: null,
    config: null,
    matchers: {
        path: function(resp, expected, argument) {
            try {
                var result = $g7UkD.search(resp.data, argument);
            } catch (err) {
                return false;
            }
            return $g7UkD.strictDeepEqual(result, expected);
        },
        pathAll: function(resp, expected, argument) {
            try {
                var results = $g7UkD.search(resp.data, argument);
            } catch (err) {
                return false;
            }
            if (!Array.isArray(results)) results = [
                results
            ];
            var numResults = results.length;
            if (!numResults) return false;
            for(var ind = 0; ind < numResults; ind++){
                if (!$g7UkD.strictDeepEqual(results[ind], expected)) return false;
            }
            return true;
        },
        pathAny: function(resp, expected, argument) {
            try {
                var results = $g7UkD.search(resp.data, argument);
            } catch (err) {
                return false;
            }
            if (!Array.isArray(results)) results = [
                results
            ];
            var numResults = results.length;
            for(var ind = 0; ind < numResults; ind++){
                if ($g7UkD.strictDeepEqual(results[ind], expected)) return true;
            }
            return false;
        },
        status: function(resp, expected) {
            var statusCode = resp.httpResponse.statusCode;
            return typeof statusCode === 'number' && statusCode === expected;
        },
        error: function(resp, expected) {
            if (typeof expected === 'string' && resp.error) return expected === resp.error.code;
            // if expected is not string, can be boolean indicating presence of error
            return expected === !!resp.error;
        }
    },
    listeners: new $hIq4q.SequentialExecutor().addNamedListeners(function(add) {
        add('RETRY_CHECK', 'retry', function(resp) {
            var waiter = resp.request._waiter;
            if (resp.error && resp.error.code === 'ResourceNotReady') resp.error.retryDelay = (waiter.config.delay || 0) * 1000;
        });
        add('CHECK_OUTPUT', 'extractData', $267e89723280aa27$var$CHECK_ACCEPTORS);
        add('CHECK_ERROR', 'extractError', $267e89723280aa27$var$CHECK_ACCEPTORS);
    }),
    /**
   * @return [AWS.Request]
   */ wait: function wait(params, callback) {
        if (typeof params === 'function') {
            callback = params;
            params = undefined;
        }
        if (params && params.$waiter) {
            params = $hIq4q.util.copy(params);
            if (typeof params.$waiter.delay === 'number') this.config.delay = params.$waiter.delay;
            if (typeof params.$waiter.maxAttempts === 'number') this.config.maxAttempts = params.$waiter.maxAttempts;
            delete params.$waiter;
        }
        var request = this.service.makeRequest(this.config.operation, params);
        request._waiter = this;
        request.response.maxRetries = this.config.maxAttempts;
        request.addListeners(this.listeners);
        if (callback) request.send(callback);
        return request;
    },
    setSuccess: function setSuccess(resp) {
        resp.error = null;
        resp.data = resp.data || {};
        resp.request.removeAllListeners('extractData');
    },
    setError: function setError(resp, retryable) {
        resp.data = null;
        resp.error = $hIq4q.util.error(resp.error || new Error(), {
            code: 'ResourceNotReady',
            message: 'Resource is not in the state ' + this.state,
            retryable: retryable
        });
    },
    /**
   * Loads waiter configuration from API configuration
   *
   * @api private
   */ loadWaiterConfig: function loadWaiterConfig(state) {
        if (!this.service.api.waiters[state]) throw new $hIq4q.util.error(new Error(), {
            code: 'StateNotFoundError',
            message: 'State ' + state + ' not found.'
        });
        this.config = $hIq4q.util.copy(this.service.api.waiters[state]);
    }
});

});

parcelRegister("7KwpD", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $5a45f8bccc89827a$var$inherit = $hIq4q.util.inherit;
/**
 * @api private
 */ $hIq4q.Signers.RequestSigner = $5a45f8bccc89827a$var$inherit({
    constructor: function RequestSigner(request) {
        this.request = request;
    },
    setServiceClientId: function setServiceClientId(id) {
        this.serviceClientId = id;
    },
    getServiceClientId: function getServiceClientId() {
        return this.serviceClientId;
    }
});
$hIq4q.Signers.RequestSigner.getVersion = function getVersion(version) {
    switch(version){
        case 'v2':
            return $hIq4q.Signers.V2;
        case 'v3':
            return $hIq4q.Signers.V3;
        case 's3v4':
            return $hIq4q.Signers.V4;
        case 'v4':
            return $hIq4q.Signers.V4;
        case 's3':
            return $hIq4q.Signers.S3;
        case 'v3https':
            return $hIq4q.Signers.V3Https;
        case 'bearer':
            return $hIq4q.Signers.Bearer;
    }
    throw new Error('Unknown signing version ' + version);
};
parcelRequire("6s81C");
parcelRequire("gLCPf");
parcelRequire("8pECV");
parcelRequire("boZl7");
parcelRequire("7O7ii");
parcelRequire("bCr9H");
parcelRequire("69745");

});
parcelRegister("6s81C", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $4b2b95339af7b3e2$var$inherit = $hIq4q.util.inherit;
/**
 * @api private
 */ $hIq4q.Signers.V2 = $4b2b95339af7b3e2$var$inherit($hIq4q.Signers.RequestSigner, {
    addAuthorization: function addAuthorization(credentials, date) {
        if (!date) date = $hIq4q.util.date.getDate();
        var r = this.request;
        r.params.Timestamp = $hIq4q.util.date.iso8601(date);
        r.params.SignatureVersion = '2';
        r.params.SignatureMethod = 'HmacSHA256';
        r.params.AWSAccessKeyId = credentials.accessKeyId;
        if (credentials.sessionToken) r.params.SecurityToken = credentials.sessionToken;
        delete r.params.Signature; // delete old Signature for re-signing
        r.params.Signature = this.signature(credentials);
        r.body = $hIq4q.util.queryParamsToString(r.params);
        r.headers['Content-Length'] = r.body.length;
    },
    signature: function signature(credentials) {
        return $hIq4q.util.crypto.hmac(credentials.secretAccessKey, this.stringToSign(), 'base64');
    },
    stringToSign: function stringToSign() {
        var parts = [];
        parts.push(this.request.method);
        parts.push(this.request.endpoint.host.toLowerCase());
        parts.push(this.request.pathname());
        parts.push($hIq4q.util.queryParamsToString(this.request.params));
        return parts.join('\n');
    }
});
/**
 * @api private
 */ module.exports = $hIq4q.Signers.V2;

});

parcelRegister("gLCPf", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $c34f2715d864ea4a$var$inherit = $hIq4q.util.inherit;
/**
 * @api private
 */ $hIq4q.Signers.V3 = $c34f2715d864ea4a$var$inherit($hIq4q.Signers.RequestSigner, {
    addAuthorization: function addAuthorization(credentials, date) {
        var datetime = $hIq4q.util.date.rfc822(date);
        this.request.headers['X-Amz-Date'] = datetime;
        if (credentials.sessionToken) this.request.headers['x-amz-security-token'] = credentials.sessionToken;
        this.request.headers['X-Amzn-Authorization'] = this.authorization(credentials, datetime);
    },
    authorization: function authorization(credentials) {
        return "AWS3 AWSAccessKeyId=" + credentials.accessKeyId + ',' + 'Algorithm=HmacSHA256,' + 'SignedHeaders=' + this.signedHeaders() + ',' + 'Signature=' + this.signature(credentials);
    },
    signedHeaders: function signedHeaders() {
        var headers = [];
        $hIq4q.util.arrayEach(this.headersToSign(), function iterator(h) {
            headers.push(h.toLowerCase());
        });
        return headers.sort().join(';');
    },
    canonicalHeaders: function canonicalHeaders() {
        var headers = this.request.headers;
        var parts = [];
        $hIq4q.util.arrayEach(this.headersToSign(), function iterator(h) {
            parts.push(h.toLowerCase().trim() + ':' + String(headers[h]).trim());
        });
        return parts.sort().join('\n') + '\n';
    },
    headersToSign: function headersToSign() {
        var headers = [];
        $hIq4q.util.each(this.request.headers, function iterator(k) {
            if (k === 'Host' || k === 'Content-Encoding' || k.match(/^X-Amz/i)) headers.push(k);
        });
        return headers;
    },
    signature: function signature(credentials) {
        return $hIq4q.util.crypto.hmac(credentials.secretAccessKey, this.stringToSign(), 'base64');
    },
    stringToSign: function stringToSign() {
        var parts = [];
        parts.push(this.request.method);
        parts.push('/');
        parts.push('');
        parts.push(this.canonicalHeaders());
        parts.push(this.request.body);
        return $hIq4q.util.crypto.sha256(parts.join('\n'));
    }
});
/**
 * @api private
 */ module.exports = $hIq4q.Signers.V3;

});

parcelRegister("8pECV", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $62002c2e2981f8dd$var$inherit = $hIq4q.util.inherit;
parcelRequire("gLCPf");
/**
 * @api private
 */ $hIq4q.Signers.V3Https = $62002c2e2981f8dd$var$inherit($hIq4q.Signers.V3, {
    authorization: function authorization(credentials) {
        return "AWS3-HTTPS AWSAccessKeyId=" + credentials.accessKeyId + ',' + 'Algorithm=HmacSHA256,' + 'Signature=' + this.signature(credentials);
    },
    stringToSign: function stringToSign() {
        return this.request.headers['X-Amz-Date'];
    }
});
/**
 * @api private
 */ module.exports = $hIq4q.Signers.V3Https;

});

parcelRegister("boZl7", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");

var $75596 = parcelRequire("75596");
var $84d1845ab746da1e$var$inherit = $hIq4q.util.inherit;
/**
 * @api private
 */ var $84d1845ab746da1e$var$expiresHeader = 'presigned-expires';
/**
 * @api private
 */ $hIq4q.Signers.V4 = $84d1845ab746da1e$var$inherit($hIq4q.Signers.RequestSigner, {
    constructor: function V4(request, serviceName, options) {
        $hIq4q.Signers.RequestSigner.call(this, request);
        this.serviceName = serviceName;
        options = options || {};
        this.signatureCache = typeof options.signatureCache === 'boolean' ? options.signatureCache : true;
        this.operation = options.operation;
        this.signatureVersion = options.signatureVersion;
    },
    algorithm: 'AWS4-HMAC-SHA256',
    addAuthorization: function addAuthorization(credentials, date) {
        var datetime = $hIq4q.util.date.iso8601(date).replace(/[:\-]|\.\d{3}/g, '');
        if (this.isPresigned()) this.updateForPresigned(credentials, datetime);
        else this.addHeaders(credentials, datetime);
        this.request.headers['Authorization'] = this.authorization(credentials, datetime);
    },
    addHeaders: function addHeaders(credentials, datetime) {
        this.request.headers['X-Amz-Date'] = datetime;
        if (credentials.sessionToken) this.request.headers['x-amz-security-token'] = credentials.sessionToken;
    },
    updateForPresigned: function updateForPresigned(credentials, datetime) {
        var credString = this.credentialString(datetime);
        var qs = {
            'X-Amz-Date': datetime,
            'X-Amz-Algorithm': this.algorithm,
            'X-Amz-Credential': credentials.accessKeyId + '/' + credString,
            'X-Amz-Expires': this.request.headers[$84d1845ab746da1e$var$expiresHeader],
            'X-Amz-SignedHeaders': this.signedHeaders()
        };
        if (credentials.sessionToken) qs['X-Amz-Security-Token'] = credentials.sessionToken;
        if (this.request.headers['Content-Type']) qs['Content-Type'] = this.request.headers['Content-Type'];
        if (this.request.headers['Content-MD5']) qs['Content-MD5'] = this.request.headers['Content-MD5'];
        if (this.request.headers['Cache-Control']) qs['Cache-Control'] = this.request.headers['Cache-Control'];
        // need to pull in any other X-Amz-* headers
        $hIq4q.util.each.call(this, this.request.headers, function(key, value) {
            if (key === $84d1845ab746da1e$var$expiresHeader) return;
            if (this.isSignableHeader(key)) {
                var lowerKey = key.toLowerCase();
                // Metadata should be normalized
                if (lowerKey.indexOf('x-amz-meta-') === 0) qs[lowerKey] = value;
                else if (lowerKey.indexOf('x-amz-') === 0) qs[key] = value;
            }
        });
        var sep = this.request.path.indexOf('?') >= 0 ? '&' : '?';
        this.request.path += sep + $hIq4q.util.queryParamsToString(qs);
    },
    authorization: function authorization(credentials, datetime) {
        var parts = [];
        var credString = this.credentialString(datetime);
        parts.push(this.algorithm + ' Credential=' + credentials.accessKeyId + '/' + credString);
        parts.push('SignedHeaders=' + this.signedHeaders());
        parts.push('Signature=' + this.signature(credentials, datetime));
        return parts.join(', ');
    },
    signature: function signature(credentials, datetime) {
        var signingKey = $75596.getSigningKey(credentials, datetime.substr(0, 8), this.request.region, this.serviceName, this.signatureCache);
        return $hIq4q.util.crypto.hmac(signingKey, this.stringToSign(datetime), 'hex');
    },
    stringToSign: function stringToSign(datetime) {
        var parts = [];
        parts.push('AWS4-HMAC-SHA256');
        parts.push(datetime);
        parts.push(this.credentialString(datetime));
        parts.push(this.hexEncodedHash(this.canonicalString()));
        return parts.join('\n');
    },
    canonicalString: function canonicalString() {
        var parts = [], pathname = this.request.pathname();
        if (this.serviceName !== 's3' && this.signatureVersion !== 's3v4') pathname = $hIq4q.util.uriEscapePath(pathname);
        parts.push(this.request.method);
        parts.push(pathname);
        parts.push(this.request.search());
        parts.push(this.canonicalHeaders() + '\n');
        parts.push(this.signedHeaders());
        parts.push(this.hexEncodedBodyHash());
        return parts.join('\n');
    },
    canonicalHeaders: function canonicalHeaders() {
        var headers = [];
        $hIq4q.util.each.call(this, this.request.headers, function(key, item) {
            headers.push([
                key,
                item
            ]);
        });
        headers.sort(function(a, b) {
            return a[0].toLowerCase() < b[0].toLowerCase() ? -1 : 1;
        });
        var parts = [];
        $hIq4q.util.arrayEach.call(this, headers, function(item) {
            var key = item[0].toLowerCase();
            if (this.isSignableHeader(key)) {
                var value = item[1];
                if (typeof value === 'undefined' || value === null || typeof value.toString !== 'function') throw $hIq4q.util.error(new Error('Header ' + key + ' contains invalid value'), {
                    code: 'InvalidHeader'
                });
                parts.push(key + ':' + this.canonicalHeaderValues(value.toString()));
            }
        });
        return parts.join('\n');
    },
    canonicalHeaderValues: function canonicalHeaderValues(values) {
        return values.replace(/\s+/g, ' ').replace(/^\s+|\s+$/g, '');
    },
    signedHeaders: function signedHeaders() {
        var keys = [];
        $hIq4q.util.each.call(this, this.request.headers, function(key) {
            key = key.toLowerCase();
            if (this.isSignableHeader(key)) keys.push(key);
        });
        return keys.sort().join(';');
    },
    credentialString: function credentialString(datetime) {
        return $75596.createScope(datetime.substr(0, 8), this.request.region, this.serviceName);
    },
    hexEncodedHash: function hash(string) {
        return $hIq4q.util.crypto.sha256(string, 'hex');
    },
    hexEncodedBodyHash: function hexEncodedBodyHash() {
        var request = this.request;
        if (this.isPresigned() && [
            's3',
            's3-object-lambda'
        ].indexOf(this.serviceName) > -1 && !request.body) return 'UNSIGNED-PAYLOAD';
        else if (request.headers['X-Amz-Content-Sha256']) return request.headers['X-Amz-Content-Sha256'];
        else return this.hexEncodedHash(this.request.body || '');
    },
    unsignableHeaders: [
        'authorization',
        'content-type',
        'content-length',
        'user-agent',
        $84d1845ab746da1e$var$expiresHeader,
        'expect',
        'x-amzn-trace-id'
    ],
    isSignableHeader: function isSignableHeader(key) {
        if (key.toLowerCase().indexOf('x-amz-') === 0) return true;
        return this.unsignableHeaders.indexOf(key) < 0;
    },
    isPresigned: function isPresigned() {
        return this.request.headers[$84d1845ab746da1e$var$expiresHeader] ? true : false;
    }
});
/**
 * @api private
 */ module.exports = $hIq4q.Signers.V4;

});
parcelRegister("75596", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
/**
 * @api private
 */ var $527cfde3a97d2058$var$cachedSecret = {};
/**
 * @api private
 */ var $527cfde3a97d2058$var$cacheQueue = [];
/**
 * @api private
 */ var $527cfde3a97d2058$var$maxCacheEntries = 50;
/**
 * @api private
 */ var $527cfde3a97d2058$var$v4Identifier = 'aws4_request';
/**
 * @api private
 */ module.exports = {
    /**
   * @api private
   *
   * @param date [String]
   * @param region [String]
   * @param serviceName [String]
   * @return [String]
   */ createScope: function createScope(date, region, serviceName) {
        return [
            date.substr(0, 8),
            region,
            serviceName,
            $527cfde3a97d2058$var$v4Identifier
        ].join('/');
    },
    /**
   * @api private
   *
   * @param credentials [Credentials]
   * @param date [String]
   * @param region [String]
   * @param service [String]
   * @param shouldCache [Boolean]
   * @return [String]
   */ getSigningKey: function getSigningKey(credentials, date, region, service, shouldCache) {
        var credsIdentifier = $hIq4q.util.crypto.hmac(credentials.secretAccessKey, credentials.accessKeyId, 'base64');
        var cacheKey = [
            credsIdentifier,
            date,
            region,
            service
        ].join('_');
        shouldCache = shouldCache !== false;
        if (shouldCache && cacheKey in $527cfde3a97d2058$var$cachedSecret) return $527cfde3a97d2058$var$cachedSecret[cacheKey];
        var kDate = $hIq4q.util.crypto.hmac('AWS4' + credentials.secretAccessKey, date, 'buffer');
        var kRegion = $hIq4q.util.crypto.hmac(kDate, region, 'buffer');
        var kService = $hIq4q.util.crypto.hmac(kRegion, service, 'buffer');
        var signingKey = $hIq4q.util.crypto.hmac(kService, $527cfde3a97d2058$var$v4Identifier, 'buffer');
        if (shouldCache) {
            $527cfde3a97d2058$var$cachedSecret[cacheKey] = signingKey;
            $527cfde3a97d2058$var$cacheQueue.push(cacheKey);
            if ($527cfde3a97d2058$var$cacheQueue.length > $527cfde3a97d2058$var$maxCacheEntries) // remove the oldest entry (not the least recently used)
            delete $527cfde3a97d2058$var$cachedSecret[$527cfde3a97d2058$var$cacheQueue.shift()];
        }
        return signingKey;
    },
    /**
   * @api private
   *
   * Empties the derived signing key cache. Made available for testing purposes
   * only.
   */ emptyCache: function emptyCache() {
        $527cfde3a97d2058$var$cachedSecret = {};
        $527cfde3a97d2058$var$cacheQueue = [];
    }
};

});


parcelRegister("7O7ii", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $5af2dc5fe12f17dd$var$inherit = $hIq4q.util.inherit;
/**
 * @api private
 */ $hIq4q.Signers.S3 = $5af2dc5fe12f17dd$var$inherit($hIq4q.Signers.RequestSigner, {
    /**
   * When building the stringToSign, these sub resource params should be
   * part of the canonical resource string with their NON-decoded values
   */ subResources: {
        'acl': 1,
        'accelerate': 1,
        'analytics': 1,
        'cors': 1,
        'lifecycle': 1,
        'delete': 1,
        'inventory': 1,
        'location': 1,
        'logging': 1,
        'metrics': 1,
        'notification': 1,
        'partNumber': 1,
        'policy': 1,
        'requestPayment': 1,
        'replication': 1,
        'restore': 1,
        'tagging': 1,
        'torrent': 1,
        'uploadId': 1,
        'uploads': 1,
        'versionId': 1,
        'versioning': 1,
        'versions': 1,
        'website': 1
    },
    // when building the stringToSign, these querystring params should be
    // part of the canonical resource string with their NON-encoded values
    responseHeaders: {
        'response-content-type': 1,
        'response-content-language': 1,
        'response-expires': 1,
        'response-cache-control': 1,
        'response-content-disposition': 1,
        'response-content-encoding': 1
    },
    addAuthorization: function addAuthorization(credentials, date) {
        if (!this.request.headers['presigned-expires']) this.request.headers['X-Amz-Date'] = $hIq4q.util.date.rfc822(date);
        if (credentials.sessionToken) // presigned URLs require this header to be lowercased
        this.request.headers['x-amz-security-token'] = credentials.sessionToken;
        var signature = this.sign(credentials.secretAccessKey, this.stringToSign());
        var auth = 'AWS ' + credentials.accessKeyId + ':' + signature;
        this.request.headers['Authorization'] = auth;
    },
    stringToSign: function stringToSign() {
        var r = this.request;
        var parts = [];
        parts.push(r.method);
        parts.push(r.headers['Content-MD5'] || '');
        parts.push(r.headers['Content-Type'] || '');
        // This is the "Date" header, but we use X-Amz-Date.
        // The S3 signing mechanism requires us to pass an empty
        // string for this Date header regardless.
        parts.push(r.headers['presigned-expires'] || '');
        var headers = this.canonicalizedAmzHeaders();
        if (headers) parts.push(headers);
        parts.push(this.canonicalizedResource());
        return parts.join('\n');
    },
    canonicalizedAmzHeaders: function canonicalizedAmzHeaders() {
        var amzHeaders = [];
        $hIq4q.util.each(this.request.headers, function(name) {
            if (name.match(/^x-amz-/i)) amzHeaders.push(name);
        });
        amzHeaders.sort(function(a, b) {
            return a.toLowerCase() < b.toLowerCase() ? -1 : 1;
        });
        var parts = [];
        $hIq4q.util.arrayEach.call(this, amzHeaders, function(name) {
            parts.push(name.toLowerCase() + ':' + String(this.request.headers[name]));
        });
        return parts.join('\n');
    },
    canonicalizedResource: function canonicalizedResource() {
        var r = this.request;
        var parts = r.path.split('?');
        var path = parts[0];
        var querystring = parts[1];
        var resource = '';
        if (r.virtualHostedBucket) resource += '/' + r.virtualHostedBucket;
        resource += path;
        if (querystring) {
            // collect a list of sub resources and query params that need to be signed
            var resources = [];
            $hIq4q.util.arrayEach.call(this, querystring.split('&'), function(param) {
                var name = param.split('=')[0];
                var value = param.split('=')[1];
                if (this.subResources[name] || this.responseHeaders[name]) {
                    var subresource = {
                        name: name
                    };
                    if (value !== undefined) {
                        if (this.subResources[name]) subresource.value = value;
                        else subresource.value = decodeURIComponent(value);
                    }
                    resources.push(subresource);
                }
            });
            resources.sort(function(a, b) {
                return a.name < b.name ? -1 : 1;
            });
            if (resources.length) {
                querystring = [];
                $hIq4q.util.arrayEach(resources, function(res) {
                    if (res.value === undefined) querystring.push(res.name);
                    else querystring.push(res.name + '=' + res.value);
                });
                resource += '?' + querystring.join('&');
            }
        }
        return resource;
    },
    sign: function sign(secret, string) {
        return $hIq4q.util.crypto.hmac(secret, string, 'base64', 'sha1');
    }
});
/**
 * @api private
 */ module.exports = $hIq4q.Signers.S3;

});

parcelRegister("bCr9H", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $87584ed3a0d66556$var$inherit = $hIq4q.util.inherit;
/**
 * @api private
 */ var $87584ed3a0d66556$var$expiresHeader = 'presigned-expires';
/**
 * @api private
 */ function $87584ed3a0d66556$var$signedUrlBuilder(request) {
    var expires = request.httpRequest.headers[$87584ed3a0d66556$var$expiresHeader];
    var signerClass = request.service.getSignerClass(request);
    delete request.httpRequest.headers['User-Agent'];
    delete request.httpRequest.headers['X-Amz-User-Agent'];
    if (signerClass === $hIq4q.Signers.V4) {
        if (expires > 604800) {
            var message = "Presigning does not support expiry time greater than a week with SigV4 signing.";
            throw $hIq4q.util.error(new Error(), {
                code: 'InvalidExpiryTime',
                message: message,
                retryable: false
            });
        }
        request.httpRequest.headers[$87584ed3a0d66556$var$expiresHeader] = expires;
    } else if (signerClass === $hIq4q.Signers.S3) {
        var now = request.service ? request.service.getSkewCorrectedDate() : $hIq4q.util.date.getDate();
        request.httpRequest.headers[$87584ed3a0d66556$var$expiresHeader] = parseInt($hIq4q.util.date.unixTimestamp(now) + expires, 10).toString();
    } else throw $hIq4q.util.error(new Error(), {
        message: 'Presigning only supports S3 or SigV4 signing.',
        code: 'UnsupportedSigner',
        retryable: false
    });
}
/**
 * @api private
 */ function $87584ed3a0d66556$var$signedUrlSigner(request) {
    var endpoint = request.httpRequest.endpoint;
    var parsedUrl = $hIq4q.util.urlParse(request.httpRequest.path);
    var queryParams = {};
    if (parsedUrl.search) queryParams = $hIq4q.util.queryStringParse(parsedUrl.search.substr(1));
    var auth = request.httpRequest.headers['Authorization'].split(' ');
    if (auth[0] === 'AWS') {
        auth = auth[1].split(':');
        queryParams['Signature'] = auth.pop();
        queryParams['AWSAccessKeyId'] = auth.join(':');
        $hIq4q.util.each(request.httpRequest.headers, function(key, value) {
            if (key === $87584ed3a0d66556$var$expiresHeader) key = 'Expires';
            if (key.indexOf('x-amz-meta-') === 0) {
                // Delete existing, potentially not normalized key
                delete queryParams[key];
                key = key.toLowerCase();
            }
            queryParams[key] = value;
        });
        delete request.httpRequest.headers[$87584ed3a0d66556$var$expiresHeader];
        delete queryParams['Authorization'];
        delete queryParams['Host'];
    } else if (auth[0] === 'AWS4-HMAC-SHA256') {
        auth.shift();
        var rest = auth.join(' ');
        var signature = rest.match(/Signature=(.*?)(?:,|\s|\r?\n|$)/)[1];
        queryParams['X-Amz-Signature'] = signature;
        delete queryParams['Expires'];
    }
    // build URL
    endpoint.pathname = parsedUrl.pathname;
    endpoint.search = $hIq4q.util.queryParamsToString(queryParams);
}
/**
 * @api private
 */ $hIq4q.Signers.Presign = $87584ed3a0d66556$var$inherit({
    /**
   * @api private
   */ sign: function sign(request, expireTime, callback) {
        request.httpRequest.headers[$87584ed3a0d66556$var$expiresHeader] = expireTime || 3600;
        request.on('build', $87584ed3a0d66556$var$signedUrlBuilder);
        request.on('sign', $87584ed3a0d66556$var$signedUrlSigner);
        request.removeListener('afterBuild', $hIq4q.EventListeners.Core.SET_CONTENT_LENGTH);
        request.removeListener('afterBuild', $hIq4q.EventListeners.Core.COMPUTE_SHA256);
        request.emit('beforePresign', [
            request
        ]);
        if (callback) request.build(function() {
            if (this.response.error) callback(this.response.error);
            else callback(null, $hIq4q.util.urlFormat(request.httpRequest.endpoint));
        });
        else {
            request.build();
            if (request.response.error) throw request.response.error;
            return $hIq4q.util.urlFormat(request.httpRequest.endpoint);
        }
    }
});
/**
 * @api private
 */ module.exports = $hIq4q.Signers.Presign;

});

parcelRegister("69745", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
/**
 * @api private
 */ $hIq4q.Signers.Bearer = $hIq4q.util.inherit($hIq4q.Signers.RequestSigner, {
    constructor: function Bearer(request) {
        $hIq4q.Signers.RequestSigner.call(this, request);
    },
    addAuthorization: function addAuthorization(token) {
        this.request.headers['Authorization'] = 'Bearer ' + token.token;
    }
});

});


parcelRegister("lgvDe", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
/**
 * @api private
 */ $hIq4q.ParamValidator = $hIq4q.util.inherit({
    /**
   * Create a new validator object.
   *
   * @param validation [Boolean|map] whether input parameters should be
   *     validated against the operation description before sending the
   *     request. Pass a map to enable any of the following specific
   *     validation features:
   *
   *     * **min** [Boolean] &mdash; Validates that a value meets the min
   *       constraint. This is enabled by default when paramValidation is set
   *       to `true`.
   *     * **max** [Boolean] &mdash; Validates that a value meets the max
   *       constraint.
   *     * **pattern** [Boolean] &mdash; Validates that a string value matches a
   *       regular expression.
   *     * **enum** [Boolean] &mdash; Validates that a string value matches one
   *       of the allowable enum values.
   */ constructor: function ParamValidator(validation) {
        if (validation === true || validation === undefined) validation = {
            'min': true
        };
        this.validation = validation;
    },
    validate: function validate(shape, params, context) {
        this.errors = [];
        this.validateMember(shape, params || {}, context || 'params');
        if (this.errors.length > 1) {
            var msg = this.errors.join('\n* ');
            msg = 'There were ' + this.errors.length + ' validation errors:\n* ' + msg;
            throw $hIq4q.util.error(new Error(msg), {
                code: 'MultipleValidationErrors',
                errors: this.errors
            });
        } else if (this.errors.length === 1) throw this.errors[0];
        else return true;
    },
    fail: function fail(code, message) {
        this.errors.push($hIq4q.util.error(new Error(message), {
            code: code
        }));
    },
    validateStructure: function validateStructure(shape, params, context) {
        if (shape.isDocument) return true;
        this.validateType(params, context, [
            'object'
        ], 'structure');
        var paramName;
        for(var i = 0; shape.required && i < shape.required.length; i++){
            paramName = shape.required[i];
            var value = params[paramName];
            if (value === undefined || value === null) this.fail('MissingRequiredParameter', 'Missing required key \'' + paramName + '\' in ' + context);
        }
        // validate hash members
        for(paramName in params){
            if (!Object.prototype.hasOwnProperty.call(params, paramName)) continue;
            var paramValue = params[paramName], memberShape = shape.members[paramName];
            if (memberShape !== undefined) {
                var memberContext = [
                    context,
                    paramName
                ].join('.');
                this.validateMember(memberShape, paramValue, memberContext);
            } else if (paramValue !== undefined && paramValue !== null) this.fail('UnexpectedParameter', 'Unexpected key \'' + paramName + '\' found in ' + context);
        }
        return true;
    },
    validateMember: function validateMember(shape, param, context) {
        switch(shape.type){
            case 'structure':
                return this.validateStructure(shape, param, context);
            case 'list':
                return this.validateList(shape, param, context);
            case 'map':
                return this.validateMap(shape, param, context);
            default:
                return this.validateScalar(shape, param, context);
        }
    },
    validateList: function validateList(shape, params, context) {
        if (this.validateType(params, context, [
            Array
        ])) {
            this.validateRange(shape, params.length, context, 'list member count');
            // validate array members
            for(var i = 0; i < params.length; i++)this.validateMember(shape.member, params[i], context + '[' + i + ']');
        }
    },
    validateMap: function validateMap(shape, params, context) {
        if (this.validateType(params, context, [
            'object'
        ], 'map')) {
            // Build up a count of map members to validate range traits.
            var mapCount = 0;
            for(var param in params){
                if (!Object.prototype.hasOwnProperty.call(params, param)) continue;
                // Validate any map key trait constraints
                this.validateMember(shape.key, param, context + '[key=\'' + param + '\']');
                this.validateMember(shape.value, params[param], context + '[\'' + param + '\']');
                mapCount++;
            }
            this.validateRange(shape, mapCount, context, 'map member count');
        }
    },
    validateScalar: function validateScalar(shape, value, context) {
        switch(shape.type){
            case null:
            case undefined:
            case 'string':
                return this.validateString(shape, value, context);
            case 'base64':
            case 'binary':
                return this.validatePayload(value, context);
            case 'integer':
            case 'float':
                return this.validateNumber(shape, value, context);
            case 'boolean':
                return this.validateType(value, context, [
                    'boolean'
                ]);
            case 'timestamp':
                return this.validateType(value, context, [
                    Date,
                    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/,
                    'number'
                ], 'Date object, ISO-8601 string, or a UNIX timestamp');
            default:
                return this.fail('UnkownType', 'Unhandled type ' + shape.type + ' for ' + context);
        }
    },
    validateString: function validateString(shape, value, context) {
        var validTypes = [
            'string'
        ];
        if (shape.isJsonValue) validTypes = validTypes.concat([
            'number',
            'object',
            'boolean'
        ]);
        if (value !== null && this.validateType(value, context, validTypes)) {
            this.validateEnum(shape, value, context);
            this.validateRange(shape, value.length, context, 'string length');
            this.validatePattern(shape, value, context);
            this.validateUri(shape, value, context);
        }
    },
    validateUri: function validateUri(shape, value, context) {
        if (shape['location'] === 'uri') {
            if (value.length === 0) this.fail('UriParameterError', 'Expected uri parameter to have length >= 1, but found "' + value + '" for ' + context);
        }
    },
    validatePattern: function validatePattern(shape, value, context) {
        if (this.validation['pattern'] && shape['pattern'] !== undefined) {
            if (!new RegExp(shape['pattern']).test(value)) this.fail('PatternMatchError', 'Provided value "' + value + '" ' + 'does not match regex pattern /' + shape['pattern'] + '/ for ' + context);
        }
    },
    validateRange: function validateRange(shape, value, context, descriptor) {
        if (this.validation['min']) {
            if (shape['min'] !== undefined && value < shape['min']) this.fail('MinRangeError', 'Expected ' + descriptor + ' >= ' + shape['min'] + ', but found ' + value + ' for ' + context);
        }
        if (this.validation['max']) {
            if (shape['max'] !== undefined && value > shape['max']) this.fail('MaxRangeError', 'Expected ' + descriptor + ' <= ' + shape['max'] + ', but found ' + value + ' for ' + context);
        }
    },
    validateEnum: function validateRange(shape, value, context) {
        if (this.validation['enum'] && shape['enum'] !== undefined) // Fail if the string value is not present in the enum list
        {
            if (shape['enum'].indexOf(value) === -1) this.fail('EnumError', 'Found string value of ' + value + ', but ' + 'expected ' + shape['enum'].join('|') + ' for ' + context);
        }
    },
    validateType: function validateType(value, context, acceptedTypes, type) {
        // We will not log an error for null or undefined, but we will return
        // false so that callers know that the expected type was not strictly met.
        if (value === null || value === undefined) return false;
        var foundInvalidType = false;
        for(var i = 0; i < acceptedTypes.length; i++){
            if (typeof acceptedTypes[i] === 'string') {
                if (typeof value === acceptedTypes[i]) return true;
            } else if (acceptedTypes[i] instanceof RegExp) {
                if ((value || '').toString().match(acceptedTypes[i])) return true;
            } else {
                if (value instanceof acceptedTypes[i]) return true;
                if ($hIq4q.util.isType(value, acceptedTypes[i])) return true;
                if (!type && !foundInvalidType) acceptedTypes = acceptedTypes.slice();
                acceptedTypes[i] = $hIq4q.util.typeName(acceptedTypes[i]);
            }
            foundInvalidType = true;
        }
        var acceptedType = type;
        if (!acceptedType) acceptedType = acceptedTypes.join(', ').replace(/,([^,]+)$/, ', or$1');
        var vowel = acceptedType.match(/^[aeiou]/i) ? 'n' : '';
        this.fail('InvalidParameterType', 'Expected ' + context + ' to be a' + vowel + ' ' + acceptedType);
        return false;
    },
    validateNumber: function validateNumber(shape, value, context) {
        if (value === null || value === undefined) return;
        if (typeof value === 'string') {
            var castedValue = parseFloat(value);
            if (castedValue.toString() === value) value = castedValue;
        }
        if (this.validateType(value, context, [
            'number'
        ])) this.validateRange(shape, value, context, 'numeric value');
    },
    validatePayload: function validatePayload(value, context) {
        if (value === null || value === undefined) return;
        if (typeof value === 'string') return;
        if (value && typeof value.byteLength === 'number') return; // typed arrays
        if ($hIq4q.util.isNode()) {
            var Stream = $hIq4q.util.stream.Stream;
            if ($hIq4q.util.Buffer.isBuffer(value) || value instanceof Stream) return;
        } else {
            if (value instanceof Blob) return;
        }
        var types = [
            'Buffer',
            'Stream',
            'File',
            'Blob',
            'ArrayBuffer',
            'DataView'
        ];
        if (value) for(var i = 0; i < types.length; i++){
            if ($hIq4q.util.isType(value, types[i])) return;
            if ($hIq4q.util.typeName(value.constructor) === types[i]) return;
        }
        this.fail('InvalidParameterType', 'Expected ' + context + ' to be a ' + 'string, Buffer, Stream, Blob, or typed array object');
    }
});

});

parcelRegister("eOFpQ", function(module, exports) {
var $ac95dc865d1e4e11$var$warning = [
    'The AWS SDK for JavaScript (v2) has reached end-of-support.',
    'It will no longer receive updates or releases.\n',
    'Please migrate your code to use AWS SDK for JavaScript (v3).',
    'For more information, check the blog post at https://a.co/cUPnyil'
].join('\n');
module.exports = {
    suppress: false
};
/**
 * To suppress this message:
 * @example
 * require('aws-sdk/lib/maintenance_mode_message').suppress = true;
 */ function $ac95dc865d1e4e11$var$emitWarning() {
    if (typeof process === 'undefined') return;
    // Skip maintenance mode message in Lambda environments
    if (typeof process.env === 'object' && typeof process.env.AWS_EXECUTION_ENV !== 'undefined' && process.env.AWS_EXECUTION_ENV.indexOf('AWS_Lambda_') === 0) return;
    if (typeof process.env === 'object' && typeof process.env.AWS_SDK_JS_SUPPRESS_MAINTENANCE_MODE_MESSAGE !== 'undefined') return;
    if (typeof process.emitWarning === 'function') process.emitWarning($ac95dc865d1e4e11$var$warning, {
        type: 'NOTE'
    });
}
setTimeout(function() {
    if (!module.exports.suppress) $ac95dc865d1e4e11$var$emitWarning();
}, 0);

});


parcelRegister("9LCkR", function(module, exports) {

$parcel$export(module.exports, "default", () => $71c63d7d7fc36e9b$export$2e2bcd8739ae039);

var $aXeCi = parcelRequire("aXeCi");

var $3app9 = parcelRequire("3app9");
function $71c63d7d7fc36e9b$var$v4(options, buf, offset) {
    var i = buf && offset || 0;
    if (typeof options == 'string') {
        buf = options === 'binary' ? new Array(16) : null;
        options = null;
    }
    options = options || {};
    var rnds = options.random || (options.rng || (0, $aXeCi.default))(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
    rnds[6] = rnds[6] & 0x0f | 0x40;
    rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided
    if (buf) for(var ii = 0; ii < 16; ++ii)buf[i + ii] = rnds[ii];
    return buf || (0, $3app9.default)(rnds);
}
var $71c63d7d7fc36e9b$export$2e2bcd8739ae039 = $71c63d7d7fc36e9b$var$v4;

});
parcelRegister("aXeCi", function(module, exports) {

$parcel$export(module.exports, "default", () => $7f9ac0a392cb85c1$export$2e2bcd8739ae039);

function $7f9ac0a392cb85c1$export$2e2bcd8739ae039() {
    return (0, ($parcel$interopDefault($dDec7$crypto))).randomBytes(16);
}

});

parcelRegister("3app9", function(module, exports) {

$parcel$export(module.exports, "default", () => $24e6031cc9120e03$export$2e2bcd8739ae039);
/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */ var $24e6031cc9120e03$var$byteToHex = [];
for(var $24e6031cc9120e03$var$i = 0; $24e6031cc9120e03$var$i < 256; ++$24e6031cc9120e03$var$i)$24e6031cc9120e03$var$byteToHex[$24e6031cc9120e03$var$i] = ($24e6031cc9120e03$var$i + 0x100).toString(16).substr(1);
function $24e6031cc9120e03$var$bytesToUuid(buf, offset) {
    var i = offset || 0;
    var bth = $24e6031cc9120e03$var$byteToHex; // join used to fix memory issue caused by concatenation: https://bugs.chromium.org/p/v8/issues/detail?id=3175#c4
    return [
        bth[buf[i++]],
        bth[buf[i++]],
        bth[buf[i++]],
        bth[buf[i++]],
        '-',
        bth[buf[i++]],
        bth[buf[i++]],
        '-',
        bth[buf[i++]],
        bth[buf[i++]],
        '-',
        bth[buf[i++]],
        bth[buf[i++]],
        '-',
        bth[buf[i++]],
        bth[buf[i++]],
        bth[buf[i++]],
        bth[buf[i++]],
        bth[buf[i++]],
        bth[buf[i++]]
    ].join('');
}
var $24e6031cc9120e03$export$2e2bcd8739ae039 = $24e6031cc9120e03$var$bytesToUuid;

});



parcelRegister("kMo4M", function(module, exports) {
/**
 * What is necessary to create an event stream in node?
 *  - http response stream
 *  - parser
 *  - event stream model
 */ 
var $70JvZ = parcelRequire("70JvZ");
var $f20af7583cf5d9fe$require$EventMessageChunkerStream = $70JvZ.EventMessageChunkerStream;

var $hsnYL = parcelRequire("hsnYL");
var $f20af7583cf5d9fe$require$EventUnmarshallerStream = $hsnYL.EventUnmarshallerStream;
function $f20af7583cf5d9fe$var$createEventStream(stream, parser, model) {
    var eventStream = new $f20af7583cf5d9fe$require$EventUnmarshallerStream({
        parser: parser,
        eventStreamModel: model
    });
    var eventMessageChunker = new $f20af7583cf5d9fe$require$EventMessageChunkerStream();
    stream.pipe(eventMessageChunker).pipe(eventStream);
    stream.on('error', function(err) {
        eventMessageChunker.emit('error', err);
    });
    eventMessageChunker.on('error', function(err) {
        eventStream.emit('error', err);
    });
    return eventStream;
}
/**
 * @api private
 */ module.exports = {
    createEventStream: $f20af7583cf5d9fe$var$createEventStream
};

});
parcelRegister("70JvZ", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $51abd6ce88e83d44$require$util = $hIq4q.util;

var $51abd6ce88e83d44$require$Transform = $dDec7$stream.Transform;
var $51abd6ce88e83d44$var$allocBuffer = $51abd6ce88e83d44$require$util.buffer.alloc;
/** @type {Transform} */ function $51abd6ce88e83d44$var$EventMessageChunkerStream(options) {
    $51abd6ce88e83d44$require$Transform.call(this, options);
    this.currentMessageTotalLength = 0;
    this.currentMessagePendingLength = 0;
    /** @type {Buffer} */ this.currentMessage = null;
    /** @type {Buffer} */ this.messageLengthBuffer = null;
}
$51abd6ce88e83d44$var$EventMessageChunkerStream.prototype = Object.create($51abd6ce88e83d44$require$Transform.prototype);
/**
 *
 * @param {Buffer} chunk
 * @param {string} encoding
 * @param {*} callback
 */ $51abd6ce88e83d44$var$EventMessageChunkerStream.prototype._transform = function(chunk, encoding, callback) {
    var chunkLength = chunk.length;
    var currentOffset = 0;
    while(currentOffset < chunkLength){
        // create new message if necessary
        if (!this.currentMessage) {
            // working on a new message, determine total length
            var bytesRemaining = chunkLength - currentOffset;
            // prevent edge case where total length spans 2 chunks
            if (!this.messageLengthBuffer) this.messageLengthBuffer = $51abd6ce88e83d44$var$allocBuffer(4);
            var numBytesForTotal = Math.min(4 - this.currentMessagePendingLength, bytesRemaining // bytes left in chunk
            );
            chunk.copy(this.messageLengthBuffer, this.currentMessagePendingLength, currentOffset, currentOffset + numBytesForTotal);
            this.currentMessagePendingLength += numBytesForTotal;
            currentOffset += numBytesForTotal;
            if (this.currentMessagePendingLength < 4) break;
            this.allocateMessage(this.messageLengthBuffer.readUInt32BE(0));
            this.messageLengthBuffer = null;
        }
        // write data into current message
        var numBytesToWrite = Math.min(this.currentMessageTotalLength - this.currentMessagePendingLength, chunkLength - currentOffset // number of bytes left in the original chunk
        );
        chunk.copy(this.currentMessage, this.currentMessagePendingLength, currentOffset, currentOffset + numBytesToWrite // chunk end to write
        );
        this.currentMessagePendingLength += numBytesToWrite;
        currentOffset += numBytesToWrite;
        // check if a message is ready to be pushed
        if (this.currentMessageTotalLength && this.currentMessageTotalLength === this.currentMessagePendingLength) {
            // push out the message
            this.push(this.currentMessage);
            // cleanup
            this.currentMessage = null;
            this.currentMessageTotalLength = 0;
            this.currentMessagePendingLength = 0;
        }
    }
    callback();
};
$51abd6ce88e83d44$var$EventMessageChunkerStream.prototype._flush = function(callback) {
    if (this.currentMessageTotalLength) {
        if (this.currentMessageTotalLength === this.currentMessagePendingLength) callback(null, this.currentMessage);
        else callback(new Error('Truncated event message received.'));
    } else callback();
};
/**
 * @param {number} size Size of the message to be allocated.
 * @api private
 */ $51abd6ce88e83d44$var$EventMessageChunkerStream.prototype.allocateMessage = function(size) {
    if (typeof size !== 'number') throw new Error('Attempted to allocate an event message where size was not a number: ' + size);
    this.currentMessageTotalLength = size;
    this.currentMessagePendingLength = 4;
    this.currentMessage = $51abd6ce88e83d44$var$allocBuffer(size);
    this.currentMessage.writeUInt32BE(size, 0);
};
/**
 * @api private
 */ module.exports = {
    EventMessageChunkerStream: $51abd6ce88e83d44$var$EventMessageChunkerStream
};

});

parcelRegister("hsnYL", function(module, exports) {

var $cb57a6f55b3f5514$require$Transform = $dDec7$stream.Transform;

var $h0AJD = parcelRequire("h0AJD");
var $cb57a6f55b3f5514$require$parseEvent = $h0AJD.parseEvent;
/** @type {Transform} */ function $cb57a6f55b3f5514$var$EventUnmarshallerStream(options) {
    options = options || {};
    // set output to object mode
    options.readableObjectMode = true;
    $cb57a6f55b3f5514$require$Transform.call(this, options);
    this._readableState.objectMode = true;
    this.parser = options.parser;
    this.eventStreamModel = options.eventStreamModel;
}
$cb57a6f55b3f5514$var$EventUnmarshallerStream.prototype = Object.create($cb57a6f55b3f5514$require$Transform.prototype);
/**
 *
 * @param {Buffer} chunk
 * @param {string} encoding
 * @param {*} callback
 */ $cb57a6f55b3f5514$var$EventUnmarshallerStream.prototype._transform = function(chunk, encoding, callback) {
    try {
        var event = $cb57a6f55b3f5514$require$parseEvent(this.parser, chunk, this.eventStreamModel);
        this.push(event);
        return callback();
    } catch (err) {
        callback(err);
    }
};
/**
 * @api private
 */ module.exports = {
    EventUnmarshallerStream: $cb57a6f55b3f5514$var$EventUnmarshallerStream
};

});
parcelRegister("h0AJD", function(module, exports) {

var $53ldA = parcelRequire("53ldA");
var $c61eee8e0b6acec2$require$parseMessage = $53ldA.parseMessage;
/**
 *
 * @param {*} parser
 * @param {Buffer} message
 * @param {*} shape
 * @api private
 */ function $c61eee8e0b6acec2$var$parseEvent(parser, message, shape) {
    var parsedMessage = $c61eee8e0b6acec2$require$parseMessage(message);
    // check if message is an event or error
    var messageType = parsedMessage.headers[':message-type'];
    if (messageType) {
        if (messageType.value === 'error') throw $c61eee8e0b6acec2$var$parseError(parsedMessage);
        else if (messageType.value !== 'event') // not sure how to parse non-events/non-errors, ignore for now
        return;
    }
    // determine event type
    var eventType = parsedMessage.headers[':event-type'];
    // check that the event type is modeled
    var eventModel = shape.members[eventType.value];
    if (!eventModel) return;
    var result = {};
    // check if an event payload exists
    var eventPayloadMemberName = eventModel.eventPayloadMemberName;
    if (eventPayloadMemberName) {
        var payloadShape = eventModel.members[eventPayloadMemberName];
        // if the shape is binary, return the byte array
        if (payloadShape.type === 'binary') result[eventPayloadMemberName] = parsedMessage.body;
        else result[eventPayloadMemberName] = parser.parse(parsedMessage.body.toString(), payloadShape);
    }
    // read event headers
    var eventHeaderNames = eventModel.eventHeaderMemberNames;
    for(var i = 0; i < eventHeaderNames.length; i++){
        var name = eventHeaderNames[i];
        if (parsedMessage.headers[name]) // parse the header!
        result[name] = eventModel.members[name].toType(parsedMessage.headers[name].value);
    }
    var output = {};
    output[eventType.value] = result;
    return output;
}
function $c61eee8e0b6acec2$var$parseError(message) {
    var errorCode = message.headers[':error-code'];
    var errorMessage = message.headers[':error-message'];
    var error = new Error(errorMessage.value || errorMessage);
    error.code = error.name = errorCode.value || errorCode;
    return error;
}
/**
 * @api private
 */ module.exports = {
    parseEvent: $c61eee8e0b6acec2$var$parseEvent
};

});
parcelRegister("53ldA", function(module, exports) {

var $fDQ1e = parcelRequire("fDQ1e");
var $3addb10ed2f6f3f0$require$Int64 = $fDQ1e.Int64;

var $dAoRM = parcelRequire("dAoRM");
var $3addb10ed2f6f3f0$require$splitMessage = $dAoRM.splitMessage;
var $3addb10ed2f6f3f0$var$BOOLEAN_TAG = 'boolean';
var $3addb10ed2f6f3f0$var$BYTE_TAG = 'byte';
var $3addb10ed2f6f3f0$var$SHORT_TAG = 'short';
var $3addb10ed2f6f3f0$var$INT_TAG = 'integer';
var $3addb10ed2f6f3f0$var$LONG_TAG = 'long';
var $3addb10ed2f6f3f0$var$BINARY_TAG = 'binary';
var $3addb10ed2f6f3f0$var$STRING_TAG = 'string';
var $3addb10ed2f6f3f0$var$TIMESTAMP_TAG = 'timestamp';
var $3addb10ed2f6f3f0$var$UUID_TAG = 'uuid';
/**
 * @api private
 *
 * @param {Buffer} headers
 */ function $3addb10ed2f6f3f0$var$parseHeaders(headers) {
    var out = {};
    var position = 0;
    while(position < headers.length){
        var nameLength = headers.readUInt8(position++);
        var name = headers.slice(position, position + nameLength).toString();
        position += nameLength;
        switch(headers.readUInt8(position++)){
            case 0 /* boolTrue */ :
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$BOOLEAN_TAG,
                    value: true
                };
                break;
            case 1 /* boolFalse */ :
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$BOOLEAN_TAG,
                    value: false
                };
                break;
            case 2 /* byte */ :
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$BYTE_TAG,
                    value: headers.readInt8(position++)
                };
                break;
            case 3 /* short */ :
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$SHORT_TAG,
                    value: headers.readInt16BE(position)
                };
                position += 2;
                break;
            case 4 /* integer */ :
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$INT_TAG,
                    value: headers.readInt32BE(position)
                };
                position += 4;
                break;
            case 5 /* long */ :
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$LONG_TAG,
                    value: new $3addb10ed2f6f3f0$require$Int64(headers.slice(position, position + 8))
                };
                position += 8;
                break;
            case 6 /* byteArray */ :
                var binaryLength = headers.readUInt16BE(position);
                position += 2;
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$BINARY_TAG,
                    value: headers.slice(position, position + binaryLength)
                };
                position += binaryLength;
                break;
            case 7 /* string */ :
                var stringLength = headers.readUInt16BE(position);
                position += 2;
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$STRING_TAG,
                    value: headers.slice(position, position + stringLength).toString()
                };
                position += stringLength;
                break;
            case 8 /* timestamp */ :
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$TIMESTAMP_TAG,
                    value: new Date(new $3addb10ed2f6f3f0$require$Int64(headers.slice(position, position + 8)).valueOf())
                };
                position += 8;
                break;
            case 9 /* uuid */ :
                var uuidChars = headers.slice(position, position + 16).toString('hex');
                position += 16;
                out[name] = {
                    type: $3addb10ed2f6f3f0$var$UUID_TAG,
                    value: uuidChars.substr(0, 8) + '-' + uuidChars.substr(8, 4) + '-' + uuidChars.substr(12, 4) + '-' + uuidChars.substr(16, 4) + '-' + uuidChars.substr(20)
                };
                break;
            default:
                throw new Error('Unrecognized header type tag');
        }
    }
    return out;
}
function $3addb10ed2f6f3f0$var$parseMessage(message) {
    var parsed = $3addb10ed2f6f3f0$require$splitMessage(message);
    return {
        headers: $3addb10ed2f6f3f0$var$parseHeaders(parsed.headers),
        body: parsed.body
    };
}
/**
 * @api private
 */ module.exports = {
    parseMessage: $3addb10ed2f6f3f0$var$parseMessage
};

});
parcelRegister("fDQ1e", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $b632d966bd1a604d$require$util = $hIq4q.util;
var $b632d966bd1a604d$var$toBuffer = $b632d966bd1a604d$require$util.buffer.toBuffer;
/**
 * A lossless representation of a signed, 64-bit integer. Instances of this
 * class may be used in arithmetic expressions as if they were numeric
 * primitives, but the binary representation will be preserved unchanged as the
 * `bytes` property of the object. The bytes should be encoded as big-endian,
 * two's complement integers.
 * @param {Buffer} bytes
 *
 * @api private
 */ function $b632d966bd1a604d$var$Int64(bytes) {
    if (bytes.length !== 8) throw new Error('Int64 buffers must be exactly 8 bytes');
    if (!$b632d966bd1a604d$require$util.Buffer.isBuffer(bytes)) bytes = $b632d966bd1a604d$var$toBuffer(bytes);
    this.bytes = bytes;
}
/**
 * @param {number} number
 * @returns {Int64}
 *
 * @api private
 */ $b632d966bd1a604d$var$Int64.fromNumber = function(number) {
    if (number > 9223372036854775807 || number < -9223372036854776000) throw new Error(number + ' is too large (or, if negative, too small) to represent as an Int64');
    var bytes = new Uint8Array(8);
    for(var i = 7, remaining = Math.abs(Math.round(number)); i > -1 && remaining > 0; i--, remaining /= 256)bytes[i] = remaining;
    if (number < 0) $b632d966bd1a604d$var$negate(bytes);
    return new $b632d966bd1a604d$var$Int64(bytes);
};
/**
 * @returns {number}
 *
 * @api private
 */ $b632d966bd1a604d$var$Int64.prototype.valueOf = function() {
    var bytes = this.bytes.slice(0);
    var negative = bytes[0] & 128;
    if (negative) $b632d966bd1a604d$var$negate(bytes);
    return parseInt(bytes.toString('hex'), 16) * (negative ? -1 : 1);
};
$b632d966bd1a604d$var$Int64.prototype.toString = function() {
    return String(this.valueOf());
};
/**
 * @param {Buffer} bytes
 *
 * @api private
 */ function $b632d966bd1a604d$var$negate(bytes) {
    for(var i = 0; i < 8; i++)bytes[i] ^= 0xFF;
    for(var i = 7; i > -1; i--){
        bytes[i]++;
        if (bytes[i] !== 0) break;
    }
}
/**
 * @api private
 */ module.exports = {
    Int64: $b632d966bd1a604d$var$Int64
};

});

parcelRegister("dAoRM", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $9e41ed1a45feb666$require$util = $hIq4q.util;
var $9e41ed1a45feb666$var$toBuffer = $9e41ed1a45feb666$require$util.buffer.toBuffer;
// All prelude components are unsigned, 32-bit integers
var $9e41ed1a45feb666$var$PRELUDE_MEMBER_LENGTH = 4;
// The prelude consists of two components
var $9e41ed1a45feb666$var$PRELUDE_LENGTH = $9e41ed1a45feb666$var$PRELUDE_MEMBER_LENGTH * 2;
// Checksums are always CRC32 hashes.
var $9e41ed1a45feb666$var$CHECKSUM_LENGTH = 4;
// Messages must include a full prelude, a prelude checksum, and a message checksum
var $9e41ed1a45feb666$var$MINIMUM_MESSAGE_LENGTH = $9e41ed1a45feb666$var$PRELUDE_LENGTH + $9e41ed1a45feb666$var$CHECKSUM_LENGTH * 2;
/**
 * @api private
 *
 * @param {Buffer} message
 */ function $9e41ed1a45feb666$var$splitMessage(message) {
    if (!$9e41ed1a45feb666$require$util.Buffer.isBuffer(message)) message = $9e41ed1a45feb666$var$toBuffer(message);
    if (message.length < $9e41ed1a45feb666$var$MINIMUM_MESSAGE_LENGTH) throw new Error('Provided message too short to accommodate event stream message overhead');
    if (message.length !== message.readUInt32BE(0)) throw new Error('Reported message length does not match received message length');
    var expectedPreludeChecksum = message.readUInt32BE($9e41ed1a45feb666$var$PRELUDE_LENGTH);
    if (expectedPreludeChecksum !== $9e41ed1a45feb666$require$util.crypto.crc32(message.slice(0, $9e41ed1a45feb666$var$PRELUDE_LENGTH))) throw new Error('The prelude checksum specified in the message (' + expectedPreludeChecksum + ') does not match the calculated CRC32 checksum.');
    var expectedMessageChecksum = message.readUInt32BE(message.length - $9e41ed1a45feb666$var$CHECKSUM_LENGTH);
    if (expectedMessageChecksum !== $9e41ed1a45feb666$require$util.crypto.crc32(message.slice(0, message.length - $9e41ed1a45feb666$var$CHECKSUM_LENGTH))) throw new Error('The message checksum did not match the expected value of ' + expectedMessageChecksum);
    var headersStart = $9e41ed1a45feb666$var$PRELUDE_LENGTH + $9e41ed1a45feb666$var$CHECKSUM_LENGTH;
    var headersEnd = headersStart + message.readUInt32BE($9e41ed1a45feb666$var$PRELUDE_MEMBER_LENGTH);
    return {
        headers: message.slice(headersStart, headersEnd),
        body: message.slice(headersEnd, message.length - $9e41ed1a45feb666$var$CHECKSUM_LENGTH)
    };
}
/**
 * @api private
 */ module.exports = {
    splitMessage: $9e41ed1a45feb666$var$splitMessage
};

});





parcelRegister("ebSwa", function(module, exports) {

var $3VQil = parcelRequire("3VQil");
var $a54c61e5827caf31$require$eventMessageChunker = $3VQil.eventMessageChunker;

var $h0AJD = parcelRequire("h0AJD");
var $a54c61e5827caf31$require$parseEvent = $h0AJD.parseEvent;
function $a54c61e5827caf31$var$createEventStream(body, parser, model) {
    var eventMessages = $a54c61e5827caf31$require$eventMessageChunker(body);
    var events = [];
    for(var i = 0; i < eventMessages.length; i++)events.push($a54c61e5827caf31$require$parseEvent(parser, eventMessages[i], model));
    return events;
}
/**
 * @api private
 */ module.exports = {
    createEventStream: $a54c61e5827caf31$var$createEventStream
};

});
parcelRegister("3VQil", function(module, exports) {
/**
 * Takes in a buffer of event messages and splits them into individual messages.
 * @param {Buffer} buffer
 * @api private
 */ function $2dcf42a027c9e07d$var$eventMessageChunker(buffer) {
    /** @type Buffer[] */ var messages = [];
    var offset = 0;
    while(offset < buffer.length){
        var totalLength = buffer.readInt32BE(offset);
        // create new buffer for individual message (shares memory with original)
        var message = buffer.slice(offset, totalLength + offset);
        // increment offset to it starts at the next message
        offset += totalLength;
        messages.push(message);
    }
    return messages;
}
/**
 * @api private
 */ module.exports = {
    eventMessageChunker: $2dcf42a027c9e07d$var$eventMessageChunker
};

});


parcelRegister("gQ4NQ", function(module, exports) {
module.exports = {
    //provide realtime clock for performance measurement
    now: function now() {
        var second = process.hrtime();
        return second[0] * 1000 + second[1] / 1000000;
    }
};

});

parcelRegister("gm9Dn", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $be862c8820f6dd63$require$util = $hIq4q.util;

var $be862c8820f6dd63$var$stringToBuffer = $be862c8820f6dd63$require$util.buffer.toBuffer;
var $be862c8820f6dd63$var$MAX_MESSAGE_SIZE = 8192; // 8 KB
/**
 * Publishes metrics via udp.
 * @param {object} options Paramters for Publisher constructor
 * @param {number} [options.port = 31000] Port number
 * @param {string} [options.clientId = ''] Client Identifier
 * @param {boolean} [options.enabled = false] enable sending metrics datagram
 * @api private
 */ function $be862c8820f6dd63$var$Publisher(options) {
    // handle configuration
    options = options || {};
    this.enabled = options.enabled || false;
    this.port = options.port || 31000;
    this.clientId = options.clientId || '';
    this.address = options.host || '127.0.0.1';
    if (this.clientId.length > 255) // ClientId has a max length of 255
    this.clientId = this.clientId.substr(0, 255);
    this.messagesInFlight = 0;
}
$be862c8820f6dd63$var$Publisher.prototype.fieldsToTrim = {
    UserAgent: 256,
    SdkException: 128,
    SdkExceptionMessage: 512,
    AwsException: 128,
    AwsExceptionMessage: 512,
    FinalSdkException: 128,
    FinalSdkExceptionMessage: 512,
    FinalAwsException: 128,
    FinalAwsExceptionMessage: 512
};
/**
 * Trims fields that have a specified max length.
 * @param {object} event ApiCall or ApiCallAttempt event.
 * @returns {object}
 * @api private
 */ $be862c8820f6dd63$var$Publisher.prototype.trimFields = function(event) {
    var trimmableFields = Object.keys(this.fieldsToTrim);
    for(var i = 0, iLen = trimmableFields.length; i < iLen; i++){
        var field = trimmableFields[i];
        if (event.hasOwnProperty(field)) {
            var maxLength = this.fieldsToTrim[field];
            var value = event[field];
            if (value && value.length > maxLength) event[field] = value.substr(0, maxLength);
        }
    }
    return event;
};
/**
 * Handles ApiCall and ApiCallAttempt events.
 * @param {Object} event apiCall or apiCallAttempt event.
 * @api private
 */ $be862c8820f6dd63$var$Publisher.prototype.eventHandler = function(event) {
    // set the clientId
    event.ClientId = this.clientId;
    this.trimFields(event);
    var message = $be862c8820f6dd63$var$stringToBuffer(JSON.stringify(event));
    if (!this.enabled || message.length > $be862c8820f6dd63$var$MAX_MESSAGE_SIZE) // drop the message if publisher not enabled or it is too large
    return;
    this.publishDatagram(message);
};
/**
 * Publishes message to an agent.
 * @param {Buffer} message JSON message to send to agent.
 * @api private
 */ $be862c8820f6dd63$var$Publisher.prototype.publishDatagram = function(message) {
    var self = this;
    var client = this.getClient();
    this.messagesInFlight++;
    this.client.send(message, 0, message.length, this.port, this.address, function(err, bytes) {
        if (--self.messagesInFlight <= 0) // destroy existing client so the event loop isn't kept open
        self.destroyClient();
    });
};
/**
 * Returns an existing udp socket, or creates one if it doesn't already exist.
 * @api private
 */ $be862c8820f6dd63$var$Publisher.prototype.getClient = function() {
    if (!this.client) this.client = $dDec7$dgram.createSocket('udp4');
    return this.client;
};
/**
 * Destroys the udp socket.
 * @api private
 */ $be862c8820f6dd63$var$Publisher.prototype.destroyClient = function() {
    if (this.client) {
        this.client.close();
        this.client = void 0;
    }
};
module.exports = {
    Publisher: $be862c8820f6dd63$var$Publisher
};

});

parcelRegister("aaTMB", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
/**
 * Resolve client-side monitoring configuration from either environmental variables
 * or shared config file. Configurations from environmental variables have higher priority
 * than those from shared config file. The resolver will try to read the shared config file
 * no matter whether the AWS_SDK_LOAD_CONFIG variable is set.
 * @api private
 */ function $76861be1f1d06c82$var$resolveMonitoringConfig() {
    var config = {
        port: undefined,
        clientId: undefined,
        enabled: undefined,
        host: undefined
    };
    if ($76861be1f1d06c82$var$fromEnvironment(config) || $76861be1f1d06c82$var$fromConfigFile(config)) return $76861be1f1d06c82$var$toJSType(config);
    return $76861be1f1d06c82$var$toJSType(config);
}
/**
 * Resolve configurations from environmental variables.
 * @param {object} client side monitoring config object needs to be resolved
 * @returns {boolean} whether resolving configurations is done
 * @api private
 */ function $76861be1f1d06c82$var$fromEnvironment(config) {
    config.port = config.port || process.env.AWS_CSM_PORT;
    config.enabled = config.enabled || process.env.AWS_CSM_ENABLED;
    config.clientId = config.clientId || process.env.AWS_CSM_CLIENT_ID;
    config.host = config.host || process.env.AWS_CSM_HOST;
    return config.port && config.enabled && config.clientId && config.host || [
        'false',
        '0'
    ].indexOf(config.enabled) >= 0; //no need to read shared config file if explicitely disabled
}
/**
 * Resolve cofigurations from shared config file with specified role name
 * @param {object} client side monitoring config object needs to be resolved
 * @returns {boolean} whether resolving configurations is done
 * @api private
 */ function $76861be1f1d06c82$var$fromConfigFile(config) {
    var sharedFileConfig;
    try {
        var configFile = $hIq4q.util.iniLoader.loadFrom({
            isConfig: true,
            filename: process.env[$hIq4q.util.sharedConfigFileEnv]
        });
        var sharedFileConfig = configFile[process.env.AWS_PROFILE || $hIq4q.util.defaultProfile];
    } catch (err) {
        return false;
    }
    if (!sharedFileConfig) return config;
    config.port = config.port || sharedFileConfig.csm_port;
    config.enabled = config.enabled || sharedFileConfig.csm_enabled;
    config.clientId = config.clientId || sharedFileConfig.csm_client_id;
    config.host = config.host || sharedFileConfig.csm_host;
    return config.port && config.enabled && config.clientId && config.host;
}
/**
 * Transfer the resolved configuration value to proper types: port as number, enabled
 * as boolean and clientId as string. The 'enabled' flag is valued to false when set
 * to 'false' or '0'.
 * @param {object} resolved client side monitoring config
 * @api private
 */ function $76861be1f1d06c82$var$toJSType(config) {
    //config.XXX is either undefined or string
    var falsyNotations = [
        'false',
        '0',
        undefined
    ];
    if (!config.enabled || falsyNotations.indexOf(config.enabled.toLowerCase()) >= 0) config.enabled = false;
    else config.enabled = true;
    config.port = config.port ? parseInt(config.port, 10) : undefined;
    return config;
}
module.exports = $76861be1f1d06c82$var$resolveMonitoringConfig;

});

parcelRegister("8AIqz", function(module, exports) {

$parcel$export(module.exports, "iniLoader", () => $641425e294b63fdd$export$4f430c92d556fecd, (v) => $641425e294b63fdd$export$4f430c92d556fecd = v);
/**
 * Singleton object to load specified config/credentials files.
 * It will cache all the files ever loaded;
 */ var $641425e294b63fdd$export$4f430c92d556fecd;

var $tereM = parcelRequire("tereM");
var $641425e294b63fdd$require$IniLoader = $tereM.IniLoader;
$641425e294b63fdd$export$4f430c92d556fecd = new $641425e294b63fdd$require$IniLoader();

});
parcelRegister("tereM", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");


function $057de8b23274821d$var$parseFile(filename) {
    return $hIq4q.util.ini.parse($hIq4q.util.readFileSync(filename));
}
function $057de8b23274821d$var$getProfiles(fileContent) {
    var tmpContent = {};
    Object.keys(fileContent).forEach(function(sectionName) {
        if (/^sso-session\s/.test(sectionName)) return;
        Object.defineProperty(tmpContent, sectionName.replace(/^profile\s/, ''), {
            value: fileContent[sectionName],
            enumerable: true
        });
    });
    return tmpContent;
}
function $057de8b23274821d$var$getSsoSessions(fileContent) {
    var tmpContent = {};
    Object.keys(fileContent).forEach(function(sectionName) {
        if (!/^sso-session\s/.test(sectionName)) return;
        Object.defineProperty(tmpContent, sectionName.replace(/^sso-session\s/, ''), {
            value: fileContent[sectionName],
            enumerable: true
        });
    });
    return tmpContent;
}
/**
 * Ini file loader class the same as that used in the SDK. It loads and
 * parses config and credentials files in .ini format and cache the content
 * to assure files are only read once.
 * Note that calling operations on the instance instantiated from this class
 * won't affect the behavior of SDK since SDK uses an internal singleton of
 * this class.
 * @!macro nobrowser
 */ $hIq4q.IniLoader = $hIq4q.util.inherit({
    constructor: function IniLoader() {
        this.resolvedProfiles = {};
        this.resolvedSsoSessions = {};
    },
    /** Remove all cached files. Used after config files are updated. */ clearCachedFiles: function clearCachedFiles() {
        this.resolvedProfiles = {};
        this.resolvedSsoSessions = {};
    },
    /**
   * Load configurations from config/credentials files and cache them
   * for later use. If no file is specified it will try to load default files.
   *
   * @param options [map] information describing the file
   * @option options filename [String] ('~/.aws/credentials' or defined by
   *   AWS_SHARED_CREDENTIALS_FILE process env var or '~/.aws/config' if
   *   isConfig is set to true)
   *   path to the file to be read.
   * @option options isConfig [Boolean] (false) True to read config file.
   * @return [map<String,String>] object containing contents from file in key-value
   *   pairs.
   */ loadFrom: function loadFrom(options) {
        options = options || {};
        var isConfig = options.isConfig === true;
        var filename = options.filename || this.getDefaultFilePath(isConfig);
        if (!this.resolvedProfiles[filename]) {
            var fileContent = $057de8b23274821d$var$parseFile(filename);
            if (isConfig) Object.defineProperty(this.resolvedProfiles, filename, {
                value: $057de8b23274821d$var$getProfiles(fileContent)
            });
            else Object.defineProperty(this.resolvedProfiles, filename, {
                value: fileContent
            });
        }
        return this.resolvedProfiles[filename];
    },
    /**
   * Load sso sessions from config/credentials files and cache them
   * for later use. If no file is specified it will try to load default file.
   *
   * @param options [map] information describing the file
   * @option options filename [String] ('~/.aws/config' or defined by
   *   AWS_CONFIG_FILE process env var)
   * @return [map<String,String>] object containing contents from file in key-value
   *   pairs.
   */ loadSsoSessionsFrom: function loadSsoSessionsFrom(options) {
        options = options || {};
        var filename = options.filename || this.getDefaultFilePath(true);
        if (!this.resolvedSsoSessions[filename]) {
            var fileContent = $057de8b23274821d$var$parseFile(filename);
            Object.defineProperty(this.resolvedSsoSessions, filename, {
                value: $057de8b23274821d$var$getSsoSessions(fileContent)
            });
        }
        return this.resolvedSsoSessions[filename];
    },
    getDefaultFilePath: function getDefaultFilePath(isConfig) {
        return $dDec7$path.join(this.getHomeDir(), '.aws', isConfig ? 'config' : 'credentials');
    },
    getHomeDir: function getHomeDir() {
        var env = process.env;
        var home = env.HOME || env.USERPROFILE || (env.HOMEPATH ? (env.HOMEDRIVE || 'C:/') + env.HOMEPATH : null);
        if (home) return home;
        if (typeof $dDec7$os.homedir === 'function') return $dDec7$os.homedir();
        throw $hIq4q.util.error(new Error('Cannot load credentials, HOME path not set'));
    }
});
var $057de8b23274821d$var$IniLoader = $hIq4q.IniLoader;
module.exports = {
    IniLoader: $057de8b23274821d$var$IniLoader
};

});


parcelRegister("lJDR7", function(module, exports) {
module.exports = JSON.parse("{\"version\":\"2.0\",\"metadata\":{\"apiVersion\":\"2014-06-30\",\"endpointPrefix\":\"cognito-identity\",\"jsonVersion\":\"1.1\",\"protocol\":\"json\",\"protocols\":[\"json\"],\"serviceFullName\":\"Amazon Cognito Identity\",\"serviceId\":\"Cognito Identity\",\"signatureVersion\":\"v4\",\"targetPrefix\":\"AWSCognitoIdentityService\",\"uid\":\"cognito-identity-2014-06-30\",\"auth\":[\"aws.auth#sigv4\"]},\"operations\":{\"CreateIdentityPool\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolName\",\"AllowUnauthenticatedIdentities\"],\"members\":{\"IdentityPoolName\":{},\"AllowUnauthenticatedIdentities\":{\"type\":\"boolean\"},\"AllowClassicFlow\":{\"type\":\"boolean\"},\"SupportedLoginProviders\":{\"shape\":\"S5\"},\"DeveloperProviderName\":{},\"OpenIdConnectProviderARNs\":{\"shape\":\"S9\"},\"CognitoIdentityProviders\":{\"shape\":\"Sb\"},\"SamlProviderARNs\":{\"shape\":\"Sg\"},\"IdentityPoolTags\":{\"shape\":\"Sh\"}}},\"output\":{\"shape\":\"Sk\"}},\"DeleteIdentities\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityIdsToDelete\"],\"members\":{\"IdentityIdsToDelete\":{\"type\":\"list\",\"member\":{}}}},\"output\":{\"type\":\"structure\",\"members\":{\"UnprocessedIdentityIds\":{\"type\":\"list\",\"member\":{\"type\":\"structure\",\"members\":{\"IdentityId\":{},\"ErrorCode\":{}}}}}}},\"DeleteIdentityPool\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\"],\"members\":{\"IdentityPoolId\":{}}}},\"DescribeIdentity\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityId\"],\"members\":{\"IdentityId\":{}}},\"output\":{\"shape\":\"Sv\"}},\"DescribeIdentityPool\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\"],\"members\":{\"IdentityPoolId\":{}}},\"output\":{\"shape\":\"Sk\"}},\"GetCredentialsForIdentity\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityId\"],\"members\":{\"IdentityId\":{},\"Logins\":{\"shape\":\"S10\"},\"CustomRoleArn\":{}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityId\":{},\"Credentials\":{\"type\":\"structure\",\"members\":{\"AccessKeyId\":{},\"SecretKey\":{},\"SessionToken\":{},\"Expiration\":{\"type\":\"timestamp\"}}}}},\"authtype\":\"none\",\"auth\":[\"smithy.api#noAuth\"]},\"GetId\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\"],\"members\":{\"AccountId\":{},\"IdentityPoolId\":{},\"Logins\":{\"shape\":\"S10\"}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityId\":{}}},\"authtype\":\"none\",\"auth\":[\"smithy.api#noAuth\"]},\"GetIdentityPoolRoles\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\"],\"members\":{\"IdentityPoolId\":{}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityPoolId\":{},\"Roles\":{\"shape\":\"S1c\"},\"RoleMappings\":{\"shape\":\"S1e\"}}}},\"GetOpenIdToken\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityId\"],\"members\":{\"IdentityId\":{},\"Logins\":{\"shape\":\"S10\"}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityId\":{},\"Token\":{}}},\"authtype\":\"none\",\"auth\":[\"smithy.api#noAuth\"]},\"GetOpenIdTokenForDeveloperIdentity\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\",\"Logins\"],\"members\":{\"IdentityPoolId\":{},\"IdentityId\":{},\"Logins\":{\"shape\":\"S10\"},\"PrincipalTags\":{\"shape\":\"S1s\"},\"TokenDuration\":{\"type\":\"long\"}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityId\":{},\"Token\":{}}}},\"GetPrincipalTagAttributeMap\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\",\"IdentityProviderName\"],\"members\":{\"IdentityPoolId\":{},\"IdentityProviderName\":{}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityPoolId\":{},\"IdentityProviderName\":{},\"UseDefaults\":{\"type\":\"boolean\"},\"PrincipalTags\":{\"shape\":\"S1s\"}}}},\"ListIdentities\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\",\"MaxResults\"],\"members\":{\"IdentityPoolId\":{},\"MaxResults\":{\"type\":\"integer\"},\"NextToken\":{},\"HideDisabled\":{\"type\":\"boolean\"}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityPoolId\":{},\"Identities\":{\"type\":\"list\",\"member\":{\"shape\":\"Sv\"}},\"NextToken\":{}}}},\"ListIdentityPools\":{\"input\":{\"type\":\"structure\",\"required\":[\"MaxResults\"],\"members\":{\"MaxResults\":{\"type\":\"integer\"},\"NextToken\":{}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityPools\":{\"type\":\"list\",\"member\":{\"type\":\"structure\",\"members\":{\"IdentityPoolId\":{},\"IdentityPoolName\":{}}}},\"NextToken\":{}}}},\"ListTagsForResource\":{\"input\":{\"type\":\"structure\",\"required\":[\"ResourceArn\"],\"members\":{\"ResourceArn\":{}}},\"output\":{\"type\":\"structure\",\"members\":{\"Tags\":{\"shape\":\"Sh\"}}}},\"LookupDeveloperIdentity\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\"],\"members\":{\"IdentityPoolId\":{},\"IdentityId\":{},\"DeveloperUserIdentifier\":{},\"MaxResults\":{\"type\":\"integer\"},\"NextToken\":{}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityId\":{},\"DeveloperUserIdentifierList\":{\"type\":\"list\",\"member\":{}},\"NextToken\":{}}}},\"MergeDeveloperIdentities\":{\"input\":{\"type\":\"structure\",\"required\":[\"SourceUserIdentifier\",\"DestinationUserIdentifier\",\"DeveloperProviderName\",\"IdentityPoolId\"],\"members\":{\"SourceUserIdentifier\":{},\"DestinationUserIdentifier\":{},\"DeveloperProviderName\":{},\"IdentityPoolId\":{}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityId\":{}}}},\"SetIdentityPoolRoles\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\",\"Roles\"],\"members\":{\"IdentityPoolId\":{},\"Roles\":{\"shape\":\"S1c\"},\"RoleMappings\":{\"shape\":\"S1e\"}}}},\"SetPrincipalTagAttributeMap\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\",\"IdentityProviderName\"],\"members\":{\"IdentityPoolId\":{},\"IdentityProviderName\":{},\"UseDefaults\":{\"type\":\"boolean\"},\"PrincipalTags\":{\"shape\":\"S1s\"}}},\"output\":{\"type\":\"structure\",\"members\":{\"IdentityPoolId\":{},\"IdentityProviderName\":{},\"UseDefaults\":{\"type\":\"boolean\"},\"PrincipalTags\":{\"shape\":\"S1s\"}}}},\"TagResource\":{\"input\":{\"type\":\"structure\",\"required\":[\"ResourceArn\",\"Tags\"],\"members\":{\"ResourceArn\":{},\"Tags\":{\"shape\":\"Sh\"}}},\"output\":{\"type\":\"structure\",\"members\":{}}},\"UnlinkDeveloperIdentity\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityId\",\"IdentityPoolId\",\"DeveloperProviderName\",\"DeveloperUserIdentifier\"],\"members\":{\"IdentityId\":{},\"IdentityPoolId\":{},\"DeveloperProviderName\":{},\"DeveloperUserIdentifier\":{}}}},\"UnlinkIdentity\":{\"input\":{\"type\":\"structure\",\"required\":[\"IdentityId\",\"Logins\",\"LoginsToRemove\"],\"members\":{\"IdentityId\":{},\"Logins\":{\"shape\":\"S10\"},\"LoginsToRemove\":{\"shape\":\"Sw\"}}},\"authtype\":\"none\",\"auth\":[\"smithy.api#noAuth\"]},\"UntagResource\":{\"input\":{\"type\":\"structure\",\"required\":[\"ResourceArn\",\"TagKeys\"],\"members\":{\"ResourceArn\":{},\"TagKeys\":{\"type\":\"list\",\"member\":{}}}},\"output\":{\"type\":\"structure\",\"members\":{}}},\"UpdateIdentityPool\":{\"input\":{\"shape\":\"Sk\"},\"output\":{\"shape\":\"Sk\"}}},\"shapes\":{\"S5\":{\"type\":\"map\",\"key\":{},\"value\":{}},\"S9\":{\"type\":\"list\",\"member\":{}},\"Sb\":{\"type\":\"list\",\"member\":{\"type\":\"structure\",\"members\":{\"ProviderName\":{},\"ClientId\":{},\"ServerSideTokenCheck\":{\"type\":\"boolean\"}}}},\"Sg\":{\"type\":\"list\",\"member\":{}},\"Sh\":{\"type\":\"map\",\"key\":{},\"value\":{}},\"Sk\":{\"type\":\"structure\",\"required\":[\"IdentityPoolId\",\"IdentityPoolName\",\"AllowUnauthenticatedIdentities\"],\"members\":{\"IdentityPoolId\":{},\"IdentityPoolName\":{},\"AllowUnauthenticatedIdentities\":{\"type\":\"boolean\"},\"AllowClassicFlow\":{\"type\":\"boolean\"},\"SupportedLoginProviders\":{\"shape\":\"S5\"},\"DeveloperProviderName\":{},\"OpenIdConnectProviderARNs\":{\"shape\":\"S9\"},\"CognitoIdentityProviders\":{\"shape\":\"Sb\"},\"SamlProviderARNs\":{\"shape\":\"Sg\"},\"IdentityPoolTags\":{\"shape\":\"Sh\"}}},\"Sv\":{\"type\":\"structure\",\"members\":{\"IdentityId\":{},\"Logins\":{\"shape\":\"Sw\"},\"CreationDate\":{\"type\":\"timestamp\"},\"LastModifiedDate\":{\"type\":\"timestamp\"}}},\"Sw\":{\"type\":\"list\",\"member\":{}},\"S10\":{\"type\":\"map\",\"key\":{},\"value\":{}},\"S1c\":{\"type\":\"map\",\"key\":{},\"value\":{}},\"S1e\":{\"type\":\"map\",\"key\":{},\"value\":{\"type\":\"structure\",\"required\":[\"Type\"],\"members\":{\"Type\":{},\"AmbiguousRoleResolution\":{},\"RulesConfiguration\":{\"type\":\"structure\",\"required\":[\"Rules\"],\"members\":{\"Rules\":{\"type\":\"list\",\"member\":{\"type\":\"structure\",\"required\":[\"Claim\",\"MatchType\",\"Value\",\"RoleARN\"],\"members\":{\"Claim\":{},\"MatchType\":{},\"Value\":{},\"RoleARN\":{}}}}}}}}},\"S1s\":{\"type\":\"map\",\"key\":{},\"value\":{}}}}");

});

parcelRegister("7lW7A", function(module, exports) {
module.exports = JSON.parse("{\"pagination\":{\"ListIdentityPools\":{\"input_token\":\"NextToken\",\"limit_key\":\"MaxResults\",\"output_token\":\"NextToken\",\"result_key\":\"IdentityPools\"}}}");

});

parcelRegister("atSp4", function(module, exports) {

var $hIq4q = parcelRequire("hIq4q");
var $7a16d02d81a5bc8f$var$util = $hIq4q.util;
var $7a16d02d81a5bc8f$var$Shape = $hIq4q.Model.Shape;

var $gowGR = parcelRequire("gowGR");
/**
 * @api private
 */ var $7a16d02d81a5bc8f$var$options = {
    explicitCharkey: false,
    trim: false,
    normalize: false,
    explicitRoot: false,
    emptyTag: null,
    explicitArray: true,
    ignoreAttrs: false,
    mergeAttrs: false,
    validator: null // a callable validator
};
function $7a16d02d81a5bc8f$var$NodeXmlParser() {}
$7a16d02d81a5bc8f$var$NodeXmlParser.prototype.parse = function(xml, shape) {
    shape = shape || {};
    var result = null;
    var error = null;
    var parser = new $gowGR.Parser($7a16d02d81a5bc8f$var$options);
    parser.parseString(xml, function(e, r) {
        error = e;
        result = r;
    });
    if (result) {
        var data = $7a16d02d81a5bc8f$var$parseXml(result, shape);
        if (result.ResponseMetadata) data.ResponseMetadata = $7a16d02d81a5bc8f$var$parseXml(result.ResponseMetadata[0], {});
        return data;
    } else if (error) throw $7a16d02d81a5bc8f$var$util.error(error, {
        code: 'XMLParserError',
        retryable: true
    });
    else return $7a16d02d81a5bc8f$var$parseXml({}, shape);
};
function $7a16d02d81a5bc8f$var$parseXml(xml, shape) {
    switch(shape.type){
        case 'structure':
            return $7a16d02d81a5bc8f$var$parseStructure(xml, shape);
        case 'map':
            return $7a16d02d81a5bc8f$var$parseMap(xml, shape);
        case 'list':
            return $7a16d02d81a5bc8f$var$parseList(xml, shape);
        case undefined:
        case null:
            return $7a16d02d81a5bc8f$var$parseUnknown(xml);
        default:
            return $7a16d02d81a5bc8f$var$parseScalar(xml, shape);
    }
}
function $7a16d02d81a5bc8f$var$parseStructure(xml, shape) {
    var data = {};
    if (xml === null) return data;
    $7a16d02d81a5bc8f$var$util.each(shape.members, function(memberName, memberShape) {
        var xmlName = memberShape.name;
        if (Object.prototype.hasOwnProperty.call(xml, xmlName) && Array.isArray(xml[xmlName])) {
            var xmlChild = xml[xmlName];
            if (!memberShape.flattened) xmlChild = xmlChild[0];
            data[memberName] = $7a16d02d81a5bc8f$var$parseXml(xmlChild, memberShape);
        } else if (memberShape.isXmlAttribute && xml.$ && Object.prototype.hasOwnProperty.call(xml.$, xmlName)) data[memberName] = $7a16d02d81a5bc8f$var$parseScalar(xml.$[xmlName], memberShape);
        else if (memberShape.type === 'list' && !shape.api.xmlNoDefaultLists) data[memberName] = memberShape.defaultValue;
    });
    return data;
}
function $7a16d02d81a5bc8f$var$parseMap(xml, shape) {
    var data = {};
    if (xml === null) return data;
    var xmlKey = shape.key.name || 'key';
    var xmlValue = shape.value.name || 'value';
    var iterable = shape.flattened ? xml : xml.entry;
    if (Array.isArray(iterable)) $7a16d02d81a5bc8f$var$util.arrayEach(iterable, function(child) {
        data[child[xmlKey][0]] = $7a16d02d81a5bc8f$var$parseXml(child[xmlValue][0], shape.value);
    });
    return data;
}
function $7a16d02d81a5bc8f$var$parseList(xml, shape) {
    var data = [];
    var name = shape.member.name || 'member';
    if (shape.flattened) $7a16d02d81a5bc8f$var$util.arrayEach(xml, function(xmlChild) {
        data.push($7a16d02d81a5bc8f$var$parseXml(xmlChild, shape.member));
    });
    else if (xml && Array.isArray(xml[name])) $7a16d02d81a5bc8f$var$util.arrayEach(xml[name], function(child) {
        data.push($7a16d02d81a5bc8f$var$parseXml(child, shape.member));
    });
    return data;
}
function $7a16d02d81a5bc8f$var$parseScalar(text, shape) {
    if (text && text.$ && text.$.encoding === 'base64') shape = new $7a16d02d81a5bc8f$var$Shape.create({
        type: text.$.encoding
    });
    if (text && text._) text = text._;
    if (typeof shape.toType === 'function') return shape.toType(text);
    else return text;
}
function $7a16d02d81a5bc8f$var$parseUnknown(xml) {
    if (xml === undefined || xml === null) return '';
    if (typeof xml === 'string') return xml;
    // parse a list
    if (Array.isArray(xml)) {
        var arr = [];
        for(i = 0; i < xml.length; i++)arr.push($7a16d02d81a5bc8f$var$parseXml(xml[i], {}));
        return arr;
    }
    // empty object
    var keys = Object.keys(xml), i;
    if (keys.length === 0 || keys.length === 1 && keys[0] === '$') return {};
    // object, parse as structure
    var data = {};
    for(i = 0; i < keys.length; i++){
        var key = keys[i], value = xml[key];
        if (key === '$') continue;
        if (value.length > 1) data[key] = $7a16d02d81a5bc8f$var$parseList(value, {
            member: {}
        });
        else data[key] = $7a16d02d81a5bc8f$var$parseXml(value[0], {});
    }
    return data;
}
/**
 * @api private
 */ module.exports = $7a16d02d81a5bc8f$var$NodeXmlParser;

});
parcelRegister("gowGR", function(module, exports) {




// Generated by CoffeeScript 1.12.7
(function() {
    "use strict";
    var builder, defaults, parser, processors, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    defaults = (parcelRequire("ewGIA"));
    builder = (parcelRequire("44OLG"));
    parser = (parcelRequire("c8EuY"));
    processors = (parcelRequire("lh24m"));
    module.exports.defaults = defaults.defaults;
    module.exports.processors = processors;
    module.exports.ValidationError = function(superClass) {
        extend(ValidationError, superClass);
        function ValidationError(message) {
            this.message = message;
        }
        return ValidationError;
    }(Error);
    module.exports.Builder = builder.Builder;
    module.exports.Parser = parser.Parser;
    module.exports.parseString = parser.parseString;
    module.exports.parseStringPromise = parser.parseStringPromise;
}).call(module.exports);

});
parcelRegister("ewGIA", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    module.exports.defaults = {
        "0.1": {
            explicitCharkey: false,
            trim: true,
            normalize: true,
            normalizeTags: false,
            attrkey: "@",
            charkey: "#",
            explicitArray: false,
            ignoreAttrs: false,
            mergeAttrs: false,
            explicitRoot: false,
            validator: null,
            xmlns: false,
            explicitChildren: false,
            childkey: '@@',
            charsAsChildren: false,
            includeWhiteChars: false,
            async: false,
            strict: true,
            attrNameProcessors: null,
            attrValueProcessors: null,
            tagNameProcessors: null,
            valueProcessors: null,
            emptyTag: ''
        },
        "0.2": {
            explicitCharkey: false,
            trim: false,
            normalize: false,
            normalizeTags: false,
            attrkey: "$",
            charkey: "_",
            explicitArray: true,
            ignoreAttrs: false,
            mergeAttrs: false,
            explicitRoot: true,
            validator: null,
            xmlns: false,
            explicitChildren: false,
            preserveChildrenOrder: false,
            childkey: '$$',
            charsAsChildren: false,
            includeWhiteChars: false,
            async: false,
            strict: true,
            attrNameProcessors: null,
            attrValueProcessors: null,
            tagNameProcessors: null,
            valueProcessors: null,
            rootName: 'root',
            xmldec: {
                'version': '1.0',
                'encoding': 'UTF-8',
                'standalone': true
            },
            doctype: null,
            renderOpts: {
                'pretty': true,
                'indent': '  ',
                'newline': '\n'
            },
            headless: false,
            chunkSize: 10000,
            emptyTag: '',
            cdata: false
        }
    };
}).call(module.exports);

});

parcelRegister("44OLG", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    "use strict";
    var builder, defaults, escapeCDATA, requiresCDATA, wrapCDATA, hasProp = {}.hasOwnProperty;
    builder = (parcelRequire("6zkIH"));
    defaults = (parcelRequire("ewGIA")).defaults;
    requiresCDATA = function(entry) {
        return typeof entry === "string" && (entry.indexOf('&') >= 0 || entry.indexOf('>') >= 0 || entry.indexOf('<') >= 0);
    };
    wrapCDATA = function(entry) {
        return "<![CDATA[" + escapeCDATA(entry) + "]]>";
    };
    escapeCDATA = function(entry) {
        return entry.replace(']]>', ']]]]><![CDATA[>');
    };
    module.exports.Builder = function() {
        function Builder(opts) {
            var key, ref, value;
            this.options = {};
            ref = defaults["0.2"];
            for(key in ref){
                if (!hasProp.call(ref, key)) continue;
                value = ref[key];
                this.options[key] = value;
            }
            for(key in opts){
                if (!hasProp.call(opts, key)) continue;
                value = opts[key];
                this.options[key] = value;
            }
        }
        Builder.prototype.buildObject = function(rootObj) {
            var attrkey, charkey, render, rootElement, rootName;
            attrkey = this.options.attrkey;
            charkey = this.options.charkey;
            if (Object.keys(rootObj).length === 1 && this.options.rootName === defaults['0.2'].rootName) {
                rootName = Object.keys(rootObj)[0];
                rootObj = rootObj[rootName];
            } else rootName = this.options.rootName;
            render = function(_this) {
                return function(element, obj) {
                    var attr, child, entry, index, key, value;
                    if (typeof obj !== 'object') {
                        if (_this.options.cdata && requiresCDATA(obj)) element.raw(wrapCDATA(obj));
                        else element.txt(obj);
                    } else if (Array.isArray(obj)) for(index in obj){
                        if (!hasProp.call(obj, index)) continue;
                        child = obj[index];
                        for(key in child){
                            entry = child[key];
                            element = render(element.ele(key), entry).up();
                        }
                    }
                    else for(key in obj){
                        if (!hasProp.call(obj, key)) continue;
                        child = obj[key];
                        if (key === attrkey) {
                            if (typeof child === "object") for(attr in child){
                                value = child[attr];
                                element = element.att(attr, value);
                            }
                        } else if (key === charkey) {
                            if (_this.options.cdata && requiresCDATA(child)) element = element.raw(wrapCDATA(child));
                            else element = element.txt(child);
                        } else if (Array.isArray(child)) for(index in child){
                            if (!hasProp.call(child, index)) continue;
                            entry = child[index];
                            if (typeof entry === 'string') {
                                if (_this.options.cdata && requiresCDATA(entry)) element = element.ele(key).raw(wrapCDATA(entry)).up();
                                else element = element.ele(key, entry).up();
                            } else element = render(element.ele(key), entry).up();
                        }
                        else if (typeof child === "object") element = render(element.ele(key), child).up();
                        else if (typeof child === 'string' && _this.options.cdata && requiresCDATA(child)) element = element.ele(key).raw(wrapCDATA(child)).up();
                        else {
                            if (child == null) child = '';
                            element = element.ele(key, child.toString()).up();
                        }
                    }
                    return element;
                };
            }(this);
            rootElement = builder.create(rootName, this.options.xmldec, this.options.doctype, {
                headless: this.options.headless,
                allowSurrogateChars: this.options.allowSurrogateChars
            });
            return render(rootElement, rootObj).end(this.options.renderOpts);
        };
        return Builder;
    }();
}).call(module.exports);

});
parcelRegister("6zkIH", function(module, exports) {








// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, WriterState, XMLDOMImplementation, XMLDocument, XMLDocumentCB, XMLStreamWriter, XMLStringWriter, assign, isFunction, ref;
    ref = (parcelRequire("lWlfz")), assign = ref.assign, isFunction = ref.isFunction;
    XMLDOMImplementation = (parcelRequire("lQKut"));
    XMLDocument = (parcelRequire("idlBn"));
    XMLDocumentCB = (parcelRequire("lyUxh"));
    XMLStringWriter = (parcelRequire("bqJ1H"));
    XMLStreamWriter = (parcelRequire("2fEro"));
    NodeType = (parcelRequire("gy5zo"));
    WriterState = (parcelRequire("adHTJ"));
    module.exports.create = function(name, xmldec, doctype, options) {
        var doc, root;
        if (name == null) throw new Error("Root element needs a name.");
        options = assign({}, xmldec, doctype, options);
        doc = new XMLDocument(options);
        root = doc.element(name);
        if (!options.headless) {
            doc.declaration(options);
            if (options.pubID != null || options.sysID != null) doc.dtd(options);
        }
        return root;
    };
    module.exports.begin = function(options, onData, onEnd) {
        var ref1;
        if (isFunction(options)) {
            ref1 = [
                options,
                onData
            ], onData = ref1[0], onEnd = ref1[1];
            options = {};
        }
        if (onData) return new XMLDocumentCB(options, onData, onEnd);
        else return new XMLDocument(options);
    };
    module.exports.stringWriter = function(options) {
        return new XMLStringWriter(options);
    };
    module.exports.streamWriter = function(stream, options) {
        return new XMLStreamWriter(stream, options);
    };
    module.exports.implementation = new XMLDOMImplementation();
    module.exports.nodeType = NodeType;
    module.exports.writerState = WriterState;
}).call(module.exports);

});
parcelRegister("lWlfz", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    var assign, getValue, isArray, isEmpty, isFunction, isObject, isPlainObject, slice = [].slice, hasProp = {}.hasOwnProperty;
    assign = function() {
        var i, key, len, source, sources, target;
        target = arguments[0], sources = 2 <= arguments.length ? slice.call(arguments, 1) : [];
        if (isFunction(Object.assign)) Object.assign.apply(null, arguments);
        else for(i = 0, len = sources.length; i < len; i++){
            source = sources[i];
            if (source != null) for(key in source){
                if (!hasProp.call(source, key)) continue;
                target[key] = source[key];
            }
        }
        return target;
    };
    isFunction = function(val) {
        return !!val && Object.prototype.toString.call(val) === '[object Function]';
    };
    isObject = function(val) {
        var ref;
        return !!val && ((ref = typeof val) === 'function' || ref === 'object');
    };
    isArray = function(val) {
        if (isFunction(Array.isArray)) return Array.isArray(val);
        else return Object.prototype.toString.call(val) === '[object Array]';
    };
    isEmpty = function(val) {
        var key;
        if (isArray(val)) return !val.length;
        else {
            for(key in val){
                if (!hasProp.call(val, key)) continue;
                return false;
            }
            return true;
        }
    };
    isPlainObject = function(val) {
        var ctor, proto;
        return isObject(val) && (proto = Object.getPrototypeOf(val)) && (ctor = proto.constructor) && typeof ctor === 'function' && ctor instanceof ctor && Function.prototype.toString.call(ctor) === Function.prototype.toString.call(Object);
    };
    getValue = function(obj) {
        if (isFunction(obj.valueOf)) return obj.valueOf();
        else return obj;
    };
    module.exports.assign = assign;
    module.exports.isFunction = isFunction;
    module.exports.isObject = isObject;
    module.exports.isArray = isArray;
    module.exports.isEmpty = isEmpty;
    module.exports.isPlainObject = isPlainObject;
    module.exports.getValue = getValue;
}).call(module.exports);

});

parcelRegister("lQKut", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    var XMLDOMImplementation;
    module.exports = XMLDOMImplementation = function() {
        function XMLDOMImplementation() {}
        XMLDOMImplementation.prototype.hasFeature = function(feature, version) {
            return true;
        };
        XMLDOMImplementation.prototype.createDocumentType = function(qualifiedName, publicId, systemId) {
            throw new Error("This DOM method is not implemented.");
        };
        XMLDOMImplementation.prototype.createDocument = function(namespaceURI, qualifiedName, doctype) {
            throw new Error("This DOM method is not implemented.");
        };
        XMLDOMImplementation.prototype.createHTMLDocument = function(title) {
            throw new Error("This DOM method is not implemented.");
        };
        XMLDOMImplementation.prototype.getFeature = function(feature, version) {
            throw new Error("This DOM method is not implemented.");
        };
        return XMLDOMImplementation;
    }();
}).call(module.exports);

});

parcelRegister("idlBn", function(module, exports) {







// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLDOMConfiguration, XMLDOMImplementation, XMLDocument, XMLNode, XMLStringWriter, XMLStringifier, isPlainObject, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    isPlainObject = (parcelRequire("lWlfz")).isPlainObject;
    XMLDOMImplementation = (parcelRequire("lQKut"));
    XMLDOMConfiguration = (parcelRequire("4iMRl"));
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    XMLStringifier = (parcelRequire("bBPYQ"));
    XMLStringWriter = (parcelRequire("bqJ1H"));
    module.exports = XMLDocument = function(superClass) {
        extend(XMLDocument, superClass);
        function XMLDocument(options) {
            XMLDocument.__super__.constructor.call(this, null);
            this.name = "#document";
            this.type = NodeType.Document;
            this.documentURI = null;
            this.domConfig = new XMLDOMConfiguration();
            options || (options = {});
            if (!options.writer) options.writer = new XMLStringWriter();
            this.options = options;
            this.stringify = new XMLStringifier(options);
        }
        Object.defineProperty(XMLDocument.prototype, 'implementation', {
            value: new XMLDOMImplementation()
        });
        Object.defineProperty(XMLDocument.prototype, 'doctype', {
            get: function() {
                var child, i, len, ref;
                ref = this.children;
                for(i = 0, len = ref.length; i < len; i++){
                    child = ref[i];
                    if (child.type === NodeType.DocType) return child;
                }
                return null;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'documentElement', {
            get: function() {
                return this.rootObject || null;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'inputEncoding', {
            get: function() {
                return null;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'strictErrorChecking', {
            get: function() {
                return false;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'xmlEncoding', {
            get: function() {
                if (this.children.length !== 0 && this.children[0].type === NodeType.Declaration) return this.children[0].encoding;
                else return null;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'xmlStandalone', {
            get: function() {
                if (this.children.length !== 0 && this.children[0].type === NodeType.Declaration) return this.children[0].standalone === 'yes';
                else return false;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'xmlVersion', {
            get: function() {
                if (this.children.length !== 0 && this.children[0].type === NodeType.Declaration) return this.children[0].version;
                else return "1.0";
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'URL', {
            get: function() {
                return this.documentURI;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'origin', {
            get: function() {
                return null;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'compatMode', {
            get: function() {
                return null;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'characterSet', {
            get: function() {
                return null;
            }
        });
        Object.defineProperty(XMLDocument.prototype, 'contentType', {
            get: function() {
                return null;
            }
        });
        XMLDocument.prototype.end = function(writer) {
            var writerOptions;
            writerOptions = {};
            if (!writer) writer = this.options.writer;
            else if (isPlainObject(writer)) {
                writerOptions = writer;
                writer = this.options.writer;
            }
            return writer.document(this, writer.filterOptions(writerOptions));
        };
        XMLDocument.prototype.toString = function(options) {
            return this.options.writer.document(this, this.options.writer.filterOptions(options));
        };
        XMLDocument.prototype.createElement = function(tagName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createDocumentFragment = function() {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createTextNode = function(data) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createComment = function(data) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createCDATASection = function(data) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createProcessingInstruction = function(target, data) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createAttribute = function(name) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createEntityReference = function(name) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.getElementsByTagName = function(tagname) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.importNode = function(importedNode, deep) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createElementNS = function(namespaceURI, qualifiedName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createAttributeNS = function(namespaceURI, qualifiedName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.getElementsByTagNameNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.getElementById = function(elementId) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.adoptNode = function(source) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.normalizeDocument = function() {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.renameNode = function(node, namespaceURI, qualifiedName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.getElementsByClassName = function(classNames) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createEvent = function(eventInterface) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createRange = function() {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createNodeIterator = function(root, whatToShow, filter) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLDocument.prototype.createTreeWalker = function(root, whatToShow, filter) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        return XMLDocument;
    }(XMLNode);
}).call(module.exports);

});
parcelRegister("4iMRl", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var XMLDOMConfiguration, XMLDOMErrorHandler, XMLDOMStringList;
    XMLDOMErrorHandler = (parcelRequire("kzxUj"));
    XMLDOMStringList = (parcelRequire("f3NuK"));
    module.exports = XMLDOMConfiguration = function() {
        function XMLDOMConfiguration() {
            var clonedSelf;
            this.defaultParams = {
                "canonical-form": false,
                "cdata-sections": false,
                "comments": false,
                "datatype-normalization": false,
                "element-content-whitespace": true,
                "entities": true,
                "error-handler": new XMLDOMErrorHandler(),
                "infoset": true,
                "validate-if-schema": false,
                "namespaces": true,
                "namespace-declarations": true,
                "normalize-characters": false,
                "schema-location": '',
                "schema-type": '',
                "split-cdata-sections": true,
                "validate": false,
                "well-formed": true
            };
            this.params = clonedSelf = Object.create(this.defaultParams);
        }
        Object.defineProperty(XMLDOMConfiguration.prototype, 'parameterNames', {
            get: function() {
                return new XMLDOMStringList(Object.keys(this.defaultParams));
            }
        });
        XMLDOMConfiguration.prototype.getParameter = function(name) {
            if (this.params.hasOwnProperty(name)) return this.params[name];
            else return null;
        };
        XMLDOMConfiguration.prototype.canSetParameter = function(name, value) {
            return true;
        };
        XMLDOMConfiguration.prototype.setParameter = function(name, value) {
            if (value != null) return this.params[name] = value;
            else return delete this.params[name];
        };
        return XMLDOMConfiguration;
    }();
}).call(module.exports);

});
parcelRegister("kzxUj", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    var XMLDOMErrorHandler;
    module.exports = XMLDOMErrorHandler = function() {
        function XMLDOMErrorHandler() {}
        XMLDOMErrorHandler.prototype.handleError = function(error) {
            throw new Error(error);
        };
        return XMLDOMErrorHandler;
    }();
}).call(module.exports);

});

parcelRegister("f3NuK", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    var XMLDOMStringList;
    module.exports = XMLDOMStringList = function() {
        function XMLDOMStringList(arr) {
            this.arr = arr || [];
        }
        Object.defineProperty(XMLDOMStringList.prototype, 'length', {
            get: function() {
                return this.arr.length;
            }
        });
        XMLDOMStringList.prototype.item = function(index) {
            return this.arr[index] || null;
        };
        XMLDOMStringList.prototype.contains = function(str) {
            return this.arr.indexOf(str) !== -1;
        };
        return XMLDOMStringList;
    }();
}).call(module.exports);

});


parcelRegister("5qtLe", function(module, exports) {














// Generated by CoffeeScript 1.12.7
(function() {
    var DocumentPosition, NodeType, XMLCData, XMLComment, XMLDeclaration, XMLDocType, XMLDummy, XMLElement, XMLNamedNodeMap, XMLNode, XMLNodeList, XMLProcessingInstruction, XMLRaw, XMLText, getValue, isEmpty, isFunction, isObject, ref1, hasProp = {}.hasOwnProperty;
    ref1 = (parcelRequire("lWlfz")), isObject = ref1.isObject, isFunction = ref1.isFunction, isEmpty = ref1.isEmpty, getValue = ref1.getValue;
    XMLElement = null;
    XMLCData = null;
    XMLComment = null;
    XMLDeclaration = null;
    XMLDocType = null;
    XMLRaw = null;
    XMLText = null;
    XMLProcessingInstruction = null;
    XMLDummy = null;
    NodeType = null;
    XMLNodeList = null;
    XMLNamedNodeMap = null;
    DocumentPosition = null;
    module.exports = XMLNode = function() {
        function XMLNode(parent1) {
            this.parent = parent1;
            if (this.parent) {
                this.options = this.parent.options;
                this.stringify = this.parent.stringify;
            }
            this.value = null;
            this.children = [];
            this.baseURI = null;
            if (!XMLElement) {
                XMLElement = (parcelRequire("9yuwu"));
                XMLCData = (parcelRequire("kZwwr"));
                XMLComment = (parcelRequire("gws8K"));
                XMLDeclaration = (parcelRequire("ivAFH"));
                XMLDocType = (parcelRequire("ka7jk"));
                XMLRaw = (parcelRequire("82KEw"));
                XMLText = (parcelRequire("dF17Q"));
                XMLProcessingInstruction = (parcelRequire("j5RFz"));
                XMLDummy = (parcelRequire("80Xj5"));
                NodeType = (parcelRequire("gy5zo"));
                XMLNodeList = (parcelRequire("4E52e"));
                XMLNamedNodeMap = (parcelRequire("7Yd27"));
                DocumentPosition = (parcelRequire("gVy2q"));
            }
        }
        Object.defineProperty(XMLNode.prototype, 'nodeName', {
            get: function() {
                return this.name;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'nodeType', {
            get: function() {
                return this.type;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'nodeValue', {
            get: function() {
                return this.value;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'parentNode', {
            get: function() {
                return this.parent;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'childNodes', {
            get: function() {
                if (!this.childNodeList || !this.childNodeList.nodes) this.childNodeList = new XMLNodeList(this.children);
                return this.childNodeList;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'firstChild', {
            get: function() {
                return this.children[0] || null;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'lastChild', {
            get: function() {
                return this.children[this.children.length - 1] || null;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'previousSibling', {
            get: function() {
                var i;
                i = this.parent.children.indexOf(this);
                return this.parent.children[i - 1] || null;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'nextSibling', {
            get: function() {
                var i;
                i = this.parent.children.indexOf(this);
                return this.parent.children[i + 1] || null;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'ownerDocument', {
            get: function() {
                return this.document() || null;
            }
        });
        Object.defineProperty(XMLNode.prototype, 'textContent', {
            get: function() {
                var child, j, len, ref2, str;
                if (this.nodeType === NodeType.Element || this.nodeType === NodeType.DocumentFragment) {
                    str = '';
                    ref2 = this.children;
                    for(j = 0, len = ref2.length; j < len; j++){
                        child = ref2[j];
                        if (child.textContent) str += child.textContent;
                    }
                    return str;
                } else return null;
            },
            set: function(value) {
                throw new Error("This DOM method is not implemented." + this.debugInfo());
            }
        });
        XMLNode.prototype.setParent = function(parent) {
            var child, j, len, ref2, results;
            this.parent = parent;
            if (parent) {
                this.options = parent.options;
                this.stringify = parent.stringify;
            }
            ref2 = this.children;
            results = [];
            for(j = 0, len = ref2.length; j < len; j++){
                child = ref2[j];
                results.push(child.setParent(this));
            }
            return results;
        };
        XMLNode.prototype.element = function(name, attributes, text) {
            var childNode, item, j, k, key, lastChild, len, len1, ref2, ref3, val;
            lastChild = null;
            if (attributes === null && text == null) ref2 = [
                {},
                null
            ], attributes = ref2[0], text = ref2[1];
            if (attributes == null) attributes = {};
            attributes = getValue(attributes);
            if (!isObject(attributes)) ref3 = [
                attributes,
                text
            ], text = ref3[0], attributes = ref3[1];
            if (name != null) name = getValue(name);
            if (Array.isArray(name)) for(j = 0, len = name.length; j < len; j++){
                item = name[j];
                lastChild = this.element(item);
            }
            else if (isFunction(name)) lastChild = this.element(name.apply());
            else if (isObject(name)) for(key in name){
                if (!hasProp.call(name, key)) continue;
                val = name[key];
                if (isFunction(val)) val = val.apply();
                if (!this.options.ignoreDecorators && this.stringify.convertAttKey && key.indexOf(this.stringify.convertAttKey) === 0) lastChild = this.attribute(key.substr(this.stringify.convertAttKey.length), val);
                else if (!this.options.separateArrayItems && Array.isArray(val) && isEmpty(val)) lastChild = this.dummy();
                else if (isObject(val) && isEmpty(val)) lastChild = this.element(key);
                else if (!this.options.keepNullNodes && val == null) lastChild = this.dummy();
                else if (!this.options.separateArrayItems && Array.isArray(val)) for(k = 0, len1 = val.length; k < len1; k++){
                    item = val[k];
                    childNode = {};
                    childNode[key] = item;
                    lastChild = this.element(childNode);
                }
                else if (isObject(val)) {
                    if (!this.options.ignoreDecorators && this.stringify.convertTextKey && key.indexOf(this.stringify.convertTextKey) === 0) lastChild = this.element(val);
                    else {
                        lastChild = this.element(key);
                        lastChild.element(val);
                    }
                } else lastChild = this.element(key, val);
            }
            else if (!this.options.keepNullNodes && text === null) lastChild = this.dummy();
            else {
                if (!this.options.ignoreDecorators && this.stringify.convertTextKey && name.indexOf(this.stringify.convertTextKey) === 0) lastChild = this.text(text);
                else if (!this.options.ignoreDecorators && this.stringify.convertCDataKey && name.indexOf(this.stringify.convertCDataKey) === 0) lastChild = this.cdata(text);
                else if (!this.options.ignoreDecorators && this.stringify.convertCommentKey && name.indexOf(this.stringify.convertCommentKey) === 0) lastChild = this.comment(text);
                else if (!this.options.ignoreDecorators && this.stringify.convertRawKey && name.indexOf(this.stringify.convertRawKey) === 0) lastChild = this.raw(text);
                else if (!this.options.ignoreDecorators && this.stringify.convertPIKey && name.indexOf(this.stringify.convertPIKey) === 0) lastChild = this.instruction(name.substr(this.stringify.convertPIKey.length), text);
                else lastChild = this.node(name, attributes, text);
            }
            if (lastChild == null) throw new Error("Could not create any elements with: " + name + ". " + this.debugInfo());
            return lastChild;
        };
        XMLNode.prototype.insertBefore = function(name, attributes, text) {
            var child, i, newChild, refChild, removed;
            if (name != null ? name.type : void 0) {
                newChild = name;
                refChild = attributes;
                newChild.setParent(this);
                if (refChild) {
                    i = children.indexOf(refChild);
                    removed = children.splice(i);
                    children.push(newChild);
                    Array.prototype.push.apply(children, removed);
                } else children.push(newChild);
                return newChild;
            } else {
                if (this.isRoot) throw new Error("Cannot insert elements at root level. " + this.debugInfo(name));
                i = this.parent.children.indexOf(this);
                removed = this.parent.children.splice(i);
                child = this.parent.element(name, attributes, text);
                Array.prototype.push.apply(this.parent.children, removed);
                return child;
            }
        };
        XMLNode.prototype.insertAfter = function(name, attributes, text) {
            var child, i, removed;
            if (this.isRoot) throw new Error("Cannot insert elements at root level. " + this.debugInfo(name));
            i = this.parent.children.indexOf(this);
            removed = this.parent.children.splice(i + 1);
            child = this.parent.element(name, attributes, text);
            Array.prototype.push.apply(this.parent.children, removed);
            return child;
        };
        XMLNode.prototype.remove = function() {
            var i, ref2;
            if (this.isRoot) throw new Error("Cannot remove the root element. " + this.debugInfo());
            i = this.parent.children.indexOf(this);
            [].splice.apply(this.parent.children, [
                i,
                i - i + 1
            ].concat(ref2 = [])), ref2;
            return this.parent;
        };
        XMLNode.prototype.node = function(name, attributes, text) {
            var child, ref2;
            if (name != null) name = getValue(name);
            attributes || (attributes = {});
            attributes = getValue(attributes);
            if (!isObject(attributes)) ref2 = [
                attributes,
                text
            ], text = ref2[0], attributes = ref2[1];
            child = new XMLElement(this, name, attributes);
            if (text != null) child.text(text);
            this.children.push(child);
            return child;
        };
        XMLNode.prototype.text = function(value) {
            var child;
            if (isObject(value)) this.element(value);
            child = new XMLText(this, value);
            this.children.push(child);
            return this;
        };
        XMLNode.prototype.cdata = function(value) {
            var child;
            child = new XMLCData(this, value);
            this.children.push(child);
            return this;
        };
        XMLNode.prototype.comment = function(value) {
            var child;
            child = new XMLComment(this, value);
            this.children.push(child);
            return this;
        };
        XMLNode.prototype.commentBefore = function(value) {
            var child, i, removed;
            i = this.parent.children.indexOf(this);
            removed = this.parent.children.splice(i);
            child = this.parent.comment(value);
            Array.prototype.push.apply(this.parent.children, removed);
            return this;
        };
        XMLNode.prototype.commentAfter = function(value) {
            var child, i, removed;
            i = this.parent.children.indexOf(this);
            removed = this.parent.children.splice(i + 1);
            child = this.parent.comment(value);
            Array.prototype.push.apply(this.parent.children, removed);
            return this;
        };
        XMLNode.prototype.raw = function(value) {
            var child;
            child = new XMLRaw(this, value);
            this.children.push(child);
            return this;
        };
        XMLNode.prototype.dummy = function() {
            var child;
            child = new XMLDummy(this);
            return child;
        };
        XMLNode.prototype.instruction = function(target, value) {
            var insTarget, insValue, instruction, j, len;
            if (target != null) target = getValue(target);
            if (value != null) value = getValue(value);
            if (Array.isArray(target)) for(j = 0, len = target.length; j < len; j++){
                insTarget = target[j];
                this.instruction(insTarget);
            }
            else if (isObject(target)) for(insTarget in target){
                if (!hasProp.call(target, insTarget)) continue;
                insValue = target[insTarget];
                this.instruction(insTarget, insValue);
            }
            else {
                if (isFunction(value)) value = value.apply();
                instruction = new XMLProcessingInstruction(this, target, value);
                this.children.push(instruction);
            }
            return this;
        };
        XMLNode.prototype.instructionBefore = function(target, value) {
            var child, i, removed;
            i = this.parent.children.indexOf(this);
            removed = this.parent.children.splice(i);
            child = this.parent.instruction(target, value);
            Array.prototype.push.apply(this.parent.children, removed);
            return this;
        };
        XMLNode.prototype.instructionAfter = function(target, value) {
            var child, i, removed;
            i = this.parent.children.indexOf(this);
            removed = this.parent.children.splice(i + 1);
            child = this.parent.instruction(target, value);
            Array.prototype.push.apply(this.parent.children, removed);
            return this;
        };
        XMLNode.prototype.declaration = function(version, encoding, standalone) {
            var doc, xmldec;
            doc = this.document();
            xmldec = new XMLDeclaration(doc, version, encoding, standalone);
            if (doc.children.length === 0) doc.children.unshift(xmldec);
            else if (doc.children[0].type === NodeType.Declaration) doc.children[0] = xmldec;
            else doc.children.unshift(xmldec);
            return doc.root() || doc;
        };
        XMLNode.prototype.dtd = function(pubID, sysID) {
            var child, doc, doctype, i, j, k, len, len1, ref2, ref3;
            doc = this.document();
            doctype = new XMLDocType(doc, pubID, sysID);
            ref2 = doc.children;
            for(i = j = 0, len = ref2.length; j < len; i = ++j){
                child = ref2[i];
                if (child.type === NodeType.DocType) {
                    doc.children[i] = doctype;
                    return doctype;
                }
            }
            ref3 = doc.children;
            for(i = k = 0, len1 = ref3.length; k < len1; i = ++k){
                child = ref3[i];
                if (child.isRoot) {
                    doc.children.splice(i, 0, doctype);
                    return doctype;
                }
            }
            doc.children.push(doctype);
            return doctype;
        };
        XMLNode.prototype.up = function() {
            if (this.isRoot) throw new Error("The root node has no parent. Use doc() if you need to get the document object.");
            return this.parent;
        };
        XMLNode.prototype.root = function() {
            var node;
            node = this;
            while(node){
                if (node.type === NodeType.Document) return node.rootObject;
                else if (node.isRoot) return node;
                else node = node.parent;
            }
        };
        XMLNode.prototype.document = function() {
            var node;
            node = this;
            while(node){
                if (node.type === NodeType.Document) return node;
                else node = node.parent;
            }
        };
        XMLNode.prototype.end = function(options) {
            return this.document().end(options);
        };
        XMLNode.prototype.prev = function() {
            var i;
            i = this.parent.children.indexOf(this);
            if (i < 1) throw new Error("Already at the first node. " + this.debugInfo());
            return this.parent.children[i - 1];
        };
        XMLNode.prototype.next = function() {
            var i;
            i = this.parent.children.indexOf(this);
            if (i === -1 || i === this.parent.children.length - 1) throw new Error("Already at the last node. " + this.debugInfo());
            return this.parent.children[i + 1];
        };
        XMLNode.prototype.importDocument = function(doc) {
            var clonedRoot;
            clonedRoot = doc.root().clone();
            clonedRoot.parent = this;
            clonedRoot.isRoot = false;
            this.children.push(clonedRoot);
            return this;
        };
        XMLNode.prototype.debugInfo = function(name) {
            var ref2, ref3;
            name = name || this.name;
            if (name == null && !((ref2 = this.parent) != null ? ref2.name : void 0)) return "";
            else if (name == null) return "parent: <" + this.parent.name + ">";
            else if (!((ref3 = this.parent) != null ? ref3.name : void 0)) return "node: <" + name + ">";
            else return "node: <" + name + ">, parent: <" + this.parent.name + ">";
        };
        XMLNode.prototype.ele = function(name, attributes, text) {
            return this.element(name, attributes, text);
        };
        XMLNode.prototype.nod = function(name, attributes, text) {
            return this.node(name, attributes, text);
        };
        XMLNode.prototype.txt = function(value) {
            return this.text(value);
        };
        XMLNode.prototype.dat = function(value) {
            return this.cdata(value);
        };
        XMLNode.prototype.com = function(value) {
            return this.comment(value);
        };
        XMLNode.prototype.ins = function(target, value) {
            return this.instruction(target, value);
        };
        XMLNode.prototype.doc = function() {
            return this.document();
        };
        XMLNode.prototype.dec = function(version, encoding, standalone) {
            return this.declaration(version, encoding, standalone);
        };
        XMLNode.prototype.e = function(name, attributes, text) {
            return this.element(name, attributes, text);
        };
        XMLNode.prototype.n = function(name, attributes, text) {
            return this.node(name, attributes, text);
        };
        XMLNode.prototype.t = function(value) {
            return this.text(value);
        };
        XMLNode.prototype.d = function(value) {
            return this.cdata(value);
        };
        XMLNode.prototype.c = function(value) {
            return this.comment(value);
        };
        XMLNode.prototype.r = function(value) {
            return this.raw(value);
        };
        XMLNode.prototype.i = function(target, value) {
            return this.instruction(target, value);
        };
        XMLNode.prototype.u = function() {
            return this.up();
        };
        XMLNode.prototype.importXMLBuilder = function(doc) {
            return this.importDocument(doc);
        };
        XMLNode.prototype.replaceChild = function(newChild, oldChild) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.removeChild = function(oldChild) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.appendChild = function(newChild) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.hasChildNodes = function() {
            return this.children.length !== 0;
        };
        XMLNode.prototype.cloneNode = function(deep) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.normalize = function() {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.isSupported = function(feature, version) {
            return true;
        };
        XMLNode.prototype.hasAttributes = function() {
            return this.attribs.length !== 0;
        };
        XMLNode.prototype.compareDocumentPosition = function(other) {
            var ref, res;
            ref = this;
            if (ref === other) return 0;
            else if (this.document() !== other.document()) {
                res = DocumentPosition.Disconnected | DocumentPosition.ImplementationSpecific;
                if (Math.random() < 0.5) res |= DocumentPosition.Preceding;
                else res |= DocumentPosition.Following;
                return res;
            } else if (ref.isAncestor(other)) return DocumentPosition.Contains | DocumentPosition.Preceding;
            else if (ref.isDescendant(other)) return DocumentPosition.Contains | DocumentPosition.Following;
            else if (ref.isPreceding(other)) return DocumentPosition.Preceding;
            else return DocumentPosition.Following;
        };
        XMLNode.prototype.isSameNode = function(other) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.lookupPrefix = function(namespaceURI) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.isDefaultNamespace = function(namespaceURI) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.lookupNamespaceURI = function(prefix) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.isEqualNode = function(node) {
            var i, j, ref2;
            if (node.nodeType !== this.nodeType) return false;
            if (node.children.length !== this.children.length) return false;
            for(i = j = 0, ref2 = this.children.length - 1; 0 <= ref2 ? j <= ref2 : j >= ref2; i = 0 <= ref2 ? ++j : --j){
                if (!this.children[i].isEqualNode(node.children[i])) return false;
            }
            return true;
        };
        XMLNode.prototype.getFeature = function(feature, version) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.setUserData = function(key, data, handler) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.getUserData = function(key) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLNode.prototype.contains = function(other) {
            if (!other) return false;
            return other === this || this.isDescendant(other);
        };
        XMLNode.prototype.isDescendant = function(node) {
            var child, isDescendantChild, j, len, ref2;
            ref2 = this.children;
            for(j = 0, len = ref2.length; j < len; j++){
                child = ref2[j];
                if (node === child) return true;
                isDescendantChild = child.isDescendant(node);
                if (isDescendantChild) return true;
            }
            return false;
        };
        XMLNode.prototype.isAncestor = function(node) {
            return node.isDescendant(this);
        };
        XMLNode.prototype.isPreceding = function(node) {
            var nodePos, thisPos;
            nodePos = this.treePosition(node);
            thisPos = this.treePosition(this);
            if (nodePos === -1 || thisPos === -1) return false;
            else return nodePos < thisPos;
        };
        XMLNode.prototype.isFollowing = function(node) {
            var nodePos, thisPos;
            nodePos = this.treePosition(node);
            thisPos = this.treePosition(this);
            if (nodePos === -1 || thisPos === -1) return false;
            else return nodePos > thisPos;
        };
        XMLNode.prototype.treePosition = function(node) {
            var found, pos;
            pos = 0;
            found = false;
            this.foreachTreeNode(this.document(), function(childNode) {
                pos++;
                if (!found && childNode === node) return found = true;
            });
            if (found) return pos;
            else return -1;
        };
        XMLNode.prototype.foreachTreeNode = function(node, func) {
            var child, j, len, ref2, res;
            node || (node = this.document());
            ref2 = node.children;
            for(j = 0, len = ref2.length; j < len; j++){
                child = ref2[j];
                if (res = func(child)) return res;
                else {
                    res = this.foreachTreeNode(child, func);
                    if (res) return res;
                }
            }
        };
        return XMLNode;
    }();
}).call(module.exports);

});
parcelRegister("9yuwu", function(module, exports) {





// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLAttribute, XMLElement, XMLNamedNodeMap, XMLNode, getValue, isFunction, isObject, ref, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    ref = (parcelRequire("lWlfz")), isObject = ref.isObject, isFunction = ref.isFunction, getValue = ref.getValue;
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    XMLAttribute = (parcelRequire("3Xf4x"));
    XMLNamedNodeMap = (parcelRequire("7Yd27"));
    module.exports = XMLElement = function(superClass) {
        extend(XMLElement, superClass);
        function XMLElement(parent, name, attributes) {
            var child, j, len, ref1;
            XMLElement.__super__.constructor.call(this, parent);
            if (name == null) throw new Error("Missing element name. " + this.debugInfo());
            this.name = this.stringify.name(name);
            this.type = NodeType.Element;
            this.attribs = {};
            this.schemaTypeInfo = null;
            if (attributes != null) this.attribute(attributes);
            if (parent.type === NodeType.Document) {
                this.isRoot = true;
                this.documentObject = parent;
                parent.rootObject = this;
                if (parent.children) {
                    ref1 = parent.children;
                    for(j = 0, len = ref1.length; j < len; j++){
                        child = ref1[j];
                        if (child.type === NodeType.DocType) {
                            child.name = this.name;
                            break;
                        }
                    }
                }
            }
        }
        Object.defineProperty(XMLElement.prototype, 'tagName', {
            get: function() {
                return this.name;
            }
        });
        Object.defineProperty(XMLElement.prototype, 'namespaceURI', {
            get: function() {
                return '';
            }
        });
        Object.defineProperty(XMLElement.prototype, 'prefix', {
            get: function() {
                return '';
            }
        });
        Object.defineProperty(XMLElement.prototype, 'localName', {
            get: function() {
                return this.name;
            }
        });
        Object.defineProperty(XMLElement.prototype, 'id', {
            get: function() {
                throw new Error("This DOM method is not implemented." + this.debugInfo());
            }
        });
        Object.defineProperty(XMLElement.prototype, 'className', {
            get: function() {
                throw new Error("This DOM method is not implemented." + this.debugInfo());
            }
        });
        Object.defineProperty(XMLElement.prototype, 'classList', {
            get: function() {
                throw new Error("This DOM method is not implemented." + this.debugInfo());
            }
        });
        Object.defineProperty(XMLElement.prototype, 'attributes', {
            get: function() {
                if (!this.attributeMap || !this.attributeMap.nodes) this.attributeMap = new XMLNamedNodeMap(this.attribs);
                return this.attributeMap;
            }
        });
        XMLElement.prototype.clone = function() {
            var att, attName, clonedSelf, ref1;
            clonedSelf = Object.create(this);
            if (clonedSelf.isRoot) clonedSelf.documentObject = null;
            clonedSelf.attribs = {};
            ref1 = this.attribs;
            for(attName in ref1){
                if (!hasProp.call(ref1, attName)) continue;
                att = ref1[attName];
                clonedSelf.attribs[attName] = att.clone();
            }
            clonedSelf.children = [];
            this.children.forEach(function(child) {
                var clonedChild;
                clonedChild = child.clone();
                clonedChild.parent = clonedSelf;
                return clonedSelf.children.push(clonedChild);
            });
            return clonedSelf;
        };
        XMLElement.prototype.attribute = function(name, value) {
            var attName, attValue;
            if (name != null) name = getValue(name);
            if (isObject(name)) for(attName in name){
                if (!hasProp.call(name, attName)) continue;
                attValue = name[attName];
                this.attribute(attName, attValue);
            }
            else {
                if (isFunction(value)) value = value.apply();
                if (this.options.keepNullAttributes && value == null) this.attribs[name] = new XMLAttribute(this, name, "");
                else if (value != null) this.attribs[name] = new XMLAttribute(this, name, value);
            }
            return this;
        };
        XMLElement.prototype.removeAttribute = function(name) {
            var attName, j, len;
            if (name == null) throw new Error("Missing attribute name. " + this.debugInfo());
            name = getValue(name);
            if (Array.isArray(name)) for(j = 0, len = name.length; j < len; j++){
                attName = name[j];
                delete this.attribs[attName];
            }
            else delete this.attribs[name];
            return this;
        };
        XMLElement.prototype.toString = function(options) {
            return this.options.writer.element(this, this.options.writer.filterOptions(options));
        };
        XMLElement.prototype.att = function(name, value) {
            return this.attribute(name, value);
        };
        XMLElement.prototype.a = function(name, value) {
            return this.attribute(name, value);
        };
        XMLElement.prototype.getAttribute = function(name) {
            if (this.attribs.hasOwnProperty(name)) return this.attribs[name].value;
            else return null;
        };
        XMLElement.prototype.setAttribute = function(name, value) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.getAttributeNode = function(name) {
            if (this.attribs.hasOwnProperty(name)) return this.attribs[name];
            else return null;
        };
        XMLElement.prototype.setAttributeNode = function(newAttr) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.removeAttributeNode = function(oldAttr) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.getElementsByTagName = function(name) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.getAttributeNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.setAttributeNS = function(namespaceURI, qualifiedName, value) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.removeAttributeNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.getAttributeNodeNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.setAttributeNodeNS = function(newAttr) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.getElementsByTagNameNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.hasAttribute = function(name) {
            return this.attribs.hasOwnProperty(name);
        };
        XMLElement.prototype.hasAttributeNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.setIdAttribute = function(name, isId) {
            if (this.attribs.hasOwnProperty(name)) return this.attribs[name].isId;
            else return isId;
        };
        XMLElement.prototype.setIdAttributeNS = function(namespaceURI, localName, isId) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.setIdAttributeNode = function(idAttr, isId) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.getElementsByTagName = function(tagname) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.getElementsByTagNameNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.getElementsByClassName = function(classNames) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLElement.prototype.isEqualNode = function(node) {
            var i, j, ref1;
            if (!XMLElement.__super__.isEqualNode.apply(this, arguments).isEqualNode(node)) return false;
            if (node.namespaceURI !== this.namespaceURI) return false;
            if (node.prefix !== this.prefix) return false;
            if (node.localName !== this.localName) return false;
            if (node.attribs.length !== this.attribs.length) return false;
            for(i = j = 0, ref1 = this.attribs.length - 1; 0 <= ref1 ? j <= ref1 : j >= ref1; i = 0 <= ref1 ? ++j : --j){
                if (!this.attribs[i].isEqualNode(node.attribs[i])) return false;
            }
            return true;
        };
        return XMLElement;
    }(XMLNode);
}).call(module.exports);

});
parcelRegister("gy5zo", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    module.exports = {
        Element: 1,
        Attribute: 2,
        Text: 3,
        CData: 4,
        EntityReference: 5,
        EntityDeclaration: 6,
        ProcessingInstruction: 7,
        Comment: 8,
        Document: 9,
        DocType: 10,
        DocumentFragment: 11,
        NotationDeclaration: 12,
        Declaration: 201,
        Raw: 202,
        AttributeDeclaration: 203,
        ElementDeclaration: 204,
        Dummy: 205
    };
}).call(module.exports);

});

parcelRegister("3Xf4x", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLAttribute, XMLNode;
    NodeType = (parcelRequire("gy5zo"));
    XMLNode = (parcelRequire("5qtLe"));
    module.exports = XMLAttribute = function() {
        function XMLAttribute(parent, name, value) {
            this.parent = parent;
            if (this.parent) {
                this.options = this.parent.options;
                this.stringify = this.parent.stringify;
            }
            if (name == null) throw new Error("Missing attribute name. " + this.debugInfo(name));
            this.name = this.stringify.name(name);
            this.value = this.stringify.attValue(value);
            this.type = NodeType.Attribute;
            this.isId = false;
            this.schemaTypeInfo = null;
        }
        Object.defineProperty(XMLAttribute.prototype, 'nodeType', {
            get: function() {
                return this.type;
            }
        });
        Object.defineProperty(XMLAttribute.prototype, 'ownerElement', {
            get: function() {
                return this.parent;
            }
        });
        Object.defineProperty(XMLAttribute.prototype, 'textContent', {
            get: function() {
                return this.value;
            },
            set: function(value) {
                return this.value = value || '';
            }
        });
        Object.defineProperty(XMLAttribute.prototype, 'namespaceURI', {
            get: function() {
                return '';
            }
        });
        Object.defineProperty(XMLAttribute.prototype, 'prefix', {
            get: function() {
                return '';
            }
        });
        Object.defineProperty(XMLAttribute.prototype, 'localName', {
            get: function() {
                return this.name;
            }
        });
        Object.defineProperty(XMLAttribute.prototype, 'specified', {
            get: function() {
                return true;
            }
        });
        XMLAttribute.prototype.clone = function() {
            return Object.create(this);
        };
        XMLAttribute.prototype.toString = function(options) {
            return this.options.writer.attribute(this, this.options.writer.filterOptions(options));
        };
        XMLAttribute.prototype.debugInfo = function(name) {
            name = name || this.name;
            if (name == null) return "parent: <" + this.parent.name + ">";
            else return "attribute: {" + name + "}, parent: <" + this.parent.name + ">";
        };
        XMLAttribute.prototype.isEqualNode = function(node) {
            if (node.namespaceURI !== this.namespaceURI) return false;
            if (node.prefix !== this.prefix) return false;
            if (node.localName !== this.localName) return false;
            if (node.value !== this.value) return false;
            return true;
        };
        return XMLAttribute;
    }();
}).call(module.exports);

});

parcelRegister("7Yd27", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    var XMLNamedNodeMap;
    module.exports = XMLNamedNodeMap = function() {
        function XMLNamedNodeMap(nodes) {
            this.nodes = nodes;
        }
        Object.defineProperty(XMLNamedNodeMap.prototype, 'length', {
            get: function() {
                return Object.keys(this.nodes).length || 0;
            }
        });
        XMLNamedNodeMap.prototype.clone = function() {
            return this.nodes = null;
        };
        XMLNamedNodeMap.prototype.getNamedItem = function(name) {
            return this.nodes[name];
        };
        XMLNamedNodeMap.prototype.setNamedItem = function(node) {
            var oldNode;
            oldNode = this.nodes[node.nodeName];
            this.nodes[node.nodeName] = node;
            return oldNode || null;
        };
        XMLNamedNodeMap.prototype.removeNamedItem = function(name) {
            var oldNode;
            oldNode = this.nodes[name];
            delete this.nodes[name];
            return oldNode || null;
        };
        XMLNamedNodeMap.prototype.item = function(index) {
            return this.nodes[Object.keys(this.nodes)[index]] || null;
        };
        XMLNamedNodeMap.prototype.getNamedItemNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented.");
        };
        XMLNamedNodeMap.prototype.setNamedItemNS = function(node) {
            throw new Error("This DOM method is not implemented.");
        };
        XMLNamedNodeMap.prototype.removeNamedItemNS = function(namespaceURI, localName) {
            throw new Error("This DOM method is not implemented.");
        };
        return XMLNamedNodeMap;
    }();
}).call(module.exports);

});


parcelRegister("kZwwr", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLCData, XMLCharacterData, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    NodeType = (parcelRequire("gy5zo"));
    XMLCharacterData = (parcelRequire("lsexD"));
    module.exports = XMLCData = function(superClass) {
        extend(XMLCData, superClass);
        function XMLCData(parent, text) {
            XMLCData.__super__.constructor.call(this, parent);
            if (text == null) throw new Error("Missing CDATA text. " + this.debugInfo());
            this.name = "#cdata-section";
            this.type = NodeType.CData;
            this.value = this.stringify.cdata(text);
        }
        XMLCData.prototype.clone = function() {
            return Object.create(this);
        };
        XMLCData.prototype.toString = function(options) {
            return this.options.writer.cdata(this, this.options.writer.filterOptions(options));
        };
        return XMLCData;
    }(XMLCharacterData);
}).call(module.exports);

});
parcelRegister("lsexD", function(module, exports) {

// Generated by CoffeeScript 1.12.7
(function() {
    var XMLCharacterData, XMLNode, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    XMLNode = (parcelRequire("5qtLe"));
    module.exports = XMLCharacterData = function(superClass) {
        extend(XMLCharacterData, superClass);
        function XMLCharacterData(parent) {
            XMLCharacterData.__super__.constructor.call(this, parent);
            this.value = '';
        }
        Object.defineProperty(XMLCharacterData.prototype, 'data', {
            get: function() {
                return this.value;
            },
            set: function(value) {
                return this.value = value || '';
            }
        });
        Object.defineProperty(XMLCharacterData.prototype, 'length', {
            get: function() {
                return this.value.length;
            }
        });
        Object.defineProperty(XMLCharacterData.prototype, 'textContent', {
            get: function() {
                return this.value;
            },
            set: function(value) {
                return this.value = value || '';
            }
        });
        XMLCharacterData.prototype.clone = function() {
            return Object.create(this);
        };
        XMLCharacterData.prototype.substringData = function(offset, count) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLCharacterData.prototype.appendData = function(arg) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLCharacterData.prototype.insertData = function(offset, arg) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLCharacterData.prototype.deleteData = function(offset, count) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLCharacterData.prototype.replaceData = function(offset, count, arg) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLCharacterData.prototype.isEqualNode = function(node) {
            if (!XMLCharacterData.__super__.isEqualNode.apply(this, arguments).isEqualNode(node)) return false;
            if (node.data !== this.data) return false;
            return true;
        };
        return XMLCharacterData;
    }(XMLNode);
}).call(module.exports);

});


parcelRegister("gws8K", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLCharacterData, XMLComment, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    NodeType = (parcelRequire("gy5zo"));
    XMLCharacterData = (parcelRequire("lsexD"));
    module.exports = XMLComment = function(superClass) {
        extend(XMLComment, superClass);
        function XMLComment(parent, text) {
            XMLComment.__super__.constructor.call(this, parent);
            if (text == null) throw new Error("Missing comment text. " + this.debugInfo());
            this.name = "#comment";
            this.type = NodeType.Comment;
            this.value = this.stringify.comment(text);
        }
        XMLComment.prototype.clone = function() {
            return Object.create(this);
        };
        XMLComment.prototype.toString = function(options) {
            return this.options.writer.comment(this, this.options.writer.filterOptions(options));
        };
        return XMLComment;
    }(XMLCharacterData);
}).call(module.exports);

});

parcelRegister("ivAFH", function(module, exports) {



// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLDeclaration, XMLNode, isObject, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    isObject = (parcelRequire("lWlfz")).isObject;
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    module.exports = XMLDeclaration = function(superClass) {
        extend(XMLDeclaration, superClass);
        function XMLDeclaration(parent, version, encoding, standalone) {
            var ref;
            XMLDeclaration.__super__.constructor.call(this, parent);
            if (isObject(version)) ref = version, version = ref.version, encoding = ref.encoding, standalone = ref.standalone;
            if (!version) version = '1.0';
            this.type = NodeType.Declaration;
            this.version = this.stringify.xmlVersion(version);
            if (encoding != null) this.encoding = this.stringify.xmlEncoding(encoding);
            if (standalone != null) this.standalone = this.stringify.xmlStandalone(standalone);
        }
        XMLDeclaration.prototype.toString = function(options) {
            return this.options.writer.declaration(this, this.options.writer.filterOptions(options));
        };
        return XMLDeclaration;
    }(XMLNode);
}).call(module.exports);

});

parcelRegister("ka7jk", function(module, exports) {








// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLDTDAttList, XMLDTDElement, XMLDTDEntity, XMLDTDNotation, XMLDocType, XMLNamedNodeMap, XMLNode, isObject, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    isObject = (parcelRequire("lWlfz")).isObject;
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    XMLDTDAttList = (parcelRequire("fRRRx"));
    XMLDTDEntity = (parcelRequire("dRFNu"));
    XMLDTDElement = (parcelRequire("7SAiC"));
    XMLDTDNotation = (parcelRequire("AQas7"));
    XMLNamedNodeMap = (parcelRequire("7Yd27"));
    module.exports = XMLDocType = function(superClass) {
        extend(XMLDocType, superClass);
        function XMLDocType(parent, pubID, sysID) {
            var child, i, len, ref, ref1, ref2;
            XMLDocType.__super__.constructor.call(this, parent);
            this.type = NodeType.DocType;
            if (parent.children) {
                ref = parent.children;
                for(i = 0, len = ref.length; i < len; i++){
                    child = ref[i];
                    if (child.type === NodeType.Element) {
                        this.name = child.name;
                        break;
                    }
                }
            }
            this.documentObject = parent;
            if (isObject(pubID)) ref1 = pubID, pubID = ref1.pubID, sysID = ref1.sysID;
            if (sysID == null) ref2 = [
                pubID,
                sysID
            ], sysID = ref2[0], pubID = ref2[1];
            if (pubID != null) this.pubID = this.stringify.dtdPubID(pubID);
            if (sysID != null) this.sysID = this.stringify.dtdSysID(sysID);
        }
        Object.defineProperty(XMLDocType.prototype, 'entities', {
            get: function() {
                var child, i, len, nodes, ref;
                nodes = {};
                ref = this.children;
                for(i = 0, len = ref.length; i < len; i++){
                    child = ref[i];
                    if (child.type === NodeType.EntityDeclaration && !child.pe) nodes[child.name] = child;
                }
                return new XMLNamedNodeMap(nodes);
            }
        });
        Object.defineProperty(XMLDocType.prototype, 'notations', {
            get: function() {
                var child, i, len, nodes, ref;
                nodes = {};
                ref = this.children;
                for(i = 0, len = ref.length; i < len; i++){
                    child = ref[i];
                    if (child.type === NodeType.NotationDeclaration) nodes[child.name] = child;
                }
                return new XMLNamedNodeMap(nodes);
            }
        });
        Object.defineProperty(XMLDocType.prototype, 'publicId', {
            get: function() {
                return this.pubID;
            }
        });
        Object.defineProperty(XMLDocType.prototype, 'systemId', {
            get: function() {
                return this.sysID;
            }
        });
        Object.defineProperty(XMLDocType.prototype, 'internalSubset', {
            get: function() {
                throw new Error("This DOM method is not implemented." + this.debugInfo());
            }
        });
        XMLDocType.prototype.element = function(name, value) {
            var child;
            child = new XMLDTDElement(this, name, value);
            this.children.push(child);
            return this;
        };
        XMLDocType.prototype.attList = function(elementName, attributeName, attributeType, defaultValueType, defaultValue) {
            var child;
            child = new XMLDTDAttList(this, elementName, attributeName, attributeType, defaultValueType, defaultValue);
            this.children.push(child);
            return this;
        };
        XMLDocType.prototype.entity = function(name, value) {
            var child;
            child = new XMLDTDEntity(this, false, name, value);
            this.children.push(child);
            return this;
        };
        XMLDocType.prototype.pEntity = function(name, value) {
            var child;
            child = new XMLDTDEntity(this, true, name, value);
            this.children.push(child);
            return this;
        };
        XMLDocType.prototype.notation = function(name, value) {
            var child;
            child = new XMLDTDNotation(this, name, value);
            this.children.push(child);
            return this;
        };
        XMLDocType.prototype.toString = function(options) {
            return this.options.writer.docType(this, this.options.writer.filterOptions(options));
        };
        XMLDocType.prototype.ele = function(name, value) {
            return this.element(name, value);
        };
        XMLDocType.prototype.att = function(elementName, attributeName, attributeType, defaultValueType, defaultValue) {
            return this.attList(elementName, attributeName, attributeType, defaultValueType, defaultValue);
        };
        XMLDocType.prototype.ent = function(name, value) {
            return this.entity(name, value);
        };
        XMLDocType.prototype.pent = function(name, value) {
            return this.pEntity(name, value);
        };
        XMLDocType.prototype.not = function(name, value) {
            return this.notation(name, value);
        };
        XMLDocType.prototype.up = function() {
            return this.root() || this.documentObject;
        };
        XMLDocType.prototype.isEqualNode = function(node) {
            if (!XMLDocType.__super__.isEqualNode.apply(this, arguments).isEqualNode(node)) return false;
            if (node.name !== this.name) return false;
            if (node.publicId !== this.publicId) return false;
            if (node.systemId !== this.systemId) return false;
            return true;
        };
        return XMLDocType;
    }(XMLNode);
}).call(module.exports);

});
parcelRegister("fRRRx", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLDTDAttList, XMLNode, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    module.exports = XMLDTDAttList = function(superClass) {
        extend(XMLDTDAttList, superClass);
        function XMLDTDAttList(parent, elementName, attributeName, attributeType, defaultValueType, defaultValue) {
            XMLDTDAttList.__super__.constructor.call(this, parent);
            if (elementName == null) throw new Error("Missing DTD element name. " + this.debugInfo());
            if (attributeName == null) throw new Error("Missing DTD attribute name. " + this.debugInfo(elementName));
            if (!attributeType) throw new Error("Missing DTD attribute type. " + this.debugInfo(elementName));
            if (!defaultValueType) throw new Error("Missing DTD attribute default. " + this.debugInfo(elementName));
            if (defaultValueType.indexOf('#') !== 0) defaultValueType = '#' + defaultValueType;
            if (!defaultValueType.match(/^(#REQUIRED|#IMPLIED|#FIXED|#DEFAULT)$/)) throw new Error("Invalid default value type; expected: #REQUIRED, #IMPLIED, #FIXED or #DEFAULT. " + this.debugInfo(elementName));
            if (defaultValue && !defaultValueType.match(/^(#FIXED|#DEFAULT)$/)) throw new Error("Default value only applies to #FIXED or #DEFAULT. " + this.debugInfo(elementName));
            this.elementName = this.stringify.name(elementName);
            this.type = NodeType.AttributeDeclaration;
            this.attributeName = this.stringify.name(attributeName);
            this.attributeType = this.stringify.dtdAttType(attributeType);
            if (defaultValue) this.defaultValue = this.stringify.dtdAttDefault(defaultValue);
            this.defaultValueType = defaultValueType;
        }
        XMLDTDAttList.prototype.toString = function(options) {
            return this.options.writer.dtdAttList(this, this.options.writer.filterOptions(options));
        };
        return XMLDTDAttList;
    }(XMLNode);
}).call(module.exports);

});

parcelRegister("dRFNu", function(module, exports) {



// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLDTDEntity, XMLNode, isObject, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    isObject = (parcelRequire("lWlfz")).isObject;
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    module.exports = XMLDTDEntity = function(superClass) {
        extend(XMLDTDEntity, superClass);
        function XMLDTDEntity(parent, pe, name, value) {
            XMLDTDEntity.__super__.constructor.call(this, parent);
            if (name == null) throw new Error("Missing DTD entity name. " + this.debugInfo(name));
            if (value == null) throw new Error("Missing DTD entity value. " + this.debugInfo(name));
            this.pe = !!pe;
            this.name = this.stringify.name(name);
            this.type = NodeType.EntityDeclaration;
            if (!isObject(value)) {
                this.value = this.stringify.dtdEntityValue(value);
                this.internal = true;
            } else {
                if (!value.pubID && !value.sysID) throw new Error("Public and/or system identifiers are required for an external entity. " + this.debugInfo(name));
                if (value.pubID && !value.sysID) throw new Error("System identifier is required for a public external entity. " + this.debugInfo(name));
                this.internal = false;
                if (value.pubID != null) this.pubID = this.stringify.dtdPubID(value.pubID);
                if (value.sysID != null) this.sysID = this.stringify.dtdSysID(value.sysID);
                if (value.nData != null) this.nData = this.stringify.dtdNData(value.nData);
                if (this.pe && this.nData) throw new Error("Notation declaration is not allowed in a parameter entity. " + this.debugInfo(name));
            }
        }
        Object.defineProperty(XMLDTDEntity.prototype, 'publicId', {
            get: function() {
                return this.pubID;
            }
        });
        Object.defineProperty(XMLDTDEntity.prototype, 'systemId', {
            get: function() {
                return this.sysID;
            }
        });
        Object.defineProperty(XMLDTDEntity.prototype, 'notationName', {
            get: function() {
                return this.nData || null;
            }
        });
        Object.defineProperty(XMLDTDEntity.prototype, 'inputEncoding', {
            get: function() {
                return null;
            }
        });
        Object.defineProperty(XMLDTDEntity.prototype, 'xmlEncoding', {
            get: function() {
                return null;
            }
        });
        Object.defineProperty(XMLDTDEntity.prototype, 'xmlVersion', {
            get: function() {
                return null;
            }
        });
        XMLDTDEntity.prototype.toString = function(options) {
            return this.options.writer.dtdEntity(this, this.options.writer.filterOptions(options));
        };
        return XMLDTDEntity;
    }(XMLNode);
}).call(module.exports);

});

parcelRegister("7SAiC", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLDTDElement, XMLNode, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    module.exports = XMLDTDElement = function(superClass) {
        extend(XMLDTDElement, superClass);
        function XMLDTDElement(parent, name, value) {
            XMLDTDElement.__super__.constructor.call(this, parent);
            if (name == null) throw new Error("Missing DTD element name. " + this.debugInfo());
            if (!value) value = '(#PCDATA)';
            if (Array.isArray(value)) value = '(' + value.join(',') + ')';
            this.name = this.stringify.name(name);
            this.type = NodeType.ElementDeclaration;
            this.value = this.stringify.dtdElementValue(value);
        }
        XMLDTDElement.prototype.toString = function(options) {
            return this.options.writer.dtdElement(this, this.options.writer.filterOptions(options));
        };
        return XMLDTDElement;
    }(XMLNode);
}).call(module.exports);

});

parcelRegister("AQas7", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLDTDNotation, XMLNode, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    module.exports = XMLDTDNotation = function(superClass) {
        extend(XMLDTDNotation, superClass);
        function XMLDTDNotation(parent, name, value) {
            XMLDTDNotation.__super__.constructor.call(this, parent);
            if (name == null) throw new Error("Missing DTD notation name. " + this.debugInfo(name));
            if (!value.pubID && !value.sysID) throw new Error("Public or system identifiers are required for an external entity. " + this.debugInfo(name));
            this.name = this.stringify.name(name);
            this.type = NodeType.NotationDeclaration;
            if (value.pubID != null) this.pubID = this.stringify.dtdPubID(value.pubID);
            if (value.sysID != null) this.sysID = this.stringify.dtdSysID(value.sysID);
        }
        Object.defineProperty(XMLDTDNotation.prototype, 'publicId', {
            get: function() {
                return this.pubID;
            }
        });
        Object.defineProperty(XMLDTDNotation.prototype, 'systemId', {
            get: function() {
                return this.sysID;
            }
        });
        XMLDTDNotation.prototype.toString = function(options) {
            return this.options.writer.dtdNotation(this, this.options.writer.filterOptions(options));
        };
        return XMLDTDNotation;
    }(XMLNode);
}).call(module.exports);

});


parcelRegister("82KEw", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLNode, XMLRaw, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    NodeType = (parcelRequire("gy5zo"));
    XMLNode = (parcelRequire("5qtLe"));
    module.exports = XMLRaw = function(superClass) {
        extend(XMLRaw, superClass);
        function XMLRaw(parent, text) {
            XMLRaw.__super__.constructor.call(this, parent);
            if (text == null) throw new Error("Missing raw text. " + this.debugInfo());
            this.type = NodeType.Raw;
            this.value = this.stringify.raw(text);
        }
        XMLRaw.prototype.clone = function() {
            return Object.create(this);
        };
        XMLRaw.prototype.toString = function(options) {
            return this.options.writer.raw(this, this.options.writer.filterOptions(options));
        };
        return XMLRaw;
    }(XMLNode);
}).call(module.exports);

});

parcelRegister("dF17Q", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLCharacterData, XMLText, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    NodeType = (parcelRequire("gy5zo"));
    XMLCharacterData = (parcelRequire("lsexD"));
    module.exports = XMLText = function(superClass) {
        extend(XMLText, superClass);
        function XMLText(parent, text) {
            XMLText.__super__.constructor.call(this, parent);
            if (text == null) throw new Error("Missing element text. " + this.debugInfo());
            this.name = "#text";
            this.type = NodeType.Text;
            this.value = this.stringify.text(text);
        }
        Object.defineProperty(XMLText.prototype, 'isElementContentWhitespace', {
            get: function() {
                throw new Error("This DOM method is not implemented." + this.debugInfo());
            }
        });
        Object.defineProperty(XMLText.prototype, 'wholeText', {
            get: function() {
                var next, prev, str;
                str = '';
                prev = this.previousSibling;
                while(prev){
                    str = prev.data + str;
                    prev = prev.previousSibling;
                }
                str += this.data;
                next = this.nextSibling;
                while(next){
                    str = str + next.data;
                    next = next.nextSibling;
                }
                return str;
            }
        });
        XMLText.prototype.clone = function() {
            return Object.create(this);
        };
        XMLText.prototype.toString = function(options) {
            return this.options.writer.text(this, this.options.writer.filterOptions(options));
        };
        XMLText.prototype.splitText = function(offset) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        XMLText.prototype.replaceWholeText = function(content) {
            throw new Error("This DOM method is not implemented." + this.debugInfo());
        };
        return XMLText;
    }(XMLCharacterData);
}).call(module.exports);

});

parcelRegister("j5RFz", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLCharacterData, XMLProcessingInstruction, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    NodeType = (parcelRequire("gy5zo"));
    XMLCharacterData = (parcelRequire("lsexD"));
    module.exports = XMLProcessingInstruction = function(superClass) {
        extend(XMLProcessingInstruction, superClass);
        function XMLProcessingInstruction(parent, target, value) {
            XMLProcessingInstruction.__super__.constructor.call(this, parent);
            if (target == null) throw new Error("Missing instruction target. " + this.debugInfo());
            this.type = NodeType.ProcessingInstruction;
            this.target = this.stringify.insTarget(target);
            this.name = this.target;
            if (value) this.value = this.stringify.insValue(value);
        }
        XMLProcessingInstruction.prototype.clone = function() {
            return Object.create(this);
        };
        XMLProcessingInstruction.prototype.toString = function(options) {
            return this.options.writer.processingInstruction(this, this.options.writer.filterOptions(options));
        };
        XMLProcessingInstruction.prototype.isEqualNode = function(node) {
            if (!XMLProcessingInstruction.__super__.isEqualNode.apply(this, arguments).isEqualNode(node)) return false;
            if (node.target !== this.target) return false;
            return true;
        };
        return XMLProcessingInstruction;
    }(XMLCharacterData);
}).call(module.exports);

});

parcelRegister("80Xj5", function(module, exports) {


// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, XMLDummy, XMLNode, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    XMLNode = (parcelRequire("5qtLe"));
    NodeType = (parcelRequire("gy5zo"));
    module.exports = XMLDummy = function(superClass) {
        extend(XMLDummy, superClass);
        function XMLDummy(parent) {
            XMLDummy.__super__.constructor.call(this, parent);
            this.type = NodeType.Dummy;
        }
        XMLDummy.prototype.clone = function() {
            return Object.create(this);
        };
        XMLDummy.prototype.toString = function(options) {
            return '';
        };
        return XMLDummy;
    }(XMLNode);
}).call(module.exports);

});

parcelRegister("4E52e", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    var XMLNodeList;
    module.exports = XMLNodeList = function() {
        function XMLNodeList(nodes) {
            this.nodes = nodes;
        }
        Object.defineProperty(XMLNodeList.prototype, 'length', {
            get: function() {
                return this.nodes.length || 0;
            }
        });
        XMLNodeList.prototype.clone = function() {
            return this.nodes = null;
        };
        XMLNodeList.prototype.item = function(index) {
            return this.nodes[index] || null;
        };
        return XMLNodeList;
    }();
}).call(module.exports);

});

parcelRegister("gVy2q", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    module.exports = {
        Disconnected: 1,
        Preceding: 2,
        Following: 4,
        Contains: 8,
        ContainedBy: 16,
        ImplementationSpecific: 32
    };
}).call(module.exports);

});


parcelRegister("bBPYQ", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    var XMLStringifier, bind = function(fn, me) {
        return function() {
            return fn.apply(me, arguments);
        };
    }, hasProp = {}.hasOwnProperty;
    module.exports = XMLStringifier = function() {
        function XMLStringifier(options) {
            this.assertLegalName = bind(this.assertLegalName, this);
            this.assertLegalChar = bind(this.assertLegalChar, this);
            var key, ref, value;
            options || (options = {});
            this.options = options;
            if (!this.options.version) this.options.version = '1.0';
            ref = options.stringify || {};
            for(key in ref){
                if (!hasProp.call(ref, key)) continue;
                value = ref[key];
                this[key] = value;
            }
        }
        XMLStringifier.prototype.name = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalName('' + val || '');
        };
        XMLStringifier.prototype.text = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar(this.textEscape('' + val || ''));
        };
        XMLStringifier.prototype.cdata = function(val) {
            if (this.options.noValidation) return val;
            val = '' + val || '';
            val = val.replace(']]>', ']]]]><![CDATA[>');
            return this.assertLegalChar(val);
        };
        XMLStringifier.prototype.comment = function(val) {
            if (this.options.noValidation) return val;
            val = '' + val || '';
            if (val.match(/--/)) throw new Error("Comment text cannot contain double-hypen: " + val);
            return this.assertLegalChar(val);
        };
        XMLStringifier.prototype.raw = function(val) {
            if (this.options.noValidation) return val;
            return '' + val || '';
        };
        XMLStringifier.prototype.attValue = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar(this.attEscape(val = '' + val || ''));
        };
        XMLStringifier.prototype.insTarget = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar('' + val || '');
        };
        XMLStringifier.prototype.insValue = function(val) {
            if (this.options.noValidation) return val;
            val = '' + val || '';
            if (val.match(/\?>/)) throw new Error("Invalid processing instruction value: " + val);
            return this.assertLegalChar(val);
        };
        XMLStringifier.prototype.xmlVersion = function(val) {
            if (this.options.noValidation) return val;
            val = '' + val || '';
            if (!val.match(/1\.[0-9]+/)) throw new Error("Invalid version number: " + val);
            return val;
        };
        XMLStringifier.prototype.xmlEncoding = function(val) {
            if (this.options.noValidation) return val;
            val = '' + val || '';
            if (!val.match(/^[A-Za-z](?:[A-Za-z0-9._-])*$/)) throw new Error("Invalid encoding: " + val);
            return this.assertLegalChar(val);
        };
        XMLStringifier.prototype.xmlStandalone = function(val) {
            if (this.options.noValidation) return val;
            if (val) return "yes";
            else return "no";
        };
        XMLStringifier.prototype.dtdPubID = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar('' + val || '');
        };
        XMLStringifier.prototype.dtdSysID = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar('' + val || '');
        };
        XMLStringifier.prototype.dtdElementValue = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar('' + val || '');
        };
        XMLStringifier.prototype.dtdAttType = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar('' + val || '');
        };
        XMLStringifier.prototype.dtdAttDefault = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar('' + val || '');
        };
        XMLStringifier.prototype.dtdEntityValue = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar('' + val || '');
        };
        XMLStringifier.prototype.dtdNData = function(val) {
            if (this.options.noValidation) return val;
            return this.assertLegalChar('' + val || '');
        };
        XMLStringifier.prototype.convertAttKey = '@';
        XMLStringifier.prototype.convertPIKey = '?';
        XMLStringifier.prototype.convertTextKey = '#text';
        XMLStringifier.prototype.convertCDataKey = '#cdata';
        XMLStringifier.prototype.convertCommentKey = '#comment';
        XMLStringifier.prototype.convertRawKey = '#raw';
        XMLStringifier.prototype.assertLegalChar = function(str) {
            var regex, res;
            if (this.options.noValidation) return str;
            regex = '';
            if (this.options.version === '1.0') {
                regex = /[\0-\x08\x0B\f\x0E-\x1F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
                if (res = str.match(regex)) throw new Error("Invalid character in string: " + str + " at index " + res.index);
            } else if (this.options.version === '1.1') {
                regex = /[\0\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
                if (res = str.match(regex)) throw new Error("Invalid character in string: " + str + " at index " + res.index);
            }
            return str;
        };
        XMLStringifier.prototype.assertLegalName = function(str) {
            var regex;
            if (this.options.noValidation) return str;
            this.assertLegalChar(str);
            regex = /^([:A-Z_a-z\xC0-\xD6\xD8-\xF6\xF8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]|[\uD800-\uDB7F][\uDC00-\uDFFF])([\x2D\.0-:A-Z_a-z\xB7\xC0-\xD6\xD8-\xF6\xF8-\u037D\u037F-\u1FFF\u200C\u200D\u203F\u2040\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]|[\uD800-\uDB7F][\uDC00-\uDFFF])*$/;
            if (!str.match(regex)) throw new Error("Invalid character in name");
            return str;
        };
        XMLStringifier.prototype.textEscape = function(str) {
            var ampregex;
            if (this.options.noValidation) return str;
            ampregex = this.options.noDoubleEncoding ? /(?!&\S+;)&/g : /&/g;
            return str.replace(ampregex, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
        };
        XMLStringifier.prototype.attEscape = function(str) {
            var ampregex;
            if (this.options.noValidation) return str;
            ampregex = this.options.noDoubleEncoding ? /(?!&\S+;)&/g : /&/g;
            return str.replace(ampregex, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;').replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');
        };
        return XMLStringifier;
    }();
}).call(module.exports);

});

parcelRegister("bqJ1H", function(module, exports) {

// Generated by CoffeeScript 1.12.7
(function() {
    var XMLStringWriter, XMLWriterBase, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    XMLWriterBase = (parcelRequire("3J9Or"));
    module.exports = XMLStringWriter = function(superClass) {
        extend(XMLStringWriter, superClass);
        function XMLStringWriter(options) {
            XMLStringWriter.__super__.constructor.call(this, options);
        }
        XMLStringWriter.prototype.document = function(doc, options) {
            var child, i, len, r, ref;
            options = this.filterOptions(options);
            r = '';
            ref = doc.children;
            for(i = 0, len = ref.length; i < len; i++){
                child = ref[i];
                r += this.writeChildNode(child, options, 0);
            }
            if (options.pretty && r.slice(-options.newline.length) === options.newline) r = r.slice(0, -options.newline.length);
            return r;
        };
        return XMLStringWriter;
    }(XMLWriterBase);
}).call(module.exports);

});
parcelRegister("3J9Or", function(module, exports) {
















// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, WriterState, XMLCData, XMLComment, XMLDTDAttList, XMLDTDElement, XMLDTDEntity, XMLDTDNotation, XMLDeclaration, XMLDocType, XMLDummy, XMLElement, XMLProcessingInstruction, XMLRaw, XMLText, XMLWriterBase, assign, hasProp = {}.hasOwnProperty;
    assign = (parcelRequire("lWlfz")).assign;
    NodeType = (parcelRequire("gy5zo"));
    XMLDeclaration = (parcelRequire("ivAFH"));
    XMLDocType = (parcelRequire("ka7jk"));
    XMLCData = (parcelRequire("kZwwr"));
    XMLComment = (parcelRequire("gws8K"));
    XMLElement = (parcelRequire("9yuwu"));
    XMLRaw = (parcelRequire("82KEw"));
    XMLText = (parcelRequire("dF17Q"));
    XMLProcessingInstruction = (parcelRequire("j5RFz"));
    XMLDummy = (parcelRequire("80Xj5"));
    XMLDTDAttList = (parcelRequire("fRRRx"));
    XMLDTDElement = (parcelRequire("7SAiC"));
    XMLDTDEntity = (parcelRequire("dRFNu"));
    XMLDTDNotation = (parcelRequire("AQas7"));
    WriterState = (parcelRequire("adHTJ"));
    module.exports = XMLWriterBase = function() {
        function XMLWriterBase(options) {
            var key, ref, value;
            options || (options = {});
            this.options = options;
            ref = options.writer || {};
            for(key in ref){
                if (!hasProp.call(ref, key)) continue;
                value = ref[key];
                this["_" + key] = this[key];
                this[key] = value;
            }
        }
        XMLWriterBase.prototype.filterOptions = function(options) {
            var filteredOptions, ref, ref1, ref2, ref3, ref4, ref5, ref6;
            options || (options = {});
            options = assign({}, this.options, options);
            filteredOptions = {
                writer: this
            };
            filteredOptions.pretty = options.pretty || false;
            filteredOptions.allowEmpty = options.allowEmpty || false;
            filteredOptions.indent = (ref = options.indent) != null ? ref : '  ';
            filteredOptions.newline = (ref1 = options.newline) != null ? ref1 : '\n';
            filteredOptions.offset = (ref2 = options.offset) != null ? ref2 : 0;
            filteredOptions.dontPrettyTextNodes = (ref3 = (ref4 = options.dontPrettyTextNodes) != null ? ref4 : options.dontprettytextnodes) != null ? ref3 : 0;
            filteredOptions.spaceBeforeSlash = (ref5 = (ref6 = options.spaceBeforeSlash) != null ? ref6 : options.spacebeforeslash) != null ? ref5 : '';
            if (filteredOptions.spaceBeforeSlash === true) filteredOptions.spaceBeforeSlash = ' ';
            filteredOptions.suppressPrettyCount = 0;
            filteredOptions.user = {};
            filteredOptions.state = WriterState.None;
            return filteredOptions;
        };
        XMLWriterBase.prototype.indent = function(node, options, level) {
            var indentLevel;
            if (!options.pretty || options.suppressPrettyCount) return '';
            else if (options.pretty) {
                indentLevel = (level || 0) + options.offset + 1;
                if (indentLevel > 0) return new Array(indentLevel).join(options.indent);
            }
            return '';
        };
        XMLWriterBase.prototype.endline = function(node, options, level) {
            if (!options.pretty || options.suppressPrettyCount) return '';
            else return options.newline;
        };
        XMLWriterBase.prototype.attribute = function(att, options, level) {
            var r;
            this.openAttribute(att, options, level);
            r = ' ' + att.name + '="' + att.value + '"';
            this.closeAttribute(att, options, level);
            return r;
        };
        XMLWriterBase.prototype.cdata = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level) + '<![CDATA[';
            options.state = WriterState.InsideTag;
            r += node.value;
            options.state = WriterState.CloseTag;
            r += ']]>' + this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.comment = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level) + '<!-- ';
            options.state = WriterState.InsideTag;
            r += node.value;
            options.state = WriterState.CloseTag;
            r += ' -->' + this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.declaration = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level) + '<?xml';
            options.state = WriterState.InsideTag;
            r += ' version="' + node.version + '"';
            if (node.encoding != null) r += ' encoding="' + node.encoding + '"';
            if (node.standalone != null) r += ' standalone="' + node.standalone + '"';
            options.state = WriterState.CloseTag;
            r += options.spaceBeforeSlash + '?>';
            r += this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.docType = function(node, options, level) {
            var child, i, len, r, ref;
            level || (level = 0);
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level);
            r += '<!DOCTYPE ' + node.root().name;
            if (node.pubID && node.sysID) r += ' PUBLIC "' + node.pubID + '" "' + node.sysID + '"';
            else if (node.sysID) r += ' SYSTEM "' + node.sysID + '"';
            if (node.children.length > 0) {
                r += ' [';
                r += this.endline(node, options, level);
                options.state = WriterState.InsideTag;
                ref = node.children;
                for(i = 0, len = ref.length; i < len; i++){
                    child = ref[i];
                    r += this.writeChildNode(child, options, level + 1);
                }
                options.state = WriterState.CloseTag;
                r += ']';
            }
            options.state = WriterState.CloseTag;
            r += options.spaceBeforeSlash + '>';
            r += this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.element = function(node, options, level) {
            var att, child, childNodeCount, firstChildNode, i, j, len, len1, name, prettySuppressed, r, ref, ref1, ref2;
            level || (level = 0);
            prettySuppressed = false;
            r = '';
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r += this.indent(node, options, level) + '<' + node.name;
            ref = node.attribs;
            for(name in ref){
                if (!hasProp.call(ref, name)) continue;
                att = ref[name];
                r += this.attribute(att, options, level);
            }
            childNodeCount = node.children.length;
            firstChildNode = childNodeCount === 0 ? null : node.children[0];
            if (childNodeCount === 0 || node.children.every(function(e) {
                return (e.type === NodeType.Text || e.type === NodeType.Raw) && e.value === '';
            })) {
                if (options.allowEmpty) {
                    r += '>';
                    options.state = WriterState.CloseTag;
                    r += '</' + node.name + '>' + this.endline(node, options, level);
                } else {
                    options.state = WriterState.CloseTag;
                    r += options.spaceBeforeSlash + '/>' + this.endline(node, options, level);
                }
            } else if (options.pretty && childNodeCount === 1 && (firstChildNode.type === NodeType.Text || firstChildNode.type === NodeType.Raw) && firstChildNode.value != null) {
                r += '>';
                options.state = WriterState.InsideTag;
                options.suppressPrettyCount++;
                prettySuppressed = true;
                r += this.writeChildNode(firstChildNode, options, level + 1);
                options.suppressPrettyCount--;
                prettySuppressed = false;
                options.state = WriterState.CloseTag;
                r += '</' + node.name + '>' + this.endline(node, options, level);
            } else {
                if (options.dontPrettyTextNodes) {
                    ref1 = node.children;
                    for(i = 0, len = ref1.length; i < len; i++){
                        child = ref1[i];
                        if ((child.type === NodeType.Text || child.type === NodeType.Raw) && child.value != null) {
                            options.suppressPrettyCount++;
                            prettySuppressed = true;
                            break;
                        }
                    }
                }
                r += '>' + this.endline(node, options, level);
                options.state = WriterState.InsideTag;
                ref2 = node.children;
                for(j = 0, len1 = ref2.length; j < len1; j++){
                    child = ref2[j];
                    r += this.writeChildNode(child, options, level + 1);
                }
                options.state = WriterState.CloseTag;
                r += this.indent(node, options, level) + '</' + node.name + '>';
                if (prettySuppressed) options.suppressPrettyCount--;
                r += this.endline(node, options, level);
                options.state = WriterState.None;
            }
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.writeChildNode = function(node, options, level) {
            switch(node.type){
                case NodeType.CData:
                    return this.cdata(node, options, level);
                case NodeType.Comment:
                    return this.comment(node, options, level);
                case NodeType.Element:
                    return this.element(node, options, level);
                case NodeType.Raw:
                    return this.raw(node, options, level);
                case NodeType.Text:
                    return this.text(node, options, level);
                case NodeType.ProcessingInstruction:
                    return this.processingInstruction(node, options, level);
                case NodeType.Dummy:
                    return '';
                case NodeType.Declaration:
                    return this.declaration(node, options, level);
                case NodeType.DocType:
                    return this.docType(node, options, level);
                case NodeType.AttributeDeclaration:
                    return this.dtdAttList(node, options, level);
                case NodeType.ElementDeclaration:
                    return this.dtdElement(node, options, level);
                case NodeType.EntityDeclaration:
                    return this.dtdEntity(node, options, level);
                case NodeType.NotationDeclaration:
                    return this.dtdNotation(node, options, level);
                default:
                    throw new Error("Unknown XML node type: " + node.constructor.name);
            }
        };
        XMLWriterBase.prototype.processingInstruction = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level) + '<?';
            options.state = WriterState.InsideTag;
            r += node.target;
            if (node.value) r += ' ' + node.value;
            options.state = WriterState.CloseTag;
            r += options.spaceBeforeSlash + '?>';
            r += this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.raw = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level);
            options.state = WriterState.InsideTag;
            r += node.value;
            options.state = WriterState.CloseTag;
            r += this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.text = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level);
            options.state = WriterState.InsideTag;
            r += node.value;
            options.state = WriterState.CloseTag;
            r += this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.dtdAttList = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level) + '<!ATTLIST';
            options.state = WriterState.InsideTag;
            r += ' ' + node.elementName + ' ' + node.attributeName + ' ' + node.attributeType;
            if (node.defaultValueType !== '#DEFAULT') r += ' ' + node.defaultValueType;
            if (node.defaultValue) r += ' "' + node.defaultValue + '"';
            options.state = WriterState.CloseTag;
            r += options.spaceBeforeSlash + '>' + this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.dtdElement = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level) + '<!ELEMENT';
            options.state = WriterState.InsideTag;
            r += ' ' + node.name + ' ' + node.value;
            options.state = WriterState.CloseTag;
            r += options.spaceBeforeSlash + '>' + this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.dtdEntity = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level) + '<!ENTITY';
            options.state = WriterState.InsideTag;
            if (node.pe) r += ' %';
            r += ' ' + node.name;
            if (node.value) r += ' "' + node.value + '"';
            else {
                if (node.pubID && node.sysID) r += ' PUBLIC "' + node.pubID + '" "' + node.sysID + '"';
                else if (node.sysID) r += ' SYSTEM "' + node.sysID + '"';
                if (node.nData) r += ' NDATA ' + node.nData;
            }
            options.state = WriterState.CloseTag;
            r += options.spaceBeforeSlash + '>' + this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.dtdNotation = function(node, options, level) {
            var r;
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            r = this.indent(node, options, level) + '<!NOTATION';
            options.state = WriterState.InsideTag;
            r += ' ' + node.name;
            if (node.pubID && node.sysID) r += ' PUBLIC "' + node.pubID + '" "' + node.sysID + '"';
            else if (node.pubID) r += ' PUBLIC "' + node.pubID + '"';
            else if (node.sysID) r += ' SYSTEM "' + node.sysID + '"';
            options.state = WriterState.CloseTag;
            r += options.spaceBeforeSlash + '>' + this.endline(node, options, level);
            options.state = WriterState.None;
            this.closeNode(node, options, level);
            return r;
        };
        XMLWriterBase.prototype.openNode = function(node, options, level) {};
        XMLWriterBase.prototype.closeNode = function(node, options, level) {};
        XMLWriterBase.prototype.openAttribute = function(att, options, level) {};
        XMLWriterBase.prototype.closeAttribute = function(att, options, level) {};
        return XMLWriterBase;
    }();
}).call(module.exports);

});
parcelRegister("adHTJ", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    module.exports = {
        None: 0,
        OpenTag: 1,
        InsideTag: 2,
        CloseTag: 3
    };
}).call(module.exports);

});




parcelRegister("lyUxh", function(module, exports) {



















// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, WriterState, XMLAttribute, XMLCData, XMLComment, XMLDTDAttList, XMLDTDElement, XMLDTDEntity, XMLDTDNotation, XMLDeclaration, XMLDocType, XMLDocument, XMLDocumentCB, XMLElement, XMLProcessingInstruction, XMLRaw, XMLStringWriter, XMLStringifier, XMLText, getValue, isFunction, isObject, isPlainObject, ref, hasProp = {}.hasOwnProperty;
    ref = (parcelRequire("lWlfz")), isObject = ref.isObject, isFunction = ref.isFunction, isPlainObject = ref.isPlainObject, getValue = ref.getValue;
    NodeType = (parcelRequire("gy5zo"));
    XMLDocument = (parcelRequire("idlBn"));
    XMLElement = (parcelRequire("9yuwu"));
    XMLCData = (parcelRequire("kZwwr"));
    XMLComment = (parcelRequire("gws8K"));
    XMLRaw = (parcelRequire("82KEw"));
    XMLText = (parcelRequire("dF17Q"));
    XMLProcessingInstruction = (parcelRequire("j5RFz"));
    XMLDeclaration = (parcelRequire("ivAFH"));
    XMLDocType = (parcelRequire("ka7jk"));
    XMLDTDAttList = (parcelRequire("fRRRx"));
    XMLDTDEntity = (parcelRequire("dRFNu"));
    XMLDTDElement = (parcelRequire("7SAiC"));
    XMLDTDNotation = (parcelRequire("AQas7"));
    XMLAttribute = (parcelRequire("3Xf4x"));
    XMLStringifier = (parcelRequire("bBPYQ"));
    XMLStringWriter = (parcelRequire("bqJ1H"));
    WriterState = (parcelRequire("adHTJ"));
    module.exports = XMLDocumentCB = function() {
        function XMLDocumentCB(options, onData, onEnd) {
            var writerOptions;
            this.name = "?xml";
            this.type = NodeType.Document;
            options || (options = {});
            writerOptions = {};
            if (!options.writer) options.writer = new XMLStringWriter();
            else if (isPlainObject(options.writer)) {
                writerOptions = options.writer;
                options.writer = new XMLStringWriter();
            }
            this.options = options;
            this.writer = options.writer;
            this.writerOptions = this.writer.filterOptions(writerOptions);
            this.stringify = new XMLStringifier(options);
            this.onDataCallback = onData || function() {};
            this.onEndCallback = onEnd || function() {};
            this.currentNode = null;
            this.currentLevel = -1;
            this.openTags = {};
            this.documentStarted = false;
            this.documentCompleted = false;
            this.root = null;
        }
        XMLDocumentCB.prototype.createChildNode = function(node) {
            var att, attName, attributes, child, i, len, ref1, ref2;
            switch(node.type){
                case NodeType.CData:
                    this.cdata(node.value);
                    break;
                case NodeType.Comment:
                    this.comment(node.value);
                    break;
                case NodeType.Element:
                    attributes = {};
                    ref1 = node.attribs;
                    for(attName in ref1){
                        if (!hasProp.call(ref1, attName)) continue;
                        att = ref1[attName];
                        attributes[attName] = att.value;
                    }
                    this.node(node.name, attributes);
                    break;
                case NodeType.Dummy:
                    this.dummy();
                    break;
                case NodeType.Raw:
                    this.raw(node.value);
                    break;
                case NodeType.Text:
                    this.text(node.value);
                    break;
                case NodeType.ProcessingInstruction:
                    this.instruction(node.target, node.value);
                    break;
                default:
                    throw new Error("This XML node type is not supported in a JS object: " + node.constructor.name);
            }
            ref2 = node.children;
            for(i = 0, len = ref2.length; i < len; i++){
                child = ref2[i];
                this.createChildNode(child);
                if (child.type === NodeType.Element) this.up();
            }
            return this;
        };
        XMLDocumentCB.prototype.dummy = function() {
            return this;
        };
        XMLDocumentCB.prototype.node = function(name, attributes, text) {
            var ref1;
            if (name == null) throw new Error("Missing node name.");
            if (this.root && this.currentLevel === -1) throw new Error("Document can only have one root node. " + this.debugInfo(name));
            this.openCurrent();
            name = getValue(name);
            if (attributes == null) attributes = {};
            attributes = getValue(attributes);
            if (!isObject(attributes)) ref1 = [
                attributes,
                text
            ], text = ref1[0], attributes = ref1[1];
            this.currentNode = new XMLElement(this, name, attributes);
            this.currentNode.children = false;
            this.currentLevel++;
            this.openTags[this.currentLevel] = this.currentNode;
            if (text != null) this.text(text);
            return this;
        };
        XMLDocumentCB.prototype.element = function(name, attributes, text) {
            var child, i, len, oldValidationFlag, ref1, root;
            if (this.currentNode && this.currentNode.type === NodeType.DocType) this.dtdElement.apply(this, arguments);
            else if (Array.isArray(name) || isObject(name) || isFunction(name)) {
                oldValidationFlag = this.options.noValidation;
                this.options.noValidation = true;
                root = new XMLDocument(this.options).element('TEMP_ROOT');
                root.element(name);
                this.options.noValidation = oldValidationFlag;
                ref1 = root.children;
                for(i = 0, len = ref1.length; i < len; i++){
                    child = ref1[i];
                    this.createChildNode(child);
                    if (child.type === NodeType.Element) this.up();
                }
            } else this.node(name, attributes, text);
            return this;
        };
        XMLDocumentCB.prototype.attribute = function(name, value) {
            var attName, attValue;
            if (!this.currentNode || this.currentNode.children) throw new Error("att() can only be used immediately after an ele() call in callback mode. " + this.debugInfo(name));
            if (name != null) name = getValue(name);
            if (isObject(name)) for(attName in name){
                if (!hasProp.call(name, attName)) continue;
                attValue = name[attName];
                this.attribute(attName, attValue);
            }
            else {
                if (isFunction(value)) value = value.apply();
                if (this.options.keepNullAttributes && value == null) this.currentNode.attribs[name] = new XMLAttribute(this, name, "");
                else if (value != null) this.currentNode.attribs[name] = new XMLAttribute(this, name, value);
            }
            return this;
        };
        XMLDocumentCB.prototype.text = function(value) {
            var node;
            this.openCurrent();
            node = new XMLText(this, value);
            this.onData(this.writer.text(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.cdata = function(value) {
            var node;
            this.openCurrent();
            node = new XMLCData(this, value);
            this.onData(this.writer.cdata(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.comment = function(value) {
            var node;
            this.openCurrent();
            node = new XMLComment(this, value);
            this.onData(this.writer.comment(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.raw = function(value) {
            var node;
            this.openCurrent();
            node = new XMLRaw(this, value);
            this.onData(this.writer.raw(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.instruction = function(target, value) {
            var i, insTarget, insValue, len, node;
            this.openCurrent();
            if (target != null) target = getValue(target);
            if (value != null) value = getValue(value);
            if (Array.isArray(target)) for(i = 0, len = target.length; i < len; i++){
                insTarget = target[i];
                this.instruction(insTarget);
            }
            else if (isObject(target)) for(insTarget in target){
                if (!hasProp.call(target, insTarget)) continue;
                insValue = target[insTarget];
                this.instruction(insTarget, insValue);
            }
            else {
                if (isFunction(value)) value = value.apply();
                node = new XMLProcessingInstruction(this, target, value);
                this.onData(this.writer.processingInstruction(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            }
            return this;
        };
        XMLDocumentCB.prototype.declaration = function(version, encoding, standalone) {
            var node;
            this.openCurrent();
            if (this.documentStarted) throw new Error("declaration() must be the first node.");
            node = new XMLDeclaration(this, version, encoding, standalone);
            this.onData(this.writer.declaration(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.doctype = function(root, pubID, sysID) {
            this.openCurrent();
            if (root == null) throw new Error("Missing root node name.");
            if (this.root) throw new Error("dtd() must come before the root node.");
            this.currentNode = new XMLDocType(this, pubID, sysID);
            this.currentNode.rootNodeName = root;
            this.currentNode.children = false;
            this.currentLevel++;
            this.openTags[this.currentLevel] = this.currentNode;
            return this;
        };
        XMLDocumentCB.prototype.dtdElement = function(name, value) {
            var node;
            this.openCurrent();
            node = new XMLDTDElement(this, name, value);
            this.onData(this.writer.dtdElement(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.attList = function(elementName, attributeName, attributeType, defaultValueType, defaultValue) {
            var node;
            this.openCurrent();
            node = new XMLDTDAttList(this, elementName, attributeName, attributeType, defaultValueType, defaultValue);
            this.onData(this.writer.dtdAttList(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.entity = function(name, value) {
            var node;
            this.openCurrent();
            node = new XMLDTDEntity(this, false, name, value);
            this.onData(this.writer.dtdEntity(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.pEntity = function(name, value) {
            var node;
            this.openCurrent();
            node = new XMLDTDEntity(this, true, name, value);
            this.onData(this.writer.dtdEntity(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.notation = function(name, value) {
            var node;
            this.openCurrent();
            node = new XMLDTDNotation(this, name, value);
            this.onData(this.writer.dtdNotation(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
            return this;
        };
        XMLDocumentCB.prototype.up = function() {
            if (this.currentLevel < 0) throw new Error("The document node has no parent.");
            if (this.currentNode) {
                if (this.currentNode.children) this.closeNode(this.currentNode);
                else this.openNode(this.currentNode);
                this.currentNode = null;
            } else this.closeNode(this.openTags[this.currentLevel]);
            delete this.openTags[this.currentLevel];
            this.currentLevel--;
            return this;
        };
        XMLDocumentCB.prototype.end = function() {
            while(this.currentLevel >= 0)this.up();
            return this.onEnd();
        };
        XMLDocumentCB.prototype.openCurrent = function() {
            if (this.currentNode) {
                this.currentNode.children = true;
                return this.openNode(this.currentNode);
            }
        };
        XMLDocumentCB.prototype.openNode = function(node) {
            var att, chunk, name, ref1;
            if (!node.isOpen) {
                if (!this.root && this.currentLevel === 0 && node.type === NodeType.Element) this.root = node;
                chunk = '';
                if (node.type === NodeType.Element) {
                    this.writerOptions.state = WriterState.OpenTag;
                    chunk = this.writer.indent(node, this.writerOptions, this.currentLevel) + '<' + node.name;
                    ref1 = node.attribs;
                    for(name in ref1){
                        if (!hasProp.call(ref1, name)) continue;
                        att = ref1[name];
                        chunk += this.writer.attribute(att, this.writerOptions, this.currentLevel);
                    }
                    chunk += (node.children ? '>' : '/>') + this.writer.endline(node, this.writerOptions, this.currentLevel);
                    this.writerOptions.state = WriterState.InsideTag;
                } else {
                    this.writerOptions.state = WriterState.OpenTag;
                    chunk = this.writer.indent(node, this.writerOptions, this.currentLevel) + '<!DOCTYPE ' + node.rootNodeName;
                    if (node.pubID && node.sysID) chunk += ' PUBLIC "' + node.pubID + '" "' + node.sysID + '"';
                    else if (node.sysID) chunk += ' SYSTEM "' + node.sysID + '"';
                    if (node.children) {
                        chunk += ' [';
                        this.writerOptions.state = WriterState.InsideTag;
                    } else {
                        this.writerOptions.state = WriterState.CloseTag;
                        chunk += '>';
                    }
                    chunk += this.writer.endline(node, this.writerOptions, this.currentLevel);
                }
                this.onData(chunk, this.currentLevel);
                return node.isOpen = true;
            }
        };
        XMLDocumentCB.prototype.closeNode = function(node) {
            var chunk;
            if (!node.isClosed) {
                chunk = '';
                this.writerOptions.state = WriterState.CloseTag;
                if (node.type === NodeType.Element) chunk = this.writer.indent(node, this.writerOptions, this.currentLevel) + '</' + node.name + '>' + this.writer.endline(node, this.writerOptions, this.currentLevel);
                else chunk = this.writer.indent(node, this.writerOptions, this.currentLevel) + ']>' + this.writer.endline(node, this.writerOptions, this.currentLevel);
                this.writerOptions.state = WriterState.None;
                this.onData(chunk, this.currentLevel);
                return node.isClosed = true;
            }
        };
        XMLDocumentCB.prototype.onData = function(chunk, level) {
            this.documentStarted = true;
            return this.onDataCallback(chunk, level + 1);
        };
        XMLDocumentCB.prototype.onEnd = function() {
            this.documentCompleted = true;
            return this.onEndCallback();
        };
        XMLDocumentCB.prototype.debugInfo = function(name) {
            if (name == null) return "";
            else return "node: <" + name + ">";
        };
        XMLDocumentCB.prototype.ele = function() {
            return this.element.apply(this, arguments);
        };
        XMLDocumentCB.prototype.nod = function(name, attributes, text) {
            return this.node(name, attributes, text);
        };
        XMLDocumentCB.prototype.txt = function(value) {
            return this.text(value);
        };
        XMLDocumentCB.prototype.dat = function(value) {
            return this.cdata(value);
        };
        XMLDocumentCB.prototype.com = function(value) {
            return this.comment(value);
        };
        XMLDocumentCB.prototype.ins = function(target, value) {
            return this.instruction(target, value);
        };
        XMLDocumentCB.prototype.dec = function(version, encoding, standalone) {
            return this.declaration(version, encoding, standalone);
        };
        XMLDocumentCB.prototype.dtd = function(root, pubID, sysID) {
            return this.doctype(root, pubID, sysID);
        };
        XMLDocumentCB.prototype.e = function(name, attributes, text) {
            return this.element(name, attributes, text);
        };
        XMLDocumentCB.prototype.n = function(name, attributes, text) {
            return this.node(name, attributes, text);
        };
        XMLDocumentCB.prototype.t = function(value) {
            return this.text(value);
        };
        XMLDocumentCB.prototype.d = function(value) {
            return this.cdata(value);
        };
        XMLDocumentCB.prototype.c = function(value) {
            return this.comment(value);
        };
        XMLDocumentCB.prototype.r = function(value) {
            return this.raw(value);
        };
        XMLDocumentCB.prototype.i = function(target, value) {
            return this.instruction(target, value);
        };
        XMLDocumentCB.prototype.att = function() {
            if (this.currentNode && this.currentNode.type === NodeType.DocType) return this.attList.apply(this, arguments);
            else return this.attribute.apply(this, arguments);
        };
        XMLDocumentCB.prototype.a = function() {
            if (this.currentNode && this.currentNode.type === NodeType.DocType) return this.attList.apply(this, arguments);
            else return this.attribute.apply(this, arguments);
        };
        XMLDocumentCB.prototype.ent = function(name, value) {
            return this.entity(name, value);
        };
        XMLDocumentCB.prototype.pent = function(name, value) {
            return this.pEntity(name, value);
        };
        XMLDocumentCB.prototype.not = function(name, value) {
            return this.notation(name, value);
        };
        return XMLDocumentCB;
    }();
}).call(module.exports);

});

parcelRegister("2fEro", function(module, exports) {



// Generated by CoffeeScript 1.12.7
(function() {
    var NodeType, WriterState, XMLStreamWriter, XMLWriterBase, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    NodeType = (parcelRequire("gy5zo"));
    XMLWriterBase = (parcelRequire("3J9Or"));
    WriterState = (parcelRequire("adHTJ"));
    module.exports = XMLStreamWriter = function(superClass) {
        extend(XMLStreamWriter, superClass);
        function XMLStreamWriter(stream, options) {
            this.stream = stream;
            XMLStreamWriter.__super__.constructor.call(this, options);
        }
        XMLStreamWriter.prototype.endline = function(node, options, level) {
            if (node.isLastRootNode && options.state === WriterState.CloseTag) return '';
            else return XMLStreamWriter.__super__.endline.call(this, node, options, level);
        };
        XMLStreamWriter.prototype.document = function(doc, options) {
            var child, i, j, k, len, len1, ref, ref1, results;
            ref = doc.children;
            for(i = j = 0, len = ref.length; j < len; i = ++j){
                child = ref[i];
                child.isLastRootNode = i === doc.children.length - 1;
            }
            options = this.filterOptions(options);
            ref1 = doc.children;
            results = [];
            for(k = 0, len1 = ref1.length; k < len1; k++){
                child = ref1[k];
                results.push(this.writeChildNode(child, options, 0));
            }
            return results;
        };
        XMLStreamWriter.prototype.attribute = function(att, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.attribute.call(this, att, options, level));
        };
        XMLStreamWriter.prototype.cdata = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.cdata.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.comment = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.comment.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.declaration = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.declaration.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.docType = function(node, options, level) {
            var child, j, len, ref;
            level || (level = 0);
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            this.stream.write(this.indent(node, options, level));
            this.stream.write('<!DOCTYPE ' + node.root().name);
            if (node.pubID && node.sysID) this.stream.write(' PUBLIC "' + node.pubID + '" "' + node.sysID + '"');
            else if (node.sysID) this.stream.write(' SYSTEM "' + node.sysID + '"');
            if (node.children.length > 0) {
                this.stream.write(' [');
                this.stream.write(this.endline(node, options, level));
                options.state = WriterState.InsideTag;
                ref = node.children;
                for(j = 0, len = ref.length; j < len; j++){
                    child = ref[j];
                    this.writeChildNode(child, options, level + 1);
                }
                options.state = WriterState.CloseTag;
                this.stream.write(']');
            }
            options.state = WriterState.CloseTag;
            this.stream.write(options.spaceBeforeSlash + '>');
            this.stream.write(this.endline(node, options, level));
            options.state = WriterState.None;
            return this.closeNode(node, options, level);
        };
        XMLStreamWriter.prototype.element = function(node, options, level) {
            var att, child, childNodeCount, firstChildNode, j, len, name, prettySuppressed, ref, ref1;
            level || (level = 0);
            this.openNode(node, options, level);
            options.state = WriterState.OpenTag;
            this.stream.write(this.indent(node, options, level) + '<' + node.name);
            ref = node.attribs;
            for(name in ref){
                if (!hasProp.call(ref, name)) continue;
                att = ref[name];
                this.attribute(att, options, level);
            }
            childNodeCount = node.children.length;
            firstChildNode = childNodeCount === 0 ? null : node.children[0];
            if (childNodeCount === 0 || node.children.every(function(e) {
                return (e.type === NodeType.Text || e.type === NodeType.Raw) && e.value === '';
            })) {
                if (options.allowEmpty) {
                    this.stream.write('>');
                    options.state = WriterState.CloseTag;
                    this.stream.write('</' + node.name + '>');
                } else {
                    options.state = WriterState.CloseTag;
                    this.stream.write(options.spaceBeforeSlash + '/>');
                }
            } else if (options.pretty && childNodeCount === 1 && (firstChildNode.type === NodeType.Text || firstChildNode.type === NodeType.Raw) && firstChildNode.value != null) {
                this.stream.write('>');
                options.state = WriterState.InsideTag;
                options.suppressPrettyCount++;
                prettySuppressed = true;
                this.writeChildNode(firstChildNode, options, level + 1);
                options.suppressPrettyCount--;
                prettySuppressed = false;
                options.state = WriterState.CloseTag;
                this.stream.write('</' + node.name + '>');
            } else {
                this.stream.write('>' + this.endline(node, options, level));
                options.state = WriterState.InsideTag;
                ref1 = node.children;
                for(j = 0, len = ref1.length; j < len; j++){
                    child = ref1[j];
                    this.writeChildNode(child, options, level + 1);
                }
                options.state = WriterState.CloseTag;
                this.stream.write(this.indent(node, options, level) + '</' + node.name + '>');
            }
            this.stream.write(this.endline(node, options, level));
            options.state = WriterState.None;
            return this.closeNode(node, options, level);
        };
        XMLStreamWriter.prototype.processingInstruction = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.processingInstruction.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.raw = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.raw.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.text = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.text.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.dtdAttList = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.dtdAttList.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.dtdElement = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.dtdElement.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.dtdEntity = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.dtdEntity.call(this, node, options, level));
        };
        XMLStreamWriter.prototype.dtdNotation = function(node, options, level) {
            return this.stream.write(XMLStreamWriter.__super__.dtdNotation.call(this, node, options, level));
        };
        return XMLStreamWriter;
    }(XMLWriterBase);
}).call(module.exports);

});



parcelRegister("c8EuY", function(module, exports) {






// Generated by CoffeeScript 1.12.7
(function() {
    "use strict";
    var bom, defaults, defineProperty, events, isEmpty, processItem, processors, sax, setImmediate, bind = function(fn, me) {
        return function() {
            return fn.apply(me, arguments);
        };
    }, extend = function(child, parent) {
        for(var key in parent)if (hasProp.call(parent, key)) child[key] = parent[key];
        function ctor() {
            this.constructor = child;
        }
        ctor.prototype = parent.prototype;
        child.prototype = new ctor();
        child.__super__ = parent.prototype;
        return child;
    }, hasProp = {}.hasOwnProperty;
    sax = (parcelRequire("bCkjh"));
    events = $dDec7$events;
    bom = (parcelRequire("dmzGi"));
    processors = (parcelRequire("lh24m"));
    setImmediate = $dDec7$timers.setImmediate;
    defaults = (parcelRequire("ewGIA")).defaults;
    isEmpty = function(thing) {
        return typeof thing === "object" && thing != null && Object.keys(thing).length === 0;
    };
    processItem = function(processors, item, key) {
        var i, len, process;
        for(i = 0, len = processors.length; i < len; i++){
            process = processors[i];
            item = process(item, key);
        }
        return item;
    };
    defineProperty = function(obj, key, value) {
        var descriptor;
        descriptor = Object.create(null);
        descriptor.value = value;
        descriptor.writable = true;
        descriptor.enumerable = true;
        descriptor.configurable = true;
        return Object.defineProperty(obj, key, descriptor);
    };
    exports.Parser = function(superClass) {
        extend(Parser, superClass);
        function Parser(opts) {
            this.parseStringPromise = bind(this.parseStringPromise, this);
            this.parseString = bind(this.parseString, this);
            this.reset = bind(this.reset, this);
            this.assignOrPush = bind(this.assignOrPush, this);
            this.processAsync = bind(this.processAsync, this);
            var key, ref, value;
            if (!(this instanceof exports.Parser)) return new exports.Parser(opts);
            this.options = {};
            ref = defaults["0.2"];
            for(key in ref){
                if (!hasProp.call(ref, key)) continue;
                value = ref[key];
                this.options[key] = value;
            }
            for(key in opts){
                if (!hasProp.call(opts, key)) continue;
                value = opts[key];
                this.options[key] = value;
            }
            if (this.options.xmlns) this.options.xmlnskey = this.options.attrkey + "ns";
            if (this.options.normalizeTags) {
                if (!this.options.tagNameProcessors) this.options.tagNameProcessors = [];
                this.options.tagNameProcessors.unshift(processors.normalize);
            }
            this.reset();
        }
        Parser.prototype.processAsync = function() {
            var chunk, err;
            try {
                if (this.remaining.length <= this.options.chunkSize) {
                    chunk = this.remaining;
                    this.remaining = '';
                    this.saxParser = this.saxParser.write(chunk);
                    return this.saxParser.close();
                } else {
                    chunk = this.remaining.substr(0, this.options.chunkSize);
                    this.remaining = this.remaining.substr(this.options.chunkSize, this.remaining.length);
                    this.saxParser = this.saxParser.write(chunk);
                    return setImmediate(this.processAsync);
                }
            } catch (error1) {
                err = error1;
                if (!this.saxParser.errThrown) {
                    this.saxParser.errThrown = true;
                    return this.emit(err);
                }
            }
        };
        Parser.prototype.assignOrPush = function(obj, key, newValue) {
            if (!(key in obj)) {
                if (!this.options.explicitArray) return defineProperty(obj, key, newValue);
                else return defineProperty(obj, key, [
                    newValue
                ]);
            } else {
                if (!(obj[key] instanceof Array)) defineProperty(obj, key, [
                    obj[key]
                ]);
                return obj[key].push(newValue);
            }
        };
        Parser.prototype.reset = function() {
            var attrkey, charkey, ontext, stack;
            this.removeAllListeners();
            this.saxParser = sax.parser(this.options.strict, {
                trim: false,
                normalize: false,
                xmlns: this.options.xmlns
            });
            this.saxParser.errThrown = false;
            this.saxParser.onerror = function(_this) {
                return function(error) {
                    _this.saxParser.resume();
                    if (!_this.saxParser.errThrown) {
                        _this.saxParser.errThrown = true;
                        return _this.emit("error", error);
                    }
                };
            }(this);
            this.saxParser.onend = function(_this) {
                return function() {
                    if (!_this.saxParser.ended) {
                        _this.saxParser.ended = true;
                        return _this.emit("end", _this.resultObject);
                    }
                };
            }(this);
            this.saxParser.ended = false;
            this.EXPLICIT_CHARKEY = this.options.explicitCharkey;
            this.resultObject = null;
            stack = [];
            attrkey = this.options.attrkey;
            charkey = this.options.charkey;
            this.saxParser.onopentag = function(_this) {
                return function(node) {
                    var key, newValue, obj, processedKey, ref;
                    obj = {};
                    obj[charkey] = "";
                    if (!_this.options.ignoreAttrs) {
                        ref = node.attributes;
                        for(key in ref){
                            if (!hasProp.call(ref, key)) continue;
                            if (!(attrkey in obj) && !_this.options.mergeAttrs) obj[attrkey] = {};
                            newValue = _this.options.attrValueProcessors ? processItem(_this.options.attrValueProcessors, node.attributes[key], key) : node.attributes[key];
                            processedKey = _this.options.attrNameProcessors ? processItem(_this.options.attrNameProcessors, key) : key;
                            if (_this.options.mergeAttrs) _this.assignOrPush(obj, processedKey, newValue);
                            else defineProperty(obj[attrkey], processedKey, newValue);
                        }
                    }
                    obj["#name"] = _this.options.tagNameProcessors ? processItem(_this.options.tagNameProcessors, node.name) : node.name;
                    if (_this.options.xmlns) obj[_this.options.xmlnskey] = {
                        uri: node.uri,
                        local: node.local
                    };
                    return stack.push(obj);
                };
            }(this);
            this.saxParser.onclosetag = function(_this) {
                return function() {
                    var cdata, emptyStr, key, node, nodeName, obj, objClone, old, s, xpath;
                    obj = stack.pop();
                    nodeName = obj["#name"];
                    if (!_this.options.explicitChildren || !_this.options.preserveChildrenOrder) delete obj["#name"];
                    if (obj.cdata === true) {
                        cdata = obj.cdata;
                        delete obj.cdata;
                    }
                    s = stack[stack.length - 1];
                    if (obj[charkey].match(/^\s*$/) && !cdata) {
                        emptyStr = obj[charkey];
                        delete obj[charkey];
                    } else {
                        if (_this.options.trim) obj[charkey] = obj[charkey].trim();
                        if (_this.options.normalize) obj[charkey] = obj[charkey].replace(/\s{2,}/g, " ").trim();
                        obj[charkey] = _this.options.valueProcessors ? processItem(_this.options.valueProcessors, obj[charkey], nodeName) : obj[charkey];
                        if (Object.keys(obj).length === 1 && charkey in obj && !_this.EXPLICIT_CHARKEY) obj = obj[charkey];
                    }
                    if (isEmpty(obj)) {
                        if (typeof _this.options.emptyTag === 'function') obj = _this.options.emptyTag();
                        else obj = _this.options.emptyTag !== '' ? _this.options.emptyTag : emptyStr;
                    }
                    if (_this.options.validator != null) {
                        xpath = "/" + (function() {
                            var i, len, results;
                            results = [];
                            for(i = 0, len = stack.length; i < len; i++){
                                node = stack[i];
                                results.push(node["#name"]);
                            }
                            return results;
                        })().concat(nodeName).join("/");
                        (function() {
                            var err;
                            try {
                                return obj = _this.options.validator(xpath, s && s[nodeName], obj);
                            } catch (error1) {
                                err = error1;
                                return _this.emit("error", err);
                            }
                        })();
                    }
                    if (_this.options.explicitChildren && !_this.options.mergeAttrs && typeof obj === 'object') {
                        if (!_this.options.preserveChildrenOrder) {
                            node = {};
                            if (_this.options.attrkey in obj) {
                                node[_this.options.attrkey] = obj[_this.options.attrkey];
                                delete obj[_this.options.attrkey];
                            }
                            if (!_this.options.charsAsChildren && _this.options.charkey in obj) {
                                node[_this.options.charkey] = obj[_this.options.charkey];
                                delete obj[_this.options.charkey];
                            }
                            if (Object.getOwnPropertyNames(obj).length > 0) node[_this.options.childkey] = obj;
                            obj = node;
                        } else if (s) {
                            s[_this.options.childkey] = s[_this.options.childkey] || [];
                            objClone = {};
                            for(key in obj){
                                if (!hasProp.call(obj, key)) continue;
                                defineProperty(objClone, key, obj[key]);
                            }
                            s[_this.options.childkey].push(objClone);
                            delete obj["#name"];
                            if (Object.keys(obj).length === 1 && charkey in obj && !_this.EXPLICIT_CHARKEY) obj = obj[charkey];
                        }
                    }
                    if (stack.length > 0) return _this.assignOrPush(s, nodeName, obj);
                    else {
                        if (_this.options.explicitRoot) {
                            old = obj;
                            obj = {};
                            defineProperty(obj, nodeName, old);
                        }
                        _this.resultObject = obj;
                        _this.saxParser.ended = true;
                        return _this.emit("end", _this.resultObject);
                    }
                };
            }(this);
            ontext = function(_this) {
                return function(text) {
                    var charChild, s;
                    s = stack[stack.length - 1];
                    if (s) {
                        s[charkey] += text;
                        if (_this.options.explicitChildren && _this.options.preserveChildrenOrder && _this.options.charsAsChildren && (_this.options.includeWhiteChars || text.replace(/\\n/g, '').trim() !== '')) {
                            s[_this.options.childkey] = s[_this.options.childkey] || [];
                            charChild = {
                                '#name': '__text__'
                            };
                            charChild[charkey] = text;
                            if (_this.options.normalize) charChild[charkey] = charChild[charkey].replace(/\s{2,}/g, " ").trim();
                            s[_this.options.childkey].push(charChild);
                        }
                        return s;
                    }
                };
            }(this);
            this.saxParser.ontext = ontext;
            return this.saxParser.oncdata = function(_this) {
                return function(text) {
                    var s;
                    s = ontext(text);
                    if (s) return s.cdata = true;
                };
            }(this);
        };
        Parser.prototype.parseString = function(str, cb) {
            var err;
            if (cb != null && typeof cb === "function") {
                this.on("end", function(result) {
                    this.reset();
                    return cb(null, result);
                });
                this.on("error", function(err) {
                    this.reset();
                    return cb(err);
                });
            }
            try {
                str = str.toString();
                if (str.trim() === '') {
                    this.emit("end", null);
                    return true;
                }
                str = bom.stripBOM(str);
                if (this.options.async) {
                    this.remaining = str;
                    setImmediate(this.processAsync);
                    return this.saxParser;
                }
                return this.saxParser.write(str).close();
            } catch (error1) {
                err = error1;
                if (!(this.saxParser.errThrown || this.saxParser.ended)) {
                    this.emit('error', err);
                    return this.saxParser.errThrown = true;
                } else if (this.saxParser.ended) throw err;
            }
        };
        Parser.prototype.parseStringPromise = function(str) {
            return new Promise(function(_this) {
                return function(resolve, reject) {
                    return _this.parseString(str, function(err, value) {
                        if (err) return reject(err);
                        else return resolve(value);
                    });
                };
            }(this));
        };
        return Parser;
    }(events);
    exports.parseString = function(str, a, b) {
        var cb, options, parser;
        if (b != null) {
            if (typeof b === 'function') cb = b;
            if (typeof a === 'object') options = a;
        } else {
            if (typeof a === 'function') cb = a;
            options = {};
        }
        parser = new exports.Parser(options);
        return parser.parseString(str, cb);
    };
    exports.parseStringPromise = function(str, a) {
        var options, parser;
        if (typeof a === 'object') options = a;
        parser = new exports.Parser(options);
        return parser.parseStringPromise(str);
    };
}).call(this);

});
parcelRegister("bCkjh", function(module, exports) {


(function(sax) {
    // wrapper for non-node envs
    sax.parser = function(strict, opt) {
        return new SAXParser(strict, opt);
    };
    sax.SAXParser = SAXParser;
    sax.SAXStream = SAXStream;
    sax.createStream = createStream;
    // When we pass the MAX_BUFFER_LENGTH position, start checking for buffer overruns.
    // When we check, schedule the next check for MAX_BUFFER_LENGTH - (max(buffer lengths)),
    // since that's the earliest that a buffer overrun could occur.  This way, checks are
    // as rare as required, but as often as necessary to ensure never crossing this bound.
    // Furthermore, buffers are only tested at most once per write(), so passing a very
    // large string into write() might have undesirable effects, but this is manageable by
    // the caller, so it is assumed to be safe.  Thus, a call to write() may, in the extreme
    // edge case, result in creating at most one complete copy of the string passed in.
    // Set to Infinity to have unlimited buffers.
    sax.MAX_BUFFER_LENGTH = 65536;
    var buffers = [
        'comment',
        'sgmlDecl',
        'textNode',
        'tagName',
        'doctype',
        'procInstName',
        'procInstBody',
        'entity',
        'attribName',
        'attribValue',
        'cdata',
        'script'
    ];
    sax.EVENTS = [
        'text',
        'processinginstruction',
        'sgmldeclaration',
        'doctype',
        'comment',
        'opentagstart',
        'attribute',
        'opentag',
        'closetag',
        'opencdata',
        'cdata',
        'closecdata',
        'error',
        'end',
        'ready',
        'script',
        'opennamespace',
        'closenamespace'
    ];
    function SAXParser(strict, opt) {
        if (!(this instanceof SAXParser)) return new SAXParser(strict, opt);
        var parser = this;
        clearBuffers(parser);
        parser.q = parser.c = '';
        parser.bufferCheckPosition = sax.MAX_BUFFER_LENGTH;
        parser.opt = opt || {};
        parser.opt.lowercase = parser.opt.lowercase || parser.opt.lowercasetags;
        parser.looseCase = parser.opt.lowercase ? 'toLowerCase' : 'toUpperCase';
        parser.tags = [];
        parser.closed = parser.closedRoot = parser.sawRoot = false;
        parser.tag = parser.error = null;
        parser.strict = !!strict;
        parser.noscript = !!(strict || parser.opt.noscript);
        parser.state = S.BEGIN;
        parser.strictEntities = parser.opt.strictEntities;
        parser.ENTITIES = parser.strictEntities ? Object.create(sax.XML_ENTITIES) : Object.create(sax.ENTITIES);
        parser.attribList = [];
        // namespaces form a prototype chain.
        // it always points at the current tag,
        // which protos to its parent tag.
        if (parser.opt.xmlns) parser.ns = Object.create(rootNS);
        // disallow unquoted attribute values if not otherwise configured
        // and strict mode is true
        if (parser.opt.unquotedAttributeValues === undefined) parser.opt.unquotedAttributeValues = !strict;
        // mostly just for error reporting
        parser.trackPosition = parser.opt.position !== false;
        if (parser.trackPosition) parser.position = parser.line = parser.column = 0;
        emit(parser, 'onready');
    }
    if (!Object.create) Object.create = function(o) {
        function F() {}
        F.prototype = o;
        var newf = new F();
        return newf;
    };
    if (!Object.keys) Object.keys = function(o) {
        var a = [];
        for(var i in o)if (o.hasOwnProperty(i)) a.push(i);
        return a;
    };
    function checkBufferLength(parser) {
        var maxAllowed = Math.max(sax.MAX_BUFFER_LENGTH, 10);
        var maxActual = 0;
        for(var i = 0, l = buffers.length; i < l; i++){
            var len = parser[buffers[i]].length;
            if (len > maxAllowed) // Text/cdata nodes can get big, and since they're buffered,
            // we can get here under normal conditions.
            // Avoid issues by emitting the text node now,
            // so at least it won't get any bigger.
            switch(buffers[i]){
                case 'textNode':
                    closeText(parser);
                    break;
                case 'cdata':
                    emitNode(parser, 'oncdata', parser.cdata);
                    parser.cdata = '';
                    break;
                case 'script':
                    emitNode(parser, 'onscript', parser.script);
                    parser.script = '';
                    break;
                default:
                    error(parser, 'Max buffer length exceeded: ' + buffers[i]);
            }
            maxActual = Math.max(maxActual, len);
        }
        // schedule the next check for the earliest possible buffer overrun.
        var m = sax.MAX_BUFFER_LENGTH - maxActual;
        parser.bufferCheckPosition = m + parser.position;
    }
    function clearBuffers(parser) {
        for(var i = 0, l = buffers.length; i < l; i++)parser[buffers[i]] = '';
    }
    function flushBuffers(parser) {
        closeText(parser);
        if (parser.cdata !== '') {
            emitNode(parser, 'oncdata', parser.cdata);
            parser.cdata = '';
        }
        if (parser.script !== '') {
            emitNode(parser, 'onscript', parser.script);
            parser.script = '';
        }
    }
    SAXParser.prototype = {
        end: function() {
            end(this);
        },
        write: write,
        resume: function() {
            this.error = null;
            return this;
        },
        close: function() {
            return this.write(null);
        },
        flush: function() {
            flushBuffers(this);
        }
    };
    var Stream;
    try {
        Stream = $8752ff7254e8f466$import$dac342ec58acbb66$6a4eb2e7fc9e8903;
    } catch (ex) {
        Stream = function() {};
    }
    if (!Stream) Stream = function() {};
    var streamWraps = sax.EVENTS.filter(function(ev) {
        return ev !== 'error' && ev !== 'end';
    });
    function createStream(strict, opt) {
        return new SAXStream(strict, opt);
    }
    function SAXStream(strict, opt) {
        if (!(this instanceof SAXStream)) return new SAXStream(strict, opt);
        Stream.apply(this);
        this._parser = new SAXParser(strict, opt);
        this.writable = true;
        this.readable = true;
        var me = this;
        this._parser.onend = function() {
            me.emit('end');
        };
        this._parser.onerror = function(er) {
            me.emit('error', er);
            // if didn't throw, then means error was handled.
            // go ahead and clear error, so we can write again.
            me._parser.error = null;
        };
        this._decoder = null;
        streamWraps.forEach(function(ev) {
            Object.defineProperty(me, 'on' + ev, {
                get: function() {
                    return me._parser['on' + ev];
                },
                set: function(h) {
                    if (!h) {
                        me.removeAllListeners(ev);
                        me._parser['on' + ev] = h;
                        return h;
                    }
                    me.on(ev, h);
                },
                enumerable: true,
                configurable: false
            });
        });
    }
    SAXStream.prototype = Object.create(Stream.prototype, {
        constructor: {
            value: SAXStream
        }
    });
    SAXStream.prototype.write = function(data) {
        if (typeof Buffer === 'function' && typeof Buffer.isBuffer === 'function' && Buffer.isBuffer(data)) {
            if (!this._decoder) {
                var SD = $dDec7$string_decoder.StringDecoder;
                this._decoder = new SD('utf8');
            }
            data = this._decoder.write(data);
        }
        this._parser.write(data.toString());
        this.emit('data', data);
        return true;
    };
    SAXStream.prototype.end = function(chunk) {
        if (chunk && chunk.length) this.write(chunk);
        this._parser.end();
        return true;
    };
    SAXStream.prototype.on = function(ev, handler) {
        var me = this;
        if (!me._parser['on' + ev] && streamWraps.indexOf(ev) !== -1) me._parser['on' + ev] = function() {
            var args = arguments.length === 1 ? [
                arguments[0]
            ] : Array.apply(null, arguments);
            args.splice(0, 0, ev);
            me.emit.apply(me, args);
        };
        return Stream.prototype.on.call(me, ev, handler);
    };
    // this really needs to be replaced with character classes.
    // XML allows all manner of ridiculous numbers and digits.
    var CDATA = '[CDATA[';
    var DOCTYPE = 'DOCTYPE';
    var XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace';
    var XMLNS_NAMESPACE = 'http://www.w3.org/2000/xmlns/';
    var rootNS = {
        xml: XML_NAMESPACE,
        xmlns: XMLNS_NAMESPACE
    };
    // http://www.w3.org/TR/REC-xml/#NT-NameStartChar
    // This implementation works on strings, a single character at a time
    // as such, it cannot ever support astral-plane characters (10000-EFFFF)
    // without a significant breaking change to either this  parser, or the
    // JavaScript language.  Implementation of an emoji-capable xml parser
    // is left as an exercise for the reader.
    var nameStart = /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/;
    var nameBody = /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040.\d-]/;
    var entityStart = /[#:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/;
    var entityBody = /[#:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040.\d-]/;
    function isWhitespace(c) {
        return c === ' ' || c === '\n' || c === '\r' || c === '\t';
    }
    function isQuote(c) {
        return c === '"' || c === "'";
    }
    function isAttribEnd(c) {
        return c === '>' || isWhitespace(c);
    }
    function isMatch(regex, c) {
        return regex.test(c);
    }
    function notMatch(regex, c) {
        return !isMatch(regex, c);
    }
    var S = 0;
    sax.STATE = {
        BEGIN: S++,
        BEGIN_WHITESPACE: S++,
        TEXT: S++,
        TEXT_ENTITY: S++,
        OPEN_WAKA: S++,
        SGML_DECL: S++,
        SGML_DECL_QUOTED: S++,
        DOCTYPE: S++,
        DOCTYPE_QUOTED: S++,
        DOCTYPE_DTD: S++,
        DOCTYPE_DTD_QUOTED: S++,
        COMMENT_STARTING: S++,
        COMMENT: S++,
        COMMENT_ENDING: S++,
        COMMENT_ENDED: S++,
        CDATA: S++,
        CDATA_ENDING: S++,
        CDATA_ENDING_2: S++,
        PROC_INST: S++,
        PROC_INST_BODY: S++,
        PROC_INST_ENDING: S++,
        OPEN_TAG: S++,
        OPEN_TAG_SLASH: S++,
        ATTRIB: S++,
        ATTRIB_NAME: S++,
        ATTRIB_NAME_SAW_WHITE: S++,
        ATTRIB_VALUE: S++,
        ATTRIB_VALUE_QUOTED: S++,
        ATTRIB_VALUE_CLOSED: S++,
        ATTRIB_VALUE_UNQUOTED: S++,
        ATTRIB_VALUE_ENTITY_Q: S++,
        ATTRIB_VALUE_ENTITY_U: S++,
        CLOSE_TAG: S++,
        CLOSE_TAG_SAW_WHITE: S++,
        SCRIPT: S++,
        SCRIPT_ENDING: S++
    };
    sax.XML_ENTITIES = {
        amp: '&',
        gt: '>',
        lt: '<',
        quot: '"',
        apos: "'"
    };
    sax.ENTITIES = {
        amp: '&',
        gt: '>',
        lt: '<',
        quot: '"',
        apos: "'",
        AElig: 198,
        Aacute: 193,
        Acirc: 194,
        Agrave: 192,
        Aring: 197,
        Atilde: 195,
        Auml: 196,
        Ccedil: 199,
        ETH: 208,
        Eacute: 201,
        Ecirc: 202,
        Egrave: 200,
        Euml: 203,
        Iacute: 205,
        Icirc: 206,
        Igrave: 204,
        Iuml: 207,
        Ntilde: 209,
        Oacute: 211,
        Ocirc: 212,
        Ograve: 210,
        Oslash: 216,
        Otilde: 213,
        Ouml: 214,
        THORN: 222,
        Uacute: 218,
        Ucirc: 219,
        Ugrave: 217,
        Uuml: 220,
        Yacute: 221,
        aacute: 225,
        acirc: 226,
        aelig: 230,
        agrave: 224,
        aring: 229,
        atilde: 227,
        auml: 228,
        ccedil: 231,
        eacute: 233,
        ecirc: 234,
        egrave: 232,
        eth: 240,
        euml: 235,
        iacute: 237,
        icirc: 238,
        igrave: 236,
        iuml: 239,
        ntilde: 241,
        oacute: 243,
        ocirc: 244,
        ograve: 242,
        oslash: 248,
        otilde: 245,
        ouml: 246,
        szlig: 223,
        thorn: 254,
        uacute: 250,
        ucirc: 251,
        ugrave: 249,
        uuml: 252,
        yacute: 253,
        yuml: 255,
        copy: 169,
        reg: 174,
        nbsp: 160,
        iexcl: 161,
        cent: 162,
        pound: 163,
        curren: 164,
        yen: 165,
        brvbar: 166,
        sect: 167,
        uml: 168,
        ordf: 170,
        laquo: 171,
        not: 172,
        shy: 173,
        macr: 175,
        deg: 176,
        plusmn: 177,
        sup1: 185,
        sup2: 178,
        sup3: 179,
        acute: 180,
        micro: 181,
        para: 182,
        middot: 183,
        cedil: 184,
        ordm: 186,
        raquo: 187,
        frac14: 188,
        frac12: 189,
        frac34: 190,
        iquest: 191,
        times: 215,
        divide: 247,
        OElig: 338,
        oelig: 339,
        Scaron: 352,
        scaron: 353,
        Yuml: 376,
        fnof: 402,
        circ: 710,
        tilde: 732,
        Alpha: 913,
        Beta: 914,
        Gamma: 915,
        Delta: 916,
        Epsilon: 917,
        Zeta: 918,
        Eta: 919,
        Theta: 920,
        Iota: 921,
        Kappa: 922,
        Lambda: 923,
        Mu: 924,
        Nu: 925,
        Xi: 926,
        Omicron: 927,
        Pi: 928,
        Rho: 929,
        Sigma: 931,
        Tau: 932,
        Upsilon: 933,
        Phi: 934,
        Chi: 935,
        Psi: 936,
        Omega: 937,
        alpha: 945,
        beta: 946,
        gamma: 947,
        delta: 948,
        epsilon: 949,
        zeta: 950,
        eta: 951,
        theta: 952,
        iota: 953,
        kappa: 954,
        lambda: 955,
        mu: 956,
        nu: 957,
        xi: 958,
        omicron: 959,
        pi: 960,
        rho: 961,
        sigmaf: 962,
        sigma: 963,
        tau: 964,
        upsilon: 965,
        phi: 966,
        chi: 967,
        psi: 968,
        omega: 969,
        thetasym: 977,
        upsih: 978,
        piv: 982,
        ensp: 8194,
        emsp: 8195,
        thinsp: 8201,
        zwnj: 8204,
        zwj: 8205,
        lrm: 8206,
        rlm: 8207,
        ndash: 8211,
        mdash: 8212,
        lsquo: 8216,
        rsquo: 8217,
        sbquo: 8218,
        ldquo: 8220,
        rdquo: 8221,
        bdquo: 8222,
        dagger: 8224,
        Dagger: 8225,
        bull: 8226,
        hellip: 8230,
        permil: 8240,
        prime: 8242,
        Prime: 8243,
        lsaquo: 8249,
        rsaquo: 8250,
        oline: 8254,
        frasl: 8260,
        euro: 8364,
        image: 8465,
        weierp: 8472,
        real: 8476,
        trade: 8482,
        alefsym: 8501,
        larr: 8592,
        uarr: 8593,
        rarr: 8594,
        darr: 8595,
        harr: 8596,
        crarr: 8629,
        lArr: 8656,
        uArr: 8657,
        rArr: 8658,
        dArr: 8659,
        hArr: 8660,
        forall: 8704,
        part: 8706,
        exist: 8707,
        empty: 8709,
        nabla: 8711,
        isin: 8712,
        notin: 8713,
        ni: 8715,
        prod: 8719,
        sum: 8721,
        minus: 8722,
        lowast: 8727,
        radic: 8730,
        prop: 8733,
        infin: 8734,
        ang: 8736,
        and: 8743,
        or: 8744,
        cap: 8745,
        cup: 8746,
        int: 8747,
        there4: 8756,
        sim: 8764,
        cong: 8773,
        asymp: 8776,
        ne: 8800,
        equiv: 8801,
        le: 8804,
        ge: 8805,
        sub: 8834,
        sup: 8835,
        nsub: 8836,
        sube: 8838,
        supe: 8839,
        oplus: 8853,
        otimes: 8855,
        perp: 8869,
        sdot: 8901,
        lceil: 8968,
        rceil: 8969,
        lfloor: 8970,
        rfloor: 8971,
        lang: 9001,
        rang: 9002,
        loz: 9674,
        spades: 9824,
        clubs: 9827,
        hearts: 9829,
        diams: 9830
    };
    Object.keys(sax.ENTITIES).forEach(function(key) {
        var e = sax.ENTITIES[key];
        var s = typeof e === 'number' ? String.fromCharCode(e) : e;
        sax.ENTITIES[key] = s;
    });
    for(var s in sax.STATE)sax.STATE[sax.STATE[s]] = s;
    // shorthand
    S = sax.STATE;
    function emit(parser, event, data) {
        parser[event] && parser[event](data);
    }
    function emitNode(parser, nodeType, data) {
        if (parser.textNode) closeText(parser);
        emit(parser, nodeType, data);
    }
    function closeText(parser) {
        parser.textNode = textopts(parser.opt, parser.textNode);
        if (parser.textNode) emit(parser, 'ontext', parser.textNode);
        parser.textNode = '';
    }
    function textopts(opt, text) {
        if (opt.trim) text = text.trim();
        if (opt.normalize) text = text.replace(/\s+/g, ' ');
        return text;
    }
    function error(parser, er) {
        closeText(parser);
        if (parser.trackPosition) er += '\nLine: ' + parser.line + '\nColumn: ' + parser.column + '\nChar: ' + parser.c;
        er = new Error(er);
        parser.error = er;
        emit(parser, 'onerror', er);
        return parser;
    }
    function end(parser) {
        if (parser.sawRoot && !parser.closedRoot) strictFail(parser, 'Unclosed root tag');
        if (parser.state !== S.BEGIN && parser.state !== S.BEGIN_WHITESPACE && parser.state !== S.TEXT) error(parser, 'Unexpected end');
        closeText(parser);
        parser.c = '';
        parser.closed = true;
        emit(parser, 'onend');
        SAXParser.call(parser, parser.strict, parser.opt);
        return parser;
    }
    function strictFail(parser, message) {
        if (typeof parser !== 'object' || !(parser instanceof SAXParser)) throw new Error('bad call to strictFail');
        if (parser.strict) error(parser, message);
    }
    function newTag(parser) {
        if (!parser.strict) parser.tagName = parser.tagName[parser.looseCase]();
        var parent = parser.tags[parser.tags.length - 1] || parser;
        var tag = parser.tag = {
            name: parser.tagName,
            attributes: {}
        };
        // will be overridden if tag contails an xmlns="foo" or xmlns:foo="bar"
        if (parser.opt.xmlns) tag.ns = parent.ns;
        parser.attribList.length = 0;
        emitNode(parser, 'onopentagstart', tag);
    }
    function qname(name, attribute) {
        var i = name.indexOf(':');
        var qualName = i < 0 ? [
            '',
            name
        ] : name.split(':');
        var prefix = qualName[0];
        var local = qualName[1];
        // <x "xmlns"="http://foo">
        if (attribute && name === 'xmlns') {
            prefix = 'xmlns';
            local = '';
        }
        return {
            prefix: prefix,
            local: local
        };
    }
    function attrib(parser) {
        if (!parser.strict) parser.attribName = parser.attribName[parser.looseCase]();
        if (parser.attribList.indexOf(parser.attribName) !== -1 || parser.tag.attributes.hasOwnProperty(parser.attribName)) {
            parser.attribName = parser.attribValue = '';
            return;
        }
        if (parser.opt.xmlns) {
            var qn = qname(parser.attribName, true);
            var prefix = qn.prefix;
            var local = qn.local;
            if (prefix === 'xmlns') {
                // namespace binding attribute. push the binding into scope
                if (local === 'xml' && parser.attribValue !== XML_NAMESPACE) strictFail(parser, 'xml: prefix must be bound to ' + XML_NAMESPACE + '\n' + 'Actual: ' + parser.attribValue);
                else if (local === 'xmlns' && parser.attribValue !== XMLNS_NAMESPACE) strictFail(parser, 'xmlns: prefix must be bound to ' + XMLNS_NAMESPACE + '\n' + 'Actual: ' + parser.attribValue);
                else {
                    var tag = parser.tag;
                    var parent = parser.tags[parser.tags.length - 1] || parser;
                    if (tag.ns === parent.ns) tag.ns = Object.create(parent.ns);
                    tag.ns[local] = parser.attribValue;
                }
            }
            // defer onattribute events until all attributes have been seen
            // so any new bindings can take effect. preserve attribute order
            // so deferred events can be emitted in document order
            parser.attribList.push([
                parser.attribName,
                parser.attribValue
            ]);
        } else {
            // in non-xmlns mode, we can emit the event right away
            parser.tag.attributes[parser.attribName] = parser.attribValue;
            emitNode(parser, 'onattribute', {
                name: parser.attribName,
                value: parser.attribValue
            });
        }
        parser.attribName = parser.attribValue = '';
    }
    function openTag(parser, selfClosing) {
        if (parser.opt.xmlns) {
            // emit namespace binding events
            var tag = parser.tag;
            // add namespace info to tag
            var qn = qname(parser.tagName);
            tag.prefix = qn.prefix;
            tag.local = qn.local;
            tag.uri = tag.ns[qn.prefix] || '';
            if (tag.prefix && !tag.uri) {
                strictFail(parser, 'Unbound namespace prefix: ' + JSON.stringify(parser.tagName));
                tag.uri = qn.prefix;
            }
            var parent = parser.tags[parser.tags.length - 1] || parser;
            if (tag.ns && parent.ns !== tag.ns) Object.keys(tag.ns).forEach(function(p) {
                emitNode(parser, 'onopennamespace', {
                    prefix: p,
                    uri: tag.ns[p]
                });
            });
            // handle deferred onattribute events
            // Note: do not apply default ns to attributes:
            //   http://www.w3.org/TR/REC-xml-names/#defaulting
            for(var i = 0, l = parser.attribList.length; i < l; i++){
                var nv = parser.attribList[i];
                var name = nv[0];
                var value = nv[1];
                var qualName = qname(name, true);
                var prefix = qualName.prefix;
                var local = qualName.local;
                var uri = prefix === '' ? '' : tag.ns[prefix] || '';
                var a = {
                    name: name,
                    value: value,
                    prefix: prefix,
                    local: local,
                    uri: uri
                };
                // if there's any attributes with an undefined namespace,
                // then fail on them now.
                if (prefix && prefix !== 'xmlns' && !uri) {
                    strictFail(parser, 'Unbound namespace prefix: ' + JSON.stringify(prefix));
                    a.uri = prefix;
                }
                parser.tag.attributes[name] = a;
                emitNode(parser, 'onattribute', a);
            }
            parser.attribList.length = 0;
        }
        parser.tag.isSelfClosing = !!selfClosing;
        // process the tag
        parser.sawRoot = true;
        parser.tags.push(parser.tag);
        emitNode(parser, 'onopentag', parser.tag);
        if (!selfClosing) {
            // special case for <script> in non-strict mode.
            if (!parser.noscript && parser.tagName.toLowerCase() === 'script') parser.state = S.SCRIPT;
            else parser.state = S.TEXT;
            parser.tag = null;
            parser.tagName = '';
        }
        parser.attribName = parser.attribValue = '';
        parser.attribList.length = 0;
    }
    function closeTag(parser) {
        if (!parser.tagName) {
            strictFail(parser, 'Weird empty close tag.');
            parser.textNode += '</>';
            parser.state = S.TEXT;
            return;
        }
        if (parser.script) {
            if (parser.tagName !== 'script') {
                parser.script += '</' + parser.tagName + '>';
                parser.tagName = '';
                parser.state = S.SCRIPT;
                return;
            }
            emitNode(parser, 'onscript', parser.script);
            parser.script = '';
        }
        // first make sure that the closing tag actually exists.
        // <a><b></c></b></a> will close everything, otherwise.
        var t = parser.tags.length;
        var tagName = parser.tagName;
        if (!parser.strict) tagName = tagName[parser.looseCase]();
        var closeTo = tagName;
        while(t--){
            var close = parser.tags[t];
            if (close.name !== closeTo) // fail the first time in strict mode
            strictFail(parser, 'Unexpected close tag');
            else break;
        }
        // didn't find it.  we already failed for strict, so just abort.
        if (t < 0) {
            strictFail(parser, 'Unmatched closing tag: ' + parser.tagName);
            parser.textNode += '</' + parser.tagName + '>';
            parser.state = S.TEXT;
            return;
        }
        parser.tagName = tagName;
        var s = parser.tags.length;
        while(s-- > t){
            var tag = parser.tag = parser.tags.pop();
            parser.tagName = parser.tag.name;
            emitNode(parser, 'onclosetag', parser.tagName);
            var x = {};
            for(var i in tag.ns)x[i] = tag.ns[i];
            var parent = parser.tags[parser.tags.length - 1] || parser;
            if (parser.opt.xmlns && tag.ns !== parent.ns) // remove namespace bindings introduced by tag
            Object.keys(tag.ns).forEach(function(p) {
                var n = tag.ns[p];
                emitNode(parser, 'onclosenamespace', {
                    prefix: p,
                    uri: n
                });
            });
        }
        if (t === 0) parser.closedRoot = true;
        parser.tagName = parser.attribValue = parser.attribName = '';
        parser.attribList.length = 0;
        parser.state = S.TEXT;
    }
    function parseEntity(parser) {
        var entity = parser.entity;
        var entityLC = entity.toLowerCase();
        var num;
        var numStr = '';
        if (parser.ENTITIES[entity]) return parser.ENTITIES[entity];
        if (parser.ENTITIES[entityLC]) return parser.ENTITIES[entityLC];
        entity = entityLC;
        if (entity.charAt(0) === '#') {
            if (entity.charAt(1) === 'x') {
                entity = entity.slice(2);
                num = parseInt(entity, 16);
                numStr = num.toString(16);
            } else {
                entity = entity.slice(1);
                num = parseInt(entity, 10);
                numStr = num.toString(10);
            }
        }
        entity = entity.replace(/^0+/, '');
        if (isNaN(num) || numStr.toLowerCase() !== entity || num < 0 || num > 0x10ffff) {
            strictFail(parser, 'Invalid character entity');
            return '&' + parser.entity + ';';
        }
        return String.fromCodePoint(num);
    }
    function beginWhiteSpace(parser, c) {
        if (c === '<') {
            parser.state = S.OPEN_WAKA;
            parser.startTagPosition = parser.position;
        } else if (!isWhitespace(c)) {
            // have to process this as a text node.
            // weird, but happens.
            strictFail(parser, 'Non-whitespace before first tag.');
            parser.textNode = c;
            parser.state = S.TEXT;
        }
    }
    function charAt(chunk, i) {
        var result = '';
        if (i < chunk.length) result = chunk.charAt(i);
        return result;
    }
    function write(chunk) {
        var parser = this;
        if (this.error) throw this.error;
        if (parser.closed) return error(parser, 'Cannot write after close. Assign an onready handler.');
        if (chunk === null) return end(parser);
        if (typeof chunk === 'object') chunk = chunk.toString();
        var i = 0;
        var c = '';
        while(true){
            c = charAt(chunk, i++);
            parser.c = c;
            if (!c) break;
            if (parser.trackPosition) {
                parser.position++;
                if (c === '\n') {
                    parser.line++;
                    parser.column = 0;
                } else parser.column++;
            }
            switch(parser.state){
                case S.BEGIN:
                    parser.state = S.BEGIN_WHITESPACE;
                    if (c === '\uFEFF') continue;
                    beginWhiteSpace(parser, c);
                    continue;
                case S.BEGIN_WHITESPACE:
                    beginWhiteSpace(parser, c);
                    continue;
                case S.TEXT:
                    if (parser.sawRoot && !parser.closedRoot) {
                        var starti = i - 1;
                        while(c && c !== '<' && c !== '&'){
                            c = charAt(chunk, i++);
                            if (c && parser.trackPosition) {
                                parser.position++;
                                if (c === '\n') {
                                    parser.line++;
                                    parser.column = 0;
                                } else parser.column++;
                            }
                        }
                        parser.textNode += chunk.substring(starti, i - 1);
                    }
                    if (c === '<' && !(parser.sawRoot && parser.closedRoot && !parser.strict)) {
                        parser.state = S.OPEN_WAKA;
                        parser.startTagPosition = parser.position;
                    } else {
                        if (!isWhitespace(c) && (!parser.sawRoot || parser.closedRoot)) strictFail(parser, 'Text data outside of root node.');
                        if (c === '&') parser.state = S.TEXT_ENTITY;
                        else parser.textNode += c;
                    }
                    continue;
                case S.SCRIPT:
                    // only non-strict
                    if (c === '<') parser.state = S.SCRIPT_ENDING;
                    else parser.script += c;
                    continue;
                case S.SCRIPT_ENDING:
                    if (c === '/') parser.state = S.CLOSE_TAG;
                    else {
                        parser.script += '<' + c;
                        parser.state = S.SCRIPT;
                    }
                    continue;
                case S.OPEN_WAKA:
                    // either a /, ?, !, or text is coming next.
                    if (c === '!') {
                        parser.state = S.SGML_DECL;
                        parser.sgmlDecl = '';
                    } else if (isWhitespace(c)) ;
                    else if (isMatch(nameStart, c)) {
                        parser.state = S.OPEN_TAG;
                        parser.tagName = c;
                    } else if (c === '/') {
                        parser.state = S.CLOSE_TAG;
                        parser.tagName = '';
                    } else if (c === '?') {
                        parser.state = S.PROC_INST;
                        parser.procInstName = parser.procInstBody = '';
                    } else {
                        strictFail(parser, 'Unencoded <');
                        // if there was some whitespace, then add that in.
                        if (parser.startTagPosition + 1 < parser.position) {
                            var pad = parser.position - parser.startTagPosition;
                            c = new Array(pad).join(' ') + c;
                        }
                        parser.textNode += '<' + c;
                        parser.state = S.TEXT;
                    }
                    continue;
                case S.SGML_DECL:
                    if (parser.sgmlDecl + c === '--') {
                        parser.state = S.COMMENT;
                        parser.comment = '';
                        parser.sgmlDecl = '';
                        continue;
                    }
                    if (parser.doctype && parser.doctype !== true && parser.sgmlDecl) {
                        parser.state = S.DOCTYPE_DTD;
                        parser.doctype += '<!' + parser.sgmlDecl + c;
                        parser.sgmlDecl = '';
                    } else if ((parser.sgmlDecl + c).toUpperCase() === CDATA) {
                        emitNode(parser, 'onopencdata');
                        parser.state = S.CDATA;
                        parser.sgmlDecl = '';
                        parser.cdata = '';
                    } else if ((parser.sgmlDecl + c).toUpperCase() === DOCTYPE) {
                        parser.state = S.DOCTYPE;
                        if (parser.doctype || parser.sawRoot) strictFail(parser, 'Inappropriately located doctype declaration');
                        parser.doctype = '';
                        parser.sgmlDecl = '';
                    } else if (c === '>') {
                        emitNode(parser, 'onsgmldeclaration', parser.sgmlDecl);
                        parser.sgmlDecl = '';
                        parser.state = S.TEXT;
                    } else if (isQuote(c)) {
                        parser.state = S.SGML_DECL_QUOTED;
                        parser.sgmlDecl += c;
                    } else parser.sgmlDecl += c;
                    continue;
                case S.SGML_DECL_QUOTED:
                    if (c === parser.q) {
                        parser.state = S.SGML_DECL;
                        parser.q = '';
                    }
                    parser.sgmlDecl += c;
                    continue;
                case S.DOCTYPE:
                    if (c === '>') {
                        parser.state = S.TEXT;
                        emitNode(parser, 'ondoctype', parser.doctype);
                        parser.doctype = true // just remember that we saw it.
                        ;
                    } else {
                        parser.doctype += c;
                        if (c === '[') parser.state = S.DOCTYPE_DTD;
                        else if (isQuote(c)) {
                            parser.state = S.DOCTYPE_QUOTED;
                            parser.q = c;
                        }
                    }
                    continue;
                case S.DOCTYPE_QUOTED:
                    parser.doctype += c;
                    if (c === parser.q) {
                        parser.q = '';
                        parser.state = S.DOCTYPE;
                    }
                    continue;
                case S.DOCTYPE_DTD:
                    if (c === ']') {
                        parser.doctype += c;
                        parser.state = S.DOCTYPE;
                    } else if (c === '<') {
                        parser.state = S.OPEN_WAKA;
                        parser.startTagPosition = parser.position;
                    } else if (isQuote(c)) {
                        parser.doctype += c;
                        parser.state = S.DOCTYPE_DTD_QUOTED;
                        parser.q = c;
                    } else parser.doctype += c;
                    continue;
                case S.DOCTYPE_DTD_QUOTED:
                    parser.doctype += c;
                    if (c === parser.q) {
                        parser.state = S.DOCTYPE_DTD;
                        parser.q = '';
                    }
                    continue;
                case S.COMMENT:
                    if (c === '-') parser.state = S.COMMENT_ENDING;
                    else parser.comment += c;
                    continue;
                case S.COMMENT_ENDING:
                    if (c === '-') {
                        parser.state = S.COMMENT_ENDED;
                        parser.comment = textopts(parser.opt, parser.comment);
                        if (parser.comment) emitNode(parser, 'oncomment', parser.comment);
                        parser.comment = '';
                    } else {
                        parser.comment += '-' + c;
                        parser.state = S.COMMENT;
                    }
                    continue;
                case S.COMMENT_ENDED:
                    if (c !== '>') {
                        strictFail(parser, 'Malformed comment');
                        // allow <!-- blah -- bloo --> in non-strict mode,
                        // which is a comment of " blah -- bloo "
                        parser.comment += '--' + c;
                        parser.state = S.COMMENT;
                    } else if (parser.doctype && parser.doctype !== true) parser.state = S.DOCTYPE_DTD;
                    else parser.state = S.TEXT;
                    continue;
                case S.CDATA:
                    var starti = i - 1;
                    while(c && c !== ']'){
                        c = charAt(chunk, i++);
                        if (c && parser.trackPosition) {
                            parser.position++;
                            if (c === '\n') {
                                parser.line++;
                                parser.column = 0;
                            } else parser.column++;
                        }
                    }
                    parser.cdata += chunk.substring(starti, i - 1);
                    if (c === ']') parser.state = S.CDATA_ENDING;
                    continue;
                case S.CDATA_ENDING:
                    if (c === ']') parser.state = S.CDATA_ENDING_2;
                    else {
                        parser.cdata += ']' + c;
                        parser.state = S.CDATA;
                    }
                    continue;
                case S.CDATA_ENDING_2:
                    if (c === '>') {
                        if (parser.cdata) emitNode(parser, 'oncdata', parser.cdata);
                        emitNode(parser, 'onclosecdata');
                        parser.cdata = '';
                        parser.state = S.TEXT;
                    } else if (c === ']') parser.cdata += ']';
                    else {
                        parser.cdata += ']]' + c;
                        parser.state = S.CDATA;
                    }
                    continue;
                case S.PROC_INST:
                    if (c === '?') parser.state = S.PROC_INST_ENDING;
                    else if (isWhitespace(c)) parser.state = S.PROC_INST_BODY;
                    else parser.procInstName += c;
                    continue;
                case S.PROC_INST_BODY:
                    if (!parser.procInstBody && isWhitespace(c)) continue;
                    else if (c === '?') parser.state = S.PROC_INST_ENDING;
                    else parser.procInstBody += c;
                    continue;
                case S.PROC_INST_ENDING:
                    if (c === '>') {
                        emitNode(parser, 'onprocessinginstruction', {
                            name: parser.procInstName,
                            body: parser.procInstBody
                        });
                        parser.procInstName = parser.procInstBody = '';
                        parser.state = S.TEXT;
                    } else {
                        parser.procInstBody += '?' + c;
                        parser.state = S.PROC_INST_BODY;
                    }
                    continue;
                case S.OPEN_TAG:
                    if (isMatch(nameBody, c)) parser.tagName += c;
                    else {
                        newTag(parser);
                        if (c === '>') openTag(parser);
                        else if (c === '/') parser.state = S.OPEN_TAG_SLASH;
                        else {
                            if (!isWhitespace(c)) strictFail(parser, 'Invalid character in tag name');
                            parser.state = S.ATTRIB;
                        }
                    }
                    continue;
                case S.OPEN_TAG_SLASH:
                    if (c === '>') {
                        openTag(parser, true);
                        closeTag(parser);
                    } else {
                        strictFail(parser, 'Forward-slash in opening tag not followed by >');
                        parser.state = S.ATTRIB;
                    }
                    continue;
                case S.ATTRIB:
                    // haven't read the attribute name yet.
                    if (isWhitespace(c)) continue;
                    else if (c === '>') openTag(parser);
                    else if (c === '/') parser.state = S.OPEN_TAG_SLASH;
                    else if (isMatch(nameStart, c)) {
                        parser.attribName = c;
                        parser.attribValue = '';
                        parser.state = S.ATTRIB_NAME;
                    } else strictFail(parser, 'Invalid attribute name');
                    continue;
                case S.ATTRIB_NAME:
                    if (c === '=') parser.state = S.ATTRIB_VALUE;
                    else if (c === '>') {
                        strictFail(parser, 'Attribute without value');
                        parser.attribValue = parser.attribName;
                        attrib(parser);
                        openTag(parser);
                    } else if (isWhitespace(c)) parser.state = S.ATTRIB_NAME_SAW_WHITE;
                    else if (isMatch(nameBody, c)) parser.attribName += c;
                    else strictFail(parser, 'Invalid attribute name');
                    continue;
                case S.ATTRIB_NAME_SAW_WHITE:
                    if (c === '=') parser.state = S.ATTRIB_VALUE;
                    else if (isWhitespace(c)) continue;
                    else {
                        strictFail(parser, 'Attribute without value');
                        parser.tag.attributes[parser.attribName] = '';
                        parser.attribValue = '';
                        emitNode(parser, 'onattribute', {
                            name: parser.attribName,
                            value: ''
                        });
                        parser.attribName = '';
                        if (c === '>') openTag(parser);
                        else if (isMatch(nameStart, c)) {
                            parser.attribName = c;
                            parser.state = S.ATTRIB_NAME;
                        } else {
                            strictFail(parser, 'Invalid attribute name');
                            parser.state = S.ATTRIB;
                        }
                    }
                    continue;
                case S.ATTRIB_VALUE:
                    if (isWhitespace(c)) continue;
                    else if (isQuote(c)) {
                        parser.q = c;
                        parser.state = S.ATTRIB_VALUE_QUOTED;
                    } else {
                        if (!parser.opt.unquotedAttributeValues) error(parser, 'Unquoted attribute value');
                        parser.state = S.ATTRIB_VALUE_UNQUOTED;
                        parser.attribValue = c;
                    }
                    continue;
                case S.ATTRIB_VALUE_QUOTED:
                    if (c !== parser.q) {
                        if (c === '&') parser.state = S.ATTRIB_VALUE_ENTITY_Q;
                        else parser.attribValue += c;
                        continue;
                    }
                    attrib(parser);
                    parser.q = '';
                    parser.state = S.ATTRIB_VALUE_CLOSED;
                    continue;
                case S.ATTRIB_VALUE_CLOSED:
                    if (isWhitespace(c)) parser.state = S.ATTRIB;
                    else if (c === '>') openTag(parser);
                    else if (c === '/') parser.state = S.OPEN_TAG_SLASH;
                    else if (isMatch(nameStart, c)) {
                        strictFail(parser, 'No whitespace between attributes');
                        parser.attribName = c;
                        parser.attribValue = '';
                        parser.state = S.ATTRIB_NAME;
                    } else strictFail(parser, 'Invalid attribute name');
                    continue;
                case S.ATTRIB_VALUE_UNQUOTED:
                    if (!isAttribEnd(c)) {
                        if (c === '&') parser.state = S.ATTRIB_VALUE_ENTITY_U;
                        else parser.attribValue += c;
                        continue;
                    }
                    attrib(parser);
                    if (c === '>') openTag(parser);
                    else parser.state = S.ATTRIB;
                    continue;
                case S.CLOSE_TAG:
                    if (!parser.tagName) {
                        if (isWhitespace(c)) continue;
                        else if (notMatch(nameStart, c)) {
                            if (parser.script) {
                                parser.script += '</' + c;
                                parser.state = S.SCRIPT;
                            } else strictFail(parser, 'Invalid tagname in closing tag.');
                        } else parser.tagName = c;
                    } else if (c === '>') closeTag(parser);
                    else if (isMatch(nameBody, c)) parser.tagName += c;
                    else if (parser.script) {
                        parser.script += '</' + parser.tagName;
                        parser.tagName = '';
                        parser.state = S.SCRIPT;
                    } else {
                        if (!isWhitespace(c)) strictFail(parser, 'Invalid tagname in closing tag');
                        parser.state = S.CLOSE_TAG_SAW_WHITE;
                    }
                    continue;
                case S.CLOSE_TAG_SAW_WHITE:
                    if (isWhitespace(c)) continue;
                    if (c === '>') closeTag(parser);
                    else strictFail(parser, 'Invalid characters in closing tag');
                    continue;
                case S.TEXT_ENTITY:
                case S.ATTRIB_VALUE_ENTITY_Q:
                case S.ATTRIB_VALUE_ENTITY_U:
                    var returnState;
                    var buffer;
                    switch(parser.state){
                        case S.TEXT_ENTITY:
                            returnState = S.TEXT;
                            buffer = 'textNode';
                            break;
                        case S.ATTRIB_VALUE_ENTITY_Q:
                            returnState = S.ATTRIB_VALUE_QUOTED;
                            buffer = 'attribValue';
                            break;
                        case S.ATTRIB_VALUE_ENTITY_U:
                            returnState = S.ATTRIB_VALUE_UNQUOTED;
                            buffer = 'attribValue';
                            break;
                    }
                    if (c === ';') {
                        var parsedEntity = parseEntity(parser);
                        if (parser.opt.unparsedEntities && !Object.values(sax.XML_ENTITIES).includes(parsedEntity)) {
                            parser.entity = '';
                            parser.state = returnState;
                            parser.write(parsedEntity);
                        } else {
                            parser[buffer] += parsedEntity;
                            parser.entity = '';
                            parser.state = returnState;
                        }
                    } else if (isMatch(parser.entity.length ? entityBody : entityStart, c)) parser.entity += c;
                    else {
                        strictFail(parser, 'Invalid character in entity name');
                        parser[buffer] += '&' + parser.entity + c;
                        parser.entity = '';
                        parser.state = returnState;
                    }
                    continue;
                default:
                    throw new Error(parser, 'Unknown state: ' + parser.state);
            }
        } // while
        if (parser.position >= parser.bufferCheckPosition) checkBufferLength(parser);
        return parser;
    }
    /*! http://mths.be/fromcodepoint v0.1.0 by @mathias */ /* istanbul ignore next */ if (!String.fromCodePoint) (function() {
        var stringFromCharCode = String.fromCharCode;
        var floor = Math.floor;
        var fromCodePoint = function() {
            var MAX_SIZE = 0x4000;
            var codeUnits = [];
            var highSurrogate;
            var lowSurrogate;
            var index = -1;
            var length = arguments.length;
            if (!length) return '';
            var result = '';
            while(++index < length){
                var codePoint = Number(arguments[index]);
                if (!isFinite(codePoint) || // `NaN`, `+Infinity`, or `-Infinity`
                codePoint < 0 || // not a valid Unicode code point
                codePoint > 0x10ffff || // not a valid Unicode code point
                floor(codePoint) !== codePoint // not an integer
                ) throw RangeError('Invalid code point: ' + codePoint);
                if (codePoint <= 0xffff) // BMP code point
                codeUnits.push(codePoint);
                else {
                    // Astral code point; split in surrogate halves
                    // http://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
                    codePoint -= 0x10000;
                    highSurrogate = (codePoint >> 10) + 0xd800;
                    lowSurrogate = codePoint % 0x400 + 0xdc00;
                    codeUnits.push(highSurrogate, lowSurrogate);
                }
                if (index + 1 === length || codeUnits.length > MAX_SIZE) {
                    result += stringFromCharCode.apply(null, codeUnits);
                    codeUnits.length = 0;
                }
            }
            return result;
        };
        /* istanbul ignore next */ if (Object.defineProperty) Object.defineProperty(String, 'fromCodePoint', {
            value: fromCodePoint,
            configurable: true,
            writable: true
        });
        else String.fromCodePoint = fromCodePoint;
    })();
})(module.exports);

});

parcelRegister("dmzGi", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    "use strict";
    module.exports.stripBOM = function(str) {
        if (str[0] === '\uFEFF') return str.substring(1);
        else return str;
    };
}).call(module.exports);

});

parcelRegister("lh24m", function(module, exports) {
// Generated by CoffeeScript 1.12.7
(function() {
    "use strict";
    var prefixMatch;
    prefixMatch = new RegExp(/(?!xmlns)^.*:/);
    module.exports.normalize = function(str) {
        return str.toLowerCase();
    };
    module.exports.firstCharLowerCase = function(str) {
        return str.charAt(0).toLowerCase() + str.slice(1);
    };
    module.exports.stripPrefix = function(str) {
        return str.replace(prefixMatch, '');
    };
    module.exports.parseNumbers = function(str) {
        if (!isNaN(str)) str = str % 1 === 0 ? parseInt(str, 10) : parseFloat(str);
        return str;
    };
    module.exports.parseBooleans = function(str) {
        if (/^(?:true|false)$/i.test(str)) str = str.toLowerCase() === 'true';
        return str;
    };
}).call(module.exports);

});




parcelRegister("c7w72", function(module, exports) {
var $8d2f0c5f56a589d8$var$getEndpoint = function() {
    return {
        IPv4: 'http://169.254.169.254',
        IPv6: 'http://[fd00:ec2::254]'
    };
};
module.exports = $8d2f0c5f56a589d8$var$getEndpoint;

});

parcelRegister("2x6hq", function(module, exports) {
var $1d8388e9bbf3b5a1$var$getEndpointMode = function() {
    return {
        IPv4: 'IPv4',
        IPv6: 'IPv6'
    };
};
module.exports = $1d8388e9bbf3b5a1$var$getEndpointMode;

});

parcelRegister("hthfz", function(module, exports) {
var $cb8286985681cec1$var$ENV_ENDPOINT_NAME = 'AWS_EC2_METADATA_SERVICE_ENDPOINT';
var $cb8286985681cec1$var$CONFIG_ENDPOINT_NAME = 'ec2_metadata_service_endpoint';
var $cb8286985681cec1$var$getEndpointConfigOptions = function() {
    return {
        environmentVariableSelector: function(env) {
            return env[$cb8286985681cec1$var$ENV_ENDPOINT_NAME];
        },
        configFileSelector: function(profile) {
            return profile[$cb8286985681cec1$var$CONFIG_ENDPOINT_NAME];
        },
        default: undefined
    };
};
module.exports = $cb8286985681cec1$var$getEndpointConfigOptions;

});

parcelRegister("4NZFI", function(module, exports) {

var $37fb93c3567dcdea$var$EndpointMode = (parcelRequire("2x6hq"))();
var $37fb93c3567dcdea$var$ENV_ENDPOINT_MODE_NAME = 'AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE';
var $37fb93c3567dcdea$var$CONFIG_ENDPOINT_MODE_NAME = 'ec2_metadata_service_endpoint_mode';
var $37fb93c3567dcdea$var$getEndpointModeConfigOptions = function() {
    return {
        environmentVariableSelector: function(env) {
            return env[$37fb93c3567dcdea$var$ENV_ENDPOINT_MODE_NAME];
        },
        configFileSelector: function(profile) {
            return profile[$37fb93c3567dcdea$var$CONFIG_ENDPOINT_MODE_NAME];
        },
        default: $37fb93c3567dcdea$var$EndpointMode.IPv4
    };
};
module.exports = $37fb93c3567dcdea$var$getEndpointModeConfigOptions;

});

parcelRegister("jaRd3", function(module, exports) {
module.exports = JSON.parse("{\"version\":\"2.0\",\"metadata\":{\"apiVersion\":\"2011-06-15\",\"endpointPrefix\":\"sts\",\"globalEndpoint\":\"sts.amazonaws.com\",\"protocol\":\"query\",\"serviceAbbreviation\":\"AWS STS\",\"serviceFullName\":\"AWS Security Token Service\",\"serviceId\":\"STS\",\"signatureVersion\":\"v4\",\"uid\":\"sts-2011-06-15\",\"xmlNamespace\":\"https://sts.amazonaws.com/doc/2011-06-15/\"},\"operations\":{\"AssumeRole\":{\"input\":{\"type\":\"structure\",\"required\":[\"RoleArn\",\"RoleSessionName\"],\"members\":{\"RoleArn\":{},\"RoleSessionName\":{},\"PolicyArns\":{\"shape\":\"S4\"},\"Policy\":{},\"DurationSeconds\":{\"type\":\"integer\"},\"Tags\":{\"shape\":\"S8\"},\"TransitiveTagKeys\":{\"type\":\"list\",\"member\":{}},\"ExternalId\":{},\"SerialNumber\":{},\"TokenCode\":{},\"SourceIdentity\":{},\"ProvidedContexts\":{\"type\":\"list\",\"member\":{\"type\":\"structure\",\"members\":{\"ProviderArn\":{},\"ContextAssertion\":{}}}}}},\"output\":{\"resultWrapper\":\"AssumeRoleResult\",\"type\":\"structure\",\"members\":{\"Credentials\":{\"shape\":\"Sl\"},\"AssumedRoleUser\":{\"shape\":\"Sq\"},\"PackedPolicySize\":{\"type\":\"integer\"},\"SourceIdentity\":{}}}},\"AssumeRoleWithSAML\":{\"input\":{\"type\":\"structure\",\"required\":[\"RoleArn\",\"PrincipalArn\",\"SAMLAssertion\"],\"members\":{\"RoleArn\":{},\"PrincipalArn\":{},\"SAMLAssertion\":{\"type\":\"string\",\"sensitive\":true},\"PolicyArns\":{\"shape\":\"S4\"},\"Policy\":{},\"DurationSeconds\":{\"type\":\"integer\"}}},\"output\":{\"resultWrapper\":\"AssumeRoleWithSAMLResult\",\"type\":\"structure\",\"members\":{\"Credentials\":{\"shape\":\"Sl\"},\"AssumedRoleUser\":{\"shape\":\"Sq\"},\"PackedPolicySize\":{\"type\":\"integer\"},\"Subject\":{},\"SubjectType\":{},\"Issuer\":{},\"Audience\":{},\"NameQualifier\":{},\"SourceIdentity\":{}}}},\"AssumeRoleWithWebIdentity\":{\"input\":{\"type\":\"structure\",\"required\":[\"RoleArn\",\"RoleSessionName\",\"WebIdentityToken\"],\"members\":{\"RoleArn\":{},\"RoleSessionName\":{},\"WebIdentityToken\":{\"type\":\"string\",\"sensitive\":true},\"ProviderId\":{},\"PolicyArns\":{\"shape\":\"S4\"},\"Policy\":{},\"DurationSeconds\":{\"type\":\"integer\"}}},\"output\":{\"resultWrapper\":\"AssumeRoleWithWebIdentityResult\",\"type\":\"structure\",\"members\":{\"Credentials\":{\"shape\":\"Sl\"},\"SubjectFromWebIdentityToken\":{},\"AssumedRoleUser\":{\"shape\":\"Sq\"},\"PackedPolicySize\":{\"type\":\"integer\"},\"Provider\":{},\"Audience\":{},\"SourceIdentity\":{}}}},\"DecodeAuthorizationMessage\":{\"input\":{\"type\":\"structure\",\"required\":[\"EncodedMessage\"],\"members\":{\"EncodedMessage\":{}}},\"output\":{\"resultWrapper\":\"DecodeAuthorizationMessageResult\",\"type\":\"structure\",\"members\":{\"DecodedMessage\":{}}}},\"GetAccessKeyInfo\":{\"input\":{\"type\":\"structure\",\"required\":[\"AccessKeyId\"],\"members\":{\"AccessKeyId\":{}}},\"output\":{\"resultWrapper\":\"GetAccessKeyInfoResult\",\"type\":\"structure\",\"members\":{\"Account\":{}}}},\"GetCallerIdentity\":{\"input\":{\"type\":\"structure\",\"members\":{}},\"output\":{\"resultWrapper\":\"GetCallerIdentityResult\",\"type\":\"structure\",\"members\":{\"UserId\":{},\"Account\":{},\"Arn\":{}}}},\"GetFederationToken\":{\"input\":{\"type\":\"structure\",\"required\":[\"Name\"],\"members\":{\"Name\":{},\"Policy\":{},\"PolicyArns\":{\"shape\":\"S4\"},\"DurationSeconds\":{\"type\":\"integer\"},\"Tags\":{\"shape\":\"S8\"}}},\"output\":{\"resultWrapper\":\"GetFederationTokenResult\",\"type\":\"structure\",\"members\":{\"Credentials\":{\"shape\":\"Sl\"},\"FederatedUser\":{\"type\":\"structure\",\"required\":[\"FederatedUserId\",\"Arn\"],\"members\":{\"FederatedUserId\":{},\"Arn\":{}}},\"PackedPolicySize\":{\"type\":\"integer\"}}}},\"GetSessionToken\":{\"input\":{\"type\":\"structure\",\"members\":{\"DurationSeconds\":{\"type\":\"integer\"},\"SerialNumber\":{},\"TokenCode\":{}}},\"output\":{\"resultWrapper\":\"GetSessionTokenResult\",\"type\":\"structure\",\"members\":{\"Credentials\":{\"shape\":\"Sl\"}}}}},\"shapes\":{\"S4\":{\"type\":\"list\",\"member\":{\"type\":\"structure\",\"members\":{\"arn\":{}}}},\"S8\":{\"type\":\"list\",\"member\":{\"type\":\"structure\",\"required\":[\"Key\",\"Value\"],\"members\":{\"Key\":{},\"Value\":{}}}},\"Sl\":{\"type\":\"structure\",\"required\":[\"AccessKeyId\",\"SecretAccessKey\",\"SessionToken\",\"Expiration\"],\"members\":{\"AccessKeyId\":{},\"SecretAccessKey\":{\"type\":\"string\",\"sensitive\":true},\"SessionToken\":{},\"Expiration\":{\"type\":\"timestamp\"}}},\"Sq\":{\"type\":\"structure\",\"required\":[\"AssumedRoleId\",\"Arn\"],\"members\":{\"AssumedRoleId\":{},\"Arn\":{}}}}}");

});

parcelRegister("7DWNz", function(module, exports) {
module.exports = JSON.parse("{\"pagination\":{}}");

});


$parcel$export(module.exports, "handler", () => $a522b9fcea980f7e$export$c3c52e219617878);
var $dffa98b1230ab04c$exports = {};
var $a47d739e92258da3$exports = {};

var $i3HcT = parcelRequire("i3HcT");

var $gffN3 = parcelRequire("gffN3");
var $a47d739e92258da3$var$isFipsRegion = $gffN3.isFipsRegion;
var $a47d739e92258da3$var$getRealRegion = $gffN3.getRealRegion;
$i3HcT.isBrowser = function() {
    return false;
};
$i3HcT.isNode = function() {
    return true;
};

// node.js specific modules
$i3HcT.crypto.lib = $dDec7$crypto;

$i3HcT.Buffer = $dDec7$buffer.Buffer;

$i3HcT.domain = $dDec7$domain;

$i3HcT.stream = $dDec7$stream;

$i3HcT.url = $dDec7$url;

$i3HcT.querystring = $dDec7$querystring;
$i3HcT.environment = 'nodejs';


$i3HcT.createEventStream = $i3HcT.stream.Readable ? (parcelRequire("kMo4M")).createEventStream : (parcelRequire("ebSwa")).createEventStream;

$i3HcT.realClock = (parcelRequire("gQ4NQ"));


$i3HcT.clientSideMonitoring = {
    Publisher: (parcelRequire("gm9Dn")).Publisher,
    configProvider: (parcelRequire("aaTMB"))
};

$i3HcT.iniLoader = (parcelRequire("8AIqz")).iniLoader;

$i3HcT.getSystemErrorName = $dDec7$util.getSystemErrorName;
$i3HcT.loadConfig = function(options) {
    var envValue = options.environmentVariableSelector(process.env);
    if (envValue !== undefined) return envValue;
    var configFile = {};
    try {
        configFile = $i3HcT.iniLoader ? $i3HcT.iniLoader.loadFrom({
            isConfig: true,
            filename: process.env[$i3HcT.sharedConfigFileEnv]
        }) : {};
    } catch (e) {}
    var sharedFileConfig = configFile[process.env.AWS_PROFILE || $i3HcT.defaultProfile] || {};
    var configValue = options.configFileSelector(sharedFileConfig);
    if (configValue !== undefined) return configValue;
    if (typeof options.default === 'function') return options.default();
    return options.default;
};
var $a47d739e92258da3$var$AWS;

/**
 * @api private
 */ $a47d739e92258da3$exports = $a47d739e92258da3$var$AWS = (parcelRequire("hIq4q"));
parcelRequire("f9Kfu");
parcelRequire("f4h1X");

var $hIq4q = parcelRequire("hIq4q");

/**
 * Represents temporary credentials retrieved from {AWS.STS}. Without any
 * extra parameters, credentials will be fetched from the
 * {AWS.STS.getSessionToken} operation. If an IAM role is provided, the
 * {AWS.STS.assumeRole} operation will be used to fetch credentials for the
 * role instead.
 *
 * @note AWS.TemporaryCredentials is deprecated, but remains available for
 *   backwards compatibility. {AWS.ChainableTemporaryCredentials} is the
 *   preferred class for temporary credentials.
 *
 * To setup temporary credentials, configure a set of master credentials
 * using the standard credentials providers (environment, EC2 instance metadata,
 * or from the filesystem), then set the global credentials to a new
 * temporary credentials object:
 *
 * ```javascript
 * // Note that environment credentials are loaded by default,
 * // the following line is shown for clarity:
 * AWS.config.credentials = new AWS.EnvironmentCredentials('AWS');
 *
 * // Now set temporary credentials seeded from the master credentials
 * AWS.config.credentials = new AWS.TemporaryCredentials();
 *
 * // subsequent requests will now use temporary credentials from AWS STS.
 * new AWS.S3().listBucket(function(err, data) { ... });
 * ```
 *
 * @!attribute masterCredentials
 *   @return [AWS.Credentials] the master (non-temporary) credentials used to
 *     get and refresh temporary credentials from AWS STS.
 * @note (see constructor)
 */ $hIq4q.TemporaryCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new temporary credentials object.
   *
   * @note In order to create temporary credentials, you first need to have
   *   "master" credentials configured in {AWS.Config.credentials}. These
   *   master credentials are necessary to retrieve the temporary credentials,
   *   as well as refresh the credentials when they expire.
   * @param params [map] a map of options that are passed to the
   *   {AWS.STS.assumeRole} or {AWS.STS.getSessionToken} operations.
   *   If a `RoleArn` parameter is passed in, credentials will be based on the
   *   IAM role.
   * @param masterCredentials [AWS.Credentials] the master (non-temporary) credentials
   *  used to get and refresh temporary credentials from AWS STS.
   * @example Creating a new credentials object for generic temporary credentials
   *   AWS.config.credentials = new AWS.TemporaryCredentials();
   * @example Creating a new credentials object for an IAM role
   *   AWS.config.credentials = new AWS.TemporaryCredentials({
   *     RoleArn: 'arn:aws:iam::1234567890:role/TemporaryCredentials',
   *   });
   * @see AWS.STS.assumeRole
   * @see AWS.STS.getSessionToken
   */ constructor: function TemporaryCredentials(params, masterCredentials) {
        $hIq4q.Credentials.call(this);
        this.loadMasterCredentials(masterCredentials);
        this.expired = true;
        this.params = params || {};
        if (this.params.RoleArn) this.params.RoleSessionName = this.params.RoleSessionName || 'temporary-credentials';
    },
    /**
   * Refreshes credentials using {AWS.STS.assumeRole} or
   * {AWS.STS.getSessionToken}, depending on whether an IAM role ARN was passed
   * to the credentials {constructor}.
   *
   * @callback callback function(err)
   *   Called when the STS service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    },
    /**
   * @api private
   */ load: function load(callback) {
        var self = this;
        self.createClients();
        self.masterCredentials.get(function() {
            self.service.config.credentials = self.masterCredentials;
            var operation = self.params.RoleArn ? self.service.assumeRole : self.service.getSessionToken;
            operation.call(self.service, function(err, data) {
                if (!err) self.service.credentialsFrom(data, self);
                callback(err);
            });
        });
    },
    /**
   * @api private
   */ loadMasterCredentials: function loadMasterCredentials(masterCredentials) {
        this.masterCredentials = masterCredentials || $hIq4q.config.credentials;
        while(this.masterCredentials.masterCredentials)this.masterCredentials = this.masterCredentials.masterCredentials;
        if (typeof this.masterCredentials.get !== 'function') this.masterCredentials = new $hIq4q.Credentials(this.masterCredentials);
    },
    /**
   * @api private
   */ createClients: function() {
        this.service = this.service || new $dffa98b1230ab04c$exports({
            params: this.params
        });
    }
});



var $hIq4q = parcelRequire("hIq4q");

/**
 * Represents temporary credentials retrieved from {AWS.STS}. Without any
 * extra parameters, credentials will be fetched from the
 * {AWS.STS.getSessionToken} operation. If an IAM role is provided, the
 * {AWS.STS.assumeRole} operation will be used to fetch credentials for the
 * role instead.
 *
 * AWS.ChainableTemporaryCredentials differs from AWS.TemporaryCredentials in
 * the way masterCredentials and refreshes are handled.
 * AWS.ChainableTemporaryCredentials refreshes expired credentials using the
 * masterCredentials passed by the user to support chaining of STS credentials.
 * However, AWS.TemporaryCredentials recursively collapses the masterCredentials
 * during instantiation, precluding the ability to refresh credentials which
 * require intermediate, temporary credentials.
 *
 * For example, if the application should use RoleA, which must be assumed from
 * RoleB, and the environment provides credentials which can assume RoleB, then
 * AWS.ChainableTemporaryCredentials must be used to support refreshing the
 * temporary credentials for RoleA:
 *
 * ```javascript
 * var roleACreds = new AWS.ChainableTemporaryCredentials({
 *   params: {RoleArn: 'RoleA'},
 *   masterCredentials: new AWS.ChainableTemporaryCredentials({
 *     params: {RoleArn: 'RoleB'},
 *     masterCredentials: new AWS.EnvironmentCredentials('AWS')
 *   })
 * });
 * ```
 *
 * If AWS.TemporaryCredentials had been used in the previous example,
 * `roleACreds` would fail to refresh because `roleACreds` would
 * use the environment credentials for the AssumeRole request.
 *
 * Another difference is that AWS.ChainableTemporaryCredentials creates the STS
 * service instance during instantiation while AWS.TemporaryCredentials creates
 * the STS service instance during the first refresh. Creating the service
 * instance during instantiation effectively captures the master credentials
 * from the global config, so that subsequent changes to the global config do
 * not affect the master credentials used to refresh the temporary credentials.
 *
 * This allows an instance of AWS.ChainableTemporaryCredentials to be assigned
 * to AWS.config.credentials:
 *
 * ```javascript
 * var envCreds = new AWS.EnvironmentCredentials('AWS');
 * AWS.config.credentials = envCreds;
 * // masterCredentials will be envCreds
 * AWS.config.credentials = new AWS.ChainableTemporaryCredentials({
 *   params: {RoleArn: '...'}
 * });
 * ```
 *
 * Similarly, to use the CredentialProviderChain's default providers as the
 * master credentials, simply create a new instance of
 * AWS.ChainableTemporaryCredentials:
 *
 * ```javascript
 * AWS.config.credentials = new ChainableTemporaryCredentials({
 *   params: {RoleArn: '...'}
 * });
 * ```
 *
 * @!attribute service
 *   @return [AWS.STS] the STS service instance used to
 *     get and refresh temporary credentials from AWS STS.
 * @note (see constructor)
 */ $hIq4q.ChainableTemporaryCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new temporary credentials object.
   *
   * @param options [map] a set of options
   * @option options params [map] ({}) a map of options that are passed to the
   *   {AWS.STS.assumeRole} or {AWS.STS.getSessionToken} operations.
   *   If a `RoleArn` parameter is passed in, credentials will be based on the
   *   IAM role. If a `SerialNumber` parameter is passed in, {tokenCodeFn} must
   *   also be passed in or an error will be thrown.
   * @option options masterCredentials [AWS.Credentials] the master credentials
   *   used to get and refresh temporary credentials from AWS STS. By default,
   *   AWS.config.credentials or AWS.config.credentialProvider will be used.
   * @option options tokenCodeFn [Function] (null) Function to provide
   *   `TokenCode`, if `SerialNumber` is provided for profile in {params}. Function
   *   is called with value of `SerialNumber` and `callback`, and should provide
   *   the `TokenCode` or an error to the callback in the format
   *   `callback(err, token)`.
   * @example Creating a new credentials object for generic temporary credentials
   *   AWS.config.credentials = new AWS.ChainableTemporaryCredentials();
   * @example Creating a new credentials object for an IAM role
   *   AWS.config.credentials = new AWS.ChainableTemporaryCredentials({
   *     params: {
   *       RoleArn: 'arn:aws:iam::1234567890:role/TemporaryCredentials'
   *     }
   *   });
   * @see AWS.STS.assumeRole
   * @see AWS.STS.getSessionToken
   */ constructor: function ChainableTemporaryCredentials(options) {
        $hIq4q.Credentials.call(this);
        options = options || {};
        this.errorCode = 'ChainableTemporaryCredentialsProviderFailure';
        this.expired = true;
        this.tokenCodeFn = null;
        var params = $hIq4q.util.copy(options.params) || {};
        if (params.RoleArn) params.RoleSessionName = params.RoleSessionName || 'temporary-credentials';
        if (params.SerialNumber) {
            if (!options.tokenCodeFn || typeof options.tokenCodeFn !== 'function') throw new $hIq4q.util.error(new Error('tokenCodeFn must be a function when params.SerialNumber is given'), {
                code: this.errorCode
            });
            else this.tokenCodeFn = options.tokenCodeFn;
        }
        var config = $hIq4q.util.merge({
            params: params,
            credentials: options.masterCredentials || $hIq4q.config.credentials
        }, options.stsConfig || {});
        this.service = new $dffa98b1230ab04c$exports(config);
    },
    /**
   * Refreshes credentials using {AWS.STS.assumeRole} or
   * {AWS.STS.getSessionToken}, depending on whether an IAM role ARN was passed
   * to the credentials {constructor}.
   *
   * @callback callback function(err)
   *   Called when the STS service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see AWS.Credentials.get
   */ refresh: function refresh(callback) {
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    },
    /**
   * @api private
   * @param callback
   */ load: function load(callback) {
        var self = this;
        var operation = self.service.config.params.RoleArn ? 'assumeRole' : 'getSessionToken';
        this.getTokenCode(function(err, tokenCode) {
            var params = {};
            if (err) {
                callback(err);
                return;
            }
            if (tokenCode) params.TokenCode = tokenCode;
            self.service[operation](params, function(err, data) {
                if (!err) self.service.credentialsFrom(data, self);
                callback(err);
            });
        });
    },
    /**
   * @api private
   */ getTokenCode: function getTokenCode(callback) {
        var self = this;
        if (this.tokenCodeFn) this.tokenCodeFn(this.service.config.params.SerialNumber, function(err, token) {
            if (err) {
                var message = err;
                if (err instanceof Error) message = err.message;
                callback($hIq4q.util.error(new Error('Error fetching MFA token: ' + message), {
                    code: self.errorCode
                }));
                return;
            }
            callback(null, token);
        });
        else callback(null);
    }
});



var $hIq4q = parcelRequire("hIq4q");

/**
 * Represents credentials retrieved from STS Web Identity Federation support.
 *
 * By default this provider gets credentials using the
 * {AWS.STS.assumeRoleWithWebIdentity} service operation. This operation
 * requires a `RoleArn` containing the ARN of the IAM trust policy for the
 * application for which credentials will be given. In addition, the
 * `WebIdentityToken` must be set to the token provided by the identity
 * provider. See {constructor} for an example on creating a credentials
 * object with proper `RoleArn` and `WebIdentityToken` values.
 *
 * ## Refreshing Credentials from Identity Service
 *
 * In addition to AWS credentials expiring after a given amount of time, the
 * login token from the identity provider will also expire. Once this token
 * expires, it will not be usable to refresh AWS credentials, and another
 * token will be needed. The SDK does not manage refreshing of the token value,
 * but this can be done through a "refresh token" supported by most identity
 * providers. Consult the documentation for the identity provider for refreshing
 * tokens. Once the refreshed token is acquired, you should make sure to update
 * this new token in the credentials object's {params} property. The following
 * code will update the WebIdentityToken, assuming you have retrieved an updated
 * token from the identity provider:
 *
 * ```javascript
 * AWS.config.credentials.params.WebIdentityToken = updatedToken;
 * ```
 *
 * Future calls to `credentials.refresh()` will now use the new token.
 *
 * @!attribute params
 *   @return [map] the map of params passed to
 *     {AWS.STS.assumeRoleWithWebIdentity}. To update the token, set the
 *     `params.WebIdentityToken` property.
 * @!attribute data
 *   @return [map] the raw data response from the call to
 *     {AWS.STS.assumeRoleWithWebIdentity}. Use this if you want to get
 *     access to other properties from the response.
 */ $hIq4q.WebIdentityCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new credentials object.
   * @param (see AWS.STS.assumeRoleWithWebIdentity)
   * @example Creating a new credentials object
   *   AWS.config.credentials = new AWS.WebIdentityCredentials({
   *     RoleArn: 'arn:aws:iam::1234567890:role/WebIdentity',
   *     WebIdentityToken: 'ABCDEFGHIJKLMNOP', // token from identity service
   *     RoleSessionName: 'web' // optional name, defaults to web-identity
   *   }, {
   *     // optionally provide configuration to apply to the underlying AWS.STS service client
   *     // if configuration is not provided, then configuration will be pulled from AWS.config
   *
   *     // specify timeout options
   *     httpOptions: {
   *       timeout: 100
   *     }
   *   });
   * @see AWS.STS.assumeRoleWithWebIdentity
   * @see AWS.Config
   */ constructor: function WebIdentityCredentials(params, clientConfig) {
        $hIq4q.Credentials.call(this);
        this.expired = true;
        this.params = params;
        this.params.RoleSessionName = this.params.RoleSessionName || 'web-identity';
        this.data = null;
        this._clientConfig = $hIq4q.util.copy(clientConfig || {});
    },
    /**
   * Refreshes credentials using {AWS.STS.assumeRoleWithWebIdentity}
   *
   * @callback callback function(err)
   *   Called when the STS service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    },
    /**
   * @api private
   */ load: function load(callback) {
        var self = this;
        self.createClients();
        self.service.assumeRoleWithWebIdentity(function(err, data) {
            self.data = null;
            if (!err) {
                self.data = data;
                self.service.credentialsFrom(data, self);
            }
            callback(err);
        });
    },
    /**
   * @api private
   */ createClients: function() {
        if (!this.service) {
            var stsConfig = $hIq4q.util.merge({}, this._clientConfig);
            stsConfig.params = this.params;
            this.service = new $dffa98b1230ab04c$exports(stsConfig);
        }
    }
});



var $hIq4q = parcelRequire("hIq4q");
var $c25da1815b774a61$exports = {};


var $hIq4q = parcelRequire("hIq4q");
var $c25da1815b774a61$var$Service = $hIq4q.Service;
var $c25da1815b774a61$var$apiLoader = $hIq4q.apiLoader;
$c25da1815b774a61$var$apiLoader.services['cognitoidentity'] = {};
$hIq4q.CognitoIdentity = $c25da1815b774a61$var$Service.defineService('cognitoidentity', [
    '2014-06-30'
]);


Object.defineProperty($c25da1815b774a61$var$apiLoader.services['cognitoidentity'], '2014-06-30', {
    get: function get() {
        var model = (parcelRequire("lJDR7"));
        model.paginators = (parcelRequire("7lW7A")).pagination;
        return model;
    },
    enumerable: true,
    configurable: true
});
$c25da1815b774a61$exports = $hIq4q.CognitoIdentity;



/**
 * Represents credentials retrieved from STS Web Identity Federation using
 * the Amazon Cognito Identity service.
 *
 * By default this provider gets credentials using the
 * {AWS.CognitoIdentity.getCredentialsForIdentity} service operation, which
 * requires either an `IdentityId` or an `IdentityPoolId` (Amazon Cognito
 * Identity Pool ID), which is used to call {AWS.CognitoIdentity.getId} to
 * obtain an `IdentityId`. If the identity or identity pool is not configured in
 * the Amazon Cognito Console to use IAM roles with the appropriate permissions,
 * then additionally a `RoleArn` is required containing the ARN of the IAM trust
 * policy for the Amazon Cognito role that the user will log into. If a `RoleArn`
 * is provided, then this provider gets credentials using the
 * {AWS.STS.assumeRoleWithWebIdentity} service operation, after first getting an
 * Open ID token from {AWS.CognitoIdentity.getOpenIdToken}.
 *
 * In addition, if this credential provider is used to provide authenticated
 * login, the `Logins` map may be set to the tokens provided by the respective
 * identity providers. See {constructor} for an example on creating a credentials
 * object with proper property values.
 *
 * DISCLAIMER: This convenience method leverages the Enhanced (simplified) Authflow. The underlying
 * implementation calls Cognito's `getId()` and `GetCredentialsForIdentity()`.
 * In this flow there is no way to explicitly set a session policy, resulting in
 * STS attaching the default policy and limiting the permissions of the federated role.
 * To be able to explicitly set a session policy, do not use this convenience method.
 * Instead, you can use the Cognito client to call `getId()`, `GetOpenIdToken()` and then use
 * that token with your desired session policy to call STS's `AssumeRoleWithWebIdentity()`
 * For further reading refer to: https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html
 *
 * ## Refreshing Credentials from Identity Service
 *
 * In addition to AWS credentials expiring after a given amount of time, the
 * login token from the identity provider will also expire. Once this token
 * expires, it will not be usable to refresh AWS credentials, and another
 * token will be needed. The SDK does not manage refreshing of the token value,
 * but this can be done through a "refresh token" supported by most identity
 * providers. Consult the documentation for the identity provider for refreshing
 * tokens. Once the refreshed token is acquired, you should make sure to update
 * this new token in the credentials object's {params} property. The following
 * code will update the WebIdentityToken, assuming you have retrieved an updated
 * token from the identity provider:
 *
 * ```javascript
 * AWS.config.credentials.params.Logins['graph.facebook.com'] = updatedToken;
 * ```
 *
 * Future calls to `credentials.refresh()` will now use the new token.
 *
 * @!attribute params
 *   @return [map] the map of params passed to
 *     {AWS.CognitoIdentity.getId},
 *     {AWS.CognitoIdentity.getOpenIdToken}, and
 *     {AWS.STS.assumeRoleWithWebIdentity}. To update the token, set the
 *     `params.WebIdentityToken` property.
 * @!attribute data
 *   @return [map] the raw data response from the call to
 *     {AWS.CognitoIdentity.getCredentialsForIdentity}, or
 *     {AWS.STS.assumeRoleWithWebIdentity}. Use this if you want to get
 *     access to other properties from the response.
 * @!attribute identityId
 *   @return [String] the Cognito ID returned by the last call to
 *     {AWS.CognitoIdentity.getOpenIdToken}. This ID represents the actual
 *     final resolved identity ID from Amazon Cognito.
 */ $hIq4q.CognitoIdentityCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * @api private
   */ localStorageKey: {
        id: 'aws.cognito.identity-id.',
        providers: 'aws.cognito.identity-providers.'
    },
    /**
   * Creates a new credentials object.
   * @example Creating a new credentials object
   *   AWS.config.credentials = new AWS.CognitoIdentityCredentials({
   *
   *     // either IdentityPoolId or IdentityId is required
   *     // See the IdentityPoolId param for AWS.CognitoIdentity.getID (linked below)
   *     // See the IdentityId param for AWS.CognitoIdentity.getCredentialsForIdentity
   *     // or AWS.CognitoIdentity.getOpenIdToken (linked below)
   *     IdentityPoolId: 'us-east-1:1699ebc0-7900-4099-b910-2df94f52a030',
   *     IdentityId: 'us-east-1:128d0a74-c82f-4553-916d-90053e4a8b0f'
   *
   *     // optional, only necessary when the identity pool is not configured
   *     // to use IAM roles in the Amazon Cognito Console
   *     // See the RoleArn param for AWS.STS.assumeRoleWithWebIdentity (linked below)
   *     RoleArn: 'arn:aws:iam::1234567890:role/MYAPP-CognitoIdentity',
   *
   *     // optional tokens, used for authenticated login
   *     // See the Logins param for AWS.CognitoIdentity.getID (linked below)
   *     Logins: {
   *       'graph.facebook.com': 'FBTOKEN',
   *       'www.amazon.com': 'AMAZONTOKEN',
   *       'accounts.google.com': 'GOOGLETOKEN',
   *       'api.twitter.com': 'TWITTERTOKEN',
   *       'www.digits.com': 'DIGITSTOKEN'
   *     },
   *
   *     // optional name, defaults to web-identity
   *     // See the RoleSessionName param for AWS.STS.assumeRoleWithWebIdentity (linked below)
   *     RoleSessionName: 'web',
   *
   *     // optional, only necessary when application runs in a browser
   *     // and multiple users are signed in at once, used for caching
   *     LoginId: 'example@gmail.com'
   *
   *   }, {
   *      // optionally provide configuration to apply to the underlying service clients
   *      // if configuration is not provided, then configuration will be pulled from AWS.config
   *
   *      // region should match the region your identity pool is located in
   *      region: 'us-east-1',
   *
   *      // specify timeout options
   *      httpOptions: {
   *        timeout: 100
   *      }
   *   });
   * @see AWS.CognitoIdentity.getId
   * @see AWS.CognitoIdentity.getCredentialsForIdentity
   * @see AWS.STS.assumeRoleWithWebIdentity
   * @see AWS.CognitoIdentity.getOpenIdToken
   * @see AWS.Config
   * @note If a region is not provided in the global AWS.config, or
   *   specified in the `clientConfig` to the CognitoIdentityCredentials
   *   constructor, you may encounter a 'Missing credentials in config' error
   *   when calling making a service call.
   */ constructor: function CognitoIdentityCredentials(params, clientConfig) {
        $hIq4q.Credentials.call(this);
        this.expired = true;
        this.params = params;
        this.data = null;
        this._identityId = null;
        this._clientConfig = $hIq4q.util.copy(clientConfig || {});
        this.loadCachedId();
        var self = this;
        Object.defineProperty(this, 'identityId', {
            get: function() {
                self.loadCachedId();
                return self._identityId || self.params.IdentityId;
            },
            set: function(identityId) {
                self._identityId = identityId;
            }
        });
    },
    /**
   * Refreshes credentials using {AWS.CognitoIdentity.getCredentialsForIdentity},
   * or {AWS.STS.assumeRoleWithWebIdentity}.
   *
   * @callback callback function(err)
   *   Called when the STS service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see AWS.Credentials.get
   */ refresh: function refresh(callback) {
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    },
    /**
   * @api private
   * @param callback
   */ load: function load(callback) {
        var self = this;
        self.createClients();
        self.data = null;
        self._identityId = null;
        self.getId(function(err) {
            if (!err) {
                if (!self.params.RoleArn) self.getCredentialsForIdentity(callback);
                else self.getCredentialsFromSTS(callback);
            } else {
                self.clearIdOnNotAuthorized(err);
                callback(err);
            }
        });
    },
    /**
   * Clears the cached Cognito ID associated with the currently configured
   * identity pool ID. Use this to manually invalidate your cache if
   * the identity pool ID was deleted.
   */ clearCachedId: function clearCache() {
        this._identityId = null;
        delete this.params.IdentityId;
        var poolId = this.params.IdentityPoolId;
        var loginId = this.params.LoginId || '';
        delete this.storage[this.localStorageKey.id + poolId + loginId];
        delete this.storage[this.localStorageKey.providers + poolId + loginId];
    },
    /**
   * @api private
   */ clearIdOnNotAuthorized: function clearIdOnNotAuthorized(err) {
        var self = this;
        if (err.code == 'NotAuthorizedException') self.clearCachedId();
    },
    /**
   * Retrieves a Cognito ID, loading from cache if it was already retrieved
   * on this device.
   *
   * @callback callback function(err, identityId)
   *   @param err [Error, null] an error object if the call failed or null if
   *     it succeeded.
   *   @param identityId [String, null] if successful, the callback will return
   *     the Cognito ID.
   * @note If not loaded explicitly, the Cognito ID is loaded and stored in
   *   localStorage in the browser environment of a device.
   * @api private
   */ getId: function getId(callback) {
        var self = this;
        if (typeof self.params.IdentityId === 'string') return callback(null, self.params.IdentityId);
        self.cognito.getId(function(err, data) {
            if (!err && data.IdentityId) {
                self.params.IdentityId = data.IdentityId;
                callback(null, data.IdentityId);
            } else callback(err);
        });
    },
    /**
   * @api private
   */ loadCredentials: function loadCredentials(data, credentials) {
        if (!data || !credentials) return;
        credentials.expired = false;
        credentials.accessKeyId = data.Credentials.AccessKeyId;
        credentials.secretAccessKey = data.Credentials.SecretKey;
        credentials.sessionToken = data.Credentials.SessionToken;
        credentials.expireTime = data.Credentials.Expiration;
    },
    /**
   * @api private
   */ getCredentialsForIdentity: function getCredentialsForIdentity(callback) {
        var self = this;
        self.cognito.getCredentialsForIdentity(function(err, data) {
            if (!err) {
                self.cacheId(data);
                self.data = data;
                self.loadCredentials(self.data, self);
            } else self.clearIdOnNotAuthorized(err);
            callback(err);
        });
    },
    /**
   * @api private
   */ getCredentialsFromSTS: function getCredentialsFromSTS(callback) {
        var self = this;
        self.cognito.getOpenIdToken(function(err, data) {
            if (!err) {
                self.cacheId(data);
                self.params.WebIdentityToken = data.Token;
                self.webIdentityCredentials.refresh(function(webErr) {
                    if (!webErr) {
                        self.data = self.webIdentityCredentials.data;
                        self.sts.credentialsFrom(self.data, self);
                    }
                    callback(webErr);
                });
            } else {
                self.clearIdOnNotAuthorized(err);
                callback(err);
            }
        });
    },
    /**
   * @api private
   */ loadCachedId: function loadCachedId() {
        var self = this;
        // in the browser we source default IdentityId from localStorage
        if ($hIq4q.util.isBrowser() && !self.params.IdentityId) {
            var id = self.getStorage('id');
            if (id && self.params.Logins) {
                var actualProviders = Object.keys(self.params.Logins);
                var cachedProviders = (self.getStorage('providers') || '').split(',');
                // only load ID if at least one provider used this ID before
                var intersect = cachedProviders.filter(function(n) {
                    return actualProviders.indexOf(n) !== -1;
                });
                if (intersect.length !== 0) self.params.IdentityId = id;
            } else if (id) self.params.IdentityId = id;
        }
    },
    /**
   * @api private
   */ createClients: function() {
        var clientConfig = this._clientConfig;
        this.webIdentityCredentials = this.webIdentityCredentials || new $hIq4q.WebIdentityCredentials(this.params, clientConfig);
        if (!this.cognito) {
            var cognitoConfig = $hIq4q.util.merge({}, clientConfig);
            cognitoConfig.params = this.params;
            this.cognito = new $c25da1815b774a61$exports(cognitoConfig);
        }
        this.sts = this.sts || new $dffa98b1230ab04c$exports(clientConfig);
    },
    /**
   * @api private
   */ cacheId: function cacheId(data) {
        this._identityId = data.IdentityId;
        this.params.IdentityId = this._identityId;
        // cache this IdentityId in browser localStorage if possible
        if ($hIq4q.util.isBrowser()) {
            this.setStorage('id', data.IdentityId);
            if (this.params.Logins) this.setStorage('providers', Object.keys(this.params.Logins).join(','));
        }
    },
    /**
   * @api private
   */ getStorage: function getStorage(key) {
        return this.storage[this.localStorageKey[key] + this.params.IdentityPoolId + (this.params.LoginId || '')];
    },
    /**
   * @api private
   */ setStorage: function setStorage(key, val) {
        try {
            this.storage[this.localStorageKey[key] + this.params.IdentityPoolId + (this.params.LoginId || '')] = val;
        } catch (_) {}
    },
    /**
   * @api private
   */ storage: function() {
        try {
            var storage = $hIq4q.util.isBrowser() && window.localStorage !== null && typeof window.localStorage === 'object' ? window.localStorage : {};
            // Test set/remove which would throw an error in Safari's private browsing
            storage['aws.test-storage'] = 'foobar';
            delete storage['aws.test-storage'];
            return storage;
        } catch (_) {
            return {};
        }
    }()
});



var $hIq4q = parcelRequire("hIq4q");

/**
 * Represents credentials retrieved from STS SAML support.
 *
 * By default this provider gets credentials using the
 * {AWS.STS.assumeRoleWithSAML} service operation. This operation
 * requires a `RoleArn` containing the ARN of the IAM trust policy for the
 * application for which credentials will be given, as well as a `PrincipalArn`
 * representing the ARN for the SAML identity provider. In addition, the
 * `SAMLAssertion` must be set to the token provided by the identity
 * provider. See {constructor} for an example on creating a credentials
 * object with proper `RoleArn`, `PrincipalArn`, and `SAMLAssertion` values.
 *
 * ## Refreshing Credentials from Identity Service
 *
 * In addition to AWS credentials expiring after a given amount of time, the
 * login token from the identity provider will also expire. Once this token
 * expires, it will not be usable to refresh AWS credentials, and another
 * token will be needed. The SDK does not manage refreshing of the token value,
 * but this can be done through a "refresh token" supported by most identity
 * providers. Consult the documentation for the identity provider for refreshing
 * tokens. Once the refreshed token is acquired, you should make sure to update
 * this new token in the credentials object's {params} property. The following
 * code will update the SAMLAssertion, assuming you have retrieved an updated
 * token from the identity provider:
 *
 * ```javascript
 * AWS.config.credentials.params.SAMLAssertion = updatedToken;
 * ```
 *
 * Future calls to `credentials.refresh()` will now use the new token.
 *
 * @!attribute params
 *   @return [map] the map of params passed to
 *     {AWS.STS.assumeRoleWithSAML}. To update the token, set the
 *     `params.SAMLAssertion` property.
 */ $hIq4q.SAMLCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new credentials object.
   * @param (see AWS.STS.assumeRoleWithSAML)
   * @example Creating a new credentials object
   *   AWS.config.credentials = new AWS.SAMLCredentials({
   *     RoleArn: 'arn:aws:iam::1234567890:role/SAMLRole',
   *     PrincipalArn: 'arn:aws:iam::1234567890:role/SAMLPrincipal',
   *     SAMLAssertion: 'base64-token', // base64-encoded token from IdP
   *   });
   * @see AWS.STS.assumeRoleWithSAML
   */ constructor: function SAMLCredentials(params) {
        $hIq4q.Credentials.call(this);
        this.expired = true;
        this.params = params;
    },
    /**
   * Refreshes credentials using {AWS.STS.assumeRoleWithSAML}
   *
   * @callback callback function(err)
   *   Called when the STS service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    },
    /**
   * @api private
   */ load: function load(callback) {
        var self = this;
        self.createClients();
        self.service.assumeRoleWithSAML(function(err, data) {
            if (!err) self.service.credentialsFrom(data, self);
            callback(err);
        });
    },
    /**
   * @api private
   */ createClients: function() {
        this.service = this.service || new $dffa98b1230ab04c$exports({
            params: this.params
        });
    }
});



var $hIq4q = parcelRequire("hIq4q");

var $cf185d50e8e9cf9e$var$iniLoader = $hIq4q.util.iniLoader;
/**
 * Represents credentials loaded from shared credentials file
 * (defaulting to ~/.aws/credentials or defined by the
 * `AWS_SHARED_CREDENTIALS_FILE` environment variable).
 *
 * ## Using process credentials
 *
 * The credentials file can specify a credential provider that executes
 * a given process and attempts to read its stdout to recieve a JSON payload
 * containing the credentials:
 *
 *     [default]
 *     credential_process = /usr/bin/credential_proc
 *
 * Automatically handles refreshing credentials if an Expiration time is
 * provided in the credentials payload. Credentials supplied in the same profile
 * will take precedence over the credential_process.
 *
 * Sourcing credentials from an external process can potentially be dangerous,
 * so proceed with caution. Other credential providers should be preferred if
 * at all possible. If using this option, you should make sure that the shared
 * credentials file is as locked down as possible using security best practices
 * for your operating system.
 *
 * ## Using custom profiles
 *
 * The SDK supports loading credentials for separate profiles. This can be done
 * in two ways:
 *
 * 1. Set the `AWS_PROFILE` environment variable in your process prior to
 *    loading the SDK.
 * 2. Directly load the AWS.ProcessCredentials provider:
 *
 * ```javascript
 * var creds = new AWS.ProcessCredentials({profile: 'myprofile'});
 * AWS.config.credentials = creds;
 * ```
 *
 * @!macro nobrowser
 */ $hIq4q.ProcessCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new ProcessCredentials object.
   *
   * @param options [map] a set of options
   * @option options profile [String] (AWS_PROFILE env var or 'default')
   *   the name of the profile to load.
   * @option options filename [String] ('~/.aws/credentials' or defined by
   *   AWS_SHARED_CREDENTIALS_FILE process env var)
   *   the filename to use when loading credentials.
   * @option options callback [Function] (err) Credentials are eagerly loaded
   *   by the constructor. When the callback is called with no error, the
   *   credentials have been loaded successfully.
   */ constructor: function ProcessCredentials(options) {
        $hIq4q.Credentials.call(this);
        options = options || {};
        this.filename = options.filename;
        this.profile = options.profile || process.env.AWS_PROFILE || $hIq4q.util.defaultProfile;
        this.get(options.callback || $hIq4q.util.fn.noop);
    },
    /**
   * @api private
   */ load: function load(callback) {
        var self = this;
        try {
            var profiles = $hIq4q.util.getProfilesFromSharedConfig($cf185d50e8e9cf9e$var$iniLoader, this.filename);
            var profile = profiles[this.profile] || {};
            if (Object.keys(profile).length === 0) throw $hIq4q.util.error(new Error('Profile ' + this.profile + ' not found'), {
                code: 'ProcessCredentialsProviderFailure'
            });
            if (profile['credential_process']) this.loadViaCredentialProcess(profile, function(err, data) {
                if (err) callback(err, null);
                else {
                    self.expired = false;
                    self.accessKeyId = data.AccessKeyId;
                    self.secretAccessKey = data.SecretAccessKey;
                    self.sessionToken = data.SessionToken;
                    if (data.Expiration) self.expireTime = new Date(data.Expiration);
                    callback(null);
                }
            });
            else throw $hIq4q.util.error(new Error('Profile ' + this.profile + ' did not include credential process'), {
                code: 'ProcessCredentialsProviderFailure'
            });
        } catch (err) {
            callback(err);
        }
    },
    /**
  * Executes the credential_process and retrieves
  * credentials from the output
  * @api private
  * @param profile [map] credentials profile
  * @throws ProcessCredentialsProviderFailure
  */ loadViaCredentialProcess: function loadViaCredentialProcess(profile, callback) {
        $dDec7$child_process.exec(profile['credential_process'], {
            env: process.env
        }, function(err, stdOut, stdErr) {
            if (err) callback($hIq4q.util.error(new Error('credential_process returned error'), {
                code: 'ProcessCredentialsProviderFailure'
            }), null);
            else try {
                var credData = JSON.parse(stdOut);
                if (credData.Expiration) {
                    var currentTime = $hIq4q.util.date.getDate();
                    var expireTime = new Date(credData.Expiration);
                    if (expireTime < currentTime) throw Error('credential_process returned expired credentials');
                }
                if (credData.Version !== 1) throw Error('credential_process does not return Version == 1');
                callback(null, credData);
            } catch (err) {
                callback($hIq4q.util.error(new Error(err.message), {
                    code: 'ProcessCredentialsProviderFailure'
                }), null);
            }
        });
    },
    /**
   * Loads the credentials from the credential process
   *
   * @callback callback function(err)
   *   Called after the credential process has been executed. When this
   *   callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        $cf185d50e8e9cf9e$var$iniLoader.clearCachedFiles();
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    }
});



// Load the xml2js XML parser
$a47d739e92258da3$var$AWS.XML.Parser = (parcelRequire("atSp4"));

var $hIq4q = parcelRequire("hIq4q");
var $9b2fa0a6d5216674$var$Stream = $hIq4q.util.stream.Stream;
var $9b2fa0a6d5216674$var$TransformStream = $hIq4q.util.stream.Transform;
var $9b2fa0a6d5216674$var$ReadableStream = $hIq4q.util.stream.Readable;
parcelRequire("jI9el");
var $9b2fa0a6d5216674$var$CONNECTION_REUSE_ENV_NAME = 'AWS_NODEJS_CONNECTION_REUSE_ENABLED';




/**
 * @api private
 */ $hIq4q.NodeHttpClient = $hIq4q.util.inherit({
    handleRequest: function handleRequest(httpRequest, httpOptions, callback, errCallback) {
        var self = this;
        var endpoint = httpRequest.endpoint;
        var pathPrefix = '';
        if (!httpOptions) httpOptions = {};
        if (httpOptions.proxy) {
            pathPrefix = endpoint.protocol + '//' + endpoint.hostname;
            if (endpoint.port !== 80 && endpoint.port !== 443) pathPrefix += ':' + endpoint.port;
            endpoint = new $hIq4q.Endpoint(httpOptions.proxy);
        }
        var useSSL = endpoint.protocol === 'https:';
        var http = useSSL ? $dDec7$https : $dDec7$http;
        var options = {
            host: endpoint.hostname,
            port: endpoint.port,
            method: httpRequest.method,
            headers: httpRequest.headers,
            path: pathPrefix + httpRequest.path
        };
        $hIq4q.util.update(options, httpOptions);
        if (!httpOptions.agent) options.agent = this.getAgent(useSSL, {
            keepAlive: process.env[$9b2fa0a6d5216674$var$CONNECTION_REUSE_ENV_NAME] === '1' ? true : false
        });
        delete options.proxy; // proxy isn't an HTTP option
        delete options.timeout; // timeout isn't an HTTP option
        var stream = http.request(options, function(httpResp) {
            if (stream.didCallback) return;
            callback(httpResp);
            httpResp.emit('headers', httpResp.statusCode, httpResp.headers, httpResp.statusMessage);
        });
        httpRequest.stream = stream; // attach stream to httpRequest
        stream.didCallback = false;
        // connection timeout support
        if (httpOptions.connectTimeout) {
            var connectTimeoutId;
            stream.on('socket', function(socket) {
                if (socket.connecting) {
                    connectTimeoutId = setTimeout(function connectTimeout() {
                        if (stream.didCallback) return;
                        stream.didCallback = true;
                        stream.abort();
                        errCallback($hIq4q.util.error(new Error('Socket timed out without establishing a connection'), {
                            code: 'TimeoutError'
                        }));
                    }, httpOptions.connectTimeout);
                    socket.on('connect', function() {
                        clearTimeout(connectTimeoutId);
                        connectTimeoutId = null;
                    });
                }
            });
        }
        // timeout support
        stream.setTimeout(httpOptions.timeout || 0, function() {
            if (stream.didCallback) return;
            stream.didCallback = true;
            var msg = 'Connection timed out after ' + httpOptions.timeout + 'ms';
            errCallback($hIq4q.util.error(new Error(msg), {
                code: 'TimeoutError'
            }));
            stream.abort();
        });
        stream.on('error', function(err) {
            if (connectTimeoutId) {
                clearTimeout(connectTimeoutId);
                connectTimeoutId = null;
            }
            if (stream.didCallback) return;
            stream.didCallback = true;
            if ('ECONNRESET' === err.code || 'EPIPE' === err.code || 'ETIMEDOUT' === err.code) errCallback($hIq4q.util.error(err, {
                code: 'TimeoutError'
            }));
            else errCallback(err);
        });
        var expect = httpRequest.headers.Expect || httpRequest.headers.expect;
        if (expect === '100-continue') stream.once('continue', function() {
            self.writeBody(stream, httpRequest);
        });
        else this.writeBody(stream, httpRequest);
        return stream;
    },
    writeBody: function writeBody(stream, httpRequest) {
        var body = httpRequest.body;
        var totalBytes = parseInt(httpRequest.headers['Content-Length'], 10);
        if (body instanceof $9b2fa0a6d5216674$var$Stream) {
            // For progress support of streaming content -
            // pipe the data through a transform stream to emit 'sendProgress' events
            var progressStream = this.progressStream(stream, totalBytes);
            if (progressStream) body.pipe(progressStream).pipe(stream);
            else body.pipe(stream);
        } else if (body) {
            // The provided body is a buffer/string and is already fully available in memory -
            // For performance it's best to send it as a whole by calling stream.end(body),
            // Callers expect a 'sendProgress' event which is best emitted once
            // the http request stream has been fully written and all data flushed.
            // The use of totalBytes is important over body.length for strings where
            // length is char length and not byte length.
            stream.once('finish', function() {
                stream.emit('sendProgress', {
                    loaded: totalBytes,
                    total: totalBytes
                });
            });
            stream.end(body);
        } else // no request body
        stream.end();
    },
    /**
   * Create the https.Agent or http.Agent according to the request schema.
   */ getAgent: function getAgent(useSSL, agentOptions) {
        var http = useSSL ? $dDec7$https : $dDec7$http;
        if (useSSL) {
            if (!$hIq4q.NodeHttpClient.sslAgent) {
                $hIq4q.NodeHttpClient.sslAgent = new http.Agent($hIq4q.util.merge({
                    rejectUnauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ? false : true
                }, agentOptions || {}));
                $hIq4q.NodeHttpClient.sslAgent.setMaxListeners(0);
                // delegate maxSockets to globalAgent, set a default limit of 50 if current value is Infinity.
                // Users can bypass this default by supplying their own Agent as part of SDK configuration.
                Object.defineProperty($hIq4q.NodeHttpClient.sslAgent, 'maxSockets', {
                    enumerable: true,
                    get: function() {
                        var defaultMaxSockets = 50;
                        var globalAgent = http.globalAgent;
                        if (globalAgent && globalAgent.maxSockets !== Infinity && typeof globalAgent.maxSockets === 'number') return globalAgent.maxSockets;
                        return defaultMaxSockets;
                    }
                });
            }
            return $hIq4q.NodeHttpClient.sslAgent;
        } else {
            if (!$hIq4q.NodeHttpClient.agent) $hIq4q.NodeHttpClient.agent = new http.Agent(agentOptions);
            return $hIq4q.NodeHttpClient.agent;
        }
    },
    progressStream: function progressStream(stream, totalBytes) {
        if (typeof $9b2fa0a6d5216674$var$TransformStream === 'undefined') // for node 0.8 there is no streaming progress
        return;
        var loadedBytes = 0;
        var reporter = new $9b2fa0a6d5216674$var$TransformStream();
        reporter._transform = function(chunk, encoding, callback) {
            if (chunk) {
                loadedBytes += chunk.length;
                stream.emit('sendProgress', {
                    loaded: loadedBytes,
                    total: totalBytes
                });
            }
            callback(null, chunk);
        };
        return reporter;
    },
    emitter: null
});
/**
 * @!ignore
 */ /**
 * @api private
 */ $hIq4q.HttpClient.prototype = $hIq4q.NodeHttpClient.prototype;
/**
 * @api private
 */ $hIq4q.HttpClient.streamsApiVersion = $9b2fa0a6d5216674$var$ReadableStream ? 2 : 1;


parcelRequire("tereM");

var $hIq4q = parcelRequire("hIq4q");


var $6f4d8fb688181ac3$var$iniLoader = $hIq4q.util.iniLoader;
/**
 * Represents OIDC credentials from a file on disk
 * If the credentials expire, the SDK can {refresh} the credentials
 * from the file.
 *
 * ## Using the web identity token file
 *
 * This provider is checked by default in the Node.js environment. To use
 * the provider simply add your OIDC token to a file (ASCII encoding) and
 * share the filename in either AWS_WEB_IDENTITY_TOKEN_FILE environment
 * variable or web_identity_token_file shared config variable
 *
 * The file contains encoded OIDC token and the characters are
 * ASCII encoded. OIDC tokens are JSON Web Tokens (JWT).
 * JWT's are 3 base64 encoded strings joined by the '.' character.
 *
 * This class will read filename from AWS_WEB_IDENTITY_TOKEN_FILE
 * environment variable or web_identity_token_file shared config variable,
 * and get the OIDC token from filename.
 * It will also read IAM role to be assumed from AWS_ROLE_ARN
 * environment variable or role_arn shared config variable.
 * This provider gets credetials using the {AWS.STS.assumeRoleWithWebIdentity}
 * service operation
 *
 * @!macro nobrowser
 */ $hIq4q.TokenFileWebIdentityCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * @example Creating a new credentials object
   *  AWS.config.credentials = new AWS.TokenFileWebIdentityCredentials(
   *   // optionally provide configuration to apply to the underlying AWS.STS service client
   *   // if configuration is not provided, then configuration will be pulled from AWS.config
   *   {
   *     // specify timeout options
   *     httpOptions: {
   *       timeout: 100
   *     }
   *   });
   * @see AWS.Config
   */ constructor: function TokenFileWebIdentityCredentials(clientConfig) {
        $hIq4q.Credentials.call(this);
        this.data = null;
        this.clientConfig = $hIq4q.util.copy(clientConfig || {});
    },
    /**
   * Returns params from environment variables
   *
   * @api private
   */ getParamsFromEnv: function getParamsFromEnv() {
        var ENV_TOKEN_FILE = 'AWS_WEB_IDENTITY_TOKEN_FILE', ENV_ROLE_ARN = 'AWS_ROLE_ARN';
        if (process.env[ENV_TOKEN_FILE] && process.env[ENV_ROLE_ARN]) return [
            {
                envTokenFile: process.env[ENV_TOKEN_FILE],
                roleArn: process.env[ENV_ROLE_ARN],
                roleSessionName: process.env['AWS_ROLE_SESSION_NAME']
            }
        ];
    },
    /**
   * Returns params from shared config variables
   *
   * @api private
   */ getParamsFromSharedConfig: function getParamsFromSharedConfig() {
        var profiles = $hIq4q.util.getProfilesFromSharedConfig($6f4d8fb688181ac3$var$iniLoader);
        var profileName = process.env.AWS_PROFILE || $hIq4q.util.defaultProfile;
        var profile = profiles[profileName] || {};
        if (Object.keys(profile).length === 0) throw $hIq4q.util.error(new Error('Profile ' + profileName + ' not found'), {
            code: 'TokenFileWebIdentityCredentialsProviderFailure'
        });
        var paramsArray = [];
        while(!profile['web_identity_token_file'] && profile['source_profile']){
            paramsArray.unshift({
                roleArn: profile['role_arn'],
                roleSessionName: profile['role_session_name']
            });
            var sourceProfile = profile['source_profile'];
            profile = profiles[sourceProfile];
        }
        paramsArray.unshift({
            envTokenFile: profile['web_identity_token_file'],
            roleArn: profile['role_arn'],
            roleSessionName: profile['role_session_name']
        });
        return paramsArray;
    },
    /**
   * Refreshes credentials using {AWS.STS.assumeRoleWithWebIdentity}
   *
   * @callback callback function(err)
   *   Called when the STS service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see AWS.Credentials.get
   */ refresh: function refresh(callback) {
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    },
    /**
   * @api private
  */ assumeRoleChaining: function assumeRoleChaining(paramsArray, callback) {
        var self = this;
        if (paramsArray.length === 0) {
            self.service.credentialsFrom(self.data, self);
            callback();
        } else {
            var params = paramsArray.shift();
            self.service.config.credentials = self.service.credentialsFrom(self.data, self);
            self.service.assumeRole({
                RoleArn: params.roleArn,
                RoleSessionName: params.roleSessionName || 'token-file-web-identity'
            }, function(err, data) {
                self.data = null;
                if (err) callback(err);
                else {
                    self.data = data;
                    self.assumeRoleChaining(paramsArray, callback);
                }
            });
        }
    },
    /**
   * @api private
   */ load: function load(callback) {
        var self = this;
        try {
            var paramsArray = self.getParamsFromEnv();
            if (!paramsArray) paramsArray = self.getParamsFromSharedConfig();
            if (paramsArray) {
                var params = paramsArray.shift();
                var oidcToken = $dDec7$fs.readFileSync(params.envTokenFile, {
                    encoding: 'ascii'
                });
                if (!self.service) self.createClients();
                self.service.assumeRoleWithWebIdentity({
                    WebIdentityToken: oidcToken,
                    RoleArn: params.roleArn,
                    RoleSessionName: params.roleSessionName || 'token-file-web-identity'
                }, function(err, data) {
                    self.data = null;
                    if (err) callback(err);
                    else {
                        self.data = data;
                        self.assumeRoleChaining(paramsArray, callback);
                    }
                });
            }
        } catch (err) {
            callback(err);
        }
    },
    /**
   * @api private
   */ createClients: function() {
        if (!this.service) {
            var stsConfig = $hIq4q.util.merge({}, this.clientConfig);
            this.service = new $dffa98b1230ab04c$exports(stsConfig);
            // Retry in case of IDPCommunicationErrorException or InvalidIdentityToken
            this.service.retryableError = function(error) {
                if (error.code === 'IDPCommunicationErrorException' || error.code === 'InvalidIdentityToken') return true;
                else return $hIq4q.Service.prototype.retryableError.call(this, error);
            };
        }
    }
});



var $hIq4q = parcelRequire("hIq4q");
var $66ee852dd8110a33$exports = {};

var $hIq4q = parcelRequire("hIq4q");
parcelRequire("jI9el");
var $66ee852dd8110a33$var$inherit = $hIq4q.util.inherit;
var $346f9ae309d26ae5$exports = {};

var $hIq4q = parcelRequire("hIq4q");

var $346f9ae309d26ae5$var$Endpoint = (parcelRequire("c7w72"))();

var $346f9ae309d26ae5$var$EndpointMode = (parcelRequire("2x6hq"))();

var $346f9ae309d26ae5$var$ENDPOINT_CONFIG_OPTIONS = (parcelRequire("hthfz"))();

var $346f9ae309d26ae5$var$ENDPOINT_MODE_CONFIG_OPTIONS = (parcelRequire("4NZFI"))();
var $346f9ae309d26ae5$var$getMetadataServiceEndpoint = function() {
    var endpoint = $hIq4q.util.loadConfig($346f9ae309d26ae5$var$ENDPOINT_CONFIG_OPTIONS);
    if (endpoint !== undefined) return endpoint;
    var endpointMode = $hIq4q.util.loadConfig($346f9ae309d26ae5$var$ENDPOINT_MODE_CONFIG_OPTIONS);
    switch(endpointMode){
        case $346f9ae309d26ae5$var$EndpointMode.IPv4:
            return $346f9ae309d26ae5$var$Endpoint.IPv4;
        case $346f9ae309d26ae5$var$EndpointMode.IPv6:
            return $346f9ae309d26ae5$var$Endpoint.IPv6;
        default:
            throw new Error('Unsupported endpoint mode: ' + endpointMode);
    }
};
$346f9ae309d26ae5$exports = $346f9ae309d26ae5$var$getMetadataServiceEndpoint;



var $66ee852dd8110a33$require$URL = $dDec7$url.URL;
/**
 * Represents a metadata service available on EC2 instances. Using the
 * {request} method, you can receieve metadata about any available resource
 * on the metadata service.
 *
 * You can disable the use of the IMDS by setting the AWS_EC2_METADATA_DISABLED
 * environment variable to a truthy value.
 *
 * @!attribute [r] httpOptions
 *   @return [map] a map of options to pass to the underlying HTTP request:
 *
 *     * **timeout** (Number) &mdash; a timeout value in milliseconds to wait
 *       before aborting the connection. Set to 0 for no timeout.
 *
 * @!macro nobrowser
 */ $hIq4q.MetadataService = $66ee852dd8110a33$var$inherit({
    /**
   * @return [String] the endpoint of the instance metadata service
   */ endpoint: $346f9ae309d26ae5$exports(),
    /**
   * @!ignore
   */ /**
   * Default HTTP options. By default, the metadata service is set to not
   * timeout on long requests. This means that on non-EC2 machines, this
   * request will never return. If you are calling this operation from an
   * environment that may not always run on EC2, set a `timeout` value so
   * the SDK will abort the request after a given number of milliseconds.
   */ httpOptions: {
        timeout: 0
    },
    /**
   * when enabled, metadata service will not fetch token
   */ disableFetchToken: false,
    /**
   * Creates a new MetadataService object with a given set of options.
   *
   * @option options host [String] the hostname of the instance metadata
   *   service
   * @option options httpOptions [map] a map of options to pass to the
   *   underlying HTTP request:
   *
   *   * **timeout** (Number) &mdash; a timeout value in milliseconds to wait
   *     before aborting the connection. Set to 0 for no timeout.
   * @option options maxRetries [Integer] the maximum number of retries to
   *   perform for timeout errors
   * @option options retryDelayOptions [map] A set of options to configure the
   *   retry delay on retryable errors. See AWS.Config for details.
   * @option options ec2MetadataV1Disabled [boolean] Whether to block IMDS v1 fallback.
   * @option options profile [string] A profile to check for IMDSv1 fallback settings.
   * @option options filename [string] Optional filename for the config file.
   */ constructor: function MetadataService(options) {
        if (options && options.host) {
            options.endpoint = 'http://' + options.host;
            delete options.host;
        }
        this.profile = options && options.profile || process.env.AWS_PROFILE || $hIq4q.util.defaultProfile;
        this.ec2MetadataV1Disabled = !!(options && options.ec2MetadataV1Disabled);
        this.filename = options && options.filename;
        $hIq4q.util.update(this, options);
    },
    /**
   * Sends a request to the instance metadata service for a given resource.
   *
   * @param path [String] the path of the resource to get
   *
   * @param options [map] an optional map used to make request
   *
   *   * **method** (String) &mdash; HTTP request method
   *
   *   * **headers** (map<String,String>) &mdash; a map of response header keys and their respective values
   *
   * @callback callback function(err, data)
   *   Called when a response is available from the service.
   *   @param err [Error, null] if an error occurred, this value will be set
   *   @param data [String, null] if the request was successful, the body of
   *     the response
   */ request: function request(path, options, callback) {
        if (arguments.length === 2) {
            callback = options;
            options = {};
        }
        if (process.env[$hIq4q.util.imdsDisabledEnv]) {
            callback(new Error('EC2 Instance Metadata Service access disabled'));
            return;
        }
        path = path || '/';
        // Verify that host is a valid URL
        if ($66ee852dd8110a33$require$URL) new $66ee852dd8110a33$require$URL(this.endpoint);
        var httpRequest = new $hIq4q.HttpRequest(this.endpoint + path);
        httpRequest.method = options.method || 'GET';
        if (options.headers) httpRequest.headers = options.headers;
        $hIq4q.util.handleRequestWithRetries(httpRequest, this, callback);
    },
    /**
  * @api private
  */ loadCredentialsCallbacks: [],
    /**
   * Fetches metadata token used for authenticating against the instance metadata service.
   *
   * @callback callback function(err, token)
   *   Called when token is loaded from the resource
   */ fetchMetadataToken: function fetchMetadataToken(callback) {
        var self = this;
        var tokenFetchPath = '/latest/api/token';
        self.request(tokenFetchPath, {
            'method': 'PUT',
            'headers': {
                'x-aws-ec2-metadata-token-ttl-seconds': '21600'
            }
        }, callback);
    },
    /**
   * Fetches credentials
   *
   * @api private
   * @callback cb function(err, creds)
   *   Called when credentials are loaded from the resource
   */ fetchCredentials: function fetchCredentials(options, cb) {
        var self = this;
        var basePath = '/latest/meta-data/iam/security-credentials/';
        var isImdsV1Fallback = self.disableFetchToken || !(options && options.headers && options.headers['x-aws-ec2-metadata-token']);
        if (isImdsV1Fallback && !process.env.AWS_EC2_METADATA_DISABLED) {
            try {
                var profiles = $hIq4q.util.getProfilesFromSharedConfig($hIq4q.util.iniLoader, this.filename);
                var profileSettings = profiles[this.profile] || {};
            } catch (e) {
                profileSettings = {};
            }
            if (profileSettings.ec2_metadata_v1_disabled && profileSettings.ec2_metadata_v1_disabled !== 'false') return cb($hIq4q.util.error(new Error('AWS EC2 Metadata v1 fallback has been blocked by AWS config file profile.')));
            if (self.ec2MetadataV1Disabled) return cb($hIq4q.util.error(new Error('AWS EC2 Metadata v1 fallback has been blocked by AWS.MetadataService::options.ec2MetadataV1Disabled=true.')));
            if (process.env.AWS_EC2_METADATA_V1_DISABLED && process.env.AWS_EC2_METADATA_V1_DISABLED !== 'false') return cb($hIq4q.util.error(new Error('AWS EC2 Metadata v1 fallback has been blocked by process.env.AWS_EC2_METADATA_V1_DISABLED.')));
        }
        self.request(basePath, options, function(err, roleName) {
            if (err) {
                self.disableFetchToken = !(err.statusCode === 401);
                cb($hIq4q.util.error(err, {
                    message: 'EC2 Metadata roleName request returned error'
                }));
                return;
            }
            roleName = roleName.split('\n')[0]; // grab first (and only) role
            self.request(basePath + roleName, options, function(credErr, credData) {
                if (credErr) {
                    self.disableFetchToken = !(credErr.statusCode === 401);
                    cb($hIq4q.util.error(credErr, {
                        message: 'EC2 Metadata creds request returned error'
                    }));
                    return;
                }
                try {
                    var credentials = JSON.parse(credData);
                    cb(null, credentials);
                } catch (parseError) {
                    cb(parseError);
                }
            });
        });
    },
    /**
   * Loads a set of credentials stored in the instance metadata service
   *
   * @api private
   * @callback callback function(err, credentials)
   *   Called when credentials are loaded from the resource
   *   @param err [Error] if an error occurred, this value will be set
   *   @param credentials [Object] the raw JSON object containing all
   *     metadata from the credentials resource
   */ loadCredentials: function loadCredentials(callback) {
        var self = this;
        self.loadCredentialsCallbacks.push(callback);
        if (self.loadCredentialsCallbacks.length > 1) return;
        function callbacks(err, creds) {
            var cb;
            while((cb = self.loadCredentialsCallbacks.shift()) !== undefined)cb(err, creds);
        }
        if (self.disableFetchToken) self.fetchCredentials({}, callbacks);
        else self.fetchMetadataToken(function(tokenError, token) {
            if (tokenError) {
                if (tokenError.code === 'TimeoutError') self.disableFetchToken = true;
                else if (tokenError.retryable === true) {
                    callbacks($hIq4q.util.error(tokenError, {
                        message: 'EC2 Metadata token request returned error'
                    }));
                    return;
                } else if (tokenError.statusCode === 400) {
                    callbacks($hIq4q.util.error(tokenError, {
                        message: 'EC2 Metadata token request returned 400'
                    }));
                    return;
                }
            }
            var options = {};
            if (token) options.headers = {
                'x-aws-ec2-metadata-token': token
            };
            self.fetchCredentials(options, callbacks);
        });
    }
});
/**
 * @api private
 */ $66ee852dd8110a33$exports = $hIq4q.MetadataService;


/**
 * Represents credentials received from the metadata service on an EC2 instance.
 *
 * By default, this class will connect to the metadata service using
 * {AWS.MetadataService} and attempt to load any available credentials. If it
 * can connect, and credentials are available, these will be used with zero
 * configuration.
 *
 * This credentials class will by default timeout after 1 second of inactivity
 * and retry 3 times.
 * If your requests to the EC2 metadata service are timing out, you can increase
 * these values by configuring them directly:
 *
 * ```javascript
 * AWS.config.credentials = new AWS.EC2MetadataCredentials({
 *   httpOptions: { timeout: 5000 }, // 5 second timeout
 *   maxRetries: 10, // retry 10 times
 *   retryDelayOptions: { base: 200 }, // see AWS.Config for information
 *   logger: console // see AWS.Config for information
 *   ec2MetadataV1Disabled: false // whether to block IMDS v1 fallback.
 * });
 * ```
 *
 * If your requests are timing out in connecting to the metadata service, such
 * as when testing on a development machine, you can use the connectTimeout
 * option, specified in milliseconds, which also defaults to 1 second.
 *
 * If the requests failed or returns expired credentials, it will
 * extend the expiration of current credential, with a warning message. For more
 * information, please go to:
 * https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html
 *
 * @!attribute originalExpiration
 *   @return [Date] The optional original expiration of the current credential.
 *   In case of AWS outage, the EC2 metadata will extend expiration of the
 *   existing credential.
 *
 * @see AWS.Config.retryDelayOptions
 * @see AWS.Config.logger
 *
 * @!macro nobrowser
 */ $hIq4q.EC2MetadataCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    constructor: function EC2MetadataCredentials(options) {
        $hIq4q.Credentials.call(this);
        options = options ? $hIq4q.util.copy(options) : {};
        options = $hIq4q.util.merge({
            maxRetries: this.defaultMaxRetries
        }, options);
        if (!options.httpOptions) options.httpOptions = {};
        options.httpOptions = $hIq4q.util.merge({
            timeout: this.defaultTimeout,
            connectTimeout: this.defaultConnectTimeout
        }, options.httpOptions);
        this.metadataService = new $hIq4q.MetadataService(options);
        this.logger = options.logger || $hIq4q.config && $hIq4q.config.logger;
    },
    /**
   * @api private
   */ defaultTimeout: 1000,
    /**
   * @api private
   */ defaultConnectTimeout: 1000,
    /**
   * @api private
   */ defaultMaxRetries: 3,
    /**
   * The original expiration of the current credential. In case of AWS
   * outage, the EC2 metadata will extend expiration of the existing
   * credential.
   */ originalExpiration: undefined,
    /**
   * Loads the credentials from the instance metadata service
   *
   * @callback callback function(err)
   *   Called when the instance metadata service responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    },
    /**
   * @api private
   * @param callback
   */ load: function load(callback) {
        var self = this;
        self.metadataService.loadCredentials(function(err, creds) {
            if (err) {
                if (self.hasLoadedCredentials()) {
                    self.extendExpirationIfExpired();
                    callback();
                } else callback(err);
            } else {
                self.setCredentials(creds);
                self.extendExpirationIfExpired();
                callback();
            }
        });
    },
    /**
   * Whether this credential has been loaded.
   * @api private
   */ hasLoadedCredentials: function hasLoadedCredentials() {
        return this.AccessKeyId && this.secretAccessKey;
    },
    /**
   * if expired, extend the expiration by 15 minutes base plus a jitter of 5
   * minutes range.
   * @api private
   */ extendExpirationIfExpired: function extendExpirationIfExpired() {
        if (this.needsRefresh()) {
            this.originalExpiration = this.originalExpiration || this.expireTime;
            this.expired = false;
            var nextTimeout = 900 + Math.floor(Math.random() * 300);
            var currentTime = $hIq4q.util.date.getDate().getTime();
            this.expireTime = new Date(currentTime + nextTimeout * 1000);
            // TODO: add doc link;
            this.logger.warn("Attempting credential expiration extension due to a credential service availability issue. A refresh of these credentials will be attempted again at " + this.expireTime + '\nFor more information, please visit: https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html');
        }
    },
    /**
   * Update the credential with new credential responded from EC2 metadata
   * service.
   * @api private
   */ setCredentials: function setCredentials(creds) {
        var currentTime = $hIq4q.util.date.getDate().getTime();
        var expireTime = new Date(creds.Expiration);
        this.expired = currentTime >= expireTime ? true : false;
        this.metadata = creds;
        this.accessKeyId = creds.AccessKeyId;
        this.secretAccessKey = creds.SecretAccessKey;
        this.sessionToken = creds.Token;
        this.expireTime = expireTime;
    }
});




var $hIq4q = parcelRequire("hIq4q");
var $6657e622cda44cd7$var$ENV_RELATIVE_URI = 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', $6657e622cda44cd7$var$ENV_FULL_URI = 'AWS_CONTAINER_CREDENTIALS_FULL_URI', $6657e622cda44cd7$var$ENV_AUTH_TOKEN = 'AWS_CONTAINER_AUTHORIZATION_TOKEN', $6657e622cda44cd7$var$ENV_AUTH_TOKEN_FILE = 'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE', $6657e622cda44cd7$var$FULL_URI_UNRESTRICTED_PROTOCOLS = [
    'https:'
], $6657e622cda44cd7$var$FULL_URI_ALLOWED_PROTOCOLS = [
    'http:',
    'https:'
], $6657e622cda44cd7$var$FULL_URI_ALLOWED_HOSTNAMES = [
    'localhost',
    '127.0.0.1',
    '169.254.170.23'
], $6657e622cda44cd7$var$RELATIVE_URI_HOST = '169.254.170.2';
/**
 * Represents credentials received from specified URI.
 *
 * This class will request refreshable credentials from the relative URI
 * specified by the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or the
 * AWS_CONTAINER_CREDENTIALS_FULL_URI environment variable. If valid credentials
 * are returned in the response, these will be used with zero configuration.
 *
 * This credentials class will by default timeout after 1 second of inactivity
 * and retry 3 times.
 * If your requests to the relative URI are timing out, you can increase
 * the value by configuring them directly:
 *
 * ```javascript
 * AWS.config.credentials = new AWS.RemoteCredentials({
 *   httpOptions: { timeout: 5000 }, // 5 second timeout
 *   maxRetries: 10, // retry 10 times
 *   retryDelayOptions: { base: 200 } // see AWS.Config for information
 * });
 * ```
 *
 * @see AWS.Config.retryDelayOptions
 *
 * @!macro nobrowser
 */ $hIq4q.RemoteCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    constructor: function RemoteCredentials(options) {
        $hIq4q.Credentials.call(this);
        options = options ? $hIq4q.util.copy(options) : {};
        if (!options.httpOptions) options.httpOptions = {};
        options.httpOptions = $hIq4q.util.merge(this.httpOptions, options.httpOptions);
        $hIq4q.util.update(this, options);
    },
    /**
   * @api private
   */ httpOptions: {
        timeout: 1000
    },
    /**
   * @api private
   */ maxRetries: 3,
    /**
   * @api private
   */ isConfiguredForEcsCredentials: function isConfiguredForEcsCredentials() {
        return Boolean(process && process.env && (process.env[$6657e622cda44cd7$var$ENV_RELATIVE_URI] || process.env[$6657e622cda44cd7$var$ENV_FULL_URI]));
    },
    /**
   * @api private
   */ getECSFullUri: function getECSFullUri() {
        if (process && process.env) {
            var relative = process.env[$6657e622cda44cd7$var$ENV_RELATIVE_URI], full = process.env[$6657e622cda44cd7$var$ENV_FULL_URI];
            if (relative) return 'http://' + $6657e622cda44cd7$var$RELATIVE_URI_HOST + relative;
            else if (full) {
                var parsed = $hIq4q.util.urlParse(full);
                if ($6657e622cda44cd7$var$FULL_URI_ALLOWED_PROTOCOLS.indexOf(parsed.protocol) < 0) throw $hIq4q.util.error(new Error('Unsupported protocol:  AWS.RemoteCredentials supports ' + $6657e622cda44cd7$var$FULL_URI_ALLOWED_PROTOCOLS.join(',') + ' only; ' + parsed.protocol + ' requested.'), {
                    code: 'ECSCredentialsProviderFailure'
                });
                if ($6657e622cda44cd7$var$FULL_URI_UNRESTRICTED_PROTOCOLS.indexOf(parsed.protocol) < 0 && $6657e622cda44cd7$var$FULL_URI_ALLOWED_HOSTNAMES.indexOf(parsed.hostname) < 0) throw $hIq4q.util.error(new Error('Unsupported hostname: AWS.RemoteCredentials only supports ' + $6657e622cda44cd7$var$FULL_URI_ALLOWED_HOSTNAMES.join(',') + ' for ' + parsed.protocol + '; ' + parsed.protocol + '//' + parsed.hostname + ' requested.'), {
                    code: 'ECSCredentialsProviderFailure'
                });
                return full;
            } else throw $hIq4q.util.error(new Error('Variable ' + $6657e622cda44cd7$var$ENV_RELATIVE_URI + ' or ' + $6657e622cda44cd7$var$ENV_FULL_URI + ' must be set to use AWS.RemoteCredentials.'), {
                code: 'ECSCredentialsProviderFailure'
            });
        } else throw $hIq4q.util.error(new Error('No process info available'), {
            code: 'ECSCredentialsProviderFailure'
        });
    },
    /**
   * @api private
   */ getECSAuthToken: function getECSAuthToken() {
        if (process && process.env && (process.env[$6657e622cda44cd7$var$ENV_FULL_URI] || process.env[$6657e622cda44cd7$var$ENV_AUTH_TOKEN_FILE])) {
            if (!process.env[$6657e622cda44cd7$var$ENV_AUTH_TOKEN] && process.env[$6657e622cda44cd7$var$ENV_AUTH_TOKEN_FILE]) try {
                var data = $dDec7$fs.readFileSync(process.env[$6657e622cda44cd7$var$ENV_AUTH_TOKEN_FILE]).toString();
                return data;
            } catch (error) {
                console.error('Error reading token file:', error);
                throw error; // Re-throw the error to propagate it
            }
            return process.env[$6657e622cda44cd7$var$ENV_AUTH_TOKEN];
        }
    },
    /**
   * @api private
   */ credsFormatIsValid: function credsFormatIsValid(credData) {
        return !!credData.accessKeyId && !!credData.secretAccessKey && !!credData.sessionToken && !!credData.expireTime;
    },
    /**
   * @api private
   */ formatCreds: function formatCreds(credData) {
        if (!!credData.credentials) credData = credData.credentials;
        return {
            expired: false,
            accessKeyId: credData.accessKeyId || credData.AccessKeyId,
            secretAccessKey: credData.secretAccessKey || credData.SecretAccessKey,
            sessionToken: credData.sessionToken || credData.Token,
            expireTime: new Date(credData.expiration || credData.Expiration)
        };
    },
    /**
   * @api private
   */ request: function request(url, callback) {
        var httpRequest = new $hIq4q.HttpRequest(url);
        httpRequest.method = 'GET';
        httpRequest.headers.Accept = 'application/json';
        var token = this.getECSAuthToken();
        if (token) httpRequest.headers.Authorization = token;
        $hIq4q.util.handleRequestWithRetries(httpRequest, this, callback);
    },
    /**
   * Loads the credentials from the relative URI specified by container
   *
   * @callback callback function(err)
   *   Called when the request to the relative URI responds (or fails). When
   *   this callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, `sessionToken`, and `expireTime` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    },
    /**
   * @api private
   */ load: function load(callback) {
        var self = this;
        var fullUri;
        try {
            fullUri = this.getECSFullUri();
        } catch (err) {
            callback(err);
            return;
        }
        this.request(fullUri, function(err, data) {
            if (!err) try {
                data = JSON.parse(data);
                var creds = self.formatCreds(data);
                if (!self.credsFormatIsValid(creds)) throw $hIq4q.util.error(new Error('Response data is not in valid format'), {
                    code: 'ECSCredentialsProviderFailure'
                });
                $hIq4q.util.update(self, creds);
            } catch (dataError) {
                err = dataError;
            }
            callback(err, creds);
        });
    }
});



var $hIq4q = parcelRequire("hIq4q");
/**
 * Represents credentials received from relative URI specified in the ECS container.
 *
 * This class will request refreshable credentials from the relative URI
 * specified by the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or the
 * AWS_CONTAINER_CREDENTIALS_FULL_URI environment variable. If valid credentials
 * are returned in the response, these will be used with zero configuration.
 *
 * This credentials class will by default timeout after 1 second of inactivity
 * and retry 3 times.
 * If your requests to the relative URI are timing out, you can increase
 * the value by configuring them directly:
 *
 * ```javascript
 * AWS.config.credentials = new AWS.ECSCredentials({
 *   httpOptions: { timeout: 5000 }, // 5 second timeout
 *   maxRetries: 10, // retry 10 times
 *   retryDelayOptions: { base: 200 } // see AWS.Config for information
 * });
 * ```
 *
 * @see AWS.Config.retryDelayOptions
 *
 * @!macro nobrowser
 */ $hIq4q.ECSCredentials = $hIq4q.RemoteCredentials;



var $hIq4q = parcelRequire("hIq4q");
/**
 * Represents credentials from the environment.
 *
 * By default, this class will look for the matching environment variables
 * prefixed by a given {envPrefix}. The un-prefixed environment variable names
 * for each credential value is listed below:
 *
 * ```javascript
 * accessKeyId: ACCESS_KEY_ID
 * secretAccessKey: SECRET_ACCESS_KEY
 * sessionToken: SESSION_TOKEN
 * ```
 *
 * With the default prefix of 'AWS', the environment variables would be:
 *
 *     AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
 *
 * @!attribute envPrefix
 *   @readonly
 *   @return [String] the prefix for the environment variable names excluding
 *     the separating underscore ('_').
 */ $hIq4q.EnvironmentCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new EnvironmentCredentials class with a given variable
   * prefix {envPrefix}. For example, to load credentials using the 'AWS'
   * prefix:
   *
   * ```javascript
   * var creds = new AWS.EnvironmentCredentials('AWS');
   * creds.accessKeyId == 'AKID' // from AWS_ACCESS_KEY_ID env var
   * ```
   *
   * @param envPrefix [String] the prefix to use (e.g., 'AWS') for environment
   *   variables. Do not include the separating underscore.
   */ constructor: function EnvironmentCredentials(envPrefix) {
        $hIq4q.Credentials.call(this);
        this.envPrefix = envPrefix;
        this.get(function() {});
    },
    /**
   * Loads credentials from the environment using the prefixed
   * environment variables.
   *
   * @callback callback function(err)
   *   Called after the (prefixed) ACCESS_KEY_ID, SECRET_ACCESS_KEY, and
   *   SESSION_TOKEN environment variables are read. When this callback is
   *   called with no error, it means that the credentials information has
   *   been loaded into the object (as the `accessKeyId`, `secretAccessKey`,
   *   and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        if (!callback) callback = $hIq4q.util.fn.callback;
        if (!process || !process.env) {
            callback($hIq4q.util.error(new Error('No process info or environment variables available'), {
                code: 'EnvironmentCredentialsProviderFailure'
            }));
            return;
        }
        var keys = [
            'ACCESS_KEY_ID',
            'SECRET_ACCESS_KEY',
            'SESSION_TOKEN'
        ];
        var values = [];
        for(var i = 0; i < keys.length; i++){
            var prefix = '';
            if (this.envPrefix) prefix = this.envPrefix + '_';
            values[i] = process.env[prefix + keys[i]];
            if (!values[i] && keys[i] !== 'SESSION_TOKEN') {
                callback($hIq4q.util.error(new Error('Variable ' + prefix + keys[i] + ' not set.'), {
                    code: 'EnvironmentCredentialsProviderFailure'
                }));
                return;
            }
        }
        this.expired = false;
        $hIq4q.Credentials.apply(this, values);
        callback();
    }
});



var $hIq4q = parcelRequire("hIq4q");
/**
 * Represents credentials from a JSON file on disk.
 * If the credentials expire, the SDK can {refresh} the credentials
 * from the file.
 *
 * The format of the file should be similar to the options passed to
 * {AWS.Config}:
 *
 * ```javascript
 * {accessKeyId: 'akid', secretAccessKey: 'secret', sessionToken: 'optional'}
 * ```
 *
 * @example Loading credentials from disk
 *   var creds = new AWS.FileSystemCredentials('./configuration.json');
 *   creds.accessKeyId == 'AKID'
 *
 * @!attribute filename
 *   @readonly
 *   @return [String] the path to the JSON file on disk containing the
 *     credentials.
 * @!macro nobrowser
 */ $hIq4q.FileSystemCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * @overload AWS.FileSystemCredentials(filename)
   *   Creates a new FileSystemCredentials object from a filename
   *
   *   @param filename [String] the path on disk to the JSON file to load.
   */ constructor: function FileSystemCredentials(filename) {
        $hIq4q.Credentials.call(this);
        this.filename = filename;
        this.get(function() {});
    },
    /**
   * Loads the credentials from the {filename} on disk.
   *
   * @callback callback function(err)
   *   Called after the JSON file on disk is read and parsed. When this callback
   *   is called with no error, it means that the credentials information
   *   has been loaded into the object (as the `accessKeyId`, `secretAccessKey`,
   *   and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        if (!callback) callback = $hIq4q.util.fn.callback;
        try {
            var creds = JSON.parse($hIq4q.util.readFileSync(this.filename));
            $hIq4q.Credentials.call(this, creds);
            if (!this.accessKeyId || !this.secretAccessKey) throw $hIq4q.util.error(new Error('Credentials not set in ' + this.filename), {
                code: 'FileSystemCredentialsProviderFailure'
            });
            this.expired = false;
            callback();
        } catch (err) {
            callback(err);
        }
    }
});



var $hIq4q = parcelRequire("hIq4q");

var $6ba4d3b4aca60791$var$iniLoader = $hIq4q.util.iniLoader;
var $6ba4d3b4aca60791$var$ASSUME_ROLE_DEFAULT_REGION = 'us-east-1';
/**
 * Represents credentials loaded from shared credentials file
 * (defaulting to ~/.aws/credentials or defined by the
 * `AWS_SHARED_CREDENTIALS_FILE` environment variable).
 *
 * ## Using the shared credentials file
 *
 * This provider is checked by default in the Node.js environment. To use the
 * credentials file provider, simply add your access and secret keys to the
 * ~/.aws/credentials file in the following format:
 *
 *     [default]
 *     aws_access_key_id = AKID...
 *     aws_secret_access_key = YOUR_SECRET_KEY
 *
 * ## Using custom profiles
 *
 * The SDK supports loading credentials for separate profiles. This can be done
 * in two ways:
 *
 * 1. Set the `AWS_PROFILE` environment variable in your process prior to
 *    loading the SDK.
 * 2. Directly load the AWS.SharedIniFileCredentials provider:
 *
 * ```javascript
 * var creds = new AWS.SharedIniFileCredentials({profile: 'myprofile'});
 * AWS.config.credentials = creds;
 * ```
 *
 * @!macro nobrowser
 */ $hIq4q.SharedIniFileCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new SharedIniFileCredentials object.
   *
   * @param options [map] a set of options
   * @option options profile [String] (AWS_PROFILE env var or 'default')
   *   the name of the profile to load.
   * @option options filename [String] ('~/.aws/credentials' or defined by
   *   AWS_SHARED_CREDENTIALS_FILE process env var)
   *   the filename to use when loading credentials.
   * @option options disableAssumeRole [Boolean] (false) True to disable
   *   support for profiles that assume an IAM role. If true, and an assume
   *   role profile is selected, an error is raised.
   * @option options preferStaticCredentials [Boolean] (false) True to
   *   prefer static credentials to role_arn if both are present.
   * @option options tokenCodeFn [Function] (null) Function to provide
   *   STS Assume Role TokenCode, if mfa_serial is provided for profile in ini
   *   file. Function is called with value of mfa_serial and callback, and
   *   should provide the TokenCode or an error to the callback in the format
   *   callback(err, token)
   * @option options callback [Function] (err) Credentials are eagerly loaded
   *   by the constructor. When the callback is called with no error, the
   *   credentials have been loaded successfully.
   * @option options httpOptions [map] A set of options to pass to the low-level
   *   HTTP request. Currently supported options are:
   *   * **proxy** [String] &mdash; the URL to proxy requests through
   *   * **agent** [http.Agent, https.Agent] &mdash; the Agent object to perform
   *     HTTP requests with. Used for connection pooling. Defaults to the global
   *     agent (`http.globalAgent`) for non-SSL connections. Note that for
   *     SSL connections, a special Agent object is used in order to enable
   *     peer certificate verification. This feature is only available in the
   *     Node.js environment.
   *   * **connectTimeout** [Integer] &mdash; Sets the socket to timeout after
   *     failing to establish a connection with the server after
   *     `connectTimeout` milliseconds. This timeout has no effect once a socket
   *     connection has been established.
   *   * **timeout** [Integer] &mdash; The number of milliseconds a request can
   *     take before automatically being terminated.
   *     Defaults to two minutes (120000).
   */ constructor: function SharedIniFileCredentials(options) {
        $hIq4q.Credentials.call(this);
        options = options || {};
        this.filename = options.filename;
        this.profile = options.profile || process.env.AWS_PROFILE || $hIq4q.util.defaultProfile;
        this.disableAssumeRole = Boolean(options.disableAssumeRole);
        this.preferStaticCredentials = Boolean(options.preferStaticCredentials);
        this.tokenCodeFn = options.tokenCodeFn || null;
        this.httpOptions = options.httpOptions || null;
        this.get(options.callback || $hIq4q.util.fn.noop);
    },
    /**
   * @api private
   */ load: function load(callback) {
        var self = this;
        try {
            var profiles = $hIq4q.util.getProfilesFromSharedConfig($6ba4d3b4aca60791$var$iniLoader, this.filename);
            var profile = profiles[this.profile] || {};
            if (Object.keys(profile).length === 0) throw $hIq4q.util.error(new Error('Profile ' + this.profile + ' not found'), {
                code: 'SharedIniFileCredentialsProviderFailure'
            });
            /*
      In the CLI, the presence of both a role_arn and static credentials have
      different meanings depending on how many profiles have been visited. For
      the first profile processed, role_arn takes precedence over any static
      credentials, but for all subsequent profiles, static credentials are
      used if present, and only in their absence will the profile's
      source_profile and role_arn keys be used to load another set of
      credentials. This var is intended to yield compatible behaviour in this
      sdk.
      */ var preferStaticCredentialsToRoleArn = Boolean(this.preferStaticCredentials && profile['aws_access_key_id'] && profile['aws_secret_access_key']);
            if (profile['role_arn'] && !preferStaticCredentialsToRoleArn) {
                this.loadRoleProfile(profiles, profile, function(err, data) {
                    if (err) callback(err);
                    else {
                        self.expired = false;
                        self.accessKeyId = data.Credentials.AccessKeyId;
                        self.secretAccessKey = data.Credentials.SecretAccessKey;
                        self.sessionToken = data.Credentials.SessionToken;
                        self.expireTime = data.Credentials.Expiration;
                        callback(null);
                    }
                });
                return;
            }
            this.accessKeyId = profile['aws_access_key_id'];
            this.secretAccessKey = profile['aws_secret_access_key'];
            this.sessionToken = profile['aws_session_token'];
            if (!this.accessKeyId || !this.secretAccessKey) throw $hIq4q.util.error(new Error('Credentials not set for profile ' + this.profile), {
                code: 'SharedIniFileCredentialsProviderFailure'
            });
            this.expired = false;
            callback(null);
        } catch (err) {
            callback(err);
        }
    },
    /**
   * Loads the credentials from the shared credentials file
   *
   * @callback callback function(err)
   *   Called after the shared INI file on disk is read and parsed. When this
   *   callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        $6ba4d3b4aca60791$var$iniLoader.clearCachedFiles();
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback, this.disableAssumeRole);
    },
    /**
   * @api private
   */ loadRoleProfile: function loadRoleProfile(creds, roleProfile, callback) {
        if (this.disableAssumeRole) throw $hIq4q.util.error(new Error("Role assumption profiles are disabled. Failed to load profile " + this.profile + ' from ' + creds.filename), {
            code: 'SharedIniFileCredentialsProviderFailure'
        });
        var self = this;
        var roleArn = roleProfile['role_arn'];
        var roleSessionName = roleProfile['role_session_name'];
        var externalId = roleProfile['external_id'];
        var mfaSerial = roleProfile['mfa_serial'];
        var sourceProfileName = roleProfile['source_profile'];
        var durationSeconds = parseInt(roleProfile['duration_seconds'], 10) || undefined;
        // From experimentation, the following behavior mimics the AWS CLI:
        //
        // 1. Use region from the profile if present.
        // 2. Otherwise fall back to N. Virginia (global endpoint).
        //
        // It is necessary to do the fallback explicitly, because if
        // 'AWS_STS_REGIONAL_ENDPOINTS=regional', the underlying STS client will
        // otherwise throw an error if region is left 'undefined'.
        //
        // Experimentation shows that the AWS CLI (tested at version 1.18.136)
        // ignores the following potential sources of a region for the purposes of
        // this AssumeRole call:
        //
        // - The [default] profile
        // - The AWS_REGION environment variable
        //
        // Ignoring the [default] profile for the purposes of AssumeRole is arguably
        // a bug in the CLI since it does use the [default] region for service
        // calls... but right now we're matching behavior of the other tool.
        var profileRegion = roleProfile['region'] || $6ba4d3b4aca60791$var$ASSUME_ROLE_DEFAULT_REGION;
        if (!sourceProfileName) throw $hIq4q.util.error(new Error('source_profile is not set using profile ' + this.profile), {
            code: 'SharedIniFileCredentialsProviderFailure'
        });
        var sourceProfileExistanceTest = creds[sourceProfileName];
        if (typeof sourceProfileExistanceTest !== 'object') throw $hIq4q.util.error(new Error('source_profile ' + sourceProfileName + ' using profile ' + this.profile + ' does not exist'), {
            code: 'SharedIniFileCredentialsProviderFailure'
        });
        var sourceCredentials = new $hIq4q.SharedIniFileCredentials($hIq4q.util.merge(this.options || {}, {
            profile: sourceProfileName,
            preferStaticCredentials: true
        }));
        this.roleArn = roleArn;
        var sts = new $dffa98b1230ab04c$exports({
            credentials: sourceCredentials,
            region: profileRegion,
            httpOptions: this.httpOptions
        });
        var roleParams = {
            DurationSeconds: durationSeconds,
            RoleArn: roleArn,
            RoleSessionName: roleSessionName || 'aws-sdk-js-' + Date.now()
        };
        if (externalId) roleParams.ExternalId = externalId;
        if (mfaSerial && self.tokenCodeFn) {
            roleParams.SerialNumber = mfaSerial;
            self.tokenCodeFn(mfaSerial, function(err, token) {
                if (err) {
                    var message;
                    if (err instanceof Error) message = err.message;
                    else message = err;
                    callback($hIq4q.util.error(new Error('Error fetching MFA token: ' + message), {
                        code: 'SharedIniFileCredentialsProviderFailure'
                    }));
                    return;
                }
                roleParams.TokenCode = token;
                sts.assumeRole(roleParams, callback);
            });
            return;
        }
        sts.assumeRole(roleParams, callback);
    }
});




var $hIq4q = parcelRequire("hIq4q");


var $7852f3d93e4177a3$var$iniLoader = $hIq4q.util.iniLoader;
/**
 *  Represents credentials from sso.getRoleCredentials API for
 * `sso_*` values defined in shared credentials file.
 *
 * ## Using SSO credentials
 *
 * The credentials file must specify the information below to use sso:
 *
 *     [profile sso-profile]
 *     sso_account_id = 012345678901
 *     sso_region = **-****-*
 *     sso_role_name = SampleRole
 *     sso_start_url = https://d-******.awsapps.com/start
 *
 * or using the session format:
 *
 *     [profile sso-token]
 *     sso_session = prod
 *     sso_account_id = 012345678901
 *     sso_role_name = SampleRole
 *
 *     [sso-session prod]
 *     sso_region = **-****-*
 *     sso_start_url = https://d-******.awsapps.com/start
 *
 * This information will be automatically added to your shared credentials file by running
 * `aws configure sso`.
 *
 * ## Using custom profiles
 *
 * The SDK supports loading credentials for separate profiles. This can be done
 * in two ways:
 *
 * 1. Set the `AWS_PROFILE` environment variable in your process prior to
 *    loading the SDK.
 * 2. Directly load the AWS.SsoCredentials provider:
 *
 * ```javascript
 * var creds = new AWS.SsoCredentials({profile: 'myprofile'});
 * AWS.config.credentials = creds;
 * ```
 *
 * @!macro nobrowser
 */ $hIq4q.SsoCredentials = $hIq4q.util.inherit($hIq4q.Credentials, {
    /**
   * Creates a new SsoCredentials object.
   *
   * @param options [map] a set of options
   * @option options profile [String] (AWS_PROFILE env var or 'default')
   *   the name of the profile to load.
   * @option options filename [String] ('~/.aws/credentials' or defined by
   *   AWS_SHARED_CREDENTIALS_FILE process env var)
   *   the filename to use when loading credentials.
   * @option options callback [Function] (err) Credentials are eagerly loaded
   *   by the constructor. When the callback is called with no error, the
   *   credentials have been loaded successfully.
   */ constructor: function SsoCredentials(options) {
        $hIq4q.Credentials.call(this);
        options = options || {};
        this.errorCode = 'SsoCredentialsProviderFailure';
        this.expired = true;
        this.filename = options.filename;
        this.profile = options.profile || process.env.AWS_PROFILE || $hIq4q.util.defaultProfile;
        this.service = options.ssoClient;
        this.httpOptions = options.httpOptions || null;
        this.get(options.callback || $hIq4q.util.fn.noop);
    },
    /**
   * @api private
   */ load: function load(callback) {
        var self = this;
        try {
            var profiles = $hIq4q.util.getProfilesFromSharedConfig($7852f3d93e4177a3$var$iniLoader, this.filename);
            var profile = profiles[this.profile] || {};
            if (Object.keys(profile).length === 0) throw $hIq4q.util.error(new Error('Profile ' + this.profile + ' not found'), {
                code: self.errorCode
            });
            if (profile.sso_session) {
                if (!profile.sso_account_id || !profile.sso_role_name) throw $hIq4q.util.error(new Error('Profile ' + this.profile + ' with session ' + profile.sso_session + ' does not have valid SSO credentials. Required parameters "sso_account_id", "sso_session", ' + '"sso_role_name". Reference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html'), {
                    code: self.errorCode
                });
            } else {
                if (!profile.sso_start_url || !profile.sso_account_id || !profile.sso_region || !profile.sso_role_name) throw $hIq4q.util.error(new Error('Profile ' + this.profile + ' does not have valid SSO credentials. Required parameters "sso_account_id", "sso_region", ' + '"sso_role_name", "sso_start_url". Reference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html'), {
                    code: self.errorCode
                });
            }
            this.getToken(this.profile, profile, function(err, token) {
                if (err) return callback(err);
                var request = {
                    accessToken: token,
                    accountId: profile.sso_account_id,
                    roleName: profile.sso_role_name
                };
                if (!self.service || self.service.config.region !== profile.sso_region) self.service = new $hIq4q.SSO({
                    region: profile.sso_region,
                    httpOptions: self.httpOptions
                });
                self.service.getRoleCredentials(request, function(err, data) {
                    if (err || !data || !data.roleCredentials) callback($hIq4q.util.error(err || new Error('Please log in using "aws sso login"'), {
                        code: self.errorCode
                    }), null);
                    else if (!data.roleCredentials.accessKeyId || !data.roleCredentials.secretAccessKey || !data.roleCredentials.sessionToken || !data.roleCredentials.expiration) throw $hIq4q.util.error(new Error('SSO returns an invalid temporary credential.'));
                    else {
                        self.expired = false;
                        self.accessKeyId = data.roleCredentials.accessKeyId;
                        self.secretAccessKey = data.roleCredentials.secretAccessKey;
                        self.sessionToken = data.roleCredentials.sessionToken;
                        self.expireTime = new Date(data.roleCredentials.expiration);
                        callback(null);
                    }
                });
            });
        } catch (err) {
            callback(err);
        }
    },
    /**
   * @private
   * Uses legacy file system retrieval or if sso-session is set,
   * use the SSOTokenProvider.
   *
   * @param {string} profileName - name of the profile.
   * @param {object} profile - profile data containing sso_session or sso_start_url etc.
   * @param {function} callback - called with (err, (string) token).
   *
   * @returns {void}
   */ getToken: function getToken(profileName, profile, callback) {
        var self = this;
        if (profile.sso_session) {
            var _iniLoader = $hIq4q.util.iniLoader;
            var ssoSessions = _iniLoader.loadSsoSessionsFrom();
            var ssoSession = ssoSessions[profile.sso_session];
            Object.assign(profile, ssoSession);
            var ssoTokenProvider = new $hIq4q.SSOTokenProvider({
                profile: profileName
            });
            ssoTokenProvider.get(function(err) {
                if (err) return callback(err);
                return callback(null, ssoTokenProvider.token);
            });
            return;
        }
        try {
            /**
       * The time window (15 mins) that SDK will treat the SSO token expires in before the defined expiration date in token.
       * This is needed because server side may have invalidated the token before the defined expiration date.
       */ var EXPIRE_WINDOW_MS = 900000;
            var hasher = $dDec7$crypto.createHash('sha1');
            var fileName = hasher.update(profile.sso_start_url).digest('hex') + '.json';
            var cachePath = $dDec7$path.join($7852f3d93e4177a3$var$iniLoader.getHomeDir(), '.aws', 'sso', 'cache', fileName);
            var cacheFile = $hIq4q.util.readFileSync(cachePath);
            var cacheContent = null;
            if (cacheFile) cacheContent = JSON.parse(cacheFile);
            if (!cacheContent) throw $hIq4q.util.error(new Error('Cached credentials not found under ' + this.profile + ' profile. Please make sure you log in with aws sso login first'), {
                code: self.errorCode
            });
            if (!cacheContent.startUrl || !cacheContent.region || !cacheContent.accessToken || !cacheContent.expiresAt) throw $hIq4q.util.error(new Error('Cached credentials are missing required properties. Try running aws sso login.'));
            if (new Date(cacheContent.expiresAt).getTime() - Date.now() <= EXPIRE_WINDOW_MS) throw $hIq4q.util.error(new Error('The SSO session associated with this profile has expired. To refresh this SSO session run aws sso login with the corresponding profile.'));
            return callback(null, cacheContent.accessToken);
        } catch (err) {
            return callback(err, null);
        }
    },
    /**
   * Loads the credentials from the AWS SSO process
   *
   * @callback callback function(err)
   *   Called after the AWS SSO process has been executed. When this
   *   callback is called with no error, it means that the credentials
   *   information has been loaded into the object (as the `accessKeyId`,
   *   `secretAccessKey`, and `sessionToken` properties).
   *   @param err [Error] if an error occurred, this value will be filled
   * @see get
   */ refresh: function refresh(callback) {
        $7852f3d93e4177a3$var$iniLoader.clearCachedFiles();
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    }
});


// Setup default providers for credentials chain
// If this changes, please update documentation for
// AWS.CredentialProviderChain.defaultProviders in
// credentials/credential_provider_chain.js
$a47d739e92258da3$var$AWS.CredentialProviderChain.defaultProviders = [
    function() {
        return new $a47d739e92258da3$var$AWS.EnvironmentCredentials('AWS');
    },
    function() {
        return new $a47d739e92258da3$var$AWS.EnvironmentCredentials('AMAZON');
    },
    function() {
        return new $a47d739e92258da3$var$AWS.SsoCredentials();
    },
    function() {
        return new $a47d739e92258da3$var$AWS.SharedIniFileCredentials();
    },
    function() {
        return new $a47d739e92258da3$var$AWS.ECSCredentials();
    },
    function() {
        return new $a47d739e92258da3$var$AWS.ProcessCredentials();
    },
    function() {
        return new $a47d739e92258da3$var$AWS.TokenFileWebIdentityCredentials();
    },
    function() {
        return new $a47d739e92258da3$var$AWS.EC2MetadataCredentials();
    }
];

var $hIq4q = parcelRequire("hIq4q");
/**
 * Represents AWS token object, which contains {token}, and optional
 * {expireTime}.
 * Creating a `Token` object allows you to pass around your
 * token to configuration and service objects.
 *
 * Note that this class typically does not need to be constructed manually,
 * as the {AWS.Config} and {AWS.Service} classes both accept simple
 * options hashes with the two keys. The token from this object will be used
 * automatically in operations which require them.
 *
 * ## Expiring and Refreshing Token
 *
 * Occasionally token can expire in the middle of a long-running
 * application. In this case, the SDK will automatically attempt to
 * refresh the token from the storage location if the Token
 * class implements the {refresh} method.
 *
 * If you are implementing a token storage location, you
 * will want to create a subclass of the `Token` class and
 * override the {refresh} method. This method allows token to be
 * retrieved from the backing store, be it a file system, database, or
 * some network storage. The method should reset the token attributes
 * on the object.
 *
 * @!attribute token
 *   @return [String] represents the literal token string. This will typically
 *     be a base64 encoded string.
 * @!attribute expireTime
 *   @return [Date] a time when token should be considered expired. Used
 *     in conjunction with {expired}.
 * @!attribute expired
 *   @return [Boolean] whether the token is expired and require a refresh. Used
 *     in conjunction with {expireTime}.
 */ $hIq4q.Token = $hIq4q.util.inherit({
    /**
   * Creates a Token object with a given set of information in options hash.
   * @option options token [String] represents the literal token string.
   * @option options expireTime [Date] field representing the time at which
   *   the token expires.
   * @example Create a token object
   *   var token = new AWS.Token({ token: 'token' });
   */ constructor: function Token(options) {
        // hide token from being displayed with util.inspect
        $hIq4q.util.hideProperties(this, [
            'token'
        ]);
        this.expired = false;
        this.expireTime = null;
        this.refreshCallbacks = [];
        if (arguments.length === 1) {
            var options = arguments[0];
            this.token = options.token;
            this.expireTime = options.expireTime;
        }
    },
    /**
   * @return [Integer] the number of seconds before {expireTime} during which
   *   the token will be considered expired.
   */ expiryWindow: 15,
    /**
   * @return [Boolean] whether the Token object should call {refresh}
   * @note Subclasses should override this method to provide custom refresh
   *   logic.
   */ needsRefresh: function needsRefresh() {
        var currentTime = $hIq4q.util.date.getDate().getTime();
        var adjustedTime = new Date(currentTime + this.expiryWindow * 1000);
        if (this.expireTime && adjustedTime > this.expireTime) return true;
        return this.expired || !this.token;
    },
    /**
   * Gets the existing token, refreshing them if they are not yet loaded
   * or have expired. Users should call this method before using {refresh},
   * as this will not attempt to reload token when they are already
   * loaded into the object.
   *
   * @callback callback function(err)
   *   When this callback is called with no error, it means either token
   *   do not need to be refreshed or refreshed token information has
   *   been loaded into the object (as the `token` property).
   *   @param err [Error] if an error occurred, this value will be filled
   */ get: function get(callback) {
        var self = this;
        if (this.needsRefresh()) this.refresh(function(err) {
            if (!err) self.expired = false; // reset expired flag
            if (callback) callback(err);
        });
        else if (callback) callback();
    },
    /**
   * @!method  getPromise()
   *   Returns a 'thenable' promise.
   *   Gets the existing token, refreshing it if it's not yet loaded
   *   or have expired. Users should call this method before using {refresh},
   *   as this will not attempt to reload token when it's already
   *   loaded into the object.
   *
   *   Two callbacks can be provided to the `then` method on the returned promise.
   *   The first callback will be called if the promise is fulfilled, and the second
   *   callback will be called if the promise is rejected.
   *   @callback fulfilledCallback function()
   *     Called if the promise is fulfilled. When this callback is called, it means
   *     either token does not need to be refreshed or refreshed token information
   *     has been loaded into the object (as the `token` property).
   *   @callback rejectedCallback function(err)
   *     Called if the promise is rejected.
   *     @param err [Error] if an error occurred, this value will be filled.
   *   @return [Promise] A promise that represents the state of the `get` call.
   *   @example Calling the `getPromise` method.
   *     var promise = tokenProvider.getPromise();
   *     promise.then(function() { ... }, function(err) { ... });
   */ /**
   * @!method  refreshPromise()
   *   Returns a 'thenable' promise.
   *   Refreshes the token. Users should call {get} before attempting
   *   to forcibly refresh token.
   *
   *   Two callbacks can be provided to the `then` method on the returned promise.
   *   The first callback will be called if the promise is fulfilled, and the second
   *   callback will be called if the promise is rejected.
   *   @callback fulfilledCallback function()
   *     Called if the promise is fulfilled. When this callback is called, it
   *     means refreshed token information has been loaded into the object
   *     (as the `token` property).
   *   @callback rejectedCallback function(err)
   *     Called if the promise is rejected.
   *     @param err [Error] if an error occurred, this value will be filled.
   *   @return [Promise] A promise that represents the state of the `refresh` call.
   *   @example Calling the `refreshPromise` method.
   *     var promise = tokenProvider.refreshPromise();
   *     promise.then(function() { ... }, function(err) { ... });
   */ /**
   * Refreshes the token. Users should call {get} before attempting
   * to forcibly refresh token.
   *
   * @callback callback function(err)
   *   When this callback is called with no error, it means refreshed
   *   token information has been loaded into the object (as the
   *   `token` property).
   *   @param err [Error] if an error occurred, this value will be filled
   * @note Subclasses should override this class to reset the
   *   {token} on the token object and then call the callback with
   *   any error information.
   * @see get
   */ refresh: function refresh(callback) {
        this.expired = false;
        callback();
    },
    /**
   * @api private
   * @param callback
   */ coalesceRefresh: function coalesceRefresh(callback, sync) {
        var self = this;
        if (self.refreshCallbacks.push(callback) === 1) self.load(function onLoad(err) {
            $hIq4q.util.arrayEach(self.refreshCallbacks, function(callback) {
                if (sync) callback(err);
                else // callback could throw, so defer to ensure all callbacks are notified
                $hIq4q.util.defer(function() {
                    callback(err);
                });
            });
            self.refreshCallbacks.length = 0;
        });
    },
    /**
   * @api private
   * @param callback
   */ load: function load(callback) {
        callback();
    }
});
/**
 * @api private
 */ $hIq4q.Token.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
    this.prototype.getPromise = $hIq4q.util.promisifyMethod('get', PromiseDependency);
    this.prototype.refreshPromise = $hIq4q.util.promisifyMethod('refresh', PromiseDependency);
};
/**
 * @api private
 */ $hIq4q.Token.deletePromisesFromClass = function deletePromisesFromClass() {
    delete this.prototype.getPromise;
    delete this.prototype.refreshPromise;
};
$hIq4q.util.addPromises($hIq4q.Token);



var $hIq4q = parcelRequire("hIq4q");
/**
 * Creates a token provider chain that searches for token in a list of
 * token providers specified by the {providers} property.
 *
 * By default, the chain will use the {defaultProviders} to resolve token.
 *
 * ## Setting Providers
 *
 * Each provider in the {providers} list should be a function that returns
 * a {AWS.Token} object, or a hardcoded token object. The function
 * form allows for delayed execution of the Token construction.
 *
 * ## Resolving Token from a Chain
 *
 * Call {resolve} to return the first valid token object that can be
 * loaded by the provider chain.
 *
 * For example, to resolve a chain with a custom provider that checks a file
 * on disk after the set of {defaultProviders}:
 *
 * ```javascript
 * var diskProvider = new FileTokenProvider('./token.json');
 * var chain = new AWS.TokenProviderChain();
 * chain.providers.push(diskProvider);
 * chain.resolve();
 * ```
 *
 * The above code will return the `diskProvider` object if the
 * file contains token and the `defaultProviders` do not contain
 * any token.
 *
 * @!attribute providers
 *   @return [Array<AWS.Token, Function>]
 *     a list of token objects or functions that return token
 *     objects. If the provider is a function, the function will be
 *     executed lazily when the provider needs to be checked for valid
 *     token. By default, this object will be set to the {defaultProviders}.
 *   @see defaultProviders
 */ $hIq4q.TokenProviderChain = $hIq4q.util.inherit($hIq4q.Token, {
    /**
   * Creates a new TokenProviderChain with a default set of providers
   * specified by {defaultProviders}.
   */ constructor: function TokenProviderChain(providers) {
        if (providers) this.providers = providers;
        else this.providers = $hIq4q.TokenProviderChain.defaultProviders.slice(0);
        this.resolveCallbacks = [];
    },
    /**
   * @!method  resolvePromise()
   *   Returns a 'thenable' promise.
   *   Resolves the provider chain by searching for the first token in {providers}.
   *
   *   Two callbacks can be provided to the `then` method on the returned promise.
   *   The first callback will be called if the promise is fulfilled, and the second
   *   callback will be called if the promise is rejected.
   *   @callback fulfilledCallback function(token)
   *     Called if the promise is fulfilled and the provider resolves the chain
   *     to a token object
   *     @param token [AWS.Token] the token object resolved by the provider chain.
   *   @callback rejectedCallback function(error)
   *     Called if the promise is rejected.
   *     @param err [Error] the error object returned if no token is found.
   *   @return [Promise] A promise that represents the state of the `resolve` method call.
   *   @example Calling the `resolvePromise` method.
   *     var promise = chain.resolvePromise();
   *     promise.then(function(token) { ... }, function(err) { ... });
   */ /**
   * Resolves the provider chain by searching for the first token in {providers}.
   *
   * @callback callback function(err, token)
   *   Called when the provider resolves the chain to a token object
   *   or null if no token can be found.
   *
   *   @param err [Error] the error object returned if no token is found.
   *   @param token [AWS.Token] the token object resolved by the provider chain.
   * @return [AWS.TokenProviderChain] the provider, for chaining.
   */ resolve: function resolve(callback) {
        var self = this;
        if (self.providers.length === 0) {
            callback(new Error('No providers'));
            return self;
        }
        if (self.resolveCallbacks.push(callback) === 1) {
            var index = 0;
            var providers = self.providers.slice(0);
            function resolveNext(err, token) {
                if (!err && token || index === providers.length) {
                    $hIq4q.util.arrayEach(self.resolveCallbacks, function(callback) {
                        callback(err, token);
                    });
                    self.resolveCallbacks.length = 0;
                    return;
                }
                var provider = providers[index++];
                if (typeof provider === 'function') token = provider.call();
                else token = provider;
                if (token.get) token.get(function(getErr) {
                    resolveNext(getErr, getErr ? null : token);
                });
                else resolveNext(null, token);
            }
            resolveNext();
        }
        return self;
    }
});
/**
 * The default set of providers used by a vanilla TokenProviderChain.
 *
 * In the browser:
 *
 * ```javascript
 * AWS.TokenProviderChain.defaultProviders = []
 * ```
 *
 * In Node.js:
 *
 * ```javascript
 * AWS.TokenProviderChain.defaultProviders = [
 *   function () { return new AWS.SSOTokenProvider(); },
 * ]
 * ```
 */ $hIq4q.TokenProviderChain.defaultProviders = [];
/**
 * @api private
 */ $hIq4q.TokenProviderChain.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
    this.prototype.resolvePromise = $hIq4q.util.promisifyMethod('resolve', PromiseDependency);
};
/**
 * @api private
 */ $hIq4q.TokenProviderChain.deletePromisesFromClass = function deletePromisesFromClass() {
    delete this.prototype.resolvePromise;
};
$hIq4q.util.addPromises($hIq4q.TokenProviderChain);



var $hIq4q = parcelRequire("hIq4q");



var $36d1daf6795d208c$var$iniLoader = $hIq4q.util.iniLoader;
// Tracking refresh attempt to ensure refresh is not attempted more than once every 30 seconds.
var $36d1daf6795d208c$var$lastRefreshAttemptTime = 0;
/**
 * Throws error is key is not present in token object.
 *
 * @param token [Object] Object to be validated.
 * @param key [String] The key to be validated on the object.
 */ var $36d1daf6795d208c$var$validateTokenKey = function validateTokenKey(token, key) {
    if (!token[key]) throw $hIq4q.util.error(new Error('Key "' + key + '" not present in SSO Token'), {
        code: 'SSOTokenProviderFailure'
    });
};
/**
 * Calls callback function with or without error based on provided times in case
 * of unsuccessful refresh.
 *
 * @param currentTime [number] current time in milliseconds since ECMAScript epoch.
 * @param tokenExpireTime [number] token expire time in milliseconds since ECMAScript epoch.
 * @param callback [Function] Callback to call in case of error.
 */ var $36d1daf6795d208c$var$refreshUnsuccessful = function refreshUnsuccessful(currentTime, tokenExpireTime, callback) {
    if (tokenExpireTime > currentTime) // Cached token is still valid, return.
    callback(null);
    else // Token invalid, throw error requesting user to sso login.
    throw $hIq4q.util.error(new Error('SSO Token refresh failed. Please log in using "aws sso login"'), {
        code: 'SSOTokenProviderFailure'
    });
};
/**
 * Represents token loaded from disk derived from the AWS SSO device grant authorication flow.
 *
 * ## Using SSO Token Provider
 *
 * This provider is checked by default in the Node.js environment in TokenProviderChain.
 * To use the SSO Token Provider, simply add your SSO Start URL and Region to the
 * ~/.aws/config file in the following format:
 *
 *     [default]
 *     sso_start_url = https://d-abc123.awsapps.com/start
 *     sso_region = us-east-1
 *
 * ## Using custom profiles
 *
 * The SDK supports loading token for separate profiles. This can be done in two ways:
 *
 * 1. Set the `AWS_PROFILE` environment variable in your process prior to loading the SDK.
 * 2. Directly load the AWS.SSOTokenProvider:
 *
 * ```javascript
 * var ssoTokenProvider = new AWS.SSOTokenProvider({profile: 'myprofile'});
 * ```
 *
 * @!macro nobrowser
 */ $hIq4q.SSOTokenProvider = $hIq4q.util.inherit($hIq4q.Token, {
    /**
   * Expiry window of five minutes.
   */ expiryWindow: 300,
    /**
   * Creates a new token object from cached access token.
   *
   * @param options [map] a set of options
   * @option options profile [String] (AWS_PROFILE env var or 'default')
   *   the name of the profile to load.
   * @option options callback [Function] (err) Token is eagerly loaded
   *   by the constructor. When the callback is called with no error, the
   *   token has been loaded successfully.
   */ constructor: function SSOTokenProvider(options) {
        $hIq4q.Token.call(this);
        options = options || {};
        this.expired = true;
        this.profile = options.profile || process.env.AWS_PROFILE || $hIq4q.util.defaultProfile;
        this.get(options.callback || $hIq4q.util.fn.noop);
    },
    /**
   * Reads sso_start_url from provided profile, and reads token from
   * ~/.aws/sso/cache/<sha1-of-utf8-encoded-value-from-sso_start_url>.json
   *
   * Throws an error if required fields token and expiresAt are missing.
   * Throws an error if token has expired and metadata to perform refresh is
   * not available.
   * Attempts to refresh the token if it's within 5 minutes before expiry time.
   *
   * @api private
   */ load: function load(callback) {
        var self = this;
        var profiles = $36d1daf6795d208c$var$iniLoader.loadFrom({
            isConfig: true
        });
        var profile = profiles[this.profile] || {};
        if (Object.keys(profile).length === 0) throw $hIq4q.util.error(new Error('Profile "' + this.profile + '" not found'), {
            code: 'SSOTokenProviderFailure'
        });
        else if (!profile['sso_session']) throw $hIq4q.util.error(new Error('Profile "' + this.profile + '" is missing required property "sso_session".'), {
            code: 'SSOTokenProviderFailure'
        });
        var ssoSessionName = profile['sso_session'];
        var ssoSessions = $36d1daf6795d208c$var$iniLoader.loadSsoSessionsFrom();
        var ssoSession = ssoSessions[ssoSessionName];
        if (!ssoSession) throw $hIq4q.util.error(new Error('Sso session "' + ssoSessionName + '" not found'), {
            code: 'SSOTokenProviderFailure'
        });
        else if (!ssoSession['sso_start_url']) throw $hIq4q.util.error(new Error('Sso session "' + this.profile + '" is missing required property "sso_start_url".'), {
            code: 'SSOTokenProviderFailure'
        });
        else if (!ssoSession['sso_region']) throw $hIq4q.util.error(new Error('Sso session "' + this.profile + '" is missing required property "sso_region".'), {
            code: 'SSOTokenProviderFailure'
        });
        var hasher = $dDec7$crypto.createHash('sha1');
        var fileName = hasher.update(ssoSessionName).digest('hex') + '.json';
        var cachePath = $dDec7$path.join($36d1daf6795d208c$var$iniLoader.getHomeDir(), '.aws', 'sso', 'cache', fileName);
        var tokenFromCache = JSON.parse($dDec7$fs.readFileSync(cachePath));
        if (!tokenFromCache) throw $hIq4q.util.error(new Error('Cached token not found. Please log in using "aws sso login" for profile "' + this.profile + '".'), {
            code: 'SSOTokenProviderFailure'
        });
        $36d1daf6795d208c$var$validateTokenKey(tokenFromCache, 'accessToken');
        $36d1daf6795d208c$var$validateTokenKey(tokenFromCache, 'expiresAt');
        var currentTime = $hIq4q.util.date.getDate().getTime();
        var adjustedTime = new Date(currentTime + this.expiryWindow * 1000);
        var tokenExpireTime = new Date(tokenFromCache['expiresAt']);
        if (tokenExpireTime > adjustedTime) {
            // Token is valid and not expired.
            self.token = tokenFromCache.accessToken;
            self.expireTime = tokenExpireTime;
            self.expired = false;
            callback(null);
            return;
        }
        // Skip new refresh, if last refresh was done within 30 seconds.
        if (currentTime - $36d1daf6795d208c$var$lastRefreshAttemptTime < 30000) {
            $36d1daf6795d208c$var$refreshUnsuccessful(currentTime, tokenExpireTime, callback);
            return;
        }
        // Token is in expiry window, refresh from SSOOIDC.createToken() call.
        $36d1daf6795d208c$var$validateTokenKey(tokenFromCache, 'clientId');
        $36d1daf6795d208c$var$validateTokenKey(tokenFromCache, 'clientSecret');
        $36d1daf6795d208c$var$validateTokenKey(tokenFromCache, 'refreshToken');
        if (!self.service || self.service.config.region !== ssoSession.sso_region) self.service = new $hIq4q.SSOOIDC({
            region: ssoSession.sso_region
        });
        var params = {
            clientId: tokenFromCache.clientId,
            clientSecret: tokenFromCache.clientSecret,
            refreshToken: tokenFromCache.refreshToken,
            grantType: 'refresh_token'
        };
        $36d1daf6795d208c$var$lastRefreshAttemptTime = $hIq4q.util.date.getDate().getTime();
        self.service.createToken(params, function(err, data) {
            if (err || !data) $36d1daf6795d208c$var$refreshUnsuccessful(currentTime, tokenExpireTime, callback);
            else try {
                $36d1daf6795d208c$var$validateTokenKey(data, 'accessToken');
                $36d1daf6795d208c$var$validateTokenKey(data, 'expiresIn');
                self.expired = false;
                self.token = data.accessToken;
                self.expireTime = new Date(Date.now() + data.expiresIn * 1000);
                callback(null);
                try {
                    // Write updated token data to disk.
                    tokenFromCache.accessToken = data.accessToken;
                    tokenFromCache.expiresAt = self.expireTime.toISOString();
                    tokenFromCache.refreshToken = data.refreshToken;
                    $dDec7$fs.writeFileSync(cachePath, JSON.stringify(tokenFromCache, null, 2));
                } catch (error) {
                // Swallow error if unable to write token to file.
                }
            } catch (error) {
                $36d1daf6795d208c$var$refreshUnsuccessful(currentTime, tokenExpireTime, callback);
            }
        });
    },
    /**
   * Loads the cached access token from disk.
   *
   * @callback callback function(err)
   *   Called after the AWS SSO process has been executed. When this
   *   callback is called with no error, it means that the token information
   *   has been loaded into the object (as the `token` property).
   *   @param err [Error] if an error occurred, this value will be filled.
   * @see get
   */ refresh: function refresh(callback) {
        $36d1daf6795d208c$var$iniLoader.clearCachedFiles();
        this.coalesceRefresh(callback || $hIq4q.util.fn.callback);
    }
});


// Setup default providers for token chain
// If this changes, please update documentation for
// AWS.TokenProviderChain.defaultProviders in
// token/token_provider_chain.js
$a47d739e92258da3$var$AWS.TokenProviderChain.defaultProviders = [
    function() {
        return new $a47d739e92258da3$var$AWS.SSOTokenProvider();
    }
];
var $a47d739e92258da3$var$getRegion = function() {
    var env = process.env;
    var region = env.AWS_REGION || env.AMAZON_REGION;
    if (env[$a47d739e92258da3$var$AWS.util.configOptInEnv]) {
        var toCheck = [
            {
                filename: env[$a47d739e92258da3$var$AWS.util.sharedCredentialsFileEnv]
            },
            {
                isConfig: true,
                filename: env[$a47d739e92258da3$var$AWS.util.sharedConfigFileEnv]
            }
        ];
        var iniLoader = $a47d739e92258da3$var$AWS.util.iniLoader;
        while(!region && toCheck.length){
            var configFile = {};
            var fileInfo = toCheck.shift();
            try {
                configFile = iniLoader.loadFrom(fileInfo);
            } catch (err) {
                if (fileInfo.isConfig) throw err;
            }
            var profile = configFile[env.AWS_PROFILE || $a47d739e92258da3$var$AWS.util.defaultProfile];
            region = profile && profile.region;
        }
    }
    return region;
};
var $a47d739e92258da3$var$getBooleanValue = function(value) {
    return value === 'true' ? true : value === 'false' ? false : undefined;
};
var $a47d739e92258da3$var$USE_FIPS_ENDPOINT_CONFIG_OPTIONS = {
    environmentVariableSelector: function(env) {
        return $a47d739e92258da3$var$getBooleanValue(env['AWS_USE_FIPS_ENDPOINT']);
    },
    configFileSelector: function(profile) {
        return $a47d739e92258da3$var$getBooleanValue(profile['use_fips_endpoint']);
    },
    default: false
};
var $a47d739e92258da3$var$USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = {
    environmentVariableSelector: function(env) {
        return $a47d739e92258da3$var$getBooleanValue(env['AWS_USE_DUALSTACK_ENDPOINT']);
    },
    configFileSelector: function(profile) {
        return $a47d739e92258da3$var$getBooleanValue(profile['use_dualstack_endpoint']);
    },
    default: false
};
// Update configuration keys
$a47d739e92258da3$var$AWS.util.update($a47d739e92258da3$var$AWS.Config.prototype.keys, {
    credentials: function() {
        var credentials = null;
        new $a47d739e92258da3$var$AWS.CredentialProviderChain([
            function() {
                return new $a47d739e92258da3$var$AWS.EnvironmentCredentials('AWS');
            },
            function() {
                return new $a47d739e92258da3$var$AWS.EnvironmentCredentials('AMAZON');
            },
            function() {
                return new $a47d739e92258da3$var$AWS.SharedIniFileCredentials({
                    disableAssumeRole: true
                });
            }
        ]).resolve(function(err, creds) {
            if (!err) credentials = creds;
        });
        return credentials;
    },
    credentialProvider: function() {
        return new $a47d739e92258da3$var$AWS.CredentialProviderChain();
    },
    logger: function() {
        return process.env.AWSJS_DEBUG ? console : null;
    },
    region: function() {
        var region = $a47d739e92258da3$var$getRegion();
        return region ? $a47d739e92258da3$var$getRealRegion(region) : undefined;
    },
    tokenProvider: function() {
        return new $a47d739e92258da3$var$AWS.TokenProviderChain();
    },
    useFipsEndpoint: function() {
        var region = $a47d739e92258da3$var$getRegion();
        return $a47d739e92258da3$var$isFipsRegion(region) ? true : $i3HcT.loadConfig($a47d739e92258da3$var$USE_FIPS_ENDPOINT_CONFIG_OPTIONS);
    },
    useDualstackEndpoint: function() {
        return $i3HcT.loadConfig($a47d739e92258da3$var$USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS);
    }
});
// Reset configuration
$a47d739e92258da3$var$AWS.config = new $a47d739e92258da3$var$AWS.Config();



var $hIq4q = parcelRequire("hIq4q");
var $dffa98b1230ab04c$var$Service = $hIq4q.Service;
var $dffa98b1230ab04c$var$apiLoader = $hIq4q.apiLoader;
$dffa98b1230ab04c$var$apiLoader.services['sts'] = {};
$hIq4q.STS = $dffa98b1230ab04c$var$Service.defineService('sts', [
    '2011-06-15'
]);

var $hIq4q = parcelRequire("hIq4q");
var $c1129a515ff9b4af$exports = {};

var $hIq4q = parcelRequire("hIq4q");
/**
 * @api private
 */ function $c1129a515ff9b4af$var$validateRegionalEndpointsFlagValue(configValue, errorOptions) {
    if (typeof configValue !== 'string') return undefined;
    else if ([
        'legacy',
        'regional'
    ].indexOf(configValue.toLowerCase()) >= 0) return configValue.toLowerCase();
    else throw $hIq4q.util.error(new Error(), errorOptions);
}
/**
 * Resolve the configuration value for regional endpoint from difference sources: client
 * config, environmental variable, shared config file. Value can be case-insensitive
 * 'legacy' or 'reginal'.
 * @param originalConfig user-supplied config object to resolve
 * @param options a map of config property names from individual configuration source
 *  - env: name of environmental variable that refers to the config
 *  - sharedConfig: name of shared configuration file property that refers to the config
 *  - clientConfig: name of client configuration property that refers to the config
 *
 * @api private
 */ function $c1129a515ff9b4af$var$resolveRegionalEndpointsFlag(originalConfig, options) {
    originalConfig = originalConfig || {};
    //validate config value
    var resolved;
    if (originalConfig[options.clientConfig]) {
        resolved = $c1129a515ff9b4af$var$validateRegionalEndpointsFlagValue(originalConfig[options.clientConfig], {
            code: 'InvalidConfiguration',
            message: 'invalid "' + options.clientConfig + '" configuration. Expect "legacy" ' + ' or "regional". Got "' + originalConfig[options.clientConfig] + '".'
        });
        if (resolved) return resolved;
    }
    if (!$hIq4q.util.isNode()) return resolved;
    //validate environmental variable
    if (Object.prototype.hasOwnProperty.call(process.env, options.env)) {
        var envFlag = process.env[options.env];
        resolved = $c1129a515ff9b4af$var$validateRegionalEndpointsFlagValue(envFlag, {
            code: 'InvalidEnvironmentalVariable',
            message: 'invalid ' + options.env + ' environmental variable. Expect "legacy" ' + ' or "regional". Got "' + process.env[options.env] + '".'
        });
        if (resolved) return resolved;
    }
    //validate shared config file
    var profile = {};
    try {
        var profiles = $hIq4q.util.getProfilesFromSharedConfig($hIq4q.util.iniLoader);
        profile = profiles[process.env.AWS_PROFILE || $hIq4q.util.defaultProfile];
    } catch (e) {}
    if (profile && Object.prototype.hasOwnProperty.call(profile, options.sharedConfig)) {
        var fileFlag = profile[options.sharedConfig];
        resolved = $c1129a515ff9b4af$var$validateRegionalEndpointsFlagValue(fileFlag, {
            code: 'InvalidConfiguration',
            message: 'invalid ' + options.sharedConfig + ' profile config. Expect "legacy" ' + ' or "regional". Got "' + profile[options.sharedConfig] + '".'
        });
        if (resolved) return resolved;
    }
    return resolved;
}
$c1129a515ff9b4af$exports = $c1129a515ff9b4af$var$resolveRegionalEndpointsFlag;


var $92dc9fec42c2fe88$var$ENV_REGIONAL_ENDPOINT_ENABLED = 'AWS_STS_REGIONAL_ENDPOINTS';
var $92dc9fec42c2fe88$var$CONFIG_REGIONAL_ENDPOINT_ENABLED = 'sts_regional_endpoints';
$hIq4q.util.update($hIq4q.STS.prototype, {
    /**
   * @overload credentialsFrom(data, credentials = null)
   *   Creates a credentials object from STS response data containing
   *   credentials information. Useful for quickly setting AWS credentials.
   *
   *   @note This is a low-level utility function. If you want to load temporary
   *     credentials into your process for subsequent requests to AWS resources,
   *     you should use {AWS.TemporaryCredentials} instead.
   *   @param data [map] data retrieved from a call to {getFederatedToken},
   *     {getSessionToken}, {assumeRole}, or {assumeRoleWithWebIdentity}.
   *   @param credentials [AWS.Credentials] an optional credentials object to
   *     fill instead of creating a new object. Useful when modifying an
   *     existing credentials object from a refresh call.
   *   @return [AWS.TemporaryCredentials] the set of temporary credentials
   *     loaded from a raw STS operation response.
   *   @example Using credentialsFrom to load global AWS credentials
   *     var sts = new AWS.STS();
   *     sts.getSessionToken(function (err, data) {
   *       if (err) console.log("Error getting credentials");
   *       else {
   *         AWS.config.credentials = sts.credentialsFrom(data);
   *       }
   *     });
   *   @see AWS.TemporaryCredentials
   */ credentialsFrom: function credentialsFrom(data, credentials) {
        if (!data) return null;
        if (!credentials) credentials = new $hIq4q.TemporaryCredentials();
        credentials.expired = false;
        credentials.accessKeyId = data.Credentials.AccessKeyId;
        credentials.secretAccessKey = data.Credentials.SecretAccessKey;
        credentials.sessionToken = data.Credentials.SessionToken;
        credentials.expireTime = data.Credentials.Expiration;
        return credentials;
    },
    assumeRoleWithWebIdentity: function assumeRoleWithWebIdentity(params, callback) {
        return this.makeUnauthenticatedRequest('assumeRoleWithWebIdentity', params, callback);
    },
    assumeRoleWithSAML: function assumeRoleWithSAML(params, callback) {
        return this.makeUnauthenticatedRequest('assumeRoleWithSAML', params, callback);
    },
    /**
   * @api private
   */ setupRequestListeners: function setupRequestListeners(request) {
        request.addListener('validate', this.optInRegionalEndpoint, true);
    },
    /**
   * @api private
   */ optInRegionalEndpoint: function optInRegionalEndpoint(req) {
        var service = req.service;
        var config = service.config;
        config.stsRegionalEndpoints = $c1129a515ff9b4af$exports(service._originalConfig, {
            env: $92dc9fec42c2fe88$var$ENV_REGIONAL_ENDPOINT_ENABLED,
            sharedConfig: $92dc9fec42c2fe88$var$CONFIG_REGIONAL_ENDPOINT_ENABLED,
            clientConfig: 'stsRegionalEndpoints'
        });
        if (config.stsRegionalEndpoints === 'regional' && service.isGlobalEndpoint) {
            //client will throw if region is not supplied; request will be signed with specified region
            if (!config.region) throw $hIq4q.util.error(new Error(), {
                code: 'ConfigError',
                message: 'Missing region in config'
            });
            var insertPoint = config.endpoint.indexOf('.amazonaws.com');
            var regionalEndpoint = config.endpoint.substring(0, insertPoint) + '.' + config.region + config.endpoint.substring(insertPoint);
            req.httpRequest.updateEndpoint(regionalEndpoint);
            req.httpRequest.region = config.region;
        }
    }
});




Object.defineProperty($dffa98b1230ab04c$var$apiLoader.services['sts'], '2011-06-15', {
    get: function get() {
        var model = (parcelRequire("jaRd3"));
        model.paginators = (parcelRequire("7DWNz")).pagination;
        return model;
    },
    enumerable: true,
    configurable: true
});
$dffa98b1230ab04c$exports = $hIq4q.STS;


const $a522b9fcea980f7e$var$client = new (0, (/*@__PURE__*/$parcel$interopDefault($dffa98b1230ab04c$exports)))();
const $a522b9fcea980f7e$export$c3c52e219617878 = async ()=>$a522b9fcea980f7e$var$client.getCallerIdentity().promise();


