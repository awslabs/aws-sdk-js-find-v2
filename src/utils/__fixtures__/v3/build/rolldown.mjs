//#region rolldown:runtime
var __defProp = Object.defineProperty;
var __esmMin = (fn, res) => () => (fn && (res = fn(fn = 0)), res);
var __exportAll = (all, symbols) => {
	let target = {};
	for (var name in all) {
		__defProp(target, name, {
			get: all[name],
			enumerable: true
		});
	}
	if (symbols) {
		__defProp(target, Symbol.toStringTag, { value: "Module" });
	}
	return target;
};

//#endregion
//#region node_modules/@smithy/protocol-http/dist-es/extensions/httpExtensionConfiguration.js
const getHttpHandlerExtensionConfiguration = (runtimeConfig) => {
	return {
		setHttpHandler(handler$1) {
			runtimeConfig.httpHandler = handler$1;
		},
		httpHandler() {
			return runtimeConfig.httpHandler;
		},
		updateHttpClientConfig(key, value) {
			runtimeConfig.httpHandler?.updateHttpClientConfig(key, value);
		},
		httpHandlerConfigs() {
			return runtimeConfig.httpHandler.httpHandlerConfigs();
		}
	};
};
const resolveHttpHandlerRuntimeConfig = (httpHandlerExtensionConfiguration) => {
	return { httpHandler: httpHandlerExtensionConfiguration.httpHandler() };
};

//#endregion
//#region node_modules/@smithy/types/dist-es/endpoint.js
var EndpointURLScheme;
(function(EndpointURLScheme$1) {
	EndpointURLScheme$1["HTTP"] = "http";
	EndpointURLScheme$1["HTTPS"] = "https";
})(EndpointURLScheme || (EndpointURLScheme = {}));

//#endregion
//#region node_modules/@smithy/types/dist-es/extensions/checksum.js
var AlgorithmId;
(function(AlgorithmId$1) {
	AlgorithmId$1["MD5"] = "md5";
	AlgorithmId$1["CRC32"] = "crc32";
	AlgorithmId$1["CRC32C"] = "crc32c";
	AlgorithmId$1["SHA1"] = "sha1";
	AlgorithmId$1["SHA256"] = "sha256";
})(AlgorithmId || (AlgorithmId = {}));

//#endregion
//#region node_modules/@smithy/types/dist-es/middleware.js
const SMITHY_CONTEXT_KEY = "__smithy_context";

//#endregion
//#region node_modules/@smithy/protocol-http/dist-es/httpRequest.js
var HttpRequest = class HttpRequest {
	method;
	protocol;
	hostname;
	port;
	path;
	query;
	headers;
	username;
	password;
	fragment;
	body;
	constructor(options) {
		this.method = options.method || "GET";
		this.hostname = options.hostname || "localhost";
		this.port = options.port;
		this.query = options.query || {};
		this.headers = options.headers || {};
		this.body = options.body;
		this.protocol = options.protocol ? options.protocol.slice(-1) !== ":" ? `${options.protocol}:` : options.protocol : "https:";
		this.path = options.path ? options.path.charAt(0) !== "/" ? `/${options.path}` : options.path : "/";
		this.username = options.username;
		this.password = options.password;
		this.fragment = options.fragment;
	}
	static clone(request) {
		const cloned = new HttpRequest({
			...request,
			headers: { ...request.headers }
		});
		if (cloned.query) cloned.query = cloneQuery(cloned.query);
		return cloned;
	}
	static isInstance(request) {
		if (!request) return false;
		const req = request;
		return "method" in req && "protocol" in req && "hostname" in req && "path" in req && typeof req["query"] === "object" && typeof req["headers"] === "object";
	}
	clone() {
		return HttpRequest.clone(this);
	}
};
function cloneQuery(query) {
	return Object.keys(query).reduce((carry, paramName) => {
		const param = query[paramName];
		return {
			...carry,
			[paramName]: Array.isArray(param) ? [...param] : param
		};
	}, {});
}

//#endregion
//#region node_modules/@smithy/protocol-http/dist-es/httpResponse.js
var HttpResponse = class {
	statusCode;
	reason;
	headers;
	body;
	constructor(options) {
		this.statusCode = options.statusCode;
		this.reason = options.reason;
		this.headers = options.headers || {};
		this.body = options.body;
	}
	static isInstance(response) {
		if (!response) return false;
		const resp = response;
		return typeof resp.statusCode === "number" && typeof resp.headers === "object";
	}
};

//#endregion
//#region node_modules/@aws-sdk/middleware-host-header/dist-es/index.js
function resolveHostHeaderConfig(input) {
	return input;
}
const hostHeaderMiddleware = (options) => (next) => async (args) => {
	if (!HttpRequest.isInstance(args.request)) return next(args);
	const { request } = args;
	const { handlerProtocol = "" } = options.requestHandler.metadata || {};
	if (handlerProtocol.indexOf("h2") >= 0 && !request.headers[":authority"]) {
		delete request.headers["host"];
		request.headers[":authority"] = request.hostname + (request.port ? ":" + request.port : "");
	} else if (!request.headers["host"]) {
		let host = request.hostname;
		if (request.port != null) host += `:${request.port}`;
		request.headers["host"] = host;
	}
	return next(args);
};
const hostHeaderMiddlewareOptions = {
	name: "hostHeaderMiddleware",
	step: "build",
	priority: "low",
	tags: ["HOST"],
	override: true
};
const getHostHeaderPlugin = (options) => ({ applyToStack: (clientStack) => {
	clientStack.add(hostHeaderMiddleware(options), hostHeaderMiddlewareOptions);
} });

//#endregion
//#region node_modules/@aws-sdk/middleware-logger/dist-es/loggerMiddleware.js
const loggerMiddleware = () => (next, context) => async (args) => {
	try {
		const response = await next(args);
		const { clientName, commandName, logger, dynamoDbDocumentClientOptions = {} } = context;
		const { overrideInputFilterSensitiveLog, overrideOutputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
		const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
		const outputFilterSensitiveLog = overrideOutputFilterSensitiveLog ?? context.outputFilterSensitiveLog;
		const { $metadata, ...outputWithoutMetadata } = response.output;
		logger?.info?.({
			clientName,
			commandName,
			input: inputFilterSensitiveLog(args.input),
			output: outputFilterSensitiveLog(outputWithoutMetadata),
			metadata: $metadata
		});
		return response;
	} catch (error) {
		const { clientName, commandName, logger, dynamoDbDocumentClientOptions = {} } = context;
		const { overrideInputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
		const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
		logger?.error?.({
			clientName,
			commandName,
			input: inputFilterSensitiveLog(args.input),
			error,
			metadata: error.$metadata
		});
		throw error;
	}
};
const loggerMiddlewareOptions = {
	name: "loggerMiddleware",
	tags: ["LOGGER"],
	step: "initialize",
	override: true
};
const getLoggerPlugin = (options) => ({ applyToStack: (clientStack) => {
	clientStack.add(loggerMiddleware(), loggerMiddlewareOptions);
} });

//#endregion
//#region node_modules/@aws-sdk/middleware-recursion-detection/dist-es/configuration.js
const recursionDetectionMiddlewareOptions = {
	step: "build",
	tags: ["RECURSION_DETECTION"],
	name: "recursionDetectionMiddleware",
	override: true,
	priority: "low"
};

//#endregion
//#region node_modules/@aws-sdk/middleware-recursion-detection/dist-es/recursionDetectionMiddleware.browser.js
const recursionDetectionMiddleware = () => (next) => async (args) => next(args);

//#endregion
//#region node_modules/@aws-sdk/middleware-recursion-detection/dist-es/getRecursionDetectionPlugin.js
const getRecursionDetectionPlugin = (options) => ({ applyToStack: (clientStack) => {
	clientStack.add(recursionDetectionMiddleware(), recursionDetectionMiddlewareOptions);
} });

//#endregion
//#region node_modules/@smithy/util-middleware/dist-es/getSmithyContext.js
const getSmithyContext = (context) => context[SMITHY_CONTEXT_KEY] || (context[SMITHY_CONTEXT_KEY] = {});

//#endregion
//#region node_modules/@smithy/util-middleware/dist-es/normalizeProvider.js
const normalizeProvider$1 = (input) => {
	if (typeof input === "function") return input;
	const promisified = Promise.resolve(input);
	return () => promisified;
};

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/resolveAuthOptions.js
const resolveAuthOptions = (candidateAuthOptions, authSchemePreference) => {
	if (!authSchemePreference || authSchemePreference.length === 0) return candidateAuthOptions;
	const preferredAuthOptions = [];
	for (const preferredSchemeName of authSchemePreference) for (const candidateAuthOption of candidateAuthOptions) if (candidateAuthOption.schemeId.split("#")[1] === preferredSchemeName) preferredAuthOptions.push(candidateAuthOption);
	for (const candidateAuthOption of candidateAuthOptions) if (!preferredAuthOptions.find(({ schemeId }) => schemeId === candidateAuthOption.schemeId)) preferredAuthOptions.push(candidateAuthOption);
	return preferredAuthOptions;
};

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js
function convertHttpAuthSchemesToMap(httpAuthSchemes) {
	const map = /* @__PURE__ */ new Map();
	for (const scheme of httpAuthSchemes) map.set(scheme.schemeId, scheme);
	return map;
}
const httpAuthSchemeMiddleware = (config, mwOptions) => (next, context) => async (args) => {
	const resolvedOptions = resolveAuthOptions(config.httpAuthSchemeProvider(await mwOptions.httpAuthSchemeParametersProvider(config, context, args.input)), config.authSchemePreference ? await config.authSchemePreference() : []);
	const authSchemes = convertHttpAuthSchemesToMap(config.httpAuthSchemes);
	const smithyContext = getSmithyContext(context);
	const failureReasons = [];
	for (const option of resolvedOptions) {
		const scheme = authSchemes.get(option.schemeId);
		if (!scheme) {
			failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` was not enabled for this service.`);
			continue;
		}
		const identityProvider = scheme.identityProvider(await mwOptions.identityProviderConfigProvider(config));
		if (!identityProvider) {
			failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` did not have an IdentityProvider configured.`);
			continue;
		}
		const { identityProperties = {}, signingProperties = {} } = option.propertiesExtractor?.(config, context) || {};
		option.identityProperties = Object.assign(option.identityProperties || {}, identityProperties);
		option.signingProperties = Object.assign(option.signingProperties || {}, signingProperties);
		smithyContext.selectedHttpAuthScheme = {
			httpAuthOption: option,
			identity: await identityProvider(option.identityProperties),
			signer: scheme.signer
		};
		break;
	}
	if (!smithyContext.selectedHttpAuthScheme) throw new Error(failureReasons.join("\n"));
	return next(args);
};

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.js
const httpAuthSchemeEndpointRuleSetMiddlewareOptions = {
	step: "serialize",
	tags: ["HTTP_AUTH_SCHEME"],
	name: "httpAuthSchemeMiddleware",
	override: true,
	relation: "before",
	toMiddleware: "endpointV2Middleware"
};
const getHttpAuthSchemeEndpointRuleSetPlugin = (config, { httpAuthSchemeParametersProvider, identityProviderConfigProvider }) => ({ applyToStack: (clientStack) => {
	clientStack.addRelativeTo(httpAuthSchemeMiddleware(config, {
		httpAuthSchemeParametersProvider,
		identityProviderConfigProvider
	}), httpAuthSchemeEndpointRuleSetMiddlewareOptions);
} });

//#endregion
//#region node_modules/@smithy/middleware-serde/dist-es/serdePlugin.js
const serializerMiddlewareOption$1 = {
	name: "serializerMiddleware",
	step: "serialize",
	tags: ["SERIALIZER"],
	override: true
};

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-signing/httpSigningMiddleware.js
const defaultErrorHandler = (signingProperties) => (error) => {
	throw error;
};
const defaultSuccessHandler = (httpResponse, signingProperties) => {};
const httpSigningMiddleware = (config) => (next, context) => async (args) => {
	if (!HttpRequest.isInstance(args.request)) return next(args);
	const scheme = getSmithyContext(context).selectedHttpAuthScheme;
	if (!scheme) throw new Error(`No HttpAuthScheme was selected: unable to sign request`);
	const { httpAuthOption: { signingProperties = {} }, identity, signer } = scheme;
	const output = await next({
		...args,
		request: await signer.sign(args.request, identity, signingProperties)
	}).catch((signer.errorHandler || defaultErrorHandler)(signingProperties));
	(signer.successHandler || defaultSuccessHandler)(output.response, signingProperties);
	return output;
};

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-signing/getHttpSigningMiddleware.js
const httpSigningMiddlewareOptions = {
	step: "finalizeRequest",
	tags: ["HTTP_SIGNING"],
	name: "httpSigningMiddleware",
	aliases: [
		"apiKeyMiddleware",
		"tokenMiddleware",
		"awsAuthMiddleware"
	],
	override: true,
	relation: "after",
	toMiddleware: "retryMiddleware"
};
const getHttpSigningPlugin = (config) => ({ applyToStack: (clientStack) => {
	clientStack.addRelativeTo(httpSigningMiddleware(config), httpSigningMiddlewareOptions);
} });

//#endregion
//#region node_modules/@smithy/core/dist-es/normalizeProvider.js
const normalizeProvider = (input) => {
	if (typeof input === "function") return input;
	const promisified = Promise.resolve(input);
	return () => promisified;
};

//#endregion
//#region node_modules/@smithy/util-base64/dist-es/constants.browser.js
const chars = `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`;
const alphabetByEncoding = Object.entries(chars).reduce((acc, [i$1, c$1]) => {
	acc[c$1] = Number(i$1);
	return acc;
}, {});
const alphabetByValue = chars.split("");
const bitsPerLetter = 6;
const bitsPerByte = 8;
const maxLetterValue = 63;

//#endregion
//#region node_modules/@smithy/util-base64/dist-es/fromBase64.browser.js
const fromBase64 = (input) => {
	let totalByteLength = input.length / 4 * 3;
	if (input.slice(-2) === "==") totalByteLength -= 2;
	else if (input.slice(-1) === "=") totalByteLength--;
	const out = new ArrayBuffer(totalByteLength);
	const dataView = new DataView(out);
	for (let i$1 = 0; i$1 < input.length; i$1 += 4) {
		let bits = 0;
		let bitLength = 0;
		for (let j$1 = i$1, limit = i$1 + 3; j$1 <= limit; j$1++) if (input[j$1] !== "=") {
			if (!(input[j$1] in alphabetByEncoding)) throw new TypeError(`Invalid character ${input[j$1]} in base64 string.`);
			bits |= alphabetByEncoding[input[j$1]] << (limit - j$1) * bitsPerLetter;
			bitLength += bitsPerLetter;
		} else bits >>= bitsPerLetter;
		const chunkOffset = i$1 / 4 * 3;
		bits >>= bitLength % bitsPerByte;
		const byteLength = Math.floor(bitLength / bitsPerByte);
		for (let k$1 = 0; k$1 < byteLength; k$1++) {
			const offset = (byteLength - k$1 - 1) * bitsPerByte;
			dataView.setUint8(chunkOffset + k$1, (bits & 255 << offset) >> offset);
		}
	}
	return new Uint8Array(out);
};

//#endregion
//#region node_modules/@smithy/util-utf8/dist-es/fromUtf8.browser.js
var fromUtf8$2;
var init_fromUtf8_browser = __esmMin((() => {
	fromUtf8$2 = (input) => new TextEncoder().encode(input);
}));

//#endregion
//#region node_modules/@smithy/util-utf8/dist-es/toUint8Array.js
var toUint8Array;
var init_toUint8Array = __esmMin((() => {
	init_fromUtf8_browser();
	toUint8Array = (data) => {
		if (typeof data === "string") return fromUtf8$2(data);
		if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
		return new Uint8Array(data);
	};
}));

//#endregion
//#region node_modules/@smithy/util-utf8/dist-es/toUtf8.browser.js
var toUtf8;
var init_toUtf8_browser = __esmMin((() => {
	toUtf8 = (input) => {
		if (typeof input === "string") return input;
		if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") throw new Error("@smithy/util-utf8: toUtf8 encoder function only accepts string | Uint8Array.");
		return new TextDecoder("utf-8").decode(input);
	};
}));

//#endregion
//#region node_modules/@smithy/util-utf8/dist-es/index.js
var init_dist_es = __esmMin((() => {
	init_fromUtf8_browser();
	init_toUint8Array();
	init_toUtf8_browser();
}));

//#endregion
//#region node_modules/@smithy/util-base64/dist-es/toBase64.browser.js
init_dist_es();
function toBase64(_input) {
	let input;
	if (typeof _input === "string") input = fromUtf8$2(_input);
	else input = _input;
	const isArrayLike = typeof input === "object" && typeof input.length === "number";
	const isUint8Array = typeof input === "object" && typeof input.byteOffset === "number" && typeof input.byteLength === "number";
	if (!isArrayLike && !isUint8Array) throw new Error("@smithy/util-base64: toBase64 encoder function only accepts string | Uint8Array.");
	let str = "";
	for (let i$1 = 0; i$1 < input.length; i$1 += 3) {
		let bits = 0;
		let bitLength = 0;
		for (let j$1 = i$1, limit = Math.min(i$1 + 3, input.length); j$1 < limit; j$1++) {
			bits |= input[j$1] << (limit - j$1 - 1) * bitsPerByte;
			bitLength += bitsPerByte;
		}
		const bitClusterCount = Math.ceil(bitLength / bitsPerLetter);
		bits <<= bitClusterCount * bitsPerLetter - bitLength;
		for (let k$1 = 1; k$1 <= bitClusterCount; k$1++) {
			const offset = (bitClusterCount - k$1) * bitsPerLetter;
			str += alphabetByValue[(bits & maxLetterValue << offset) >> offset];
		}
		str += "==".slice(0, 4 - bitClusterCount);
	}
	return str;
}

//#endregion
//#region node_modules/@smithy/util-stream/dist-es/blob/Uint8ArrayBlobAdapter.js
init_dist_es();
var Uint8ArrayBlobAdapter = class Uint8ArrayBlobAdapter extends Uint8Array {
	static fromString(source, encoding = "utf-8") {
		if (typeof source === "string") {
			if (encoding === "base64") return Uint8ArrayBlobAdapter.mutate(fromBase64(source));
			return Uint8ArrayBlobAdapter.mutate(fromUtf8$2(source));
		}
		throw new Error(`Unsupported conversion from ${typeof source} to Uint8ArrayBlobAdapter.`);
	}
	static mutate(source) {
		Object.setPrototypeOf(source, Uint8ArrayBlobAdapter.prototype);
		return source;
	}
	transformToString(encoding = "utf-8") {
		if (encoding === "base64") return toBase64(this);
		return toUtf8(this);
	}
};

//#endregion
//#region node_modules/@smithy/util-uri-escape/dist-es/escape-uri.js
const escapeUri = (uri) => encodeURIComponent(uri).replace(/[!'()*]/g, hexEncode);
const hexEncode = (c$1) => `%${c$1.charCodeAt(0).toString(16).toUpperCase()}`;

//#endregion
//#region node_modules/@smithy/querystring-builder/dist-es/index.js
function buildQueryString(query) {
	const parts = [];
	for (let key of Object.keys(query).sort()) {
		const value = query[key];
		key = escapeUri(key);
		if (Array.isArray(value)) for (let i$1 = 0, iLen = value.length; i$1 < iLen; i$1++) parts.push(`${key}=${escapeUri(value[i$1])}`);
		else {
			let qsEntry = key;
			if (value || typeof value === "string") qsEntry += `=${escapeUri(value)}`;
			parts.push(qsEntry);
		}
	}
	return parts.join("&");
}

//#endregion
//#region node_modules/@smithy/fetch-http-handler/dist-es/create-request.js
function createRequest(url, requestOptions) {
	return new Request(url, requestOptions);
}

//#endregion
//#region node_modules/@smithy/fetch-http-handler/dist-es/request-timeout.js
function requestTimeout(timeoutInMs = 0) {
	return new Promise((resolve, reject) => {
		if (timeoutInMs) setTimeout(() => {
			const timeoutError = /* @__PURE__ */ new Error(`Request did not complete within ${timeoutInMs} ms`);
			timeoutError.name = "TimeoutError";
			reject(timeoutError);
		}, timeoutInMs);
	});
}

//#endregion
//#region node_modules/@smithy/fetch-http-handler/dist-es/fetch-http-handler.js
const keepAliveSupport = { supported: void 0 };
var FetchHttpHandler = class FetchHttpHandler {
	config;
	configProvider;
	static create(instanceOrOptions) {
		if (typeof instanceOrOptions?.handle === "function") return instanceOrOptions;
		return new FetchHttpHandler(instanceOrOptions);
	}
	constructor(options) {
		if (typeof options === "function") this.configProvider = options().then((opts) => opts || {});
		else {
			this.config = options ?? {};
			this.configProvider = Promise.resolve(this.config);
		}
		if (keepAliveSupport.supported === void 0) keepAliveSupport.supported = Boolean(typeof Request !== "undefined" && "keepalive" in createRequest("https://[::1]"));
	}
	destroy() {}
	async handle(request, { abortSignal, requestTimeout: requestTimeout$1 } = {}) {
		if (!this.config) this.config = await this.configProvider;
		const requestTimeoutInMs = requestTimeout$1 ?? this.config.requestTimeout;
		const keepAlive = this.config.keepAlive === true;
		const credentials = this.config.credentials;
		if (abortSignal?.aborted) {
			const abortError = /* @__PURE__ */ new Error("Request aborted");
			abortError.name = "AbortError";
			return Promise.reject(abortError);
		}
		let path = request.path;
		const queryString = buildQueryString(request.query || {});
		if (queryString) path += `?${queryString}`;
		if (request.fragment) path += `#${request.fragment}`;
		let auth = "";
		if (request.username != null || request.password != null) auth = `${request.username ?? ""}:${request.password ?? ""}@`;
		const { port, method } = request;
		const url = `${request.protocol}//${auth}${request.hostname}${port ? `:${port}` : ""}${path}`;
		const body = method === "GET" || method === "HEAD" ? void 0 : request.body;
		const requestOptions = {
			body,
			headers: new Headers(request.headers),
			method,
			credentials
		};
		if (this.config?.cache) requestOptions.cache = this.config.cache;
		if (body) requestOptions.duplex = "half";
		if (typeof AbortController !== "undefined") requestOptions.signal = abortSignal;
		if (keepAliveSupport.supported) requestOptions.keepalive = keepAlive;
		if (typeof this.config.requestInit === "function") Object.assign(requestOptions, this.config.requestInit(request));
		let removeSignalEventListener = () => {};
		const fetchRequest = createRequest(url, requestOptions);
		const raceOfPromises = [fetch(fetchRequest).then((response) => {
			const fetchHeaders = response.headers;
			const transformedHeaders = {};
			for (const pair of fetchHeaders.entries()) transformedHeaders[pair[0]] = pair[1];
			if (!(response.body != void 0)) return response.blob().then((body$1) => ({ response: new HttpResponse({
				headers: transformedHeaders,
				reason: response.statusText,
				statusCode: response.status,
				body: body$1
			}) }));
			return { response: new HttpResponse({
				headers: transformedHeaders,
				reason: response.statusText,
				statusCode: response.status,
				body: response.body
			}) };
		}), requestTimeout(requestTimeoutInMs)];
		if (abortSignal) raceOfPromises.push(new Promise((resolve, reject) => {
			const onAbort = () => {
				const abortError = /* @__PURE__ */ new Error("Request aborted");
				abortError.name = "AbortError";
				reject(abortError);
			};
			if (typeof abortSignal.addEventListener === "function") {
				const signal = abortSignal;
				signal.addEventListener("abort", onAbort, { once: true });
				removeSignalEventListener = () => signal.removeEventListener("abort", onAbort);
			} else abortSignal.onabort = onAbort;
		}));
		return Promise.race(raceOfPromises).finally(removeSignalEventListener);
	}
	updateHttpClientConfig(key, value) {
		this.config = void 0;
		this.configProvider = this.configProvider.then((config) => {
			config[key] = value;
			return config;
		});
	}
	httpHandlerConfigs() {
		return this.config ?? {};
	}
};

//#endregion
//#region node_modules/@smithy/fetch-http-handler/dist-es/stream-collector.js
const streamCollector = async (stream) => {
	if (typeof Blob === "function" && stream instanceof Blob || stream.constructor?.name === "Blob") {
		if (Blob.prototype.arrayBuffer !== void 0) return new Uint8Array(await stream.arrayBuffer());
		return collectBlob(stream);
	}
	return collectStream(stream);
};
async function collectBlob(blob) {
	const arrayBuffer = fromBase64(await readToBase64(blob));
	return new Uint8Array(arrayBuffer);
}
async function collectStream(stream) {
	const chunks = [];
	const reader = stream.getReader();
	let isDone = false;
	let length = 0;
	while (!isDone) {
		const { done, value } = await reader.read();
		if (value) {
			chunks.push(value);
			length += value.length;
		}
		isDone = done;
	}
	const collected = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		collected.set(chunk, offset);
		offset += chunk.length;
	}
	return collected;
}
function readToBase64(blob) {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onloadend = () => {
			if (reader.readyState !== 2) return reject(/* @__PURE__ */ new Error("Reader aborted too early"));
			const result = reader.result ?? "";
			const commaIndex = result.indexOf(",");
			const dataOffset = commaIndex > -1 ? commaIndex + 1 : result.length;
			resolve(result.substring(dataOffset));
		};
		reader.onabort = () => reject(/* @__PURE__ */ new Error("Read aborted"));
		reader.onerror = () => reject(reader.error);
		reader.readAsDataURL(blob);
	});
}

//#endregion
//#region node_modules/@smithy/util-hex-encoding/dist-es/index.js
const SHORT_TO_HEX = {};
const HEX_TO_SHORT = {};
for (let i$1 = 0; i$1 < 256; i$1++) {
	let encodedByte = i$1.toString(16).toLowerCase();
	if (encodedByte.length === 1) encodedByte = `0${encodedByte}`;
	SHORT_TO_HEX[i$1] = encodedByte;
	HEX_TO_SHORT[encodedByte] = i$1;
}
function fromHex(encoded) {
	if (encoded.length % 2 !== 0) throw new Error("Hex encoded strings must have an even number length");
	const out = new Uint8Array(encoded.length / 2);
	for (let i$1 = 0; i$1 < encoded.length; i$1 += 2) {
		const encodedByte = encoded.slice(i$1, i$1 + 2).toLowerCase();
		if (encodedByte in HEX_TO_SHORT) out[i$1 / 2] = HEX_TO_SHORT[encodedByte];
		else throw new Error(`Cannot decode unrecognized sequence ${encodedByte} as hexadecimal`);
	}
	return out;
}
function toHex(bytes) {
	let out = "";
	for (let i$1 = 0; i$1 < bytes.byteLength; i$1++) out += SHORT_TO_HEX[bytes[i$1]];
	return out;
}

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/collect-stream-body.js
const collectBody = async (streamBody = new Uint8Array(), context) => {
	if (streamBody instanceof Uint8Array) return Uint8ArrayBlobAdapter.mutate(streamBody);
	if (!streamBody) return Uint8ArrayBlobAdapter.mutate(new Uint8Array());
	const fromContext = context.streamCollector(streamBody);
	return Uint8ArrayBlobAdapter.mutate(await fromContext);
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/extended-encode-uri-component.js
function extendedEncodeURIComponent(str) {
	return encodeURIComponent(str).replace(/[!'()*]/g, function(c$1) {
		return "%" + c$1.charCodeAt(0).toString(16).toUpperCase();
	});
}

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/deref.js
const deref = (schemaRef) => {
	if (typeof schemaRef === "function") return schemaRef();
	return schemaRef;
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/operation.js
const operation = (namespace, name, traits, input, output) => ({
	name,
	namespace,
	traits,
	input,
	output
});

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaDeserializationMiddleware.js
const schemaDeserializationMiddleware = (config) => (next, context) => async (args) => {
	const { response } = await next(args);
	const { operationSchema } = getSmithyContext(context);
	const [, ns, n$1, t$1, i$1, o$1] = operationSchema ?? [];
	try {
		return {
			response,
			output: await config.protocol.deserializeResponse(operation(ns, n$1, t$1, i$1, o$1), {
				...config,
				...context
			}, response)
		};
	} catch (error) {
		Object.defineProperty(error, "$response", {
			value: response,
			enumerable: false,
			writable: false,
			configurable: false
		});
		if (!("$metadata" in error)) {
			const hint = `Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`;
			try {
				error.message += "\n  " + hint;
			} catch (e$1) {
				if (!context.logger || context.logger?.constructor?.name === "NoOpLogger") console.warn(hint);
				else context.logger?.warn?.(hint);
			}
			if (typeof error.$responseBodyText !== "undefined") {
				if (error.$response) error.$response.body = error.$responseBodyText;
			}
			try {
				if (HttpResponse.isInstance(response)) {
					const { headers = {} } = response;
					const headerEntries = Object.entries(headers);
					error.$metadata = {
						httpStatusCode: response.statusCode,
						requestId: findHeader(/^x-[\w-]+-request-?id$/, headerEntries),
						extendedRequestId: findHeader(/^x-[\w-]+-id-2$/, headerEntries),
						cfId: findHeader(/^x-[\w-]+-cf-id$/, headerEntries)
					};
				}
			} catch (e$1) {}
		}
		throw error;
	}
};
const findHeader = (pattern, headers) => {
	return (headers.find(([k$1]) => {
		return k$1.match(pattern);
	}) || [void 0, void 0])[1];
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaSerializationMiddleware.js
const schemaSerializationMiddleware = (config) => (next, context) => async (args) => {
	const { operationSchema } = getSmithyContext(context);
	const [, ns, n$1, t$1, i$1, o$1] = operationSchema ?? [];
	const endpoint = context.endpointV2?.url && config.urlParser ? async () => config.urlParser(context.endpointV2.url) : config.endpoint;
	const request = await config.protocol.serializeRequest(operation(ns, n$1, t$1, i$1, o$1), args.input, {
		...config,
		...context,
		endpoint
	});
	return next({
		...args,
		request
	});
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/middleware/getSchemaSerdePlugin.js
const deserializerMiddlewareOption = {
	name: "deserializerMiddleware",
	step: "deserialize",
	tags: ["DESERIALIZER"],
	override: true
};
const serializerMiddlewareOption = {
	name: "serializerMiddleware",
	step: "serialize",
	tags: ["SERIALIZER"],
	override: true
};
function getSchemaSerdePlugin(config) {
	return { applyToStack: (commandStack) => {
		commandStack.add(schemaSerializationMiddleware(config), serializerMiddlewareOption);
		commandStack.add(schemaDeserializationMiddleware(config), deserializerMiddlewareOption);
		config.protocol.setSerdeContext(config);
	} };
}

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/translateTraits.js
function translateTraits(indicator) {
	if (typeof indicator === "object") return indicator;
	indicator = indicator | 0;
	const traits = {};
	let i$1 = 0;
	for (const trait of [
		"httpLabel",
		"idempotent",
		"idempotencyToken",
		"sensitive",
		"httpPayload",
		"httpResponseCode",
		"httpQueryParams"
	]) if ((indicator >> i$1++ & 1) === 1) traits[trait] = 1;
	return traits;
}

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/NormalizedSchema.js
var NormalizedSchema = class NormalizedSchema {
	ref;
	memberName;
	static symbol = Symbol.for("@smithy/nor");
	symbol = NormalizedSchema.symbol;
	name;
	schema;
	_isMemberSchema;
	traits;
	memberTraits;
	normalizedTraits;
	constructor(ref, memberName) {
		this.ref = ref;
		this.memberName = memberName;
		const traitStack = [];
		let _ref = ref;
		let schema = ref;
		this._isMemberSchema = false;
		while (isMemberSchema(_ref)) {
			traitStack.push(_ref[1]);
			_ref = _ref[0];
			schema = deref(_ref);
			this._isMemberSchema = true;
		}
		if (traitStack.length > 0) {
			this.memberTraits = {};
			for (let i$1 = traitStack.length - 1; i$1 >= 0; --i$1) {
				const traitSet = traitStack[i$1];
				Object.assign(this.memberTraits, translateTraits(traitSet));
			}
		} else this.memberTraits = 0;
		if (schema instanceof NormalizedSchema) {
			const computedMemberTraits = this.memberTraits;
			Object.assign(this, schema);
			this.memberTraits = Object.assign({}, computedMemberTraits, schema.getMemberTraits(), this.getMemberTraits());
			this.normalizedTraits = void 0;
			this.memberName = memberName ?? schema.memberName;
			return;
		}
		this.schema = deref(schema);
		if (isStaticSchema(this.schema)) {
			this.name = `${this.schema[1]}#${this.schema[2]}`;
			this.traits = this.schema[3];
		} else {
			this.name = this.memberName ?? String(schema);
			this.traits = 0;
		}
		if (this._isMemberSchema && !memberName) throw new Error(`@smithy/core/schema - NormalizedSchema member init ${this.getName(true)} missing member name.`);
	}
	static [Symbol.hasInstance](lhs) {
		const isPrototype = this.prototype.isPrototypeOf(lhs);
		if (!isPrototype && typeof lhs === "object" && lhs !== null) return lhs.symbol === this.symbol;
		return isPrototype;
	}
	static of(ref) {
		const sc = deref(ref);
		if (sc instanceof NormalizedSchema) return sc;
		if (isMemberSchema(sc)) {
			const [ns, traits] = sc;
			if (ns instanceof NormalizedSchema) {
				Object.assign(ns.getMergedTraits(), translateTraits(traits));
				return ns;
			}
			throw new Error(`@smithy/core/schema - may not init unwrapped member schema=${JSON.stringify(ref, null, 2)}.`);
		}
		return new NormalizedSchema(sc);
	}
	getSchema() {
		const sc = this.schema;
		if (sc[0] === 0) return sc[4];
		return sc;
	}
	getName(withNamespace = false) {
		const { name } = this;
		return !withNamespace && name && name.includes("#") ? name.split("#")[1] : name || void 0;
	}
	getMemberName() {
		return this.memberName;
	}
	isMemberSchema() {
		return this._isMemberSchema;
	}
	isListSchema() {
		const sc = this.getSchema();
		return typeof sc === "number" ? sc >= 64 && sc < 128 : sc[0] === 1;
	}
	isMapSchema() {
		const sc = this.getSchema();
		return typeof sc === "number" ? sc >= 128 && sc <= 255 : sc[0] === 2;
	}
	isStructSchema() {
		const id = this.getSchema()[0];
		return id === 3 || id === -3 || id === 4;
	}
	isUnionSchema() {
		return this.getSchema()[0] === 4;
	}
	isBlobSchema() {
		const sc = this.getSchema();
		return sc === 21 || sc === 42;
	}
	isTimestampSchema() {
		const sc = this.getSchema();
		return typeof sc === "number" && sc >= 4 && sc <= 7;
	}
	isUnitSchema() {
		return this.getSchema() === "unit";
	}
	isDocumentSchema() {
		return this.getSchema() === 15;
	}
	isStringSchema() {
		return this.getSchema() === 0;
	}
	isBooleanSchema() {
		return this.getSchema() === 2;
	}
	isNumericSchema() {
		return this.getSchema() === 1;
	}
	isBigIntegerSchema() {
		return this.getSchema() === 17;
	}
	isBigDecimalSchema() {
		return this.getSchema() === 19;
	}
	isStreaming() {
		const { streaming } = this.getMergedTraits();
		return !!streaming || this.getSchema() === 42;
	}
	isIdempotencyToken() {
		const match = (traits$1) => (traits$1 & 4) === 4 || !!traits$1?.idempotencyToken;
		const { normalizedTraits, traits, memberTraits } = this;
		return match(normalizedTraits) || match(traits) || match(memberTraits);
	}
	getMergedTraits() {
		return this.normalizedTraits ?? (this.normalizedTraits = {
			...this.getOwnTraits(),
			...this.getMemberTraits()
		});
	}
	getMemberTraits() {
		return translateTraits(this.memberTraits);
	}
	getOwnTraits() {
		return translateTraits(this.traits);
	}
	getKeySchema() {
		const [isDoc, isMap] = [this.isDocumentSchema(), this.isMapSchema()];
		if (!isDoc && !isMap) throw new Error(`@smithy/core/schema - cannot get key for non-map: ${this.getName(true)}`);
		const schema = this.getSchema();
		return member([isDoc ? 15 : schema[4] ?? 0, 0], "key");
	}
	getValueSchema() {
		const sc = this.getSchema();
		const [isDoc, isMap, isList] = [
			this.isDocumentSchema(),
			this.isMapSchema(),
			this.isListSchema()
		];
		const memberSchema = typeof sc === "number" ? 63 & sc : sc && typeof sc === "object" && (isMap || isList) ? sc[3 + sc[0]] : isDoc ? 15 : void 0;
		if (memberSchema != null) return member([memberSchema, 0], isMap ? "value" : "member");
		throw new Error(`@smithy/core/schema - ${this.getName(true)} has no value member.`);
	}
	getMemberSchema(memberName) {
		const struct = this.getSchema();
		if (this.isStructSchema() && struct[4].includes(memberName)) {
			const i$1 = struct[4].indexOf(memberName);
			const memberSchema = struct[5][i$1];
			return member(isMemberSchema(memberSchema) ? memberSchema : [memberSchema, 0], memberName);
		}
		if (this.isDocumentSchema()) return member([15, 0], memberName);
		throw new Error(`@smithy/core/schema - ${this.getName(true)} has no no member=${memberName}.`);
	}
	getMemberSchemas() {
		const buffer = {};
		try {
			for (const [k$1, v$1] of this.structIterator()) buffer[k$1] = v$1;
		} catch (ignored) {}
		return buffer;
	}
	getEventStreamMember() {
		if (this.isStructSchema()) {
			for (const [memberName, memberSchema] of this.structIterator()) if (memberSchema.isStreaming() && memberSchema.isStructSchema()) return memberName;
		}
		return "";
	}
	*structIterator() {
		if (this.isUnitSchema()) return;
		if (!this.isStructSchema()) throw new Error("@smithy/core/schema - cannot iterate non-struct schema.");
		const struct = this.getSchema();
		for (let i$1 = 0; i$1 < struct[4].length; ++i$1) yield [struct[4][i$1], member([struct[5][i$1], 0], struct[4][i$1])];
	}
};
function member(memberSchema, memberName) {
	if (memberSchema instanceof NormalizedSchema) return Object.assign(memberSchema, {
		memberName,
		_isMemberSchema: true
	});
	return new NormalizedSchema(memberSchema, memberName);
}
const isMemberSchema = (sc) => Array.isArray(sc) && sc.length === 2;
const isStaticSchema = (sc) => Array.isArray(sc) && sc.length >= 5;

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/TypeRegistry.js
var TypeRegistry = class TypeRegistry {
	namespace;
	schemas;
	exceptions;
	static registries = /* @__PURE__ */ new Map();
	constructor(namespace, schemas = /* @__PURE__ */ new Map(), exceptions = /* @__PURE__ */ new Map()) {
		this.namespace = namespace;
		this.schemas = schemas;
		this.exceptions = exceptions;
	}
	static for(namespace) {
		if (!TypeRegistry.registries.has(namespace)) TypeRegistry.registries.set(namespace, new TypeRegistry(namespace));
		return TypeRegistry.registries.get(namespace);
	}
	register(shapeId, schema) {
		const qualifiedName = this.normalizeShapeId(shapeId);
		TypeRegistry.for(qualifiedName.split("#")[0]).schemas.set(qualifiedName, schema);
	}
	getSchema(shapeId) {
		const id = this.normalizeShapeId(shapeId);
		if (!this.schemas.has(id)) throw new Error(`@smithy/core/schema - schema not found for ${id}`);
		return this.schemas.get(id);
	}
	registerError(es, ctor) {
		const $error = es;
		const registry = TypeRegistry.for($error[1]);
		registry.schemas.set($error[1] + "#" + $error[2], $error);
		registry.exceptions.set($error, ctor);
	}
	getErrorCtor(es) {
		const $error = es;
		return TypeRegistry.for($error[1]).exceptions.get($error);
	}
	getBaseException() {
		for (const exceptionKey of this.exceptions.keys()) if (Array.isArray(exceptionKey)) {
			const [, ns, name] = exceptionKey;
			const id = ns + "#" + name;
			if (id.startsWith("smithy.ts.sdk.synthetic.") && id.endsWith("ServiceException")) return exceptionKey;
		}
	}
	find(predicate) {
		return [...this.schemas.values()].find(predicate);
	}
	clear() {
		this.schemas.clear();
		this.exceptions.clear();
	}
	normalizeShapeId(shapeId) {
		if (shapeId.includes("#")) return shapeId;
		return this.namespace + "#" + shapeId;
	}
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/date-utils.js
const DAYS = [
	"Sun",
	"Mon",
	"Tue",
	"Wed",
	"Thu",
	"Fri",
	"Sat"
];
const MONTHS = [
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
];
function dateToUtcString(date$1) {
	const year$1 = date$1.getUTCFullYear();
	const month = date$1.getUTCMonth();
	const dayOfWeek = date$1.getUTCDay();
	const dayOfMonthInt = date$1.getUTCDate();
	const hoursInt = date$1.getUTCHours();
	const minutesInt = date$1.getUTCMinutes();
	const secondsInt = date$1.getUTCSeconds();
	const dayOfMonthString = dayOfMonthInt < 10 ? `0${dayOfMonthInt}` : `${dayOfMonthInt}`;
	const hoursString = hoursInt < 10 ? `0${hoursInt}` : `${hoursInt}`;
	const minutesString = minutesInt < 10 ? `0${minutesInt}` : `${minutesInt}`;
	const secondsString = secondsInt < 10 ? `0${secondsInt}` : `${secondsInt}`;
	return `${DAYS[dayOfWeek]}, ${dayOfMonthString} ${MONTHS[month]} ${year$1} ${hoursString}:${minutesString}:${secondsString} GMT`;
}
const FIFTY_YEARS_IN_MILLIS = 50 * 365 * 24 * 60 * 60 * 1e3;

//#endregion
//#region node_modules/@smithy/uuid/dist-es/randomUUID.browser.js
const randomUUID = typeof crypto !== "undefined" && crypto.randomUUID && crypto.randomUUID.bind(crypto);

//#endregion
//#region node_modules/@smithy/uuid/dist-es/v4.js
const decimalToHex = Array.from({ length: 256 }, (_, i$1) => i$1.toString(16).padStart(2, "0"));
const v4 = () => {
	if (randomUUID) return randomUUID();
	const rnds = new Uint8Array(16);
	crypto.getRandomValues(rnds);
	rnds[6] = rnds[6] & 15 | 64;
	rnds[8] = rnds[8] & 63 | 128;
	return decimalToHex[rnds[0]] + decimalToHex[rnds[1]] + decimalToHex[rnds[2]] + decimalToHex[rnds[3]] + "-" + decimalToHex[rnds[4]] + decimalToHex[rnds[5]] + "-" + decimalToHex[rnds[6]] + decimalToHex[rnds[7]] + "-" + decimalToHex[rnds[8]] + decimalToHex[rnds[9]] + "-" + decimalToHex[rnds[10]] + decimalToHex[rnds[11]] + decimalToHex[rnds[12]] + decimalToHex[rnds[13]] + decimalToHex[rnds[14]] + decimalToHex[rnds[15]];
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/lazy-json.js
const LazyJsonString = function LazyJsonString$1(val) {
	return Object.assign(new String(val), {
		deserializeJSON() {
			return JSON.parse(String(val));
		},
		toString() {
			return String(val);
		},
		toJSON() {
			return String(val);
		}
	});
};
LazyJsonString.from = (object) => {
	if (object && typeof object === "object" && (object instanceof LazyJsonString || "deserializeJSON" in object)) return object;
	else if (typeof object === "string" || Object.getPrototypeOf(object) === String.prototype) return LazyJsonString(String(object));
	return LazyJsonString(JSON.stringify(object));
};
LazyJsonString.fromObject = LazyJsonString.from;

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/schema-serde-lib/schema-date-utils.js
const ddd = `(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)(?:[ne|u?r]?s?day)?`;
const mmm = `(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`;
const time = `(\\d?\\d):(\\d{2}):(\\d{2})(?:\\.(\\d+))?`;
const date = `(\\d?\\d)`;
const year = `(\\d{4})`;
const RFC3339_WITH_OFFSET = /* @__PURE__ */ new RegExp(/^(\d{4})-(\d\d)-(\d\d)[tT](\d\d):(\d\d):(\d\d)(\.(\d+))?(([-+]\d\d:\d\d)|[zZ])$/);
const IMF_FIXDATE = /* @__PURE__ */ new RegExp(`^${ddd}, ${date} ${mmm} ${year} ${time} GMT$`);
const RFC_850_DATE = /* @__PURE__ */ new RegExp(`^${ddd}, ${date}-${mmm}-(\\d\\d) ${time} GMT$`);
const ASC_TIME = /* @__PURE__ */ new RegExp(`^${ddd} ${mmm} ( [1-9]|\\d\\d) ${time} ${year}$`);
const months = [
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
];
const _parseEpochTimestamp = (value) => {
	if (value == null) return;
	let num = NaN;
	if (typeof value === "number") num = value;
	else if (typeof value === "string") {
		if (!/^-?\d*\.?\d+$/.test(value)) throw new TypeError(`parseEpochTimestamp - numeric string invalid.`);
		num = Number.parseFloat(value);
	} else if (typeof value === "object" && value.tag === 1) num = value.value;
	if (isNaN(num) || Math.abs(num) === Infinity) throw new TypeError("Epoch timestamps must be valid finite numbers.");
	return new Date(Math.round(num * 1e3));
};
const _parseRfc3339DateTimeWithOffset = (value) => {
	if (value == null) return;
	if (typeof value !== "string") throw new TypeError("RFC3339 timestamps must be strings");
	const matches = RFC3339_WITH_OFFSET.exec(value);
	if (!matches) throw new TypeError(`Invalid RFC3339 timestamp format ${value}`);
	const [, yearStr, monthStr, dayStr, hours, minutes, seconds, , ms, offsetStr] = matches;
	range(monthStr, 1, 12);
	range(dayStr, 1, 31);
	range(hours, 0, 23);
	range(minutes, 0, 59);
	range(seconds, 0, 60);
	const date$1 = new Date(Date.UTC(Number(yearStr), Number(monthStr) - 1, Number(dayStr), Number(hours), Number(minutes), Number(seconds), Number(ms) ? Math.round(parseFloat(`0.${ms}`) * 1e3) : 0));
	date$1.setUTCFullYear(Number(yearStr));
	if (offsetStr.toUpperCase() != "Z") {
		const [, sign, offsetH, offsetM] = /([+-])(\d\d):(\d\d)/.exec(offsetStr) || [
			void 0,
			"+",
			0,
			0
		];
		const scalar = sign === "-" ? 1 : -1;
		date$1.setTime(date$1.getTime() + scalar * (Number(offsetH) * 60 * 60 * 1e3 + Number(offsetM) * 60 * 1e3));
	}
	return date$1;
};
const _parseRfc7231DateTime = (value) => {
	if (value == null) return;
	if (typeof value !== "string") throw new TypeError("RFC7231 timestamps must be strings.");
	let day;
	let month;
	let year$1;
	let hour;
	let minute;
	let second;
	let fraction;
	let matches;
	if (matches = IMF_FIXDATE.exec(value)) [, day, month, year$1, hour, minute, second, fraction] = matches;
	else if (matches = RFC_850_DATE.exec(value)) {
		[, day, month, year$1, hour, minute, second, fraction] = matches;
		year$1 = (Number(year$1) + 1900).toString();
	} else if (matches = ASC_TIME.exec(value)) [, month, day, hour, minute, second, fraction, year$1] = matches;
	if (year$1 && second) {
		const timestamp = Date.UTC(Number(year$1), months.indexOf(month), Number(day), Number(hour), Number(minute), Number(second), fraction ? Math.round(parseFloat(`0.${fraction}`) * 1e3) : 0);
		range(day, 1, 31);
		range(hour, 0, 23);
		range(minute, 0, 59);
		range(second, 0, 60);
		const date$1 = new Date(timestamp);
		date$1.setUTCFullYear(Number(year$1));
		return date$1;
	}
	throw new TypeError(`Invalid RFC7231 date-time value ${value}.`);
};
function range(v$1, min, max) {
	const _v = Number(v$1);
	if (_v < min || _v > max) throw new Error(`Value ${_v} out of range [${min}, ${max}]`);
}

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/split-header.js
const splitHeader = (value) => {
	const z$1 = value.length;
	const values = [];
	let withinQuotes = false;
	let prevChar = void 0;
	let anchor = 0;
	for (let i$1 = 0; i$1 < z$1; ++i$1) {
		const char = value[i$1];
		switch (char) {
			case `"`:
				if (prevChar !== "\\") withinQuotes = !withinQuotes;
				break;
			case ",":
				if (!withinQuotes) {
					values.push(value.slice(anchor, i$1));
					anchor = i$1 + 1;
				}
				break;
			default:
		}
		prevChar = char;
	}
	values.push(value.slice(anchor));
	return values.map((v$1) => {
		v$1 = v$1.trim();
		const z$2 = v$1.length;
		if (z$2 < 2) return v$1;
		if (v$1[0] === `"` && v$1[z$2 - 1] === `"`) v$1 = v$1.slice(1, z$2 - 1);
		return v$1.replace(/\\"/g, "\"");
	});
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/value/NumericValue.js
const format = /^-?\d*(\.\d+)?$/;
var NumericValue = class NumericValue {
	string;
	type;
	constructor(string, type) {
		this.string = string;
		this.type = type;
		if (!format.test(string)) throw new Error(`@smithy/core/serde - NumericValue must only contain [0-9], at most one decimal point ".", and an optional negation prefix "-".`);
	}
	toString() {
		return this.string;
	}
	static [Symbol.hasInstance](object) {
		if (!object || typeof object !== "object") return false;
		const _nv = object;
		return NumericValue.prototype.isPrototypeOf(object) || _nv.type === "bigDecimal" && format.test(_nv.string);
	}
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/SerdeContext.js
var SerdeContext = class {
	serdeContext;
	setSerdeContext(serdeContext) {
		this.serdeContext = serdeContext;
	}
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/event-streams/EventStreamSerde.js
var EventStreamSerde;
var init_EventStreamSerde = __esmMin((() => {
	init_dist_es();
	EventStreamSerde = class {
		marshaller;
		serializer;
		deserializer;
		serdeContext;
		defaultContentType;
		constructor({ marshaller, serializer, deserializer, serdeContext, defaultContentType }) {
			this.marshaller = marshaller;
			this.serializer = serializer;
			this.deserializer = deserializer;
			this.serdeContext = serdeContext;
			this.defaultContentType = defaultContentType;
		}
		async serializeEventStream({ eventStream, requestSchema, initialRequest }) {
			const marshaller = this.marshaller;
			const eventStreamMember = requestSchema.getEventStreamMember();
			const unionSchema = requestSchema.getMemberSchema(eventStreamMember);
			const serializer = this.serializer;
			const defaultContentType = this.defaultContentType;
			const initialRequestMarker = Symbol("initialRequestMarker");
			const eventStreamIterable = { async *[Symbol.asyncIterator]() {
				if (initialRequest) {
					const headers = {
						":event-type": {
							type: "string",
							value: "initial-request"
						},
						":message-type": {
							type: "string",
							value: "event"
						},
						":content-type": {
							type: "string",
							value: defaultContentType
						}
					};
					serializer.write(requestSchema, initialRequest);
					const body = serializer.flush();
					yield {
						[initialRequestMarker]: true,
						headers,
						body
					};
				}
				for await (const page of eventStream) yield page;
			} };
			return marshaller.serialize(eventStreamIterable, (event) => {
				if (event[initialRequestMarker]) return {
					headers: event.headers,
					body: event.body
				};
				const unionMember = Object.keys(event).find((key) => {
					return key !== "__type";
				}) ?? "";
				const { additionalHeaders, body, eventType, explicitPayloadContentType } = this.writeEventBody(unionMember, unionSchema, event);
				return {
					headers: {
						":event-type": {
							type: "string",
							value: eventType
						},
						":message-type": {
							type: "string",
							value: "event"
						},
						":content-type": {
							type: "string",
							value: explicitPayloadContentType ?? defaultContentType
						},
						...additionalHeaders
					},
					body
				};
			});
		}
		async deserializeEventStream({ response, responseSchema, initialResponseContainer }) {
			const marshaller = this.marshaller;
			const eventStreamMember = responseSchema.getEventStreamMember();
			const memberSchemas = responseSchema.getMemberSchema(eventStreamMember).getMemberSchemas();
			const initialResponseMarker = Symbol("initialResponseMarker");
			const asyncIterable = marshaller.deserialize(response.body, async (event) => {
				const unionMember = Object.keys(event).find((key) => {
					return key !== "__type";
				}) ?? "";
				const body = event[unionMember].body;
				if (unionMember === "initial-response") {
					const dataObject = await this.deserializer.read(responseSchema, body);
					delete dataObject[eventStreamMember];
					return {
						[initialResponseMarker]: true,
						...dataObject
					};
				} else if (unionMember in memberSchemas) {
					const eventStreamSchema = memberSchemas[unionMember];
					if (eventStreamSchema.isStructSchema()) {
						const out = {};
						let hasBindings = false;
						for (const [name, member$1] of eventStreamSchema.structIterator()) {
							const { eventHeader, eventPayload } = member$1.getMergedTraits();
							hasBindings = hasBindings || Boolean(eventHeader || eventPayload);
							if (eventPayload) {
								if (member$1.isBlobSchema()) out[name] = body;
								else if (member$1.isStringSchema()) out[name] = (this.serdeContext?.utf8Encoder ?? toUtf8)(body);
								else if (member$1.isStructSchema()) out[name] = await this.deserializer.read(member$1, body);
							} else if (eventHeader) {
								const value = event[unionMember].headers[name]?.value;
								if (value != null) if (member$1.isNumericSchema()) if (value && typeof value === "object" && "bytes" in value) out[name] = BigInt(value.toString());
								else out[name] = Number(value);
								else out[name] = value;
							}
						}
						if (hasBindings) return { [unionMember]: out };
					}
					return { [unionMember]: await this.deserializer.read(eventStreamSchema, body) };
				} else return { $unknown: event };
			});
			const asyncIterator = asyncIterable[Symbol.asyncIterator]();
			const firstEvent = await asyncIterator.next();
			if (firstEvent.done) return asyncIterable;
			if (firstEvent.value?.[initialResponseMarker]) {
				if (!responseSchema) throw new Error("@smithy::core/protocols - initial-response event encountered in event stream but no response schema given.");
				for (const [key, value] of Object.entries(firstEvent.value)) initialResponseContainer[key] = value;
			}
			return { async *[Symbol.asyncIterator]() {
				if (!firstEvent?.value?.[initialResponseMarker]) yield firstEvent.value;
				while (true) {
					const { done, value } = await asyncIterator.next();
					if (done) break;
					yield value;
				}
			} };
		}
		writeEventBody(unionMember, unionSchema, event) {
			const serializer = this.serializer;
			let eventType = unionMember;
			let explicitPayloadMember = null;
			let explicitPayloadContentType;
			const isKnownSchema = unionSchema.getSchema()[4].includes(unionMember);
			const additionalHeaders = {};
			if (!isKnownSchema) {
				const [type, value] = event[unionMember];
				eventType = type;
				serializer.write(15, value);
			} else {
				const eventSchema = unionSchema.getMemberSchema(unionMember);
				if (eventSchema.isStructSchema()) {
					for (const [memberName, memberSchema] of eventSchema.structIterator()) {
						const { eventHeader, eventPayload } = memberSchema.getMergedTraits();
						if (eventPayload) explicitPayloadMember = memberName;
						else if (eventHeader) {
							const value = event[unionMember][memberName];
							let type = "binary";
							if (memberSchema.isNumericSchema()) if ((-2) ** 31 <= value && value <= 2 ** 31 - 1) type = "integer";
							else type = "long";
							else if (memberSchema.isTimestampSchema()) type = "timestamp";
							else if (memberSchema.isStringSchema()) type = "string";
							else if (memberSchema.isBooleanSchema()) type = "boolean";
							if (value != null) {
								additionalHeaders[memberName] = {
									type,
									value
								};
								delete event[unionMember][memberName];
							}
						}
					}
					if (explicitPayloadMember !== null) {
						const payloadSchema = eventSchema.getMemberSchema(explicitPayloadMember);
						if (payloadSchema.isBlobSchema()) explicitPayloadContentType = "application/octet-stream";
						else if (payloadSchema.isStringSchema()) explicitPayloadContentType = "text/plain";
						serializer.write(payloadSchema, event[unionMember][explicitPayloadMember]);
					} else serializer.write(eventSchema, event[unionMember]);
				} else throw new Error("@smithy/core/event-streams - non-struct member not supported in event stream union.");
			}
			const messageSerialization = serializer.flush();
			return {
				body: typeof messageSerialization === "string" ? (this.serdeContext?.utf8Decoder ?? fromUtf8$2)(messageSerialization) : messageSerialization,
				eventType,
				explicitPayloadContentType,
				additionalHeaders
			};
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/event-streams/index.js
var event_streams_exports = /* @__PURE__ */ __exportAll({ EventStreamSerde: () => EventStreamSerde });
var init_event_streams = __esmMin((() => {
	init_EventStreamSerde();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/HttpProtocol.js
var HttpProtocol = class extends SerdeContext {
	options;
	constructor(options) {
		super();
		this.options = options;
	}
	getRequestType() {
		return HttpRequest;
	}
	getResponseType() {
		return HttpResponse;
	}
	setSerdeContext(serdeContext) {
		this.serdeContext = serdeContext;
		this.serializer.setSerdeContext(serdeContext);
		this.deserializer.setSerdeContext(serdeContext);
		if (this.getPayloadCodec()) this.getPayloadCodec().setSerdeContext(serdeContext);
	}
	updateServiceEndpoint(request, endpoint) {
		if ("url" in endpoint) {
			request.protocol = endpoint.url.protocol;
			request.hostname = endpoint.url.hostname;
			request.port = endpoint.url.port ? Number(endpoint.url.port) : void 0;
			request.path = endpoint.url.pathname;
			request.fragment = endpoint.url.hash || void 0;
			request.username = endpoint.url.username || void 0;
			request.password = endpoint.url.password || void 0;
			if (!request.query) request.query = {};
			for (const [k$1, v$1] of endpoint.url.searchParams.entries()) request.query[k$1] = v$1;
			return request;
		} else {
			request.protocol = endpoint.protocol;
			request.hostname = endpoint.hostname;
			request.port = endpoint.port ? Number(endpoint.port) : void 0;
			request.path = endpoint.path;
			request.query = { ...endpoint.query };
			return request;
		}
	}
	setHostPrefix(request, operationSchema, input) {
		const inputNs = NormalizedSchema.of(operationSchema.input);
		const opTraits = translateTraits(operationSchema.traits ?? {});
		if (opTraits.endpoint) {
			let hostPrefix = opTraits.endpoint?.[0];
			if (typeof hostPrefix === "string") {
				const hostLabelInputs = [...inputNs.structIterator()].filter(([, member$1]) => member$1.getMergedTraits().hostLabel);
				for (const [name] of hostLabelInputs) {
					const replacement = input[name];
					if (typeof replacement !== "string") throw new Error(`@smithy/core/schema - ${name} in input must be a string as hostLabel.`);
					hostPrefix = hostPrefix.replace(`{${name}}`, replacement);
				}
				request.hostname = hostPrefix + request.hostname;
			}
		}
	}
	deserializeMetadata(output) {
		return {
			httpStatusCode: output.statusCode,
			requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
			extendedRequestId: output.headers["x-amz-id-2"],
			cfId: output.headers["x-amz-cf-id"]
		};
	}
	async serializeEventStream({ eventStream, requestSchema, initialRequest }) {
		return (await this.loadEventStreamCapability()).serializeEventStream({
			eventStream,
			requestSchema,
			initialRequest
		});
	}
	async deserializeEventStream({ response, responseSchema, initialResponseContainer }) {
		return (await this.loadEventStreamCapability()).deserializeEventStream({
			response,
			responseSchema,
			initialResponseContainer
		});
	}
	async loadEventStreamCapability() {
		const { EventStreamSerde: EventStreamSerde$1 } = await Promise.resolve().then(() => (init_event_streams(), event_streams_exports));
		return new EventStreamSerde$1({
			marshaller: this.getEventStreamMarshaller(),
			serializer: this.serializer,
			deserializer: this.deserializer,
			serdeContext: this.serdeContext,
			defaultContentType: this.getDefaultContentType()
		});
	}
	getDefaultContentType() {
		throw new Error(`@smithy/core/protocols - ${this.constructor.name} getDefaultContentType() implementation missing.`);
	}
	async deserializeHttpMessage(schema, context, response, arg4, arg5) {
		return [];
	}
	getEventStreamMarshaller() {
		const context = this.serdeContext;
		if (!context.eventStreamMarshaller) throw new Error("@smithy/core - HttpProtocol: eventStreamMarshaller missing in serdeContext.");
		return context.eventStreamMarshaller;
	}
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/RpcProtocol.js
var RpcProtocol = class extends HttpProtocol {
	async serializeRequest(operationSchema, input, context) {
		const serializer = this.serializer;
		const query = {};
		const headers = {};
		const endpoint = await context.endpoint();
		const ns = NormalizedSchema.of(operationSchema?.input);
		const schema = ns.getSchema();
		let payload;
		const request = new HttpRequest({
			protocol: "",
			hostname: "",
			port: void 0,
			path: "/",
			fragment: void 0,
			query,
			headers,
			body: void 0
		});
		if (endpoint) {
			this.updateServiceEndpoint(request, endpoint);
			this.setHostPrefix(request, operationSchema, input);
		}
		const _input = { ...input };
		if (input) {
			const eventStreamMember = ns.getEventStreamMember();
			if (eventStreamMember) {
				if (_input[eventStreamMember]) {
					const initialRequest = {};
					for (const [memberName, memberSchema] of ns.structIterator()) if (memberName !== eventStreamMember && _input[memberName]) {
						serializer.write(memberSchema, _input[memberName]);
						initialRequest[memberName] = serializer.flush();
					}
					payload = await this.serializeEventStream({
						eventStream: _input[eventStreamMember],
						requestSchema: ns,
						initialRequest
					});
				}
			} else {
				serializer.write(schema, _input);
				payload = serializer.flush();
			}
		}
		request.headers = headers;
		request.query = query;
		request.body = payload;
		request.method = "POST";
		return request;
	}
	async deserializeResponse(operationSchema, context, response) {
		const deserializer = this.deserializer;
		const ns = NormalizedSchema.of(operationSchema.output);
		const dataObject = {};
		if (response.statusCode >= 300) {
			const bytes = await collectBody(response.body, context);
			if (bytes.byteLength > 0) Object.assign(dataObject, await deserializer.read(15, bytes));
			await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
			throw new Error("@smithy/core/protocols - RPC Protocol error handler failed to throw.");
		}
		for (const header in response.headers) {
			const value = response.headers[header];
			delete response.headers[header];
			response.headers[header.toLowerCase()] = value;
		}
		const eventStreamMember = ns.getEventStreamMember();
		if (eventStreamMember) dataObject[eventStreamMember] = await this.deserializeEventStream({
			response,
			responseSchema: ns,
			initialResponseContainer: dataObject
		});
		else {
			const bytes = await collectBody(response.body, context);
			if (bytes.byteLength > 0) Object.assign(dataObject, await deserializer.read(ns, bytes));
		}
		dataObject.$metadata = this.deserializeMetadata(response);
		return dataObject;
	}
};

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/serde/determineTimestampFormat.js
function determineTimestampFormat(ns, settings) {
	if (settings.timestampFormat.useTrait) {
		if (ns.isTimestampSchema() && (ns.getSchema() === 5 || ns.getSchema() === 6 || ns.getSchema() === 7)) return ns.getSchema();
	}
	const { httpLabel, httpPrefixHeaders, httpHeader, httpQuery } = ns.getMergedTraits();
	return (settings.httpBindings ? typeof httpPrefixHeaders === "string" || Boolean(httpHeader) ? 6 : Boolean(httpQuery) || Boolean(httpLabel) ? 5 : void 0 : void 0) ?? settings.timestampFormat.default;
}

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/serde/FromStringShapeDeserializer.js
init_dist_es();
var FromStringShapeDeserializer = class extends SerdeContext {
	settings;
	constructor(settings) {
		super();
		this.settings = settings;
	}
	read(_schema, data) {
		const ns = NormalizedSchema.of(_schema);
		if (ns.isListSchema()) return splitHeader(data).map((item) => this.read(ns.getValueSchema(), item));
		if (ns.isBlobSchema()) return (this.serdeContext?.base64Decoder ?? fromBase64)(data);
		if (ns.isTimestampSchema()) switch (determineTimestampFormat(ns, this.settings)) {
			case 5: return _parseRfc3339DateTimeWithOffset(data);
			case 6: return _parseRfc7231DateTime(data);
			case 7: return _parseEpochTimestamp(data);
			default:
				console.warn("Missing timestamp format, parsing value with Date constructor:", data);
				return new Date(data);
		}
		if (ns.isStringSchema()) {
			const mediaType = ns.getMergedTraits().mediaType;
			let intermediateValue = data;
			if (mediaType) {
				if (ns.getMergedTraits().httpHeader) intermediateValue = this.base64ToUtf8(intermediateValue);
				if (mediaType === "application/json" || mediaType.endsWith("+json")) intermediateValue = LazyJsonString.from(intermediateValue);
				return intermediateValue;
			}
		}
		if (ns.isNumericSchema()) return Number(data);
		if (ns.isBigIntegerSchema()) return BigInt(data);
		if (ns.isBigDecimalSchema()) return new NumericValue(data, "bigDecimal");
		if (ns.isBooleanSchema()) return String(data).toLowerCase() === "true";
		return data;
	}
	base64ToUtf8(base64String) {
		return (this.serdeContext?.utf8Encoder ?? toUtf8)((this.serdeContext?.base64Decoder ?? fromBase64)(base64String));
	}
};

//#endregion
//#region node_modules/@smithy/core/dist-es/setFeature.js
function setFeature$1(context, feature, value) {
	if (!context.__smithy_context) context.__smithy_context = { features: {} };
	else if (!context.__smithy_context.features) context.__smithy_context.features = {};
	context.__smithy_context.features[feature] = value;
}

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/DefaultIdentityProviderConfig.js
var DefaultIdentityProviderConfig = class {
	authSchemes = /* @__PURE__ */ new Map();
	constructor(config) {
		for (const [key, value] of Object.entries(config)) if (value !== void 0) this.authSchemes.set(key, value);
	}
	getIdentityProvider(schemeId) {
		return this.authSchemes.get(schemeId);
	}
};

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/noAuth.js
var NoAuthSigner = class {
	async sign(httpRequest, identity, signingProperties) {
		return httpRequest;
	}
};

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/memoizeIdentityProvider.js
const createIsIdentityExpiredFunction = (expirationMs) => function isIdentityExpired$1(identity) {
	return doesIdentityRequireRefresh(identity) && identity.expiration.getTime() - Date.now() < expirationMs;
};
const EXPIRATION_MS = 3e5;
const isIdentityExpired = createIsIdentityExpiredFunction(EXPIRATION_MS);
const doesIdentityRequireRefresh = (identity) => identity.expiration !== void 0;
const memoizeIdentityProvider = (provider, isExpired, requiresRefresh) => {
	if (provider === void 0) return;
	const normalizedProvider = typeof provider !== "function" ? async () => Promise.resolve(provider) : provider;
	let resolved;
	let pending;
	let hasResult;
	let isConstant = false;
	const coalesceProvider = async (options) => {
		if (!pending) pending = normalizedProvider(options);
		try {
			resolved = await pending;
			hasResult = true;
			isConstant = false;
		} finally {
			pending = void 0;
		}
		return resolved;
	};
	if (isExpired === void 0) return async (options) => {
		if (!hasResult || options?.forceRefresh) resolved = await coalesceProvider(options);
		return resolved;
	};
	return async (options) => {
		if (!hasResult || options?.forceRefresh) resolved = await coalesceProvider(options);
		if (isConstant) return resolved;
		if (!requiresRefresh(resolved)) {
			isConstant = true;
			return resolved;
		}
		if (isExpired(resolved)) {
			await coalesceProvider(options);
			return resolved;
		}
		return resolved;
	};
};

//#endregion
//#region node_modules/@aws-sdk/middleware-user-agent/dist-es/configurations.js
const DEFAULT_UA_APP_ID = void 0;
function isValidUserAgentAppId(appId) {
	if (appId === void 0) return true;
	return typeof appId === "string" && appId.length <= 50;
}
function resolveUserAgentConfig(input) {
	const normalizedAppIdProvider = normalizeProvider(input.userAgentAppId ?? DEFAULT_UA_APP_ID);
	const { customUserAgent } = input;
	return Object.assign(input, {
		customUserAgent: typeof customUserAgent === "string" ? [[customUserAgent]] : customUserAgent,
		userAgentAppId: async () => {
			const appId = await normalizedAppIdProvider();
			if (!isValidUserAgentAppId(appId)) {
				const logger = input.logger?.constructor?.name === "NoOpLogger" || !input.logger ? console : input.logger;
				if (typeof appId !== "string") logger?.warn("userAgentAppId must be a string or undefined.");
				else if (appId.length > 50) logger?.warn("The provided userAgentAppId exceeds the maximum length of 50 characters.");
			}
			return appId;
		}
	});
}

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/cache/EndpointCache.js
var EndpointCache = class {
	capacity;
	data = /* @__PURE__ */ new Map();
	parameters = [];
	constructor({ size, params }) {
		this.capacity = size ?? 50;
		if (params) this.parameters = params;
	}
	get(endpointParams, resolver) {
		const key = this.hash(endpointParams);
		if (key === false) return resolver();
		if (!this.data.has(key)) {
			if (this.data.size > this.capacity + 10) {
				const keys = this.data.keys();
				let i$1 = 0;
				while (true) {
					const { value, done } = keys.next();
					this.data.delete(value);
					if (done || ++i$1 > 10) break;
				}
			}
			this.data.set(key, resolver());
		}
		return this.data.get(key);
	}
	size() {
		return this.data.size;
	}
	hash(endpointParams) {
		let buffer = "";
		const { parameters } = this;
		if (parameters.length === 0) return false;
		for (const param of parameters) {
			const val = String(endpointParams[param] ?? "");
			if (val.includes("|;")) return false;
			buffer += val + "|;";
		}
		return buffer;
	}
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/isIpAddress.js
const IP_V4_REGEX = /* @__PURE__ */ new RegExp(`^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}$`);
const isIpAddress = (value) => IP_V4_REGEX.test(value) || value.startsWith("[") && value.endsWith("]");

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/isValidHostLabel.js
const VALID_HOST_LABEL_REGEX = /* @__PURE__ */ new RegExp(`^(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63}$`);
const isValidHostLabel = (value, allowSubDomains = false) => {
	if (!allowSubDomains) return VALID_HOST_LABEL_REGEX.test(value);
	const labels = value.split(".");
	for (const label of labels) if (!isValidHostLabel(label)) return false;
	return true;
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/customEndpointFunctions.js
const customEndpointFunctions = {};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/debug/debugId.js
const debugId = "endpoints";

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/debug/toDebugString.js
function toDebugString(input) {
	if (typeof input !== "object" || input == null) return input;
	if ("ref" in input) return `$${toDebugString(input.ref)}`;
	if ("fn" in input) return `${input.fn}(${(input.argv || []).map(toDebugString).join(", ")})`;
	return JSON.stringify(input, null, 2);
}

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/types/EndpointError.js
var EndpointError = class extends Error {
	constructor(message) {
		super(message);
		this.name = "EndpointError";
	}
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/booleanEquals.js
const booleanEquals = (value1, value2) => value1 === value2;

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/getAttrPathList.js
const getAttrPathList = (path) => {
	const parts = path.split(".");
	const pathList = [];
	for (const part of parts) {
		const squareBracketIndex = part.indexOf("[");
		if (squareBracketIndex !== -1) {
			if (part.indexOf("]") !== part.length - 1) throw new EndpointError(`Path: '${path}' does not end with ']'`);
			const arrayIndex = part.slice(squareBracketIndex + 1, -1);
			if (Number.isNaN(parseInt(arrayIndex))) throw new EndpointError(`Invalid array index: '${arrayIndex}' in path: '${path}'`);
			if (squareBracketIndex !== 0) pathList.push(part.slice(0, squareBracketIndex));
			pathList.push(arrayIndex);
		} else pathList.push(part);
	}
	return pathList;
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/getAttr.js
const getAttr = (value, path) => getAttrPathList(path).reduce((acc, index) => {
	if (typeof acc !== "object") throw new EndpointError(`Index '${index}' in '${path}' not found in '${JSON.stringify(value)}'`);
	else if (Array.isArray(acc)) return acc[parseInt(index)];
	return acc[index];
}, value);

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/isSet.js
const isSet = (value) => value != null;

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/not.js
const not = (value) => !value;

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/parseURL.js
const DEFAULT_PORTS = {
	[EndpointURLScheme.HTTP]: 80,
	[EndpointURLScheme.HTTPS]: 443
};
const parseURL = (value) => {
	const whatwgURL = (() => {
		try {
			if (value instanceof URL) return value;
			if (typeof value === "object" && "hostname" in value) {
				const { hostname: hostname$1, port, protocol: protocol$1 = "", path = "", query = {} } = value;
				const url = new URL(`${protocol$1}//${hostname$1}${port ? `:${port}` : ""}${path}`);
				url.search = Object.entries(query).map(([k$1, v$1]) => `${k$1}=${v$1}`).join("&");
				return url;
			}
			return new URL(value);
		} catch (error) {
			return null;
		}
	})();
	if (!whatwgURL) {
		console.error(`Unable to parse ${JSON.stringify(value)} as a whatwg URL.`);
		return null;
	}
	const urlString = whatwgURL.href;
	const { host, hostname, pathname, protocol, search } = whatwgURL;
	if (search) return null;
	const scheme = protocol.slice(0, -1);
	if (!Object.values(EndpointURLScheme).includes(scheme)) return null;
	const isIp = isIpAddress(hostname);
	return {
		scheme,
		authority: `${host}${urlString.includes(`${host}:${DEFAULT_PORTS[scheme]}`) || typeof value === "string" && value.includes(`${host}:${DEFAULT_PORTS[scheme]}`) ? `:${DEFAULT_PORTS[scheme]}` : ``}`,
		path: pathname,
		normalizedPath: pathname.endsWith("/") ? pathname : `${pathname}/`,
		isIp
	};
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/stringEquals.js
const stringEquals = (value1, value2) => value1 === value2;

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/substring.js
const substring = (input, start, stop, reverse) => {
	if (start >= stop || input.length < stop) return null;
	if (!reverse) return input.substring(start, stop);
	return input.substring(input.length - stop, input.length - start);
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/lib/uriEncode.js
const uriEncode = (value) => encodeURIComponent(value).replace(/[!*'()]/g, (c$1) => `%${c$1.charCodeAt(0).toString(16).toUpperCase()}`);

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/endpointFunctions.js
const endpointFunctions = {
	booleanEquals,
	getAttr,
	isSet,
	isValidHostLabel,
	not,
	parseURL,
	stringEquals,
	substring,
	uriEncode
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/evaluateTemplate.js
const evaluateTemplate = (template, options) => {
	const evaluatedTemplateArr = [];
	const templateContext = {
		...options.endpointParams,
		...options.referenceRecord
	};
	let currentIndex = 0;
	while (currentIndex < template.length) {
		const openingBraceIndex = template.indexOf("{", currentIndex);
		if (openingBraceIndex === -1) {
			evaluatedTemplateArr.push(template.slice(currentIndex));
			break;
		}
		evaluatedTemplateArr.push(template.slice(currentIndex, openingBraceIndex));
		const closingBraceIndex = template.indexOf("}", openingBraceIndex);
		if (closingBraceIndex === -1) {
			evaluatedTemplateArr.push(template.slice(openingBraceIndex));
			break;
		}
		if (template[openingBraceIndex + 1] === "{" && template[closingBraceIndex + 1] === "}") {
			evaluatedTemplateArr.push(template.slice(openingBraceIndex + 1, closingBraceIndex));
			currentIndex = closingBraceIndex + 2;
		}
		const parameterName = template.substring(openingBraceIndex + 1, closingBraceIndex);
		if (parameterName.includes("#")) {
			const [refName, attrName] = parameterName.split("#");
			evaluatedTemplateArr.push(getAttr(templateContext[refName], attrName));
		} else evaluatedTemplateArr.push(templateContext[parameterName]);
		currentIndex = closingBraceIndex + 1;
	}
	return evaluatedTemplateArr.join("");
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/getReferenceValue.js
const getReferenceValue = ({ ref }, options) => {
	return {
		...options.endpointParams,
		...options.referenceRecord
	}[ref];
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/evaluateExpression.js
const evaluateExpression = (obj, keyName, options) => {
	if (typeof obj === "string") return evaluateTemplate(obj, options);
	else if (obj["fn"]) return group$2.callFunction(obj, options);
	else if (obj["ref"]) return getReferenceValue(obj, options);
	throw new EndpointError(`'${keyName}': ${String(obj)} is not a string, function or reference.`);
};
const callFunction = ({ fn, argv }, options) => {
	const evaluatedArgs = argv.map((arg) => ["boolean", "number"].includes(typeof arg) ? arg : group$2.evaluateExpression(arg, "arg", options));
	const fnSegments = fn.split(".");
	if (fnSegments[0] in customEndpointFunctions && fnSegments[1] != null) return customEndpointFunctions[fnSegments[0]][fnSegments[1]](...evaluatedArgs);
	return endpointFunctions[fn](...evaluatedArgs);
};
const group$2 = {
	evaluateExpression,
	callFunction
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/evaluateCondition.js
const evaluateCondition = ({ assign, ...fnArgs }, options) => {
	if (assign && assign in options.referenceRecord) throw new EndpointError(`'${assign}' is already defined in Reference Record.`);
	const value = callFunction(fnArgs, options);
	options.logger?.debug?.(`${debugId} evaluateCondition: ${toDebugString(fnArgs)} = ${toDebugString(value)}`);
	return {
		result: value === "" ? true : !!value,
		...assign != null && { toAssign: {
			name: assign,
			value
		} }
	};
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/evaluateConditions.js
const evaluateConditions = (conditions = [], options) => {
	const conditionsReferenceRecord = {};
	for (const condition of conditions) {
		const { result, toAssign } = evaluateCondition(condition, {
			...options,
			referenceRecord: {
				...options.referenceRecord,
				...conditionsReferenceRecord
			}
		});
		if (!result) return { result };
		if (toAssign) {
			conditionsReferenceRecord[toAssign.name] = toAssign.value;
			options.logger?.debug?.(`${debugId} assign: ${toAssign.name} := ${toDebugString(toAssign.value)}`);
		}
	}
	return {
		result: true,
		referenceRecord: conditionsReferenceRecord
	};
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointHeaders.js
const getEndpointHeaders = (headers, options) => Object.entries(headers).reduce((acc, [headerKey, headerVal]) => ({
	...acc,
	[headerKey]: headerVal.map((headerValEntry) => {
		const processedExpr = evaluateExpression(headerValEntry, "Header value entry", options);
		if (typeof processedExpr !== "string") throw new EndpointError(`Header '${headerKey}' value '${processedExpr}' is not a string`);
		return processedExpr;
	})
}), {});

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointProperties.js
const getEndpointProperties = (properties, options) => Object.entries(properties).reduce((acc, [propertyKey, propertyVal]) => ({
	...acc,
	[propertyKey]: group$1.getEndpointProperty(propertyVal, options)
}), {});
const getEndpointProperty = (property, options) => {
	if (Array.isArray(property)) return property.map((propertyEntry) => getEndpointProperty(propertyEntry, options));
	switch (typeof property) {
		case "string": return evaluateTemplate(property, options);
		case "object":
			if (property === null) throw new EndpointError(`Unexpected endpoint property: ${property}`);
			return group$1.getEndpointProperties(property, options);
		case "boolean": return property;
		default: throw new EndpointError(`Unexpected endpoint property type: ${typeof property}`);
	}
};
const group$1 = {
	getEndpointProperty,
	getEndpointProperties
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointUrl.js
const getEndpointUrl = (endpointUrl, options) => {
	const expression = evaluateExpression(endpointUrl, "Endpoint URL", options);
	if (typeof expression === "string") try {
		return new URL(expression);
	} catch (error) {
		console.error(`Failed to construct URL with ${expression}`, error);
		throw error;
	}
	throw new EndpointError(`Endpoint URL must be a string, got ${typeof expression}`);
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/evaluateEndpointRule.js
const evaluateEndpointRule = (endpointRule, options) => {
	const { conditions, endpoint } = endpointRule;
	const { result, referenceRecord } = evaluateConditions(conditions, options);
	if (!result) return;
	const endpointRuleOptions = {
		...options,
		referenceRecord: {
			...options.referenceRecord,
			...referenceRecord
		}
	};
	const { url, properties, headers } = endpoint;
	options.logger?.debug?.(`${debugId} Resolving endpoint from template: ${toDebugString(endpoint)}`);
	return {
		...headers != void 0 && { headers: getEndpointHeaders(headers, endpointRuleOptions) },
		...properties != void 0 && { properties: getEndpointProperties(properties, endpointRuleOptions) },
		url: getEndpointUrl(url, endpointRuleOptions)
	};
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/evaluateErrorRule.js
const evaluateErrorRule = (errorRule, options) => {
	const { conditions, error } = errorRule;
	const { result, referenceRecord } = evaluateConditions(conditions, options);
	if (!result) return;
	throw new EndpointError(evaluateExpression(error, "Error", {
		...options,
		referenceRecord: {
			...options.referenceRecord,
			...referenceRecord
		}
	}));
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/utils/evaluateRules.js
const evaluateRules = (rules, options) => {
	for (const rule of rules) if (rule.type === "endpoint") {
		const endpointOrUndefined = evaluateEndpointRule(rule, options);
		if (endpointOrUndefined) return endpointOrUndefined;
	} else if (rule.type === "error") evaluateErrorRule(rule, options);
	else if (rule.type === "tree") {
		const endpointOrUndefined = group.evaluateTreeRule(rule, options);
		if (endpointOrUndefined) return endpointOrUndefined;
	} else throw new EndpointError(`Unknown endpoint rule: ${rule}`);
	throw new EndpointError(`Rules evaluation failed`);
};
const evaluateTreeRule = (treeRule, options) => {
	const { conditions, rules } = treeRule;
	const { result, referenceRecord } = evaluateConditions(conditions, options);
	if (!result) return;
	return group.evaluateRules(rules, {
		...options,
		referenceRecord: {
			...options.referenceRecord,
			...referenceRecord
		}
	});
};
const group = {
	evaluateRules,
	evaluateTreeRule
};

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-es/resolveEndpoint.js
const resolveEndpoint = (ruleSetObject, options) => {
	const { endpointParams, logger } = options;
	const { parameters, rules } = ruleSetObject;
	options.logger?.debug?.(`${debugId} Initial EndpointParams: ${toDebugString(endpointParams)}`);
	const paramsWithDefault = Object.entries(parameters).filter(([, v$1]) => v$1.default != null).map(([k$1, v$1]) => [k$1, v$1.default]);
	if (paramsWithDefault.length > 0) for (const [paramKey, paramDefaultValue] of paramsWithDefault) endpointParams[paramKey] = endpointParams[paramKey] ?? paramDefaultValue;
	const requiredParams = Object.entries(parameters).filter(([, v$1]) => v$1.required).map(([k$1]) => k$1);
	for (const requiredParam of requiredParams) if (endpointParams[requiredParam] == null) throw new EndpointError(`Missing required parameter: '${requiredParam}'`);
	const endpoint = evaluateRules(rules, {
		endpointParams,
		logger,
		referenceRecord: {}
	});
	options.logger?.debug?.(`${debugId} Resolved endpoint: ${toDebugString(endpoint)}`);
	return endpoint;
};

//#endregion
//#region node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/isVirtualHostableS3Bucket.js
const isVirtualHostableS3Bucket = (value, allowSubDomains = false) => {
	if (allowSubDomains) {
		for (const label of value.split(".")) if (!isVirtualHostableS3Bucket(label)) return false;
		return true;
	}
	if (!isValidHostLabel(value)) return false;
	if (value.length < 3 || value.length > 63) return false;
	if (value !== value.toLowerCase()) return false;
	if (isIpAddress(value)) return false;
	return true;
};

//#endregion
//#region node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/parseArn.js
const ARN_DELIMITER = ":";
const RESOURCE_DELIMITER = "/";
const parseArn = (value) => {
	const segments = value.split(ARN_DELIMITER);
	if (segments.length < 6) return null;
	const [arn, partition$1, service, region, accountId, ...resourcePath] = segments;
	if (arn !== "arn" || partition$1 === "" || service === "" || resourcePath.join(ARN_DELIMITER) === "") return null;
	return {
		partition: partition$1,
		service,
		region,
		accountId,
		resourceId: resourcePath.map((resource) => resource.split(RESOURCE_DELIMITER)).flat()
	};
};

//#endregion
//#region node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/partitions.json
var partitions_default = {
	partitions: [
		{
			"id": "aws",
			"outputs": {
				"dnsSuffix": "amazonaws.com",
				"dualStackDnsSuffix": "api.aws",
				"implicitGlobalRegion": "us-east-1",
				"name": "aws",
				"supportsDualStack": true,
				"supportsFIPS": true
			},
			"regionRegex": "^(us|eu|ap|sa|ca|me|af|il|mx)\\-\\w+\\-\\d+$",
			"regions": {
				"af-south-1": { "description": "Africa (Cape Town)" },
				"ap-east-1": { "description": "Asia Pacific (Hong Kong)" },
				"ap-east-2": { "description": "Asia Pacific (Taipei)" },
				"ap-northeast-1": { "description": "Asia Pacific (Tokyo)" },
				"ap-northeast-2": { "description": "Asia Pacific (Seoul)" },
				"ap-northeast-3": { "description": "Asia Pacific (Osaka)" },
				"ap-south-1": { "description": "Asia Pacific (Mumbai)" },
				"ap-south-2": { "description": "Asia Pacific (Hyderabad)" },
				"ap-southeast-1": { "description": "Asia Pacific (Singapore)" },
				"ap-southeast-2": { "description": "Asia Pacific (Sydney)" },
				"ap-southeast-3": { "description": "Asia Pacific (Jakarta)" },
				"ap-southeast-4": { "description": "Asia Pacific (Melbourne)" },
				"ap-southeast-5": { "description": "Asia Pacific (Malaysia)" },
				"ap-southeast-6": { "description": "Asia Pacific (New Zealand)" },
				"ap-southeast-7": { "description": "Asia Pacific (Thailand)" },
				"aws-global": { "description": "aws global region" },
				"ca-central-1": { "description": "Canada (Central)" },
				"ca-west-1": { "description": "Canada West (Calgary)" },
				"eu-central-1": { "description": "Europe (Frankfurt)" },
				"eu-central-2": { "description": "Europe (Zurich)" },
				"eu-north-1": { "description": "Europe (Stockholm)" },
				"eu-south-1": { "description": "Europe (Milan)" },
				"eu-south-2": { "description": "Europe (Spain)" },
				"eu-west-1": { "description": "Europe (Ireland)" },
				"eu-west-2": { "description": "Europe (London)" },
				"eu-west-3": { "description": "Europe (Paris)" },
				"il-central-1": { "description": "Israel (Tel Aviv)" },
				"me-central-1": { "description": "Middle East (UAE)" },
				"me-south-1": { "description": "Middle East (Bahrain)" },
				"mx-central-1": { "description": "Mexico (Central)" },
				"sa-east-1": { "description": "South America (Sao Paulo)" },
				"us-east-1": { "description": "US East (N. Virginia)" },
				"us-east-2": { "description": "US East (Ohio)" },
				"us-west-1": { "description": "US West (N. California)" },
				"us-west-2": { "description": "US West (Oregon)" }
			}
		},
		{
			"id": "aws-cn",
			"outputs": {
				"dnsSuffix": "amazonaws.com.cn",
				"dualStackDnsSuffix": "api.amazonwebservices.com.cn",
				"implicitGlobalRegion": "cn-northwest-1",
				"name": "aws-cn",
				"supportsDualStack": true,
				"supportsFIPS": true
			},
			"regionRegex": "^cn\\-\\w+\\-\\d+$",
			"regions": {
				"aws-cn-global": { "description": "aws-cn global region" },
				"cn-north-1": { "description": "China (Beijing)" },
				"cn-northwest-1": { "description": "China (Ningxia)" }
			}
		},
		{
			"id": "aws-eusc",
			"outputs": {
				"dnsSuffix": "amazonaws.eu",
				"dualStackDnsSuffix": "api.amazonwebservices.eu",
				"implicitGlobalRegion": "eusc-de-east-1",
				"name": "aws-eusc",
				"supportsDualStack": true,
				"supportsFIPS": true
			},
			"regionRegex": "^eusc\\-(de)\\-\\w+\\-\\d+$",
			"regions": { "eusc-de-east-1": { "description": "EU (Germany)" } }
		},
		{
			"id": "aws-iso",
			"outputs": {
				"dnsSuffix": "c2s.ic.gov",
				"dualStackDnsSuffix": "api.aws.ic.gov",
				"implicitGlobalRegion": "us-iso-east-1",
				"name": "aws-iso",
				"supportsDualStack": true,
				"supportsFIPS": true
			},
			"regionRegex": "^us\\-iso\\-\\w+\\-\\d+$",
			"regions": {
				"aws-iso-global": { "description": "aws-iso global region" },
				"us-iso-east-1": { "description": "US ISO East" },
				"us-iso-west-1": { "description": "US ISO WEST" }
			}
		},
		{
			"id": "aws-iso-b",
			"outputs": {
				"dnsSuffix": "sc2s.sgov.gov",
				"dualStackDnsSuffix": "api.aws.scloud",
				"implicitGlobalRegion": "us-isob-east-1",
				"name": "aws-iso-b",
				"supportsDualStack": true,
				"supportsFIPS": true
			},
			"regionRegex": "^us\\-isob\\-\\w+\\-\\d+$",
			"regions": {
				"aws-iso-b-global": { "description": "aws-iso-b global region" },
				"us-isob-east-1": { "description": "US ISOB East (Ohio)" },
				"us-isob-west-1": { "description": "US ISOB West" }
			}
		},
		{
			"id": "aws-iso-e",
			"outputs": {
				"dnsSuffix": "cloud.adc-e.uk",
				"dualStackDnsSuffix": "api.cloud-aws.adc-e.uk",
				"implicitGlobalRegion": "eu-isoe-west-1",
				"name": "aws-iso-e",
				"supportsDualStack": true,
				"supportsFIPS": true
			},
			"regionRegex": "^eu\\-isoe\\-\\w+\\-\\d+$",
			"regions": {
				"aws-iso-e-global": { "description": "aws-iso-e global region" },
				"eu-isoe-west-1": { "description": "EU ISOE West" }
			}
		},
		{
			"id": "aws-iso-f",
			"outputs": {
				"dnsSuffix": "csp.hci.ic.gov",
				"dualStackDnsSuffix": "api.aws.hci.ic.gov",
				"implicitGlobalRegion": "us-isof-south-1",
				"name": "aws-iso-f",
				"supportsDualStack": true,
				"supportsFIPS": true
			},
			"regionRegex": "^us\\-isof\\-\\w+\\-\\d+$",
			"regions": {
				"aws-iso-f-global": { "description": "aws-iso-f global region" },
				"us-isof-east-1": { "description": "US ISOF EAST" },
				"us-isof-south-1": { "description": "US ISOF SOUTH" }
			}
		},
		{
			"id": "aws-us-gov",
			"outputs": {
				"dnsSuffix": "amazonaws.com",
				"dualStackDnsSuffix": "api.aws",
				"implicitGlobalRegion": "us-gov-west-1",
				"name": "aws-us-gov",
				"supportsDualStack": true,
				"supportsFIPS": true
			},
			"regionRegex": "^us\\-gov\\-\\w+\\-\\d+$",
			"regions": {
				"aws-us-gov-global": { "description": "aws-us-gov global region" },
				"us-gov-east-1": { "description": "AWS GovCloud (US-East)" },
				"us-gov-west-1": { "description": "AWS GovCloud (US-West)" }
			}
		}
	],
	version: "1.1"
};

//#endregion
//#region node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/partition.js
let selectedPartitionsInfo = partitions_default;
let selectedUserAgentPrefix = "";
const partition = (value) => {
	const { partitions: partitions$1 } = selectedPartitionsInfo;
	for (const partition$1 of partitions$1) {
		const { regions, outputs } = partition$1;
		for (const [region, regionData] of Object.entries(regions)) if (region === value) return {
			...outputs,
			...regionData
		};
	}
	for (const partition$1 of partitions$1) {
		const { regionRegex, outputs } = partition$1;
		if (new RegExp(regionRegex).test(value)) return { ...outputs };
	}
	const DEFAULT_PARTITION = partitions$1.find((partition$1) => partition$1.id === "aws");
	if (!DEFAULT_PARTITION) throw new Error("Provided region was not found in the partition array or regex, and default partition with id 'aws' doesn't exist.");
	return { ...DEFAULT_PARTITION.outputs };
};
const getUserAgentPrefix = () => selectedUserAgentPrefix;

//#endregion
//#region node_modules/@aws-sdk/util-endpoints/dist-es/aws.js
const awsEndpointFunctions = {
	isVirtualHostableS3Bucket,
	parseArn,
	partition
};
customEndpointFunctions.aws = awsEndpointFunctions;

//#endregion
//#region node_modules/@smithy/querystring-parser/dist-es/index.js
function parseQueryString(querystring) {
	const query = {};
	querystring = querystring.replace(/^\?/, "");
	if (querystring) for (const pair of querystring.split("&")) {
		let [key, value = null] = pair.split("=");
		key = decodeURIComponent(key);
		if (value) value = decodeURIComponent(value);
		if (!(key in query)) query[key] = value;
		else if (Array.isArray(query[key])) query[key].push(value);
		else query[key] = [query[key], value];
	}
	return query;
}

//#endregion
//#region node_modules/@smithy/url-parser/dist-es/index.js
const parseUrl = (url) => {
	if (typeof url === "string") return parseUrl(new URL(url));
	const { hostname, pathname, port, protocol, search } = url;
	let query;
	if (search) query = parseQueryString(search);
	return {
		hostname,
		port: port ? parseInt(port) : void 0,
		protocol,
		path: pathname,
		query
	};
};

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js
function setCredentialFeature(credentials, feature, value) {
	if (!credentials.$source) credentials.$source = {};
	credentials.$source[feature] = value;
	return credentials;
}

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js
function setFeature(context, feature, value) {
	if (!context.__aws_sdk_context) context.__aws_sdk_context = { features: {} };
	else if (!context.__aws_sdk_context.features) context.__aws_sdk_context.features = {};
	context.__aws_sdk_context.features[feature] = value;
}

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getDateHeader.js
const getDateHeader = (response) => HttpResponse.isInstance(response) ? response.headers?.date ?? response.headers?.Date : void 0;

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.js
const getSkewCorrectedDate = (systemClockOffset) => new Date(Date.now() + systemClockOffset);

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/isClockSkewed.js
const isClockSkewed = (clockTime, systemClockOffset) => Math.abs(getSkewCorrectedDate(systemClockOffset).getTime() - clockTime) >= 3e5;

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.js
const getUpdatedSystemClockOffset = (clockTime, currentSystemClockOffset) => {
	const clockTimeInMs = Date.parse(clockTime);
	if (isClockSkewed(clockTimeInMs, currentSystemClockOffset)) return clockTimeInMs - Date.now();
	return currentSystemClockOffset;
};

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js
const throwSigningPropertyError = (name, property) => {
	if (!property) throw new Error(`Property \`${name}\` is not resolved for AWS SDK SigV4Auth`);
	return property;
};
const validateSigningProperties = async (signingProperties) => {
	const context = throwSigningPropertyError("context", signingProperties.context);
	const config = throwSigningPropertyError("config", signingProperties.config);
	const authScheme = context.endpointV2?.properties?.authSchemes?.[0];
	return {
		config,
		signer: await throwSigningPropertyError("signer", config.signer)(authScheme),
		signingRegion: signingProperties?.signingRegion,
		signingRegionSet: signingProperties?.signingRegionSet,
		signingName: signingProperties?.signingName
	};
};
var AwsSdkSigV4Signer = class {
	async sign(httpRequest, identity, signingProperties) {
		if (!HttpRequest.isInstance(httpRequest)) throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
		const validatedProps = await validateSigningProperties(signingProperties);
		const { config, signer } = validatedProps;
		let { signingRegion, signingName } = validatedProps;
		const handlerExecutionContext = signingProperties.context;
		if (handlerExecutionContext?.authSchemes?.length ?? false) {
			const [first, second] = handlerExecutionContext.authSchemes;
			if (first?.name === "sigv4a" && second?.name === "sigv4") {
				signingRegion = second?.signingRegion ?? signingRegion;
				signingName = second?.signingName ?? signingName;
			}
		}
		return await signer.sign(httpRequest, {
			signingDate: getSkewCorrectedDate(config.systemClockOffset),
			signingRegion,
			signingService: signingName
		});
	}
	errorHandler(signingProperties) {
		return (error) => {
			const serverTime = error.ServerTime ?? getDateHeader(error.$response);
			if (serverTime) {
				const config = throwSigningPropertyError("config", signingProperties.config);
				const initialSystemClockOffset = config.systemClockOffset;
				config.systemClockOffset = getUpdatedSystemClockOffset(serverTime, config.systemClockOffset);
				if (config.systemClockOffset !== initialSystemClockOffset && error.$metadata) error.$metadata.clockSkewCorrected = true;
			}
			throw error;
		};
	}
	successHandler(httpResponse, signingProperties) {
		const dateHeader = getDateHeader(httpResponse);
		if (dateHeader) {
			const config = throwSigningPropertyError("config", signingProperties.config);
			config.systemClockOffset = getUpdatedSystemClockOffset(dateHeader, config.systemClockOffset);
		}
	}
};

//#endregion
//#region node_modules/@smithy/property-provider/dist-es/memoize.js
const memoize = (provider, isExpired, requiresRefresh) => {
	let resolved;
	let pending;
	let hasResult;
	let isConstant = false;
	const coalesceProvider = async () => {
		if (!pending) pending = provider();
		try {
			resolved = await pending;
			hasResult = true;
			isConstant = false;
		} finally {
			pending = void 0;
		}
		return resolved;
	};
	if (isExpired === void 0) return async (options) => {
		if (!hasResult || options?.forceRefresh) resolved = await coalesceProvider();
		return resolved;
	};
	return async (options) => {
		if (!hasResult || options?.forceRefresh) resolved = await coalesceProvider();
		if (isConstant) return resolved;
		if (requiresRefresh && !requiresRefresh(resolved)) {
			isConstant = true;
			return resolved;
		}
		if (isExpired(resolved)) {
			await coalesceProvider();
			return resolved;
		}
		return resolved;
	};
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/constants.js
const ALGORITHM_QUERY_PARAM = "X-Amz-Algorithm";
const CREDENTIAL_QUERY_PARAM = "X-Amz-Credential";
const AMZ_DATE_QUERY_PARAM = "X-Amz-Date";
const SIGNED_HEADERS_QUERY_PARAM = "X-Amz-SignedHeaders";
const EXPIRES_QUERY_PARAM = "X-Amz-Expires";
const SIGNATURE_QUERY_PARAM = "X-Amz-Signature";
const TOKEN_QUERY_PARAM = "X-Amz-Security-Token";
const AUTH_HEADER = "authorization";
const AMZ_DATE_HEADER = AMZ_DATE_QUERY_PARAM.toLowerCase();
const DATE_HEADER = "date";
const GENERATED_HEADERS = [
	AUTH_HEADER,
	AMZ_DATE_HEADER,
	DATE_HEADER
];
const SIGNATURE_HEADER = SIGNATURE_QUERY_PARAM.toLowerCase();
const SHA256_HEADER = "x-amz-content-sha256";
const TOKEN_HEADER = TOKEN_QUERY_PARAM.toLowerCase();
const ALWAYS_UNSIGNABLE_HEADERS = {
	authorization: true,
	"cache-control": true,
	connection: true,
	expect: true,
	from: true,
	"keep-alive": true,
	"max-forwards": true,
	pragma: true,
	referer: true,
	te: true,
	trailer: true,
	"transfer-encoding": true,
	upgrade: true,
	"user-agent": true,
	"x-amzn-trace-id": true
};
const PROXY_HEADER_PATTERN = /^proxy-/;
const SEC_HEADER_PATTERN = /^sec-/;
const ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256";
const EVENT_ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256-PAYLOAD";
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
const MAX_CACHE_SIZE = 50;
const KEY_TYPE_IDENTIFIER = "aws4_request";
const MAX_PRESIGNED_TTL = 3600 * 24 * 7;

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/credentialDerivation.js
init_dist_es();
const signingKeyCache = {};
const cacheQueue = [];
const createScope = (shortDate, region, service) => `${shortDate}/${region}/${service}/${KEY_TYPE_IDENTIFIER}`;
const getSigningKey = async (sha256Constructor, credentials, shortDate, region, service) => {
	const cacheKey = `${shortDate}:${region}:${service}:${toHex(await hmac(sha256Constructor, credentials.secretAccessKey, credentials.accessKeyId))}:${credentials.sessionToken}`;
	if (cacheKey in signingKeyCache) return signingKeyCache[cacheKey];
	cacheQueue.push(cacheKey);
	while (cacheQueue.length > MAX_CACHE_SIZE) delete signingKeyCache[cacheQueue.shift()];
	let key = `AWS4${credentials.secretAccessKey}`;
	for (const signable of [
		shortDate,
		region,
		service,
		KEY_TYPE_IDENTIFIER
	]) key = await hmac(sha256Constructor, key, signable);
	return signingKeyCache[cacheKey] = key;
};
const hmac = (ctor, secret, data) => {
	const hash = new ctor(secret);
	hash.update(toUint8Array(data));
	return hash.digest();
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/getCanonicalHeaders.js
const getCanonicalHeaders = ({ headers }, unsignableHeaders, signableHeaders) => {
	const canonical = {};
	for (const headerName of Object.keys(headers).sort()) {
		if (headers[headerName] == void 0) continue;
		const canonicalHeaderName = headerName.toLowerCase();
		if (canonicalHeaderName in ALWAYS_UNSIGNABLE_HEADERS || unsignableHeaders?.has(canonicalHeaderName) || PROXY_HEADER_PATTERN.test(canonicalHeaderName) || SEC_HEADER_PATTERN.test(canonicalHeaderName)) {
			if (!signableHeaders || signableHeaders && !signableHeaders.has(canonicalHeaderName)) continue;
		}
		canonical[canonicalHeaderName] = headers[headerName].trim().replace(/\s+/g, " ");
	}
	return canonical;
};

//#endregion
//#region node_modules/@smithy/is-array-buffer/dist-es/index.js
const isArrayBuffer = (arg) => typeof ArrayBuffer === "function" && arg instanceof ArrayBuffer || Object.prototype.toString.call(arg) === "[object ArrayBuffer]";

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/getPayloadHash.js
init_dist_es();
const getPayloadHash = async ({ headers, body }, hashConstructor) => {
	for (const headerName of Object.keys(headers)) if (headerName.toLowerCase() === SHA256_HEADER) return headers[headerName];
	if (body == void 0) return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	else if (typeof body === "string" || ArrayBuffer.isView(body) || isArrayBuffer(body)) {
		const hashCtor = new hashConstructor();
		hashCtor.update(toUint8Array(body));
		return toHex(await hashCtor.digest());
	}
	return UNSIGNED_PAYLOAD;
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/HeaderFormatter.js
init_dist_es();
var HeaderFormatter = class {
	format(headers) {
		const chunks = [];
		for (const headerName of Object.keys(headers)) {
			const bytes = fromUtf8$2(headerName);
			chunks.push(Uint8Array.from([bytes.byteLength]), bytes, this.formatHeaderValue(headers[headerName]));
		}
		const out = new Uint8Array(chunks.reduce((carry, bytes) => carry + bytes.byteLength, 0));
		let position = 0;
		for (const chunk of chunks) {
			out.set(chunk, position);
			position += chunk.byteLength;
		}
		return out;
	}
	formatHeaderValue(header) {
		switch (header.type) {
			case "boolean": return Uint8Array.from([header.value ? 0 : 1]);
			case "byte": return Uint8Array.from([2, header.value]);
			case "short":
				const shortView = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(3));
				shortView.setUint8(0, 3);
				shortView.setInt16(1, header.value, false);
				return new Uint8Array(shortView.buffer);
			case "integer":
				const intView = /* @__PURE__ */ new DataView(/* @__PURE__ */ new ArrayBuffer(5));
				intView.setUint8(0, 4);
				intView.setInt32(1, header.value, false);
				return new Uint8Array(intView.buffer);
			case "long":
				const longBytes = new Uint8Array(9);
				longBytes[0] = 5;
				longBytes.set(header.value.bytes, 1);
				return longBytes;
			case "binary":
				const binView = new DataView(new ArrayBuffer(3 + header.value.byteLength));
				binView.setUint8(0, 6);
				binView.setUint16(1, header.value.byteLength, false);
				const binBytes = new Uint8Array(binView.buffer);
				binBytes.set(header.value, 3);
				return binBytes;
			case "string":
				const utf8Bytes = fromUtf8$2(header.value);
				const strView = new DataView(new ArrayBuffer(3 + utf8Bytes.byteLength));
				strView.setUint8(0, 7);
				strView.setUint16(1, utf8Bytes.byteLength, false);
				const strBytes = new Uint8Array(strView.buffer);
				strBytes.set(utf8Bytes, 3);
				return strBytes;
			case "timestamp":
				const tsBytes = new Uint8Array(9);
				tsBytes[0] = 8;
				tsBytes.set(Int64.fromNumber(header.value.valueOf()).bytes, 1);
				return tsBytes;
			case "uuid":
				if (!UUID_PATTERN.test(header.value)) throw new Error(`Invalid UUID received: ${header.value}`);
				const uuidBytes = new Uint8Array(17);
				uuidBytes[0] = 9;
				uuidBytes.set(fromHex(header.value.replace(/\-/g, "")), 1);
				return uuidBytes;
		}
	}
};
var HEADER_VALUE_TYPE;
(function(HEADER_VALUE_TYPE$1) {
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["boolTrue"] = 0] = "boolTrue";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["boolFalse"] = 1] = "boolFalse";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["byte"] = 2] = "byte";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["short"] = 3] = "short";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["integer"] = 4] = "integer";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["long"] = 5] = "long";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["byteArray"] = 6] = "byteArray";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["string"] = 7] = "string";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["timestamp"] = 8] = "timestamp";
	HEADER_VALUE_TYPE$1[HEADER_VALUE_TYPE$1["uuid"] = 9] = "uuid";
})(HEADER_VALUE_TYPE || (HEADER_VALUE_TYPE = {}));
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
var Int64 = class Int64 {
	bytes;
	constructor(bytes) {
		this.bytes = bytes;
		if (bytes.byteLength !== 8) throw new Error("Int64 buffers must be exactly 8 bytes");
	}
	static fromNumber(number) {
		if (number > 0x8000000000000000 || number < -0x8000000000000000) throw new Error(`${number} is too large (or, if negative, too small) to represent as an Int64`);
		const bytes = new Uint8Array(8);
		for (let i$1 = 7, remaining = Math.abs(Math.round(number)); i$1 > -1 && remaining > 0; i$1--, remaining /= 256) bytes[i$1] = remaining;
		if (number < 0) negate(bytes);
		return new Int64(bytes);
	}
	valueOf() {
		const bytes = this.bytes.slice(0);
		const negative = bytes[0] & 128;
		if (negative) negate(bytes);
		return parseInt(toHex(bytes), 16) * (negative ? -1 : 1);
	}
	toString() {
		return String(this.valueOf());
	}
};
function negate(bytes) {
	for (let i$1 = 0; i$1 < 8; i$1++) bytes[i$1] ^= 255;
	for (let i$1 = 7; i$1 > -1; i$1--) {
		bytes[i$1]++;
		if (bytes[i$1] !== 0) break;
	}
}

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/headerUtil.js
const hasHeader = (soughtHeader, headers) => {
	soughtHeader = soughtHeader.toLowerCase();
	for (const headerName of Object.keys(headers)) if (soughtHeader === headerName.toLowerCase()) return true;
	return false;
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/moveHeadersToQuery.js
const moveHeadersToQuery = (request, options = {}) => {
	const { headers, query = {} } = HttpRequest.clone(request);
	for (const name of Object.keys(headers)) {
		const lname = name.toLowerCase();
		if (lname.slice(0, 6) === "x-amz-" && !options.unhoistableHeaders?.has(lname) || options.hoistableHeaders?.has(lname)) {
			query[name] = headers[name];
			delete headers[name];
		}
	}
	return {
		...request,
		headers,
		query
	};
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/prepareRequest.js
const prepareRequest = (request) => {
	request = HttpRequest.clone(request);
	for (const headerName of Object.keys(request.headers)) if (GENERATED_HEADERS.indexOf(headerName.toLowerCase()) > -1) delete request.headers[headerName];
	return request;
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/getCanonicalQuery.js
const getCanonicalQuery = ({ query = {} }) => {
	const keys = [];
	const serialized = {};
	for (const key of Object.keys(query)) {
		if (key.toLowerCase() === SIGNATURE_HEADER) continue;
		const encodedKey = escapeUri(key);
		keys.push(encodedKey);
		const value = query[key];
		if (typeof value === "string") serialized[encodedKey] = `${encodedKey}=${escapeUri(value)}`;
		else if (Array.isArray(value)) serialized[encodedKey] = value.slice(0).reduce((encoded, value$1) => encoded.concat([`${encodedKey}=${escapeUri(value$1)}`]), []).sort().join("&");
	}
	return keys.sort().map((key) => serialized[key]).filter((serialized$1) => serialized$1).join("&");
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/utilDate.js
const iso8601 = (time$1) => toDate(time$1).toISOString().replace(/\.\d{3}Z$/, "Z");
const toDate = (time$1) => {
	if (typeof time$1 === "number") return /* @__PURE__ */ new Date(time$1 * 1e3);
	if (typeof time$1 === "string") {
		if (Number(time$1)) return /* @__PURE__ */ new Date(Number(time$1) * 1e3);
		return new Date(time$1);
	}
	return time$1;
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/SignatureV4Base.js
init_dist_es();
var SignatureV4Base = class {
	service;
	regionProvider;
	credentialProvider;
	sha256;
	uriEscapePath;
	applyChecksum;
	constructor({ applyChecksum, credentials, region, service, sha256, uriEscapePath = true }) {
		this.service = service;
		this.sha256 = sha256;
		this.uriEscapePath = uriEscapePath;
		this.applyChecksum = typeof applyChecksum === "boolean" ? applyChecksum : true;
		this.regionProvider = normalizeProvider$1(region);
		this.credentialProvider = normalizeProvider$1(credentials);
	}
	createCanonicalRequest(request, canonicalHeaders, payloadHash) {
		const sortedHeaders = Object.keys(canonicalHeaders).sort();
		return `${request.method}
${this.getCanonicalPath(request)}
${getCanonicalQuery(request)}
${sortedHeaders.map((name) => `${name}:${canonicalHeaders[name]}`).join("\n")}

${sortedHeaders.join(";")}
${payloadHash}`;
	}
	async createStringToSign(longDate, credentialScope, canonicalRequest, algorithmIdentifier) {
		const hash = new this.sha256();
		hash.update(toUint8Array(canonicalRequest));
		return `${algorithmIdentifier}
${longDate}
${credentialScope}
${toHex(await hash.digest())}`;
	}
	getCanonicalPath({ path }) {
		if (this.uriEscapePath) {
			const normalizedPathSegments = [];
			for (const pathSegment of path.split("/")) {
				if (pathSegment?.length === 0) continue;
				if (pathSegment === ".") continue;
				if (pathSegment === "..") normalizedPathSegments.pop();
				else normalizedPathSegments.push(pathSegment);
			}
			return escapeUri(`${path?.startsWith("/") ? "/" : ""}${normalizedPathSegments.join("/")}${normalizedPathSegments.length > 0 && path?.endsWith("/") ? "/" : ""}`).replace(/%2F/g, "/");
		}
		return path;
	}
	validateResolvedCredentials(credentials) {
		if (typeof credentials !== "object" || typeof credentials.accessKeyId !== "string" || typeof credentials.secretAccessKey !== "string") throw new Error("Resolved credential object is not valid");
	}
	formatDate(now) {
		const longDate = iso8601(now).replace(/[\-:]/g, "");
		return {
			longDate,
			shortDate: longDate.slice(0, 8)
		};
	}
	getCanonicalHeaderList(headers) {
		return Object.keys(headers).sort().join(";");
	}
};

//#endregion
//#region node_modules/@smithy/signature-v4/dist-es/SignatureV4.js
init_dist_es();
var SignatureV4 = class extends SignatureV4Base {
	headerFormatter = new HeaderFormatter();
	constructor({ applyChecksum, credentials, region, service, sha256, uriEscapePath = true }) {
		super({
			applyChecksum,
			credentials,
			region,
			service,
			sha256,
			uriEscapePath
		});
	}
	async presign(originalRequest, options = {}) {
		const { signingDate = /* @__PURE__ */ new Date(), expiresIn = 3600, unsignableHeaders, unhoistableHeaders, signableHeaders, hoistableHeaders, signingRegion, signingService } = options;
		const credentials = await this.credentialProvider();
		this.validateResolvedCredentials(credentials);
		const region = signingRegion ?? await this.regionProvider();
		const { longDate, shortDate } = this.formatDate(signingDate);
		if (expiresIn > MAX_PRESIGNED_TTL) return Promise.reject("Signature version 4 presigned URLs must have an expiration date less than one week in the future");
		const scope = createScope(shortDate, region, signingService ?? this.service);
		const request = moveHeadersToQuery(prepareRequest(originalRequest), {
			unhoistableHeaders,
			hoistableHeaders
		});
		if (credentials.sessionToken) request.query[TOKEN_QUERY_PARAM] = credentials.sessionToken;
		request.query[ALGORITHM_QUERY_PARAM] = ALGORITHM_IDENTIFIER;
		request.query[CREDENTIAL_QUERY_PARAM] = `${credentials.accessKeyId}/${scope}`;
		request.query[AMZ_DATE_QUERY_PARAM] = longDate;
		request.query[EXPIRES_QUERY_PARAM] = expiresIn.toString(10);
		const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
		request.query[SIGNED_HEADERS_QUERY_PARAM] = this.getCanonicalHeaderList(canonicalHeaders);
		request.query[SIGNATURE_QUERY_PARAM] = await this.getSignature(longDate, scope, this.getSigningKey(credentials, region, shortDate, signingService), this.createCanonicalRequest(request, canonicalHeaders, await getPayloadHash(originalRequest, this.sha256)));
		return request;
	}
	async sign(toSign, options) {
		if (typeof toSign === "string") return this.signString(toSign, options);
		else if (toSign.headers && toSign.payload) return this.signEvent(toSign, options);
		else if (toSign.message) return this.signMessage(toSign, options);
		else return this.signRequest(toSign, options);
	}
	async signEvent({ headers, payload }, { signingDate = /* @__PURE__ */ new Date(), priorSignature, signingRegion, signingService }) {
		const region = signingRegion ?? await this.regionProvider();
		const { shortDate, longDate } = this.formatDate(signingDate);
		const scope = createScope(shortDate, region, signingService ?? this.service);
		const hashedPayload = await getPayloadHash({
			headers: {},
			body: payload
		}, this.sha256);
		const hash = new this.sha256();
		hash.update(headers);
		const stringToSign = [
			EVENT_ALGORITHM_IDENTIFIER,
			longDate,
			scope,
			priorSignature,
			toHex(await hash.digest()),
			hashedPayload
		].join("\n");
		return this.signString(stringToSign, {
			signingDate,
			signingRegion: region,
			signingService
		});
	}
	async signMessage(signableMessage, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService }) {
		return this.signEvent({
			headers: this.headerFormatter.format(signableMessage.message.headers),
			payload: signableMessage.message.body
		}, {
			signingDate,
			signingRegion,
			signingService,
			priorSignature: signableMessage.priorSignature
		}).then((signature) => {
			return {
				message: signableMessage.message,
				signature
			};
		});
	}
	async signString(stringToSign, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService } = {}) {
		const credentials = await this.credentialProvider();
		this.validateResolvedCredentials(credentials);
		const region = signingRegion ?? await this.regionProvider();
		const { shortDate } = this.formatDate(signingDate);
		const hash = new this.sha256(await this.getSigningKey(credentials, region, shortDate, signingService));
		hash.update(toUint8Array(stringToSign));
		return toHex(await hash.digest());
	}
	async signRequest(requestToSign, { signingDate = /* @__PURE__ */ new Date(), signableHeaders, unsignableHeaders, signingRegion, signingService } = {}) {
		const credentials = await this.credentialProvider();
		this.validateResolvedCredentials(credentials);
		const region = signingRegion ?? await this.regionProvider();
		const request = prepareRequest(requestToSign);
		const { longDate, shortDate } = this.formatDate(signingDate);
		const scope = createScope(shortDate, region, signingService ?? this.service);
		request.headers[AMZ_DATE_HEADER] = longDate;
		if (credentials.sessionToken) request.headers[TOKEN_HEADER] = credentials.sessionToken;
		const payloadHash = await getPayloadHash(request, this.sha256);
		if (!hasHeader(SHA256_HEADER, request.headers) && this.applyChecksum) request.headers[SHA256_HEADER] = payloadHash;
		const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
		const signature = await this.getSignature(longDate, scope, this.getSigningKey(credentials, region, shortDate, signingService), this.createCanonicalRequest(request, canonicalHeaders, payloadHash));
		request.headers[AUTH_HEADER] = `${ALGORITHM_IDENTIFIER} Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${this.getCanonicalHeaderList(canonicalHeaders)}, Signature=${signature}`;
		return request;
	}
	async getSignature(longDate, credentialScope, keyPromise, canonicalRequest) {
		const stringToSign = await this.createStringToSign(longDate, credentialScope, canonicalRequest, ALGORITHM_IDENTIFIER);
		const hash = new this.sha256(await keyPromise);
		hash.update(toUint8Array(stringToSign));
		return toHex(await hash.digest());
	}
	getSigningKey(credentials, region, shortDate, service) {
		return getSigningKey(this.sha256, credentials, shortDate, region, service || this.service);
	}
};

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.js
const resolveAwsSdkSigV4Config = (config) => {
	let inputCredentials = config.credentials;
	let isUserSupplied = !!config.credentials;
	let resolvedCredentials = void 0;
	Object.defineProperty(config, "credentials", {
		set(credentials) {
			if (credentials && credentials !== inputCredentials && credentials !== resolvedCredentials) isUserSupplied = true;
			inputCredentials = credentials;
			const boundProvider = bindCallerConfig(config, normalizeCredentialProvider(config, {
				credentials: inputCredentials,
				credentialDefaultProvider: config.credentialDefaultProvider
			}));
			if (isUserSupplied && !boundProvider.attributed) {
				resolvedCredentials = async (options) => boundProvider(options).then((creds) => setCredentialFeature(creds, "CREDENTIALS_CODE", "e"));
				resolvedCredentials.memoized = boundProvider.memoized;
				resolvedCredentials.configBound = boundProvider.configBound;
				resolvedCredentials.attributed = true;
			} else resolvedCredentials = boundProvider;
		},
		get() {
			return resolvedCredentials;
		},
		enumerable: true,
		configurable: true
	});
	config.credentials = inputCredentials;
	const { signingEscapePath = true, systemClockOffset = config.systemClockOffset || 0, sha256 } = config;
	let signer;
	if (config.signer) signer = normalizeProvider(config.signer);
	else if (config.regionInfoProvider) signer = () => normalizeProvider(config.region)().then(async (region) => [await config.regionInfoProvider(region, {
		useFipsEndpoint: await config.useFipsEndpoint(),
		useDualstackEndpoint: await config.useDualstackEndpoint()
	}) || {}, region]).then(([regionInfo, region]) => {
		const { signingRegion, signingService } = regionInfo;
		config.signingRegion = config.signingRegion || signingRegion || region;
		config.signingName = config.signingName || signingService || config.serviceId;
		const params = {
			...config,
			credentials: config.credentials,
			region: config.signingRegion,
			service: config.signingName,
			sha256,
			uriEscapePath: signingEscapePath
		};
		return new (config.signerConstructor || SignatureV4)(params);
	});
	else signer = async (authScheme) => {
		authScheme = Object.assign({}, {
			name: "sigv4",
			signingName: config.signingName || config.defaultSigningName,
			signingRegion: await normalizeProvider(config.region)(),
			properties: {}
		}, authScheme);
		const signingRegion = authScheme.signingRegion;
		const signingService = authScheme.signingName;
		config.signingRegion = config.signingRegion || signingRegion;
		config.signingName = config.signingName || signingService || config.serviceId;
		const params = {
			...config,
			credentials: config.credentials,
			region: config.signingRegion,
			service: config.signingName,
			sha256,
			uriEscapePath: signingEscapePath
		};
		return new (config.signerConstructor || SignatureV4)(params);
	};
	return Object.assign(config, {
		systemClockOffset,
		signingEscapePath,
		signer
	});
};
function normalizeCredentialProvider(config, { credentials, credentialDefaultProvider }) {
	let credentialsProvider;
	if (credentials) if (!credentials?.memoized) credentialsProvider = memoizeIdentityProvider(credentials, isIdentityExpired, doesIdentityRequireRefresh);
	else credentialsProvider = credentials;
	else if (credentialDefaultProvider) credentialsProvider = normalizeProvider(credentialDefaultProvider(Object.assign({}, config, { parentClientConfig: config })));
	else credentialsProvider = async () => {
		throw new Error("@aws-sdk/core::resolveAwsSdkSigV4Config - `credentials` not provided and no credentialDefaultProvider was configured.");
	};
	credentialsProvider.memoized = true;
	return credentialsProvider;
}
function bindCallerConfig(config, credentialsProvider) {
	if (credentialsProvider.configBound) return credentialsProvider;
	const fn = async (options) => credentialsProvider({
		...options,
		callerClientConfig: config
	});
	fn.memoized = credentialsProvider.memoized;
	fn.configBound = true;
	return fn;
}

//#endregion
//#region node_modules/@smithy/util-body-length-browser/dist-es/calculateBodyLength.js
const TEXT_ENCODER = typeof TextEncoder == "function" ? new TextEncoder() : null;
const calculateBodyLength = (body) => {
	if (typeof body === "string") {
		if (TEXT_ENCODER) return TEXT_ENCODER.encode(body).byteLength;
		let len = body.length;
		for (let i$1 = len - 1; i$1 >= 0; i$1--) {
			const code = body.charCodeAt(i$1);
			if (code > 127 && code <= 2047) len++;
			else if (code > 2047 && code <= 65535) len += 2;
			if (code >= 56320 && code <= 57343) i$1--;
		}
		return len;
	} else if (typeof body.byteLength === "number") return body.byteLength;
	else if (typeof body.size === "number") return body.size;
	throw new Error(`Body Length computation failed for ${body}`);
};

//#endregion
//#region node_modules/@smithy/middleware-stack/dist-es/MiddlewareStack.js
const getAllAliases = (name, aliases) => {
	const _aliases = [];
	if (name) _aliases.push(name);
	if (aliases) for (const alias of aliases) _aliases.push(alias);
	return _aliases;
};
const getMiddlewareNameWithAliases = (name, aliases) => {
	return `${name || "anonymous"}${aliases && aliases.length > 0 ? ` (a.k.a. ${aliases.join(",")})` : ""}`;
};
const constructStack = () => {
	let absoluteEntries = [];
	let relativeEntries = [];
	let identifyOnResolve = false;
	const entriesNameSet = /* @__PURE__ */ new Set();
	const sort = (entries) => entries.sort((a$1, b$1) => stepWeights[b$1.step] - stepWeights[a$1.step] || priorityWeights[b$1.priority || "normal"] - priorityWeights[a$1.priority || "normal"]);
	const removeByName = (toRemove) => {
		let isRemoved = false;
		const filterCb = (entry) => {
			const aliases = getAllAliases(entry.name, entry.aliases);
			if (aliases.includes(toRemove)) {
				isRemoved = true;
				for (const alias of aliases) entriesNameSet.delete(alias);
				return false;
			}
			return true;
		};
		absoluteEntries = absoluteEntries.filter(filterCb);
		relativeEntries = relativeEntries.filter(filterCb);
		return isRemoved;
	};
	const removeByReference = (toRemove) => {
		let isRemoved = false;
		const filterCb = (entry) => {
			if (entry.middleware === toRemove) {
				isRemoved = true;
				for (const alias of getAllAliases(entry.name, entry.aliases)) entriesNameSet.delete(alias);
				return false;
			}
			return true;
		};
		absoluteEntries = absoluteEntries.filter(filterCb);
		relativeEntries = relativeEntries.filter(filterCb);
		return isRemoved;
	};
	const cloneTo = (toStack) => {
		absoluteEntries.forEach((entry) => {
			toStack.add(entry.middleware, { ...entry });
		});
		relativeEntries.forEach((entry) => {
			toStack.addRelativeTo(entry.middleware, { ...entry });
		});
		toStack.identifyOnResolve?.(stack.identifyOnResolve());
		return toStack;
	};
	const expandRelativeMiddlewareList = (from) => {
		const expandedMiddlewareList = [];
		from.before.forEach((entry) => {
			if (entry.before.length === 0 && entry.after.length === 0) expandedMiddlewareList.push(entry);
			else expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
		});
		expandedMiddlewareList.push(from);
		from.after.reverse().forEach((entry) => {
			if (entry.before.length === 0 && entry.after.length === 0) expandedMiddlewareList.push(entry);
			else expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
		});
		return expandedMiddlewareList;
	};
	const getMiddlewareList = (debug = false) => {
		const normalizedAbsoluteEntries = [];
		const normalizedRelativeEntries = [];
		const normalizedEntriesNameMap = {};
		absoluteEntries.forEach((entry) => {
			const normalizedEntry = {
				...entry,
				before: [],
				after: []
			};
			for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) normalizedEntriesNameMap[alias] = normalizedEntry;
			normalizedAbsoluteEntries.push(normalizedEntry);
		});
		relativeEntries.forEach((entry) => {
			const normalizedEntry = {
				...entry,
				before: [],
				after: []
			};
			for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) normalizedEntriesNameMap[alias] = normalizedEntry;
			normalizedRelativeEntries.push(normalizedEntry);
		});
		normalizedRelativeEntries.forEach((entry) => {
			if (entry.toMiddleware) {
				const toMiddleware = normalizedEntriesNameMap[entry.toMiddleware];
				if (toMiddleware === void 0) {
					if (debug) return;
					throw new Error(`${entry.toMiddleware} is not found when adding ${getMiddlewareNameWithAliases(entry.name, entry.aliases)} middleware ${entry.relation} ${entry.toMiddleware}`);
				}
				if (entry.relation === "after") toMiddleware.after.push(entry);
				if (entry.relation === "before") toMiddleware.before.push(entry);
			}
		});
		return sort(normalizedAbsoluteEntries).map(expandRelativeMiddlewareList).reduce((wholeList, expandedMiddlewareList) => {
			wholeList.push(...expandedMiddlewareList);
			return wholeList;
		}, []);
	};
	const stack = {
		add: (middleware, options = {}) => {
			const { name, override, aliases: _aliases } = options;
			const entry = {
				step: "initialize",
				priority: "normal",
				middleware,
				...options
			};
			const aliases = getAllAliases(name, _aliases);
			if (aliases.length > 0) {
				if (aliases.some((alias) => entriesNameSet.has(alias))) {
					if (!override) throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
					for (const alias of aliases) {
						const toOverrideIndex = absoluteEntries.findIndex((entry$1) => entry$1.name === alias || entry$1.aliases?.some((a$1) => a$1 === alias));
						if (toOverrideIndex === -1) continue;
						const toOverride = absoluteEntries[toOverrideIndex];
						if (toOverride.step !== entry.step || entry.priority !== toOverride.priority) throw new Error(`"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware with ${toOverride.priority} priority in ${toOverride.step} step cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware with ${entry.priority} priority in ${entry.step} step.`);
						absoluteEntries.splice(toOverrideIndex, 1);
					}
				}
				for (const alias of aliases) entriesNameSet.add(alias);
			}
			absoluteEntries.push(entry);
		},
		addRelativeTo: (middleware, options) => {
			const { name, override, aliases: _aliases } = options;
			const entry = {
				middleware,
				...options
			};
			const aliases = getAllAliases(name, _aliases);
			if (aliases.length > 0) {
				if (aliases.some((alias) => entriesNameSet.has(alias))) {
					if (!override) throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
					for (const alias of aliases) {
						const toOverrideIndex = relativeEntries.findIndex((entry$1) => entry$1.name === alias || entry$1.aliases?.some((a$1) => a$1 === alias));
						if (toOverrideIndex === -1) continue;
						const toOverride = relativeEntries[toOverrideIndex];
						if (toOverride.toMiddleware !== entry.toMiddleware || toOverride.relation !== entry.relation) throw new Error(`"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware ${toOverride.relation} "${toOverride.toMiddleware}" middleware cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware ${entry.relation} "${entry.toMiddleware}" middleware.`);
						relativeEntries.splice(toOverrideIndex, 1);
					}
				}
				for (const alias of aliases) entriesNameSet.add(alias);
			}
			relativeEntries.push(entry);
		},
		clone: () => cloneTo(constructStack()),
		use: (plugin) => {
			plugin.applyToStack(stack);
		},
		remove: (toRemove) => {
			if (typeof toRemove === "string") return removeByName(toRemove);
			else return removeByReference(toRemove);
		},
		removeByTag: (toRemove) => {
			let isRemoved = false;
			const filterCb = (entry) => {
				const { tags, name, aliases: _aliases } = entry;
				if (tags && tags.includes(toRemove)) {
					const aliases = getAllAliases(name, _aliases);
					for (const alias of aliases) entriesNameSet.delete(alias);
					isRemoved = true;
					return false;
				}
				return true;
			};
			absoluteEntries = absoluteEntries.filter(filterCb);
			relativeEntries = relativeEntries.filter(filterCb);
			return isRemoved;
		},
		concat: (from) => {
			const cloned = cloneTo(constructStack());
			cloned.use(from);
			cloned.identifyOnResolve(identifyOnResolve || cloned.identifyOnResolve() || (from.identifyOnResolve?.() ?? false));
			return cloned;
		},
		applyToStack: cloneTo,
		identify: () => {
			return getMiddlewareList(true).map((mw) => {
				const step = mw.step ?? mw.relation + " " + mw.toMiddleware;
				return getMiddlewareNameWithAliases(mw.name, mw.aliases) + " - " + step;
			});
		},
		identifyOnResolve(toggle) {
			if (typeof toggle === "boolean") identifyOnResolve = toggle;
			return identifyOnResolve;
		},
		resolve: (handler$1, context) => {
			for (const middleware of getMiddlewareList().map((entry) => entry.middleware).reverse()) handler$1 = middleware(handler$1, context);
			if (identifyOnResolve) console.log(stack.identify());
			return handler$1;
		}
	};
	return stack;
};
const stepWeights = {
	initialize: 5,
	serialize: 4,
	build: 3,
	finalizeRequest: 2,
	deserialize: 1
};
const priorityWeights = {
	high: 3,
	normal: 2,
	low: 1
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/client.js
var Client = class {
	config;
	middlewareStack = constructStack();
	initConfig;
	handlers;
	constructor(config) {
		this.config = config;
		const { protocol, protocolSettings } = config;
		if (protocolSettings) {
			if (typeof protocol === "function") config.protocol = new protocol(protocolSettings);
		}
	}
	send(command, optionsOrCb, cb) {
		const options = typeof optionsOrCb !== "function" ? optionsOrCb : void 0;
		const callback = typeof optionsOrCb === "function" ? optionsOrCb : cb;
		const useHandlerCache = options === void 0 && this.config.cacheMiddleware === true;
		let handler$1;
		if (useHandlerCache) {
			if (!this.handlers) this.handlers = /* @__PURE__ */ new WeakMap();
			const handlers = this.handlers;
			if (handlers.has(command.constructor)) handler$1 = handlers.get(command.constructor);
			else {
				handler$1 = command.resolveMiddleware(this.middlewareStack, this.config, options);
				handlers.set(command.constructor, handler$1);
			}
		} else {
			delete this.handlers;
			handler$1 = command.resolveMiddleware(this.middlewareStack, this.config, options);
		}
		if (callback) handler$1(command).then((result) => callback(null, result.output), (err) => callback(err)).catch(() => {});
		else return handler$1(command).then((result) => result.output);
	}
	destroy() {
		this.config?.requestHandler?.destroy?.();
		delete this.handlers;
	}
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/schemaLogFilter.js
const SENSITIVE_STRING = "***SensitiveInformation***";
function schemaLogFilter(schema, data) {
	if (data == null) return data;
	const ns = NormalizedSchema.of(schema);
	if (ns.getMergedTraits().sensitive) return SENSITIVE_STRING;
	if (ns.isListSchema()) {
		if (!!ns.getValueSchema().getMergedTraits().sensitive) return SENSITIVE_STRING;
	} else if (ns.isMapSchema()) {
		if (!!ns.getKeySchema().getMergedTraits().sensitive || !!ns.getValueSchema().getMergedTraits().sensitive) return SENSITIVE_STRING;
	} else if (ns.isStructSchema() && typeof data === "object") {
		const object = data;
		const newObject = {};
		for (const [member$1, memberNs] of ns.structIterator()) if (object[member$1] != null) newObject[member$1] = schemaLogFilter(memberNs, object[member$1]);
		return newObject;
	}
	return data;
}

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/command.js
var Command = class {
	middlewareStack = constructStack();
	schema;
	static classBuilder() {
		return new ClassBuilder();
	}
	resolveMiddlewareWithContext(clientStack, configuration, options, { middlewareFn, clientName, commandName, inputFilterSensitiveLog, outputFilterSensitiveLog, smithyContext, additionalContext, CommandCtor }) {
		for (const mw of middlewareFn.bind(this)(CommandCtor, clientStack, configuration, options)) this.middlewareStack.use(mw);
		const stack = clientStack.concat(this.middlewareStack);
		const { logger } = configuration;
		const handlerExecutionContext = {
			logger,
			clientName,
			commandName,
			inputFilterSensitiveLog,
			outputFilterSensitiveLog,
			[SMITHY_CONTEXT_KEY]: {
				commandInstance: this,
				...smithyContext
			},
			...additionalContext
		};
		const { requestHandler } = configuration;
		return stack.resolve((request) => requestHandler.handle(request.request, options || {}), handlerExecutionContext);
	}
};
var ClassBuilder = class {
	_init = () => {};
	_ep = {};
	_middlewareFn = () => [];
	_commandName = "";
	_clientName = "";
	_additionalContext = {};
	_smithyContext = {};
	_inputFilterSensitiveLog = void 0;
	_outputFilterSensitiveLog = void 0;
	_serializer = null;
	_deserializer = null;
	_operationSchema;
	init(cb) {
		this._init = cb;
	}
	ep(endpointParameterInstructions) {
		this._ep = endpointParameterInstructions;
		return this;
	}
	m(middlewareSupplier) {
		this._middlewareFn = middlewareSupplier;
		return this;
	}
	s(service, operation$1, smithyContext = {}) {
		this._smithyContext = {
			service,
			operation: operation$1,
			...smithyContext
		};
		return this;
	}
	c(additionalContext = {}) {
		this._additionalContext = additionalContext;
		return this;
	}
	n(clientName, commandName) {
		this._clientName = clientName;
		this._commandName = commandName;
		return this;
	}
	f(inputFilter = (_) => _, outputFilter = (_) => _) {
		this._inputFilterSensitiveLog = inputFilter;
		this._outputFilterSensitiveLog = outputFilter;
		return this;
	}
	ser(serializer) {
		this._serializer = serializer;
		return this;
	}
	de(deserializer) {
		this._deserializer = deserializer;
		return this;
	}
	sc(operation$1) {
		this._operationSchema = operation$1;
		this._smithyContext.operationSchema = operation$1;
		return this;
	}
	build() {
		const closure = this;
		let CommandRef;
		return CommandRef = class extends Command {
			input;
			static getEndpointParameterInstructions() {
				return closure._ep;
			}
			constructor(...[input]) {
				super();
				this.input = input ?? {};
				closure._init(this);
				this.schema = closure._operationSchema;
			}
			resolveMiddleware(stack, configuration, options) {
				const op = closure._operationSchema;
				const input = op?.[4] ?? op?.input;
				const output = op?.[5] ?? op?.output;
				return this.resolveMiddlewareWithContext(stack, configuration, options, {
					CommandCtor: CommandRef,
					middlewareFn: closure._middlewareFn,
					clientName: closure._clientName,
					commandName: closure._commandName,
					inputFilterSensitiveLog: closure._inputFilterSensitiveLog ?? (op ? schemaLogFilter.bind(null, input) : (_) => _),
					outputFilterSensitiveLog: closure._outputFilterSensitiveLog ?? (op ? schemaLogFilter.bind(null, output) : (_) => _),
					smithyContext: closure._smithyContext,
					additionalContext: closure._additionalContext
				});
			}
			serialize = closure._serializer;
			deserialize = closure._deserializer;
		};
	}
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/exceptions.js
var ServiceException = class ServiceException extends Error {
	$fault;
	$response;
	$retryable;
	$metadata;
	constructor(options) {
		super(options.message);
		Object.setPrototypeOf(this, Object.getPrototypeOf(this).constructor.prototype);
		this.name = options.name;
		this.$fault = options.$fault;
		this.$metadata = options.$metadata;
	}
	static isInstance(value) {
		if (!value) return false;
		const candidate = value;
		return ServiceException.prototype.isPrototypeOf(candidate) || Boolean(candidate.$fault) && Boolean(candidate.$metadata) && (candidate.$fault === "client" || candidate.$fault === "server");
	}
	static [Symbol.hasInstance](instance) {
		if (!instance) return false;
		const candidate = instance;
		if (this === ServiceException) return ServiceException.isInstance(instance);
		if (ServiceException.isInstance(instance)) {
			if (candidate.name && this.name) return this.prototype.isPrototypeOf(instance) || candidate.name === this.name;
			return this.prototype.isPrototypeOf(instance);
		}
		return false;
	}
};
const decorateServiceException = (exception, additions = {}) => {
	Object.entries(additions).filter(([, v$1]) => v$1 !== void 0).forEach(([k$1, v$1]) => {
		if (exception[k$1] == void 0 || exception[k$1] === "") exception[k$1] = v$1;
	});
	exception.message = exception.message || exception.Message || "UnknownError";
	delete exception.Message;
	return exception;
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/defaults-mode.js
const loadConfigsForDefaultMode = (mode) => {
	switch (mode) {
		case "standard": return {
			retryMode: "standard",
			connectionTimeout: 3100
		};
		case "in-region": return {
			retryMode: "standard",
			connectionTimeout: 1100
		};
		case "cross-region": return {
			retryMode: "standard",
			connectionTimeout: 3100
		};
		case "mobile": return {
			retryMode: "standard",
			connectionTimeout: 3e4
		};
		default: return {};
	}
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/extensions/checksum.js
const getChecksumConfiguration = (runtimeConfig) => {
	const checksumAlgorithms = [];
	for (const id in AlgorithmId) {
		const algorithmId = AlgorithmId[id];
		if (runtimeConfig[algorithmId] === void 0) continue;
		checksumAlgorithms.push({
			algorithmId: () => algorithmId,
			checksumConstructor: () => runtimeConfig[algorithmId]
		});
	}
	return {
		addChecksumAlgorithm(algo) {
			checksumAlgorithms.push(algo);
		},
		checksumAlgorithms() {
			return checksumAlgorithms;
		}
	};
};
const resolveChecksumRuntimeConfig = (clientConfig) => {
	const runtimeConfig = {};
	clientConfig.checksumAlgorithms().forEach((checksumAlgorithm) => {
		runtimeConfig[checksumAlgorithm.algorithmId()] = checksumAlgorithm.checksumConstructor();
	});
	return runtimeConfig;
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/extensions/retry.js
const getRetryConfiguration = (runtimeConfig) => {
	return {
		setRetryStrategy(retryStrategy) {
			runtimeConfig.retryStrategy = retryStrategy;
		},
		retryStrategy() {
			return runtimeConfig.retryStrategy;
		}
	};
};
const resolveRetryRuntimeConfig = (retryStrategyConfiguration) => {
	const runtimeConfig = {};
	runtimeConfig.retryStrategy = retryStrategyConfiguration.retryStrategy();
	return runtimeConfig;
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/extensions/defaultExtensionConfiguration.js
const getDefaultExtensionConfiguration = (runtimeConfig) => {
	return Object.assign(getChecksumConfiguration(runtimeConfig), getRetryConfiguration(runtimeConfig));
};
const resolveDefaultRuntimeConfig = (config) => {
	return Object.assign(resolveChecksumRuntimeConfig(config), resolveRetryRuntimeConfig(config));
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/get-value-from-text-node.js
const getValueFromTextNode = (obj) => {
	const textNodeName = "#text";
	for (const key in obj) if (obj.hasOwnProperty(key) && obj[key][textNodeName] !== void 0) obj[key] = obj[key][textNodeName];
	else if (typeof obj[key] === "object" && obj[key] !== null) obj[key] = getValueFromTextNode(obj[key]);
	return obj;
};

//#endregion
//#region node_modules/@smithy/smithy-client/dist-es/NoOpLogger.js
var NoOpLogger = class {
	trace() {}
	debug() {}
	info() {}
	warn() {}
	error() {}
};

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/ProtocolLib.js
var ProtocolLib = class {
	queryCompat;
	constructor(queryCompat = false) {
		this.queryCompat = queryCompat;
	}
	resolveRestContentType(defaultContentType, inputSchema) {
		const members = inputSchema.getMemberSchemas();
		const httpPayloadMember = Object.values(members).find((m$1) => {
			return !!m$1.getMergedTraits().httpPayload;
		});
		if (httpPayloadMember) {
			const mediaType = httpPayloadMember.getMergedTraits().mediaType;
			if (mediaType) return mediaType;
			else if (httpPayloadMember.isStringSchema()) return "text/plain";
			else if (httpPayloadMember.isBlobSchema()) return "application/octet-stream";
			else return defaultContentType;
		} else if (!inputSchema.isUnitSchema()) {
			if (Object.values(members).find((m$1) => {
				const { httpQuery, httpQueryParams, httpHeader, httpLabel, httpPrefixHeaders } = m$1.getMergedTraits();
				return !httpQuery && !httpQueryParams && !httpHeader && !httpLabel && httpPrefixHeaders === void 0;
			})) return defaultContentType;
		}
	}
	async getErrorSchemaOrThrowBaseException(errorIdentifier, defaultNamespace, response, dataObject, metadata, getErrorSchema) {
		let namespace = defaultNamespace;
		let errorName = errorIdentifier;
		if (errorIdentifier.includes("#")) [namespace, errorName] = errorIdentifier.split("#");
		const errorMetadata = {
			$metadata: metadata,
			$fault: response.statusCode < 500 ? "client" : "server"
		};
		const registry = TypeRegistry.for(namespace);
		try {
			return {
				errorSchema: getErrorSchema?.(registry, errorName) ?? registry.getSchema(errorIdentifier),
				errorMetadata
			};
		} catch (e$1) {
			dataObject.message = dataObject.message ?? dataObject.Message ?? "UnknownError";
			const synthetic = TypeRegistry.for("smithy.ts.sdk.synthetic." + namespace);
			const baseExceptionSchema = synthetic.getBaseException();
			if (baseExceptionSchema) {
				const ErrorCtor = synthetic.getErrorCtor(baseExceptionSchema) ?? Error;
				throw this.decorateServiceException(Object.assign(new ErrorCtor({ name: errorName }), errorMetadata), dataObject);
			}
			throw this.decorateServiceException(Object.assign(new Error(errorName), errorMetadata), dataObject);
		}
	}
	decorateServiceException(exception, additions = {}) {
		if (this.queryCompat) {
			const msg = exception.Message ?? additions.Message;
			const error = decorateServiceException(exception, additions);
			if (msg) error.message = msg;
			error.Error = {
				...error.Error,
				Type: error.Error.Type,
				Code: error.Error.Code,
				Message: error.Error.message ?? error.Error.Message ?? msg
			};
			const reqId = error.$metadata.requestId;
			if (reqId) error.RequestId = reqId;
			return error;
		}
		return decorateServiceException(exception, additions);
	}
	setQueryCompatError(output, response) {
		const queryErrorHeader = response.headers?.["x-amzn-query-error"];
		if (output !== void 0 && queryErrorHeader != null) {
			const [Code, Type] = queryErrorHeader.split(";");
			const entries = Object.entries(output);
			const Error$1 = {
				Code,
				Type
			};
			Object.assign(output, Error$1);
			for (const [k$1, v$1] of entries) Error$1[k$1 === "message" ? "Message" : k$1] = v$1;
			delete Error$1.__type;
			output.Error = Error$1;
		}
	}
	queryCompatOutput(queryCompatErrorData, errorData) {
		if (queryCompatErrorData.Error) errorData.Error = queryCompatErrorData.Error;
		if (queryCompatErrorData.Type) errorData.Type = queryCompatErrorData.Type;
		if (queryCompatErrorData.Code) errorData.Code = queryCompatErrorData.Code;
	}
	findQueryCompatibleError(registry, errorName) {
		try {
			return registry.getSchema(errorName);
		} catch (e$1) {
			return registry.find((schema) => NormalizedSchema.of(schema).getMergedTraits().awsQueryError?.[0] === errorName);
		}
	}
};

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/ConfigurableSerdeContext.js
var SerdeContextConfig = class {
	serdeContext;
	setSerdeContext(serdeContext) {
		this.serdeContext = serdeContext;
	}
};

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/structIterator.js
function* serializingStructIterator(ns, sourceObject) {
	if (ns.isUnitSchema()) return;
	const struct = ns.getSchema();
	for (let i$1 = 0; i$1 < struct[4].length; ++i$1) {
		const key = struct[4][i$1];
		const memberSchema = struct[5][i$1];
		const memberNs = new NormalizedSchema([memberSchema, 0], key);
		if (!(key in sourceObject) && !memberNs.isIdempotencyToken()) continue;
		yield [key, memberNs];
	}
}

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/UnionSerde.js
var UnionSerde = class {
	from;
	to;
	keys;
	constructor(from, to) {
		this.from = from;
		this.to = to;
		this.keys = new Set(Object.keys(this.from).filter((k$1) => k$1 !== "__type"));
	}
	mark(key) {
		this.keys.delete(key);
	}
	hasUnknown() {
		return this.keys.size === 1 && Object.keys(this.to).length === 0;
	}
	writeUnknown() {
		if (this.hasUnknown()) {
			const k$1 = this.keys.values().next().value;
			const v$1 = this.from[k$1];
			this.to.$unknown = [k$1, v$1];
		}
	}
};

//#endregion
//#region node_modules/@aws-sdk/xml-builder/dist-es/xml-parser.browser.js
let parser;
function parseXML(xmlString) {
	if (!parser) parser = new DOMParser();
	const xmlDocument = parser.parseFromString(xmlString, "application/xml");
	if (xmlDocument.getElementsByTagName("parsererror").length > 0) throw new Error("DOMParser XML parsing error.");
	const xmlToObj = (node) => {
		if (node.nodeType === Node.TEXT_NODE) {
			if (node.textContent?.trim()) return node.textContent;
		}
		if (node.nodeType === Node.ELEMENT_NODE) {
			const element = node;
			if (element.attributes.length === 0 && element.childNodes.length === 0) return "";
			const obj = {};
			const attributes = Array.from(element.attributes);
			for (const attr of attributes) obj[`${attr.name}`] = attr.value;
			const childNodes = Array.from(element.childNodes);
			for (const child of childNodes) {
				const childResult = xmlToObj(child);
				if (childResult != null) {
					const childName = child.nodeName;
					if (childNodes.length === 1 && attributes.length === 0 && childName === "#text") return childResult;
					if (obj[childName]) if (Array.isArray(obj[childName])) obj[childName].push(childResult);
					else obj[childName] = [obj[childName], childResult];
					else obj[childName] = childResult;
				} else if (childNodes.length === 1 && attributes.length === 0) return element.textContent;
			}
			return obj;
		}
		return null;
	};
	return { [xmlDocument.documentElement.nodeName]: xmlToObj(xmlDocument.documentElement) };
}

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeDeserializer.js
init_dist_es();
var XmlShapeDeserializer = class extends SerdeContextConfig {
	settings;
	stringDeserializer;
	constructor(settings) {
		super();
		this.settings = settings;
		this.stringDeserializer = new FromStringShapeDeserializer(settings);
	}
	setSerdeContext(serdeContext) {
		this.serdeContext = serdeContext;
		this.stringDeserializer.setSerdeContext(serdeContext);
	}
	read(schema, bytes, key) {
		const ns = NormalizedSchema.of(schema);
		const memberSchemas = ns.getMemberSchemas();
		if (ns.isStructSchema() && ns.isMemberSchema() && !!Object.values(memberSchemas).find((memberNs) => {
			return !!memberNs.getMemberTraits().eventPayload;
		})) {
			const output = {};
			const memberName = Object.keys(memberSchemas)[0];
			if (memberSchemas[memberName].isBlobSchema()) output[memberName] = bytes;
			else output[memberName] = this.read(memberSchemas[memberName], bytes);
			return output;
		}
		const xmlString = (this.serdeContext?.utf8Encoder ?? toUtf8)(bytes);
		const parsedObject = this.parseXml(xmlString);
		return this.readSchema(schema, key ? parsedObject[key] : parsedObject);
	}
	readSchema(_schema, value) {
		const ns = NormalizedSchema.of(_schema);
		if (ns.isUnitSchema()) return;
		const traits = ns.getMergedTraits();
		if (ns.isListSchema() && !Array.isArray(value)) return this.readSchema(ns, [value]);
		if (value == null) return value;
		if (typeof value === "object") {
			const sparse = !!traits.sparse;
			const flat = !!traits.xmlFlattened;
			if (ns.isListSchema()) {
				const listValue = ns.getValueSchema();
				const buffer$1 = [];
				const sourceKey = listValue.getMergedTraits().xmlName ?? "member";
				const source = flat ? value : (value[0] ?? value)[sourceKey];
				const sourceArray = Array.isArray(source) ? source : [source];
				for (const v$1 of sourceArray) if (v$1 != null || sparse) buffer$1.push(this.readSchema(listValue, v$1));
				return buffer$1;
			}
			const buffer = {};
			if (ns.isMapSchema()) {
				const keyNs = ns.getKeySchema();
				const memberNs = ns.getValueSchema();
				let entries;
				if (flat) entries = Array.isArray(value) ? value : [value];
				else entries = Array.isArray(value.entry) ? value.entry : [value.entry];
				const keyProperty = keyNs.getMergedTraits().xmlName ?? "key";
				const valueProperty = memberNs.getMergedTraits().xmlName ?? "value";
				for (const entry of entries) {
					const key = entry[keyProperty];
					const value$1 = entry[valueProperty];
					if (value$1 != null || sparse) buffer[key] = this.readSchema(memberNs, value$1);
				}
				return buffer;
			}
			if (ns.isStructSchema()) {
				const union = ns.isUnionSchema();
				let unionSerde;
				if (union) unionSerde = new UnionSerde(value, buffer);
				for (const [memberName, memberSchema] of ns.structIterator()) {
					const memberTraits = memberSchema.getMergedTraits();
					const xmlObjectKey = !memberTraits.httpPayload ? memberSchema.getMemberTraits().xmlName ?? memberName : memberTraits.xmlName ?? memberSchema.getName();
					if (union) unionSerde.mark(xmlObjectKey);
					if (value[xmlObjectKey] != null) buffer[memberName] = this.readSchema(memberSchema, value[xmlObjectKey]);
				}
				if (union) unionSerde.writeUnknown();
				return buffer;
			}
			if (ns.isDocumentSchema()) return value;
			throw new Error(`@aws-sdk/core/protocols - xml deserializer unhandled schema type for ${ns.getName(true)}`);
		}
		if (ns.isListSchema()) return [];
		if (ns.isMapSchema() || ns.isStructSchema()) return {};
		return this.stringDeserializer.read(ns, value);
	}
	parseXml(xml) {
		if (xml.length) {
			let parsedObj;
			try {
				parsedObj = parseXML(xml);
			} catch (e$1) {
				if (e$1 && typeof e$1 === "object") Object.defineProperty(e$1, "$responseBodyText", { value: xml });
				throw e$1;
			}
			const textNodeName = "#text";
			const key = Object.keys(parsedObj)[0];
			const parsedObjToReturn = parsedObj[key];
			if (parsedObjToReturn[textNodeName]) {
				parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
				delete parsedObjToReturn[textNodeName];
			}
			return getValueFromTextNode(parsedObjToReturn);
		}
		return {};
	}
};

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/QueryShapeSerializer.js
var QueryShapeSerializer = class extends SerdeContextConfig {
	settings;
	buffer;
	constructor(settings) {
		super();
		this.settings = settings;
	}
	write(schema, value, prefix = "") {
		if (this.buffer === void 0) this.buffer = "";
		const ns = NormalizedSchema.of(schema);
		if (prefix && !prefix.endsWith(".")) prefix += ".";
		if (ns.isBlobSchema()) {
			if (typeof value === "string" || value instanceof Uint8Array) {
				this.writeKey(prefix);
				this.writeValue((this.serdeContext?.base64Encoder ?? toBase64)(value));
			}
		} else if (ns.isBooleanSchema() || ns.isNumericSchema() || ns.isStringSchema()) {
			if (value != null) {
				this.writeKey(prefix);
				this.writeValue(String(value));
			} else if (ns.isIdempotencyToken()) {
				this.writeKey(prefix);
				this.writeValue(v4());
			}
		} else if (ns.isBigIntegerSchema()) {
			if (value != null) {
				this.writeKey(prefix);
				this.writeValue(String(value));
			}
		} else if (ns.isBigDecimalSchema()) {
			if (value != null) {
				this.writeKey(prefix);
				this.writeValue(value instanceof NumericValue ? value.string : String(value));
			}
		} else if (ns.isTimestampSchema()) {
			if (value instanceof Date) {
				this.writeKey(prefix);
				switch (determineTimestampFormat(ns, this.settings)) {
					case 5:
						this.writeValue(value.toISOString().replace(".000Z", "Z"));
						break;
					case 6:
						this.writeValue(dateToUtcString(value));
						break;
					case 7:
						this.writeValue(String(value.getTime() / 1e3));
						break;
				}
			}
		} else if (ns.isDocumentSchema()) if (Array.isArray(value)) this.write(79, value, prefix);
		else if (value instanceof Date) this.write(4, value, prefix);
		else if (value instanceof Uint8Array) this.write(21, value, prefix);
		else if (value && typeof value === "object") this.write(143, value, prefix);
		else {
			this.writeKey(prefix);
			this.writeValue(String(value));
		}
		else if (ns.isListSchema()) {
			if (Array.isArray(value)) if (value.length === 0) {
				if (this.settings.serializeEmptyLists) {
					this.writeKey(prefix);
					this.writeValue("");
				}
			} else {
				const member$1 = ns.getValueSchema();
				const flat = this.settings.flattenLists || ns.getMergedTraits().xmlFlattened;
				let i$1 = 1;
				for (const item of value) {
					if (item == null) continue;
					const suffix = this.getKey("member", member$1.getMergedTraits().xmlName);
					const key = flat ? `${prefix}${i$1}` : `${prefix}${suffix}.${i$1}`;
					this.write(member$1, item, key);
					++i$1;
				}
			}
		} else if (ns.isMapSchema()) {
			if (value && typeof value === "object") {
				const keySchema = ns.getKeySchema();
				const memberSchema = ns.getValueSchema();
				const flat = ns.getMergedTraits().xmlFlattened;
				let i$1 = 1;
				for (const [k$1, v$1] of Object.entries(value)) {
					if (v$1 == null) continue;
					const keySuffix = this.getKey("key", keySchema.getMergedTraits().xmlName);
					const key = flat ? `${prefix}${i$1}.${keySuffix}` : `${prefix}entry.${i$1}.${keySuffix}`;
					const valueSuffix = this.getKey("value", memberSchema.getMergedTraits().xmlName);
					const valueKey = flat ? `${prefix}${i$1}.${valueSuffix}` : `${prefix}entry.${i$1}.${valueSuffix}`;
					this.write(keySchema, k$1, key);
					this.write(memberSchema, v$1, valueKey);
					++i$1;
				}
			}
		} else if (ns.isStructSchema()) {
			if (value && typeof value === "object") {
				let didWriteMember = false;
				for (const [memberName, member$1] of serializingStructIterator(ns, value)) {
					if (value[memberName] == null && !member$1.isIdempotencyToken()) continue;
					const suffix = this.getKey(memberName, member$1.getMergedTraits().xmlName);
					const key = `${prefix}${suffix}`;
					this.write(member$1, value[memberName], key);
					didWriteMember = true;
				}
				if (!didWriteMember && ns.isUnionSchema()) {
					const { $unknown } = value;
					if (Array.isArray($unknown)) {
						const [k$1, v$1] = $unknown;
						const key = `${prefix}${k$1}`;
						this.write(15, v$1, key);
					}
				}
			}
		} else if (ns.isUnitSchema()) {} else throw new Error(`@aws-sdk/core/protocols - QuerySerializer unrecognized schema type ${ns.getName(true)}`);
	}
	flush() {
		if (this.buffer === void 0) throw new Error("@aws-sdk/core/protocols - QuerySerializer cannot flush with nothing written to buffer.");
		const str = this.buffer;
		delete this.buffer;
		return str;
	}
	getKey(memberName, xmlName) {
		const key = xmlName ?? memberName;
		if (this.settings.capitalizeKeys) return key[0].toUpperCase() + key.slice(1);
		return key;
	}
	writeKey(key) {
		if (key.endsWith(".")) key = key.slice(0, key.length - 1);
		this.buffer += `&${extendedEncodeURIComponent(key)}=`;
	}
	writeValue(value) {
		this.buffer += extendedEncodeURIComponent(value);
	}
};

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsQueryProtocol.js
var AwsQueryProtocol = class extends RpcProtocol {
	options;
	serializer;
	deserializer;
	mixin = new ProtocolLib();
	constructor(options) {
		super({ defaultNamespace: options.defaultNamespace });
		this.options = options;
		const settings = {
			timestampFormat: {
				useTrait: true,
				default: 5
			},
			httpBindings: false,
			xmlNamespace: options.xmlNamespace,
			serviceNamespace: options.defaultNamespace,
			serializeEmptyLists: true
		};
		this.serializer = new QueryShapeSerializer(settings);
		this.deserializer = new XmlShapeDeserializer(settings);
	}
	getShapeId() {
		return "aws.protocols#awsQuery";
	}
	setSerdeContext(serdeContext) {
		this.serializer.setSerdeContext(serdeContext);
		this.deserializer.setSerdeContext(serdeContext);
	}
	getPayloadCodec() {
		throw new Error("AWSQuery protocol has no payload codec.");
	}
	async serializeRequest(operationSchema, input, context) {
		const request = await super.serializeRequest(operationSchema, input, context);
		if (!request.path.endsWith("/")) request.path += "/";
		Object.assign(request.headers, { "content-type": `application/x-www-form-urlencoded` });
		if (deref(operationSchema.input) === "unit" || !request.body) request.body = "";
		request.body = `Action=${operationSchema.name.split("#")[1] ?? operationSchema.name}&Version=${this.options.version}` + request.body;
		if (request.body.endsWith("&")) request.body = request.body.slice(-1);
		return request;
	}
	async deserializeResponse(operationSchema, context, response) {
		const deserializer = this.deserializer;
		const ns = NormalizedSchema.of(operationSchema.output);
		const dataObject = {};
		if (response.statusCode >= 300) {
			const bytes$1 = await collectBody(response.body, context);
			if (bytes$1.byteLength > 0) Object.assign(dataObject, await deserializer.read(15, bytes$1));
			await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
		}
		for (const header in response.headers) {
			const value = response.headers[header];
			delete response.headers[header];
			response.headers[header.toLowerCase()] = value;
		}
		const shortName = operationSchema.name.split("#")[1] ?? operationSchema.name;
		const awsQueryResultKey = ns.isStructSchema() && this.useNestedResult() ? shortName + "Result" : void 0;
		const bytes = await collectBody(response.body, context);
		if (bytes.byteLength > 0) Object.assign(dataObject, await deserializer.read(ns, bytes, awsQueryResultKey));
		return {
			$metadata: this.deserializeMetadata(response),
			...dataObject
		};
	}
	useNestedResult() {
		return true;
	}
	async handleError(operationSchema, context, response, dataObject, metadata) {
		const errorIdentifier = this.loadQueryErrorCode(response, dataObject) ?? "Unknown";
		const errorData = this.loadQueryError(dataObject);
		const message = this.loadQueryErrorMessage(dataObject);
		errorData.message = message;
		errorData.Error = {
			Type: errorData.Type,
			Code: errorData.Code,
			Message: message
		};
		const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, errorData, metadata, this.mixin.findQueryCompatibleError);
		const ns = NormalizedSchema.of(errorSchema);
		const exception = new ((TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema)) ?? Error)(message);
		const output = {
			Type: errorData.Error.Type,
			Code: errorData.Error.Code,
			Error: errorData.Error
		};
		for (const [name, member$1] of ns.structIterator()) {
			const target = member$1.getMergedTraits().xmlName ?? name;
			const value = errorData[target] ?? dataObject[target];
			output[name] = this.deserializer.readSchema(member$1, value);
		}
		throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
			$fault: ns.getMergedTraits().error,
			message
		}, output), dataObject);
	}
	loadQueryErrorCode(output, data) {
		const code = (data.Errors?.[0]?.Error ?? data.Errors?.Error ?? data.Error)?.Code;
		if (code !== void 0) return code;
		if (output.statusCode == 404) return "NotFound";
	}
	loadQueryError(data) {
		return data.Errors?.[0]?.Error ?? data.Errors?.Error ?? data.Error;
	}
	loadQueryErrorMessage(data) {
		const errorData = this.loadQueryError(data);
		return errorData?.message ?? errorData?.Message ?? data.message ?? data.Message ?? "Unknown";
	}
	getDefaultContentType() {
		return "application/x-www-form-urlencoded";
	}
};

//#endregion
//#region node_modules/@aws-sdk/middleware-user-agent/dist-es/check-features.js
const ACCOUNT_ID_ENDPOINT_REGEX = /\d{12}\.ddb/;
async function checkFeatures(context, config, args) {
	if (args.request?.headers?.["smithy-protocol"] === "rpc-v2-cbor") setFeature(context, "PROTOCOL_RPC_V2_CBOR", "M");
	if (typeof config.retryStrategy === "function") {
		const retryStrategy = await config.retryStrategy();
		if (typeof retryStrategy.acquireInitialRetryToken === "function") if (retryStrategy.constructor?.name?.includes("Adaptive")) setFeature(context, "RETRY_MODE_ADAPTIVE", "F");
		else setFeature(context, "RETRY_MODE_STANDARD", "E");
		else setFeature(context, "RETRY_MODE_LEGACY", "D");
	}
	if (typeof config.accountIdEndpointMode === "function") {
		const endpointV2 = context.endpointV2;
		if (String(endpointV2?.url?.hostname).match(ACCOUNT_ID_ENDPOINT_REGEX)) setFeature(context, "ACCOUNT_ID_ENDPOINT", "O");
		switch (await config.accountIdEndpointMode?.()) {
			case "disabled":
				setFeature(context, "ACCOUNT_ID_MODE_DISABLED", "Q");
				break;
			case "preferred":
				setFeature(context, "ACCOUNT_ID_MODE_PREFERRED", "P");
				break;
			case "required":
				setFeature(context, "ACCOUNT_ID_MODE_REQUIRED", "R");
				break;
		}
	}
	const identity = context.__smithy_context?.selectedHttpAuthScheme?.identity;
	if (identity?.$source) {
		const credentials = identity;
		if (credentials.accountId) setFeature(context, "RESOLVED_ACCOUNT_ID", "T");
		for (const [key, value] of Object.entries(credentials.$source ?? {})) setFeature(context, key, value);
	}
}

//#endregion
//#region node_modules/@aws-sdk/middleware-user-agent/dist-es/constants.js
const USER_AGENT = "user-agent";
const X_AMZ_USER_AGENT = "x-amz-user-agent";
const SPACE = " ";
const UA_NAME_SEPARATOR = "/";
const UA_NAME_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w]/g;
const UA_VALUE_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w#]/g;
const UA_ESCAPE_CHAR = "-";

//#endregion
//#region node_modules/@aws-sdk/middleware-user-agent/dist-es/encode-features.js
const BYTE_LIMIT = 1024;
function encodeFeatures(features) {
	let buffer = "";
	for (const key in features) {
		const val = features[key];
		if (buffer.length + val.length + 1 <= BYTE_LIMIT) {
			if (buffer.length) buffer += "," + val;
			else buffer += val;
			continue;
		}
		break;
	}
	return buffer;
}

//#endregion
//#region node_modules/@aws-sdk/middleware-user-agent/dist-es/user-agent-middleware.js
const userAgentMiddleware = (options) => (next, context) => async (args) => {
	const { request } = args;
	if (!HttpRequest.isInstance(request)) return next(args);
	const { headers } = request;
	const userAgent = context?.userAgent?.map(escapeUserAgent) || [];
	const defaultUserAgent = (await options.defaultUserAgentProvider()).map(escapeUserAgent);
	await checkFeatures(context, options, args);
	const awsContext = context;
	defaultUserAgent.push(`m/${encodeFeatures(Object.assign({}, context.__smithy_context?.features, awsContext.__aws_sdk_context?.features))}`);
	const customUserAgent = options?.customUserAgent?.map(escapeUserAgent) || [];
	const appId = await options.userAgentAppId();
	if (appId) defaultUserAgent.push(escapeUserAgent([`app`, `${appId}`]));
	const prefix = getUserAgentPrefix();
	const sdkUserAgentValue = (prefix ? [prefix] : []).concat([
		...defaultUserAgent,
		...userAgent,
		...customUserAgent
	]).join(SPACE);
	const normalUAValue = [...defaultUserAgent.filter((section) => section.startsWith("aws-sdk-")), ...customUserAgent].join(SPACE);
	if (options.runtime !== "browser") {
		if (normalUAValue) headers[X_AMZ_USER_AGENT] = headers[X_AMZ_USER_AGENT] ? `${headers[USER_AGENT]} ${normalUAValue}` : normalUAValue;
		headers[USER_AGENT] = sdkUserAgentValue;
	} else headers[X_AMZ_USER_AGENT] = sdkUserAgentValue;
	return next({
		...args,
		request
	});
};
const escapeUserAgent = (userAgentPair) => {
	const name = userAgentPair[0].split(UA_NAME_SEPARATOR).map((part) => part.replace(UA_NAME_ESCAPE_REGEX, UA_ESCAPE_CHAR)).join(UA_NAME_SEPARATOR);
	const version$2 = userAgentPair[1]?.replace(UA_VALUE_ESCAPE_REGEX, UA_ESCAPE_CHAR);
	const prefixSeparatorIndex = name.indexOf(UA_NAME_SEPARATOR);
	const prefix = name.substring(0, prefixSeparatorIndex);
	let uaName = name.substring(prefixSeparatorIndex + 1);
	if (prefix === "api") uaName = uaName.toLowerCase();
	return [
		prefix,
		uaName,
		version$2
	].filter((item) => item && item.length > 0).reduce((acc, item, index) => {
		switch (index) {
			case 0: return item;
			case 1: return `${acc}/${item}`;
			default: return `${acc}#${item}`;
		}
	}, "");
};
const getUserAgentMiddlewareOptions = {
	name: "getUserAgentMiddleware",
	step: "build",
	priority: "low",
	tags: ["SET_USER_AGENT", "USER_AGENT"],
	override: true
};
const getUserAgentPlugin = (config) => ({ applyToStack: (clientStack) => {
	clientStack.add(userAgentMiddleware(config), getUserAgentMiddlewareOptions);
} });

//#endregion
//#region node_modules/@smithy/config-resolver/dist-es/endpointsConfig/NodeUseDualstackEndpointConfigOptions.js
const DEFAULT_USE_DUALSTACK_ENDPOINT = false;

//#endregion
//#region node_modules/@smithy/config-resolver/dist-es/endpointsConfig/NodeUseFipsEndpointConfigOptions.js
const DEFAULT_USE_FIPS_ENDPOINT = false;

//#endregion
//#region node_modules/@smithy/config-resolver/dist-es/regionConfig/checkRegion.js
const validRegions = /* @__PURE__ */ new Set();
const checkRegion = (region, check = isValidHostLabel) => {
	if (!validRegions.has(region) && !check(region)) if (region === "*") console.warn(`@smithy/config-resolver WARN - Please use the caller region instead of "*". See "sigv4a" in https://github.com/aws/aws-sdk-js-v3/blob/main/supplemental-docs/CLIENTS.md.`);
	else throw new Error(`Region not accepted: region="${region}" is not a valid hostname component.`);
	else validRegions.add(region);
};

//#endregion
//#region node_modules/@smithy/config-resolver/dist-es/regionConfig/isFipsRegion.js
const isFipsRegion = (region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips"));

//#endregion
//#region node_modules/@smithy/config-resolver/dist-es/regionConfig/getRealRegion.js
const getRealRegion = (region) => isFipsRegion(region) ? ["fips-aws-global", "aws-fips"].includes(region) ? "us-east-1" : region.replace(/fips-(dkr-|prod-)?|-fips/, "") : region;

//#endregion
//#region node_modules/@smithy/config-resolver/dist-es/regionConfig/resolveRegionConfig.js
const resolveRegionConfig = (input) => {
	const { region, useFipsEndpoint } = input;
	if (!region) throw new Error("Region is missing");
	return Object.assign(input, {
		region: async () => {
			const realRegion = getRealRegion(typeof region === "function" ? await region() : region);
			checkRegion(realRegion);
			return realRegion;
		},
		useFipsEndpoint: async () => {
			if (isFipsRegion(typeof region === "string" ? region : await region())) return true;
			return typeof useFipsEndpoint !== "function" ? Promise.resolve(!!useFipsEndpoint) : useFipsEndpoint();
		}
	});
};

//#endregion
//#region node_modules/@smithy/middleware-content-length/dist-es/index.js
const CONTENT_LENGTH_HEADER = "content-length";
function contentLengthMiddleware(bodyLengthChecker) {
	return (next) => async (args) => {
		const request = args.request;
		if (HttpRequest.isInstance(request)) {
			const { body, headers } = request;
			if (body && Object.keys(headers).map((str) => str.toLowerCase()).indexOf(CONTENT_LENGTH_HEADER) === -1) try {
				const length = bodyLengthChecker(body);
				request.headers = {
					...request.headers,
					[CONTENT_LENGTH_HEADER]: String(length)
				};
			} catch (error) {}
		}
		return next({
			...args,
			request
		});
	};
}
const contentLengthMiddlewareOptions = {
	step: "build",
	tags: ["SET_CONTENT_LENGTH", "CONTENT_LENGTH"],
	name: "contentLengthMiddleware",
	override: true
};
const getContentLengthPlugin = (options) => ({ applyToStack: (clientStack) => {
	clientStack.add(contentLengthMiddleware(options.bodyLengthChecker), contentLengthMiddlewareOptions);
} });

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-es/service-customizations/s3.js
const resolveParamsForS3 = async (endpointParams) => {
	const bucket = endpointParams?.Bucket || "";
	if (typeof endpointParams.Bucket === "string") endpointParams.Bucket = bucket.replace(/#/g, encodeURIComponent("#")).replace(/\?/g, encodeURIComponent("?"));
	if (isArnBucketName(bucket)) {
		if (endpointParams.ForcePathStyle === true) throw new Error("Path-style addressing cannot be used with ARN buckets");
	} else if (!isDnsCompatibleBucketName(bucket) || bucket.indexOf(".") !== -1 && !String(endpointParams.Endpoint).startsWith("http:") || bucket.toLowerCase() !== bucket || bucket.length < 3) endpointParams.ForcePathStyle = true;
	if (endpointParams.DisableMultiRegionAccessPoints) {
		endpointParams.disableMultiRegionAccessPoints = true;
		endpointParams.DisableMRAP = true;
	}
	return endpointParams;
};
const DOMAIN_PATTERN = /^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$/;
const IP_ADDRESS_PATTERN = /(\d+\.){3}\d+/;
const DOTS_PATTERN = /\.\./;
const isDnsCompatibleBucketName = (bucketName) => DOMAIN_PATTERN.test(bucketName) && !IP_ADDRESS_PATTERN.test(bucketName) && !DOTS_PATTERN.test(bucketName);
const isArnBucketName = (bucketName) => {
	const [arn, partition$1, service, , , bucket] = bucketName.split(":");
	const isArn = arn === "arn" && bucketName.split(":").length >= 6;
	const isValidArn = Boolean(isArn && partition$1 && service && bucket);
	if (isArn && !isValidArn) throw new Error(`Invalid ARN: ${bucketName} was an invalid ARN.`);
	return isValidArn;
};

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-es/adaptors/createConfigValueProvider.js
const createConfigValueProvider = (configKey, canonicalEndpointParamKey, config, isClientContextParam = false) => {
	const configProvider = async () => {
		let configValue;
		if (isClientContextParam) configValue = config.clientContextParams?.[configKey] ?? config[configKey] ?? config[canonicalEndpointParamKey];
		else configValue = config[configKey] ?? config[canonicalEndpointParamKey];
		if (typeof configValue === "function") return configValue();
		return configValue;
	};
	if (configKey === "credentialScope" || canonicalEndpointParamKey === "CredentialScope") return async () => {
		const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
		return credentials?.credentialScope ?? credentials?.CredentialScope;
	};
	if (configKey === "accountId" || canonicalEndpointParamKey === "AccountId") return async () => {
		const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
		return credentials?.accountId ?? credentials?.AccountId;
	};
	if (configKey === "endpoint" || canonicalEndpointParamKey === "endpoint") return async () => {
		if (config.isCustomEndpoint === false) return;
		const endpoint = await configProvider();
		if (endpoint && typeof endpoint === "object") {
			if ("url" in endpoint) return endpoint.url.href;
			if ("hostname" in endpoint) {
				const { protocol, hostname, port, path } = endpoint;
				return `${protocol}//${hostname}${port ? ":" + port : ""}${path}`;
			}
		}
		return endpoint;
	};
	return configProvider;
};

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointFromConfig.browser.js
const getEndpointFromConfig = async (serviceId) => void 0;

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-es/adaptors/toEndpointV1.js
const toEndpointV1 = (endpoint) => {
	if (typeof endpoint === "object") {
		if ("url" in endpoint) return parseUrl(endpoint.url);
		return endpoint;
	}
	return parseUrl(endpoint);
};

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointFromInstructions.js
const getEndpointFromInstructions = async (commandInput, instructionsSupplier, clientConfig, context) => {
	if (!clientConfig.isCustomEndpoint) {
		let endpointFromConfig;
		if (clientConfig.serviceConfiguredEndpoint) endpointFromConfig = await clientConfig.serviceConfiguredEndpoint();
		else endpointFromConfig = await getEndpointFromConfig(clientConfig.serviceId);
		if (endpointFromConfig) {
			clientConfig.endpoint = () => Promise.resolve(toEndpointV1(endpointFromConfig));
			clientConfig.isCustomEndpoint = true;
		}
	}
	const endpointParams = await resolveParams(commandInput, instructionsSupplier, clientConfig);
	if (typeof clientConfig.endpointProvider !== "function") throw new Error("config.endpointProvider is not set.");
	return clientConfig.endpointProvider(endpointParams, context);
};
const resolveParams = async (commandInput, instructionsSupplier, clientConfig) => {
	const endpointParams = {};
	const instructions = instructionsSupplier?.getEndpointParameterInstructions?.() || {};
	for (const [name, instruction] of Object.entries(instructions)) switch (instruction.type) {
		case "staticContextParams":
			endpointParams[name] = instruction.value;
			break;
		case "contextParams":
			endpointParams[name] = commandInput[instruction.name];
			break;
		case "clientContextParams":
		case "builtInParams":
			endpointParams[name] = await createConfigValueProvider(instruction.name, name, clientConfig, instruction.type !== "builtInParams")();
			break;
		case "operationContextParams":
			endpointParams[name] = instruction.get(commandInput);
			break;
		default: throw new Error("Unrecognized endpoint parameter instruction: " + JSON.stringify(instruction));
	}
	if (Object.keys(instructions).length === 0) Object.assign(endpointParams, clientConfig);
	if (String(clientConfig.serviceId).toLowerCase() === "s3") await resolveParamsForS3(endpointParams);
	return endpointParams;
};

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-es/endpointMiddleware.js
const endpointMiddleware = ({ config, instructions }) => {
	return (next, context) => async (args) => {
		if (config.isCustomEndpoint) setFeature$1(context, "ENDPOINT_OVERRIDE", "N");
		const endpoint = await getEndpointFromInstructions(args.input, { getEndpointParameterInstructions() {
			return instructions;
		} }, { ...config }, context);
		context.endpointV2 = endpoint;
		context.authSchemes = endpoint.properties?.authSchemes;
		const authScheme = context.authSchemes?.[0];
		if (authScheme) {
			context["signing_region"] = authScheme.signingRegion;
			context["signing_service"] = authScheme.signingName;
			const httpAuthOption = getSmithyContext(context)?.selectedHttpAuthScheme?.httpAuthOption;
			if (httpAuthOption) httpAuthOption.signingProperties = Object.assign(httpAuthOption.signingProperties || {}, {
				signing_region: authScheme.signingRegion,
				signingRegion: authScheme.signingRegion,
				signing_service: authScheme.signingName,
				signingName: authScheme.signingName,
				signingRegionSet: authScheme.signingRegionSet
			}, authScheme.properties);
		}
		return next({ ...args });
	};
};

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-es/getEndpointPlugin.js
const endpointMiddlewareOptions = {
	step: "serialize",
	tags: [
		"ENDPOINT_PARAMETERS",
		"ENDPOINT_V2",
		"ENDPOINT"
	],
	name: "endpointV2Middleware",
	override: true,
	relation: "before",
	toMiddleware: serializerMiddlewareOption$1.name
};
const getEndpointPlugin = (config, instructions) => ({ applyToStack: (clientStack) => {
	clientStack.addRelativeTo(endpointMiddleware({
		config,
		instructions
	}), endpointMiddlewareOptions);
} });

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-es/resolveEndpointConfig.js
const resolveEndpointConfig = (input) => {
	const tls = input.tls ?? true;
	const { endpoint, useDualstackEndpoint, useFipsEndpoint } = input;
	const customEndpointProvider = endpoint != null ? async () => toEndpointV1(await normalizeProvider$1(endpoint)()) : void 0;
	const isCustomEndpoint = !!endpoint;
	const resolvedConfig = Object.assign(input, {
		endpoint: customEndpointProvider,
		tls,
		isCustomEndpoint,
		useDualstackEndpoint: normalizeProvider$1(useDualstackEndpoint ?? false),
		useFipsEndpoint: normalizeProvider$1(useFipsEndpoint ?? false)
	});
	let configuredEndpointPromise = void 0;
	resolvedConfig.serviceConfiguredEndpoint = async () => {
		if (input.serviceId && !configuredEndpointPromise) configuredEndpointPromise = getEndpointFromConfig(input.serviceId);
		return configuredEndpointPromise;
	};
	return resolvedConfig;
};

//#endregion
//#region node_modules/@smithy/util-retry/dist-es/config.js
var RETRY_MODES;
(function(RETRY_MODES$1) {
	RETRY_MODES$1["STANDARD"] = "standard";
	RETRY_MODES$1["ADAPTIVE"] = "adaptive";
})(RETRY_MODES || (RETRY_MODES = {}));
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_RETRY_MODE = RETRY_MODES.STANDARD;

//#endregion
//#region node_modules/@smithy/service-error-classification/dist-es/constants.js
const THROTTLING_ERROR_CODES = [
	"BandwidthLimitExceeded",
	"EC2ThrottledException",
	"LimitExceededException",
	"PriorRequestNotComplete",
	"ProvisionedThroughputExceededException",
	"RequestLimitExceeded",
	"RequestThrottled",
	"RequestThrottledException",
	"SlowDown",
	"ThrottledException",
	"Throttling",
	"ThrottlingException",
	"TooManyRequestsException",
	"TransactionInProgressException"
];
const TRANSIENT_ERROR_CODES = [
	"TimeoutError",
	"RequestTimeout",
	"RequestTimeoutException"
];
const TRANSIENT_ERROR_STATUS_CODES = [
	500,
	502,
	503,
	504
];
const NODEJS_TIMEOUT_ERROR_CODES = [
	"ECONNRESET",
	"ECONNREFUSED",
	"EPIPE",
	"ETIMEDOUT"
];
const NODEJS_NETWORK_ERROR_CODES = [
	"EHOSTUNREACH",
	"ENETUNREACH",
	"ENOTFOUND"
];

//#endregion
//#region node_modules/@smithy/service-error-classification/dist-es/index.js
const isRetryableByTrait = (error) => error?.$retryable !== void 0;
const isClockSkewCorrectedError = (error) => error.$metadata?.clockSkewCorrected;
const isBrowserNetworkError = (error) => {
	const errorMessages = new Set([
		"Failed to fetch",
		"NetworkError when attempting to fetch resource",
		"The Internet connection appears to be offline",
		"Load failed",
		"Network request failed"
	]);
	if (!(error && error instanceof TypeError)) return false;
	return errorMessages.has(error.message);
};
const isThrottlingError = (error) => error.$metadata?.httpStatusCode === 429 || THROTTLING_ERROR_CODES.includes(error.name) || error.$retryable?.throttling == true;
const isTransientError = (error, depth = 0) => isRetryableByTrait(error) || isClockSkewCorrectedError(error) || TRANSIENT_ERROR_CODES.includes(error.name) || NODEJS_TIMEOUT_ERROR_CODES.includes(error?.code || "") || NODEJS_NETWORK_ERROR_CODES.includes(error?.code || "") || TRANSIENT_ERROR_STATUS_CODES.includes(error.$metadata?.httpStatusCode || 0) || isBrowserNetworkError(error) || error.cause !== void 0 && depth <= 10 && isTransientError(error.cause, depth + 1);
const isServerError = (error) => {
	if (error.$metadata?.httpStatusCode !== void 0) {
		const statusCode = error.$metadata.httpStatusCode;
		if (500 <= statusCode && statusCode <= 599 && !isTransientError(error)) return true;
		return false;
	}
	return false;
};

//#endregion
//#region node_modules/@smithy/util-retry/dist-es/DefaultRateLimiter.js
var DefaultRateLimiter = class DefaultRateLimiter {
	static setTimeoutFn = setTimeout;
	beta;
	minCapacity;
	minFillRate;
	scaleConstant;
	smooth;
	currentCapacity = 0;
	enabled = false;
	lastMaxRate = 0;
	measuredTxRate = 0;
	requestCount = 0;
	fillRate;
	lastThrottleTime;
	lastTimestamp = 0;
	lastTxRateBucket;
	maxCapacity;
	timeWindow = 0;
	constructor(options) {
		this.beta = options?.beta ?? .7;
		this.minCapacity = options?.minCapacity ?? 1;
		this.minFillRate = options?.minFillRate ?? .5;
		this.scaleConstant = options?.scaleConstant ?? .4;
		this.smooth = options?.smooth ?? .8;
		this.lastThrottleTime = this.getCurrentTimeInSeconds();
		this.lastTxRateBucket = Math.floor(this.getCurrentTimeInSeconds());
		this.fillRate = this.minFillRate;
		this.maxCapacity = this.minCapacity;
	}
	getCurrentTimeInSeconds() {
		return Date.now() / 1e3;
	}
	async getSendToken() {
		return this.acquireTokenBucket(1);
	}
	async acquireTokenBucket(amount) {
		if (!this.enabled) return;
		this.refillTokenBucket();
		if (amount > this.currentCapacity) {
			const delay = (amount - this.currentCapacity) / this.fillRate * 1e3;
			await new Promise((resolve) => DefaultRateLimiter.setTimeoutFn(resolve, delay));
		}
		this.currentCapacity = this.currentCapacity - amount;
	}
	refillTokenBucket() {
		const timestamp = this.getCurrentTimeInSeconds();
		if (!this.lastTimestamp) {
			this.lastTimestamp = timestamp;
			return;
		}
		const fillAmount = (timestamp - this.lastTimestamp) * this.fillRate;
		this.currentCapacity = Math.min(this.maxCapacity, this.currentCapacity + fillAmount);
		this.lastTimestamp = timestamp;
	}
	updateClientSendingRate(response) {
		let calculatedRate;
		this.updateMeasuredRate();
		if (isThrottlingError(response)) {
			const rateToUse = !this.enabled ? this.measuredTxRate : Math.min(this.measuredTxRate, this.fillRate);
			this.lastMaxRate = rateToUse;
			this.calculateTimeWindow();
			this.lastThrottleTime = this.getCurrentTimeInSeconds();
			calculatedRate = this.cubicThrottle(rateToUse);
			this.enableTokenBucket();
		} else {
			this.calculateTimeWindow();
			calculatedRate = this.cubicSuccess(this.getCurrentTimeInSeconds());
		}
		const newRate = Math.min(calculatedRate, 2 * this.measuredTxRate);
		this.updateTokenBucketRate(newRate);
	}
	calculateTimeWindow() {
		this.timeWindow = this.getPrecise(Math.pow(this.lastMaxRate * (1 - this.beta) / this.scaleConstant, 1 / 3));
	}
	cubicThrottle(rateToUse) {
		return this.getPrecise(rateToUse * this.beta);
	}
	cubicSuccess(timestamp) {
		return this.getPrecise(this.scaleConstant * Math.pow(timestamp - this.lastThrottleTime - this.timeWindow, 3) + this.lastMaxRate);
	}
	enableTokenBucket() {
		this.enabled = true;
	}
	updateTokenBucketRate(newRate) {
		this.refillTokenBucket();
		this.fillRate = Math.max(newRate, this.minFillRate);
		this.maxCapacity = Math.max(newRate, this.minCapacity);
		this.currentCapacity = Math.min(this.currentCapacity, this.maxCapacity);
	}
	updateMeasuredRate() {
		const t$1 = this.getCurrentTimeInSeconds();
		const timeBucket = Math.floor(t$1 * 2) / 2;
		this.requestCount++;
		if (timeBucket > this.lastTxRateBucket) {
			const currentRate = this.requestCount / (timeBucket - this.lastTxRateBucket);
			this.measuredTxRate = this.getPrecise(currentRate * this.smooth + this.measuredTxRate * (1 - this.smooth));
			this.requestCount = 0;
			this.lastTxRateBucket = timeBucket;
		}
	}
	getPrecise(num) {
		return parseFloat(num.toFixed(8));
	}
};

//#endregion
//#region node_modules/@smithy/util-retry/dist-es/constants.js
const DEFAULT_RETRY_DELAY_BASE = 100;
const MAXIMUM_RETRY_DELAY = 20 * 1e3;
const THROTTLING_RETRY_DELAY_BASE = 500;
const INITIAL_RETRY_TOKENS = 500;
const RETRY_COST = 5;
const TIMEOUT_RETRY_COST = 10;
const NO_RETRY_INCREMENT = 1;
const INVOCATION_ID_HEADER = "amz-sdk-invocation-id";
const REQUEST_HEADER = "amz-sdk-request";

//#endregion
//#region node_modules/@smithy/util-retry/dist-es/defaultRetryBackoffStrategy.js
const getDefaultRetryBackoffStrategy = () => {
	let delayBase = DEFAULT_RETRY_DELAY_BASE;
	const computeNextBackoffDelay = (attempts) => {
		return Math.floor(Math.min(MAXIMUM_RETRY_DELAY, Math.random() * 2 ** attempts * delayBase));
	};
	const setDelayBase = (delay) => {
		delayBase = delay;
	};
	return {
		computeNextBackoffDelay,
		setDelayBase
	};
};

//#endregion
//#region node_modules/@smithy/util-retry/dist-es/defaultRetryToken.js
const createDefaultRetryToken = ({ retryDelay, retryCount, retryCost }) => {
	const getRetryCount = () => retryCount;
	const getRetryDelay = () => Math.min(MAXIMUM_RETRY_DELAY, retryDelay);
	const getRetryCost = () => retryCost;
	return {
		getRetryCount,
		getRetryDelay,
		getRetryCost
	};
};

//#endregion
//#region node_modules/@smithy/util-retry/dist-es/StandardRetryStrategy.js
var StandardRetryStrategy = class {
	maxAttempts;
	mode = RETRY_MODES.STANDARD;
	capacity = INITIAL_RETRY_TOKENS;
	retryBackoffStrategy = getDefaultRetryBackoffStrategy();
	maxAttemptsProvider;
	constructor(maxAttempts) {
		this.maxAttempts = maxAttempts;
		this.maxAttemptsProvider = typeof maxAttempts === "function" ? maxAttempts : async () => maxAttempts;
	}
	async acquireInitialRetryToken(retryTokenScope) {
		return createDefaultRetryToken({
			retryDelay: DEFAULT_RETRY_DELAY_BASE,
			retryCount: 0
		});
	}
	async refreshRetryTokenForRetry(token, errorInfo) {
		const maxAttempts = await this.getMaxAttempts();
		if (this.shouldRetry(token, errorInfo, maxAttempts)) {
			const errorType = errorInfo.errorType;
			this.retryBackoffStrategy.setDelayBase(errorType === "THROTTLING" ? THROTTLING_RETRY_DELAY_BASE : DEFAULT_RETRY_DELAY_BASE);
			const delayFromErrorType = this.retryBackoffStrategy.computeNextBackoffDelay(token.getRetryCount());
			const retryDelay = errorInfo.retryAfterHint ? Math.max(errorInfo.retryAfterHint.getTime() - Date.now() || 0, delayFromErrorType) : delayFromErrorType;
			const capacityCost = this.getCapacityCost(errorType);
			this.capacity -= capacityCost;
			return createDefaultRetryToken({
				retryDelay,
				retryCount: token.getRetryCount() + 1,
				retryCost: capacityCost
			});
		}
		throw new Error("No retry token available");
	}
	recordSuccess(token) {
		this.capacity = Math.max(INITIAL_RETRY_TOKENS, this.capacity + (token.getRetryCost() ?? NO_RETRY_INCREMENT));
	}
	getCapacity() {
		return this.capacity;
	}
	async getMaxAttempts() {
		try {
			return await this.maxAttemptsProvider();
		} catch (error) {
			console.warn(`Max attempts provider could not resolve. Using default of ${DEFAULT_MAX_ATTEMPTS}`);
			return DEFAULT_MAX_ATTEMPTS;
		}
	}
	shouldRetry(tokenToRenew, errorInfo, maxAttempts) {
		return tokenToRenew.getRetryCount() + 1 < maxAttempts && this.capacity >= this.getCapacityCost(errorInfo.errorType) && this.isRetryableError(errorInfo.errorType);
	}
	getCapacityCost(errorType) {
		return errorType === "TRANSIENT" ? TIMEOUT_RETRY_COST : RETRY_COST;
	}
	isRetryableError(errorType) {
		return errorType === "THROTTLING" || errorType === "TRANSIENT";
	}
};

//#endregion
//#region node_modules/@smithy/util-retry/dist-es/AdaptiveRetryStrategy.js
var AdaptiveRetryStrategy = class {
	maxAttemptsProvider;
	rateLimiter;
	standardRetryStrategy;
	mode = RETRY_MODES.ADAPTIVE;
	constructor(maxAttemptsProvider, options) {
		this.maxAttemptsProvider = maxAttemptsProvider;
		const { rateLimiter } = options ?? {};
		this.rateLimiter = rateLimiter ?? new DefaultRateLimiter();
		this.standardRetryStrategy = new StandardRetryStrategy(maxAttemptsProvider);
	}
	async acquireInitialRetryToken(retryTokenScope) {
		await this.rateLimiter.getSendToken();
		return this.standardRetryStrategy.acquireInitialRetryToken(retryTokenScope);
	}
	async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
		this.rateLimiter.updateClientSendingRate(errorInfo);
		return this.standardRetryStrategy.refreshRetryTokenForRetry(tokenToRenew, errorInfo);
	}
	recordSuccess(token) {
		this.rateLimiter.updateClientSendingRate({});
		this.standardRetryStrategy.recordSuccess(token);
	}
};

//#endregion
//#region node_modules/@smithy/middleware-retry/dist-es/util.js
const asSdkError = (error) => {
	if (error instanceof Error) return error;
	if (error instanceof Object) return Object.assign(/* @__PURE__ */ new Error(), error);
	if (typeof error === "string") return new Error(error);
	return /* @__PURE__ */ new Error(`AWS SDK error wrapper for ${error}`);
};

//#endregion
//#region node_modules/@smithy/middleware-retry/dist-es/configurations.js
const resolveRetryConfig = (input) => {
	const { retryStrategy, retryMode: _retryMode, maxAttempts: _maxAttempts } = input;
	const maxAttempts = normalizeProvider$1(_maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
	return Object.assign(input, {
		maxAttempts,
		retryStrategy: async () => {
			if (retryStrategy) return retryStrategy;
			if (await normalizeProvider$1(_retryMode)() === RETRY_MODES.ADAPTIVE) return new AdaptiveRetryStrategy(maxAttempts);
			return new StandardRetryStrategy(maxAttempts);
		}
	});
};

//#endregion
//#region node_modules/@smithy/middleware-retry/dist-es/isStreamingPayload/isStreamingPayload.browser.js
const isStreamingPayload = (request) => request?.body instanceof ReadableStream;

//#endregion
//#region node_modules/@smithy/middleware-retry/dist-es/retryMiddleware.js
const retryMiddleware = (options) => (next, context) => async (args) => {
	let retryStrategy = await options.retryStrategy();
	const maxAttempts = await options.maxAttempts();
	if (isRetryStrategyV2(retryStrategy)) {
		retryStrategy = retryStrategy;
		let retryToken = await retryStrategy.acquireInitialRetryToken(context["partition_id"]);
		let lastError = /* @__PURE__ */ new Error();
		let attempts = 0;
		let totalRetryDelay = 0;
		const { request } = args;
		const isRequest = HttpRequest.isInstance(request);
		if (isRequest) request.headers[INVOCATION_ID_HEADER] = v4();
		while (true) try {
			if (isRequest) request.headers[REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
			const { response, output } = await next(args);
			retryStrategy.recordSuccess(retryToken);
			output.$metadata.attempts = attempts + 1;
			output.$metadata.totalRetryDelay = totalRetryDelay;
			return {
				response,
				output
			};
		} catch (e$1) {
			const retryErrorInfo = getRetryErrorInfo(e$1);
			lastError = asSdkError(e$1);
			if (isRequest && isStreamingPayload(request)) {
				(context.logger instanceof NoOpLogger ? console : context.logger)?.warn("An error was encountered in a non-retryable streaming request.");
				throw lastError;
			}
			try {
				retryToken = await retryStrategy.refreshRetryTokenForRetry(retryToken, retryErrorInfo);
			} catch (refreshError) {
				if (!lastError.$metadata) lastError.$metadata = {};
				lastError.$metadata.attempts = attempts + 1;
				lastError.$metadata.totalRetryDelay = totalRetryDelay;
				throw lastError;
			}
			attempts = retryToken.getRetryCount();
			const delay = retryToken.getRetryDelay();
			totalRetryDelay += delay;
			await new Promise((resolve) => setTimeout(resolve, delay));
		}
	} else {
		retryStrategy = retryStrategy;
		if (retryStrategy?.mode) context.userAgent = [...context.userAgent || [], ["cfg/retry-mode", retryStrategy.mode]];
		return retryStrategy.retry(next, args);
	}
};
const isRetryStrategyV2 = (retryStrategy) => typeof retryStrategy.acquireInitialRetryToken !== "undefined" && typeof retryStrategy.refreshRetryTokenForRetry !== "undefined" && typeof retryStrategy.recordSuccess !== "undefined";
const getRetryErrorInfo = (error) => {
	const errorInfo = {
		error,
		errorType: getRetryErrorType(error)
	};
	const retryAfterHint = getRetryAfterHint(error.$response);
	if (retryAfterHint) errorInfo.retryAfterHint = retryAfterHint;
	return errorInfo;
};
const getRetryErrorType = (error) => {
	if (isThrottlingError(error)) return "THROTTLING";
	if (isTransientError(error)) return "TRANSIENT";
	if (isServerError(error)) return "SERVER_ERROR";
	return "CLIENT_ERROR";
};
const retryMiddlewareOptions = {
	name: "retryMiddleware",
	tags: ["RETRY"],
	step: "finalizeRequest",
	priority: "high",
	override: true
};
const getRetryPlugin = (options) => ({ applyToStack: (clientStack) => {
	clientStack.add(retryMiddleware(options), retryMiddlewareOptions);
} });
const getRetryAfterHint = (response) => {
	if (!HttpResponse.isInstance(response)) return;
	const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
	if (!retryAfterHeaderName) return;
	const retryAfter = response.headers[retryAfterHeaderName];
	const retryAfterSeconds = Number(retryAfter);
	if (!Number.isNaN(retryAfterSeconds)) return /* @__PURE__ */ new Date(retryAfterSeconds * 1e3);
	return new Date(retryAfter);
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/auth/httpAuthSchemeProvider.js
const defaultSTSHttpAuthSchemeParametersProvider = async (config, context, input) => {
	return {
		operation: getSmithyContext(context).operation,
		region: await normalizeProvider$1(config.region)() || (() => {
			throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
		})()
	};
};
function createAwsAuthSigv4HttpAuthOption(authParameters) {
	return {
		schemeId: "aws.auth#sigv4",
		signingProperties: {
			name: "sts",
			region: authParameters.region
		},
		propertiesExtractor: (config, context) => ({ signingProperties: {
			config,
			context
		} })
	};
}
function createSmithyApiNoAuthHttpAuthOption(authParameters) {
	return { schemeId: "smithy.api#noAuth" };
}
const defaultSTSHttpAuthSchemeProvider = (authParameters) => {
	const options = [];
	switch (authParameters.operation) {
		case "AssumeRoleWithSAML":
			options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
			break;
		case "AssumeRoleWithWebIdentity":
			options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
			break;
		default: options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
	}
	return options;
};
const resolveStsAuthConfig = (input) => Object.assign(input, { stsClientCtor: STSClient });
const resolveHttpAuthSchemeConfig = (config) => {
	const config_1 = resolveAwsSdkSigV4Config(resolveStsAuthConfig(config));
	return Object.assign(config_1, { authSchemePreference: normalizeProvider$1(config.authSchemePreference ?? []) });
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/endpoint/EndpointParameters.js
const resolveClientEndpointParameters = (options) => {
	return Object.assign(options, {
		useDualstackEndpoint: options.useDualstackEndpoint ?? false,
		useFipsEndpoint: options.useFipsEndpoint ?? false,
		useGlobalEndpoint: options.useGlobalEndpoint ?? false,
		defaultSigningName: "sts"
	});
};
const commonParams = {
	UseGlobalEndpoint: {
		type: "builtInParams",
		name: "useGlobalEndpoint"
	},
	UseFIPS: {
		type: "builtInParams",
		name: "useFipsEndpoint"
	},
	Endpoint: {
		type: "builtInParams",
		name: "endpoint"
	},
	Region: {
		type: "builtInParams",
		name: "region"
	},
	UseDualStack: {
		type: "builtInParams",
		name: "useDualstackEndpoint"
	}
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/package.json
var version = "3.958.0";

//#endregion
//#region node_modules/@aws-crypto/util/node_modules/@smithy/util-utf8/dist-es/fromUtf8.browser.js
const fromUtf8$1 = (input) => new TextEncoder().encode(input);

//#endregion
//#region node_modules/@aws-crypto/util/build/module/convertToBuffer.js
var fromUtf8 = typeof Buffer !== "undefined" && Buffer.from ? function(input) {
	return Buffer.from(input, "utf8");
} : fromUtf8$1;
function convertToBuffer(data) {
	if (data instanceof Uint8Array) return data;
	if (typeof data === "string") return fromUtf8(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
	return new Uint8Array(data);
}

//#endregion
//#region node_modules/@aws-crypto/util/build/module/isEmptyData.js
function isEmptyData(data) {
	if (typeof data === "string") return data.length === 0;
	return data.byteLength === 0;
}

//#endregion
//#region node_modules/@aws-crypto/sha256-browser/build/module/constants.js
var SHA_256_HASH = { name: "SHA-256" };
var SHA_256_HMAC_ALGO = {
	name: "HMAC",
	hash: SHA_256_HASH
};
var EMPTY_DATA_SHA_256 = new Uint8Array([
	227,
	176,
	196,
	66,
	152,
	252,
	28,
	20,
	154,
	251,
	244,
	200,
	153,
	111,
	185,
	36,
	39,
	174,
	65,
	228,
	100,
	155,
	147,
	76,
	164,
	149,
	153,
	27,
	120,
	82,
	184,
	85
]);

//#endregion
//#region node_modules/@aws-sdk/util-locate-window/dist-es/index.js
const fallbackWindow = {};
function locateWindow() {
	if (typeof window !== "undefined") return window;
	else if (typeof self !== "undefined") return self;
	return fallbackWindow;
}

//#endregion
//#region node_modules/@aws-crypto/sha256-browser/build/module/webCryptoSha256.js
var Sha256$2 = function() {
	function Sha256$3(secret) {
		this.toHash = new Uint8Array(0);
		this.secret = secret;
		this.reset();
	}
	Sha256$3.prototype.update = function(data) {
		if (isEmptyData(data)) return;
		var update = convertToBuffer(data);
		var typedArray = new Uint8Array(this.toHash.byteLength + update.byteLength);
		typedArray.set(this.toHash, 0);
		typedArray.set(update, this.toHash.byteLength);
		this.toHash = typedArray;
	};
	Sha256$3.prototype.digest = function() {
		var _this = this;
		if (this.key) return this.key.then(function(key) {
			return locateWindow().crypto.subtle.sign(SHA_256_HMAC_ALGO, key, _this.toHash).then(function(data) {
				return new Uint8Array(data);
			});
		});
		if (isEmptyData(this.toHash)) return Promise.resolve(EMPTY_DATA_SHA_256);
		return Promise.resolve().then(function() {
			return locateWindow().crypto.subtle.digest(SHA_256_HASH, _this.toHash);
		}).then(function(data) {
			return Promise.resolve(new Uint8Array(data));
		});
	};
	Sha256$3.prototype.reset = function() {
		var _this = this;
		this.toHash = new Uint8Array(0);
		if (this.secret && this.secret !== void 0) {
			this.key = new Promise(function(resolve, reject) {
				locateWindow().crypto.subtle.importKey("raw", convertToBuffer(_this.secret), SHA_256_HMAC_ALGO, false, ["sign"]).then(resolve, reject);
			});
			this.key.catch(function() {});
		}
	};
	return Sha256$3;
}();

//#endregion
//#region node_modules/tslib/tslib.es6.mjs
function __awaiter(thisArg, _arguments, P, generator) {
	function adopt(value) {
		return value instanceof P ? value : new P(function(resolve) {
			resolve(value);
		});
	}
	return new (P || (P = Promise))(function(resolve, reject) {
		function fulfilled(value) {
			try {
				step(generator.next(value));
			} catch (e$1) {
				reject(e$1);
			}
		}
		function rejected(value) {
			try {
				step(generator["throw"](value));
			} catch (e$1) {
				reject(e$1);
			}
		}
		function step(result) {
			result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
		}
		step((generator = generator.apply(thisArg, _arguments || [])).next());
	});
}
function __generator(thisArg, body) {
	var _ = {
		label: 0,
		sent: function() {
			if (t$1[0] & 1) throw t$1[1];
			return t$1[1];
		},
		trys: [],
		ops: []
	}, f$1, y$1, t$1, g$1 = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
	return g$1.next = verb(0), g$1["throw"] = verb(1), g$1["return"] = verb(2), typeof Symbol === "function" && (g$1[Symbol.iterator] = function() {
		return this;
	}), g$1;
	function verb(n$1) {
		return function(v$1) {
			return step([n$1, v$1]);
		};
	}
	function step(op) {
		if (f$1) throw new TypeError("Generator is already executing.");
		while (g$1 && (g$1 = 0, op[0] && (_ = 0)), _) try {
			if (f$1 = 1, y$1 && (t$1 = op[0] & 2 ? y$1["return"] : op[0] ? y$1["throw"] || ((t$1 = y$1["return"]) && t$1.call(y$1), 0) : y$1.next) && !(t$1 = t$1.call(y$1, op[1])).done) return t$1;
			if (y$1 = 0, t$1) op = [op[0] & 2, t$1.value];
			switch (op[0]) {
				case 0:
				case 1:
					t$1 = op;
					break;
				case 4:
					_.label++;
					return {
						value: op[1],
						done: false
					};
				case 5:
					_.label++;
					y$1 = op[1];
					op = [0];
					continue;
				case 7:
					op = _.ops.pop();
					_.trys.pop();
					continue;
				default:
					if (!(t$1 = _.trys, t$1 = t$1.length > 0 && t$1[t$1.length - 1]) && (op[0] === 6 || op[0] === 2)) {
						_ = 0;
						continue;
					}
					if (op[0] === 3 && (!t$1 || op[1] > t$1[0] && op[1] < t$1[3])) {
						_.label = op[1];
						break;
					}
					if (op[0] === 6 && _.label < t$1[1]) {
						_.label = t$1[1];
						t$1 = op;
						break;
					}
					if (t$1 && _.label < t$1[2]) {
						_.label = t$1[2];
						_.ops.push(op);
						break;
					}
					if (t$1[2]) _.ops.pop();
					_.trys.pop();
					continue;
			}
			op = body.call(thisArg, _);
		} catch (e$1) {
			op = [6, e$1];
			y$1 = 0;
		} finally {
			f$1 = t$1 = 0;
		}
		if (op[0] & 5) throw op[1];
		return {
			value: op[0] ? op[1] : void 0,
			done: true
		};
	}
}

//#endregion
//#region node_modules/@aws-crypto/sha256-js/build/module/constants.js
/**
* @internal
*/
var BLOCK_SIZE = 64;
/**
* @internal
*/
var DIGEST_LENGTH = 32;
/**
* @internal
*/
var KEY = new Uint32Array([
	1116352408,
	1899447441,
	3049323471,
	3921009573,
	961987163,
	1508970993,
	2453635748,
	2870763221,
	3624381080,
	310598401,
	607225278,
	1426881987,
	1925078388,
	2162078206,
	2614888103,
	3248222580,
	3835390401,
	4022224774,
	264347078,
	604807628,
	770255983,
	1249150122,
	1555081692,
	1996064986,
	2554220882,
	2821834349,
	2952996808,
	3210313671,
	3336571891,
	3584528711,
	113926993,
	338241895,
	666307205,
	773529912,
	1294757372,
	1396182291,
	1695183700,
	1986661051,
	2177026350,
	2456956037,
	2730485921,
	2820302411,
	3259730800,
	3345764771,
	3516065817,
	3600352804,
	4094571909,
	275423344,
	430227734,
	506948616,
	659060556,
	883997877,
	958139571,
	1322822218,
	1537002063,
	1747873779,
	1955562222,
	2024104815,
	2227730452,
	2361852424,
	2428436474,
	2756734187,
	3204031479,
	3329325298
]);
/**
* @internal
*/
var INIT = [
	1779033703,
	3144134277,
	1013904242,
	2773480762,
	1359893119,
	2600822924,
	528734635,
	1541459225
];
/**
* @internal
*/
var MAX_HASHABLE_LENGTH = Math.pow(2, 53) - 1;

//#endregion
//#region node_modules/@aws-crypto/sha256-js/build/module/RawSha256.js
/**
* @internal
*/
var RawSha256 = function() {
	function RawSha256$1() {
		this.state = Int32Array.from(INIT);
		this.temp = new Int32Array(64);
		this.buffer = new Uint8Array(64);
		this.bufferLength = 0;
		this.bytesHashed = 0;
		/**
		* @internal
		*/
		this.finished = false;
	}
	RawSha256$1.prototype.update = function(data) {
		if (this.finished) throw new Error("Attempted to update an already finished hash.");
		var position = 0;
		var byteLength = data.byteLength;
		this.bytesHashed += byteLength;
		if (this.bytesHashed * 8 > MAX_HASHABLE_LENGTH) throw new Error("Cannot hash more than 2^53 - 1 bits");
		while (byteLength > 0) {
			this.buffer[this.bufferLength++] = data[position++];
			byteLength--;
			if (this.bufferLength === BLOCK_SIZE) {
				this.hashBuffer();
				this.bufferLength = 0;
			}
		}
	};
	RawSha256$1.prototype.digest = function() {
		if (!this.finished) {
			var bitsHashed = this.bytesHashed * 8;
			var bufferView = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
			var undecoratedLength = this.bufferLength;
			bufferView.setUint8(this.bufferLength++, 128);
			if (undecoratedLength % BLOCK_SIZE >= BLOCK_SIZE - 8) {
				for (var i$1 = this.bufferLength; i$1 < BLOCK_SIZE; i$1++) bufferView.setUint8(i$1, 0);
				this.hashBuffer();
				this.bufferLength = 0;
			}
			for (var i$1 = this.bufferLength; i$1 < BLOCK_SIZE - 8; i$1++) bufferView.setUint8(i$1, 0);
			bufferView.setUint32(BLOCK_SIZE - 8, Math.floor(bitsHashed / 4294967296), true);
			bufferView.setUint32(BLOCK_SIZE - 4, bitsHashed);
			this.hashBuffer();
			this.finished = true;
		}
		var out = new Uint8Array(DIGEST_LENGTH);
		for (var i$1 = 0; i$1 < 8; i$1++) {
			out[i$1 * 4] = this.state[i$1] >>> 24 & 255;
			out[i$1 * 4 + 1] = this.state[i$1] >>> 16 & 255;
			out[i$1 * 4 + 2] = this.state[i$1] >>> 8 & 255;
			out[i$1 * 4 + 3] = this.state[i$1] >>> 0 & 255;
		}
		return out;
	};
	RawSha256$1.prototype.hashBuffer = function() {
		var _a = this, buffer = _a.buffer, state = _a.state;
		var state0 = state[0], state1 = state[1], state2 = state[2], state3 = state[3], state4 = state[4], state5 = state[5], state6 = state[6], state7 = state[7];
		for (var i$1 = 0; i$1 < BLOCK_SIZE; i$1++) {
			if (i$1 < 16) this.temp[i$1] = (buffer[i$1 * 4] & 255) << 24 | (buffer[i$1 * 4 + 1] & 255) << 16 | (buffer[i$1 * 4 + 2] & 255) << 8 | buffer[i$1 * 4 + 3] & 255;
			else {
				var u$1 = this.temp[i$1 - 2];
				var t1_1 = (u$1 >>> 17 | u$1 << 15) ^ (u$1 >>> 19 | u$1 << 13) ^ u$1 >>> 10;
				u$1 = this.temp[i$1 - 15];
				var t2_1 = (u$1 >>> 7 | u$1 << 25) ^ (u$1 >>> 18 | u$1 << 14) ^ u$1 >>> 3;
				this.temp[i$1] = (t1_1 + this.temp[i$1 - 7] | 0) + (t2_1 + this.temp[i$1 - 16] | 0);
			}
			var t1 = (((state4 >>> 6 | state4 << 26) ^ (state4 >>> 11 | state4 << 21) ^ (state4 >>> 25 | state4 << 7)) + (state4 & state5 ^ ~state4 & state6) | 0) + (state7 + (KEY[i$1] + this.temp[i$1] | 0) | 0) | 0;
			var t2 = ((state0 >>> 2 | state0 << 30) ^ (state0 >>> 13 | state0 << 19) ^ (state0 >>> 22 | state0 << 10)) + (state0 & state1 ^ state0 & state2 ^ state1 & state2) | 0;
			state7 = state6;
			state6 = state5;
			state5 = state4;
			state4 = state3 + t1 | 0;
			state3 = state2;
			state2 = state1;
			state1 = state0;
			state0 = t1 + t2 | 0;
		}
		state[0] += state0;
		state[1] += state1;
		state[2] += state2;
		state[3] += state3;
		state[4] += state4;
		state[5] += state5;
		state[6] += state6;
		state[7] += state7;
	};
	return RawSha256$1;
}();

//#endregion
//#region node_modules/@aws-crypto/sha256-js/build/module/jsSha256.js
var Sha256$1 = function() {
	function Sha256$3(secret) {
		this.secret = secret;
		this.hash = new RawSha256();
		this.reset();
	}
	Sha256$3.prototype.update = function(toHash) {
		if (isEmptyData(toHash) || this.error) return;
		try {
			this.hash.update(convertToBuffer(toHash));
		} catch (e$1) {
			this.error = e$1;
		}
	};
	Sha256$3.prototype.digestSync = function() {
		if (this.error) throw this.error;
		if (this.outer) {
			if (!this.outer.finished) this.outer.update(this.hash.digest());
			return this.outer.digest();
		}
		return this.hash.digest();
	};
	Sha256$3.prototype.digest = function() {
		return __awaiter(this, void 0, void 0, function() {
			return __generator(this, function(_a) {
				return [2, this.digestSync()];
			});
		});
	};
	Sha256$3.prototype.reset = function() {
		this.hash = new RawSha256();
		if (this.secret) {
			this.outer = new RawSha256();
			var inner = bufferFromSecret(this.secret);
			var outer = new Uint8Array(BLOCK_SIZE);
			outer.set(inner);
			for (var i$1 = 0; i$1 < BLOCK_SIZE; i$1++) {
				inner[i$1] ^= 54;
				outer[i$1] ^= 92;
			}
			this.hash.update(inner);
			this.outer.update(outer);
			for (var i$1 = 0; i$1 < inner.byteLength; i$1++) inner[i$1] = 0;
		}
	};
	return Sha256$3;
}();
function bufferFromSecret(secret) {
	var input = convertToBuffer(secret);
	if (input.byteLength > BLOCK_SIZE) {
		var bufferHash = new RawSha256();
		bufferHash.update(input);
		input = bufferHash.digest();
	}
	var buffer = new Uint8Array(BLOCK_SIZE);
	buffer.set(input);
	return buffer;
}

//#endregion
//#region node_modules/@aws-crypto/supports-web-crypto/build/module/supportsWebCrypto.js
var subtleCryptoMethods = [
	"decrypt",
	"digest",
	"encrypt",
	"exportKey",
	"generateKey",
	"importKey",
	"sign",
	"verify"
];
function supportsWebCrypto(window$1) {
	if (supportsSecureRandom(window$1) && typeof window$1.crypto.subtle === "object") {
		var subtle = window$1.crypto.subtle;
		return supportsSubtleCrypto(subtle);
	}
	return false;
}
function supportsSecureRandom(window$1) {
	if (typeof window$1 === "object" && typeof window$1.crypto === "object") return typeof window$1.crypto.getRandomValues === "function";
	return false;
}
function supportsSubtleCrypto(subtle) {
	return subtle && subtleCryptoMethods.every(function(methodName) {
		return typeof subtle[methodName] === "function";
	});
}

//#endregion
//#region node_modules/@aws-crypto/sha256-browser/build/module/crossPlatformSha256.js
var Sha256 = function() {
	function Sha256$3(secret) {
		if (supportsWebCrypto(locateWindow())) this.hash = new Sha256$2(secret);
		else this.hash = new Sha256$1(secret);
	}
	Sha256$3.prototype.update = function(data, encoding) {
		this.hash.update(convertToBuffer(data));
	};
	Sha256$3.prototype.digest = function() {
		return this.hash.digest();
	};
	Sha256$3.prototype.reset = function() {
		this.hash.reset();
	};
	return Sha256$3;
}();

//#endregion
//#region node_modules/@aws-sdk/util-user-agent-browser/dist-es/index.js
const createDefaultUserAgentProvider = ({ serviceId, clientVersion }) => async (config) => {
	const navigator = typeof window !== "undefined" ? window.navigator : void 0;
	const uaString = navigator?.userAgent ?? "";
	const osName = navigator?.userAgentData?.platform ?? fallback.os(uaString) ?? "other";
	const osVersion = void 0;
	const brands = navigator?.userAgentData?.brands ?? [];
	const brand = brands[brands.length - 1];
	const browserName = brand?.brand ?? fallback.browser(uaString) ?? "unknown";
	const browserVersion = brand?.version ?? "unknown";
	const sections = [
		["aws-sdk-js", clientVersion],
		["ua", "2.1"],
		[`os/${osName}`, osVersion],
		["lang/js"],
		["md/browser", `${browserName}_${browserVersion}`]
	];
	if (serviceId) sections.push([`api/${serviceId}`, clientVersion]);
	const appId = await config?.userAgentAppId?.();
	if (appId) sections.push([`app/${appId}`]);
	return sections;
};
const fallback = {
	os(ua) {
		if (/iPhone|iPad|iPod/.test(ua)) return "iOS";
		if (/Macintosh|Mac OS X/.test(ua)) return "macOS";
		if (/Windows NT/.test(ua)) return "Windows";
		if (/Android/.test(ua)) return "Android";
		if (/Linux/.test(ua)) return "Linux";
	},
	browser(ua) {
		if (/EdgiOS|EdgA|Edg\//.test(ua)) return "Microsoft Edge";
		if (/Firefox\//.test(ua)) return "Firefox";
		if (/Chrome\//.test(ua)) return "Chrome";
		if (/Safari\//.test(ua)) return "Safari";
	}
};

//#endregion
//#region node_modules/@smithy/invalid-dependency/dist-es/invalidProvider.js
const invalidProvider = (message) => () => Promise.reject(message);

//#endregion
//#region node_modules/@smithy/util-defaults-mode-browser/dist-es/constants.js
const DEFAULTS_MODE_OPTIONS = [
	"in-region",
	"cross-region",
	"mobile",
	"standard",
	"legacy"
];

//#endregion
//#region node_modules/@smithy/util-defaults-mode-browser/dist-es/resolveDefaultsModeConfig.js
const resolveDefaultsModeConfig = ({ defaultsMode } = {}) => memoize(async () => {
	const mode = typeof defaultsMode === "function" ? await defaultsMode() : defaultsMode;
	switch (mode?.toLowerCase()) {
		case "auto": return Promise.resolve(useMobileConfiguration() ? "mobile" : "standard");
		case "mobile":
		case "in-region":
		case "cross-region":
		case "standard":
		case "legacy": return Promise.resolve(mode?.toLocaleLowerCase());
		case void 0: return Promise.resolve("legacy");
		default: throw new Error(`Invalid parameter for "defaultsMode", expect ${DEFAULTS_MODE_OPTIONS.join(", ")}, got ${mode}`);
	}
});
const useMobileConfiguration = () => {
	const navigator = window?.navigator;
	if (navigator?.connection) {
		const { effectiveType, rtt, downlink } = navigator?.connection;
		if (typeof effectiveType === "string" && effectiveType !== "4g" || Number(rtt) > 100 || Number(downlink) < 10) return true;
	}
	return navigator?.userAgentData?.mobile || typeof navigator?.maxTouchPoints === "number" && navigator?.maxTouchPoints > 1;
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/endpoint/ruleset.js
const F = "required", G = "type", H = "fn", I = "argv", J = "ref";
const a = false, b = true, c = "booleanEquals", d = "stringEquals", e = "sigv4", f = "sts", g = "us-east-1", h = "endpoint", i = "https://sts.{Region}.{PartitionResult#dnsSuffix}", j = "tree", k = "error", l = "getAttr", m = {
	[F]: false,
	[G]: "string"
}, n = {
	[F]: true,
	"default": false,
	[G]: "boolean"
}, o = { [J]: "Endpoint" }, p = {
	[H]: "isSet",
	[I]: [{ [J]: "Region" }]
}, q = { [J]: "Region" }, r = {
	[H]: "aws.partition",
	[I]: [q],
	"assign": "PartitionResult"
}, s = { [J]: "UseFIPS" }, t = { [J]: "UseDualStack" }, u = {
	"url": "https://sts.amazonaws.com",
	"properties": { "authSchemes": [{
		"name": e,
		"signingName": f,
		"signingRegion": g
	}] },
	"headers": {}
}, v = {}, w = {
	"conditions": [{
		[H]: d,
		[I]: [q, "aws-global"]
	}],
	[h]: u,
	[G]: h
}, x = {
	[H]: c,
	[I]: [s, true]
}, y = {
	[H]: c,
	[I]: [t, true]
}, z = {
	[H]: l,
	[I]: [{ [J]: "PartitionResult" }, "supportsFIPS"]
}, A = { [J]: "PartitionResult" }, B = {
	[H]: c,
	[I]: [true, {
		[H]: l,
		[I]: [A, "supportsDualStack"]
	}]
}, C = [{
	[H]: "isSet",
	[I]: [o]
}], D = [x], E = [y];
const _data = {
	version: "1.0",
	parameters: {
		Region: m,
		UseDualStack: n,
		UseFIPS: n,
		Endpoint: m,
		UseGlobalEndpoint: n
	},
	rules: [
		{
			conditions: [
				{
					[H]: c,
					[I]: [{ [J]: "UseGlobalEndpoint" }, b]
				},
				{
					[H]: "not",
					[I]: C
				},
				p,
				r,
				{
					[H]: c,
					[I]: [s, a]
				},
				{
					[H]: c,
					[I]: [t, a]
				}
			],
			rules: [
				{
					conditions: [{
						[H]: d,
						[I]: [q, "ap-northeast-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "ap-south-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "ap-southeast-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "ap-southeast-2"]
					}],
					endpoint: u,
					[G]: h
				},
				w,
				{
					conditions: [{
						[H]: d,
						[I]: [q, "ca-central-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "eu-central-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "eu-north-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "eu-west-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "eu-west-2"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "eu-west-3"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "sa-east-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, g]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "us-east-2"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "us-west-1"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					conditions: [{
						[H]: d,
						[I]: [q, "us-west-2"]
					}],
					endpoint: u,
					[G]: h
				},
				{
					endpoint: {
						url: i,
						properties: { authSchemes: [{
							name: e,
							signingName: f,
							signingRegion: "{Region}"
						}] },
						headers: v
					},
					[G]: h
				}
			],
			[G]: j
		},
		{
			conditions: C,
			rules: [
				{
					conditions: D,
					error: "Invalid Configuration: FIPS and custom endpoint are not supported",
					[G]: k
				},
				{
					conditions: E,
					error: "Invalid Configuration: Dualstack and custom endpoint are not supported",
					[G]: k
				},
				{
					endpoint: {
						url: o,
						properties: v,
						headers: v
					},
					[G]: h
				}
			],
			[G]: j
		},
		{
			conditions: [p],
			rules: [{
				conditions: [r],
				rules: [
					{
						conditions: [x, y],
						rules: [{
							conditions: [{
								[H]: c,
								[I]: [b, z]
							}, B],
							rules: [{
								endpoint: {
									url: "https://sts-fips.{Region}.{PartitionResult#dualStackDnsSuffix}",
									properties: v,
									headers: v
								},
								[G]: h
							}],
							[G]: j
						}, {
							error: "FIPS and DualStack are enabled, but this partition does not support one or both",
							[G]: k
						}],
						[G]: j
					},
					{
						conditions: D,
						rules: [{
							conditions: [{
								[H]: c,
								[I]: [z, b]
							}],
							rules: [{
								conditions: [{
									[H]: d,
									[I]: [{
										[H]: l,
										[I]: [A, "name"]
									}, "aws-us-gov"]
								}],
								endpoint: {
									url: "https://sts.{Region}.amazonaws.com",
									properties: v,
									headers: v
								},
								[G]: h
							}, {
								endpoint: {
									url: "https://sts-fips.{Region}.{PartitionResult#dnsSuffix}",
									properties: v,
									headers: v
								},
								[G]: h
							}],
							[G]: j
						}, {
							error: "FIPS is enabled but this partition does not support FIPS",
							[G]: k
						}],
						[G]: j
					},
					{
						conditions: E,
						rules: [{
							conditions: [B],
							rules: [{
								endpoint: {
									url: "https://sts.{Region}.{PartitionResult#dualStackDnsSuffix}",
									properties: v,
									headers: v
								},
								[G]: h
							}],
							[G]: j
						}, {
							error: "DualStack is enabled but this partition does not support DualStack",
							[G]: k
						}],
						[G]: j
					},
					w,
					{
						endpoint: {
							url: i,
							properties: v,
							headers: v
						},
						[G]: h
					}
				],
				[G]: j
			}],
			[G]: j
		},
		{
			error: "Invalid Configuration: Missing Region",
			[G]: k
		}
	]
};
const ruleSet = _data;

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/endpoint/endpointResolver.js
const cache = new EndpointCache({
	size: 50,
	params: [
		"Endpoint",
		"Region",
		"UseDualStack",
		"UseFIPS",
		"UseGlobalEndpoint"
	]
});
const defaultEndpointResolver = (endpointParams, context = {}) => {
	return cache.get(endpointParams, () => resolveEndpoint(ruleSet, {
		endpointParams,
		logger: context.logger
	}));
};
customEndpointFunctions.aws = awsEndpointFunctions;

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/runtimeConfig.shared.js
init_dist_es();
const getRuntimeConfig$1 = (config) => {
	return {
		apiVersion: "2011-06-15",
		base64Decoder: config?.base64Decoder ?? fromBase64,
		base64Encoder: config?.base64Encoder ?? toBase64,
		disableHostPrefix: config?.disableHostPrefix ?? false,
		endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
		extensions: config?.extensions ?? [],
		httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSTSHttpAuthSchemeProvider,
		httpAuthSchemes: config?.httpAuthSchemes ?? [{
			schemeId: "aws.auth#sigv4",
			identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
			signer: new AwsSdkSigV4Signer()
		}, {
			schemeId: "smithy.api#noAuth",
			identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
			signer: new NoAuthSigner()
		}],
		logger: config?.logger ?? new NoOpLogger(),
		protocol: config?.protocol ?? AwsQueryProtocol,
		protocolSettings: config?.protocolSettings ?? {
			defaultNamespace: "com.amazonaws.sts",
			xmlNamespace: "https://sts.amazonaws.com/doc/2011-06-15/",
			version: "2011-06-15",
			serviceTarget: "AWSSecurityTokenServiceV20110615"
		},
		serviceId: config?.serviceId ?? "STS",
		urlParser: config?.urlParser ?? parseUrl,
		utf8Decoder: config?.utf8Decoder ?? fromUtf8$2,
		utf8Encoder: config?.utf8Encoder ?? toUtf8
	};
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/runtimeConfig.browser.js
const getRuntimeConfig = (config) => {
	const defaultsMode = resolveDefaultsModeConfig(config);
	const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
	const clientSharedValues = getRuntimeConfig$1(config);
	return {
		...clientSharedValues,
		...config,
		runtime: "browser",
		defaultsMode,
		bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
		credentialDefaultProvider: config?.credentialDefaultProvider ?? ((_) => () => Promise.reject(/* @__PURE__ */ new Error("Credential is missing"))),
		defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({
			serviceId: clientSharedValues.serviceId,
			clientVersion: version
		}),
		maxAttempts: config?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
		region: config?.region ?? invalidProvider("Region is missing"),
		requestHandler: FetchHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
		retryMode: config?.retryMode ?? (async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE),
		sha256: config?.sha256 ?? Sha256,
		streamCollector: config?.streamCollector ?? streamCollector,
		useDualstackEndpoint: config?.useDualstackEndpoint ?? (() => Promise.resolve(DEFAULT_USE_DUALSTACK_ENDPOINT)),
		useFipsEndpoint: config?.useFipsEndpoint ?? (() => Promise.resolve(DEFAULT_USE_FIPS_ENDPOINT))
	};
};

//#endregion
//#region node_modules/@aws-sdk/region-config-resolver/dist-es/extensions/index.js
const getAwsRegionExtensionConfiguration = (runtimeConfig) => {
	return {
		setRegion(region) {
			runtimeConfig.region = region;
		},
		region() {
			return runtimeConfig.region;
		}
	};
};
const resolveAwsRegionExtensionConfiguration = (awsRegionExtensionConfiguration) => {
	return { region: awsRegionExtensionConfiguration.region() };
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/auth/httpAuthExtensionConfiguration.js
const getHttpAuthExtensionConfiguration = (runtimeConfig) => {
	const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
	let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
	let _credentials = runtimeConfig.credentials;
	return {
		setHttpAuthScheme(httpAuthScheme) {
			const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
			if (index === -1) _httpAuthSchemes.push(httpAuthScheme);
			else _httpAuthSchemes.splice(index, 1, httpAuthScheme);
		},
		httpAuthSchemes() {
			return _httpAuthSchemes;
		},
		setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
			_httpAuthSchemeProvider = httpAuthSchemeProvider;
		},
		httpAuthSchemeProvider() {
			return _httpAuthSchemeProvider;
		},
		setCredentials(credentials) {
			_credentials = credentials;
		},
		credentials() {
			return _credentials;
		}
	};
};
const resolveHttpAuthRuntimeConfig = (config) => {
	return {
		httpAuthSchemes: config.httpAuthSchemes(),
		httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
		credentials: config.credentials()
	};
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/runtimeExtensions.js
const resolveRuntimeExtensions = (runtimeConfig, extensions) => {
	const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
	extensions.forEach((extension) => extension.configure(extensionConfiguration));
	return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/STSClient.js
var STSClient = class extends Client {
	config;
	constructor(...[configuration]) {
		const _config_0 = getRuntimeConfig(configuration || {});
		super(_config_0);
		this.initConfig = _config_0;
		this.config = resolveRuntimeExtensions(resolveHttpAuthSchemeConfig(resolveEndpointConfig(resolveHostHeaderConfig(resolveRegionConfig(resolveRetryConfig(resolveUserAgentConfig(resolveClientEndpointParameters(_config_0))))))), configuration?.extensions || []);
		this.middlewareStack.use(getSchemaSerdePlugin(this.config));
		this.middlewareStack.use(getUserAgentPlugin(this.config));
		this.middlewareStack.use(getRetryPlugin(this.config));
		this.middlewareStack.use(getContentLengthPlugin(this.config));
		this.middlewareStack.use(getHostHeaderPlugin(this.config));
		this.middlewareStack.use(getLoggerPlugin(this.config));
		this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
		this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
			httpAuthSchemeParametersProvider: defaultSTSHttpAuthSchemeParametersProvider,
			identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({ "aws.auth#sigv4": config.credentials })
		}));
		this.middlewareStack.use(getHttpSigningPlugin(this.config));
	}
	destroy() {
		super.destroy();
	}
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/models/STSServiceException.js
var STSServiceException = class STSServiceException extends ServiceException {
	constructor(options) {
		super(options);
		Object.setPrototypeOf(this, STSServiceException.prototype);
	}
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/models/errors.js
var ExpiredTokenException = class ExpiredTokenException extends STSServiceException {
	name = "ExpiredTokenException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "ExpiredTokenException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, ExpiredTokenException.prototype);
	}
};
var MalformedPolicyDocumentException = class MalformedPolicyDocumentException extends STSServiceException {
	name = "MalformedPolicyDocumentException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "MalformedPolicyDocumentException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, MalformedPolicyDocumentException.prototype);
	}
};
var PackedPolicyTooLargeException = class PackedPolicyTooLargeException extends STSServiceException {
	name = "PackedPolicyTooLargeException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "PackedPolicyTooLargeException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, PackedPolicyTooLargeException.prototype);
	}
};
var RegionDisabledException = class RegionDisabledException extends STSServiceException {
	name = "RegionDisabledException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "RegionDisabledException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, RegionDisabledException.prototype);
	}
};
var IDPRejectedClaimException = class IDPRejectedClaimException extends STSServiceException {
	name = "IDPRejectedClaimException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "IDPRejectedClaimException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, IDPRejectedClaimException.prototype);
	}
};
var InvalidIdentityTokenException = class InvalidIdentityTokenException extends STSServiceException {
	name = "InvalidIdentityTokenException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "InvalidIdentityTokenException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, InvalidIdentityTokenException.prototype);
	}
};
var IDPCommunicationErrorException = class IDPCommunicationErrorException extends STSServiceException {
	name = "IDPCommunicationErrorException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "IDPCommunicationErrorException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, IDPCommunicationErrorException.prototype);
	}
};
var InvalidAuthorizationMessageException = class InvalidAuthorizationMessageException extends STSServiceException {
	name = "InvalidAuthorizationMessageException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "InvalidAuthorizationMessageException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, InvalidAuthorizationMessageException.prototype);
	}
};
var ExpiredTradeInTokenException = class ExpiredTradeInTokenException extends STSServiceException {
	name = "ExpiredTradeInTokenException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "ExpiredTradeInTokenException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, ExpiredTradeInTokenException.prototype);
	}
};
var JWTPayloadSizeExceededException = class JWTPayloadSizeExceededException extends STSServiceException {
	name = "JWTPayloadSizeExceededException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "JWTPayloadSizeExceededException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, JWTPayloadSizeExceededException.prototype);
	}
};
var OutboundWebIdentityFederationDisabledException = class OutboundWebIdentityFederationDisabledException extends STSServiceException {
	name = "OutboundWebIdentityFederationDisabledException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "OutboundWebIdentityFederationDisabledException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, OutboundWebIdentityFederationDisabledException.prototype);
	}
};
var SessionDurationEscalationException = class SessionDurationEscalationException extends STSServiceException {
	name = "SessionDurationEscalationException";
	$fault = "client";
	constructor(opts) {
		super({
			name: "SessionDurationEscalationException",
			$fault: "client",
			...opts
		});
		Object.setPrototypeOf(this, SessionDurationEscalationException.prototype);
	}
};

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/schemas/schemas_0.js
const _A = "Arn";
const _Ac = "Account";
const _ETE = "ExpiredTokenException";
const _ETITE = "ExpiredTradeInTokenException";
const _GCI = "GetCallerIdentity";
const _GCIR = "GetCallerIdentityRequest";
const _GCIRe = "GetCallerIdentityResponse";
const _IAME = "InvalidAuthorizationMessageException";
const _IDPCEE = "IDPCommunicationErrorException";
const _IDPRCE = "IDPRejectedClaimException";
const _IITE = "InvalidIdentityTokenException";
const _JWTPSEE = "JWTPayloadSizeExceededException";
const _MPDE = "MalformedPolicyDocumentException";
const _OWIFDE = "OutboundWebIdentityFederationDisabledException";
const _PPTLE = "PackedPolicyTooLargeException";
const _RDE = "RegionDisabledException";
const _SDEE = "SessionDurationEscalationException";
const _UI = "UserId";
const _aQE = "awsQueryError";
const _c = "client";
const _e = "error";
const _hE = "httpError";
const _m = "message";
const _s = "smithy.ts.sdk.synthetic.com.amazonaws.sts";
const n0 = "com.amazonaws.sts";
var ExpiredTokenException$ = [
	-3,
	n0,
	_ETE,
	{
		[_aQE]: [`ExpiredTokenException`, 400],
		[_e]: _c,
		[_hE]: 400
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(ExpiredTokenException$, ExpiredTokenException);
var ExpiredTradeInTokenException$ = [
	-3,
	n0,
	_ETITE,
	{
		[_aQE]: [`ExpiredTradeInTokenException`, 400],
		[_e]: _c,
		[_hE]: 400
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(ExpiredTradeInTokenException$, ExpiredTradeInTokenException);
var GetCallerIdentityRequest$ = [
	3,
	n0,
	_GCIR,
	0,
	[],
	[]
];
var GetCallerIdentityResponse$ = [
	3,
	n0,
	_GCIRe,
	0,
	[
		_UI,
		_Ac,
		_A
	],
	[
		0,
		0,
		0
	]
];
var IDPCommunicationErrorException$ = [
	-3,
	n0,
	_IDPCEE,
	{
		[_aQE]: [`IDPCommunicationError`, 400],
		[_e]: _c,
		[_hE]: 400
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(IDPCommunicationErrorException$, IDPCommunicationErrorException);
var IDPRejectedClaimException$ = [
	-3,
	n0,
	_IDPRCE,
	{
		[_aQE]: [`IDPRejectedClaim`, 403],
		[_e]: _c,
		[_hE]: 403
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(IDPRejectedClaimException$, IDPRejectedClaimException);
var InvalidAuthorizationMessageException$ = [
	-3,
	n0,
	_IAME,
	{
		[_aQE]: [`InvalidAuthorizationMessageException`, 400],
		[_e]: _c,
		[_hE]: 400
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(InvalidAuthorizationMessageException$, InvalidAuthorizationMessageException);
var InvalidIdentityTokenException$ = [
	-3,
	n0,
	_IITE,
	{
		[_aQE]: [`InvalidIdentityToken`, 400],
		[_e]: _c,
		[_hE]: 400
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(InvalidIdentityTokenException$, InvalidIdentityTokenException);
var JWTPayloadSizeExceededException$ = [
	-3,
	n0,
	_JWTPSEE,
	{
		[_aQE]: [`JWTPayloadSizeExceededException`, 400],
		[_e]: _c,
		[_hE]: 400
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(JWTPayloadSizeExceededException$, JWTPayloadSizeExceededException);
var MalformedPolicyDocumentException$ = [
	-3,
	n0,
	_MPDE,
	{
		[_aQE]: [`MalformedPolicyDocument`, 400],
		[_e]: _c,
		[_hE]: 400
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(MalformedPolicyDocumentException$, MalformedPolicyDocumentException);
var OutboundWebIdentityFederationDisabledException$ = [
	-3,
	n0,
	_OWIFDE,
	{
		[_aQE]: [`OutboundWebIdentityFederationDisabledException`, 403],
		[_e]: _c,
		[_hE]: 403
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(OutboundWebIdentityFederationDisabledException$, OutboundWebIdentityFederationDisabledException);
var PackedPolicyTooLargeException$ = [
	-3,
	n0,
	_PPTLE,
	{
		[_aQE]: [`PackedPolicyTooLarge`, 400],
		[_e]: _c,
		[_hE]: 400
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(PackedPolicyTooLargeException$, PackedPolicyTooLargeException);
var RegionDisabledException$ = [
	-3,
	n0,
	_RDE,
	{
		[_aQE]: [`RegionDisabledException`, 403],
		[_e]: _c,
		[_hE]: 403
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(RegionDisabledException$, RegionDisabledException);
var SessionDurationEscalationException$ = [
	-3,
	n0,
	_SDEE,
	{
		[_aQE]: [`SessionDurationEscalationException`, 403],
		[_e]: _c,
		[_hE]: 403
	},
	[_m],
	[0]
];
TypeRegistry.for(n0).registerError(SessionDurationEscalationException$, SessionDurationEscalationException);
var STSServiceException$ = [
	-3,
	_s,
	"STSServiceException",
	0,
	[],
	[]
];
TypeRegistry.for(_s).registerError(STSServiceException$, STSServiceException);
var GetCallerIdentity$ = [
	9,
	n0,
	_GCI,
	0,
	() => GetCallerIdentityRequest$,
	() => GetCallerIdentityResponse$
];

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-es/commands/GetCallerIdentityCommand.js
var GetCallerIdentityCommand = class extends Command.classBuilder().ep(commonParams).m(function(Command$1, cs, config, o$1) {
	return [getEndpointPlugin(config, Command$1.getEndpointParameterInstructions())];
}).s("AWSSecurityTokenServiceV20110615", "GetCallerIdentity", {}).n("STSClient", "GetCallerIdentityCommand").sc(GetCallerIdentity$).build() {};

//#endregion
//#region src/utils/__fixtures__/v3/index.js
const client = new STSClient();
const handler = async () => client.send(new GetCallerIdentityCommand());

//#endregion
export { handler };