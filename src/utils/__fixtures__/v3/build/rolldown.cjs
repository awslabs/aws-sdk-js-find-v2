//#region rolldown:runtime
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esmMin = (fn, res) => () => (fn && (res = fn(fn = 0)), res);
var __commonJSMin = (cb, mod) => () => (mod || cb((mod = { exports: {} }).exports, mod), mod.exports);
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
var __copyProps = (to, from, except, desc) => {
	if (from && typeof from === "object" || typeof from === "function") {
		for (var keys = __getOwnPropNames(from), i$3 = 0, n$3 = keys.length, key; i$3 < n$3; i$3++) {
			key = keys[i$3];
			if (!__hasOwnProp.call(to, key) && key !== except) {
				__defProp(to, key, {
					get: ((k$3) => from[k$3]).bind(null, key),
					enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
				});
			}
		}
	}
	return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));
var __toCommonJS = (mod) => __hasOwnProp.call(mod, "module.exports") ? mod["module.exports"] : __copyProps(__defProp({}, "__esModule", { value: true }), mod);

//#endregion

//#region node_modules/@smithy/types/dist-cjs/index.js
var require_dist_cjs$53 = /* @__PURE__ */ __commonJSMin(((exports) => {
	exports.HttpAuthLocation = void 0;
	(function(HttpAuthLocation) {
		HttpAuthLocation["HEADER"] = "header";
		HttpAuthLocation["QUERY"] = "query";
	})(exports.HttpAuthLocation || (exports.HttpAuthLocation = {}));
	exports.HttpApiKeyAuthLocation = void 0;
	(function(HttpApiKeyAuthLocation$1) {
		HttpApiKeyAuthLocation$1["HEADER"] = "header";
		HttpApiKeyAuthLocation$1["QUERY"] = "query";
	})(exports.HttpApiKeyAuthLocation || (exports.HttpApiKeyAuthLocation = {}));
	exports.EndpointURLScheme = void 0;
	(function(EndpointURLScheme) {
		EndpointURLScheme["HTTP"] = "http";
		EndpointURLScheme["HTTPS"] = "https";
	})(exports.EndpointURLScheme || (exports.EndpointURLScheme = {}));
	exports.AlgorithmId = void 0;
	(function(AlgorithmId) {
		AlgorithmId["MD5"] = "md5";
		AlgorithmId["CRC32"] = "crc32";
		AlgorithmId["CRC32C"] = "crc32c";
		AlgorithmId["SHA1"] = "sha1";
		AlgorithmId["SHA256"] = "sha256";
	})(exports.AlgorithmId || (exports.AlgorithmId = {}));
	const getChecksumConfiguration = (runtimeConfig) => {
		const checksumAlgorithms = [];
		if (runtimeConfig.sha256 !== void 0) checksumAlgorithms.push({
			algorithmId: () => exports.AlgorithmId.SHA256,
			checksumConstructor: () => runtimeConfig.sha256
		});
		if (runtimeConfig.md5 != void 0) checksumAlgorithms.push({
			algorithmId: () => exports.AlgorithmId.MD5,
			checksumConstructor: () => runtimeConfig.md5
		});
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
	const getDefaultClientConfiguration = (runtimeConfig) => {
		return getChecksumConfiguration(runtimeConfig);
	};
	const resolveDefaultRuntimeConfig = (config) => {
		return resolveChecksumRuntimeConfig(config);
	};
	exports.FieldPosition = void 0;
	(function(FieldPosition) {
		FieldPosition[FieldPosition["HEADER"] = 0] = "HEADER";
		FieldPosition[FieldPosition["TRAILER"] = 1] = "TRAILER";
	})(exports.FieldPosition || (exports.FieldPosition = {}));
	const SMITHY_CONTEXT_KEY = "__smithy_context";
	exports.IniSectionType = void 0;
	(function(IniSectionType) {
		IniSectionType["PROFILE"] = "profile";
		IniSectionType["SSO_SESSION"] = "sso-session";
		IniSectionType["SERVICES"] = "services";
	})(exports.IniSectionType || (exports.IniSectionType = {}));
	exports.RequestHandlerProtocol = void 0;
	(function(RequestHandlerProtocol) {
		RequestHandlerProtocol["HTTP_0_9"] = "http/0.9";
		RequestHandlerProtocol["HTTP_1_0"] = "http/1.0";
		RequestHandlerProtocol["TDS_8_0"] = "tds/8.0";
	})(exports.RequestHandlerProtocol || (exports.RequestHandlerProtocol = {}));
	exports.SMITHY_CONTEXT_KEY = SMITHY_CONTEXT_KEY;
	exports.getDefaultClientConfiguration = getDefaultClientConfiguration;
	exports.resolveDefaultRuntimeConfig = resolveDefaultRuntimeConfig;
}));

//#endregion
//#region node_modules/@smithy/protocol-http/dist-cjs/index.js
var require_dist_cjs$52 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var types = require_dist_cjs$53();
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
	var Field = class {
		name;
		kind;
		values;
		constructor({ name, kind = types.FieldPosition.HEADER, values = [] }) {
			this.name = name;
			this.kind = kind;
			this.values = values;
		}
		add(value) {
			this.values.push(value);
		}
		set(values) {
			this.values = values;
		}
		remove(value) {
			this.values = this.values.filter((v$3) => v$3 !== value);
		}
		toString() {
			return this.values.map((v$3) => v$3.includes(",") || v$3.includes(" ") ? `"${v$3}"` : v$3).join(", ");
		}
		get() {
			return this.values;
		}
	};
	var Fields = class {
		entries = {};
		encoding;
		constructor({ fields = [], encoding = "utf-8" }) {
			fields.forEach(this.setField.bind(this));
			this.encoding = encoding;
		}
		setField(field) {
			this.entries[field.name.toLowerCase()] = field;
		}
		getField(name) {
			return this.entries[name.toLowerCase()];
		}
		removeField(name) {
			delete this.entries[name.toLowerCase()];
		}
		getByType(kind) {
			return Object.values(this.entries).filter((field) => field.kind === kind);
		}
	};
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
	function isValidHostname(hostname) {
		return /^[a-z0-9][a-z0-9\.\-]*[a-z0-9]$/.test(hostname);
	}
	exports.Field = Field;
	exports.Fields = Fields;
	exports.HttpRequest = HttpRequest;
	exports.HttpResponse = HttpResponse;
	exports.getHttpHandlerExtensionConfiguration = getHttpHandlerExtensionConfiguration;
	exports.isValidHostname = isValidHostname;
	exports.resolveHttpHandlerRuntimeConfig = resolveHttpHandlerRuntimeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/middleware-host-header/dist-cjs/index.js
var require_dist_cjs$51 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var protocolHttp = require_dist_cjs$52();
	function resolveHostHeaderConfig(input) {
		return input;
	}
	const hostHeaderMiddleware = (options) => (next) => async (args) => {
		if (!protocolHttp.HttpRequest.isInstance(args.request)) return next(args);
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
	exports.getHostHeaderPlugin = getHostHeaderPlugin;
	exports.hostHeaderMiddleware = hostHeaderMiddleware;
	exports.hostHeaderMiddlewareOptions = hostHeaderMiddlewareOptions;
	exports.resolveHostHeaderConfig = resolveHostHeaderConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/middleware-logger/dist-cjs/index.js
var require_dist_cjs$50 = /* @__PURE__ */ __commonJSMin(((exports) => {
	const loggerMiddleware = () => (next, context) => async (args) => {
		try {
			const response = await next(args);
			const { clientName, commandName, logger: logger$1, dynamoDbDocumentClientOptions = {} } = context;
			const { overrideInputFilterSensitiveLog, overrideOutputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
			const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
			const outputFilterSensitiveLog = overrideOutputFilterSensitiveLog ?? context.outputFilterSensitiveLog;
			const { $metadata, ...outputWithoutMetadata } = response.output;
			logger$1?.info?.({
				clientName,
				commandName,
				input: inputFilterSensitiveLog(args.input),
				output: outputFilterSensitiveLog(outputWithoutMetadata),
				metadata: $metadata
			});
			return response;
		} catch (error$1) {
			const { clientName, commandName, logger: logger$1, dynamoDbDocumentClientOptions = {} } = context;
			const { overrideInputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
			const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
			logger$1?.error?.({
				clientName,
				commandName,
				input: inputFilterSensitiveLog(args.input),
				error: error$1,
				metadata: error$1.$metadata
			});
			throw error$1;
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
	exports.getLoggerPlugin = getLoggerPlugin;
	exports.loggerMiddleware = loggerMiddleware;
	exports.loggerMiddlewareOptions = loggerMiddlewareOptions;
}));

//#endregion
//#region node_modules/@aws/lambda-invoke-store/dist-es/invoke-store.js
var invoke_store_exports = /* @__PURE__ */ __exportAll({
	InvokeStore: () => InvokeStore,
	InvokeStoreBase: () => InvokeStoreBase
});
var PROTECTED_KEYS, NO_GLOBAL_AWS_LAMBDA, InvokeStoreBase, InvokeStoreSingle, InvokeStoreMulti, InvokeStore;
var init_invoke_store = __esmMin((() => {
	PROTECTED_KEYS = {
		REQUEST_ID: Symbol.for("_AWS_LAMBDA_REQUEST_ID"),
		X_RAY_TRACE_ID: Symbol.for("_AWS_LAMBDA_X_RAY_TRACE_ID"),
		TENANT_ID: Symbol.for("_AWS_LAMBDA_TENANT_ID")
	};
	NO_GLOBAL_AWS_LAMBDA = ["true", "1"].includes(process.env?.AWS_LAMBDA_NODEJS_NO_GLOBAL_AWSLAMBDA ?? "");
	if (!NO_GLOBAL_AWS_LAMBDA) globalThis.awslambda = globalThis.awslambda || {};
	InvokeStoreBase = class {
		static PROTECTED_KEYS = PROTECTED_KEYS;
		isProtectedKey(key) {
			return Object.values(PROTECTED_KEYS).includes(key);
		}
		getRequestId() {
			return this.get(PROTECTED_KEYS.REQUEST_ID) ?? "-";
		}
		getXRayTraceId() {
			return this.get(PROTECTED_KEYS.X_RAY_TRACE_ID);
		}
		getTenantId() {
			return this.get(PROTECTED_KEYS.TENANT_ID);
		}
	};
	InvokeStoreSingle = class extends InvokeStoreBase {
		currentContext;
		getContext() {
			return this.currentContext;
		}
		hasContext() {
			return this.currentContext !== void 0;
		}
		get(key) {
			return this.currentContext?.[key];
		}
		set(key, value) {
			if (this.isProtectedKey(key)) throw new Error(`Cannot modify protected Lambda context field: ${String(key)}`);
			this.currentContext = this.currentContext || {};
			this.currentContext[key] = value;
		}
		run(context, fn) {
			this.currentContext = context;
			return fn();
		}
	};
	InvokeStoreMulti = class InvokeStoreMulti extends InvokeStoreBase {
		als;
		static async create() {
			const instance = new InvokeStoreMulti();
			instance.als = new (await (import("node:async_hooks"))).AsyncLocalStorage();
			return instance;
		}
		getContext() {
			return this.als.getStore();
		}
		hasContext() {
			return this.als.getStore() !== void 0;
		}
		get(key) {
			return this.als.getStore()?.[key];
		}
		set(key, value) {
			if (this.isProtectedKey(key)) throw new Error(`Cannot modify protected Lambda context field: ${String(key)}`);
			const store = this.als.getStore();
			if (!store) throw new Error("No context available");
			store[key] = value;
		}
		run(context, fn) {
			return this.als.run(context, fn);
		}
	};
	;
	(function(InvokeStore$1) {
		let instance = null;
		async function getInstanceAsync() {
			if (!instance) instance = (async () => {
				const newInstance = "AWS_LAMBDA_MAX_CONCURRENCY" in process.env ? await InvokeStoreMulti.create() : new InvokeStoreSingle();
				if (!NO_GLOBAL_AWS_LAMBDA && globalThis.awslambda?.InvokeStore) return globalThis.awslambda.InvokeStore;
				else if (!NO_GLOBAL_AWS_LAMBDA && globalThis.awslambda) {
					globalThis.awslambda.InvokeStore = newInstance;
					return newInstance;
				} else return newInstance;
			})();
			return instance;
		}
		InvokeStore$1.getInstanceAsync = getInstanceAsync;
		InvokeStore$1._testing = process.env.AWS_LAMBDA_BENCHMARK_MODE === "1" ? { reset: () => {
			instance = null;
			if (globalThis.awslambda?.InvokeStore) delete globalThis.awslambda.InvokeStore;
			globalThis.awslambda = {};
		} } : void 0;
	})(InvokeStore || (InvokeStore = {}));
}));

//#endregion
//#region node_modules/@aws-sdk/middleware-recursion-detection/dist-cjs/recursionDetectionMiddleware.js
var require_recursionDetectionMiddleware = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.recursionDetectionMiddleware = void 0;
	const lambda_invoke_store_1 = (init_invoke_store(), __toCommonJS(invoke_store_exports));
	const protocol_http_1 = require_dist_cjs$52();
	const TRACE_ID_HEADER_NAME = "X-Amzn-Trace-Id";
	const ENV_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME";
	const ENV_TRACE_ID = "_X_AMZN_TRACE_ID";
	const recursionDetectionMiddleware = () => (next) => async (args) => {
		const { request } = args;
		if (!protocol_http_1.HttpRequest.isInstance(request)) return next(args);
		const traceIdHeader = Object.keys(request.headers ?? {}).find((h$3) => h$3.toLowerCase() === TRACE_ID_HEADER_NAME.toLowerCase()) ?? TRACE_ID_HEADER_NAME;
		if (request.headers.hasOwnProperty(traceIdHeader)) return next(args);
		const functionName = process.env[ENV_LAMBDA_FUNCTION_NAME];
		const traceIdFromEnv = process.env[ENV_TRACE_ID];
		const traceId = (await lambda_invoke_store_1.InvokeStore.getInstanceAsync())?.getXRayTraceId() ?? traceIdFromEnv;
		const nonEmptyString = (str) => typeof str === "string" && str.length > 0;
		if (nonEmptyString(functionName) && nonEmptyString(traceId)) request.headers[TRACE_ID_HEADER_NAME] = traceId;
		return next({
			...args,
			request
		});
	};
	exports.recursionDetectionMiddleware = recursionDetectionMiddleware;
}));

//#endregion
//#region node_modules/@aws-sdk/middleware-recursion-detection/dist-cjs/index.js
var require_dist_cjs$49 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var recursionDetectionMiddleware = require_recursionDetectionMiddleware();
	const recursionDetectionMiddlewareOptions = {
		step: "build",
		tags: ["RECURSION_DETECTION"],
		name: "recursionDetectionMiddleware",
		override: true,
		priority: "low"
	};
	const getRecursionDetectionPlugin = (options) => ({ applyToStack: (clientStack) => {
		clientStack.add(recursionDetectionMiddleware.recursionDetectionMiddleware(), recursionDetectionMiddlewareOptions);
	} });
	exports.getRecursionDetectionPlugin = getRecursionDetectionPlugin;
	Object.keys(recursionDetectionMiddleware).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return recursionDetectionMiddleware[k$3];
			}
		});
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/getSmithyContext.js
var import_dist_cjs$150, getSmithyContext$8;
var init_getSmithyContext = __esmMin((() => {
	import_dist_cjs$150 = require_dist_cjs$53();
	getSmithyContext$8 = (context) => context[import_dist_cjs$150.SMITHY_CONTEXT_KEY] || (context[import_dist_cjs$150.SMITHY_CONTEXT_KEY] = {});
}));

//#endregion
//#region node_modules/@smithy/util-middleware/dist-cjs/index.js
var require_dist_cjs$48 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var types = require_dist_cjs$53();
	const getSmithyContext = (context) => context[types.SMITHY_CONTEXT_KEY] || (context[types.SMITHY_CONTEXT_KEY] = {});
	const normalizeProvider = (input) => {
		if (typeof input === "function") return input;
		const promisified = Promise.resolve(input);
		return () => promisified;
	};
	exports.getSmithyContext = getSmithyContext;
	exports.normalizeProvider = normalizeProvider;
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/resolveAuthOptions.js
var resolveAuthOptions;
var init_resolveAuthOptions = __esmMin((() => {
	resolveAuthOptions = (candidateAuthOptions, authSchemePreference) => {
		if (!authSchemePreference || authSchemePreference.length === 0) return candidateAuthOptions;
		const preferredAuthOptions = [];
		for (const preferredSchemeName of authSchemePreference) for (const candidateAuthOption of candidateAuthOptions) if (candidateAuthOption.schemeId.split("#")[1] === preferredSchemeName) preferredAuthOptions.push(candidateAuthOption);
		for (const candidateAuthOption of candidateAuthOptions) if (!preferredAuthOptions.find(({ schemeId }) => schemeId === candidateAuthOption.schemeId)) preferredAuthOptions.push(candidateAuthOption);
		return preferredAuthOptions;
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js
function convertHttpAuthSchemesToMap(httpAuthSchemes) {
	const map$1 = /* @__PURE__ */ new Map();
	for (const scheme of httpAuthSchemes) map$1.set(scheme.schemeId, scheme);
	return map$1;
}
var import_dist_cjs$149, httpAuthSchemeMiddleware;
var init_httpAuthSchemeMiddleware = __esmMin((() => {
	import_dist_cjs$149 = require_dist_cjs$48();
	init_resolveAuthOptions();
	httpAuthSchemeMiddleware = (config, mwOptions) => (next, context) => async (args) => {
		const resolvedOptions = resolveAuthOptions(config.httpAuthSchemeProvider(await mwOptions.httpAuthSchemeParametersProvider(config, context, args.input)), config.authSchemePreference ? await config.authSchemePreference() : []);
		const authSchemes = convertHttpAuthSchemesToMap(config.httpAuthSchemes);
		const smithyContext = (0, import_dist_cjs$149.getSmithyContext)(context);
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
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.js
var httpAuthSchemeEndpointRuleSetMiddlewareOptions, getHttpAuthSchemeEndpointRuleSetPlugin;
var init_getHttpAuthSchemeEndpointRuleSetPlugin = __esmMin((() => {
	init_httpAuthSchemeMiddleware();
	httpAuthSchemeEndpointRuleSetMiddlewareOptions = {
		step: "serialize",
		tags: ["HTTP_AUTH_SCHEME"],
		name: "httpAuthSchemeMiddleware",
		override: true,
		relation: "before",
		toMiddleware: "endpointV2Middleware"
	};
	getHttpAuthSchemeEndpointRuleSetPlugin = (config, { httpAuthSchemeParametersProvider, identityProviderConfigProvider }) => ({ applyToStack: (clientStack) => {
		clientStack.addRelativeTo(httpAuthSchemeMiddleware(config, {
			httpAuthSchemeParametersProvider,
			identityProviderConfigProvider
		}), httpAuthSchemeEndpointRuleSetMiddlewareOptions);
	} });
}));

//#endregion
//#region node_modules/@smithy/middleware-serde/dist-cjs/index.js
var require_dist_cjs$47 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var protocolHttp = require_dist_cjs$52();
	const deserializerMiddleware = (options, deserializer) => (next, context) => async (args) => {
		const { response } = await next(args);
		try {
			return {
				response,
				output: await deserializer(response, options)
			};
		} catch (error$1) {
			Object.defineProperty(error$1, "$response", {
				value: response,
				enumerable: false,
				writable: false,
				configurable: false
			});
			if (!("$metadata" in error$1)) {
				const hint = `Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`;
				try {
					error$1.message += "\n  " + hint;
				} catch (e$3) {
					if (!context.logger || context.logger?.constructor?.name === "NoOpLogger") console.warn(hint);
					else context.logger?.warn?.(hint);
				}
				if (typeof error$1.$responseBodyText !== "undefined") {
					if (error$1.$response) error$1.$response.body = error$1.$responseBodyText;
				}
				try {
					if (protocolHttp.HttpResponse.isInstance(response)) {
						const { headers = {} } = response;
						const headerEntries = Object.entries(headers);
						error$1.$metadata = {
							httpStatusCode: response.statusCode,
							requestId: findHeader(/^x-[\w-]+-request-?id$/, headerEntries),
							extendedRequestId: findHeader(/^x-[\w-]+-id-2$/, headerEntries),
							cfId: findHeader(/^x-[\w-]+-cf-id$/, headerEntries)
						};
					}
				} catch (e$3) {}
			}
			throw error$1;
		}
	};
	const findHeader = (pattern, headers) => {
		return (headers.find(([k$3]) => {
			return k$3.match(pattern);
		}) || [void 0, void 0])[1];
	};
	const serializerMiddleware = (options, serializer) => (next, context) => async (args) => {
		const endpointConfig = options;
		const endpoint = context.endpointV2?.url && endpointConfig.urlParser ? async () => endpointConfig.urlParser(context.endpointV2.url) : endpointConfig.endpoint;
		if (!endpoint) throw new Error("No valid endpoint provider available.");
		const request = await serializer(args.input, {
			...options,
			endpoint
		});
		return next({
			...args,
			request
		});
	};
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
	function getSerdePlugin(config, serializer, deserializer) {
		return { applyToStack: (commandStack) => {
			commandStack.add(deserializerMiddleware(config, deserializer), deserializerMiddlewareOption);
			commandStack.add(serializerMiddleware(config, serializer), serializerMiddlewareOption);
		} };
	}
	exports.deserializerMiddleware = deserializerMiddleware;
	exports.deserializerMiddlewareOption = deserializerMiddlewareOption;
	exports.getSerdePlugin = getSerdePlugin;
	exports.serializerMiddleware = serializerMiddleware;
	exports.serializerMiddlewareOption = serializerMiddlewareOption;
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemePlugin.js
var import_dist_cjs$148, httpAuthSchemeMiddlewareOptions, getHttpAuthSchemePlugin;
var init_getHttpAuthSchemePlugin = __esmMin((() => {
	import_dist_cjs$148 = require_dist_cjs$47();
	init_httpAuthSchemeMiddleware();
	httpAuthSchemeMiddlewareOptions = {
		step: "serialize",
		tags: ["HTTP_AUTH_SCHEME"],
		name: "httpAuthSchemeMiddleware",
		override: true,
		relation: "before",
		toMiddleware: import_dist_cjs$148.serializerMiddlewareOption.name
	};
	getHttpAuthSchemePlugin = (config, { httpAuthSchemeParametersProvider, identityProviderConfigProvider }) => ({ applyToStack: (clientStack) => {
		clientStack.addRelativeTo(httpAuthSchemeMiddleware(config, {
			httpAuthSchemeParametersProvider,
			identityProviderConfigProvider
		}), httpAuthSchemeMiddlewareOptions);
	} });
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/index.js
var init_middleware_http_auth_scheme = __esmMin((() => {
	init_httpAuthSchemeMiddleware();
	init_getHttpAuthSchemeEndpointRuleSetPlugin();
	init_getHttpAuthSchemePlugin();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-signing/httpSigningMiddleware.js
var import_dist_cjs$146, import_dist_cjs$147, defaultErrorHandler, defaultSuccessHandler, httpSigningMiddleware;
var init_httpSigningMiddleware = __esmMin((() => {
	import_dist_cjs$146 = require_dist_cjs$52();
	import_dist_cjs$147 = require_dist_cjs$48();
	defaultErrorHandler = (signingProperties) => (error$1) => {
		throw error$1;
	};
	defaultSuccessHandler = (httpResponse, signingProperties) => {};
	httpSigningMiddleware = (config) => (next, context) => async (args) => {
		if (!import_dist_cjs$146.HttpRequest.isInstance(args.request)) return next(args);
		const scheme = (0, import_dist_cjs$147.getSmithyContext)(context).selectedHttpAuthScheme;
		if (!scheme) throw new Error(`No HttpAuthScheme was selected: unable to sign request`);
		const { httpAuthOption: { signingProperties = {} }, identity, signer } = scheme;
		const output = await next({
			...args,
			request: await signer.sign(args.request, identity, signingProperties)
		}).catch((signer.errorHandler || defaultErrorHandler)(signingProperties));
		(signer.successHandler || defaultSuccessHandler)(output.response, signingProperties);
		return output;
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-signing/getHttpSigningMiddleware.js
var httpSigningMiddlewareOptions, getHttpSigningPlugin;
var init_getHttpSigningMiddleware = __esmMin((() => {
	init_httpSigningMiddleware();
	httpSigningMiddlewareOptions = {
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
	getHttpSigningPlugin = (config) => ({ applyToStack: (clientStack) => {
		clientStack.addRelativeTo(httpSigningMiddleware(config), httpSigningMiddlewareOptions);
	} });
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/middleware-http-signing/index.js
var init_middleware_http_signing = __esmMin((() => {
	init_httpSigningMiddleware();
	init_getHttpSigningMiddleware();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/normalizeProvider.js
var normalizeProvider$3;
var init_normalizeProvider = __esmMin((() => {
	normalizeProvider$3 = (input) => {
		if (typeof input === "function") return input;
		const promisified = Promise.resolve(input);
		return () => promisified;
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/pagination/createPaginator.js
function createPaginator(ClientCtor, CommandCtor, inputTokenName, outputTokenName, pageSizeTokenName) {
	return async function* paginateOperation(config, input, ...additionalArguments) {
		const _input = input;
		let token = config.startingToken ?? _input[inputTokenName];
		let hasNext = true;
		let page;
		while (hasNext) {
			_input[inputTokenName] = token;
			if (pageSizeTokenName) _input[pageSizeTokenName] = _input[pageSizeTokenName] ?? config.pageSize;
			if (config.client instanceof ClientCtor) page = await makePagedClientRequest(CommandCtor, config.client, input, config.withCommand, ...additionalArguments);
			else throw new Error(`Invalid client, expected instance of ${ClientCtor.name}`);
			yield page;
			const prevToken = token;
			token = get(page, outputTokenName);
			hasNext = !!(token && (!config.stopOnSameToken || token !== prevToken));
		}
		return void 0;
	};
}
var makePagedClientRequest, get;
var init_createPaginator = __esmMin((() => {
	makePagedClientRequest = async (CommandCtor, client$1, input, withCommand = (_) => _, ...args) => {
		let command = new CommandCtor(input);
		command = withCommand(command) ?? command;
		return await client$1.send(command, ...args);
	};
	get = (fromObject, path$1) => {
		let cursor$1 = fromObject;
		const pathComponents = path$1.split(".");
		for (const step of pathComponents) {
			if (!cursor$1 || typeof cursor$1 !== "object") return;
			cursor$1 = cursor$1[step];
		}
		return cursor$1;
	};
}));

//#endregion
//#region node_modules/@smithy/is-array-buffer/dist-cjs/index.js
var require_dist_cjs$46 = /* @__PURE__ */ __commonJSMin(((exports) => {
	const isArrayBuffer = (arg) => typeof ArrayBuffer === "function" && arg instanceof ArrayBuffer || Object.prototype.toString.call(arg) === "[object ArrayBuffer]";
	exports.isArrayBuffer = isArrayBuffer;
}));

//#endregion
//#region node_modules/@smithy/util-buffer-from/dist-cjs/index.js
var require_dist_cjs$45 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var isArrayBuffer = require_dist_cjs$46();
	var buffer$2 = require("buffer");
	const fromArrayBuffer = (input, offset = 0, length = input.byteLength - offset) => {
		if (!isArrayBuffer.isArrayBuffer(input)) throw new TypeError(`The "input" argument must be ArrayBuffer. Received type ${typeof input} (${input})`);
		return buffer$2.Buffer.from(input, offset, length);
	};
	const fromString = (input, encoding) => {
		if (typeof input !== "string") throw new TypeError(`The "input" argument must be of type string. Received type ${typeof input} (${input})`);
		return encoding ? buffer$2.Buffer.from(input, encoding) : buffer$2.Buffer.from(input);
	};
	exports.fromArrayBuffer = fromArrayBuffer;
	exports.fromString = fromString;
}));

//#endregion
//#region node_modules/@smithy/util-base64/dist-cjs/fromBase64.js
var require_fromBase64 = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.fromBase64 = void 0;
	const util_buffer_from_1 = require_dist_cjs$45();
	const BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
	const fromBase64 = (input) => {
		if (input.length * 3 % 4 !== 0) throw new TypeError(`Incorrect padding on base64 string.`);
		if (!BASE64_REGEX.exec(input)) throw new TypeError(`Invalid base64 string.`);
		const buffer$3 = (0, util_buffer_from_1.fromString)(input, "base64");
		return new Uint8Array(buffer$3.buffer, buffer$3.byteOffset, buffer$3.byteLength);
	};
	exports.fromBase64 = fromBase64;
}));

//#endregion
//#region node_modules/@smithy/util-utf8/dist-cjs/index.js
var require_dist_cjs$44 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilBufferFrom = require_dist_cjs$45();
	const fromUtf8 = (input) => {
		const buf = utilBufferFrom.fromString(input, "utf8");
		return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength / Uint8Array.BYTES_PER_ELEMENT);
	};
	const toUint8Array = (data$1) => {
		if (typeof data$1 === "string") return fromUtf8(data$1);
		if (ArrayBuffer.isView(data$1)) return new Uint8Array(data$1.buffer, data$1.byteOffset, data$1.byteLength / Uint8Array.BYTES_PER_ELEMENT);
		return new Uint8Array(data$1);
	};
	const toUtf8 = (input) => {
		if (typeof input === "string") return input;
		if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") throw new Error("@smithy/util-utf8: toUtf8 encoder function only accepts string | Uint8Array.");
		return utilBufferFrom.fromArrayBuffer(input.buffer, input.byteOffset, input.byteLength).toString("utf8");
	};
	exports.fromUtf8 = fromUtf8;
	exports.toUint8Array = toUint8Array;
	exports.toUtf8 = toUtf8;
}));

//#endregion
//#region node_modules/@smithy/util-base64/dist-cjs/toBase64.js
var require_toBase64 = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.toBase64 = void 0;
	const util_buffer_from_1 = require_dist_cjs$45();
	const util_utf8_1 = require_dist_cjs$44();
	const toBase64 = (_input) => {
		let input;
		if (typeof _input === "string") input = (0, util_utf8_1.fromUtf8)(_input);
		else input = _input;
		if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") throw new Error("@smithy/util-base64: toBase64 encoder function only accepts string | Uint8Array.");
		return (0, util_buffer_from_1.fromArrayBuffer)(input.buffer, input.byteOffset, input.byteLength).toString("base64");
	};
	exports.toBase64 = toBase64;
}));

//#endregion
//#region node_modules/@smithy/util-base64/dist-cjs/index.js
var require_dist_cjs$43 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var fromBase64 = require_fromBase64();
	var toBase64 = require_toBase64();
	Object.keys(fromBase64).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return fromBase64[k$3];
			}
		});
	});
	Object.keys(toBase64).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return toBase64[k$3];
			}
		});
	});
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/checksum/ChecksumStream.js
var require_ChecksumStream = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.ChecksumStream = void 0;
	const util_base64_1 = require_dist_cjs$43();
	const stream_1$5 = require("stream");
	var ChecksumStream = class extends stream_1$5.Duplex {
		expectedChecksum;
		checksumSourceLocation;
		checksum;
		source;
		base64Encoder;
		constructor({ expectedChecksum, checksum, source, checksumSourceLocation, base64Encoder }) {
			super();
			if (typeof source.pipe === "function") this.source = source;
			else throw new Error(`@smithy/util-stream: unsupported source type ${source?.constructor?.name ?? source} in ChecksumStream.`);
			this.base64Encoder = base64Encoder ?? util_base64_1.toBase64;
			this.expectedChecksum = expectedChecksum;
			this.checksum = checksum;
			this.checksumSourceLocation = checksumSourceLocation;
			this.source.pipe(this);
		}
		_read(size) {}
		_write(chunk, encoding, callback) {
			try {
				this.checksum.update(chunk);
				this.push(chunk);
			} catch (e$3) {
				return callback(e$3);
			}
			return callback();
		}
		async _final(callback) {
			try {
				const digest = await this.checksum.digest();
				const received = this.base64Encoder(digest);
				if (this.expectedChecksum !== received) return callback(/* @__PURE__ */ new Error(`Checksum mismatch: expected "${this.expectedChecksum}" but received "${received}" in response header "${this.checksumSourceLocation}".`));
			} catch (e$3) {
				return callback(e$3);
			}
			this.push(null);
			return callback();
		}
	};
	exports.ChecksumStream = ChecksumStream;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/stream-type-check.js
var require_stream_type_check = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.isBlob = exports.isReadableStream = void 0;
	const isReadableStream = (stream$1) => typeof ReadableStream === "function" && (stream$1?.constructor?.name === ReadableStream.name || stream$1 instanceof ReadableStream);
	exports.isReadableStream = isReadableStream;
	const isBlob = (blob) => {
		return typeof Blob === "function" && (blob?.constructor?.name === Blob.name || blob instanceof Blob);
	};
	exports.isBlob = isBlob;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/checksum/ChecksumStream.browser.js
var require_ChecksumStream_browser = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.ChecksumStream = void 0;
	const ReadableStreamRef = typeof ReadableStream === "function" ? ReadableStream : function() {};
	var ChecksumStream = class extends ReadableStreamRef {};
	exports.ChecksumStream = ChecksumStream;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/checksum/createChecksumStream.browser.js
var require_createChecksumStream_browser = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.createChecksumStream = void 0;
	const util_base64_1 = require_dist_cjs$43();
	const stream_type_check_1 = require_stream_type_check();
	const ChecksumStream_browser_1 = require_ChecksumStream_browser();
	const createChecksumStream = ({ expectedChecksum, checksum, source, checksumSourceLocation, base64Encoder }) => {
		if (!(0, stream_type_check_1.isReadableStream)(source)) throw new Error(`@smithy/util-stream: unsupported source type ${source?.constructor?.name ?? source} in ChecksumStream.`);
		const encoder = base64Encoder ?? util_base64_1.toBase64;
		if (typeof TransformStream !== "function") throw new Error("@smithy/util-stream: unable to instantiate ChecksumStream because API unavailable: ReadableStream/TransformStream.");
		const transform = new TransformStream({
			start() {},
			async transform(chunk, controller) {
				checksum.update(chunk);
				controller.enqueue(chunk);
			},
			async flush(controller) {
				const received = encoder(await checksum.digest());
				if (expectedChecksum !== received) {
					const error$1 = /* @__PURE__ */ new Error(`Checksum mismatch: expected "${expectedChecksum}" but received "${received}" in response header "${checksumSourceLocation}".`);
					controller.error(error$1);
				} else controller.terminate();
			}
		});
		source.pipeThrough(transform);
		const readable = transform.readable;
		Object.setPrototypeOf(readable, ChecksumStream_browser_1.ChecksumStream.prototype);
		return readable;
	};
	exports.createChecksumStream = createChecksumStream;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/checksum/createChecksumStream.js
var require_createChecksumStream = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.createChecksumStream = createChecksumStream;
	const stream_type_check_1 = require_stream_type_check();
	const ChecksumStream_1 = require_ChecksumStream();
	const createChecksumStream_browser_1 = require_createChecksumStream_browser();
	function createChecksumStream(init) {
		if (typeof ReadableStream === "function" && (0, stream_type_check_1.isReadableStream)(init.source)) return (0, createChecksumStream_browser_1.createChecksumStream)(init);
		return new ChecksumStream_1.ChecksumStream(init);
	}
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/ByteArrayCollector.js
var require_ByteArrayCollector = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.ByteArrayCollector = void 0;
	var ByteArrayCollector = class {
		allocByteArray;
		byteLength = 0;
		byteArrays = [];
		constructor(allocByteArray) {
			this.allocByteArray = allocByteArray;
		}
		push(byteArray) {
			this.byteArrays.push(byteArray);
			this.byteLength += byteArray.byteLength;
		}
		flush() {
			if (this.byteArrays.length === 1) {
				const bytes = this.byteArrays[0];
				this.reset();
				return bytes;
			}
			const aggregation = this.allocByteArray(this.byteLength);
			let cursor$1 = 0;
			for (let i$3 = 0; i$3 < this.byteArrays.length; ++i$3) {
				const bytes = this.byteArrays[i$3];
				aggregation.set(bytes, cursor$1);
				cursor$1 += bytes.byteLength;
			}
			this.reset();
			return aggregation;
		}
		reset() {
			this.byteArrays = [];
			this.byteLength = 0;
		}
	};
	exports.ByteArrayCollector = ByteArrayCollector;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/createBufferedReadableStream.js
var require_createBufferedReadableStream = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.createBufferedReadable = void 0;
	exports.createBufferedReadableStream = createBufferedReadableStream;
	exports.merge = merge;
	exports.flush = flush;
	exports.sizeOf = sizeOf;
	exports.modeOf = modeOf;
	const ByteArrayCollector_1 = require_ByteArrayCollector();
	function createBufferedReadableStream(upstream, size, logger$1) {
		const reader = upstream.getReader();
		let streamBufferingLoggedWarning = false;
		let bytesSeen = 0;
		const buffers = ["", new ByteArrayCollector_1.ByteArrayCollector((size$1) => new Uint8Array(size$1))];
		let mode = -1;
		const pull = async (controller) => {
			const { value, done } = await reader.read();
			const chunk = value;
			if (done) {
				if (mode !== -1) {
					const remainder = flush(buffers, mode);
					if (sizeOf(remainder) > 0) controller.enqueue(remainder);
				}
				controller.close();
			} else {
				const chunkMode = modeOf(chunk, false);
				if (mode !== chunkMode) {
					if (mode >= 0) controller.enqueue(flush(buffers, mode));
					mode = chunkMode;
				}
				if (mode === -1) {
					controller.enqueue(chunk);
					return;
				}
				const chunkSize = sizeOf(chunk);
				bytesSeen += chunkSize;
				const bufferSize = sizeOf(buffers[mode]);
				if (chunkSize >= size && bufferSize === 0) controller.enqueue(chunk);
				else {
					const newSize = merge(buffers, mode, chunk);
					if (!streamBufferingLoggedWarning && bytesSeen > size * 2) {
						streamBufferingLoggedWarning = true;
						logger$1?.warn(`@smithy/util-stream - stream chunk size ${chunkSize} is below threshold of ${size}, automatically buffering.`);
					}
					if (newSize >= size) controller.enqueue(flush(buffers, mode));
					else await pull(controller);
				}
			}
		};
		return new ReadableStream({ pull });
	}
	exports.createBufferedReadable = createBufferedReadableStream;
	function merge(buffers, mode, chunk) {
		switch (mode) {
			case 0:
				buffers[0] += chunk;
				return sizeOf(buffers[0]);
			case 1:
			case 2:
				buffers[mode].push(chunk);
				return sizeOf(buffers[mode]);
		}
	}
	function flush(buffers, mode) {
		switch (mode) {
			case 0:
				const s$3 = buffers[0];
				buffers[0] = "";
				return s$3;
			case 1:
			case 2: return buffers[mode].flush();
		}
		throw new Error(`@smithy/util-stream - invalid index ${mode} given to flush()`);
	}
	function sizeOf(chunk) {
		return chunk?.byteLength ?? chunk?.length ?? 0;
	}
	function modeOf(chunk, allowBuffer = true) {
		if (allowBuffer && typeof Buffer !== "undefined" && chunk instanceof Buffer) return 2;
		if (chunk instanceof Uint8Array) return 1;
		if (typeof chunk === "string") return 0;
		return -1;
	}
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/createBufferedReadable.js
var require_createBufferedReadable = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.createBufferedReadable = createBufferedReadable;
	const node_stream_1 = require("node:stream");
	const ByteArrayCollector_1 = require_ByteArrayCollector();
	const createBufferedReadableStream_1 = require_createBufferedReadableStream();
	const stream_type_check_1 = require_stream_type_check();
	function createBufferedReadable(upstream, size, logger$1) {
		if ((0, stream_type_check_1.isReadableStream)(upstream)) return (0, createBufferedReadableStream_1.createBufferedReadableStream)(upstream, size, logger$1);
		const downstream = new node_stream_1.Readable({ read() {} });
		let streamBufferingLoggedWarning = false;
		let bytesSeen = 0;
		const buffers = [
			"",
			new ByteArrayCollector_1.ByteArrayCollector((size$1) => new Uint8Array(size$1)),
			new ByteArrayCollector_1.ByteArrayCollector((size$1) => Buffer.from(new Uint8Array(size$1)))
		];
		let mode = -1;
		upstream.on("data", (chunk) => {
			const chunkMode = (0, createBufferedReadableStream_1.modeOf)(chunk, true);
			if (mode !== chunkMode) {
				if (mode >= 0) downstream.push((0, createBufferedReadableStream_1.flush)(buffers, mode));
				mode = chunkMode;
			}
			if (mode === -1) {
				downstream.push(chunk);
				return;
			}
			const chunkSize = (0, createBufferedReadableStream_1.sizeOf)(chunk);
			bytesSeen += chunkSize;
			const bufferSize = (0, createBufferedReadableStream_1.sizeOf)(buffers[mode]);
			if (chunkSize >= size && bufferSize === 0) downstream.push(chunk);
			else {
				const newSize = (0, createBufferedReadableStream_1.merge)(buffers, mode, chunk);
				if (!streamBufferingLoggedWarning && bytesSeen > size * 2) {
					streamBufferingLoggedWarning = true;
					logger$1?.warn(`@smithy/util-stream - stream chunk size ${chunkSize} is below threshold of ${size}, automatically buffering.`);
				}
				if (newSize >= size) downstream.push((0, createBufferedReadableStream_1.flush)(buffers, mode));
			}
		});
		upstream.on("end", () => {
			if (mode !== -1) {
				const remainder = (0, createBufferedReadableStream_1.flush)(buffers, mode);
				if ((0, createBufferedReadableStream_1.sizeOf)(remainder) > 0) downstream.push(remainder);
			}
			downstream.push(null);
		});
		return downstream;
	}
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/getAwsChunkedEncodingStream.js
var require_getAwsChunkedEncodingStream = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getAwsChunkedEncodingStream = void 0;
	const stream_1$4 = require("stream");
	const getAwsChunkedEncodingStream = (readableStream, options) => {
		const { base64Encoder, bodyLengthChecker, checksumAlgorithmFn, checksumLocationName, streamHasher } = options;
		const checksumRequired = base64Encoder !== void 0 && checksumAlgorithmFn !== void 0 && checksumLocationName !== void 0 && streamHasher !== void 0;
		const digest = checksumRequired ? streamHasher(checksumAlgorithmFn, readableStream) : void 0;
		const awsChunkedEncodingStream = new stream_1$4.Readable({ read: () => {} });
		readableStream.on("data", (data$1) => {
			const length = bodyLengthChecker(data$1) || 0;
			awsChunkedEncodingStream.push(`${length.toString(16)}\r\n`);
			awsChunkedEncodingStream.push(data$1);
			awsChunkedEncodingStream.push("\r\n");
		});
		readableStream.on("end", async () => {
			awsChunkedEncodingStream.push(`0\r\n`);
			if (checksumRequired) {
				const checksum = base64Encoder(await digest);
				awsChunkedEncodingStream.push(`${checksumLocationName}:${checksum}\r\n`);
				awsChunkedEncodingStream.push(`\r\n`);
			}
			awsChunkedEncodingStream.push(null);
		});
		return awsChunkedEncodingStream;
	};
	exports.getAwsChunkedEncodingStream = getAwsChunkedEncodingStream;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/headStream.browser.js
var require_headStream_browser = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.headStream = headStream;
	async function headStream(stream$1, bytes) {
		let byteLengthCounter = 0;
		const chunks = [];
		const reader = stream$1.getReader();
		let isDone = false;
		while (!isDone) {
			const { done, value } = await reader.read();
			if (value) {
				chunks.push(value);
				byteLengthCounter += value?.byteLength ?? 0;
			}
			if (byteLengthCounter >= bytes) break;
			isDone = done;
		}
		reader.releaseLock();
		const collected = new Uint8Array(Math.min(bytes, byteLengthCounter));
		let offset = 0;
		for (const chunk of chunks) {
			if (chunk.byteLength > collected.byteLength - offset) {
				collected.set(chunk.subarray(0, collected.byteLength - offset), offset);
				break;
			} else collected.set(chunk, offset);
			offset += chunk.length;
		}
		return collected;
	}
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/headStream.js
var require_headStream = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.headStream = void 0;
	const stream_1$3 = require("stream");
	const headStream_browser_1 = require_headStream_browser();
	const stream_type_check_1 = require_stream_type_check();
	const headStream = (stream$1, bytes) => {
		if ((0, stream_type_check_1.isReadableStream)(stream$1)) return (0, headStream_browser_1.headStream)(stream$1, bytes);
		return new Promise((resolve, reject) => {
			const collector = new Collector();
			collector.limit = bytes;
			stream$1.pipe(collector);
			stream$1.on("error", (err) => {
				collector.end();
				reject(err);
			});
			collector.on("error", reject);
			collector.on("finish", function() {
				resolve(new Uint8Array(Buffer.concat(this.buffers)));
			});
		});
	};
	exports.headStream = headStream;
	var Collector = class extends stream_1$3.Writable {
		buffers = [];
		limit = Infinity;
		bytesBuffered = 0;
		_write(chunk, encoding, callback) {
			this.buffers.push(chunk);
			this.bytesBuffered += chunk.byteLength ?? 0;
			if (this.bytesBuffered >= this.limit) {
				const excess = this.bytesBuffered - this.limit;
				const tailBuffer = this.buffers[this.buffers.length - 1];
				this.buffers[this.buffers.length - 1] = tailBuffer.subarray(0, tailBuffer.byteLength - excess);
				this.emit("finish");
			}
			callback();
		}
	};
}));

//#endregion
//#region node_modules/@smithy/util-uri-escape/dist-cjs/index.js
var require_dist_cjs$42 = /* @__PURE__ */ __commonJSMin(((exports) => {
	const escapeUri = (uri) => encodeURIComponent(uri).replace(/[!'()*]/g, hexEncode);
	const hexEncode = (c$3) => `%${c$3.charCodeAt(0).toString(16).toUpperCase()}`;
	const escapeUriPath = (uri) => uri.split("/").map(escapeUri).join("/");
	exports.escapeUri = escapeUri;
	exports.escapeUriPath = escapeUriPath;
}));

//#endregion
//#region node_modules/@smithy/querystring-builder/dist-cjs/index.js
var require_dist_cjs$41 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilUriEscape = require_dist_cjs$42();
	function buildQueryString(query) {
		const parts = [];
		for (let key of Object.keys(query).sort()) {
			const value = query[key];
			key = utilUriEscape.escapeUri(key);
			if (Array.isArray(value)) for (let i$3 = 0, iLen = value.length; i$3 < iLen; i$3++) parts.push(`${key}=${utilUriEscape.escapeUri(value[i$3])}`);
			else {
				let qsEntry = key;
				if (value || typeof value === "string") qsEntry += `=${utilUriEscape.escapeUri(value)}`;
				parts.push(qsEntry);
			}
		}
		return parts.join("&");
	}
	exports.buildQueryString = buildQueryString;
}));

//#endregion
//#region node_modules/@smithy/node-http-handler/dist-cjs/index.js
var require_dist_cjs$40 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var protocolHttp = require_dist_cjs$52();
	var querystringBuilder = require_dist_cjs$41();
	var http$1 = require("http");
	var https = require("https");
	var stream = require("stream");
	var http2 = require("http2");
	const NODEJS_TIMEOUT_ERROR_CODES = [
		"ECONNRESET",
		"EPIPE",
		"ETIMEDOUT"
	];
	const getTransformedHeaders = (headers) => {
		const transformedHeaders = {};
		for (const name of Object.keys(headers)) {
			const headerValues = headers[name];
			transformedHeaders[name] = Array.isArray(headerValues) ? headerValues.join(",") : headerValues;
		}
		return transformedHeaders;
	};
	const timing = {
		setTimeout: (cb, ms) => setTimeout(cb, ms),
		clearTimeout: (timeoutId) => clearTimeout(timeoutId)
	};
	const DEFER_EVENT_LISTENER_TIME$2 = 1e3;
	const setConnectionTimeout = (request, reject, timeoutInMs = 0) => {
		if (!timeoutInMs) return -1;
		const registerTimeout = (offset) => {
			const timeoutId = timing.setTimeout(() => {
				request.destroy();
				reject(Object.assign(/* @__PURE__ */ new Error(`@smithy/node-http-handler - the request socket did not establish a connection with the server within the configured timeout of ${timeoutInMs} ms.`), { name: "TimeoutError" }));
			}, timeoutInMs - offset);
			const doWithSocket = (socket) => {
				if (socket?.connecting) socket.on("connect", () => {
					timing.clearTimeout(timeoutId);
				});
				else timing.clearTimeout(timeoutId);
			};
			if (request.socket) doWithSocket(request.socket);
			else request.on("socket", doWithSocket);
		};
		if (timeoutInMs < 2e3) {
			registerTimeout(0);
			return 0;
		}
		return timing.setTimeout(registerTimeout.bind(null, DEFER_EVENT_LISTENER_TIME$2), DEFER_EVENT_LISTENER_TIME$2);
	};
	const setRequestTimeout = (req, reject, timeoutInMs = 0, throwOnRequestTimeout, logger$1) => {
		if (timeoutInMs) return timing.setTimeout(() => {
			let msg = `@smithy/node-http-handler - [${throwOnRequestTimeout ? "ERROR" : "WARN"}] a request has exceeded the configured ${timeoutInMs} ms requestTimeout.`;
			if (throwOnRequestTimeout) {
				const error$1 = Object.assign(new Error(msg), {
					name: "TimeoutError",
					code: "ETIMEDOUT"
				});
				req.destroy(error$1);
				reject(error$1);
			} else {
				msg += ` Init client requestHandler with throwOnRequestTimeout=true to turn this into an error.`;
				logger$1?.warn?.(msg);
			}
		}, timeoutInMs);
		return -1;
	};
	const DEFER_EVENT_LISTENER_TIME$1 = 3e3;
	const setSocketKeepAlive = (request, { keepAlive, keepAliveMsecs }, deferTimeMs = DEFER_EVENT_LISTENER_TIME$1) => {
		if (keepAlive !== true) return -1;
		const registerListener = () => {
			if (request.socket) request.socket.setKeepAlive(keepAlive, keepAliveMsecs || 0);
			else request.on("socket", (socket) => {
				socket.setKeepAlive(keepAlive, keepAliveMsecs || 0);
			});
		};
		if (deferTimeMs === 0) {
			registerListener();
			return 0;
		}
		return timing.setTimeout(registerListener, deferTimeMs);
	};
	const DEFER_EVENT_LISTENER_TIME = 3e3;
	const setSocketTimeout = (request, reject, timeoutInMs = 0) => {
		const registerTimeout = (offset) => {
			const timeout = timeoutInMs - offset;
			const onTimeout = () => {
				request.destroy();
				reject(Object.assign(/* @__PURE__ */ new Error(`@smithy/node-http-handler - the request socket timed out after ${timeoutInMs} ms of inactivity (configured by client requestHandler).`), { name: "TimeoutError" }));
			};
			if (request.socket) {
				request.socket.setTimeout(timeout, onTimeout);
				request.on("close", () => request.socket?.removeListener("timeout", onTimeout));
			} else request.setTimeout(timeout, onTimeout);
		};
		if (0 < timeoutInMs && timeoutInMs < 6e3) {
			registerTimeout(0);
			return 0;
		}
		return timing.setTimeout(registerTimeout.bind(null, timeoutInMs === 0 ? 0 : DEFER_EVENT_LISTENER_TIME), DEFER_EVENT_LISTENER_TIME);
	};
	const MIN_WAIT_TIME = 6e3;
	async function writeRequestBody(httpRequest, request, maxContinueTimeoutMs = MIN_WAIT_TIME, externalAgent = false) {
		const headers = request.headers ?? {};
		const expect = headers.Expect || headers.expect;
		let timeoutId = -1;
		let sendBody = true;
		if (!externalAgent && expect === "100-continue") sendBody = await Promise.race([new Promise((resolve) => {
			timeoutId = Number(timing.setTimeout(() => resolve(true), Math.max(MIN_WAIT_TIME, maxContinueTimeoutMs)));
		}), new Promise((resolve) => {
			httpRequest.on("continue", () => {
				timing.clearTimeout(timeoutId);
				resolve(true);
			});
			httpRequest.on("response", () => {
				timing.clearTimeout(timeoutId);
				resolve(false);
			});
			httpRequest.on("error", () => {
				timing.clearTimeout(timeoutId);
				resolve(false);
			});
		})]);
		if (sendBody) writeBody(httpRequest, request.body);
	}
	function writeBody(httpRequest, body) {
		if (body instanceof stream.Readable) {
			body.pipe(httpRequest);
			return;
		}
		if (body) {
			if (Buffer.isBuffer(body) || typeof body === "string") {
				httpRequest.end(body);
				return;
			}
			const uint8 = body;
			if (typeof uint8 === "object" && uint8.buffer && typeof uint8.byteOffset === "number" && typeof uint8.byteLength === "number") {
				httpRequest.end(Buffer.from(uint8.buffer, uint8.byteOffset, uint8.byteLength));
				return;
			}
			httpRequest.end(Buffer.from(body));
			return;
		}
		httpRequest.end();
	}
	const DEFAULT_REQUEST_TIMEOUT = 0;
	var NodeHttpHandler = class NodeHttpHandler {
		config;
		configProvider;
		socketWarningTimestamp = 0;
		externalAgent = false;
		metadata = { handlerProtocol: "http/1.1" };
		static create(instanceOrOptions) {
			if (typeof instanceOrOptions?.handle === "function") return instanceOrOptions;
			return new NodeHttpHandler(instanceOrOptions);
		}
		static checkSocketUsage(agent, socketWarningTimestamp, logger$1 = console) {
			const { sockets, requests, maxSockets } = agent;
			if (typeof maxSockets !== "number" || maxSockets === Infinity) return socketWarningTimestamp;
			if (Date.now() - 15e3 < socketWarningTimestamp) return socketWarningTimestamp;
			if (sockets && requests) for (const origin in sockets) {
				const socketsInUse = sockets[origin]?.length ?? 0;
				const requestsEnqueued = requests[origin]?.length ?? 0;
				if (socketsInUse >= maxSockets && requestsEnqueued >= 2 * maxSockets) {
					logger$1?.warn?.(`@smithy/node-http-handler:WARN - socket usage at capacity=${socketsInUse} and ${requestsEnqueued} additional requests are enqueued.
See https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/node-configuring-maxsockets.html
or increase socketAcquisitionWarningTimeout=(millis) in the NodeHttpHandler config.`);
					return Date.now();
				}
			}
			return socketWarningTimestamp;
		}
		constructor(options) {
			this.configProvider = new Promise((resolve, reject) => {
				if (typeof options === "function") options().then((_options) => {
					resolve(this.resolveDefaultConfig(_options));
				}).catch(reject);
				else resolve(this.resolveDefaultConfig(options));
			});
		}
		resolveDefaultConfig(options) {
			const { requestTimeout, connectionTimeout, socketTimeout, socketAcquisitionWarningTimeout, httpAgent, httpsAgent, throwOnRequestTimeout } = options || {};
			const keepAlive = true;
			const maxSockets = 50;
			return {
				connectionTimeout,
				requestTimeout,
				socketTimeout,
				socketAcquisitionWarningTimeout,
				throwOnRequestTimeout,
				httpAgent: (() => {
					if (httpAgent instanceof http$1.Agent || typeof httpAgent?.destroy === "function") {
						this.externalAgent = true;
						return httpAgent;
					}
					return new http$1.Agent({
						keepAlive,
						maxSockets,
						...httpAgent
					});
				})(),
				httpsAgent: (() => {
					if (httpsAgent instanceof https.Agent || typeof httpsAgent?.destroy === "function") {
						this.externalAgent = true;
						return httpsAgent;
					}
					return new https.Agent({
						keepAlive,
						maxSockets,
						...httpsAgent
					});
				})(),
				logger: console
			};
		}
		destroy() {
			this.config?.httpAgent?.destroy();
			this.config?.httpsAgent?.destroy();
		}
		async handle(request, { abortSignal, requestTimeout } = {}) {
			if (!this.config) this.config = await this.configProvider;
			return new Promise((_resolve, _reject) => {
				const config = this.config;
				let writeRequestBodyPromise = void 0;
				const timeouts = [];
				const resolve = async (arg) => {
					await writeRequestBodyPromise;
					timeouts.forEach(timing.clearTimeout);
					_resolve(arg);
				};
				const reject = async (arg) => {
					await writeRequestBodyPromise;
					timeouts.forEach(timing.clearTimeout);
					_reject(arg);
				};
				if (abortSignal?.aborted) {
					const abortError = /* @__PURE__ */ new Error("Request aborted");
					abortError.name = "AbortError";
					reject(abortError);
					return;
				}
				const isSSL = request.protocol === "https:";
				const headers = request.headers ?? {};
				const expectContinue = (headers.Expect ?? headers.expect) === "100-continue";
				let agent = isSSL ? config.httpsAgent : config.httpAgent;
				if (expectContinue && !this.externalAgent) agent = new (isSSL ? https.Agent : http$1.Agent)({
					keepAlive: false,
					maxSockets: Infinity
				});
				timeouts.push(timing.setTimeout(() => {
					this.socketWarningTimestamp = NodeHttpHandler.checkSocketUsage(agent, this.socketWarningTimestamp, config.logger);
				}, config.socketAcquisitionWarningTimeout ?? (config.requestTimeout ?? 2e3) + (config.connectionTimeout ?? 1e3)));
				const queryString = querystringBuilder.buildQueryString(request.query || {});
				let auth = void 0;
				if (request.username != null || request.password != null) auth = `${request.username ?? ""}:${request.password ?? ""}`;
				let path$1 = request.path;
				if (queryString) path$1 += `?${queryString}`;
				if (request.fragment) path$1 += `#${request.fragment}`;
				let hostname = request.hostname ?? "";
				if (hostname[0] === "[" && hostname.endsWith("]")) hostname = request.hostname.slice(1, -1);
				else hostname = request.hostname;
				const nodeHttpsOptions = {
					headers: request.headers,
					host: hostname,
					method: request.method,
					path: path$1,
					port: request.port,
					agent,
					auth
				};
				const req = (isSSL ? https.request : http$1.request)(nodeHttpsOptions, (res) => {
					resolve({ response: new protocolHttp.HttpResponse({
						statusCode: res.statusCode || -1,
						reason: res.statusMessage,
						headers: getTransformedHeaders(res.headers),
						body: res
					}) });
				});
				req.on("error", (err) => {
					if (NODEJS_TIMEOUT_ERROR_CODES.includes(err.code)) reject(Object.assign(err, { name: "TimeoutError" }));
					else reject(err);
				});
				if (abortSignal) {
					const onAbort = () => {
						req.destroy();
						const abortError = /* @__PURE__ */ new Error("Request aborted");
						abortError.name = "AbortError";
						reject(abortError);
					};
					if (typeof abortSignal.addEventListener === "function") {
						const signal = abortSignal;
						signal.addEventListener("abort", onAbort, { once: true });
						req.once("close", () => signal.removeEventListener("abort", onAbort));
					} else abortSignal.onabort = onAbort;
				}
				const effectiveRequestTimeout = requestTimeout ?? config.requestTimeout;
				timeouts.push(setConnectionTimeout(req, reject, config.connectionTimeout));
				timeouts.push(setRequestTimeout(req, reject, effectiveRequestTimeout, config.throwOnRequestTimeout, config.logger ?? console));
				timeouts.push(setSocketTimeout(req, reject, config.socketTimeout));
				const httpAgent = nodeHttpsOptions.agent;
				if (typeof httpAgent === "object" && "keepAlive" in httpAgent) timeouts.push(setSocketKeepAlive(req, {
					keepAlive: httpAgent.keepAlive,
					keepAliveMsecs: httpAgent.keepAliveMsecs
				}));
				writeRequestBodyPromise = writeRequestBody(req, request, effectiveRequestTimeout, this.externalAgent).catch((e$3) => {
					timeouts.forEach(timing.clearTimeout);
					return _reject(e$3);
				});
			});
		}
		updateHttpClientConfig(key, value) {
			this.config = void 0;
			this.configProvider = this.configProvider.then((config) => {
				return {
					...config,
					[key]: value
				};
			});
		}
		httpHandlerConfigs() {
			return this.config ?? {};
		}
	};
	var NodeHttp2ConnectionPool = class {
		sessions = [];
		constructor(sessions) {
			this.sessions = sessions ?? [];
		}
		poll() {
			if (this.sessions.length > 0) return this.sessions.shift();
		}
		offerLast(session) {
			this.sessions.push(session);
		}
		contains(session) {
			return this.sessions.includes(session);
		}
		remove(session) {
			this.sessions = this.sessions.filter((s$3) => s$3 !== session);
		}
		[Symbol.iterator]() {
			return this.sessions[Symbol.iterator]();
		}
		destroy(connection) {
			for (const session of this.sessions) if (session === connection) {
				if (!session.destroyed) session.destroy();
			}
		}
	};
	var NodeHttp2ConnectionManager = class {
		constructor(config) {
			this.config = config;
			if (this.config.maxConcurrency && this.config.maxConcurrency <= 0) throw new RangeError("maxConcurrency must be greater than zero.");
		}
		config;
		sessionCache = /* @__PURE__ */ new Map();
		lease(requestContext, connectionConfiguration) {
			const url$1 = this.getUrlString(requestContext);
			const existingPool = this.sessionCache.get(url$1);
			if (existingPool) {
				const existingSession = existingPool.poll();
				if (existingSession && !this.config.disableConcurrency) return existingSession;
			}
			const session = http2.connect(url$1);
			if (this.config.maxConcurrency) session.settings({ maxConcurrentStreams: this.config.maxConcurrency }, (err) => {
				if (err) throw new Error("Fail to set maxConcurrentStreams to " + this.config.maxConcurrency + "when creating new session for " + requestContext.destination.toString());
			});
			session.unref();
			const destroySessionCb = () => {
				session.destroy();
				this.deleteSession(url$1, session);
			};
			session.on("goaway", destroySessionCb);
			session.on("error", destroySessionCb);
			session.on("frameError", destroySessionCb);
			session.on("close", () => this.deleteSession(url$1, session));
			if (connectionConfiguration.requestTimeout) session.setTimeout(connectionConfiguration.requestTimeout, destroySessionCb);
			const connectionPool = this.sessionCache.get(url$1) || new NodeHttp2ConnectionPool();
			connectionPool.offerLast(session);
			this.sessionCache.set(url$1, connectionPool);
			return session;
		}
		deleteSession(authority, session) {
			const existingConnectionPool = this.sessionCache.get(authority);
			if (!existingConnectionPool) return;
			if (!existingConnectionPool.contains(session)) return;
			existingConnectionPool.remove(session);
			this.sessionCache.set(authority, existingConnectionPool);
		}
		release(requestContext, session) {
			const cacheKey = this.getUrlString(requestContext);
			this.sessionCache.get(cacheKey)?.offerLast(session);
		}
		destroy() {
			for (const [key, connectionPool] of this.sessionCache) {
				for (const session of connectionPool) {
					if (!session.destroyed) session.destroy();
					connectionPool.remove(session);
				}
				this.sessionCache.delete(key);
			}
		}
		setMaxConcurrentStreams(maxConcurrentStreams) {
			if (maxConcurrentStreams && maxConcurrentStreams <= 0) throw new RangeError("maxConcurrentStreams must be greater than zero.");
			this.config.maxConcurrency = maxConcurrentStreams;
		}
		setDisableConcurrentStreams(disableConcurrentStreams) {
			this.config.disableConcurrency = disableConcurrentStreams;
		}
		getUrlString(request) {
			return request.destination.toString();
		}
	};
	var NodeHttp2Handler = class NodeHttp2Handler {
		config;
		configProvider;
		metadata = { handlerProtocol: "h2" };
		connectionManager = new NodeHttp2ConnectionManager({});
		static create(instanceOrOptions) {
			if (typeof instanceOrOptions?.handle === "function") return instanceOrOptions;
			return new NodeHttp2Handler(instanceOrOptions);
		}
		constructor(options) {
			this.configProvider = new Promise((resolve, reject) => {
				if (typeof options === "function") options().then((opts) => {
					resolve(opts || {});
				}).catch(reject);
				else resolve(options || {});
			});
		}
		destroy() {
			this.connectionManager.destroy();
		}
		async handle(request, { abortSignal, requestTimeout } = {}) {
			if (!this.config) {
				this.config = await this.configProvider;
				this.connectionManager.setDisableConcurrentStreams(this.config.disableConcurrentStreams || false);
				if (this.config.maxConcurrentStreams) this.connectionManager.setMaxConcurrentStreams(this.config.maxConcurrentStreams);
			}
			const { requestTimeout: configRequestTimeout, disableConcurrentStreams } = this.config;
			const effectiveRequestTimeout = requestTimeout ?? configRequestTimeout;
			return new Promise((_resolve, _reject) => {
				let fulfilled = false;
				let writeRequestBodyPromise = void 0;
				const resolve = async (arg) => {
					await writeRequestBodyPromise;
					_resolve(arg);
				};
				const reject = async (arg) => {
					await writeRequestBodyPromise;
					_reject(arg);
				};
				if (abortSignal?.aborted) {
					fulfilled = true;
					const abortError = /* @__PURE__ */ new Error("Request aborted");
					abortError.name = "AbortError";
					reject(abortError);
					return;
				}
				const { hostname, method, port, protocol, query } = request;
				let auth = "";
				if (request.username != null || request.password != null) auth = `${request.username ?? ""}:${request.password ?? ""}@`;
				const authority = `${protocol}//${auth}${hostname}${port ? `:${port}` : ""}`;
				const requestContext = { destination: new URL(authority) };
				const session = this.connectionManager.lease(requestContext, {
					requestTimeout: this.config?.sessionTimeout,
					disableConcurrentStreams: disableConcurrentStreams || false
				});
				const rejectWithDestroy = (err) => {
					if (disableConcurrentStreams) this.destroySession(session);
					fulfilled = true;
					reject(err);
				};
				const queryString = querystringBuilder.buildQueryString(query || {});
				let path$1 = request.path;
				if (queryString) path$1 += `?${queryString}`;
				if (request.fragment) path$1 += `#${request.fragment}`;
				const req = session.request({
					...request.headers,
					[http2.constants.HTTP2_HEADER_PATH]: path$1,
					[http2.constants.HTTP2_HEADER_METHOD]: method
				});
				session.ref();
				req.on("response", (headers) => {
					const httpResponse = new protocolHttp.HttpResponse({
						statusCode: headers[":status"] || -1,
						headers: getTransformedHeaders(headers),
						body: req
					});
					fulfilled = true;
					resolve({ response: httpResponse });
					if (disableConcurrentStreams) {
						session.close();
						this.connectionManager.deleteSession(authority, session);
					}
				});
				if (effectiveRequestTimeout) req.setTimeout(effectiveRequestTimeout, () => {
					req.close();
					const timeoutError = /* @__PURE__ */ new Error(`Stream timed out because of no activity for ${effectiveRequestTimeout} ms`);
					timeoutError.name = "TimeoutError";
					rejectWithDestroy(timeoutError);
				});
				if (abortSignal) {
					const onAbort = () => {
						req.close();
						const abortError = /* @__PURE__ */ new Error("Request aborted");
						abortError.name = "AbortError";
						rejectWithDestroy(abortError);
					};
					if (typeof abortSignal.addEventListener === "function") {
						const signal = abortSignal;
						signal.addEventListener("abort", onAbort, { once: true });
						req.once("close", () => signal.removeEventListener("abort", onAbort));
					} else abortSignal.onabort = onAbort;
				}
				req.on("frameError", (type, code, id) => {
					rejectWithDestroy(/* @__PURE__ */ new Error(`Frame type id ${type} in stream id ${id} has failed with code ${code}.`));
				});
				req.on("error", rejectWithDestroy);
				req.on("aborted", () => {
					rejectWithDestroy(/* @__PURE__ */ new Error(`HTTP/2 stream is abnormally aborted in mid-communication with result code ${req.rstCode}.`));
				});
				req.on("close", () => {
					session.unref();
					if (disableConcurrentStreams) session.destroy();
					if (!fulfilled) rejectWithDestroy(/* @__PURE__ */ new Error("Unexpected error: http2 request did not get a response"));
				});
				writeRequestBodyPromise = writeRequestBody(req, request, effectiveRequestTimeout);
			});
		}
		updateHttpClientConfig(key, value) {
			this.config = void 0;
			this.configProvider = this.configProvider.then((config) => {
				return {
					...config,
					[key]: value
				};
			});
		}
		httpHandlerConfigs() {
			return this.config ?? {};
		}
		destroySession(session) {
			if (!session.destroyed) session.destroy();
		}
	};
	var Collector = class extends stream.Writable {
		bufferedBytes = [];
		_write(chunk, encoding, callback) {
			this.bufferedBytes.push(chunk);
			callback();
		}
	};
	const streamCollector = (stream$1) => {
		if (isReadableStreamInstance(stream$1)) return collectReadableStream(stream$1);
		return new Promise((resolve, reject) => {
			const collector = new Collector();
			stream$1.pipe(collector);
			stream$1.on("error", (err) => {
				collector.end();
				reject(err);
			});
			collector.on("error", reject);
			collector.on("finish", function() {
				resolve(new Uint8Array(Buffer.concat(this.bufferedBytes)));
			});
		});
	};
	const isReadableStreamInstance = (stream$1) => typeof ReadableStream === "function" && stream$1 instanceof ReadableStream;
	async function collectReadableStream(stream$1) {
		const chunks = [];
		const reader = stream$1.getReader();
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
	exports.DEFAULT_REQUEST_TIMEOUT = DEFAULT_REQUEST_TIMEOUT;
	exports.NodeHttp2Handler = NodeHttp2Handler;
	exports.NodeHttpHandler = NodeHttpHandler;
	exports.streamCollector = streamCollector;
}));

//#endregion
//#region node_modules/@smithy/fetch-http-handler/dist-cjs/index.js
var require_dist_cjs$39 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var protocolHttp = require_dist_cjs$52();
	var querystringBuilder = require_dist_cjs$41();
	var utilBase64 = require_dist_cjs$43();
	function createRequest(url$1, requestOptions) {
		return new Request(url$1, requestOptions);
	}
	function requestTimeout(timeoutInMs = 0) {
		return new Promise((resolve, reject) => {
			if (timeoutInMs) setTimeout(() => {
				const timeoutError = /* @__PURE__ */ new Error(`Request did not complete within ${timeoutInMs} ms`);
				timeoutError.name = "TimeoutError";
				reject(timeoutError);
			}, timeoutInMs);
		});
	}
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
			let path$1 = request.path;
			const queryString = querystringBuilder.buildQueryString(request.query || {});
			if (queryString) path$1 += `?${queryString}`;
			if (request.fragment) path$1 += `#${request.fragment}`;
			let auth = "";
			if (request.username != null || request.password != null) auth = `${request.username ?? ""}:${request.password ?? ""}@`;
			const { port, method } = request;
			const url$1 = `${request.protocol}//${auth}${request.hostname}${port ? `:${port}` : ""}${path$1}`;
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
			const fetchRequest = createRequest(url$1, requestOptions);
			const raceOfPromises = [fetch(fetchRequest).then((response) => {
				const fetchHeaders = response.headers;
				const transformedHeaders = {};
				for (const pair of fetchHeaders.entries()) transformedHeaders[pair[0]] = pair[1];
				if (!(response.body != void 0)) return response.blob().then((body$1) => ({ response: new protocolHttp.HttpResponse({
					headers: transformedHeaders,
					reason: response.statusText,
					statusCode: response.status,
					body: body$1
				}) }));
				return { response: new protocolHttp.HttpResponse({
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
	const streamCollector = async (stream$1) => {
		if (typeof Blob === "function" && stream$1 instanceof Blob || stream$1.constructor?.name === "Blob") {
			if (Blob.prototype.arrayBuffer !== void 0) return new Uint8Array(await stream$1.arrayBuffer());
			return collectBlob(stream$1);
		}
		return collectStream(stream$1);
	};
	async function collectBlob(blob) {
		const base64 = await readToBase64(blob);
		const arrayBuffer = utilBase64.fromBase64(base64);
		return new Uint8Array(arrayBuffer);
	}
	async function collectStream(stream$1) {
		const chunks = [];
		const reader = stream$1.getReader();
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
	exports.FetchHttpHandler = FetchHttpHandler;
	exports.keepAliveSupport = keepAliveSupport;
	exports.streamCollector = streamCollector;
}));

//#endregion
//#region node_modules/@smithy/util-hex-encoding/dist-cjs/index.js
var require_dist_cjs$38 = /* @__PURE__ */ __commonJSMin(((exports) => {
	const SHORT_TO_HEX = {};
	const HEX_TO_SHORT = {};
	for (let i$3 = 0; i$3 < 256; i$3++) {
		let encodedByte = i$3.toString(16).toLowerCase();
		if (encodedByte.length === 1) encodedByte = `0${encodedByte}`;
		SHORT_TO_HEX[i$3] = encodedByte;
		HEX_TO_SHORT[encodedByte] = i$3;
	}
	function fromHex(encoded) {
		if (encoded.length % 2 !== 0) throw new Error("Hex encoded strings must have an even number length");
		const out = new Uint8Array(encoded.length / 2);
		for (let i$3 = 0; i$3 < encoded.length; i$3 += 2) {
			const encodedByte = encoded.slice(i$3, i$3 + 2).toLowerCase();
			if (encodedByte in HEX_TO_SHORT) out[i$3 / 2] = HEX_TO_SHORT[encodedByte];
			else throw new Error(`Cannot decode unrecognized sequence ${encodedByte} as hexadecimal`);
		}
		return out;
	}
	function toHex(bytes) {
		let out = "";
		for (let i$3 = 0; i$3 < bytes.byteLength; i$3++) out += SHORT_TO_HEX[bytes[i$3]];
		return out;
	}
	exports.fromHex = fromHex;
	exports.toHex = toHex;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/sdk-stream-mixin.browser.js
var require_sdk_stream_mixin_browser = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.sdkStreamMixin = void 0;
	const fetch_http_handler_1 = require_dist_cjs$39();
	const util_base64_1 = require_dist_cjs$43();
	const util_hex_encoding_1 = require_dist_cjs$38();
	const util_utf8_1 = require_dist_cjs$44();
	const stream_type_check_1 = require_stream_type_check();
	const ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED = "The stream has already been transformed.";
	const sdkStreamMixin = (stream$1) => {
		if (!isBlobInstance(stream$1) && !(0, stream_type_check_1.isReadableStream)(stream$1)) {
			const name = stream$1?.__proto__?.constructor?.name || stream$1;
			throw new Error(`Unexpected stream implementation, expect Blob or ReadableStream, got ${name}`);
		}
		let transformed = false;
		const transformToByteArray = async () => {
			if (transformed) throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
			transformed = true;
			return await (0, fetch_http_handler_1.streamCollector)(stream$1);
		};
		const blobToWebStream = (blob) => {
			if (typeof blob.stream !== "function") throw new Error("Cannot transform payload Blob to web stream. Please make sure the Blob.stream() is polyfilled.\nIf you are using React Native, this API is not yet supported, see: https://react-native.canny.io/feature-requests/p/fetch-streaming-body");
			return blob.stream();
		};
		return Object.assign(stream$1, {
			transformToByteArray,
			transformToString: async (encoding) => {
				const buf = await transformToByteArray();
				if (encoding === "base64") return (0, util_base64_1.toBase64)(buf);
				else if (encoding === "hex") return (0, util_hex_encoding_1.toHex)(buf);
				else if (encoding === void 0 || encoding === "utf8" || encoding === "utf-8") return (0, util_utf8_1.toUtf8)(buf);
				else if (typeof TextDecoder === "function") return new TextDecoder(encoding).decode(buf);
				else throw new Error("TextDecoder is not available, please make sure polyfill is provided.");
			},
			transformToWebStream: () => {
				if (transformed) throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
				transformed = true;
				if (isBlobInstance(stream$1)) return blobToWebStream(stream$1);
				else if ((0, stream_type_check_1.isReadableStream)(stream$1)) return stream$1;
				else throw new Error(`Cannot transform payload to web stream, got ${stream$1}`);
			}
		});
	};
	exports.sdkStreamMixin = sdkStreamMixin;
	const isBlobInstance = (stream$1) => typeof Blob === "function" && stream$1 instanceof Blob;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/sdk-stream-mixin.js
var require_sdk_stream_mixin = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.sdkStreamMixin = void 0;
	const node_http_handler_1 = require_dist_cjs$40();
	const util_buffer_from_1 = require_dist_cjs$45();
	const stream_1$2 = require("stream");
	const sdk_stream_mixin_browser_1 = require_sdk_stream_mixin_browser();
	const ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED = "The stream has already been transformed.";
	const sdkStreamMixin = (stream$1) => {
		if (!(stream$1 instanceof stream_1$2.Readable)) try {
			return (0, sdk_stream_mixin_browser_1.sdkStreamMixin)(stream$1);
		} catch (e$3) {
			const name = stream$1?.__proto__?.constructor?.name || stream$1;
			throw new Error(`Unexpected stream implementation, expect Stream.Readable instance, got ${name}`);
		}
		let transformed = false;
		const transformToByteArray = async () => {
			if (transformed) throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
			transformed = true;
			return await (0, node_http_handler_1.streamCollector)(stream$1);
		};
		return Object.assign(stream$1, {
			transformToByteArray,
			transformToString: async (encoding) => {
				const buf = await transformToByteArray();
				if (encoding === void 0 || Buffer.isEncoding(encoding)) return (0, util_buffer_from_1.fromArrayBuffer)(buf.buffer, buf.byteOffset, buf.byteLength).toString(encoding);
				else return new TextDecoder(encoding).decode(buf);
			},
			transformToWebStream: () => {
				if (transformed) throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
				if (stream$1.readableFlowing !== null) throw new Error("The stream has been consumed by other callbacks.");
				if (typeof stream_1$2.Readable.toWeb !== "function") throw new Error("Readable.toWeb() is not supported. Please ensure a polyfill is available.");
				transformed = true;
				return stream_1$2.Readable.toWeb(stream$1);
			}
		});
	};
	exports.sdkStreamMixin = sdkStreamMixin;
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/splitStream.browser.js
var require_splitStream_browser = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.splitStream = splitStream;
	async function splitStream(stream$1) {
		if (typeof stream$1.stream === "function") stream$1 = stream$1.stream();
		return stream$1.tee();
	}
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/splitStream.js
var require_splitStream = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.splitStream = splitStream;
	const stream_1$1 = require("stream");
	const splitStream_browser_1 = require_splitStream_browser();
	const stream_type_check_1 = require_stream_type_check();
	async function splitStream(stream$1) {
		if ((0, stream_type_check_1.isReadableStream)(stream$1) || (0, stream_type_check_1.isBlob)(stream$1)) return (0, splitStream_browser_1.splitStream)(stream$1);
		const stream1 = new stream_1$1.PassThrough();
		const stream2 = new stream_1$1.PassThrough();
		stream$1.pipe(stream1);
		stream$1.pipe(stream2);
		return [stream1, stream2];
	}
}));

//#endregion
//#region node_modules/@smithy/util-stream/dist-cjs/index.js
var require_dist_cjs$37 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilBase64 = require_dist_cjs$43();
	var utilUtf8 = require_dist_cjs$44();
	var ChecksumStream = require_ChecksumStream();
	var createChecksumStream = require_createChecksumStream();
	var createBufferedReadable = require_createBufferedReadable();
	var getAwsChunkedEncodingStream = require_getAwsChunkedEncodingStream();
	var headStream = require_headStream();
	var sdkStreamMixin = require_sdk_stream_mixin();
	var splitStream = require_splitStream();
	var streamTypeCheck = require_stream_type_check();
	var Uint8ArrayBlobAdapter = class Uint8ArrayBlobAdapter extends Uint8Array {
		static fromString(source, encoding = "utf-8") {
			if (typeof source === "string") {
				if (encoding === "base64") return Uint8ArrayBlobAdapter.mutate(utilBase64.fromBase64(source));
				return Uint8ArrayBlobAdapter.mutate(utilUtf8.fromUtf8(source));
			}
			throw new Error(`Unsupported conversion from ${typeof source} to Uint8ArrayBlobAdapter.`);
		}
		static mutate(source) {
			Object.setPrototypeOf(source, Uint8ArrayBlobAdapter.prototype);
			return source;
		}
		transformToString(encoding = "utf-8") {
			if (encoding === "base64") return utilBase64.toBase64(this);
			return utilUtf8.toUtf8(this);
		}
	};
	exports.Uint8ArrayBlobAdapter = Uint8ArrayBlobAdapter;
	Object.keys(ChecksumStream).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return ChecksumStream[k$3];
			}
		});
	});
	Object.keys(createChecksumStream).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return createChecksumStream[k$3];
			}
		});
	});
	Object.keys(createBufferedReadable).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return createBufferedReadable[k$3];
			}
		});
	});
	Object.keys(getAwsChunkedEncodingStream).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return getAwsChunkedEncodingStream[k$3];
			}
		});
	});
	Object.keys(headStream).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return headStream[k$3];
			}
		});
	});
	Object.keys(sdkStreamMixin).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return sdkStreamMixin[k$3];
			}
		});
	});
	Object.keys(splitStream).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return splitStream[k$3];
			}
		});
	});
	Object.keys(streamTypeCheck).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return streamTypeCheck[k$3];
			}
		});
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/collect-stream-body.js
var import_dist_cjs$145, collectBody$1;
var init_collect_stream_body = __esmMin((() => {
	import_dist_cjs$145 = require_dist_cjs$37();
	collectBody$1 = async (streamBody = new Uint8Array(), context) => {
		if (streamBody instanceof Uint8Array) return import_dist_cjs$145.Uint8ArrayBlobAdapter.mutate(streamBody);
		if (!streamBody) return import_dist_cjs$145.Uint8ArrayBlobAdapter.mutate(new Uint8Array());
		const fromContext = context.streamCollector(streamBody);
		return import_dist_cjs$145.Uint8ArrayBlobAdapter.mutate(await fromContext);
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/extended-encode-uri-component.js
function extendedEncodeURIComponent(str) {
	return encodeURIComponent(str).replace(/[!'()*]/g, function(c$3) {
		return "%" + c$3.charCodeAt(0).toString(16).toUpperCase();
	});
}
var init_extended_encode_uri_component = __esmMin((() => {}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/deref.js
var deref;
var init_deref = __esmMin((() => {
	deref = (schemaRef) => {
		if (typeof schemaRef === "function") return schemaRef();
		return schemaRef;
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/operation.js
var operation;
var init_operation = __esmMin((() => {
	operation = (namespace, name, traits, input, output) => ({
		name,
		namespace,
		traits,
		input,
		output
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaDeserializationMiddleware.js
var import_dist_cjs$143, import_dist_cjs$144, schemaDeserializationMiddleware, findHeader;
var init_schemaDeserializationMiddleware = __esmMin((() => {
	import_dist_cjs$143 = require_dist_cjs$52();
	import_dist_cjs$144 = require_dist_cjs$48();
	init_operation();
	schemaDeserializationMiddleware = (config) => (next, context) => async (args) => {
		const { response } = await next(args);
		const { operationSchema } = (0, import_dist_cjs$144.getSmithyContext)(context);
		const [, ns, n$3, t$3, i$3, o$3] = operationSchema ?? [];
		try {
			return {
				response,
				output: await config.protocol.deserializeResponse(operation(ns, n$3, t$3, i$3, o$3), {
					...config,
					...context
				}, response)
			};
		} catch (error$1) {
			Object.defineProperty(error$1, "$response", {
				value: response,
				enumerable: false,
				writable: false,
				configurable: false
			});
			if (!("$metadata" in error$1)) {
				const hint = `Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`;
				try {
					error$1.message += "\n  " + hint;
				} catch (e$3) {
					if (!context.logger || context.logger?.constructor?.name === "NoOpLogger") console.warn(hint);
					else context.logger?.warn?.(hint);
				}
				if (typeof error$1.$responseBodyText !== "undefined") {
					if (error$1.$response) error$1.$response.body = error$1.$responseBodyText;
				}
				try {
					if (import_dist_cjs$143.HttpResponse.isInstance(response)) {
						const { headers = {} } = response;
						const headerEntries = Object.entries(headers);
						error$1.$metadata = {
							httpStatusCode: response.statusCode,
							requestId: findHeader(/^x-[\w-]+-request-?id$/, headerEntries),
							extendedRequestId: findHeader(/^x-[\w-]+-id-2$/, headerEntries),
							cfId: findHeader(/^x-[\w-]+-cf-id$/, headerEntries)
						};
					}
				} catch (e$3) {}
			}
			throw error$1;
		}
	};
	findHeader = (pattern, headers) => {
		return (headers.find(([k$3]) => {
			return k$3.match(pattern);
		}) || [void 0, void 0])[1];
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaSerializationMiddleware.js
var import_dist_cjs$142, schemaSerializationMiddleware;
var init_schemaSerializationMiddleware = __esmMin((() => {
	import_dist_cjs$142 = require_dist_cjs$48();
	init_operation();
	schemaSerializationMiddleware = (config) => (next, context) => async (args) => {
		const { operationSchema } = (0, import_dist_cjs$142.getSmithyContext)(context);
		const [, ns, n$3, t$3, i$3, o$3] = operationSchema ?? [];
		const endpoint = context.endpointV2?.url && config.urlParser ? async () => config.urlParser(context.endpointV2.url) : config.endpoint;
		const request = await config.protocol.serializeRequest(operation(ns, n$3, t$3, i$3, o$3), args.input, {
			...config,
			...context,
			endpoint
		});
		return next({
			...args,
			request
		});
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/middleware/getSchemaSerdePlugin.js
function getSchemaSerdePlugin(config) {
	return { applyToStack: (commandStack) => {
		commandStack.add(schemaSerializationMiddleware(config), serializerMiddlewareOption);
		commandStack.add(schemaDeserializationMiddleware(config), deserializerMiddlewareOption);
		config.protocol.setSerdeContext(config);
	} };
}
var deserializerMiddlewareOption, serializerMiddlewareOption;
var init_getSchemaSerdePlugin = __esmMin((() => {
	init_schemaDeserializationMiddleware();
	init_schemaSerializationMiddleware();
	deserializerMiddlewareOption = {
		name: "deserializerMiddleware",
		step: "deserialize",
		tags: ["DESERIALIZER"],
		override: true
	};
	serializerMiddlewareOption = {
		name: "serializerMiddleware",
		step: "serialize",
		tags: ["SERIALIZER"],
		override: true
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/Schema.js
var Schema;
var init_Schema = __esmMin((() => {
	Schema = class {
		name;
		namespace;
		traits;
		static assign(instance, values) {
			return Object.assign(instance, values);
		}
		static [Symbol.hasInstance](lhs) {
			const isPrototype = this.prototype.isPrototypeOf(lhs);
			if (!isPrototype && typeof lhs === "object" && lhs !== null) return lhs.symbol === this.symbol;
			return isPrototype;
		}
		getName() {
			return this.namespace + "#" + this.name;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/ListSchema.js
var ListSchema, list;
var init_ListSchema = __esmMin((() => {
	init_Schema();
	ListSchema = class ListSchema extends Schema {
		static symbol = Symbol.for("@smithy/lis");
		name;
		traits;
		valueSchema;
		symbol = ListSchema.symbol;
	};
	list = (namespace, name, traits, valueSchema) => Schema.assign(new ListSchema(), {
		name,
		namespace,
		traits,
		valueSchema
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/MapSchema.js
var MapSchema, map;
var init_MapSchema = __esmMin((() => {
	init_Schema();
	MapSchema = class MapSchema extends Schema {
		static symbol = Symbol.for("@smithy/map");
		name;
		traits;
		keySchema;
		valueSchema;
		symbol = MapSchema.symbol;
	};
	map = (namespace, name, traits, keySchema, valueSchema) => Schema.assign(new MapSchema(), {
		name,
		namespace,
		traits,
		keySchema,
		valueSchema
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/OperationSchema.js
var OperationSchema, op;
var init_OperationSchema = __esmMin((() => {
	init_Schema();
	OperationSchema = class OperationSchema extends Schema {
		static symbol = Symbol.for("@smithy/ope");
		name;
		traits;
		input;
		output;
		symbol = OperationSchema.symbol;
	};
	op = (namespace, name, traits, input, output) => Schema.assign(new OperationSchema(), {
		name,
		namespace,
		traits,
		input,
		output
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/StructureSchema.js
var StructureSchema, struct;
var init_StructureSchema = __esmMin((() => {
	init_Schema();
	StructureSchema = class StructureSchema extends Schema {
		static symbol = Symbol.for("@smithy/str");
		name;
		traits;
		memberNames;
		memberList;
		symbol = StructureSchema.symbol;
	};
	struct = (namespace, name, traits, memberNames, memberList) => Schema.assign(new StructureSchema(), {
		name,
		namespace,
		traits,
		memberNames,
		memberList
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/ErrorSchema.js
var ErrorSchema, error;
var init_ErrorSchema = __esmMin((() => {
	init_Schema();
	init_StructureSchema();
	ErrorSchema = class ErrorSchema extends StructureSchema {
		static symbol = Symbol.for("@smithy/err");
		ctor;
		symbol = ErrorSchema.symbol;
	};
	error = (namespace, name, traits, memberNames, memberList, ctor) => Schema.assign(new ErrorSchema(), {
		name,
		namespace,
		traits,
		memberNames,
		memberList,
		ctor: null
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/translateTraits.js
function translateTraits(indicator) {
	if (typeof indicator === "object") return indicator;
	indicator = indicator | 0;
	const traits = {};
	let i$3 = 0;
	for (const trait of [
		"httpLabel",
		"idempotent",
		"idempotencyToken",
		"sensitive",
		"httpPayload",
		"httpResponseCode",
		"httpQueryParams"
	]) if ((indicator >> i$3++ & 1) === 1) traits[trait] = 1;
	return traits;
}
var init_translateTraits = __esmMin((() => {}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/NormalizedSchema.js
function member(memberSchema, memberName) {
	if (memberSchema instanceof NormalizedSchema) return Object.assign(memberSchema, {
		memberName,
		_isMemberSchema: true
	});
	return new NormalizedSchema(memberSchema, memberName);
}
var NormalizedSchema, isMemberSchema, isStaticSchema;
var init_NormalizedSchema = __esmMin((() => {
	init_deref();
	init_translateTraits();
	NormalizedSchema = class NormalizedSchema {
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
				for (let i$3 = traitStack.length - 1; i$3 >= 0; --i$3) {
					const traitSet = traitStack[i$3];
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
			const struct$1 = this.getSchema();
			if (this.isStructSchema() && struct$1[4].includes(memberName)) {
				const i$3 = struct$1[4].indexOf(memberName);
				const memberSchema = struct$1[5][i$3];
				return member(isMemberSchema(memberSchema) ? memberSchema : [memberSchema, 0], memberName);
			}
			if (this.isDocumentSchema()) return member([15, 0], memberName);
			throw new Error(`@smithy/core/schema - ${this.getName(true)} has no no member=${memberName}.`);
		}
		getMemberSchemas() {
			const buffer$3 = {};
			try {
				for (const [k$3, v$3] of this.structIterator()) buffer$3[k$3] = v$3;
			} catch (ignored) {}
			return buffer$3;
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
			const struct$1 = this.getSchema();
			for (let i$3 = 0; i$3 < struct$1[4].length; ++i$3) yield [struct$1[4][i$3], member([struct$1[5][i$3], 0], struct$1[4][i$3])];
		}
	};
	isMemberSchema = (sc) => Array.isArray(sc) && sc.length === 2;
	isStaticSchema = (sc) => Array.isArray(sc) && sc.length >= 5;
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/SimpleSchema.js
var SimpleSchema, sim, simAdapter;
var init_SimpleSchema = __esmMin((() => {
	init_Schema();
	SimpleSchema = class SimpleSchema extends Schema {
		static symbol = Symbol.for("@smithy/sim");
		name;
		schemaRef;
		traits;
		symbol = SimpleSchema.symbol;
	};
	sim = (namespace, name, schemaRef, traits) => Schema.assign(new SimpleSchema(), {
		name,
		namespace,
		traits,
		schemaRef
	});
	simAdapter = (namespace, name, traits, schemaRef) => Schema.assign(new SimpleSchema(), {
		name,
		namespace,
		traits,
		schemaRef
	});
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/schemas/sentinels.js
var SCHEMA;
var init_sentinels = __esmMin((() => {
	SCHEMA = {
		BLOB: 21,
		STREAMING_BLOB: 42,
		BOOLEAN: 2,
		STRING: 0,
		NUMERIC: 1,
		BIG_INTEGER: 17,
		BIG_DECIMAL: 19,
		DOCUMENT: 15,
		TIMESTAMP_DEFAULT: 4,
		TIMESTAMP_DATE_TIME: 5,
		TIMESTAMP_HTTP_DATE: 6,
		TIMESTAMP_EPOCH_SECONDS: 7,
		LIST_MODIFIER: 64,
		MAP_MODIFIER: 128
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/TypeRegistry.js
var TypeRegistry;
var init_TypeRegistry = __esmMin((() => {
	TypeRegistry = class TypeRegistry {
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
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/schema/index.js
var schema_exports = /* @__PURE__ */ __exportAll({
	ErrorSchema: () => ErrorSchema,
	ListSchema: () => ListSchema,
	MapSchema: () => MapSchema,
	NormalizedSchema: () => NormalizedSchema,
	OperationSchema: () => OperationSchema,
	SCHEMA: () => SCHEMA,
	Schema: () => Schema,
	SimpleSchema: () => SimpleSchema,
	StructureSchema: () => StructureSchema,
	TypeRegistry: () => TypeRegistry,
	deref: () => deref,
	deserializerMiddlewareOption: () => deserializerMiddlewareOption,
	error: () => error,
	getSchemaSerdePlugin: () => getSchemaSerdePlugin,
	isStaticSchema: () => isStaticSchema,
	list: () => list,
	map: () => map,
	op: () => op,
	operation: () => operation,
	serializerMiddlewareOption: () => serializerMiddlewareOption,
	sim: () => sim,
	simAdapter: () => simAdapter,
	struct: () => struct,
	translateTraits: () => translateTraits
});
var init_schema = __esmMin((() => {
	init_deref();
	init_getSchemaSerdePlugin();
	init_ListSchema();
	init_MapSchema();
	init_OperationSchema();
	init_operation();
	init_ErrorSchema();
	init_NormalizedSchema();
	init_Schema();
	init_SimpleSchema();
	init_StructureSchema();
	init_sentinels();
	init_translateTraits();
	init_TypeRegistry();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/copyDocumentWithTransform.js
var copyDocumentWithTransform;
var init_copyDocumentWithTransform = __esmMin((() => {
	copyDocumentWithTransform = (source, schemaRef, transform = (_) => _) => source;
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/parse-utils.js
var parseBoolean, expectBoolean, expectNumber, MAX_FLOAT, expectFloat32, expectLong, expectInt, expectInt32, expectShort, expectByte, expectSizedInt, castInt, expectNonNull, expectObject, expectString, expectUnion$1, strictParseDouble, strictParseFloat, strictParseFloat32, NUMBER_REGEX, parseNumber, limitedParseDouble, handleFloat, limitedParseFloat, limitedParseFloat32, parseFloatString, strictParseLong, strictParseInt, strictParseInt32, strictParseShort, strictParseByte, stackTraceWarning, logger;
var init_parse_utils = __esmMin((() => {
	parseBoolean = (value) => {
		switch (value) {
			case "true": return true;
			case "false": return false;
			default: throw new Error(`Unable to parse boolean value "${value}"`);
		}
	};
	expectBoolean = (value) => {
		if (value === null || value === void 0) return;
		if (typeof value === "number") {
			if (value === 0 || value === 1) logger.warn(stackTraceWarning(`Expected boolean, got ${typeof value}: ${value}`));
			if (value === 0) return false;
			if (value === 1) return true;
		}
		if (typeof value === "string") {
			const lower = value.toLowerCase();
			if (lower === "false" || lower === "true") logger.warn(stackTraceWarning(`Expected boolean, got ${typeof value}: ${value}`));
			if (lower === "false") return false;
			if (lower === "true") return true;
		}
		if (typeof value === "boolean") return value;
		throw new TypeError(`Expected boolean, got ${typeof value}: ${value}`);
	};
	expectNumber = (value) => {
		if (value === null || value === void 0) return;
		if (typeof value === "string") {
			const parsed = parseFloat(value);
			if (!Number.isNaN(parsed)) {
				if (String(parsed) !== String(value)) logger.warn(stackTraceWarning(`Expected number but observed string: ${value}`));
				return parsed;
			}
		}
		if (typeof value === "number") return value;
		throw new TypeError(`Expected number, got ${typeof value}: ${value}`);
	};
	MAX_FLOAT = Math.ceil(2 ** 127 * (2 - 2 ** -23));
	expectFloat32 = (value) => {
		const expected = expectNumber(value);
		if (expected !== void 0 && !Number.isNaN(expected) && expected !== Infinity && expected !== -Infinity) {
			if (Math.abs(expected) > MAX_FLOAT) throw new TypeError(`Expected 32-bit float, got ${value}`);
		}
		return expected;
	};
	expectLong = (value) => {
		if (value === null || value === void 0) return;
		if (Number.isInteger(value) && !Number.isNaN(value)) return value;
		throw new TypeError(`Expected integer, got ${typeof value}: ${value}`);
	};
	expectInt = expectLong;
	expectInt32 = (value) => expectSizedInt(value, 32);
	expectShort = (value) => expectSizedInt(value, 16);
	expectByte = (value) => expectSizedInt(value, 8);
	expectSizedInt = (value, size) => {
		const expected = expectLong(value);
		if (expected !== void 0 && castInt(expected, size) !== expected) throw new TypeError(`Expected ${size}-bit integer, got ${value}`);
		return expected;
	};
	castInt = (value, size) => {
		switch (size) {
			case 32: return Int32Array.of(value)[0];
			case 16: return Int16Array.of(value)[0];
			case 8: return Int8Array.of(value)[0];
		}
	};
	expectNonNull = (value, location) => {
		if (value === null || value === void 0) {
			if (location) throw new TypeError(`Expected a non-null value for ${location}`);
			throw new TypeError("Expected a non-null value");
		}
		return value;
	};
	expectObject = (value) => {
		if (value === null || value === void 0) return;
		if (typeof value === "object" && !Array.isArray(value)) return value;
		const receivedType = Array.isArray(value) ? "array" : typeof value;
		throw new TypeError(`Expected object, got ${receivedType}: ${value}`);
	};
	expectString = (value) => {
		if (value === null || value === void 0) return;
		if (typeof value === "string") return value;
		if ([
			"boolean",
			"number",
			"bigint"
		].includes(typeof value)) {
			logger.warn(stackTraceWarning(`Expected string, got ${typeof value}: ${value}`));
			return String(value);
		}
		throw new TypeError(`Expected string, got ${typeof value}: ${value}`);
	};
	expectUnion$1 = (value) => {
		if (value === null || value === void 0) return;
		const asObject = expectObject(value);
		const setKeys = Object.entries(asObject).filter(([, v$3]) => v$3 != null).map(([k$3]) => k$3);
		if (setKeys.length === 0) throw new TypeError(`Unions must have exactly one non-null member. None were found.`);
		if (setKeys.length > 1) throw new TypeError(`Unions must have exactly one non-null member. Keys ${setKeys} were not null.`);
		return asObject;
	};
	strictParseDouble = (value) => {
		if (typeof value == "string") return expectNumber(parseNumber(value));
		return expectNumber(value);
	};
	strictParseFloat = strictParseDouble;
	strictParseFloat32 = (value) => {
		if (typeof value == "string") return expectFloat32(parseNumber(value));
		return expectFloat32(value);
	};
	NUMBER_REGEX = /(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|(-?Infinity)|(NaN)/g;
	parseNumber = (value) => {
		const matches = value.match(NUMBER_REGEX);
		if (matches === null || matches[0].length !== value.length) throw new TypeError(`Expected real number, got implicit NaN`);
		return parseFloat(value);
	};
	limitedParseDouble = (value) => {
		if (typeof value == "string") return parseFloatString(value);
		return expectNumber(value);
	};
	handleFloat = limitedParseDouble;
	limitedParseFloat = limitedParseDouble;
	limitedParseFloat32 = (value) => {
		if (typeof value == "string") return parseFloatString(value);
		return expectFloat32(value);
	};
	parseFloatString = (value) => {
		switch (value) {
			case "NaN": return NaN;
			case "Infinity": return Infinity;
			case "-Infinity": return -Infinity;
			default: throw new Error(`Unable to parse float value: ${value}`);
		}
	};
	strictParseLong = (value) => {
		if (typeof value === "string") return expectLong(parseNumber(value));
		return expectLong(value);
	};
	strictParseInt = strictParseLong;
	strictParseInt32 = (value) => {
		if (typeof value === "string") return expectInt32(parseNumber(value));
		return expectInt32(value);
	};
	strictParseShort = (value) => {
		if (typeof value === "string") return expectShort(parseNumber(value));
		return expectShort(value);
	};
	strictParseByte = (value) => {
		if (typeof value === "string") return expectByte(parseNumber(value));
		return expectByte(value);
	};
	stackTraceWarning = (message) => {
		return String(new TypeError(message).stack || message).split("\n").slice(0, 5).filter((s$3) => !s$3.includes("stackTraceWarning")).join("\n");
	};
	logger = { warn: console.warn };
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/date-utils.js
function dateToUtcString$2(date$1) {
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
var DAYS, MONTHS, RFC3339, parseRfc3339DateTime, RFC3339_WITH_OFFSET$1, parseRfc3339DateTimeWithOffset, IMF_FIXDATE$1, RFC_850_DATE$1, ASC_TIME$1, parseRfc7231DateTime, parseEpochTimestamp, buildDate, parseTwoDigitYear, FIFTY_YEARS_IN_MILLIS, adjustRfc850Year, parseMonthByShortName, DAYS_IN_MONTH, validateDayOfMonth, isLeapYear, parseDateValue, parseMilliseconds, parseOffsetToMilliseconds, stripLeadingZeroes;
var init_date_utils = __esmMin((() => {
	init_parse_utils();
	DAYS = [
		"Sun",
		"Mon",
		"Tue",
		"Wed",
		"Thu",
		"Fri",
		"Sat"
	];
	MONTHS = [
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
	RFC3339 = /* @__PURE__ */ new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?[zZ]$/);
	parseRfc3339DateTime = (value) => {
		if (value === null || value === void 0) return;
		if (typeof value !== "string") throw new TypeError("RFC-3339 date-times must be expressed as strings");
		const match = RFC3339.exec(value);
		if (!match) throw new TypeError("Invalid RFC-3339 date-time value");
		const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds] = match;
		return buildDate(strictParseShort(stripLeadingZeroes(yearStr)), parseDateValue(monthStr, "month", 1, 12), parseDateValue(dayStr, "day", 1, 31), {
			hours,
			minutes,
			seconds,
			fractionalMilliseconds
		});
	};
	RFC3339_WITH_OFFSET$1 = /* @__PURE__ */ new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(([-+]\d{2}\:\d{2})|[zZ])$/);
	parseRfc3339DateTimeWithOffset = (value) => {
		if (value === null || value === void 0) return;
		if (typeof value !== "string") throw new TypeError("RFC-3339 date-times must be expressed as strings");
		const match = RFC3339_WITH_OFFSET$1.exec(value);
		if (!match) throw new TypeError("Invalid RFC-3339 date-time value");
		const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, offsetStr] = match;
		const date$1 = buildDate(strictParseShort(stripLeadingZeroes(yearStr)), parseDateValue(monthStr, "month", 1, 12), parseDateValue(dayStr, "day", 1, 31), {
			hours,
			minutes,
			seconds,
			fractionalMilliseconds
		});
		if (offsetStr.toUpperCase() != "Z") date$1.setTime(date$1.getTime() - parseOffsetToMilliseconds(offsetStr));
		return date$1;
	};
	IMF_FIXDATE$1 = /* @__PURE__ */ new RegExp(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/);
	RFC_850_DATE$1 = /* @__PURE__ */ new RegExp(/^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/);
	ASC_TIME$1 = /* @__PURE__ */ new RegExp(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( [1-9]|\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? (\d{4})$/);
	parseRfc7231DateTime = (value) => {
		if (value === null || value === void 0) return;
		if (typeof value !== "string") throw new TypeError("RFC-7231 date-times must be expressed as strings");
		let match = IMF_FIXDATE$1.exec(value);
		if (match) {
			const [_, dayStr, monthStr, yearStr, hours, minutes, seconds, fractionalMilliseconds] = match;
			return buildDate(strictParseShort(stripLeadingZeroes(yearStr)), parseMonthByShortName(monthStr), parseDateValue(dayStr, "day", 1, 31), {
				hours,
				minutes,
				seconds,
				fractionalMilliseconds
			});
		}
		match = RFC_850_DATE$1.exec(value);
		if (match) {
			const [_, dayStr, monthStr, yearStr, hours, minutes, seconds, fractionalMilliseconds] = match;
			return adjustRfc850Year(buildDate(parseTwoDigitYear(yearStr), parseMonthByShortName(monthStr), parseDateValue(dayStr, "day", 1, 31), {
				hours,
				minutes,
				seconds,
				fractionalMilliseconds
			}));
		}
		match = ASC_TIME$1.exec(value);
		if (match) {
			const [_, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, yearStr] = match;
			return buildDate(strictParseShort(stripLeadingZeroes(yearStr)), parseMonthByShortName(monthStr), parseDateValue(dayStr.trimLeft(), "day", 1, 31), {
				hours,
				minutes,
				seconds,
				fractionalMilliseconds
			});
		}
		throw new TypeError("Invalid RFC-7231 date-time value");
	};
	parseEpochTimestamp = (value) => {
		if (value === null || value === void 0) return;
		let valueAsDouble;
		if (typeof value === "number") valueAsDouble = value;
		else if (typeof value === "string") valueAsDouble = strictParseDouble(value);
		else if (typeof value === "object" && value.tag === 1) valueAsDouble = value.value;
		else throw new TypeError("Epoch timestamps must be expressed as floating point numbers or their string representation");
		if (Number.isNaN(valueAsDouble) || valueAsDouble === Infinity || valueAsDouble === -Infinity) throw new TypeError("Epoch timestamps must be valid, non-Infinite, non-NaN numerics");
		return new Date(Math.round(valueAsDouble * 1e3));
	};
	buildDate = (year$1, month, day, time$1) => {
		const adjustedMonth = month - 1;
		validateDayOfMonth(year$1, adjustedMonth, day);
		return new Date(Date.UTC(year$1, adjustedMonth, day, parseDateValue(time$1.hours, "hour", 0, 23), parseDateValue(time$1.minutes, "minute", 0, 59), parseDateValue(time$1.seconds, "seconds", 0, 60), parseMilliseconds(time$1.fractionalMilliseconds)));
	};
	parseTwoDigitYear = (value) => {
		const thisYear = (/* @__PURE__ */ new Date()).getUTCFullYear();
		const valueInThisCentury = Math.floor(thisYear / 100) * 100 + strictParseShort(stripLeadingZeroes(value));
		if (valueInThisCentury < thisYear) return valueInThisCentury + 100;
		return valueInThisCentury;
	};
	FIFTY_YEARS_IN_MILLIS = 50 * 365 * 24 * 60 * 60 * 1e3;
	adjustRfc850Year = (input) => {
		if (input.getTime() - (/* @__PURE__ */ new Date()).getTime() > FIFTY_YEARS_IN_MILLIS) return new Date(Date.UTC(input.getUTCFullYear() - 100, input.getUTCMonth(), input.getUTCDate(), input.getUTCHours(), input.getUTCMinutes(), input.getUTCSeconds(), input.getUTCMilliseconds()));
		return input;
	};
	parseMonthByShortName = (value) => {
		const monthIdx = MONTHS.indexOf(value);
		if (monthIdx < 0) throw new TypeError(`Invalid month: ${value}`);
		return monthIdx + 1;
	};
	DAYS_IN_MONTH = [
		31,
		28,
		31,
		30,
		31,
		30,
		31,
		31,
		30,
		31,
		30,
		31
	];
	validateDayOfMonth = (year$1, month, day) => {
		let maxDays = DAYS_IN_MONTH[month];
		if (month === 1 && isLeapYear(year$1)) maxDays = 29;
		if (day > maxDays) throw new TypeError(`Invalid day for ${MONTHS[month]} in ${year$1}: ${day}`);
	};
	isLeapYear = (year$1) => {
		return year$1 % 4 === 0 && (year$1 % 100 !== 0 || year$1 % 400 === 0);
	};
	parseDateValue = (value, type, lower, upper) => {
		const dateVal = strictParseByte(stripLeadingZeroes(value));
		if (dateVal < lower || dateVal > upper) throw new TypeError(`${type} must be between ${lower} and ${upper}, inclusive`);
		return dateVal;
	};
	parseMilliseconds = (value) => {
		if (value === null || value === void 0) return 0;
		return strictParseFloat32("0." + value) * 1e3;
	};
	parseOffsetToMilliseconds = (value) => {
		const directionStr = value[0];
		let direction = 1;
		if (directionStr == "+") direction = 1;
		else if (directionStr == "-") direction = -1;
		else throw new TypeError(`Offset direction, ${directionStr}, must be "+" or "-"`);
		const hour = Number(value.substring(1, 3));
		const minute = Number(value.substring(4, 6));
		return direction * (hour * 60 + minute) * 60 * 1e3;
	};
	stripLeadingZeroes = (value) => {
		let idx = 0;
		while (idx < value.length - 1 && value.charAt(idx) === "0") idx++;
		if (idx === 0) return value;
		return value.slice(idx);
	};
}));

//#endregion
//#region node_modules/tslib/tslib.es6.mjs
var tslib_es6_exports = /* @__PURE__ */ __exportAll({
	__addDisposableResource: () => __addDisposableResource,
	__assign: () => __assign,
	__asyncDelegator: () => __asyncDelegator,
	__asyncGenerator: () => __asyncGenerator,
	__asyncValues: () => __asyncValues,
	__await: () => __await,
	__awaiter: () => __awaiter,
	__classPrivateFieldGet: () => __classPrivateFieldGet,
	__classPrivateFieldIn: () => __classPrivateFieldIn,
	__classPrivateFieldSet: () => __classPrivateFieldSet,
	__createBinding: () => __createBinding,
	__decorate: () => __decorate,
	__disposeResources: () => __disposeResources,
	__esDecorate: () => __esDecorate,
	__exportStar: () => __exportStar,
	__extends: () => __extends,
	__generator: () => __generator,
	__importDefault: () => __importDefault,
	__importStar: () => __importStar,
	__makeTemplateObject: () => __makeTemplateObject,
	__metadata: () => __metadata,
	__param: () => __param,
	__propKey: () => __propKey,
	__read: () => __read,
	__rest: () => __rest,
	__rewriteRelativeImportExtension: () => __rewriteRelativeImportExtension,
	__runInitializers: () => __runInitializers,
	__setFunctionName: () => __setFunctionName,
	__spread: () => __spread,
	__spreadArray: () => __spreadArray,
	__spreadArrays: () => __spreadArrays,
	__values: () => __values,
	default: () => tslib_es6_default
});
function __extends(d$3, b$3) {
	if (typeof b$3 !== "function" && b$3 !== null) throw new TypeError("Class extends value " + String(b$3) + " is not a constructor or null");
	extendStatics(d$3, b$3);
	function __() {
		this.constructor = d$3;
	}
	d$3.prototype = b$3 === null ? Object.create(b$3) : (__.prototype = b$3.prototype, new __());
}
function __rest(s$3, e$3) {
	var t$3 = {};
	for (var p$3 in s$3) if (Object.prototype.hasOwnProperty.call(s$3, p$3) && e$3.indexOf(p$3) < 0) t$3[p$3] = s$3[p$3];
	if (s$3 != null && typeof Object.getOwnPropertySymbols === "function") {
		for (var i$3 = 0, p$3 = Object.getOwnPropertySymbols(s$3); i$3 < p$3.length; i$3++) if (e$3.indexOf(p$3[i$3]) < 0 && Object.prototype.propertyIsEnumerable.call(s$3, p$3[i$3])) t$3[p$3[i$3]] = s$3[p$3[i$3]];
	}
	return t$3;
}
function __decorate(decorators, target, key, desc) {
	var c$3 = arguments.length, r$3 = c$3 < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d$3;
	if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r$3 = Reflect.decorate(decorators, target, key, desc);
	else for (var i$3 = decorators.length - 1; i$3 >= 0; i$3--) if (d$3 = decorators[i$3]) r$3 = (c$3 < 3 ? d$3(r$3) : c$3 > 3 ? d$3(target, key, r$3) : d$3(target, key)) || r$3;
	return c$3 > 3 && r$3 && Object.defineProperty(target, key, r$3), r$3;
}
function __param(paramIndex, decorator) {
	return function(target, key) {
		decorator(target, key, paramIndex);
	};
}
function __esDecorate(ctor, descriptorIn, decorators, contextIn, initializers, extraInitializers) {
	function accept(f$3) {
		if (f$3 !== void 0 && typeof f$3 !== "function") throw new TypeError("Function expected");
		return f$3;
	}
	var kind = contextIn.kind, key = kind === "getter" ? "get" : kind === "setter" ? "set" : "value";
	var target = !descriptorIn && ctor ? contextIn["static"] ? ctor : ctor.prototype : null;
	var descriptor = descriptorIn || (target ? Object.getOwnPropertyDescriptor(target, contextIn.name) : {});
	var _, done = false;
	for (var i$3 = decorators.length - 1; i$3 >= 0; i$3--) {
		var context = {};
		for (var p$3 in contextIn) context[p$3] = p$3 === "access" ? {} : contextIn[p$3];
		for (var p$3 in contextIn.access) context.access[p$3] = contextIn.access[p$3];
		context.addInitializer = function(f$3) {
			if (done) throw new TypeError("Cannot add initializers after decoration has completed");
			extraInitializers.push(accept(f$3 || null));
		};
		var result = (0, decorators[i$3])(kind === "accessor" ? {
			get: descriptor.get,
			set: descriptor.set
		} : descriptor[key], context);
		if (kind === "accessor") {
			if (result === void 0) continue;
			if (result === null || typeof result !== "object") throw new TypeError("Object expected");
			if (_ = accept(result.get)) descriptor.get = _;
			if (_ = accept(result.set)) descriptor.set = _;
			if (_ = accept(result.init)) initializers.unshift(_);
		} else if (_ = accept(result)) if (kind === "field") initializers.unshift(_);
		else descriptor[key] = _;
	}
	if (target) Object.defineProperty(target, contextIn.name, descriptor);
	done = true;
}
function __runInitializers(thisArg, initializers, value) {
	var useValue = arguments.length > 2;
	for (var i$3 = 0; i$3 < initializers.length; i$3++) value = useValue ? initializers[i$3].call(thisArg, value) : initializers[i$3].call(thisArg);
	return useValue ? value : void 0;
}
function __propKey(x$3) {
	return typeof x$3 === "symbol" ? x$3 : "".concat(x$3);
}
function __setFunctionName(f$3, name, prefix) {
	if (typeof name === "symbol") name = name.description ? "[".concat(name.description, "]") : "";
	return Object.defineProperty(f$3, "name", {
		configurable: true,
		value: prefix ? "".concat(prefix, " ", name) : name
	});
}
function __metadata(metadataKey, metadataValue) {
	if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}
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
			} catch (e$3) {
				reject(e$3);
			}
		}
		function rejected(value) {
			try {
				step(generator["throw"](value));
			} catch (e$3) {
				reject(e$3);
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
			if (t$3[0] & 1) throw t$3[1];
			return t$3[1];
		},
		trys: [],
		ops: []
	}, f$3, y$1, t$3, g$3 = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
	return g$3.next = verb(0), g$3["throw"] = verb(1), g$3["return"] = verb(2), typeof Symbol === "function" && (g$3[Symbol.iterator] = function() {
		return this;
	}), g$3;
	function verb(n$3) {
		return function(v$3) {
			return step([n$3, v$3]);
		};
	}
	function step(op$1) {
		if (f$3) throw new TypeError("Generator is already executing.");
		while (g$3 && (g$3 = 0, op$1[0] && (_ = 0)), _) try {
			if (f$3 = 1, y$1 && (t$3 = op$1[0] & 2 ? y$1["return"] : op$1[0] ? y$1["throw"] || ((t$3 = y$1["return"]) && t$3.call(y$1), 0) : y$1.next) && !(t$3 = t$3.call(y$1, op$1[1])).done) return t$3;
			if (y$1 = 0, t$3) op$1 = [op$1[0] & 2, t$3.value];
			switch (op$1[0]) {
				case 0:
				case 1:
					t$3 = op$1;
					break;
				case 4:
					_.label++;
					return {
						value: op$1[1],
						done: false
					};
				case 5:
					_.label++;
					y$1 = op$1[1];
					op$1 = [0];
					continue;
				case 7:
					op$1 = _.ops.pop();
					_.trys.pop();
					continue;
				default:
					if (!(t$3 = _.trys, t$3 = t$3.length > 0 && t$3[t$3.length - 1]) && (op$1[0] === 6 || op$1[0] === 2)) {
						_ = 0;
						continue;
					}
					if (op$1[0] === 3 && (!t$3 || op$1[1] > t$3[0] && op$1[1] < t$3[3])) {
						_.label = op$1[1];
						break;
					}
					if (op$1[0] === 6 && _.label < t$3[1]) {
						_.label = t$3[1];
						t$3 = op$1;
						break;
					}
					if (t$3 && _.label < t$3[2]) {
						_.label = t$3[2];
						_.ops.push(op$1);
						break;
					}
					if (t$3[2]) _.ops.pop();
					_.trys.pop();
					continue;
			}
			op$1 = body.call(thisArg, _);
		} catch (e$3) {
			op$1 = [6, e$3];
			y$1 = 0;
		} finally {
			f$3 = t$3 = 0;
		}
		if (op$1[0] & 5) throw op$1[1];
		return {
			value: op$1[0] ? op$1[1] : void 0,
			done: true
		};
	}
}
function __exportStar(m$3, o$3) {
	for (var p$3 in m$3) if (p$3 !== "default" && !Object.prototype.hasOwnProperty.call(o$3, p$3)) __createBinding(o$3, m$3, p$3);
}
function __values(o$3) {
	var s$3 = typeof Symbol === "function" && Symbol.iterator, m$3 = s$3 && o$3[s$3], i$3 = 0;
	if (m$3) return m$3.call(o$3);
	if (o$3 && typeof o$3.length === "number") return { next: function() {
		if (o$3 && i$3 >= o$3.length) o$3 = void 0;
		return {
			value: o$3 && o$3[i$3++],
			done: !o$3
		};
	} };
	throw new TypeError(s$3 ? "Object is not iterable." : "Symbol.iterator is not defined.");
}
function __read(o$3, n$3) {
	var m$3 = typeof Symbol === "function" && o$3[Symbol.iterator];
	if (!m$3) return o$3;
	var i$3 = m$3.call(o$3), r$3, ar = [], e$3;
	try {
		while ((n$3 === void 0 || n$3-- > 0) && !(r$3 = i$3.next()).done) ar.push(r$3.value);
	} catch (error$1) {
		e$3 = { error: error$1 };
	} finally {
		try {
			if (r$3 && !r$3.done && (m$3 = i$3["return"])) m$3.call(i$3);
		} finally {
			if (e$3) throw e$3.error;
		}
	}
	return ar;
}
/** @deprecated */
function __spread() {
	for (var ar = [], i$3 = 0; i$3 < arguments.length; i$3++) ar = ar.concat(__read(arguments[i$3]));
	return ar;
}
/** @deprecated */
function __spreadArrays() {
	for (var s$3 = 0, i$3 = 0, il = arguments.length; i$3 < il; i$3++) s$3 += arguments[i$3].length;
	for (var r$3 = Array(s$3), k$3 = 0, i$3 = 0; i$3 < il; i$3++) for (var a$3 = arguments[i$3], j$3 = 0, jl = a$3.length; j$3 < jl; j$3++, k$3++) r$3[k$3] = a$3[j$3];
	return r$3;
}
function __spreadArray(to, from, pack) {
	if (pack || arguments.length === 2) {
		for (var i$3 = 0, l$3 = from.length, ar; i$3 < l$3; i$3++) if (ar || !(i$3 in from)) {
			if (!ar) ar = Array.prototype.slice.call(from, 0, i$3);
			ar[i$3] = from[i$3];
		}
	}
	return to.concat(ar || Array.prototype.slice.call(from));
}
function __await(v$3) {
	return this instanceof __await ? (this.v = v$3, this) : new __await(v$3);
}
function __asyncGenerator(thisArg, _arguments, generator) {
	if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
	var g$3 = generator.apply(thisArg, _arguments || []), i$3, q$3 = [];
	return i$3 = Object.create((typeof AsyncIterator === "function" ? AsyncIterator : Object).prototype), verb("next"), verb("throw"), verb("return", awaitReturn), i$3[Symbol.asyncIterator] = function() {
		return this;
	}, i$3;
	function awaitReturn(f$3) {
		return function(v$3) {
			return Promise.resolve(v$3).then(f$3, reject);
		};
	}
	function verb(n$3, f$3) {
		if (g$3[n$3]) {
			i$3[n$3] = function(v$3) {
				return new Promise(function(a$3, b$3) {
					q$3.push([
						n$3,
						v$3,
						a$3,
						b$3
					]) > 1 || resume(n$3, v$3);
				});
			};
			if (f$3) i$3[n$3] = f$3(i$3[n$3]);
		}
	}
	function resume(n$3, v$3) {
		try {
			step(g$3[n$3](v$3));
		} catch (e$3) {
			settle(q$3[0][3], e$3);
		}
	}
	function step(r$3) {
		r$3.value instanceof __await ? Promise.resolve(r$3.value.v).then(fulfill, reject) : settle(q$3[0][2], r$3);
	}
	function fulfill(value) {
		resume("next", value);
	}
	function reject(value) {
		resume("throw", value);
	}
	function settle(f$3, v$3) {
		if (f$3(v$3), q$3.shift(), q$3.length) resume(q$3[0][0], q$3[0][1]);
	}
}
function __asyncDelegator(o$3) {
	var i$3, p$3;
	return i$3 = {}, verb("next"), verb("throw", function(e$3) {
		throw e$3;
	}), verb("return"), i$3[Symbol.iterator] = function() {
		return this;
	}, i$3;
	function verb(n$3, f$3) {
		i$3[n$3] = o$3[n$3] ? function(v$3) {
			return (p$3 = !p$3) ? {
				value: __await(o$3[n$3](v$3)),
				done: false
			} : f$3 ? f$3(v$3) : v$3;
		} : f$3;
	}
}
function __asyncValues(o$3) {
	if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
	var m$3 = o$3[Symbol.asyncIterator], i$3;
	return m$3 ? m$3.call(o$3) : (o$3 = typeof __values === "function" ? __values(o$3) : o$3[Symbol.iterator](), i$3 = {}, verb("next"), verb("throw"), verb("return"), i$3[Symbol.asyncIterator] = function() {
		return this;
	}, i$3);
	function verb(n$3) {
		i$3[n$3] = o$3[n$3] && function(v$3) {
			return new Promise(function(resolve, reject) {
				v$3 = o$3[n$3](v$3), settle(resolve, reject, v$3.done, v$3.value);
			});
		};
	}
	function settle(resolve, reject, d$3, v$3) {
		Promise.resolve(v$3).then(function(v$4) {
			resolve({
				value: v$4,
				done: d$3
			});
		}, reject);
	}
}
function __makeTemplateObject(cooked, raw) {
	if (Object.defineProperty) Object.defineProperty(cooked, "raw", { value: raw });
	else cooked.raw = raw;
	return cooked;
}
function __importStar(mod) {
	if (mod && mod.__esModule) return mod;
	var result = {};
	if (mod != null) {
		for (var k$3 = ownKeys(mod), i$3 = 0; i$3 < k$3.length; i$3++) if (k$3[i$3] !== "default") __createBinding(result, mod, k$3[i$3]);
	}
	__setModuleDefault(result, mod);
	return result;
}
function __importDefault(mod) {
	return mod && mod.__esModule ? mod : { default: mod };
}
function __classPrivateFieldGet(receiver, state$1, kind, f$3) {
	if (kind === "a" && !f$3) throw new TypeError("Private accessor was defined without a getter");
	if (typeof state$1 === "function" ? receiver !== state$1 || !f$3 : !state$1.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
	return kind === "m" ? f$3 : kind === "a" ? f$3.call(receiver) : f$3 ? f$3.value : state$1.get(receiver);
}
function __classPrivateFieldSet(receiver, state$1, value, kind, f$3) {
	if (kind === "m") throw new TypeError("Private method is not writable");
	if (kind === "a" && !f$3) throw new TypeError("Private accessor was defined without a setter");
	if (typeof state$1 === "function" ? receiver !== state$1 || !f$3 : !state$1.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
	return kind === "a" ? f$3.call(receiver, value) : f$3 ? f$3.value = value : state$1.set(receiver, value), value;
}
function __classPrivateFieldIn(state$1, receiver) {
	if (receiver === null || typeof receiver !== "object" && typeof receiver !== "function") throw new TypeError("Cannot use 'in' operator on non-object");
	return typeof state$1 === "function" ? receiver === state$1 : state$1.has(receiver);
}
function __addDisposableResource(env, value, async) {
	if (value !== null && value !== void 0) {
		if (typeof value !== "object" && typeof value !== "function") throw new TypeError("Object expected.");
		var dispose, inner;
		if (async) {
			if (!Symbol.asyncDispose) throw new TypeError("Symbol.asyncDispose is not defined.");
			dispose = value[Symbol.asyncDispose];
		}
		if (dispose === void 0) {
			if (!Symbol.dispose) throw new TypeError("Symbol.dispose is not defined.");
			dispose = value[Symbol.dispose];
			if (async) inner = dispose;
		}
		if (typeof dispose !== "function") throw new TypeError("Object not disposable.");
		if (inner) dispose = function() {
			try {
				inner.call(this);
			} catch (e$3) {
				return Promise.reject(e$3);
			}
		};
		env.stack.push({
			value,
			dispose,
			async
		});
	} else if (async) env.stack.push({ async: true });
	return value;
}
function __disposeResources(env) {
	function fail(e$3) {
		env.error = env.hasError ? new _SuppressedError(e$3, env.error, "An error was suppressed during disposal.") : e$3;
		env.hasError = true;
	}
	var r$3, s$3 = 0;
	function next() {
		while (r$3 = env.stack.pop()) try {
			if (!r$3.async && s$3 === 1) return s$3 = 0, env.stack.push(r$3), Promise.resolve().then(next);
			if (r$3.dispose) {
				var result = r$3.dispose.call(r$3.value);
				if (r$3.async) return s$3 |= 2, Promise.resolve(result).then(next, function(e$3) {
					fail(e$3);
					return next();
				});
			} else s$3 |= 1;
		} catch (e$3) {
			fail(e$3);
		}
		if (s$3 === 1) return env.hasError ? Promise.reject(env.error) : Promise.resolve();
		if (env.hasError) throw env.error;
	}
	return next();
}
function __rewriteRelativeImportExtension(path$1, preserveJsx) {
	if (typeof path$1 === "string" && /^\.\.?\//.test(path$1)) return path$1.replace(/\.(tsx)$|((?:\.d)?)((?:\.[^./]+?)?)\.([cm]?)ts$/i, function(m$3, tsx, d$3, ext, cm) {
		return tsx ? preserveJsx ? ".jsx" : ".js" : d$3 && (!ext || !cm) ? m$3 : d$3 + ext + "." + cm.toLowerCase() + "js";
	});
	return path$1;
}
var extendStatics, __assign, __createBinding, __setModuleDefault, ownKeys, _SuppressedError, tslib_es6_default;
var init_tslib_es6 = __esmMin((() => {
	extendStatics = function(d$3, b$3) {
		extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d$4, b$4) {
			d$4.__proto__ = b$4;
		} || function(d$4, b$4) {
			for (var p$3 in b$4) if (Object.prototype.hasOwnProperty.call(b$4, p$3)) d$4[p$3] = b$4[p$3];
		};
		return extendStatics(d$3, b$3);
	};
	__assign = function() {
		__assign = Object.assign || function __assign$1(t$3) {
			for (var s$3, i$3 = 1, n$3 = arguments.length; i$3 < n$3; i$3++) {
				s$3 = arguments[i$3];
				for (var p$3 in s$3) if (Object.prototype.hasOwnProperty.call(s$3, p$3)) t$3[p$3] = s$3[p$3];
			}
			return t$3;
		};
		return __assign.apply(this, arguments);
	};
	__createBinding = Object.create ? (function(o$3, m$3, k$3, k2) {
		if (k2 === void 0) k2 = k$3;
		var desc = Object.getOwnPropertyDescriptor(m$3, k$3);
		if (!desc || ("get" in desc ? !m$3.__esModule : desc.writable || desc.configurable)) desc = {
			enumerable: true,
			get: function() {
				return m$3[k$3];
			}
		};
		Object.defineProperty(o$3, k2, desc);
	}) : (function(o$3, m$3, k$3, k2) {
		if (k2 === void 0) k2 = k$3;
		o$3[k2] = m$3[k$3];
	});
	__setModuleDefault = Object.create ? (function(o$3, v$3) {
		Object.defineProperty(o$3, "default", {
			enumerable: true,
			value: v$3
		});
	}) : function(o$3, v$3) {
		o$3["default"] = v$3;
	};
	ownKeys = function(o$3) {
		ownKeys = Object.getOwnPropertyNames || function(o$4) {
			var ar = [];
			for (var k$3 in o$4) if (Object.prototype.hasOwnProperty.call(o$4, k$3)) ar[ar.length] = k$3;
			return ar;
		};
		return ownKeys(o$3);
	};
	_SuppressedError = typeof SuppressedError === "function" ? SuppressedError : function(error$1, suppressed, message) {
		var e$3 = new Error(message);
		return e$3.name = "SuppressedError", e$3.error = error$1, e$3.suppressed = suppressed, e$3;
	};
	tslib_es6_default = {
		__extends,
		__assign,
		__rest,
		__decorate,
		__param,
		__esDecorate,
		__runInitializers,
		__propKey,
		__setFunctionName,
		__metadata,
		__awaiter,
		__generator,
		__createBinding,
		__exportStar,
		__values,
		__read,
		__spread,
		__spreadArrays,
		__spreadArray,
		__await,
		__asyncGenerator,
		__asyncDelegator,
		__asyncValues,
		__makeTemplateObject,
		__importStar,
		__importDefault,
		__classPrivateFieldGet,
		__classPrivateFieldSet,
		__classPrivateFieldIn,
		__addDisposableResource,
		__disposeResources,
		__rewriteRelativeImportExtension
	};
}));

//#endregion
//#region node_modules/@smithy/uuid/dist-cjs/randomUUID.js
var require_randomUUID = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.randomUUID = void 0;
	const crypto_1$1 = (init_tslib_es6(), __toCommonJS(tslib_es6_exports)).__importDefault(require("crypto"));
	exports.randomUUID = crypto_1$1.default.randomUUID.bind(crypto_1$1.default);
}));

//#endregion
//#region node_modules/@smithy/uuid/dist-cjs/index.js
var require_dist_cjs$36 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var randomUUID = require_randomUUID();
	const decimalToHex = Array.from({ length: 256 }, (_, i$3) => i$3.toString(16).padStart(2, "0"));
	const v4 = () => {
		if (randomUUID.randomUUID) return randomUUID.randomUUID();
		const rnds = new Uint8Array(16);
		crypto.getRandomValues(rnds);
		rnds[6] = rnds[6] & 15 | 64;
		rnds[8] = rnds[8] & 63 | 128;
		return decimalToHex[rnds[0]] + decimalToHex[rnds[1]] + decimalToHex[rnds[2]] + decimalToHex[rnds[3]] + "-" + decimalToHex[rnds[4]] + decimalToHex[rnds[5]] + "-" + decimalToHex[rnds[6]] + decimalToHex[rnds[7]] + "-" + decimalToHex[rnds[8]] + decimalToHex[rnds[9]] + "-" + decimalToHex[rnds[10]] + decimalToHex[rnds[11]] + decimalToHex[rnds[12]] + decimalToHex[rnds[13]] + decimalToHex[rnds[14]] + decimalToHex[rnds[15]];
	};
	exports.v4 = v4;
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/generateIdempotencyToken.js
var import_dist_cjs$141;
var init_generateIdempotencyToken = __esmMin((() => {
	import_dist_cjs$141 = require_dist_cjs$36();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/lazy-json.js
var LazyJsonString;
var init_lazy_json = __esmMin((() => {
	LazyJsonString = function LazyJsonString$1(val) {
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
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/quote-header.js
function quoteHeader(part) {
	if (part.includes(",") || part.includes("\"")) part = `"${part.replace(/"/g, "\\\"")}"`;
	return part;
}
var init_quote_header = __esmMin((() => {}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/schema-serde-lib/schema-date-utils.js
function range(v$3, min, max) {
	const _v = Number(v$3);
	if (_v < min || _v > max) throw new Error(`Value ${_v} out of range [${min}, ${max}]`);
}
var ddd, mmm, time, date, year, RFC3339_WITH_OFFSET, IMF_FIXDATE, RFC_850_DATE, ASC_TIME, months, _parseEpochTimestamp, _parseRfc3339DateTimeWithOffset, _parseRfc7231DateTime;
var init_schema_date_utils = __esmMin((() => {
	ddd = `(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)(?:[ne|u?r]?s?day)?`;
	mmm = `(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`;
	time = `(\\d?\\d):(\\d{2}):(\\d{2})(?:\\.(\\d+))?`;
	date = `(\\d?\\d)`;
	year = `(\\d{4})`;
	RFC3339_WITH_OFFSET = /* @__PURE__ */ new RegExp(/^(\d{4})-(\d\d)-(\d\d)[tT](\d\d):(\d\d):(\d\d)(\.(\d+))?(([-+]\d\d:\d\d)|[zZ])$/);
	IMF_FIXDATE = /* @__PURE__ */ new RegExp(`^${ddd}, ${date} ${mmm} ${year} ${time} GMT$`);
	RFC_850_DATE = /* @__PURE__ */ new RegExp(`^${ddd}, ${date}-${mmm}-(\\d\\d) ${time} GMT$`);
	ASC_TIME = /* @__PURE__ */ new RegExp(`^${ddd} ${mmm} ( [1-9]|\\d\\d) ${time} ${year}$`);
	months = [
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
	_parseEpochTimestamp = (value) => {
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
	_parseRfc3339DateTimeWithOffset = (value) => {
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
	_parseRfc7231DateTime = (value) => {
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
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/split-every.js
function splitEvery(value, delimiter, numDelimiters) {
	if (numDelimiters <= 0 || !Number.isInteger(numDelimiters)) throw new Error("Invalid number of delimiters (" + numDelimiters + ") for splitEvery.");
	const segments = value.split(delimiter);
	if (numDelimiters === 1) return segments;
	const compoundSegments = [];
	let currentSegment = "";
	for (let i$3 = 0; i$3 < segments.length; i$3++) {
		if (currentSegment === "") currentSegment = segments[i$3];
		else currentSegment += delimiter + segments[i$3];
		if ((i$3 + 1) % numDelimiters === 0) {
			compoundSegments.push(currentSegment);
			currentSegment = "";
		}
	}
	if (currentSegment !== "") compoundSegments.push(currentSegment);
	return compoundSegments;
}
var init_split_every = __esmMin((() => {}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/split-header.js
var splitHeader;
var init_split_header = __esmMin((() => {
	splitHeader = (value) => {
		const z$1 = value.length;
		const values = [];
		let withinQuotes = false;
		let prevChar = void 0;
		let anchor = 0;
		for (let i$3 = 0; i$3 < z$1; ++i$3) {
			const char = value[i$3];
			switch (char) {
				case `"`:
					if (prevChar !== "\\") withinQuotes = !withinQuotes;
					break;
				case ",":
					if (!withinQuotes) {
						values.push(value.slice(anchor, i$3));
						anchor = i$3 + 1;
					}
					break;
				default:
			}
			prevChar = char;
		}
		values.push(value.slice(anchor));
		return values.map((v$3) => {
			v$3 = v$3.trim();
			const z$2 = v$3.length;
			if (z$2 < 2) return v$3;
			if (v$3[0] === `"` && v$3[z$2 - 1] === `"`) v$3 = v$3.slice(1, z$2 - 1);
			return v$3.replace(/\\"/g, "\"");
		});
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/value/NumericValue.js
function nv(input) {
	return new NumericValue(String(input), "bigDecimal");
}
var format, NumericValue;
var init_NumericValue = __esmMin((() => {
	format = /^-?\d*(\.\d+)?$/;
	NumericValue = class NumericValue {
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
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/serde/index.js
var serde_exports = /* @__PURE__ */ __exportAll({
	LazyJsonString: () => LazyJsonString,
	NumericValue: () => NumericValue,
	_parseEpochTimestamp: () => _parseEpochTimestamp,
	_parseRfc3339DateTimeWithOffset: () => _parseRfc3339DateTimeWithOffset,
	_parseRfc7231DateTime: () => _parseRfc7231DateTime,
	copyDocumentWithTransform: () => copyDocumentWithTransform,
	dateToUtcString: () => dateToUtcString$2,
	expectBoolean: () => expectBoolean,
	expectByte: () => expectByte,
	expectFloat32: () => expectFloat32,
	expectInt: () => expectInt,
	expectInt32: () => expectInt32,
	expectLong: () => expectLong,
	expectNonNull: () => expectNonNull,
	expectNumber: () => expectNumber,
	expectObject: () => expectObject,
	expectShort: () => expectShort,
	expectString: () => expectString,
	expectUnion: () => expectUnion$1,
	generateIdempotencyToken: () => import_dist_cjs$141.v4,
	handleFloat: () => handleFloat,
	limitedParseDouble: () => limitedParseDouble,
	limitedParseFloat: () => limitedParseFloat,
	limitedParseFloat32: () => limitedParseFloat32,
	logger: () => logger,
	nv: () => nv,
	parseBoolean: () => parseBoolean,
	parseEpochTimestamp: () => parseEpochTimestamp,
	parseRfc3339DateTime: () => parseRfc3339DateTime,
	parseRfc3339DateTimeWithOffset: () => parseRfc3339DateTimeWithOffset,
	parseRfc7231DateTime: () => parseRfc7231DateTime,
	quoteHeader: () => quoteHeader,
	splitEvery: () => splitEvery,
	splitHeader: () => splitHeader,
	strictParseByte: () => strictParseByte,
	strictParseDouble: () => strictParseDouble,
	strictParseFloat: () => strictParseFloat,
	strictParseFloat32: () => strictParseFloat32,
	strictParseInt: () => strictParseInt,
	strictParseInt32: () => strictParseInt32,
	strictParseLong: () => strictParseLong,
	strictParseShort: () => strictParseShort
});
var init_serde = __esmMin((() => {
	init_copyDocumentWithTransform();
	init_date_utils();
	init_generateIdempotencyToken();
	init_lazy_json();
	init_parse_utils();
	init_quote_header();
	init_schema_date_utils();
	init_split_every();
	init_split_header();
	init_NumericValue();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/SerdeContext.js
var SerdeContext;
var init_SerdeContext = __esmMin((() => {
	SerdeContext = class {
		serdeContext;
		setSerdeContext(serdeContext) {
			this.serdeContext = serdeContext;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/event-streams/EventStreamSerde.js
var import_dist_cjs$140, EventStreamSerde;
var init_EventStreamSerde = __esmMin((() => {
	import_dist_cjs$140 = require_dist_cjs$44();
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
								else if (member$1.isStringSchema()) out[name] = (this.serdeContext?.utf8Encoder ?? import_dist_cjs$140.toUtf8)(body);
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
				body: typeof messageSerialization === "string" ? (this.serdeContext?.utf8Decoder ?? import_dist_cjs$140.fromUtf8)(messageSerialization) : messageSerialization,
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
var import_dist_cjs$139, HttpProtocol;
var init_HttpProtocol = __esmMin((() => {
	init_schema();
	import_dist_cjs$139 = require_dist_cjs$52();
	init_SerdeContext();
	HttpProtocol = class extends SerdeContext {
		options;
		constructor(options) {
			super();
			this.options = options;
		}
		getRequestType() {
			return import_dist_cjs$139.HttpRequest;
		}
		getResponseType() {
			return import_dist_cjs$139.HttpResponse;
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
				for (const [k$3, v$3] of endpoint.url.searchParams.entries()) request.query[k$3] = v$3;
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
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/HttpBindingProtocol.js
var import_dist_cjs$137, import_dist_cjs$138, HttpBindingProtocol;
var init_HttpBindingProtocol = __esmMin((() => {
	init_schema();
	init_serde();
	import_dist_cjs$137 = require_dist_cjs$52();
	import_dist_cjs$138 = require_dist_cjs$37();
	init_collect_stream_body();
	init_extended_encode_uri_component();
	init_HttpProtocol();
	HttpBindingProtocol = class extends HttpProtocol {
		async serializeRequest(operationSchema, _input, context) {
			const input = { ..._input ?? {} };
			const serializer = this.serializer;
			const query = {};
			const headers = {};
			const endpoint = await context.endpoint();
			const ns = NormalizedSchema.of(operationSchema?.input);
			const schema = ns.getSchema();
			let hasNonHttpBindingMember = false;
			let payload$1;
			const request = new import_dist_cjs$137.HttpRequest({
				protocol: "",
				hostname: "",
				port: void 0,
				path: "",
				fragment: void 0,
				query,
				headers,
				body: void 0
			});
			if (endpoint) {
				this.updateServiceEndpoint(request, endpoint);
				this.setHostPrefix(request, operationSchema, input);
				const opTraits = translateTraits(operationSchema.traits);
				if (opTraits.http) {
					request.method = opTraits.http[0];
					const [path$1, search] = opTraits.http[1].split("?");
					if (request.path == "/") request.path = path$1;
					else request.path += path$1;
					const traitSearchParams = new URLSearchParams(search ?? "");
					Object.assign(query, Object.fromEntries(traitSearchParams));
				}
			}
			for (const [memberName, memberNs] of ns.structIterator()) {
				const memberTraits = memberNs.getMergedTraits() ?? {};
				const inputMemberValue = input[memberName];
				if (inputMemberValue == null && !memberNs.isIdempotencyToken()) continue;
				if (memberTraits.httpPayload) {
					if (memberNs.isStreaming()) if (memberNs.isStructSchema()) {
						if (input[memberName]) payload$1 = await this.serializeEventStream({
							eventStream: input[memberName],
							requestSchema: ns
						});
					} else payload$1 = inputMemberValue;
					else {
						serializer.write(memberNs, inputMemberValue);
						payload$1 = serializer.flush();
					}
					delete input[memberName];
				} else if (memberTraits.httpLabel) {
					serializer.write(memberNs, inputMemberValue);
					const replacement = serializer.flush();
					if (request.path.includes(`{${memberName}+}`)) request.path = request.path.replace(`{${memberName}+}`, replacement.split("/").map(extendedEncodeURIComponent).join("/"));
					else if (request.path.includes(`{${memberName}}`)) request.path = request.path.replace(`{${memberName}}`, extendedEncodeURIComponent(replacement));
					delete input[memberName];
				} else if (memberTraits.httpHeader) {
					serializer.write(memberNs, inputMemberValue);
					headers[memberTraits.httpHeader.toLowerCase()] = String(serializer.flush());
					delete input[memberName];
				} else if (typeof memberTraits.httpPrefixHeaders === "string") {
					for (const [key, val] of Object.entries(inputMemberValue)) {
						const amalgam = memberTraits.httpPrefixHeaders + key;
						serializer.write([memberNs.getValueSchema(), { httpHeader: amalgam }], val);
						headers[amalgam.toLowerCase()] = serializer.flush();
					}
					delete input[memberName];
				} else if (memberTraits.httpQuery || memberTraits.httpQueryParams) {
					this.serializeQuery(memberNs, inputMemberValue, query);
					delete input[memberName];
				} else hasNonHttpBindingMember = true;
			}
			if (hasNonHttpBindingMember && input) {
				serializer.write(schema, input);
				payload$1 = serializer.flush();
			}
			request.headers = headers;
			request.query = query;
			request.body = payload$1;
			return request;
		}
		serializeQuery(ns, data$1, query) {
			const serializer = this.serializer;
			const traits = ns.getMergedTraits();
			if (traits.httpQueryParams) {
				for (const [key, val] of Object.entries(data$1)) if (!(key in query)) {
					const valueSchema = ns.getValueSchema();
					Object.assign(valueSchema.getMergedTraits(), {
						...traits,
						httpQuery: key,
						httpQueryParams: void 0
					});
					this.serializeQuery(valueSchema, val, query);
				}
				return;
			}
			if (ns.isListSchema()) {
				const sparse = !!ns.getMergedTraits().sparse;
				const buffer$3 = [];
				for (const item of data$1) {
					serializer.write([ns.getValueSchema(), traits], item);
					const serializable = serializer.flush();
					if (sparse || serializable !== void 0) buffer$3.push(serializable);
				}
				query[traits.httpQuery] = buffer$3;
			} else {
				serializer.write([ns, traits], data$1);
				query[traits.httpQuery] = serializer.flush();
			}
		}
		async deserializeResponse(operationSchema, context, response) {
			const deserializer = this.deserializer;
			const ns = NormalizedSchema.of(operationSchema.output);
			const dataObject = {};
			if (response.statusCode >= 300) {
				const bytes = await collectBody$1(response.body, context);
				if (bytes.byteLength > 0) Object.assign(dataObject, await deserializer.read(15, bytes));
				await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
				throw new Error("@smithy/core/protocols - HTTP Protocol error handler failed to throw.");
			}
			for (const header in response.headers) {
				const value = response.headers[header];
				delete response.headers[header];
				response.headers[header.toLowerCase()] = value;
			}
			const nonHttpBindingMembers = await this.deserializeHttpMessage(ns, context, response, dataObject);
			if (nonHttpBindingMembers.length) {
				const bytes = await collectBody$1(response.body, context);
				if (bytes.byteLength > 0) {
					const dataFromBody = await deserializer.read(ns, bytes);
					for (const member$1 of nonHttpBindingMembers) dataObject[member$1] = dataFromBody[member$1];
				}
			} else if (nonHttpBindingMembers.discardResponseBody) await collectBody$1(response.body, context);
			dataObject.$metadata = this.deserializeMetadata(response);
			return dataObject;
		}
		async deserializeHttpMessage(schema, context, response, arg4, arg5) {
			let dataObject;
			if (arg4 instanceof Set) dataObject = arg5;
			else dataObject = arg4;
			let discardResponseBody = true;
			const deserializer = this.deserializer;
			const ns = NormalizedSchema.of(schema);
			const nonHttpBindingMembers = [];
			for (const [memberName, memberSchema] of ns.structIterator()) {
				const memberTraits = memberSchema.getMemberTraits();
				if (memberTraits.httpPayload) {
					discardResponseBody = false;
					if (memberSchema.isStreaming()) if (memberSchema.isStructSchema()) dataObject[memberName] = await this.deserializeEventStream({
						response,
						responseSchema: ns
					});
					else dataObject[memberName] = (0, import_dist_cjs$138.sdkStreamMixin)(response.body);
					else if (response.body) {
						const bytes = await collectBody$1(response.body, context);
						if (bytes.byteLength > 0) dataObject[memberName] = await deserializer.read(memberSchema, bytes);
					}
				} else if (memberTraits.httpHeader) {
					const key = String(memberTraits.httpHeader).toLowerCase();
					const value = response.headers[key];
					if (null != value) if (memberSchema.isListSchema()) {
						const headerListValueSchema = memberSchema.getValueSchema();
						headerListValueSchema.getMergedTraits().httpHeader = key;
						let sections;
						if (headerListValueSchema.isTimestampSchema() && headerListValueSchema.getSchema() === 4) sections = splitEvery(value, ",", 2);
						else sections = splitHeader(value);
						const list$1 = [];
						for (const section of sections) list$1.push(await deserializer.read(headerListValueSchema, section.trim()));
						dataObject[memberName] = list$1;
					} else dataObject[memberName] = await deserializer.read(memberSchema, value);
				} else if (memberTraits.httpPrefixHeaders !== void 0) {
					dataObject[memberName] = {};
					for (const [header, value] of Object.entries(response.headers)) if (header.startsWith(memberTraits.httpPrefixHeaders)) {
						const valueSchema = memberSchema.getValueSchema();
						valueSchema.getMergedTraits().httpHeader = header;
						dataObject[memberName][header.slice(memberTraits.httpPrefixHeaders.length)] = await deserializer.read(valueSchema, value);
					}
				} else if (memberTraits.httpResponseCode) dataObject[memberName] = response.statusCode;
				else nonHttpBindingMembers.push(memberName);
			}
			nonHttpBindingMembers.discardResponseBody = discardResponseBody;
			return nonHttpBindingMembers;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/RpcProtocol.js
var import_dist_cjs$136, RpcProtocol;
var init_RpcProtocol = __esmMin((() => {
	init_schema();
	import_dist_cjs$136 = require_dist_cjs$52();
	init_collect_stream_body();
	init_HttpProtocol();
	RpcProtocol = class extends HttpProtocol {
		async serializeRequest(operationSchema, input, context) {
			const serializer = this.serializer;
			const query = {};
			const headers = {};
			const endpoint = await context.endpoint();
			const ns = NormalizedSchema.of(operationSchema?.input);
			const schema = ns.getSchema();
			let payload$1;
			const request = new import_dist_cjs$136.HttpRequest({
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
						payload$1 = await this.serializeEventStream({
							eventStream: _input[eventStreamMember],
							requestSchema: ns,
							initialRequest
						});
					}
				} else {
					serializer.write(schema, _input);
					payload$1 = serializer.flush();
				}
			}
			request.headers = headers;
			request.query = query;
			request.body = payload$1;
			request.method = "POST";
			return request;
		}
		async deserializeResponse(operationSchema, context, response) {
			const deserializer = this.deserializer;
			const ns = NormalizedSchema.of(operationSchema.output);
			const dataObject = {};
			if (response.statusCode >= 300) {
				const bytes = await collectBody$1(response.body, context);
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
				const bytes = await collectBody$1(response.body, context);
				if (bytes.byteLength > 0) Object.assign(dataObject, await deserializer.read(ns, bytes));
			}
			dataObject.$metadata = this.deserializeMetadata(response);
			return dataObject;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/resolve-path.js
var resolvedPath;
var init_resolve_path = __esmMin((() => {
	init_extended_encode_uri_component();
	resolvedPath = (resolvedPath$1, input, memberName, labelValueProvider, uriLabel, isGreedyLabel) => {
		if (input != null && input[memberName] !== void 0) {
			const labelValue = labelValueProvider();
			if (labelValue.length <= 0) throw new Error("Empty value provided for input HTTP label: " + memberName + ".");
			resolvedPath$1 = resolvedPath$1.replace(uriLabel, isGreedyLabel ? labelValue.split("/").map((segment) => extendedEncodeURIComponent(segment)).join("/") : extendedEncodeURIComponent(labelValue));
		} else throw new Error("No value provided for input HTTP label: " + memberName + ".");
		return resolvedPath$1;
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/requestBuilder.js
function requestBuilder(input, context) {
	return new RequestBuilder(input, context);
}
var import_dist_cjs$135, RequestBuilder;
var init_requestBuilder$1 = __esmMin((() => {
	import_dist_cjs$135 = require_dist_cjs$52();
	init_resolve_path();
	RequestBuilder = class {
		input;
		context;
		query = {};
		method = "";
		headers = {};
		path = "";
		body = null;
		hostname = "";
		resolvePathStack = [];
		constructor(input, context) {
			this.input = input;
			this.context = context;
		}
		async build() {
			const { hostname, protocol = "https", port, path: basePath } = await this.context.endpoint();
			this.path = basePath;
			for (const resolvePath of this.resolvePathStack) resolvePath(this.path);
			return new import_dist_cjs$135.HttpRequest({
				protocol,
				hostname: this.hostname || hostname,
				port,
				method: this.method,
				path: this.path,
				query: this.query,
				body: this.body,
				headers: this.headers
			});
		}
		hn(hostname) {
			this.hostname = hostname;
			return this;
		}
		bp(uriLabel) {
			this.resolvePathStack.push((basePath) => {
				this.path = `${basePath?.endsWith("/") ? basePath.slice(0, -1) : basePath || ""}` + uriLabel;
			});
			return this;
		}
		p(memberName, labelValueProvider, uriLabel, isGreedyLabel) {
			this.resolvePathStack.push((path$1) => {
				this.path = resolvedPath(path$1, this.input, memberName, labelValueProvider, uriLabel, isGreedyLabel);
			});
			return this;
		}
		h(headers) {
			this.headers = headers;
			return this;
		}
		q(query) {
			this.query = query;
			return this;
		}
		b(body) {
			this.body = body;
			return this;
		}
		m(method) {
			this.method = method;
			return this;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/serde/determineTimestampFormat.js
function determineTimestampFormat(ns, settings) {
	if (settings.timestampFormat.useTrait) {
		if (ns.isTimestampSchema() && (ns.getSchema() === 5 || ns.getSchema() === 6 || ns.getSchema() === 7)) return ns.getSchema();
	}
	const { httpLabel, httpPrefixHeaders, httpHeader, httpQuery } = ns.getMergedTraits();
	return (settings.httpBindings ? typeof httpPrefixHeaders === "string" || Boolean(httpHeader) ? 6 : Boolean(httpQuery) || Boolean(httpLabel) ? 5 : void 0 : void 0) ?? settings.timestampFormat.default;
}
var init_determineTimestampFormat = __esmMin((() => {}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/serde/FromStringShapeDeserializer.js
var import_dist_cjs$133, import_dist_cjs$134, FromStringShapeDeserializer;
var init_FromStringShapeDeserializer = __esmMin((() => {
	init_schema();
	init_serde();
	import_dist_cjs$133 = require_dist_cjs$43();
	import_dist_cjs$134 = require_dist_cjs$44();
	init_SerdeContext();
	init_determineTimestampFormat();
	FromStringShapeDeserializer = class extends SerdeContext {
		settings;
		constructor(settings) {
			super();
			this.settings = settings;
		}
		read(_schema, data$1) {
			const ns = NormalizedSchema.of(_schema);
			if (ns.isListSchema()) return splitHeader(data$1).map((item) => this.read(ns.getValueSchema(), item));
			if (ns.isBlobSchema()) return (this.serdeContext?.base64Decoder ?? import_dist_cjs$133.fromBase64)(data$1);
			if (ns.isTimestampSchema()) switch (determineTimestampFormat(ns, this.settings)) {
				case 5: return _parseRfc3339DateTimeWithOffset(data$1);
				case 6: return _parseRfc7231DateTime(data$1);
				case 7: return _parseEpochTimestamp(data$1);
				default:
					console.warn("Missing timestamp format, parsing value with Date constructor:", data$1);
					return new Date(data$1);
			}
			if (ns.isStringSchema()) {
				const mediaType = ns.getMergedTraits().mediaType;
				let intermediateValue = data$1;
				if (mediaType) {
					if (ns.getMergedTraits().httpHeader) intermediateValue = this.base64ToUtf8(intermediateValue);
					if (mediaType === "application/json" || mediaType.endsWith("+json")) intermediateValue = LazyJsonString.from(intermediateValue);
					return intermediateValue;
				}
			}
			if (ns.isNumericSchema()) return Number(data$1);
			if (ns.isBigIntegerSchema()) return BigInt(data$1);
			if (ns.isBigDecimalSchema()) return new NumericValue(data$1, "bigDecimal");
			if (ns.isBooleanSchema()) return String(data$1).toLowerCase() === "true";
			return data$1;
		}
		base64ToUtf8(base64String) {
			return (this.serdeContext?.utf8Encoder ?? import_dist_cjs$134.toUtf8)((this.serdeContext?.base64Decoder ?? import_dist_cjs$133.fromBase64)(base64String));
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeDeserializer.js
var import_dist_cjs$132, HttpInterceptingShapeDeserializer;
var init_HttpInterceptingShapeDeserializer = __esmMin((() => {
	init_schema();
	import_dist_cjs$132 = require_dist_cjs$44();
	init_SerdeContext();
	init_FromStringShapeDeserializer();
	HttpInterceptingShapeDeserializer = class extends SerdeContext {
		codecDeserializer;
		stringDeserializer;
		constructor(codecDeserializer, codecSettings) {
			super();
			this.codecDeserializer = codecDeserializer;
			this.stringDeserializer = new FromStringShapeDeserializer(codecSettings);
		}
		setSerdeContext(serdeContext) {
			this.stringDeserializer.setSerdeContext(serdeContext);
			this.codecDeserializer.setSerdeContext(serdeContext);
			this.serdeContext = serdeContext;
		}
		read(schema, data$1) {
			const ns = NormalizedSchema.of(schema);
			const traits = ns.getMergedTraits();
			const toString = this.serdeContext?.utf8Encoder ?? import_dist_cjs$132.toUtf8;
			if (traits.httpHeader || traits.httpResponseCode) return this.stringDeserializer.read(ns, toString(data$1));
			if (traits.httpPayload) {
				if (ns.isBlobSchema()) {
					const toBytes = this.serdeContext?.utf8Decoder ?? import_dist_cjs$132.fromUtf8;
					if (typeof data$1 === "string") return toBytes(data$1);
					return data$1;
				} else if (ns.isStringSchema()) {
					if ("byteLength" in data$1) return toString(data$1);
					return data$1;
				}
			}
			return this.codecDeserializer.read(ns, data$1);
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/serde/ToStringShapeSerializer.js
var import_dist_cjs$131, ToStringShapeSerializer;
var init_ToStringShapeSerializer = __esmMin((() => {
	init_schema();
	init_serde();
	import_dist_cjs$131 = require_dist_cjs$43();
	init_SerdeContext();
	init_determineTimestampFormat();
	ToStringShapeSerializer = class extends SerdeContext {
		settings;
		stringBuffer = "";
		constructor(settings) {
			super();
			this.settings = settings;
		}
		write(schema, value) {
			const ns = NormalizedSchema.of(schema);
			switch (typeof value) {
				case "object":
					if (value === null) {
						this.stringBuffer = "null";
						return;
					}
					if (ns.isTimestampSchema()) {
						if (!(value instanceof Date)) throw new Error(`@smithy/core/protocols - received non-Date value ${value} when schema expected Date in ${ns.getName(true)}`);
						switch (determineTimestampFormat(ns, this.settings)) {
							case 5:
								this.stringBuffer = value.toISOString().replace(".000Z", "Z");
								break;
							case 6:
								this.stringBuffer = dateToUtcString$2(value);
								break;
							case 7:
								this.stringBuffer = String(value.getTime() / 1e3);
								break;
							default:
								console.warn("Missing timestamp format, using epoch seconds", value);
								this.stringBuffer = String(value.getTime() / 1e3);
						}
						return;
					}
					if (ns.isBlobSchema() && "byteLength" in value) {
						this.stringBuffer = (this.serdeContext?.base64Encoder ?? import_dist_cjs$131.toBase64)(value);
						return;
					}
					if (ns.isListSchema() && Array.isArray(value)) {
						let buffer$3 = "";
						for (const item of value) {
							this.write([ns.getValueSchema(), ns.getMergedTraits()], item);
							const headerItem = this.flush();
							const serialized = ns.getValueSchema().isTimestampSchema() ? headerItem : quoteHeader(headerItem);
							if (buffer$3 !== "") buffer$3 += ", ";
							buffer$3 += serialized;
						}
						this.stringBuffer = buffer$3;
						return;
					}
					this.stringBuffer = JSON.stringify(value, null, 2);
					break;
				case "string":
					const mediaType = ns.getMergedTraits().mediaType;
					let intermediateValue = value;
					if (mediaType) {
						if (mediaType === "application/json" || mediaType.endsWith("+json")) intermediateValue = LazyJsonString.from(intermediateValue);
						if (ns.getMergedTraits().httpHeader) {
							this.stringBuffer = (this.serdeContext?.base64Encoder ?? import_dist_cjs$131.toBase64)(intermediateValue.toString());
							return;
						}
					}
					this.stringBuffer = value;
					break;
				default: if (ns.isIdempotencyToken()) this.stringBuffer = (0, import_dist_cjs$141.v4)();
				else this.stringBuffer = String(value);
			}
		}
		flush() {
			const buffer$3 = this.stringBuffer;
			this.stringBuffer = "";
			return buffer$3;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeSerializer.js
var HttpInterceptingShapeSerializer;
var init_HttpInterceptingShapeSerializer = __esmMin((() => {
	init_schema();
	init_ToStringShapeSerializer();
	HttpInterceptingShapeSerializer = class {
		codecSerializer;
		stringSerializer;
		buffer;
		constructor(codecSerializer, codecSettings, stringSerializer = new ToStringShapeSerializer(codecSettings)) {
			this.codecSerializer = codecSerializer;
			this.stringSerializer = stringSerializer;
		}
		setSerdeContext(serdeContext) {
			this.codecSerializer.setSerdeContext(serdeContext);
			this.stringSerializer.setSerdeContext(serdeContext);
		}
		write(schema, value) {
			const ns = NormalizedSchema.of(schema);
			const traits = ns.getMergedTraits();
			if (traits.httpHeader || traits.httpLabel || traits.httpQuery) {
				this.stringSerializer.write(ns, value);
				this.buffer = this.stringSerializer.flush();
				return;
			}
			return this.codecSerializer.write(ns, value);
		}
		flush() {
			if (this.buffer !== void 0) {
				const buffer$3 = this.buffer;
				this.buffer = void 0;
				return buffer$3;
			}
			return this.codecSerializer.flush();
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/protocols/index.js
var protocols_exports$1 = /* @__PURE__ */ __exportAll({
	FromStringShapeDeserializer: () => FromStringShapeDeserializer,
	HttpBindingProtocol: () => HttpBindingProtocol,
	HttpInterceptingShapeDeserializer: () => HttpInterceptingShapeDeserializer,
	HttpInterceptingShapeSerializer: () => HttpInterceptingShapeSerializer,
	HttpProtocol: () => HttpProtocol,
	RequestBuilder: () => RequestBuilder,
	RpcProtocol: () => RpcProtocol,
	SerdeContext: () => SerdeContext,
	ToStringShapeSerializer: () => ToStringShapeSerializer,
	collectBody: () => collectBody$1,
	determineTimestampFormat: () => determineTimestampFormat,
	extendedEncodeURIComponent: () => extendedEncodeURIComponent,
	requestBuilder: () => requestBuilder,
	resolvedPath: () => resolvedPath
});
var init_protocols$1 = __esmMin((() => {
	init_collect_stream_body();
	init_extended_encode_uri_component();
	init_HttpBindingProtocol();
	init_HttpProtocol();
	init_RpcProtocol();
	init_requestBuilder$1();
	init_resolve_path();
	init_FromStringShapeDeserializer();
	init_HttpInterceptingShapeDeserializer();
	init_HttpInterceptingShapeSerializer();
	init_ToStringShapeSerializer();
	init_determineTimestampFormat();
	init_SerdeContext();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/request-builder/requestBuilder.js
var init_requestBuilder = __esmMin((() => {
	init_protocols$1();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/setFeature.js
function setFeature$1(context, feature, value) {
	if (!context.__smithy_context) context.__smithy_context = { features: {} };
	else if (!context.__smithy_context.features) context.__smithy_context.features = {};
	context.__smithy_context.features[feature] = value;
}
var init_setFeature$1 = __esmMin((() => {}));

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/DefaultIdentityProviderConfig.js
var DefaultIdentityProviderConfig;
var init_DefaultIdentityProviderConfig = __esmMin((() => {
	DefaultIdentityProviderConfig = class {
		authSchemes = /* @__PURE__ */ new Map();
		constructor(config) {
			for (const [key, value] of Object.entries(config)) if (value !== void 0) this.authSchemes.set(key, value);
		}
		getIdentityProvider(schemeId) {
			return this.authSchemes.get(schemeId);
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpApiKeyAuth.js
var import_dist_cjs$129, import_dist_cjs$130, HttpApiKeyAuthSigner;
var init_httpApiKeyAuth = __esmMin((() => {
	import_dist_cjs$129 = require_dist_cjs$52();
	import_dist_cjs$130 = require_dist_cjs$53();
	HttpApiKeyAuthSigner = class {
		async sign(httpRequest, identity, signingProperties) {
			if (!signingProperties) throw new Error("request could not be signed with `apiKey` since the `name` and `in` signer properties are missing");
			if (!signingProperties.name) throw new Error("request could not be signed with `apiKey` since the `name` signer property is missing");
			if (!signingProperties.in) throw new Error("request could not be signed with `apiKey` since the `in` signer property is missing");
			if (!identity.apiKey) throw new Error("request could not be signed with `apiKey` since the `apiKey` is not defined");
			const clonedRequest = import_dist_cjs$129.HttpRequest.clone(httpRequest);
			if (signingProperties.in === import_dist_cjs$130.HttpApiKeyAuthLocation.QUERY) clonedRequest.query[signingProperties.name] = identity.apiKey;
			else if (signingProperties.in === import_dist_cjs$130.HttpApiKeyAuthLocation.HEADER) clonedRequest.headers[signingProperties.name] = signingProperties.scheme ? `${signingProperties.scheme} ${identity.apiKey}` : identity.apiKey;
			else throw new Error("request can only be signed with `apiKey` locations `query` or `header`, but found: `" + signingProperties.in + "`");
			return clonedRequest;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpBearerAuth.js
var import_dist_cjs$128, HttpBearerAuthSigner;
var init_httpBearerAuth = __esmMin((() => {
	import_dist_cjs$128 = require_dist_cjs$52();
	HttpBearerAuthSigner = class {
		async sign(httpRequest, identity, signingProperties) {
			const clonedRequest = import_dist_cjs$128.HttpRequest.clone(httpRequest);
			if (!identity.token) throw new Error("request could not be signed with `token` since the `token` is not defined");
			clonedRequest.headers["Authorization"] = `Bearer ${identity.token}`;
			return clonedRequest;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/noAuth.js
var NoAuthSigner;
var init_noAuth = __esmMin((() => {
	NoAuthSigner = class {
		async sign(httpRequest, identity, signingProperties) {
			return httpRequest;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/index.js
var init_httpAuthSchemes$1 = __esmMin((() => {
	init_httpApiKeyAuth();
	init_httpBearerAuth();
	init_noAuth();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/memoizeIdentityProvider.js
var createIsIdentityExpiredFunction, EXPIRATION_MS, isIdentityExpired, doesIdentityRequireRefresh, memoizeIdentityProvider;
var init_memoizeIdentityProvider = __esmMin((() => {
	createIsIdentityExpiredFunction = (expirationMs) => function isIdentityExpired$1(identity) {
		return doesIdentityRequireRefresh(identity) && identity.expiration.getTime() - Date.now() < expirationMs;
	};
	EXPIRATION_MS = 3e5;
	isIdentityExpired = createIsIdentityExpiredFunction(EXPIRATION_MS);
	doesIdentityRequireRefresh = (identity) => identity.expiration !== void 0;
	memoizeIdentityProvider = (provider, isExpired, requiresRefresh) => {
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
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/util-identity-and-auth/index.js
var init_util_identity_and_auth = __esmMin((() => {
	init_DefaultIdentityProviderConfig();
	init_httpAuthSchemes$1();
	init_memoizeIdentityProvider();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/index.js
var dist_es_exports$1 = /* @__PURE__ */ __exportAll({
	DefaultIdentityProviderConfig: () => DefaultIdentityProviderConfig,
	EXPIRATION_MS: () => EXPIRATION_MS,
	HttpApiKeyAuthSigner: () => HttpApiKeyAuthSigner,
	HttpBearerAuthSigner: () => HttpBearerAuthSigner,
	NoAuthSigner: () => NoAuthSigner,
	createIsIdentityExpiredFunction: () => createIsIdentityExpiredFunction,
	createPaginator: () => createPaginator,
	doesIdentityRequireRefresh: () => doesIdentityRequireRefresh,
	getHttpAuthSchemeEndpointRuleSetPlugin: () => getHttpAuthSchemeEndpointRuleSetPlugin,
	getHttpAuthSchemePlugin: () => getHttpAuthSchemePlugin,
	getHttpSigningPlugin: () => getHttpSigningPlugin,
	getSmithyContext: () => getSmithyContext$8,
	httpAuthSchemeEndpointRuleSetMiddlewareOptions: () => httpAuthSchemeEndpointRuleSetMiddlewareOptions,
	httpAuthSchemeMiddleware: () => httpAuthSchemeMiddleware,
	httpAuthSchemeMiddlewareOptions: () => httpAuthSchemeMiddlewareOptions,
	httpSigningMiddleware: () => httpSigningMiddleware,
	httpSigningMiddlewareOptions: () => httpSigningMiddlewareOptions,
	isIdentityExpired: () => isIdentityExpired,
	memoizeIdentityProvider: () => memoizeIdentityProvider,
	normalizeProvider: () => normalizeProvider$3,
	requestBuilder: () => requestBuilder,
	setFeature: () => setFeature$1
});
var init_dist_es$1 = __esmMin((() => {
	init_getSmithyContext();
	init_middleware_http_auth_scheme();
	init_middleware_http_signing();
	init_normalizeProvider();
	init_createPaginator();
	init_requestBuilder();
	init_setFeature$1();
	init_util_identity_and_auth();
}));

//#endregion
//#region node_modules/@smithy/util-endpoints/dist-cjs/index.js
var require_dist_cjs$35 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var types = require_dist_cjs$53();
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
					let i$3 = 0;
					while (true) {
						const { value, done } = keys.next();
						this.data.delete(value);
						if (done || ++i$3 > 10) break;
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
			let buffer$3 = "";
			const { parameters } = this;
			if (parameters.length === 0) return false;
			for (const param of parameters) {
				const val = String(endpointParams[param] ?? "");
				if (val.includes("|;")) return false;
				buffer$3 += val + "|;";
			}
			return buffer$3;
		}
	};
	const IP_V4_REGEX = /* @__PURE__ */ new RegExp(`^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}$`);
	const isIpAddress = (value) => IP_V4_REGEX.test(value) || value.startsWith("[") && value.endsWith("]");
	const VALID_HOST_LABEL_REGEX = /* @__PURE__ */ new RegExp(`^(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63}$`);
	const isValidHostLabel = (value, allowSubDomains = false) => {
		if (!allowSubDomains) return VALID_HOST_LABEL_REGEX.test(value);
		const labels = value.split(".");
		for (const label of labels) if (!isValidHostLabel(label)) return false;
		return true;
	};
	const customEndpointFunctions = {};
	const debugId = "endpoints";
	function toDebugString(input) {
		if (typeof input !== "object" || input == null) return input;
		if ("ref" in input) return `$${toDebugString(input.ref)}`;
		if ("fn" in input) return `${input.fn}(${(input.argv || []).map(toDebugString).join(", ")})`;
		return JSON.stringify(input, null, 2);
	}
	var EndpointError = class extends Error {
		constructor(message) {
			super(message);
			this.name = "EndpointError";
		}
	};
	const booleanEquals = (value1, value2) => value1 === value2;
	const getAttrPathList = (path$1) => {
		const parts = path$1.split(".");
		const pathList = [];
		for (const part of parts) {
			const squareBracketIndex = part.indexOf("[");
			if (squareBracketIndex !== -1) {
				if (part.indexOf("]") !== part.length - 1) throw new EndpointError(`Path: '${path$1}' does not end with ']'`);
				const arrayIndex = part.slice(squareBracketIndex + 1, -1);
				if (Number.isNaN(parseInt(arrayIndex))) throw new EndpointError(`Invalid array index: '${arrayIndex}' in path: '${path$1}'`);
				if (squareBracketIndex !== 0) pathList.push(part.slice(0, squareBracketIndex));
				pathList.push(arrayIndex);
			} else pathList.push(part);
		}
		return pathList;
	};
	const getAttr = (value, path$1) => getAttrPathList(path$1).reduce((acc, index) => {
		if (typeof acc !== "object") throw new EndpointError(`Index '${index}' in '${path$1}' not found in '${JSON.stringify(value)}'`);
		else if (Array.isArray(acc)) return acc[parseInt(index)];
		return acc[index];
	}, value);
	const isSet = (value) => value != null;
	const not = (value) => !value;
	const DEFAULT_PORTS = {
		[types.EndpointURLScheme.HTTP]: 80,
		[types.EndpointURLScheme.HTTPS]: 443
	};
	const parseURL = (value) => {
		const whatwgURL = (() => {
			try {
				if (value instanceof URL) return value;
				if (typeof value === "object" && "hostname" in value) {
					const { hostname: hostname$1, port, protocol: protocol$1 = "", path: path$1 = "", query = {} } = value;
					const url$1 = new URL(`${protocol$1}//${hostname$1}${port ? `:${port}` : ""}${path$1}`);
					url$1.search = Object.entries(query).map(([k$3, v$3]) => `${k$3}=${v$3}`).join("&");
					return url$1;
				}
				return new URL(value);
			} catch (error$1) {
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
		if (!Object.values(types.EndpointURLScheme).includes(scheme)) return null;
		const isIp = isIpAddress(hostname);
		return {
			scheme,
			authority: `${host}${urlString.includes(`${host}:${DEFAULT_PORTS[scheme]}`) || typeof value === "string" && value.includes(`${host}:${DEFAULT_PORTS[scheme]}`) ? `:${DEFAULT_PORTS[scheme]}` : ``}`,
			path: pathname,
			normalizedPath: pathname.endsWith("/") ? pathname : `${pathname}/`,
			isIp
		};
	};
	const stringEquals = (value1, value2) => value1 === value2;
	const substring = (input, start, stop, reverse) => {
		if (start >= stop || input.length < stop) return null;
		if (!reverse) return input.substring(start, stop);
		return input.substring(input.length - stop, input.length - start);
	};
	const uriEncode = (value) => encodeURIComponent(value).replace(/[!*'()]/g, (c$3) => `%${c$3.charCodeAt(0).toString(16).toUpperCase()}`);
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
	const getReferenceValue = ({ ref }, options) => {
		return {
			...options.endpointParams,
			...options.referenceRecord
		}[ref];
	};
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
	const getEndpointHeaders = (headers, options) => Object.entries(headers).reduce((acc, [headerKey, headerVal]) => ({
		...acc,
		[headerKey]: headerVal.map((headerValEntry) => {
			const processedExpr = evaluateExpression(headerValEntry, "Header value entry", options);
			if (typeof processedExpr !== "string") throw new EndpointError(`Header '${headerKey}' value '${processedExpr}' is not a string`);
			return processedExpr;
		})
	}), {});
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
	const getEndpointUrl = (endpointUrl, options) => {
		const expression = evaluateExpression(endpointUrl, "Endpoint URL", options);
		if (typeof expression === "string") try {
			return new URL(expression);
		} catch (error$1) {
			console.error(`Failed to construct URL with ${expression}`, error$1);
			throw error$1;
		}
		throw new EndpointError(`Endpoint URL must be a string, got ${typeof expression}`);
	};
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
		const { url: url$1, properties, headers } = endpoint;
		options.logger?.debug?.(`${debugId} Resolving endpoint from template: ${toDebugString(endpoint)}`);
		return {
			...headers != void 0 && { headers: getEndpointHeaders(headers, endpointRuleOptions) },
			...properties != void 0 && { properties: getEndpointProperties(properties, endpointRuleOptions) },
			url: getEndpointUrl(url$1, endpointRuleOptions)
		};
	};
	const evaluateErrorRule = (errorRule, options) => {
		const { conditions, error: error$1 } = errorRule;
		const { result, referenceRecord } = evaluateConditions(conditions, options);
		if (!result) return;
		throw new EndpointError(evaluateExpression(error$1, "Error", {
			...options,
			referenceRecord: {
				...options.referenceRecord,
				...referenceRecord
			}
		}));
	};
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
	const resolveEndpoint = (ruleSetObject, options) => {
		const { endpointParams, logger: logger$1 } = options;
		const { parameters, rules } = ruleSetObject;
		options.logger?.debug?.(`${debugId} Initial EndpointParams: ${toDebugString(endpointParams)}`);
		const paramsWithDefault = Object.entries(parameters).filter(([, v$3]) => v$3.default != null).map(([k$3, v$3]) => [k$3, v$3.default]);
		if (paramsWithDefault.length > 0) for (const [paramKey, paramDefaultValue] of paramsWithDefault) endpointParams[paramKey] = endpointParams[paramKey] ?? paramDefaultValue;
		const requiredParams = Object.entries(parameters).filter(([, v$3]) => v$3.required).map(([k$3]) => k$3);
		for (const requiredParam of requiredParams) if (endpointParams[requiredParam] == null) throw new EndpointError(`Missing required parameter: '${requiredParam}'`);
		const endpoint = evaluateRules(rules, {
			endpointParams,
			logger: logger$1,
			referenceRecord: {}
		});
		options.logger?.debug?.(`${debugId} Resolved endpoint: ${toDebugString(endpoint)}`);
		return endpoint;
	};
	exports.EndpointCache = EndpointCache;
	exports.EndpointError = EndpointError;
	exports.customEndpointFunctions = customEndpointFunctions;
	exports.isIpAddress = isIpAddress;
	exports.isValidHostLabel = isValidHostLabel;
	exports.resolveEndpoint = resolveEndpoint;
}));

//#endregion
//#region node_modules/@smithy/querystring-parser/dist-cjs/index.js
var require_dist_cjs$34 = /* @__PURE__ */ __commonJSMin(((exports) => {
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
	exports.parseQueryString = parseQueryString;
}));

//#endregion
//#region node_modules/@smithy/url-parser/dist-cjs/index.js
var require_dist_cjs$33 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var querystringParser = require_dist_cjs$34();
	const parseUrl = (url$1) => {
		if (typeof url$1 === "string") return parseUrl(new URL(url$1));
		const { hostname, pathname, port, protocol, search } = url$1;
		let query;
		if (search) query = querystringParser.parseQueryString(search);
		return {
			hostname,
			port: port ? parseInt(port) : void 0,
			protocol,
			path: pathname,
			query
		};
	};
	exports.parseUrl = parseUrl;
}));

//#endregion
//#region node_modules/@aws-sdk/util-endpoints/dist-cjs/index.js
var require_dist_cjs$32 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilEndpoints = require_dist_cjs$35();
	var urlParser = require_dist_cjs$33();
	const isVirtualHostableS3Bucket = (value, allowSubDomains = false) => {
		if (allowSubDomains) {
			for (const label of value.split(".")) if (!isVirtualHostableS3Bucket(label)) return false;
			return true;
		}
		if (!utilEndpoints.isValidHostLabel(value)) return false;
		if (value.length < 3 || value.length > 63) return false;
		if (value !== value.toLowerCase()) return false;
		if (utilEndpoints.isIpAddress(value)) return false;
		return true;
	};
	const ARN_DELIMITER = ":";
	const RESOURCE_DELIMITER = "/";
	const parseArn = (value) => {
		const segments = value.split(ARN_DELIMITER);
		if (segments.length < 6) return null;
		const [arn, partition, service, region, accountId, ...resourcePath] = segments;
		if (arn !== "arn" || partition === "" || service === "" || resourcePath.join(ARN_DELIMITER) === "") return null;
		return {
			partition,
			service,
			region,
			accountId,
			resourceId: resourcePath.map((resource) => resource.split(RESOURCE_DELIMITER)).flat()
		};
	};
	var partitionsInfo = {
		partitions: [
			{
				id: "aws",
				outputs: {
					dnsSuffix: "amazonaws.com",
					dualStackDnsSuffix: "api.aws",
					implicitGlobalRegion: "us-east-1",
					name: "aws",
					supportsDualStack: true,
					supportsFIPS: true
				},
				regionRegex: "^(us|eu|ap|sa|ca|me|af|il|mx)\\-\\w+\\-\\d+$",
				regions: {
					"af-south-1": { description: "Africa (Cape Town)" },
					"ap-east-1": { description: "Asia Pacific (Hong Kong)" },
					"ap-east-2": { description: "Asia Pacific (Taipei)" },
					"ap-northeast-1": { description: "Asia Pacific (Tokyo)" },
					"ap-northeast-2": { description: "Asia Pacific (Seoul)" },
					"ap-northeast-3": { description: "Asia Pacific (Osaka)" },
					"ap-south-1": { description: "Asia Pacific (Mumbai)" },
					"ap-south-2": { description: "Asia Pacific (Hyderabad)" },
					"ap-southeast-1": { description: "Asia Pacific (Singapore)" },
					"ap-southeast-2": { description: "Asia Pacific (Sydney)" },
					"ap-southeast-3": { description: "Asia Pacific (Jakarta)" },
					"ap-southeast-4": { description: "Asia Pacific (Melbourne)" },
					"ap-southeast-5": { description: "Asia Pacific (Malaysia)" },
					"ap-southeast-6": { description: "Asia Pacific (New Zealand)" },
					"ap-southeast-7": { description: "Asia Pacific (Thailand)" },
					"aws-global": { description: "aws global region" },
					"ca-central-1": { description: "Canada (Central)" },
					"ca-west-1": { description: "Canada West (Calgary)" },
					"eu-central-1": { description: "Europe (Frankfurt)" },
					"eu-central-2": { description: "Europe (Zurich)" },
					"eu-north-1": { description: "Europe (Stockholm)" },
					"eu-south-1": { description: "Europe (Milan)" },
					"eu-south-2": { description: "Europe (Spain)" },
					"eu-west-1": { description: "Europe (Ireland)" },
					"eu-west-2": { description: "Europe (London)" },
					"eu-west-3": { description: "Europe (Paris)" },
					"il-central-1": { description: "Israel (Tel Aviv)" },
					"me-central-1": { description: "Middle East (UAE)" },
					"me-south-1": { description: "Middle East (Bahrain)" },
					"mx-central-1": { description: "Mexico (Central)" },
					"sa-east-1": { description: "South America (Sao Paulo)" },
					"us-east-1": { description: "US East (N. Virginia)" },
					"us-east-2": { description: "US East (Ohio)" },
					"us-west-1": { description: "US West (N. California)" },
					"us-west-2": { description: "US West (Oregon)" }
				}
			},
			{
				id: "aws-cn",
				outputs: {
					dnsSuffix: "amazonaws.com.cn",
					dualStackDnsSuffix: "api.amazonwebservices.com.cn",
					implicitGlobalRegion: "cn-northwest-1",
					name: "aws-cn",
					supportsDualStack: true,
					supportsFIPS: true
				},
				regionRegex: "^cn\\-\\w+\\-\\d+$",
				regions: {
					"aws-cn-global": { description: "aws-cn global region" },
					"cn-north-1": { description: "China (Beijing)" },
					"cn-northwest-1": { description: "China (Ningxia)" }
				}
			},
			{
				id: "aws-eusc",
				outputs: {
					dnsSuffix: "amazonaws.eu",
					dualStackDnsSuffix: "api.amazonwebservices.eu",
					implicitGlobalRegion: "eusc-de-east-1",
					name: "aws-eusc",
					supportsDualStack: true,
					supportsFIPS: true
				},
				regionRegex: "^eusc\\-(de)\\-\\w+\\-\\d+$",
				regions: { "eusc-de-east-1": { description: "EU (Germany)" } }
			},
			{
				id: "aws-iso",
				outputs: {
					dnsSuffix: "c2s.ic.gov",
					dualStackDnsSuffix: "api.aws.ic.gov",
					implicitGlobalRegion: "us-iso-east-1",
					name: "aws-iso",
					supportsDualStack: true,
					supportsFIPS: true
				},
				regionRegex: "^us\\-iso\\-\\w+\\-\\d+$",
				regions: {
					"aws-iso-global": { description: "aws-iso global region" },
					"us-iso-east-1": { description: "US ISO East" },
					"us-iso-west-1": { description: "US ISO WEST" }
				}
			},
			{
				id: "aws-iso-b",
				outputs: {
					dnsSuffix: "sc2s.sgov.gov",
					dualStackDnsSuffix: "api.aws.scloud",
					implicitGlobalRegion: "us-isob-east-1",
					name: "aws-iso-b",
					supportsDualStack: true,
					supportsFIPS: true
				},
				regionRegex: "^us\\-isob\\-\\w+\\-\\d+$",
				regions: {
					"aws-iso-b-global": { description: "aws-iso-b global region" },
					"us-isob-east-1": { description: "US ISOB East (Ohio)" },
					"us-isob-west-1": { description: "US ISOB West" }
				}
			},
			{
				id: "aws-iso-e",
				outputs: {
					dnsSuffix: "cloud.adc-e.uk",
					dualStackDnsSuffix: "api.cloud-aws.adc-e.uk",
					implicitGlobalRegion: "eu-isoe-west-1",
					name: "aws-iso-e",
					supportsDualStack: true,
					supportsFIPS: true
				},
				regionRegex: "^eu\\-isoe\\-\\w+\\-\\d+$",
				regions: {
					"aws-iso-e-global": { description: "aws-iso-e global region" },
					"eu-isoe-west-1": { description: "EU ISOE West" }
				}
			},
			{
				id: "aws-iso-f",
				outputs: {
					dnsSuffix: "csp.hci.ic.gov",
					dualStackDnsSuffix: "api.aws.hci.ic.gov",
					implicitGlobalRegion: "us-isof-south-1",
					name: "aws-iso-f",
					supportsDualStack: true,
					supportsFIPS: true
				},
				regionRegex: "^us\\-isof\\-\\w+\\-\\d+$",
				regions: {
					"aws-iso-f-global": { description: "aws-iso-f global region" },
					"us-isof-east-1": { description: "US ISOF EAST" },
					"us-isof-south-1": { description: "US ISOF SOUTH" }
				}
			},
			{
				id: "aws-us-gov",
				outputs: {
					dnsSuffix: "amazonaws.com",
					dualStackDnsSuffix: "api.aws",
					implicitGlobalRegion: "us-gov-west-1",
					name: "aws-us-gov",
					supportsDualStack: true,
					supportsFIPS: true
				},
				regionRegex: "^us\\-gov\\-\\w+\\-\\d+$",
				regions: {
					"aws-us-gov-global": { description: "aws-us-gov global region" },
					"us-gov-east-1": { description: "AWS GovCloud (US-East)" },
					"us-gov-west-1": { description: "AWS GovCloud (US-West)" }
				}
			}
		],
		version: "1.1"
	};
	let selectedPartitionsInfo = partitionsInfo;
	let selectedUserAgentPrefix = "";
	const partition = (value) => {
		const { partitions } = selectedPartitionsInfo;
		for (const partition of partitions) {
			const { regions, outputs } = partition;
			for (const [region, regionData] of Object.entries(regions)) if (region === value) return {
				...outputs,
				...regionData
			};
		}
		for (const partition of partitions) {
			const { regionRegex, outputs } = partition;
			if (new RegExp(regionRegex).test(value)) return { ...outputs };
		}
		const DEFAULT_PARTITION = partitions.find((partition) => partition.id === "aws");
		if (!DEFAULT_PARTITION) throw new Error("Provided region was not found in the partition array or regex, and default partition with id 'aws' doesn't exist.");
		return { ...DEFAULT_PARTITION.outputs };
	};
	const setPartitionInfo = (partitionsInfo, userAgentPrefix = "") => {
		selectedPartitionsInfo = partitionsInfo;
		selectedUserAgentPrefix = userAgentPrefix;
	};
	const useDefaultPartitionInfo = () => {
		setPartitionInfo(partitionsInfo, "");
	};
	const getUserAgentPrefix = () => selectedUserAgentPrefix;
	const awsEndpointFunctions = {
		isVirtualHostableS3Bucket,
		parseArn,
		partition
	};
	utilEndpoints.customEndpointFunctions.aws = awsEndpointFunctions;
	const resolveDefaultAwsRegionalEndpointsConfig = (input) => {
		if (typeof input.endpointProvider !== "function") throw new Error("@aws-sdk/util-endpoint - endpointProvider and endpoint missing in config for this client.");
		const { endpoint } = input;
		if (endpoint === void 0) input.endpoint = async () => {
			return toEndpointV1(input.endpointProvider({
				Region: typeof input.region === "function" ? await input.region() : input.region,
				UseDualStack: typeof input.useDualstackEndpoint === "function" ? await input.useDualstackEndpoint() : input.useDualstackEndpoint,
				UseFIPS: typeof input.useFipsEndpoint === "function" ? await input.useFipsEndpoint() : input.useFipsEndpoint,
				Endpoint: void 0
			}, { logger: input.logger }));
		};
		return input;
	};
	const toEndpointV1 = (endpoint) => urlParser.parseUrl(endpoint.url);
	Object.defineProperty(exports, "EndpointError", {
		enumerable: true,
		get: function() {
			return utilEndpoints.EndpointError;
		}
	});
	Object.defineProperty(exports, "isIpAddress", {
		enumerable: true,
		get: function() {
			return utilEndpoints.isIpAddress;
		}
	});
	Object.defineProperty(exports, "resolveEndpoint", {
		enumerable: true,
		get: function() {
			return utilEndpoints.resolveEndpoint;
		}
	});
	exports.awsEndpointFunctions = awsEndpointFunctions;
	exports.getUserAgentPrefix = getUserAgentPrefix;
	exports.partition = partition;
	exports.resolveDefaultAwsRegionalEndpointsConfig = resolveDefaultAwsRegionalEndpointsConfig;
	exports.setPartitionInfo = setPartitionInfo;
	exports.toEndpointV1 = toEndpointV1;
	exports.useDefaultPartitionInfo = useDefaultPartitionInfo;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/client/emitWarningIfUnsupportedVersion.js
var state, emitWarningIfUnsupportedVersion$3;
var init_emitWarningIfUnsupportedVersion = __esmMin((() => {
	state = { warningEmitted: false };
	emitWarningIfUnsupportedVersion$3 = (version$1) => {
		if (version$1 && !state.warningEmitted && parseInt(version$1.substring(1, version$1.indexOf("."))) < 20) {
			state.warningEmitted = true;
			process.emitWarning(`NodeDeprecationWarning: The AWS SDK for JavaScript (v3) will
no longer support Node.js ${version$1} in January 2026.

To continue receiving updates to AWS services, bug fixes, and security
updates please upgrade to a supported Node.js LTS version.

More information can be found at: https://a.co/c895JFp`);
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js
function setCredentialFeature(credentials, feature, value) {
	if (!credentials.$source) credentials.$source = {};
	credentials.$source[feature] = value;
	return credentials;
}
var init_setCredentialFeature = __esmMin((() => {}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js
function setFeature(context, feature, value) {
	if (!context.__aws_sdk_context) context.__aws_sdk_context = { features: {} };
	else if (!context.__aws_sdk_context.features) context.__aws_sdk_context.features = {};
	context.__aws_sdk_context.features[feature] = value;
}
var init_setFeature = __esmMin((() => {}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/client/setTokenFeature.js
function setTokenFeature(token, feature, value) {
	if (!token.$source) token.$source = {};
	token.$source[feature] = value;
	return token;
}
var init_setTokenFeature = __esmMin((() => {}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/client/index.js
var client_exports = /* @__PURE__ */ __exportAll({
	emitWarningIfUnsupportedVersion: () => emitWarningIfUnsupportedVersion$3,
	setCredentialFeature: () => setCredentialFeature,
	setFeature: () => setFeature,
	setTokenFeature: () => setTokenFeature,
	state: () => state
});
var init_client = __esmMin((() => {
	init_emitWarningIfUnsupportedVersion();
	init_setCredentialFeature();
	init_setFeature();
	init_setTokenFeature();
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getDateHeader.js
var import_dist_cjs$127, getDateHeader;
var init_getDateHeader = __esmMin((() => {
	import_dist_cjs$127 = require_dist_cjs$52();
	getDateHeader = (response) => import_dist_cjs$127.HttpResponse.isInstance(response) ? response.headers?.date ?? response.headers?.Date : void 0;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.js
var getSkewCorrectedDate;
var init_getSkewCorrectedDate = __esmMin((() => {
	getSkewCorrectedDate = (systemClockOffset) => new Date(Date.now() + systemClockOffset);
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/isClockSkewed.js
var isClockSkewed;
var init_isClockSkewed = __esmMin((() => {
	init_getSkewCorrectedDate();
	isClockSkewed = (clockTime, systemClockOffset) => Math.abs(getSkewCorrectedDate(systemClockOffset).getTime() - clockTime) >= 3e5;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.js
var getUpdatedSystemClockOffset;
var init_getUpdatedSystemClockOffset = __esmMin((() => {
	init_isClockSkewed();
	getUpdatedSystemClockOffset = (clockTime, currentSystemClockOffset) => {
		const clockTimeInMs = Date.parse(clockTime);
		if (isClockSkewed(clockTimeInMs, currentSystemClockOffset)) return clockTimeInMs - Date.now();
		return currentSystemClockOffset;
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/index.js
var init_utils = __esmMin((() => {
	init_getDateHeader();
	init_getSkewCorrectedDate();
	init_getUpdatedSystemClockOffset();
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js
var import_dist_cjs$126, throwSigningPropertyError, validateSigningProperties, AwsSdkSigV4Signer, AWSSDKSigV4Signer;
var init_AwsSdkSigV4Signer = __esmMin((() => {
	import_dist_cjs$126 = require_dist_cjs$52();
	init_utils();
	throwSigningPropertyError = (name, property) => {
		if (!property) throw new Error(`Property \`${name}\` is not resolved for AWS SDK SigV4Auth`);
		return property;
	};
	validateSigningProperties = async (signingProperties) => {
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
	AwsSdkSigV4Signer = class {
		async sign(httpRequest, identity, signingProperties) {
			if (!import_dist_cjs$126.HttpRequest.isInstance(httpRequest)) throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
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
			return (error$1) => {
				const serverTime = error$1.ServerTime ?? getDateHeader(error$1.$response);
				if (serverTime) {
					const config = throwSigningPropertyError("config", signingProperties.config);
					const initialSystemClockOffset = config.systemClockOffset;
					config.systemClockOffset = getUpdatedSystemClockOffset(serverTime, config.systemClockOffset);
					if (config.systemClockOffset !== initialSystemClockOffset && error$1.$metadata) error$1.$metadata.clockSkewCorrected = true;
				}
				throw error$1;
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
	AWSSDKSigV4Signer = AwsSdkSigV4Signer;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4ASigner.js
var import_dist_cjs$125, AwsSdkSigV4ASigner;
var init_AwsSdkSigV4ASigner = __esmMin((() => {
	import_dist_cjs$125 = require_dist_cjs$52();
	init_utils();
	init_AwsSdkSigV4Signer();
	AwsSdkSigV4ASigner = class extends AwsSdkSigV4Signer {
		async sign(httpRequest, identity, signingProperties) {
			if (!import_dist_cjs$125.HttpRequest.isInstance(httpRequest)) throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
			const { config, signer, signingRegion, signingRegionSet, signingName } = await validateSigningProperties(signingProperties);
			const multiRegionOverride = (await config.sigv4aSigningRegionSet?.() ?? signingRegionSet ?? [signingRegion]).join(",");
			return await signer.sign(httpRequest, {
				signingDate: getSkewCorrectedDate(config.systemClockOffset),
				signingRegion: multiRegionOverride,
				signingService: signingName
			});
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getArrayForCommaSeparatedString.js
var getArrayForCommaSeparatedString;
var init_getArrayForCommaSeparatedString = __esmMin((() => {
	getArrayForCommaSeparatedString = (str) => typeof str === "string" && str.length > 0 ? str.split(",").map((item) => item.trim()) : [];
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getBearerTokenEnvKey.js
var getBearerTokenEnvKey;
var init_getBearerTokenEnvKey = __esmMin((() => {
	getBearerTokenEnvKey = (signingName) => `AWS_BEARER_TOKEN_${signingName.replace(/[\s-]/g, "_").toUpperCase()}`;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/NODE_AUTH_SCHEME_PREFERENCE_OPTIONS.js
var NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY, NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY, NODE_AUTH_SCHEME_PREFERENCE_OPTIONS;
var init_NODE_AUTH_SCHEME_PREFERENCE_OPTIONS = __esmMin((() => {
	init_getArrayForCommaSeparatedString();
	init_getBearerTokenEnvKey();
	NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY = "AWS_AUTH_SCHEME_PREFERENCE";
	NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY = "auth_scheme_preference";
	NODE_AUTH_SCHEME_PREFERENCE_OPTIONS = {
		environmentVariableSelector: (env, options) => {
			if (options?.signingName) {
				if (getBearerTokenEnvKey(options.signingName) in env) return ["httpBearerAuth"];
			}
			if (!(NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY in env)) return void 0;
			return getArrayForCommaSeparatedString(env[NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY]);
		},
		configFileSelector: (profile) => {
			if (!(NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY in profile)) return void 0;
			return getArrayForCommaSeparatedString(profile[NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY]);
		},
		default: []
	};
}));

//#endregion
//#region node_modules/@smithy/property-provider/dist-cjs/index.js
var require_dist_cjs$31 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var ProviderError = class ProviderError extends Error {
		name = "ProviderError";
		tryNextLink;
		constructor(message, options = true) {
			let logger$1;
			let tryNextLink = true;
			if (typeof options === "boolean") {
				logger$1 = void 0;
				tryNextLink = options;
			} else if (options != null && typeof options === "object") {
				logger$1 = options.logger;
				tryNextLink = options.tryNextLink ?? true;
			}
			super(message);
			this.tryNextLink = tryNextLink;
			Object.setPrototypeOf(this, ProviderError.prototype);
			logger$1?.debug?.(`@smithy/property-provider ${tryNextLink ? "->" : "(!)"} ${message}`);
		}
		static from(error$1, options = true) {
			return Object.assign(new this(error$1.message, options), error$1);
		}
	};
	var CredentialsProviderError = class CredentialsProviderError extends ProviderError {
		name = "CredentialsProviderError";
		constructor(message, options = true) {
			super(message, options);
			Object.setPrototypeOf(this, CredentialsProviderError.prototype);
		}
	};
	var TokenProviderError = class TokenProviderError extends ProviderError {
		name = "TokenProviderError";
		constructor(message, options = true) {
			super(message, options);
			Object.setPrototypeOf(this, TokenProviderError.prototype);
		}
	};
	const chain = (...providers) => async () => {
		if (providers.length === 0) throw new ProviderError("No providers in chain");
		let lastProviderError;
		for (const provider of providers) try {
			return await provider();
		} catch (err) {
			lastProviderError = err;
			if (err?.tryNextLink) continue;
			throw err;
		}
		throw lastProviderError;
	};
	const fromStatic = (staticValue) => () => Promise.resolve(staticValue);
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
	exports.CredentialsProviderError = CredentialsProviderError;
	exports.ProviderError = ProviderError;
	exports.TokenProviderError = TokenProviderError;
	exports.chain = chain;
	exports.fromStatic = fromStatic;
	exports.memoize = memoize;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4AConfig.js
var import_dist_cjs$124, resolveAwsSdkSigV4AConfig, NODE_SIGV4A_CONFIG_OPTIONS;
var init_resolveAwsSdkSigV4AConfig = __esmMin((() => {
	init_dist_es$1();
	import_dist_cjs$124 = require_dist_cjs$31();
	resolveAwsSdkSigV4AConfig = (config) => {
		config.sigv4aSigningRegionSet = normalizeProvider$3(config.sigv4aSigningRegionSet);
		return config;
	};
	NODE_SIGV4A_CONFIG_OPTIONS = {
		environmentVariableSelector(env) {
			if (env.AWS_SIGV4A_SIGNING_REGION_SET) return env.AWS_SIGV4A_SIGNING_REGION_SET.split(",").map((_) => _.trim());
			throw new import_dist_cjs$124.ProviderError("AWS_SIGV4A_SIGNING_REGION_SET not set in env.", { tryNextLink: true });
		},
		configFileSelector(profile) {
			if (profile.sigv4a_signing_region_set) return (profile.sigv4a_signing_region_set ?? "").split(",").map((_) => _.trim());
			throw new import_dist_cjs$124.ProviderError("sigv4a_signing_region_set not set in profile.", { tryNextLink: true });
		},
		default: void 0
	};
}));

//#endregion
//#region node_modules/@smithy/signature-v4/dist-cjs/index.js
var require_dist_cjs$30 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilHexEncoding = require_dist_cjs$38();
	var utilUtf8 = require_dist_cjs$44();
	var isArrayBuffer = require_dist_cjs$46();
	var protocolHttp = require_dist_cjs$52();
	var utilMiddleware = require_dist_cjs$48();
	var utilUriEscape = require_dist_cjs$42();
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
	const signingKeyCache = {};
	const cacheQueue = [];
	const createScope = (shortDate, region, service) => `${shortDate}/${region}/${service}/${KEY_TYPE_IDENTIFIER}`;
	const getSigningKey = async (sha256Constructor, credentials, shortDate, region, service) => {
		const credsHash = await hmac(sha256Constructor, credentials.secretAccessKey, credentials.accessKeyId);
		const cacheKey = `${shortDate}:${region}:${service}:${utilHexEncoding.toHex(credsHash)}:${credentials.sessionToken}`;
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
	const hmac = (ctor, secret, data$1) => {
		const hash = new ctor(secret);
		hash.update(utilUtf8.toUint8Array(data$1));
		return hash.digest();
	};
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
	const getPayloadHash = async ({ headers, body }, hashConstructor) => {
		for (const headerName of Object.keys(headers)) if (headerName.toLowerCase() === SHA256_HEADER) return headers[headerName];
		if (body == void 0) return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
		else if (typeof body === "string" || ArrayBuffer.isView(body) || isArrayBuffer.isArrayBuffer(body)) {
			const hashCtor = new hashConstructor();
			hashCtor.update(utilUtf8.toUint8Array(body));
			return utilHexEncoding.toHex(await hashCtor.digest());
		}
		return UNSIGNED_PAYLOAD;
	};
	var HeaderFormatter = class {
		format(headers) {
			const chunks = [];
			for (const headerName of Object.keys(headers)) {
				const bytes = utilUtf8.fromUtf8(headerName);
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
					const utf8Bytes = utilUtf8.fromUtf8(header.value);
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
					uuidBytes.set(utilHexEncoding.fromHex(header.value.replace(/\-/g, "")), 1);
					return uuidBytes;
			}
		}
	};
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
			for (let i$3 = 7, remaining = Math.abs(Math.round(number)); i$3 > -1 && remaining > 0; i$3--, remaining /= 256) bytes[i$3] = remaining;
			if (number < 0) negate(bytes);
			return new Int64(bytes);
		}
		valueOf() {
			const bytes = this.bytes.slice(0);
			const negative = bytes[0] & 128;
			if (negative) negate(bytes);
			return parseInt(utilHexEncoding.toHex(bytes), 16) * (negative ? -1 : 1);
		}
		toString() {
			return String(this.valueOf());
		}
	};
	function negate(bytes) {
		for (let i$3 = 0; i$3 < 8; i$3++) bytes[i$3] ^= 255;
		for (let i$3 = 7; i$3 > -1; i$3--) {
			bytes[i$3]++;
			if (bytes[i$3] !== 0) break;
		}
	}
	const hasHeader = (soughtHeader, headers) => {
		soughtHeader = soughtHeader.toLowerCase();
		for (const headerName of Object.keys(headers)) if (soughtHeader === headerName.toLowerCase()) return true;
		return false;
	};
	const moveHeadersToQuery = (request, options = {}) => {
		const { headers, query = {} } = protocolHttp.HttpRequest.clone(request);
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
	const prepareRequest = (request) => {
		request = protocolHttp.HttpRequest.clone(request);
		for (const headerName of Object.keys(request.headers)) if (GENERATED_HEADERS.indexOf(headerName.toLowerCase()) > -1) delete request.headers[headerName];
		return request;
	};
	const getCanonicalQuery = ({ query = {} }) => {
		const keys = [];
		const serialized = {};
		for (const key of Object.keys(query)) {
			if (key.toLowerCase() === SIGNATURE_HEADER) continue;
			const encodedKey = utilUriEscape.escapeUri(key);
			keys.push(encodedKey);
			const value = query[key];
			if (typeof value === "string") serialized[encodedKey] = `${encodedKey}=${utilUriEscape.escapeUri(value)}`;
			else if (Array.isArray(value)) serialized[encodedKey] = value.slice(0).reduce((encoded, value$1) => encoded.concat([`${encodedKey}=${utilUriEscape.escapeUri(value$1)}`]), []).sort().join("&");
		}
		return keys.sort().map((key) => serialized[key]).filter((serialized$1) => serialized$1).join("&");
	};
	const iso8601 = (time$1) => toDate(time$1).toISOString().replace(/\.\d{3}Z$/, "Z");
	const toDate = (time$1) => {
		if (typeof time$1 === "number") return /* @__PURE__ */ new Date(time$1 * 1e3);
		if (typeof time$1 === "string") {
			if (Number(time$1)) return /* @__PURE__ */ new Date(Number(time$1) * 1e3);
			return new Date(time$1);
		}
		return time$1;
	};
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
			this.regionProvider = utilMiddleware.normalizeProvider(region);
			this.credentialProvider = utilMiddleware.normalizeProvider(credentials);
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
			hash.update(utilUtf8.toUint8Array(canonicalRequest));
			const hashedRequest = await hash.digest();
			return `${algorithmIdentifier}
${longDate}
${credentialScope}
${utilHexEncoding.toHex(hashedRequest)}`;
		}
		getCanonicalPath({ path: path$1 }) {
			if (this.uriEscapePath) {
				const normalizedPathSegments = [];
				for (const pathSegment of path$1.split("/")) {
					if (pathSegment?.length === 0) continue;
					if (pathSegment === ".") continue;
					if (pathSegment === "..") normalizedPathSegments.pop();
					else normalizedPathSegments.push(pathSegment);
				}
				const normalizedPath = `${path$1?.startsWith("/") ? "/" : ""}${normalizedPathSegments.join("/")}${normalizedPathSegments.length > 0 && path$1?.endsWith("/") ? "/" : ""}`;
				return utilUriEscape.escapeUri(normalizedPath).replace(/%2F/g, "/");
			}
			return path$1;
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
		async signEvent({ headers, payload: payload$1 }, { signingDate = /* @__PURE__ */ new Date(), priorSignature, signingRegion, signingService }) {
			const region = signingRegion ?? await this.regionProvider();
			const { shortDate, longDate } = this.formatDate(signingDate);
			const scope = createScope(shortDate, region, signingService ?? this.service);
			const hashedPayload = await getPayloadHash({
				headers: {},
				body: payload$1
			}, this.sha256);
			const hash = new this.sha256();
			hash.update(headers);
			const stringToSign = [
				EVENT_ALGORITHM_IDENTIFIER,
				longDate,
				scope,
				priorSignature,
				utilHexEncoding.toHex(await hash.digest()),
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
			hash.update(utilUtf8.toUint8Array(stringToSign));
			return utilHexEncoding.toHex(await hash.digest());
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
			hash.update(utilUtf8.toUint8Array(stringToSign));
			return utilHexEncoding.toHex(await hash.digest());
		}
		getSigningKey(credentials, region, shortDate, service) {
			return getSigningKey(this.sha256, credentials, shortDate, region, service || this.service);
		}
	};
	exports.SignatureV4 = SignatureV4;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.js
function normalizeCredentialProvider(config, { credentials, credentialDefaultProvider }) {
	let credentialsProvider;
	if (credentials) if (!credentials?.memoized) credentialsProvider = memoizeIdentityProvider(credentials, isIdentityExpired, doesIdentityRequireRefresh);
	else credentialsProvider = credentials;
	else if (credentialDefaultProvider) credentialsProvider = normalizeProvider$3(credentialDefaultProvider(Object.assign({}, config, { parentClientConfig: config })));
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
var import_dist_cjs$123, resolveAwsSdkSigV4Config, resolveAWSSDKSigV4Config;
var init_resolveAwsSdkSigV4Config = __esmMin((() => {
	init_client();
	init_dist_es$1();
	import_dist_cjs$123 = require_dist_cjs$30();
	resolveAwsSdkSigV4Config = (config) => {
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
		if (config.signer) signer = normalizeProvider$3(config.signer);
		else if (config.regionInfoProvider) signer = () => normalizeProvider$3(config.region)().then(async (region) => [await config.regionInfoProvider(region, {
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
			return new (config.signerConstructor || import_dist_cjs$123.SignatureV4)(params);
		});
		else signer = async (authScheme) => {
			authScheme = Object.assign({}, {
				name: "sigv4",
				signingName: config.signingName || config.defaultSigningName,
				signingRegion: await normalizeProvider$3(config.region)(),
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
			return new (config.signerConstructor || import_dist_cjs$123.SignatureV4)(params);
		};
		return Object.assign(config, {
			systemClockOffset,
			signingEscapePath,
			signer
		});
	};
	resolveAWSSDKSigV4Config = resolveAwsSdkSigV4Config;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/index.js
var init_aws_sdk = __esmMin((() => {
	init_AwsSdkSigV4Signer();
	init_AwsSdkSigV4ASigner();
	init_NODE_AUTH_SCHEME_PREFERENCE_OPTIONS();
	init_resolveAwsSdkSigV4AConfig();
	init_resolveAwsSdkSigV4Config();
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/index.js
var httpAuthSchemes_exports = /* @__PURE__ */ __exportAll({
	AWSSDKSigV4Signer: () => AWSSDKSigV4Signer,
	AwsSdkSigV4ASigner: () => AwsSdkSigV4ASigner,
	AwsSdkSigV4Signer: () => AwsSdkSigV4Signer,
	NODE_AUTH_SCHEME_PREFERENCE_OPTIONS: () => NODE_AUTH_SCHEME_PREFERENCE_OPTIONS,
	NODE_SIGV4A_CONFIG_OPTIONS: () => NODE_SIGV4A_CONFIG_OPTIONS,
	getBearerTokenEnvKey: () => getBearerTokenEnvKey,
	resolveAWSSDKSigV4Config: () => resolveAWSSDKSigV4Config,
	resolveAwsSdkSigV4AConfig: () => resolveAwsSdkSigV4AConfig,
	resolveAwsSdkSigV4Config: () => resolveAwsSdkSigV4Config,
	validateSigningProperties: () => validateSigningProperties
});
var init_httpAuthSchemes = __esmMin((() => {
	init_aws_sdk();
	init_getBearerTokenEnvKey();
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/cbor/cbor-types.js
function alloc(size) {
	return typeof Buffer !== "undefined" ? Buffer.alloc(size) : new Uint8Array(size);
}
function tag(data$1) {
	data$1[tagSymbol] = true;
	return data$1;
}
var majorUint64, majorNegativeInt64, majorUnstructuredByteString, majorUtf8String, majorList, majorMap, majorTag, majorSpecial, specialFalse, specialTrue, specialNull, specialUndefined, extendedOneByte, extendedFloat16, extendedFloat32, extendedFloat64, minorIndefinite, tagSymbol;
var init_cbor_types = __esmMin((() => {
	majorUint64 = 0;
	majorNegativeInt64 = 1;
	majorUnstructuredByteString = 2;
	majorUtf8String = 3;
	majorList = 4;
	majorMap = 5;
	majorTag = 6;
	majorSpecial = 7;
	specialFalse = 20;
	specialTrue = 21;
	specialNull = 22;
	specialUndefined = 23;
	extendedOneByte = 24;
	extendedFloat16 = 25;
	extendedFloat32 = 26;
	extendedFloat64 = 27;
	minorIndefinite = 31;
	tagSymbol = Symbol("@smithy/core/cbor::tagSymbol");
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/cbor/cbor-decode.js
function setPayload(bytes) {
	payload = bytes;
	dataView$1 = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
}
function decode(at, to) {
	if (at >= to) throw new Error("unexpected end of (decode) payload.");
	const major = (payload[at] & 224) >> 5;
	const minor = payload[at] & 31;
	switch (major) {
		case majorUint64:
		case majorNegativeInt64:
		case majorTag:
			let unsignedInt;
			let offset;
			if (minor < 24) {
				unsignedInt = minor;
				offset = 1;
			} else switch (minor) {
				case extendedOneByte:
				case extendedFloat16:
				case extendedFloat32:
				case extendedFloat64:
					const countLength = minorValueToArgumentLength[minor];
					const countOffset = countLength + 1;
					offset = countOffset;
					if (to - at < countOffset) throw new Error(`countLength ${countLength} greater than remaining buf len.`);
					const countIndex = at + 1;
					if (countLength === 1) unsignedInt = payload[countIndex];
					else if (countLength === 2) unsignedInt = dataView$1.getUint16(countIndex);
					else if (countLength === 4) unsignedInt = dataView$1.getUint32(countIndex);
					else unsignedInt = dataView$1.getBigUint64(countIndex);
					break;
				default: throw new Error(`unexpected minor value ${minor}.`);
			}
			if (major === majorUint64) {
				_offset = offset;
				return castBigInt(unsignedInt);
			} else if (major === majorNegativeInt64) {
				let negativeInt;
				if (typeof unsignedInt === "bigint") negativeInt = BigInt(-1) - unsignedInt;
				else negativeInt = -1 - unsignedInt;
				_offset = offset;
				return castBigInt(negativeInt);
			} else if (minor === 2 || minor === 3) {
				const length = decodeCount(at + offset, to);
				let b$3 = BigInt(0);
				const start = at + offset + _offset;
				for (let i$3 = start; i$3 < start + length; ++i$3) b$3 = b$3 << BigInt(8) | BigInt(payload[i$3]);
				_offset = offset + _offset + length;
				return minor === 3 ? -b$3 - BigInt(1) : b$3;
			} else if (minor === 4) {
				const [exponent, mantissa] = decode(at + offset, to);
				const normalizer = mantissa < 0 ? -1 : 1;
				const mantissaStr = "0".repeat(Math.abs(exponent) + 1) + String(BigInt(normalizer) * BigInt(mantissa));
				let numericString;
				const sign = mantissa < 0 ? "-" : "";
				numericString = exponent === 0 ? mantissaStr : mantissaStr.slice(0, mantissaStr.length + exponent) + "." + mantissaStr.slice(exponent);
				numericString = numericString.replace(/^0+/g, "");
				if (numericString === "") numericString = "0";
				if (numericString[0] === ".") numericString = "0" + numericString;
				numericString = sign + numericString;
				_offset = offset + _offset;
				return nv(numericString);
			} else {
				const value = decode(at + offset, to);
				_offset = offset + _offset;
				return tag({
					tag: castBigInt(unsignedInt),
					value
				});
			}
		case majorUtf8String:
		case majorMap:
		case majorList:
		case majorUnstructuredByteString: if (minor === minorIndefinite) switch (major) {
			case majorUtf8String: return decodeUtf8StringIndefinite(at, to);
			case majorMap: return decodeMapIndefinite(at, to);
			case majorList: return decodeListIndefinite(at, to);
			case majorUnstructuredByteString: return decodeUnstructuredByteStringIndefinite(at, to);
		}
		else switch (major) {
			case majorUtf8String: return decodeUtf8String(at, to);
			case majorMap: return decodeMap(at, to);
			case majorList: return decodeList(at, to);
			case majorUnstructuredByteString: return decodeUnstructuredByteString(at, to);
		}
		default: return decodeSpecial(at, to);
	}
}
function bytesToUtf8(bytes, at, to) {
	if (USE_BUFFER$1 && bytes.constructor?.name === "Buffer") return bytes.toString("utf-8", at, to);
	if (textDecoder) return textDecoder.decode(bytes.subarray(at, to));
	return (0, import_dist_cjs$122.toUtf8)(bytes.subarray(at, to));
}
function demote(bigInteger) {
	const num = Number(bigInteger);
	if (num < Number.MIN_SAFE_INTEGER || Number.MAX_SAFE_INTEGER < num) console.warn(/* @__PURE__ */ new Error(`@smithy/core/cbor - truncating BigInt(${bigInteger}) to ${num} with loss of precision.`));
	return num;
}
function bytesToFloat16(a$3, b$3) {
	const sign = a$3 >> 7;
	const exponent = (a$3 & 124) >> 2;
	const fraction = (a$3 & 3) << 8 | b$3;
	const scalar = sign === 0 ? 1 : -1;
	let exponentComponent;
	let summation;
	if (exponent === 0) if (fraction === 0) return 0;
	else {
		exponentComponent = Math.pow(2, -14);
		summation = 0;
	}
	else if (exponent === 31) if (fraction === 0) return scalar * Infinity;
	else return NaN;
	else {
		exponentComponent = Math.pow(2, exponent - 15);
		summation = 1;
	}
	summation += fraction / 1024;
	return scalar * (exponentComponent * summation);
}
function decodeCount(at, to) {
	const minor = payload[at] & 31;
	if (minor < 24) {
		_offset = 1;
		return minor;
	}
	if (minor === extendedOneByte || minor === extendedFloat16 || minor === extendedFloat32 || minor === extendedFloat64) {
		const countLength = minorValueToArgumentLength[minor];
		_offset = countLength + 1;
		if (to - at < _offset) throw new Error(`countLength ${countLength} greater than remaining buf len.`);
		const countIndex = at + 1;
		if (countLength === 1) return payload[countIndex];
		else if (countLength === 2) return dataView$1.getUint16(countIndex);
		else if (countLength === 4) return dataView$1.getUint32(countIndex);
		return demote(dataView$1.getBigUint64(countIndex));
	}
	throw new Error(`unexpected minor value ${minor}.`);
}
function decodeUtf8String(at, to) {
	const length = decodeCount(at, to);
	const offset = _offset;
	at += offset;
	if (to - at < length) throw new Error(`string len ${length} greater than remaining buf len.`);
	const value = bytesToUtf8(payload, at, at + length);
	_offset = offset + length;
	return value;
}
function decodeUtf8StringIndefinite(at, to) {
	at += 1;
	const vector = [];
	for (const base = at; at < to;) {
		if (payload[at] === 255) {
			const data$1 = alloc(vector.length);
			data$1.set(vector, 0);
			_offset = at - base + 2;
			return bytesToUtf8(data$1, 0, data$1.length);
		}
		const major = (payload[at] & 224) >> 5;
		const minor = payload[at] & 31;
		if (major !== majorUtf8String) throw new Error(`unexpected major type ${major} in indefinite string.`);
		if (minor === minorIndefinite) throw new Error("nested indefinite string.");
		const bytes = decodeUnstructuredByteString(at, to);
		at += _offset;
		for (let i$3 = 0; i$3 < bytes.length; ++i$3) vector.push(bytes[i$3]);
	}
	throw new Error("expected break marker.");
}
function decodeUnstructuredByteString(at, to) {
	const length = decodeCount(at, to);
	const offset = _offset;
	at += offset;
	if (to - at < length) throw new Error(`unstructured byte string len ${length} greater than remaining buf len.`);
	const value = payload.subarray(at, at + length);
	_offset = offset + length;
	return value;
}
function decodeUnstructuredByteStringIndefinite(at, to) {
	at += 1;
	const vector = [];
	for (const base = at; at < to;) {
		if (payload[at] === 255) {
			const data$1 = alloc(vector.length);
			data$1.set(vector, 0);
			_offset = at - base + 2;
			return data$1;
		}
		const major = (payload[at] & 224) >> 5;
		const minor = payload[at] & 31;
		if (major !== majorUnstructuredByteString) throw new Error(`unexpected major type ${major} in indefinite string.`);
		if (minor === minorIndefinite) throw new Error("nested indefinite string.");
		const bytes = decodeUnstructuredByteString(at, to);
		at += _offset;
		for (let i$3 = 0; i$3 < bytes.length; ++i$3) vector.push(bytes[i$3]);
	}
	throw new Error("expected break marker.");
}
function decodeList(at, to) {
	const listDataLength = decodeCount(at, to);
	const offset = _offset;
	at += offset;
	const base = at;
	const list$1 = Array(listDataLength);
	for (let i$3 = 0; i$3 < listDataLength; ++i$3) {
		const item = decode(at, to);
		const itemOffset = _offset;
		list$1[i$3] = item;
		at += itemOffset;
	}
	_offset = offset + (at - base);
	return list$1;
}
function decodeListIndefinite(at, to) {
	at += 1;
	const list$1 = [];
	for (const base = at; at < to;) {
		if (payload[at] === 255) {
			_offset = at - base + 2;
			return list$1;
		}
		const item = decode(at, to);
		at += _offset;
		list$1.push(item);
	}
	throw new Error("expected break marker.");
}
function decodeMap(at, to) {
	const mapDataLength = decodeCount(at, to);
	const offset = _offset;
	at += offset;
	const base = at;
	const map$1 = {};
	for (let i$3 = 0; i$3 < mapDataLength; ++i$3) {
		if (at >= to) throw new Error("unexpected end of map payload.");
		const major = (payload[at] & 224) >> 5;
		if (major !== majorUtf8String) throw new Error(`unexpected major type ${major} for map key at index ${at}.`);
		const key = decode(at, to);
		at += _offset;
		const value = decode(at, to);
		at += _offset;
		map$1[key] = value;
	}
	_offset = offset + (at - base);
	return map$1;
}
function decodeMapIndefinite(at, to) {
	at += 1;
	const base = at;
	const map$1 = {};
	for (; at < to;) {
		if (at >= to) throw new Error("unexpected end of map payload.");
		if (payload[at] === 255) {
			_offset = at - base + 2;
			return map$1;
		}
		const major = (payload[at] & 224) >> 5;
		if (major !== majorUtf8String) throw new Error(`unexpected major type ${major} for map key.`);
		const key = decode(at, to);
		at += _offset;
		const value = decode(at, to);
		at += _offset;
		map$1[key] = value;
	}
	throw new Error("expected break marker.");
}
function decodeSpecial(at, to) {
	const minor = payload[at] & 31;
	switch (minor) {
		case specialTrue:
		case specialFalse:
			_offset = 1;
			return minor === specialTrue;
		case specialNull:
			_offset = 1;
			return null;
		case specialUndefined:
			_offset = 1;
			return null;
		case extendedFloat16:
			if (to - at < 3) throw new Error("incomplete float16 at end of buf.");
			_offset = 3;
			return bytesToFloat16(payload[at + 1], payload[at + 2]);
		case extendedFloat32:
			if (to - at < 5) throw new Error("incomplete float32 at end of buf.");
			_offset = 5;
			return dataView$1.getFloat32(at + 1);
		case extendedFloat64:
			if (to - at < 9) throw new Error("incomplete float64 at end of buf.");
			_offset = 9;
			return dataView$1.getFloat64(at + 1);
		default: throw new Error(`unexpected minor value ${minor}.`);
	}
}
function castBigInt(bigInt) {
	if (typeof bigInt === "number") return bigInt;
	const num = Number(bigInt);
	if (Number.MIN_SAFE_INTEGER <= num && num <= Number.MAX_SAFE_INTEGER) return num;
	return bigInt;
}
var import_dist_cjs$122, USE_TEXT_DECODER, USE_BUFFER$1, payload, dataView$1, textDecoder, _offset, minorValueToArgumentLength;
var init_cbor_decode = __esmMin((() => {
	init_serde();
	import_dist_cjs$122 = require_dist_cjs$44();
	init_cbor_types();
	USE_TEXT_DECODER = typeof TextDecoder !== "undefined";
	USE_BUFFER$1 = typeof Buffer !== "undefined";
	payload = alloc(0);
	dataView$1 = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
	textDecoder = USE_TEXT_DECODER ? new TextDecoder() : null;
	_offset = 0;
	minorValueToArgumentLength = {
		[extendedOneByte]: 1,
		[extendedFloat16]: 2,
		[extendedFloat32]: 4,
		[extendedFloat64]: 8
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/cbor/cbor-encode.js
function ensureSpace(bytes) {
	if (data.byteLength - cursor < bytes) if (cursor < 16e6) resize(Math.max(data.byteLength * 4, data.byteLength + bytes));
	else resize(data.byteLength + bytes + 16e6);
}
function toUint8Array() {
	const out = alloc(cursor);
	out.set(data.subarray(0, cursor), 0);
	cursor = 0;
	return out;
}
function resize(size) {
	const old = data;
	data = alloc(size);
	if (old) if (old.copy) old.copy(data, 0, 0, old.byteLength);
	else data.set(old, 0);
	dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
}
function encodeHeader(major, value) {
	if (value < 24) data[cursor++] = major << 5 | value;
	else if (value < 256) {
		data[cursor++] = major << 5 | 24;
		data[cursor++] = value;
	} else if (value < 65536) {
		data[cursor++] = major << 5 | extendedFloat16;
		dataView.setUint16(cursor, value);
		cursor += 2;
	} else if (value < 2 ** 32) {
		data[cursor++] = major << 5 | extendedFloat32;
		dataView.setUint32(cursor, value);
		cursor += 4;
	} else {
		data[cursor++] = major << 5 | extendedFloat64;
		dataView.setBigUint64(cursor, typeof value === "bigint" ? value : BigInt(value));
		cursor += 8;
	}
}
function encode(_input) {
	const encodeStack = [_input];
	while (encodeStack.length) {
		const input = encodeStack.pop();
		ensureSpace(typeof input === "string" ? input.length * 4 : 64);
		if (typeof input === "string") {
			if (USE_BUFFER) {
				encodeHeader(majorUtf8String, Buffer.byteLength(input));
				cursor += data.write(input, cursor);
			} else {
				const bytes = (0, import_dist_cjs$121.fromUtf8)(input);
				encodeHeader(majorUtf8String, bytes.byteLength);
				data.set(bytes, cursor);
				cursor += bytes.byteLength;
			}
			continue;
		} else if (typeof input === "number") {
			if (Number.isInteger(input)) {
				const nonNegative = input >= 0;
				const major = nonNegative ? majorUint64 : majorNegativeInt64;
				const value = nonNegative ? input : -input - 1;
				if (value < 24) data[cursor++] = major << 5 | value;
				else if (value < 256) {
					data[cursor++] = major << 5 | 24;
					data[cursor++] = value;
				} else if (value < 65536) {
					data[cursor++] = major << 5 | extendedFloat16;
					data[cursor++] = value >> 8;
					data[cursor++] = value;
				} else if (value < 4294967296) {
					data[cursor++] = major << 5 | extendedFloat32;
					dataView.setUint32(cursor, value);
					cursor += 4;
				} else {
					data[cursor++] = major << 5 | extendedFloat64;
					dataView.setBigUint64(cursor, BigInt(value));
					cursor += 8;
				}
				continue;
			}
			data[cursor++] = majorSpecial << 5 | extendedFloat64;
			dataView.setFloat64(cursor, input);
			cursor += 8;
			continue;
		} else if (typeof input === "bigint") {
			const nonNegative = input >= 0;
			const major = nonNegative ? majorUint64 : majorNegativeInt64;
			const value = nonNegative ? input : -input - BigInt(1);
			const n$3 = Number(value);
			if (n$3 < 24) data[cursor++] = major << 5 | n$3;
			else if (n$3 < 256) {
				data[cursor++] = major << 5 | 24;
				data[cursor++] = n$3;
			} else if (n$3 < 65536) {
				data[cursor++] = major << 5 | extendedFloat16;
				data[cursor++] = n$3 >> 8;
				data[cursor++] = n$3 & 255;
			} else if (n$3 < 4294967296) {
				data[cursor++] = major << 5 | extendedFloat32;
				dataView.setUint32(cursor, n$3);
				cursor += 4;
			} else if (value < BigInt("18446744073709551616")) {
				data[cursor++] = major << 5 | extendedFloat64;
				dataView.setBigUint64(cursor, value);
				cursor += 8;
			} else {
				const binaryBigInt = value.toString(2);
				const bigIntBytes = new Uint8Array(Math.ceil(binaryBigInt.length / 8));
				let b$3 = value;
				let i$3 = 0;
				while (bigIntBytes.byteLength - ++i$3 >= 0) {
					bigIntBytes[bigIntBytes.byteLength - i$3] = Number(b$3 & BigInt(255));
					b$3 >>= BigInt(8);
				}
				ensureSpace(bigIntBytes.byteLength * 2);
				data[cursor++] = nonNegative ? 194 : 195;
				if (USE_BUFFER) encodeHeader(majorUnstructuredByteString, Buffer.byteLength(bigIntBytes));
				else encodeHeader(majorUnstructuredByteString, bigIntBytes.byteLength);
				data.set(bigIntBytes, cursor);
				cursor += bigIntBytes.byteLength;
			}
			continue;
		} else if (input === null) {
			data[cursor++] = majorSpecial << 5 | specialNull;
			continue;
		} else if (typeof input === "boolean") {
			data[cursor++] = majorSpecial << 5 | (input ? specialTrue : specialFalse);
			continue;
		} else if (typeof input === "undefined") throw new Error("@smithy/core/cbor: client may not serialize undefined value.");
		else if (Array.isArray(input)) {
			for (let i$3 = input.length - 1; i$3 >= 0; --i$3) encodeStack.push(input[i$3]);
			encodeHeader(majorList, input.length);
			continue;
		} else if (typeof input.byteLength === "number") {
			ensureSpace(input.length * 2);
			encodeHeader(majorUnstructuredByteString, input.length);
			data.set(input, cursor);
			cursor += input.byteLength;
			continue;
		} else if (typeof input === "object") {
			if (input instanceof NumericValue) {
				const decimalIndex = input.string.indexOf(".");
				const exponent = decimalIndex === -1 ? 0 : decimalIndex - input.string.length + 1;
				const mantissa = BigInt(input.string.replace(".", ""));
				data[cursor++] = 196;
				encodeStack.push(mantissa);
				encodeStack.push(exponent);
				encodeHeader(majorList, 2);
				continue;
			}
			if (input[tagSymbol]) if ("tag" in input && "value" in input) {
				encodeStack.push(input.value);
				encodeHeader(majorTag, input.tag);
				continue;
			} else throw new Error("tag encountered with missing fields, need 'tag' and 'value', found: " + JSON.stringify(input));
			const keys = Object.keys(input);
			for (let i$3 = keys.length - 1; i$3 >= 0; --i$3) {
				const key = keys[i$3];
				encodeStack.push(input[key]);
				encodeStack.push(key);
			}
			encodeHeader(majorMap, keys.length);
			continue;
		}
		throw new Error(`data type ${input?.constructor?.name ?? typeof input} not compatible for encoding.`);
	}
}
var import_dist_cjs$121, USE_BUFFER, data, dataView, cursor;
var init_cbor_encode = __esmMin((() => {
	init_serde();
	import_dist_cjs$121 = require_dist_cjs$44();
	init_cbor_types();
	USE_BUFFER = typeof Buffer !== "undefined";
	data = alloc(2048);
	dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
	cursor = 0;
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/cbor/cbor.js
var cbor;
var init_cbor$1 = __esmMin((() => {
	init_cbor_decode();
	init_cbor_encode();
	cbor = {
		deserialize(payload$1) {
			setPayload(payload$1);
			return decode(0, payload$1.length);
		},
		serialize(input) {
			try {
				encode(input);
				return toUint8Array();
			} catch (e$3) {
				toUint8Array();
				throw e$3;
			}
		},
		resizeEncodingBuffer(size) {
			resize(size);
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/cbor/parseCborBody.js
var dateToTag, loadSmithyRpcV2CborErrorCode;
var init_parseCborBody = __esmMin((() => {
	init_protocols$1();
	init_cbor_types();
	dateToTag = (date$1) => {
		return tag({
			tag: 1,
			value: date$1.getTime() / 1e3
		});
	};
	loadSmithyRpcV2CborErrorCode = (output, data$1) => {
		const sanitizeErrorCode = (rawValue) => {
			let cleanValue = rawValue;
			if (typeof cleanValue === "number") cleanValue = cleanValue.toString();
			if (cleanValue.indexOf(",") >= 0) cleanValue = cleanValue.split(",")[0];
			if (cleanValue.indexOf(":") >= 0) cleanValue = cleanValue.split(":")[0];
			if (cleanValue.indexOf("#") >= 0) cleanValue = cleanValue.split("#")[1];
			return cleanValue;
		};
		if (data$1["__type"] !== void 0) return sanitizeErrorCode(data$1["__type"]);
		const codeKey = Object.keys(data$1).find((key) => key.toLowerCase() === "code");
		if (codeKey && data$1[codeKey] !== void 0) return sanitizeErrorCode(data$1[codeKey]);
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/cbor/CborCodec.js
var import_dist_cjs$120, CborCodec, CborShapeSerializer, CborShapeDeserializer;
var init_CborCodec = __esmMin((() => {
	init_protocols$1();
	init_schema();
	init_serde();
	import_dist_cjs$120 = require_dist_cjs$43();
	init_cbor$1();
	init_parseCborBody();
	CborCodec = class extends SerdeContext {
		createSerializer() {
			const serializer = new CborShapeSerializer();
			serializer.setSerdeContext(this.serdeContext);
			return serializer;
		}
		createDeserializer() {
			const deserializer = new CborShapeDeserializer();
			deserializer.setSerdeContext(this.serdeContext);
			return deserializer;
		}
	};
	CborShapeSerializer = class extends SerdeContext {
		value;
		write(schema, value) {
			this.value = this.serialize(schema, value);
		}
		serialize(schema, source) {
			const ns = NormalizedSchema.of(schema);
			if (source == null) {
				if (ns.isIdempotencyToken()) return (0, import_dist_cjs$141.v4)();
				return source;
			}
			if (ns.isBlobSchema()) {
				if (typeof source === "string") return (this.serdeContext?.base64Decoder ?? import_dist_cjs$120.fromBase64)(source);
				return source;
			}
			if (ns.isTimestampSchema()) {
				if (typeof source === "number" || typeof source === "bigint") return dateToTag(/* @__PURE__ */ new Date(Number(source) / 1e3 | 0));
				return dateToTag(source);
			}
			if (typeof source === "function" || typeof source === "object") {
				const sourceObject = source;
				if (ns.isListSchema() && Array.isArray(sourceObject)) {
					const sparse = !!ns.getMergedTraits().sparse;
					const newArray = [];
					let i$3 = 0;
					for (const item of sourceObject) {
						const value = this.serialize(ns.getValueSchema(), item);
						if (value != null || sparse) newArray[i$3++] = value;
					}
					return newArray;
				}
				if (sourceObject instanceof Date) return dateToTag(sourceObject);
				const newObject = {};
				if (ns.isMapSchema()) {
					const sparse = !!ns.getMergedTraits().sparse;
					for (const key of Object.keys(sourceObject)) {
						const value = this.serialize(ns.getValueSchema(), sourceObject[key]);
						if (value != null || sparse) newObject[key] = value;
					}
				} else if (ns.isStructSchema()) {
					for (const [key, memberSchema] of ns.structIterator()) {
						const value = this.serialize(memberSchema, sourceObject[key]);
						if (value != null) newObject[key] = value;
					}
					if (ns.isUnionSchema() && Array.isArray(sourceObject.$unknown)) {
						const [k$3, v$3] = sourceObject.$unknown;
						newObject[k$3] = v$3;
					}
				} else if (ns.isDocumentSchema()) for (const key of Object.keys(sourceObject)) newObject[key] = this.serialize(ns.getValueSchema(), sourceObject[key]);
				return newObject;
			}
			return source;
		}
		flush() {
			const buffer$3 = cbor.serialize(this.value);
			this.value = void 0;
			return buffer$3;
		}
	};
	CborShapeDeserializer = class extends SerdeContext {
		read(schema, bytes) {
			const data$1 = cbor.deserialize(bytes);
			return this.readValue(schema, data$1);
		}
		readValue(_schema, value) {
			const ns = NormalizedSchema.of(_schema);
			if (ns.isTimestampSchema()) {
				if (typeof value === "number") return _parseEpochTimestamp(value);
				if (typeof value === "object") {
					if (value.tag === 1 && "value" in value) return _parseEpochTimestamp(value.value);
				}
			}
			if (ns.isBlobSchema()) {
				if (typeof value === "string") return (this.serdeContext?.base64Decoder ?? import_dist_cjs$120.fromBase64)(value);
				return value;
			}
			if (typeof value === "undefined" || typeof value === "boolean" || typeof value === "number" || typeof value === "string" || typeof value === "bigint" || typeof value === "symbol") return value;
			else if (typeof value === "object") {
				if (value === null) return null;
				if ("byteLength" in value) return value;
				if (value instanceof Date) return value;
				if (ns.isDocumentSchema()) return value;
				if (ns.isListSchema()) {
					const newArray = [];
					const memberSchema = ns.getValueSchema();
					const sparse = !!ns.getMergedTraits().sparse;
					for (const item of value) {
						const itemValue = this.readValue(memberSchema, item);
						if (itemValue != null || sparse) newArray.push(itemValue);
					}
					return newArray;
				}
				const newObject = {};
				if (ns.isMapSchema()) {
					const sparse = !!ns.getMergedTraits().sparse;
					const targetSchema = ns.getValueSchema();
					for (const key of Object.keys(value)) {
						const itemValue = this.readValue(targetSchema, value[key]);
						if (itemValue != null || sparse) newObject[key] = itemValue;
					}
				} else if (ns.isStructSchema()) {
					const isUnion = ns.isUnionSchema();
					let keys;
					if (isUnion) keys = new Set(Object.keys(value).filter((k$3) => k$3 !== "__type"));
					for (const [key, memberSchema] of ns.structIterator()) {
						if (isUnion) keys.delete(key);
						if (value[key] != null) newObject[key] = this.readValue(memberSchema, value[key]);
					}
					if (isUnion && keys?.size === 1 && Object.keys(newObject).length === 0) {
						const k$3 = keys.values().next().value;
						newObject.$unknown = [k$3, value[k$3]];
					}
				}
				return newObject;
			} else return value;
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/cbor/SmithyRpcV2CborProtocol.js
var import_dist_cjs$119, SmithyRpcV2CborProtocol;
var init_SmithyRpcV2CborProtocol = __esmMin((() => {
	init_protocols$1();
	init_schema();
	import_dist_cjs$119 = require_dist_cjs$48();
	init_CborCodec();
	init_parseCborBody();
	SmithyRpcV2CborProtocol = class extends RpcProtocol {
		codec = new CborCodec();
		serializer = this.codec.createSerializer();
		deserializer = this.codec.createDeserializer();
		constructor({ defaultNamespace }) {
			super({ defaultNamespace });
		}
		getShapeId() {
			return "smithy.protocols#rpcv2Cbor";
		}
		getPayloadCodec() {
			return this.codec;
		}
		async serializeRequest(operationSchema, input, context) {
			const request = await super.serializeRequest(operationSchema, input, context);
			Object.assign(request.headers, {
				"content-type": this.getDefaultContentType(),
				"smithy-protocol": "rpc-v2-cbor",
				accept: this.getDefaultContentType()
			});
			if (deref(operationSchema.input) === "unit") {
				delete request.body;
				delete request.headers["content-type"];
			} else {
				if (!request.body) {
					this.serializer.write(15, {});
					request.body = this.serializer.flush();
				}
				try {
					request.headers["content-length"] = String(request.body.byteLength);
				} catch (e$3) {}
			}
			const { service, operation: operation$1 } = (0, import_dist_cjs$119.getSmithyContext)(context);
			const path$1 = `/service/${service}/operation/${operation$1}`;
			if (request.path.endsWith("/")) request.path += path$1.slice(1);
			else request.path += path$1;
			return request;
		}
		async deserializeResponse(operationSchema, context, response) {
			return super.deserializeResponse(operationSchema, context, response);
		}
		async handleError(operationSchema, context, response, dataObject, metadata) {
			const errorName = loadSmithyRpcV2CborErrorCode(response, dataObject) ?? "Unknown";
			let namespace = this.options.defaultNamespace;
			if (errorName.includes("#")) [namespace] = errorName.split("#");
			const errorMetadata = {
				$metadata: metadata,
				$fault: response.statusCode <= 500 ? "client" : "server"
			};
			const registry = TypeRegistry.for(namespace);
			let errorSchema;
			try {
				errorSchema = registry.getSchema(errorName);
			} catch (e$3) {
				if (dataObject.Message) dataObject.message = dataObject.Message;
				const synthetic = TypeRegistry.for("smithy.ts.sdk.synthetic." + namespace);
				const baseExceptionSchema = synthetic.getBaseException();
				if (baseExceptionSchema) {
					const ErrorCtor$1 = synthetic.getErrorCtor(baseExceptionSchema);
					throw Object.assign(new ErrorCtor$1({ name: errorName }), errorMetadata, dataObject);
				}
				throw Object.assign(new Error(errorName), errorMetadata, dataObject);
			}
			const ns = NormalizedSchema.of(errorSchema);
			const ErrorCtor = registry.getErrorCtor(errorSchema);
			const message = dataObject.message ?? dataObject.Message ?? "Unknown";
			const exception = new ErrorCtor(message);
			const output = {};
			for (const [name, member$1] of ns.structIterator()) output[name] = this.deserializer.readValue(member$1, dataObject[name]);
			throw Object.assign(exception, errorMetadata, {
				$fault: ns.getMergedTraits().error,
				message
			}, output);
		}
		getDefaultContentType() {
			return "application/cbor";
		}
	};
}));

//#endregion
//#region node_modules/@smithy/core/dist-es/submodules/cbor/index.js
var init_cbor = __esmMin((() => {
	init_parseCborBody();
	init_SmithyRpcV2CborProtocol();
	init_CborCodec();
}));

//#endregion
//#region node_modules/@smithy/middleware-stack/dist-cjs/index.js
var require_dist_cjs$29 = /* @__PURE__ */ __commonJSMin(((exports) => {
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
		const sort = (entries) => entries.sort((a$3, b$3) => stepWeights[b$3.step] - stepWeights[a$3.step] || priorityWeights[b$3.priority || "normal"] - priorityWeights[a$3.priority || "normal"]);
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
							const toOverrideIndex = absoluteEntries.findIndex((entry$1) => entry$1.name === alias || entry$1.aliases?.some((a$3) => a$3 === alias));
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
							const toOverrideIndex = relativeEntries.findIndex((entry$1) => entry$1.name === alias || entry$1.aliases?.some((a$3) => a$3 === alias));
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
	exports.constructStack = constructStack;
}));

//#endregion
//#region node_modules/@smithy/smithy-client/dist-cjs/index.js
var require_dist_cjs$28 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var middlewareStack = require_dist_cjs$29();
	var protocols = (init_protocols$1(), __toCommonJS(protocols_exports$1));
	var types = require_dist_cjs$53();
	var schema = (init_schema(), __toCommonJS(schema_exports));
	var serde = (init_serde(), __toCommonJS(serde_exports));
	var Client = class {
		config;
		middlewareStack = middlewareStack.constructStack();
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
	const SENSITIVE_STRING$1 = "***SensitiveInformation***";
	function schemaLogFilter(schema$1, data$1) {
		if (data$1 == null) return data$1;
		const ns = schema.NormalizedSchema.of(schema$1);
		if (ns.getMergedTraits().sensitive) return SENSITIVE_STRING$1;
		if (ns.isListSchema()) {
			if (!!ns.getValueSchema().getMergedTraits().sensitive) return SENSITIVE_STRING$1;
		} else if (ns.isMapSchema()) {
			if (!!ns.getKeySchema().getMergedTraits().sensitive || !!ns.getValueSchema().getMergedTraits().sensitive) return SENSITIVE_STRING$1;
		} else if (ns.isStructSchema() && typeof data$1 === "object") {
			const object = data$1;
			const newObject = {};
			for (const [member$1, memberNs] of ns.structIterator()) if (object[member$1] != null) newObject[member$1] = schemaLogFilter(memberNs, object[member$1]);
			return newObject;
		}
		return data$1;
	}
	var Command = class {
		middlewareStack = middlewareStack.constructStack();
		schema;
		static classBuilder() {
			return new ClassBuilder();
		}
		resolveMiddlewareWithContext(clientStack, configuration, options, { middlewareFn, clientName, commandName, inputFilterSensitiveLog, outputFilterSensitiveLog, smithyContext, additionalContext, CommandCtor }) {
			for (const mw of middlewareFn.bind(this)(CommandCtor, clientStack, configuration, options)) this.middlewareStack.use(mw);
			const stack = clientStack.concat(this.middlewareStack);
			const { logger: logger$1 } = configuration;
			const handlerExecutionContext = {
				logger: logger$1,
				clientName,
				commandName,
				inputFilterSensitiveLog,
				outputFilterSensitiveLog,
				[types.SMITHY_CONTEXT_KEY]: {
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
					const op$1 = closure._operationSchema;
					const input = op$1?.[4] ?? op$1?.input;
					const output = op$1?.[5] ?? op$1?.output;
					return this.resolveMiddlewareWithContext(stack, configuration, options, {
						CommandCtor: CommandRef,
						middlewareFn: closure._middlewareFn,
						clientName: closure._clientName,
						commandName: closure._commandName,
						inputFilterSensitiveLog: closure._inputFilterSensitiveLog ?? (op$1 ? schemaLogFilter.bind(null, input) : (_) => _),
						outputFilterSensitiveLog: closure._outputFilterSensitiveLog ?? (op$1 ? schemaLogFilter.bind(null, output) : (_) => _),
						smithyContext: closure._smithyContext,
						additionalContext: closure._additionalContext
					});
				}
				serialize = closure._serializer;
				deserialize = closure._deserializer;
			};
		}
	};
	const SENSITIVE_STRING = "***SensitiveInformation***";
	const createAggregatedClient = (commands$3, Client) => {
		for (const command of Object.keys(commands$3)) {
			const CommandCtor = commands$3[command];
			const methodImpl = async function(args, optionsOrCb, cb) {
				const command$1 = new CommandCtor(args);
				if (typeof optionsOrCb === "function") this.send(command$1, optionsOrCb);
				else if (typeof cb === "function") {
					if (typeof optionsOrCb !== "object") throw new Error(`Expected http options but got ${typeof optionsOrCb}`);
					this.send(command$1, optionsOrCb || {}, cb);
				} else return this.send(command$1, optionsOrCb);
			};
			const methodName = (command[0].toLowerCase() + command.slice(1)).replace(/Command$/, "");
			Client.prototype[methodName] = methodImpl;
		}
	};
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
		Object.entries(additions).filter(([, v$3]) => v$3 !== void 0).forEach(([k$3, v$3]) => {
			if (exception[k$3] == void 0 || exception[k$3] === "") exception[k$3] = v$3;
		});
		exception.message = exception.message || exception.Message || "UnknownError";
		delete exception.Message;
		return exception;
	};
	const throwDefaultError = ({ output, parsedBody, exceptionCtor, errorCode }) => {
		const $metadata = deserializeMetadata(output);
		const statusCode = $metadata.httpStatusCode ? $metadata.httpStatusCode + "" : void 0;
		throw decorateServiceException(new exceptionCtor({
			name: parsedBody?.code || parsedBody?.Code || errorCode || statusCode || "UnknownError",
			$fault: "client",
			$metadata
		}), parsedBody);
	};
	const withBaseException = (ExceptionCtor) => {
		return ({ output, parsedBody, errorCode }) => {
			throwDefaultError({
				output,
				parsedBody,
				exceptionCtor: ExceptionCtor,
				errorCode
			});
		};
	};
	const deserializeMetadata = (output) => ({
		httpStatusCode: output.statusCode,
		requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
		extendedRequestId: output.headers["x-amz-id-2"],
		cfId: output.headers["x-amz-cf-id"]
	});
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
	let warningEmitted = false;
	const emitWarningIfUnsupportedVersion = (version$1) => {
		if (version$1 && !warningEmitted && parseInt(version$1.substring(1, version$1.indexOf("."))) < 16) warningEmitted = true;
	};
	const getChecksumConfiguration = (runtimeConfig) => {
		const checksumAlgorithms = [];
		for (const id in types.AlgorithmId) {
			const algorithmId = types.AlgorithmId[id];
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
	const getDefaultExtensionConfiguration = (runtimeConfig) => {
		return Object.assign(getChecksumConfiguration(runtimeConfig), getRetryConfiguration(runtimeConfig));
	};
	const getDefaultClientConfiguration = getDefaultExtensionConfiguration;
	const resolveDefaultRuntimeConfig = (config) => {
		return Object.assign(resolveChecksumRuntimeConfig(config), resolveRetryRuntimeConfig(config));
	};
	const getArrayIfSingleItem = (mayBeArray) => Array.isArray(mayBeArray) ? mayBeArray : [mayBeArray];
	const getValueFromTextNode = (obj) => {
		const textNodeName = "#text";
		for (const key in obj) if (obj.hasOwnProperty(key) && obj[key][textNodeName] !== void 0) obj[key] = obj[key][textNodeName];
		else if (typeof obj[key] === "object" && obj[key] !== null) obj[key] = getValueFromTextNode(obj[key]);
		return obj;
	};
	const isSerializableHeaderValue = (value) => {
		return value != null;
	};
	var NoOpLogger = class {
		trace() {}
		debug() {}
		info() {}
		warn() {}
		error() {}
	};
	function map(arg0, arg1, arg2) {
		let target;
		let filter;
		let instructions;
		if (typeof arg1 === "undefined" && typeof arg2 === "undefined") {
			target = {};
			instructions = arg0;
		} else {
			target = arg0;
			if (typeof arg1 === "function") {
				filter = arg1;
				instructions = arg2;
				return mapWithFilter(target, filter, instructions);
			} else instructions = arg1;
		}
		for (const key of Object.keys(instructions)) {
			if (!Array.isArray(instructions[key])) {
				target[key] = instructions[key];
				continue;
			}
			applyInstruction(target, null, instructions, key);
		}
		return target;
	}
	const convertMap = (target) => {
		const output = {};
		for (const [k$3, v$3] of Object.entries(target || {})) output[k$3] = [, v$3];
		return output;
	};
	const take = (source, instructions) => {
		const out = {};
		for (const key in instructions) applyInstruction(out, source, instructions, key);
		return out;
	};
	const mapWithFilter = (target, filter, instructions) => {
		return map(target, Object.entries(instructions).reduce((_instructions, [key, value]) => {
			if (Array.isArray(value)) _instructions[key] = value;
			else if (typeof value === "function") _instructions[key] = [filter, value()];
			else _instructions[key] = [filter, value];
			return _instructions;
		}, {}));
	};
	const applyInstruction = (target, source, instructions, targetKey) => {
		if (source !== null) {
			let instruction = instructions[targetKey];
			if (typeof instruction === "function") instruction = [, instruction];
			const [filter$1 = nonNullish, valueFn = pass, sourceKey = targetKey] = instruction;
			if (typeof filter$1 === "function" && filter$1(source[sourceKey]) || typeof filter$1 !== "function" && !!filter$1) target[targetKey] = valueFn(source[sourceKey]);
			return;
		}
		let [filter, value] = instructions[targetKey];
		if (typeof value === "function") {
			let _value;
			const defaultFilterPassed = filter === void 0 && (_value = value()) != null;
			const customFilterPassed = typeof filter === "function" && !!filter(void 0) || typeof filter !== "function" && !!filter;
			if (defaultFilterPassed) target[targetKey] = _value;
			else if (customFilterPassed) target[targetKey] = value();
		} else {
			const defaultFilterPassed = filter === void 0 && value != null;
			const customFilterPassed = typeof filter === "function" && !!filter(value) || typeof filter !== "function" && !!filter;
			if (defaultFilterPassed || customFilterPassed) target[targetKey] = value;
		}
	};
	const nonNullish = (_) => _ != null;
	const pass = (_) => _;
	const serializeFloat = (value) => {
		if (value !== value) return "NaN";
		switch (value) {
			case Infinity: return "Infinity";
			case -Infinity: return "-Infinity";
			default: return value;
		}
	};
	const serializeDateTime = (date$1) => date$1.toISOString().replace(".000Z", "Z");
	const _json = (obj) => {
		if (obj == null) return {};
		if (Array.isArray(obj)) return obj.filter((_) => _ != null).map(_json);
		if (typeof obj === "object") {
			const target = {};
			for (const key of Object.keys(obj)) {
				if (obj[key] == null) continue;
				target[key] = _json(obj[key]);
			}
			return target;
		}
		return obj;
	};
	Object.defineProperty(exports, "collectBody", {
		enumerable: true,
		get: function() {
			return protocols.collectBody;
		}
	});
	Object.defineProperty(exports, "extendedEncodeURIComponent", {
		enumerable: true,
		get: function() {
			return protocols.extendedEncodeURIComponent;
		}
	});
	Object.defineProperty(exports, "resolvedPath", {
		enumerable: true,
		get: function() {
			return protocols.resolvedPath;
		}
	});
	exports.Client = Client;
	exports.Command = Command;
	exports.NoOpLogger = NoOpLogger;
	exports.SENSITIVE_STRING = SENSITIVE_STRING;
	exports.ServiceException = ServiceException;
	exports._json = _json;
	exports.convertMap = convertMap;
	exports.createAggregatedClient = createAggregatedClient;
	exports.decorateServiceException = decorateServiceException;
	exports.emitWarningIfUnsupportedVersion = emitWarningIfUnsupportedVersion;
	exports.getArrayIfSingleItem = getArrayIfSingleItem;
	exports.getDefaultClientConfiguration = getDefaultClientConfiguration;
	exports.getDefaultExtensionConfiguration = getDefaultExtensionConfiguration;
	exports.getValueFromTextNode = getValueFromTextNode;
	exports.isSerializableHeaderValue = isSerializableHeaderValue;
	exports.loadConfigsForDefaultMode = loadConfigsForDefaultMode;
	exports.map = map;
	exports.resolveDefaultRuntimeConfig = resolveDefaultRuntimeConfig;
	exports.serializeDateTime = serializeDateTime;
	exports.serializeFloat = serializeFloat;
	exports.take = take;
	exports.throwDefaultError = throwDefaultError;
	exports.withBaseException = withBaseException;
	Object.keys(serde).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return serde[k$3];
			}
		});
	});
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/ProtocolLib.js
var import_dist_cjs$118, ProtocolLib;
var init_ProtocolLib = __esmMin((() => {
	init_schema();
	import_dist_cjs$118 = require_dist_cjs$28();
	ProtocolLib = class {
		queryCompat;
		constructor(queryCompat = false) {
			this.queryCompat = queryCompat;
		}
		resolveRestContentType(defaultContentType, inputSchema) {
			const members = inputSchema.getMemberSchemas();
			const httpPayloadMember = Object.values(members).find((m$3) => {
				return !!m$3.getMergedTraits().httpPayload;
			});
			if (httpPayloadMember) {
				const mediaType = httpPayloadMember.getMergedTraits().mediaType;
				if (mediaType) return mediaType;
				else if (httpPayloadMember.isStringSchema()) return "text/plain";
				else if (httpPayloadMember.isBlobSchema()) return "application/octet-stream";
				else return defaultContentType;
			} else if (!inputSchema.isUnitSchema()) {
				if (Object.values(members).find((m$3) => {
					const { httpQuery, httpQueryParams, httpHeader, httpLabel, httpPrefixHeaders } = m$3.getMergedTraits();
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
			} catch (e$3) {
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
				const error$1 = (0, import_dist_cjs$118.decorateServiceException)(exception, additions);
				if (msg) error$1.message = msg;
				error$1.Error = {
					...error$1.Error,
					Type: error$1.Error.Type,
					Code: error$1.Error.Code,
					Message: error$1.Error.message ?? error$1.Error.Message ?? msg
				};
				const reqId = error$1.$metadata.requestId;
				if (reqId) error$1.RequestId = reqId;
				return error$1;
			}
			return (0, import_dist_cjs$118.decorateServiceException)(exception, additions);
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
				for (const [k$3, v$3] of entries) Error$1[k$3 === "message" ? "Message" : k$3] = v$3;
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
			} catch (e$3) {
				return registry.find((schema) => NormalizedSchema.of(schema).getMergedTraits().awsQueryError?.[0] === errorName);
			}
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/cbor/AwsSmithyRpcV2CborProtocol.js
var AwsSmithyRpcV2CborProtocol;
var init_AwsSmithyRpcV2CborProtocol = __esmMin((() => {
	init_cbor();
	init_schema();
	init_ProtocolLib();
	AwsSmithyRpcV2CborProtocol = class extends SmithyRpcV2CborProtocol {
		awsQueryCompatible;
		mixin;
		constructor({ defaultNamespace, awsQueryCompatible }) {
			super({ defaultNamespace });
			this.awsQueryCompatible = !!awsQueryCompatible;
			this.mixin = new ProtocolLib(this.awsQueryCompatible);
		}
		async serializeRequest(operationSchema, input, context) {
			const request = await super.serializeRequest(operationSchema, input, context);
			if (this.awsQueryCompatible) request.headers["x-amzn-query-mode"] = "true";
			return request;
		}
		async handleError(operationSchema, context, response, dataObject, metadata) {
			if (this.awsQueryCompatible) this.mixin.setQueryCompatError(dataObject, response);
			const errorName = (() => {
				const compatHeader = response.headers["x-amzn-query-error"];
				if (compatHeader && this.awsQueryCompatible) return compatHeader.split(";")[0];
				return loadSmithyRpcV2CborErrorCode(response, dataObject) ?? "Unknown";
			})();
			const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorName, this.options.defaultNamespace, response, dataObject, metadata, this.awsQueryCompatible ? this.mixin.findQueryCompatibleError : void 0);
			const ns = NormalizedSchema.of(errorSchema);
			const message = dataObject.message ?? dataObject.Message ?? "Unknown";
			const exception = new ((TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema)) ?? Error)(message);
			const output = {};
			for (const [name, member$1] of ns.structIterator()) if (dataObject[name] != null) output[name] = this.deserializer.readValue(member$1, dataObject[name]);
			if (this.awsQueryCompatible) this.mixin.queryCompatOutput(dataObject, output);
			throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
				$fault: ns.getMergedTraits().error,
				message
			}, output), dataObject);
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/coercing-serializers.js
var _toStr, _toBool, _toNum;
var init_coercing_serializers = __esmMin((() => {
	_toStr = (val) => {
		if (val == null) return val;
		if (typeof val === "number" || typeof val === "bigint") {
			const warning = /* @__PURE__ */ new Error(`Received number ${val} where a string was expected.`);
			warning.name = "Warning";
			console.warn(warning);
			return String(val);
		}
		if (typeof val === "boolean") {
			const warning = /* @__PURE__ */ new Error(`Received boolean ${val} where a string was expected.`);
			warning.name = "Warning";
			console.warn(warning);
			return String(val);
		}
		return val;
	};
	_toBool = (val) => {
		if (val == null) return val;
		if (typeof val === "number") {}
		if (typeof val === "string") {
			const lowercase = val.toLowerCase();
			if (val !== "" && lowercase !== "false" && lowercase !== "true") {
				const warning = /* @__PURE__ */ new Error(`Received string "${val}" where a boolean was expected.`);
				warning.name = "Warning";
				console.warn(warning);
			}
			return val !== "" && lowercase !== "false";
		}
		return val;
	};
	_toNum = (val) => {
		if (val == null) return val;
		if (typeof val === "boolean") {}
		if (typeof val === "string") {
			const num = Number(val);
			if (num.toString() !== val) {
				const warning = /* @__PURE__ */ new Error(`Received string "${val}" where a number was expected.`);
				warning.name = "Warning";
				console.warn(warning);
				return val;
			}
			return num;
		}
		return val;
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/ConfigurableSerdeContext.js
var SerdeContextConfig;
var init_ConfigurableSerdeContext = __esmMin((() => {
	SerdeContextConfig = class {
		serdeContext;
		setSerdeContext(serdeContext) {
			this.serdeContext = serdeContext;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/structIterator.js
function* serializingStructIterator(ns, sourceObject) {
	if (ns.isUnitSchema()) return;
	const struct$1 = ns.getSchema();
	for (let i$3 = 0; i$3 < struct$1[4].length; ++i$3) {
		const key = struct$1[4][i$3];
		const memberSchema = struct$1[5][i$3];
		const memberNs = new NormalizedSchema([memberSchema, 0], key);
		if (!(key in sourceObject) && !memberNs.isIdempotencyToken()) continue;
		yield [key, memberNs];
	}
}
function* deserializingStructIterator(ns, sourceObject, nameTrait) {
	if (ns.isUnitSchema()) return;
	const struct$1 = ns.getSchema();
	let keysRemaining = Object.keys(sourceObject).filter((k$3) => k$3 !== "__type").length;
	for (let i$3 = 0; i$3 < struct$1[4].length; ++i$3) {
		if (keysRemaining === 0) break;
		const key = struct$1[4][i$3];
		const memberSchema = struct$1[5][i$3];
		const memberNs = new NormalizedSchema([memberSchema, 0], key);
		let serializationKey = key;
		if (nameTrait) serializationKey = memberNs.getMergedTraits()[nameTrait] ?? key;
		if (!(serializationKey in sourceObject)) continue;
		yield [key, memberNs];
		keysRemaining -= 1;
	}
}
var init_structIterator = __esmMin((() => {
	init_schema();
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/UnionSerde.js
var UnionSerde;
var init_UnionSerde = __esmMin((() => {
	UnionSerde = class {
		from;
		to;
		keys;
		constructor(from, to) {
			this.from = from;
			this.to = to;
			this.keys = new Set(Object.keys(this.from).filter((k$3) => k$3 !== "__type"));
		}
		mark(key) {
			this.keys.delete(key);
		}
		hasUnknown() {
			return this.keys.size === 1 && Object.keys(this.to).length === 0;
		}
		writeUnknown() {
			if (this.hasUnknown()) {
				const k$3 = this.keys.values().next().value;
				const v$3 = this.from[k$3];
				this.to.$unknown = [k$3, v$3];
			}
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReviver.js
function jsonReviver(key, value, context) {
	if (context?.source) {
		const numericString = context.source;
		if (typeof value === "number") {
			if (value > Number.MAX_SAFE_INTEGER || value < Number.MIN_SAFE_INTEGER || numericString !== String(value)) if (numericString.includes(".")) return new NumericValue(numericString, "bigDecimal");
			else return BigInt(numericString);
		}
	}
	return value;
}
var init_jsonReviver = __esmMin((() => {
	init_serde();
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/common.js
var import_dist_cjs$116, import_dist_cjs$117, collectBodyString;
var init_common = __esmMin((() => {
	import_dist_cjs$116 = require_dist_cjs$28();
	import_dist_cjs$117 = require_dist_cjs$44();
	collectBodyString = (streamBody, context) => (0, import_dist_cjs$116.collectBody)(streamBody, context).then((body) => (context?.utf8Encoder ?? import_dist_cjs$117.toUtf8)(body));
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/parseJsonBody.js
var parseJsonBody, parseJsonErrorBody, loadRestJsonErrorCode;
var init_parseJsonBody = __esmMin((() => {
	init_common();
	parseJsonBody = (streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
		if (encoded.length) try {
			return JSON.parse(encoded);
		} catch (e$3) {
			if (e$3?.name === "SyntaxError") Object.defineProperty(e$3, "$responseBodyText", { value: encoded });
			throw e$3;
		}
		return {};
	});
	parseJsonErrorBody = async (errorBody, context) => {
		const value = await parseJsonBody(errorBody, context);
		value.message = value.message ?? value.Message;
		return value;
	};
	loadRestJsonErrorCode = (output, data$1) => {
		const findKey = (object, key) => Object.keys(object).find((k$3) => k$3.toLowerCase() === key.toLowerCase());
		const sanitizeErrorCode = (rawValue) => {
			let cleanValue = rawValue;
			if (typeof cleanValue === "number") cleanValue = cleanValue.toString();
			if (cleanValue.indexOf(",") >= 0) cleanValue = cleanValue.split(",")[0];
			if (cleanValue.indexOf(":") >= 0) cleanValue = cleanValue.split(":")[0];
			if (cleanValue.indexOf("#") >= 0) cleanValue = cleanValue.split("#")[1];
			return cleanValue;
		};
		const headerKey = findKey(output.headers, "x-amzn-errortype");
		if (headerKey !== void 0) return sanitizeErrorCode(output.headers[headerKey]);
		if (data$1 && typeof data$1 === "object") {
			const codeKey = findKey(data$1, "code");
			if (codeKey && data$1[codeKey] !== void 0) return sanitizeErrorCode(data$1[codeKey]);
			if (data$1["__type"] !== void 0) return sanitizeErrorCode(data$1["__type"]);
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeDeserializer.js
var import_dist_cjs$115, JsonShapeDeserializer;
var init_JsonShapeDeserializer = __esmMin((() => {
	init_protocols$1();
	init_schema();
	init_serde();
	import_dist_cjs$115 = require_dist_cjs$43();
	init_ConfigurableSerdeContext();
	init_structIterator();
	init_UnionSerde();
	init_jsonReviver();
	init_parseJsonBody();
	JsonShapeDeserializer = class extends SerdeContextConfig {
		settings;
		constructor(settings) {
			super();
			this.settings = settings;
		}
		async read(schema, data$1) {
			return this._read(schema, typeof data$1 === "string" ? JSON.parse(data$1, jsonReviver) : await parseJsonBody(data$1, this.serdeContext));
		}
		readObject(schema, data$1) {
			return this._read(schema, data$1);
		}
		_read(schema, value) {
			const isObject = value !== null && typeof value === "object";
			const ns = NormalizedSchema.of(schema);
			if (isObject) {
				if (ns.isStructSchema()) {
					const union = ns.isUnionSchema();
					const out = {};
					let unionSerde;
					if (union) unionSerde = new UnionSerde(value, out);
					for (const [memberName, memberSchema] of deserializingStructIterator(ns, value, this.settings.jsonName ? "jsonName" : false)) {
						const fromKey = this.settings.jsonName ? memberSchema.getMergedTraits().jsonName ?? memberName : memberName;
						if (union) unionSerde.mark(fromKey);
						if (value[fromKey] != null) out[memberName] = this._read(memberSchema, value[fromKey]);
					}
					if (union) unionSerde.writeUnknown();
					return out;
				}
				if (Array.isArray(value) && ns.isListSchema()) {
					const listMember = ns.getValueSchema();
					const out = [];
					const sparse = !!ns.getMergedTraits().sparse;
					for (const item of value) if (sparse || item != null) out.push(this._read(listMember, item));
					return out;
				}
				if (ns.isMapSchema()) {
					const mapMember = ns.getValueSchema();
					const out = {};
					const sparse = !!ns.getMergedTraits().sparse;
					for (const [_k, _v] of Object.entries(value)) if (sparse || _v != null) out[_k] = this._read(mapMember, _v);
					return out;
				}
			}
			if (ns.isBlobSchema() && typeof value === "string") return (0, import_dist_cjs$115.fromBase64)(value);
			const mediaType = ns.getMergedTraits().mediaType;
			if (ns.isStringSchema() && typeof value === "string" && mediaType) {
				if (mediaType === "application/json" || mediaType.endsWith("+json")) return LazyJsonString.from(value);
				return value;
			}
			if (ns.isTimestampSchema() && value != null) switch (determineTimestampFormat(ns, this.settings)) {
				case 5: return parseRfc3339DateTimeWithOffset(value);
				case 6: return parseRfc7231DateTime(value);
				case 7: return parseEpochTimestamp(value);
				default:
					console.warn("Missing timestamp format, parsing value with Date constructor:", value);
					return new Date(value);
			}
			if (ns.isBigIntegerSchema() && (typeof value === "number" || typeof value === "string")) return BigInt(value);
			if (ns.isBigDecimalSchema() && value != void 0) {
				if (value instanceof NumericValue) return value;
				const untyped = value;
				if (untyped.type === "bigDecimal" && "string" in untyped) return new NumericValue(untyped.string, untyped.type);
				return new NumericValue(String(value), "bigDecimal");
			}
			if (ns.isNumericSchema() && typeof value === "string") {
				switch (value) {
					case "Infinity": return Infinity;
					case "-Infinity": return -Infinity;
					case "NaN": return NaN;
				}
				return value;
			}
			if (ns.isDocumentSchema()) if (isObject) {
				const out = Array.isArray(value) ? [] : {};
				for (const [k$3, v$3] of Object.entries(value)) if (v$3 instanceof NumericValue) out[k$3] = v$3;
				else out[k$3] = this._read(ns, v$3);
				return out;
			} else return structuredClone(value);
			return value;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReplacer.js
var NUMERIC_CONTROL_CHAR, JsonReplacer;
var init_jsonReplacer = __esmMin((() => {
	init_serde();
	NUMERIC_CONTROL_CHAR = String.fromCharCode(925);
	JsonReplacer = class {
		values = /* @__PURE__ */ new Map();
		counter = 0;
		stage = 0;
		createReplacer() {
			if (this.stage === 1) throw new Error("@aws-sdk/core/protocols - JsonReplacer already created.");
			if (this.stage === 2) throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
			this.stage = 1;
			return (key, value) => {
				if (value instanceof NumericValue) {
					const v$3 = `${NUMERIC_CONTROL_CHAR + "nv" + this.counter++}_` + value.string;
					this.values.set(`"${v$3}"`, value.string);
					return v$3;
				}
				if (typeof value === "bigint") {
					const s$3 = value.toString();
					const v$3 = `${NUMERIC_CONTROL_CHAR + "b" + this.counter++}_` + s$3;
					this.values.set(`"${v$3}"`, s$3);
					return v$3;
				}
				return value;
			};
		}
		replaceInJson(json) {
			if (this.stage === 0) throw new Error("@aws-sdk/core/protocols - JsonReplacer not created yet.");
			if (this.stage === 2) throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
			this.stage = 2;
			if (this.counter === 0) return json;
			for (const [key, value] of this.values) json = json.replace(key, value);
			return json;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeSerializer.js
var import_dist_cjs$114, JsonShapeSerializer;
var init_JsonShapeSerializer = __esmMin((() => {
	init_protocols$1();
	init_schema();
	init_serde();
	import_dist_cjs$114 = require_dist_cjs$43();
	init_ConfigurableSerdeContext();
	init_structIterator();
	init_jsonReplacer();
	JsonShapeSerializer = class extends SerdeContextConfig {
		settings;
		buffer;
		useReplacer = false;
		rootSchema;
		constructor(settings) {
			super();
			this.settings = settings;
		}
		write(schema, value) {
			this.rootSchema = NormalizedSchema.of(schema);
			this.buffer = this._write(this.rootSchema, value);
		}
		writeDiscriminatedDocument(schema, value) {
			this.write(schema, value);
			if (typeof this.buffer === "object") this.buffer.__type = NormalizedSchema.of(schema).getName(true);
		}
		flush() {
			const { rootSchema, useReplacer } = this;
			this.rootSchema = void 0;
			this.useReplacer = false;
			if (rootSchema?.isStructSchema() || rootSchema?.isDocumentSchema()) {
				if (!useReplacer) return JSON.stringify(this.buffer);
				const replacer = new JsonReplacer();
				return replacer.replaceInJson(JSON.stringify(this.buffer, replacer.createReplacer(), 0));
			}
			return this.buffer;
		}
		_write(schema, value, container) {
			const isObject = value !== null && typeof value === "object";
			const ns = NormalizedSchema.of(schema);
			if (isObject) {
				if (ns.isStructSchema()) {
					const out = {};
					for (const [memberName, memberSchema] of serializingStructIterator(ns, value)) {
						const serializableValue = this._write(memberSchema, value[memberName], ns);
						if (serializableValue !== void 0) {
							const jsonName = memberSchema.getMergedTraits().jsonName;
							const targetKey = this.settings.jsonName ? jsonName ?? memberName : memberName;
							out[targetKey] = serializableValue;
						}
					}
					if (ns.isUnionSchema() && Object.keys(out).length === 0) {
						const { $unknown } = value;
						if (Array.isArray($unknown)) {
							const [k$3, v$3] = $unknown;
							out[k$3] = this._write(15, v$3);
						}
					}
					return out;
				}
				if (Array.isArray(value) && ns.isListSchema()) {
					const listMember = ns.getValueSchema();
					const out = [];
					const sparse = !!ns.getMergedTraits().sparse;
					for (const item of value) if (sparse || item != null) out.push(this._write(listMember, item));
					return out;
				}
				if (ns.isMapSchema()) {
					const mapMember = ns.getValueSchema();
					const out = {};
					const sparse = !!ns.getMergedTraits().sparse;
					for (const [_k, _v] of Object.entries(value)) if (sparse || _v != null) out[_k] = this._write(mapMember, _v);
					return out;
				}
				if (value instanceof Uint8Array && (ns.isBlobSchema() || ns.isDocumentSchema())) {
					if (ns === this.rootSchema) return value;
					return (this.serdeContext?.base64Encoder ?? import_dist_cjs$114.toBase64)(value);
				}
				if (value instanceof Date && (ns.isTimestampSchema() || ns.isDocumentSchema())) switch (determineTimestampFormat(ns, this.settings)) {
					case 5: return value.toISOString().replace(".000Z", "Z");
					case 6: return dateToUtcString$2(value);
					case 7: return value.getTime() / 1e3;
					default:
						console.warn("Missing timestamp format, using epoch seconds", value);
						return value.getTime() / 1e3;
				}
				if (value instanceof NumericValue) this.useReplacer = true;
			}
			if (value === null && container?.isStructSchema()) return;
			if (ns.isStringSchema()) {
				if (typeof value === "undefined" && ns.isIdempotencyToken()) return (0, import_dist_cjs$141.v4)();
				const mediaType = ns.getMergedTraits().mediaType;
				if (value != null && mediaType) {
					if (mediaType === "application/json" || mediaType.endsWith("+json")) return LazyJsonString.from(value);
				}
				return value;
			}
			if (typeof value === "number" && ns.isNumericSchema()) {
				if (Math.abs(value) === Infinity || isNaN(value)) return String(value);
				return value;
			}
			if (typeof value === "string" && ns.isBlobSchema()) {
				if (ns === this.rootSchema) return value;
				return (this.serdeContext?.base64Encoder ?? import_dist_cjs$114.toBase64)(value);
			}
			if (typeof value === "bigint") this.useReplacer = true;
			if (ns.isDocumentSchema()) if (isObject) {
				const out = Array.isArray(value) ? [] : {};
				for (const [k$3, v$3] of Object.entries(value)) if (v$3 instanceof NumericValue) {
					this.useReplacer = true;
					out[k$3] = v$3;
				} else out[k$3] = this._write(ns, v$3);
				return out;
			} else return structuredClone(value);
			return value;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonCodec.js
var JsonCodec;
var init_JsonCodec = __esmMin((() => {
	init_ConfigurableSerdeContext();
	init_JsonShapeDeserializer();
	init_JsonShapeSerializer();
	JsonCodec = class extends SerdeContextConfig {
		settings;
		constructor(settings) {
			super();
			this.settings = settings;
		}
		createSerializer() {
			const serializer = new JsonShapeSerializer(this.settings);
			serializer.setSerdeContext(this.serdeContext);
			return serializer;
		}
		createDeserializer() {
			const deserializer = new JsonShapeDeserializer(this.settings);
			deserializer.setSerdeContext(this.serdeContext);
			return deserializer;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJsonRpcProtocol.js
var AwsJsonRpcProtocol;
var init_AwsJsonRpcProtocol = __esmMin((() => {
	init_protocols$1();
	init_schema();
	init_ProtocolLib();
	init_JsonCodec();
	init_parseJsonBody();
	AwsJsonRpcProtocol = class extends RpcProtocol {
		serializer;
		deserializer;
		serviceTarget;
		codec;
		mixin;
		awsQueryCompatible;
		constructor({ defaultNamespace, serviceTarget, awsQueryCompatible, jsonCodec }) {
			super({ defaultNamespace });
			this.serviceTarget = serviceTarget;
			this.codec = jsonCodec ?? new JsonCodec({
				timestampFormat: {
					useTrait: true,
					default: 7
				},
				jsonName: false
			});
			this.serializer = this.codec.createSerializer();
			this.deserializer = this.codec.createDeserializer();
			this.awsQueryCompatible = !!awsQueryCompatible;
			this.mixin = new ProtocolLib(this.awsQueryCompatible);
		}
		async serializeRequest(operationSchema, input, context) {
			const request = await super.serializeRequest(operationSchema, input, context);
			if (!request.path.endsWith("/")) request.path += "/";
			Object.assign(request.headers, {
				"content-type": `application/x-amz-json-${this.getJsonRpcVersion()}`,
				"x-amz-target": `${this.serviceTarget}.${operationSchema.name}`
			});
			if (this.awsQueryCompatible) request.headers["x-amzn-query-mode"] = "true";
			if (deref(operationSchema.input) === "unit" || !request.body) request.body = "{}";
			return request;
		}
		getPayloadCodec() {
			return this.codec;
		}
		async handleError(operationSchema, context, response, dataObject, metadata) {
			if (this.awsQueryCompatible) this.mixin.setQueryCompatError(dataObject, response);
			const errorIdentifier = loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
			const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata, this.awsQueryCompatible ? this.mixin.findQueryCompatibleError : void 0);
			const ns = NormalizedSchema.of(errorSchema);
			const message = dataObject.message ?? dataObject.Message ?? "Unknown";
			const exception = new ((TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema)) ?? Error)(message);
			const output = {};
			for (const [name, member$1] of ns.structIterator()) if (dataObject[name] != null) output[name] = this.codec.createDeserializer().readObject(member$1, dataObject[name]);
			if (this.awsQueryCompatible) this.mixin.queryCompatOutput(dataObject, output);
			throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
				$fault: ns.getMergedTraits().error,
				message
			}, output), dataObject);
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_0Protocol.js
var AwsJson1_0Protocol;
var init_AwsJson1_0Protocol = __esmMin((() => {
	init_AwsJsonRpcProtocol();
	AwsJson1_0Protocol = class extends AwsJsonRpcProtocol {
		constructor({ defaultNamespace, serviceTarget, awsQueryCompatible, jsonCodec }) {
			super({
				defaultNamespace,
				serviceTarget,
				awsQueryCompatible,
				jsonCodec
			});
		}
		getShapeId() {
			return "aws.protocols#awsJson1_0";
		}
		getJsonRpcVersion() {
			return "1.0";
		}
		getDefaultContentType() {
			return "application/x-amz-json-1.0";
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_1Protocol.js
var AwsJson1_1Protocol;
var init_AwsJson1_1Protocol = __esmMin((() => {
	init_AwsJsonRpcProtocol();
	AwsJson1_1Protocol = class extends AwsJsonRpcProtocol {
		constructor({ defaultNamespace, serviceTarget, awsQueryCompatible, jsonCodec }) {
			super({
				defaultNamespace,
				serviceTarget,
				awsQueryCompatible,
				jsonCodec
			});
		}
		getShapeId() {
			return "aws.protocols#awsJson1_1";
		}
		getJsonRpcVersion() {
			return "1.1";
		}
		getDefaultContentType() {
			return "application/x-amz-json-1.1";
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsRestJsonProtocol.js
var AwsRestJsonProtocol;
var init_AwsRestJsonProtocol = __esmMin((() => {
	init_protocols$1();
	init_schema();
	init_ProtocolLib();
	init_JsonCodec();
	init_parseJsonBody();
	AwsRestJsonProtocol = class extends HttpBindingProtocol {
		serializer;
		deserializer;
		codec;
		mixin = new ProtocolLib();
		constructor({ defaultNamespace }) {
			super({ defaultNamespace });
			const settings = {
				timestampFormat: {
					useTrait: true,
					default: 7
				},
				httpBindings: true,
				jsonName: true
			};
			this.codec = new JsonCodec(settings);
			this.serializer = new HttpInterceptingShapeSerializer(this.codec.createSerializer(), settings);
			this.deserializer = new HttpInterceptingShapeDeserializer(this.codec.createDeserializer(), settings);
		}
		getShapeId() {
			return "aws.protocols#restJson1";
		}
		getPayloadCodec() {
			return this.codec;
		}
		setSerdeContext(serdeContext) {
			this.codec.setSerdeContext(serdeContext);
			super.setSerdeContext(serdeContext);
		}
		async serializeRequest(operationSchema, input, context) {
			const request = await super.serializeRequest(operationSchema, input, context);
			const inputSchema = NormalizedSchema.of(operationSchema.input);
			if (!request.headers["content-type"]) {
				const contentType = this.mixin.resolveRestContentType(this.getDefaultContentType(), inputSchema);
				if (contentType) request.headers["content-type"] = contentType;
			}
			if (request.body == null && request.headers["content-type"] === this.getDefaultContentType()) request.body = "{}";
			return request;
		}
		async deserializeResponse(operationSchema, context, response) {
			const output = await super.deserializeResponse(operationSchema, context, response);
			const outputSchema = NormalizedSchema.of(operationSchema.output);
			for (const [name, member$1] of outputSchema.structIterator()) if (member$1.getMemberTraits().httpPayload && !(name in output)) output[name] = null;
			return output;
		}
		async handleError(operationSchema, context, response, dataObject, metadata) {
			const errorIdentifier = loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
			const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata);
			const ns = NormalizedSchema.of(errorSchema);
			const message = dataObject.message ?? dataObject.Message ?? "Unknown";
			const exception = new ((TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema)) ?? Error)(message);
			await this.deserializeHttpMessage(errorSchema, context, response, dataObject);
			const output = {};
			for (const [name, member$1] of ns.structIterator()) {
				const target = member$1.getMergedTraits().jsonName ?? name;
				output[name] = this.codec.createDeserializer().readObject(member$1, dataObject[target]);
			}
			throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
				$fault: ns.getMergedTraits().error,
				message
			}, output), dataObject);
		}
		getDefaultContentType() {
			return "application/json";
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/awsExpectUnion.js
var import_dist_cjs$113, awsExpectUnion;
var init_awsExpectUnion = __esmMin((() => {
	import_dist_cjs$113 = require_dist_cjs$28();
	awsExpectUnion = (value) => {
		if (value == null) return;
		if (typeof value === "object" && "__type" in value) delete value.__type;
		return (0, import_dist_cjs$113.expectUnion)(value);
	};
}));

//#endregion
//#region node_modules/fast-xml-parser/lib/fxp.cjs
var require_fxp = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	(() => {
		"use strict";
		var t$3 = {
			d: (e$4, n$3) => {
				for (var i$4 in n$3) t$3.o(n$3, i$4) && !t$3.o(e$4, i$4) && Object.defineProperty(e$4, i$4, {
					enumerable: !0,
					get: n$3[i$4]
				});
			},
			o: (t$4, e$4) => Object.prototype.hasOwnProperty.call(t$4, e$4),
			r: (t$4) => {
				"undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(t$4, Symbol.toStringTag, { value: "Module" }), Object.defineProperty(t$4, "__esModule", { value: !0 });
			}
		}, e$3 = {};
		t$3.r(e$3), t$3.d(e$3, {
			XMLBuilder: () => ft,
			XMLParser: () => st,
			XMLValidator: () => mt
		});
		const i$3 = /* @__PURE__ */ new RegExp("^[:A-Za-z_\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD][:A-Za-z_\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.\\d\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$");
		function s$3(t$4, e$4) {
			const n$3 = [];
			let i$4 = e$4.exec(t$4);
			for (; i$4;) {
				const s$4 = [];
				s$4.startIndex = e$4.lastIndex - i$4[0].length;
				const r$4 = i$4.length;
				for (let t$5 = 0; t$5 < r$4; t$5++) s$4.push(i$4[t$5]);
				n$3.push(s$4), i$4 = e$4.exec(t$4);
			}
			return n$3;
		}
		const r$3 = function(t$4) {
			return !(null == i$3.exec(t$4));
		}, o$3 = {
			allowBooleanAttributes: !1,
			unpairedTags: []
		};
		function a$3(t$4, e$4) {
			e$4 = Object.assign({}, o$3, e$4);
			const n$3 = [];
			let i$4 = !1, s$4 = !1;
			"﻿" === t$4[0] && (t$4 = t$4.substr(1));
			for (let o$4 = 0; o$4 < t$4.length; o$4++) if ("<" === t$4[o$4] && "?" === t$4[o$4 + 1]) {
				if (o$4 += 2, o$4 = u$3(t$4, o$4), o$4.err) return o$4;
			} else {
				if ("<" !== t$4[o$4]) {
					if (l$3(t$4[o$4])) continue;
					return x$3("InvalidChar", "char '" + t$4[o$4] + "' is not expected.", N(t$4, o$4));
				}
				{
					let a$4 = o$4;
					if (o$4++, "!" === t$4[o$4]) {
						o$4 = h$3(t$4, o$4);
						continue;
					}
					{
						let d$4 = !1;
						"/" === t$4[o$4] && (d$4 = !0, o$4++);
						let f$4 = "";
						for (; o$4 < t$4.length && ">" !== t$4[o$4] && " " !== t$4[o$4] && "	" !== t$4[o$4] && "\n" !== t$4[o$4] && "\r" !== t$4[o$4]; o$4++) f$4 += t$4[o$4];
						if (f$4 = f$4.trim(), "/" === f$4[f$4.length - 1] && (f$4 = f$4.substring(0, f$4.length - 1), o$4--), !r$3(f$4)) {
							let e$5;
							return e$5 = 0 === f$4.trim().length ? "Invalid space after '<'." : "Tag '" + f$4 + "' is an invalid name.", x$3("InvalidTag", e$5, N(t$4, o$4));
						}
						const p$4 = c$3(t$4, o$4);
						if (!1 === p$4) return x$3("InvalidAttr", "Attributes for '" + f$4 + "' have open quote.", N(t$4, o$4));
						let b$4 = p$4.value;
						if (o$4 = p$4.index, "/" === b$4[b$4.length - 1]) {
							const n$4 = o$4 - b$4.length;
							b$4 = b$4.substring(0, b$4.length - 1);
							const s$5 = g$3(b$4, e$4);
							if (!0 !== s$5) return x$3(s$5.err.code, s$5.err.msg, N(t$4, n$4 + s$5.err.line));
							i$4 = !0;
						} else if (d$4) {
							if (!p$4.tagClosed) return x$3("InvalidTag", "Closing tag '" + f$4 + "' doesn't have proper closing.", N(t$4, o$4));
							if (b$4.trim().length > 0) return x$3("InvalidTag", "Closing tag '" + f$4 + "' can't have attributes or invalid starting.", N(t$4, a$4));
							if (0 === n$3.length) return x$3("InvalidTag", "Closing tag '" + f$4 + "' has not been opened.", N(t$4, a$4));
							{
								const e$5 = n$3.pop();
								if (f$4 !== e$5.tagName) {
									let n$4 = N(t$4, e$5.tagStartPos);
									return x$3("InvalidTag", "Expected closing tag '" + e$5.tagName + "' (opened in line " + n$4.line + ", col " + n$4.col + ") instead of closing tag '" + f$4 + "'.", N(t$4, a$4));
								}
								0 == n$3.length && (s$4 = !0);
							}
						} else {
							const r$4 = g$3(b$4, e$4);
							if (!0 !== r$4) return x$3(r$4.err.code, r$4.err.msg, N(t$4, o$4 - b$4.length + r$4.err.line));
							if (!0 === s$4) return x$3("InvalidXml", "Multiple possible root nodes found.", N(t$4, o$4));
							-1 !== e$4.unpairedTags.indexOf(f$4) || n$3.push({
								tagName: f$4,
								tagStartPos: a$4
							}), i$4 = !0;
						}
						for (o$4++; o$4 < t$4.length; o$4++) if ("<" === t$4[o$4]) {
							if ("!" === t$4[o$4 + 1]) {
								o$4++, o$4 = h$3(t$4, o$4);
								continue;
							}
							if ("?" !== t$4[o$4 + 1]) break;
							if (o$4 = u$3(t$4, ++o$4), o$4.err) return o$4;
						} else if ("&" === t$4[o$4]) {
							const e$5 = m$3(t$4, o$4);
							if (-1 == e$5) return x$3("InvalidChar", "char '&' is not expected.", N(t$4, o$4));
							o$4 = e$5;
						} else if (!0 === s$4 && !l$3(t$4[o$4])) return x$3("InvalidXml", "Extra text at the end", N(t$4, o$4));
						"<" === t$4[o$4] && o$4--;
					}
				}
			}
			return i$4 ? 1 == n$3.length ? x$3("InvalidTag", "Unclosed tag '" + n$3[0].tagName + "'.", N(t$4, n$3[0].tagStartPos)) : !(n$3.length > 0) || x$3("InvalidXml", "Invalid '" + JSON.stringify(n$3.map(((t$5) => t$5.tagName)), null, 4).replace(/\r?\n/g, "") + "' found.", {
				line: 1,
				col: 1
			}) : x$3("InvalidXml", "Start tag expected.", 1);
		}
		function l$3(t$4) {
			return " " === t$4 || "	" === t$4 || "\n" === t$4 || "\r" === t$4;
		}
		function u$3(t$4, e$4) {
			const n$3 = e$4;
			for (; e$4 < t$4.length; e$4++) if ("?" != t$4[e$4] && " " != t$4[e$4]);
			else {
				const i$4 = t$4.substr(n$3, e$4 - n$3);
				if (e$4 > 5 && "xml" === i$4) return x$3("InvalidXml", "XML declaration allowed only at the start of the document.", N(t$4, e$4));
				if ("?" == t$4[e$4] && ">" == t$4[e$4 + 1]) {
					e$4++;
					break;
				}
			}
			return e$4;
		}
		function h$3(t$4, e$4) {
			if (t$4.length > e$4 + 5 && "-" === t$4[e$4 + 1] && "-" === t$4[e$4 + 2]) {
				for (e$4 += 3; e$4 < t$4.length; e$4++) if ("-" === t$4[e$4] && "-" === t$4[e$4 + 1] && ">" === t$4[e$4 + 2]) {
					e$4 += 2;
					break;
				}
			} else if (t$4.length > e$4 + 8 && "D" === t$4[e$4 + 1] && "O" === t$4[e$4 + 2] && "C" === t$4[e$4 + 3] && "T" === t$4[e$4 + 4] && "Y" === t$4[e$4 + 5] && "P" === t$4[e$4 + 6] && "E" === t$4[e$4 + 7]) {
				let n$3 = 1;
				for (e$4 += 8; e$4 < t$4.length; e$4++) if ("<" === t$4[e$4]) n$3++;
				else if (">" === t$4[e$4] && (n$3--, 0 === n$3)) break;
			} else if (t$4.length > e$4 + 9 && "[" === t$4[e$4 + 1] && "C" === t$4[e$4 + 2] && "D" === t$4[e$4 + 3] && "A" === t$4[e$4 + 4] && "T" === t$4[e$4 + 5] && "A" === t$4[e$4 + 6] && "[" === t$4[e$4 + 7]) {
				for (e$4 += 8; e$4 < t$4.length; e$4++) if ("]" === t$4[e$4] && "]" === t$4[e$4 + 1] && ">" === t$4[e$4 + 2]) {
					e$4 += 2;
					break;
				}
			}
			return e$4;
		}
		const d$3 = "\"", f$3 = "'";
		function c$3(t$4, e$4) {
			let n$3 = "", i$4 = "", s$4 = !1;
			for (; e$4 < t$4.length; e$4++) {
				if (t$4[e$4] === d$3 || t$4[e$4] === f$3) "" === i$4 ? i$4 = t$4[e$4] : i$4 !== t$4[e$4] || (i$4 = "");
				else if (">" === t$4[e$4] && "" === i$4) {
					s$4 = !0;
					break;
				}
				n$3 += t$4[e$4];
			}
			return "" === i$4 && {
				value: n$3,
				index: e$4,
				tagClosed: s$4
			};
		}
		const p$3 = new RegExp("(\\s*)([^\\s=]+)(\\s*=)?(\\s*(['\"])(([\\s\\S])*?)\\5)?", "g");
		function g$3(t$4, e$4) {
			const n$3 = s$3(t$4, p$3), i$4 = {};
			for (let t$5 = 0; t$5 < n$3.length; t$5++) {
				if (0 === n$3[t$5][1].length) return x$3("InvalidAttr", "Attribute '" + n$3[t$5][2] + "' has no space in starting.", E$1(n$3[t$5]));
				if (void 0 !== n$3[t$5][3] && void 0 === n$3[t$5][4]) return x$3("InvalidAttr", "Attribute '" + n$3[t$5][2] + "' is without value.", E$1(n$3[t$5]));
				if (void 0 === n$3[t$5][3] && !e$4.allowBooleanAttributes) return x$3("InvalidAttr", "boolean attribute '" + n$3[t$5][2] + "' is not allowed.", E$1(n$3[t$5]));
				const s$4 = n$3[t$5][2];
				if (!b$3(s$4)) return x$3("InvalidAttr", "Attribute '" + s$4 + "' is an invalid name.", E$1(n$3[t$5]));
				if (i$4.hasOwnProperty(s$4)) return x$3("InvalidAttr", "Attribute '" + s$4 + "' is repeated.", E$1(n$3[t$5]));
				i$4[s$4] = 1;
			}
			return !0;
		}
		function m$3(t$4, e$4) {
			if (";" === t$4[++e$4]) return -1;
			if ("#" === t$4[e$4]) return function(t$5, e$5) {
				let n$4 = /\d/;
				for ("x" === t$5[e$5] && (e$5++, n$4 = /[\da-fA-F]/); e$5 < t$5.length; e$5++) {
					if (";" === t$5[e$5]) return e$5;
					if (!t$5[e$5].match(n$4)) break;
				}
				return -1;
			}(t$4, ++e$4);
			let n$3 = 0;
			for (; e$4 < t$4.length; e$4++, n$3++) if (!(t$4[e$4].match(/\w/) && n$3 < 20)) {
				if (";" === t$4[e$4]) break;
				return -1;
			}
			return e$4;
		}
		function x$3(t$4, e$4, n$3) {
			return { err: {
				code: t$4,
				msg: e$4,
				line: n$3.line || n$3,
				col: n$3.col
			} };
		}
		function b$3(t$4) {
			return r$3(t$4);
		}
		function N(t$4, e$4) {
			const n$3 = t$4.substring(0, e$4).split(/\r?\n/);
			return {
				line: n$3.length,
				col: n$3[n$3.length - 1].length + 1
			};
		}
		function E$1(t$4) {
			return t$4.startIndex + t$4[1].length;
		}
		const v$3 = {
			preserveOrder: !1,
			attributeNamePrefix: "@_",
			attributesGroupName: !1,
			textNodeName: "#text",
			ignoreAttributes: !0,
			removeNSPrefix: !1,
			allowBooleanAttributes: !1,
			parseTagValue: !0,
			parseAttributeValue: !1,
			trimValues: !0,
			cdataPropName: !1,
			numberParseOptions: {
				hex: !0,
				leadingZeros: !0,
				eNotation: !0
			},
			tagValueProcessor: function(t$4, e$4) {
				return e$4;
			},
			attributeValueProcessor: function(t$4, e$4) {
				return e$4;
			},
			stopNodes: [],
			alwaysCreateTextNode: !1,
			isArray: () => !1,
			commentPropName: !1,
			unpairedTags: [],
			processEntities: !0,
			htmlEntities: !1,
			ignoreDeclaration: !1,
			ignorePiTags: !1,
			transformTagName: !1,
			transformAttributeName: !1,
			updateTag: function(t$4, e$4, n$3) {
				return t$4;
			},
			captureMetaData: !1
		};
		let y$1;
		y$1 = "function" != typeof Symbol ? "@@xmlMetadata" : Symbol("XML Node Metadata");
		class T {
			constructor(t$4) {
				this.tagname = t$4, this.child = [], this[":@"] = {};
			}
			add(t$4, e$4) {
				"__proto__" === t$4 && (t$4 = "#__proto__"), this.child.push({ [t$4]: e$4 });
			}
			addChild(t$4, e$4) {
				"__proto__" === t$4.tagname && (t$4.tagname = "#__proto__"), t$4[":@"] && Object.keys(t$4[":@"]).length > 0 ? this.child.push({
					[t$4.tagname]: t$4.child,
					":@": t$4[":@"]
				}) : this.child.push({ [t$4.tagname]: t$4.child }), void 0 !== e$4 && (this.child[this.child.length - 1][y$1] = { startIndex: e$4 });
			}
			static getMetaDataSymbol() {
				return y$1;
			}
		}
		function w$3(t$4, e$4) {
			const n$3 = {};
			if ("O" !== t$4[e$4 + 3] || "C" !== t$4[e$4 + 4] || "T" !== t$4[e$4 + 5] || "Y" !== t$4[e$4 + 6] || "P" !== t$4[e$4 + 7] || "E" !== t$4[e$4 + 8]) throw new Error("Invalid Tag instead of DOCTYPE");
			{
				e$4 += 9;
				let i$4 = 1, s$4 = !1, r$4 = !1, o$4 = "";
				for (; e$4 < t$4.length; e$4++) if ("<" !== t$4[e$4] || r$4) if (">" === t$4[e$4]) {
					if (r$4 ? "-" === t$4[e$4 - 1] && "-" === t$4[e$4 - 2] && (r$4 = !1, i$4--) : i$4--, 0 === i$4) break;
				} else "[" === t$4[e$4] ? s$4 = !0 : o$4 += t$4[e$4];
				else {
					if (s$4 && C$1(t$4, "!ENTITY", e$4)) {
						let i$5, s$5;
						e$4 += 7, [i$5, s$5, e$4] = O(t$4, e$4 + 1), -1 === s$5.indexOf("&") && (n$3[i$5] = {
							regx: RegExp(`&${i$5};`, "g"),
							val: s$5
						});
					} else if (s$4 && C$1(t$4, "!ELEMENT", e$4)) {
						e$4 += 8;
						const { index: n$4 } = S(t$4, e$4 + 1);
						e$4 = n$4;
					} else if (s$4 && C$1(t$4, "!ATTLIST", e$4)) e$4 += 8;
					else if (s$4 && C$1(t$4, "!NOTATION", e$4)) {
						e$4 += 9;
						const { index: n$4 } = A$1(t$4, e$4 + 1);
						e$4 = n$4;
					} else {
						if (!C$1(t$4, "!--", e$4)) throw new Error("Invalid DOCTYPE");
						r$4 = !0;
					}
					i$4++, o$4 = "";
				}
				if (0 !== i$4) throw new Error("Unclosed DOCTYPE");
			}
			return {
				entities: n$3,
				i: e$4
			};
		}
		const P = (t$4, e$4) => {
			for (; e$4 < t$4.length && /\s/.test(t$4[e$4]);) e$4++;
			return e$4;
		};
		function O(t$4, e$4) {
			e$4 = P(t$4, e$4);
			let n$3 = "";
			for (; e$4 < t$4.length && !/\s/.test(t$4[e$4]) && "\"" !== t$4[e$4] && "'" !== t$4[e$4];) n$3 += t$4[e$4], e$4++;
			if ($(n$3), e$4 = P(t$4, e$4), "SYSTEM" === t$4.substring(e$4, e$4 + 6).toUpperCase()) throw new Error("External entities are not supported");
			if ("%" === t$4[e$4]) throw new Error("Parameter entities are not supported");
			let i$4 = "";
			return [e$4, i$4] = I$1(t$4, e$4, "entity"), [
				n$3,
				i$4,
				--e$4
			];
		}
		function A$1(t$4, e$4) {
			e$4 = P(t$4, e$4);
			let n$3 = "";
			for (; e$4 < t$4.length && !/\s/.test(t$4[e$4]);) n$3 += t$4[e$4], e$4++;
			$(n$3), e$4 = P(t$4, e$4);
			const i$4 = t$4.substring(e$4, e$4 + 6).toUpperCase();
			if ("SYSTEM" !== i$4 && "PUBLIC" !== i$4) throw new Error(`Expected SYSTEM or PUBLIC, found "${i$4}"`);
			e$4 += i$4.length, e$4 = P(t$4, e$4);
			let s$4 = null, r$4 = null;
			if ("PUBLIC" === i$4) [e$4, s$4] = I$1(t$4, e$4, "publicIdentifier"), "\"" !== t$4[e$4 = P(t$4, e$4)] && "'" !== t$4[e$4] || ([e$4, r$4] = I$1(t$4, e$4, "systemIdentifier"));
			else if ("SYSTEM" === i$4 && ([e$4, r$4] = I$1(t$4, e$4, "systemIdentifier"), !r$4)) throw new Error("Missing mandatory system identifier for SYSTEM notation");
			return {
				notationName: n$3,
				publicIdentifier: s$4,
				systemIdentifier: r$4,
				index: --e$4
			};
		}
		function I$1(t$4, e$4, n$3) {
			let i$4 = "";
			const s$4 = t$4[e$4];
			if ("\"" !== s$4 && "'" !== s$4) throw new Error(`Expected quoted string, found "${s$4}"`);
			for (e$4++; e$4 < t$4.length && t$4[e$4] !== s$4;) i$4 += t$4[e$4], e$4++;
			if (t$4[e$4] !== s$4) throw new Error(`Unterminated ${n$3} value`);
			return [++e$4, i$4];
		}
		function S(t$4, e$4) {
			e$4 = P(t$4, e$4);
			let n$3 = "";
			for (; e$4 < t$4.length && !/\s/.test(t$4[e$4]);) n$3 += t$4[e$4], e$4++;
			if (!$(n$3)) throw new Error(`Invalid element name: "${n$3}"`);
			let i$4 = "";
			if ("E" === t$4[e$4 = P(t$4, e$4)] && C$1(t$4, "MPTY", e$4)) e$4 += 4;
			else if ("A" === t$4[e$4] && C$1(t$4, "NY", e$4)) e$4 += 2;
			else {
				if ("(" !== t$4[e$4]) throw new Error(`Invalid Element Expression, found "${t$4[e$4]}"`);
				for (e$4++; e$4 < t$4.length && ")" !== t$4[e$4];) i$4 += t$4[e$4], e$4++;
				if (")" !== t$4[e$4]) throw new Error("Unterminated content model");
			}
			return {
				elementName: n$3,
				contentModel: i$4.trim(),
				index: e$4
			};
		}
		function C$1(t$4, e$4, n$3) {
			for (let i$4 = 0; i$4 < e$4.length; i$4++) if (e$4[i$4] !== t$4[n$3 + i$4 + 1]) return !1;
			return !0;
		}
		function $(t$4) {
			if (r$3(t$4)) return t$4;
			throw new Error(`Invalid entity name ${t$4}`);
		}
		const j$3 = /^[-+]?0x[a-fA-F0-9]+$/, D$1 = /^([\-\+])?(0*)([0-9]*(\.[0-9]*)?)$/, V = {
			hex: !0,
			leadingZeros: !0,
			decimalPoint: ".",
			eNotation: !0
		};
		const M = /^([-+])?(0*)(\d*(\.\d*)?[eE][-\+]?\d+)$/;
		function _(t$4) {
			return "function" == typeof t$4 ? t$4 : Array.isArray(t$4) ? (e$4) => {
				for (const n$3 of t$4) {
					if ("string" == typeof n$3 && e$4 === n$3) return !0;
					if (n$3 instanceof RegExp && n$3.test(e$4)) return !0;
				}
			} : () => !1;
		}
		class k$3 {
			constructor(t$4) {
				this.options = t$4, this.currentNode = null, this.tagsNodeStack = [], this.docTypeEntities = {}, this.lastEntities = {
					apos: {
						regex: /&(apos|#39|#x27);/g,
						val: "'"
					},
					gt: {
						regex: /&(gt|#62|#x3E);/g,
						val: ">"
					},
					lt: {
						regex: /&(lt|#60|#x3C);/g,
						val: "<"
					},
					quot: {
						regex: /&(quot|#34|#x22);/g,
						val: "\""
					}
				}, this.ampEntity = {
					regex: /&(amp|#38|#x26);/g,
					val: "&"
				}, this.htmlEntities = {
					space: {
						regex: /&(nbsp|#160);/g,
						val: " "
					},
					cent: {
						regex: /&(cent|#162);/g,
						val: "¢"
					},
					pound: {
						regex: /&(pound|#163);/g,
						val: "£"
					},
					yen: {
						regex: /&(yen|#165);/g,
						val: "¥"
					},
					euro: {
						regex: /&(euro|#8364);/g,
						val: "€"
					},
					copyright: {
						regex: /&(copy|#169);/g,
						val: "©"
					},
					reg: {
						regex: /&(reg|#174);/g,
						val: "®"
					},
					inr: {
						regex: /&(inr|#8377);/g,
						val: "₹"
					},
					num_dec: {
						regex: /&#([0-9]{1,7});/g,
						val: (t$5, e$4) => String.fromCodePoint(Number.parseInt(e$4, 10))
					},
					num_hex: {
						regex: /&#x([0-9a-fA-F]{1,6});/g,
						val: (t$5, e$4) => String.fromCodePoint(Number.parseInt(e$4, 16))
					}
				}, this.addExternalEntities = F$1, this.parseXml = X, this.parseTextData = L, this.resolveNameSpace = B$1, this.buildAttributesMap = G$1, this.isItStopNode = Z, this.replaceEntitiesValue = R, this.readStopNodeData = J$1, this.saveTextToParentTag = q$3, this.addChild = Y, this.ignoreAttributesFn = _(this.options.ignoreAttributes);
			}
		}
		function F$1(t$4) {
			const e$4 = Object.keys(t$4);
			for (let n$3 = 0; n$3 < e$4.length; n$3++) {
				const i$4 = e$4[n$3];
				this.lastEntities[i$4] = {
					regex: new RegExp("&" + i$4 + ";", "g"),
					val: t$4[i$4]
				};
			}
		}
		function L(t$4, e$4, n$3, i$4, s$4, r$4, o$4) {
			if (void 0 !== t$4 && (this.options.trimValues && !i$4 && (t$4 = t$4.trim()), t$4.length > 0)) {
				o$4 || (t$4 = this.replaceEntitiesValue(t$4));
				const i$5 = this.options.tagValueProcessor(e$4, t$4, n$3, s$4, r$4);
				return null == i$5 ? t$4 : typeof i$5 != typeof t$4 || i$5 !== t$4 ? i$5 : this.options.trimValues || t$4.trim() === t$4 ? H$1(t$4, this.options.parseTagValue, this.options.numberParseOptions) : t$4;
			}
		}
		function B$1(t$4) {
			if (this.options.removeNSPrefix) {
				const e$4 = t$4.split(":"), n$3 = "/" === t$4.charAt(0) ? "/" : "";
				if ("xmlns" === e$4[0]) return "";
				2 === e$4.length && (t$4 = n$3 + e$4[1]);
			}
			return t$4;
		}
		const U = new RegExp("([^\\s=]+)\\s*(=\\s*(['\"])([\\s\\S]*?)\\3)?", "gm");
		function G$1(t$4, e$4, n$3) {
			if (!0 !== this.options.ignoreAttributes && "string" == typeof t$4) {
				const n$4 = s$3(t$4, U), i$4 = n$4.length, r$4 = {};
				for (let t$5 = 0; t$5 < i$4; t$5++) {
					const i$5 = this.resolveNameSpace(n$4[t$5][1]);
					if (this.ignoreAttributesFn(i$5, e$4)) continue;
					let s$4 = n$4[t$5][4], o$4 = this.options.attributeNamePrefix + i$5;
					if (i$5.length) if (this.options.transformAttributeName && (o$4 = this.options.transformAttributeName(o$4)), "__proto__" === o$4 && (o$4 = "#__proto__"), void 0 !== s$4) {
						this.options.trimValues && (s$4 = s$4.trim()), s$4 = this.replaceEntitiesValue(s$4);
						const t$6 = this.options.attributeValueProcessor(i$5, s$4, e$4);
						r$4[o$4] = null == t$6 ? s$4 : typeof t$6 != typeof s$4 || t$6 !== s$4 ? t$6 : H$1(s$4, this.options.parseAttributeValue, this.options.numberParseOptions);
					} else this.options.allowBooleanAttributes && (r$4[o$4] = !0);
				}
				if (!Object.keys(r$4).length) return;
				if (this.options.attributesGroupName) {
					const t$5 = {};
					return t$5[this.options.attributesGroupName] = r$4, t$5;
				}
				return r$4;
			}
		}
		const X = function(t$4) {
			t$4 = t$4.replace(/\r\n?/g, "\n");
			const e$4 = new T("!xml");
			let n$3 = e$4, i$4 = "", s$4 = "";
			for (let r$4 = 0; r$4 < t$4.length; r$4++) if ("<" === t$4[r$4]) if ("/" === t$4[r$4 + 1]) {
				const e$5 = W(t$4, ">", r$4, "Closing Tag is not closed.");
				let o$4 = t$4.substring(r$4 + 2, e$5).trim();
				if (this.options.removeNSPrefix) {
					const t$5 = o$4.indexOf(":");
					-1 !== t$5 && (o$4 = o$4.substr(t$5 + 1));
				}
				this.options.transformTagName && (o$4 = this.options.transformTagName(o$4)), n$3 && (i$4 = this.saveTextToParentTag(i$4, n$3, s$4));
				const a$4 = s$4.substring(s$4.lastIndexOf(".") + 1);
				if (o$4 && -1 !== this.options.unpairedTags.indexOf(o$4)) throw new Error(`Unpaired tag can not be used as closing tag: </${o$4}>`);
				let l$4 = 0;
				a$4 && -1 !== this.options.unpairedTags.indexOf(a$4) ? (l$4 = s$4.lastIndexOf(".", s$4.lastIndexOf(".") - 1), this.tagsNodeStack.pop()) : l$4 = s$4.lastIndexOf("."), s$4 = s$4.substring(0, l$4), n$3 = this.tagsNodeStack.pop(), i$4 = "", r$4 = e$5;
			} else if ("?" === t$4[r$4 + 1]) {
				let e$5 = z$1(t$4, r$4, !1, "?>");
				if (!e$5) throw new Error("Pi Tag is not closed.");
				if (i$4 = this.saveTextToParentTag(i$4, n$3, s$4), this.options.ignoreDeclaration && "?xml" === e$5.tagName || this.options.ignorePiTags);
				else {
					const t$5 = new T(e$5.tagName);
					t$5.add(this.options.textNodeName, ""), e$5.tagName !== e$5.tagExp && e$5.attrExpPresent && (t$5[":@"] = this.buildAttributesMap(e$5.tagExp, s$4, e$5.tagName)), this.addChild(n$3, t$5, s$4, r$4);
				}
				r$4 = e$5.closeIndex + 1;
			} else if ("!--" === t$4.substr(r$4 + 1, 3)) {
				const e$5 = W(t$4, "-->", r$4 + 4, "Comment is not closed.");
				if (this.options.commentPropName) {
					const o$4 = t$4.substring(r$4 + 4, e$5 - 2);
					i$4 = this.saveTextToParentTag(i$4, n$3, s$4), n$3.add(this.options.commentPropName, [{ [this.options.textNodeName]: o$4 }]);
				}
				r$4 = e$5;
			} else if ("!D" === t$4.substr(r$4 + 1, 2)) {
				const e$5 = w$3(t$4, r$4);
				this.docTypeEntities = e$5.entities, r$4 = e$5.i;
			} else if ("![" === t$4.substr(r$4 + 1, 2)) {
				const e$5 = W(t$4, "]]>", r$4, "CDATA is not closed.") - 2, o$4 = t$4.substring(r$4 + 9, e$5);
				i$4 = this.saveTextToParentTag(i$4, n$3, s$4);
				let a$4 = this.parseTextData(o$4, n$3.tagname, s$4, !0, !1, !0, !0);
				a$4 ??= "", this.options.cdataPropName ? n$3.add(this.options.cdataPropName, [{ [this.options.textNodeName]: o$4 }]) : n$3.add(this.options.textNodeName, a$4), r$4 = e$5 + 2;
			} else {
				let o$4 = z$1(t$4, r$4, this.options.removeNSPrefix), a$4 = o$4.tagName;
				const l$4 = o$4.rawTagName;
				let u$4 = o$4.tagExp, h$4 = o$4.attrExpPresent, d$4 = o$4.closeIndex;
				this.options.transformTagName && (a$4 = this.options.transformTagName(a$4)), n$3 && i$4 && "!xml" !== n$3.tagname && (i$4 = this.saveTextToParentTag(i$4, n$3, s$4, !1));
				const f$4 = n$3;
				f$4 && -1 !== this.options.unpairedTags.indexOf(f$4.tagname) && (n$3 = this.tagsNodeStack.pop(), s$4 = s$4.substring(0, s$4.lastIndexOf("."))), a$4 !== e$4.tagname && (s$4 += s$4 ? "." + a$4 : a$4);
				const c$4 = r$4;
				if (this.isItStopNode(this.options.stopNodes, s$4, a$4)) {
					let e$5 = "";
					if (u$4.length > 0 && u$4.lastIndexOf("/") === u$4.length - 1) "/" === a$4[a$4.length - 1] ? (a$4 = a$4.substr(0, a$4.length - 1), s$4 = s$4.substr(0, s$4.length - 1), u$4 = a$4) : u$4 = u$4.substr(0, u$4.length - 1), r$4 = o$4.closeIndex;
					else if (-1 !== this.options.unpairedTags.indexOf(a$4)) r$4 = o$4.closeIndex;
					else {
						const n$4 = this.readStopNodeData(t$4, l$4, d$4 + 1);
						if (!n$4) throw new Error(`Unexpected end of ${l$4}`);
						r$4 = n$4.i, e$5 = n$4.tagContent;
					}
					const i$5 = new T(a$4);
					a$4 !== u$4 && h$4 && (i$5[":@"] = this.buildAttributesMap(u$4, s$4, a$4)), e$5 && (e$5 = this.parseTextData(e$5, a$4, s$4, !0, h$4, !0, !0)), s$4 = s$4.substr(0, s$4.lastIndexOf(".")), i$5.add(this.options.textNodeName, e$5), this.addChild(n$3, i$5, s$4, c$4);
				} else {
					if (u$4.length > 0 && u$4.lastIndexOf("/") === u$4.length - 1) {
						"/" === a$4[a$4.length - 1] ? (a$4 = a$4.substr(0, a$4.length - 1), s$4 = s$4.substr(0, s$4.length - 1), u$4 = a$4) : u$4 = u$4.substr(0, u$4.length - 1), this.options.transformTagName && (a$4 = this.options.transformTagName(a$4));
						const t$5 = new T(a$4);
						a$4 !== u$4 && h$4 && (t$5[":@"] = this.buildAttributesMap(u$4, s$4, a$4)), this.addChild(n$3, t$5, s$4, c$4), s$4 = s$4.substr(0, s$4.lastIndexOf("."));
					} else {
						const t$5 = new T(a$4);
						this.tagsNodeStack.push(n$3), a$4 !== u$4 && h$4 && (t$5[":@"] = this.buildAttributesMap(u$4, s$4, a$4)), this.addChild(n$3, t$5, s$4, c$4), n$3 = t$5;
					}
					i$4 = "", r$4 = d$4;
				}
			}
			else i$4 += t$4[r$4];
			return e$4.child;
		};
		function Y(t$4, e$4, n$3, i$4) {
			this.options.captureMetaData || (i$4 = void 0);
			const s$4 = this.options.updateTag(e$4.tagname, n$3, e$4[":@"]);
			!1 === s$4 || ("string" == typeof s$4 ? (e$4.tagname = s$4, t$4.addChild(e$4, i$4)) : t$4.addChild(e$4, i$4));
		}
		const R = function(t$4) {
			if (this.options.processEntities) {
				for (let e$4 in this.docTypeEntities) {
					const n$3 = this.docTypeEntities[e$4];
					t$4 = t$4.replace(n$3.regx, n$3.val);
				}
				for (let e$4 in this.lastEntities) {
					const n$3 = this.lastEntities[e$4];
					t$4 = t$4.replace(n$3.regex, n$3.val);
				}
				if (this.options.htmlEntities) for (let e$4 in this.htmlEntities) {
					const n$3 = this.htmlEntities[e$4];
					t$4 = t$4.replace(n$3.regex, n$3.val);
				}
				t$4 = t$4.replace(this.ampEntity.regex, this.ampEntity.val);
			}
			return t$4;
		};
		function q$3(t$4, e$4, n$3, i$4) {
			return t$4 && (void 0 === i$4 && (i$4 = 0 === e$4.child.length), void 0 !== (t$4 = this.parseTextData(t$4, e$4.tagname, n$3, !1, !!e$4[":@"] && 0 !== Object.keys(e$4[":@"]).length, i$4)) && "" !== t$4 && e$4.add(this.options.textNodeName, t$4), t$4 = ""), t$4;
		}
		function Z(t$4, e$4, n$3) {
			const i$4 = "*." + n$3;
			for (const n$4 in t$4) {
				const s$4 = t$4[n$4];
				if (i$4 === s$4 || e$4 === s$4) return !0;
			}
			return !1;
		}
		function W(t$4, e$4, n$3, i$4) {
			const s$4 = t$4.indexOf(e$4, n$3);
			if (-1 === s$4) throw new Error(i$4);
			return s$4 + e$4.length - 1;
		}
		function z$1(t$4, e$4, n$3, i$4 = ">") {
			const s$4 = function(t$5, e$5, n$4 = ">") {
				let i$5, s$5 = "";
				for (let r$5 = e$5; r$5 < t$5.length; r$5++) {
					let e$6 = t$5[r$5];
					if (i$5) e$6 === i$5 && (i$5 = "");
					else if ("\"" === e$6 || "'" === e$6) i$5 = e$6;
					else if (e$6 === n$4[0]) {
						if (!n$4[1]) return {
							data: s$5,
							index: r$5
						};
						if (t$5[r$5 + 1] === n$4[1]) return {
							data: s$5,
							index: r$5
						};
					} else "	" === e$6 && (e$6 = " ");
					s$5 += e$6;
				}
			}(t$4, e$4 + 1, i$4);
			if (!s$4) return;
			let r$4 = s$4.data;
			const o$4 = s$4.index, a$4 = r$4.search(/\s/);
			let l$4 = r$4, u$4 = !0;
			-1 !== a$4 && (l$4 = r$4.substring(0, a$4), r$4 = r$4.substring(a$4 + 1).trimStart());
			const h$4 = l$4;
			if (n$3) {
				const t$5 = l$4.indexOf(":");
				-1 !== t$5 && (l$4 = l$4.substr(t$5 + 1), u$4 = l$4 !== s$4.data.substr(t$5 + 1));
			}
			return {
				tagName: l$4,
				tagExp: r$4,
				closeIndex: o$4,
				attrExpPresent: u$4,
				rawTagName: h$4
			};
		}
		function J$1(t$4, e$4, n$3) {
			const i$4 = n$3;
			let s$4 = 1;
			for (; n$3 < t$4.length; n$3++) if ("<" === t$4[n$3]) if ("/" === t$4[n$3 + 1]) {
				const r$4 = W(t$4, ">", n$3, `${e$4} is not closed`);
				if (t$4.substring(n$3 + 2, r$4).trim() === e$4 && (s$4--, 0 === s$4)) return {
					tagContent: t$4.substring(i$4, n$3),
					i: r$4
				};
				n$3 = r$4;
			} else if ("?" === t$4[n$3 + 1]) n$3 = W(t$4, "?>", n$3 + 1, "StopNode is not closed.");
			else if ("!--" === t$4.substr(n$3 + 1, 3)) n$3 = W(t$4, "-->", n$3 + 3, "StopNode is not closed.");
			else if ("![" === t$4.substr(n$3 + 1, 2)) n$3 = W(t$4, "]]>", n$3, "StopNode is not closed.") - 2;
			else {
				const i$5 = z$1(t$4, n$3, ">");
				i$5 && ((i$5 && i$5.tagName) === e$4 && "/" !== i$5.tagExp[i$5.tagExp.length - 1] && s$4++, n$3 = i$5.closeIndex);
			}
		}
		function H$1(t$4, e$4, n$3) {
			if (e$4 && "string" == typeof t$4) {
				const e$5 = t$4.trim();
				return "true" === e$5 || "false" !== e$5 && function(t$5, e$6 = {}) {
					if (e$6 = Object.assign({}, V, e$6), !t$5 || "string" != typeof t$5) return t$5;
					let n$4 = t$5.trim();
					if (void 0 !== e$6.skipLike && e$6.skipLike.test(n$4)) return t$5;
					if ("0" === t$5) return 0;
					if (e$6.hex && j$3.test(n$4)) return function(t$6) {
						if (parseInt) return parseInt(t$6, 16);
						if (Number.parseInt) return Number.parseInt(t$6, 16);
						if (window && window.parseInt) return window.parseInt(t$6, 16);
						throw new Error("parseInt, Number.parseInt, window.parseInt are not supported");
					}(n$4);
					if (-1 !== n$4.search(/.+[eE].+/)) return function(t$6, e$7, n$5) {
						if (!n$5.eNotation) return t$6;
						const i$5 = e$7.match(M);
						if (i$5) {
							let s$4 = i$5[1] || "";
							const r$4 = -1 === i$5[3].indexOf("e") ? "E" : "e", o$4 = i$5[2], a$4 = s$4 ? t$6[o$4.length + 1] === r$4 : t$6[o$4.length] === r$4;
							return o$4.length > 1 && a$4 ? t$6 : 1 !== o$4.length || !i$5[3].startsWith(`.${r$4}`) && i$5[3][0] !== r$4 ? n$5.leadingZeros && !a$4 ? (e$7 = (i$5[1] || "") + i$5[3], Number(e$7)) : t$6 : Number(e$7);
						}
						return t$6;
					}(t$5, n$4, e$6);
					{
						const s$4 = D$1.exec(n$4);
						if (s$4) {
							const r$4 = s$4[1] || "", o$4 = s$4[2];
							let a$4 = (i$4 = s$4[3]) && -1 !== i$4.indexOf(".") ? ("." === (i$4 = i$4.replace(/0+$/, "")) ? i$4 = "0" : "." === i$4[0] ? i$4 = "0" + i$4 : "." === i$4[i$4.length - 1] && (i$4 = i$4.substring(0, i$4.length - 1)), i$4) : i$4;
							const l$4 = r$4 ? "." === t$5[o$4.length + 1] : "." === t$5[o$4.length];
							if (!e$6.leadingZeros && (o$4.length > 1 || 1 === o$4.length && !l$4)) return t$5;
							{
								const i$5 = Number(n$4), s$5 = String(i$5);
								if (0 === i$5 || -0 === i$5) return i$5;
								if (-1 !== s$5.search(/[eE]/)) return e$6.eNotation ? i$5 : t$5;
								if (-1 !== n$4.indexOf(".")) return "0" === s$5 || s$5 === a$4 || s$5 === `${r$4}${a$4}` ? i$5 : t$5;
								let l$5 = o$4 ? a$4 : n$4;
								return o$4 ? l$5 === s$5 || r$4 + l$5 === s$5 ? i$5 : t$5 : l$5 === s$5 || l$5 === r$4 + s$5 ? i$5 : t$5;
							}
						}
						return t$5;
					}
					var i$4;
				}(t$4, n$3);
			}
			return void 0 !== t$4 ? t$4 : "";
		}
		const K = T.getMetaDataSymbol();
		function Q(t$4, e$4) {
			return tt(t$4, e$4);
		}
		function tt(t$4, e$4, n$3) {
			let i$4;
			const s$4 = {};
			for (let r$4 = 0; r$4 < t$4.length; r$4++) {
				const o$4 = t$4[r$4], a$4 = et(o$4);
				let l$4 = "";
				if (l$4 = void 0 === n$3 ? a$4 : n$3 + "." + a$4, a$4 === e$4.textNodeName) void 0 === i$4 ? i$4 = o$4[a$4] : i$4 += "" + o$4[a$4];
				else {
					if (void 0 === a$4) continue;
					if (o$4[a$4]) {
						let t$5 = tt(o$4[a$4], e$4, l$4);
						const n$4 = it(t$5, e$4);
						void 0 !== o$4[K] && (t$5[K] = o$4[K]), o$4[":@"] ? nt(t$5, o$4[":@"], l$4, e$4) : 1 !== Object.keys(t$5).length || void 0 === t$5[e$4.textNodeName] || e$4.alwaysCreateTextNode ? 0 === Object.keys(t$5).length && (e$4.alwaysCreateTextNode ? t$5[e$4.textNodeName] = "" : t$5 = "") : t$5 = t$5[e$4.textNodeName], void 0 !== s$4[a$4] && s$4.hasOwnProperty(a$4) ? (Array.isArray(s$4[a$4]) || (s$4[a$4] = [s$4[a$4]]), s$4[a$4].push(t$5)) : e$4.isArray(a$4, l$4, n$4) ? s$4[a$4] = [t$5] : s$4[a$4] = t$5;
					}
				}
			}
			return "string" == typeof i$4 ? i$4.length > 0 && (s$4[e$4.textNodeName] = i$4) : void 0 !== i$4 && (s$4[e$4.textNodeName] = i$4), s$4;
		}
		function et(t$4) {
			const e$4 = Object.keys(t$4);
			for (let t$5 = 0; t$5 < e$4.length; t$5++) {
				const n$3 = e$4[t$5];
				if (":@" !== n$3) return n$3;
			}
		}
		function nt(t$4, e$4, n$3, i$4) {
			if (e$4) {
				const s$4 = Object.keys(e$4), r$4 = s$4.length;
				for (let o$4 = 0; o$4 < r$4; o$4++) {
					const r$5 = s$4[o$4];
					i$4.isArray(r$5, n$3 + "." + r$5, !0, !0) ? t$4[r$5] = [e$4[r$5]] : t$4[r$5] = e$4[r$5];
				}
			}
		}
		function it(t$4, e$4) {
			const { textNodeName: n$3 } = e$4, i$4 = Object.keys(t$4).length;
			return 0 === i$4 || !(1 !== i$4 || !t$4[n$3] && "boolean" != typeof t$4[n$3] && 0 !== t$4[n$3]);
		}
		class st {
			constructor(t$4) {
				this.externalEntities = {}, this.options = function(t$5) {
					return Object.assign({}, v$3, t$5);
				}(t$4);
			}
			parse(t$4, e$4) {
				if ("string" == typeof t$4);
				else {
					if (!t$4.toString) throw new Error("XML data is accepted in String or Bytes[] form.");
					t$4 = t$4.toString();
				}
				if (e$4) {
					!0 === e$4 && (e$4 = {});
					const n$4 = a$3(t$4, e$4);
					if (!0 !== n$4) throw Error(`${n$4.err.msg}:${n$4.err.line}:${n$4.err.col}`);
				}
				const n$3 = new k$3(this.options);
				n$3.addExternalEntities(this.externalEntities);
				const i$4 = n$3.parseXml(t$4);
				return this.options.preserveOrder || void 0 === i$4 ? i$4 : Q(i$4, this.options);
			}
			addEntity(t$4, e$4) {
				if (-1 !== e$4.indexOf("&")) throw new Error("Entity value can't have '&'");
				if (-1 !== t$4.indexOf("&") || -1 !== t$4.indexOf(";")) throw new Error("An entity must be set without '&' and ';'. Eg. use '#xD' for '&#xD;'");
				if ("&" === e$4) throw new Error("An entity with value '&' is not permitted");
				this.externalEntities[t$4] = e$4;
			}
			static getMetaDataSymbol() {
				return T.getMetaDataSymbol();
			}
		}
		function rt(t$4, e$4) {
			let n$3 = "";
			return e$4.format && e$4.indentBy.length > 0 && (n$3 = "\n"), ot(t$4, e$4, "", n$3);
		}
		function ot(t$4, e$4, n$3, i$4) {
			let s$4 = "", r$4 = !1;
			for (let o$4 = 0; o$4 < t$4.length; o$4++) {
				const a$4 = t$4[o$4], l$4 = at(a$4);
				if (void 0 === l$4) continue;
				let u$4 = "";
				if (u$4 = 0 === n$3.length ? l$4 : `${n$3}.${l$4}`, l$4 === e$4.textNodeName) {
					let t$5 = a$4[l$4];
					ut(u$4, e$4) || (t$5 = e$4.tagValueProcessor(l$4, t$5), t$5 = ht(t$5, e$4)), r$4 && (s$4 += i$4), s$4 += t$5, r$4 = !1;
					continue;
				}
				if (l$4 === e$4.cdataPropName) {
					r$4 && (s$4 += i$4), s$4 += `<![CDATA[${a$4[l$4][0][e$4.textNodeName]}]]>`, r$4 = !1;
					continue;
				}
				if (l$4 === e$4.commentPropName) {
					s$4 += i$4 + `\x3c!--${a$4[l$4][0][e$4.textNodeName]}--\x3e`, r$4 = !0;
					continue;
				}
				if ("?" === l$4[0]) {
					const t$5 = lt(a$4[":@"], e$4), n$4 = "?xml" === l$4 ? "" : i$4;
					let o$5 = a$4[l$4][0][e$4.textNodeName];
					o$5 = 0 !== o$5.length ? " " + o$5 : "", s$4 += n$4 + `<${l$4}${o$5}${t$5}?>`, r$4 = !0;
					continue;
				}
				let h$4 = i$4;
				"" !== h$4 && (h$4 += e$4.indentBy);
				const d$4 = i$4 + `<${l$4}${lt(a$4[":@"], e$4)}`, f$4 = ot(a$4[l$4], e$4, u$4, h$4);
				-1 !== e$4.unpairedTags.indexOf(l$4) ? e$4.suppressUnpairedNode ? s$4 += d$4 + ">" : s$4 += d$4 + "/>" : f$4 && 0 !== f$4.length || !e$4.suppressEmptyNode ? f$4 && f$4.endsWith(">") ? s$4 += d$4 + `>${f$4}${i$4}</${l$4}>` : (s$4 += d$4 + ">", f$4 && "" !== i$4 && (f$4.includes("/>") || f$4.includes("</")) ? s$4 += i$4 + e$4.indentBy + f$4 + i$4 : s$4 += f$4, s$4 += `</${l$4}>`) : s$4 += d$4 + "/>", r$4 = !0;
			}
			return s$4;
		}
		function at(t$4) {
			const e$4 = Object.keys(t$4);
			for (let n$3 = 0; n$3 < e$4.length; n$3++) {
				const i$4 = e$4[n$3];
				if (t$4.hasOwnProperty(i$4) && ":@" !== i$4) return i$4;
			}
		}
		function lt(t$4, e$4) {
			let n$3 = "";
			if (t$4 && !e$4.ignoreAttributes) for (let i$4 in t$4) {
				if (!t$4.hasOwnProperty(i$4)) continue;
				let s$4 = e$4.attributeValueProcessor(i$4, t$4[i$4]);
				s$4 = ht(s$4, e$4), !0 === s$4 && e$4.suppressBooleanAttributes ? n$3 += ` ${i$4.substr(e$4.attributeNamePrefix.length)}` : n$3 += ` ${i$4.substr(e$4.attributeNamePrefix.length)}="${s$4}"`;
			}
			return n$3;
		}
		function ut(t$4, e$4) {
			let n$3 = (t$4 = t$4.substr(0, t$4.length - e$4.textNodeName.length - 1)).substr(t$4.lastIndexOf(".") + 1);
			for (let i$4 in e$4.stopNodes) if (e$4.stopNodes[i$4] === t$4 || e$4.stopNodes[i$4] === "*." + n$3) return !0;
			return !1;
		}
		function ht(t$4, e$4) {
			if (t$4 && t$4.length > 0 && e$4.processEntities) for (let n$3 = 0; n$3 < e$4.entities.length; n$3++) {
				const i$4 = e$4.entities[n$3];
				t$4 = t$4.replace(i$4.regex, i$4.val);
			}
			return t$4;
		}
		const dt = {
			attributeNamePrefix: "@_",
			attributesGroupName: !1,
			textNodeName: "#text",
			ignoreAttributes: !0,
			cdataPropName: !1,
			format: !1,
			indentBy: "  ",
			suppressEmptyNode: !1,
			suppressUnpairedNode: !0,
			suppressBooleanAttributes: !0,
			tagValueProcessor: function(t$4, e$4) {
				return e$4;
			},
			attributeValueProcessor: function(t$4, e$4) {
				return e$4;
			},
			preserveOrder: !1,
			commentPropName: !1,
			unpairedTags: [],
			entities: [
				{
					regex: new RegExp("&", "g"),
					val: "&amp;"
				},
				{
					regex: new RegExp(">", "g"),
					val: "&gt;"
				},
				{
					regex: new RegExp("<", "g"),
					val: "&lt;"
				},
				{
					regex: new RegExp("'", "g"),
					val: "&apos;"
				},
				{
					regex: new RegExp("\"", "g"),
					val: "&quot;"
				}
			],
			processEntities: !0,
			stopNodes: [],
			oneListGroup: !1
		};
		function ft(t$4) {
			this.options = Object.assign({}, dt, t$4), !0 === this.options.ignoreAttributes || this.options.attributesGroupName ? this.isAttribute = function() {
				return !1;
			} : (this.ignoreAttributesFn = _(this.options.ignoreAttributes), this.attrPrefixLen = this.options.attributeNamePrefix.length, this.isAttribute = gt), this.processTextOrObjNode = ct, this.options.format ? (this.indentate = pt, this.tagEndChar = ">\n", this.newLine = "\n") : (this.indentate = function() {
				return "";
			}, this.tagEndChar = ">", this.newLine = "");
		}
		function ct(t$4, e$4, n$3, i$4) {
			const s$4 = this.j2x(t$4, n$3 + 1, i$4.concat(e$4));
			return void 0 !== t$4[this.options.textNodeName] && 1 === Object.keys(t$4).length ? this.buildTextValNode(t$4[this.options.textNodeName], e$4, s$4.attrStr, n$3) : this.buildObjectNode(s$4.val, e$4, s$4.attrStr, n$3);
		}
		function pt(t$4) {
			return this.options.indentBy.repeat(t$4);
		}
		function gt(t$4) {
			return !(!t$4.startsWith(this.options.attributeNamePrefix) || t$4 === this.options.textNodeName) && t$4.substr(this.attrPrefixLen);
		}
		ft.prototype.build = function(t$4) {
			return this.options.preserveOrder ? rt(t$4, this.options) : (Array.isArray(t$4) && this.options.arrayNodeName && this.options.arrayNodeName.length > 1 && (t$4 = { [this.options.arrayNodeName]: t$4 }), this.j2x(t$4, 0, []).val);
		}, ft.prototype.j2x = function(t$4, e$4, n$3) {
			let i$4 = "", s$4 = "";
			const r$4 = n$3.join(".");
			for (let o$4 in t$4) if (Object.prototype.hasOwnProperty.call(t$4, o$4)) if (void 0 === t$4[o$4]) this.isAttribute(o$4) && (s$4 += "");
			else if (null === t$4[o$4]) this.isAttribute(o$4) || o$4 === this.options.cdataPropName ? s$4 += "" : "?" === o$4[0] ? s$4 += this.indentate(e$4) + "<" + o$4 + "?" + this.tagEndChar : s$4 += this.indentate(e$4) + "<" + o$4 + "/" + this.tagEndChar;
			else if (t$4[o$4] instanceof Date) s$4 += this.buildTextValNode(t$4[o$4], o$4, "", e$4);
			else if ("object" != typeof t$4[o$4]) {
				const n$4 = this.isAttribute(o$4);
				if (n$4 && !this.ignoreAttributesFn(n$4, r$4)) i$4 += this.buildAttrPairStr(n$4, "" + t$4[o$4]);
				else if (!n$4) if (o$4 === this.options.textNodeName) {
					let e$5 = this.options.tagValueProcessor(o$4, "" + t$4[o$4]);
					s$4 += this.replaceEntitiesValue(e$5);
				} else s$4 += this.buildTextValNode(t$4[o$4], o$4, "", e$4);
			} else if (Array.isArray(t$4[o$4])) {
				const i$5 = t$4[o$4].length;
				let r$5 = "", a$4 = "";
				for (let l$4 = 0; l$4 < i$5; l$4++) {
					const i$6 = t$4[o$4][l$4];
					if (void 0 === i$6);
					else if (null === i$6) "?" === o$4[0] ? s$4 += this.indentate(e$4) + "<" + o$4 + "?" + this.tagEndChar : s$4 += this.indentate(e$4) + "<" + o$4 + "/" + this.tagEndChar;
					else if ("object" == typeof i$6) if (this.options.oneListGroup) {
						const t$5 = this.j2x(i$6, e$4 + 1, n$3.concat(o$4));
						r$5 += t$5.val, this.options.attributesGroupName && i$6.hasOwnProperty(this.options.attributesGroupName) && (a$4 += t$5.attrStr);
					} else r$5 += this.processTextOrObjNode(i$6, o$4, e$4, n$3);
					else if (this.options.oneListGroup) {
						let t$5 = this.options.tagValueProcessor(o$4, i$6);
						t$5 = this.replaceEntitiesValue(t$5), r$5 += t$5;
					} else r$5 += this.buildTextValNode(i$6, o$4, "", e$4);
				}
				this.options.oneListGroup && (r$5 = this.buildObjectNode(r$5, o$4, a$4, e$4)), s$4 += r$5;
			} else if (this.options.attributesGroupName && o$4 === this.options.attributesGroupName) {
				const e$5 = Object.keys(t$4[o$4]), n$4 = e$5.length;
				for (let s$5 = 0; s$5 < n$4; s$5++) i$4 += this.buildAttrPairStr(e$5[s$5], "" + t$4[o$4][e$5[s$5]]);
			} else s$4 += this.processTextOrObjNode(t$4[o$4], o$4, e$4, n$3);
			return {
				attrStr: i$4,
				val: s$4
			};
		}, ft.prototype.buildAttrPairStr = function(t$4, e$4) {
			return e$4 = this.options.attributeValueProcessor(t$4, "" + e$4), e$4 = this.replaceEntitiesValue(e$4), this.options.suppressBooleanAttributes && "true" === e$4 ? " " + t$4 : " " + t$4 + "=\"" + e$4 + "\"";
		}, ft.prototype.buildObjectNode = function(t$4, e$4, n$3, i$4) {
			if ("" === t$4) return "?" === e$4[0] ? this.indentate(i$4) + "<" + e$4 + n$3 + "?" + this.tagEndChar : this.indentate(i$4) + "<" + e$4 + n$3 + this.closeTag(e$4) + this.tagEndChar;
			{
				let s$4 = "</" + e$4 + this.tagEndChar, r$4 = "";
				return "?" === e$4[0] && (r$4 = "?", s$4 = ""), !n$3 && "" !== n$3 || -1 !== t$4.indexOf("<") ? !1 !== this.options.commentPropName && e$4 === this.options.commentPropName && 0 === r$4.length ? this.indentate(i$4) + `\x3c!--${t$4}--\x3e` + this.newLine : this.indentate(i$4) + "<" + e$4 + n$3 + r$4 + this.tagEndChar + t$4 + this.indentate(i$4) + s$4 : this.indentate(i$4) + "<" + e$4 + n$3 + r$4 + ">" + t$4 + s$4;
			}
		}, ft.prototype.closeTag = function(t$4) {
			let e$4 = "";
			return -1 !== this.options.unpairedTags.indexOf(t$4) ? this.options.suppressUnpairedNode || (e$4 = "/") : e$4 = this.options.suppressEmptyNode ? "/" : `></${t$4}`, e$4;
		}, ft.prototype.buildTextValNode = function(t$4, e$4, n$3, i$4) {
			if (!1 !== this.options.cdataPropName && e$4 === this.options.cdataPropName) return this.indentate(i$4) + `<![CDATA[${t$4}]]>` + this.newLine;
			if (!1 !== this.options.commentPropName && e$4 === this.options.commentPropName) return this.indentate(i$4) + `\x3c!--${t$4}--\x3e` + this.newLine;
			if ("?" === e$4[0]) return this.indentate(i$4) + "<" + e$4 + n$3 + "?" + this.tagEndChar;
			{
				let s$4 = this.options.tagValueProcessor(e$4, t$4);
				return s$4 = this.replaceEntitiesValue(s$4), "" === s$4 ? this.indentate(i$4) + "<" + e$4 + n$3 + this.closeTag(e$4) + this.tagEndChar : this.indentate(i$4) + "<" + e$4 + n$3 + ">" + s$4 + "</" + e$4 + this.tagEndChar;
			}
		}, ft.prototype.replaceEntitiesValue = function(t$4) {
			if (t$4 && t$4.length > 0 && this.options.processEntities) for (let e$4 = 0; e$4 < this.options.entities.length; e$4++) {
				const n$3 = this.options.entities[e$4];
				t$4 = t$4.replace(n$3.regex, n$3.val);
			}
			return t$4;
		};
		const mt = { validate: a$3 };
		module.exports = e$3;
	})();
}));

//#endregion
//#region node_modules/@aws-sdk/xml-builder/dist-cjs/xml-parser.js
var require_xml_parser = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.parseXML = parseXML;
	const parser = new (require_fxp()).XMLParser({
		attributeNamePrefix: "",
		htmlEntities: true,
		ignoreAttributes: false,
		ignoreDeclaration: true,
		parseTagValue: false,
		trimValues: false,
		tagValueProcessor: (_, val) => val.trim() === "" && val.includes("\n") ? "" : void 0
	});
	parser.addEntity("#xD", "\r");
	parser.addEntity("#10", "\n");
	function parseXML(xmlString) {
		return parser.parse(xmlString, true);
	}
}));

//#endregion
//#region node_modules/@aws-sdk/xml-builder/dist-cjs/index.js
var require_dist_cjs$27 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var xmlParser = require_xml_parser();
	function escapeAttribute(value) {
		return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
	}
	function escapeElement(value) {
		return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&apos;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\r/g, "&#x0D;").replace(/\n/g, "&#x0A;").replace(/\u0085/g, "&#x85;").replace(/\u2028/, "&#x2028;");
	}
	var XmlText = class {
		value;
		constructor(value) {
			this.value = value;
		}
		toString() {
			return escapeElement("" + this.value);
		}
	};
	var XmlNode = class XmlNode {
		name;
		children;
		attributes = {};
		static of(name, childText, withName) {
			const node = new XmlNode(name);
			if (childText !== void 0) node.addChildNode(new XmlText(childText));
			if (withName !== void 0) node.withName(withName);
			return node;
		}
		constructor(name, children = []) {
			this.name = name;
			this.children = children;
		}
		withName(name) {
			this.name = name;
			return this;
		}
		addAttribute(name, value) {
			this.attributes[name] = value;
			return this;
		}
		addChildNode(child) {
			this.children.push(child);
			return this;
		}
		removeAttribute(name) {
			delete this.attributes[name];
			return this;
		}
		n(name) {
			this.name = name;
			return this;
		}
		c(child) {
			this.children.push(child);
			return this;
		}
		a(name, value) {
			if (value != null) this.attributes[name] = value;
			return this;
		}
		cc(input, field, withName = field) {
			if (input[field] != null) {
				const node = XmlNode.of(field, input[field]).withName(withName);
				this.c(node);
			}
		}
		l(input, listName, memberName, valueProvider) {
			if (input[listName] != null) valueProvider().map((node) => {
				node.withName(memberName);
				this.c(node);
			});
		}
		lc(input, listName, memberName, valueProvider) {
			if (input[listName] != null) {
				const nodes = valueProvider();
				const containerNode = new XmlNode(memberName);
				nodes.map((node) => {
					containerNode.c(node);
				});
				this.c(containerNode);
			}
		}
		toString() {
			const hasChildren = Boolean(this.children.length);
			let xmlText = `<${this.name}`;
			const attributes = this.attributes;
			for (const attributeName of Object.keys(attributes)) {
				const attribute = attributes[attributeName];
				if (attribute != null) xmlText += ` ${attributeName}="${escapeAttribute("" + attribute)}"`;
			}
			return xmlText += !hasChildren ? "/>" : `>${this.children.map((c$3) => c$3.toString()).join("")}</${this.name}>`;
		}
	};
	Object.defineProperty(exports, "parseXML", {
		enumerable: true,
		get: function() {
			return xmlParser.parseXML;
		}
	});
	exports.XmlNode = XmlNode;
	exports.XmlText = XmlText;
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeDeserializer.js
var import_dist_cjs$110, import_dist_cjs$111, import_dist_cjs$112, XmlShapeDeserializer;
var init_XmlShapeDeserializer = __esmMin((() => {
	import_dist_cjs$110 = require_dist_cjs$27();
	init_protocols$1();
	init_schema();
	import_dist_cjs$111 = require_dist_cjs$28();
	import_dist_cjs$112 = require_dist_cjs$44();
	init_ConfigurableSerdeContext();
	init_UnionSerde();
	XmlShapeDeserializer = class extends SerdeContextConfig {
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
			const xmlString = (this.serdeContext?.utf8Encoder ?? import_dist_cjs$112.toUtf8)(bytes);
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
					const buffer$4 = [];
					const sourceKey = listValue.getMergedTraits().xmlName ?? "member";
					const source = flat ? value : (value[0] ?? value)[sourceKey];
					const sourceArray = Array.isArray(source) ? source : [source];
					for (const v$3 of sourceArray) if (v$3 != null || sparse) buffer$4.push(this.readSchema(listValue, v$3));
					return buffer$4;
				}
				const buffer$3 = {};
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
						if (value$1 != null || sparse) buffer$3[key] = this.readSchema(memberNs, value$1);
					}
					return buffer$3;
				}
				if (ns.isStructSchema()) {
					const union = ns.isUnionSchema();
					let unionSerde;
					if (union) unionSerde = new UnionSerde(value, buffer$3);
					for (const [memberName, memberSchema] of ns.structIterator()) {
						const memberTraits = memberSchema.getMergedTraits();
						const xmlObjectKey = !memberTraits.httpPayload ? memberSchema.getMemberTraits().xmlName ?? memberName : memberTraits.xmlName ?? memberSchema.getName();
						if (union) unionSerde.mark(xmlObjectKey);
						if (value[xmlObjectKey] != null) buffer$3[memberName] = this.readSchema(memberSchema, value[xmlObjectKey]);
					}
					if (union) unionSerde.writeUnknown();
					return buffer$3;
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
					parsedObj = (0, import_dist_cjs$110.parseXML)(xml);
				} catch (e$3) {
					if (e$3 && typeof e$3 === "object") Object.defineProperty(e$3, "$responseBodyText", { value: xml });
					throw e$3;
				}
				const textNodeName = "#text";
				const key = Object.keys(parsedObj)[0];
				const parsedObjToReturn = parsedObj[key];
				if (parsedObjToReturn[textNodeName]) {
					parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
					delete parsedObjToReturn[textNodeName];
				}
				return (0, import_dist_cjs$111.getValueFromTextNode)(parsedObjToReturn);
			}
			return {};
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/QueryShapeSerializer.js
var import_dist_cjs$108, import_dist_cjs$109, QueryShapeSerializer;
var init_QueryShapeSerializer = __esmMin((() => {
	init_protocols$1();
	init_schema();
	init_serde();
	import_dist_cjs$108 = require_dist_cjs$28();
	import_dist_cjs$109 = require_dist_cjs$43();
	init_ConfigurableSerdeContext();
	init_structIterator();
	QueryShapeSerializer = class extends SerdeContextConfig {
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
					this.writeValue((this.serdeContext?.base64Encoder ?? import_dist_cjs$109.toBase64)(value));
				}
			} else if (ns.isBooleanSchema() || ns.isNumericSchema() || ns.isStringSchema()) {
				if (value != null) {
					this.writeKey(prefix);
					this.writeValue(String(value));
				} else if (ns.isIdempotencyToken()) {
					this.writeKey(prefix);
					this.writeValue((0, import_dist_cjs$141.v4)());
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
							this.writeValue((0, import_dist_cjs$108.dateToUtcString)(value));
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
					let i$3 = 1;
					for (const item of value) {
						if (item == null) continue;
						const suffix = this.getKey("member", member$1.getMergedTraits().xmlName);
						const key = flat ? `${prefix}${i$3}` : `${prefix}${suffix}.${i$3}`;
						this.write(member$1, item, key);
						++i$3;
					}
				}
			} else if (ns.isMapSchema()) {
				if (value && typeof value === "object") {
					const keySchema = ns.getKeySchema();
					const memberSchema = ns.getValueSchema();
					const flat = ns.getMergedTraits().xmlFlattened;
					let i$3 = 1;
					for (const [k$3, v$3] of Object.entries(value)) {
						if (v$3 == null) continue;
						const keySuffix = this.getKey("key", keySchema.getMergedTraits().xmlName);
						const key = flat ? `${prefix}${i$3}.${keySuffix}` : `${prefix}entry.${i$3}.${keySuffix}`;
						const valueSuffix = this.getKey("value", memberSchema.getMergedTraits().xmlName);
						const valueKey = flat ? `${prefix}${i$3}.${valueSuffix}` : `${prefix}entry.${i$3}.${valueSuffix}`;
						this.write(keySchema, k$3, key);
						this.write(memberSchema, v$3, valueKey);
						++i$3;
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
							const [k$3, v$3] = $unknown;
							const key = `${prefix}${k$3}`;
							this.write(15, v$3, key);
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
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsQueryProtocol.js
var AwsQueryProtocol;
var init_AwsQueryProtocol = __esmMin((() => {
	init_protocols$1();
	init_schema();
	init_ProtocolLib();
	init_XmlShapeDeserializer();
	init_QueryShapeSerializer();
	AwsQueryProtocol = class extends RpcProtocol {
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
				const bytes$1 = await collectBody$1(response.body, context);
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
			const bytes = await collectBody$1(response.body, context);
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
		loadQueryErrorCode(output, data$1) {
			const code = (data$1.Errors?.[0]?.Error ?? data$1.Errors?.Error ?? data$1.Error)?.Code;
			if (code !== void 0) return code;
			if (output.statusCode == 404) return "NotFound";
		}
		loadQueryError(data$1) {
			return data$1.Errors?.[0]?.Error ?? data$1.Errors?.Error ?? data$1.Error;
		}
		loadQueryErrorMessage(data$1) {
			const errorData = this.loadQueryError(data$1);
			return errorData?.message ?? errorData?.Message ?? data$1.message ?? data$1.Message ?? "Unknown";
		}
		getDefaultContentType() {
			return "application/x-www-form-urlencoded";
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsEc2QueryProtocol.js
var AwsEc2QueryProtocol;
var init_AwsEc2QueryProtocol = __esmMin((() => {
	init_AwsQueryProtocol();
	AwsEc2QueryProtocol = class extends AwsQueryProtocol {
		options;
		constructor(options) {
			super(options);
			this.options = options;
			Object.assign(this.serializer.settings, {
				capitalizeKeys: true,
				flattenLists: true,
				serializeEmptyLists: false
			});
		}
		useNestedResult() {
			return false;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/parseXmlBody.js
var import_dist_cjs$106, import_dist_cjs$107, parseXmlBody, parseXmlErrorBody, loadRestXmlErrorCode;
var init_parseXmlBody = __esmMin((() => {
	import_dist_cjs$106 = require_dist_cjs$27();
	import_dist_cjs$107 = require_dist_cjs$28();
	init_common();
	parseXmlBody = (streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
		if (encoded.length) {
			let parsedObj;
			try {
				parsedObj = (0, import_dist_cjs$106.parseXML)(encoded);
			} catch (e$3) {
				if (e$3 && typeof e$3 === "object") Object.defineProperty(e$3, "$responseBodyText", { value: encoded });
				throw e$3;
			}
			const textNodeName = "#text";
			const key = Object.keys(parsedObj)[0];
			const parsedObjToReturn = parsedObj[key];
			if (parsedObjToReturn[textNodeName]) {
				parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
				delete parsedObjToReturn[textNodeName];
			}
			return (0, import_dist_cjs$107.getValueFromTextNode)(parsedObjToReturn);
		}
		return {};
	});
	parseXmlErrorBody = async (errorBody, context) => {
		const value = await parseXmlBody(errorBody, context);
		if (value.Error) value.Error.message = value.Error.message ?? value.Error.Message;
		return value;
	};
	loadRestXmlErrorCode = (output, data$1) => {
		if (data$1?.Error?.Code !== void 0) return data$1.Error.Code;
		if (data$1?.Code !== void 0) return data$1.Code;
		if (output.statusCode == 404) return "NotFound";
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeSerializer.js
var import_dist_cjs$103, import_dist_cjs$104, import_dist_cjs$105, XmlShapeSerializer;
var init_XmlShapeSerializer = __esmMin((() => {
	import_dist_cjs$103 = require_dist_cjs$27();
	init_protocols$1();
	init_schema();
	init_serde();
	import_dist_cjs$104 = require_dist_cjs$28();
	import_dist_cjs$105 = require_dist_cjs$43();
	init_ConfigurableSerdeContext();
	init_structIterator();
	XmlShapeSerializer = class extends SerdeContextConfig {
		settings;
		stringBuffer;
		byteBuffer;
		buffer;
		constructor(settings) {
			super();
			this.settings = settings;
		}
		write(schema, value) {
			const ns = NormalizedSchema.of(schema);
			if (ns.isStringSchema() && typeof value === "string") this.stringBuffer = value;
			else if (ns.isBlobSchema()) this.byteBuffer = "byteLength" in value ? value : (this.serdeContext?.base64Decoder ?? import_dist_cjs$105.fromBase64)(value);
			else {
				this.buffer = this.writeStruct(ns, value, void 0);
				const traits = ns.getMergedTraits();
				if (traits.httpPayload && !traits.xmlName) this.buffer.withName(ns.getName());
			}
		}
		flush() {
			if (this.byteBuffer !== void 0) {
				const bytes = this.byteBuffer;
				delete this.byteBuffer;
				return bytes;
			}
			if (this.stringBuffer !== void 0) {
				const str = this.stringBuffer;
				delete this.stringBuffer;
				return str;
			}
			const buffer$3 = this.buffer;
			if (this.settings.xmlNamespace) {
				if (!buffer$3?.attributes?.["xmlns"]) buffer$3.addAttribute("xmlns", this.settings.xmlNamespace);
			}
			delete this.buffer;
			return buffer$3.toString();
		}
		writeStruct(ns, value, parentXmlns) {
			const traits = ns.getMergedTraits();
			const name = ns.isMemberSchema() && !traits.httpPayload ? ns.getMemberTraits().xmlName ?? ns.getMemberName() : traits.xmlName ?? ns.getName();
			if (!name || !ns.isStructSchema()) throw new Error(`@aws-sdk/core/protocols - xml serializer, cannot write struct with empty name or non-struct, schema=${ns.getName(true)}.`);
			const structXmlNode = import_dist_cjs$103.XmlNode.of(name);
			const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(ns, parentXmlns);
			for (const [memberName, memberSchema] of serializingStructIterator(ns, value)) {
				const val = value[memberName];
				if (val != null || memberSchema.isIdempotencyToken()) {
					if (memberSchema.getMergedTraits().xmlAttribute) {
						structXmlNode.addAttribute(memberSchema.getMergedTraits().xmlName ?? memberName, this.writeSimple(memberSchema, val));
						continue;
					}
					if (memberSchema.isListSchema()) this.writeList(memberSchema, val, structXmlNode, xmlns);
					else if (memberSchema.isMapSchema()) this.writeMap(memberSchema, val, structXmlNode, xmlns);
					else if (memberSchema.isStructSchema()) structXmlNode.addChildNode(this.writeStruct(memberSchema, val, xmlns));
					else {
						const memberNode = import_dist_cjs$103.XmlNode.of(memberSchema.getMergedTraits().xmlName ?? memberSchema.getMemberName());
						this.writeSimpleInto(memberSchema, val, memberNode, xmlns);
						structXmlNode.addChildNode(memberNode);
					}
				}
			}
			const { $unknown } = value;
			if ($unknown && ns.isUnionSchema() && Array.isArray($unknown) && Object.keys(value).length === 1) {
				const [k$3, v$3] = $unknown;
				const node = import_dist_cjs$103.XmlNode.of(k$3);
				if (typeof v$3 !== "string") if (value instanceof import_dist_cjs$103.XmlNode || value instanceof import_dist_cjs$103.XmlText) structXmlNode.addChildNode(value);
				else throw new Error("@aws-sdk - $unknown union member in XML requires value of type string, @aws-sdk/xml-builder::XmlNode or XmlText.");
				this.writeSimpleInto(0, v$3, node, xmlns);
				structXmlNode.addChildNode(node);
			}
			if (xmlns) structXmlNode.addAttribute(xmlnsAttr, xmlns);
			return structXmlNode;
		}
		writeList(listMember, array, container, parentXmlns) {
			if (!listMember.isMemberSchema()) throw new Error(`@aws-sdk/core/protocols - xml serializer, cannot write non-member list: ${listMember.getName(true)}`);
			const listTraits = listMember.getMergedTraits();
			const listValueSchema = listMember.getValueSchema();
			const listValueTraits = listValueSchema.getMergedTraits();
			const sparse = !!listValueTraits.sparse;
			const flat = !!listTraits.xmlFlattened;
			const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(listMember, parentXmlns);
			const writeItem = (container$1, value) => {
				if (listValueSchema.isListSchema()) this.writeList(listValueSchema, Array.isArray(value) ? value : [value], container$1, xmlns);
				else if (listValueSchema.isMapSchema()) this.writeMap(listValueSchema, value, container$1, xmlns);
				else if (listValueSchema.isStructSchema()) {
					const struct$1 = this.writeStruct(listValueSchema, value, xmlns);
					container$1.addChildNode(struct$1.withName(flat ? listTraits.xmlName ?? listMember.getMemberName() : listValueTraits.xmlName ?? "member"));
				} else {
					const listItemNode = import_dist_cjs$103.XmlNode.of(flat ? listTraits.xmlName ?? listMember.getMemberName() : listValueTraits.xmlName ?? "member");
					this.writeSimpleInto(listValueSchema, value, listItemNode, xmlns);
					container$1.addChildNode(listItemNode);
				}
			};
			if (flat) {
				for (const value of array) if (sparse || value != null) writeItem(container, value);
			} else {
				const listNode = import_dist_cjs$103.XmlNode.of(listTraits.xmlName ?? listMember.getMemberName());
				if (xmlns) listNode.addAttribute(xmlnsAttr, xmlns);
				for (const value of array) if (sparse || value != null) writeItem(listNode, value);
				container.addChildNode(listNode);
			}
		}
		writeMap(mapMember, map$1, container, parentXmlns, containerIsMap = false) {
			if (!mapMember.isMemberSchema()) throw new Error(`@aws-sdk/core/protocols - xml serializer, cannot write non-member map: ${mapMember.getName(true)}`);
			const mapTraits = mapMember.getMergedTraits();
			const mapKeySchema = mapMember.getKeySchema();
			const keyTag = mapKeySchema.getMergedTraits().xmlName ?? "key";
			const mapValueSchema = mapMember.getValueSchema();
			const mapValueTraits = mapValueSchema.getMergedTraits();
			const valueTag = mapValueTraits.xmlName ?? "value";
			const sparse = !!mapValueTraits.sparse;
			const flat = !!mapTraits.xmlFlattened;
			const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(mapMember, parentXmlns);
			const addKeyValue = (entry, key, val) => {
				const keyNode = import_dist_cjs$103.XmlNode.of(keyTag, key);
				const [keyXmlnsAttr, keyXmlns] = this.getXmlnsAttribute(mapKeySchema, xmlns);
				if (keyXmlns) keyNode.addAttribute(keyXmlnsAttr, keyXmlns);
				entry.addChildNode(keyNode);
				let valueNode = import_dist_cjs$103.XmlNode.of(valueTag);
				if (mapValueSchema.isListSchema()) this.writeList(mapValueSchema, val, valueNode, xmlns);
				else if (mapValueSchema.isMapSchema()) this.writeMap(mapValueSchema, val, valueNode, xmlns, true);
				else if (mapValueSchema.isStructSchema()) valueNode = this.writeStruct(mapValueSchema, val, xmlns);
				else this.writeSimpleInto(mapValueSchema, val, valueNode, xmlns);
				entry.addChildNode(valueNode);
			};
			if (flat) {
				for (const [key, val] of Object.entries(map$1)) if (sparse || val != null) {
					const entry = import_dist_cjs$103.XmlNode.of(mapTraits.xmlName ?? mapMember.getMemberName());
					addKeyValue(entry, key, val);
					container.addChildNode(entry);
				}
			} else {
				let mapNode;
				if (!containerIsMap) {
					mapNode = import_dist_cjs$103.XmlNode.of(mapTraits.xmlName ?? mapMember.getMemberName());
					if (xmlns) mapNode.addAttribute(xmlnsAttr, xmlns);
					container.addChildNode(mapNode);
				}
				for (const [key, val] of Object.entries(map$1)) if (sparse || val != null) {
					const entry = import_dist_cjs$103.XmlNode.of("entry");
					addKeyValue(entry, key, val);
					(containerIsMap ? container : mapNode).addChildNode(entry);
				}
			}
		}
		writeSimple(_schema, value) {
			if (null === value) throw new Error("@aws-sdk/core/protocols - (XML serializer) cannot write null value.");
			const ns = NormalizedSchema.of(_schema);
			let nodeContents = null;
			if (value && typeof value === "object") if (ns.isBlobSchema()) nodeContents = (this.serdeContext?.base64Encoder ?? import_dist_cjs$105.toBase64)(value);
			else if (ns.isTimestampSchema() && value instanceof Date) switch (determineTimestampFormat(ns, this.settings)) {
				case 5:
					nodeContents = value.toISOString().replace(".000Z", "Z");
					break;
				case 6:
					nodeContents = (0, import_dist_cjs$104.dateToUtcString)(value);
					break;
				case 7:
					nodeContents = String(value.getTime() / 1e3);
					break;
				default:
					console.warn("Missing timestamp format, using http date", value);
					nodeContents = (0, import_dist_cjs$104.dateToUtcString)(value);
					break;
			}
			else if (ns.isBigDecimalSchema() && value) {
				if (value instanceof NumericValue) return value.string;
				return String(value);
			} else if (ns.isMapSchema() || ns.isListSchema()) throw new Error("@aws-sdk/core/protocols - xml serializer, cannot call _write() on List/Map schema, call writeList or writeMap() instead.");
			else throw new Error(`@aws-sdk/core/protocols - xml serializer, unhandled schema type for object value and schema: ${ns.getName(true)}`);
			if (ns.isBooleanSchema() || ns.isNumericSchema() || ns.isBigIntegerSchema() || ns.isBigDecimalSchema()) nodeContents = String(value);
			if (ns.isStringSchema()) if (value === void 0 && ns.isIdempotencyToken()) nodeContents = (0, import_dist_cjs$141.v4)();
			else nodeContents = String(value);
			if (nodeContents === null) throw new Error(`Unhandled schema-value pair ${ns.getName(true)}=${value}`);
			return nodeContents;
		}
		writeSimpleInto(_schema, value, into, parentXmlns) {
			const nodeContents = this.writeSimple(_schema, value);
			const ns = NormalizedSchema.of(_schema);
			const content = new import_dist_cjs$103.XmlText(nodeContents);
			const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(ns, parentXmlns);
			if (xmlns) into.addAttribute(xmlnsAttr, xmlns);
			into.addChildNode(content);
		}
		getXmlnsAttribute(ns, parentXmlns) {
			const [prefix, xmlns] = ns.getMergedTraits().xmlNamespace ?? [];
			if (xmlns && xmlns !== parentXmlns) return [prefix ? `xmlns:${prefix}` : "xmlns", xmlns];
			return [void 0, void 0];
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlCodec.js
var XmlCodec;
var init_XmlCodec = __esmMin((() => {
	init_ConfigurableSerdeContext();
	init_XmlShapeDeserializer();
	init_XmlShapeSerializer();
	XmlCodec = class extends SerdeContextConfig {
		settings;
		constructor(settings) {
			super();
			this.settings = settings;
		}
		createSerializer() {
			const serializer = new XmlShapeSerializer(this.settings);
			serializer.setSerdeContext(this.serdeContext);
			return serializer;
		}
		createDeserializer() {
			const deserializer = new XmlShapeDeserializer(this.settings);
			deserializer.setSerdeContext(this.serdeContext);
			return deserializer;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/AwsRestXmlProtocol.js
var AwsRestXmlProtocol;
var init_AwsRestXmlProtocol = __esmMin((() => {
	init_protocols$1();
	init_schema();
	init_ProtocolLib();
	init_parseXmlBody();
	init_XmlCodec();
	AwsRestXmlProtocol = class extends HttpBindingProtocol {
		codec;
		serializer;
		deserializer;
		mixin = new ProtocolLib();
		constructor(options) {
			super(options);
			const settings = {
				timestampFormat: {
					useTrait: true,
					default: 5
				},
				httpBindings: true,
				xmlNamespace: options.xmlNamespace,
				serviceNamespace: options.defaultNamespace
			};
			this.codec = new XmlCodec(settings);
			this.serializer = new HttpInterceptingShapeSerializer(this.codec.createSerializer(), settings);
			this.deserializer = new HttpInterceptingShapeDeserializer(this.codec.createDeserializer(), settings);
		}
		getPayloadCodec() {
			return this.codec;
		}
		getShapeId() {
			return "aws.protocols#restXml";
		}
		async serializeRequest(operationSchema, input, context) {
			const request = await super.serializeRequest(operationSchema, input, context);
			const inputSchema = NormalizedSchema.of(operationSchema.input);
			if (!request.headers["content-type"]) {
				const contentType = this.mixin.resolveRestContentType(this.getDefaultContentType(), inputSchema);
				if (contentType) request.headers["content-type"] = contentType;
			}
			if (typeof request.body === "string" && request.headers["content-type"] === this.getDefaultContentType() && !request.body.startsWith("<?xml ") && !this.hasUnstructuredPayloadBinding(inputSchema)) request.body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + request.body;
			return request;
		}
		async deserializeResponse(operationSchema, context, response) {
			return super.deserializeResponse(operationSchema, context, response);
		}
		async handleError(operationSchema, context, response, dataObject, metadata) {
			const errorIdentifier = loadRestXmlErrorCode(response, dataObject) ?? "Unknown";
			const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata);
			const ns = NormalizedSchema.of(errorSchema);
			const message = dataObject.Error?.message ?? dataObject.Error?.Message ?? dataObject.message ?? dataObject.Message ?? "Unknown";
			const exception = new ((TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema)) ?? Error)(message);
			await this.deserializeHttpMessage(errorSchema, context, response, dataObject);
			const output = {};
			for (const [name, member$1] of ns.structIterator()) {
				const target = member$1.getMergedTraits().xmlName ?? name;
				const value = dataObject.Error?.[target] ?? dataObject[target];
				output[name] = this.codec.createDeserializer().readSchema(member$1, value);
			}
			throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
				$fault: ns.getMergedTraits().error,
				message
			}, output), dataObject);
		}
		getDefaultContentType() {
			return "application/xml";
		}
		hasUnstructuredPayloadBinding(ns) {
			for (const [, member$1] of ns.structIterator()) if (member$1.getMergedTraits().httpPayload) return !(member$1.isStructSchema() || member$1.isMapSchema() || member$1.isListSchema());
			return false;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/submodules/protocols/index.js
var protocols_exports = /* @__PURE__ */ __exportAll({
	AwsEc2QueryProtocol: () => AwsEc2QueryProtocol,
	AwsJson1_0Protocol: () => AwsJson1_0Protocol,
	AwsJson1_1Protocol: () => AwsJson1_1Protocol,
	AwsJsonRpcProtocol: () => AwsJsonRpcProtocol,
	AwsQueryProtocol: () => AwsQueryProtocol,
	AwsRestJsonProtocol: () => AwsRestJsonProtocol,
	AwsRestXmlProtocol: () => AwsRestXmlProtocol,
	AwsSmithyRpcV2CborProtocol: () => AwsSmithyRpcV2CborProtocol,
	JsonCodec: () => JsonCodec,
	JsonShapeDeserializer: () => JsonShapeDeserializer,
	JsonShapeSerializer: () => JsonShapeSerializer,
	XmlCodec: () => XmlCodec,
	XmlShapeDeserializer: () => XmlShapeDeserializer,
	XmlShapeSerializer: () => XmlShapeSerializer,
	_toBool: () => _toBool,
	_toNum: () => _toNum,
	_toStr: () => _toStr,
	awsExpectUnion: () => awsExpectUnion,
	loadRestJsonErrorCode: () => loadRestJsonErrorCode,
	loadRestXmlErrorCode: () => loadRestXmlErrorCode,
	parseJsonBody: () => parseJsonBody,
	parseJsonErrorBody: () => parseJsonErrorBody,
	parseXmlBody: () => parseXmlBody,
	parseXmlErrorBody: () => parseXmlErrorBody
});
var init_protocols = __esmMin((() => {
	init_AwsSmithyRpcV2CborProtocol();
	init_coercing_serializers();
	init_AwsJson1_0Protocol();
	init_AwsJson1_1Protocol();
	init_AwsJsonRpcProtocol();
	init_AwsRestJsonProtocol();
	init_JsonCodec();
	init_JsonShapeDeserializer();
	init_JsonShapeSerializer();
	init_awsExpectUnion();
	init_parseJsonBody();
	init_AwsEc2QueryProtocol();
	init_AwsQueryProtocol();
	init_AwsRestXmlProtocol();
	init_XmlCodec();
	init_XmlShapeDeserializer();
	init_XmlShapeSerializer();
	init_parseXmlBody();
}));

//#endregion
//#region node_modules/@aws-sdk/core/dist-es/index.js
var dist_es_exports = /* @__PURE__ */ __exportAll({
	AWSSDKSigV4Signer: () => AWSSDKSigV4Signer,
	AwsEc2QueryProtocol: () => AwsEc2QueryProtocol,
	AwsJson1_0Protocol: () => AwsJson1_0Protocol,
	AwsJson1_1Protocol: () => AwsJson1_1Protocol,
	AwsJsonRpcProtocol: () => AwsJsonRpcProtocol,
	AwsQueryProtocol: () => AwsQueryProtocol,
	AwsRestJsonProtocol: () => AwsRestJsonProtocol,
	AwsRestXmlProtocol: () => AwsRestXmlProtocol,
	AwsSdkSigV4ASigner: () => AwsSdkSigV4ASigner,
	AwsSdkSigV4Signer: () => AwsSdkSigV4Signer,
	AwsSmithyRpcV2CborProtocol: () => AwsSmithyRpcV2CborProtocol,
	JsonCodec: () => JsonCodec,
	JsonShapeDeserializer: () => JsonShapeDeserializer,
	JsonShapeSerializer: () => JsonShapeSerializer,
	NODE_AUTH_SCHEME_PREFERENCE_OPTIONS: () => NODE_AUTH_SCHEME_PREFERENCE_OPTIONS,
	NODE_SIGV4A_CONFIG_OPTIONS: () => NODE_SIGV4A_CONFIG_OPTIONS,
	XmlCodec: () => XmlCodec,
	XmlShapeDeserializer: () => XmlShapeDeserializer,
	XmlShapeSerializer: () => XmlShapeSerializer,
	_toBool: () => _toBool,
	_toNum: () => _toNum,
	_toStr: () => _toStr,
	awsExpectUnion: () => awsExpectUnion,
	emitWarningIfUnsupportedVersion: () => emitWarningIfUnsupportedVersion$3,
	getBearerTokenEnvKey: () => getBearerTokenEnvKey,
	loadRestJsonErrorCode: () => loadRestJsonErrorCode,
	loadRestXmlErrorCode: () => loadRestXmlErrorCode,
	parseJsonBody: () => parseJsonBody,
	parseJsonErrorBody: () => parseJsonErrorBody,
	parseXmlBody: () => parseXmlBody,
	parseXmlErrorBody: () => parseXmlErrorBody,
	resolveAWSSDKSigV4Config: () => resolveAWSSDKSigV4Config,
	resolveAwsSdkSigV4AConfig: () => resolveAwsSdkSigV4AConfig,
	resolveAwsSdkSigV4Config: () => resolveAwsSdkSigV4Config,
	setCredentialFeature: () => setCredentialFeature,
	setFeature: () => setFeature,
	setTokenFeature: () => setTokenFeature,
	state: () => state,
	validateSigningProperties: () => validateSigningProperties
});
var init_dist_es = __esmMin((() => {
	init_client();
	init_httpAuthSchemes();
	init_protocols();
}));

//#endregion
//#region node_modules/@aws-sdk/middleware-user-agent/dist-cjs/index.js
var require_dist_cjs$26 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var core = (init_dist_es$1(), __toCommonJS(dist_es_exports$1));
	var utilEndpoints = require_dist_cjs$32();
	var protocolHttp = require_dist_cjs$52();
	var core$1 = (init_dist_es(), __toCommonJS(dist_es_exports));
	const DEFAULT_UA_APP_ID = void 0;
	function isValidUserAgentAppId(appId) {
		if (appId === void 0) return true;
		return typeof appId === "string" && appId.length <= 50;
	}
	function resolveUserAgentConfig(input) {
		const normalizedAppIdProvider = core.normalizeProvider(input.userAgentAppId ?? DEFAULT_UA_APP_ID);
		const { customUserAgent } = input;
		return Object.assign(input, {
			customUserAgent: typeof customUserAgent === "string" ? [[customUserAgent]] : customUserAgent,
			userAgentAppId: async () => {
				const appId = await normalizedAppIdProvider();
				if (!isValidUserAgentAppId(appId)) {
					const logger$1 = input.logger?.constructor?.name === "NoOpLogger" || !input.logger ? console : input.logger;
					if (typeof appId !== "string") logger$1?.warn("userAgentAppId must be a string or undefined.");
					else if (appId.length > 50) logger$1?.warn("The provided userAgentAppId exceeds the maximum length of 50 characters.");
				}
				return appId;
			}
		});
	}
	const ACCOUNT_ID_ENDPOINT_REGEX = /\d{12}\.ddb/;
	async function checkFeatures(context, config, args) {
		if (args.request?.headers?.["smithy-protocol"] === "rpc-v2-cbor") core$1.setFeature(context, "PROTOCOL_RPC_V2_CBOR", "M");
		if (typeof config.retryStrategy === "function") {
			const retryStrategy = await config.retryStrategy();
			if (typeof retryStrategy.acquireInitialRetryToken === "function") if (retryStrategy.constructor?.name?.includes("Adaptive")) core$1.setFeature(context, "RETRY_MODE_ADAPTIVE", "F");
			else core$1.setFeature(context, "RETRY_MODE_STANDARD", "E");
			else core$1.setFeature(context, "RETRY_MODE_LEGACY", "D");
		}
		if (typeof config.accountIdEndpointMode === "function") {
			const endpointV2 = context.endpointV2;
			if (String(endpointV2?.url?.hostname).match(ACCOUNT_ID_ENDPOINT_REGEX)) core$1.setFeature(context, "ACCOUNT_ID_ENDPOINT", "O");
			switch (await config.accountIdEndpointMode?.()) {
				case "disabled":
					core$1.setFeature(context, "ACCOUNT_ID_MODE_DISABLED", "Q");
					break;
				case "preferred":
					core$1.setFeature(context, "ACCOUNT_ID_MODE_PREFERRED", "P");
					break;
				case "required":
					core$1.setFeature(context, "ACCOUNT_ID_MODE_REQUIRED", "R");
					break;
			}
		}
		const identity = context.__smithy_context?.selectedHttpAuthScheme?.identity;
		if (identity?.$source) {
			const credentials = identity;
			if (credentials.accountId) core$1.setFeature(context, "RESOLVED_ACCOUNT_ID", "T");
			for (const [key, value] of Object.entries(credentials.$source ?? {})) core$1.setFeature(context, key, value);
		}
	}
	const USER_AGENT = "user-agent";
	const X_AMZ_USER_AGENT = "x-amz-user-agent";
	const SPACE = " ";
	const UA_NAME_SEPARATOR = "/";
	const UA_NAME_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w]/g;
	const UA_VALUE_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w#]/g;
	const UA_ESCAPE_CHAR = "-";
	const BYTE_LIMIT = 1024;
	function encodeFeatures(features) {
		let buffer$3 = "";
		for (const key in features) {
			const val = features[key];
			if (buffer$3.length + val.length + 1 <= BYTE_LIMIT) {
				if (buffer$3.length) buffer$3 += "," + val;
				else buffer$3 += val;
				continue;
			}
			break;
		}
		return buffer$3;
	}
	const userAgentMiddleware = (options) => (next, context) => async (args) => {
		const { request } = args;
		if (!protocolHttp.HttpRequest.isInstance(request)) return next(args);
		const { headers } = request;
		const userAgent = context?.userAgent?.map(escapeUserAgent) || [];
		const defaultUserAgent = (await options.defaultUserAgentProvider()).map(escapeUserAgent);
		await checkFeatures(context, options, args);
		const awsContext = context;
		defaultUserAgent.push(`m/${encodeFeatures(Object.assign({}, context.__smithy_context?.features, awsContext.__aws_sdk_context?.features))}`);
		const customUserAgent = options?.customUserAgent?.map(escapeUserAgent) || [];
		const appId = await options.userAgentAppId();
		if (appId) defaultUserAgent.push(escapeUserAgent([`app`, `${appId}`]));
		const prefix = utilEndpoints.getUserAgentPrefix();
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
		const version$1 = userAgentPair[1]?.replace(UA_VALUE_ESCAPE_REGEX, UA_ESCAPE_CHAR);
		const prefixSeparatorIndex = name.indexOf(UA_NAME_SEPARATOR);
		const prefix = name.substring(0, prefixSeparatorIndex);
		let uaName = name.substring(prefixSeparatorIndex + 1);
		if (prefix === "api") uaName = uaName.toLowerCase();
		return [
			prefix,
			uaName,
			version$1
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
	exports.DEFAULT_UA_APP_ID = DEFAULT_UA_APP_ID;
	exports.getUserAgentMiddlewareOptions = getUserAgentMiddlewareOptions;
	exports.getUserAgentPlugin = getUserAgentPlugin;
	exports.resolveUserAgentConfig = resolveUserAgentConfig;
	exports.userAgentMiddleware = userAgentMiddleware;
}));

//#endregion
//#region node_modules/@smithy/util-config-provider/dist-cjs/index.js
var require_dist_cjs$25 = /* @__PURE__ */ __commonJSMin(((exports) => {
	const booleanSelector = (obj, key, type) => {
		if (!(key in obj)) return void 0;
		if (obj[key] === "true") return true;
		if (obj[key] === "false") return false;
		throw new Error(`Cannot load ${type} "${key}". Expected "true" or "false", got ${obj[key]}.`);
	};
	const numberSelector = (obj, key, type) => {
		if (!(key in obj)) return void 0;
		const numberValue = parseInt(obj[key], 10);
		if (Number.isNaN(numberValue)) throw new TypeError(`Cannot load ${type} '${key}'. Expected number, got '${obj[key]}'.`);
		return numberValue;
	};
	exports.SelectorType = void 0;
	(function(SelectorType) {
		SelectorType["ENV"] = "env";
		SelectorType["CONFIG"] = "shared config entry";
	})(exports.SelectorType || (exports.SelectorType = {}));
	exports.booleanSelector = booleanSelector;
	exports.numberSelector = numberSelector;
}));

//#endregion
//#region node_modules/@smithy/config-resolver/dist-cjs/index.js
var require_dist_cjs$24 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilConfigProvider = require_dist_cjs$25();
	var utilMiddleware = require_dist_cjs$48();
	var utilEndpoints = require_dist_cjs$35();
	const ENV_USE_DUALSTACK_ENDPOINT = "AWS_USE_DUALSTACK_ENDPOINT";
	const CONFIG_USE_DUALSTACK_ENDPOINT = "use_dualstack_endpoint";
	const DEFAULT_USE_DUALSTACK_ENDPOINT = false;
	const NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => utilConfigProvider.booleanSelector(env, ENV_USE_DUALSTACK_ENDPOINT, utilConfigProvider.SelectorType.ENV),
		configFileSelector: (profile) => utilConfigProvider.booleanSelector(profile, CONFIG_USE_DUALSTACK_ENDPOINT, utilConfigProvider.SelectorType.CONFIG),
		default: false
	};
	const ENV_USE_FIPS_ENDPOINT = "AWS_USE_FIPS_ENDPOINT";
	const CONFIG_USE_FIPS_ENDPOINT = "use_fips_endpoint";
	const DEFAULT_USE_FIPS_ENDPOINT = false;
	const NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => utilConfigProvider.booleanSelector(env, ENV_USE_FIPS_ENDPOINT, utilConfigProvider.SelectorType.ENV),
		configFileSelector: (profile) => utilConfigProvider.booleanSelector(profile, CONFIG_USE_FIPS_ENDPOINT, utilConfigProvider.SelectorType.CONFIG),
		default: false
	};
	const resolveCustomEndpointsConfig = (input) => {
		const { tls, endpoint, urlParser, useDualstackEndpoint } = input;
		return Object.assign(input, {
			tls: tls ?? true,
			endpoint: utilMiddleware.normalizeProvider(typeof endpoint === "string" ? urlParser(endpoint) : endpoint),
			isCustomEndpoint: true,
			useDualstackEndpoint: utilMiddleware.normalizeProvider(useDualstackEndpoint ?? false)
		});
	};
	const getEndpointFromRegion = async (input) => {
		const { tls = true } = input;
		const region = await input.region();
		if (!(/* @__PURE__ */ new RegExp(/^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])$/)).test(region)) throw new Error("Invalid region in client config");
		const useDualstackEndpoint = await input.useDualstackEndpoint();
		const useFipsEndpoint = await input.useFipsEndpoint();
		const { hostname } = await input.regionInfoProvider(region, {
			useDualstackEndpoint,
			useFipsEndpoint
		}) ?? {};
		if (!hostname) throw new Error("Cannot resolve hostname from client config");
		return input.urlParser(`${tls ? "https:" : "http:"}//${hostname}`);
	};
	const resolveEndpointsConfig = (input) => {
		const useDualstackEndpoint = utilMiddleware.normalizeProvider(input.useDualstackEndpoint ?? false);
		const { endpoint, useFipsEndpoint, urlParser, tls } = input;
		return Object.assign(input, {
			tls: tls ?? true,
			endpoint: endpoint ? utilMiddleware.normalizeProvider(typeof endpoint === "string" ? urlParser(endpoint) : endpoint) : () => getEndpointFromRegion({
				...input,
				useDualstackEndpoint,
				useFipsEndpoint
			}),
			isCustomEndpoint: !!endpoint,
			useDualstackEndpoint
		});
	};
	const REGION_ENV_NAME = "AWS_REGION";
	const REGION_INI_NAME = "region";
	const NODE_REGION_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => env[REGION_ENV_NAME],
		configFileSelector: (profile) => profile[REGION_INI_NAME],
		default: () => {
			throw new Error("Region is missing");
		}
	};
	const NODE_REGION_CONFIG_FILE_OPTIONS = { preferredFile: "credentials" };
	const validRegions = /* @__PURE__ */ new Set();
	const checkRegion = (region, check = utilEndpoints.isValidHostLabel) => {
		if (!validRegions.has(region) && !check(region)) if (region === "*") console.warn(`@smithy/config-resolver WARN - Please use the caller region instead of "*". See "sigv4a" in https://github.com/aws/aws-sdk-js-v3/blob/main/supplemental-docs/CLIENTS.md.`);
		else throw new Error(`Region not accepted: region="${region}" is not a valid hostname component.`);
		else validRegions.add(region);
	};
	const isFipsRegion = (region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips"));
	const getRealRegion = (region) => isFipsRegion(region) ? ["fips-aws-global", "aws-fips"].includes(region) ? "us-east-1" : region.replace(/fips-(dkr-|prod-)?|-fips/, "") : region;
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
	const getHostnameFromVariants = (variants = [], { useFipsEndpoint, useDualstackEndpoint }) => variants.find(({ tags }) => useFipsEndpoint === tags.includes("fips") && useDualstackEndpoint === tags.includes("dualstack"))?.hostname;
	const getResolvedHostname = (resolvedRegion, { regionHostname, partitionHostname }) => regionHostname ? regionHostname : partitionHostname ? partitionHostname.replace("{region}", resolvedRegion) : void 0;
	const getResolvedPartition = (region, { partitionHash }) => Object.keys(partitionHash || {}).find((key) => partitionHash[key].regions.includes(region)) ?? "aws";
	const getResolvedSigningRegion = (hostname, { signingRegion, regionRegex, useFipsEndpoint }) => {
		if (signingRegion) return signingRegion;
		else if (useFipsEndpoint) {
			const regionRegexJs = regionRegex.replace("\\\\", "\\").replace(/^\^/g, "\\.").replace(/\$$/g, "\\.");
			const regionRegexmatchArray = hostname.match(regionRegexJs);
			if (regionRegexmatchArray) return regionRegexmatchArray[0].slice(1, -1);
		}
	};
	const getRegionInfo = (region, { useFipsEndpoint = false, useDualstackEndpoint = false, signingService, regionHash, partitionHash }) => {
		const partition = getResolvedPartition(region, { partitionHash });
		const resolvedRegion = region in regionHash ? region : partitionHash[partition]?.endpoint ?? region;
		const hostnameOptions = {
			useFipsEndpoint,
			useDualstackEndpoint
		};
		const hostname = getResolvedHostname(resolvedRegion, {
			regionHostname: getHostnameFromVariants(regionHash[resolvedRegion]?.variants, hostnameOptions),
			partitionHostname: getHostnameFromVariants(partitionHash[partition]?.variants, hostnameOptions)
		});
		if (hostname === void 0) throw new Error(`Endpoint resolution failed for: [object Object]`);
		const signingRegion = getResolvedSigningRegion(hostname, {
			signingRegion: regionHash[resolvedRegion]?.signingRegion,
			regionRegex: partitionHash[partition].regionRegex,
			useFipsEndpoint
		});
		return {
			partition,
			signingService,
			hostname,
			...signingRegion && { signingRegion },
			...regionHash[resolvedRegion]?.signingService && { signingService: regionHash[resolvedRegion].signingService }
		};
	};
	exports.CONFIG_USE_DUALSTACK_ENDPOINT = CONFIG_USE_DUALSTACK_ENDPOINT;
	exports.CONFIG_USE_FIPS_ENDPOINT = CONFIG_USE_FIPS_ENDPOINT;
	exports.DEFAULT_USE_DUALSTACK_ENDPOINT = DEFAULT_USE_DUALSTACK_ENDPOINT;
	exports.DEFAULT_USE_FIPS_ENDPOINT = DEFAULT_USE_FIPS_ENDPOINT;
	exports.ENV_USE_DUALSTACK_ENDPOINT = ENV_USE_DUALSTACK_ENDPOINT;
	exports.ENV_USE_FIPS_ENDPOINT = ENV_USE_FIPS_ENDPOINT;
	exports.NODE_REGION_CONFIG_FILE_OPTIONS = NODE_REGION_CONFIG_FILE_OPTIONS;
	exports.NODE_REGION_CONFIG_OPTIONS = NODE_REGION_CONFIG_OPTIONS;
	exports.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS;
	exports.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS = NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS;
	exports.REGION_ENV_NAME = REGION_ENV_NAME;
	exports.REGION_INI_NAME = REGION_INI_NAME;
	exports.getRegionInfo = getRegionInfo;
	exports.resolveCustomEndpointsConfig = resolveCustomEndpointsConfig;
	exports.resolveEndpointsConfig = resolveEndpointsConfig;
	exports.resolveRegionConfig = resolveRegionConfig;
}));

//#endregion
//#region node_modules/@smithy/middleware-content-length/dist-cjs/index.js
var require_dist_cjs$23 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var protocolHttp = require_dist_cjs$52();
	const CONTENT_LENGTH_HEADER = "content-length";
	function contentLengthMiddleware(bodyLengthChecker) {
		return (next) => async (args) => {
			const request = args.request;
			if (protocolHttp.HttpRequest.isInstance(request)) {
				const { body, headers } = request;
				if (body && Object.keys(headers).map((str) => str.toLowerCase()).indexOf(CONTENT_LENGTH_HEADER) === -1) try {
					const length = bodyLengthChecker(body);
					request.headers = {
						...request.headers,
						[CONTENT_LENGTH_HEADER]: String(length)
					};
				} catch (error$1) {}
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
	exports.contentLengthMiddleware = contentLengthMiddleware;
	exports.contentLengthMiddlewareOptions = contentLengthMiddlewareOptions;
	exports.getContentLengthPlugin = getContentLengthPlugin;
}));

//#endregion
//#region node_modules/@smithy/shared-ini-file-loader/dist-cjs/getHomeDir.js
var require_getHomeDir = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getHomeDir = void 0;
	const os_1 = require("os");
	const path_1$1 = require("path");
	const homeDirCache = {};
	const getHomeDirCacheKey = () => {
		if (process && process.geteuid) return `${process.geteuid()}`;
		return "DEFAULT";
	};
	const getHomeDir = () => {
		const { HOME, USERPROFILE, HOMEPATH, HOMEDRIVE = `C:${path_1$1.sep}` } = process.env;
		if (HOME) return HOME;
		if (USERPROFILE) return USERPROFILE;
		if (HOMEPATH) return `${HOMEDRIVE}${HOMEPATH}`;
		const homeDirCacheKey = getHomeDirCacheKey();
		if (!homeDirCache[homeDirCacheKey]) homeDirCache[homeDirCacheKey] = (0, os_1.homedir)();
		return homeDirCache[homeDirCacheKey];
	};
	exports.getHomeDir = getHomeDir;
}));

//#endregion
//#region node_modules/@smithy/shared-ini-file-loader/dist-cjs/getSSOTokenFilepath.js
var require_getSSOTokenFilepath = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getSSOTokenFilepath = void 0;
	const crypto_1 = require("crypto");
	const path_1 = require("path");
	const getHomeDir_1 = require_getHomeDir();
	const getSSOTokenFilepath = (id) => {
		const cacheName = (0, crypto_1.createHash)("sha1").update(id).digest("hex");
		return (0, path_1.join)((0, getHomeDir_1.getHomeDir)(), ".aws", "sso", "cache", `${cacheName}.json`);
	};
	exports.getSSOTokenFilepath = getSSOTokenFilepath;
}));

//#endregion
//#region node_modules/@smithy/shared-ini-file-loader/dist-cjs/getSSOTokenFromFile.js
var require_getSSOTokenFromFile = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getSSOTokenFromFile = exports.tokenIntercept = void 0;
	const promises_1$2 = require("fs/promises");
	const getSSOTokenFilepath_1 = require_getSSOTokenFilepath();
	exports.tokenIntercept = {};
	const getSSOTokenFromFile = async (id) => {
		if (exports.tokenIntercept[id]) return exports.tokenIntercept[id];
		const ssoTokenFilepath = (0, getSSOTokenFilepath_1.getSSOTokenFilepath)(id);
		const ssoTokenText = await (0, promises_1$2.readFile)(ssoTokenFilepath, "utf8");
		return JSON.parse(ssoTokenText);
	};
	exports.getSSOTokenFromFile = getSSOTokenFromFile;
}));

//#endregion
//#region node_modules/@smithy/shared-ini-file-loader/dist-cjs/readFile.js
var require_readFile = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.readFile = exports.fileIntercept = exports.filePromises = void 0;
	const promises_1$1 = require("node:fs/promises");
	exports.filePromises = {};
	exports.fileIntercept = {};
	const readFile = (path$1, options) => {
		if (exports.fileIntercept[path$1] !== void 0) return exports.fileIntercept[path$1];
		if (!exports.filePromises[path$1] || options?.ignoreCache) exports.filePromises[path$1] = (0, promises_1$1.readFile)(path$1, "utf8");
		return exports.filePromises[path$1];
	};
	exports.readFile = readFile;
}));

//#endregion
//#region node_modules/@smithy/shared-ini-file-loader/dist-cjs/index.js
var require_dist_cjs$22 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var getHomeDir = require_getHomeDir();
	var getSSOTokenFilepath = require_getSSOTokenFilepath();
	var getSSOTokenFromFile = require_getSSOTokenFromFile();
	var path = require("path");
	var types = require_dist_cjs$53();
	var readFile = require_readFile();
	const ENV_PROFILE = "AWS_PROFILE";
	const DEFAULT_PROFILE = "default";
	const getProfileName = (init) => init.profile || process.env[ENV_PROFILE] || DEFAULT_PROFILE;
	const CONFIG_PREFIX_SEPARATOR = ".";
	const getConfigData = (data$1) => Object.entries(data$1).filter(([key]) => {
		const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
		if (indexOfSeparator === -1) return false;
		return Object.values(types.IniSectionType).includes(key.substring(0, indexOfSeparator));
	}).reduce((acc, [key, value]) => {
		const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
		const updatedKey = key.substring(0, indexOfSeparator) === types.IniSectionType.PROFILE ? key.substring(indexOfSeparator + 1) : key;
		acc[updatedKey] = value;
		return acc;
	}, { ...data$1.default && { default: data$1.default } });
	const ENV_CONFIG_PATH = "AWS_CONFIG_FILE";
	const getConfigFilepath = () => process.env[ENV_CONFIG_PATH] || path.join(getHomeDir.getHomeDir(), ".aws", "config");
	const ENV_CREDENTIALS_PATH = "AWS_SHARED_CREDENTIALS_FILE";
	const getCredentialsFilepath = () => process.env[ENV_CREDENTIALS_PATH] || path.join(getHomeDir.getHomeDir(), ".aws", "credentials");
	const prefixKeyRegex = /^([\w-]+)\s(["'])?([\w-@\+\.%:/]+)\2$/;
	const profileNameBlockList = ["__proto__", "profile __proto__"];
	const parseIni = (iniData) => {
		const map$1 = {};
		let currentSection;
		let currentSubSection;
		for (const iniLine of iniData.split(/\r?\n/)) {
			const trimmedLine = iniLine.split(/(^|\s)[;#]/)[0].trim();
			if (trimmedLine[0] === "[" && trimmedLine[trimmedLine.length - 1] === "]") {
				currentSection = void 0;
				currentSubSection = void 0;
				const sectionName = trimmedLine.substring(1, trimmedLine.length - 1);
				const matches = prefixKeyRegex.exec(sectionName);
				if (matches) {
					const [, prefix, , name] = matches;
					if (Object.values(types.IniSectionType).includes(prefix)) currentSection = [prefix, name].join(CONFIG_PREFIX_SEPARATOR);
				} else currentSection = sectionName;
				if (profileNameBlockList.includes(sectionName)) throw new Error(`Found invalid profile name "${sectionName}"`);
			} else if (currentSection) {
				const indexOfEqualsSign = trimmedLine.indexOf("=");
				if (![0, -1].includes(indexOfEqualsSign)) {
					const [name, value] = [trimmedLine.substring(0, indexOfEqualsSign).trim(), trimmedLine.substring(indexOfEqualsSign + 1).trim()];
					if (value === "") currentSubSection = name;
					else {
						if (currentSubSection && iniLine.trimStart() === iniLine) currentSubSection = void 0;
						map$1[currentSection] = map$1[currentSection] || {};
						const key = currentSubSection ? [currentSubSection, name].join(CONFIG_PREFIX_SEPARATOR) : name;
						map$1[currentSection][key] = value;
					}
				}
			}
		}
		return map$1;
	};
	const swallowError$1 = () => ({});
	const loadSharedConfigFiles = async (init = {}) => {
		const { filepath = getCredentialsFilepath(), configFilepath = getConfigFilepath() } = init;
		const homeDir = getHomeDir.getHomeDir();
		const relativeHomeDirPrefix = "~/";
		let resolvedFilepath = filepath;
		if (filepath.startsWith(relativeHomeDirPrefix)) resolvedFilepath = path.join(homeDir, filepath.slice(2));
		let resolvedConfigFilepath = configFilepath;
		if (configFilepath.startsWith(relativeHomeDirPrefix)) resolvedConfigFilepath = path.join(homeDir, configFilepath.slice(2));
		const parsedFiles = await Promise.all([readFile.readFile(resolvedConfigFilepath, { ignoreCache: init.ignoreCache }).then(parseIni).then(getConfigData).catch(swallowError$1), readFile.readFile(resolvedFilepath, { ignoreCache: init.ignoreCache }).then(parseIni).catch(swallowError$1)]);
		return {
			configFile: parsedFiles[0],
			credentialsFile: parsedFiles[1]
		};
	};
	const getSsoSessionData = (data$1) => Object.entries(data$1).filter(([key]) => key.startsWith(types.IniSectionType.SSO_SESSION + CONFIG_PREFIX_SEPARATOR)).reduce((acc, [key, value]) => ({
		...acc,
		[key.substring(key.indexOf(CONFIG_PREFIX_SEPARATOR) + 1)]: value
	}), {});
	const swallowError = () => ({});
	const loadSsoSessionData = async (init = {}) => readFile.readFile(init.configFilepath ?? getConfigFilepath()).then(parseIni).then(getSsoSessionData).catch(swallowError);
	const mergeConfigFiles = (...files) => {
		const merged = {};
		for (const file of files) for (const [key, values] of Object.entries(file)) if (merged[key] !== void 0) Object.assign(merged[key], values);
		else merged[key] = values;
		return merged;
	};
	const parseKnownFiles = async (init) => {
		const parsedFiles = await loadSharedConfigFiles(init);
		return mergeConfigFiles(parsedFiles.configFile, parsedFiles.credentialsFile);
	};
	const externalDataInterceptor = {
		getFileRecord() {
			return readFile.fileIntercept;
		},
		interceptFile(path$1, contents) {
			readFile.fileIntercept[path$1] = Promise.resolve(contents);
		},
		getTokenRecord() {
			return getSSOTokenFromFile.tokenIntercept;
		},
		interceptToken(id, contents) {
			getSSOTokenFromFile.tokenIntercept[id] = contents;
		}
	};
	Object.defineProperty(exports, "getSSOTokenFromFile", {
		enumerable: true,
		get: function() {
			return getSSOTokenFromFile.getSSOTokenFromFile;
		}
	});
	Object.defineProperty(exports, "readFile", {
		enumerable: true,
		get: function() {
			return readFile.readFile;
		}
	});
	exports.CONFIG_PREFIX_SEPARATOR = CONFIG_PREFIX_SEPARATOR;
	exports.DEFAULT_PROFILE = DEFAULT_PROFILE;
	exports.ENV_PROFILE = ENV_PROFILE;
	exports.externalDataInterceptor = externalDataInterceptor;
	exports.getProfileName = getProfileName;
	exports.loadSharedConfigFiles = loadSharedConfigFiles;
	exports.loadSsoSessionData = loadSsoSessionData;
	exports.parseKnownFiles = parseKnownFiles;
	Object.keys(getHomeDir).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return getHomeDir[k$3];
			}
		});
	});
	Object.keys(getSSOTokenFilepath).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return getSSOTokenFilepath[k$3];
			}
		});
	});
}));

//#endregion
//#region node_modules/@smithy/node-config-provider/dist-cjs/index.js
var require_dist_cjs$21 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var propertyProvider = require_dist_cjs$31();
	var sharedIniFileLoader = require_dist_cjs$22();
	function getSelectorName(functionString) {
		try {
			const constants = new Set(Array.from(functionString.match(/([A-Z_]){3,}/g) ?? []));
			constants.delete("CONFIG");
			constants.delete("CONFIG_PREFIX_SEPARATOR");
			constants.delete("ENV");
			return [...constants].join(", ");
		} catch (e$3) {
			return functionString;
		}
	}
	const fromEnv = (envVarSelector, options) => async () => {
		try {
			const config = envVarSelector(process.env, options);
			if (config === void 0) throw new Error();
			return config;
		} catch (e$3) {
			throw new propertyProvider.CredentialsProviderError(e$3.message || `Not found in ENV: ${getSelectorName(envVarSelector.toString())}`, { logger: options?.logger });
		}
	};
	const fromSharedConfigFiles = (configSelector, { preferredFile = "config", ...init } = {}) => async () => {
		const profile = sharedIniFileLoader.getProfileName(init);
		const { configFile, credentialsFile } = await sharedIniFileLoader.loadSharedConfigFiles(init);
		const profileFromCredentials = credentialsFile[profile] || {};
		const profileFromConfig = configFile[profile] || {};
		const mergedProfile = preferredFile === "config" ? {
			...profileFromCredentials,
			...profileFromConfig
		} : {
			...profileFromConfig,
			...profileFromCredentials
		};
		try {
			const configValue = configSelector(mergedProfile, preferredFile === "config" ? configFile : credentialsFile);
			if (configValue === void 0) throw new Error();
			return configValue;
		} catch (e$3) {
			throw new propertyProvider.CredentialsProviderError(e$3.message || `Not found in config files w/ profile [${profile}]: ${getSelectorName(configSelector.toString())}`, { logger: init.logger });
		}
	};
	const isFunction = (func) => typeof func === "function";
	const fromStatic = (defaultValue) => isFunction(defaultValue) ? async () => await defaultValue() : propertyProvider.fromStatic(defaultValue);
	const loadConfig = ({ environmentVariableSelector, configFileSelector, default: defaultValue }, configuration = {}) => {
		const { signingName, logger: logger$1 } = configuration;
		const envOptions = {
			signingName,
			logger: logger$1
		};
		return propertyProvider.memoize(propertyProvider.chain(fromEnv(environmentVariableSelector, envOptions), fromSharedConfigFiles(configFileSelector, configuration), fromStatic(defaultValue)));
	};
	exports.loadConfig = loadConfig;
}));

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-cjs/adaptors/getEndpointUrlConfig.js
var require_getEndpointUrlConfig = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getEndpointUrlConfig = void 0;
	const shared_ini_file_loader_1 = require_dist_cjs$22();
	const ENV_ENDPOINT_URL = "AWS_ENDPOINT_URL";
	const CONFIG_ENDPOINT_URL = "endpoint_url";
	const getEndpointUrlConfig = (serviceId) => ({
		environmentVariableSelector: (env) => {
			const serviceEndpointUrl = env[[ENV_ENDPOINT_URL, ...serviceId.split(" ").map((w$3) => w$3.toUpperCase())].join("_")];
			if (serviceEndpointUrl) return serviceEndpointUrl;
			const endpointUrl = env[ENV_ENDPOINT_URL];
			if (endpointUrl) return endpointUrl;
		},
		configFileSelector: (profile, config) => {
			if (config && profile.services) {
				const servicesSection = config[["services", profile.services].join(shared_ini_file_loader_1.CONFIG_PREFIX_SEPARATOR)];
				if (servicesSection) {
					const endpointUrl$1 = servicesSection[[serviceId.split(" ").map((w$3) => w$3.toLowerCase()).join("_"), CONFIG_ENDPOINT_URL].join(shared_ini_file_loader_1.CONFIG_PREFIX_SEPARATOR)];
					if (endpointUrl$1) return endpointUrl$1;
				}
			}
			const endpointUrl = profile[CONFIG_ENDPOINT_URL];
			if (endpointUrl) return endpointUrl;
		},
		default: void 0
	});
	exports.getEndpointUrlConfig = getEndpointUrlConfig;
}));

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-cjs/adaptors/getEndpointFromConfig.js
var require_getEndpointFromConfig = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getEndpointFromConfig = void 0;
	const node_config_provider_1 = require_dist_cjs$21();
	const getEndpointUrlConfig_1 = require_getEndpointUrlConfig();
	const getEndpointFromConfig = async (serviceId) => (0, node_config_provider_1.loadConfig)((0, getEndpointUrlConfig_1.getEndpointUrlConfig)(serviceId ?? ""))();
	exports.getEndpointFromConfig = getEndpointFromConfig;
}));

//#endregion
//#region node_modules/@smithy/middleware-endpoint/dist-cjs/index.js
var require_dist_cjs$20 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var getEndpointFromConfig = require_getEndpointFromConfig();
	var urlParser = require_dist_cjs$33();
	var core = (init_dist_es$1(), __toCommonJS(dist_es_exports$1));
	var utilMiddleware = require_dist_cjs$48();
	var middlewareSerde = require_dist_cjs$47();
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
		const [arn, partition, service, , , bucket] = bucketName.split(":");
		const isArn = arn === "arn" && bucketName.split(":").length >= 6;
		const isValidArn = Boolean(isArn && partition && service && bucket);
		if (isArn && !isValidArn) throw new Error(`Invalid ARN: ${bucketName} was an invalid ARN.`);
		return isValidArn;
	};
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
					const { protocol, hostname, port, path: path$1 } = endpoint;
					return `${protocol}//${hostname}${port ? ":" + port : ""}${path$1}`;
				}
			}
			return endpoint;
		};
		return configProvider;
	};
	const toEndpointV1 = (endpoint) => {
		if (typeof endpoint === "object") {
			if ("url" in endpoint) return urlParser.parseUrl(endpoint.url);
			return endpoint;
		}
		return urlParser.parseUrl(endpoint);
	};
	const getEndpointFromInstructions = async (commandInput, instructionsSupplier, clientConfig, context) => {
		if (!clientConfig.isCustomEndpoint) {
			let endpointFromConfig;
			if (clientConfig.serviceConfiguredEndpoint) endpointFromConfig = await clientConfig.serviceConfiguredEndpoint();
			else endpointFromConfig = await getEndpointFromConfig.getEndpointFromConfig(clientConfig.serviceId);
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
	const endpointMiddleware = ({ config, instructions }) => {
		return (next, context) => async (args) => {
			if (config.isCustomEndpoint) core.setFeature(context, "ENDPOINT_OVERRIDE", "N");
			const endpoint = await getEndpointFromInstructions(args.input, { getEndpointParameterInstructions() {
				return instructions;
			} }, { ...config }, context);
			context.endpointV2 = endpoint;
			context.authSchemes = endpoint.properties?.authSchemes;
			const authScheme = context.authSchemes?.[0];
			if (authScheme) {
				context["signing_region"] = authScheme.signingRegion;
				context["signing_service"] = authScheme.signingName;
				const httpAuthOption = utilMiddleware.getSmithyContext(context)?.selectedHttpAuthScheme?.httpAuthOption;
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
		toMiddleware: middlewareSerde.serializerMiddlewareOption.name
	};
	const getEndpointPlugin = (config, instructions) => ({ applyToStack: (clientStack) => {
		clientStack.addRelativeTo(endpointMiddleware({
			config,
			instructions
		}), endpointMiddlewareOptions);
	} });
	const resolveEndpointConfig = (input) => {
		const tls = input.tls ?? true;
		const { endpoint, useDualstackEndpoint, useFipsEndpoint } = input;
		const customEndpointProvider = endpoint != null ? async () => toEndpointV1(await utilMiddleware.normalizeProvider(endpoint)()) : void 0;
		const isCustomEndpoint = !!endpoint;
		const resolvedConfig = Object.assign(input, {
			endpoint: customEndpointProvider,
			tls,
			isCustomEndpoint,
			useDualstackEndpoint: utilMiddleware.normalizeProvider(useDualstackEndpoint ?? false),
			useFipsEndpoint: utilMiddleware.normalizeProvider(useFipsEndpoint ?? false)
		});
		let configuredEndpointPromise = void 0;
		resolvedConfig.serviceConfiguredEndpoint = async () => {
			if (input.serviceId && !configuredEndpointPromise) configuredEndpointPromise = getEndpointFromConfig.getEndpointFromConfig(input.serviceId);
			return configuredEndpointPromise;
		};
		return resolvedConfig;
	};
	const resolveEndpointRequiredConfig = (input) => {
		const { endpoint } = input;
		if (endpoint === void 0) input.endpoint = async () => {
			throw new Error("@smithy/middleware-endpoint: (default endpointRuleSet) endpoint is not set - you must configure an endpoint.");
		};
		return input;
	};
	exports.endpointMiddleware = endpointMiddleware;
	exports.endpointMiddlewareOptions = endpointMiddlewareOptions;
	exports.getEndpointFromInstructions = getEndpointFromInstructions;
	exports.getEndpointPlugin = getEndpointPlugin;
	exports.resolveEndpointConfig = resolveEndpointConfig;
	exports.resolveEndpointRequiredConfig = resolveEndpointRequiredConfig;
	exports.resolveParams = resolveParams;
	exports.toEndpointV1 = toEndpointV1;
}));

//#endregion
//#region node_modules/@smithy/service-error-classification/dist-cjs/index.js
var require_dist_cjs$19 = /* @__PURE__ */ __commonJSMin(((exports) => {
	const CLOCK_SKEW_ERROR_CODES = [
		"AuthFailure",
		"InvalidSignatureException",
		"RequestExpired",
		"RequestInTheFuture",
		"RequestTimeTooSkewed",
		"SignatureDoesNotMatch"
	];
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
	const isRetryableByTrait = (error$1) => error$1?.$retryable !== void 0;
	const isClockSkewError = (error$1) => CLOCK_SKEW_ERROR_CODES.includes(error$1.name);
	const isClockSkewCorrectedError = (error$1) => error$1.$metadata?.clockSkewCorrected;
	const isBrowserNetworkError = (error$1) => {
		const errorMessages = new Set([
			"Failed to fetch",
			"NetworkError when attempting to fetch resource",
			"The Internet connection appears to be offline",
			"Load failed",
			"Network request failed"
		]);
		if (!(error$1 && error$1 instanceof TypeError)) return false;
		return errorMessages.has(error$1.message);
	};
	const isThrottlingError = (error$1) => error$1.$metadata?.httpStatusCode === 429 || THROTTLING_ERROR_CODES.includes(error$1.name) || error$1.$retryable?.throttling == true;
	const isTransientError = (error$1, depth = 0) => isRetryableByTrait(error$1) || isClockSkewCorrectedError(error$1) || TRANSIENT_ERROR_CODES.includes(error$1.name) || NODEJS_TIMEOUT_ERROR_CODES.includes(error$1?.code || "") || NODEJS_NETWORK_ERROR_CODES.includes(error$1?.code || "") || TRANSIENT_ERROR_STATUS_CODES.includes(error$1.$metadata?.httpStatusCode || 0) || isBrowserNetworkError(error$1) || error$1.cause !== void 0 && depth <= 10 && isTransientError(error$1.cause, depth + 1);
	const isServerError = (error$1) => {
		if (error$1.$metadata?.httpStatusCode !== void 0) {
			const statusCode = error$1.$metadata.httpStatusCode;
			if (500 <= statusCode && statusCode <= 599 && !isTransientError(error$1)) return true;
			return false;
		}
		return false;
	};
	exports.isBrowserNetworkError = isBrowserNetworkError;
	exports.isClockSkewCorrectedError = isClockSkewCorrectedError;
	exports.isClockSkewError = isClockSkewError;
	exports.isRetryableByTrait = isRetryableByTrait;
	exports.isServerError = isServerError;
	exports.isThrottlingError = isThrottlingError;
	exports.isTransientError = isTransientError;
}));

//#endregion
//#region node_modules/@smithy/util-retry/dist-cjs/index.js
var require_dist_cjs$18 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var serviceErrorClassification = require_dist_cjs$19();
	exports.RETRY_MODES = void 0;
	(function(RETRY_MODES) {
		RETRY_MODES["STANDARD"] = "standard";
		RETRY_MODES["ADAPTIVE"] = "adaptive";
	})(exports.RETRY_MODES || (exports.RETRY_MODES = {}));
	const DEFAULT_MAX_ATTEMPTS = 3;
	const DEFAULT_RETRY_MODE = exports.RETRY_MODES.STANDARD;
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
			if (serviceErrorClassification.isThrottlingError(response)) {
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
			const t$3 = this.getCurrentTimeInSeconds();
			const timeBucket = Math.floor(t$3 * 2) / 2;
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
	const DEFAULT_RETRY_DELAY_BASE = 100;
	const MAXIMUM_RETRY_DELAY = 20 * 1e3;
	const THROTTLING_RETRY_DELAY_BASE = 500;
	const INITIAL_RETRY_TOKENS = 500;
	const RETRY_COST = 5;
	const TIMEOUT_RETRY_COST = 10;
	const NO_RETRY_INCREMENT = 1;
	const INVOCATION_ID_HEADER = "amz-sdk-invocation-id";
	const REQUEST_HEADER = "amz-sdk-request";
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
	var StandardRetryStrategy = class {
		maxAttempts;
		mode = exports.RETRY_MODES.STANDARD;
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
			} catch (error$1) {
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
	var AdaptiveRetryStrategy = class {
		maxAttemptsProvider;
		rateLimiter;
		standardRetryStrategy;
		mode = exports.RETRY_MODES.ADAPTIVE;
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
	var ConfiguredRetryStrategy = class extends StandardRetryStrategy {
		computeNextBackoffDelay;
		constructor(maxAttempts, computeNextBackoffDelay = DEFAULT_RETRY_DELAY_BASE) {
			super(typeof maxAttempts === "function" ? maxAttempts : async () => maxAttempts);
			if (typeof computeNextBackoffDelay === "number") this.computeNextBackoffDelay = () => computeNextBackoffDelay;
			else this.computeNextBackoffDelay = computeNextBackoffDelay;
		}
		async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
			const token = await super.refreshRetryTokenForRetry(tokenToRenew, errorInfo);
			token.getRetryDelay = () => this.computeNextBackoffDelay(token.getRetryCount());
			return token;
		}
	};
	exports.AdaptiveRetryStrategy = AdaptiveRetryStrategy;
	exports.ConfiguredRetryStrategy = ConfiguredRetryStrategy;
	exports.DEFAULT_MAX_ATTEMPTS = DEFAULT_MAX_ATTEMPTS;
	exports.DEFAULT_RETRY_DELAY_BASE = DEFAULT_RETRY_DELAY_BASE;
	exports.DEFAULT_RETRY_MODE = DEFAULT_RETRY_MODE;
	exports.DefaultRateLimiter = DefaultRateLimiter;
	exports.INITIAL_RETRY_TOKENS = INITIAL_RETRY_TOKENS;
	exports.INVOCATION_ID_HEADER = INVOCATION_ID_HEADER;
	exports.MAXIMUM_RETRY_DELAY = MAXIMUM_RETRY_DELAY;
	exports.NO_RETRY_INCREMENT = NO_RETRY_INCREMENT;
	exports.REQUEST_HEADER = REQUEST_HEADER;
	exports.RETRY_COST = RETRY_COST;
	exports.StandardRetryStrategy = StandardRetryStrategy;
	exports.THROTTLING_RETRY_DELAY_BASE = THROTTLING_RETRY_DELAY_BASE;
	exports.TIMEOUT_RETRY_COST = TIMEOUT_RETRY_COST;
}));

//#endregion
//#region node_modules/@smithy/middleware-retry/dist-cjs/isStreamingPayload/isStreamingPayload.js
var require_isStreamingPayload = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.isStreamingPayload = void 0;
	const stream_1 = require("stream");
	const isStreamingPayload = (request) => request?.body instanceof stream_1.Readable || typeof ReadableStream !== "undefined" && request?.body instanceof ReadableStream;
	exports.isStreamingPayload = isStreamingPayload;
}));

//#endregion
//#region node_modules/@smithy/middleware-retry/dist-cjs/index.js
var require_dist_cjs$17 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilRetry = require_dist_cjs$18();
	var protocolHttp = require_dist_cjs$52();
	var serviceErrorClassification = require_dist_cjs$19();
	var uuid = require_dist_cjs$36();
	var utilMiddleware = require_dist_cjs$48();
	var smithyClient = require_dist_cjs$28();
	var isStreamingPayload = require_isStreamingPayload();
	const getDefaultRetryQuota = (initialRetryTokens, options) => {
		const MAX_CAPACITY = initialRetryTokens;
		const noRetryIncrement = utilRetry.NO_RETRY_INCREMENT;
		const retryCost = utilRetry.RETRY_COST;
		const timeoutRetryCost = utilRetry.TIMEOUT_RETRY_COST;
		let availableCapacity = initialRetryTokens;
		const getCapacityAmount = (error$1) => error$1.name === "TimeoutError" ? timeoutRetryCost : retryCost;
		const hasRetryTokens = (error$1) => getCapacityAmount(error$1) <= availableCapacity;
		const retrieveRetryTokens = (error$1) => {
			if (!hasRetryTokens(error$1)) throw new Error("No retry token available");
			const capacityAmount = getCapacityAmount(error$1);
			availableCapacity -= capacityAmount;
			return capacityAmount;
		};
		const releaseRetryTokens = (capacityReleaseAmount) => {
			availableCapacity += capacityReleaseAmount ?? noRetryIncrement;
			availableCapacity = Math.min(availableCapacity, MAX_CAPACITY);
		};
		return Object.freeze({
			hasRetryTokens,
			retrieveRetryTokens,
			releaseRetryTokens
		});
	};
	const defaultDelayDecider = (delayBase, attempts) => Math.floor(Math.min(utilRetry.MAXIMUM_RETRY_DELAY, Math.random() * 2 ** attempts * delayBase));
	const defaultRetryDecider = (error$1) => {
		if (!error$1) return false;
		return serviceErrorClassification.isRetryableByTrait(error$1) || serviceErrorClassification.isClockSkewError(error$1) || serviceErrorClassification.isThrottlingError(error$1) || serviceErrorClassification.isTransientError(error$1);
	};
	const asSdkError = (error$1) => {
		if (error$1 instanceof Error) return error$1;
		if (error$1 instanceof Object) return Object.assign(/* @__PURE__ */ new Error(), error$1);
		if (typeof error$1 === "string") return new Error(error$1);
		return /* @__PURE__ */ new Error(`AWS SDK error wrapper for ${error$1}`);
	};
	var StandardRetryStrategy = class {
		maxAttemptsProvider;
		retryDecider;
		delayDecider;
		retryQuota;
		mode = utilRetry.RETRY_MODES.STANDARD;
		constructor(maxAttemptsProvider, options) {
			this.maxAttemptsProvider = maxAttemptsProvider;
			this.retryDecider = options?.retryDecider ?? defaultRetryDecider;
			this.delayDecider = options?.delayDecider ?? defaultDelayDecider;
			this.retryQuota = options?.retryQuota ?? getDefaultRetryQuota(utilRetry.INITIAL_RETRY_TOKENS);
		}
		shouldRetry(error$1, attempts, maxAttempts) {
			return attempts < maxAttempts && this.retryDecider(error$1) && this.retryQuota.hasRetryTokens(error$1);
		}
		async getMaxAttempts() {
			let maxAttempts;
			try {
				maxAttempts = await this.maxAttemptsProvider();
			} catch (error$1) {
				maxAttempts = utilRetry.DEFAULT_MAX_ATTEMPTS;
			}
			return maxAttempts;
		}
		async retry(next, args, options) {
			let retryTokenAmount;
			let attempts = 0;
			let totalDelay = 0;
			const maxAttempts = await this.getMaxAttempts();
			const { request } = args;
			if (protocolHttp.HttpRequest.isInstance(request)) request.headers[utilRetry.INVOCATION_ID_HEADER] = uuid.v4();
			while (true) try {
				if (protocolHttp.HttpRequest.isInstance(request)) request.headers[utilRetry.REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
				if (options?.beforeRequest) await options.beforeRequest();
				const { response, output } = await next(args);
				if (options?.afterRequest) options.afterRequest(response);
				this.retryQuota.releaseRetryTokens(retryTokenAmount);
				output.$metadata.attempts = attempts + 1;
				output.$metadata.totalRetryDelay = totalDelay;
				return {
					response,
					output
				};
			} catch (e$3) {
				const err = asSdkError(e$3);
				attempts++;
				if (this.shouldRetry(err, attempts, maxAttempts)) {
					retryTokenAmount = this.retryQuota.retrieveRetryTokens(err);
					const delayFromDecider = this.delayDecider(serviceErrorClassification.isThrottlingError(err) ? utilRetry.THROTTLING_RETRY_DELAY_BASE : utilRetry.DEFAULT_RETRY_DELAY_BASE, attempts);
					const delayFromResponse = getDelayFromRetryAfterHeader(err.$response);
					const delay = Math.max(delayFromResponse || 0, delayFromDecider);
					totalDelay += delay;
					await new Promise((resolve) => setTimeout(resolve, delay));
					continue;
				}
				if (!err.$metadata) err.$metadata = {};
				err.$metadata.attempts = attempts;
				err.$metadata.totalRetryDelay = totalDelay;
				throw err;
			}
		}
	};
	const getDelayFromRetryAfterHeader = (response) => {
		if (!protocolHttp.HttpResponse.isInstance(response)) return;
		const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
		if (!retryAfterHeaderName) return;
		const retryAfter = response.headers[retryAfterHeaderName];
		const retryAfterSeconds = Number(retryAfter);
		if (!Number.isNaN(retryAfterSeconds)) return retryAfterSeconds * 1e3;
		return new Date(retryAfter).getTime() - Date.now();
	};
	var AdaptiveRetryStrategy = class extends StandardRetryStrategy {
		rateLimiter;
		constructor(maxAttemptsProvider, options) {
			const { rateLimiter, ...superOptions } = options ?? {};
			super(maxAttemptsProvider, superOptions);
			this.rateLimiter = rateLimiter ?? new utilRetry.DefaultRateLimiter();
			this.mode = utilRetry.RETRY_MODES.ADAPTIVE;
		}
		async retry(next, args) {
			return super.retry(next, args, {
				beforeRequest: async () => {
					return this.rateLimiter.getSendToken();
				},
				afterRequest: (response) => {
					this.rateLimiter.updateClientSendingRate(response);
				}
			});
		}
	};
	const ENV_MAX_ATTEMPTS = "AWS_MAX_ATTEMPTS";
	const CONFIG_MAX_ATTEMPTS = "max_attempts";
	const NODE_MAX_ATTEMPT_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => {
			const value = env[ENV_MAX_ATTEMPTS];
			if (!value) return void 0;
			const maxAttempt = parseInt(value);
			if (Number.isNaN(maxAttempt)) throw new Error(`Environment variable ${ENV_MAX_ATTEMPTS} mast be a number, got "${value}"`);
			return maxAttempt;
		},
		configFileSelector: (profile) => {
			const value = profile[CONFIG_MAX_ATTEMPTS];
			if (!value) return void 0;
			const maxAttempt = parseInt(value);
			if (Number.isNaN(maxAttempt)) throw new Error(`Shared config file entry ${CONFIG_MAX_ATTEMPTS} mast be a number, got "${value}"`);
			return maxAttempt;
		},
		default: utilRetry.DEFAULT_MAX_ATTEMPTS
	};
	const resolveRetryConfig = (input) => {
		const { retryStrategy, retryMode: _retryMode, maxAttempts: _maxAttempts } = input;
		const maxAttempts = utilMiddleware.normalizeProvider(_maxAttempts ?? utilRetry.DEFAULT_MAX_ATTEMPTS);
		return Object.assign(input, {
			maxAttempts,
			retryStrategy: async () => {
				if (retryStrategy) return retryStrategy;
				if (await utilMiddleware.normalizeProvider(_retryMode)() === utilRetry.RETRY_MODES.ADAPTIVE) return new utilRetry.AdaptiveRetryStrategy(maxAttempts);
				return new utilRetry.StandardRetryStrategy(maxAttempts);
			}
		});
	};
	const ENV_RETRY_MODE = "AWS_RETRY_MODE";
	const CONFIG_RETRY_MODE = "retry_mode";
	const NODE_RETRY_MODE_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => env[ENV_RETRY_MODE],
		configFileSelector: (profile) => profile[CONFIG_RETRY_MODE],
		default: utilRetry.DEFAULT_RETRY_MODE
	};
	const omitRetryHeadersMiddleware = () => (next) => async (args) => {
		const { request } = args;
		if (protocolHttp.HttpRequest.isInstance(request)) {
			delete request.headers[utilRetry.INVOCATION_ID_HEADER];
			delete request.headers[utilRetry.REQUEST_HEADER];
		}
		return next(args);
	};
	const omitRetryHeadersMiddlewareOptions = {
		name: "omitRetryHeadersMiddleware",
		tags: [
			"RETRY",
			"HEADERS",
			"OMIT_RETRY_HEADERS"
		],
		relation: "before",
		toMiddleware: "awsAuthMiddleware",
		override: true
	};
	const getOmitRetryHeadersPlugin = (options) => ({ applyToStack: (clientStack) => {
		clientStack.addRelativeTo(omitRetryHeadersMiddleware(), omitRetryHeadersMiddlewareOptions);
	} });
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
			const isRequest = protocolHttp.HttpRequest.isInstance(request);
			if (isRequest) request.headers[utilRetry.INVOCATION_ID_HEADER] = uuid.v4();
			while (true) try {
				if (isRequest) request.headers[utilRetry.REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
				const { response, output } = await next(args);
				retryStrategy.recordSuccess(retryToken);
				output.$metadata.attempts = attempts + 1;
				output.$metadata.totalRetryDelay = totalRetryDelay;
				return {
					response,
					output
				};
			} catch (e$3) {
				const retryErrorInfo = getRetryErrorInfo(e$3);
				lastError = asSdkError(e$3);
				if (isRequest && isStreamingPayload.isStreamingPayload(request)) {
					(context.logger instanceof smithyClient.NoOpLogger ? console : context.logger)?.warn("An error was encountered in a non-retryable streaming request.");
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
	const getRetryErrorInfo = (error$1) => {
		const errorInfo = {
			error: error$1,
			errorType: getRetryErrorType(error$1)
		};
		const retryAfterHint = getRetryAfterHint(error$1.$response);
		if (retryAfterHint) errorInfo.retryAfterHint = retryAfterHint;
		return errorInfo;
	};
	const getRetryErrorType = (error$1) => {
		if (serviceErrorClassification.isThrottlingError(error$1)) return "THROTTLING";
		if (serviceErrorClassification.isTransientError(error$1)) return "TRANSIENT";
		if (serviceErrorClassification.isServerError(error$1)) return "SERVER_ERROR";
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
		if (!protocolHttp.HttpResponse.isInstance(response)) return;
		const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
		if (!retryAfterHeaderName) return;
		const retryAfter = response.headers[retryAfterHeaderName];
		const retryAfterSeconds = Number(retryAfter);
		if (!Number.isNaN(retryAfterSeconds)) return /* @__PURE__ */ new Date(retryAfterSeconds * 1e3);
		return new Date(retryAfter);
	};
	exports.AdaptiveRetryStrategy = AdaptiveRetryStrategy;
	exports.CONFIG_MAX_ATTEMPTS = CONFIG_MAX_ATTEMPTS;
	exports.CONFIG_RETRY_MODE = CONFIG_RETRY_MODE;
	exports.ENV_MAX_ATTEMPTS = ENV_MAX_ATTEMPTS;
	exports.ENV_RETRY_MODE = ENV_RETRY_MODE;
	exports.NODE_MAX_ATTEMPT_CONFIG_OPTIONS = NODE_MAX_ATTEMPT_CONFIG_OPTIONS;
	exports.NODE_RETRY_MODE_CONFIG_OPTIONS = NODE_RETRY_MODE_CONFIG_OPTIONS;
	exports.StandardRetryStrategy = StandardRetryStrategy;
	exports.defaultDelayDecider = defaultDelayDecider;
	exports.defaultRetryDecider = defaultRetryDecider;
	exports.getOmitRetryHeadersPlugin = getOmitRetryHeadersPlugin;
	exports.getRetryAfterHint = getRetryAfterHint;
	exports.getRetryPlugin = getRetryPlugin;
	exports.omitRetryHeadersMiddleware = omitRetryHeadersMiddleware;
	exports.omitRetryHeadersMiddlewareOptions = omitRetryHeadersMiddlewareOptions;
	exports.resolveRetryConfig = resolveRetryConfig;
	exports.retryMiddleware = retryMiddleware;
	exports.retryMiddlewareOptions = retryMiddlewareOptions;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/auth/httpAuthSchemeProvider.js
var require_httpAuthSchemeProvider$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.resolveHttpAuthSchemeConfig = exports.resolveStsAuthConfig = exports.defaultSTSHttpAuthSchemeProvider = exports.defaultSTSHttpAuthSchemeParametersProvider = void 0;
	const core_1 = (init_dist_es(), __toCommonJS(dist_es_exports));
	const util_middleware_1 = require_dist_cjs$48();
	const STSClient_1 = require_STSClient();
	const defaultSTSHttpAuthSchemeParametersProvider = async (config, context, input) => {
		return {
			operation: (0, util_middleware_1.getSmithyContext)(context).operation,
			region: await (0, util_middleware_1.normalizeProvider)(config.region)() || (() => {
				throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
			})()
		};
	};
	exports.defaultSTSHttpAuthSchemeParametersProvider = defaultSTSHttpAuthSchemeParametersProvider;
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
	exports.defaultSTSHttpAuthSchemeProvider = defaultSTSHttpAuthSchemeProvider;
	const resolveStsAuthConfig = (input) => Object.assign(input, { stsClientCtor: STSClient_1.STSClient });
	exports.resolveStsAuthConfig = resolveStsAuthConfig;
	const resolveHttpAuthSchemeConfig = (config) => {
		const config_0 = (0, exports.resolveStsAuthConfig)(config);
		const config_1 = (0, core_1.resolveAwsSdkSigV4Config)(config_0);
		return Object.assign(config_1, { authSchemePreference: (0, util_middleware_1.normalizeProvider)(config.authSchemePreference ?? []) });
	};
	exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/EndpointParameters.js
var require_EndpointParameters = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.commonParams = exports.resolveClientEndpointParameters = void 0;
	const resolveClientEndpointParameters = (options) => {
		return Object.assign(options, {
			useDualstackEndpoint: options.useDualstackEndpoint ?? false,
			useFipsEndpoint: options.useFipsEndpoint ?? false,
			useGlobalEndpoint: options.useGlobalEndpoint ?? false,
			defaultSigningName: "sts"
		});
	};
	exports.resolveClientEndpointParameters = resolveClientEndpointParameters;
	exports.commonParams = {
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
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/package.json
var require_package$1 = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = {
		"name": "@aws-sdk/client-sts",
		"description": "AWS SDK for JavaScript Sts Client for Node.js, Browser and React Native",
		"version": "3.958.0",
		"scripts": {
			"build": "concurrently 'yarn:build:types' 'yarn:build:es' && yarn build:cjs",
			"build:cjs": "node ../../scripts/compilation/inline client-sts",
			"build:es": "tsc -p tsconfig.es.json",
			"build:include:deps": "yarn g:turbo run build -F=\"$npm_package_name\"",
			"build:types": "rimraf ./dist-types tsconfig.types.tsbuildinfo && tsc -p tsconfig.types.json",
			"build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
			"clean": "rimraf ./dist-* && rimraf *.tsbuildinfo",
			"extract:docs": "api-extractor run --local",
			"generate:client": "node ../../scripts/generate-clients/single-service --solo sts",
			"test": "yarn g:vitest run",
			"test:e2e": "yarn g:vitest run -c vitest.config.e2e.mts --mode development",
			"test:e2e:watch": "yarn g:vitest watch -c vitest.config.e2e.mts",
			"test:index": "tsc --noEmit ./test/index-types.ts && node ./test/index-objects.spec.mjs",
			"test:watch": "yarn g:vitest watch"
		},
		"main": "./dist-cjs/index.js",
		"types": "./dist-types/index.d.ts",
		"module": "./dist-es/index.js",
		"sideEffects": false,
		"dependencies": {
			"@aws-crypto/sha256-browser": "5.2.0",
			"@aws-crypto/sha256-js": "5.2.0",
			"@aws-sdk/core": "3.957.0",
			"@aws-sdk/credential-provider-node": "3.958.0",
			"@aws-sdk/middleware-host-header": "3.957.0",
			"@aws-sdk/middleware-logger": "3.957.0",
			"@aws-sdk/middleware-recursion-detection": "3.957.0",
			"@aws-sdk/middleware-user-agent": "3.957.0",
			"@aws-sdk/region-config-resolver": "3.957.0",
			"@aws-sdk/types": "3.957.0",
			"@aws-sdk/util-endpoints": "3.957.0",
			"@aws-sdk/util-user-agent-browser": "3.957.0",
			"@aws-sdk/util-user-agent-node": "3.957.0",
			"@smithy/config-resolver": "^4.4.5",
			"@smithy/core": "^3.20.0",
			"@smithy/fetch-http-handler": "^5.3.8",
			"@smithy/hash-node": "^4.2.7",
			"@smithy/invalid-dependency": "^4.2.7",
			"@smithy/middleware-content-length": "^4.2.7",
			"@smithy/middleware-endpoint": "^4.4.1",
			"@smithy/middleware-retry": "^4.4.17",
			"@smithy/middleware-serde": "^4.2.8",
			"@smithy/middleware-stack": "^4.2.7",
			"@smithy/node-config-provider": "^4.3.7",
			"@smithy/node-http-handler": "^4.4.7",
			"@smithy/protocol-http": "^5.3.7",
			"@smithy/smithy-client": "^4.10.2",
			"@smithy/types": "^4.11.0",
			"@smithy/url-parser": "^4.2.7",
			"@smithy/util-base64": "^4.3.0",
			"@smithy/util-body-length-browser": "^4.2.0",
			"@smithy/util-body-length-node": "^4.2.1",
			"@smithy/util-defaults-mode-browser": "^4.3.16",
			"@smithy/util-defaults-mode-node": "^4.2.19",
			"@smithy/util-endpoints": "^3.2.7",
			"@smithy/util-middleware": "^4.2.7",
			"@smithy/util-retry": "^4.2.7",
			"@smithy/util-utf8": "^4.2.0",
			"tslib": "^2.6.2"
		},
		"devDependencies": {
			"@tsconfig/node18": "18.2.4",
			"@types/node": "^18.19.69",
			"concurrently": "7.0.0",
			"downlevel-dts": "0.10.1",
			"rimraf": "3.0.2",
			"typescript": "~5.8.3"
		},
		"engines": { "node": ">=18.0.0" },
		"typesVersions": { "<4.0": { "dist-types/*": ["dist-types/ts3.4/*"] } },
		"files": ["dist-*/**"],
		"author": {
			"name": "AWS SDK for JavaScript Team",
			"url": "https://aws.amazon.com/javascript/"
		},
		"license": "Apache-2.0",
		"browser": { "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser" },
		"react-native": { "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native" },
		"homepage": "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sts",
		"repository": {
			"type": "git",
			"url": "https://github.com/aws/aws-sdk-js-v3.git",
			"directory": "clients/client-sts"
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-env/dist-cjs/index.js
var require_dist_cjs$16 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var client = (init_client(), __toCommonJS(client_exports));
	var propertyProvider = require_dist_cjs$31();
	const ENV_KEY = "AWS_ACCESS_KEY_ID";
	const ENV_SECRET = "AWS_SECRET_ACCESS_KEY";
	const ENV_SESSION = "AWS_SESSION_TOKEN";
	const ENV_EXPIRATION = "AWS_CREDENTIAL_EXPIRATION";
	const ENV_CREDENTIAL_SCOPE = "AWS_CREDENTIAL_SCOPE";
	const ENV_ACCOUNT_ID = "AWS_ACCOUNT_ID";
	const fromEnv = (init) => async () => {
		init?.logger?.debug("@aws-sdk/credential-provider-env - fromEnv");
		const accessKeyId = process.env[ENV_KEY];
		const secretAccessKey = process.env[ENV_SECRET];
		const sessionToken = process.env[ENV_SESSION];
		const expiry = process.env[ENV_EXPIRATION];
		const credentialScope = process.env[ENV_CREDENTIAL_SCOPE];
		const accountId = process.env[ENV_ACCOUNT_ID];
		if (accessKeyId && secretAccessKey) {
			const credentials = {
				accessKeyId,
				secretAccessKey,
				...sessionToken && { sessionToken },
				...expiry && { expiration: new Date(expiry) },
				...credentialScope && { credentialScope },
				...accountId && { accountId }
			};
			client.setCredentialFeature(credentials, "CREDENTIALS_ENV_VARS", "g");
			return credentials;
		}
		throw new propertyProvider.CredentialsProviderError("Unable to find environment variable credentials.", { logger: init?.logger });
	};
	exports.ENV_ACCOUNT_ID = ENV_ACCOUNT_ID;
	exports.ENV_CREDENTIAL_SCOPE = ENV_CREDENTIAL_SCOPE;
	exports.ENV_EXPIRATION = ENV_EXPIRATION;
	exports.ENV_KEY = ENV_KEY;
	exports.ENV_SECRET = ENV_SECRET;
	exports.ENV_SESSION = ENV_SESSION;
	exports.fromEnv = fromEnv;
}));

//#endregion
//#region node_modules/@smithy/credential-provider-imds/dist-cjs/index.js
var require_dist_cjs$15 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var propertyProvider = require_dist_cjs$31();
	var url = require("url");
	var buffer$1 = require("buffer");
	var http = require("http");
	var nodeConfigProvider = require_dist_cjs$21();
	var urlParser = require_dist_cjs$33();
	function httpRequest(options) {
		return new Promise((resolve, reject) => {
			const req = http.request({
				method: "GET",
				...options,
				hostname: options.hostname?.replace(/^\[(.+)\]$/, "$1")
			});
			req.on("error", (err) => {
				reject(Object.assign(new propertyProvider.ProviderError("Unable to connect to instance metadata service"), err));
				req.destroy();
			});
			req.on("timeout", () => {
				reject(new propertyProvider.ProviderError("TimeoutError from instance metadata service"));
				req.destroy();
			});
			req.on("response", (res) => {
				const { statusCode = 400 } = res;
				if (statusCode < 200 || 300 <= statusCode) {
					reject(Object.assign(new propertyProvider.ProviderError("Error response received from instance metadata service"), { statusCode }));
					req.destroy();
				}
				const chunks = [];
				res.on("data", (chunk) => {
					chunks.push(chunk);
				});
				res.on("end", () => {
					resolve(buffer$1.Buffer.concat(chunks));
					req.destroy();
				});
			});
			req.end();
		});
	}
	const isImdsCredentials = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.AccessKeyId === "string" && typeof arg.SecretAccessKey === "string" && typeof arg.Token === "string" && typeof arg.Expiration === "string";
	const fromImdsCredentials = (creds) => ({
		accessKeyId: creds.AccessKeyId,
		secretAccessKey: creds.SecretAccessKey,
		sessionToken: creds.Token,
		expiration: new Date(creds.Expiration),
		...creds.AccountId && { accountId: creds.AccountId }
	});
	const DEFAULT_TIMEOUT = 1e3;
	const DEFAULT_MAX_RETRIES = 0;
	const providerConfigFromInit = ({ maxRetries = DEFAULT_MAX_RETRIES, timeout = DEFAULT_TIMEOUT }) => ({
		maxRetries,
		timeout
	});
	const retry = (toRetry, maxRetries) => {
		let promise = toRetry();
		for (let i$3 = 0; i$3 < maxRetries; i$3++) promise = promise.catch(toRetry);
		return promise;
	};
	const ENV_CMDS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
	const ENV_CMDS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
	const ENV_CMDS_AUTH_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
	const fromContainerMetadata = (init = {}) => {
		const { timeout, maxRetries } = providerConfigFromInit(init);
		return () => retry(async () => {
			const requestOptions = await getCmdsUri({ logger: init.logger });
			const credsResponse = JSON.parse(await requestFromEcsImds(timeout, requestOptions));
			if (!isImdsCredentials(credsResponse)) throw new propertyProvider.CredentialsProviderError("Invalid response received from instance metadata service.", { logger: init.logger });
			return fromImdsCredentials(credsResponse);
		}, maxRetries);
	};
	const requestFromEcsImds = async (timeout, options) => {
		if (process.env[ENV_CMDS_AUTH_TOKEN]) options.headers = {
			...options.headers,
			Authorization: process.env[ENV_CMDS_AUTH_TOKEN]
		};
		return (await httpRequest({
			...options,
			timeout
		})).toString();
	};
	const CMDS_IP = "169.254.170.2";
	const GREENGRASS_HOSTS = {
		localhost: true,
		"127.0.0.1": true
	};
	const GREENGRASS_PROTOCOLS = {
		"http:": true,
		"https:": true
	};
	const getCmdsUri = async ({ logger: logger$1 }) => {
		if (process.env[ENV_CMDS_RELATIVE_URI]) return {
			hostname: CMDS_IP,
			path: process.env[ENV_CMDS_RELATIVE_URI]
		};
		if (process.env[ENV_CMDS_FULL_URI]) {
			const parsed = url.parse(process.env[ENV_CMDS_FULL_URI]);
			if (!parsed.hostname || !(parsed.hostname in GREENGRASS_HOSTS)) throw new propertyProvider.CredentialsProviderError(`${parsed.hostname} is not a valid container metadata service hostname`, {
				tryNextLink: false,
				logger: logger$1
			});
			if (!parsed.protocol || !(parsed.protocol in GREENGRASS_PROTOCOLS)) throw new propertyProvider.CredentialsProviderError(`${parsed.protocol} is not a valid container metadata service protocol`, {
				tryNextLink: false,
				logger: logger$1
			});
			return {
				...parsed,
				port: parsed.port ? parseInt(parsed.port, 10) : void 0
			};
		}
		throw new propertyProvider.CredentialsProviderError(`The container metadata credential provider cannot be used unless the ${ENV_CMDS_RELATIVE_URI} or ${ENV_CMDS_FULL_URI} environment variable is set`, {
			tryNextLink: false,
			logger: logger$1
		});
	};
	var InstanceMetadataV1FallbackError = class InstanceMetadataV1FallbackError extends propertyProvider.CredentialsProviderError {
		tryNextLink;
		name = "InstanceMetadataV1FallbackError";
		constructor(message, tryNextLink = true) {
			super(message, tryNextLink);
			this.tryNextLink = tryNextLink;
			Object.setPrototypeOf(this, InstanceMetadataV1FallbackError.prototype);
		}
	};
	exports.Endpoint = void 0;
	(function(Endpoint) {
		Endpoint["IPv4"] = "http://169.254.169.254";
		Endpoint["IPv6"] = "http://[fd00:ec2::254]";
	})(exports.Endpoint || (exports.Endpoint = {}));
	const ENV_ENDPOINT_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT";
	const CONFIG_ENDPOINT_NAME = "ec2_metadata_service_endpoint";
	const ENDPOINT_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => env[ENV_ENDPOINT_NAME],
		configFileSelector: (profile) => profile[CONFIG_ENDPOINT_NAME],
		default: void 0
	};
	var EndpointMode;
	(function(EndpointMode) {
		EndpointMode["IPv4"] = "IPv4";
		EndpointMode["IPv6"] = "IPv6";
	})(EndpointMode || (EndpointMode = {}));
	const ENV_ENDPOINT_MODE_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE";
	const CONFIG_ENDPOINT_MODE_NAME = "ec2_metadata_service_endpoint_mode";
	const ENDPOINT_MODE_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => env[ENV_ENDPOINT_MODE_NAME],
		configFileSelector: (profile) => profile[CONFIG_ENDPOINT_MODE_NAME],
		default: EndpointMode.IPv4
	};
	const getInstanceMetadataEndpoint = async () => urlParser.parseUrl(await getFromEndpointConfig() || await getFromEndpointModeConfig());
	const getFromEndpointConfig = async () => nodeConfigProvider.loadConfig(ENDPOINT_CONFIG_OPTIONS)();
	const getFromEndpointModeConfig = async () => {
		const endpointMode = await nodeConfigProvider.loadConfig(ENDPOINT_MODE_CONFIG_OPTIONS)();
		switch (endpointMode) {
			case EndpointMode.IPv4: return exports.Endpoint.IPv4;
			case EndpointMode.IPv6: return exports.Endpoint.IPv6;
			default: throw new Error(`Unsupported endpoint mode: ${endpointMode}. Select from ${Object.values(EndpointMode)}`);
		}
	};
	const STATIC_STABILITY_REFRESH_INTERVAL_SECONDS = 300;
	const STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS = 300;
	const getExtendedInstanceMetadataCredentials = (credentials, logger$1) => {
		const refreshInterval = STATIC_STABILITY_REFRESH_INTERVAL_SECONDS + Math.floor(Math.random() * STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS);
		const newExpiration = new Date(Date.now() + refreshInterval * 1e3);
		logger$1.warn(`Attempting credential expiration extension due to a credential service availability issue. A refresh of these credentials will be attempted after ${new Date(newExpiration)}.\nFor more information, please visit: https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html`);
		const originalExpiration = credentials.originalExpiration ?? credentials.expiration;
		return {
			...credentials,
			...originalExpiration ? { originalExpiration } : {},
			expiration: newExpiration
		};
	};
	const staticStabilityProvider = (provider, options = {}) => {
		const logger$1 = options?.logger || console;
		let pastCredentials;
		return async () => {
			let credentials;
			try {
				credentials = await provider();
				if (credentials.expiration && credentials.expiration.getTime() < Date.now()) credentials = getExtendedInstanceMetadataCredentials(credentials, logger$1);
			} catch (e$3) {
				if (pastCredentials) {
					logger$1.warn("Credential renew failed: ", e$3);
					credentials = getExtendedInstanceMetadataCredentials(pastCredentials, logger$1);
				} else throw e$3;
			}
			pastCredentials = credentials;
			return credentials;
		};
	};
	const IMDS_PATH = "/latest/meta-data/iam/security-credentials/";
	const IMDS_TOKEN_PATH = "/latest/api/token";
	const AWS_EC2_METADATA_V1_DISABLED = "AWS_EC2_METADATA_V1_DISABLED";
	const PROFILE_AWS_EC2_METADATA_V1_DISABLED = "ec2_metadata_v1_disabled";
	const X_AWS_EC2_METADATA_TOKEN = "x-aws-ec2-metadata-token";
	const fromInstanceMetadata = (init = {}) => staticStabilityProvider(getInstanceMetadataProvider(init), { logger: init.logger });
	const getInstanceMetadataProvider = (init = {}) => {
		let disableFetchToken = false;
		const { logger: logger$1, profile } = init;
		const { timeout, maxRetries } = providerConfigFromInit(init);
		const getCredentials = async (maxRetries$1, options) => {
			if (disableFetchToken || options.headers?.[X_AWS_EC2_METADATA_TOKEN] == null) {
				let fallbackBlockedFromProfile = false;
				let fallbackBlockedFromProcessEnv = false;
				const configValue = await nodeConfigProvider.loadConfig({
					environmentVariableSelector: (env) => {
						const envValue = env[AWS_EC2_METADATA_V1_DISABLED];
						fallbackBlockedFromProcessEnv = !!envValue && envValue !== "false";
						if (envValue === void 0) throw new propertyProvider.CredentialsProviderError(`${AWS_EC2_METADATA_V1_DISABLED} not set in env, checking config file next.`, { logger: init.logger });
						return fallbackBlockedFromProcessEnv;
					},
					configFileSelector: (profile$1) => {
						const profileValue = profile$1[PROFILE_AWS_EC2_METADATA_V1_DISABLED];
						fallbackBlockedFromProfile = !!profileValue && profileValue !== "false";
						return fallbackBlockedFromProfile;
					},
					default: false
				}, { profile })();
				if (init.ec2MetadataV1Disabled || configValue) {
					const causes = [];
					if (init.ec2MetadataV1Disabled) causes.push("credential provider initialization (runtime option ec2MetadataV1Disabled)");
					if (fallbackBlockedFromProfile) causes.push(`config file profile (${PROFILE_AWS_EC2_METADATA_V1_DISABLED})`);
					if (fallbackBlockedFromProcessEnv) causes.push(`process environment variable (${AWS_EC2_METADATA_V1_DISABLED})`);
					throw new InstanceMetadataV1FallbackError(`AWS EC2 Metadata v1 fallback has been blocked by AWS SDK configuration in the following: [${causes.join(", ")}].`);
				}
			}
			const imdsProfile = (await retry(async () => {
				let profile$1;
				try {
					profile$1 = await getProfile(options);
				} catch (err) {
					if (err.statusCode === 401) disableFetchToken = false;
					throw err;
				}
				return profile$1;
			}, maxRetries$1)).trim();
			return retry(async () => {
				let creds;
				try {
					creds = await getCredentialsFromProfile(imdsProfile, options, init);
				} catch (err) {
					if (err.statusCode === 401) disableFetchToken = false;
					throw err;
				}
				return creds;
			}, maxRetries$1);
		};
		return async () => {
			const endpoint = await getInstanceMetadataEndpoint();
			if (disableFetchToken) {
				logger$1?.debug("AWS SDK Instance Metadata", "using v1 fallback (no token fetch)");
				return getCredentials(maxRetries, {
					...endpoint,
					timeout
				});
			} else {
				let token;
				try {
					token = (await getMetadataToken({
						...endpoint,
						timeout
					})).toString();
				} catch (error$1) {
					if (error$1?.statusCode === 400) throw Object.assign(error$1, { message: "EC2 Metadata token request returned error" });
					else if (error$1.message === "TimeoutError" || [
						403,
						404,
						405
					].includes(error$1.statusCode)) disableFetchToken = true;
					logger$1?.debug("AWS SDK Instance Metadata", "using v1 fallback (initial)");
					return getCredentials(maxRetries, {
						...endpoint,
						timeout
					});
				}
				return getCredentials(maxRetries, {
					...endpoint,
					headers: { [X_AWS_EC2_METADATA_TOKEN]: token },
					timeout
				});
			}
		};
	};
	const getMetadataToken = async (options) => httpRequest({
		...options,
		path: IMDS_TOKEN_PATH,
		method: "PUT",
		headers: { "x-aws-ec2-metadata-token-ttl-seconds": "21600" }
	});
	const getProfile = async (options) => (await httpRequest({
		...options,
		path: IMDS_PATH
	})).toString();
	const getCredentialsFromProfile = async (profile, options, init) => {
		const credentialsResponse = JSON.parse((await httpRequest({
			...options,
			path: IMDS_PATH + profile
		})).toString());
		if (!isImdsCredentials(credentialsResponse)) throw new propertyProvider.CredentialsProviderError("Invalid response received from instance metadata service.", { logger: init.logger });
		return fromImdsCredentials(credentialsResponse);
	};
	exports.DEFAULT_MAX_RETRIES = DEFAULT_MAX_RETRIES;
	exports.DEFAULT_TIMEOUT = DEFAULT_TIMEOUT;
	exports.ENV_CMDS_AUTH_TOKEN = ENV_CMDS_AUTH_TOKEN;
	exports.ENV_CMDS_FULL_URI = ENV_CMDS_FULL_URI;
	exports.ENV_CMDS_RELATIVE_URI = ENV_CMDS_RELATIVE_URI;
	exports.fromContainerMetadata = fromContainerMetadata;
	exports.fromInstanceMetadata = fromInstanceMetadata;
	exports.getInstanceMetadataEndpoint = getInstanceMetadataEndpoint;
	exports.httpRequest = httpRequest;
	exports.providerConfigFromInit = providerConfigFromInit;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/checkUrl.js
var require_checkUrl = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.checkUrl = void 0;
	const property_provider_1 = require_dist_cjs$31();
	const ECS_CONTAINER_HOST = "169.254.170.2";
	const EKS_CONTAINER_HOST_IPv4 = "169.254.170.23";
	const EKS_CONTAINER_HOST_IPv6 = "[fd00:ec2::23]";
	const checkUrl = (url$1, logger$1) => {
		if (url$1.protocol === "https:") return;
		if (url$1.hostname === ECS_CONTAINER_HOST || url$1.hostname === EKS_CONTAINER_HOST_IPv4 || url$1.hostname === EKS_CONTAINER_HOST_IPv6) return;
		if (url$1.hostname.includes("[")) {
			if (url$1.hostname === "[::1]" || url$1.hostname === "[0000:0000:0000:0000:0000:0000:0000:0001]") return;
		} else {
			if (url$1.hostname === "localhost") return;
			const ipComponents = url$1.hostname.split(".");
			const inRange = (component) => {
				const num = parseInt(component, 10);
				return 0 <= num && num <= 255;
			};
			if (ipComponents[0] === "127" && inRange(ipComponents[1]) && inRange(ipComponents[2]) && inRange(ipComponents[3]) && ipComponents.length === 4) return;
		}
		throw new property_provider_1.CredentialsProviderError(`URL not accepted. It must either be HTTPS or match one of the following:
  - loopback CIDR 127.0.0.0/8 or [::1/128]
  - ECS container host 169.254.170.2
  - EKS container host 169.254.170.23 or [fd00:ec2::23]`, { logger: logger$1 });
	};
	exports.checkUrl = checkUrl;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/requestHelpers.js
var require_requestHelpers = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.createGetRequest = createGetRequest;
	exports.getCredentials = getCredentials;
	const property_provider_1 = require_dist_cjs$31();
	const protocol_http_1 = require_dist_cjs$52();
	const smithy_client_1 = require_dist_cjs$28();
	const util_stream_1 = require_dist_cjs$37();
	function createGetRequest(url$1) {
		return new protocol_http_1.HttpRequest({
			protocol: url$1.protocol,
			hostname: url$1.hostname,
			port: Number(url$1.port),
			path: url$1.pathname,
			query: Array.from(url$1.searchParams.entries()).reduce((acc, [k$3, v$3]) => {
				acc[k$3] = v$3;
				return acc;
			}, {}),
			fragment: url$1.hash
		});
	}
	async function getCredentials(response, logger$1) {
		const str = await (0, util_stream_1.sdkStreamMixin)(response.body).transformToString();
		if (response.statusCode === 200) {
			const parsed = JSON.parse(str);
			if (typeof parsed.AccessKeyId !== "string" || typeof parsed.SecretAccessKey !== "string" || typeof parsed.Token !== "string" || typeof parsed.Expiration !== "string") throw new property_provider_1.CredentialsProviderError("HTTP credential provider response not of the required format, an object matching: { AccessKeyId: string, SecretAccessKey: string, Token: string, Expiration: string(rfc3339) }", { logger: logger$1 });
			return {
				accessKeyId: parsed.AccessKeyId,
				secretAccessKey: parsed.SecretAccessKey,
				sessionToken: parsed.Token,
				expiration: (0, smithy_client_1.parseRfc3339DateTime)(parsed.Expiration)
			};
		}
		if (response.statusCode >= 400 && response.statusCode < 500) {
			let parsedBody = {};
			try {
				parsedBody = JSON.parse(str);
			} catch (e$3) {}
			throw Object.assign(new property_provider_1.CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger: logger$1 }), {
				Code: parsedBody.Code,
				Message: parsedBody.Message
			});
		}
		throw new property_provider_1.CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger: logger$1 });
	}
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/retry-wrapper.js
var require_retry_wrapper = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.retryWrapper = void 0;
	const retryWrapper = (toRetry, maxRetries, delayMs) => {
		return async () => {
			for (let i$3 = 0; i$3 < maxRetries; ++i$3) try {
				return await toRetry();
			} catch (e$3) {
				await new Promise((resolve) => setTimeout(resolve, delayMs));
			}
			return await toRetry();
		};
	};
	exports.retryWrapper = retryWrapper;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/fromHttp.js
var require_fromHttp = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.fromHttp = void 0;
	const tslib_1 = (init_tslib_es6(), __toCommonJS(tslib_es6_exports));
	const client_1 = (init_client(), __toCommonJS(client_exports));
	const node_http_handler_1 = require_dist_cjs$40();
	const property_provider_1 = require_dist_cjs$31();
	const promises_1 = tslib_1.__importDefault(require("fs/promises"));
	const checkUrl_1 = require_checkUrl();
	const requestHelpers_1 = require_requestHelpers();
	const retry_wrapper_1 = require_retry_wrapper();
	const AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
	const DEFAULT_LINK_LOCAL_HOST = "http://169.254.170.2";
	const AWS_CONTAINER_CREDENTIALS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
	const AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";
	const AWS_CONTAINER_AUTHORIZATION_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
	const fromHttp = (options = {}) => {
		options.logger?.debug("@aws-sdk/credential-provider-http - fromHttp");
		let host;
		const relative = options.awsContainerCredentialsRelativeUri ?? process.env[AWS_CONTAINER_CREDENTIALS_RELATIVE_URI];
		const full = options.awsContainerCredentialsFullUri ?? process.env[AWS_CONTAINER_CREDENTIALS_FULL_URI];
		const token = options.awsContainerAuthorizationToken ?? process.env[AWS_CONTAINER_AUTHORIZATION_TOKEN];
		const tokenFile = options.awsContainerAuthorizationTokenFile ?? process.env[AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE];
		const warn = options.logger?.constructor?.name === "NoOpLogger" || !options.logger?.warn ? console.warn : options.logger.warn.bind(options.logger);
		if (relative && full) {
			warn("@aws-sdk/credential-provider-http: you have set both awsContainerCredentialsRelativeUri and awsContainerCredentialsFullUri.");
			warn("awsContainerCredentialsFullUri will take precedence.");
		}
		if (token && tokenFile) {
			warn("@aws-sdk/credential-provider-http: you have set both awsContainerAuthorizationToken and awsContainerAuthorizationTokenFile.");
			warn("awsContainerAuthorizationToken will take precedence.");
		}
		if (full) host = full;
		else if (relative) host = `${DEFAULT_LINK_LOCAL_HOST}${relative}`;
		else throw new property_provider_1.CredentialsProviderError(`No HTTP credential provider host provided.
Set AWS_CONTAINER_CREDENTIALS_FULL_URI or AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.`, { logger: options.logger });
		const url$1 = new URL(host);
		(0, checkUrl_1.checkUrl)(url$1, options.logger);
		const requestHandler = node_http_handler_1.NodeHttpHandler.create({
			requestTimeout: options.timeout ?? 1e3,
			connectionTimeout: options.timeout ?? 1e3
		});
		return (0, retry_wrapper_1.retryWrapper)(async () => {
			const request = (0, requestHelpers_1.createGetRequest)(url$1);
			if (token) request.headers.Authorization = token;
			else if (tokenFile) request.headers.Authorization = (await promises_1.default.readFile(tokenFile)).toString();
			try {
				const result = await requestHandler.handle(request);
				return (0, requestHelpers_1.getCredentials)(result.response).then((creds) => (0, client_1.setCredentialFeature)(creds, "CREDENTIALS_HTTP", "z"));
			} catch (e$3) {
				throw new property_provider_1.CredentialsProviderError(String(e$3), { logger: options.logger });
			}
		}, options.maxRetries ?? 3, options.timeout ?? 1e3);
	};
	exports.fromHttp = fromHttp;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-http/dist-cjs/index.js
var require_dist_cjs$14 = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.fromHttp = void 0;
	var fromHttp_1 = require_fromHttp();
	Object.defineProperty(exports, "fromHttp", {
		enumerable: true,
		get: function() {
			return fromHttp_1.fromHttp;
		}
	});
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption$2(authParameters) {
	return {
		schemeId: "aws.auth#sigv4",
		signingProperties: {
			name: "sso-oauth",
			region: authParameters.region
		},
		propertiesExtractor: (config, context) => ({ signingProperties: {
			config,
			context
		} })
	};
}
function createSmithyApiNoAuthHttpAuthOption$2(authParameters) {
	return { schemeId: "smithy.api#noAuth" };
}
var import_dist_cjs$102, defaultSSOOIDCHttpAuthSchemeParametersProvider, defaultSSOOIDCHttpAuthSchemeProvider, resolveHttpAuthSchemeConfig$2;
var init_httpAuthSchemeProvider$2 = __esmMin((() => {
	init_dist_es();
	import_dist_cjs$102 = require_dist_cjs$48();
	defaultSSOOIDCHttpAuthSchemeParametersProvider = async (config, context, input) => {
		return {
			operation: (0, import_dist_cjs$102.getSmithyContext)(context).operation,
			region: await (0, import_dist_cjs$102.normalizeProvider)(config.region)() || (() => {
				throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
			})()
		};
	};
	defaultSSOOIDCHttpAuthSchemeProvider = (authParameters) => {
		const options = [];
		switch (authParameters.operation) {
			case "CreateToken":
				options.push(createSmithyApiNoAuthHttpAuthOption$2(authParameters));
				break;
			default: options.push(createAwsAuthSigv4HttpAuthOption$2(authParameters));
		}
		return options;
	};
	resolveHttpAuthSchemeConfig$2 = (config) => {
		const config_0 = resolveAwsSdkSigV4Config(config);
		return Object.assign(config_0, { authSchemePreference: (0, import_dist_cjs$102.normalizeProvider)(config.authSchemePreference ?? []) });
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/EndpointParameters.js
var resolveClientEndpointParameters$2, commonParams$2;
var init_EndpointParameters$2 = __esmMin((() => {
	resolveClientEndpointParameters$2 = (options) => {
		return Object.assign(options, {
			useDualstackEndpoint: options.useDualstackEndpoint ?? false,
			useFipsEndpoint: options.useFipsEndpoint ?? false,
			defaultSigningName: "sso-oauth"
		});
	};
	commonParams$2 = {
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
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/package.json
var version = "3.958.0";

//#endregion
//#region node_modules/@aws-sdk/util-user-agent-node/dist-cjs/index.js
var require_dist_cjs$13 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var os = require("os");
	var process$1 = require("process");
	var middlewareUserAgent = require_dist_cjs$26();
	const crtAvailability = { isCrtAvailable: false };
	const isCrtAvailable = () => {
		if (crtAvailability.isCrtAvailable) return ["md/crt-avail"];
		return null;
	};
	const createDefaultUserAgentProvider = ({ serviceId, clientVersion }) => {
		return async (config) => {
			const sections = [
				["aws-sdk-js", clientVersion],
				["ua", "2.1"],
				[`os/${os.platform()}`, os.release()],
				["lang/js"],
				["md/nodejs", `${process$1.versions.node}`]
			];
			const crtAvailable = isCrtAvailable();
			if (crtAvailable) sections.push(crtAvailable);
			if (serviceId) sections.push([`api/${serviceId}`, clientVersion]);
			if (process$1.env.AWS_EXECUTION_ENV) sections.push([`exec-env/${process$1.env.AWS_EXECUTION_ENV}`]);
			const appId = await config?.userAgentAppId?.();
			return appId ? [...sections, [`app/${appId}`]] : [...sections];
		};
	};
	const defaultUserAgent = createDefaultUserAgentProvider;
	const UA_APP_ID_ENV_NAME = "AWS_SDK_UA_APP_ID";
	const UA_APP_ID_INI_NAME = "sdk_ua_app_id";
	const UA_APP_ID_INI_NAME_DEPRECATED = "sdk-ua-app-id";
	const NODE_APP_ID_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => env[UA_APP_ID_ENV_NAME],
		configFileSelector: (profile) => profile[UA_APP_ID_INI_NAME] ?? profile[UA_APP_ID_INI_NAME_DEPRECATED],
		default: middlewareUserAgent.DEFAULT_UA_APP_ID
	};
	exports.NODE_APP_ID_CONFIG_OPTIONS = NODE_APP_ID_CONFIG_OPTIONS;
	exports.UA_APP_ID_ENV_NAME = UA_APP_ID_ENV_NAME;
	exports.UA_APP_ID_INI_NAME = UA_APP_ID_INI_NAME;
	exports.createDefaultUserAgentProvider = createDefaultUserAgentProvider;
	exports.crtAvailability = crtAvailability;
	exports.defaultUserAgent = defaultUserAgent;
}));

//#endregion
//#region node_modules/@smithy/hash-node/dist-cjs/index.js
var require_dist_cjs$12 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var utilBufferFrom = require_dist_cjs$45();
	var utilUtf8 = require_dist_cjs$44();
	var buffer = require("buffer");
	var crypto$1 = require("crypto");
	var Hash = class {
		algorithmIdentifier;
		secret;
		hash;
		constructor(algorithmIdentifier, secret) {
			this.algorithmIdentifier = algorithmIdentifier;
			this.secret = secret;
			this.reset();
		}
		update(toHash, encoding) {
			this.hash.update(utilUtf8.toUint8Array(castSourceData(toHash, encoding)));
		}
		digest() {
			return Promise.resolve(this.hash.digest());
		}
		reset() {
			this.hash = this.secret ? crypto$1.createHmac(this.algorithmIdentifier, castSourceData(this.secret)) : crypto$1.createHash(this.algorithmIdentifier);
		}
	};
	function castSourceData(toCast, encoding) {
		if (buffer.Buffer.isBuffer(toCast)) return toCast;
		if (typeof toCast === "string") return utilBufferFrom.fromString(toCast, encoding);
		if (ArrayBuffer.isView(toCast)) return utilBufferFrom.fromArrayBuffer(toCast.buffer, toCast.byteOffset, toCast.byteLength);
		return utilBufferFrom.fromArrayBuffer(toCast);
	}
	exports.Hash = Hash;
}));

//#endregion
//#region node_modules/@smithy/util-body-length-node/dist-cjs/index.js
var require_dist_cjs$11 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var node_fs$1 = require("node:fs");
	const calculateBodyLength = (body) => {
		if (!body) return 0;
		if (typeof body === "string") return Buffer.byteLength(body);
		else if (typeof body.byteLength === "number") return body.byteLength;
		else if (typeof body.size === "number") return body.size;
		else if (typeof body.start === "number" && typeof body.end === "number") return body.end + 1 - body.start;
		else if (body instanceof node_fs$1.ReadStream) {
			if (body.path != null) return node_fs$1.lstatSync(body.path).size;
			else if (typeof body.fd === "number") return node_fs$1.fstatSync(body.fd).size;
		}
		throw new Error(`Body Length computation failed for ${body}`);
	};
	exports.calculateBodyLength = calculateBodyLength;
}));

//#endregion
//#region node_modules/@smithy/util-defaults-mode-node/dist-cjs/index.js
var require_dist_cjs$10 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var configResolver = require_dist_cjs$24();
	var nodeConfigProvider = require_dist_cjs$21();
	var propertyProvider = require_dist_cjs$31();
	const AWS_EXECUTION_ENV = "AWS_EXECUTION_ENV";
	const AWS_REGION_ENV = "AWS_REGION";
	const AWS_DEFAULT_REGION_ENV = "AWS_DEFAULT_REGION";
	const ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
	const DEFAULTS_MODE_OPTIONS = [
		"in-region",
		"cross-region",
		"mobile",
		"standard",
		"legacy"
	];
	const IMDS_REGION_PATH = "/latest/meta-data/placement/region";
	const AWS_DEFAULTS_MODE_ENV = "AWS_DEFAULTS_MODE";
	const AWS_DEFAULTS_MODE_CONFIG = "defaults_mode";
	const NODE_DEFAULTS_MODE_CONFIG_OPTIONS = {
		environmentVariableSelector: (env) => {
			return env[AWS_DEFAULTS_MODE_ENV];
		},
		configFileSelector: (profile) => {
			return profile[AWS_DEFAULTS_MODE_CONFIG];
		},
		default: "legacy"
	};
	const resolveDefaultsModeConfig = ({ region = nodeConfigProvider.loadConfig(configResolver.NODE_REGION_CONFIG_OPTIONS), defaultsMode = nodeConfigProvider.loadConfig(NODE_DEFAULTS_MODE_CONFIG_OPTIONS) } = {}) => propertyProvider.memoize(async () => {
		const mode = typeof defaultsMode === "function" ? await defaultsMode() : defaultsMode;
		switch (mode?.toLowerCase()) {
			case "auto": return resolveNodeDefaultsModeAuto(region);
			case "in-region":
			case "cross-region":
			case "mobile":
			case "standard":
			case "legacy": return Promise.resolve(mode?.toLocaleLowerCase());
			case void 0: return Promise.resolve("legacy");
			default: throw new Error(`Invalid parameter for "defaultsMode", expect ${DEFAULTS_MODE_OPTIONS.join(", ")}, got ${mode}`);
		}
	});
	const resolveNodeDefaultsModeAuto = async (clientRegion) => {
		if (clientRegion) {
			const resolvedRegion = typeof clientRegion === "function" ? await clientRegion() : clientRegion;
			const inferredRegion = await inferPhysicalRegion();
			if (!inferredRegion) return "standard";
			if (resolvedRegion === inferredRegion) return "in-region";
			else return "cross-region";
		}
		return "standard";
	};
	const inferPhysicalRegion = async () => {
		if (process.env[AWS_EXECUTION_ENV] && (process.env[AWS_REGION_ENV] || process.env[AWS_DEFAULT_REGION_ENV])) return process.env[AWS_REGION_ENV] ?? process.env[AWS_DEFAULT_REGION_ENV];
		if (!process.env[ENV_IMDS_DISABLED]) try {
			const { getInstanceMetadataEndpoint, httpRequest } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$15()));
			return (await httpRequest({
				...await getInstanceMetadataEndpoint(),
				path: IMDS_REGION_PATH
			})).toString();
		} catch (e$3) {}
	};
	exports.resolveDefaultsModeConfig = resolveDefaultsModeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/ruleset.js
var u$2, v$2, w$2, x$2, a$2, b$2, c$2, d$2, e$2, f$2, g$2, h$2, i$2, j$2, k$2, l$2, m$2, n$2, o$2, p$2, q$2, r$2, s$2, t$2, _data$2, ruleSet$2;
var init_ruleset$2 = __esmMin((() => {
	u$2 = "required", v$2 = "fn", w$2 = "argv", x$2 = "ref";
	a$2 = true, b$2 = "isSet", c$2 = "booleanEquals", d$2 = "error", e$2 = "endpoint", f$2 = "tree", g$2 = "PartitionResult", h$2 = "getAttr", i$2 = {
		[u$2]: false,
		"type": "string"
	}, j$2 = {
		[u$2]: true,
		"default": false,
		"type": "boolean"
	}, k$2 = { [x$2]: "Endpoint" }, l$2 = {
		[v$2]: c$2,
		[w$2]: [{ [x$2]: "UseFIPS" }, true]
	}, m$2 = {
		[v$2]: c$2,
		[w$2]: [{ [x$2]: "UseDualStack" }, true]
	}, n$2 = {}, o$2 = {
		[v$2]: h$2,
		[w$2]: [{ [x$2]: g$2 }, "supportsFIPS"]
	}, p$2 = { [x$2]: g$2 }, q$2 = {
		[v$2]: c$2,
		[w$2]: [true, {
			[v$2]: h$2,
			[w$2]: [p$2, "supportsDualStack"]
		}]
	}, r$2 = [l$2], s$2 = [m$2], t$2 = [{ [x$2]: "Region" }];
	_data$2 = {
		version: "1.0",
		parameters: {
			Region: i$2,
			UseDualStack: j$2,
			UseFIPS: j$2,
			Endpoint: i$2
		},
		rules: [
			{
				conditions: [{
					[v$2]: b$2,
					[w$2]: [k$2]
				}],
				rules: [
					{
						conditions: r$2,
						error: "Invalid Configuration: FIPS and custom endpoint are not supported",
						type: d$2
					},
					{
						conditions: s$2,
						error: "Invalid Configuration: Dualstack and custom endpoint are not supported",
						type: d$2
					},
					{
						endpoint: {
							url: k$2,
							properties: n$2,
							headers: n$2
						},
						type: e$2
					}
				],
				type: f$2
			},
			{
				conditions: [{
					[v$2]: b$2,
					[w$2]: t$2
				}],
				rules: [{
					conditions: [{
						[v$2]: "aws.partition",
						[w$2]: t$2,
						assign: g$2
					}],
					rules: [
						{
							conditions: [l$2, m$2],
							rules: [{
								conditions: [{
									[v$2]: c$2,
									[w$2]: [a$2, o$2]
								}, q$2],
								rules: [{
									endpoint: {
										url: "https://oidc-fips.{Region}.{PartitionResult#dualStackDnsSuffix}",
										properties: n$2,
										headers: n$2
									},
									type: e$2
								}],
								type: f$2
							}, {
								error: "FIPS and DualStack are enabled, but this partition does not support one or both",
								type: d$2
							}],
							type: f$2
						},
						{
							conditions: r$2,
							rules: [{
								conditions: [{
									[v$2]: c$2,
									[w$2]: [o$2, a$2]
								}],
								rules: [{
									conditions: [{
										[v$2]: "stringEquals",
										[w$2]: [{
											[v$2]: h$2,
											[w$2]: [p$2, "name"]
										}, "aws-us-gov"]
									}],
									endpoint: {
										url: "https://oidc.{Region}.amazonaws.com",
										properties: n$2,
										headers: n$2
									},
									type: e$2
								}, {
									endpoint: {
										url: "https://oidc-fips.{Region}.{PartitionResult#dnsSuffix}",
										properties: n$2,
										headers: n$2
									},
									type: e$2
								}],
								type: f$2
							}, {
								error: "FIPS is enabled but this partition does not support FIPS",
								type: d$2
							}],
							type: f$2
						},
						{
							conditions: s$2,
							rules: [{
								conditions: [q$2],
								rules: [{
									endpoint: {
										url: "https://oidc.{Region}.{PartitionResult#dualStackDnsSuffix}",
										properties: n$2,
										headers: n$2
									},
									type: e$2
								}],
								type: f$2
							}, {
								error: "DualStack is enabled but this partition does not support DualStack",
								type: d$2
							}],
							type: f$2
						},
						{
							endpoint: {
								url: "https://oidc.{Region}.{PartitionResult#dnsSuffix}",
								properties: n$2,
								headers: n$2
							},
							type: e$2
						}
					],
					type: f$2
				}],
				type: f$2
			},
			{
				error: "Invalid Configuration: Missing Region",
				type: d$2
			}
		]
	};
	ruleSet$2 = _data$2;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/endpointResolver.js
var import_dist_cjs$100, import_dist_cjs$101, cache$2, defaultEndpointResolver$2;
var init_endpointResolver$2 = __esmMin((() => {
	import_dist_cjs$100 = require_dist_cjs$32();
	import_dist_cjs$101 = require_dist_cjs$35();
	init_ruleset$2();
	cache$2 = new import_dist_cjs$101.EndpointCache({
		size: 50,
		params: [
			"Endpoint",
			"Region",
			"UseDualStack",
			"UseFIPS"
		]
	});
	defaultEndpointResolver$2 = (endpointParams, context = {}) => {
		return cache$2.get(endpointParams, () => (0, import_dist_cjs$101.resolveEndpoint)(ruleSet$2, {
			endpointParams,
			logger: context.logger
		}));
	};
	import_dist_cjs$101.customEndpointFunctions.aws = import_dist_cjs$100.awsEndpointFunctions;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.shared.js
var import_dist_cjs$96, import_dist_cjs$97, import_dist_cjs$98, import_dist_cjs$99, getRuntimeConfig$5;
var init_runtimeConfig_shared$2 = __esmMin((() => {
	init_dist_es();
	init_protocols();
	init_dist_es$1();
	import_dist_cjs$96 = require_dist_cjs$28();
	import_dist_cjs$97 = require_dist_cjs$33();
	import_dist_cjs$98 = require_dist_cjs$43();
	import_dist_cjs$99 = require_dist_cjs$44();
	init_httpAuthSchemeProvider$2();
	init_endpointResolver$2();
	getRuntimeConfig$5 = (config) => {
		return {
			apiVersion: "2019-06-10",
			base64Decoder: config?.base64Decoder ?? import_dist_cjs$98.fromBase64,
			base64Encoder: config?.base64Encoder ?? import_dist_cjs$98.toBase64,
			disableHostPrefix: config?.disableHostPrefix ?? false,
			endpointProvider: config?.endpointProvider ?? defaultEndpointResolver$2,
			extensions: config?.extensions ?? [],
			httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSSOOIDCHttpAuthSchemeProvider,
			httpAuthSchemes: config?.httpAuthSchemes ?? [{
				schemeId: "aws.auth#sigv4",
				identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
				signer: new AwsSdkSigV4Signer()
			}, {
				schemeId: "smithy.api#noAuth",
				identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
				signer: new NoAuthSigner()
			}],
			logger: config?.logger ?? new import_dist_cjs$96.NoOpLogger(),
			protocol: config?.protocol ?? AwsRestJsonProtocol,
			protocolSettings: config?.protocolSettings ?? {
				defaultNamespace: "com.amazonaws.ssooidc",
				version: "2019-06-10",
				serviceTarget: "AWSSSOOIDCService"
			},
			serviceId: config?.serviceId ?? "SSO OIDC",
			urlParser: config?.urlParser ?? import_dist_cjs$97.parseUrl,
			utf8Decoder: config?.utf8Decoder ?? import_dist_cjs$99.fromUtf8,
			utf8Encoder: config?.utf8Encoder ?? import_dist_cjs$99.toUtf8
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.js
var import_dist_cjs$86, import_dist_cjs$87, import_dist_cjs$88, import_dist_cjs$89, import_dist_cjs$90, import_dist_cjs$91, import_dist_cjs$92, import_dist_cjs$93, import_dist_cjs$94, import_dist_cjs$95, getRuntimeConfig$4;
var init_runtimeConfig$2 = __esmMin((() => {
	init_dist_es();
	import_dist_cjs$86 = require_dist_cjs$13();
	import_dist_cjs$87 = require_dist_cjs$24();
	import_dist_cjs$88 = require_dist_cjs$12();
	import_dist_cjs$89 = require_dist_cjs$17();
	import_dist_cjs$90 = require_dist_cjs$21();
	import_dist_cjs$91 = require_dist_cjs$40();
	import_dist_cjs$92 = require_dist_cjs$28();
	import_dist_cjs$93 = require_dist_cjs$11();
	import_dist_cjs$94 = require_dist_cjs$10();
	import_dist_cjs$95 = require_dist_cjs$18();
	init_runtimeConfig_shared$2();
	getRuntimeConfig$4 = (config) => {
		(0, import_dist_cjs$92.emitWarningIfUnsupportedVersion)(process.version);
		const defaultsMode = (0, import_dist_cjs$94.resolveDefaultsModeConfig)(config);
		const defaultConfigProvider = () => defaultsMode().then(import_dist_cjs$92.loadConfigsForDefaultMode);
		const clientSharedValues = getRuntimeConfig$5(config);
		emitWarningIfUnsupportedVersion$3(process.version);
		const loaderConfig = {
			profile: config?.profile,
			logger: clientSharedValues.logger
		};
		return {
			...clientSharedValues,
			...config,
			runtime: "node",
			defaultsMode,
			authSchemePreference: config?.authSchemePreference ?? (0, import_dist_cjs$90.loadConfig)(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
			bodyLengthChecker: config?.bodyLengthChecker ?? import_dist_cjs$93.calculateBodyLength,
			defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, import_dist_cjs$86.createDefaultUserAgentProvider)({
				serviceId: clientSharedValues.serviceId,
				clientVersion: version
			}),
			maxAttempts: config?.maxAttempts ?? (0, import_dist_cjs$90.loadConfig)(import_dist_cjs$89.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
			region: config?.region ?? (0, import_dist_cjs$90.loadConfig)(import_dist_cjs$87.NODE_REGION_CONFIG_OPTIONS, {
				...import_dist_cjs$87.NODE_REGION_CONFIG_FILE_OPTIONS,
				...loaderConfig
			}),
			requestHandler: import_dist_cjs$91.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
			retryMode: config?.retryMode ?? (0, import_dist_cjs$90.loadConfig)({
				...import_dist_cjs$89.NODE_RETRY_MODE_CONFIG_OPTIONS,
				default: async () => (await defaultConfigProvider()).retryMode || import_dist_cjs$95.DEFAULT_RETRY_MODE
			}, config),
			sha256: config?.sha256 ?? import_dist_cjs$88.Hash.bind(null, "sha256"),
			streamCollector: config?.streamCollector ?? import_dist_cjs$91.streamCollector,
			useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, import_dist_cjs$90.loadConfig)(import_dist_cjs$87.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			useFipsEndpoint: config?.useFipsEndpoint ?? (0, import_dist_cjs$90.loadConfig)(import_dist_cjs$87.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			userAgentAppId: config?.userAgentAppId ?? (0, import_dist_cjs$90.loadConfig)(import_dist_cjs$86.NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/region-config-resolver/dist-cjs/regionConfig/stsRegionDefaultResolver.js
var require_stsRegionDefaultResolver = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.warning = void 0;
	exports.stsRegionDefaultResolver = stsRegionDefaultResolver;
	const config_resolver_1 = require_dist_cjs$24();
	const node_config_provider_1 = require_dist_cjs$21();
	function stsRegionDefaultResolver(loaderConfig = {}) {
		return (0, node_config_provider_1.loadConfig)({
			...config_resolver_1.NODE_REGION_CONFIG_OPTIONS,
			async default() {
				if (!exports.warning.silence) console.warn("@aws-sdk - WARN - default STS region of us-east-1 used. See @aws-sdk/credential-providers README and set a region explicitly.");
				return "us-east-1";
			}
		}, {
			...config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS,
			...loaderConfig
		});
	}
	exports.warning = { silence: false };
}));

//#endregion
//#region node_modules/@aws-sdk/region-config-resolver/dist-cjs/index.js
var require_dist_cjs$9 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var stsRegionDefaultResolver = require_stsRegionDefaultResolver();
	var configResolver = require_dist_cjs$24();
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
	Object.defineProperty(exports, "NODE_REGION_CONFIG_FILE_OPTIONS", {
		enumerable: true,
		get: function() {
			return configResolver.NODE_REGION_CONFIG_FILE_OPTIONS;
		}
	});
	Object.defineProperty(exports, "NODE_REGION_CONFIG_OPTIONS", {
		enumerable: true,
		get: function() {
			return configResolver.NODE_REGION_CONFIG_OPTIONS;
		}
	});
	Object.defineProperty(exports, "REGION_ENV_NAME", {
		enumerable: true,
		get: function() {
			return configResolver.REGION_ENV_NAME;
		}
	});
	Object.defineProperty(exports, "REGION_INI_NAME", {
		enumerable: true,
		get: function() {
			return configResolver.REGION_INI_NAME;
		}
	});
	Object.defineProperty(exports, "resolveRegionConfig", {
		enumerable: true,
		get: function() {
			return configResolver.resolveRegionConfig;
		}
	});
	exports.getAwsRegionExtensionConfiguration = getAwsRegionExtensionConfiguration;
	exports.resolveAwsRegionExtensionConfiguration = resolveAwsRegionExtensionConfiguration;
	Object.keys(stsRegionDefaultResolver).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return stsRegionDefaultResolver[k$3];
			}
		});
	});
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration$2, resolveHttpAuthRuntimeConfig$2;
var init_httpAuthExtensionConfiguration$2 = __esmMin((() => {
	getHttpAuthExtensionConfiguration$2 = (runtimeConfig) => {
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
	resolveHttpAuthRuntimeConfig$2 = (config) => {
		return {
			httpAuthSchemes: config.httpAuthSchemes(),
			httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
			credentials: config.credentials()
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeExtensions.js
var import_dist_cjs$83, import_dist_cjs$84, import_dist_cjs$85, resolveRuntimeExtensions$2;
var init_runtimeExtensions$2 = __esmMin((() => {
	import_dist_cjs$83 = require_dist_cjs$9();
	import_dist_cjs$84 = require_dist_cjs$52();
	import_dist_cjs$85 = require_dist_cjs$28();
	init_httpAuthExtensionConfiguration$2();
	resolveRuntimeExtensions$2 = (runtimeConfig, extensions) => {
		const extensionConfiguration = Object.assign((0, import_dist_cjs$83.getAwsRegionExtensionConfiguration)(runtimeConfig), (0, import_dist_cjs$85.getDefaultExtensionConfiguration)(runtimeConfig), (0, import_dist_cjs$84.getHttpHandlerExtensionConfiguration)(runtimeConfig), getHttpAuthExtensionConfiguration$2(runtimeConfig));
		extensions.forEach((extension) => extension.configure(extensionConfiguration));
		return Object.assign(runtimeConfig, (0, import_dist_cjs$83.resolveAwsRegionExtensionConfiguration)(extensionConfiguration), (0, import_dist_cjs$85.resolveDefaultRuntimeConfig)(extensionConfiguration), (0, import_dist_cjs$84.resolveHttpHandlerRuntimeConfig)(extensionConfiguration), resolveHttpAuthRuntimeConfig$2(extensionConfiguration));
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDCClient.js
var import_dist_cjs$74, import_dist_cjs$75, import_dist_cjs$76, import_dist_cjs$77, import_dist_cjs$78, import_dist_cjs$79, import_dist_cjs$80, import_dist_cjs$81, import_dist_cjs$82, SSOOIDCClient;
var init_SSOOIDCClient = __esmMin((() => {
	import_dist_cjs$74 = require_dist_cjs$51();
	import_dist_cjs$75 = require_dist_cjs$50();
	import_dist_cjs$76 = require_dist_cjs$49();
	import_dist_cjs$77 = require_dist_cjs$26();
	import_dist_cjs$78 = require_dist_cjs$24();
	init_dist_es$1();
	init_schema();
	import_dist_cjs$79 = require_dist_cjs$23();
	import_dist_cjs$80 = require_dist_cjs$20();
	import_dist_cjs$81 = require_dist_cjs$17();
	import_dist_cjs$82 = require_dist_cjs$28();
	init_httpAuthSchemeProvider$2();
	init_EndpointParameters$2();
	init_runtimeConfig$2();
	init_runtimeExtensions$2();
	SSOOIDCClient = class extends import_dist_cjs$82.Client {
		config;
		constructor(...[configuration]) {
			const _config_0 = getRuntimeConfig$4(configuration || {});
			super(_config_0);
			this.initConfig = _config_0;
			this.config = resolveRuntimeExtensions$2(resolveHttpAuthSchemeConfig$2((0, import_dist_cjs$80.resolveEndpointConfig)((0, import_dist_cjs$74.resolveHostHeaderConfig)((0, import_dist_cjs$78.resolveRegionConfig)((0, import_dist_cjs$81.resolveRetryConfig)((0, import_dist_cjs$77.resolveUserAgentConfig)(resolveClientEndpointParameters$2(_config_0))))))), configuration?.extensions || []);
			this.middlewareStack.use(getSchemaSerdePlugin(this.config));
			this.middlewareStack.use((0, import_dist_cjs$77.getUserAgentPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$81.getRetryPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$79.getContentLengthPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$74.getHostHeaderPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$75.getLoggerPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$76.getRecursionDetectionPlugin)(this.config));
			this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
				httpAuthSchemeParametersProvider: defaultSSOOIDCHttpAuthSchemeParametersProvider,
				identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({ "aws.auth#sigv4": config.credentials })
			}));
			this.middlewareStack.use(getHttpSigningPlugin(this.config));
		}
		destroy() {
			super.destroy();
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/SSOOIDCServiceException.js
var import_dist_cjs$73, SSOOIDCServiceException;
var init_SSOOIDCServiceException = __esmMin((() => {
	import_dist_cjs$73 = require_dist_cjs$28();
	SSOOIDCServiceException = class SSOOIDCServiceException extends import_dist_cjs$73.ServiceException {
		constructor(options) {
			super(options);
			Object.setPrototypeOf(this, SSOOIDCServiceException.prototype);
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/errors.js
var AccessDeniedException$1, AuthorizationPendingException, ExpiredTokenException$1, InternalServerException$1, InvalidClientException, InvalidGrantException, InvalidRequestException, InvalidScopeException, SlowDownException, UnauthorizedClientException, UnsupportedGrantTypeException;
var init_errors$2 = __esmMin((() => {
	init_SSOOIDCServiceException();
	AccessDeniedException$1 = class AccessDeniedException$1 extends SSOOIDCServiceException {
		name = "AccessDeniedException";
		$fault = "client";
		error;
		reason;
		error_description;
		constructor(opts) {
			super({
				name: "AccessDeniedException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, AccessDeniedException$1.prototype);
			this.error = opts.error;
			this.reason = opts.reason;
			this.error_description = opts.error_description;
		}
	};
	AuthorizationPendingException = class AuthorizationPendingException extends SSOOIDCServiceException {
		name = "AuthorizationPendingException";
		$fault = "client";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "AuthorizationPendingException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, AuthorizationPendingException.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
	ExpiredTokenException$1 = class ExpiredTokenException$1 extends SSOOIDCServiceException {
		name = "ExpiredTokenException";
		$fault = "client";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "ExpiredTokenException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, ExpiredTokenException$1.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
	InternalServerException$1 = class InternalServerException$1 extends SSOOIDCServiceException {
		name = "InternalServerException";
		$fault = "server";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "InternalServerException",
				$fault: "server",
				...opts
			});
			Object.setPrototypeOf(this, InternalServerException$1.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
	InvalidClientException = class InvalidClientException extends SSOOIDCServiceException {
		name = "InvalidClientException";
		$fault = "client";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "InvalidClientException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, InvalidClientException.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
	InvalidGrantException = class InvalidGrantException extends SSOOIDCServiceException {
		name = "InvalidGrantException";
		$fault = "client";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "InvalidGrantException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, InvalidGrantException.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
	InvalidRequestException = class InvalidRequestException extends SSOOIDCServiceException {
		name = "InvalidRequestException";
		$fault = "client";
		error;
		reason;
		error_description;
		constructor(opts) {
			super({
				name: "InvalidRequestException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, InvalidRequestException.prototype);
			this.error = opts.error;
			this.reason = opts.reason;
			this.error_description = opts.error_description;
		}
	};
	InvalidScopeException = class InvalidScopeException extends SSOOIDCServiceException {
		name = "InvalidScopeException";
		$fault = "client";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "InvalidScopeException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, InvalidScopeException.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
	SlowDownException = class SlowDownException extends SSOOIDCServiceException {
		name = "SlowDownException";
		$fault = "client";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "SlowDownException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, SlowDownException.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
	UnauthorizedClientException = class UnauthorizedClientException extends SSOOIDCServiceException {
		name = "UnauthorizedClientException";
		$fault = "client";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "UnauthorizedClientException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, UnauthorizedClientException.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
	UnsupportedGrantTypeException = class UnsupportedGrantTypeException extends SSOOIDCServiceException {
		name = "UnsupportedGrantTypeException";
		$fault = "client";
		error;
		error_description;
		constructor(opts) {
			super({
				name: "UnsupportedGrantTypeException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, UnsupportedGrantTypeException.prototype);
			this.error = opts.error;
			this.error_description = opts.error_description;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/schemas/schemas_0.js
var _ADE$1, _APE, _AT$1, _CS, _CT, _CTR, _CTRr, _CV, _ETE$1, _ICE, _IGE, _IRE, _ISE$1, _ISEn, _IT, _RT$1, _SDE, _UCE, _UGTE, _aT$1, _c$2, _cI$1, _cS, _cV$1, _co$1, _dC, _e$2, _eI$1, _ed, _gT$1, _h$1, _hE$2, _iT$1, _r, _rT$1, _rU$1, _s$2, _se, _sm$1, _tT$1, n0$2, AccessToken, ClientSecret, CodeVerifier, IdToken, RefreshToken$1, AccessDeniedException$$1, AuthorizationPendingException$, CreateTokenRequest$, CreateTokenResponse$, ExpiredTokenException$$1, InternalServerException$$1, InvalidClientException$, InvalidGrantException$, InvalidRequestException$, InvalidScopeException$, SlowDownException$, UnauthorizedClientException$, UnsupportedGrantTypeException$, SSOOIDCServiceException$, CreateToken$;
var init_schemas_0$2 = __esmMin((() => {
	init_schema();
	init_errors$2();
	init_SSOOIDCServiceException();
	_ADE$1 = "AccessDeniedException";
	_APE = "AuthorizationPendingException";
	_AT$1 = "AccessToken";
	_CS = "ClientSecret";
	_CT = "CreateToken";
	_CTR = "CreateTokenRequest";
	_CTRr = "CreateTokenResponse";
	_CV = "CodeVerifier";
	_ETE$1 = "ExpiredTokenException";
	_ICE = "InvalidClientException";
	_IGE = "InvalidGrantException";
	_IRE = "InvalidRequestException";
	_ISE$1 = "InternalServerException";
	_ISEn = "InvalidScopeException";
	_IT = "IdToken";
	_RT$1 = "RefreshToken";
	_SDE = "SlowDownException";
	_UCE = "UnauthorizedClientException";
	_UGTE = "UnsupportedGrantTypeException";
	_aT$1 = "accessToken";
	_c$2 = "client";
	_cI$1 = "clientId";
	_cS = "clientSecret";
	_cV$1 = "codeVerifier";
	_co$1 = "code";
	_dC = "deviceCode";
	_e$2 = "error";
	_eI$1 = "expiresIn";
	_ed = "error_description";
	_gT$1 = "grantType";
	_h$1 = "http";
	_hE$2 = "httpError";
	_iT$1 = "idToken";
	_r = "reason";
	_rT$1 = "refreshToken";
	_rU$1 = "redirectUri";
	_s$2 = "scope";
	_se = "server";
	_sm$1 = "smithy.ts.sdk.synthetic.com.amazonaws.ssooidc";
	_tT$1 = "tokenType";
	n0$2 = "com.amazonaws.ssooidc";
	AccessToken = [
		0,
		n0$2,
		_AT$1,
		8,
		0
	];
	ClientSecret = [
		0,
		n0$2,
		_CS,
		8,
		0
	];
	CodeVerifier = [
		0,
		n0$2,
		_CV,
		8,
		0
	];
	IdToken = [
		0,
		n0$2,
		_IT,
		8,
		0
	];
	RefreshToken$1 = [
		0,
		n0$2,
		_RT$1,
		8,
		0
	];
	AccessDeniedException$$1 = [
		-3,
		n0$2,
		_ADE$1,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[
			_e$2,
			_r,
			_ed
		],
		[
			0,
			0,
			0
		]
	];
	TypeRegistry.for(n0$2).registerError(AccessDeniedException$$1, AccessDeniedException$1);
	AuthorizationPendingException$ = [
		-3,
		n0$2,
		_APE,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(AuthorizationPendingException$, AuthorizationPendingException);
	CreateTokenRequest$ = [
		3,
		n0$2,
		_CTR,
		0,
		[
			_cI$1,
			_cS,
			_gT$1,
			_dC,
			_co$1,
			_rT$1,
			_s$2,
			_rU$1,
			_cV$1
		],
		[
			0,
			[() => ClientSecret, 0],
			0,
			0,
			0,
			[() => RefreshToken$1, 0],
			64,
			0,
			[() => CodeVerifier, 0]
		]
	];
	CreateTokenResponse$ = [
		3,
		n0$2,
		_CTRr,
		0,
		[
			_aT$1,
			_tT$1,
			_eI$1,
			_rT$1,
			_iT$1
		],
		[
			[() => AccessToken, 0],
			0,
			1,
			[() => RefreshToken$1, 0],
			[() => IdToken, 0]
		]
	];
	ExpiredTokenException$$1 = [
		-3,
		n0$2,
		_ETE$1,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(ExpiredTokenException$$1, ExpiredTokenException$1);
	InternalServerException$$1 = [
		-3,
		n0$2,
		_ISE$1,
		{
			[_e$2]: _se,
			[_hE$2]: 500
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(InternalServerException$$1, InternalServerException$1);
	InvalidClientException$ = [
		-3,
		n0$2,
		_ICE,
		{
			[_e$2]: _c$2,
			[_hE$2]: 401
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(InvalidClientException$, InvalidClientException);
	InvalidGrantException$ = [
		-3,
		n0$2,
		_IGE,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(InvalidGrantException$, InvalidGrantException);
	InvalidRequestException$ = [
		-3,
		n0$2,
		_IRE,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[
			_e$2,
			_r,
			_ed
		],
		[
			0,
			0,
			0
		]
	];
	TypeRegistry.for(n0$2).registerError(InvalidRequestException$, InvalidRequestException);
	InvalidScopeException$ = [
		-3,
		n0$2,
		_ISEn,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(InvalidScopeException$, InvalidScopeException);
	SlowDownException$ = [
		-3,
		n0$2,
		_SDE,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(SlowDownException$, SlowDownException);
	UnauthorizedClientException$ = [
		-3,
		n0$2,
		_UCE,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(UnauthorizedClientException$, UnauthorizedClientException);
	UnsupportedGrantTypeException$ = [
		-3,
		n0$2,
		_UGTE,
		{
			[_e$2]: _c$2,
			[_hE$2]: 400
		},
		[_e$2, _ed],
		[0, 0]
	];
	TypeRegistry.for(n0$2).registerError(UnsupportedGrantTypeException$, UnsupportedGrantTypeException);
	SSOOIDCServiceException$ = [
		-3,
		_sm$1,
		"SSOOIDCServiceException",
		0,
		[],
		[]
	];
	TypeRegistry.for(_sm$1).registerError(SSOOIDCServiceException$, SSOOIDCServiceException);
	CreateToken$ = [
		9,
		n0$2,
		_CT,
		{ [_h$1]: [
			"POST",
			"/token",
			200
		] },
		() => CreateTokenRequest$,
		() => CreateTokenResponse$
	];
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/CreateTokenCommand.js
var import_dist_cjs$71, import_dist_cjs$72, CreateTokenCommand;
var init_CreateTokenCommand = __esmMin((() => {
	import_dist_cjs$71 = require_dist_cjs$20();
	import_dist_cjs$72 = require_dist_cjs$28();
	init_EndpointParameters$2();
	init_schemas_0$2();
	CreateTokenCommand = class extends import_dist_cjs$72.Command.classBuilder().ep(commonParams$2).m(function(Command, cs, config, o$3) {
		return [(0, import_dist_cjs$71.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSSOOIDCService", "CreateToken", {}).n("SSOOIDCClient", "CreateTokenCommand").sc(CreateToken$).build() {};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDC.js
var import_dist_cjs$70, commands$2, SSOOIDC;
var init_SSOOIDC = __esmMin((() => {
	import_dist_cjs$70 = require_dist_cjs$28();
	init_CreateTokenCommand();
	init_SSOOIDCClient();
	commands$2 = { CreateTokenCommand };
	SSOOIDC = class extends SSOOIDCClient {};
	(0, import_dist_cjs$70.createAggregatedClient)(commands$2, SSOOIDC);
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/index.js
var init_commands$2 = __esmMin((() => {
	init_CreateTokenCommand();
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/enums.js
var AccessDeniedExceptionReason, InvalidRequestExceptionReason;
var init_enums$1 = __esmMin((() => {
	AccessDeniedExceptionReason = { KMS_ACCESS_DENIED: "KMS_AccessDeniedException" };
	InvalidRequestExceptionReason = {
		KMS_DISABLED_KEY: "KMS_DisabledException",
		KMS_INVALID_KEY_USAGE: "KMS_InvalidKeyUsageException",
		KMS_INVALID_STATE: "KMS_InvalidStateException",
		KMS_KEY_NOT_FOUND: "KMS_NotFoundException"
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/models_0.js
var init_models_0$2 = __esmMin((() => {}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/index.js
var sso_oidc_exports = /* @__PURE__ */ __exportAll({
	$Command: () => import_dist_cjs$72.Command,
	AccessDeniedException: () => AccessDeniedException$1,
	AccessDeniedException$: () => AccessDeniedException$$1,
	AccessDeniedExceptionReason: () => AccessDeniedExceptionReason,
	AuthorizationPendingException: () => AuthorizationPendingException,
	AuthorizationPendingException$: () => AuthorizationPendingException$,
	CreateToken$: () => CreateToken$,
	CreateTokenCommand: () => CreateTokenCommand,
	CreateTokenRequest$: () => CreateTokenRequest$,
	CreateTokenResponse$: () => CreateTokenResponse$,
	ExpiredTokenException: () => ExpiredTokenException$1,
	ExpiredTokenException$: () => ExpiredTokenException$$1,
	InternalServerException: () => InternalServerException$1,
	InternalServerException$: () => InternalServerException$$1,
	InvalidClientException: () => InvalidClientException,
	InvalidClientException$: () => InvalidClientException$,
	InvalidGrantException: () => InvalidGrantException,
	InvalidGrantException$: () => InvalidGrantException$,
	InvalidRequestException: () => InvalidRequestException,
	InvalidRequestException$: () => InvalidRequestException$,
	InvalidRequestExceptionReason: () => InvalidRequestExceptionReason,
	InvalidScopeException: () => InvalidScopeException,
	InvalidScopeException$: () => InvalidScopeException$,
	SSOOIDC: () => SSOOIDC,
	SSOOIDCClient: () => SSOOIDCClient,
	SSOOIDCServiceException: () => SSOOIDCServiceException,
	SSOOIDCServiceException$: () => SSOOIDCServiceException$,
	SlowDownException: () => SlowDownException,
	SlowDownException$: () => SlowDownException$,
	UnauthorizedClientException: () => UnauthorizedClientException,
	UnauthorizedClientException$: () => UnauthorizedClientException$,
	UnsupportedGrantTypeException: () => UnsupportedGrantTypeException,
	UnsupportedGrantTypeException$: () => UnsupportedGrantTypeException$,
	__Client: () => import_dist_cjs$82.Client
});
var init_sso_oidc = __esmMin((() => {
	init_SSOOIDCClient();
	init_SSOOIDC();
	init_commands$2();
	init_schemas_0$2();
	init_enums$1();
	init_errors$2();
	init_models_0$2();
	init_SSOOIDCServiceException();
}));

//#endregion
//#region node_modules/@aws-sdk/token-providers/dist-cjs/index.js
var require_dist_cjs$8 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var client = (init_client(), __toCommonJS(client_exports));
	var httpAuthSchemes = (init_httpAuthSchemes(), __toCommonJS(httpAuthSchemes_exports));
	var propertyProvider = require_dist_cjs$31();
	var sharedIniFileLoader = require_dist_cjs$22();
	var fs = require("fs");
	const fromEnvSigningName = ({ logger: logger$1, signingName } = {}) => async () => {
		logger$1?.debug?.("@aws-sdk/token-providers - fromEnvSigningName");
		if (!signingName) throw new propertyProvider.TokenProviderError("Please pass 'signingName' to compute environment variable key", { logger: logger$1 });
		const bearerTokenKey = httpAuthSchemes.getBearerTokenEnvKey(signingName);
		if (!(bearerTokenKey in process.env)) throw new propertyProvider.TokenProviderError(`Token not present in '${bearerTokenKey}' environment variable`, { logger: logger$1 });
		const token = { token: process.env[bearerTokenKey] };
		client.setTokenFeature(token, "BEARER_SERVICE_ENV_VARS", "3");
		return token;
	};
	const EXPIRE_WINDOW_MS = 300 * 1e3;
	const REFRESH_MESSAGE = `To refresh this SSO session run 'aws sso login' with the corresponding profile.`;
	const getSsoOidcClient = async (ssoRegion, init = {}, callerClientConfig) => {
		const { SSOOIDCClient: SSOOIDCClient$1 } = await Promise.resolve().then(() => (init_sso_oidc(), sso_oidc_exports));
		const coalesce = (prop) => init.clientConfig?.[prop] ?? init.parentClientConfig?.[prop] ?? callerClientConfig?.[prop];
		return new SSOOIDCClient$1(Object.assign({}, init.clientConfig ?? {}, {
			region: ssoRegion ?? init.clientConfig?.region,
			logger: coalesce("logger"),
			userAgentAppId: coalesce("userAgentAppId")
		}));
	};
	const getNewSsoOidcToken = async (ssoToken, ssoRegion, init = {}, callerClientConfig) => {
		const { CreateTokenCommand: CreateTokenCommand$1 } = await Promise.resolve().then(() => (init_sso_oidc(), sso_oidc_exports));
		return (await getSsoOidcClient(ssoRegion, init, callerClientConfig)).send(new CreateTokenCommand$1({
			clientId: ssoToken.clientId,
			clientSecret: ssoToken.clientSecret,
			refreshToken: ssoToken.refreshToken,
			grantType: "refresh_token"
		}));
	};
	const validateTokenExpiry = (token) => {
		if (token.expiration && token.expiration.getTime() < Date.now()) throw new propertyProvider.TokenProviderError(`Token is expired. ${REFRESH_MESSAGE}`, false);
	};
	const validateTokenKey = (key, value, forRefresh = false) => {
		if (typeof value === "undefined") throw new propertyProvider.TokenProviderError(`Value not present for '${key}' in SSO Token${forRefresh ? ". Cannot refresh" : ""}. ${REFRESH_MESSAGE}`, false);
	};
	const { writeFile } = fs.promises;
	const writeSSOTokenToFile = (id, ssoToken) => {
		return writeFile(sharedIniFileLoader.getSSOTokenFilepath(id), JSON.stringify(ssoToken, null, 2));
	};
	const lastRefreshAttemptTime = /* @__PURE__ */ new Date(0);
	const fromSso = (init = {}) => async ({ callerClientConfig } = {}) => {
		init.logger?.debug("@aws-sdk/token-providers - fromSso");
		const profiles = await sharedIniFileLoader.parseKnownFiles(init);
		const profileName = sharedIniFileLoader.getProfileName({ profile: init.profile ?? callerClientConfig?.profile });
		const profile = profiles[profileName];
		if (!profile) throw new propertyProvider.TokenProviderError(`Profile '${profileName}' could not be found in shared credentials file.`, false);
		else if (!profile["sso_session"]) throw new propertyProvider.TokenProviderError(`Profile '${profileName}' is missing required property 'sso_session'.`);
		const ssoSessionName = profile["sso_session"];
		const ssoSession = (await sharedIniFileLoader.loadSsoSessionData(init))[ssoSessionName];
		if (!ssoSession) throw new propertyProvider.TokenProviderError(`Sso session '${ssoSessionName}' could not be found in shared credentials file.`, false);
		for (const ssoSessionRequiredKey of ["sso_start_url", "sso_region"]) if (!ssoSession[ssoSessionRequiredKey]) throw new propertyProvider.TokenProviderError(`Sso session '${ssoSessionName}' is missing required property '${ssoSessionRequiredKey}'.`, false);
		ssoSession["sso_start_url"];
		const ssoRegion = ssoSession["sso_region"];
		let ssoToken;
		try {
			ssoToken = await sharedIniFileLoader.getSSOTokenFromFile(ssoSessionName);
		} catch (e$3) {
			throw new propertyProvider.TokenProviderError(`The SSO session token associated with profile=${profileName} was not found or is invalid. ${REFRESH_MESSAGE}`, false);
		}
		validateTokenKey("accessToken", ssoToken.accessToken);
		validateTokenKey("expiresAt", ssoToken.expiresAt);
		const { accessToken, expiresAt } = ssoToken;
		const existingToken = {
			token: accessToken,
			expiration: new Date(expiresAt)
		};
		if (existingToken.expiration.getTime() - Date.now() > EXPIRE_WINDOW_MS) return existingToken;
		if (Date.now() - lastRefreshAttemptTime.getTime() < 30 * 1e3) {
			validateTokenExpiry(existingToken);
			return existingToken;
		}
		validateTokenKey("clientId", ssoToken.clientId, true);
		validateTokenKey("clientSecret", ssoToken.clientSecret, true);
		validateTokenKey("refreshToken", ssoToken.refreshToken, true);
		try {
			lastRefreshAttemptTime.setTime(Date.now());
			const newSsoOidcToken = await getNewSsoOidcToken(ssoToken, ssoRegion, init, callerClientConfig);
			validateTokenKey("accessToken", newSsoOidcToken.accessToken);
			validateTokenKey("expiresIn", newSsoOidcToken.expiresIn);
			const newTokenExpiration = new Date(Date.now() + newSsoOidcToken.expiresIn * 1e3);
			try {
				await writeSSOTokenToFile(ssoSessionName, {
					...ssoToken,
					accessToken: newSsoOidcToken.accessToken,
					expiresAt: newTokenExpiration.toISOString(),
					refreshToken: newSsoOidcToken.refreshToken
				});
			} catch (error$1) {}
			return {
				token: newSsoOidcToken.accessToken,
				expiration: newTokenExpiration
			};
		} catch (error$1) {
			validateTokenExpiry(existingToken);
			return existingToken;
		}
	};
	const fromStatic = ({ token, logger: logger$1 }) => async () => {
		logger$1?.debug("@aws-sdk/token-providers - fromStatic");
		if (!token || !token.token) throw new propertyProvider.TokenProviderError(`Please pass a valid token to fromStatic`, false);
		return token;
	};
	const nodeProvider = (init = {}) => propertyProvider.memoize(propertyProvider.chain(fromSso(init), async () => {
		throw new propertyProvider.TokenProviderError("Could not load token from any providers", false);
	}), (token) => token.expiration !== void 0 && token.expiration.getTime() - Date.now() < 3e5, (token) => token.expiration !== void 0);
	exports.fromEnvSigningName = fromEnvSigningName;
	exports.fromSso = fromSso;
	exports.fromStatic = fromStatic;
	exports.nodeProvider = nodeProvider;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sso/dist-cjs/auth/httpAuthSchemeProvider.js
var require_httpAuthSchemeProvider = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.resolveHttpAuthSchemeConfig = exports.defaultSSOHttpAuthSchemeProvider = exports.defaultSSOHttpAuthSchemeParametersProvider = void 0;
	const core_1 = (init_dist_es(), __toCommonJS(dist_es_exports));
	const util_middleware_1 = require_dist_cjs$48();
	const defaultSSOHttpAuthSchemeParametersProvider = async (config, context, input) => {
		return {
			operation: (0, util_middleware_1.getSmithyContext)(context).operation,
			region: await (0, util_middleware_1.normalizeProvider)(config.region)() || (() => {
				throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
			})()
		};
	};
	exports.defaultSSOHttpAuthSchemeParametersProvider = defaultSSOHttpAuthSchemeParametersProvider;
	function createAwsAuthSigv4HttpAuthOption(authParameters) {
		return {
			schemeId: "aws.auth#sigv4",
			signingProperties: {
				name: "awsssoportal",
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
	const defaultSSOHttpAuthSchemeProvider = (authParameters) => {
		const options = [];
		switch (authParameters.operation) {
			case "GetRoleCredentials":
				options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
				break;
			case "ListAccountRoles":
				options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
				break;
			case "ListAccounts":
				options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
				break;
			case "Logout":
				options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
				break;
			default: options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
		}
		return options;
	};
	exports.defaultSSOHttpAuthSchemeProvider = defaultSSOHttpAuthSchemeProvider;
	const resolveHttpAuthSchemeConfig = (config) => {
		const config_0 = (0, core_1.resolveAwsSdkSigV4Config)(config);
		return Object.assign(config_0, { authSchemePreference: (0, util_middleware_1.normalizeProvider)(config.authSchemePreference ?? []) });
	};
	exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sso/package.json
var require_package = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	module.exports = {
		"name": "@aws-sdk/client-sso",
		"description": "AWS SDK for JavaScript Sso Client for Node.js, Browser and React Native",
		"version": "3.958.0",
		"scripts": {
			"build": "concurrently 'yarn:build:types' 'yarn:build:es' && yarn build:cjs",
			"build:cjs": "node ../../scripts/compilation/inline client-sso",
			"build:es": "tsc -p tsconfig.es.json",
			"build:include:deps": "yarn g:turbo run build -F=\"$npm_package_name\"",
			"build:types": "tsc -p tsconfig.types.json",
			"build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
			"clean": "rimraf ./dist-* && rimraf *.tsbuildinfo",
			"extract:docs": "api-extractor run --local",
			"generate:client": "node ../../scripts/generate-clients/single-service --solo sso",
			"test:index": "tsc --noEmit ./test/index-types.ts && node ./test/index-objects.spec.mjs"
		},
		"main": "./dist-cjs/index.js",
		"types": "./dist-types/index.d.ts",
		"module": "./dist-es/index.js",
		"sideEffects": false,
		"dependencies": {
			"@aws-crypto/sha256-browser": "5.2.0",
			"@aws-crypto/sha256-js": "5.2.0",
			"@aws-sdk/core": "3.957.0",
			"@aws-sdk/middleware-host-header": "3.957.0",
			"@aws-sdk/middleware-logger": "3.957.0",
			"@aws-sdk/middleware-recursion-detection": "3.957.0",
			"@aws-sdk/middleware-user-agent": "3.957.0",
			"@aws-sdk/region-config-resolver": "3.957.0",
			"@aws-sdk/types": "3.957.0",
			"@aws-sdk/util-endpoints": "3.957.0",
			"@aws-sdk/util-user-agent-browser": "3.957.0",
			"@aws-sdk/util-user-agent-node": "3.957.0",
			"@smithy/config-resolver": "^4.4.5",
			"@smithy/core": "^3.20.0",
			"@smithy/fetch-http-handler": "^5.3.8",
			"@smithy/hash-node": "^4.2.7",
			"@smithy/invalid-dependency": "^4.2.7",
			"@smithy/middleware-content-length": "^4.2.7",
			"@smithy/middleware-endpoint": "^4.4.1",
			"@smithy/middleware-retry": "^4.4.17",
			"@smithy/middleware-serde": "^4.2.8",
			"@smithy/middleware-stack": "^4.2.7",
			"@smithy/node-config-provider": "^4.3.7",
			"@smithy/node-http-handler": "^4.4.7",
			"@smithy/protocol-http": "^5.3.7",
			"@smithy/smithy-client": "^4.10.2",
			"@smithy/types": "^4.11.0",
			"@smithy/url-parser": "^4.2.7",
			"@smithy/util-base64": "^4.3.0",
			"@smithy/util-body-length-browser": "^4.2.0",
			"@smithy/util-body-length-node": "^4.2.1",
			"@smithy/util-defaults-mode-browser": "^4.3.16",
			"@smithy/util-defaults-mode-node": "^4.2.19",
			"@smithy/util-endpoints": "^3.2.7",
			"@smithy/util-middleware": "^4.2.7",
			"@smithy/util-retry": "^4.2.7",
			"@smithy/util-utf8": "^4.2.0",
			"tslib": "^2.6.2"
		},
		"devDependencies": {
			"@tsconfig/node18": "18.2.4",
			"@types/node": "^18.19.69",
			"concurrently": "7.0.0",
			"downlevel-dts": "0.10.1",
			"rimraf": "3.0.2",
			"typescript": "~5.8.3"
		},
		"engines": { "node": ">=18.0.0" },
		"typesVersions": { "<4.0": { "dist-types/*": ["dist-types/ts3.4/*"] } },
		"files": ["dist-*/**"],
		"author": {
			"name": "AWS SDK for JavaScript Team",
			"url": "https://aws.amazon.com/javascript/"
		},
		"license": "Apache-2.0",
		"browser": { "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser" },
		"react-native": { "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native" },
		"homepage": "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sso",
		"repository": {
			"type": "git",
			"url": "https://github.com/aws/aws-sdk-js-v3.git",
			"directory": "clients/client-sso"
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/client-sso/dist-cjs/endpoint/ruleset.js
var require_ruleset$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.ruleSet = void 0;
	const u = "required", v = "fn", w = "argv", x = "ref";
	const a = true, b = "isSet", c = "booleanEquals", d = "error", e = "endpoint", f = "tree", g = "PartitionResult", h = "getAttr", i = {
		[u]: false,
		"type": "string"
	}, j = {
		[u]: true,
		"default": false,
		"type": "boolean"
	}, k = { [x]: "Endpoint" }, l = {
		[v]: c,
		[w]: [{ [x]: "UseFIPS" }, true]
	}, m = {
		[v]: c,
		[w]: [{ [x]: "UseDualStack" }, true]
	}, n = {}, o = {
		[v]: h,
		[w]: [{ [x]: g }, "supportsFIPS"]
	}, p = { [x]: g }, q = {
		[v]: c,
		[w]: [true, {
			[v]: h,
			[w]: [p, "supportsDualStack"]
		}]
	}, r = [l], s = [m], t = [{ [x]: "Region" }];
	const _data = {
		version: "1.0",
		parameters: {
			Region: i,
			UseDualStack: j,
			UseFIPS: j,
			Endpoint: i
		},
		rules: [
			{
				conditions: [{
					[v]: b,
					[w]: [k]
				}],
				rules: [
					{
						conditions: r,
						error: "Invalid Configuration: FIPS and custom endpoint are not supported",
						type: d
					},
					{
						conditions: s,
						error: "Invalid Configuration: Dualstack and custom endpoint are not supported",
						type: d
					},
					{
						endpoint: {
							url: k,
							properties: n,
							headers: n
						},
						type: e
					}
				],
				type: f
			},
			{
				conditions: [{
					[v]: b,
					[w]: t
				}],
				rules: [{
					conditions: [{
						[v]: "aws.partition",
						[w]: t,
						assign: g
					}],
					rules: [
						{
							conditions: [l, m],
							rules: [{
								conditions: [{
									[v]: c,
									[w]: [a, o]
								}, q],
								rules: [{
									endpoint: {
										url: "https://portal.sso-fips.{Region}.{PartitionResult#dualStackDnsSuffix}",
										properties: n,
										headers: n
									},
									type: e
								}],
								type: f
							}, {
								error: "FIPS and DualStack are enabled, but this partition does not support one or both",
								type: d
							}],
							type: f
						},
						{
							conditions: r,
							rules: [{
								conditions: [{
									[v]: c,
									[w]: [o, a]
								}],
								rules: [{
									conditions: [{
										[v]: "stringEquals",
										[w]: [{
											[v]: h,
											[w]: [p, "name"]
										}, "aws-us-gov"]
									}],
									endpoint: {
										url: "https://portal.sso.{Region}.amazonaws.com",
										properties: n,
										headers: n
									},
									type: e
								}, {
									endpoint: {
										url: "https://portal.sso-fips.{Region}.{PartitionResult#dnsSuffix}",
										properties: n,
										headers: n
									},
									type: e
								}],
								type: f
							}, {
								error: "FIPS is enabled but this partition does not support FIPS",
								type: d
							}],
							type: f
						},
						{
							conditions: s,
							rules: [{
								conditions: [q],
								rules: [{
									endpoint: {
										url: "https://portal.sso.{Region}.{PartitionResult#dualStackDnsSuffix}",
										properties: n,
										headers: n
									},
									type: e
								}],
								type: f
							}, {
								error: "DualStack is enabled but this partition does not support DualStack",
								type: d
							}],
							type: f
						},
						{
							endpoint: {
								url: "https://portal.sso.{Region}.{PartitionResult#dnsSuffix}",
								properties: n,
								headers: n
							},
							type: e
						}
					],
					type: f
				}],
				type: f
			},
			{
				error: "Invalid Configuration: Missing Region",
				type: d
			}
		]
	};
	exports.ruleSet = _data;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sso/dist-cjs/endpoint/endpointResolver.js
var require_endpointResolver$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.defaultEndpointResolver = void 0;
	const util_endpoints_1 = require_dist_cjs$32();
	const util_endpoints_2 = require_dist_cjs$35();
	const ruleset_1 = require_ruleset$1();
	const cache = new util_endpoints_2.EndpointCache({
		size: 50,
		params: [
			"Endpoint",
			"Region",
			"UseDualStack",
			"UseFIPS"
		]
	});
	const defaultEndpointResolver = (endpointParams, context = {}) => {
		return cache.get(endpointParams, () => (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
			endpointParams,
			logger: context.logger
		}));
	};
	exports.defaultEndpointResolver = defaultEndpointResolver;
	util_endpoints_2.customEndpointFunctions.aws = util_endpoints_1.awsEndpointFunctions;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sso/dist-cjs/runtimeConfig.shared.js
var require_runtimeConfig_shared$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getRuntimeConfig = void 0;
	const core_1 = (init_dist_es(), __toCommonJS(dist_es_exports));
	const protocols_1 = (init_protocols(), __toCommonJS(protocols_exports));
	const core_2 = (init_dist_es$1(), __toCommonJS(dist_es_exports$1));
	const smithy_client_1 = require_dist_cjs$28();
	const url_parser_1 = require_dist_cjs$33();
	const util_base64_1 = require_dist_cjs$43();
	const util_utf8_1 = require_dist_cjs$44();
	const httpAuthSchemeProvider_1 = require_httpAuthSchemeProvider();
	const endpointResolver_1 = require_endpointResolver$1();
	const getRuntimeConfig = (config) => {
		return {
			apiVersion: "2019-06-10",
			base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
			base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
			disableHostPrefix: config?.disableHostPrefix ?? false,
			endpointProvider: config?.endpointProvider ?? endpointResolver_1.defaultEndpointResolver,
			extensions: config?.extensions ?? [],
			httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? httpAuthSchemeProvider_1.defaultSSOHttpAuthSchemeProvider,
			httpAuthSchemes: config?.httpAuthSchemes ?? [{
				schemeId: "aws.auth#sigv4",
				identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
				signer: new core_1.AwsSdkSigV4Signer()
			}, {
				schemeId: "smithy.api#noAuth",
				identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
				signer: new core_2.NoAuthSigner()
			}],
			logger: config?.logger ?? new smithy_client_1.NoOpLogger(),
			protocol: config?.protocol ?? protocols_1.AwsRestJsonProtocol,
			protocolSettings: config?.protocolSettings ?? {
				defaultNamespace: "com.amazonaws.sso",
				version: "2019-06-10",
				serviceTarget: "SWBPortalService"
			},
			serviceId: config?.serviceId ?? "SSO",
			urlParser: config?.urlParser ?? url_parser_1.parseUrl,
			utf8Decoder: config?.utf8Decoder ?? util_utf8_1.fromUtf8,
			utf8Encoder: config?.utf8Encoder ?? util_utf8_1.toUtf8
		};
	};
	exports.getRuntimeConfig = getRuntimeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sso/dist-cjs/runtimeConfig.js
var require_runtimeConfig$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getRuntimeConfig = void 0;
	const package_json_1 = (init_tslib_es6(), __toCommonJS(tslib_es6_exports)).__importDefault(require_package());
	const core_1 = (init_dist_es(), __toCommonJS(dist_es_exports));
	const util_user_agent_node_1 = require_dist_cjs$13();
	const config_resolver_1 = require_dist_cjs$24();
	const hash_node_1 = require_dist_cjs$12();
	const middleware_retry_1 = require_dist_cjs$17();
	const node_config_provider_1 = require_dist_cjs$21();
	const node_http_handler_1 = require_dist_cjs$40();
	const smithy_client_1 = require_dist_cjs$28();
	const util_body_length_node_1 = require_dist_cjs$11();
	const util_defaults_mode_node_1 = require_dist_cjs$10();
	const util_retry_1 = require_dist_cjs$18();
	const runtimeConfig_shared_1 = require_runtimeConfig_shared$1();
	const getRuntimeConfig = (config) => {
		(0, smithy_client_1.emitWarningIfUnsupportedVersion)(process.version);
		const defaultsMode = (0, util_defaults_mode_node_1.resolveDefaultsModeConfig)(config);
		const defaultConfigProvider = () => defaultsMode().then(smithy_client_1.loadConfigsForDefaultMode);
		const clientSharedValues = (0, runtimeConfig_shared_1.getRuntimeConfig)(config);
		(0, core_1.emitWarningIfUnsupportedVersion)(process.version);
		const loaderConfig = {
			profile: config?.profile,
			logger: clientSharedValues.logger
		};
		return {
			...clientSharedValues,
			...config,
			runtime: "node",
			defaultsMode,
			authSchemePreference: config?.authSchemePreference ?? (0, node_config_provider_1.loadConfig)(core_1.NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
			bodyLengthChecker: config?.bodyLengthChecker ?? util_body_length_node_1.calculateBodyLength,
			defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, util_user_agent_node_1.createDefaultUserAgentProvider)({
				serviceId: clientSharedValues.serviceId,
				clientVersion: package_json_1.default.version
			}),
			maxAttempts: config?.maxAttempts ?? (0, node_config_provider_1.loadConfig)(middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
			region: config?.region ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_REGION_CONFIG_OPTIONS, {
				...config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS,
				...loaderConfig
			}),
			requestHandler: node_http_handler_1.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
			retryMode: config?.retryMode ?? (0, node_config_provider_1.loadConfig)({
				...middleware_retry_1.NODE_RETRY_MODE_CONFIG_OPTIONS,
				default: async () => (await defaultConfigProvider()).retryMode || util_retry_1.DEFAULT_RETRY_MODE
			}, config),
			sha256: config?.sha256 ?? hash_node_1.Hash.bind(null, "sha256"),
			streamCollector: config?.streamCollector ?? node_http_handler_1.streamCollector,
			useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			useFipsEndpoint: config?.useFipsEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			userAgentAppId: config?.userAgentAppId ?? (0, node_config_provider_1.loadConfig)(util_user_agent_node_1.NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
		};
	};
	exports.getRuntimeConfig = getRuntimeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sso/dist-cjs/index.js
var require_dist_cjs$7 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var middlewareHostHeader = require_dist_cjs$51();
	var middlewareLogger = require_dist_cjs$50();
	var middlewareRecursionDetection = require_dist_cjs$49();
	var middlewareUserAgent = require_dist_cjs$26();
	var configResolver = require_dist_cjs$24();
	var core = (init_dist_es$1(), __toCommonJS(dist_es_exports$1));
	var schema = (init_schema(), __toCommonJS(schema_exports));
	var middlewareContentLength = require_dist_cjs$23();
	var middlewareEndpoint = require_dist_cjs$20();
	var middlewareRetry = require_dist_cjs$17();
	var smithyClient = require_dist_cjs$28();
	var httpAuthSchemeProvider = require_httpAuthSchemeProvider();
	var runtimeConfig = require_runtimeConfig$1();
	var regionConfigResolver = require_dist_cjs$9();
	var protocolHttp = require_dist_cjs$52();
	const resolveClientEndpointParameters = (options) => {
		return Object.assign(options, {
			useDualstackEndpoint: options.useDualstackEndpoint ?? false,
			useFipsEndpoint: options.useFipsEndpoint ?? false,
			defaultSigningName: "awsssoportal"
		});
	};
	const commonParams = {
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
	const resolveRuntimeExtensions = (runtimeConfig, extensions) => {
		const extensionConfiguration = Object.assign(regionConfigResolver.getAwsRegionExtensionConfiguration(runtimeConfig), smithyClient.getDefaultExtensionConfiguration(runtimeConfig), protocolHttp.getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
		extensions.forEach((extension) => extension.configure(extensionConfiguration));
		return Object.assign(runtimeConfig, regionConfigResolver.resolveAwsRegionExtensionConfiguration(extensionConfiguration), smithyClient.resolveDefaultRuntimeConfig(extensionConfiguration), protocolHttp.resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
	};
	var SSOClient = class extends smithyClient.Client {
		config;
		constructor(...[configuration]) {
			const _config_0 = runtimeConfig.getRuntimeConfig(configuration || {});
			super(_config_0);
			this.initConfig = _config_0;
			const _config_1 = resolveClientEndpointParameters(_config_0);
			const _config_2 = middlewareUserAgent.resolveUserAgentConfig(_config_1);
			const _config_3 = middlewareRetry.resolveRetryConfig(_config_2);
			const _config_4 = configResolver.resolveRegionConfig(_config_3);
			const _config_5 = middlewareHostHeader.resolveHostHeaderConfig(_config_4);
			const _config_6 = middlewareEndpoint.resolveEndpointConfig(_config_5);
			this.config = resolveRuntimeExtensions(httpAuthSchemeProvider.resolveHttpAuthSchemeConfig(_config_6), configuration?.extensions || []);
			this.middlewareStack.use(schema.getSchemaSerdePlugin(this.config));
			this.middlewareStack.use(middlewareUserAgent.getUserAgentPlugin(this.config));
			this.middlewareStack.use(middlewareRetry.getRetryPlugin(this.config));
			this.middlewareStack.use(middlewareContentLength.getContentLengthPlugin(this.config));
			this.middlewareStack.use(middlewareHostHeader.getHostHeaderPlugin(this.config));
			this.middlewareStack.use(middlewareLogger.getLoggerPlugin(this.config));
			this.middlewareStack.use(middlewareRecursionDetection.getRecursionDetectionPlugin(this.config));
			this.middlewareStack.use(core.getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
				httpAuthSchemeParametersProvider: httpAuthSchemeProvider.defaultSSOHttpAuthSchemeParametersProvider,
				identityProviderConfigProvider: async (config) => new core.DefaultIdentityProviderConfig({ "aws.auth#sigv4": config.credentials })
			}));
			this.middlewareStack.use(core.getHttpSigningPlugin(this.config));
		}
		destroy() {
			super.destroy();
		}
	};
	var SSOServiceException = class SSOServiceException extends smithyClient.ServiceException {
		constructor(options) {
			super(options);
			Object.setPrototypeOf(this, SSOServiceException.prototype);
		}
	};
	var InvalidRequestException = class InvalidRequestException extends SSOServiceException {
		name = "InvalidRequestException";
		$fault = "client";
		constructor(opts) {
			super({
				name: "InvalidRequestException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, InvalidRequestException.prototype);
		}
	};
	var ResourceNotFoundException = class ResourceNotFoundException extends SSOServiceException {
		name = "ResourceNotFoundException";
		$fault = "client";
		constructor(opts) {
			super({
				name: "ResourceNotFoundException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, ResourceNotFoundException.prototype);
		}
	};
	var TooManyRequestsException = class TooManyRequestsException extends SSOServiceException {
		name = "TooManyRequestsException";
		$fault = "client";
		constructor(opts) {
			super({
				name: "TooManyRequestsException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, TooManyRequestsException.prototype);
		}
	};
	var UnauthorizedException = class UnauthorizedException extends SSOServiceException {
		name = "UnauthorizedException";
		$fault = "client";
		constructor(opts) {
			super({
				name: "UnauthorizedException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, UnauthorizedException.prototype);
		}
	};
	const _AI = "AccountInfo";
	const _ALT = "AccountListType";
	const _ATT = "AccessTokenType";
	const _GRC = "GetRoleCredentials";
	const _GRCR = "GetRoleCredentialsRequest";
	const _GRCRe = "GetRoleCredentialsResponse";
	const _IRE = "InvalidRequestException";
	const _L = "Logout";
	const _LA = "ListAccounts";
	const _LAR = "ListAccountsRequest";
	const _LARR = "ListAccountRolesRequest";
	const _LARRi = "ListAccountRolesResponse";
	const _LARi = "ListAccountsResponse";
	const _LARis = "ListAccountRoles";
	const _LR = "LogoutRequest";
	const _RC = "RoleCredentials";
	const _RI = "RoleInfo";
	const _RLT = "RoleListType";
	const _RNFE = "ResourceNotFoundException";
	const _SAKT = "SecretAccessKeyType";
	const _STT = "SessionTokenType";
	const _TMRE = "TooManyRequestsException";
	const _UE = "UnauthorizedException";
	const _aI = "accountId";
	const _aKI = "accessKeyId";
	const _aL = "accountList";
	const _aN = "accountName";
	const _aT = "accessToken";
	const _ai = "account_id";
	const _c = "client";
	const _e = "error";
	const _eA = "emailAddress";
	const _ex = "expiration";
	const _h = "http";
	const _hE = "httpError";
	const _hH = "httpHeader";
	const _hQ = "httpQuery";
	const _m = "message";
	const _mR = "maxResults";
	const _mr = "max_result";
	const _nT = "nextToken";
	const _nt = "next_token";
	const _rC = "roleCredentials";
	const _rL = "roleList";
	const _rN = "roleName";
	const _rn = "role_name";
	const _s = "smithy.ts.sdk.synthetic.com.amazonaws.sso";
	const _sAK = "secretAccessKey";
	const _sT = "sessionToken";
	const _xasbt = "x-amz-sso_bearer_token";
	const n0 = "com.amazonaws.sso";
	var AccessTokenType = [
		0,
		n0,
		_ATT,
		8,
		0
	];
	var SecretAccessKeyType = [
		0,
		n0,
		_SAKT,
		8,
		0
	];
	var SessionTokenType = [
		0,
		n0,
		_STT,
		8,
		0
	];
	var AccountInfo$ = [
		3,
		n0,
		_AI,
		0,
		[
			_aI,
			_aN,
			_eA
		],
		[
			0,
			0,
			0
		]
	];
	var GetRoleCredentialsRequest$ = [
		3,
		n0,
		_GRCR,
		0,
		[
			_rN,
			_aI,
			_aT
		],
		[
			[0, { [_hQ]: _rn }],
			[0, { [_hQ]: _ai }],
			[() => AccessTokenType, { [_hH]: _xasbt }]
		]
	];
	var GetRoleCredentialsResponse$ = [
		3,
		n0,
		_GRCRe,
		0,
		[_rC],
		[[() => RoleCredentials$, 0]]
	];
	var InvalidRequestException$ = [
		-3,
		n0,
		_IRE,
		{
			[_e]: _c,
			[_hE]: 400
		},
		[_m],
		[0]
	];
	schema.TypeRegistry.for(n0).registerError(InvalidRequestException$, InvalidRequestException);
	var ListAccountRolesRequest$ = [
		3,
		n0,
		_LARR,
		0,
		[
			_nT,
			_mR,
			_aT,
			_aI
		],
		[
			[0, { [_hQ]: _nt }],
			[1, { [_hQ]: _mr }],
			[() => AccessTokenType, { [_hH]: _xasbt }],
			[0, { [_hQ]: _ai }]
		]
	];
	var ListAccountRolesResponse$ = [
		3,
		n0,
		_LARRi,
		0,
		[_nT, _rL],
		[0, () => RoleListType]
	];
	var ListAccountsRequest$ = [
		3,
		n0,
		_LAR,
		0,
		[
			_nT,
			_mR,
			_aT
		],
		[
			[0, { [_hQ]: _nt }],
			[1, { [_hQ]: _mr }],
			[() => AccessTokenType, { [_hH]: _xasbt }]
		]
	];
	var ListAccountsResponse$ = [
		3,
		n0,
		_LARi,
		0,
		[_nT, _aL],
		[0, () => AccountListType]
	];
	var LogoutRequest$ = [
		3,
		n0,
		_LR,
		0,
		[_aT],
		[[() => AccessTokenType, { [_hH]: _xasbt }]]
	];
	var ResourceNotFoundException$ = [
		-3,
		n0,
		_RNFE,
		{
			[_e]: _c,
			[_hE]: 404
		},
		[_m],
		[0]
	];
	schema.TypeRegistry.for(n0).registerError(ResourceNotFoundException$, ResourceNotFoundException);
	var RoleCredentials$ = [
		3,
		n0,
		_RC,
		0,
		[
			_aKI,
			_sAK,
			_sT,
			_ex
		],
		[
			0,
			[() => SecretAccessKeyType, 0],
			[() => SessionTokenType, 0],
			1
		]
	];
	var RoleInfo$ = [
		3,
		n0,
		_RI,
		0,
		[_rN, _aI],
		[0, 0]
	];
	var TooManyRequestsException$ = [
		-3,
		n0,
		_TMRE,
		{
			[_e]: _c,
			[_hE]: 429
		},
		[_m],
		[0]
	];
	schema.TypeRegistry.for(n0).registerError(TooManyRequestsException$, TooManyRequestsException);
	var UnauthorizedException$ = [
		-3,
		n0,
		_UE,
		{
			[_e]: _c,
			[_hE]: 401
		},
		[_m],
		[0]
	];
	schema.TypeRegistry.for(n0).registerError(UnauthorizedException$, UnauthorizedException);
	var __Unit = "unit";
	var SSOServiceException$ = [
		-3,
		_s,
		"SSOServiceException",
		0,
		[],
		[]
	];
	schema.TypeRegistry.for(_s).registerError(SSOServiceException$, SSOServiceException);
	var AccountListType = [
		1,
		n0,
		_ALT,
		0,
		() => AccountInfo$
	];
	var RoleListType = [
		1,
		n0,
		_RLT,
		0,
		() => RoleInfo$
	];
	var GetRoleCredentials$ = [
		9,
		n0,
		_GRC,
		{ [_h]: [
			"GET",
			"/federation/credentials",
			200
		] },
		() => GetRoleCredentialsRequest$,
		() => GetRoleCredentialsResponse$
	];
	var ListAccountRoles$ = [
		9,
		n0,
		_LARis,
		{ [_h]: [
			"GET",
			"/assignment/roles",
			200
		] },
		() => ListAccountRolesRequest$,
		() => ListAccountRolesResponse$
	];
	var ListAccounts$ = [
		9,
		n0,
		_LA,
		{ [_h]: [
			"GET",
			"/assignment/accounts",
			200
		] },
		() => ListAccountsRequest$,
		() => ListAccountsResponse$
	];
	var Logout$ = [
		9,
		n0,
		_L,
		{ [_h]: [
			"POST",
			"/logout",
			200
		] },
		() => LogoutRequest$,
		() => __Unit
	];
	var GetRoleCredentialsCommand = class extends smithyClient.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("SWBPortalService", "GetRoleCredentials", {}).n("SSOClient", "GetRoleCredentialsCommand").sc(GetRoleCredentials$).build() {};
	var ListAccountRolesCommand = class extends smithyClient.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("SWBPortalService", "ListAccountRoles", {}).n("SSOClient", "ListAccountRolesCommand").sc(ListAccountRoles$).build() {};
	var ListAccountsCommand = class extends smithyClient.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("SWBPortalService", "ListAccounts", {}).n("SSOClient", "ListAccountsCommand").sc(ListAccounts$).build() {};
	var LogoutCommand = class extends smithyClient.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("SWBPortalService", "Logout", {}).n("SSOClient", "LogoutCommand").sc(Logout$).build() {};
	const commands = {
		GetRoleCredentialsCommand,
		ListAccountRolesCommand,
		ListAccountsCommand,
		LogoutCommand
	};
	var SSO = class extends SSOClient {};
	smithyClient.createAggregatedClient(commands, SSO);
	const paginateListAccountRoles = core.createPaginator(SSOClient, ListAccountRolesCommand, "nextToken", "nextToken", "maxResults");
	const paginateListAccounts = core.createPaginator(SSOClient, ListAccountsCommand, "nextToken", "nextToken", "maxResults");
	Object.defineProperty(exports, "$Command", {
		enumerable: true,
		get: function() {
			return smithyClient.Command;
		}
	});
	Object.defineProperty(exports, "__Client", {
		enumerable: true,
		get: function() {
			return smithyClient.Client;
		}
	});
	exports.AccountInfo$ = AccountInfo$;
	exports.GetRoleCredentials$ = GetRoleCredentials$;
	exports.GetRoleCredentialsCommand = GetRoleCredentialsCommand;
	exports.GetRoleCredentialsRequest$ = GetRoleCredentialsRequest$;
	exports.GetRoleCredentialsResponse$ = GetRoleCredentialsResponse$;
	exports.InvalidRequestException = InvalidRequestException;
	exports.InvalidRequestException$ = InvalidRequestException$;
	exports.ListAccountRoles$ = ListAccountRoles$;
	exports.ListAccountRolesCommand = ListAccountRolesCommand;
	exports.ListAccountRolesRequest$ = ListAccountRolesRequest$;
	exports.ListAccountRolesResponse$ = ListAccountRolesResponse$;
	exports.ListAccounts$ = ListAccounts$;
	exports.ListAccountsCommand = ListAccountsCommand;
	exports.ListAccountsRequest$ = ListAccountsRequest$;
	exports.ListAccountsResponse$ = ListAccountsResponse$;
	exports.Logout$ = Logout$;
	exports.LogoutCommand = LogoutCommand;
	exports.LogoutRequest$ = LogoutRequest$;
	exports.ResourceNotFoundException = ResourceNotFoundException;
	exports.ResourceNotFoundException$ = ResourceNotFoundException$;
	exports.RoleCredentials$ = RoleCredentials$;
	exports.RoleInfo$ = RoleInfo$;
	exports.SSO = SSO;
	exports.SSOClient = SSOClient;
	exports.SSOServiceException = SSOServiceException;
	exports.SSOServiceException$ = SSOServiceException$;
	exports.TooManyRequestsException = TooManyRequestsException;
	exports.TooManyRequestsException$ = TooManyRequestsException$;
	exports.UnauthorizedException = UnauthorizedException;
	exports.UnauthorizedException$ = UnauthorizedException$;
	exports.paginateListAccountRoles = paginateListAccountRoles;
	exports.paginateListAccounts = paginateListAccounts;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-sso/dist-cjs/loadSso-CVy8iqsZ.js
var require_loadSso_CVy8iqsZ = /* @__PURE__ */ __commonJSMin(((exports) => {
	var clientSso = require_dist_cjs$7();
	Object.defineProperty(exports, "GetRoleCredentialsCommand", {
		enumerable: true,
		get: function() {
			return clientSso.GetRoleCredentialsCommand;
		}
	});
	Object.defineProperty(exports, "SSOClient", {
		enumerable: true,
		get: function() {
			return clientSso.SSOClient;
		}
	});
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-sso/dist-cjs/index.js
var require_dist_cjs$6 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var propertyProvider = require_dist_cjs$31();
	var sharedIniFileLoader = require_dist_cjs$22();
	var client = (init_client(), __toCommonJS(client_exports));
	var tokenProviders = require_dist_cjs$8();
	const isSsoProfile = (arg) => arg && (typeof arg.sso_start_url === "string" || typeof arg.sso_account_id === "string" || typeof arg.sso_session === "string" || typeof arg.sso_region === "string" || typeof arg.sso_role_name === "string");
	const SHOULD_FAIL_CREDENTIAL_CHAIN = false;
	const resolveSSOCredentials = async ({ ssoStartUrl, ssoSession, ssoAccountId, ssoRegion, ssoRoleName, ssoClient, clientConfig, parentClientConfig, callerClientConfig, profile, filepath, configFilepath, ignoreCache, logger: logger$1 }) => {
		let token;
		const refreshMessage = `To refresh this SSO session run aws sso login with the corresponding profile.`;
		if (ssoSession) try {
			const _token = await tokenProviders.fromSso({
				profile,
				filepath,
				configFilepath,
				ignoreCache
			})();
			token = {
				accessToken: _token.token,
				expiresAt: new Date(_token.expiration).toISOString()
			};
		} catch (e$3) {
			throw new propertyProvider.CredentialsProviderError(e$3.message, {
				tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
				logger: logger$1
			});
		}
		else try {
			token = await sharedIniFileLoader.getSSOTokenFromFile(ssoStartUrl);
		} catch (e$3) {
			throw new propertyProvider.CredentialsProviderError(`The SSO session associated with this profile is invalid. ${refreshMessage}`, {
				tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
				logger: logger$1
			});
		}
		if (new Date(token.expiresAt).getTime() - Date.now() <= 0) throw new propertyProvider.CredentialsProviderError(`The SSO session associated with this profile has expired. ${refreshMessage}`, {
			tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
			logger: logger$1
		});
		const { accessToken } = token;
		const { SSOClient, GetRoleCredentialsCommand } = await Promise.resolve().then(function() {
			return require_loadSso_CVy8iqsZ();
		});
		const sso = ssoClient || new SSOClient(Object.assign({}, clientConfig ?? {}, {
			logger: clientConfig?.logger ?? callerClientConfig?.logger ?? parentClientConfig?.logger,
			region: clientConfig?.region ?? ssoRegion,
			userAgentAppId: clientConfig?.userAgentAppId ?? callerClientConfig?.userAgentAppId ?? parentClientConfig?.userAgentAppId
		}));
		let ssoResp;
		try {
			ssoResp = await sso.send(new GetRoleCredentialsCommand({
				accountId: ssoAccountId,
				roleName: ssoRoleName,
				accessToken
			}));
		} catch (e$3) {
			throw new propertyProvider.CredentialsProviderError(e$3, {
				tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
				logger: logger$1
			});
		}
		const { roleCredentials: { accessKeyId, secretAccessKey, sessionToken, expiration, credentialScope, accountId } = {} } = ssoResp;
		if (!accessKeyId || !secretAccessKey || !sessionToken || !expiration) throw new propertyProvider.CredentialsProviderError("SSO returns an invalid temporary credential.", {
			tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
			logger: logger$1
		});
		const credentials = {
			accessKeyId,
			secretAccessKey,
			sessionToken,
			expiration: new Date(expiration),
			...credentialScope && { credentialScope },
			...accountId && { accountId }
		};
		if (ssoSession) client.setCredentialFeature(credentials, "CREDENTIALS_SSO", "s");
		else client.setCredentialFeature(credentials, "CREDENTIALS_SSO_LEGACY", "u");
		return credentials;
	};
	const validateSsoProfile = (profile, logger$1) => {
		const { sso_start_url, sso_account_id, sso_region, sso_role_name } = profile;
		if (!sso_start_url || !sso_account_id || !sso_region || !sso_role_name) throw new propertyProvider.CredentialsProviderError(`Profile is configured with invalid SSO credentials. Required parameters "sso_account_id", "sso_region", "sso_role_name", "sso_start_url". Got ${Object.keys(profile).join(", ")}\nReference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html`, {
			tryNextLink: false,
			logger: logger$1
		});
		return profile;
	};
	const fromSSO = (init = {}) => async ({ callerClientConfig } = {}) => {
		init.logger?.debug("@aws-sdk/credential-provider-sso - fromSSO");
		const { ssoStartUrl, ssoAccountId, ssoRegion, ssoRoleName, ssoSession } = init;
		const { ssoClient } = init;
		const profileName = sharedIniFileLoader.getProfileName({ profile: init.profile ?? callerClientConfig?.profile });
		if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) {
			const profile = (await sharedIniFileLoader.parseKnownFiles(init))[profileName];
			if (!profile) throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} was not found.`, { logger: init.logger });
			if (!isSsoProfile(profile)) throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} is not configured with SSO credentials.`, { logger: init.logger });
			if (profile?.sso_session) {
				const session = (await sharedIniFileLoader.loadSsoSessionData(init))[profile.sso_session];
				const conflictMsg = ` configurations in profile ${profileName} and sso-session ${profile.sso_session}`;
				if (ssoRegion && ssoRegion !== session.sso_region) throw new propertyProvider.CredentialsProviderError(`Conflicting SSO region` + conflictMsg, {
					tryNextLink: false,
					logger: init.logger
				});
				if (ssoStartUrl && ssoStartUrl !== session.sso_start_url) throw new propertyProvider.CredentialsProviderError(`Conflicting SSO start_url` + conflictMsg, {
					tryNextLink: false,
					logger: init.logger
				});
				profile.sso_region = session.sso_region;
				profile.sso_start_url = session.sso_start_url;
			}
			const { sso_start_url, sso_account_id, sso_region, sso_role_name, sso_session } = validateSsoProfile(profile, init.logger);
			return resolveSSOCredentials({
				ssoStartUrl: sso_start_url,
				ssoSession: sso_session,
				ssoAccountId: sso_account_id,
				ssoRegion: sso_region,
				ssoRoleName: sso_role_name,
				ssoClient,
				clientConfig: init.clientConfig,
				parentClientConfig: init.parentClientConfig,
				callerClientConfig: init.callerClientConfig,
				profile: profileName,
				filepath: init.filepath,
				configFilepath: init.configFilepath,
				ignoreCache: init.ignoreCache,
				logger: init.logger
			});
		} else if (!ssoStartUrl || !ssoAccountId || !ssoRegion || !ssoRoleName) throw new propertyProvider.CredentialsProviderError("Incomplete configuration. The fromSSO() argument hash must include \"ssoStartUrl\", \"ssoAccountId\", \"ssoRegion\", \"ssoRoleName\"", {
			tryNextLink: false,
			logger: init.logger
		});
		else return resolveSSOCredentials({
			ssoStartUrl,
			ssoSession,
			ssoAccountId,
			ssoRegion,
			ssoRoleName,
			ssoClient,
			clientConfig: init.clientConfig,
			parentClientConfig: init.parentClientConfig,
			callerClientConfig: init.callerClientConfig,
			profile: profileName,
			filepath: init.filepath,
			configFilepath: init.configFilepath,
			ignoreCache: init.ignoreCache,
			logger: init.logger
		});
	};
	exports.fromSSO = fromSSO;
	exports.isSsoProfile = isSsoProfile;
	exports.validateSsoProfile = validateSsoProfile;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption$1(authParameters) {
	return {
		schemeId: "aws.auth#sigv4",
		signingProperties: {
			name: "signin",
			region: authParameters.region
		},
		propertiesExtractor: (config, context) => ({ signingProperties: {
			config,
			context
		} })
	};
}
function createSmithyApiNoAuthHttpAuthOption$1(authParameters) {
	return { schemeId: "smithy.api#noAuth" };
}
var import_dist_cjs$69, defaultSigninHttpAuthSchemeParametersProvider, defaultSigninHttpAuthSchemeProvider, resolveHttpAuthSchemeConfig$1;
var init_httpAuthSchemeProvider$1 = __esmMin((() => {
	init_dist_es();
	import_dist_cjs$69 = require_dist_cjs$48();
	defaultSigninHttpAuthSchemeParametersProvider = async (config, context, input) => {
		return {
			operation: (0, import_dist_cjs$69.getSmithyContext)(context).operation,
			region: await (0, import_dist_cjs$69.normalizeProvider)(config.region)() || (() => {
				throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
			})()
		};
	};
	defaultSigninHttpAuthSchemeProvider = (authParameters) => {
		const options = [];
		switch (authParameters.operation) {
			case "CreateOAuth2Token":
				options.push(createSmithyApiNoAuthHttpAuthOption$1(authParameters));
				break;
			default: options.push(createAwsAuthSigv4HttpAuthOption$1(authParameters));
		}
		return options;
	};
	resolveHttpAuthSchemeConfig$1 = (config) => {
		const config_0 = resolveAwsSdkSigV4Config(config);
		return Object.assign(config_0, { authSchemePreference: (0, import_dist_cjs$69.normalizeProvider)(config.authSchemePreference ?? []) });
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/EndpointParameters.js
var resolveClientEndpointParameters$1, commonParams$1;
var init_EndpointParameters$1 = __esmMin((() => {
	resolveClientEndpointParameters$1 = (options) => {
		return Object.assign(options, {
			useDualstackEndpoint: options.useDualstackEndpoint ?? false,
			useFipsEndpoint: options.useFipsEndpoint ?? false,
			defaultSigningName: "signin"
		});
	};
	commonParams$1 = {
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
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/ruleset.js
var u$1, v$1, w$1, x$1, a$1, b$1, c$1, d$1, e$1, f$1, g$1, h$1, i$1, j$1, k$1, l$1, m$1, n$1, o$1, p$1, q$1, r$1, s$1, t$1, _data$1, ruleSet$1;
var init_ruleset$1 = __esmMin((() => {
	u$1 = "required", v$1 = "fn", w$1 = "argv", x$1 = "ref";
	a$1 = true, b$1 = "isSet", c$1 = "booleanEquals", d$1 = "error", e$1 = "endpoint", f$1 = "tree", g$1 = "PartitionResult", h$1 = "stringEquals", i$1 = {
		[u$1]: true,
		"default": false,
		"type": "boolean"
	}, j$1 = {
		[u$1]: false,
		"type": "string"
	}, k$1 = { [x$1]: "Endpoint" }, l$1 = {
		[v$1]: c$1,
		[w$1]: [{ [x$1]: "UseFIPS" }, true]
	}, m$1 = {
		[v$1]: c$1,
		[w$1]: [{ [x$1]: "UseDualStack" }, true]
	}, n$1 = {}, o$1 = {
		[v$1]: "getAttr",
		[w$1]: [{ [x$1]: g$1 }, "name"]
	}, p$1 = {
		[v$1]: c$1,
		[w$1]: [{ [x$1]: "UseFIPS" }, false]
	}, q$1 = {
		[v$1]: c$1,
		[w$1]: [{ [x$1]: "UseDualStack" }, false]
	}, r$1 = {
		[v$1]: "getAttr",
		[w$1]: [{ [x$1]: g$1 }, "supportsFIPS"]
	}, s$1 = {
		[v$1]: c$1,
		[w$1]: [true, {
			[v$1]: "getAttr",
			[w$1]: [{ [x$1]: g$1 }, "supportsDualStack"]
		}]
	}, t$1 = [{ [x$1]: "Region" }];
	_data$1 = {
		version: "1.0",
		parameters: {
			UseDualStack: i$1,
			UseFIPS: i$1,
			Endpoint: j$1,
			Region: j$1
		},
		rules: [{
			conditions: [{
				[v$1]: b$1,
				[w$1]: [k$1]
			}],
			rules: [{
				conditions: [l$1],
				error: "Invalid Configuration: FIPS and custom endpoint are not supported",
				type: d$1
			}, {
				rules: [{
					conditions: [m$1],
					error: "Invalid Configuration: Dualstack and custom endpoint are not supported",
					type: d$1
				}, {
					endpoint: {
						url: k$1,
						properties: n$1,
						headers: n$1
					},
					type: e$1
				}],
				type: f$1
			}],
			type: f$1
		}, {
			rules: [{
				conditions: [{
					[v$1]: b$1,
					[w$1]: t$1
				}],
				rules: [{
					conditions: [{
						[v$1]: "aws.partition",
						[w$1]: t$1,
						assign: g$1
					}],
					rules: [
						{
							conditions: [
								{
									[v$1]: h$1,
									[w$1]: [o$1, "aws"]
								},
								p$1,
								q$1
							],
							endpoint: {
								url: "https://{Region}.signin.aws.amazon.com",
								properties: n$1,
								headers: n$1
							},
							type: e$1
						},
						{
							conditions: [
								{
									[v$1]: h$1,
									[w$1]: [o$1, "aws-cn"]
								},
								p$1,
								q$1
							],
							endpoint: {
								url: "https://{Region}.signin.amazonaws.cn",
								properties: n$1,
								headers: n$1
							},
							type: e$1
						},
						{
							conditions: [
								{
									[v$1]: h$1,
									[w$1]: [o$1, "aws-us-gov"]
								},
								p$1,
								q$1
							],
							endpoint: {
								url: "https://{Region}.signin.amazonaws-us-gov.com",
								properties: n$1,
								headers: n$1
							},
							type: e$1
						},
						{
							conditions: [l$1, m$1],
							rules: [{
								conditions: [{
									[v$1]: c$1,
									[w$1]: [a$1, r$1]
								}, s$1],
								rules: [{
									endpoint: {
										url: "https://signin-fips.{Region}.{PartitionResult#dualStackDnsSuffix}",
										properties: n$1,
										headers: n$1
									},
									type: e$1
								}],
								type: f$1
							}, {
								error: "FIPS and DualStack are enabled, but this partition does not support one or both",
								type: d$1
							}],
							type: f$1
						},
						{
							conditions: [l$1, q$1],
							rules: [{
								conditions: [{
									[v$1]: c$1,
									[w$1]: [r$1, a$1]
								}],
								rules: [{
									endpoint: {
										url: "https://signin-fips.{Region}.{PartitionResult#dnsSuffix}",
										properties: n$1,
										headers: n$1
									},
									type: e$1
								}],
								type: f$1
							}, {
								error: "FIPS is enabled but this partition does not support FIPS",
								type: d$1
							}],
							type: f$1
						},
						{
							conditions: [p$1, m$1],
							rules: [{
								conditions: [s$1],
								rules: [{
									endpoint: {
										url: "https://signin.{Region}.{PartitionResult#dualStackDnsSuffix}",
										properties: n$1,
										headers: n$1
									},
									type: e$1
								}],
								type: f$1
							}, {
								error: "DualStack is enabled but this partition does not support DualStack",
								type: d$1
							}],
							type: f$1
						},
						{
							endpoint: {
								url: "https://signin.{Region}.{PartitionResult#dnsSuffix}",
								properties: n$1,
								headers: n$1
							},
							type: e$1
						}
					],
					type: f$1
				}],
				type: f$1
			}, {
				error: "Invalid Configuration: Missing Region",
				type: d$1
			}],
			type: f$1
		}]
	};
	ruleSet$1 = _data$1;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/endpointResolver.js
var import_dist_cjs$67, import_dist_cjs$68, cache$1, defaultEndpointResolver$1;
var init_endpointResolver$1 = __esmMin((() => {
	import_dist_cjs$67 = require_dist_cjs$32();
	import_dist_cjs$68 = require_dist_cjs$35();
	init_ruleset$1();
	cache$1 = new import_dist_cjs$68.EndpointCache({
		size: 50,
		params: [
			"Endpoint",
			"Region",
			"UseDualStack",
			"UseFIPS"
		]
	});
	defaultEndpointResolver$1 = (endpointParams, context = {}) => {
		return cache$1.get(endpointParams, () => (0, import_dist_cjs$68.resolveEndpoint)(ruleSet$1, {
			endpointParams,
			logger: context.logger
		}));
	};
	import_dist_cjs$68.customEndpointFunctions.aws = import_dist_cjs$67.awsEndpointFunctions;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.shared.js
var import_dist_cjs$63, import_dist_cjs$64, import_dist_cjs$65, import_dist_cjs$66, getRuntimeConfig$3;
var init_runtimeConfig_shared$1 = __esmMin((() => {
	init_dist_es();
	init_protocols();
	init_dist_es$1();
	import_dist_cjs$63 = require_dist_cjs$28();
	import_dist_cjs$64 = require_dist_cjs$33();
	import_dist_cjs$65 = require_dist_cjs$43();
	import_dist_cjs$66 = require_dist_cjs$44();
	init_httpAuthSchemeProvider$1();
	init_endpointResolver$1();
	getRuntimeConfig$3 = (config) => {
		return {
			apiVersion: "2023-01-01",
			base64Decoder: config?.base64Decoder ?? import_dist_cjs$65.fromBase64,
			base64Encoder: config?.base64Encoder ?? import_dist_cjs$65.toBase64,
			disableHostPrefix: config?.disableHostPrefix ?? false,
			endpointProvider: config?.endpointProvider ?? defaultEndpointResolver$1,
			extensions: config?.extensions ?? [],
			httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSigninHttpAuthSchemeProvider,
			httpAuthSchemes: config?.httpAuthSchemes ?? [{
				schemeId: "aws.auth#sigv4",
				identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
				signer: new AwsSdkSigV4Signer()
			}, {
				schemeId: "smithy.api#noAuth",
				identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
				signer: new NoAuthSigner()
			}],
			logger: config?.logger ?? new import_dist_cjs$63.NoOpLogger(),
			protocol: config?.protocol ?? AwsRestJsonProtocol,
			protocolSettings: config?.protocolSettings ?? {
				defaultNamespace: "com.amazonaws.signin",
				version: "2023-01-01",
				serviceTarget: "Signin"
			},
			serviceId: config?.serviceId ?? "Signin",
			urlParser: config?.urlParser ?? import_dist_cjs$64.parseUrl,
			utf8Decoder: config?.utf8Decoder ?? import_dist_cjs$66.fromUtf8,
			utf8Encoder: config?.utf8Encoder ?? import_dist_cjs$66.toUtf8
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.js
var import_dist_cjs$53, import_dist_cjs$54, import_dist_cjs$55, import_dist_cjs$56, import_dist_cjs$57, import_dist_cjs$58, import_dist_cjs$59, import_dist_cjs$60, import_dist_cjs$61, import_dist_cjs$62, getRuntimeConfig$2;
var init_runtimeConfig$1 = __esmMin((() => {
	init_dist_es();
	import_dist_cjs$53 = require_dist_cjs$13();
	import_dist_cjs$54 = require_dist_cjs$24();
	import_dist_cjs$55 = require_dist_cjs$12();
	import_dist_cjs$56 = require_dist_cjs$17();
	import_dist_cjs$57 = require_dist_cjs$21();
	import_dist_cjs$58 = require_dist_cjs$40();
	import_dist_cjs$59 = require_dist_cjs$28();
	import_dist_cjs$60 = require_dist_cjs$11();
	import_dist_cjs$61 = require_dist_cjs$10();
	import_dist_cjs$62 = require_dist_cjs$18();
	init_runtimeConfig_shared$1();
	getRuntimeConfig$2 = (config) => {
		(0, import_dist_cjs$59.emitWarningIfUnsupportedVersion)(process.version);
		const defaultsMode = (0, import_dist_cjs$61.resolveDefaultsModeConfig)(config);
		const defaultConfigProvider = () => defaultsMode().then(import_dist_cjs$59.loadConfigsForDefaultMode);
		const clientSharedValues = getRuntimeConfig$3(config);
		emitWarningIfUnsupportedVersion$3(process.version);
		const loaderConfig = {
			profile: config?.profile,
			logger: clientSharedValues.logger
		};
		return {
			...clientSharedValues,
			...config,
			runtime: "node",
			defaultsMode,
			authSchemePreference: config?.authSchemePreference ?? (0, import_dist_cjs$57.loadConfig)(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
			bodyLengthChecker: config?.bodyLengthChecker ?? import_dist_cjs$60.calculateBodyLength,
			defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, import_dist_cjs$53.createDefaultUserAgentProvider)({
				serviceId: clientSharedValues.serviceId,
				clientVersion: version
			}),
			maxAttempts: config?.maxAttempts ?? (0, import_dist_cjs$57.loadConfig)(import_dist_cjs$56.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
			region: config?.region ?? (0, import_dist_cjs$57.loadConfig)(import_dist_cjs$54.NODE_REGION_CONFIG_OPTIONS, {
				...import_dist_cjs$54.NODE_REGION_CONFIG_FILE_OPTIONS,
				...loaderConfig
			}),
			requestHandler: import_dist_cjs$58.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
			retryMode: config?.retryMode ?? (0, import_dist_cjs$57.loadConfig)({
				...import_dist_cjs$56.NODE_RETRY_MODE_CONFIG_OPTIONS,
				default: async () => (await defaultConfigProvider()).retryMode || import_dist_cjs$62.DEFAULT_RETRY_MODE
			}, config),
			sha256: config?.sha256 ?? import_dist_cjs$55.Hash.bind(null, "sha256"),
			streamCollector: config?.streamCollector ?? import_dist_cjs$58.streamCollector,
			useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, import_dist_cjs$57.loadConfig)(import_dist_cjs$54.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			useFipsEndpoint: config?.useFipsEndpoint ?? (0, import_dist_cjs$57.loadConfig)(import_dist_cjs$54.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			userAgentAppId: config?.userAgentAppId ?? (0, import_dist_cjs$57.loadConfig)(import_dist_cjs$53.NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration$1, resolveHttpAuthRuntimeConfig$1;
var init_httpAuthExtensionConfiguration$1 = __esmMin((() => {
	getHttpAuthExtensionConfiguration$1 = (runtimeConfig) => {
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
	resolveHttpAuthRuntimeConfig$1 = (config) => {
		return {
			httpAuthSchemes: config.httpAuthSchemes(),
			httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
			credentials: config.credentials()
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeExtensions.js
var import_dist_cjs$50, import_dist_cjs$51, import_dist_cjs$52, resolveRuntimeExtensions$1;
var init_runtimeExtensions$1 = __esmMin((() => {
	import_dist_cjs$50 = require_dist_cjs$9();
	import_dist_cjs$51 = require_dist_cjs$52();
	import_dist_cjs$52 = require_dist_cjs$28();
	init_httpAuthExtensionConfiguration$1();
	resolveRuntimeExtensions$1 = (runtimeConfig, extensions) => {
		const extensionConfiguration = Object.assign((0, import_dist_cjs$50.getAwsRegionExtensionConfiguration)(runtimeConfig), (0, import_dist_cjs$52.getDefaultExtensionConfiguration)(runtimeConfig), (0, import_dist_cjs$51.getHttpHandlerExtensionConfiguration)(runtimeConfig), getHttpAuthExtensionConfiguration$1(runtimeConfig));
		extensions.forEach((extension) => extension.configure(extensionConfiguration));
		return Object.assign(runtimeConfig, (0, import_dist_cjs$50.resolveAwsRegionExtensionConfiguration)(extensionConfiguration), (0, import_dist_cjs$52.resolveDefaultRuntimeConfig)(extensionConfiguration), (0, import_dist_cjs$51.resolveHttpHandlerRuntimeConfig)(extensionConfiguration), resolveHttpAuthRuntimeConfig$1(extensionConfiguration));
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/SigninClient.js
var import_dist_cjs$41, import_dist_cjs$42, import_dist_cjs$43, import_dist_cjs$44, import_dist_cjs$45, import_dist_cjs$46, import_dist_cjs$47, import_dist_cjs$48, import_dist_cjs$49, SigninClient;
var init_SigninClient = __esmMin((() => {
	import_dist_cjs$41 = require_dist_cjs$51();
	import_dist_cjs$42 = require_dist_cjs$50();
	import_dist_cjs$43 = require_dist_cjs$49();
	import_dist_cjs$44 = require_dist_cjs$26();
	import_dist_cjs$45 = require_dist_cjs$24();
	init_dist_es$1();
	init_schema();
	import_dist_cjs$46 = require_dist_cjs$23();
	import_dist_cjs$47 = require_dist_cjs$20();
	import_dist_cjs$48 = require_dist_cjs$17();
	import_dist_cjs$49 = require_dist_cjs$28();
	init_httpAuthSchemeProvider$1();
	init_EndpointParameters$1();
	init_runtimeConfig$1();
	init_runtimeExtensions$1();
	SigninClient = class extends import_dist_cjs$49.Client {
		config;
		constructor(...[configuration]) {
			const _config_0 = getRuntimeConfig$2(configuration || {});
			super(_config_0);
			this.initConfig = _config_0;
			this.config = resolveRuntimeExtensions$1(resolveHttpAuthSchemeConfig$1((0, import_dist_cjs$47.resolveEndpointConfig)((0, import_dist_cjs$41.resolveHostHeaderConfig)((0, import_dist_cjs$45.resolveRegionConfig)((0, import_dist_cjs$48.resolveRetryConfig)((0, import_dist_cjs$44.resolveUserAgentConfig)(resolveClientEndpointParameters$1(_config_0))))))), configuration?.extensions || []);
			this.middlewareStack.use(getSchemaSerdePlugin(this.config));
			this.middlewareStack.use((0, import_dist_cjs$44.getUserAgentPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$48.getRetryPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$46.getContentLengthPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$41.getHostHeaderPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$42.getLoggerPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$43.getRecursionDetectionPlugin)(this.config));
			this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
				httpAuthSchemeParametersProvider: defaultSigninHttpAuthSchemeParametersProvider,
				identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({ "aws.auth#sigv4": config.credentials })
			}));
			this.middlewareStack.use(getHttpSigningPlugin(this.config));
		}
		destroy() {
			super.destroy();
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/SigninServiceException.js
var import_dist_cjs$40, SigninServiceException;
var init_SigninServiceException = __esmMin((() => {
	import_dist_cjs$40 = require_dist_cjs$28();
	SigninServiceException = class SigninServiceException extends import_dist_cjs$40.ServiceException {
		constructor(options) {
			super(options);
			Object.setPrototypeOf(this, SigninServiceException.prototype);
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/errors.js
var AccessDeniedException, InternalServerException, TooManyRequestsError, ValidationException;
var init_errors$1 = __esmMin((() => {
	init_SigninServiceException();
	AccessDeniedException = class AccessDeniedException extends SigninServiceException {
		name = "AccessDeniedException";
		$fault = "client";
		error;
		constructor(opts) {
			super({
				name: "AccessDeniedException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, AccessDeniedException.prototype);
			this.error = opts.error;
		}
	};
	InternalServerException = class InternalServerException extends SigninServiceException {
		name = "InternalServerException";
		$fault = "server";
		error;
		constructor(opts) {
			super({
				name: "InternalServerException",
				$fault: "server",
				...opts
			});
			Object.setPrototypeOf(this, InternalServerException.prototype);
			this.error = opts.error;
		}
	};
	TooManyRequestsError = class TooManyRequestsError extends SigninServiceException {
		name = "TooManyRequestsError";
		$fault = "client";
		error;
		constructor(opts) {
			super({
				name: "TooManyRequestsError",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, TooManyRequestsError.prototype);
			this.error = opts.error;
		}
	};
	ValidationException = class ValidationException extends SigninServiceException {
		name = "ValidationException";
		$fault = "client";
		error;
		constructor(opts) {
			super({
				name: "ValidationException",
				$fault: "client",
				...opts
			});
			Object.setPrototypeOf(this, ValidationException.prototype);
			this.error = opts.error;
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/schemas/schemas_0.js
var _ADE, _AT, _COAT, _COATR, _COATRB, _COATRBr, _COATRr, _ISE, _RT, _TMRE, _VE, _aKI, _aT, _c$1, _cI, _cV, _co, _e$1, _eI, _gT, _h, _hE$1, _iT, _jN, _m$1, _rT, _rU, _s$1, _sAK, _sT, _sm, _tI, _tO, _tT, n0$1, RefreshToken, AccessDeniedException$, AccessToken$, CreateOAuth2TokenRequest$, CreateOAuth2TokenRequestBody$, CreateOAuth2TokenResponse$, CreateOAuth2TokenResponseBody$, InternalServerException$, TooManyRequestsError$, ValidationException$, SigninServiceException$, CreateOAuth2Token$;
var init_schemas_0$1 = __esmMin((() => {
	init_schema();
	init_errors$1();
	init_SigninServiceException();
	_ADE = "AccessDeniedException";
	_AT = "AccessToken";
	_COAT = "CreateOAuth2Token";
	_COATR = "CreateOAuth2TokenRequest";
	_COATRB = "CreateOAuth2TokenRequestBody";
	_COATRBr = "CreateOAuth2TokenResponseBody";
	_COATRr = "CreateOAuth2TokenResponse";
	_ISE = "InternalServerException";
	_RT = "RefreshToken";
	_TMRE = "TooManyRequestsError";
	_VE = "ValidationException";
	_aKI = "accessKeyId";
	_aT = "accessToken";
	_c$1 = "client";
	_cI = "clientId";
	_cV = "codeVerifier";
	_co = "code";
	_e$1 = "error";
	_eI = "expiresIn";
	_gT = "grantType";
	_h = "http";
	_hE$1 = "httpError";
	_iT = "idToken";
	_jN = "jsonName";
	_m$1 = "message";
	_rT = "refreshToken";
	_rU = "redirectUri";
	_s$1 = "server";
	_sAK = "secretAccessKey";
	_sT = "sessionToken";
	_sm = "smithy.ts.sdk.synthetic.com.amazonaws.signin";
	_tI = "tokenInput";
	_tO = "tokenOutput";
	_tT = "tokenType";
	n0$1 = "com.amazonaws.signin";
	RefreshToken = [
		0,
		n0$1,
		_RT,
		8,
		0
	];
	AccessDeniedException$ = [
		-3,
		n0$1,
		_ADE,
		{ [_e$1]: _c$1 },
		[_e$1, _m$1],
		[0, 0]
	];
	TypeRegistry.for(n0$1).registerError(AccessDeniedException$, AccessDeniedException);
	AccessToken$ = [
		3,
		n0$1,
		_AT,
		8,
		[
			_aKI,
			_sAK,
			_sT
		],
		[
			[0, { [_jN]: _aKI }],
			[0, { [_jN]: _sAK }],
			[0, { [_jN]: _sT }]
		]
	];
	CreateOAuth2TokenRequest$ = [
		3,
		n0$1,
		_COATR,
		0,
		[_tI],
		[[() => CreateOAuth2TokenRequestBody$, 16]]
	];
	CreateOAuth2TokenRequestBody$ = [
		3,
		n0$1,
		_COATRB,
		0,
		[
			_cI,
			_gT,
			_co,
			_rU,
			_cV,
			_rT
		],
		[
			[0, { [_jN]: _cI }],
			[0, { [_jN]: _gT }],
			0,
			[0, { [_jN]: _rU }],
			[0, { [_jN]: _cV }],
			[() => RefreshToken, { [_jN]: _rT }]
		]
	];
	CreateOAuth2TokenResponse$ = [
		3,
		n0$1,
		_COATRr,
		0,
		[_tO],
		[[() => CreateOAuth2TokenResponseBody$, 16]]
	];
	CreateOAuth2TokenResponseBody$ = [
		3,
		n0$1,
		_COATRBr,
		0,
		[
			_aT,
			_tT,
			_eI,
			_rT,
			_iT
		],
		[
			[() => AccessToken$, { [_jN]: _aT }],
			[0, { [_jN]: _tT }],
			[1, { [_jN]: _eI }],
			[() => RefreshToken, { [_jN]: _rT }],
			[0, { [_jN]: _iT }]
		]
	];
	InternalServerException$ = [
		-3,
		n0$1,
		_ISE,
		{
			[_e$1]: _s$1,
			[_hE$1]: 500
		},
		[_e$1, _m$1],
		[0, 0]
	];
	TypeRegistry.for(n0$1).registerError(InternalServerException$, InternalServerException);
	TooManyRequestsError$ = [
		-3,
		n0$1,
		_TMRE,
		{
			[_e$1]: _c$1,
			[_hE$1]: 429
		},
		[_e$1, _m$1],
		[0, 0]
	];
	TypeRegistry.for(n0$1).registerError(TooManyRequestsError$, TooManyRequestsError);
	ValidationException$ = [
		-3,
		n0$1,
		_VE,
		{
			[_e$1]: _c$1,
			[_hE$1]: 400
		},
		[_e$1, _m$1],
		[0, 0]
	];
	TypeRegistry.for(n0$1).registerError(ValidationException$, ValidationException);
	SigninServiceException$ = [
		-3,
		_sm,
		"SigninServiceException",
		0,
		[],
		[]
	];
	TypeRegistry.for(_sm).registerError(SigninServiceException$, SigninServiceException);
	CreateOAuth2Token$ = [
		9,
		n0$1,
		_COAT,
		{ [_h]: [
			"POST",
			"/v1/token",
			200
		] },
		() => CreateOAuth2TokenRequest$,
		() => CreateOAuth2TokenResponse$
	];
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/CreateOAuth2TokenCommand.js
var import_dist_cjs$38, import_dist_cjs$39, CreateOAuth2TokenCommand;
var init_CreateOAuth2TokenCommand = __esmMin((() => {
	import_dist_cjs$38 = require_dist_cjs$20();
	import_dist_cjs$39 = require_dist_cjs$28();
	init_EndpointParameters$1();
	init_schemas_0$1();
	CreateOAuth2TokenCommand = class extends import_dist_cjs$39.Command.classBuilder().ep(commonParams$1).m(function(Command, cs, config, o$3) {
		return [(0, import_dist_cjs$38.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())];
	}).s("Signin", "CreateOAuth2Token", {}).n("SigninClient", "CreateOAuth2TokenCommand").sc(CreateOAuth2Token$).build() {};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/Signin.js
var import_dist_cjs$37, commands$1, Signin;
var init_Signin = __esmMin((() => {
	import_dist_cjs$37 = require_dist_cjs$28();
	init_CreateOAuth2TokenCommand();
	init_SigninClient();
	commands$1 = { CreateOAuth2TokenCommand };
	Signin = class extends SigninClient {};
	(0, import_dist_cjs$37.createAggregatedClient)(commands$1, Signin);
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/index.js
var init_commands$1 = __esmMin((() => {
	init_CreateOAuth2TokenCommand();
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/enums.js
var OAuth2ErrorCode;
var init_enums = __esmMin((() => {
	OAuth2ErrorCode = {
		AUTHCODE_EXPIRED: "AUTHCODE_EXPIRED",
		INSUFFICIENT_PERMISSIONS: "INSUFFICIENT_PERMISSIONS",
		INVALID_REQUEST: "INVALID_REQUEST",
		SERVER_ERROR: "server_error",
		TOKEN_EXPIRED: "TOKEN_EXPIRED",
		USER_CREDENTIALS_CHANGED: "USER_CREDENTIALS_CHANGED"
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/models_0.js
var init_models_0$1 = __esmMin((() => {}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/index.js
var signin_exports = /* @__PURE__ */ __exportAll({
	$Command: () => import_dist_cjs$39.Command,
	AccessDeniedException: () => AccessDeniedException,
	AccessDeniedException$: () => AccessDeniedException$,
	AccessToken$: () => AccessToken$,
	CreateOAuth2Token$: () => CreateOAuth2Token$,
	CreateOAuth2TokenCommand: () => CreateOAuth2TokenCommand,
	CreateOAuth2TokenRequest$: () => CreateOAuth2TokenRequest$,
	CreateOAuth2TokenRequestBody$: () => CreateOAuth2TokenRequestBody$,
	CreateOAuth2TokenResponse$: () => CreateOAuth2TokenResponse$,
	CreateOAuth2TokenResponseBody$: () => CreateOAuth2TokenResponseBody$,
	InternalServerException: () => InternalServerException,
	InternalServerException$: () => InternalServerException$,
	OAuth2ErrorCode: () => OAuth2ErrorCode,
	Signin: () => Signin,
	SigninClient: () => SigninClient,
	SigninServiceException: () => SigninServiceException,
	SigninServiceException$: () => SigninServiceException$,
	TooManyRequestsError: () => TooManyRequestsError,
	TooManyRequestsError$: () => TooManyRequestsError$,
	ValidationException: () => ValidationException,
	ValidationException$: () => ValidationException$,
	__Client: () => import_dist_cjs$49.Client
});
var init_signin = __esmMin((() => {
	init_SigninClient();
	init_Signin();
	init_commands$1();
	init_schemas_0$1();
	init_enums();
	init_errors$1();
	init_models_0$1();
	init_SigninServiceException();
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-login/dist-cjs/index.js
var require_dist_cjs$5 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var client = (init_client(), __toCommonJS(client_exports));
	var propertyProvider = require_dist_cjs$31();
	var sharedIniFileLoader = require_dist_cjs$22();
	var protocolHttp = require_dist_cjs$52();
	var node_crypto = require("node:crypto");
	var node_fs = require("node:fs");
	var node_os = require("node:os");
	var node_path = require("node:path");
	var LoginCredentialsFetcher = class LoginCredentialsFetcher {
		profileData;
		init;
		callerClientConfig;
		static REFRESH_THRESHOLD = 300 * 1e3;
		constructor(profileData, init, callerClientConfig) {
			this.profileData = profileData;
			this.init = init;
			this.callerClientConfig = callerClientConfig;
		}
		async loadCredentials() {
			const token = await this.loadToken();
			if (!token) throw new propertyProvider.CredentialsProviderError(`Failed to load a token for session ${this.loginSession}, please re-authenticate using aws login`, {
				tryNextLink: false,
				logger: this.logger
			});
			const accessToken = token.accessToken;
			const now = Date.now();
			if (new Date(accessToken.expiresAt).getTime() - now <= LoginCredentialsFetcher.REFRESH_THRESHOLD) return this.refresh(token);
			return {
				accessKeyId: accessToken.accessKeyId,
				secretAccessKey: accessToken.secretAccessKey,
				sessionToken: accessToken.sessionToken,
				accountId: accessToken.accountId,
				expiration: new Date(accessToken.expiresAt)
			};
		}
		get logger() {
			return this.init?.logger;
		}
		get loginSession() {
			return this.profileData.login_session;
		}
		async refresh(token) {
			const { SigninClient: SigninClient$1, CreateOAuth2TokenCommand: CreateOAuth2TokenCommand$1 } = await Promise.resolve().then(() => (init_signin(), signin_exports));
			const { logger: logger$1, userAgentAppId } = this.callerClientConfig ?? {};
			const isH2$1 = (requestHandler$1) => {
				return requestHandler$1?.metadata?.handlerProtocol === "h2";
			};
			const requestHandler = isH2$1(this.callerClientConfig?.requestHandler) ? void 0 : this.callerClientConfig?.requestHandler;
			const client$1 = new SigninClient$1({
				credentials: {
					accessKeyId: "",
					secretAccessKey: ""
				},
				region: this.profileData.region ?? await this.callerClientConfig?.region?.() ?? process.env.AWS_REGION,
				requestHandler,
				logger: logger$1,
				userAgentAppId,
				...this.init?.clientConfig
			});
			this.createDPoPInterceptor(client$1.middlewareStack);
			const commandInput = { tokenInput: {
				clientId: token.clientId,
				refreshToken: token.refreshToken,
				grantType: "refresh_token"
			} };
			try {
				const response = await client$1.send(new CreateOAuth2TokenCommand$1(commandInput));
				const { accessKeyId, secretAccessKey, sessionToken } = response.tokenOutput?.accessToken ?? {};
				const { refreshToken, expiresIn } = response.tokenOutput ?? {};
				if (!accessKeyId || !secretAccessKey || !sessionToken || !refreshToken) throw new propertyProvider.CredentialsProviderError("Token refresh response missing required fields", {
					logger: this.logger,
					tryNextLink: false
				});
				const expiresInMs = (expiresIn ?? 900) * 1e3;
				const expiration = new Date(Date.now() + expiresInMs);
				const updatedToken = {
					...token,
					accessToken: {
						...token.accessToken,
						accessKeyId,
						secretAccessKey,
						sessionToken,
						expiresAt: expiration.toISOString()
					},
					refreshToken
				};
				await this.saveToken(updatedToken);
				const newAccessToken = updatedToken.accessToken;
				return {
					accessKeyId: newAccessToken.accessKeyId,
					secretAccessKey: newAccessToken.secretAccessKey,
					sessionToken: newAccessToken.sessionToken,
					accountId: newAccessToken.accountId,
					expiration
				};
			} catch (error$1) {
				if (error$1.name === "AccessDeniedException") {
					const errorType = error$1.error;
					let message;
					switch (errorType) {
						case "TOKEN_EXPIRED":
							message = "Your session has expired. Please reauthenticate.";
							break;
						case "USER_CREDENTIALS_CHANGED":
							message = "Unable to refresh credentials because of a change in your password. Please reauthenticate with your new password.";
							break;
						case "INSUFFICIENT_PERMISSIONS":
							message = "Unable to refresh credentials due to insufficient permissions. You may be missing permission for the 'CreateOAuth2Token' action.";
							break;
						default: message = `Failed to refresh token: ${String(error$1)}. Please re-authenticate using \`aws login\``;
					}
					throw new propertyProvider.CredentialsProviderError(message, {
						logger: this.logger,
						tryNextLink: false
					});
				}
				throw new propertyProvider.CredentialsProviderError(`Failed to refresh token: ${String(error$1)}. Please re-authenticate using aws login`, { logger: this.logger });
			}
		}
		async loadToken() {
			const tokenFilePath = this.getTokenFilePath();
			try {
				let tokenData;
				try {
					tokenData = await sharedIniFileLoader.readFile(tokenFilePath, { ignoreCache: this.init?.ignoreCache });
				} catch {
					tokenData = await node_fs.promises.readFile(tokenFilePath, "utf8");
				}
				const token = JSON.parse(tokenData);
				const missingFields = [
					"accessToken",
					"clientId",
					"refreshToken",
					"dpopKey"
				].filter((k$3) => !token[k$3]);
				if (!token.accessToken?.accountId) missingFields.push("accountId");
				if (missingFields.length > 0) throw new propertyProvider.CredentialsProviderError(`Token validation failed, missing fields: ${missingFields.join(", ")}`, {
					logger: this.logger,
					tryNextLink: false
				});
				return token;
			} catch (error$1) {
				throw new propertyProvider.CredentialsProviderError(`Failed to load token from ${tokenFilePath}: ${String(error$1)}`, {
					logger: this.logger,
					tryNextLink: false
				});
			}
		}
		async saveToken(token) {
			const tokenFilePath = this.getTokenFilePath();
			const directory = node_path.dirname(tokenFilePath);
			try {
				await node_fs.promises.mkdir(directory, { recursive: true });
			} catch (error$1) {}
			await node_fs.promises.writeFile(tokenFilePath, JSON.stringify(token, null, 2), "utf8");
		}
		getTokenFilePath() {
			const directory = process.env.AWS_LOGIN_CACHE_DIRECTORY ?? node_path.join(node_os.homedir(), ".aws", "login", "cache");
			const loginSessionBytes = Buffer.from(this.loginSession, "utf8");
			const loginSessionSha256 = node_crypto.createHash("sha256").update(loginSessionBytes).digest("hex");
			return node_path.join(directory, `${loginSessionSha256}.json`);
		}
		derToRawSignature(derSignature) {
			let offset = 2;
			if (derSignature[offset] !== 2) throw new Error("Invalid DER signature");
			offset++;
			const rLength = derSignature[offset++];
			let r$3 = derSignature.subarray(offset, offset + rLength);
			offset += rLength;
			if (derSignature[offset] !== 2) throw new Error("Invalid DER signature");
			offset++;
			const sLength = derSignature[offset++];
			let s$3 = derSignature.subarray(offset, offset + sLength);
			r$3 = r$3[0] === 0 ? r$3.subarray(1) : r$3;
			s$3 = s$3[0] === 0 ? s$3.subarray(1) : s$3;
			const rPadded = Buffer.concat([Buffer.alloc(32 - r$3.length), r$3]);
			const sPadded = Buffer.concat([Buffer.alloc(32 - s$3.length), s$3]);
			return Buffer.concat([rPadded, sPadded]);
		}
		createDPoPInterceptor(middlewareStack) {
			middlewareStack.add((next) => async (args) => {
				if (protocolHttp.HttpRequest.isInstance(args.request)) {
					const request = args.request;
					const actualEndpoint = `${request.protocol}//${request.hostname}${request.port ? `:${request.port}` : ""}${request.path}`;
					const dpop = await this.generateDpop(request.method, actualEndpoint);
					request.headers = {
						...request.headers,
						DPoP: dpop
					};
				}
				return next(args);
			}, {
				step: "finalizeRequest",
				name: "dpopInterceptor",
				override: true
			});
		}
		async generateDpop(method = "POST", endpoint) {
			const token = await this.loadToken();
			try {
				const privateKey = node_crypto.createPrivateKey({
					key: token.dpopKey,
					format: "pem",
					type: "sec1"
				});
				const publicDer = node_crypto.createPublicKey(privateKey).export({
					format: "der",
					type: "spki"
				});
				let pointStart = -1;
				for (let i$3 = 0; i$3 < publicDer.length; i$3++) if (publicDer[i$3] === 4) {
					pointStart = i$3;
					break;
				}
				const x$3 = publicDer.slice(pointStart + 1, pointStart + 33);
				const y$1 = publicDer.slice(pointStart + 33, pointStart + 65);
				const header = {
					alg: "ES256",
					typ: "dpop+jwt",
					jwk: {
						kty: "EC",
						crv: "P-256",
						x: x$3.toString("base64url"),
						y: y$1.toString("base64url")
					}
				};
				const payload$1 = {
					jti: crypto.randomUUID(),
					htm: method,
					htu: endpoint,
					iat: Math.floor(Date.now() / 1e3)
				};
				const message = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(payload$1)).toString("base64url")}`;
				const asn1Signature = node_crypto.sign("sha256", Buffer.from(message), privateKey);
				return `${message}.${this.derToRawSignature(asn1Signature).toString("base64url")}`;
			} catch (error$1) {
				throw new propertyProvider.CredentialsProviderError(`Failed to generate Dpop proof: ${error$1 instanceof Error ? error$1.message : String(error$1)}`, {
					logger: this.logger,
					tryNextLink: false
				});
			}
		}
	};
	const fromLoginCredentials = (init) => async ({ callerClientConfig } = {}) => {
		init?.logger?.debug?.("@aws-sdk/credential-providers - fromLoginCredentials");
		const profiles = await sharedIniFileLoader.parseKnownFiles(init || {});
		const profileName = sharedIniFileLoader.getProfileName({ profile: init?.profile ?? callerClientConfig?.profile });
		const profile = profiles[profileName];
		if (!profile?.login_session) throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} does not contain login_session.`, {
			tryNextLink: true,
			logger: init?.logger
		});
		const credentials = await new LoginCredentialsFetcher(profile, init, callerClientConfig).loadCredentials();
		return client.setCredentialFeature(credentials, "CREDENTIALS_LOGIN", "AD");
	};
	exports.fromLoginCredentials = fromLoginCredentials;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthSchemeProvider.js
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
var import_dist_cjs$36, defaultSTSHttpAuthSchemeParametersProvider, defaultSTSHttpAuthSchemeProvider, resolveStsAuthConfig, resolveHttpAuthSchemeConfig;
var init_httpAuthSchemeProvider = __esmMin((() => {
	init_dist_es();
	import_dist_cjs$36 = require_dist_cjs$48();
	init_STSClient();
	defaultSTSHttpAuthSchemeParametersProvider = async (config, context, input) => {
		return {
			operation: (0, import_dist_cjs$36.getSmithyContext)(context).operation,
			region: await (0, import_dist_cjs$36.normalizeProvider)(config.region)() || (() => {
				throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
			})()
		};
	};
	defaultSTSHttpAuthSchemeProvider = (authParameters) => {
		const options = [];
		switch (authParameters.operation) {
			case "AssumeRoleWithWebIdentity":
				options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
				break;
			default: options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
		}
		return options;
	};
	resolveStsAuthConfig = (input) => Object.assign(input, { stsClientCtor: STSClient$1 });
	resolveHttpAuthSchemeConfig = (config) => {
		const config_1 = resolveAwsSdkSigV4Config(resolveStsAuthConfig(config));
		return Object.assign(config_1, { authSchemePreference: (0, import_dist_cjs$36.normalizeProvider)(config.authSchemePreference ?? []) });
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/EndpointParameters.js
var resolveClientEndpointParameters, commonParams;
var init_EndpointParameters = __esmMin((() => {
	resolveClientEndpointParameters = (options) => {
		return Object.assign(options, {
			useDualstackEndpoint: options.useDualstackEndpoint ?? false,
			useFipsEndpoint: options.useFipsEndpoint ?? false,
			useGlobalEndpoint: options.useGlobalEndpoint ?? false,
			defaultSigningName: "sts"
		});
	};
	commonParams = {
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
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/ruleset.js
var F, G, H, I, J, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, A, B, C, D, E, _data, ruleSet;
var init_ruleset = __esmMin((() => {
	F = "required", G = "type", H = "fn", I = "argv", J = "ref";
	a = false, b = true, c = "booleanEquals", d = "stringEquals", e = "sigv4", f = "sts", g = "us-east-1", h = "endpoint", i = "https://sts.{Region}.{PartitionResult#dnsSuffix}", j = "tree", k = "error", l = "getAttr", m = {
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
	_data = {
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
	ruleSet = _data;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/endpointResolver.js
var import_dist_cjs$34, import_dist_cjs$35, cache, defaultEndpointResolver;
var init_endpointResolver = __esmMin((() => {
	import_dist_cjs$34 = require_dist_cjs$32();
	import_dist_cjs$35 = require_dist_cjs$35();
	init_ruleset();
	cache = new import_dist_cjs$35.EndpointCache({
		size: 50,
		params: [
			"Endpoint",
			"Region",
			"UseDualStack",
			"UseFIPS",
			"UseGlobalEndpoint"
		]
	});
	defaultEndpointResolver = (endpointParams, context = {}) => {
		return cache.get(endpointParams, () => (0, import_dist_cjs$35.resolveEndpoint)(ruleSet, {
			endpointParams,
			logger: context.logger
		}));
	};
	import_dist_cjs$35.customEndpointFunctions.aws = import_dist_cjs$34.awsEndpointFunctions;
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.shared.js
var import_dist_cjs$30, import_dist_cjs$31, import_dist_cjs$32, import_dist_cjs$33, getRuntimeConfig$1;
var init_runtimeConfig_shared = __esmMin((() => {
	init_dist_es();
	init_protocols();
	init_dist_es$1();
	import_dist_cjs$30 = require_dist_cjs$28();
	import_dist_cjs$31 = require_dist_cjs$33();
	import_dist_cjs$32 = require_dist_cjs$43();
	import_dist_cjs$33 = require_dist_cjs$44();
	init_httpAuthSchemeProvider();
	init_endpointResolver();
	getRuntimeConfig$1 = (config) => {
		return {
			apiVersion: "2011-06-15",
			base64Decoder: config?.base64Decoder ?? import_dist_cjs$32.fromBase64,
			base64Encoder: config?.base64Encoder ?? import_dist_cjs$32.toBase64,
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
			logger: config?.logger ?? new import_dist_cjs$30.NoOpLogger(),
			protocol: config?.protocol ?? AwsQueryProtocol,
			protocolSettings: config?.protocolSettings ?? {
				defaultNamespace: "com.amazonaws.sts",
				xmlNamespace: "https://sts.amazonaws.com/doc/2011-06-15/",
				version: "2011-06-15",
				serviceTarget: "AWSSecurityTokenServiceV20110615"
			},
			serviceId: config?.serviceId ?? "STS",
			urlParser: config?.urlParser ?? import_dist_cjs$31.parseUrl,
			utf8Decoder: config?.utf8Decoder ?? import_dist_cjs$33.fromUtf8,
			utf8Encoder: config?.utf8Encoder ?? import_dist_cjs$33.toUtf8
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.js
var import_dist_cjs$20, import_dist_cjs$21, import_dist_cjs$22, import_dist_cjs$23, import_dist_cjs$24, import_dist_cjs$25, import_dist_cjs$26, import_dist_cjs$27, import_dist_cjs$28, import_dist_cjs$29, getRuntimeConfig;
var init_runtimeConfig = __esmMin((() => {
	init_dist_es();
	import_dist_cjs$20 = require_dist_cjs$13();
	import_dist_cjs$21 = require_dist_cjs$24();
	init_dist_es$1();
	import_dist_cjs$22 = require_dist_cjs$12();
	import_dist_cjs$23 = require_dist_cjs$17();
	import_dist_cjs$24 = require_dist_cjs$21();
	import_dist_cjs$25 = require_dist_cjs$40();
	import_dist_cjs$26 = require_dist_cjs$28();
	import_dist_cjs$27 = require_dist_cjs$11();
	import_dist_cjs$28 = require_dist_cjs$10();
	import_dist_cjs$29 = require_dist_cjs$18();
	init_runtimeConfig_shared();
	getRuntimeConfig = (config) => {
		(0, import_dist_cjs$26.emitWarningIfUnsupportedVersion)(process.version);
		const defaultsMode = (0, import_dist_cjs$28.resolveDefaultsModeConfig)(config);
		const defaultConfigProvider = () => defaultsMode().then(import_dist_cjs$26.loadConfigsForDefaultMode);
		const clientSharedValues = getRuntimeConfig$1(config);
		emitWarningIfUnsupportedVersion$3(process.version);
		const loaderConfig = {
			profile: config?.profile,
			logger: clientSharedValues.logger
		};
		return {
			...clientSharedValues,
			...config,
			runtime: "node",
			defaultsMode,
			authSchemePreference: config?.authSchemePreference ?? (0, import_dist_cjs$24.loadConfig)(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
			bodyLengthChecker: config?.bodyLengthChecker ?? import_dist_cjs$27.calculateBodyLength,
			defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, import_dist_cjs$20.createDefaultUserAgentProvider)({
				serviceId: clientSharedValues.serviceId,
				clientVersion: version
			}),
			httpAuthSchemes: config?.httpAuthSchemes ?? [{
				schemeId: "aws.auth#sigv4",
				identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4") || (async (idProps) => await config.credentialDefaultProvider(idProps?.__config || {})()),
				signer: new AwsSdkSigV4Signer()
			}, {
				schemeId: "smithy.api#noAuth",
				identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
				signer: new NoAuthSigner()
			}],
			maxAttempts: config?.maxAttempts ?? (0, import_dist_cjs$24.loadConfig)(import_dist_cjs$23.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
			region: config?.region ?? (0, import_dist_cjs$24.loadConfig)(import_dist_cjs$21.NODE_REGION_CONFIG_OPTIONS, {
				...import_dist_cjs$21.NODE_REGION_CONFIG_FILE_OPTIONS,
				...loaderConfig
			}),
			requestHandler: import_dist_cjs$25.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
			retryMode: config?.retryMode ?? (0, import_dist_cjs$24.loadConfig)({
				...import_dist_cjs$23.NODE_RETRY_MODE_CONFIG_OPTIONS,
				default: async () => (await defaultConfigProvider()).retryMode || import_dist_cjs$29.DEFAULT_RETRY_MODE
			}, config),
			sha256: config?.sha256 ?? import_dist_cjs$22.Hash.bind(null, "sha256"),
			streamCollector: config?.streamCollector ?? import_dist_cjs$25.streamCollector,
			useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, import_dist_cjs$24.loadConfig)(import_dist_cjs$21.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			useFipsEndpoint: config?.useFipsEndpoint ?? (0, import_dist_cjs$24.loadConfig)(import_dist_cjs$21.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			userAgentAppId: config?.userAgentAppId ?? (0, import_dist_cjs$24.loadConfig)(import_dist_cjs$20.NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration, resolveHttpAuthRuntimeConfig;
var init_httpAuthExtensionConfiguration = __esmMin((() => {
	getHttpAuthExtensionConfiguration = (runtimeConfig) => {
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
	resolveHttpAuthRuntimeConfig = (config) => {
		return {
			httpAuthSchemes: config.httpAuthSchemes(),
			httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
			credentials: config.credentials()
		};
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeExtensions.js
var import_dist_cjs$17, import_dist_cjs$18, import_dist_cjs$19, resolveRuntimeExtensions;
var init_runtimeExtensions = __esmMin((() => {
	import_dist_cjs$17 = require_dist_cjs$9();
	import_dist_cjs$18 = require_dist_cjs$52();
	import_dist_cjs$19 = require_dist_cjs$28();
	init_httpAuthExtensionConfiguration();
	resolveRuntimeExtensions = (runtimeConfig, extensions) => {
		const extensionConfiguration = Object.assign((0, import_dist_cjs$17.getAwsRegionExtensionConfiguration)(runtimeConfig), (0, import_dist_cjs$19.getDefaultExtensionConfiguration)(runtimeConfig), (0, import_dist_cjs$18.getHttpHandlerExtensionConfiguration)(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
		extensions.forEach((extension) => extension.configure(extensionConfiguration));
		return Object.assign(runtimeConfig, (0, import_dist_cjs$17.resolveAwsRegionExtensionConfiguration)(extensionConfiguration), (0, import_dist_cjs$19.resolveDefaultRuntimeConfig)(extensionConfiguration), (0, import_dist_cjs$18.resolveHttpHandlerRuntimeConfig)(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STSClient.js
var import_dist_cjs$8, import_dist_cjs$9, import_dist_cjs$10, import_dist_cjs$11, import_dist_cjs$12, import_dist_cjs$13, import_dist_cjs$14, import_dist_cjs$15, import_dist_cjs$16, STSClient$1;
var init_STSClient = __esmMin((() => {
	import_dist_cjs$8 = require_dist_cjs$51();
	import_dist_cjs$9 = require_dist_cjs$50();
	import_dist_cjs$10 = require_dist_cjs$49();
	import_dist_cjs$11 = require_dist_cjs$26();
	import_dist_cjs$12 = require_dist_cjs$24();
	init_dist_es$1();
	init_schema();
	import_dist_cjs$13 = require_dist_cjs$23();
	import_dist_cjs$14 = require_dist_cjs$20();
	import_dist_cjs$15 = require_dist_cjs$17();
	import_dist_cjs$16 = require_dist_cjs$28();
	init_httpAuthSchemeProvider();
	init_EndpointParameters();
	init_runtimeConfig();
	init_runtimeExtensions();
	STSClient$1 = class extends import_dist_cjs$16.Client {
		config;
		constructor(...[configuration]) {
			const _config_0 = getRuntimeConfig(configuration || {});
			super(_config_0);
			this.initConfig = _config_0;
			this.config = resolveRuntimeExtensions(resolveHttpAuthSchemeConfig((0, import_dist_cjs$14.resolveEndpointConfig)((0, import_dist_cjs$8.resolveHostHeaderConfig)((0, import_dist_cjs$12.resolveRegionConfig)((0, import_dist_cjs$15.resolveRetryConfig)((0, import_dist_cjs$11.resolveUserAgentConfig)(resolveClientEndpointParameters(_config_0))))))), configuration?.extensions || []);
			this.middlewareStack.use(getSchemaSerdePlugin(this.config));
			this.middlewareStack.use((0, import_dist_cjs$11.getUserAgentPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$15.getRetryPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$13.getContentLengthPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$8.getHostHeaderPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$9.getLoggerPlugin)(this.config));
			this.middlewareStack.use((0, import_dist_cjs$10.getRecursionDetectionPlugin)(this.config));
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
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/STSServiceException.js
var import_dist_cjs$7, STSServiceException;
var init_STSServiceException = __esmMin((() => {
	import_dist_cjs$7 = require_dist_cjs$28();
	STSServiceException = class STSServiceException extends import_dist_cjs$7.ServiceException {
		constructor(options) {
			super(options);
			Object.setPrototypeOf(this, STSServiceException.prototype);
		}
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/errors.js
var ExpiredTokenException, MalformedPolicyDocumentException, PackedPolicyTooLargeException, RegionDisabledException, IDPRejectedClaimException, InvalidIdentityTokenException, IDPCommunicationErrorException;
var init_errors = __esmMin((() => {
	init_STSServiceException();
	ExpiredTokenException = class ExpiredTokenException extends STSServiceException {
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
	MalformedPolicyDocumentException = class MalformedPolicyDocumentException extends STSServiceException {
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
	PackedPolicyTooLargeException = class PackedPolicyTooLargeException extends STSServiceException {
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
	RegionDisabledException = class RegionDisabledException extends STSServiceException {
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
	IDPRejectedClaimException = class IDPRejectedClaimException extends STSServiceException {
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
	InvalidIdentityTokenException = class InvalidIdentityTokenException extends STSServiceException {
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
	IDPCommunicationErrorException = class IDPCommunicationErrorException extends STSServiceException {
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
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/schemas/schemas_0.js
var _A, _AKI, _AR, _ARI, _ARR, _ARRs, _ARU, _ARWWI, _ARWWIR, _ARWWIRs, _Au, _C, _CA, _DS, _E, _EI, _ETE, _IDPCEE, _IDPRCE, _IITE, _K, _MPDE, _P, _PA, _PAr, _PC, _PCLT, _PCr, _PDT, _PI, _PPS, _PPTLE, _Pr, _RA, _RDE, _RSN, _SAK, _SFWIT, _SI, _SN, _ST, _T, _TC, _TTK, _Ta, _V, _WIT, _a, _aKST, _aQE, _c, _cTT, _e, _hE, _m, _pDLT, _s, _tLT, n0, accessKeySecretType, clientTokenType, AssumedRoleUser$, AssumeRoleRequest$, AssumeRoleResponse$, AssumeRoleWithWebIdentityRequest$, AssumeRoleWithWebIdentityResponse$, Credentials$, ExpiredTokenException$, IDPCommunicationErrorException$, IDPRejectedClaimException$, InvalidIdentityTokenException$, MalformedPolicyDocumentException$, PackedPolicyTooLargeException$, PolicyDescriptorType$, ProvidedContext$, RegionDisabledException$, Tag$, STSServiceException$, policyDescriptorListType, ProvidedContextsListType, tagListType, AssumeRole$, AssumeRoleWithWebIdentity$;
var init_schemas_0 = __esmMin((() => {
	init_schema();
	init_errors();
	init_STSServiceException();
	_A = "Arn";
	_AKI = "AccessKeyId";
	_AR = "AssumeRole";
	_ARI = "AssumedRoleId";
	_ARR = "AssumeRoleRequest";
	_ARRs = "AssumeRoleResponse";
	_ARU = "AssumedRoleUser";
	_ARWWI = "AssumeRoleWithWebIdentity";
	_ARWWIR = "AssumeRoleWithWebIdentityRequest";
	_ARWWIRs = "AssumeRoleWithWebIdentityResponse";
	_Au = "Audience";
	_C = "Credentials";
	_CA = "ContextAssertion";
	_DS = "DurationSeconds";
	_E = "Expiration";
	_EI = "ExternalId";
	_ETE = "ExpiredTokenException";
	_IDPCEE = "IDPCommunicationErrorException";
	_IDPRCE = "IDPRejectedClaimException";
	_IITE = "InvalidIdentityTokenException";
	_K = "Key";
	_MPDE = "MalformedPolicyDocumentException";
	_P = "Policy";
	_PA = "PolicyArns";
	_PAr = "ProviderArn";
	_PC = "ProvidedContexts";
	_PCLT = "ProvidedContextsListType";
	_PCr = "ProvidedContext";
	_PDT = "PolicyDescriptorType";
	_PI = "ProviderId";
	_PPS = "PackedPolicySize";
	_PPTLE = "PackedPolicyTooLargeException";
	_Pr = "Provider";
	_RA = "RoleArn";
	_RDE = "RegionDisabledException";
	_RSN = "RoleSessionName";
	_SAK = "SecretAccessKey";
	_SFWIT = "SubjectFromWebIdentityToken";
	_SI = "SourceIdentity";
	_SN = "SerialNumber";
	_ST = "SessionToken";
	_T = "Tags";
	_TC = "TokenCode";
	_TTK = "TransitiveTagKeys";
	_Ta = "Tag";
	_V = "Value";
	_WIT = "WebIdentityToken";
	_a = "arn";
	_aKST = "accessKeySecretType";
	_aQE = "awsQueryError";
	_c = "client";
	_cTT = "clientTokenType";
	_e = "error";
	_hE = "httpError";
	_m = "message";
	_pDLT = "policyDescriptorListType";
	_s = "smithy.ts.sdk.synthetic.com.amazonaws.sts";
	_tLT = "tagListType";
	n0 = "com.amazonaws.sts";
	accessKeySecretType = [
		0,
		n0,
		_aKST,
		8,
		0
	];
	clientTokenType = [
		0,
		n0,
		_cTT,
		8,
		0
	];
	AssumedRoleUser$ = [
		3,
		n0,
		_ARU,
		0,
		[_ARI, _A],
		[0, 0]
	];
	AssumeRoleRequest$ = [
		3,
		n0,
		_ARR,
		0,
		[
			_RA,
			_RSN,
			_PA,
			_P,
			_DS,
			_T,
			_TTK,
			_EI,
			_SN,
			_TC,
			_SI,
			_PC
		],
		[
			0,
			0,
			() => policyDescriptorListType,
			0,
			1,
			() => tagListType,
			64,
			0,
			0,
			0,
			0,
			() => ProvidedContextsListType
		]
	];
	AssumeRoleResponse$ = [
		3,
		n0,
		_ARRs,
		0,
		[
			_C,
			_ARU,
			_PPS,
			_SI
		],
		[
			[() => Credentials$, 0],
			() => AssumedRoleUser$,
			1,
			0
		]
	];
	AssumeRoleWithWebIdentityRequest$ = [
		3,
		n0,
		_ARWWIR,
		0,
		[
			_RA,
			_RSN,
			_WIT,
			_PI,
			_PA,
			_P,
			_DS
		],
		[
			0,
			0,
			[() => clientTokenType, 0],
			0,
			() => policyDescriptorListType,
			0,
			1
		]
	];
	AssumeRoleWithWebIdentityResponse$ = [
		3,
		n0,
		_ARWWIRs,
		0,
		[
			_C,
			_SFWIT,
			_ARU,
			_PPS,
			_Pr,
			_Au,
			_SI
		],
		[
			[() => Credentials$, 0],
			0,
			() => AssumedRoleUser$,
			1,
			0,
			0,
			0
		]
	];
	Credentials$ = [
		3,
		n0,
		_C,
		0,
		[
			_AKI,
			_SAK,
			_ST,
			_E
		],
		[
			0,
			[() => accessKeySecretType, 0],
			0,
			4
		]
	];
	ExpiredTokenException$ = [
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
	IDPCommunicationErrorException$ = [
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
	IDPRejectedClaimException$ = [
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
	InvalidIdentityTokenException$ = [
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
	MalformedPolicyDocumentException$ = [
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
	PackedPolicyTooLargeException$ = [
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
	PolicyDescriptorType$ = [
		3,
		n0,
		_PDT,
		0,
		[_a],
		[0]
	];
	ProvidedContext$ = [
		3,
		n0,
		_PCr,
		0,
		[_PAr, _CA],
		[0, 0]
	];
	RegionDisabledException$ = [
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
	Tag$ = [
		3,
		n0,
		_Ta,
		0,
		[_K, _V],
		[0, 0]
	];
	STSServiceException$ = [
		-3,
		_s,
		"STSServiceException",
		0,
		[],
		[]
	];
	TypeRegistry.for(_s).registerError(STSServiceException$, STSServiceException);
	policyDescriptorListType = [
		1,
		n0,
		_pDLT,
		0,
		() => PolicyDescriptorType$
	];
	ProvidedContextsListType = [
		1,
		n0,
		_PCLT,
		0,
		() => ProvidedContext$
	];
	tagListType = [
		1,
		n0,
		_tLT,
		0,
		() => Tag$
	];
	AssumeRole$ = [
		9,
		n0,
		_AR,
		0,
		() => AssumeRoleRequest$,
		() => AssumeRoleResponse$
	];
	AssumeRoleWithWebIdentity$ = [
		9,
		n0,
		_ARWWI,
		0,
		() => AssumeRoleWithWebIdentityRequest$,
		() => AssumeRoleWithWebIdentityResponse$
	];
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleCommand.js
var import_dist_cjs$5, import_dist_cjs$6, AssumeRoleCommand;
var init_AssumeRoleCommand = __esmMin((() => {
	import_dist_cjs$5 = require_dist_cjs$20();
	import_dist_cjs$6 = require_dist_cjs$28();
	init_EndpointParameters();
	init_schemas_0();
	AssumeRoleCommand = class extends import_dist_cjs$6.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o$3) {
		return [(0, import_dist_cjs$5.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "AssumeRole", {}).n("STSClient", "AssumeRoleCommand").sc(AssumeRole$).build() {};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleWithWebIdentityCommand.js
var import_dist_cjs$3, import_dist_cjs$4, AssumeRoleWithWebIdentityCommand;
var init_AssumeRoleWithWebIdentityCommand = __esmMin((() => {
	import_dist_cjs$3 = require_dist_cjs$20();
	import_dist_cjs$4 = require_dist_cjs$28();
	init_EndpointParameters();
	init_schemas_0();
	AssumeRoleWithWebIdentityCommand = class extends import_dist_cjs$4.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o$3) {
		return [(0, import_dist_cjs$3.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithWebIdentity", {}).n("STSClient", "AssumeRoleWithWebIdentityCommand").sc(AssumeRoleWithWebIdentity$).build() {};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STS.js
var import_dist_cjs$2, commands, STS;
var init_STS = __esmMin((() => {
	import_dist_cjs$2 = require_dist_cjs$28();
	init_AssumeRoleCommand();
	init_AssumeRoleWithWebIdentityCommand();
	init_STSClient();
	commands = {
		AssumeRoleCommand,
		AssumeRoleWithWebIdentityCommand
	};
	STS = class extends STSClient$1 {};
	(0, import_dist_cjs$2.createAggregatedClient)(commands, STS);
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/index.js
var init_commands = __esmMin((() => {
	init_AssumeRoleCommand();
	init_AssumeRoleWithWebIdentityCommand();
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/models_0.js
var init_models_0 = __esmMin((() => {}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultStsRoleAssumers.js
var import_dist_cjs$1, getAccountIdFromAssumedRoleUser, resolveRegion, getDefaultRoleAssumer$1, getDefaultRoleAssumerWithWebIdentity$1, isH2;
var init_defaultStsRoleAssumers = __esmMin((() => {
	init_client();
	import_dist_cjs$1 = require_dist_cjs$9();
	init_AssumeRoleCommand();
	init_AssumeRoleWithWebIdentityCommand();
	getAccountIdFromAssumedRoleUser = (assumedRoleUser) => {
		if (typeof assumedRoleUser?.Arn === "string") {
			const arnComponents = assumedRoleUser.Arn.split(":");
			if (arnComponents.length > 4 && arnComponents[4] !== "") return arnComponents[4];
		}
	};
	resolveRegion = async (_region, _parentRegion, credentialProviderLogger, loaderConfig = {}) => {
		const region = typeof _region === "function" ? await _region() : _region;
		const parentRegion = typeof _parentRegion === "function" ? await _parentRegion() : _parentRegion;
		let stsDefaultRegion = "";
		const resolvedRegion = region ?? parentRegion ?? (stsDefaultRegion = await (0, import_dist_cjs$1.stsRegionDefaultResolver)(loaderConfig)());
		credentialProviderLogger?.debug?.("@aws-sdk/client-sts::resolveRegion", "accepting first of:", `${region} (credential provider clientConfig)`, `${parentRegion} (contextual client)`, `${stsDefaultRegion} (STS default: AWS_REGION, profile region, or us-east-1)`);
		return resolvedRegion;
	};
	getDefaultRoleAssumer$1 = (stsOptions, STSClient$2) => {
		let stsClient;
		let closureSourceCreds;
		return async (sourceCreds, params) => {
			closureSourceCreds = sourceCreds;
			if (!stsClient) {
				const { logger: logger$1 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
				const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
					logger: logger$1,
					profile
				});
				const isCompatibleRequestHandler = !isH2(requestHandler);
				stsClient = new STSClient$2({
					...stsOptions,
					userAgentAppId,
					profile,
					credentialDefaultProvider: () => async () => closureSourceCreds,
					region: resolvedRegion,
					requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
					logger: logger$1
				});
			}
			const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleCommand(params));
			if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) throw new Error(`Invalid response from STS.assumeRole call with role ${params.RoleArn}`);
			const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
			const credentials = {
				accessKeyId: Credentials.AccessKeyId,
				secretAccessKey: Credentials.SecretAccessKey,
				sessionToken: Credentials.SessionToken,
				expiration: Credentials.Expiration,
				...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
				...accountId && { accountId }
			};
			setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE", "i");
			return credentials;
		};
	};
	getDefaultRoleAssumerWithWebIdentity$1 = (stsOptions, STSClient$2) => {
		let stsClient;
		return async (params) => {
			if (!stsClient) {
				const { logger: logger$1 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
				const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
					logger: logger$1,
					profile
				});
				const isCompatibleRequestHandler = !isH2(requestHandler);
				stsClient = new STSClient$2({
					...stsOptions,
					userAgentAppId,
					profile,
					region: resolvedRegion,
					requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
					logger: logger$1
				});
			}
			const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleWithWebIdentityCommand(params));
			if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) throw new Error(`Invalid response from STS.assumeRoleWithWebIdentity call with role ${params.RoleArn}`);
			const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
			const credentials = {
				accessKeyId: Credentials.AccessKeyId,
				secretAccessKey: Credentials.SecretAccessKey,
				sessionToken: Credentials.SessionToken,
				expiration: Credentials.Expiration,
				...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
				...accountId && { accountId }
			};
			if (accountId) setCredentialFeature(credentials, "RESOLVED_ACCOUNT_ID", "T");
			setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE_WEB_ID", "k");
			return credentials;
		};
	};
	isH2 = (requestHandler) => {
		return requestHandler?.metadata?.handlerProtocol === "h2";
	};
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultRoleAssumers.js
var getCustomizableStsClientCtor, getDefaultRoleAssumer, getDefaultRoleAssumerWithWebIdentity, decorateDefaultCredentialProvider;
var init_defaultRoleAssumers = __esmMin((() => {
	init_defaultStsRoleAssumers();
	init_STSClient();
	getCustomizableStsClientCtor = (baseCtor, customizations) => {
		if (!customizations) return baseCtor;
		else return class CustomizableSTSClient extends baseCtor {
			constructor(config) {
				super(config);
				for (const customization of customizations) this.middlewareStack.use(customization);
			}
		};
	};
	getDefaultRoleAssumer = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumer$1(stsOptions, getCustomizableStsClientCtor(STSClient$1, stsPlugins));
	getDefaultRoleAssumerWithWebIdentity = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumerWithWebIdentity$1(stsOptions, getCustomizableStsClientCtor(STSClient$1, stsPlugins));
	decorateDefaultCredentialProvider = (provider) => (input) => provider({
		roleAssumer: getDefaultRoleAssumer(input),
		roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity(input),
		...input
	});
}));

//#endregion
//#region node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/index.js
var sts_exports = /* @__PURE__ */ __exportAll({
	AssumeRole$: () => AssumeRole$,
	AssumeRoleCommand: () => AssumeRoleCommand,
	AssumeRoleRequest$: () => AssumeRoleRequest$,
	AssumeRoleResponse$: () => AssumeRoleResponse$,
	AssumeRoleWithWebIdentity$: () => AssumeRoleWithWebIdentity$,
	AssumeRoleWithWebIdentityCommand: () => AssumeRoleWithWebIdentityCommand,
	AssumeRoleWithWebIdentityRequest$: () => AssumeRoleWithWebIdentityRequest$,
	AssumeRoleWithWebIdentityResponse$: () => AssumeRoleWithWebIdentityResponse$,
	AssumedRoleUser$: () => AssumedRoleUser$,
	Credentials$: () => Credentials$,
	ExpiredTokenException: () => ExpiredTokenException,
	ExpiredTokenException$: () => ExpiredTokenException$,
	IDPCommunicationErrorException: () => IDPCommunicationErrorException,
	IDPCommunicationErrorException$: () => IDPCommunicationErrorException$,
	IDPRejectedClaimException: () => IDPRejectedClaimException,
	IDPRejectedClaimException$: () => IDPRejectedClaimException$,
	InvalidIdentityTokenException: () => InvalidIdentityTokenException,
	InvalidIdentityTokenException$: () => InvalidIdentityTokenException$,
	MalformedPolicyDocumentException: () => MalformedPolicyDocumentException,
	MalformedPolicyDocumentException$: () => MalformedPolicyDocumentException$,
	PackedPolicyTooLargeException: () => PackedPolicyTooLargeException,
	PackedPolicyTooLargeException$: () => PackedPolicyTooLargeException$,
	PolicyDescriptorType$: () => PolicyDescriptorType$,
	ProvidedContext$: () => ProvidedContext$,
	RegionDisabledException: () => RegionDisabledException,
	RegionDisabledException$: () => RegionDisabledException$,
	STS: () => STS,
	STSClient: () => STSClient$1,
	STSServiceException: () => STSServiceException,
	STSServiceException$: () => STSServiceException$,
	Tag$: () => Tag$,
	__Client: () => import_dist_cjs$16.Client,
	decorateDefaultCredentialProvider: () => decorateDefaultCredentialProvider,
	getDefaultRoleAssumer: () => getDefaultRoleAssumer,
	getDefaultRoleAssumerWithWebIdentity: () => getDefaultRoleAssumerWithWebIdentity
});
var init_sts = __esmMin((() => {
	init_STSClient();
	init_STS();
	init_commands();
	init_schemas_0();
	init_errors();
	init_models_0();
	init_defaultRoleAssumers();
	init_STSServiceException();
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-process/dist-cjs/index.js
var require_dist_cjs$4 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var sharedIniFileLoader = require_dist_cjs$22();
	var propertyProvider = require_dist_cjs$31();
	var child_process = require("child_process");
	var util = require("util");
	var client = (init_client(), __toCommonJS(client_exports));
	const getValidatedProcessCredentials = (profileName, data$1, profiles) => {
		if (data$1.Version !== 1) throw Error(`Profile ${profileName} credential_process did not return Version 1.`);
		if (data$1.AccessKeyId === void 0 || data$1.SecretAccessKey === void 0) throw Error(`Profile ${profileName} credential_process returned invalid credentials.`);
		if (data$1.Expiration) {
			const currentTime = /* @__PURE__ */ new Date();
			if (new Date(data$1.Expiration) < currentTime) throw Error(`Profile ${profileName} credential_process returned expired credentials.`);
		}
		let accountId = data$1.AccountId;
		if (!accountId && profiles?.[profileName]?.aws_account_id) accountId = profiles[profileName].aws_account_id;
		const credentials = {
			accessKeyId: data$1.AccessKeyId,
			secretAccessKey: data$1.SecretAccessKey,
			...data$1.SessionToken && { sessionToken: data$1.SessionToken },
			...data$1.Expiration && { expiration: new Date(data$1.Expiration) },
			...data$1.CredentialScope && { credentialScope: data$1.CredentialScope },
			...accountId && { accountId }
		};
		client.setCredentialFeature(credentials, "CREDENTIALS_PROCESS", "w");
		return credentials;
	};
	const resolveProcessCredentials = async (profileName, profiles, logger$1) => {
		const profile = profiles[profileName];
		if (profiles[profileName]) {
			const credentialProcess = profile["credential_process"];
			if (credentialProcess !== void 0) {
				const execPromise = util.promisify(sharedIniFileLoader.externalDataInterceptor?.getTokenRecord?.().exec ?? child_process.exec);
				try {
					const { stdout } = await execPromise(credentialProcess);
					let data$1;
					try {
						data$1 = JSON.parse(stdout.trim());
					} catch {
						throw Error(`Profile ${profileName} credential_process returned invalid JSON.`);
					}
					return getValidatedProcessCredentials(profileName, data$1, profiles);
				} catch (error$1) {
					throw new propertyProvider.CredentialsProviderError(error$1.message, { logger: logger$1 });
				}
			} else throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} did not contain credential_process.`, { logger: logger$1 });
		} else throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} could not be found in shared credentials file.`, { logger: logger$1 });
	};
	const fromProcess = (init = {}) => async ({ callerClientConfig } = {}) => {
		init.logger?.debug("@aws-sdk/credential-provider-process - fromProcess");
		const profiles = await sharedIniFileLoader.parseKnownFiles(init);
		return resolveProcessCredentials(sharedIniFileLoader.getProfileName({ profile: init.profile ?? callerClientConfig?.profile }), profiles, init.logger);
	};
	exports.fromProcess = fromProcess;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/fromWebToken.js
var require_fromWebToken = /* @__PURE__ */ __commonJSMin(((exports) => {
	var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o$3, m$3, k$3, k2) {
		if (k2 === void 0) k2 = k$3;
		var desc = Object.getOwnPropertyDescriptor(m$3, k$3);
		if (!desc || ("get" in desc ? !m$3.__esModule : desc.writable || desc.configurable)) desc = {
			enumerable: true,
			get: function() {
				return m$3[k$3];
			}
		};
		Object.defineProperty(o$3, k2, desc);
	}) : (function(o$3, m$3, k$3, k2) {
		if (k2 === void 0) k2 = k$3;
		o$3[k2] = m$3[k$3];
	}));
	var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o$3, v$3) {
		Object.defineProperty(o$3, "default", {
			enumerable: true,
			value: v$3
		});
	}) : function(o$3, v$3) {
		o$3["default"] = v$3;
	});
	var __importStar = exports && exports.__importStar || (function() {
		var ownKeys$1 = function(o$3) {
			ownKeys$1 = Object.getOwnPropertyNames || function(o$4) {
				var ar = [];
				for (var k$3 in o$4) if (Object.prototype.hasOwnProperty.call(o$4, k$3)) ar[ar.length] = k$3;
				return ar;
			};
			return ownKeys$1(o$3);
		};
		return function(mod) {
			if (mod && mod.__esModule) return mod;
			var result = {};
			if (mod != null) {
				for (var k$3 = ownKeys$1(mod), i$3 = 0; i$3 < k$3.length; i$3++) if (k$3[i$3] !== "default") __createBinding(result, mod, k$3[i$3]);
			}
			__setModuleDefault(result, mod);
			return result;
		};
	})();
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.fromWebToken = void 0;
	const fromWebToken = (init) => async (awsIdentityProperties) => {
		init.logger?.debug("@aws-sdk/credential-provider-web-identity - fromWebToken");
		const { roleArn, roleSessionName, webIdentityToken, providerId, policyArns, policy, durationSeconds } = init;
		let { roleAssumerWithWebIdentity } = init;
		if (!roleAssumerWithWebIdentity) {
			const { getDefaultRoleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity$2 } = await Promise.resolve().then(() => __importStar((init_sts(), __toCommonJS(sts_exports))));
			roleAssumerWithWebIdentity = getDefaultRoleAssumerWithWebIdentity$2({
				...init.clientConfig,
				credentialProviderLogger: init.logger,
				parentClientConfig: {
					...awsIdentityProperties?.callerClientConfig,
					...init.parentClientConfig
				}
			}, init.clientPlugins);
		}
		return roleAssumerWithWebIdentity({
			RoleArn: roleArn,
			RoleSessionName: roleSessionName ?? `aws-sdk-js-session-${Date.now()}`,
			WebIdentityToken: webIdentityToken,
			ProviderId: providerId,
			PolicyArns: policyArns,
			Policy: policy,
			DurationSeconds: durationSeconds
		});
	};
	exports.fromWebToken = fromWebToken;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/fromTokenFile.js
var require_fromTokenFile = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.fromTokenFile = void 0;
	const client_1 = (init_client(), __toCommonJS(client_exports));
	const property_provider_1 = require_dist_cjs$31();
	const shared_ini_file_loader_1 = require_dist_cjs$22();
	const fs_1 = require("fs");
	const fromWebToken_1 = require_fromWebToken();
	const ENV_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE";
	const ENV_ROLE_ARN = "AWS_ROLE_ARN";
	const ENV_ROLE_SESSION_NAME = "AWS_ROLE_SESSION_NAME";
	const fromTokenFile = (init = {}) => async (awsIdentityProperties) => {
		init.logger?.debug("@aws-sdk/credential-provider-web-identity - fromTokenFile");
		const webIdentityTokenFile = init?.webIdentityTokenFile ?? process.env[ENV_TOKEN_FILE];
		const roleArn = init?.roleArn ?? process.env[ENV_ROLE_ARN];
		const roleSessionName = init?.roleSessionName ?? process.env[ENV_ROLE_SESSION_NAME];
		if (!webIdentityTokenFile || !roleArn) throw new property_provider_1.CredentialsProviderError("Web identity configuration not specified", { logger: init.logger });
		const credentials = await (0, fromWebToken_1.fromWebToken)({
			...init,
			webIdentityToken: shared_ini_file_loader_1.externalDataInterceptor?.getTokenRecord?.()[webIdentityTokenFile] ?? (0, fs_1.readFileSync)(webIdentityTokenFile, { encoding: "ascii" }),
			roleArn,
			roleSessionName
		})(awsIdentityProperties);
		if (webIdentityTokenFile === process.env[ENV_TOKEN_FILE]) (0, client_1.setCredentialFeature)(credentials, "CREDENTIALS_ENV_VARS_STS_WEB_ID_TOKEN", "h");
		return credentials;
	};
	exports.fromTokenFile = fromTokenFile;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/index.js
var require_dist_cjs$3 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var fromTokenFile = require_fromTokenFile();
	var fromWebToken = require_fromWebToken();
	Object.keys(fromTokenFile).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return fromTokenFile[k$3];
			}
		});
	});
	Object.keys(fromWebToken).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return fromWebToken[k$3];
			}
		});
	});
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-ini/dist-cjs/index.js
var require_dist_cjs$2 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var sharedIniFileLoader = require_dist_cjs$22();
	var propertyProvider = require_dist_cjs$31();
	var client = (init_client(), __toCommonJS(client_exports));
	var credentialProviderLogin = require_dist_cjs$5();
	const resolveCredentialSource = (credentialSource, profileName, logger$1) => {
		const sourceProvidersMap = {
			EcsContainer: async (options) => {
				const { fromHttp } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$14()));
				const { fromContainerMetadata } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$15()));
				logger$1?.debug("@aws-sdk/credential-provider-ini - credential_source is EcsContainer");
				return async () => propertyProvider.chain(fromHttp(options ?? {}), fromContainerMetadata(options))().then(setNamedProvider);
			},
			Ec2InstanceMetadata: async (options) => {
				logger$1?.debug("@aws-sdk/credential-provider-ini - credential_source is Ec2InstanceMetadata");
				const { fromInstanceMetadata } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$15()));
				return async () => fromInstanceMetadata(options)().then(setNamedProvider);
			},
			Environment: async (options) => {
				logger$1?.debug("@aws-sdk/credential-provider-ini - credential_source is Environment");
				const { fromEnv } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$16()));
				return async () => fromEnv(options)().then(setNamedProvider);
			}
		};
		if (credentialSource in sourceProvidersMap) return sourceProvidersMap[credentialSource];
		else throw new propertyProvider.CredentialsProviderError(`Unsupported credential source in profile ${profileName}. Got ${credentialSource}, expected EcsContainer or Ec2InstanceMetadata or Environment.`, { logger: logger$1 });
	};
	const setNamedProvider = (creds) => client.setCredentialFeature(creds, "CREDENTIALS_PROFILE_NAMED_PROVIDER", "p");
	const isAssumeRoleProfile = (arg, { profile = "default", logger: logger$1 } = {}) => {
		return Boolean(arg) && typeof arg === "object" && typeof arg.role_arn === "string" && ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1 && ["undefined", "string"].indexOf(typeof arg.external_id) > -1 && ["undefined", "string"].indexOf(typeof arg.mfa_serial) > -1 && (isAssumeRoleWithSourceProfile(arg, {
			profile,
			logger: logger$1
		}) || isCredentialSourceProfile(arg, {
			profile,
			logger: logger$1
		}));
	};
	const isAssumeRoleWithSourceProfile = (arg, { profile, logger: logger$1 }) => {
		const withSourceProfile = typeof arg.source_profile === "string" && typeof arg.credential_source === "undefined";
		if (withSourceProfile) logger$1?.debug?.(`    ${profile} isAssumeRoleWithSourceProfile source_profile=${arg.source_profile}`);
		return withSourceProfile;
	};
	const isCredentialSourceProfile = (arg, { profile, logger: logger$1 }) => {
		const withProviderProfile = typeof arg.credential_source === "string" && typeof arg.source_profile === "undefined";
		if (withProviderProfile) logger$1?.debug?.(`    ${profile} isCredentialSourceProfile credential_source=${arg.credential_source}`);
		return withProviderProfile;
	};
	const resolveAssumeRoleCredentials = async (profileName, profiles, options, callerClientConfig, visitedProfiles = {}, resolveProfileData) => {
		options.logger?.debug("@aws-sdk/credential-provider-ini - resolveAssumeRoleCredentials (STS)");
		const profileData = profiles[profileName];
		const { source_profile, region } = profileData;
		if (!options.roleAssumer) {
			const { getDefaultRoleAssumer: getDefaultRoleAssumer$2 } = await Promise.resolve().then(() => (init_sts(), sts_exports));
			options.roleAssumer = getDefaultRoleAssumer$2({
				...options.clientConfig,
				credentialProviderLogger: options.logger,
				parentClientConfig: {
					...callerClientConfig,
					...options?.parentClientConfig,
					region: region ?? options?.parentClientConfig?.region ?? callerClientConfig?.region
				}
			}, options.clientPlugins);
		}
		if (source_profile && source_profile in visitedProfiles) throw new propertyProvider.CredentialsProviderError(`Detected a cycle attempting to resolve credentials for profile ${sharedIniFileLoader.getProfileName(options)}. Profiles visited: ` + Object.keys(visitedProfiles).join(", "), { logger: options.logger });
		options.logger?.debug(`@aws-sdk/credential-provider-ini - finding credential resolver using ${source_profile ? `source_profile=[${source_profile}]` : `profile=[${profileName}]`}`);
		const sourceCredsProvider = source_profile ? resolveProfileData(source_profile, profiles, options, callerClientConfig, {
			...visitedProfiles,
			[source_profile]: true
		}, isCredentialSourceWithoutRoleArn(profiles[source_profile] ?? {})) : (await resolveCredentialSource(profileData.credential_source, profileName, options.logger)(options))();
		if (isCredentialSourceWithoutRoleArn(profileData)) return sourceCredsProvider.then((creds) => client.setCredentialFeature(creds, "CREDENTIALS_PROFILE_SOURCE_PROFILE", "o"));
		else {
			const params = {
				RoleArn: profileData.role_arn,
				RoleSessionName: profileData.role_session_name || `aws-sdk-js-${Date.now()}`,
				ExternalId: profileData.external_id,
				DurationSeconds: parseInt(profileData.duration_seconds || "3600", 10)
			};
			const { mfa_serial } = profileData;
			if (mfa_serial) {
				if (!options.mfaCodeProvider) throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} requires multi-factor authentication, but no MFA code callback was provided.`, {
					logger: options.logger,
					tryNextLink: false
				});
				params.SerialNumber = mfa_serial;
				params.TokenCode = await options.mfaCodeProvider(mfa_serial);
			}
			const sourceCreds = await sourceCredsProvider;
			return options.roleAssumer(sourceCreds, params).then((creds) => client.setCredentialFeature(creds, "CREDENTIALS_PROFILE_SOURCE_PROFILE", "o"));
		}
	};
	const isCredentialSourceWithoutRoleArn = (section) => {
		return !section.role_arn && !!section.credential_source;
	};
	const isLoginProfile = (data$1) => {
		return Boolean(data$1 && data$1.login_session);
	};
	const resolveLoginCredentials = async (profileName, options, callerClientConfig) => {
		const credentials = await credentialProviderLogin.fromLoginCredentials({
			...options,
			profile: profileName
		})({ callerClientConfig });
		return client.setCredentialFeature(credentials, "CREDENTIALS_PROFILE_LOGIN", "AC");
	};
	const isProcessProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.credential_process === "string";
	const resolveProcessCredentials = async (options, profile) => Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$4())).then(({ fromProcess }) => fromProcess({
		...options,
		profile
	})().then((creds) => client.setCredentialFeature(creds, "CREDENTIALS_PROFILE_PROCESS", "v")));
	const resolveSsoCredentials = async (profile, profileData, options = {}, callerClientConfig) => {
		const { fromSSO } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$6()));
		return fromSSO({
			profile,
			logger: options.logger,
			parentClientConfig: options.parentClientConfig,
			clientConfig: options.clientConfig
		})({ callerClientConfig }).then((creds) => {
			if (profileData.sso_session) return client.setCredentialFeature(creds, "CREDENTIALS_PROFILE_SSO", "r");
			else return client.setCredentialFeature(creds, "CREDENTIALS_PROFILE_SSO_LEGACY", "t");
		});
	};
	const isSsoProfile = (arg) => arg && (typeof arg.sso_start_url === "string" || typeof arg.sso_account_id === "string" || typeof arg.sso_session === "string" || typeof arg.sso_region === "string" || typeof arg.sso_role_name === "string");
	const isStaticCredsProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.aws_access_key_id === "string" && typeof arg.aws_secret_access_key === "string" && ["undefined", "string"].indexOf(typeof arg.aws_session_token) > -1 && ["undefined", "string"].indexOf(typeof arg.aws_account_id) > -1;
	const resolveStaticCredentials = async (profile, options) => {
		options?.logger?.debug("@aws-sdk/credential-provider-ini - resolveStaticCredentials");
		const credentials = {
			accessKeyId: profile.aws_access_key_id,
			secretAccessKey: profile.aws_secret_access_key,
			sessionToken: profile.aws_session_token,
			...profile.aws_credential_scope && { credentialScope: profile.aws_credential_scope },
			...profile.aws_account_id && { accountId: profile.aws_account_id }
		};
		return client.setCredentialFeature(credentials, "CREDENTIALS_PROFILE", "n");
	};
	const isWebIdentityProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.web_identity_token_file === "string" && typeof arg.role_arn === "string" && ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1;
	const resolveWebIdentityCredentials = async (profile, options, callerClientConfig) => Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$3())).then(({ fromTokenFile }) => fromTokenFile({
		webIdentityTokenFile: profile.web_identity_token_file,
		roleArn: profile.role_arn,
		roleSessionName: profile.role_session_name,
		roleAssumerWithWebIdentity: options.roleAssumerWithWebIdentity,
		logger: options.logger,
		parentClientConfig: options.parentClientConfig
	})({ callerClientConfig }).then((creds) => client.setCredentialFeature(creds, "CREDENTIALS_PROFILE_STS_WEB_ID_TOKEN", "q")));
	const resolveProfileData = async (profileName, profiles, options, callerClientConfig, visitedProfiles = {}, isAssumeRoleRecursiveCall = false) => {
		const data$1 = profiles[profileName];
		if (Object.keys(visitedProfiles).length > 0 && isStaticCredsProfile(data$1)) return resolveStaticCredentials(data$1, options);
		if (isAssumeRoleRecursiveCall || isAssumeRoleProfile(data$1, {
			profile: profileName,
			logger: options.logger
		})) return resolveAssumeRoleCredentials(profileName, profiles, options, callerClientConfig, visitedProfiles, resolveProfileData);
		if (isStaticCredsProfile(data$1)) return resolveStaticCredentials(data$1, options);
		if (isWebIdentityProfile(data$1)) return resolveWebIdentityCredentials(data$1, options, callerClientConfig);
		if (isProcessProfile(data$1)) return resolveProcessCredentials(options, profileName);
		if (isSsoProfile(data$1)) return await resolveSsoCredentials(profileName, data$1, options, callerClientConfig);
		if (isLoginProfile(data$1)) return resolveLoginCredentials(profileName, options, callerClientConfig);
		throw new propertyProvider.CredentialsProviderError(`Could not resolve credentials using profile: [${profileName}] in configuration/credentials file(s).`, { logger: options.logger });
	};
	const fromIni = (init = {}) => async ({ callerClientConfig } = {}) => {
		init.logger?.debug("@aws-sdk/credential-provider-ini - fromIni");
		const profiles = await sharedIniFileLoader.parseKnownFiles(init);
		return resolveProfileData(sharedIniFileLoader.getProfileName({ profile: init.profile ?? callerClientConfig?.profile }), profiles, init, callerClientConfig);
	};
	exports.fromIni = fromIni;
}));

//#endregion
//#region node_modules/@aws-sdk/credential-provider-node/dist-cjs/index.js
var require_dist_cjs$1 = /* @__PURE__ */ __commonJSMin(((exports) => {
	var credentialProviderEnv = require_dist_cjs$16();
	var propertyProvider = require_dist_cjs$31();
	var sharedIniFileLoader = require_dist_cjs$22();
	const ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
	const remoteProvider = async (init) => {
		const { ENV_CMDS_FULL_URI, ENV_CMDS_RELATIVE_URI, fromContainerMetadata, fromInstanceMetadata } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$15()));
		if (process.env[ENV_CMDS_RELATIVE_URI] || process.env[ENV_CMDS_FULL_URI]) {
			init.logger?.debug("@aws-sdk/credential-provider-node - remoteProvider::fromHttp/fromContainerMetadata");
			const { fromHttp } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$14()));
			return propertyProvider.chain(fromHttp(init), fromContainerMetadata(init));
		}
		if (process.env[ENV_IMDS_DISABLED] && process.env[ENV_IMDS_DISABLED] !== "false") return async () => {
			throw new propertyProvider.CredentialsProviderError("EC2 Instance Metadata Service access disabled", { logger: init.logger });
		};
		init.logger?.debug("@aws-sdk/credential-provider-node - remoteProvider::fromInstanceMetadata");
		return fromInstanceMetadata(init);
	};
	function memoizeChain(providers, treatAsExpired) {
		const chain = internalCreateChain(providers);
		let activeLock;
		let passiveLock;
		let credentials;
		const provider = async (options) => {
			if (options?.forceRefresh) return await chain(options);
			if (credentials?.expiration) {
				if (credentials?.expiration?.getTime() < Date.now()) credentials = void 0;
			}
			if (activeLock) await activeLock;
			else if (!credentials || treatAsExpired?.(credentials)) if (credentials) {
				if (!passiveLock) passiveLock = chain(options).then((c$3) => {
					credentials = c$3;
					passiveLock = void 0;
				});
			} else {
				activeLock = chain(options).then((c$3) => {
					credentials = c$3;
					activeLock = void 0;
				});
				return provider(options);
			}
			return credentials;
		};
		return provider;
	}
	const internalCreateChain = (providers) => async (awsIdentityProperties) => {
		let lastProviderError;
		for (const provider of providers) try {
			return await provider(awsIdentityProperties);
		} catch (err) {
			lastProviderError = err;
			if (err?.tryNextLink) continue;
			throw err;
		}
		throw lastProviderError;
	};
	let multipleCredentialSourceWarningEmitted = false;
	const defaultProvider = (init = {}) => memoizeChain([
		async () => {
			if (init.profile ?? process.env[sharedIniFileLoader.ENV_PROFILE]) {
				if (process.env[credentialProviderEnv.ENV_KEY] && process.env[credentialProviderEnv.ENV_SECRET]) {
					if (!multipleCredentialSourceWarningEmitted) {
						(init.logger?.warn && init.logger?.constructor?.name !== "NoOpLogger" ? init.logger.warn.bind(init.logger) : console.warn)(`@aws-sdk/credential-provider-node - defaultProvider::fromEnv WARNING:
    Multiple credential sources detected: 
    Both AWS_PROFILE and the pair AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY static credentials are set.
    This SDK will proceed with the AWS_PROFILE value.
    
    However, a future version may change this behavior to prefer the ENV static credentials.
    Please ensure that your environment only sets either the AWS_PROFILE or the
    AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY pair.
`);
						multipleCredentialSourceWarningEmitted = true;
					}
				}
				throw new propertyProvider.CredentialsProviderError("AWS_PROFILE is set, skipping fromEnv provider.", {
					logger: init.logger,
					tryNextLink: true
				});
			}
			init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromEnv");
			return credentialProviderEnv.fromEnv(init)();
		},
		async (awsIdentityProperties) => {
			init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromSSO");
			const { ssoStartUrl, ssoAccountId, ssoRegion, ssoRoleName, ssoSession } = init;
			if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) throw new propertyProvider.CredentialsProviderError("Skipping SSO provider in default chain (inputs do not include SSO fields).", { logger: init.logger });
			const { fromSSO } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$6()));
			return fromSSO(init)(awsIdentityProperties);
		},
		async (awsIdentityProperties) => {
			init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromIni");
			const { fromIni } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$2()));
			return fromIni(init)(awsIdentityProperties);
		},
		async (awsIdentityProperties) => {
			init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromProcess");
			const { fromProcess } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$4()));
			return fromProcess(init)(awsIdentityProperties);
		},
		async (awsIdentityProperties) => {
			init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromTokenFile");
			const { fromTokenFile } = await Promise.resolve().then(() => /* @__PURE__ */ __toESM(require_dist_cjs$3()));
			return fromTokenFile(init)(awsIdentityProperties);
		},
		async () => {
			init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::remoteProvider");
			return (await remoteProvider(init))();
		},
		async () => {
			throw new propertyProvider.CredentialsProviderError("Could not load credentials from any providers", {
				tryNextLink: false,
				logger: init.logger
			});
		}
	], credentialsTreatedAsExpired);
	const credentialsWillNeedRefresh = (credentials) => credentials?.expiration !== void 0;
	const credentialsTreatedAsExpired = (credentials) => credentials?.expiration !== void 0 && credentials.expiration.getTime() - Date.now() < 3e5;
	exports.credentialsTreatedAsExpired = credentialsTreatedAsExpired;
	exports.credentialsWillNeedRefresh = credentialsWillNeedRefresh;
	exports.defaultProvider = defaultProvider;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/ruleset.js
var require_ruleset = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.ruleSet = void 0;
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
	exports.ruleSet = _data;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/endpointResolver.js
var require_endpointResolver = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.defaultEndpointResolver = void 0;
	const util_endpoints_1 = require_dist_cjs$32();
	const util_endpoints_2 = require_dist_cjs$35();
	const ruleset_1 = require_ruleset();
	const cache = new util_endpoints_2.EndpointCache({
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
		return cache.get(endpointParams, () => (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
			endpointParams,
			logger: context.logger
		}));
	};
	exports.defaultEndpointResolver = defaultEndpointResolver;
	util_endpoints_2.customEndpointFunctions.aws = util_endpoints_1.awsEndpointFunctions;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/runtimeConfig.shared.js
var require_runtimeConfig_shared = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getRuntimeConfig = void 0;
	const core_1 = (init_dist_es(), __toCommonJS(dist_es_exports));
	const protocols_1 = (init_protocols(), __toCommonJS(protocols_exports));
	const core_2 = (init_dist_es$1(), __toCommonJS(dist_es_exports$1));
	const smithy_client_1 = require_dist_cjs$28();
	const url_parser_1 = require_dist_cjs$33();
	const util_base64_1 = require_dist_cjs$43();
	const util_utf8_1 = require_dist_cjs$44();
	const httpAuthSchemeProvider_1 = require_httpAuthSchemeProvider$1();
	const endpointResolver_1 = require_endpointResolver();
	const getRuntimeConfig = (config) => {
		return {
			apiVersion: "2011-06-15",
			base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
			base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
			disableHostPrefix: config?.disableHostPrefix ?? false,
			endpointProvider: config?.endpointProvider ?? endpointResolver_1.defaultEndpointResolver,
			extensions: config?.extensions ?? [],
			httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? httpAuthSchemeProvider_1.defaultSTSHttpAuthSchemeProvider,
			httpAuthSchemes: config?.httpAuthSchemes ?? [{
				schemeId: "aws.auth#sigv4",
				identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
				signer: new core_1.AwsSdkSigV4Signer()
			}, {
				schemeId: "smithy.api#noAuth",
				identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
				signer: new core_2.NoAuthSigner()
			}],
			logger: config?.logger ?? new smithy_client_1.NoOpLogger(),
			protocol: config?.protocol ?? protocols_1.AwsQueryProtocol,
			protocolSettings: config?.protocolSettings ?? {
				defaultNamespace: "com.amazonaws.sts",
				xmlNamespace: "https://sts.amazonaws.com/doc/2011-06-15/",
				version: "2011-06-15",
				serviceTarget: "AWSSecurityTokenServiceV20110615"
			},
			serviceId: config?.serviceId ?? "STS",
			urlParser: config?.urlParser ?? url_parser_1.parseUrl,
			utf8Decoder: config?.utf8Decoder ?? util_utf8_1.fromUtf8,
			utf8Encoder: config?.utf8Encoder ?? util_utf8_1.toUtf8
		};
	};
	exports.getRuntimeConfig = getRuntimeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/runtimeConfig.js
var require_runtimeConfig = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.getRuntimeConfig = void 0;
	const package_json_1 = (init_tslib_es6(), __toCommonJS(tslib_es6_exports)).__importDefault(require_package$1());
	const core_1 = (init_dist_es(), __toCommonJS(dist_es_exports));
	const credential_provider_node_1 = require_dist_cjs$1();
	const util_user_agent_node_1 = require_dist_cjs$13();
	const config_resolver_1 = require_dist_cjs$24();
	const core_2 = (init_dist_es$1(), __toCommonJS(dist_es_exports$1));
	const hash_node_1 = require_dist_cjs$12();
	const middleware_retry_1 = require_dist_cjs$17();
	const node_config_provider_1 = require_dist_cjs$21();
	const node_http_handler_1 = require_dist_cjs$40();
	const smithy_client_1 = require_dist_cjs$28();
	const util_body_length_node_1 = require_dist_cjs$11();
	const util_defaults_mode_node_1 = require_dist_cjs$10();
	const util_retry_1 = require_dist_cjs$18();
	const runtimeConfig_shared_1 = require_runtimeConfig_shared();
	const getRuntimeConfig = (config) => {
		(0, smithy_client_1.emitWarningIfUnsupportedVersion)(process.version);
		const defaultsMode = (0, util_defaults_mode_node_1.resolveDefaultsModeConfig)(config);
		const defaultConfigProvider = () => defaultsMode().then(smithy_client_1.loadConfigsForDefaultMode);
		const clientSharedValues = (0, runtimeConfig_shared_1.getRuntimeConfig)(config);
		(0, core_1.emitWarningIfUnsupportedVersion)(process.version);
		const loaderConfig = {
			profile: config?.profile,
			logger: clientSharedValues.logger
		};
		return {
			...clientSharedValues,
			...config,
			runtime: "node",
			defaultsMode,
			authSchemePreference: config?.authSchemePreference ?? (0, node_config_provider_1.loadConfig)(core_1.NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
			bodyLengthChecker: config?.bodyLengthChecker ?? util_body_length_node_1.calculateBodyLength,
			credentialDefaultProvider: config?.credentialDefaultProvider ?? credential_provider_node_1.defaultProvider,
			defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, util_user_agent_node_1.createDefaultUserAgentProvider)({
				serviceId: clientSharedValues.serviceId,
				clientVersion: package_json_1.default.version
			}),
			httpAuthSchemes: config?.httpAuthSchemes ?? [{
				schemeId: "aws.auth#sigv4",
				identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4") || (async (idProps) => await (0, credential_provider_node_1.defaultProvider)(idProps?.__config || {})()),
				signer: new core_1.AwsSdkSigV4Signer()
			}, {
				schemeId: "smithy.api#noAuth",
				identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
				signer: new core_2.NoAuthSigner()
			}],
			maxAttempts: config?.maxAttempts ?? (0, node_config_provider_1.loadConfig)(middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
			region: config?.region ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_REGION_CONFIG_OPTIONS, {
				...config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS,
				...loaderConfig
			}),
			requestHandler: node_http_handler_1.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
			retryMode: config?.retryMode ?? (0, node_config_provider_1.loadConfig)({
				...middleware_retry_1.NODE_RETRY_MODE_CONFIG_OPTIONS,
				default: async () => (await defaultConfigProvider()).retryMode || util_retry_1.DEFAULT_RETRY_MODE
			}, config),
			sha256: config?.sha256 ?? hash_node_1.Hash.bind(null, "sha256"),
			streamCollector: config?.streamCollector ?? node_http_handler_1.streamCollector,
			useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			useFipsEndpoint: config?.useFipsEndpoint ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
			userAgentAppId: config?.userAgentAppId ?? (0, node_config_provider_1.loadConfig)(util_user_agent_node_1.NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
		};
	};
	exports.getRuntimeConfig = getRuntimeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/auth/httpAuthExtensionConfiguration.js
var require_httpAuthExtensionConfiguration = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.resolveHttpAuthRuntimeConfig = exports.getHttpAuthExtensionConfiguration = void 0;
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
	exports.getHttpAuthExtensionConfiguration = getHttpAuthExtensionConfiguration;
	const resolveHttpAuthRuntimeConfig = (config) => {
		return {
			httpAuthSchemes: config.httpAuthSchemes(),
			httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
			credentials: config.credentials()
		};
	};
	exports.resolveHttpAuthRuntimeConfig = resolveHttpAuthRuntimeConfig;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/runtimeExtensions.js
var require_runtimeExtensions = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.resolveRuntimeExtensions = void 0;
	const region_config_resolver_1 = require_dist_cjs$9();
	const protocol_http_1 = require_dist_cjs$52();
	const smithy_client_1 = require_dist_cjs$28();
	const httpAuthExtensionConfiguration_1 = require_httpAuthExtensionConfiguration();
	const resolveRuntimeExtensions = (runtimeConfig, extensions) => {
		const extensionConfiguration = Object.assign((0, region_config_resolver_1.getAwsRegionExtensionConfiguration)(runtimeConfig), (0, smithy_client_1.getDefaultExtensionConfiguration)(runtimeConfig), (0, protocol_http_1.getHttpHandlerExtensionConfiguration)(runtimeConfig), (0, httpAuthExtensionConfiguration_1.getHttpAuthExtensionConfiguration)(runtimeConfig));
		extensions.forEach((extension) => extension.configure(extensionConfiguration));
		return Object.assign(runtimeConfig, (0, region_config_resolver_1.resolveAwsRegionExtensionConfiguration)(extensionConfiguration), (0, smithy_client_1.resolveDefaultRuntimeConfig)(extensionConfiguration), (0, protocol_http_1.resolveHttpHandlerRuntimeConfig)(extensionConfiguration), (0, httpAuthExtensionConfiguration_1.resolveHttpAuthRuntimeConfig)(extensionConfiguration));
	};
	exports.resolveRuntimeExtensions = resolveRuntimeExtensions;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/STSClient.js
var require_STSClient = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.STSClient = exports.__Client = void 0;
	const middleware_host_header_1 = require_dist_cjs$51();
	const middleware_logger_1 = require_dist_cjs$50();
	const middleware_recursion_detection_1 = require_dist_cjs$49();
	const middleware_user_agent_1 = require_dist_cjs$26();
	const config_resolver_1 = require_dist_cjs$24();
	const core_1 = (init_dist_es$1(), __toCommonJS(dist_es_exports$1));
	const schema_1 = (init_schema(), __toCommonJS(schema_exports));
	const middleware_content_length_1 = require_dist_cjs$23();
	const middleware_endpoint_1 = require_dist_cjs$20();
	const middleware_retry_1 = require_dist_cjs$17();
	const smithy_client_1 = require_dist_cjs$28();
	Object.defineProperty(exports, "__Client", {
		enumerable: true,
		get: function() {
			return smithy_client_1.Client;
		}
	});
	const httpAuthSchemeProvider_1 = require_httpAuthSchemeProvider$1();
	const EndpointParameters_1 = require_EndpointParameters();
	const runtimeConfig_1 = require_runtimeConfig();
	const runtimeExtensions_1 = require_runtimeExtensions();
	var STSClient = class extends smithy_client_1.Client {
		config;
		constructor(...[configuration]) {
			const _config_0 = (0, runtimeConfig_1.getRuntimeConfig)(configuration || {});
			super(_config_0);
			this.initConfig = _config_0;
			const _config_1 = (0, EndpointParameters_1.resolveClientEndpointParameters)(_config_0);
			const _config_2 = (0, middleware_user_agent_1.resolveUserAgentConfig)(_config_1);
			const _config_3 = (0, middleware_retry_1.resolveRetryConfig)(_config_2);
			const _config_4 = (0, config_resolver_1.resolveRegionConfig)(_config_3);
			const _config_5 = (0, middleware_host_header_1.resolveHostHeaderConfig)(_config_4);
			const _config_6 = (0, middleware_endpoint_1.resolveEndpointConfig)(_config_5);
			const _config_7 = (0, httpAuthSchemeProvider_1.resolveHttpAuthSchemeConfig)(_config_6);
			this.config = (0, runtimeExtensions_1.resolveRuntimeExtensions)(_config_7, configuration?.extensions || []);
			this.middlewareStack.use((0, schema_1.getSchemaSerdePlugin)(this.config));
			this.middlewareStack.use((0, middleware_user_agent_1.getUserAgentPlugin)(this.config));
			this.middlewareStack.use((0, middleware_retry_1.getRetryPlugin)(this.config));
			this.middlewareStack.use((0, middleware_content_length_1.getContentLengthPlugin)(this.config));
			this.middlewareStack.use((0, middleware_host_header_1.getHostHeaderPlugin)(this.config));
			this.middlewareStack.use((0, middleware_logger_1.getLoggerPlugin)(this.config));
			this.middlewareStack.use((0, middleware_recursion_detection_1.getRecursionDetectionPlugin)(this.config));
			this.middlewareStack.use((0, core_1.getHttpAuthSchemeEndpointRuleSetPlugin)(this.config, {
				httpAuthSchemeParametersProvider: httpAuthSchemeProvider_1.defaultSTSHttpAuthSchemeParametersProvider,
				identityProviderConfigProvider: async (config) => new core_1.DefaultIdentityProviderConfig({ "aws.auth#sigv4": config.credentials })
			}));
			this.middlewareStack.use((0, core_1.getHttpSigningPlugin)(this.config));
		}
		destroy() {
			super.destroy();
		}
	};
	exports.STSClient = STSClient;
}));

//#endregion
//#region node_modules/@aws-sdk/client-sts/dist-cjs/index.js
var require_dist_cjs = /* @__PURE__ */ __commonJSMin(((exports) => {
	var STSClient = require_STSClient();
	var smithyClient = require_dist_cjs$28();
	var middlewareEndpoint = require_dist_cjs$20();
	var EndpointParameters = require_EndpointParameters();
	var schema = (init_schema(), __toCommonJS(schema_exports));
	var client = (init_client(), __toCommonJS(client_exports));
	var regionConfigResolver = require_dist_cjs$9();
	var STSServiceException = class STSServiceException extends smithyClient.ServiceException {
		constructor(options) {
			super(options);
			Object.setPrototypeOf(this, STSServiceException.prototype);
		}
	};
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
	const _A = "Arn";
	const _AKI = "AccessKeyId";
	const _AP = "AssumedPrincipal";
	const _AR = "AssumeRole";
	const _ARI = "AssumedRoleId";
	const _ARR = "AssumeRoleRequest";
	const _ARRs = "AssumeRoleResponse";
	const _ARRss = "AssumeRootRequest";
	const _ARRssu = "AssumeRootResponse";
	const _ARU = "AssumedRoleUser";
	const _ARWSAML = "AssumeRoleWithSAML";
	const _ARWSAMLR = "AssumeRoleWithSAMLRequest";
	const _ARWSAMLRs = "AssumeRoleWithSAMLResponse";
	const _ARWWI = "AssumeRoleWithWebIdentity";
	const _ARWWIR = "AssumeRoleWithWebIdentityRequest";
	const _ARWWIRs = "AssumeRoleWithWebIdentityResponse";
	const _ARs = "AssumeRoot";
	const _Ac = "Account";
	const _Au = "Audience";
	const _C = "Credentials";
	const _CA = "ContextAssertion";
	const _DAM = "DecodeAuthorizationMessage";
	const _DAMR = "DecodeAuthorizationMessageRequest";
	const _DAMRe = "DecodeAuthorizationMessageResponse";
	const _DM = "DecodedMessage";
	const _DS = "DurationSeconds";
	const _E = "Expiration";
	const _EI = "ExternalId";
	const _EM = "EncodedMessage";
	const _ETE = "ExpiredTokenException";
	const _ETITE = "ExpiredTradeInTokenException";
	const _FU = "FederatedUser";
	const _FUI = "FederatedUserId";
	const _GAKI = "GetAccessKeyInfo";
	const _GAKIR = "GetAccessKeyInfoRequest";
	const _GAKIRe = "GetAccessKeyInfoResponse";
	const _GCI = "GetCallerIdentity";
	const _GCIR = "GetCallerIdentityRequest";
	const _GCIRe = "GetCallerIdentityResponse";
	const _GDAT = "GetDelegatedAccessToken";
	const _GDATR = "GetDelegatedAccessTokenRequest";
	const _GDATRe = "GetDelegatedAccessTokenResponse";
	const _GFT = "GetFederationToken";
	const _GFTR = "GetFederationTokenRequest";
	const _GFTRe = "GetFederationTokenResponse";
	const _GST = "GetSessionToken";
	const _GSTR = "GetSessionTokenRequest";
	const _GSTRe = "GetSessionTokenResponse";
	const _GWIT = "GetWebIdentityToken";
	const _GWITR = "GetWebIdentityTokenRequest";
	const _GWITRe = "GetWebIdentityTokenResponse";
	const _I = "Issuer";
	const _IAME = "InvalidAuthorizationMessageException";
	const _IDPCEE = "IDPCommunicationErrorException";
	const _IDPRCE = "IDPRejectedClaimException";
	const _IITE = "InvalidIdentityTokenException";
	const _JWTPSEE = "JWTPayloadSizeExceededException";
	const _K = "Key";
	const _MPDE = "MalformedPolicyDocumentException";
	const _N = "Name";
	const _NQ = "NameQualifier";
	const _OWIFDE = "OutboundWebIdentityFederationDisabledException";
	const _P = "Policy";
	const _PA = "PolicyArns";
	const _PAr = "PrincipalArn";
	const _PAro = "ProviderArn";
	const _PC = "ProvidedContexts";
	const _PCLT = "ProvidedContextsListType";
	const _PCr = "ProvidedContext";
	const _PDT = "PolicyDescriptorType";
	const _PI = "ProviderId";
	const _PPS = "PackedPolicySize";
	const _PPTLE = "PackedPolicyTooLargeException";
	const _Pr = "Provider";
	const _RA = "RoleArn";
	const _RDE = "RegionDisabledException";
	const _RSN = "RoleSessionName";
	const _S = "Subject";
	const _SA = "SigningAlgorithm";
	const _SAK = "SecretAccessKey";
	const _SAMLA = "SAMLAssertion";
	const _SAMLAT = "SAMLAssertionType";
	const _SDEE = "SessionDurationEscalationException";
	const _SFWIT = "SubjectFromWebIdentityToken";
	const _SI = "SourceIdentity";
	const _SN = "SerialNumber";
	const _ST = "SubjectType";
	const _STe = "SessionToken";
	const _T = "Tags";
	const _TC = "TokenCode";
	const _TIT = "TradeInToken";
	const _TP = "TargetPrincipal";
	const _TPA = "TaskPolicyArn";
	const _TTK = "TransitiveTagKeys";
	const _Ta = "Tag";
	const _UI = "UserId";
	const _V = "Value";
	const _WIT = "WebIdentityToken";
	const _a = "arn";
	const _aKST = "accessKeySecretType";
	const _aQE = "awsQueryError";
	const _c = "client";
	const _cTT = "clientTokenType";
	const _e = "error";
	const _hE = "httpError";
	const _m = "message";
	const _pDLT = "policyDescriptorListType";
	const _s = "smithy.ts.sdk.synthetic.com.amazonaws.sts";
	const _tITT = "tradeInTokenType";
	const _tLT = "tagListType";
	const _wITT = "webIdentityTokenType";
	const n0 = "com.amazonaws.sts";
	var accessKeySecretType = [
		0,
		n0,
		_aKST,
		8,
		0
	];
	var clientTokenType = [
		0,
		n0,
		_cTT,
		8,
		0
	];
	var SAMLAssertionType = [
		0,
		n0,
		_SAMLAT,
		8,
		0
	];
	var tradeInTokenType = [
		0,
		n0,
		_tITT,
		8,
		0
	];
	var webIdentityTokenType = [
		0,
		n0,
		_wITT,
		8,
		0
	];
	var AssumedRoleUser$ = [
		3,
		n0,
		_ARU,
		0,
		[_ARI, _A],
		[0, 0]
	];
	var AssumeRoleRequest$ = [
		3,
		n0,
		_ARR,
		0,
		[
			_RA,
			_RSN,
			_PA,
			_P,
			_DS,
			_T,
			_TTK,
			_EI,
			_SN,
			_TC,
			_SI,
			_PC
		],
		[
			0,
			0,
			() => policyDescriptorListType,
			0,
			1,
			() => tagListType,
			64,
			0,
			0,
			0,
			0,
			() => ProvidedContextsListType
		]
	];
	var AssumeRoleResponse$ = [
		3,
		n0,
		_ARRs,
		0,
		[
			_C,
			_ARU,
			_PPS,
			_SI
		],
		[
			[() => Credentials$, 0],
			() => AssumedRoleUser$,
			1,
			0
		]
	];
	var AssumeRoleWithSAMLRequest$ = [
		3,
		n0,
		_ARWSAMLR,
		0,
		[
			_RA,
			_PAr,
			_SAMLA,
			_PA,
			_P,
			_DS
		],
		[
			0,
			0,
			[() => SAMLAssertionType, 0],
			() => policyDescriptorListType,
			0,
			1
		]
	];
	var AssumeRoleWithSAMLResponse$ = [
		3,
		n0,
		_ARWSAMLRs,
		0,
		[
			_C,
			_ARU,
			_PPS,
			_S,
			_ST,
			_I,
			_Au,
			_NQ,
			_SI
		],
		[
			[() => Credentials$, 0],
			() => AssumedRoleUser$,
			1,
			0,
			0,
			0,
			0,
			0,
			0
		]
	];
	var AssumeRoleWithWebIdentityRequest$ = [
		3,
		n0,
		_ARWWIR,
		0,
		[
			_RA,
			_RSN,
			_WIT,
			_PI,
			_PA,
			_P,
			_DS
		],
		[
			0,
			0,
			[() => clientTokenType, 0],
			0,
			() => policyDescriptorListType,
			0,
			1
		]
	];
	var AssumeRoleWithWebIdentityResponse$ = [
		3,
		n0,
		_ARWWIRs,
		0,
		[
			_C,
			_SFWIT,
			_ARU,
			_PPS,
			_Pr,
			_Au,
			_SI
		],
		[
			[() => Credentials$, 0],
			0,
			() => AssumedRoleUser$,
			1,
			0,
			0,
			0
		]
	];
	var AssumeRootRequest$ = [
		3,
		n0,
		_ARRss,
		0,
		[
			_TP,
			_TPA,
			_DS
		],
		[
			0,
			() => PolicyDescriptorType$,
			1
		]
	];
	var AssumeRootResponse$ = [
		3,
		n0,
		_ARRssu,
		0,
		[_C, _SI],
		[[() => Credentials$, 0], 0]
	];
	var Credentials$ = [
		3,
		n0,
		_C,
		0,
		[
			_AKI,
			_SAK,
			_STe,
			_E
		],
		[
			0,
			[() => accessKeySecretType, 0],
			0,
			4
		]
	];
	var DecodeAuthorizationMessageRequest$ = [
		3,
		n0,
		_DAMR,
		0,
		[_EM],
		[0]
	];
	var DecodeAuthorizationMessageResponse$ = [
		3,
		n0,
		_DAMRe,
		0,
		[_DM],
		[0]
	];
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
	schema.TypeRegistry.for(n0).registerError(ExpiredTokenException$, ExpiredTokenException);
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
	schema.TypeRegistry.for(n0).registerError(ExpiredTradeInTokenException$, ExpiredTradeInTokenException);
	var FederatedUser$ = [
		3,
		n0,
		_FU,
		0,
		[_FUI, _A],
		[0, 0]
	];
	var GetAccessKeyInfoRequest$ = [
		3,
		n0,
		_GAKIR,
		0,
		[_AKI],
		[0]
	];
	var GetAccessKeyInfoResponse$ = [
		3,
		n0,
		_GAKIRe,
		0,
		[_Ac],
		[0]
	];
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
	var GetDelegatedAccessTokenRequest$ = [
		3,
		n0,
		_GDATR,
		0,
		[_TIT],
		[[() => tradeInTokenType, 0]]
	];
	var GetDelegatedAccessTokenResponse$ = [
		3,
		n0,
		_GDATRe,
		0,
		[
			_C,
			_PPS,
			_AP
		],
		[
			[() => Credentials$, 0],
			1,
			0
		]
	];
	var GetFederationTokenRequest$ = [
		3,
		n0,
		_GFTR,
		0,
		[
			_N,
			_P,
			_PA,
			_DS,
			_T
		],
		[
			0,
			0,
			() => policyDescriptorListType,
			1,
			() => tagListType
		]
	];
	var GetFederationTokenResponse$ = [
		3,
		n0,
		_GFTRe,
		0,
		[
			_C,
			_FU,
			_PPS
		],
		[
			[() => Credentials$, 0],
			() => FederatedUser$,
			1
		]
	];
	var GetSessionTokenRequest$ = [
		3,
		n0,
		_GSTR,
		0,
		[
			_DS,
			_SN,
			_TC
		],
		[
			1,
			0,
			0
		]
	];
	var GetSessionTokenResponse$ = [
		3,
		n0,
		_GSTRe,
		0,
		[_C],
		[[() => Credentials$, 0]]
	];
	var GetWebIdentityTokenRequest$ = [
		3,
		n0,
		_GWITR,
		0,
		[
			_Au,
			_DS,
			_SA,
			_T
		],
		[
			64,
			1,
			0,
			() => tagListType
		]
	];
	var GetWebIdentityTokenResponse$ = [
		3,
		n0,
		_GWITRe,
		0,
		[_WIT, _E],
		[[() => webIdentityTokenType, 0], 4]
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
	schema.TypeRegistry.for(n0).registerError(IDPCommunicationErrorException$, IDPCommunicationErrorException);
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
	schema.TypeRegistry.for(n0).registerError(IDPRejectedClaimException$, IDPRejectedClaimException);
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
	schema.TypeRegistry.for(n0).registerError(InvalidAuthorizationMessageException$, InvalidAuthorizationMessageException);
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
	schema.TypeRegistry.for(n0).registerError(InvalidIdentityTokenException$, InvalidIdentityTokenException);
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
	schema.TypeRegistry.for(n0).registerError(JWTPayloadSizeExceededException$, JWTPayloadSizeExceededException);
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
	schema.TypeRegistry.for(n0).registerError(MalformedPolicyDocumentException$, MalformedPolicyDocumentException);
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
	schema.TypeRegistry.for(n0).registerError(OutboundWebIdentityFederationDisabledException$, OutboundWebIdentityFederationDisabledException);
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
	schema.TypeRegistry.for(n0).registerError(PackedPolicyTooLargeException$, PackedPolicyTooLargeException);
	var PolicyDescriptorType$ = [
		3,
		n0,
		_PDT,
		0,
		[_a],
		[0]
	];
	var ProvidedContext$ = [
		3,
		n0,
		_PCr,
		0,
		[_PAro, _CA],
		[0, 0]
	];
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
	schema.TypeRegistry.for(n0).registerError(RegionDisabledException$, RegionDisabledException);
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
	schema.TypeRegistry.for(n0).registerError(SessionDurationEscalationException$, SessionDurationEscalationException);
	var Tag$ = [
		3,
		n0,
		_Ta,
		0,
		[_K, _V],
		[0, 0]
	];
	var STSServiceException$ = [
		-3,
		_s,
		"STSServiceException",
		0,
		[],
		[]
	];
	schema.TypeRegistry.for(_s).registerError(STSServiceException$, STSServiceException);
	var policyDescriptorListType = [
		1,
		n0,
		_pDLT,
		0,
		() => PolicyDescriptorType$
	];
	var ProvidedContextsListType = [
		1,
		n0,
		_PCLT,
		0,
		() => ProvidedContext$
	];
	var tagListType = [
		1,
		n0,
		_tLT,
		0,
		() => Tag$
	];
	var AssumeRole$ = [
		9,
		n0,
		_AR,
		0,
		() => AssumeRoleRequest$,
		() => AssumeRoleResponse$
	];
	var AssumeRoleWithSAML$ = [
		9,
		n0,
		_ARWSAML,
		0,
		() => AssumeRoleWithSAMLRequest$,
		() => AssumeRoleWithSAMLResponse$
	];
	var AssumeRoleWithWebIdentity$ = [
		9,
		n0,
		_ARWWI,
		0,
		() => AssumeRoleWithWebIdentityRequest$,
		() => AssumeRoleWithWebIdentityResponse$
	];
	var AssumeRoot$ = [
		9,
		n0,
		_ARs,
		0,
		() => AssumeRootRequest$,
		() => AssumeRootResponse$
	];
	var DecodeAuthorizationMessage$ = [
		9,
		n0,
		_DAM,
		0,
		() => DecodeAuthorizationMessageRequest$,
		() => DecodeAuthorizationMessageResponse$
	];
	var GetAccessKeyInfo$ = [
		9,
		n0,
		_GAKI,
		0,
		() => GetAccessKeyInfoRequest$,
		() => GetAccessKeyInfoResponse$
	];
	var GetCallerIdentity$ = [
		9,
		n0,
		_GCI,
		0,
		() => GetCallerIdentityRequest$,
		() => GetCallerIdentityResponse$
	];
	var GetDelegatedAccessToken$ = [
		9,
		n0,
		_GDAT,
		0,
		() => GetDelegatedAccessTokenRequest$,
		() => GetDelegatedAccessTokenResponse$
	];
	var GetFederationToken$ = [
		9,
		n0,
		_GFT,
		0,
		() => GetFederationTokenRequest$,
		() => GetFederationTokenResponse$
	];
	var GetSessionToken$ = [
		9,
		n0,
		_GST,
		0,
		() => GetSessionTokenRequest$,
		() => GetSessionTokenResponse$
	];
	var GetWebIdentityToken$ = [
		9,
		n0,
		_GWIT,
		0,
		() => GetWebIdentityTokenRequest$,
		() => GetWebIdentityTokenResponse$
	];
	var AssumeRoleCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "AssumeRole", {}).n("STSClient", "AssumeRoleCommand").sc(AssumeRole$).build() {};
	var AssumeRoleWithSAMLCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithSAML", {}).n("STSClient", "AssumeRoleWithSAMLCommand").sc(AssumeRoleWithSAML$).build() {};
	var AssumeRoleWithWebIdentityCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithWebIdentity", {}).n("STSClient", "AssumeRoleWithWebIdentityCommand").sc(AssumeRoleWithWebIdentity$).build() {};
	var AssumeRootCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "AssumeRoot", {}).n("STSClient", "AssumeRootCommand").sc(AssumeRoot$).build() {};
	var DecodeAuthorizationMessageCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "DecodeAuthorizationMessage", {}).n("STSClient", "DecodeAuthorizationMessageCommand").sc(DecodeAuthorizationMessage$).build() {};
	var GetAccessKeyInfoCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "GetAccessKeyInfo", {}).n("STSClient", "GetAccessKeyInfoCommand").sc(GetAccessKeyInfo$).build() {};
	var GetCallerIdentityCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "GetCallerIdentity", {}).n("STSClient", "GetCallerIdentityCommand").sc(GetCallerIdentity$).build() {};
	var GetDelegatedAccessTokenCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "GetDelegatedAccessToken", {}).n("STSClient", "GetDelegatedAccessTokenCommand").sc(GetDelegatedAccessToken$).build() {};
	var GetFederationTokenCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "GetFederationToken", {}).n("STSClient", "GetFederationTokenCommand").sc(GetFederationToken$).build() {};
	var GetSessionTokenCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "GetSessionToken", {}).n("STSClient", "GetSessionTokenCommand").sc(GetSessionToken$).build() {};
	var GetWebIdentityTokenCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o$3) {
		return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
	}).s("AWSSecurityTokenServiceV20110615", "GetWebIdentityToken", {}).n("STSClient", "GetWebIdentityTokenCommand").sc(GetWebIdentityToken$).build() {};
	const commands = {
		AssumeRoleCommand,
		AssumeRoleWithSAMLCommand,
		AssumeRoleWithWebIdentityCommand,
		AssumeRootCommand,
		DecodeAuthorizationMessageCommand,
		GetAccessKeyInfoCommand,
		GetCallerIdentityCommand,
		GetDelegatedAccessTokenCommand,
		GetFederationTokenCommand,
		GetSessionTokenCommand,
		GetWebIdentityTokenCommand
	};
	var STS = class extends STSClient.STSClient {};
	smithyClient.createAggregatedClient(commands, STS);
	const getAccountIdFromAssumedRoleUser = (assumedRoleUser) => {
		if (typeof assumedRoleUser?.Arn === "string") {
			const arnComponents = assumedRoleUser.Arn.split(":");
			if (arnComponents.length > 4 && arnComponents[4] !== "") return arnComponents[4];
		}
	};
	const resolveRegion = async (_region, _parentRegion, credentialProviderLogger, loaderConfig = {}) => {
		const region = typeof _region === "function" ? await _region() : _region;
		const parentRegion = typeof _parentRegion === "function" ? await _parentRegion() : _parentRegion;
		let stsDefaultRegion = "";
		const resolvedRegion = region ?? parentRegion ?? (stsDefaultRegion = await regionConfigResolver.stsRegionDefaultResolver(loaderConfig)());
		credentialProviderLogger?.debug?.("@aws-sdk/client-sts::resolveRegion", "accepting first of:", `${region} (credential provider clientConfig)`, `${parentRegion} (contextual client)`, `${stsDefaultRegion} (STS default: AWS_REGION, profile region, or us-east-1)`);
		return resolvedRegion;
	};
	const getDefaultRoleAssumer$1 = (stsOptions, STSClient$2) => {
		let stsClient;
		let closureSourceCreds;
		return async (sourceCreds, params) => {
			closureSourceCreds = sourceCreds;
			if (!stsClient) {
				const { logger: logger$1 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
				const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
					logger: logger$1,
					profile
				});
				const isCompatibleRequestHandler = !isH2(requestHandler);
				stsClient = new STSClient$2({
					...stsOptions,
					userAgentAppId,
					profile,
					credentialDefaultProvider: () => async () => closureSourceCreds,
					region: resolvedRegion,
					requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
					logger: logger$1
				});
			}
			const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleCommand(params));
			if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) throw new Error(`Invalid response from STS.assumeRole call with role ${params.RoleArn}`);
			const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
			const credentials = {
				accessKeyId: Credentials.AccessKeyId,
				secretAccessKey: Credentials.SecretAccessKey,
				sessionToken: Credentials.SessionToken,
				expiration: Credentials.Expiration,
				...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
				...accountId && { accountId }
			};
			client.setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE", "i");
			return credentials;
		};
	};
	const getDefaultRoleAssumerWithWebIdentity$1 = (stsOptions, STSClient$2) => {
		let stsClient;
		return async (params) => {
			if (!stsClient) {
				const { logger: logger$1 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
				const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
					logger: logger$1,
					profile
				});
				const isCompatibleRequestHandler = !isH2(requestHandler);
				stsClient = new STSClient$2({
					...stsOptions,
					userAgentAppId,
					profile,
					region: resolvedRegion,
					requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
					logger: logger$1
				});
			}
			const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleWithWebIdentityCommand(params));
			if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) throw new Error(`Invalid response from STS.assumeRoleWithWebIdentity call with role ${params.RoleArn}`);
			const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
			const credentials = {
				accessKeyId: Credentials.AccessKeyId,
				secretAccessKey: Credentials.SecretAccessKey,
				sessionToken: Credentials.SessionToken,
				expiration: Credentials.Expiration,
				...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
				...accountId && { accountId }
			};
			if (accountId) client.setCredentialFeature(credentials, "RESOLVED_ACCOUNT_ID", "T");
			client.setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE_WEB_ID", "k");
			return credentials;
		};
	};
	const isH2 = (requestHandler) => {
		return requestHandler?.metadata?.handlerProtocol === "h2";
	};
	const getCustomizableStsClientCtor = (baseCtor, customizations) => {
		if (!customizations) return baseCtor;
		else return class CustomizableSTSClient extends baseCtor {
			constructor(config) {
				super(config);
				for (const customization of customizations) this.middlewareStack.use(customization);
			}
		};
	};
	const getDefaultRoleAssumer = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumer$1(stsOptions, getCustomizableStsClientCtor(STSClient.STSClient, stsPlugins));
	const getDefaultRoleAssumerWithWebIdentity = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumerWithWebIdentity$1(stsOptions, getCustomizableStsClientCtor(STSClient.STSClient, stsPlugins));
	const decorateDefaultCredentialProvider = (provider) => (input) => provider({
		roleAssumer: getDefaultRoleAssumer(input),
		roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity(input),
		...input
	});
	Object.defineProperty(exports, "$Command", {
		enumerable: true,
		get: function() {
			return smithyClient.Command;
		}
	});
	exports.AssumeRole$ = AssumeRole$;
	exports.AssumeRoleCommand = AssumeRoleCommand;
	exports.AssumeRoleRequest$ = AssumeRoleRequest$;
	exports.AssumeRoleResponse$ = AssumeRoleResponse$;
	exports.AssumeRoleWithSAML$ = AssumeRoleWithSAML$;
	exports.AssumeRoleWithSAMLCommand = AssumeRoleWithSAMLCommand;
	exports.AssumeRoleWithSAMLRequest$ = AssumeRoleWithSAMLRequest$;
	exports.AssumeRoleWithSAMLResponse$ = AssumeRoleWithSAMLResponse$;
	exports.AssumeRoleWithWebIdentity$ = AssumeRoleWithWebIdentity$;
	exports.AssumeRoleWithWebIdentityCommand = AssumeRoleWithWebIdentityCommand;
	exports.AssumeRoleWithWebIdentityRequest$ = AssumeRoleWithWebIdentityRequest$;
	exports.AssumeRoleWithWebIdentityResponse$ = AssumeRoleWithWebIdentityResponse$;
	exports.AssumeRoot$ = AssumeRoot$;
	exports.AssumeRootCommand = AssumeRootCommand;
	exports.AssumeRootRequest$ = AssumeRootRequest$;
	exports.AssumeRootResponse$ = AssumeRootResponse$;
	exports.AssumedRoleUser$ = AssumedRoleUser$;
	exports.Credentials$ = Credentials$;
	exports.DecodeAuthorizationMessage$ = DecodeAuthorizationMessage$;
	exports.DecodeAuthorizationMessageCommand = DecodeAuthorizationMessageCommand;
	exports.DecodeAuthorizationMessageRequest$ = DecodeAuthorizationMessageRequest$;
	exports.DecodeAuthorizationMessageResponse$ = DecodeAuthorizationMessageResponse$;
	exports.ExpiredTokenException = ExpiredTokenException;
	exports.ExpiredTokenException$ = ExpiredTokenException$;
	exports.ExpiredTradeInTokenException = ExpiredTradeInTokenException;
	exports.ExpiredTradeInTokenException$ = ExpiredTradeInTokenException$;
	exports.FederatedUser$ = FederatedUser$;
	exports.GetAccessKeyInfo$ = GetAccessKeyInfo$;
	exports.GetAccessKeyInfoCommand = GetAccessKeyInfoCommand;
	exports.GetAccessKeyInfoRequest$ = GetAccessKeyInfoRequest$;
	exports.GetAccessKeyInfoResponse$ = GetAccessKeyInfoResponse$;
	exports.GetCallerIdentity$ = GetCallerIdentity$;
	exports.GetCallerIdentityCommand = GetCallerIdentityCommand;
	exports.GetCallerIdentityRequest$ = GetCallerIdentityRequest$;
	exports.GetCallerIdentityResponse$ = GetCallerIdentityResponse$;
	exports.GetDelegatedAccessToken$ = GetDelegatedAccessToken$;
	exports.GetDelegatedAccessTokenCommand = GetDelegatedAccessTokenCommand;
	exports.GetDelegatedAccessTokenRequest$ = GetDelegatedAccessTokenRequest$;
	exports.GetDelegatedAccessTokenResponse$ = GetDelegatedAccessTokenResponse$;
	exports.GetFederationToken$ = GetFederationToken$;
	exports.GetFederationTokenCommand = GetFederationTokenCommand;
	exports.GetFederationTokenRequest$ = GetFederationTokenRequest$;
	exports.GetFederationTokenResponse$ = GetFederationTokenResponse$;
	exports.GetSessionToken$ = GetSessionToken$;
	exports.GetSessionTokenCommand = GetSessionTokenCommand;
	exports.GetSessionTokenRequest$ = GetSessionTokenRequest$;
	exports.GetSessionTokenResponse$ = GetSessionTokenResponse$;
	exports.GetWebIdentityToken$ = GetWebIdentityToken$;
	exports.GetWebIdentityTokenCommand = GetWebIdentityTokenCommand;
	exports.GetWebIdentityTokenRequest$ = GetWebIdentityTokenRequest$;
	exports.GetWebIdentityTokenResponse$ = GetWebIdentityTokenResponse$;
	exports.IDPCommunicationErrorException = IDPCommunicationErrorException;
	exports.IDPCommunicationErrorException$ = IDPCommunicationErrorException$;
	exports.IDPRejectedClaimException = IDPRejectedClaimException;
	exports.IDPRejectedClaimException$ = IDPRejectedClaimException$;
	exports.InvalidAuthorizationMessageException = InvalidAuthorizationMessageException;
	exports.InvalidAuthorizationMessageException$ = InvalidAuthorizationMessageException$;
	exports.InvalidIdentityTokenException = InvalidIdentityTokenException;
	exports.InvalidIdentityTokenException$ = InvalidIdentityTokenException$;
	exports.JWTPayloadSizeExceededException = JWTPayloadSizeExceededException;
	exports.JWTPayloadSizeExceededException$ = JWTPayloadSizeExceededException$;
	exports.MalformedPolicyDocumentException = MalformedPolicyDocumentException;
	exports.MalformedPolicyDocumentException$ = MalformedPolicyDocumentException$;
	exports.OutboundWebIdentityFederationDisabledException = OutboundWebIdentityFederationDisabledException;
	exports.OutboundWebIdentityFederationDisabledException$ = OutboundWebIdentityFederationDisabledException$;
	exports.PackedPolicyTooLargeException = PackedPolicyTooLargeException;
	exports.PackedPolicyTooLargeException$ = PackedPolicyTooLargeException$;
	exports.PolicyDescriptorType$ = PolicyDescriptorType$;
	exports.ProvidedContext$ = ProvidedContext$;
	exports.RegionDisabledException = RegionDisabledException;
	exports.RegionDisabledException$ = RegionDisabledException$;
	exports.STS = STS;
	exports.STSServiceException = STSServiceException;
	exports.STSServiceException$ = STSServiceException$;
	exports.SessionDurationEscalationException = SessionDurationEscalationException;
	exports.SessionDurationEscalationException$ = SessionDurationEscalationException$;
	exports.Tag$ = Tag$;
	exports.decorateDefaultCredentialProvider = decorateDefaultCredentialProvider;
	exports.getDefaultRoleAssumer = getDefaultRoleAssumer;
	exports.getDefaultRoleAssumerWithWebIdentity = getDefaultRoleAssumerWithWebIdentity;
	Object.keys(STSClient).forEach(function(k$3) {
		if (k$3 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k$3)) Object.defineProperty(exports, k$3, {
			enumerable: true,
			get: function() {
				return STSClient[k$3];
			}
		});
	});
}));

//#endregion
//#region src/utils/__fixtures__/v3/index.js
var import_dist_cjs = require_dist_cjs();
const client = new import_dist_cjs.STSClient();
const handler = async () => client.send(new import_dist_cjs.GetCallerIdentityCommand());

//#endregion
exports.handler = handler;