var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x4) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x4, {
  get: (a4, b4) => (typeof require !== "undefined" ? require : a4)[b4]
}) : x4)(function(x4) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x4 + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@smithy/types/dist-cjs/index.js
var require_dist_cjs = __commonJS({
  "node_modules/@smithy/types/dist-cjs/index.js"(exports) {
    "use strict";
    exports.HttpAuthLocation = void 0;
    (function(HttpAuthLocation) {
      HttpAuthLocation["HEADER"] = "header";
      HttpAuthLocation["QUERY"] = "query";
    })(exports.HttpAuthLocation || (exports.HttpAuthLocation = {}));
    exports.HttpApiKeyAuthLocation = void 0;
    (function(HttpApiKeyAuthLocation2) {
      HttpApiKeyAuthLocation2["HEADER"] = "header";
      HttpApiKeyAuthLocation2["QUERY"] = "query";
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
    var getChecksumConfiguration = (runtimeConfig) => {
      const checksumAlgorithms = [];
      if (runtimeConfig.sha256 !== void 0) {
        checksumAlgorithms.push({
          algorithmId: () => exports.AlgorithmId.SHA256,
          checksumConstructor: () => runtimeConfig.sha256
        });
      }
      if (runtimeConfig.md5 != void 0) {
        checksumAlgorithms.push({
          algorithmId: () => exports.AlgorithmId.MD5,
          checksumConstructor: () => runtimeConfig.md5
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
    var resolveChecksumRuntimeConfig = (clientConfig) => {
      const runtimeConfig = {};
      clientConfig.checksumAlgorithms().forEach((checksumAlgorithm) => {
        runtimeConfig[checksumAlgorithm.algorithmId()] = checksumAlgorithm.checksumConstructor();
      });
      return runtimeConfig;
    };
    var getDefaultClientConfiguration = (runtimeConfig) => {
      return getChecksumConfiguration(runtimeConfig);
    };
    var resolveDefaultRuntimeConfig4 = (config) => {
      return resolveChecksumRuntimeConfig(config);
    };
    exports.FieldPosition = void 0;
    (function(FieldPosition) {
      FieldPosition[FieldPosition["HEADER"] = 0] = "HEADER";
      FieldPosition[FieldPosition["TRAILER"] = 1] = "TRAILER";
    })(exports.FieldPosition || (exports.FieldPosition = {}));
    var SMITHY_CONTEXT_KEY2 = "__smithy_context";
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
    exports.SMITHY_CONTEXT_KEY = SMITHY_CONTEXT_KEY2;
    exports.getDefaultClientConfiguration = getDefaultClientConfiguration;
    exports.resolveDefaultRuntimeConfig = resolveDefaultRuntimeConfig4;
  }
});

// node_modules/@smithy/protocol-http/dist-cjs/index.js
var require_dist_cjs2 = __commonJS({
  "node_modules/@smithy/protocol-http/dist-cjs/index.js"(exports) {
    "use strict";
    var types = require_dist_cjs();
    var getHttpHandlerExtensionConfiguration4 = (runtimeConfig) => {
      return {
        setHttpHandler(handler2) {
          runtimeConfig.httpHandler = handler2;
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
    var resolveHttpHandlerRuntimeConfig4 = (httpHandlerExtensionConfiguration) => {
      return {
        httpHandler: httpHandlerExtensionConfiguration.httpHandler()
      };
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
        this.values = this.values.filter((v4) => v4 !== value);
      }
      toString() {
        return this.values.map((v4) => v4.includes(",") || v4.includes(" ") ? `"${v4}"` : v4).join(", ");
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
    var HttpRequest10 = class _HttpRequest {
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
        const cloned = new _HttpRequest({
          ...request,
          headers: { ...request.headers }
        });
        if (cloned.query) {
          cloned.query = cloneQuery(cloned.query);
        }
        return cloned;
      }
      static isInstance(request) {
        if (!request) {
          return false;
        }
        const req = request;
        return "method" in req && "protocol" in req && "hostname" in req && "path" in req && typeof req["query"] === "object" && typeof req["headers"] === "object";
      }
      clone() {
        return _HttpRequest.clone(this);
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
    var HttpResponse4 = class {
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
        if (!response)
          return false;
        const resp = response;
        return typeof resp.statusCode === "number" && typeof resp.headers === "object";
      }
    };
    function isValidHostname(hostname) {
      const hostPattern = /^[a-z0-9][a-z0-9\.\-]*[a-z0-9]$/;
      return hostPattern.test(hostname);
    }
    exports.Field = Field;
    exports.Fields = Fields;
    exports.HttpRequest = HttpRequest10;
    exports.HttpResponse = HttpResponse4;
    exports.getHttpHandlerExtensionConfiguration = getHttpHandlerExtensionConfiguration4;
    exports.isValidHostname = isValidHostname;
    exports.resolveHttpHandlerRuntimeConfig = resolveHttpHandlerRuntimeConfig4;
  }
});

// node_modules/@aws-sdk/middleware-host-header/dist-cjs/index.js
var require_dist_cjs3 = __commonJS({
  "node_modules/@aws-sdk/middleware-host-header/dist-cjs/index.js"(exports) {
    "use strict";
    var protocolHttp = require_dist_cjs2();
    function resolveHostHeaderConfig4(input) {
      return input;
    }
    var hostHeaderMiddleware = (options) => (next) => async (args) => {
      if (!protocolHttp.HttpRequest.isInstance(args.request))
        return next(args);
      const { request } = args;
      const { handlerProtocol = "" } = options.requestHandler.metadata || {};
      if (handlerProtocol.indexOf("h2") >= 0 && !request.headers[":authority"]) {
        delete request.headers["host"];
        request.headers[":authority"] = request.hostname + (request.port ? ":" + request.port : "");
      } else if (!request.headers["host"]) {
        let host = request.hostname;
        if (request.port != null)
          host += `:${request.port}`;
        request.headers["host"] = host;
      }
      return next(args);
    };
    var hostHeaderMiddlewareOptions = {
      name: "hostHeaderMiddleware",
      step: "build",
      priority: "low",
      tags: ["HOST"],
      override: true
    };
    var getHostHeaderPlugin4 = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(hostHeaderMiddleware(options), hostHeaderMiddlewareOptions);
      }
    });
    exports.getHostHeaderPlugin = getHostHeaderPlugin4;
    exports.hostHeaderMiddleware = hostHeaderMiddleware;
    exports.hostHeaderMiddlewareOptions = hostHeaderMiddlewareOptions;
    exports.resolveHostHeaderConfig = resolveHostHeaderConfig4;
  }
});

// node_modules/@aws-sdk/middleware-logger/dist-cjs/index.js
var require_dist_cjs4 = __commonJS({
  "node_modules/@aws-sdk/middleware-logger/dist-cjs/index.js"(exports) {
    "use strict";
    var loggerMiddleware = () => (next, context) => async (args) => {
      try {
        const response = await next(args);
        const { clientName, commandName, logger: logger2, dynamoDbDocumentClientOptions = {} } = context;
        const { overrideInputFilterSensitiveLog, overrideOutputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
        const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
        const outputFilterSensitiveLog = overrideOutputFilterSensitiveLog ?? context.outputFilterSensitiveLog;
        const { $metadata, ...outputWithoutMetadata } = response.output;
        logger2?.info?.({
          clientName,
          commandName,
          input: inputFilterSensitiveLog(args.input),
          output: outputFilterSensitiveLog(outputWithoutMetadata),
          metadata: $metadata
        });
        return response;
      } catch (error2) {
        const { clientName, commandName, logger: logger2, dynamoDbDocumentClientOptions = {} } = context;
        const { overrideInputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
        const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
        logger2?.error?.({
          clientName,
          commandName,
          input: inputFilterSensitiveLog(args.input),
          error: error2,
          metadata: error2.$metadata
        });
        throw error2;
      }
    };
    var loggerMiddlewareOptions = {
      name: "loggerMiddleware",
      tags: ["LOGGER"],
      step: "initialize",
      override: true
    };
    var getLoggerPlugin4 = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(loggerMiddleware(), loggerMiddlewareOptions);
      }
    });
    exports.getLoggerPlugin = getLoggerPlugin4;
    exports.loggerMiddleware = loggerMiddleware;
    exports.loggerMiddlewareOptions = loggerMiddlewareOptions;
  }
});

// node_modules/@aws/lambda-invoke-store/dist-es/invoke-store.js
var invoke_store_exports = {};
__export(invoke_store_exports, {
  InvokeStore: () => InvokeStore,
  InvokeStoreBase: () => InvokeStoreBase
});
var PROTECTED_KEYS, NO_GLOBAL_AWS_LAMBDA, InvokeStoreBase, InvokeStoreSingle, InvokeStoreMulti, InvokeStore;
var init_invoke_store = __esm({
  "node_modules/@aws/lambda-invoke-store/dist-es/invoke-store.js"() {
    PROTECTED_KEYS = {
      REQUEST_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_REQUEST_ID"),
      X_RAY_TRACE_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_X_RAY_TRACE_ID"),
      TENANT_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_TENANT_ID")
    };
    NO_GLOBAL_AWS_LAMBDA = ["true", "1"].includes(process.env?.AWS_LAMBDA_NODEJS_NO_GLOBAL_AWSLAMBDA ?? "");
    if (!NO_GLOBAL_AWS_LAMBDA) {
      globalThis.awslambda = globalThis.awslambda || {};
    }
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
        if (this.isProtectedKey(key)) {
          throw new Error(`Cannot modify protected Lambda context field: ${String(key)}`);
        }
        this.currentContext = this.currentContext || {};
        this.currentContext[key] = value;
      }
      run(context, fn) {
        this.currentContext = context;
        return fn();
      }
    };
    InvokeStoreMulti = class _InvokeStoreMulti extends InvokeStoreBase {
      als;
      static async create() {
        const instance = new _InvokeStoreMulti();
        const asyncHooks = await import("node:async_hooks");
        instance.als = new asyncHooks.AsyncLocalStorage();
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
        if (this.isProtectedKey(key)) {
          throw new Error(`Cannot modify protected Lambda context field: ${String(key)}`);
        }
        const store = this.als.getStore();
        if (!store) {
          throw new Error("No context available");
        }
        store[key] = value;
      }
      run(context, fn) {
        return this.als.run(context, fn);
      }
    };
    (function(InvokeStore2) {
      let instance = null;
      async function getInstanceAsync() {
        if (!instance) {
          instance = (async () => {
            const isMulti = "AWS_LAMBDA_MAX_CONCURRENCY" in process.env;
            const newInstance = isMulti ? await InvokeStoreMulti.create() : new InvokeStoreSingle();
            if (!NO_GLOBAL_AWS_LAMBDA && globalThis.awslambda?.InvokeStore) {
              return globalThis.awslambda.InvokeStore;
            } else if (!NO_GLOBAL_AWS_LAMBDA && globalThis.awslambda) {
              globalThis.awslambda.InvokeStore = newInstance;
              return newInstance;
            } else {
              return newInstance;
            }
          })();
        }
        return instance;
      }
      InvokeStore2.getInstanceAsync = getInstanceAsync;
      InvokeStore2._testing = process.env.AWS_LAMBDA_BENCHMARK_MODE === "1" ? {
        reset: () => {
          instance = null;
          if (globalThis.awslambda?.InvokeStore) {
            delete globalThis.awslambda.InvokeStore;
          }
          globalThis.awslambda = {};
        }
      } : void 0;
    })(InvokeStore || (InvokeStore = {}));
  }
});

// node_modules/@aws-sdk/middleware-recursion-detection/dist-cjs/recursionDetectionMiddleware.js
var require_recursionDetectionMiddleware = __commonJS({
  "node_modules/@aws-sdk/middleware-recursion-detection/dist-cjs/recursionDetectionMiddleware.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.recursionDetectionMiddleware = void 0;
    var lambda_invoke_store_1 = (init_invoke_store(), __toCommonJS(invoke_store_exports));
    var protocol_http_1 = require_dist_cjs2();
    var TRACE_ID_HEADER_NAME = "X-Amzn-Trace-Id";
    var ENV_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME";
    var ENV_TRACE_ID = "_X_AMZN_TRACE_ID";
    var recursionDetectionMiddleware = () => (next) => async (args) => {
      const { request } = args;
      if (!protocol_http_1.HttpRequest.isInstance(request)) {
        return next(args);
      }
      const traceIdHeader = Object.keys(request.headers ?? {}).find((h4) => h4.toLowerCase() === TRACE_ID_HEADER_NAME.toLowerCase()) ?? TRACE_ID_HEADER_NAME;
      if (request.headers.hasOwnProperty(traceIdHeader)) {
        return next(args);
      }
      const functionName = process.env[ENV_LAMBDA_FUNCTION_NAME];
      const traceIdFromEnv = process.env[ENV_TRACE_ID];
      const invokeStore = await lambda_invoke_store_1.InvokeStore.getInstanceAsync();
      const traceIdFromInvokeStore = invokeStore?.getXRayTraceId();
      const traceId = traceIdFromInvokeStore ?? traceIdFromEnv;
      const nonEmptyString = (str) => typeof str === "string" && str.length > 0;
      if (nonEmptyString(functionName) && nonEmptyString(traceId)) {
        request.headers[TRACE_ID_HEADER_NAME] = traceId;
      }
      return next({
        ...args,
        request
      });
    };
    exports.recursionDetectionMiddleware = recursionDetectionMiddleware;
  }
});

// node_modules/@aws-sdk/middleware-recursion-detection/dist-cjs/index.js
var require_dist_cjs5 = __commonJS({
  "node_modules/@aws-sdk/middleware-recursion-detection/dist-cjs/index.js"(exports) {
    "use strict";
    var recursionDetectionMiddleware = require_recursionDetectionMiddleware();
    var recursionDetectionMiddlewareOptions = {
      step: "build",
      tags: ["RECURSION_DETECTION"],
      name: "recursionDetectionMiddleware",
      override: true,
      priority: "low"
    };
    var getRecursionDetectionPlugin4 = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(recursionDetectionMiddleware.recursionDetectionMiddleware(), recursionDetectionMiddlewareOptions);
      }
    });
    exports.getRecursionDetectionPlugin = getRecursionDetectionPlugin4;
    Object.keys(recursionDetectionMiddleware).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return recursionDetectionMiddleware[k4];
        }
      });
    });
  }
});

// node_modules/@smithy/core/dist-es/getSmithyContext.js
var import_types, getSmithyContext;
var init_getSmithyContext = __esm({
  "node_modules/@smithy/core/dist-es/getSmithyContext.js"() {
    import_types = __toESM(require_dist_cjs());
    getSmithyContext = (context) => context[import_types.SMITHY_CONTEXT_KEY] || (context[import_types.SMITHY_CONTEXT_KEY] = {});
  }
});

// node_modules/@smithy/util-middleware/dist-cjs/index.js
var require_dist_cjs6 = __commonJS({
  "node_modules/@smithy/util-middleware/dist-cjs/index.js"(exports) {
    "use strict";
    var types = require_dist_cjs();
    var getSmithyContext10 = (context) => context[types.SMITHY_CONTEXT_KEY] || (context[types.SMITHY_CONTEXT_KEY] = {});
    var normalizeProvider5 = (input) => {
      if (typeof input === "function")
        return input;
      const promisified = Promise.resolve(input);
      return () => promisified;
    };
    exports.getSmithyContext = getSmithyContext10;
    exports.normalizeProvider = normalizeProvider5;
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/resolveAuthOptions.js
var resolveAuthOptions;
var init_resolveAuthOptions = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/resolveAuthOptions.js"() {
    resolveAuthOptions = (candidateAuthOptions, authSchemePreference) => {
      if (!authSchemePreference || authSchemePreference.length === 0) {
        return candidateAuthOptions;
      }
      const preferredAuthOptions = [];
      for (const preferredSchemeName of authSchemePreference) {
        for (const candidateAuthOption of candidateAuthOptions) {
          const candidateAuthSchemeName = candidateAuthOption.schemeId.split("#")[1];
          if (candidateAuthSchemeName === preferredSchemeName) {
            preferredAuthOptions.push(candidateAuthOption);
          }
        }
      }
      for (const candidateAuthOption of candidateAuthOptions) {
        if (!preferredAuthOptions.find(({ schemeId }) => schemeId === candidateAuthOption.schemeId)) {
          preferredAuthOptions.push(candidateAuthOption);
        }
      }
      return preferredAuthOptions;
    };
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js
function convertHttpAuthSchemesToMap(httpAuthSchemes) {
  const map2 = /* @__PURE__ */ new Map();
  for (const scheme of httpAuthSchemes) {
    map2.set(scheme.schemeId, scheme);
  }
  return map2;
}
var import_util_middleware, httpAuthSchemeMiddleware;
var init_httpAuthSchemeMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js"() {
    import_util_middleware = __toESM(require_dist_cjs6());
    init_resolveAuthOptions();
    httpAuthSchemeMiddleware = (config, mwOptions) => (next, context) => async (args) => {
      const options = config.httpAuthSchemeProvider(await mwOptions.httpAuthSchemeParametersProvider(config, context, args.input));
      const authSchemePreference = config.authSchemePreference ? await config.authSchemePreference() : [];
      const resolvedOptions = resolveAuthOptions(options, authSchemePreference);
      const authSchemes = convertHttpAuthSchemesToMap(config.httpAuthSchemes);
      const smithyContext = (0, import_util_middleware.getSmithyContext)(context);
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
      if (!smithyContext.selectedHttpAuthScheme) {
        throw new Error(failureReasons.join("\n"));
      }
      return next(args);
    };
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.js
var httpAuthSchemeEndpointRuleSetMiddlewareOptions, getHttpAuthSchemeEndpointRuleSetPlugin;
var init_getHttpAuthSchemeEndpointRuleSetPlugin = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.js"() {
    init_httpAuthSchemeMiddleware();
    httpAuthSchemeEndpointRuleSetMiddlewareOptions = {
      step: "serialize",
      tags: ["HTTP_AUTH_SCHEME"],
      name: "httpAuthSchemeMiddleware",
      override: true,
      relation: "before",
      toMiddleware: "endpointV2Middleware"
    };
    getHttpAuthSchemeEndpointRuleSetPlugin = (config, { httpAuthSchemeParametersProvider, identityProviderConfigProvider }) => ({
      applyToStack: (clientStack) => {
        clientStack.addRelativeTo(httpAuthSchemeMiddleware(config, {
          httpAuthSchemeParametersProvider,
          identityProviderConfigProvider
        }), httpAuthSchemeEndpointRuleSetMiddlewareOptions);
      }
    });
  }
});

// node_modules/@smithy/middleware-serde/dist-cjs/index.js
var require_dist_cjs7 = __commonJS({
  "node_modules/@smithy/middleware-serde/dist-cjs/index.js"(exports) {
    "use strict";
    var protocolHttp = require_dist_cjs2();
    var deserializerMiddleware = (options, deserializer) => (next, context) => async (args) => {
      const { response } = await next(args);
      try {
        const parsed = await deserializer(response, options);
        return {
          response,
          output: parsed
        };
      } catch (error2) {
        Object.defineProperty(error2, "$response", {
          value: response,
          enumerable: false,
          writable: false,
          configurable: false
        });
        if (!("$metadata" in error2)) {
          const hint = `Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`;
          try {
            error2.message += "\n  " + hint;
          } catch (e4) {
            if (!context.logger || context.logger?.constructor?.name === "NoOpLogger") {
              console.warn(hint);
            } else {
              context.logger?.warn?.(hint);
            }
          }
          if (typeof error2.$responseBodyText !== "undefined") {
            if (error2.$response) {
              error2.$response.body = error2.$responseBodyText;
            }
          }
          try {
            if (protocolHttp.HttpResponse.isInstance(response)) {
              const { headers = {} } = response;
              const headerEntries = Object.entries(headers);
              error2.$metadata = {
                httpStatusCode: response.statusCode,
                requestId: findHeader2(/^x-[\w-]+-request-?id$/, headerEntries),
                extendedRequestId: findHeader2(/^x-[\w-]+-id-2$/, headerEntries),
                cfId: findHeader2(/^x-[\w-]+-cf-id$/, headerEntries)
              };
            }
          } catch (e4) {
          }
        }
        throw error2;
      }
    };
    var findHeader2 = (pattern, headers) => {
      return (headers.find(([k4]) => {
        return k4.match(pattern);
      }) || [void 0, void 0])[1];
    };
    var serializerMiddleware = (options, serializer) => (next, context) => async (args) => {
      const endpointConfig = options;
      const endpoint = context.endpointV2?.url && endpointConfig.urlParser ? async () => endpointConfig.urlParser(context.endpointV2.url) : endpointConfig.endpoint;
      if (!endpoint) {
        throw new Error("No valid endpoint provider available.");
      }
      const request = await serializer(args.input, { ...options, endpoint });
      return next({
        ...args,
        request
      });
    };
    var deserializerMiddlewareOption2 = {
      name: "deserializerMiddleware",
      step: "deserialize",
      tags: ["DESERIALIZER"],
      override: true
    };
    var serializerMiddlewareOption3 = {
      name: "serializerMiddleware",
      step: "serialize",
      tags: ["SERIALIZER"],
      override: true
    };
    function getSerdePlugin(config, serializer, deserializer) {
      return {
        applyToStack: (commandStack) => {
          commandStack.add(deserializerMiddleware(config, deserializer), deserializerMiddlewareOption2);
          commandStack.add(serializerMiddleware(config, serializer), serializerMiddlewareOption3);
        }
      };
    }
    exports.deserializerMiddleware = deserializerMiddleware;
    exports.deserializerMiddlewareOption = deserializerMiddlewareOption2;
    exports.getSerdePlugin = getSerdePlugin;
    exports.serializerMiddleware = serializerMiddleware;
    exports.serializerMiddlewareOption = serializerMiddlewareOption3;
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemePlugin.js
var import_middleware_serde, httpAuthSchemeMiddlewareOptions, getHttpAuthSchemePlugin;
var init_getHttpAuthSchemePlugin = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemePlugin.js"() {
    import_middleware_serde = __toESM(require_dist_cjs7());
    init_httpAuthSchemeMiddleware();
    httpAuthSchemeMiddlewareOptions = {
      step: "serialize",
      tags: ["HTTP_AUTH_SCHEME"],
      name: "httpAuthSchemeMiddleware",
      override: true,
      relation: "before",
      toMiddleware: import_middleware_serde.serializerMiddlewareOption.name
    };
    getHttpAuthSchemePlugin = (config, { httpAuthSchemeParametersProvider, identityProviderConfigProvider }) => ({
      applyToStack: (clientStack) => {
        clientStack.addRelativeTo(httpAuthSchemeMiddleware(config, {
          httpAuthSchemeParametersProvider,
          identityProviderConfigProvider
        }), httpAuthSchemeMiddlewareOptions);
      }
    });
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/index.js
var init_middleware_http_auth_scheme = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/index.js"() {
    init_httpAuthSchemeMiddleware();
    init_getHttpAuthSchemeEndpointRuleSetPlugin();
    init_getHttpAuthSchemePlugin();
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-signing/httpSigningMiddleware.js
var import_protocol_http, import_util_middleware2, defaultErrorHandler, defaultSuccessHandler, httpSigningMiddleware;
var init_httpSigningMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-signing/httpSigningMiddleware.js"() {
    import_protocol_http = __toESM(require_dist_cjs2());
    import_util_middleware2 = __toESM(require_dist_cjs6());
    defaultErrorHandler = (signingProperties) => (error2) => {
      throw error2;
    };
    defaultSuccessHandler = (httpResponse, signingProperties) => {
    };
    httpSigningMiddleware = (config) => (next, context) => async (args) => {
      if (!import_protocol_http.HttpRequest.isInstance(args.request)) {
        return next(args);
      }
      const smithyContext = (0, import_util_middleware2.getSmithyContext)(context);
      const scheme = smithyContext.selectedHttpAuthScheme;
      if (!scheme) {
        throw new Error(`No HttpAuthScheme was selected: unable to sign request`);
      }
      const { httpAuthOption: { signingProperties = {} }, identity, signer } = scheme;
      const output = await next({
        ...args,
        request: await signer.sign(args.request, identity, signingProperties)
      }).catch((signer.errorHandler || defaultErrorHandler)(signingProperties));
      (signer.successHandler || defaultSuccessHandler)(output.response, signingProperties);
      return output;
    };
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-signing/getHttpSigningMiddleware.js
var httpSigningMiddlewareOptions, getHttpSigningPlugin;
var init_getHttpSigningMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-signing/getHttpSigningMiddleware.js"() {
    init_httpSigningMiddleware();
    httpSigningMiddlewareOptions = {
      step: "finalizeRequest",
      tags: ["HTTP_SIGNING"],
      name: "httpSigningMiddleware",
      aliases: ["apiKeyMiddleware", "tokenMiddleware", "awsAuthMiddleware"],
      override: true,
      relation: "after",
      toMiddleware: "retryMiddleware"
    };
    getHttpSigningPlugin = (config) => ({
      applyToStack: (clientStack) => {
        clientStack.addRelativeTo(httpSigningMiddleware(config), httpSigningMiddlewareOptions);
      }
    });
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-signing/index.js
var init_middleware_http_signing = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-signing/index.js"() {
    init_httpSigningMiddleware();
    init_getHttpSigningMiddleware();
  }
});

// node_modules/@smithy/core/dist-es/normalizeProvider.js
var normalizeProvider;
var init_normalizeProvider = __esm({
  "node_modules/@smithy/core/dist-es/normalizeProvider.js"() {
    normalizeProvider = (input) => {
      if (typeof input === "function")
        return input;
      const promisified = Promise.resolve(input);
      return () => promisified;
    };
  }
});

// node_modules/@smithy/core/dist-es/pagination/createPaginator.js
function createPaginator(ClientCtor, CommandCtor, inputTokenName, outputTokenName, pageSizeTokenName) {
  return async function* paginateOperation(config, input, ...additionalArguments) {
    const _input = input;
    let token = config.startingToken ?? _input[inputTokenName];
    let hasNext = true;
    let page;
    while (hasNext) {
      _input[inputTokenName] = token;
      if (pageSizeTokenName) {
        _input[pageSizeTokenName] = _input[pageSizeTokenName] ?? config.pageSize;
      }
      if (config.client instanceof ClientCtor) {
        page = await makePagedClientRequest(CommandCtor, config.client, input, config.withCommand, ...additionalArguments);
      } else {
        throw new Error(`Invalid client, expected instance of ${ClientCtor.name}`);
      }
      yield page;
      const prevToken = token;
      token = get(page, outputTokenName);
      hasNext = !!(token && (!config.stopOnSameToken || token !== prevToken));
    }
    return void 0;
  };
}
var makePagedClientRequest, get;
var init_createPaginator = __esm({
  "node_modules/@smithy/core/dist-es/pagination/createPaginator.js"() {
    makePagedClientRequest = async (CommandCtor, client2, input, withCommand = (_) => _, ...args) => {
      let command = new CommandCtor(input);
      command = withCommand(command) ?? command;
      return await client2.send(command, ...args);
    };
    get = (fromObject, path) => {
      let cursor2 = fromObject;
      const pathComponents = path.split(".");
      for (const step of pathComponents) {
        if (!cursor2 || typeof cursor2 !== "object") {
          return void 0;
        }
        cursor2 = cursor2[step];
      }
      return cursor2;
    };
  }
});

// node_modules/@smithy/is-array-buffer/dist-cjs/index.js
var require_dist_cjs8 = __commonJS({
  "node_modules/@smithy/is-array-buffer/dist-cjs/index.js"(exports) {
    "use strict";
    var isArrayBuffer = (arg) => typeof ArrayBuffer === "function" && arg instanceof ArrayBuffer || Object.prototype.toString.call(arg) === "[object ArrayBuffer]";
    exports.isArrayBuffer = isArrayBuffer;
  }
});

// node_modules/@smithy/util-buffer-from/dist-cjs/index.js
var require_dist_cjs9 = __commonJS({
  "node_modules/@smithy/util-buffer-from/dist-cjs/index.js"(exports) {
    "use strict";
    var isArrayBuffer = require_dist_cjs8();
    var buffer = __require("buffer");
    var fromArrayBuffer = (input, offset = 0, length = input.byteLength - offset) => {
      if (!isArrayBuffer.isArrayBuffer(input)) {
        throw new TypeError(`The "input" argument must be ArrayBuffer. Received type ${typeof input} (${input})`);
      }
      return buffer.Buffer.from(input, offset, length);
    };
    var fromString = (input, encoding) => {
      if (typeof input !== "string") {
        throw new TypeError(`The "input" argument must be of type string. Received type ${typeof input} (${input})`);
      }
      return encoding ? buffer.Buffer.from(input, encoding) : buffer.Buffer.from(input);
    };
    exports.fromArrayBuffer = fromArrayBuffer;
    exports.fromString = fromString;
  }
});

// node_modules/@smithy/util-base64/dist-cjs/fromBase64.js
var require_fromBase64 = __commonJS({
  "node_modules/@smithy/util-base64/dist-cjs/fromBase64.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.fromBase64 = void 0;
    var util_buffer_from_1 = require_dist_cjs9();
    var BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
    var fromBase648 = (input) => {
      if (input.length * 3 % 4 !== 0) {
        throw new TypeError(`Incorrect padding on base64 string.`);
      }
      if (!BASE64_REGEX.exec(input)) {
        throw new TypeError(`Invalid base64 string.`);
      }
      const buffer = (0, util_buffer_from_1.fromString)(input, "base64");
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    };
    exports.fromBase64 = fromBase648;
  }
});

// node_modules/@smithy/util-utf8/dist-cjs/index.js
var require_dist_cjs10 = __commonJS({
  "node_modules/@smithy/util-utf8/dist-cjs/index.js"(exports) {
    "use strict";
    var utilBufferFrom = require_dist_cjs9();
    var fromUtf87 = (input) => {
      const buf = utilBufferFrom.fromString(input, "utf8");
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength / Uint8Array.BYTES_PER_ELEMENT);
    };
    var toUint8Array2 = (data2) => {
      if (typeof data2 === "string") {
        return fromUtf87(data2);
      }
      if (ArrayBuffer.isView(data2)) {
        return new Uint8Array(data2.buffer, data2.byteOffset, data2.byteLength / Uint8Array.BYTES_PER_ELEMENT);
      }
      return new Uint8Array(data2);
    };
    var toUtf810 = (input) => {
      if (typeof input === "string") {
        return input;
      }
      if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") {
        throw new Error("@smithy/util-utf8: toUtf8 encoder function only accepts string | Uint8Array.");
      }
      return utilBufferFrom.fromArrayBuffer(input.buffer, input.byteOffset, input.byteLength).toString("utf8");
    };
    exports.fromUtf8 = fromUtf87;
    exports.toUint8Array = toUint8Array2;
    exports.toUtf8 = toUtf810;
  }
});

// node_modules/@smithy/util-base64/dist-cjs/toBase64.js
var require_toBase64 = __commonJS({
  "node_modules/@smithy/util-base64/dist-cjs/toBase64.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toBase64 = void 0;
    var util_buffer_from_1 = require_dist_cjs9();
    var util_utf8_1 = require_dist_cjs10();
    var toBase648 = (_input) => {
      let input;
      if (typeof _input === "string") {
        input = (0, util_utf8_1.fromUtf8)(_input);
      } else {
        input = _input;
      }
      if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") {
        throw new Error("@smithy/util-base64: toBase64 encoder function only accepts string | Uint8Array.");
      }
      return (0, util_buffer_from_1.fromArrayBuffer)(input.buffer, input.byteOffset, input.byteLength).toString("base64");
    };
    exports.toBase64 = toBase648;
  }
});

// node_modules/@smithy/util-base64/dist-cjs/index.js
var require_dist_cjs11 = __commonJS({
  "node_modules/@smithy/util-base64/dist-cjs/index.js"(exports) {
    "use strict";
    var fromBase648 = require_fromBase64();
    var toBase648 = require_toBase64();
    Object.keys(fromBase648).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return fromBase648[k4];
        }
      });
    });
    Object.keys(toBase648).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return toBase648[k4];
        }
      });
    });
  }
});

// node_modules/@smithy/util-stream/dist-cjs/checksum/ChecksumStream.js
var require_ChecksumStream = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/checksum/ChecksumStream.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.ChecksumStream = void 0;
    var util_base64_1 = require_dist_cjs11();
    var stream_1 = __require("stream");
    var ChecksumStream = class extends stream_1.Duplex {
      expectedChecksum;
      checksumSourceLocation;
      checksum;
      source;
      base64Encoder;
      constructor({ expectedChecksum, checksum, source, checksumSourceLocation, base64Encoder }) {
        super();
        if (typeof source.pipe === "function") {
          this.source = source;
        } else {
          throw new Error(`@smithy/util-stream: unsupported source type ${source?.constructor?.name ?? source} in ChecksumStream.`);
        }
        this.base64Encoder = base64Encoder ?? util_base64_1.toBase64;
        this.expectedChecksum = expectedChecksum;
        this.checksum = checksum;
        this.checksumSourceLocation = checksumSourceLocation;
        this.source.pipe(this);
      }
      _read(size) {
      }
      _write(chunk, encoding, callback) {
        try {
          this.checksum.update(chunk);
          this.push(chunk);
        } catch (e4) {
          return callback(e4);
        }
        return callback();
      }
      async _final(callback) {
        try {
          const digest = await this.checksum.digest();
          const received = this.base64Encoder(digest);
          if (this.expectedChecksum !== received) {
            return callback(new Error(`Checksum mismatch: expected "${this.expectedChecksum}" but received "${received}" in response header "${this.checksumSourceLocation}".`));
          }
        } catch (e4) {
          return callback(e4);
        }
        this.push(null);
        return callback();
      }
    };
    exports.ChecksumStream = ChecksumStream;
  }
});

// node_modules/@smithy/util-stream/dist-cjs/stream-type-check.js
var require_stream_type_check = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/stream-type-check.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.isBlob = exports.isReadableStream = void 0;
    var isReadableStream = (stream) => typeof ReadableStream === "function" && (stream?.constructor?.name === ReadableStream.name || stream instanceof ReadableStream);
    exports.isReadableStream = isReadableStream;
    var isBlob = (blob) => {
      return typeof Blob === "function" && (blob?.constructor?.name === Blob.name || blob instanceof Blob);
    };
    exports.isBlob = isBlob;
  }
});

// node_modules/@smithy/util-stream/dist-cjs/checksum/ChecksumStream.browser.js
var require_ChecksumStream_browser = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/checksum/ChecksumStream.browser.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.ChecksumStream = void 0;
    var ReadableStreamRef = typeof ReadableStream === "function" ? ReadableStream : function() {
    };
    var ChecksumStream = class extends ReadableStreamRef {
    };
    exports.ChecksumStream = ChecksumStream;
  }
});

// node_modules/@smithy/util-stream/dist-cjs/checksum/createChecksumStream.browser.js
var require_createChecksumStream_browser = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/checksum/createChecksumStream.browser.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.createChecksumStream = void 0;
    var util_base64_1 = require_dist_cjs11();
    var stream_type_check_1 = require_stream_type_check();
    var ChecksumStream_browser_1 = require_ChecksumStream_browser();
    var createChecksumStream = ({ expectedChecksum, checksum, source, checksumSourceLocation, base64Encoder }) => {
      if (!(0, stream_type_check_1.isReadableStream)(source)) {
        throw new Error(`@smithy/util-stream: unsupported source type ${source?.constructor?.name ?? source} in ChecksumStream.`);
      }
      const encoder = base64Encoder ?? util_base64_1.toBase64;
      if (typeof TransformStream !== "function") {
        throw new Error("@smithy/util-stream: unable to instantiate ChecksumStream because API unavailable: ReadableStream/TransformStream.");
      }
      const transform = new TransformStream({
        start() {
        },
        async transform(chunk, controller) {
          checksum.update(chunk);
          controller.enqueue(chunk);
        },
        async flush(controller) {
          const digest = await checksum.digest();
          const received = encoder(digest);
          if (expectedChecksum !== received) {
            const error2 = new Error(`Checksum mismatch: expected "${expectedChecksum}" but received "${received}" in response header "${checksumSourceLocation}".`);
            controller.error(error2);
          } else {
            controller.terminate();
          }
        }
      });
      source.pipeThrough(transform);
      const readable = transform.readable;
      Object.setPrototypeOf(readable, ChecksumStream_browser_1.ChecksumStream.prototype);
      return readable;
    };
    exports.createChecksumStream = createChecksumStream;
  }
});

// node_modules/@smithy/util-stream/dist-cjs/checksum/createChecksumStream.js
var require_createChecksumStream = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/checksum/createChecksumStream.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.createChecksumStream = createChecksumStream;
    var stream_type_check_1 = require_stream_type_check();
    var ChecksumStream_1 = require_ChecksumStream();
    var createChecksumStream_browser_1 = require_createChecksumStream_browser();
    function createChecksumStream(init) {
      if (typeof ReadableStream === "function" && (0, stream_type_check_1.isReadableStream)(init.source)) {
        return (0, createChecksumStream_browser_1.createChecksumStream)(init);
      }
      return new ChecksumStream_1.ChecksumStream(init);
    }
  }
});

// node_modules/@smithy/util-stream/dist-cjs/ByteArrayCollector.js
var require_ByteArrayCollector = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/ByteArrayCollector.js"(exports) {
    "use strict";
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
        let cursor2 = 0;
        for (let i4 = 0; i4 < this.byteArrays.length; ++i4) {
          const bytes = this.byteArrays[i4];
          aggregation.set(bytes, cursor2);
          cursor2 += bytes.byteLength;
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
  }
});

// node_modules/@smithy/util-stream/dist-cjs/createBufferedReadableStream.js
var require_createBufferedReadableStream = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/createBufferedReadableStream.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.createBufferedReadable = void 0;
    exports.createBufferedReadableStream = createBufferedReadableStream;
    exports.merge = merge;
    exports.flush = flush;
    exports.sizeOf = sizeOf;
    exports.modeOf = modeOf;
    var ByteArrayCollector_1 = require_ByteArrayCollector();
    function createBufferedReadableStream(upstream, size, logger2) {
      const reader = upstream.getReader();
      let streamBufferingLoggedWarning = false;
      let bytesSeen = 0;
      const buffers = ["", new ByteArrayCollector_1.ByteArrayCollector((size2) => new Uint8Array(size2))];
      let mode = -1;
      const pull = async (controller) => {
        const { value, done } = await reader.read();
        const chunk = value;
        if (done) {
          if (mode !== -1) {
            const remainder = flush(buffers, mode);
            if (sizeOf(remainder) > 0) {
              controller.enqueue(remainder);
            }
          }
          controller.close();
        } else {
          const chunkMode = modeOf(chunk, false);
          if (mode !== chunkMode) {
            if (mode >= 0) {
              controller.enqueue(flush(buffers, mode));
            }
            mode = chunkMode;
          }
          if (mode === -1) {
            controller.enqueue(chunk);
            return;
          }
          const chunkSize = sizeOf(chunk);
          bytesSeen += chunkSize;
          const bufferSize = sizeOf(buffers[mode]);
          if (chunkSize >= size && bufferSize === 0) {
            controller.enqueue(chunk);
          } else {
            const newSize = merge(buffers, mode, chunk);
            if (!streamBufferingLoggedWarning && bytesSeen > size * 2) {
              streamBufferingLoggedWarning = true;
              logger2?.warn(`@smithy/util-stream - stream chunk size ${chunkSize} is below threshold of ${size}, automatically buffering.`);
            }
            if (newSize >= size) {
              controller.enqueue(flush(buffers, mode));
            } else {
              await pull(controller);
            }
          }
        }
      };
      return new ReadableStream({
        pull
      });
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
          const s4 = buffers[0];
          buffers[0] = "";
          return s4;
        case 1:
        case 2:
          return buffers[mode].flush();
      }
      throw new Error(`@smithy/util-stream - invalid index ${mode} given to flush()`);
    }
    function sizeOf(chunk) {
      return chunk?.byteLength ?? chunk?.length ?? 0;
    }
    function modeOf(chunk, allowBuffer = true) {
      if (allowBuffer && typeof Buffer !== "undefined" && chunk instanceof Buffer) {
        return 2;
      }
      if (chunk instanceof Uint8Array) {
        return 1;
      }
      if (typeof chunk === "string") {
        return 0;
      }
      return -1;
    }
  }
});

// node_modules/@smithy/util-stream/dist-cjs/createBufferedReadable.js
var require_createBufferedReadable = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/createBufferedReadable.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.createBufferedReadable = createBufferedReadable;
    var node_stream_1 = __require("node:stream");
    var ByteArrayCollector_1 = require_ByteArrayCollector();
    var createBufferedReadableStream_1 = require_createBufferedReadableStream();
    var stream_type_check_1 = require_stream_type_check();
    function createBufferedReadable(upstream, size, logger2) {
      if ((0, stream_type_check_1.isReadableStream)(upstream)) {
        return (0, createBufferedReadableStream_1.createBufferedReadableStream)(upstream, size, logger2);
      }
      const downstream = new node_stream_1.Readable({ read() {
      } });
      let streamBufferingLoggedWarning = false;
      let bytesSeen = 0;
      const buffers = [
        "",
        new ByteArrayCollector_1.ByteArrayCollector((size2) => new Uint8Array(size2)),
        new ByteArrayCollector_1.ByteArrayCollector((size2) => Buffer.from(new Uint8Array(size2)))
      ];
      let mode = -1;
      upstream.on("data", (chunk) => {
        const chunkMode = (0, createBufferedReadableStream_1.modeOf)(chunk, true);
        if (mode !== chunkMode) {
          if (mode >= 0) {
            downstream.push((0, createBufferedReadableStream_1.flush)(buffers, mode));
          }
          mode = chunkMode;
        }
        if (mode === -1) {
          downstream.push(chunk);
          return;
        }
        const chunkSize = (0, createBufferedReadableStream_1.sizeOf)(chunk);
        bytesSeen += chunkSize;
        const bufferSize = (0, createBufferedReadableStream_1.sizeOf)(buffers[mode]);
        if (chunkSize >= size && bufferSize === 0) {
          downstream.push(chunk);
        } else {
          const newSize = (0, createBufferedReadableStream_1.merge)(buffers, mode, chunk);
          if (!streamBufferingLoggedWarning && bytesSeen > size * 2) {
            streamBufferingLoggedWarning = true;
            logger2?.warn(`@smithy/util-stream - stream chunk size ${chunkSize} is below threshold of ${size}, automatically buffering.`);
          }
          if (newSize >= size) {
            downstream.push((0, createBufferedReadableStream_1.flush)(buffers, mode));
          }
        }
      });
      upstream.on("end", () => {
        if (mode !== -1) {
          const remainder = (0, createBufferedReadableStream_1.flush)(buffers, mode);
          if ((0, createBufferedReadableStream_1.sizeOf)(remainder) > 0) {
            downstream.push(remainder);
          }
        }
        downstream.push(null);
      });
      return downstream;
    }
  }
});

// node_modules/@smithy/util-stream/dist-cjs/getAwsChunkedEncodingStream.js
var require_getAwsChunkedEncodingStream = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/getAwsChunkedEncodingStream.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getAwsChunkedEncodingStream = void 0;
    var stream_1 = __require("stream");
    var getAwsChunkedEncodingStream = (readableStream, options) => {
      const { base64Encoder, bodyLengthChecker, checksumAlgorithmFn, checksumLocationName, streamHasher } = options;
      const checksumRequired = base64Encoder !== void 0 && checksumAlgorithmFn !== void 0 && checksumLocationName !== void 0 && streamHasher !== void 0;
      const digest = checksumRequired ? streamHasher(checksumAlgorithmFn, readableStream) : void 0;
      const awsChunkedEncodingStream = new stream_1.Readable({ read: () => {
      } });
      readableStream.on("data", (data2) => {
        const length = bodyLengthChecker(data2) || 0;
        awsChunkedEncodingStream.push(`${length.toString(16)}\r
`);
        awsChunkedEncodingStream.push(data2);
        awsChunkedEncodingStream.push("\r\n");
      });
      readableStream.on("end", async () => {
        awsChunkedEncodingStream.push(`0\r
`);
        if (checksumRequired) {
          const checksum = base64Encoder(await digest);
          awsChunkedEncodingStream.push(`${checksumLocationName}:${checksum}\r
`);
          awsChunkedEncodingStream.push(`\r
`);
        }
        awsChunkedEncodingStream.push(null);
      });
      return awsChunkedEncodingStream;
    };
    exports.getAwsChunkedEncodingStream = getAwsChunkedEncodingStream;
  }
});

// node_modules/@smithy/util-stream/dist-cjs/headStream.browser.js
var require_headStream_browser = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/headStream.browser.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.headStream = headStream;
    async function headStream(stream, bytes) {
      let byteLengthCounter = 0;
      const chunks = [];
      const reader = stream.getReader();
      let isDone = false;
      while (!isDone) {
        const { done, value } = await reader.read();
        if (value) {
          chunks.push(value);
          byteLengthCounter += value?.byteLength ?? 0;
        }
        if (byteLengthCounter >= bytes) {
          break;
        }
        isDone = done;
      }
      reader.releaseLock();
      const collected = new Uint8Array(Math.min(bytes, byteLengthCounter));
      let offset = 0;
      for (const chunk of chunks) {
        if (chunk.byteLength > collected.byteLength - offset) {
          collected.set(chunk.subarray(0, collected.byteLength - offset), offset);
          break;
        } else {
          collected.set(chunk, offset);
        }
        offset += chunk.length;
      }
      return collected;
    }
  }
});

// node_modules/@smithy/util-stream/dist-cjs/headStream.js
var require_headStream = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/headStream.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.headStream = void 0;
    var stream_1 = __require("stream");
    var headStream_browser_1 = require_headStream_browser();
    var stream_type_check_1 = require_stream_type_check();
    var headStream = (stream, bytes) => {
      if ((0, stream_type_check_1.isReadableStream)(stream)) {
        return (0, headStream_browser_1.headStream)(stream, bytes);
      }
      return new Promise((resolve, reject) => {
        const collector = new Collector();
        collector.limit = bytes;
        stream.pipe(collector);
        stream.on("error", (err) => {
          collector.end();
          reject(err);
        });
        collector.on("error", reject);
        collector.on("finish", function() {
          const bytes2 = new Uint8Array(Buffer.concat(this.buffers));
          resolve(bytes2);
        });
      });
    };
    exports.headStream = headStream;
    var Collector = class extends stream_1.Writable {
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
  }
});

// node_modules/@smithy/util-uri-escape/dist-cjs/index.js
var require_dist_cjs12 = __commonJS({
  "node_modules/@smithy/util-uri-escape/dist-cjs/index.js"(exports) {
    "use strict";
    var escapeUri = (uri) => encodeURIComponent(uri).replace(/[!'()*]/g, hexEncode);
    var hexEncode = (c4) => `%${c4.charCodeAt(0).toString(16).toUpperCase()}`;
    var escapeUriPath = (uri) => uri.split("/").map(escapeUri).join("/");
    exports.escapeUri = escapeUri;
    exports.escapeUriPath = escapeUriPath;
  }
});

// node_modules/@smithy/querystring-builder/dist-cjs/index.js
var require_dist_cjs13 = __commonJS({
  "node_modules/@smithy/querystring-builder/dist-cjs/index.js"(exports) {
    "use strict";
    var utilUriEscape = require_dist_cjs12();
    function buildQueryString(query) {
      const parts = [];
      for (let key of Object.keys(query).sort()) {
        const value = query[key];
        key = utilUriEscape.escapeUri(key);
        if (Array.isArray(value)) {
          for (let i4 = 0, iLen = value.length; i4 < iLen; i4++) {
            parts.push(`${key}=${utilUriEscape.escapeUri(value[i4])}`);
          }
        } else {
          let qsEntry = key;
          if (value || typeof value === "string") {
            qsEntry += `=${utilUriEscape.escapeUri(value)}`;
          }
          parts.push(qsEntry);
        }
      }
      return parts.join("&");
    }
    exports.buildQueryString = buildQueryString;
  }
});

// node_modules/@smithy/node-http-handler/dist-cjs/index.js
var require_dist_cjs14 = __commonJS({
  "node_modules/@smithy/node-http-handler/dist-cjs/index.js"(exports) {
    "use strict";
    var protocolHttp = require_dist_cjs2();
    var querystringBuilder = require_dist_cjs13();
    var http = __require("http");
    var https = __require("https");
    var stream = __require("stream");
    var http2 = __require("http2");
    var NODEJS_TIMEOUT_ERROR_CODES = ["ECONNRESET", "EPIPE", "ETIMEDOUT"];
    var getTransformedHeaders = (headers) => {
      const transformedHeaders = {};
      for (const name of Object.keys(headers)) {
        const headerValues = headers[name];
        transformedHeaders[name] = Array.isArray(headerValues) ? headerValues.join(",") : headerValues;
      }
      return transformedHeaders;
    };
    var timing = {
      setTimeout: (cb, ms) => setTimeout(cb, ms),
      clearTimeout: (timeoutId) => clearTimeout(timeoutId)
    };
    var DEFER_EVENT_LISTENER_TIME$2 = 1e3;
    var setConnectionTimeout = (request, reject, timeoutInMs = 0) => {
      if (!timeoutInMs) {
        return -1;
      }
      const registerTimeout = (offset) => {
        const timeoutId = timing.setTimeout(() => {
          request.destroy();
          reject(Object.assign(new Error(`@smithy/node-http-handler - the request socket did not establish a connection with the server within the configured timeout of ${timeoutInMs} ms.`), {
            name: "TimeoutError"
          }));
        }, timeoutInMs - offset);
        const doWithSocket = (socket) => {
          if (socket?.connecting) {
            socket.on("connect", () => {
              timing.clearTimeout(timeoutId);
            });
          } else {
            timing.clearTimeout(timeoutId);
          }
        };
        if (request.socket) {
          doWithSocket(request.socket);
        } else {
          request.on("socket", doWithSocket);
        }
      };
      if (timeoutInMs < 2e3) {
        registerTimeout(0);
        return 0;
      }
      return timing.setTimeout(registerTimeout.bind(null, DEFER_EVENT_LISTENER_TIME$2), DEFER_EVENT_LISTENER_TIME$2);
    };
    var setRequestTimeout = (req, reject, timeoutInMs = 0, throwOnRequestTimeout, logger2) => {
      if (timeoutInMs) {
        return timing.setTimeout(() => {
          let msg = `@smithy/node-http-handler - [${throwOnRequestTimeout ? "ERROR" : "WARN"}] a request has exceeded the configured ${timeoutInMs} ms requestTimeout.`;
          if (throwOnRequestTimeout) {
            const error2 = Object.assign(new Error(msg), {
              name: "TimeoutError",
              code: "ETIMEDOUT"
            });
            req.destroy(error2);
            reject(error2);
          } else {
            msg += ` Init client requestHandler with throwOnRequestTimeout=true to turn this into an error.`;
            logger2?.warn?.(msg);
          }
        }, timeoutInMs);
      }
      return -1;
    };
    var DEFER_EVENT_LISTENER_TIME$1 = 3e3;
    var setSocketKeepAlive = (request, { keepAlive, keepAliveMsecs }, deferTimeMs = DEFER_EVENT_LISTENER_TIME$1) => {
      if (keepAlive !== true) {
        return -1;
      }
      const registerListener = () => {
        if (request.socket) {
          request.socket.setKeepAlive(keepAlive, keepAliveMsecs || 0);
        } else {
          request.on("socket", (socket) => {
            socket.setKeepAlive(keepAlive, keepAliveMsecs || 0);
          });
        }
      };
      if (deferTimeMs === 0) {
        registerListener();
        return 0;
      }
      return timing.setTimeout(registerListener, deferTimeMs);
    };
    var DEFER_EVENT_LISTENER_TIME = 3e3;
    var setSocketTimeout = (request, reject, timeoutInMs = 0) => {
      const registerTimeout = (offset) => {
        const timeout = timeoutInMs - offset;
        const onTimeout = () => {
          request.destroy();
          reject(Object.assign(new Error(`@smithy/node-http-handler - the request socket timed out after ${timeoutInMs} ms of inactivity (configured by client requestHandler).`), { name: "TimeoutError" }));
        };
        if (request.socket) {
          request.socket.setTimeout(timeout, onTimeout);
          request.on("close", () => request.socket?.removeListener("timeout", onTimeout));
        } else {
          request.setTimeout(timeout, onTimeout);
        }
      };
      if (0 < timeoutInMs && timeoutInMs < 6e3) {
        registerTimeout(0);
        return 0;
      }
      return timing.setTimeout(registerTimeout.bind(null, timeoutInMs === 0 ? 0 : DEFER_EVENT_LISTENER_TIME), DEFER_EVENT_LISTENER_TIME);
    };
    var MIN_WAIT_TIME = 6e3;
    async function writeRequestBody(httpRequest, request, maxContinueTimeoutMs = MIN_WAIT_TIME, externalAgent = false) {
      const headers = request.headers ?? {};
      const expect = headers.Expect || headers.expect;
      let timeoutId = -1;
      let sendBody = true;
      if (!externalAgent && expect === "100-continue") {
        sendBody = await Promise.race([
          new Promise((resolve) => {
            timeoutId = Number(timing.setTimeout(() => resolve(true), Math.max(MIN_WAIT_TIME, maxContinueTimeoutMs)));
          }),
          new Promise((resolve) => {
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
          })
        ]);
      }
      if (sendBody) {
        writeBody(httpRequest, request.body);
      }
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
    var DEFAULT_REQUEST_TIMEOUT = 0;
    var NodeHttpHandler = class _NodeHttpHandler {
      config;
      configProvider;
      socketWarningTimestamp = 0;
      externalAgent = false;
      metadata = { handlerProtocol: "http/1.1" };
      static create(instanceOrOptions) {
        if (typeof instanceOrOptions?.handle === "function") {
          return instanceOrOptions;
        }
        return new _NodeHttpHandler(instanceOrOptions);
      }
      static checkSocketUsage(agent, socketWarningTimestamp, logger2 = console) {
        const { sockets, requests, maxSockets } = agent;
        if (typeof maxSockets !== "number" || maxSockets === Infinity) {
          return socketWarningTimestamp;
        }
        const interval = 15e3;
        if (Date.now() - interval < socketWarningTimestamp) {
          return socketWarningTimestamp;
        }
        if (sockets && requests) {
          for (const origin in sockets) {
            const socketsInUse = sockets[origin]?.length ?? 0;
            const requestsEnqueued = requests[origin]?.length ?? 0;
            if (socketsInUse >= maxSockets && requestsEnqueued >= 2 * maxSockets) {
              logger2?.warn?.(`@smithy/node-http-handler:WARN - socket usage at capacity=${socketsInUse} and ${requestsEnqueued} additional requests are enqueued.
See https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/node-configuring-maxsockets.html
or increase socketAcquisitionWarningTimeout=(millis) in the NodeHttpHandler config.`);
              return Date.now();
            }
          }
        }
        return socketWarningTimestamp;
      }
      constructor(options) {
        this.configProvider = new Promise((resolve, reject) => {
          if (typeof options === "function") {
            options().then((_options) => {
              resolve(this.resolveDefaultConfig(_options));
            }).catch(reject);
          } else {
            resolve(this.resolveDefaultConfig(options));
          }
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
            if (httpAgent instanceof http.Agent || typeof httpAgent?.destroy === "function") {
              this.externalAgent = true;
              return httpAgent;
            }
            return new http.Agent({ keepAlive, maxSockets, ...httpAgent });
          })(),
          httpsAgent: (() => {
            if (httpsAgent instanceof https.Agent || typeof httpsAgent?.destroy === "function") {
              this.externalAgent = true;
              return httpsAgent;
            }
            return new https.Agent({ keepAlive, maxSockets, ...httpsAgent });
          })(),
          logger: console
        };
      }
      destroy() {
        this.config?.httpAgent?.destroy();
        this.config?.httpsAgent?.destroy();
      }
      async handle(request, { abortSignal, requestTimeout } = {}) {
        if (!this.config) {
          this.config = await this.configProvider;
        }
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
            const abortError = new Error("Request aborted");
            abortError.name = "AbortError";
            reject(abortError);
            return;
          }
          const isSSL = request.protocol === "https:";
          const headers = request.headers ?? {};
          const expectContinue = (headers.Expect ?? headers.expect) === "100-continue";
          let agent = isSSL ? config.httpsAgent : config.httpAgent;
          if (expectContinue && !this.externalAgent) {
            agent = new (isSSL ? https.Agent : http.Agent)({
              keepAlive: false,
              maxSockets: Infinity
            });
          }
          timeouts.push(timing.setTimeout(() => {
            this.socketWarningTimestamp = _NodeHttpHandler.checkSocketUsage(agent, this.socketWarningTimestamp, config.logger);
          }, config.socketAcquisitionWarningTimeout ?? (config.requestTimeout ?? 2e3) + (config.connectionTimeout ?? 1e3)));
          const queryString = querystringBuilder.buildQueryString(request.query || {});
          let auth = void 0;
          if (request.username != null || request.password != null) {
            const username = request.username ?? "";
            const password = request.password ?? "";
            auth = `${username}:${password}`;
          }
          let path = request.path;
          if (queryString) {
            path += `?${queryString}`;
          }
          if (request.fragment) {
            path += `#${request.fragment}`;
          }
          let hostname = request.hostname ?? "";
          if (hostname[0] === "[" && hostname.endsWith("]")) {
            hostname = request.hostname.slice(1, -1);
          } else {
            hostname = request.hostname;
          }
          const nodeHttpsOptions = {
            headers: request.headers,
            host: hostname,
            method: request.method,
            path,
            port: request.port,
            agent,
            auth
          };
          const requestFunc = isSSL ? https.request : http.request;
          const req = requestFunc(nodeHttpsOptions, (res) => {
            const httpResponse = new protocolHttp.HttpResponse({
              statusCode: res.statusCode || -1,
              reason: res.statusMessage,
              headers: getTransformedHeaders(res.headers),
              body: res
            });
            resolve({ response: httpResponse });
          });
          req.on("error", (err) => {
            if (NODEJS_TIMEOUT_ERROR_CODES.includes(err.code)) {
              reject(Object.assign(err, { name: "TimeoutError" }));
            } else {
              reject(err);
            }
          });
          if (abortSignal) {
            const onAbort = () => {
              req.destroy();
              const abortError = new Error("Request aborted");
              abortError.name = "AbortError";
              reject(abortError);
            };
            if (typeof abortSignal.addEventListener === "function") {
              const signal = abortSignal;
              signal.addEventListener("abort", onAbort, { once: true });
              req.once("close", () => signal.removeEventListener("abort", onAbort));
            } else {
              abortSignal.onabort = onAbort;
            }
          }
          const effectiveRequestTimeout = requestTimeout ?? config.requestTimeout;
          timeouts.push(setConnectionTimeout(req, reject, config.connectionTimeout));
          timeouts.push(setRequestTimeout(req, reject, effectiveRequestTimeout, config.throwOnRequestTimeout, config.logger ?? console));
          timeouts.push(setSocketTimeout(req, reject, config.socketTimeout));
          const httpAgent = nodeHttpsOptions.agent;
          if (typeof httpAgent === "object" && "keepAlive" in httpAgent) {
            timeouts.push(setSocketKeepAlive(req, {
              keepAlive: httpAgent.keepAlive,
              keepAliveMsecs: httpAgent.keepAliveMsecs
            }));
          }
          writeRequestBodyPromise = writeRequestBody(req, request, effectiveRequestTimeout, this.externalAgent).catch((e4) => {
            timeouts.forEach(timing.clearTimeout);
            return _reject(e4);
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
        if (this.sessions.length > 0) {
          return this.sessions.shift();
        }
      }
      offerLast(session) {
        this.sessions.push(session);
      }
      contains(session) {
        return this.sessions.includes(session);
      }
      remove(session) {
        this.sessions = this.sessions.filter((s4) => s4 !== session);
      }
      [Symbol.iterator]() {
        return this.sessions[Symbol.iterator]();
      }
      destroy(connection) {
        for (const session of this.sessions) {
          if (session === connection) {
            if (!session.destroyed) {
              session.destroy();
            }
          }
        }
      }
    };
    var NodeHttp2ConnectionManager = class {
      constructor(config) {
        this.config = config;
        if (this.config.maxConcurrency && this.config.maxConcurrency <= 0) {
          throw new RangeError("maxConcurrency must be greater than zero.");
        }
      }
      config;
      sessionCache = /* @__PURE__ */ new Map();
      lease(requestContext, connectionConfiguration) {
        const url = this.getUrlString(requestContext);
        const existingPool = this.sessionCache.get(url);
        if (existingPool) {
          const existingSession = existingPool.poll();
          if (existingSession && !this.config.disableConcurrency) {
            return existingSession;
          }
        }
        const session = http2.connect(url);
        if (this.config.maxConcurrency) {
          session.settings({ maxConcurrentStreams: this.config.maxConcurrency }, (err) => {
            if (err) {
              throw new Error("Fail to set maxConcurrentStreams to " + this.config.maxConcurrency + "when creating new session for " + requestContext.destination.toString());
            }
          });
        }
        session.unref();
        const destroySessionCb = () => {
          session.destroy();
          this.deleteSession(url, session);
        };
        session.on("goaway", destroySessionCb);
        session.on("error", destroySessionCb);
        session.on("frameError", destroySessionCb);
        session.on("close", () => this.deleteSession(url, session));
        if (connectionConfiguration.requestTimeout) {
          session.setTimeout(connectionConfiguration.requestTimeout, destroySessionCb);
        }
        const connectionPool = this.sessionCache.get(url) || new NodeHttp2ConnectionPool();
        connectionPool.offerLast(session);
        this.sessionCache.set(url, connectionPool);
        return session;
      }
      deleteSession(authority, session) {
        const existingConnectionPool = this.sessionCache.get(authority);
        if (!existingConnectionPool) {
          return;
        }
        if (!existingConnectionPool.contains(session)) {
          return;
        }
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
            if (!session.destroyed) {
              session.destroy();
            }
            connectionPool.remove(session);
          }
          this.sessionCache.delete(key);
        }
      }
      setMaxConcurrentStreams(maxConcurrentStreams) {
        if (maxConcurrentStreams && maxConcurrentStreams <= 0) {
          throw new RangeError("maxConcurrentStreams must be greater than zero.");
        }
        this.config.maxConcurrency = maxConcurrentStreams;
      }
      setDisableConcurrentStreams(disableConcurrentStreams) {
        this.config.disableConcurrency = disableConcurrentStreams;
      }
      getUrlString(request) {
        return request.destination.toString();
      }
    };
    var NodeHttp2Handler = class _NodeHttp2Handler {
      config;
      configProvider;
      metadata = { handlerProtocol: "h2" };
      connectionManager = new NodeHttp2ConnectionManager({});
      static create(instanceOrOptions) {
        if (typeof instanceOrOptions?.handle === "function") {
          return instanceOrOptions;
        }
        return new _NodeHttp2Handler(instanceOrOptions);
      }
      constructor(options) {
        this.configProvider = new Promise((resolve, reject) => {
          if (typeof options === "function") {
            options().then((opts) => {
              resolve(opts || {});
            }).catch(reject);
          } else {
            resolve(options || {});
          }
        });
      }
      destroy() {
        this.connectionManager.destroy();
      }
      async handle(request, { abortSignal, requestTimeout } = {}) {
        if (!this.config) {
          this.config = await this.configProvider;
          this.connectionManager.setDisableConcurrentStreams(this.config.disableConcurrentStreams || false);
          if (this.config.maxConcurrentStreams) {
            this.connectionManager.setMaxConcurrentStreams(this.config.maxConcurrentStreams);
          }
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
            const abortError = new Error("Request aborted");
            abortError.name = "AbortError";
            reject(abortError);
            return;
          }
          const { hostname, method, port, protocol, query } = request;
          let auth = "";
          if (request.username != null || request.password != null) {
            const username = request.username ?? "";
            const password = request.password ?? "";
            auth = `${username}:${password}@`;
          }
          const authority = `${protocol}//${auth}${hostname}${port ? `:${port}` : ""}`;
          const requestContext = { destination: new URL(authority) };
          const session = this.connectionManager.lease(requestContext, {
            requestTimeout: this.config?.sessionTimeout,
            disableConcurrentStreams: disableConcurrentStreams || false
          });
          const rejectWithDestroy = (err) => {
            if (disableConcurrentStreams) {
              this.destroySession(session);
            }
            fulfilled = true;
            reject(err);
          };
          const queryString = querystringBuilder.buildQueryString(query || {});
          let path = request.path;
          if (queryString) {
            path += `?${queryString}`;
          }
          if (request.fragment) {
            path += `#${request.fragment}`;
          }
          const req = session.request({
            ...request.headers,
            [http2.constants.HTTP2_HEADER_PATH]: path,
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
          if (effectiveRequestTimeout) {
            req.setTimeout(effectiveRequestTimeout, () => {
              req.close();
              const timeoutError = new Error(`Stream timed out because of no activity for ${effectiveRequestTimeout} ms`);
              timeoutError.name = "TimeoutError";
              rejectWithDestroy(timeoutError);
            });
          }
          if (abortSignal) {
            const onAbort = () => {
              req.close();
              const abortError = new Error("Request aborted");
              abortError.name = "AbortError";
              rejectWithDestroy(abortError);
            };
            if (typeof abortSignal.addEventListener === "function") {
              const signal = abortSignal;
              signal.addEventListener("abort", onAbort, { once: true });
              req.once("close", () => signal.removeEventListener("abort", onAbort));
            } else {
              abortSignal.onabort = onAbort;
            }
          }
          req.on("frameError", (type, code, id) => {
            rejectWithDestroy(new Error(`Frame type id ${type} in stream id ${id} has failed with code ${code}.`));
          });
          req.on("error", rejectWithDestroy);
          req.on("aborted", () => {
            rejectWithDestroy(new Error(`HTTP/2 stream is abnormally aborted in mid-communication with result code ${req.rstCode}.`));
          });
          req.on("close", () => {
            session.unref();
            if (disableConcurrentStreams) {
              session.destroy();
            }
            if (!fulfilled) {
              rejectWithDestroy(new Error("Unexpected error: http2 request did not get a response"));
            }
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
        if (!session.destroyed) {
          session.destroy();
        }
      }
    };
    var Collector = class extends stream.Writable {
      bufferedBytes = [];
      _write(chunk, encoding, callback) {
        this.bufferedBytes.push(chunk);
        callback();
      }
    };
    var streamCollector4 = (stream2) => {
      if (isReadableStreamInstance(stream2)) {
        return collectReadableStream(stream2);
      }
      return new Promise((resolve, reject) => {
        const collector = new Collector();
        stream2.pipe(collector);
        stream2.on("error", (err) => {
          collector.end();
          reject(err);
        });
        collector.on("error", reject);
        collector.on("finish", function() {
          const bytes = new Uint8Array(Buffer.concat(this.bufferedBytes));
          resolve(bytes);
        });
      });
    };
    var isReadableStreamInstance = (stream2) => typeof ReadableStream === "function" && stream2 instanceof ReadableStream;
    async function collectReadableStream(stream2) {
      const chunks = [];
      const reader = stream2.getReader();
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
    exports.streamCollector = streamCollector4;
  }
});

// node_modules/@smithy/fetch-http-handler/dist-cjs/index.js
var require_dist_cjs15 = __commonJS({
  "node_modules/@smithy/fetch-http-handler/dist-cjs/index.js"(exports) {
    "use strict";
    var protocolHttp = require_dist_cjs2();
    var querystringBuilder = require_dist_cjs13();
    var utilBase64 = require_dist_cjs11();
    function createRequest(url, requestOptions) {
      return new Request(url, requestOptions);
    }
    function requestTimeout(timeoutInMs = 0) {
      return new Promise((resolve, reject) => {
        if (timeoutInMs) {
          setTimeout(() => {
            const timeoutError = new Error(`Request did not complete within ${timeoutInMs} ms`);
            timeoutError.name = "TimeoutError";
            reject(timeoutError);
          }, timeoutInMs);
        }
      });
    }
    var keepAliveSupport = {
      supported: void 0
    };
    var FetchHttpHandler = class _FetchHttpHandler {
      config;
      configProvider;
      static create(instanceOrOptions) {
        if (typeof instanceOrOptions?.handle === "function") {
          return instanceOrOptions;
        }
        return new _FetchHttpHandler(instanceOrOptions);
      }
      constructor(options) {
        if (typeof options === "function") {
          this.configProvider = options().then((opts) => opts || {});
        } else {
          this.config = options ?? {};
          this.configProvider = Promise.resolve(this.config);
        }
        if (keepAliveSupport.supported === void 0) {
          keepAliveSupport.supported = Boolean(typeof Request !== "undefined" && "keepalive" in createRequest("https://[::1]"));
        }
      }
      destroy() {
      }
      async handle(request, { abortSignal, requestTimeout: requestTimeout$1 } = {}) {
        if (!this.config) {
          this.config = await this.configProvider;
        }
        const requestTimeoutInMs = requestTimeout$1 ?? this.config.requestTimeout;
        const keepAlive = this.config.keepAlive === true;
        const credentials = this.config.credentials;
        if (abortSignal?.aborted) {
          const abortError = new Error("Request aborted");
          abortError.name = "AbortError";
          return Promise.reject(abortError);
        }
        let path = request.path;
        const queryString = querystringBuilder.buildQueryString(request.query || {});
        if (queryString) {
          path += `?${queryString}`;
        }
        if (request.fragment) {
          path += `#${request.fragment}`;
        }
        let auth = "";
        if (request.username != null || request.password != null) {
          const username = request.username ?? "";
          const password = request.password ?? "";
          auth = `${username}:${password}@`;
        }
        const { port, method } = request;
        const url = `${request.protocol}//${auth}${request.hostname}${port ? `:${port}` : ""}${path}`;
        const body = method === "GET" || method === "HEAD" ? void 0 : request.body;
        const requestOptions = {
          body,
          headers: new Headers(request.headers),
          method,
          credentials
        };
        if (this.config?.cache) {
          requestOptions.cache = this.config.cache;
        }
        if (body) {
          requestOptions.duplex = "half";
        }
        if (typeof AbortController !== "undefined") {
          requestOptions.signal = abortSignal;
        }
        if (keepAliveSupport.supported) {
          requestOptions.keepalive = keepAlive;
        }
        if (typeof this.config.requestInit === "function") {
          Object.assign(requestOptions, this.config.requestInit(request));
        }
        let removeSignalEventListener = () => {
        };
        const fetchRequest = createRequest(url, requestOptions);
        const raceOfPromises = [
          fetch(fetchRequest).then((response) => {
            const fetchHeaders = response.headers;
            const transformedHeaders = {};
            for (const pair of fetchHeaders.entries()) {
              transformedHeaders[pair[0]] = pair[1];
            }
            const hasReadableStream = response.body != void 0;
            if (!hasReadableStream) {
              return response.blob().then((body2) => ({
                response: new protocolHttp.HttpResponse({
                  headers: transformedHeaders,
                  reason: response.statusText,
                  statusCode: response.status,
                  body: body2
                })
              }));
            }
            return {
              response: new protocolHttp.HttpResponse({
                headers: transformedHeaders,
                reason: response.statusText,
                statusCode: response.status,
                body: response.body
              })
            };
          }),
          requestTimeout(requestTimeoutInMs)
        ];
        if (abortSignal) {
          raceOfPromises.push(new Promise((resolve, reject) => {
            const onAbort = () => {
              const abortError = new Error("Request aborted");
              abortError.name = "AbortError";
              reject(abortError);
            };
            if (typeof abortSignal.addEventListener === "function") {
              const signal = abortSignal;
              signal.addEventListener("abort", onAbort, { once: true });
              removeSignalEventListener = () => signal.removeEventListener("abort", onAbort);
            } else {
              abortSignal.onabort = onAbort;
            }
          }));
        }
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
    var streamCollector4 = async (stream) => {
      if (typeof Blob === "function" && stream instanceof Blob || stream.constructor?.name === "Blob") {
        if (Blob.prototype.arrayBuffer !== void 0) {
          return new Uint8Array(await stream.arrayBuffer());
        }
        return collectBlob(stream);
      }
      return collectStream(stream);
    };
    async function collectBlob(blob) {
      const base64 = await readToBase64(blob);
      const arrayBuffer = utilBase64.fromBase64(base64);
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
          if (reader.readyState !== 2) {
            return reject(new Error("Reader aborted too early"));
          }
          const result = reader.result ?? "";
          const commaIndex = result.indexOf(",");
          const dataOffset = commaIndex > -1 ? commaIndex + 1 : result.length;
          resolve(result.substring(dataOffset));
        };
        reader.onabort = () => reject(new Error("Read aborted"));
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(blob);
      });
    }
    exports.FetchHttpHandler = FetchHttpHandler;
    exports.keepAliveSupport = keepAliveSupport;
    exports.streamCollector = streamCollector4;
  }
});

// node_modules/@smithy/util-hex-encoding/dist-cjs/index.js
var require_dist_cjs16 = __commonJS({
  "node_modules/@smithy/util-hex-encoding/dist-cjs/index.js"(exports) {
    "use strict";
    var SHORT_TO_HEX = {};
    var HEX_TO_SHORT = {};
    for (let i4 = 0; i4 < 256; i4++) {
      let encodedByte = i4.toString(16).toLowerCase();
      if (encodedByte.length === 1) {
        encodedByte = `0${encodedByte}`;
      }
      SHORT_TO_HEX[i4] = encodedByte;
      HEX_TO_SHORT[encodedByte] = i4;
    }
    function fromHex(encoded) {
      if (encoded.length % 2 !== 0) {
        throw new Error("Hex encoded strings must have an even number length");
      }
      const out = new Uint8Array(encoded.length / 2);
      for (let i4 = 0; i4 < encoded.length; i4 += 2) {
        const encodedByte = encoded.slice(i4, i4 + 2).toLowerCase();
        if (encodedByte in HEX_TO_SHORT) {
          out[i4 / 2] = HEX_TO_SHORT[encodedByte];
        } else {
          throw new Error(`Cannot decode unrecognized sequence ${encodedByte} as hexadecimal`);
        }
      }
      return out;
    }
    function toHex(bytes) {
      let out = "";
      for (let i4 = 0; i4 < bytes.byteLength; i4++) {
        out += SHORT_TO_HEX[bytes[i4]];
      }
      return out;
    }
    exports.fromHex = fromHex;
    exports.toHex = toHex;
  }
});

// node_modules/@smithy/util-stream/dist-cjs/sdk-stream-mixin.browser.js
var require_sdk_stream_mixin_browser = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/sdk-stream-mixin.browser.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sdkStreamMixin = void 0;
    var fetch_http_handler_1 = require_dist_cjs15();
    var util_base64_1 = require_dist_cjs11();
    var util_hex_encoding_1 = require_dist_cjs16();
    var util_utf8_1 = require_dist_cjs10();
    var stream_type_check_1 = require_stream_type_check();
    var ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED = "The stream has already been transformed.";
    var sdkStreamMixin2 = (stream) => {
      if (!isBlobInstance(stream) && !(0, stream_type_check_1.isReadableStream)(stream)) {
        const name = stream?.__proto__?.constructor?.name || stream;
        throw new Error(`Unexpected stream implementation, expect Blob or ReadableStream, got ${name}`);
      }
      let transformed = false;
      const transformToByteArray = async () => {
        if (transformed) {
          throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
        }
        transformed = true;
        return await (0, fetch_http_handler_1.streamCollector)(stream);
      };
      const blobToWebStream = (blob) => {
        if (typeof blob.stream !== "function") {
          throw new Error("Cannot transform payload Blob to web stream. Please make sure the Blob.stream() is polyfilled.\nIf you are using React Native, this API is not yet supported, see: https://react-native.canny.io/feature-requests/p/fetch-streaming-body");
        }
        return blob.stream();
      };
      return Object.assign(stream, {
        transformToByteArray,
        transformToString: async (encoding) => {
          const buf = await transformToByteArray();
          if (encoding === "base64") {
            return (0, util_base64_1.toBase64)(buf);
          } else if (encoding === "hex") {
            return (0, util_hex_encoding_1.toHex)(buf);
          } else if (encoding === void 0 || encoding === "utf8" || encoding === "utf-8") {
            return (0, util_utf8_1.toUtf8)(buf);
          } else if (typeof TextDecoder === "function") {
            return new TextDecoder(encoding).decode(buf);
          } else {
            throw new Error("TextDecoder is not available, please make sure polyfill is provided.");
          }
        },
        transformToWebStream: () => {
          if (transformed) {
            throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
          }
          transformed = true;
          if (isBlobInstance(stream)) {
            return blobToWebStream(stream);
          } else if ((0, stream_type_check_1.isReadableStream)(stream)) {
            return stream;
          } else {
            throw new Error(`Cannot transform payload to web stream, got ${stream}`);
          }
        }
      });
    };
    exports.sdkStreamMixin = sdkStreamMixin2;
    var isBlobInstance = (stream) => typeof Blob === "function" && stream instanceof Blob;
  }
});

// node_modules/@smithy/util-stream/dist-cjs/sdk-stream-mixin.js
var require_sdk_stream_mixin = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/sdk-stream-mixin.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.sdkStreamMixin = void 0;
    var node_http_handler_1 = require_dist_cjs14();
    var util_buffer_from_1 = require_dist_cjs9();
    var stream_1 = __require("stream");
    var sdk_stream_mixin_browser_1 = require_sdk_stream_mixin_browser();
    var ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED = "The stream has already been transformed.";
    var sdkStreamMixin2 = (stream) => {
      if (!(stream instanceof stream_1.Readable)) {
        try {
          return (0, sdk_stream_mixin_browser_1.sdkStreamMixin)(stream);
        } catch (e4) {
          const name = stream?.__proto__?.constructor?.name || stream;
          throw new Error(`Unexpected stream implementation, expect Stream.Readable instance, got ${name}`);
        }
      }
      let transformed = false;
      const transformToByteArray = async () => {
        if (transformed) {
          throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
        }
        transformed = true;
        return await (0, node_http_handler_1.streamCollector)(stream);
      };
      return Object.assign(stream, {
        transformToByteArray,
        transformToString: async (encoding) => {
          const buf = await transformToByteArray();
          if (encoding === void 0 || Buffer.isEncoding(encoding)) {
            return (0, util_buffer_from_1.fromArrayBuffer)(buf.buffer, buf.byteOffset, buf.byteLength).toString(encoding);
          } else {
            const decoder = new TextDecoder(encoding);
            return decoder.decode(buf);
          }
        },
        transformToWebStream: () => {
          if (transformed) {
            throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
          }
          if (stream.readableFlowing !== null) {
            throw new Error("The stream has been consumed by other callbacks.");
          }
          if (typeof stream_1.Readable.toWeb !== "function") {
            throw new Error("Readable.toWeb() is not supported. Please ensure a polyfill is available.");
          }
          transformed = true;
          return stream_1.Readable.toWeb(stream);
        }
      });
    };
    exports.sdkStreamMixin = sdkStreamMixin2;
  }
});

// node_modules/@smithy/util-stream/dist-cjs/splitStream.browser.js
var require_splitStream_browser = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/splitStream.browser.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.splitStream = splitStream;
    async function splitStream(stream) {
      if (typeof stream.stream === "function") {
        stream = stream.stream();
      }
      const readableStream = stream;
      return readableStream.tee();
    }
  }
});

// node_modules/@smithy/util-stream/dist-cjs/splitStream.js
var require_splitStream = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/splitStream.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.splitStream = splitStream;
    var stream_1 = __require("stream");
    var splitStream_browser_1 = require_splitStream_browser();
    var stream_type_check_1 = require_stream_type_check();
    async function splitStream(stream) {
      if ((0, stream_type_check_1.isReadableStream)(stream) || (0, stream_type_check_1.isBlob)(stream)) {
        return (0, splitStream_browser_1.splitStream)(stream);
      }
      const stream1 = new stream_1.PassThrough();
      const stream2 = new stream_1.PassThrough();
      stream.pipe(stream1);
      stream.pipe(stream2);
      return [stream1, stream2];
    }
  }
});

// node_modules/@smithy/util-stream/dist-cjs/index.js
var require_dist_cjs17 = __commonJS({
  "node_modules/@smithy/util-stream/dist-cjs/index.js"(exports) {
    "use strict";
    var utilBase64 = require_dist_cjs11();
    var utilUtf8 = require_dist_cjs10();
    var ChecksumStream = require_ChecksumStream();
    var createChecksumStream = require_createChecksumStream();
    var createBufferedReadable = require_createBufferedReadable();
    var getAwsChunkedEncodingStream = require_getAwsChunkedEncodingStream();
    var headStream = require_headStream();
    var sdkStreamMixin2 = require_sdk_stream_mixin();
    var splitStream = require_splitStream();
    var streamTypeCheck = require_stream_type_check();
    var Uint8ArrayBlobAdapter2 = class _Uint8ArrayBlobAdapter extends Uint8Array {
      static fromString(source, encoding = "utf-8") {
        if (typeof source === "string") {
          if (encoding === "base64") {
            return _Uint8ArrayBlobAdapter.mutate(utilBase64.fromBase64(source));
          }
          return _Uint8ArrayBlobAdapter.mutate(utilUtf8.fromUtf8(source));
        }
        throw new Error(`Unsupported conversion from ${typeof source} to Uint8ArrayBlobAdapter.`);
      }
      static mutate(source) {
        Object.setPrototypeOf(source, _Uint8ArrayBlobAdapter.prototype);
        return source;
      }
      transformToString(encoding = "utf-8") {
        if (encoding === "base64") {
          return utilBase64.toBase64(this);
        }
        return utilUtf8.toUtf8(this);
      }
    };
    exports.Uint8ArrayBlobAdapter = Uint8ArrayBlobAdapter2;
    Object.keys(ChecksumStream).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return ChecksumStream[k4];
        }
      });
    });
    Object.keys(createChecksumStream).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return createChecksumStream[k4];
        }
      });
    });
    Object.keys(createBufferedReadable).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return createBufferedReadable[k4];
        }
      });
    });
    Object.keys(getAwsChunkedEncodingStream).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return getAwsChunkedEncodingStream[k4];
        }
      });
    });
    Object.keys(headStream).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return headStream[k4];
        }
      });
    });
    Object.keys(sdkStreamMixin2).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return sdkStreamMixin2[k4];
        }
      });
    });
    Object.keys(splitStream).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return splitStream[k4];
        }
      });
    });
    Object.keys(streamTypeCheck).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return streamTypeCheck[k4];
        }
      });
    });
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/collect-stream-body.js
var import_util_stream, collectBody;
var init_collect_stream_body = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/collect-stream-body.js"() {
    import_util_stream = __toESM(require_dist_cjs17());
    collectBody = async (streamBody = new Uint8Array(), context) => {
      if (streamBody instanceof Uint8Array) {
        return import_util_stream.Uint8ArrayBlobAdapter.mutate(streamBody);
      }
      if (!streamBody) {
        return import_util_stream.Uint8ArrayBlobAdapter.mutate(new Uint8Array());
      }
      const fromContext = context.streamCollector(streamBody);
      return import_util_stream.Uint8ArrayBlobAdapter.mutate(await fromContext);
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/extended-encode-uri-component.js
function extendedEncodeURIComponent(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, function(c4) {
    return "%" + c4.charCodeAt(0).toString(16).toUpperCase();
  });
}
var init_extended_encode_uri_component = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/extended-encode-uri-component.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/deref.js
var deref;
var init_deref = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/deref.js"() {
    deref = (schemaRef) => {
      if (typeof schemaRef === "function") {
        return schemaRef();
      }
      return schemaRef;
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/operation.js
var operation;
var init_operation = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/operation.js"() {
    operation = (namespace, name, traits, input, output) => ({
      name,
      namespace,
      traits,
      input,
      output
    });
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaDeserializationMiddleware.js
var import_protocol_http2, import_util_middleware3, schemaDeserializationMiddleware, findHeader;
var init_schemaDeserializationMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaDeserializationMiddleware.js"() {
    import_protocol_http2 = __toESM(require_dist_cjs2());
    import_util_middleware3 = __toESM(require_dist_cjs6());
    init_operation();
    schemaDeserializationMiddleware = (config) => (next, context) => async (args) => {
      const { response } = await next(args);
      const { operationSchema } = (0, import_util_middleware3.getSmithyContext)(context);
      const [, ns, n4, t4, i4, o4] = operationSchema ?? [];
      try {
        const parsed = await config.protocol.deserializeResponse(operation(ns, n4, t4, i4, o4), {
          ...config,
          ...context
        }, response);
        return {
          response,
          output: parsed
        };
      } catch (error2) {
        Object.defineProperty(error2, "$response", {
          value: response,
          enumerable: false,
          writable: false,
          configurable: false
        });
        if (!("$metadata" in error2)) {
          const hint = `Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`;
          try {
            error2.message += "\n  " + hint;
          } catch (e4) {
            if (!context.logger || context.logger?.constructor?.name === "NoOpLogger") {
              console.warn(hint);
            } else {
              context.logger?.warn?.(hint);
            }
          }
          if (typeof error2.$responseBodyText !== "undefined") {
            if (error2.$response) {
              error2.$response.body = error2.$responseBodyText;
            }
          }
          try {
            if (import_protocol_http2.HttpResponse.isInstance(response)) {
              const { headers = {} } = response;
              const headerEntries = Object.entries(headers);
              error2.$metadata = {
                httpStatusCode: response.statusCode,
                requestId: findHeader(/^x-[\w-]+-request-?id$/, headerEntries),
                extendedRequestId: findHeader(/^x-[\w-]+-id-2$/, headerEntries),
                cfId: findHeader(/^x-[\w-]+-cf-id$/, headerEntries)
              };
            }
          } catch (e4) {
          }
        }
        throw error2;
      }
    };
    findHeader = (pattern, headers) => {
      return (headers.find(([k4]) => {
        return k4.match(pattern);
      }) || [void 0, void 0])[1];
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaSerializationMiddleware.js
var import_util_middleware4, schemaSerializationMiddleware;
var init_schemaSerializationMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaSerializationMiddleware.js"() {
    import_util_middleware4 = __toESM(require_dist_cjs6());
    init_operation();
    schemaSerializationMiddleware = (config) => (next, context) => async (args) => {
      const { operationSchema } = (0, import_util_middleware4.getSmithyContext)(context);
      const [, ns, n4, t4, i4, o4] = operationSchema ?? [];
      const endpoint = context.endpointV2?.url && config.urlParser ? async () => config.urlParser(context.endpointV2.url) : config.endpoint;
      const request = await config.protocol.serializeRequest(operation(ns, n4, t4, i4, o4), args.input, {
        ...config,
        ...context,
        endpoint
      });
      return next({
        ...args,
        request
      });
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/middleware/getSchemaSerdePlugin.js
function getSchemaSerdePlugin(config) {
  return {
    applyToStack: (commandStack) => {
      commandStack.add(schemaSerializationMiddleware(config), serializerMiddlewareOption2);
      commandStack.add(schemaDeserializationMiddleware(config), deserializerMiddlewareOption);
      config.protocol.setSerdeContext(config);
    }
  };
}
var deserializerMiddlewareOption, serializerMiddlewareOption2;
var init_getSchemaSerdePlugin = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/middleware/getSchemaSerdePlugin.js"() {
    init_schemaDeserializationMiddleware();
    init_schemaSerializationMiddleware();
    deserializerMiddlewareOption = {
      name: "deserializerMiddleware",
      step: "deserialize",
      tags: ["DESERIALIZER"],
      override: true
    };
    serializerMiddlewareOption2 = {
      name: "serializerMiddleware",
      step: "serialize",
      tags: ["SERIALIZER"],
      override: true
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/Schema.js
var Schema;
var init_Schema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/Schema.js"() {
    Schema = class {
      name;
      namespace;
      traits;
      static assign(instance, values) {
        const schema = Object.assign(instance, values);
        return schema;
      }
      static [Symbol.hasInstance](lhs) {
        const isPrototype = this.prototype.isPrototypeOf(lhs);
        if (!isPrototype && typeof lhs === "object" && lhs !== null) {
          const list2 = lhs;
          return list2.symbol === this.symbol;
        }
        return isPrototype;
      }
      getName() {
        return this.namespace + "#" + this.name;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/ListSchema.js
var ListSchema, list;
var init_ListSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/ListSchema.js"() {
    init_Schema();
    ListSchema = class _ListSchema extends Schema {
      static symbol = /* @__PURE__ */ Symbol.for("@smithy/lis");
      name;
      traits;
      valueSchema;
      symbol = _ListSchema.symbol;
    };
    list = (namespace, name, traits, valueSchema) => Schema.assign(new ListSchema(), {
      name,
      namespace,
      traits,
      valueSchema
    });
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/MapSchema.js
var MapSchema, map;
var init_MapSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/MapSchema.js"() {
    init_Schema();
    MapSchema = class _MapSchema extends Schema {
      static symbol = /* @__PURE__ */ Symbol.for("@smithy/map");
      name;
      traits;
      keySchema;
      valueSchema;
      symbol = _MapSchema.symbol;
    };
    map = (namespace, name, traits, keySchema, valueSchema) => Schema.assign(new MapSchema(), {
      name,
      namespace,
      traits,
      keySchema,
      valueSchema
    });
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/OperationSchema.js
var OperationSchema, op;
var init_OperationSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/OperationSchema.js"() {
    init_Schema();
    OperationSchema = class _OperationSchema extends Schema {
      static symbol = /* @__PURE__ */ Symbol.for("@smithy/ope");
      name;
      traits;
      input;
      output;
      symbol = _OperationSchema.symbol;
    };
    op = (namespace, name, traits, input, output) => Schema.assign(new OperationSchema(), {
      name,
      namespace,
      traits,
      input,
      output
    });
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/StructureSchema.js
var StructureSchema, struct;
var init_StructureSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/StructureSchema.js"() {
    init_Schema();
    StructureSchema = class _StructureSchema extends Schema {
      static symbol = /* @__PURE__ */ Symbol.for("@smithy/str");
      name;
      traits;
      memberNames;
      memberList;
      symbol = _StructureSchema.symbol;
    };
    struct = (namespace, name, traits, memberNames, memberList) => Schema.assign(new StructureSchema(), {
      name,
      namespace,
      traits,
      memberNames,
      memberList
    });
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/ErrorSchema.js
var ErrorSchema, error;
var init_ErrorSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/ErrorSchema.js"() {
    init_Schema();
    init_StructureSchema();
    ErrorSchema = class _ErrorSchema extends StructureSchema {
      static symbol = /* @__PURE__ */ Symbol.for("@smithy/err");
      ctor;
      symbol = _ErrorSchema.symbol;
    };
    error = (namespace, name, traits, memberNames, memberList, ctor) => Schema.assign(new ErrorSchema(), {
      name,
      namespace,
      traits,
      memberNames,
      memberList,
      ctor: null
    });
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/translateTraits.js
function translateTraits(indicator) {
  if (typeof indicator === "object") {
    return indicator;
  }
  indicator = indicator | 0;
  const traits = {};
  let i4 = 0;
  for (const trait of [
    "httpLabel",
    "idempotent",
    "idempotencyToken",
    "sensitive",
    "httpPayload",
    "httpResponseCode",
    "httpQueryParams"
  ]) {
    if ((indicator >> i4++ & 1) === 1) {
      traits[trait] = 1;
    }
  }
  return traits;
}
var init_translateTraits = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/translateTraits.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/NormalizedSchema.js
function member(memberSchema, memberName) {
  if (memberSchema instanceof NormalizedSchema) {
    return Object.assign(memberSchema, {
      memberName,
      _isMemberSchema: true
    });
  }
  const internalCtorAccess = NormalizedSchema;
  return new internalCtorAccess(memberSchema, memberName);
}
var NormalizedSchema, isMemberSchema, isStaticSchema;
var init_NormalizedSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/NormalizedSchema.js"() {
    init_deref();
    init_translateTraits();
    NormalizedSchema = class _NormalizedSchema {
      ref;
      memberName;
      static symbol = /* @__PURE__ */ Symbol.for("@smithy/nor");
      symbol = _NormalizedSchema.symbol;
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
          for (let i4 = traitStack.length - 1; i4 >= 0; --i4) {
            const traitSet = traitStack[i4];
            Object.assign(this.memberTraits, translateTraits(traitSet));
          }
        } else {
          this.memberTraits = 0;
        }
        if (schema instanceof _NormalizedSchema) {
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
        if (this._isMemberSchema && !memberName) {
          throw new Error(`@smithy/core/schema - NormalizedSchema member init ${this.getName(true)} missing member name.`);
        }
      }
      static [Symbol.hasInstance](lhs) {
        const isPrototype = this.prototype.isPrototypeOf(lhs);
        if (!isPrototype && typeof lhs === "object" && lhs !== null) {
          const ns = lhs;
          return ns.symbol === this.symbol;
        }
        return isPrototype;
      }
      static of(ref) {
        const sc = deref(ref);
        if (sc instanceof _NormalizedSchema) {
          return sc;
        }
        if (isMemberSchema(sc)) {
          const [ns, traits] = sc;
          if (ns instanceof _NormalizedSchema) {
            Object.assign(ns.getMergedTraits(), translateTraits(traits));
            return ns;
          }
          throw new Error(`@smithy/core/schema - may not init unwrapped member schema=${JSON.stringify(ref, null, 2)}.`);
        }
        return new _NormalizedSchema(sc);
      }
      getSchema() {
        const sc = this.schema;
        if (sc[0] === 0) {
          return sc[4];
        }
        return sc;
      }
      getName(withNamespace = false) {
        const { name } = this;
        const short = !withNamespace && name && name.includes("#");
        return short ? name.split("#")[1] : name || void 0;
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
        const sc = this.getSchema();
        const id = sc[0];
        return id === 3 || id === -3 || id === 4;
      }
      isUnionSchema() {
        const sc = this.getSchema();
        return sc[0] === 4;
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
        const match = (traits2) => (traits2 & 4) === 4 || !!traits2?.idempotencyToken;
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
        if (!isDoc && !isMap) {
          throw new Error(`@smithy/core/schema - cannot get key for non-map: ${this.getName(true)}`);
        }
        const schema = this.getSchema();
        const memberSchema = isDoc ? 15 : schema[4] ?? 0;
        return member([memberSchema, 0], "key");
      }
      getValueSchema() {
        const sc = this.getSchema();
        const [isDoc, isMap, isList] = [this.isDocumentSchema(), this.isMapSchema(), this.isListSchema()];
        const memberSchema = typeof sc === "number" ? 63 & sc : sc && typeof sc === "object" && (isMap || isList) ? sc[3 + sc[0]] : isDoc ? 15 : void 0;
        if (memberSchema != null) {
          return member([memberSchema, 0], isMap ? "value" : "member");
        }
        throw new Error(`@smithy/core/schema - ${this.getName(true)} has no value member.`);
      }
      getMemberSchema(memberName) {
        const struct2 = this.getSchema();
        if (this.isStructSchema() && struct2[4].includes(memberName)) {
          const i4 = struct2[4].indexOf(memberName);
          const memberSchema = struct2[5][i4];
          return member(isMemberSchema(memberSchema) ? memberSchema : [memberSchema, 0], memberName);
        }
        if (this.isDocumentSchema()) {
          return member([15, 0], memberName);
        }
        throw new Error(`@smithy/core/schema - ${this.getName(true)} has no no member=${memberName}.`);
      }
      getMemberSchemas() {
        const buffer = {};
        try {
          for (const [k4, v4] of this.structIterator()) {
            buffer[k4] = v4;
          }
        } catch (ignored) {
        }
        return buffer;
      }
      getEventStreamMember() {
        if (this.isStructSchema()) {
          for (const [memberName, memberSchema] of this.structIterator()) {
            if (memberSchema.isStreaming() && memberSchema.isStructSchema()) {
              return memberName;
            }
          }
        }
        return "";
      }
      *structIterator() {
        if (this.isUnitSchema()) {
          return;
        }
        if (!this.isStructSchema()) {
          throw new Error("@smithy/core/schema - cannot iterate non-struct schema.");
        }
        const struct2 = this.getSchema();
        for (let i4 = 0; i4 < struct2[4].length; ++i4) {
          yield [struct2[4][i4], member([struct2[5][i4], 0], struct2[4][i4])];
        }
      }
    };
    isMemberSchema = (sc) => Array.isArray(sc) && sc.length === 2;
    isStaticSchema = (sc) => Array.isArray(sc) && sc.length >= 5;
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/SimpleSchema.js
var SimpleSchema, sim, simAdapter;
var init_SimpleSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/SimpleSchema.js"() {
    init_Schema();
    SimpleSchema = class _SimpleSchema extends Schema {
      static symbol = /* @__PURE__ */ Symbol.for("@smithy/sim");
      name;
      schemaRef;
      traits;
      symbol = _SimpleSchema.symbol;
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
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/sentinels.js
var SCHEMA;
var init_sentinels = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/sentinels.js"() {
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
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/TypeRegistry.js
var TypeRegistry;
var init_TypeRegistry = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/TypeRegistry.js"() {
    TypeRegistry = class _TypeRegistry {
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
        if (!_TypeRegistry.registries.has(namespace)) {
          _TypeRegistry.registries.set(namespace, new _TypeRegistry(namespace));
        }
        return _TypeRegistry.registries.get(namespace);
      }
      register(shapeId, schema) {
        const qualifiedName = this.normalizeShapeId(shapeId);
        const registry = _TypeRegistry.for(qualifiedName.split("#")[0]);
        registry.schemas.set(qualifiedName, schema);
      }
      getSchema(shapeId) {
        const id = this.normalizeShapeId(shapeId);
        if (!this.schemas.has(id)) {
          throw new Error(`@smithy/core/schema - schema not found for ${id}`);
        }
        return this.schemas.get(id);
      }
      registerError(es, ctor) {
        const $error = es;
        const registry = _TypeRegistry.for($error[1]);
        registry.schemas.set($error[1] + "#" + $error[2], $error);
        registry.exceptions.set($error, ctor);
      }
      getErrorCtor(es) {
        const $error = es;
        const registry = _TypeRegistry.for($error[1]);
        return registry.exceptions.get($error);
      }
      getBaseException() {
        for (const exceptionKey of this.exceptions.keys()) {
          if (Array.isArray(exceptionKey)) {
            const [, ns, name] = exceptionKey;
            const id = ns + "#" + name;
            if (id.startsWith("smithy.ts.sdk.synthetic.") && id.endsWith("ServiceException")) {
              return exceptionKey;
            }
          }
        }
        return void 0;
      }
      find(predicate) {
        return [...this.schemas.values()].find(predicate);
      }
      clear() {
        this.schemas.clear();
        this.exceptions.clear();
      }
      normalizeShapeId(shapeId) {
        if (shapeId.includes("#")) {
          return shapeId;
        }
        return this.namespace + "#" + shapeId;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/index.js
var schema_exports = {};
__export(schema_exports, {
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
  serializerMiddlewareOption: () => serializerMiddlewareOption2,
  sim: () => sim,
  simAdapter: () => simAdapter,
  struct: () => struct,
  translateTraits: () => translateTraits
});
var init_schema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/index.js"() {
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
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/copyDocumentWithTransform.js
var copyDocumentWithTransform;
var init_copyDocumentWithTransform = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/copyDocumentWithTransform.js"() {
    copyDocumentWithTransform = (source, schemaRef, transform = (_) => _) => source;
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/parse-utils.js
var parseBoolean, expectBoolean, expectNumber, MAX_FLOAT, expectFloat32, expectLong, expectInt, expectInt32, expectShort, expectByte, expectSizedInt, castInt, expectNonNull, expectObject, expectString, expectUnion, strictParseDouble, strictParseFloat, strictParseFloat32, NUMBER_REGEX, parseNumber, limitedParseDouble, handleFloat, limitedParseFloat, limitedParseFloat32, parseFloatString, strictParseLong, strictParseInt, strictParseInt32, strictParseShort, strictParseByte, stackTraceWarning, logger;
var init_parse_utils = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/parse-utils.js"() {
    parseBoolean = (value) => {
      switch (value) {
        case "true":
          return true;
        case "false":
          return false;
        default:
          throw new Error(`Unable to parse boolean value "${value}"`);
      }
    };
    expectBoolean = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value === "number") {
        if (value === 0 || value === 1) {
          logger.warn(stackTraceWarning(`Expected boolean, got ${typeof value}: ${value}`));
        }
        if (value === 0) {
          return false;
        }
        if (value === 1) {
          return true;
        }
      }
      if (typeof value === "string") {
        const lower = value.toLowerCase();
        if (lower === "false" || lower === "true") {
          logger.warn(stackTraceWarning(`Expected boolean, got ${typeof value}: ${value}`));
        }
        if (lower === "false") {
          return false;
        }
        if (lower === "true") {
          return true;
        }
      }
      if (typeof value === "boolean") {
        return value;
      }
      throw new TypeError(`Expected boolean, got ${typeof value}: ${value}`);
    };
    expectNumber = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value === "string") {
        const parsed = parseFloat(value);
        if (!Number.isNaN(parsed)) {
          if (String(parsed) !== String(value)) {
            logger.warn(stackTraceWarning(`Expected number but observed string: ${value}`));
          }
          return parsed;
        }
      }
      if (typeof value === "number") {
        return value;
      }
      throw new TypeError(`Expected number, got ${typeof value}: ${value}`);
    };
    MAX_FLOAT = Math.ceil(2 ** 127 * (2 - 2 ** -23));
    expectFloat32 = (value) => {
      const expected = expectNumber(value);
      if (expected !== void 0 && !Number.isNaN(expected) && expected !== Infinity && expected !== -Infinity) {
        if (Math.abs(expected) > MAX_FLOAT) {
          throw new TypeError(`Expected 32-bit float, got ${value}`);
        }
      }
      return expected;
    };
    expectLong = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (Number.isInteger(value) && !Number.isNaN(value)) {
        return value;
      }
      throw new TypeError(`Expected integer, got ${typeof value}: ${value}`);
    };
    expectInt = expectLong;
    expectInt32 = (value) => expectSizedInt(value, 32);
    expectShort = (value) => expectSizedInt(value, 16);
    expectByte = (value) => expectSizedInt(value, 8);
    expectSizedInt = (value, size) => {
      const expected = expectLong(value);
      if (expected !== void 0 && castInt(expected, size) !== expected) {
        throw new TypeError(`Expected ${size}-bit integer, got ${value}`);
      }
      return expected;
    };
    castInt = (value, size) => {
      switch (size) {
        case 32:
          return Int32Array.of(value)[0];
        case 16:
          return Int16Array.of(value)[0];
        case 8:
          return Int8Array.of(value)[0];
      }
    };
    expectNonNull = (value, location) => {
      if (value === null || value === void 0) {
        if (location) {
          throw new TypeError(`Expected a non-null value for ${location}`);
        }
        throw new TypeError("Expected a non-null value");
      }
      return value;
    };
    expectObject = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value === "object" && !Array.isArray(value)) {
        return value;
      }
      const receivedType = Array.isArray(value) ? "array" : typeof value;
      throw new TypeError(`Expected object, got ${receivedType}: ${value}`);
    };
    expectString = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value === "string") {
        return value;
      }
      if (["boolean", "number", "bigint"].includes(typeof value)) {
        logger.warn(stackTraceWarning(`Expected string, got ${typeof value}: ${value}`));
        return String(value);
      }
      throw new TypeError(`Expected string, got ${typeof value}: ${value}`);
    };
    expectUnion = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      const asObject = expectObject(value);
      const setKeys = Object.entries(asObject).filter(([, v4]) => v4 != null).map(([k4]) => k4);
      if (setKeys.length === 0) {
        throw new TypeError(`Unions must have exactly one non-null member. None were found.`);
      }
      if (setKeys.length > 1) {
        throw new TypeError(`Unions must have exactly one non-null member. Keys ${setKeys} were not null.`);
      }
      return asObject;
    };
    strictParseDouble = (value) => {
      if (typeof value == "string") {
        return expectNumber(parseNumber(value));
      }
      return expectNumber(value);
    };
    strictParseFloat = strictParseDouble;
    strictParseFloat32 = (value) => {
      if (typeof value == "string") {
        return expectFloat32(parseNumber(value));
      }
      return expectFloat32(value);
    };
    NUMBER_REGEX = /(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|(-?Infinity)|(NaN)/g;
    parseNumber = (value) => {
      const matches = value.match(NUMBER_REGEX);
      if (matches === null || matches[0].length !== value.length) {
        throw new TypeError(`Expected real number, got implicit NaN`);
      }
      return parseFloat(value);
    };
    limitedParseDouble = (value) => {
      if (typeof value == "string") {
        return parseFloatString(value);
      }
      return expectNumber(value);
    };
    handleFloat = limitedParseDouble;
    limitedParseFloat = limitedParseDouble;
    limitedParseFloat32 = (value) => {
      if (typeof value == "string") {
        return parseFloatString(value);
      }
      return expectFloat32(value);
    };
    parseFloatString = (value) => {
      switch (value) {
        case "NaN":
          return NaN;
        case "Infinity":
          return Infinity;
        case "-Infinity":
          return -Infinity;
        default:
          throw new Error(`Unable to parse float value: ${value}`);
      }
    };
    strictParseLong = (value) => {
      if (typeof value === "string") {
        return expectLong(parseNumber(value));
      }
      return expectLong(value);
    };
    strictParseInt = strictParseLong;
    strictParseInt32 = (value) => {
      if (typeof value === "string") {
        return expectInt32(parseNumber(value));
      }
      return expectInt32(value);
    };
    strictParseShort = (value) => {
      if (typeof value === "string") {
        return expectShort(parseNumber(value));
      }
      return expectShort(value);
    };
    strictParseByte = (value) => {
      if (typeof value === "string") {
        return expectByte(parseNumber(value));
      }
      return expectByte(value);
    };
    stackTraceWarning = (message) => {
      return String(new TypeError(message).stack || message).split("\n").slice(0, 5).filter((s4) => !s4.includes("stackTraceWarning")).join("\n");
    };
    logger = {
      warn: console.warn
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/date-utils.js
function dateToUtcString(date2) {
  const year2 = date2.getUTCFullYear();
  const month = date2.getUTCMonth();
  const dayOfWeek = date2.getUTCDay();
  const dayOfMonthInt = date2.getUTCDate();
  const hoursInt = date2.getUTCHours();
  const minutesInt = date2.getUTCMinutes();
  const secondsInt = date2.getUTCSeconds();
  const dayOfMonthString = dayOfMonthInt < 10 ? `0${dayOfMonthInt}` : `${dayOfMonthInt}`;
  const hoursString = hoursInt < 10 ? `0${hoursInt}` : `${hoursInt}`;
  const minutesString = minutesInt < 10 ? `0${minutesInt}` : `${minutesInt}`;
  const secondsString = secondsInt < 10 ? `0${secondsInt}` : `${secondsInt}`;
  return `${DAYS[dayOfWeek]}, ${dayOfMonthString} ${MONTHS[month]} ${year2} ${hoursString}:${minutesString}:${secondsString} GMT`;
}
var DAYS, MONTHS, RFC3339, parseRfc3339DateTime, RFC3339_WITH_OFFSET, parseRfc3339DateTimeWithOffset, IMF_FIXDATE, RFC_850_DATE, ASC_TIME, parseRfc7231DateTime, parseEpochTimestamp, buildDate, parseTwoDigitYear, FIFTY_YEARS_IN_MILLIS, adjustRfc850Year, parseMonthByShortName, DAYS_IN_MONTH, validateDayOfMonth, isLeapYear, parseDateValue, parseMilliseconds, parseOffsetToMilliseconds, stripLeadingZeroes;
var init_date_utils = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/date-utils.js"() {
    init_parse_utils();
    DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    RFC3339 = new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?[zZ]$/);
    parseRfc3339DateTime = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC-3339 date-times must be expressed as strings");
      }
      const match = RFC3339.exec(value);
      if (!match) {
        throw new TypeError("Invalid RFC-3339 date-time value");
      }
      const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds] = match;
      const year2 = strictParseShort(stripLeadingZeroes(yearStr));
      const month = parseDateValue(monthStr, "month", 1, 12);
      const day = parseDateValue(dayStr, "day", 1, 31);
      return buildDate(year2, month, day, { hours, minutes, seconds, fractionalMilliseconds });
    };
    RFC3339_WITH_OFFSET = new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(([-+]\d{2}\:\d{2})|[zZ])$/);
    parseRfc3339DateTimeWithOffset = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC-3339 date-times must be expressed as strings");
      }
      const match = RFC3339_WITH_OFFSET.exec(value);
      if (!match) {
        throw new TypeError("Invalid RFC-3339 date-time value");
      }
      const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, offsetStr] = match;
      const year2 = strictParseShort(stripLeadingZeroes(yearStr));
      const month = parseDateValue(monthStr, "month", 1, 12);
      const day = parseDateValue(dayStr, "day", 1, 31);
      const date2 = buildDate(year2, month, day, { hours, minutes, seconds, fractionalMilliseconds });
      if (offsetStr.toUpperCase() != "Z") {
        date2.setTime(date2.getTime() - parseOffsetToMilliseconds(offsetStr));
      }
      return date2;
    };
    IMF_FIXDATE = new RegExp(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/);
    RFC_850_DATE = new RegExp(/^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/);
    ASC_TIME = new RegExp(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( [1-9]|\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? (\d{4})$/);
    parseRfc7231DateTime = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC-7231 date-times must be expressed as strings");
      }
      let match = IMF_FIXDATE.exec(value);
      if (match) {
        const [_, dayStr, monthStr, yearStr, hours, minutes, seconds, fractionalMilliseconds] = match;
        return buildDate(strictParseShort(stripLeadingZeroes(yearStr)), parseMonthByShortName(monthStr), parseDateValue(dayStr, "day", 1, 31), { hours, minutes, seconds, fractionalMilliseconds });
      }
      match = RFC_850_DATE.exec(value);
      if (match) {
        const [_, dayStr, monthStr, yearStr, hours, minutes, seconds, fractionalMilliseconds] = match;
        return adjustRfc850Year(buildDate(parseTwoDigitYear(yearStr), parseMonthByShortName(monthStr), parseDateValue(dayStr, "day", 1, 31), {
          hours,
          minutes,
          seconds,
          fractionalMilliseconds
        }));
      }
      match = ASC_TIME.exec(value);
      if (match) {
        const [_, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, yearStr] = match;
        return buildDate(strictParseShort(stripLeadingZeroes(yearStr)), parseMonthByShortName(monthStr), parseDateValue(dayStr.trimLeft(), "day", 1, 31), { hours, minutes, seconds, fractionalMilliseconds });
      }
      throw new TypeError("Invalid RFC-7231 date-time value");
    };
    parseEpochTimestamp = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      let valueAsDouble;
      if (typeof value === "number") {
        valueAsDouble = value;
      } else if (typeof value === "string") {
        valueAsDouble = strictParseDouble(value);
      } else if (typeof value === "object" && value.tag === 1) {
        valueAsDouble = value.value;
      } else {
        throw new TypeError("Epoch timestamps must be expressed as floating point numbers or their string representation");
      }
      if (Number.isNaN(valueAsDouble) || valueAsDouble === Infinity || valueAsDouble === -Infinity) {
        throw new TypeError("Epoch timestamps must be valid, non-Infinite, non-NaN numerics");
      }
      return new Date(Math.round(valueAsDouble * 1e3));
    };
    buildDate = (year2, month, day, time2) => {
      const adjustedMonth = month - 1;
      validateDayOfMonth(year2, adjustedMonth, day);
      return new Date(Date.UTC(year2, adjustedMonth, day, parseDateValue(time2.hours, "hour", 0, 23), parseDateValue(time2.minutes, "minute", 0, 59), parseDateValue(time2.seconds, "seconds", 0, 60), parseMilliseconds(time2.fractionalMilliseconds)));
    };
    parseTwoDigitYear = (value) => {
      const thisYear = (/* @__PURE__ */ new Date()).getUTCFullYear();
      const valueInThisCentury = Math.floor(thisYear / 100) * 100 + strictParseShort(stripLeadingZeroes(value));
      if (valueInThisCentury < thisYear) {
        return valueInThisCentury + 100;
      }
      return valueInThisCentury;
    };
    FIFTY_YEARS_IN_MILLIS = 50 * 365 * 24 * 60 * 60 * 1e3;
    adjustRfc850Year = (input) => {
      if (input.getTime() - (/* @__PURE__ */ new Date()).getTime() > FIFTY_YEARS_IN_MILLIS) {
        return new Date(Date.UTC(input.getUTCFullYear() - 100, input.getUTCMonth(), input.getUTCDate(), input.getUTCHours(), input.getUTCMinutes(), input.getUTCSeconds(), input.getUTCMilliseconds()));
      }
      return input;
    };
    parseMonthByShortName = (value) => {
      const monthIdx = MONTHS.indexOf(value);
      if (monthIdx < 0) {
        throw new TypeError(`Invalid month: ${value}`);
      }
      return monthIdx + 1;
    };
    DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    validateDayOfMonth = (year2, month, day) => {
      let maxDays = DAYS_IN_MONTH[month];
      if (month === 1 && isLeapYear(year2)) {
        maxDays = 29;
      }
      if (day > maxDays) {
        throw new TypeError(`Invalid day for ${MONTHS[month]} in ${year2}: ${day}`);
      }
    };
    isLeapYear = (year2) => {
      return year2 % 4 === 0 && (year2 % 100 !== 0 || year2 % 400 === 0);
    };
    parseDateValue = (value, type, lower, upper) => {
      const dateVal = strictParseByte(stripLeadingZeroes(value));
      if (dateVal < lower || dateVal > upper) {
        throw new TypeError(`${type} must be between ${lower} and ${upper}, inclusive`);
      }
      return dateVal;
    };
    parseMilliseconds = (value) => {
      if (value === null || value === void 0) {
        return 0;
      }
      return strictParseFloat32("0." + value) * 1e3;
    };
    parseOffsetToMilliseconds = (value) => {
      const directionStr = value[0];
      let direction = 1;
      if (directionStr == "+") {
        direction = 1;
      } else if (directionStr == "-") {
        direction = -1;
      } else {
        throw new TypeError(`Offset direction, ${directionStr}, must be "+" or "-"`);
      }
      const hour = Number(value.substring(1, 3));
      const minute = Number(value.substring(4, 6));
      return direction * (hour * 60 + minute) * 60 * 1e3;
    };
    stripLeadingZeroes = (value) => {
      let idx = 0;
      while (idx < value.length - 1 && value.charAt(idx) === "0") {
        idx++;
      }
      if (idx === 0) {
        return value;
      }
      return value.slice(idx);
    };
  }
});

// node_modules/tslib/tslib.es6.mjs
var tslib_es6_exports = {};
__export(tslib_es6_exports, {
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
function __extends(d4, b4) {
  if (typeof b4 !== "function" && b4 !== null)
    throw new TypeError("Class extends value " + String(b4) + " is not a constructor or null");
  extendStatics(d4, b4);
  function __() {
    this.constructor = d4;
  }
  d4.prototype = b4 === null ? Object.create(b4) : (__.prototype = b4.prototype, new __());
}
function __rest(s4, e4) {
  var t4 = {};
  for (var p4 in s4) if (Object.prototype.hasOwnProperty.call(s4, p4) && e4.indexOf(p4) < 0)
    t4[p4] = s4[p4];
  if (s4 != null && typeof Object.getOwnPropertySymbols === "function")
    for (var i4 = 0, p4 = Object.getOwnPropertySymbols(s4); i4 < p4.length; i4++) {
      if (e4.indexOf(p4[i4]) < 0 && Object.prototype.propertyIsEnumerable.call(s4, p4[i4]))
        t4[p4[i4]] = s4[p4[i4]];
    }
  return t4;
}
function __decorate(decorators, target, key, desc) {
  var c4 = arguments.length, r4 = c4 < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d4;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r4 = Reflect.decorate(decorators, target, key, desc);
  else for (var i4 = decorators.length - 1; i4 >= 0; i4--) if (d4 = decorators[i4]) r4 = (c4 < 3 ? d4(r4) : c4 > 3 ? d4(target, key, r4) : d4(target, key)) || r4;
  return c4 > 3 && r4 && Object.defineProperty(target, key, r4), r4;
}
function __param(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
function __esDecorate(ctor, descriptorIn, decorators, contextIn, initializers, extraInitializers) {
  function accept(f4) {
    if (f4 !== void 0 && typeof f4 !== "function") throw new TypeError("Function expected");
    return f4;
  }
  var kind = contextIn.kind, key = kind === "getter" ? "get" : kind === "setter" ? "set" : "value";
  var target = !descriptorIn && ctor ? contextIn["static"] ? ctor : ctor.prototype : null;
  var descriptor = descriptorIn || (target ? Object.getOwnPropertyDescriptor(target, contextIn.name) : {});
  var _, done = false;
  for (var i4 = decorators.length - 1; i4 >= 0; i4--) {
    var context = {};
    for (var p4 in contextIn) context[p4] = p4 === "access" ? {} : contextIn[p4];
    for (var p4 in contextIn.access) context.access[p4] = contextIn.access[p4];
    context.addInitializer = function(f4) {
      if (done) throw new TypeError("Cannot add initializers after decoration has completed");
      extraInitializers.push(accept(f4 || null));
    };
    var result = (0, decorators[i4])(kind === "accessor" ? { get: descriptor.get, set: descriptor.set } : descriptor[key], context);
    if (kind === "accessor") {
      if (result === void 0) continue;
      if (result === null || typeof result !== "object") throw new TypeError("Object expected");
      if (_ = accept(result.get)) descriptor.get = _;
      if (_ = accept(result.set)) descriptor.set = _;
      if (_ = accept(result.init)) initializers.unshift(_);
    } else if (_ = accept(result)) {
      if (kind === "field") initializers.unshift(_);
      else descriptor[key] = _;
    }
  }
  if (target) Object.defineProperty(target, contextIn.name, descriptor);
  done = true;
}
function __runInitializers(thisArg, initializers, value) {
  var useValue = arguments.length > 2;
  for (var i4 = 0; i4 < initializers.length; i4++) {
    value = useValue ? initializers[i4].call(thisArg, value) : initializers[i4].call(thisArg);
  }
  return useValue ? value : void 0;
}
function __propKey(x4) {
  return typeof x4 === "symbol" ? x4 : "".concat(x4);
}
function __setFunctionName(f4, name, prefix) {
  if (typeof name === "symbol") name = name.description ? "[".concat(name.description, "]") : "";
  return Object.defineProperty(f4, "name", { configurable: true, value: prefix ? "".concat(prefix, " ", name) : name });
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
      } catch (e4) {
        reject(e4);
      }
    }
    function rejected(value) {
      try {
        step(generator["throw"](value));
      } catch (e4) {
        reject(e4);
      }
    }
    function step(result) {
      result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
    }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
}
function __generator(thisArg, body) {
  var _ = { label: 0, sent: function() {
    if (t4[0] & 1) throw t4[1];
    return t4[1];
  }, trys: [], ops: [] }, f4, y2, t4, g4 = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
  return g4.next = verb(0), g4["throw"] = verb(1), g4["return"] = verb(2), typeof Symbol === "function" && (g4[Symbol.iterator] = function() {
    return this;
  }), g4;
  function verb(n4) {
    return function(v4) {
      return step([n4, v4]);
    };
  }
  function step(op2) {
    if (f4) throw new TypeError("Generator is already executing.");
    while (g4 && (g4 = 0, op2[0] && (_ = 0)), _) try {
      if (f4 = 1, y2 && (t4 = op2[0] & 2 ? y2["return"] : op2[0] ? y2["throw"] || ((t4 = y2["return"]) && t4.call(y2), 0) : y2.next) && !(t4 = t4.call(y2, op2[1])).done) return t4;
      if (y2 = 0, t4) op2 = [op2[0] & 2, t4.value];
      switch (op2[0]) {
        case 0:
        case 1:
          t4 = op2;
          break;
        case 4:
          _.label++;
          return { value: op2[1], done: false };
        case 5:
          _.label++;
          y2 = op2[1];
          op2 = [0];
          continue;
        case 7:
          op2 = _.ops.pop();
          _.trys.pop();
          continue;
        default:
          if (!(t4 = _.trys, t4 = t4.length > 0 && t4[t4.length - 1]) && (op2[0] === 6 || op2[0] === 2)) {
            _ = 0;
            continue;
          }
          if (op2[0] === 3 && (!t4 || op2[1] > t4[0] && op2[1] < t4[3])) {
            _.label = op2[1];
            break;
          }
          if (op2[0] === 6 && _.label < t4[1]) {
            _.label = t4[1];
            t4 = op2;
            break;
          }
          if (t4 && _.label < t4[2]) {
            _.label = t4[2];
            _.ops.push(op2);
            break;
          }
          if (t4[2]) _.ops.pop();
          _.trys.pop();
          continue;
      }
      op2 = body.call(thisArg, _);
    } catch (e4) {
      op2 = [6, e4];
      y2 = 0;
    } finally {
      f4 = t4 = 0;
    }
    if (op2[0] & 5) throw op2[1];
    return { value: op2[0] ? op2[1] : void 0, done: true };
  }
}
function __exportStar(m4, o4) {
  for (var p4 in m4) if (p4 !== "default" && !Object.prototype.hasOwnProperty.call(o4, p4)) __createBinding(o4, m4, p4);
}
function __values(o4) {
  var s4 = typeof Symbol === "function" && Symbol.iterator, m4 = s4 && o4[s4], i4 = 0;
  if (m4) return m4.call(o4);
  if (o4 && typeof o4.length === "number") return {
    next: function() {
      if (o4 && i4 >= o4.length) o4 = void 0;
      return { value: o4 && o4[i4++], done: !o4 };
    }
  };
  throw new TypeError(s4 ? "Object is not iterable." : "Symbol.iterator is not defined.");
}
function __read(o4, n4) {
  var m4 = typeof Symbol === "function" && o4[Symbol.iterator];
  if (!m4) return o4;
  var i4 = m4.call(o4), r4, ar = [], e4;
  try {
    while ((n4 === void 0 || n4-- > 0) && !(r4 = i4.next()).done) ar.push(r4.value);
  } catch (error2) {
    e4 = { error: error2 };
  } finally {
    try {
      if (r4 && !r4.done && (m4 = i4["return"])) m4.call(i4);
    } finally {
      if (e4) throw e4.error;
    }
  }
  return ar;
}
function __spread() {
  for (var ar = [], i4 = 0; i4 < arguments.length; i4++)
    ar = ar.concat(__read(arguments[i4]));
  return ar;
}
function __spreadArrays() {
  for (var s4 = 0, i4 = 0, il = arguments.length; i4 < il; i4++) s4 += arguments[i4].length;
  for (var r4 = Array(s4), k4 = 0, i4 = 0; i4 < il; i4++)
    for (var a4 = arguments[i4], j4 = 0, jl = a4.length; j4 < jl; j4++, k4++)
      r4[k4] = a4[j4];
  return r4;
}
function __spreadArray(to, from, pack) {
  if (pack || arguments.length === 2) for (var i4 = 0, l4 = from.length, ar; i4 < l4; i4++) {
    if (ar || !(i4 in from)) {
      if (!ar) ar = Array.prototype.slice.call(from, 0, i4);
      ar[i4] = from[i4];
    }
  }
  return to.concat(ar || Array.prototype.slice.call(from));
}
function __await(v4) {
  return this instanceof __await ? (this.v = v4, this) : new __await(v4);
}
function __asyncGenerator(thisArg, _arguments, generator) {
  if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
  var g4 = generator.apply(thisArg, _arguments || []), i4, q4 = [];
  return i4 = Object.create((typeof AsyncIterator === "function" ? AsyncIterator : Object).prototype), verb("next"), verb("throw"), verb("return", awaitReturn), i4[Symbol.asyncIterator] = function() {
    return this;
  }, i4;
  function awaitReturn(f4) {
    return function(v4) {
      return Promise.resolve(v4).then(f4, reject);
    };
  }
  function verb(n4, f4) {
    if (g4[n4]) {
      i4[n4] = function(v4) {
        return new Promise(function(a4, b4) {
          q4.push([n4, v4, a4, b4]) > 1 || resume(n4, v4);
        });
      };
      if (f4) i4[n4] = f4(i4[n4]);
    }
  }
  function resume(n4, v4) {
    try {
      step(g4[n4](v4));
    } catch (e4) {
      settle(q4[0][3], e4);
    }
  }
  function step(r4) {
    r4.value instanceof __await ? Promise.resolve(r4.value.v).then(fulfill, reject) : settle(q4[0][2], r4);
  }
  function fulfill(value) {
    resume("next", value);
  }
  function reject(value) {
    resume("throw", value);
  }
  function settle(f4, v4) {
    if (f4(v4), q4.shift(), q4.length) resume(q4[0][0], q4[0][1]);
  }
}
function __asyncDelegator(o4) {
  var i4, p4;
  return i4 = {}, verb("next"), verb("throw", function(e4) {
    throw e4;
  }), verb("return"), i4[Symbol.iterator] = function() {
    return this;
  }, i4;
  function verb(n4, f4) {
    i4[n4] = o4[n4] ? function(v4) {
      return (p4 = !p4) ? { value: __await(o4[n4](v4)), done: false } : f4 ? f4(v4) : v4;
    } : f4;
  }
}
function __asyncValues(o4) {
  if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
  var m4 = o4[Symbol.asyncIterator], i4;
  return m4 ? m4.call(o4) : (o4 = typeof __values === "function" ? __values(o4) : o4[Symbol.iterator](), i4 = {}, verb("next"), verb("throw"), verb("return"), i4[Symbol.asyncIterator] = function() {
    return this;
  }, i4);
  function verb(n4) {
    i4[n4] = o4[n4] && function(v4) {
      return new Promise(function(resolve, reject) {
        v4 = o4[n4](v4), settle(resolve, reject, v4.done, v4.value);
      });
    };
  }
  function settle(resolve, reject, d4, v4) {
    Promise.resolve(v4).then(function(v5) {
      resolve({ value: v5, done: d4 });
    }, reject);
  }
}
function __makeTemplateObject(cooked, raw) {
  if (Object.defineProperty) {
    Object.defineProperty(cooked, "raw", { value: raw });
  } else {
    cooked.raw = raw;
  }
  return cooked;
}
function __importStar(mod) {
  if (mod && mod.__esModule) return mod;
  var result = {};
  if (mod != null) {
    for (var k4 = ownKeys(mod), i4 = 0; i4 < k4.length; i4++) if (k4[i4] !== "default") __createBinding(result, mod, k4[i4]);
  }
  __setModuleDefault(result, mod);
  return result;
}
function __importDefault(mod) {
  return mod && mod.__esModule ? mod : { default: mod };
}
function __classPrivateFieldGet(receiver, state2, kind, f4) {
  if (kind === "a" && !f4) throw new TypeError("Private accessor was defined without a getter");
  if (typeof state2 === "function" ? receiver !== state2 || !f4 : !state2.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return kind === "m" ? f4 : kind === "a" ? f4.call(receiver) : f4 ? f4.value : state2.get(receiver);
}
function __classPrivateFieldSet(receiver, state2, value, kind, f4) {
  if (kind === "m") throw new TypeError("Private method is not writable");
  if (kind === "a" && !f4) throw new TypeError("Private accessor was defined without a setter");
  if (typeof state2 === "function" ? receiver !== state2 || !f4 : !state2.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return kind === "a" ? f4.call(receiver, value) : f4 ? f4.value = value : state2.set(receiver, value), value;
}
function __classPrivateFieldIn(state2, receiver) {
  if (receiver === null || typeof receiver !== "object" && typeof receiver !== "function") throw new TypeError("Cannot use 'in' operator on non-object");
  return typeof state2 === "function" ? receiver === state2 : state2.has(receiver);
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
      } catch (e4) {
        return Promise.reject(e4);
      }
    };
    env.stack.push({ value, dispose, async });
  } else if (async) {
    env.stack.push({ async: true });
  }
  return value;
}
function __disposeResources(env) {
  function fail(e4) {
    env.error = env.hasError ? new _SuppressedError(e4, env.error, "An error was suppressed during disposal.") : e4;
    env.hasError = true;
  }
  var r4, s4 = 0;
  function next() {
    while (r4 = env.stack.pop()) {
      try {
        if (!r4.async && s4 === 1) return s4 = 0, env.stack.push(r4), Promise.resolve().then(next);
        if (r4.dispose) {
          var result = r4.dispose.call(r4.value);
          if (r4.async) return s4 |= 2, Promise.resolve(result).then(next, function(e4) {
            fail(e4);
            return next();
          });
        } else s4 |= 1;
      } catch (e4) {
        fail(e4);
      }
    }
    if (s4 === 1) return env.hasError ? Promise.reject(env.error) : Promise.resolve();
    if (env.hasError) throw env.error;
  }
  return next();
}
function __rewriteRelativeImportExtension(path, preserveJsx) {
  if (typeof path === "string" && /^\.\.?\//.test(path)) {
    return path.replace(/\.(tsx)$|((?:\.d)?)((?:\.[^./]+?)?)\.([cm]?)ts$/i, function(m4, tsx, d4, ext, cm) {
      return tsx ? preserveJsx ? ".jsx" : ".js" : d4 && (!ext || !cm) ? m4 : d4 + ext + "." + cm.toLowerCase() + "js";
    });
  }
  return path;
}
var extendStatics, __assign, __createBinding, __setModuleDefault, ownKeys, _SuppressedError, tslib_es6_default;
var init_tslib_es6 = __esm({
  "node_modules/tslib/tslib.es6.mjs"() {
    extendStatics = function(d4, b4) {
      extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d5, b5) {
        d5.__proto__ = b5;
      } || function(d5, b5) {
        for (var p4 in b5) if (Object.prototype.hasOwnProperty.call(b5, p4)) d5[p4] = b5[p4];
      };
      return extendStatics(d4, b4);
    };
    __assign = function() {
      __assign = Object.assign || function __assign2(t4) {
        for (var s4, i4 = 1, n4 = arguments.length; i4 < n4; i4++) {
          s4 = arguments[i4];
          for (var p4 in s4) if (Object.prototype.hasOwnProperty.call(s4, p4)) t4[p4] = s4[p4];
        }
        return t4;
      };
      return __assign.apply(this, arguments);
    };
    __createBinding = Object.create ? (function(o4, m4, k4, k22) {
      if (k22 === void 0) k22 = k4;
      var desc = Object.getOwnPropertyDescriptor(m4, k4);
      if (!desc || ("get" in desc ? !m4.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m4[k4];
        } };
      }
      Object.defineProperty(o4, k22, desc);
    }) : (function(o4, m4, k4, k22) {
      if (k22 === void 0) k22 = k4;
      o4[k22] = m4[k4];
    });
    __setModuleDefault = Object.create ? (function(o4, v4) {
      Object.defineProperty(o4, "default", { enumerable: true, value: v4 });
    }) : function(o4, v4) {
      o4["default"] = v4;
    };
    ownKeys = function(o4) {
      ownKeys = Object.getOwnPropertyNames || function(o5) {
        var ar = [];
        for (var k4 in o5) if (Object.prototype.hasOwnProperty.call(o5, k4)) ar[ar.length] = k4;
        return ar;
      };
      return ownKeys(o4);
    };
    _SuppressedError = typeof SuppressedError === "function" ? SuppressedError : function(error2, suppressed, message) {
      var e4 = new Error(message);
      return e4.name = "SuppressedError", e4.error = error2, e4.suppressed = suppressed, e4;
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
  }
});

// node_modules/@smithy/uuid/dist-cjs/randomUUID.js
var require_randomUUID = __commonJS({
  "node_modules/@smithy/uuid/dist-cjs/randomUUID.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.randomUUID = void 0;
    var tslib_1 = (init_tslib_es6(), __toCommonJS(tslib_es6_exports));
    var crypto_1 = tslib_1.__importDefault(__require("crypto"));
    exports.randomUUID = crypto_1.default.randomUUID.bind(crypto_1.default);
  }
});

// node_modules/@smithy/uuid/dist-cjs/index.js
var require_dist_cjs18 = __commonJS({
  "node_modules/@smithy/uuid/dist-cjs/index.js"(exports) {
    "use strict";
    var randomUUID = require_randomUUID();
    var decimalToHex = Array.from({ length: 256 }, (_, i4) => i4.toString(16).padStart(2, "0"));
    var v4 = () => {
      if (randomUUID.randomUUID) {
        return randomUUID.randomUUID();
      }
      const rnds = new Uint8Array(16);
      crypto.getRandomValues(rnds);
      rnds[6] = rnds[6] & 15 | 64;
      rnds[8] = rnds[8] & 63 | 128;
      return decimalToHex[rnds[0]] + decimalToHex[rnds[1]] + decimalToHex[rnds[2]] + decimalToHex[rnds[3]] + "-" + decimalToHex[rnds[4]] + decimalToHex[rnds[5]] + "-" + decimalToHex[rnds[6]] + decimalToHex[rnds[7]] + "-" + decimalToHex[rnds[8]] + decimalToHex[rnds[9]] + "-" + decimalToHex[rnds[10]] + decimalToHex[rnds[11]] + decimalToHex[rnds[12]] + decimalToHex[rnds[13]] + decimalToHex[rnds[14]] + decimalToHex[rnds[15]];
    };
    exports.v4 = v4;
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/generateIdempotencyToken.js
var import_uuid;
var init_generateIdempotencyToken = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/generateIdempotencyToken.js"() {
    import_uuid = __toESM(require_dist_cjs18());
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/lazy-json.js
var LazyJsonString;
var init_lazy_json = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/lazy-json.js"() {
    LazyJsonString = function LazyJsonString2(val) {
      const str = Object.assign(new String(val), {
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
      return str;
    };
    LazyJsonString.from = (object) => {
      if (object && typeof object === "object" && (object instanceof LazyJsonString || "deserializeJSON" in object)) {
        return object;
      } else if (typeof object === "string" || Object.getPrototypeOf(object) === String.prototype) {
        return LazyJsonString(String(object));
      }
      return LazyJsonString(JSON.stringify(object));
    };
    LazyJsonString.fromObject = LazyJsonString.from;
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/quote-header.js
function quoteHeader(part) {
  if (part.includes(",") || part.includes('"')) {
    part = `"${part.replace(/"/g, '\\"')}"`;
  }
  return part;
}
var init_quote_header = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/quote-header.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/schema-serde-lib/schema-date-utils.js
function range(v4, min, max) {
  const _v = Number(v4);
  if (_v < min || _v > max) {
    throw new Error(`Value ${_v} out of range [${min}, ${max}]`);
  }
}
var ddd, mmm, time, date, year, RFC3339_WITH_OFFSET2, IMF_FIXDATE2, RFC_850_DATE2, ASC_TIME2, months, _parseEpochTimestamp, _parseRfc3339DateTimeWithOffset, _parseRfc7231DateTime;
var init_schema_date_utils = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/schema-serde-lib/schema-date-utils.js"() {
    ddd = `(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)(?:[ne|u?r]?s?day)?`;
    mmm = `(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`;
    time = `(\\d?\\d):(\\d{2}):(\\d{2})(?:\\.(\\d+))?`;
    date = `(\\d?\\d)`;
    year = `(\\d{4})`;
    RFC3339_WITH_OFFSET2 = new RegExp(/^(\d{4})-(\d\d)-(\d\d)[tT](\d\d):(\d\d):(\d\d)(\.(\d+))?(([-+]\d\d:\d\d)|[zZ])$/);
    IMF_FIXDATE2 = new RegExp(`^${ddd}, ${date} ${mmm} ${year} ${time} GMT$`);
    RFC_850_DATE2 = new RegExp(`^${ddd}, ${date}-${mmm}-(\\d\\d) ${time} GMT$`);
    ASC_TIME2 = new RegExp(`^${ddd} ${mmm} ( [1-9]|\\d\\d) ${time} ${year}$`);
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    _parseEpochTimestamp = (value) => {
      if (value == null) {
        return void 0;
      }
      let num = NaN;
      if (typeof value === "number") {
        num = value;
      } else if (typeof value === "string") {
        if (!/^-?\d*\.?\d+$/.test(value)) {
          throw new TypeError(`parseEpochTimestamp - numeric string invalid.`);
        }
        num = Number.parseFloat(value);
      } else if (typeof value === "object" && value.tag === 1) {
        num = value.value;
      }
      if (isNaN(num) || Math.abs(num) === Infinity) {
        throw new TypeError("Epoch timestamps must be valid finite numbers.");
      }
      return new Date(Math.round(num * 1e3));
    };
    _parseRfc3339DateTimeWithOffset = (value) => {
      if (value == null) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC3339 timestamps must be strings");
      }
      const matches = RFC3339_WITH_OFFSET2.exec(value);
      if (!matches) {
        throw new TypeError(`Invalid RFC3339 timestamp format ${value}`);
      }
      const [, yearStr, monthStr, dayStr, hours, minutes, seconds, , ms, offsetStr] = matches;
      range(monthStr, 1, 12);
      range(dayStr, 1, 31);
      range(hours, 0, 23);
      range(minutes, 0, 59);
      range(seconds, 0, 60);
      const date2 = new Date(Date.UTC(Number(yearStr), Number(monthStr) - 1, Number(dayStr), Number(hours), Number(minutes), Number(seconds), Number(ms) ? Math.round(parseFloat(`0.${ms}`) * 1e3) : 0));
      date2.setUTCFullYear(Number(yearStr));
      if (offsetStr.toUpperCase() != "Z") {
        const [, sign, offsetH, offsetM] = /([+-])(\d\d):(\d\d)/.exec(offsetStr) || [void 0, "+", 0, 0];
        const scalar = sign === "-" ? 1 : -1;
        date2.setTime(date2.getTime() + scalar * (Number(offsetH) * 60 * 60 * 1e3 + Number(offsetM) * 60 * 1e3));
      }
      return date2;
    };
    _parseRfc7231DateTime = (value) => {
      if (value == null) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC7231 timestamps must be strings.");
      }
      let day;
      let month;
      let year2;
      let hour;
      let minute;
      let second;
      let fraction;
      let matches;
      if (matches = IMF_FIXDATE2.exec(value)) {
        [, day, month, year2, hour, minute, second, fraction] = matches;
      } else if (matches = RFC_850_DATE2.exec(value)) {
        [, day, month, year2, hour, minute, second, fraction] = matches;
        year2 = (Number(year2) + 1900).toString();
      } else if (matches = ASC_TIME2.exec(value)) {
        [, month, day, hour, minute, second, fraction, year2] = matches;
      }
      if (year2 && second) {
        const timestamp = Date.UTC(Number(year2), months.indexOf(month), Number(day), Number(hour), Number(minute), Number(second), fraction ? Math.round(parseFloat(`0.${fraction}`) * 1e3) : 0);
        range(day, 1, 31);
        range(hour, 0, 23);
        range(minute, 0, 59);
        range(second, 0, 60);
        const date2 = new Date(timestamp);
        date2.setUTCFullYear(Number(year2));
        return date2;
      }
      throw new TypeError(`Invalid RFC7231 date-time value ${value}.`);
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/split-every.js
function splitEvery(value, delimiter, numDelimiters) {
  if (numDelimiters <= 0 || !Number.isInteger(numDelimiters)) {
    throw new Error("Invalid number of delimiters (" + numDelimiters + ") for splitEvery.");
  }
  const segments = value.split(delimiter);
  if (numDelimiters === 1) {
    return segments;
  }
  const compoundSegments = [];
  let currentSegment = "";
  for (let i4 = 0; i4 < segments.length; i4++) {
    if (currentSegment === "") {
      currentSegment = segments[i4];
    } else {
      currentSegment += delimiter + segments[i4];
    }
    if ((i4 + 1) % numDelimiters === 0) {
      compoundSegments.push(currentSegment);
      currentSegment = "";
    }
  }
  if (currentSegment !== "") {
    compoundSegments.push(currentSegment);
  }
  return compoundSegments;
}
var init_split_every = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/split-every.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/split-header.js
var splitHeader;
var init_split_header = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/split-header.js"() {
    splitHeader = (value) => {
      const z2 = value.length;
      const values = [];
      let withinQuotes = false;
      let prevChar = void 0;
      let anchor = 0;
      for (let i4 = 0; i4 < z2; ++i4) {
        const char = value[i4];
        switch (char) {
          case `"`:
            if (prevChar !== "\\") {
              withinQuotes = !withinQuotes;
            }
            break;
          case ",":
            if (!withinQuotes) {
              values.push(value.slice(anchor, i4));
              anchor = i4 + 1;
            }
            break;
          default:
        }
        prevChar = char;
      }
      values.push(value.slice(anchor));
      return values.map((v4) => {
        v4 = v4.trim();
        const z3 = v4.length;
        if (z3 < 2) {
          return v4;
        }
        if (v4[0] === `"` && v4[z3 - 1] === `"`) {
          v4 = v4.slice(1, z3 - 1);
        }
        return v4.replace(/\\"/g, '"');
      });
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/value/NumericValue.js
function nv(input) {
  return new NumericValue(String(input), "bigDecimal");
}
var format, NumericValue;
var init_NumericValue = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/value/NumericValue.js"() {
    format = /^-?\d*(\.\d+)?$/;
    NumericValue = class _NumericValue {
      string;
      type;
      constructor(string, type) {
        this.string = string;
        this.type = type;
        if (!format.test(string)) {
          throw new Error(`@smithy/core/serde - NumericValue must only contain [0-9], at most one decimal point ".", and an optional negation prefix "-".`);
        }
      }
      toString() {
        return this.string;
      }
      static [Symbol.hasInstance](object) {
        if (!object || typeof object !== "object") {
          return false;
        }
        const _nv = object;
        return _NumericValue.prototype.isPrototypeOf(object) || _nv.type === "bigDecimal" && format.test(_nv.string);
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/index.js
var serde_exports = {};
__export(serde_exports, {
  LazyJsonString: () => LazyJsonString,
  NumericValue: () => NumericValue,
  _parseEpochTimestamp: () => _parseEpochTimestamp,
  _parseRfc3339DateTimeWithOffset: () => _parseRfc3339DateTimeWithOffset,
  _parseRfc7231DateTime: () => _parseRfc7231DateTime,
  copyDocumentWithTransform: () => copyDocumentWithTransform,
  dateToUtcString: () => dateToUtcString,
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
  expectUnion: () => expectUnion,
  generateIdempotencyToken: () => import_uuid.v4,
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
var init_serde = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/index.js"() {
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
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/SerdeContext.js
var SerdeContext;
var init_SerdeContext = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/SerdeContext.js"() {
    SerdeContext = class {
      serdeContext;
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/event-streams/EventStreamSerde.js
var import_util_utf8, EventStreamSerde;
var init_EventStreamSerde = __esm({
  "node_modules/@smithy/core/dist-es/submodules/event-streams/EventStreamSerde.js"() {
    import_util_utf8 = __toESM(require_dist_cjs10());
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
        const initialRequestMarker = /* @__PURE__ */ Symbol("initialRequestMarker");
        const eventStreamIterable = {
          async *[Symbol.asyncIterator]() {
            if (initialRequest) {
              const headers = {
                ":event-type": { type: "string", value: "initial-request" },
                ":message-type": { type: "string", value: "event" },
                ":content-type": { type: "string", value: defaultContentType }
              };
              serializer.write(requestSchema, initialRequest);
              const body = serializer.flush();
              yield {
                [initialRequestMarker]: true,
                headers,
                body
              };
            }
            for await (const page of eventStream) {
              yield page;
            }
          }
        };
        return marshaller.serialize(eventStreamIterable, (event) => {
          if (event[initialRequestMarker]) {
            return {
              headers: event.headers,
              body: event.body
            };
          }
          const unionMember = Object.keys(event).find((key) => {
            return key !== "__type";
          }) ?? "";
          const { additionalHeaders, body, eventType, explicitPayloadContentType } = this.writeEventBody(unionMember, unionSchema, event);
          const headers = {
            ":event-type": { type: "string", value: eventType },
            ":message-type": { type: "string", value: "event" },
            ":content-type": { type: "string", value: explicitPayloadContentType ?? defaultContentType },
            ...additionalHeaders
          };
          return {
            headers,
            body
          };
        });
      }
      async deserializeEventStream({ response, responseSchema, initialResponseContainer }) {
        const marshaller = this.marshaller;
        const eventStreamMember = responseSchema.getEventStreamMember();
        const unionSchema = responseSchema.getMemberSchema(eventStreamMember);
        const memberSchemas = unionSchema.getMemberSchemas();
        const initialResponseMarker = /* @__PURE__ */ Symbol("initialResponseMarker");
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
              for (const [name, member2] of eventStreamSchema.structIterator()) {
                const { eventHeader, eventPayload } = member2.getMergedTraits();
                hasBindings = hasBindings || Boolean(eventHeader || eventPayload);
                if (eventPayload) {
                  if (member2.isBlobSchema()) {
                    out[name] = body;
                  } else if (member2.isStringSchema()) {
                    out[name] = (this.serdeContext?.utf8Encoder ?? import_util_utf8.toUtf8)(body);
                  } else if (member2.isStructSchema()) {
                    out[name] = await this.deserializer.read(member2, body);
                  }
                } else if (eventHeader) {
                  const value = event[unionMember].headers[name]?.value;
                  if (value != null) {
                    if (member2.isNumericSchema()) {
                      if (value && typeof value === "object" && "bytes" in value) {
                        out[name] = BigInt(value.toString());
                      } else {
                        out[name] = Number(value);
                      }
                    } else {
                      out[name] = value;
                    }
                  }
                }
              }
              if (hasBindings) {
                return {
                  [unionMember]: out
                };
              }
            }
            return {
              [unionMember]: await this.deserializer.read(eventStreamSchema, body)
            };
          } else {
            return {
              $unknown: event
            };
          }
        });
        const asyncIterator = asyncIterable[Symbol.asyncIterator]();
        const firstEvent = await asyncIterator.next();
        if (firstEvent.done) {
          return asyncIterable;
        }
        if (firstEvent.value?.[initialResponseMarker]) {
          if (!responseSchema) {
            throw new Error("@smithy::core/protocols - initial-response event encountered in event stream but no response schema given.");
          }
          for (const [key, value] of Object.entries(firstEvent.value)) {
            initialResponseContainer[key] = value;
          }
        }
        return {
          async *[Symbol.asyncIterator]() {
            if (!firstEvent?.value?.[initialResponseMarker]) {
              yield firstEvent.value;
            }
            while (true) {
              const { done, value } = await asyncIterator.next();
              if (done) {
                break;
              }
              yield value;
            }
          }
        };
      }
      writeEventBody(unionMember, unionSchema, event) {
        const serializer = this.serializer;
        let eventType = unionMember;
        let explicitPayloadMember = null;
        let explicitPayloadContentType;
        const isKnownSchema = (() => {
          const struct2 = unionSchema.getSchema();
          return struct2[4].includes(unionMember);
        })();
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
              if (eventPayload) {
                explicitPayloadMember = memberName;
              } else if (eventHeader) {
                const value = event[unionMember][memberName];
                let type = "binary";
                if (memberSchema.isNumericSchema()) {
                  if ((-2) ** 31 <= value && value <= 2 ** 31 - 1) {
                    type = "integer";
                  } else {
                    type = "long";
                  }
                } else if (memberSchema.isTimestampSchema()) {
                  type = "timestamp";
                } else if (memberSchema.isStringSchema()) {
                  type = "string";
                } else if (memberSchema.isBooleanSchema()) {
                  type = "boolean";
                }
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
              if (payloadSchema.isBlobSchema()) {
                explicitPayloadContentType = "application/octet-stream";
              } else if (payloadSchema.isStringSchema()) {
                explicitPayloadContentType = "text/plain";
              }
              serializer.write(payloadSchema, event[unionMember][explicitPayloadMember]);
            } else {
              serializer.write(eventSchema, event[unionMember]);
            }
          } else {
            throw new Error("@smithy/core/event-streams - non-struct member not supported in event stream union.");
          }
        }
        const messageSerialization = serializer.flush();
        const body = typeof messageSerialization === "string" ? (this.serdeContext?.utf8Decoder ?? import_util_utf8.fromUtf8)(messageSerialization) : messageSerialization;
        return {
          body,
          eventType,
          explicitPayloadContentType,
          additionalHeaders
        };
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/event-streams/index.js
var event_streams_exports = {};
__export(event_streams_exports, {
  EventStreamSerde: () => EventStreamSerde
});
var init_event_streams = __esm({
  "node_modules/@smithy/core/dist-es/submodules/event-streams/index.js"() {
    init_EventStreamSerde();
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/HttpProtocol.js
var import_protocol_http3, HttpProtocol;
var init_HttpProtocol = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/HttpProtocol.js"() {
    init_schema();
    import_protocol_http3 = __toESM(require_dist_cjs2());
    init_SerdeContext();
    HttpProtocol = class extends SerdeContext {
      options;
      constructor(options) {
        super();
        this.options = options;
      }
      getRequestType() {
        return import_protocol_http3.HttpRequest;
      }
      getResponseType() {
        return import_protocol_http3.HttpResponse;
      }
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
        this.serializer.setSerdeContext(serdeContext);
        this.deserializer.setSerdeContext(serdeContext);
        if (this.getPayloadCodec()) {
          this.getPayloadCodec().setSerdeContext(serdeContext);
        }
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
          if (!request.query) {
            request.query = {};
          }
          for (const [k4, v4] of endpoint.url.searchParams.entries()) {
            request.query[k4] = v4;
          }
          return request;
        } else {
          request.protocol = endpoint.protocol;
          request.hostname = endpoint.hostname;
          request.port = endpoint.port ? Number(endpoint.port) : void 0;
          request.path = endpoint.path;
          request.query = {
            ...endpoint.query
          };
          return request;
        }
      }
      setHostPrefix(request, operationSchema, input) {
        const inputNs = NormalizedSchema.of(operationSchema.input);
        const opTraits = translateTraits(operationSchema.traits ?? {});
        if (opTraits.endpoint) {
          let hostPrefix = opTraits.endpoint?.[0];
          if (typeof hostPrefix === "string") {
            const hostLabelInputs = [...inputNs.structIterator()].filter(([, member2]) => member2.getMergedTraits().hostLabel);
            for (const [name] of hostLabelInputs) {
              const replacement = input[name];
              if (typeof replacement !== "string") {
                throw new Error(`@smithy/core/schema - ${name} in input must be a string as hostLabel.`);
              }
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
        const eventStreamSerde = await this.loadEventStreamCapability();
        return eventStreamSerde.serializeEventStream({
          eventStream,
          requestSchema,
          initialRequest
        });
      }
      async deserializeEventStream({ response, responseSchema, initialResponseContainer }) {
        const eventStreamSerde = await this.loadEventStreamCapability();
        return eventStreamSerde.deserializeEventStream({
          response,
          responseSchema,
          initialResponseContainer
        });
      }
      async loadEventStreamCapability() {
        const { EventStreamSerde: EventStreamSerde2 } = await Promise.resolve().then(() => (init_event_streams(), event_streams_exports));
        return new EventStreamSerde2({
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
        void schema;
        void context;
        void response;
        void arg4;
        void arg5;
        return [];
      }
      getEventStreamMarshaller() {
        const context = this.serdeContext;
        if (!context.eventStreamMarshaller) {
          throw new Error("@smithy/core - HttpProtocol: eventStreamMarshaller missing in serdeContext.");
        }
        return context.eventStreamMarshaller;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/HttpBindingProtocol.js
var import_protocol_http4, import_util_stream2, HttpBindingProtocol;
var init_HttpBindingProtocol = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/HttpBindingProtocol.js"() {
    init_schema();
    init_serde();
    import_protocol_http4 = __toESM(require_dist_cjs2());
    import_util_stream2 = __toESM(require_dist_cjs17());
    init_collect_stream_body();
    init_extended_encode_uri_component();
    init_HttpProtocol();
    HttpBindingProtocol = class extends HttpProtocol {
      async serializeRequest(operationSchema, _input, context) {
        const input = {
          ..._input ?? {}
        };
        const serializer = this.serializer;
        const query = {};
        const headers = {};
        const endpoint = await context.endpoint();
        const ns = NormalizedSchema.of(operationSchema?.input);
        const schema = ns.getSchema();
        let hasNonHttpBindingMember = false;
        let payload2;
        const request = new import_protocol_http4.HttpRequest({
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
            const [path, search] = opTraits.http[1].split("?");
            if (request.path == "/") {
              request.path = path;
            } else {
              request.path += path;
            }
            const traitSearchParams = new URLSearchParams(search ?? "");
            Object.assign(query, Object.fromEntries(traitSearchParams));
          }
        }
        for (const [memberName, memberNs] of ns.structIterator()) {
          const memberTraits = memberNs.getMergedTraits() ?? {};
          const inputMemberValue = input[memberName];
          if (inputMemberValue == null && !memberNs.isIdempotencyToken()) {
            continue;
          }
          if (memberTraits.httpPayload) {
            const isStreaming = memberNs.isStreaming();
            if (isStreaming) {
              const isEventStream = memberNs.isStructSchema();
              if (isEventStream) {
                if (input[memberName]) {
                  payload2 = await this.serializeEventStream({
                    eventStream: input[memberName],
                    requestSchema: ns
                  });
                }
              } else {
                payload2 = inputMemberValue;
              }
            } else {
              serializer.write(memberNs, inputMemberValue);
              payload2 = serializer.flush();
            }
            delete input[memberName];
          } else if (memberTraits.httpLabel) {
            serializer.write(memberNs, inputMemberValue);
            const replacement = serializer.flush();
            if (request.path.includes(`{${memberName}+}`)) {
              request.path = request.path.replace(`{${memberName}+}`, replacement.split("/").map(extendedEncodeURIComponent).join("/"));
            } else if (request.path.includes(`{${memberName}}`)) {
              request.path = request.path.replace(`{${memberName}}`, extendedEncodeURIComponent(replacement));
            }
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
          } else {
            hasNonHttpBindingMember = true;
          }
        }
        if (hasNonHttpBindingMember && input) {
          serializer.write(schema, input);
          payload2 = serializer.flush();
        }
        request.headers = headers;
        request.query = query;
        request.body = payload2;
        return request;
      }
      serializeQuery(ns, data2, query) {
        const serializer = this.serializer;
        const traits = ns.getMergedTraits();
        if (traits.httpQueryParams) {
          for (const [key, val] of Object.entries(data2)) {
            if (!(key in query)) {
              const valueSchema = ns.getValueSchema();
              Object.assign(valueSchema.getMergedTraits(), {
                ...traits,
                httpQuery: key,
                httpQueryParams: void 0
              });
              this.serializeQuery(valueSchema, val, query);
            }
          }
          return;
        }
        if (ns.isListSchema()) {
          const sparse = !!ns.getMergedTraits().sparse;
          const buffer = [];
          for (const item of data2) {
            serializer.write([ns.getValueSchema(), traits], item);
            const serializable = serializer.flush();
            if (sparse || serializable !== void 0) {
              buffer.push(serializable);
            }
          }
          query[traits.httpQuery] = buffer;
        } else {
          serializer.write([ns, traits], data2);
          query[traits.httpQuery] = serializer.flush();
        }
      }
      async deserializeResponse(operationSchema, context, response) {
        const deserializer = this.deserializer;
        const ns = NormalizedSchema.of(operationSchema.output);
        const dataObject = {};
        if (response.statusCode >= 300) {
          const bytes = await collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(15, bytes));
          }
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
          const bytes = await collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            const dataFromBody = await deserializer.read(ns, bytes);
            for (const member2 of nonHttpBindingMembers) {
              dataObject[member2] = dataFromBody[member2];
            }
          }
        } else if (nonHttpBindingMembers.discardResponseBody) {
          await collectBody(response.body, context);
        }
        dataObject.$metadata = this.deserializeMetadata(response);
        return dataObject;
      }
      async deserializeHttpMessage(schema, context, response, arg4, arg5) {
        let dataObject;
        if (arg4 instanceof Set) {
          dataObject = arg5;
        } else {
          dataObject = arg4;
        }
        let discardResponseBody = true;
        const deserializer = this.deserializer;
        const ns = NormalizedSchema.of(schema);
        const nonHttpBindingMembers = [];
        for (const [memberName, memberSchema] of ns.structIterator()) {
          const memberTraits = memberSchema.getMemberTraits();
          if (memberTraits.httpPayload) {
            discardResponseBody = false;
            const isStreaming = memberSchema.isStreaming();
            if (isStreaming) {
              const isEventStream = memberSchema.isStructSchema();
              if (isEventStream) {
                dataObject[memberName] = await this.deserializeEventStream({
                  response,
                  responseSchema: ns
                });
              } else {
                dataObject[memberName] = (0, import_util_stream2.sdkStreamMixin)(response.body);
              }
            } else if (response.body) {
              const bytes = await collectBody(response.body, context);
              if (bytes.byteLength > 0) {
                dataObject[memberName] = await deserializer.read(memberSchema, bytes);
              }
            }
          } else if (memberTraits.httpHeader) {
            const key = String(memberTraits.httpHeader).toLowerCase();
            const value = response.headers[key];
            if (null != value) {
              if (memberSchema.isListSchema()) {
                const headerListValueSchema = memberSchema.getValueSchema();
                headerListValueSchema.getMergedTraits().httpHeader = key;
                let sections;
                if (headerListValueSchema.isTimestampSchema() && headerListValueSchema.getSchema() === 4) {
                  sections = splitEvery(value, ",", 2);
                } else {
                  sections = splitHeader(value);
                }
                const list2 = [];
                for (const section of sections) {
                  list2.push(await deserializer.read(headerListValueSchema, section.trim()));
                }
                dataObject[memberName] = list2;
              } else {
                dataObject[memberName] = await deserializer.read(memberSchema, value);
              }
            }
          } else if (memberTraits.httpPrefixHeaders !== void 0) {
            dataObject[memberName] = {};
            for (const [header, value] of Object.entries(response.headers)) {
              if (header.startsWith(memberTraits.httpPrefixHeaders)) {
                const valueSchema = memberSchema.getValueSchema();
                valueSchema.getMergedTraits().httpHeader = header;
                dataObject[memberName][header.slice(memberTraits.httpPrefixHeaders.length)] = await deserializer.read(valueSchema, value);
              }
            }
          } else if (memberTraits.httpResponseCode) {
            dataObject[memberName] = response.statusCode;
          } else {
            nonHttpBindingMembers.push(memberName);
          }
        }
        nonHttpBindingMembers.discardResponseBody = discardResponseBody;
        return nonHttpBindingMembers;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/RpcProtocol.js
var import_protocol_http5, RpcProtocol;
var init_RpcProtocol = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/RpcProtocol.js"() {
    init_schema();
    import_protocol_http5 = __toESM(require_dist_cjs2());
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
        let payload2;
        const request = new import_protocol_http5.HttpRequest({
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
        const _input = {
          ...input
        };
        if (input) {
          const eventStreamMember = ns.getEventStreamMember();
          if (eventStreamMember) {
            if (_input[eventStreamMember]) {
              const initialRequest = {};
              for (const [memberName, memberSchema] of ns.structIterator()) {
                if (memberName !== eventStreamMember && _input[memberName]) {
                  serializer.write(memberSchema, _input[memberName]);
                  initialRequest[memberName] = serializer.flush();
                }
              }
              payload2 = await this.serializeEventStream({
                eventStream: _input[eventStreamMember],
                requestSchema: ns,
                initialRequest
              });
            }
          } else {
            serializer.write(schema, _input);
            payload2 = serializer.flush();
          }
        }
        request.headers = headers;
        request.query = query;
        request.body = payload2;
        request.method = "POST";
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        const deserializer = this.deserializer;
        const ns = NormalizedSchema.of(operationSchema.output);
        const dataObject = {};
        if (response.statusCode >= 300) {
          const bytes = await collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(15, bytes));
          }
          await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
          throw new Error("@smithy/core/protocols - RPC Protocol error handler failed to throw.");
        }
        for (const header in response.headers) {
          const value = response.headers[header];
          delete response.headers[header];
          response.headers[header.toLowerCase()] = value;
        }
        const eventStreamMember = ns.getEventStreamMember();
        if (eventStreamMember) {
          dataObject[eventStreamMember] = await this.deserializeEventStream({
            response,
            responseSchema: ns,
            initialResponseContainer: dataObject
          });
        } else {
          const bytes = await collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(ns, bytes));
          }
        }
        dataObject.$metadata = this.deserializeMetadata(response);
        return dataObject;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/resolve-path.js
var resolvedPath;
var init_resolve_path = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/resolve-path.js"() {
    init_extended_encode_uri_component();
    resolvedPath = (resolvedPath2, input, memberName, labelValueProvider, uriLabel, isGreedyLabel) => {
      if (input != null && input[memberName] !== void 0) {
        const labelValue = labelValueProvider();
        if (labelValue.length <= 0) {
          throw new Error("Empty value provided for input HTTP label: " + memberName + ".");
        }
        resolvedPath2 = resolvedPath2.replace(uriLabel, isGreedyLabel ? labelValue.split("/").map((segment) => extendedEncodeURIComponent(segment)).join("/") : extendedEncodeURIComponent(labelValue));
      } else {
        throw new Error("No value provided for input HTTP label: " + memberName + ".");
      }
      return resolvedPath2;
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/requestBuilder.js
function requestBuilder(input, context) {
  return new RequestBuilder(input, context);
}
var import_protocol_http6, RequestBuilder;
var init_requestBuilder = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/requestBuilder.js"() {
    import_protocol_http6 = __toESM(require_dist_cjs2());
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
        for (const resolvePath of this.resolvePathStack) {
          resolvePath(this.path);
        }
        return new import_protocol_http6.HttpRequest({
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
        this.resolvePathStack.push((path) => {
          this.path = resolvedPath(path, this.input, memberName, labelValueProvider, uriLabel, isGreedyLabel);
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
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/determineTimestampFormat.js
function determineTimestampFormat(ns, settings) {
  if (settings.timestampFormat.useTrait) {
    if (ns.isTimestampSchema() && (ns.getSchema() === 5 || ns.getSchema() === 6 || ns.getSchema() === 7)) {
      return ns.getSchema();
    }
  }
  const { httpLabel, httpPrefixHeaders, httpHeader, httpQuery } = ns.getMergedTraits();
  const bindingFormat = settings.httpBindings ? typeof httpPrefixHeaders === "string" || Boolean(httpHeader) ? 6 : Boolean(httpQuery) || Boolean(httpLabel) ? 5 : void 0 : void 0;
  return bindingFormat ?? settings.timestampFormat.default;
}
var init_determineTimestampFormat = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/determineTimestampFormat.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/FromStringShapeDeserializer.js
var import_util_base64, import_util_utf82, FromStringShapeDeserializer;
var init_FromStringShapeDeserializer = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/FromStringShapeDeserializer.js"() {
    init_schema();
    init_serde();
    import_util_base64 = __toESM(require_dist_cjs11());
    import_util_utf82 = __toESM(require_dist_cjs10());
    init_SerdeContext();
    init_determineTimestampFormat();
    FromStringShapeDeserializer = class extends SerdeContext {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      read(_schema, data2) {
        const ns = NormalizedSchema.of(_schema);
        if (ns.isListSchema()) {
          return splitHeader(data2).map((item) => this.read(ns.getValueSchema(), item));
        }
        if (ns.isBlobSchema()) {
          return (this.serdeContext?.base64Decoder ?? import_util_base64.fromBase64)(data2);
        }
        if (ns.isTimestampSchema()) {
          const format2 = determineTimestampFormat(ns, this.settings);
          switch (format2) {
            case 5:
              return _parseRfc3339DateTimeWithOffset(data2);
            case 6:
              return _parseRfc7231DateTime(data2);
            case 7:
              return _parseEpochTimestamp(data2);
            default:
              console.warn("Missing timestamp format, parsing value with Date constructor:", data2);
              return new Date(data2);
          }
        }
        if (ns.isStringSchema()) {
          const mediaType = ns.getMergedTraits().mediaType;
          let intermediateValue = data2;
          if (mediaType) {
            if (ns.getMergedTraits().httpHeader) {
              intermediateValue = this.base64ToUtf8(intermediateValue);
            }
            const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
            if (isJson) {
              intermediateValue = LazyJsonString.from(intermediateValue);
            }
            return intermediateValue;
          }
        }
        if (ns.isNumericSchema()) {
          return Number(data2);
        }
        if (ns.isBigIntegerSchema()) {
          return BigInt(data2);
        }
        if (ns.isBigDecimalSchema()) {
          return new NumericValue(data2, "bigDecimal");
        }
        if (ns.isBooleanSchema()) {
          return String(data2).toLowerCase() === "true";
        }
        return data2;
      }
      base64ToUtf8(base64String) {
        return (this.serdeContext?.utf8Encoder ?? import_util_utf82.toUtf8)((this.serdeContext?.base64Decoder ?? import_util_base64.fromBase64)(base64String));
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeDeserializer.js
var import_util_utf83, HttpInterceptingShapeDeserializer;
var init_HttpInterceptingShapeDeserializer = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeDeserializer.js"() {
    init_schema();
    import_util_utf83 = __toESM(require_dist_cjs10());
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
      read(schema, data2) {
        const ns = NormalizedSchema.of(schema);
        const traits = ns.getMergedTraits();
        const toString = this.serdeContext?.utf8Encoder ?? import_util_utf83.toUtf8;
        if (traits.httpHeader || traits.httpResponseCode) {
          return this.stringDeserializer.read(ns, toString(data2));
        }
        if (traits.httpPayload) {
          if (ns.isBlobSchema()) {
            const toBytes = this.serdeContext?.utf8Decoder ?? import_util_utf83.fromUtf8;
            if (typeof data2 === "string") {
              return toBytes(data2);
            }
            return data2;
          } else if (ns.isStringSchema()) {
            if ("byteLength" in data2) {
              return toString(data2);
            }
            return data2;
          }
        }
        return this.codecDeserializer.read(ns, data2);
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/ToStringShapeSerializer.js
var import_util_base642, ToStringShapeSerializer;
var init_ToStringShapeSerializer = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/ToStringShapeSerializer.js"() {
    init_schema();
    init_serde();
    import_util_base642 = __toESM(require_dist_cjs11());
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
              if (!(value instanceof Date)) {
                throw new Error(`@smithy/core/protocols - received non-Date value ${value} when schema expected Date in ${ns.getName(true)}`);
              }
              const format2 = determineTimestampFormat(ns, this.settings);
              switch (format2) {
                case 5:
                  this.stringBuffer = value.toISOString().replace(".000Z", "Z");
                  break;
                case 6:
                  this.stringBuffer = dateToUtcString(value);
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
              this.stringBuffer = (this.serdeContext?.base64Encoder ?? import_util_base642.toBase64)(value);
              return;
            }
            if (ns.isListSchema() && Array.isArray(value)) {
              let buffer = "";
              for (const item of value) {
                this.write([ns.getValueSchema(), ns.getMergedTraits()], item);
                const headerItem = this.flush();
                const serialized = ns.getValueSchema().isTimestampSchema() ? headerItem : quoteHeader(headerItem);
                if (buffer !== "") {
                  buffer += ", ";
                }
                buffer += serialized;
              }
              this.stringBuffer = buffer;
              return;
            }
            this.stringBuffer = JSON.stringify(value, null, 2);
            break;
          case "string":
            const mediaType = ns.getMergedTraits().mediaType;
            let intermediateValue = value;
            if (mediaType) {
              const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
              if (isJson) {
                intermediateValue = LazyJsonString.from(intermediateValue);
              }
              if (ns.getMergedTraits().httpHeader) {
                this.stringBuffer = (this.serdeContext?.base64Encoder ?? import_util_base642.toBase64)(intermediateValue.toString());
                return;
              }
            }
            this.stringBuffer = value;
            break;
          default:
            if (ns.isIdempotencyToken()) {
              this.stringBuffer = (0, import_uuid.v4)();
            } else {
              this.stringBuffer = String(value);
            }
        }
      }
      flush() {
        const buffer = this.stringBuffer;
        this.stringBuffer = "";
        return buffer;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeSerializer.js
var HttpInterceptingShapeSerializer;
var init_HttpInterceptingShapeSerializer = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeSerializer.js"() {
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
          const buffer = this.buffer;
          this.buffer = void 0;
          return buffer;
        }
        return this.codecSerializer.flush();
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/index.js
var protocols_exports = {};
__export(protocols_exports, {
  FromStringShapeDeserializer: () => FromStringShapeDeserializer,
  HttpBindingProtocol: () => HttpBindingProtocol,
  HttpInterceptingShapeDeserializer: () => HttpInterceptingShapeDeserializer,
  HttpInterceptingShapeSerializer: () => HttpInterceptingShapeSerializer,
  HttpProtocol: () => HttpProtocol,
  RequestBuilder: () => RequestBuilder,
  RpcProtocol: () => RpcProtocol,
  SerdeContext: () => SerdeContext,
  ToStringShapeSerializer: () => ToStringShapeSerializer,
  collectBody: () => collectBody,
  determineTimestampFormat: () => determineTimestampFormat,
  extendedEncodeURIComponent: () => extendedEncodeURIComponent,
  requestBuilder: () => requestBuilder,
  resolvedPath: () => resolvedPath
});
var init_protocols = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/index.js"() {
    init_collect_stream_body();
    init_extended_encode_uri_component();
    init_HttpBindingProtocol();
    init_HttpProtocol();
    init_RpcProtocol();
    init_requestBuilder();
    init_resolve_path();
    init_FromStringShapeDeserializer();
    init_HttpInterceptingShapeDeserializer();
    init_HttpInterceptingShapeSerializer();
    init_ToStringShapeSerializer();
    init_determineTimestampFormat();
    init_SerdeContext();
  }
});

// node_modules/@smithy/core/dist-es/request-builder/requestBuilder.js
var init_requestBuilder2 = __esm({
  "node_modules/@smithy/core/dist-es/request-builder/requestBuilder.js"() {
    init_protocols();
  }
});

// node_modules/@smithy/core/dist-es/setFeature.js
function setFeature(context, feature, value) {
  if (!context.__smithy_context) {
    context.__smithy_context = {
      features: {}
    };
  } else if (!context.__smithy_context.features) {
    context.__smithy_context.features = {};
  }
  context.__smithy_context.features[feature] = value;
}
var init_setFeature = __esm({
  "node_modules/@smithy/core/dist-es/setFeature.js"() {
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/DefaultIdentityProviderConfig.js
var DefaultIdentityProviderConfig;
var init_DefaultIdentityProviderConfig = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/DefaultIdentityProviderConfig.js"() {
    DefaultIdentityProviderConfig = class {
      authSchemes = /* @__PURE__ */ new Map();
      constructor(config) {
        for (const [key, value] of Object.entries(config)) {
          if (value !== void 0) {
            this.authSchemes.set(key, value);
          }
        }
      }
      getIdentityProvider(schemeId) {
        return this.authSchemes.get(schemeId);
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpApiKeyAuth.js
var import_protocol_http7, import_types2, HttpApiKeyAuthSigner;
var init_httpApiKeyAuth = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpApiKeyAuth.js"() {
    import_protocol_http7 = __toESM(require_dist_cjs2());
    import_types2 = __toESM(require_dist_cjs());
    HttpApiKeyAuthSigner = class {
      async sign(httpRequest, identity, signingProperties) {
        if (!signingProperties) {
          throw new Error("request could not be signed with `apiKey` since the `name` and `in` signer properties are missing");
        }
        if (!signingProperties.name) {
          throw new Error("request could not be signed with `apiKey` since the `name` signer property is missing");
        }
        if (!signingProperties.in) {
          throw new Error("request could not be signed with `apiKey` since the `in` signer property is missing");
        }
        if (!identity.apiKey) {
          throw new Error("request could not be signed with `apiKey` since the `apiKey` is not defined");
        }
        const clonedRequest = import_protocol_http7.HttpRequest.clone(httpRequest);
        if (signingProperties.in === import_types2.HttpApiKeyAuthLocation.QUERY) {
          clonedRequest.query[signingProperties.name] = identity.apiKey;
        } else if (signingProperties.in === import_types2.HttpApiKeyAuthLocation.HEADER) {
          clonedRequest.headers[signingProperties.name] = signingProperties.scheme ? `${signingProperties.scheme} ${identity.apiKey}` : identity.apiKey;
        } else {
          throw new Error("request can only be signed with `apiKey` locations `query` or `header`, but found: `" + signingProperties.in + "`");
        }
        return clonedRequest;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpBearerAuth.js
var import_protocol_http8, HttpBearerAuthSigner;
var init_httpBearerAuth = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpBearerAuth.js"() {
    import_protocol_http8 = __toESM(require_dist_cjs2());
    HttpBearerAuthSigner = class {
      async sign(httpRequest, identity, signingProperties) {
        const clonedRequest = import_protocol_http8.HttpRequest.clone(httpRequest);
        if (!identity.token) {
          throw new Error("request could not be signed with `token` since the `token` is not defined");
        }
        clonedRequest.headers["Authorization"] = `Bearer ${identity.token}`;
        return clonedRequest;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/noAuth.js
var NoAuthSigner;
var init_noAuth = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/noAuth.js"() {
    NoAuthSigner = class {
      async sign(httpRequest, identity, signingProperties) {
        return httpRequest;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/index.js
var init_httpAuthSchemes = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/index.js"() {
    init_httpApiKeyAuth();
    init_httpBearerAuth();
    init_noAuth();
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/memoizeIdentityProvider.js
var createIsIdentityExpiredFunction, EXPIRATION_MS, isIdentityExpired, doesIdentityRequireRefresh, memoizeIdentityProvider;
var init_memoizeIdentityProvider = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/memoizeIdentityProvider.js"() {
    createIsIdentityExpiredFunction = (expirationMs) => function isIdentityExpired2(identity) {
      return doesIdentityRequireRefresh(identity) && identity.expiration.getTime() - Date.now() < expirationMs;
    };
    EXPIRATION_MS = 3e5;
    isIdentityExpired = createIsIdentityExpiredFunction(EXPIRATION_MS);
    doesIdentityRequireRefresh = (identity) => identity.expiration !== void 0;
    memoizeIdentityProvider = (provider, isExpired, requiresRefresh) => {
      if (provider === void 0) {
        return void 0;
      }
      const normalizedProvider = typeof provider !== "function" ? async () => Promise.resolve(provider) : provider;
      let resolved;
      let pending;
      let hasResult;
      let isConstant = false;
      const coalesceProvider = async (options) => {
        if (!pending) {
          pending = normalizedProvider(options);
        }
        try {
          resolved = await pending;
          hasResult = true;
          isConstant = false;
        } finally {
          pending = void 0;
        }
        return resolved;
      };
      if (isExpired === void 0) {
        return async (options) => {
          if (!hasResult || options?.forceRefresh) {
            resolved = await coalesceProvider(options);
          }
          return resolved;
        };
      }
      return async (options) => {
        if (!hasResult || options?.forceRefresh) {
          resolved = await coalesceProvider(options);
        }
        if (isConstant) {
          return resolved;
        }
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
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/index.js
var init_util_identity_and_auth = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/index.js"() {
    init_DefaultIdentityProviderConfig();
    init_httpAuthSchemes();
    init_memoizeIdentityProvider();
  }
});

// node_modules/@smithy/core/dist-es/index.js
var dist_es_exports = {};
__export(dist_es_exports, {
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
  getSmithyContext: () => getSmithyContext,
  httpAuthSchemeEndpointRuleSetMiddlewareOptions: () => httpAuthSchemeEndpointRuleSetMiddlewareOptions,
  httpAuthSchemeMiddleware: () => httpAuthSchemeMiddleware,
  httpAuthSchemeMiddlewareOptions: () => httpAuthSchemeMiddlewareOptions,
  httpSigningMiddleware: () => httpSigningMiddleware,
  httpSigningMiddlewareOptions: () => httpSigningMiddlewareOptions,
  isIdentityExpired: () => isIdentityExpired,
  memoizeIdentityProvider: () => memoizeIdentityProvider,
  normalizeProvider: () => normalizeProvider,
  requestBuilder: () => requestBuilder,
  setFeature: () => setFeature
});
var init_dist_es = __esm({
  "node_modules/@smithy/core/dist-es/index.js"() {
    init_getSmithyContext();
    init_middleware_http_auth_scheme();
    init_middleware_http_signing();
    init_normalizeProvider();
    init_createPaginator();
    init_requestBuilder2();
    init_setFeature();
    init_util_identity_and_auth();
  }
});

// node_modules/@smithy/util-endpoints/dist-cjs/index.js
var require_dist_cjs19 = __commonJS({
  "node_modules/@smithy/util-endpoints/dist-cjs/index.js"(exports) {
    "use strict";
    var types = require_dist_cjs();
    var EndpointCache4 = class {
      capacity;
      data = /* @__PURE__ */ new Map();
      parameters = [];
      constructor({ size, params }) {
        this.capacity = size ?? 50;
        if (params) {
          this.parameters = params;
        }
      }
      get(endpointParams, resolver) {
        const key = this.hash(endpointParams);
        if (key === false) {
          return resolver();
        }
        if (!this.data.has(key)) {
          if (this.data.size > this.capacity + 10) {
            const keys = this.data.keys();
            let i4 = 0;
            while (true) {
              const { value, done } = keys.next();
              this.data.delete(value);
              if (done || ++i4 > 10) {
                break;
              }
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
        if (parameters.length === 0) {
          return false;
        }
        for (const param of parameters) {
          const val = String(endpointParams[param] ?? "");
          if (val.includes("|;")) {
            return false;
          }
          buffer += val + "|;";
        }
        return buffer;
      }
    };
    var IP_V4_REGEX = new RegExp(`^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}$`);
    var isIpAddress = (value) => IP_V4_REGEX.test(value) || value.startsWith("[") && value.endsWith("]");
    var VALID_HOST_LABEL_REGEX = new RegExp(`^(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63}$`);
    var isValidHostLabel = (value, allowSubDomains = false) => {
      if (!allowSubDomains) {
        return VALID_HOST_LABEL_REGEX.test(value);
      }
      const labels = value.split(".");
      for (const label of labels) {
        if (!isValidHostLabel(label)) {
          return false;
        }
      }
      return true;
    };
    var customEndpointFunctions4 = {};
    var debugId = "endpoints";
    function toDebugString(input) {
      if (typeof input !== "object" || input == null) {
        return input;
      }
      if ("ref" in input) {
        return `$${toDebugString(input.ref)}`;
      }
      if ("fn" in input) {
        return `${input.fn}(${(input.argv || []).map(toDebugString).join(", ")})`;
      }
      return JSON.stringify(input, null, 2);
    }
    var EndpointError = class extends Error {
      constructor(message) {
        super(message);
        this.name = "EndpointError";
      }
    };
    var booleanEquals = (value1, value2) => value1 === value2;
    var getAttrPathList = (path) => {
      const parts = path.split(".");
      const pathList = [];
      for (const part of parts) {
        const squareBracketIndex = part.indexOf("[");
        if (squareBracketIndex !== -1) {
          if (part.indexOf("]") !== part.length - 1) {
            throw new EndpointError(`Path: '${path}' does not end with ']'`);
          }
          const arrayIndex = part.slice(squareBracketIndex + 1, -1);
          if (Number.isNaN(parseInt(arrayIndex))) {
            throw new EndpointError(`Invalid array index: '${arrayIndex}' in path: '${path}'`);
          }
          if (squareBracketIndex !== 0) {
            pathList.push(part.slice(0, squareBracketIndex));
          }
          pathList.push(arrayIndex);
        } else {
          pathList.push(part);
        }
      }
      return pathList;
    };
    var getAttr = (value, path) => getAttrPathList(path).reduce((acc, index) => {
      if (typeof acc !== "object") {
        throw new EndpointError(`Index '${index}' in '${path}' not found in '${JSON.stringify(value)}'`);
      } else if (Array.isArray(acc)) {
        return acc[parseInt(index)];
      }
      return acc[index];
    }, value);
    var isSet = (value) => value != null;
    var not = (value) => !value;
    var DEFAULT_PORTS = {
      [types.EndpointURLScheme.HTTP]: 80,
      [types.EndpointURLScheme.HTTPS]: 443
    };
    var parseURL = (value) => {
      const whatwgURL = (() => {
        try {
          if (value instanceof URL) {
            return value;
          }
          if (typeof value === "object" && "hostname" in value) {
            const { hostname: hostname2, port, protocol: protocol2 = "", path = "", query = {} } = value;
            const url = new URL(`${protocol2}//${hostname2}${port ? `:${port}` : ""}${path}`);
            url.search = Object.entries(query).map(([k4, v4]) => `${k4}=${v4}`).join("&");
            return url;
          }
          return new URL(value);
        } catch (error2) {
          return null;
        }
      })();
      if (!whatwgURL) {
        console.error(`Unable to parse ${JSON.stringify(value)} as a whatwg URL.`);
        return null;
      }
      const urlString = whatwgURL.href;
      const { host, hostname, pathname, protocol, search } = whatwgURL;
      if (search) {
        return null;
      }
      const scheme = protocol.slice(0, -1);
      if (!Object.values(types.EndpointURLScheme).includes(scheme)) {
        return null;
      }
      const isIp = isIpAddress(hostname);
      const inputContainsDefaultPort = urlString.includes(`${host}:${DEFAULT_PORTS[scheme]}`) || typeof value === "string" && value.includes(`${host}:${DEFAULT_PORTS[scheme]}`);
      const authority = `${host}${inputContainsDefaultPort ? `:${DEFAULT_PORTS[scheme]}` : ``}`;
      return {
        scheme,
        authority,
        path: pathname,
        normalizedPath: pathname.endsWith("/") ? pathname : `${pathname}/`,
        isIp
      };
    };
    var stringEquals = (value1, value2) => value1 === value2;
    var substring = (input, start, stop, reverse) => {
      if (start >= stop || input.length < stop) {
        return null;
      }
      if (!reverse) {
        return input.substring(start, stop);
      }
      return input.substring(input.length - stop, input.length - start);
    };
    var uriEncode = (value) => encodeURIComponent(value).replace(/[!*'()]/g, (c4) => `%${c4.charCodeAt(0).toString(16).toUpperCase()}`);
    var endpointFunctions = {
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
    var evaluateTemplate = (template, options) => {
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
        } else {
          evaluatedTemplateArr.push(templateContext[parameterName]);
        }
        currentIndex = closingBraceIndex + 1;
      }
      return evaluatedTemplateArr.join("");
    };
    var getReferenceValue = ({ ref }, options) => {
      const referenceRecord = {
        ...options.endpointParams,
        ...options.referenceRecord
      };
      return referenceRecord[ref];
    };
    var evaluateExpression = (obj, keyName, options) => {
      if (typeof obj === "string") {
        return evaluateTemplate(obj, options);
      } else if (obj["fn"]) {
        return group$2.callFunction(obj, options);
      } else if (obj["ref"]) {
        return getReferenceValue(obj, options);
      }
      throw new EndpointError(`'${keyName}': ${String(obj)} is not a string, function or reference.`);
    };
    var callFunction = ({ fn, argv }, options) => {
      const evaluatedArgs = argv.map((arg) => ["boolean", "number"].includes(typeof arg) ? arg : group$2.evaluateExpression(arg, "arg", options));
      const fnSegments = fn.split(".");
      if (fnSegments[0] in customEndpointFunctions4 && fnSegments[1] != null) {
        return customEndpointFunctions4[fnSegments[0]][fnSegments[1]](...evaluatedArgs);
      }
      return endpointFunctions[fn](...evaluatedArgs);
    };
    var group$2 = {
      evaluateExpression,
      callFunction
    };
    var evaluateCondition = ({ assign, ...fnArgs }, options) => {
      if (assign && assign in options.referenceRecord) {
        throw new EndpointError(`'${assign}' is already defined in Reference Record.`);
      }
      const value = callFunction(fnArgs, options);
      options.logger?.debug?.(`${debugId} evaluateCondition: ${toDebugString(fnArgs)} = ${toDebugString(value)}`);
      return {
        result: value === "" ? true : !!value,
        ...assign != null && { toAssign: { name: assign, value } }
      };
    };
    var evaluateConditions = (conditions = [], options) => {
      const conditionsReferenceRecord = {};
      for (const condition of conditions) {
        const { result, toAssign } = evaluateCondition(condition, {
          ...options,
          referenceRecord: {
            ...options.referenceRecord,
            ...conditionsReferenceRecord
          }
        });
        if (!result) {
          return { result };
        }
        if (toAssign) {
          conditionsReferenceRecord[toAssign.name] = toAssign.value;
          options.logger?.debug?.(`${debugId} assign: ${toAssign.name} := ${toDebugString(toAssign.value)}`);
        }
      }
      return { result: true, referenceRecord: conditionsReferenceRecord };
    };
    var getEndpointHeaders = (headers, options) => Object.entries(headers).reduce((acc, [headerKey, headerVal]) => ({
      ...acc,
      [headerKey]: headerVal.map((headerValEntry) => {
        const processedExpr = evaluateExpression(headerValEntry, "Header value entry", options);
        if (typeof processedExpr !== "string") {
          throw new EndpointError(`Header '${headerKey}' value '${processedExpr}' is not a string`);
        }
        return processedExpr;
      })
    }), {});
    var getEndpointProperties = (properties, options) => Object.entries(properties).reduce((acc, [propertyKey, propertyVal]) => ({
      ...acc,
      [propertyKey]: group$1.getEndpointProperty(propertyVal, options)
    }), {});
    var getEndpointProperty = (property, options) => {
      if (Array.isArray(property)) {
        return property.map((propertyEntry) => getEndpointProperty(propertyEntry, options));
      }
      switch (typeof property) {
        case "string":
          return evaluateTemplate(property, options);
        case "object":
          if (property === null) {
            throw new EndpointError(`Unexpected endpoint property: ${property}`);
          }
          return group$1.getEndpointProperties(property, options);
        case "boolean":
          return property;
        default:
          throw new EndpointError(`Unexpected endpoint property type: ${typeof property}`);
      }
    };
    var group$1 = {
      getEndpointProperty,
      getEndpointProperties
    };
    var getEndpointUrl = (endpointUrl, options) => {
      const expression = evaluateExpression(endpointUrl, "Endpoint URL", options);
      if (typeof expression === "string") {
        try {
          return new URL(expression);
        } catch (error2) {
          console.error(`Failed to construct URL with ${expression}`, error2);
          throw error2;
        }
      }
      throw new EndpointError(`Endpoint URL must be a string, got ${typeof expression}`);
    };
    var evaluateEndpointRule = (endpointRule, options) => {
      const { conditions, endpoint } = endpointRule;
      const { result, referenceRecord } = evaluateConditions(conditions, options);
      if (!result) {
        return;
      }
      const endpointRuleOptions = {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord }
      };
      const { url, properties, headers } = endpoint;
      options.logger?.debug?.(`${debugId} Resolving endpoint from template: ${toDebugString(endpoint)}`);
      return {
        ...headers != void 0 && {
          headers: getEndpointHeaders(headers, endpointRuleOptions)
        },
        ...properties != void 0 && {
          properties: getEndpointProperties(properties, endpointRuleOptions)
        },
        url: getEndpointUrl(url, endpointRuleOptions)
      };
    };
    var evaluateErrorRule = (errorRule, options) => {
      const { conditions, error: error2 } = errorRule;
      const { result, referenceRecord } = evaluateConditions(conditions, options);
      if (!result) {
        return;
      }
      throw new EndpointError(evaluateExpression(error2, "Error", {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord }
      }));
    };
    var evaluateRules = (rules, options) => {
      for (const rule of rules) {
        if (rule.type === "endpoint") {
          const endpointOrUndefined = evaluateEndpointRule(rule, options);
          if (endpointOrUndefined) {
            return endpointOrUndefined;
          }
        } else if (rule.type === "error") {
          evaluateErrorRule(rule, options);
        } else if (rule.type === "tree") {
          const endpointOrUndefined = group.evaluateTreeRule(rule, options);
          if (endpointOrUndefined) {
            return endpointOrUndefined;
          }
        } else {
          throw new EndpointError(`Unknown endpoint rule: ${rule}`);
        }
      }
      throw new EndpointError(`Rules evaluation failed`);
    };
    var evaluateTreeRule = (treeRule, options) => {
      const { conditions, rules } = treeRule;
      const { result, referenceRecord } = evaluateConditions(conditions, options);
      if (!result) {
        return;
      }
      return group.evaluateRules(rules, {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord }
      });
    };
    var group = {
      evaluateRules,
      evaluateTreeRule
    };
    var resolveEndpoint4 = (ruleSetObject, options) => {
      const { endpointParams, logger: logger2 } = options;
      const { parameters, rules } = ruleSetObject;
      options.logger?.debug?.(`${debugId} Initial EndpointParams: ${toDebugString(endpointParams)}`);
      const paramsWithDefault = Object.entries(parameters).filter(([, v4]) => v4.default != null).map(([k4, v4]) => [k4, v4.default]);
      if (paramsWithDefault.length > 0) {
        for (const [paramKey, paramDefaultValue] of paramsWithDefault) {
          endpointParams[paramKey] = endpointParams[paramKey] ?? paramDefaultValue;
        }
      }
      const requiredParams = Object.entries(parameters).filter(([, v4]) => v4.required).map(([k4]) => k4);
      for (const requiredParam of requiredParams) {
        if (endpointParams[requiredParam] == null) {
          throw new EndpointError(`Missing required parameter: '${requiredParam}'`);
        }
      }
      const endpoint = evaluateRules(rules, { endpointParams, logger: logger2, referenceRecord: {} });
      options.logger?.debug?.(`${debugId} Resolved endpoint: ${toDebugString(endpoint)}`);
      return endpoint;
    };
    exports.EndpointCache = EndpointCache4;
    exports.EndpointError = EndpointError;
    exports.customEndpointFunctions = customEndpointFunctions4;
    exports.isIpAddress = isIpAddress;
    exports.isValidHostLabel = isValidHostLabel;
    exports.resolveEndpoint = resolveEndpoint4;
  }
});

// node_modules/@smithy/querystring-parser/dist-cjs/index.js
var require_dist_cjs20 = __commonJS({
  "node_modules/@smithy/querystring-parser/dist-cjs/index.js"(exports) {
    "use strict";
    function parseQueryString(querystring) {
      const query = {};
      querystring = querystring.replace(/^\?/, "");
      if (querystring) {
        for (const pair of querystring.split("&")) {
          let [key, value = null] = pair.split("=");
          key = decodeURIComponent(key);
          if (value) {
            value = decodeURIComponent(value);
          }
          if (!(key in query)) {
            query[key] = value;
          } else if (Array.isArray(query[key])) {
            query[key].push(value);
          } else {
            query[key] = [query[key], value];
          }
        }
      }
      return query;
    }
    exports.parseQueryString = parseQueryString;
  }
});

// node_modules/@smithy/url-parser/dist-cjs/index.js
var require_dist_cjs21 = __commonJS({
  "node_modules/@smithy/url-parser/dist-cjs/index.js"(exports) {
    "use strict";
    var querystringParser = require_dist_cjs20();
    var parseUrl4 = (url) => {
      if (typeof url === "string") {
        return parseUrl4(new URL(url));
      }
      const { hostname, pathname, port, protocol, search } = url;
      let query;
      if (search) {
        query = querystringParser.parseQueryString(search);
      }
      return {
        hostname,
        port: port ? parseInt(port) : void 0,
        protocol,
        path: pathname,
        query
      };
    };
    exports.parseUrl = parseUrl4;
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-cjs/index.js
var require_dist_cjs22 = __commonJS({
  "node_modules/@aws-sdk/util-endpoints/dist-cjs/index.js"(exports) {
    "use strict";
    var utilEndpoints = require_dist_cjs19();
    var urlParser = require_dist_cjs21();
    var isVirtualHostableS3Bucket = (value, allowSubDomains = false) => {
      if (allowSubDomains) {
        for (const label of value.split(".")) {
          if (!isVirtualHostableS3Bucket(label)) {
            return false;
          }
        }
        return true;
      }
      if (!utilEndpoints.isValidHostLabel(value)) {
        return false;
      }
      if (value.length < 3 || value.length > 63) {
        return false;
      }
      if (value !== value.toLowerCase()) {
        return false;
      }
      if (utilEndpoints.isIpAddress(value)) {
        return false;
      }
      return true;
    };
    var ARN_DELIMITER = ":";
    var RESOURCE_DELIMITER = "/";
    var parseArn = (value) => {
      const segments = value.split(ARN_DELIMITER);
      if (segments.length < 6)
        return null;
      const [arn, partition2, service, region, accountId, ...resourcePath] = segments;
      if (arn !== "arn" || partition2 === "" || service === "" || resourcePath.join(ARN_DELIMITER) === "")
        return null;
      const resourceId = resourcePath.map((resource) => resource.split(RESOURCE_DELIMITER)).flat();
      return {
        partition: partition2,
        service,
        region,
        accountId,
        resourceId
      };
    };
    var partitions = [
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
          "af-south-1": {
            description: "Africa (Cape Town)"
          },
          "ap-east-1": {
            description: "Asia Pacific (Hong Kong)"
          },
          "ap-east-2": {
            description: "Asia Pacific (Taipei)"
          },
          "ap-northeast-1": {
            description: "Asia Pacific (Tokyo)"
          },
          "ap-northeast-2": {
            description: "Asia Pacific (Seoul)"
          },
          "ap-northeast-3": {
            description: "Asia Pacific (Osaka)"
          },
          "ap-south-1": {
            description: "Asia Pacific (Mumbai)"
          },
          "ap-south-2": {
            description: "Asia Pacific (Hyderabad)"
          },
          "ap-southeast-1": {
            description: "Asia Pacific (Singapore)"
          },
          "ap-southeast-2": {
            description: "Asia Pacific (Sydney)"
          },
          "ap-southeast-3": {
            description: "Asia Pacific (Jakarta)"
          },
          "ap-southeast-4": {
            description: "Asia Pacific (Melbourne)"
          },
          "ap-southeast-5": {
            description: "Asia Pacific (Malaysia)"
          },
          "ap-southeast-6": {
            description: "Asia Pacific (New Zealand)"
          },
          "ap-southeast-7": {
            description: "Asia Pacific (Thailand)"
          },
          "aws-global": {
            description: "aws global region"
          },
          "ca-central-1": {
            description: "Canada (Central)"
          },
          "ca-west-1": {
            description: "Canada West (Calgary)"
          },
          "eu-central-1": {
            description: "Europe (Frankfurt)"
          },
          "eu-central-2": {
            description: "Europe (Zurich)"
          },
          "eu-north-1": {
            description: "Europe (Stockholm)"
          },
          "eu-south-1": {
            description: "Europe (Milan)"
          },
          "eu-south-2": {
            description: "Europe (Spain)"
          },
          "eu-west-1": {
            description: "Europe (Ireland)"
          },
          "eu-west-2": {
            description: "Europe (London)"
          },
          "eu-west-3": {
            description: "Europe (Paris)"
          },
          "il-central-1": {
            description: "Israel (Tel Aviv)"
          },
          "me-central-1": {
            description: "Middle East (UAE)"
          },
          "me-south-1": {
            description: "Middle East (Bahrain)"
          },
          "mx-central-1": {
            description: "Mexico (Central)"
          },
          "sa-east-1": {
            description: "South America (Sao Paulo)"
          },
          "us-east-1": {
            description: "US East (N. Virginia)"
          },
          "us-east-2": {
            description: "US East (Ohio)"
          },
          "us-west-1": {
            description: "US West (N. California)"
          },
          "us-west-2": {
            description: "US West (Oregon)"
          }
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
          "aws-cn-global": {
            description: "aws-cn global region"
          },
          "cn-north-1": {
            description: "China (Beijing)"
          },
          "cn-northwest-1": {
            description: "China (Ningxia)"
          }
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
        regions: {
          "eusc-de-east-1": {
            description: "EU (Germany)"
          }
        }
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
          "aws-iso-global": {
            description: "aws-iso global region"
          },
          "us-iso-east-1": {
            description: "US ISO East"
          },
          "us-iso-west-1": {
            description: "US ISO WEST"
          }
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
          "aws-iso-b-global": {
            description: "aws-iso-b global region"
          },
          "us-isob-east-1": {
            description: "US ISOB East (Ohio)"
          },
          "us-isob-west-1": {
            description: "US ISOB West"
          }
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
          "aws-iso-e-global": {
            description: "aws-iso-e global region"
          },
          "eu-isoe-west-1": {
            description: "EU ISOE West"
          }
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
          "aws-iso-f-global": {
            description: "aws-iso-f global region"
          },
          "us-isof-east-1": {
            description: "US ISOF EAST"
          },
          "us-isof-south-1": {
            description: "US ISOF SOUTH"
          }
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
          "aws-us-gov-global": {
            description: "aws-us-gov global region"
          },
          "us-gov-east-1": {
            description: "AWS GovCloud (US-East)"
          },
          "us-gov-west-1": {
            description: "AWS GovCloud (US-West)"
          }
        }
      }
    ];
    var version = "1.1";
    var partitionsInfo = {
      partitions,
      version
    };
    var selectedPartitionsInfo = partitionsInfo;
    var selectedUserAgentPrefix = "";
    var partition = (value) => {
      const { partitions: partitions2 } = selectedPartitionsInfo;
      for (const partition2 of partitions2) {
        const { regions, outputs } = partition2;
        for (const [region, regionData] of Object.entries(regions)) {
          if (region === value) {
            return {
              ...outputs,
              ...regionData
            };
          }
        }
      }
      for (const partition2 of partitions2) {
        const { regionRegex, outputs } = partition2;
        if (new RegExp(regionRegex).test(value)) {
          return {
            ...outputs
          };
        }
      }
      const DEFAULT_PARTITION = partitions2.find((partition2) => partition2.id === "aws");
      if (!DEFAULT_PARTITION) {
        throw new Error("Provided region was not found in the partition array or regex, and default partition with id 'aws' doesn't exist.");
      }
      return {
        ...DEFAULT_PARTITION.outputs
      };
    };
    var setPartitionInfo = (partitionsInfo2, userAgentPrefix = "") => {
      selectedPartitionsInfo = partitionsInfo2;
      selectedUserAgentPrefix = userAgentPrefix;
    };
    var useDefaultPartitionInfo = () => {
      setPartitionInfo(partitionsInfo, "");
    };
    var getUserAgentPrefix = () => selectedUserAgentPrefix;
    var awsEndpointFunctions4 = {
      isVirtualHostableS3Bucket,
      parseArn,
      partition
    };
    utilEndpoints.customEndpointFunctions.aws = awsEndpointFunctions4;
    var resolveDefaultAwsRegionalEndpointsConfig = (input) => {
      if (typeof input.endpointProvider !== "function") {
        throw new Error("@aws-sdk/util-endpoint - endpointProvider and endpoint missing in config for this client.");
      }
      const { endpoint } = input;
      if (endpoint === void 0) {
        input.endpoint = async () => {
          return toEndpointV1(input.endpointProvider({
            Region: typeof input.region === "function" ? await input.region() : input.region,
            UseDualStack: typeof input.useDualstackEndpoint === "function" ? await input.useDualstackEndpoint() : input.useDualstackEndpoint,
            UseFIPS: typeof input.useFipsEndpoint === "function" ? await input.useFipsEndpoint() : input.useFipsEndpoint,
            Endpoint: void 0
          }, { logger: input.logger }));
        };
      }
      return input;
    };
    var toEndpointV1 = (endpoint) => urlParser.parseUrl(endpoint.url);
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
    exports.awsEndpointFunctions = awsEndpointFunctions4;
    exports.getUserAgentPrefix = getUserAgentPrefix;
    exports.partition = partition;
    exports.resolveDefaultAwsRegionalEndpointsConfig = resolveDefaultAwsRegionalEndpointsConfig;
    exports.setPartitionInfo = setPartitionInfo;
    exports.toEndpointV1 = toEndpointV1;
    exports.useDefaultPartitionInfo = useDefaultPartitionInfo;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/emitWarningIfUnsupportedVersion.js
var state, emitWarningIfUnsupportedVersion;
var init_emitWarningIfUnsupportedVersion = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/emitWarningIfUnsupportedVersion.js"() {
    state = {
      warningEmitted: false
    };
    emitWarningIfUnsupportedVersion = (version) => {
      if (version && !state.warningEmitted && parseInt(version.substring(1, version.indexOf("."))) < 20) {
        state.warningEmitted = true;
        process.emitWarning(`NodeDeprecationWarning: The AWS SDK for JavaScript (v3) will
no longer support Node.js ${version} in January 2026.

To continue receiving updates to AWS services, bug fixes, and security
updates please upgrade to a supported Node.js LTS version.

More information can be found at: https://a.co/c895JFp`);
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js
function setCredentialFeature(credentials, feature, value) {
  if (!credentials.$source) {
    credentials.$source = {};
  }
  credentials.$source[feature] = value;
  return credentials;
}
var init_setCredentialFeature = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js
function setFeature2(context, feature, value) {
  if (!context.__aws_sdk_context) {
    context.__aws_sdk_context = {
      features: {}
    };
  } else if (!context.__aws_sdk_context.features) {
    context.__aws_sdk_context.features = {};
  }
  context.__aws_sdk_context.features[feature] = value;
}
var init_setFeature2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/setTokenFeature.js
function setTokenFeature(token, feature, value) {
  if (!token.$source) {
    token.$source = {};
  }
  token.$source[feature] = value;
  return token;
}
var init_setTokenFeature = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/setTokenFeature.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/index.js
var client_exports = {};
__export(client_exports, {
  emitWarningIfUnsupportedVersion: () => emitWarningIfUnsupportedVersion,
  setCredentialFeature: () => setCredentialFeature,
  setFeature: () => setFeature2,
  setTokenFeature: () => setTokenFeature,
  state: () => state
});
var init_client = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/index.js"() {
    init_emitWarningIfUnsupportedVersion();
    init_setCredentialFeature();
    init_setFeature2();
    init_setTokenFeature();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getDateHeader.js
var import_protocol_http9, getDateHeader;
var init_getDateHeader = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getDateHeader.js"() {
    import_protocol_http9 = __toESM(require_dist_cjs2());
    getDateHeader = (response) => import_protocol_http9.HttpResponse.isInstance(response) ? response.headers?.date ?? response.headers?.Date : void 0;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.js
var getSkewCorrectedDate;
var init_getSkewCorrectedDate = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.js"() {
    getSkewCorrectedDate = (systemClockOffset) => new Date(Date.now() + systemClockOffset);
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/isClockSkewed.js
var isClockSkewed;
var init_isClockSkewed = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/isClockSkewed.js"() {
    init_getSkewCorrectedDate();
    isClockSkewed = (clockTime, systemClockOffset) => Math.abs(getSkewCorrectedDate(systemClockOffset).getTime() - clockTime) >= 3e5;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.js
var getUpdatedSystemClockOffset;
var init_getUpdatedSystemClockOffset = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.js"() {
    init_isClockSkewed();
    getUpdatedSystemClockOffset = (clockTime, currentSystemClockOffset) => {
      const clockTimeInMs = Date.parse(clockTime);
      if (isClockSkewed(clockTimeInMs, currentSystemClockOffset)) {
        return clockTimeInMs - Date.now();
      }
      return currentSystemClockOffset;
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/index.js
var init_utils = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/index.js"() {
    init_getDateHeader();
    init_getSkewCorrectedDate();
    init_getUpdatedSystemClockOffset();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js
var import_protocol_http10, throwSigningPropertyError, validateSigningProperties, AwsSdkSigV4Signer, AWSSDKSigV4Signer;
var init_AwsSdkSigV4Signer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js"() {
    import_protocol_http10 = __toESM(require_dist_cjs2());
    init_utils();
    throwSigningPropertyError = (name, property) => {
      if (!property) {
        throw new Error(`Property \`${name}\` is not resolved for AWS SDK SigV4Auth`);
      }
      return property;
    };
    validateSigningProperties = async (signingProperties) => {
      const context = throwSigningPropertyError("context", signingProperties.context);
      const config = throwSigningPropertyError("config", signingProperties.config);
      const authScheme = context.endpointV2?.properties?.authSchemes?.[0];
      const signerFunction = throwSigningPropertyError("signer", config.signer);
      const signer = await signerFunction(authScheme);
      const signingRegion = signingProperties?.signingRegion;
      const signingRegionSet = signingProperties?.signingRegionSet;
      const signingName = signingProperties?.signingName;
      return {
        config,
        signer,
        signingRegion,
        signingRegionSet,
        signingName
      };
    };
    AwsSdkSigV4Signer = class {
      async sign(httpRequest, identity, signingProperties) {
        if (!import_protocol_http10.HttpRequest.isInstance(httpRequest)) {
          throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
        }
        const validatedProps = await validateSigningProperties(signingProperties);
        const { config, signer } = validatedProps;
        let { signingRegion, signingName } = validatedProps;
        const handlerExecutionContext = signingProperties.context;
        if (handlerExecutionContext?.authSchemes?.length ?? 0 > 1) {
          const [first, second] = handlerExecutionContext.authSchemes;
          if (first?.name === "sigv4a" && second?.name === "sigv4") {
            signingRegion = second?.signingRegion ?? signingRegion;
            signingName = second?.signingName ?? signingName;
          }
        }
        const signedRequest = await signer.sign(httpRequest, {
          signingDate: getSkewCorrectedDate(config.systemClockOffset),
          signingRegion,
          signingService: signingName
        });
        return signedRequest;
      }
      errorHandler(signingProperties) {
        return (error2) => {
          const serverTime = error2.ServerTime ?? getDateHeader(error2.$response);
          if (serverTime) {
            const config = throwSigningPropertyError("config", signingProperties.config);
            const initialSystemClockOffset = config.systemClockOffset;
            config.systemClockOffset = getUpdatedSystemClockOffset(serverTime, config.systemClockOffset);
            const clockSkewCorrected = config.systemClockOffset !== initialSystemClockOffset;
            if (clockSkewCorrected && error2.$metadata) {
              error2.$metadata.clockSkewCorrected = true;
            }
          }
          throw error2;
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
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4ASigner.js
var import_protocol_http11, AwsSdkSigV4ASigner;
var init_AwsSdkSigV4ASigner = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4ASigner.js"() {
    import_protocol_http11 = __toESM(require_dist_cjs2());
    init_utils();
    init_AwsSdkSigV4Signer();
    AwsSdkSigV4ASigner = class extends AwsSdkSigV4Signer {
      async sign(httpRequest, identity, signingProperties) {
        if (!import_protocol_http11.HttpRequest.isInstance(httpRequest)) {
          throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
        }
        const { config, signer, signingRegion, signingRegionSet, signingName } = await validateSigningProperties(signingProperties);
        const configResolvedSigningRegionSet = await config.sigv4aSigningRegionSet?.();
        const multiRegionOverride = (configResolvedSigningRegionSet ?? signingRegionSet ?? [signingRegion]).join(",");
        const signedRequest = await signer.sign(httpRequest, {
          signingDate: getSkewCorrectedDate(config.systemClockOffset),
          signingRegion: multiRegionOverride,
          signingService: signingName
        });
        return signedRequest;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getArrayForCommaSeparatedString.js
var getArrayForCommaSeparatedString;
var init_getArrayForCommaSeparatedString = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getArrayForCommaSeparatedString.js"() {
    getArrayForCommaSeparatedString = (str) => typeof str === "string" && str.length > 0 ? str.split(",").map((item) => item.trim()) : [];
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getBearerTokenEnvKey.js
var getBearerTokenEnvKey;
var init_getBearerTokenEnvKey = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getBearerTokenEnvKey.js"() {
    getBearerTokenEnvKey = (signingName) => `AWS_BEARER_TOKEN_${signingName.replace(/[\s-]/g, "_").toUpperCase()}`;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/NODE_AUTH_SCHEME_PREFERENCE_OPTIONS.js
var NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY, NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY, NODE_AUTH_SCHEME_PREFERENCE_OPTIONS;
var init_NODE_AUTH_SCHEME_PREFERENCE_OPTIONS = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/NODE_AUTH_SCHEME_PREFERENCE_OPTIONS.js"() {
    init_getArrayForCommaSeparatedString();
    init_getBearerTokenEnvKey();
    NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY = "AWS_AUTH_SCHEME_PREFERENCE";
    NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY = "auth_scheme_preference";
    NODE_AUTH_SCHEME_PREFERENCE_OPTIONS = {
      environmentVariableSelector: (env, options) => {
        if (options?.signingName) {
          const bearerTokenKey = getBearerTokenEnvKey(options.signingName);
          if (bearerTokenKey in env)
            return ["httpBearerAuth"];
        }
        if (!(NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY in env))
          return void 0;
        return getArrayForCommaSeparatedString(env[NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY]);
      },
      configFileSelector: (profile) => {
        if (!(NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY in profile))
          return void 0;
        return getArrayForCommaSeparatedString(profile[NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY]);
      },
      default: []
    };
  }
});

// node_modules/@smithy/property-provider/dist-cjs/index.js
var require_dist_cjs23 = __commonJS({
  "node_modules/@smithy/property-provider/dist-cjs/index.js"(exports) {
    "use strict";
    var ProviderError2 = class _ProviderError extends Error {
      name = "ProviderError";
      tryNextLink;
      constructor(message, options = true) {
        let logger2;
        let tryNextLink = true;
        if (typeof options === "boolean") {
          logger2 = void 0;
          tryNextLink = options;
        } else if (options != null && typeof options === "object") {
          logger2 = options.logger;
          tryNextLink = options.tryNextLink ?? true;
        }
        super(message);
        this.tryNextLink = tryNextLink;
        Object.setPrototypeOf(this, _ProviderError.prototype);
        logger2?.debug?.(`@smithy/property-provider ${tryNextLink ? "->" : "(!)"} ${message}`);
      }
      static from(error2, options = true) {
        return Object.assign(new this(error2.message, options), error2);
      }
    };
    var CredentialsProviderError = class _CredentialsProviderError extends ProviderError2 {
      name = "CredentialsProviderError";
      constructor(message, options = true) {
        super(message, options);
        Object.setPrototypeOf(this, _CredentialsProviderError.prototype);
      }
    };
    var TokenProviderError = class _TokenProviderError extends ProviderError2 {
      name = "TokenProviderError";
      constructor(message, options = true) {
        super(message, options);
        Object.setPrototypeOf(this, _TokenProviderError.prototype);
      }
    };
    var chain = (...providers) => async () => {
      if (providers.length === 0) {
        throw new ProviderError2("No providers in chain");
      }
      let lastProviderError;
      for (const provider of providers) {
        try {
          const credentials = await provider();
          return credentials;
        } catch (err) {
          lastProviderError = err;
          if (err?.tryNextLink) {
            continue;
          }
          throw err;
        }
      }
      throw lastProviderError;
    };
    var fromStatic = (staticValue) => () => Promise.resolve(staticValue);
    var memoize = (provider, isExpired, requiresRefresh) => {
      let resolved;
      let pending;
      let hasResult;
      let isConstant = false;
      const coalesceProvider = async () => {
        if (!pending) {
          pending = provider();
        }
        try {
          resolved = await pending;
          hasResult = true;
          isConstant = false;
        } finally {
          pending = void 0;
        }
        return resolved;
      };
      if (isExpired === void 0) {
        return async (options) => {
          if (!hasResult || options?.forceRefresh) {
            resolved = await coalesceProvider();
          }
          return resolved;
        };
      }
      return async (options) => {
        if (!hasResult || options?.forceRefresh) {
          resolved = await coalesceProvider();
        }
        if (isConstant) {
          return resolved;
        }
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
    exports.ProviderError = ProviderError2;
    exports.TokenProviderError = TokenProviderError;
    exports.chain = chain;
    exports.fromStatic = fromStatic;
    exports.memoize = memoize;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4AConfig.js
var import_property_provider, resolveAwsSdkSigV4AConfig, NODE_SIGV4A_CONFIG_OPTIONS;
var init_resolveAwsSdkSigV4AConfig = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4AConfig.js"() {
    init_dist_es();
    import_property_provider = __toESM(require_dist_cjs23());
    resolveAwsSdkSigV4AConfig = (config) => {
      config.sigv4aSigningRegionSet = normalizeProvider(config.sigv4aSigningRegionSet);
      return config;
    };
    NODE_SIGV4A_CONFIG_OPTIONS = {
      environmentVariableSelector(env) {
        if (env.AWS_SIGV4A_SIGNING_REGION_SET) {
          return env.AWS_SIGV4A_SIGNING_REGION_SET.split(",").map((_) => _.trim());
        }
        throw new import_property_provider.ProviderError("AWS_SIGV4A_SIGNING_REGION_SET not set in env.", {
          tryNextLink: true
        });
      },
      configFileSelector(profile) {
        if (profile.sigv4a_signing_region_set) {
          return (profile.sigv4a_signing_region_set ?? "").split(",").map((_) => _.trim());
        }
        throw new import_property_provider.ProviderError("sigv4a_signing_region_set not set in profile.", {
          tryNextLink: true
        });
      },
      default: void 0
    };
  }
});

// node_modules/@smithy/signature-v4/dist-cjs/index.js
var require_dist_cjs24 = __commonJS({
  "node_modules/@smithy/signature-v4/dist-cjs/index.js"(exports) {
    "use strict";
    var utilHexEncoding = require_dist_cjs16();
    var utilUtf8 = require_dist_cjs10();
    var isArrayBuffer = require_dist_cjs8();
    var protocolHttp = require_dist_cjs2();
    var utilMiddleware = require_dist_cjs6();
    var utilUriEscape = require_dist_cjs12();
    var ALGORITHM_QUERY_PARAM = "X-Amz-Algorithm";
    var CREDENTIAL_QUERY_PARAM = "X-Amz-Credential";
    var AMZ_DATE_QUERY_PARAM = "X-Amz-Date";
    var SIGNED_HEADERS_QUERY_PARAM = "X-Amz-SignedHeaders";
    var EXPIRES_QUERY_PARAM = "X-Amz-Expires";
    var SIGNATURE_QUERY_PARAM = "X-Amz-Signature";
    var TOKEN_QUERY_PARAM = "X-Amz-Security-Token";
    var REGION_SET_PARAM = "X-Amz-Region-Set";
    var AUTH_HEADER = "authorization";
    var AMZ_DATE_HEADER = AMZ_DATE_QUERY_PARAM.toLowerCase();
    var DATE_HEADER = "date";
    var GENERATED_HEADERS = [AUTH_HEADER, AMZ_DATE_HEADER, DATE_HEADER];
    var SIGNATURE_HEADER = SIGNATURE_QUERY_PARAM.toLowerCase();
    var SHA256_HEADER = "x-amz-content-sha256";
    var TOKEN_HEADER = TOKEN_QUERY_PARAM.toLowerCase();
    var HOST_HEADER = "host";
    var ALWAYS_UNSIGNABLE_HEADERS = {
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
    var PROXY_HEADER_PATTERN = /^proxy-/;
    var SEC_HEADER_PATTERN = /^sec-/;
    var UNSIGNABLE_PATTERNS = [/^proxy-/i, /^sec-/i];
    var ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256";
    var ALGORITHM_IDENTIFIER_V4A = "AWS4-ECDSA-P256-SHA256";
    var EVENT_ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256-PAYLOAD";
    var UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    var MAX_CACHE_SIZE = 50;
    var KEY_TYPE_IDENTIFIER = "aws4_request";
    var MAX_PRESIGNED_TTL = 60 * 60 * 24 * 7;
    var signingKeyCache = {};
    var cacheQueue = [];
    var createScope = (shortDate, region, service) => `${shortDate}/${region}/${service}/${KEY_TYPE_IDENTIFIER}`;
    var getSigningKey = async (sha256Constructor, credentials, shortDate, region, service) => {
      const credsHash = await hmac(sha256Constructor, credentials.secretAccessKey, credentials.accessKeyId);
      const cacheKey = `${shortDate}:${region}:${service}:${utilHexEncoding.toHex(credsHash)}:${credentials.sessionToken}`;
      if (cacheKey in signingKeyCache) {
        return signingKeyCache[cacheKey];
      }
      cacheQueue.push(cacheKey);
      while (cacheQueue.length > MAX_CACHE_SIZE) {
        delete signingKeyCache[cacheQueue.shift()];
      }
      let key = `AWS4${credentials.secretAccessKey}`;
      for (const signable of [shortDate, region, service, KEY_TYPE_IDENTIFIER]) {
        key = await hmac(sha256Constructor, key, signable);
      }
      return signingKeyCache[cacheKey] = key;
    };
    var clearCredentialCache = () => {
      cacheQueue.length = 0;
      Object.keys(signingKeyCache).forEach((cacheKey) => {
        delete signingKeyCache[cacheKey];
      });
    };
    var hmac = (ctor, secret, data2) => {
      const hash = new ctor(secret);
      hash.update(utilUtf8.toUint8Array(data2));
      return hash.digest();
    };
    var getCanonicalHeaders = ({ headers }, unsignableHeaders, signableHeaders) => {
      const canonical = {};
      for (const headerName of Object.keys(headers).sort()) {
        if (headers[headerName] == void 0) {
          continue;
        }
        const canonicalHeaderName = headerName.toLowerCase();
        if (canonicalHeaderName in ALWAYS_UNSIGNABLE_HEADERS || unsignableHeaders?.has(canonicalHeaderName) || PROXY_HEADER_PATTERN.test(canonicalHeaderName) || SEC_HEADER_PATTERN.test(canonicalHeaderName)) {
          if (!signableHeaders || signableHeaders && !signableHeaders.has(canonicalHeaderName)) {
            continue;
          }
        }
        canonical[canonicalHeaderName] = headers[headerName].trim().replace(/\s+/g, " ");
      }
      return canonical;
    };
    var getPayloadHash = async ({ headers, body }, hashConstructor) => {
      for (const headerName of Object.keys(headers)) {
        if (headerName.toLowerCase() === SHA256_HEADER) {
          return headers[headerName];
        }
      }
      if (body == void 0) {
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      } else if (typeof body === "string" || ArrayBuffer.isView(body) || isArrayBuffer.isArrayBuffer(body)) {
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
          case "boolean":
            return Uint8Array.from([header.value ? 0 : 1]);
          case "byte":
            return Uint8Array.from([2, header.value]);
          case "short":
            const shortView = new DataView(new ArrayBuffer(3));
            shortView.setUint8(0, 3);
            shortView.setInt16(1, header.value, false);
            return new Uint8Array(shortView.buffer);
          case "integer":
            const intView = new DataView(new ArrayBuffer(5));
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
            if (!UUID_PATTERN.test(header.value)) {
              throw new Error(`Invalid UUID received: ${header.value}`);
            }
            const uuidBytes = new Uint8Array(17);
            uuidBytes[0] = 9;
            uuidBytes.set(utilHexEncoding.fromHex(header.value.replace(/\-/g, "")), 1);
            return uuidBytes;
        }
      }
    };
    var UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
    var Int64 = class _Int64 {
      bytes;
      constructor(bytes) {
        this.bytes = bytes;
        if (bytes.byteLength !== 8) {
          throw new Error("Int64 buffers must be exactly 8 bytes");
        }
      }
      static fromNumber(number) {
        if (number > 9223372036854776e3 || number < -9223372036854776e3) {
          throw new Error(`${number} is too large (or, if negative, too small) to represent as an Int64`);
        }
        const bytes = new Uint8Array(8);
        for (let i4 = 7, remaining = Math.abs(Math.round(number)); i4 > -1 && remaining > 0; i4--, remaining /= 256) {
          bytes[i4] = remaining;
        }
        if (number < 0) {
          negate(bytes);
        }
        return new _Int64(bytes);
      }
      valueOf() {
        const bytes = this.bytes.slice(0);
        const negative = bytes[0] & 128;
        if (negative) {
          negate(bytes);
        }
        return parseInt(utilHexEncoding.toHex(bytes), 16) * (negative ? -1 : 1);
      }
      toString() {
        return String(this.valueOf());
      }
    };
    function negate(bytes) {
      for (let i4 = 0; i4 < 8; i4++) {
        bytes[i4] ^= 255;
      }
      for (let i4 = 7; i4 > -1; i4--) {
        bytes[i4]++;
        if (bytes[i4] !== 0)
          break;
      }
    }
    var hasHeader = (soughtHeader, headers) => {
      soughtHeader = soughtHeader.toLowerCase();
      for (const headerName of Object.keys(headers)) {
        if (soughtHeader === headerName.toLowerCase()) {
          return true;
        }
      }
      return false;
    };
    var moveHeadersToQuery = (request, options = {}) => {
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
    var prepareRequest = (request) => {
      request = protocolHttp.HttpRequest.clone(request);
      for (const headerName of Object.keys(request.headers)) {
        if (GENERATED_HEADERS.indexOf(headerName.toLowerCase()) > -1) {
          delete request.headers[headerName];
        }
      }
      return request;
    };
    var getCanonicalQuery = ({ query = {} }) => {
      const keys = [];
      const serialized = {};
      for (const key of Object.keys(query)) {
        if (key.toLowerCase() === SIGNATURE_HEADER) {
          continue;
        }
        const encodedKey = utilUriEscape.escapeUri(key);
        keys.push(encodedKey);
        const value = query[key];
        if (typeof value === "string") {
          serialized[encodedKey] = `${encodedKey}=${utilUriEscape.escapeUri(value)}`;
        } else if (Array.isArray(value)) {
          serialized[encodedKey] = value.slice(0).reduce((encoded, value2) => encoded.concat([`${encodedKey}=${utilUriEscape.escapeUri(value2)}`]), []).sort().join("&");
        }
      }
      return keys.sort().map((key) => serialized[key]).filter((serialized2) => serialized2).join("&");
    };
    var iso8601 = (time2) => toDate(time2).toISOString().replace(/\.\d{3}Z$/, "Z");
    var toDate = (time2) => {
      if (typeof time2 === "number") {
        return new Date(time2 * 1e3);
      }
      if (typeof time2 === "string") {
        if (Number(time2)) {
          return new Date(Number(time2) * 1e3);
        }
        return new Date(time2);
      }
      return time2;
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
      getCanonicalPath({ path }) {
        if (this.uriEscapePath) {
          const normalizedPathSegments = [];
          for (const pathSegment of path.split("/")) {
            if (pathSegment?.length === 0)
              continue;
            if (pathSegment === ".")
              continue;
            if (pathSegment === "..") {
              normalizedPathSegments.pop();
            } else {
              normalizedPathSegments.push(pathSegment);
            }
          }
          const normalizedPath = `${path?.startsWith("/") ? "/" : ""}${normalizedPathSegments.join("/")}${normalizedPathSegments.length > 0 && path?.endsWith("/") ? "/" : ""}`;
          const doubleEncoded = utilUriEscape.escapeUri(normalizedPath);
          return doubleEncoded.replace(/%2F/g, "/");
        }
        return path;
      }
      validateResolvedCredentials(credentials) {
        if (typeof credentials !== "object" || typeof credentials.accessKeyId !== "string" || typeof credentials.secretAccessKey !== "string") {
          throw new Error("Resolved credential object is not valid");
        }
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
    var SignatureV42 = class extends SignatureV4Base {
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
        if (expiresIn > MAX_PRESIGNED_TTL) {
          return Promise.reject("Signature version 4 presigned URLs must have an expiration date less than one week in the future");
        }
        const scope = createScope(shortDate, region, signingService ?? this.service);
        const request = moveHeadersToQuery(prepareRequest(originalRequest), { unhoistableHeaders, hoistableHeaders });
        if (credentials.sessionToken) {
          request.query[TOKEN_QUERY_PARAM] = credentials.sessionToken;
        }
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
        if (typeof toSign === "string") {
          return this.signString(toSign, options);
        } else if (toSign.headers && toSign.payload) {
          return this.signEvent(toSign, options);
        } else if (toSign.message) {
          return this.signMessage(toSign, options);
        } else {
          return this.signRequest(toSign, options);
        }
      }
      async signEvent({ headers, payload: payload2 }, { signingDate = /* @__PURE__ */ new Date(), priorSignature, signingRegion, signingService }) {
        const region = signingRegion ?? await this.regionProvider();
        const { shortDate, longDate } = this.formatDate(signingDate);
        const scope = createScope(shortDate, region, signingService ?? this.service);
        const hashedPayload = await getPayloadHash({ headers: {}, body: payload2 }, this.sha256);
        const hash = new this.sha256();
        hash.update(headers);
        const hashedHeaders = utilHexEncoding.toHex(await hash.digest());
        const stringToSign = [
          EVENT_ALGORITHM_IDENTIFIER,
          longDate,
          scope,
          priorSignature,
          hashedHeaders,
          hashedPayload
        ].join("\n");
        return this.signString(stringToSign, { signingDate, signingRegion: region, signingService });
      }
      async signMessage(signableMessage, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService }) {
        const promise = this.signEvent({
          headers: this.headerFormatter.format(signableMessage.message.headers),
          payload: signableMessage.message.body
        }, {
          signingDate,
          signingRegion,
          signingService,
          priorSignature: signableMessage.priorSignature
        });
        return promise.then((signature) => {
          return { message: signableMessage.message, signature };
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
        if (credentials.sessionToken) {
          request.headers[TOKEN_HEADER] = credentials.sessionToken;
        }
        const payloadHash = await getPayloadHash(request, this.sha256);
        if (!hasHeader(SHA256_HEADER, request.headers) && this.applyChecksum) {
          request.headers[SHA256_HEADER] = payloadHash;
        }
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
    var signatureV4aContainer = {
      SignatureV4a: null
    };
    exports.ALGORITHM_IDENTIFIER = ALGORITHM_IDENTIFIER;
    exports.ALGORITHM_IDENTIFIER_V4A = ALGORITHM_IDENTIFIER_V4A;
    exports.ALGORITHM_QUERY_PARAM = ALGORITHM_QUERY_PARAM;
    exports.ALWAYS_UNSIGNABLE_HEADERS = ALWAYS_UNSIGNABLE_HEADERS;
    exports.AMZ_DATE_HEADER = AMZ_DATE_HEADER;
    exports.AMZ_DATE_QUERY_PARAM = AMZ_DATE_QUERY_PARAM;
    exports.AUTH_HEADER = AUTH_HEADER;
    exports.CREDENTIAL_QUERY_PARAM = CREDENTIAL_QUERY_PARAM;
    exports.DATE_HEADER = DATE_HEADER;
    exports.EVENT_ALGORITHM_IDENTIFIER = EVENT_ALGORITHM_IDENTIFIER;
    exports.EXPIRES_QUERY_PARAM = EXPIRES_QUERY_PARAM;
    exports.GENERATED_HEADERS = GENERATED_HEADERS;
    exports.HOST_HEADER = HOST_HEADER;
    exports.KEY_TYPE_IDENTIFIER = KEY_TYPE_IDENTIFIER;
    exports.MAX_CACHE_SIZE = MAX_CACHE_SIZE;
    exports.MAX_PRESIGNED_TTL = MAX_PRESIGNED_TTL;
    exports.PROXY_HEADER_PATTERN = PROXY_HEADER_PATTERN;
    exports.REGION_SET_PARAM = REGION_SET_PARAM;
    exports.SEC_HEADER_PATTERN = SEC_HEADER_PATTERN;
    exports.SHA256_HEADER = SHA256_HEADER;
    exports.SIGNATURE_HEADER = SIGNATURE_HEADER;
    exports.SIGNATURE_QUERY_PARAM = SIGNATURE_QUERY_PARAM;
    exports.SIGNED_HEADERS_QUERY_PARAM = SIGNED_HEADERS_QUERY_PARAM;
    exports.SignatureV4 = SignatureV42;
    exports.SignatureV4Base = SignatureV4Base;
    exports.TOKEN_HEADER = TOKEN_HEADER;
    exports.TOKEN_QUERY_PARAM = TOKEN_QUERY_PARAM;
    exports.UNSIGNABLE_PATTERNS = UNSIGNABLE_PATTERNS;
    exports.UNSIGNED_PAYLOAD = UNSIGNED_PAYLOAD;
    exports.clearCredentialCache = clearCredentialCache;
    exports.createScope = createScope;
    exports.getCanonicalHeaders = getCanonicalHeaders;
    exports.getCanonicalQuery = getCanonicalQuery;
    exports.getPayloadHash = getPayloadHash;
    exports.getSigningKey = getSigningKey;
    exports.hasHeader = hasHeader;
    exports.moveHeadersToQuery = moveHeadersToQuery;
    exports.prepareRequest = prepareRequest;
    exports.signatureV4aContainer = signatureV4aContainer;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.js
function normalizeCredentialProvider(config, { credentials, credentialDefaultProvider }) {
  let credentialsProvider;
  if (credentials) {
    if (!credentials?.memoized) {
      credentialsProvider = memoizeIdentityProvider(credentials, isIdentityExpired, doesIdentityRequireRefresh);
    } else {
      credentialsProvider = credentials;
    }
  } else {
    if (credentialDefaultProvider) {
      credentialsProvider = normalizeProvider(credentialDefaultProvider(Object.assign({}, config, {
        parentClientConfig: config
      })));
    } else {
      credentialsProvider = async () => {
        throw new Error("@aws-sdk/core::resolveAwsSdkSigV4Config - `credentials` not provided and no credentialDefaultProvider was configured.");
      };
    }
  }
  credentialsProvider.memoized = true;
  return credentialsProvider;
}
function bindCallerConfig(config, credentialsProvider) {
  if (credentialsProvider.configBound) {
    return credentialsProvider;
  }
  const fn = async (options) => credentialsProvider({ ...options, callerClientConfig: config });
  fn.memoized = credentialsProvider.memoized;
  fn.configBound = true;
  return fn;
}
var import_signature_v4, resolveAwsSdkSigV4Config, resolveAWSSDKSigV4Config;
var init_resolveAwsSdkSigV4Config = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.js"() {
    init_client();
    init_dist_es();
    import_signature_v4 = __toESM(require_dist_cjs24());
    resolveAwsSdkSigV4Config = (config) => {
      let inputCredentials = config.credentials;
      let isUserSupplied = !!config.credentials;
      let resolvedCredentials = void 0;
      Object.defineProperty(config, "credentials", {
        set(credentials) {
          if (credentials && credentials !== inputCredentials && credentials !== resolvedCredentials) {
            isUserSupplied = true;
          }
          inputCredentials = credentials;
          const memoizedProvider = normalizeCredentialProvider(config, {
            credentials: inputCredentials,
            credentialDefaultProvider: config.credentialDefaultProvider
          });
          const boundProvider = bindCallerConfig(config, memoizedProvider);
          if (isUserSupplied && !boundProvider.attributed) {
            resolvedCredentials = async (options) => boundProvider(options).then((creds) => setCredentialFeature(creds, "CREDENTIALS_CODE", "e"));
            resolvedCredentials.memoized = boundProvider.memoized;
            resolvedCredentials.configBound = boundProvider.configBound;
            resolvedCredentials.attributed = true;
          } else {
            resolvedCredentials = boundProvider;
          }
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
      if (config.signer) {
        signer = normalizeProvider(config.signer);
      } else if (config.regionInfoProvider) {
        signer = () => normalizeProvider(config.region)().then(async (region) => [
          await config.regionInfoProvider(region, {
            useFipsEndpoint: await config.useFipsEndpoint(),
            useDualstackEndpoint: await config.useDualstackEndpoint()
          }) || {},
          region
        ]).then(([regionInfo, region]) => {
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
          const SignerCtor = config.signerConstructor || import_signature_v4.SignatureV4;
          return new SignerCtor(params);
        });
      } else {
        signer = async (authScheme) => {
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
          const SignerCtor = config.signerConstructor || import_signature_v4.SignatureV4;
          return new SignerCtor(params);
        };
      }
      const resolvedConfig = Object.assign(config, {
        systemClockOffset,
        signingEscapePath,
        signer
      });
      return resolvedConfig;
    };
    resolveAWSSDKSigV4Config = resolveAwsSdkSigV4Config;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/index.js
var init_aws_sdk = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/index.js"() {
    init_AwsSdkSigV4Signer();
    init_AwsSdkSigV4ASigner();
    init_NODE_AUTH_SCHEME_PREFERENCE_OPTIONS();
    init_resolveAwsSdkSigV4AConfig();
    init_resolveAwsSdkSigV4Config();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/index.js
var httpAuthSchemes_exports = {};
__export(httpAuthSchemes_exports, {
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
var init_httpAuthSchemes2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/index.js"() {
    init_aws_sdk();
    init_getBearerTokenEnvKey();
  }
});

// node_modules/@smithy/core/dist-es/submodules/cbor/cbor-types.js
function alloc(size) {
  return typeof Buffer !== "undefined" ? Buffer.alloc(size) : new Uint8Array(size);
}
function tag(data2) {
  data2[tagSymbol] = true;
  return data2;
}
var majorUint64, majorNegativeInt64, majorUnstructuredByteString, majorUtf8String, majorList, majorMap, majorTag, majorSpecial, specialFalse, specialTrue, specialNull, specialUndefined, extendedOneByte, extendedFloat16, extendedFloat32, extendedFloat64, minorIndefinite, tagSymbol;
var init_cbor_types = __esm({
  "node_modules/@smithy/core/dist-es/submodules/cbor/cbor-types.js"() {
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
    tagSymbol = /* @__PURE__ */ Symbol("@smithy/core/cbor::tagSymbol");
  }
});

// node_modules/@smithy/core/dist-es/submodules/cbor/cbor-decode.js
function setPayload(bytes) {
  payload = bytes;
  dataView = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
}
function decode(at, to) {
  if (at >= to) {
    throw new Error("unexpected end of (decode) payload.");
  }
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
      } else {
        switch (minor) {
          case extendedOneByte:
          case extendedFloat16:
          case extendedFloat32:
          case extendedFloat64:
            const countLength = minorValueToArgumentLength[minor];
            const countOffset = countLength + 1;
            offset = countOffset;
            if (to - at < countOffset) {
              throw new Error(`countLength ${countLength} greater than remaining buf len.`);
            }
            const countIndex = at + 1;
            if (countLength === 1) {
              unsignedInt = payload[countIndex];
            } else if (countLength === 2) {
              unsignedInt = dataView.getUint16(countIndex);
            } else if (countLength === 4) {
              unsignedInt = dataView.getUint32(countIndex);
            } else {
              unsignedInt = dataView.getBigUint64(countIndex);
            }
            break;
          default:
            throw new Error(`unexpected minor value ${minor}.`);
        }
      }
      if (major === majorUint64) {
        _offset = offset;
        return castBigInt(unsignedInt);
      } else if (major === majorNegativeInt64) {
        let negativeInt;
        if (typeof unsignedInt === "bigint") {
          negativeInt = BigInt(-1) - unsignedInt;
        } else {
          negativeInt = -1 - unsignedInt;
        }
        _offset = offset;
        return castBigInt(negativeInt);
      } else {
        if (minor === 2 || minor === 3) {
          const length = decodeCount(at + offset, to);
          let b4 = BigInt(0);
          const start = at + offset + _offset;
          for (let i4 = start; i4 < start + length; ++i4) {
            b4 = b4 << BigInt(8) | BigInt(payload[i4]);
          }
          _offset = offset + _offset + length;
          return minor === 3 ? -b4 - BigInt(1) : b4;
        } else if (minor === 4) {
          const decimalFraction = decode(at + offset, to);
          const [exponent, mantissa] = decimalFraction;
          const normalizer = mantissa < 0 ? -1 : 1;
          const mantissaStr = "0".repeat(Math.abs(exponent) + 1) + String(BigInt(normalizer) * BigInt(mantissa));
          let numericString;
          const sign = mantissa < 0 ? "-" : "";
          numericString = exponent === 0 ? mantissaStr : mantissaStr.slice(0, mantissaStr.length + exponent) + "." + mantissaStr.slice(exponent);
          numericString = numericString.replace(/^0+/g, "");
          if (numericString === "") {
            numericString = "0";
          }
          if (numericString[0] === ".") {
            numericString = "0" + numericString;
          }
          numericString = sign + numericString;
          _offset = offset + _offset;
          return nv(numericString);
        } else {
          const value = decode(at + offset, to);
          const valueOffset = _offset;
          _offset = offset + valueOffset;
          return tag({ tag: castBigInt(unsignedInt), value });
        }
      }
    case majorUtf8String:
    case majorMap:
    case majorList:
    case majorUnstructuredByteString:
      if (minor === minorIndefinite) {
        switch (major) {
          case majorUtf8String:
            return decodeUtf8StringIndefinite(at, to);
          case majorMap:
            return decodeMapIndefinite(at, to);
          case majorList:
            return decodeListIndefinite(at, to);
          case majorUnstructuredByteString:
            return decodeUnstructuredByteStringIndefinite(at, to);
        }
      } else {
        switch (major) {
          case majorUtf8String:
            return decodeUtf8String(at, to);
          case majorMap:
            return decodeMap(at, to);
          case majorList:
            return decodeList(at, to);
          case majorUnstructuredByteString:
            return decodeUnstructuredByteString(at, to);
        }
      }
    default:
      return decodeSpecial(at, to);
  }
}
function bytesToUtf8(bytes, at, to) {
  if (USE_BUFFER && bytes.constructor?.name === "Buffer") {
    return bytes.toString("utf-8", at, to);
  }
  if (textDecoder) {
    return textDecoder.decode(bytes.subarray(at, to));
  }
  return (0, import_util_utf84.toUtf8)(bytes.subarray(at, to));
}
function demote(bigInteger) {
  const num = Number(bigInteger);
  if (num < Number.MIN_SAFE_INTEGER || Number.MAX_SAFE_INTEGER < num) {
    console.warn(new Error(`@smithy/core/cbor - truncating BigInt(${bigInteger}) to ${num} with loss of precision.`));
  }
  return num;
}
function bytesToFloat16(a4, b4) {
  const sign = a4 >> 7;
  const exponent = (a4 & 124) >> 2;
  const fraction = (a4 & 3) << 8 | b4;
  const scalar = sign === 0 ? 1 : -1;
  let exponentComponent;
  let summation;
  if (exponent === 0) {
    if (fraction === 0) {
      return 0;
    } else {
      exponentComponent = Math.pow(2, 1 - 15);
      summation = 0;
    }
  } else if (exponent === 31) {
    if (fraction === 0) {
      return scalar * Infinity;
    } else {
      return NaN;
    }
  } else {
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
    if (to - at < _offset) {
      throw new Error(`countLength ${countLength} greater than remaining buf len.`);
    }
    const countIndex = at + 1;
    if (countLength === 1) {
      return payload[countIndex];
    } else if (countLength === 2) {
      return dataView.getUint16(countIndex);
    } else if (countLength === 4) {
      return dataView.getUint32(countIndex);
    }
    return demote(dataView.getBigUint64(countIndex));
  }
  throw new Error(`unexpected minor value ${minor}.`);
}
function decodeUtf8String(at, to) {
  const length = decodeCount(at, to);
  const offset = _offset;
  at += offset;
  if (to - at < length) {
    throw new Error(`string len ${length} greater than remaining buf len.`);
  }
  const value = bytesToUtf8(payload, at, at + length);
  _offset = offset + length;
  return value;
}
function decodeUtf8StringIndefinite(at, to) {
  at += 1;
  const vector = [];
  for (const base = at; at < to; ) {
    if (payload[at] === 255) {
      const data2 = alloc(vector.length);
      data2.set(vector, 0);
      _offset = at - base + 2;
      return bytesToUtf8(data2, 0, data2.length);
    }
    const major = (payload[at] & 224) >> 5;
    const minor = payload[at] & 31;
    if (major !== majorUtf8String) {
      throw new Error(`unexpected major type ${major} in indefinite string.`);
    }
    if (minor === minorIndefinite) {
      throw new Error("nested indefinite string.");
    }
    const bytes = decodeUnstructuredByteString(at, to);
    const length = _offset;
    at += length;
    for (let i4 = 0; i4 < bytes.length; ++i4) {
      vector.push(bytes[i4]);
    }
  }
  throw new Error("expected break marker.");
}
function decodeUnstructuredByteString(at, to) {
  const length = decodeCount(at, to);
  const offset = _offset;
  at += offset;
  if (to - at < length) {
    throw new Error(`unstructured byte string len ${length} greater than remaining buf len.`);
  }
  const value = payload.subarray(at, at + length);
  _offset = offset + length;
  return value;
}
function decodeUnstructuredByteStringIndefinite(at, to) {
  at += 1;
  const vector = [];
  for (const base = at; at < to; ) {
    if (payload[at] === 255) {
      const data2 = alloc(vector.length);
      data2.set(vector, 0);
      _offset = at - base + 2;
      return data2;
    }
    const major = (payload[at] & 224) >> 5;
    const minor = payload[at] & 31;
    if (major !== majorUnstructuredByteString) {
      throw new Error(`unexpected major type ${major} in indefinite string.`);
    }
    if (minor === minorIndefinite) {
      throw new Error("nested indefinite string.");
    }
    const bytes = decodeUnstructuredByteString(at, to);
    const length = _offset;
    at += length;
    for (let i4 = 0; i4 < bytes.length; ++i4) {
      vector.push(bytes[i4]);
    }
  }
  throw new Error("expected break marker.");
}
function decodeList(at, to) {
  const listDataLength = decodeCount(at, to);
  const offset = _offset;
  at += offset;
  const base = at;
  const list2 = Array(listDataLength);
  for (let i4 = 0; i4 < listDataLength; ++i4) {
    const item = decode(at, to);
    const itemOffset = _offset;
    list2[i4] = item;
    at += itemOffset;
  }
  _offset = offset + (at - base);
  return list2;
}
function decodeListIndefinite(at, to) {
  at += 1;
  const list2 = [];
  for (const base = at; at < to; ) {
    if (payload[at] === 255) {
      _offset = at - base + 2;
      return list2;
    }
    const item = decode(at, to);
    const n4 = _offset;
    at += n4;
    list2.push(item);
  }
  throw new Error("expected break marker.");
}
function decodeMap(at, to) {
  const mapDataLength = decodeCount(at, to);
  const offset = _offset;
  at += offset;
  const base = at;
  const map2 = {};
  for (let i4 = 0; i4 < mapDataLength; ++i4) {
    if (at >= to) {
      throw new Error("unexpected end of map payload.");
    }
    const major = (payload[at] & 224) >> 5;
    if (major !== majorUtf8String) {
      throw new Error(`unexpected major type ${major} for map key at index ${at}.`);
    }
    const key = decode(at, to);
    at += _offset;
    const value = decode(at, to);
    at += _offset;
    map2[key] = value;
  }
  _offset = offset + (at - base);
  return map2;
}
function decodeMapIndefinite(at, to) {
  at += 1;
  const base = at;
  const map2 = {};
  for (; at < to; ) {
    if (at >= to) {
      throw new Error("unexpected end of map payload.");
    }
    if (payload[at] === 255) {
      _offset = at - base + 2;
      return map2;
    }
    const major = (payload[at] & 224) >> 5;
    if (major !== majorUtf8String) {
      throw new Error(`unexpected major type ${major} for map key.`);
    }
    const key = decode(at, to);
    at += _offset;
    const value = decode(at, to);
    at += _offset;
    map2[key] = value;
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
      if (to - at < 3) {
        throw new Error("incomplete float16 at end of buf.");
      }
      _offset = 3;
      return bytesToFloat16(payload[at + 1], payload[at + 2]);
    case extendedFloat32:
      if (to - at < 5) {
        throw new Error("incomplete float32 at end of buf.");
      }
      _offset = 5;
      return dataView.getFloat32(at + 1);
    case extendedFloat64:
      if (to - at < 9) {
        throw new Error("incomplete float64 at end of buf.");
      }
      _offset = 9;
      return dataView.getFloat64(at + 1);
    default:
      throw new Error(`unexpected minor value ${minor}.`);
  }
}
function castBigInt(bigInt) {
  if (typeof bigInt === "number") {
    return bigInt;
  }
  const num = Number(bigInt);
  if (Number.MIN_SAFE_INTEGER <= num && num <= Number.MAX_SAFE_INTEGER) {
    return num;
  }
  return bigInt;
}
var import_util_utf84, USE_TEXT_DECODER, USE_BUFFER, payload, dataView, textDecoder, _offset, minorValueToArgumentLength;
var init_cbor_decode = __esm({
  "node_modules/@smithy/core/dist-es/submodules/cbor/cbor-decode.js"() {
    init_serde();
    import_util_utf84 = __toESM(require_dist_cjs10());
    init_cbor_types();
    USE_TEXT_DECODER = typeof TextDecoder !== "undefined";
    USE_BUFFER = typeof Buffer !== "undefined";
    payload = alloc(0);
    dataView = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    textDecoder = USE_TEXT_DECODER ? new TextDecoder() : null;
    _offset = 0;
    minorValueToArgumentLength = {
      [extendedOneByte]: 1,
      [extendedFloat16]: 2,
      [extendedFloat32]: 4,
      [extendedFloat64]: 8
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/cbor/cbor-encode.js
function ensureSpace(bytes) {
  const remaining = data.byteLength - cursor;
  if (remaining < bytes) {
    if (cursor < 16e6) {
      resize(Math.max(data.byteLength * 4, data.byteLength + bytes));
    } else {
      resize(data.byteLength + bytes + 16e6);
    }
  }
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
  if (old) {
    if (old.copy) {
      old.copy(data, 0, 0, old.byteLength);
    } else {
      data.set(old, 0);
    }
  }
  dataView2 = new DataView(data.buffer, data.byteOffset, data.byteLength);
}
function encodeHeader(major, value) {
  if (value < 24) {
    data[cursor++] = major << 5 | value;
  } else if (value < 1 << 8) {
    data[cursor++] = major << 5 | 24;
    data[cursor++] = value;
  } else if (value < 1 << 16) {
    data[cursor++] = major << 5 | extendedFloat16;
    dataView2.setUint16(cursor, value);
    cursor += 2;
  } else if (value < 2 ** 32) {
    data[cursor++] = major << 5 | extendedFloat32;
    dataView2.setUint32(cursor, value);
    cursor += 4;
  } else {
    data[cursor++] = major << 5 | extendedFloat64;
    dataView2.setBigUint64(cursor, typeof value === "bigint" ? value : BigInt(value));
    cursor += 8;
  }
}
function encode(_input) {
  const encodeStack = [_input];
  while (encodeStack.length) {
    const input = encodeStack.pop();
    ensureSpace(typeof input === "string" ? input.length * 4 : 64);
    if (typeof input === "string") {
      if (USE_BUFFER2) {
        encodeHeader(majorUtf8String, Buffer.byteLength(input));
        cursor += data.write(input, cursor);
      } else {
        const bytes = (0, import_util_utf85.fromUtf8)(input);
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
        if (value < 24) {
          data[cursor++] = major << 5 | value;
        } else if (value < 256) {
          data[cursor++] = major << 5 | 24;
          data[cursor++] = value;
        } else if (value < 65536) {
          data[cursor++] = major << 5 | extendedFloat16;
          data[cursor++] = value >> 8;
          data[cursor++] = value;
        } else if (value < 4294967296) {
          data[cursor++] = major << 5 | extendedFloat32;
          dataView2.setUint32(cursor, value);
          cursor += 4;
        } else {
          data[cursor++] = major << 5 | extendedFloat64;
          dataView2.setBigUint64(cursor, BigInt(value));
          cursor += 8;
        }
        continue;
      }
      data[cursor++] = majorSpecial << 5 | extendedFloat64;
      dataView2.setFloat64(cursor, input);
      cursor += 8;
      continue;
    } else if (typeof input === "bigint") {
      const nonNegative = input >= 0;
      const major = nonNegative ? majorUint64 : majorNegativeInt64;
      const value = nonNegative ? input : -input - BigInt(1);
      const n4 = Number(value);
      if (n4 < 24) {
        data[cursor++] = major << 5 | n4;
      } else if (n4 < 256) {
        data[cursor++] = major << 5 | 24;
        data[cursor++] = n4;
      } else if (n4 < 65536) {
        data[cursor++] = major << 5 | extendedFloat16;
        data[cursor++] = n4 >> 8;
        data[cursor++] = n4 & 255;
      } else if (n4 < 4294967296) {
        data[cursor++] = major << 5 | extendedFloat32;
        dataView2.setUint32(cursor, n4);
        cursor += 4;
      } else if (value < BigInt("18446744073709551616")) {
        data[cursor++] = major << 5 | extendedFloat64;
        dataView2.setBigUint64(cursor, value);
        cursor += 8;
      } else {
        const binaryBigInt = value.toString(2);
        const bigIntBytes = new Uint8Array(Math.ceil(binaryBigInt.length / 8));
        let b4 = value;
        let i4 = 0;
        while (bigIntBytes.byteLength - ++i4 >= 0) {
          bigIntBytes[bigIntBytes.byteLength - i4] = Number(b4 & BigInt(255));
          b4 >>= BigInt(8);
        }
        ensureSpace(bigIntBytes.byteLength * 2);
        data[cursor++] = nonNegative ? 194 : 195;
        if (USE_BUFFER2) {
          encodeHeader(majorUnstructuredByteString, Buffer.byteLength(bigIntBytes));
        } else {
          encodeHeader(majorUnstructuredByteString, bigIntBytes.byteLength);
        }
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
    } else if (typeof input === "undefined") {
      throw new Error("@smithy/core/cbor: client may not serialize undefined value.");
    } else if (Array.isArray(input)) {
      for (let i4 = input.length - 1; i4 >= 0; --i4) {
        encodeStack.push(input[i4]);
      }
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
      if (input[tagSymbol]) {
        if ("tag" in input && "value" in input) {
          encodeStack.push(input.value);
          encodeHeader(majorTag, input.tag);
          continue;
        } else {
          throw new Error("tag encountered with missing fields, need 'tag' and 'value', found: " + JSON.stringify(input));
        }
      }
      const keys = Object.keys(input);
      for (let i4 = keys.length - 1; i4 >= 0; --i4) {
        const key = keys[i4];
        encodeStack.push(input[key]);
        encodeStack.push(key);
      }
      encodeHeader(majorMap, keys.length);
      continue;
    }
    throw new Error(`data type ${input?.constructor?.name ?? typeof input} not compatible for encoding.`);
  }
}
var import_util_utf85, USE_BUFFER2, initialSize, data, dataView2, cursor;
var init_cbor_encode = __esm({
  "node_modules/@smithy/core/dist-es/submodules/cbor/cbor-encode.js"() {
    init_serde();
    import_util_utf85 = __toESM(require_dist_cjs10());
    init_cbor_types();
    USE_BUFFER2 = typeof Buffer !== "undefined";
    initialSize = 2048;
    data = alloc(initialSize);
    dataView2 = new DataView(data.buffer, data.byteOffset, data.byteLength);
    cursor = 0;
  }
});

// node_modules/@smithy/core/dist-es/submodules/cbor/cbor.js
var cbor;
var init_cbor = __esm({
  "node_modules/@smithy/core/dist-es/submodules/cbor/cbor.js"() {
    init_cbor_decode();
    init_cbor_encode();
    cbor = {
      deserialize(payload2) {
        setPayload(payload2);
        return decode(0, payload2.length);
      },
      serialize(input) {
        try {
          encode(input);
          return toUint8Array();
        } catch (e4) {
          toUint8Array();
          throw e4;
        }
      },
      resizeEncodingBuffer(size) {
        resize(size);
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/cbor/parseCborBody.js
var dateToTag, loadSmithyRpcV2CborErrorCode;
var init_parseCborBody = __esm({
  "node_modules/@smithy/core/dist-es/submodules/cbor/parseCborBody.js"() {
    init_cbor_types();
    dateToTag = (date2) => {
      return tag({
        tag: 1,
        value: date2.getTime() / 1e3
      });
    };
    loadSmithyRpcV2CborErrorCode = (output, data2) => {
      const sanitizeErrorCode = (rawValue) => {
        let cleanValue = rawValue;
        if (typeof cleanValue === "number") {
          cleanValue = cleanValue.toString();
        }
        if (cleanValue.indexOf(",") >= 0) {
          cleanValue = cleanValue.split(",")[0];
        }
        if (cleanValue.indexOf(":") >= 0) {
          cleanValue = cleanValue.split(":")[0];
        }
        if (cleanValue.indexOf("#") >= 0) {
          cleanValue = cleanValue.split("#")[1];
        }
        return cleanValue;
      };
      if (data2["__type"] !== void 0) {
        return sanitizeErrorCode(data2["__type"]);
      }
      const codeKey = Object.keys(data2).find((key) => key.toLowerCase() === "code");
      if (codeKey && data2[codeKey] !== void 0) {
        return sanitizeErrorCode(data2[codeKey]);
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/cbor/CborCodec.js
var import_util_base643, CborCodec, CborShapeSerializer, CborShapeDeserializer;
var init_CborCodec = __esm({
  "node_modules/@smithy/core/dist-es/submodules/cbor/CborCodec.js"() {
    init_protocols();
    init_schema();
    init_serde();
    import_util_base643 = __toESM(require_dist_cjs11());
    init_cbor();
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
          if (ns.isIdempotencyToken()) {
            return (0, import_uuid.v4)();
          }
          return source;
        }
        if (ns.isBlobSchema()) {
          if (typeof source === "string") {
            return (this.serdeContext?.base64Decoder ?? import_util_base643.fromBase64)(source);
          }
          return source;
        }
        if (ns.isTimestampSchema()) {
          if (typeof source === "number" || typeof source === "bigint") {
            return dateToTag(new Date(Number(source) / 1e3 | 0));
          }
          return dateToTag(source);
        }
        if (typeof source === "function" || typeof source === "object") {
          const sourceObject = source;
          if (ns.isListSchema() && Array.isArray(sourceObject)) {
            const sparse = !!ns.getMergedTraits().sparse;
            const newArray = [];
            let i4 = 0;
            for (const item of sourceObject) {
              const value = this.serialize(ns.getValueSchema(), item);
              if (value != null || sparse) {
                newArray[i4++] = value;
              }
            }
            return newArray;
          }
          if (sourceObject instanceof Date) {
            return dateToTag(sourceObject);
          }
          const newObject = {};
          if (ns.isMapSchema()) {
            const sparse = !!ns.getMergedTraits().sparse;
            for (const key of Object.keys(sourceObject)) {
              const value = this.serialize(ns.getValueSchema(), sourceObject[key]);
              if (value != null || sparse) {
                newObject[key] = value;
              }
            }
          } else if (ns.isStructSchema()) {
            for (const [key, memberSchema] of ns.structIterator()) {
              const value = this.serialize(memberSchema, sourceObject[key]);
              if (value != null) {
                newObject[key] = value;
              }
            }
            const isUnion = ns.isUnionSchema();
            if (isUnion && Array.isArray(sourceObject.$unknown)) {
              const [k4, v4] = sourceObject.$unknown;
              newObject[k4] = v4;
            }
          } else if (ns.isDocumentSchema()) {
            for (const key of Object.keys(sourceObject)) {
              newObject[key] = this.serialize(ns.getValueSchema(), sourceObject[key]);
            }
          }
          return newObject;
        }
        return source;
      }
      flush() {
        const buffer = cbor.serialize(this.value);
        this.value = void 0;
        return buffer;
      }
    };
    CborShapeDeserializer = class extends SerdeContext {
      read(schema, bytes) {
        const data2 = cbor.deserialize(bytes);
        return this.readValue(schema, data2);
      }
      readValue(_schema, value) {
        const ns = NormalizedSchema.of(_schema);
        if (ns.isTimestampSchema()) {
          if (typeof value === "number") {
            return _parseEpochTimestamp(value);
          }
          if (typeof value === "object") {
            if (value.tag === 1 && "value" in value) {
              return _parseEpochTimestamp(value.value);
            }
          }
        }
        if (ns.isBlobSchema()) {
          if (typeof value === "string") {
            return (this.serdeContext?.base64Decoder ?? import_util_base643.fromBase64)(value);
          }
          return value;
        }
        if (typeof value === "undefined" || typeof value === "boolean" || typeof value === "number" || typeof value === "string" || typeof value === "bigint" || typeof value === "symbol") {
          return value;
        } else if (typeof value === "object") {
          if (value === null) {
            return null;
          }
          if ("byteLength" in value) {
            return value;
          }
          if (value instanceof Date) {
            return value;
          }
          if (ns.isDocumentSchema()) {
            return value;
          }
          if (ns.isListSchema()) {
            const newArray = [];
            const memberSchema = ns.getValueSchema();
            const sparse = !!ns.getMergedTraits().sparse;
            for (const item of value) {
              const itemValue = this.readValue(memberSchema, item);
              if (itemValue != null || sparse) {
                newArray.push(itemValue);
              }
            }
            return newArray;
          }
          const newObject = {};
          if (ns.isMapSchema()) {
            const sparse = !!ns.getMergedTraits().sparse;
            const targetSchema = ns.getValueSchema();
            for (const key of Object.keys(value)) {
              const itemValue = this.readValue(targetSchema, value[key]);
              if (itemValue != null || sparse) {
                newObject[key] = itemValue;
              }
            }
          } else if (ns.isStructSchema()) {
            const isUnion = ns.isUnionSchema();
            let keys;
            if (isUnion) {
              keys = new Set(Object.keys(value).filter((k4) => k4 !== "__type"));
            }
            for (const [key, memberSchema] of ns.structIterator()) {
              if (isUnion) {
                keys.delete(key);
              }
              if (value[key] != null) {
                newObject[key] = this.readValue(memberSchema, value[key]);
              }
            }
            if (isUnion && keys?.size === 1 && Object.keys(newObject).length === 0) {
              const k4 = keys.values().next().value;
              newObject.$unknown = [k4, value[k4]];
            }
          }
          return newObject;
        } else {
          return value;
        }
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/cbor/SmithyRpcV2CborProtocol.js
var import_util_middleware5, SmithyRpcV2CborProtocol;
var init_SmithyRpcV2CborProtocol = __esm({
  "node_modules/@smithy/core/dist-es/submodules/cbor/SmithyRpcV2CborProtocol.js"() {
    init_protocols();
    init_schema();
    import_util_middleware5 = __toESM(require_dist_cjs6());
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
          } catch (e4) {
          }
        }
        const { service, operation: operation2 } = (0, import_util_middleware5.getSmithyContext)(context);
        const path = `/service/${service}/operation/${operation2}`;
        if (request.path.endsWith("/")) {
          request.path += path.slice(1);
        } else {
          request.path += path;
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        return super.deserializeResponse(operationSchema, context, response);
      }
      async handleError(operationSchema, context, response, dataObject, metadata) {
        const errorName = loadSmithyRpcV2CborErrorCode(response, dataObject) ?? "Unknown";
        let namespace = this.options.defaultNamespace;
        if (errorName.includes("#")) {
          [namespace] = errorName.split("#");
        }
        const errorMetadata = {
          $metadata: metadata,
          $fault: response.statusCode <= 500 ? "client" : "server"
        };
        const registry = TypeRegistry.for(namespace);
        let errorSchema;
        try {
          errorSchema = registry.getSchema(errorName);
        } catch (e4) {
          if (dataObject.Message) {
            dataObject.message = dataObject.Message;
          }
          const synthetic = TypeRegistry.for("smithy.ts.sdk.synthetic." + namespace);
          const baseExceptionSchema = synthetic.getBaseException();
          if (baseExceptionSchema) {
            const ErrorCtor2 = synthetic.getErrorCtor(baseExceptionSchema);
            throw Object.assign(new ErrorCtor2({ name: errorName }), errorMetadata, dataObject);
          }
          throw Object.assign(new Error(errorName), errorMetadata, dataObject);
        }
        const ns = NormalizedSchema.of(errorSchema);
        const ErrorCtor = registry.getErrorCtor(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const exception = new ErrorCtor(message);
        const output = {};
        for (const [name, member2] of ns.structIterator()) {
          output[name] = this.deserializer.readValue(member2, dataObject[name]);
        }
        throw Object.assign(exception, errorMetadata, {
          $fault: ns.getMergedTraits().error,
          message
        }, output);
      }
      getDefaultContentType() {
        return "application/cbor";
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/cbor/index.js
var init_cbor2 = __esm({
  "node_modules/@smithy/core/dist-es/submodules/cbor/index.js"() {
    init_parseCborBody();
    init_SmithyRpcV2CborProtocol();
    init_CborCodec();
  }
});

// node_modules/@smithy/middleware-stack/dist-cjs/index.js
var require_dist_cjs25 = __commonJS({
  "node_modules/@smithy/middleware-stack/dist-cjs/index.js"(exports) {
    "use strict";
    var getAllAliases = (name, aliases) => {
      const _aliases = [];
      if (name) {
        _aliases.push(name);
      }
      if (aliases) {
        for (const alias of aliases) {
          _aliases.push(alias);
        }
      }
      return _aliases;
    };
    var getMiddlewareNameWithAliases = (name, aliases) => {
      return `${name || "anonymous"}${aliases && aliases.length > 0 ? ` (a.k.a. ${aliases.join(",")})` : ""}`;
    };
    var constructStack = () => {
      let absoluteEntries = [];
      let relativeEntries = [];
      let identifyOnResolve = false;
      const entriesNameSet = /* @__PURE__ */ new Set();
      const sort = (entries) => entries.sort((a4, b4) => stepWeights[b4.step] - stepWeights[a4.step] || priorityWeights[b4.priority || "normal"] - priorityWeights[a4.priority || "normal"]);
      const removeByName = (toRemove) => {
        let isRemoved = false;
        const filterCb = (entry) => {
          const aliases = getAllAliases(entry.name, entry.aliases);
          if (aliases.includes(toRemove)) {
            isRemoved = true;
            for (const alias of aliases) {
              entriesNameSet.delete(alias);
            }
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
            for (const alias of getAllAliases(entry.name, entry.aliases)) {
              entriesNameSet.delete(alias);
            }
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
          if (entry.before.length === 0 && entry.after.length === 0) {
            expandedMiddlewareList.push(entry);
          } else {
            expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
          }
        });
        expandedMiddlewareList.push(from);
        from.after.reverse().forEach((entry) => {
          if (entry.before.length === 0 && entry.after.length === 0) {
            expandedMiddlewareList.push(entry);
          } else {
            expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
          }
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
          for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) {
            normalizedEntriesNameMap[alias] = normalizedEntry;
          }
          normalizedAbsoluteEntries.push(normalizedEntry);
        });
        relativeEntries.forEach((entry) => {
          const normalizedEntry = {
            ...entry,
            before: [],
            after: []
          };
          for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) {
            normalizedEntriesNameMap[alias] = normalizedEntry;
          }
          normalizedRelativeEntries.push(normalizedEntry);
        });
        normalizedRelativeEntries.forEach((entry) => {
          if (entry.toMiddleware) {
            const toMiddleware = normalizedEntriesNameMap[entry.toMiddleware];
            if (toMiddleware === void 0) {
              if (debug) {
                return;
              }
              throw new Error(`${entry.toMiddleware} is not found when adding ${getMiddlewareNameWithAliases(entry.name, entry.aliases)} middleware ${entry.relation} ${entry.toMiddleware}`);
            }
            if (entry.relation === "after") {
              toMiddleware.after.push(entry);
            }
            if (entry.relation === "before") {
              toMiddleware.before.push(entry);
            }
          }
        });
        const mainChain = sort(normalizedAbsoluteEntries).map(expandRelativeMiddlewareList).reduce((wholeList, expandedMiddlewareList) => {
          wholeList.push(...expandedMiddlewareList);
          return wholeList;
        }, []);
        return mainChain;
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
              if (!override)
                throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
              for (const alias of aliases) {
                const toOverrideIndex = absoluteEntries.findIndex((entry2) => entry2.name === alias || entry2.aliases?.some((a4) => a4 === alias));
                if (toOverrideIndex === -1) {
                  continue;
                }
                const toOverride = absoluteEntries[toOverrideIndex];
                if (toOverride.step !== entry.step || entry.priority !== toOverride.priority) {
                  throw new Error(`"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware with ${toOverride.priority} priority in ${toOverride.step} step cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware with ${entry.priority} priority in ${entry.step} step.`);
                }
                absoluteEntries.splice(toOverrideIndex, 1);
              }
            }
            for (const alias of aliases) {
              entriesNameSet.add(alias);
            }
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
              if (!override)
                throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
              for (const alias of aliases) {
                const toOverrideIndex = relativeEntries.findIndex((entry2) => entry2.name === alias || entry2.aliases?.some((a4) => a4 === alias));
                if (toOverrideIndex === -1) {
                  continue;
                }
                const toOverride = relativeEntries[toOverrideIndex];
                if (toOverride.toMiddleware !== entry.toMiddleware || toOverride.relation !== entry.relation) {
                  throw new Error(`"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware ${toOverride.relation} "${toOverride.toMiddleware}" middleware cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware ${entry.relation} "${entry.toMiddleware}" middleware.`);
                }
                relativeEntries.splice(toOverrideIndex, 1);
              }
            }
            for (const alias of aliases) {
              entriesNameSet.add(alias);
            }
          }
          relativeEntries.push(entry);
        },
        clone: () => cloneTo(constructStack()),
        use: (plugin) => {
          plugin.applyToStack(stack);
        },
        remove: (toRemove) => {
          if (typeof toRemove === "string")
            return removeByName(toRemove);
          else
            return removeByReference(toRemove);
        },
        removeByTag: (toRemove) => {
          let isRemoved = false;
          const filterCb = (entry) => {
            const { tags, name, aliases: _aliases } = entry;
            if (tags && tags.includes(toRemove)) {
              const aliases = getAllAliases(name, _aliases);
              for (const alias of aliases) {
                entriesNameSet.delete(alias);
              }
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
          if (typeof toggle === "boolean")
            identifyOnResolve = toggle;
          return identifyOnResolve;
        },
        resolve: (handler2, context) => {
          for (const middleware of getMiddlewareList().map((entry) => entry.middleware).reverse()) {
            handler2 = middleware(handler2, context);
          }
          if (identifyOnResolve) {
            console.log(stack.identify());
          }
          return handler2;
        }
      };
      return stack;
    };
    var stepWeights = {
      initialize: 5,
      serialize: 4,
      build: 3,
      finalizeRequest: 2,
      deserialize: 1
    };
    var priorityWeights = {
      high: 3,
      normal: 2,
      low: 1
    };
    exports.constructStack = constructStack;
  }
});

// node_modules/@smithy/smithy-client/dist-cjs/index.js
var require_dist_cjs26 = __commonJS({
  "node_modules/@smithy/smithy-client/dist-cjs/index.js"(exports) {
    "use strict";
    var middlewareStack = require_dist_cjs25();
    var protocols = (init_protocols(), __toCommonJS(protocols_exports));
    var types = require_dist_cjs();
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
          if (typeof protocol === "function") {
            config.protocol = new protocol(protocolSettings);
          }
        }
      }
      send(command, optionsOrCb, cb) {
        const options = typeof optionsOrCb !== "function" ? optionsOrCb : void 0;
        const callback = typeof optionsOrCb === "function" ? optionsOrCb : cb;
        const useHandlerCache = options === void 0 && this.config.cacheMiddleware === true;
        let handler2;
        if (useHandlerCache) {
          if (!this.handlers) {
            this.handlers = /* @__PURE__ */ new WeakMap();
          }
          const handlers = this.handlers;
          if (handlers.has(command.constructor)) {
            handler2 = handlers.get(command.constructor);
          } else {
            handler2 = command.resolveMiddleware(this.middlewareStack, this.config, options);
            handlers.set(command.constructor, handler2);
          }
        } else {
          delete this.handlers;
          handler2 = command.resolveMiddleware(this.middlewareStack, this.config, options);
        }
        if (callback) {
          handler2(command).then((result) => callback(null, result.output), (err) => callback(err)).catch(() => {
          });
        } else {
          return handler2(command).then((result) => result.output);
        }
      }
      destroy() {
        this.config?.requestHandler?.destroy?.();
        delete this.handlers;
      }
    };
    var SENSITIVE_STRING$1 = "***SensitiveInformation***";
    function schemaLogFilter(schema$1, data2) {
      if (data2 == null) {
        return data2;
      }
      const ns = schema.NormalizedSchema.of(schema$1);
      if (ns.getMergedTraits().sensitive) {
        return SENSITIVE_STRING$1;
      }
      if (ns.isListSchema()) {
        const isSensitive = !!ns.getValueSchema().getMergedTraits().sensitive;
        if (isSensitive) {
          return SENSITIVE_STRING$1;
        }
      } else if (ns.isMapSchema()) {
        const isSensitive = !!ns.getKeySchema().getMergedTraits().sensitive || !!ns.getValueSchema().getMergedTraits().sensitive;
        if (isSensitive) {
          return SENSITIVE_STRING$1;
        }
      } else if (ns.isStructSchema() && typeof data2 === "object") {
        const object = data2;
        const newObject = {};
        for (const [member2, memberNs] of ns.structIterator()) {
          if (object[member2] != null) {
            newObject[member2] = schemaLogFilter(memberNs, object[member2]);
          }
        }
        return newObject;
      }
      return data2;
    }
    var Command = class {
      middlewareStack = middlewareStack.constructStack();
      schema;
      static classBuilder() {
        return new ClassBuilder();
      }
      resolveMiddlewareWithContext(clientStack, configuration, options, { middlewareFn, clientName, commandName, inputFilterSensitiveLog, outputFilterSensitiveLog, smithyContext, additionalContext, CommandCtor }) {
        for (const mw of middlewareFn.bind(this)(CommandCtor, clientStack, configuration, options)) {
          this.middlewareStack.use(mw);
        }
        const stack = clientStack.concat(this.middlewareStack);
        const { logger: logger2 } = configuration;
        const handlerExecutionContext = {
          logger: logger2,
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
      _init = () => {
      };
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
      s(service, operation2, smithyContext = {}) {
        this._smithyContext = {
          service,
          operation: operation2,
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
      sc(operation2) {
        this._operationSchema = operation2;
        this._smithyContext.operationSchema = operation2;
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
            const op2 = closure._operationSchema;
            const input = op2?.[4] ?? op2?.input;
            const output = op2?.[5] ?? op2?.output;
            return this.resolveMiddlewareWithContext(stack, configuration, options, {
              CommandCtor: CommandRef,
              middlewareFn: closure._middlewareFn,
              clientName: closure._clientName,
              commandName: closure._commandName,
              inputFilterSensitiveLog: closure._inputFilterSensitiveLog ?? (op2 ? schemaLogFilter.bind(null, input) : (_) => _),
              outputFilterSensitiveLog: closure._outputFilterSensitiveLog ?? (op2 ? schemaLogFilter.bind(null, output) : (_) => _),
              smithyContext: closure._smithyContext,
              additionalContext: closure._additionalContext
            });
          }
          serialize = closure._serializer;
          deserialize = closure._deserializer;
        };
      }
    };
    var SENSITIVE_STRING = "***SensitiveInformation***";
    var createAggregatedClient4 = (commands4, Client2) => {
      for (const command of Object.keys(commands4)) {
        const CommandCtor = commands4[command];
        const methodImpl = async function(args, optionsOrCb, cb) {
          const command2 = new CommandCtor(args);
          if (typeof optionsOrCb === "function") {
            this.send(command2, optionsOrCb);
          } else if (typeof cb === "function") {
            if (typeof optionsOrCb !== "object")
              throw new Error(`Expected http options but got ${typeof optionsOrCb}`);
            this.send(command2, optionsOrCb || {}, cb);
          } else {
            return this.send(command2, optionsOrCb);
          }
        };
        const methodName = (command[0].toLowerCase() + command.slice(1)).replace(/Command$/, "");
        Client2.prototype[methodName] = methodImpl;
      }
    };
    var ServiceException = class _ServiceException extends Error {
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
        if (!value)
          return false;
        const candidate = value;
        return _ServiceException.prototype.isPrototypeOf(candidate) || Boolean(candidate.$fault) && Boolean(candidate.$metadata) && (candidate.$fault === "client" || candidate.$fault === "server");
      }
      static [Symbol.hasInstance](instance) {
        if (!instance)
          return false;
        const candidate = instance;
        if (this === _ServiceException) {
          return _ServiceException.isInstance(instance);
        }
        if (_ServiceException.isInstance(instance)) {
          if (candidate.name && this.name) {
            return this.prototype.isPrototypeOf(instance) || candidate.name === this.name;
          }
          return this.prototype.isPrototypeOf(instance);
        }
        return false;
      }
    };
    var decorateServiceException2 = (exception, additions = {}) => {
      Object.entries(additions).filter(([, v4]) => v4 !== void 0).forEach(([k4, v4]) => {
        if (exception[k4] == void 0 || exception[k4] === "") {
          exception[k4] = v4;
        }
      });
      const message = exception.message || exception.Message || "UnknownError";
      exception.message = message;
      delete exception.Message;
      return exception;
    };
    var throwDefaultError = ({ output, parsedBody, exceptionCtor, errorCode }) => {
      const $metadata = deserializeMetadata(output);
      const statusCode = $metadata.httpStatusCode ? $metadata.httpStatusCode + "" : void 0;
      const response = new exceptionCtor({
        name: parsedBody?.code || parsedBody?.Code || errorCode || statusCode || "UnknownError",
        $fault: "client",
        $metadata
      });
      throw decorateServiceException2(response, parsedBody);
    };
    var withBaseException = (ExceptionCtor) => {
      return ({ output, parsedBody, errorCode }) => {
        throwDefaultError({ output, parsedBody, exceptionCtor: ExceptionCtor, errorCode });
      };
    };
    var deserializeMetadata = (output) => ({
      httpStatusCode: output.statusCode,
      requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
      extendedRequestId: output.headers["x-amz-id-2"],
      cfId: output.headers["x-amz-cf-id"]
    });
    var loadConfigsForDefaultMode4 = (mode) => {
      switch (mode) {
        case "standard":
          return {
            retryMode: "standard",
            connectionTimeout: 3100
          };
        case "in-region":
          return {
            retryMode: "standard",
            connectionTimeout: 1100
          };
        case "cross-region":
          return {
            retryMode: "standard",
            connectionTimeout: 3100
          };
        case "mobile":
          return {
            retryMode: "standard",
            connectionTimeout: 3e4
          };
        default:
          return {};
      }
    };
    var warningEmitted = false;
    var emitWarningIfUnsupportedVersion5 = (version) => {
      if (version && !warningEmitted && parseInt(version.substring(1, version.indexOf("."))) < 16) {
        warningEmitted = true;
      }
    };
    var getChecksumConfiguration = (runtimeConfig) => {
      const checksumAlgorithms = [];
      for (const id in types.AlgorithmId) {
        const algorithmId = types.AlgorithmId[id];
        if (runtimeConfig[algorithmId] === void 0) {
          continue;
        }
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
    var resolveChecksumRuntimeConfig = (clientConfig) => {
      const runtimeConfig = {};
      clientConfig.checksumAlgorithms().forEach((checksumAlgorithm) => {
        runtimeConfig[checksumAlgorithm.algorithmId()] = checksumAlgorithm.checksumConstructor();
      });
      return runtimeConfig;
    };
    var getRetryConfiguration = (runtimeConfig) => {
      return {
        setRetryStrategy(retryStrategy) {
          runtimeConfig.retryStrategy = retryStrategy;
        },
        retryStrategy() {
          return runtimeConfig.retryStrategy;
        }
      };
    };
    var resolveRetryRuntimeConfig = (retryStrategyConfiguration) => {
      const runtimeConfig = {};
      runtimeConfig.retryStrategy = retryStrategyConfiguration.retryStrategy();
      return runtimeConfig;
    };
    var getDefaultExtensionConfiguration4 = (runtimeConfig) => {
      return Object.assign(getChecksumConfiguration(runtimeConfig), getRetryConfiguration(runtimeConfig));
    };
    var getDefaultClientConfiguration = getDefaultExtensionConfiguration4;
    var resolveDefaultRuntimeConfig4 = (config) => {
      return Object.assign(resolveChecksumRuntimeConfig(config), resolveRetryRuntimeConfig(config));
    };
    var getArrayIfSingleItem = (mayBeArray) => Array.isArray(mayBeArray) ? mayBeArray : [mayBeArray];
    var getValueFromTextNode3 = (obj) => {
      const textNodeName = "#text";
      for (const key in obj) {
        if (obj.hasOwnProperty(key) && obj[key][textNodeName] !== void 0) {
          obj[key] = obj[key][textNodeName];
        } else if (typeof obj[key] === "object" && obj[key] !== null) {
          obj[key] = getValueFromTextNode3(obj[key]);
        }
      }
      return obj;
    };
    var isSerializableHeaderValue = (value) => {
      return value != null;
    };
    var NoOpLogger4 = class {
      trace() {
      }
      debug() {
      }
      info() {
      }
      warn() {
      }
      error() {
      }
    };
    function map2(arg0, arg1, arg2) {
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
        } else {
          instructions = arg1;
        }
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
    var convertMap = (target) => {
      const output = {};
      for (const [k4, v4] of Object.entries(target || {})) {
        output[k4] = [, v4];
      }
      return output;
    };
    var take = (source, instructions) => {
      const out = {};
      for (const key in instructions) {
        applyInstruction(out, source, instructions, key);
      }
      return out;
    };
    var mapWithFilter = (target, filter, instructions) => {
      return map2(target, Object.entries(instructions).reduce((_instructions, [key, value]) => {
        if (Array.isArray(value)) {
          _instructions[key] = value;
        } else {
          if (typeof value === "function") {
            _instructions[key] = [filter, value()];
          } else {
            _instructions[key] = [filter, value];
          }
        }
        return _instructions;
      }, {}));
    };
    var applyInstruction = (target, source, instructions, targetKey) => {
      if (source !== null) {
        let instruction = instructions[targetKey];
        if (typeof instruction === "function") {
          instruction = [, instruction];
        }
        const [filter2 = nonNullish, valueFn = pass, sourceKey = targetKey] = instruction;
        if (typeof filter2 === "function" && filter2(source[sourceKey]) || typeof filter2 !== "function" && !!filter2) {
          target[targetKey] = valueFn(source[sourceKey]);
        }
        return;
      }
      let [filter, value] = instructions[targetKey];
      if (typeof value === "function") {
        let _value;
        const defaultFilterPassed = filter === void 0 && (_value = value()) != null;
        const customFilterPassed = typeof filter === "function" && !!filter(void 0) || typeof filter !== "function" && !!filter;
        if (defaultFilterPassed) {
          target[targetKey] = _value;
        } else if (customFilterPassed) {
          target[targetKey] = value();
        }
      } else {
        const defaultFilterPassed = filter === void 0 && value != null;
        const customFilterPassed = typeof filter === "function" && !!filter(value) || typeof filter !== "function" && !!filter;
        if (defaultFilterPassed || customFilterPassed) {
          target[targetKey] = value;
        }
      }
    };
    var nonNullish = (_) => _ != null;
    var pass = (_) => _;
    var serializeFloat = (value) => {
      if (value !== value) {
        return "NaN";
      }
      switch (value) {
        case Infinity:
          return "Infinity";
        case -Infinity:
          return "-Infinity";
        default:
          return value;
      }
    };
    var serializeDateTime = (date2) => date2.toISOString().replace(".000Z", "Z");
    var _json = (obj) => {
      if (obj == null) {
        return {};
      }
      if (Array.isArray(obj)) {
        return obj.filter((_) => _ != null).map(_json);
      }
      if (typeof obj === "object") {
        const target = {};
        for (const key of Object.keys(obj)) {
          if (obj[key] == null) {
            continue;
          }
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
    exports.NoOpLogger = NoOpLogger4;
    exports.SENSITIVE_STRING = SENSITIVE_STRING;
    exports.ServiceException = ServiceException;
    exports._json = _json;
    exports.convertMap = convertMap;
    exports.createAggregatedClient = createAggregatedClient4;
    exports.decorateServiceException = decorateServiceException2;
    exports.emitWarningIfUnsupportedVersion = emitWarningIfUnsupportedVersion5;
    exports.getArrayIfSingleItem = getArrayIfSingleItem;
    exports.getDefaultClientConfiguration = getDefaultClientConfiguration;
    exports.getDefaultExtensionConfiguration = getDefaultExtensionConfiguration4;
    exports.getValueFromTextNode = getValueFromTextNode3;
    exports.isSerializableHeaderValue = isSerializableHeaderValue;
    exports.loadConfigsForDefaultMode = loadConfigsForDefaultMode4;
    exports.map = map2;
    exports.resolveDefaultRuntimeConfig = resolveDefaultRuntimeConfig4;
    exports.serializeDateTime = serializeDateTime;
    exports.serializeFloat = serializeFloat;
    exports.take = take;
    exports.throwDefaultError = throwDefaultError;
    exports.withBaseException = withBaseException;
    Object.keys(serde).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return serde[k4];
        }
      });
    });
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/ProtocolLib.js
var import_smithy_client, ProtocolLib;
var init_ProtocolLib = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/ProtocolLib.js"() {
    init_schema();
    import_smithy_client = __toESM(require_dist_cjs26());
    ProtocolLib = class {
      queryCompat;
      constructor(queryCompat = false) {
        this.queryCompat = queryCompat;
      }
      resolveRestContentType(defaultContentType, inputSchema) {
        const members = inputSchema.getMemberSchemas();
        const httpPayloadMember = Object.values(members).find((m4) => {
          return !!m4.getMergedTraits().httpPayload;
        });
        if (httpPayloadMember) {
          const mediaType = httpPayloadMember.getMergedTraits().mediaType;
          if (mediaType) {
            return mediaType;
          } else if (httpPayloadMember.isStringSchema()) {
            return "text/plain";
          } else if (httpPayloadMember.isBlobSchema()) {
            return "application/octet-stream";
          } else {
            return defaultContentType;
          }
        } else if (!inputSchema.isUnitSchema()) {
          const hasBody = Object.values(members).find((m4) => {
            const { httpQuery, httpQueryParams, httpHeader, httpLabel, httpPrefixHeaders } = m4.getMergedTraits();
            const noPrefixHeaders = httpPrefixHeaders === void 0;
            return !httpQuery && !httpQueryParams && !httpHeader && !httpLabel && noPrefixHeaders;
          });
          if (hasBody) {
            return defaultContentType;
          }
        }
      }
      async getErrorSchemaOrThrowBaseException(errorIdentifier, defaultNamespace, response, dataObject, metadata, getErrorSchema) {
        let namespace = defaultNamespace;
        let errorName = errorIdentifier;
        if (errorIdentifier.includes("#")) {
          [namespace, errorName] = errorIdentifier.split("#");
        }
        const errorMetadata = {
          $metadata: metadata,
          $fault: response.statusCode < 500 ? "client" : "server"
        };
        const registry = TypeRegistry.for(namespace);
        try {
          const errorSchema = getErrorSchema?.(registry, errorName) ?? registry.getSchema(errorIdentifier);
          return { errorSchema, errorMetadata };
        } catch (e4) {
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
          const error2 = (0, import_smithy_client.decorateServiceException)(exception, additions);
          if (msg) {
            error2.message = msg;
          }
          error2.Error = {
            ...error2.Error,
            Type: error2.Error.Type,
            Code: error2.Error.Code,
            Message: error2.Error.message ?? error2.Error.Message ?? msg
          };
          const reqId = error2.$metadata.requestId;
          if (reqId) {
            error2.RequestId = reqId;
          }
          return error2;
        }
        return (0, import_smithy_client.decorateServiceException)(exception, additions);
      }
      setQueryCompatError(output, response) {
        const queryErrorHeader = response.headers?.["x-amzn-query-error"];
        if (output !== void 0 && queryErrorHeader != null) {
          const [Code, Type] = queryErrorHeader.split(";");
          const entries = Object.entries(output);
          const Error2 = {
            Code,
            Type
          };
          Object.assign(output, Error2);
          for (const [k4, v4] of entries) {
            Error2[k4 === "message" ? "Message" : k4] = v4;
          }
          delete Error2.__type;
          output.Error = Error2;
        }
      }
      queryCompatOutput(queryCompatErrorData, errorData) {
        if (queryCompatErrorData.Error) {
          errorData.Error = queryCompatErrorData.Error;
        }
        if (queryCompatErrorData.Type) {
          errorData.Type = queryCompatErrorData.Type;
        }
        if (queryCompatErrorData.Code) {
          errorData.Code = queryCompatErrorData.Code;
        }
      }
      findQueryCompatibleError(registry, errorName) {
        try {
          return registry.getSchema(errorName);
        } catch (e4) {
          return registry.find((schema) => NormalizedSchema.of(schema).getMergedTraits().awsQueryError?.[0] === errorName);
        }
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/cbor/AwsSmithyRpcV2CborProtocol.js
var AwsSmithyRpcV2CborProtocol;
var init_AwsSmithyRpcV2CborProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/cbor/AwsSmithyRpcV2CborProtocol.js"() {
    init_cbor2();
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
        if (this.awsQueryCompatible) {
          request.headers["x-amzn-query-mode"] = "true";
        }
        return request;
      }
      async handleError(operationSchema, context, response, dataObject, metadata) {
        if (this.awsQueryCompatible) {
          this.mixin.setQueryCompatError(dataObject, response);
        }
        const errorName = (() => {
          const compatHeader = response.headers["x-amzn-query-error"];
          if (compatHeader && this.awsQueryCompatible) {
            return compatHeader.split(";")[0];
          }
          return loadSmithyRpcV2CborErrorCode(response, dataObject) ?? "Unknown";
        })();
        const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorName, this.options.defaultNamespace, response, dataObject, metadata, this.awsQueryCompatible ? this.mixin.findQueryCompatibleError : void 0);
        const ns = NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor = TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ?? Error;
        const exception = new ErrorCtor(message);
        const output = {};
        for (const [name, member2] of ns.structIterator()) {
          if (dataObject[name] != null) {
            output[name] = this.deserializer.readValue(member2, dataObject[name]);
          }
        }
        if (this.awsQueryCompatible) {
          this.mixin.queryCompatOutput(dataObject, output);
        }
        throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
          $fault: ns.getMergedTraits().error,
          message
        }, output), dataObject);
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/coercing-serializers.js
var _toStr, _toBool, _toNum;
var init_coercing_serializers = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/coercing-serializers.js"() {
    _toStr = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "number" || typeof val === "bigint") {
        const warning = new Error(`Received number ${val} where a string was expected.`);
        warning.name = "Warning";
        console.warn(warning);
        return String(val);
      }
      if (typeof val === "boolean") {
        const warning = new Error(`Received boolean ${val} where a string was expected.`);
        warning.name = "Warning";
        console.warn(warning);
        return String(val);
      }
      return val;
    };
    _toBool = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "number") {
      }
      if (typeof val === "string") {
        const lowercase = val.toLowerCase();
        if (val !== "" && lowercase !== "false" && lowercase !== "true") {
          const warning = new Error(`Received string "${val}" where a boolean was expected.`);
          warning.name = "Warning";
          console.warn(warning);
        }
        return val !== "" && lowercase !== "false";
      }
      return val;
    };
    _toNum = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "boolean") {
      }
      if (typeof val === "string") {
        const num = Number(val);
        if (num.toString() !== val) {
          const warning = new Error(`Received string "${val}" where a number was expected.`);
          warning.name = "Warning";
          console.warn(warning);
          return val;
        }
        return num;
      }
      return val;
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/ConfigurableSerdeContext.js
var SerdeContextConfig;
var init_ConfigurableSerdeContext = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/ConfigurableSerdeContext.js"() {
    SerdeContextConfig = class {
      serdeContext;
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/structIterator.js
function* serializingStructIterator(ns, sourceObject) {
  if (ns.isUnitSchema()) {
    return;
  }
  const struct2 = ns.getSchema();
  for (let i4 = 0; i4 < struct2[4].length; ++i4) {
    const key = struct2[4][i4];
    const memberSchema = struct2[5][i4];
    const memberNs = new NormalizedSchema([memberSchema, 0], key);
    if (!(key in sourceObject) && !memberNs.isIdempotencyToken()) {
      continue;
    }
    yield [key, memberNs];
  }
}
function* deserializingStructIterator(ns, sourceObject, nameTrait) {
  if (ns.isUnitSchema()) {
    return;
  }
  const struct2 = ns.getSchema();
  let keysRemaining = Object.keys(sourceObject).filter((k4) => k4 !== "__type").length;
  for (let i4 = 0; i4 < struct2[4].length; ++i4) {
    if (keysRemaining === 0) {
      break;
    }
    const key = struct2[4][i4];
    const memberSchema = struct2[5][i4];
    const memberNs = new NormalizedSchema([memberSchema, 0], key);
    let serializationKey = key;
    if (nameTrait) {
      serializationKey = memberNs.getMergedTraits()[nameTrait] ?? key;
    }
    if (!(serializationKey in sourceObject)) {
      continue;
    }
    yield [key, memberNs];
    keysRemaining -= 1;
  }
}
var init_structIterator = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/structIterator.js"() {
    init_schema();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/UnionSerde.js
var UnionSerde;
var init_UnionSerde = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/UnionSerde.js"() {
    UnionSerde = class {
      from;
      to;
      keys;
      constructor(from, to) {
        this.from = from;
        this.to = to;
        this.keys = new Set(Object.keys(this.from).filter((k4) => k4 !== "__type"));
      }
      mark(key) {
        this.keys.delete(key);
      }
      hasUnknown() {
        return this.keys.size === 1 && Object.keys(this.to).length === 0;
      }
      writeUnknown() {
        if (this.hasUnknown()) {
          const k4 = this.keys.values().next().value;
          const v4 = this.from[k4];
          this.to.$unknown = [k4, v4];
        }
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReviver.js
function jsonReviver(key, value, context) {
  if (context?.source) {
    const numericString = context.source;
    if (typeof value === "number") {
      if (value > Number.MAX_SAFE_INTEGER || value < Number.MIN_SAFE_INTEGER || numericString !== String(value)) {
        const isFractional = numericString.includes(".");
        if (isFractional) {
          return new NumericValue(numericString, "bigDecimal");
        } else {
          return BigInt(numericString);
        }
      }
    }
  }
  return value;
}
var init_jsonReviver = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReviver.js"() {
    init_serde();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/common.js
var import_smithy_client2, import_util_utf86, collectBodyString;
var init_common = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/common.js"() {
    import_smithy_client2 = __toESM(require_dist_cjs26());
    import_util_utf86 = __toESM(require_dist_cjs10());
    collectBodyString = (streamBody, context) => (0, import_smithy_client2.collectBody)(streamBody, context).then((body) => (context?.utf8Encoder ?? import_util_utf86.toUtf8)(body));
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/parseJsonBody.js
var parseJsonBody, parseJsonErrorBody, loadRestJsonErrorCode;
var init_parseJsonBody = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/parseJsonBody.js"() {
    init_common();
    parseJsonBody = (streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
      if (encoded.length) {
        try {
          return JSON.parse(encoded);
        } catch (e4) {
          if (e4?.name === "SyntaxError") {
            Object.defineProperty(e4, "$responseBodyText", {
              value: encoded
            });
          }
          throw e4;
        }
      }
      return {};
    });
    parseJsonErrorBody = async (errorBody, context) => {
      const value = await parseJsonBody(errorBody, context);
      value.message = value.message ?? value.Message;
      return value;
    };
    loadRestJsonErrorCode = (output, data2) => {
      const findKey = (object, key) => Object.keys(object).find((k4) => k4.toLowerCase() === key.toLowerCase());
      const sanitizeErrorCode = (rawValue) => {
        let cleanValue = rawValue;
        if (typeof cleanValue === "number") {
          cleanValue = cleanValue.toString();
        }
        if (cleanValue.indexOf(",") >= 0) {
          cleanValue = cleanValue.split(",")[0];
        }
        if (cleanValue.indexOf(":") >= 0) {
          cleanValue = cleanValue.split(":")[0];
        }
        if (cleanValue.indexOf("#") >= 0) {
          cleanValue = cleanValue.split("#")[1];
        }
        return cleanValue;
      };
      const headerKey = findKey(output.headers, "x-amzn-errortype");
      if (headerKey !== void 0) {
        return sanitizeErrorCode(output.headers[headerKey]);
      }
      if (data2 && typeof data2 === "object") {
        const codeKey = findKey(data2, "code");
        if (codeKey && data2[codeKey] !== void 0) {
          return sanitizeErrorCode(data2[codeKey]);
        }
        if (data2["__type"] !== void 0) {
          return sanitizeErrorCode(data2["__type"]);
        }
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeDeserializer.js
var import_util_base644, JsonShapeDeserializer;
var init_JsonShapeDeserializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeDeserializer.js"() {
    init_protocols();
    init_schema();
    init_serde();
    import_util_base644 = __toESM(require_dist_cjs11());
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
      async read(schema, data2) {
        return this._read(schema, typeof data2 === "string" ? JSON.parse(data2, jsonReviver) : await parseJsonBody(data2, this.serdeContext));
      }
      readObject(schema, data2) {
        return this._read(schema, data2);
      }
      _read(schema, value) {
        const isObject = value !== null && typeof value === "object";
        const ns = NormalizedSchema.of(schema);
        if (isObject) {
          if (ns.isStructSchema()) {
            const union = ns.isUnionSchema();
            const out = {};
            let unionSerde;
            if (union) {
              unionSerde = new UnionSerde(value, out);
            }
            for (const [memberName, memberSchema] of deserializingStructIterator(ns, value, this.settings.jsonName ? "jsonName" : false)) {
              const fromKey = this.settings.jsonName ? memberSchema.getMergedTraits().jsonName ?? memberName : memberName;
              if (union) {
                unionSerde.mark(fromKey);
              }
              if (value[fromKey] != null) {
                out[memberName] = this._read(memberSchema, value[fromKey]);
              }
            }
            if (union) {
              unionSerde.writeUnknown();
            }
            return out;
          }
          if (Array.isArray(value) && ns.isListSchema()) {
            const listMember = ns.getValueSchema();
            const out = [];
            const sparse = !!ns.getMergedTraits().sparse;
            for (const item of value) {
              if (sparse || item != null) {
                out.push(this._read(listMember, item));
              }
            }
            return out;
          }
          if (ns.isMapSchema()) {
            const mapMember = ns.getValueSchema();
            const out = {};
            const sparse = !!ns.getMergedTraits().sparse;
            for (const [_k, _v] of Object.entries(value)) {
              if (sparse || _v != null) {
                out[_k] = this._read(mapMember, _v);
              }
            }
            return out;
          }
        }
        if (ns.isBlobSchema() && typeof value === "string") {
          return (0, import_util_base644.fromBase64)(value);
        }
        const mediaType = ns.getMergedTraits().mediaType;
        if (ns.isStringSchema() && typeof value === "string" && mediaType) {
          const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
          if (isJson) {
            return LazyJsonString.from(value);
          }
          return value;
        }
        if (ns.isTimestampSchema() && value != null) {
          const format2 = determineTimestampFormat(ns, this.settings);
          switch (format2) {
            case 5:
              return parseRfc3339DateTimeWithOffset(value);
            case 6:
              return parseRfc7231DateTime(value);
            case 7:
              return parseEpochTimestamp(value);
            default:
              console.warn("Missing timestamp format, parsing value with Date constructor:", value);
              return new Date(value);
          }
        }
        if (ns.isBigIntegerSchema() && (typeof value === "number" || typeof value === "string")) {
          return BigInt(value);
        }
        if (ns.isBigDecimalSchema() && value != void 0) {
          if (value instanceof NumericValue) {
            return value;
          }
          const untyped = value;
          if (untyped.type === "bigDecimal" && "string" in untyped) {
            return new NumericValue(untyped.string, untyped.type);
          }
          return new NumericValue(String(value), "bigDecimal");
        }
        if (ns.isNumericSchema() && typeof value === "string") {
          switch (value) {
            case "Infinity":
              return Infinity;
            case "-Infinity":
              return -Infinity;
            case "NaN":
              return NaN;
          }
          return value;
        }
        if (ns.isDocumentSchema()) {
          if (isObject) {
            const out = Array.isArray(value) ? [] : {};
            for (const [k4, v4] of Object.entries(value)) {
              if (v4 instanceof NumericValue) {
                out[k4] = v4;
              } else {
                out[k4] = this._read(ns, v4);
              }
            }
            return out;
          } else {
            return structuredClone(value);
          }
        }
        return value;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReplacer.js
var NUMERIC_CONTROL_CHAR, JsonReplacer;
var init_jsonReplacer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReplacer.js"() {
    init_serde();
    NUMERIC_CONTROL_CHAR = String.fromCharCode(925);
    JsonReplacer = class {
      values = /* @__PURE__ */ new Map();
      counter = 0;
      stage = 0;
      createReplacer() {
        if (this.stage === 1) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer already created.");
        }
        if (this.stage === 2) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
        }
        this.stage = 1;
        return (key, value) => {
          if (value instanceof NumericValue) {
            const v4 = `${NUMERIC_CONTROL_CHAR + "nv" + this.counter++}_` + value.string;
            this.values.set(`"${v4}"`, value.string);
            return v4;
          }
          if (typeof value === "bigint") {
            const s4 = value.toString();
            const v4 = `${NUMERIC_CONTROL_CHAR + "b" + this.counter++}_` + s4;
            this.values.set(`"${v4}"`, s4);
            return v4;
          }
          return value;
        };
      }
      replaceInJson(json) {
        if (this.stage === 0) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer not created yet.");
        }
        if (this.stage === 2) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
        }
        this.stage = 2;
        if (this.counter === 0) {
          return json;
        }
        for (const [key, value] of this.values) {
          json = json.replace(key, value);
        }
        return json;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeSerializer.js
var import_util_base645, JsonShapeSerializer;
var init_JsonShapeSerializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeSerializer.js"() {
    init_protocols();
    init_schema();
    init_serde();
    import_util_base645 = __toESM(require_dist_cjs11());
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
        if (typeof this.buffer === "object") {
          this.buffer.__type = NormalizedSchema.of(schema).getName(true);
        }
      }
      flush() {
        const { rootSchema, useReplacer } = this;
        this.rootSchema = void 0;
        this.useReplacer = false;
        if (rootSchema?.isStructSchema() || rootSchema?.isDocumentSchema()) {
          if (!useReplacer) {
            return JSON.stringify(this.buffer);
          }
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
                const [k4, v4] = $unknown;
                out[k4] = this._write(15, v4);
              }
            }
            return out;
          }
          if (Array.isArray(value) && ns.isListSchema()) {
            const listMember = ns.getValueSchema();
            const out = [];
            const sparse = !!ns.getMergedTraits().sparse;
            for (const item of value) {
              if (sparse || item != null) {
                out.push(this._write(listMember, item));
              }
            }
            return out;
          }
          if (ns.isMapSchema()) {
            const mapMember = ns.getValueSchema();
            const out = {};
            const sparse = !!ns.getMergedTraits().sparse;
            for (const [_k, _v] of Object.entries(value)) {
              if (sparse || _v != null) {
                out[_k] = this._write(mapMember, _v);
              }
            }
            return out;
          }
          if (value instanceof Uint8Array && (ns.isBlobSchema() || ns.isDocumentSchema())) {
            if (ns === this.rootSchema) {
              return value;
            }
            return (this.serdeContext?.base64Encoder ?? import_util_base645.toBase64)(value);
          }
          if (value instanceof Date && (ns.isTimestampSchema() || ns.isDocumentSchema())) {
            const format2 = determineTimestampFormat(ns, this.settings);
            switch (format2) {
              case 5:
                return value.toISOString().replace(".000Z", "Z");
              case 6:
                return dateToUtcString(value);
              case 7:
                return value.getTime() / 1e3;
              default:
                console.warn("Missing timestamp format, using epoch seconds", value);
                return value.getTime() / 1e3;
            }
          }
          if (value instanceof NumericValue) {
            this.useReplacer = true;
          }
        }
        if (value === null && container?.isStructSchema()) {
          return void 0;
        }
        if (ns.isStringSchema()) {
          if (typeof value === "undefined" && ns.isIdempotencyToken()) {
            return (0, import_uuid.v4)();
          }
          const mediaType = ns.getMergedTraits().mediaType;
          if (value != null && mediaType) {
            const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
            if (isJson) {
              return LazyJsonString.from(value);
            }
          }
          return value;
        }
        if (typeof value === "number" && ns.isNumericSchema()) {
          if (Math.abs(value) === Infinity || isNaN(value)) {
            return String(value);
          }
          return value;
        }
        if (typeof value === "string" && ns.isBlobSchema()) {
          if (ns === this.rootSchema) {
            return value;
          }
          return (this.serdeContext?.base64Encoder ?? import_util_base645.toBase64)(value);
        }
        if (typeof value === "bigint") {
          this.useReplacer = true;
        }
        if (ns.isDocumentSchema()) {
          if (isObject) {
            const out = Array.isArray(value) ? [] : {};
            for (const [k4, v4] of Object.entries(value)) {
              if (v4 instanceof NumericValue) {
                this.useReplacer = true;
                out[k4] = v4;
              } else {
                out[k4] = this._write(ns, v4);
              }
            }
            return out;
          } else {
            return structuredClone(value);
          }
        }
        return value;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonCodec.js
var JsonCodec;
var init_JsonCodec = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonCodec.js"() {
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
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJsonRpcProtocol.js
var AwsJsonRpcProtocol;
var init_AwsJsonRpcProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJsonRpcProtocol.js"() {
    init_protocols();
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
        super({
          defaultNamespace
        });
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
        if (!request.path.endsWith("/")) {
          request.path += "/";
        }
        Object.assign(request.headers, {
          "content-type": `application/x-amz-json-${this.getJsonRpcVersion()}`,
          "x-amz-target": `${this.serviceTarget}.${operationSchema.name}`
        });
        if (this.awsQueryCompatible) {
          request.headers["x-amzn-query-mode"] = "true";
        }
        if (deref(operationSchema.input) === "unit" || !request.body) {
          request.body = "{}";
        }
        return request;
      }
      getPayloadCodec() {
        return this.codec;
      }
      async handleError(operationSchema, context, response, dataObject, metadata) {
        if (this.awsQueryCompatible) {
          this.mixin.setQueryCompatError(dataObject, response);
        }
        const errorIdentifier = loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata, this.awsQueryCompatible ? this.mixin.findQueryCompatibleError : void 0);
        const ns = NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor = TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ?? Error;
        const exception = new ErrorCtor(message);
        const output = {};
        for (const [name, member2] of ns.structIterator()) {
          if (dataObject[name] != null) {
            output[name] = this.codec.createDeserializer().readObject(member2, dataObject[name]);
          }
        }
        if (this.awsQueryCompatible) {
          this.mixin.queryCompatOutput(dataObject, output);
        }
        throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
          $fault: ns.getMergedTraits().error,
          message
        }, output), dataObject);
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_0Protocol.js
var AwsJson1_0Protocol;
var init_AwsJson1_0Protocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_0Protocol.js"() {
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
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_1Protocol.js
var AwsJson1_1Protocol;
var init_AwsJson1_1Protocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_1Protocol.js"() {
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
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsRestJsonProtocol.js
var AwsRestJsonProtocol;
var init_AwsRestJsonProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsRestJsonProtocol.js"() {
    init_protocols();
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
        super({
          defaultNamespace
        });
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
          if (contentType) {
            request.headers["content-type"] = contentType;
          }
        }
        if (request.body == null && request.headers["content-type"] === this.getDefaultContentType()) {
          request.body = "{}";
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        const output = await super.deserializeResponse(operationSchema, context, response);
        const outputSchema = NormalizedSchema.of(operationSchema.output);
        for (const [name, member2] of outputSchema.structIterator()) {
          if (member2.getMemberTraits().httpPayload && !(name in output)) {
            output[name] = null;
          }
        }
        return output;
      }
      async handleError(operationSchema, context, response, dataObject, metadata) {
        const errorIdentifier = loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata);
        const ns = NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor = TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ?? Error;
        const exception = new ErrorCtor(message);
        await this.deserializeHttpMessage(errorSchema, context, response, dataObject);
        const output = {};
        for (const [name, member2] of ns.structIterator()) {
          const target = member2.getMergedTraits().jsonName ?? name;
          output[name] = this.codec.createDeserializer().readObject(member2, dataObject[target]);
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
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/awsExpectUnion.js
var import_smithy_client3, awsExpectUnion;
var init_awsExpectUnion = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/awsExpectUnion.js"() {
    import_smithy_client3 = __toESM(require_dist_cjs26());
    awsExpectUnion = (value) => {
      if (value == null) {
        return void 0;
      }
      if (typeof value === "object" && "__type" in value) {
        delete value.__type;
      }
      return (0, import_smithy_client3.expectUnion)(value);
    };
  }
});

// node_modules/fast-xml-parser/lib/fxp.cjs
var require_fxp = __commonJS({
  "node_modules/fast-xml-parser/lib/fxp.cjs"(exports, module) {
    (() => {
      "use strict";
      var t4 = { d: (e5, n5) => {
        for (var i5 in n5) t4.o(n5, i5) && !t4.o(e5, i5) && Object.defineProperty(e5, i5, { enumerable: true, get: n5[i5] });
      }, o: (t5, e5) => Object.prototype.hasOwnProperty.call(t5, e5), r: (t5) => {
        "undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(t5, Symbol.toStringTag, { value: "Module" }), Object.defineProperty(t5, "__esModule", { value: true });
      } }, e4 = {};
      t4.r(e4), t4.d(e4, { XMLBuilder: () => ft, XMLParser: () => st, XMLValidator: () => mt });
      const n4 = ":A-Za-z_\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD", i4 = new RegExp("^[" + n4 + "][" + n4 + "\\-.\\d\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$");
      function s4(t5, e5) {
        const n5 = [];
        let i5 = e5.exec(t5);
        for (; i5; ) {
          const s5 = [];
          s5.startIndex = e5.lastIndex - i5[0].length;
          const r5 = i5.length;
          for (let t6 = 0; t6 < r5; t6++) s5.push(i5[t6]);
          n5.push(s5), i5 = e5.exec(t5);
        }
        return n5;
      }
      const r4 = function(t5) {
        return !(null == i4.exec(t5));
      }, o4 = { allowBooleanAttributes: false, unpairedTags: [] };
      function a4(t5, e5) {
        e5 = Object.assign({}, o4, e5);
        const n5 = [];
        let i5 = false, s5 = false;
        "\uFEFF" === t5[0] && (t5 = t5.substr(1));
        for (let o5 = 0; o5 < t5.length; o5++) if ("<" === t5[o5] && "?" === t5[o5 + 1]) {
          if (o5 += 2, o5 = u4(t5, o5), o5.err) return o5;
        } else {
          if ("<" !== t5[o5]) {
            if (l4(t5[o5])) continue;
            return x4("InvalidChar", "char '" + t5[o5] + "' is not expected.", N(t5, o5));
          }
          {
            let a5 = o5;
            if (o5++, "!" === t5[o5]) {
              o5 = h4(t5, o5);
              continue;
            }
            {
              let d5 = false;
              "/" === t5[o5] && (d5 = true, o5++);
              let f5 = "";
              for (; o5 < t5.length && ">" !== t5[o5] && " " !== t5[o5] && "	" !== t5[o5] && "\n" !== t5[o5] && "\r" !== t5[o5]; o5++) f5 += t5[o5];
              if (f5 = f5.trim(), "/" === f5[f5.length - 1] && (f5 = f5.substring(0, f5.length - 1), o5--), !r4(f5)) {
                let e6;
                return e6 = 0 === f5.trim().length ? "Invalid space after '<'." : "Tag '" + f5 + "' is an invalid name.", x4("InvalidTag", e6, N(t5, o5));
              }
              const p5 = c4(t5, o5);
              if (false === p5) return x4("InvalidAttr", "Attributes for '" + f5 + "' have open quote.", N(t5, o5));
              let b5 = p5.value;
              if (o5 = p5.index, "/" === b5[b5.length - 1]) {
                const n6 = o5 - b5.length;
                b5 = b5.substring(0, b5.length - 1);
                const s6 = g4(b5, e5);
                if (true !== s6) return x4(s6.err.code, s6.err.msg, N(t5, n6 + s6.err.line));
                i5 = true;
              } else if (d5) {
                if (!p5.tagClosed) return x4("InvalidTag", "Closing tag '" + f5 + "' doesn't have proper closing.", N(t5, o5));
                if (b5.trim().length > 0) return x4("InvalidTag", "Closing tag '" + f5 + "' can't have attributes or invalid starting.", N(t5, a5));
                if (0 === n5.length) return x4("InvalidTag", "Closing tag '" + f5 + "' has not been opened.", N(t5, a5));
                {
                  const e6 = n5.pop();
                  if (f5 !== e6.tagName) {
                    let n6 = N(t5, e6.tagStartPos);
                    return x4("InvalidTag", "Expected closing tag '" + e6.tagName + "' (opened in line " + n6.line + ", col " + n6.col + ") instead of closing tag '" + f5 + "'.", N(t5, a5));
                  }
                  0 == n5.length && (s5 = true);
                }
              } else {
                const r5 = g4(b5, e5);
                if (true !== r5) return x4(r5.err.code, r5.err.msg, N(t5, o5 - b5.length + r5.err.line));
                if (true === s5) return x4("InvalidXml", "Multiple possible root nodes found.", N(t5, o5));
                -1 !== e5.unpairedTags.indexOf(f5) || n5.push({ tagName: f5, tagStartPos: a5 }), i5 = true;
              }
              for (o5++; o5 < t5.length; o5++) if ("<" === t5[o5]) {
                if ("!" === t5[o5 + 1]) {
                  o5++, o5 = h4(t5, o5);
                  continue;
                }
                if ("?" !== t5[o5 + 1]) break;
                if (o5 = u4(t5, ++o5), o5.err) return o5;
              } else if ("&" === t5[o5]) {
                const e6 = m4(t5, o5);
                if (-1 == e6) return x4("InvalidChar", "char '&' is not expected.", N(t5, o5));
                o5 = e6;
              } else if (true === s5 && !l4(t5[o5])) return x4("InvalidXml", "Extra text at the end", N(t5, o5));
              "<" === t5[o5] && o5--;
            }
          }
        }
        return i5 ? 1 == n5.length ? x4("InvalidTag", "Unclosed tag '" + n5[0].tagName + "'.", N(t5, n5[0].tagStartPos)) : !(n5.length > 0) || x4("InvalidXml", "Invalid '" + JSON.stringify(n5.map(((t6) => t6.tagName)), null, 4).replace(/\r?\n/g, "") + "' found.", { line: 1, col: 1 }) : x4("InvalidXml", "Start tag expected.", 1);
      }
      function l4(t5) {
        return " " === t5 || "	" === t5 || "\n" === t5 || "\r" === t5;
      }
      function u4(t5, e5) {
        const n5 = e5;
        for (; e5 < t5.length; e5++) if ("?" != t5[e5] && " " != t5[e5]) ;
        else {
          const i5 = t5.substr(n5, e5 - n5);
          if (e5 > 5 && "xml" === i5) return x4("InvalidXml", "XML declaration allowed only at the start of the document.", N(t5, e5));
          if ("?" == t5[e5] && ">" == t5[e5 + 1]) {
            e5++;
            break;
          }
        }
        return e5;
      }
      function h4(t5, e5) {
        if (t5.length > e5 + 5 && "-" === t5[e5 + 1] && "-" === t5[e5 + 2]) {
          for (e5 += 3; e5 < t5.length; e5++) if ("-" === t5[e5] && "-" === t5[e5 + 1] && ">" === t5[e5 + 2]) {
            e5 += 2;
            break;
          }
        } else if (t5.length > e5 + 8 && "D" === t5[e5 + 1] && "O" === t5[e5 + 2] && "C" === t5[e5 + 3] && "T" === t5[e5 + 4] && "Y" === t5[e5 + 5] && "P" === t5[e5 + 6] && "E" === t5[e5 + 7]) {
          let n5 = 1;
          for (e5 += 8; e5 < t5.length; e5++) if ("<" === t5[e5]) n5++;
          else if (">" === t5[e5] && (n5--, 0 === n5)) break;
        } else if (t5.length > e5 + 9 && "[" === t5[e5 + 1] && "C" === t5[e5 + 2] && "D" === t5[e5 + 3] && "A" === t5[e5 + 4] && "T" === t5[e5 + 5] && "A" === t5[e5 + 6] && "[" === t5[e5 + 7]) {
          for (e5 += 8; e5 < t5.length; e5++) if ("]" === t5[e5] && "]" === t5[e5 + 1] && ">" === t5[e5 + 2]) {
            e5 += 2;
            break;
          }
        }
        return e5;
      }
      const d4 = '"', f4 = "'";
      function c4(t5, e5) {
        let n5 = "", i5 = "", s5 = false;
        for (; e5 < t5.length; e5++) {
          if (t5[e5] === d4 || t5[e5] === f4) "" === i5 ? i5 = t5[e5] : i5 !== t5[e5] || (i5 = "");
          else if (">" === t5[e5] && "" === i5) {
            s5 = true;
            break;
          }
          n5 += t5[e5];
        }
        return "" === i5 && { value: n5, index: e5, tagClosed: s5 };
      }
      const p4 = new RegExp(`(\\s*)([^\\s=]+)(\\s*=)?(\\s*(['"])(([\\s\\S])*?)\\5)?`, "g");
      function g4(t5, e5) {
        const n5 = s4(t5, p4), i5 = {};
        for (let t6 = 0; t6 < n5.length; t6++) {
          if (0 === n5[t6][1].length) return x4("InvalidAttr", "Attribute '" + n5[t6][2] + "' has no space in starting.", E2(n5[t6]));
          if (void 0 !== n5[t6][3] && void 0 === n5[t6][4]) return x4("InvalidAttr", "Attribute '" + n5[t6][2] + "' is without value.", E2(n5[t6]));
          if (void 0 === n5[t6][3] && !e5.allowBooleanAttributes) return x4("InvalidAttr", "boolean attribute '" + n5[t6][2] + "' is not allowed.", E2(n5[t6]));
          const s5 = n5[t6][2];
          if (!b4(s5)) return x4("InvalidAttr", "Attribute '" + s5 + "' is an invalid name.", E2(n5[t6]));
          if (i5.hasOwnProperty(s5)) return x4("InvalidAttr", "Attribute '" + s5 + "' is repeated.", E2(n5[t6]));
          i5[s5] = 1;
        }
        return true;
      }
      function m4(t5, e5) {
        if (";" === t5[++e5]) return -1;
        if ("#" === t5[e5]) return (function(t6, e6) {
          let n6 = /\d/;
          for ("x" === t6[e6] && (e6++, n6 = /[\da-fA-F]/); e6 < t6.length; e6++) {
            if (";" === t6[e6]) return e6;
            if (!t6[e6].match(n6)) break;
          }
          return -1;
        })(t5, ++e5);
        let n5 = 0;
        for (; e5 < t5.length; e5++, n5++) if (!(t5[e5].match(/\w/) && n5 < 20)) {
          if (";" === t5[e5]) break;
          return -1;
        }
        return e5;
      }
      function x4(t5, e5, n5) {
        return { err: { code: t5, msg: e5, line: n5.line || n5, col: n5.col } };
      }
      function b4(t5) {
        return r4(t5);
      }
      function N(t5, e5) {
        const n5 = t5.substring(0, e5).split(/\r?\n/);
        return { line: n5.length, col: n5[n5.length - 1].length + 1 };
      }
      function E2(t5) {
        return t5.startIndex + t5[1].length;
      }
      const v4 = { preserveOrder: false, attributeNamePrefix: "@_", attributesGroupName: false, textNodeName: "#text", ignoreAttributes: true, removeNSPrefix: false, allowBooleanAttributes: false, parseTagValue: true, parseAttributeValue: false, trimValues: true, cdataPropName: false, numberParseOptions: { hex: true, leadingZeros: true, eNotation: true }, tagValueProcessor: function(t5, e5) {
        return e5;
      }, attributeValueProcessor: function(t5, e5) {
        return e5;
      }, stopNodes: [], alwaysCreateTextNode: false, isArray: () => false, commentPropName: false, unpairedTags: [], processEntities: true, htmlEntities: false, ignoreDeclaration: false, ignorePiTags: false, transformTagName: false, transformAttributeName: false, updateTag: function(t5, e5, n5) {
        return t5;
      }, captureMetaData: false };
      let y2;
      y2 = "function" != typeof Symbol ? "@@xmlMetadata" : /* @__PURE__ */ Symbol("XML Node Metadata");
      class T {
        constructor(t5) {
          this.tagname = t5, this.child = [], this[":@"] = {};
        }
        add(t5, e5) {
          "__proto__" === t5 && (t5 = "#__proto__"), this.child.push({ [t5]: e5 });
        }
        addChild(t5, e5) {
          "__proto__" === t5.tagname && (t5.tagname = "#__proto__"), t5[":@"] && Object.keys(t5[":@"]).length > 0 ? this.child.push({ [t5.tagname]: t5.child, ":@": t5[":@"] }) : this.child.push({ [t5.tagname]: t5.child }), void 0 !== e5 && (this.child[this.child.length - 1][y2] = { startIndex: e5 });
        }
        static getMetaDataSymbol() {
          return y2;
        }
      }
      function w4(t5, e5) {
        const n5 = {};
        if ("O" !== t5[e5 + 3] || "C" !== t5[e5 + 4] || "T" !== t5[e5 + 5] || "Y" !== t5[e5 + 6] || "P" !== t5[e5 + 7] || "E" !== t5[e5 + 8]) throw new Error("Invalid Tag instead of DOCTYPE");
        {
          e5 += 9;
          let i5 = 1, s5 = false, r5 = false, o5 = "";
          for (; e5 < t5.length; e5++) if ("<" !== t5[e5] || r5) if (">" === t5[e5]) {
            if (r5 ? "-" === t5[e5 - 1] && "-" === t5[e5 - 2] && (r5 = false, i5--) : i5--, 0 === i5) break;
          } else "[" === t5[e5] ? s5 = true : o5 += t5[e5];
          else {
            if (s5 && C2(t5, "!ENTITY", e5)) {
              let i6, s6;
              e5 += 7, [i6, s6, e5] = O(t5, e5 + 1), -1 === s6.indexOf("&") && (n5[i6] = { regx: RegExp(`&${i6};`, "g"), val: s6 });
            } else if (s5 && C2(t5, "!ELEMENT", e5)) {
              e5 += 8;
              const { index: n6 } = S(t5, e5 + 1);
              e5 = n6;
            } else if (s5 && C2(t5, "!ATTLIST", e5)) e5 += 8;
            else if (s5 && C2(t5, "!NOTATION", e5)) {
              e5 += 9;
              const { index: n6 } = A2(t5, e5 + 1);
              e5 = n6;
            } else {
              if (!C2(t5, "!--", e5)) throw new Error("Invalid DOCTYPE");
              r5 = true;
            }
            i5++, o5 = "";
          }
          if (0 !== i5) throw new Error("Unclosed DOCTYPE");
        }
        return { entities: n5, i: e5 };
      }
      const P = (t5, e5) => {
        for (; e5 < t5.length && /\s/.test(t5[e5]); ) e5++;
        return e5;
      };
      function O(t5, e5) {
        e5 = P(t5, e5);
        let n5 = "";
        for (; e5 < t5.length && !/\s/.test(t5[e5]) && '"' !== t5[e5] && "'" !== t5[e5]; ) n5 += t5[e5], e5++;
        if ($(n5), e5 = P(t5, e5), "SYSTEM" === t5.substring(e5, e5 + 6).toUpperCase()) throw new Error("External entities are not supported");
        if ("%" === t5[e5]) throw new Error("Parameter entities are not supported");
        let i5 = "";
        return [e5, i5] = I2(t5, e5, "entity"), [n5, i5, --e5];
      }
      function A2(t5, e5) {
        e5 = P(t5, e5);
        let n5 = "";
        for (; e5 < t5.length && !/\s/.test(t5[e5]); ) n5 += t5[e5], e5++;
        $(n5), e5 = P(t5, e5);
        const i5 = t5.substring(e5, e5 + 6).toUpperCase();
        if ("SYSTEM" !== i5 && "PUBLIC" !== i5) throw new Error(`Expected SYSTEM or PUBLIC, found "${i5}"`);
        e5 += i5.length, e5 = P(t5, e5);
        let s5 = null, r5 = null;
        if ("PUBLIC" === i5) [e5, s5] = I2(t5, e5, "publicIdentifier"), '"' !== t5[e5 = P(t5, e5)] && "'" !== t5[e5] || ([e5, r5] = I2(t5, e5, "systemIdentifier"));
        else if ("SYSTEM" === i5 && ([e5, r5] = I2(t5, e5, "systemIdentifier"), !r5)) throw new Error("Missing mandatory system identifier for SYSTEM notation");
        return { notationName: n5, publicIdentifier: s5, systemIdentifier: r5, index: --e5 };
      }
      function I2(t5, e5, n5) {
        let i5 = "";
        const s5 = t5[e5];
        if ('"' !== s5 && "'" !== s5) throw new Error(`Expected quoted string, found "${s5}"`);
        for (e5++; e5 < t5.length && t5[e5] !== s5; ) i5 += t5[e5], e5++;
        if (t5[e5] !== s5) throw new Error(`Unterminated ${n5} value`);
        return [++e5, i5];
      }
      function S(t5, e5) {
        e5 = P(t5, e5);
        let n5 = "";
        for (; e5 < t5.length && !/\s/.test(t5[e5]); ) n5 += t5[e5], e5++;
        if (!$(n5)) throw new Error(`Invalid element name: "${n5}"`);
        let i5 = "";
        if ("E" === t5[e5 = P(t5, e5)] && C2(t5, "MPTY", e5)) e5 += 4;
        else if ("A" === t5[e5] && C2(t5, "NY", e5)) e5 += 2;
        else {
          if ("(" !== t5[e5]) throw new Error(`Invalid Element Expression, found "${t5[e5]}"`);
          for (e5++; e5 < t5.length && ")" !== t5[e5]; ) i5 += t5[e5], e5++;
          if (")" !== t5[e5]) throw new Error("Unterminated content model");
        }
        return { elementName: n5, contentModel: i5.trim(), index: e5 };
      }
      function C2(t5, e5, n5) {
        for (let i5 = 0; i5 < e5.length; i5++) if (e5[i5] !== t5[n5 + i5 + 1]) return false;
        return true;
      }
      function $(t5) {
        if (r4(t5)) return t5;
        throw new Error(`Invalid entity name ${t5}`);
      }
      const j4 = /^[-+]?0x[a-fA-F0-9]+$/, D2 = /^([\-\+])?(0*)([0-9]*(\.[0-9]*)?)$/, V = { hex: true, leadingZeros: true, decimalPoint: ".", eNotation: true };
      const M = /^([-+])?(0*)(\d*(\.\d*)?[eE][-\+]?\d+)$/;
      function _(t5) {
        return "function" == typeof t5 ? t5 : Array.isArray(t5) ? (e5) => {
          for (const n5 of t5) {
            if ("string" == typeof n5 && e5 === n5) return true;
            if (n5 instanceof RegExp && n5.test(e5)) return true;
          }
        } : () => false;
      }
      class k4 {
        constructor(t5) {
          this.options = t5, this.currentNode = null, this.tagsNodeStack = [], this.docTypeEntities = {}, this.lastEntities = { apos: { regex: /&(apos|#39|#x27);/g, val: "'" }, gt: { regex: /&(gt|#62|#x3E);/g, val: ">" }, lt: { regex: /&(lt|#60|#x3C);/g, val: "<" }, quot: { regex: /&(quot|#34|#x22);/g, val: '"' } }, this.ampEntity = { regex: /&(amp|#38|#x26);/g, val: "&" }, this.htmlEntities = { space: { regex: /&(nbsp|#160);/g, val: " " }, cent: { regex: /&(cent|#162);/g, val: "\xA2" }, pound: { regex: /&(pound|#163);/g, val: "\xA3" }, yen: { regex: /&(yen|#165);/g, val: "\xA5" }, euro: { regex: /&(euro|#8364);/g, val: "\u20AC" }, copyright: { regex: /&(copy|#169);/g, val: "\xA9" }, reg: { regex: /&(reg|#174);/g, val: "\xAE" }, inr: { regex: /&(inr|#8377);/g, val: "\u20B9" }, num_dec: { regex: /&#([0-9]{1,7});/g, val: (t6, e5) => String.fromCodePoint(Number.parseInt(e5, 10)) }, num_hex: { regex: /&#x([0-9a-fA-F]{1,6});/g, val: (t6, e5) => String.fromCodePoint(Number.parseInt(e5, 16)) } }, this.addExternalEntities = F2, this.parseXml = X, this.parseTextData = L, this.resolveNameSpace = B2, this.buildAttributesMap = G2, this.isItStopNode = Z, this.replaceEntitiesValue = R, this.readStopNodeData = J2, this.saveTextToParentTag = q4, this.addChild = Y, this.ignoreAttributesFn = _(this.options.ignoreAttributes);
        }
      }
      function F2(t5) {
        const e5 = Object.keys(t5);
        for (let n5 = 0; n5 < e5.length; n5++) {
          const i5 = e5[n5];
          this.lastEntities[i5] = { regex: new RegExp("&" + i5 + ";", "g"), val: t5[i5] };
        }
      }
      function L(t5, e5, n5, i5, s5, r5, o5) {
        if (void 0 !== t5 && (this.options.trimValues && !i5 && (t5 = t5.trim()), t5.length > 0)) {
          o5 || (t5 = this.replaceEntitiesValue(t5));
          const i6 = this.options.tagValueProcessor(e5, t5, n5, s5, r5);
          return null == i6 ? t5 : typeof i6 != typeof t5 || i6 !== t5 ? i6 : this.options.trimValues || t5.trim() === t5 ? H2(t5, this.options.parseTagValue, this.options.numberParseOptions) : t5;
        }
      }
      function B2(t5) {
        if (this.options.removeNSPrefix) {
          const e5 = t5.split(":"), n5 = "/" === t5.charAt(0) ? "/" : "";
          if ("xmlns" === e5[0]) return "";
          2 === e5.length && (t5 = n5 + e5[1]);
        }
        return t5;
      }
      const U = new RegExp(`([^\\s=]+)\\s*(=\\s*(['"])([\\s\\S]*?)\\3)?`, "gm");
      function G2(t5, e5, n5) {
        if (true !== this.options.ignoreAttributes && "string" == typeof t5) {
          const n6 = s4(t5, U), i5 = n6.length, r5 = {};
          for (let t6 = 0; t6 < i5; t6++) {
            const i6 = this.resolveNameSpace(n6[t6][1]);
            if (this.ignoreAttributesFn(i6, e5)) continue;
            let s5 = n6[t6][4], o5 = this.options.attributeNamePrefix + i6;
            if (i6.length) if (this.options.transformAttributeName && (o5 = this.options.transformAttributeName(o5)), "__proto__" === o5 && (o5 = "#__proto__"), void 0 !== s5) {
              this.options.trimValues && (s5 = s5.trim()), s5 = this.replaceEntitiesValue(s5);
              const t7 = this.options.attributeValueProcessor(i6, s5, e5);
              r5[o5] = null == t7 ? s5 : typeof t7 != typeof s5 || t7 !== s5 ? t7 : H2(s5, this.options.parseAttributeValue, this.options.numberParseOptions);
            } else this.options.allowBooleanAttributes && (r5[o5] = true);
          }
          if (!Object.keys(r5).length) return;
          if (this.options.attributesGroupName) {
            const t6 = {};
            return t6[this.options.attributesGroupName] = r5, t6;
          }
          return r5;
        }
      }
      const X = function(t5) {
        t5 = t5.replace(/\r\n?/g, "\n");
        const e5 = new T("!xml");
        let n5 = e5, i5 = "", s5 = "";
        for (let r5 = 0; r5 < t5.length; r5++) if ("<" === t5[r5]) if ("/" === t5[r5 + 1]) {
          const e6 = W(t5, ">", r5, "Closing Tag is not closed.");
          let o5 = t5.substring(r5 + 2, e6).trim();
          if (this.options.removeNSPrefix) {
            const t6 = o5.indexOf(":");
            -1 !== t6 && (o5 = o5.substr(t6 + 1));
          }
          this.options.transformTagName && (o5 = this.options.transformTagName(o5)), n5 && (i5 = this.saveTextToParentTag(i5, n5, s5));
          const a5 = s5.substring(s5.lastIndexOf(".") + 1);
          if (o5 && -1 !== this.options.unpairedTags.indexOf(o5)) throw new Error(`Unpaired tag can not be used as closing tag: </${o5}>`);
          let l5 = 0;
          a5 && -1 !== this.options.unpairedTags.indexOf(a5) ? (l5 = s5.lastIndexOf(".", s5.lastIndexOf(".") - 1), this.tagsNodeStack.pop()) : l5 = s5.lastIndexOf("."), s5 = s5.substring(0, l5), n5 = this.tagsNodeStack.pop(), i5 = "", r5 = e6;
        } else if ("?" === t5[r5 + 1]) {
          let e6 = z2(t5, r5, false, "?>");
          if (!e6) throw new Error("Pi Tag is not closed.");
          if (i5 = this.saveTextToParentTag(i5, n5, s5), this.options.ignoreDeclaration && "?xml" === e6.tagName || this.options.ignorePiTags) ;
          else {
            const t6 = new T(e6.tagName);
            t6.add(this.options.textNodeName, ""), e6.tagName !== e6.tagExp && e6.attrExpPresent && (t6[":@"] = this.buildAttributesMap(e6.tagExp, s5, e6.tagName)), this.addChild(n5, t6, s5, r5);
          }
          r5 = e6.closeIndex + 1;
        } else if ("!--" === t5.substr(r5 + 1, 3)) {
          const e6 = W(t5, "-->", r5 + 4, "Comment is not closed.");
          if (this.options.commentPropName) {
            const o5 = t5.substring(r5 + 4, e6 - 2);
            i5 = this.saveTextToParentTag(i5, n5, s5), n5.add(this.options.commentPropName, [{ [this.options.textNodeName]: o5 }]);
          }
          r5 = e6;
        } else if ("!D" === t5.substr(r5 + 1, 2)) {
          const e6 = w4(t5, r5);
          this.docTypeEntities = e6.entities, r5 = e6.i;
        } else if ("![" === t5.substr(r5 + 1, 2)) {
          const e6 = W(t5, "]]>", r5, "CDATA is not closed.") - 2, o5 = t5.substring(r5 + 9, e6);
          i5 = this.saveTextToParentTag(i5, n5, s5);
          let a5 = this.parseTextData(o5, n5.tagname, s5, true, false, true, true);
          null == a5 && (a5 = ""), this.options.cdataPropName ? n5.add(this.options.cdataPropName, [{ [this.options.textNodeName]: o5 }]) : n5.add(this.options.textNodeName, a5), r5 = e6 + 2;
        } else {
          let o5 = z2(t5, r5, this.options.removeNSPrefix), a5 = o5.tagName;
          const l5 = o5.rawTagName;
          let u5 = o5.tagExp, h5 = o5.attrExpPresent, d5 = o5.closeIndex;
          this.options.transformTagName && (a5 = this.options.transformTagName(a5)), n5 && i5 && "!xml" !== n5.tagname && (i5 = this.saveTextToParentTag(i5, n5, s5, false));
          const f5 = n5;
          f5 && -1 !== this.options.unpairedTags.indexOf(f5.tagname) && (n5 = this.tagsNodeStack.pop(), s5 = s5.substring(0, s5.lastIndexOf("."))), a5 !== e5.tagname && (s5 += s5 ? "." + a5 : a5);
          const c5 = r5;
          if (this.isItStopNode(this.options.stopNodes, s5, a5)) {
            let e6 = "";
            if (u5.length > 0 && u5.lastIndexOf("/") === u5.length - 1) "/" === a5[a5.length - 1] ? (a5 = a5.substr(0, a5.length - 1), s5 = s5.substr(0, s5.length - 1), u5 = a5) : u5 = u5.substr(0, u5.length - 1), r5 = o5.closeIndex;
            else if (-1 !== this.options.unpairedTags.indexOf(a5)) r5 = o5.closeIndex;
            else {
              const n6 = this.readStopNodeData(t5, l5, d5 + 1);
              if (!n6) throw new Error(`Unexpected end of ${l5}`);
              r5 = n6.i, e6 = n6.tagContent;
            }
            const i6 = new T(a5);
            a5 !== u5 && h5 && (i6[":@"] = this.buildAttributesMap(u5, s5, a5)), e6 && (e6 = this.parseTextData(e6, a5, s5, true, h5, true, true)), s5 = s5.substr(0, s5.lastIndexOf(".")), i6.add(this.options.textNodeName, e6), this.addChild(n5, i6, s5, c5);
          } else {
            if (u5.length > 0 && u5.lastIndexOf("/") === u5.length - 1) {
              "/" === a5[a5.length - 1] ? (a5 = a5.substr(0, a5.length - 1), s5 = s5.substr(0, s5.length - 1), u5 = a5) : u5 = u5.substr(0, u5.length - 1), this.options.transformTagName && (a5 = this.options.transformTagName(a5));
              const t6 = new T(a5);
              a5 !== u5 && h5 && (t6[":@"] = this.buildAttributesMap(u5, s5, a5)), this.addChild(n5, t6, s5, c5), s5 = s5.substr(0, s5.lastIndexOf("."));
            } else {
              const t6 = new T(a5);
              this.tagsNodeStack.push(n5), a5 !== u5 && h5 && (t6[":@"] = this.buildAttributesMap(u5, s5, a5)), this.addChild(n5, t6, s5, c5), n5 = t6;
            }
            i5 = "", r5 = d5;
          }
        }
        else i5 += t5[r5];
        return e5.child;
      };
      function Y(t5, e5, n5, i5) {
        this.options.captureMetaData || (i5 = void 0);
        const s5 = this.options.updateTag(e5.tagname, n5, e5[":@"]);
        false === s5 || ("string" == typeof s5 ? (e5.tagname = s5, t5.addChild(e5, i5)) : t5.addChild(e5, i5));
      }
      const R = function(t5) {
        if (this.options.processEntities) {
          for (let e5 in this.docTypeEntities) {
            const n5 = this.docTypeEntities[e5];
            t5 = t5.replace(n5.regx, n5.val);
          }
          for (let e5 in this.lastEntities) {
            const n5 = this.lastEntities[e5];
            t5 = t5.replace(n5.regex, n5.val);
          }
          if (this.options.htmlEntities) for (let e5 in this.htmlEntities) {
            const n5 = this.htmlEntities[e5];
            t5 = t5.replace(n5.regex, n5.val);
          }
          t5 = t5.replace(this.ampEntity.regex, this.ampEntity.val);
        }
        return t5;
      };
      function q4(t5, e5, n5, i5) {
        return t5 && (void 0 === i5 && (i5 = 0 === e5.child.length), void 0 !== (t5 = this.parseTextData(t5, e5.tagname, n5, false, !!e5[":@"] && 0 !== Object.keys(e5[":@"]).length, i5)) && "" !== t5 && e5.add(this.options.textNodeName, t5), t5 = ""), t5;
      }
      function Z(t5, e5, n5) {
        const i5 = "*." + n5;
        for (const n6 in t5) {
          const s5 = t5[n6];
          if (i5 === s5 || e5 === s5) return true;
        }
        return false;
      }
      function W(t5, e5, n5, i5) {
        const s5 = t5.indexOf(e5, n5);
        if (-1 === s5) throw new Error(i5);
        return s5 + e5.length - 1;
      }
      function z2(t5, e5, n5, i5 = ">") {
        const s5 = (function(t6, e6, n6 = ">") {
          let i6, s6 = "";
          for (let r6 = e6; r6 < t6.length; r6++) {
            let e7 = t6[r6];
            if (i6) e7 === i6 && (i6 = "");
            else if ('"' === e7 || "'" === e7) i6 = e7;
            else if (e7 === n6[0]) {
              if (!n6[1]) return { data: s6, index: r6 };
              if (t6[r6 + 1] === n6[1]) return { data: s6, index: r6 };
            } else "	" === e7 && (e7 = " ");
            s6 += e7;
          }
        })(t5, e5 + 1, i5);
        if (!s5) return;
        let r5 = s5.data;
        const o5 = s5.index, a5 = r5.search(/\s/);
        let l5 = r5, u5 = true;
        -1 !== a5 && (l5 = r5.substring(0, a5), r5 = r5.substring(a5 + 1).trimStart());
        const h5 = l5;
        if (n5) {
          const t6 = l5.indexOf(":");
          -1 !== t6 && (l5 = l5.substr(t6 + 1), u5 = l5 !== s5.data.substr(t6 + 1));
        }
        return { tagName: l5, tagExp: r5, closeIndex: o5, attrExpPresent: u5, rawTagName: h5 };
      }
      function J2(t5, e5, n5) {
        const i5 = n5;
        let s5 = 1;
        for (; n5 < t5.length; n5++) if ("<" === t5[n5]) if ("/" === t5[n5 + 1]) {
          const r5 = W(t5, ">", n5, `${e5} is not closed`);
          if (t5.substring(n5 + 2, r5).trim() === e5 && (s5--, 0 === s5)) return { tagContent: t5.substring(i5, n5), i: r5 };
          n5 = r5;
        } else if ("?" === t5[n5 + 1]) n5 = W(t5, "?>", n5 + 1, "StopNode is not closed.");
        else if ("!--" === t5.substr(n5 + 1, 3)) n5 = W(t5, "-->", n5 + 3, "StopNode is not closed.");
        else if ("![" === t5.substr(n5 + 1, 2)) n5 = W(t5, "]]>", n5, "StopNode is not closed.") - 2;
        else {
          const i6 = z2(t5, n5, ">");
          i6 && ((i6 && i6.tagName) === e5 && "/" !== i6.tagExp[i6.tagExp.length - 1] && s5++, n5 = i6.closeIndex);
        }
      }
      function H2(t5, e5, n5) {
        if (e5 && "string" == typeof t5) {
          const e6 = t5.trim();
          return "true" === e6 || "false" !== e6 && (function(t6, e7 = {}) {
            if (e7 = Object.assign({}, V, e7), !t6 || "string" != typeof t6) return t6;
            let n6 = t6.trim();
            if (void 0 !== e7.skipLike && e7.skipLike.test(n6)) return t6;
            if ("0" === t6) return 0;
            if (e7.hex && j4.test(n6)) return (function(t7) {
              if (parseInt) return parseInt(t7, 16);
              if (Number.parseInt) return Number.parseInt(t7, 16);
              if (window && window.parseInt) return window.parseInt(t7, 16);
              throw new Error("parseInt, Number.parseInt, window.parseInt are not supported");
            })(n6);
            if (-1 !== n6.search(/.+[eE].+/)) return (function(t7, e8, n7) {
              if (!n7.eNotation) return t7;
              const i6 = e8.match(M);
              if (i6) {
                let s5 = i6[1] || "";
                const r5 = -1 === i6[3].indexOf("e") ? "E" : "e", o5 = i6[2], a5 = s5 ? t7[o5.length + 1] === r5 : t7[o5.length] === r5;
                return o5.length > 1 && a5 ? t7 : 1 !== o5.length || !i6[3].startsWith(`.${r5}`) && i6[3][0] !== r5 ? n7.leadingZeros && !a5 ? (e8 = (i6[1] || "") + i6[3], Number(e8)) : t7 : Number(e8);
              }
              return t7;
            })(t6, n6, e7);
            {
              const s5 = D2.exec(n6);
              if (s5) {
                const r5 = s5[1] || "", o5 = s5[2];
                let a5 = (i5 = s5[3]) && -1 !== i5.indexOf(".") ? ("." === (i5 = i5.replace(/0+$/, "")) ? i5 = "0" : "." === i5[0] ? i5 = "0" + i5 : "." === i5[i5.length - 1] && (i5 = i5.substring(0, i5.length - 1)), i5) : i5;
                const l5 = r5 ? "." === t6[o5.length + 1] : "." === t6[o5.length];
                if (!e7.leadingZeros && (o5.length > 1 || 1 === o5.length && !l5)) return t6;
                {
                  const i6 = Number(n6), s6 = String(i6);
                  if (0 === i6 || -0 === i6) return i6;
                  if (-1 !== s6.search(/[eE]/)) return e7.eNotation ? i6 : t6;
                  if (-1 !== n6.indexOf(".")) return "0" === s6 || s6 === a5 || s6 === `${r5}${a5}` ? i6 : t6;
                  let l6 = o5 ? a5 : n6;
                  return o5 ? l6 === s6 || r5 + l6 === s6 ? i6 : t6 : l6 === s6 || l6 === r5 + s6 ? i6 : t6;
                }
              }
              return t6;
            }
            var i5;
          })(t5, n5);
        }
        return void 0 !== t5 ? t5 : "";
      }
      const K = T.getMetaDataSymbol();
      function Q(t5, e5) {
        return tt(t5, e5);
      }
      function tt(t5, e5, n5) {
        let i5;
        const s5 = {};
        for (let r5 = 0; r5 < t5.length; r5++) {
          const o5 = t5[r5], a5 = et(o5);
          let l5 = "";
          if (l5 = void 0 === n5 ? a5 : n5 + "." + a5, a5 === e5.textNodeName) void 0 === i5 ? i5 = o5[a5] : i5 += "" + o5[a5];
          else {
            if (void 0 === a5) continue;
            if (o5[a5]) {
              let t6 = tt(o5[a5], e5, l5);
              const n6 = it(t6, e5);
              void 0 !== o5[K] && (t6[K] = o5[K]), o5[":@"] ? nt(t6, o5[":@"], l5, e5) : 1 !== Object.keys(t6).length || void 0 === t6[e5.textNodeName] || e5.alwaysCreateTextNode ? 0 === Object.keys(t6).length && (e5.alwaysCreateTextNode ? t6[e5.textNodeName] = "" : t6 = "") : t6 = t6[e5.textNodeName], void 0 !== s5[a5] && s5.hasOwnProperty(a5) ? (Array.isArray(s5[a5]) || (s5[a5] = [s5[a5]]), s5[a5].push(t6)) : e5.isArray(a5, l5, n6) ? s5[a5] = [t6] : s5[a5] = t6;
            }
          }
        }
        return "string" == typeof i5 ? i5.length > 0 && (s5[e5.textNodeName] = i5) : void 0 !== i5 && (s5[e5.textNodeName] = i5), s5;
      }
      function et(t5) {
        const e5 = Object.keys(t5);
        for (let t6 = 0; t6 < e5.length; t6++) {
          const n5 = e5[t6];
          if (":@" !== n5) return n5;
        }
      }
      function nt(t5, e5, n5, i5) {
        if (e5) {
          const s5 = Object.keys(e5), r5 = s5.length;
          for (let o5 = 0; o5 < r5; o5++) {
            const r6 = s5[o5];
            i5.isArray(r6, n5 + "." + r6, true, true) ? t5[r6] = [e5[r6]] : t5[r6] = e5[r6];
          }
        }
      }
      function it(t5, e5) {
        const { textNodeName: n5 } = e5, i5 = Object.keys(t5).length;
        return 0 === i5 || !(1 !== i5 || !t5[n5] && "boolean" != typeof t5[n5] && 0 !== t5[n5]);
      }
      class st {
        constructor(t5) {
          this.externalEntities = {}, this.options = (function(t6) {
            return Object.assign({}, v4, t6);
          })(t5);
        }
        parse(t5, e5) {
          if ("string" == typeof t5) ;
          else {
            if (!t5.toString) throw new Error("XML data is accepted in String or Bytes[] form.");
            t5 = t5.toString();
          }
          if (e5) {
            true === e5 && (e5 = {});
            const n6 = a4(t5, e5);
            if (true !== n6) throw Error(`${n6.err.msg}:${n6.err.line}:${n6.err.col}`);
          }
          const n5 = new k4(this.options);
          n5.addExternalEntities(this.externalEntities);
          const i5 = n5.parseXml(t5);
          return this.options.preserveOrder || void 0 === i5 ? i5 : Q(i5, this.options);
        }
        addEntity(t5, e5) {
          if (-1 !== e5.indexOf("&")) throw new Error("Entity value can't have '&'");
          if (-1 !== t5.indexOf("&") || -1 !== t5.indexOf(";")) throw new Error("An entity must be set without '&' and ';'. Eg. use '#xD' for '&#xD;'");
          if ("&" === e5) throw new Error("An entity with value '&' is not permitted");
          this.externalEntities[t5] = e5;
        }
        static getMetaDataSymbol() {
          return T.getMetaDataSymbol();
        }
      }
      function rt(t5, e5) {
        let n5 = "";
        return e5.format && e5.indentBy.length > 0 && (n5 = "\n"), ot(t5, e5, "", n5);
      }
      function ot(t5, e5, n5, i5) {
        let s5 = "", r5 = false;
        for (let o5 = 0; o5 < t5.length; o5++) {
          const a5 = t5[o5], l5 = at(a5);
          if (void 0 === l5) continue;
          let u5 = "";
          if (u5 = 0 === n5.length ? l5 : `${n5}.${l5}`, l5 === e5.textNodeName) {
            let t6 = a5[l5];
            ut(u5, e5) || (t6 = e5.tagValueProcessor(l5, t6), t6 = ht(t6, e5)), r5 && (s5 += i5), s5 += t6, r5 = false;
            continue;
          }
          if (l5 === e5.cdataPropName) {
            r5 && (s5 += i5), s5 += `<![CDATA[${a5[l5][0][e5.textNodeName]}]]>`, r5 = false;
            continue;
          }
          if (l5 === e5.commentPropName) {
            s5 += i5 + `<!--${a5[l5][0][e5.textNodeName]}-->`, r5 = true;
            continue;
          }
          if ("?" === l5[0]) {
            const t6 = lt(a5[":@"], e5), n6 = "?xml" === l5 ? "" : i5;
            let o6 = a5[l5][0][e5.textNodeName];
            o6 = 0 !== o6.length ? " " + o6 : "", s5 += n6 + `<${l5}${o6}${t6}?>`, r5 = true;
            continue;
          }
          let h5 = i5;
          "" !== h5 && (h5 += e5.indentBy);
          const d5 = i5 + `<${l5}${lt(a5[":@"], e5)}`, f5 = ot(a5[l5], e5, u5, h5);
          -1 !== e5.unpairedTags.indexOf(l5) ? e5.suppressUnpairedNode ? s5 += d5 + ">" : s5 += d5 + "/>" : f5 && 0 !== f5.length || !e5.suppressEmptyNode ? f5 && f5.endsWith(">") ? s5 += d5 + `>${f5}${i5}</${l5}>` : (s5 += d5 + ">", f5 && "" !== i5 && (f5.includes("/>") || f5.includes("</")) ? s5 += i5 + e5.indentBy + f5 + i5 : s5 += f5, s5 += `</${l5}>`) : s5 += d5 + "/>", r5 = true;
        }
        return s5;
      }
      function at(t5) {
        const e5 = Object.keys(t5);
        for (let n5 = 0; n5 < e5.length; n5++) {
          const i5 = e5[n5];
          if (t5.hasOwnProperty(i5) && ":@" !== i5) return i5;
        }
      }
      function lt(t5, e5) {
        let n5 = "";
        if (t5 && !e5.ignoreAttributes) for (let i5 in t5) {
          if (!t5.hasOwnProperty(i5)) continue;
          let s5 = e5.attributeValueProcessor(i5, t5[i5]);
          s5 = ht(s5, e5), true === s5 && e5.suppressBooleanAttributes ? n5 += ` ${i5.substr(e5.attributeNamePrefix.length)}` : n5 += ` ${i5.substr(e5.attributeNamePrefix.length)}="${s5}"`;
        }
        return n5;
      }
      function ut(t5, e5) {
        let n5 = (t5 = t5.substr(0, t5.length - e5.textNodeName.length - 1)).substr(t5.lastIndexOf(".") + 1);
        for (let i5 in e5.stopNodes) if (e5.stopNodes[i5] === t5 || e5.stopNodes[i5] === "*." + n5) return true;
        return false;
      }
      function ht(t5, e5) {
        if (t5 && t5.length > 0 && e5.processEntities) for (let n5 = 0; n5 < e5.entities.length; n5++) {
          const i5 = e5.entities[n5];
          t5 = t5.replace(i5.regex, i5.val);
        }
        return t5;
      }
      const dt = { attributeNamePrefix: "@_", attributesGroupName: false, textNodeName: "#text", ignoreAttributes: true, cdataPropName: false, format: false, indentBy: "  ", suppressEmptyNode: false, suppressUnpairedNode: true, suppressBooleanAttributes: true, tagValueProcessor: function(t5, e5) {
        return e5;
      }, attributeValueProcessor: function(t5, e5) {
        return e5;
      }, preserveOrder: false, commentPropName: false, unpairedTags: [], entities: [{ regex: new RegExp("&", "g"), val: "&amp;" }, { regex: new RegExp(">", "g"), val: "&gt;" }, { regex: new RegExp("<", "g"), val: "&lt;" }, { regex: new RegExp("'", "g"), val: "&apos;" }, { regex: new RegExp('"', "g"), val: "&quot;" }], processEntities: true, stopNodes: [], oneListGroup: false };
      function ft(t5) {
        this.options = Object.assign({}, dt, t5), true === this.options.ignoreAttributes || this.options.attributesGroupName ? this.isAttribute = function() {
          return false;
        } : (this.ignoreAttributesFn = _(this.options.ignoreAttributes), this.attrPrefixLen = this.options.attributeNamePrefix.length, this.isAttribute = gt), this.processTextOrObjNode = ct, this.options.format ? (this.indentate = pt, this.tagEndChar = ">\n", this.newLine = "\n") : (this.indentate = function() {
          return "";
        }, this.tagEndChar = ">", this.newLine = "");
      }
      function ct(t5, e5, n5, i5) {
        const s5 = this.j2x(t5, n5 + 1, i5.concat(e5));
        return void 0 !== t5[this.options.textNodeName] && 1 === Object.keys(t5).length ? this.buildTextValNode(t5[this.options.textNodeName], e5, s5.attrStr, n5) : this.buildObjectNode(s5.val, e5, s5.attrStr, n5);
      }
      function pt(t5) {
        return this.options.indentBy.repeat(t5);
      }
      function gt(t5) {
        return !(!t5.startsWith(this.options.attributeNamePrefix) || t5 === this.options.textNodeName) && t5.substr(this.attrPrefixLen);
      }
      ft.prototype.build = function(t5) {
        return this.options.preserveOrder ? rt(t5, this.options) : (Array.isArray(t5) && this.options.arrayNodeName && this.options.arrayNodeName.length > 1 && (t5 = { [this.options.arrayNodeName]: t5 }), this.j2x(t5, 0, []).val);
      }, ft.prototype.j2x = function(t5, e5, n5) {
        let i5 = "", s5 = "";
        const r5 = n5.join(".");
        for (let o5 in t5) if (Object.prototype.hasOwnProperty.call(t5, o5)) if (void 0 === t5[o5]) this.isAttribute(o5) && (s5 += "");
        else if (null === t5[o5]) this.isAttribute(o5) || o5 === this.options.cdataPropName ? s5 += "" : "?" === o5[0] ? s5 += this.indentate(e5) + "<" + o5 + "?" + this.tagEndChar : s5 += this.indentate(e5) + "<" + o5 + "/" + this.tagEndChar;
        else if (t5[o5] instanceof Date) s5 += this.buildTextValNode(t5[o5], o5, "", e5);
        else if ("object" != typeof t5[o5]) {
          const n6 = this.isAttribute(o5);
          if (n6 && !this.ignoreAttributesFn(n6, r5)) i5 += this.buildAttrPairStr(n6, "" + t5[o5]);
          else if (!n6) if (o5 === this.options.textNodeName) {
            let e6 = this.options.tagValueProcessor(o5, "" + t5[o5]);
            s5 += this.replaceEntitiesValue(e6);
          } else s5 += this.buildTextValNode(t5[o5], o5, "", e5);
        } else if (Array.isArray(t5[o5])) {
          const i6 = t5[o5].length;
          let r6 = "", a5 = "";
          for (let l5 = 0; l5 < i6; l5++) {
            const i7 = t5[o5][l5];
            if (void 0 === i7) ;
            else if (null === i7) "?" === o5[0] ? s5 += this.indentate(e5) + "<" + o5 + "?" + this.tagEndChar : s5 += this.indentate(e5) + "<" + o5 + "/" + this.tagEndChar;
            else if ("object" == typeof i7) if (this.options.oneListGroup) {
              const t6 = this.j2x(i7, e5 + 1, n5.concat(o5));
              r6 += t6.val, this.options.attributesGroupName && i7.hasOwnProperty(this.options.attributesGroupName) && (a5 += t6.attrStr);
            } else r6 += this.processTextOrObjNode(i7, o5, e5, n5);
            else if (this.options.oneListGroup) {
              let t6 = this.options.tagValueProcessor(o5, i7);
              t6 = this.replaceEntitiesValue(t6), r6 += t6;
            } else r6 += this.buildTextValNode(i7, o5, "", e5);
          }
          this.options.oneListGroup && (r6 = this.buildObjectNode(r6, o5, a5, e5)), s5 += r6;
        } else if (this.options.attributesGroupName && o5 === this.options.attributesGroupName) {
          const e6 = Object.keys(t5[o5]), n6 = e6.length;
          for (let s6 = 0; s6 < n6; s6++) i5 += this.buildAttrPairStr(e6[s6], "" + t5[o5][e6[s6]]);
        } else s5 += this.processTextOrObjNode(t5[o5], o5, e5, n5);
        return { attrStr: i5, val: s5 };
      }, ft.prototype.buildAttrPairStr = function(t5, e5) {
        return e5 = this.options.attributeValueProcessor(t5, "" + e5), e5 = this.replaceEntitiesValue(e5), this.options.suppressBooleanAttributes && "true" === e5 ? " " + t5 : " " + t5 + '="' + e5 + '"';
      }, ft.prototype.buildObjectNode = function(t5, e5, n5, i5) {
        if ("" === t5) return "?" === e5[0] ? this.indentate(i5) + "<" + e5 + n5 + "?" + this.tagEndChar : this.indentate(i5) + "<" + e5 + n5 + this.closeTag(e5) + this.tagEndChar;
        {
          let s5 = "</" + e5 + this.tagEndChar, r5 = "";
          return "?" === e5[0] && (r5 = "?", s5 = ""), !n5 && "" !== n5 || -1 !== t5.indexOf("<") ? false !== this.options.commentPropName && e5 === this.options.commentPropName && 0 === r5.length ? this.indentate(i5) + `<!--${t5}-->` + this.newLine : this.indentate(i5) + "<" + e5 + n5 + r5 + this.tagEndChar + t5 + this.indentate(i5) + s5 : this.indentate(i5) + "<" + e5 + n5 + r5 + ">" + t5 + s5;
        }
      }, ft.prototype.closeTag = function(t5) {
        let e5 = "";
        return -1 !== this.options.unpairedTags.indexOf(t5) ? this.options.suppressUnpairedNode || (e5 = "/") : e5 = this.options.suppressEmptyNode ? "/" : `></${t5}`, e5;
      }, ft.prototype.buildTextValNode = function(t5, e5, n5, i5) {
        if (false !== this.options.cdataPropName && e5 === this.options.cdataPropName) return this.indentate(i5) + `<![CDATA[${t5}]]>` + this.newLine;
        if (false !== this.options.commentPropName && e5 === this.options.commentPropName) return this.indentate(i5) + `<!--${t5}-->` + this.newLine;
        if ("?" === e5[0]) return this.indentate(i5) + "<" + e5 + n5 + "?" + this.tagEndChar;
        {
          let s5 = this.options.tagValueProcessor(e5, t5);
          return s5 = this.replaceEntitiesValue(s5), "" === s5 ? this.indentate(i5) + "<" + e5 + n5 + this.closeTag(e5) + this.tagEndChar : this.indentate(i5) + "<" + e5 + n5 + ">" + s5 + "</" + e5 + this.tagEndChar;
        }
      }, ft.prototype.replaceEntitiesValue = function(t5) {
        if (t5 && t5.length > 0 && this.options.processEntities) for (let e5 = 0; e5 < this.options.entities.length; e5++) {
          const n5 = this.options.entities[e5];
          t5 = t5.replace(n5.regex, n5.val);
        }
        return t5;
      };
      const mt = { validate: a4 };
      module.exports = e4;
    })();
  }
});

// node_modules/@aws-sdk/xml-builder/dist-cjs/xml-parser.js
var require_xml_parser = __commonJS({
  "node_modules/@aws-sdk/xml-builder/dist-cjs/xml-parser.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.parseXML = parseXML3;
    var fast_xml_parser_1 = require_fxp();
    var parser = new fast_xml_parser_1.XMLParser({
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
    function parseXML3(xmlString) {
      return parser.parse(xmlString, true);
    }
  }
});

// node_modules/@aws-sdk/xml-builder/dist-cjs/index.js
var require_dist_cjs27 = __commonJS({
  "node_modules/@aws-sdk/xml-builder/dist-cjs/index.js"(exports) {
    "use strict";
    var xmlParser = require_xml_parser();
    function escapeAttribute(value) {
      return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }
    function escapeElement(value) {
      return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&apos;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\r/g, "&#x0D;").replace(/\n/g, "&#x0A;").replace(/\u0085/g, "&#x85;").replace(/\u2028/, "&#x2028;");
    }
    var XmlText2 = class {
      value;
      constructor(value) {
        this.value = value;
      }
      toString() {
        return escapeElement("" + this.value);
      }
    };
    var XmlNode2 = class _XmlNode {
      name;
      children;
      attributes = {};
      static of(name, childText, withName) {
        const node = new _XmlNode(name);
        if (childText !== void 0) {
          node.addChildNode(new XmlText2(childText));
        }
        if (withName !== void 0) {
          node.withName(withName);
        }
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
        if (value != null) {
          this.attributes[name] = value;
        }
        return this;
      }
      cc(input, field, withName = field) {
        if (input[field] != null) {
          const node = _XmlNode.of(field, input[field]).withName(withName);
          this.c(node);
        }
      }
      l(input, listName, memberName, valueProvider) {
        if (input[listName] != null) {
          const nodes = valueProvider();
          nodes.map((node) => {
            node.withName(memberName);
            this.c(node);
          });
        }
      }
      lc(input, listName, memberName, valueProvider) {
        if (input[listName] != null) {
          const nodes = valueProvider();
          const containerNode = new _XmlNode(memberName);
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
          if (attribute != null) {
            xmlText += ` ${attributeName}="${escapeAttribute("" + attribute)}"`;
          }
        }
        return xmlText += !hasChildren ? "/>" : `>${this.children.map((c4) => c4.toString()).join("")}</${this.name}>`;
      }
    };
    Object.defineProperty(exports, "parseXML", {
      enumerable: true,
      get: function() {
        return xmlParser.parseXML;
      }
    });
    exports.XmlNode = XmlNode2;
    exports.XmlText = XmlText2;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeDeserializer.js
var import_xml_builder, import_smithy_client4, import_util_utf87, XmlShapeDeserializer;
var init_XmlShapeDeserializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeDeserializer.js"() {
    import_xml_builder = __toESM(require_dist_cjs27());
    init_protocols();
    init_schema();
    import_smithy_client4 = __toESM(require_dist_cjs26());
    import_util_utf87 = __toESM(require_dist_cjs10());
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
        const isEventPayload = ns.isStructSchema() && ns.isMemberSchema() && !!Object.values(memberSchemas).find((memberNs) => {
          return !!memberNs.getMemberTraits().eventPayload;
        });
        if (isEventPayload) {
          const output = {};
          const memberName = Object.keys(memberSchemas)[0];
          const eventMemberSchema = memberSchemas[memberName];
          if (eventMemberSchema.isBlobSchema()) {
            output[memberName] = bytes;
          } else {
            output[memberName] = this.read(memberSchemas[memberName], bytes);
          }
          return output;
        }
        const xmlString = (this.serdeContext?.utf8Encoder ?? import_util_utf87.toUtf8)(bytes);
        const parsedObject = this.parseXml(xmlString);
        return this.readSchema(schema, key ? parsedObject[key] : parsedObject);
      }
      readSchema(_schema, value) {
        const ns = NormalizedSchema.of(_schema);
        if (ns.isUnitSchema()) {
          return;
        }
        const traits = ns.getMergedTraits();
        if (ns.isListSchema() && !Array.isArray(value)) {
          return this.readSchema(ns, [value]);
        }
        if (value == null) {
          return value;
        }
        if (typeof value === "object") {
          const sparse = !!traits.sparse;
          const flat = !!traits.xmlFlattened;
          if (ns.isListSchema()) {
            const listValue = ns.getValueSchema();
            const buffer2 = [];
            const sourceKey = listValue.getMergedTraits().xmlName ?? "member";
            const source = flat ? value : (value[0] ?? value)[sourceKey];
            const sourceArray = Array.isArray(source) ? source : [source];
            for (const v4 of sourceArray) {
              if (v4 != null || sparse) {
                buffer2.push(this.readSchema(listValue, v4));
              }
            }
            return buffer2;
          }
          const buffer = {};
          if (ns.isMapSchema()) {
            const keyNs = ns.getKeySchema();
            const memberNs = ns.getValueSchema();
            let entries;
            if (flat) {
              entries = Array.isArray(value) ? value : [value];
            } else {
              entries = Array.isArray(value.entry) ? value.entry : [value.entry];
            }
            const keyProperty = keyNs.getMergedTraits().xmlName ?? "key";
            const valueProperty = memberNs.getMergedTraits().xmlName ?? "value";
            for (const entry of entries) {
              const key = entry[keyProperty];
              const value2 = entry[valueProperty];
              if (value2 != null || sparse) {
                buffer[key] = this.readSchema(memberNs, value2);
              }
            }
            return buffer;
          }
          if (ns.isStructSchema()) {
            const union = ns.isUnionSchema();
            let unionSerde;
            if (union) {
              unionSerde = new UnionSerde(value, buffer);
            }
            for (const [memberName, memberSchema] of ns.structIterator()) {
              const memberTraits = memberSchema.getMergedTraits();
              const xmlObjectKey = !memberTraits.httpPayload ? memberSchema.getMemberTraits().xmlName ?? memberName : memberTraits.xmlName ?? memberSchema.getName();
              if (union) {
                unionSerde.mark(xmlObjectKey);
              }
              if (value[xmlObjectKey] != null) {
                buffer[memberName] = this.readSchema(memberSchema, value[xmlObjectKey]);
              }
            }
            if (union) {
              unionSerde.writeUnknown();
            }
            return buffer;
          }
          if (ns.isDocumentSchema()) {
            return value;
          }
          throw new Error(`@aws-sdk/core/protocols - xml deserializer unhandled schema type for ${ns.getName(true)}`);
        }
        if (ns.isListSchema()) {
          return [];
        }
        if (ns.isMapSchema() || ns.isStructSchema()) {
          return {};
        }
        return this.stringDeserializer.read(ns, value);
      }
      parseXml(xml) {
        if (xml.length) {
          let parsedObj;
          try {
            parsedObj = (0, import_xml_builder.parseXML)(xml);
          } catch (e4) {
            if (e4 && typeof e4 === "object") {
              Object.defineProperty(e4, "$responseBodyText", {
                value: xml
              });
            }
            throw e4;
          }
          const textNodeName = "#text";
          const key = Object.keys(parsedObj)[0];
          const parsedObjToReturn = parsedObj[key];
          if (parsedObjToReturn[textNodeName]) {
            parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
            delete parsedObjToReturn[textNodeName];
          }
          return (0, import_smithy_client4.getValueFromTextNode)(parsedObjToReturn);
        }
        return {};
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/QueryShapeSerializer.js
var import_smithy_client5, import_util_base646, QueryShapeSerializer;
var init_QueryShapeSerializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/QueryShapeSerializer.js"() {
    init_protocols();
    init_schema();
    init_serde();
    import_smithy_client5 = __toESM(require_dist_cjs26());
    import_util_base646 = __toESM(require_dist_cjs11());
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
        if (this.buffer === void 0) {
          this.buffer = "";
        }
        const ns = NormalizedSchema.of(schema);
        if (prefix && !prefix.endsWith(".")) {
          prefix += ".";
        }
        if (ns.isBlobSchema()) {
          if (typeof value === "string" || value instanceof Uint8Array) {
            this.writeKey(prefix);
            this.writeValue((this.serdeContext?.base64Encoder ?? import_util_base646.toBase64)(value));
          }
        } else if (ns.isBooleanSchema() || ns.isNumericSchema() || ns.isStringSchema()) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(String(value));
          } else if (ns.isIdempotencyToken()) {
            this.writeKey(prefix);
            this.writeValue((0, import_uuid.v4)());
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
            const format2 = determineTimestampFormat(ns, this.settings);
            switch (format2) {
              case 5:
                this.writeValue(value.toISOString().replace(".000Z", "Z"));
                break;
              case 6:
                this.writeValue((0, import_smithy_client5.dateToUtcString)(value));
                break;
              case 7:
                this.writeValue(String(value.getTime() / 1e3));
                break;
            }
          }
        } else if (ns.isDocumentSchema()) {
          if (Array.isArray(value)) {
            this.write(64 | 15, value, prefix);
          } else if (value instanceof Date) {
            this.write(4, value, prefix);
          } else if (value instanceof Uint8Array) {
            this.write(21, value, prefix);
          } else if (value && typeof value === "object") {
            this.write(128 | 15, value, prefix);
          } else {
            this.writeKey(prefix);
            this.writeValue(String(value));
          }
        } else if (ns.isListSchema()) {
          if (Array.isArray(value)) {
            if (value.length === 0) {
              if (this.settings.serializeEmptyLists) {
                this.writeKey(prefix);
                this.writeValue("");
              }
            } else {
              const member2 = ns.getValueSchema();
              const flat = this.settings.flattenLists || ns.getMergedTraits().xmlFlattened;
              let i4 = 1;
              for (const item of value) {
                if (item == null) {
                  continue;
                }
                const suffix = this.getKey("member", member2.getMergedTraits().xmlName);
                const key = flat ? `${prefix}${i4}` : `${prefix}${suffix}.${i4}`;
                this.write(member2, item, key);
                ++i4;
              }
            }
          }
        } else if (ns.isMapSchema()) {
          if (value && typeof value === "object") {
            const keySchema = ns.getKeySchema();
            const memberSchema = ns.getValueSchema();
            const flat = ns.getMergedTraits().xmlFlattened;
            let i4 = 1;
            for (const [k4, v4] of Object.entries(value)) {
              if (v4 == null) {
                continue;
              }
              const keySuffix = this.getKey("key", keySchema.getMergedTraits().xmlName);
              const key = flat ? `${prefix}${i4}.${keySuffix}` : `${prefix}entry.${i4}.${keySuffix}`;
              const valueSuffix = this.getKey("value", memberSchema.getMergedTraits().xmlName);
              const valueKey = flat ? `${prefix}${i4}.${valueSuffix}` : `${prefix}entry.${i4}.${valueSuffix}`;
              this.write(keySchema, k4, key);
              this.write(memberSchema, v4, valueKey);
              ++i4;
            }
          }
        } else if (ns.isStructSchema()) {
          if (value && typeof value === "object") {
            let didWriteMember = false;
            for (const [memberName, member2] of serializingStructIterator(ns, value)) {
              if (value[memberName] == null && !member2.isIdempotencyToken()) {
                continue;
              }
              const suffix = this.getKey(memberName, member2.getMergedTraits().xmlName);
              const key = `${prefix}${suffix}`;
              this.write(member2, value[memberName], key);
              didWriteMember = true;
            }
            if (!didWriteMember && ns.isUnionSchema()) {
              const { $unknown } = value;
              if (Array.isArray($unknown)) {
                const [k4, v4] = $unknown;
                const key = `${prefix}${k4}`;
                this.write(15, v4, key);
              }
            }
          }
        } else if (ns.isUnitSchema()) {
        } else {
          throw new Error(`@aws-sdk/core/protocols - QuerySerializer unrecognized schema type ${ns.getName(true)}`);
        }
      }
      flush() {
        if (this.buffer === void 0) {
          throw new Error("@aws-sdk/core/protocols - QuerySerializer cannot flush with nothing written to buffer.");
        }
        const str = this.buffer;
        delete this.buffer;
        return str;
      }
      getKey(memberName, xmlName) {
        const key = xmlName ?? memberName;
        if (this.settings.capitalizeKeys) {
          return key[0].toUpperCase() + key.slice(1);
        }
        return key;
      }
      writeKey(key) {
        if (key.endsWith(".")) {
          key = key.slice(0, key.length - 1);
        }
        this.buffer += `&${extendedEncodeURIComponent(key)}=`;
      }
      writeValue(value) {
        this.buffer += extendedEncodeURIComponent(value);
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsQueryProtocol.js
var AwsQueryProtocol;
var init_AwsQueryProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsQueryProtocol.js"() {
    init_protocols();
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
        super({
          defaultNamespace: options.defaultNamespace
        });
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
        if (!request.path.endsWith("/")) {
          request.path += "/";
        }
        Object.assign(request.headers, {
          "content-type": `application/x-www-form-urlencoded`
        });
        if (deref(operationSchema.input) === "unit" || !request.body) {
          request.body = "";
        }
        const action = operationSchema.name.split("#")[1] ?? operationSchema.name;
        request.body = `Action=${action}&Version=${this.options.version}` + request.body;
        if (request.body.endsWith("&")) {
          request.body = request.body.slice(-1);
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        const deserializer = this.deserializer;
        const ns = NormalizedSchema.of(operationSchema.output);
        const dataObject = {};
        if (response.statusCode >= 300) {
          const bytes2 = await collectBody(response.body, context);
          if (bytes2.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(15, bytes2));
          }
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
        if (bytes.byteLength > 0) {
          Object.assign(dataObject, await deserializer.read(ns, bytes, awsQueryResultKey));
        }
        const output = {
          $metadata: this.deserializeMetadata(response),
          ...dataObject
        };
        return output;
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
        const ErrorCtor = TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ?? Error;
        const exception = new ErrorCtor(message);
        const output = {
          Type: errorData.Error.Type,
          Code: errorData.Error.Code,
          Error: errorData.Error
        };
        for (const [name, member2] of ns.structIterator()) {
          const target = member2.getMergedTraits().xmlName ?? name;
          const value = errorData[target] ?? dataObject[target];
          output[name] = this.deserializer.readSchema(member2, value);
        }
        throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
          $fault: ns.getMergedTraits().error,
          message
        }, output), dataObject);
      }
      loadQueryErrorCode(output, data2) {
        const code = (data2.Errors?.[0]?.Error ?? data2.Errors?.Error ?? data2.Error)?.Code;
        if (code !== void 0) {
          return code;
        }
        if (output.statusCode == 404) {
          return "NotFound";
        }
      }
      loadQueryError(data2) {
        return data2.Errors?.[0]?.Error ?? data2.Errors?.Error ?? data2.Error;
      }
      loadQueryErrorMessage(data2) {
        const errorData = this.loadQueryError(data2);
        return errorData?.message ?? errorData?.Message ?? data2.message ?? data2.Message ?? "Unknown";
      }
      getDefaultContentType() {
        return "application/x-www-form-urlencoded";
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsEc2QueryProtocol.js
var AwsEc2QueryProtocol;
var init_AwsEc2QueryProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsEc2QueryProtocol.js"() {
    init_AwsQueryProtocol();
    AwsEc2QueryProtocol = class extends AwsQueryProtocol {
      options;
      constructor(options) {
        super(options);
        this.options = options;
        const ec2Settings = {
          capitalizeKeys: true,
          flattenLists: true,
          serializeEmptyLists: false
        };
        Object.assign(this.serializer.settings, ec2Settings);
      }
      useNestedResult() {
        return false;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/parseXmlBody.js
var import_xml_builder2, import_smithy_client6, parseXmlBody, parseXmlErrorBody, loadRestXmlErrorCode;
var init_parseXmlBody = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/parseXmlBody.js"() {
    import_xml_builder2 = __toESM(require_dist_cjs27());
    import_smithy_client6 = __toESM(require_dist_cjs26());
    init_common();
    parseXmlBody = (streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
      if (encoded.length) {
        let parsedObj;
        try {
          parsedObj = (0, import_xml_builder2.parseXML)(encoded);
        } catch (e4) {
          if (e4 && typeof e4 === "object") {
            Object.defineProperty(e4, "$responseBodyText", {
              value: encoded
            });
          }
          throw e4;
        }
        const textNodeName = "#text";
        const key = Object.keys(parsedObj)[0];
        const parsedObjToReturn = parsedObj[key];
        if (parsedObjToReturn[textNodeName]) {
          parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
          delete parsedObjToReturn[textNodeName];
        }
        return (0, import_smithy_client6.getValueFromTextNode)(parsedObjToReturn);
      }
      return {};
    });
    parseXmlErrorBody = async (errorBody, context) => {
      const value = await parseXmlBody(errorBody, context);
      if (value.Error) {
        value.Error.message = value.Error.message ?? value.Error.Message;
      }
      return value;
    };
    loadRestXmlErrorCode = (output, data2) => {
      if (data2?.Error?.Code !== void 0) {
        return data2.Error.Code;
      }
      if (data2?.Code !== void 0) {
        return data2.Code;
      }
      if (output.statusCode == 404) {
        return "NotFound";
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeSerializer.js
var import_xml_builder3, import_smithy_client7, import_util_base647, XmlShapeSerializer;
var init_XmlShapeSerializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeSerializer.js"() {
    import_xml_builder3 = __toESM(require_dist_cjs27());
    init_protocols();
    init_schema();
    init_serde();
    import_smithy_client7 = __toESM(require_dist_cjs26());
    import_util_base647 = __toESM(require_dist_cjs11());
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
        if (ns.isStringSchema() && typeof value === "string") {
          this.stringBuffer = value;
        } else if (ns.isBlobSchema()) {
          this.byteBuffer = "byteLength" in value ? value : (this.serdeContext?.base64Decoder ?? import_util_base647.fromBase64)(value);
        } else {
          this.buffer = this.writeStruct(ns, value, void 0);
          const traits = ns.getMergedTraits();
          if (traits.httpPayload && !traits.xmlName) {
            this.buffer.withName(ns.getName());
          }
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
        const buffer = this.buffer;
        if (this.settings.xmlNamespace) {
          if (!buffer?.attributes?.["xmlns"]) {
            buffer.addAttribute("xmlns", this.settings.xmlNamespace);
          }
        }
        delete this.buffer;
        return buffer.toString();
      }
      writeStruct(ns, value, parentXmlns) {
        const traits = ns.getMergedTraits();
        const name = ns.isMemberSchema() && !traits.httpPayload ? ns.getMemberTraits().xmlName ?? ns.getMemberName() : traits.xmlName ?? ns.getName();
        if (!name || !ns.isStructSchema()) {
          throw new Error(`@aws-sdk/core/protocols - xml serializer, cannot write struct with empty name or non-struct, schema=${ns.getName(true)}.`);
        }
        const structXmlNode = import_xml_builder3.XmlNode.of(name);
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(ns, parentXmlns);
        for (const [memberName, memberSchema] of serializingStructIterator(ns, value)) {
          const val = value[memberName];
          if (val != null || memberSchema.isIdempotencyToken()) {
            if (memberSchema.getMergedTraits().xmlAttribute) {
              structXmlNode.addAttribute(memberSchema.getMergedTraits().xmlName ?? memberName, this.writeSimple(memberSchema, val));
              continue;
            }
            if (memberSchema.isListSchema()) {
              this.writeList(memberSchema, val, structXmlNode, xmlns);
            } else if (memberSchema.isMapSchema()) {
              this.writeMap(memberSchema, val, structXmlNode, xmlns);
            } else if (memberSchema.isStructSchema()) {
              structXmlNode.addChildNode(this.writeStruct(memberSchema, val, xmlns));
            } else {
              const memberNode = import_xml_builder3.XmlNode.of(memberSchema.getMergedTraits().xmlName ?? memberSchema.getMemberName());
              this.writeSimpleInto(memberSchema, val, memberNode, xmlns);
              structXmlNode.addChildNode(memberNode);
            }
          }
        }
        const { $unknown } = value;
        if ($unknown && ns.isUnionSchema() && Array.isArray($unknown) && Object.keys(value).length === 1) {
          const [k4, v4] = $unknown;
          const node = import_xml_builder3.XmlNode.of(k4);
          if (typeof v4 !== "string") {
            if (value instanceof import_xml_builder3.XmlNode || value instanceof import_xml_builder3.XmlText) {
              structXmlNode.addChildNode(value);
            } else {
              throw new Error(`@aws-sdk - $unknown union member in XML requires value of type string, @aws-sdk/xml-builder::XmlNode or XmlText.`);
            }
          }
          this.writeSimpleInto(0, v4, node, xmlns);
          structXmlNode.addChildNode(node);
        }
        if (xmlns) {
          structXmlNode.addAttribute(xmlnsAttr, xmlns);
        }
        return structXmlNode;
      }
      writeList(listMember, array, container, parentXmlns) {
        if (!listMember.isMemberSchema()) {
          throw new Error(`@aws-sdk/core/protocols - xml serializer, cannot write non-member list: ${listMember.getName(true)}`);
        }
        const listTraits = listMember.getMergedTraits();
        const listValueSchema = listMember.getValueSchema();
        const listValueTraits = listValueSchema.getMergedTraits();
        const sparse = !!listValueTraits.sparse;
        const flat = !!listTraits.xmlFlattened;
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(listMember, parentXmlns);
        const writeItem = (container2, value) => {
          if (listValueSchema.isListSchema()) {
            this.writeList(listValueSchema, Array.isArray(value) ? value : [value], container2, xmlns);
          } else if (listValueSchema.isMapSchema()) {
            this.writeMap(listValueSchema, value, container2, xmlns);
          } else if (listValueSchema.isStructSchema()) {
            const struct2 = this.writeStruct(listValueSchema, value, xmlns);
            container2.addChildNode(struct2.withName(flat ? listTraits.xmlName ?? listMember.getMemberName() : listValueTraits.xmlName ?? "member"));
          } else {
            const listItemNode = import_xml_builder3.XmlNode.of(flat ? listTraits.xmlName ?? listMember.getMemberName() : listValueTraits.xmlName ?? "member");
            this.writeSimpleInto(listValueSchema, value, listItemNode, xmlns);
            container2.addChildNode(listItemNode);
          }
        };
        if (flat) {
          for (const value of array) {
            if (sparse || value != null) {
              writeItem(container, value);
            }
          }
        } else {
          const listNode = import_xml_builder3.XmlNode.of(listTraits.xmlName ?? listMember.getMemberName());
          if (xmlns) {
            listNode.addAttribute(xmlnsAttr, xmlns);
          }
          for (const value of array) {
            if (sparse || value != null) {
              writeItem(listNode, value);
            }
          }
          container.addChildNode(listNode);
        }
      }
      writeMap(mapMember, map2, container, parentXmlns, containerIsMap = false) {
        if (!mapMember.isMemberSchema()) {
          throw new Error(`@aws-sdk/core/protocols - xml serializer, cannot write non-member map: ${mapMember.getName(true)}`);
        }
        const mapTraits = mapMember.getMergedTraits();
        const mapKeySchema = mapMember.getKeySchema();
        const mapKeyTraits = mapKeySchema.getMergedTraits();
        const keyTag = mapKeyTraits.xmlName ?? "key";
        const mapValueSchema = mapMember.getValueSchema();
        const mapValueTraits = mapValueSchema.getMergedTraits();
        const valueTag = mapValueTraits.xmlName ?? "value";
        const sparse = !!mapValueTraits.sparse;
        const flat = !!mapTraits.xmlFlattened;
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(mapMember, parentXmlns);
        const addKeyValue = (entry, key, val) => {
          const keyNode = import_xml_builder3.XmlNode.of(keyTag, key);
          const [keyXmlnsAttr, keyXmlns] = this.getXmlnsAttribute(mapKeySchema, xmlns);
          if (keyXmlns) {
            keyNode.addAttribute(keyXmlnsAttr, keyXmlns);
          }
          entry.addChildNode(keyNode);
          let valueNode = import_xml_builder3.XmlNode.of(valueTag);
          if (mapValueSchema.isListSchema()) {
            this.writeList(mapValueSchema, val, valueNode, xmlns);
          } else if (mapValueSchema.isMapSchema()) {
            this.writeMap(mapValueSchema, val, valueNode, xmlns, true);
          } else if (mapValueSchema.isStructSchema()) {
            valueNode = this.writeStruct(mapValueSchema, val, xmlns);
          } else {
            this.writeSimpleInto(mapValueSchema, val, valueNode, xmlns);
          }
          entry.addChildNode(valueNode);
        };
        if (flat) {
          for (const [key, val] of Object.entries(map2)) {
            if (sparse || val != null) {
              const entry = import_xml_builder3.XmlNode.of(mapTraits.xmlName ?? mapMember.getMemberName());
              addKeyValue(entry, key, val);
              container.addChildNode(entry);
            }
          }
        } else {
          let mapNode;
          if (!containerIsMap) {
            mapNode = import_xml_builder3.XmlNode.of(mapTraits.xmlName ?? mapMember.getMemberName());
            if (xmlns) {
              mapNode.addAttribute(xmlnsAttr, xmlns);
            }
            container.addChildNode(mapNode);
          }
          for (const [key, val] of Object.entries(map2)) {
            if (sparse || val != null) {
              const entry = import_xml_builder3.XmlNode.of("entry");
              addKeyValue(entry, key, val);
              (containerIsMap ? container : mapNode).addChildNode(entry);
            }
          }
        }
      }
      writeSimple(_schema, value) {
        if (null === value) {
          throw new Error("@aws-sdk/core/protocols - (XML serializer) cannot write null value.");
        }
        const ns = NormalizedSchema.of(_schema);
        let nodeContents = null;
        if (value && typeof value === "object") {
          if (ns.isBlobSchema()) {
            nodeContents = (this.serdeContext?.base64Encoder ?? import_util_base647.toBase64)(value);
          } else if (ns.isTimestampSchema() && value instanceof Date) {
            const format2 = determineTimestampFormat(ns, this.settings);
            switch (format2) {
              case 5:
                nodeContents = value.toISOString().replace(".000Z", "Z");
                break;
              case 6:
                nodeContents = (0, import_smithy_client7.dateToUtcString)(value);
                break;
              case 7:
                nodeContents = String(value.getTime() / 1e3);
                break;
              default:
                console.warn("Missing timestamp format, using http date", value);
                nodeContents = (0, import_smithy_client7.dateToUtcString)(value);
                break;
            }
          } else if (ns.isBigDecimalSchema() && value) {
            if (value instanceof NumericValue) {
              return value.string;
            }
            return String(value);
          } else if (ns.isMapSchema() || ns.isListSchema()) {
            throw new Error("@aws-sdk/core/protocols - xml serializer, cannot call _write() on List/Map schema, call writeList or writeMap() instead.");
          } else {
            throw new Error(`@aws-sdk/core/protocols - xml serializer, unhandled schema type for object value and schema: ${ns.getName(true)}`);
          }
        }
        if (ns.isBooleanSchema() || ns.isNumericSchema() || ns.isBigIntegerSchema() || ns.isBigDecimalSchema()) {
          nodeContents = String(value);
        }
        if (ns.isStringSchema()) {
          if (value === void 0 && ns.isIdempotencyToken()) {
            nodeContents = (0, import_uuid.v4)();
          } else {
            nodeContents = String(value);
          }
        }
        if (nodeContents === null) {
          throw new Error(`Unhandled schema-value pair ${ns.getName(true)}=${value}`);
        }
        return nodeContents;
      }
      writeSimpleInto(_schema, value, into, parentXmlns) {
        const nodeContents = this.writeSimple(_schema, value);
        const ns = NormalizedSchema.of(_schema);
        const content = new import_xml_builder3.XmlText(nodeContents);
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(ns, parentXmlns);
        if (xmlns) {
          into.addAttribute(xmlnsAttr, xmlns);
        }
        into.addChildNode(content);
      }
      getXmlnsAttribute(ns, parentXmlns) {
        const traits = ns.getMergedTraits();
        const [prefix, xmlns] = traits.xmlNamespace ?? [];
        if (xmlns && xmlns !== parentXmlns) {
          return [prefix ? `xmlns:${prefix}` : "xmlns", xmlns];
        }
        return [void 0, void 0];
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlCodec.js
var XmlCodec;
var init_XmlCodec = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlCodec.js"() {
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
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/AwsRestXmlProtocol.js
var AwsRestXmlProtocol;
var init_AwsRestXmlProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/AwsRestXmlProtocol.js"() {
    init_protocols();
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
          if (contentType) {
            request.headers["content-type"] = contentType;
          }
        }
        if (typeof request.body === "string" && request.headers["content-type"] === this.getDefaultContentType() && !request.body.startsWith("<?xml ") && !this.hasUnstructuredPayloadBinding(inputSchema)) {
          request.body = '<?xml version="1.0" encoding="UTF-8"?>' + request.body;
        }
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
        const ErrorCtor = TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ?? Error;
        const exception = new ErrorCtor(message);
        await this.deserializeHttpMessage(errorSchema, context, response, dataObject);
        const output = {};
        for (const [name, member2] of ns.structIterator()) {
          const target = member2.getMergedTraits().xmlName ?? name;
          const value = dataObject.Error?.[target] ?? dataObject[target];
          output[name] = this.codec.createDeserializer().readSchema(member2, value);
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
        for (const [, member2] of ns.structIterator()) {
          if (member2.getMergedTraits().httpPayload) {
            return !(member2.isStructSchema() || member2.isMapSchema() || member2.isListSchema());
          }
        }
        return false;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/index.js
var protocols_exports2 = {};
__export(protocols_exports2, {
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
var init_protocols2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/index.js"() {
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
  }
});

// node_modules/@aws-sdk/core/dist-es/index.js
var dist_es_exports2 = {};
__export(dist_es_exports2, {
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
  emitWarningIfUnsupportedVersion: () => emitWarningIfUnsupportedVersion,
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
  setFeature: () => setFeature2,
  setTokenFeature: () => setTokenFeature,
  state: () => state,
  validateSigningProperties: () => validateSigningProperties
});
var init_dist_es2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/index.js"() {
    init_client();
    init_httpAuthSchemes2();
    init_protocols2();
  }
});

// node_modules/@aws-sdk/middleware-user-agent/dist-cjs/index.js
var require_dist_cjs28 = __commonJS({
  "node_modules/@aws-sdk/middleware-user-agent/dist-cjs/index.js"(exports) {
    "use strict";
    var core = (init_dist_es(), __toCommonJS(dist_es_exports));
    var utilEndpoints = require_dist_cjs22();
    var protocolHttp = require_dist_cjs2();
    var core$1 = (init_dist_es2(), __toCommonJS(dist_es_exports2));
    var DEFAULT_UA_APP_ID = void 0;
    function isValidUserAgentAppId(appId) {
      if (appId === void 0) {
        return true;
      }
      return typeof appId === "string" && appId.length <= 50;
    }
    function resolveUserAgentConfig4(input) {
      const normalizedAppIdProvider = core.normalizeProvider(input.userAgentAppId ?? DEFAULT_UA_APP_ID);
      const { customUserAgent } = input;
      return Object.assign(input, {
        customUserAgent: typeof customUserAgent === "string" ? [[customUserAgent]] : customUserAgent,
        userAgentAppId: async () => {
          const appId = await normalizedAppIdProvider();
          if (!isValidUserAgentAppId(appId)) {
            const logger2 = input.logger?.constructor?.name === "NoOpLogger" || !input.logger ? console : input.logger;
            if (typeof appId !== "string") {
              logger2?.warn("userAgentAppId must be a string or undefined.");
            } else if (appId.length > 50) {
              logger2?.warn("The provided userAgentAppId exceeds the maximum length of 50 characters.");
            }
          }
          return appId;
        }
      });
    }
    var ACCOUNT_ID_ENDPOINT_REGEX = /\d{12}\.ddb/;
    async function checkFeatures(context, config, args) {
      const request = args.request;
      if (request?.headers?.["smithy-protocol"] === "rpc-v2-cbor") {
        core$1.setFeature(context, "PROTOCOL_RPC_V2_CBOR", "M");
      }
      if (typeof config.retryStrategy === "function") {
        const retryStrategy = await config.retryStrategy();
        if (typeof retryStrategy.acquireInitialRetryToken === "function") {
          if (retryStrategy.constructor?.name?.includes("Adaptive")) {
            core$1.setFeature(context, "RETRY_MODE_ADAPTIVE", "F");
          } else {
            core$1.setFeature(context, "RETRY_MODE_STANDARD", "E");
          }
        } else {
          core$1.setFeature(context, "RETRY_MODE_LEGACY", "D");
        }
      }
      if (typeof config.accountIdEndpointMode === "function") {
        const endpointV2 = context.endpointV2;
        if (String(endpointV2?.url?.hostname).match(ACCOUNT_ID_ENDPOINT_REGEX)) {
          core$1.setFeature(context, "ACCOUNT_ID_ENDPOINT", "O");
        }
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
        if (credentials.accountId) {
          core$1.setFeature(context, "RESOLVED_ACCOUNT_ID", "T");
        }
        for (const [key, value] of Object.entries(credentials.$source ?? {})) {
          core$1.setFeature(context, key, value);
        }
      }
    }
    var USER_AGENT = "user-agent";
    var X_AMZ_USER_AGENT = "x-amz-user-agent";
    var SPACE = " ";
    var UA_NAME_SEPARATOR = "/";
    var UA_NAME_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w]/g;
    var UA_VALUE_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w#]/g;
    var UA_ESCAPE_CHAR = "-";
    var BYTE_LIMIT = 1024;
    function encodeFeatures(features) {
      let buffer = "";
      for (const key in features) {
        const val = features[key];
        if (buffer.length + val.length + 1 <= BYTE_LIMIT) {
          if (buffer.length) {
            buffer += "," + val;
          } else {
            buffer += val;
          }
          continue;
        }
        break;
      }
      return buffer;
    }
    var userAgentMiddleware = (options) => (next, context) => async (args) => {
      const { request } = args;
      if (!protocolHttp.HttpRequest.isInstance(request)) {
        return next(args);
      }
      const { headers } = request;
      const userAgent = context?.userAgent?.map(escapeUserAgent) || [];
      const defaultUserAgent = (await options.defaultUserAgentProvider()).map(escapeUserAgent);
      await checkFeatures(context, options, args);
      const awsContext = context;
      defaultUserAgent.push(`m/${encodeFeatures(Object.assign({}, context.__smithy_context?.features, awsContext.__aws_sdk_context?.features))}`);
      const customUserAgent = options?.customUserAgent?.map(escapeUserAgent) || [];
      const appId = await options.userAgentAppId();
      if (appId) {
        defaultUserAgent.push(escapeUserAgent([`app`, `${appId}`]));
      }
      const prefix = utilEndpoints.getUserAgentPrefix();
      const sdkUserAgentValue = (prefix ? [prefix] : []).concat([...defaultUserAgent, ...userAgent, ...customUserAgent]).join(SPACE);
      const normalUAValue = [
        ...defaultUserAgent.filter((section) => section.startsWith("aws-sdk-")),
        ...customUserAgent
      ].join(SPACE);
      if (options.runtime !== "browser") {
        if (normalUAValue) {
          headers[X_AMZ_USER_AGENT] = headers[X_AMZ_USER_AGENT] ? `${headers[USER_AGENT]} ${normalUAValue}` : normalUAValue;
        }
        headers[USER_AGENT] = sdkUserAgentValue;
      } else {
        headers[X_AMZ_USER_AGENT] = sdkUserAgentValue;
      }
      return next({
        ...args,
        request
      });
    };
    var escapeUserAgent = (userAgentPair) => {
      const name = userAgentPair[0].split(UA_NAME_SEPARATOR).map((part) => part.replace(UA_NAME_ESCAPE_REGEX, UA_ESCAPE_CHAR)).join(UA_NAME_SEPARATOR);
      const version = userAgentPair[1]?.replace(UA_VALUE_ESCAPE_REGEX, UA_ESCAPE_CHAR);
      const prefixSeparatorIndex = name.indexOf(UA_NAME_SEPARATOR);
      const prefix = name.substring(0, prefixSeparatorIndex);
      let uaName = name.substring(prefixSeparatorIndex + 1);
      if (prefix === "api") {
        uaName = uaName.toLowerCase();
      }
      return [prefix, uaName, version].filter((item) => item && item.length > 0).reduce((acc, item, index) => {
        switch (index) {
          case 0:
            return item;
          case 1:
            return `${acc}/${item}`;
          default:
            return `${acc}#${item}`;
        }
      }, "");
    };
    var getUserAgentMiddlewareOptions = {
      name: "getUserAgentMiddleware",
      step: "build",
      priority: "low",
      tags: ["SET_USER_AGENT", "USER_AGENT"],
      override: true
    };
    var getUserAgentPlugin4 = (config) => ({
      applyToStack: (clientStack) => {
        clientStack.add(userAgentMiddleware(config), getUserAgentMiddlewareOptions);
      }
    });
    exports.DEFAULT_UA_APP_ID = DEFAULT_UA_APP_ID;
    exports.getUserAgentMiddlewareOptions = getUserAgentMiddlewareOptions;
    exports.getUserAgentPlugin = getUserAgentPlugin4;
    exports.resolveUserAgentConfig = resolveUserAgentConfig4;
    exports.userAgentMiddleware = userAgentMiddleware;
  }
});

// node_modules/@smithy/util-config-provider/dist-cjs/index.js
var require_dist_cjs29 = __commonJS({
  "node_modules/@smithy/util-config-provider/dist-cjs/index.js"(exports) {
    "use strict";
    var booleanSelector = (obj, key, type) => {
      if (!(key in obj))
        return void 0;
      if (obj[key] === "true")
        return true;
      if (obj[key] === "false")
        return false;
      throw new Error(`Cannot load ${type} "${key}". Expected "true" or "false", got ${obj[key]}.`);
    };
    var numberSelector = (obj, key, type) => {
      if (!(key in obj))
        return void 0;
      const numberValue = parseInt(obj[key], 10);
      if (Number.isNaN(numberValue)) {
        throw new TypeError(`Cannot load ${type} '${key}'. Expected number, got '${obj[key]}'.`);
      }
      return numberValue;
    };
    exports.SelectorType = void 0;
    (function(SelectorType) {
      SelectorType["ENV"] = "env";
      SelectorType["CONFIG"] = "shared config entry";
    })(exports.SelectorType || (exports.SelectorType = {}));
    exports.booleanSelector = booleanSelector;
    exports.numberSelector = numberSelector;
  }
});

// node_modules/@smithy/config-resolver/dist-cjs/index.js
var require_dist_cjs30 = __commonJS({
  "node_modules/@smithy/config-resolver/dist-cjs/index.js"(exports) {
    "use strict";
    var utilConfigProvider = require_dist_cjs29();
    var utilMiddleware = require_dist_cjs6();
    var utilEndpoints = require_dist_cjs19();
    var ENV_USE_DUALSTACK_ENDPOINT = "AWS_USE_DUALSTACK_ENDPOINT";
    var CONFIG_USE_DUALSTACK_ENDPOINT = "use_dualstack_endpoint";
    var DEFAULT_USE_DUALSTACK_ENDPOINT = false;
    var NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS4 = {
      environmentVariableSelector: (env) => utilConfigProvider.booleanSelector(env, ENV_USE_DUALSTACK_ENDPOINT, utilConfigProvider.SelectorType.ENV),
      configFileSelector: (profile) => utilConfigProvider.booleanSelector(profile, CONFIG_USE_DUALSTACK_ENDPOINT, utilConfigProvider.SelectorType.CONFIG),
      default: false
    };
    var ENV_USE_FIPS_ENDPOINT = "AWS_USE_FIPS_ENDPOINT";
    var CONFIG_USE_FIPS_ENDPOINT = "use_fips_endpoint";
    var DEFAULT_USE_FIPS_ENDPOINT = false;
    var NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS4 = {
      environmentVariableSelector: (env) => utilConfigProvider.booleanSelector(env, ENV_USE_FIPS_ENDPOINT, utilConfigProvider.SelectorType.ENV),
      configFileSelector: (profile) => utilConfigProvider.booleanSelector(profile, CONFIG_USE_FIPS_ENDPOINT, utilConfigProvider.SelectorType.CONFIG),
      default: false
    };
    var resolveCustomEndpointsConfig = (input) => {
      const { tls, endpoint, urlParser, useDualstackEndpoint } = input;
      return Object.assign(input, {
        tls: tls ?? true,
        endpoint: utilMiddleware.normalizeProvider(typeof endpoint === "string" ? urlParser(endpoint) : endpoint),
        isCustomEndpoint: true,
        useDualstackEndpoint: utilMiddleware.normalizeProvider(useDualstackEndpoint ?? false)
      });
    };
    var getEndpointFromRegion = async (input) => {
      const { tls = true } = input;
      const region = await input.region();
      const dnsHostRegex = new RegExp(/^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])$/);
      if (!dnsHostRegex.test(region)) {
        throw new Error("Invalid region in client config");
      }
      const useDualstackEndpoint = await input.useDualstackEndpoint();
      const useFipsEndpoint = await input.useFipsEndpoint();
      const { hostname } = await input.regionInfoProvider(region, { useDualstackEndpoint, useFipsEndpoint }) ?? {};
      if (!hostname) {
        throw new Error("Cannot resolve hostname from client config");
      }
      return input.urlParser(`${tls ? "https:" : "http:"}//${hostname}`);
    };
    var resolveEndpointsConfig = (input) => {
      const useDualstackEndpoint = utilMiddleware.normalizeProvider(input.useDualstackEndpoint ?? false);
      const { endpoint, useFipsEndpoint, urlParser, tls } = input;
      return Object.assign(input, {
        tls: tls ?? true,
        endpoint: endpoint ? utilMiddleware.normalizeProvider(typeof endpoint === "string" ? urlParser(endpoint) : endpoint) : () => getEndpointFromRegion({ ...input, useDualstackEndpoint, useFipsEndpoint }),
        isCustomEndpoint: !!endpoint,
        useDualstackEndpoint
      });
    };
    var REGION_ENV_NAME = "AWS_REGION";
    var REGION_INI_NAME = "region";
    var NODE_REGION_CONFIG_OPTIONS4 = {
      environmentVariableSelector: (env) => env[REGION_ENV_NAME],
      configFileSelector: (profile) => profile[REGION_INI_NAME],
      default: () => {
        throw new Error("Region is missing");
      }
    };
    var NODE_REGION_CONFIG_FILE_OPTIONS4 = {
      preferredFile: "credentials"
    };
    var validRegions = /* @__PURE__ */ new Set();
    var checkRegion = (region, check = utilEndpoints.isValidHostLabel) => {
      if (!validRegions.has(region) && !check(region)) {
        if (region === "*") {
          console.warn(`@smithy/config-resolver WARN - Please use the caller region instead of "*". See "sigv4a" in https://github.com/aws/aws-sdk-js-v3/blob/main/supplemental-docs/CLIENTS.md.`);
        } else {
          throw new Error(`Region not accepted: region="${region}" is not a valid hostname component.`);
        }
      } else {
        validRegions.add(region);
      }
    };
    var isFipsRegion = (region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips"));
    var getRealRegion = (region) => isFipsRegion(region) ? ["fips-aws-global", "aws-fips"].includes(region) ? "us-east-1" : region.replace(/fips-(dkr-|prod-)?|-fips/, "") : region;
    var resolveRegionConfig4 = (input) => {
      const { region, useFipsEndpoint } = input;
      if (!region) {
        throw new Error("Region is missing");
      }
      return Object.assign(input, {
        region: async () => {
          const providedRegion = typeof region === "function" ? await region() : region;
          const realRegion = getRealRegion(providedRegion);
          checkRegion(realRegion);
          return realRegion;
        },
        useFipsEndpoint: async () => {
          const providedRegion = typeof region === "string" ? region : await region();
          if (isFipsRegion(providedRegion)) {
            return true;
          }
          return typeof useFipsEndpoint !== "function" ? Promise.resolve(!!useFipsEndpoint) : useFipsEndpoint();
        }
      });
    };
    var getHostnameFromVariants = (variants = [], { useFipsEndpoint, useDualstackEndpoint }) => variants.find(({ tags }) => useFipsEndpoint === tags.includes("fips") && useDualstackEndpoint === tags.includes("dualstack"))?.hostname;
    var getResolvedHostname = (resolvedRegion, { regionHostname, partitionHostname }) => regionHostname ? regionHostname : partitionHostname ? partitionHostname.replace("{region}", resolvedRegion) : void 0;
    var getResolvedPartition = (region, { partitionHash }) => Object.keys(partitionHash || {}).find((key) => partitionHash[key].regions.includes(region)) ?? "aws";
    var getResolvedSigningRegion = (hostname, { signingRegion, regionRegex, useFipsEndpoint }) => {
      if (signingRegion) {
        return signingRegion;
      } else if (useFipsEndpoint) {
        const regionRegexJs = regionRegex.replace("\\\\", "\\").replace(/^\^/g, "\\.").replace(/\$$/g, "\\.");
        const regionRegexmatchArray = hostname.match(regionRegexJs);
        if (regionRegexmatchArray) {
          return regionRegexmatchArray[0].slice(1, -1);
        }
      }
    };
    var getRegionInfo = (region, { useFipsEndpoint = false, useDualstackEndpoint = false, signingService, regionHash, partitionHash }) => {
      const partition = getResolvedPartition(region, { partitionHash });
      const resolvedRegion = region in regionHash ? region : partitionHash[partition]?.endpoint ?? region;
      const hostnameOptions = { useFipsEndpoint, useDualstackEndpoint };
      const regionHostname = getHostnameFromVariants(regionHash[resolvedRegion]?.variants, hostnameOptions);
      const partitionHostname = getHostnameFromVariants(partitionHash[partition]?.variants, hostnameOptions);
      const hostname = getResolvedHostname(resolvedRegion, { regionHostname, partitionHostname });
      if (hostname === void 0) {
        throw new Error(`Endpoint resolution failed for: ${{ resolvedRegion, useFipsEndpoint, useDualstackEndpoint }}`);
      }
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
        ...regionHash[resolvedRegion]?.signingService && {
          signingService: regionHash[resolvedRegion].signingService
        }
      };
    };
    exports.CONFIG_USE_DUALSTACK_ENDPOINT = CONFIG_USE_DUALSTACK_ENDPOINT;
    exports.CONFIG_USE_FIPS_ENDPOINT = CONFIG_USE_FIPS_ENDPOINT;
    exports.DEFAULT_USE_DUALSTACK_ENDPOINT = DEFAULT_USE_DUALSTACK_ENDPOINT;
    exports.DEFAULT_USE_FIPS_ENDPOINT = DEFAULT_USE_FIPS_ENDPOINT;
    exports.ENV_USE_DUALSTACK_ENDPOINT = ENV_USE_DUALSTACK_ENDPOINT;
    exports.ENV_USE_FIPS_ENDPOINT = ENV_USE_FIPS_ENDPOINT;
    exports.NODE_REGION_CONFIG_FILE_OPTIONS = NODE_REGION_CONFIG_FILE_OPTIONS4;
    exports.NODE_REGION_CONFIG_OPTIONS = NODE_REGION_CONFIG_OPTIONS4;
    exports.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS4;
    exports.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS = NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS4;
    exports.REGION_ENV_NAME = REGION_ENV_NAME;
    exports.REGION_INI_NAME = REGION_INI_NAME;
    exports.getRegionInfo = getRegionInfo;
    exports.resolveCustomEndpointsConfig = resolveCustomEndpointsConfig;
    exports.resolveEndpointsConfig = resolveEndpointsConfig;
    exports.resolveRegionConfig = resolveRegionConfig4;
  }
});

// node_modules/@smithy/middleware-content-length/dist-cjs/index.js
var require_dist_cjs31 = __commonJS({
  "node_modules/@smithy/middleware-content-length/dist-cjs/index.js"(exports) {
    "use strict";
    var protocolHttp = require_dist_cjs2();
    var CONTENT_LENGTH_HEADER = "content-length";
    function contentLengthMiddleware(bodyLengthChecker) {
      return (next) => async (args) => {
        const request = args.request;
        if (protocolHttp.HttpRequest.isInstance(request)) {
          const { body, headers } = request;
          if (body && Object.keys(headers).map((str) => str.toLowerCase()).indexOf(CONTENT_LENGTH_HEADER) === -1) {
            try {
              const length = bodyLengthChecker(body);
              request.headers = {
                ...request.headers,
                [CONTENT_LENGTH_HEADER]: String(length)
              };
            } catch (error2) {
            }
          }
        }
        return next({
          ...args,
          request
        });
      };
    }
    var contentLengthMiddlewareOptions = {
      step: "build",
      tags: ["SET_CONTENT_LENGTH", "CONTENT_LENGTH"],
      name: "contentLengthMiddleware",
      override: true
    };
    var getContentLengthPlugin4 = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(contentLengthMiddleware(options.bodyLengthChecker), contentLengthMiddlewareOptions);
      }
    });
    exports.contentLengthMiddleware = contentLengthMiddleware;
    exports.contentLengthMiddlewareOptions = contentLengthMiddlewareOptions;
    exports.getContentLengthPlugin = getContentLengthPlugin4;
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-cjs/getHomeDir.js
var require_getHomeDir = __commonJS({
  "node_modules/@smithy/shared-ini-file-loader/dist-cjs/getHomeDir.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getHomeDir = void 0;
    var os_1 = __require("os");
    var path_1 = __require("path");
    var homeDirCache = {};
    var getHomeDirCacheKey = () => {
      if (process && process.geteuid) {
        return `${process.geteuid()}`;
      }
      return "DEFAULT";
    };
    var getHomeDir = () => {
      const { HOME, USERPROFILE, HOMEPATH, HOMEDRIVE = `C:${path_1.sep}` } = process.env;
      if (HOME)
        return HOME;
      if (USERPROFILE)
        return USERPROFILE;
      if (HOMEPATH)
        return `${HOMEDRIVE}${HOMEPATH}`;
      const homeDirCacheKey = getHomeDirCacheKey();
      if (!homeDirCache[homeDirCacheKey])
        homeDirCache[homeDirCacheKey] = (0, os_1.homedir)();
      return homeDirCache[homeDirCacheKey];
    };
    exports.getHomeDir = getHomeDir;
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-cjs/getSSOTokenFilepath.js
var require_getSSOTokenFilepath = __commonJS({
  "node_modules/@smithy/shared-ini-file-loader/dist-cjs/getSSOTokenFilepath.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getSSOTokenFilepath = void 0;
    var crypto_1 = __require("crypto");
    var path_1 = __require("path");
    var getHomeDir_1 = require_getHomeDir();
    var getSSOTokenFilepath = (id) => {
      const hasher = (0, crypto_1.createHash)("sha1");
      const cacheName = hasher.update(id).digest("hex");
      return (0, path_1.join)((0, getHomeDir_1.getHomeDir)(), ".aws", "sso", "cache", `${cacheName}.json`);
    };
    exports.getSSOTokenFilepath = getSSOTokenFilepath;
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-cjs/getSSOTokenFromFile.js
var require_getSSOTokenFromFile = __commonJS({
  "node_modules/@smithy/shared-ini-file-loader/dist-cjs/getSSOTokenFromFile.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getSSOTokenFromFile = exports.tokenIntercept = void 0;
    var promises_1 = __require("fs/promises");
    var getSSOTokenFilepath_1 = require_getSSOTokenFilepath();
    exports.tokenIntercept = {};
    var getSSOTokenFromFile = async (id) => {
      if (exports.tokenIntercept[id]) {
        return exports.tokenIntercept[id];
      }
      const ssoTokenFilepath = (0, getSSOTokenFilepath_1.getSSOTokenFilepath)(id);
      const ssoTokenText = await (0, promises_1.readFile)(ssoTokenFilepath, "utf8");
      return JSON.parse(ssoTokenText);
    };
    exports.getSSOTokenFromFile = getSSOTokenFromFile;
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-cjs/readFile.js
var require_readFile = __commonJS({
  "node_modules/@smithy/shared-ini-file-loader/dist-cjs/readFile.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.readFile = exports.fileIntercept = exports.filePromises = void 0;
    var promises_1 = __require("node:fs/promises");
    exports.filePromises = {};
    exports.fileIntercept = {};
    var readFile = (path, options) => {
      if (exports.fileIntercept[path] !== void 0) {
        return exports.fileIntercept[path];
      }
      if (!exports.filePromises[path] || options?.ignoreCache) {
        exports.filePromises[path] = (0, promises_1.readFile)(path, "utf8");
      }
      return exports.filePromises[path];
    };
    exports.readFile = readFile;
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-cjs/index.js
var require_dist_cjs32 = __commonJS({
  "node_modules/@smithy/shared-ini-file-loader/dist-cjs/index.js"(exports) {
    "use strict";
    var getHomeDir = require_getHomeDir();
    var getSSOTokenFilepath = require_getSSOTokenFilepath();
    var getSSOTokenFromFile = require_getSSOTokenFromFile();
    var path = __require("path");
    var types = require_dist_cjs();
    var readFile = require_readFile();
    var ENV_PROFILE = "AWS_PROFILE";
    var DEFAULT_PROFILE = "default";
    var getProfileName = (init) => init.profile || process.env[ENV_PROFILE] || DEFAULT_PROFILE;
    var CONFIG_PREFIX_SEPARATOR = ".";
    var getConfigData = (data2) => Object.entries(data2).filter(([key]) => {
      const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
      if (indexOfSeparator === -1) {
        return false;
      }
      return Object.values(types.IniSectionType).includes(key.substring(0, indexOfSeparator));
    }).reduce((acc, [key, value]) => {
      const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
      const updatedKey = key.substring(0, indexOfSeparator) === types.IniSectionType.PROFILE ? key.substring(indexOfSeparator + 1) : key;
      acc[updatedKey] = value;
      return acc;
    }, {
      ...data2.default && { default: data2.default }
    });
    var ENV_CONFIG_PATH = "AWS_CONFIG_FILE";
    var getConfigFilepath = () => process.env[ENV_CONFIG_PATH] || path.join(getHomeDir.getHomeDir(), ".aws", "config");
    var ENV_CREDENTIALS_PATH = "AWS_SHARED_CREDENTIALS_FILE";
    var getCredentialsFilepath = () => process.env[ENV_CREDENTIALS_PATH] || path.join(getHomeDir.getHomeDir(), ".aws", "credentials");
    var prefixKeyRegex = /^([\w-]+)\s(["'])?([\w-@\+\.%:/]+)\2$/;
    var profileNameBlockList = ["__proto__", "profile __proto__"];
    var parseIni = (iniData) => {
      const map2 = {};
      let currentSection;
      let currentSubSection;
      for (const iniLine of iniData.split(/\r?\n/)) {
        const trimmedLine = iniLine.split(/(^|\s)[;#]/)[0].trim();
        const isSection = trimmedLine[0] === "[" && trimmedLine[trimmedLine.length - 1] === "]";
        if (isSection) {
          currentSection = void 0;
          currentSubSection = void 0;
          const sectionName = trimmedLine.substring(1, trimmedLine.length - 1);
          const matches = prefixKeyRegex.exec(sectionName);
          if (matches) {
            const [, prefix, , name] = matches;
            if (Object.values(types.IniSectionType).includes(prefix)) {
              currentSection = [prefix, name].join(CONFIG_PREFIX_SEPARATOR);
            }
          } else {
            currentSection = sectionName;
          }
          if (profileNameBlockList.includes(sectionName)) {
            throw new Error(`Found invalid profile name "${sectionName}"`);
          }
        } else if (currentSection) {
          const indexOfEqualsSign = trimmedLine.indexOf("=");
          if (![0, -1].includes(indexOfEqualsSign)) {
            const [name, value] = [
              trimmedLine.substring(0, indexOfEqualsSign).trim(),
              trimmedLine.substring(indexOfEqualsSign + 1).trim()
            ];
            if (value === "") {
              currentSubSection = name;
            } else {
              if (currentSubSection && iniLine.trimStart() === iniLine) {
                currentSubSection = void 0;
              }
              map2[currentSection] = map2[currentSection] || {};
              const key = currentSubSection ? [currentSubSection, name].join(CONFIG_PREFIX_SEPARATOR) : name;
              map2[currentSection][key] = value;
            }
          }
        }
      }
      return map2;
    };
    var swallowError$1 = () => ({});
    var loadSharedConfigFiles = async (init = {}) => {
      const { filepath = getCredentialsFilepath(), configFilepath = getConfigFilepath() } = init;
      const homeDir = getHomeDir.getHomeDir();
      const relativeHomeDirPrefix = "~/";
      let resolvedFilepath = filepath;
      if (filepath.startsWith(relativeHomeDirPrefix)) {
        resolvedFilepath = path.join(homeDir, filepath.slice(2));
      }
      let resolvedConfigFilepath = configFilepath;
      if (configFilepath.startsWith(relativeHomeDirPrefix)) {
        resolvedConfigFilepath = path.join(homeDir, configFilepath.slice(2));
      }
      const parsedFiles = await Promise.all([
        readFile.readFile(resolvedConfigFilepath, {
          ignoreCache: init.ignoreCache
        }).then(parseIni).then(getConfigData).catch(swallowError$1),
        readFile.readFile(resolvedFilepath, {
          ignoreCache: init.ignoreCache
        }).then(parseIni).catch(swallowError$1)
      ]);
      return {
        configFile: parsedFiles[0],
        credentialsFile: parsedFiles[1]
      };
    };
    var getSsoSessionData = (data2) => Object.entries(data2).filter(([key]) => key.startsWith(types.IniSectionType.SSO_SESSION + CONFIG_PREFIX_SEPARATOR)).reduce((acc, [key, value]) => ({ ...acc, [key.substring(key.indexOf(CONFIG_PREFIX_SEPARATOR) + 1)]: value }), {});
    var swallowError = () => ({});
    var loadSsoSessionData = async (init = {}) => readFile.readFile(init.configFilepath ?? getConfigFilepath()).then(parseIni).then(getSsoSessionData).catch(swallowError);
    var mergeConfigFiles = (...files) => {
      const merged = {};
      for (const file of files) {
        for (const [key, values] of Object.entries(file)) {
          if (merged[key] !== void 0) {
            Object.assign(merged[key], values);
          } else {
            merged[key] = values;
          }
        }
      }
      return merged;
    };
    var parseKnownFiles = async (init) => {
      const parsedFiles = await loadSharedConfigFiles(init);
      return mergeConfigFiles(parsedFiles.configFile, parsedFiles.credentialsFile);
    };
    var externalDataInterceptor = {
      getFileRecord() {
        return readFile.fileIntercept;
      },
      interceptFile(path2, contents) {
        readFile.fileIntercept[path2] = Promise.resolve(contents);
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
    Object.keys(getHomeDir).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return getHomeDir[k4];
        }
      });
    });
    Object.keys(getSSOTokenFilepath).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return getSSOTokenFilepath[k4];
        }
      });
    });
  }
});

// node_modules/@smithy/node-config-provider/dist-cjs/index.js
var require_dist_cjs33 = __commonJS({
  "node_modules/@smithy/node-config-provider/dist-cjs/index.js"(exports) {
    "use strict";
    var propertyProvider = require_dist_cjs23();
    var sharedIniFileLoader = require_dist_cjs32();
    function getSelectorName(functionString) {
      try {
        const constants = new Set(Array.from(functionString.match(/([A-Z_]){3,}/g) ?? []));
        constants.delete("CONFIG");
        constants.delete("CONFIG_PREFIX_SEPARATOR");
        constants.delete("ENV");
        return [...constants].join(", ");
      } catch (e4) {
        return functionString;
      }
    }
    var fromEnv = (envVarSelector, options) => async () => {
      try {
        const config = envVarSelector(process.env, options);
        if (config === void 0) {
          throw new Error();
        }
        return config;
      } catch (e4) {
        throw new propertyProvider.CredentialsProviderError(e4.message || `Not found in ENV: ${getSelectorName(envVarSelector.toString())}`, { logger: options?.logger });
      }
    };
    var fromSharedConfigFiles = (configSelector, { preferredFile = "config", ...init } = {}) => async () => {
      const profile = sharedIniFileLoader.getProfileName(init);
      const { configFile, credentialsFile } = await sharedIniFileLoader.loadSharedConfigFiles(init);
      const profileFromCredentials = credentialsFile[profile] || {};
      const profileFromConfig = configFile[profile] || {};
      const mergedProfile = preferredFile === "config" ? { ...profileFromCredentials, ...profileFromConfig } : { ...profileFromConfig, ...profileFromCredentials };
      try {
        const cfgFile = preferredFile === "config" ? configFile : credentialsFile;
        const configValue = configSelector(mergedProfile, cfgFile);
        if (configValue === void 0) {
          throw new Error();
        }
        return configValue;
      } catch (e4) {
        throw new propertyProvider.CredentialsProviderError(e4.message || `Not found in config files w/ profile [${profile}]: ${getSelectorName(configSelector.toString())}`, { logger: init.logger });
      }
    };
    var isFunction = (func) => typeof func === "function";
    var fromStatic = (defaultValue) => isFunction(defaultValue) ? async () => await defaultValue() : propertyProvider.fromStatic(defaultValue);
    var loadConfig = ({ environmentVariableSelector, configFileSelector, default: defaultValue }, configuration = {}) => {
      const { signingName, logger: logger2 } = configuration;
      const envOptions = { signingName, logger: logger2 };
      return propertyProvider.memoize(propertyProvider.chain(fromEnv(environmentVariableSelector, envOptions), fromSharedConfigFiles(configFileSelector, configuration), fromStatic(defaultValue)));
    };
    exports.loadConfig = loadConfig;
  }
});

// node_modules/@smithy/middleware-endpoint/dist-cjs/adaptors/getEndpointUrlConfig.js
var require_getEndpointUrlConfig = __commonJS({
  "node_modules/@smithy/middleware-endpoint/dist-cjs/adaptors/getEndpointUrlConfig.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getEndpointUrlConfig = void 0;
    var shared_ini_file_loader_1 = require_dist_cjs32();
    var ENV_ENDPOINT_URL = "AWS_ENDPOINT_URL";
    var CONFIG_ENDPOINT_URL = "endpoint_url";
    var getEndpointUrlConfig = (serviceId) => ({
      environmentVariableSelector: (env) => {
        const serviceSuffixParts = serviceId.split(" ").map((w4) => w4.toUpperCase());
        const serviceEndpointUrl = env[[ENV_ENDPOINT_URL, ...serviceSuffixParts].join("_")];
        if (serviceEndpointUrl)
          return serviceEndpointUrl;
        const endpointUrl = env[ENV_ENDPOINT_URL];
        if (endpointUrl)
          return endpointUrl;
        return void 0;
      },
      configFileSelector: (profile, config) => {
        if (config && profile.services) {
          const servicesSection = config[["services", profile.services].join(shared_ini_file_loader_1.CONFIG_PREFIX_SEPARATOR)];
          if (servicesSection) {
            const servicePrefixParts = serviceId.split(" ").map((w4) => w4.toLowerCase());
            const endpointUrl2 = servicesSection[[servicePrefixParts.join("_"), CONFIG_ENDPOINT_URL].join(shared_ini_file_loader_1.CONFIG_PREFIX_SEPARATOR)];
            if (endpointUrl2)
              return endpointUrl2;
          }
        }
        const endpointUrl = profile[CONFIG_ENDPOINT_URL];
        if (endpointUrl)
          return endpointUrl;
        return void 0;
      },
      default: void 0
    });
    exports.getEndpointUrlConfig = getEndpointUrlConfig;
  }
});

// node_modules/@smithy/middleware-endpoint/dist-cjs/adaptors/getEndpointFromConfig.js
var require_getEndpointFromConfig = __commonJS({
  "node_modules/@smithy/middleware-endpoint/dist-cjs/adaptors/getEndpointFromConfig.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getEndpointFromConfig = void 0;
    var node_config_provider_1 = require_dist_cjs33();
    var getEndpointUrlConfig_1 = require_getEndpointUrlConfig();
    var getEndpointFromConfig = async (serviceId) => (0, node_config_provider_1.loadConfig)((0, getEndpointUrlConfig_1.getEndpointUrlConfig)(serviceId ?? ""))();
    exports.getEndpointFromConfig = getEndpointFromConfig;
  }
});

// node_modules/@smithy/middleware-endpoint/dist-cjs/index.js
var require_dist_cjs34 = __commonJS({
  "node_modules/@smithy/middleware-endpoint/dist-cjs/index.js"(exports) {
    "use strict";
    var getEndpointFromConfig = require_getEndpointFromConfig();
    var urlParser = require_dist_cjs21();
    var core = (init_dist_es(), __toCommonJS(dist_es_exports));
    var utilMiddleware = require_dist_cjs6();
    var middlewareSerde = require_dist_cjs7();
    var resolveParamsForS3 = async (endpointParams) => {
      const bucket = endpointParams?.Bucket || "";
      if (typeof endpointParams.Bucket === "string") {
        endpointParams.Bucket = bucket.replace(/#/g, encodeURIComponent("#")).replace(/\?/g, encodeURIComponent("?"));
      }
      if (isArnBucketName(bucket)) {
        if (endpointParams.ForcePathStyle === true) {
          throw new Error("Path-style addressing cannot be used with ARN buckets");
        }
      } else if (!isDnsCompatibleBucketName(bucket) || bucket.indexOf(".") !== -1 && !String(endpointParams.Endpoint).startsWith("http:") || bucket.toLowerCase() !== bucket || bucket.length < 3) {
        endpointParams.ForcePathStyle = true;
      }
      if (endpointParams.DisableMultiRegionAccessPoints) {
        endpointParams.disableMultiRegionAccessPoints = true;
        endpointParams.DisableMRAP = true;
      }
      return endpointParams;
    };
    var DOMAIN_PATTERN = /^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$/;
    var IP_ADDRESS_PATTERN = /(\d+\.){3}\d+/;
    var DOTS_PATTERN = /\.\./;
    var isDnsCompatibleBucketName = (bucketName) => DOMAIN_PATTERN.test(bucketName) && !IP_ADDRESS_PATTERN.test(bucketName) && !DOTS_PATTERN.test(bucketName);
    var isArnBucketName = (bucketName) => {
      const [arn, partition, service, , , bucket] = bucketName.split(":");
      const isArn = arn === "arn" && bucketName.split(":").length >= 6;
      const isValidArn = Boolean(isArn && partition && service && bucket);
      if (isArn && !isValidArn) {
        throw new Error(`Invalid ARN: ${bucketName} was an invalid ARN.`);
      }
      return isValidArn;
    };
    var createConfigValueProvider = (configKey, canonicalEndpointParamKey, config, isClientContextParam = false) => {
      const configProvider = async () => {
        let configValue;
        if (isClientContextParam) {
          const clientContextParams = config.clientContextParams;
          const nestedValue = clientContextParams?.[configKey];
          configValue = nestedValue ?? config[configKey] ?? config[canonicalEndpointParamKey];
        } else {
          configValue = config[configKey] ?? config[canonicalEndpointParamKey];
        }
        if (typeof configValue === "function") {
          return configValue();
        }
        return configValue;
      };
      if (configKey === "credentialScope" || canonicalEndpointParamKey === "CredentialScope") {
        return async () => {
          const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
          const configValue = credentials?.credentialScope ?? credentials?.CredentialScope;
          return configValue;
        };
      }
      if (configKey === "accountId" || canonicalEndpointParamKey === "AccountId") {
        return async () => {
          const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
          const configValue = credentials?.accountId ?? credentials?.AccountId;
          return configValue;
        };
      }
      if (configKey === "endpoint" || canonicalEndpointParamKey === "endpoint") {
        return async () => {
          if (config.isCustomEndpoint === false) {
            return void 0;
          }
          const endpoint = await configProvider();
          if (endpoint && typeof endpoint === "object") {
            if ("url" in endpoint) {
              return endpoint.url.href;
            }
            if ("hostname" in endpoint) {
              const { protocol, hostname, port, path } = endpoint;
              return `${protocol}//${hostname}${port ? ":" + port : ""}${path}`;
            }
          }
          return endpoint;
        };
      }
      return configProvider;
    };
    var toEndpointV1 = (endpoint) => {
      if (typeof endpoint === "object") {
        if ("url" in endpoint) {
          return urlParser.parseUrl(endpoint.url);
        }
        return endpoint;
      }
      return urlParser.parseUrl(endpoint);
    };
    var getEndpointFromInstructions = async (commandInput, instructionsSupplier, clientConfig, context) => {
      if (!clientConfig.isCustomEndpoint) {
        let endpointFromConfig;
        if (clientConfig.serviceConfiguredEndpoint) {
          endpointFromConfig = await clientConfig.serviceConfiguredEndpoint();
        } else {
          endpointFromConfig = await getEndpointFromConfig.getEndpointFromConfig(clientConfig.serviceId);
        }
        if (endpointFromConfig) {
          clientConfig.endpoint = () => Promise.resolve(toEndpointV1(endpointFromConfig));
          clientConfig.isCustomEndpoint = true;
        }
      }
      const endpointParams = await resolveParams(commandInput, instructionsSupplier, clientConfig);
      if (typeof clientConfig.endpointProvider !== "function") {
        throw new Error("config.endpointProvider is not set.");
      }
      const endpoint = clientConfig.endpointProvider(endpointParams, context);
      return endpoint;
    };
    var resolveParams = async (commandInput, instructionsSupplier, clientConfig) => {
      const endpointParams = {};
      const instructions = instructionsSupplier?.getEndpointParameterInstructions?.() || {};
      for (const [name, instruction] of Object.entries(instructions)) {
        switch (instruction.type) {
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
          default:
            throw new Error("Unrecognized endpoint parameter instruction: " + JSON.stringify(instruction));
        }
      }
      if (Object.keys(instructions).length === 0) {
        Object.assign(endpointParams, clientConfig);
      }
      if (String(clientConfig.serviceId).toLowerCase() === "s3") {
        await resolveParamsForS3(endpointParams);
      }
      return endpointParams;
    };
    var endpointMiddleware = ({ config, instructions }) => {
      return (next, context) => async (args) => {
        if (config.isCustomEndpoint) {
          core.setFeature(context, "ENDPOINT_OVERRIDE", "N");
        }
        const endpoint = await getEndpointFromInstructions(args.input, {
          getEndpointParameterInstructions() {
            return instructions;
          }
        }, { ...config }, context);
        context.endpointV2 = endpoint;
        context.authSchemes = endpoint.properties?.authSchemes;
        const authScheme = context.authSchemes?.[0];
        if (authScheme) {
          context["signing_region"] = authScheme.signingRegion;
          context["signing_service"] = authScheme.signingName;
          const smithyContext = utilMiddleware.getSmithyContext(context);
          const httpAuthOption = smithyContext?.selectedHttpAuthScheme?.httpAuthOption;
          if (httpAuthOption) {
            httpAuthOption.signingProperties = Object.assign(httpAuthOption.signingProperties || {}, {
              signing_region: authScheme.signingRegion,
              signingRegion: authScheme.signingRegion,
              signing_service: authScheme.signingName,
              signingName: authScheme.signingName,
              signingRegionSet: authScheme.signingRegionSet
            }, authScheme.properties);
          }
        }
        return next({
          ...args
        });
      };
    };
    var endpointMiddlewareOptions = {
      step: "serialize",
      tags: ["ENDPOINT_PARAMETERS", "ENDPOINT_V2", "ENDPOINT"],
      name: "endpointV2Middleware",
      override: true,
      relation: "before",
      toMiddleware: middlewareSerde.serializerMiddlewareOption.name
    };
    var getEndpointPlugin5 = (config, instructions) => ({
      applyToStack: (clientStack) => {
        clientStack.addRelativeTo(endpointMiddleware({
          config,
          instructions
        }), endpointMiddlewareOptions);
      }
    });
    var resolveEndpointConfig4 = (input) => {
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
        if (input.serviceId && !configuredEndpointPromise) {
          configuredEndpointPromise = getEndpointFromConfig.getEndpointFromConfig(input.serviceId);
        }
        return configuredEndpointPromise;
      };
      return resolvedConfig;
    };
    var resolveEndpointRequiredConfig = (input) => {
      const { endpoint } = input;
      if (endpoint === void 0) {
        input.endpoint = async () => {
          throw new Error("@smithy/middleware-endpoint: (default endpointRuleSet) endpoint is not set - you must configure an endpoint.");
        };
      }
      return input;
    };
    exports.endpointMiddleware = endpointMiddleware;
    exports.endpointMiddlewareOptions = endpointMiddlewareOptions;
    exports.getEndpointFromInstructions = getEndpointFromInstructions;
    exports.getEndpointPlugin = getEndpointPlugin5;
    exports.resolveEndpointConfig = resolveEndpointConfig4;
    exports.resolveEndpointRequiredConfig = resolveEndpointRequiredConfig;
    exports.resolveParams = resolveParams;
    exports.toEndpointV1 = toEndpointV1;
  }
});

// node_modules/@smithy/service-error-classification/dist-cjs/index.js
var require_dist_cjs35 = __commonJS({
  "node_modules/@smithy/service-error-classification/dist-cjs/index.js"(exports) {
    "use strict";
    var CLOCK_SKEW_ERROR_CODES = [
      "AuthFailure",
      "InvalidSignatureException",
      "RequestExpired",
      "RequestInTheFuture",
      "RequestTimeTooSkewed",
      "SignatureDoesNotMatch"
    ];
    var THROTTLING_ERROR_CODES = [
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
    var TRANSIENT_ERROR_CODES = ["TimeoutError", "RequestTimeout", "RequestTimeoutException"];
    var TRANSIENT_ERROR_STATUS_CODES = [500, 502, 503, 504];
    var NODEJS_TIMEOUT_ERROR_CODES = ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"];
    var NODEJS_NETWORK_ERROR_CODES = ["EHOSTUNREACH", "ENETUNREACH", "ENOTFOUND"];
    var isRetryableByTrait = (error2) => error2?.$retryable !== void 0;
    var isClockSkewError = (error2) => CLOCK_SKEW_ERROR_CODES.includes(error2.name);
    var isClockSkewCorrectedError = (error2) => error2.$metadata?.clockSkewCorrected;
    var isBrowserNetworkError = (error2) => {
      const errorMessages = /* @__PURE__ */ new Set([
        "Failed to fetch",
        "NetworkError when attempting to fetch resource",
        "The Internet connection appears to be offline",
        "Load failed",
        "Network request failed"
      ]);
      const isValid = error2 && error2 instanceof TypeError;
      if (!isValid) {
        return false;
      }
      return errorMessages.has(error2.message);
    };
    var isThrottlingError = (error2) => error2.$metadata?.httpStatusCode === 429 || THROTTLING_ERROR_CODES.includes(error2.name) || error2.$retryable?.throttling == true;
    var isTransientError = (error2, depth = 0) => isRetryableByTrait(error2) || isClockSkewCorrectedError(error2) || TRANSIENT_ERROR_CODES.includes(error2.name) || NODEJS_TIMEOUT_ERROR_CODES.includes(error2?.code || "") || NODEJS_NETWORK_ERROR_CODES.includes(error2?.code || "") || TRANSIENT_ERROR_STATUS_CODES.includes(error2.$metadata?.httpStatusCode || 0) || isBrowserNetworkError(error2) || error2.cause !== void 0 && depth <= 10 && isTransientError(error2.cause, depth + 1);
    var isServerError = (error2) => {
      if (error2.$metadata?.httpStatusCode !== void 0) {
        const statusCode = error2.$metadata.httpStatusCode;
        if (500 <= statusCode && statusCode <= 599 && !isTransientError(error2)) {
          return true;
        }
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
  }
});

// node_modules/@smithy/util-retry/dist-cjs/index.js
var require_dist_cjs36 = __commonJS({
  "node_modules/@smithy/util-retry/dist-cjs/index.js"(exports) {
    "use strict";
    var serviceErrorClassification = require_dist_cjs35();
    exports.RETRY_MODES = void 0;
    (function(RETRY_MODES) {
      RETRY_MODES["STANDARD"] = "standard";
      RETRY_MODES["ADAPTIVE"] = "adaptive";
    })(exports.RETRY_MODES || (exports.RETRY_MODES = {}));
    var DEFAULT_MAX_ATTEMPTS = 3;
    var DEFAULT_RETRY_MODE4 = exports.RETRY_MODES.STANDARD;
    var DefaultRateLimiter = class _DefaultRateLimiter {
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
        this.beta = options?.beta ?? 0.7;
        this.minCapacity = options?.minCapacity ?? 1;
        this.minFillRate = options?.minFillRate ?? 0.5;
        this.scaleConstant = options?.scaleConstant ?? 0.4;
        this.smooth = options?.smooth ?? 0.8;
        const currentTimeInSeconds = this.getCurrentTimeInSeconds();
        this.lastThrottleTime = currentTimeInSeconds;
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
        if (!this.enabled) {
          return;
        }
        this.refillTokenBucket();
        if (amount > this.currentCapacity) {
          const delay = (amount - this.currentCapacity) / this.fillRate * 1e3;
          await new Promise((resolve) => _DefaultRateLimiter.setTimeoutFn(resolve, delay));
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
        const t4 = this.getCurrentTimeInSeconds();
        const timeBucket = Math.floor(t4 * 2) / 2;
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
    var DEFAULT_RETRY_DELAY_BASE = 100;
    var MAXIMUM_RETRY_DELAY = 20 * 1e3;
    var THROTTLING_RETRY_DELAY_BASE = 500;
    var INITIAL_RETRY_TOKENS = 500;
    var RETRY_COST = 5;
    var TIMEOUT_RETRY_COST = 10;
    var NO_RETRY_INCREMENT = 1;
    var INVOCATION_ID_HEADER = "amz-sdk-invocation-id";
    var REQUEST_HEADER = "amz-sdk-request";
    var getDefaultRetryBackoffStrategy = () => {
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
    var createDefaultRetryToken = ({ retryDelay, retryCount, retryCost }) => {
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
        } catch (error2) {
          console.warn(`Max attempts provider could not resolve. Using default of ${DEFAULT_MAX_ATTEMPTS}`);
          return DEFAULT_MAX_ATTEMPTS;
        }
      }
      shouldRetry(tokenToRenew, errorInfo, maxAttempts) {
        const attempts = tokenToRenew.getRetryCount() + 1;
        return attempts < maxAttempts && this.capacity >= this.getCapacityCost(errorInfo.errorType) && this.isRetryableError(errorInfo.errorType);
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
        if (typeof computeNextBackoffDelay === "number") {
          this.computeNextBackoffDelay = () => computeNextBackoffDelay;
        } else {
          this.computeNextBackoffDelay = computeNextBackoffDelay;
        }
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
    exports.DEFAULT_RETRY_MODE = DEFAULT_RETRY_MODE4;
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
  }
});

// node_modules/@smithy/middleware-retry/dist-cjs/isStreamingPayload/isStreamingPayload.js
var require_isStreamingPayload = __commonJS({
  "node_modules/@smithy/middleware-retry/dist-cjs/isStreamingPayload/isStreamingPayload.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.isStreamingPayload = void 0;
    var stream_1 = __require("stream");
    var isStreamingPayload = (request) => request?.body instanceof stream_1.Readable || typeof ReadableStream !== "undefined" && request?.body instanceof ReadableStream;
    exports.isStreamingPayload = isStreamingPayload;
  }
});

// node_modules/@smithy/middleware-retry/dist-cjs/index.js
var require_dist_cjs37 = __commonJS({
  "node_modules/@smithy/middleware-retry/dist-cjs/index.js"(exports) {
    "use strict";
    var utilRetry = require_dist_cjs36();
    var protocolHttp = require_dist_cjs2();
    var serviceErrorClassification = require_dist_cjs35();
    var uuid = require_dist_cjs18();
    var utilMiddleware = require_dist_cjs6();
    var smithyClient = require_dist_cjs26();
    var isStreamingPayload = require_isStreamingPayload();
    var getDefaultRetryQuota = (initialRetryTokens, options) => {
      const MAX_CAPACITY = initialRetryTokens;
      const noRetryIncrement = utilRetry.NO_RETRY_INCREMENT;
      const retryCost = utilRetry.RETRY_COST;
      const timeoutRetryCost = utilRetry.TIMEOUT_RETRY_COST;
      let availableCapacity = initialRetryTokens;
      const getCapacityAmount = (error2) => error2.name === "TimeoutError" ? timeoutRetryCost : retryCost;
      const hasRetryTokens = (error2) => getCapacityAmount(error2) <= availableCapacity;
      const retrieveRetryTokens = (error2) => {
        if (!hasRetryTokens(error2)) {
          throw new Error("No retry token available");
        }
        const capacityAmount = getCapacityAmount(error2);
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
    var defaultDelayDecider = (delayBase, attempts) => Math.floor(Math.min(utilRetry.MAXIMUM_RETRY_DELAY, Math.random() * 2 ** attempts * delayBase));
    var defaultRetryDecider = (error2) => {
      if (!error2) {
        return false;
      }
      return serviceErrorClassification.isRetryableByTrait(error2) || serviceErrorClassification.isClockSkewError(error2) || serviceErrorClassification.isThrottlingError(error2) || serviceErrorClassification.isTransientError(error2);
    };
    var asSdkError = (error2) => {
      if (error2 instanceof Error)
        return error2;
      if (error2 instanceof Object)
        return Object.assign(new Error(), error2);
      if (typeof error2 === "string")
        return new Error(error2);
      return new Error(`AWS SDK error wrapper for ${error2}`);
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
      shouldRetry(error2, attempts, maxAttempts) {
        return attempts < maxAttempts && this.retryDecider(error2) && this.retryQuota.hasRetryTokens(error2);
      }
      async getMaxAttempts() {
        let maxAttempts;
        try {
          maxAttempts = await this.maxAttemptsProvider();
        } catch (error2) {
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
        if (protocolHttp.HttpRequest.isInstance(request)) {
          request.headers[utilRetry.INVOCATION_ID_HEADER] = uuid.v4();
        }
        while (true) {
          try {
            if (protocolHttp.HttpRequest.isInstance(request)) {
              request.headers[utilRetry.REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
            }
            if (options?.beforeRequest) {
              await options.beforeRequest();
            }
            const { response, output } = await next(args);
            if (options?.afterRequest) {
              options.afterRequest(response);
            }
            this.retryQuota.releaseRetryTokens(retryTokenAmount);
            output.$metadata.attempts = attempts + 1;
            output.$metadata.totalRetryDelay = totalDelay;
            return { response, output };
          } catch (e4) {
            const err = asSdkError(e4);
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
            if (!err.$metadata) {
              err.$metadata = {};
            }
            err.$metadata.attempts = attempts;
            err.$metadata.totalRetryDelay = totalDelay;
            throw err;
          }
        }
      }
    };
    var getDelayFromRetryAfterHeader = (response) => {
      if (!protocolHttp.HttpResponse.isInstance(response))
        return;
      const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
      if (!retryAfterHeaderName)
        return;
      const retryAfter = response.headers[retryAfterHeaderName];
      const retryAfterSeconds = Number(retryAfter);
      if (!Number.isNaN(retryAfterSeconds))
        return retryAfterSeconds * 1e3;
      const retryAfterDate = new Date(retryAfter);
      return retryAfterDate.getTime() - Date.now();
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
    var ENV_MAX_ATTEMPTS = "AWS_MAX_ATTEMPTS";
    var CONFIG_MAX_ATTEMPTS = "max_attempts";
    var NODE_MAX_ATTEMPT_CONFIG_OPTIONS4 = {
      environmentVariableSelector: (env) => {
        const value = env[ENV_MAX_ATTEMPTS];
        if (!value)
          return void 0;
        const maxAttempt = parseInt(value);
        if (Number.isNaN(maxAttempt)) {
          throw new Error(`Environment variable ${ENV_MAX_ATTEMPTS} mast be a number, got "${value}"`);
        }
        return maxAttempt;
      },
      configFileSelector: (profile) => {
        const value = profile[CONFIG_MAX_ATTEMPTS];
        if (!value)
          return void 0;
        const maxAttempt = parseInt(value);
        if (Number.isNaN(maxAttempt)) {
          throw new Error(`Shared config file entry ${CONFIG_MAX_ATTEMPTS} mast be a number, got "${value}"`);
        }
        return maxAttempt;
      },
      default: utilRetry.DEFAULT_MAX_ATTEMPTS
    };
    var resolveRetryConfig4 = (input) => {
      const { retryStrategy, retryMode: _retryMode, maxAttempts: _maxAttempts } = input;
      const maxAttempts = utilMiddleware.normalizeProvider(_maxAttempts ?? utilRetry.DEFAULT_MAX_ATTEMPTS);
      return Object.assign(input, {
        maxAttempts,
        retryStrategy: async () => {
          if (retryStrategy) {
            return retryStrategy;
          }
          const retryMode = await utilMiddleware.normalizeProvider(_retryMode)();
          if (retryMode === utilRetry.RETRY_MODES.ADAPTIVE) {
            return new utilRetry.AdaptiveRetryStrategy(maxAttempts);
          }
          return new utilRetry.StandardRetryStrategy(maxAttempts);
        }
      });
    };
    var ENV_RETRY_MODE = "AWS_RETRY_MODE";
    var CONFIG_RETRY_MODE = "retry_mode";
    var NODE_RETRY_MODE_CONFIG_OPTIONS4 = {
      environmentVariableSelector: (env) => env[ENV_RETRY_MODE],
      configFileSelector: (profile) => profile[CONFIG_RETRY_MODE],
      default: utilRetry.DEFAULT_RETRY_MODE
    };
    var omitRetryHeadersMiddleware = () => (next) => async (args) => {
      const { request } = args;
      if (protocolHttp.HttpRequest.isInstance(request)) {
        delete request.headers[utilRetry.INVOCATION_ID_HEADER];
        delete request.headers[utilRetry.REQUEST_HEADER];
      }
      return next(args);
    };
    var omitRetryHeadersMiddlewareOptions = {
      name: "omitRetryHeadersMiddleware",
      tags: ["RETRY", "HEADERS", "OMIT_RETRY_HEADERS"],
      relation: "before",
      toMiddleware: "awsAuthMiddleware",
      override: true
    };
    var getOmitRetryHeadersPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.addRelativeTo(omitRetryHeadersMiddleware(), omitRetryHeadersMiddlewareOptions);
      }
    });
    var retryMiddleware = (options) => (next, context) => async (args) => {
      let retryStrategy = await options.retryStrategy();
      const maxAttempts = await options.maxAttempts();
      if (isRetryStrategyV2(retryStrategy)) {
        retryStrategy = retryStrategy;
        let retryToken = await retryStrategy.acquireInitialRetryToken(context["partition_id"]);
        let lastError = new Error();
        let attempts = 0;
        let totalRetryDelay = 0;
        const { request } = args;
        const isRequest = protocolHttp.HttpRequest.isInstance(request);
        if (isRequest) {
          request.headers[utilRetry.INVOCATION_ID_HEADER] = uuid.v4();
        }
        while (true) {
          try {
            if (isRequest) {
              request.headers[utilRetry.REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
            }
            const { response, output } = await next(args);
            retryStrategy.recordSuccess(retryToken);
            output.$metadata.attempts = attempts + 1;
            output.$metadata.totalRetryDelay = totalRetryDelay;
            return { response, output };
          } catch (e4) {
            const retryErrorInfo = getRetryErrorInfo(e4);
            lastError = asSdkError(e4);
            if (isRequest && isStreamingPayload.isStreamingPayload(request)) {
              (context.logger instanceof smithyClient.NoOpLogger ? console : context.logger)?.warn("An error was encountered in a non-retryable streaming request.");
              throw lastError;
            }
            try {
              retryToken = await retryStrategy.refreshRetryTokenForRetry(retryToken, retryErrorInfo);
            } catch (refreshError) {
              if (!lastError.$metadata) {
                lastError.$metadata = {};
              }
              lastError.$metadata.attempts = attempts + 1;
              lastError.$metadata.totalRetryDelay = totalRetryDelay;
              throw lastError;
            }
            attempts = retryToken.getRetryCount();
            const delay = retryToken.getRetryDelay();
            totalRetryDelay += delay;
            await new Promise((resolve) => setTimeout(resolve, delay));
          }
        }
      } else {
        retryStrategy = retryStrategy;
        if (retryStrategy?.mode)
          context.userAgent = [...context.userAgent || [], ["cfg/retry-mode", retryStrategy.mode]];
        return retryStrategy.retry(next, args);
      }
    };
    var isRetryStrategyV2 = (retryStrategy) => typeof retryStrategy.acquireInitialRetryToken !== "undefined" && typeof retryStrategy.refreshRetryTokenForRetry !== "undefined" && typeof retryStrategy.recordSuccess !== "undefined";
    var getRetryErrorInfo = (error2) => {
      const errorInfo = {
        error: error2,
        errorType: getRetryErrorType(error2)
      };
      const retryAfterHint = getRetryAfterHint(error2.$response);
      if (retryAfterHint) {
        errorInfo.retryAfterHint = retryAfterHint;
      }
      return errorInfo;
    };
    var getRetryErrorType = (error2) => {
      if (serviceErrorClassification.isThrottlingError(error2))
        return "THROTTLING";
      if (serviceErrorClassification.isTransientError(error2))
        return "TRANSIENT";
      if (serviceErrorClassification.isServerError(error2))
        return "SERVER_ERROR";
      return "CLIENT_ERROR";
    };
    var retryMiddlewareOptions = {
      name: "retryMiddleware",
      tags: ["RETRY"],
      step: "finalizeRequest",
      priority: "high",
      override: true
    };
    var getRetryPlugin4 = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(retryMiddleware(options), retryMiddlewareOptions);
      }
    });
    var getRetryAfterHint = (response) => {
      if (!protocolHttp.HttpResponse.isInstance(response))
        return;
      const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
      if (!retryAfterHeaderName)
        return;
      const retryAfter = response.headers[retryAfterHeaderName];
      const retryAfterSeconds = Number(retryAfter);
      if (!Number.isNaN(retryAfterSeconds))
        return new Date(retryAfterSeconds * 1e3);
      const retryAfterDate = new Date(retryAfter);
      return retryAfterDate;
    };
    exports.AdaptiveRetryStrategy = AdaptiveRetryStrategy;
    exports.CONFIG_MAX_ATTEMPTS = CONFIG_MAX_ATTEMPTS;
    exports.CONFIG_RETRY_MODE = CONFIG_RETRY_MODE;
    exports.ENV_MAX_ATTEMPTS = ENV_MAX_ATTEMPTS;
    exports.ENV_RETRY_MODE = ENV_RETRY_MODE;
    exports.NODE_MAX_ATTEMPT_CONFIG_OPTIONS = NODE_MAX_ATTEMPT_CONFIG_OPTIONS4;
    exports.NODE_RETRY_MODE_CONFIG_OPTIONS = NODE_RETRY_MODE_CONFIG_OPTIONS4;
    exports.StandardRetryStrategy = StandardRetryStrategy;
    exports.defaultDelayDecider = defaultDelayDecider;
    exports.defaultRetryDecider = defaultRetryDecider;
    exports.getOmitRetryHeadersPlugin = getOmitRetryHeadersPlugin;
    exports.getRetryAfterHint = getRetryAfterHint;
    exports.getRetryPlugin = getRetryPlugin4;
    exports.omitRetryHeadersMiddleware = omitRetryHeadersMiddleware;
    exports.omitRetryHeadersMiddlewareOptions = omitRetryHeadersMiddlewareOptions;
    exports.resolveRetryConfig = resolveRetryConfig4;
    exports.retryMiddleware = retryMiddleware;
    exports.retryMiddlewareOptions = retryMiddlewareOptions;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/auth/httpAuthSchemeProvider.js
var require_httpAuthSchemeProvider = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/auth/httpAuthSchemeProvider.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.resolveHttpAuthSchemeConfig = exports.resolveStsAuthConfig = exports.defaultSTSHttpAuthSchemeProvider = exports.defaultSTSHttpAuthSchemeParametersProvider = void 0;
    var core_1 = (init_dist_es2(), __toCommonJS(dist_es_exports2));
    var util_middleware_1 = require_dist_cjs6();
    var STSClient_1 = require_STSClient();
    var defaultSTSHttpAuthSchemeParametersProvider2 = async (config, context, input) => {
      return {
        operation: (0, util_middleware_1.getSmithyContext)(context).operation,
        region: await (0, util_middleware_1.normalizeProvider)(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    exports.defaultSTSHttpAuthSchemeParametersProvider = defaultSTSHttpAuthSchemeParametersProvider2;
    function createAwsAuthSigv4HttpAuthOption4(authParameters) {
      return {
        schemeId: "aws.auth#sigv4",
        signingProperties: {
          name: "sts",
          region: authParameters.region
        },
        propertiesExtractor: (config, context) => ({
          signingProperties: {
            config,
            context
          }
        })
      };
    }
    function createSmithyApiNoAuthHttpAuthOption4(authParameters) {
      return {
        schemeId: "smithy.api#noAuth"
      };
    }
    var defaultSTSHttpAuthSchemeProvider2 = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "AssumeRoleWithSAML":
          {
            options.push(createSmithyApiNoAuthHttpAuthOption4(authParameters));
            break;
          }
          ;
        case "AssumeRoleWithWebIdentity":
          {
            options.push(createSmithyApiNoAuthHttpAuthOption4(authParameters));
            break;
          }
          ;
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption4(authParameters));
        }
      }
      return options;
    };
    exports.defaultSTSHttpAuthSchemeProvider = defaultSTSHttpAuthSchemeProvider2;
    var resolveStsAuthConfig2 = (input) => Object.assign(input, {
      stsClientCtor: STSClient_1.STSClient
    });
    exports.resolveStsAuthConfig = resolveStsAuthConfig2;
    var resolveHttpAuthSchemeConfig4 = (config) => {
      const config_0 = (0, exports.resolveStsAuthConfig)(config);
      const config_1 = (0, core_1.resolveAwsSdkSigV4Config)(config_0);
      return Object.assign(config_1, {
        authSchemePreference: (0, util_middleware_1.normalizeProvider)(config.authSchemePreference ?? [])
      });
    };
    exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig4;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/EndpointParameters.js
var require_EndpointParameters = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/EndpointParameters.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.commonParams = exports.resolveClientEndpointParameters = void 0;
    var resolveClientEndpointParameters4 = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        useGlobalEndpoint: options.useGlobalEndpoint ?? false,
        defaultSigningName: "sts"
      });
    };
    exports.resolveClientEndpointParameters = resolveClientEndpointParameters4;
    exports.commonParams = {
      UseGlobalEndpoint: { type: "builtInParams", name: "useGlobalEndpoint" },
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
  }
});

// node_modules/@aws-sdk/client-sts/package.json
var require_package = __commonJS({
  "node_modules/@aws-sdk/client-sts/package.json"(exports, module) {
    module.exports = {
      name: "@aws-sdk/client-sts",
      description: "AWS SDK for JavaScript Sts Client for Node.js, Browser and React Native",
      version: "3.958.0",
      scripts: {
        build: "concurrently 'yarn:build:types' 'yarn:build:es' && yarn build:cjs",
        "build:cjs": "node ../../scripts/compilation/inline client-sts",
        "build:es": "tsc -p tsconfig.es.json",
        "build:include:deps": 'yarn g:turbo run build -F="$npm_package_name"',
        "build:types": "rimraf ./dist-types tsconfig.types.tsbuildinfo && tsc -p tsconfig.types.json",
        "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
        clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
        "extract:docs": "api-extractor run --local",
        "generate:client": "node ../../scripts/generate-clients/single-service --solo sts",
        test: "yarn g:vitest run",
        "test:e2e": "yarn g:vitest run -c vitest.config.e2e.mts --mode development",
        "test:e2e:watch": "yarn g:vitest watch -c vitest.config.e2e.mts",
        "test:index": "tsc --noEmit ./test/index-types.ts && node ./test/index-objects.spec.mjs",
        "test:watch": "yarn g:vitest watch"
      },
      main: "./dist-cjs/index.js",
      types: "./dist-types/index.d.ts",
      module: "./dist-es/index.js",
      sideEffects: false,
      dependencies: {
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
        tslib: "^2.6.2"
      },
      devDependencies: {
        "@tsconfig/node18": "18.2.4",
        "@types/node": "^18.19.69",
        concurrently: "7.0.0",
        "downlevel-dts": "0.10.1",
        rimraf: "3.0.2",
        typescript: "~5.8.3"
      },
      engines: {
        node: ">=18.0.0"
      },
      typesVersions: {
        "<4.0": {
          "dist-types/*": [
            "dist-types/ts3.4/*"
          ]
        }
      },
      files: [
        "dist-*/**"
      ],
      author: {
        name: "AWS SDK for JavaScript Team",
        url: "https://aws.amazon.com/javascript/"
      },
      license: "Apache-2.0",
      browser: {
        "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser"
      },
      "react-native": {
        "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native"
      },
      homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sts",
      repository: {
        type: "git",
        url: "https://github.com/aws/aws-sdk-js-v3.git",
        directory: "clients/client-sts"
      }
    };
  }
});

// node_modules/@aws-sdk/credential-provider-env/dist-cjs/index.js
var require_dist_cjs38 = __commonJS({
  "node_modules/@aws-sdk/credential-provider-env/dist-cjs/index.js"(exports) {
    "use strict";
    var client2 = (init_client(), __toCommonJS(client_exports));
    var propertyProvider = require_dist_cjs23();
    var ENV_KEY = "AWS_ACCESS_KEY_ID";
    var ENV_SECRET = "AWS_SECRET_ACCESS_KEY";
    var ENV_SESSION = "AWS_SESSION_TOKEN";
    var ENV_EXPIRATION = "AWS_CREDENTIAL_EXPIRATION";
    var ENV_CREDENTIAL_SCOPE = "AWS_CREDENTIAL_SCOPE";
    var ENV_ACCOUNT_ID = "AWS_ACCOUNT_ID";
    var fromEnv = (init) => async () => {
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
        client2.setCredentialFeature(credentials, "CREDENTIALS_ENV_VARS", "g");
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
  }
});

// node_modules/@smithy/credential-provider-imds/dist-cjs/index.js
var require_dist_cjs39 = __commonJS({
  "node_modules/@smithy/credential-provider-imds/dist-cjs/index.js"(exports) {
    "use strict";
    var propertyProvider = require_dist_cjs23();
    var url = __require("url");
    var buffer = __require("buffer");
    var http = __require("http");
    var nodeConfigProvider = require_dist_cjs33();
    var urlParser = require_dist_cjs21();
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
            resolve(buffer.Buffer.concat(chunks));
            req.destroy();
          });
        });
        req.end();
      });
    }
    var isImdsCredentials = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.AccessKeyId === "string" && typeof arg.SecretAccessKey === "string" && typeof arg.Token === "string" && typeof arg.Expiration === "string";
    var fromImdsCredentials = (creds) => ({
      accessKeyId: creds.AccessKeyId,
      secretAccessKey: creds.SecretAccessKey,
      sessionToken: creds.Token,
      expiration: new Date(creds.Expiration),
      ...creds.AccountId && { accountId: creds.AccountId }
    });
    var DEFAULT_TIMEOUT = 1e3;
    var DEFAULT_MAX_RETRIES = 0;
    var providerConfigFromInit = ({ maxRetries = DEFAULT_MAX_RETRIES, timeout = DEFAULT_TIMEOUT }) => ({ maxRetries, timeout });
    var retry = (toRetry, maxRetries) => {
      let promise = toRetry();
      for (let i4 = 0; i4 < maxRetries; i4++) {
        promise = promise.catch(toRetry);
      }
      return promise;
    };
    var ENV_CMDS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
    var ENV_CMDS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
    var ENV_CMDS_AUTH_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
    var fromContainerMetadata = (init = {}) => {
      const { timeout, maxRetries } = providerConfigFromInit(init);
      return () => retry(async () => {
        const requestOptions = await getCmdsUri({ logger: init.logger });
        const credsResponse = JSON.parse(await requestFromEcsImds(timeout, requestOptions));
        if (!isImdsCredentials(credsResponse)) {
          throw new propertyProvider.CredentialsProviderError("Invalid response received from instance metadata service.", {
            logger: init.logger
          });
        }
        return fromImdsCredentials(credsResponse);
      }, maxRetries);
    };
    var requestFromEcsImds = async (timeout, options) => {
      if (process.env[ENV_CMDS_AUTH_TOKEN]) {
        options.headers = {
          ...options.headers,
          Authorization: process.env[ENV_CMDS_AUTH_TOKEN]
        };
      }
      const buffer2 = await httpRequest({
        ...options,
        timeout
      });
      return buffer2.toString();
    };
    var CMDS_IP = "169.254.170.2";
    var GREENGRASS_HOSTS = {
      localhost: true,
      "127.0.0.1": true
    };
    var GREENGRASS_PROTOCOLS = {
      "http:": true,
      "https:": true
    };
    var getCmdsUri = async ({ logger: logger2 }) => {
      if (process.env[ENV_CMDS_RELATIVE_URI]) {
        return {
          hostname: CMDS_IP,
          path: process.env[ENV_CMDS_RELATIVE_URI]
        };
      }
      if (process.env[ENV_CMDS_FULL_URI]) {
        const parsed = url.parse(process.env[ENV_CMDS_FULL_URI]);
        if (!parsed.hostname || !(parsed.hostname in GREENGRASS_HOSTS)) {
          throw new propertyProvider.CredentialsProviderError(`${parsed.hostname} is not a valid container metadata service hostname`, {
            tryNextLink: false,
            logger: logger2
          });
        }
        if (!parsed.protocol || !(parsed.protocol in GREENGRASS_PROTOCOLS)) {
          throw new propertyProvider.CredentialsProviderError(`${parsed.protocol} is not a valid container metadata service protocol`, {
            tryNextLink: false,
            logger: logger2
          });
        }
        return {
          ...parsed,
          port: parsed.port ? parseInt(parsed.port, 10) : void 0
        };
      }
      throw new propertyProvider.CredentialsProviderError(`The container metadata credential provider cannot be used unless the ${ENV_CMDS_RELATIVE_URI} or ${ENV_CMDS_FULL_URI} environment variable is set`, {
        tryNextLink: false,
        logger: logger2
      });
    };
    var InstanceMetadataV1FallbackError = class _InstanceMetadataV1FallbackError extends propertyProvider.CredentialsProviderError {
      tryNextLink;
      name = "InstanceMetadataV1FallbackError";
      constructor(message, tryNextLink = true) {
        super(message, tryNextLink);
        this.tryNextLink = tryNextLink;
        Object.setPrototypeOf(this, _InstanceMetadataV1FallbackError.prototype);
      }
    };
    exports.Endpoint = void 0;
    (function(Endpoint) {
      Endpoint["IPv4"] = "http://169.254.169.254";
      Endpoint["IPv6"] = "http://[fd00:ec2::254]";
    })(exports.Endpoint || (exports.Endpoint = {}));
    var ENV_ENDPOINT_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT";
    var CONFIG_ENDPOINT_NAME = "ec2_metadata_service_endpoint";
    var ENDPOINT_CONFIG_OPTIONS = {
      environmentVariableSelector: (env) => env[ENV_ENDPOINT_NAME],
      configFileSelector: (profile) => profile[CONFIG_ENDPOINT_NAME],
      default: void 0
    };
    var EndpointMode;
    (function(EndpointMode2) {
      EndpointMode2["IPv4"] = "IPv4";
      EndpointMode2["IPv6"] = "IPv6";
    })(EndpointMode || (EndpointMode = {}));
    var ENV_ENDPOINT_MODE_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE";
    var CONFIG_ENDPOINT_MODE_NAME = "ec2_metadata_service_endpoint_mode";
    var ENDPOINT_MODE_CONFIG_OPTIONS = {
      environmentVariableSelector: (env) => env[ENV_ENDPOINT_MODE_NAME],
      configFileSelector: (profile) => profile[CONFIG_ENDPOINT_MODE_NAME],
      default: EndpointMode.IPv4
    };
    var getInstanceMetadataEndpoint = async () => urlParser.parseUrl(await getFromEndpointConfig() || await getFromEndpointModeConfig());
    var getFromEndpointConfig = async () => nodeConfigProvider.loadConfig(ENDPOINT_CONFIG_OPTIONS)();
    var getFromEndpointModeConfig = async () => {
      const endpointMode = await nodeConfigProvider.loadConfig(ENDPOINT_MODE_CONFIG_OPTIONS)();
      switch (endpointMode) {
        case EndpointMode.IPv4:
          return exports.Endpoint.IPv4;
        case EndpointMode.IPv6:
          return exports.Endpoint.IPv6;
        default:
          throw new Error(`Unsupported endpoint mode: ${endpointMode}. Select from ${Object.values(EndpointMode)}`);
      }
    };
    var STATIC_STABILITY_REFRESH_INTERVAL_SECONDS = 5 * 60;
    var STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS = 5 * 60;
    var STATIC_STABILITY_DOC_URL = "https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html";
    var getExtendedInstanceMetadataCredentials = (credentials, logger2) => {
      const refreshInterval = STATIC_STABILITY_REFRESH_INTERVAL_SECONDS + Math.floor(Math.random() * STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS);
      const newExpiration = new Date(Date.now() + refreshInterval * 1e3);
      logger2.warn(`Attempting credential expiration extension due to a credential service availability issue. A refresh of these credentials will be attempted after ${new Date(newExpiration)}.
For more information, please visit: ` + STATIC_STABILITY_DOC_URL);
      const originalExpiration = credentials.originalExpiration ?? credentials.expiration;
      return {
        ...credentials,
        ...originalExpiration ? { originalExpiration } : {},
        expiration: newExpiration
      };
    };
    var staticStabilityProvider = (provider, options = {}) => {
      const logger2 = options?.logger || console;
      let pastCredentials;
      return async () => {
        let credentials;
        try {
          credentials = await provider();
          if (credentials.expiration && credentials.expiration.getTime() < Date.now()) {
            credentials = getExtendedInstanceMetadataCredentials(credentials, logger2);
          }
        } catch (e4) {
          if (pastCredentials) {
            logger2.warn("Credential renew failed: ", e4);
            credentials = getExtendedInstanceMetadataCredentials(pastCredentials, logger2);
          } else {
            throw e4;
          }
        }
        pastCredentials = credentials;
        return credentials;
      };
    };
    var IMDS_PATH = "/latest/meta-data/iam/security-credentials/";
    var IMDS_TOKEN_PATH = "/latest/api/token";
    var AWS_EC2_METADATA_V1_DISABLED = "AWS_EC2_METADATA_V1_DISABLED";
    var PROFILE_AWS_EC2_METADATA_V1_DISABLED = "ec2_metadata_v1_disabled";
    var X_AWS_EC2_METADATA_TOKEN = "x-aws-ec2-metadata-token";
    var fromInstanceMetadata = (init = {}) => staticStabilityProvider(getInstanceMetadataProvider(init), { logger: init.logger });
    var getInstanceMetadataProvider = (init = {}) => {
      let disableFetchToken = false;
      const { logger: logger2, profile } = init;
      const { timeout, maxRetries } = providerConfigFromInit(init);
      const getCredentials = async (maxRetries2, options) => {
        const isImdsV1Fallback = disableFetchToken || options.headers?.[X_AWS_EC2_METADATA_TOKEN] == null;
        if (isImdsV1Fallback) {
          let fallbackBlockedFromProfile = false;
          let fallbackBlockedFromProcessEnv = false;
          const configValue = await nodeConfigProvider.loadConfig({
            environmentVariableSelector: (env) => {
              const envValue = env[AWS_EC2_METADATA_V1_DISABLED];
              fallbackBlockedFromProcessEnv = !!envValue && envValue !== "false";
              if (envValue === void 0) {
                throw new propertyProvider.CredentialsProviderError(`${AWS_EC2_METADATA_V1_DISABLED} not set in env, checking config file next.`, { logger: init.logger });
              }
              return fallbackBlockedFromProcessEnv;
            },
            configFileSelector: (profile2) => {
              const profileValue = profile2[PROFILE_AWS_EC2_METADATA_V1_DISABLED];
              fallbackBlockedFromProfile = !!profileValue && profileValue !== "false";
              return fallbackBlockedFromProfile;
            },
            default: false
          }, {
            profile
          })();
          if (init.ec2MetadataV1Disabled || configValue) {
            const causes = [];
            if (init.ec2MetadataV1Disabled)
              causes.push("credential provider initialization (runtime option ec2MetadataV1Disabled)");
            if (fallbackBlockedFromProfile)
              causes.push(`config file profile (${PROFILE_AWS_EC2_METADATA_V1_DISABLED})`);
            if (fallbackBlockedFromProcessEnv)
              causes.push(`process environment variable (${AWS_EC2_METADATA_V1_DISABLED})`);
            throw new InstanceMetadataV1FallbackError(`AWS EC2 Metadata v1 fallback has been blocked by AWS SDK configuration in the following: [${causes.join(", ")}].`);
          }
        }
        const imdsProfile = (await retry(async () => {
          let profile2;
          try {
            profile2 = await getProfile(options);
          } catch (err) {
            if (err.statusCode === 401) {
              disableFetchToken = false;
            }
            throw err;
          }
          return profile2;
        }, maxRetries2)).trim();
        return retry(async () => {
          let creds;
          try {
            creds = await getCredentialsFromProfile(imdsProfile, options, init);
          } catch (err) {
            if (err.statusCode === 401) {
              disableFetchToken = false;
            }
            throw err;
          }
          return creds;
        }, maxRetries2);
      };
      return async () => {
        const endpoint = await getInstanceMetadataEndpoint();
        if (disableFetchToken) {
          logger2?.debug("AWS SDK Instance Metadata", "using v1 fallback (no token fetch)");
          return getCredentials(maxRetries, { ...endpoint, timeout });
        } else {
          let token;
          try {
            token = (await getMetadataToken({ ...endpoint, timeout })).toString();
          } catch (error2) {
            if (error2?.statusCode === 400) {
              throw Object.assign(error2, {
                message: "EC2 Metadata token request returned error"
              });
            } else if (error2.message === "TimeoutError" || [403, 404, 405].includes(error2.statusCode)) {
              disableFetchToken = true;
            }
            logger2?.debug("AWS SDK Instance Metadata", "using v1 fallback (initial)");
            return getCredentials(maxRetries, { ...endpoint, timeout });
          }
          return getCredentials(maxRetries, {
            ...endpoint,
            headers: {
              [X_AWS_EC2_METADATA_TOKEN]: token
            },
            timeout
          });
        }
      };
    };
    var getMetadataToken = async (options) => httpRequest({
      ...options,
      path: IMDS_TOKEN_PATH,
      method: "PUT",
      headers: {
        "x-aws-ec2-metadata-token-ttl-seconds": "21600"
      }
    });
    var getProfile = async (options) => (await httpRequest({ ...options, path: IMDS_PATH })).toString();
    var getCredentialsFromProfile = async (profile, options, init) => {
      const credentialsResponse = JSON.parse((await httpRequest({
        ...options,
        path: IMDS_PATH + profile
      })).toString());
      if (!isImdsCredentials(credentialsResponse)) {
        throw new propertyProvider.CredentialsProviderError("Invalid response received from instance metadata service.", {
          logger: init.logger
        });
      }
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
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/checkUrl.js
var require_checkUrl = __commonJS({
  "node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/checkUrl.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.checkUrl = void 0;
    var property_provider_1 = require_dist_cjs23();
    var ECS_CONTAINER_HOST = "169.254.170.2";
    var EKS_CONTAINER_HOST_IPv4 = "169.254.170.23";
    var EKS_CONTAINER_HOST_IPv6 = "[fd00:ec2::23]";
    var checkUrl = (url, logger2) => {
      if (url.protocol === "https:") {
        return;
      }
      if (url.hostname === ECS_CONTAINER_HOST || url.hostname === EKS_CONTAINER_HOST_IPv4 || url.hostname === EKS_CONTAINER_HOST_IPv6) {
        return;
      }
      if (url.hostname.includes("[")) {
        if (url.hostname === "[::1]" || url.hostname === "[0000:0000:0000:0000:0000:0000:0000:0001]") {
          return;
        }
      } else {
        if (url.hostname === "localhost") {
          return;
        }
        const ipComponents = url.hostname.split(".");
        const inRange = (component) => {
          const num = parseInt(component, 10);
          return 0 <= num && num <= 255;
        };
        if (ipComponents[0] === "127" && inRange(ipComponents[1]) && inRange(ipComponents[2]) && inRange(ipComponents[3]) && ipComponents.length === 4) {
          return;
        }
      }
      throw new property_provider_1.CredentialsProviderError(`URL not accepted. It must either be HTTPS or match one of the following:
  - loopback CIDR 127.0.0.0/8 or [::1/128]
  - ECS container host 169.254.170.2
  - EKS container host 169.254.170.23 or [fd00:ec2::23]`, { logger: logger2 });
    };
    exports.checkUrl = checkUrl;
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/requestHelpers.js
var require_requestHelpers = __commonJS({
  "node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/requestHelpers.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.createGetRequest = createGetRequest;
    exports.getCredentials = getCredentials;
    var property_provider_1 = require_dist_cjs23();
    var protocol_http_1 = require_dist_cjs2();
    var smithy_client_1 = require_dist_cjs26();
    var util_stream_1 = require_dist_cjs17();
    function createGetRequest(url) {
      return new protocol_http_1.HttpRequest({
        protocol: url.protocol,
        hostname: url.hostname,
        port: Number(url.port),
        path: url.pathname,
        query: Array.from(url.searchParams.entries()).reduce((acc, [k4, v4]) => {
          acc[k4] = v4;
          return acc;
        }, {}),
        fragment: url.hash
      });
    }
    async function getCredentials(response, logger2) {
      const stream = (0, util_stream_1.sdkStreamMixin)(response.body);
      const str = await stream.transformToString();
      if (response.statusCode === 200) {
        const parsed = JSON.parse(str);
        if (typeof parsed.AccessKeyId !== "string" || typeof parsed.SecretAccessKey !== "string" || typeof parsed.Token !== "string" || typeof parsed.Expiration !== "string") {
          throw new property_provider_1.CredentialsProviderError("HTTP credential provider response not of the required format, an object matching: { AccessKeyId: string, SecretAccessKey: string, Token: string, Expiration: string(rfc3339) }", { logger: logger2 });
        }
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
        } catch (e4) {
        }
        throw Object.assign(new property_provider_1.CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger: logger2 }), {
          Code: parsedBody.Code,
          Message: parsedBody.Message
        });
      }
      throw new property_provider_1.CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger: logger2 });
    }
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/retry-wrapper.js
var require_retry_wrapper = __commonJS({
  "node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/retry-wrapper.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.retryWrapper = void 0;
    var retryWrapper = (toRetry, maxRetries, delayMs) => {
      return async () => {
        for (let i4 = 0; i4 < maxRetries; ++i4) {
          try {
            return await toRetry();
          } catch (e4) {
            await new Promise((resolve) => setTimeout(resolve, delayMs));
          }
        }
        return await toRetry();
      };
    };
    exports.retryWrapper = retryWrapper;
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/fromHttp.js
var require_fromHttp = __commonJS({
  "node_modules/@aws-sdk/credential-provider-http/dist-cjs/fromHttp/fromHttp.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.fromHttp = void 0;
    var tslib_1 = (init_tslib_es6(), __toCommonJS(tslib_es6_exports));
    var client_1 = (init_client(), __toCommonJS(client_exports));
    var node_http_handler_1 = require_dist_cjs14();
    var property_provider_1 = require_dist_cjs23();
    var promises_1 = tslib_1.__importDefault(__require("fs/promises"));
    var checkUrl_1 = require_checkUrl();
    var requestHelpers_1 = require_requestHelpers();
    var retry_wrapper_1 = require_retry_wrapper();
    var AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
    var DEFAULT_LINK_LOCAL_HOST = "http://169.254.170.2";
    var AWS_CONTAINER_CREDENTIALS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
    var AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";
    var AWS_CONTAINER_AUTHORIZATION_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
    var fromHttp = (options = {}) => {
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
      if (full) {
        host = full;
      } else if (relative) {
        host = `${DEFAULT_LINK_LOCAL_HOST}${relative}`;
      } else {
        throw new property_provider_1.CredentialsProviderError(`No HTTP credential provider host provided.
Set AWS_CONTAINER_CREDENTIALS_FULL_URI or AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.`, { logger: options.logger });
      }
      const url = new URL(host);
      (0, checkUrl_1.checkUrl)(url, options.logger);
      const requestHandler = node_http_handler_1.NodeHttpHandler.create({
        requestTimeout: options.timeout ?? 1e3,
        connectionTimeout: options.timeout ?? 1e3
      });
      return (0, retry_wrapper_1.retryWrapper)(async () => {
        const request = (0, requestHelpers_1.createGetRequest)(url);
        if (token) {
          request.headers.Authorization = token;
        } else if (tokenFile) {
          request.headers.Authorization = (await promises_1.default.readFile(tokenFile)).toString();
        }
        try {
          const result = await requestHandler.handle(request);
          return (0, requestHelpers_1.getCredentials)(result.response).then((creds) => (0, client_1.setCredentialFeature)(creds, "CREDENTIALS_HTTP", "z"));
        } catch (e4) {
          throw new property_provider_1.CredentialsProviderError(String(e4), { logger: options.logger });
        }
      }, options.maxRetries ?? 3, options.timeout ?? 1e3);
    };
    exports.fromHttp = fromHttp;
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-cjs/index.js
var require_dist_cjs40 = __commonJS({
  "node_modules/@aws-sdk/credential-provider-http/dist-cjs/index.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.fromHttp = void 0;
    var fromHttp_1 = require_fromHttp();
    Object.defineProperty(exports, "fromHttp", { enumerable: true, get: function() {
      return fromHttp_1.fromHttp;
    } });
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "sso-oauth",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var import_util_middleware6, defaultSSOOIDCHttpAuthSchemeParametersProvider, defaultSSOOIDCHttpAuthSchemeProvider, resolveHttpAuthSchemeConfig;
var init_httpAuthSchemeProvider = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthSchemeProvider.js"() {
    init_dist_es2();
    import_util_middleware6 = __toESM(require_dist_cjs6());
    defaultSSOOIDCHttpAuthSchemeParametersProvider = async (config, context, input) => {
      return {
        operation: (0, import_util_middleware6.getSmithyContext)(context).operation,
        region: await (0, import_util_middleware6.normalizeProvider)(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    defaultSSOOIDCHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "CreateToken": {
          options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
          break;
        }
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
        }
      }
      return options;
    };
    resolveHttpAuthSchemeConfig = (config) => {
      const config_0 = resolveAwsSdkSigV4Config(config);
      return Object.assign(config_0, {
        authSchemePreference: (0, import_util_middleware6.normalizeProvider)(config.authSchemePreference ?? [])
      });
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/EndpointParameters.js
var resolveClientEndpointParameters, commonParams;
var init_EndpointParameters = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/EndpointParameters.js"() {
    resolveClientEndpointParameters = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "sso-oauth"
      });
    };
    commonParams = {
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/package.json
var package_default;
var init_package = __esm({
  "node_modules/@aws-sdk/nested-clients/package.json"() {
    package_default = {
      name: "@aws-sdk/nested-clients",
      version: "3.958.0",
      description: "Nested clients for AWS SDK packages.",
      main: "./dist-cjs/index.js",
      module: "./dist-es/index.js",
      types: "./dist-types/index.d.ts",
      scripts: {
        build: "yarn lint && concurrently 'yarn:build:cjs' 'yarn:build:es' 'yarn:build:types'",
        "build:cjs": "node ../../scripts/compilation/inline nested-clients",
        "build:es": "tsc -p tsconfig.es.json",
        "build:include:deps": 'yarn g:turbo run build -F="$npm_package_name"',
        "build:types": "tsc -p tsconfig.types.json",
        "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
        clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
        lint: "node ../../scripts/validation/submodules-linter.js --pkg nested-clients",
        test: "yarn g:vitest run",
        "test:watch": "yarn g:vitest watch"
      },
      engines: {
        node: ">=18.0.0"
      },
      sideEffects: false,
      author: {
        name: "AWS SDK for JavaScript Team",
        url: "https://aws.amazon.com/javascript/"
      },
      license: "Apache-2.0",
      dependencies: {
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
        tslib: "^2.6.2"
      },
      devDependencies: {
        concurrently: "7.0.0",
        "downlevel-dts": "0.10.1",
        rimraf: "3.0.2",
        typescript: "~5.8.3"
      },
      typesVersions: {
        "<4.0": {
          "dist-types/*": [
            "dist-types/ts3.4/*"
          ]
        }
      },
      files: [
        "./signin.d.ts",
        "./signin.js",
        "./sso-oidc.d.ts",
        "./sso-oidc.js",
        "./sts.d.ts",
        "./sts.js",
        "dist-*/**"
      ],
      browser: {
        "./dist-es/submodules/signin/runtimeConfig": "./dist-es/submodules/signin/runtimeConfig.browser",
        "./dist-es/submodules/sso-oidc/runtimeConfig": "./dist-es/submodules/sso-oidc/runtimeConfig.browser",
        "./dist-es/submodules/sts/runtimeConfig": "./dist-es/submodules/sts/runtimeConfig.browser"
      },
      "react-native": {},
      homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/packages/nested-clients",
      repository: {
        type: "git",
        url: "https://github.com/aws/aws-sdk-js-v3.git",
        directory: "packages/nested-clients"
      },
      exports: {
        "./package.json": "./package.json",
        "./sso-oidc": {
          types: "./dist-types/submodules/sso-oidc/index.d.ts",
          module: "./dist-es/submodules/sso-oidc/index.js",
          node: "./dist-cjs/submodules/sso-oidc/index.js",
          import: "./dist-es/submodules/sso-oidc/index.js",
          require: "./dist-cjs/submodules/sso-oidc/index.js"
        },
        "./sts": {
          types: "./dist-types/submodules/sts/index.d.ts",
          module: "./dist-es/submodules/sts/index.js",
          node: "./dist-cjs/submodules/sts/index.js",
          import: "./dist-es/submodules/sts/index.js",
          require: "./dist-cjs/submodules/sts/index.js"
        },
        "./signin": {
          types: "./dist-types/submodules/signin/index.d.ts",
          module: "./dist-es/submodules/signin/index.js",
          node: "./dist-cjs/submodules/signin/index.js",
          import: "./dist-es/submodules/signin/index.js",
          require: "./dist-cjs/submodules/signin/index.js"
        }
      }
    };
  }
});

// node_modules/@aws-sdk/util-user-agent-node/dist-cjs/index.js
var require_dist_cjs41 = __commonJS({
  "node_modules/@aws-sdk/util-user-agent-node/dist-cjs/index.js"(exports) {
    "use strict";
    var os = __require("os");
    var process2 = __require("process");
    var middlewareUserAgent = require_dist_cjs28();
    var crtAvailability = {
      isCrtAvailable: false
    };
    var isCrtAvailable = () => {
      if (crtAvailability.isCrtAvailable) {
        return ["md/crt-avail"];
      }
      return null;
    };
    var createDefaultUserAgentProvider4 = ({ serviceId, clientVersion }) => {
      return async (config) => {
        const sections = [
          ["aws-sdk-js", clientVersion],
          ["ua", "2.1"],
          [`os/${os.platform()}`, os.release()],
          ["lang/js"],
          ["md/nodejs", `${process2.versions.node}`]
        ];
        const crtAvailable = isCrtAvailable();
        if (crtAvailable) {
          sections.push(crtAvailable);
        }
        if (serviceId) {
          sections.push([`api/${serviceId}`, clientVersion]);
        }
        if (process2.env.AWS_EXECUTION_ENV) {
          sections.push([`exec-env/${process2.env.AWS_EXECUTION_ENV}`]);
        }
        const appId = await config?.userAgentAppId?.();
        const resolvedUserAgent = appId ? [...sections, [`app/${appId}`]] : [...sections];
        return resolvedUserAgent;
      };
    };
    var defaultUserAgent = createDefaultUserAgentProvider4;
    var UA_APP_ID_ENV_NAME = "AWS_SDK_UA_APP_ID";
    var UA_APP_ID_INI_NAME = "sdk_ua_app_id";
    var UA_APP_ID_INI_NAME_DEPRECATED = "sdk-ua-app-id";
    var NODE_APP_ID_CONFIG_OPTIONS4 = {
      environmentVariableSelector: (env) => env[UA_APP_ID_ENV_NAME],
      configFileSelector: (profile) => profile[UA_APP_ID_INI_NAME] ?? profile[UA_APP_ID_INI_NAME_DEPRECATED],
      default: middlewareUserAgent.DEFAULT_UA_APP_ID
    };
    exports.NODE_APP_ID_CONFIG_OPTIONS = NODE_APP_ID_CONFIG_OPTIONS4;
    exports.UA_APP_ID_ENV_NAME = UA_APP_ID_ENV_NAME;
    exports.UA_APP_ID_INI_NAME = UA_APP_ID_INI_NAME;
    exports.createDefaultUserAgentProvider = createDefaultUserAgentProvider4;
    exports.crtAvailability = crtAvailability;
    exports.defaultUserAgent = defaultUserAgent;
  }
});

// node_modules/@smithy/hash-node/dist-cjs/index.js
var require_dist_cjs42 = __commonJS({
  "node_modules/@smithy/hash-node/dist-cjs/index.js"(exports) {
    "use strict";
    var utilBufferFrom = require_dist_cjs9();
    var utilUtf8 = require_dist_cjs10();
    var buffer = __require("buffer");
    var crypto2 = __require("crypto");
    var Hash4 = class {
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
        this.hash = this.secret ? crypto2.createHmac(this.algorithmIdentifier, castSourceData(this.secret)) : crypto2.createHash(this.algorithmIdentifier);
      }
    };
    function castSourceData(toCast, encoding) {
      if (buffer.Buffer.isBuffer(toCast)) {
        return toCast;
      }
      if (typeof toCast === "string") {
        return utilBufferFrom.fromString(toCast, encoding);
      }
      if (ArrayBuffer.isView(toCast)) {
        return utilBufferFrom.fromArrayBuffer(toCast.buffer, toCast.byteOffset, toCast.byteLength);
      }
      return utilBufferFrom.fromArrayBuffer(toCast);
    }
    exports.Hash = Hash4;
  }
});

// node_modules/@smithy/util-body-length-node/dist-cjs/index.js
var require_dist_cjs43 = __commonJS({
  "node_modules/@smithy/util-body-length-node/dist-cjs/index.js"(exports) {
    "use strict";
    var node_fs = __require("node:fs");
    var calculateBodyLength4 = (body) => {
      if (!body) {
        return 0;
      }
      if (typeof body === "string") {
        return Buffer.byteLength(body);
      } else if (typeof body.byteLength === "number") {
        return body.byteLength;
      } else if (typeof body.size === "number") {
        return body.size;
      } else if (typeof body.start === "number" && typeof body.end === "number") {
        return body.end + 1 - body.start;
      } else if (body instanceof node_fs.ReadStream) {
        if (body.path != null) {
          return node_fs.lstatSync(body.path).size;
        } else if (typeof body.fd === "number") {
          return node_fs.fstatSync(body.fd).size;
        }
      }
      throw new Error(`Body Length computation failed for ${body}`);
    };
    exports.calculateBodyLength = calculateBodyLength4;
  }
});

// node_modules/@smithy/util-defaults-mode-node/dist-cjs/index.js
var require_dist_cjs44 = __commonJS({
  "node_modules/@smithy/util-defaults-mode-node/dist-cjs/index.js"(exports) {
    "use strict";
    var configResolver = require_dist_cjs30();
    var nodeConfigProvider = require_dist_cjs33();
    var propertyProvider = require_dist_cjs23();
    var AWS_EXECUTION_ENV = "AWS_EXECUTION_ENV";
    var AWS_REGION_ENV = "AWS_REGION";
    var AWS_DEFAULT_REGION_ENV = "AWS_DEFAULT_REGION";
    var ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
    var DEFAULTS_MODE_OPTIONS = ["in-region", "cross-region", "mobile", "standard", "legacy"];
    var IMDS_REGION_PATH = "/latest/meta-data/placement/region";
    var AWS_DEFAULTS_MODE_ENV = "AWS_DEFAULTS_MODE";
    var AWS_DEFAULTS_MODE_CONFIG = "defaults_mode";
    var NODE_DEFAULTS_MODE_CONFIG_OPTIONS = {
      environmentVariableSelector: (env) => {
        return env[AWS_DEFAULTS_MODE_ENV];
      },
      configFileSelector: (profile) => {
        return profile[AWS_DEFAULTS_MODE_CONFIG];
      },
      default: "legacy"
    };
    var resolveDefaultsModeConfig4 = ({ region = nodeConfigProvider.loadConfig(configResolver.NODE_REGION_CONFIG_OPTIONS), defaultsMode = nodeConfigProvider.loadConfig(NODE_DEFAULTS_MODE_CONFIG_OPTIONS) } = {}) => propertyProvider.memoize(async () => {
      const mode = typeof defaultsMode === "function" ? await defaultsMode() : defaultsMode;
      switch (mode?.toLowerCase()) {
        case "auto":
          return resolveNodeDefaultsModeAuto(region);
        case "in-region":
        case "cross-region":
        case "mobile":
        case "standard":
        case "legacy":
          return Promise.resolve(mode?.toLocaleLowerCase());
        case void 0:
          return Promise.resolve("legacy");
        default:
          throw new Error(`Invalid parameter for "defaultsMode", expect ${DEFAULTS_MODE_OPTIONS.join(", ")}, got ${mode}`);
      }
    });
    var resolveNodeDefaultsModeAuto = async (clientRegion) => {
      if (clientRegion) {
        const resolvedRegion = typeof clientRegion === "function" ? await clientRegion() : clientRegion;
        const inferredRegion = await inferPhysicalRegion();
        if (!inferredRegion) {
          return "standard";
        }
        if (resolvedRegion === inferredRegion) {
          return "in-region";
        } else {
          return "cross-region";
        }
      }
      return "standard";
    };
    var inferPhysicalRegion = async () => {
      if (process.env[AWS_EXECUTION_ENV] && (process.env[AWS_REGION_ENV] || process.env[AWS_DEFAULT_REGION_ENV])) {
        return process.env[AWS_REGION_ENV] ?? process.env[AWS_DEFAULT_REGION_ENV];
      }
      if (!process.env[ENV_IMDS_DISABLED]) {
        try {
          const { getInstanceMetadataEndpoint, httpRequest } = await Promise.resolve().then(() => __toESM(require_dist_cjs39()));
          const endpoint = await getInstanceMetadataEndpoint();
          return (await httpRequest({ ...endpoint, path: IMDS_REGION_PATH })).toString();
        } catch (e4) {
        }
      }
    };
    exports.resolveDefaultsModeConfig = resolveDefaultsModeConfig4;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/ruleset.js
var u, v, w, x, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, _data, ruleSet;
var init_ruleset = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/ruleset.js"() {
    u = "required";
    v = "fn";
    w = "argv";
    x = "ref";
    a = true;
    b = "isSet";
    c = "booleanEquals";
    d = "error";
    e = "endpoint";
    f = "tree";
    g = "PartitionResult";
    h = "getAttr";
    i = { [u]: false, "type": "string" };
    j = { [u]: true, "default": false, "type": "boolean" };
    k = { [x]: "Endpoint" };
    l = { [v]: c, [w]: [{ [x]: "UseFIPS" }, true] };
    m = { [v]: c, [w]: [{ [x]: "UseDualStack" }, true] };
    n = {};
    o = { [v]: h, [w]: [{ [x]: g }, "supportsFIPS"] };
    p = { [x]: g };
    q = { [v]: c, [w]: [true, { [v]: h, [w]: [p, "supportsDualStack"] }] };
    r = [l];
    s = [m];
    t = [{ [x]: "Region" }];
    _data = { version: "1.0", parameters: { Region: i, UseDualStack: j, UseFIPS: j, Endpoint: i }, rules: [{ conditions: [{ [v]: b, [w]: [k] }], rules: [{ conditions: r, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d }, { conditions: s, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d }, { endpoint: { url: k, properties: n, headers: n }, type: e }], type: f }, { conditions: [{ [v]: b, [w]: t }], rules: [{ conditions: [{ [v]: "aws.partition", [w]: t, assign: g }], rules: [{ conditions: [l, m], rules: [{ conditions: [{ [v]: c, [w]: [a, o] }, q], rules: [{ endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d }], type: f }, { conditions: r, rules: [{ conditions: [{ [v]: c, [w]: [o, a] }], rules: [{ conditions: [{ [v]: "stringEquals", [w]: [{ [v]: h, [w]: [p, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://oidc.{Region}.amazonaws.com", properties: n, headers: n }, type: e }, { endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS is enabled but this partition does not support FIPS", type: d }], type: f }, { conditions: s, rules: [{ conditions: [q], rules: [{ endpoint: { url: "https://oidc.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "DualStack is enabled but this partition does not support DualStack", type: d }], type: f }, { endpoint: { url: "https://oidc.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }], type: f }, { error: "Invalid Configuration: Missing Region", type: d }] };
    ruleSet = _data;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/endpointResolver.js
var import_util_endpoints, import_util_endpoints2, cache, defaultEndpointResolver;
var init_endpointResolver = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/endpointResolver.js"() {
    import_util_endpoints = __toESM(require_dist_cjs22());
    import_util_endpoints2 = __toESM(require_dist_cjs19());
    init_ruleset();
    cache = new import_util_endpoints2.EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
    });
    defaultEndpointResolver = (endpointParams, context = {}) => {
      return cache.get(endpointParams, () => (0, import_util_endpoints2.resolveEndpoint)(ruleSet, {
        endpointParams,
        logger: context.logger
      }));
    };
    import_util_endpoints2.customEndpointFunctions.aws = import_util_endpoints.awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.shared.js
var import_smithy_client8, import_url_parser, import_util_base648, import_util_utf88, getRuntimeConfig;
var init_runtimeConfig_shared = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.shared.js"() {
    init_dist_es2();
    init_protocols2();
    init_dist_es();
    import_smithy_client8 = __toESM(require_dist_cjs26());
    import_url_parser = __toESM(require_dist_cjs21());
    import_util_base648 = __toESM(require_dist_cjs11());
    import_util_utf88 = __toESM(require_dist_cjs10());
    init_httpAuthSchemeProvider();
    init_endpointResolver();
    getRuntimeConfig = (config) => {
      return {
        apiVersion: "2019-06-10",
        base64Decoder: config?.base64Decoder ?? import_util_base648.fromBase64,
        base64Encoder: config?.base64Encoder ?? import_util_base648.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSSOOIDCHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        logger: config?.logger ?? new import_smithy_client8.NoOpLogger(),
        protocol: config?.protocol ?? AwsRestJsonProtocol,
        protocolSettings: config?.protocolSettings ?? {
          defaultNamespace: "com.amazonaws.ssooidc",
          version: "2019-06-10",
          serviceTarget: "AWSSSOOIDCService"
        },
        serviceId: config?.serviceId ?? "SSO OIDC",
        urlParser: config?.urlParser ?? import_url_parser.parseUrl,
        utf8Decoder: config?.utf8Decoder ?? import_util_utf88.fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? import_util_utf88.toUtf8
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.js
var import_util_user_agent_node, import_config_resolver, import_hash_node, import_middleware_retry, import_node_config_provider, import_node_http_handler, import_smithy_client9, import_util_body_length_node, import_util_defaults_mode_node, import_util_retry, getRuntimeConfig2;
var init_runtimeConfig = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.js"() {
    init_package();
    init_dist_es2();
    import_util_user_agent_node = __toESM(require_dist_cjs41());
    import_config_resolver = __toESM(require_dist_cjs30());
    import_hash_node = __toESM(require_dist_cjs42());
    import_middleware_retry = __toESM(require_dist_cjs37());
    import_node_config_provider = __toESM(require_dist_cjs33());
    import_node_http_handler = __toESM(require_dist_cjs14());
    import_smithy_client9 = __toESM(require_dist_cjs26());
    import_util_body_length_node = __toESM(require_dist_cjs43());
    import_util_defaults_mode_node = __toESM(require_dist_cjs44());
    import_util_retry = __toESM(require_dist_cjs36());
    init_runtimeConfig_shared();
    getRuntimeConfig2 = (config) => {
      (0, import_smithy_client9.emitWarningIfUnsupportedVersion)(process.version);
      const defaultsMode = (0, import_util_defaults_mode_node.resolveDefaultsModeConfig)(config);
      const defaultConfigProvider = () => defaultsMode().then(import_smithy_client9.loadConfigsForDefaultMode);
      const clientSharedValues = getRuntimeConfig(config);
      emitWarningIfUnsupportedVersion(process.version);
      const loaderConfig = {
        profile: config?.profile,
        logger: clientSharedValues.logger
      };
      return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        authSchemePreference: config?.authSchemePreference ?? (0, import_node_config_provider.loadConfig)(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
        bodyLengthChecker: config?.bodyLengthChecker ?? import_util_body_length_node.calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, import_util_user_agent_node.createDefaultUserAgentProvider)({ serviceId: clientSharedValues.serviceId, clientVersion: package_default.version }),
        maxAttempts: config?.maxAttempts ?? (0, import_node_config_provider.loadConfig)(import_middleware_retry.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? (0, import_node_config_provider.loadConfig)(import_config_resolver.NODE_REGION_CONFIG_OPTIONS, { ...import_config_resolver.NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
        requestHandler: import_node_http_handler.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ?? (0, import_node_config_provider.loadConfig)({
          ...import_middleware_retry.NODE_RETRY_MODE_CONFIG_OPTIONS,
          default: async () => (await defaultConfigProvider()).retryMode || import_util_retry.DEFAULT_RETRY_MODE
        }, config),
        sha256: config?.sha256 ?? import_hash_node.Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? import_node_http_handler.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, import_node_config_provider.loadConfig)(import_config_resolver.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        useFipsEndpoint: config?.useFipsEndpoint ?? (0, import_node_config_provider.loadConfig)(import_config_resolver.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        userAgentAppId: config?.userAgentAppId ?? (0, import_node_config_provider.loadConfig)(import_util_user_agent_node.NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
      };
    };
  }
});

// node_modules/@aws-sdk/region-config-resolver/dist-cjs/regionConfig/stsRegionDefaultResolver.js
var require_stsRegionDefaultResolver = __commonJS({
  "node_modules/@aws-sdk/region-config-resolver/dist-cjs/regionConfig/stsRegionDefaultResolver.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.warning = void 0;
    exports.stsRegionDefaultResolver = stsRegionDefaultResolver2;
    var config_resolver_1 = require_dist_cjs30();
    var node_config_provider_1 = require_dist_cjs33();
    function stsRegionDefaultResolver2(loaderConfig = {}) {
      return (0, node_config_provider_1.loadConfig)({
        ...config_resolver_1.NODE_REGION_CONFIG_OPTIONS,
        async default() {
          if (!exports.warning.silence) {
            console.warn("@aws-sdk - WARN - default STS region of us-east-1 used. See @aws-sdk/credential-providers README and set a region explicitly.");
          }
          return "us-east-1";
        }
      }, { ...config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig });
    }
    exports.warning = {
      silence: false
    };
  }
});

// node_modules/@aws-sdk/region-config-resolver/dist-cjs/index.js
var require_dist_cjs45 = __commonJS({
  "node_modules/@aws-sdk/region-config-resolver/dist-cjs/index.js"(exports) {
    "use strict";
    var stsRegionDefaultResolver2 = require_stsRegionDefaultResolver();
    var configResolver = require_dist_cjs30();
    var getAwsRegionExtensionConfiguration4 = (runtimeConfig) => {
      return {
        setRegion(region) {
          runtimeConfig.region = region;
        },
        region() {
          return runtimeConfig.region;
        }
      };
    };
    var resolveAwsRegionExtensionConfiguration4 = (awsRegionExtensionConfiguration) => {
      return {
        region: awsRegionExtensionConfiguration.region()
      };
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
    exports.getAwsRegionExtensionConfiguration = getAwsRegionExtensionConfiguration4;
    exports.resolveAwsRegionExtensionConfiguration = resolveAwsRegionExtensionConfiguration4;
    Object.keys(stsRegionDefaultResolver2).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return stsRegionDefaultResolver2[k4];
        }
      });
    });
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration, resolveHttpAuthRuntimeConfig;
var init_httpAuthExtensionConfiguration = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthExtensionConfiguration.js"() {
    getHttpAuthExtensionConfiguration = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
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
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeExtensions.js
var import_region_config_resolver, import_protocol_http12, import_smithy_client10, resolveRuntimeExtensions;
var init_runtimeExtensions = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeExtensions.js"() {
    import_region_config_resolver = __toESM(require_dist_cjs45());
    import_protocol_http12 = __toESM(require_dist_cjs2());
    import_smithy_client10 = __toESM(require_dist_cjs26());
    init_httpAuthExtensionConfiguration();
    resolveRuntimeExtensions = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign((0, import_region_config_resolver.getAwsRegionExtensionConfiguration)(runtimeConfig), (0, import_smithy_client10.getDefaultExtensionConfiguration)(runtimeConfig), (0, import_protocol_http12.getHttpHandlerExtensionConfiguration)(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig, (0, import_region_config_resolver.resolveAwsRegionExtensionConfiguration)(extensionConfiguration), (0, import_smithy_client10.resolveDefaultRuntimeConfig)(extensionConfiguration), (0, import_protocol_http12.resolveHttpHandlerRuntimeConfig)(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDCClient.js
var import_middleware_host_header, import_middleware_logger, import_middleware_recursion_detection, import_middleware_user_agent, import_config_resolver2, import_middleware_content_length, import_middleware_endpoint, import_middleware_retry2, import_smithy_client11, SSOOIDCClient;
var init_SSOOIDCClient = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDCClient.js"() {
    import_middleware_host_header = __toESM(require_dist_cjs3());
    import_middleware_logger = __toESM(require_dist_cjs4());
    import_middleware_recursion_detection = __toESM(require_dist_cjs5());
    import_middleware_user_agent = __toESM(require_dist_cjs28());
    import_config_resolver2 = __toESM(require_dist_cjs30());
    init_dist_es();
    init_schema();
    import_middleware_content_length = __toESM(require_dist_cjs31());
    import_middleware_endpoint = __toESM(require_dist_cjs34());
    import_middleware_retry2 = __toESM(require_dist_cjs37());
    import_smithy_client11 = __toESM(require_dist_cjs26());
    init_httpAuthSchemeProvider();
    init_EndpointParameters();
    init_runtimeConfig();
    init_runtimeExtensions();
    SSOOIDCClient = class extends import_smithy_client11.Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = getRuntimeConfig2(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters(_config_0);
        const _config_2 = (0, import_middleware_user_agent.resolveUserAgentConfig)(_config_1);
        const _config_3 = (0, import_middleware_retry2.resolveRetryConfig)(_config_2);
        const _config_4 = (0, import_config_resolver2.resolveRegionConfig)(_config_3);
        const _config_5 = (0, import_middleware_host_header.resolveHostHeaderConfig)(_config_4);
        const _config_6 = (0, import_middleware_endpoint.resolveEndpointConfig)(_config_5);
        const _config_7 = resolveHttpAuthSchemeConfig(_config_6);
        const _config_8 = resolveRuntimeExtensions(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use(getSchemaSerdePlugin(this.config));
        this.middlewareStack.use((0, import_middleware_user_agent.getUserAgentPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_retry2.getRetryPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_content_length.getContentLengthPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_host_header.getHostHeaderPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_logger.getLoggerPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_recursion_detection.getRecursionDetectionPlugin)(this.config));
        this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
          httpAuthSchemeParametersProvider: defaultSSOOIDCHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use(getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/SSOOIDCServiceException.js
var import_smithy_client12, SSOOIDCServiceException;
var init_SSOOIDCServiceException = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/SSOOIDCServiceException.js"() {
    import_smithy_client12 = __toESM(require_dist_cjs26());
    SSOOIDCServiceException = class _SSOOIDCServiceException extends import_smithy_client12.ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _SSOOIDCServiceException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/errors.js
var AccessDeniedException, AuthorizationPendingException, ExpiredTokenException, InternalServerException, InvalidClientException, InvalidGrantException, InvalidRequestException, InvalidScopeException, SlowDownException, UnauthorizedClientException, UnsupportedGrantTypeException;
var init_errors = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/errors.js"() {
    init_SSOOIDCServiceException();
    AccessDeniedException = class _AccessDeniedException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _AccessDeniedException.prototype);
        this.error = opts.error;
        this.reason = opts.reason;
        this.error_description = opts.error_description;
      }
    };
    AuthorizationPendingException = class _AuthorizationPendingException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _AuthorizationPendingException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    ExpiredTokenException = class _ExpiredTokenException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    InternalServerException = class _InternalServerException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _InternalServerException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    InvalidClientException = class _InvalidClientException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _InvalidClientException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    InvalidGrantException = class _InvalidGrantException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _InvalidGrantException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    InvalidRequestException = class _InvalidRequestException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _InvalidRequestException.prototype);
        this.error = opts.error;
        this.reason = opts.reason;
        this.error_description = opts.error_description;
      }
    };
    InvalidScopeException = class _InvalidScopeException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _InvalidScopeException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    SlowDownException = class _SlowDownException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _SlowDownException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    UnauthorizedClientException = class _UnauthorizedClientException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _UnauthorizedClientException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    UnsupportedGrantTypeException = class _UnsupportedGrantTypeException extends SSOOIDCServiceException {
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
        Object.setPrototypeOf(this, _UnsupportedGrantTypeException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/schemas/schemas_0.js
var _ADE, _APE, _AT, _CS, _CT, _CTR, _CTRr, _CV, _ETE, _ICE, _IGE, _IRE, _ISE, _ISEn, _IT, _RT, _SDE, _UCE, _UGTE, _aT, _c, _cI, _cS, _cV, _co, _dC, _e, _eI, _ed, _gT, _h, _hE, _iT, _r, _rT, _rU, _s, _se, _sm, _tT, n0, AccessToken, ClientSecret, CodeVerifier, IdToken, RefreshToken, AccessDeniedException$, AuthorizationPendingException$, CreateTokenRequest$, CreateTokenResponse$, ExpiredTokenException$, InternalServerException$, InvalidClientException$, InvalidGrantException$, InvalidRequestException$, InvalidScopeException$, SlowDownException$, UnauthorizedClientException$, UnsupportedGrantTypeException$, SSOOIDCServiceException$, Scopes, CreateToken$;
var init_schemas_0 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/schemas/schemas_0.js"() {
    init_schema();
    init_errors();
    init_SSOOIDCServiceException();
    _ADE = "AccessDeniedException";
    _APE = "AuthorizationPendingException";
    _AT = "AccessToken";
    _CS = "ClientSecret";
    _CT = "CreateToken";
    _CTR = "CreateTokenRequest";
    _CTRr = "CreateTokenResponse";
    _CV = "CodeVerifier";
    _ETE = "ExpiredTokenException";
    _ICE = "InvalidClientException";
    _IGE = "InvalidGrantException";
    _IRE = "InvalidRequestException";
    _ISE = "InternalServerException";
    _ISEn = "InvalidScopeException";
    _IT = "IdToken";
    _RT = "RefreshToken";
    _SDE = "SlowDownException";
    _UCE = "UnauthorizedClientException";
    _UGTE = "UnsupportedGrantTypeException";
    _aT = "accessToken";
    _c = "client";
    _cI = "clientId";
    _cS = "clientSecret";
    _cV = "codeVerifier";
    _co = "code";
    _dC = "deviceCode";
    _e = "error";
    _eI = "expiresIn";
    _ed = "error_description";
    _gT = "grantType";
    _h = "http";
    _hE = "httpError";
    _iT = "idToken";
    _r = "reason";
    _rT = "refreshToken";
    _rU = "redirectUri";
    _s = "scope";
    _se = "server";
    _sm = "smithy.ts.sdk.synthetic.com.amazonaws.ssooidc";
    _tT = "tokenType";
    n0 = "com.amazonaws.ssooidc";
    AccessToken = [0, n0, _AT, 8, 0];
    ClientSecret = [0, n0, _CS, 8, 0];
    CodeVerifier = [0, n0, _CV, 8, 0];
    IdToken = [0, n0, _IT, 8, 0];
    RefreshToken = [0, n0, _RT, 8, 0];
    AccessDeniedException$ = [
      -3,
      n0,
      _ADE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _r, _ed],
      [0, 0, 0]
    ];
    TypeRegistry.for(n0).registerError(AccessDeniedException$, AccessDeniedException);
    AuthorizationPendingException$ = [
      -3,
      n0,
      _APE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _ed],
      [0, 0]
    ];
    TypeRegistry.for(n0).registerError(AuthorizationPendingException$, AuthorizationPendingException);
    CreateTokenRequest$ = [
      3,
      n0,
      _CTR,
      0,
      [_cI, _cS, _gT, _dC, _co, _rT, _s, _rU, _cV],
      [0, [() => ClientSecret, 0], 0, 0, 0, [() => RefreshToken, 0], 64 | 0, 0, [() => CodeVerifier, 0]]
    ];
    CreateTokenResponse$ = [
      3,
      n0,
      _CTRr,
      0,
      [_aT, _tT, _eI, _rT, _iT],
      [[() => AccessToken, 0], 0, 1, [() => RefreshToken, 0], [() => IdToken, 0]]
    ];
    ExpiredTokenException$ = [-3, n0, _ETE, { [_e]: _c, [_hE]: 400 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(ExpiredTokenException$, ExpiredTokenException);
    InternalServerException$ = [-3, n0, _ISE, { [_e]: _se, [_hE]: 500 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(InternalServerException$, InternalServerException);
    InvalidClientException$ = [-3, n0, _ICE, { [_e]: _c, [_hE]: 401 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(InvalidClientException$, InvalidClientException);
    InvalidGrantException$ = [-3, n0, _IGE, { [_e]: _c, [_hE]: 400 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(InvalidGrantException$, InvalidGrantException);
    InvalidRequestException$ = [
      -3,
      n0,
      _IRE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _r, _ed],
      [0, 0, 0]
    ];
    TypeRegistry.for(n0).registerError(InvalidRequestException$, InvalidRequestException);
    InvalidScopeException$ = [-3, n0, _ISEn, { [_e]: _c, [_hE]: 400 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(InvalidScopeException$, InvalidScopeException);
    SlowDownException$ = [-3, n0, _SDE, { [_e]: _c, [_hE]: 400 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(SlowDownException$, SlowDownException);
    UnauthorizedClientException$ = [
      -3,
      n0,
      _UCE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _ed],
      [0, 0]
    ];
    TypeRegistry.for(n0).registerError(UnauthorizedClientException$, UnauthorizedClientException);
    UnsupportedGrantTypeException$ = [
      -3,
      n0,
      _UGTE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _ed],
      [0, 0]
    ];
    TypeRegistry.for(n0).registerError(UnsupportedGrantTypeException$, UnsupportedGrantTypeException);
    SSOOIDCServiceException$ = [-3, _sm, "SSOOIDCServiceException", 0, [], []];
    TypeRegistry.for(_sm).registerError(SSOOIDCServiceException$, SSOOIDCServiceException);
    Scopes = 64 | 0;
    CreateToken$ = [
      9,
      n0,
      _CT,
      { [_h]: ["POST", "/token", 200] },
      () => CreateTokenRequest$,
      () => CreateTokenResponse$
    ];
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/CreateTokenCommand.js
var import_middleware_endpoint2, import_smithy_client13, CreateTokenCommand;
var init_CreateTokenCommand = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/CreateTokenCommand.js"() {
    import_middleware_endpoint2 = __toESM(require_dist_cjs34());
    import_smithy_client13 = __toESM(require_dist_cjs26());
    init_EndpointParameters();
    init_schemas_0();
    CreateTokenCommand = class extends import_smithy_client13.Command.classBuilder().ep(commonParams).m(function(Command, cs, config, o4) {
      return [(0, import_middleware_endpoint2.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSSOOIDCService", "CreateToken", {}).n("SSOOIDCClient", "CreateTokenCommand").sc(CreateToken$).build() {
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDC.js
var import_smithy_client14, commands, SSOOIDC;
var init_SSOOIDC = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDC.js"() {
    import_smithy_client14 = __toESM(require_dist_cjs26());
    init_CreateTokenCommand();
    init_SSOOIDCClient();
    commands = {
      CreateTokenCommand
    };
    SSOOIDC = class extends SSOOIDCClient {
    };
    (0, import_smithy_client14.createAggregatedClient)(commands, SSOOIDC);
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/index.js
var init_commands = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/index.js"() {
    init_CreateTokenCommand();
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/enums.js
var AccessDeniedExceptionReason, InvalidRequestExceptionReason;
var init_enums = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/enums.js"() {
    AccessDeniedExceptionReason = {
      KMS_ACCESS_DENIED: "KMS_AccessDeniedException"
    };
    InvalidRequestExceptionReason = {
      KMS_DISABLED_KEY: "KMS_DisabledException",
      KMS_INVALID_KEY_USAGE: "KMS_InvalidKeyUsageException",
      KMS_INVALID_STATE: "KMS_InvalidStateException",
      KMS_KEY_NOT_FOUND: "KMS_NotFoundException"
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/models_0.js
var init_models_0 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/models_0.js"() {
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/index.js
var sso_oidc_exports = {};
__export(sso_oidc_exports, {
  $Command: () => import_smithy_client13.Command,
  AccessDeniedException: () => AccessDeniedException,
  AccessDeniedException$: () => AccessDeniedException$,
  AccessDeniedExceptionReason: () => AccessDeniedExceptionReason,
  AuthorizationPendingException: () => AuthorizationPendingException,
  AuthorizationPendingException$: () => AuthorizationPendingException$,
  CreateToken$: () => CreateToken$,
  CreateTokenCommand: () => CreateTokenCommand,
  CreateTokenRequest$: () => CreateTokenRequest$,
  CreateTokenResponse$: () => CreateTokenResponse$,
  ExpiredTokenException: () => ExpiredTokenException,
  ExpiredTokenException$: () => ExpiredTokenException$,
  InternalServerException: () => InternalServerException,
  InternalServerException$: () => InternalServerException$,
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
  __Client: () => import_smithy_client11.Client
});
var init_sso_oidc = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/index.js"() {
    init_SSOOIDCClient();
    init_SSOOIDC();
    init_commands();
    init_schemas_0();
    init_enums();
    init_errors();
    init_models_0();
    init_SSOOIDCServiceException();
  }
});

// node_modules/@aws-sdk/token-providers/dist-cjs/index.js
var require_dist_cjs46 = __commonJS({
  "node_modules/@aws-sdk/token-providers/dist-cjs/index.js"(exports) {
    "use strict";
    var client2 = (init_client(), __toCommonJS(client_exports));
    var httpAuthSchemes = (init_httpAuthSchemes2(), __toCommonJS(httpAuthSchemes_exports));
    var propertyProvider = require_dist_cjs23();
    var sharedIniFileLoader = require_dist_cjs32();
    var fs = __require("fs");
    var fromEnvSigningName = ({ logger: logger2, signingName } = {}) => async () => {
      logger2?.debug?.("@aws-sdk/token-providers - fromEnvSigningName");
      if (!signingName) {
        throw new propertyProvider.TokenProviderError("Please pass 'signingName' to compute environment variable key", { logger: logger2 });
      }
      const bearerTokenKey = httpAuthSchemes.getBearerTokenEnvKey(signingName);
      if (!(bearerTokenKey in process.env)) {
        throw new propertyProvider.TokenProviderError(`Token not present in '${bearerTokenKey}' environment variable`, { logger: logger2 });
      }
      const token = { token: process.env[bearerTokenKey] };
      client2.setTokenFeature(token, "BEARER_SERVICE_ENV_VARS", "3");
      return token;
    };
    var EXPIRE_WINDOW_MS = 5 * 60 * 1e3;
    var REFRESH_MESSAGE = `To refresh this SSO session run 'aws sso login' with the corresponding profile.`;
    var getSsoOidcClient = async (ssoRegion, init = {}, callerClientConfig) => {
      const { SSOOIDCClient: SSOOIDCClient2 } = await Promise.resolve().then(() => (init_sso_oidc(), sso_oidc_exports));
      const coalesce = (prop) => init.clientConfig?.[prop] ?? init.parentClientConfig?.[prop] ?? callerClientConfig?.[prop];
      const ssoOidcClient = new SSOOIDCClient2(Object.assign({}, init.clientConfig ?? {}, {
        region: ssoRegion ?? init.clientConfig?.region,
        logger: coalesce("logger"),
        userAgentAppId: coalesce("userAgentAppId")
      }));
      return ssoOidcClient;
    };
    var getNewSsoOidcToken = async (ssoToken, ssoRegion, init = {}, callerClientConfig) => {
      const { CreateTokenCommand: CreateTokenCommand2 } = await Promise.resolve().then(() => (init_sso_oidc(), sso_oidc_exports));
      const ssoOidcClient = await getSsoOidcClient(ssoRegion, init, callerClientConfig);
      return ssoOidcClient.send(new CreateTokenCommand2({
        clientId: ssoToken.clientId,
        clientSecret: ssoToken.clientSecret,
        refreshToken: ssoToken.refreshToken,
        grantType: "refresh_token"
      }));
    };
    var validateTokenExpiry = (token) => {
      if (token.expiration && token.expiration.getTime() < Date.now()) {
        throw new propertyProvider.TokenProviderError(`Token is expired. ${REFRESH_MESSAGE}`, false);
      }
    };
    var validateTokenKey = (key, value, forRefresh = false) => {
      if (typeof value === "undefined") {
        throw new propertyProvider.TokenProviderError(`Value not present for '${key}' in SSO Token${forRefresh ? ". Cannot refresh" : ""}. ${REFRESH_MESSAGE}`, false);
      }
    };
    var { writeFile } = fs.promises;
    var writeSSOTokenToFile = (id, ssoToken) => {
      const tokenFilepath = sharedIniFileLoader.getSSOTokenFilepath(id);
      const tokenString = JSON.stringify(ssoToken, null, 2);
      return writeFile(tokenFilepath, tokenString);
    };
    var lastRefreshAttemptTime = /* @__PURE__ */ new Date(0);
    var fromSso = (init = {}) => async ({ callerClientConfig } = {}) => {
      init.logger?.debug("@aws-sdk/token-providers - fromSso");
      const profiles = await sharedIniFileLoader.parseKnownFiles(init);
      const profileName = sharedIniFileLoader.getProfileName({
        profile: init.profile ?? callerClientConfig?.profile
      });
      const profile = profiles[profileName];
      if (!profile) {
        throw new propertyProvider.TokenProviderError(`Profile '${profileName}' could not be found in shared credentials file.`, false);
      } else if (!profile["sso_session"]) {
        throw new propertyProvider.TokenProviderError(`Profile '${profileName}' is missing required property 'sso_session'.`);
      }
      const ssoSessionName = profile["sso_session"];
      const ssoSessions = await sharedIniFileLoader.loadSsoSessionData(init);
      const ssoSession = ssoSessions[ssoSessionName];
      if (!ssoSession) {
        throw new propertyProvider.TokenProviderError(`Sso session '${ssoSessionName}' could not be found in shared credentials file.`, false);
      }
      for (const ssoSessionRequiredKey of ["sso_start_url", "sso_region"]) {
        if (!ssoSession[ssoSessionRequiredKey]) {
          throw new propertyProvider.TokenProviderError(`Sso session '${ssoSessionName}' is missing required property '${ssoSessionRequiredKey}'.`, false);
        }
      }
      ssoSession["sso_start_url"];
      const ssoRegion = ssoSession["sso_region"];
      let ssoToken;
      try {
        ssoToken = await sharedIniFileLoader.getSSOTokenFromFile(ssoSessionName);
      } catch (e4) {
        throw new propertyProvider.TokenProviderError(`The SSO session token associated with profile=${profileName} was not found or is invalid. ${REFRESH_MESSAGE}`, false);
      }
      validateTokenKey("accessToken", ssoToken.accessToken);
      validateTokenKey("expiresAt", ssoToken.expiresAt);
      const { accessToken, expiresAt } = ssoToken;
      const existingToken = { token: accessToken, expiration: new Date(expiresAt) };
      if (existingToken.expiration.getTime() - Date.now() > EXPIRE_WINDOW_MS) {
        return existingToken;
      }
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
        } catch (error2) {
        }
        return {
          token: newSsoOidcToken.accessToken,
          expiration: newTokenExpiration
        };
      } catch (error2) {
        validateTokenExpiry(existingToken);
        return existingToken;
      }
    };
    var fromStatic = ({ token, logger: logger2 }) => async () => {
      logger2?.debug("@aws-sdk/token-providers - fromStatic");
      if (!token || !token.token) {
        throw new propertyProvider.TokenProviderError(`Please pass a valid token to fromStatic`, false);
      }
      return token;
    };
    var nodeProvider = (init = {}) => propertyProvider.memoize(propertyProvider.chain(fromSso(init), async () => {
      throw new propertyProvider.TokenProviderError("Could not load token from any providers", false);
    }), (token) => token.expiration !== void 0 && token.expiration.getTime() - Date.now() < 3e5, (token) => token.expiration !== void 0);
    exports.fromEnvSigningName = fromEnvSigningName;
    exports.fromSso = fromSso;
    exports.fromStatic = fromStatic;
    exports.nodeProvider = nodeProvider;
  }
});

// node_modules/@aws-sdk/client-sso/dist-cjs/auth/httpAuthSchemeProvider.js
var require_httpAuthSchemeProvider2 = __commonJS({
  "node_modules/@aws-sdk/client-sso/dist-cjs/auth/httpAuthSchemeProvider.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.resolveHttpAuthSchemeConfig = exports.defaultSSOHttpAuthSchemeProvider = exports.defaultSSOHttpAuthSchemeParametersProvider = void 0;
    var core_1 = (init_dist_es2(), __toCommonJS(dist_es_exports2));
    var util_middleware_1 = require_dist_cjs6();
    var defaultSSOHttpAuthSchemeParametersProvider = async (config, context, input) => {
      return {
        operation: (0, util_middleware_1.getSmithyContext)(context).operation,
        region: await (0, util_middleware_1.normalizeProvider)(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    exports.defaultSSOHttpAuthSchemeParametersProvider = defaultSSOHttpAuthSchemeParametersProvider;
    function createAwsAuthSigv4HttpAuthOption4(authParameters) {
      return {
        schemeId: "aws.auth#sigv4",
        signingProperties: {
          name: "awsssoportal",
          region: authParameters.region
        },
        propertiesExtractor: (config, context) => ({
          signingProperties: {
            config,
            context
          }
        })
      };
    }
    function createSmithyApiNoAuthHttpAuthOption4(authParameters) {
      return {
        schemeId: "smithy.api#noAuth"
      };
    }
    var defaultSSOHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "GetRoleCredentials":
          {
            options.push(createSmithyApiNoAuthHttpAuthOption4(authParameters));
            break;
          }
          ;
        case "ListAccountRoles":
          {
            options.push(createSmithyApiNoAuthHttpAuthOption4(authParameters));
            break;
          }
          ;
        case "ListAccounts":
          {
            options.push(createSmithyApiNoAuthHttpAuthOption4(authParameters));
            break;
          }
          ;
        case "Logout":
          {
            options.push(createSmithyApiNoAuthHttpAuthOption4(authParameters));
            break;
          }
          ;
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption4(authParameters));
        }
      }
      return options;
    };
    exports.defaultSSOHttpAuthSchemeProvider = defaultSSOHttpAuthSchemeProvider;
    var resolveHttpAuthSchemeConfig4 = (config) => {
      const config_0 = (0, core_1.resolveAwsSdkSigV4Config)(config);
      return Object.assign(config_0, {
        authSchemePreference: (0, util_middleware_1.normalizeProvider)(config.authSchemePreference ?? [])
      });
    };
    exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig4;
  }
});

// node_modules/@aws-sdk/client-sso/package.json
var require_package2 = __commonJS({
  "node_modules/@aws-sdk/client-sso/package.json"(exports, module) {
    module.exports = {
      name: "@aws-sdk/client-sso",
      description: "AWS SDK for JavaScript Sso Client for Node.js, Browser and React Native",
      version: "3.958.0",
      scripts: {
        build: "concurrently 'yarn:build:types' 'yarn:build:es' && yarn build:cjs",
        "build:cjs": "node ../../scripts/compilation/inline client-sso",
        "build:es": "tsc -p tsconfig.es.json",
        "build:include:deps": 'yarn g:turbo run build -F="$npm_package_name"',
        "build:types": "tsc -p tsconfig.types.json",
        "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
        clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
        "extract:docs": "api-extractor run --local",
        "generate:client": "node ../../scripts/generate-clients/single-service --solo sso",
        "test:index": "tsc --noEmit ./test/index-types.ts && node ./test/index-objects.spec.mjs"
      },
      main: "./dist-cjs/index.js",
      types: "./dist-types/index.d.ts",
      module: "./dist-es/index.js",
      sideEffects: false,
      dependencies: {
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
        tslib: "^2.6.2"
      },
      devDependencies: {
        "@tsconfig/node18": "18.2.4",
        "@types/node": "^18.19.69",
        concurrently: "7.0.0",
        "downlevel-dts": "0.10.1",
        rimraf: "3.0.2",
        typescript: "~5.8.3"
      },
      engines: {
        node: ">=18.0.0"
      },
      typesVersions: {
        "<4.0": {
          "dist-types/*": [
            "dist-types/ts3.4/*"
          ]
        }
      },
      files: [
        "dist-*/**"
      ],
      author: {
        name: "AWS SDK for JavaScript Team",
        url: "https://aws.amazon.com/javascript/"
      },
      license: "Apache-2.0",
      browser: {
        "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser"
      },
      "react-native": {
        "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native"
      },
      homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sso",
      repository: {
        type: "git",
        url: "https://github.com/aws/aws-sdk-js-v3.git",
        directory: "clients/client-sso"
      }
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-cjs/endpoint/ruleset.js
var require_ruleset = __commonJS({
  "node_modules/@aws-sdk/client-sso/dist-cjs/endpoint/ruleset.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.ruleSet = void 0;
    var u4 = "required";
    var v4 = "fn";
    var w4 = "argv";
    var x4 = "ref";
    var a4 = true;
    var b4 = "isSet";
    var c4 = "booleanEquals";
    var d4 = "error";
    var e4 = "endpoint";
    var f4 = "tree";
    var g4 = "PartitionResult";
    var h4 = "getAttr";
    var i4 = { [u4]: false, "type": "string" };
    var j4 = { [u4]: true, "default": false, "type": "boolean" };
    var k4 = { [x4]: "Endpoint" };
    var l4 = { [v4]: c4, [w4]: [{ [x4]: "UseFIPS" }, true] };
    var m4 = { [v4]: c4, [w4]: [{ [x4]: "UseDualStack" }, true] };
    var n4 = {};
    var o4 = { [v4]: h4, [w4]: [{ [x4]: g4 }, "supportsFIPS"] };
    var p4 = { [x4]: g4 };
    var q4 = { [v4]: c4, [w4]: [true, { [v4]: h4, [w4]: [p4, "supportsDualStack"] }] };
    var r4 = [l4];
    var s4 = [m4];
    var t4 = [{ [x4]: "Region" }];
    var _data4 = { version: "1.0", parameters: { Region: i4, UseDualStack: j4, UseFIPS: j4, Endpoint: i4 }, rules: [{ conditions: [{ [v4]: b4, [w4]: [k4] }], rules: [{ conditions: r4, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d4 }, { conditions: s4, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d4 }, { endpoint: { url: k4, properties: n4, headers: n4 }, type: e4 }], type: f4 }, { conditions: [{ [v4]: b4, [w4]: t4 }], rules: [{ conditions: [{ [v4]: "aws.partition", [w4]: t4, assign: g4 }], rules: [{ conditions: [l4, m4], rules: [{ conditions: [{ [v4]: c4, [w4]: [a4, o4] }, q4], rules: [{ endpoint: { url: "https://portal.sso-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n4, headers: n4 }, type: e4 }], type: f4 }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d4 }], type: f4 }, { conditions: r4, rules: [{ conditions: [{ [v4]: c4, [w4]: [o4, a4] }], rules: [{ conditions: [{ [v4]: "stringEquals", [w4]: [{ [v4]: h4, [w4]: [p4, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://portal.sso.{Region}.amazonaws.com", properties: n4, headers: n4 }, type: e4 }, { endpoint: { url: "https://portal.sso-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n4, headers: n4 }, type: e4 }], type: f4 }, { error: "FIPS is enabled but this partition does not support FIPS", type: d4 }], type: f4 }, { conditions: s4, rules: [{ conditions: [q4], rules: [{ endpoint: { url: "https://portal.sso.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n4, headers: n4 }, type: e4 }], type: f4 }, { error: "DualStack is enabled but this partition does not support DualStack", type: d4 }], type: f4 }, { endpoint: { url: "https://portal.sso.{Region}.{PartitionResult#dnsSuffix}", properties: n4, headers: n4 }, type: e4 }], type: f4 }], type: f4 }, { error: "Invalid Configuration: Missing Region", type: d4 }] };
    exports.ruleSet = _data4;
  }
});

// node_modules/@aws-sdk/client-sso/dist-cjs/endpoint/endpointResolver.js
var require_endpointResolver = __commonJS({
  "node_modules/@aws-sdk/client-sso/dist-cjs/endpoint/endpointResolver.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.defaultEndpointResolver = void 0;
    var util_endpoints_1 = require_dist_cjs22();
    var util_endpoints_2 = require_dist_cjs19();
    var ruleset_1 = require_ruleset();
    var cache4 = new util_endpoints_2.EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
    });
    var defaultEndpointResolver4 = (endpointParams, context = {}) => {
      return cache4.get(endpointParams, () => (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
        endpointParams,
        logger: context.logger
      }));
    };
    exports.defaultEndpointResolver = defaultEndpointResolver4;
    util_endpoints_2.customEndpointFunctions.aws = util_endpoints_1.awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/client-sso/dist-cjs/runtimeConfig.shared.js
var require_runtimeConfig_shared = __commonJS({
  "node_modules/@aws-sdk/client-sso/dist-cjs/runtimeConfig.shared.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getRuntimeConfig = void 0;
    var core_1 = (init_dist_es2(), __toCommonJS(dist_es_exports2));
    var protocols_1 = (init_protocols2(), __toCommonJS(protocols_exports2));
    var core_2 = (init_dist_es(), __toCommonJS(dist_es_exports));
    var smithy_client_1 = require_dist_cjs26();
    var url_parser_1 = require_dist_cjs21();
    var util_base64_1 = require_dist_cjs11();
    var util_utf8_1 = require_dist_cjs10();
    var httpAuthSchemeProvider_1 = require_httpAuthSchemeProvider2();
    var endpointResolver_1 = require_endpointResolver();
    var getRuntimeConfig7 = (config) => {
      return {
        apiVersion: "2019-06-10",
        base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
        base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? endpointResolver_1.defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? httpAuthSchemeProvider_1.defaultSSOHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new core_1.AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new core_2.NoAuthSigner()
          }
        ],
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
    exports.getRuntimeConfig = getRuntimeConfig7;
  }
});

// node_modules/@aws-sdk/client-sso/dist-cjs/runtimeConfig.js
var require_runtimeConfig = __commonJS({
  "node_modules/@aws-sdk/client-sso/dist-cjs/runtimeConfig.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getRuntimeConfig = void 0;
    var tslib_1 = (init_tslib_es6(), __toCommonJS(tslib_es6_exports));
    var package_json_1 = tslib_1.__importDefault(require_package2());
    var core_1 = (init_dist_es2(), __toCommonJS(dist_es_exports2));
    var util_user_agent_node_1 = require_dist_cjs41();
    var config_resolver_1 = require_dist_cjs30();
    var hash_node_1 = require_dist_cjs42();
    var middleware_retry_1 = require_dist_cjs37();
    var node_config_provider_1 = require_dist_cjs33();
    var node_http_handler_1 = require_dist_cjs14();
    var smithy_client_1 = require_dist_cjs26();
    var util_body_length_node_1 = require_dist_cjs43();
    var util_defaults_mode_node_1 = require_dist_cjs44();
    var util_retry_1 = require_dist_cjs36();
    var runtimeConfig_shared_1 = require_runtimeConfig_shared();
    var getRuntimeConfig7 = (config) => {
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
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, util_user_agent_node_1.createDefaultUserAgentProvider)({ serviceId: clientSharedValues.serviceId, clientVersion: package_json_1.default.version }),
        maxAttempts: config?.maxAttempts ?? (0, node_config_provider_1.loadConfig)(middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_REGION_CONFIG_OPTIONS, { ...config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
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
    exports.getRuntimeConfig = getRuntimeConfig7;
  }
});

// node_modules/@aws-sdk/client-sso/dist-cjs/index.js
var require_dist_cjs47 = __commonJS({
  "node_modules/@aws-sdk/client-sso/dist-cjs/index.js"(exports) {
    "use strict";
    var middlewareHostHeader = require_dist_cjs3();
    var middlewareLogger = require_dist_cjs4();
    var middlewareRecursionDetection = require_dist_cjs5();
    var middlewareUserAgent = require_dist_cjs28();
    var configResolver = require_dist_cjs30();
    var core = (init_dist_es(), __toCommonJS(dist_es_exports));
    var schema = (init_schema(), __toCommonJS(schema_exports));
    var middlewareContentLength = require_dist_cjs31();
    var middlewareEndpoint = require_dist_cjs34();
    var middlewareRetry = require_dist_cjs37();
    var smithyClient = require_dist_cjs26();
    var httpAuthSchemeProvider = require_httpAuthSchemeProvider2();
    var runtimeConfig = require_runtimeConfig();
    var regionConfigResolver = require_dist_cjs45();
    var protocolHttp = require_dist_cjs2();
    var resolveClientEndpointParameters4 = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "awsssoportal"
      });
    };
    var commonParams4 = {
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
    var getHttpAuthExtensionConfiguration4 = (runtimeConfig2) => {
      const _httpAuthSchemes = runtimeConfig2.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig2.httpAuthSchemeProvider;
      let _credentials = runtimeConfig2.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
        },
        httpAuthSchemes() {
          return _httpAuthSchemes;
        },
        setHttpAuthSchemeProvider(httpAuthSchemeProvider2) {
          _httpAuthSchemeProvider = httpAuthSchemeProvider2;
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
    var resolveHttpAuthRuntimeConfig4 = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials()
      };
    };
    var resolveRuntimeExtensions4 = (runtimeConfig2, extensions) => {
      const extensionConfiguration = Object.assign(regionConfigResolver.getAwsRegionExtensionConfiguration(runtimeConfig2), smithyClient.getDefaultExtensionConfiguration(runtimeConfig2), protocolHttp.getHttpHandlerExtensionConfiguration(runtimeConfig2), getHttpAuthExtensionConfiguration4(runtimeConfig2));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig2, regionConfigResolver.resolveAwsRegionExtensionConfiguration(extensionConfiguration), smithyClient.resolveDefaultRuntimeConfig(extensionConfiguration), protocolHttp.resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig4(extensionConfiguration));
    };
    var SSOClient = class extends smithyClient.Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = runtimeConfig.getRuntimeConfig(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters4(_config_0);
        const _config_2 = middlewareUserAgent.resolveUserAgentConfig(_config_1);
        const _config_3 = middlewareRetry.resolveRetryConfig(_config_2);
        const _config_4 = configResolver.resolveRegionConfig(_config_3);
        const _config_5 = middlewareHostHeader.resolveHostHeaderConfig(_config_4);
        const _config_6 = middlewareEndpoint.resolveEndpointConfig(_config_5);
        const _config_7 = httpAuthSchemeProvider.resolveHttpAuthSchemeConfig(_config_6);
        const _config_8 = resolveRuntimeExtensions4(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use(schema.getSchemaSerdePlugin(this.config));
        this.middlewareStack.use(middlewareUserAgent.getUserAgentPlugin(this.config));
        this.middlewareStack.use(middlewareRetry.getRetryPlugin(this.config));
        this.middlewareStack.use(middlewareContentLength.getContentLengthPlugin(this.config));
        this.middlewareStack.use(middlewareHostHeader.getHostHeaderPlugin(this.config));
        this.middlewareStack.use(middlewareLogger.getLoggerPlugin(this.config));
        this.middlewareStack.use(middlewareRecursionDetection.getRecursionDetectionPlugin(this.config));
        this.middlewareStack.use(core.getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
          httpAuthSchemeParametersProvider: httpAuthSchemeProvider.defaultSSOHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new core.DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use(core.getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
    var SSOServiceException = class _SSOServiceException extends smithyClient.ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _SSOServiceException.prototype);
      }
    };
    var InvalidRequestException2 = class _InvalidRequestException extends SSOServiceException {
      name = "InvalidRequestException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "InvalidRequestException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidRequestException.prototype);
      }
    };
    var ResourceNotFoundException = class _ResourceNotFoundException extends SSOServiceException {
      name = "ResourceNotFoundException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "ResourceNotFoundException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ResourceNotFoundException.prototype);
      }
    };
    var TooManyRequestsException = class _TooManyRequestsException extends SSOServiceException {
      name = "TooManyRequestsException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "TooManyRequestsException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _TooManyRequestsException.prototype);
      }
    };
    var UnauthorizedException = class _UnauthorizedException extends SSOServiceException {
      name = "UnauthorizedException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "UnauthorizedException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _UnauthorizedException.prototype);
      }
    };
    var _AI = "AccountInfo";
    var _ALT = "AccountListType";
    var _ATT = "AccessTokenType";
    var _GRC = "GetRoleCredentials";
    var _GRCR = "GetRoleCredentialsRequest";
    var _GRCRe = "GetRoleCredentialsResponse";
    var _IRE2 = "InvalidRequestException";
    var _L = "Logout";
    var _LA = "ListAccounts";
    var _LAR = "ListAccountsRequest";
    var _LARR = "ListAccountRolesRequest";
    var _LARRi = "ListAccountRolesResponse";
    var _LARi = "ListAccountsResponse";
    var _LARis = "ListAccountRoles";
    var _LR = "LogoutRequest";
    var _RC = "RoleCredentials";
    var _RI = "RoleInfo";
    var _RLT = "RoleListType";
    var _RNFE = "ResourceNotFoundException";
    var _SAKT = "SecretAccessKeyType";
    var _STT = "SessionTokenType";
    var _TMRE2 = "TooManyRequestsException";
    var _UE = "UnauthorizedException";
    var _aI = "accountId";
    var _aKI2 = "accessKeyId";
    var _aL = "accountList";
    var _aN = "accountName";
    var _aT3 = "accessToken";
    var _ai = "account_id";
    var _c4 = "client";
    var _e4 = "error";
    var _eA = "emailAddress";
    var _ex = "expiration";
    var _h3 = "http";
    var _hE4 = "httpError";
    var _hH = "httpHeader";
    var _hQ = "httpQuery";
    var _m3 = "message";
    var _mR = "maxResults";
    var _mr = "max_result";
    var _nT = "nextToken";
    var _nt = "next_token";
    var _rC = "roleCredentials";
    var _rL = "roleList";
    var _rN = "roleName";
    var _rn = "role_name";
    var _s4 = "smithy.ts.sdk.synthetic.com.amazonaws.sso";
    var _sAK2 = "secretAccessKey";
    var _sT2 = "sessionToken";
    var _xasbt = "x-amz-sso_bearer_token";
    var n04 = "com.amazonaws.sso";
    var AccessTokenType = [0, n04, _ATT, 8, 0];
    var SecretAccessKeyType = [0, n04, _SAKT, 8, 0];
    var SessionTokenType = [0, n04, _STT, 8, 0];
    var AccountInfo$ = [
      3,
      n04,
      _AI,
      0,
      [_aI, _aN, _eA],
      [0, 0, 0]
    ];
    var GetRoleCredentialsRequest$ = [
      3,
      n04,
      _GRCR,
      0,
      [_rN, _aI, _aT3],
      [[0, { [_hQ]: _rn }], [0, { [_hQ]: _ai }], [() => AccessTokenType, { [_hH]: _xasbt }]]
    ];
    var GetRoleCredentialsResponse$ = [
      3,
      n04,
      _GRCRe,
      0,
      [_rC],
      [[() => RoleCredentials$, 0]]
    ];
    var InvalidRequestException$2 = [
      -3,
      n04,
      _IRE2,
      { [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(InvalidRequestException$2, InvalidRequestException2);
    var ListAccountRolesRequest$ = [
      3,
      n04,
      _LARR,
      0,
      [_nT, _mR, _aT3, _aI],
      [[0, { [_hQ]: _nt }], [1, { [_hQ]: _mr }], [() => AccessTokenType, { [_hH]: _xasbt }], [0, { [_hQ]: _ai }]]
    ];
    var ListAccountRolesResponse$ = [
      3,
      n04,
      _LARRi,
      0,
      [_nT, _rL],
      [0, () => RoleListType]
    ];
    var ListAccountsRequest$ = [
      3,
      n04,
      _LAR,
      0,
      [_nT, _mR, _aT3],
      [[0, { [_hQ]: _nt }], [1, { [_hQ]: _mr }], [() => AccessTokenType, { [_hH]: _xasbt }]]
    ];
    var ListAccountsResponse$ = [
      3,
      n04,
      _LARi,
      0,
      [_nT, _aL],
      [0, () => AccountListType]
    ];
    var LogoutRequest$ = [
      3,
      n04,
      _LR,
      0,
      [_aT3],
      [[() => AccessTokenType, { [_hH]: _xasbt }]]
    ];
    var ResourceNotFoundException$ = [
      -3,
      n04,
      _RNFE,
      { [_e4]: _c4, [_hE4]: 404 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(ResourceNotFoundException$, ResourceNotFoundException);
    var RoleCredentials$ = [
      3,
      n04,
      _RC,
      0,
      [_aKI2, _sAK2, _sT2, _ex],
      [0, [() => SecretAccessKeyType, 0], [() => SessionTokenType, 0], 1]
    ];
    var RoleInfo$ = [
      3,
      n04,
      _RI,
      0,
      [_rN, _aI],
      [0, 0]
    ];
    var TooManyRequestsException$ = [
      -3,
      n04,
      _TMRE2,
      { [_e4]: _c4, [_hE4]: 429 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(TooManyRequestsException$, TooManyRequestsException);
    var UnauthorizedException$ = [
      -3,
      n04,
      _UE,
      { [_e4]: _c4, [_hE4]: 401 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(UnauthorizedException$, UnauthorizedException);
    var __Unit = "unit";
    var SSOServiceException$ = [-3, _s4, "SSOServiceException", 0, [], []];
    schema.TypeRegistry.for(_s4).registerError(SSOServiceException$, SSOServiceException);
    var AccountListType = [
      1,
      n04,
      _ALT,
      0,
      () => AccountInfo$
    ];
    var RoleListType = [
      1,
      n04,
      _RLT,
      0,
      () => RoleInfo$
    ];
    var GetRoleCredentials$ = [
      9,
      n04,
      _GRC,
      { [_h3]: ["GET", "/federation/credentials", 200] },
      () => GetRoleCredentialsRequest$,
      () => GetRoleCredentialsResponse$
    ];
    var ListAccountRoles$ = [
      9,
      n04,
      _LARis,
      { [_h3]: ["GET", "/assignment/roles", 200] },
      () => ListAccountRolesRequest$,
      () => ListAccountRolesResponse$
    ];
    var ListAccounts$ = [
      9,
      n04,
      _LA,
      { [_h3]: ["GET", "/assignment/accounts", 200] },
      () => ListAccountsRequest$,
      () => ListAccountsResponse$
    ];
    var Logout$ = [
      9,
      n04,
      _L,
      { [_h3]: ["POST", "/logout", 200] },
      () => LogoutRequest$,
      () => __Unit
    ];
    var GetRoleCredentialsCommand = class extends smithyClient.Command.classBuilder().ep(commonParams4).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("SWBPortalService", "GetRoleCredentials", {}).n("SSOClient", "GetRoleCredentialsCommand").sc(GetRoleCredentials$).build() {
    };
    var ListAccountRolesCommand = class extends smithyClient.Command.classBuilder().ep(commonParams4).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("SWBPortalService", "ListAccountRoles", {}).n("SSOClient", "ListAccountRolesCommand").sc(ListAccountRoles$).build() {
    };
    var ListAccountsCommand = class extends smithyClient.Command.classBuilder().ep(commonParams4).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("SWBPortalService", "ListAccounts", {}).n("SSOClient", "ListAccountsCommand").sc(ListAccounts$).build() {
    };
    var LogoutCommand = class extends smithyClient.Command.classBuilder().ep(commonParams4).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("SWBPortalService", "Logout", {}).n("SSOClient", "LogoutCommand").sc(Logout$).build() {
    };
    var commands4 = {
      GetRoleCredentialsCommand,
      ListAccountRolesCommand,
      ListAccountsCommand,
      LogoutCommand
    };
    var SSO = class extends SSOClient {
    };
    smithyClient.createAggregatedClient(commands4, SSO);
    var paginateListAccountRoles = core.createPaginator(SSOClient, ListAccountRolesCommand, "nextToken", "nextToken", "maxResults");
    var paginateListAccounts = core.createPaginator(SSOClient, ListAccountsCommand, "nextToken", "nextToken", "maxResults");
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
    exports.InvalidRequestException = InvalidRequestException2;
    exports.InvalidRequestException$ = InvalidRequestException$2;
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
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-cjs/loadSso-CVy8iqsZ.js
var require_loadSso_CVy8iqsZ = __commonJS({
  "node_modules/@aws-sdk/credential-provider-sso/dist-cjs/loadSso-CVy8iqsZ.js"(exports) {
    "use strict";
    var clientSso = require_dist_cjs47();
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
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-cjs/index.js
var require_dist_cjs48 = __commonJS({
  "node_modules/@aws-sdk/credential-provider-sso/dist-cjs/index.js"(exports) {
    "use strict";
    var propertyProvider = require_dist_cjs23();
    var sharedIniFileLoader = require_dist_cjs32();
    var client2 = (init_client(), __toCommonJS(client_exports));
    var tokenProviders = require_dist_cjs46();
    var isSsoProfile = (arg) => arg && (typeof arg.sso_start_url === "string" || typeof arg.sso_account_id === "string" || typeof arg.sso_session === "string" || typeof arg.sso_region === "string" || typeof arg.sso_role_name === "string");
    var SHOULD_FAIL_CREDENTIAL_CHAIN = false;
    var resolveSSOCredentials = async ({ ssoStartUrl, ssoSession, ssoAccountId, ssoRegion, ssoRoleName, ssoClient, clientConfig, parentClientConfig, callerClientConfig, profile, filepath, configFilepath, ignoreCache, logger: logger2 }) => {
      let token;
      const refreshMessage = `To refresh this SSO session run aws sso login with the corresponding profile.`;
      if (ssoSession) {
        try {
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
        } catch (e4) {
          throw new propertyProvider.CredentialsProviderError(e4.message, {
            tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
            logger: logger2
          });
        }
      } else {
        try {
          token = await sharedIniFileLoader.getSSOTokenFromFile(ssoStartUrl);
        } catch (e4) {
          throw new propertyProvider.CredentialsProviderError(`The SSO session associated with this profile is invalid. ${refreshMessage}`, {
            tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
            logger: logger2
          });
        }
      }
      if (new Date(token.expiresAt).getTime() - Date.now() <= 0) {
        throw new propertyProvider.CredentialsProviderError(`The SSO session associated with this profile has expired. ${refreshMessage}`, {
          tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
          logger: logger2
        });
      }
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
      } catch (e4) {
        throw new propertyProvider.CredentialsProviderError(e4, {
          tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
          logger: logger2
        });
      }
      const { roleCredentials: { accessKeyId, secretAccessKey, sessionToken, expiration, credentialScope, accountId } = {} } = ssoResp;
      if (!accessKeyId || !secretAccessKey || !sessionToken || !expiration) {
        throw new propertyProvider.CredentialsProviderError("SSO returns an invalid temporary credential.", {
          tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
          logger: logger2
        });
      }
      const credentials = {
        accessKeyId,
        secretAccessKey,
        sessionToken,
        expiration: new Date(expiration),
        ...credentialScope && { credentialScope },
        ...accountId && { accountId }
      };
      if (ssoSession) {
        client2.setCredentialFeature(credentials, "CREDENTIALS_SSO", "s");
      } else {
        client2.setCredentialFeature(credentials, "CREDENTIALS_SSO_LEGACY", "u");
      }
      return credentials;
    };
    var validateSsoProfile = (profile, logger2) => {
      const { sso_start_url, sso_account_id, sso_region, sso_role_name } = profile;
      if (!sso_start_url || !sso_account_id || !sso_region || !sso_role_name) {
        throw new propertyProvider.CredentialsProviderError(`Profile is configured with invalid SSO credentials. Required parameters "sso_account_id", "sso_region", "sso_role_name", "sso_start_url". Got ${Object.keys(profile).join(", ")}
Reference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html`, { tryNextLink: false, logger: logger2 });
      }
      return profile;
    };
    var fromSSO = (init = {}) => async ({ callerClientConfig } = {}) => {
      init.logger?.debug("@aws-sdk/credential-provider-sso - fromSSO");
      const { ssoStartUrl, ssoAccountId, ssoRegion, ssoRoleName, ssoSession } = init;
      const { ssoClient } = init;
      const profileName = sharedIniFileLoader.getProfileName({
        profile: init.profile ?? callerClientConfig?.profile
      });
      if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) {
        const profiles = await sharedIniFileLoader.parseKnownFiles(init);
        const profile = profiles[profileName];
        if (!profile) {
          throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} was not found.`, { logger: init.logger });
        }
        if (!isSsoProfile(profile)) {
          throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} is not configured with SSO credentials.`, {
            logger: init.logger
          });
        }
        if (profile?.sso_session) {
          const ssoSessions = await sharedIniFileLoader.loadSsoSessionData(init);
          const session = ssoSessions[profile.sso_session];
          const conflictMsg = ` configurations in profile ${profileName} and sso-session ${profile.sso_session}`;
          if (ssoRegion && ssoRegion !== session.sso_region) {
            throw new propertyProvider.CredentialsProviderError(`Conflicting SSO region` + conflictMsg, {
              tryNextLink: false,
              logger: init.logger
            });
          }
          if (ssoStartUrl && ssoStartUrl !== session.sso_start_url) {
            throw new propertyProvider.CredentialsProviderError(`Conflicting SSO start_url` + conflictMsg, {
              tryNextLink: false,
              logger: init.logger
            });
          }
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
      } else if (!ssoStartUrl || !ssoAccountId || !ssoRegion || !ssoRoleName) {
        throw new propertyProvider.CredentialsProviderError('Incomplete configuration. The fromSSO() argument hash must include "ssoStartUrl", "ssoAccountId", "ssoRegion", "ssoRoleName"', { tryNextLink: false, logger: init.logger });
      } else {
        return resolveSSOCredentials({
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
      }
    };
    exports.fromSSO = fromSSO;
    exports.isSsoProfile = isSsoProfile;
    exports.validateSsoProfile = validateSsoProfile;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption2(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "signin",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption2(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var import_util_middleware7, defaultSigninHttpAuthSchemeParametersProvider, defaultSigninHttpAuthSchemeProvider, resolveHttpAuthSchemeConfig2;
var init_httpAuthSchemeProvider2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthSchemeProvider.js"() {
    init_dist_es2();
    import_util_middleware7 = __toESM(require_dist_cjs6());
    defaultSigninHttpAuthSchemeParametersProvider = async (config, context, input) => {
      return {
        operation: (0, import_util_middleware7.getSmithyContext)(context).operation,
        region: await (0, import_util_middleware7.normalizeProvider)(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    defaultSigninHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "CreateOAuth2Token": {
          options.push(createSmithyApiNoAuthHttpAuthOption2(authParameters));
          break;
        }
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption2(authParameters));
        }
      }
      return options;
    };
    resolveHttpAuthSchemeConfig2 = (config) => {
      const config_0 = resolveAwsSdkSigV4Config(config);
      return Object.assign(config_0, {
        authSchemePreference: (0, import_util_middleware7.normalizeProvider)(config.authSchemePreference ?? [])
      });
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/EndpointParameters.js
var resolveClientEndpointParameters2, commonParams2;
var init_EndpointParameters2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/EndpointParameters.js"() {
    resolveClientEndpointParameters2 = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "signin"
      });
    };
    commonParams2 = {
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/ruleset.js
var u2, v2, w2, x2, a2, b2, c2, d2, e2, f2, g2, h2, i2, j2, k2, l2, m2, n2, o2, p2, q2, r2, s2, t2, _data2, ruleSet2;
var init_ruleset2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/ruleset.js"() {
    u2 = "required";
    v2 = "fn";
    w2 = "argv";
    x2 = "ref";
    a2 = true;
    b2 = "isSet";
    c2 = "booleanEquals";
    d2 = "error";
    e2 = "endpoint";
    f2 = "tree";
    g2 = "PartitionResult";
    h2 = "stringEquals";
    i2 = { [u2]: true, "default": false, "type": "boolean" };
    j2 = { [u2]: false, "type": "string" };
    k2 = { [x2]: "Endpoint" };
    l2 = { [v2]: c2, [w2]: [{ [x2]: "UseFIPS" }, true] };
    m2 = { [v2]: c2, [w2]: [{ [x2]: "UseDualStack" }, true] };
    n2 = {};
    o2 = { [v2]: "getAttr", [w2]: [{ [x2]: g2 }, "name"] };
    p2 = { [v2]: c2, [w2]: [{ [x2]: "UseFIPS" }, false] };
    q2 = { [v2]: c2, [w2]: [{ [x2]: "UseDualStack" }, false] };
    r2 = { [v2]: "getAttr", [w2]: [{ [x2]: g2 }, "supportsFIPS"] };
    s2 = { [v2]: c2, [w2]: [true, { [v2]: "getAttr", [w2]: [{ [x2]: g2 }, "supportsDualStack"] }] };
    t2 = [{ [x2]: "Region" }];
    _data2 = { version: "1.0", parameters: { UseDualStack: i2, UseFIPS: i2, Endpoint: j2, Region: j2 }, rules: [{ conditions: [{ [v2]: b2, [w2]: [k2] }], rules: [{ conditions: [l2], error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d2 }, { rules: [{ conditions: [m2], error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d2 }, { endpoint: { url: k2, properties: n2, headers: n2 }, type: e2 }], type: f2 }], type: f2 }, { rules: [{ conditions: [{ [v2]: b2, [w2]: t2 }], rules: [{ conditions: [{ [v2]: "aws.partition", [w2]: t2, assign: g2 }], rules: [{ conditions: [{ [v2]: h2, [w2]: [o2, "aws"] }, p2, q2], endpoint: { url: "https://{Region}.signin.aws.amazon.com", properties: n2, headers: n2 }, type: e2 }, { conditions: [{ [v2]: h2, [w2]: [o2, "aws-cn"] }, p2, q2], endpoint: { url: "https://{Region}.signin.amazonaws.cn", properties: n2, headers: n2 }, type: e2 }, { conditions: [{ [v2]: h2, [w2]: [o2, "aws-us-gov"] }, p2, q2], endpoint: { url: "https://{Region}.signin.amazonaws-us-gov.com", properties: n2, headers: n2 }, type: e2 }, { conditions: [l2, m2], rules: [{ conditions: [{ [v2]: c2, [w2]: [a2, r2] }, s2], rules: [{ endpoint: { url: "https://signin-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n2, headers: n2 }, type: e2 }], type: f2 }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d2 }], type: f2 }, { conditions: [l2, q2], rules: [{ conditions: [{ [v2]: c2, [w2]: [r2, a2] }], rules: [{ endpoint: { url: "https://signin-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n2, headers: n2 }, type: e2 }], type: f2 }, { error: "FIPS is enabled but this partition does not support FIPS", type: d2 }], type: f2 }, { conditions: [p2, m2], rules: [{ conditions: [s2], rules: [{ endpoint: { url: "https://signin.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n2, headers: n2 }, type: e2 }], type: f2 }, { error: "DualStack is enabled but this partition does not support DualStack", type: d2 }], type: f2 }, { endpoint: { url: "https://signin.{Region}.{PartitionResult#dnsSuffix}", properties: n2, headers: n2 }, type: e2 }], type: f2 }], type: f2 }, { error: "Invalid Configuration: Missing Region", type: d2 }], type: f2 }] };
    ruleSet2 = _data2;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/endpointResolver.js
var import_util_endpoints3, import_util_endpoints4, cache2, defaultEndpointResolver2;
var init_endpointResolver2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/endpointResolver.js"() {
    import_util_endpoints3 = __toESM(require_dist_cjs22());
    import_util_endpoints4 = __toESM(require_dist_cjs19());
    init_ruleset2();
    cache2 = new import_util_endpoints4.EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
    });
    defaultEndpointResolver2 = (endpointParams, context = {}) => {
      return cache2.get(endpointParams, () => (0, import_util_endpoints4.resolveEndpoint)(ruleSet2, {
        endpointParams,
        logger: context.logger
      }));
    };
    import_util_endpoints4.customEndpointFunctions.aws = import_util_endpoints3.awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.shared.js
var import_smithy_client15, import_url_parser2, import_util_base649, import_util_utf89, getRuntimeConfig3;
var init_runtimeConfig_shared2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.shared.js"() {
    init_dist_es2();
    init_protocols2();
    init_dist_es();
    import_smithy_client15 = __toESM(require_dist_cjs26());
    import_url_parser2 = __toESM(require_dist_cjs21());
    import_util_base649 = __toESM(require_dist_cjs11());
    import_util_utf89 = __toESM(require_dist_cjs10());
    init_httpAuthSchemeProvider2();
    init_endpointResolver2();
    getRuntimeConfig3 = (config) => {
      return {
        apiVersion: "2023-01-01",
        base64Decoder: config?.base64Decoder ?? import_util_base649.fromBase64,
        base64Encoder: config?.base64Encoder ?? import_util_base649.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? defaultEndpointResolver2,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSigninHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        logger: config?.logger ?? new import_smithy_client15.NoOpLogger(),
        protocol: config?.protocol ?? AwsRestJsonProtocol,
        protocolSettings: config?.protocolSettings ?? {
          defaultNamespace: "com.amazonaws.signin",
          version: "2023-01-01",
          serviceTarget: "Signin"
        },
        serviceId: config?.serviceId ?? "Signin",
        urlParser: config?.urlParser ?? import_url_parser2.parseUrl,
        utf8Decoder: config?.utf8Decoder ?? import_util_utf89.fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? import_util_utf89.toUtf8
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.js
var import_util_user_agent_node2, import_config_resolver3, import_hash_node2, import_middleware_retry3, import_node_config_provider2, import_node_http_handler2, import_smithy_client16, import_util_body_length_node2, import_util_defaults_mode_node2, import_util_retry2, getRuntimeConfig4;
var init_runtimeConfig2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.js"() {
    init_package();
    init_dist_es2();
    import_util_user_agent_node2 = __toESM(require_dist_cjs41());
    import_config_resolver3 = __toESM(require_dist_cjs30());
    import_hash_node2 = __toESM(require_dist_cjs42());
    import_middleware_retry3 = __toESM(require_dist_cjs37());
    import_node_config_provider2 = __toESM(require_dist_cjs33());
    import_node_http_handler2 = __toESM(require_dist_cjs14());
    import_smithy_client16 = __toESM(require_dist_cjs26());
    import_util_body_length_node2 = __toESM(require_dist_cjs43());
    import_util_defaults_mode_node2 = __toESM(require_dist_cjs44());
    import_util_retry2 = __toESM(require_dist_cjs36());
    init_runtimeConfig_shared2();
    getRuntimeConfig4 = (config) => {
      (0, import_smithy_client16.emitWarningIfUnsupportedVersion)(process.version);
      const defaultsMode = (0, import_util_defaults_mode_node2.resolveDefaultsModeConfig)(config);
      const defaultConfigProvider = () => defaultsMode().then(import_smithy_client16.loadConfigsForDefaultMode);
      const clientSharedValues = getRuntimeConfig3(config);
      emitWarningIfUnsupportedVersion(process.version);
      const loaderConfig = {
        profile: config?.profile,
        logger: clientSharedValues.logger
      };
      return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        authSchemePreference: config?.authSchemePreference ?? (0, import_node_config_provider2.loadConfig)(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
        bodyLengthChecker: config?.bodyLengthChecker ?? import_util_body_length_node2.calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, import_util_user_agent_node2.createDefaultUserAgentProvider)({ serviceId: clientSharedValues.serviceId, clientVersion: package_default.version }),
        maxAttempts: config?.maxAttempts ?? (0, import_node_config_provider2.loadConfig)(import_middleware_retry3.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? (0, import_node_config_provider2.loadConfig)(import_config_resolver3.NODE_REGION_CONFIG_OPTIONS, { ...import_config_resolver3.NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
        requestHandler: import_node_http_handler2.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ?? (0, import_node_config_provider2.loadConfig)({
          ...import_middleware_retry3.NODE_RETRY_MODE_CONFIG_OPTIONS,
          default: async () => (await defaultConfigProvider()).retryMode || import_util_retry2.DEFAULT_RETRY_MODE
        }, config),
        sha256: config?.sha256 ?? import_hash_node2.Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? import_node_http_handler2.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, import_node_config_provider2.loadConfig)(import_config_resolver3.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        useFipsEndpoint: config?.useFipsEndpoint ?? (0, import_node_config_provider2.loadConfig)(import_config_resolver3.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        userAgentAppId: config?.userAgentAppId ?? (0, import_node_config_provider2.loadConfig)(import_util_user_agent_node2.NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration2, resolveHttpAuthRuntimeConfig2;
var init_httpAuthExtensionConfiguration2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthExtensionConfiguration.js"() {
    getHttpAuthExtensionConfiguration2 = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
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
    resolveHttpAuthRuntimeConfig2 = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials()
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeExtensions.js
var import_region_config_resolver2, import_protocol_http13, import_smithy_client17, resolveRuntimeExtensions2;
var init_runtimeExtensions2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeExtensions.js"() {
    import_region_config_resolver2 = __toESM(require_dist_cjs45());
    import_protocol_http13 = __toESM(require_dist_cjs2());
    import_smithy_client17 = __toESM(require_dist_cjs26());
    init_httpAuthExtensionConfiguration2();
    resolveRuntimeExtensions2 = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign((0, import_region_config_resolver2.getAwsRegionExtensionConfiguration)(runtimeConfig), (0, import_smithy_client17.getDefaultExtensionConfiguration)(runtimeConfig), (0, import_protocol_http13.getHttpHandlerExtensionConfiguration)(runtimeConfig), getHttpAuthExtensionConfiguration2(runtimeConfig));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig, (0, import_region_config_resolver2.resolveAwsRegionExtensionConfiguration)(extensionConfiguration), (0, import_smithy_client17.resolveDefaultRuntimeConfig)(extensionConfiguration), (0, import_protocol_http13.resolveHttpHandlerRuntimeConfig)(extensionConfiguration), resolveHttpAuthRuntimeConfig2(extensionConfiguration));
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/SigninClient.js
var import_middleware_host_header2, import_middleware_logger2, import_middleware_recursion_detection2, import_middleware_user_agent2, import_config_resolver4, import_middleware_content_length2, import_middleware_endpoint3, import_middleware_retry4, import_smithy_client18, SigninClient;
var init_SigninClient = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/SigninClient.js"() {
    import_middleware_host_header2 = __toESM(require_dist_cjs3());
    import_middleware_logger2 = __toESM(require_dist_cjs4());
    import_middleware_recursion_detection2 = __toESM(require_dist_cjs5());
    import_middleware_user_agent2 = __toESM(require_dist_cjs28());
    import_config_resolver4 = __toESM(require_dist_cjs30());
    init_dist_es();
    init_schema();
    import_middleware_content_length2 = __toESM(require_dist_cjs31());
    import_middleware_endpoint3 = __toESM(require_dist_cjs34());
    import_middleware_retry4 = __toESM(require_dist_cjs37());
    import_smithy_client18 = __toESM(require_dist_cjs26());
    init_httpAuthSchemeProvider2();
    init_EndpointParameters2();
    init_runtimeConfig2();
    init_runtimeExtensions2();
    SigninClient = class extends import_smithy_client18.Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = getRuntimeConfig4(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters2(_config_0);
        const _config_2 = (0, import_middleware_user_agent2.resolveUserAgentConfig)(_config_1);
        const _config_3 = (0, import_middleware_retry4.resolveRetryConfig)(_config_2);
        const _config_4 = (0, import_config_resolver4.resolveRegionConfig)(_config_3);
        const _config_5 = (0, import_middleware_host_header2.resolveHostHeaderConfig)(_config_4);
        const _config_6 = (0, import_middleware_endpoint3.resolveEndpointConfig)(_config_5);
        const _config_7 = resolveHttpAuthSchemeConfig2(_config_6);
        const _config_8 = resolveRuntimeExtensions2(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use(getSchemaSerdePlugin(this.config));
        this.middlewareStack.use((0, import_middleware_user_agent2.getUserAgentPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_retry4.getRetryPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_content_length2.getContentLengthPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_host_header2.getHostHeaderPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_logger2.getLoggerPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_recursion_detection2.getRecursionDetectionPlugin)(this.config));
        this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
          httpAuthSchemeParametersProvider: defaultSigninHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use(getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/SigninServiceException.js
var import_smithy_client19, SigninServiceException;
var init_SigninServiceException = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/SigninServiceException.js"() {
    import_smithy_client19 = __toESM(require_dist_cjs26());
    SigninServiceException = class _SigninServiceException extends import_smithy_client19.ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _SigninServiceException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/errors.js
var AccessDeniedException2, InternalServerException2, TooManyRequestsError, ValidationException;
var init_errors2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/errors.js"() {
    init_SigninServiceException();
    AccessDeniedException2 = class _AccessDeniedException extends SigninServiceException {
      name = "AccessDeniedException";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "AccessDeniedException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _AccessDeniedException.prototype);
        this.error = opts.error;
      }
    };
    InternalServerException2 = class _InternalServerException extends SigninServiceException {
      name = "InternalServerException";
      $fault = "server";
      error;
      constructor(opts) {
        super({
          name: "InternalServerException",
          $fault: "server",
          ...opts
        });
        Object.setPrototypeOf(this, _InternalServerException.prototype);
        this.error = opts.error;
      }
    };
    TooManyRequestsError = class _TooManyRequestsError extends SigninServiceException {
      name = "TooManyRequestsError";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "TooManyRequestsError",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _TooManyRequestsError.prototype);
        this.error = opts.error;
      }
    };
    ValidationException = class _ValidationException extends SigninServiceException {
      name = "ValidationException";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "ValidationException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ValidationException.prototype);
        this.error = opts.error;
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/schemas/schemas_0.js
var _ADE2, _AT2, _COAT, _COATR, _COATRB, _COATRBr, _COATRr, _ISE2, _RT2, _TMRE, _VE, _aKI, _aT2, _c2, _cI2, _cV2, _co2, _e2, _eI2, _gT2, _h2, _hE2, _iT2, _jN, _m, _rT2, _rU2, _s2, _sAK, _sT, _sm2, _tI, _tO, _tT2, n02, RefreshToken2, AccessDeniedException$2, AccessToken$, CreateOAuth2TokenRequest$, CreateOAuth2TokenRequestBody$, CreateOAuth2TokenResponse$, CreateOAuth2TokenResponseBody$, InternalServerException$2, TooManyRequestsError$, ValidationException$, SigninServiceException$, CreateOAuth2Token$;
var init_schemas_02 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/schemas/schemas_0.js"() {
    init_schema();
    init_errors2();
    init_SigninServiceException();
    _ADE2 = "AccessDeniedException";
    _AT2 = "AccessToken";
    _COAT = "CreateOAuth2Token";
    _COATR = "CreateOAuth2TokenRequest";
    _COATRB = "CreateOAuth2TokenRequestBody";
    _COATRBr = "CreateOAuth2TokenResponseBody";
    _COATRr = "CreateOAuth2TokenResponse";
    _ISE2 = "InternalServerException";
    _RT2 = "RefreshToken";
    _TMRE = "TooManyRequestsError";
    _VE = "ValidationException";
    _aKI = "accessKeyId";
    _aT2 = "accessToken";
    _c2 = "client";
    _cI2 = "clientId";
    _cV2 = "codeVerifier";
    _co2 = "code";
    _e2 = "error";
    _eI2 = "expiresIn";
    _gT2 = "grantType";
    _h2 = "http";
    _hE2 = "httpError";
    _iT2 = "idToken";
    _jN = "jsonName";
    _m = "message";
    _rT2 = "refreshToken";
    _rU2 = "redirectUri";
    _s2 = "server";
    _sAK = "secretAccessKey";
    _sT = "sessionToken";
    _sm2 = "smithy.ts.sdk.synthetic.com.amazonaws.signin";
    _tI = "tokenInput";
    _tO = "tokenOutput";
    _tT2 = "tokenType";
    n02 = "com.amazonaws.signin";
    RefreshToken2 = [0, n02, _RT2, 8, 0];
    AccessDeniedException$2 = [-3, n02, _ADE2, { [_e2]: _c2 }, [_e2, _m], [0, 0]];
    TypeRegistry.for(n02).registerError(AccessDeniedException$2, AccessDeniedException2);
    AccessToken$ = [
      3,
      n02,
      _AT2,
      8,
      [_aKI, _sAK, _sT],
      [
        [0, { [_jN]: _aKI }],
        [0, { [_jN]: _sAK }],
        [0, { [_jN]: _sT }]
      ]
    ];
    CreateOAuth2TokenRequest$ = [
      3,
      n02,
      _COATR,
      0,
      [_tI],
      [[() => CreateOAuth2TokenRequestBody$, 16]]
    ];
    CreateOAuth2TokenRequestBody$ = [
      3,
      n02,
      _COATRB,
      0,
      [_cI2, _gT2, _co2, _rU2, _cV2, _rT2],
      [
        [0, { [_jN]: _cI2 }],
        [0, { [_jN]: _gT2 }],
        0,
        [0, { [_jN]: _rU2 }],
        [0, { [_jN]: _cV2 }],
        [() => RefreshToken2, { [_jN]: _rT2 }]
      ]
    ];
    CreateOAuth2TokenResponse$ = [
      3,
      n02,
      _COATRr,
      0,
      [_tO],
      [[() => CreateOAuth2TokenResponseBody$, 16]]
    ];
    CreateOAuth2TokenResponseBody$ = [
      3,
      n02,
      _COATRBr,
      0,
      [_aT2, _tT2, _eI2, _rT2, _iT2],
      [
        [() => AccessToken$, { [_jN]: _aT2 }],
        [0, { [_jN]: _tT2 }],
        [1, { [_jN]: _eI2 }],
        [() => RefreshToken2, { [_jN]: _rT2 }],
        [0, { [_jN]: _iT2 }]
      ]
    ];
    InternalServerException$2 = [-3, n02, _ISE2, { [_e2]: _s2, [_hE2]: 500 }, [_e2, _m], [0, 0]];
    TypeRegistry.for(n02).registerError(InternalServerException$2, InternalServerException2);
    TooManyRequestsError$ = [-3, n02, _TMRE, { [_e2]: _c2, [_hE2]: 429 }, [_e2, _m], [0, 0]];
    TypeRegistry.for(n02).registerError(TooManyRequestsError$, TooManyRequestsError);
    ValidationException$ = [-3, n02, _VE, { [_e2]: _c2, [_hE2]: 400 }, [_e2, _m], [0, 0]];
    TypeRegistry.for(n02).registerError(ValidationException$, ValidationException);
    SigninServiceException$ = [-3, _sm2, "SigninServiceException", 0, [], []];
    TypeRegistry.for(_sm2).registerError(SigninServiceException$, SigninServiceException);
    CreateOAuth2Token$ = [
      9,
      n02,
      _COAT,
      { [_h2]: ["POST", "/v1/token", 200] },
      () => CreateOAuth2TokenRequest$,
      () => CreateOAuth2TokenResponse$
    ];
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/CreateOAuth2TokenCommand.js
var import_middleware_endpoint4, import_smithy_client20, CreateOAuth2TokenCommand;
var init_CreateOAuth2TokenCommand = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/CreateOAuth2TokenCommand.js"() {
    import_middleware_endpoint4 = __toESM(require_dist_cjs34());
    import_smithy_client20 = __toESM(require_dist_cjs26());
    init_EndpointParameters2();
    init_schemas_02();
    CreateOAuth2TokenCommand = class extends import_smithy_client20.Command.classBuilder().ep(commonParams2).m(function(Command, cs, config, o4) {
      return [(0, import_middleware_endpoint4.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())];
    }).s("Signin", "CreateOAuth2Token", {}).n("SigninClient", "CreateOAuth2TokenCommand").sc(CreateOAuth2Token$).build() {
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/Signin.js
var import_smithy_client21, commands2, Signin;
var init_Signin = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/Signin.js"() {
    import_smithy_client21 = __toESM(require_dist_cjs26());
    init_CreateOAuth2TokenCommand();
    init_SigninClient();
    commands2 = {
      CreateOAuth2TokenCommand
    };
    Signin = class extends SigninClient {
    };
    (0, import_smithy_client21.createAggregatedClient)(commands2, Signin);
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/index.js
var init_commands2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/index.js"() {
    init_CreateOAuth2TokenCommand();
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/enums.js
var OAuth2ErrorCode;
var init_enums2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/enums.js"() {
    OAuth2ErrorCode = {
      AUTHCODE_EXPIRED: "AUTHCODE_EXPIRED",
      INSUFFICIENT_PERMISSIONS: "INSUFFICIENT_PERMISSIONS",
      INVALID_REQUEST: "INVALID_REQUEST",
      SERVER_ERROR: "server_error",
      TOKEN_EXPIRED: "TOKEN_EXPIRED",
      USER_CREDENTIALS_CHANGED: "USER_CREDENTIALS_CHANGED"
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/models_0.js
var init_models_02 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/models_0.js"() {
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/index.js
var signin_exports = {};
__export(signin_exports, {
  $Command: () => import_smithy_client20.Command,
  AccessDeniedException: () => AccessDeniedException2,
  AccessDeniedException$: () => AccessDeniedException$2,
  AccessToken$: () => AccessToken$,
  CreateOAuth2Token$: () => CreateOAuth2Token$,
  CreateOAuth2TokenCommand: () => CreateOAuth2TokenCommand,
  CreateOAuth2TokenRequest$: () => CreateOAuth2TokenRequest$,
  CreateOAuth2TokenRequestBody$: () => CreateOAuth2TokenRequestBody$,
  CreateOAuth2TokenResponse$: () => CreateOAuth2TokenResponse$,
  CreateOAuth2TokenResponseBody$: () => CreateOAuth2TokenResponseBody$,
  InternalServerException: () => InternalServerException2,
  InternalServerException$: () => InternalServerException$2,
  OAuth2ErrorCode: () => OAuth2ErrorCode,
  Signin: () => Signin,
  SigninClient: () => SigninClient,
  SigninServiceException: () => SigninServiceException,
  SigninServiceException$: () => SigninServiceException$,
  TooManyRequestsError: () => TooManyRequestsError,
  TooManyRequestsError$: () => TooManyRequestsError$,
  ValidationException: () => ValidationException,
  ValidationException$: () => ValidationException$,
  __Client: () => import_smithy_client18.Client
});
var init_signin = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/index.js"() {
    init_SigninClient();
    init_Signin();
    init_commands2();
    init_schemas_02();
    init_enums2();
    init_errors2();
    init_models_02();
    init_SigninServiceException();
  }
});

// node_modules/@aws-sdk/credential-provider-login/dist-cjs/index.js
var require_dist_cjs49 = __commonJS({
  "node_modules/@aws-sdk/credential-provider-login/dist-cjs/index.js"(exports) {
    "use strict";
    var client2 = (init_client(), __toCommonJS(client_exports));
    var propertyProvider = require_dist_cjs23();
    var sharedIniFileLoader = require_dist_cjs32();
    var protocolHttp = require_dist_cjs2();
    var node_crypto = __require("node:crypto");
    var node_fs = __require("node:fs");
    var node_os = __require("node:os");
    var node_path = __require("node:path");
    var LoginCredentialsFetcher = class _LoginCredentialsFetcher {
      profileData;
      init;
      callerClientConfig;
      static REFRESH_THRESHOLD = 5 * 60 * 1e3;
      constructor(profileData, init, callerClientConfig) {
        this.profileData = profileData;
        this.init = init;
        this.callerClientConfig = callerClientConfig;
      }
      async loadCredentials() {
        const token = await this.loadToken();
        if (!token) {
          throw new propertyProvider.CredentialsProviderError(`Failed to load a token for session ${this.loginSession}, please re-authenticate using aws login`, { tryNextLink: false, logger: this.logger });
        }
        const accessToken = token.accessToken;
        const now = Date.now();
        const expiryTime = new Date(accessToken.expiresAt).getTime();
        const timeUntilExpiry = expiryTime - now;
        if (timeUntilExpiry <= _LoginCredentialsFetcher.REFRESH_THRESHOLD) {
          return this.refresh(token);
        }
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
        const { SigninClient: SigninClient2, CreateOAuth2TokenCommand: CreateOAuth2TokenCommand2 } = await Promise.resolve().then(() => (init_signin(), signin_exports));
        const { logger: logger2, userAgentAppId } = this.callerClientConfig ?? {};
        const isH22 = (requestHandler2) => {
          return requestHandler2?.metadata?.handlerProtocol === "h2";
        };
        const requestHandler = isH22(this.callerClientConfig?.requestHandler) ? void 0 : this.callerClientConfig?.requestHandler;
        const region = this.profileData.region ?? await this.callerClientConfig?.region?.() ?? process.env.AWS_REGION;
        const client3 = new SigninClient2({
          credentials: {
            accessKeyId: "",
            secretAccessKey: ""
          },
          region,
          requestHandler,
          logger: logger2,
          userAgentAppId,
          ...this.init?.clientConfig
        });
        this.createDPoPInterceptor(client3.middlewareStack);
        const commandInput = {
          tokenInput: {
            clientId: token.clientId,
            refreshToken: token.refreshToken,
            grantType: "refresh_token"
          }
        };
        try {
          const response = await client3.send(new CreateOAuth2TokenCommand2(commandInput));
          const { accessKeyId, secretAccessKey, sessionToken } = response.tokenOutput?.accessToken ?? {};
          const { refreshToken, expiresIn } = response.tokenOutput ?? {};
          if (!accessKeyId || !secretAccessKey || !sessionToken || !refreshToken) {
            throw new propertyProvider.CredentialsProviderError("Token refresh response missing required fields", {
              logger: this.logger,
              tryNextLink: false
            });
          }
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
        } catch (error2) {
          if (error2.name === "AccessDeniedException") {
            const errorType = error2.error;
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
              default:
                message = `Failed to refresh token: ${String(error2)}. Please re-authenticate using \`aws login\``;
            }
            throw new propertyProvider.CredentialsProviderError(message, { logger: this.logger, tryNextLink: false });
          }
          throw new propertyProvider.CredentialsProviderError(`Failed to refresh token: ${String(error2)}. Please re-authenticate using aws login`, { logger: this.logger });
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
          const missingFields = ["accessToken", "clientId", "refreshToken", "dpopKey"].filter((k4) => !token[k4]);
          if (!token.accessToken?.accountId) {
            missingFields.push("accountId");
          }
          if (missingFields.length > 0) {
            throw new propertyProvider.CredentialsProviderError(`Token validation failed, missing fields: ${missingFields.join(", ")}`, {
              logger: this.logger,
              tryNextLink: false
            });
          }
          return token;
        } catch (error2) {
          throw new propertyProvider.CredentialsProviderError(`Failed to load token from ${tokenFilePath}: ${String(error2)}`, {
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
        } catch (error2) {
        }
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
        if (derSignature[offset] !== 2) {
          throw new Error("Invalid DER signature");
        }
        offset++;
        const rLength = derSignature[offset++];
        let r4 = derSignature.subarray(offset, offset + rLength);
        offset += rLength;
        if (derSignature[offset] !== 2) {
          throw new Error("Invalid DER signature");
        }
        offset++;
        const sLength = derSignature[offset++];
        let s4 = derSignature.subarray(offset, offset + sLength);
        r4 = r4[0] === 0 ? r4.subarray(1) : r4;
        s4 = s4[0] === 0 ? s4.subarray(1) : s4;
        const rPadded = Buffer.concat([Buffer.alloc(32 - r4.length), r4]);
        const sPadded = Buffer.concat([Buffer.alloc(32 - s4.length), s4]);
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
          const publicKey = node_crypto.createPublicKey(privateKey);
          const publicDer = publicKey.export({ format: "der", type: "spki" });
          let pointStart = -1;
          for (let i4 = 0; i4 < publicDer.length; i4++) {
            if (publicDer[i4] === 4) {
              pointStart = i4;
              break;
            }
          }
          const x4 = publicDer.slice(pointStart + 1, pointStart + 33);
          const y2 = publicDer.slice(pointStart + 33, pointStart + 65);
          const header = {
            alg: "ES256",
            typ: "dpop+jwt",
            jwk: {
              kty: "EC",
              crv: "P-256",
              x: x4.toString("base64url"),
              y: y2.toString("base64url")
            }
          };
          const payload2 = {
            jti: crypto.randomUUID(),
            htm: method,
            htu: endpoint,
            iat: Math.floor(Date.now() / 1e3)
          };
          const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
          const payloadB64 = Buffer.from(JSON.stringify(payload2)).toString("base64url");
          const message = `${headerB64}.${payloadB64}`;
          const asn1Signature = node_crypto.sign("sha256", Buffer.from(message), privateKey);
          const rawSignature = this.derToRawSignature(asn1Signature);
          const signatureB64 = rawSignature.toString("base64url");
          return `${message}.${signatureB64}`;
        } catch (error2) {
          throw new propertyProvider.CredentialsProviderError(`Failed to generate Dpop proof: ${error2 instanceof Error ? error2.message : String(error2)}`, { logger: this.logger, tryNextLink: false });
        }
      }
    };
    var fromLoginCredentials = (init) => async ({ callerClientConfig } = {}) => {
      init?.logger?.debug?.("@aws-sdk/credential-providers - fromLoginCredentials");
      const profiles = await sharedIniFileLoader.parseKnownFiles(init || {});
      const profileName = sharedIniFileLoader.getProfileName({
        profile: init?.profile ?? callerClientConfig?.profile
      });
      const profile = profiles[profileName];
      if (!profile?.login_session) {
        throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} does not contain login_session.`, {
          tryNextLink: true,
          logger: init?.logger
        });
      }
      const fetcher = new LoginCredentialsFetcher(profile, init, callerClientConfig);
      const credentials = await fetcher.loadCredentials();
      return client2.setCredentialFeature(credentials, "CREDENTIALS_LOGIN", "AD");
    };
    exports.fromLoginCredentials = fromLoginCredentials;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption3(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "sts",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption3(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var import_util_middleware8, defaultSTSHttpAuthSchemeParametersProvider, defaultSTSHttpAuthSchemeProvider, resolveStsAuthConfig, resolveHttpAuthSchemeConfig3;
var init_httpAuthSchemeProvider3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthSchemeProvider.js"() {
    init_dist_es2();
    import_util_middleware8 = __toESM(require_dist_cjs6());
    init_STSClient();
    defaultSTSHttpAuthSchemeParametersProvider = async (config, context, input) => {
      return {
        operation: (0, import_util_middleware8.getSmithyContext)(context).operation,
        region: await (0, import_util_middleware8.normalizeProvider)(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    defaultSTSHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "AssumeRoleWithWebIdentity": {
          options.push(createSmithyApiNoAuthHttpAuthOption3(authParameters));
          break;
        }
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption3(authParameters));
        }
      }
      return options;
    };
    resolveStsAuthConfig = (input) => Object.assign(input, {
      stsClientCtor: STSClient
    });
    resolveHttpAuthSchemeConfig3 = (config) => {
      const config_0 = resolveStsAuthConfig(config);
      const config_1 = resolveAwsSdkSigV4Config(config_0);
      return Object.assign(config_1, {
        authSchemePreference: (0, import_util_middleware8.normalizeProvider)(config.authSchemePreference ?? [])
      });
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/EndpointParameters.js
var resolveClientEndpointParameters3, commonParams3;
var init_EndpointParameters3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/EndpointParameters.js"() {
    resolveClientEndpointParameters3 = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        useGlobalEndpoint: options.useGlobalEndpoint ?? false,
        defaultSigningName: "sts"
      });
    };
    commonParams3 = {
      UseGlobalEndpoint: { type: "builtInParams", name: "useGlobalEndpoint" },
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/ruleset.js
var F, G, H, I, J, a3, b3, c3, d3, e3, f3, g3, h3, i3, j3, k3, l3, m3, n3, o3, p3, q3, r3, s3, t3, u3, v3, w3, x3, y, z, A, B, C, D, E, _data3, ruleSet3;
var init_ruleset3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/ruleset.js"() {
    F = "required";
    G = "type";
    H = "fn";
    I = "argv";
    J = "ref";
    a3 = false;
    b3 = true;
    c3 = "booleanEquals";
    d3 = "stringEquals";
    e3 = "sigv4";
    f3 = "sts";
    g3 = "us-east-1";
    h3 = "endpoint";
    i3 = "https://sts.{Region}.{PartitionResult#dnsSuffix}";
    j3 = "tree";
    k3 = "error";
    l3 = "getAttr";
    m3 = { [F]: false, [G]: "string" };
    n3 = { [F]: true, "default": false, [G]: "boolean" };
    o3 = { [J]: "Endpoint" };
    p3 = { [H]: "isSet", [I]: [{ [J]: "Region" }] };
    q3 = { [J]: "Region" };
    r3 = { [H]: "aws.partition", [I]: [q3], "assign": "PartitionResult" };
    s3 = { [J]: "UseFIPS" };
    t3 = { [J]: "UseDualStack" };
    u3 = { "url": "https://sts.amazonaws.com", "properties": { "authSchemes": [{ "name": e3, "signingName": f3, "signingRegion": g3 }] }, "headers": {} };
    v3 = {};
    w3 = { "conditions": [{ [H]: d3, [I]: [q3, "aws-global"] }], [h3]: u3, [G]: h3 };
    x3 = { [H]: c3, [I]: [s3, true] };
    y = { [H]: c3, [I]: [t3, true] };
    z = { [H]: l3, [I]: [{ [J]: "PartitionResult" }, "supportsFIPS"] };
    A = { [J]: "PartitionResult" };
    B = { [H]: c3, [I]: [true, { [H]: l3, [I]: [A, "supportsDualStack"] }] };
    C = [{ [H]: "isSet", [I]: [o3] }];
    D = [x3];
    E = [y];
    _data3 = { version: "1.0", parameters: { Region: m3, UseDualStack: n3, UseFIPS: n3, Endpoint: m3, UseGlobalEndpoint: n3 }, rules: [{ conditions: [{ [H]: c3, [I]: [{ [J]: "UseGlobalEndpoint" }, b3] }, { [H]: "not", [I]: C }, p3, r3, { [H]: c3, [I]: [s3, a3] }, { [H]: c3, [I]: [t3, a3] }], rules: [{ conditions: [{ [H]: d3, [I]: [q3, "ap-northeast-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "ap-south-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "ap-southeast-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "ap-southeast-2"] }], endpoint: u3, [G]: h3 }, w3, { conditions: [{ [H]: d3, [I]: [q3, "ca-central-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-central-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-north-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-west-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-west-2"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-west-3"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "sa-east-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, g3] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "us-east-2"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "us-west-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "us-west-2"] }], endpoint: u3, [G]: h3 }, { endpoint: { url: i3, properties: { authSchemes: [{ name: e3, signingName: f3, signingRegion: "{Region}" }] }, headers: v3 }, [G]: h3 }], [G]: j3 }, { conditions: C, rules: [{ conditions: D, error: "Invalid Configuration: FIPS and custom endpoint are not supported", [G]: k3 }, { conditions: E, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", [G]: k3 }, { endpoint: { url: o3, properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }, { conditions: [p3], rules: [{ conditions: [r3], rules: [{ conditions: [x3, y], rules: [{ conditions: [{ [H]: c3, [I]: [b3, z] }, B], rules: [{ endpoint: { url: "https://sts-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", [G]: k3 }], [G]: j3 }, { conditions: D, rules: [{ conditions: [{ [H]: c3, [I]: [z, b3] }], rules: [{ conditions: [{ [H]: d3, [I]: [{ [H]: l3, [I]: [A, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://sts.{Region}.amazonaws.com", properties: v3, headers: v3 }, [G]: h3 }, { endpoint: { url: "https://sts-fips.{Region}.{PartitionResult#dnsSuffix}", properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }, { error: "FIPS is enabled but this partition does not support FIPS", [G]: k3 }], [G]: j3 }, { conditions: E, rules: [{ conditions: [B], rules: [{ endpoint: { url: "https://sts.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }, { error: "DualStack is enabled but this partition does not support DualStack", [G]: k3 }], [G]: j3 }, w3, { endpoint: { url: i3, properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }], [G]: j3 }, { error: "Invalid Configuration: Missing Region", [G]: k3 }] };
    ruleSet3 = _data3;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/endpointResolver.js
var import_util_endpoints5, import_util_endpoints6, cache3, defaultEndpointResolver3;
var init_endpointResolver3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/endpointResolver.js"() {
    import_util_endpoints5 = __toESM(require_dist_cjs22());
    import_util_endpoints6 = __toESM(require_dist_cjs19());
    init_ruleset3();
    cache3 = new import_util_endpoints6.EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS", "UseGlobalEndpoint"]
    });
    defaultEndpointResolver3 = (endpointParams, context = {}) => {
      return cache3.get(endpointParams, () => (0, import_util_endpoints6.resolveEndpoint)(ruleSet3, {
        endpointParams,
        logger: context.logger
      }));
    };
    import_util_endpoints6.customEndpointFunctions.aws = import_util_endpoints5.awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.shared.js
var import_smithy_client22, import_url_parser3, import_util_base6410, import_util_utf810, getRuntimeConfig5;
var init_runtimeConfig_shared3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.shared.js"() {
    init_dist_es2();
    init_protocols2();
    init_dist_es();
    import_smithy_client22 = __toESM(require_dist_cjs26());
    import_url_parser3 = __toESM(require_dist_cjs21());
    import_util_base6410 = __toESM(require_dist_cjs11());
    import_util_utf810 = __toESM(require_dist_cjs10());
    init_httpAuthSchemeProvider3();
    init_endpointResolver3();
    getRuntimeConfig5 = (config) => {
      return {
        apiVersion: "2011-06-15",
        base64Decoder: config?.base64Decoder ?? import_util_base6410.fromBase64,
        base64Encoder: config?.base64Encoder ?? import_util_base6410.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? defaultEndpointResolver3,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSTSHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        logger: config?.logger ?? new import_smithy_client22.NoOpLogger(),
        protocol: config?.protocol ?? AwsQueryProtocol,
        protocolSettings: config?.protocolSettings ?? {
          defaultNamespace: "com.amazonaws.sts",
          xmlNamespace: "https://sts.amazonaws.com/doc/2011-06-15/",
          version: "2011-06-15",
          serviceTarget: "AWSSecurityTokenServiceV20110615"
        },
        serviceId: config?.serviceId ?? "STS",
        urlParser: config?.urlParser ?? import_url_parser3.parseUrl,
        utf8Decoder: config?.utf8Decoder ?? import_util_utf810.fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? import_util_utf810.toUtf8
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.js
var import_util_user_agent_node3, import_config_resolver5, import_hash_node3, import_middleware_retry5, import_node_config_provider3, import_node_http_handler3, import_smithy_client23, import_util_body_length_node3, import_util_defaults_mode_node3, import_util_retry3, getRuntimeConfig6;
var init_runtimeConfig3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.js"() {
    init_package();
    init_dist_es2();
    import_util_user_agent_node3 = __toESM(require_dist_cjs41());
    import_config_resolver5 = __toESM(require_dist_cjs30());
    init_dist_es();
    import_hash_node3 = __toESM(require_dist_cjs42());
    import_middleware_retry5 = __toESM(require_dist_cjs37());
    import_node_config_provider3 = __toESM(require_dist_cjs33());
    import_node_http_handler3 = __toESM(require_dist_cjs14());
    import_smithy_client23 = __toESM(require_dist_cjs26());
    import_util_body_length_node3 = __toESM(require_dist_cjs43());
    import_util_defaults_mode_node3 = __toESM(require_dist_cjs44());
    import_util_retry3 = __toESM(require_dist_cjs36());
    init_runtimeConfig_shared3();
    getRuntimeConfig6 = (config) => {
      (0, import_smithy_client23.emitWarningIfUnsupportedVersion)(process.version);
      const defaultsMode = (0, import_util_defaults_mode_node3.resolveDefaultsModeConfig)(config);
      const defaultConfigProvider = () => defaultsMode().then(import_smithy_client23.loadConfigsForDefaultMode);
      const clientSharedValues = getRuntimeConfig5(config);
      emitWarningIfUnsupportedVersion(process.version);
      const loaderConfig = {
        profile: config?.profile,
        logger: clientSharedValues.logger
      };
      return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        authSchemePreference: config?.authSchemePreference ?? (0, import_node_config_provider3.loadConfig)(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
        bodyLengthChecker: config?.bodyLengthChecker ?? import_util_body_length_node3.calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, import_util_user_agent_node3.createDefaultUserAgentProvider)({ serviceId: clientSharedValues.serviceId, clientVersion: package_default.version }),
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4") || (async (idProps) => await config.credentialDefaultProvider(idProps?.__config || {})()),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        maxAttempts: config?.maxAttempts ?? (0, import_node_config_provider3.loadConfig)(import_middleware_retry5.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? (0, import_node_config_provider3.loadConfig)(import_config_resolver5.NODE_REGION_CONFIG_OPTIONS, { ...import_config_resolver5.NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
        requestHandler: import_node_http_handler3.NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ?? (0, import_node_config_provider3.loadConfig)({
          ...import_middleware_retry5.NODE_RETRY_MODE_CONFIG_OPTIONS,
          default: async () => (await defaultConfigProvider()).retryMode || import_util_retry3.DEFAULT_RETRY_MODE
        }, config),
        sha256: config?.sha256 ?? import_hash_node3.Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? import_node_http_handler3.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? (0, import_node_config_provider3.loadConfig)(import_config_resolver5.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        useFipsEndpoint: config?.useFipsEndpoint ?? (0, import_node_config_provider3.loadConfig)(import_config_resolver5.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        userAgentAppId: config?.userAgentAppId ?? (0, import_node_config_provider3.loadConfig)(import_util_user_agent_node3.NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration3, resolveHttpAuthRuntimeConfig3;
var init_httpAuthExtensionConfiguration3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthExtensionConfiguration.js"() {
    getHttpAuthExtensionConfiguration3 = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
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
    resolveHttpAuthRuntimeConfig3 = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials()
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeExtensions.js
var import_region_config_resolver3, import_protocol_http14, import_smithy_client24, resolveRuntimeExtensions3;
var init_runtimeExtensions3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeExtensions.js"() {
    import_region_config_resolver3 = __toESM(require_dist_cjs45());
    import_protocol_http14 = __toESM(require_dist_cjs2());
    import_smithy_client24 = __toESM(require_dist_cjs26());
    init_httpAuthExtensionConfiguration3();
    resolveRuntimeExtensions3 = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign((0, import_region_config_resolver3.getAwsRegionExtensionConfiguration)(runtimeConfig), (0, import_smithy_client24.getDefaultExtensionConfiguration)(runtimeConfig), (0, import_protocol_http14.getHttpHandlerExtensionConfiguration)(runtimeConfig), getHttpAuthExtensionConfiguration3(runtimeConfig));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig, (0, import_region_config_resolver3.resolveAwsRegionExtensionConfiguration)(extensionConfiguration), (0, import_smithy_client24.resolveDefaultRuntimeConfig)(extensionConfiguration), (0, import_protocol_http14.resolveHttpHandlerRuntimeConfig)(extensionConfiguration), resolveHttpAuthRuntimeConfig3(extensionConfiguration));
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STSClient.js
var import_middleware_host_header3, import_middleware_logger3, import_middleware_recursion_detection3, import_middleware_user_agent3, import_config_resolver6, import_middleware_content_length3, import_middleware_endpoint5, import_middleware_retry6, import_smithy_client25, STSClient;
var init_STSClient = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STSClient.js"() {
    import_middleware_host_header3 = __toESM(require_dist_cjs3());
    import_middleware_logger3 = __toESM(require_dist_cjs4());
    import_middleware_recursion_detection3 = __toESM(require_dist_cjs5());
    import_middleware_user_agent3 = __toESM(require_dist_cjs28());
    import_config_resolver6 = __toESM(require_dist_cjs30());
    init_dist_es();
    init_schema();
    import_middleware_content_length3 = __toESM(require_dist_cjs31());
    import_middleware_endpoint5 = __toESM(require_dist_cjs34());
    import_middleware_retry6 = __toESM(require_dist_cjs37());
    import_smithy_client25 = __toESM(require_dist_cjs26());
    init_httpAuthSchemeProvider3();
    init_EndpointParameters3();
    init_runtimeConfig3();
    init_runtimeExtensions3();
    STSClient = class extends import_smithy_client25.Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = getRuntimeConfig6(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters3(_config_0);
        const _config_2 = (0, import_middleware_user_agent3.resolveUserAgentConfig)(_config_1);
        const _config_3 = (0, import_middleware_retry6.resolveRetryConfig)(_config_2);
        const _config_4 = (0, import_config_resolver6.resolveRegionConfig)(_config_3);
        const _config_5 = (0, import_middleware_host_header3.resolveHostHeaderConfig)(_config_4);
        const _config_6 = (0, import_middleware_endpoint5.resolveEndpointConfig)(_config_5);
        const _config_7 = resolveHttpAuthSchemeConfig3(_config_6);
        const _config_8 = resolveRuntimeExtensions3(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use(getSchemaSerdePlugin(this.config));
        this.middlewareStack.use((0, import_middleware_user_agent3.getUserAgentPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_retry6.getRetryPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_content_length3.getContentLengthPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_host_header3.getHostHeaderPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_logger3.getLoggerPlugin)(this.config));
        this.middlewareStack.use((0, import_middleware_recursion_detection3.getRecursionDetectionPlugin)(this.config));
        this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
          httpAuthSchemeParametersProvider: defaultSTSHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use(getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/STSServiceException.js
var import_smithy_client26, STSServiceException;
var init_STSServiceException = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/STSServiceException.js"() {
    import_smithy_client26 = __toESM(require_dist_cjs26());
    STSServiceException = class _STSServiceException extends import_smithy_client26.ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _STSServiceException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/errors.js
var ExpiredTokenException2, MalformedPolicyDocumentException, PackedPolicyTooLargeException, RegionDisabledException, IDPRejectedClaimException, InvalidIdentityTokenException, IDPCommunicationErrorException;
var init_errors3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/errors.js"() {
    init_STSServiceException();
    ExpiredTokenException2 = class _ExpiredTokenException extends STSServiceException {
      name = "ExpiredTokenException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "ExpiredTokenException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
      }
    };
    MalformedPolicyDocumentException = class _MalformedPolicyDocumentException extends STSServiceException {
      name = "MalformedPolicyDocumentException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "MalformedPolicyDocumentException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _MalformedPolicyDocumentException.prototype);
      }
    };
    PackedPolicyTooLargeException = class _PackedPolicyTooLargeException extends STSServiceException {
      name = "PackedPolicyTooLargeException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "PackedPolicyTooLargeException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _PackedPolicyTooLargeException.prototype);
      }
    };
    RegionDisabledException = class _RegionDisabledException extends STSServiceException {
      name = "RegionDisabledException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "RegionDisabledException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _RegionDisabledException.prototype);
      }
    };
    IDPRejectedClaimException = class _IDPRejectedClaimException extends STSServiceException {
      name = "IDPRejectedClaimException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "IDPRejectedClaimException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _IDPRejectedClaimException.prototype);
      }
    };
    InvalidIdentityTokenException = class _InvalidIdentityTokenException extends STSServiceException {
      name = "InvalidIdentityTokenException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "InvalidIdentityTokenException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidIdentityTokenException.prototype);
      }
    };
    IDPCommunicationErrorException = class _IDPCommunicationErrorException extends STSServiceException {
      name = "IDPCommunicationErrorException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "IDPCommunicationErrorException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _IDPCommunicationErrorException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/schemas/schemas_0.js
var _A, _AKI, _AR, _ARI, _ARR, _ARRs, _ARU, _ARWWI, _ARWWIR, _ARWWIRs, _Au, _C, _CA, _DS, _E, _EI, _ETE2, _IDPCEE, _IDPRCE, _IITE, _K, _MPDE, _P, _PA, _PAr, _PC, _PCLT, _PCr, _PDT, _PI, _PPS, _PPTLE, _Pr, _RA, _RDE, _RSN, _SAK, _SFWIT, _SI, _SN, _ST, _T, _TC, _TTK, _Ta, _V, _WIT, _a, _aKST, _aQE, _c3, _cTT, _e3, _hE3, _m2, _pDLT, _s3, _tLT, n03, accessKeySecretType, clientTokenType, AssumedRoleUser$, AssumeRoleRequest$, AssumeRoleResponse$, AssumeRoleWithWebIdentityRequest$, AssumeRoleWithWebIdentityResponse$, Credentials$, ExpiredTokenException$2, IDPCommunicationErrorException$, IDPRejectedClaimException$, InvalidIdentityTokenException$, MalformedPolicyDocumentException$, PackedPolicyTooLargeException$, PolicyDescriptorType$, ProvidedContext$, RegionDisabledException$, Tag$, STSServiceException$, policyDescriptorListType, ProvidedContextsListType, tagKeyListType, tagListType, AssumeRole$, AssumeRoleWithWebIdentity$;
var init_schemas_03 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/schemas/schemas_0.js"() {
    init_schema();
    init_errors3();
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
    _ETE2 = "ExpiredTokenException";
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
    _c3 = "client";
    _cTT = "clientTokenType";
    _e3 = "error";
    _hE3 = "httpError";
    _m2 = "message";
    _pDLT = "policyDescriptorListType";
    _s3 = "smithy.ts.sdk.synthetic.com.amazonaws.sts";
    _tLT = "tagListType";
    n03 = "com.amazonaws.sts";
    accessKeySecretType = [0, n03, _aKST, 8, 0];
    clientTokenType = [0, n03, _cTT, 8, 0];
    AssumedRoleUser$ = [3, n03, _ARU, 0, [_ARI, _A], [0, 0]];
    AssumeRoleRequest$ = [
      3,
      n03,
      _ARR,
      0,
      [_RA, _RSN, _PA, _P, _DS, _T, _TTK, _EI, _SN, _TC, _SI, _PC],
      [0, 0, () => policyDescriptorListType, 0, 1, () => tagListType, 64 | 0, 0, 0, 0, 0, () => ProvidedContextsListType]
    ];
    AssumeRoleResponse$ = [
      3,
      n03,
      _ARRs,
      0,
      [_C, _ARU, _PPS, _SI],
      [[() => Credentials$, 0], () => AssumedRoleUser$, 1, 0]
    ];
    AssumeRoleWithWebIdentityRequest$ = [
      3,
      n03,
      _ARWWIR,
      0,
      [_RA, _RSN, _WIT, _PI, _PA, _P, _DS],
      [0, 0, [() => clientTokenType, 0], 0, () => policyDescriptorListType, 0, 1]
    ];
    AssumeRoleWithWebIdentityResponse$ = [
      3,
      n03,
      _ARWWIRs,
      0,
      [_C, _SFWIT, _ARU, _PPS, _Pr, _Au, _SI],
      [[() => Credentials$, 0], 0, () => AssumedRoleUser$, 1, 0, 0, 0]
    ];
    Credentials$ = [
      3,
      n03,
      _C,
      0,
      [_AKI, _SAK, _ST, _E],
      [0, [() => accessKeySecretType, 0], 0, 4]
    ];
    ExpiredTokenException$2 = [
      -3,
      n03,
      _ETE2,
      { [_aQE]: [`ExpiredTokenException`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(ExpiredTokenException$2, ExpiredTokenException2);
    IDPCommunicationErrorException$ = [
      -3,
      n03,
      _IDPCEE,
      { [_aQE]: [`IDPCommunicationError`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(IDPCommunicationErrorException$, IDPCommunicationErrorException);
    IDPRejectedClaimException$ = [
      -3,
      n03,
      _IDPRCE,
      { [_aQE]: [`IDPRejectedClaim`, 403], [_e3]: _c3, [_hE3]: 403 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(IDPRejectedClaimException$, IDPRejectedClaimException);
    InvalidIdentityTokenException$ = [
      -3,
      n03,
      _IITE,
      { [_aQE]: [`InvalidIdentityToken`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(InvalidIdentityTokenException$, InvalidIdentityTokenException);
    MalformedPolicyDocumentException$ = [
      -3,
      n03,
      _MPDE,
      { [_aQE]: [`MalformedPolicyDocument`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(MalformedPolicyDocumentException$, MalformedPolicyDocumentException);
    PackedPolicyTooLargeException$ = [
      -3,
      n03,
      _PPTLE,
      { [_aQE]: [`PackedPolicyTooLarge`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(PackedPolicyTooLargeException$, PackedPolicyTooLargeException);
    PolicyDescriptorType$ = [3, n03, _PDT, 0, [_a], [0]];
    ProvidedContext$ = [3, n03, _PCr, 0, [_PAr, _CA], [0, 0]];
    RegionDisabledException$ = [
      -3,
      n03,
      _RDE,
      { [_aQE]: [`RegionDisabledException`, 403], [_e3]: _c3, [_hE3]: 403 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(RegionDisabledException$, RegionDisabledException);
    Tag$ = [3, n03, _Ta, 0, [_K, _V], [0, 0]];
    STSServiceException$ = [-3, _s3, "STSServiceException", 0, [], []];
    TypeRegistry.for(_s3).registerError(STSServiceException$, STSServiceException);
    policyDescriptorListType = [1, n03, _pDLT, 0, () => PolicyDescriptorType$];
    ProvidedContextsListType = [1, n03, _PCLT, 0, () => ProvidedContext$];
    tagKeyListType = 64 | 0;
    tagListType = [1, n03, _tLT, 0, () => Tag$];
    AssumeRole$ = [9, n03, _AR, 0, () => AssumeRoleRequest$, () => AssumeRoleResponse$];
    AssumeRoleWithWebIdentity$ = [
      9,
      n03,
      _ARWWI,
      0,
      () => AssumeRoleWithWebIdentityRequest$,
      () => AssumeRoleWithWebIdentityResponse$
    ];
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleCommand.js
var import_middleware_endpoint6, import_smithy_client27, AssumeRoleCommand;
var init_AssumeRoleCommand = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleCommand.js"() {
    import_middleware_endpoint6 = __toESM(require_dist_cjs34());
    import_smithy_client27 = __toESM(require_dist_cjs26());
    init_EndpointParameters3();
    init_schemas_03();
    AssumeRoleCommand = class extends import_smithy_client27.Command.classBuilder().ep(commonParams3).m(function(Command, cs, config, o4) {
      return [(0, import_middleware_endpoint6.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "AssumeRole", {}).n("STSClient", "AssumeRoleCommand").sc(AssumeRole$).build() {
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleWithWebIdentityCommand.js
var import_middleware_endpoint7, import_smithy_client28, AssumeRoleWithWebIdentityCommand;
var init_AssumeRoleWithWebIdentityCommand = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleWithWebIdentityCommand.js"() {
    import_middleware_endpoint7 = __toESM(require_dist_cjs34());
    import_smithy_client28 = __toESM(require_dist_cjs26());
    init_EndpointParameters3();
    init_schemas_03();
    AssumeRoleWithWebIdentityCommand = class extends import_smithy_client28.Command.classBuilder().ep(commonParams3).m(function(Command, cs, config, o4) {
      return [(0, import_middleware_endpoint7.getEndpointPlugin)(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithWebIdentity", {}).n("STSClient", "AssumeRoleWithWebIdentityCommand").sc(AssumeRoleWithWebIdentity$).build() {
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STS.js
var import_smithy_client29, commands3, STS;
var init_STS = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STS.js"() {
    import_smithy_client29 = __toESM(require_dist_cjs26());
    init_AssumeRoleCommand();
    init_AssumeRoleWithWebIdentityCommand();
    init_STSClient();
    commands3 = {
      AssumeRoleCommand,
      AssumeRoleWithWebIdentityCommand
    };
    STS = class extends STSClient {
    };
    (0, import_smithy_client29.createAggregatedClient)(commands3, STS);
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/index.js
var init_commands3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/index.js"() {
    init_AssumeRoleCommand();
    init_AssumeRoleWithWebIdentityCommand();
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/models_0.js
var init_models_03 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/models_0.js"() {
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultStsRoleAssumers.js
var import_region_config_resolver4, getAccountIdFromAssumedRoleUser, resolveRegion, getDefaultRoleAssumer, getDefaultRoleAssumerWithWebIdentity, isH2;
var init_defaultStsRoleAssumers = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultStsRoleAssumers.js"() {
    init_client();
    import_region_config_resolver4 = __toESM(require_dist_cjs45());
    init_AssumeRoleCommand();
    init_AssumeRoleWithWebIdentityCommand();
    getAccountIdFromAssumedRoleUser = (assumedRoleUser) => {
      if (typeof assumedRoleUser?.Arn === "string") {
        const arnComponents = assumedRoleUser.Arn.split(":");
        if (arnComponents.length > 4 && arnComponents[4] !== "") {
          return arnComponents[4];
        }
      }
      return void 0;
    };
    resolveRegion = async (_region, _parentRegion, credentialProviderLogger, loaderConfig = {}) => {
      const region = typeof _region === "function" ? await _region() : _region;
      const parentRegion = typeof _parentRegion === "function" ? await _parentRegion() : _parentRegion;
      let stsDefaultRegion = "";
      const resolvedRegion = region ?? parentRegion ?? (stsDefaultRegion = await (0, import_region_config_resolver4.stsRegionDefaultResolver)(loaderConfig)());
      credentialProviderLogger?.debug?.("@aws-sdk/client-sts::resolveRegion", "accepting first of:", `${region} (credential provider clientConfig)`, `${parentRegion} (contextual client)`, `${stsDefaultRegion} (STS default: AWS_REGION, profile region, or us-east-1)`);
      return resolvedRegion;
    };
    getDefaultRoleAssumer = (stsOptions, STSClient3) => {
      let stsClient;
      let closureSourceCreds;
      return async (sourceCreds, params) => {
        closureSourceCreds = sourceCreds;
        if (!stsClient) {
          const { logger: logger2 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
          const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
            logger: logger2,
            profile
          });
          const isCompatibleRequestHandler = !isH2(requestHandler);
          stsClient = new STSClient3({
            ...stsOptions,
            userAgentAppId,
            profile,
            credentialDefaultProvider: () => async () => closureSourceCreds,
            region: resolvedRegion,
            requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
            logger: logger2
          });
        }
        const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleCommand(params));
        if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) {
          throw new Error(`Invalid response from STS.assumeRole call with role ${params.RoleArn}`);
        }
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
    getDefaultRoleAssumerWithWebIdentity = (stsOptions, STSClient3) => {
      let stsClient;
      return async (params) => {
        if (!stsClient) {
          const { logger: logger2 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
          const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
            logger: logger2,
            profile
          });
          const isCompatibleRequestHandler = !isH2(requestHandler);
          stsClient = new STSClient3({
            ...stsOptions,
            userAgentAppId,
            profile,
            region: resolvedRegion,
            requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
            logger: logger2
          });
        }
        const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleWithWebIdentityCommand(params));
        if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) {
          throw new Error(`Invalid response from STS.assumeRoleWithWebIdentity call with role ${params.RoleArn}`);
        }
        const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
        const credentials = {
          accessKeyId: Credentials.AccessKeyId,
          secretAccessKey: Credentials.SecretAccessKey,
          sessionToken: Credentials.SessionToken,
          expiration: Credentials.Expiration,
          ...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
          ...accountId && { accountId }
        };
        if (accountId) {
          setCredentialFeature(credentials, "RESOLVED_ACCOUNT_ID", "T");
        }
        setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE_WEB_ID", "k");
        return credentials;
      };
    };
    isH2 = (requestHandler) => {
      return requestHandler?.metadata?.handlerProtocol === "h2";
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultRoleAssumers.js
var getCustomizableStsClientCtor, getDefaultRoleAssumer2, getDefaultRoleAssumerWithWebIdentity2, decorateDefaultCredentialProvider;
var init_defaultRoleAssumers = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultRoleAssumers.js"() {
    init_defaultStsRoleAssumers();
    init_STSClient();
    getCustomizableStsClientCtor = (baseCtor, customizations) => {
      if (!customizations)
        return baseCtor;
      else
        return class CustomizableSTSClient extends baseCtor {
          constructor(config) {
            super(config);
            for (const customization of customizations) {
              this.middlewareStack.use(customization);
            }
          }
        };
    };
    getDefaultRoleAssumer2 = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumer(stsOptions, getCustomizableStsClientCtor(STSClient, stsPlugins));
    getDefaultRoleAssumerWithWebIdentity2 = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumerWithWebIdentity(stsOptions, getCustomizableStsClientCtor(STSClient, stsPlugins));
    decorateDefaultCredentialProvider = (provider) => (input) => provider({
      roleAssumer: getDefaultRoleAssumer2(input),
      roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity2(input),
      ...input
    });
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/index.js
var sts_exports = {};
__export(sts_exports, {
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
  ExpiredTokenException: () => ExpiredTokenException2,
  ExpiredTokenException$: () => ExpiredTokenException$2,
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
  STSClient: () => STSClient,
  STSServiceException: () => STSServiceException,
  STSServiceException$: () => STSServiceException$,
  Tag$: () => Tag$,
  __Client: () => import_smithy_client25.Client,
  decorateDefaultCredentialProvider: () => decorateDefaultCredentialProvider,
  getDefaultRoleAssumer: () => getDefaultRoleAssumer2,
  getDefaultRoleAssumerWithWebIdentity: () => getDefaultRoleAssumerWithWebIdentity2
});
var init_sts = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/index.js"() {
    init_STSClient();
    init_STS();
    init_commands3();
    init_schemas_03();
    init_errors3();
    init_models_03();
    init_defaultRoleAssumers();
    init_STSServiceException();
  }
});

// node_modules/@aws-sdk/credential-provider-process/dist-cjs/index.js
var require_dist_cjs50 = __commonJS({
  "node_modules/@aws-sdk/credential-provider-process/dist-cjs/index.js"(exports) {
    "use strict";
    var sharedIniFileLoader = require_dist_cjs32();
    var propertyProvider = require_dist_cjs23();
    var child_process = __require("child_process");
    var util = __require("util");
    var client2 = (init_client(), __toCommonJS(client_exports));
    var getValidatedProcessCredentials = (profileName, data2, profiles) => {
      if (data2.Version !== 1) {
        throw Error(`Profile ${profileName} credential_process did not return Version 1.`);
      }
      if (data2.AccessKeyId === void 0 || data2.SecretAccessKey === void 0) {
        throw Error(`Profile ${profileName} credential_process returned invalid credentials.`);
      }
      if (data2.Expiration) {
        const currentTime = /* @__PURE__ */ new Date();
        const expireTime = new Date(data2.Expiration);
        if (expireTime < currentTime) {
          throw Error(`Profile ${profileName} credential_process returned expired credentials.`);
        }
      }
      let accountId = data2.AccountId;
      if (!accountId && profiles?.[profileName]?.aws_account_id) {
        accountId = profiles[profileName].aws_account_id;
      }
      const credentials = {
        accessKeyId: data2.AccessKeyId,
        secretAccessKey: data2.SecretAccessKey,
        ...data2.SessionToken && { sessionToken: data2.SessionToken },
        ...data2.Expiration && { expiration: new Date(data2.Expiration) },
        ...data2.CredentialScope && { credentialScope: data2.CredentialScope },
        ...accountId && { accountId }
      };
      client2.setCredentialFeature(credentials, "CREDENTIALS_PROCESS", "w");
      return credentials;
    };
    var resolveProcessCredentials = async (profileName, profiles, logger2) => {
      const profile = profiles[profileName];
      if (profiles[profileName]) {
        const credentialProcess = profile["credential_process"];
        if (credentialProcess !== void 0) {
          const execPromise = util.promisify(sharedIniFileLoader.externalDataInterceptor?.getTokenRecord?.().exec ?? child_process.exec);
          try {
            const { stdout } = await execPromise(credentialProcess);
            let data2;
            try {
              data2 = JSON.parse(stdout.trim());
            } catch {
              throw Error(`Profile ${profileName} credential_process returned invalid JSON.`);
            }
            return getValidatedProcessCredentials(profileName, data2, profiles);
          } catch (error2) {
            throw new propertyProvider.CredentialsProviderError(error2.message, { logger: logger2 });
          }
        } else {
          throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} did not contain credential_process.`, { logger: logger2 });
        }
      } else {
        throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} could not be found in shared credentials file.`, {
          logger: logger2
        });
      }
    };
    var fromProcess = (init = {}) => async ({ callerClientConfig } = {}) => {
      init.logger?.debug("@aws-sdk/credential-provider-process - fromProcess");
      const profiles = await sharedIniFileLoader.parseKnownFiles(init);
      return resolveProcessCredentials(sharedIniFileLoader.getProfileName({
        profile: init.profile ?? callerClientConfig?.profile
      }), profiles, init.logger);
    };
    exports.fromProcess = fromProcess;
  }
});

// node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/fromWebToken.js
var require_fromWebToken = __commonJS({
  "node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/fromWebToken.js"(exports) {
    "use strict";
    var __createBinding2 = exports && exports.__createBinding || (Object.create ? (function(o4, m4, k4, k22) {
      if (k22 === void 0) k22 = k4;
      var desc = Object.getOwnPropertyDescriptor(m4, k4);
      if (!desc || ("get" in desc ? !m4.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m4[k4];
        } };
      }
      Object.defineProperty(o4, k22, desc);
    }) : (function(o4, m4, k4, k22) {
      if (k22 === void 0) k22 = k4;
      o4[k22] = m4[k4];
    }));
    var __setModuleDefault2 = exports && exports.__setModuleDefault || (Object.create ? (function(o4, v4) {
      Object.defineProperty(o4, "default", { enumerable: true, value: v4 });
    }) : function(o4, v4) {
      o4["default"] = v4;
    });
    var __importStar2 = exports && exports.__importStar || /* @__PURE__ */ (function() {
      var ownKeys2 = function(o4) {
        ownKeys2 = Object.getOwnPropertyNames || function(o5) {
          var ar = [];
          for (var k4 in o5) if (Object.prototype.hasOwnProperty.call(o5, k4)) ar[ar.length] = k4;
          return ar;
        };
        return ownKeys2(o4);
      };
      return function(mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) {
          for (var k4 = ownKeys2(mod), i4 = 0; i4 < k4.length; i4++) if (k4[i4] !== "default") __createBinding2(result, mod, k4[i4]);
        }
        __setModuleDefault2(result, mod);
        return result;
      };
    })();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.fromWebToken = void 0;
    var fromWebToken = (init) => async (awsIdentityProperties) => {
      init.logger?.debug("@aws-sdk/credential-provider-web-identity - fromWebToken");
      const { roleArn, roleSessionName, webIdentityToken, providerId, policyArns, policy, durationSeconds } = init;
      let { roleAssumerWithWebIdentity } = init;
      if (!roleAssumerWithWebIdentity) {
        const { getDefaultRoleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity3 } = await Promise.resolve().then(() => __importStar2((init_sts(), __toCommonJS(sts_exports))));
        roleAssumerWithWebIdentity = getDefaultRoleAssumerWithWebIdentity3({
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
  }
});

// node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/fromTokenFile.js
var require_fromTokenFile = __commonJS({
  "node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/fromTokenFile.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.fromTokenFile = void 0;
    var client_1 = (init_client(), __toCommonJS(client_exports));
    var property_provider_1 = require_dist_cjs23();
    var shared_ini_file_loader_1 = require_dist_cjs32();
    var fs_1 = __require("fs");
    var fromWebToken_1 = require_fromWebToken();
    var ENV_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE";
    var ENV_ROLE_ARN = "AWS_ROLE_ARN";
    var ENV_ROLE_SESSION_NAME = "AWS_ROLE_SESSION_NAME";
    var fromTokenFile = (init = {}) => async (awsIdentityProperties) => {
      init.logger?.debug("@aws-sdk/credential-provider-web-identity - fromTokenFile");
      const webIdentityTokenFile = init?.webIdentityTokenFile ?? process.env[ENV_TOKEN_FILE];
      const roleArn = init?.roleArn ?? process.env[ENV_ROLE_ARN];
      const roleSessionName = init?.roleSessionName ?? process.env[ENV_ROLE_SESSION_NAME];
      if (!webIdentityTokenFile || !roleArn) {
        throw new property_provider_1.CredentialsProviderError("Web identity configuration not specified", {
          logger: init.logger
        });
      }
      const credentials = await (0, fromWebToken_1.fromWebToken)({
        ...init,
        webIdentityToken: shared_ini_file_loader_1.externalDataInterceptor?.getTokenRecord?.()[webIdentityTokenFile] ?? (0, fs_1.readFileSync)(webIdentityTokenFile, { encoding: "ascii" }),
        roleArn,
        roleSessionName
      })(awsIdentityProperties);
      if (webIdentityTokenFile === process.env[ENV_TOKEN_FILE]) {
        (0, client_1.setCredentialFeature)(credentials, "CREDENTIALS_ENV_VARS_STS_WEB_ID_TOKEN", "h");
      }
      return credentials;
    };
    exports.fromTokenFile = fromTokenFile;
  }
});

// node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/index.js
var require_dist_cjs51 = __commonJS({
  "node_modules/@aws-sdk/credential-provider-web-identity/dist-cjs/index.js"(exports) {
    "use strict";
    var fromTokenFile = require_fromTokenFile();
    var fromWebToken = require_fromWebToken();
    Object.keys(fromTokenFile).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return fromTokenFile[k4];
        }
      });
    });
    Object.keys(fromWebToken).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return fromWebToken[k4];
        }
      });
    });
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-cjs/index.js
var require_dist_cjs52 = __commonJS({
  "node_modules/@aws-sdk/credential-provider-ini/dist-cjs/index.js"(exports) {
    "use strict";
    var sharedIniFileLoader = require_dist_cjs32();
    var propertyProvider = require_dist_cjs23();
    var client2 = (init_client(), __toCommonJS(client_exports));
    var credentialProviderLogin = require_dist_cjs49();
    var resolveCredentialSource = (credentialSource, profileName, logger2) => {
      const sourceProvidersMap = {
        EcsContainer: async (options) => {
          const { fromHttp } = await Promise.resolve().then(() => __toESM(require_dist_cjs40()));
          const { fromContainerMetadata } = await Promise.resolve().then(() => __toESM(require_dist_cjs39()));
          logger2?.debug("@aws-sdk/credential-provider-ini - credential_source is EcsContainer");
          return async () => propertyProvider.chain(fromHttp(options ?? {}), fromContainerMetadata(options))().then(setNamedProvider);
        },
        Ec2InstanceMetadata: async (options) => {
          logger2?.debug("@aws-sdk/credential-provider-ini - credential_source is Ec2InstanceMetadata");
          const { fromInstanceMetadata } = await Promise.resolve().then(() => __toESM(require_dist_cjs39()));
          return async () => fromInstanceMetadata(options)().then(setNamedProvider);
        },
        Environment: async (options) => {
          logger2?.debug("@aws-sdk/credential-provider-ini - credential_source is Environment");
          const { fromEnv } = await Promise.resolve().then(() => __toESM(require_dist_cjs38()));
          return async () => fromEnv(options)().then(setNamedProvider);
        }
      };
      if (credentialSource in sourceProvidersMap) {
        return sourceProvidersMap[credentialSource];
      } else {
        throw new propertyProvider.CredentialsProviderError(`Unsupported credential source in profile ${profileName}. Got ${credentialSource}, expected EcsContainer or Ec2InstanceMetadata or Environment.`, { logger: logger2 });
      }
    };
    var setNamedProvider = (creds) => client2.setCredentialFeature(creds, "CREDENTIALS_PROFILE_NAMED_PROVIDER", "p");
    var isAssumeRoleProfile = (arg, { profile = "default", logger: logger2 } = {}) => {
      return Boolean(arg) && typeof arg === "object" && typeof arg.role_arn === "string" && ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1 && ["undefined", "string"].indexOf(typeof arg.external_id) > -1 && ["undefined", "string"].indexOf(typeof arg.mfa_serial) > -1 && (isAssumeRoleWithSourceProfile(arg, { profile, logger: logger2 }) || isCredentialSourceProfile(arg, { profile, logger: logger2 }));
    };
    var isAssumeRoleWithSourceProfile = (arg, { profile, logger: logger2 }) => {
      const withSourceProfile = typeof arg.source_profile === "string" && typeof arg.credential_source === "undefined";
      if (withSourceProfile) {
        logger2?.debug?.(`    ${profile} isAssumeRoleWithSourceProfile source_profile=${arg.source_profile}`);
      }
      return withSourceProfile;
    };
    var isCredentialSourceProfile = (arg, { profile, logger: logger2 }) => {
      const withProviderProfile = typeof arg.credential_source === "string" && typeof arg.source_profile === "undefined";
      if (withProviderProfile) {
        logger2?.debug?.(`    ${profile} isCredentialSourceProfile credential_source=${arg.credential_source}`);
      }
      return withProviderProfile;
    };
    var resolveAssumeRoleCredentials = async (profileName, profiles, options, callerClientConfig, visitedProfiles = {}, resolveProfileData2) => {
      options.logger?.debug("@aws-sdk/credential-provider-ini - resolveAssumeRoleCredentials (STS)");
      const profileData = profiles[profileName];
      const { source_profile, region } = profileData;
      if (!options.roleAssumer) {
        const { getDefaultRoleAssumer: getDefaultRoleAssumer3 } = await Promise.resolve().then(() => (init_sts(), sts_exports));
        options.roleAssumer = getDefaultRoleAssumer3({
          ...options.clientConfig,
          credentialProviderLogger: options.logger,
          parentClientConfig: {
            ...callerClientConfig,
            ...options?.parentClientConfig,
            region: region ?? options?.parentClientConfig?.region ?? callerClientConfig?.region
          }
        }, options.clientPlugins);
      }
      if (source_profile && source_profile in visitedProfiles) {
        throw new propertyProvider.CredentialsProviderError(`Detected a cycle attempting to resolve credentials for profile ${sharedIniFileLoader.getProfileName(options)}. Profiles visited: ` + Object.keys(visitedProfiles).join(", "), { logger: options.logger });
      }
      options.logger?.debug(`@aws-sdk/credential-provider-ini - finding credential resolver using ${source_profile ? `source_profile=[${source_profile}]` : `profile=[${profileName}]`}`);
      const sourceCredsProvider = source_profile ? resolveProfileData2(source_profile, profiles, options, callerClientConfig, {
        ...visitedProfiles,
        [source_profile]: true
      }, isCredentialSourceWithoutRoleArn(profiles[source_profile] ?? {})) : (await resolveCredentialSource(profileData.credential_source, profileName, options.logger)(options))();
      if (isCredentialSourceWithoutRoleArn(profileData)) {
        return sourceCredsProvider.then((creds) => client2.setCredentialFeature(creds, "CREDENTIALS_PROFILE_SOURCE_PROFILE", "o"));
      } else {
        const params = {
          RoleArn: profileData.role_arn,
          RoleSessionName: profileData.role_session_name || `aws-sdk-js-${Date.now()}`,
          ExternalId: profileData.external_id,
          DurationSeconds: parseInt(profileData.duration_seconds || "3600", 10)
        };
        const { mfa_serial } = profileData;
        if (mfa_serial) {
          if (!options.mfaCodeProvider) {
            throw new propertyProvider.CredentialsProviderError(`Profile ${profileName} requires multi-factor authentication, but no MFA code callback was provided.`, { logger: options.logger, tryNextLink: false });
          }
          params.SerialNumber = mfa_serial;
          params.TokenCode = await options.mfaCodeProvider(mfa_serial);
        }
        const sourceCreds = await sourceCredsProvider;
        return options.roleAssumer(sourceCreds, params).then((creds) => client2.setCredentialFeature(creds, "CREDENTIALS_PROFILE_SOURCE_PROFILE", "o"));
      }
    };
    var isCredentialSourceWithoutRoleArn = (section) => {
      return !section.role_arn && !!section.credential_source;
    };
    var isLoginProfile = (data2) => {
      return Boolean(data2 && data2.login_session);
    };
    var resolveLoginCredentials = async (profileName, options, callerClientConfig) => {
      const credentials = await credentialProviderLogin.fromLoginCredentials({
        ...options,
        profile: profileName
      })({ callerClientConfig });
      return client2.setCredentialFeature(credentials, "CREDENTIALS_PROFILE_LOGIN", "AC");
    };
    var isProcessProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.credential_process === "string";
    var resolveProcessCredentials = async (options, profile) => Promise.resolve().then(() => __toESM(require_dist_cjs50())).then(({ fromProcess }) => fromProcess({
      ...options,
      profile
    })().then((creds) => client2.setCredentialFeature(creds, "CREDENTIALS_PROFILE_PROCESS", "v")));
    var resolveSsoCredentials = async (profile, profileData, options = {}, callerClientConfig) => {
      const { fromSSO } = await Promise.resolve().then(() => __toESM(require_dist_cjs48()));
      return fromSSO({
        profile,
        logger: options.logger,
        parentClientConfig: options.parentClientConfig,
        clientConfig: options.clientConfig
      })({
        callerClientConfig
      }).then((creds) => {
        if (profileData.sso_session) {
          return client2.setCredentialFeature(creds, "CREDENTIALS_PROFILE_SSO", "r");
        } else {
          return client2.setCredentialFeature(creds, "CREDENTIALS_PROFILE_SSO_LEGACY", "t");
        }
      });
    };
    var isSsoProfile = (arg) => arg && (typeof arg.sso_start_url === "string" || typeof arg.sso_account_id === "string" || typeof arg.sso_session === "string" || typeof arg.sso_region === "string" || typeof arg.sso_role_name === "string");
    var isStaticCredsProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.aws_access_key_id === "string" && typeof arg.aws_secret_access_key === "string" && ["undefined", "string"].indexOf(typeof arg.aws_session_token) > -1 && ["undefined", "string"].indexOf(typeof arg.aws_account_id) > -1;
    var resolveStaticCredentials = async (profile, options) => {
      options?.logger?.debug("@aws-sdk/credential-provider-ini - resolveStaticCredentials");
      const credentials = {
        accessKeyId: profile.aws_access_key_id,
        secretAccessKey: profile.aws_secret_access_key,
        sessionToken: profile.aws_session_token,
        ...profile.aws_credential_scope && { credentialScope: profile.aws_credential_scope },
        ...profile.aws_account_id && { accountId: profile.aws_account_id }
      };
      return client2.setCredentialFeature(credentials, "CREDENTIALS_PROFILE", "n");
    };
    var isWebIdentityProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.web_identity_token_file === "string" && typeof arg.role_arn === "string" && ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1;
    var resolveWebIdentityCredentials = async (profile, options, callerClientConfig) => Promise.resolve().then(() => __toESM(require_dist_cjs51())).then(({ fromTokenFile }) => fromTokenFile({
      webIdentityTokenFile: profile.web_identity_token_file,
      roleArn: profile.role_arn,
      roleSessionName: profile.role_session_name,
      roleAssumerWithWebIdentity: options.roleAssumerWithWebIdentity,
      logger: options.logger,
      parentClientConfig: options.parentClientConfig
    })({
      callerClientConfig
    }).then((creds) => client2.setCredentialFeature(creds, "CREDENTIALS_PROFILE_STS_WEB_ID_TOKEN", "q")));
    var resolveProfileData = async (profileName, profiles, options, callerClientConfig, visitedProfiles = {}, isAssumeRoleRecursiveCall = false) => {
      const data2 = profiles[profileName];
      if (Object.keys(visitedProfiles).length > 0 && isStaticCredsProfile(data2)) {
        return resolveStaticCredentials(data2, options);
      }
      if (isAssumeRoleRecursiveCall || isAssumeRoleProfile(data2, { profile: profileName, logger: options.logger })) {
        return resolveAssumeRoleCredentials(profileName, profiles, options, callerClientConfig, visitedProfiles, resolveProfileData);
      }
      if (isStaticCredsProfile(data2)) {
        return resolveStaticCredentials(data2, options);
      }
      if (isWebIdentityProfile(data2)) {
        return resolveWebIdentityCredentials(data2, options, callerClientConfig);
      }
      if (isProcessProfile(data2)) {
        return resolveProcessCredentials(options, profileName);
      }
      if (isSsoProfile(data2)) {
        return await resolveSsoCredentials(profileName, data2, options, callerClientConfig);
      }
      if (isLoginProfile(data2)) {
        return resolveLoginCredentials(profileName, options, callerClientConfig);
      }
      throw new propertyProvider.CredentialsProviderError(`Could not resolve credentials using profile: [${profileName}] in configuration/credentials file(s).`, { logger: options.logger });
    };
    var fromIni = (init = {}) => async ({ callerClientConfig } = {}) => {
      init.logger?.debug("@aws-sdk/credential-provider-ini - fromIni");
      const profiles = await sharedIniFileLoader.parseKnownFiles(init);
      return resolveProfileData(sharedIniFileLoader.getProfileName({
        profile: init.profile ?? callerClientConfig?.profile
      }), profiles, init, callerClientConfig);
    };
    exports.fromIni = fromIni;
  }
});

// node_modules/@aws-sdk/credential-provider-node/dist-cjs/index.js
var require_dist_cjs53 = __commonJS({
  "node_modules/@aws-sdk/credential-provider-node/dist-cjs/index.js"(exports) {
    "use strict";
    var credentialProviderEnv = require_dist_cjs38();
    var propertyProvider = require_dist_cjs23();
    var sharedIniFileLoader = require_dist_cjs32();
    var ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
    var remoteProvider = async (init) => {
      const { ENV_CMDS_FULL_URI, ENV_CMDS_RELATIVE_URI, fromContainerMetadata, fromInstanceMetadata } = await Promise.resolve().then(() => __toESM(require_dist_cjs39()));
      if (process.env[ENV_CMDS_RELATIVE_URI] || process.env[ENV_CMDS_FULL_URI]) {
        init.logger?.debug("@aws-sdk/credential-provider-node - remoteProvider::fromHttp/fromContainerMetadata");
        const { fromHttp } = await Promise.resolve().then(() => __toESM(require_dist_cjs40()));
        return propertyProvider.chain(fromHttp(init), fromContainerMetadata(init));
      }
      if (process.env[ENV_IMDS_DISABLED] && process.env[ENV_IMDS_DISABLED] !== "false") {
        return async () => {
          throw new propertyProvider.CredentialsProviderError("EC2 Instance Metadata Service access disabled", { logger: init.logger });
        };
      }
      init.logger?.debug("@aws-sdk/credential-provider-node - remoteProvider::fromInstanceMetadata");
      return fromInstanceMetadata(init);
    };
    function memoizeChain(providers, treatAsExpired) {
      const chain = internalCreateChain(providers);
      let activeLock;
      let passiveLock;
      let credentials;
      const provider = async (options) => {
        if (options?.forceRefresh) {
          return await chain(options);
        }
        if (credentials?.expiration) {
          if (credentials?.expiration?.getTime() < Date.now()) {
            credentials = void 0;
          }
        }
        if (activeLock) {
          await activeLock;
        } else if (!credentials || treatAsExpired?.(credentials)) {
          if (credentials) {
            if (!passiveLock) {
              passiveLock = chain(options).then((c4) => {
                credentials = c4;
                passiveLock = void 0;
              });
            }
          } else {
            activeLock = chain(options).then((c4) => {
              credentials = c4;
              activeLock = void 0;
            });
            return provider(options);
          }
        }
        return credentials;
      };
      return provider;
    }
    var internalCreateChain = (providers) => async (awsIdentityProperties) => {
      let lastProviderError;
      for (const provider of providers) {
        try {
          return await provider(awsIdentityProperties);
        } catch (err) {
          lastProviderError = err;
          if (err?.tryNextLink) {
            continue;
          }
          throw err;
        }
      }
      throw lastProviderError;
    };
    var multipleCredentialSourceWarningEmitted = false;
    var defaultProvider = (init = {}) => memoizeChain([
      async () => {
        const profile = init.profile ?? process.env[sharedIniFileLoader.ENV_PROFILE];
        if (profile) {
          const envStaticCredentialsAreSet = process.env[credentialProviderEnv.ENV_KEY] && process.env[credentialProviderEnv.ENV_SECRET];
          if (envStaticCredentialsAreSet) {
            if (!multipleCredentialSourceWarningEmitted) {
              const warnFn = init.logger?.warn && init.logger?.constructor?.name !== "NoOpLogger" ? init.logger.warn.bind(init.logger) : console.warn;
              warnFn(`@aws-sdk/credential-provider-node - defaultProvider::fromEnv WARNING:
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
        if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) {
          throw new propertyProvider.CredentialsProviderError("Skipping SSO provider in default chain (inputs do not include SSO fields).", { logger: init.logger });
        }
        const { fromSSO } = await Promise.resolve().then(() => __toESM(require_dist_cjs48()));
        return fromSSO(init)(awsIdentityProperties);
      },
      async (awsIdentityProperties) => {
        init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromIni");
        const { fromIni } = await Promise.resolve().then(() => __toESM(require_dist_cjs52()));
        return fromIni(init)(awsIdentityProperties);
      },
      async (awsIdentityProperties) => {
        init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromProcess");
        const { fromProcess } = await Promise.resolve().then(() => __toESM(require_dist_cjs50()));
        return fromProcess(init)(awsIdentityProperties);
      },
      async (awsIdentityProperties) => {
        init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromTokenFile");
        const { fromTokenFile } = await Promise.resolve().then(() => __toESM(require_dist_cjs51()));
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
    var credentialsWillNeedRefresh = (credentials) => credentials?.expiration !== void 0;
    var credentialsTreatedAsExpired = (credentials) => credentials?.expiration !== void 0 && credentials.expiration.getTime() - Date.now() < 3e5;
    exports.credentialsTreatedAsExpired = credentialsTreatedAsExpired;
    exports.credentialsWillNeedRefresh = credentialsWillNeedRefresh;
    exports.defaultProvider = defaultProvider;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/ruleset.js
var require_ruleset2 = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/ruleset.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.ruleSet = void 0;
    var F2 = "required";
    var G2 = "type";
    var H2 = "fn";
    var I2 = "argv";
    var J2 = "ref";
    var a4 = false;
    var b4 = true;
    var c4 = "booleanEquals";
    var d4 = "stringEquals";
    var e4 = "sigv4";
    var f4 = "sts";
    var g4 = "us-east-1";
    var h4 = "endpoint";
    var i4 = "https://sts.{Region}.{PartitionResult#dnsSuffix}";
    var j4 = "tree";
    var k4 = "error";
    var l4 = "getAttr";
    var m4 = { [F2]: false, [G2]: "string" };
    var n4 = { [F2]: true, "default": false, [G2]: "boolean" };
    var o4 = { [J2]: "Endpoint" };
    var p4 = { [H2]: "isSet", [I2]: [{ [J2]: "Region" }] };
    var q4 = { [J2]: "Region" };
    var r4 = { [H2]: "aws.partition", [I2]: [q4], "assign": "PartitionResult" };
    var s4 = { [J2]: "UseFIPS" };
    var t4 = { [J2]: "UseDualStack" };
    var u4 = { "url": "https://sts.amazonaws.com", "properties": { "authSchemes": [{ "name": e4, "signingName": f4, "signingRegion": g4 }] }, "headers": {} };
    var v4 = {};
    var w4 = { "conditions": [{ [H2]: d4, [I2]: [q4, "aws-global"] }], [h4]: u4, [G2]: h4 };
    var x4 = { [H2]: c4, [I2]: [s4, true] };
    var y2 = { [H2]: c4, [I2]: [t4, true] };
    var z2 = { [H2]: l4, [I2]: [{ [J2]: "PartitionResult" }, "supportsFIPS"] };
    var A2 = { [J2]: "PartitionResult" };
    var B2 = { [H2]: c4, [I2]: [true, { [H2]: l4, [I2]: [A2, "supportsDualStack"] }] };
    var C2 = [{ [H2]: "isSet", [I2]: [o4] }];
    var D2 = [x4];
    var E2 = [y2];
    var _data4 = { version: "1.0", parameters: { Region: m4, UseDualStack: n4, UseFIPS: n4, Endpoint: m4, UseGlobalEndpoint: n4 }, rules: [{ conditions: [{ [H2]: c4, [I2]: [{ [J2]: "UseGlobalEndpoint" }, b4] }, { [H2]: "not", [I2]: C2 }, p4, r4, { [H2]: c4, [I2]: [s4, a4] }, { [H2]: c4, [I2]: [t4, a4] }], rules: [{ conditions: [{ [H2]: d4, [I2]: [q4, "ap-northeast-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "ap-south-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "ap-southeast-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "ap-southeast-2"] }], endpoint: u4, [G2]: h4 }, w4, { conditions: [{ [H2]: d4, [I2]: [q4, "ca-central-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "eu-central-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "eu-north-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "eu-west-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "eu-west-2"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "eu-west-3"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "sa-east-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, g4] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "us-east-2"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "us-west-1"] }], endpoint: u4, [G2]: h4 }, { conditions: [{ [H2]: d4, [I2]: [q4, "us-west-2"] }], endpoint: u4, [G2]: h4 }, { endpoint: { url: i4, properties: { authSchemes: [{ name: e4, signingName: f4, signingRegion: "{Region}" }] }, headers: v4 }, [G2]: h4 }], [G2]: j4 }, { conditions: C2, rules: [{ conditions: D2, error: "Invalid Configuration: FIPS and custom endpoint are not supported", [G2]: k4 }, { conditions: E2, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", [G2]: k4 }, { endpoint: { url: o4, properties: v4, headers: v4 }, [G2]: h4 }], [G2]: j4 }, { conditions: [p4], rules: [{ conditions: [r4], rules: [{ conditions: [x4, y2], rules: [{ conditions: [{ [H2]: c4, [I2]: [b4, z2] }, B2], rules: [{ endpoint: { url: "https://sts-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: v4, headers: v4 }, [G2]: h4 }], [G2]: j4 }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", [G2]: k4 }], [G2]: j4 }, { conditions: D2, rules: [{ conditions: [{ [H2]: c4, [I2]: [z2, b4] }], rules: [{ conditions: [{ [H2]: d4, [I2]: [{ [H2]: l4, [I2]: [A2, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://sts.{Region}.amazonaws.com", properties: v4, headers: v4 }, [G2]: h4 }, { endpoint: { url: "https://sts-fips.{Region}.{PartitionResult#dnsSuffix}", properties: v4, headers: v4 }, [G2]: h4 }], [G2]: j4 }, { error: "FIPS is enabled but this partition does not support FIPS", [G2]: k4 }], [G2]: j4 }, { conditions: E2, rules: [{ conditions: [B2], rules: [{ endpoint: { url: "https://sts.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: v4, headers: v4 }, [G2]: h4 }], [G2]: j4 }, { error: "DualStack is enabled but this partition does not support DualStack", [G2]: k4 }], [G2]: j4 }, w4, { endpoint: { url: i4, properties: v4, headers: v4 }, [G2]: h4 }], [G2]: j4 }], [G2]: j4 }, { error: "Invalid Configuration: Missing Region", [G2]: k4 }] };
    exports.ruleSet = _data4;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/endpointResolver.js
var require_endpointResolver2 = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/endpoint/endpointResolver.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.defaultEndpointResolver = void 0;
    var util_endpoints_1 = require_dist_cjs22();
    var util_endpoints_2 = require_dist_cjs19();
    var ruleset_1 = require_ruleset2();
    var cache4 = new util_endpoints_2.EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS", "UseGlobalEndpoint"]
    });
    var defaultEndpointResolver4 = (endpointParams, context = {}) => {
      return cache4.get(endpointParams, () => (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
        endpointParams,
        logger: context.logger
      }));
    };
    exports.defaultEndpointResolver = defaultEndpointResolver4;
    util_endpoints_2.customEndpointFunctions.aws = util_endpoints_1.awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/runtimeConfig.shared.js
var require_runtimeConfig_shared2 = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/runtimeConfig.shared.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getRuntimeConfig = void 0;
    var core_1 = (init_dist_es2(), __toCommonJS(dist_es_exports2));
    var protocols_1 = (init_protocols2(), __toCommonJS(protocols_exports2));
    var core_2 = (init_dist_es(), __toCommonJS(dist_es_exports));
    var smithy_client_1 = require_dist_cjs26();
    var url_parser_1 = require_dist_cjs21();
    var util_base64_1 = require_dist_cjs11();
    var util_utf8_1 = require_dist_cjs10();
    var httpAuthSchemeProvider_1 = require_httpAuthSchemeProvider();
    var endpointResolver_1 = require_endpointResolver2();
    var getRuntimeConfig7 = (config) => {
      return {
        apiVersion: "2011-06-15",
        base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
        base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? endpointResolver_1.defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? httpAuthSchemeProvider_1.defaultSTSHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new core_1.AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new core_2.NoAuthSigner()
          }
        ],
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
    exports.getRuntimeConfig = getRuntimeConfig7;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/runtimeConfig.js
var require_runtimeConfig2 = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/runtimeConfig.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getRuntimeConfig = void 0;
    var tslib_1 = (init_tslib_es6(), __toCommonJS(tslib_es6_exports));
    var package_json_1 = tslib_1.__importDefault(require_package());
    var core_1 = (init_dist_es2(), __toCommonJS(dist_es_exports2));
    var credential_provider_node_1 = require_dist_cjs53();
    var util_user_agent_node_1 = require_dist_cjs41();
    var config_resolver_1 = require_dist_cjs30();
    var core_2 = (init_dist_es(), __toCommonJS(dist_es_exports));
    var hash_node_1 = require_dist_cjs42();
    var middleware_retry_1 = require_dist_cjs37();
    var node_config_provider_1 = require_dist_cjs33();
    var node_http_handler_1 = require_dist_cjs14();
    var smithy_client_1 = require_dist_cjs26();
    var util_body_length_node_1 = require_dist_cjs43();
    var util_defaults_mode_node_1 = require_dist_cjs44();
    var util_retry_1 = require_dist_cjs36();
    var runtimeConfig_shared_1 = require_runtimeConfig_shared2();
    var getRuntimeConfig7 = (config) => {
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
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? (0, util_user_agent_node_1.createDefaultUserAgentProvider)({ serviceId: clientSharedValues.serviceId, clientVersion: package_json_1.default.version }),
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4") || (async (idProps) => await (0, credential_provider_node_1.defaultProvider)(idProps?.__config || {})()),
            signer: new core_1.AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new core_2.NoAuthSigner()
          }
        ],
        maxAttempts: config?.maxAttempts ?? (0, node_config_provider_1.loadConfig)(middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? (0, node_config_provider_1.loadConfig)(config_resolver_1.NODE_REGION_CONFIG_OPTIONS, { ...config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
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
    exports.getRuntimeConfig = getRuntimeConfig7;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/auth/httpAuthExtensionConfiguration.js
var require_httpAuthExtensionConfiguration = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/auth/httpAuthExtensionConfiguration.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.resolveHttpAuthRuntimeConfig = exports.getHttpAuthExtensionConfiguration = void 0;
    var getHttpAuthExtensionConfiguration4 = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
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
    exports.getHttpAuthExtensionConfiguration = getHttpAuthExtensionConfiguration4;
    var resolveHttpAuthRuntimeConfig4 = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials()
      };
    };
    exports.resolveHttpAuthRuntimeConfig = resolveHttpAuthRuntimeConfig4;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/runtimeExtensions.js
var require_runtimeExtensions = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/runtimeExtensions.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.resolveRuntimeExtensions = void 0;
    var region_config_resolver_1 = require_dist_cjs45();
    var protocol_http_1 = require_dist_cjs2();
    var smithy_client_1 = require_dist_cjs26();
    var httpAuthExtensionConfiguration_1 = require_httpAuthExtensionConfiguration();
    var resolveRuntimeExtensions4 = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign((0, region_config_resolver_1.getAwsRegionExtensionConfiguration)(runtimeConfig), (0, smithy_client_1.getDefaultExtensionConfiguration)(runtimeConfig), (0, protocol_http_1.getHttpHandlerExtensionConfiguration)(runtimeConfig), (0, httpAuthExtensionConfiguration_1.getHttpAuthExtensionConfiguration)(runtimeConfig));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig, (0, region_config_resolver_1.resolveAwsRegionExtensionConfiguration)(extensionConfiguration), (0, smithy_client_1.resolveDefaultRuntimeConfig)(extensionConfiguration), (0, protocol_http_1.resolveHttpHandlerRuntimeConfig)(extensionConfiguration), (0, httpAuthExtensionConfiguration_1.resolveHttpAuthRuntimeConfig)(extensionConfiguration));
    };
    exports.resolveRuntimeExtensions = resolveRuntimeExtensions4;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/STSClient.js
var require_STSClient = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/STSClient.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.STSClient = exports.__Client = void 0;
    var middleware_host_header_1 = require_dist_cjs3();
    var middleware_logger_1 = require_dist_cjs4();
    var middleware_recursion_detection_1 = require_dist_cjs5();
    var middleware_user_agent_1 = require_dist_cjs28();
    var config_resolver_1 = require_dist_cjs30();
    var core_1 = (init_dist_es(), __toCommonJS(dist_es_exports));
    var schema_1 = (init_schema(), __toCommonJS(schema_exports));
    var middleware_content_length_1 = require_dist_cjs31();
    var middleware_endpoint_1 = require_dist_cjs34();
    var middleware_retry_1 = require_dist_cjs37();
    var smithy_client_1 = require_dist_cjs26();
    Object.defineProperty(exports, "__Client", { enumerable: true, get: function() {
      return smithy_client_1.Client;
    } });
    var httpAuthSchemeProvider_1 = require_httpAuthSchemeProvider();
    var EndpointParameters_1 = require_EndpointParameters();
    var runtimeConfig_1 = require_runtimeConfig2();
    var runtimeExtensions_1 = require_runtimeExtensions();
    var STSClient3 = class extends smithy_client_1.Client {
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
        const _config_8 = (0, runtimeExtensions_1.resolveRuntimeExtensions)(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use((0, schema_1.getSchemaSerdePlugin)(this.config));
        this.middlewareStack.use((0, middleware_user_agent_1.getUserAgentPlugin)(this.config));
        this.middlewareStack.use((0, middleware_retry_1.getRetryPlugin)(this.config));
        this.middlewareStack.use((0, middleware_content_length_1.getContentLengthPlugin)(this.config));
        this.middlewareStack.use((0, middleware_host_header_1.getHostHeaderPlugin)(this.config));
        this.middlewareStack.use((0, middleware_logger_1.getLoggerPlugin)(this.config));
        this.middlewareStack.use((0, middleware_recursion_detection_1.getRecursionDetectionPlugin)(this.config));
        this.middlewareStack.use((0, core_1.getHttpAuthSchemeEndpointRuleSetPlugin)(this.config, {
          httpAuthSchemeParametersProvider: httpAuthSchemeProvider_1.defaultSTSHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new core_1.DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use((0, core_1.getHttpSigningPlugin)(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
    exports.STSClient = STSClient3;
  }
});

// node_modules/@aws-sdk/client-sts/dist-cjs/index.js
var require_dist_cjs54 = __commonJS({
  "node_modules/@aws-sdk/client-sts/dist-cjs/index.js"(exports) {
    "use strict";
    var STSClient3 = require_STSClient();
    var smithyClient = require_dist_cjs26();
    var middlewareEndpoint = require_dist_cjs34();
    var EndpointParameters = require_EndpointParameters();
    var schema = (init_schema(), __toCommonJS(schema_exports));
    var client2 = (init_client(), __toCommonJS(client_exports));
    var regionConfigResolver = require_dist_cjs45();
    var STSServiceException2 = class _STSServiceException extends smithyClient.ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _STSServiceException.prototype);
      }
    };
    var ExpiredTokenException3 = class _ExpiredTokenException extends STSServiceException2 {
      name = "ExpiredTokenException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "ExpiredTokenException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
      }
    };
    var MalformedPolicyDocumentException2 = class _MalformedPolicyDocumentException extends STSServiceException2 {
      name = "MalformedPolicyDocumentException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "MalformedPolicyDocumentException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _MalformedPolicyDocumentException.prototype);
      }
    };
    var PackedPolicyTooLargeException2 = class _PackedPolicyTooLargeException extends STSServiceException2 {
      name = "PackedPolicyTooLargeException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "PackedPolicyTooLargeException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _PackedPolicyTooLargeException.prototype);
      }
    };
    var RegionDisabledException2 = class _RegionDisabledException extends STSServiceException2 {
      name = "RegionDisabledException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "RegionDisabledException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _RegionDisabledException.prototype);
      }
    };
    var IDPRejectedClaimException2 = class _IDPRejectedClaimException extends STSServiceException2 {
      name = "IDPRejectedClaimException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "IDPRejectedClaimException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _IDPRejectedClaimException.prototype);
      }
    };
    var InvalidIdentityTokenException2 = class _InvalidIdentityTokenException extends STSServiceException2 {
      name = "InvalidIdentityTokenException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "InvalidIdentityTokenException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidIdentityTokenException.prototype);
      }
    };
    var IDPCommunicationErrorException2 = class _IDPCommunicationErrorException extends STSServiceException2 {
      name = "IDPCommunicationErrorException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "IDPCommunicationErrorException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _IDPCommunicationErrorException.prototype);
      }
    };
    var InvalidAuthorizationMessageException = class _InvalidAuthorizationMessageException extends STSServiceException2 {
      name = "InvalidAuthorizationMessageException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "InvalidAuthorizationMessageException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidAuthorizationMessageException.prototype);
      }
    };
    var ExpiredTradeInTokenException = class _ExpiredTradeInTokenException extends STSServiceException2 {
      name = "ExpiredTradeInTokenException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "ExpiredTradeInTokenException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ExpiredTradeInTokenException.prototype);
      }
    };
    var JWTPayloadSizeExceededException = class _JWTPayloadSizeExceededException extends STSServiceException2 {
      name = "JWTPayloadSizeExceededException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "JWTPayloadSizeExceededException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _JWTPayloadSizeExceededException.prototype);
      }
    };
    var OutboundWebIdentityFederationDisabledException = class _OutboundWebIdentityFederationDisabledException extends STSServiceException2 {
      name = "OutboundWebIdentityFederationDisabledException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "OutboundWebIdentityFederationDisabledException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _OutboundWebIdentityFederationDisabledException.prototype);
      }
    };
    var SessionDurationEscalationException = class _SessionDurationEscalationException extends STSServiceException2 {
      name = "SessionDurationEscalationException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "SessionDurationEscalationException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _SessionDurationEscalationException.prototype);
      }
    };
    var _A2 = "Arn";
    var _AKI2 = "AccessKeyId";
    var _AP = "AssumedPrincipal";
    var _AR2 = "AssumeRole";
    var _ARI2 = "AssumedRoleId";
    var _ARR2 = "AssumeRoleRequest";
    var _ARRs2 = "AssumeRoleResponse";
    var _ARRss = "AssumeRootRequest";
    var _ARRssu = "AssumeRootResponse";
    var _ARU2 = "AssumedRoleUser";
    var _ARWSAML = "AssumeRoleWithSAML";
    var _ARWSAMLR = "AssumeRoleWithSAMLRequest";
    var _ARWSAMLRs = "AssumeRoleWithSAMLResponse";
    var _ARWWI2 = "AssumeRoleWithWebIdentity";
    var _ARWWIR2 = "AssumeRoleWithWebIdentityRequest";
    var _ARWWIRs2 = "AssumeRoleWithWebIdentityResponse";
    var _ARs = "AssumeRoot";
    var _Ac = "Account";
    var _Au2 = "Audience";
    var _C2 = "Credentials";
    var _CA2 = "ContextAssertion";
    var _DAM = "DecodeAuthorizationMessage";
    var _DAMR = "DecodeAuthorizationMessageRequest";
    var _DAMRe = "DecodeAuthorizationMessageResponse";
    var _DM = "DecodedMessage";
    var _DS2 = "DurationSeconds";
    var _E2 = "Expiration";
    var _EI2 = "ExternalId";
    var _EM = "EncodedMessage";
    var _ETE3 = "ExpiredTokenException";
    var _ETITE = "ExpiredTradeInTokenException";
    var _FU = "FederatedUser";
    var _FUI = "FederatedUserId";
    var _GAKI = "GetAccessKeyInfo";
    var _GAKIR = "GetAccessKeyInfoRequest";
    var _GAKIRe = "GetAccessKeyInfoResponse";
    var _GCI = "GetCallerIdentity";
    var _GCIR = "GetCallerIdentityRequest";
    var _GCIRe = "GetCallerIdentityResponse";
    var _GDAT = "GetDelegatedAccessToken";
    var _GDATR = "GetDelegatedAccessTokenRequest";
    var _GDATRe = "GetDelegatedAccessTokenResponse";
    var _GFT = "GetFederationToken";
    var _GFTR = "GetFederationTokenRequest";
    var _GFTRe = "GetFederationTokenResponse";
    var _GST = "GetSessionToken";
    var _GSTR = "GetSessionTokenRequest";
    var _GSTRe = "GetSessionTokenResponse";
    var _GWIT = "GetWebIdentityToken";
    var _GWITR = "GetWebIdentityTokenRequest";
    var _GWITRe = "GetWebIdentityTokenResponse";
    var _I = "Issuer";
    var _IAME = "InvalidAuthorizationMessageException";
    var _IDPCEE2 = "IDPCommunicationErrorException";
    var _IDPRCE2 = "IDPRejectedClaimException";
    var _IITE2 = "InvalidIdentityTokenException";
    var _JWTPSEE = "JWTPayloadSizeExceededException";
    var _K2 = "Key";
    var _MPDE2 = "MalformedPolicyDocumentException";
    var _N = "Name";
    var _NQ = "NameQualifier";
    var _OWIFDE = "OutboundWebIdentityFederationDisabledException";
    var _P2 = "Policy";
    var _PA2 = "PolicyArns";
    var _PAr2 = "PrincipalArn";
    var _PAro = "ProviderArn";
    var _PC2 = "ProvidedContexts";
    var _PCLT2 = "ProvidedContextsListType";
    var _PCr2 = "ProvidedContext";
    var _PDT2 = "PolicyDescriptorType";
    var _PI2 = "ProviderId";
    var _PPS2 = "PackedPolicySize";
    var _PPTLE2 = "PackedPolicyTooLargeException";
    var _Pr2 = "Provider";
    var _RA2 = "RoleArn";
    var _RDE2 = "RegionDisabledException";
    var _RSN2 = "RoleSessionName";
    var _S = "Subject";
    var _SA = "SigningAlgorithm";
    var _SAK2 = "SecretAccessKey";
    var _SAMLA = "SAMLAssertion";
    var _SAMLAT = "SAMLAssertionType";
    var _SDEE = "SessionDurationEscalationException";
    var _SFWIT2 = "SubjectFromWebIdentityToken";
    var _SI2 = "SourceIdentity";
    var _SN2 = "SerialNumber";
    var _ST2 = "SubjectType";
    var _STe = "SessionToken";
    var _T2 = "Tags";
    var _TC2 = "TokenCode";
    var _TIT = "TradeInToken";
    var _TP = "TargetPrincipal";
    var _TPA = "TaskPolicyArn";
    var _TTK2 = "TransitiveTagKeys";
    var _Ta2 = "Tag";
    var _UI = "UserId";
    var _V2 = "Value";
    var _WIT2 = "WebIdentityToken";
    var _a2 = "arn";
    var _aKST2 = "accessKeySecretType";
    var _aQE2 = "awsQueryError";
    var _c4 = "client";
    var _cTT2 = "clientTokenType";
    var _e4 = "error";
    var _hE4 = "httpError";
    var _m3 = "message";
    var _pDLT2 = "policyDescriptorListType";
    var _s4 = "smithy.ts.sdk.synthetic.com.amazonaws.sts";
    var _tITT = "tradeInTokenType";
    var _tLT2 = "tagListType";
    var _wITT = "webIdentityTokenType";
    var n04 = "com.amazonaws.sts";
    var accessKeySecretType2 = [0, n04, _aKST2, 8, 0];
    var clientTokenType2 = [0, n04, _cTT2, 8, 0];
    var SAMLAssertionType = [0, n04, _SAMLAT, 8, 0];
    var tradeInTokenType = [0, n04, _tITT, 8, 0];
    var webIdentityTokenType = [0, n04, _wITT, 8, 0];
    var AssumedRoleUser$2 = [
      3,
      n04,
      _ARU2,
      0,
      [_ARI2, _A2],
      [0, 0]
    ];
    var AssumeRoleRequest$2 = [
      3,
      n04,
      _ARR2,
      0,
      [_RA2, _RSN2, _PA2, _P2, _DS2, _T2, _TTK2, _EI2, _SN2, _TC2, _SI2, _PC2],
      [0, 0, () => policyDescriptorListType2, 0, 1, () => tagListType2, 64 | 0, 0, 0, 0, 0, () => ProvidedContextsListType2]
    ];
    var AssumeRoleResponse$2 = [
      3,
      n04,
      _ARRs2,
      0,
      [_C2, _ARU2, _PPS2, _SI2],
      [[() => Credentials$2, 0], () => AssumedRoleUser$2, 1, 0]
    ];
    var AssumeRoleWithSAMLRequest$ = [
      3,
      n04,
      _ARWSAMLR,
      0,
      [_RA2, _PAr2, _SAMLA, _PA2, _P2, _DS2],
      [0, 0, [() => SAMLAssertionType, 0], () => policyDescriptorListType2, 0, 1]
    ];
    var AssumeRoleWithSAMLResponse$ = [
      3,
      n04,
      _ARWSAMLRs,
      0,
      [_C2, _ARU2, _PPS2, _S, _ST2, _I, _Au2, _NQ, _SI2],
      [[() => Credentials$2, 0], () => AssumedRoleUser$2, 1, 0, 0, 0, 0, 0, 0]
    ];
    var AssumeRoleWithWebIdentityRequest$2 = [
      3,
      n04,
      _ARWWIR2,
      0,
      [_RA2, _RSN2, _WIT2, _PI2, _PA2, _P2, _DS2],
      [0, 0, [() => clientTokenType2, 0], 0, () => policyDescriptorListType2, 0, 1]
    ];
    var AssumeRoleWithWebIdentityResponse$2 = [
      3,
      n04,
      _ARWWIRs2,
      0,
      [_C2, _SFWIT2, _ARU2, _PPS2, _Pr2, _Au2, _SI2],
      [[() => Credentials$2, 0], 0, () => AssumedRoleUser$2, 1, 0, 0, 0]
    ];
    var AssumeRootRequest$ = [
      3,
      n04,
      _ARRss,
      0,
      [_TP, _TPA, _DS2],
      [0, () => PolicyDescriptorType$2, 1]
    ];
    var AssumeRootResponse$ = [
      3,
      n04,
      _ARRssu,
      0,
      [_C2, _SI2],
      [[() => Credentials$2, 0], 0]
    ];
    var Credentials$2 = [
      3,
      n04,
      _C2,
      0,
      [_AKI2, _SAK2, _STe, _E2],
      [0, [() => accessKeySecretType2, 0], 0, 4]
    ];
    var DecodeAuthorizationMessageRequest$ = [
      3,
      n04,
      _DAMR,
      0,
      [_EM],
      [0]
    ];
    var DecodeAuthorizationMessageResponse$ = [
      3,
      n04,
      _DAMRe,
      0,
      [_DM],
      [0]
    ];
    var ExpiredTokenException$3 = [
      -3,
      n04,
      _ETE3,
      { [_aQE2]: [`ExpiredTokenException`, 400], [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(ExpiredTokenException$3, ExpiredTokenException3);
    var ExpiredTradeInTokenException$ = [
      -3,
      n04,
      _ETITE,
      { [_aQE2]: [`ExpiredTradeInTokenException`, 400], [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(ExpiredTradeInTokenException$, ExpiredTradeInTokenException);
    var FederatedUser$ = [
      3,
      n04,
      _FU,
      0,
      [_FUI, _A2],
      [0, 0]
    ];
    var GetAccessKeyInfoRequest$ = [
      3,
      n04,
      _GAKIR,
      0,
      [_AKI2],
      [0]
    ];
    var GetAccessKeyInfoResponse$ = [
      3,
      n04,
      _GAKIRe,
      0,
      [_Ac],
      [0]
    ];
    var GetCallerIdentityRequest$ = [
      3,
      n04,
      _GCIR,
      0,
      [],
      []
    ];
    var GetCallerIdentityResponse$ = [
      3,
      n04,
      _GCIRe,
      0,
      [_UI, _Ac, _A2],
      [0, 0, 0]
    ];
    var GetDelegatedAccessTokenRequest$ = [
      3,
      n04,
      _GDATR,
      0,
      [_TIT],
      [[() => tradeInTokenType, 0]]
    ];
    var GetDelegatedAccessTokenResponse$ = [
      3,
      n04,
      _GDATRe,
      0,
      [_C2, _PPS2, _AP],
      [[() => Credentials$2, 0], 1, 0]
    ];
    var GetFederationTokenRequest$ = [
      3,
      n04,
      _GFTR,
      0,
      [_N, _P2, _PA2, _DS2, _T2],
      [0, 0, () => policyDescriptorListType2, 1, () => tagListType2]
    ];
    var GetFederationTokenResponse$ = [
      3,
      n04,
      _GFTRe,
      0,
      [_C2, _FU, _PPS2],
      [[() => Credentials$2, 0], () => FederatedUser$, 1]
    ];
    var GetSessionTokenRequest$ = [
      3,
      n04,
      _GSTR,
      0,
      [_DS2, _SN2, _TC2],
      [1, 0, 0]
    ];
    var GetSessionTokenResponse$ = [
      3,
      n04,
      _GSTRe,
      0,
      [_C2],
      [[() => Credentials$2, 0]]
    ];
    var GetWebIdentityTokenRequest$ = [
      3,
      n04,
      _GWITR,
      0,
      [_Au2, _DS2, _SA, _T2],
      [64 | 0, 1, 0, () => tagListType2]
    ];
    var GetWebIdentityTokenResponse$ = [
      3,
      n04,
      _GWITRe,
      0,
      [_WIT2, _E2],
      [[() => webIdentityTokenType, 0], 4]
    ];
    var IDPCommunicationErrorException$2 = [
      -3,
      n04,
      _IDPCEE2,
      { [_aQE2]: [`IDPCommunicationError`, 400], [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(IDPCommunicationErrorException$2, IDPCommunicationErrorException2);
    var IDPRejectedClaimException$2 = [
      -3,
      n04,
      _IDPRCE2,
      { [_aQE2]: [`IDPRejectedClaim`, 403], [_e4]: _c4, [_hE4]: 403 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(IDPRejectedClaimException$2, IDPRejectedClaimException2);
    var InvalidAuthorizationMessageException$ = [
      -3,
      n04,
      _IAME,
      { [_aQE2]: [`InvalidAuthorizationMessageException`, 400], [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(InvalidAuthorizationMessageException$, InvalidAuthorizationMessageException);
    var InvalidIdentityTokenException$2 = [
      -3,
      n04,
      _IITE2,
      { [_aQE2]: [`InvalidIdentityToken`, 400], [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(InvalidIdentityTokenException$2, InvalidIdentityTokenException2);
    var JWTPayloadSizeExceededException$ = [
      -3,
      n04,
      _JWTPSEE,
      { [_aQE2]: [`JWTPayloadSizeExceededException`, 400], [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(JWTPayloadSizeExceededException$, JWTPayloadSizeExceededException);
    var MalformedPolicyDocumentException$2 = [
      -3,
      n04,
      _MPDE2,
      { [_aQE2]: [`MalformedPolicyDocument`, 400], [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(MalformedPolicyDocumentException$2, MalformedPolicyDocumentException2);
    var OutboundWebIdentityFederationDisabledException$ = [
      -3,
      n04,
      _OWIFDE,
      { [_aQE2]: [`OutboundWebIdentityFederationDisabledException`, 403], [_e4]: _c4, [_hE4]: 403 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(OutboundWebIdentityFederationDisabledException$, OutboundWebIdentityFederationDisabledException);
    var PackedPolicyTooLargeException$2 = [
      -3,
      n04,
      _PPTLE2,
      { [_aQE2]: [`PackedPolicyTooLarge`, 400], [_e4]: _c4, [_hE4]: 400 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(PackedPolicyTooLargeException$2, PackedPolicyTooLargeException2);
    var PolicyDescriptorType$2 = [
      3,
      n04,
      _PDT2,
      0,
      [_a2],
      [0]
    ];
    var ProvidedContext$2 = [
      3,
      n04,
      _PCr2,
      0,
      [_PAro, _CA2],
      [0, 0]
    ];
    var RegionDisabledException$2 = [
      -3,
      n04,
      _RDE2,
      { [_aQE2]: [`RegionDisabledException`, 403], [_e4]: _c4, [_hE4]: 403 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(RegionDisabledException$2, RegionDisabledException2);
    var SessionDurationEscalationException$ = [
      -3,
      n04,
      _SDEE,
      { [_aQE2]: [`SessionDurationEscalationException`, 403], [_e4]: _c4, [_hE4]: 403 },
      [_m3],
      [0]
    ];
    schema.TypeRegistry.for(n04).registerError(SessionDurationEscalationException$, SessionDurationEscalationException);
    var Tag$2 = [
      3,
      n04,
      _Ta2,
      0,
      [_K2, _V2],
      [0, 0]
    ];
    var STSServiceException$2 = [-3, _s4, "STSServiceException", 0, [], []];
    schema.TypeRegistry.for(_s4).registerError(STSServiceException$2, STSServiceException2);
    var policyDescriptorListType2 = [
      1,
      n04,
      _pDLT2,
      0,
      () => PolicyDescriptorType$2
    ];
    var ProvidedContextsListType2 = [
      1,
      n04,
      _PCLT2,
      0,
      () => ProvidedContext$2
    ];
    var tagListType2 = [
      1,
      n04,
      _tLT2,
      0,
      () => Tag$2
    ];
    var AssumeRole$2 = [
      9,
      n04,
      _AR2,
      0,
      () => AssumeRoleRequest$2,
      () => AssumeRoleResponse$2
    ];
    var AssumeRoleWithSAML$ = [
      9,
      n04,
      _ARWSAML,
      0,
      () => AssumeRoleWithSAMLRequest$,
      () => AssumeRoleWithSAMLResponse$
    ];
    var AssumeRoleWithWebIdentity$2 = [
      9,
      n04,
      _ARWWI2,
      0,
      () => AssumeRoleWithWebIdentityRequest$2,
      () => AssumeRoleWithWebIdentityResponse$2
    ];
    var AssumeRoot$ = [
      9,
      n04,
      _ARs,
      0,
      () => AssumeRootRequest$,
      () => AssumeRootResponse$
    ];
    var DecodeAuthorizationMessage$ = [
      9,
      n04,
      _DAM,
      0,
      () => DecodeAuthorizationMessageRequest$,
      () => DecodeAuthorizationMessageResponse$
    ];
    var GetAccessKeyInfo$ = [
      9,
      n04,
      _GAKI,
      0,
      () => GetAccessKeyInfoRequest$,
      () => GetAccessKeyInfoResponse$
    ];
    var GetCallerIdentity$ = [
      9,
      n04,
      _GCI,
      0,
      () => GetCallerIdentityRequest$,
      () => GetCallerIdentityResponse$
    ];
    var GetDelegatedAccessToken$ = [
      9,
      n04,
      _GDAT,
      0,
      () => GetDelegatedAccessTokenRequest$,
      () => GetDelegatedAccessTokenResponse$
    ];
    var GetFederationToken$ = [
      9,
      n04,
      _GFT,
      0,
      () => GetFederationTokenRequest$,
      () => GetFederationTokenResponse$
    ];
    var GetSessionToken$ = [
      9,
      n04,
      _GST,
      0,
      () => GetSessionTokenRequest$,
      () => GetSessionTokenResponse$
    ];
    var GetWebIdentityToken$ = [
      9,
      n04,
      _GWIT,
      0,
      () => GetWebIdentityTokenRequest$,
      () => GetWebIdentityTokenResponse$
    ];
    var AssumeRoleCommand2 = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "AssumeRole", {}).n("STSClient", "AssumeRoleCommand").sc(AssumeRole$2).build() {
    };
    var AssumeRoleWithSAMLCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithSAML", {}).n("STSClient", "AssumeRoleWithSAMLCommand").sc(AssumeRoleWithSAML$).build() {
    };
    var AssumeRoleWithWebIdentityCommand2 = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithWebIdentity", {}).n("STSClient", "AssumeRoleWithWebIdentityCommand").sc(AssumeRoleWithWebIdentity$2).build() {
    };
    var AssumeRootCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "AssumeRoot", {}).n("STSClient", "AssumeRootCommand").sc(AssumeRoot$).build() {
    };
    var DecodeAuthorizationMessageCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "DecodeAuthorizationMessage", {}).n("STSClient", "DecodeAuthorizationMessageCommand").sc(DecodeAuthorizationMessage$).build() {
    };
    var GetAccessKeyInfoCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "GetAccessKeyInfo", {}).n("STSClient", "GetAccessKeyInfoCommand").sc(GetAccessKeyInfo$).build() {
    };
    var GetCallerIdentityCommand2 = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "GetCallerIdentity", {}).n("STSClient", "GetCallerIdentityCommand").sc(GetCallerIdentity$).build() {
    };
    var GetDelegatedAccessTokenCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "GetDelegatedAccessToken", {}).n("STSClient", "GetDelegatedAccessTokenCommand").sc(GetDelegatedAccessToken$).build() {
    };
    var GetFederationTokenCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "GetFederationToken", {}).n("STSClient", "GetFederationTokenCommand").sc(GetFederationToken$).build() {
    };
    var GetSessionTokenCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "GetSessionToken", {}).n("STSClient", "GetSessionTokenCommand").sc(GetSessionToken$).build() {
    };
    var GetWebIdentityTokenCommand = class extends smithyClient.Command.classBuilder().ep(EndpointParameters.commonParams).m(function(Command, cs, config, o4) {
      return [middlewareEndpoint.getEndpointPlugin(config, Command.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "GetWebIdentityToken", {}).n("STSClient", "GetWebIdentityTokenCommand").sc(GetWebIdentityToken$).build() {
    };
    var commands4 = {
      AssumeRoleCommand: AssumeRoleCommand2,
      AssumeRoleWithSAMLCommand,
      AssumeRoleWithWebIdentityCommand: AssumeRoleWithWebIdentityCommand2,
      AssumeRootCommand,
      DecodeAuthorizationMessageCommand,
      GetAccessKeyInfoCommand,
      GetCallerIdentityCommand: GetCallerIdentityCommand2,
      GetDelegatedAccessTokenCommand,
      GetFederationTokenCommand,
      GetSessionTokenCommand,
      GetWebIdentityTokenCommand
    };
    var STS2 = class extends STSClient3.STSClient {
    };
    smithyClient.createAggregatedClient(commands4, STS2);
    var getAccountIdFromAssumedRoleUser2 = (assumedRoleUser) => {
      if (typeof assumedRoleUser?.Arn === "string") {
        const arnComponents = assumedRoleUser.Arn.split(":");
        if (arnComponents.length > 4 && arnComponents[4] !== "") {
          return arnComponents[4];
        }
      }
      return void 0;
    };
    var resolveRegion2 = async (_region, _parentRegion, credentialProviderLogger, loaderConfig = {}) => {
      const region = typeof _region === "function" ? await _region() : _region;
      const parentRegion = typeof _parentRegion === "function" ? await _parentRegion() : _parentRegion;
      let stsDefaultRegion = "";
      const resolvedRegion = region ?? parentRegion ?? (stsDefaultRegion = await regionConfigResolver.stsRegionDefaultResolver(loaderConfig)());
      credentialProviderLogger?.debug?.("@aws-sdk/client-sts::resolveRegion", "accepting first of:", `${region} (credential provider clientConfig)`, `${parentRegion} (contextual client)`, `${stsDefaultRegion} (STS default: AWS_REGION, profile region, or us-east-1)`);
      return resolvedRegion;
    };
    var getDefaultRoleAssumer$1 = (stsOptions, STSClient4) => {
      let stsClient;
      let closureSourceCreds;
      return async (sourceCreds, params) => {
        closureSourceCreds = sourceCreds;
        if (!stsClient) {
          const { logger: logger2 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
          const resolvedRegion = await resolveRegion2(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
            logger: logger2,
            profile
          });
          const isCompatibleRequestHandler = !isH22(requestHandler);
          stsClient = new STSClient4({
            ...stsOptions,
            userAgentAppId,
            profile,
            credentialDefaultProvider: () => async () => closureSourceCreds,
            region: resolvedRegion,
            requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
            logger: logger2
          });
        }
        const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleCommand2(params));
        if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) {
          throw new Error(`Invalid response from STS.assumeRole call with role ${params.RoleArn}`);
        }
        const accountId = getAccountIdFromAssumedRoleUser2(AssumedRoleUser);
        const credentials = {
          accessKeyId: Credentials.AccessKeyId,
          secretAccessKey: Credentials.SecretAccessKey,
          sessionToken: Credentials.SessionToken,
          expiration: Credentials.Expiration,
          ...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
          ...accountId && { accountId }
        };
        client2.setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE", "i");
        return credentials;
      };
    };
    var getDefaultRoleAssumerWithWebIdentity$1 = (stsOptions, STSClient4) => {
      let stsClient;
      return async (params) => {
        if (!stsClient) {
          const { logger: logger2 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
          const resolvedRegion = await resolveRegion2(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
            logger: logger2,
            profile
          });
          const isCompatibleRequestHandler = !isH22(requestHandler);
          stsClient = new STSClient4({
            ...stsOptions,
            userAgentAppId,
            profile,
            region: resolvedRegion,
            requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
            logger: logger2
          });
        }
        const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleWithWebIdentityCommand2(params));
        if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) {
          throw new Error(`Invalid response from STS.assumeRoleWithWebIdentity call with role ${params.RoleArn}`);
        }
        const accountId = getAccountIdFromAssumedRoleUser2(AssumedRoleUser);
        const credentials = {
          accessKeyId: Credentials.AccessKeyId,
          secretAccessKey: Credentials.SecretAccessKey,
          sessionToken: Credentials.SessionToken,
          expiration: Credentials.Expiration,
          ...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
          ...accountId && { accountId }
        };
        if (accountId) {
          client2.setCredentialFeature(credentials, "RESOLVED_ACCOUNT_ID", "T");
        }
        client2.setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE_WEB_ID", "k");
        return credentials;
      };
    };
    var isH22 = (requestHandler) => {
      return requestHandler?.metadata?.handlerProtocol === "h2";
    };
    var getCustomizableStsClientCtor2 = (baseCtor, customizations) => {
      if (!customizations)
        return baseCtor;
      else
        return class CustomizableSTSClient extends baseCtor {
          constructor(config) {
            super(config);
            for (const customization of customizations) {
              this.middlewareStack.use(customization);
            }
          }
        };
    };
    var getDefaultRoleAssumer3 = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumer$1(stsOptions, getCustomizableStsClientCtor2(STSClient3.STSClient, stsPlugins));
    var getDefaultRoleAssumerWithWebIdentity3 = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumerWithWebIdentity$1(stsOptions, getCustomizableStsClientCtor2(STSClient3.STSClient, stsPlugins));
    var decorateDefaultCredentialProvider2 = (provider) => (input) => provider({
      roleAssumer: getDefaultRoleAssumer3(input),
      roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity3(input),
      ...input
    });
    Object.defineProperty(exports, "$Command", {
      enumerable: true,
      get: function() {
        return smithyClient.Command;
      }
    });
    exports.AssumeRole$ = AssumeRole$2;
    exports.AssumeRoleCommand = AssumeRoleCommand2;
    exports.AssumeRoleRequest$ = AssumeRoleRequest$2;
    exports.AssumeRoleResponse$ = AssumeRoleResponse$2;
    exports.AssumeRoleWithSAML$ = AssumeRoleWithSAML$;
    exports.AssumeRoleWithSAMLCommand = AssumeRoleWithSAMLCommand;
    exports.AssumeRoleWithSAMLRequest$ = AssumeRoleWithSAMLRequest$;
    exports.AssumeRoleWithSAMLResponse$ = AssumeRoleWithSAMLResponse$;
    exports.AssumeRoleWithWebIdentity$ = AssumeRoleWithWebIdentity$2;
    exports.AssumeRoleWithWebIdentityCommand = AssumeRoleWithWebIdentityCommand2;
    exports.AssumeRoleWithWebIdentityRequest$ = AssumeRoleWithWebIdentityRequest$2;
    exports.AssumeRoleWithWebIdentityResponse$ = AssumeRoleWithWebIdentityResponse$2;
    exports.AssumeRoot$ = AssumeRoot$;
    exports.AssumeRootCommand = AssumeRootCommand;
    exports.AssumeRootRequest$ = AssumeRootRequest$;
    exports.AssumeRootResponse$ = AssumeRootResponse$;
    exports.AssumedRoleUser$ = AssumedRoleUser$2;
    exports.Credentials$ = Credentials$2;
    exports.DecodeAuthorizationMessage$ = DecodeAuthorizationMessage$;
    exports.DecodeAuthorizationMessageCommand = DecodeAuthorizationMessageCommand;
    exports.DecodeAuthorizationMessageRequest$ = DecodeAuthorizationMessageRequest$;
    exports.DecodeAuthorizationMessageResponse$ = DecodeAuthorizationMessageResponse$;
    exports.ExpiredTokenException = ExpiredTokenException3;
    exports.ExpiredTokenException$ = ExpiredTokenException$3;
    exports.ExpiredTradeInTokenException = ExpiredTradeInTokenException;
    exports.ExpiredTradeInTokenException$ = ExpiredTradeInTokenException$;
    exports.FederatedUser$ = FederatedUser$;
    exports.GetAccessKeyInfo$ = GetAccessKeyInfo$;
    exports.GetAccessKeyInfoCommand = GetAccessKeyInfoCommand;
    exports.GetAccessKeyInfoRequest$ = GetAccessKeyInfoRequest$;
    exports.GetAccessKeyInfoResponse$ = GetAccessKeyInfoResponse$;
    exports.GetCallerIdentity$ = GetCallerIdentity$;
    exports.GetCallerIdentityCommand = GetCallerIdentityCommand2;
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
    exports.IDPCommunicationErrorException = IDPCommunicationErrorException2;
    exports.IDPCommunicationErrorException$ = IDPCommunicationErrorException$2;
    exports.IDPRejectedClaimException = IDPRejectedClaimException2;
    exports.IDPRejectedClaimException$ = IDPRejectedClaimException$2;
    exports.InvalidAuthorizationMessageException = InvalidAuthorizationMessageException;
    exports.InvalidAuthorizationMessageException$ = InvalidAuthorizationMessageException$;
    exports.InvalidIdentityTokenException = InvalidIdentityTokenException2;
    exports.InvalidIdentityTokenException$ = InvalidIdentityTokenException$2;
    exports.JWTPayloadSizeExceededException = JWTPayloadSizeExceededException;
    exports.JWTPayloadSizeExceededException$ = JWTPayloadSizeExceededException$;
    exports.MalformedPolicyDocumentException = MalformedPolicyDocumentException2;
    exports.MalformedPolicyDocumentException$ = MalformedPolicyDocumentException$2;
    exports.OutboundWebIdentityFederationDisabledException = OutboundWebIdentityFederationDisabledException;
    exports.OutboundWebIdentityFederationDisabledException$ = OutboundWebIdentityFederationDisabledException$;
    exports.PackedPolicyTooLargeException = PackedPolicyTooLargeException2;
    exports.PackedPolicyTooLargeException$ = PackedPolicyTooLargeException$2;
    exports.PolicyDescriptorType$ = PolicyDescriptorType$2;
    exports.ProvidedContext$ = ProvidedContext$2;
    exports.RegionDisabledException = RegionDisabledException2;
    exports.RegionDisabledException$ = RegionDisabledException$2;
    exports.STS = STS2;
    exports.STSServiceException = STSServiceException2;
    exports.STSServiceException$ = STSServiceException$2;
    exports.SessionDurationEscalationException = SessionDurationEscalationException;
    exports.SessionDurationEscalationException$ = SessionDurationEscalationException$;
    exports.Tag$ = Tag$2;
    exports.decorateDefaultCredentialProvider = decorateDefaultCredentialProvider2;
    exports.getDefaultRoleAssumer = getDefaultRoleAssumer3;
    exports.getDefaultRoleAssumerWithWebIdentity = getDefaultRoleAssumerWithWebIdentity3;
    Object.keys(STSClient3).forEach(function(k4) {
      if (k4 !== "default" && !Object.prototype.hasOwnProperty.call(exports, k4)) Object.defineProperty(exports, k4, {
        enumerable: true,
        get: function() {
          return STSClient3[k4];
        }
      });
    });
  }
});

// src/utils/__fixtures__/v3/index.js
var import_client_sts = __toESM(require_dist_cjs54());
var client = new import_client_sts.STSClient();
var handler = async () => client.send(new import_client_sts.GetCallerIdentityCommand());
export {
  handler
};
