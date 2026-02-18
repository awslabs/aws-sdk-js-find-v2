import { createRequire as __WEBPACK_EXTERNAL_createRequire } from "node:module";
const __WEBPACK_EXTERNAL_createRequire_require = __WEBPACK_EXTERNAL_createRequire(import.meta.url);
/******/ var __webpack_modules__ = ({

/***/ 8825
(module, __unused_webpack_exports, __webpack_require__) {

__webpack_require__(4129);
var AWS = __webpack_require__(9132);
var Service = AWS.Service;
var apiLoader = AWS.apiLoader;

apiLoader.services['cognitoidentity'] = {};
AWS.CognitoIdentity = Service.defineService('cognitoidentity', ['2014-06-30']);
Object.defineProperty(apiLoader.services['cognitoidentity'], '2014-06-30', {
  get: function get() {
    var model = __webpack_require__(6607);
    model.paginators = (__webpack_require__(6741)/* .pagination */ .X);
    return model;
  },
  enumerable: true,
  configurable: true
});

module.exports = AWS.CognitoIdentity;


/***/ },

/***/ 2788
(module, __unused_webpack_exports, __webpack_require__) {

__webpack_require__(4129);
var AWS = __webpack_require__(9132);
var Service = AWS.Service;
var apiLoader = AWS.apiLoader;

apiLoader.services['sts'] = {};
AWS.STS = Service.defineService('sts', ['2011-06-15']);
__webpack_require__(2632);
Object.defineProperty(apiLoader.services['sts'], '2011-06-15', {
  get: function get() {
    var model = __webpack_require__(9105);
    model.paginators = (__webpack_require__(4747)/* .pagination */ .X);
    return model;
  },
  enumerable: true,
  configurable: true
});

module.exports = AWS.STS;


/***/ },

/***/ 9701
(module) {

function apiLoader(svc, version) {
  if (!apiLoader.services.hasOwnProperty(svc)) {
    throw new Error('InvalidService: Failed to load api for ' + svc);
  }
  return apiLoader.services[svc][version];
}

/**
 * @api private
 *
 * This member of AWS.apiLoader is private, but changing it will necessitate a
 * change to ../scripts/services-table-generator.ts
 */
apiLoader.services = {};

/**
 * @api private
 */
module.exports = apiLoader;


/***/ },

/***/ 4089
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
__webpack_require__(1833);
__webpack_require__(4279);
var PromisesDependency;

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
 */
AWS.Config = AWS.util.inherit({
  /**
   * @!endgroup
   */

  /**
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
   */
  constructor: function Config(options) {
    if (options === undefined) options = {};
    options = this.extractCredentials(options);

    AWS.util.each.call(this, this.keys, function (key, value) {
      this.set(key, options[key], value);
    });
  },

  /**
   * @!group Managing Credentials
   */

  /**
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
   */
  getCredentials: function getCredentials(callback) {
    var self = this;

    function finish(err) {
      callback(err, err ? null : self.credentials);
    }

    function credError(msg, err) {
      return new AWS.util.error(err || new Error(), {
        code: 'CredentialsError',
        message: msg,
        name: 'CredentialsError'
      });
    }

    function getAsyncCredentials() {
      self.credentials.get(function(err) {
        if (err) {
          var msg = 'Could not load credentials from ' +
            self.credentials.constructor.name;
          err = credError(msg, err);
        }
        finish(err);
      });
    }

    function getStaticCredentials() {
      var err = null;
      if (!self.credentials.accessKeyId || !self.credentials.secretAccessKey) {
        err = credError('Missing credentials');
      }
      finish(err);
    }

    if (self.credentials) {
      if (typeof self.credentials.get === 'function') {
        getAsyncCredentials();
      } else { // static credentials
        getStaticCredentials();
      }
    } else if (self.credentialProvider) {
      self.credentialProvider.resolve(function(err, creds) {
        if (err) {
          err = credError('Could not load credentials from any providers', err);
        }
        self.credentials = creds;
        finish(err);
      });
    } else {
      finish(credError('No credentials to load'));
    }
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
   */
  getToken: function getToken(callback) {
    var self = this;

    function finish(err) {
      callback(err, err ? null : self.token);
    }

    function tokenError(msg, err) {
      return new AWS.util.error(err || new Error(), {
        code: 'TokenError',
        message: msg,
        name: 'TokenError'
      });
    }

    function getAsyncToken() {
      self.token.get(function(err) {
        if (err) {
          var msg = 'Could not load token from ' +
            self.token.constructor.name;
          err = tokenError(msg, err);
        }
        finish(err);
      });
    }

    function getStaticToken() {
      var err = null;
      if (!self.token.token) {
        err = tokenError('Missing token');
      }
      finish(err);
    }

    if (self.token) {
      if (typeof self.token.get === 'function') {
        getAsyncToken();
      } else { // static token
        getStaticToken();
      }
    } else if (self.tokenProvider) {
      self.tokenProvider.resolve(function(err, token) {
        if (err) {
          err = tokenError('Could not load token from any providers', err);
        }
        self.token = token;
        finish(err);
      });
    } else {
      finish(tokenError('No token to load'));
    }
  },

  /**
   * @!group Loading and Setting Configuration Options
   */

  /**
   * @overload update(options, allowUnknownKeys = false)
   *   Updates the current configuration object with new options.
   *
   *   @example Update maxRetries property of a configuration object
   *     config.update({maxRetries: 10});
   *   @param [Object] options a map of option keys and values.
   *   @param [Boolean] allowUnknownKeys whether unknown keys can be set on
   *     the configuration object. Defaults to `false`.
   *   @see constructor
   */
  update: function update(options, allowUnknownKeys) {
    allowUnknownKeys = allowUnknownKeys || false;
    options = this.extractCredentials(options);
    AWS.util.each.call(this, options, function (key, value) {
      if (allowUnknownKeys || Object.prototype.hasOwnProperty.call(this.keys, key) ||
          AWS.Service.hasService(key)) {
        this.set(key, value);
      }
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
   */
  loadFromPath: function loadFromPath(path) {
    this.clear();

    var options = JSON.parse(AWS.util.readFileSync(path));
    var fileSystemCreds = new AWS.FileSystemCredentials(path);
    var chain = new AWS.CredentialProviderChain();
    chain.providers.unshift(fileSystemCreds);
    chain.resolve(function (err, creds) {
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
   */
  clear: function clear() {
    /*jshint forin:false */
    AWS.util.each.call(this, this.keys, function (key) {
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
   */
  set: function set(property, value, defaultValue) {
    if (value === undefined) {
      if (defaultValue === undefined) {
        defaultValue = this.keys[property];
      }
      if (typeof defaultValue === 'function') {
        this[property] = defaultValue.call(this);
      } else {
        this[property] = defaultValue;
      }
    } else if (property === 'httpOptions' && this[property]) {
      // deep merge httpOptions
      this[property] = AWS.util.merge(this[property], value);
    } else {
      this[property] = value;
    }
  },

  /**
   * All of the keys with their default values.
   *
   * @constant
   * @api private
   */
  keys: {
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
   */
  extractCredentials: function extractCredentials(options) {
    if (options.accessKeyId && options.secretAccessKey) {
      options = AWS.util.copy(options);
      options.credentials = new AWS.Credentials(options);
    }
    return options;
  },

  /**
   * Sets the promise dependency the SDK will use wherever Promises are returned.
   * Passing `null` will force the SDK to use native Promises if they are available.
   * If native Promises are not available, passing `null` will have no effect.
   * @param [Constructor] dep A reference to a Promise constructor
   */
  setPromisesDependency: function setPromisesDependency(dep) {
    PromisesDependency = dep;
    // if null was passed in, we should try to use native promises
    if (dep === null && typeof Promise === 'function') {
      PromisesDependency = Promise;
    }
    var constructors = [AWS.Request, AWS.Credentials, AWS.CredentialProviderChain];
    if (AWS.S3) {
      constructors.push(AWS.S3);
      if (AWS.S3.ManagedUpload) {
        constructors.push(AWS.S3.ManagedUpload);
      }
    }
    AWS.util.addPromises(constructors, PromisesDependency);
  },

  /**
   * Gets the promise dependency set by `AWS.config.setPromisesDependency`.
   */
  getPromisesDependency: function getPromisesDependency() {
    return PromisesDependency;
  }
});

/**
 * @return [AWS.Config] The global configuration object singleton instance
 * @readonly
 * @see AWS.Config
 */
AWS.config = new AWS.Config();


/***/ },

/***/ 8497
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
/**
 * @api private
 */
function validateRegionalEndpointsFlagValue(configValue, errorOptions) {
  if (typeof configValue !== 'string') return undefined;
  else if (['legacy', 'regional'].indexOf(configValue.toLowerCase()) >= 0) {
    return configValue.toLowerCase();
  } else {
    throw AWS.util.error(new Error(), errorOptions);
  }
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
 */
function resolveRegionalEndpointsFlag(originalConfig, options) {
  originalConfig = originalConfig || {};
  //validate config value
  var resolved;
  if (originalConfig[options.clientConfig]) {
    resolved = validateRegionalEndpointsFlagValue(originalConfig[options.clientConfig], {
      code: 'InvalidConfiguration',
      message: 'invalid "' + options.clientConfig + '" configuration. Expect "legacy" ' +
      ' or "regional". Got "' + originalConfig[options.clientConfig] + '".'
    });
    if (resolved) return resolved;
  }
  if (!AWS.util.isNode()) return resolved;
  //validate environmental variable
  if (Object.prototype.hasOwnProperty.call(process.env, options.env)) {
    var envFlag = process.env[options.env];
    resolved = validateRegionalEndpointsFlagValue(envFlag, {
      code: 'InvalidEnvironmentalVariable',
      message: 'invalid ' + options.env + ' environmental variable. Expect "legacy" ' +
      ' or "regional". Got "' + process.env[options.env] + '".'
    });
    if (resolved) return resolved;
  }
  //validate shared config file
  var profile = {};
  try {
    var profiles = AWS.util.getProfilesFromSharedConfig(AWS.util.iniLoader);
    profile = profiles[process.env.AWS_PROFILE || AWS.util.defaultProfile];
  } catch (e) {};
  if (profile && Object.prototype.hasOwnProperty.call(profile, options.sharedConfig)) {
    var fileFlag = profile[options.sharedConfig];
    resolved = validateRegionalEndpointsFlagValue(fileFlag, {
      code: 'InvalidConfiguration',
      message: 'invalid ' + options.sharedConfig + ' profile config. Expect "legacy" ' +
      ' or "regional". Got "' + profile[options.sharedConfig] + '".'
    });
    if (resolved) return resolved;
  }
  return resolved;
}

module.exports = resolveRegionalEndpointsFlag;


/***/ },

/***/ 9132
(module, __unused_webpack_exports, __webpack_require__) {

/**
 * The main AWS namespace
 */
var AWS = { util: __webpack_require__(9019) };

/**
 * @api private
 * @!macro [new] nobrowser
 *   @note This feature is not supported in the browser environment of the SDK.
 */
var _hidden = {}; _hidden.toString(); // hack to parse macro

/**
 * @api private
 */
module.exports = AWS;

AWS.util.update(AWS, {

  /**
   * @constant
   */
  VERSION: '2.1693.0',

  /**
   * @api private
   */
  Signers: {},

  /**
   * @api private
   */
  Protocol: {
    Json: __webpack_require__(3652),
    Query: __webpack_require__(324),
    Rest: __webpack_require__(9648),
    RestJson: __webpack_require__(5897),
    RestXml: __webpack_require__(5830)
  },

  /**
   * @api private
   */
  XML: {
    Builder: __webpack_require__(1838),
    Parser: null // conditionally set based on environment
  },

  /**
   * @api private
   */
  JSON: {
    Builder: __webpack_require__(3681),
    Parser: __webpack_require__(5919)
  },

  /**
   * @api private
   */
  Model: {
    Api: __webpack_require__(9341),
    Operation: __webpack_require__(6176),
    Shape: __webpack_require__(1304),
    Paginator: __webpack_require__(8910),
    ResourceWaiter: __webpack_require__(3110)
  },

  /**
   * @api private
   */
  apiLoader: __webpack_require__(9701),

  /**
   * @api private
   */
  EndpointCache: (__webpack_require__(5593)/* .EndpointCache */ .k)
});
__webpack_require__(5138);
__webpack_require__(5400);
__webpack_require__(4089);
__webpack_require__(5615);
__webpack_require__(5585);
__webpack_require__(4002);
__webpack_require__(4396);
__webpack_require__(4344);
__webpack_require__(7383);
__webpack_require__(1215);
__webpack_require__(2520);

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
 */
AWS.events = new AWS.SequentialExecutor();

//create endpoint cache lazily
AWS.util.memoizedProperty(AWS, 'endpointCache', function() {
  return new AWS.EndpointCache(AWS.config.endpointCacheSize);
}, true);


/***/ },

/***/ 1833
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

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
 */
AWS.Credentials = AWS.util.inherit({
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
   */
  constructor: function Credentials() {
    // hide secretAccessKey from being displayed with util.inspect
    AWS.util.hideProperties(this, ['secretAccessKey']);

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
   */
  expiryWindow: 15,

  /**
   * @return [Boolean] whether the credentials object should call {refresh}
   * @note Subclasses should override this method to provide custom refresh
   *   logic.
   */
  needsRefresh: function needsRefresh() {
    var currentTime = AWS.util.date.getDate().getTime();
    var adjustedTime = new Date(currentTime + this.expiryWindow * 1000);

    if (this.expireTime && adjustedTime > this.expireTime) {
      return true;
    } else {
      return this.expired || !this.accessKeyId || !this.secretAccessKey;
    }
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
   */
  get: function get(callback) {
    var self = this;
    if (this.needsRefresh()) {
      this.refresh(function(err) {
        if (!err) self.expired = false; // reset expired flag
        if (callback) callback(err);
      });
    } else if (callback) {
      callback();
    }
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
   */

  /**
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
   */

  /**
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
   */
  refresh: function refresh(callback) {
    this.expired = false;
    callback();
  },

  /**
   * @api private
   * @param callback
   */
  coalesceRefresh: function coalesceRefresh(callback, sync) {
    var self = this;
    if (self.refreshCallbacks.push(callback) === 1) {
      self.load(function onLoad(err) {
        AWS.util.arrayEach(self.refreshCallbacks, function(callback) {
          if (sync) {
            callback(err);
          } else {
            // callback could throw, so defer to ensure all callbacks are notified
            AWS.util.defer(function () {
              callback(err);
            });
          }
        });
        self.refreshCallbacks.length = 0;
      });
    }
  },

  /**
   * @api private
   * @param callback
   */
  load: function load(callback) {
    callback();
  }
});

/**
 * @api private
 */
AWS.Credentials.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
  this.prototype.getPromise = AWS.util.promisifyMethod('get', PromiseDependency);
  this.prototype.refreshPromise = AWS.util.promisifyMethod('refresh', PromiseDependency);
};

/**
 * @api private
 */
AWS.Credentials.deletePromisesFromClass = function deletePromisesFromClass() {
  delete this.prototype.getPromise;
  delete this.prototype.refreshPromise;
};

AWS.util.addPromises(AWS.Credentials);


/***/ },

/***/ 4230
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var STS = __webpack_require__(2788);

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
 */
AWS.ChainableTemporaryCredentials = AWS.util.inherit(AWS.Credentials, {
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
   */
  constructor: function ChainableTemporaryCredentials(options) {
    AWS.Credentials.call(this);
    options = options || {};
    this.errorCode = 'ChainableTemporaryCredentialsProviderFailure';
    this.expired = true;
    this.tokenCodeFn = null;

    var params = AWS.util.copy(options.params) || {};
    if (params.RoleArn) {
      params.RoleSessionName = params.RoleSessionName || 'temporary-credentials';
    }
    if (params.SerialNumber) {
      if (!options.tokenCodeFn || (typeof options.tokenCodeFn !== 'function')) {
        throw new AWS.util.error(
          new Error('tokenCodeFn must be a function when params.SerialNumber is given'),
          {code: this.errorCode}
        );
      } else {
        this.tokenCodeFn = options.tokenCodeFn;
      }
    }
    var config = AWS.util.merge(
      {
        params: params,
        credentials: options.masterCredentials || AWS.config.credentials
      },
      options.stsConfig || {}
    );
    this.service = new STS(config);
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
   */
  refresh: function refresh(callback) {
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },

  /**
   * @api private
   * @param callback
   */
  load: function load(callback) {
    var self = this;
    var operation = self.service.config.params.RoleArn ? 'assumeRole' : 'getSessionToken';
    this.getTokenCode(function (err, tokenCode) {
      var params = {};
      if (err) {
        callback(err);
        return;
      }
      if (tokenCode) {
        params.TokenCode = tokenCode;
      }
      self.service[operation](params, function (err, data) {
        if (!err) {
          self.service.credentialsFrom(data, self);
        }
        callback(err);
      });
    });
  },

  /**
   * @api private
   */
  getTokenCode: function getTokenCode(callback) {
    var self = this;
    if (this.tokenCodeFn) {
      this.tokenCodeFn(this.service.config.params.SerialNumber, function (err, token) {
        if (err) {
          var message = err;
          if (err instanceof Error) {
            message = err.message;
          }
          callback(
            AWS.util.error(
              new Error('Error fetching MFA token: ' + message),
              { code: self.errorCode}
            )
          );
          return;
        }
        callback(null, token);
      });
    } else {
      callback(null);
    }
  }
});


/***/ },

/***/ 4855
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var CognitoIdentity = __webpack_require__(8825);
var STS = __webpack_require__(2788);

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
 */
AWS.CognitoIdentityCredentials = AWS.util.inherit(AWS.Credentials, {
  /**
   * @api private
   */
  localStorageKey: {
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
   */
  constructor: function CognitoIdentityCredentials(params, clientConfig) {
    AWS.Credentials.call(this);
    this.expired = true;
    this.params = params;
    this.data = null;
    this._identityId = null;
    this._clientConfig = AWS.util.copy(clientConfig || {});
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
   */
  refresh: function refresh(callback) {
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },

  /**
   * @api private
   * @param callback
   */
  load: function load(callback) {
    var self = this;
    self.createClients();
    self.data = null;
    self._identityId = null;
    self.getId(function(err) {
      if (!err) {
        if (!self.params.RoleArn) {
          self.getCredentialsForIdentity(callback);
        } else {
          self.getCredentialsFromSTS(callback);
        }
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
   */
  clearCachedId: function clearCache() {
    this._identityId = null;
    delete this.params.IdentityId;

    var poolId = this.params.IdentityPoolId;
    var loginId = this.params.LoginId || '';
    delete this.storage[this.localStorageKey.id + poolId + loginId];
    delete this.storage[this.localStorageKey.providers + poolId + loginId];
  },

  /**
   * @api private
   */
  clearIdOnNotAuthorized: function clearIdOnNotAuthorized(err) {
    var self = this;
    if (err.code == 'NotAuthorizedException') {
      self.clearCachedId();
    }
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
   */
  getId: function getId(callback) {
    var self = this;
    if (typeof self.params.IdentityId === 'string') {
      return callback(null, self.params.IdentityId);
    }

    self.cognito.getId(function(err, data) {
      if (!err && data.IdentityId) {
        self.params.IdentityId = data.IdentityId;
        callback(null, data.IdentityId);
      } else {
        callback(err);
      }
    });
  },


  /**
   * @api private
   */
  loadCredentials: function loadCredentials(data, credentials) {
    if (!data || !credentials) return;
    credentials.expired = false;
    credentials.accessKeyId = data.Credentials.AccessKeyId;
    credentials.secretAccessKey = data.Credentials.SecretKey;
    credentials.sessionToken = data.Credentials.SessionToken;
    credentials.expireTime = data.Credentials.Expiration;
  },

  /**
   * @api private
   */
  getCredentialsForIdentity: function getCredentialsForIdentity(callback) {
    var self = this;
    self.cognito.getCredentialsForIdentity(function(err, data) {
      if (!err) {
        self.cacheId(data);
        self.data = data;
        self.loadCredentials(self.data, self);
      } else {
        self.clearIdOnNotAuthorized(err);
      }
      callback(err);
    });
  },

  /**
   * @api private
   */
  getCredentialsFromSTS: function getCredentialsFromSTS(callback) {
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
   */
  loadCachedId: function loadCachedId() {
    var self = this;

    // in the browser we source default IdentityId from localStorage
    if (AWS.util.isBrowser() && !self.params.IdentityId) {
      var id = self.getStorage('id');
      if (id && self.params.Logins) {
        var actualProviders = Object.keys(self.params.Logins);
        var cachedProviders =
          (self.getStorage('providers') || '').split(',');

        // only load ID if at least one provider used this ID before
        var intersect = cachedProviders.filter(function(n) {
          return actualProviders.indexOf(n) !== -1;
        });
        if (intersect.length !== 0) {
          self.params.IdentityId = id;
        }
      } else if (id) {
        self.params.IdentityId = id;
      }
    }
  },

  /**
   * @api private
   */
  createClients: function() {
    var clientConfig = this._clientConfig;
    this.webIdentityCredentials = this.webIdentityCredentials ||
      new AWS.WebIdentityCredentials(this.params, clientConfig);
    if (!this.cognito) {
      var cognitoConfig = AWS.util.merge({}, clientConfig);
      cognitoConfig.params = this.params;
      this.cognito = new CognitoIdentity(cognitoConfig);
    }
    this.sts = this.sts || new STS(clientConfig);
  },

  /**
   * @api private
   */
  cacheId: function cacheId(data) {
    this._identityId = data.IdentityId;
    this.params.IdentityId = this._identityId;

    // cache this IdentityId in browser localStorage if possible
    if (AWS.util.isBrowser()) {
      this.setStorage('id', data.IdentityId);

      if (this.params.Logins) {
        this.setStorage('providers', Object.keys(this.params.Logins).join(','));
      }
    }
  },

  /**
   * @api private
   */
  getStorage: function getStorage(key) {
    return this.storage[this.localStorageKey[key] + this.params.IdentityPoolId + (this.params.LoginId || '')];
  },

  /**
   * @api private
   */
  setStorage: function setStorage(key, val) {
    try {
      this.storage[this.localStorageKey[key] + this.params.IdentityPoolId + (this.params.LoginId || '')] = val;
    } catch (_) {}
  },

  /**
   * @api private
   */
  storage: (function() {
    try {
      var storage = AWS.util.isBrowser() && window.localStorage !== null && typeof window.localStorage === 'object' ?
          window.localStorage : {};

      // Test set/remove which would throw an error in Safari's private browsing
      storage['aws.test-storage'] = 'foobar';
      delete storage['aws.test-storage'];

      return storage;
    } catch (_) {
      return {};
    }
  })()
});


/***/ },

/***/ 4279
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

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
 */
AWS.CredentialProviderChain = AWS.util.inherit(AWS.Credentials, {

  /**
   * Creates a new CredentialProviderChain with a default set of providers
   * specified by {defaultProviders}.
   */
  constructor: function CredentialProviderChain(providers) {
    if (providers) {
      this.providers = providers;
    } else {
      this.providers = AWS.CredentialProviderChain.defaultProviders.slice(0);
    }
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
   */

  /**
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
   */
  resolve: function resolve(callback) {
    var self = this;
    if (self.providers.length === 0) {
      callback(new Error('No providers'));
      return self;
    }

    if (self.resolveCallbacks.push(callback) === 1) {
      var index = 0;
      var providers = self.providers.slice(0);

      function resolveNext(err, creds) {
        if ((!err && creds) || index === providers.length) {
          AWS.util.arrayEach(self.resolveCallbacks, function (callback) {
            callback(err, creds);
          });
          self.resolveCallbacks.length = 0;
          return;
        }

        var provider = providers[index++];
        if (typeof provider === 'function') {
          creds = provider.call();
        } else {
          creds = provider;
        }

        if (creds.get) {
          creds.get(function (getErr) {
            resolveNext(getErr, getErr ? null : creds);
          });
        } else {
          resolveNext(null, creds);
        }
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
 */
AWS.CredentialProviderChain.defaultProviders = [];

/**
 * @api private
 */
AWS.CredentialProviderChain.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
  this.prototype.resolvePromise = AWS.util.promisifyMethod('resolve', PromiseDependency);
};

/**
 * @api private
 */
AWS.CredentialProviderChain.deletePromisesFromClass = function deletePromisesFromClass() {
  delete this.prototype.resolvePromise;
};

AWS.util.addPromises(AWS.CredentialProviderChain);


/***/ },

/***/ 4963
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
__webpack_require__(2366);

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
 */
AWS.EC2MetadataCredentials = AWS.util.inherit(AWS.Credentials, {
  constructor: function EC2MetadataCredentials(options) {
    AWS.Credentials.call(this);

    options = options ? AWS.util.copy(options) : {};
    options = AWS.util.merge(
      {maxRetries: this.defaultMaxRetries}, options);
    if (!options.httpOptions) options.httpOptions = {};
    options.httpOptions = AWS.util.merge(
      {timeout: this.defaultTimeout,
        connectTimeout: this.defaultConnectTimeout},
       options.httpOptions);

    this.metadataService = new AWS.MetadataService(options);
    this.logger = options.logger || AWS.config && AWS.config.logger;
  },

  /**
   * @api private
   */
  defaultTimeout: 1000,

   /**
   * @api private
   */
  defaultConnectTimeout: 1000,

  /**
   * @api private
   */
  defaultMaxRetries: 3,

  /**
   * The original expiration of the current credential. In case of AWS
   * outage, the EC2 metadata will extend expiration of the existing
   * credential.
   */
  originalExpiration: undefined,

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
   */
  refresh: function refresh(callback) {
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },

  /**
   * @api private
   * @param callback
   */
  load: function load(callback) {
    var self = this;
    self.metadataService.loadCredentials(function(err, creds) {
      if (err) {
        if (self.hasLoadedCredentials()) {
          self.extendExpirationIfExpired();
          callback();
        } else {
          callback(err);
        }
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
   */
  hasLoadedCredentials: function hasLoadedCredentials() {
    return this.AccessKeyId && this.secretAccessKey;
  },

  /**
   * if expired, extend the expiration by 15 minutes base plus a jitter of 5
   * minutes range.
   * @api private
   */
  extendExpirationIfExpired: function extendExpirationIfExpired() {
    if (this.needsRefresh()) {
      this.originalExpiration = this.originalExpiration || this.expireTime;
      this.expired = false;
      var nextTimeout = 15 * 60 + Math.floor(Math.random() * 5 * 60);
      var currentTime = AWS.util.date.getDate().getTime();
      this.expireTime = new Date(currentTime + nextTimeout * 1000);
      // TODO: add doc link;
      this.logger.warn('Attempting credential expiration extension due to a '
          + 'credential service availability issue. A refresh of these '
          + 'credentials will be attempted again at ' + this.expireTime
          + '\nFor more information, please visit: https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html');
    }
  },

  /**
   * Update the credential with new credential responded from EC2 metadata
   * service.
   * @api private
   */
  setCredentials: function setCredentials(creds) {
    var currentTime = AWS.util.date.getDate().getTime();
    var expireTime = new Date(creds.Expiration);
    this.expired = currentTime >= expireTime ? true : false;
    this.metadata = creds;
    this.accessKeyId = creds.AccessKeyId;
    this.secretAccessKey = creds.SecretAccessKey;
    this.sessionToken = creds.Token;
    this.expireTime = expireTime;
  }
});


/***/ },

/***/ 8794
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

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
 */
AWS.ECSCredentials = AWS.RemoteCredentials;


/***/ },

/***/ 9510
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

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
 */
AWS.EnvironmentCredentials = AWS.util.inherit(AWS.Credentials, {

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
   */
  constructor: function EnvironmentCredentials(envPrefix) {
    AWS.Credentials.call(this);
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
   */
  refresh: function refresh(callback) {
    if (!callback) callback = AWS.util.fn.callback;

    if (!process || !process.env) {
      callback(AWS.util.error(
        new Error('No process info or environment variables available'),
        { code: 'EnvironmentCredentialsProviderFailure' }
      ));
      return;
    }

    var keys = ['ACCESS_KEY_ID', 'SECRET_ACCESS_KEY', 'SESSION_TOKEN'];
    var values = [];

    for (var i = 0; i < keys.length; i++) {
      var prefix = '';
      if (this.envPrefix) prefix = this.envPrefix + '_';
      values[i] = process.env[prefix + keys[i]];
      if (!values[i] && keys[i] !== 'SESSION_TOKEN') {
        callback(AWS.util.error(
          new Error('Variable ' + prefix + keys[i] + ' not set.'),
        { code: 'EnvironmentCredentialsProviderFailure' }
        ));
        return;
      }
    }

    this.expired = false;
    AWS.Credentials.apply(this, values);
    callback();
  }

});


/***/ },

/***/ 81
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

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
 */
AWS.FileSystemCredentials = AWS.util.inherit(AWS.Credentials, {

  /**
   * @overload AWS.FileSystemCredentials(filename)
   *   Creates a new FileSystemCredentials object from a filename
   *
   *   @param filename [String] the path on disk to the JSON file to load.
   */
  constructor: function FileSystemCredentials(filename) {
    AWS.Credentials.call(this);
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
   */
  refresh: function refresh(callback) {
    if (!callback) callback = AWS.util.fn.callback;
    try {
      var creds = JSON.parse(AWS.util.readFileSync(this.filename));
      AWS.Credentials.call(this, creds);
      if (!this.accessKeyId || !this.secretAccessKey) {
        throw AWS.util.error(
          new Error('Credentials not set in ' + this.filename),
        { code: 'FileSystemCredentialsProviderFailure' }
        );
      }
      this.expired = false;
      callback();
    } catch (err) {
      callback(err);
    }
  }

});


/***/ },

/***/ 3466
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var proc = __webpack_require__(5317);
var iniLoader = AWS.util.iniLoader;

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
 */
AWS.ProcessCredentials = AWS.util.inherit(AWS.Credentials, {
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
   */
  constructor: function ProcessCredentials(options) {
    AWS.Credentials.call(this);

    options = options || {};

    this.filename = options.filename;
    this.profile = options.profile || process.env.AWS_PROFILE || AWS.util.defaultProfile;
    this.get(options.callback || AWS.util.fn.noop);
  },

  /**
   * @api private
   */
  load: function load(callback) {
    var self = this;
    try {
      var profiles = AWS.util.getProfilesFromSharedConfig(iniLoader, this.filename);
      var profile = profiles[this.profile] || {};

      if (Object.keys(profile).length === 0) {
        throw AWS.util.error(
          new Error('Profile ' + this.profile + ' not found'),
          { code: 'ProcessCredentialsProviderFailure' }
        );
      }

      if (profile['credential_process']) {
        this.loadViaCredentialProcess(profile, function(err, data) {
          if (err) {
            callback(err, null);
          } else {
            self.expired = false;
            self.accessKeyId = data.AccessKeyId;
            self.secretAccessKey = data.SecretAccessKey;
            self.sessionToken = data.SessionToken;
            if (data.Expiration) {
              self.expireTime = new Date(data.Expiration);
            }
            callback(null);
          }
        });
      } else {
        throw AWS.util.error(
          new Error('Profile ' + this.profile + ' did not include credential process'),
          { code: 'ProcessCredentialsProviderFailure' }
        );
      }
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
  */
  loadViaCredentialProcess: function loadViaCredentialProcess(profile, callback) {
    proc.exec(profile['credential_process'], { env: process.env }, function(err, stdOut, stdErr) {
      if (err) {
        callback(AWS.util.error(
          new Error('credential_process returned error'),
          { code: 'ProcessCredentialsProviderFailure'}
        ), null);
      } else {
        try {
          var credData = JSON.parse(stdOut);
          if (credData.Expiration) {
            var currentTime = AWS.util.date.getDate();
            var expireTime = new Date(credData.Expiration);
            if (expireTime < currentTime) {
              throw Error('credential_process returned expired credentials');
            }
          }

          if (credData.Version !== 1) {
            throw Error('credential_process does not return Version == 1');
          }
          callback(null, credData);
        } catch (err) {
          callback(AWS.util.error(
            new Error(err.message),
            { code: 'ProcessCredentialsProviderFailure'}
          ), null);
        }
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
   */
  refresh: function refresh(callback) {
    iniLoader.clearCachedFiles();
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  }
});


/***/ },

/***/ 3163
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var fs = __webpack_require__(9896);

var AWS = __webpack_require__(9132),
  ENV_RELATIVE_URI = 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
  ENV_FULL_URI = 'AWS_CONTAINER_CREDENTIALS_FULL_URI',
  ENV_AUTH_TOKEN = 'AWS_CONTAINER_AUTHORIZATION_TOKEN',
  ENV_AUTH_TOKEN_FILE = 'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE',
  FULL_URI_UNRESTRICTED_PROTOCOLS = ['https:'],
  FULL_URI_ALLOWED_PROTOCOLS = ['http:', 'https:'],
  FULL_URI_ALLOWED_HOSTNAMES = ['localhost', '127.0.0.1', '169.254.170.23'],
  RELATIVE_URI_HOST = '169.254.170.2';

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
 */
AWS.RemoteCredentials = AWS.util.inherit(AWS.Credentials, {
  constructor: function RemoteCredentials(options) {
    AWS.Credentials.call(this);
    options = options ? AWS.util.copy(options) : {};
    if (!options.httpOptions) options.httpOptions = {};
    options.httpOptions = AWS.util.merge(
      this.httpOptions, options.httpOptions);
    AWS.util.update(this, options);
  },

  /**
   * @api private
   */
  httpOptions: { timeout: 1000 },

  /**
   * @api private
   */
  maxRetries: 3,

  /**
   * @api private
   */
  isConfiguredForEcsCredentials: function isConfiguredForEcsCredentials() {
    return Boolean(
        process &&
        process.env &&
        (process.env[ENV_RELATIVE_URI] || process.env[ENV_FULL_URI])
    );
  },

  /**
   * @api private
   */
  getECSFullUri: function getECSFullUri() {
    if (process && process.env) {
      var relative = process.env[ENV_RELATIVE_URI],
          full = process.env[ENV_FULL_URI];
      if (relative) {
        return 'http://' + RELATIVE_URI_HOST + relative;
      } else if (full) {
        var parsed = AWS.util.urlParse(full);
        if (FULL_URI_ALLOWED_PROTOCOLS.indexOf(parsed.protocol) < 0) {
          throw AWS.util.error(
            new Error('Unsupported protocol:  AWS.RemoteCredentials supports '
              + FULL_URI_ALLOWED_PROTOCOLS.join(',') + ' only; '
              + parsed.protocol + ' requested.'),
            { code: 'ECSCredentialsProviderFailure' }
          );
        }

        if (FULL_URI_UNRESTRICTED_PROTOCOLS.indexOf(parsed.protocol) < 0 &&
            FULL_URI_ALLOWED_HOSTNAMES.indexOf(parsed.hostname) < 0) {
          throw AWS.util.error(
            new Error('Unsupported hostname: AWS.RemoteCredentials only supports '
              + FULL_URI_ALLOWED_HOSTNAMES.join(',') + ' for ' + parsed.protocol + '; '
              + parsed.protocol + '//' + parsed.hostname + ' requested.'),
            { code: 'ECSCredentialsProviderFailure' }
          );
        }

        return full;
      } else {
        throw AWS.util.error(
          new Error('Variable ' + ENV_RELATIVE_URI + ' or ' + ENV_FULL_URI +
            ' must be set to use AWS.RemoteCredentials.'),
          { code: 'ECSCredentialsProviderFailure' }
        );
      }
    } else {
      throw AWS.util.error(
        new Error('No process info available'),
        { code: 'ECSCredentialsProviderFailure' }
      );
    }
  },

  /**
   * @api private
   */
  getECSAuthToken: function getECSAuthToken() {
    if (process && process.env && (process.env[ENV_FULL_URI] || process.env[ENV_AUTH_TOKEN_FILE])) {
      if (!process.env[ENV_AUTH_TOKEN] && process.env[ENV_AUTH_TOKEN_FILE]) {
        try {
          var data = fs.readFileSync(process.env[ENV_AUTH_TOKEN_FILE]).toString();
          return data;
        } catch (error) {
          console.error('Error reading token file:', error);
          throw error; // Re-throw the error to propagate it
        }
      }
      return process.env[ENV_AUTH_TOKEN];
    }
  },

  /**
   * @api private
   */
  credsFormatIsValid: function credsFormatIsValid(credData) {
    return (!!credData.accessKeyId && !!credData.secretAccessKey &&
      !!credData.sessionToken && !!credData.expireTime);
  },

  /**
   * @api private
   */
  formatCreds: function formatCreds(credData) {
    if (!!credData.credentials) {
      credData = credData.credentials;
    }

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
   */
  request: function request(url, callback) {
    var httpRequest = new AWS.HttpRequest(url);
    httpRequest.method = 'GET';
    httpRequest.headers.Accept = 'application/json';
    var token = this.getECSAuthToken();
    if (token) {
      httpRequest.headers.Authorization = token;
    }
    AWS.util.handleRequestWithRetries(httpRequest, this, callback);
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
   */
  refresh: function refresh(callback) {
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },

  /**
   * @api private
   */
  load: function load(callback) {
    var self = this;
    var fullUri;

    try {
      fullUri = this.getECSFullUri();
    } catch (err) {
      callback(err);
      return;
    }

    this.request(fullUri, function(err, data) {
      if (!err) {
        try {
          data = JSON.parse(data);
          var creds = self.formatCreds(data);
          if (!self.credsFormatIsValid(creds)) {
            throw AWS.util.error(
              new Error('Response data is not in valid format'),
              { code: 'ECSCredentialsProviderFailure' }
            );
          }
          AWS.util.update(self, creds);
        } catch (dataError) {
          err = dataError;
        }
      }
      callback(err, creds);
    });
  }
});


/***/ },

/***/ 8236
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var STS = __webpack_require__(2788);

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
 */
AWS.SAMLCredentials = AWS.util.inherit(AWS.Credentials, {
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
   */
  constructor: function SAMLCredentials(params) {
    AWS.Credentials.call(this);
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
   */
  refresh: function refresh(callback) {
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },

  /**
   * @api private
   */
  load: function load(callback) {
    var self = this;
    self.createClients();
    self.service.assumeRoleWithSAML(function (err, data) {
      if (!err) {
        self.service.credentialsFrom(data, self);
      }
      callback(err);
    });
  },

  /**
   * @api private
   */
  createClients: function() {
    this.service = this.service || new STS({params: this.params});
  }

});


/***/ },

/***/ 9248
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var STS = __webpack_require__(2788);
var iniLoader = AWS.util.iniLoader;

var ASSUME_ROLE_DEFAULT_REGION = 'us-east-1';

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
 */
AWS.SharedIniFileCredentials = AWS.util.inherit(AWS.Credentials, {
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
   */
  constructor: function SharedIniFileCredentials(options) {
    AWS.Credentials.call(this);

    options = options || {};

    this.filename = options.filename;
    this.profile = options.profile || process.env.AWS_PROFILE || AWS.util.defaultProfile;
    this.disableAssumeRole = Boolean(options.disableAssumeRole);
    this.preferStaticCredentials = Boolean(options.preferStaticCredentials);
    this.tokenCodeFn = options.tokenCodeFn || null;
    this.httpOptions = options.httpOptions || null;
    this.get(options.callback || AWS.util.fn.noop);
  },

  /**
   * @api private
   */
  load: function load(callback) {
    var self = this;
    try {
      var profiles = AWS.util.getProfilesFromSharedConfig(iniLoader, this.filename);
      var profile = profiles[this.profile] || {};

      if (Object.keys(profile).length === 0) {
        throw AWS.util.error(
          new Error('Profile ' + this.profile + ' not found'),
          { code: 'SharedIniFileCredentialsProviderFailure' }
        );
      }

      /*
      In the CLI, the presence of both a role_arn and static credentials have
      different meanings depending on how many profiles have been visited. For
      the first profile processed, role_arn takes precedence over any static
      credentials, but for all subsequent profiles, static credentials are
      used if present, and only in their absence will the profile's
      source_profile and role_arn keys be used to load another set of
      credentials. This var is intended to yield compatible behaviour in this
      sdk.
      */
      var preferStaticCredentialsToRoleArn = Boolean(
        this.preferStaticCredentials
        && profile['aws_access_key_id']
        && profile['aws_secret_access_key']
      );

      if (profile['role_arn'] && !preferStaticCredentialsToRoleArn) {
        this.loadRoleProfile(profiles, profile, function(err, data) {
          if (err) {
            callback(err);
          } else {
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

      if (!this.accessKeyId || !this.secretAccessKey) {
        throw AWS.util.error(
          new Error('Credentials not set for profile ' + this.profile),
          { code: 'SharedIniFileCredentialsProviderFailure' }
        );
      }
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
   */
  refresh: function refresh(callback) {
    iniLoader.clearCachedFiles();
    this.coalesceRefresh(
      callback || AWS.util.fn.callback,
      this.disableAssumeRole
    );
  },

  /**
   * @api private
   */
  loadRoleProfile: function loadRoleProfile(creds, roleProfile, callback) {
    if (this.disableAssumeRole) {
      throw AWS.util.error(
        new Error('Role assumption profiles are disabled. ' +
                  'Failed to load profile ' + this.profile +
                  ' from ' + creds.filename),
        { code: 'SharedIniFileCredentialsProviderFailure' }
      );
    }

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
    var profileRegion = roleProfile['region'] || ASSUME_ROLE_DEFAULT_REGION;

    if (!sourceProfileName) {
      throw AWS.util.error(
        new Error('source_profile is not set using profile ' + this.profile),
        { code: 'SharedIniFileCredentialsProviderFailure' }
      );
    }

    var sourceProfileExistanceTest = creds[sourceProfileName];

    if (typeof sourceProfileExistanceTest !== 'object') {
      throw AWS.util.error(
        new Error('source_profile ' + sourceProfileName + ' using profile '
          + this.profile + ' does not exist'),
        { code: 'SharedIniFileCredentialsProviderFailure' }
      );
    }

    var sourceCredentials = new AWS.SharedIniFileCredentials(
      AWS.util.merge(this.options || {}, {
        profile: sourceProfileName,
        preferStaticCredentials: true
      })
    );

    this.roleArn = roleArn;
    var sts = new STS({
      credentials: sourceCredentials,
      region: profileRegion,
      httpOptions: this.httpOptions
    });

    var roleParams = {
      DurationSeconds: durationSeconds,
      RoleArn: roleArn,
      RoleSessionName: roleSessionName || 'aws-sdk-js-' + Date.now()
    };

    if (externalId) {
      roleParams.ExternalId = externalId;
    }

    if (mfaSerial && self.tokenCodeFn) {
      roleParams.SerialNumber = mfaSerial;
      self.tokenCodeFn(mfaSerial, function(err, token) {
        if (err) {
          var message;
          if (err instanceof Error) {
            message = err.message;
          } else {
            message = err;
          }
          callback(
            AWS.util.error(
              new Error('Error fetching MFA token: ' + message),
              { code: 'SharedIniFileCredentialsProviderFailure' }
            ));
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


/***/ },

/***/ 7964
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var path = __webpack_require__(6928);
var crypto = __webpack_require__(6982);
var iniLoader = AWS.util.iniLoader;

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
 */
AWS.SsoCredentials = AWS.util.inherit(AWS.Credentials, {
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
   */
  constructor: function SsoCredentials(options) {
    AWS.Credentials.call(this);

    options = options || {};
    this.errorCode = 'SsoCredentialsProviderFailure';
    this.expired = true;

    this.filename = options.filename;
    this.profile = options.profile || process.env.AWS_PROFILE || AWS.util.defaultProfile;
    this.service = options.ssoClient;
    this.httpOptions = options.httpOptions || null;
    this.get(options.callback || AWS.util.fn.noop);
  },

  /**
   * @api private
   */
  load: function load(callback) {
    var self = this;

    try {
      var profiles = AWS.util.getProfilesFromSharedConfig(iniLoader, this.filename);
      var profile = profiles[this.profile] || {};

      if (Object.keys(profile).length === 0) {
        throw AWS.util.error(
          new Error('Profile ' + this.profile + ' not found'),
          { code: self.errorCode }
        );
      }

      if (profile.sso_session) {
        if (!profile.sso_account_id || !profile.sso_role_name) {
          throw AWS.util.error(
            new Error('Profile ' + this.profile + ' with session ' + profile.sso_session +
              ' does not have valid SSO credentials. Required parameters "sso_account_id", "sso_session", ' +
              '"sso_role_name". Reference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html'),
            { code: self.errorCode }
          );
        }
      } else {
        if (!profile.sso_start_url || !profile.sso_account_id || !profile.sso_region || !profile.sso_role_name) {
          throw AWS.util.error(
            new Error('Profile ' + this.profile + ' does not have valid SSO credentials. Required parameters "sso_account_id", "sso_region", ' +
            '"sso_role_name", "sso_start_url". Reference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html'),
            { code: self.errorCode }
          );
        }
      }

      this.getToken(this.profile, profile, function (err, token) {
        if (err) {
          return callback(err);
        }
        var request = {
          accessToken: token,
          accountId: profile.sso_account_id,
          roleName: profile.sso_role_name,
        };

        if (!self.service || self.service.config.region !== profile.sso_region) {
          self.service = new AWS.SSO({
            region: profile.sso_region,
            httpOptions: self.httpOptions,
          });
        }

        self.service.getRoleCredentials(request, function(err, data) {
          if (err || !data || !data.roleCredentials) {
            callback(AWS.util.error(
              err || new Error('Please log in using "aws sso login"'),
              { code: self.errorCode }
            ), null);
          } else if (!data.roleCredentials.accessKeyId || !data.roleCredentials.secretAccessKey || !data.roleCredentials.sessionToken || !data.roleCredentials.expiration) {
            throw AWS.util.error(new Error(
              'SSO returns an invalid temporary credential.'
            ));
          } else {
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
   */
  getToken: function getToken(profileName, profile, callback) {
    var self = this;

    if (profile.sso_session) {
      var _iniLoader = AWS.util.iniLoader;
      var ssoSessions = _iniLoader.loadSsoSessionsFrom();
      var ssoSession = ssoSessions[profile.sso_session];
      Object.assign(profile, ssoSession);

      var ssoTokenProvider = new AWS.SSOTokenProvider({
        profile: profileName,
      });
      ssoTokenProvider.get(function (err) {
        if (err) {
          return callback(err);
        }
        return callback(null, ssoTokenProvider.token);
      });
      return;
    }

    try {
      /**
       * The time window (15 mins) that SDK will treat the SSO token expires in before the defined expiration date in token.
       * This is needed because server side may have invalidated the token before the defined expiration date.
       */
      var EXPIRE_WINDOW_MS = 15 * 60 * 1000;
      var hasher = crypto.createHash('sha1');
      var fileName = hasher.update(profile.sso_start_url).digest('hex') + '.json';
      var cachePath = path.join(
        iniLoader.getHomeDir(),
        '.aws',
        'sso',
        'cache',
        fileName
      );
      var cacheFile = AWS.util.readFileSync(cachePath);
      var cacheContent = null;
      if (cacheFile) {
        cacheContent = JSON.parse(cacheFile);
      }
      if (!cacheContent) {
        throw AWS.util.error(
          new Error('Cached credentials not found under ' + this.profile + ' profile. Please make sure you log in with aws sso login first'),
          { code: self.errorCode }
        );
      }

      if (!cacheContent.startUrl || !cacheContent.region || !cacheContent.accessToken || !cacheContent.expiresAt) {
        throw AWS.util.error(
          new Error('Cached credentials are missing required properties. Try running aws sso login.')
        );
      }

      if (new Date(cacheContent.expiresAt).getTime() - Date.now() <= EXPIRE_WINDOW_MS) {
        throw AWS.util.error(new Error(
          'The SSO session associated with this profile has expired. To refresh this SSO session run aws sso login with the corresponding profile.'
        ));
      }

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
   */
  refresh: function refresh(callback) {
    iniLoader.clearCachedFiles();
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },
});


/***/ },

/***/ 9756
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var STS = __webpack_require__(2788);

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
 */
AWS.TemporaryCredentials = AWS.util.inherit(AWS.Credentials, {
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
   */
  constructor: function TemporaryCredentials(params, masterCredentials) {
    AWS.Credentials.call(this);
    this.loadMasterCredentials(masterCredentials);
    this.expired = true;

    this.params = params || {};
    if (this.params.RoleArn) {
      this.params.RoleSessionName =
        this.params.RoleSessionName || 'temporary-credentials';
    }
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
   */
  refresh: function refresh (callback) {
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },

  /**
   * @api private
   */
  load: function load (callback) {
    var self = this;
    self.createClients();
    self.masterCredentials.get(function () {
      self.service.config.credentials = self.masterCredentials;
      var operation = self.params.RoleArn ?
        self.service.assumeRole : self.service.getSessionToken;
      operation.call(self.service, function (err, data) {
        if (!err) {
          self.service.credentialsFrom(data, self);
        }
        callback(err);
      });
    });
  },

  /**
   * @api private
   */
  loadMasterCredentials: function loadMasterCredentials (masterCredentials) {
    this.masterCredentials = masterCredentials || AWS.config.credentials;
    while (this.masterCredentials.masterCredentials) {
      this.masterCredentials = this.masterCredentials.masterCredentials;
    }

    if (typeof this.masterCredentials.get !== 'function') {
      this.masterCredentials = new AWS.Credentials(this.masterCredentials);
    }
  },

  /**
   * @api private
   */
  createClients: function () {
    this.service = this.service || new STS({params: this.params});
  }

});


/***/ },

/***/ 4939
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var fs = __webpack_require__(9896);
var STS = __webpack_require__(2788);
var iniLoader = AWS.util.iniLoader;

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
 */
AWS.TokenFileWebIdentityCredentials = AWS.util.inherit(AWS.Credentials, {

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
   */
  constructor: function TokenFileWebIdentityCredentials(clientConfig) {
    AWS.Credentials.call(this);
    this.data = null;
    this.clientConfig = AWS.util.copy(clientConfig || {});
  },

  /**
   * Returns params from environment variables
   *
   * @api private
   */
  getParamsFromEnv: function getParamsFromEnv() {
    var ENV_TOKEN_FILE = 'AWS_WEB_IDENTITY_TOKEN_FILE',
        ENV_ROLE_ARN = 'AWS_ROLE_ARN';
    if (process.env[ENV_TOKEN_FILE] && process.env[ENV_ROLE_ARN]) {
      return [{
        envTokenFile: process.env[ENV_TOKEN_FILE],
        roleArn: process.env[ENV_ROLE_ARN],
        roleSessionName: process.env['AWS_ROLE_SESSION_NAME']
      }];
    }
  },

  /**
   * Returns params from shared config variables
   *
   * @api private
   */
  getParamsFromSharedConfig: function getParamsFromSharedConfig() {
    var profiles = AWS.util.getProfilesFromSharedConfig(iniLoader);
    var profileName = process.env.AWS_PROFILE || AWS.util.defaultProfile;
    var profile = profiles[profileName] || {};

    if (Object.keys(profile).length === 0) {
      throw AWS.util.error(
        new Error('Profile ' + profileName + ' not found'),
        { code: 'TokenFileWebIdentityCredentialsProviderFailure' }
      );
    }

    var paramsArray = [];

    while (!profile['web_identity_token_file'] && profile['source_profile']) {
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
   */
  refresh: function refresh(callback) {
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },

  /**
   * @api private
  */
  assumeRoleChaining: function assumeRoleChaining(paramsArray, callback) {
    var self = this;
    if (paramsArray.length === 0) {
      self.service.credentialsFrom(self.data, self);
      callback();
    } else {
      var params = paramsArray.shift();
      self.service.config.credentials = self.service.credentialsFrom(self.data, self);
      self.service.assumeRole(
        {
          RoleArn: params.roleArn,
          RoleSessionName: params.roleSessionName || 'token-file-web-identity'
        },
        function (err, data) {
          self.data = null;
          if (err) {
            callback(err);
          } else {
            self.data = data;
            self.assumeRoleChaining(paramsArray, callback);
          }
        }
      );
    }
  },

  /**
   * @api private
   */
  load: function load(callback) {
    var self = this;
    try {
      var paramsArray = self.getParamsFromEnv();
      if (!paramsArray) {
        paramsArray = self.getParamsFromSharedConfig();
      }
      if (paramsArray) {
        var params = paramsArray.shift();
        var oidcToken = fs.readFileSync(params.envTokenFile, {encoding: 'ascii'});
        if (!self.service) {
          self.createClients();
        }
        self.service.assumeRoleWithWebIdentity(
          {
            WebIdentityToken: oidcToken,
            RoleArn: params.roleArn,
            RoleSessionName: params.roleSessionName || 'token-file-web-identity'
          },
          function (err, data) {
            self.data = null;
            if (err) {
              callback(err);
            } else {
              self.data = data;
              self.assumeRoleChaining(paramsArray, callback);
            }
          }
        );
      }
    } catch (err) {
      callback(err);
    }
  },

  /**
   * @api private
   */
  createClients: function() {
    if (!this.service) {
      var stsConfig = AWS.util.merge({}, this.clientConfig);
      this.service = new STS(stsConfig);

      // Retry in case of IDPCommunicationErrorException or InvalidIdentityToken
      this.service.retryableError = function(error) {
        if (error.code === 'IDPCommunicationErrorException' || error.code === 'InvalidIdentityToken') {
          return true;
        } else {
          return AWS.Service.prototype.retryableError.call(this, error);
        }
      };
    }
  }
});


/***/ },

/***/ 3184
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var STS = __webpack_require__(2788);

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
 */
AWS.WebIdentityCredentials = AWS.util.inherit(AWS.Credentials, {
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
   */
  constructor: function WebIdentityCredentials(params, clientConfig) {
    AWS.Credentials.call(this);
    this.expired = true;
    this.params = params;
    this.params.RoleSessionName = this.params.RoleSessionName || 'web-identity';
    this.data = null;
    this._clientConfig = AWS.util.copy(clientConfig || {});
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
   */
  refresh: function refresh(callback) {
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },

  /**
   * @api private
   */
  load: function load(callback) {
    var self = this;
    self.createClients();
    self.service.assumeRoleWithWebIdentity(function (err, data) {
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
   */
  createClients: function() {
    if (!this.service) {
      var stsConfig = AWS.util.merge({}, this._clientConfig);
      stsConfig.params = this.params;
      this.service = new STS(stsConfig);
    }
  }

});


/***/ },

/***/ 1130
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var util = __webpack_require__(9019);
var endpointDiscoveryEnabledEnvs = ['AWS_ENABLE_ENDPOINT_DISCOVERY', 'AWS_ENDPOINT_DISCOVERY_ENABLED'];

/**
 * Generate key (except resources and operation part) to index the endpoints in the cache
 * If input shape has endpointdiscoveryid trait then use
 *   accessKey + operation + resources + region + service as cache key
 * If input shape doesn't have endpointdiscoveryid trait then use
 *   accessKey + region + service as cache key
 * @return [map<String,String>] object with keys to index endpoints.
 * @api private
 */
function getCacheKey(request) {
  var service = request.service;
  var api = service.api || {};
  var operations = api.operations;
  var identifiers = {};
  if (service.config.region) {
    identifiers.region = service.config.region;
  }
  if (api.serviceId) {
    identifiers.serviceId = api.serviceId;
  }
  if (service.config.credentials.accessKeyId) {
    identifiers.accessKeyId = service.config.credentials.accessKeyId;
  }
  return identifiers;
}

/**
 * Recursive helper for marshallCustomIdentifiers().
 * Looks for required string input members that have 'endpointdiscoveryid' trait.
 * @api private
 */
function marshallCustomIdentifiersHelper(result, params, shape) {
  if (!shape || params === undefined || params === null) return;
  if (shape.type === 'structure' && shape.required && shape.required.length > 0) {
    util.arrayEach(shape.required, function(name) {
      var memberShape = shape.members[name];
      if (memberShape.endpointDiscoveryId === true) {
        var locationName = memberShape.isLocationName ? memberShape.name : name;
        result[locationName] = String(params[name]);
      } else {
        marshallCustomIdentifiersHelper(result, params[name], memberShape);
      }
    });
  }
}

/**
 * Get custom identifiers for cache key.
 * Identifies custom identifiers by checking each shape's `endpointDiscoveryId` trait.
 * @param [object] request object
 * @param [object] input shape of the given operation's api
 * @api private
 */
function marshallCustomIdentifiers(request, shape) {
  var identifiers = {};
  marshallCustomIdentifiersHelper(identifiers, request.params, shape);
  return identifiers;
}

/**
 * Call endpoint discovery operation when it's optional.
 * When endpoint is available in cache then use the cached endpoints. If endpoints
 * are unavailable then use regional endpoints and call endpoint discovery operation
 * asynchronously. This is turned off by default.
 * @param [object] request object
 * @api private
 */
function optionalDiscoverEndpoint(request) {
  var service = request.service;
  var api = service.api;
  var operationModel = api.operations ? api.operations[request.operation] : undefined;
  var inputShape = operationModel ? operationModel.input : undefined;

  var identifiers = marshallCustomIdentifiers(request, inputShape);
  var cacheKey = getCacheKey(request);
  if (Object.keys(identifiers).length > 0) {
    cacheKey = util.update(cacheKey, identifiers);
    if (operationModel) cacheKey.operation = operationModel.name;
  }
  var endpoints = AWS.endpointCache.get(cacheKey);
  if (endpoints && endpoints.length === 1 && endpoints[0].Address === '') {
    //endpoint operation is being made but response not yet received
    //or endpoint operation just failed in 1 minute
    return;
  } else if (endpoints && endpoints.length > 0) {
    //found endpoint record from cache
    request.httpRequest.updateEndpoint(endpoints[0].Address);
  } else {
    //endpoint record not in cache or outdated. make discovery operation
    var endpointRequest = service.makeRequest(api.endpointOperation, {
      Operation: operationModel.name,
      Identifiers: identifiers,
    });
    addApiVersionHeader(endpointRequest);
    endpointRequest.removeListener('validate', AWS.EventListeners.Core.VALIDATE_PARAMETERS);
    endpointRequest.removeListener('retry', AWS.EventListeners.Core.RETRY_CHECK);
    //put in a placeholder for endpoints already requested, prevent
    //too much in-flight calls
    AWS.endpointCache.put(cacheKey, [{
      Address: '',
      CachePeriodInMinutes: 1
    }]);
    endpointRequest.send(function(err, data) {
      if (data && data.Endpoints) {
        AWS.endpointCache.put(cacheKey, data.Endpoints);
      } else if (err) {
        AWS.endpointCache.put(cacheKey, [{
          Address: '',
          CachePeriodInMinutes: 1 //not to make more endpoint operation in next 1 minute
        }]);
      }
    });
  }
}

var requestQueue = {};

/**
 * Call endpoint discovery operation when it's required.
 * When endpoint is available in cache then use cached ones. If endpoints are
 * unavailable then SDK should call endpoint operation then use returned new
 * endpoint for the api call. SDK will automatically attempt to do endpoint
 * discovery. This is turned off by default
 * @param [object] request object
 * @api private
 */
function requiredDiscoverEndpoint(request, done) {
  var service = request.service;
  var api = service.api;
  var operationModel = api.operations ? api.operations[request.operation] : undefined;
  var inputShape = operationModel ? operationModel.input : undefined;

  var identifiers = marshallCustomIdentifiers(request, inputShape);
  var cacheKey = getCacheKey(request);
  if (Object.keys(identifiers).length > 0) {
    cacheKey = util.update(cacheKey, identifiers);
    if (operationModel) cacheKey.operation = operationModel.name;
  }
  var cacheKeyStr = AWS.EndpointCache.getKeyString(cacheKey);
  var endpoints = AWS.endpointCache.get(cacheKeyStr); //endpoint cache also accepts string keys
  if (endpoints && endpoints.length === 1 && endpoints[0].Address === '') {
    //endpoint operation is being made but response not yet received
    //push request object to a pending queue
    if (!requestQueue[cacheKeyStr]) requestQueue[cacheKeyStr] = [];
    requestQueue[cacheKeyStr].push({request: request, callback: done});
    return;
  } else if (endpoints && endpoints.length > 0) {
    request.httpRequest.updateEndpoint(endpoints[0].Address);
    done();
  } else {
    var endpointRequest = service.makeRequest(api.endpointOperation, {
      Operation: operationModel.name,
      Identifiers: identifiers,
    });
    endpointRequest.removeListener('validate', AWS.EventListeners.Core.VALIDATE_PARAMETERS);
    addApiVersionHeader(endpointRequest);

    //put in a placeholder for endpoints already requested, prevent
    //too much in-flight calls
    AWS.endpointCache.put(cacheKeyStr, [{
      Address: '',
      CachePeriodInMinutes: 60 //long-live cache
    }]);
    endpointRequest.send(function(err, data) {
      if (err) {
        request.response.error = util.error(err, { retryable: false });
        AWS.endpointCache.remove(cacheKey);

        //fail all the pending requests in batch
        if (requestQueue[cacheKeyStr]) {
          var pendingRequests = requestQueue[cacheKeyStr];
          util.arrayEach(pendingRequests, function(requestContext) {
            requestContext.request.response.error = util.error(err, { retryable: false });
            requestContext.callback();
          });
          delete requestQueue[cacheKeyStr];
        }
      } else if (data) {
        AWS.endpointCache.put(cacheKeyStr, data.Endpoints);
        request.httpRequest.updateEndpoint(data.Endpoints[0].Address);

        //update the endpoint for all the pending requests in batch
        if (requestQueue[cacheKeyStr]) {
          var pendingRequests = requestQueue[cacheKeyStr];
          util.arrayEach(pendingRequests, function(requestContext) {
            requestContext.request.httpRequest.updateEndpoint(data.Endpoints[0].Address);
            requestContext.callback();
          });
          delete requestQueue[cacheKeyStr];
        }
      }
      done();
    });
  }
}

/**
 * add api version header to endpoint operation
 * @api private
 */
function addApiVersionHeader(endpointRequest) {
  var api = endpointRequest.service.api;
  var apiVersion = api.apiVersion;
  if (apiVersion && !endpointRequest.httpRequest.headers['x-amz-api-version']) {
    endpointRequest.httpRequest.headers['x-amz-api-version'] = apiVersion;
  }
}

/**
 * If api call gets invalid endpoint exception, SDK should attempt to remove the invalid
 * endpoint from cache.
 * @api private
 */
function invalidateCachedEndpoints(response) {
  var error = response.error;
  var httpResponse = response.httpResponse;
  if (error &&
    (error.code === 'InvalidEndpointException' || httpResponse.statusCode === 421)
  ) {
    var request = response.request;
    var operations = request.service.api.operations || {};
    var inputShape = operations[request.operation] ? operations[request.operation].input : undefined;
    var identifiers = marshallCustomIdentifiers(request, inputShape);
    var cacheKey = getCacheKey(request);
    if (Object.keys(identifiers).length > 0) {
      cacheKey = util.update(cacheKey, identifiers);
      if (operations[request.operation]) cacheKey.operation = operations[request.operation].name;
    }
    AWS.endpointCache.remove(cacheKey);
  }
}

/**
 * If endpoint is explicitly configured, SDK should not do endpoint discovery in anytime.
 * @param [object] client Service client object.
 * @api private
 */
function hasCustomEndpoint(client) {
  //if set endpoint is set for specific client, enable endpoint discovery will raise an error.
  if (client._originalConfig && client._originalConfig.endpoint && client._originalConfig.endpointDiscoveryEnabled === true) {
    throw util.error(new Error(), {
      code: 'ConfigurationException',
      message: 'Custom endpoint is supplied; endpointDiscoveryEnabled must not be true.'
    });
  };
  var svcConfig = AWS.config[client.serviceIdentifier] || {};
  return Boolean(AWS.config.endpoint || svcConfig.endpoint || (client._originalConfig && client._originalConfig.endpoint));
}

/**
 * @api private
 */
function isFalsy(value) {
  return ['false', '0'].indexOf(value) >= 0;
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
 */
function resolveEndpointDiscoveryConfig(request) {
  var service = request.service || {};
  if (service.config.endpointDiscoveryEnabled !== undefined) {
    return service.config.endpointDiscoveryEnabled;
  }

  //shared ini file is only available in Node
  //not to check env in browser
  if (util.isBrowser()) return undefined;

  // If any of recognized endpoint discovery config env is set
  for (var i = 0; i < endpointDiscoveryEnabledEnvs.length; i++) {
    var env = endpointDiscoveryEnabledEnvs[i];
    if (Object.prototype.hasOwnProperty.call(process.env, env)) {
      if (process.env[env] === '' || process.env[env] === undefined) {
        throw util.error(new Error(), {
          code: 'ConfigurationException',
          message: 'environmental variable ' + env + ' cannot be set to nothing'
        });
      }
      return !isFalsy(process.env[env]);
    }
  }

  var configFile = {};
  try {
    configFile = AWS.util.iniLoader ? AWS.util.iniLoader.loadFrom({
      isConfig: true,
      filename: process.env[AWS.util.sharedConfigFileEnv]
    }) : {};
  } catch (e) {}
  var sharedFileConfig = configFile[
    process.env.AWS_PROFILE || AWS.util.defaultProfile
  ] || {};
  if (Object.prototype.hasOwnProperty.call(sharedFileConfig, 'endpoint_discovery_enabled')) {
    if (sharedFileConfig.endpoint_discovery_enabled === undefined) {
      throw util.error(new Error(), {
        code: 'ConfigurationException',
        message: 'config file entry \'endpoint_discovery_enabled\' cannot be set to nothing'
      });
    }
    return !isFalsy(sharedFileConfig.endpoint_discovery_enabled);
  }
  return undefined;
}

/**
 * attach endpoint discovery logic to request object
 * @param [object] request
 * @api private
 */
function discoverEndpoint(request, done) {
  var service = request.service || {};
  if (hasCustomEndpoint(service) || request.isPresigned()) return done();

  var operations = service.api.operations || {};
  var operationModel = operations[request.operation];
  var isEndpointDiscoveryRequired = operationModel ? operationModel.endpointDiscoveryRequired : 'NULL';
  var isEnabled = resolveEndpointDiscoveryConfig(request);
  var hasRequiredEndpointDiscovery = service.api.hasRequiredEndpointDiscovery;
  if (isEnabled || hasRequiredEndpointDiscovery) {
    // Once a customer enables endpoint discovery, the SDK should start appending
    // the string endpoint-discovery to the user-agent on all requests.
    request.httpRequest.appendToUserAgent('endpoint-discovery');
  }
  switch (isEndpointDiscoveryRequired) {
    case 'OPTIONAL':
      if (isEnabled || hasRequiredEndpointDiscovery) {
        // For a given service; if at least one operation requires endpoint discovery then the SDK must enable endpoint discovery
        // by default for all operations of that service, including operations where endpoint discovery is optional.
        optionalDiscoverEndpoint(request);
        request.addNamedListener('INVALIDATE_CACHED_ENDPOINTS', 'extractError', invalidateCachedEndpoints);
      }
      done();
      break;
    case 'REQUIRED':
      if (isEnabled === false) {
        // For a given operation; if endpoint discovery is required and it has been disabled on the SDK client,
        // then the SDK must return a clear and actionable exception.
        request.response.error = util.error(new Error(), {
          code: 'ConfigurationException',
          message: 'Endpoint Discovery is disabled but ' + service.api.className + '.' + request.operation +
                    '() requires it. Please check your configurations.'
        });
        done();
        break;
      }
      request.addNamedListener('INVALIDATE_CACHED_ENDPOINTS', 'extractError', invalidateCachedEndpoints);
      requiredDiscoverEndpoint(request, done);
      break;
    case 'NULL':
    default:
      done();
      break;
  }
}

module.exports = {
  discoverEndpoint: discoverEndpoint,
  requiredDiscoverEndpoint: requiredDiscoverEndpoint,
  optionalDiscoverEndpoint: optionalDiscoverEndpoint,
  marshallCustomIdentifiers: marshallCustomIdentifiers,
  getCacheKey: getCacheKey,
  invalidateCachedEndpoint: invalidateCachedEndpoints,
};


/***/ },

/***/ 8277
(module, __unused_webpack_exports, __webpack_require__) {

var eventMessageChunker = (__webpack_require__(866).eventMessageChunker);
var parseEvent = (__webpack_require__(2957).parseEvent);

function createEventStream(body, parser, model) {
    var eventMessages = eventMessageChunker(body);

    var events = [];

    for (var i = 0; i < eventMessages.length; i++) {
        events.push(parseEvent(parser, eventMessages[i], model));
    }

    return events;
}

/**
 * @api private
 */
module.exports = {
    createEventStream: createEventStream
};


/***/ },

/***/ 6115
(module, __unused_webpack_exports, __webpack_require__) {

var util = (__webpack_require__(9132).util);
var Transform = (__webpack_require__(2203).Transform);
var allocBuffer = util.buffer.alloc;

/** @type {Transform} */
function EventMessageChunkerStream(options) {
    Transform.call(this, options);

    this.currentMessageTotalLength = 0;
    this.currentMessagePendingLength = 0;
    /** @type {Buffer} */
    this.currentMessage = null;

    /** @type {Buffer} */
    this.messageLengthBuffer = null;
}

EventMessageChunkerStream.prototype = Object.create(Transform.prototype);

/**
 *
 * @param {Buffer} chunk
 * @param {string} encoding
 * @param {*} callback
 */
EventMessageChunkerStream.prototype._transform = function(chunk, encoding, callback) {
    var chunkLength = chunk.length;
    var currentOffset = 0;

    while (currentOffset < chunkLength) {
        // create new message if necessary
        if (!this.currentMessage) {
            // working on a new message, determine total length
            var bytesRemaining = chunkLength - currentOffset;
            // prevent edge case where total length spans 2 chunks
            if (!this.messageLengthBuffer) {
                this.messageLengthBuffer = allocBuffer(4);
            }
            var numBytesForTotal = Math.min(
                4 - this.currentMessagePendingLength, // remaining bytes to fill the messageLengthBuffer
                bytesRemaining // bytes left in chunk
            );

            chunk.copy(
                this.messageLengthBuffer,
                this.currentMessagePendingLength,
                currentOffset,
                currentOffset + numBytesForTotal
            );

            this.currentMessagePendingLength += numBytesForTotal;
            currentOffset += numBytesForTotal;

            if (this.currentMessagePendingLength < 4) {
                // not enough information to create the current message
                break;
            }
            this.allocateMessage(this.messageLengthBuffer.readUInt32BE(0));
            this.messageLengthBuffer = null;
        }

        // write data into current message
        var numBytesToWrite = Math.min(
            this.currentMessageTotalLength - this.currentMessagePendingLength, // number of bytes left to complete message
            chunkLength - currentOffset // number of bytes left in the original chunk
        );
        chunk.copy(
            this.currentMessage, // target buffer
            this.currentMessagePendingLength, // target offset
            currentOffset, // chunk offset
            currentOffset + numBytesToWrite // chunk end to write
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

EventMessageChunkerStream.prototype._flush = function(callback) {
    if (this.currentMessageTotalLength) {
        if (this.currentMessageTotalLength === this.currentMessagePendingLength) {
            callback(null, this.currentMessage);
        } else {
            callback(new Error('Truncated event message received.'));
        }
    } else {
        callback();
    }
};

/**
 * @param {number} size Size of the message to be allocated.
 * @api private
 */
EventMessageChunkerStream.prototype.allocateMessage = function(size) {
    if (typeof size !== 'number') {
        throw new Error('Attempted to allocate an event message where size was not a number: ' + size);
    }
    this.currentMessageTotalLength = size;
    this.currentMessagePendingLength = 4;
    this.currentMessage = allocBuffer(size);
    this.currentMessage.writeUInt32BE(size, 0);
};

/**
 * @api private
 */
module.exports = {
    EventMessageChunkerStream: EventMessageChunkerStream
};


/***/ },

/***/ 866
(module) {

/**
 * Takes in a buffer of event messages and splits them into individual messages.
 * @param {Buffer} buffer
 * @api private
 */
function eventMessageChunker(buffer) {
    /** @type Buffer[] */
    var messages = [];
    var offset = 0;

    while (offset < buffer.length) {
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
 */
module.exports = {
    eventMessageChunker: eventMessageChunker
};


/***/ },

/***/ 2293
(module, __unused_webpack_exports, __webpack_require__) {

var Transform = (__webpack_require__(2203).Transform);
var parseEvent = (__webpack_require__(2957).parseEvent);

/** @type {Transform} */
function EventUnmarshallerStream(options) {
    options = options || {};
    // set output to object mode
    options.readableObjectMode = true;
    Transform.call(this, options);
    this._readableState.objectMode = true;

    this.parser = options.parser;
    this.eventStreamModel = options.eventStreamModel;
}

EventUnmarshallerStream.prototype = Object.create(Transform.prototype);

/**
 *
 * @param {Buffer} chunk
 * @param {string} encoding
 * @param {*} callback
 */
EventUnmarshallerStream.prototype._transform = function(chunk, encoding, callback) {
    try {
        var event = parseEvent(this.parser, chunk, this.eventStreamModel);
        this.push(event);
        return callback();
    } catch (err) {
        callback(err);
    }
};

/**
 * @api private
 */
module.exports = {
    EventUnmarshallerStream: EventUnmarshallerStream
};


/***/ },

/***/ 7960
(module, __unused_webpack_exports, __webpack_require__) {

var util = (__webpack_require__(9132).util);
var toBuffer = util.buffer.toBuffer;

/**
 * A lossless representation of a signed, 64-bit integer. Instances of this
 * class may be used in arithmetic expressions as if they were numeric
 * primitives, but the binary representation will be preserved unchanged as the
 * `bytes` property of the object. The bytes should be encoded as big-endian,
 * two's complement integers.
 * @param {Buffer} bytes
 *
 * @api private
 */
function Int64(bytes) {
    if (bytes.length !== 8) {
        throw new Error('Int64 buffers must be exactly 8 bytes');
    }
    if (!util.Buffer.isBuffer(bytes)) bytes = toBuffer(bytes);

    this.bytes = bytes;
}

/**
 * @param {number} number
 * @returns {Int64}
 *
 * @api private
 */
Int64.fromNumber = function(number) {
    if (number > 9223372036854775807 || number < -9223372036854775808) {
        throw new Error(
            number + ' is too large (or, if negative, too small) to represent as an Int64'
        );
    }

    var bytes = new Uint8Array(8);
    for (
        var i = 7, remaining = Math.abs(Math.round(number));
        i > -1 && remaining > 0;
        i--, remaining /= 256
    ) {
        bytes[i] = remaining;
    }

    if (number < 0) {
        negate(bytes);
    }

    return new Int64(bytes);
};

/**
 * @returns {number}
 *
 * @api private
 */
Int64.prototype.valueOf = function() {
    var bytes = this.bytes.slice(0);
    var negative = bytes[0] & 128;
    if (negative) {
        negate(bytes);
    }

    return parseInt(bytes.toString('hex'), 16) * (negative ? -1 : 1);
};

Int64.prototype.toString = function() {
    return String(this.valueOf());
};

/**
 * @param {Buffer} bytes
 *
 * @api private
 */
function negate(bytes) {
    for (var i = 0; i < 8; i++) {
        bytes[i] ^= 0xFF;
    }
    for (var i = 7; i > -1; i--) {
        bytes[i]++;
        if (bytes[i] !== 0) {
            break;
        }
    }
}

/**
 * @api private
 */
module.exports = {
    Int64: Int64
};


/***/ },

/***/ 2957
(module, __unused_webpack_exports, __webpack_require__) {

var parseMessage = (__webpack_require__(1030).parseMessage);

/**
 *
 * @param {*} parser
 * @param {Buffer} message
 * @param {*} shape
 * @api private
 */
function parseEvent(parser, message, shape) {
    var parsedMessage = parseMessage(message);

    // check if message is an event or error
    var messageType = parsedMessage.headers[':message-type'];
    if (messageType) {
        if (messageType.value === 'error') {
            throw parseError(parsedMessage);
        } else if (messageType.value !== 'event') {
            // not sure how to parse non-events/non-errors, ignore for now
            return;
        }
    }

    // determine event type
    var eventType = parsedMessage.headers[':event-type'];
    // check that the event type is modeled
    var eventModel = shape.members[eventType.value];
    if (!eventModel) {
        return;
    }

    var result = {};
    // check if an event payload exists
    var eventPayloadMemberName = eventModel.eventPayloadMemberName;
    if (eventPayloadMemberName) {
        var payloadShape = eventModel.members[eventPayloadMemberName];
        // if the shape is binary, return the byte array
        if (payloadShape.type === 'binary') {
            result[eventPayloadMemberName] = parsedMessage.body;
        } else {
            result[eventPayloadMemberName] = parser.parse(parsedMessage.body.toString(), payloadShape);
        }
    }

    // read event headers
    var eventHeaderNames = eventModel.eventHeaderMemberNames;
    for (var i = 0; i < eventHeaderNames.length; i++) {
        var name = eventHeaderNames[i];
        if (parsedMessage.headers[name]) {
            // parse the header!
            result[name] = eventModel.members[name].toType(parsedMessage.headers[name].value);
        }
    }

    var output = {};
    output[eventType.value] = result;
    return output;
}

function parseError(message) {
    var errorCode = message.headers[':error-code'];
    var errorMessage = message.headers[':error-message'];
    var error = new Error(errorMessage.value || errorMessage);
    error.code = error.name = errorCode.value || errorCode;
    return error;
}

/**
 * @api private
 */
module.exports = {
    parseEvent: parseEvent
};


/***/ },

/***/ 1030
(module, __unused_webpack_exports, __webpack_require__) {

var Int64 = (__webpack_require__(7960).Int64);

var splitMessage = (__webpack_require__(1769).splitMessage);

var BOOLEAN_TAG = 'boolean';
var BYTE_TAG = 'byte';
var SHORT_TAG = 'short';
var INT_TAG = 'integer';
var LONG_TAG = 'long';
var BINARY_TAG = 'binary';
var STRING_TAG = 'string';
var TIMESTAMP_TAG = 'timestamp';
var UUID_TAG = 'uuid';

/**
 * @api private
 *
 * @param {Buffer} headers
 */
function parseHeaders(headers) {
    var out = {};
    var position = 0;
    while (position < headers.length) {
        var nameLength = headers.readUInt8(position++);
        var name = headers.slice(position, position + nameLength).toString();
        position += nameLength;
        switch (headers.readUInt8(position++)) {
            case 0 /* boolTrue */:
                out[name] = {
                    type: BOOLEAN_TAG,
                    value: true
                };
                break;
            case 1 /* boolFalse */:
                out[name] = {
                    type: BOOLEAN_TAG,
                    value: false
                };
                break;
            case 2 /* byte */:
                out[name] = {
                    type: BYTE_TAG,
                    value: headers.readInt8(position++)
                };
                break;
            case 3 /* short */:
                out[name] = {
                    type: SHORT_TAG,
                    value: headers.readInt16BE(position)
                };
                position += 2;
                break;
            case 4 /* integer */:
                out[name] = {
                    type: INT_TAG,
                    value: headers.readInt32BE(position)
                };
                position += 4;
                break;
            case 5 /* long */:
                out[name] = {
                    type: LONG_TAG,
                    value: new Int64(headers.slice(position, position + 8))
                };
                position += 8;
                break;
            case 6 /* byteArray */:
                var binaryLength = headers.readUInt16BE(position);
                position += 2;
                out[name] = {
                    type: BINARY_TAG,
                    value: headers.slice(position, position + binaryLength)
                };
                position += binaryLength;
                break;
            case 7 /* string */:
                var stringLength = headers.readUInt16BE(position);
                position += 2;
                out[name] = {
                    type: STRING_TAG,
                    value: headers.slice(
                        position,
                        position + stringLength
                    ).toString()
                };
                position += stringLength;
                break;
            case 8 /* timestamp */:
                out[name] = {
                    type: TIMESTAMP_TAG,
                    value: new Date(
                        new Int64(headers.slice(position, position + 8))
                            .valueOf()
                    )
                };
                position += 8;
                break;
            case 9 /* uuid */:
                var uuidChars = headers.slice(position, position + 16)
                    .toString('hex');
                position += 16;
                out[name] = {
                    type: UUID_TAG,
                    value: uuidChars.substr(0, 8) + '-' +
                        uuidChars.substr(8, 4) + '-' +
                        uuidChars.substr(12, 4) + '-' +
                        uuidChars.substr(16, 4) + '-' +
                        uuidChars.substr(20)
                };
                break;
            default:
                throw new Error('Unrecognized header type tag');
        }
    }
    return out;
}

function parseMessage(message) {
    var parsed = splitMessage(message);
    return { headers: parseHeaders(parsed.headers), body: parsed.body };
}

/**
 * @api private
 */
module.exports = {
    parseMessage: parseMessage
};


/***/ },

/***/ 1769
(module, __unused_webpack_exports, __webpack_require__) {

var util = (__webpack_require__(9132).util);
var toBuffer = util.buffer.toBuffer;

// All prelude components are unsigned, 32-bit integers
var PRELUDE_MEMBER_LENGTH = 4;
// The prelude consists of two components
var PRELUDE_LENGTH = PRELUDE_MEMBER_LENGTH * 2;
// Checksums are always CRC32 hashes.
var CHECKSUM_LENGTH = 4;
// Messages must include a full prelude, a prelude checksum, and a message checksum
var MINIMUM_MESSAGE_LENGTH = PRELUDE_LENGTH + CHECKSUM_LENGTH * 2;

/**
 * @api private
 *
 * @param {Buffer} message
 */
function splitMessage(message) {
    if (!util.Buffer.isBuffer(message)) message = toBuffer(message);

    if (message.length < MINIMUM_MESSAGE_LENGTH) {
        throw new Error('Provided message too short to accommodate event stream message overhead');
    }

    if (message.length !== message.readUInt32BE(0)) {
        throw new Error('Reported message length does not match received message length');
    }

    var expectedPreludeChecksum = message.readUInt32BE(PRELUDE_LENGTH);

    if (
        expectedPreludeChecksum !== util.crypto.crc32(
            message.slice(0, PRELUDE_LENGTH)
        )
    ) {
        throw new Error(
            'The prelude checksum specified in the message (' +
            expectedPreludeChecksum +
            ') does not match the calculated CRC32 checksum.'
        );
    }

    var expectedMessageChecksum = message.readUInt32BE(message.length - CHECKSUM_LENGTH);

    if (
        expectedMessageChecksum !== util.crypto.crc32(
            message.slice(0, message.length - CHECKSUM_LENGTH)
        )
    ) {
        throw new Error(
            'The message checksum did not match the expected value of ' +
                expectedMessageChecksum
        );
    }

    var headersStart = PRELUDE_LENGTH + CHECKSUM_LENGTH;
    var headersEnd = headersStart + message.readUInt32BE(PRELUDE_MEMBER_LENGTH);

    return {
        headers: message.slice(headersStart, headersEnd),
        body: message.slice(headersEnd, message.length - CHECKSUM_LENGTH),
    };
}

/**
 * @api private
 */
module.exports = {
    splitMessage: splitMessage
};


/***/ },

/***/ 3422
(module, __unused_webpack_exports, __webpack_require__) {

/**
 * What is necessary to create an event stream in node?
 *  - http response stream
 *  - parser
 *  - event stream model
 */

var EventMessageChunkerStream = (__webpack_require__(6115).EventMessageChunkerStream);
var EventUnmarshallerStream = (__webpack_require__(2293).EventUnmarshallerStream);

function createEventStream(stream, parser, model) {
    var eventStream = new EventUnmarshallerStream({
        parser: parser,
        eventStreamModel: model
    });

    var eventMessageChunker = new EventMessageChunkerStream();

    stream.pipe(
        eventMessageChunker
    ).pipe(eventStream);

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
 */
module.exports = {
    createEventStream: createEventStream
};


/***/ },

/***/ 5585
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var SequentialExecutor = __webpack_require__(5138);
var DISCOVER_ENDPOINT = (__webpack_require__(1130).discoverEndpoint);
/**
 * The namespace used to register global event listeners for request building
 * and sending.
 */
AWS.EventListeners = {
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
   */
  Core: {} /* doc hack */
};

/**
 * @api private
 */
function getOperationAuthtype(req) {
  if (!req.service.api.operations) {
    return '';
  }
  var operation = req.service.api.operations[req.operation];
  return operation ? operation.authtype : '';
}

/**
 * @api private
 */
function getIdentityType(req) {
  var service = req.service;

  if (service.config.signatureVersion) {
    return service.config.signatureVersion;
  }

  if (service.api.signatureVersion) {
    return service.api.signatureVersion;
  }

  return getOperationAuthtype(req);
}

AWS.EventListeners = {
  Core: new SequentialExecutor().addNamedListeners(function(add, addAsync) {
    addAsync(
      'VALIDATE_CREDENTIALS', 'validate',
      function VALIDATE_CREDENTIALS(req, done) {
        if (!req.service.api.signatureVersion && !req.service.config.signatureVersion) return done(); // none

        var identityType = getIdentityType(req);
        if (identityType === 'bearer') {
          req.service.config.getToken(function(err) {
            if (err) {
              req.response.error = AWS.util.error(err, {code: 'TokenError'});
            }
            done();
          });
          return;
        }

        req.service.config.getCredentials(function(err) {
          if (err) {
            req.response.error = AWS.util.error(err,
              {
                code: 'CredentialsError',
                message: 'Missing credentials in config, if using AWS_CONFIG_FILE, set AWS_SDK_LOAD_CONFIG=1'
              }
            );
          }
          done();
        });
    });

    add('VALIDATE_REGION', 'validate', function VALIDATE_REGION(req) {
      if (!req.service.isGlobalEndpoint) {
        var dnsHostRegex = new RegExp(/^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])$/);
        if (!req.service.config.region) {
          req.response.error = AWS.util.error(new Error(),
            {code: 'ConfigError', message: 'Missing region in config'});
        } else if (!dnsHostRegex.test(req.service.config.region)) {
          req.response.error = AWS.util.error(new Error(),
            {code: 'ConfigError', message: 'Invalid region in config'});
        }
      }
    });

    add('BUILD_IDEMPOTENCY_TOKENS', 'validate', function BUILD_IDEMPOTENCY_TOKENS(req) {
      if (!req.service.api.operations) {
        return;
      }
      var operation = req.service.api.operations[req.operation];
      if (!operation) {
        return;
      }
      var idempotentMembers = operation.idempotentMembers;
      if (!idempotentMembers.length) {
        return;
      }
      // creates a copy of params so user's param object isn't mutated
      var params = AWS.util.copy(req.params);
      for (var i = 0, iLen = idempotentMembers.length; i < iLen; i++) {
        if (!params[idempotentMembers[i]]) {
          // add the member
          params[idempotentMembers[i]] = AWS.util.uuid.v4();
        }
      }
      req.params = params;
    });

    add('VALIDATE_PARAMETERS', 'validate', function VALIDATE_PARAMETERS(req) {
      if (!req.service.api.operations) {
        return;
      }
      var rules = req.service.api.operations[req.operation].input;
      var validation = req.service.config.paramValidation;
      new AWS.ParamValidator(validation).validate(rules, req.params);
    });

    add('COMPUTE_CHECKSUM', 'afterBuild', function COMPUTE_CHECKSUM(req) {
      if (!req.service.api.operations) {
        return;
      }
      var operation = req.service.api.operations[req.operation];
      if (!operation) {
        return;
      }
      var body = req.httpRequest.body;
      var isNonStreamingPayload = body && (AWS.util.Buffer.isBuffer(body) || typeof body === 'string');
      var headers = req.httpRequest.headers;
      if (
        operation.httpChecksumRequired &&
        req.service.config.computeChecksums &&
        isNonStreamingPayload &&
        !headers['Content-MD5']
      ) {
        var md5 = AWS.util.crypto.md5(body, 'base64');
        headers['Content-MD5'] = md5;
      }
    });

    addAsync('COMPUTE_SHA256', 'afterBuild', function COMPUTE_SHA256(req, done) {
      req.haltHandlersOnError();
      if (!req.service.api.operations) {
        return;
      }
      var operation = req.service.api.operations[req.operation];
      var authtype = operation ? operation.authtype : '';
      if (!req.service.api.signatureVersion && !authtype && !req.service.config.signatureVersion) return done(); // none
      if (req.service.getSignerClass(req) === AWS.Signers.V4) {
        var body = req.httpRequest.body || '';
        if (authtype.indexOf('unsigned-body') >= 0) {
          req.httpRequest.headers['X-Amz-Content-Sha256'] = 'UNSIGNED-PAYLOAD';
          return done();
        }
        AWS.util.computeSha256(body, function(err, sha) {
          if (err) {
            done(err);
          }
          else {
            req.httpRequest.headers['X-Amz-Content-Sha256'] = sha;
            done();
          }
        });
      } else {
        done();
      }
    });

    add('SET_CONTENT_LENGTH', 'afterBuild', function SET_CONTENT_LENGTH(req) {
      var authtype = getOperationAuthtype(req);
      var payloadMember = AWS.util.getRequestPayloadShape(req);
      if (req.httpRequest.headers['Content-Length'] === undefined) {
        try {
          var length = AWS.util.string.byteLength(req.httpRequest.body);
          req.httpRequest.headers['Content-Length'] = length;
        } catch (err) {
          if (payloadMember && payloadMember.isStreaming) {
            if (payloadMember.requiresLength) {
              //streaming payload requires length(s3, glacier)
              throw err;
            } else if (authtype.indexOf('unsigned-body') >= 0) {
              //unbounded streaming payload(lex, mediastore)
              req.httpRequest.headers['Transfer-Encoding'] = 'chunked';
              return;
            } else {
              throw err;
            }
          }
          throw err;
        }
      }
    });

    add('SET_HTTP_HOST', 'afterBuild', function SET_HTTP_HOST(req) {
      req.httpRequest.headers['Host'] = req.httpRequest.endpoint.host;
    });

    add('SET_TRACE_ID', 'afterBuild', function SET_TRACE_ID(req) {
      var traceIdHeaderName = 'X-Amzn-Trace-Id';
      if (AWS.util.isNode() && !Object.hasOwnProperty.call(req.httpRequest.headers, traceIdHeaderName)) {
        var ENV_LAMBDA_FUNCTION_NAME = 'AWS_LAMBDA_FUNCTION_NAME';
        var ENV_TRACE_ID = '_X_AMZN_TRACE_ID';
        var functionName = process.env[ENV_LAMBDA_FUNCTION_NAME];
        var traceId = process.env[ENV_TRACE_ID];
        if (
          typeof functionName === 'string' &&
          functionName.length > 0 &&
          typeof traceId === 'string' &&
          traceId.length > 0
        ) {
          req.httpRequest.headers[traceIdHeaderName] = traceId;
        }
      }
    });

    add('RESTART', 'restart', function RESTART() {
      var err = this.response.error;
      if (!err || !err.retryable) return;

      this.httpRequest = new AWS.HttpRequest(
        this.service.endpoint,
        this.service.region
      );

      if (this.response.retryCount < this.service.config.maxRetries) {
        this.response.retryCount++;
      } else {
        this.response.error = null;
      }
    });

    var addToHead = true;
    addAsync('DISCOVER_ENDPOINT', 'sign', DISCOVER_ENDPOINT, addToHead);

    addAsync('SIGN', 'sign', function SIGN(req, done) {
      var service = req.service;
      var identityType = getIdentityType(req);
      if (!identityType || identityType.length === 0) return done(); // none

      if (identityType === 'bearer') {
        service.config.getToken(function (err, token) {
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
      } else {
        service.config.getCredentials(function (err, credentials) {
          if (err) {
            req.response.error = err;
            return done();
          }

          try {
            var date = service.getSkewCorrectedDate();
            var SignerClass = service.getSignerClass(req);
            var operations = req.service.api.operations || {};
            var operation = operations[req.operation];
            var signer = new SignerClass(req.httpRequest,
              service.getSigningName(req),
              {
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

      }
    });

    add('VALIDATE_RESPONSE', 'validateResponse', function VALIDATE_RESPONSE(resp) {
      if (this.service.successfulResponse(resp, this)) {
        resp.data = {};
        resp.error = null;
      } else {
        resp.data = null;
        resp.error = AWS.util.error(new Error(),
          {code: 'UnknownError', message: 'An unknown error occurred.'});
      }
    });

    add('ERROR', 'error', function ERROR(err, resp) {
      var awsQueryCompatible = resp.request.service.api.awsQueryCompatible;
      if (awsQueryCompatible) {
        var headers = resp.httpResponse.headers;
        var queryErrorCode = headers ? headers['x-amzn-query-error'] : undefined;
        if (queryErrorCode && queryErrorCode.includes(';')) {
          resp.error.code = queryErrorCode.split(';')[0];
        }
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
          resp.request.emit(
            'httpHeaders',
            [statusCode, headers, resp, statusMessage]
          );

          if (!resp.httpResponse.streaming) {
            if (AWS.HttpClient.streamsApiVersion === 2) { // streams2 API check
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
                if (data !== null) {
                  resp.request.emit('httpData', [data, resp]);
                }
              });
            } else { // legacy streams API
              httpResp.on('data', function onData(data) {
                resp.request.emit('httpData', [data, resp]);
              });
            }
          }
        });

        httpResp.on('end', function onEnd() {
          if (!stream || !stream.didCallback) {
            if (AWS.HttpClient.streamsApiVersion === 2 && (operation.hasEventOutput && service.successfulResponse(resp))) {
              // don't concatenate response chunks when streaming event stream data when response is successful
              return;
            }
            resp.request.emit('httpDone');
            done();
          }
        });
      }

      function progress(httpResp) {
        httpResp.on('sendProgress', function onSendProgress(value) {
          resp.request.emit('httpUploadProgress', [value, resp]);
        });

        httpResp.on('receiveProgress', function onReceiveProgress(value) {
          resp.request.emit('httpDownloadProgress', [value, resp]);
        });
      }

      function error(err) {
        if (err.code !== 'RequestAbortedError') {
          var errCode = err.code === 'TimeoutError' ? err.code : 'NetworkingError';
          err = AWS.util.error(err, {
            code: errCode,
            region: resp.request.httpRequest.region,
            hostname: resp.request.httpRequest.endpoint.hostname,
            retryable: true
          });
        }
        resp.error = err;
        resp.request.emit('httpError', [resp.error, resp], function() {
          done();
        });
      }

      function executeSend() {
        var http = AWS.HttpClient.getInstance();
        var httpOptions = resp.request.service.config.httpOptions || {};
        try {
          var stream = http.handleRequest(resp.request.httpRequest, httpOptions,
                                          callback, error);
          progress(stream);
        } catch (err) {
          error(err);
        }
      }
      var timeDiff = (resp.request.service.getSkewCorrectedDate() - this.signedAt) / 1000;
      if (timeDiff >= 60 * 10) { // if we signed 10min ago, re-sign
        this.emit('sign', [this], function(err) {
          if (err) done(err);
          else executeSend();
        });
      } else {
        executeSend();
      }
    });

    add('HTTP_HEADERS', 'httpHeaders',
        function HTTP_HEADERS(statusCode, headers, resp, statusMessage) {
      resp.httpResponse.statusCode = statusCode;
      resp.httpResponse.statusMessage = statusMessage;
      resp.httpResponse.headers = headers;
      resp.httpResponse.body = AWS.util.buffer.toBuffer('');
      resp.httpResponse.buffers = [];
      resp.httpResponse.numBytes = 0;
      var dateHeader = headers.date || headers.Date;
      var service = resp.request.service;
      if (dateHeader) {
        var serverTime = Date.parse(dateHeader);
        if (service.config.correctClockSkew
            && service.isClockSkewed(serverTime)) {
          service.applyClockOffset(serverTime);
        }
      }
    });

    add('HTTP_DATA', 'httpData', function HTTP_DATA(chunk, resp) {
      if (chunk) {
        if (AWS.util.isNode()) {
          resp.httpResponse.numBytes += chunk.length;

          var total = resp.httpResponse.headers['content-length'];
          var progress = { loaded: resp.httpResponse.numBytes, total: total };
          resp.request.emit('httpDownloadProgress', [progress, resp]);
        }

        resp.httpResponse.buffers.push(AWS.util.buffer.toBuffer(chunk));
      }
    });

    add('HTTP_DONE', 'httpDone', function HTTP_DONE(resp) {
      // convert buffers array into single buffer
      if (resp.httpResponse.buffers && resp.httpResponse.buffers.length > 0) {
        var body = AWS.util.buffer.concat(resp.httpResponse.buffers);
        resp.httpResponse.body = body;
      }
      delete resp.httpResponse.numBytes;
      delete resp.httpResponse.buffers;
    });

    add('FINALIZE_ERROR', 'retry', function FINALIZE_ERROR(resp) {
      if (resp.httpResponse.statusCode) {
        resp.error.statusCode = resp.httpResponse.statusCode;
        if (resp.error.retryable === undefined) {
          resp.error.retryable = this.service.retryableError(resp.error, this);
        }
      }
    });

    add('INVALIDATE_CREDENTIALS', 'retry', function INVALIDATE_CREDENTIALS(resp) {
      if (!resp.error) return;
      switch (resp.error.code) {
        case 'RequestExpired': // EC2 only
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
        if (err.code.match(/Signature/) && err.message.match(/expired/)) {
          resp.error.retryable = true;
        }
      }
    });

    add('CLOCK_SKEWED', 'retry', function CLOCK_SKEWED(resp) {
      if (!resp.error) return;
      if (this.service.clockSkewError(resp.error)
          && this.service.config.correctClockSkew) {
        resp.error.retryable = true;
      }
    });

    add('REDIRECT', 'retry', function REDIRECT(resp) {
      if (resp.error && resp.error.statusCode >= 300 &&
          resp.error.statusCode < 400 && resp.httpResponse.headers['location']) {
        this.httpRequest.endpoint =
          new AWS.Endpoint(resp.httpResponse.headers['location']);
        this.httpRequest.headers['Host'] = this.httpRequest.endpoint.host;
        this.httpRequest.path = this.httpRequest.endpoint.path;
        resp.error.redirect = true;
        resp.error.retryable = true;
      }
    });

    add('RETRY_CHECK', 'retry', function RETRY_CHECK(resp) {
      if (resp.error) {
        if (resp.error.redirect && resp.redirectCount < resp.maxRedirects) {
          resp.error.retryDelay = 0;
        } else if (resp.retryCount < resp.maxRetries) {
          resp.error.retryDelay = this.service.retryDelays(resp.retryCount, resp.error) || 0;
        }
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
      } else {
        done();
      }
    });
  }),

  CorePost: new SequentialExecutor().addNamedListeners(function(add) {
    add('EXTRACT_REQUEST_ID', 'extractData', AWS.util.extractRequestId);
    add('EXTRACT_REQUEST_ID', 'extractError', AWS.util.extractRequestId);

    add('ENOTFOUND_ERROR', 'httpError', function ENOTFOUND_ERROR(err) {
      function isDNSError(err) {
        return err.errno === 'ENOTFOUND' ||
          typeof err.errno === 'number' &&
          typeof AWS.util.getSystemErrorName === 'function' &&
          ['EAI_NONAME', 'EAI_NODATA'].indexOf(AWS.util.getSystemErrorName(err.errno) >= 0);
      }
      if (err.code === 'NetworkingError' && isDNSError(err)) {
        var message = 'Inaccessible host: `' + err.hostname + '\' at port `' + err.port +
          '\'. This service may not be available in the `' + err.region +
          '\' region.';
        this.response.error = AWS.util.error(new Error(message), {
          code: 'UnknownEndpoint',
          region: err.region,
          hostname: err.hostname,
          retryable: true,
          originalError: err
        });
      }
    });
  }),

  Logger: new SequentialExecutor().addNamedListeners(function(add) {
    add('LOG_REQUEST', 'complete', function LOG_REQUEST(resp) {
      var req = resp.request;
      var logger = req.service.config.logger;
      if (!logger) return;
      function filterSensitiveLog(inputShape, shape) {
        if (!shape) {
          return shape;
        }
        if (inputShape.isSensitive) {
          return '***SensitiveInformation***';
        }
        switch (inputShape.type) {
          case 'structure':
            var struct = {};
            AWS.util.each(shape, function(subShapeName, subShape) {
              if (Object.prototype.hasOwnProperty.call(inputShape.members, subShapeName)) {
                struct[subShapeName] = filterSensitiveLog(inputShape.members[subShapeName], subShape);
              } else {
                struct[subShapeName] = subShape;
              }
            });
            return struct;
          case 'list':
            var list = [];
            AWS.util.arrayEach(shape, function(subShape, index) {
              list.push(filterSensitiveLog(inputShape.member, subShape));
            });
            return list;
          case 'map':
            var map = {};
            AWS.util.each(shape, function(key, value) {
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
        if (
          req.service.api.operations &&
              req.service.api.operations[req.operation] &&
              req.service.api.operations[req.operation].input
        ) {
          var inputShape = req.service.api.operations[req.operation].input;
          censoredParams = filterSensitiveLog(inputShape, req.params);
        }
        var params = (__webpack_require__(9023).inspect)(censoredParams, true, null);
        var message = '';
        if (ansi) message += '\x1B[33m';
        message += '[AWS ' + req.service.serviceIdentifier + ' ' + status;
        message += ' ' + delta.toString() + 's ' + resp.retryCount + ' retries]';
        if (ansi) message += '\x1B[0;1m';
        message += ' ' + AWS.util.string.lowerFirst(req.operation);
        message += '(' + params + ')';
        if (ansi) message += '\x1B[0m';
        return message;
      }

      var line = buildMessage();
      if (typeof logger.log === 'function') {
        logger.log(line);
      } else if (typeof logger.write === 'function') {
        logger.write(line + '\n');
      }
    });
  }),

  Json: new SequentialExecutor().addNamedListeners(function(add) {
    var svc = __webpack_require__(3652);
    add('BUILD', 'build', svc.buildRequest);
    add('EXTRACT_DATA', 'extractData', svc.extractData);
    add('EXTRACT_ERROR', 'extractError', svc.extractError);
  }),

  Rest: new SequentialExecutor().addNamedListeners(function(add) {
    var svc = __webpack_require__(9648);
    add('BUILD', 'build', svc.buildRequest);
    add('EXTRACT_DATA', 'extractData', svc.extractData);
    add('EXTRACT_ERROR', 'extractError', svc.extractError);
  }),

  RestJson: new SequentialExecutor().addNamedListeners(function(add) {
    var svc = __webpack_require__(5897);
    add('BUILD', 'build', svc.buildRequest);
    add('EXTRACT_DATA', 'extractData', svc.extractData);
    add('EXTRACT_ERROR', 'extractError', svc.extractError);
    add('UNSET_CONTENT_LENGTH', 'afterBuild', svc.unsetContentLength);
  }),

  RestXml: new SequentialExecutor().addNamedListeners(function(add) {
    var svc = __webpack_require__(5830);
    add('BUILD', 'build', svc.buildRequest);
    add('EXTRACT_DATA', 'extractData', svc.extractData);
    add('EXTRACT_ERROR', 'extractError', svc.extractError);
  }),

  Query: new SequentialExecutor().addNamedListeners(function(add) {
    var svc = __webpack_require__(324);
    add('BUILD', 'build', svc.buildRequest);
    add('EXTRACT_DATA', 'extractData', svc.extractData);
    add('EXTRACT_ERROR', 'extractError', svc.extractError);
  })
};


/***/ },

/***/ 5615
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var inherit = AWS.util.inherit;

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
 */
AWS.Endpoint = inherit({

  /**
   * @overload Endpoint(endpoint)
   *   Constructs a new endpoint given an endpoint URL. If the
   *   URL omits a protocol (http or https), the default protocol
   *   set in the global {AWS.config} will be used.
   *   @param endpoint [String] the URL to construct an endpoint from
   */
  constructor: function Endpoint(endpoint, config) {
    AWS.util.hideProperties(this, ['slashes', 'auth', 'hash', 'search', 'query']);

    if (typeof endpoint === 'undefined' || endpoint === null) {
      throw new Error('Invalid endpoint: ' + endpoint);
    } else if (typeof endpoint !== 'string') {
      return AWS.util.copy(endpoint);
    }

    if (!endpoint.match(/^http/)) {
      var useSSL = config && config.sslEnabled !== undefined ?
        config.sslEnabled : AWS.config.sslEnabled;
      endpoint = (useSSL ? 'https' : 'http') + '://' + endpoint;
    }

    AWS.util.update(this, AWS.util.urlParse(endpoint));

    // Ensure the port property is set as an integer
    if (this.port) {
      this.port = parseInt(this.port, 10);
    } else {
      this.port = this.protocol === 'https:' ? 443 : 80;
    }
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
 */
AWS.HttpRequest = inherit({

  /**
   * @api private
   */
  constructor: function HttpRequest(endpoint, region) {
    endpoint = new AWS.Endpoint(endpoint);
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
   */
  setUserAgent: function setUserAgent() {
    this._userAgent = this.headers[this.getUserAgentHeaderName()] = AWS.util.userAgent();
  },

  getUserAgentHeaderName: function getUserAgentHeaderName() {
    var prefix = AWS.util.isBrowser() ? 'X-Amz-' : '';
    return prefix + 'User-Agent';
  },

  /**
   * @api private
   */
  appendToUserAgent: function appendToUserAgent(agentPartial) {
    if (typeof agentPartial === 'string' && agentPartial) {
      this._userAgent += ' ' + agentPartial;
    }
    this.headers[this.getUserAgentHeaderName()] = this._userAgent;
  },

  /**
   * @api private
   */
  getUserAgent: function getUserAgent() {
    return this._userAgent;
  },

  /**
   * @return [String] the part of the {path} excluding the
   *   query string
   */
  pathname: function pathname() {
    return this.path.split('?', 1)[0];
  },

  /**
   * @return [String] the query string portion of the {path}
   */
  search: function search() {
    var query = this.path.split('?', 2)[1];
    if (query) {
      query = AWS.util.queryStringParse(query);
      return AWS.util.queryParamsToString(query);
    }
    return '';
  },

  /**
   * @api private
   * update httpRequest endpoint with endpoint string
   */
  updateEndpoint: function updateEndpoint(endpointStr) {
    var newEndpoint = new AWS.Endpoint(endpointStr);
    this.endpoint = newEndpoint;
    this.path = newEndpoint.path || '/';
    if (this.headers['Host']) {
      this.headers['Host'] = newEndpoint.host;
    }
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
 */
AWS.HttpResponse = inherit({

  /**
   * @api private
   */
  constructor: function HttpResponse() {
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
   */
  createUnbufferedStream: function createUnbufferedStream() {
    this.streaming = true;
    return this.stream;
  }
});


AWS.HttpClient = inherit({});

/**
 * @api private
 */
AWS.HttpClient.getInstance = function getInstance() {
  if (this.singleton === undefined) {
    this.singleton = new this();
  }
  return this.singleton;
};


/***/ },

/***/ 9958
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var Stream = AWS.util.stream.Stream;
var TransformStream = AWS.util.stream.Transform;
var ReadableStream = AWS.util.stream.Readable;
__webpack_require__(5615);
var CONNECTION_REUSE_ENV_NAME = 'AWS_NODEJS_CONNECTION_REUSE_ENABLED';

/**
 * @api private
 */
AWS.NodeHttpClient = AWS.util.inherit({
  handleRequest: function handleRequest(httpRequest, httpOptions, callback, errCallback) {
    var self = this;
    var endpoint = httpRequest.endpoint;
    var pathPrefix = '';
    if (!httpOptions) httpOptions = {};
    if (httpOptions.proxy) {
      pathPrefix = endpoint.protocol + '//' + endpoint.hostname;
      if (endpoint.port !== 80 && endpoint.port !== 443) {
        pathPrefix += ':' + endpoint.port;
      }
      endpoint = new AWS.Endpoint(httpOptions.proxy);
    }

    var useSSL = endpoint.protocol === 'https:';
    var http = useSSL ? __webpack_require__(5692) : __webpack_require__(8611);
    var options = {
      host: endpoint.hostname,
      port: endpoint.port,
      method: httpRequest.method,
      headers: httpRequest.headers,
      path: pathPrefix + httpRequest.path
    };

    AWS.util.update(options, httpOptions);

    if (!httpOptions.agent) {
      options.agent = this.getAgent(useSSL, {
        keepAlive: process.env[CONNECTION_REUSE_ENV_NAME] === '1' ? true : false
      });
    }

    delete options.proxy; // proxy isn't an HTTP option
    delete options.timeout; // timeout isn't an HTTP option

    var stream = http.request(options, function (httpResp) {
      if (stream.didCallback) return;

      callback(httpResp);
      httpResp.emit(
        'headers',
        httpResp.statusCode,
        httpResp.headers,
        httpResp.statusMessage
      );
    });
    httpRequest.stream = stream; // attach stream to httpRequest
    stream.didCallback = false;

    // connection timeout support
    if (httpOptions.connectTimeout) {
      var connectTimeoutId;
      stream.on('socket', function(socket) {
        if (socket.connecting) {
          connectTimeoutId = setTimeout(function connectTimeout() {
            if (stream.didCallback) return; stream.didCallback = true;

            stream.abort();
            errCallback(AWS.util.error(
              new Error('Socket timed out without establishing a connection'),
              {code: 'TimeoutError'}
            ));
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
      if (stream.didCallback) return; stream.didCallback = true;

      var msg = 'Connection timed out after ' + httpOptions.timeout + 'ms';
      errCallback(AWS.util.error(new Error(msg), {code: 'TimeoutError'}));
      stream.abort();
    });

    stream.on('error', function(err) {
      if (connectTimeoutId) {
        clearTimeout(connectTimeoutId);
        connectTimeoutId = null;
      }
      if (stream.didCallback) return; stream.didCallback = true;
      if ('ECONNRESET' === err.code || 'EPIPE' === err.code || 'ETIMEDOUT' === err.code) {
        errCallback(AWS.util.error(err, {code: 'TimeoutError'}));
      } else {
        errCallback(err);
      }
    });

    var expect = httpRequest.headers.Expect || httpRequest.headers.expect;
    if (expect === '100-continue') {
      stream.once('continue', function() {
        self.writeBody(stream, httpRequest);
      });
    } else {
      this.writeBody(stream, httpRequest);
    }

    return stream;
  },

  writeBody: function writeBody(stream, httpRequest) {
    var body = httpRequest.body;
    var totalBytes = parseInt(httpRequest.headers['Content-Length'], 10);

    if (body instanceof Stream) {
      // For progress support of streaming content -
      // pipe the data through a transform stream to emit 'sendProgress' events
      var progressStream = this.progressStream(stream, totalBytes);
      if (progressStream) {
        body.pipe(progressStream).pipe(stream);
      } else {
        body.pipe(stream);
      }
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
    } else {
      // no request body
      stream.end();
    }
  },

  /**
   * Create the https.Agent or http.Agent according to the request schema.
   */
  getAgent: function getAgent(useSSL, agentOptions) {
    var http = useSSL ? __webpack_require__(5692) : __webpack_require__(8611);
    if (useSSL) {
      if (!AWS.NodeHttpClient.sslAgent) {
        AWS.NodeHttpClient.sslAgent = new http.Agent(AWS.util.merge({
          rejectUnauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ? false : true
        }, agentOptions || {}));
        AWS.NodeHttpClient.sslAgent.setMaxListeners(0);

        // delegate maxSockets to globalAgent, set a default limit of 50 if current value is Infinity.
        // Users can bypass this default by supplying their own Agent as part of SDK configuration.
        Object.defineProperty(AWS.NodeHttpClient.sslAgent, 'maxSockets', {
          enumerable: true,
          get: function() {
            var defaultMaxSockets = 50;
            var globalAgent = http.globalAgent;
            if (globalAgent && globalAgent.maxSockets !== Infinity && typeof globalAgent.maxSockets === 'number') {
              return globalAgent.maxSockets;
            }
            return defaultMaxSockets;
          }
        });
      }
      return AWS.NodeHttpClient.sslAgent;
    } else {
      if (!AWS.NodeHttpClient.agent) {
        AWS.NodeHttpClient.agent = new http.Agent(agentOptions);
      }
      return AWS.NodeHttpClient.agent;
    }
  },

  progressStream: function progressStream(stream, totalBytes) {
    if (typeof TransformStream === 'undefined') {
      // for node 0.8 there is no streaming progress
      return;
    }
    var loadedBytes = 0;
    var reporter = new TransformStream();
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
 */

/**
 * @api private
 */
AWS.HttpClient.prototype = AWS.NodeHttpClient.prototype;

/**
 * @api private
 */
AWS.HttpClient.streamsApiVersion = ReadableStream ? 2 : 1;


/***/ },

/***/ 3681
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);

function JsonBuilder() { }

JsonBuilder.prototype.build = function(value, shape) {
  return JSON.stringify(translate(value, shape));
};

function translate(value, shape) {
  if (!shape || value === undefined || value === null) return undefined;

  switch (shape.type) {
    case 'structure': return translateStructure(value, shape);
    case 'map': return translateMap(value, shape);
    case 'list': return translateList(value, shape);
    default: return translateScalar(value, shape);
  }
}

function translateStructure(structure, shape) {
  if (shape.isDocument) {
    return structure;
  }
  var struct = {};
  util.each(structure, function(name, value) {
    var memberShape = shape.members[name];
    if (memberShape) {
      if (memberShape.location !== 'body') return;
      var locationName = memberShape.isLocationName ? memberShape.name : name;
      var result = translate(value, memberShape);
      if (result !== undefined) struct[locationName] = result;
    }
  });
  return struct;
}

function translateList(list, shape) {
  var out = [];
  util.arrayEach(list, function(value) {
    var result = translate(value, shape.member);
    if (result !== undefined) out.push(result);
  });
  return out;
}

function translateMap(map, shape) {
  var out = {};
  util.each(map, function(key, value) {
    var result = translate(value, shape.value);
    if (result !== undefined) out[key] = result;
  });
  return out;
}

function translateScalar(value, shape) {
  return shape.toWireFormat(value);
}

/**
 * @api private
 */
module.exports = JsonBuilder;


/***/ },

/***/ 5919
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);

function JsonParser() { }

JsonParser.prototype.parse = function(value, shape) {
  return translate(JSON.parse(value), shape);
};

function translate(value, shape) {
  if (!shape || value === undefined) return undefined;

  switch (shape.type) {
    case 'structure': return translateStructure(value, shape);
    case 'map': return translateMap(value, shape);
    case 'list': return translateList(value, shape);
    default: return translateScalar(value, shape);
  }
}

function translateStructure(structure, shape) {
  if (structure == null) return undefined;
  if (shape.isDocument) return structure;

  var struct = {};
  var shapeMembers = shape.members;
  var isAwsQueryCompatible = shape.api && shape.api.awsQueryCompatible;
  util.each(shapeMembers, function(name, memberShape) {
    var locationName = memberShape.isLocationName ? memberShape.name : name;
    if (Object.prototype.hasOwnProperty.call(structure, locationName)) {
      var value = structure[locationName];
      var result = translate(value, memberShape);
      if (result !== undefined) struct[name] = result;
    } else if (isAwsQueryCompatible && memberShape.defaultValue) {
      if (memberShape.type === 'list') {
        struct[name] = typeof memberShape.defaultValue === 'function' ? memberShape.defaultValue() : memberShape.defaultValue;
      }
    }
  });
  return struct;
}

function translateList(list, shape) {
  if (list == null) return undefined;

  var out = [];
  util.arrayEach(list, function(value) {
    var result = translate(value, shape.member);
    if (result === undefined) out.push(null);
    else out.push(result);
  });
  return out;
}

function translateMap(map, shape) {
  if (map == null) return undefined;

  var out = {};
  util.each(map, function(key, value) {
    var result = translate(value, shape.value);
    if (result === undefined) out[key] = null;
    else out[key] = result;
  });
  return out;
}

function translateScalar(value, shape) {
  return shape.toType(value);
}

/**
 * @api private
 */
module.exports = JsonParser;


/***/ },

/***/ 2520
(module) {

var warning = [
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
 */
function emitWarning() {
  if (typeof process === 'undefined')
    return;

  // Skip maintenance mode message in Lambda environments
  if (
    typeof process.env === 'object' &&
    typeof process.env.AWS_EXECUTION_ENV !== 'undefined' &&
    process.env.AWS_EXECUTION_ENV.indexOf('AWS_Lambda_') === 0
  ) {
    return;
  }

  if (
    typeof process.env === 'object' &&
    typeof process.env.AWS_SDK_JS_SUPPRESS_MAINTENANCE_MODE_MESSAGE !== 'undefined'
  ) {
    return;
  }

  if (typeof process.emitWarning === 'function') {
    process.emitWarning(warning, {
      type: 'NOTE'
    });
  }
}

setTimeout(function () {
  if (!module.exports.suppress) {
    emitWarning();
  }
}, 0);


/***/ },

/***/ 2366
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
__webpack_require__(5615);
var inherit = AWS.util.inherit;
var getMetadataServiceEndpoint = __webpack_require__(8613);
var URL = (__webpack_require__(7016).URL);

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
 */
AWS.MetadataService = inherit({
  /**
   * @return [String] the endpoint of the instance metadata service
   */
  endpoint: getMetadataServiceEndpoint(),

  /**
   * @!ignore
   */

  /**
   * Default HTTP options. By default, the metadata service is set to not
   * timeout on long requests. This means that on non-EC2 machines, this
   * request will never return. If you are calling this operation from an
   * environment that may not always run on EC2, set a `timeout` value so
   * the SDK will abort the request after a given number of milliseconds.
   */
  httpOptions: { timeout: 0 },

  /**
   * when enabled, metadata service will not fetch token
   */
  disableFetchToken: false,

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
   */
  constructor: function MetadataService(options) {
    if (options && options.host) {
      options.endpoint = 'http://' + options.host;
      delete options.host;
    }
    this.profile = options && options.profile || process.env.AWS_PROFILE || AWS.util.defaultProfile;
    this.ec2MetadataV1Disabled = !!(options && options.ec2MetadataV1Disabled);
    this.filename = options && options.filename;
    AWS.util.update(this, options);
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
   */
  request: function request(path, options, callback) {
    if (arguments.length === 2) {
      callback = options;
      options = {};
    }

    if (process.env[AWS.util.imdsDisabledEnv]) {
      callback(new Error('EC2 Instance Metadata Service access disabled'));
      return;
    }

    path = path || '/';

    // Verify that host is a valid URL
    if (URL) { new URL(this.endpoint); }

    var httpRequest = new AWS.HttpRequest(this.endpoint + path);
    httpRequest.method = options.method || 'GET';
    if (options.headers) {
      httpRequest.headers = options.headers;
    }
    AWS.util.handleRequestWithRetries(httpRequest, this, callback);
  },

  /**
  * @api private
  */
  loadCredentialsCallbacks: [],

  /**
   * Fetches metadata token used for authenticating against the instance metadata service.
   *
   * @callback callback function(err, token)
   *   Called when token is loaded from the resource
   */
  fetchMetadataToken: function fetchMetadataToken(callback) {
    var self = this;
    var tokenFetchPath = '/latest/api/token';
    self.request(
      tokenFetchPath,
      {
        'method': 'PUT',
        'headers': {
          'x-aws-ec2-metadata-token-ttl-seconds': '21600'
        }
      },
      callback
    );
  },

  /**
   * Fetches credentials
   *
   * @api private
   * @callback cb function(err, creds)
   *   Called when credentials are loaded from the resource
   */
  fetchCredentials: function fetchCredentials(options, cb) {
    var self = this;
    var basePath = '/latest/meta-data/iam/security-credentials/';

    var isImdsV1Fallback = self.disableFetchToken
      || !(options && options.headers && options.headers['x-aws-ec2-metadata-token']);

    if (isImdsV1Fallback && !(process.env.AWS_EC2_METADATA_DISABLED)) {
      try {
        var profiles = AWS.util.getProfilesFromSharedConfig(AWS.util.iniLoader, this.filename);
        var profileSettings = profiles[this.profile] || {};
      } catch (e) {
        profileSettings = {};
      }

      if (profileSettings.ec2_metadata_v1_disabled && profileSettings.ec2_metadata_v1_disabled !== 'false') {
        return cb(AWS.util.error(
          new Error('AWS EC2 Metadata v1 fallback has been blocked by AWS config file profile.')
        ));
      }

      if (self.ec2MetadataV1Disabled) {
        return cb(AWS.util.error(
          new Error('AWS EC2 Metadata v1 fallback has been blocked by AWS.MetadataService::options.ec2MetadataV1Disabled=true.')
        ));
      }

      if (process.env.AWS_EC2_METADATA_V1_DISABLED && process.env.AWS_EC2_METADATA_V1_DISABLED !== 'false') {
        return cb(AWS.util.error(
          new Error('AWS EC2 Metadata v1 fallback has been blocked by process.env.AWS_EC2_METADATA_V1_DISABLED.')
        ));
      }
    }

    self.request(basePath, options, function (err, roleName) {
      if (err) {
        self.disableFetchToken = !(err.statusCode === 401);
        cb(AWS.util.error(
          err,
          {
            message: 'EC2 Metadata roleName request returned error'
          }
        ));
        return;
      }
      roleName = roleName.split('\n')[0]; // grab first (and only) role
      self.request(basePath + roleName, options, function (credErr, credData) {
        if (credErr) {
          self.disableFetchToken = !(credErr.statusCode === 401);
          cb(AWS.util.error(
            credErr,
            {
              message: 'EC2 Metadata creds request returned error'
            }
          ));
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
   */
  loadCredentials: function loadCredentials(callback) {
    var self = this;
    self.loadCredentialsCallbacks.push(callback);
    if (self.loadCredentialsCallbacks.length > 1) { return; }

    function callbacks(err, creds) {
      var cb;
      while ((cb = self.loadCredentialsCallbacks.shift()) !== undefined) {
        cb(err, creds);
      }
    }

    if (self.disableFetchToken) {
      self.fetchCredentials({}, callbacks);
    } else {
      self.fetchMetadataToken(function(tokenError, token) {
        if (tokenError) {
          if (tokenError.code === 'TimeoutError') {
            self.disableFetchToken = true;
          } else if (tokenError.retryable === true) {
            callbacks(AWS.util.error(
              tokenError,
              {
                message: 'EC2 Metadata token request returned error'
              }
            ));
            return;
          } else if (tokenError.statusCode === 400) {
            callbacks(AWS.util.error(
              tokenError,
              {
                message: 'EC2 Metadata token request returned 400'
              }
            ));
            return;
          }
        }
        var options = {};
        if (token) {
          options.headers = {
            'x-aws-ec2-metadata-token': token
          };
        }
        self.fetchCredentials(options, callbacks);
      });

    }
  }
});

/**
 * @api private
 */
module.exports = AWS.MetadataService;


/***/ },

/***/ 4237
(module) {

var getEndpoint = function() {
  return {
    IPv4: 'http://169.254.169.254',
    IPv6: 'http://[fd00:ec2::254]',
  };
};

module.exports = getEndpoint;


/***/ },

/***/ 1615
(module) {

var ENV_ENDPOINT_NAME = 'AWS_EC2_METADATA_SERVICE_ENDPOINT';
var CONFIG_ENDPOINT_NAME = 'ec2_metadata_service_endpoint';

var getEndpointConfigOptions = function() {
  return {
    environmentVariableSelector: function(env) { return env[ENV_ENDPOINT_NAME]; },
    configFileSelector: function(profile) { return profile[CONFIG_ENDPOINT_NAME]; },
    default: undefined,
  };
};

module.exports = getEndpointConfigOptions;


/***/ },

/***/ 183
(module) {

var getEndpointMode = function() {
  return {
    IPv4: 'IPv4',
    IPv6: 'IPv6',
  };
};

module.exports = getEndpointMode;


/***/ },

/***/ 2857
(module, __unused_webpack_exports, __webpack_require__) {

var EndpointMode = __webpack_require__(183)();

var ENV_ENDPOINT_MODE_NAME = 'AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE';
var CONFIG_ENDPOINT_MODE_NAME = 'ec2_metadata_service_endpoint_mode';

var getEndpointModeConfigOptions = function() {
  return {
    environmentVariableSelector: function(env) { return env[ENV_ENDPOINT_MODE_NAME]; },
    configFileSelector: function(profile) { return profile[CONFIG_ENDPOINT_MODE_NAME]; },
    default: EndpointMode.IPv4,
  };
};

module.exports = getEndpointModeConfigOptions;


/***/ },

/***/ 8613
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

var Endpoint = __webpack_require__(4237)();
var EndpointMode = __webpack_require__(183)();

var ENDPOINT_CONFIG_OPTIONS = __webpack_require__(1615)();
var ENDPOINT_MODE_CONFIG_OPTIONS = __webpack_require__(2857)();

var getMetadataServiceEndpoint = function() {
  var endpoint = AWS.util.loadConfig(ENDPOINT_CONFIG_OPTIONS);
  if (endpoint !== undefined) return endpoint;

  var endpointMode = AWS.util.loadConfig(ENDPOINT_MODE_CONFIG_OPTIONS);
  switch (endpointMode) {
    case EndpointMode.IPv4:
      return Endpoint.IPv4;
    case EndpointMode.IPv6:
      return Endpoint.IPv6;
    default:
      throw new Error('Unsupported endpoint mode: ' + endpointMode);
  }
};

module.exports = getMetadataServiceEndpoint;


/***/ },

/***/ 9341
(module, __unused_webpack_exports, __webpack_require__) {

var Collection = __webpack_require__(6737);
var Operation = __webpack_require__(6176);
var Shape = __webpack_require__(1304);
var Paginator = __webpack_require__(8910);
var ResourceWaiter = __webpack_require__(3110);
var metadata = __webpack_require__(5087);

var util = __webpack_require__(9019);
var property = util.property;
var memoizedProperty = util.memoizedProperty;

function Api(api, options) {
  var self = this;
  api = api || {};
  options = options || {};
  options.api = this;

  api.metadata = api.metadata || {};

  var serviceIdentifier = options.serviceIdentifier;
  delete options.serviceIdentifier;

  property(this, 'isApi', true, false);
  property(this, 'apiVersion', api.metadata.apiVersion);
  property(this, 'endpointPrefix', api.metadata.endpointPrefix);
  property(this, 'signingName', api.metadata.signingName);
  property(this, 'globalEndpoint', api.metadata.globalEndpoint);
  property(this, 'signatureVersion', api.metadata.signatureVersion);
  property(this, 'jsonVersion', api.metadata.jsonVersion);
  property(this, 'targetPrefix', api.metadata.targetPrefix);
  property(this, 'protocol', api.metadata.protocol);
  property(this, 'timestampFormat', api.metadata.timestampFormat);
  property(this, 'xmlNamespaceUri', api.metadata.xmlNamespace);
  property(this, 'abbreviation', api.metadata.serviceAbbreviation);
  property(this, 'fullName', api.metadata.serviceFullName);
  property(this, 'serviceId', api.metadata.serviceId);
  if (serviceIdentifier && metadata[serviceIdentifier]) {
      property(this, 'xmlNoDefaultLists', metadata[serviceIdentifier].xmlNoDefaultLists, false);
  }

  memoizedProperty(this, 'className', function() {
    var name = api.metadata.serviceAbbreviation || api.metadata.serviceFullName;
    if (!name) return null;

    name = name.replace(/^Amazon|AWS\s*|\(.*|\s+|\W+/g, '');
    if (name === 'ElasticLoadBalancing') name = 'ELB';
    return name;
  });

  function addEndpointOperation(name, operation) {
    if (operation.endpointoperation === true) {
      property(self, 'endpointOperation', util.string.lowerFirst(name));
    }
    if (operation.endpointdiscovery && !self.hasRequiredEndpointDiscovery) {
      property(
        self,
        'hasRequiredEndpointDiscovery',
        operation.endpointdiscovery.required === true
      );
    }
  }

  property(this, 'operations', new Collection(api.operations, options, function(name, operation) {
    return new Operation(name, operation, options);
  }, util.string.lowerFirst, addEndpointOperation));

  property(this, 'shapes', new Collection(api.shapes, options, function(name, shape) {
    return Shape.create(shape, options);
  }));

  property(this, 'paginators', new Collection(api.paginators, options, function(name, paginator) {
    return new Paginator(name, paginator, options);
  }));

  property(this, 'waiters', new Collection(api.waiters, options, function(name, waiter) {
    return new ResourceWaiter(name, waiter, options);
  }, util.string.lowerFirst));

  if (options.documentation) {
    property(this, 'documentation', api.documentation);
    property(this, 'documentationUrl', api.documentationUrl);
  }
  property(this, 'awsQueryCompatible', api.metadata.awsQueryCompatible);
}

/**
 * @api private
 */
module.exports = Api;


/***/ },

/***/ 6737
(module, __unused_webpack_exports, __webpack_require__) {

var memoizedProperty = (__webpack_require__(9019).memoizedProperty);

function memoize(name, value, factory, nameTr) {
  memoizedProperty(this, nameTr(name), function() {
    return factory(name, value);
  });
}

function Collection(iterable, options, factory, nameTr, callback) {
  nameTr = nameTr || String;
  var self = this;

  for (var id in iterable) {
    if (Object.prototype.hasOwnProperty.call(iterable, id)) {
      memoize.call(self, id, iterable[id], factory, nameTr);
      if (callback) callback(id, iterable[id]);
    }
  }
}

/**
 * @api private
 */
module.exports = Collection;


/***/ },

/***/ 6176
(module, __unused_webpack_exports, __webpack_require__) {

var Shape = __webpack_require__(1304);

var util = __webpack_require__(9019);
var property = util.property;
var memoizedProperty = util.memoizedProperty;

function Operation(name, operation, options) {
  var self = this;
  options = options || {};

  property(this, 'name', operation.name || name);
  property(this, 'api', options.api, false);

  operation.http = operation.http || {};
  property(this, 'endpoint', operation.endpoint);
  property(this, 'httpMethod', operation.http.method || 'POST');
  property(this, 'httpPath', operation.http.requestUri || '/');
  property(this, 'authtype', operation.authtype || '');
  property(
    this,
    'endpointDiscoveryRequired',
    operation.endpointdiscovery ?
      (operation.endpointdiscovery.required ? 'REQUIRED' : 'OPTIONAL') :
    'NULL'
  );

  // httpChecksum replaces usage of httpChecksumRequired, but some APIs
  // (s3control) still uses old trait.
  var httpChecksumRequired = operation.httpChecksumRequired
    || (operation.httpChecksum && operation.httpChecksum.requestChecksumRequired);
  property(this, 'httpChecksumRequired', httpChecksumRequired, false);

  memoizedProperty(this, 'input', function() {
    if (!operation.input) {
      return new Shape.create({type: 'structure'}, options);
    }
    return Shape.create(operation.input, options);
  });

  memoizedProperty(this, 'output', function() {
    if (!operation.output) {
      return new Shape.create({type: 'structure'}, options);
    }
    return Shape.create(operation.output, options);
  });

  memoizedProperty(this, 'errors', function() {
    var list = [];
    if (!operation.errors) return null;

    for (var i = 0; i < operation.errors.length; i++) {
      list.push(Shape.create(operation.errors[i], options));
    }

    return list;
  });

  memoizedProperty(this, 'paginator', function() {
    return options.api.paginators[name];
  });

  if (options.documentation) {
    property(this, 'documentation', operation.documentation);
    property(this, 'documentationUrl', operation.documentationUrl);
  }

  // idempotentMembers only tracks top-level input shapes
  memoizedProperty(this, 'idempotentMembers', function() {
    var idempotentMembers = [];
    var input = self.input;
    var members = input.members;
    if (!input.members) {
      return idempotentMembers;
    }
    for (var name in members) {
      if (!members.hasOwnProperty(name)) {
        continue;
      }
      if (members[name].isIdempotent === true) {
        idempotentMembers.push(name);
      }
    }
    return idempotentMembers;
  });

  memoizedProperty(this, 'hasEventOutput', function() {
    var output = self.output;
    return hasEventStream(output);
  });
}

function hasEventStream(topLevelShape) {
  var members = topLevelShape.members;
  var payload = topLevelShape.payload;

  if (!topLevelShape.members) {
    return false;
  }

  if (payload) {
    var payloadMember = members[payload];
    return payloadMember.isEventStream;
  }

  // check if any member is an event stream
  for (var name in members) {
    if (!members.hasOwnProperty(name)) {
      if (members[name].isEventStream === true) {
        return true;
      }
    }
  }
  return false;
}

/**
 * @api private
 */
module.exports = Operation;


/***/ },

/***/ 8910
(module, __unused_webpack_exports, __webpack_require__) {

var property = (__webpack_require__(9019).property);

function Paginator(name, paginator) {
  property(this, 'inputToken', paginator.input_token);
  property(this, 'limitKey', paginator.limit_key);
  property(this, 'moreResults', paginator.more_results);
  property(this, 'outputToken', paginator.output_token);
  property(this, 'resultKey', paginator.result_key);
}

/**
 * @api private
 */
module.exports = Paginator;


/***/ },

/***/ 3110
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);
var property = util.property;

function ResourceWaiter(name, waiter, options) {
  options = options || {};
  property(this, 'name', name);
  property(this, 'api', options.api, false);

  if (waiter.operation) {
    property(this, 'operation', util.string.lowerFirst(waiter.operation));
  }

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
    if (value) {
      property(self, key, value);
    }
  });
}

/**
 * @api private
 */
module.exports = ResourceWaiter;


/***/ },

/***/ 1304
(module, __unused_webpack_exports, __webpack_require__) {

var Collection = __webpack_require__(6737);

var util = __webpack_require__(9019);

function property(obj, name, value) {
  if (value !== null && value !== undefined) {
    util.property.apply(this, arguments);
  }
}

function memoizedProperty(obj, name) {
  if (!obj.constructor.prototype[name]) {
    util.memoizedProperty.apply(this, arguments);
  }
}

function Shape(shape, options, memberName) {
  options = options || {};

  property(this, 'shape', shape.shape);
  property(this, 'api', options.api, false);
  property(this, 'type', shape.type);
  property(this, 'enum', shape.enum);
  property(this, 'min', shape.min);
  property(this, 'max', shape.max);
  property(this, 'pattern', shape.pattern);
  property(this, 'location', shape.location || this.location || 'body');
  property(this, 'name', this.name || shape.xmlName || shape.queryName ||
    shape.locationName || memberName);
  property(this, 'isStreaming', shape.streaming || this.isStreaming || false);
  property(this, 'requiresLength', shape.requiresLength, false);
  property(this, 'isComposite', shape.isComposite || false);
  property(this, 'isShape', true, false);
  property(this, 'isQueryName', Boolean(shape.queryName), false);
  property(this, 'isLocationName', Boolean(shape.locationName), false);
  property(this, 'isIdempotent', shape.idempotencyToken === true);
  property(this, 'isJsonValue', shape.jsonvalue === true);
  property(this, 'isSensitive', shape.sensitive === true || shape.prototype && shape.prototype.sensitive === true);
  property(this, 'isEventStream', Boolean(shape.eventstream), false);
  property(this, 'isEvent', Boolean(shape.event), false);
  property(this, 'isEventPayload', Boolean(shape.eventpayload), false);
  property(this, 'isEventHeader', Boolean(shape.eventheader), false);
  property(this, 'isTimestampFormatSet', Boolean(shape.timestampFormat) || shape.prototype && shape.prototype.isTimestampFormatSet === true, false);
  property(this, 'endpointDiscoveryId', Boolean(shape.endpointdiscoveryid), false);
  property(this, 'hostLabel', Boolean(shape.hostLabel), false);

  if (options.documentation) {
    property(this, 'documentation', shape.documentation);
    property(this, 'documentationUrl', shape.documentationUrl);
  }

  if (shape.xmlAttribute) {
    property(this, 'isXmlAttribute', shape.xmlAttribute || false);
  }

  // type conversion and parsing
  property(this, 'defaultValue', null);
  this.toWireFormat = function(value) {
    if (value === null || value === undefined) return '';
    return value;
  };
  this.toType = function(value) { return value; };
}

/**
 * @api private
 */
Shape.normalizedTypes = {
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
 */
Shape.types = {
  'structure': StructureShape,
  'list': ListShape,
  'map': MapShape,
  'boolean': BooleanShape,
  'timestamp': TimestampShape,
  'float': FloatShape,
  'integer': IntegerShape,
  'string': StringShape,
  'base64': Base64Shape,
  'binary': BinaryShape
};

Shape.resolve = function resolve(shape, options) {
  if (shape.shape) {
    var refShape = options.api.shapes[shape.shape];
    if (!refShape) {
      throw new Error('Cannot find shape reference: ' + shape.shape);
    }

    return refShape;
  } else {
    return null;
  }
};

Shape.create = function create(shape, options, memberName) {
  if (shape.isShape) return shape;

  var refShape = Shape.resolve(shape, options);
  if (refShape) {
    var filteredKeys = Object.keys(shape);
    if (!options.documentation) {
      filteredKeys = filteredKeys.filter(function(name) {
        return !name.match(/documentation/);
      });
    }

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
    if (Shape.normalizedTypes[shape.type]) {
      shape.type = Shape.normalizedTypes[shape.type];
    }

    if (Shape.types[shape.type]) {
      return new Shape.types[shape.type](shape, options, memberName);
    } else {
      throw new Error('Unrecognized shape type: ' + origType);
    }
  }
};

function CompositeShape(shape) {
  Shape.apply(this, arguments);
  property(this, 'isComposite', true);

  if (shape.flattened) {
    property(this, 'flattened', shape.flattened || false);
  }
}

function StructureShape(shape, options) {
  var self = this;
  var requiredMap = null, firstInit = !this.isShape;

  CompositeShape.apply(this, arguments);

  if (firstInit) {
    property(this, 'defaultValue', function() { return {}; });
    property(this, 'members', {});
    property(this, 'memberNames', []);
    property(this, 'required', []);
    property(this, 'isRequired', function() { return false; });
    property(this, 'isDocument', Boolean(shape.document));
  }

  if (shape.members) {
    property(this, 'members', new Collection(shape.members, options, function(name, member) {
      return Shape.create(member, options, name);
    }));
    memoizedProperty(this, 'memberNames', function() {
      return shape.xmlOrder || Object.keys(shape.members);
    });

    if (shape.event) {
      memoizedProperty(this, 'eventPayloadMemberName', function() {
        var members = self.members;
        var memberNames = self.memberNames;
        // iterate over members to find ones that are event payloads
        for (var i = 0, iLen = memberNames.length; i < iLen; i++) {
          if (members[memberNames[i]].isEventPayload) {
            return memberNames[i];
          }
        }
      });

      memoizedProperty(this, 'eventHeaderMemberNames', function() {
        var members = self.members;
        var memberNames = self.memberNames;
        var eventHeaderMemberNames = [];
        // iterate over members to find ones that are event headers
        for (var i = 0, iLen = memberNames.length; i < iLen; i++) {
          if (members[memberNames[i]].isEventHeader) {
            eventHeaderMemberNames.push(memberNames[i]);
          }
        }
        return eventHeaderMemberNames;
      });
    }
  }

  if (shape.required) {
    property(this, 'required', shape.required);
    property(this, 'isRequired', function(name) {
      if (!requiredMap) {
        requiredMap = {};
        for (var i = 0; i < shape.required.length; i++) {
          requiredMap[shape.required[i]] = true;
        }
      }

      return requiredMap[name];
    }, false, true);
  }

  property(this, 'resultWrapper', shape.resultWrapper || null);

  if (shape.payload) {
    property(this, 'payload', shape.payload);
  }

  if (typeof shape.xmlNamespace === 'string') {
    property(this, 'xmlNamespaceUri', shape.xmlNamespace);
  } else if (typeof shape.xmlNamespace === 'object') {
    property(this, 'xmlNamespacePrefix', shape.xmlNamespace.prefix);
    property(this, 'xmlNamespaceUri', shape.xmlNamespace.uri);
  }
}

function ListShape(shape, options) {
  var self = this, firstInit = !this.isShape;
  CompositeShape.apply(this, arguments);

  if (firstInit) {
    property(this, 'defaultValue', function() { return []; });
  }

  if (shape.member) {
    memoizedProperty(this, 'member', function() {
      return Shape.create(shape.member, options);
    });
  }

  if (this.flattened) {
    var oldName = this.name;
    memoizedProperty(this, 'name', function() {
      return self.member.name || oldName;
    });
  }
}

function MapShape(shape, options) {
  var firstInit = !this.isShape;
  CompositeShape.apply(this, arguments);

  if (firstInit) {
    property(this, 'defaultValue', function() { return {}; });
    property(this, 'key', Shape.create({type: 'string'}, options));
    property(this, 'value', Shape.create({type: 'string'}, options));
  }

  if (shape.key) {
    memoizedProperty(this, 'key', function() {
      return Shape.create(shape.key, options);
    });
  }
  if (shape.value) {
    memoizedProperty(this, 'value', function() {
      return Shape.create(shape.value, options);
    });
  }
}

function TimestampShape(shape) {
  var self = this;
  Shape.apply(this, arguments);

  if (shape.timestampFormat) {
    property(this, 'timestampFormat', shape.timestampFormat);
  } else if (self.isTimestampFormatSet && this.timestampFormat) {
    property(this, 'timestampFormat', this.timestampFormat);
  } else if (this.location === 'header') {
    property(this, 'timestampFormat', 'rfc822');
  } else if (this.location === 'querystring') {
    property(this, 'timestampFormat', 'iso8601');
  } else if (this.api) {
    switch (this.api.protocol) {
      case 'json':
      case 'rest-json':
        property(this, 'timestampFormat', 'unixTimestamp');
        break;
      case 'rest-xml':
      case 'query':
      case 'ec2':
        property(this, 'timestampFormat', 'iso8601');
        break;
    }
  }

  this.toType = function(value) {
    if (value === null || value === undefined) return null;
    if (typeof value.toUTCString === 'function') return value;
    return typeof value === 'string' || typeof value === 'number' ?
           util.date.parseTimestamp(value) : null;
  };

  this.toWireFormat = function(value) {
    return util.date.format(value, self.timestampFormat);
  };
}

function StringShape() {
  Shape.apply(this, arguments);

  var nullLessProtocols = ['rest-xml', 'query', 'ec2'];
  this.toType = function(value) {
    value = this.api && nullLessProtocols.indexOf(this.api.protocol) > -1 ?
      value || '' : value;
    if (this.isJsonValue) {
      return JSON.parse(value);
    }

    return value && typeof value.toString === 'function' ?
      value.toString() : value;
  };

  this.toWireFormat = function(value) {
    return this.isJsonValue ? JSON.stringify(value) : value;
  };
}

function FloatShape() {
  Shape.apply(this, arguments);

  this.toType = function(value) {
    if (value === null || value === undefined) return null;
    return parseFloat(value);
  };
  this.toWireFormat = this.toType;
}

function IntegerShape() {
  Shape.apply(this, arguments);

  this.toType = function(value) {
    if (value === null || value === undefined) return null;
    return parseInt(value, 10);
  };
  this.toWireFormat = this.toType;
}

function BinaryShape() {
  Shape.apply(this, arguments);
  this.toType = function(value) {
    var buf = util.base64.decode(value);
    if (this.isSensitive && util.isNode() && typeof util.Buffer.alloc === 'function') {
  /* Node.js can create a Buffer that is not isolated.
   * i.e. buf.byteLength !== buf.buffer.byteLength
   * This means that the sensitive data is accessible to anyone with access to buf.buffer.
   * If this is the node shared Buffer, then other code within this process _could_ find this secret.
   * Copy sensitive data to an isolated Buffer and zero the sensitive data.
   * While this is safe to do here, copying this code somewhere else may produce unexpected results.
   */
      var secureBuf = util.Buffer.alloc(buf.length, buf);
      buf.fill(0);
      buf = secureBuf;
    }
    return buf;
  };
  this.toWireFormat = util.base64.encode;
}

function Base64Shape() {
  BinaryShape.apply(this, arguments);
}

function BooleanShape() {
  Shape.apply(this, arguments);

  this.toType = function(value) {
    if (typeof value === 'boolean') return value;
    if (value === null || value === undefined) return null;
    return value === 'true';
  };
}

/**
 * @api private
 */
Shape.shapes = {
  StructureShape: StructureShape,
  ListShape: ListShape,
  MapShape: MapShape,
  StringShape: StringShape,
  BooleanShape: BooleanShape,
  Base64Shape: Base64Shape
};

/**
 * @api private
 */
module.exports = Shape;


/***/ },

/***/ 4129
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);

var region_utils = __webpack_require__(7357);
var isFipsRegion = region_utils.isFipsRegion;
var getRealRegion = region_utils.getRealRegion;

util.isBrowser = function() { return false; };
util.isNode = function() { return true; };

// node.js specific modules
util.crypto.lib = __webpack_require__(6982);
util.Buffer = (__webpack_require__(181).Buffer);
util.domain = __webpack_require__(3167);
util.stream = __webpack_require__(2203);
util.url = __webpack_require__(7016);
util.querystring = __webpack_require__(3480);
util.environment = 'nodejs';
util.createEventStream = util.stream.Readable ?
  (__webpack_require__(3422).createEventStream) : (__webpack_require__(8277).createEventStream);
util.realClock = __webpack_require__(2032);
util.clientSideMonitoring = {
  Publisher: (__webpack_require__(1840).Publisher),
  configProvider: __webpack_require__(9050),
};
util.iniLoader = (__webpack_require__(5742)/* .iniLoader */ .s);
util.getSystemErrorName = (__webpack_require__(9023).getSystemErrorName);

util.loadConfig = function(options) {
  var envValue = options.environmentVariableSelector(process.env);
  if (envValue !== undefined) {
    return envValue;
  }

  var configFile = {};
  try {
    configFile = util.iniLoader ? util.iniLoader.loadFrom({
      isConfig: true,
      filename: process.env[util.sharedConfigFileEnv]
    }) : {};
  } catch (e) {}
  var sharedFileConfig = configFile[
    process.env.AWS_PROFILE || util.defaultProfile
  ] || {};
  var configValue = options.configFileSelector(sharedFileConfig);
  if (configValue !== undefined) {
    return configValue;
  }

  if (typeof options.default === 'function') {
    return options.default();
  }
  return options.default;
};

var AWS;

/**
 * @api private
 */
module.exports = AWS = __webpack_require__(9132);

__webpack_require__(1833);
__webpack_require__(4279);
__webpack_require__(9756);
__webpack_require__(4230);
__webpack_require__(3184);
__webpack_require__(4855);
__webpack_require__(8236);
__webpack_require__(3466);

// Load the xml2js XML parser
AWS.XML.Parser = __webpack_require__(6627);

// Load Node HTTP client
__webpack_require__(9958);

__webpack_require__(858);

// Load custom credential providers
__webpack_require__(4939);
__webpack_require__(4963);
__webpack_require__(3163);
__webpack_require__(8794);
__webpack_require__(9510);
__webpack_require__(81);
__webpack_require__(9248);
__webpack_require__(3466);
__webpack_require__(7964);

// Setup default providers for credentials chain
// If this changes, please update documentation for
// AWS.CredentialProviderChain.defaultProviders in
// credentials/credential_provider_chain.js
AWS.CredentialProviderChain.defaultProviders = [
  function () { return new AWS.EnvironmentCredentials('AWS'); },
  function () { return new AWS.EnvironmentCredentials('AMAZON'); },
  function () { return new AWS.SsoCredentials(); },
  function () { return new AWS.SharedIniFileCredentials(); },
  function () { return new AWS.ECSCredentials(); },
  function () { return new AWS.ProcessCredentials(); },
  function () { return new AWS.TokenFileWebIdentityCredentials(); },
  function () { return new AWS.EC2MetadataCredentials(); }
];

// Load custom token providers
__webpack_require__(7486);
__webpack_require__(4796);
__webpack_require__(8614);

// Setup default providers for token chain
// If this changes, please update documentation for
// AWS.TokenProviderChain.defaultProviders in
// token/token_provider_chain.js
AWS.TokenProviderChain.defaultProviders = [
  function () { return new AWS.SSOTokenProvider(); },
];

var getRegion = function() {
  var env = process.env;
  var region = env.AWS_REGION || env.AMAZON_REGION;
  if (env[AWS.util.configOptInEnv]) {
    var toCheck = [
      {filename: env[AWS.util.sharedCredentialsFileEnv]},
      {isConfig: true, filename: env[AWS.util.sharedConfigFileEnv]}
    ];
    var iniLoader = AWS.util.iniLoader;
    while (!region && toCheck.length) {
      var configFile = {};
      var fileInfo = toCheck.shift();
      try {
        configFile = iniLoader.loadFrom(fileInfo);
      } catch (err) {
        if (fileInfo.isConfig) throw err;
      }
      var profile = configFile[env.AWS_PROFILE || AWS.util.defaultProfile];
      region = profile && profile.region;
    }
  }
  return region;
};

var getBooleanValue = function(value) {
  return value === 'true' ? true: value === 'false' ? false: undefined;
};

var USE_FIPS_ENDPOINT_CONFIG_OPTIONS = {
  environmentVariableSelector: function(env) {
    return getBooleanValue(env['AWS_USE_FIPS_ENDPOINT']);
  },
  configFileSelector: function(profile) {
    return getBooleanValue(profile['use_fips_endpoint']);
  },
  default: false,
};

var USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = {
  environmentVariableSelector: function(env) {
    return getBooleanValue(env['AWS_USE_DUALSTACK_ENDPOINT']);
  },
  configFileSelector: function(profile) {
    return getBooleanValue(profile['use_dualstack_endpoint']);
  },
  default: false,
};

// Update configuration keys
AWS.util.update(AWS.Config.prototype.keys, {
  credentials: function () {
    var credentials = null;
    new AWS.CredentialProviderChain([
      function () { return new AWS.EnvironmentCredentials('AWS'); },
      function () { return new AWS.EnvironmentCredentials('AMAZON'); },
      function () { return new AWS.SharedIniFileCredentials({ disableAssumeRole: true }); }
    ]).resolve(function(err, creds) {
      if (!err) credentials = creds;
    });
    return credentials;
  },
  credentialProvider: function() {
    return new AWS.CredentialProviderChain();
  },
  logger: function () {
    return process.env.AWSJS_DEBUG ? console : null;
  },
  region: function() {
    var region = getRegion();
    return region ? getRealRegion(region): undefined;
  },
  tokenProvider: function() {
    return new AWS.TokenProviderChain();
  },
  useFipsEndpoint: function() {
    var region = getRegion();
    return isFipsRegion(region)
      ? true
      : util.loadConfig(USE_FIPS_ENDPOINT_CONFIG_OPTIONS);
  },
  useDualstackEndpoint: function() {
    return util.loadConfig(USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS);
  }
});

// Reset configuration
AWS.config = new AWS.Config();


/***/ },

/***/ 1215
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

/**
 * @api private
 */
AWS.ParamValidator = AWS.util.inherit({
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
   */
  constructor: function ParamValidator(validation) {
    if (validation === true || validation === undefined) {
      validation = {'min': true};
    }
    this.validation = validation;
  },

  validate: function validate(shape, params, context) {
    this.errors = [];
    this.validateMember(shape, params || {}, context || 'params');

    if (this.errors.length > 1) {
      var msg = this.errors.join('\n* ');
      msg = 'There were ' + this.errors.length +
        ' validation errors:\n* ' + msg;
      throw AWS.util.error(new Error(msg),
        {code: 'MultipleValidationErrors', errors: this.errors});
    } else if (this.errors.length === 1) {
      throw this.errors[0];
    } else {
      return true;
    }
  },

  fail: function fail(code, message) {
    this.errors.push(AWS.util.error(new Error(message), {code: code}));
  },

  validateStructure: function validateStructure(shape, params, context) {
    if (shape.isDocument) return true;

    this.validateType(params, context, ['object'], 'structure');
    var paramName;
    for (var i = 0; shape.required && i < shape.required.length; i++) {
      paramName = shape.required[i];
      var value = params[paramName];
      if (value === undefined || value === null) {
        this.fail('MissingRequiredParameter',
          'Missing required key \'' + paramName + '\' in ' + context);
      }
    }

    // validate hash members
    for (paramName in params) {
      if (!Object.prototype.hasOwnProperty.call(params, paramName)) continue;

      var paramValue = params[paramName],
          memberShape = shape.members[paramName];

      if (memberShape !== undefined) {
        var memberContext = [context, paramName].join('.');
        this.validateMember(memberShape, paramValue, memberContext);
      } else if (paramValue !== undefined && paramValue !== null) {
        this.fail('UnexpectedParameter',
          'Unexpected key \'' + paramName + '\' found in ' + context);
      }
    }

    return true;
  },

  validateMember: function validateMember(shape, param, context) {
    switch (shape.type) {
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
    if (this.validateType(params, context, [Array])) {
      this.validateRange(shape, params.length, context, 'list member count');
      // validate array members
      for (var i = 0; i < params.length; i++) {
        this.validateMember(shape.member, params[i], context + '[' + i + ']');
      }
    }
  },

  validateMap: function validateMap(shape, params, context) {
    if (this.validateType(params, context, ['object'], 'map')) {
      // Build up a count of map members to validate range traits.
      var mapCount = 0;
      for (var param in params) {
        if (!Object.prototype.hasOwnProperty.call(params, param)) continue;
        // Validate any map key trait constraints
        this.validateMember(shape.key, param,
                            context + '[key=\'' + param + '\']');
        this.validateMember(shape.value, params[param],
                            context + '[\'' + param + '\']');
        mapCount++;
      }
      this.validateRange(shape, mapCount, context, 'map member count');
    }
  },

  validateScalar: function validateScalar(shape, value, context) {
    switch (shape.type) {
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
        return this.validateType(value, context, ['boolean']);
      case 'timestamp':
        return this.validateType(value, context, [Date,
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/, 'number'],
          'Date object, ISO-8601 string, or a UNIX timestamp');
      default:
        return this.fail('UnkownType', 'Unhandled type ' +
                         shape.type + ' for ' + context);
    }
  },

  validateString: function validateString(shape, value, context) {
    var validTypes = ['string'];
    if (shape.isJsonValue) {
      validTypes = validTypes.concat(['number', 'object', 'boolean']);
    }
    if (value !== null && this.validateType(value, context, validTypes)) {
      this.validateEnum(shape, value, context);
      this.validateRange(shape, value.length, context, 'string length');
      this.validatePattern(shape, value, context);
      this.validateUri(shape, value, context);
    }
  },

  validateUri: function validateUri(shape, value, context) {
    if (shape['location'] === 'uri') {
      if (value.length === 0) {
        this.fail('UriParameterError', 'Expected uri parameter to have length >= 1,'
          + ' but found "' + value +'" for ' + context);
      }
    }
  },

  validatePattern: function validatePattern(shape, value, context) {
    if (this.validation['pattern'] && shape['pattern'] !== undefined) {
      if (!(new RegExp(shape['pattern'])).test(value)) {
        this.fail('PatternMatchError', 'Provided value "' + value + '" '
          + 'does not match regex pattern /' + shape['pattern'] + '/ for '
          + context);
      }
    }
  },

  validateRange: function validateRange(shape, value, context, descriptor) {
    if (this.validation['min']) {
      if (shape['min'] !== undefined && value < shape['min']) {
        this.fail('MinRangeError', 'Expected ' + descriptor + ' >= '
          + shape['min'] + ', but found ' + value + ' for ' + context);
      }
    }
    if (this.validation['max']) {
      if (shape['max'] !== undefined && value > shape['max']) {
        this.fail('MaxRangeError', 'Expected ' + descriptor + ' <= '
          + shape['max'] + ', but found ' + value + ' for ' + context);
      }
    }
  },

  validateEnum: function validateRange(shape, value, context) {
    if (this.validation['enum'] && shape['enum'] !== undefined) {
      // Fail if the string value is not present in the enum list
      if (shape['enum'].indexOf(value) === -1) {
        this.fail('EnumError', 'Found string value of ' + value + ', but '
          + 'expected ' + shape['enum'].join('|') + ' for ' + context);
      }
    }
  },

  validateType: function validateType(value, context, acceptedTypes, type) {
    // We will not log an error for null or undefined, but we will return
    // false so that callers know that the expected type was not strictly met.
    if (value === null || value === undefined) return false;

    var foundInvalidType = false;
    for (var i = 0; i < acceptedTypes.length; i++) {
      if (typeof acceptedTypes[i] === 'string') {
        if (typeof value === acceptedTypes[i]) return true;
      } else if (acceptedTypes[i] instanceof RegExp) {
        if ((value || '').toString().match(acceptedTypes[i])) return true;
      } else {
        if (value instanceof acceptedTypes[i]) return true;
        if (AWS.util.isType(value, acceptedTypes[i])) return true;
        if (!type && !foundInvalidType) acceptedTypes = acceptedTypes.slice();
        acceptedTypes[i] = AWS.util.typeName(acceptedTypes[i]);
      }
      foundInvalidType = true;
    }

    var acceptedType = type;
    if (!acceptedType) {
      acceptedType = acceptedTypes.join(', ').replace(/,([^,]+)$/, ', or$1');
    }

    var vowel = acceptedType.match(/^[aeiou]/i) ? 'n' : '';
    this.fail('InvalidParameterType', 'Expected ' + context + ' to be a' +
              vowel + ' ' + acceptedType);
    return false;
  },

  validateNumber: function validateNumber(shape, value, context) {
    if (value === null || value === undefined) return;
    if (typeof value === 'string') {
      var castedValue = parseFloat(value);
      if (castedValue.toString() === value) value = castedValue;
    }
    if (this.validateType(value, context, ['number'])) {
      this.validateRange(shape, value, context, 'numeric value');
    }
  },

  validatePayload: function validatePayload(value, context) {
    if (value === null || value === undefined) return;
    if (typeof value === 'string') return;
    if (value && typeof value.byteLength === 'number') return; // typed arrays
    if (AWS.util.isNode()) { // special check for buffer/stream in Node.js
      var Stream = AWS.util.stream.Stream;
      if (AWS.util.Buffer.isBuffer(value) || value instanceof Stream) return;
    } else {
      if (typeof Blob !== void 0 && value instanceof Blob) return;
    }

    var types = ['Buffer', 'Stream', 'File', 'Blob', 'ArrayBuffer', 'DataView'];
    if (value) {
      for (var i = 0; i < types.length; i++) {
        if (AWS.util.isType(value, types[i])) return;
        if (AWS.util.typeName(value.constructor) === types[i]) return;
      }
    }

    this.fail('InvalidParameterType', 'Expected ' + context + ' to be a ' +
      'string, Buffer, Stream, Blob, or typed array object');
  }
});


/***/ },

/***/ 8201
(module, __unused_webpack_exports, __webpack_require__) {

var util =  __webpack_require__(9019);
var AWS = __webpack_require__(9132);

/**
 * Prepend prefix defined by API model to endpoint that's already
 * constructed. This feature does not apply to operations using
 * endpoint discovery and can be disabled.
 * @api private
 */
function populateHostPrefix(request)  {
  var enabled = request.service.config.hostPrefixEnabled;
  if (!enabled) return request;
  var operationModel = request.service.api.operations[request.operation];
  //don't marshal host prefix when operation has endpoint discovery traits
  if (hasEndpointDiscover(request)) return request;
  if (operationModel.endpoint && operationModel.endpoint.hostPrefix) {
    var hostPrefixNotation = operationModel.endpoint.hostPrefix;
    var hostPrefix = expandHostPrefix(hostPrefixNotation, request.params, operationModel.input);
    prependEndpointPrefix(request.httpRequest.endpoint, hostPrefix);
    validateHostname(request.httpRequest.endpoint.hostname);
  }
  return request;
}

/**
 * @api private
 */
function hasEndpointDiscover(request) {
  var api = request.service.api;
  var operationModel = api.operations[request.operation];
  var isEndpointOperation = api.endpointOperation && (api.endpointOperation === util.string.lowerFirst(operationModel.name));
  return (operationModel.endpointDiscoveryRequired !== 'NULL' || isEndpointOperation === true);
}

/**
 * @api private
 */
function expandHostPrefix(hostPrefixNotation, params, shape) {
  util.each(shape.members, function(name, member) {
    if (member.hostLabel === true) {
      if (typeof params[name] !== 'string' || params[name] === '') {
        throw util.error(new Error(), {
          message: 'Parameter ' + name + ' should be a non-empty string.',
          code: 'InvalidParameter'
        });
      }
      var regex = new RegExp('\\{' + name + '\\}', 'g');
      hostPrefixNotation = hostPrefixNotation.replace(regex, params[name]);
    }
  });
  return hostPrefixNotation;
}

/**
 * @api private
 */
function prependEndpointPrefix(endpoint, prefix) {
  if (endpoint.host) {
    endpoint.host = prefix + endpoint.host;
  }
  if (endpoint.hostname) {
    endpoint.hostname = prefix + endpoint.hostname;
  }
}

/**
 * @api private
 */
function validateHostname(hostname) {
  var labels = hostname.split('.');
  //Reference: https://tools.ietf.org/html/rfc1123#section-2
  var hostPattern = /^[a-zA-Z0-9]{1}$|^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$/;
  util.arrayEach(labels, function(label) {
    if (!label.length || label.length < 1 || label.length > 63) {
      throw util.error(new Error(), {
        code: 'ValidationError',
        message: 'Hostname label length should be between 1 to 63 characters, inclusive.'
      });
    }
    if (!hostPattern.test(label)) {
      throw AWS.util.error(new Error(),
        {code: 'ValidationError', message: label + ' is not hostname compatible.'});
    }
  });
}

module.exports = {
  populateHostPrefix: populateHostPrefix
};


/***/ },

/***/ 3652
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);
var JsonBuilder = __webpack_require__(3681);
var JsonParser = __webpack_require__(5919);
var populateHostPrefix = (__webpack_require__(8201).populateHostPrefix);

function buildRequest(req) {
  var httpRequest = req.httpRequest;
  var api = req.service.api;
  var target = api.targetPrefix + '.' + api.operations[req.operation].name;
  var version = api.jsonVersion || '1.0';
  var input = api.operations[req.operation].input;
  var builder = new JsonBuilder();

  if (version === 1) version = '1.0';

  if (api.awsQueryCompatible) {
    if (!httpRequest.params) {
      httpRequest.params = {};
    }
    // because Query protocol does this.
    Object.assign(httpRequest.params, req.params);
  }

  httpRequest.body = builder.build(req.params || {}, input);
  httpRequest.headers['Content-Type'] = 'application/x-amz-json-' + version;
  httpRequest.headers['X-Amz-Target'] = target;

  populateHostPrefix(req);
}

function extractError(resp) {
  var error = {};
  var httpResponse = resp.httpResponse;

  error.code = httpResponse.headers['x-amzn-errortype'] || 'UnknownError';
  if (typeof error.code === 'string') {
    error.code = error.code.split(':')[0];
  }

  if (httpResponse.body.length > 0) {
    try {
      var e = JSON.parse(httpResponse.body.toString());

      var code = e.__type || e.code || e.Code;
      if (code) {
        error.code = code.split('#').pop();
      }
      if (error.code === 'RequestEntityTooLarge') {
        error.message = 'Request body must be less than 1 MB';
      } else {
        error.message = (e.message || e.Message || null);
      }

      // The minimized models do not have error shapes, so
      // without expanding the model size, it's not possible
      // to validate the response shape (members) or
      // check if any are sensitive to logging.

      // Assign the fields as non-enumerable, allowing specific access only.
      for (var key in e || {}) {
        if (key === 'code' || key === 'message') {
          continue;
        }
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
  } else {
    error.statusCode = httpResponse.statusCode;
    error.message = httpResponse.statusCode.toString();
  }

  resp.error = util.error(new Error(), error);
}

function extractData(resp) {
  var body = resp.httpResponse.body.toString() || '{}';
  if (resp.request.service.config.convertResponseTypes === false) {
    resp.data = JSON.parse(body);
  } else {
    var operation = resp.request.service.api.operations[resp.request.operation];
    var shape = operation.output || {};
    var parser = new JsonParser();
    resp.data = parser.parse(body, shape);
  }
}

/**
 * @api private
 */
module.exports = {
  buildRequest: buildRequest,
  extractError: extractError,
  extractData: extractData
};


/***/ },

/***/ 324
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var util = __webpack_require__(9019);
var QueryParamSerializer = __webpack_require__(329);
var Shape = __webpack_require__(1304);
var populateHostPrefix = (__webpack_require__(8201).populateHostPrefix);

function buildRequest(req) {
  var operation = req.service.api.operations[req.operation];
  var httpRequest = req.httpRequest;
  httpRequest.headers['Content-Type'] =
    'application/x-www-form-urlencoded; charset=utf-8';
  httpRequest.params = {
    Version: req.service.api.apiVersion,
    Action: operation.name
  };

  // convert the request parameters into a list of query params,
  // e.g. Deeply.NestedParam.0.Name=value
  var builder = new QueryParamSerializer();
  builder.serialize(req.params, operation.input, function(name, value) {
    httpRequest.params[name] = value;
  });
  httpRequest.body = util.queryParamsToString(httpRequest.params);

  populateHostPrefix(req);
}

function extractError(resp) {
  var data, body = resp.httpResponse.body.toString();
  if (body.match('<UnknownOperationException')) {
    data = {
      Code: 'UnknownOperation',
      Message: 'Unknown operation ' + resp.request.operation
    };
  } else {
    try {
      data = new AWS.XML.Parser().parse(body);
    } catch (e) {
      data = {
        Code: resp.httpResponse.statusCode,
        Message: resp.httpResponse.statusMessage
      };
    }
  }

  if (data.requestId && !resp.requestId) resp.requestId = data.requestId;
  if (data.Errors) data = data.Errors;
  if (data.Error) data = data.Error;
  if (data.Code) {
    resp.error = util.error(new Error(), {
      code: data.Code,
      message: data.Message
    });
  } else {
    resp.error = util.error(new Error(), {
      code: resp.httpResponse.statusCode,
      message: null
    });
  }
}

function extractData(resp) {
  var req = resp.request;
  var operation = req.service.api.operations[req.operation];
  var shape = operation.output || {};
  var origRules = shape;

  if (origRules.resultWrapper) {
    var tmp = Shape.create({type: 'structure'});
    tmp.members[origRules.resultWrapper] = shape;
    tmp.memberNames = [origRules.resultWrapper];
    util.property(shape, 'name', shape.resultWrapper);
    shape = tmp;
  }

  var parser = new AWS.XML.Parser();

  // TODO: Refactor XML Parser to parse RequestId from response.
  if (shape && shape.members && !shape.members._XAMZRequestId) {
    var requestIdShape = Shape.create(
      { type: 'string' },
      { api: { protocol: 'query' } },
      'requestId'
    );
    shape.members._XAMZRequestId = requestIdShape;
  }

  var data = parser.parse(resp.httpResponse.body.toString(), shape);
  resp.requestId = data._XAMZRequestId || data.requestId;

  if (data._XAMZRequestId) delete data._XAMZRequestId;

  if (origRules.resultWrapper) {
    if (data[origRules.resultWrapper]) {
      util.update(data, data[origRules.resultWrapper]);
      delete data[origRules.resultWrapper];
    }
  }

  resp.data = data;
}

/**
 * @api private
 */
module.exports = {
  buildRequest: buildRequest,
  extractError: extractError,
  extractData: extractData
};


/***/ },

/***/ 9648
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);
var populateHostPrefix = (__webpack_require__(8201).populateHostPrefix);

function populateMethod(req) {
  req.httpRequest.method = req.service.api.operations[req.operation].httpMethod;
}

function generateURI(endpointPath, operationPath, input, params) {
  var uri = [endpointPath, operationPath].join('/');
  uri = uri.replace(/\/+/g, '/');

  var queryString = {}, queryStringSet = false;
  util.each(input.members, function (name, member) {
    var paramValue = params[name];
    if (paramValue === null || paramValue === undefined) return;
    if (member.location === 'uri') {
      var regex = new RegExp('\\{' + member.name + '(\\+)?\\}');
      uri = uri.replace(regex, function(_, plus) {
        var fn = plus ? util.uriEscapePath : util.uriEscape;
        return fn(String(paramValue));
      });
    } else if (member.location === 'querystring') {
      queryStringSet = true;

      if (member.type === 'list') {
        queryString[member.name] = paramValue.map(function(val) {
          return util.uriEscape(member.member.toWireFormat(val).toString());
        });
      } else if (member.type === 'map') {
        util.each(paramValue, function(key, value) {
          if (Array.isArray(value)) {
            queryString[key] = value.map(function(val) {
              return util.uriEscape(String(val));
            });
          } else {
            queryString[key] = util.uriEscape(String(value));
          }
        });
      } else {
        queryString[member.name] = util.uriEscape(member.toWireFormat(paramValue).toString());
      }
    }
  });

  if (queryStringSet) {
    uri += (uri.indexOf('?') >= 0 ? '&' : '?');
    var parts = [];
    util.arrayEach(Object.keys(queryString).sort(), function(key) {
      if (!Array.isArray(queryString[key])) {
        queryString[key] = [queryString[key]];
      }
      for (var i = 0; i < queryString[key].length; i++) {
        parts.push(util.uriEscape(String(key)) + '=' + queryString[key][i]);
      }
    });
    uri += parts.join('&');
  }

  return uri;
}

function populateURI(req) {
  var operation = req.service.api.operations[req.operation];
  var input = operation.input;

  var uri = generateURI(req.httpRequest.endpoint.path, operation.httpPath, input, req.params);
  req.httpRequest.path = uri;
}

function populateHeaders(req) {
  var operation = req.service.api.operations[req.operation];
  util.each(operation.input.members, function (name, member) {
    var value = req.params[name];
    if (value === null || value === undefined) return;

    if (member.location === 'headers' && member.type === 'map') {
      util.each(value, function(key, memberValue) {
        req.httpRequest.headers[member.name + key] = memberValue;
      });
    } else if (member.location === 'header') {
      value = member.toWireFormat(value).toString();
      if (member.isJsonValue) {
        value = util.base64.encode(value);
      }
      req.httpRequest.headers[member.name] = value;
    }
  });
}

function buildRequest(req) {
  populateMethod(req);
  populateURI(req);
  populateHeaders(req);
  populateHostPrefix(req);
}

function extractError() {
}

function extractData(resp) {
  var req = resp.request;
  var data = {};
  var r = resp.httpResponse;
  var operation = req.service.api.operations[req.operation];
  var output = operation.output;

  // normalize headers names to lower-cased keys for matching
  var headers = {};
  util.each(r.headers, function (k, v) {
    headers[k.toLowerCase()] = v;
  });

  util.each(output.members, function(name, member) {
    var header = (member.name || name).toLowerCase();
    if (member.location === 'headers' && member.type === 'map') {
      data[name] = {};
      var location = member.isLocationName ? member.name : '';
      var pattern = new RegExp('^' + location + '(.+)', 'i');
      util.each(r.headers, function (k, v) {
        var result = k.match(pattern);
        if (result !== null) {
          data[name][result[1]] = v;
        }
      });
    } else if (member.location === 'header') {
      if (headers[header] !== undefined) {
        var value = member.isJsonValue ?
          util.base64.decode(headers[header]) :
          headers[header];
        data[name] = member.toType(value);
      }
    } else if (member.location === 'statusCode') {
      data[name] = parseInt(r.statusCode, 10);
    }
  });

  resp.data = data;
}

/**
 * @api private
 */
module.exports = {
  buildRequest: buildRequest,
  extractError: extractError,
  extractData: extractData,
  generateURI: generateURI
};


/***/ },

/***/ 5897
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var util = __webpack_require__(9019);
var Rest = __webpack_require__(9648);
var Json = __webpack_require__(3652);
var JsonBuilder = __webpack_require__(3681);
var JsonParser = __webpack_require__(5919);

var METHODS_WITHOUT_BODY = ['GET', 'HEAD', 'DELETE'];

function unsetContentLength(req) {
  var payloadMember = util.getRequestPayloadShape(req);
  if (
    payloadMember === undefined &&
    METHODS_WITHOUT_BODY.indexOf(req.httpRequest.method) >= 0
  ) {
    delete req.httpRequest.headers['Content-Length'];
  }
}

function populateBody(req) {
  var builder = new JsonBuilder();
  var input = req.service.api.operations[req.operation].input;

  if (input.payload) {
    var params = {};
    var payloadShape = input.members[input.payload];
    params = req.params[input.payload];

    if (payloadShape.type === 'structure') {
      req.httpRequest.body = builder.build(params || {}, payloadShape);
      applyContentTypeHeader(req);
    } else if (params !== undefined) {
      // non-JSON payload
      req.httpRequest.body = params;
      if (payloadShape.type === 'binary' || payloadShape.isStreaming) {
        applyContentTypeHeader(req, true);
      }
    }
  } else {
    req.httpRequest.body = builder.build(req.params, input);
    applyContentTypeHeader(req);
  }
}

function applyContentTypeHeader(req, isBinary) {
  if (!req.httpRequest.headers['Content-Type']) {
    var type = isBinary ? 'binary/octet-stream' : 'application/json';
    req.httpRequest.headers['Content-Type'] = type;
  }
}

function buildRequest(req) {
  Rest.buildRequest(req);

  // never send body payload on GET/HEAD/DELETE
  if (METHODS_WITHOUT_BODY.indexOf(req.httpRequest.method) < 0) {
    populateBody(req);
  }
}

function extractError(resp) {
  Json.extractError(resp);
}

function extractData(resp) {
  Rest.extractData(resp);

  var req = resp.request;
  var operation = req.service.api.operations[req.operation];
  var rules = req.service.api.operations[req.operation].output || {};
  var parser;
  var hasEventOutput = operation.hasEventOutput;

  if (rules.payload) {
    var payloadMember = rules.members[rules.payload];
    var body = resp.httpResponse.body;
    if (payloadMember.isEventStream) {
      parser = new JsonParser();
      resp.data[rules.payload] = util.createEventStream(
        AWS.HttpClient.streamsApiVersion === 2 ? resp.httpResponse.stream : body,
        parser,
        payloadMember
      );
    } else if (payloadMember.type === 'structure' || payloadMember.type === 'list') {
      var parser = new JsonParser();
      resp.data[rules.payload] = parser.parse(body, payloadMember);
    } else if (payloadMember.type === 'binary' || payloadMember.isStreaming) {
      resp.data[rules.payload] = body;
    } else {
      resp.data[rules.payload] = payloadMember.toType(body);
    }
  } else {
    var data = resp.data;
    Json.extractData(resp);
    resp.data = util.merge(data, resp.data);
  }
}

/**
 * @api private
 */
module.exports = {
  buildRequest: buildRequest,
  extractError: extractError,
  extractData: extractData,
  unsetContentLength: unsetContentLength
};


/***/ },

/***/ 5830
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var util = __webpack_require__(9019);
var Rest = __webpack_require__(9648);

function populateBody(req) {
  var input = req.service.api.operations[req.operation].input;
  var builder = new AWS.XML.Builder();
  var params = req.params;

  var payload = input.payload;
  if (payload) {
    var payloadMember = input.members[payload];
    params = params[payload];
    if (params === undefined) return;

    if (payloadMember.type === 'structure') {
      var rootElement = payloadMember.name;
      req.httpRequest.body = builder.toXML(params, payloadMember, rootElement, true);
    } else { // non-xml payload
      req.httpRequest.body = params;
    }
  } else {
    req.httpRequest.body = builder.toXML(params, input, input.name ||
      input.shape || util.string.upperFirst(req.operation) + 'Request');
  }
}

function buildRequest(req) {
  Rest.buildRequest(req);

  // never send body payload on GET/HEAD
  if (['GET', 'HEAD'].indexOf(req.httpRequest.method) < 0) {
    populateBody(req);
  }
}

function extractError(resp) {
  Rest.extractError(resp);

  var data;
  try {
    data = new AWS.XML.Parser().parse(resp.httpResponse.body.toString());
  } catch (e) {
    data = {
      Code: resp.httpResponse.statusCode,
      Message: resp.httpResponse.statusMessage
    };
  }

  if (data.Errors) data = data.Errors;
  if (data.Error) data = data.Error;
  if (data.Code) {
    resp.error = util.error(new Error(), {
      code: data.Code,
      message: data.Message
    });
  } else {
    resp.error = util.error(new Error(), {
      code: resp.httpResponse.statusCode,
      message: null
    });
  }
}

function extractData(resp) {
  Rest.extractData(resp);

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
      parser = new AWS.XML.Parser();
      resp.data[payload] = util.createEventStream(
        AWS.HttpClient.streamsApiVersion === 2 ? resp.httpResponse.stream : resp.httpResponse.body,
        parser,
        payloadMember
      );
    } else if (payloadMember.type === 'structure') {
      parser = new AWS.XML.Parser();
      resp.data[payload] = parser.parse(body.toString(), payloadMember);
    } else if (payloadMember.type === 'binary' || payloadMember.isStreaming) {
      resp.data[payload] = body;
    } else {
      resp.data[payload] = payloadMember.toType(body);
    }
  } else if (body.length > 0) {
    parser = new AWS.XML.Parser();
    var data = parser.parse(body.toString(), output);
    util.update(resp.data, data);
  }
}

/**
 * @api private
 */
module.exports = {
  buildRequest: buildRequest,
  extractError: extractError,
  extractData: extractData
};


/***/ },

/***/ 9050
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

/**
 * Resolve client-side monitoring configuration from either environmental variables
 * or shared config file. Configurations from environmental variables have higher priority
 * than those from shared config file. The resolver will try to read the shared config file
 * no matter whether the AWS_SDK_LOAD_CONFIG variable is set.
 * @api private
 */
function resolveMonitoringConfig() {
  var config = {
    port: undefined,
    clientId: undefined,
    enabled: undefined,
    host: undefined
  };
  if (fromEnvironment(config) || fromConfigFile(config)) return toJSType(config);
  return toJSType(config);
}

/**
 * Resolve configurations from environmental variables.
 * @param {object} client side monitoring config object needs to be resolved
 * @returns {boolean} whether resolving configurations is done
 * @api private
 */
function fromEnvironment(config) {
  config.port = config.port || process.env.AWS_CSM_PORT;
  config.enabled = config.enabled || process.env.AWS_CSM_ENABLED;
  config.clientId = config.clientId || process.env.AWS_CSM_CLIENT_ID;
  config.host = config.host || process.env.AWS_CSM_HOST;
  return config.port && config.enabled && config.clientId && config.host ||
    ['false', '0'].indexOf(config.enabled) >= 0; //no need to read shared config file if explicitely disabled
}

/**
 * Resolve cofigurations from shared config file with specified role name
 * @param {object} client side monitoring config object needs to be resolved
 * @returns {boolean} whether resolving configurations is done
 * @api private
 */
function fromConfigFile(config) {
  var sharedFileConfig;
  try {
    var configFile = AWS.util.iniLoader.loadFrom({
      isConfig: true,
      filename: process.env[AWS.util.sharedConfigFileEnv]
    });
    var sharedFileConfig = configFile[
      process.env.AWS_PROFILE || AWS.util.defaultProfile
    ];
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
 */
function toJSType(config) {
    //config.XXX is either undefined or string
  var falsyNotations = ['false', '0', undefined];
  if (!config.enabled || falsyNotations.indexOf(config.enabled.toLowerCase()) >= 0) {
    config.enabled = false;
  } else {
    config.enabled = true;
  }
  config.port = config.port ? parseInt(config.port, 10) : undefined;
  return config;
}

module.exports = resolveMonitoringConfig;


/***/ },

/***/ 1840
(module, __unused_webpack_exports, __webpack_require__) {

var util = (__webpack_require__(9132).util);
var dgram = __webpack_require__(7194);
var stringToBuffer = util.buffer.toBuffer;

var MAX_MESSAGE_SIZE = 1024 * 8; // 8 KB

/**
 * Publishes metrics via udp.
 * @param {object} options Paramters for Publisher constructor
 * @param {number} [options.port = 31000] Port number
 * @param {string} [options.clientId = ''] Client Identifier
 * @param {boolean} [options.enabled = false] enable sending metrics datagram
 * @api private
 */
function Publisher(options) {
    // handle configuration
    options = options || {};
    this.enabled = options.enabled || false;
    this.port = options.port || 31000;
    this.clientId = options.clientId || '';
    this.address = options.host || '127.0.0.1';
    if (this.clientId.length > 255) {
        // ClientId has a max length of 255
        this.clientId = this.clientId.substr(0, 255);
    }
    this.messagesInFlight = 0;
}

Publisher.prototype.fieldsToTrim = {
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
 */
Publisher.prototype.trimFields = function(event) {
    var trimmableFields = Object.keys(this.fieldsToTrim);
    for (var i = 0, iLen = trimmableFields.length; i < iLen; i++) {
        var field = trimmableFields[i];
        if (event.hasOwnProperty(field)) {
            var maxLength = this.fieldsToTrim[field];
            var value = event[field];
            if (value && value.length > maxLength) {
                event[field] = value.substr(0, maxLength);
            }
        }
    }
    return event;
};

/**
 * Handles ApiCall and ApiCallAttempt events.
 * @param {Object} event apiCall or apiCallAttempt event.
 * @api private
 */
Publisher.prototype.eventHandler = function(event) {
    // set the clientId
    event.ClientId = this.clientId;

    this.trimFields(event);

    var message = stringToBuffer(JSON.stringify(event));
    if (!this.enabled || message.length > MAX_MESSAGE_SIZE) {
        // drop the message if publisher not enabled or it is too large
        return;
    }

    this.publishDatagram(message);
};

/**
 * Publishes message to an agent.
 * @param {Buffer} message JSON message to send to agent.
 * @api private
 */
Publisher.prototype.publishDatagram = function(message) {
    var self = this;
    var client = this.getClient();

    this.messagesInFlight++;
    this.client.send(message, 0, message.length, this.port, this.address, function(err, bytes) {
        if (--self.messagesInFlight <= 0) {
            // destroy existing client so the event loop isn't kept open
            self.destroyClient();
        }
    });
};

/**
 * Returns an existing udp socket, or creates one if it doesn't already exist.
 * @api private
 */
Publisher.prototype.getClient = function() {
    if (!this.client) {
        this.client = dgram.createSocket('udp4');
    }
    return this.client;
};

/**
 * Destroys the udp socket.
 * @api private
 */
Publisher.prototype.destroyClient = function() {
    if (this.client) {
        this.client.close();
        this.client = void 0;
    }
};

module.exports = {
    Publisher: Publisher
};


/***/ },

/***/ 329
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);

function QueryParamSerializer() {
}

QueryParamSerializer.prototype.serialize = function(params, shape, fn) {
  serializeStructure('', params, shape, fn);
};

function ucfirst(shape) {
  if (shape.isQueryName || shape.api.protocol !== 'ec2') {
    return shape.name;
  } else {
    return shape.name[0].toUpperCase() + shape.name.substr(1);
  }
}

function serializeStructure(prefix, struct, rules, fn) {
  util.each(rules.members, function(name, member) {
    var value = struct[name];
    if (value === null || value === undefined) return;

    var memberName = ucfirst(member);
    memberName = prefix ? prefix + '.' + memberName : memberName;
    serializeMember(memberName, value, member, fn);
  });
}

function serializeMap(name, map, rules, fn) {
  var i = 1;
  util.each(map, function (key, value) {
    var prefix = rules.flattened ? '.' : '.entry.';
    var position = prefix + (i++) + '.';
    var keyName = position + (rules.key.name || 'key');
    var valueName = position + (rules.value.name || 'value');
    serializeMember(name + keyName, key, rules.key, fn);
    serializeMember(name + valueName, value, rules.value, fn);
  });
}

function serializeList(name, list, rules, fn) {
  var memberRules = rules.member || {};

  if (list.length === 0) {
    if (rules.api.protocol !== 'ec2') {
      fn.call(this, name, null);
    }
    return;
  }

  util.arrayEach(list, function (v, n) {
    var suffix = '.' + (n + 1);
    if (rules.api.protocol === 'ec2') {
      // Do nothing for EC2
      suffix = suffix + ''; // make linter happy
    } else if (rules.flattened) {
      if (memberRules.name) {
        var parts = name.split('.');
        parts.pop();
        parts.push(ucfirst(memberRules));
        name = parts.join('.');
      }
    } else {
      suffix = '.' + (memberRules.name ? memberRules.name : 'member') + suffix;
    }
    serializeMember(name + suffix, v, memberRules, fn);
  });
}

function serializeMember(name, value, rules, fn) {
  if (value === null || value === undefined) return;
  if (rules.type === 'structure') {
    serializeStructure(name, value, rules, fn);
  } else if (rules.type === 'list') {
    serializeList(name, value, rules, fn);
  } else if (rules.type === 'map') {
    serializeMap(name, value, rules, fn);
  } else {
    fn(name, rules.toWireFormat(value).toString());
  }
}

/**
 * @api private
 */
module.exports = QueryParamSerializer;


/***/ },

/***/ 2032
(module) {

module.exports = {
  //provide realtime clock for performance measurement
  now: function now() {
    var second = process.hrtime();
    return second[0] * 1000 + (second[1] / 1000000);
  }
};


/***/ },

/***/ 7357
(module) {

function isFipsRegion(region) {
  return typeof region === 'string' && (region.startsWith('fips-') || region.endsWith('-fips'));
}

function isGlobalRegion(region) {
  return typeof region === 'string' && ['aws-global', 'aws-us-gov-global'].includes(region);
}

function getRealRegion(region) {
  return ['fips-aws-global', 'aws-fips', 'aws-global'].includes(region)
      ? 'us-east-1'
      : ['fips-aws-us-gov-global', 'aws-us-gov-global'].includes(region)
      ? 'us-gov-west-1'
      : region.replace(/fips-(dkr-|prod-)?|-fips/, '');
}

module.exports = {
  isFipsRegion: isFipsRegion,
  isGlobalRegion: isGlobalRegion,
  getRealRegion: getRealRegion
};


/***/ },

/***/ 9240
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);
var regionConfig = __webpack_require__(3548);

function generateRegionPrefix(region) {
  if (!region) return null;
  var parts = region.split('-');
  if (parts.length < 3) return null;
  return parts.slice(0, parts.length - 2).join('-') + '-*';
}

function derivedKeys(service) {
  var region = service.config.region;
  var regionPrefix = generateRegionPrefix(region);
  var endpointPrefix = service.api.endpointPrefix;

  return [
    [region, endpointPrefix],
    [regionPrefix, endpointPrefix],
    [region, '*'],
    [regionPrefix, '*'],
    ['*', endpointPrefix],
    [region, 'internal-*'],
    ['*', '*']
  ].map(function(item) {
    return item[0] && item[1] ? item.join('/') : null;
  });
}

function applyConfig(service, config) {
  util.each(config, function(key, value) {
    if (key === 'globalEndpoint') return;
    if (service.config[key] === undefined || service.config[key] === null) {
      service.config[key] = value;
    }
  });
}

function configureEndpoint(service) {
  var keys = derivedKeys(service);
  var useFipsEndpoint = service.config.useFipsEndpoint;
  var useDualstackEndpoint = service.config.useDualstackEndpoint;
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (!key) continue;

    var rules = useFipsEndpoint
      ? useDualstackEndpoint
        ? regionConfig.dualstackFipsRules
        : regionConfig.fipsRules
      : useDualstackEndpoint
      ? regionConfig.dualstackRules
      : regionConfig.rules;

    if (Object.prototype.hasOwnProperty.call(rules, key)) {
      var config = rules[key];
      if (typeof config === 'string') {
        config = regionConfig.patterns[config];
      }

      // set global endpoint
      service.isGlobalEndpoint = !!config.globalEndpoint;
      if (config.signingRegion) {
        service.signingRegion = config.signingRegion;
      }

      // signature version
      if (!config.signatureVersion) {
        // Note: config is a global object and should not be mutated here.
        // However, we are retaining this line for backwards compatibility.
        // The non-v4 signatureVersion will be set in a copied object below.
        config.signatureVersion = 'v4';
      }

      var useBearer = (service.api && service.api.signatureVersion) === 'bearer';

      // merge config
      applyConfig(service, Object.assign(
        {},
        config,
        { signatureVersion: useBearer ? 'bearer' : config.signatureVersion }
      ));
      return;
    }
  }
}

function getEndpointSuffix(region) {
  var regionRegexes = {
    '^(us|eu|ap|sa|ca|me)\\-\\w+\\-\\d+$': 'amazonaws.com',
    '^cn\\-\\w+\\-\\d+$': 'amazonaws.com.cn',
    '^us\\-gov\\-\\w+\\-\\d+$': 'amazonaws.com',
    '^us\\-iso\\-\\w+\\-\\d+$': 'c2s.ic.gov',
    '^us\\-isob\\-\\w+\\-\\d+$': 'sc2s.sgov.gov',
    '^eu\\-isoe\\-west\\-1$': 'cloud.adc-e.uk',
    '^us\\-isof\\-\\w+\\-\\d+$': 'csp.hci.ic.gov',
  };
  var defaultSuffix = 'amazonaws.com';
  var regexes = Object.keys(regionRegexes);
  for (var i = 0; i < regexes.length; i++) {
    var regionPattern = RegExp(regexes[i]);
    var dnsSuffix = regionRegexes[regexes[i]];
    if (regionPattern.test(region)) return dnsSuffix;
  }
  return defaultSuffix;
}

/**
 * @api private
 */
module.exports = {
  configureEndpoint: configureEndpoint,
  getEndpointSuffix: getEndpointSuffix,
};


/***/ },

/***/ 4002
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var AcceptorStateMachine = __webpack_require__(8900);
var inherit = AWS.util.inherit;
var domain = AWS.util.domain;
var jmespath = __webpack_require__(7533);

/**
 * @api private
 */
var hardErrorStates = {success: 1, error: 1, complete: 1};

function isTerminalState(machine) {
  return Object.prototype.hasOwnProperty.call(hardErrorStates, machine._asm.currentState);
}

var fsm = new AcceptorStateMachine();
fsm.setupStates = function() {
  var transition = function(_, done) {
    var self = this;
    self._haltHandlersOnError = false;

    self.emit(self._asm.currentState, function(err) {
      if (err) {
        if (isTerminalState(self)) {
          if (domain && self.domain instanceof domain.Domain) {
            err.domainEmitter = self;
            err.domain = self.domain;
            err.domainThrown = false;
            self.domain.emit('error', err);
          } else {
            throw err;
          }
        } else {
          self.response.error = err;
          done(err);
        }
      } else {
        done(self.response.error);
      }
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
fsm.setupStates();

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
 */
AWS.Request = inherit({

  /**
   * Creates a request for an operation on a given service with
   * a set of input parameters.
   *
   * @param service [AWS.Service] the service to perform the operation on
   * @param operation [String] the operation to perform on the service
   * @param params [Object] parameters to send to the operation.
   *   See the operation's documentation for the format of the
   *   parameters.
   */
  constructor: function Request(service, operation, params) {
    var endpoint = service.endpoint;
    var region = service.config.region;
    var customUserAgent = service.config.customUserAgent;

    if (service.signingRegion) {
      region = service.signingRegion;
    } else if (service.isGlobalEndpoint) {
      region = 'us-east-1';
    }

    this.domain = domain && domain.active;
    this.service = service;
    this.operation = operation;
    this.params = params || {};
    this.httpRequest = new AWS.HttpRequest(endpoint, region);
    this.httpRequest.appendToUserAgent(customUserAgent);
    this.startTime = service.getSkewCorrectedDate();

    this.response = new AWS.Response(this);
    this._asm = new AcceptorStateMachine(fsm.states, 'validate');
    this._haltHandlersOnError = false;

    AWS.SequentialExecutor.call(this);
    this.emit = this.emitEvent;
  },

  /**
   * @!group Sending a Request
   */

  /**
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
   */
  send: function send(callback) {
    if (callback) {
      // append to user agent
      this.httpRequest.appendToUserAgent('callback');
      this.on('complete', function (resp) {
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
   */

  /**
   * @api private
   */
  build: function build(callback) {
    return this.runTo('send', callback);
  },

  /**
   * @api private
   */
  runTo: function runTo(state, done) {
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
   */
  abort: function abort() {
    this.removeAllListeners('validateResponse');
    this.removeAllListeners('extractError');
    this.on('validateResponse', function addAbortedError(resp) {
      resp.error = AWS.util.error(new Error('Request aborted by user'), {
         code: 'RequestAbortedError', retryable: false
      });
    });

    if (this.httpRequest.stream && !this.httpRequest.stream.didCallback) { // abort HTTP stream
      this.httpRequest.stream.abort();
      if (this.httpRequest._abortCallback) {
         this.httpRequest._abortCallback();
      } else {
        this.removeAllListeners('send'); // haven't sent yet, so let's not
      }
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
   */
  eachPage: function eachPage(callback) {
    // Make all callbacks async-ish
    callback = AWS.util.fn.makeAsync(callback, 3);

    function wrappedCallback(response) {
      callback.call(response, response.error, response.data, function (result) {
        if (result === false) return;

        if (response.hasNextPage()) {
          response.nextPage().on('complete', wrappedCallback).send();
        } else {
          callback.call(response, null, null, AWS.util.fn.noop);
        }
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
   */
  eachItem: function eachItem(callback) {
    var self = this;
    function wrappedCallback(err, data) {
      if (err) return callback(err, null);
      if (data === null) return callback(null, null);

      var config = self.service.paginationConfig(self.operation);
      var resultKey = config.resultKey;
      if (Array.isArray(resultKey)) resultKey = resultKey[0];
      var items = jmespath.search(data, resultKey);
      var continueIteration = true;
      AWS.util.arrayEach(items, function(item) {
        continueIteration = callback(null, item);
        if (continueIteration === false) {
          return AWS.util.abort;
        }
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
   */
  isPageable: function isPageable() {
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
   */
  createReadStream: function createReadStream() {
    var streams = AWS.util.stream;
    var req = this;
    var stream = null;

    if (AWS.HttpClient.streamsApiVersion === 2) {
      stream = new streams.PassThrough();
      process.nextTick(function() { req.send(); });
    } else {
      stream = new streams.Stream();
      stream.readable = true;

      stream.sent = false;
      stream.on('newListener', function(event) {
        if (!stream.sent && event === 'data') {
          stream.sent = true;
          process.nextTick(function() { req.send(); });
        }
      });
    }

    this.on('error', function(err) {
      stream.emit('error', err);
    });

    this.on('httpHeaders', function streamHeaders(statusCode, headers, resp) {
      if (statusCode < 300) {
        req.removeListener('httpData', AWS.EventListeners.Core.HTTP_DATA);
        req.removeListener('httpError', AWS.EventListeners.Core.HTTP_ERROR);
        req.on('httpError', function streamHttpError(error) {
          resp.error = error;
          resp.error.retryable = false;
        });

        var shouldCheckContentLength = false;
        var expectedLen;
        if (req.httpRequest.method !== 'HEAD') {
          expectedLen = parseInt(headers['content-length'], 10);
        }
        if (expectedLen !== undefined && !isNaN(expectedLen) && expectedLen >= 0) {
          shouldCheckContentLength = true;
          var receivedLen = 0;
        }

        var checkContentLengthAndEmit = function checkContentLengthAndEmit() {
          if (shouldCheckContentLength && receivedLen !== expectedLen) {
            stream.emit('error', AWS.util.error(
              new Error('Stream content length mismatch. Received ' +
                receivedLen + ' of ' + expectedLen + ' bytes.'),
              { code: 'StreamContentLengthMismatch' }
            ));
          } else if (AWS.HttpClient.streamsApiVersion === 2) {
            stream.end();
          } else {
            stream.emit('end');
          }
        };

        var httpStream = resp.httpResponse.createUnbufferedStream();

        if (AWS.HttpClient.streamsApiVersion === 2) {
          if (shouldCheckContentLength) {
            var lengthAccumulator = new streams.PassThrough();
            lengthAccumulator._write = function(chunk) {
              if (chunk && chunk.length) {
                receivedLen += chunk.length;
              }
              return streams.PassThrough.prototype._write.apply(this, arguments);
            };

            lengthAccumulator.on('end', checkContentLengthAndEmit);
            stream.on('error', function(err) {
              shouldCheckContentLength = false;
              httpStream.unpipe(lengthAccumulator);
              lengthAccumulator.emit('end');
              lengthAccumulator.end();
            });
            httpStream.pipe(lengthAccumulator).pipe(stream, { end: false });
          } else {
            httpStream.pipe(stream);
          }
        } else {

          if (shouldCheckContentLength) {
            httpStream.on('data', function(arg) {
              if (arg && arg.length) {
                receivedLen += arg.length;
              }
            });
          }

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
   */
  emitEvent: function emit(eventName, args, done) {
    if (typeof args === 'function') { done = args; args = null; }
    if (!done) done = function() { };
    if (!args) args = this.eventParameters(eventName, this.response);

    var origEmit = AWS.SequentialExecutor.prototype.emit;
    origEmit.call(this, eventName, args, function (err) {
      if (err) this.response.error = err;
      done.call(this, err);
    });
  },

  /**
   * @api private
   */
  eventParameters: function eventParameters(eventName) {
    switch (eventName) {
      case 'restart':
      case 'validate':
      case 'sign':
      case 'build':
      case 'afterValidate':
      case 'afterBuild':
        return [this];
      case 'error':
        return [this.response.error, this.response];
      default:
        return [this.response];
    }
  },

  /**
   * @api private
   */
  presign: function presign(expires, callback) {
    if (!callback && typeof expires === 'function') {
      callback = expires;
      expires = null;
    }
    return new AWS.Signers.Presign().sign(this.toGet(), expires, callback);
  },

  /**
   * @api private
   */
  isPresigned: function isPresigned() {
    return Object.prototype.hasOwnProperty.call(this.httpRequest.headers, 'presigned-expires');
  },

  /**
   * @api private
   */
  toUnauthenticated: function toUnauthenticated() {
    this._unAuthenticated = true;
    this.removeListener('validate', AWS.EventListeners.Core.VALIDATE_CREDENTIALS);
    this.removeListener('sign', AWS.EventListeners.Core.SIGN);
    return this;
  },

  /**
   * @api private
   */
  toGet: function toGet() {
    if (this.service.api.protocol === 'query' ||
        this.service.api.protocol === 'ec2') {
      this.removeListener('build', this.buildAsGet);
      this.addListener('build', this.buildAsGet);
    }
    return this;
  },

  /**
   * @api private
   */
  buildAsGet: function buildAsGet(request) {
    request.httpRequest.method = 'GET';
    request.httpRequest.path = request.service.endpoint.path +
                               '?' + request.httpRequest.body;
    request.httpRequest.body = '';

    // don't need these headers on a GET request
    delete request.httpRequest.headers['Content-Length'];
    delete request.httpRequest.headers['Content-Type'];
  },

  /**
   * @api private
   */
  haltHandlersOnError: function haltHandlersOnError() {
    this._haltHandlersOnError = true;
  }
});

/**
 * @api private
 */
AWS.Request.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
  this.prototype.promise = function promise() {
    var self = this;
    // append to user agent
    this.httpRequest.appendToUserAgent('promise');
    return new PromiseDependency(function(resolve, reject) {
      self.on('complete', function(resp) {
        if (resp.error) {
          reject(resp.error);
        } else {
          // define $response property so that it is not enumerable
          // this prevents circular reference errors when stringifying the JSON object
          resolve(Object.defineProperty(
            resp.data || {},
            '$response',
            {value: resp}
          ));
        }
      });
      self.runTo();
    });
  };
};

/**
 * @api private
 */
AWS.Request.deletePromisesFromClass = function deletePromisesFromClass() {
  delete this.prototype.promise;
};

AWS.util.addPromises(AWS.Request);

AWS.util.mixin(AWS.Request, AWS.SequentialExecutor);


/***/ },

/***/ 4344
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

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

var AWS = __webpack_require__(9132);
var inherit = AWS.util.inherit;
var jmespath = __webpack_require__(7533);

/**
 * @api private
 */
function CHECK_ACCEPTORS(resp) {
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

  if (state === 'success') {
    waiter.setSuccess(resp);
  } else {
    waiter.setError(resp, state === 'retry');
  }
}

/**
 * @api private
 */
AWS.ResourceWaiter = inherit({
  /**
   * Waits for a given state on a service object
   * @param service [Service] the service object to wait on
   * @param state [String] the state (defined in waiter configuration) to wait
   *   for.
   * @example Create a waiter for running EC2 instances
   *   var ec2 = new AWS.EC2;
   *   var waiter = new AWS.ResourceWaiter(ec2, 'instanceRunning');
   */
  constructor: function constructor(service, state) {
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
        var result = jmespath.search(resp.data, argument);
      } catch (err) {
        return false;
      }

      return jmespath.strictDeepEqual(result,expected);
    },

    pathAll: function(resp, expected, argument) {
      try {
        var results = jmespath.search(resp.data, argument);
      } catch (err) {
        return false;
      }

      if (!Array.isArray(results)) results = [results];
      var numResults = results.length;
      if (!numResults) return false;
      for (var ind = 0 ; ind < numResults; ind++) {
        if (!jmespath.strictDeepEqual(results[ind], expected)) {
          return false;
        }
      }
      return true;
    },

    pathAny: function(resp, expected, argument) {
      try {
        var results = jmespath.search(resp.data, argument);
      } catch (err) {
        return false;
      }

      if (!Array.isArray(results)) results = [results];
      var numResults = results.length;
      for (var ind = 0 ; ind < numResults; ind++) {
        if (jmespath.strictDeepEqual(results[ind], expected)) {
          return true;
        }
      }
      return false;
    },

    status: function(resp, expected) {
      var statusCode = resp.httpResponse.statusCode;
      return (typeof statusCode === 'number') && (statusCode === expected);
    },

    error: function(resp, expected) {
      if (typeof expected === 'string' && resp.error) {
        return expected === resp.error.code;
      }
      // if expected is not string, can be boolean indicating presence of error
      return expected === !!resp.error;
    }
  },

  listeners: new AWS.SequentialExecutor().addNamedListeners(function(add) {
    add('RETRY_CHECK', 'retry', function(resp) {
      var waiter = resp.request._waiter;
      if (resp.error && resp.error.code === 'ResourceNotReady') {
        resp.error.retryDelay = (waiter.config.delay || 0) * 1000;
      }
    });

    add('CHECK_OUTPUT', 'extractData', CHECK_ACCEPTORS);

    add('CHECK_ERROR', 'extractError', CHECK_ACCEPTORS);
  }),

  /**
   * @return [AWS.Request]
   */
  wait: function wait(params, callback) {
    if (typeof params === 'function') {
      callback = params; params = undefined;
    }

    if (params && params.$waiter) {
      params = AWS.util.copy(params);
      if (typeof params.$waiter.delay === 'number') {
        this.config.delay = params.$waiter.delay;
      }
      if (typeof params.$waiter.maxAttempts === 'number') {
        this.config.maxAttempts = params.$waiter.maxAttempts;
      }
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
    resp.error = AWS.util.error(resp.error || new Error(), {
      code: 'ResourceNotReady',
      message: 'Resource is not in the state ' + this.state,
      retryable: retryable
    });
  },

  /**
   * Loads waiter configuration from API configuration
   *
   * @api private
   */
  loadWaiterConfig: function loadWaiterConfig(state) {
    if (!this.service.api.waiters[state]) {
      throw new AWS.util.error(new Error(), {
        code: 'StateNotFoundError',
        message: 'State ' + state + ' not found.'
      });
    }

    this.config = AWS.util.copy(this.service.api.waiters[state]);
  }
});


/***/ },

/***/ 4396
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var inherit = AWS.util.inherit;
var jmespath = __webpack_require__(7533);

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
 */
AWS.Response = inherit({

  /**
   * @api private
   */
  constructor: function Response(request) {
    this.request = request;
    this.data = null;
    this.error = null;
    this.retryCount = 0;
    this.redirectCount = 0;
    this.httpResponse = new AWS.HttpResponse();
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
   */
  nextPage: function nextPage(callback) {
    var config;
    var service = this.request.service;
    var operation = this.request.operation;
    try {
      config = service.paginationConfig(operation, true);
    } catch (e) { this.error = e; }

    if (!this.hasNextPage()) {
      if (callback) callback(this.error, null);
      else if (this.error) throw this.error;
      return null;
    }

    var params = AWS.util.copy(this.request.params);
    if (!this.nextPageTokens) {
      return callback ? callback(null, null) : null;
    } else {
      var inputTokens = config.inputToken;
      if (typeof inputTokens === 'string') inputTokens = [inputTokens];
      for (var i = 0; i < inputTokens.length; i++) {
        params[inputTokens[i]] = this.nextPageTokens[i];
      }
      return service.makeRequest(this.request.operation, params, callback);
    }
  },

  /**
   * @return [Boolean] whether more pages of data can be returned by further
   *   requests
   * @since v1.4.0
   */
  hasNextPage: function hasNextPage() {
    this.cacheNextPageTokens();
    if (this.nextPageTokens) return true;
    if (this.nextPageTokens === undefined) return undefined;
    else return false;
  },

  /**
   * @api private
   */
  cacheNextPageTokens: function cacheNextPageTokens() {
    if (Object.prototype.hasOwnProperty.call(this, 'nextPageTokens')) return this.nextPageTokens;
    this.nextPageTokens = undefined;

    var config = this.request.service.paginationConfig(this.request.operation);
    if (!config) return this.nextPageTokens;

    this.nextPageTokens = null;
    if (config.moreResults) {
      if (!jmespath.search(this.data, config.moreResults)) {
        return this.nextPageTokens;
      }
    }

    var exprs = config.outputToken;
    if (typeof exprs === 'string') exprs = [exprs];
    AWS.util.arrayEach.call(this, exprs, function (expr) {
      var output = jmespath.search(this.data, expr);
      if (output) {
        this.nextPageTokens = this.nextPageTokens || [];
        this.nextPageTokens.push(output);
      }
    });

    return this.nextPageTokens;
  }

});


/***/ },

/***/ 5138
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

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
 */
AWS.SequentialExecutor = AWS.util.inherit({

  constructor: function SequentialExecutor() {
    this._events = {};
  },

  /**
   * @api private
   */
  listeners: function listeners(eventName) {
    return this._events[eventName] ? this._events[eventName].slice(0) : [];
  },

  on: function on(eventName, listener, toHead) {
    if (this._events[eventName]) {
      toHead ?
        this._events[eventName].unshift(listener) :
        this._events[eventName].push(listener);
    } else {
      this._events[eventName] = [listener];
    }
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
      for (var i = 0; i < length; ++i) {
        if (listeners[i] === listener) {
          position = i;
        }
      }
      if (position > -1) {
        listeners.splice(position, 1);
      }
    }
    return this;
  },

  removeAllListeners: function removeAllListeners(eventName) {
    if (eventName) {
      delete this._events[eventName];
    } else {
      this._events = {};
    }
    return this;
  },

  /**
   * @api private
   */
  emit: function emit(eventName, eventArgs, doneCallback) {
    if (!doneCallback) doneCallback = function() { };
    var listeners = this.listeners(eventName);
    var count = listeners.length;
    this.callListeners(listeners, eventArgs, doneCallback);
    return count > 0;
  },

  /**
   * @api private
   */
  callListeners: function callListeners(listeners, args, doneCallback, prevError) {
    var self = this;
    var error = prevError || null;

    function callNextListener(err) {
      if (err) {
        error = AWS.util.error(error || new Error(), err);
        if (self._haltHandlersOnError) {
          return doneCallback.call(self, error);
        }
      }
      self.callListeners(listeners, args, doneCallback, error);
    }

    while (listeners.length > 0) {
      var listener = listeners.shift();
      if (listener._isAsync) { // asynchronous listener
        listener.apply(self, args.concat([callNextListener]));
        return; // stop here, callNextListener will continue
      } else { // synchronous listener
        try {
          listener.apply(self, args);
        } catch (err) {
          error = AWS.util.error(error || new Error(), err);
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
   */
  addListeners: function addListeners(listeners) {
    var self = this;

    // extract listeners if parameter is an SequentialExecutor object
    if (listeners._events) listeners = listeners._events;

    AWS.util.each(listeners, function(event, callbacks) {
      if (typeof callbacks === 'function') callbacks = [callbacks];
      AWS.util.arrayEach(callbacks, function(callback) {
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
   */
  addNamedListener: function addNamedListener(name, eventName, callback, toHead) {
    this[name] = callback;
    this.addListener(eventName, callback, toHead);
    return this;
  },

  /**
   * @api private
   */
  addNamedAsyncListener: function addNamedAsyncListener(name, eventName, callback, toHead) {
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
   */
  addNamedListeners: function addNamedListeners(callback) {
    var self = this;
    callback(
      function() {
        self.addNamedListener.apply(self, arguments);
      },
      function() {
        self.addNamedAsyncListener.apply(self, arguments);
      }
    );
    return this;
  }
});

/**
 * {on} is the prefered method.
 * @api private
 */
AWS.SequentialExecutor.prototype.addListener = AWS.SequentialExecutor.prototype.on;

/**
 * @api private
 */
module.exports = AWS.SequentialExecutor;


/***/ },

/***/ 5400
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var Api = __webpack_require__(9341);
var regionConfig = __webpack_require__(9240);

var inherit = AWS.util.inherit;
var clientCount = 0;
var region_utils = __webpack_require__(7357);

/**
 * The service class representing an AWS service.
 *
 * @class_abstract This class is an abstract class.
 *
 * @!attribute apiVersions
 *   @return [Array<String>] the list of API versions supported by this service.
 *   @readonly
 */
AWS.Service = inherit({
  /**
   * Create a new service object with a configuration object
   *
   * @param config [map] a map of configuration options
   */
  constructor: function Service(config) {
    if (!this.loadServiceClass) {
      throw AWS.util.error(new Error(),
        'Service must be constructed with `new\' operator');
    }

    if (config) {
      if (config.region) {
        var region = config.region;
        if (region_utils.isFipsRegion(region)) {
          config.region = region_utils.getRealRegion(region);
          config.useFipsEndpoint = true;
        }
        if (region_utils.isGlobalRegion(region)) {
          config.region = region_utils.getRealRegion(region);
        }
      }
      if (typeof config.useDualstack === 'boolean'
        && typeof config.useDualstackEndpoint !== 'boolean') {
        config.useDualstackEndpoint = config.useDualstack;
      }
    }

    var ServiceClass = this.loadServiceClass(config || {});
    if (ServiceClass) {
      var originalConfig = AWS.util.copy(config);
      var svc = new ServiceClass(config);
      Object.defineProperty(svc, '_originalConfig', {
        get: function() { return originalConfig; },
        enumerable: false,
        configurable: true
      });
      svc._clientId = ++clientCount;
      return svc;
    }
    this.initialize(config);
  },

  /**
   * @api private
   */
  initialize: function initialize(config) {
    var svcConfig = AWS.config[this.serviceIdentifier];
    this.config = new AWS.Config(AWS.config);
    if (svcConfig) this.config.update(svcConfig, true);
    if (config) this.config.update(config, true);

    this.validateService();
    if (!this.config.endpoint) regionConfig.configureEndpoint(this);

    this.config.endpoint = this.endpointFromTemplate(this.config.endpoint);
    this.setEndpoint(this.config.endpoint);
    //enable attaching listeners to service client
    AWS.SequentialExecutor.call(this);
    AWS.Service.addDefaultMonitoringListeners(this);
    if ((this.config.clientSideMonitoring || AWS.Service._clientSideMonitoring) && this.publisher) {
      var publisher = this.publisher;
      this.addNamedListener('PUBLISH_API_CALL', 'apiCall', function PUBLISH_API_CALL(event) {
        process.nextTick(function() {publisher.eventHandler(event);});
      });
      this.addNamedListener('PUBLISH_API_ATTEMPT', 'apiCallAttempt', function PUBLISH_API_ATTEMPT(event) {
        process.nextTick(function() {publisher.eventHandler(event);});
      });
    }
  },

  /**
   * @api private
   */
  validateService: function validateService() {
  },

  /**
   * @api private
   */
  loadServiceClass: function loadServiceClass(serviceConfig) {
    var config = serviceConfig;
    if (!AWS.util.isEmpty(this.api)) {
      return null;
    } else if (config.apiConfig) {
      return AWS.Service.defineServiceApi(this.constructor, config.apiConfig);
    } else if (!this.constructor.services) {
      return null;
    } else {
      config = new AWS.Config(AWS.config);
      config.update(serviceConfig, true);
      var version = config.apiVersions[this.constructor.serviceIdentifier];
      version = version || config.apiVersion;
      return this.getLatestServiceClass(version);
    }
  },

  /**
   * @api private
   */
  getLatestServiceClass: function getLatestServiceClass(version) {
    version = this.getLatestServiceVersion(version);
    if (this.constructor.services[version] === null) {
      AWS.Service.defineServiceApi(this.constructor, version);
    }

    return this.constructor.services[version];
  },

  /**
   * @api private
   */
  getLatestServiceVersion: function getLatestServiceVersion(version) {
    if (!this.constructor.services || this.constructor.services.length === 0) {
      throw new Error('No services defined on ' +
                      this.constructor.serviceIdentifier);
    }

    if (!version) {
      version = 'latest';
    } else if (AWS.util.isType(version, Date)) {
      version = AWS.util.date.iso8601(version).split('T')[0];
    }

    if (Object.hasOwnProperty(this.constructor.services, version)) {
      return version;
    }

    var keys = Object.keys(this.constructor.services).sort();
    var selectedVersion = null;
    for (var i = keys.length - 1; i >= 0; i--) {
      // versions that end in "*" are not available on disk and can be
      // skipped, so do not choose these as selectedVersions
      if (keys[i][keys[i].length - 1] !== '*') {
        selectedVersion = keys[i];
      }
      if (keys[i].substr(0, 10) <= version) {
        return selectedVersion;
      }
    }

    throw new Error('Could not find ' + this.constructor.serviceIdentifier +
                    ' API to satisfy version constraint `' + version + '\'');
  },

  /**
   * @api private
   */
  api: {},

  /**
   * @api private
   */
  defaultRetryCount: 3,

  /**
   * @api private
   */
  customizeRequests: function customizeRequests(callback) {
    if (!callback) {
      this.customRequestHandler = null;
    } else if (typeof callback === 'function') {
      this.customRequestHandler = callback;
    } else {
      throw new Error('Invalid callback type \'' + typeof callback + '\' provided in customizeRequests');
    }
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
   */
  makeRequest: function makeRequest(operation, params, callback) {
    if (typeof params === 'function') {
      callback = params;
      params = null;
    }

    params = params || {};
    if (this.config.params) { // copy only toplevel bound params
      var rules = this.api.operations[operation];
      if (rules) {
        params = AWS.util.copy(params);
        AWS.util.each(this.config.params, function(key, value) {
          if (rules.input.members[key]) {
            if (params[key] === undefined || params[key] === null) {
              params[key] = value;
            }
          }
        });
      }
    }

    var request = new AWS.Request(this, operation, params);
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
   */
  makeUnauthenticatedRequest: function makeUnauthenticatedRequest(operation, params, callback) {
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
   */
  waitFor: function waitFor(state, params, callback) {
    var waiter = new AWS.ResourceWaiter(this, state);
    return waiter.wait(params, callback);
  },

  /**
   * @api private
   */
  addAllRequestListeners: function addAllRequestListeners(request) {
    var list = [AWS.events, AWS.EventListeners.Core, this.serviceInterface(),
                AWS.EventListeners.CorePost];
    for (var i = 0; i < list.length; i++) {
      if (list[i]) request.addListeners(list[i]);
    }

    // disable parameter validation
    if (!this.config.paramValidation) {
      request.removeListener('validate',
        AWS.EventListeners.Core.VALIDATE_PARAMETERS);
    }

    if (this.config.logger) { // add logging events
      request.addListeners(AWS.EventListeners.Logger);
    }

    this.setupRequestListeners(request);
    // call prototype's customRequestHandler
    if (typeof this.constructor.prototype.customRequestHandler === 'function') {
      this.constructor.prototype.customRequestHandler(request);
    }
    // call instance's customRequestHandler
    if (Object.prototype.hasOwnProperty.call(this, 'customRequestHandler') && typeof this.customRequestHandler === 'function') {
      this.customRequestHandler(request);
    }
  },

  /**
   * Event recording metrics for a whole API call.
   * @returns {object} a subset of api call metrics
   * @api private
   */
  apiCallEvent: function apiCallEvent(request) {
    var api = request.service.api.operations[request.operation];
    var monitoringEvent = {
      Type: 'ApiCall',
      Api: api ? api.name : request.operation,
      Version: 1,
      Service: request.service.api.serviceId || request.service.api.endpointPrefix,
      Region: request.httpRequest.region,
      MaxRetriesExceeded: 0,
      UserAgent: request.httpRequest.getUserAgent(),
    };
    var response = request.response;
    if (response.httpResponse.statusCode) {
      monitoringEvent.FinalHttpStatusCode = response.httpResponse.statusCode;
    }
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
   */
  apiAttemptEvent: function apiAttemptEvent(request) {
    var api = request.service.api.operations[request.operation];
    var monitoringEvent = {
      Type: 'ApiCallAttempt',
      Api: api ? api.name : request.operation,
      Version: 1,
      Service: request.service.api.serviceId || request.service.api.endpointPrefix,
      Fqdn: request.httpRequest.endpoint.hostname,
      UserAgent: request.httpRequest.getUserAgent(),
    };
    var response = request.response;
    if (response.httpResponse.statusCode) {
      monitoringEvent.HttpStatusCode = response.httpResponse.statusCode;
    }
    if (
      !request._unAuthenticated &&
      request.service.config.credentials &&
      request.service.config.credentials.accessKeyId
    ) {
      monitoringEvent.AccessKey = request.service.config.credentials.accessKeyId;
    }
    if (!response.httpResponse.headers) return monitoringEvent;
    if (request.httpRequest.headers['x-amz-security-token']) {
      monitoringEvent.SessionToken = request.httpRequest.headers['x-amz-security-token'];
    }
    if (response.httpResponse.headers['x-amzn-requestid']) {
      monitoringEvent.XAmznRequestId = response.httpResponse.headers['x-amzn-requestid'];
    }
    if (response.httpResponse.headers['x-amz-request-id']) {
      monitoringEvent.XAmzRequestId = response.httpResponse.headers['x-amz-request-id'];
    }
    if (response.httpResponse.headers['x-amz-id-2']) {
      monitoringEvent.XAmzId2 = response.httpResponse.headers['x-amz-id-2'];
    }
    return monitoringEvent;
  },

  /**
   * Add metrics of failed request.
   * @api private
   */
  attemptFailEvent: function attemptFailEvent(request) {
    var monitoringEvent = this.apiAttemptEvent(request);
    var response = request.response;
    var error = response.error;
    if (response.httpResponse.statusCode > 299 ) {
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
   */
  attachMonitoringEmitter: function attachMonitoringEmitter(request) {
    var attemptTimestamp; //timestamp marking the beginning of a request attempt
    var attemptStartRealTime; //Start time of request attempt. Used to calculating attemptLatency
    var attemptLatency; //latency from request sent out to http response reaching SDK
    var callStartRealTime; //Start time of API call. Used to calculating API call latency
    var attemptCount = 0; //request.retryCount is not reliable here
    var region; //region cache region for each attempt since it can be updated in plase (e.g. s3)
    var callTimestamp; //timestamp when the request is created
    var self = this;
    var addToHead = true;

    request.on('validate', function () {
      callStartRealTime = AWS.util.realClock.now();
      callTimestamp = Date.now();
    }, addToHead);
    request.on('sign', function () {
      attemptStartRealTime = AWS.util.realClock.now();
      attemptTimestamp = Date.now();
      region = request.httpRequest.region;
      attemptCount++;
    }, addToHead);
    request.on('validateResponse', function() {
      attemptLatency = Math.round(AWS.util.realClock.now() - attemptStartRealTime);
    });
    request.addNamedListener('API_CALL_ATTEMPT', 'success', function API_CALL_ATTEMPT() {
      var apiAttemptEvent = self.apiAttemptEvent(request);
      apiAttemptEvent.Timestamp = attemptTimestamp;
      apiAttemptEvent.AttemptLatency = attemptLatency >= 0 ? attemptLatency : 0;
      apiAttemptEvent.Region = region;
      self.emit('apiCallAttempt', [apiAttemptEvent]);
    });
    request.addNamedListener('API_CALL_ATTEMPT_RETRY', 'retry', function API_CALL_ATTEMPT_RETRY() {
      var apiAttemptEvent = self.attemptFailEvent(request);
      apiAttemptEvent.Timestamp = attemptTimestamp;
      //attemptLatency may not be available if fail before response
      attemptLatency = attemptLatency ||
        Math.round(AWS.util.realClock.now() - attemptStartRealTime);
      apiAttemptEvent.AttemptLatency = attemptLatency >= 0 ? attemptLatency : 0;
      apiAttemptEvent.Region = region;
      self.emit('apiCallAttempt', [apiAttemptEvent]);
    });
    request.addNamedListener('API_CALL', 'complete', function API_CALL() {
      var apiCallEvent = self.apiCallEvent(request);
      apiCallEvent.AttemptCount = attemptCount;
      if (apiCallEvent.AttemptCount <= 0) return;
      apiCallEvent.Timestamp = callTimestamp;
      var latency = Math.round(AWS.util.realClock.now() - callStartRealTime);
      apiCallEvent.Latency = latency >= 0 ? latency : 0;
      var response = request.response;
      if (
        response.error &&
        response.error.retryable &&
        typeof response.retryCount === 'number' &&
        typeof response.maxRetries === 'number' &&
        (response.retryCount >= response.maxRetries)
      ) {
        apiCallEvent.MaxRetriesExceeded = 1;
      }
      self.emit('apiCall', [apiCallEvent]);
    });
  },

  /**
   * Override this method to setup any custom request listeners for each
   * new request to the service.
   *
   * @method_abstract This is an abstract method.
   */
  setupRequestListeners: function setupRequestListeners(request) {
  },

  /**
   * Gets the signing name for a given request
   * @api private
   */
  getSigningName: function getSigningName() {
    return this.api.signingName || this.api.endpointPrefix;
  },

  /**
   * Gets the signer class for a given request
   * @api private
   */
  getSignerClass: function getSignerClass(request) {
    var version;
    // get operation authtype if present
    var operation = null;
    var authtype = '';
    if (request) {
      var operations = request.service.api.operations || {};
      operation = operations[request.operation] || null;
      authtype = operation ? operation.authtype : '';
    }
    if (this.config.signatureVersion) {
      version = this.config.signatureVersion;
    } else if (authtype === 'v4' || authtype === 'v4-unsigned-body') {
      version = 'v4';
    } else if (authtype === 'bearer') {
      version = 'bearer';
    } else {
      version = this.api.signatureVersion;
    }
    return AWS.Signers.RequestSigner.getVersion(version);
  },

  /**
   * @api private
   */
  serviceInterface: function serviceInterface() {
    switch (this.api.protocol) {
      case 'ec2': return AWS.EventListeners.Query;
      case 'query': return AWS.EventListeners.Query;
      case 'json': return AWS.EventListeners.Json;
      case 'rest-json': return AWS.EventListeners.RestJson;
      case 'rest-xml': return AWS.EventListeners.RestXml;
    }
    if (this.api.protocol) {
      throw new Error('Invalid service `protocol\' ' +
        this.api.protocol + ' in API config');
    }
  },

  /**
   * @api private
   */
  successfulResponse: function successfulResponse(resp) {
    return resp.httpResponse.statusCode < 300;
  },

  /**
   * How many times a failed request should be retried before giving up.
   * the defaultRetryCount can be overriden by service classes.
   *
   * @api private
   */
  numRetries: function numRetries() {
    if (this.config.maxRetries !== undefined) {
      return this.config.maxRetries;
    } else {
      return this.defaultRetryCount;
    }
  },

  /**
   * @api private
   */
  retryDelays: function retryDelays(retryCount, err) {
    return AWS.util.calculateRetryDelay(retryCount, this.config.retryDelayOptions, err);
  },

  /**
   * @api private
   */
  retryableError: function retryableError(error) {
    if (this.timeoutError(error)) return true;
    if (this.networkingError(error)) return true;
    if (this.expiredCredentialsError(error)) return true;
    if (this.throttledError(error)) return true;
    if (error.statusCode >= 500) return true;
    return false;
  },

  /**
   * @api private
   */
  networkingError: function networkingError(error) {
    return error.code === 'NetworkingError';
  },

  /**
   * @api private
   */
  timeoutError: function timeoutError(error) {
    return error.code === 'TimeoutError';
  },

  /**
   * @api private
   */
  expiredCredentialsError: function expiredCredentialsError(error) {
    // TODO : this only handles *one* of the expired credential codes
    return (error.code === 'ExpiredTokenException');
  },

  /**
   * @api private
   */
  clockSkewError: function clockSkewError(error) {
    switch (error.code) {
      case 'RequestTimeTooSkewed':
      case 'RequestExpired':
      case 'InvalidSignatureException':
      case 'SignatureDoesNotMatch':
      case 'AuthFailure':
      case 'RequestInTheFuture':
        return true;
      default: return false;
    }
  },

  /**
   * @api private
   */
  getSkewCorrectedDate: function getSkewCorrectedDate() {
    return new Date(Date.now() + this.config.systemClockOffset);
  },

  /**
   * @api private
   */
  applyClockOffset: function applyClockOffset(newServerTime) {
    if (newServerTime) {
      this.config.systemClockOffset = newServerTime - Date.now();
    }
  },

  /**
   * @api private
   */
  isClockSkewed: function isClockSkewed(newServerTime) {
    if (newServerTime) {
      return Math.abs(this.getSkewCorrectedDate().getTime() - newServerTime) >= 300000;
    }
  },

  /**
   * @api private
   */
  throttledError: function throttledError(error) {
    // this logic varies between services
    if (error.statusCode === 429) return true;
    switch (error.code) {
      case 'ProvisionedThroughputExceededException':
      case 'Throttling':
      case 'ThrottlingException':
      case 'RequestLimitExceeded':
      case 'RequestThrottled':
      case 'RequestThrottledException':
      case 'TooManyRequestsException':
      case 'TransactionInProgressException': //dynamodb
      case 'EC2ThrottledException':
        return true;
      default:
        return false;
    }
  },

  /**
   * @api private
   */
  endpointFromTemplate: function endpointFromTemplate(endpoint) {
    if (typeof endpoint !== 'string') return endpoint;

    var e = endpoint;
    e = e.replace(/\{service\}/g, this.api.endpointPrefix);
    e = e.replace(/\{region\}/g, this.config.region);
    e = e.replace(/\{scheme\}/g, this.config.sslEnabled ? 'https' : 'http');
    return e;
  },

  /**
   * @api private
   */
  setEndpoint: function setEndpoint(endpoint) {
    this.endpoint = new AWS.Endpoint(endpoint, this.config);
  },

  /**
   * @api private
   */
  paginationConfig: function paginationConfig(operation, throwException) {
    var paginator = this.api.operations[operation].paginator;
    if (!paginator) {
      if (throwException) {
        var e = new Error();
        throw AWS.util.error(e, 'No pagination configuration for ' + operation);
      }
      return null;
    }

    return paginator;
  }
});

AWS.util.update(AWS.Service, {

  /**
   * Adds one method for each operation described in the api configuration
   *
   * @api private
   */
  defineMethods: function defineMethods(svc) {
    AWS.util.each(svc.prototype.api.operations, function iterator(method) {
      if (svc.prototype[method]) return;
      var operation = svc.prototype.api.operations[method];
      if (operation.authtype === 'none') {
        svc.prototype[method] = function (params, callback) {
          return this.makeUnauthenticatedRequest(method, params, callback);
        };
      } else {
        svc.prototype[method] = function (params, callback) {
          return this.makeRequest(method, params, callback);
        };
      }
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
   */
  defineService: function defineService(serviceIdentifier, versions, features) {
    AWS.Service._serviceMap[serviceIdentifier] = true;
    if (!Array.isArray(versions)) {
      features = versions;
      versions = [];
    }

    var svc = inherit(AWS.Service, features || {});

    if (typeof serviceIdentifier === 'string') {
      AWS.Service.addVersions(svc, versions);

      var identifier = svc.serviceIdentifier || serviceIdentifier;
      svc.serviceIdentifier = identifier;
    } else { // defineService called with an API
      svc.prototype.api = serviceIdentifier;
      AWS.Service.defineMethods(svc);
    }
    AWS.SequentialExecutor.call(this.prototype);
    //util.clientSideMonitoring is only available in node
    if (!this.prototype.publisher && AWS.util.clientSideMonitoring) {
      var Publisher = AWS.util.clientSideMonitoring.Publisher;
      var configProvider = AWS.util.clientSideMonitoring.configProvider;
      var publisherConfig = configProvider();
      this.prototype.publisher = new Publisher(publisherConfig);
      if (publisherConfig.enabled) {
        //if csm is enabled in environment, SDK should send all metrics
        AWS.Service._clientSideMonitoring = true;
      }
    }
    AWS.SequentialExecutor.call(svc.prototype);
    AWS.Service.addDefaultMonitoringListeners(svc.prototype);
    return svc;
  },

  /**
   * @api private
   */
  addVersions: function addVersions(svc, versions) {
    if (!Array.isArray(versions)) versions = [versions];

    svc.services = svc.services || {};
    for (var i = 0; i < versions.length; i++) {
      if (svc.services[versions[i]] === undefined) {
        svc.services[versions[i]] = null;
      }
    }

    svc.apiVersions = Object.keys(svc.services).sort();
  },

  /**
   * @api private
   */
  defineServiceApi: function defineServiceApi(superclass, version, apiConfig) {
    var svc = inherit(superclass, {
      serviceIdentifier: superclass.serviceIdentifier
    });

    function setApi(api) {
      if (api.isApi) {
        svc.prototype.api = api;
      } else {
        svc.prototype.api = new Api(api, {
          serviceIdentifier: superclass.serviceIdentifier
        });
      }
    }

    if (typeof version === 'string') {
      if (apiConfig) {
        setApi(apiConfig);
      } else {
        try {
          setApi(AWS.apiLoader(superclass.serviceIdentifier, version));
        } catch (err) {
          throw AWS.util.error(err, {
            message: 'Could not find API configuration ' +
              superclass.serviceIdentifier + '-' + version
          });
        }
      }
      if (!Object.prototype.hasOwnProperty.call(superclass.services, version)) {
        superclass.apiVersions = superclass.apiVersions.concat(version).sort();
      }
      superclass.services[version] = svc;
    } else {
      setApi(version);
    }

    AWS.Service.defineMethods(svc);
    return svc;
  },

  /**
   * @api private
   */
  hasService: function(identifier) {
    return Object.prototype.hasOwnProperty.call(AWS.Service._serviceMap, identifier);
  },

  /**
   * @param attachOn attach default monitoring listeners to object
   *
   * Each monitoring event should be emitted from service client to service constructor prototype and then
   * to global service prototype like bubbling up. These default monitoring events listener will transfer
   * the monitoring events to the upper layer.
   * @api private
   */
  addDefaultMonitoringListeners: function addDefaultMonitoringListeners(attachOn) {
    attachOn.addNamedListener('MONITOR_EVENTS_BUBBLE', 'apiCallAttempt', function EVENTS_BUBBLE(event) {
      var baseClass = Object.getPrototypeOf(attachOn);
      if (baseClass._events) baseClass.emit('apiCallAttempt', [event]);
    });
    attachOn.addNamedListener('CALL_EVENTS_BUBBLE', 'apiCall', function CALL_EVENTS_BUBBLE(event) {
      var baseClass = Object.getPrototypeOf(attachOn);
      if (baseClass._events) baseClass.emit('apiCall', [event]);
    });
  },

  /**
   * @api private
   */
  _serviceMap: {}
});

AWS.util.mixin(AWS.Service, AWS.SequentialExecutor);

/**
 * @api private
 */
module.exports = AWS.Service;


/***/ },

/***/ 2632
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var resolveRegionalEndpointsFlag = __webpack_require__(8497);
var ENV_REGIONAL_ENDPOINT_ENABLED = 'AWS_STS_REGIONAL_ENDPOINTS';
var CONFIG_REGIONAL_ENDPOINT_ENABLED = 'sts_regional_endpoints';

AWS.util.update(AWS.STS.prototype, {
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
   */
  credentialsFrom: function credentialsFrom(data, credentials) {
    if (!data) return null;
    if (!credentials) credentials = new AWS.TemporaryCredentials();
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
   */
  setupRequestListeners: function setupRequestListeners(request) {
    request.addListener('validate', this.optInRegionalEndpoint, true);
  },

  /**
   * @api private
   */
  optInRegionalEndpoint: function optInRegionalEndpoint(req) {
    var service = req.service;
    var config = service.config;
    config.stsRegionalEndpoints = resolveRegionalEndpointsFlag(service._originalConfig, {
      env: ENV_REGIONAL_ENDPOINT_ENABLED,
      sharedConfig: CONFIG_REGIONAL_ENDPOINT_ENABLED,
      clientConfig: 'stsRegionalEndpoints'
    });
    if (
      config.stsRegionalEndpoints === 'regional' &&
      service.isGlobalEndpoint
    ) {
      //client will throw if region is not supplied; request will be signed with specified region
      if (!config.region) {
        throw AWS.util.error(new Error(),
          {code: 'ConfigError', message: 'Missing region in config'});
      }
      var insertPoint = config.endpoint.indexOf('.amazonaws.com');
      var regionalEndpoint = config.endpoint.substring(0, insertPoint) +
        '.' + config.region + config.endpoint.substring(insertPoint);
      req.httpRequest.updateEndpoint(regionalEndpoint);
      req.httpRequest.region = config.region;
    }
  }

});


/***/ },

/***/ 5742
(module, __unused_webpack_exports, __webpack_require__) {

var IniLoader = (__webpack_require__(858).IniLoader);
/**
 * Singleton object to load specified config/credentials files.
 * It will cache all the files ever loaded;
 */
module.exports.s = new IniLoader();


/***/ },

/***/ 858
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var os = __webpack_require__(857);
var path = __webpack_require__(6928);

function parseFile(filename) {
  return AWS.util.ini.parse(AWS.util.readFileSync(filename));
}

function getProfiles(fileContent) {
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

function getSsoSessions(fileContent) {
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
 */
AWS.IniLoader = AWS.util.inherit({
  constructor: function IniLoader() {
    this.resolvedProfiles = {};
    this.resolvedSsoSessions = {};
  },

  /** Remove all cached files. Used after config files are updated. */
  clearCachedFiles: function clearCachedFiles() {
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
   */
  loadFrom: function loadFrom(options) {
    options = options || {};
    var isConfig = options.isConfig === true;
    var filename = options.filename || this.getDefaultFilePath(isConfig);
    if (!this.resolvedProfiles[filename]) {
      var fileContent = parseFile(filename);
      if (isConfig) {
        Object.defineProperty(this.resolvedProfiles, filename, {
          value: getProfiles(fileContent)
        });
      } else {
        Object.defineProperty(this.resolvedProfiles, filename, { value: fileContent });
      }
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
   */
  loadSsoSessionsFrom: function loadSsoSessionsFrom(options) {
    options = options || {};
    var filename = options.filename || this.getDefaultFilePath(true);
    if (!this.resolvedSsoSessions[filename]) {
      var fileContent = parseFile(filename);
      Object.defineProperty(this.resolvedSsoSessions, filename, {
        value: getSsoSessions(fileContent)
      });
    }
    return this.resolvedSsoSessions[filename];
  },

  getDefaultFilePath: function getDefaultFilePath(isConfig) {
    return path.join(
      this.getHomeDir(),
      '.aws',
      isConfig ? 'config' : 'credentials'
    );
  },

  getHomeDir: function getHomeDir() {
    var env = process.env;
    var home = env.HOME ||
      env.USERPROFILE ||
      (env.HOMEPATH ? ((env.HOMEDRIVE || 'C:/') + env.HOMEPATH) : null);

    if (home) {
      return home;
    }

    if (typeof os.homedir === 'function') {
      return os.homedir();
    }

    throw AWS.util.error(
      new Error('Cannot load credentials, HOME path not set')
    );
  }
});

var IniLoader = AWS.IniLoader;

module.exports = {
  IniLoader: IniLoader
};


/***/ },

/***/ 2486
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

/**
 * @api private
 */
AWS.Signers.Bearer = AWS.util.inherit(AWS.Signers.RequestSigner, {
  constructor: function Bearer(request) {
    AWS.Signers.RequestSigner.call(this, request);
  },

  addAuthorization: function addAuthorization(token) {
    this.request.headers['Authorization'] = 'Bearer ' + token.token;
  }
});


/***/ },

/***/ 9899
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var inherit = AWS.util.inherit;

/**
 * @api private
 */
var expiresHeader = 'presigned-expires';

/**
 * @api private
 */
function signedUrlBuilder(request) {
  var expires = request.httpRequest.headers[expiresHeader];
  var signerClass = request.service.getSignerClass(request);

  delete request.httpRequest.headers['User-Agent'];
  delete request.httpRequest.headers['X-Amz-User-Agent'];

  if (signerClass === AWS.Signers.V4) {
    if (expires > 604800) { // one week expiry is invalid
      var message = 'Presigning does not support expiry time greater ' +
                    'than a week with SigV4 signing.';
      throw AWS.util.error(new Error(), {
        code: 'InvalidExpiryTime', message: message, retryable: false
      });
    }
    request.httpRequest.headers[expiresHeader] = expires;
  } else if (signerClass === AWS.Signers.S3) {
    var now = request.service ? request.service.getSkewCorrectedDate() : AWS.util.date.getDate();
    request.httpRequest.headers[expiresHeader] = parseInt(
      AWS.util.date.unixTimestamp(now) + expires, 10).toString();
  } else {
    throw AWS.util.error(new Error(), {
      message: 'Presigning only supports S3 or SigV4 signing.',
      code: 'UnsupportedSigner', retryable: false
    });
  }
}

/**
 * @api private
 */
function signedUrlSigner(request) {
  var endpoint = request.httpRequest.endpoint;
  var parsedUrl = AWS.util.urlParse(request.httpRequest.path);
  var queryParams = {};

  if (parsedUrl.search) {
    queryParams = AWS.util.queryStringParse(parsedUrl.search.substr(1));
  }

  var auth = request.httpRequest.headers['Authorization'].split(' ');
  if (auth[0] === 'AWS') {
    auth = auth[1].split(':');
    queryParams['Signature'] = auth.pop();
    queryParams['AWSAccessKeyId'] = auth.join(':');

    AWS.util.each(request.httpRequest.headers, function (key, value) {
      if (key === expiresHeader) key = 'Expires';
      if (key.indexOf('x-amz-meta-') === 0) {
        // Delete existing, potentially not normalized key
        delete queryParams[key];
        key = key.toLowerCase();
      }
      queryParams[key] = value;
    });
    delete request.httpRequest.headers[expiresHeader];
    delete queryParams['Authorization'];
    delete queryParams['Host'];
  } else if (auth[0] === 'AWS4-HMAC-SHA256') { // SigV4 signing
    auth.shift();
    var rest = auth.join(' ');
    var signature = rest.match(/Signature=(.*?)(?:,|\s|\r?\n|$)/)[1];
    queryParams['X-Amz-Signature'] = signature;
    delete queryParams['Expires'];
  }

  // build URL
  endpoint.pathname = parsedUrl.pathname;
  endpoint.search = AWS.util.queryParamsToString(queryParams);
}

/**
 * @api private
 */
AWS.Signers.Presign = inherit({
  /**
   * @api private
   */
  sign: function sign(request, expireTime, callback) {
    request.httpRequest.headers[expiresHeader] = expireTime || 3600;
    request.on('build', signedUrlBuilder);
    request.on('sign', signedUrlSigner);
    request.removeListener('afterBuild',
      AWS.EventListeners.Core.SET_CONTENT_LENGTH);
    request.removeListener('afterBuild',
      AWS.EventListeners.Core.COMPUTE_SHA256);

    request.emit('beforePresign', [request]);

    if (callback) {
      request.build(function() {
        if (this.response.error) callback(this.response.error);
        else {
          callback(null, AWS.util.urlFormat(request.httpRequest.endpoint));
        }
      });
    } else {
      request.build();
      if (request.response.error) throw request.response.error;
      return AWS.util.urlFormat(request.httpRequest.endpoint);
    }
  }
});

/**
 * @api private
 */
module.exports = AWS.Signers.Presign;


/***/ },

/***/ 7383
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

var inherit = AWS.util.inherit;

/**
 * @api private
 */
AWS.Signers.RequestSigner = inherit({
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

AWS.Signers.RequestSigner.getVersion = function getVersion(version) {
  switch (version) {
    case 'v2': return AWS.Signers.V2;
    case 'v3': return AWS.Signers.V3;
    case 's3v4': return AWS.Signers.V4;
    case 'v4': return AWS.Signers.V4;
    case 's3': return AWS.Signers.S3;
    case 'v3https': return AWS.Signers.V3Https;
    case 'bearer': return AWS.Signers.Bearer;
  }
  throw new Error('Unknown signing version ' + version);
};

__webpack_require__(4243);
__webpack_require__(2956);
__webpack_require__(9667);
__webpack_require__(1417);
__webpack_require__(7661);
__webpack_require__(9899);
__webpack_require__(2486);


/***/ },

/***/ 7661
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var inherit = AWS.util.inherit;

/**
 * @api private
 */
AWS.Signers.S3 = inherit(AWS.Signers.RequestSigner, {
  /**
   * When building the stringToSign, these sub resource params should be
   * part of the canonical resource string with their NON-decoded values
   */
  subResources: {
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
    if (!this.request.headers['presigned-expires']) {
      this.request.headers['X-Amz-Date'] = AWS.util.date.rfc822(date);
    }

    if (credentials.sessionToken) {
      // presigned URLs require this header to be lowercased
      this.request.headers['x-amz-security-token'] = credentials.sessionToken;
    }

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

    AWS.util.each(this.request.headers, function (name) {
      if (name.match(/^x-amz-/i))
        amzHeaders.push(name);
    });

    amzHeaders.sort(function (a, b) {
      return a.toLowerCase() < b.toLowerCase() ? -1 : 1;
    });

    var parts = [];
    AWS.util.arrayEach.call(this, amzHeaders, function (name) {
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

    if (r.virtualHostedBucket)
      resource += '/' + r.virtualHostedBucket;

    resource += path;

    if (querystring) {

      // collect a list of sub resources and query params that need to be signed
      var resources = [];

      AWS.util.arrayEach.call(this, querystring.split('&'), function (param) {
        var name = param.split('=')[0];
        var value = param.split('=')[1];
        if (this.subResources[name] || this.responseHeaders[name]) {
          var subresource = { name: name };
          if (value !== undefined) {
            if (this.subResources[name]) {
              subresource.value = value;
            } else {
              subresource.value = decodeURIComponent(value);
            }
          }
          resources.push(subresource);
        }
      });

      resources.sort(function (a, b) { return a.name < b.name ? -1 : 1; });

      if (resources.length) {

        querystring = [];
        AWS.util.arrayEach(resources, function (res) {
          if (res.value === undefined) {
            querystring.push(res.name);
          } else {
            querystring.push(res.name + '=' + res.value);
          }
        });

        resource += '?' + querystring.join('&');
      }

    }

    return resource;

  },

  sign: function sign(secret, string) {
    return AWS.util.crypto.hmac(secret, string, 'base64', 'sha1');
  }
});

/**
 * @api private
 */
module.exports = AWS.Signers.S3;


/***/ },

/***/ 4243
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var inherit = AWS.util.inherit;

/**
 * @api private
 */
AWS.Signers.V2 = inherit(AWS.Signers.RequestSigner, {
  addAuthorization: function addAuthorization(credentials, date) {

    if (!date) date = AWS.util.date.getDate();

    var r = this.request;

    r.params.Timestamp = AWS.util.date.iso8601(date);
    r.params.SignatureVersion = '2';
    r.params.SignatureMethod = 'HmacSHA256';
    r.params.AWSAccessKeyId = credentials.accessKeyId;

    if (credentials.sessionToken) {
      r.params.SecurityToken = credentials.sessionToken;
    }

    delete r.params.Signature; // delete old Signature for re-signing
    r.params.Signature = this.signature(credentials);

    r.body = AWS.util.queryParamsToString(r.params);
    r.headers['Content-Length'] = r.body.length;
  },

  signature: function signature(credentials) {
    return AWS.util.crypto.hmac(credentials.secretAccessKey, this.stringToSign(), 'base64');
  },

  stringToSign: function stringToSign() {
    var parts = [];
    parts.push(this.request.method);
    parts.push(this.request.endpoint.host.toLowerCase());
    parts.push(this.request.pathname());
    parts.push(AWS.util.queryParamsToString(this.request.params));
    return parts.join('\n');
  }

});

/**
 * @api private
 */
module.exports = AWS.Signers.V2;


/***/ },

/***/ 2956
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var inherit = AWS.util.inherit;

/**
 * @api private
 */
AWS.Signers.V3 = inherit(AWS.Signers.RequestSigner, {
  addAuthorization: function addAuthorization(credentials, date) {

    var datetime = AWS.util.date.rfc822(date);

    this.request.headers['X-Amz-Date'] = datetime;

    if (credentials.sessionToken) {
      this.request.headers['x-amz-security-token'] = credentials.sessionToken;
    }

    this.request.headers['X-Amzn-Authorization'] =
      this.authorization(credentials, datetime);

  },

  authorization: function authorization(credentials) {
    return 'AWS3 ' +
      'AWSAccessKeyId=' + credentials.accessKeyId + ',' +
      'Algorithm=HmacSHA256,' +
      'SignedHeaders=' + this.signedHeaders() + ',' +
      'Signature=' + this.signature(credentials);
  },

  signedHeaders: function signedHeaders() {
    var headers = [];
    AWS.util.arrayEach(this.headersToSign(), function iterator(h) {
      headers.push(h.toLowerCase());
    });
    return headers.sort().join(';');
  },

  canonicalHeaders: function canonicalHeaders() {
    var headers = this.request.headers;
    var parts = [];
    AWS.util.arrayEach(this.headersToSign(), function iterator(h) {
      parts.push(h.toLowerCase().trim() + ':' + String(headers[h]).trim());
    });
    return parts.sort().join('\n') + '\n';
  },

  headersToSign: function headersToSign() {
    var headers = [];
    AWS.util.each(this.request.headers, function iterator(k) {
      if (k === 'Host' || k === 'Content-Encoding' || k.match(/^X-Amz/i)) {
        headers.push(k);
      }
    });
    return headers;
  },

  signature: function signature(credentials) {
    return AWS.util.crypto.hmac(credentials.secretAccessKey, this.stringToSign(), 'base64');
  },

  stringToSign: function stringToSign() {
    var parts = [];
    parts.push(this.request.method);
    parts.push('/');
    parts.push('');
    parts.push(this.canonicalHeaders());
    parts.push(this.request.body);
    return AWS.util.crypto.sha256(parts.join('\n'));
  }

});

/**
 * @api private
 */
module.exports = AWS.Signers.V3;


/***/ },

/***/ 9667
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var inherit = AWS.util.inherit;

__webpack_require__(2956);

/**
 * @api private
 */
AWS.Signers.V3Https = inherit(AWS.Signers.V3, {
  authorization: function authorization(credentials) {
    return 'AWS3-HTTPS ' +
      'AWSAccessKeyId=' + credentials.accessKeyId + ',' +
      'Algorithm=HmacSHA256,' +
      'Signature=' + this.signature(credentials);
  },

  stringToSign: function stringToSign() {
    return this.request.headers['X-Amz-Date'];
  }
});

/**
 * @api private
 */
module.exports = AWS.Signers.V3Https;


/***/ },

/***/ 1417
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var v4Credentials = __webpack_require__(9944);
var inherit = AWS.util.inherit;

/**
 * @api private
 */
var expiresHeader = 'presigned-expires';

/**
 * @api private
 */
AWS.Signers.V4 = inherit(AWS.Signers.RequestSigner, {
  constructor: function V4(request, serviceName, options) {
    AWS.Signers.RequestSigner.call(this, request);
    this.serviceName = serviceName;
    options = options || {};
    this.signatureCache = typeof options.signatureCache === 'boolean' ? options.signatureCache : true;
    this.operation = options.operation;
    this.signatureVersion = options.signatureVersion;
  },

  algorithm: 'AWS4-HMAC-SHA256',

  addAuthorization: function addAuthorization(credentials, date) {
    var datetime = AWS.util.date.iso8601(date).replace(/[:\-]|\.\d{3}/g, '');

    if (this.isPresigned()) {
      this.updateForPresigned(credentials, datetime);
    } else {
      this.addHeaders(credentials, datetime);
    }

    this.request.headers['Authorization'] =
      this.authorization(credentials, datetime);
  },

  addHeaders: function addHeaders(credentials, datetime) {
    this.request.headers['X-Amz-Date'] = datetime;
    if (credentials.sessionToken) {
      this.request.headers['x-amz-security-token'] = credentials.sessionToken;
    }
  },

  updateForPresigned: function updateForPresigned(credentials, datetime) {
    var credString = this.credentialString(datetime);
    var qs = {
      'X-Amz-Date': datetime,
      'X-Amz-Algorithm': this.algorithm,
      'X-Amz-Credential': credentials.accessKeyId + '/' + credString,
      'X-Amz-Expires': this.request.headers[expiresHeader],
      'X-Amz-SignedHeaders': this.signedHeaders()
    };

    if (credentials.sessionToken) {
      qs['X-Amz-Security-Token'] = credentials.sessionToken;
    }

    if (this.request.headers['Content-Type']) {
      qs['Content-Type'] = this.request.headers['Content-Type'];
    }
    if (this.request.headers['Content-MD5']) {
      qs['Content-MD5'] = this.request.headers['Content-MD5'];
    }
    if (this.request.headers['Cache-Control']) {
      qs['Cache-Control'] = this.request.headers['Cache-Control'];
    }

    // need to pull in any other X-Amz-* headers
    AWS.util.each.call(this, this.request.headers, function(key, value) {
      if (key === expiresHeader) return;
      if (this.isSignableHeader(key)) {
        var lowerKey = key.toLowerCase();
        // Metadata should be normalized
        if (lowerKey.indexOf('x-amz-meta-') === 0) {
          qs[lowerKey] = value;
        } else if (lowerKey.indexOf('x-amz-') === 0) {
          qs[key] = value;
        }
      }
    });

    var sep = this.request.path.indexOf('?') >= 0 ? '&' : '?';
    this.request.path += sep + AWS.util.queryParamsToString(qs);
  },

  authorization: function authorization(credentials, datetime) {
    var parts = [];
    var credString = this.credentialString(datetime);
    parts.push(this.algorithm + ' Credential=' +
      credentials.accessKeyId + '/' + credString);
    parts.push('SignedHeaders=' + this.signedHeaders());
    parts.push('Signature=' + this.signature(credentials, datetime));
    return parts.join(', ');
  },

  signature: function signature(credentials, datetime) {
    var signingKey = v4Credentials.getSigningKey(
      credentials,
      datetime.substr(0, 8),
      this.request.region,
      this.serviceName,
      this.signatureCache
    );
    return AWS.util.crypto.hmac(signingKey, this.stringToSign(datetime), 'hex');
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
    if (this.serviceName !== 's3' && this.signatureVersion !== 's3v4') pathname = AWS.util.uriEscapePath(pathname);

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
    AWS.util.each.call(this, this.request.headers, function (key, item) {
      headers.push([key, item]);
    });
    headers.sort(function (a, b) {
      return a[0].toLowerCase() < b[0].toLowerCase() ? -1 : 1;
    });
    var parts = [];
    AWS.util.arrayEach.call(this, headers, function (item) {
      var key = item[0].toLowerCase();
      if (this.isSignableHeader(key)) {
        var value = item[1];
        if (typeof value === 'undefined' || value === null || typeof value.toString !== 'function') {
          throw AWS.util.error(new Error('Header ' + key + ' contains invalid value'), {
            code: 'InvalidHeader'
          });
        }
        parts.push(key + ':' +
          this.canonicalHeaderValues(value.toString()));
      }
    });
    return parts.join('\n');
  },

  canonicalHeaderValues: function canonicalHeaderValues(values) {
    return values.replace(/\s+/g, ' ').replace(/^\s+|\s+$/g, '');
  },

  signedHeaders: function signedHeaders() {
    var keys = [];
    AWS.util.each.call(this, this.request.headers, function (key) {
      key = key.toLowerCase();
      if (this.isSignableHeader(key)) keys.push(key);
    });
    return keys.sort().join(';');
  },

  credentialString: function credentialString(datetime) {
    return v4Credentials.createScope(
      datetime.substr(0, 8),
      this.request.region,
      this.serviceName
    );
  },

  hexEncodedHash: function hash(string) {
    return AWS.util.crypto.sha256(string, 'hex');
  },

  hexEncodedBodyHash: function hexEncodedBodyHash() {
    var request = this.request;
    if (this.isPresigned() && (['s3', 's3-object-lambda'].indexOf(this.serviceName) > -1) && !request.body) {
      return 'UNSIGNED-PAYLOAD';
    } else if (request.headers['X-Amz-Content-Sha256']) {
      return request.headers['X-Amz-Content-Sha256'];
    } else {
      return this.hexEncodedHash(this.request.body || '');
    }
  },

  unsignableHeaders: [
    'authorization',
    'content-type',
    'content-length',
    'user-agent',
    expiresHeader,
    'expect',
    'x-amzn-trace-id'
  ],

  isSignableHeader: function isSignableHeader(key) {
    if (key.toLowerCase().indexOf('x-amz-') === 0) return true;
    return this.unsignableHeaders.indexOf(key) < 0;
  },

  isPresigned: function isPresigned() {
    return this.request.headers[expiresHeader] ? true : false;
  }

});

/**
 * @api private
 */
module.exports = AWS.Signers.V4;


/***/ },

/***/ 9944
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

/**
 * @api private
 */
var cachedSecret = {};

/**
 * @api private
 */
var cacheQueue = [];

/**
 * @api private
 */
var maxCacheEntries = 50;

/**
 * @api private
 */
var v4Identifier = 'aws4_request';

/**
 * @api private
 */
module.exports = {
  /**
   * @api private
   *
   * @param date [String]
   * @param region [String]
   * @param serviceName [String]
   * @return [String]
   */
  createScope: function createScope(date, region, serviceName) {
    return [
      date.substr(0, 8),
      region,
      serviceName,
      v4Identifier
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
   */
  getSigningKey: function getSigningKey(
    credentials,
    date,
    region,
    service,
    shouldCache
  ) {
    var credsIdentifier = AWS.util.crypto
      .hmac(credentials.secretAccessKey, credentials.accessKeyId, 'base64');
    var cacheKey = [credsIdentifier, date, region, service].join('_');
    shouldCache = shouldCache !== false;
    if (shouldCache && (cacheKey in cachedSecret)) {
      return cachedSecret[cacheKey];
    }

    var kDate = AWS.util.crypto.hmac(
      'AWS4' + credentials.secretAccessKey,
      date,
      'buffer'
    );
    var kRegion = AWS.util.crypto.hmac(kDate, region, 'buffer');
    var kService = AWS.util.crypto.hmac(kRegion, service, 'buffer');

    var signingKey = AWS.util.crypto.hmac(kService, v4Identifier, 'buffer');
    if (shouldCache) {
      cachedSecret[cacheKey] = signingKey;
      cacheQueue.push(cacheKey);
      if (cacheQueue.length > maxCacheEntries) {
        // remove the oldest entry (not the least recently used)
        delete cachedSecret[cacheQueue.shift()];
      }
    }

    return signingKey;
  },

  /**
   * @api private
   *
   * Empties the derived signing key cache. Made available for testing purposes
   * only.
   */
  emptyCache: function emptyCache() {
    cachedSecret = {};
    cacheQueue = [];
  }
};


/***/ },

/***/ 8900
(module) {

function AcceptorStateMachine(states, state) {
  this.currentState = state || null;
  this.states = states || {};
}

AcceptorStateMachine.prototype.runTo = function runTo(finalState, done, bindObject, inputError) {
  if (typeof finalState === 'function') {
    inputError = bindObject; bindObject = done;
    done = finalState; finalState = null;
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
    if (self.currentState === finalState) {
      return done ? done.call(bindObject, err) : null;
    }

    self.runTo(finalState, done, bindObject, err);
  });
};

AcceptorStateMachine.prototype.addState = function addState(name, acceptState, failState, fn) {
  if (typeof acceptState === 'function') {
    fn = acceptState; acceptState = null; failState = null;
  } else if (typeof failState === 'function') {
    fn = failState; failState = null;
  }

  if (!this.currentState) this.currentState = name;
  this.states[name] = { accept: acceptState, fail: failState, fn: fn };
  return this;
};

/**
 * @api private
 */
module.exports = AcceptorStateMachine;


/***/ },

/***/ 7486
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

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
 */
AWS.Token = AWS.util.inherit({
  /**
   * Creates a Token object with a given set of information in options hash.
   * @option options token [String] represents the literal token string.
   * @option options expireTime [Date] field representing the time at which
   *   the token expires.
   * @example Create a token object
   *   var token = new AWS.Token({ token: 'token' });
   */
  constructor: function Token(options) {
    // hide token from being displayed with util.inspect
    AWS.util.hideProperties(this, ['token']);

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
   */
  expiryWindow: 15,

  /**
   * @return [Boolean] whether the Token object should call {refresh}
   * @note Subclasses should override this method to provide custom refresh
   *   logic.
   */
  needsRefresh: function needsRefresh() {
    var currentTime = AWS.util.date.getDate().getTime();
    var adjustedTime = new Date(currentTime + this.expiryWindow * 1000);

    if (this.expireTime && adjustedTime > this.expireTime)
      return true;

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
   */
  get: function get(callback) {
    var self = this;
    if (this.needsRefresh()) {
      this.refresh(function(err) {
        if (!err) self.expired = false; // reset expired flag
        if (callback) callback(err);
      });
    } else if (callback) {
      callback();
    }
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
   */

  /**
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
   */

  /**
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
   */
  refresh: function refresh(callback) {
    this.expired = false;
    callback();
  },

  /**
   * @api private
   * @param callback
   */
  coalesceRefresh: function coalesceRefresh(callback, sync) {
    var self = this;
    if (self.refreshCallbacks.push(callback) === 1) {
      self.load(function onLoad(err) {
        AWS.util.arrayEach(self.refreshCallbacks, function(callback) {
          if (sync) {
            callback(err);
          } else {
            // callback could throw, so defer to ensure all callbacks are notified
            AWS.util.defer(function () {
              callback(err);
            });
          }
        });
        self.refreshCallbacks.length = 0;
      });
    }
  },

  /**
   * @api private
   * @param callback
   */
  load: function load(callback) {
    callback();
  }
});

/**
 * @api private
 */
AWS.Token.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
  this.prototype.getPromise = AWS.util.promisifyMethod('get', PromiseDependency);
  this.prototype.refreshPromise = AWS.util.promisifyMethod('refresh', PromiseDependency);
};

/**
 * @api private
 */
AWS.Token.deletePromisesFromClass = function deletePromisesFromClass() {
  delete this.prototype.getPromise;
  delete this.prototype.refreshPromise;
};

AWS.util.addPromises(AWS.Token);


/***/ },

/***/ 8614
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var crypto = __webpack_require__(6982);
var fs = __webpack_require__(9896);
var path = __webpack_require__(6928);
var iniLoader = AWS.util.iniLoader;

// Tracking refresh attempt to ensure refresh is not attempted more than once every 30 seconds.
var lastRefreshAttemptTime = 0;

/**
 * Throws error is key is not present in token object.
 *
 * @param token [Object] Object to be validated.
 * @param key [String] The key to be validated on the object.
 */
var validateTokenKey = function validateTokenKey(token, key) {
  if (!token[key]) {
    throw AWS.util.error(
      new Error('Key "' + key + '" not present in SSO Token'),
      { code: 'SSOTokenProviderFailure' }
    );
  }
};

/**
 * Calls callback function with or without error based on provided times in case
 * of unsuccessful refresh.
 *
 * @param currentTime [number] current time in milliseconds since ECMAScript epoch.
 * @param tokenExpireTime [number] token expire time in milliseconds since ECMAScript epoch.
 * @param callback [Function] Callback to call in case of error.
 */
var refreshUnsuccessful = function refreshUnsuccessful(
  currentTime,
  tokenExpireTime,
  callback
) {
  if (tokenExpireTime > currentTime) {
    // Cached token is still valid, return.
    callback(null);
  } else {
    // Token invalid, throw error requesting user to sso login.
    throw AWS.util.error(
      new Error('SSO Token refresh failed. Please log in using "aws sso login"'),
      { code: 'SSOTokenProviderFailure' }
    );
  }
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
 */
AWS.SSOTokenProvider = AWS.util.inherit(AWS.Token, {
  /**
   * Expiry window of five minutes.
   */
  expiryWindow: 5 * 60,

  /**
   * Creates a new token object from cached access token.
   *
   * @param options [map] a set of options
   * @option options profile [String] (AWS_PROFILE env var or 'default')
   *   the name of the profile to load.
   * @option options callback [Function] (err) Token is eagerly loaded
   *   by the constructor. When the callback is called with no error, the
   *   token has been loaded successfully.
   */
  constructor: function SSOTokenProvider(options) {
    AWS.Token.call(this);

    options = options || {};

    this.expired = true;
    this.profile = options.profile || process.env.AWS_PROFILE || AWS.util.defaultProfile;
    this.get(options.callback || AWS.util.fn.noop);
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
   */
  load: function load(callback) {
    var self = this;
    var profiles = iniLoader.loadFrom({ isConfig: true });
    var profile = profiles[this.profile] || {};

    if (Object.keys(profile).length === 0) {
      throw AWS.util.error(
        new Error('Profile "' + this.profile + '" not found'),
        { code: 'SSOTokenProviderFailure' }
      );
    } else if (!profile['sso_session']) {
      throw AWS.util.error(
        new Error('Profile "' + this.profile + '" is missing required property "sso_session".'),
        { code: 'SSOTokenProviderFailure' }
      );
    }

    var ssoSessionName = profile['sso_session'];
    var ssoSessions = iniLoader.loadSsoSessionsFrom();
    var ssoSession = ssoSessions[ssoSessionName];

    if (!ssoSession) {
      throw AWS.util.error(
        new Error('Sso session "' + ssoSessionName + '" not found'),
        { code: 'SSOTokenProviderFailure' }
      );
    } else if (!ssoSession['sso_start_url']) {
      throw AWS.util.error(
        new Error('Sso session "' + this.profile + '" is missing required property "sso_start_url".'),
        { code: 'SSOTokenProviderFailure' }
      );
    } else if (!ssoSession['sso_region']) {
      throw AWS.util.error(
        new Error('Sso session "' + this.profile + '" is missing required property "sso_region".'),
        { code: 'SSOTokenProviderFailure' }
      );
    }

    var hasher = crypto.createHash('sha1');
    var fileName = hasher.update(ssoSessionName).digest('hex') + '.json';
    var cachePath = path.join(iniLoader.getHomeDir(), '.aws', 'sso', 'cache', fileName);
    var tokenFromCache = JSON.parse(fs.readFileSync(cachePath));

    if (!tokenFromCache) {
      throw AWS.util.error(
        new Error('Cached token not found. Please log in using "aws sso login"'
          + ' for profile "' + this.profile + '".'),
        { code: 'SSOTokenProviderFailure' }
      );
    }

    validateTokenKey(tokenFromCache, 'accessToken');
    validateTokenKey(tokenFromCache, 'expiresAt');

    var currentTime = AWS.util.date.getDate().getTime();
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
    if (currentTime - lastRefreshAttemptTime < 30 * 1000) {
      refreshUnsuccessful(currentTime, tokenExpireTime, callback);
      return;
    }

    // Token is in expiry window, refresh from SSOOIDC.createToken() call.
    validateTokenKey(tokenFromCache, 'clientId');
    validateTokenKey(tokenFromCache, 'clientSecret');
    validateTokenKey(tokenFromCache, 'refreshToken');

    if (!self.service || self.service.config.region !== ssoSession.sso_region) {
      self.service = new AWS.SSOOIDC({ region: ssoSession.sso_region });
    }

    var params = {
      clientId: tokenFromCache.clientId,
      clientSecret: tokenFromCache.clientSecret,
      refreshToken: tokenFromCache.refreshToken,
      grantType: 'refresh_token',
    };

    lastRefreshAttemptTime = AWS.util.date.getDate().getTime();
    self.service.createToken(params, function(err, data) {
      if (err || !data) {
        refreshUnsuccessful(currentTime, tokenExpireTime, callback);
      } else {
        try {
          validateTokenKey(data, 'accessToken');
          validateTokenKey(data, 'expiresIn');
          self.expired = false;
          self.token = data.accessToken;
          self.expireTime = new Date(Date.now() + data.expiresIn * 1000);
          callback(null);

          try {
            // Write updated token data to disk.
            tokenFromCache.accessToken = data.accessToken;
            tokenFromCache.expiresAt = self.expireTime.toISOString();
            tokenFromCache.refreshToken = data.refreshToken;
            fs.writeFileSync(cachePath, JSON.stringify(tokenFromCache, null, 2));
          } catch (error) {
            // Swallow error if unable to write token to file.
          }
        } catch (error) {
          refreshUnsuccessful(currentTime, tokenExpireTime, callback);
        }
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
   */
  refresh: function refresh(callback) {
    iniLoader.clearCachedFiles();
    this.coalesceRefresh(callback || AWS.util.fn.callback);
  },
});


/***/ },

/***/ 4796
(__unused_webpack_module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);

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
 */
AWS.TokenProviderChain = AWS.util.inherit(AWS.Token, {

  /**
   * Creates a new TokenProviderChain with a default set of providers
   * specified by {defaultProviders}.
   */
  constructor: function TokenProviderChain(providers) {
    if (providers) {
      this.providers = providers;
    } else {
      this.providers = AWS.TokenProviderChain.defaultProviders.slice(0);
    }
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
   */

  /**
   * Resolves the provider chain by searching for the first token in {providers}.
   *
   * @callback callback function(err, token)
   *   Called when the provider resolves the chain to a token object
   *   or null if no token can be found.
   *
   *   @param err [Error] the error object returned if no token is found.
   *   @param token [AWS.Token] the token object resolved by the provider chain.
   * @return [AWS.TokenProviderChain] the provider, for chaining.
   */
  resolve: function resolve(callback) {
    var self = this;
    if (self.providers.length === 0) {
      callback(new Error('No providers'));
      return self;
    }

    if (self.resolveCallbacks.push(callback) === 1) {
      var index = 0;
      var providers = self.providers.slice(0);

      function resolveNext(err, token) {
        if ((!err && token) || index === providers.length) {
          AWS.util.arrayEach(self.resolveCallbacks, function (callback) {
            callback(err, token);
          });
          self.resolveCallbacks.length = 0;
          return;
        }

        var provider = providers[index++];
        if (typeof provider === 'function') {
          token = provider.call();
        } else {
          token = provider;
        }

        if (token.get) {
          token.get(function (getErr) {
            resolveNext(getErr, getErr ? null : token);
          });
        } else {
          resolveNext(null, token);
        }
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
 */
AWS.TokenProviderChain.defaultProviders = [];

/**
 * @api private
 */
AWS.TokenProviderChain.addPromisesToClass = function addPromisesToClass(PromiseDependency) {
  this.prototype.resolvePromise = AWS.util.promisifyMethod('resolve', PromiseDependency);
};

/**
 * @api private
 */
AWS.TokenProviderChain.deletePromisesFromClass = function deletePromisesFromClass() {
  delete this.prototype.resolvePromise;
};

AWS.util.addPromises(AWS.TokenProviderChain);


/***/ },

/***/ 9019
(module, __unused_webpack_exports, __webpack_require__) {

/* eslint guard-for-in:0 */
var AWS;

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
 */
var util = {
  environment: 'nodejs',
  engine: function engine() {
    if (util.isBrowser() && typeof navigator !== 'undefined') {
      return navigator.userAgent;
    } else {
      var engine = process.platform + '/' + process.version;
      if (process.env.AWS_EXECUTION_ENV) {
        engine += ' exec-env/' + process.env.AWS_EXECUTION_ENV;
      }
      return engine;
    }
  },

  userAgent: function userAgent() {
    var name = util.environment;
    var agent = 'aws-sdk-' + name + '/' + (__webpack_require__(9132).VERSION);
    if (name === 'nodejs') agent += ' ' + util.engine();
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
    util.arrayEach(string.split('/'), function (part) {
      parts.push(util.uriEscape(part));
    });
    return parts.join('/');
  },

  urlParse: function urlParse(url) {
    return util.url.parse(url);
  },

  urlFormat: function urlFormat(url) {
    return util.url.format(url);
  },

  queryStringParse: function queryStringParse(qs) {
    return util.querystring.parse(qs);
  },

  queryParamsToString: function queryParamsToString(params) {
    var items = [];
    var escape = util.uriEscape;
    var sortedKeys = Object.keys(params).sort();

    util.arrayEach(sortedKeys, function(name) {
      var value = params[name];
      var ename = escape(name);
      var result = ename + '=';
      if (Array.isArray(value)) {
        var vals = [];
        util.arrayEach(value, function(item) { vals.push(escape(item)); });
        result = ename + '=' + vals.sort().join('&' + ename + '=');
      } else if (value !== undefined && value !== null) {
        result = ename + '=' + escape(value);
      }
      items.push(result);
    });

    return items.join('&');
  },

  readFileSync: function readFileSync(path) {
    if (util.isBrowser()) return null;
    return (__webpack_require__(9896).readFileSync)(path, 'utf-8');
  },

  base64: {
    encode: function encode64(string) {
      if (typeof string === 'number') {
        throw util.error(new Error('Cannot base64 encode number ' + string));
      }
      if (string === null || typeof string === 'undefined') {
        return string;
      }
      var buf = util.buffer.toBuffer(string);
      return buf.toString('base64');
    },

    decode: function decode64(string) {
      if (typeof string === 'number') {
        throw util.error(new Error('Cannot base64 decode number ' + string));
      }
      if (string === null || typeof string === 'undefined') {
        return string;
      }
      return util.buffer.toBuffer(string, 'base64');
    }

  },

  buffer: {
    /**
     * Buffer constructor for Node buffer and buffer pollyfill
     */
    toBuffer: function(data, encoding) {
      return (typeof util.Buffer.from === 'function' && util.Buffer.from !== Uint8Array.from) ?
        util.Buffer.from(data, encoding) : new util.Buffer(data, encoding);
    },

    alloc: function(size, fill, encoding) {
      if (typeof size !== 'number') {
        throw new Error('size passed to alloc must be a number.');
      }
      if (typeof util.Buffer.alloc === 'function') {
        return util.Buffer.alloc(size, fill, encoding);
      } else {
        var buf = new util.Buffer(size);
        if (fill !== undefined && typeof buf.fill === 'function') {
          buf.fill(fill, undefined, undefined, encoding);
        }
        return buf;
      }
    },

    toStream: function toStream(buffer) {
      if (!util.Buffer.isBuffer(buffer)) buffer =  util.buffer.toBuffer(buffer);

      var readable = new (util.stream.Readable)();
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
     */
    concat: function(buffers) {
      var length = 0,
          offset = 0,
          buffer = null, i;

      for (i = 0; i < buffers.length; i++) {
        length += buffers[i].length;
      }

      buffer = util.buffer.alloc(length);

      for (i = 0; i < buffers.length; i++) {
        buffers[i].copy(buffer, offset);
        offset += buffers[i].length;
      }

      return buffer;
    }
  },

  string: {
    byteLength: function byteLength(string) {
      if (string === null || string === undefined) return 0;
      if (typeof string === 'string') string = util.buffer.toBuffer(string);

      if (typeof string.byteLength === 'number') {
        return string.byteLength;
      } else if (typeof string.length === 'number') {
        return string.length;
      } else if (typeof string.size === 'number') {
        return string.size;
      } else if (typeof string.path === 'string') {
        return (__webpack_require__(9896).lstatSync)(string.path).size;
      } else {
        throw util.error(new Error('Cannot determine length of ' + string),
          { object: string });
      }
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
      util.arrayEach(ini.split(/\r?\n/), function(line) {
        line = line.split(/(^|\s)[;#]/)[0].trim(); // remove comments and trim
        var isSection = line[0] === '[' && line[line.length - 1] === ']';
        if (isSection) {
          currentSection = line.substring(1, line.length - 1);
          if (currentSection === '__proto__' || currentSection.split(/\s/)[1] === '__proto__') {
            throw util.error(
              new Error('Cannot load profile name \'' + currentSection + '\' from shared ini file.')
            );
          }
        } else if (currentSection) {
          var indexOfEqualsSign = line.indexOf('=');
          var start = 0;
          var end = line.length - 1;
          var isAssignment =
            indexOfEqualsSign !== -1 && indexOfEqualsSign !== start && indexOfEqualsSign !== end;

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
    callback: function (err) { if (err) throw err; },

    /**
     * Turn a synchronous function into as "async" function by making it call
     * a callback. The underlying function is called with all but the last argument,
     * which is treated as the callback. The callback is passed passed a first argument
     * of null on success to mimick standard node callbacks.
     */
    makeAsync: function makeAsync(fn, expectedArgs) {
      if (expectedArgs && expectedArgs <= fn.length) {
        return fn;
      }

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
   */
  date: {

    /**
     * @return [Date] the current JavaScript date object. Since all
     *   AWS services rely on this date object, you can override
     *   this function to provide a special time value to AWS service
     *   requests.
     */
    getDate: function getDate() {
      if (!AWS) AWS = __webpack_require__(9132);
      if (AWS.config.systemClockOffset) { // use offset when non-zero
        return new Date(new Date().getTime() + AWS.config.systemClockOffset);
      } else {
        return new Date();
      }
    },

    /**
     * @return [String] the date in ISO-8601 format
     */
    iso8601: function iso8601(date) {
      if (date === undefined) { date = util.date.getDate(); }
      return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
    },

    /**
     * @return [String] the date in RFC 822 format
     */
    rfc822: function rfc822(date) {
      if (date === undefined) { date = util.date.getDate(); }
      return date.toUTCString();
    },

    /**
     * @return [Integer] the UNIX timestamp value for the current time
     */
    unixTimestamp: function unixTimestamp(date) {
      if (date === undefined) { date = util.date.getDate(); }
      return date.getTime() / 1000;
    },

    /**
     * @param [String,number,Date] date
     * @return [Date]
     */
    from: function format(date) {
      if (typeof date === 'number') {
        return new Date(date * 1000); // unix timestamp
      } else {
        return new Date(date);
      }
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
     */
    format: function format(date, formatter) {
      if (!formatter) formatter = 'iso8601';
      return util.date[formatter](util.date.from(date));
    },

    parseTimestamp: function parseTimestamp(value) {
      if (typeof value === 'number') { // unix timestamp (number)
        return new Date(value * 1000);
      } else if (value.match(/^\d+$/)) { // unix timestamp
        return new Date(value * 1000);
      } else if (value.match(/^\d{4}/)) { // iso8601
        return new Date(value);
      } else if (value.match(/^\w{3},/)) { // rfc822
        return new Date(value);
      } else {
        throw util.error(
          new Error('unhandled timestamp format: ' + value),
          {code: 'TimestampParserError'});
      }
    }

  },

  crypto: {
    crc32Table: [
     0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419,
     0x706AF48F, 0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4,
     0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07,
     0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
     0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856,
     0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
     0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4,
     0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
     0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3,
     0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC, 0x51DE003A,
     0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599,
     0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
     0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190,
     0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
     0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E,
     0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
     0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED,
     0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
     0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3,
     0xFBD44C65, 0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
     0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A,
     0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5,
     0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA, 0xBE0B1010,
     0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
     0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17,
     0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6,
     0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615,
     0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
     0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344,
     0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
     0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A,
     0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
     0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1,
     0xA6BC5767, 0x3FB506DD, 0x48B2364B, 0xD80D2BDA, 0xAF0A1B4C,
     0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF,
     0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
     0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE,
     0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31,
     0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C,
     0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
     0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B,
     0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
     0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1,
     0x18B74777, 0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
     0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45, 0xA00AE278,
     0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7,
     0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66,
     0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
     0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605,
     0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8,
     0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B,
     0x2D02EF8D],

    crc32: function crc32(data) {
      var tbl = util.crypto.crc32Table;
      var crc = 0 ^ -1;

      if (typeof data === 'string') {
        data = util.buffer.toBuffer(data);
      }

      for (var i = 0; i < data.length; i++) {
        var code = data.readUInt8(i);
        crc = (crc >>> 8) ^ tbl[(crc ^ code) & 0xFF];
      }
      return (crc ^ -1) >>> 0;
    },

    hmac: function hmac(key, string, digest, fn) {
      if (!digest) digest = 'binary';
      if (digest === 'buffer') { digest = undefined; }
      if (!fn) fn = 'sha256';
      if (typeof string === 'string') string = util.buffer.toBuffer(string);
      return util.crypto.lib.createHmac(fn, key).update(string).digest(digest);
    },

    md5: function md5(data, digest, callback) {
      return util.crypto.hash('md5', data, digest, callback);
    },

    sha256: function sha256(data, digest, callback) {
      return util.crypto.hash('sha256', data, digest, callback);
    },

    hash: function(algorithm, data, digest, callback) {
      var hash = util.crypto.createHash(algorithm);
      if (!digest) { digest = 'binary'; }
      if (digest === 'buffer') { digest = undefined; }
      if (typeof data === 'string') data = util.buffer.toBuffer(data);
      var sliceFn = util.arraySliceFn(data);
      var isBuffer = util.Buffer.isBuffer(data);
      //Identifying objects with an ArrayBuffer as buffers
      if (util.isBrowser() && typeof ArrayBuffer !== 'undefined' && data && data.buffer instanceof ArrayBuffer) isBuffer = true;

      if (callback && typeof data === 'object' &&
          typeof data.on === 'function' && !isBuffer) {
        data.on('data', function(chunk) { hash.update(chunk); });
        data.on('error', function(err) { callback(err); });
        data.on('end', function() { callback(null, hash.digest(digest)); });
      } else if (callback && sliceFn && !isBuffer &&
                 typeof FileReader !== 'undefined') {
        // this might be a File/Blob
        var index = 0, size = 1024 * 512;
        var reader = new FileReader();
        reader.onerror = function() {
          callback(new Error('Failed to read data.'));
        };
        reader.onload = function() {
          var buf = new util.Buffer(new Uint8Array(reader.result));
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
        if (util.isBrowser() && typeof data === 'object' && !isBuffer) {
          data = new util.Buffer(new Uint8Array(data));
        }
        var out = hash.update(data).digest(digest);
        if (callback) callback(null, out);
        return out;
      }
    },

    toHex: function toHex(data) {
      var out = [];
      for (var i = 0; i < data.length; i++) {
        out.push(('0' + data.charCodeAt(i).toString(16)).substr(-2, 2));
      }
      return out.join('');
    },

    createHash: function createHash(algorithm) {
      return util.crypto.lib.createHash(algorithm);
    }

  },

  /** @!ignore */

  /* Abort constant */
  abort: {},

  each: function each(object, iterFunction) {
    for (var key in object) {
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        var ret = iterFunction.call(this, key, object[key]);
        if (ret === util.abort) break;
      }
    }
  },

  arrayEach: function arrayEach(array, iterFunction) {
    for (var idx in array) {
      if (Object.prototype.hasOwnProperty.call(array, idx)) {
        var ret = iterFunction.call(this, array[idx], parseInt(idx, 10));
        if (ret === util.abort) break;
      }
    }
  },

  update: function update(obj1, obj2) {
    util.each(obj2, function iterator(key, item) {
      obj1[key] = item;
    });
    return obj1;
  },

  merge: function merge(obj1, obj2) {
    return util.update(util.copy(obj1), obj2);
  },

  copy: function copy(object) {
    if (object === null || object === undefined) return object;
    var dupe = {};
    // jshint forin:false
    for (var key in object) {
      dupe[key] = object[key];
    }
    return dupe;
  },

  isEmpty: function isEmpty(obj) {
    for (var prop in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, prop)) {
        return false;
      }
    }
    return true;
  },

  arraySliceFn: function arraySliceFn(obj) {
    var fn = obj.slice || obj.webkitSlice || obj.mozSlice;
    return typeof fn === 'function' ? fn : null;
  },

  isType: function isType(obj, type) {
    // handle cross-"frame" objects
    if (typeof type === 'function') type = util.typeName(type);
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
      if (typeof options === 'string' || (options && options.message)) {
        originalError = util.copy(err);
        originalError.message = err.message;
      }
    }
    err.message = err.message || null;

    if (typeof options === 'string') {
      err.message = options;
    } else if (typeof options === 'object' && options !== null) {
      util.update(err, options);
      if (options.message)
        err.message = options.message;
      if (options.code || options.name)
        err.code = options.code || options.name;
      if (options.stack)
        err.stack = options.stack;
    }

    if (typeof Object.defineProperty === 'function') {
      Object.defineProperty(err, 'name', {writable: true, enumerable: false});
      Object.defineProperty(err, 'message', {enumerable: true});
    }

    err.name = String(options && options.name || err.name || err.code || 'Error');
    err.time = new Date();

    if (originalError) {
      err.originalError = originalError;
    }


    for (var key in options || {}) {
      if (key[0] === '[' && key[key.length - 1] === ']') {
        key = key.slice(1, -1);
        if (key === 'code' || key === 'message') {
          continue;
        }
        err['[' + key + ']'] = 'See error.' + key + ' for details.';
        Object.defineProperty(err, key, {
          value: err[key] || (options && options[key]) || (originalError && originalError[key]),
          enumerable: false,
          writable: true
        });
      }
    }

    return err;
  },

  /**
   * @api private
   */
  inherit: function inherit(klass, features) {
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
    if (features.constructor === Object) {
      features.constructor = function() {
        if (klass !== Object) {
          return klass.apply(this, arguments);
        }
      };
    }

    features.constructor.prototype = newObject;
    util.update(features.constructor.prototype, features);
    features.constructor.__super__ = klass;
    return features.constructor;
  },

  /**
   * @api private
   */
  mixin: function mixin() {
    var klass = arguments[0];
    for (var i = 1; i < arguments.length; i++) {
      // jshint forin:false
      for (var prop in arguments[i].prototype) {
        var fn = arguments[i].prototype[prop];
        if (prop !== 'constructor') {
          klass.prototype[prop] = fn;
        }
      }
    }
    return klass;
  },

  /**
   * @api private
   */
  hideProperties: function hideProperties(obj, props) {
    if (typeof Object.defineProperty !== 'function') return;

    util.arrayEach(props, function (key) {
      Object.defineProperty(obj, key, {
        enumerable: false, writable: true, configurable: true });
    });
  },

  /**
   * @api private
   */
  property: function property(obj, name, value, enumerable, isValue) {
    var opts = {
      configurable: true,
      enumerable: enumerable !== undefined ? enumerable : true
    };
    if (typeof value === 'function' && !isValue) {
      opts.get = value;
    }
    else {
      opts.value = value; opts.writable = true;
    }

    Object.defineProperty(obj, name, opts);
  },

  /**
   * @api private
   */
  memoizedProperty: function memoizedProperty(obj, name, get, enumerable) {
    var cachedValue = null;

    // build enumerable attribute for each value with lazy accessor.
    util.property(obj, name, function() {
      if (cachedValue === null) {
        cachedValue = get();
      }
      return cachedValue;
    }, enumerable);
  },

  /**
   * TODO Remove in major version revision
   * This backfill populates response data without the
   * top-level payload name.
   *
   * @api private
   */
  hoistPayloadMember: function hoistPayloadMember(resp) {
    var req = resp.request;
    var operationName = req.operation;
    var operation = req.service.api.operations[operationName];
    var output = operation.output;
    if (output.payload && !operation.hasEventOutput) {
      var payloadMember = output.members[output.payload];
      var responsePayload = resp.data[output.payload];
      if (payloadMember.type === 'structure') {
        util.each(responsePayload, function(key, value) {
          util.property(resp.data, key, value, false);
        });
      }
    }
  },

  /**
   * Compute SHA-256 checksums of streams
   *
   * @api private
   */
  computeSha256: function computeSha256(body, done) {
    if (util.isNode()) {
      var Stream = util.stream.Stream;
      var fs = __webpack_require__(9896);
      if (typeof Stream === 'function' && body instanceof Stream) {
        if (typeof body.path === 'string') { // assume file object
          var settings = {};
          if (typeof body.start === 'number') {
            settings.start = body.start;
          }
          if (typeof body.end === 'number') {
            settings.end = body.end;
          }
          body = fs.createReadStream(body.path, settings);
        } else { // TODO support other stream types
          return done(new Error('Non-file stream objects are ' +
                                'not supported with SigV4'));
        }
      }
    }

    util.crypto.sha256(body, 'hex', function(err, sha) {
      if (err) done(err);
      else done(null, sha);
    });
  },

  /**
   * @api private
   */
  isClockSkewed: function isClockSkewed(serverTime) {
    if (serverTime) {
      util.property(AWS.config, 'isClockSkewed',
        Math.abs(new Date().getTime() - serverTime) >= 300000, false);
      return AWS.config.isClockSkewed;
    }
  },

  applyClockOffset: function applyClockOffset(serverTime) {
    if (serverTime)
      AWS.config.systemClockOffset = serverTime - new Date().getTime();
  },

  /**
   * @api private
   */
  extractRequestId: function extractRequestId(resp) {
    var requestId = resp.httpResponse.headers['x-amz-request-id'] ||
                     resp.httpResponse.headers['x-amzn-requestid'];

    if (!requestId && resp.data && resp.data.ResponseMetadata) {
      requestId = resp.data.ResponseMetadata.RequestId;
    }

    if (requestId) {
      resp.requestId = requestId;
    }

    if (resp.error) {
      resp.error.requestId = requestId;
    }
  },

  /**
   * @api private
   */
  addPromises: function addPromises(constructors, PromiseDependency) {
    var deletePromises = false;
    if (PromiseDependency === undefined && AWS && AWS.config) {
      PromiseDependency = AWS.config.getPromisesDependency();
    }
    if (PromiseDependency === undefined && typeof Promise !== 'undefined') {
      PromiseDependency = Promise;
    }
    if (typeof PromiseDependency !== 'function') deletePromises = true;
    if (!Array.isArray(constructors)) constructors = [constructors];

    for (var ind = 0; ind < constructors.length; ind++) {
      var constructor = constructors[ind];
      if (deletePromises) {
        if (constructor.deletePromisesFromClass) {
          constructor.deletePromisesFromClass();
        }
      } else if (constructor.addPromisesToClass) {
        constructor.addPromisesToClass(PromiseDependency);
      }
    }
  },

  /**
   * @api private
   * Return a function that will return a promise whose fate is decided by the
   * callback behavior of the given method with `methodName`. The method to be
   * promisified should conform to node.js convention of accepting a callback as
   * last argument and calling that callback with error as the first argument
   * and success value on the second argument.
   */
  promisifyMethod: function promisifyMethod(methodName, PromiseDependency) {
    return function promise() {
      var self = this;
      var args = Array.prototype.slice.call(arguments);
      return new PromiseDependency(function(resolve, reject) {
        args.push(function(err, data) {
          if (err) {
            reject(err);
          } else {
            resolve(data);
          }
        });
        self[methodName].apply(self, args);
      });
    };
  },

  /**
   * @api private
   */
  isDualstackAvailable: function isDualstackAvailable(service) {
    if (!service) return false;
    var metadata = __webpack_require__(5087);
    if (typeof service !== 'string') service = service.serviceIdentifier;
    if (typeof service !== 'string' || !metadata.hasOwnProperty(service)) return false;
    return !!metadata[service].dualstackAvailable;
  },

  /**
   * @api private
   */
  calculateRetryDelay: function calculateRetryDelay(retryCount, retryDelayOptions, err) {
    if (!retryDelayOptions) retryDelayOptions = {};
    var customBackoff = retryDelayOptions.customBackoff || null;
    if (typeof customBackoff === 'function') {
      return customBackoff(retryCount, err);
    }
    var base = typeof retryDelayOptions.base === 'number' ? retryDelayOptions.base : 100;
    var delay = Math.random() * (Math.pow(2, retryCount) * base);
    return delay;
  },

  /**
   * @api private
   */
  handleRequestWithRetries: function handleRequestWithRetries(httpRequest, options, cb) {
    if (!options) options = {};
    var http = AWS.HttpClient.getInstance();
    var httpOptions = options.httpOptions || {};
    var retryCount = 0;

    var errCallback = function(err) {
      var maxRetries = options.maxRetries || 0;
      if (err && err.code === 'TimeoutError') err.retryable = true;

      // Call `calculateRetryDelay()` only when relevant, see #3401
      if (err && err.retryable && retryCount < maxRetries) {
        var delay = util.calculateRetryDelay(retryCount, options.retryDelayOptions, err);
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
        httpResponse.on('data', function(chunk) { data += chunk.toString(); });
        httpResponse.on('end', function() {
          var statusCode = httpResponse.statusCode;
          if (statusCode < 300) {
            cb(null, data);
          } else {
            var retryAfter = parseInt(httpResponse.headers['retry-after'], 10) * 1000 || 0;
            var err = util.error(new Error(),
              {
                statusCode: statusCode,
                retryable: statusCode >= 500 || statusCode === 429
              }
            );
            if (retryAfter && err.retryable) err.retryAfter = retryAfter;
            errCallback(err);
          }
        });
      }, errCallback);
    };

    AWS.util.defer(sendRequest);
  },

  /**
   * @api private
   */
  uuid: {
    v4: function uuidV4() {
      return (__webpack_require__(5137).v4)();
    }
  },

  /**
   * @api private
   */
  convertPayloadToString: function convertPayloadToString(resp) {
    var req = resp.request;
    var operation = req.operation;
    var rules = req.service.api.operations[operation].output || {};
    if (rules.payload && resp.data[rules.payload]) {
      resp.data[rules.payload] = resp.data[rules.payload].toString();
    }
  },

  /**
   * @api private
   */
  defer: function defer(callback) {
    if (typeof process === 'object' && typeof process.nextTick === 'function') {
      process.nextTick(callback);
    } else if (typeof setImmediate === 'function') {
      setImmediate(callback);
    } else {
      setTimeout(callback, 0);
    }
  },

  /**
   * @api private
   */
  getRequestPayloadShape: function getRequestPayloadShape(req) {
    var operations = req.service.api.operations;
    if (!operations) return undefined;
    var operation = (operations || {})[req.operation];
    if (!operation || !operation.input || !operation.input.payload) return undefined;
    return operation.input.members[operation.input.payload];
  },

  getProfilesFromSharedConfig: function getProfilesFromSharedConfig(iniLoader, filename) {
    var profiles = {};
    var profilesFromConfig = {};
    if (process.env[util.configOptInEnv]) {
      var profilesFromConfig = iniLoader.loadFrom({
        isConfig: true,
        filename: process.env[util.sharedConfigFileEnv]
      });
    }
    var profilesFromCreds= {};
    try {
      var profilesFromCreds = iniLoader.loadFrom({
        filename: filename ||
          (process.env[util.configOptInEnv] && process.env[util.sharedCredentialsFileEnv])
      });
    } catch (error) {
      // if using config, assume it is fully descriptive without a credentials file:
      if (!process.env[util.configOptInEnv]) throw error;
    }
    for (var i = 0, profileNames = Object.keys(profilesFromConfig); i < profileNames.length; i++) {
      profiles[profileNames[i]] = objectAssign(profiles[profileNames[i]] || {}, profilesFromConfig[profileNames[i]]);
    }
    for (var i = 0, profileNames = Object.keys(profilesFromCreds); i < profileNames.length; i++) {
      profiles[profileNames[i]] = objectAssign(profiles[profileNames[i]] || {}, profilesFromCreds[profileNames[i]]);
    }
    return profiles;

    /**
     * Roughly the semantics of `Object.assign(target, source)`
     */
    function objectAssign(target, source) {
      for (var i = 0, keys = Object.keys(source); i < keys.length; i++) {
        target[keys[i]] = source[keys[i]];
      }
      return target;
    }
  },

  /**
   * @api private
   */
  ARN: {
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
      if (
        arnObject.service === undefined ||
        arnObject.region === undefined ||
        arnObject.accountId === undefined ||
        arnObject.resource === undefined
      ) throw util.error(new Error('Input ARN object is invalid'));
      return 'arn:'+ (arnObject.partition || 'aws') + ':' + arnObject.service +
        ':' + arnObject.region + ':' + arnObject.accountId + ':' + arnObject.resource;
    }
  },

  /**
   * @api private
   */
  defaultProfile: 'default',

  /**
   * @api private
   */
  configOptInEnv: 'AWS_SDK_LOAD_CONFIG',

  /**
   * @api private
   */
  sharedCredentialsFileEnv: 'AWS_SHARED_CREDENTIALS_FILE',

  /**
   * @api private
   */
  sharedConfigFileEnv: 'AWS_CONFIG_FILE',

  /**
   * @api private
   */
  imdsDisabledEnv: 'AWS_EC2_METADATA_DISABLED'
};

/**
 * @api private
 */
module.exports = util;


/***/ },

/***/ 1838
(module, __unused_webpack_exports, __webpack_require__) {

var util = __webpack_require__(9019);
var XmlNode = (__webpack_require__(4533).XmlNode);
var XmlText = (__webpack_require__(7710).XmlText);

function XmlBuilder() { }

XmlBuilder.prototype.toXML = function(params, shape, rootElement, noEmpty) {
  var xml = new XmlNode(rootElement);
  applyNamespaces(xml, shape, true);
  serialize(xml, params, shape);
  return xml.children.length > 0 || noEmpty ? xml.toString() : '';
};

function serialize(xml, value, shape) {
  switch (shape.type) {
    case 'structure': return serializeStructure(xml, value, shape);
    case 'map': return serializeMap(xml, value, shape);
    case 'list': return serializeList(xml, value, shape);
    default: return serializeScalar(xml, value, shape);
  }
}

function serializeStructure(xml, params, shape) {
  util.arrayEach(shape.memberNames, function(memberName) {
    var memberShape = shape.members[memberName];
    if (memberShape.location !== 'body') return;

    var value = params[memberName];
    var name = memberShape.name;
    if (value !== undefined && value !== null) {
      if (memberShape.isXmlAttribute) {
        xml.addAttribute(name, value);
      } else if (memberShape.flattened) {
        serialize(xml, value, memberShape);
      } else {
        var element = new XmlNode(name);
        xml.addChildNode(element);
        applyNamespaces(element, memberShape);
        serialize(element, value, memberShape);
      }
    }
  });
}

function serializeMap(xml, map, shape) {
  var xmlKey = shape.key.name || 'key';
  var xmlValue = shape.value.name || 'value';

  util.each(map, function(key, value) {
    var entry = new XmlNode(shape.flattened ? shape.name : 'entry');
    xml.addChildNode(entry);

    var entryKey = new XmlNode(xmlKey);
    var entryValue = new XmlNode(xmlValue);
    entry.addChildNode(entryKey);
    entry.addChildNode(entryValue);

    serialize(entryKey, key, shape.key);
    serialize(entryValue, value, shape.value);
  });
}

function serializeList(xml, list, shape) {
  if (shape.flattened) {
    util.arrayEach(list, function(value) {
      var name = shape.member.name || shape.name;
      var element = new XmlNode(name);
      xml.addChildNode(element);
      serialize(element, value, shape.member);
    });
  } else {
    util.arrayEach(list, function(value) {
      var name = shape.member.name || 'member';
      var element = new XmlNode(name);
      xml.addChildNode(element);
      serialize(element, value, shape.member);
    });
  }
}

function serializeScalar(xml, value, shape) {
  xml.addChildNode(
    new XmlText(shape.toWireFormat(value))
  );
}

function applyNamespaces(xml, shape, isRoot) {
  var uri, prefix = 'xmlns';
  if (shape.xmlNamespaceUri) {
    uri = shape.xmlNamespaceUri;
    if (shape.xmlNamespacePrefix) prefix += ':' + shape.xmlNamespacePrefix;
  } else if (isRoot && shape.api.xmlNamespaceUri) {
    uri = shape.api.xmlNamespaceUri;
  }

  if (uri) xml.addAttribute(prefix, uri);
}

/**
 * @api private
 */
module.exports = XmlBuilder;


/***/ },

/***/ 4735
(module) {

/**
 * Escapes characters that can not be in an XML attribute.
 */
function escapeAttribute(value) {
    return value.replace(/&/g, '&amp;').replace(/'/g, '&apos;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * @api private
 */
module.exports = {
    escapeAttribute: escapeAttribute
};


/***/ },

/***/ 4215
(module) {

/**
 * Escapes characters that can not be in an XML element.
 */
function escapeElement(value) {
    return value.replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/\r/g, '&#x0D;')
                .replace(/\n/g, '&#x0A;')
                .replace(/\u0085/g, '&#x85;')
                .replace(/\u2028/, '&#x2028;');
}

/**
 * @api private
 */
module.exports = {
    escapeElement: escapeElement
};


/***/ },

/***/ 6627
(module, __unused_webpack_exports, __webpack_require__) {

var AWS = __webpack_require__(9132);
var util = AWS.util;
var Shape = AWS.Model.Shape;

var xml2js = __webpack_require__(8805);

/**
 * @api private
 */
var options = {  // options passed to xml2js parser
  explicitCharkey: false, // undocumented
  trim: false,            // trim the leading/trailing whitespace from text nodes
  normalize: false,       // trim interior whitespace inside text nodes
  explicitRoot: false,    // return the root node in the resulting object?
  emptyTag: null,         // the default value for empty nodes
  explicitArray: true,    // always put child nodes in an array
  ignoreAttrs: false,     // ignore attributes, only create text nodes
  mergeAttrs: false,      // merge attributes and child elements
  validator: null         // a callable validator
};

function NodeXmlParser() { }

NodeXmlParser.prototype.parse = function(xml, shape) {
  shape = shape || {};

  var result = null;
  var error = null;

  var parser = new xml2js.Parser(options);
  parser.parseString(xml, function (e, r) {
    error = e;
    result = r;
  });

  if (result) {
    var data = parseXml(result, shape);
    if (result.ResponseMetadata) {
      data.ResponseMetadata = parseXml(result.ResponseMetadata[0], {});
    }
    return data;
  } else if (error) {
    throw util.error(error, {code: 'XMLParserError', retryable: true});
  } else { // empty xml document
    return parseXml({}, shape);
  }
};

function parseXml(xml, shape) {
  switch (shape.type) {
    case 'structure': return parseStructure(xml, shape);
    case 'map': return parseMap(xml, shape);
    case 'list': return parseList(xml, shape);
    case undefined: case null: return parseUnknown(xml);
    default: return parseScalar(xml, shape);
  }
}

function parseStructure(xml, shape) {
  var data = {};
  if (xml === null) return data;

  util.each(shape.members, function(memberName, memberShape) {
    var xmlName = memberShape.name;
    if (Object.prototype.hasOwnProperty.call(xml, xmlName) && Array.isArray(xml[xmlName])) {
      var xmlChild = xml[xmlName];
      if (!memberShape.flattened) xmlChild = xmlChild[0];

      data[memberName] = parseXml(xmlChild, memberShape);
    } else if (memberShape.isXmlAttribute &&
               xml.$ && Object.prototype.hasOwnProperty.call(xml.$, xmlName)) {
      data[memberName] = parseScalar(xml.$[xmlName], memberShape);
    } else if (memberShape.type === 'list' && !shape.api.xmlNoDefaultLists) {
      data[memberName] = memberShape.defaultValue;
    }
  });

  return data;
}

function parseMap(xml, shape) {
  var data = {};
  if (xml === null) return data;

  var xmlKey = shape.key.name || 'key';
  var xmlValue = shape.value.name || 'value';
  var iterable = shape.flattened ? xml : xml.entry;

  if (Array.isArray(iterable)) {
    util.arrayEach(iterable, function(child) {
      data[child[xmlKey][0]] = parseXml(child[xmlValue][0], shape.value);
    });
  }

  return data;
}

function parseList(xml, shape) {
  var data = [];
  var name = shape.member.name || 'member';
  if (shape.flattened) {
    util.arrayEach(xml, function(xmlChild) {
      data.push(parseXml(xmlChild, shape.member));
    });
  } else if (xml && Array.isArray(xml[name])) {
    util.arrayEach(xml[name], function(child) {
      data.push(parseXml(child, shape.member));
    });
  }

  return data;
}

function parseScalar(text, shape) {
  if (text && text.$ && text.$.encoding === 'base64') {
    shape = new Shape.create({type: text.$.encoding});
  }
  if (text && text._) text = text._;

  if (typeof shape.toType === 'function') {
    return shape.toType(text);
  } else {
    return text;
  }
}

function parseUnknown(xml) {
  if (xml === undefined || xml === null) return '';
  if (typeof xml === 'string') return xml;

  // parse a list
  if (Array.isArray(xml)) {
    var arr = [];
    for (i = 0; i < xml.length; i++) {
      arr.push(parseXml(xml[i], {}));
    }
    return arr;
  }

  // empty object
  var keys = Object.keys(xml), i;
  if (keys.length === 0 || (keys.length === 1 && keys[0] === '$')) {
    return {};
  }

  // object, parse as structure
  var data = {};
  for (i = 0; i < keys.length; i++) {
    var key = keys[i], value = xml[key];
    if (key === '$') continue;
    if (value.length > 1) { // this member is a list
      data[key] = parseList(value, {member: {}});
    } else { // this member is a single item
      data[key] = parseXml(value[0], {});
    }
  }
  return data;
}

/**
 * @api private
 */
module.exports = NodeXmlParser;


/***/ },

/***/ 4533
(module, __unused_webpack_exports, __webpack_require__) {

var escapeAttribute = (__webpack_require__(4735).escapeAttribute);

/**
 * Represents an XML node.
 * @api private
 */
function XmlNode(name, children) {
    if (children === void 0) { children = []; }
    this.name = name;
    this.children = children;
    this.attributes = {};
}
XmlNode.prototype.addAttribute = function (name, value) {
    this.attributes[name] = value;
    return this;
};
XmlNode.prototype.addChildNode = function (child) {
    this.children.push(child);
    return this;
};
XmlNode.prototype.removeAttribute = function (name) {
    delete this.attributes[name];
    return this;
};
XmlNode.prototype.toString = function () {
    var hasChildren = Boolean(this.children.length);
    var xmlText = '<' + this.name;
    // add attributes
    var attributes = this.attributes;
    for (var i = 0, attributeNames = Object.keys(attributes); i < attributeNames.length; i++) {
        var attributeName = attributeNames[i];
        var attribute = attributes[attributeName];
        if (typeof attribute !== 'undefined' && attribute !== null) {
            xmlText += ' ' + attributeName + '=\"' + escapeAttribute('' + attribute) + '\"';
        }
    }
    return xmlText += !hasChildren ? '/>' : '>' + this.children.map(function (c) { return c.toString(); }).join('') + '</' + this.name + '>';
};

/**
 * @api private
 */
module.exports = {
    XmlNode: XmlNode
};


/***/ },

/***/ 7710
(module, __unused_webpack_exports, __webpack_require__) {

var escapeElement = (__webpack_require__(4215).escapeElement);

/**
 * Represents an XML text value.
 * @api private
 */
function XmlText(value) {
    this.value = value;
}

XmlText.prototype.toString = function () {
    return escapeElement('' + this.value);
};

/**
 * @api private
 */
module.exports = {
    XmlText: XmlText
};


/***/ },

/***/ 1592
(__unused_webpack_module, exports) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
var byteToHex = [];

for (var i = 0; i < 256; ++i) {
  byteToHex[i] = (i + 0x100).toString(16).substr(1);
}

function bytesToUuid(buf, offset) {
  var i = offset || 0;
  var bth = byteToHex; // join used to fix memory issue caused by concatenation: https://bugs.chromium.org/p/v8/issues/detail?id=3175#c4

  return [bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], '-', bth[buf[i++]], bth[buf[i++]], '-', bth[buf[i++]], bth[buf[i++]], '-', bth[buf[i++]], bth[buf[i++]], '-', bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], bth[buf[i++]]].join('');
}

var _default = bytesToUuid;
exports["default"] = _default;

/***/ },

/***/ 5137
(__unused_webpack_module, exports, __webpack_require__) {

var __webpack_unused_export__;


__webpack_unused_export__ = ({
  value: true
});
__webpack_unused_export__ = ({
  enumerable: true,
  get: function () {
    return _v.default;
  }
});
__webpack_unused_export__ = ({
  enumerable: true,
  get: function () {
    return _v2.default;
  }
});
Object.defineProperty(exports, "v4", ({
  enumerable: true,
  get: function () {
    return _v3.default;
  }
}));
__webpack_unused_export__ = ({
  enumerable: true,
  get: function () {
    return _v4.default;
  }
});

var _v = _interopRequireDefault(__webpack_require__(3724));

var _v2 = _interopRequireDefault(__webpack_require__(2694));

var _v3 = _interopRequireDefault(__webpack_require__(1223));

var _v4 = _interopRequireDefault(__webpack_require__(1504));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/***/ },

/***/ 5533
(__unused_webpack_module, exports, __webpack_require__) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__webpack_require__(6982));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('md5').update(bytes).digest();
}

var _default = md5;
exports["default"] = _default;

/***/ },

/***/ 9148
(__unused_webpack_module, exports, __webpack_require__) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = rng;

var _crypto = _interopRequireDefault(__webpack_require__(6982));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function rng() {
  return _crypto.default.randomBytes(16);
}

/***/ },

/***/ 680
(__unused_webpack_module, exports, __webpack_require__) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _crypto = _interopRequireDefault(__webpack_require__(6982));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === 'string') {
    bytes = Buffer.from(bytes, 'utf8');
  }

  return _crypto.default.createHash('sha1').update(bytes).digest();
}

var _default = sha1;
exports["default"] = _default;

/***/ },

/***/ 3724
(__unused_webpack_module, exports, __webpack_require__) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__webpack_require__(9148));

var _bytesToUuid = _interopRequireDefault(__webpack_require__(1592));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html
var _nodeId;

var _clockseq; // Previous uuid creation time


var _lastMSecs = 0;
var _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

function v1(options, buf, offset) {
  var i = buf && offset || 0;
  var b = buf || [];
  options = options || {};
  var node = options.node || _nodeId;
  var clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189

  if (node == null || clockseq == null) {
    var seedBytes = options.random || (options.rng || _rng.default)();

    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }

    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


  var msecs = options.msecs !== undefined ? options.msecs : new Date().getTime(); // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock

  var nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

  var dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval


  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  } // Per 4.2.1.2 Throw error if too many uuids are requested


  if (nsecs >= 10000) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

  msecs += 12219292800000; // `time_low`

  var tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff; // `time_mid`

  var tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff; // `time_high_and_version`

  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

  b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

  b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

  b[i++] = clockseq & 0xff; // `node`

  for (var n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf ? buf : (0, _bytesToUuid.default)(b);
}

var _default = v1;
exports["default"] = _default;

/***/ },

/***/ 2694
(__unused_webpack_module, exports, __webpack_require__) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__webpack_require__(1311));

var _md = _interopRequireDefault(__webpack_require__(5533));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v3 = (0, _v.default)('v3', 0x30, _md.default);
var _default = v3;
exports["default"] = _default;

/***/ },

/***/ 1311
(__unused_webpack_module, exports, __webpack_require__) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = _default;
exports.URL = exports.DNS = void 0;

var _bytesToUuid = _interopRequireDefault(__webpack_require__(1592));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function uuidToBytes(uuid) {
  // Note: We assume we're being passed a valid uuid string
  var bytes = [];
  uuid.replace(/[a-fA-F0-9]{2}/g, function (hex) {
    bytes.push(parseInt(hex, 16));
  });
  return bytes;
}

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  var bytes = new Array(str.length);

  for (var i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }

  return bytes;
}

const DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
exports.DNS = DNS;
const URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
exports.URL = URL;

function _default(name, version, hashfunc) {
  var generateUUID = function (value, namespace, buf, offset) {
    var off = buf && offset || 0;
    if (typeof value == 'string') value = stringToBytes(value);
    if (typeof namespace == 'string') namespace = uuidToBytes(namespace);
    if (!Array.isArray(value)) throw TypeError('value must be an array of bytes');
    if (!Array.isArray(namespace) || namespace.length !== 16) throw TypeError('namespace must be uuid string or an Array of 16 byte values'); // Per 4.3

    var bytes = hashfunc(namespace.concat(value));
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      for (var idx = 0; idx < 16; ++idx) {
        buf[off + idx] = bytes[idx];
      }
    }

    return buf || (0, _bytesToUuid.default)(bytes);
  }; // Function#name is not settable on some platforms (#270)


  try {
    generateUUID.name = name;
  } catch (err) {} // For CommonJS default export support


  generateUUID.DNS = DNS;
  generateUUID.URL = URL;
  return generateUUID;
}

/***/ },

/***/ 1223
(__unused_webpack_module, exports, __webpack_require__) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _rng = _interopRequireDefault(__webpack_require__(9148));

var _bytesToUuid = _interopRequireDefault(__webpack_require__(1592));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function v4(options, buf, offset) {
  var i = buf && offset || 0;

  if (typeof options == 'string') {
    buf = options === 'binary' ? new Array(16) : null;
    options = null;
  }

  options = options || {};

  var rnds = options.random || (options.rng || _rng.default)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`


  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    for (var ii = 0; ii < 16; ++ii) {
      buf[i + ii] = rnds[ii];
    }
  }

  return buf || (0, _bytesToUuid.default)(rnds);
}

var _default = v4;
exports["default"] = _default;

/***/ },

/***/ 1504
(__unused_webpack_module, exports, __webpack_require__) {



Object.defineProperty(exports, "__esModule", ({
  value: true
}));
exports["default"] = void 0;

var _v = _interopRequireDefault(__webpack_require__(1311));

var _sha = _interopRequireDefault(__webpack_require__(680));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const v5 = (0, _v.default)('v5', 0x50, _sha.default);
var _default = v5;
exports["default"] = _default;

/***/ },

/***/ 5593
(__unused_webpack_module, exports, __webpack_require__) {

var __webpack_unused_export__;

__webpack_unused_export__ = ({ value: true });
var LRU_1 = __webpack_require__(8278);
var CACHE_SIZE = 1000;
/**
 * Inspired node-lru-cache[https://github.com/isaacs/node-lru-cache]
 */
var EndpointCache = /** @class */ (function () {
    function EndpointCache(maxSize) {
        if (maxSize === void 0) { maxSize = CACHE_SIZE; }
        this.maxSize = maxSize;
        this.cache = new LRU_1.LRUCache(maxSize);
    }
    ;
    Object.defineProperty(EndpointCache.prototype, "size", {
        get: function () {
            return this.cache.length;
        },
        enumerable: true,
        configurable: true
    });
    EndpointCache.prototype.put = function (key, value) {
      var keyString = typeof key !== 'string' ? EndpointCache.getKeyString(key) : key;
        var endpointRecord = this.populateValue(value);
        this.cache.put(keyString, endpointRecord);
    };
    EndpointCache.prototype.get = function (key) {
      var keyString = typeof key !== 'string' ? EndpointCache.getKeyString(key) : key;
        var now = Date.now();
        var records = this.cache.get(keyString);
        if (records) {
            for (var i = records.length-1; i >= 0; i--) {
                var record = records[i];
                if (record.Expire < now) {
                    records.splice(i, 1);
                }
            }
            if (records.length === 0) {
                this.cache.remove(keyString);
                return undefined;
            }
        }
        return records;
    };
    EndpointCache.getKeyString = function (key) {
        var identifiers = [];
        var identifierNames = Object.keys(key).sort();
        for (var i = 0; i < identifierNames.length; i++) {
            var identifierName = identifierNames[i];
            if (key[identifierName] === undefined)
                continue;
            identifiers.push(key[identifierName]);
        }
        return identifiers.join(' ');
    };
    EndpointCache.prototype.populateValue = function (endpoints) {
        var now = Date.now();
        return endpoints.map(function (endpoint) { return ({
            Address: endpoint.Address || '',
            Expire: now + (endpoint.CachePeriodInMinutes || 1) * 60 * 1000
        }); });
    };
    EndpointCache.prototype.empty = function () {
        this.cache.empty();
    };
    EndpointCache.prototype.remove = function (key) {
      var keyString = typeof key !== 'string' ? EndpointCache.getKeyString(key) : key;
        this.cache.remove(keyString);
    };
    return EndpointCache;
}());
exports.k = EndpointCache;

/***/ },

/***/ 8278
(__unused_webpack_module, exports) {


Object.defineProperty(exports, "__esModule", ({ value: true }));
var LinkedListNode = /** @class */ (function () {
    function LinkedListNode(key, value) {
        this.key = key;
        this.value = value;
    }
    return LinkedListNode;
}());
var LRUCache = /** @class */ (function () {
    function LRUCache(size) {
        this.nodeMap = {};
        this.size = 0;
        if (typeof size !== 'number' || size < 1) {
            throw new Error('Cache size can only be positive number');
        }
        this.sizeLimit = size;
    }
    Object.defineProperty(LRUCache.prototype, "length", {
        get: function () {
            return this.size;
        },
        enumerable: true,
        configurable: true
    });
    LRUCache.prototype.prependToList = function (node) {
        if (!this.headerNode) {
            this.tailNode = node;
        }
        else {
            this.headerNode.prev = node;
            node.next = this.headerNode;
        }
        this.headerNode = node;
        this.size++;
    };
    LRUCache.prototype.removeFromTail = function () {
        if (!this.tailNode) {
            return undefined;
        }
        var node = this.tailNode;
        var prevNode = node.prev;
        if (prevNode) {
            prevNode.next = undefined;
        }
        node.prev = undefined;
        this.tailNode = prevNode;
        this.size--;
        return node;
    };
    LRUCache.prototype.detachFromList = function (node) {
        if (this.headerNode === node) {
            this.headerNode = node.next;
        }
        if (this.tailNode === node) {
            this.tailNode = node.prev;
        }
        if (node.prev) {
            node.prev.next = node.next;
        }
        if (node.next) {
            node.next.prev = node.prev;
        }
        node.next = undefined;
        node.prev = undefined;
        this.size--;
    };
    LRUCache.prototype.get = function (key) {
        if (this.nodeMap[key]) {
            var node = this.nodeMap[key];
            this.detachFromList(node);
            this.prependToList(node);
            return node.value;
        }
    };
    LRUCache.prototype.remove = function (key) {
        if (this.nodeMap[key]) {
            var node = this.nodeMap[key];
            this.detachFromList(node);
            delete this.nodeMap[key];
        }
    };
    LRUCache.prototype.put = function (key, value) {
        if (this.nodeMap[key]) {
            this.remove(key);
        }
        else if (this.size === this.sizeLimit) {
            var tailNode = this.removeFromTail();
            var key_1 = tailNode.key;
            delete this.nodeMap[key_1];
        }
        var newNode = new LinkedListNode(key, value);
        this.nodeMap[key] = newNode;
        this.prependToList(newNode);
    };
    LRUCache.prototype.empty = function () {
        var keys = Object.keys(this.nodeMap);
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            var node = this.nodeMap[key];
            this.detachFromList(node);
            delete this.nodeMap[key];
        }
    };
    return LRUCache;
}());
exports.LRUCache = LRUCache;

/***/ },

/***/ 7533
(__unused_webpack_module, exports) {

(function(exports) {
  "use strict";

  function isArray(obj) {
    if (obj !== null) {
      return Object.prototype.toString.call(obj) === "[object Array]";
    } else {
      return false;
    }
  }

  function isObject(obj) {
    if (obj !== null) {
      return Object.prototype.toString.call(obj) === "[object Object]";
    } else {
      return false;
    }
  }

  function strictDeepEqual(first, second) {
    // Check the scalar case first.
    if (first === second) {
      return true;
    }

    // Check if they are the same type.
    var firstType = Object.prototype.toString.call(first);
    if (firstType !== Object.prototype.toString.call(second)) {
      return false;
    }
    // We know that first and second have the same type so we can just check the
    // first type from now on.
    if (isArray(first) === true) {
      // Short circuit if they're not the same length;
      if (first.length !== second.length) {
        return false;
      }
      for (var i = 0; i < first.length; i++) {
        if (strictDeepEqual(first[i], second[i]) === false) {
          return false;
        }
      }
      return true;
    }
    if (isObject(first) === true) {
      // An object is equal if it has the same key/value pairs.
      var keysSeen = {};
      for (var key in first) {
        if (hasOwnProperty.call(first, key)) {
          if (strictDeepEqual(first[key], second[key]) === false) {
            return false;
          }
          keysSeen[key] = true;
        }
      }
      // Now check that there aren't any keys in second that weren't
      // in first.
      for (var key2 in second) {
        if (hasOwnProperty.call(second, key2)) {
          if (keysSeen[key2] !== true) {
            return false;
          }
        }
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
    if (obj === "" || obj === false || obj === null) {
        return true;
    } else if (isArray(obj) && obj.length === 0) {
        // Check for an empty array.
        return true;
    } else if (isObject(obj)) {
        // Check for an empty object.
        for (var key in obj) {
            // If there are any keys, then
            // the object is not empty so the object
            // is not false.
            if (obj.hasOwnProperty(key)) {
              return false;
            }
        }
        return true;
    } else {
        return false;
    }
  }

  function objValues(obj) {
    var keys = Object.keys(obj);
    var values = [];
    for (var i = 0; i < keys.length; i++) {
      values.push(obj[keys[i]]);
    }
    return values;
  }

  function merge(a, b) {
      var merged = {};
      for (var key in a) {
          merged[key] = a[key];
      }
      for (var key2 in b) {
          merged[key2] = b[key2];
      }
      return merged;
  }

  var trimLeft;
  if (typeof String.prototype.trimLeft === "function") {
    trimLeft = function(str) {
      return str.trimLeft();
    };
  } else {
    trimLeft = function(str) {
      return str.match(/^\s*(.*)/)[1];
    };
  }

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
  var TOK_LPAREN= "Lparen";
  var TOK_LITERAL= "Literal";

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
      return (ch >= "a" && ch <= "z") ||
             (ch >= "A" && ch <= "Z") ||
             ch === "_";
  }

  function isNum(ch) {
      return (ch >= "0" && ch <= "9") ||
             ch === "-";
  }
  function isAlphaNum(ch) {
      return (ch >= "a" && ch <= "z") ||
             (ch >= "A" && ch <= "Z") ||
             (ch >= "0" && ch <= "9") ||
             ch === "_";
  }

  function Lexer() {
  }
  Lexer.prototype = {
      tokenize: function(stream) {
          var tokens = [];
          this._current = 0;
          var start;
          var identifier;
          var token;
          while (this._current < stream.length) {
              if (isAlpha(stream[this._current])) {
                  start = this._current;
                  identifier = this._consumeUnquotedIdentifier(stream);
                  tokens.push({type: TOK_UNQUOTEDIDENTIFIER,
                               value: identifier,
                               start: start});
              } else if (basicTokens[stream[this._current]] !== undefined) {
                  tokens.push({type: basicTokens[stream[this._current]],
                              value: stream[this._current],
                              start: this._current});
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
                  tokens.push({type: TOK_QUOTEDIDENTIFIER,
                               value: identifier,
                               start: start});
              } else if (stream[this._current] === "'") {
                  start = this._current;
                  identifier = this._consumeRawStringLiteral(stream);
                  tokens.push({type: TOK_LITERAL,
                               value: identifier,
                               start: start});
              } else if (stream[this._current] === "`") {
                  start = this._current;
                  var literal = this._consumeLiteral(stream);
                  tokens.push({type: TOK_LITERAL,
                               value: literal,
                               start: start});
              } else if (operatorStartToken[stream[this._current]] !== undefined) {
                  tokens.push(this._consumeOperator(stream));
              } else if (skipChars[stream[this._current]] !== undefined) {
                  // Ignore whitespace.
                  this._current++;
              } else if (stream[this._current] === "&") {
                  start = this._current;
                  this._current++;
                  if (stream[this._current] === "&") {
                      this._current++;
                      tokens.push({type: TOK_AND, value: "&&", start: start});
                  } else {
                      tokens.push({type: TOK_EXPREF, value: "&", start: start});
                  }
              } else if (stream[this._current] === "|") {
                  start = this._current;
                  this._current++;
                  if (stream[this._current] === "|") {
                      this._current++;
                      tokens.push({type: TOK_OR, value: "||", start: start});
                  } else {
                      tokens.push({type: TOK_PIPE, value: "|", start: start});
                  }
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
          while (this._current < stream.length && isAlphaNum(stream[this._current])) {
              this._current++;
          }
          return stream.slice(start, this._current);
      },

      _consumeQuotedIdentifier: function(stream) {
          var start = this._current;
          this._current++;
          var maxLength = stream.length;
          while (stream[this._current] !== "\"" && this._current < maxLength) {
              // You can escape a double quote and you can escape an escape.
              var current = this._current;
              if (stream[current] === "\\" && (stream[current + 1] === "\\" ||
                                               stream[current + 1] === "\"")) {
                  current += 2;
              } else {
                  current++;
              }
              this._current = current;
          }
          this._current++;
          return JSON.parse(stream.slice(start, this._current));
      },

      _consumeRawStringLiteral: function(stream) {
          var start = this._current;
          this._current++;
          var maxLength = stream.length;
          while (stream[this._current] !== "'" && this._current < maxLength) {
              // You can escape a single quote and you can escape an escape.
              var current = this._current;
              if (stream[current] === "\\" && (stream[current + 1] === "\\" ||
                                               stream[current + 1] === "'")) {
                  current += 2;
              } else {
                  current++;
              }
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
          while (isNum(stream[this._current]) && this._current < maxLength) {
              this._current++;
          }
          var value = parseInt(stream.slice(start, this._current));
          return {type: TOK_NUMBER, value: value, start: start};
      },

      _consumeLBracket: function(stream) {
          var start = this._current;
          this._current++;
          if (stream[this._current] === "?") {
              this._current++;
              return {type: TOK_FILTER, value: "[?", start: start};
          } else if (stream[this._current] === "]") {
              this._current++;
              return {type: TOK_FLATTEN, value: "[]", start: start};
          } else {
              return {type: TOK_LBRACKET, value: "[", start: start};
          }
      },

      _consumeOperator: function(stream) {
          var start = this._current;
          var startingChar = stream[start];
          this._current++;
          if (startingChar === "!") {
              if (stream[this._current] === "=") {
                  this._current++;
                  return {type: TOK_NE, value: "!=", start: start};
              } else {
                return {type: TOK_NOT, value: "!", start: start};
              }
          } else if (startingChar === "<") {
              if (stream[this._current] === "=") {
                  this._current++;
                  return {type: TOK_LTE, value: "<=", start: start};
              } else {
                  return {type: TOK_LT, value: "<", start: start};
              }
          } else if (startingChar === ">") {
              if (stream[this._current] === "=") {
                  this._current++;
                  return {type: TOK_GTE, value: ">=", start: start};
              } else {
                  return {type: TOK_GT, value: ">", start: start};
              }
          } else if (startingChar === "=") {
              if (stream[this._current] === "=") {
                  this._current++;
                  return {type: TOK_EQ, value: "==", start: start};
              }
          }
      },

      _consumeLiteral: function(stream) {
          this._current++;
          var start = this._current;
          var maxLength = stream.length;
          var literal;
          while(stream[this._current] !== "`" && this._current < maxLength) {
              // You can escape a literal char or you can escape the escape.
              var current = this._current;
              if (stream[current] === "\\" && (stream[current + 1] === "\\" ||
                                               stream[current + 1] === "`")) {
                  current += 2;
              } else {
                  current++;
              }
              this._current = current;
          }
          var literalString = trimLeft(stream.slice(start, this._current));
          literalString = literalString.replace("\\`", "`");
          if (this._looksLikeJSON(literalString)) {
              literal = JSON.parse(literalString);
          } else {
              // Try to JSON parse it as "<literal>"
              literal = JSON.parse("\"" + literalString + "\"");
          }
          // +1 gets us to the ending "`", +1 to move on to the next char.
          this._current++;
          return literal;
      },

      _looksLikeJSON: function(literalString) {
          var startingChars = "[{\"";
          var jsonLiterals = ["true", "false", "null"];
          var numberLooking = "-0123456789";

          if (literalString === "") {
              return false;
          } else if (startingChars.indexOf(literalString[0]) >= 0) {
              return true;
          } else if (jsonLiterals.indexOf(literalString) >= 0) {
              return true;
          } else if (numberLooking.indexOf(literalString[0]) >= 0) {
              try {
                  JSON.parse(literalString);
                  return true;
              } catch (ex) {
                  return false;
              }
          } else {
              return false;
          }
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

  function Parser() {
  }

  Parser.prototype = {
      parse: function(expression) {
          this._loadTokens(expression);
          this.index = 0;
          var ast = this.expression(0);
          if (this._lookahead(0) !== TOK_EOF) {
              var t = this._lookaheadToken(0);
              var error = new Error(
                  "Unexpected token type: " + t.type + ", value: " + t.value);
              error.name = "ParserError";
              throw error;
          }
          return ast;
      },

      _loadTokens: function(expression) {
          var lexer = new Lexer();
          var tokens = lexer.tokenize(expression);
          tokens.push({type: TOK_EOF, value: "", start: expression.length});
          this.tokens = tokens;
      },

      expression: function(rbp) {
          var leftToken = this._lookaheadToken(0);
          this._advance();
          var left = this.nud(leftToken);
          var currentToken = this._lookahead(0);
          while (rbp < bindingPower[currentToken]) {
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
        switch (token.type) {
          case TOK_LITERAL:
            return {type: "Literal", value: token.value};
          case TOK_UNQUOTEDIDENTIFIER:
            return {type: "Field", name: token.value};
          case TOK_QUOTEDIDENTIFIER:
            var node = {type: "Field", name: token.value};
            if (this._lookahead(0) === TOK_LPAREN) {
                throw new Error("Quoted identifier not allowed for function names.");
            }
            return node;
          case TOK_NOT:
            right = this.expression(bindingPower.Not);
            return {type: "NotExpression", children: [right]};
          case TOK_STAR:
            left = {type: "Identity"};
            right = null;
            if (this._lookahead(0) === TOK_RBRACKET) {
                // This can happen in a multiselect,
                // [a, b, *]
                right = {type: "Identity"};
            } else {
                right = this._parseProjectionRHS(bindingPower.Star);
            }
            return {type: "ValueProjection", children: [left, right]};
          case TOK_FILTER:
            return this.led(token.type, {type: "Identity"});
          case TOK_LBRACE:
            return this._parseMultiselectHash();
          case TOK_FLATTEN:
            left = {type: TOK_FLATTEN, children: [{type: "Identity"}]};
            right = this._parseProjectionRHS(bindingPower.Flatten);
            return {type: "Projection", children: [left, right]};
          case TOK_LBRACKET:
            if (this._lookahead(0) === TOK_NUMBER || this._lookahead(0) === TOK_COLON) {
                right = this._parseIndexExpression();
                return this._projectIfSlice({type: "Identity"}, right);
            } else if (this._lookahead(0) === TOK_STAR &&
                       this._lookahead(1) === TOK_RBRACKET) {
                this._advance();
                this._advance();
                right = this._parseProjectionRHS(bindingPower.Star);
                return {type: "Projection",
                        children: [{type: "Identity"}, right]};
            }
            return this._parseMultiselectList();
          case TOK_CURRENT:
            return {type: TOK_CURRENT};
          case TOK_EXPREF:
            expression = this.expression(bindingPower.Expref);
            return {type: "ExpressionReference", children: [expression]};
          case TOK_LPAREN:
            var args = [];
            while (this._lookahead(0) !== TOK_RPAREN) {
              if (this._lookahead(0) === TOK_CURRENT) {
                expression = {type: TOK_CURRENT};
                this._advance();
              } else {
                expression = this.expression(0);
              }
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
        switch(tokenName) {
          case TOK_DOT:
            var rbp = bindingPower.Dot;
            if (this._lookahead(0) !== TOK_STAR) {
                right = this._parseDotRHS(rbp);
                return {type: "Subexpression", children: [left, right]};
            }
            // Creating a projection.
            this._advance();
            right = this._parseProjectionRHS(rbp);
            return {type: "ValueProjection", children: [left, right]};
          case TOK_PIPE:
            right = this.expression(bindingPower.Pipe);
            return {type: TOK_PIPE, children: [left, right]};
          case TOK_OR:
            right = this.expression(bindingPower.Or);
            return {type: "OrExpression", children: [left, right]};
          case TOK_AND:
            right = this.expression(bindingPower.And);
            return {type: "AndExpression", children: [left, right]};
          case TOK_LPAREN:
            var name = left.name;
            var args = [];
            var expression, node;
            while (this._lookahead(0) !== TOK_RPAREN) {
              if (this._lookahead(0) === TOK_CURRENT) {
                expression = {type: TOK_CURRENT};
                this._advance();
              } else {
                expression = this.expression(0);
              }
              if (this._lookahead(0) === TOK_COMMA) {
                this._match(TOK_COMMA);
              }
              args.push(expression);
            }
            this._match(TOK_RPAREN);
            node = {type: "Function", name: name, children: args};
            return node;
          case TOK_FILTER:
            var condition = this.expression(0);
            this._match(TOK_RBRACKET);
            if (this._lookahead(0) === TOK_FLATTEN) {
              right = {type: "Identity"};
            } else {
              right = this._parseProjectionRHS(bindingPower.Filter);
            }
            return {type: "FilterProjection", children: [left, right, condition]};
          case TOK_FLATTEN:
            var leftNode = {type: TOK_FLATTEN, children: [left]};
            var rightNode = this._parseProjectionRHS(bindingPower.Flatten);
            return {type: "Projection", children: [leftNode, rightNode]};
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
            return {type: "Projection", children: [left, right]};
          default:
            this._errorToken(this._lookaheadToken(0));
        }
      },

      _match: function(tokenType) {
          if (this._lookahead(0) === tokenType) {
              this._advance();
          } else {
              var t = this._lookaheadToken(0);
              var error = new Error("Expected " + tokenType + ", got: " + t.type);
              error.name = "ParserError";
              throw error;
          }
      },

      _errorToken: function(token) {
          var error = new Error("Invalid token (" +
                                token.type + "): \"" +
                                token.value + "\"");
          error.name = "ParserError";
          throw error;
      },


      _parseIndexExpression: function() {
          if (this._lookahead(0) === TOK_COLON || this._lookahead(1) === TOK_COLON) {
              return this._parseSliceExpression();
          } else {
              var node = {
                  type: "Index",
                  value: this._lookaheadToken(0).value};
              this._advance();
              this._match(TOK_RBRACKET);
              return node;
          }
      },

      _projectIfSlice: function(left, right) {
          var indexExpr = {type: "IndexExpression", children: [left, right]};
          if (right.type === "Slice") {
              return {
                  type: "Projection",
                  children: [indexExpr, this._parseProjectionRHS(bindingPower.Star)]
              };
          } else {
              return indexExpr;
          }
      },

      _parseSliceExpression: function() {
          // [start:end:step] where each part is optional, as well as the last
          // colon.
          var parts = [null, null, null];
          var index = 0;
          var currentToken = this._lookahead(0);
          while (currentToken !== TOK_RBRACKET && index < 3) {
              if (currentToken === TOK_COLON) {
                  index++;
                  this._advance();
              } else if (currentToken === TOK_NUMBER) {
                  parts[index] = this._lookaheadToken(0).value;
                  this._advance();
              } else {
                  var t = this._lookahead(0);
                  var error = new Error("Syntax error, unexpected token: " +
                                        t.value + "(" + t.type + ")");
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
        return {type: "Comparator", name: comparator, children: [left, right]};
      },

      _parseDotRHS: function(rbp) {
          var lookahead = this._lookahead(0);
          var exprTokens = [TOK_UNQUOTEDIDENTIFIER, TOK_QUOTEDIDENTIFIER, TOK_STAR];
          if (exprTokens.indexOf(lookahead) >= 0) {
              return this.expression(rbp);
          } else if (lookahead === TOK_LBRACKET) {
              this._match(TOK_LBRACKET);
              return this._parseMultiselectList();
          } else if (lookahead === TOK_LBRACE) {
              this._match(TOK_LBRACE);
              return this._parseMultiselectHash();
          }
      },

      _parseProjectionRHS: function(rbp) {
          var right;
          if (bindingPower[this._lookahead(0)] < 10) {
              right = {type: "Identity"};
          } else if (this._lookahead(0) === TOK_LBRACKET) {
              right = this.expression(rbp);
          } else if (this._lookahead(0) === TOK_FILTER) {
              right = this.expression(rbp);
          } else if (this._lookahead(0) === TOK_DOT) {
              this._match(TOK_DOT);
              right = this._parseDotRHS(rbp);
          } else {
              var t = this._lookaheadToken(0);
              var error = new Error("Sytanx error, unexpected token: " +
                                    t.value + "(" + t.type + ")");
              error.name = "ParserError";
              throw error;
          }
          return right;
      },

      _parseMultiselectList: function() {
          var expressions = [];
          while (this._lookahead(0) !== TOK_RBRACKET) {
              var expression = this.expression(0);
              expressions.push(expression);
              if (this._lookahead(0) === TOK_COMMA) {
                  this._match(TOK_COMMA);
                  if (this._lookahead(0) === TOK_RBRACKET) {
                    throw new Error("Unexpected token Rbracket");
                  }
              }
          }
          this._match(TOK_RBRACKET);
          return {type: "MultiSelectList", children: expressions};
      },

      _parseMultiselectHash: function() {
        var pairs = [];
        var identifierTypes = [TOK_UNQUOTEDIDENTIFIER, TOK_QUOTEDIDENTIFIER];
        var keyToken, keyName, value, node;
        for (;;) {
          keyToken = this._lookaheadToken(0);
          if (identifierTypes.indexOf(keyToken.type) < 0) {
            throw new Error("Expecting an identifier token, got: " +
                            keyToken.type);
          }
          keyName = keyToken.value;
          this._advance();
          this._match(TOK_COLON);
          value = this.expression(0);
          node = {type: "KeyValuePair", name: keyName, value: value};
          pairs.push(node);
          if (this._lookahead(0) === TOK_COMMA) {
            this._match(TOK_COMMA);
          } else if (this._lookahead(0) === TOK_RBRACE) {
            this._match(TOK_RBRACE);
            break;
          }
        }
        return {type: "MultiSelectHash", children: pairs};
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
          switch (node.type) {
            case "Field":
              if (value !== null && isObject(value)) {
                  field = value[node.name];
                  if (field === undefined) {
                      return null;
                  } else {
                      return field;
                  }
              }
              return null;
            case "Subexpression":
              result = this.visit(node.children[0], value);
              for (i = 1; i < node.children.length; i++) {
                  result = this.visit(node.children[1], result);
                  if (result === null) {
                      return null;
                  }
              }
              return result;
            case "IndexExpression":
              left = this.visit(node.children[0], value);
              right = this.visit(node.children[1], left);
              return right;
            case "Index":
              if (!isArray(value)) {
                return null;
              }
              var index = node.value;
              if (index < 0) {
                index = value.length + index;
              }
              result = value[index];
              if (result === undefined) {
                result = null;
              }
              return result;
            case "Slice":
              if (!isArray(value)) {
                return null;
              }
              var sliceParams = node.children.slice(0);
              var computed = this.computeSliceParams(value.length, sliceParams);
              var start = computed[0];
              var stop = computed[1];
              var step = computed[2];
              result = [];
              if (step > 0) {
                  for (i = start; i < stop; i += step) {
                      result.push(value[i]);
                  }
              } else {
                  for (i = start; i > stop; i += step) {
                      result.push(value[i]);
                  }
              }
              return result;
            case "Projection":
              // Evaluate left child.
              var base = this.visit(node.children[0], value);
              if (!isArray(base)) {
                return null;
              }
              collected = [];
              for (i = 0; i < base.length; i++) {
                current = this.visit(node.children[1], base[i]);
                if (current !== null) {
                  collected.push(current);
                }
              }
              return collected;
            case "ValueProjection":
              // Evaluate left child.
              base = this.visit(node.children[0], value);
              if (!isObject(base)) {
                return null;
              }
              collected = [];
              var values = objValues(base);
              for (i = 0; i < values.length; i++) {
                current = this.visit(node.children[1], values[i]);
                if (current !== null) {
                  collected.push(current);
                }
              }
              return collected;
            case "FilterProjection":
              base = this.visit(node.children[0], value);
              if (!isArray(base)) {
                return null;
              }
              var filtered = [];
              var finalResults = [];
              for (i = 0; i < base.length; i++) {
                matched = this.visit(node.children[2], base[i]);
                if (!isFalse(matched)) {
                  filtered.push(base[i]);
                }
              }
              for (var j = 0; j < filtered.length; j++) {
                current = this.visit(node.children[1], filtered[j]);
                if (current !== null) {
                  finalResults.push(current);
                }
              }
              return finalResults;
            case "Comparator":
              first = this.visit(node.children[0], value);
              second = this.visit(node.children[1], value);
              switch(node.name) {
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
              if (!isArray(original)) {
                return null;
              }
              var merged = [];
              for (i = 0; i < original.length; i++) {
                current = original[i];
                if (isArray(current)) {
                  merged.push.apply(merged, current);
                } else {
                  merged.push(current);
                }
              }
              return merged;
            case "Identity":
              return value;
            case "MultiSelectList":
              if (value === null) {
                return null;
              }
              collected = [];
              for (i = 0; i < node.children.length; i++) {
                  collected.push(this.visit(node.children[i], value));
              }
              return collected;
            case "MultiSelectHash":
              if (value === null) {
                return null;
              }
              collected = {};
              var child;
              for (i = 0; i < node.children.length; i++) {
                child = node.children[i];
                collected[child.name] = this.visit(child.value, value);
              }
              return collected;
            case "OrExpression":
              matched = this.visit(node.children[0], value);
              if (isFalse(matched)) {
                  matched = this.visit(node.children[1], value);
              }
              return matched;
            case "AndExpression":
              first = this.visit(node.children[0], value);

              if (isFalse(first) === true) {
                return first;
              }
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
              for (i = 0; i < node.children.length; i++) {
                  resolvedArgs.push(this.visit(node.children[i], value));
              }
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
        var computed = [null, null, null];
        if (step === null) {
          step = 1;
        } else if (step === 0) {
          var error = new Error("Invalid slice, step cannot be 0");
          error.name = "RuntimeError";
          throw error;
        }
        var stepValueNegative = step < 0 ? true : false;

        if (start === null) {
            start = stepValueNegative ? arrayLength - 1 : 0;
        } else {
            start = this.capSliceRange(arrayLength, start, step);
        }

        if (stop === null) {
            stop = stepValueNegative ? -1 : arrayLength;
        } else {
            stop = this.capSliceRange(arrayLength, stop, step);
        }
        computed[0] = start;
        computed[1] = stop;
        computed[2] = step;
        return computed;
      },

      capSliceRange: function(arrayLength, actualValue, step) {
          if (actualValue < 0) {
              actualValue += arrayLength;
              if (actualValue < 0) {
                  actualValue = step < 0 ? -1 : 0;
              }
          } else if (actualValue >= arrayLength) {
              actualValue = step < 0 ? arrayLength - 1 : arrayLength;
          }
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
        abs: {_func: this._functionAbs, _signature: [{types: [TYPE_NUMBER]}]},
        avg: {_func: this._functionAvg, _signature: [{types: [TYPE_ARRAY_NUMBER]}]},
        ceil: {_func: this._functionCeil, _signature: [{types: [TYPE_NUMBER]}]},
        contains: {
            _func: this._functionContains,
            _signature: [{types: [TYPE_STRING, TYPE_ARRAY]},
                        {types: [TYPE_ANY]}]},
        "ends_with": {
            _func: this._functionEndsWith,
            _signature: [{types: [TYPE_STRING]}, {types: [TYPE_STRING]}]},
        floor: {_func: this._functionFloor, _signature: [{types: [TYPE_NUMBER]}]},
        length: {
            _func: this._functionLength,
            _signature: [{types: [TYPE_STRING, TYPE_ARRAY, TYPE_OBJECT]}]},
        map: {
            _func: this._functionMap,
            _signature: [{types: [TYPE_EXPREF]}, {types: [TYPE_ARRAY]}]},
        max: {
            _func: this._functionMax,
            _signature: [{types: [TYPE_ARRAY_NUMBER, TYPE_ARRAY_STRING]}]},
        "merge": {
            _func: this._functionMerge,
            _signature: [{types: [TYPE_OBJECT], variadic: true}]
        },
        "max_by": {
          _func: this._functionMaxBy,
          _signature: [{types: [TYPE_ARRAY]}, {types: [TYPE_EXPREF]}]
        },
        sum: {_func: this._functionSum, _signature: [{types: [TYPE_ARRAY_NUMBER]}]},
        "starts_with": {
            _func: this._functionStartsWith,
            _signature: [{types: [TYPE_STRING]}, {types: [TYPE_STRING]}]},
        min: {
            _func: this._functionMin,
            _signature: [{types: [TYPE_ARRAY_NUMBER, TYPE_ARRAY_STRING]}]},
        "min_by": {
          _func: this._functionMinBy,
          _signature: [{types: [TYPE_ARRAY]}, {types: [TYPE_EXPREF]}]
        },
        type: {_func: this._functionType, _signature: [{types: [TYPE_ANY]}]},
        keys: {_func: this._functionKeys, _signature: [{types: [TYPE_OBJECT]}]},
        values: {_func: this._functionValues, _signature: [{types: [TYPE_OBJECT]}]},
        sort: {_func: this._functionSort, _signature: [{types: [TYPE_ARRAY_STRING, TYPE_ARRAY_NUMBER]}]},
        "sort_by": {
          _func: this._functionSortBy,
          _signature: [{types: [TYPE_ARRAY]}, {types: [TYPE_EXPREF]}]
        },
        join: {
            _func: this._functionJoin,
            _signature: [
                {types: [TYPE_STRING]},
                {types: [TYPE_ARRAY_STRING]}
            ]
        },
        reverse: {
            _func: this._functionReverse,
            _signature: [{types: [TYPE_STRING, TYPE_ARRAY]}]},
        "to_array": {_func: this._functionToArray, _signature: [{types: [TYPE_ANY]}]},
        "to_string": {_func: this._functionToString, _signature: [{types: [TYPE_ANY]}]},
        "to_number": {_func: this._functionToNumber, _signature: [{types: [TYPE_ANY]}]},
        "not_null": {
            _func: this._functionNotNull,
            _signature: [{types: [TYPE_ANY], variadic: true}]
        }
    };
  }

  Runtime.prototype = {
    callFunction: function(name, resolvedArgs) {
      var functionEntry = this.functionTable[name];
      if (functionEntry === undefined) {
          throw new Error("Unknown function: " + name + "()");
      }
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
                throw new Error("ArgumentError: " + name + "() " +
                                "takes at least" + signature.length + pluralized +
                                " but received " + args.length);
            }
        } else if (args.length !== signature.length) {
            pluralized = signature.length === 1 ? " argument" : " arguments";
            throw new Error("ArgumentError: " + name + "() " +
                            "takes " + signature.length + pluralized +
                            " but received " + args.length);
        }
        var currentSpec;
        var actualType;
        var typeMatched;
        for (var i = 0; i < signature.length; i++) {
            typeMatched = false;
            currentSpec = signature[i].types;
            actualType = this._getTypeName(args[i]);
            for (var j = 0; j < currentSpec.length; j++) {
                if (this._typeMatches(actualType, currentSpec[j], args[i])) {
                    typeMatched = true;
                    break;
                }
            }
            if (!typeMatched) {
                var expected = currentSpec
                    .map(function(typeIdentifier) {
                        return TYPE_NAME_TABLE[typeIdentifier];
                    })
                    .join(',');
                throw new Error("TypeError: " + name + "() " +
                                "expected argument " + (i + 1) +
                                " to be type " + expected +
                                " but received type " +
                                TYPE_NAME_TABLE[actualType] + " instead.");
            }
        }
    },

    _typeMatches: function(actual, expected, argValue) {
        if (expected === TYPE_ANY) {
            return true;
        }
        if (expected === TYPE_ARRAY_STRING ||
            expected === TYPE_ARRAY_NUMBER ||
            expected === TYPE_ARRAY) {
            // The expected type can either just be array,
            // or it can require a specific subtype (array of numbers).
            //
            // The simplest case is if "array" with no subtype is specified.
            if (expected === TYPE_ARRAY) {
                return actual === TYPE_ARRAY;
            } else if (actual === TYPE_ARRAY) {
                // Otherwise we need to check subtypes.
                // I think this has potential to be improved.
                var subtype;
                if (expected === TYPE_ARRAY_NUMBER) {
                  subtype = TYPE_NUMBER;
                } else if (expected === TYPE_ARRAY_STRING) {
                  subtype = TYPE_STRING;
                }
                for (var i = 0; i < argValue.length; i++) {
                    if (!this._typeMatches(
                            this._getTypeName(argValue[i]), subtype,
                                             argValue[i])) {
                        return false;
                    }
                }
                return true;
            }
        } else {
            return actual === expected;
        }
    },
    _getTypeName: function(obj) {
        switch (Object.prototype.toString.call(obj)) {
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
              if (obj.jmespathType === TOK_EXPREF) {
                return TYPE_EXPREF;
              } else {
                return TYPE_OBJECT;
              }
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
          for (var i = originalStr.length - 1; i >= 0; i--) {
              reversedStr += originalStr[i];
          }
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
        for (var i = 0; i < inputArray.length; i++) {
            sum += inputArray[i];
        }
        return sum / inputArray.length;
    },

    _functionContains: function(resolvedArgs) {
        return resolvedArgs[0].indexOf(resolvedArgs[1]) >= 0;
    },

    _functionFloor: function(resolvedArgs) {
        return Math.floor(resolvedArgs[0]);
    },

    _functionLength: function(resolvedArgs) {
       if (!isObject(resolvedArgs[0])) {
         return resolvedArgs[0].length;
       } else {
         // As far as I can tell, there's no way to get the length
         // of an object without O(n) iteration through the object.
         return Object.keys(resolvedArgs[0]).length;
       }
    },

    _functionMap: function(resolvedArgs) {
      var mapped = [];
      var interpreter = this._interpreter;
      var exprefNode = resolvedArgs[0];
      var elements = resolvedArgs[1];
      for (var i = 0; i < elements.length; i++) {
          mapped.push(interpreter.visit(exprefNode, elements[i]));
      }
      return mapped;
    },

    _functionMerge: function(resolvedArgs) {
      var merged = {};
      for (var i = 0; i < resolvedArgs.length; i++) {
        var current = resolvedArgs[i];
        for (var key in current) {
          merged[key] = current[key];
        }
      }
      return merged;
    },

    _functionMax: function(resolvedArgs) {
      if (resolvedArgs[0].length > 0) {
        var typeName = this._getTypeName(resolvedArgs[0][0]);
        if (typeName === TYPE_NUMBER) {
          return Math.max.apply(Math, resolvedArgs[0]);
        } else {
          var elements = resolvedArgs[0];
          var maxElement = elements[0];
          for (var i = 1; i < elements.length; i++) {
              if (maxElement.localeCompare(elements[i]) < 0) {
                  maxElement = elements[i];
              }
          }
          return maxElement;
        }
      } else {
          return null;
      }
    },

    _functionMin: function(resolvedArgs) {
      if (resolvedArgs[0].length > 0) {
        var typeName = this._getTypeName(resolvedArgs[0][0]);
        if (typeName === TYPE_NUMBER) {
          return Math.min.apply(Math, resolvedArgs[0]);
        } else {
          var elements = resolvedArgs[0];
          var minElement = elements[0];
          for (var i = 1; i < elements.length; i++) {
              if (elements[i].localeCompare(minElement) < 0) {
                  minElement = elements[i];
              }
          }
          return minElement;
        }
      } else {
        return null;
      }
    },

    _functionSum: function(resolvedArgs) {
      var sum = 0;
      var listToSum = resolvedArgs[0];
      for (var i = 0; i < listToSum.length; i++) {
        sum += listToSum[i];
      }
      return sum;
    },

    _functionType: function(resolvedArgs) {
        switch (this._getTypeName(resolvedArgs[0])) {
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
        for (var i = 0; i < keys.length; i++) {
            values.push(obj[keys[i]]);
        }
        return values;
    },

    _functionJoin: function(resolvedArgs) {
        var joinChar = resolvedArgs[0];
        var listJoin = resolvedArgs[1];
        return listJoin.join(joinChar);
    },

    _functionToArray: function(resolvedArgs) {
        if (this._getTypeName(resolvedArgs[0]) === TYPE_ARRAY) {
            return resolvedArgs[0];
        } else {
            return [resolvedArgs[0]];
        }
    },

    _functionToString: function(resolvedArgs) {
        if (this._getTypeName(resolvedArgs[0]) === TYPE_STRING) {
            return resolvedArgs[0];
        } else {
            return JSON.stringify(resolvedArgs[0]);
        }
    },

    _functionToNumber: function(resolvedArgs) {
        var typeName = this._getTypeName(resolvedArgs[0]);
        var convertedValue;
        if (typeName === TYPE_NUMBER) {
            return resolvedArgs[0];
        } else if (typeName === TYPE_STRING) {
            convertedValue = +resolvedArgs[0];
            if (!isNaN(convertedValue)) {
                return convertedValue;
            }
        }
        return null;
    },

    _functionNotNull: function(resolvedArgs) {
        for (var i = 0; i < resolvedArgs.length; i++) {
            if (this._getTypeName(resolvedArgs[i]) !== TYPE_NULL) {
                return resolvedArgs[i];
            }
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
        if (sortedArray.length === 0) {
            return sortedArray;
        }
        var interpreter = this._interpreter;
        var exprefNode = resolvedArgs[1];
        var requiredType = this._getTypeName(
            interpreter.visit(exprefNode, sortedArray[0]));
        if ([TYPE_NUMBER, TYPE_STRING].indexOf(requiredType) < 0) {
            throw new Error("TypeError");
        }
        var that = this;
        // In order to get a stable sort out of an unstable
        // sort algorithm, we decorate/sort/undecorate (DSU)
        // by creating a new list of [index, element] pairs.
        // In the cmp function, if the evaluated elements are
        // equal, then the index will be used as the tiebreaker.
        // After the decorated list has been sorted, it will be
        // undecorated to extract the original elements.
        var decorated = [];
        for (var i = 0; i < sortedArray.length; i++) {
          decorated.push([i, sortedArray[i]]);
        }
        decorated.sort(function(a, b) {
          var exprA = interpreter.visit(exprefNode, a[1]);
          var exprB = interpreter.visit(exprefNode, b[1]);
          if (that._getTypeName(exprA) !== requiredType) {
              throw new Error(
                  "TypeError: expected " + requiredType + ", received " +
                  that._getTypeName(exprA));
          } else if (that._getTypeName(exprB) !== requiredType) {
              throw new Error(
                  "TypeError: expected " + requiredType + ", received " +
                  that._getTypeName(exprB));
          }
          if (exprA > exprB) {
            return 1;
          } else if (exprA < exprB) {
            return -1;
          } else {
            // If they're equal compare the items by their
            // order to maintain relative order of equal keys
            // (i.e. to get a stable sort).
            return a[0] - b[0];
          }
        });
        // Undecorate: extract out the original list elements.
        for (var j = 0; j < decorated.length; j++) {
          sortedArray[j] = decorated[j][1];
        }
        return sortedArray;
    },

    _functionMaxBy: function(resolvedArgs) {
      var exprefNode = resolvedArgs[1];
      var resolvedArray = resolvedArgs[0];
      var keyFunction = this.createKeyFunction(exprefNode, [TYPE_NUMBER, TYPE_STRING]);
      var maxNumber = -Infinity;
      var maxRecord;
      var current;
      for (var i = 0; i < resolvedArray.length; i++) {
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
      var keyFunction = this.createKeyFunction(exprefNode, [TYPE_NUMBER, TYPE_STRING]);
      var minNumber = Infinity;
      var minRecord;
      var current;
      for (var i = 0; i < resolvedArray.length; i++) {
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
          var msg = "TypeError: expected one of " + allowedTypes +
                    ", received " + that._getTypeName(current);
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

  exports.tokenize = tokenize;
  exports.compile = compile;
  exports.search = search;
  exports.strictDeepEqual = strictDeepEqual;
})( false ? 0 : exports);


/***/ },

/***/ 3177
(__unused_webpack_module, exports) {

// Generated by CoffeeScript 1.12.7
(function() {
  "use strict";
  exports.stripBOM = function(str) {
    if (str[0] === '\uFEFF') {
      return str.substring(1);
    } else {
      return str;
    }
  };

}).call(this);


/***/ },

/***/ 6712
(__unused_webpack_module, exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  "use strict";
  var builder, defaults, escapeCDATA, requiresCDATA, wrapCDATA,
    hasProp = {}.hasOwnProperty;

  builder = __webpack_require__(9665);

  defaults = (__webpack_require__(6465).defaults);

  requiresCDATA = function(entry) {
    return typeof entry === "string" && (entry.indexOf('&') >= 0 || entry.indexOf('>') >= 0 || entry.indexOf('<') >= 0);
  };

  wrapCDATA = function(entry) {
    return "<![CDATA[" + (escapeCDATA(entry)) + "]]>";
  };

  escapeCDATA = function(entry) {
    return entry.replace(']]>', ']]]]><![CDATA[>');
  };

  exports.Builder = (function() {
    function Builder(opts) {
      var key, ref, value;
      this.options = {};
      ref = defaults["0.2"];
      for (key in ref) {
        if (!hasProp.call(ref, key)) continue;
        value = ref[key];
        this.options[key] = value;
      }
      for (key in opts) {
        if (!hasProp.call(opts, key)) continue;
        value = opts[key];
        this.options[key] = value;
      }
    }

    Builder.prototype.buildObject = function(rootObj) {
      var attrkey, charkey, render, rootElement, rootName;
      attrkey = this.options.attrkey;
      charkey = this.options.charkey;
      if ((Object.keys(rootObj).length === 1) && (this.options.rootName === defaults['0.2'].rootName)) {
        rootName = Object.keys(rootObj)[0];
        rootObj = rootObj[rootName];
      } else {
        rootName = this.options.rootName;
      }
      render = (function(_this) {
        return function(element, obj) {
          var attr, child, entry, index, key, value;
          if (typeof obj !== 'object') {
            if (_this.options.cdata && requiresCDATA(obj)) {
              element.raw(wrapCDATA(obj));
            } else {
              element.txt(obj);
            }
          } else if (Array.isArray(obj)) {
            for (index in obj) {
              if (!hasProp.call(obj, index)) continue;
              child = obj[index];
              for (key in child) {
                entry = child[key];
                element = render(element.ele(key), entry).up();
              }
            }
          } else {
            for (key in obj) {
              if (!hasProp.call(obj, key)) continue;
              child = obj[key];
              if (key === attrkey) {
                if (typeof child === "object") {
                  for (attr in child) {
                    value = child[attr];
                    element = element.att(attr, value);
                  }
                }
              } else if (key === charkey) {
                if (_this.options.cdata && requiresCDATA(child)) {
                  element = element.raw(wrapCDATA(child));
                } else {
                  element = element.txt(child);
                }
              } else if (Array.isArray(child)) {
                for (index in child) {
                  if (!hasProp.call(child, index)) continue;
                  entry = child[index];
                  if (typeof entry === 'string') {
                    if (_this.options.cdata && requiresCDATA(entry)) {
                      element = element.ele(key).raw(wrapCDATA(entry)).up();
                    } else {
                      element = element.ele(key, entry).up();
                    }
                  } else {
                    element = render(element.ele(key), entry).up();
                  }
                }
              } else if (typeof child === "object") {
                element = render(element.ele(key), child).up();
              } else {
                if (typeof child === 'string' && _this.options.cdata && requiresCDATA(child)) {
                  element = element.ele(key).raw(wrapCDATA(child)).up();
                } else {
                  if (child == null) {
                    child = '';
                  }
                  element = element.ele(key, child.toString()).up();
                }
              }
            }
          }
          return element;
        };
      })(this);
      rootElement = builder.create(rootName, this.options.xmldec, this.options.doctype, {
        headless: this.options.headless,
        allowSurrogateChars: this.options.allowSurrogateChars
      });
      return render(rootElement, rootObj).end(this.options.renderOpts);
    };

    return Builder;

  })();

}).call(this);


/***/ },

/***/ 6465
(__unused_webpack_module, exports) {

// Generated by CoffeeScript 1.12.7
(function() {
  exports.defaults = {
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

}).call(this);


/***/ },

/***/ 1912
(__unused_webpack_module, exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  "use strict";
  var bom, defaults, defineProperty, events, isEmpty, processItem, processors, sax, setImmediate,
    bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  sax = __webpack_require__(6313);

  events = __webpack_require__(4434);

  bom = __webpack_require__(3177);

  processors = __webpack_require__(2114);

  setImmediate = (__webpack_require__(3557).setImmediate);

  defaults = (__webpack_require__(6465).defaults);

  isEmpty = function(thing) {
    return typeof thing === "object" && (thing != null) && Object.keys(thing).length === 0;
  };

  processItem = function(processors, item, key) {
    var i, len, process;
    for (i = 0, len = processors.length; i < len; i++) {
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

  exports.Parser = (function(superClass) {
    extend(Parser, superClass);

    function Parser(opts) {
      this.parseStringPromise = bind(this.parseStringPromise, this);
      this.parseString = bind(this.parseString, this);
      this.reset = bind(this.reset, this);
      this.assignOrPush = bind(this.assignOrPush, this);
      this.processAsync = bind(this.processAsync, this);
      var key, ref, value;
      if (!(this instanceof exports.Parser)) {
        return new exports.Parser(opts);
      }
      this.options = {};
      ref = defaults["0.2"];
      for (key in ref) {
        if (!hasProp.call(ref, key)) continue;
        value = ref[key];
        this.options[key] = value;
      }
      for (key in opts) {
        if (!hasProp.call(opts, key)) continue;
        value = opts[key];
        this.options[key] = value;
      }
      if (this.options.xmlns) {
        this.options.xmlnskey = this.options.attrkey + "ns";
      }
      if (this.options.normalizeTags) {
        if (!this.options.tagNameProcessors) {
          this.options.tagNameProcessors = [];
        }
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
        if (!this.options.explicitArray) {
          return defineProperty(obj, key, newValue);
        } else {
          return defineProperty(obj, key, [newValue]);
        }
      } else {
        if (!(obj[key] instanceof Array)) {
          defineProperty(obj, key, [obj[key]]);
        }
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
      this.saxParser.onerror = (function(_this) {
        return function(error) {
          _this.saxParser.resume();
          if (!_this.saxParser.errThrown) {
            _this.saxParser.errThrown = true;
            return _this.emit("error", error);
          }
        };
      })(this);
      this.saxParser.onend = (function(_this) {
        return function() {
          if (!_this.saxParser.ended) {
            _this.saxParser.ended = true;
            return _this.emit("end", _this.resultObject);
          }
        };
      })(this);
      this.saxParser.ended = false;
      this.EXPLICIT_CHARKEY = this.options.explicitCharkey;
      this.resultObject = null;
      stack = [];
      attrkey = this.options.attrkey;
      charkey = this.options.charkey;
      this.saxParser.onopentag = (function(_this) {
        return function(node) {
          var key, newValue, obj, processedKey, ref;
          obj = {};
          obj[charkey] = "";
          if (!_this.options.ignoreAttrs) {
            ref = node.attributes;
            for (key in ref) {
              if (!hasProp.call(ref, key)) continue;
              if (!(attrkey in obj) && !_this.options.mergeAttrs) {
                obj[attrkey] = {};
              }
              newValue = _this.options.attrValueProcessors ? processItem(_this.options.attrValueProcessors, node.attributes[key], key) : node.attributes[key];
              processedKey = _this.options.attrNameProcessors ? processItem(_this.options.attrNameProcessors, key) : key;
              if (_this.options.mergeAttrs) {
                _this.assignOrPush(obj, processedKey, newValue);
              } else {
                defineProperty(obj[attrkey], processedKey, newValue);
              }
            }
          }
          obj["#name"] = _this.options.tagNameProcessors ? processItem(_this.options.tagNameProcessors, node.name) : node.name;
          if (_this.options.xmlns) {
            obj[_this.options.xmlnskey] = {
              uri: node.uri,
              local: node.local
            };
          }
          return stack.push(obj);
        };
      })(this);
      this.saxParser.onclosetag = (function(_this) {
        return function() {
          var cdata, emptyStr, key, node, nodeName, obj, objClone, old, s, xpath;
          obj = stack.pop();
          nodeName = obj["#name"];
          if (!_this.options.explicitChildren || !_this.options.preserveChildrenOrder) {
            delete obj["#name"];
          }
          if (obj.cdata === true) {
            cdata = obj.cdata;
            delete obj.cdata;
          }
          s = stack[stack.length - 1];
          if (obj[charkey].match(/^\s*$/) && !cdata) {
            emptyStr = obj[charkey];
            delete obj[charkey];
          } else {
            if (_this.options.trim) {
              obj[charkey] = obj[charkey].trim();
            }
            if (_this.options.normalize) {
              obj[charkey] = obj[charkey].replace(/\s{2,}/g, " ").trim();
            }
            obj[charkey] = _this.options.valueProcessors ? processItem(_this.options.valueProcessors, obj[charkey], nodeName) : obj[charkey];
            if (Object.keys(obj).length === 1 && charkey in obj && !_this.EXPLICIT_CHARKEY) {
              obj = obj[charkey];
            }
          }
          if (isEmpty(obj)) {
            if (typeof _this.options.emptyTag === 'function') {
              obj = _this.options.emptyTag();
            } else {
              obj = _this.options.emptyTag !== '' ? _this.options.emptyTag : emptyStr;
            }
          }
          if (_this.options.validator != null) {
            xpath = "/" + ((function() {
              var i, len, results;
              results = [];
              for (i = 0, len = stack.length; i < len; i++) {
                node = stack[i];
                results.push(node["#name"]);
              }
              return results;
            })()).concat(nodeName).join("/");
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
              if (Object.getOwnPropertyNames(obj).length > 0) {
                node[_this.options.childkey] = obj;
              }
              obj = node;
            } else if (s) {
              s[_this.options.childkey] = s[_this.options.childkey] || [];
              objClone = {};
              for (key in obj) {
                if (!hasProp.call(obj, key)) continue;
                defineProperty(objClone, key, obj[key]);
              }
              s[_this.options.childkey].push(objClone);
              delete obj["#name"];
              if (Object.keys(obj).length === 1 && charkey in obj && !_this.EXPLICIT_CHARKEY) {
                obj = obj[charkey];
              }
            }
          }
          if (stack.length > 0) {
            return _this.assignOrPush(s, nodeName, obj);
          } else {
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
      })(this);
      ontext = (function(_this) {
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
              if (_this.options.normalize) {
                charChild[charkey] = charChild[charkey].replace(/\s{2,}/g, " ").trim();
              }
              s[_this.options.childkey].push(charChild);
            }
            return s;
          }
        };
      })(this);
      this.saxParser.ontext = ontext;
      return this.saxParser.oncdata = (function(_this) {
        return function(text) {
          var s;
          s = ontext(text);
          if (s) {
            return s.cdata = true;
          }
        };
      })(this);
    };

    Parser.prototype.parseString = function(str, cb) {
      var err;
      if ((cb != null) && typeof cb === "function") {
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
        } else if (this.saxParser.ended) {
          throw err;
        }
      }
    };

    Parser.prototype.parseStringPromise = function(str) {
      return new Promise((function(_this) {
        return function(resolve, reject) {
          return _this.parseString(str, function(err, value) {
            if (err) {
              return reject(err);
            } else {
              return resolve(value);
            }
          });
        };
      })(this));
    };

    return Parser;

  })(events);

  exports.parseString = function(str, a, b) {
    var cb, options, parser;
    if (b != null) {
      if (typeof b === 'function') {
        cb = b;
      }
      if (typeof a === 'object') {
        options = a;
      }
    } else {
      if (typeof a === 'function') {
        cb = a;
      }
      options = {};
    }
    parser = new exports.Parser(options);
    return parser.parseString(str, cb);
  };

  exports.parseStringPromise = function(str, a) {
    var options, parser;
    if (typeof a === 'object') {
      options = a;
    }
    parser = new exports.Parser(options);
    return parser.parseStringPromise(str);
  };

}).call(this);


/***/ },

/***/ 2114
(__unused_webpack_module, exports) {

// Generated by CoffeeScript 1.12.7
(function() {
  "use strict";
  var prefixMatch;

  prefixMatch = new RegExp(/(?!xmlns)^.*:/);

  exports.normalize = function(str) {
    return str.toLowerCase();
  };

  exports.firstCharLowerCase = function(str) {
    return str.charAt(0).toLowerCase() + str.slice(1);
  };

  exports.stripPrefix = function(str) {
    return str.replace(prefixMatch, '');
  };

  exports.parseNumbers = function(str) {
    if (!isNaN(str)) {
      str = str % 1 === 0 ? parseInt(str, 10) : parseFloat(str);
    }
    return str;
  };

  exports.parseBooleans = function(str) {
    if (/^(?:true|false)$/i.test(str)) {
      str = str.toLowerCase() === 'true';
    }
    return str;
  };

}).call(this);


/***/ },

/***/ 8805
(__unused_webpack_module, exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  "use strict";
  var builder, defaults, parser, processors,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  defaults = __webpack_require__(6465);

  builder = __webpack_require__(6712);

  parser = __webpack_require__(1912);

  processors = __webpack_require__(2114);

  exports.defaults = defaults.defaults;

  exports.processors = processors;

  exports.ValidationError = (function(superClass) {
    extend(ValidationError, superClass);

    function ValidationError(message) {
      this.message = message;
    }

    return ValidationError;

  })(Error);

  exports.Builder = builder.Builder;

  exports.Parser = parser.Parser;

  exports.parseString = parser.parseString;

  exports.parseStringPromise = parser.parseStringPromise;

}).call(this);


/***/ },

/***/ 6313
(__unused_webpack_module, exports, __webpack_require__) {

;(function (sax) {
  // wrapper for non-node envs
  sax.parser = function (strict, opt) {
    return new SAXParser(strict, opt)
  }
  sax.SAXParser = SAXParser
  sax.SAXStream = SAXStream
  sax.createStream = createStream

  // When we pass the MAX_BUFFER_LENGTH position, start checking for buffer overruns.
  // When we check, schedule the next check for MAX_BUFFER_LENGTH - (max(buffer lengths)),
  // since that's the earliest that a buffer overrun could occur.  This way, checks are
  // as rare as required, but as often as necessary to ensure never crossing this bound.
  // Furthermore, buffers are only tested at most once per write(), so passing a very
  // large string into write() might have undesirable effects, but this is manageable by
  // the caller, so it is assumed to be safe.  Thus, a call to write() may, in the extreme
  // edge case, result in creating at most one complete copy of the string passed in.
  // Set to Infinity to have unlimited buffers.
  sax.MAX_BUFFER_LENGTH = 64 * 1024

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
    'script',
  ]

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
    'closenamespace',
  ]

  function SAXParser(strict, opt) {
    if (!(this instanceof SAXParser)) {
      return new SAXParser(strict, opt)
    }

    var parser = this
    clearBuffers(parser)
    parser.q = parser.c = ''
    parser.bufferCheckPosition = sax.MAX_BUFFER_LENGTH
    parser.opt = opt || {}
    parser.opt.lowercase = parser.opt.lowercase || parser.opt.lowercasetags
    parser.looseCase = parser.opt.lowercase ? 'toLowerCase' : 'toUpperCase'
    parser.tags = []
    parser.closed = parser.closedRoot = parser.sawRoot = false
    parser.tag = parser.error = null
    parser.strict = !!strict
    parser.noscript = !!(strict || parser.opt.noscript)
    parser.state = S.BEGIN
    parser.strictEntities = parser.opt.strictEntities
    parser.ENTITIES =
      parser.strictEntities ?
        Object.create(sax.XML_ENTITIES)
      : Object.create(sax.ENTITIES)
    parser.attribList = []

    // namespaces form a prototype chain.
    // it always points at the current tag,
    // which protos to its parent tag.
    if (parser.opt.xmlns) {
      parser.ns = Object.create(rootNS)
    }

    // disallow unquoted attribute values if not otherwise configured
    // and strict mode is true
    if (parser.opt.unquotedAttributeValues === undefined) {
      parser.opt.unquotedAttributeValues = !strict
    }

    // mostly just for error reporting
    parser.trackPosition = parser.opt.position !== false
    if (parser.trackPosition) {
      parser.position = parser.line = parser.column = 0
    }
    emit(parser, 'onready')
  }

  if (!Object.create) {
    Object.create = function (o) {
      function F() {}
      F.prototype = o
      var newf = new F()
      return newf
    }
  }

  if (!Object.keys) {
    Object.keys = function (o) {
      var a = []
      for (var i in o) if (o.hasOwnProperty(i)) a.push(i)
      return a
    }
  }

  function checkBufferLength(parser) {
    var maxAllowed = Math.max(sax.MAX_BUFFER_LENGTH, 10)
    var maxActual = 0
    for (var i = 0, l = buffers.length; i < l; i++) {
      var len = parser[buffers[i]].length
      if (len > maxAllowed) {
        // Text/cdata nodes can get big, and since they're buffered,
        // we can get here under normal conditions.
        // Avoid issues by emitting the text node now,
        // so at least it won't get any bigger.
        switch (buffers[i]) {
          case 'textNode':
            closeText(parser)
            break

          case 'cdata':
            emitNode(parser, 'oncdata', parser.cdata)
            parser.cdata = ''
            break

          case 'script':
            emitNode(parser, 'onscript', parser.script)
            parser.script = ''
            break

          default:
            error(parser, 'Max buffer length exceeded: ' + buffers[i])
        }
      }
      maxActual = Math.max(maxActual, len)
    }
    // schedule the next check for the earliest possible buffer overrun.
    var m = sax.MAX_BUFFER_LENGTH - maxActual
    parser.bufferCheckPosition = m + parser.position
  }

  function clearBuffers(parser) {
    for (var i = 0, l = buffers.length; i < l; i++) {
      parser[buffers[i]] = ''
    }
  }

  function flushBuffers(parser) {
    closeText(parser)
    if (parser.cdata !== '') {
      emitNode(parser, 'oncdata', parser.cdata)
      parser.cdata = ''
    }
    if (parser.script !== '') {
      emitNode(parser, 'onscript', parser.script)
      parser.script = ''
    }
  }

  SAXParser.prototype = {
    end: function () {
      end(this)
    },
    write: write,
    resume: function () {
      this.error = null
      return this
    },
    close: function () {
      return this.write(null)
    },
    flush: function () {
      flushBuffers(this)
    },
  }

  var Stream
  try {
    Stream = (__webpack_require__(2203).Stream)
  } catch (ex) {
    Stream = function () {}
  }
  if (!Stream) Stream = function () {}

  var streamWraps = sax.EVENTS.filter(function (ev) {
    return ev !== 'error' && ev !== 'end'
  })

  function createStream(strict, opt) {
    return new SAXStream(strict, opt)
  }

  function SAXStream(strict, opt) {
    if (!(this instanceof SAXStream)) {
      return new SAXStream(strict, opt)
    }

    Stream.apply(this)

    this._parser = new SAXParser(strict, opt)
    this.writable = true
    this.readable = true

    var me = this

    this._parser.onend = function () {
      me.emit('end')
    }

    this._parser.onerror = function (er) {
      me.emit('error', er)

      // if didn't throw, then means error was handled.
      // go ahead and clear error, so we can write again.
      me._parser.error = null
    }

    this._decoder = null

    streamWraps.forEach(function (ev) {
      Object.defineProperty(me, 'on' + ev, {
        get: function () {
          return me._parser['on' + ev]
        },
        set: function (h) {
          if (!h) {
            me.removeAllListeners(ev)
            me._parser['on' + ev] = h
            return h
          }
          me.on(ev, h)
        },
        enumerable: true,
        configurable: false,
      })
    })
  }

  SAXStream.prototype = Object.create(Stream.prototype, {
    constructor: {
      value: SAXStream,
    },
  })

  SAXStream.prototype.write = function (data) {
    if (
      typeof Buffer === 'function' &&
      typeof Buffer.isBuffer === 'function' &&
      Buffer.isBuffer(data)
    ) {
      if (!this._decoder) {
        var SD = (__webpack_require__(3193).StringDecoder)
        this._decoder = new SD('utf8')
      }
      data = this._decoder.write(data)
    }

    this._parser.write(data.toString())
    this.emit('data', data)
    return true
  }

  SAXStream.prototype.end = function (chunk) {
    if (chunk && chunk.length) {
      this.write(chunk)
    }
    this._parser.end()
    return true
  }

  SAXStream.prototype.on = function (ev, handler) {
    var me = this
    if (!me._parser['on' + ev] && streamWraps.indexOf(ev) !== -1) {
      me._parser['on' + ev] = function () {
        var args =
          arguments.length === 1 ?
            [arguments[0]]
          : Array.apply(null, arguments)
        args.splice(0, 0, ev)
        me.emit.apply(me, args)
      }
    }

    return Stream.prototype.on.call(me, ev, handler)
  }

  // this really needs to be replaced with character classes.
  // XML allows all manner of ridiculous numbers and digits.
  var CDATA = '[CDATA['
  var DOCTYPE = 'DOCTYPE'
  var XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace'
  var XMLNS_NAMESPACE = 'http://www.w3.org/2000/xmlns/'
  var rootNS = { xml: XML_NAMESPACE, xmlns: XMLNS_NAMESPACE }

  // http://www.w3.org/TR/REC-xml/#NT-NameStartChar
  // This implementation works on strings, a single character at a time
  // as such, it cannot ever support astral-plane characters (10000-EFFFF)
  // without a significant breaking change to either this  parser, or the
  // JavaScript language.  Implementation of an emoji-capable xml parser
  // is left as an exercise for the reader.
  var nameStart =
    /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/

  var nameBody =
    /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040.\d-]/

  var entityStart =
    /[#:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/
  var entityBody =
    /[#:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040.\d-]/

  function isWhitespace(c) {
    return c === ' ' || c === '\n' || c === '\r' || c === '\t'
  }

  function isQuote(c) {
    return c === '"' || c === "'"
  }

  function isAttribEnd(c) {
    return c === '>' || isWhitespace(c)
  }

  function isMatch(regex, c) {
    return regex.test(c)
  }

  function notMatch(regex, c) {
    return !isMatch(regex, c)
  }

  var S = 0
  sax.STATE = {
    BEGIN: S++, // leading byte order mark or whitespace
    BEGIN_WHITESPACE: S++, // leading whitespace
    TEXT: S++, // general stuff
    TEXT_ENTITY: S++, // &amp and such.
    OPEN_WAKA: S++, // <
    SGML_DECL: S++, // <!BLARG
    SGML_DECL_QUOTED: S++, // <!BLARG foo "bar
    DOCTYPE: S++, // <!DOCTYPE
    DOCTYPE_QUOTED: S++, // <!DOCTYPE "//blah
    DOCTYPE_DTD: S++, // <!DOCTYPE "//blah" [ ...
    DOCTYPE_DTD_QUOTED: S++, // <!DOCTYPE "//blah" [ "foo
    COMMENT_STARTING: S++, // <!-
    COMMENT: S++, // <!--
    COMMENT_ENDING: S++, // <!-- blah -
    COMMENT_ENDED: S++, // <!-- blah --
    CDATA: S++, // <![CDATA[ something
    CDATA_ENDING: S++, // ]
    CDATA_ENDING_2: S++, // ]]
    PROC_INST: S++, // <?hi
    PROC_INST_BODY: S++, // <?hi there
    PROC_INST_ENDING: S++, // <?hi "there" ?
    OPEN_TAG: S++, // <strong
    OPEN_TAG_SLASH: S++, // <strong /
    ATTRIB: S++, // <a
    ATTRIB_NAME: S++, // <a foo
    ATTRIB_NAME_SAW_WHITE: S++, // <a foo _
    ATTRIB_VALUE: S++, // <a foo=
    ATTRIB_VALUE_QUOTED: S++, // <a foo="bar
    ATTRIB_VALUE_CLOSED: S++, // <a foo="bar"
    ATTRIB_VALUE_UNQUOTED: S++, // <a foo=bar
    ATTRIB_VALUE_ENTITY_Q: S++, // <foo bar="&quot;"
    ATTRIB_VALUE_ENTITY_U: S++, // <foo bar=&quot
    CLOSE_TAG: S++, // </a
    CLOSE_TAG_SAW_WHITE: S++, // </a   >
    SCRIPT: S++, // <script> ...
    SCRIPT_ENDING: S++, // <script> ... <
  }

  sax.XML_ENTITIES = {
    amp: '&',
    gt: '>',
    lt: '<',
    quot: '"',
    apos: "'",
  }

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
    diams: 9830,
  }

  Object.keys(sax.ENTITIES).forEach(function (key) {
    var e = sax.ENTITIES[key]
    var s = typeof e === 'number' ? String.fromCharCode(e) : e
    sax.ENTITIES[key] = s
  })

  for (var s in sax.STATE) {
    sax.STATE[sax.STATE[s]] = s
  }

  // shorthand
  S = sax.STATE

  function emit(parser, event, data) {
    parser[event] && parser[event](data)
  }

  function emitNode(parser, nodeType, data) {
    if (parser.textNode) closeText(parser)
    emit(parser, nodeType, data)
  }

  function closeText(parser) {
    parser.textNode = textopts(parser.opt, parser.textNode)
    if (parser.textNode) emit(parser, 'ontext', parser.textNode)
    parser.textNode = ''
  }

  function textopts(opt, text) {
    if (opt.trim) text = text.trim()
    if (opt.normalize) text = text.replace(/\s+/g, ' ')
    return text
  }

  function error(parser, er) {
    closeText(parser)
    if (parser.trackPosition) {
      er +=
        '\nLine: ' +
        parser.line +
        '\nColumn: ' +
        parser.column +
        '\nChar: ' +
        parser.c
    }
    er = new Error(er)
    parser.error = er
    emit(parser, 'onerror', er)
    return parser
  }

  function end(parser) {
    if (parser.sawRoot && !parser.closedRoot)
      strictFail(parser, 'Unclosed root tag')
    if (
      parser.state !== S.BEGIN &&
      parser.state !== S.BEGIN_WHITESPACE &&
      parser.state !== S.TEXT
    ) {
      error(parser, 'Unexpected end')
    }
    closeText(parser)
    parser.c = ''
    parser.closed = true
    emit(parser, 'onend')
    SAXParser.call(parser, parser.strict, parser.opt)
    return parser
  }

  function strictFail(parser, message) {
    if (typeof parser !== 'object' || !(parser instanceof SAXParser)) {
      throw new Error('bad call to strictFail')
    }
    if (parser.strict) {
      error(parser, message)
    }
  }

  function newTag(parser) {
    if (!parser.strict) parser.tagName = parser.tagName[parser.looseCase]()
    var parent = parser.tags[parser.tags.length - 1] || parser
    var tag = (parser.tag = { name: parser.tagName, attributes: {} })

    // will be overridden if tag contails an xmlns="foo" or xmlns:foo="bar"
    if (parser.opt.xmlns) {
      tag.ns = parent.ns
    }
    parser.attribList.length = 0
    emitNode(parser, 'onopentagstart', tag)
  }

  function qname(name, attribute) {
    var i = name.indexOf(':')
    var qualName = i < 0 ? ['', name] : name.split(':')
    var prefix = qualName[0]
    var local = qualName[1]

    // <x "xmlns"="http://foo">
    if (attribute && name === 'xmlns') {
      prefix = 'xmlns'
      local = ''
    }

    return { prefix: prefix, local: local }
  }

  function attrib(parser) {
    if (!parser.strict) {
      parser.attribName = parser.attribName[parser.looseCase]()
    }

    if (
      parser.attribList.indexOf(parser.attribName) !== -1 ||
      parser.tag.attributes.hasOwnProperty(parser.attribName)
    ) {
      parser.attribName = parser.attribValue = ''
      return
    }

    if (parser.opt.xmlns) {
      var qn = qname(parser.attribName, true)
      var prefix = qn.prefix
      var local = qn.local

      if (prefix === 'xmlns') {
        // namespace binding attribute. push the binding into scope
        if (local === 'xml' && parser.attribValue !== XML_NAMESPACE) {
          strictFail(
            parser,
            'xml: prefix must be bound to ' +
              XML_NAMESPACE +
              '\n' +
              'Actual: ' +
              parser.attribValue
          )
        } else if (
          local === 'xmlns' &&
          parser.attribValue !== XMLNS_NAMESPACE
        ) {
          strictFail(
            parser,
            'xmlns: prefix must be bound to ' +
              XMLNS_NAMESPACE +
              '\n' +
              'Actual: ' +
              parser.attribValue
          )
        } else {
          var tag = parser.tag
          var parent = parser.tags[parser.tags.length - 1] || parser
          if (tag.ns === parent.ns) {
            tag.ns = Object.create(parent.ns)
          }
          tag.ns[local] = parser.attribValue
        }
      }

      // defer onattribute events until all attributes have been seen
      // so any new bindings can take effect. preserve attribute order
      // so deferred events can be emitted in document order
      parser.attribList.push([parser.attribName, parser.attribValue])
    } else {
      // in non-xmlns mode, we can emit the event right away
      parser.tag.attributes[parser.attribName] = parser.attribValue
      emitNode(parser, 'onattribute', {
        name: parser.attribName,
        value: parser.attribValue,
      })
    }

    parser.attribName = parser.attribValue = ''
  }

  function openTag(parser, selfClosing) {
    if (parser.opt.xmlns) {
      // emit namespace binding events
      var tag = parser.tag

      // add namespace info to tag
      var qn = qname(parser.tagName)
      tag.prefix = qn.prefix
      tag.local = qn.local
      tag.uri = tag.ns[qn.prefix] || ''

      if (tag.prefix && !tag.uri) {
        strictFail(
          parser,
          'Unbound namespace prefix: ' + JSON.stringify(parser.tagName)
        )
        tag.uri = qn.prefix
      }

      var parent = parser.tags[parser.tags.length - 1] || parser
      if (tag.ns && parent.ns !== tag.ns) {
        Object.keys(tag.ns).forEach(function (p) {
          emitNode(parser, 'onopennamespace', {
            prefix: p,
            uri: tag.ns[p],
          })
        })
      }

      // handle deferred onattribute events
      // Note: do not apply default ns to attributes:
      //   http://www.w3.org/TR/REC-xml-names/#defaulting
      for (var i = 0, l = parser.attribList.length; i < l; i++) {
        var nv = parser.attribList[i]
        var name = nv[0]
        var value = nv[1]
        var qualName = qname(name, true)
        var prefix = qualName.prefix
        var local = qualName.local
        var uri = prefix === '' ? '' : tag.ns[prefix] || ''
        var a = {
          name: name,
          value: value,
          prefix: prefix,
          local: local,
          uri: uri,
        }

        // if there's any attributes with an undefined namespace,
        // then fail on them now.
        if (prefix && prefix !== 'xmlns' && !uri) {
          strictFail(
            parser,
            'Unbound namespace prefix: ' + JSON.stringify(prefix)
          )
          a.uri = prefix
        }
        parser.tag.attributes[name] = a
        emitNode(parser, 'onattribute', a)
      }
      parser.attribList.length = 0
    }

    parser.tag.isSelfClosing = !!selfClosing

    // process the tag
    parser.sawRoot = true
    parser.tags.push(parser.tag)
    emitNode(parser, 'onopentag', parser.tag)
    if (!selfClosing) {
      // special case for <script> in non-strict mode.
      if (!parser.noscript && parser.tagName.toLowerCase() === 'script') {
        parser.state = S.SCRIPT
      } else {
        parser.state = S.TEXT
      }
      parser.tag = null
      parser.tagName = ''
    }
    parser.attribName = parser.attribValue = ''
    parser.attribList.length = 0
  }

  function closeTag(parser) {
    if (!parser.tagName) {
      strictFail(parser, 'Weird empty close tag.')
      parser.textNode += '</>'
      parser.state = S.TEXT
      return
    }

    if (parser.script) {
      if (parser.tagName !== 'script') {
        parser.script += '</' + parser.tagName + '>'
        parser.tagName = ''
        parser.state = S.SCRIPT
        return
      }
      emitNode(parser, 'onscript', parser.script)
      parser.script = ''
    }

    // first make sure that the closing tag actually exists.
    // <a><b></c></b></a> will close everything, otherwise.
    var t = parser.tags.length
    var tagName = parser.tagName
    if (!parser.strict) {
      tagName = tagName[parser.looseCase]()
    }
    var closeTo = tagName
    while (t--) {
      var close = parser.tags[t]
      if (close.name !== closeTo) {
        // fail the first time in strict mode
        strictFail(parser, 'Unexpected close tag')
      } else {
        break
      }
    }

    // didn't find it.  we already failed for strict, so just abort.
    if (t < 0) {
      strictFail(parser, 'Unmatched closing tag: ' + parser.tagName)
      parser.textNode += '</' + parser.tagName + '>'
      parser.state = S.TEXT
      return
    }
    parser.tagName = tagName
    var s = parser.tags.length
    while (s-- > t) {
      var tag = (parser.tag = parser.tags.pop())
      parser.tagName = parser.tag.name
      emitNode(parser, 'onclosetag', parser.tagName)

      var x = {}
      for (var i in tag.ns) {
        x[i] = tag.ns[i]
      }

      var parent = parser.tags[parser.tags.length - 1] || parser
      if (parser.opt.xmlns && tag.ns !== parent.ns) {
        // remove namespace bindings introduced by tag
        Object.keys(tag.ns).forEach(function (p) {
          var n = tag.ns[p]
          emitNode(parser, 'onclosenamespace', { prefix: p, uri: n })
        })
      }
    }
    if (t === 0) parser.closedRoot = true
    parser.tagName = parser.attribValue = parser.attribName = ''
    parser.attribList.length = 0
    parser.state = S.TEXT
  }

  function parseEntity(parser) {
    var entity = parser.entity
    var entityLC = entity.toLowerCase()
    var num
    var numStr = ''

    if (parser.ENTITIES[entity]) {
      return parser.ENTITIES[entity]
    }
    if (parser.ENTITIES[entityLC]) {
      return parser.ENTITIES[entityLC]
    }
    entity = entityLC
    if (entity.charAt(0) === '#') {
      if (entity.charAt(1) === 'x') {
        entity = entity.slice(2)
        num = parseInt(entity, 16)
        numStr = num.toString(16)
      } else {
        entity = entity.slice(1)
        num = parseInt(entity, 10)
        numStr = num.toString(10)
      }
    }
    entity = entity.replace(/^0+/, '')
    if (
      isNaN(num) ||
      numStr.toLowerCase() !== entity ||
      num < 0 ||
      num > 0x10ffff
    ) {
      strictFail(parser, 'Invalid character entity')
      return '&' + parser.entity + ';'
    }

    return String.fromCodePoint(num)
  }

  function beginWhiteSpace(parser, c) {
    if (c === '<') {
      parser.state = S.OPEN_WAKA
      parser.startTagPosition = parser.position
    } else if (!isWhitespace(c)) {
      // have to process this as a text node.
      // weird, but happens.
      strictFail(parser, 'Non-whitespace before first tag.')
      parser.textNode = c
      parser.state = S.TEXT
    }
  }

  function charAt(chunk, i) {
    var result = ''
    if (i < chunk.length) {
      result = chunk.charAt(i)
    }
    return result
  }

  function write(chunk) {
    var parser = this
    if (this.error) {
      throw this.error
    }
    if (parser.closed) {
      return error(
        parser,
        'Cannot write after close. Assign an onready handler.'
      )
    }
    if (chunk === null) {
      return end(parser)
    }
    if (typeof chunk === 'object') {
      chunk = chunk.toString()
    }
    var i = 0
    var c = ''
    while (true) {
      c = charAt(chunk, i++)
      parser.c = c

      if (!c) {
        break
      }

      if (parser.trackPosition) {
        parser.position++
        if (c === '\n') {
          parser.line++
          parser.column = 0
        } else {
          parser.column++
        }
      }

      switch (parser.state) {
        case S.BEGIN:
          parser.state = S.BEGIN_WHITESPACE
          if (c === '\uFEFF') {
            continue
          }
          beginWhiteSpace(parser, c)
          continue

        case S.BEGIN_WHITESPACE:
          beginWhiteSpace(parser, c)
          continue

        case S.TEXT:
          if (parser.sawRoot && !parser.closedRoot) {
            var starti = i - 1
            while (c && c !== '<' && c !== '&') {
              c = charAt(chunk, i++)
              if (c && parser.trackPosition) {
                parser.position++
                if (c === '\n') {
                  parser.line++
                  parser.column = 0
                } else {
                  parser.column++
                }
              }
            }
            parser.textNode += chunk.substring(starti, i - 1)
          }
          if (
            c === '<' &&
            !(parser.sawRoot && parser.closedRoot && !parser.strict)
          ) {
            parser.state = S.OPEN_WAKA
            parser.startTagPosition = parser.position
          } else {
            if (
              !isWhitespace(c) &&
              (!parser.sawRoot || parser.closedRoot)
            ) {
              strictFail(parser, 'Text data outside of root node.')
            }
            if (c === '&') {
              parser.state = S.TEXT_ENTITY
            } else {
              parser.textNode += c
            }
          }
          continue

        case S.SCRIPT:
          // only non-strict
          if (c === '<') {
            parser.state = S.SCRIPT_ENDING
          } else {
            parser.script += c
          }
          continue

        case S.SCRIPT_ENDING:
          if (c === '/') {
            parser.state = S.CLOSE_TAG
          } else {
            parser.script += '<' + c
            parser.state = S.SCRIPT
          }
          continue

        case S.OPEN_WAKA:
          // either a /, ?, !, or text is coming next.
          if (c === '!') {
            parser.state = S.SGML_DECL
            parser.sgmlDecl = ''
          } else if (isWhitespace(c)) {
            // wait for it...
          } else if (isMatch(nameStart, c)) {
            parser.state = S.OPEN_TAG
            parser.tagName = c
          } else if (c === '/') {
            parser.state = S.CLOSE_TAG
            parser.tagName = ''
          } else if (c === '?') {
            parser.state = S.PROC_INST
            parser.procInstName = parser.procInstBody = ''
          } else {
            strictFail(parser, 'Unencoded <')
            // if there was some whitespace, then add that in.
            if (parser.startTagPosition + 1 < parser.position) {
              var pad = parser.position - parser.startTagPosition
              c = new Array(pad).join(' ') + c
            }
            parser.textNode += '<' + c
            parser.state = S.TEXT
          }
          continue

        case S.SGML_DECL:
          if (parser.sgmlDecl + c === '--') {
            parser.state = S.COMMENT
            parser.comment = ''
            parser.sgmlDecl = ''
            continue
          }

          if (
            parser.doctype &&
            parser.doctype !== true &&
            parser.sgmlDecl
          ) {
            parser.state = S.DOCTYPE_DTD
            parser.doctype += '<!' + parser.sgmlDecl + c
            parser.sgmlDecl = ''
          } else if ((parser.sgmlDecl + c).toUpperCase() === CDATA) {
            emitNode(parser, 'onopencdata')
            parser.state = S.CDATA
            parser.sgmlDecl = ''
            parser.cdata = ''
          } else if ((parser.sgmlDecl + c).toUpperCase() === DOCTYPE) {
            parser.state = S.DOCTYPE
            if (parser.doctype || parser.sawRoot) {
              strictFail(
                parser,
                'Inappropriately located doctype declaration'
              )
            }
            parser.doctype = ''
            parser.sgmlDecl = ''
          } else if (c === '>') {
            emitNode(parser, 'onsgmldeclaration', parser.sgmlDecl)
            parser.sgmlDecl = ''
            parser.state = S.TEXT
          } else if (isQuote(c)) {
            parser.state = S.SGML_DECL_QUOTED
            parser.sgmlDecl += c
          } else {
            parser.sgmlDecl += c
          }
          continue

        case S.SGML_DECL_QUOTED:
          if (c === parser.q) {
            parser.state = S.SGML_DECL
            parser.q = ''
          }
          parser.sgmlDecl += c
          continue

        case S.DOCTYPE:
          if (c === '>') {
            parser.state = S.TEXT
            emitNode(parser, 'ondoctype', parser.doctype)
            parser.doctype = true // just remember that we saw it.
          } else {
            parser.doctype += c
            if (c === '[') {
              parser.state = S.DOCTYPE_DTD
            } else if (isQuote(c)) {
              parser.state = S.DOCTYPE_QUOTED
              parser.q = c
            }
          }
          continue

        case S.DOCTYPE_QUOTED:
          parser.doctype += c
          if (c === parser.q) {
            parser.q = ''
            parser.state = S.DOCTYPE
          }
          continue

        case S.DOCTYPE_DTD:
          if (c === ']') {
            parser.doctype += c
            parser.state = S.DOCTYPE
          } else if (c === '<') {
            parser.state = S.OPEN_WAKA
            parser.startTagPosition = parser.position
          } else if (isQuote(c)) {
            parser.doctype += c
            parser.state = S.DOCTYPE_DTD_QUOTED
            parser.q = c
          } else {
            parser.doctype += c
          }
          continue

        case S.DOCTYPE_DTD_QUOTED:
          parser.doctype += c
          if (c === parser.q) {
            parser.state = S.DOCTYPE_DTD
            parser.q = ''
          }
          continue

        case S.COMMENT:
          if (c === '-') {
            parser.state = S.COMMENT_ENDING
          } else {
            parser.comment += c
          }
          continue

        case S.COMMENT_ENDING:
          if (c === '-') {
            parser.state = S.COMMENT_ENDED
            parser.comment = textopts(parser.opt, parser.comment)
            if (parser.comment) {
              emitNode(parser, 'oncomment', parser.comment)
            }
            parser.comment = ''
          } else {
            parser.comment += '-' + c
            parser.state = S.COMMENT
          }
          continue

        case S.COMMENT_ENDED:
          if (c !== '>') {
            strictFail(parser, 'Malformed comment')
            // allow <!-- blah -- bloo --> in non-strict mode,
            // which is a comment of " blah -- bloo "
            parser.comment += '--' + c
            parser.state = S.COMMENT
          } else if (parser.doctype && parser.doctype !== true) {
            parser.state = S.DOCTYPE_DTD
          } else {
            parser.state = S.TEXT
          }
          continue

        case S.CDATA:
          var starti = i - 1
          while (c && c !== ']') {
            c = charAt(chunk, i++)
            if (c && parser.trackPosition) {
              parser.position++
              if (c === '\n') {
                parser.line++
                parser.column = 0
              } else {
                parser.column++
              }
            }
          }
          parser.cdata += chunk.substring(starti, i - 1)
          if (c === ']') {
            parser.state = S.CDATA_ENDING
          }
          continue

        case S.CDATA_ENDING:
          if (c === ']') {
            parser.state = S.CDATA_ENDING_2
          } else {
            parser.cdata += ']' + c
            parser.state = S.CDATA
          }
          continue

        case S.CDATA_ENDING_2:
          if (c === '>') {
            if (parser.cdata) {
              emitNode(parser, 'oncdata', parser.cdata)
            }
            emitNode(parser, 'onclosecdata')
            parser.cdata = ''
            parser.state = S.TEXT
          } else if (c === ']') {
            parser.cdata += ']'
          } else {
            parser.cdata += ']]' + c
            parser.state = S.CDATA
          }
          continue

        case S.PROC_INST:
          if (c === '?') {
            parser.state = S.PROC_INST_ENDING
          } else if (isWhitespace(c)) {
            parser.state = S.PROC_INST_BODY
          } else {
            parser.procInstName += c
          }
          continue

        case S.PROC_INST_BODY:
          if (!parser.procInstBody && isWhitespace(c)) {
            continue
          } else if (c === '?') {
            parser.state = S.PROC_INST_ENDING
          } else {
            parser.procInstBody += c
          }
          continue

        case S.PROC_INST_ENDING:
          if (c === '>') {
            emitNode(parser, 'onprocessinginstruction', {
              name: parser.procInstName,
              body: parser.procInstBody,
            })
            parser.procInstName = parser.procInstBody = ''
            parser.state = S.TEXT
          } else {
            parser.procInstBody += '?' + c
            parser.state = S.PROC_INST_BODY
          }
          continue

        case S.OPEN_TAG:
          if (isMatch(nameBody, c)) {
            parser.tagName += c
          } else {
            newTag(parser)
            if (c === '>') {
              openTag(parser)
            } else if (c === '/') {
              parser.state = S.OPEN_TAG_SLASH
            } else {
              if (!isWhitespace(c)) {
                strictFail(parser, 'Invalid character in tag name')
              }
              parser.state = S.ATTRIB
            }
          }
          continue

        case S.OPEN_TAG_SLASH:
          if (c === '>') {
            openTag(parser, true)
            closeTag(parser)
          } else {
            strictFail(
              parser,
              'Forward-slash in opening tag not followed by >'
            )
            parser.state = S.ATTRIB
          }
          continue

        case S.ATTRIB:
          // haven't read the attribute name yet.
          if (isWhitespace(c)) {
            continue
          } else if (c === '>') {
            openTag(parser)
          } else if (c === '/') {
            parser.state = S.OPEN_TAG_SLASH
          } else if (isMatch(nameStart, c)) {
            parser.attribName = c
            parser.attribValue = ''
            parser.state = S.ATTRIB_NAME
          } else {
            strictFail(parser, 'Invalid attribute name')
          }
          continue

        case S.ATTRIB_NAME:
          if (c === '=') {
            parser.state = S.ATTRIB_VALUE
          } else if (c === '>') {
            strictFail(parser, 'Attribute without value')
            parser.attribValue = parser.attribName
            attrib(parser)
            openTag(parser)
          } else if (isWhitespace(c)) {
            parser.state = S.ATTRIB_NAME_SAW_WHITE
          } else if (isMatch(nameBody, c)) {
            parser.attribName += c
          } else {
            strictFail(parser, 'Invalid attribute name')
          }
          continue

        case S.ATTRIB_NAME_SAW_WHITE:
          if (c === '=') {
            parser.state = S.ATTRIB_VALUE
          } else if (isWhitespace(c)) {
            continue
          } else {
            strictFail(parser, 'Attribute without value')
            parser.tag.attributes[parser.attribName] = ''
            parser.attribValue = ''
            emitNode(parser, 'onattribute', {
              name: parser.attribName,
              value: '',
            })
            parser.attribName = ''
            if (c === '>') {
              openTag(parser)
            } else if (isMatch(nameStart, c)) {
              parser.attribName = c
              parser.state = S.ATTRIB_NAME
            } else {
              strictFail(parser, 'Invalid attribute name')
              parser.state = S.ATTRIB
            }
          }
          continue

        case S.ATTRIB_VALUE:
          if (isWhitespace(c)) {
            continue
          } else if (isQuote(c)) {
            parser.q = c
            parser.state = S.ATTRIB_VALUE_QUOTED
          } else {
            if (!parser.opt.unquotedAttributeValues) {
              error(parser, 'Unquoted attribute value')
            }
            parser.state = S.ATTRIB_VALUE_UNQUOTED
            parser.attribValue = c
          }
          continue

        case S.ATTRIB_VALUE_QUOTED:
          if (c !== parser.q) {
            if (c === '&') {
              parser.state = S.ATTRIB_VALUE_ENTITY_Q
            } else {
              parser.attribValue += c
            }
            continue
          }
          attrib(parser)
          parser.q = ''
          parser.state = S.ATTRIB_VALUE_CLOSED
          continue

        case S.ATTRIB_VALUE_CLOSED:
          if (isWhitespace(c)) {
            parser.state = S.ATTRIB
          } else if (c === '>') {
            openTag(parser)
          } else if (c === '/') {
            parser.state = S.OPEN_TAG_SLASH
          } else if (isMatch(nameStart, c)) {
            strictFail(parser, 'No whitespace between attributes')
            parser.attribName = c
            parser.attribValue = ''
            parser.state = S.ATTRIB_NAME
          } else {
            strictFail(parser, 'Invalid attribute name')
          }
          continue

        case S.ATTRIB_VALUE_UNQUOTED:
          if (!isAttribEnd(c)) {
            if (c === '&') {
              parser.state = S.ATTRIB_VALUE_ENTITY_U
            } else {
              parser.attribValue += c
            }
            continue
          }
          attrib(parser)
          if (c === '>') {
            openTag(parser)
          } else {
            parser.state = S.ATTRIB
          }
          continue

        case S.CLOSE_TAG:
          if (!parser.tagName) {
            if (isWhitespace(c)) {
              continue
            } else if (notMatch(nameStart, c)) {
              if (parser.script) {
                parser.script += '</' + c
                parser.state = S.SCRIPT
              } else {
                strictFail(parser, 'Invalid tagname in closing tag.')
              }
            } else {
              parser.tagName = c
            }
          } else if (c === '>') {
            closeTag(parser)
          } else if (isMatch(nameBody, c)) {
            parser.tagName += c
          } else if (parser.script) {
            parser.script += '</' + parser.tagName
            parser.tagName = ''
            parser.state = S.SCRIPT
          } else {
            if (!isWhitespace(c)) {
              strictFail(parser, 'Invalid tagname in closing tag')
            }
            parser.state = S.CLOSE_TAG_SAW_WHITE
          }
          continue

        case S.CLOSE_TAG_SAW_WHITE:
          if (isWhitespace(c)) {
            continue
          }
          if (c === '>') {
            closeTag(parser)
          } else {
            strictFail(parser, 'Invalid characters in closing tag')
          }
          continue

        case S.TEXT_ENTITY:
        case S.ATTRIB_VALUE_ENTITY_Q:
        case S.ATTRIB_VALUE_ENTITY_U:
          var returnState
          var buffer
          switch (parser.state) {
            case S.TEXT_ENTITY:
              returnState = S.TEXT
              buffer = 'textNode'
              break

            case S.ATTRIB_VALUE_ENTITY_Q:
              returnState = S.ATTRIB_VALUE_QUOTED
              buffer = 'attribValue'
              break

            case S.ATTRIB_VALUE_ENTITY_U:
              returnState = S.ATTRIB_VALUE_UNQUOTED
              buffer = 'attribValue'
              break
          }

          if (c === ';') {
            var parsedEntity = parseEntity(parser)
            if (
              parser.opt.unparsedEntities &&
              !Object.values(sax.XML_ENTITIES).includes(parsedEntity)
            ) {
              parser.entity = ''
              parser.state = returnState
              parser.write(parsedEntity)
            } else {
              parser[buffer] += parsedEntity
              parser.entity = ''
              parser.state = returnState
            }
          } else if (
            isMatch(parser.entity.length ? entityBody : entityStart, c)
          ) {
            parser.entity += c
          } else {
            strictFail(parser, 'Invalid character in entity name')
            parser[buffer] += '&' + parser.entity + c
            parser.entity = ''
            parser.state = returnState
          }

          continue

        default: /* istanbul ignore next */ {
          throw new Error(parser, 'Unknown state: ' + parser.state)
        }
      }
    } // while

    if (parser.position >= parser.bufferCheckPosition) {
      checkBufferLength(parser)
    }
    return parser
  }

  /*! http://mths.be/fromcodepoint v0.1.0 by @mathias */
  /* istanbul ignore next */
  if (!String.fromCodePoint) {
    ;(function () {
      var stringFromCharCode = String.fromCharCode
      var floor = Math.floor
      var fromCodePoint = function () {
        var MAX_SIZE = 0x4000
        var codeUnits = []
        var highSurrogate
        var lowSurrogate
        var index = -1
        var length = arguments.length
        if (!length) {
          return ''
        }
        var result = ''
        while (++index < length) {
          var codePoint = Number(arguments[index])
          if (
            !isFinite(codePoint) || // `NaN`, `+Infinity`, or `-Infinity`
            codePoint < 0 || // not a valid Unicode code point
            codePoint > 0x10ffff || // not a valid Unicode code point
            floor(codePoint) !== codePoint // not an integer
          ) {
            throw RangeError('Invalid code point: ' + codePoint)
          }
          if (codePoint <= 0xffff) {
            // BMP code point
            codeUnits.push(codePoint)
          } else {
            // Astral code point; split in surrogate halves
            // http://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
            codePoint -= 0x10000
            highSurrogate = (codePoint >> 10) + 0xd800
            lowSurrogate = (codePoint % 0x400) + 0xdc00
            codeUnits.push(highSurrogate, lowSurrogate)
          }
          if (index + 1 === length || codeUnits.length > MAX_SIZE) {
            result += stringFromCharCode.apply(null, codeUnits)
            codeUnits.length = 0
          }
        }
        return result
      }
      /* istanbul ignore next */
      if (Object.defineProperty) {
        Object.defineProperty(String, 'fromCodePoint', {
          value: fromCodePoint,
          configurable: true,
          writable: true,
        })
      } else {
        String.fromCodePoint = fromCodePoint
      }
    })()
  }
})( false ? (0) : exports)


/***/ },

/***/ 4923
(module) {

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

}).call(this);


/***/ },

/***/ 1737
(module) {

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

}).call(this);


/***/ },

/***/ 9241
(module) {

// Generated by CoffeeScript 1.12.7
(function() {
  var assign, getValue, isArray, isEmpty, isFunction, isObject, isPlainObject,
    slice = [].slice,
    hasProp = {}.hasOwnProperty;

  assign = function() {
    var i, key, len, source, sources, target;
    target = arguments[0], sources = 2 <= arguments.length ? slice.call(arguments, 1) : [];
    if (isFunction(Object.assign)) {
      Object.assign.apply(null, arguments);
    } else {
      for (i = 0, len = sources.length; i < len; i++) {
        source = sources[i];
        if (source != null) {
          for (key in source) {
            if (!hasProp.call(source, key)) continue;
            target[key] = source[key];
          }
        }
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
    if (isFunction(Array.isArray)) {
      return Array.isArray(val);
    } else {
      return Object.prototype.toString.call(val) === '[object Array]';
    }
  };

  isEmpty = function(val) {
    var key;
    if (isArray(val)) {
      return !val.length;
    } else {
      for (key in val) {
        if (!hasProp.call(val, key)) continue;
        return false;
      }
      return true;
    }
  };

  isPlainObject = function(val) {
    var ctor, proto;
    return isObject(val) && (proto = Object.getPrototypeOf(val)) && (ctor = proto.constructor) && (typeof ctor === 'function') && (ctor instanceof ctor) && (Function.prototype.toString.call(ctor) === Function.prototype.toString.call(Object));
  };

  getValue = function(obj) {
    if (isFunction(obj.valueOf)) {
      return obj.valueOf();
    } else {
      return obj;
    }
  };

  module.exports.assign = assign;

  module.exports.isFunction = isFunction;

  module.exports.isObject = isObject;

  module.exports.isArray = isArray;

  module.exports.isEmpty = isEmpty;

  module.exports.isPlainObject = isPlainObject;

  module.exports.getValue = getValue;

}).call(this);


/***/ },

/***/ 8753
(module) {

// Generated by CoffeeScript 1.12.7
(function() {
  module.exports = {
    None: 0,
    OpenTag: 1,
    InsideTag: 2,
    CloseTag: 3
  };

}).call(this);


/***/ },

/***/ 4238
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLAttribute, XMLNode;

  NodeType = __webpack_require__(1737);

  XMLNode = __webpack_require__(468);

  module.exports = XMLAttribute = (function() {
    function XMLAttribute(parent, name, value) {
      this.parent = parent;
      if (this.parent) {
        this.options = this.parent.options;
        this.stringify = this.parent.stringify;
      }
      if (name == null) {
        throw new Error("Missing attribute name. " + this.debugInfo(name));
      }
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
      if (name == null) {
        return "parent: <" + this.parent.name + ">";
      } else {
        return "attribute: {" + name + "}, parent: <" + this.parent.name + ">";
      }
    };

    XMLAttribute.prototype.isEqualNode = function(node) {
      if (node.namespaceURI !== this.namespaceURI) {
        return false;
      }
      if (node.prefix !== this.prefix) {
        return false;
      }
      if (node.localName !== this.localName) {
        return false;
      }
      if (node.value !== this.value) {
        return false;
      }
      return true;
    };

    return XMLAttribute;

  })();

}).call(this);


/***/ },

/***/ 2691
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLCData, XMLCharacterData,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  NodeType = __webpack_require__(1737);

  XMLCharacterData = __webpack_require__(7457);

  module.exports = XMLCData = (function(superClass) {
    extend(XMLCData, superClass);

    function XMLCData(parent, text) {
      XMLCData.__super__.constructor.call(this, parent);
      if (text == null) {
        throw new Error("Missing CDATA text. " + this.debugInfo());
      }
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

  })(XMLCharacterData);

}).call(this);


/***/ },

/***/ 7457
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLCharacterData, XMLNode,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  XMLNode = __webpack_require__(468);

  module.exports = XMLCharacterData = (function(superClass) {
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
      if (!XMLCharacterData.__super__.isEqualNode.apply(this, arguments).isEqualNode(node)) {
        return false;
      }
      if (node.data !== this.data) {
        return false;
      }
      return true;
    };

    return XMLCharacterData;

  })(XMLNode);

}).call(this);


/***/ },

/***/ 2679
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLCharacterData, XMLComment,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  NodeType = __webpack_require__(1737);

  XMLCharacterData = __webpack_require__(7457);

  module.exports = XMLComment = (function(superClass) {
    extend(XMLComment, superClass);

    function XMLComment(parent, text) {
      XMLComment.__super__.constructor.call(this, parent);
      if (text == null) {
        throw new Error("Missing comment text. " + this.debugInfo());
      }
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

  })(XMLCharacterData);

}).call(this);


/***/ },

/***/ 3074
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLDOMConfiguration, XMLDOMErrorHandler, XMLDOMStringList;

  XMLDOMErrorHandler = __webpack_require__(5660);

  XMLDOMStringList = __webpack_require__(2527);

  module.exports = XMLDOMConfiguration = (function() {
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
      if (this.params.hasOwnProperty(name)) {
        return this.params[name];
      } else {
        return null;
      }
    };

    XMLDOMConfiguration.prototype.canSetParameter = function(name, value) {
      return true;
    };

    XMLDOMConfiguration.prototype.setParameter = function(name, value) {
      if (value != null) {
        return this.params[name] = value;
      } else {
        return delete this.params[name];
      }
    };

    return XMLDOMConfiguration;

  })();

}).call(this);


/***/ },

/***/ 5660
(module) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLDOMErrorHandler;

  module.exports = XMLDOMErrorHandler = (function() {
    function XMLDOMErrorHandler() {}

    XMLDOMErrorHandler.prototype.handleError = function(error) {
      throw new Error(error);
    };

    return XMLDOMErrorHandler;

  })();

}).call(this);


/***/ },

/***/ 7260
(module) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLDOMImplementation;

  module.exports = XMLDOMImplementation = (function() {
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

  })();

}).call(this);


/***/ },

/***/ 2527
(module) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLDOMStringList;

  module.exports = XMLDOMStringList = (function() {
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

  })();

}).call(this);


/***/ },

/***/ 4111
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLDTDAttList, XMLNode,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  module.exports = XMLDTDAttList = (function(superClass) {
    extend(XMLDTDAttList, superClass);

    function XMLDTDAttList(parent, elementName, attributeName, attributeType, defaultValueType, defaultValue) {
      XMLDTDAttList.__super__.constructor.call(this, parent);
      if (elementName == null) {
        throw new Error("Missing DTD element name. " + this.debugInfo());
      }
      if (attributeName == null) {
        throw new Error("Missing DTD attribute name. " + this.debugInfo(elementName));
      }
      if (!attributeType) {
        throw new Error("Missing DTD attribute type. " + this.debugInfo(elementName));
      }
      if (!defaultValueType) {
        throw new Error("Missing DTD attribute default. " + this.debugInfo(elementName));
      }
      if (defaultValueType.indexOf('#') !== 0) {
        defaultValueType = '#' + defaultValueType;
      }
      if (!defaultValueType.match(/^(#REQUIRED|#IMPLIED|#FIXED|#DEFAULT)$/)) {
        throw new Error("Invalid default value type; expected: #REQUIRED, #IMPLIED, #FIXED or #DEFAULT. " + this.debugInfo(elementName));
      }
      if (defaultValue && !defaultValueType.match(/^(#FIXED|#DEFAULT)$/)) {
        throw new Error("Default value only applies to #FIXED or #DEFAULT. " + this.debugInfo(elementName));
      }
      this.elementName = this.stringify.name(elementName);
      this.type = NodeType.AttributeDeclaration;
      this.attributeName = this.stringify.name(attributeName);
      this.attributeType = this.stringify.dtdAttType(attributeType);
      if (defaultValue) {
        this.defaultValue = this.stringify.dtdAttDefault(defaultValue);
      }
      this.defaultValueType = defaultValueType;
    }

    XMLDTDAttList.prototype.toString = function(options) {
      return this.options.writer.dtdAttList(this, this.options.writer.filterOptions(options));
    };

    return XMLDTDAttList;

  })(XMLNode);

}).call(this);


/***/ },

/***/ 7696
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLDTDElement, XMLNode,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  module.exports = XMLDTDElement = (function(superClass) {
    extend(XMLDTDElement, superClass);

    function XMLDTDElement(parent, name, value) {
      XMLDTDElement.__super__.constructor.call(this, parent);
      if (name == null) {
        throw new Error("Missing DTD element name. " + this.debugInfo());
      }
      if (!value) {
        value = '(#PCDATA)';
      }
      if (Array.isArray(value)) {
        value = '(' + value.join(',') + ')';
      }
      this.name = this.stringify.name(name);
      this.type = NodeType.ElementDeclaration;
      this.value = this.stringify.dtdElementValue(value);
    }

    XMLDTDElement.prototype.toString = function(options) {
      return this.options.writer.dtdElement(this, this.options.writer.filterOptions(options));
    };

    return XMLDTDElement;

  })(XMLNode);

}).call(this);


/***/ },

/***/ 5529
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLDTDEntity, XMLNode, isObject,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  isObject = (__webpack_require__(9241).isObject);

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  module.exports = XMLDTDEntity = (function(superClass) {
    extend(XMLDTDEntity, superClass);

    function XMLDTDEntity(parent, pe, name, value) {
      XMLDTDEntity.__super__.constructor.call(this, parent);
      if (name == null) {
        throw new Error("Missing DTD entity name. " + this.debugInfo(name));
      }
      if (value == null) {
        throw new Error("Missing DTD entity value. " + this.debugInfo(name));
      }
      this.pe = !!pe;
      this.name = this.stringify.name(name);
      this.type = NodeType.EntityDeclaration;
      if (!isObject(value)) {
        this.value = this.stringify.dtdEntityValue(value);
        this.internal = true;
      } else {
        if (!value.pubID && !value.sysID) {
          throw new Error("Public and/or system identifiers are required for an external entity. " + this.debugInfo(name));
        }
        if (value.pubID && !value.sysID) {
          throw new Error("System identifier is required for a public external entity. " + this.debugInfo(name));
        }
        this.internal = false;
        if (value.pubID != null) {
          this.pubID = this.stringify.dtdPubID(value.pubID);
        }
        if (value.sysID != null) {
          this.sysID = this.stringify.dtdSysID(value.sysID);
        }
        if (value.nData != null) {
          this.nData = this.stringify.dtdNData(value.nData);
        }
        if (this.pe && this.nData) {
          throw new Error("Notation declaration is not allowed in a parameter entity. " + this.debugInfo(name));
        }
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

  })(XMLNode);

}).call(this);


/***/ },

/***/ 8012
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLDTDNotation, XMLNode,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  module.exports = XMLDTDNotation = (function(superClass) {
    extend(XMLDTDNotation, superClass);

    function XMLDTDNotation(parent, name, value) {
      XMLDTDNotation.__super__.constructor.call(this, parent);
      if (name == null) {
        throw new Error("Missing DTD notation name. " + this.debugInfo(name));
      }
      if (!value.pubID && !value.sysID) {
        throw new Error("Public or system identifiers are required for an external entity. " + this.debugInfo(name));
      }
      this.name = this.stringify.name(name);
      this.type = NodeType.NotationDeclaration;
      if (value.pubID != null) {
        this.pubID = this.stringify.dtdPubID(value.pubID);
      }
      if (value.sysID != null) {
        this.sysID = this.stringify.dtdSysID(value.sysID);
      }
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

  })(XMLNode);

}).call(this);


/***/ },

/***/ 4130
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLDeclaration, XMLNode, isObject,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  isObject = (__webpack_require__(9241).isObject);

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  module.exports = XMLDeclaration = (function(superClass) {
    extend(XMLDeclaration, superClass);

    function XMLDeclaration(parent, version, encoding, standalone) {
      var ref;
      XMLDeclaration.__super__.constructor.call(this, parent);
      if (isObject(version)) {
        ref = version, version = ref.version, encoding = ref.encoding, standalone = ref.standalone;
      }
      if (!version) {
        version = '1.0';
      }
      this.type = NodeType.Declaration;
      this.version = this.stringify.xmlVersion(version);
      if (encoding != null) {
        this.encoding = this.stringify.xmlEncoding(encoding);
      }
      if (standalone != null) {
        this.standalone = this.stringify.xmlStandalone(standalone);
      }
    }

    XMLDeclaration.prototype.toString = function(options) {
      return this.options.writer.declaration(this, this.options.writer.filterOptions(options));
    };

    return XMLDeclaration;

  })(XMLNode);

}).call(this);


/***/ },

/***/ 6376
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLDTDAttList, XMLDTDElement, XMLDTDEntity, XMLDTDNotation, XMLDocType, XMLNamedNodeMap, XMLNode, isObject,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  isObject = (__webpack_require__(9241).isObject);

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  XMLDTDAttList = __webpack_require__(4111);

  XMLDTDEntity = __webpack_require__(5529);

  XMLDTDElement = __webpack_require__(7696);

  XMLDTDNotation = __webpack_require__(8012);

  XMLNamedNodeMap = __webpack_require__(4797);

  module.exports = XMLDocType = (function(superClass) {
    extend(XMLDocType, superClass);

    function XMLDocType(parent, pubID, sysID) {
      var child, i, len, ref, ref1, ref2;
      XMLDocType.__super__.constructor.call(this, parent);
      this.type = NodeType.DocType;
      if (parent.children) {
        ref = parent.children;
        for (i = 0, len = ref.length; i < len; i++) {
          child = ref[i];
          if (child.type === NodeType.Element) {
            this.name = child.name;
            break;
          }
        }
      }
      this.documentObject = parent;
      if (isObject(pubID)) {
        ref1 = pubID, pubID = ref1.pubID, sysID = ref1.sysID;
      }
      if (sysID == null) {
        ref2 = [pubID, sysID], sysID = ref2[0], pubID = ref2[1];
      }
      if (pubID != null) {
        this.pubID = this.stringify.dtdPubID(pubID);
      }
      if (sysID != null) {
        this.sysID = this.stringify.dtdSysID(sysID);
      }
    }

    Object.defineProperty(XMLDocType.prototype, 'entities', {
      get: function() {
        var child, i, len, nodes, ref;
        nodes = {};
        ref = this.children;
        for (i = 0, len = ref.length; i < len; i++) {
          child = ref[i];
          if ((child.type === NodeType.EntityDeclaration) && !child.pe) {
            nodes[child.name] = child;
          }
        }
        return new XMLNamedNodeMap(nodes);
      }
    });

    Object.defineProperty(XMLDocType.prototype, 'notations', {
      get: function() {
        var child, i, len, nodes, ref;
        nodes = {};
        ref = this.children;
        for (i = 0, len = ref.length; i < len; i++) {
          child = ref[i];
          if (child.type === NodeType.NotationDeclaration) {
            nodes[child.name] = child;
          }
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
      if (!XMLDocType.__super__.isEqualNode.apply(this, arguments).isEqualNode(node)) {
        return false;
      }
      if (node.name !== this.name) {
        return false;
      }
      if (node.publicId !== this.publicId) {
        return false;
      }
      if (node.systemId !== this.systemId) {
        return false;
      }
      return true;
    };

    return XMLDocType;

  })(XMLNode);

}).call(this);


/***/ },

/***/ 1933
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLDOMConfiguration, XMLDOMImplementation, XMLDocument, XMLNode, XMLStringWriter, XMLStringifier, isPlainObject,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  isPlainObject = (__webpack_require__(9241).isPlainObject);

  XMLDOMImplementation = __webpack_require__(7260);

  XMLDOMConfiguration = __webpack_require__(3074);

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  XMLStringifier = __webpack_require__(3976);

  XMLStringWriter = __webpack_require__(382);

  module.exports = XMLDocument = (function(superClass) {
    extend(XMLDocument, superClass);

    function XMLDocument(options) {
      XMLDocument.__super__.constructor.call(this, null);
      this.name = "#document";
      this.type = NodeType.Document;
      this.documentURI = null;
      this.domConfig = new XMLDOMConfiguration();
      options || (options = {});
      if (!options.writer) {
        options.writer = new XMLStringWriter();
      }
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
        for (i = 0, len = ref.length; i < len; i++) {
          child = ref[i];
          if (child.type === NodeType.DocType) {
            return child;
          }
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
        if (this.children.length !== 0 && this.children[0].type === NodeType.Declaration) {
          return this.children[0].encoding;
        } else {
          return null;
        }
      }
    });

    Object.defineProperty(XMLDocument.prototype, 'xmlStandalone', {
      get: function() {
        if (this.children.length !== 0 && this.children[0].type === NodeType.Declaration) {
          return this.children[0].standalone === 'yes';
        } else {
          return false;
        }
      }
    });

    Object.defineProperty(XMLDocument.prototype, 'xmlVersion', {
      get: function() {
        if (this.children.length !== 0 && this.children[0].type === NodeType.Declaration) {
          return this.children[0].version;
        } else {
          return "1.0";
        }
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
      if (!writer) {
        writer = this.options.writer;
      } else if (isPlainObject(writer)) {
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

  })(XMLNode);

}).call(this);


/***/ },

/***/ 400
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, WriterState, XMLAttribute, XMLCData, XMLComment, XMLDTDAttList, XMLDTDElement, XMLDTDEntity, XMLDTDNotation, XMLDeclaration, XMLDocType, XMLDocument, XMLDocumentCB, XMLElement, XMLProcessingInstruction, XMLRaw, XMLStringWriter, XMLStringifier, XMLText, getValue, isFunction, isObject, isPlainObject, ref,
    hasProp = {}.hasOwnProperty;

  ref = __webpack_require__(9241), isObject = ref.isObject, isFunction = ref.isFunction, isPlainObject = ref.isPlainObject, getValue = ref.getValue;

  NodeType = __webpack_require__(1737);

  XMLDocument = __webpack_require__(1933);

  XMLElement = __webpack_require__(3906);

  XMLCData = __webpack_require__(2691);

  XMLComment = __webpack_require__(2679);

  XMLRaw = __webpack_require__(1268);

  XMLText = __webpack_require__(2535);

  XMLProcessingInstruction = __webpack_require__(5915);

  XMLDeclaration = __webpack_require__(4130);

  XMLDocType = __webpack_require__(6376);

  XMLDTDAttList = __webpack_require__(4111);

  XMLDTDEntity = __webpack_require__(5529);

  XMLDTDElement = __webpack_require__(7696);

  XMLDTDNotation = __webpack_require__(8012);

  XMLAttribute = __webpack_require__(4238);

  XMLStringifier = __webpack_require__(3976);

  XMLStringWriter = __webpack_require__(382);

  WriterState = __webpack_require__(8753);

  module.exports = XMLDocumentCB = (function() {
    function XMLDocumentCB(options, onData, onEnd) {
      var writerOptions;
      this.name = "?xml";
      this.type = NodeType.Document;
      options || (options = {});
      writerOptions = {};
      if (!options.writer) {
        options.writer = new XMLStringWriter();
      } else if (isPlainObject(options.writer)) {
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
      switch (node.type) {
        case NodeType.CData:
          this.cdata(node.value);
          break;
        case NodeType.Comment:
          this.comment(node.value);
          break;
        case NodeType.Element:
          attributes = {};
          ref1 = node.attribs;
          for (attName in ref1) {
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
      for (i = 0, len = ref2.length; i < len; i++) {
        child = ref2[i];
        this.createChildNode(child);
        if (child.type === NodeType.Element) {
          this.up();
        }
      }
      return this;
    };

    XMLDocumentCB.prototype.dummy = function() {
      return this;
    };

    XMLDocumentCB.prototype.node = function(name, attributes, text) {
      var ref1;
      if (name == null) {
        throw new Error("Missing node name.");
      }
      if (this.root && this.currentLevel === -1) {
        throw new Error("Document can only have one root node. " + this.debugInfo(name));
      }
      this.openCurrent();
      name = getValue(name);
      if (attributes == null) {
        attributes = {};
      }
      attributes = getValue(attributes);
      if (!isObject(attributes)) {
        ref1 = [attributes, text], text = ref1[0], attributes = ref1[1];
      }
      this.currentNode = new XMLElement(this, name, attributes);
      this.currentNode.children = false;
      this.currentLevel++;
      this.openTags[this.currentLevel] = this.currentNode;
      if (text != null) {
        this.text(text);
      }
      return this;
    };

    XMLDocumentCB.prototype.element = function(name, attributes, text) {
      var child, i, len, oldValidationFlag, ref1, root;
      if (this.currentNode && this.currentNode.type === NodeType.DocType) {
        this.dtdElement.apply(this, arguments);
      } else {
        if (Array.isArray(name) || isObject(name) || isFunction(name)) {
          oldValidationFlag = this.options.noValidation;
          this.options.noValidation = true;
          root = new XMLDocument(this.options).element('TEMP_ROOT');
          root.element(name);
          this.options.noValidation = oldValidationFlag;
          ref1 = root.children;
          for (i = 0, len = ref1.length; i < len; i++) {
            child = ref1[i];
            this.createChildNode(child);
            if (child.type === NodeType.Element) {
              this.up();
            }
          }
        } else {
          this.node(name, attributes, text);
        }
      }
      return this;
    };

    XMLDocumentCB.prototype.attribute = function(name, value) {
      var attName, attValue;
      if (!this.currentNode || this.currentNode.children) {
        throw new Error("att() can only be used immediately after an ele() call in callback mode. " + this.debugInfo(name));
      }
      if (name != null) {
        name = getValue(name);
      }
      if (isObject(name)) {
        for (attName in name) {
          if (!hasProp.call(name, attName)) continue;
          attValue = name[attName];
          this.attribute(attName, attValue);
        }
      } else {
        if (isFunction(value)) {
          value = value.apply();
        }
        if (this.options.keepNullAttributes && (value == null)) {
          this.currentNode.attribs[name] = new XMLAttribute(this, name, "");
        } else if (value != null) {
          this.currentNode.attribs[name] = new XMLAttribute(this, name, value);
        }
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
      if (target != null) {
        target = getValue(target);
      }
      if (value != null) {
        value = getValue(value);
      }
      if (Array.isArray(target)) {
        for (i = 0, len = target.length; i < len; i++) {
          insTarget = target[i];
          this.instruction(insTarget);
        }
      } else if (isObject(target)) {
        for (insTarget in target) {
          if (!hasProp.call(target, insTarget)) continue;
          insValue = target[insTarget];
          this.instruction(insTarget, insValue);
        }
      } else {
        if (isFunction(value)) {
          value = value.apply();
        }
        node = new XMLProcessingInstruction(this, target, value);
        this.onData(this.writer.processingInstruction(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
      }
      return this;
    };

    XMLDocumentCB.prototype.declaration = function(version, encoding, standalone) {
      var node;
      this.openCurrent();
      if (this.documentStarted) {
        throw new Error("declaration() must be the first node.");
      }
      node = new XMLDeclaration(this, version, encoding, standalone);
      this.onData(this.writer.declaration(node, this.writerOptions, this.currentLevel + 1), this.currentLevel + 1);
      return this;
    };

    XMLDocumentCB.prototype.doctype = function(root, pubID, sysID) {
      this.openCurrent();
      if (root == null) {
        throw new Error("Missing root node name.");
      }
      if (this.root) {
        throw new Error("dtd() must come before the root node.");
      }
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
      if (this.currentLevel < 0) {
        throw new Error("The document node has no parent.");
      }
      if (this.currentNode) {
        if (this.currentNode.children) {
          this.closeNode(this.currentNode);
        } else {
          this.openNode(this.currentNode);
        }
        this.currentNode = null;
      } else {
        this.closeNode(this.openTags[this.currentLevel]);
      }
      delete this.openTags[this.currentLevel];
      this.currentLevel--;
      return this;
    };

    XMLDocumentCB.prototype.end = function() {
      while (this.currentLevel >= 0) {
        this.up();
      }
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
        if (!this.root && this.currentLevel === 0 && node.type === NodeType.Element) {
          this.root = node;
        }
        chunk = '';
        if (node.type === NodeType.Element) {
          this.writerOptions.state = WriterState.OpenTag;
          chunk = this.writer.indent(node, this.writerOptions, this.currentLevel) + '<' + node.name;
          ref1 = node.attribs;
          for (name in ref1) {
            if (!hasProp.call(ref1, name)) continue;
            att = ref1[name];
            chunk += this.writer.attribute(att, this.writerOptions, this.currentLevel);
          }
          chunk += (node.children ? '>' : '/>') + this.writer.endline(node, this.writerOptions, this.currentLevel);
          this.writerOptions.state = WriterState.InsideTag;
        } else {
          this.writerOptions.state = WriterState.OpenTag;
          chunk = this.writer.indent(node, this.writerOptions, this.currentLevel) + '<!DOCTYPE ' + node.rootNodeName;
          if (node.pubID && node.sysID) {
            chunk += ' PUBLIC "' + node.pubID + '" "' + node.sysID + '"';
          } else if (node.sysID) {
            chunk += ' SYSTEM "' + node.sysID + '"';
          }
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
        if (node.type === NodeType.Element) {
          chunk = this.writer.indent(node, this.writerOptions, this.currentLevel) + '</' + node.name + '>' + this.writer.endline(node, this.writerOptions, this.currentLevel);
        } else {
          chunk = this.writer.indent(node, this.writerOptions, this.currentLevel) + ']>' + this.writer.endline(node, this.writerOptions, this.currentLevel);
        }
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
      if (name == null) {
        return "";
      } else {
        return "node: <" + name + ">";
      }
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
      if (this.currentNode && this.currentNode.type === NodeType.DocType) {
        return this.attList.apply(this, arguments);
      } else {
        return this.attribute.apply(this, arguments);
      }
    };

    XMLDocumentCB.prototype.a = function() {
      if (this.currentNode && this.currentNode.type === NodeType.DocType) {
        return this.attList.apply(this, arguments);
      } else {
        return this.attribute.apply(this, arguments);
      }
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

  })();

}).call(this);


/***/ },

/***/ 1218
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLDummy, XMLNode,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  module.exports = XMLDummy = (function(superClass) {
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

  })(XMLNode);

}).call(this);


/***/ },

/***/ 3906
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLAttribute, XMLElement, XMLNamedNodeMap, XMLNode, getValue, isFunction, isObject, ref,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  ref = __webpack_require__(9241), isObject = ref.isObject, isFunction = ref.isFunction, getValue = ref.getValue;

  XMLNode = __webpack_require__(468);

  NodeType = __webpack_require__(1737);

  XMLAttribute = __webpack_require__(4238);

  XMLNamedNodeMap = __webpack_require__(4797);

  module.exports = XMLElement = (function(superClass) {
    extend(XMLElement, superClass);

    function XMLElement(parent, name, attributes) {
      var child, j, len, ref1;
      XMLElement.__super__.constructor.call(this, parent);
      if (name == null) {
        throw new Error("Missing element name. " + this.debugInfo());
      }
      this.name = this.stringify.name(name);
      this.type = NodeType.Element;
      this.attribs = {};
      this.schemaTypeInfo = null;
      if (attributes != null) {
        this.attribute(attributes);
      }
      if (parent.type === NodeType.Document) {
        this.isRoot = true;
        this.documentObject = parent;
        parent.rootObject = this;
        if (parent.children) {
          ref1 = parent.children;
          for (j = 0, len = ref1.length; j < len; j++) {
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
        if (!this.attributeMap || !this.attributeMap.nodes) {
          this.attributeMap = new XMLNamedNodeMap(this.attribs);
        }
        return this.attributeMap;
      }
    });

    XMLElement.prototype.clone = function() {
      var att, attName, clonedSelf, ref1;
      clonedSelf = Object.create(this);
      if (clonedSelf.isRoot) {
        clonedSelf.documentObject = null;
      }
      clonedSelf.attribs = {};
      ref1 = this.attribs;
      for (attName in ref1) {
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
      if (name != null) {
        name = getValue(name);
      }
      if (isObject(name)) {
        for (attName in name) {
          if (!hasProp.call(name, attName)) continue;
          attValue = name[attName];
          this.attribute(attName, attValue);
        }
      } else {
        if (isFunction(value)) {
          value = value.apply();
        }
        if (this.options.keepNullAttributes && (value == null)) {
          this.attribs[name] = new XMLAttribute(this, name, "");
        } else if (value != null) {
          this.attribs[name] = new XMLAttribute(this, name, value);
        }
      }
      return this;
    };

    XMLElement.prototype.removeAttribute = function(name) {
      var attName, j, len;
      if (name == null) {
        throw new Error("Missing attribute name. " + this.debugInfo());
      }
      name = getValue(name);
      if (Array.isArray(name)) {
        for (j = 0, len = name.length; j < len; j++) {
          attName = name[j];
          delete this.attribs[attName];
        }
      } else {
        delete this.attribs[name];
      }
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
      if (this.attribs.hasOwnProperty(name)) {
        return this.attribs[name].value;
      } else {
        return null;
      }
    };

    XMLElement.prototype.setAttribute = function(name, value) {
      throw new Error("This DOM method is not implemented." + this.debugInfo());
    };

    XMLElement.prototype.getAttributeNode = function(name) {
      if (this.attribs.hasOwnProperty(name)) {
        return this.attribs[name];
      } else {
        return null;
      }
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
      if (this.attribs.hasOwnProperty(name)) {
        return this.attribs[name].isId;
      } else {
        return isId;
      }
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
      if (!XMLElement.__super__.isEqualNode.apply(this, arguments).isEqualNode(node)) {
        return false;
      }
      if (node.namespaceURI !== this.namespaceURI) {
        return false;
      }
      if (node.prefix !== this.prefix) {
        return false;
      }
      if (node.localName !== this.localName) {
        return false;
      }
      if (node.attribs.length !== this.attribs.length) {
        return false;
      }
      for (i = j = 0, ref1 = this.attribs.length - 1; 0 <= ref1 ? j <= ref1 : j >= ref1; i = 0 <= ref1 ? ++j : --j) {
        if (!this.attribs[i].isEqualNode(node.attribs[i])) {
          return false;
        }
      }
      return true;
    };

    return XMLElement;

  })(XMLNode);

}).call(this);


/***/ },

/***/ 4797
(module) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLNamedNodeMap;

  module.exports = XMLNamedNodeMap = (function() {
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

  })();

}).call(this);


/***/ },

/***/ 468
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var DocumentPosition, NodeType, XMLCData, XMLComment, XMLDeclaration, XMLDocType, XMLDummy, XMLElement, XMLNamedNodeMap, XMLNode, XMLNodeList, XMLProcessingInstruction, XMLRaw, XMLText, getValue, isEmpty, isFunction, isObject, ref1,
    hasProp = {}.hasOwnProperty;

  ref1 = __webpack_require__(9241), isObject = ref1.isObject, isFunction = ref1.isFunction, isEmpty = ref1.isEmpty, getValue = ref1.getValue;

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

  module.exports = XMLNode = (function() {
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
        XMLElement = __webpack_require__(3906);
        XMLCData = __webpack_require__(2691);
        XMLComment = __webpack_require__(2679);
        XMLDeclaration = __webpack_require__(4130);
        XMLDocType = __webpack_require__(6376);
        XMLRaw = __webpack_require__(1268);
        XMLText = __webpack_require__(2535);
        XMLProcessingInstruction = __webpack_require__(5915);
        XMLDummy = __webpack_require__(1218);
        NodeType = __webpack_require__(1737);
        XMLNodeList = __webpack_require__(6684);
        XMLNamedNodeMap = __webpack_require__(4797);
        DocumentPosition = __webpack_require__(4923);
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
        if (!this.childNodeList || !this.childNodeList.nodes) {
          this.childNodeList = new XMLNodeList(this.children);
        }
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
          for (j = 0, len = ref2.length; j < len; j++) {
            child = ref2[j];
            if (child.textContent) {
              str += child.textContent;
            }
          }
          return str;
        } else {
          return null;
        }
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
      for (j = 0, len = ref2.length; j < len; j++) {
        child = ref2[j];
        results.push(child.setParent(this));
      }
      return results;
    };

    XMLNode.prototype.element = function(name, attributes, text) {
      var childNode, item, j, k, key, lastChild, len, len1, ref2, ref3, val;
      lastChild = null;
      if (attributes === null && (text == null)) {
        ref2 = [{}, null], attributes = ref2[0], text = ref2[1];
      }
      if (attributes == null) {
        attributes = {};
      }
      attributes = getValue(attributes);
      if (!isObject(attributes)) {
        ref3 = [attributes, text], text = ref3[0], attributes = ref3[1];
      }
      if (name != null) {
        name = getValue(name);
      }
      if (Array.isArray(name)) {
        for (j = 0, len = name.length; j < len; j++) {
          item = name[j];
          lastChild = this.element(item);
        }
      } else if (isFunction(name)) {
        lastChild = this.element(name.apply());
      } else if (isObject(name)) {
        for (key in name) {
          if (!hasProp.call(name, key)) continue;
          val = name[key];
          if (isFunction(val)) {
            val = val.apply();
          }
          if (!this.options.ignoreDecorators && this.stringify.convertAttKey && key.indexOf(this.stringify.convertAttKey) === 0) {
            lastChild = this.attribute(key.substr(this.stringify.convertAttKey.length), val);
          } else if (!this.options.separateArrayItems && Array.isArray(val) && isEmpty(val)) {
            lastChild = this.dummy();
          } else if (isObject(val) && isEmpty(val)) {
            lastChild = this.element(key);
          } else if (!this.options.keepNullNodes && (val == null)) {
            lastChild = this.dummy();
          } else if (!this.options.separateArrayItems && Array.isArray(val)) {
            for (k = 0, len1 = val.length; k < len1; k++) {
              item = val[k];
              childNode = {};
              childNode[key] = item;
              lastChild = this.element(childNode);
            }
          } else if (isObject(val)) {
            if (!this.options.ignoreDecorators && this.stringify.convertTextKey && key.indexOf(this.stringify.convertTextKey) === 0) {
              lastChild = this.element(val);
            } else {
              lastChild = this.element(key);
              lastChild.element(val);
            }
          } else {
            lastChild = this.element(key, val);
          }
        }
      } else if (!this.options.keepNullNodes && text === null) {
        lastChild = this.dummy();
      } else {
        if (!this.options.ignoreDecorators && this.stringify.convertTextKey && name.indexOf(this.stringify.convertTextKey) === 0) {
          lastChild = this.text(text);
        } else if (!this.options.ignoreDecorators && this.stringify.convertCDataKey && name.indexOf(this.stringify.convertCDataKey) === 0) {
          lastChild = this.cdata(text);
        } else if (!this.options.ignoreDecorators && this.stringify.convertCommentKey && name.indexOf(this.stringify.convertCommentKey) === 0) {
          lastChild = this.comment(text);
        } else if (!this.options.ignoreDecorators && this.stringify.convertRawKey && name.indexOf(this.stringify.convertRawKey) === 0) {
          lastChild = this.raw(text);
        } else if (!this.options.ignoreDecorators && this.stringify.convertPIKey && name.indexOf(this.stringify.convertPIKey) === 0) {
          lastChild = this.instruction(name.substr(this.stringify.convertPIKey.length), text);
        } else {
          lastChild = this.node(name, attributes, text);
        }
      }
      if (lastChild == null) {
        throw new Error("Could not create any elements with: " + name + ". " + this.debugInfo());
      }
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
        } else {
          children.push(newChild);
        }
        return newChild;
      } else {
        if (this.isRoot) {
          throw new Error("Cannot insert elements at root level. " + this.debugInfo(name));
        }
        i = this.parent.children.indexOf(this);
        removed = this.parent.children.splice(i);
        child = this.parent.element(name, attributes, text);
        Array.prototype.push.apply(this.parent.children, removed);
        return child;
      }
    };

    XMLNode.prototype.insertAfter = function(name, attributes, text) {
      var child, i, removed;
      if (this.isRoot) {
        throw new Error("Cannot insert elements at root level. " + this.debugInfo(name));
      }
      i = this.parent.children.indexOf(this);
      removed = this.parent.children.splice(i + 1);
      child = this.parent.element(name, attributes, text);
      Array.prototype.push.apply(this.parent.children, removed);
      return child;
    };

    XMLNode.prototype.remove = function() {
      var i, ref2;
      if (this.isRoot) {
        throw new Error("Cannot remove the root element. " + this.debugInfo());
      }
      i = this.parent.children.indexOf(this);
      [].splice.apply(this.parent.children, [i, i - i + 1].concat(ref2 = [])), ref2;
      return this.parent;
    };

    XMLNode.prototype.node = function(name, attributes, text) {
      var child, ref2;
      if (name != null) {
        name = getValue(name);
      }
      attributes || (attributes = {});
      attributes = getValue(attributes);
      if (!isObject(attributes)) {
        ref2 = [attributes, text], text = ref2[0], attributes = ref2[1];
      }
      child = new XMLElement(this, name, attributes);
      if (text != null) {
        child.text(text);
      }
      this.children.push(child);
      return child;
    };

    XMLNode.prototype.text = function(value) {
      var child;
      if (isObject(value)) {
        this.element(value);
      }
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
      if (target != null) {
        target = getValue(target);
      }
      if (value != null) {
        value = getValue(value);
      }
      if (Array.isArray(target)) {
        for (j = 0, len = target.length; j < len; j++) {
          insTarget = target[j];
          this.instruction(insTarget);
        }
      } else if (isObject(target)) {
        for (insTarget in target) {
          if (!hasProp.call(target, insTarget)) continue;
          insValue = target[insTarget];
          this.instruction(insTarget, insValue);
        }
      } else {
        if (isFunction(value)) {
          value = value.apply();
        }
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
      if (doc.children.length === 0) {
        doc.children.unshift(xmldec);
      } else if (doc.children[0].type === NodeType.Declaration) {
        doc.children[0] = xmldec;
      } else {
        doc.children.unshift(xmldec);
      }
      return doc.root() || doc;
    };

    XMLNode.prototype.dtd = function(pubID, sysID) {
      var child, doc, doctype, i, j, k, len, len1, ref2, ref3;
      doc = this.document();
      doctype = new XMLDocType(doc, pubID, sysID);
      ref2 = doc.children;
      for (i = j = 0, len = ref2.length; j < len; i = ++j) {
        child = ref2[i];
        if (child.type === NodeType.DocType) {
          doc.children[i] = doctype;
          return doctype;
        }
      }
      ref3 = doc.children;
      for (i = k = 0, len1 = ref3.length; k < len1; i = ++k) {
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
      if (this.isRoot) {
        throw new Error("The root node has no parent. Use doc() if you need to get the document object.");
      }
      return this.parent;
    };

    XMLNode.prototype.root = function() {
      var node;
      node = this;
      while (node) {
        if (node.type === NodeType.Document) {
          return node.rootObject;
        } else if (node.isRoot) {
          return node;
        } else {
          node = node.parent;
        }
      }
    };

    XMLNode.prototype.document = function() {
      var node;
      node = this;
      while (node) {
        if (node.type === NodeType.Document) {
          return node;
        } else {
          node = node.parent;
        }
      }
    };

    XMLNode.prototype.end = function(options) {
      return this.document().end(options);
    };

    XMLNode.prototype.prev = function() {
      var i;
      i = this.parent.children.indexOf(this);
      if (i < 1) {
        throw new Error("Already at the first node. " + this.debugInfo());
      }
      return this.parent.children[i - 1];
    };

    XMLNode.prototype.next = function() {
      var i;
      i = this.parent.children.indexOf(this);
      if (i === -1 || i === this.parent.children.length - 1) {
        throw new Error("Already at the last node. " + this.debugInfo());
      }
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
      if ((name == null) && !((ref2 = this.parent) != null ? ref2.name : void 0)) {
        return "";
      } else if (name == null) {
        return "parent: <" + this.parent.name + ">";
      } else if (!((ref3 = this.parent) != null ? ref3.name : void 0)) {
        return "node: <" + name + ">";
      } else {
        return "node: <" + name + ">, parent: <" + this.parent.name + ">";
      }
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
      if (ref === other) {
        return 0;
      } else if (this.document() !== other.document()) {
        res = DocumentPosition.Disconnected | DocumentPosition.ImplementationSpecific;
        if (Math.random() < 0.5) {
          res |= DocumentPosition.Preceding;
        } else {
          res |= DocumentPosition.Following;
        }
        return res;
      } else if (ref.isAncestor(other)) {
        return DocumentPosition.Contains | DocumentPosition.Preceding;
      } else if (ref.isDescendant(other)) {
        return DocumentPosition.Contains | DocumentPosition.Following;
      } else if (ref.isPreceding(other)) {
        return DocumentPosition.Preceding;
      } else {
        return DocumentPosition.Following;
      }
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
      if (node.nodeType !== this.nodeType) {
        return false;
      }
      if (node.children.length !== this.children.length) {
        return false;
      }
      for (i = j = 0, ref2 = this.children.length - 1; 0 <= ref2 ? j <= ref2 : j >= ref2; i = 0 <= ref2 ? ++j : --j) {
        if (!this.children[i].isEqualNode(node.children[i])) {
          return false;
        }
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
      if (!other) {
        return false;
      }
      return other === this || this.isDescendant(other);
    };

    XMLNode.prototype.isDescendant = function(node) {
      var child, isDescendantChild, j, len, ref2;
      ref2 = this.children;
      for (j = 0, len = ref2.length; j < len; j++) {
        child = ref2[j];
        if (node === child) {
          return true;
        }
        isDescendantChild = child.isDescendant(node);
        if (isDescendantChild) {
          return true;
        }
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
      if (nodePos === -1 || thisPos === -1) {
        return false;
      } else {
        return nodePos < thisPos;
      }
    };

    XMLNode.prototype.isFollowing = function(node) {
      var nodePos, thisPos;
      nodePos = this.treePosition(node);
      thisPos = this.treePosition(this);
      if (nodePos === -1 || thisPos === -1) {
        return false;
      } else {
        return nodePos > thisPos;
      }
    };

    XMLNode.prototype.treePosition = function(node) {
      var found, pos;
      pos = 0;
      found = false;
      this.foreachTreeNode(this.document(), function(childNode) {
        pos++;
        if (!found && childNode === node) {
          return found = true;
        }
      });
      if (found) {
        return pos;
      } else {
        return -1;
      }
    };

    XMLNode.prototype.foreachTreeNode = function(node, func) {
      var child, j, len, ref2, res;
      node || (node = this.document());
      ref2 = node.children;
      for (j = 0, len = ref2.length; j < len; j++) {
        child = ref2[j];
        if (res = func(child)) {
          return res;
        } else {
          res = this.foreachTreeNode(child, func);
          if (res) {
            return res;
          }
        }
      }
    };

    return XMLNode;

  })();

}).call(this);


/***/ },

/***/ 6684
(module) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLNodeList;

  module.exports = XMLNodeList = (function() {
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

  })();

}).call(this);


/***/ },

/***/ 5915
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLCharacterData, XMLProcessingInstruction,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  NodeType = __webpack_require__(1737);

  XMLCharacterData = __webpack_require__(7457);

  module.exports = XMLProcessingInstruction = (function(superClass) {
    extend(XMLProcessingInstruction, superClass);

    function XMLProcessingInstruction(parent, target, value) {
      XMLProcessingInstruction.__super__.constructor.call(this, parent);
      if (target == null) {
        throw new Error("Missing instruction target. " + this.debugInfo());
      }
      this.type = NodeType.ProcessingInstruction;
      this.target = this.stringify.insTarget(target);
      this.name = this.target;
      if (value) {
        this.value = this.stringify.insValue(value);
      }
    }

    XMLProcessingInstruction.prototype.clone = function() {
      return Object.create(this);
    };

    XMLProcessingInstruction.prototype.toString = function(options) {
      return this.options.writer.processingInstruction(this, this.options.writer.filterOptions(options));
    };

    XMLProcessingInstruction.prototype.isEqualNode = function(node) {
      if (!XMLProcessingInstruction.__super__.isEqualNode.apply(this, arguments).isEqualNode(node)) {
        return false;
      }
      if (node.target !== this.target) {
        return false;
      }
      return true;
    };

    return XMLProcessingInstruction;

  })(XMLCharacterData);

}).call(this);


/***/ },

/***/ 1268
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLNode, XMLRaw,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  NodeType = __webpack_require__(1737);

  XMLNode = __webpack_require__(468);

  module.exports = XMLRaw = (function(superClass) {
    extend(XMLRaw, superClass);

    function XMLRaw(parent, text) {
      XMLRaw.__super__.constructor.call(this, parent);
      if (text == null) {
        throw new Error("Missing raw text. " + this.debugInfo());
      }
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

  })(XMLNode);

}).call(this);


/***/ },

/***/ 6775
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, WriterState, XMLStreamWriter, XMLWriterBase,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  NodeType = __webpack_require__(1737);

  XMLWriterBase = __webpack_require__(6286);

  WriterState = __webpack_require__(8753);

  module.exports = XMLStreamWriter = (function(superClass) {
    extend(XMLStreamWriter, superClass);

    function XMLStreamWriter(stream, options) {
      this.stream = stream;
      XMLStreamWriter.__super__.constructor.call(this, options);
    }

    XMLStreamWriter.prototype.endline = function(node, options, level) {
      if (node.isLastRootNode && options.state === WriterState.CloseTag) {
        return '';
      } else {
        return XMLStreamWriter.__super__.endline.call(this, node, options, level);
      }
    };

    XMLStreamWriter.prototype.document = function(doc, options) {
      var child, i, j, k, len, len1, ref, ref1, results;
      ref = doc.children;
      for (i = j = 0, len = ref.length; j < len; i = ++j) {
        child = ref[i];
        child.isLastRootNode = i === doc.children.length - 1;
      }
      options = this.filterOptions(options);
      ref1 = doc.children;
      results = [];
      for (k = 0, len1 = ref1.length; k < len1; k++) {
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
      if (node.pubID && node.sysID) {
        this.stream.write(' PUBLIC "' + node.pubID + '" "' + node.sysID + '"');
      } else if (node.sysID) {
        this.stream.write(' SYSTEM "' + node.sysID + '"');
      }
      if (node.children.length > 0) {
        this.stream.write(' [');
        this.stream.write(this.endline(node, options, level));
        options.state = WriterState.InsideTag;
        ref = node.children;
        for (j = 0, len = ref.length; j < len; j++) {
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
      for (name in ref) {
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
      } else if (options.pretty && childNodeCount === 1 && (firstChildNode.type === NodeType.Text || firstChildNode.type === NodeType.Raw) && (firstChildNode.value != null)) {
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
        for (j = 0, len = ref1.length; j < len; j++) {
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

  })(XMLWriterBase);

}).call(this);


/***/ },

/***/ 382
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLStringWriter, XMLWriterBase,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  XMLWriterBase = __webpack_require__(6286);

  module.exports = XMLStringWriter = (function(superClass) {
    extend(XMLStringWriter, superClass);

    function XMLStringWriter(options) {
      XMLStringWriter.__super__.constructor.call(this, options);
    }

    XMLStringWriter.prototype.document = function(doc, options) {
      var child, i, len, r, ref;
      options = this.filterOptions(options);
      r = '';
      ref = doc.children;
      for (i = 0, len = ref.length; i < len; i++) {
        child = ref[i];
        r += this.writeChildNode(child, options, 0);
      }
      if (options.pretty && r.slice(-options.newline.length) === options.newline) {
        r = r.slice(0, -options.newline.length);
      }
      return r;
    };

    return XMLStringWriter;

  })(XMLWriterBase);

}).call(this);


/***/ },

/***/ 3976
(module) {

// Generated by CoffeeScript 1.12.7
(function() {
  var XMLStringifier,
    bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    hasProp = {}.hasOwnProperty;

  module.exports = XMLStringifier = (function() {
    function XMLStringifier(options) {
      this.assertLegalName = bind(this.assertLegalName, this);
      this.assertLegalChar = bind(this.assertLegalChar, this);
      var key, ref, value;
      options || (options = {});
      this.options = options;
      if (!this.options.version) {
        this.options.version = '1.0';
      }
      ref = options.stringify || {};
      for (key in ref) {
        if (!hasProp.call(ref, key)) continue;
        value = ref[key];
        this[key] = value;
      }
    }

    XMLStringifier.prototype.name = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalName('' + val || '');
    };

    XMLStringifier.prototype.text = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar(this.textEscape('' + val || ''));
    };

    XMLStringifier.prototype.cdata = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      val = '' + val || '';
      val = val.replace(']]>', ']]]]><![CDATA[>');
      return this.assertLegalChar(val);
    };

    XMLStringifier.prototype.comment = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      val = '' + val || '';
      if (val.match(/--/)) {
        throw new Error("Comment text cannot contain double-hypen: " + val);
      }
      return this.assertLegalChar(val);
    };

    XMLStringifier.prototype.raw = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return '' + val || '';
    };

    XMLStringifier.prototype.attValue = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar(this.attEscape(val = '' + val || ''));
    };

    XMLStringifier.prototype.insTarget = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar('' + val || '');
    };

    XMLStringifier.prototype.insValue = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      val = '' + val || '';
      if (val.match(/\?>/)) {
        throw new Error("Invalid processing instruction value: " + val);
      }
      return this.assertLegalChar(val);
    };

    XMLStringifier.prototype.xmlVersion = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      val = '' + val || '';
      if (!val.match(/1\.[0-9]+/)) {
        throw new Error("Invalid version number: " + val);
      }
      return val;
    };

    XMLStringifier.prototype.xmlEncoding = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      val = '' + val || '';
      if (!val.match(/^[A-Za-z](?:[A-Za-z0-9._-])*$/)) {
        throw new Error("Invalid encoding: " + val);
      }
      return this.assertLegalChar(val);
    };

    XMLStringifier.prototype.xmlStandalone = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      if (val) {
        return "yes";
      } else {
        return "no";
      }
    };

    XMLStringifier.prototype.dtdPubID = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar('' + val || '');
    };

    XMLStringifier.prototype.dtdSysID = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar('' + val || '');
    };

    XMLStringifier.prototype.dtdElementValue = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar('' + val || '');
    };

    XMLStringifier.prototype.dtdAttType = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar('' + val || '');
    };

    XMLStringifier.prototype.dtdAttDefault = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar('' + val || '');
    };

    XMLStringifier.prototype.dtdEntityValue = function(val) {
      if (this.options.noValidation) {
        return val;
      }
      return this.assertLegalChar('' + val || '');
    };

    XMLStringifier.prototype.dtdNData = function(val) {
      if (this.options.noValidation) {
        return val;
      }
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
      if (this.options.noValidation) {
        return str;
      }
      regex = '';
      if (this.options.version === '1.0') {
        regex = /[\0-\x08\x0B\f\x0E-\x1F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
        if (res = str.match(regex)) {
          throw new Error("Invalid character in string: " + str + " at index " + res.index);
        }
      } else if (this.options.version === '1.1') {
        regex = /[\0\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
        if (res = str.match(regex)) {
          throw new Error("Invalid character in string: " + str + " at index " + res.index);
        }
      }
      return str;
    };

    XMLStringifier.prototype.assertLegalName = function(str) {
      var regex;
      if (this.options.noValidation) {
        return str;
      }
      this.assertLegalChar(str);
      regex = /^([:A-Z_a-z\xC0-\xD6\xD8-\xF6\xF8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]|[\uD800-\uDB7F][\uDC00-\uDFFF])([\x2D\.0-:A-Z_a-z\xB7\xC0-\xD6\xD8-\xF6\xF8-\u037D\u037F-\u1FFF\u200C\u200D\u203F\u2040\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]|[\uD800-\uDB7F][\uDC00-\uDFFF])*$/;
      if (!str.match(regex)) {
        throw new Error("Invalid character in name");
      }
      return str;
    };

    XMLStringifier.prototype.textEscape = function(str) {
      var ampregex;
      if (this.options.noValidation) {
        return str;
      }
      ampregex = this.options.noDoubleEncoding ? /(?!&\S+;)&/g : /&/g;
      return str.replace(ampregex, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
    };

    XMLStringifier.prototype.attEscape = function(str) {
      var ampregex;
      if (this.options.noValidation) {
        return str;
      }
      ampregex = this.options.noDoubleEncoding ? /(?!&\S+;)&/g : /&/g;
      return str.replace(ampregex, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;').replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');
    };

    return XMLStringifier;

  })();

}).call(this);


/***/ },

/***/ 2535
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, XMLCharacterData, XMLText,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  NodeType = __webpack_require__(1737);

  XMLCharacterData = __webpack_require__(7457);

  module.exports = XMLText = (function(superClass) {
    extend(XMLText, superClass);

    function XMLText(parent, text) {
      XMLText.__super__.constructor.call(this, parent);
      if (text == null) {
        throw new Error("Missing element text. " + this.debugInfo());
      }
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
        while (prev) {
          str = prev.data + str;
          prev = prev.previousSibling;
        }
        str += this.data;
        next = this.nextSibling;
        while (next) {
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

  })(XMLCharacterData);

}).call(this);


/***/ },

/***/ 6286
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, WriterState, XMLCData, XMLComment, XMLDTDAttList, XMLDTDElement, XMLDTDEntity, XMLDTDNotation, XMLDeclaration, XMLDocType, XMLDummy, XMLElement, XMLProcessingInstruction, XMLRaw, XMLText, XMLWriterBase, assign,
    hasProp = {}.hasOwnProperty;

  assign = (__webpack_require__(9241).assign);

  NodeType = __webpack_require__(1737);

  XMLDeclaration = __webpack_require__(4130);

  XMLDocType = __webpack_require__(6376);

  XMLCData = __webpack_require__(2691);

  XMLComment = __webpack_require__(2679);

  XMLElement = __webpack_require__(3906);

  XMLRaw = __webpack_require__(1268);

  XMLText = __webpack_require__(2535);

  XMLProcessingInstruction = __webpack_require__(5915);

  XMLDummy = __webpack_require__(1218);

  XMLDTDAttList = __webpack_require__(4111);

  XMLDTDElement = __webpack_require__(7696);

  XMLDTDEntity = __webpack_require__(5529);

  XMLDTDNotation = __webpack_require__(8012);

  WriterState = __webpack_require__(8753);

  module.exports = XMLWriterBase = (function() {
    function XMLWriterBase(options) {
      var key, ref, value;
      options || (options = {});
      this.options = options;
      ref = options.writer || {};
      for (key in ref) {
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
      if (filteredOptions.spaceBeforeSlash === true) {
        filteredOptions.spaceBeforeSlash = ' ';
      }
      filteredOptions.suppressPrettyCount = 0;
      filteredOptions.user = {};
      filteredOptions.state = WriterState.None;
      return filteredOptions;
    };

    XMLWriterBase.prototype.indent = function(node, options, level) {
      var indentLevel;
      if (!options.pretty || options.suppressPrettyCount) {
        return '';
      } else if (options.pretty) {
        indentLevel = (level || 0) + options.offset + 1;
        if (indentLevel > 0) {
          return new Array(indentLevel).join(options.indent);
        }
      }
      return '';
    };

    XMLWriterBase.prototype.endline = function(node, options, level) {
      if (!options.pretty || options.suppressPrettyCount) {
        return '';
      } else {
        return options.newline;
      }
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
      if (node.encoding != null) {
        r += ' encoding="' + node.encoding + '"';
      }
      if (node.standalone != null) {
        r += ' standalone="' + node.standalone + '"';
      }
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
      if (node.pubID && node.sysID) {
        r += ' PUBLIC "' + node.pubID + '" "' + node.sysID + '"';
      } else if (node.sysID) {
        r += ' SYSTEM "' + node.sysID + '"';
      }
      if (node.children.length > 0) {
        r += ' [';
        r += this.endline(node, options, level);
        options.state = WriterState.InsideTag;
        ref = node.children;
        for (i = 0, len = ref.length; i < len; i++) {
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
      for (name in ref) {
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
      } else if (options.pretty && childNodeCount === 1 && (firstChildNode.type === NodeType.Text || firstChildNode.type === NodeType.Raw) && (firstChildNode.value != null)) {
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
          for (i = 0, len = ref1.length; i < len; i++) {
            child = ref1[i];
            if ((child.type === NodeType.Text || child.type === NodeType.Raw) && (child.value != null)) {
              options.suppressPrettyCount++;
              prettySuppressed = true;
              break;
            }
          }
        }
        r += '>' + this.endline(node, options, level);
        options.state = WriterState.InsideTag;
        ref2 = node.children;
        for (j = 0, len1 = ref2.length; j < len1; j++) {
          child = ref2[j];
          r += this.writeChildNode(child, options, level + 1);
        }
        options.state = WriterState.CloseTag;
        r += this.indent(node, options, level) + '</' + node.name + '>';
        if (prettySuppressed) {
          options.suppressPrettyCount--;
        }
        r += this.endline(node, options, level);
        options.state = WriterState.None;
      }
      this.closeNode(node, options, level);
      return r;
    };

    XMLWriterBase.prototype.writeChildNode = function(node, options, level) {
      switch (node.type) {
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
      if (node.value) {
        r += ' ' + node.value;
      }
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
      if (node.defaultValueType !== '#DEFAULT') {
        r += ' ' + node.defaultValueType;
      }
      if (node.defaultValue) {
        r += ' "' + node.defaultValue + '"';
      }
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
      if (node.pe) {
        r += ' %';
      }
      r += ' ' + node.name;
      if (node.value) {
        r += ' "' + node.value + '"';
      } else {
        if (node.pubID && node.sysID) {
          r += ' PUBLIC "' + node.pubID + '" "' + node.sysID + '"';
        } else if (node.sysID) {
          r += ' SYSTEM "' + node.sysID + '"';
        }
        if (node.nData) {
          r += ' NDATA ' + node.nData;
        }
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
      if (node.pubID && node.sysID) {
        r += ' PUBLIC "' + node.pubID + '" "' + node.sysID + '"';
      } else if (node.pubID) {
        r += ' PUBLIC "' + node.pubID + '"';
      } else if (node.sysID) {
        r += ' SYSTEM "' + node.sysID + '"';
      }
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

  })();

}).call(this);


/***/ },

/***/ 9665
(module, __unused_webpack_exports, __webpack_require__) {

// Generated by CoffeeScript 1.12.7
(function() {
  var NodeType, WriterState, XMLDOMImplementation, XMLDocument, XMLDocumentCB, XMLStreamWriter, XMLStringWriter, assign, isFunction, ref;

  ref = __webpack_require__(9241), assign = ref.assign, isFunction = ref.isFunction;

  XMLDOMImplementation = __webpack_require__(7260);

  XMLDocument = __webpack_require__(1933);

  XMLDocumentCB = __webpack_require__(400);

  XMLStringWriter = __webpack_require__(382);

  XMLStreamWriter = __webpack_require__(6775);

  NodeType = __webpack_require__(1737);

  WriterState = __webpack_require__(8753);

  module.exports.create = function(name, xmldec, doctype, options) {
    var doc, root;
    if (name == null) {
      throw new Error("Root element needs a name.");
    }
    options = assign({}, xmldec, doctype, options);
    doc = new XMLDocument(options);
    root = doc.element(name);
    if (!options.headless) {
      doc.declaration(options);
      if ((options.pubID != null) || (options.sysID != null)) {
        doc.dtd(options);
      }
    }
    return root;
  };

  module.exports.begin = function(options, onData, onEnd) {
    var ref1;
    if (isFunction(options)) {
      ref1 = [options, onData], onData = ref1[0], onEnd = ref1[1];
      options = {};
    }
    if (onData) {
      return new XMLDocumentCB(options, onData, onEnd);
    } else {
      return new XMLDocument(options);
    }
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

}).call(this);


/***/ },

/***/ 181
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("buffer");

/***/ },

/***/ 5317
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("child_process");

/***/ },

/***/ 6982
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("crypto");

/***/ },

/***/ 7194
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("dgram");

/***/ },

/***/ 3167
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("domain");

/***/ },

/***/ 4434
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("events");

/***/ },

/***/ 9896
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("fs");

/***/ },

/***/ 8611
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("http");

/***/ },

/***/ 5692
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("https");

/***/ },

/***/ 857
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("os");

/***/ },

/***/ 6928
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("path");

/***/ },

/***/ 3480
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("querystring");

/***/ },

/***/ 2203
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("stream");

/***/ },

/***/ 3193
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("string_decoder");

/***/ },

/***/ 3557
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("timers");

/***/ },

/***/ 7016
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("url");

/***/ },

/***/ 9023
(module) {

module.exports = __WEBPACK_EXTERNAL_createRequire_require("util");

/***/ },

/***/ 6607
(module) {

module.exports = /*#__PURE__*/JSON.parse('{"version":"2.0","metadata":{"apiVersion":"2014-06-30","endpointPrefix":"cognito-identity","jsonVersion":"1.1","protocol":"json","protocols":["json"],"serviceFullName":"Amazon Cognito Identity","serviceId":"Cognito Identity","signatureVersion":"v4","targetPrefix":"AWSCognitoIdentityService","uid":"cognito-identity-2014-06-30","auth":["aws.auth#sigv4"]},"operations":{"CreateIdentityPool":{"input":{"type":"structure","required":["IdentityPoolName","AllowUnauthenticatedIdentities"],"members":{"IdentityPoolName":{},"AllowUnauthenticatedIdentities":{"type":"boolean"},"AllowClassicFlow":{"type":"boolean"},"SupportedLoginProviders":{"shape":"S5"},"DeveloperProviderName":{},"OpenIdConnectProviderARNs":{"shape":"S9"},"CognitoIdentityProviders":{"shape":"Sb"},"SamlProviderARNs":{"shape":"Sg"},"IdentityPoolTags":{"shape":"Sh"}}},"output":{"shape":"Sk"}},"DeleteIdentities":{"input":{"type":"structure","required":["IdentityIdsToDelete"],"members":{"IdentityIdsToDelete":{"type":"list","member":{}}}},"output":{"type":"structure","members":{"UnprocessedIdentityIds":{"type":"list","member":{"type":"structure","members":{"IdentityId":{},"ErrorCode":{}}}}}}},"DeleteIdentityPool":{"input":{"type":"structure","required":["IdentityPoolId"],"members":{"IdentityPoolId":{}}}},"DescribeIdentity":{"input":{"type":"structure","required":["IdentityId"],"members":{"IdentityId":{}}},"output":{"shape":"Sv"}},"DescribeIdentityPool":{"input":{"type":"structure","required":["IdentityPoolId"],"members":{"IdentityPoolId":{}}},"output":{"shape":"Sk"}},"GetCredentialsForIdentity":{"input":{"type":"structure","required":["IdentityId"],"members":{"IdentityId":{},"Logins":{"shape":"S10"},"CustomRoleArn":{}}},"output":{"type":"structure","members":{"IdentityId":{},"Credentials":{"type":"structure","members":{"AccessKeyId":{},"SecretKey":{},"SessionToken":{},"Expiration":{"type":"timestamp"}}}}},"authtype":"none","auth":["smithy.api#noAuth"]},"GetId":{"input":{"type":"structure","required":["IdentityPoolId"],"members":{"AccountId":{},"IdentityPoolId":{},"Logins":{"shape":"S10"}}},"output":{"type":"structure","members":{"IdentityId":{}}},"authtype":"none","auth":["smithy.api#noAuth"]},"GetIdentityPoolRoles":{"input":{"type":"structure","required":["IdentityPoolId"],"members":{"IdentityPoolId":{}}},"output":{"type":"structure","members":{"IdentityPoolId":{},"Roles":{"shape":"S1c"},"RoleMappings":{"shape":"S1e"}}}},"GetOpenIdToken":{"input":{"type":"structure","required":["IdentityId"],"members":{"IdentityId":{},"Logins":{"shape":"S10"}}},"output":{"type":"structure","members":{"IdentityId":{},"Token":{}}},"authtype":"none","auth":["smithy.api#noAuth"]},"GetOpenIdTokenForDeveloperIdentity":{"input":{"type":"structure","required":["IdentityPoolId","Logins"],"members":{"IdentityPoolId":{},"IdentityId":{},"Logins":{"shape":"S10"},"PrincipalTags":{"shape":"S1s"},"TokenDuration":{"type":"long"}}},"output":{"type":"structure","members":{"IdentityId":{},"Token":{}}}},"GetPrincipalTagAttributeMap":{"input":{"type":"structure","required":["IdentityPoolId","IdentityProviderName"],"members":{"IdentityPoolId":{},"IdentityProviderName":{}}},"output":{"type":"structure","members":{"IdentityPoolId":{},"IdentityProviderName":{},"UseDefaults":{"type":"boolean"},"PrincipalTags":{"shape":"S1s"}}}},"ListIdentities":{"input":{"type":"structure","required":["IdentityPoolId","MaxResults"],"members":{"IdentityPoolId":{},"MaxResults":{"type":"integer"},"NextToken":{},"HideDisabled":{"type":"boolean"}}},"output":{"type":"structure","members":{"IdentityPoolId":{},"Identities":{"type":"list","member":{"shape":"Sv"}},"NextToken":{}}}},"ListIdentityPools":{"input":{"type":"structure","required":["MaxResults"],"members":{"MaxResults":{"type":"integer"},"NextToken":{}}},"output":{"type":"structure","members":{"IdentityPools":{"type":"list","member":{"type":"structure","members":{"IdentityPoolId":{},"IdentityPoolName":{}}}},"NextToken":{}}}},"ListTagsForResource":{"input":{"type":"structure","required":["ResourceArn"],"members":{"ResourceArn":{}}},"output":{"type":"structure","members":{"Tags":{"shape":"Sh"}}}},"LookupDeveloperIdentity":{"input":{"type":"structure","required":["IdentityPoolId"],"members":{"IdentityPoolId":{},"IdentityId":{},"DeveloperUserIdentifier":{},"MaxResults":{"type":"integer"},"NextToken":{}}},"output":{"type":"structure","members":{"IdentityId":{},"DeveloperUserIdentifierList":{"type":"list","member":{}},"NextToken":{}}}},"MergeDeveloperIdentities":{"input":{"type":"structure","required":["SourceUserIdentifier","DestinationUserIdentifier","DeveloperProviderName","IdentityPoolId"],"members":{"SourceUserIdentifier":{},"DestinationUserIdentifier":{},"DeveloperProviderName":{},"IdentityPoolId":{}}},"output":{"type":"structure","members":{"IdentityId":{}}}},"SetIdentityPoolRoles":{"input":{"type":"structure","required":["IdentityPoolId","Roles"],"members":{"IdentityPoolId":{},"Roles":{"shape":"S1c"},"RoleMappings":{"shape":"S1e"}}}},"SetPrincipalTagAttributeMap":{"input":{"type":"structure","required":["IdentityPoolId","IdentityProviderName"],"members":{"IdentityPoolId":{},"IdentityProviderName":{},"UseDefaults":{"type":"boolean"},"PrincipalTags":{"shape":"S1s"}}},"output":{"type":"structure","members":{"IdentityPoolId":{},"IdentityProviderName":{},"UseDefaults":{"type":"boolean"},"PrincipalTags":{"shape":"S1s"}}}},"TagResource":{"input":{"type":"structure","required":["ResourceArn","Tags"],"members":{"ResourceArn":{},"Tags":{"shape":"Sh"}}},"output":{"type":"structure","members":{}}},"UnlinkDeveloperIdentity":{"input":{"type":"structure","required":["IdentityId","IdentityPoolId","DeveloperProviderName","DeveloperUserIdentifier"],"members":{"IdentityId":{},"IdentityPoolId":{},"DeveloperProviderName":{},"DeveloperUserIdentifier":{}}}},"UnlinkIdentity":{"input":{"type":"structure","required":["IdentityId","Logins","LoginsToRemove"],"members":{"IdentityId":{},"Logins":{"shape":"S10"},"LoginsToRemove":{"shape":"Sw"}}},"authtype":"none","auth":["smithy.api#noAuth"]},"UntagResource":{"input":{"type":"structure","required":["ResourceArn","TagKeys"],"members":{"ResourceArn":{},"TagKeys":{"type":"list","member":{}}}},"output":{"type":"structure","members":{}}},"UpdateIdentityPool":{"input":{"shape":"Sk"},"output":{"shape":"Sk"}}},"shapes":{"S5":{"type":"map","key":{},"value":{}},"S9":{"type":"list","member":{}},"Sb":{"type":"list","member":{"type":"structure","members":{"ProviderName":{},"ClientId":{},"ServerSideTokenCheck":{"type":"boolean"}}}},"Sg":{"type":"list","member":{}},"Sh":{"type":"map","key":{},"value":{}},"Sk":{"type":"structure","required":["IdentityPoolId","IdentityPoolName","AllowUnauthenticatedIdentities"],"members":{"IdentityPoolId":{},"IdentityPoolName":{},"AllowUnauthenticatedIdentities":{"type":"boolean"},"AllowClassicFlow":{"type":"boolean"},"SupportedLoginProviders":{"shape":"S5"},"DeveloperProviderName":{},"OpenIdConnectProviderARNs":{"shape":"S9"},"CognitoIdentityProviders":{"shape":"Sb"},"SamlProviderARNs":{"shape":"Sg"},"IdentityPoolTags":{"shape":"Sh"}}},"Sv":{"type":"structure","members":{"IdentityId":{},"Logins":{"shape":"Sw"},"CreationDate":{"type":"timestamp"},"LastModifiedDate":{"type":"timestamp"}}},"Sw":{"type":"list","member":{}},"S10":{"type":"map","key":{},"value":{}},"S1c":{"type":"map","key":{},"value":{}},"S1e":{"type":"map","key":{},"value":{"type":"structure","required":["Type"],"members":{"Type":{},"AmbiguousRoleResolution":{},"RulesConfiguration":{"type":"structure","required":["Rules"],"members":{"Rules":{"type":"list","member":{"type":"structure","required":["Claim","MatchType","Value","RoleARN"],"members":{"Claim":{},"MatchType":{},"Value":{},"RoleARN":{}}}}}}}}},"S1s":{"type":"map","key":{},"value":{}}}}');

/***/ },

/***/ 6741
(module) {

module.exports = /*#__PURE__*/JSON.parse('{"X":{"ListIdentityPools":{"input_token":"NextToken","limit_key":"MaxResults","output_token":"NextToken","result_key":"IdentityPools"}}}');

/***/ },

/***/ 5087
(module) {

module.exports = /*#__PURE__*/JSON.parse('{"acm":{"name":"ACM","cors":true},"apigateway":{"name":"APIGateway","cors":true},"applicationautoscaling":{"prefix":"application-autoscaling","name":"ApplicationAutoScaling","cors":true},"appstream":{"name":"AppStream"},"autoscaling":{"name":"AutoScaling","cors":true},"batch":{"name":"Batch"},"budgets":{"name":"Budgets"},"clouddirectory":{"name":"CloudDirectory","versions":["2016-05-10*"]},"cloudformation":{"name":"CloudFormation","cors":true},"cloudfront":{"name":"CloudFront","versions":["2013-05-12*","2013-11-11*","2014-05-31*","2014-10-21*","2014-11-06*","2015-04-17*","2015-07-27*","2015-09-17*","2016-01-13*","2016-01-28*","2016-08-01*","2016-08-20*","2016-09-07*","2016-09-29*","2016-11-25*","2017-03-25*","2017-10-30*","2018-06-18*","2018-11-05*","2019-03-26*"],"cors":true},"cloudhsm":{"name":"CloudHSM","cors":true},"cloudsearch":{"name":"CloudSearch"},"cloudsearchdomain":{"name":"CloudSearchDomain"},"cloudtrail":{"name":"CloudTrail","cors":true},"cloudwatch":{"prefix":"monitoring","name":"CloudWatch","cors":true},"cloudwatchevents":{"prefix":"events","name":"CloudWatchEvents","versions":["2014-02-03*"],"cors":true},"cloudwatchlogs":{"prefix":"logs","name":"CloudWatchLogs","cors":true},"codebuild":{"name":"CodeBuild","cors":true},"codecommit":{"name":"CodeCommit","cors":true},"codedeploy":{"name":"CodeDeploy","cors":true},"codepipeline":{"name":"CodePipeline","cors":true},"cognitoidentity":{"prefix":"cognito-identity","name":"CognitoIdentity","cors":true},"cognitoidentityserviceprovider":{"prefix":"cognito-idp","name":"CognitoIdentityServiceProvider","cors":true},"cognitosync":{"prefix":"cognito-sync","name":"CognitoSync","cors":true},"configservice":{"prefix":"config","name":"ConfigService","cors":true},"cur":{"name":"CUR","cors":true},"datapipeline":{"name":"DataPipeline"},"devicefarm":{"name":"DeviceFarm","cors":true},"directconnect":{"name":"DirectConnect","cors":true},"directoryservice":{"prefix":"ds","name":"DirectoryService"},"discovery":{"name":"Discovery"},"dms":{"name":"DMS"},"dynamodb":{"name":"DynamoDB","cors":true},"dynamodbstreams":{"prefix":"streams.dynamodb","name":"DynamoDBStreams","cors":true},"ec2":{"name":"EC2","versions":["2013-06-15*","2013-10-15*","2014-02-01*","2014-05-01*","2014-06-15*","2014-09-01*","2014-10-01*","2015-03-01*","2015-04-15*","2015-10-01*","2016-04-01*","2016-09-15*"],"cors":true},"ecr":{"name":"ECR","cors":true},"ecs":{"name":"ECS","cors":true},"efs":{"prefix":"elasticfilesystem","name":"EFS","cors":true},"elasticache":{"name":"ElastiCache","versions":["2012-11-15*","2014-03-24*","2014-07-15*","2014-09-30*"],"cors":true},"elasticbeanstalk":{"name":"ElasticBeanstalk","cors":true},"elb":{"prefix":"elasticloadbalancing","name":"ELB","cors":true},"elbv2":{"prefix":"elasticloadbalancingv2","name":"ELBv2","cors":true},"emr":{"prefix":"elasticmapreduce","name":"EMR","cors":true},"es":{"name":"ES"},"elastictranscoder":{"name":"ElasticTranscoder","cors":true},"firehose":{"name":"Firehose","cors":true},"gamelift":{"name":"GameLift","cors":true},"glacier":{"name":"Glacier"},"health":{"name":"Health"},"iam":{"name":"IAM","cors":true},"importexport":{"name":"ImportExport"},"inspector":{"name":"Inspector","versions":["2015-08-18*"],"cors":true},"iot":{"name":"Iot","cors":true},"iotdata":{"prefix":"iot-data","name":"IotData","cors":true},"kinesis":{"name":"Kinesis","cors":true},"kinesisanalytics":{"name":"KinesisAnalytics"},"kms":{"name":"KMS","cors":true},"lambda":{"name":"Lambda","cors":true},"lexruntime":{"prefix":"runtime.lex","name":"LexRuntime","cors":true},"lightsail":{"name":"Lightsail"},"machinelearning":{"name":"MachineLearning","cors":true},"marketplacecommerceanalytics":{"name":"MarketplaceCommerceAnalytics","cors":true},"marketplacemetering":{"prefix":"meteringmarketplace","name":"MarketplaceMetering"},"mturk":{"prefix":"mturk-requester","name":"MTurk","cors":true},"mobileanalytics":{"name":"MobileAnalytics","cors":true},"opsworks":{"name":"OpsWorks","cors":true},"opsworkscm":{"name":"OpsWorksCM"},"organizations":{"name":"Organizations"},"pinpoint":{"name":"Pinpoint"},"polly":{"name":"Polly","cors":true},"rds":{"name":"RDS","versions":["2014-09-01*"],"cors":true},"redshift":{"name":"Redshift","cors":true},"rekognition":{"name":"Rekognition","cors":true},"resourcegroupstaggingapi":{"name":"ResourceGroupsTaggingAPI"},"route53":{"name":"Route53","cors":true},"route53domains":{"name":"Route53Domains","cors":true},"s3":{"name":"S3","dualstackAvailable":true,"cors":true},"s3control":{"name":"S3Control","dualstackAvailable":true,"xmlNoDefaultLists":true},"servicecatalog":{"name":"ServiceCatalog","cors":true},"ses":{"prefix":"email","name":"SES","cors":true},"shield":{"name":"Shield"},"simpledb":{"prefix":"sdb","name":"SimpleDB"},"sms":{"name":"SMS"},"snowball":{"name":"Snowball"},"sns":{"name":"SNS","cors":true},"sqs":{"name":"SQS","cors":true},"ssm":{"name":"SSM","cors":true},"storagegateway":{"name":"StorageGateway","cors":true},"stepfunctions":{"prefix":"states","name":"StepFunctions"},"sts":{"name":"STS","cors":true},"support":{"name":"Support"},"swf":{"name":"SWF"},"xray":{"name":"XRay","cors":true},"waf":{"name":"WAF","cors":true},"wafregional":{"prefix":"waf-regional","name":"WAFRegional"},"workdocs":{"name":"WorkDocs","cors":true},"workspaces":{"name":"WorkSpaces"},"lexmodelbuildingservice":{"prefix":"lex-models","name":"LexModelBuildingService","cors":true},"marketplaceentitlementservice":{"prefix":"entitlement.marketplace","name":"MarketplaceEntitlementService"},"athena":{"name":"Athena","cors":true},"greengrass":{"name":"Greengrass"},"dax":{"name":"DAX"},"migrationhub":{"prefix":"AWSMigrationHub","name":"MigrationHub"},"cloudhsmv2":{"name":"CloudHSMV2","cors":true},"glue":{"name":"Glue"},"pricing":{"name":"Pricing","cors":true},"costexplorer":{"prefix":"ce","name":"CostExplorer","cors":true},"mediaconvert":{"name":"MediaConvert"},"medialive":{"name":"MediaLive"},"mediapackage":{"name":"MediaPackage"},"mediastore":{"name":"MediaStore"},"mediastoredata":{"prefix":"mediastore-data","name":"MediaStoreData","cors":true},"appsync":{"name":"AppSync"},"guardduty":{"name":"GuardDuty"},"mq":{"name":"MQ"},"comprehend":{"name":"Comprehend","cors":true},"iotjobsdataplane":{"prefix":"iot-jobs-data","name":"IoTJobsDataPlane"},"kinesisvideoarchivedmedia":{"prefix":"kinesis-video-archived-media","name":"KinesisVideoArchivedMedia","cors":true},"kinesisvideomedia":{"prefix":"kinesis-video-media","name":"KinesisVideoMedia","cors":true},"kinesisvideo":{"name":"KinesisVideo","cors":true},"sagemakerruntime":{"prefix":"runtime.sagemaker","name":"SageMakerRuntime"},"sagemaker":{"name":"SageMaker"},"translate":{"name":"Translate","cors":true},"resourcegroups":{"prefix":"resource-groups","name":"ResourceGroups","cors":true},"cloud9":{"name":"Cloud9"},"serverlessapplicationrepository":{"prefix":"serverlessrepo","name":"ServerlessApplicationRepository"},"servicediscovery":{"name":"ServiceDiscovery"},"workmail":{"name":"WorkMail"},"autoscalingplans":{"prefix":"autoscaling-plans","name":"AutoScalingPlans"},"transcribeservice":{"prefix":"transcribe","name":"TranscribeService"},"connect":{"name":"Connect","cors":true},"acmpca":{"prefix":"acm-pca","name":"ACMPCA"},"fms":{"name":"FMS"},"secretsmanager":{"name":"SecretsManager","cors":true},"iotanalytics":{"name":"IoTAnalytics","cors":true},"iot1clickdevicesservice":{"prefix":"iot1click-devices","name":"IoT1ClickDevicesService"},"iot1clickprojects":{"prefix":"iot1click-projects","name":"IoT1ClickProjects"},"pi":{"name":"PI"},"neptune":{"name":"Neptune"},"mediatailor":{"name":"MediaTailor"},"eks":{"name":"EKS"},"dlm":{"name":"DLM"},"signer":{"name":"Signer"},"chime":{"name":"Chime"},"pinpointemail":{"prefix":"pinpoint-email","name":"PinpointEmail"},"ram":{"name":"RAM"},"route53resolver":{"name":"Route53Resolver"},"pinpointsmsvoice":{"prefix":"sms-voice","name":"PinpointSMSVoice"},"quicksight":{"name":"QuickSight"},"rdsdataservice":{"prefix":"rds-data","name":"RDSDataService"},"amplify":{"name":"Amplify"},"datasync":{"name":"DataSync"},"robomaker":{"name":"RoboMaker"},"transfer":{"name":"Transfer"},"globalaccelerator":{"name":"GlobalAccelerator"},"comprehendmedical":{"name":"ComprehendMedical","cors":true},"kinesisanalyticsv2":{"name":"KinesisAnalyticsV2"},"mediaconnect":{"name":"MediaConnect"},"fsx":{"name":"FSx"},"securityhub":{"name":"SecurityHub"},"appmesh":{"name":"AppMesh","versions":["2018-10-01*"]},"licensemanager":{"prefix":"license-manager","name":"LicenseManager"},"kafka":{"name":"Kafka"},"apigatewaymanagementapi":{"name":"ApiGatewayManagementApi"},"apigatewayv2":{"name":"ApiGatewayV2"},"docdb":{"name":"DocDB"},"backup":{"name":"Backup"},"worklink":{"name":"WorkLink"},"textract":{"name":"Textract"},"managedblockchain":{"name":"ManagedBlockchain"},"mediapackagevod":{"prefix":"mediapackage-vod","name":"MediaPackageVod"},"groundstation":{"name":"GroundStation"},"iotthingsgraph":{"name":"IoTThingsGraph"},"iotevents":{"name":"IoTEvents"},"ioteventsdata":{"prefix":"iotevents-data","name":"IoTEventsData"},"personalize":{"name":"Personalize","cors":true},"personalizeevents":{"prefix":"personalize-events","name":"PersonalizeEvents","cors":true},"personalizeruntime":{"prefix":"personalize-runtime","name":"PersonalizeRuntime","cors":true},"applicationinsights":{"prefix":"application-insights","name":"ApplicationInsights"},"servicequotas":{"prefix":"service-quotas","name":"ServiceQuotas"},"ec2instanceconnect":{"prefix":"ec2-instance-connect","name":"EC2InstanceConnect"},"eventbridge":{"name":"EventBridge"},"lakeformation":{"name":"LakeFormation"},"forecastservice":{"prefix":"forecast","name":"ForecastService","cors":true},"forecastqueryservice":{"prefix":"forecastquery","name":"ForecastQueryService","cors":true},"qldb":{"name":"QLDB"},"qldbsession":{"prefix":"qldb-session","name":"QLDBSession"},"workmailmessageflow":{"name":"WorkMailMessageFlow"},"codestarnotifications":{"prefix":"codestar-notifications","name":"CodeStarNotifications"},"savingsplans":{"name":"SavingsPlans"},"sso":{"name":"SSO"},"ssooidc":{"prefix":"sso-oidc","name":"SSOOIDC"},"marketplacecatalog":{"prefix":"marketplace-catalog","name":"MarketplaceCatalog","cors":true},"dataexchange":{"name":"DataExchange"},"sesv2":{"name":"SESV2"},"migrationhubconfig":{"prefix":"migrationhub-config","name":"MigrationHubConfig"},"connectparticipant":{"name":"ConnectParticipant"},"appconfig":{"name":"AppConfig"},"iotsecuretunneling":{"name":"IoTSecureTunneling"},"wafv2":{"name":"WAFV2"},"elasticinference":{"prefix":"elastic-inference","name":"ElasticInference"},"imagebuilder":{"name":"Imagebuilder"},"schemas":{"name":"Schemas"},"accessanalyzer":{"name":"AccessAnalyzer"},"codegurureviewer":{"prefix":"codeguru-reviewer","name":"CodeGuruReviewer"},"codeguruprofiler":{"name":"CodeGuruProfiler"},"computeoptimizer":{"prefix":"compute-optimizer","name":"ComputeOptimizer"},"frauddetector":{"name":"FraudDetector"},"kendra":{"name":"Kendra"},"networkmanager":{"name":"NetworkManager"},"outposts":{"name":"Outposts"},"augmentedairuntime":{"prefix":"sagemaker-a2i-runtime","name":"AugmentedAIRuntime"},"ebs":{"name":"EBS"},"kinesisvideosignalingchannels":{"prefix":"kinesis-video-signaling","name":"KinesisVideoSignalingChannels","cors":true},"detective":{"name":"Detective"},"codestarconnections":{"prefix":"codestar-connections","name":"CodeStarconnections"},"synthetics":{"name":"Synthetics"},"iotsitewise":{"name":"IoTSiteWise"},"macie2":{"name":"Macie2"},"codeartifact":{"name":"CodeArtifact"},"ivs":{"name":"IVS"},"braket":{"name":"Braket"},"identitystore":{"name":"IdentityStore"},"appflow":{"name":"Appflow"},"redshiftdata":{"prefix":"redshift-data","name":"RedshiftData"},"ssoadmin":{"prefix":"sso-admin","name":"SSOAdmin"},"timestreamquery":{"prefix":"timestream-query","name":"TimestreamQuery"},"timestreamwrite":{"prefix":"timestream-write","name":"TimestreamWrite"},"s3outposts":{"name":"S3Outposts"},"databrew":{"name":"DataBrew"},"servicecatalogappregistry":{"prefix":"servicecatalog-appregistry","name":"ServiceCatalogAppRegistry"},"networkfirewall":{"prefix":"network-firewall","name":"NetworkFirewall"},"mwaa":{"name":"MWAA"},"amplifybackend":{"name":"AmplifyBackend"},"appintegrations":{"name":"AppIntegrations"},"connectcontactlens":{"prefix":"connect-contact-lens","name":"ConnectContactLens"},"devopsguru":{"prefix":"devops-guru","name":"DevOpsGuru"},"ecrpublic":{"prefix":"ecr-public","name":"ECRPUBLIC"},"lookoutvision":{"name":"LookoutVision"},"sagemakerfeaturestoreruntime":{"prefix":"sagemaker-featurestore-runtime","name":"SageMakerFeatureStoreRuntime"},"customerprofiles":{"prefix":"customer-profiles","name":"CustomerProfiles"},"auditmanager":{"name":"AuditManager"},"emrcontainers":{"prefix":"emr-containers","name":"EMRcontainers"},"healthlake":{"name":"HealthLake"},"sagemakeredge":{"prefix":"sagemaker-edge","name":"SagemakerEdge"},"amp":{"name":"Amp","cors":true},"greengrassv2":{"name":"GreengrassV2"},"iotdeviceadvisor":{"name":"IotDeviceAdvisor"},"iotfleethub":{"name":"IoTFleetHub"},"iotwireless":{"name":"IoTWireless"},"location":{"name":"Location","cors":true},"wellarchitected":{"name":"WellArchitected"},"lexmodelsv2":{"prefix":"models.lex.v2","name":"LexModelsV2"},"lexruntimev2":{"prefix":"runtime.lex.v2","name":"LexRuntimeV2","cors":true},"fis":{"name":"Fis"},"lookoutmetrics":{"name":"LookoutMetrics"},"mgn":{"name":"Mgn"},"lookoutequipment":{"name":"LookoutEquipment"},"nimble":{"name":"Nimble"},"finspace":{"name":"Finspace"},"finspacedata":{"prefix":"finspace-data","name":"Finspacedata"},"ssmcontacts":{"prefix":"ssm-contacts","name":"SSMContacts"},"ssmincidents":{"prefix":"ssm-incidents","name":"SSMIncidents"},"applicationcostprofiler":{"name":"ApplicationCostProfiler"},"apprunner":{"name":"AppRunner"},"proton":{"name":"Proton"},"route53recoverycluster":{"prefix":"route53-recovery-cluster","name":"Route53RecoveryCluster"},"route53recoverycontrolconfig":{"prefix":"route53-recovery-control-config","name":"Route53RecoveryControlConfig"},"route53recoveryreadiness":{"prefix":"route53-recovery-readiness","name":"Route53RecoveryReadiness"},"chimesdkidentity":{"prefix":"chime-sdk-identity","name":"ChimeSDKIdentity"},"chimesdkmessaging":{"prefix":"chime-sdk-messaging","name":"ChimeSDKMessaging"},"snowdevicemanagement":{"prefix":"snow-device-management","name":"SnowDeviceManagement"},"memorydb":{"name":"MemoryDB"},"opensearch":{"name":"OpenSearch"},"kafkaconnect":{"name":"KafkaConnect"},"voiceid":{"prefix":"voice-id","name":"VoiceID"},"wisdom":{"name":"Wisdom"},"account":{"name":"Account"},"cloudcontrol":{"name":"CloudControl"},"grafana":{"name":"Grafana"},"panorama":{"name":"Panorama"},"chimesdkmeetings":{"prefix":"chime-sdk-meetings","name":"ChimeSDKMeetings"},"resiliencehub":{"name":"Resiliencehub"},"migrationhubstrategy":{"name":"MigrationHubStrategy"},"appconfigdata":{"name":"AppConfigData"},"drs":{"name":"Drs"},"migrationhubrefactorspaces":{"prefix":"migration-hub-refactor-spaces","name":"MigrationHubRefactorSpaces"},"evidently":{"name":"Evidently"},"inspector2":{"name":"Inspector2"},"rbin":{"name":"Rbin"},"rum":{"name":"RUM"},"backupgateway":{"prefix":"backup-gateway","name":"BackupGateway"},"iottwinmaker":{"name":"IoTTwinMaker"},"workspacesweb":{"prefix":"workspaces-web","name":"WorkSpacesWeb"},"amplifyuibuilder":{"name":"AmplifyUIBuilder"},"keyspaces":{"name":"Keyspaces"},"billingconductor":{"name":"Billingconductor"},"pinpointsmsvoicev2":{"prefix":"pinpoint-sms-voice-v2","name":"PinpointSMSVoiceV2"},"ivschat":{"name":"Ivschat"},"chimesdkmediapipelines":{"prefix":"chime-sdk-media-pipelines","name":"ChimeSDKMediaPipelines"},"emrserverless":{"prefix":"emr-serverless","name":"EMRServerless"},"m2":{"name":"M2"},"connectcampaigns":{"name":"ConnectCampaigns"},"redshiftserverless":{"prefix":"redshift-serverless","name":"RedshiftServerless"},"rolesanywhere":{"name":"RolesAnywhere"},"licensemanagerusersubscriptions":{"prefix":"license-manager-user-subscriptions","name":"LicenseManagerUserSubscriptions"},"privatenetworks":{"name":"PrivateNetworks"},"supportapp":{"prefix":"support-app","name":"SupportApp"},"controltower":{"name":"ControlTower"},"iotfleetwise":{"name":"IoTFleetWise"},"migrationhuborchestrator":{"name":"MigrationHubOrchestrator"},"connectcases":{"name":"ConnectCases"},"resourceexplorer2":{"prefix":"resource-explorer-2","name":"ResourceExplorer2"},"scheduler":{"name":"Scheduler"},"chimesdkvoice":{"prefix":"chime-sdk-voice","name":"ChimeSDKVoice"},"ssmsap":{"prefix":"ssm-sap","name":"SsmSap"},"oam":{"name":"OAM"},"arczonalshift":{"prefix":"arc-zonal-shift","name":"ARCZonalShift"},"omics":{"name":"Omics"},"opensearchserverless":{"name":"OpenSearchServerless"},"securitylake":{"name":"SecurityLake"},"simspaceweaver":{"name":"SimSpaceWeaver"},"docdbelastic":{"prefix":"docdb-elastic","name":"DocDBElastic"},"sagemakergeospatial":{"prefix":"sagemaker-geospatial","name":"SageMakerGeospatial"},"codecatalyst":{"name":"CodeCatalyst"},"pipes":{"name":"Pipes"},"sagemakermetrics":{"prefix":"sagemaker-metrics","name":"SageMakerMetrics"},"kinesisvideowebrtcstorage":{"prefix":"kinesis-video-webrtc-storage","name":"KinesisVideoWebRTCStorage"},"licensemanagerlinuxsubscriptions":{"prefix":"license-manager-linux-subscriptions","name":"LicenseManagerLinuxSubscriptions"},"kendraranking":{"prefix":"kendra-ranking","name":"KendraRanking"},"cleanrooms":{"name":"CleanRooms"},"cloudtraildata":{"prefix":"cloudtrail-data","name":"CloudTrailData"},"tnb":{"name":"Tnb"},"internetmonitor":{"name":"InternetMonitor"},"ivsrealtime":{"prefix":"ivs-realtime","name":"IVSRealTime"},"vpclattice":{"prefix":"vpc-lattice","name":"VPCLattice"},"osis":{"name":"OSIS"},"mediapackagev2":{"name":"MediaPackageV2"},"paymentcryptography":{"prefix":"payment-cryptography","name":"PaymentCryptography"},"paymentcryptographydata":{"prefix":"payment-cryptography-data","name":"PaymentCryptographyData"},"codegurusecurity":{"prefix":"codeguru-security","name":"CodeGuruSecurity"},"verifiedpermissions":{"name":"VerifiedPermissions"},"appfabric":{"name":"AppFabric"},"medicalimaging":{"prefix":"medical-imaging","name":"MedicalImaging"},"entityresolution":{"name":"EntityResolution"},"managedblockchainquery":{"prefix":"managedblockchain-query","name":"ManagedBlockchainQuery"},"neptunedata":{"name":"Neptunedata"},"pcaconnectorad":{"prefix":"pca-connector-ad","name":"PcaConnectorAd"},"bedrock":{"name":"Bedrock"},"bedrockruntime":{"prefix":"bedrock-runtime","name":"BedrockRuntime"},"datazone":{"name":"DataZone"},"launchwizard":{"prefix":"launch-wizard","name":"LaunchWizard"},"trustedadvisor":{"name":"TrustedAdvisor"},"inspectorscan":{"prefix":"inspector-scan","name":"InspectorScan"},"bcmdataexports":{"prefix":"bcm-data-exports","name":"BCMDataExports"},"costoptimizationhub":{"prefix":"cost-optimization-hub","name":"CostOptimizationHub"},"eksauth":{"prefix":"eks-auth","name":"EKSAuth"},"freetier":{"name":"FreeTier"},"repostspace":{"name":"Repostspace"},"workspacesthinclient":{"prefix":"workspaces-thin-client","name":"WorkSpacesThinClient"},"b2bi":{"name":"B2bi"},"bedrockagent":{"prefix":"bedrock-agent","name":"BedrockAgent"},"bedrockagentruntime":{"prefix":"bedrock-agent-runtime","name":"BedrockAgentRuntime"},"qbusiness":{"name":"QBusiness"},"qconnect":{"name":"QConnect"},"cleanroomsml":{"name":"CleanRoomsML"},"marketplaceagreement":{"prefix":"marketplace-agreement","name":"MarketplaceAgreement"},"marketplacedeployment":{"prefix":"marketplace-deployment","name":"MarketplaceDeployment"},"networkmonitor":{"name":"NetworkMonitor"},"supplychain":{"name":"SupplyChain"},"artifact":{"name":"Artifact"},"chatbot":{"name":"Chatbot"},"timestreaminfluxdb":{"prefix":"timestream-influxdb","name":"TimestreamInfluxDB"},"codeconnections":{"name":"CodeConnections"},"deadline":{"name":"Deadline"},"controlcatalog":{"name":"ControlCatalog"},"route53profiles":{"name":"Route53Profiles"},"mailmanager":{"name":"MailManager"},"taxsettings":{"name":"TaxSettings"},"applicationsignals":{"prefix":"application-signals","name":"ApplicationSignals"},"pcaconnectorscep":{"prefix":"pca-connector-scep","name":"PcaConnectorScep"},"apptest":{"name":"AppTest"},"qapps":{"name":"QApps"},"ssmquicksetup":{"prefix":"ssm-quicksetup","name":"SSMQuickSetup"},"pcs":{"name":"PCS"}}');

/***/ },

/***/ 9105
(module) {

module.exports = /*#__PURE__*/JSON.parse('{"version":"2.0","metadata":{"apiVersion":"2011-06-15","endpointPrefix":"sts","globalEndpoint":"sts.amazonaws.com","protocol":"query","serviceAbbreviation":"AWS STS","serviceFullName":"AWS Security Token Service","serviceId":"STS","signatureVersion":"v4","uid":"sts-2011-06-15","xmlNamespace":"https://sts.amazonaws.com/doc/2011-06-15/"},"operations":{"AssumeRole":{"input":{"type":"structure","required":["RoleArn","RoleSessionName"],"members":{"RoleArn":{},"RoleSessionName":{},"PolicyArns":{"shape":"S4"},"Policy":{},"DurationSeconds":{"type":"integer"},"Tags":{"shape":"S8"},"TransitiveTagKeys":{"type":"list","member":{}},"ExternalId":{},"SerialNumber":{},"TokenCode":{},"SourceIdentity":{},"ProvidedContexts":{"type":"list","member":{"type":"structure","members":{"ProviderArn":{},"ContextAssertion":{}}}}}},"output":{"resultWrapper":"AssumeRoleResult","type":"structure","members":{"Credentials":{"shape":"Sl"},"AssumedRoleUser":{"shape":"Sq"},"PackedPolicySize":{"type":"integer"},"SourceIdentity":{}}}},"AssumeRoleWithSAML":{"input":{"type":"structure","required":["RoleArn","PrincipalArn","SAMLAssertion"],"members":{"RoleArn":{},"PrincipalArn":{},"SAMLAssertion":{"type":"string","sensitive":true},"PolicyArns":{"shape":"S4"},"Policy":{},"DurationSeconds":{"type":"integer"}}},"output":{"resultWrapper":"AssumeRoleWithSAMLResult","type":"structure","members":{"Credentials":{"shape":"Sl"},"AssumedRoleUser":{"shape":"Sq"},"PackedPolicySize":{"type":"integer"},"Subject":{},"SubjectType":{},"Issuer":{},"Audience":{},"NameQualifier":{},"SourceIdentity":{}}}},"AssumeRoleWithWebIdentity":{"input":{"type":"structure","required":["RoleArn","RoleSessionName","WebIdentityToken"],"members":{"RoleArn":{},"RoleSessionName":{},"WebIdentityToken":{"type":"string","sensitive":true},"ProviderId":{},"PolicyArns":{"shape":"S4"},"Policy":{},"DurationSeconds":{"type":"integer"}}},"output":{"resultWrapper":"AssumeRoleWithWebIdentityResult","type":"structure","members":{"Credentials":{"shape":"Sl"},"SubjectFromWebIdentityToken":{},"AssumedRoleUser":{"shape":"Sq"},"PackedPolicySize":{"type":"integer"},"Provider":{},"Audience":{},"SourceIdentity":{}}}},"DecodeAuthorizationMessage":{"input":{"type":"structure","required":["EncodedMessage"],"members":{"EncodedMessage":{}}},"output":{"resultWrapper":"DecodeAuthorizationMessageResult","type":"structure","members":{"DecodedMessage":{}}}},"GetAccessKeyInfo":{"input":{"type":"structure","required":["AccessKeyId"],"members":{"AccessKeyId":{}}},"output":{"resultWrapper":"GetAccessKeyInfoResult","type":"structure","members":{"Account":{}}}},"GetCallerIdentity":{"input":{"type":"structure","members":{}},"output":{"resultWrapper":"GetCallerIdentityResult","type":"structure","members":{"UserId":{},"Account":{},"Arn":{}}}},"GetFederationToken":{"input":{"type":"structure","required":["Name"],"members":{"Name":{},"Policy":{},"PolicyArns":{"shape":"S4"},"DurationSeconds":{"type":"integer"},"Tags":{"shape":"S8"}}},"output":{"resultWrapper":"GetFederationTokenResult","type":"structure","members":{"Credentials":{"shape":"Sl"},"FederatedUser":{"type":"structure","required":["FederatedUserId","Arn"],"members":{"FederatedUserId":{},"Arn":{}}},"PackedPolicySize":{"type":"integer"}}}},"GetSessionToken":{"input":{"type":"structure","members":{"DurationSeconds":{"type":"integer"},"SerialNumber":{},"TokenCode":{}}},"output":{"resultWrapper":"GetSessionTokenResult","type":"structure","members":{"Credentials":{"shape":"Sl"}}}}},"shapes":{"S4":{"type":"list","member":{"type":"structure","members":{"arn":{}}}},"S8":{"type":"list","member":{"type":"structure","required":["Key","Value"],"members":{"Key":{},"Value":{}}}},"Sl":{"type":"structure","required":["AccessKeyId","SecretAccessKey","SessionToken","Expiration"],"members":{"AccessKeyId":{},"SecretAccessKey":{"type":"string","sensitive":true},"SessionToken":{},"Expiration":{"type":"timestamp"}}},"Sq":{"type":"structure","required":["AssumedRoleId","Arn"],"members":{"AssumedRoleId":{},"Arn":{}}}}}');

/***/ },

/***/ 4747
(module) {

module.exports = {"X":{}};

/***/ },

/***/ 3548
(module) {

module.exports = /*#__PURE__*/JSON.parse('{"rules":{"*/*":{"endpoint":"{service}.{region}.amazonaws.com"},"cn-*/*":{"endpoint":"{service}.{region}.amazonaws.com.cn"},"eu-isoe-*/*":"euIsoe","us-iso-*/*":"usIso","us-isob-*/*":"usIsob","us-isof-*/*":"usIsof","*/budgets":"globalSSL","*/cloudfront":"globalSSL","*/sts":"globalSSL","*/importexport":{"endpoint":"{service}.amazonaws.com","signatureVersion":"v2","globalEndpoint":true},"*/route53":"globalSSL","cn-*/route53":{"endpoint":"{service}.amazonaws.com.cn","globalEndpoint":true,"signingRegion":"cn-northwest-1"},"us-gov-*/route53":"globalGovCloud","us-iso-*/route53":{"endpoint":"{service}.c2s.ic.gov","globalEndpoint":true,"signingRegion":"us-iso-east-1"},"us-isob-*/route53":{"endpoint":"{service}.sc2s.sgov.gov","globalEndpoint":true,"signingRegion":"us-isob-east-1"},"us-isof-*/route53":"globalUsIsof","eu-isoe-*/route53":"globalEuIsoe","*/waf":"globalSSL","*/iam":"globalSSL","cn-*/iam":{"endpoint":"{service}.cn-north-1.amazonaws.com.cn","globalEndpoint":true,"signingRegion":"cn-north-1"},"us-iso-*/iam":{"endpoint":"{service}.us-iso-east-1.c2s.ic.gov","globalEndpoint":true,"signingRegion":"us-iso-east-1"},"us-gov-*/iam":"globalGovCloud","*/ce":{"endpoint":"{service}.us-east-1.amazonaws.com","globalEndpoint":true,"signingRegion":"us-east-1"},"cn-*/ce":{"endpoint":"{service}.cn-northwest-1.amazonaws.com.cn","globalEndpoint":true,"signingRegion":"cn-northwest-1"},"us-gov-*/sts":{"endpoint":"{service}.{region}.amazonaws.com"},"us-gov-west-1/s3":"s3signature","us-west-1/s3":"s3signature","us-west-2/s3":"s3signature","eu-west-1/s3":"s3signature","ap-southeast-1/s3":"s3signature","ap-southeast-2/s3":"s3signature","ap-northeast-1/s3":"s3signature","sa-east-1/s3":"s3signature","us-east-1/s3":{"endpoint":"{service}.amazonaws.com","signatureVersion":"s3"},"us-east-1/sdb":{"endpoint":"{service}.amazonaws.com","signatureVersion":"v2"},"*/sdb":{"endpoint":"{service}.{region}.amazonaws.com","signatureVersion":"v2"},"*/resource-explorer-2":"dualstackByDefault","*/kendra-ranking":"dualstackByDefault","*/internetmonitor":"dualstackByDefault","*/codecatalyst":"globalDualstackByDefault"},"fipsRules":{"*/*":"fipsStandard","us-gov-*/*":"fipsStandard","us-iso-*/*":{"endpoint":"{service}-fips.{region}.c2s.ic.gov"},"us-iso-*/dms":"usIso","us-isob-*/*":{"endpoint":"{service}-fips.{region}.sc2s.sgov.gov"},"us-isob-*/dms":"usIsob","cn-*/*":{"endpoint":"{service}-fips.{region}.amazonaws.com.cn"},"*/api.ecr":"fips.api.ecr","*/api.sagemaker":"fips.api.sagemaker","*/batch":"fipsDotPrefix","*/eks":"fipsDotPrefix","*/models.lex":"fips.models.lex","*/runtime.lex":"fips.runtime.lex","*/runtime.sagemaker":{"endpoint":"runtime-fips.sagemaker.{region}.amazonaws.com"},"*/iam":"fipsWithoutRegion","*/route53":"fipsWithoutRegion","*/transcribe":"fipsDotPrefix","*/waf":"fipsWithoutRegion","us-gov-*/transcribe":"fipsDotPrefix","us-gov-*/api.ecr":"fips.api.ecr","us-gov-*/models.lex":"fips.models.lex","us-gov-*/runtime.lex":"fips.runtime.lex","us-gov-*/access-analyzer":"fipsWithServiceOnly","us-gov-*/acm":"fipsWithServiceOnly","us-gov-*/acm-pca":"fipsWithServiceOnly","us-gov-*/api.sagemaker":"fipsWithServiceOnly","us-gov-*/appconfig":"fipsWithServiceOnly","us-gov-*/application-autoscaling":"fipsWithServiceOnly","us-gov-*/autoscaling":"fipsWithServiceOnly","us-gov-*/autoscaling-plans":"fipsWithServiceOnly","us-gov-*/batch":"fipsWithServiceOnly","us-gov-*/cassandra":"fipsWithServiceOnly","us-gov-*/clouddirectory":"fipsWithServiceOnly","us-gov-*/cloudformation":"fipsWithServiceOnly","us-gov-*/cloudshell":"fipsWithServiceOnly","us-gov-*/cloudtrail":"fipsWithServiceOnly","us-gov-*/config":"fipsWithServiceOnly","us-gov-*/connect":"fipsWithServiceOnly","us-gov-*/databrew":"fipsWithServiceOnly","us-gov-*/dlm":"fipsWithServiceOnly","us-gov-*/dms":"fipsWithServiceOnly","us-gov-*/dynamodb":"fipsWithServiceOnly","us-gov-*/ec2":"fipsWithServiceOnly","us-gov-*/eks":"fipsWithServiceOnly","us-gov-*/elasticache":"fipsWithServiceOnly","us-gov-*/elasticbeanstalk":"fipsWithServiceOnly","us-gov-*/elasticloadbalancing":"fipsWithServiceOnly","us-gov-*/elasticmapreduce":"fipsWithServiceOnly","us-gov-*/events":"fipsWithServiceOnly","us-gov-*/fis":"fipsWithServiceOnly","us-gov-*/glacier":"fipsWithServiceOnly","us-gov-*/greengrass":"fipsWithServiceOnly","us-gov-*/guardduty":"fipsWithServiceOnly","us-gov-*/identitystore":"fipsWithServiceOnly","us-gov-*/imagebuilder":"fipsWithServiceOnly","us-gov-*/kafka":"fipsWithServiceOnly","us-gov-*/kinesis":"fipsWithServiceOnly","us-gov-*/logs":"fipsWithServiceOnly","us-gov-*/mediaconvert":"fipsWithServiceOnly","us-gov-*/monitoring":"fipsWithServiceOnly","us-gov-*/networkmanager":"fipsWithServiceOnly","us-gov-*/organizations":"fipsWithServiceOnly","us-gov-*/outposts":"fipsWithServiceOnly","us-gov-*/participant.connect":"fipsWithServiceOnly","us-gov-*/ram":"fipsWithServiceOnly","us-gov-*/rds":"fipsWithServiceOnly","us-gov-*/redshift":"fipsWithServiceOnly","us-gov-*/resource-groups":"fipsWithServiceOnly","us-gov-*/runtime.sagemaker":"fipsWithServiceOnly","us-gov-*/serverlessrepo":"fipsWithServiceOnly","us-gov-*/servicecatalog-appregistry":"fipsWithServiceOnly","us-gov-*/servicequotas":"fipsWithServiceOnly","us-gov-*/sns":"fipsWithServiceOnly","us-gov-*/sqs":"fipsWithServiceOnly","us-gov-*/ssm":"fipsWithServiceOnly","us-gov-*/streams.dynamodb":"fipsWithServiceOnly","us-gov-*/sts":"fipsWithServiceOnly","us-gov-*/support":"fipsWithServiceOnly","us-gov-*/swf":"fipsWithServiceOnly","us-gov-west-1/states":"fipsWithServiceOnly","us-iso-east-1/elasticfilesystem":{"endpoint":"elasticfilesystem-fips.{region}.c2s.ic.gov"},"us-gov-west-1/organizations":"fipsWithServiceOnly","us-gov-west-1/route53":{"endpoint":"route53.us-gov.amazonaws.com"},"*/resource-explorer-2":"fipsDualstackByDefault","*/kendra-ranking":"dualstackByDefault","*/internetmonitor":"dualstackByDefault","*/codecatalyst":"fipsGlobalDualstackByDefault"},"dualstackRules":{"*/*":{"endpoint":"{service}.{region}.api.aws"},"cn-*/*":{"endpoint":"{service}.{region}.api.amazonwebservices.com.cn"},"*/s3":"dualstackLegacy","cn-*/s3":"dualstackLegacyCn","*/s3-control":"dualstackLegacy","cn-*/s3-control":"dualstackLegacyCn","ap-south-1/ec2":"dualstackLegacyEc2","eu-west-1/ec2":"dualstackLegacyEc2","sa-east-1/ec2":"dualstackLegacyEc2","us-east-1/ec2":"dualstackLegacyEc2","us-east-2/ec2":"dualstackLegacyEc2","us-west-2/ec2":"dualstackLegacyEc2"},"dualstackFipsRules":{"*/*":{"endpoint":"{service}-fips.{region}.api.aws"},"cn-*/*":{"endpoint":"{service}-fips.{region}.api.amazonwebservices.com.cn"},"*/s3":"dualstackFipsLegacy","cn-*/s3":"dualstackFipsLegacyCn","*/s3-control":"dualstackFipsLegacy","cn-*/s3-control":"dualstackFipsLegacyCn"},"patterns":{"globalSSL":{"endpoint":"https://{service}.amazonaws.com","globalEndpoint":true,"signingRegion":"us-east-1"},"globalGovCloud":{"endpoint":"{service}.us-gov.amazonaws.com","globalEndpoint":true,"signingRegion":"us-gov-west-1"},"globalUsIsof":{"endpoint":"{service}.csp.hci.ic.gov","globalEndpoint":true,"signingRegion":"us-isof-south-1"},"globalEuIsoe":{"endpoint":"{service}.cloud.adc-e.uk","globalEndpoint":true,"signingRegion":"eu-isoe-west-1"},"s3signature":{"endpoint":"{service}.{region}.amazonaws.com","signatureVersion":"s3"},"euIsoe":{"endpoint":"{service}.{region}.cloud.adc-e.uk"},"usIso":{"endpoint":"{service}.{region}.c2s.ic.gov"},"usIsob":{"endpoint":"{service}.{region}.sc2s.sgov.gov"},"usIsof":{"endpoint":"{service}.{region}.csp.hci.ic.gov"},"fipsStandard":{"endpoint":"{service}-fips.{region}.amazonaws.com"},"fipsDotPrefix":{"endpoint":"fips.{service}.{region}.amazonaws.com"},"fipsWithoutRegion":{"endpoint":"{service}-fips.amazonaws.com"},"fips.api.ecr":{"endpoint":"ecr-fips.{region}.amazonaws.com"},"fips.api.sagemaker":{"endpoint":"api-fips.sagemaker.{region}.amazonaws.com"},"fips.models.lex":{"endpoint":"models-fips.lex.{region}.amazonaws.com"},"fips.runtime.lex":{"endpoint":"runtime-fips.lex.{region}.amazonaws.com"},"fipsWithServiceOnly":{"endpoint":"{service}.{region}.amazonaws.com"},"dualstackLegacy":{"endpoint":"{service}.dualstack.{region}.amazonaws.com"},"dualstackLegacyCn":{"endpoint":"{service}.dualstack.{region}.amazonaws.com.cn"},"dualstackFipsLegacy":{"endpoint":"{service}-fips.dualstack.{region}.amazonaws.com"},"dualstackFipsLegacyCn":{"endpoint":"{service}-fips.dualstack.{region}.amazonaws.com.cn"},"dualstackLegacyEc2":{"endpoint":"api.ec2.{region}.aws"},"dualstackByDefault":{"endpoint":"{service}.{region}.api.aws"},"fipsDualstackByDefault":{"endpoint":"{service}-fips.{region}.api.aws"},"globalDualstackByDefault":{"endpoint":"{service}.global.api.aws"},"fipsGlobalDualstackByDefault":{"endpoint":"{service}-fips.global.api.aws"}}}');

/***/ }

/******/ });
/************************************************************************/
/******/ // The module cache
/******/ var __webpack_module_cache__ = {};
/******/ 
/******/ // The require function
/******/ function __webpack_require__(moduleId) {
/******/ 	// Check if module is in cache
/******/ 	var cachedModule = __webpack_module_cache__[moduleId];
/******/ 	if (cachedModule !== undefined) {
/******/ 		return cachedModule.exports;
/******/ 	}
/******/ 	// Create a new module (and put it into the cache)
/******/ 	var module = __webpack_module_cache__[moduleId] = {
/******/ 		// no module.id needed
/******/ 		// no module.loaded needed
/******/ 		exports: {}
/******/ 	};
/******/ 
/******/ 	// Execute the module function
/******/ 	__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 
/******/ 	// Return the exports of the module
/******/ 	return module.exports;
/******/ }
/******/ 
/************************************************************************/
/******/ /* webpack/runtime/compat get default export */
/******/ (() => {
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = (module) => {
/******/ 		var getter = module && module.__esModule ?
/******/ 			() => (module['default']) :
/******/ 			() => (module);
/******/ 		__webpack_require__.d(getter, { a: getter });
/******/ 		return getter;
/******/ 	};
/******/ })();
/******/ 
/******/ /* webpack/runtime/define property getters */
/******/ (() => {
/******/ 	// define getter functions for harmony exports
/******/ 	__webpack_require__.d = (exports, definition) => {
/******/ 		for(var key in definition) {
/******/ 			if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 				Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 			}
/******/ 		}
/******/ 	};
/******/ })();
/******/ 
/******/ /* webpack/runtime/hasOwnProperty shorthand */
/******/ (() => {
/******/ 	__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ })();
/******/ 
/******/ /* webpack/runtime/make namespace object */
/******/ (() => {
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = (exports) => {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/ })();
/******/ 
/************************************************************************/
var __webpack_exports__ = {};
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   handler: () => (/* binding */ handler)
/* harmony export */ });
/* harmony import */ var aws_sdk_clients_sts_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(2788);
/* harmony import */ var aws_sdk_clients_sts_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(aws_sdk_clients_sts_js__WEBPACK_IMPORTED_MODULE_0__);


const client = new (aws_sdk_clients_sts_js__WEBPACK_IMPORTED_MODULE_0___default())();

const handler = async () => client.getCallerIdentity().promise();

module.exports = __webpack_exports__;
