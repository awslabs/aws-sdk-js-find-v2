const {
  AccessAnalyzer: AccessAnalyzerClient
} = require("@aws-sdk/client-accessanalyzer");
const {
  ACM: ACMClient
} = require("@aws-sdk/client-acm");
const {
  ApplicationDiscoveryService: DiscoveryClient
} = require("@aws-sdk/client-application-discovery-service");

new AccessAnalyzerClient();
new DiscoveryClient();
new ACMClient();
