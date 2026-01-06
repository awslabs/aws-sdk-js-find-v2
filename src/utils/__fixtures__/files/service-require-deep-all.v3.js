const { AccessAnalyzer } = require("@aws-sdk/client-accessanalyzer");
const { ACM } = require("@aws-sdk/client-acm");
const { ApplicationDiscoveryService } = require("@aws-sdk/client-application-discovery-service");

new AccessAnalyzer();
new ApplicationDiscoveryService();
new ACM();
