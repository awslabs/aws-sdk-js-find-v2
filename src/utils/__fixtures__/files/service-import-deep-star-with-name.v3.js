import { AccessAnalyzer as AccessAnalyzerClient } from "@aws-sdk/client-accessanalyzer";
import { ACM as ACMClient } from "@aws-sdk/client-acm";
import { ApplicationDiscoveryService as DiscoveryClient } from "@aws-sdk/client-application-discovery-service";

new AccessAnalyzerClient();
new DiscoveryClient();
new ACMClient();
