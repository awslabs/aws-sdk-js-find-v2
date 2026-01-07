import { join } from "node:path";

export const NODE_MODULES = "node_modules";

export const AWS_SDK = "aws-sdk";

export const PACKAGE_JSON = "package.json";

export const AWS_SDK_PACKAGE_JSON = join(NODE_MODULES, AWS_SDK, PACKAGE_JSON);
