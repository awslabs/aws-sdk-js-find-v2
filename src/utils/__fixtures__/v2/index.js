import STS from "aws-sdk/clients/sts.js";

const client = new STS();

export const handler = async () => client.getCallerIdentity().promise();
