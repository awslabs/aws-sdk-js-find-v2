import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";

const client = new STSClient();

export const handler = async () => client.send(new GetCallerIdentityCommand());
