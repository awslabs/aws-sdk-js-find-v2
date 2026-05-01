import {STSClient as $lonhb$STSClient, GetCallerIdentityCommand as $lonhb$GetCallerIdentityCommand} from "@aws-sdk/client-sts";


const $3752f3bf108a5116$var$client = new (0, $lonhb$STSClient)();
const $3752f3bf108a5116$export$c3c52e219617878 = async ()=>$3752f3bf108a5116$var$client.send(new (0, $lonhb$GetCallerIdentityCommand)());


export {$3752f3bf108a5116$export$c3c52e219617878 as handler};
