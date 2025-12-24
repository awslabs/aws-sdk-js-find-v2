import {STSClient as $2qsul$STSClient, GetCallerIdentityCommand as $2qsul$GetCallerIdentityCommand} from "@aws-sdk/client-sts";


const $4411d4be9676e056$var$client = new (0, $2qsul$STSClient)();
const $4411d4be9676e056$export$c3c52e219617878 = async ()=>$4411d4be9676e056$var$client.send(new (0, $2qsul$GetCallerIdentityCommand)());


export {$4411d4be9676e056$export$c3c52e219617878 as handler};
