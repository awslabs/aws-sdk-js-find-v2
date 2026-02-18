import {STSClient as $4NZ5z$STSClient, GetCallerIdentityCommand as $4NZ5z$GetCallerIdentityCommand} from "@aws-sdk/client-sts";


const $82c50f5d8caffe0f$var$client = new (0, $4NZ5z$STSClient)();
const $82c50f5d8caffe0f$export$c3c52e219617878 = async ()=>$82c50f5d8caffe0f$var$client.send(new (0, $4NZ5z$GetCallerIdentityCommand)());


export {$82c50f5d8caffe0f$export$c3c52e219617878 as handler};
