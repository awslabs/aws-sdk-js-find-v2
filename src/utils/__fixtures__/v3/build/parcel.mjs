import {STSClient as $ius22$STSClient, GetCallerIdentityCommand as $ius22$GetCallerIdentityCommand} from "@aws-sdk/client-sts";


const $c26794c0ff393f32$var$client = new (0, $ius22$STSClient)();
const $c26794c0ff393f32$export$c3c52e219617878 = async ()=>$c26794c0ff393f32$var$client.send(new (0, $ius22$GetCallerIdentityCommand)());


export {$c26794c0ff393f32$export$c3c52e219617878 as handler};
