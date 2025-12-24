import {STSClient as $89kMf$STSClient, GetCallerIdentityCommand as $89kMf$GetCallerIdentityCommand} from "@aws-sdk/client-sts";


const $a1824f2350e24476$var$client = new (0, $89kMf$STSClient)();
const $a1824f2350e24476$export$c3c52e219617878 = async ()=>$a1824f2350e24476$var$client.send(new (0, $89kMf$GetCallerIdentityCommand)());


export {$a1824f2350e24476$export$c3c52e219617878 as handler};
