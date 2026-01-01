import {STSClient as $g6jQl$STSClient, GetCallerIdentityCommand as $g6jQl$GetCallerIdentityCommand} from "@aws-sdk/client-sts";


const $a1824f2350e24476$var$client = new (0, $g6jQl$STSClient)();
const $a1824f2350e24476$export$c3c52e219617878 = async ()=>$a1824f2350e24476$var$client.send(new (0, $g6jQl$GetCallerIdentityCommand)());


export {$a1824f2350e24476$export$c3c52e219617878 as handler};
