var $fHheo$awssdkclientsts = require("@aws-sdk/client-sts");


function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}

$parcel$export(module.exports, "handler", () => $341871660ad46082$export$c3c52e219617878);

const $341871660ad46082$var$client = new (0, $fHheo$awssdkclientsts.STSClient)();
const $341871660ad46082$export$c3c52e219617878 = async ()=>$341871660ad46082$var$client.send(new (0, $fHheo$awssdkclientsts.GetCallerIdentityCommand)());


