var $gXZXF$awssdkclientsts = require("@aws-sdk/client-sts");


function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}

$parcel$export(module.exports, "handler", () => $59204422e7f212b9$export$c3c52e219617878);

const $59204422e7f212b9$var$client = new (0, $gXZXF$awssdkclientsts.STSClient)();
const $59204422e7f212b9$export$c3c52e219617878 = async ()=>$59204422e7f212b9$var$client.send(new (0, $gXZXF$awssdkclientsts.GetCallerIdentityCommand)());


