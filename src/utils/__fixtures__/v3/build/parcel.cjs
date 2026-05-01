var $j3GqM$awssdkclientsts = require("@aws-sdk/client-sts");


function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}

$parcel$export(module.exports, "handler", () => $eb2795c9a742cec3$export$c3c52e219617878);

const $eb2795c9a742cec3$var$client = new (0, $j3GqM$awssdkclientsts.STSClient)();
const $eb2795c9a742cec3$export$c3c52e219617878 = async ()=>$eb2795c9a742cec3$var$client.send(new (0, $j3GqM$awssdkclientsts.GetCallerIdentityCommand)());


