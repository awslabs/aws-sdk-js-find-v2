var $6eZio$awssdkclientsts = require("@aws-sdk/client-sts");


function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}

$parcel$export(module.exports, "handler", () => $3bb8d7964bf13401$export$c3c52e219617878);

const $3bb8d7964bf13401$var$client = new (0, $6eZio$awssdkclientsts.STSClient)();
const $3bb8d7964bf13401$export$c3c52e219617878 = async ()=>$3bb8d7964bf13401$var$client.send(new (0, $6eZio$awssdkclientsts.GetCallerIdentityCommand)());


