var $5GwW3$awssdkclientsts = require("@aws-sdk/client-sts");


function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}

$parcel$export(module.exports, "handler", () => $938e6321027dc68a$export$c3c52e219617878);

const $938e6321027dc68a$var$client = new (0, $5GwW3$awssdkclientsts.STSClient)();
const $938e6321027dc68a$export$c3c52e219617878 = async ()=>$938e6321027dc68a$var$client.send(new (0, $5GwW3$awssdkclientsts.GetCallerIdentityCommand)());


