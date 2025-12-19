import { parentPort, workerData } from "node:worker_threads";
import { getLambdaFunctionContents } from "./utils/getLambdaFunctionContents.ts";
import { hasSdkV2InBundle } from "./utils/hasSdkV2InBundle.ts";
import { JS_SDK_V2_MARKER } from "./constants.ts";

const { zipPath } = workerData as { zipPath: string };

const scan = async () => {
  const { packageJsonContents, bundleContent } = await getLambdaFunctionContents(zipPath);

  if (packageJsonContents?.length) {
    for (const content of packageJsonContents) {
      try {
        if ("aws-sdk" in (JSON.parse(content).dependencies || {})) {
          return JS_SDK_V2_MARKER.Y;
        }
      } catch {}
    }
  }

  if (bundleContent && hasSdkV2InBundle(bundleContent)) {
    return JS_SDK_V2_MARKER.Y;
  }

  return JS_SDK_V2_MARKER.N;
};

scan().then((result) => parentPort?.postMessage(result));
