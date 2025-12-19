import { parentPort, workerData } from "node:worker_threads";
import { hasSdkV2InBundle } from "./utils/hasSdkV2InBundle.ts";
import { JS_SDK_V2_MARKER } from "./constants.ts";

const { packageJsonContents, bundleContent } = workerData as {
  packageJsonContents: string[] | undefined;
  bundleContent: string | undefined;
};

const scan = () => {
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

parentPort?.postMessage(scan());
