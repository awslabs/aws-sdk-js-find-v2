import type { Lambda } from "@aws-sdk/client-lambda";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { JS_SDK_V2_MARKER } from "./constants.ts";
import { downloadFile } from "./utils/downloadFile.ts";

export const scanLambdaFunction = async (client: Lambda, functionName: string) => {
  const response = await client.getFunction({ FunctionName: functionName });
  if (!response.Code?.Location) {
    console.log(`${JS_SDK_V2_MARKER.UNKNOWN} ${functionName}: Code location not found.`);
    return;
  }

  const zipPath = join(tmpdir(), `${functionName}.zip`);
  try {
    await downloadFile(response.Code.Location, zipPath);
    const result = await new Promise<string>((resolve, reject) => {
      const worker = new Worker(new URL("./scanLambdaFunction.worker.js", import.meta.url), {
        workerData: { zipPath },
      });
      worker.on("message", resolve);
      worker.on("error", reject);
    });
    console.log(`${result} ${functionName}`);
  } finally {
    await rm(zipPath, { force: true });
  }
};
