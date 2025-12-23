import pLimit from "p-limit";
import { exec } from "node:child_process";
import { readdir } from "node:fs/promises";
import { cpus } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { getInputPath } from "./configs/utils/getInputPath.js";
import { Version } from "./configs/utils/constants.js";

const execAsync = promisify(exec);

const configDir = join(import.meta.dirname, "configs");
const jsFiles = (await readdir(configDir)).filter((file) => file.endsWith(".js"));

const promises = [];
for (const fileName of jsFiles) {
  const bundlerName = fileName.substring(0, fileName.indexOf("."));
  const filePath = join(configDir, fileName);

  if (bundlerName === "esbuild") {
    // esbuild doesn't support config.
    promises.push(async () => {
      try {
        console.log(`[${bundlerName}] Running with code '${fileName}'`);
        await execAsync(`node ${filePath}`);
      } catch (error) {
        throw new Error(`[${bundlerName}] failed`, { cause: error });
      }
    });
    continue;
  }

  promises.push(async () => {
    try {
      console.log(`[${bundlerName}] Running with config '${fileName}'`);
      await execAsync(`npx ${bundlerName} -c ${filePath}`);
    } catch (error) {
      throw new Error(`[${bundlerName}] failed`, { cause: error });
    }
  });
}

// Parcel uses configuration from package.json
for (const version of Object.values(Version)) {
  promises.push(async () => {
    const bundlerName = "parcel";
    try {
      console.log(`[${bundlerName}] Running for '${version}'`);
      execAsync(`npx parcel build ${getInputPath(version)} --no-source-maps`);
    } catch (error) {
      throw new Error(`[${bundlerName}] failed`, { cause: error });
    }
  });
}

const limit = pLimit(cpus().length || 1);
await Promise.all(promises.map((promise) => limit(promise)));
