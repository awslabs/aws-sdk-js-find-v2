import { exec } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { getFixturesDir } from "./configs/utils/getFixturesDir.js";
import { Version } from "./configs/utils/constants.js";

const execAsync = promisify(exec);

const configDir = join(import.meta.dirname, "configs");
const jsFiles = (await readdir(configDir)).filter((file) => file.endsWith(".js"));

for (const fileName of jsFiles) {
  const bundlerName = fileName.substring(0, fileName.indexOf("."));
  const filePath = join(configDir, fileName);

  if (bundlerName === "esbuild") {
    // esbuild doesn't support config.
    console.log(`[${bundlerName}] Running with code '${fileName}'`);
    await execAsync(`node ${filePath}`);
    continue;
  }

  console.log(`[${bundlerName}] Running with config '${fileName}'`);
  await execAsync(`npx ${bundlerName} -c ${filePath}`);
}

// Parcel uses configuration from package.json
for (const version of Object.values(Version)) {
  const bundlerName = "parcel";
  console.log(`[${bundlerName}] Running for '${version}'`);
  await execAsync(`npx parcel build ${join(getFixturesDir(), version)} --no-cache`);
}
