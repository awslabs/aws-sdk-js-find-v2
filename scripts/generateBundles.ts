import pLimit from "p-limit";
import { exec } from "node:child_process";
import { readdir } from "node:fs/promises";
import { cpus } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

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
      console.log(`Running '${bundlerName}' with code '${fileName}'`);
      await execAsync(`node ${filePath}`);
    });
    continue;
  }

  promises.push(async () => {
    console.log(`Running '${bundlerName}' with config '${fileName}'`);
    await execAsync(`npx ${bundlerName} -c ${filePath}`);
  });
}

const limit = pLimit(cpus().length || 1);
// Promises are reversed, since slower bundlers (webpack, rollup) are added after faster ones (esbuild, rolldown).
await Promise.all(promises.reverse().map((promise) => limit(promise)));
