import { exec } from "node:child_process";
import { readdir } from "node:fs/promises";
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
    console.log(`[${bundlerName}] Running with code '${fileName}'`);
    promises.push(
      execAsync(`node ${filePath}`).catch((error) => {
        throw new Error(`[${bundlerName}] failed`, { cause: error });
      }),
    );
    continue;
  }

  console.log(`[${bundlerName}] Running with config '${fileName}'`);
  promises.push(
    execAsync(`npx ${bundlerName} -c ${filePath}`).catch((error) => {
      throw new Error(`[${bundlerName}] failed`, { cause: error });
    }),
  );
}

await Promise.all(promises);
