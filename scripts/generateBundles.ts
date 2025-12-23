import { exec } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execAsync = promisify(exec);

const configDir = join(import.meta.dirname, "configs");
const jsFiles = (await readdir(configDir)).filter((file) => file.endsWith(".js"));

for (const fileName of jsFiles) {
  const bundlerName = fileName.substring(0, fileName.indexOf("."));
  const filePath = join(configDir, fileName);

  if (bundlerName === "esbuild") {
    // esbuild doesn't support config.
    console.log(`Running '${bundlerName}' with code '${fileName}'`);
    await execAsync(`node ${filePath}`);
    continue;
  }

  console.log(`Running '${bundlerName}' with config '${fileName}'`);
  await execAsync(`npx ${bundlerName} -c ${filePath}`);
}
