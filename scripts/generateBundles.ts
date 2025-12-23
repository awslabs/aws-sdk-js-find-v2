import { exec } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execAsync = promisify(exec);

// const __dirname = import.meta.dirname;
// const fixturesFilepath = join(__dirname, "..", "src", "utils", "__fixtures__");

// const Version = {
//   v2: "v2",
//   v3: "v3",
// } as const;
// type Version = (typeof Version)[keyof typeof Version];

// const ModuleSystem = {
//   cjs: "cjs",
//   esm: "esm",
// } as const;
// type ModuleSystem = (typeof ModuleSystem)[keyof typeof ModuleSystem];

// const inputpath = {
//   [Version.v2]: join(fixturesFilepath, "v2", "index.mjs"),
//   [Version.v3]: join(fixturesFilepath, "v3", "index.mjs"),
// };

// const getFileExtension = (moduleSystem: ModuleSystem) =>
//   moduleSystem === ModuleSystem.cjs ? "js" : "mjs";

// const getOutputFileName = (bundler: string, version: Version, moduleSystem: ModuleSystem) =>
//   [bundler, version, getFileExtension(moduleSystem)].join(".");

// const getEsbuildCommand = (version: Version, moduleSystem: ModuleSystem) =>
//   `npx esbuild --bundle --minify ${inputpath[version]} --outfile=${join(
//     fixturesFilepath,
//     getOutputFileName("esbuild", version, moduleSystem),
//   )} --format=${moduleSystem}`;

// const getRollupCommand = (version: Version, moduleSystem: ModuleSystem) =>
//   `npx rollup ${inputpath[version]} --file=${join(
//     fixturesFilepath,
//     getOutputFileName("rollup", version, moduleSystem),
//   )} --format=${moduleSystem} -c`;

// const getRolldownCommand = (version: Version, moduleSystem: ModuleSystem) =>
//   `npx rolldown ${inputpath[version]} --file=${join(
//     fixturesFilepath,
//     getOutputFileName("rolldown", version, moduleSystem),
//   )} --format=${moduleSystem} -c`;

// for (const version of Object.values(Version)) {
//   for (const moduleSystem of Object.values(ModuleSystem)) {
//     await execAsync(getEsbuildCommand(version, moduleSystem));
//     await execAsync(getRollupCommand(version, moduleSystem));
//     await execAsync(getRolldownCommand(version, moduleSystem));
//   }
// }

const configDir = join(import.meta.dirname, "configs");
const jsFiles = (await readdir(configDir)).filter((file) => file.endsWith(".js"));
for (const fileName of jsFiles) {
  const bundlerName = fileName.substring(0, fileName.indexOf("."));
  const configPath = join(configDir, fileName);
  await execAsync(`npx ${bundlerName} -c ${configPath}`);
}

