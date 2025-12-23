import { join } from "node:path";
import { Extension, ModuleSystem, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";
import { getRollupConfig } from "./utils/getRollupConfig.js";

const createConfig = (version, moduleSystem) => ({
  ...getRollupConfig(),
  input: getInputPath(version),
  output: {
    file: join(getFixturesDir(), getOutputFilename("rollup", version, Extension[moduleSystem])),
    format: moduleSystem,
    inlineDynamicImports: true,
  },
});

const configs = [];
for (const version of Object.values(Version)) {
  for (const moduleSystem of Object.values(ModuleSystem)) {
    configs.push(createConfig(version, moduleSystem));
  }
}

export default configs;
