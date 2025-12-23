import { join } from "node:path";
import { defineConfig } from "rolldown";
import { ModuleSystem, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const createConfig = (version, moduleSystem) =>
  defineConfig({
    input: getInputPath(version),
    output: {
      file: join(getFixturesDir(), getOutputFilename("rolldown", version, moduleSystem)),
      format: moduleSystem,
      inlineDynamicImports: true,
      minify: true,
    },
  });

const configs = [];
for (const version of Object.values(Version)) {
  for (const moduleSystem of Object.values(ModuleSystem)) {
    configs.push(createConfig(version, moduleSystem));
  }
}

export default configs;
