import { join } from "node:path";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import terser from "@rollup/plugin-terser";
import json from "@rollup/plugin-json";

import { ModuleSystem, Version } from "./utils/constants.js";
import { getOutputDir } from "./utils/getOutputDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const createConfig = (version, minify, moduleSystem) => ({
  plugins: [resolve({ preferBuiltins: true }), commonjs(), ...(minify ? [terser()] : []), json()],
  input: getInputPath(version),
  output: {
    file: join(getOutputDir(version), getOutputFilename("rollup", minify, moduleSystem)),
    format: moduleSystem,
    inlineDynamicImports: true,
  },
});

const configs = [];
for (const version of Object.values(Version)) {
  for (const minify of [true, false]) {
    for (const moduleSystem of Object.values(ModuleSystem)) {
      configs.push(createConfig(version, minify, moduleSystem));
    }
  }
}

export default configs;
