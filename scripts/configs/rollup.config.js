import { join } from "node:path";

import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import terser from "@rollup/plugin-terser";

import { ModuleSystem, Version } from "./utils/constants.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputDir } from "./utils/getOutputDir.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const createConfig = (version, minify, moduleSystem) => ({
  plugins: [resolve({ preferBuiltins: true }), commonjs(), ...(minify ? [terser()] : []), json()],
  input: getInputPath(version),
  output: {
    file: join(getOutputDir(version), getOutputFilename("rollup", minify, moduleSystem)),
    format: moduleSystem,
    inlineDynamicImports: true,
    minify,
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
