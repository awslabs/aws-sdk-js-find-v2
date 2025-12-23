import { join } from "node:path";
import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";
import { getRollupConfig } from "./utils/getRollupConfig.js";

const createConfig = (version, extension, format) => ({
  ...getRollupConfig(),
  input: getInputPath(version),
  output: {
    inlineDynamicImports: true,
    file: join(getFixturesDir(), getOutputFilename("rollup", version, extension)),
    format,
  },
});

export default [
  createConfig(Version.v2, Extension.js, "cjs"),
  createConfig(Version.v2, Extension.mjs, "esm"),
  createConfig(Version.v3, Extension.js, "cjs"),
  createConfig(Version.v3, Extension.mjs, "esm"),
];
