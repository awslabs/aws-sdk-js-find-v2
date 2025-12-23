import { join } from "node:path";
import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";
import { getRollupConfig } from "./utils/getRollupConfig.js";

export default {
  ...getRollupConfig(),
  input: getInputPath(Version.v3),
  output: {
    inlineDynamicImports: true,
    file: join(getFixturesDir(), getOutputFilename("rollup", Version.v3, Extension.mjs)),
    format: "esm",
  },
};
