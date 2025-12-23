import { join } from "node:path";
import { defineConfig } from "rolldown";
import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

export default defineConfig({
  input: getInputPath(Version.v3),
  output: {
    file: join(getFixturesDir(), getOutputFilename("rolldown", Version.v3, Extension.mjs)),
    format: "esm",
    inlineDynamicImports: true,
    minify: true,
  },
});

