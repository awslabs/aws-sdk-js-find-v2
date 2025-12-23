import { join } from "node:path";
import { defineConfig } from "rolldown";
import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const createConfig = (version, extension, format) =>
  defineConfig({
    input: getInputPath(version),
    output: {
      file: join(getFixturesDir(), getOutputFilename("rolldown", version, extension)),
      format,
      ...(version === Version.v3 && { inlineDynamicImports: true }),
      minify: true,
    },
  });

export default [
  createConfig(Version.v2, Extension.js, "cjs"),
  createConfig(Version.v2, Extension.mjs, "esm"),
  createConfig(Version.v3, Extension.js, "cjs"),
  createConfig(Version.v3, Extension.mjs, "esm"),
];
