import { join } from "node:path";
import { defineConfig } from "rolldown";
import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

export default defineConfig({
  input: getInputPath(Version.v2),
  output: {
    file: join(getFixturesDir(), getOutputFilename("rolldown", Version.v2, Extension.js)),
    format: "cjs",
    minify: true,
  },
});
