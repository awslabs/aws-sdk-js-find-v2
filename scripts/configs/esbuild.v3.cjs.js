import { build } from "esbuild";
import { join } from "node:path";
import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

await build({
  bundle: true,
  minify: true,
  entryPoints: [getInputPath(Version.v3)],
  outfile: join(getFixturesDir(), getOutputFilename("esbuild", Version.v3, Extension.js)),
  format: "cjs",
});