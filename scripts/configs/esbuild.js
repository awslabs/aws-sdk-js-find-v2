import { build } from "esbuild";
import { join } from "node:path";
import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const configs = [
  [Version.v2, Extension.js, "cjs"],
  [Version.v2, Extension.mjs, "esm"],
  [Version.v3, Extension.js, "cjs"],
  [Version.v3, Extension.mjs, "esm"],
];

await Promise.all(
  configs.map(([version, extension, format]) =>
    build({
      bundle: true,
      minify: true,
      entryPoints: [getInputPath(version)],
      outfile: join(getFixturesDir(), getOutputFilename("esbuild", version, extension)),
      format,
    }),
  ),
);
