import { build } from "esbuild";
import { join } from "node:path";
import { Extension, ModuleSystem, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const promises = [];
for (const version of Object.values(Version)) {
  for (const moduleSystem of Object.values(ModuleSystem)) {
    promises.push(
      build({
        bundle: true,
        minify: true,
        entryPoints: [getInputPath(version)],
        outfile: join(
          getFixturesDir(),
          getOutputFilename("esbuild", version, Extension[moduleSystem]),
        ),
        format: moduleSystem,
      }),
    );
  }
}

await Promise.all(promises);
