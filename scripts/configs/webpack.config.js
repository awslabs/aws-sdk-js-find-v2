import { Extension, ModuleSystem, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";
import { getWebpackConfig } from "./utils/getWebpackConfig.js";

const LibraryType = {
  [ModuleSystem.cjs]: "commonjs2",
  [ModuleSystem.esm]: "module",
};

const createConfig = (version, moduleSystem) => ({
  ...getWebpackConfig(),
  entry: getInputPath(version),
  output: {
    path: getFixturesDir(),
    filename: getOutputFilename("webpack", version, Extension[moduleSystem]),
    library: { type: LibraryType[moduleSystem] },
  },
});

const configs = [];
for (const version of Object.values(Version)) {
  for (const moduleSystem of Object.values(ModuleSystem)) {
    configs.push(createConfig(version, moduleSystem));
  }
}

export default configs;
