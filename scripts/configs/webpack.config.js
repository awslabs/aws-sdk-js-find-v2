import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";
import { getWebpackConfig } from "./utils/getWebpackConfig.js";

const createConfig = (version, extension, libraryType) => ({
  ...getWebpackConfig(),
  entry: getInputPath(version),
  output: {
    path: getFixturesDir(),
    filename: getOutputFilename("webpack", version, extension),
    library: { type: libraryType },
  },
});

export default [
  createConfig(Version.v2, Extension.js, "commonjs2"),
  createConfig(Version.v2, Extension.mjs, "module"),
  createConfig(Version.v3, Extension.js, "commonjs2"),
  createConfig(Version.v3, Extension.mjs, "module"),
];
