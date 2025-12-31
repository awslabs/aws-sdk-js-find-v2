import rspack from "@rspack/core";

import { ModuleSystem, Version } from "./utils/constants.js";
import { getOutputDir } from "./utils/getOutputDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const LibraryType = {
  [ModuleSystem.cjs]: "commonjs2",
  [ModuleSystem.esm]: "module",
};

const createConfig = (version, moduleSystem) => ({
  target: "node",
  mode: "production",
  devtool: false,
  optimization: {
    minimizer: [new rspack.SwcJsMinimizerRspackPlugin({ extractComments: false })],
  },
  plugins: [new rspack.optimize.LimitChunkCountPlugin({ maxChunks: 1 })],
  experiments: { outputModule: true },
  entry: getInputPath(version),
  output: {
    path: getOutputDir(version),
    filename: getOutputFilename("rspack", moduleSystem),
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
