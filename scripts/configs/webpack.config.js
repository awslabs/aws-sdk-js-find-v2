import TerserPlugin from "terser-webpack-plugin";
import webpack from "webpack";

import { ModuleSystem, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const LibraryType = {
  [ModuleSystem.cjs]: "commonjs2",
  [ModuleSystem.esm]: "module",
};

const createConfig = (version, moduleSystem) => ({
  target: "node",
  mode: "production",
  optimization: { minimizer: [new TerserPlugin({ extractComments: false })] },
  plugins: [new webpack.optimize.LimitChunkCountPlugin({ maxChunks: 1 })],
  experiments: { outputModule: true },
  entry: getInputPath(version),
  output: {
    path: getFixturesDir(),
    filename: getOutputFilename("webpack", version, moduleSystem),
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
