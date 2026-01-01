import TerserPlugin from "terser-webpack-plugin";
import webpack from "webpack";

import { ModuleSystem, Version } from "./utils/constants.js";
import { getOutputDir } from "./utils/getOutputDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";

const LibraryType = {
  [ModuleSystem.cjs]: "commonjs2",
  [ModuleSystem.esm]: "module",
};

const createConfig = (version, minify, moduleSystem) => ({
  target: "node",
  mode: "production",
  optimization: {
    minimize: minify,
    minimizer: [new TerserPlugin({ extractComments: false })],
  },
  plugins: [new webpack.optimize.LimitChunkCountPlugin({ maxChunks: 1 })],
  experiments: { outputModule: true },
  entry: getInputPath(version),
  output: {
    path: getOutputDir(version),
    filename: getOutputFilename("webpack", minify, moduleSystem),
    library: { type: LibraryType[moduleSystem] },
  },
});

const configs = [];
for (const version of Object.values(Version)) {
  for (const minify of [true, false]) {
    for (const moduleSystem of Object.values(ModuleSystem)) {
      configs.push(createConfig(version, minify, moduleSystem));
    }
  }
}

export default configs;
