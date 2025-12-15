import { join } from "node:path";
import TerserPlugin from "terser-webpack-plugin";
import webpack from "webpack";

const outputPath = join(import.meta.dirname, "src", "utils", "__fixtures__");

export default {
  target: "node",
  mode: "production",
  output: {
    path: outputPath,
  },
  optimization: {
    minimizer: [
      new TerserPlugin({
        extractComments: false,
      }),
    ],
  },
  plugins: [
    new webpack.optimize.LimitChunkCountPlugin({
      maxChunks: 1,
    }),
  ],
  experiments: {
    outputModule: true,
  },
};
