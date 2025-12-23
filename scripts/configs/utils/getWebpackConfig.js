import TerserPlugin from "terser-webpack-plugin";
import webpack from "webpack";

export const getWebpackConfig = () => ({
  target: "node",
  mode: "production",
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
});
