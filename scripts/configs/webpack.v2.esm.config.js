import { Extension, Version } from "./utils/constants.js";
import { getFixturesDir } from "./utils/getFixturesDir.js";
import { getInputPath } from "./utils/getInputPath.js";
import { getOutputFilename } from "./utils/getOutputFilename.js";
import { getWebpackConfig } from "./utils/getWebpackConfig.js";

export default {
  ...getWebpackConfig(),
  entry: getInputPath(Version.v2),
  output: {
    path: getFixturesDir(),
    filename: getOutputFilename("webpack", Version.v2, Extension.mjs),
    library: {
      type: "module",
    },
  },
};
