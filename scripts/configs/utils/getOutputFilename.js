import { Extension } from "./constants.js";

export const getOutputFilename = (bundler, minify, moduleSystem) =>
  [bundler, ...(minify ? ["min"] : []), Extension[moduleSystem]].join(".");
