import { Extension } from "./constants.js";

export const getOutputFilename = (bundler, moduleSystem) =>
  [bundler, "min", Extension[moduleSystem]].join(".");
