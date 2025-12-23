import { Extension } from "./constants.js";

export const getOutputFilename = (bundler, version, moduleSystem) =>
  [bundler, version, Extension[moduleSystem]].join(".");
