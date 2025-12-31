import { Extension } from "./constants.js";

export const getOutputFilename = (bundler, moduleSystem) =>
  [bundler, Extension[moduleSystem]].join(".");
