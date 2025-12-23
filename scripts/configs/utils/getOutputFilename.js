export const getOutputFilename = (bundler, version, extension) =>
  [bundler, version, extension].join(".");
