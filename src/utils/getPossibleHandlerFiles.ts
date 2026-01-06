/**
 * Returns possible file paths for a Lambda handler.
 * @param handlerPath - Lambda handler path (e.g., "index.handler").
 * @returns Array of possible file paths with js, mjs, cjs, ts extensions.
 */
export const getPossibleHandlerFiles = (handlerPath: string): string[] => {
  const [handlerFile] = handlerPath.split(".");
  return [`${handlerFile}.js`, `${handlerFile}.mjs`, `${handlerFile}.cjs`, `${handlerFile}.ts`];
};
