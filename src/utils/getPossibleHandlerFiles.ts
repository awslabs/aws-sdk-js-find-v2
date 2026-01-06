export const getPossibleHandlerFiles = (handlerPath: string): string[] => {
  const [handlerFile] = handlerPath.split(".");
  return [`${handlerFile}.js`, `${handlerFile}.mjs`, `${handlerFile}.cjs`, `${handlerFile}.ts`];
};
