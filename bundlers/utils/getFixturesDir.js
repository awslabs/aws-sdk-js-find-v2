import { join } from "node:path";

export const getFixturesDir = (version) =>
  join(import.meta.dirname, "..", "..", "src", "utils", "__fixtures__");
