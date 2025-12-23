import { join } from "node:path";

export const getFixturesDir = () =>
  join(import.meta.dirname, "..", "..", "..", "src", "utils", "__fixtures__");
