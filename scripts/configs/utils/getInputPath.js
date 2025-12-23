import { join } from "node:path";
import { getFixturesDir } from "./getFixturesDir.js";

export const getInputPath = (version) => join(getFixturesDir(), version, "index.mjs");
