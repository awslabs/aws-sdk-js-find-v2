import { join } from "node:path";
import { getFixturesDir } from "./getFixturesDir.js";

export const getOutputDir = (version) => join(getFixturesDir(), version, "build");
