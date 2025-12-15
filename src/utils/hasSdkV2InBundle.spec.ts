import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";
import { hasSdkV2InBundle } from "./hasSdkV2InBundle";

describe("hasSdkV2InBundle", () => {
  const fixturesDir = join(__dirname, "__fixtures__");
  const files = readdirSync(fixturesDir).filter((file) =>
    statSync(join(fixturesDir, file)).isFile()
  );

  if (files.length === 0) {
    throw new Error(
      "No fixture files found. Run 'npm run test:generate:bundles' first."
    );
  }

  files.forEach((file) => {
    const hasV2 = file.endsWith("v2.js") || file.endsWith("v2.mjs");
    it(`returns '${hasV2 ? "true" : "false"}' for '${file}'`, () => {
      const content = readFileSync(join(fixturesDir, file), "utf-8");
      expect(hasSdkV2InBundle(content)).toBe(hasV2);
    });
  });
});
