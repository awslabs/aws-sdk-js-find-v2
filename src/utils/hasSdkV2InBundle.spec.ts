import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";
import { hasSdkV2InBundle } from "./hasSdkV2InBundle";

describe("hasSdkV2InBundle", () => {
  describe.each([
    [true, "v2"],
    [false, "v3"],
  ])("should return %b for '%s'", (output, version) => {
    const bundlesDir = join(__dirname, "__fixtures__", version, "build");
    const files = readdirSync(bundlesDir).filter((file) =>
      statSync(join(bundlesDir, file)).isFile(),
    );

    if (files.length === 0) {
      throw new Error("No fixture files found. Run 'npm run test:generate:bundles' first.");
    }

    files.forEach((file) => {
      it(`in '${file}'`, () => {
        const content = readFileSync(join(bundlesDir, file), "utf-8");
        expect(hasSdkV2InBundle(content)).toBe(output);
      });
    });
  });
});
