import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";

import { hasSdkV2InBundle } from "./hasSdkV2InBundle";
import { devDependencies } from "../../package.json";

describe("hasSdkV2InBundle", () => {
  const sdkVersionRange = devDependencies["aws-sdk"];

  describe.each([
    [true, "v2", sdkVersionRange],
    [false, "v3", sdkVersionRange],
    [false, "v2", `<${sdkVersionRange}`],
  ])(
    "should return %s for '%s' with sdk version range '%s'",
    (output, version, sdkVersionRange) => {
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
          expect(hasSdkV2InBundle(content, sdkVersionRange)).toBe(output);
        });
      });
    },
  );
});
