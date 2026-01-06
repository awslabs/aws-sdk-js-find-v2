import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";

import { hasSdkV2InFile } from "./hasSdkV2InFile";

describe("hasSdkV2InFile", () => {
  describe.each([
    [true, "v2"],
    [false, "v3"],
  ])("should return %s for '%s'", (output, version) => {
    const bundlesDir = join(__dirname, "__fixtures__", "files");
    const files = readdirSync(bundlesDir).filter(
      (file) =>
        statSync(join(bundlesDir, file)).isFile() && new RegExp(`${version}.[jt]s$`).test(file),
    );

    files.forEach((file) => {
      it(`in '${file}'`, () => {
        const content = readFileSync(join(bundlesDir, file), "utf-8");
        return expect(hasSdkV2InFile(file, content)).resolves.toBe(output);
      });
    });
  });
});
