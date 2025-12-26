import { writeFile } from "node:fs/promises";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { downloadFile } from "./downloadFile.ts";

vi.mock("node:fs/promises");

describe("downloadFile", () => {
  const mockUrl = "https://example.com/file.zip";
  const mockOutputPath = "/tmp/file.zip";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("downloads and writes file successfully", async () => {
    const mockBody = "file content";
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      body: mockBody,
    });

    await downloadFile(mockUrl, mockOutputPath);

    expect(fetch).toHaveBeenCalledWith(mockUrl);
    expect(writeFile).toHaveBeenCalledWith(mockOutputPath, mockBody);
  });

  it("throws error when response is not ok", async () => {
    const mockStatus = 404;
    const mockStatusText = "Not Found";
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: mockStatus,
      statusText: "Not Found",
    });

    await expect(downloadFile(mockUrl, mockOutputPath)).rejects.toThrow(
      `Failed to download '${mockUrl}'. Received ${mockStatus} with '${mockStatusText}'.`,
    );
    expect(writeFile).not.toHaveBeenCalled();
  });

  it("throws error when response body is null", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      body: null,
    });

    await expect(downloadFile(mockUrl, mockOutputPath)).rejects.toThrow(
      `Response body is null for '${mockUrl}'`,
    );
    expect(writeFile).not.toHaveBeenCalled();
  });
});
