import { describe, it, expect, vi, beforeEach } from "vitest";
import { processRemoteZip } from "./processRemoteZip.ts";

const mockWriteFile = vi.fn();
const mockRm = vi.fn();
const mockRandomUUID = vi.fn();

vi.mock("node:fs/promises", () => ({
  writeFile: (...args: unknown[]) => mockWriteFile(...args),
  rm: (...args: unknown[]) => mockRm(...args),
}));

vi.mock("node:os", () => ({
  tmpdir: () => "/tmp",
}));

vi.mock("node:crypto", () => ({
  randomUUID: () => mockRandomUUID(),
}));

describe("processRemoteZip", () => {
  const mockBody = new ReadableStream();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn());
    mockRandomUUID.mockReturnValue("test-uuid");
  });

  it("downloads, processes, and cleans up zip file", async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: true, body: mockBody } as Response);
    mockWriteFile.mockResolvedValue(undefined);
    mockRm.mockResolvedValue(undefined);

    const processor = vi.fn().mockResolvedValue(undefined);
    await processRemoteZip("https://example.com/test.zip", processor);

    expect(fetch).toHaveBeenCalledWith("https://example.com/test.zip");
    expect(mockWriteFile).toHaveBeenCalledWith("/tmp/test-uuid.zip", mockBody);
    expect(processor).toHaveBeenCalledWith("/tmp/test-uuid.zip");
    expect(mockRm).toHaveBeenCalledWith("/tmp/test-uuid.zip", { force: true });
  });

  it("throws when fetch fails", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
    } as Response);

    const processor = vi.fn().mockResolvedValue(undefined);
    await expect(processRemoteZip("https://example.com/missing.zip", processor)).rejects.toThrow(
      "Failed to download 'https://example.com/missing.zip'. Received 404 with 'Not Found'.",
    );
    expect(mockWriteFile).not.toHaveBeenCalled();
    expect(processor).not.toHaveBeenCalled();
    expect(mockRm).not.toHaveBeenCalled();
  });

  it("throws when response body is null", async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: true, body: null } as Response);

    const processor = vi.fn().mockResolvedValue(undefined);
    await expect(processRemoteZip("https://example.com/test.zip", processor)).rejects.toThrow(
      "Response body is null for 'https://example.com/test.zip'",
    );
    expect(mockWriteFile).not.toHaveBeenCalled();
    expect(processor).not.toHaveBeenCalled();
    expect(mockRm).not.toHaveBeenCalled();
  });

  it("cleans up even when processor throws", async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: true, body: mockBody } as Response);
    mockWriteFile.mockResolvedValue(undefined);
    mockRm.mockResolvedValue(undefined);

    const processor = vi.fn().mockRejectedValue(new Error("Processor failed"));

    await expect(processRemoteZip("https://example.com/test.zip", processor)).rejects.toThrow(
      "Processor failed",
    );
    expect(mockWriteFile).toHaveBeenCalledWith("/tmp/test-uuid.zip", mockBody);
    expect(processor).toHaveBeenCalledWith("/tmp/test-uuid.zip");
    expect(mockRm).toHaveBeenCalledWith("/tmp/test-uuid.zip", { force: true });
  });
});
