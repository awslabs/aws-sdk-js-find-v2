import { describe, it, expect, vi, beforeEach } from "vitest";
import { processZipEntries } from "./processZipEntries.ts";

const mockZip = {
  entries: vi.fn(),
  entryData: vi.fn(),
  close: vi.fn(),
};

vi.mock("node-stream-zip", () => ({
  default: {
    async: class {
      entries = mockZip.entries;
      entryData = mockZip.entryData;
      close = mockZip.close;
    },
  },
}));

describe("processZipEntries", () => {
  const mockZipPath = "/tmp/test.zip";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("processes each zip entry with the processor callback", async () => {
    const entry1 = { name: "file1.js" };
    const entry2 = { name: "file2.js" };
    mockZip.entries.mockResolvedValue({ "file1.js": entry1, "file2.js": entry2 });
    mockZip.entryData.mockResolvedValue(Buffer.from("content"));

    const processor = vi.fn().mockResolvedValue(undefined);
    await processZipEntries(mockZipPath, processor);

    expect(processor).toHaveBeenCalledTimes(2);
    expect(processor).toHaveBeenCalledWith(entry1, expect.any(Function));
    expect(processor).toHaveBeenCalledWith(entry2, expect.any(Function));
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("provides getData function that retrieves entry data", async () => {
    const entry = { name: "test.js" };
    const mockBuffer = Buffer.from("test content");
    mockZip.entries.mockResolvedValue({ "test.js": entry });
    mockZip.entryData.mockResolvedValue(mockBuffer);

    let capturedGetData: () => Promise<Buffer>;
    const processor = vi.fn((_entry, getData) => {
      capturedGetData = getData;
      return Promise.resolve();
    });

    await processZipEntries(mockZipPath, processor);
    const data = await capturedGetData!();

    expect(data).toBe(mockBuffer);
    expect(mockZip.entryData).toHaveBeenCalledWith("test.js");
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("handles empty zip file", async () => {
    mockZip.entries.mockResolvedValue({});

    const processor = vi.fn();
    await processZipEntries(mockZipPath, processor);

    expect(processor).not.toHaveBeenCalled();
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("continues with empty entries when zip.entries() throws", async () => {
    mockZip.entries.mockRejectedValue(new Error("Invalid zip"));

    const processor = vi.fn();
    await processZipEntries(mockZipPath, processor);

    expect(processor).not.toHaveBeenCalled();
    expect(mockZip.close).toHaveBeenCalled();
  });

  it("ignores errors when processor throws", async () => {
    const entry1 = { name: "file1.js" };
    const entry2 = { name: "file2.js" };
    mockZip.entries.mockResolvedValue({ "file1.js": entry1, "file2.js": entry2 });

    const processor = vi
      .fn()
      .mockRejectedValueOnce(new Error("Processor error"))
      .mockResolvedValueOnce(undefined);
    await processZipEntries(mockZipPath, processor);

    expect(processor).toHaveBeenCalledTimes(2);
    expect(mockZip.close).toHaveBeenCalled();
  });
});
