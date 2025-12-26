import { createInterface } from "node:readline/promises";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { getDownloadConfirmation } from "./getDownloadConfirmation.ts";

vi.mock("node:readline/promises");

describe("getDownloadConfirmation", () => {
  const mockClose = vi.fn();
  const mockQuestion = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(createInterface).mockReturnValue({
      question: mockQuestion,
      close: mockClose,
    } as any);
  });

  it.each(["y", "Y", "yes", "YES", "Yes", " yes "])("returns true for '%s'", async (answer) => {
    mockQuestion.mockResolvedValue(answer);
    expect(await getDownloadConfirmation(5, 1024, 512)).toBe(true);
    expect(mockClose).toHaveBeenCalled();
  });

  it.each(["n", "N", "no", "", " no "])("returns false for '%s'", async (answer) => {
    mockQuestion.mockResolvedValue(answer);
    expect(await getDownloadConfirmation(5, 1024, 512)).toBe(false);
    expect(mockClose).toHaveBeenCalled();
  });
});
