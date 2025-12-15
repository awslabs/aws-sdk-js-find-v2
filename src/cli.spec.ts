import { describe, it, expect, vi, beforeEach } from "vitest";
import { createProgram } from "./cli.ts";
import { scanLambdaFunctions } from "./scanLambdaFunctions.ts";
import packageJson from "../package.json" with { type: "json" };

describe("CLI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mock("./scanLambdaFunctions.ts", () => ({
      scanLambdaFunctions: vi.fn().mockResolvedValue(undefined),
    }));
  });

  describe("program configuration", () => {
    it("should have correct name", () => {
      const program = createProgram();
      expect(program.name()).toBe(packageJson.name);
    });

    it("should have correct description", () => {
      const program = createProgram();
      expect(program.description()).toBe(
        "CLI to find resources which call AWS using JavaScript SDK v2"
      );
    });

    it("should have correct version", () => {
      const program = createProgram();
      expect(program.version()).toBe(packageJson.version);
    });
  });

  describe("lambda command", () => {
    it("should have lambda command registered", () => {
      const program = createProgram();
      const lambdaCommand = program.commands.find(
        (cmd) => cmd.name() === "lambda"
      );
      expect(lambdaCommand).toBeDefined();
    });

    it("should have correct description for lambda command", () => {
      const program = createProgram();
      const lambdaCommand = program.commands.find(
        (cmd) => cmd.name() === "lambda"
      );
      expect(lambdaCommand?.description()).toBe(
        "Scans Lambda Node.js Functions for JavaScript SDK v2."
      );
    });

    it("should call scanLambdaFunctions when lambda command is executed", async () => {
      const program = createProgram();
      
      // Prevent process.exit on missing required args
      program.exitOverride();
      
      await program.parseAsync(["node", "cli", "lambda"]);
      
      expect(scanLambdaFunctions).toHaveBeenCalledTimes(1);
    });

    it("should not call scanLambdaFunctions when no command is provided", async () => {
      const program = createProgram();
      program.exitOverride();
      
      try {
        await program.parseAsync(["node", "cli"]);
      } catch {
        // Commander throws when no command is provided.
      }
      
      expect(scanLambdaFunctions).not.toHaveBeenCalled();
    });
  });

  describe("error handling", () => {
    it("should handle scanLambdaFunctions errors gracefully", async () => {
      const mockError = new Error("Scan failed");
      vi.mocked(scanLambdaFunctions).mockRejectedValueOnce(mockError);
      
      const program = createProgram();
      program.exitOverride();
      
      await expect(
        program.parseAsync(["node", "cli", "lambda"])
      ).rejects.toThrow("Scan failed");
    });
  });
});