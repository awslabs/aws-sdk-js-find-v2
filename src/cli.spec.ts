import { describe, it, expect, vi, beforeEach } from "vitest";
import { cpus } from "node:os";
import { createProgram } from "./cli.ts";
import { scanLambdaFunctions } from "./scanLambdaFunctions.ts";
import { LambdaCommandOutputType } from "./utils/printLambdaCommandOutput.ts";
import packageJson from "../package.json" with { type: "json" };

describe("CLI", () => {
  const mockOptions = {
    yes: false,
    jobs: cpus().length,
    output: LambdaCommandOutputType.json,
  };

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
        "CLI to find resources which call AWS using JavaScript SDK v2",
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
      const lambdaCommand = program.commands.find((cmd) => cmd.name() === "lambda");
      expect(lambdaCommand).toBeDefined();
    });

    it("should have correct description for lambda command", () => {
      const program = createProgram();
      const lambdaCommand = program.commands.find((cmd) => cmd.name() === "lambda");
      expect(lambdaCommand?.description()).toBe(
        "Scans Lambda Node.js Functions for JavaScript SDK v2",
      );
    });

    it("should call scanLambdaFunctions when lambda command is executed", async () => {
      const program = createProgram();

      // Prevent process.exit on missing required args
      program.exitOverride();

      await program.parseAsync(["node", "cli", "lambda"]);

      expect(scanLambdaFunctions).toHaveBeenCalledTimes(1);
      expect(scanLambdaFunctions).toHaveBeenCalledWith(mockOptions);
    });

    describe("should pass region option to scanLambdaFunctions", () => {
      it("with --region", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "--region", "us-west-2"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          region: "us-west-2",
        });
      });

      it("with -r", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "-r", "eu-west-1"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          region: "eu-west-1",
        });
      });
    });

    describe("should pass profile option to scanLambdaFunctions", () => {
      it("with --profile", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "--profile", "dev"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          profile: "dev",
        });
      });

      it("with -p", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "-p", "prod"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          profile: "prod",
        });
      });
    });

    describe("should pass yes option to scanLambdaFunctions", () => {
      it("with --yes", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "--yes"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          yes: true,
        });
      });

      it("with -y", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "-y"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          yes: true,
        });
      });
    });

    describe("should pass jobs option to scanLambdaFunctions", () => {
      it("with --jobs", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "--jobs", "4"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          jobs: 4,
        });
      });

      it("with -j", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "-j", "2"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          jobs: 2,
        });
      });

      it("defaults to number of CPUs", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          jobs: cpus().length,
        });
      });

      it("throws error for non-integer value", async () => {
        const program = createProgram();
        program.exitOverride();

        await expect(program.parseAsync(["node", "cli", "lambda", "-j", "abc"])).rejects.toThrow(
          "jobs must be a positive integer",
        );
      });

      it("throws error for zero", async () => {
        const program = createProgram();
        program.exitOverride();

        await expect(program.parseAsync(["node", "cli", "lambda", "-j", "0"])).rejects.toThrow(
          "jobs must be a positive integer",
        );
      });

      it("throws error for negative value", async () => {
        const program = createProgram();
        program.exitOverride();

        await expect(program.parseAsync(["node", "cli", "lambda", "-j", "-1"])).rejects.toThrow(
          "jobs must be a positive integer",
        );
      });

      it("throws error for decimal value", async () => {
        const program = createProgram();
        program.exitOverride();

        await expect(program.parseAsync(["node", "cli", "lambda", "-j", "1.5"])).rejects.toThrow(
          "jobs must be a positive integer",
        );
      });
    });

    describe("should pass output option to scanLambdaFunctions", () => {
      it("with --output", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "--output", "table"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith({
          ...mockOptions,
          output: LambdaCommandOutputType.table,
        });
      });

      it("with -o", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda", "-o", "json"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith(mockOptions);
      });

      it("defaults to json", async () => {
        const program = createProgram();
        program.exitOverride();

        await program.parseAsync(["node", "cli", "lambda"]);

        expect(scanLambdaFunctions).toHaveBeenCalledWith(mockOptions);
      });

      it("throws error for invalid output type", async () => {
        const program = createProgram();
        program.exitOverride();

        await expect(
          program.parseAsync(["node", "cli", "lambda", "-o", "invalid"]),
        ).rejects.toThrow();
      });
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

      await expect(program.parseAsync(["node", "cli", "lambda"])).rejects.toThrow("Scan failed");
    });
  });
});
