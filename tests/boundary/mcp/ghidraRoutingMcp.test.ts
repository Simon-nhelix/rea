import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { describe, expect, it } from "vitest";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/client/validators/ajv";
import { CONSOLE_TARGET_FORMATS } from "../../../src/domain/consoleRom.js";
import { toolOutputSchemaWithMetadata } from "../../../src/contracts/toolSchemaMetadata.js";
import { connectGhidraMcp } from "./ghidraMcpHarness.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { expandToolAvailability } from "../../../src/contracts/toolOutputSchemaPrimitives.js";

describe("Ghidra MCP capability routing", () => {
  it("routes composed and capability tools", async () => {
    const harness = await connectGhidraMcp("ghidra-routing");
    const { calls, mcp } = harness;
    try {
      const batch = await mcp.callTool({
        name: "batch_decompile",
        arguments: { addresses: ["fixture_main"] },
      });
      expect(batch.isError).not.toBe(true);
      expect(batch.structuredContent).toMatchObject({
        normalized_result: {
          succeeded: 1,
          failed: 0,
          items: [{ status: "ok" }],
        },
      });

      const availableNames = (await mcp.listTools()).tools.map(
        ({ name }) => name,
      );
      expect(availableNames).toContain("set_comment");
      const denied = await mcp.callTool({
        name: "set_comment",
        arguments: { address: "0x1000", comment: "must not mutate" },
      });
      expect(denied.isError).toBe(true);
      expect(parseMcpToolError(denied)).toMatchObject({
        error: {
          code: "capability_unavailable",
          category: "unsupported_provider",
        },
      });
      expect(calls).not.toContain("set_comment");

      const status = await mcp.callTool({
        name: "binary_session",
        arguments: {},
      });
      const sessionStatus = toolContract("binary_session").outputSchema.parse(
        status.structuredContent,
      );
      expect(sessionStatus.result).toMatchObject({
        open: true,
        analysis_provider_binding: {
          provider: { id: "ghidra", version: "12.1.4" },
        },
      });
      // Reuse a production-shaped session observation to verify that every
      // admitted console format has the same lifecycle contract as open_binary.
      for (const dialect of ["draft-2020-12", "draft-07"] as const) {
        const advertised = toolOutputSchemaWithMetadata(
          toolContract("binary_session"),
        )["~standard"].jsonSchema.output({ target: dialect });
        const validate = new AjvJsonSchemaValidator().getValidator(advertised);
        for (const format of CONSOLE_TARGET_FORMATS) {
          const observation = {
            result: {
              ...sessionStatus.result,
              format,
              kind: "executable",
              architecture: (
                {
                  gba: "arm",
                  "psx-exe": "r3000",
                  "ps2-elf": "r5900",
                  psp: "allegrex",
                  ps3: "cell-ppu",
                  xbox: "x86",
                  "dc-bin": "sh4",
                  saturn: "sh2",
                  nds: "arm",
                  md: "68000",
                  pce: "6502",
                  "gc-dol": "gekko",
                  snes: "65816",
                  nes: "6502",
                  gb: "sm83",
                  wsc: "x86",
                  n64: "r4300",
                } as const
              )[format],
              entry_point: "0x8000",
            },
          };
          expect(
            toolContract("open_binary").outputSchema.safeParse(observation)
              .success,
          ).toBe(true);
          expect(
            toolContract("binary_session").outputSchema.safeParse(observation)
              .success,
          ).toBe(true);
          expect(validate(observation).valid).toBe(true);
          const { entry_point: _entry, ...missingEntry } = observation.result;
          expect(validate({ result: missingEntry }).valid).toBe(false);
        }
      }
      const availability = expandToolAvailability(
        sessionStatus.result.tool_availability,
      );
      expect(availability).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "binary_overview", available: true }),
          expect.objectContaining({
            name: "get_objc_classes",
            available: true,
          }),
          expect.objectContaining({ name: "batch_decompile", available: true }),
          expect.objectContaining({ name: "trace_feature", available: true }),
          expect.objectContaining({ name: "get_call_graph", available: true }),
          expect.objectContaining({
            name: "find_xrefs_to_name",
            available: true,
          }),
          expect.objectContaining({ name: "set_comment", available: false }),
        ]),
      );
    } finally {
      await harness.close();
    }
  }, 30_000);
});
