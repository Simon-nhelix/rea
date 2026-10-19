import { Ajv2020 } from "ajv/dist/2020.js";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, onTestFinished } from "vitest";
import { createServer } from "../../../src/server/createServer.js";
import {
  createCacheProvider,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { mcpTest } from "../../support/mcp/mcpFixture.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";

mcpTest(
  "returns mixed pointer/orphan manuscripts through the advertised SDK-converted schema",
  async ({ mcp }) => {
    const root = await createTestTempDirectory("rea-rom-manuscript-mcp-");
    const path = join(root, "dialogue.bin");
    const bytes = Buffer.alloc(128);
    bytes.writeUInt16LE(0x20);
    bytes.writeUInt16LE(0x40, 2);
    bytes.write("AA\0BB\0", 0x20, "ascii");
    bytes.write("CC\0", 0x40, "ascii");
    await writeFile(path, bytes);
    const calls: string[] = [];
    const session = createTestBinarySession(createCacheProvider(calls));
    onTestFinished(async () => {
      await session.close();
    });
    const client = await mcp.connect(
      createServer({ kind: "session", session }),
    );
    const opened = await client.callTool({
      name: "open_binary",
      arguments: {
        path,
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x08000000",
        load_address: "0x08000000",
      },
    });
    expect(opened.isError).not.toBe(true);
    const tools = await client.listTools();
    const advertised = tools.tools.find(
      (tool) => tool.name === "scan_pointer_table",
    )?.outputSchema;
    if (advertised === undefined)
      throw new Error("Missing scan_pointer_table output schema");
    const schema: Record<string, unknown> = advertised;
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    expect(ajv.validateSchema(schema)).toBe(true);
    const result = await client.callTool({
      name: "scan_pointer_table",
      arguments: {
        table_offset: 0,
        count: 2,
        pointer_size: 2,
        encoding: "ascii",
        include_manuscript: true,
        include_orphan_strings: true,
        resolve_xrefs: false,
      },
    });
    expect(result.isError).not.toBe(true);
    expect(
      ajv.validate(schema, result.structuredContent),
      JSON.stringify(ajv.errors),
    ).toBe(true);
    const evidence = toolContract("scan_pointer_table").outputSchema.parse(
      result.structuredContent,
    );
    expect(evidence.normalized_result).toMatchObject({
      entries: [{ allocated_budget_bytes: 3 }, {}],
      manuscript_records: [
        { jp: "AA", max_bytes: 3, target_address: "0x8000020" },
        { jp: "CC" },
        {
          origin: "orphan",
          id: "orphan_00000023",
          jp: "BB",
          pointer_address: null,
        },
      ],
    });
    expect(calls.filter((name) => name !== "health")).toEqual([]);
  },
);
