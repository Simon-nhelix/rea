import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const jal = (target: number): number =>
  ((3 << 26) | ((target >>> 2) & 0x03ffffff)) >>> 0;

cliTest(
  "finds a call in a headerless overlay and reports zero references explicitly",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-code-refs-cli-");
    const environment = {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
    };
    const overlay = Buffer.alloc(16);
    overlay.writeUInt32LE(jal(0x800cba44), 4);
    const path = join(root, "OVL.BIN");
    await writeFile(path, overlay);

    const result = await cli.run({
      arguments: [
        "find-code-references",
        "--file",
        `${path}:0x800D61D8`,
        "--target",
        "0x800CBA44",
        "--target",
        "0x800CBCE8",
        "--json",
      ],
      environment,
    });
    expect(result.exitCode).toBe(0);
    expect(result.json).toMatchObject({
      operation: "find_code_references",
      normalized_result: {
        total_references: 1,
        references: [
          {
            kind: "call",
            address: "0x800d61dc",
            file_offset: 4,
            instruction: "jal 0x800cba44",
          },
        ],
        summary: [
          { target: "0x800cba44", counts: { call: 1 } },
          { target: "0x800cbce8", counts: { total: 0 } },
        ],
      },
    });
  },
);
