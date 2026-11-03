import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseBinaryTarget } from "../../../src/application/BinaryTargetResolver.js";
import { isConsoleBinaryTarget } from "../../../src/domain/binaryTargetTypes.js";
import { sampleLinearProgram } from "../../fixtures/dos/linearExecutable.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

describe("DOS extender LE/LX target resolution", () => {
  it.each([
    ["LE with e_lfanew", sampleLinearProgram()],
    ["LE behind a bound extender stub", sampleLinearProgram({ bound: true })],
    ["LX", sampleLinearProgram({ signature: "LX" })],
  ] as const)("opens %s as a dos-le console target", async (_label, bytes) => {
    const directory = await createTestTempDirectory("rea-target-dos-le-");
    const path = join(directory, "game.exe");
    await writeFile(path, bytes);

    const result = await parseBinaryTarget(path);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(result.value).toMatchObject({
      format: "dos-le",
      kind: "executable",
      architecture: "x86",
    });
    if (!isConsoleBinaryTarget(result.value))
      throw new Error("not a console target");
    expect(result.value.consoleRom).toMatchObject({
      loadBase: "0x10000",
      entryPoint: "0x10000",
      fileMappings: [
        { name: "OBJ1_CODE", virtualAddress: "0x10000" },
        { name: "OBJ2_DATA", virtualAddress: "0x20000" },
      ],
    });
  });

  it("keeps a plain MZ program as dos-mz", async () => {
    const directory = await createTestTempDirectory("rea-target-dos-mz-");
    const path = join(directory, "plain.exe");
    const bytes = Buffer.alloc(0x200);
    bytes.write("MZ", 0, "latin1");
    bytes.writeUInt16LE(0, 2);
    bytes.writeUInt16LE(1, 4);
    bytes.writeUInt16LE(4, 8);
    await writeFile(path, bytes);

    const result = await parseBinaryTarget(path);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(result.value.format).toBe("dos-mz");
  });
});
