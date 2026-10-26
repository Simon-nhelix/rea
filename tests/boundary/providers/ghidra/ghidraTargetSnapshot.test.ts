import {
  universalMacho,
  CPU_ARM64,
  CPU_X86_64,
} from "../../../fixtures/universalMacho.js";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

import { createGhidraTargetSnapshot } from "../../../../src/ghidra/GhidraTargetSnapshot.js";

describe("Ghidra target snapshot", () => {
  it("uses the selected installation platform instead of the ambient host", async () => {
    const root = await createTestTempDirectory("rea-ghidra-platform-");
    const source = join(root, "source.exe");
    const bytes = Buffer.from("platform fixture");
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    await writeFile(source, bytes);
    const snapshot = await createGhidraTargetSnapshot(source, root, sha256, {
      platform: "linux",
    });
    expect(snapshot.admission).toBeUndefined();
    expect(Buffer.compare(await readFile(snapshot.path), bytes)).toBe(0);
    await expect(
      createGhidraTargetSnapshot(source, root, sha256, { platform: "linux" }),
    ).rejects.toMatchObject({ code: "EEXIST" });
    expect(Buffer.compare(await readFile(snapshot.path), bytes)).toBe(0);
    await expect(
      createGhidraTargetSnapshot(source, root, sha256, { platform: "win32" }),
    ).rejects.toThrow(/No native private runtime owns/u);
  });
});

const digest = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
const fatFixture = () => {
  const thin = Buffer.alloc(150_000, 0x5a);
  thin.writeUInt32LE(0xfeedfacf, 0);
  return universalMacho([
    { bytes: thin, cpuType: CPU_X86_64, cpuSubtype: 3 },
    { bytes: thin, cpuType: CPU_ARM64, cpuSubtype: 0x80000002 },
  ]);
};

it("extracts exactly the committed arm64e slice across stream chunks and preserves the original identity", async () => {
  const root = await createTestTempDirectory("rea-fat-snapshot-");
  const fixture = fatFixture();
  const source = join(root, "universal");
  await writeFile(source, fixture.bytes);
  const slice = fixture.slices[1]!;
  const snapshot = await createGhidraTargetSnapshot(
    source,
    root,
    digest(fixture.bytes),
    {
      universalSlice: { ...slice, architecture: "arm64" },
      platform: "darwin",
    },
  );
  const expected = fixture.bytes.subarray(
    slice.offset,
    slice.offset + slice.size,
  );
  expect((await readFile(snapshot.path)).equals(expected)).toBe(true);
  expect(snapshot.sha256).toBe(digest(fixture.bytes));
  expect(snapshot.importedSha256).toBe(digest(expected));
  expect((await readFile(source)).equals(fixture.bytes)).toBe(true);
});

it.each(["range", "cpu", "subtype", "unselected-bytes", "windows"] as const)(
  "refuses invalid universal admission: %s",
  async (failure) => {
    const root = await createTestTempDirectory("rea-fat-reject-");
    const fixture = fatFixture();
    const expected = digest(fixture.bytes);
    const slice = fixture.slices[1]!;
    const source = join(root, "universal");
    if (failure === "subtype") fixture.bytes.writeUInt32BE(0, 8 + 20 + 4);
    if (failure === "unselected-bytes") {
      const index = fixture.slices[0]!.offset + 100;
      fixture.bytes[index] = fixture.bytes[index]! ^ 1;
    }
    await writeFile(source, fixture.bytes);
    await expect(
      createGhidraTargetSnapshot(source, root, expected, {
        universalSlice: {
          offset: slice.offset,
          size: slice.size + (failure === "range" ? 1 : 0),
          architecture: failure === "cpu" ? "x86_64" : "arm64",
        },
        platform: failure === "windows" ? "win32" : "darwin",
      }),
    ).rejects.toThrow();
  },
);

it("preserves cancellation before universal extraction", async () => {
  const root = await createTestTempDirectory("rea-fat-cancel-");
  const fixture = fatFixture();
  const source = join(root, "universal");
  await writeFile(source, fixture.bytes);
  await expect(
    createGhidraTargetSnapshot(source, root, digest(fixture.bytes), {
      universalSlice: { ...fixture.slices[1]!, architecture: "arm64" },
      signal: AbortSignal.abort("caller-stopped"),
      platform: "darwin",
    }),
  ).rejects.toMatchObject({ reason: "cancelled" });
  expect((await readFile(source)).equals(fixture.bytes)).toBe(true);
});
