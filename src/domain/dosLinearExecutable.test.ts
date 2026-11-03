import { describe, expect, it } from "vitest";
import {
  dosLinearAddressOfFileOffset,
  dosLinearFileOffset,
  dosLinearFixupPatch,
  dosLinearMappedRuns,
  dosLinearRelocatedFileBytes,
  locateDosLinearHeader,
  parseDosLinearExecutable,
} from "./dosLinearExecutable.js";
import {
  buildLinearExecutable,
  sampleLinearProgram,
} from "../../tests/fixtures/dos/linearExecutable.js";

describe("DOS extender LE/LX parsing", () => {
  it("locates the header through e_lfanew and parses objects and fixups", () => {
    const file = sampleLinearProgram();
    const parsed = parseDosLinearExecutable(file);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const module = parsed.value;
    expect(module.signature).toBe("LE");
    expect(module.headerOffset).toBe(0x80);
    expect(module.dataPagesBase).toBe(0);
    expect(
      module.objects.map((o) => [o.number, o.virtualAddress, o.executable]),
    ).toEqual([
      [1, 0x10000, true],
      [2, 0x20000, false],
    ]);
    expect(module.entry).toEqual({ object: 1, offset: 0, address: 0x10000 });
    expect(
      module.fixups.map((f) => [f.sourceAddress, f.source, f.targetAddress]),
    ).toEqual([
      [0x10001, "offset32", 0x20000],
      [0x10006, "offset32", 0x20008],
      [0x1000d, "offset32", 0x20020],
      [0x20020, "offset32", 0x20000],
      [0x20024, "offset32", 0x20008],
      [0x20028, "offset32", 0x20010],
    ]);
    const hello = dosLinearFileOffset(module, 0x20000);
    expect(hello).not.toBeNull();
    expect(file.toString("latin1", hello!, hello! + 5)).toBe("HELLO");
    expect(dosLinearAddressOfFileOffset(module, hello!)).toBe(0x20000);
    // The fixup site is file-backed and holds zero bytes before relocation.
    const slot = module.fixups[3]!;
    expect(slot.sourceFileOffset).toBe(hello! + 0x20);
    expect(file.readUInt32LE(slot.sourceFileOffset!)).toBe(0);
    expect(Buffer.from(dosLinearFixupPatch(slot)!).readUInt32LE(0)).toBe(
      0x20000,
    );
  });

  it("maps file-backed runs and leaves the zero-filled object tail unmapped", () => {
    const parsed = parseDosLinearExecutable(sampleLinearProgram());
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const runs = dosLinearMappedRuns(parsed.value);
    expect(runs.map((r) => [r.object, r.virtualAddress, r.byteLength])).toEqual(
      [
        [1, 0x10000, 0x40],
        [2, 0x20000, 0x40],
      ],
    );
    expect(dosLinearFileOffset(parsed.value, 0x20100)).toBeNull();
  });

  it("parses LX page maps", () => {
    const parsed = parseDosLinearExecutable(
      sampleLinearProgram({ signature: "LX" }),
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.signature).toBe("LX");
    expect(parsed.value.fixups).toHaveLength(6);
  });

  it("follows a bound extender stub to the program's own stub", () => {
    const file = sampleLinearProgram({ bound: true });
    const located = locateDosLinearHeader(file);
    expect(located).toEqual({
      ok: true,
      value: { signature: "LE", headerOffset: 0x280, containerOffset: 0x200 },
    });
    const parsed = parseDosLinearExecutable(file);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.dataPagesBase).toBe(0x200);
    const hello = dosLinearFileOffset(parsed.value, 0x20000)!;
    expect(file.toString("latin1", hello, hello + 5)).toBe("HELLO");
  });

  it("resolves relative32 fixups between objects", () => {
    const code = Buffer.from([0xe8, 0, 0, 0, 0, 0xc3]);
    const file = buildLinearExecutable({
      objects: [
        {
          base: 0x10000,
          bytes: code,
          executable: true,
          writable: false,
          fixups: [
            {
              sourceOffset: 1,
              sourceType: 0x08,
              targetObject: 2,
              targetOffset: 0,
            },
          ],
        },
        {
          base: 0x30000,
          bytes: Buffer.from([0xc3]),
          executable: true,
          writable: false,
        },
      ],
      entryObject: 1,
      entryOffset: 0,
    });
    const parsed = parseDosLinearExecutable(file);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const [call] = parsed.value.fixups;
    expect(call?.source).toBe("relative32");
    expect(Buffer.from(dosLinearFixupPatch(call!)!).readInt32LE(0)).toBe(
      0x30000 - 0x10005,
    );
  });

  it("rejects plain MZ programs and DOS/16M modules", () => {
    const plain = Buffer.alloc(0x200);
    plain.write("MZ", 0, "latin1");
    plain.writeUInt16LE(0, 2);
    plain.writeUInt16LE(1, 4);
    plain.writeUInt16LE(4, 8);
    expect(locateDosLinearHeader(plain).ok).toBe(false);
    const bw = Buffer.concat([plain, Buffer.from("BW\0\0")]);
    const result = locateDosLinearHeader(bw);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("DOS/16M");
  });

  it("rejects page ranges outside the page map", () => {
    const file = Buffer.from(sampleLinearProgram());
    // Object 2 page count far beyond the module page count.
    file.writeUInt32LE(99, 0x80 + 0xc4 + 24 + 16);
    const parsed = parseDosLinearExecutable(file);
    expect(parsed.ok).toBe(false);
  });

  it("writes internal fixups into a loaded copy at the same file offsets", () => {
    const file = sampleLinearProgram();
    const parsed = parseDosLinearExecutable(file);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const loaded = dosLinearRelocatedFileBytes(file, parsed.value);
    expect(loaded.length).toBe(file.length);
    const code = dosLinearFileOffset(parsed.value, 0x10000)!;
    const table = dosLinearFileOffset(parsed.value, 0x20020)!;
    expect(loaded.readUInt32LE(code + 1)).toBe(0x20000);
    expect([0, 4, 8].map((i) => loaded.readUInt32LE(table + i))).toEqual([
      0x20000, 0x20008, 0x20010,
    ]);
    // The source file is not modified.
    expect(file.readUInt32LE(table)).toBe(0);
  });
});
