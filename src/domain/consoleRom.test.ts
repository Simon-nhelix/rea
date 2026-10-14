import { describe, expect, it } from "vitest";
import {
  admitConsoleTarget,
  detectConsoleFormatFromHeader,
  formatConsoleTargetSpecTsv,
} from "./consoleRom.js";

describe("consoleRom", () => {
  it("auto-detects PS-X EXE header and parses load/entry/text_size", () => {
    const header = Buffer.alloc(0x800, 0);
    header.write("PS-X EXE", 0x00, "ascii");
    header.writeUInt32LE(0x80010000, 0x10); // initial PC
    header.writeUInt32LE(0x80010000, 0x18); // load address
    header.writeUInt32LE(0x00024000, 0x1c); // text size

    expect(
      detectConsoleFormatFromHeader(header, 0x24800, "/roms/slps_012.34"),
    ).toBe("psx-exe");
    const admitted = admitConsoleTarget({
      format: "psx-exe",
      headerBytes: header,
      fileBytes: 0x24800,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("psx-exe");
    expect(admitted.value.architecture).toBe("r3000");
    expect(admitted.value.entryPoint).toBe("0x80010000");
    expect(admitted.value.fileMappings[0]).toEqual({
      name: "PSX_TEXT",
      virtualAddress: "0x80010000",
      fileOffset: 0x800,
      byteLength: 0x24000,
      executable: true,
      writable: true,
    });
  });

  it("auto-detects GBA ROM via Nintendo logo and 0x96 fixed byte", () => {
    const header = Buffer.alloc(0x100, 0);
    header[0x03] = 0xea;
    Buffer.from("24ffae51699aa2213d84820a84e409ad", "hex").copy(header, 0x04);
    header[0xb2] = 0x96;

    expect(
      detectConsoleFormatFromHeader(header, 0x1000000, "/roms/mother3.gba"),
    ).toBe("gba");
    const admitted = admitConsoleTarget({
      format: "gba",
      headerBytes: header,
      fileBytes: 0x1000000,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("gba");
    expect(admitted.value.architecture).toBe("arm");
    expect(admitted.value.entryPoint).toBe("0x8000000");
  });

  it("auto-detects NES iNES ROM and maps PRG-ROM to 0x8000", () => {
    const header = Buffer.alloc(0x20, 0);
    header.write("NES\x1a", 0, "ascii");
    header[4] = 2; // 2 * 16KB = 32KB PRG

    expect(
      detectConsoleFormatFromHeader(header, 16 + 0x8000, "/roms/dq.nes"),
    ).toBe("nes");
    const admitted = admitConsoleTarget({
      format: "nes",
      headerBytes: header,
      fileBytes: 16 + 0x8000,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("nes");
    expect(admitted.value.architecture).toBe("6502");
    expect(admitted.value.fileMappings[0]?.fileOffset).toBe(16);
    expect(admitted.value.fileMappings[0]?.virtualAddress).toBe("0x8000");
  });

  it("auto-detects Game Boy ROM and maps BANK0 + BANKN", () => {
    const header = Buffer.alloc(0x180, 0);
    Buffer.from("ceed6666cc0d000b03730083000c000d", "hex").copy(header, 0x104);
    expect(
      detectConsoleFormatFromHeader(header, 0x40000, "/roms/zelda.gbc"),
    ).toBe("gb");
    const admitted = admitConsoleTarget({
      format: "gb",
      headerBytes: header,
      fileBytes: 0x40000,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("gb");
    expect(admitted.value.architecture).toBe("sm83");
    expect(admitted.value.entryPoint).toBe("0x100");
  });

  it("auto-detects GameCube DOL header and builds text/data segments", () => {
    const header = Buffer.alloc(0x100, 0);
    header.writeUInt32BE(0x00000100, 0x00); // Text0 file offset
    header.writeUInt32BE(0x80003100, 0x48); // Text0 load address
    header.writeUInt32BE(0x00010000, 0x90); // Text0 size
    header.writeUInt32BE(0x80003100, 0xe0); // Entry point

    expect(
      detectConsoleFormatFromHeader(header, 0x20000, "/roms/main.dol"),
    ).toBe("gc-dol");
    const admitted = admitConsoleTarget({
      format: "gc-dol",
      headerBytes: header,
      fileBytes: 0x20000,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("gc-dol");
    expect(admitted.value.architecture).toBe("gekko");
    expect(admitted.value.entryPoint).toBe("0x80003100");
    expect(admitted.value.fileMappings[0]?.name).toBe(".text0");
  });

  it("admits SNES LoROM with 512-byte copier header and serializes TSV spec", () => {
    const header = Buffer.alloc(0x8200, 0);
    // LoROM reset vector at 0x200 + 0x7ffc = 0x81fc
    header.writeUInt16LE(0x8000, 0x81fc);

    const admitted = admitConsoleTarget({
      format: "snes",
      headerBytes: header,
      fileBytes: 0x400200,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("snes");
    expect(admitted.value.architecture).toBe("65816");
    expect(admitted.value.entryPoint).toBe("0x8000");

    const tsv = formatConsoleTargetSpecTsv(admitted.value);
    expect(tsv).toContain("meta\tsnes\t65816:LE:16:default\t0x8000");
    expect(tsv).toContain("map\tBANK00_ROM\t0x8000\t512\t");
  });
});
