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

describe("consoleRom PSP, Xbox, and PS3", () => {
  it("auto-detects PSP PRX and PBP containers and relocates PRX segments to 0x08804000", () => {
    const pbp = Buffer.alloc(0x200, 0);
    pbp.write("\x00PBP", 0, "binary");
    pbp.writeUInt32LE(0x80, 0x20); // DATA.PSP offset = 0x80
    pbp.writeUInt32LE(0x200, 0x24); // DATA.PSAR offset = 0x200

    // Embedded ELF32 LE MIPS PRX (e_type = 0xffa0) at 0x80
    const elf = pbp.subarray(0x80);
    elf.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
    elf.writeUInt16LE(0xffa0, 0x10); // ET_PSP_PRX
    elf.writeUInt16LE(8, 0x12); // EM_MIPS
    elf.writeUInt32LE(0x100, 0x18); // relative entry 0x100 -> 0x08804100
    elf.writeUInt32LE(0x34, 0x1c); // e_phoff
    elf.writeUInt32LE(0x00a20000, 0x24); // Allegrex flags
    elf.writeUInt16LE(32, 0x2a); // e_phentsize
    elf.writeUInt16LE(1, 0x2c); // e_phnum = 1
    // Program header 0: PT_LOAD
    elf.writeUInt32LE(1, 0x34); // p_type = PT_LOAD
    elf.writeUInt32LE(0x60, 0x38); // p_offset = 0x60 (file offset 0x80 + 0x60 = 0xe0)
    elf.writeUInt32LE(0x0, 0x3c); // p_vaddr = 0x0 -> relocated to 0x08804000
    elf.writeUInt32LE(0x100, 0x44); // p_filesz = 0x100
    elf.writeUInt32LE(5, 0x4c); // PF_R | PF_X

    expect(detectConsoleFormatFromHeader(pbp, 0x200, "/roms/EBOOT.PBP")).toBe(
      "psp",
    );
    const admitted = admitConsoleTarget({
      format: "psp",
      headerBytes: pbp,
      fileBytes: 0x200,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("psp");
    expect(admitted.value.architecture).toBe("allegrex");
    expect(admitted.value.entryPoint).toBe("0x8804100");
    expect(admitted.value.fileMappings[0]).toEqual({
      name: "LOAD_0",
      virtualAddress: "0x8804000",
      fileOffset: 0xe0,
      byteLength: 0x100,
      executable: true,
      writable: false,
    });
  });

  it("auto-detects Original Xbox XBE header, decodes retail XOR entry point, and maps sections", () => {
    const xbe = Buffer.alloc(0x400, 0);
    xbe.write("XBEH", 0, "ascii");
    const baseAddr = 0x00010000;
    const realEntry = 0x00011234;
    const xorRetailEntry = (realEntry ^ 0xa8fc57ab) >>> 0;
    xbe.writeUInt32LE(baseAddr, 0x104); // BaseAddress
    xbe.writeUInt32LE(0x400, 0x108); // SizeOfHeaders
    xbe.writeUInt32LE(0x10000, 0x10c); // SizeOfImage
    xbe.writeUInt32LE(baseAddr + 0x200, 0x118); // CertificateAddress
    xbe.writeUInt32LE(1, 0x11c); // NumberOfSections
    xbe.writeUInt32LE(baseAddr + 0x300, 0x120); // SectionHeadersAddress
    xbe.writeUInt32LE(xorRetailEntry, 0x128); // XOR-encoded retail EntryPoint

    // Certificate at offset 0x200
    xbe.writeUInt32LE(0x4d530001, 0x208); // TitleId
    xbe.write("Halo", 0x20c, "utf16le");

    // Section 0 at offset 0x300, name at 0x350
    xbe.write(".text\0", 0x350, "ascii");
    xbe.writeUInt32LE(0x05, 0x300); // Flags: Writable(1) | Executable(4)
    xbe.writeUInt32LE(0x00011000, 0x304); // VirtualAddress
    xbe.writeUInt32LE(0x2000, 0x308); // VirtualSize
    xbe.writeUInt32LE(0x1000, 0x30c); // RawAddress
    xbe.writeUInt32LE(0x2000, 0x310); // RawSize
    xbe.writeUInt32LE(baseAddr + 0x350, 0x314); // SectionNameAddress

    expect(
      detectConsoleFormatFromHeader(xbe, 0x10000, "/roms/default.xbe"),
    ).toBe("xbox");
    const admitted = admitConsoleTarget({
      format: "xbox",
      headerBytes: xbe,
      fileBytes: 0x10000,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("xbox");
    expect(admitted.value.architecture).toBe("x86");
    expect(admitted.value.entryPoint).toBe("0x11234");
    expect(admitted.value.romMetadata.build_type).toBe("retail");
    expect(admitted.value.romMetadata.title_name).toBe("Halo");
    expect(admitted.value.fileMappings[0]).toEqual({
      name: ".text",
      virtualAddress: "0x11000",
      fileOffset: 0x1000,
      byteLength: 0x2000,
      executable: true,
      writable: true,
    });
  });

  it("auto-detects PS3 Cell PPU ELF64 Big-Endian and resolves OPD descriptor entry points", () => {
    const ps3 = Buffer.alloc(0x400, 0);
    ps3.set([0x7f, 0x45, 0x4c, 0x46, 2, 2, 1, 0x66]); // ELF64 BE, OSABI=0x66 (Cell LV2)
    ps3.writeUInt16BE(2, 0x10); // ET_EXEC
    ps3.writeUInt16BE(21, 0x12); // EM_PPC64
    ps3.writeBigUInt64BE(0x20000n, 0x18); // e_entry -> points to OPD in LOAD_1
    ps3.writeBigUInt64BE(0x40n, 0x20); // e_phoff = 0x40
    ps3.writeUInt16BE(56, 0x36); // e_phentsize = 56
    ps3.writeUInt16BE(2, 0x38); // e_phnum = 2

    // PHDR 0 at 0x40: Executable code segment at VA 0x10000 (file offset 0x100, size 0x100)
    ps3.writeUInt32BE(1, 0x40); // PT_LOAD
    ps3.writeUInt32BE(5, 0x44); // PF_R | PF_X
    ps3.writeBigUInt64BE(0x100n, 0x48); // p_offset
    ps3.writeBigUInt64BE(0x10000n, 0x50); // p_vaddr
    ps3.writeBigUInt64BE(0x100n, 0x60); // p_filesz

    // PHDR 1 at 0x78: Data/OPD segment at VA 0x20000 (file offset 0x200, size 0x100)
    ps3.writeUInt32BE(1, 0x78); // PT_LOAD
    ps3.writeUInt32BE(6, 0x7c); // PF_R | PF_W
    ps3.writeBigUInt64BE(0x200n, 0x80); // p_offset
    ps3.writeBigUInt64BE(0x20000n, 0x88); // p_vaddr
    ps3.writeBigUInt64BE(0x100n, 0x98); // p_filesz

    // OPD descriptor at file offset 0x200 (VA 0x20000): [func_addr = 0x10040, toc = 0x28000]
    ps3.writeUInt32BE(0x00010040, 0x200);
    ps3.writeUInt32BE(0x00028000, 0x204);

    expect(detectConsoleFormatFromHeader(ps3, 0x400, "/roms/EBOOT.ELF")).toBe(
      "ps3",
    );
    const admitted = admitConsoleTarget({
      format: "ps3",
      headerBytes: ps3,
      fileBytes: 0x400,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("ps3");
    expect(admitted.value.architecture).toBe("cell-ppu");
    expect(admitted.value.entryPoint).toBe("0x10040");
    expect(admitted.value.romMetadata.toc_base).toBe("0x28000");
  });
});
