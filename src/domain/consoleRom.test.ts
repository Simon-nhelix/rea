import { describe, expect, it } from "vitest";
import {
  admitConsoleTarget,
  detectConsoleFormatFromHeader,
  detectN64ByteOrder,
  formatConsoleTargetSpecTsv,
  resolveConsoleFileOffset,
  resolveConsoleVirtualAddress,
  unswapN64Bytes,
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
    expect(admitted.value.ghidraLanguageId).toBe("SM83:LE:16:default");
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
    // Ghidra scope: only the entry bank is executable in the TSV projection,
    // while the admission keeps every bank executable.
    expect(tsv).toContain("map\tBANK00_ROM\t0x8000\t512\t32768\tr-x");
    expect(tsv).toContain("map\tBANK01_ROM\t0x18000\t33280\t32768\tr--");
    expect(admitted.value.fileMappings.every((map) => map.executable)).toBe(
      true,
    );
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

describe("consoleRom Saturn, NDS, Mega Drive, PCE, and multi-bank coordinates", () => {
  it("auto-detects Sega Saturn, Nintendo DS, Mega Drive, and PC Engine ROMs", () => {
    // Sega Saturn IP.BIN / executable
    const saturn = Buffer.alloc(0x200, 0);
    saturn.write("SEGA SEGASATURN ", 0x00, "ascii");
    saturn.write("T-12345G  V1.000", 0x20, "ascii");
    saturn.write("GRANDIA         ", 0x60, "ascii");
    saturn.writeUInt32BE(0x00004000, 0xe0); // firstReadSize
    saturn.writeUInt32BE(0x06004000, 0xf0); // firstReadAddress
    expect(detectConsoleFormatFromHeader(saturn, 0x10000, "/roms/ip.bin")).toBe(
      "saturn",
    );
    const satAdmitted = admitConsoleTarget({
      format: "saturn",
      headerBytes: saturn,
      fileBytes: 0x10000,
    });
    expect(satAdmitted.ok).toBe(true);
    if (satAdmitted.ok) {
      expect(satAdmitted.value.architecture).toBe("sh2");
      expect(satAdmitted.value.ghidraLanguageId).toBe("SuperH:BE:32:SH-2");
      expect(satAdmitted.value.entryPoint).toBe("0x6004000");
    }

    // Nintendo DS (.nds)
    const nds = Buffer.alloc(0x200, 0);
    nds.write("CHRONOTRIGGER", 0x00, "ascii");
    nds.write("YCTJ", 0x0c, "ascii");
    nds.writeUInt32LE(0x00004000, 0x20); // arm9RomOffset
    nds.writeUInt32LE(0x02000800, 0x24); // arm9EntryAddress
    nds.writeUInt32LE(0x02000000, 0x28); // arm9RamAddress
    nds.writeUInt32LE(0x00010000, 0x2c); // arm9Size
    nds.writeUInt16LE(0xcf56, 0x15c); // Nintendo logo CRC
    expect(detectConsoleFormatFromHeader(nds, 0x40000, "/roms/ct.nds")).toBe(
      "nds",
    );
    const ndsAdmitted = admitConsoleTarget({
      format: "nds",
      headerBytes: nds,
      fileBytes: 0x40000,
    });
    expect(ndsAdmitted.ok).toBe(true);
    if (ndsAdmitted.ok) {
      expect(ndsAdmitted.value.architecture).toBe("arm");
      expect(ndsAdmitted.value.entryPoint).toBe("0x2000800");
      expect(ndsAdmitted.value.fileMappings[0]?.fileOffset).toBe(0x4000);
    }

    // Sega Mega Drive / Genesis (.md)
    const md = Buffer.alloc(0x200, 0);
    md.writeUInt32BE(0x00fffe00, 0x00); // Initial SSP
    md.writeUInt32BE(0x00000200, 0x04); // Reset PC
    md.write("SEGA MEGA DRIVE ", 0x100, "ascii");
    md.write("LANGELISSER II  ", 0x120, "ascii");
    expect(detectConsoleFormatFromHeader(md, 0x100000, "/roms/lang2.md")).toBe(
      "md",
    );
    const mdAdmitted = admitConsoleTarget({
      format: "md",
      headerBytes: md,
      fileBytes: 0x100000,
    });
    expect(mdAdmitted.ok).toBe(true);
    if (mdAdmitted.ok) {
      expect(mdAdmitted.value.architecture).toBe("68000");
      expect(mdAdmitted.value.entryPoint).toBe("0x200");
    }

    // PC Engine (.pce) with 512-byte copier header
    const pce = Buffer.alloc(0x2200, 0);
    pce.writeUInt16LE(0xe120, 0x200 + 0x1ffe); // Reset vector in Bank 0
    expect(detectConsoleFormatFromHeader(pce, 0x4200, "/roms/ys.pce")).toBe(
      "pce",
    );
    const pceAdmitted = admitConsoleTarget({
      format: "pce",
      headerBytes: pce,
      fileBytes: 0x4200,
    });
    expect(pceAdmitted.ok).toBe(true);
    if (pceAdmitted.ok) {
      expect(pceAdmitted.value.architecture).toBe("6502");
      expect(pceAdmitted.value.ghidraLanguageId).toBe(
        "HuC6280:LE:16:experimental",
      );
      expect(pceAdmitted.value.entryPoint).toBe("0xe120");
    }

    // Standalone 16 KiB Saturn IP.BIN whose firstReadAddress is in 1ST_READ.BIN
    const satIpOnly = Buffer.alloc(0x4000, 0);
    satIpOnly.write("SEGA SEGASATURN ", 0x00, "ascii");
    satIpOnly.writeUInt32BE(0x06010000, 0xf0);
    const satIpAdmitted = admitConsoleTarget({
      format: "saturn",
      headerBytes: satIpOnly,
      fileBytes: 0x4000,
    });
    expect(satIpAdmitted.ok).toBe(true);
    if (satIpAdmitted.ok) {
      expect(satIpAdmitted.value.entryPoint).toBe("0x6002100");
    }

    // Dreamcast SH-4 raw boot binary (.bin with SH-4 NOPs + 0x8Cxxxxxx literal pool pointer)
    const dcBin = Buffer.alloc(0x80, 0);
    dcBin.writeUInt16LE(0x0009, 0x00); // nop
    dcBin.writeUInt32LE(0x8c184c40, 0x28); // literal pool pointer in Dreamcast RAM
    expect(
      detectConsoleFormatFromHeader(dcBin, 0x10000, "/roms/1ST_READ.BIN"),
    ).toBe("dc-bin");
  });
});

describe("consoleRom multi-bank and overlay coordinate resolution", () => {
  it("maps the last LoROM banks through ROM mirrors and round-trips their offsets", () => {
    const admitted = admitConsoleTarget({
      format: "snes",
      headerBytes: Buffer.alloc(0x8000),
      fileBytes: 0x400000,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.romMetadata.bank_count).toBe(128);
    expect(admitted.value.fileMappings).toHaveLength(254);
    for (const [bank, address] of [
      [125, 0x7d8100],
      [126, 0xfe8100],
      [127, 0xff8100],
    ]) {
      const offset = bank! * 0x8000 + 0x100;
      expect(resolveConsoleVirtualAddress(admitted.value, offset)).toBe(
        `0x${address!.toString(16)}`,
      );
      expect(resolveConsoleFileOffset(admitted.value, address!)).toBe(offset);
    }
    expect(resolveConsoleFileOffset(admitted.value, 0x7e8100)).toBeNull();
    expect(resolveConsoleVirtualAddress(admitted.value, 0x400000)).toBeNull();
  });

  it("uses the same bounded HiROM aliases for imports and offset lookup", () => {
    const header = Buffer.alloc(0x10000);
    header.writeUInt16LE(0xffff, 0xffdc);
    header.writeUInt16LE(0x8000, 0xfffc);
    const admitted = admitConsoleTarget({
      format: "snes",
      headerBytes: header,
      fileBytes: 0x1c000,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.romMetadata.mapping_mode).toBe("HiROM");
    for (const address of [0xc18100, 0x418100, 0x018100, 0x818100]) {
      expect(resolveConsoleFileOffset(admitted.value, address)).toBe(0x18100);
    }
    expect(resolveConsoleVirtualAddress(admitted.value, 0x18100)).toBe(
      "0xc18100",
    );
    for (const address of [0xc1c000, 0x41c000, 0x01c000, 0x81c000]) {
      expect(resolveConsoleFileOffset(admitted.value, address)).toBeNull();
    }
    expect(resolveConsoleVirtualAddress(admitted.value, 0x1c000)).toBeNull();
    for (const map of admitted.value.fileMappings) {
      expect(map.fileOffset + map.byteLength).toBeLessThanOrEqual(0x1c000);
    }
  });

  it("does not infer a Dreamcast from opcode and pointer coincidences", () => {
    const bytes = Buffer.alloc(0x80);
    bytes.writeUInt16LE(0x0009, 0);
    bytes.writeUInt32LE(0x8c184c40, 0x28);
    expect(
      detectConsoleFormatFromHeader(bytes, 0x10000, "/roms/unrelated.bin"),
    ).toBeUndefined();
    expect(
      detectConsoleFormatFromHeader(bytes, 0x10000, "/roms/not1st_read.bin"),
    ).toBeUndefined();
  });

  it("resolves multi-bank SNES, GB, and PS1 headerless overlay coordinates", () => {
    // Headerless PS1 overlay with explicit entry point
    const overlay = Buffer.alloc(0x1000, 0x11);
    const psxOverlay = admitConsoleTarget({
      format: "psx-exe",
      headerBytes: overlay,
      fileBytes: 0x1000,
      entryPoint: "0x80120000",
    });
    expect(psxOverlay.ok).toBe(true);
    if (psxOverlay.ok) {
      expect(psxOverlay.value.loadBase).toBe("0x80120000");
      expect(psxOverlay.value.fileMappings[0]?.virtualAddress).toBe(
        "0x80120000",
      );
    }

    // Multi-bank SNES LoROM (4 banks = 128 KiB + 512B SMC header)
    const snesHeader = Buffer.alloc(0x8200, 0);
    snesHeader.writeUInt16LE(0x8000, 0x81fc);
    const snes = admitConsoleTarget({
      format: "snes",
      headerBytes: snesHeader,
      fileBytes: 512 + 4 * 0x8000,
    });
    expect(snes.ok).toBe(true);
    if (snes.ok) {
      expect(snes.value.fileMappings).toHaveLength(8);
      // Bank 2 ($02:8100) -> 512 + 2 * 0x8000 + 0x100
      expect(resolveConsoleFileOffset(snes.value, 0x028100)).toBe(
        512 + 0x10100,
      );
      // FastROM mirror ($82:8100) -> same file offset
      expect(resolveConsoleFileOffset(snes.value, 0x828100)).toBe(
        512 + 0x10100,
      );
      // Bank-local 16-bit pointer ($8100) inside a table located in Bank 2
      expect(
        resolveConsoleFileOffset(snes.value, 0x8100, {
          tableFileOffset: 512 + 0x10000,
        }),
      ).toBe(512 + 0x10100);
      expect(resolveConsoleVirtualAddress(snes.value, 512 + 0x10100)).toBe(
        "0x28100",
      );
      expect(
        resolveConsoleVirtualAddress(snes.value, 512 + 4 * 0x8000),
      ).toBeNull();
      expect(resolveConsoleVirtualAddress(snes.value, 511)).toBeNull();

      // Overlapping mappings keep declaration-order (first match) semantics.
      const overlapping = {
        ...snes.value,
        fileMappings: [
          {
            name: "WIDE",
            virtualAddress: "0x8000",
            fileOffset: 0,
            byteLength: 0x10000,
            executable: true,
            writable: false,
          },
          {
            name: "INNER",
            virtualAddress: "0x9000",
            fileOffset: 0x9000,
            byteLength: 0x1000,
            executable: true,
            writable: false,
          },
        ],
      };
      expect(resolveConsoleFileOffset(overlapping, 0x9100)).toBe(0x1100);
    }
  });
});

describe("PCE reset mapping provenance", () => {
  it.each([0, 512])(
    "maps only reset bank zero with %i copier bytes",
    (copierBytes) => {
      const header = Buffer.alloc(copierBytes + 0x2000);
      header.writeUInt16LE(0xe0f3, copierBytes + 0x1ffe);
      const admitted = admitConsoleTarget({
        format: "pce",
        headerBytes: header,
        fileBytes: copierBytes + 0x40000,
      });
      if (!admitted.ok) throw new Error(admitted.error.reason);
      expect(admitted.value.fileMappings).toEqual([
        {
          name: "PCE_ROM_BANK0",
          virtualAddress: "0xe000",
          fileOffset: copierBytes,
          byteLength: 0x2000,
          executable: true,
          writable: false,
        },
      ]);
      expect(admitted.value.memoryRegions).toEqual([]);
      expect(admitted.value.romMetadata.mapping_scope).toBe(
        "reset-bank0-window-only",
      );
      expect(resolveConsoleFileOffset(admitted.value, 0xe0f3)).toBe(
        copierBytes + 0xf3,
      );
      expect(
        resolveConsoleVirtualAddress(admitted.value, copierBytes + 0xf3),
      ).toBe("0xe0f3");
      // A pointer table's own physical bank does not establish any MPR mapping.
      for (const address of [
        0x0000, 0x2000, 0x4000, 0x6000, 0x8000, 0xa000, 0xc000, 0xcb0f,
      ]) {
        expect(
          resolveConsoleFileOffset(admitted.value, address, {
            tableFileOffset: copierBytes + 0x2b00,
            fileBytes: copierBytes + 0x40000,
          }),
        ).toBeNull();
      }
      expect(
        resolveConsoleVirtualAddress(admitted.value, copierBytes + 0x2b0f),
      ).toBeNull();
      expect(formatConsoleTargetSpecTsv(admitted.value)).not.toContain(
        "PCE_ROM_WINDOW",
      );
    },
  );

  it("preserves an unresolvable reset vector instead of inventing E000", () => {
    const header = Buffer.alloc(0x2000);
    header.writeUInt16LE(0x4100, 0x1ffe);
    const admitted = admitConsoleTarget({
      format: "pce",
      headerBytes: header,
      fileBytes: 0x40000,
    });
    if (!admitted.ok) throw new Error(admitted.error.reason);
    expect(admitted.value.entryPoint).toBe("0x4100");
    expect(resolveConsoleFileOffset(admitted.value, 0x4100)).toBeNull();
  });

  it("maps PS2 ELF with >64 CodeWarrior overlay program headers and admits MWo3 overlays", () => {
    const phNum = 245;
    const header = Buffer.alloc(0x34 + phNum * 32, 0);
    header.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
    header.writeUInt16LE(2, 0x10); // ET_EXEC
    header.writeUInt16LE(8, 0x12); // EM_MIPS
    header.writeUInt32LE(0x00100108, 0x18); // entry
    header.writeUInt32LE(0x34, 0x1c); // phoff
    header.writeUInt32LE(0x20924001, 0x24); // R5900 flags
    header.writeUInt16LE(32, 0x2a); // phentsize
    header.writeUInt16LE(phNum, 0x2c); // phnum = 245 (> 64)
    // PH[0]: PT_LOAD
    header.writeUInt32LE(1, 0x34);
    header.writeUInt32LE(0x1f00, 0x38); // p_offset
    header.writeUInt32LE(0x00100000, 0x3c); // p_vaddr
    header.writeUInt32LE(0x40b500, 0x44); // p_filesz
    header.writeUInt32LE(7, 0x4c); // PF_R | PF_W | PF_X

    const admitted = admitConsoleTarget({
      format: "ps2-elf",
      headerBytes: header,
      fileBytes: 0x40d400,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.fileMappings).toHaveLength(1);
    expect(resolveConsoleFileOffset(admitted.value, 0x00100108)).toBe(0x2008);

    // CodeWarrior MWo3 overlay
    const mwo3 = Buffer.alloc(0x80, 0);
    mwo3.write("MWo3", 0, "ascii");
    mwo3.writeUInt32LE(1, 0x04); // ph index
    mwo3.writeUInt32LE(0x00814e00, 0x08); // loadAddr
    mwo3.writeUInt32LE(0x1000, 0x0c); // textSize
    mwo3.writeUInt32LE(0x2000, 0x10); // dataSize
    mwo3.write("stg_000.bin\0", 0x20, "ascii");
    expect(
      detectConsoleFormatFromHeader(mwo3, 0x3040, "/roms/stg_000.bin"),
    ).toBe("ps2-elf");
    const ovAdmitted = admitConsoleTarget({
      format: "ps2-elf",
      headerBytes: mwo3,
      fileBytes: 0x3040,
    });
    expect(ovAdmitted.ok).toBe(true);
    if (!ovAdmitted.ok) return;
    expect(ovAdmitted.value.entryPoint).toBe("0x814e40");
    expect(resolveConsoleFileOffset(ovAdmitted.value, 0x00815e40)).toBe(0x1040);
  });
});

const buildN64Rom = (bootAddress = 0x80000400): Buffer => {
  const rom = Buffer.alloc(0x2000, 0);
  rom.set([0x80, 0x37, 0x12, 0x40], 0);
  rom.writeUInt32BE(0x0000000f, 0x04); // clock rate
  rom.writeUInt32BE(bootAddress, 0x08); // IPL3 boot address
  rom.write("TEST GAME", 0x20, "ascii");
  for (let i = 0x20 + "TEST GAME".length; i < 0x34; i++) rom[i] = 0x20;
  rom.write("NTST", 0x3b, "ascii");
  rom[0x3f] = 1; // ROM version
  // lui $t0, 0x8000 at the boot image start (file offset 0x1000)
  rom.writeUInt32BE(0x3c088000, 0x1000);
  return rom;
};

const swapBytes16 = (bytes: Buffer): Buffer => {
  const out = Buffer.from(bytes);
  for (let i = 0; i + 1 < out.length; i += 2) {
    const first = out[i]!;
    out[i] = out[i + 1]!;
    out[i + 1] = first;
  }
  return out;
};

const swapWords32 = (bytes: Buffer): Buffer => {
  const out = Buffer.from(bytes);
  for (let i = 0; i + 3 < out.length; i += 4) {
    const word = out.readUInt32BE(i);
    out.writeUInt32LE(word, i);
  }
  return out;
};

describe("consoleRom Nintendo 64", () => {
  const buildRom = buildN64Rom;
  const swap16 = swapBytes16;
  const swap32 = swapWords32;

  it("identifies all three dump byte orders from the signature", () => {
    const rom = buildRom();
    expect(detectN64ByteOrder(rom)).toEqual({
      order: "big-endian",
      swap: undefined,
    });
    expect(detectN64ByteOrder(swap16(rom))).toEqual({
      order: "byteswapped-16",
      swap: 16,
    });
    expect(detectN64ByteOrder(swap32(rom))).toEqual({
      order: "little-endian",
      swap: 32,
    });
    expect(detectN64ByteOrder(Buffer.alloc(16))).toBeUndefined();
    expect(detectN64ByteOrder(Buffer.alloc(3))).toBeUndefined();
    // Unswap is its own inverse in both modes.
    expect(unswapN64Bytes(swap16(rom), 16).equals(rom)).toBe(true);
    expect(unswapN64Bytes(swap32(rom), 32).equals(rom)).toBe(true);
  });

  it("auto-detects and admits a big-endian .z64 image at the boot alignment", () => {
    const rom = buildRom();
    expect(
      detectConsoleFormatFromHeader(rom, rom.length, "/roms/game.bin"),
    ).toBe("n64");
    const admitted = admitConsoleTarget({
      format: "n64",
      headerBytes: rom,
      fileBytes: rom.length,
    });
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;
    expect(admitted.value.format).toBe("n64");
    expect(admitted.value.architecture).toBe("r4300");
    expect(admitted.value.ghidraLanguageId).toBe("MIPS:BE:32:default");
    expect(admitted.value.entryPoint).toBe("0x80000400");
    expect(admitted.value.loadBase).toBe("0x7ffff400");
    expect(admitted.value.fileByteSwap).toBeUndefined();
    expect(admitted.value.romMetadata).toMatchObject({
      game_title: "TEST GAME",
      game_code: "NTST",
      rom_version: 1,
      byte_order: "big-endian",
      boot_address: "0x80000400",
    });
    // IPL3 loads file offset 0x1000 to the boot address.
    expect(resolveConsoleVirtualAddress(admitted.value, 0x1000)).toBe(
      "0x80000400",
    );
    expect(resolveConsoleFileOffset(admitted.value, 0x80000400)).toBe(0x1000);
    const tsv = formatConsoleTargetSpecTsv(admitted.value);
    expect(tsv).toContain("meta\tn64\tMIPS:BE:32:default\t0x80000400");
    expect(tsv).not.toContain("swap\t");
  });

  it("admits byteswapped and little-endian dumps with the same facts", () => {
    for (const [dump, swap, order] of [
      [swap16(buildRom()), 16, "byteswapped-16"],
      [swap32(buildRom()), 32, "little-endian"],
    ] as const) {
      expect(
        detectConsoleFormatFromHeader(dump, dump.length, "/roms/game.rom"),
      ).toBe("n64");
      const admitted = admitConsoleTarget({
        format: "n64",
        headerBytes: dump,
        fileBytes: dump.length,
      });
      expect(admitted.ok).toBe(true);
      if (!admitted.ok) return;
      expect(admitted.value.entryPoint).toBe("0x80000400");
      expect(admitted.value.romMetadata.game_title).toBe("TEST GAME");
      expect(admitted.value.romMetadata.byte_order).toBe(order);
      expect(admitted.value.fileByteSwap).toBe(swap);
      const tsv = formatConsoleTargetSpecTsv(admitted.value);
      expect(tsv).toContain(`swap\t${swap}`);
      // The layout matches the big-endian dump exactly.
      expect(admitted.value.fileMappings).toEqual([
        {
          name: "ROM",
          virtualAddress: "0x7ffff400",
          fileOffset: 0,
          byteLength: dump.length,
          executable: true,
          writable: false,
        },
      ]);
    }
  });

  it("needs the suffix channel when the boot address is outside RDRAM", () => {
    const rom = buildRom(0x90000400);
    expect(
      detectConsoleFormatFromHeader(rom, rom.length, "/roms/game.bin"),
    ).toBeUndefined();
    expect(
      detectConsoleFormatFromHeader(rom, rom.length, "/roms/game.z64"),
    ).toBe("n64");
  });

  it("rejects non-cartridge bytes and unusable boot addresses", () => {
    expect(
      admitConsoleTarget({
        format: "n64",
        headerBytes: Buffer.alloc(0x2000, 0),
        fileBytes: 0x2000,
      }).ok,
    ).toBe(false);
    expect(
      admitConsoleTarget({
        format: "n64",
        headerBytes: buildRom(0),
        fileBytes: 0x2000,
      }).ok,
    ).toBe(false);
    expect(
      admitConsoleTarget({
        format: "n64",
        headerBytes: buildRom(0x80000402),
        fileBytes: 0x2000,
      }).ok,
    ).toBe(false);
    // Header and IPL3 alone carry no boot image byte.
    expect(
      admitConsoleTarget({
        format: "n64",
        headerBytes: buildRom(),
        fileBytes: 0x1000,
      }).ok,
    ).toBe(false);
  });
});
