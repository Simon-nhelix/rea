import { err, ok, type Result } from "./result.js";
import {
  parseRawBinaryEntryPoint,
  type RawBinaryAdmissionRejection,
} from "./rawBinary.js";

/** Supported video-game console executable and ROM target formats. */
export const CONSOLE_TARGET_FORMATS = [
  "gba",
  "psx-exe",
  "ps2-elf",
  "psp",
  "ps3",
  "xbox",
  "dc-bin",
  "saturn",
  "nds",
  "md",
  "pce",
  "gc-dol",
  "snes",
  "nes",
  "gb",
  "wsc",
  "n64",
] as const;

export type ConsoleTargetFormat = (typeof CONSOLE_TARGET_FORMATS)[number];

export const isConsoleTargetFormat = (
  value: unknown,
): value is ConsoleTargetFormat =>
  typeof value === "string" &&
  (CONSOLE_TARGET_FORMATS as readonly string[]).includes(value);

/** CPU architectures used across supported console targets. */
export type ConsoleArchitecture =
  | "arm"
  | "r3000"
  | "r5900"
  | "allegrex"
  | "cell-ppu"
  | "xenon"
  | "sh2"
  | "sh4"
  | "68000"
  | "gekko"
  | "65816"
  | "6502"
  | "sm83"
  | "r4300"
  | "x86";

/** One file-backed segment mapping in the console's virtual address space. */
export interface ConsoleFileMapping {
  readonly name: string;
  readonly virtualAddress: string;
  readonly fileOffset: number;
  readonly byteLength: number;
  readonly executable: boolean;
  readonly writable: boolean;
}

/** One hardware RAM, VRAM, or MMIO region in the console's memory map. */
export interface ConsoleMemoryRegion {
  readonly name: string;
  readonly virtualAddress: string;
  readonly byteLength: number;
  readonly kind: "ram" | "vram" | "mmio" | "scratchpad";
}

/** Parsed console target metadata committed into BinaryTarget and Ghidra profiles. */
export interface ConsoleTargetAdmission {
  readonly format: ConsoleTargetFormat;
  readonly architecture: ConsoleArchitecture;
  readonly ghidraLanguageId: string;
  readonly compilerSpecId: string;
  readonly loader: "BinaryLoader" | "ElfLoader";
  readonly loadBase: string;
  readonly entryPoint: string;
  readonly entryPointSource: string;
  readonly fileMappings: readonly ConsoleFileMapping[];
  readonly memoryRegions: readonly ConsoleMemoryRegion[];
  readonly romMetadata: Readonly<
    Record<string, string | number | boolean | null>
  >;
  /**
   * File byte permutation relative to the console's native byte order.
   * `16` means adjacent byte pairs are swapped, `32` means each 4-byte word
   * is stored reversed. Absent means file bytes are already native.
   * Consumers that read file content must undo this permutation; file
   * offsets and virtual addresses are unchanged by it.
   */
  readonly fileByteSwap?: 16 | 32;
}

const GBA_LOGO_PREFIX = Buffer.from([
  0x24, 0xff, 0xae, 0x51, 0x69, 0x9a, 0xa2, 0x21, 0x3d, 0x84, 0x82, 0x0a, 0x84,
  0xe4, 0x09, 0xad,
]);

const GB_LOGO_PREFIX = Buffer.from([
  0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00, 0x83, 0x00,
  0x0c, 0x00, 0x0d,
]);

/** Nintendo 64 cartridge byte order identified from the 0x80371240 signature. */
export type N64ByteOrder = "big-endian" | "byteswapped-16" | "little-endian";

/** Byte-order facts declared by the Nintendo 64 cartridge header signature. */
export interface N64ByteOrderFacts {
  readonly order: N64ByteOrder;
  /** Permutation a consumer must undo to read native bytes, when swapped. */
  readonly swap: 16 | 32 | undefined;
}

/**
 * Identify the dump byte order of a Nintendo 64 ROM from its first four bytes:
 * big-endian (.z64), 16-bit byteswapped (.v64), or little-endian (.n64).
 */
export const detectN64ByteOrder = (
  bytes: Buffer,
): N64ByteOrderFacts | undefined => {
  if (bytes.length < 4) return undefined;
  if (
    bytes[0] === 0x80 &&
    bytes[1] === 0x37 &&
    bytes[2] === 0x12 &&
    bytes[3] === 0x40
  ) {
    return { order: "big-endian", swap: undefined };
  }
  if (
    bytes[0] === 0x37 &&
    bytes[1] === 0x80 &&
    bytes[2] === 0x40 &&
    bytes[3] === 0x12
  ) {
    return { order: "byteswapped-16", swap: 16 };
  }
  if (
    bytes[0] === 0x40 &&
    bytes[1] === 0x12 &&
    bytes[2] === 0x37 &&
    bytes[3] === 0x80
  ) {
    return { order: "little-endian", swap: 32 };
  }
  return undefined;
};

/** Undo a Nintendo 64 file byte permutation; byte offsets are preserved. */
export const unswapN64Bytes = (bytes: Buffer, swap: 16 | 32): Buffer => {
  const out = Buffer.from(bytes);
  if (swap === 16) {
    for (let i = 0; i + 1 < out.length; i += 2) {
      const first = out[i]!;
      out[i] = out[i + 1]!;
      out[i + 1] = first;
    }
    return out;
  }
  for (let i = 0; i + 3 < out.length; i += 4) {
    const b0 = out[i]!;
    const b1 = out[i + 1]!;
    out[i] = out[i + 3]!;
    out[i + 1] = out[i + 2]!;
    out[i + 2] = b1;
    out[i + 3] = b0;
  }
  return out;
};

/**
 * Inspect file prefix bytes and optional path suffix to auto-detect unambiguous
 * console headers when no explicit format hint was supplied.
 */
export const detectConsoleFormatFromHeader = (
  bytes: Buffer,
  fileSize: number,
  lowerPath = "",
): ConsoleTargetFormat | undefined => {
  // 1. PS-X EXE ("PS-X EXE" magic at 0x00, minimum 0x800-byte header)
  if (
    bytes.length >= 0x40 &&
    fileSize > 0x800 &&
    bytes.subarray(0, 8).equals(Buffer.from("PS-X EXE", "ascii"))
  ) {
    return "psx-exe";
  }

  // 2. NES iNES ("NES\x1a" magic at 0x00, minimum 16-byte header)
  if (
    bytes.length >= 16 &&
    fileSize > 16 &&
    bytes[0] === 0x4e &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x53 &&
    bytes[3] === 0x1a
  ) {
    return "nes";
  }

  // 3. Original Xbox XBE ("XBEH" magic at 0x00) or Xbox 360 XEX2 ("XEX2" magic at 0x00)
  if (
    bytes.length >= 0x20 &&
    (bytes.subarray(0, 4).equals(Buffer.from("XBEH", "ascii")) ||
      bytes.subarray(0, 4).equals(Buffer.from("XEX2", "ascii")))
  ) {
    return "xbox";
  }

  // 4. PSP PBP ("\x00PBP" magic at 0x00) or ~PSP encrypted module ("~PSP" magic at 0x00)
  if (
    bytes.length >= 0x28 &&
    ((bytes[0] === 0x00 &&
      bytes[1] === 0x50 &&
      bytes[2] === 0x42 &&
      bytes[3] === 0x50) ||
      bytes.subarray(0, 4).equals(Buffer.from("~PSP", "ascii")))
  ) {
    return "psp";
  }

  // 5. PS3 Signed ELF / SELF / SPRX ("SCE\0" magic at 0x00)
  if (
    bytes.length >= 0x20 &&
    bytes[0] === 0x53 &&
    bytes[1] === 0x43 &&
    bytes[2] === 0x45 &&
    bytes[3] === 0x00
  ) {
    return "ps3";
  }

  // 6. PS2 Emotion Engine ELF32, CodeWarrior MWo3 overlay, or PSP PRX / Commercial Allegrex ELF32
  if (
    bytes.length >= 0x40 &&
    bytes[0] === 0x4d && // 'M'
    bytes[1] === 0x57 && // 'W'
    bytes[2] === 0x6f && // 'o'
    bytes[3] === 0x33 // '3'
  ) {
    const loadAddr = bytes.readUInt32LE(0x08);
    if (loadAddr >= 0x00100000 && loadAddr < 0x02000000) {
      return "ps2-elf";
    }
  }
  if (
    bytes.length >= 0x34 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46 &&
    bytes[4] === 1 && // ELFCLASS32
    bytes[5] === 1 && // ELFDATA2LSB
    bytes.readUInt16LE(18) === 8 // EM_MIPS
  ) {
    const eType = bytes.readUInt16LE(16);
    const flags = bytes.readUInt32LE(36);
    if ((flags & 0x00ff0000) === 0x00920000) {
      return "ps2-elf";
    }
    if (
      eType === 0xffa0 ||
      ((flags & 0x00ff0000) === 0x00a20000 && flags !== 0x10a23001)
    ) {
      return "psp";
    }
  }

  // 7. PS3 Cell LV2 PPU ELF64 Big-Endian (EM_PPC64 = 21 or EI_OSABI = 0x66)
  if (
    bytes.length >= 0x40 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46 &&
    bytes[4] === 2 && // ELFCLASS64
    bytes[5] === 2 // ELFDATA2MSB
  ) {
    const eMachine = bytes.readUInt16BE(18);
    const osAbi = bytes[7];
    if (eMachine === 21 || osAbi === 0x66) {
      return "ps3";
    }
  }

  // 8. GBA ROM (Nintendo logo at 0x04..0x13 and fixed 0x96 at 0xB2)
  if (
    bytes.length >= 0xc0 &&
    bytes[0xb2] === 0x96 &&
    bytes.subarray(0x04, 0x14).equals(GBA_LOGO_PREFIX)
  ) {
    return "gba";
  }

  // 9. Nintendo DS ROM (Nintendo logo at 0xC0..0xCF and valid ARM9 load/entry fields)
  if (
    bytes.length >= 0x160 &&
    bytes.subarray(0xc0, 0xd0).equals(GBA_LOGO_PREFIX)
  ) {
    const arm9Entry = bytes.readUInt32LE(0x24);
    const arm9Ram = bytes.readUInt32LE(0x28);
    if (
      arm9Entry >= 0x02000000 &&
      arm9Entry < 0x02400000 &&
      arm9Ram >= 0x02000000 &&
      arm9Ram < 0x02400000
    ) {
      return "nds";
    }
  }

  // 10. Sega Saturn IP.BIN / boot header ("SEGA SEGASATURN " at 0x00)
  if (
    bytes.length >= 0x100 &&
    bytes.subarray(0, 16).equals(Buffer.from("SEGA SEGASATURN ", "ascii"))
  ) {
    return "saturn";
  }

  // 11. Sega Mega Drive / Genesis ("SEGA MEGA DRIVE " or "SEGA GENESIS    " at 0x100)
  if (
    bytes.length >= 0x200 &&
    (bytes
      .subarray(0x100, 0x110)
      .equals(Buffer.from("SEGA MEGA DRIVE ", "ascii")) ||
      bytes
        .subarray(0x100, 0x110)
        .equals(Buffer.from("SEGA GENESIS    ", "ascii")) ||
      bytes.subarray(0x100, 0x105).equals(Buffer.from("SEGA ", "ascii")))
  ) {
    return "md";
  }

  // 12. Game Boy / Game Boy Color ROM (Nintendo logo at 0x104..0x113)
  if (
    bytes.length >= 0x150 &&
    bytes.subarray(0x104, 0x114).equals(GB_LOGO_PREFIX)
  ) {
    return "gb";
  }

  // Nintendo 64 ROM (0x80371240 signature in any dump byte order, with an
  // IPL3 boot address inside RDRAM KSEG0)
  if (bytes.length >= 0x40 && fileSize > 0x1000) {
    const byteOrder = detectN64ByteOrder(bytes);
    if (byteOrder !== undefined) {
      const header =
        byteOrder.swap === undefined
          ? bytes
          : unswapN64Bytes(bytes.subarray(0, 0x40), byteOrder.swap);
      const boot = header.readUInt32BE(0x08);
      if (boot >= 0x80000000 && boot < 0x80800000 && boot % 4 === 0) {
        return "n64";
      }
    }
  }

  // 13. GameCube DOL (valid section table with entry in 0x80000000..0x817fffff)
  if (
    (lowerPath.endsWith(".dol") || bytes.length >= 0x100) &&
    isValidGameCubeDolHeader(bytes, fileSize, lowerPath.endsWith(".dol"))
  ) {
    return "gc-dol";
  }

  // 14. SNES / Super Famicom (.sfc / .smc)
  if (lowerPath.endsWith(".sfc") || lowerPath.endsWith(".smc")) {
    return "snes";
  }

  // 15. Nintendo DS (.nds)
  if (lowerPath.endsWith(".nds")) {
    return "nds";
  }

  // 16. Sega Mega Drive / Genesis (.gen / .smd)
  if (lowerPath.endsWith(".gen") || lowerPath.endsWith(".smd")) {
    return "md";
  }

  // 17. PC Engine / TurboGrafx-16 (.pce)
  if (lowerPath.endsWith(".pce")) {
    return "pce";
  }

  // 18. WonderSwan / WonderSwan Color (.ws / .wsc)
  if (lowerPath.endsWith(".ws") || lowerPath.endsWith(".wsc")) {
    return "wsc";
  }

  // 19. Nintendo 64 (.z64 / .v64 / .n64)
  if (
    lowerPath.endsWith(".z64") ||
    lowerPath.endsWith(".v64") ||
    lowerPath.endsWith(".n64")
  ) {
    return "n64";
  }

  // Raw SH-4 has no identifying magic. Only the conventional boot filename
  // supplies a format hint; opcode/pointer coincidences in arbitrary .bin data
  // do not establish a Dreamcast target.
  if (
    /(?:^|[\\/])1st_read\.bin$/iu.test(lowerPath) &&
    bytes.length >= 0x40 &&
    fileSize >= 0x40 &&
    fileSize <= 0x01000000
  ) {
    return "dc-bin";
  }

  return undefined;
};

const isValidGameCubeDolHeader = (
  bytes: Buffer,
  fileSize: number,
  hasDolExtension: boolean,
): boolean => {
  if (bytes.length < 0x100 || fileSize < 0x100) return false;
  const entry = bytes.readUInt32BE(0xe0);
  if (entry < 0x80003100 || entry >= 0x81800000) return false;
  let validSections = 0;
  for (let i = 0; i < 18; i++) {
    const offset = bytes.readUInt32BE(i * 4);
    const address = bytes.readUInt32BE(0x48 + i * 4);
    const size = bytes.readUInt32BE(0x90 + i * 4);
    if (offset === 0 && address === 0 && size === 0) continue;
    if (offset < 0x100 || offset + size > fileSize) return false;
    if (address < 0x80000000 || address >= 0x81800000) return false;
    validSections++;
  }
  if (validSections === 0) return false;
  return hasDolExtension || validSections >= 2;
};

const hex32 = (value: number | bigint): string =>
  `0x${BigInt(value).toString(16)}`;

/**
 * Admit and parse a console ROM or executable into deterministic memory mappings,
 * hardware regions, and Ghidra loader coordinates.
 */
export const admitConsoleTarget = (input: {
  readonly format: ConsoleTargetFormat;
  readonly headerBytes: Buffer;
  readonly innerHeaderBytes?: Buffer | undefined;
  readonly trailerBytes?: Buffer | undefined;
  readonly fileBytes: number;
  readonly entryPoint?: unknown;
}): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const { format, headerBytes, innerHeaderBytes, trailerBytes, fileBytes } =
    input;
  if (!Number.isSafeInteger(fileBytes) || fileBytes < 1) {
    return err({
      reason: `${format} requires at least one file byte`,
      constraint: "file_format_rejected",
    });
  }
  let explicitEntry: { canonical: string; source: string } | undefined;
  if (input.entryPoint !== undefined) {
    if (typeof input.entryPoint !== "string") {
      return err({
        reason: "entry_point must be a hexadecimal address of the form 0x…",
        constraint: "load_selection_rejected",
      });
    }
    const parsed = parseRawBinaryEntryPoint(input.entryPoint);
    if (!parsed.ok) {
      return err({
        reason: parsed.error,
        constraint: "load_selection_rejected",
      });
    }
    explicitEntry = {
      canonical: parsed.value.canonical,
      source: parsed.value.source,
    };
  }

  switch (format) {
    case "gba":
      return admitGba(headerBytes, fileBytes, explicitEntry);
    case "psx-exe":
      return admitPsxExe(headerBytes, fileBytes, explicitEntry);
    case "ps2-elf":
      return admitPs2Elf(headerBytes, fileBytes, explicitEntry);
    case "psp":
      return admitPsp(headerBytes, innerHeaderBytes, fileBytes, explicitEntry);
    case "ps3":
      return admitPs3(headerBytes, fileBytes, explicitEntry);
    case "xbox":
      return admitXbox(headerBytes, fileBytes, explicitEntry);
    case "dc-bin":
      return admitDcBin(fileBytes, explicitEntry);
    case "saturn":
      return admitSaturn(headerBytes, fileBytes, explicitEntry);
    case "nds":
      return admitNds(headerBytes, fileBytes, explicitEntry);
    case "md":
      return admitMd(headerBytes, fileBytes, explicitEntry);
    case "pce":
      return admitPce(headerBytes, fileBytes, explicitEntry);
    case "gc-dol":
      return admitGcDol(headerBytes, fileBytes, explicitEntry);
    case "snes":
      return admitSnes(headerBytes, fileBytes, explicitEntry);
    case "nes":
      return admitNes(headerBytes, trailerBytes, fileBytes, explicitEntry);
    case "gb":
      return admitGb(headerBytes, fileBytes, explicitEntry);
    case "wsc":
      return admitWsc(trailerBytes, fileBytes, explicitEntry);
    case "n64":
      return admitN64(headerBytes, fileBytes, explicitEntry);
  }
};

const admitGba = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (fileBytes > 0x02000000) {
    return err({
      reason: "GBA ROM exceeds the 32 MiB Game Pak address window",
      constraint: "file_format_rejected",
    });
  }
  const title =
    headerBytes.length >= 0xac
      ? headerBytes.subarray(0xa0, 0xac).toString("ascii").replace(/\0+$/u, "")
      : "";
  const gameCode =
    headerBytes.length >= 0xb0
      ? headerBytes.subarray(0xac, 0xb0).toString("ascii").replace(/\0+$/u, "")
      : "";
  const entryPoint = explicitEntry?.canonical ?? "0x8000000";
  return ok({
    format: "gba",
    architecture: "arm",
    ghidraLanguageId: "ARM:LE:32:v4t",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0x8000000",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? "0x08000000",
    fileMappings: [
      {
        name: "ROM",
        virtualAddress: "0x8000000",
        fileOffset: 0,
        byteLength: fileBytes,
        executable: true,
        writable: false,
      },
    ],
    memoryRegions: [
      {
        name: "EWRAM",
        virtualAddress: "0x2000000",
        byteLength: 0x40000,
        kind: "ram",
      },
      {
        name: "IWRAM",
        virtualAddress: "0x3000000",
        byteLength: 0x8000,
        kind: "ram",
      },
      {
        name: "IO_REG",
        virtualAddress: "0x4000000",
        byteLength: 0x400,
        kind: "mmio",
      },
      {
        name: "PALRAM",
        virtualAddress: "0x5000000",
        byteLength: 0x400,
        kind: "vram",
      },
      {
        name: "VRAM",
        virtualAddress: "0x6000000",
        byteLength: 0x18000,
        kind: "vram",
      },
      {
        name: "OAM",
        virtualAddress: "0x7000000",
        byteLength: 0x400,
        kind: "vram",
      },
      {
        name: "SRAM",
        virtualAddress: "0xe000000",
        byteLength: 0x10000,
        kind: "ram",
      },
    ],
    romMetadata: {
      title: title || null,
      game_code: gameCode || null,
    },
  });
};

const admitPsxExe = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const hasPsxMagic =
    headerBytes.length >= 0x40 &&
    headerBytes.subarray(0, 8).equals(Buffer.from("PS-X EXE", "ascii"));
  if (hasPsxMagic && fileBytes <= 0x800) {
    return err({
      reason:
        "PS-X EXE header requires payload bytes after the 0x800-byte header",
      constraint: "file_format_rejected",
    });
  }
  const pc0 = hasPsxMagic ? headerBytes.readUInt32LE(0x10) : 0;
  const gp0 = hasPsxMagic ? headerBytes.readUInt32LE(0x14) : 0;
  const tAddr = hasPsxMagic ? headerBytes.readUInt32LE(0x18) : 0;
  const tSize = hasPsxMagic ? headerBytes.readUInt32LE(0x1c) : fileBytes;
  const loadAddress =
    tAddr !== 0 ? hex32(tAddr) : (explicitEntry?.canonical ?? "0x80010000");
  const entryPoint =
    explicitEntry?.canonical ?? (pc0 !== 0 ? hex32(pc0) : loadAddress);
  const payloadOffset = hasPsxMagic ? 0x800 : 0;
  const payloadLength = fileBytes - payloadOffset;
  return ok({
    format: "psx-exe",
    architecture: "r3000",
    ghidraLanguageId: "MIPS:LE:32:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: loadAddress,
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: [
      {
        name: hasPsxMagic ? "PSX_TEXT" : "PSX_OVERLAY",
        virtualAddress: loadAddress,
        fileOffset: payloadOffset,
        byteLength: payloadLength,
        executable: true,
        writable: true,
      },
    ],
    memoryRegions: [
      {
        name: "KSEG0_RAM",
        virtualAddress: "0x80000000",
        byteLength: 0x200000,
        kind: "ram",
      },
      {
        name: "SCRATCHPAD",
        virtualAddress: "0x1f800000",
        byteLength: 0x400,
        kind: "scratchpad",
      },
      {
        name: "HW_IO",
        virtualAddress: "0x1f801000",
        byteLength: 0x2000,
        kind: "mmio",
      },
    ],
    romMetadata: {
      has_psx_header: hasPsxMagic,
      pc0: hex32(pc0 !== 0 ? pc0 : BigInt(entryPoint)),
      gp0: hex32(gp0),
      t_addr: hex32(tAddr !== 0 ? tAddr : BigInt(loadAddress)),
      t_size: tSize,
    },
  });
};

const parseElf32LeLoadMappings = (
  elfBytes: Buffer,
  containerOffset: number,
  fileBytes: number,
  relocationBase = 0,
): ConsoleFileMapping[] => {
  if (elfBytes.length < 0x34) return [];
  const phOff = elfBytes.readUInt32LE(0x1c);
  const phEntSize = elfBytes.readUInt16LE(0x2a);
  const phNum = elfBytes.readUInt16LE(0x2c);
  if (phOff === 0 || phEntSize < 32 || phNum === 0 || phNum > 1024) return [];
  const mappings: ConsoleFileMapping[] = [];
  for (let i = 0; i < phNum; i++) {
    const off = phOff + i * phEntSize;
    if (off + 32 > elfBytes.length) break;
    const pType = elfBytes.readUInt32LE(off);
    if (pType !== 1) continue; // PT_LOAD
    const pOffset = elfBytes.readUInt32LE(off + 0x04);
    const pVaddr = elfBytes.readUInt32LE(off + 0x08);
    const pFilesz = elfBytes.readUInt32LE(off + 0x10);
    const pFlags = elfBytes.readUInt32LE(off + 0x18);
    if (pFilesz === 0 || containerOffset + pOffset + pFilesz > fileBytes) {
      continue;
    }
    const virtualAddr =
      pVaddr < relocationBase ? (pVaddr + relocationBase) >>> 0 : pVaddr;
    mappings.push({
      name: `LOAD_${mappings.length}`,
      virtualAddress: hex32(virtualAddr),
      fileOffset: containerOffset + pOffset,
      byteLength: pFilesz,
      executable: (pFlags & 1) !== 0,
      writable: (pFlags & 2) !== 0,
    });
  }
  return mappings;
};

const admitPs2Elf = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const ps2MemoryRegions: readonly ConsoleMemoryRegion[] = [
    {
      name: "EE_MAIN_RAM",
      virtualAddress: "0x100000",
      byteLength: 0x1f00000,
      kind: "ram",
    },
    {
      name: "EE_SCRATCHPAD",
      virtualAddress: "0x70000000",
      byteLength: 0x4000,
      kind: "scratchpad",
    },
    {
      name: "GS_PRIVILEGED",
      virtualAddress: "0x12000000",
      byteLength: 0x2000,
      kind: "mmio",
    },
  ];

  // CodeWarrior PS2 overlay ('MWo3' 0x40-byte header)
  if (
    headerBytes.length >= 0x40 &&
    headerBytes[0] === 0x4d &&
    headerBytes[1] === 0x57 &&
    headerBytes[2] === 0x6f &&
    headerBytes[3] === 0x33
  ) {
    const phIndex = headerBytes.readUInt32LE(0x04);
    const loadAddr = headerBytes.readUInt32LE(0x08);
    const textSize = headerBytes.readUInt32LE(0x0c);
    const dataSize = headerBytes.readUInt32LE(0x10);
    const bssSize = headerBytes.readUInt32LE(0x14);
    const overlayName = headerBytes
      .subarray(0x20, 0x40)
      .toString("ascii")
      .split("\0")[0];
    const declaredBytes = 0x40 + textSize + dataSize;
    const mappedBytes = Math.min(fileBytes, declaredBytes);
    const entryPoint =
      explicitEntry?.canonical ?? hex32((loadAddr + 0x40) >>> 0);
    return ok({
      format: "ps2-elf",
      architecture: "r5900",
      ghidraLanguageId: "MIPS:LE:64:64-32addr",
      compilerSpecId: "default",
      loader: "BinaryLoader",
      loadBase: hex32(loadAddr),
      entryPoint,
      entryPointSource: explicitEntry?.source ?? entryPoint,
      fileMappings: [
        {
          name: "MWO3_OVERLAY",
          virtualAddress: hex32(loadAddr),
          fileOffset: 0,
          byteLength: mappedBytes,
          executable: true,
          writable: true,
        },
      ],
      memoryRegions: ps2MemoryRegions,
      romMetadata: {
        container: "MWo3",
        overlay_name: overlayName ?? "",
        ph_index: phIndex,
        load_address: hex32(loadAddr),
        text_size: textSize,
        data_size: dataSize,
        bss_size: bssSize,
      },
    });
  }

  if (
    headerBytes.length < 0x34 ||
    headerBytes[0] !== 0x7f ||
    headerBytes[1] !== 0x45 ||
    headerBytes[2] !== 0x4c ||
    headerBytes[3] !== 0x46 ||
    headerBytes[4] !== 1 ||
    headerBytes[5] !== 1 ||
    headerBytes.readUInt16LE(18) !== 8
  ) {
    return err({
      reason: "ps2-elf requires a little-endian 32-bit MIPS ELF image",
      constraint: "file_format_rejected",
    });
  }
  const entry = headerBytes.readUInt32LE(0x18);
  const flags = headerBytes.readUInt32LE(0x24);
  const mappings = parseElf32LeLoadMappings(headerBytes, 0, fileBytes);
  const entryPoint =
    explicitEntry?.canonical ?? (entry !== 0 ? hex32(entry) : "0x100000");
  return ok({
    format: "ps2-elf",
    architecture: "r5900",
    ghidraLanguageId: "MIPS:LE:64:64-32addr",
    compilerSpecId: "default",
    loader: "ElfLoader",
    loadBase: mappings[0]?.virtualAddress ?? "0x100000",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: mappings,
    memoryRegions: ps2MemoryRegions,
    romMetadata: {
      elf_entry: hex32(entry),
      elf_flags: hex32(flags),
      emotion_engine: (flags & 0x00ff0000) === 0x00920000,
      segment_count: mappings.length,
    },
  });
};

const admitPsp = (
  headerBytes: Buffer,
  innerHeaderBytes: Buffer | undefined,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (headerBytes.length < 0x28 || fileBytes < 0x28) {
    return err({
      reason: "psp target requires at least 40 header bytes",
      constraint: "file_format_rejected",
    });
  }
  const pspMemoryRegions: readonly ConsoleMemoryRegion[] = [
    {
      name: "PSP_SCRATCHPAD",
      virtualAddress: "0x10000",
      byteLength: 0x4000,
      kind: "scratchpad",
    },
    {
      name: "PSP_VRAM",
      virtualAddress: "0x4000000",
      byteLength: 0x200000,
      kind: "vram",
    },
    {
      name: "PSP_USER_RAM",
      virtualAddress: "0x8800000",
      byteLength: 0x1800000,
      kind: "ram",
    },
  ];

  // Check for PBP container ("\x00PBP" magic)
  const isPbp =
    headerBytes[0] === 0x00 &&
    headerBytes[1] === 0x50 &&
    headerBytes[2] === 0x42 &&
    headerBytes[3] === 0x50;
  let containerOffset = 0;
  let pbpDataLength = fileBytes;
  if (isPbp) {
    const dataPspOffset = headerBytes.readUInt32LE(0x20);
    const dataPsarOffset = headerBytes.readUInt32LE(0x24);
    if (dataPspOffset === 0 || dataPspOffset >= fileBytes) {
      return err({
        reason: "PSP PBP container declares an invalid DATA.PSP offset",
        constraint: "file_format_rejected",
      });
    }
    containerOffset = dataPspOffset;
    pbpDataLength =
      dataPsarOffset > dataPspOffset && dataPsarOffset <= fileBytes
        ? dataPsarOffset - dataPspOffset
        : fileBytes - dataPspOffset;
  }

  const innerBytes =
    innerHeaderBytes !== undefined && innerHeaderBytes.length > 0
      ? innerHeaderBytes
      : containerOffset < headerBytes.length
        ? headerBytes.subarray(containerOffset)
        : Buffer.alloc(0);

  // Check if inner payload is an ELF32 LE MIPS binary (ET_EXEC or ET_PSP_PRX 0xFFA0)
  if (
    innerBytes.length >= 0x34 &&
    innerBytes[0] === 0x7f &&
    innerBytes[1] === 0x45 &&
    innerBytes[2] === 0x4c &&
    innerBytes[3] === 0x46
  ) {
    if (
      innerBytes[4] !== 1 ||
      innerBytes[5] !== 1 ||
      innerBytes.readUInt16LE(18) !== 8
    ) {
      return err({
        reason: "psp ELF payload must be a little-endian 32-bit MIPS image",
        constraint: "file_format_rejected",
      });
    }
    const eType = innerBytes.readUInt16LE(0x10);
    const rawEntry = innerBytes.readUInt32LE(0x18);
    const flags = innerBytes.readUInt32LE(0x24);
    const isPrx = eType === 0xffa0 || rawEntry < 0x08800000;
    const relocBase = isPrx ? 0x08804000 : 0;
    const mappings = parseElf32LeLoadMappings(
      innerBytes,
      containerOffset,
      fileBytes,
      relocBase,
    );
    const fallbackBase = mappings[0]?.virtualAddress ?? "0x8804000";
    const resolvedEntry =
      rawEntry === 0
        ? fallbackBase
        : hex32(rawEntry < relocBase ? rawEntry + relocBase : rawEntry);
    const entryPoint = explicitEntry?.canonical ?? resolvedEntry;
    const finalMappings: readonly ConsoleFileMapping[] =
      mappings.length > 0
        ? mappings
        : [
            {
              name: "PSP_TEXT",
              virtualAddress: "0x8804000",
              fileOffset: containerOffset,
              byteLength: pbpDataLength,
              executable: true,
              writable: true,
            },
          ];
    return ok({
      format: "psp",
      architecture: "allegrex",
      ghidraLanguageId: "MIPS:LE:32:default",
      compilerSpecId: "default",
      loader: "BinaryLoader",
      loadBase: finalMappings[0]!.virtualAddress,
      entryPoint,
      entryPointSource: explicitEntry?.source ?? entryPoint,
      fileMappings: finalMappings,
      memoryRegions: pspMemoryRegions,
      romMetadata: {
        container: isPbp ? "PBP" : eType === 0xffa0 ? "PRX" : "ELF",
        elf_type: hex32(eType),
        elf_flags: hex32(flags),
        is_prx: isPrx,
        encrypted_kirk: false,
        segment_count: finalMappings.length,
      },
    });
  }

  // ~PSP encrypted/packed module or raw PSP binary
  const isKirkPsp =
    innerBytes.length >= 0x28 &&
    innerBytes.subarray(0, 4).equals(Buffer.from("~PSP", "ascii"));
  const moduleName =
    isKirkPsp && innerBytes.length >= 0x26
      ? innerBytes.subarray(0x0a, 0x26).toString("ascii").replace(/\0+$/u, "")
      : null;
  const entryPoint = explicitEntry?.canonical ?? "0x8804000";
  return ok({
    format: "psp",
    architecture: "allegrex",
    ghidraLanguageId: "MIPS:LE:32:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0x8804000",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? "0x08804000",
    fileMappings: [
      {
        name: isKirkPsp ? "PSP_KIRK_IMAGE" : "PSP_RAW_IMAGE",
        virtualAddress: "0x8804000",
        fileOffset: containerOffset,
        byteLength: pbpDataLength,
        executable: true,
        writable: true,
      },
    ],
    memoryRegions: pspMemoryRegions,
    romMetadata: {
      container: isPbp ? "PBP" : isKirkPsp ? "~PSP" : "RAW",
      module_name: moduleName,
      encrypted_kirk: isKirkPsp,
    },
  });
};

const admitPs3 = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (headerBytes.length < 0x40 || fileBytes < 0x40) {
    return err({
      reason: "ps3 target requires at least a 64-byte ELF64 or SELF header",
      constraint: "file_format_rejected",
    });
  }
  const ps3MemoryRegions: readonly ConsoleMemoryRegion[] = [
    {
      name: "PS3_MAIN_RAM",
      virtualAddress: "0x10000",
      byteLength: 0x10000000,
      kind: "ram",
    },
    {
      name: "PS3_RSX_VRAM",
      virtualAddress: "0xc0000000",
      byteLength: 0x10000000,
      kind: "vram",
    },
  ];

  // 1. Check for PS3 "SCE\0" Signed ELF (SELF / SPRX)
  if (
    headerBytes[0] === 0x53 &&
    headerBytes[1] === 0x43 &&
    headerBytes[2] === 0x45 &&
    headerBytes[3] === 0x00
  ) {
    const selfVersion = headerBytes.readUInt32BE(0x04);
    const keyType = headerBytes.readUInt16BE(0x08);
    const headerLen = Number(headerBytes.readBigUInt64BE(0x10));
    const elfOffset =
      headerBytes.length >= 0x38
        ? Number(headerBytes.readBigUInt64BE(0x30))
        : 0;
    let embeddedEntry = 0x10200n;
    if (
      elfOffset > 0 &&
      elfOffset + 0x40 <= headerBytes.length &&
      headerBytes[elfOffset] === 0x7f &&
      headerBytes[elfOffset + 1] === 0x45 &&
      headerBytes[elfOffset + 2] === 0x4c &&
      headerBytes[elfOffset + 3] === 0x46
    ) {
      embeddedEntry = headerBytes.readBigUInt64BE(elfOffset + 0x18);
    }
    const payloadOffset =
      headerLen > 0 && headerLen < fileBytes ? headerLen : 0;
    const payloadLength = fileBytes - payloadOffset;
    const entryPoint =
      explicitEntry?.canonical ??
      (embeddedEntry !== 0n ? hex32(embeddedEntry) : "0x10200");
    return ok({
      format: "ps3",
      architecture: "cell-ppu",
      ghidraLanguageId: "PowerPC:BE:64:64-32addr",
      compilerSpecId: "default",
      loader: "BinaryLoader",
      loadBase: "0x10000",
      entryPoint,
      entryPointSource: explicitEntry?.source ?? entryPoint,
      fileMappings: [
        {
          name: "PS3_SELF_PAYLOAD",
          virtualAddress: "0x10000",
          fileOffset: payloadOffset,
          byteLength: payloadLength,
          executable: true,
          writable: true,
        },
      ],
      memoryRegions: ps3MemoryRegions,
      romMetadata: {
        container: "SELF",
        self_version: selfVersion,
        is_debug_fself: keyType === 0x8000,
        elf_entry: hex32(embeddedEntry),
        header_length: headerLen,
      },
    });
  }

  // 2. Decrypted PS3 ELF64 Big-Endian (Cell PPU EM_PPC64 = 21)
  if (
    headerBytes[0] !== 0x7f ||
    headerBytes[1] !== 0x45 ||
    headerBytes[2] !== 0x4c ||
    headerBytes[3] !== 0x46 ||
    headerBytes[4] !== 2 ||
    headerBytes[5] !== 2
  ) {
    return err({
      reason:
        "ps3 requires a big-endian 64-bit Cell PPU ELF image or SCE SELF container",
      constraint: "file_format_rejected",
    });
  }
  const osAbi = headerBytes[7]!;
  const eType = headerBytes.readUInt16BE(0x10);
  const eMachine = headerBytes.readUInt16BE(0x12);
  if (eMachine !== 21 && eMachine !== 20) {
    return err({
      reason: `ps3 ELF requires PowerPC64 (EM_PPC64=21), got e_machine=${eMachine}`,
      constraint: "file_format_rejected",
    });
  }
  const rawEntry = headerBytes.readBigUInt64BE(0x18);
  const phOff = Number(headerBytes.readBigUInt64BE(0x20));
  const flags = headerBytes.readUInt32BE(0x30);
  const phEntSize = headerBytes.readUInt16BE(0x36);
  const phNum = headerBytes.readUInt16BE(0x38);

  const mappings: ConsoleFileMapping[] = [];
  if (phOff > 0 && phEntSize >= 56 && phNum > 0 && phNum <= 64) {
    for (let i = 0; i < phNum; i++) {
      const off = phOff + i * phEntSize;
      if (off + 56 > headerBytes.length) break;
      const pType = headerBytes.readUInt32BE(off);
      if (pType !== 1) continue; // PT_LOAD
      const pFlags = headerBytes.readUInt32BE(off + 0x04);
      const pOffset = Number(headerBytes.readBigUInt64BE(off + 0x08));
      const pVaddr = headerBytes.readBigUInt64BE(off + 0x10);
      const pFilesz = Number(headerBytes.readBigUInt64BE(off + 0x20));
      if (pFilesz === 0 || pOffset + pFilesz > fileBytes) continue;
      mappings.push({
        name: `LOAD_${mappings.length}`,
        virtualAddress: hex32(pVaddr),
        fileOffset: pOffset,
        byteLength: pFilesz,
        executable: (pFlags & 1) !== 0,
        writable: (pFlags & 2) !== 0,
      });
    }
  }

  // Resolve PS3 PPC64 OPD (Official Procedure Descriptor) entry point if rawEntry
  // points into a non-executable data segment (.opd) whose first word points into code.
  let resolvedEntry = rawEntry;
  let tocBase: string | null = null;
  for (const map of mappings) {
    const mapStart = BigInt(map.virtualAddress);
    const mapEnd = mapStart + BigInt(map.byteLength);
    if (rawEntry >= mapStart && rawEntry + 8n <= mapEnd && !map.executable) {
      const opdFileOffset = map.fileOffset + Number(rawEntry - mapStart);
      if (opdFileOffset + 8 <= headerBytes.length) {
        const candidate32 = BigInt(headerBytes.readUInt32BE(opdFileOffset));
        const candidate32Toc = BigInt(
          headerBytes.readUInt32BE(opdFileOffset + 4),
        );
        const candidate64 = headerBytes.readBigUInt64BE(opdFileOffset);
        const candidate64Toc =
          opdFileOffset + 16 <= headerBytes.length
            ? headerBytes.readBigUInt64BE(opdFileOffset + 8)
            : 0n;
        const hitsExec = (addr: bigint): boolean =>
          mappings.some((m) => {
            const s = BigInt(m.virtualAddress);
            return m.executable && addr >= s && addr < s + BigInt(m.byteLength);
          });
        if (candidate32 !== 0n && hitsExec(candidate32)) {
          resolvedEntry = candidate32;
          tocBase = hex32(candidate32Toc);
        } else if (candidate64 !== 0n && hitsExec(candidate64)) {
          resolvedEntry = candidate64;
          tocBase = hex32(candidate64Toc);
        }
      }
      break;
    }
  }

  const finalMappings: readonly ConsoleFileMapping[] =
    mappings.length > 0
      ? mappings
      : [
          {
            name: "PS3_ELF_IMAGE",
            virtualAddress: "0x10000",
            fileOffset: 0,
            byteLength: fileBytes,
            executable: true,
            writable: true,
          },
        ];
  const entryPoint =
    explicitEntry?.canonical ??
    (resolvedEntry !== 0n
      ? hex32(resolvedEntry)
      : finalMappings[0]!.virtualAddress);

  return ok({
    format: "ps3",
    architecture: "cell-ppu",
    ghidraLanguageId: "PowerPC:BE:64:64-32addr",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: finalMappings[0]!.virtualAddress,
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: finalMappings,
    memoryRegions: ps3MemoryRegions,
    romMetadata: {
      container: eType === 0xffa4 ? "SPRX" : "ELF64",
      os_abi: hex32(osAbi),
      elf_entry: hex32(rawEntry),
      resolved_code_entry: hex32(resolvedEntry),
      toc_base: tocBase,
      elf_flags: hex32(flags),
      segment_count: finalMappings.length,
    },
  });
};

const admitXbox = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  // 1. Xbox 360 XEX2 ("XEX2" magic at 0x00)
  if (
    headerBytes.length >= 0x20 &&
    headerBytes.subarray(0, 4).equals(Buffer.from("XEX2", "ascii"))
  ) {
    const peDataOffset = headerBytes.readUInt32BE(0x08);
    const optHeaderCount = headerBytes.readUInt32BE(0x14);
    let xexEntry = 0x82000000;
    let xexBase = 0x82000000;
    const maxHeaders = Math.min(optHeaderCount, 64);
    for (let i = 0; i < maxHeaders; i++) {
      const dirOff = 0x18 + i * 8;
      if (dirOff + 8 > headerBytes.length) break;
      const key = headerBytes.readUInt32BE(dirOff);
      const val = headerBytes.readUInt32BE(dirOff + 4);
      if (key === 0x00010100) {
        xexEntry = val;
      } else if (key === 0x00010201) {
        xexBase = val;
      }
    }
    const payloadOffset =
      peDataOffset > 0 && peDataOffset < fileBytes ? peDataOffset : 0;
    const entryPoint = explicitEntry?.canonical ?? hex32(xexEntry);
    return ok({
      format: "xbox",
      architecture: "xenon",
      ghidraLanguageId: "PowerPC:BE:64:64-32addr",
      compilerSpecId: "default",
      loader: "BinaryLoader",
      loadBase: hex32(xexBase),
      entryPoint,
      entryPointSource: explicitEntry?.source ?? entryPoint,
      fileMappings: [
        {
          name: "XEX2_PAYLOAD",
          virtualAddress: hex32(xexBase),
          fileOffset: payloadOffset,
          byteLength: fileBytes - payloadOffset,
          executable: true,
          writable: true,
        },
      ],
      memoryRegions: [
        {
          name: "XBOX360_RAM",
          virtualAddress: "0x80000000",
          byteLength: 0x20000000,
          kind: "ram",
        },
      ],
      romMetadata: {
        container: "XEX2",
        image_base: hex32(xexBase),
        entry_point: hex32(xexEntry),
        pe_data_offset: payloadOffset,
      },
    });
  }

  // 2. Original Xbox XBE ("XBEH" magic at 0x00)
  if (
    headerBytes.length < 0x180 ||
    fileBytes < 0x180 ||
    !headerBytes.subarray(0, 4).equals(Buffer.from("XBEH", "ascii"))
  ) {
    return err({
      reason:
        "xbox requires an Original Xbox XBE (XBEH) or Xbox 360 XEX2 header",
      constraint: "file_format_rejected",
    });
  }

  const baseAddress = headerBytes.readUInt32LE(0x104) || 0x00010000;
  const sizeOfHeaders = headerBytes.readUInt32LE(0x108);
  const sizeOfImage = headerBytes.readUInt32LE(0x10c) || fileBytes;
  const certAddress = headerBytes.readUInt32LE(0x118);
  const numSections = headerBytes.readUInt32LE(0x11c);
  const sectionHeadersAddr = headerBytes.readUInt32LE(0x120);
  const rawEntry = headerBytes.readUInt32LE(0x128);
  const rawKernelThunk = headerBytes.readUInt32LE(0x158);

  // Decode XOR-obfuscated XBE entry point (Retail, Debug, or Chihiro)
  const imageEnd = baseAddress + sizeOfImage;
  const retailEntry = (rawEntry ^ 0xa8fc57ab) >>> 0;
  const debugEntry = (rawEntry ^ 0x94859d4b) >>> 0;
  const chihiroEntry = (rawEntry ^ 0x40b5c16e) >>> 0;
  let decodedEntry = baseAddress;
  let xbeBuildType = "raw";
  if (retailEntry >= baseAddress && retailEntry < imageEnd) {
    decodedEntry = retailEntry;
    xbeBuildType = "retail";
  } else if (debugEntry >= baseAddress && debugEntry < imageEnd) {
    decodedEntry = debugEntry;
    xbeBuildType = "debug";
  } else if (chihiroEntry >= baseAddress && chihiroEntry < imageEnd) {
    decodedEntry = chihiroEntry;
    xbeBuildType = "chihiro";
  } else if (rawEntry >= baseAddress && rawEntry < imageEnd) {
    decodedEntry = rawEntry;
  }

  const retailThunk = (rawKernelThunk ^ 0x5b6d40b6) >>> 0;
  const debugThunk = (rawKernelThunk ^ 0xefb1f152) >>> 0;
  const decodedThunk =
    xbeBuildType === "debug"
      ? debugThunk
      : xbeBuildType === "retail"
        ? retailThunk
        : rawKernelThunk;

  // Read Certificate Title ID & Title Name if within headerBytes
  let titleId: string | null = null;
  let titleName: string | null = null;
  if (certAddress >= baseAddress) {
    const certOff = certAddress - baseAddress;
    if (certOff + 0x5c <= headerBytes.length) {
      titleId = hex32(headerBytes.readUInt32LE(certOff + 0x08));
      const rawTitle = headerBytes
        .subarray(certOff + 0x0c, certOff + 0x5c)
        .toString("utf16le")
        .replace(/\0+$/u, "");
      if (rawTitle.length > 0) titleName = rawTitle;
    }
  }

  // Parse XBE Section Headers (56 bytes per section)
  const mappings: ConsoleFileMapping[] = [];
  if (
    sectionHeadersAddr >= baseAddress &&
    numSections > 0 &&
    numSections <= 64
  ) {
    const tableOff = sectionHeadersAddr - baseAddress;
    for (let i = 0; i < numSections; i++) {
      const secOff = tableOff + i * 56;
      if (secOff + 56 > headerBytes.length) break;
      const flags = headerBytes.readUInt32LE(secOff);
      const vaddr = headerBytes.readUInt32LE(secOff + 0x04);
      const rawAddr = headerBytes.readUInt32LE(secOff + 0x0c);
      const rawSize = headerBytes.readUInt32LE(secOff + 0x10);
      const nameAddr = headerBytes.readUInt32LE(secOff + 0x14);
      if (rawSize === 0 || rawAddr + rawSize > fileBytes) continue;
      let secName = `SEC_${i}`;
      if (nameAddr >= baseAddress) {
        const nameOff = nameAddr - baseAddress;
        if (nameOff < headerBytes.length) {
          const maxEnd = Math.min(headerBytes.length, nameOff + 32);
          const sub = headerBytes.subarray(nameOff, maxEnd);
          const nul = sub.indexOf(0);
          const ascii = (nul >= 0 ? sub.subarray(0, nul) : sub).toString(
            "ascii",
          );
          if (/^[\x20-\x7e]+$/u.test(ascii)) secName = ascii;
        }
      }
      mappings.push({
        name: secName,
        virtualAddress: hex32(vaddr),
        fileOffset: rawAddr,
        byteLength: rawSize,
        writable: (flags & 1) !== 0,
        executable: (flags & 4) !== 0,
      });
    }
  }

  const finalMappings: readonly ConsoleFileMapping[] =
    mappings.length > 0
      ? mappings
      : [
          {
            name: "XBE_IMAGE",
            virtualAddress: hex32(baseAddress),
            fileOffset: 0,
            byteLength: fileBytes,
            executable: true,
            writable: true,
          },
        ];

  const entryPoint = explicitEntry?.canonical ?? hex32(decodedEntry);
  return ok({
    format: "xbox",
    architecture: "x86",
    ghidraLanguageId: "x86:LE:32:default",
    compilerSpecId: "windows",
    loader: "BinaryLoader",
    loadBase: hex32(baseAddress),
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: finalMappings,
    memoryRegions: [
      {
        name: "XBOX_MAIN_RAM",
        virtualAddress: "0x10000",
        byteLength: 0x3ff0000,
        kind: "ram",
      },
    ],
    romMetadata: {
      container: "XBE",
      build_type: xbeBuildType,
      base_address: hex32(baseAddress),
      size_of_headers: sizeOfHeaders,
      size_of_image: sizeOfImage,
      decoded_entry: hex32(decodedEntry),
      kernel_thunk: hex32(decodedThunk),
      title_id: titleId,
      title_name: titleName,
      section_count: finalMappings.length,
    },
  });
};

const admitDcBin = (
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (fileBytes > 0x01000000) {
    return err({
      reason: "dc-bin image exceeds Dreamcast 16 MiB main RAM",
      constraint: "file_format_rejected",
    });
  }
  const loadBase = explicitEntry?.canonical ?? "0x8c010000";
  return ok({
    format: "dc-bin",
    architecture: "sh4",
    ghidraLanguageId: "SuperH4:LE:32:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase,
    entryPoint: loadBase,
    entryPointSource: explicitEntry?.source ?? "0x8c010000",
    fileMappings: [
      {
        name: "DC_1ST_READ",
        virtualAddress: loadBase,
        fileOffset: 0,
        byteLength: fileBytes,
        executable: true,
        writable: true,
      },
    ],
    memoryRegions: [
      {
        name: "DC_SYSRAM",
        virtualAddress: "0x8c000000",
        byteLength: 0x1000000,
        kind: "ram",
      },
      {
        name: "DC_VRAM",
        virtualAddress: "0xa5000000",
        byteLength: 0x800000,
        kind: "vram",
      },
      {
        name: "HOLLY_MMIO",
        virtualAddress: "0xa05f8000",
        byteLength: 0x2000,
        kind: "mmio",
      },
    ],
    romMetadata: {
      load_base: loadBase,
    },
  });
};

const admitSaturn = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const hasIpHeader =
    headerBytes.length >= 0x100 &&
    headerBytes
      .subarray(0, 16)
      .equals(Buffer.from("SEGA SEGASATURN ", "ascii"));
  const firstReadAddr =
    hasIpHeader && headerBytes.length >= 0xf4
      ? headerBytes.readUInt32BE(0xf0)
      : 0;
  const title =
    hasIpHeader && headerBytes.length >= 0xd0
      ? headerBytes
          .subarray(0x60, 0xd0)
          .toString("ascii")
          .replace(/\0+$/u, "")
          .trim()
      : "";
  const productId =
    hasIpHeader && headerBytes.length >= 0x2a
      ? headerBytes
          .subarray(0x20, 0x2a)
          .toString("ascii")
          .replace(/\0+$/u, "")
          .trim()
      : "";

  const defaultLoad = hasIpHeader ? 0x06002000 : 0x06004000;
  const loadBase = explicitEntry?.canonical ?? hex32(defaultLoad);
  const entryPoint =
    explicitEntry?.canonical ??
    (hasIpHeader &&
    firstReadAddr >= 0x06002000 &&
    firstReadAddr < 0x06002000 + fileBytes
      ? hex32(firstReadAddr)
      : hasIpHeader && fileBytes > 0x100
        ? "0x6002100"
        : loadBase);

  return ok({
    format: "saturn",
    architecture: "sh2",
    ghidraLanguageId: "SuperH:BE:32:SH-2",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase,
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: [
      {
        name: hasIpHeader ? "SATURN_DISC_BOOT" : "SATURN_OVERLAY_OR_1ST_READ",
        virtualAddress: loadBase,
        fileOffset: 0,
        byteLength: Math.min(fileBytes, 0x100000),
        executable: true,
        writable: true,
      },
    ],
    memoryRegions: [
      {
        name: "WORK_RAM_LOW",
        virtualAddress: "0x200000",
        byteLength: 0x100000,
        kind: "ram",
      },
      {
        name: "WORK_RAM_HIGH",
        virtualAddress: "0x6000000",
        byteLength: 0x100000,
        kind: "ram",
      },
      {
        name: "VDP1_VRAM",
        virtualAddress: "0x5c00000",
        byteLength: 0x80000,
        kind: "vram",
      },
      {
        name: "VDP1_FB",
        virtualAddress: "0x5c80000",
        byteLength: 0x40000,
        kind: "vram",
      },
      {
        name: "VDP2_VRAM",
        virtualAddress: "0x5e00000",
        byteLength: 0x80000,
        kind: "vram",
      },
      {
        name: "VDP2_CRAM",
        virtualAddress: "0x5f00000",
        byteLength: 0x1000,
        kind: "vram",
      },
      {
        name: "VDP2_REG",
        virtualAddress: "0x5f80000",
        byteLength: 0x200,
        kind: "mmio",
      },
      {
        name: "SCU_REG",
        virtualAddress: "0x5fe0000",
        byteLength: 0x100,
        kind: "mmio",
      },
    ],
    romMetadata: {
      has_ip_header: hasIpHeader,
      title: title || null,
      product_id: productId || null,
      first_read_address: firstReadAddr !== 0 ? hex32(firstReadAddr) : null,
      load_base: loadBase,
    },
  });
};

const admitNds = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const hasNdsHeader =
    headerBytes.length >= 0x160 &&
    fileBytes >= 0x200 &&
    headerBytes.subarray(0xc0, 0xd0).equals(GBA_LOGO_PREFIX);

  if (!hasNdsHeader && explicitEntry === undefined && fileBytes < 0x200) {
    return err({
      reason:
        "nds ROM requires at least a 512-byte NDS cartridge header unless entry_point is specified",
      constraint: "file_format_rejected",
    });
  }

  const title =
    headerBytes.length >= 0x0c
      ? headerBytes.subarray(0x00, 0x0c).toString("ascii").replace(/\0+$/u, "")
      : "";
  const gameCode =
    headerBytes.length >= 0x10
      ? headerBytes.subarray(0x0c, 0x10).toString("ascii").replace(/\0+$/u, "")
      : "";

  const arm9RomOffset =
    headerBytes.length >= 0x24 ? headerBytes.readUInt32LE(0x20) : 0;
  const arm9Entry =
    headerBytes.length >= 0x28 ? headerBytes.readUInt32LE(0x24) : 0x02000000;
  const arm9Ram =
    headerBytes.length >= 0x2c ? headerBytes.readUInt32LE(0x28) : 0x02000000;
  const arm9Size =
    headerBytes.length >= 0x30 ? headerBytes.readUInt32LE(0x2c) : fileBytes;

  const arm7RomOffset =
    headerBytes.length >= 0x34 ? headerBytes.readUInt32LE(0x30) : 0;
  const arm7Entry =
    headerBytes.length >= 0x38 ? headerBytes.readUInt32LE(0x34) : 0;
  const arm7Ram =
    headerBytes.length >= 0x3c ? headerBytes.readUInt32LE(0x38) : 0;
  const arm7Size =
    headerBytes.length >= 0x40 ? headerBytes.readUInt32LE(0x3c) : 0;

  const mappings: ConsoleFileMapping[] = [];
  if (
    arm9Size > 0 &&
    arm9RomOffset + arm9Size <= fileBytes &&
    arm9Ram >= 0x01ff8000 &&
    arm9Ram < 0x02800000
  ) {
    mappings.push({
      name: "NDS_ARM9",
      virtualAddress: hex32(arm9Ram),
      fileOffset: arm9RomOffset,
      byteLength: arm9Size,
      executable: true,
      writable: true,
    });
  } else {
    const fallbackRam = explicitEntry?.canonical ?? "0x2000000";
    mappings.push({
      name: "NDS_ARM9_RAW",
      virtualAddress: fallbackRam,
      fileOffset: 0,
      byteLength: Math.min(fileBytes, 0x400000),
      executable: true,
      writable: true,
    });
  }

  if (
    arm7Size > 0 &&
    arm7RomOffset > 0 &&
    arm7RomOffset + arm7Size <= fileBytes &&
    arm7Ram >= 0x02000000 &&
    arm7Ram < 0x04000000
  ) {
    const arm9Start = BigInt(mappings[0]!.virtualAddress);
    const arm9End = arm9Start + BigInt(mappings[0]!.byteLength);
    const arm7Start = BigInt(arm7Ram);
    const arm7End = arm7Start + BigInt(arm7Size);
    if (arm7End <= arm9Start || arm7Start >= arm9End) {
      mappings.push({
        name: "NDS_ARM7",
        virtualAddress: hex32(arm7Ram),
        fileOffset: arm7RomOffset,
        byteLength: arm7Size,
        executable: true,
        writable: true,
      });
    }
  }

  const loadBase = mappings[0]!.virtualAddress;
  const entryPoint =
    explicitEntry?.canonical ??
    (arm9Entry >= 0x01ff8000 && arm9Entry < 0x02800000
      ? hex32(arm9Entry)
      : loadBase);

  return ok({
    format: "nds",
    architecture: "arm",
    ghidraLanguageId: "ARM:LE:32:v5t",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase,
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: mappings,
    memoryRegions: [
      {
        name: "MAIN_RAM",
        virtualAddress: "0x2000000",
        byteLength: 0x400000,
        kind: "ram",
      },
      {
        name: "SHARED_WRAM",
        virtualAddress: "0x3000000",
        byteLength: 0x8000,
        kind: "ram",
      },
      {
        name: "ARM7_WRAM",
        virtualAddress: "0x37f8000",
        byteLength: 0x10000,
        kind: "ram",
      },
      {
        name: "NDS_IO",
        virtualAddress: "0x4000000",
        byteLength: 0x2000,
        kind: "mmio",
      },
      {
        name: "NDS_PALETTE",
        virtualAddress: "0x5000000",
        byteLength: 0x800,
        kind: "vram",
      },
      {
        name: "NDS_VRAM",
        virtualAddress: "0x6000000",
        byteLength: 0x100000,
        kind: "vram",
      },
      {
        name: "NDS_OAM",
        virtualAddress: "0x7000000",
        byteLength: 0x800,
        kind: "vram",
      },
    ],
    romMetadata: {
      title: title || null,
      game_code: gameCode || null,
      arm9_rom_offset: arm9RomOffset,
      arm9_entry: hex32(arm9Entry),
      arm9_ram_address: hex32(arm9Ram),
      arm9_size: arm9Size,
      arm7_rom_offset: arm7RomOffset,
      arm7_entry: arm7Entry !== 0 ? hex32(arm7Entry) : null,
      arm7_ram_address: arm7Ram !== 0 ? hex32(arm7Ram) : null,
      arm7_size: arm7Size,
    },
  });
};

const admitMd = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (fileBytes < 0x200 && explicitEntry === undefined) {
    return err({
      reason:
        "md ROM requires at least a 512-byte 68000 vector + Sega header unless entry_point is specified",
      constraint: "file_format_rejected",
    });
  }
  const initialSsp =
    headerBytes.length >= 4 ? headerBytes.readUInt32BE(0x00) : 0x00fffe00;
  const resetVector =
    headerBytes.length >= 8 ? headerBytes.readUInt32BE(0x04) : 0x00000200;
  const domesticTitle =
    headerBytes.length >= 0x150
      ? headerBytes
          .subarray(0x120, 0x150)
          .toString("ascii")
          .replace(/\0+$/u, "")
          .trim()
      : "";
  const overseasTitle =
    headerBytes.length >= 0x180
      ? headerBytes
          .subarray(0x150, 0x180)
          .toString("ascii")
          .replace(/\0+$/u, "")
          .trim()
      : "";
  const serial =
    headerBytes.length >= 0x18e
      ? headerBytes
          .subarray(0x180, 0x18e)
          .toString("ascii")
          .replace(/\0+$/u, "")
          .trim()
      : "";

  const resolvedReset =
    resetVector > 0 && resetVector < Math.min(fileBytes, 0x400000)
      ? hex32(resetVector)
      : "0x200";
  const entryPoint = explicitEntry?.canonical ?? resolvedReset;

  return ok({
    format: "md",
    architecture: "68000",
    ghidraLanguageId: "68000:BE:32:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0x0",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: [
      {
        name: "MD_ROM",
        virtualAddress: "0x0",
        fileOffset: 0,
        byteLength: Math.min(fileBytes, 0x400000),
        executable: true,
        writable: false,
      },
    ],
    memoryRegions: [
      {
        name: "Z80_RAM",
        virtualAddress: "0xa00000",
        byteLength: 0x2000,
        kind: "ram",
      },
      {
        name: "MD_IO",
        virtualAddress: "0xa10000",
        byteLength: 0x1000,
        kind: "mmio",
      },
      {
        name: "VDP_PORT",
        virtualAddress: "0xc00000",
        byteLength: 0x20,
        kind: "mmio",
      },
      {
        name: "WORK_RAM",
        virtualAddress: "0xff0000",
        byteLength: 0x10000,
        kind: "ram",
      },
    ],
    romMetadata: {
      domestic_title: domesticTitle || null,
      overseas_title: overseasTitle || null,
      serial: serial || null,
      initial_ssp: hex32(initialSsp),
      reset_vector: hex32(resetVector),
    },
  });
};

const admitPce = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const copierOffset =
    fileBytes >= 0x2200 && fileBytes % 0x2000 === 512 ? 512 : 0;
  const romBytes = fileBytes - copierOffset;
  if (romBytes < 0x2000) {
    return err({
      reason: "pce ROM requires at least one 8 KiB bank (0x2000 bytes)",
      constraint: "file_format_rejected",
    });
  }
  if (headerBytes.length < copierOffset + 0x2000) {
    return err({
      reason:
        "pce reset-vector admission requires the complete first 8 KiB bank",
      constraint: "file_format_rejected",
    });
  }
  const resetVector = headerBytes.readUInt16LE(copierOffset + 0x1ffe);
  const entryPoint = explicitEntry?.canonical ?? hex32(resetVector);
  const bank0Size = Math.min(romBytes, 0x2000);

  return ok({
    format: "pce",
    architecture: "6502",
    ghidraLanguageId: "HuC6280:LE:16:experimental",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0xe000",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: [
      {
        name: "PCE_ROM_BANK0",
        virtualAddress: "0xe000",
        fileOffset: copierOffset,
        byteLength: bank0Size,
        executable: true,
        writable: false,
      },
    ],
    // Logical zero page/stack operands are CPU-defined, but their physical
    // storage and other logical windows depend on MPR state. Do not infer the
    // usual post-boot IO/RAM configuration from a headerless cartridge image.
    memoryRegions: [],
    romMetadata: {
      copier_header_bytes: copierOffset,
      reset_vector: hex32(resetVector),
      mapping_scope: "reset-bank0-window-only",
      mpr7_reset_bank: 0,
      runtime_mpr_state: "unknown",
      bank_count: Math.ceil(romBytes / 0x2000),
    },
  });
};

const admitGcDol = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (headerBytes.length < 0x100 || fileBytes < 0x100) {
    return err({
      reason: "gc-dol requires at least a 256-byte DOL header",
      constraint: "file_format_rejected",
    });
  }
  const mappings: ConsoleFileMapping[] = [];
  for (let i = 0; i < 18; i++) {
    const isText = i < 7;
    const index = isText ? i : i - 7;
    const offset = headerBytes.readUInt32BE(i * 4);
    const address = headerBytes.readUInt32BE(0x48 + i * 4);
    const size = headerBytes.readUInt32BE(0x90 + i * 4);
    if (offset === 0 || size === 0) continue;
    if (offset + size > fileBytes) {
      return err({
        reason: `gc-dol section ${isText ? `Text${index}` : `Data${index}`} exceeds file bounds`,
        constraint: "file_format_rejected",
      });
    }
    mappings.push({
      name: isText ? `.text${index}` : `.data${index}`,
      virtualAddress: hex32(address),
      fileOffset: offset,
      byteLength: size,
      executable: isText,
      writable: !isText,
    });
  }
  if (mappings.length === 0) {
    return err({
      reason: "gc-dol header declares no non-empty text or data sections",
      constraint: "file_format_rejected",
    });
  }
  const bssAddress = headerBytes.readUInt32BE(0xd8);
  const bssSize = headerBytes.readUInt32BE(0xdc);
  const headerEntry = headerBytes.readUInt32BE(0xe0);
  const entryPoint =
    explicitEntry?.canonical ??
    (headerEntry !== 0 ? hex32(headerEntry) : mappings[0]!.virtualAddress);
  return ok({
    format: "gc-dol",
    architecture: "gekko",
    ghidraLanguageId: "PowerPC:BE:32:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: mappings[0]!.virtualAddress,
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: mappings,
    memoryRegions: [
      ...(bssAddress !== 0 && bssSize !== 0
        ? [
            {
              name: ".bss",
              virtualAddress: hex32(bssAddress),
              byteLength: bssSize,
              kind: "ram" as const,
            },
          ]
        : []),
      {
        name: "GC_MMIO",
        virtualAddress: "0xcc000000",
        byteLength: 0x10000,
        kind: "mmio",
      },
    ],
    romMetadata: {
      section_count: mappings.length,
      bss_address: bssAddress !== 0 ? hex32(bssAddress) : null,
      bss_size: bssSize,
      dol_entry: hex32(headerEntry),
    },
  });
};

const admitSnes = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const smcOffset = fileBytes >= 0x8200 && fileBytes % 1024 === 512 ? 512 : 0;
  const romBytes = fileBytes - smcOffset;
  if (romBytes < 0x8000) {
    return err({
      reason: "snes ROM requires at least one 32 KiB bank",
      constraint: "file_format_rejected",
    });
  }
  // Inspect LoROM (0x7FC0) and HiROM (0xFFC0) if within headerBytes
  const scoreHeader = (offset: number): { score: number; reset: number } => {
    if (headerBytes.length < offset + 0x40) return { score: 0, reset: 0x8000 };
    const complement = headerBytes.readUInt16LE(offset + 0x1c);
    const checksum = headerBytes.readUInt16LE(offset + 0x1e);
    const reset = headerBytes.readUInt16LE(offset + 0x3c);
    let score = 0;
    if ((complement ^ checksum) === 0xffff) score += 4;
    if (reset >= 0x8000) score += 2;
    return { score, reset: reset >= 0x8000 ? reset : 0x8000 };
  };
  const lo = scoreHeader(smcOffset + 0x7fc0);
  const hi = scoreHeader(smcOffset + 0xffc0);
  const isHiRom = hi.score > lo.score;
  const resetVector = isHiRom ? hi.reset : lo.reset;
  const entryPoint = explicitEntry?.canonical ?? hex32(resetVector);
  const firstBankSize = Math.min(romBytes, 0x8000);
  const mappings: ConsoleFileMapping[] = [];
  if (isHiRom) {
    mappings.push({
      name: "BANK00_ROM",
      virtualAddress: "0x8000",
      fileOffset: smcOffset + (romBytes >= 0x10000 ? 0x8000 : 0),
      byteLength: Math.min(
        firstBankSize,
        romBytes - (romBytes >= 0x10000 ? 0x8000 : 0),
      ),
      executable: true,
      writable: false,
    });
    const bankCount = Math.min(64, Math.ceil(romBytes / 0x10000));
    for (let i = 0; i < bankCount; i++) {
      const bankOffset = i * 0x10000;
      const bankSize = Math.min(romBytes - bankOffset, 0x10000);
      if (bankSize <= 0) break;
      mappings.push({
        name: `HIROM_BANK${i.toString(16).toUpperCase().padStart(2, "0")}`,
        virtualAddress: hex32(0xc00000 + bankOffset),
        fileOffset: smcOffset + bankOffset,
        byteLength: bankSize,
        executable: true,
        writable: false,
      });
    }
  } else {
    const bankCount = Math.min(128, Math.ceil(romBytes / 0x8000));
    for (let i = 0; i < bankCount; i++) {
      const bankOffset = i * 0x8000;
      const bankSize = Math.min(romBytes - bankOffset, 0x8000);
      if (bankSize <= 0) break;
      mappings.push({
        name: `BANK${i.toString(16).toUpperCase().padStart(2, "0")}_ROM`,
        // CPU banks $7E/$7F are WRAM; use their ROM mirrors $FE/$FF.
        virtualAddress: hex32((i >= 0x7e ? i + 0x80 : i) * 0x10000 + 0x8000),
        fileOffset: smcOffset + bankOffset,
        byteLength: bankSize,
        executable: true,
        writable: false,
      });
    }
  }
  // Represent aliases once at admission so address lookup and provider imports
  // consume identical mappings, including a final partial bank.
  const canonicalMappings = [...mappings];
  for (const map of canonicalMappings) {
    if (isHiRom) {
      if (!map.name.startsWith("HIROM_BANK")) continue;
      const bank = (Number(BigInt(map.virtualAddress)) - 0xc00000) / 0x10000;
      if (bank < 0x3e) {
        mappings.push({
          ...map,
          name: `MIRROR_HIROM_BANK${bank.toString(16).toUpperCase()}`,
          virtualAddress: hex32((0x40 + bank) * 0x10000),
        });
      }
      const upperLength = map.byteLength - 0x8000;
      if (upperLength <= 0) continue;
      for (const mirrorBank of [bank, bank + 0x80]) {
        if (mirrorBank === 0) continue; // BANK00_ROM already owns this alias.
        mappings.push({
          ...map,
          name: `MIRROR_BANK${mirrorBank.toString(16).toUpperCase()}_ROM`,
          virtualAddress: hex32(mirrorBank * 0x10000 + 0x8000),
          fileOffset: map.fileOffset + 0x8000,
          byteLength: upperLength,
        });
      }
    } else {
      const address = Number(BigInt(map.virtualAddress));
      if (address >= 0x800000) continue; // $FE/$FF are already canonical.
      mappings.push({
        ...map,
        name: `FAST_${map.name}`,
        virtualAddress: hex32(address + 0x800000),
      });
    }
  }
  return ok({
    format: "snes",
    architecture: "65816",
    ghidraLanguageId: "65816:LE:16:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0x8000",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: mappings,
    memoryRegions: [
      {
        name: "LOW_WRAM",
        virtualAddress: "0x0",
        byteLength: 0x2000,
        kind: "ram",
      },
      {
        name: "PPU_APU_IO",
        virtualAddress: "0x2100",
        byteLength: 0x100,
        kind: "mmio",
      },
      {
        name: "CPU_DMA_IO",
        virtualAddress: "0x4200",
        byteLength: 0x200,
        kind: "mmio",
      },
      {
        name: "WRAM_7E",
        virtualAddress: "0x7e0000",
        byteLength: 0x20000,
        kind: "ram",
      },
    ],
    romMetadata: {
      mapping_mode: isHiRom ? "HiROM" : "LoROM",
      copier_header_bytes: smcOffset,
      reset_vector: hex32(resetVector),
      bank_count: isHiRom
        ? Math.min(64, Math.ceil(romBytes / 0x10000))
        : Math.min(128, Math.ceil(romBytes / 0x8000)),
    },
  });
};

const admitNes = (
  headerBytes: Buffer,
  trailerBytes: Buffer | undefined,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const hasInesHeader =
    headerBytes.length >= 16 &&
    headerBytes[0] === 0x4e &&
    headerBytes[1] === 0x45 &&
    headerBytes[2] === 0x53 &&
    headerBytes[3] === 0x1a;
  const trainerBytes =
    hasInesHeader && (headerBytes[6]! & 0x04) !== 0 ? 512 : 0;
  const prgOffset = hasInesHeader ? 16 + trainerBytes : 0;
  const prgUnits = hasInesHeader ? headerBytes[4]! : 0;
  const chrUnits = hasInesHeader ? headerBytes[5]! : 0;
  const mapper = hasInesHeader
    ? (headerBytes[6]! >> 4) | (headerBytes[7]! & 0xf0)
    : 0;
  const availableBytes = fileBytes - prgOffset;
  if (availableBytes < 1) {
    return err({
      reason: "nes ROM contains no PRG-ROM payload bytes after header",
      constraint: "file_format_rejected",
    });
  }
  const prgSize =
    prgUnits > 0 ? Math.min(availableBytes, prgUnits * 16384) : availableBytes;
  // Read reset vector at 0xFFFC in the last PRG bank when available
  let resetVector = 0x8000;
  const lastPrgEnd = prgOffset + prgSize;
  if (lastPrgEnd >= 6 && lastPrgEnd <= headerBytes.length) {
    const candidate = headerBytes.readUInt16LE(lastPrgEnd - 4);
    if (candidate >= 0x8000) resetVector = candidate;
  } else if (trailerBytes !== undefined && trailerBytes.length >= 6) {
    const candidate = trailerBytes.readUInt16LE(trailerBytes.length - 4);
    if (candidate >= 0x8000) resetVector = candidate;
  }
  const entryPoint = explicitEntry?.canonical ?? hex32(resetVector);
  const mappings: ConsoleFileMapping[] =
    prgSize <= 0x4000
      ? [
          {
            name: "PRG_BANK0",
            virtualAddress: "0x8000",
            fileOffset: prgOffset,
            byteLength: prgSize,
            executable: true,
            writable: false,
          },
          ...(prgSize === 0x4000
            ? [
                {
                  name: "PRG_MIRROR",
                  virtualAddress: "0xc000",
                  fileOffset: prgOffset,
                  byteLength: 0x4000,
                  executable: true,
                  writable: false,
                },
              ]
            : []),
        ]
      : [
          {
            name: "PRG_LOW",
            virtualAddress: "0x8000",
            fileOffset: prgOffset,
            byteLength: 0x4000,
            executable: true,
            writable: false,
          },
          {
            name: "PRG_HIGH_FIXED",
            virtualAddress: "0xc000",
            fileOffset: prgOffset + prgSize - 0x4000,
            byteLength: 0x4000,
            executable: true,
            writable: false,
          },
        ];

  return ok({
    format: "nes",
    architecture: "6502",
    ghidraLanguageId: "6502:LE:16:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0x8000",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: mappings,
    memoryRegions: [
      {
        name: "NES_RAM",
        virtualAddress: "0x0",
        byteLength: 0x800,
        kind: "ram",
      },
      {
        name: "PPU_REG",
        virtualAddress: "0x2000",
        byteLength: 0x8,
        kind: "mmio",
      },
      {
        name: "APU_IO_REG",
        virtualAddress: "0x4000",
        byteLength: 0x20,
        kind: "mmio",
      },
      {
        name: "PRG_RAM",
        virtualAddress: "0x6000",
        byteLength: 0x2000,
        kind: "ram",
      },
    ],
    romMetadata: {
      ines_header: hasInesHeader,
      mapper,
      prg_rom_bytes: prgSize,
      chr_rom_bytes: chrUnits * 8192,
      reset_vector: hex32(resetVector),
    },
  });
};

const admitGb = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (fileBytes < 0x150 && explicitEntry === undefined) {
    return err({
      reason:
        "gb ROM requires at least 336 bytes (header through 0x014F) unless entry_point is specified",
      constraint: "file_format_rejected",
    });
  }
  const title =
    headerBytes.length >= 0x144
      ? headerBytes
          .subarray(0x134, 0x144)
          .toString("ascii")
          .replace(/\0+$/u, "")
      : "";
  const entryPoint = explicitEntry?.canonical ?? "0x100";
  const bank0Size = Math.min(fileBytes, 0x4000);
  const bank1Size =
    fileBytes > 0x4000 ? Math.min(fileBytes - 0x4000, 0x4000) : 0;
  return ok({
    format: "gb",
    architecture: "sm83",
    ghidraLanguageId: "SM83:LE:16:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0x0",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? "0x0100",
    fileMappings: [
      {
        name: "ROM_BANK0",
        virtualAddress: "0x0",
        fileOffset: 0,
        byteLength: bank0Size,
        executable: true,
        writable: false,
      },
      ...(bank1Size > 0
        ? [
            {
              name: "ROM_BANK1",
              virtualAddress: "0x4000",
              fileOffset: 0x4000,
              byteLength: bank1Size,
              executable: true,
              writable: false,
            },
          ]
        : []),
    ],
    memoryRegions: [
      {
        name: "GB_VRAM",
        virtualAddress: "0x8000",
        byteLength: 0x2000,
        kind: "vram",
      },
      {
        name: "GB_WRAM",
        virtualAddress: "0xc000",
        byteLength: 0x2000,
        kind: "ram",
      },
      {
        name: "GB_IO_HRAM",
        virtualAddress: "0xff00",
        byteLength: 0x100,
        kind: "mmio",
      },
    ],
    romMetadata: {
      title: title || null,
    },
  });
};

const admitWsc = (
  trailerBytes: Buffer | undefined,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (fileBytes < 16) {
    return err({
      reason: "wsc ROM requires at least 16 bytes for the reset vector trailer",
      constraint: "file_format_rejected",
    });
  }
  const fixedBankSize = Math.min(fileBytes, 0x10000);
  const fixedBankOffset = fileBytes - fixedBankSize;
  const fixedBankVirtualStart = 0x100000 - fixedBankSize;
  let resetLinear = 0xffff0;
  if (
    trailerBytes !== undefined &&
    trailerBytes.length >= 16 &&
    trailerBytes[trailerBytes.length - 16] === 0xea
  ) {
    const ip = trailerBytes.readUInt16LE(trailerBytes.length - 15);
    const cs = trailerBytes.readUInt16LE(trailerBytes.length - 13);
    const targetLinear = ((cs << 4) + ip) & 0xfffff;
    if (targetLinear >= fixedBankVirtualStart && targetLinear <= 0xfffff) {
      resetLinear = targetLinear;
    }
  }
  const entryPoint = explicitEntry?.canonical ?? hex32(resetLinear);
  return ok({
    format: "wsc",
    architecture: "x86",
    ghidraLanguageId: "x86:LE:16:Real Mode",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: hex32(fixedBankVirtualStart),
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: [
      {
        name: "WSC_FIXED_ROM",
        virtualAddress: hex32(fixedBankVirtualStart),
        fileOffset: fixedBankOffset,
        byteLength: fixedBankSize,
        executable: true,
        writable: false,
      },
    ],
    memoryRegions: [
      {
        name: "WSC_RAM",
        virtualAddress: "0x0",
        byteLength: 0x10000,
        kind: "ram",
      },
    ],
    romMetadata: {
      reset_linear: hex32(resetLinear),
      fixed_bank_offset: fixedBankOffset,
    },
  });
};

const admitN64 = (
  headerBytes: Buffer,
  fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  if (headerBytes.length < 0x40 || fileBytes <= 0x1000) {
    return err({
      reason:
        "n64 ROM requires a 64-byte cartridge header, the 0x1000-byte IPL3 area, and at least one boot image byte",
      constraint: "file_format_rejected",
    });
  }
  const byteOrder = detectN64ByteOrder(headerBytes);
  if (byteOrder === undefined) {
    return err({
      reason:
        "n64 ROM does not start with the 0x80371240 cartridge signature in big-endian, 16-bit byteswapped, or little-endian order",
      constraint: "file_format_rejected",
    });
  }
  const header =
    byteOrder.swap === undefined
      ? headerBytes
      : unswapN64Bytes(headerBytes.subarray(0, 0x40), byteOrder.swap);
  // IPL3 DMAs the boot image from ROM offset 0x1000 to the header boot
  // address; the static image keeps that alignment so file offset 0x1000
  // sits exactly at the boot address.
  const bootAddress = header.readUInt32BE(0x08);
  if (bootAddress === 0 || bootAddress % 4 !== 0 || bootAddress < 0x1000) {
    return err({
      reason: `n64 header boot address ${hex32(bootAddress)} is not a word-aligned address IPL3 can load the boot image to`,
      constraint: "file_format_rejected",
    });
  }
  const loadBase = bootAddress - 0x1000;
  if (loadBase + fileBytes > 0x100000000) {
    return err({
      reason:
        "n64 ROM mapped at its header boot address exceeds the 32-bit address space",
      constraint: "file_format_rejected",
    });
  }
  const title = header
    .subarray(0x20, 0x34)
    .toString("ascii")
    .replace(/[\0 ]+$/u, "");
  const gameCode = header
    .subarray(0x3b, 0x3f)
    .toString("ascii")
    .replace(/\0+$/u, "");
  const entryPoint = explicitEntry?.canonical ?? hex32(bootAddress);
  return ok({
    format: "n64",
    architecture: "r4300",
    ghidraLanguageId: "MIPS:BE:32:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: hex32(loadBase),
    entryPoint,
    entryPointSource: explicitEntry?.source ?? hex32(bootAddress),
    fileMappings: [
      {
        name: "ROM",
        virtualAddress: hex32(loadBase),
        fileOffset: 0,
        byteLength: fileBytes,
        executable: true,
        writable: false,
      },
    ],
    memoryRegions: [
      {
        name: "SP_DMEM",
        virtualAddress: "0xa4000000",
        byteLength: 0x1000,
        kind: "scratchpad",
      },
      {
        name: "SP_IMEM",
        virtualAddress: "0xa4001000",
        byteLength: 0x1000,
        kind: "scratchpad",
      },
      {
        name: "RCP_IO",
        virtualAddress: "0xa4040000",
        byteLength: 0x8c0000,
        kind: "mmio",
      },
    ],
    romMetadata: {
      game_title: title,
      game_code: gameCode,
      rom_version: header[0x3f]!,
      clock_rate: header.readUInt32BE(0x04),
      boot_address: hex32(bootAddress),
      byte_order: byteOrder.order,
    },
    ...(byteOrder.swap === undefined ? {} : { fileByteSwap: byteOrder.swap }),
  });
};

interface ParsedMappingInterval {
  readonly start: bigint;
  readonly end: bigint;
  readonly fileOffset: number;
}

interface ParsedMappingIntervals {
  /** Declaration order; first match wins when mappings overlap. */
  readonly intervals: readonly ParsedMappingInterval[];
  /** Start-sorted intervals when pairwise non-overlapping, else null. */
  readonly sortedNonOverlapping: readonly ParsedMappingInterval[] | null;
}

const mappingIntervalCache = new WeakMap<
  ConsoleTargetAdmission,
  ParsedMappingIntervals
>();

const parsedMappingIntervals = (
  admission: ConsoleTargetAdmission,
): ParsedMappingIntervals => {
  const cached = mappingIntervalCache.get(admission);
  if (cached !== undefined) return cached;
  const intervals = admission.fileMappings.map((map) => {
    const start = BigInt(map.virtualAddress);
    return {
      start,
      end: start + BigInt(map.byteLength),
      fileOffset: map.fileOffset,
    };
  });
  const sorted = [...intervals].sort((a, b) =>
    a.start < b.start ? -1 : a.start > b.start ? 1 : 0,
  );
  let nonOverlapping = true;
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i]!.start < sorted[i - 1]!.end) {
      nonOverlapping = false;
      break;
    }
  }
  const parsed: ParsedMappingIntervals = {
    intervals,
    sortedNonOverlapping: nonOverlapping ? sorted : null,
  };
  mappingIntervalCache.set(admission, parsed);
  return parsed;
};

/**
 * Resolve a console virtual address to a file offset using the admitted fileMappings
 * plus bank-window and FastROM mirror rules for SNES/GB/NES/WSC.
 */
export const resolveConsoleFileOffset = (
  admission: ConsoleTargetAdmission,
  virtualAddress: bigint | number,
  options?: {
    readonly tableFileOffset?: number | undefined;
    readonly fileBytes?: number | undefined;
  },
): number | null => {
  const vaddr = BigInt(virtualAddress);
  if (vaddr < 0n) return null;
  const tableFileOffset = options?.tableFileOffset;
  const maxFileBytes = options?.fileBytes;

  // 1. Bank-local 16-bit pointer resolution when a tableFileOffset is in a known bank
  if (tableFileOffset !== undefined && tableFileOffset >= 0) {
    if (
      admission.format === "gb" &&
      vaddr >= 0x4000n &&
      vaddr < 0x8000n &&
      tableFileOffset >= 0x4000
    ) {
      const bankBase = Math.floor(tableFileOffset / 0x4000) * 0x4000;
      const resolved = bankBase + Number(vaddr - 0x4000n);
      if (maxFileBytes === undefined || resolved < maxFileBytes) {
        return resolved;
      }
    }
    if (admission.format === "snes" && vaddr >= 0x8000n && vaddr <= 0xffffn) {
      const smcOffset = Number(admission.romMetadata.copier_header_bytes ?? 0);
      if (tableFileOffset >= smcOffset) {
        const isHiRom = admission.romMetadata.mapping_mode === "HiROM";
        const bankSize = isHiRom ? 0x10000 : 0x8000;
        const bankIndex = Math.floor((tableFileOffset - smcOffset) / bankSize);
        const offsetWithinBank = isHiRom
          ? Number(vaddr)
          : Number(vaddr - 0x8000n);
        const resolved = smcOffset + bankIndex * bankSize + offsetWithinBank;
        if (maxFileBytes === undefined || resolved < maxFileBytes) {
          return resolved;
        }
      }
    }
    if (admission.format === "nes" && vaddr >= 0x8000n && vaddr < 0xc000n) {
      const prgOffset = admission.fileMappings[0]?.fileOffset ?? 16;
      const prgSize = Number(admission.romMetadata.prg_rom_bytes ?? 0);
      if (prgSize > 0x4000 && tableFileOffset >= prgOffset) {
        const bankIndex = Math.floor((tableFileOffset - prgOffset) / 0x4000);
        const resolved =
          prgOffset + bankIndex * 0x4000 + Number(vaddr - 0x8000n);
        if (
          resolved < prgOffset + prgSize &&
          (maxFileBytes === undefined || resolved < maxFileBytes)
        ) {
          return resolved;
        }
      }
    }
  }

  // 2. Direct lookup across admitted fileMappings (parsed once per admission)
  const findInMappings = (candidate: bigint): number | null => {
    const { intervals, sortedNonOverlapping } =
      parsedMappingIntervals(admission);
    if (sortedNonOverlapping !== null) {
      let lo = 0;
      let hi = sortedNonOverlapping.length - 1;
      let found: ParsedMappingInterval | undefined;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const interval = sortedNonOverlapping[mid]!;
        if (interval.start <= candidate) {
          found = interval;
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }
      return found !== undefined && candidate < found.end
        ? found.fileOffset + Number(candidate - found.start)
        : null;
    }
    for (const interval of intervals) {
      if (candidate >= interval.start && candidate < interval.end) {
        return interval.fileOffset + Number(candidate - interval.start);
      }
    }
    return null;
  };

  const direct = findInMappings(vaddr);
  if (direct !== null) return direct;

  return null;
};

/**
 * Resolve a file offset in a console ROM/executable to its canonical virtual address.
 */
export const resolveConsoleVirtualAddress = (
  admission: ConsoleTargetAdmission,
  fileOffset: number,
): string | null => {
  if (!Number.isSafeInteger(fileOffset) || fileOffset < 0) return null;

  // For SNES HiROM, prefer the full 24-bit HIROM_BANKxx mapping over the 16-bit BANK00_ROM mirror
  if (
    admission.format === "snes" &&
    admission.romMetadata.mapping_mode === "HiROM"
  ) {
    for (const map of admission.fileMappings) {
      if (!map.name.startsWith("HIROM_BANK")) continue;
      if (
        fileOffset >= map.fileOffset &&
        fileOffset < map.fileOffset + map.byteLength
      ) {
        return hex32(
          BigInt(map.virtualAddress) + BigInt(fileOffset - map.fileOffset),
        );
      }
    }
  }

  for (const map of admission.fileMappings) {
    if (
      fileOffset >= map.fileOffset &&
      fileOffset < map.fileOffset + map.byteLength
    ) {
      return hex32(
        BigInt(map.virtualAddress) + BigInt(fileOffset - map.fileOffset),
      );
    }
  }

  // Bank-window fallback for 16-bit banked ROMs whose upper banks share a switchable window
  if (admission.format === "gb" && fileOffset >= 0x4000) {
    return hex32(0x4000 + (fileOffset % 0x4000));
  }
  if (admission.format === "nes") {
    const prgOffset = admission.fileMappings[0]?.fileOffset ?? 16;
    const prgSize = Number(admission.romMetadata.prg_rom_bytes ?? 0);
    if (fileOffset >= prgOffset && fileOffset < prgOffset + prgSize) {
      return hex32(0x8000 + ((fileOffset - prgOffset) % 0x4000));
    }
  }
  if (admission.format === "wsc") {
    return hex32(0x20000 + (fileOffset % 0x10000));
  }

  return null;
};

/**
 * Serialize console target mappings and regions into the TSV spec consumed by
 * ReaGhidraPrepareConsole.java. This is the Ghidra analysis-scope projection:
 * for banked ROMs with many file mappings (SNES), only the entry bank is
 * marked executable so function-start search does not scan every bank;
 * entry-flow disassembly still reaches referenced code in other banks.
 * The admission's own executable facts are unchanged.
 */
export const formatConsoleTargetSpecTsv = (
  admission: ConsoleTargetAdmission,
): string => {
  const lines: string[] = [
    `meta\t${admission.format}\t${admission.ghidraLanguageId}\t${admission.entryPoint}\t${admission.loader}`,
  ];
  if (admission.fileByteSwap !== undefined) {
    lines.push(`swap\t${admission.fileByteSwap}`);
  }
  const entry = (() => {
    try {
      return BigInt(admission.entryPoint);
    } catch {
      return null;
    }
  })();
  const { intervals } = parsedMappingIntervals(admission);
  const entryMapped =
    entry !== null &&
    intervals.some(
      (interval) => entry >= interval.start && entry < interval.end,
    );
  const scopeToEntryBank = admission.fileMappings.length > 8 && entryMapped;
  for (let i = 0; i < admission.fileMappings.length; i++) {
    const map = admission.fileMappings[i]!;
    const interval = intervals[i]!;
    const containsEntry =
      entry !== null && entry >= interval.start && entry < interval.end;
    const executable = map.executable && (!scopeToEntryBank || containsEntry);
    const rwx = `r${map.writable ? "w" : "-"}${executable ? "x" : "-"}`;
    lines.push(
      `map\t${map.name}\t${map.virtualAddress}\t${map.fileOffset}\t${map.byteLength}\t${rwx}`,
    );
  }
  for (const region of admission.memoryRegions) {
    const executable = region.kind === "ram" || region.kind === "scratchpad";
    const rwx = `rw${executable ? "x" : "-"}`;
    lines.push(
      `mem\t${region.name}\t${region.virtualAddress}\t${region.byteLength}\t${rwx}`,
    );
  }
  return `${lines.join("\n")}\n`;
};
