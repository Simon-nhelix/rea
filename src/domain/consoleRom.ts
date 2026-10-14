import { z } from "zod";
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
  "dc-bin",
  "gc-dol",
  "snes",
  "nes",
  "gb",
  "wsc",
] as const;

export type ConsoleTargetFormat = (typeof CONSOLE_TARGET_FORMATS)[number];

export const consoleTargetFormatSchema = z.enum(CONSOLE_TARGET_FORMATS);

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
  | "sh4"
  | "gekko"
  | "65816"
  | "6502"
  | "sm83"
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
}

const GBA_LOGO_PREFIX = Buffer.from([
  0x24, 0xff, 0xae, 0x51, 0x69, 0x9a, 0xa2, 0x21, 0x3d, 0x84, 0x82, 0x0a, 0x84,
  0xe4, 0x09, 0xad,
]);

const GB_LOGO_PREFIX = Buffer.from([
  0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00, 0x83, 0x00,
  0x0c, 0x00, 0x0d,
]);

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

  // 3. PS2 Emotion Engine ELF32 (LE MIPS with EF_MIPS_MACH_5900 = 0x00920000)
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
    const flags = bytes.readUInt32LE(36);
    if ((flags & 0x00ff0000) === 0x00920000) {
      return "ps2-elf";
    }
  }

  // 4. GBA ROM (Nintendo logo at 0x04..0x13 and fixed 0x96 at 0xB2)
  if (
    bytes.length >= 0xc0 &&
    bytes[0xb2] === 0x96 &&
    bytes.subarray(0x04, 0x14).equals(GBA_LOGO_PREFIX)
  ) {
    return "gba";
  }

  // 5. Game Boy / Game Boy Color ROM (Nintendo logo at 0x104..0x113)
  if (
    bytes.length >= 0x150 &&
    bytes.subarray(0x104, 0x114).equals(GB_LOGO_PREFIX)
  ) {
    return "gb";
  }

  // 6. GameCube DOL (valid section table with entry in 0x80000000..0x817fffff)
  if (
    (lowerPath.endsWith(".dol") || bytes.length >= 0x100) &&
    isValidGameCubeDolHeader(bytes, fileSize, lowerPath.endsWith(".dol"))
  ) {
    return "gc-dol";
  }

  // 7. SNES / Super Famicom (.sfc / .smc with valid LoROM or HiROM checksum complement)
  if (lowerPath.endsWith(".sfc") || lowerPath.endsWith(".smc")) {
    return "snes";
  }

  // 8. WonderSwan / WonderSwan Color (.ws / .wsc)
  if (lowerPath.endsWith(".ws") || lowerPath.endsWith(".wsc")) {
    return "wsc";
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
  readonly trailerBytes?: Buffer | undefined;
  readonly fileBytes: number;
  readonly entryPoint?: unknown;
}): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
  const { format, headerBytes, trailerBytes, fileBytes } = input;
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
    case "dc-bin":
      return admitDcBin(fileBytes, explicitEntry);
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
  const pc0 = hasPsxMagic ? headerBytes.readUInt32LE(0x10) : 0x80010000;
  const gp0 = hasPsxMagic ? headerBytes.readUInt32LE(0x14) : 0;
  const tAddr = hasPsxMagic ? headerBytes.readUInt32LE(0x18) : 0x80010000;
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
      pc0: hex32(pc0),
      gp0: hex32(gp0),
      t_addr: hex32(tAddr),
      t_size: tSize,
    },
  });
};

const admitPs2Elf = (
  headerBytes: Buffer,
  _fileBytes: number,
  explicitEntry?: { canonical: string; source: string },
): Result<ConsoleTargetAdmission, RawBinaryAdmissionRejection> => {
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
  const entryPoint =
    explicitEntry?.canonical ?? (entry !== 0 ? hex32(entry) : "0x100000");
  return ok({
    format: "ps2-elf",
    architecture: "r5900",
    ghidraLanguageId: "MIPS:LE:64:64-32addr",
    compilerSpecId: "default",
    loader: "ElfLoader",
    loadBase: "0x100000",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: [],
    memoryRegions: [
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
    ],
    romMetadata: {
      elf_entry: hex32(entry),
      elf_flags: hex32(flags),
      emotion_engine: (flags & 0x00ff0000) === 0x00920000,
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
  return ok({
    format: "snes",
    architecture: "65816",
    ghidraLanguageId: "65816:LE:16:default",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0x8000",
    entryPoint,
    entryPointSource: explicitEntry?.source ?? entryPoint,
    fileMappings: [
      {
        name: "BANK00_ROM",
        virtualAddress: "0x8000",
        fileOffset: smcOffset + (isHiRom && romBytes >= 0x10000 ? 0x8000 : 0),
        byteLength: firstBankSize,
        executable: true,
        writable: false,
      },
    ],
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
    ],
    romMetadata: {
      mapping_mode: isHiRom ? "HiROM" : "LoROM",
      copier_header_bytes: smcOffset,
      reset_vector: hex32(resetVector),
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
  } else if (
    trailerBytes !== undefined &&
    trailerBytes.length >= 6 &&
    lastPrgEnd === fileBytes
  ) {
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
    ghidraLanguageId: "z80:LE:16:default",
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

/** Serialize console target mappings and regions into the TSV spec consumed by ReaGhidraPrepareConsole.java. */
export const formatConsoleTargetSpecTsv = (
  admission: ConsoleTargetAdmission,
): string => {
  const lines: string[] = [
    `meta\t${admission.format}\t${admission.ghidraLanguageId}\t${admission.entryPoint}\t${admission.loader}`,
  ];
  for (const map of admission.fileMappings) {
    const rwx = `r${map.writable ? "w" : "-"}${map.executable ? "x" : "-"}`;
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
