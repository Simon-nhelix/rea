import { parseDosMzHeader } from "./dosMz.js";
import { validateDosComLength } from "./dosCom.js";
import { err, ok, type Result } from "./result.js";

/**
 * Paragraph at which REA places a DOS program's first loaded byte. It matches
 * Ghidra's MZ loader default, so local scans and Ghidra report the same linear
 * addresses: linear = segment * 16 + offset.
 */
export const DOS_REAL_MODE_LOAD_SEGMENT = 0x1000;

/** DOS COM programs start after the 256-byte program segment prefix. */
const DOS_COM_PSP_BYTES = 0x100;

/** One MZ segment relocation: the file word the loader adds the load segment to. */
export interface DosRealModeRelocation {
  readonly fileOffset: number;
  readonly linearAddress: number;
}

/** Real-mode coordinates of a DOS MZ load module or COM image. */
export interface DosRealModeImage {
  readonly format: "dos-mz" | "dos-com";
  readonly loadSegment: number;
  /** File offset of the first loaded byte (after the MZ header). */
  readonly moduleFileOffset: number;
  readonly moduleBytes: number;
  /** Linear address of the first loaded byte. */
  readonly moduleLinearAddress: number;
  readonly entry: {
    readonly segment: number;
    readonly offset: number;
    readonly linearAddress: number;
  };
  readonly relocations: readonly DosRealModeRelocation[];
  readonly overlayBytes: number;
}

/** Parse the loaded coordinates of a DOS MZ or COM file. */
export const parseDosRealModeImage = (
  format: "dos-mz" | "dos-com",
  bytes: Buffer,
): Result<DosRealModeImage, string> => {
  const loadSegment = DOS_REAL_MODE_LOAD_SEGMENT;
  if (format === "dos-com") {
    const length = validateDosComLength(bytes.length);
    if (!length.ok) return length;
    const linear = loadSegment * 16 + DOS_COM_PSP_BYTES;
    return ok({
      format,
      loadSegment,
      moduleFileOffset: 0,
      moduleBytes: bytes.length,
      moduleLinearAddress: linear,
      entry: {
        segment: loadSegment,
        offset: DOS_COM_PSP_BYTES,
        linearAddress: linear,
      },
      relocations: [],
      overlayBytes: 0,
    });
  }
  const parsed = parseDosMzHeader(bytes);
  if (!parsed.ok) return parsed;
  const header = parsed.value;
  const relocations: DosRealModeRelocation[] = [];
  for (let index = 0; index < header.relocationCount; index++) {
    const table = header.relocationTableOffset + index * 4;
    const offset = bytes.readUInt16LE(table);
    const segment = bytes.readUInt16LE(table + 2);
    const relative = segment * 16 + offset;
    relocations.push({
      fileOffset: header.headerBytes + relative,
      linearAddress: loadSegment * 16 + relative,
    });
  }
  const entrySegment = (loadSegment + header.entrySegment) & 0xffff;
  return ok({
    format,
    loadSegment,
    moduleFileOffset: header.headerBytes,
    moduleBytes: header.moduleBytes,
    moduleLinearAddress: loadSegment * 16,
    entry: {
      segment: entrySegment,
      offset: header.entryOffset,
      linearAddress: entrySegment * 16 + header.entryOffset,
    },
    relocations,
    overlayBytes: header.overlayBytes,
  });
};

/** File offset of a linear address inside the loaded module, if any. */
export const dosRealModeFileOffset = (
  image: DosRealModeImage,
  linearAddress: number,
): number | null => {
  const relative = linearAddress - image.moduleLinearAddress;
  return Number.isSafeInteger(relative) &&
    relative >= 0 &&
    relative < image.moduleBytes
    ? image.moduleFileOffset + relative
    : null;
};

/** Linear address of a file offset; the MZ header and overlays have none. */
export const dosRealModeLinearAddress = (
  image: DosRealModeImage,
  fileOffset: number,
): number | null => {
  const relative = fileOffset - image.moduleFileOffset;
  return relative >= 0 && relative < image.moduleBytes
    ? image.moduleLinearAddress + relative
    : null;
};

/** Linear address of a little-endian offset:segment far pointer. */
export const dosFarPointerLinearAddress = (value: number): number =>
  (value >>> 16) * 16 + (value & 0xffff);

/**
 * The file bytes as DOS loads them: each relocated segment word holds the
 * load segment added, so far pointers and segment loads read as real-mode
 * addresses. File offsets are unchanged.
 */
export const dosRealModeRelocatedFileBytes = (
  bytes: Uint8Array,
  image: DosRealModeImage,
): Buffer => {
  const relocated = Buffer.from(bytes);
  for (const relocation of image.relocations) {
    if (relocation.fileOffset + 2 > relocated.length) continue;
    relocated.writeUInt16LE(
      (relocated.readUInt16LE(relocation.fileOffset) + image.loadSegment) &
        0xffff,
      relocation.fileOffset,
    );
  }
  return relocated;
};

/** Data segment that a program's startup code loads into DS. */
export interface DosRealModeDataSegment {
  readonly segment: number;
  /** Linear address of the `mov r16, imm16` that supplies the value. */
  readonly linearAddress: number;
}

/** How far after the entry point the startup `mov ds, r16` is searched. */
const DATA_SEGMENT_SEARCH_BYTES = 0x100;
/** How far before `mov ds, r16` the matching `mov r16, imm16` is searched. */
const DATA_SEGMENT_SOURCE_BYTES = 0x20;

/**
 * Find the startup data segment: the first `mov ds, r16` (8E D8+r) after the
 * entry point whose register was set by a nearby `mov r16, imm16` (B8+r).
 * `loaded` must be the relocated bytes so the immediate is a loaded segment.
 * This is a byte pattern heuristic, not an emulation of the startup code.
 */
export const dosRealModeEntryDataSegment = (
  loaded: Uint8Array,
  image: DosRealModeImage,
): DosRealModeDataSegment | undefined => {
  if (image.format === "dos-com")
    return {
      segment: image.loadSegment,
      linearAddress: image.entry.linearAddress,
    };
  const entry = dosRealModeFileOffset(image, image.entry.linearAddress);
  if (entry === null) return undefined;
  const moduleEnd = image.moduleFileOffset + image.moduleBytes;
  const end = Math.min(moduleEnd - 1, entry + DATA_SEGMENT_SEARCH_BYTES);
  for (let at = entry; at < end; at++) {
    const modrm = loaded[at + 1] ?? 0;
    if (loaded[at] !== 0x8e || (modrm & 0xf8) !== 0xd8) continue;
    const register = modrm & 7;
    const first = Math.max(entry, at - DATA_SEGMENT_SOURCE_BYTES);
    for (let source = at - 3; source >= first; source--) {
      if (loaded[source] !== 0xb8 + register) continue;
      const linearAddress = dosRealModeLinearAddress(image, source);
      if (linearAddress === null) continue;
      return {
        segment: (loaded[source + 1] ?? 0) | ((loaded[source + 2] ?? 0) << 8),
        linearAddress,
      };
    }
  }
  return undefined;
};
