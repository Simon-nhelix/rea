import {
  dosLinearFileOffset,
  dosLinearMappedRuns,
  dosLinearRelocatedFileBytes,
  locateDosLinearHeader,
  parseDosLinearExecutable,
} from "../../domain/dosLinearExecutable.js";
import {
  dosRealModeEntryDataSegment,
  dosRealModeRelocatedFileBytes,
  parseDosRealModeImage,
} from "../../domain/dosRealModeImage.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { LoadAddressSource } from "../../domain/romCodeReferences.js";

/** Data segment used for x86-16 near operands, and where it came from. */
export interface DosDataSegment {
  readonly segment: number;
  readonly source: "caller" | "entry-code" | "com-psp";
  readonly address: number | null;
}

/** One scan region of a DOS program, in the loaded (relocated) bytes. */
export interface DosRegion {
  readonly loadAddress: number;
  readonly loadAddressSource: LoadAddressSource;
  readonly fileOffset: number;
  readonly length: number;
  readonly notes: readonly string[];
  readonly executable: boolean;
  readonly pointerSites: readonly number[] | undefined;
  readonly dataSegment: DosDataSegment | undefined;
}

export interface DosRegions {
  /** The file as DOS loads it: same offsets, relocations written. */
  readonly scanBytes: Uint8Array;
  readonly regions: readonly DosRegion[];
}

const hex = (value: number): string => `0x${value.toString(16)}`;

const isMz = (bytes: Uint8Array): boolean =>
  bytes.length >= 2 &&
  ((bytes[0] === 0x4d && bytes[1] === 0x5a) ||
    (bytes[0] === 0x5a && bytes[1] === 0x4d));

/** Regions of a DOS extender LE/LX program for the x86-32 scan. */
const linearRegions = (
  path: string,
  bytes: Uint8Array,
): Result<DosRegions, string> => {
  const parsed = parseDosLinearExecutable(Buffer.from(bytes));
  if (!parsed.ok)
    return err(
      `${path}: ${parsed.error}; give its load address as files[].load_address to scan it as raw bytes.`,
    );
  const module = parsed.value;
  // Only 32-bit offset fixups name a flat address in four contiguous bytes.
  const sites = module.fixups
    .filter(
      (fixup) =>
        fixup.source === "offset32" &&
        fixup.sourceFileOffset !== null &&
        dosLinearFileOffset(module, fixup.sourceAddress + 3) ===
          fixup.sourceFileOffset + 3,
    )
    .map((fixup) => fixup.sourceFileOffset!)
    .sort((a, b) => a - b);
  const skipped = Object.values(module.skippedFixups).reduce(
    (sum, count) => sum + count,
    0,
  );
  const runs = dosLinearMappedRuns(module);
  return ok({
    scanBytes: dosLinearRelocatedFileBytes(Buffer.from(bytes), module),
    regions: runs.map((run) => ({
      loadAddress: run.virtualAddress,
      loadAddressSource: "dos-le-header" as const,
      fileOffset: run.fileOffset,
      length: run.byteLength,
      executable: run.executable,
      pointerSites: sites.filter(
        (site) =>
          site >= run.fileOffset && site + 4 <= run.fileOffset + run.byteLength,
      ),
      dataSegment: undefined,
      notes: [
        `${path}: ${module.signature} object ${run.object} scanned at its relocation base with ${module.fixups.length} internal fixups applied${run.executable ? "" : "; data object, so only fixup pointer words are reported"}.`,
        ...(skipped > 0
          ? [
              `${path}: ${skipped} import or unsupported fixups were not applied; their sites keep file bytes.`,
            ]
          : []),
      ],
    })),
  });
};

const parseSegment = (text: string): number =>
  Number.parseInt(text.replace(/^0[xX]/u, ""), 16);

/** Regions of a DOS MZ or COM program for the x86-16 scan. */
const realModeRegions = (
  path: string,
  bytes: Uint8Array,
  dataSegment: string | undefined,
): Result<DosRegions, string> => {
  if (locateDosLinearHeader(Buffer.from(bytes)).ok)
    return err(
      `${path} is a DOS extender LE/LX program; scan it with architecture x86-32.`,
    );
  const format = isMz(bytes)
    ? "dos-mz"
    : path.toLowerCase().endsWith(".com")
      ? "dos-com"
      : undefined;
  if (format === undefined)
    return err(
      `${path} has no MZ header and is not a .com file; give its load address as files[].load_address (CLI: --file ${path}:0x10000).`,
    );
  const parsed = parseDosRealModeImage(format, Buffer.from(bytes));
  if (!parsed.ok) return err(`${path}: ${parsed.error}`);
  const image = parsed.value;
  const scanBytes = dosRealModeRelocatedFileBytes(bytes, image);
  const found =
    dataSegment === undefined
      ? dosRealModeEntryDataSegment(scanBytes, image)
      : undefined;
  const segment: DosDataSegment | undefined =
    dataSegment !== undefined
      ? { segment: parseSegment(dataSegment), source: "caller", address: null }
      : found === undefined
        ? undefined
        : {
            segment: found.segment,
            source: format === "dos-com" ? "com-psp" : "entry-code",
            address: format === "dos-com" ? null : found.linearAddress,
          };
  return ok({
    scanBytes,
    regions: [
      {
        loadAddress: image.moduleLinearAddress,
        loadAddressSource: format === "dos-mz" ? "dos-mz-header" : "dos-com",
        fileOffset: image.moduleFileOffset,
        length: image.moduleBytes,
        executable: true,
        // A relocated far pointer is offset:segment with the segment word at the site.
        pointerSites: image.relocations
          .map((relocation) => relocation.fileOffset - 2)
          .filter((site) => site >= image.moduleFileOffset),
        dataSegment: segment,
        notes: [
          `${path}: ${format === "dos-mz" ? "MZ load module" : "COM image"} scanned at linear ${hex(image.moduleLinearAddress)} (load segment ${hex(image.loadSegment)}) with ${image.relocations.length} segment relocations applied${image.overlayBytes > 0 ? `; ${image.overlayBytes} overlay bytes after the module are not scanned` : ""}.`,
          segment === undefined
            ? `${path}: no startup mov ds was found, so near data operands were skipped; pass data_segment to scan them.`
            : `${path}: near data operands use DS ${hex(segment.segment)} (linear base ${hex(segment.segment * 16)}, ${segment.source}); code that changes DS or uses ES/SS data is not tracked.`,
        ],
      },
    ],
  });
};

/** Locate x86 scan regions from a DOS header, using the loaded bytes. */
export const locateDosRegions = (
  path: string,
  bytes: Uint8Array,
  architecture: "x86-16" | "x86-32",
  dataSegment: string | undefined,
): Result<DosRegions, string> =>
  architecture === "x86-32"
    ? linearRegions(path, bytes)
    : realModeRegions(path, bytes, dataSegment);

/** Data segment for a caller-addressed x86-16 file: only the caller's value. */
export const callerDataSegment = (
  dataSegment: string | undefined,
): DosDataSegment | undefined =>
  dataSegment === undefined
    ? undefined
    : { segment: parseSegment(dataSegment), source: "caller", address: null };
