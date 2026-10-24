import { compositeKey } from "../../domain/unicodeCodePointOrder.js";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type {
  AnalysisOperation,
  AnalysisOperationPort,
} from "../AnalysisProvider.js";
import type { EnhancedResult } from "../EnhancedToolTypes.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  isConsoleBinaryTarget,
  type BinaryTarget,
} from "../../domain/binaryTargetTypes.js";
import {
  resolveConsoleFileOffset,
  resolveConsoleVirtualAddress,
  unswapN64Bytes,
} from "../../domain/consoleRom.js";
import {
  computePointerSlotBudgets,
  decodeRomStringFromBytes,
  decodeRomStringWithControlCodes,
  type RomTextWithControlCodes,
  encodeRomQueryString,
  extractRomStringsFromBuffer,
  findCodeCavesInSliceTopK,
  findOrphanStringsInPointerGaps,
  formatHexPattern,
  formatRomScanCursor,
  inferOverlayLoadAddress,
  isWordRomTextEncoding,
  normalizeRomTextEncoding,
  parseCustomCharTable,
  parseRomScanCursor,
  readPointerValue,
  requiresRomCharTable,
  resolveRomWordFormat,
  scanRomStrings,
  type CustomCharTable,
  type DiscoverPointerTablesInput,
  type FindCodeCavesInput,
  type InferredBaseCandidate,
  type ManuscriptRecord,
  type RomScanResume,
  type RomStringScanInput,
  type RomTextEncoding,
  type RomWordFormat,
  type ScannedRomString,
  type ScanPointerTableInput,
  type SearchRomStringsInput,
} from "../../domain/romHacking.js";
import {
  parseRomControlCodes,
  type RomControlCodeInput,
  type RomControlCodeTable,
} from "../../domain/romControlCodes.js";
import type { RomTextFilters } from "../../domain/romTextQuality.js";
import {
  isTerminatorAt,
  markSentenceStarts,
  measurePointerTableCoverage,
  readPointerNumber,
  type PointerBase,
  type PointerTableCoverage,
  type RomTerminatorUnit,
} from "../../domain/romPointerSegments.js";
import {
  isLocalByteSource,
  locateLocalByteOffset,
  type LocalByteSource,
  type RomByteSourceDescription,
} from "./LocalByteSource.js";
import { jsonValueSchema, type JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";

const readBytesResponseSchema = z.object({
  address: z.string(),
  bytes_hex: z.string(),
  returned_bytes: z.number().int().min(0),
  complete: z.boolean(),
});

const searchBytesResponseSchema = z.object({
  matches: z.array(
    z.object({
      address: z.string(),
    }),
  ),
  complete: z.boolean(),
  next_cursor: z.string().nullable().optional(),
});

const fileOffsetResponseSchema = z.object({
  file_offset: z.number().int().min(0),
});

interface LocalRomContext {
  readonly romBytes: Buffer;
  readonly toFileOffset: (
    virtualAddress: bigint,
    tableFileOffset?: number,
  ) => number | null;
  readonly toVirtualAddress: (fileOffset: number) => string | null;
  /** Mapping-owned conversion of file-offset aliases; banked CPU aliases stay intact. */
  readonly normalizePointerAddress?: (
    address: bigint,
    fileOffset: number,
  ) => string;
  /** How a plain local byte source was read; absent for admitted targets. */
  readonly source?: RomByteSourceDescription;
  /** Sector coordinates for byte sources that have sectors. */
  readonly locate?: (
    fileOffset: number,
  ) => ReturnType<typeof locateLocalByteOffset>;
}

/** A parsed target, or a local file read as plain bytes. */
export type RomToolTarget = BinaryTarget | LocalByteSource;

const ROM_BYTES_CACHE_LIMIT = 4;
const romBytesCache = new Map<string, Buffer>();

/** ROM bytes keyed by the resolved target identity (path + content digest). */
const readRomBytesCached = async (
  target: BinaryTarget & { readonly path: string; readonly sha256: string },
): Promise<Buffer | undefined> => {
  const key = compositeKey([target.path, target.sha256]);
  const cached = romBytesCache.get(key);
  if (cached !== undefined) {
    // Refresh LRU order.
    romBytesCache.delete(key);
    romBytesCache.set(key, cached);
    return cached;
  }
  let romBytes: Buffer;
  try {
    romBytes = await readFile(target.path);
  } catch {
    return undefined;
  }
  // Undo the byte permutation the console admission declared (byteswapped
  // or little-endian dumps) so scans decode native bytes; the cache key
  // still identifies the original file.
  if (
    isConsoleBinaryTarget(target) &&
    target.consoleRom.fileByteSwap !== undefined
  ) {
    romBytes = unswapN64Bytes(romBytes, target.consoleRom.fileByteSwap);
  }
  romBytesCache.set(key, romBytes);
  while (romBytesCache.size > ROM_BYTES_CACHE_LIMIT) {
    const oldest = romBytesCache.keys().next().value;
    if (oldest === undefined) break;
    romBytesCache.delete(oldest);
  }
  return romBytes;
};

const localFileMapping = (
  length: number,
  loadAddress = 0n,
): Pick<
  LocalRomContext,
  "toFileOffset" | "toVirtualAddress" | "normalizePointerAddress"
> => ({
  toFileOffset: (virtualAddress) => {
    const offset = Number(virtualAddress - loadAddress);
    if (Number.isSafeInteger(offset) && offset >= 0 && offset < length)
      return offset;
    // Raw-file callers may supply file offsets as well as mapped RAM addresses.
    // Resolve mapped addresses first; retain the original file-coordinate alias.
    const fileOffset = Number(virtualAddress);
    return Number.isSafeInteger(fileOffset) &&
      fileOffset >= 0 &&
      fileOffset < length
      ? fileOffset
      : null;
  },
  toVirtualAddress: (fileOffset) =>
    fileOffset >= 0 && fileOffset < length
      ? `0x${(loadAddress + BigInt(fileOffset)).toString(16)}`
      : null,
  normalizePointerAddress: (address, fileOffset) => {
    const mappedOffset = address - loadAddress;
    return `0x${(mappedOffset >= 0n && mappedOffset < BigInt(length) ? address : loadAddress + BigInt(fileOffset)).toString(16)}`;
  },
});

const loadLocalRomContext = async (
  target: RomToolTarget | undefined,
): Promise<LocalRomContext | undefined> => {
  if (target === undefined) return undefined;
  if (isLocalByteSource(target)) {
    return {
      romBytes: target.bytes,
      ...localFileMapping(target.bytes.length),
      source: target.description,
      ...(target.description.sector_size === undefined
        ? {}
        : {
            locate: (fileOffset: number) =>
              locateLocalByteOffset(target, fileOffset),
          }),
    };
  }
  if (
    target.kind !== "executable" ||
    (!isConsoleBinaryTarget(target) && target.format !== "raw-binary")
  ) {
    return undefined;
  }
  const romBytes = await readRomBytesCached(target);
  if (romBytes === undefined) return undefined;
  if (isConsoleBinaryTarget(target)) {
    const admission = target.consoleRom;
    return {
      romBytes,
      toFileOffset: (virtualAddress, tableFileOffset) =>
        resolveConsoleFileOffset(admission, virtualAddress, {
          tableFileOffset,
          fileBytes: romBytes.length,
        }),
      toVirtualAddress: (fileOffset) =>
        resolveConsoleVirtualAddress(admission, fileOffset),
    };
  }
  return {
    romBytes,
    ...localFileMapping(romBytes.length, BigInt(target.loadAddress)),
  };
};

/** `source` result field for plain byte sources. */
const sourceField = (
  localRom: LocalRomContext | undefined,
): { readonly source?: RomByteSourceDescription } =>
  localRom?.source === undefined ? {} : { source: localRom.source };

const callOperation = async (
  analysis: AnalysisOperationPort,
  operation: AnalysisOperation,
  parameters: Readonly<Record<string, JsonValue>>,
  signal?: AbortSignal,
): Promise<Result<JsonValue, AnalysisError>> => {
  const execution = await analysis.execute(
    operation,
    parameters,
    signal === undefined ? undefined : { signal },
  );
  if (!execution.ok) return execution;
  return ok(execution.value.result);
};

const parseHexAddressBigInt = (
  operation: string,
  field: string,
  raw: string,
): Result<bigint, AnalysisError> => {
  const trimmed = raw.trim();
  const normalized = /^0x/iu.test(trimmed) ? trimmed : `0x${trimmed}`;
  if (!/^0x[0-9a-fA-F]+$/u.test(normalized)) {
    return err(
      new AnalysisInputError(operation, {
        userMessage: `Invalid hexadecimal address for ${field}: ${raw}`,
      }),
    );
  }
  return ok(BigInt(normalized));
};

const loadCustomTable = async (
  operation: string,
  encoding: RomTextEncoding,
  tablePath: string | undefined,
  tableText: string | undefined,
): Promise<Result<CustomCharTable | undefined, AnalysisError>> => {
  if (tableText !== undefined) {
    const parsed = parseCustomCharTable(tableText);
    return parsed.ok
      ? ok(parsed.value)
      : err(new AnalysisInputError(operation, { userMessage: parsed.error }));
  }
  if (tablePath !== undefined) {
    let content: string;
    try {
      content = await readFile(tablePath, "utf8");
    } catch (cause) {
      return err(
        new AnalysisInputError(operation, {
          userMessage: `Failed to read custom character table at ${tablePath}`,
          cause,
        }),
      );
    }
    const parsed = parseCustomCharTable(content);
    return parsed.ok
      ? ok(parsed.value)
      : err(new AnalysisInputError(operation, { userMessage: parsed.error }));
  }
  if (requiresRomCharTable(encoding)) {
    return err(
      new AnalysisInputError(operation, {
        userMessage: `encoding '${encoding}' requires either table_path or table_text.`,
      }),
    );
  }
  return ok(undefined);
};

/** Resolve word options once per request; byte encodings reject them. */
const loadWordFormat = (
  operation: string,
  input: {
    readonly encoding: RomTextEncoding;
    readonly terminator_word?: number | null | undefined;
    readonly newline_word?: number | undefined;
    readonly tile_mask?: number | undefined;
    readonly tile_attribute?: number | null | undefined;
  },
  terminatorByte: number | null,
  customTable: CustomCharTable | undefined,
): Result<RomWordFormat | undefined, AnalysisError> => {
  const resolved = resolveRomWordFormat({
    encoding: input.encoding,
    terminatorByte,
    terminatorWord: input.terminator_word,
    newlineWord: input.newline_word,
    tileMask: input.tile_mask,
    tileAttribute: input.tile_attribute,
    customTable,
  });
  return resolved.ok
    ? resolved
    : err(new AnalysisInputError(operation, { userMessage: resolved.error }));
};

const resolveOptionalFileOffset = async (
  analysis: AnalysisOperationPort,
  address: string,
  signal?: AbortSignal,
): Promise<number | null> => {
  const res = await callOperation(
    analysis,
    "address_to_file_offset",
    { address },
    signal,
  );
  if (!res.ok) return null;
  const parsed = fileOffsetResponseSchema.safeParse(res.value);
  return parsed.success ? parsed.data.file_offset : null;
};

const resolveOptionalXrefs = async (
  analysis: AnalysisOperationPort,
  address: string,
  enabled: boolean,
  signal?: AbortSignal,
): Promise<string[]> => {
  if (!enabled) return [];
  const res = await callOperation(analysis, "xrefs", { address }, signal);
  if (!res.ok) return [];
  if (Array.isArray(res.value)) {
    const parsed = z.array(z.string()).safeParse(res.value);
    return parsed.success ? parsed.data : [];
  }
  if (
    typeof res.value === "object" &&
    res.value !== null &&
    "xrefs" in res.value
  ) {
    const parsed = z.array(z.string()).safeParse(res.value.xrefs);
    return parsed.success ? parsed.data : [];
  }
  return [];
};

/** Resolve file offsets for many addresses: one provider call per unique address, issued together. */
const resolveFileOffsetsBatched = async (
  analysis: AnalysisOperationPort,
  addresses: readonly string[],
  signal?: AbortSignal,
): Promise<ReadonlyMap<string, number | null>> => {
  const unique = [...new Set(addresses)];
  const values = await Promise.all(
    unique.map((address) =>
      resolveOptionalFileOffset(analysis, address, signal),
    ),
  );
  return new Map(unique.map((address, index) => [address, values[index]!]));
};

/** Resolve xrefs for many addresses: one provider call per unique address, issued together. */
const resolveXrefsBatched = async (
  analysis: AnalysisOperationPort,
  addresses: readonly string[],
  enabled: boolean,
  signal?: AbortSignal,
): Promise<ReadonlyMap<string, readonly string[]>> => {
  if (!enabled) return new Map();
  const unique = [...new Set(addresses)];
  const values = await Promise.all(
    unique.map((address) =>
      resolveOptionalXrefs(analysis, address, true, signal),
    ),
  );
  return new Map(unique.map((address, index) => [address, values[index]!]));
};

/** Parse an opaque search cursor (a non-negative decimal resume position). */
const parseRomCursor = (
  operation: string,
  cursor: string | undefined,
): Result<number, AnalysisError> => {
  if (cursor === undefined) return ok(0);
  if (!/^\d+$/u.test(cursor.trim())) {
    return err(
      new AnalysisInputError(operation, {
        userMessage:
          "Invalid cursor: pass back the next_cursor value from the previous identical call.",
      }),
    );
  }
  const value = Number(cursor.trim());
  return Number.isSafeInteger(value)
    ? ok(value)
    : err(
        new AnalysisInputError(operation, {
          userMessage:
            "Invalid cursor: pass back the next_cursor value from the previous identical call.",
        }),
      );
};

/** Whether a decode consumed the whole window without reaching its terminator. */
const decodeWindowTruncated = (
  buf: Uint8Array,
  byteLength: number,
  terminatorByte: number | null,
  windowMayContinue: boolean,
): boolean =>
  windowMayContinue &&
  byteLength >= buf.length &&
  byteLength > 0 &&
  !(terminatorByte !== null && buf[byteLength - 1] === terminatorByte);

/** The unit that ends a string in this request's encoding, if there is one. */
const resolveTerminatorUnit = (
  encoding: RomTextEncoding,
  terminatorByte: number | null,
  words: RomWordFormat | undefined,
): RomTerminatorUnit | undefined => {
  if (words !== undefined)
    return words.terminatorWord === null
      ? undefined
      : {
          size: 2,
          value: words.terminatorWord,
          littleEndian: words.littleEndian,
        };
  if (terminatorByte === null) return undefined;
  const canonical = normalizeRomTextEncoding(encoding);
  if (canonical === "utf-16le" || canonical === "utf-16be")
    return {
      size: 2,
      value: terminatorByte * 0x101,
      littleEndian: canonical === "utf-16le",
    };
  return { size: 1, value: terminatorByte };
};

/**
 * Validate how raw pointer values become file offsets. Segment fields select
 * segment mode unless base_mode says otherwise; segment pointers are offsets
 * from the segment start, so base_address must stay 0.
 */
const resolvePointerBase = (
  operation: string,
  input: {
    readonly base_mode?: "address" | "segment" | undefined;
    readonly segment_start?: number | undefined;
    readonly segment_length?: number | undefined;
    readonly segment_align?: number | undefined;
  },
  baseAddress: bigint,
): Result<PointerBase, AnalysisError> => {
  const fail = (userMessage: string) =>
    err(new AnalysisInputError(operation, { userMessage }));
  const hasSegment =
    input.segment_start !== undefined ||
    input.segment_length !== undefined ||
    input.segment_align !== undefined;
  const mode = input.base_mode ?? (hasSegment ? "segment" : "address");
  if (mode === "address") {
    return hasSegment
      ? fail(
          "segment_start, segment_length and segment_align apply only to base_mode segment.",
        )
      : ok({ mode: "address" });
  }
  if (baseAddress !== 0n)
    return fail(
      "base_address applies only to base_mode address; segment pointers are offsets from the segment start.",
    );
  if (input.segment_length === undefined)
    return fail("base_mode segment needs segment_length.");
  if (input.segment_start !== undefined && input.segment_align !== undefined)
    return fail("Use segment_start or segment_align, not both.");
  if (input.segment_start !== undefined)
    return ok({
      mode: "segment",
      start: input.segment_start,
      length: input.segment_length,
    });
  if (input.segment_align !== undefined)
    return ok({
      mode: "segment",
      align: input.segment_align,
      length: input.segment_length,
    });
  return fail(
    "base_mode segment needs segment_start (one segment) or segment_align (every aligned segment start).",
  );
};

const SEGMENT_NEEDS_LOCAL_BYTES =
  "base_mode segment reads pointer targets as file offsets and needs local file bytes (a console ROM, raw binary, or data file).";

/**
 * Parse declared control codes once per request, so every scan path reads one
 * owner's view of where codes begin and end.
 */
const loadControlCodes = (
  operation: string,
  input: {
    readonly control_codes?: ReadonlyArray<RomControlCodeInput> | undefined;
  },
  words: RomWordFormat | undefined,
): Result<RomControlCodeTable | undefined, AnalysisError> => {
  const declared = input.control_codes;
  if (declared === undefined || declared.length === 0) return ok(undefined);
  const parsed = parseRomControlCodes(declared);
  if (!parsed.ok) {
    return err(
      new AnalysisInputError(operation, { userMessage: parsed.error }),
    );
  }
  if (words !== undefined) {
    for (const code of parsed.value.codes) {
      if (code.bytes.length % 2 !== 0 || code.argumentBytes % 2 !== 0) {
        return err(
          new AnalysisInputError(operation, {
            userMessage: `control_codes[${code.name}]: 16-bit word encodings (${words.encoding}) require even byte lengths for control code sequences and argument_bytes.`,
          }),
        );
      }
    }
  }
  return ok(parsed.value);
};

/** One decoded target string, with its display view when codes were declared. */
interface DecodedScanText {
  readonly text: string;
  readonly byteLength: number;
  readonly rawHex: string;
  readonly display: RomTextWithControlCodes | undefined;
}

/** Decode one target string the same way on the local and provider paths. */
const decodeScanText = (
  buffer: Uint8Array,
  options: {
    readonly encoding: RomTextEncoding;
    readonly terminatorByte: number | null;
    readonly customTable: CustomCharTable | undefined;
    readonly words: RomWordFormat | undefined;
    readonly controlCodes: RomControlCodeTable | undefined;
  },
): DecodedScanText => {
  if (options.controlCodes !== undefined) {
    const display = decodeRomStringWithControlCodes(
      buffer,
      options.encoding,
      options.terminatorByte,
      options.customTable,
      options.controlCodes,
      options.words,
    );
    return {
      text: display.text,
      byteLength: display.byte_length,
      rawHex: formatHexPattern(buffer.subarray(0, display.byte_length)),
      display,
    };
  }
  const decoded = decodeRomStringFromBytes(
    buffer,
    options.encoding,
    options.terminatorByte,
    options.customTable,
    options.words,
  );
  return {
    text: decoded.decoded,
    byteLength: decoded.byteLength,
    rawHex: decoded.rawHex,
    display: undefined,
  };
};

/** Lines and character counts a translator writes against, when declared. */
const manuscriptDisplayFields = (
  display: RomTextWithControlCodes | undefined,
): Record<string, unknown> =>
  display === undefined
    ? {}
    : {
        lines: [...display.lines],
        character_length: display.character_length,
        longest_line_characters: display.longest_line_characters,
        ...(display.control_codes.length === 0
          ? {}
          : {
              control_codes: display.control_codes.map((use) => ({ ...use })),
            }),
      };

/** Manuscript strings are decoded to their terminator within this bound. */
const MANUSCRIPT_MAX_BYTES = 4096;

/** Collapse manuscript records sharing one target; extra slots become references. */
const dedupManuscriptRecords = <
  T extends {
    readonly index: number;
    readonly target_address: string;
    readonly target_file_offset: number | null;
    also_referenced_by?: number[];
  },
>(
  records: readonly T[],
): T[] => {
  const firstByTarget = new Map<string, T>();
  const unique: T[] = [];
  for (const record of records) {
    const key =
      record.target_file_offset !== null
        ? `off:${record.target_file_offset}`
        : `addr:${record.target_address}`;
    const first = firstByTarget.get(key);
    if (first === undefined) {
      firstByTarget.set(key, record);
      unique.push(record);
    } else {
      first.also_referenced_by ??= [];
      first.also_referenced_by.push(record.index);
    }
  }
  return unique;
};

/** Request facts resolved once before any search_rom_strings mode runs. */
interface PreparedRomSearch {
  readonly terminatorByte: number | null;
  readonly customTable: CustomCharTable | undefined;
  readonly words: RomWordFormat | undefined;
  readonly controlCodes: RomControlCodeTable | undefined;
  readonly filters: RomTextFilters;
  readonly localRom: LocalRomContext | undefined;
}

const rangeOnlyOptionsUsed = (input: SearchRomStringsInput): boolean =>
  input.dedupe ||
  input.include_score ||
  input.require_terminator ||
  input.fullwidth_only ||
  input.min_kana > 0 ||
  input.max_level2_kanji_ratio !== undefined ||
  input.min_text_score !== undefined;

const prepareRomSearch = async (
  input: SearchRomStringsInput,
  target: RomToolTarget | undefined,
): Promise<Result<PreparedRomSearch, AnalysisError>> => {
  const operation = "search_rom_strings";
  const terminatorByte =
    input.terminator_byte === undefined ? 0x00 : input.terminator_byte;
  if (input.query !== undefined && rangeOnlyOptionsUsed(input))
    return err(
      new AnalysisInputError(operation, {
        userMessage:
          "dedupe, include_score, require_terminator and the text filters apply to range scans; omit query to scan a range.",
      }),
    );
  const tableResult = await loadCustomTable(
    operation,
    input.encoding,
    input.table_path,
    input.table_text,
  );
  if (!tableResult.ok) return tableResult;
  const customTable = tableResult.value;
  const words = loadWordFormat(operation, input, terminatorByte, customTable);
  if (!words.ok) return words;
  const controlCodes = loadControlCodes(operation, input, words.value);
  if (!controlCodes.ok) return controlCodes;
  return ok({
    terminatorByte,
    customTable,
    words: words.value,
    controlCodes: controlCodes.value,
    filters: {
      fullwidthOnly: input.fullwidth_only,
      minKana: input.min_kana,
      maxLevel2KanjiRatio: input.max_level2_kanji_ratio,
      minTextScore: input.min_text_score,
    },
    localRom: await loadLocalRomContext(target),
  });
};

/** Every occurrence of the encoded query inside [start, end), in file order. */
function* localQueryOffsets(
  romBytes: Buffer,
  needle: Buffer,
  start: number,
  end: number,
): Generator<number, void, undefined> {
  let scanAt = start;
  while (scanAt + needle.length <= end) {
    const idx = romBytes.indexOf(needle, scanAt);
    if (idx === -1 || idx + needle.length > end) return;
    yield idx;
    scanAt = idx + 1;
  }
}

const localQueryRange = (
  localRom: LocalRomContext,
  input: SearchRomStringsInput,
): Result<{ readonly start: number; readonly end: number }, AnalysisError> => {
  let start = 0;
  if (input.start_offset !== undefined) {
    start = Math.min(input.start_offset, localRom.romBytes.length);
  } else if (input.start_address !== undefined) {
    const parsedStart = parseHexAddressBigInt(
      "search_rom_strings",
      "start_address",
      input.start_address,
    );
    if (!parsedStart.ok) return parsedStart;
    const resolved = localRom.toFileOffset(parsedStart.value);
    if (resolved !== null) start = Math.min(resolved, localRom.romBytes.length);
  }
  const end =
    input.end_offset !== undefined
      ? Math.min(input.end_offset, localRom.romBytes.length)
      : localRom.romBytes.length;
  return ok({ start, end });
};

/** One query hit decoded from its file offset to the terminator. */
const projectLocalQueryMatch = (
  localRom: LocalRomContext,
  prepared: PreparedRomSearch,
  input: SearchRomStringsInput,
  needle: Buffer,
  fileOffset: number,
) => {
  const query = input.query ?? "";
  const address =
    localRom.toVirtualAddress(fileOffset) ?? `0x${fileOffset.toString(16)}`;
  const buf = localRom.romBytes.subarray(
    fileOffset,
    Math.min(localRom.romBytes.length, fileOffset + 128),
  );
  const decoded = decodeScanText(buf, {
    encoding: input.encoding,
    terminatorByte: prepared.terminatorByte,
    customTable: prepared.customTable,
    words: prepared.words,
    controlCodes: prepared.controlCodes,
  });
  const text = decoded.text.length > 0 ? decoded.text : query;
  const bytesHex =
    decoded.text.length > 0
      ? decoded.rawHex.replace(/\s+/gu, "").toLowerCase()
      : needle.toString("hex");
  const byteLength =
    decoded.text.length > 0 ? decoded.byteLength : needle.length;
  const terminated =
    decoded.display !== undefined
      ? decoded.display.stop === "end-code"
      : queryDecodeTerminated(prepared, buf, decoded.byteLength);
  const textTruncated =
    !terminated && fileOffset + buf.length < localRom.romBytes.length;
  return {
    address,
    file_offset: fileOffset,
    ...localRom.locate?.(fileOffset),
    encoding: input.encoding,
    text,
    ...(textTruncated ? { text_truncated: true } : {}),
    ...manuscriptDisplayFields(decoded.display),
    ...(input.include_hex ? { bytes_hex: bytesHex } : {}),
    byte_length: byteLength,
    terminated,
  };
};

/** Whether a decode from a query hit stopped at its terminator. */
const queryDecodeTerminated = (
  prepared: PreparedRomSearch,
  buf: Uint8Array,
  byteLength: number,
): boolean => {
  if (prepared.words !== undefined) {
    const terminator = prepared.words.terminatorWord;
    if (terminator === null || byteLength < 2) return false;
    const at = byteLength - 2;
    const word = prepared.words.littleEndian
      ? (buf[at] ?? 0) | ((buf[at + 1] ?? 0) << 8)
      : ((buf[at] ?? 0) << 8) | (buf[at + 1] ?? 0);
    return word === terminator;
  }
  return prepared.terminatorByte !== null
    ? byteLength < buf.length || buf.includes(prepared.terminatorByte)
    : byteLength < buf.length;
};

/** A local range scan resolved to one byte window. */
interface LocalRangePlan {
  readonly slice: Buffer;
  readonly startOffset: number;
  readonly sliceMayContinue: boolean;
  readonly scan: Omit<RomStringScanInput, "resume" | "startOffset">;
}

const planLocalRange = (
  localRom: LocalRomContext,
  prepared: PreparedRomSearch,
  input: SearchRomStringsInput,
  wholeFileByDefault: boolean,
): Result<LocalRangePlan, AnalysisError> => {
  let startOffset = input.start_offset ?? 0;
  let baseAddress = BigInt(startOffset);
  if (input.start_offset === undefined && input.start_address !== undefined) {
    const parsedAddr = parseHexAddressBigInt(
      "search_rom_strings",
      "start_address",
      input.start_address,
    );
    if (!parsedAddr.ok) return parsedAddr;
    baseAddress = parsedAddr.value;
    const resolved = localRom.toFileOffset(parsedAddr.value);
    if (resolved === null) {
      return err(
        new AnalysisInputError("search_rom_strings", {
          userMessage: `start_address ${input.start_address} does not map to a file offset in this ROM.`,
        }),
      );
    }
    startOffset = resolved;
  } else {
    const resolvedVaddr = localRom.toVirtualAddress(startOffset);
    if (resolvedVaddr !== null) baseAddress = BigInt(resolvedVaddr);
  }
  const fileLength = localRom.romBytes.length;
  const sliceStart = Math.min(startOffset, fileLength);
  const end =
    input.end_offset !== undefined
      ? Math.min(fileLength, Math.max(sliceStart, input.end_offset))
      : wholeFileByDefault &&
          input.start_offset === undefined &&
          input.start_address === undefined
        ? fileLength
        : Math.min(fileLength, sliceStart + input.length);
  const slice = localRom.romBytes.subarray(sliceStart, end);
  return ok({
    slice,
    startOffset: sliceStart,
    sliceMayContinue: end < fileLength,
    scan: rangeScanInput(prepared, input, slice, baseAddress, sliceStart),
  });
};

const rangeScanInput = (
  prepared: PreparedRomSearch,
  input: SearchRomStringsInput,
  bytes: Uint8Array,
  baseAddress: bigint,
  parityOrigin: number,
): Omit<RomStringScanInput, "resume" | "startOffset"> => ({
  bytes,
  baseAddress,
  encoding: input.encoding,
  minLength: input.min_length,
  terminatorByte: prepared.terminatorByte,
  customTable: prepared.customTable,
  words: prepared.words,
  controlCodes: prepared.controlCodes,
  includeRawHex: input.include_hex,
  filters: prepared.filters,
  measure: input.include_score,
  requireTerminator: input.require_terminator,
  wordParity: input.word_parity,
  parityOrigin,
});

/** One scanned string as a match, before xrefs are attached. */
const projectRangeMatch = (
  input: SearchRomStringsInput,
  item: ScannedRomString,
  location: {
    readonly address: string;
    readonly fileOffset: number | null;
    readonly sector?: ReturnType<typeof locateLocalByteOffset>;
    readonly truncated: boolean;
    readonly occurrences?: readonly number[];
  },
) => ({
  address: location.address,
  file_offset: location.fileOffset,
  ...location.sector,
  encoding: input.encoding,
  text: item.decoded,
  ...(location.truncated ? { text_truncated: true } : {}),
  ...(item.score === undefined ? {} : { text_score: item.score }),
  ...manuscriptDisplayFields(item.display),
  ...(input.include_hex
    ? { bytes_hex: item.rawHex.replace(/\s+/gu, "").toLowerCase() }
    : {}),
  byte_length: item.byteLength,
  terminated: item.terminated,
  ...(location.occurrences === undefined
    ? {}
    : { occurrences: [...location.occurrences] }),
});

/** Distinct byte strings in first-appearance order with every buffer offset. */
const groupScannedStrings = (
  scan: Iterable<ScannedRomString>,
  bytes: Uint8Array,
): { readonly first: ScannedRomString; readonly offsets: number[] }[] => {
  const groups = new Map<
    string,
    { readonly first: ScannedRomString; readonly offsets: number[] }
  >();
  const view = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (const item of scan) {
    const key = view.toString(
      "latin1",
      item.offsetInBuffer,
      item.offsetInBuffer + item.byteLength,
    );
    const group = groups.get(key);
    if (group === undefined)
      groups.set(key, { first: item, offsets: [item.offsetInBuffer] });
    else group.offsets.push(item.offsetInBuffer);
  }
  return [...groups.values()];
};

const DEDUPE_CURSOR = /^d(\d+)$/u;

/**
 * Select one page of range-scan strings. Plain scans resume from the scanner's
 * own restart point; dedupe scans group the whole window and page by group.
 */
const selectRangePage = (
  scan: Omit<RomStringScanInput, "resume" | "startOffset">,
  input: SearchRomStringsInput,
): Result<
  {
    readonly items: readonly {
      readonly item: ScannedRomString;
      readonly offsets?: readonly number[];
    }[];
    readonly nextCursor: string | null;
  },
  AnalysisError
> => {
  const invalidCursor = err(
    new AnalysisInputError("search_rom_strings", {
      userMessage:
        "Invalid cursor: pass back the next_cursor value from the previous identical call.",
    }),
  );
  if (input.dedupe) {
    let first = 0;
    if (input.cursor !== undefined) {
      const match = DEDUPE_CURSOR.exec(input.cursor.trim());
      if (match === null) return invalidCursor;
      first = Number(match[1]);
    }
    const groups = groupScannedStrings(scanRomStrings(scan), scan.bytes);
    const page = groups.slice(first, first + input.max_results);
    return ok({
      items: page.map((group) => ({
        item: group.first,
        offsets: group.offsets,
      })),
      nextCursor:
        first + input.max_results < groups.length
          ? `d${first + input.max_results}`
          : null,
    });
  }
  let resume: RomScanResume | undefined;
  if (input.cursor !== undefined) {
    const parsed = parseRomScanCursor(input.cursor, {
      word: isWordRomTextEncoding(normalizeRomTextEncoding(input.encoding)),
      bufferLength: scan.bytes.length,
      parityOrigin: scan.parityOrigin ?? 0,
    });
    if (!parsed.ok) return invalidCursor;
    resume = parsed.value;
  }
  const items: { readonly item: ScannedRomString }[] = [];
  let nextCursor: string | null = null;
  for (const item of scanRomStrings({ ...scan, resume })) {
    if (items.length === input.max_results) {
      nextCursor = formatRomScanCursor(item.resume);
      break;
    }
    items.push({ item });
  }
  return ok({ items, nextCursor });
};

export const executeSearchRomStrings = async (
  analysis: AnalysisOperationPort,
  input: SearchRomStringsInput,
  signal?: AbortSignal,
  target?: RomToolTarget,
): EnhancedResult => {
  const preparedResult = await prepareRomSearch(input, target);
  if (!preparedResult.ok) return preparedResult;
  const prepared = preparedResult.value;
  const { localRom, customTable, terminatorByte, words } = prepared;

  if (input.query !== undefined) {
    const encodedResult = encodeRomQueryString(
      input.query,
      input.encoding,
      customTable,
      words,
    );
    if (!encodedResult.ok) {
      return err(
        new AnalysisInputError("search_rom_strings", {
          userMessage: encodedResult.error,
        }),
      );
    }
    const pattern = formatHexPattern(encodedResult.value).toUpperCase();

    if (localRom !== undefined) {
      // Provider query search uses the provider's own opaque cursor verbatim;
      // local scans use a numeric resume offset.
      const cursorResult = parseRomCursor("search_rom_strings", input.cursor);
      if (!cursorResult.ok) return cursorResult;
      const range = localQueryRange(localRom, input);
      if (!range.ok) return range;
      const needle = Buffer.from(encodedResult.value);

      // Count every match in the range (native indexOf) while collecting
      // only this page, starting at the cursor's file offset.
      const pageStart = Math.max(range.value.start, cursorResult.value);
      const foundOffsets: number[] = [];
      let totalMatches = 0;
      let nextCursor: string | null = null;
      for (const idx of localQueryOffsets(
        localRom.romBytes,
        needle,
        range.value.start,
        range.value.end,
      )) {
        totalMatches++;
        if (idx < pageStart) continue;
        if (foundOffsets.length < input.max_results) foundOffsets.push(idx);
        else nextCursor ??= String(idx);
      }

      const pendingMatches = foundOffsets.map((fileOffset) =>
        projectLocalQueryMatch(localRom, prepared, input, needle, fileOffset),
      );
      const xrefsByAddress = await resolveXrefsBatched(
        analysis,
        pendingMatches.map((match) => match.address),
        input.resolve_xrefs,
        signal,
      );
      const matches = pendingMatches.map((match) => ({
        ...match,
        xrefs: [...(xrefsByAddress.get(match.address) ?? [])],
      }));

      return ok({
        mode: "query_search",
        encoding: input.encoding,
        encoded_query_pattern: pattern,
        matches,
        total_matches: totalMatches,
        truncated: nextCursor !== null,
        next_cursor: nextCursor,
        ...sourceField(localRom),
      });
    }

    const searchResult = await callOperation(
      analysis,
      "search_bytes",
      {
        pattern,
        ...(input.start_address === undefined
          ? {}
          : { start: input.start_address }),
        limit: input.max_results,
        ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
      },
      signal,
    );
    if (!searchResult.ok) return searchResult;

    const parsedSearch = searchBytesResponseSchema.safeParse(
      searchResult.value,
    );
    if (!parsedSearch.success) {
      return err(
        new AnalysisOutputError(
          "search_bytes",
          "Provider returned an invalid byte search result",
          {
            cause: parsedSearch.error,
          },
        ),
      );
    }

    const pageMatches = parsedSearch.data.matches.slice(0, input.max_results);
    const providerNextCursor = parsedSearch.data.next_cursor ?? null;
    const providerTruncated =
      providerNextCursor !== null || !parsedSearch.data.complete;
    const pendingMatches = [];
    for (const item of pageMatches) {
      const readRes = await callOperation(
        analysis,
        "read_bytes",
        { address: item.address, length: 128 },
        signal,
      );
      let text = input.query;
      let bytesHex = Buffer.from(encodedResult.value).toString("hex");
      let byteLength = encodedResult.value.length;
      let terminated = false;

      if (readRes.ok) {
        const parsedRead = readBytesResponseSchema.safeParse(readRes.value);
        if (parsedRead.success && parsedRead.data.bytes_hex.length > 0) {
          const buf = Buffer.from(parsedRead.data.bytes_hex, "hex");
          const decoded = decodeRomStringFromBytes(
            buf,
            input.encoding,
            terminatorByte,
            customTable,
            words,
          );
          if (decoded.decoded.length > 0) {
            text = decoded.decoded;
            bytesHex = decoded.rawHex.replace(/\s+/gu, "").toLowerCase();
            byteLength = decoded.byteLength;
            terminated = queryDecodeTerminated(
              prepared,
              buf,
              decoded.byteLength,
            );
          }
        }
      }

      pendingMatches.push({
        address: item.address,
        encoding: input.encoding,
        text,
        text_truncated: !terminated && byteLength >= 128,
        bytes_hex: bytesHex,
        byte_length: byteLength,
        terminated,
      });
    }
    const pendingAddresses = pendingMatches.map((match) => match.address);
    const [offsetsByAddress, xrefsByAddress] = await Promise.all([
      resolveFileOffsetsBatched(analysis, pendingAddresses, signal),
      resolveXrefsBatched(
        analysis,
        pendingAddresses,
        input.resolve_xrefs,
        signal,
      ),
    ]);
    const matches = pendingMatches.map((match) => ({
      address: match.address,
      file_offset: offsetsByAddress.get(match.address) ?? null,
      encoding: match.encoding,
      text: match.text,
      ...(match.text_truncated ? { text_truncated: true } : {}),
      ...(input.include_hex ? { bytes_hex: match.bytes_hex } : {}),
      byte_length: match.byte_length,
      terminated: match.terminated,
      xrefs: [...(xrefsByAddress.get(match.address) ?? [])],
    }));

    return ok({
      mode: "query_search",
      encoding: input.encoding,
      encoded_query_pattern: pattern,
      matches,
      total_matches: matches.length,
      truncated: providerTruncated,
      next_cursor: providerNextCursor,
    });
  }

  if (input.start_address === undefined && input.start_offset === undefined) {
    return err(
      new AnalysisInputError("search_rom_strings", {
        userMessage:
          "Provide either query (to search encoded bytes across ROM) or start_address / start_offset (to scan a memory range).",
      }),
    );
  }

  if (localRom !== undefined) {
    const plan = planLocalRange(localRom, prepared, input, false);
    if (!plan.ok) return plan;
    const { slice, startOffset, sliceMayContinue } = plan.value;
    const page = selectRangePage(plan.value.scan, input);
    if (!page.ok) return page;
    const pendingMatches = page.value.items.map(({ item, offsets }) => {
      const fileOffset = startOffset + item.offsetInBuffer;
      return projectRangeMatch(input, item, {
        address: localRom.toVirtualAddress(fileOffset) ?? item.address,
        fileOffset,
        sector: localRom.locate?.(fileOffset),
        truncated:
          sliceMayContinue &&
          !item.terminated &&
          item.offsetInBuffer + item.byteLength >= slice.length,
        ...(offsets === undefined
          ? {}
          : { occurrences: offsets.map((offset) => startOffset + offset) }),
      });
    });
    const xrefsByAddress = await resolveXrefsBatched(
      analysis,
      pendingMatches.map((match) => match.address),
      input.resolve_xrefs,
      signal,
    );
    const matches = pendingMatches.map((match) => ({
      ...match,
      xrefs: [...(xrefsByAddress.get(match.address) ?? [])],
    }));

    return ok({
      mode: "range_scan",
      encoding: input.encoding,
      encoded_query_pattern: null,
      matches,
      total_matches: matches.length,
      truncated: page.value.nextCursor !== null,
      next_cursor: page.value.nextCursor,
      ...sourceField(localRom),
    });
  }

  if (input.dedupe)
    return err(
      new AnalysisInputError("search_rom_strings", {
        userMessage:
          "dedupe needs local file bytes (a console ROM, raw binary, or data file).",
      }),
    );

  const startAddressStr =
    input.start_address ?? `0x${(input.start_offset ?? 0).toString(16)}`;
  const baseAddrResult = parseHexAddressBigInt(
    "search_rom_strings",
    "start_address",
    startAddressStr,
  );
  if (!baseAddrResult.ok) return baseAddrResult;

  const scanLength =
    input.end_offset !== undefined && input.start_offset !== undefined
      ? Math.max(1, input.end_offset - input.start_offset)
      : input.length;

  const readRes = await callOperation(
    analysis,
    "read_bytes",
    { address: startAddressStr, length: scanLength },
    signal,
  );
  if (!readRes.ok) return readRes;

  const parsedRead = readBytesResponseSchema.safeParse(readRes.value);
  if (!parsedRead.success) {
    return err(
      new AnalysisOutputError(
        "read_bytes",
        "Provider returned an invalid byte read result",
        { cause: parsedRead.error },
      ),
    );
  }

  const buffer = Buffer.from(parsedRead.data.bytes_hex, "hex");
  const page = selectRangePage(
    rangeScanInput(
      prepared,
      input,
      buffer,
      baseAddrResult.value,
      input.start_offset ?? 0,
    ),
    input,
  );
  if (!page.ok) return page;
  const extracted = page.value.items.map(({ item }) => item);

  const pendingAddresses = extracted.map((item) => item.address);
  const [providerOffsets, providerXrefs] = await Promise.all([
    resolveFileOffsetsBatched(analysis, pendingAddresses, signal),
    resolveXrefsBatched(
      analysis,
      pendingAddresses,
      input.resolve_xrefs,
      signal,
    ),
  ]);
  const matches = extracted.map((item) => ({
    ...projectRangeMatch(input, item, {
      address: item.address,
      fileOffset: providerOffsets.get(item.address) ?? null,
      truncated:
        !item.terminated &&
        item.offsetInBuffer + item.byteLength >= buffer.length,
    }),
    xrefs: [...(providerXrefs.get(item.address) ?? [])],
  }));

  return ok({
    mode: "range_scan",
    encoding: input.encoding,
    encoded_query_pattern: null,
    matches,
    total_matches: matches.length,
    truncated: page.value.nextCursor !== null,
    next_cursor: page.value.nextCursor,
  });
};

/** Summary of a search_rom_strings run written to a JSON Lines file. */
export type RomStringExportSummary = {
  readonly mode: "query_search" | "range_scan";
  readonly encoding: RomTextEncoding;
  readonly encoded_query_pattern: string | null;
  readonly deduplicated: boolean;
  readonly range: {
    readonly start_offset: number;
    readonly end_offset: number;
  };
  readonly source?: RomByteSourceDescription;
};

/**
 * Run search_rom_strings over local bytes without page or result limits and
 * hand each match to `write` as one record. With dedupe, records are written
 * after the whole range is grouped. Without a query or range, the whole file
 * is scanned.
 */
export const exportSearchRomStrings = async (
  input: SearchRomStringsInput,
  target: RomToolTarget,
  write: (record: Readonly<Record<string, JsonValue>>) => Promise<void>,
  signal?: AbortSignal,
): Promise<Result<RomStringExportSummary, AnalysisError>> => {
  const operation = "search_rom_strings";
  if (input.cursor !== undefined || input.resolve_xrefs)
    return err(
      new AnalysisInputError(operation, {
        userMessage:
          "File export writes every match from local bytes; cursor and resolve_xrefs do not apply.",
      }),
    );
  const preparedResult = await prepareRomSearch(input, target);
  if (!preparedResult.ok) return preparedResult;
  const prepared = preparedResult.value;
  const { localRom } = prepared;
  if (localRom === undefined)
    return err(
      new AnalysisInputError(operation, {
        userMessage:
          "File export needs local file bytes (a console ROM, raw binary, or data file).",
      }),
    );
  const cancelled = (): Result<never, AnalysisError> | undefined =>
    signal?.aborted === true
      ? err(
          new AnalysisInputError(operation, {
            userMessage: "Export was cancelled.",
          }),
        )
      : undefined;

  if (input.query !== undefined) {
    const encoded = encodeRomQueryString(
      input.query,
      input.encoding,
      prepared.customTable,
      prepared.words,
    );
    if (!encoded.ok)
      return err(
        new AnalysisInputError(operation, { userMessage: encoded.error }),
      );
    const range = localQueryRange(localRom, input);
    if (!range.ok) return range;
    const needle = Buffer.from(encoded.value);
    for (const fileOffset of localQueryOffsets(
      localRom.romBytes,
      needle,
      range.value.start,
      range.value.end,
    )) {
      const stop = cancelled();
      if (stop !== undefined) return stop;
      await write(
        projectLocalQueryMatch(localRom, prepared, input, needle, fileOffset),
      );
    }
    return ok({
      mode: "query_search",
      encoding: input.encoding,
      encoded_query_pattern: formatHexPattern(encoded.value).toUpperCase(),
      deduplicated: false,
      range: {
        start_offset: range.value.start,
        end_offset: range.value.end,
      },
      ...sourceField(localRom),
    });
  }

  const plan = planLocalRange(localRom, prepared, input, true);
  if (!plan.ok) return plan;
  const { slice, startOffset, sliceMayContinue, scan } = plan.value;
  const project = (item: ScannedRomString, offsets?: readonly number[]) => {
    const fileOffset = startOffset + item.offsetInBuffer;
    return projectRangeMatch(input, item, {
      address: localRom.toVirtualAddress(fileOffset) ?? item.address,
      fileOffset,
      sector: localRom.locate?.(fileOffset),
      truncated:
        sliceMayContinue &&
        !item.terminated &&
        item.offsetInBuffer + item.byteLength >= slice.length,
      ...(offsets === undefined
        ? {}
        : { occurrences: offsets.map((offset) => startOffset + offset) }),
    });
  };
  if (input.dedupe) {
    for (const group of groupScannedStrings(scanRomStrings(scan), slice)) {
      const stop = cancelled();
      if (stop !== undefined) return stop;
      await write(project(group.first, group.offsets));
    }
  } else {
    for (const item of scanRomStrings(scan)) {
      const stop = cancelled();
      if (stop !== undefined) return stop;
      await write(project(item));
    }
  }
  return ok({
    mode: "range_scan",
    encoding: input.encoding,
    encoded_query_pattern: null,
    deduplicated: input.dedupe,
    range: {
      start_offset: startOffset,
      end_offset: startOffset + slice.length,
    },
    ...sourceField(localRom),
  });
};

const resolvePointerTargetInFile = (
  baseAddr: bigint,
  rawValue: bigint,
  romLength: number,
  toFileOffset: (vaddr: bigint, entryFileOffset?: number) => number | null,
  entryFileOffset?: number,
  normalizePointerAddress?: LocalRomContext["normalizePointerAddress"],
): {
  readonly targetAddress: string;
  readonly targetFileOffset: number | null;
} => {
  const additiveAddr = baseAddr + rawValue;
  const additiveOffset = toFileOffset(additiveAddr, entryFileOffset);
  if (additiveOffset !== null) {
    return {
      targetAddress:
        normalizePointerAddress?.(additiveAddr, additiveOffset) ??
        `0x${additiveAddr.toString(16)}`,
      targetFileOffset: additiveOffset,
    };
  }
  if (
    baseAddr > 0n &&
    rawValue >= baseAddr &&
    rawValue - baseAddr < BigInt(romLength)
  ) {
    return {
      targetAddress: `0x${rawValue.toString(16)}`,
      targetFileOffset: Number(rawValue - baseAddr),
    };
  }
  return {
    targetAddress: `0x${additiveAddr.toString(16)}`,
    targetFileOffset: null,
  };
};

export const executeScanPointerTable = async (
  analysis: AnalysisOperationPort,
  input: ScanPointerTableInput,
  signal?: AbortSignal,
  target?: RomToolTarget,
): EnhancedResult => {
  if (input.address === undefined && input.table_offset === undefined) {
    return err(
      new AnalysisInputError("scan_pointer_table", {
        userMessage:
          "Provide either address or table_offset to locate the pointer table.",
      }),
    );
  }

  const terminatorByte =
    input.terminator_byte === undefined ? 0x00 : input.terminator_byte;

  const baseAddrResult = parseHexAddressBigInt(
    "scan_pointer_table",
    "base_address",
    input.base_address,
  );
  if (!baseAddrResult.ok) return baseAddrResult;

  const stride = input.stride ?? input.pointer_size;
  if (stride < input.pointer_size) {
    return err(
      new AnalysisInputError("scan_pointer_table", {
        userMessage: `stride (${String(stride)}) must be greater than or equal to pointer_size (${String(input.pointer_size)}).`,
      }),
    );
  }
  const pointerBaseResult = resolvePointerBase(
    "scan_pointer_table",
    input,
    baseAddrResult.value,
  );
  if (!pointerBaseResult.ok) return pointerBaseResult;
  const pointerBase = pointerBaseResult.value;
  const segment =
    pointerBase.mode === "segment" && "start" in pointerBase
      ? pointerBase
      : undefined;

  const tableResult = await loadCustomTable(
    "scan_pointer_table",
    input.encoding,
    input.table_path,
    input.table_text,
  );
  if (!tableResult.ok) return tableResult;
  const customTable = tableResult.value;
  const wordsResult = loadWordFormat(
    "scan_pointer_table",
    input,
    terminatorByte,
    customTable,
  );
  if (!wordsResult.ok) return wordsResult;
  const words = wordsResult.value;
  const controlCodesResult = loadControlCodes(
    "scan_pointer_table",
    input,
    words,
  );
  if (!controlCodesResult.ok) return controlCodesResult;
  const controlCodes = controlCodesResult.value;
  const localRom = await loadLocalRomContext(target);
  if (segment !== undefined && localRom === undefined)
    return err(
      new AnalysisInputError("scan_pointer_table", {
        userMessage: SEGMENT_NEEDS_LOCAL_BYTES,
      }),
    );

  const totalBytesToRead = input.count * stride;
  const pointerWidth = input.pointer_size;
  const endian = input.endian;

  if (localRom !== undefined) {
    let tableFileOffset: number | null = null;
    let tableAddrBigInt = 0n;

    if (input.table_offset !== undefined) {
      tableFileOffset = input.table_offset;
      if (input.address !== undefined) {
        const parsedAddr = parseHexAddressBigInt(
          "scan_pointer_table",
          "address",
          input.address,
        );
        if (!parsedAddr.ok) return parsedAddr;
        tableAddrBigInt = parsedAddr.value;
      } else {
        const resolvedVaddr = localRom.toVirtualAddress(tableFileOffset);
        tableAddrBigInt = BigInt(
          resolvedVaddr ?? `0x${tableFileOffset.toString(16)}`,
        );
      }
    } else if (input.address !== undefined) {
      const parsedAddr = parseHexAddressBigInt(
        "scan_pointer_table",
        "address",
        input.address,
      );
      if (!parsedAddr.ok) return parsedAddr;
      tableAddrBigInt = parsedAddr.value;
      tableFileOffset = localRom.toFileOffset(tableAddrBigInt);
      if (
        tableFileOffset === null &&
        baseAddrResult.value > 0n &&
        tableAddrBigInt >= baseAddrResult.value &&
        tableAddrBigInt - baseAddrResult.value <
          BigInt(localRom.romBytes.length)
      ) {
        tableFileOffset = Number(tableAddrBigInt - baseAddrResult.value);
      }
    }

    if (
      tableFileOffset !== null &&
      tableFileOffset >= 0 &&
      tableFileOffset < localRom.romBytes.length
    ) {
      const tableBuffer = localRom.romBytes.subarray(
        tableFileOffset,
        Math.min(
          localRom.romBytes.length,
          tableFileOffset + input.start_index * stride + totalBytesToRead,
        ),
      );
      const entries = [];

      for (
        let index = input.start_index;
        index < input.start_index + input.count;
        index += 1
      ) {
        const byteOffset = index * stride;
        if (byteOffset + pointerWidth > tableBuffer.length) break;

        const entryFileOffset = tableFileOffset + byteOffset;
        const entryAddress =
          localRom.toVirtualAddress(entryFileOffset) ??
          `0x${(tableAddrBigInt + BigInt(byteOffset)).toString(16)}`;
        const rawValue = readPointerValue(
          tableBuffer,
          byteOffset,
          pointerWidth,
          endian,
        );
        const rawPointer = `0x${rawValue.toString(16).padStart(pointerWidth * 2, "0")}`;
        let targetAddress: string;
        let targetFileOffset: number | null;
        if (segment === undefined) {
          const resolvedTarget = resolvePointerTargetInFile(
            baseAddrResult.value,
            rawValue,
            localRom.romBytes.length,
            localRom.toFileOffset,
            entryFileOffset,
            localRom.normalizePointerAddress,
          );
          targetAddress = resolvedTarget.targetAddress;
          targetFileOffset = resolvedTarget.targetFileOffset;
        } else {
          // Values at or past the segment length point outside the segment.
          const segmentOffset = segment.start + Number(rawValue);
          targetFileOffset =
            rawValue < BigInt(segment.length) &&
            segmentOffset < localRom.romBytes.length
              ? segmentOffset
              : null;
          targetAddress =
            (targetFileOffset === null
              ? null
              : localRom.toVirtualAddress(targetFileOffset)) ??
            `0x${segmentOffset.toString(16)}`;
        }

        let previewText: string | null = null;
        let previewTruncated = false;
        let previewBytesHex: string | null = null;
        let previewByteLength: number | null = null;

        if (
          input.preview_bytes > 0 &&
          targetFileOffset !== null &&
          targetFileOffset >= 0 &&
          targetFileOffset < localRom.romBytes.length
        ) {
          const targetBuf = localRom.romBytes.subarray(
            targetFileOffset,
            Math.min(
              localRom.romBytes.length,
              targetFileOffset + input.preview_bytes,
            ),
          );
          if (targetBuf.length > 0) {
            const decoded = decodeScanText(targetBuf, {
              encoding: input.encoding,
              terminatorByte,
              customTable,
              words,
              controlCodes,
            });
            previewText = decoded.text;
            previewTruncated = decodeWindowTruncated(
              targetBuf,
              decoded.byteLength,
              terminatorByte,
              targetFileOffset + targetBuf.length < localRom.romBytes.length,
            );
            previewBytesHex = input.include_hex
              ? decoded.rawHex.replace(/\s+/gu, "").toLowerCase()
              : null;
            previewByteLength = decoded.byteLength;
          }
        }

        entries.push({
          index,
          entry_address: entryAddress,
          entry_file_offset: entryFileOffset,
          raw_pointer: rawPointer,
          target_address: targetAddress,
          target_file_offset: targetFileOffset,
          preview_text: previewText,
          ...(previewTruncated ? { preview_truncated: true } : {}),
          preview_bytes_hex: previewBytesHex,
          preview_byte_length: previewByteLength,
        });
      }
      const localXrefs = await resolveXrefsBatched(
        analysis,
        entries.flatMap((entry) => [entry.entry_address, entry.target_address]),
        input.resolve_xrefs,
        signal,
      );
      for (const entry of entries) {
        Object.assign(entry, {
          entry_xrefs: [...(localXrefs.get(entry.entry_address) ?? [])],
          target_xrefs: [...(localXrefs.get(entry.target_address) ?? [])],
        });
      }

      const unit = resolveTerminatorUnit(input.encoding, terminatorByte, words);
      const orphanStrings = input.include_orphan_strings
        ? findOrphanStringsInPointerGaps({
            bytes: localRom.romBytes,
            entries,
            unitSize: unit?.size ?? (words !== undefined ? 2 : 1),
            isPaddingAt: (offset: number) =>
              unit !== undefined
                ? isTerminatorAt(localRom.romBytes, offset, unit)
                : false,
            decodeAt: (slice: Uint8Array) => {
              const valid = isLikelyValidDecodedTarget(
                slice,
                input.encoding,
                terminatorByte,
                2,
                customTable,
                words,
                controlCodes,
              );
              if (!valid.valid) return null;
              const dec = decodeScanText(slice, {
                encoding: input.encoding,
                terminatorByte,
                customTable,
                words,
                controlCodes,
              });
              const terminated =
                dec.display?.stop === "end-code" ||
                (unit !== undefined &&
                  dec.byteLength >= unit.size &&
                  isTerminatorAt(slice, dec.byteLength - unit.size, unit));
              return {
                text: dec.text,
                byteLength: dec.byteLength,
                rawHex: dec.rawHex,
                terminated,
                ...(dec.display === undefined
                  ? {}
                  : {
                      controlCodes: dec.display.control_codes,
                      lines: dec.display.lines,
                      characterLength: dec.display.character_length,
                      longestLineCharacters:
                        dec.display.longest_line_characters,
                    }),
              };
            },
            toVirtualAddress: (fo: number) =>
              baseAddrResult.value > 0n && localRom.source !== undefined
                ? `0x${(baseAddrResult.value + BigInt(fo)).toString(16)}`
                : localRom.toVirtualAddress(fo),
            includeHex: input.include_hex,
          })
        : undefined;
      const budgetEntries = [
        ...entries,
        ...(orphanStrings ?? []).map((orphan) => ({
          target_file_offset: orphan.file_offset,
          target_address: orphan.address,
          preview_byte_length: orphan.byte_length,
        })),
      ];
      const budgets = computePointerSlotBudgets(budgetEntries);
      const enrichedEntries = entries.map((entry, idx) => ({
        ...entry,
        allocated_budget_bytes: budgets[idx] ?? null,
      }));
      const wantsManuscript = input.include_manuscript || input.manuscript_only;
      // Manuscript text is decoded to its terminator (not the preview cap),
      // once per unique target.
      const fullByTarget = new Map<
        string,
        {
          text: string;
          byteLength: number;
          truncated: boolean;
          display: RomTextWithControlCodes | undefined;
        }
      >();
      if (wantsManuscript) {
        for (const entry of enrichedEntries) {
          const key =
            entry.target_file_offset !== null
              ? `off:${entry.target_file_offset}`
              : `addr:${entry.target_address}`;
          if (fullByTarget.has(key)) continue;
          const off = entry.target_file_offset;
          if (off === null || off < 0 || off >= localRom.romBytes.length) {
            continue;
          }
          const buf = localRom.romBytes.subarray(
            off,
            Math.min(localRom.romBytes.length, off + MANUSCRIPT_MAX_BYTES),
          );
          const decoded = decodeScanText(buf, {
            encoding: input.encoding,
            terminatorByte,
            customTable,
            words,
            controlCodes,
          });
          fullByTarget.set(key, {
            text: decoded.text,
            byteLength: decoded.byteLength,
            display: decoded.display,
            truncated: decodeWindowTruncated(
              buf,
              decoded.byteLength,
              terminatorByte,
              off + buf.length < localRom.romBytes.length,
            ),
          });
        }
      }
      const manuscriptRecords: ManuscriptRecord[] | undefined = wantsManuscript
        ? dedupManuscriptRecords(
            enrichedEntries.map((entry) => {
              const key =
                entry.target_file_offset !== null
                  ? `off:${entry.target_file_offset}`
                  : `addr:${entry.target_address}`;
              const full = fullByTarget.get(key);
              return {
                id: `ptr_${entry.index.toString().padStart(4, "0")}`,
                index: entry.index,
                pointer_address: entry.entry_address,
                pointer_file_offset: entry.entry_file_offset,
                target_address: entry.target_address,
                target_file_offset: entry.target_file_offset,
                byte_length: full?.byteLength ?? entry.preview_byte_length,
                max_bytes: entry.allocated_budget_bytes,
                jp: full?.text ?? entry.preview_text ?? "",
                ...(full?.truncated ? { truncated: true } : {}),
                ...manuscriptDisplayFields(full?.display),
                ko: "",
              };
            }),
          )
        : undefined;
      if (manuscriptRecords !== undefined) {
        for (const orphan of orphanStrings ?? []) {
          manuscriptRecords.push({
            origin: "orphan",
            id: `orphan_${orphan.file_offset.toString(16).padStart(8, "0")}`,
            pointer_address: null,
            pointer_file_offset: null,
            after_entry_index: orphan.after_entry_index,
            gap_index: orphan.gap_index,
            target_address: orphan.address,
            target_file_offset: orphan.file_offset,
            byte_length: orphan.byte_length,
            max_bytes: orphan.allocated_budget_bytes,
            jp: orphan.text,
            ko: "",
            ...(orphan.lines === undefined ? {} : { lines: orphan.lines }),
            ...(orphan.character_length === undefined
              ? {}
              : { character_length: orphan.character_length }),
            ...(orphan.longest_line_characters === undefined
              ? {}
              : { longest_line_characters: orphan.longest_line_characters }),
            ...(orphan.control_codes === undefined
              ? {}
              : {
                  control_codes: orphan.control_codes.map((code) => ({
                    ...code,
                  })),
                }),
          });
        }
      }

      const coverage =
        unit === undefined
          ? null
          : measurePointerTableCoverage({
              bytes: localRom.romBytes,
              unit,
              targets: enrichedEntries.flatMap((entry) =>
                entry.target_file_offset === null
                  ? []
                  : [entry.target_file_offset],
              ),
              tableEnd:
                tableFileOffset +
                (input.start_index + enrichedEntries.length) * stride,
            });

      return ok({
        table_address: `0x${tableAddrBigInt.toString(16)}`,
        table_file_offset: tableFileOffset,
        pointer_size: pointerWidth,
        endian,
        base_address: `0x${baseAddrResult.value.toString(16)}`,
        base_mode: pointerBase.mode,
        ...(segment === undefined
          ? {}
          : { segment_start: segment.start, segment_length: segment.length }),
        stride,
        encoding: input.encoding,
        entries: input.manuscript_only ? [] : enrichedEntries,
        entries_scanned: enrichedEntries.length,
        start_index: input.start_index,
        next_start_index: input.start_index + enrichedEntries.length,
        ...(manuscriptRecords === undefined
          ? {}
          : { manuscript_records: jsonValueSchema.parse(manuscriptRecords) }),
        ...(orphanStrings === undefined
          ? {}
          : { orphan_strings: jsonValueSchema.parse(orphanStrings) }),
        coverage,
        ...sourceField(localRom),
      });
    }
  }

  if (segment !== undefined)
    return err(
      new AnalysisInputError("scan_pointer_table", {
        userMessage:
          "The pointer table does not map to a file offset inside this file.",
      }),
    );

  const addressStr =
    input.address ?? `0x${(input.table_offset ?? 0).toString(16)}`;
  const tableAddrResult = parseHexAddressBigInt(
    "scan_pointer_table",
    "address",
    addressStr,
  );
  if (!tableAddrResult.ok) return tableAddrResult;

  const pageReadAddress =
    input.start_index === 0
      ? addressStr
      : `0x${(tableAddrResult.value + BigInt(input.start_index * stride)).toString(16)}`;
  const readRes = await callOperation(
    analysis,
    "read_bytes",
    { address: pageReadAddress, length: totalBytesToRead },
    signal,
  );
  if (!readRes.ok) return readRes;

  const parsedRead = readBytesResponseSchema.safeParse(readRes.value);
  if (!parsedRead.success) {
    return err(
      new AnalysisOutputError(
        "read_bytes",
        "Provider returned an invalid byte read result",
        { cause: parsedRead.error },
      ),
    );
  }

  const tableBuffer = Buffer.from(parsedRead.data.bytes_hex, "hex");
  const rawEntries = [];
  for (let localIndex = 0; localIndex < input.count; localIndex += 1) {
    const byteOffset = localIndex * stride;
    if (byteOffset + pointerWidth > tableBuffer.length) break;
    const rawValue = readPointerValue(
      tableBuffer,
      byteOffset,
      pointerWidth,
      endian,
    );
    rawEntries.push({
      index: input.start_index + localIndex,
      entry_address: `0x${(tableAddrResult.value + BigInt(input.start_index * stride + byteOffset)).toString(16)}`,
      raw_pointer: `0x${rawValue.toString(16).padStart(pointerWidth * 2, "0")}`,
      target_address: `0x${(baseAddrResult.value + rawValue).toString(16)}`,
    });
  }

  // Batch every per-entry provider call: offsets and xrefs once per unique
  // address, previews once per unique target, all issued together.
  const allAddresses = rawEntries.flatMap((entry) => [
    entry.entry_address,
    entry.target_address,
  ]);
  const uniqueTargets = [...new Set(rawEntries.map((e) => e.target_address))];
  const readPreview = async (
    targetAddress: string,
  ): Promise<{
    readonly text: string | null;
    readonly truncated: boolean;
    readonly bytesHex: string | null;
    readonly byteLength: number | null;
  }> => {
    if (input.preview_bytes <= 0) {
      return { text: null, truncated: false, bytesHex: null, byteLength: null };
    }
    const targetRead = await callOperation(
      analysis,
      "read_bytes",
      { address: targetAddress, length: input.preview_bytes },
      signal,
    );
    if (!targetRead.ok) {
      return { text: null, truncated: false, bytesHex: null, byteLength: null };
    }
    const parsedTargetRead = readBytesResponseSchema.safeParse(
      targetRead.value,
    );
    if (
      !parsedTargetRead.success ||
      parsedTargetRead.data.bytes_hex.length === 0
    ) {
      return { text: null, truncated: false, bytesHex: null, byteLength: null };
    }
    const targetBuf = Buffer.from(parsedTargetRead.data.bytes_hex, "hex");
    const decoded = decodeScanText(targetBuf, {
      encoding: input.encoding,
      terminatorByte,
      customTable,
      words,
      controlCodes,
    });
    return {
      text: decoded.text,
      truncated: decodeWindowTruncated(
        targetBuf,
        decoded.byteLength,
        terminatorByte,
        true,
      ),
      bytesHex: input.include_hex
        ? decoded.rawHex.replace(/\s+/gu, "").toLowerCase()
        : null,
      byteLength: decoded.byteLength,
    };
  };
  const [scanOffsets, scanXrefs, previewValues] = await Promise.all([
    resolveFileOffsetsBatched(analysis, allAddresses, signal),
    resolveXrefsBatched(analysis, allAddresses, input.resolve_xrefs, signal),
    Promise.all(uniqueTargets.map(readPreview)),
  ]);
  const previewsByTarget = new Map(
    uniqueTargets.map((address, index) => [address, previewValues[index]!]),
  );
  const entries = rawEntries.map((entry) => {
    const preview = previewsByTarget.get(entry.target_address) ?? {
      text: null,
      truncated: false,
      bytesHex: null,
      byteLength: null,
    };
    return {
      index: entry.index,
      entry_address: entry.entry_address,
      entry_file_offset: scanOffsets.get(entry.entry_address) ?? null,
      raw_pointer: entry.raw_pointer,
      target_address: entry.target_address,
      target_file_offset: scanOffsets.get(entry.target_address) ?? null,
      preview_text: preview.text,
      ...(preview.truncated ? { preview_truncated: true } : {}),
      preview_bytes_hex: preview.bytesHex,
      preview_byte_length: preview.byteLength,
      entry_xrefs: [...(scanXrefs.get(entry.entry_address) ?? [])],
      target_xrefs: [...(scanXrefs.get(entry.target_address) ?? [])],
    };
  });

  const budgets = computePointerSlotBudgets(entries);
  const enrichedEntries = entries.map((entry, idx) => ({
    ...entry,
    allocated_budget_bytes: budgets[idx] ?? null,
  }));
  const wantsManuscript = input.include_manuscript || input.manuscript_only;
  // Manuscript text is decoded to its terminator (not the preview cap),
  // with one batched read per unique target.
  const fullByTarget = new Map<
    string,
    {
      text: string;
      byteLength: number;
      truncated: boolean;
      display: RomTextWithControlCodes | undefined;
    }
  >();
  if (wantsManuscript) {
    const readFull = async (
      targetAddress: string,
    ): Promise<{
      text: string;
      byteLength: number;
      truncated: boolean;
      display: RomTextWithControlCodes | undefined;
    } | null> => {
      const fullRead = await callOperation(
        analysis,
        "read_bytes",
        { address: targetAddress, length: MANUSCRIPT_MAX_BYTES },
        signal,
      );
      if (!fullRead.ok) return null;
      const parsedFull = readBytesResponseSchema.safeParse(fullRead.value);
      if (!parsedFull.success || parsedFull.data.bytes_hex.length === 0) {
        return null;
      }
      const buf = Buffer.from(parsedFull.data.bytes_hex, "hex");
      const decoded = decodeScanText(buf, {
        encoding: input.encoding,
        terminatorByte,
        customTable,
        words,
        controlCodes,
      });
      return {
        text: decoded.text,
        byteLength: decoded.byteLength,
        display: decoded.display,
        truncated: decodeWindowTruncated(
          buf,
          decoded.byteLength,
          terminatorByte,
          true,
        ),
      };
    };
    const fullValues = await Promise.all(uniqueTargets.map(readFull));
    uniqueTargets.forEach((address, index) => {
      const full = fullValues[index];
      if (full !== null && full !== undefined) {
        fullByTarget.set(`addr:${address}`, full);
      }
    });
  }
  const manuscriptRecords = wantsManuscript
    ? dedupManuscriptRecords(
        enrichedEntries.map((entry) => {
          const full = fullByTarget.get(`addr:${entry.target_address}`);
          return {
            id: `ptr_${entry.index.toString().padStart(4, "0")}`,
            index: entry.index,
            pointer_address: entry.entry_address,
            pointer_file_offset: entry.entry_file_offset,
            target_address: entry.target_address,
            target_file_offset: entry.target_file_offset,
            byte_length: full?.byteLength ?? entry.preview_byte_length,
            max_bytes: entry.allocated_budget_bytes,
            jp: full?.text ?? entry.preview_text ?? "",
            ...(full?.truncated ? { truncated: true } : {}),
            ...manuscriptDisplayFields(full?.display),
            ko: "",
          };
        }),
      )
    : undefined;

  return ok({
    table_address: `0x${tableAddrResult.value.toString(16)}`,
    pointer_size: pointerWidth,
    endian,
    base_address: `0x${baseAddrResult.value.toString(16)}`,
    stride,
    encoding: input.encoding,
    entries: input.manuscript_only ? [] : enrichedEntries,
    entries_scanned: enrichedEntries.length,
    start_index: input.start_index,
    next_start_index: input.start_index + enrichedEntries.length,
    ...(manuscriptRecords === undefined
      ? {}
      : { manuscript_records: manuscriptRecords }),
  });
};

/** Summary of a scan_pointer_table run written to a JSON Lines file. */
export type ScanPointerTableExportSummary = {
  readonly table_address: string;
  readonly table_file_offset: number | null;
  readonly pointer_size: 2 | 3 | 4;
  readonly endian: "little" | "big";
  readonly base_address: string;
  readonly stride: number;
  readonly encoding: RomTextEncoding;
  readonly entries_scanned: number;
  readonly record_kind: "entry" | "manuscript";
  readonly orphan_strings?: JsonValue;
  readonly coverage?: PointerTableCoverage | null;
  readonly source?: RomByteSourceDescription;
};

/**
 * Run scan_pointer_table over local bytes and stream each entry (or manuscript
 * record when include_manuscript / manuscript_only is set) as a JSON Lines record.
 */
export const exportScanPointerTable = async (
  input: ScanPointerTableInput,
  target: RomToolTarget,
  write: (record: Readonly<Record<string, JsonValue>>) => Promise<void>,
  signal?: AbortSignal,
): Promise<Result<ScanPointerTableExportSummary, AnalysisError>> => {
  const operation = "scan_pointer_table";
  if (input.resolve_xrefs) {
    return err(
      new AnalysisInputError(operation, {
        userMessage:
          "File export writes every entry from local bytes; resolve_xrefs does not apply.",
      }),
    );
  }
  const providerFreePort: AnalysisOperationPort = {
    execute: (op) =>
      Promise.resolve(
        err(
          new AnalysisInputError(op, {
            userMessage:
              "File export needs local file bytes (a console ROM, raw binary, or data file).",
          }),
        ),
      ),
  };
  const scanned = await executeScanPointerTable(
    providerFreePort,
    input,
    signal,
    target,
  );
  if (!scanned.ok) return scanned;
  const data = scanned.value as Record<string, JsonValue>;
  const wantsManuscript = input.include_manuscript || input.manuscript_only;
  const records = (wantsManuscript ? data.manuscript_records : data.entries) as
    | ReadonlyArray<Readonly<Record<string, JsonValue>>>
    | undefined;
  for (const record of records ?? []) {
    if (signal?.aborted === true) {
      return err(
        new AnalysisInputError(operation, {
          userMessage: "Export was cancelled.",
        }),
      );
    }
    await write(record);
  }
  return ok({
    table_address: String(data.table_address ?? "0x0"),
    table_file_offset:
      typeof data.table_file_offset === "number"
        ? data.table_file_offset
        : null,
    pointer_size: input.pointer_size,
    endian: input.endian,
    base_address: String(data.base_address ?? input.base_address),
    stride: input.stride ?? input.pointer_size,
    encoding: input.encoding,
    entries_scanned:
      typeof data.entries_scanned === "number" ? data.entries_scanned : 0,
    record_kind: wantsManuscript ? "manuscript" : "entry",
    ...(!wantsManuscript && data.orphan_strings !== undefined
      ? { orphan_strings: data.orphan_strings }
      : {}),
    ...(data.coverage !== undefined
      ? { coverage: data.coverage as PointerTableCoverage | null }
      : {}),
    ...(data.source !== undefined
      ? { source: data.source as RomByteSourceDescription }
      : {}),
  });
};

const isLikelyValidDecodedTarget = (
  bytes: Uint8Array,
  encoding: RomTextEncoding,
  terminatorByte: number | null,
  minStringLength: number,
  customTable: CustomCharTable | undefined,
  words: RomWordFormat | undefined,
  controlCodes?: RomControlCodeTable,
): {
  readonly valid: boolean;
  readonly text: string;
  readonly byteLength: number;
} => {
  if (bytes.length === 0) {
    return { valid: false, text: "", byteLength: 0 };
  }
  const canonical = normalizeRomTextEncoding(encoding);
  if (
    terminatorByte !== null &&
    bytes[0] === terminatorByte &&
    !(
      canonical === "tbl" &&
      terminatorByte === 0x00 &&
      customTable?.decodeByLength.get(1)?.has(0) === true &&
      !customTable.endTokens.has(0)
    )
  ) {
    return { valid: false, text: "", byteLength: 0 };
  }

  const extracted = extractRomStringsFromBuffer({
    bytes: bytes.subarray(0, Math.min(bytes.length, 96)),
    baseAddress: 0n,
    encoding,
    minLength: minStringLength,
    terminatorByte,
    customTable,
    words,
    controlCodes,
    // A pointer target is a string start, so only the even word parity
    // relative to the target is meaningful.
    wordParity: "even",
    limit: 1,
    includeRawHex: false,
  });
  const first = extracted[0];
  if (first === undefined || first.offsetInBuffer !== 0) {
    return { valid: false, text: "", byteLength: 0 };
  }
  return {
    valid: true,
    text: first.decoded,
    byteLength: first.byteLength,
  };
};

export const executeDiscoverPointerTables = async (
  analysis: AnalysisOperationPort,
  input: DiscoverPointerTablesInput,
  signal?: AbortSignal,
  target?: RomToolTarget,
): EnhancedResult => {
  const terminatorByte =
    input.terminator_byte === undefined ? 0x00 : input.terminator_byte;
  const baseAddrResult = parseHexAddressBigInt(
    "discover_pointer_tables",
    "base_address",
    input.base_address,
  );
  if (!baseAddrResult.ok) return baseAddrResult;

  const stride = input.stride ?? input.pointer_size;
  if (stride < input.pointer_size) {
    return err(
      new AnalysisInputError("discover_pointer_tables", {
        userMessage: `stride (${String(stride)}) must be greater than or equal to pointer_size (${String(input.pointer_size)}).`,
      }),
    );
  }
  const pointerBaseResult = resolvePointerBase(
    "discover_pointer_tables",
    input,
    baseAddrResult.value,
  );
  if (!pointerBaseResult.ok) return pointerBaseResult;
  const pointerBase = pointerBaseResult.value;

  const tableResult = await loadCustomTable(
    "discover_pointer_tables",
    input.encoding,
    input.table_path,
    input.table_text,
  );
  if (!tableResult.ok) return tableResult;
  const customTable = tableResult.value;
  const wordsResult = loadWordFormat(
    "discover_pointer_tables",
    input,
    terminatorByte,
    customTable,
  );
  if (!wordsResult.ok) return wordsResult;
  const words = wordsResult.value;
  const unit = resolveTerminatorUnit(input.encoding, terminatorByte, words);
  if (input.target_after_terminator && unit === undefined)
    return err(
      new AnalysisInputError("discover_pointer_tables", {
        userMessage:
          "target_after_terminator needs a terminator: terminator_byte, or terminator_word for word encodings.",
      }),
    );
  const localRom = await loadLocalRomContext(target);
  if (pointerBase.mode === "segment" && localRom === undefined)
    return err(
      new AnalysisInputError("discover_pointer_tables", {
        userMessage: SEGMENT_NEEDS_LOCAL_BYTES,
      }),
    );
  if (
    input.min_coverage !== undefined &&
    (localRom === undefined || unit === undefined)
  )
    return err(
      new AnalysisInputError("discover_pointer_tables", {
        userMessage:
          "min_coverage needs local file bytes and a terminator (terminator_byte, or terminator_word for word encodings).",
      }),
    );

  let romBuffer: Uint8Array;
  let scanStartOffset = 0;
  let scanEndOffset = 0;
  let toFileOffset: (vaddr: bigint, entryFileOffset?: number) => number | null;
  let toVirtualAddress: (fileOffset: number) => string | null;

  if (localRom !== undefined) {
    romBuffer = localRom.romBytes;
    if (
      pointerBase.mode === "segment" &&
      "start" in pointerBase &&
      input.start_offset === undefined &&
      input.start_address === undefined &&
      input.end_offset === undefined
    ) {
      // One segment and no explicit range: scan the segment itself.
      scanStartOffset = Math.min(pointerBase.start, romBuffer.length);
      scanEndOffset = Math.min(
        romBuffer.length,
        pointerBase.start + pointerBase.length,
      );
    } else {
      if (input.start_offset !== undefined) {
        scanStartOffset = Math.min(input.start_offset, romBuffer.length);
      } else if (input.start_address !== undefined) {
        const parsedStart = parseHexAddressBigInt(
          "discover_pointer_tables",
          "start_address",
          input.start_address,
        );
        if (!parsedStart.ok) return parsedStart;
        const resolved = localRom.toFileOffset(parsedStart.value);
        if (resolved === null) {
          return err(
            new AnalysisInputError("discover_pointer_tables", {
              userMessage: `start_address ${input.start_address} does not map to a file offset in this ROM.`,
            }),
          );
        }
        scanStartOffset = Math.min(resolved, romBuffer.length);
      }
      scanEndOffset =
        input.end_offset !== undefined
          ? Math.min(input.end_offset, romBuffer.length)
          : Math.min(romBuffer.length, scanStartOffset + input.length);
    }
    toFileOffset = localRom.toFileOffset;
    toVirtualAddress = localRom.toVirtualAddress;
  } else {
    const startAddrStr =
      input.start_address ?? `0x${(input.start_offset ?? 0).toString(16)}`;
    const parsedStart = parseHexAddressBigInt(
      "discover_pointer_tables",
      "start_address",
      startAddrStr,
    );
    if (!parsedStart.ok) return parsedStart;
    const baseReadAddr = parsedStart.value;
    const readLen =
      input.end_offset !== undefined && input.start_offset !== undefined
        ? Math.max(16, input.end_offset - input.start_offset)
        : input.length;
    const readRes = await callOperation(
      analysis,
      "read_bytes",
      { address: startAddrStr, length: readLen },
      signal,
    );
    if (!readRes.ok) return readRes;
    const parsedRead = readBytesResponseSchema.safeParse(readRes.value);
    if (!parsedRead.success) {
      return err(
        new AnalysisOutputError(
          "read_bytes",
          "Provider returned an invalid byte read result",
          { cause: parsedRead.error },
        ),
      );
    }
    romBuffer = Buffer.from(parsedRead.data.bytes_hex, "hex");
    scanStartOffset = 0;
    scanEndOffset = romBuffer.length;
    toFileOffset = (vaddr) => {
      const rel = vaddr - baseReadAddr;
      return rel >= 0n && rel < BigInt(romBuffer.length) ? Number(rel) : null;
    };
    toVirtualAddress = (fileOffset) =>
      `0x${(baseReadAddr + BigInt(fileOffset)).toString(16)}`;
  }

  const pointerWidth = input.pointer_size;
  const endian = input.endian;
  let effectiveBaseAddr = baseAddrResult.value;
  let inferredBaseAddress: string | null | undefined;
  let inferredBaseCandidates: readonly InferredBaseCandidate[] | undefined;

  const targetCache = new Map<
    number,
    {
      readonly valid: boolean;
      readonly text: string;
      readonly byteLength: number;
    }
  >();
  // With target_after_terminator, targets are sentence starts, empty ones included.
  const sentenceUnit = input.target_after_terminator ? unit : undefined;

  const checkTargetOffset = (
    targetFileOffset: number,
  ): {
    readonly valid: boolean;
    readonly text: string;
    readonly byteLength: number;
  } => {
    const cached = targetCache.get(targetFileOffset);
    if (cached !== undefined) return cached;
    if (targetFileOffset < 0 || targetFileOffset >= romBuffer.length) {
      const invalid = { valid: false, text: "", byteLength: 0 };
      targetCache.set(targetFileOffset, invalid);
      return invalid;
    }
    if (
      sentenceUnit !== undefined &&
      isTerminatorAt(romBuffer, targetFileOffset, sentenceUnit)
    ) {
      // An empty placeholder string; sentenceKind already placed it.
      const empty = { valid: true, text: "", byteLength: sentenceUnit.size };
      targetCache.set(targetFileOffset, empty);
      return empty;
    }
    const res = isLikelyValidDecodedTarget(
      romBuffer.subarray(
        targetFileOffset,
        Math.min(romBuffer.length, targetFileOffset + 96),
      ),
      input.encoding,
      terminatorByte,
      input.min_string_length,
      customTable,
      words,
    );
    targetCache.set(targetFileOffset, res);
    return res;
  };

  // Sentence starts: offsets right after a terminator (target_after_terminator).
  const sentenceStarts =
    sentenceUnit === undefined
      ? undefined
      : markSentenceStarts(romBuffer, sentenceUnit);

  if (input.infer_base_address && pointerBase.mode === "address") {
    const candidates = inferOverlayLoadAddress({
      bytes: romBuffer,
      scanStartOffset,
      scanEndOffset,
      pointerSize: pointerWidth,
      endian,
      stride,
      minEntries: input.min_entries,
      sentenceStarts,
      isValidStringStart: (fileOffset: number) => {
        if (
          sentenceUnit !== undefined &&
          isTerminatorAt(romBuffer, fileOffset, sentenceUnit)
        ) {
          return false;
        }
        return checkTargetOffset(fileOffset).valid;
      },
    });
    inferredBaseCandidates = candidates;
    const bestCandidate = candidates[0];
    inferredBaseAddress =
      bestCandidate !== undefined ? bestCandidate.base_address : null;
    if (effectiveBaseAddr === 0n && bestCandidate !== undefined) {
      effectiveBaseAddr = BigInt(bestCandidate.base_address);
    }
  }
  const segmentLength = pointerBase.mode === "segment" ? pointerBase.length : 0;
  // All-ones values end a table like 0 does (e.g. FFFF list ends).
  const endMarker = 256 ** pointerWidth - 1;

  /** Target file offset of one entry, or null when the value cannot point at text. */
  const entryTarget = (
    entryOffset: number,
    segmentStart: number | null,
  ): number | null => {
    if (segmentStart === null) {
      const rawVal = readPointerValue(
        romBuffer,
        entryOffset,
        pointerWidth,
        endian,
      );
      if (rawVal === 0n) return null;
      return resolvePointerTargetInFile(
        effectiveBaseAddr,
        rawVal,
        romBuffer.length,
        toFileOffset,
        entryOffset,
        localRom?.normalizePointerAddress,
      ).targetFileOffset;
    }
    const raw = readPointerNumber(romBuffer, entryOffset, pointerWidth, endian);
    if (raw === 0 || raw === endMarker || raw >= segmentLength) return null;
    const fileOffset = segmentStart + raw;
    return fileOffset < romBuffer.length ? fileOffset : null;
  };

  /**
   * 0: not a sentence start. 1: after a terminator, or the segment start.
   * 2: may be the first string after the table, which follows the last entry
   * instead of a terminator; every such entry must then point exactly where
   * the table ends.
   */
  const sentenceKind = (
    targetOffset: number,
    entryOffset: number,
    tableStart: number,
    segmentStart: number | null,
    tableEnd: number | null,
  ): 0 | 1 | 2 => {
    if (sentenceStarts === undefined) return 1;
    if (sentenceStarts[targetOffset] !== 0 || targetOffset === segmentStart)
      return 1;
    if (
      targetOffset > entryOffset &&
      (targetOffset - tableStart) % stride === 0 &&
      (tableEnd === null || tableEnd === targetOffset)
    )
      return 2;
    return 0;
  };

  type RunEntry = {
    readonly entryFileOffset: number;
    readonly targetFileOffset: number;
    readonly targetAddress: string;
    readonly text: string;
    readonly byteLength: number;
  };

  const MAX_TABLE_ENTRIES = 8192;
  const probeTargets = new Float64Array(MAX_TABLE_ENTRIES);
  // Per (segment start, entry residue): starts below this offset are known to
  // fail, because a later start of the same residue only sees a suffix of a
  // run that was already rejected.
  const deadUntil = new Map<number, number>();

  /** Distinct targets in probeTargets[from, to) that are not empty strings. */
  const distinctTextTargets = (from: number, to: number): number => {
    const seen = new Set<number>();
    for (let i = from; i < to && seen.size < 2; i++) {
      const targetOffset = probeTargets[i]!;
      if (
        sentenceUnit === undefined ||
        !isTerminatorAt(romBuffer, targetOffset, sentenceUnit)
      )
        seen.add(targetOffset);
    }
    return seen.size;
  };

  /**
   * Run of valid entries from tableStart when it is a table (at least
   * min_entries entries and two distinct targets); cheap checks first, then
   * decoding.
   */
  const probeRun = (
    tableStart: number,
    segmentStart: number | null,
  ): RunEntry[] | undefined => {
    const residue = tableStart % stride;
    const deadKey =
      segmentStart === null ? -1 - residue : segmentStart * stride + residue;
    if ((deadUntil.get(deadKey) ?? -1) > tableStart) return undefined;
    let count = 0;
    let tableEnd: number | null = null;
    let firstAfterTable = -1;
    let lastAfterTable = -1;
    let probeOffset = tableStart;
    while (
      probeOffset + pointerWidth <= scanEndOffset &&
      count < MAX_TABLE_ENTRIES &&
      (tableEnd === null || probeOffset < tableEnd)
    ) {
      const targetOffset = entryTarget(probeOffset, segmentStart);
      if (targetOffset === null) break;
      const kind = sentenceKind(
        targetOffset,
        probeOffset,
        tableStart,
        segmentStart,
        tableEnd,
      );
      if (kind === 0) break;
      if (kind === 2) {
        tableEnd = targetOffset;
        if (firstAfterTable === -1) firstAfterTable = count;
        lastAfterTable = count;
      }
      probeTargets[count++] = targetOffset;
      probeOffset += stride;
    }
    // Phase 2: decode targets; then the table must end where its first
    // after-table string begins.
    let length = 0;
    let decodedTo = count;
    let cutAtTableEnd = false;
    if (count >= input.min_entries) {
      while (length < count && checkTargetOffset(probeTargets[length]!).valid)
        length++;
      decodedTo = length;
      if (tableEnd !== null && tableStart + length * stride !== tableEnd) {
        length = Math.min(length, firstAfterTable);
        cutAtTableEnd = true;
      }
    }
    if (length >= input.min_entries && distinctTextTargets(0, length) >= 2) {
      deadUntil.delete(deadKey);
    } else {
      // A later start k entries on (same residue) sees probes[k..] while it
      // keeps the last after-table entry, so it is rejected whenever its
      // entries are a subset of rejected ones. A capped run may grow.
      let deadEntries = 1;
      if (count < MAX_TABLE_ENTRIES) {
        const sameProbes = lastAfterTable === -1 ? count : lastAfterTable + 1;
        if (count < input.min_entries || distinctTextTargets(0, count) < 2)
          deadEntries = sameProbes;
        else
          deadEntries = Math.min(
            sameProbes,
            decodedTo + 1,
            cutAtTableEnd ? firstAfterTable + 1 : count,
          );
      }
      deadUntil.set(deadKey, tableStart + Math.max(1, deadEntries) * stride);
      return undefined;
    }
    const run: RunEntry[] = [];
    for (let i = 0; i < length; i++) {
      const targetOffset = probeTargets[i]!;
      const checked = checkTargetOffset(targetOffset);
      const entryFileOffset = tableStart + i * stride;
      run.push({
        entryFileOffset,
        targetFileOffset: targetOffset,
        targetAddress:
          segmentStart === null
            ? resolvePointerTargetInFile(
                effectiveBaseAddr,
                readPointerValue(
                  romBuffer,
                  entryFileOffset,
                  pointerWidth,
                  endian,
                ),
                romBuffer.length,
                toFileOffset,
                entryFileOffset,
                localRom?.normalizePointerAddress,
              ).targetAddress
            : (toVirtualAddress(targetOffset) ??
              `0x${targetOffset.toString(16)}`),
        text: checked.text,
        byteLength: checked.byteLength,
      });
    }
    return run;
  };

  /** Cheap test of the first two entries against one segment start. */
  const firstEntriesFit = (
    tableStart: number,
    segmentStart: number,
    raw0: number,
    raw1: number,
  ): boolean => {
    const target0 = segmentStart + raw0;
    const target1 = segmentStart + raw1;
    if (target0 >= romBuffer.length || target1 >= romBuffer.length)
      return false;
    const kind0 = sentenceKind(
      target0,
      tableStart,
      tableStart,
      segmentStart,
      null,
    );
    if (kind0 === 0) return false;
    const second = tableStart + stride;
    if (kind0 === 2 && target0 <= second) return false;
    return (
      sentenceKind(
        target1,
        second,
        tableStart,
        segmentStart,
        kind0 === 2 ? target0 : null,
      ) !== 0
    );
  };

  type FoundTable = {
    readonly run: RunEntry[];
    readonly segmentStart: number | null;
    readonly coverage: PointerTableCoverage | null;
  };

  /** Coverage of an accepted run, and the min_coverage filter. */
  const judgeRun = (
    run: RunEntry[] | undefined,
    tableStart: number,
    segmentStart: number | null,
  ): FoundTable | undefined => {
    if (run === undefined) return undefined;
    const coverage =
      localRom === undefined || unit === undefined
        ? null
        : measurePointerTableCoverage({
            bytes: romBuffer,
            unit,
            targets: run.map((e) => e.targetFileOffset),
            tableEnd: tableStart + run.length * stride,
          });
    if (
      input.min_coverage !== undefined &&
      (coverage === null || coverage.ratio < input.min_coverage)
    )
      return undefined;
    return { run, segmentStart, coverage };
  };

  /** Longest table at tableStart and the segment start it is relative to. */
  const findRunAt = (tableStart: number): FoundTable | undefined => {
    if (pointerBase.mode === "address")
      return judgeRun(probeRun(tableStart, null), tableStart, null);
    if ("start" in pointerBase)
      return judgeRun(
        probeRun(tableStart, pointerBase.start),
        tableStart,
        pointerBase.start,
      );
    // Every aligned start whose segment still contains the table.
    const second = tableStart + stride;
    if (second + pointerWidth > scanEndOffset) return undefined;
    const raw0 = readPointerNumber(romBuffer, tableStart, pointerWidth, endian);
    const raw1 = readPointerNumber(romBuffer, second, pointerWidth, endian);
    if (
      raw0 === 0 ||
      raw1 === 0 ||
      raw0 === endMarker ||
      raw1 === endMarker ||
      raw0 >= segmentLength ||
      raw1 >= segmentLength
    )
      return undefined;
    let best: FoundTable | undefined;
    for (
      let segmentStart = tableStart - (tableStart % pointerBase.align);
      segmentStart >= 0 && tableStart - segmentStart < segmentLength;
      segmentStart -= pointerBase.align
    ) {
      if (!firstEntriesFit(tableStart, segmentStart, raw0, raw1)) continue;
      const found = judgeRun(
        probeRun(tableStart, segmentStart),
        tableStart,
        segmentStart,
      );
      if (
        found !== undefined &&
        (best === undefined ||
          found.run.length > best.run.length ||
          (found.run.length === best.run.length &&
            (found.coverage?.ratio ?? 0) > (best.coverage?.ratio ?? 0)))
      )
        best = found;
    }
    return best;
  };

  // Same pointer value repeated from an offset, per entry residue: a start
  // with MAX_TABLE_ENTRIES identical entries ahead can only be rejected.
  const identicalEnd: number[] = Array.from({ length: stride }, () => -1);
  const identicalAhead = (offset: number): number => {
    const residue = offset % stride;
    if (identicalEnd[residue]! <= offset) {
      const value = readPointerNumber(romBuffer, offset, pointerWidth, endian);
      let end = offset + stride;
      while (
        end + pointerWidth <= scanEndOffset &&
        readPointerNumber(romBuffer, end, pointerWidth, endian) === value
      )
        end += stride;
      identicalEnd[residue] = end;
    }
    return (identicalEnd[residue]! - offset) / stride;
  };

  const discoveredTables = [];
  const stepAlignment = pointerWidth === 4 ? 2 : 1;
  let cursor = scanStartOffset;

  while (
    cursor + input.min_entries * stride <= scanEndOffset &&
    discoveredTables.length < input.max_tables
  ) {
    const found =
      identicalAhead(cursor) >= MAX_TABLE_ENTRIES
        ? undefined
        : findRunAt(cursor);
    if (found !== undefined) {
      const { run: runEntries, segmentStart, coverage } = found;
      const uniqueTargets = new Set(runEntries.map((e) => e.targetFileOffset))
        .size;
      const tableFileOffset = cursor;
      const tableEnd = cursor + runEntries.length * stride;
      const tableAddress =
        effectiveBaseAddr > 0n && localRom?.source !== undefined
          ? `0x${(effectiveBaseAddr + BigInt(tableFileOffset)).toString(16)}`
          : (toVirtualAddress(tableFileOffset) ??
            `0x${tableFileOffset.toString(16)}`);
      const budgets = computePointerSlotBudgets(
        runEntries.map((e) => ({
          target_file_offset: e.targetFileOffset,
          target_address: e.targetAddress,
          preview_byte_length: e.byteLength,
        })),
      );
      const lengths = runEntries.map((e) => e.byteLength);
      const minBytes = Math.min(...lengths);
      const maxBytes = Math.max(...lengths);
      const avgBytes =
        Math.round(
          (lengths.reduce((acc, v) => acc + v, 0) / lengths.length) * 100,
        ) / 100;
      const samples = runEntries
        .slice(0, input.sample_entries)
        .map((e, idx) => ({
          index: idx,
          entry_address:
            effectiveBaseAddr > 0n && localRom?.source !== undefined
              ? `0x${(effectiveBaseAddr + BigInt(e.entryFileOffset)).toString(16)}`
              : (toVirtualAddress(e.entryFileOffset) ??
                `0x${e.entryFileOffset.toString(16)}`),
          target_address: e.targetAddress,
          target_file_offset: e.targetFileOffset,
          preview_text: e.text,
          byte_length: e.byteLength,
          allocated_budget_bytes: budgets[idx] ?? null,
        }));

      discoveredTables.push({
        table_address: tableAddress,
        table_file_offset: localRom !== undefined ? tableFileOffset : null,
        entry_count: runEntries.length,
        unique_targets: uniqueTargets,
        pointer_size: pointerWidth,
        stride,
        min_string_bytes: minBytes,
        max_string_bytes: maxBytes,
        avg_string_bytes: avgBytes,
        table_xrefs: [] as string[],
        samples,
        ...(segmentStart === null ? {} : { segment_start: segmentStart }),
        coverage,
      });
      cursor = tableEnd;
      continue;
    }

    cursor += stepAlignment;
  }
  const truncated =
    discoveredTables.length >= input.max_tables &&
    cursor + input.min_entries * stride <= scanEndOffset;

  const discoveredXrefs = await resolveXrefsBatched(
    analysis,
    discoveredTables.map((table) => table.table_address),
    input.resolve_xrefs,
    signal,
  );
  for (const table of discoveredTables) {
    Object.assign(table, {
      table_xrefs: [...(discoveredXrefs.get(table.table_address) ?? [])],
    });
  }

  return ok({
    encoding: input.encoding,
    pointer_size: pointerWidth,
    endian,
    base_address: `0x${effectiveBaseAddr.toString(16)}`,
    ...(inferredBaseAddress === undefined
      ? {}
      : { inferred_base_address: inferredBaseAddress }),
    ...(inferredBaseCandidates === undefined
      ? {}
      : { inferred_base_candidates: [...inferredBaseCandidates] }),
    stride,
    bytes_scanned: Math.max(0, scanEndOffset - scanStartOffset),
    base_mode: pointerBase.mode,
    ...(pointerBase.mode === "address"
      ? {}
      : "start" in pointerBase
        ? {
            segment_start: pointerBase.start,
            segment_length: pointerBase.length,
          }
        : {
            segment_align: pointerBase.align,
            segment_length: pointerBase.length,
          }),
    ...(input.target_after_terminator ? { target_after_terminator: true } : {}),
    ...(input.min_coverage === undefined
      ? {}
      : { min_coverage: input.min_coverage }),
    tables: discoveredTables,
    total_tables: discoveredTables.length,
    truncated,
    ...(truncated && localRom !== undefined
      ? { next_start_offset: cursor }
      : {}),
    ...sourceField(localRom),
  });
};

export const executeFindCodeCaves = async (
  analysis: AnalysisOperationPort,
  input: FindCodeCavesInput,
  signal?: AbortSignal,
  target?: RomToolTarget,
): EnhancedResult => {
  const localRom = await loadLocalRomContext(target);
  const rawCaves: {
    readonly address: string;
    readonly file_offset: number | null;
    readonly byte_length: number;
    readonly fill_byte: string;
    readonly region_name: string | null;
    readonly executable: boolean;
  }[] = [];
  let totalCavesFound = 0;
  const sortRawCaves = (): void => {
    rawCaves.sort(
      (a, b) =>
        b.byte_length - a.byte_length ||
        (a.file_offset ?? 0) - (b.file_offset ?? 0),
    );
  };
  const addCaves = (
    found: readonly (typeof rawCaves)[number][],
    total: number,
  ): void => {
    totalCavesFound += total;
    rawCaves.push(...found);
    if (rawCaves.length > input.max_results * 4) {
      sortRawCaves();
      rawCaves.length = input.max_results;
    }
  };

  if (localRom !== undefined) {
    const romBytes = localRom.romBytes;
    if (
      target !== undefined &&
      !isLocalByteSource(target) &&
      isConsoleBinaryTarget(target) &&
      input.start_offset === undefined &&
      input.end_offset === undefined &&
      input.start_address === undefined
    ) {
      const seenRanges = new Set<string>();
      for (const map of target.consoleRom.fileMappings) {
        if (input.executable_only && !map.executable) continue;
        const rangeKey = `${map.fileOffset}:${map.byteLength}`;
        if (seenRanges.has(rangeKey)) continue;
        seenRanges.add(rangeKey);
        const start = Math.min(map.fileOffset, romBytes.length);
        const end = Math.min(map.fileOffset + map.byteLength, romBytes.length);
        if (end <= start) continue;
        const mapStartVaddr = BigInt(map.virtualAddress);
        const found = findCodeCavesInSliceTopK({
          bytes: romBytes.subarray(start, end),
          sliceFileOffset: start,
          regionName: map.name,
          executable: map.executable,
          minSize: input.min_size,
          alignment: input.alignment,
          fillByte: input.fill_byte,
          toVirtualAddress: (fo) =>
            `0x${(mapStartVaddr + BigInt(fo - start)).toString(16)}`,
          limit: input.max_results,
        });
        addCaves(found.caves, found.total);
      }
    } else {
      let startOffset = input.start_offset ?? 0;
      if (
        input.start_offset === undefined &&
        input.start_address !== undefined
      ) {
        const parsedAddr = parseHexAddressBigInt(
          "find_code_caves",
          "start_address",
          input.start_address,
        );
        if (!parsedAddr.ok) return parsedAddr;
        const resolved = localRom.toFileOffset(parsedAddr.value);
        if (resolved === null) {
          return err(
            new AnalysisInputError("find_code_caves", {
              userMessage: `start_address ${input.start_address} does not map to a file offset in this ROM.`,
            }),
          );
        }
        startOffset = resolved;
      }
      const endOffset =
        input.end_offset !== undefined
          ? Math.min(input.end_offset, romBytes.length)
          : romBytes.length;
      const found = findCodeCavesInSliceTopK({
        bytes: romBytes.subarray(
          Math.min(startOffset, romBytes.length),
          Math.max(Math.min(startOffset, romBytes.length), endOffset),
        ),
        sliceFileOffset: startOffset,
        regionName:
          localRom.source !== undefined
            ? "DATA"
            : target !== undefined &&
                !isLocalByteSource(target) &&
                isConsoleBinaryTarget(target)
              ? (target.consoleRom.fileMappings[0]?.name ?? "ROM")
              : "RAW_BINARY",
        executable: true,
        minSize: input.min_size,
        alignment: input.alignment,
        fillByte: input.fill_byte,
        toVirtualAddress: localRom.toVirtualAddress,
        limit: input.max_results,
      });
      addCaves(found.caves, found.total);
    }
  } else {
    const startAddrStr =
      input.start_address ?? `0x${(input.start_offset ?? 0).toString(16)}`;
    const parsedAddr = parseHexAddressBigInt(
      "find_code_caves",
      "start_address",
      startAddrStr,
    );
    if (!parsedAddr.ok) return parsedAddr;
    const baseAddr = parsedAddr.value;
    const readLen =
      input.end_offset !== undefined && input.start_offset !== undefined
        ? Math.max(16, input.end_offset - input.start_offset)
        : input.length;
    const readRes = await callOperation(
      analysis,
      "read_bytes",
      { address: startAddrStr, length: readLen },
      signal,
    );
    if (!readRes.ok) return readRes;
    const parsedRead = readBytesResponseSchema.safeParse(readRes.value);
    if (!parsedRead.success) {
      return err(
        new AnalysisOutputError(
          "read_bytes",
          "Provider returned an invalid byte read result",
          { cause: parsedRead.error },
        ),
      );
    }
    const buffer = Buffer.from(parsedRead.data.bytes_hex, "hex");
    const found = findCodeCavesInSliceTopK({
      bytes: buffer,
      sliceFileOffset: 0,
      regionName: null,
      executable: true,
      minSize: input.min_size,
      alignment: input.alignment,
      fillByte: input.fill_byte,
      toVirtualAddress: (fo) => `0x${(baseAddr + BigInt(fo)).toString(16)}`,
      limit: input.max_results,
    });
    // Provider file offsets are resolved below, only for returned caves.
    addCaves(
      found.caves.map((cave) => ({ ...cave, file_offset: null })),
      found.total,
    );
  }

  sortRawCaves();

  const selected = rawCaves.slice(0, input.max_results);
  const selectedAddresses = selected.map((item) => item.address);
  const needsProviderOffsets = localRom === undefined && selected.length > 0;
  const [caveOffsets, caveXrefs] = await Promise.all([
    needsProviderOffsets
      ? resolveFileOffsetsBatched(analysis, selectedAddresses, signal)
      : Promise.resolve(new Map<string, number | null>()),
    resolveXrefsBatched(
      analysis,
      selectedAddresses,
      input.resolve_xrefs,
      signal,
    ),
  ]);
  const caves = selected.map((item) => ({
    ...item,
    ...(needsProviderOffsets
      ? { file_offset: caveOffsets.get(item.address) ?? null }
      : {}),
    xrefs: [...(caveXrefs.get(item.address) ?? [])],
  }));

  return ok({
    min_size: input.min_size,
    alignment: input.alignment,
    caves,
    total_caves: totalCavesFound,
    ...sourceField(localRom),
  });
};
