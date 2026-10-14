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
} from "../../domain/consoleRom.js";
import {
  computePointerSlotBudgets,
  decodeRomStringFromBytes,
  encodeRomQueryString,
  extractRomStringsFromBuffer,
  findCodeCavesInSliceTopK,
  formatHexPattern,
  normalizeRomTextEncoding,
  parseCustomCharTable,
  readPointerValue,
  type CustomCharTable,
  type DiscoverPointerTablesInput,
  type FindCodeCavesInput,
  type RomTextEncoding,
  type ScanPointerTableInput,
  type SearchRomStringsInput,
} from "../../domain/romHacking.js";
import type { JsonValue } from "../../domain/jsonValue.js";
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
}

const ROM_BYTES_CACHE_LIMIT = 4;
const romBytesCache = new Map<string, Buffer>();

/** ROM bytes keyed by the resolved target identity (path + content digest). */
const readRomBytesCached = async (
  target: BinaryTarget & { readonly path: string; readonly sha256: string },
): Promise<Buffer | undefined> => {
  const key = `${target.path}\0${target.sha256}`;
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
  romBytesCache.set(key, romBytes);
  while (romBytesCache.size > ROM_BYTES_CACHE_LIMIT) {
    const oldest = romBytesCache.keys().next().value;
    if (oldest === undefined) break;
    romBytesCache.delete(oldest);
  }
  return romBytes;
};

const loadLocalRomContext = async (
  target: BinaryTarget | undefined,
): Promise<LocalRomContext | undefined> => {
  if (
    target === undefined ||
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
    toFileOffset: (virtualAddress) => {
      const offset = Number(virtualAddress);
      return Number.isSafeInteger(offset) &&
        offset >= 0 &&
        offset < romBytes.length
        ? offset
        : null;
    },
    toVirtualAddress: (fileOffset) =>
      fileOffset >= 0 && fileOffset < romBytes.length
        ? `0x${fileOffset.toString(16)}`
        : null,
  };
};

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
  if (encoding === "tbl") {
    return err(
      new AnalysisInputError(operation, {
        userMessage: "encoding 'tbl' requires either table_path or table_text.",
      }),
    );
  }
  return ok(undefined);
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

/** Whether an extracted string ran to the scan-window edge without its terminator. */
const extractedTextTruncated = (
  bytes: Uint8Array,
  offsetInBuffer: number,
  byteLength: number,
  terminatorByte: number | null,
  windowMayContinue: boolean,
): boolean => {
  if (!windowMayContinue || byteLength <= 0) return false;
  const end = offsetInBuffer + byteLength;
  if (end < bytes.length) return false;
  return !(terminatorByte !== null && bytes[end - 1] === terminatorByte);
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

export const executeSearchRomStrings = async (
  analysis: AnalysisOperationPort,
  input: SearchRomStringsInput,
  signal?: AbortSignal,
  target?: BinaryTarget,
): EnhancedResult => {
  const terminatorByte =
    input.terminator_byte === undefined ? 0x00 : input.terminator_byte;
  const tableResult = await loadCustomTable(
    "search_rom_strings",
    input.encoding,
    input.table_path,
    input.table_text,
  );
  if (!tableResult.ok) return tableResult;
  const customTable = tableResult.value;
  const localRom = await loadLocalRomContext(target);
  // Provider query search uses the provider's own opaque cursor verbatim;
  // local and range scans use a numeric resume offset.
  const usesProviderCursor =
    input.query !== undefined && localRom === undefined;
  let pageCursor = 0;
  if (!usesProviderCursor) {
    const cursorResult = parseRomCursor("search_rom_strings", input.cursor);
    if (!cursorResult.ok) return cursorResult;
    pageCursor = cursorResult.value;
  }

  if (input.query !== undefined) {
    const encodedResult = encodeRomQueryString(
      input.query,
      input.encoding,
      customTable,
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
      const needle = Buffer.from(encodedResult.value);
      let searchStart = 0;
      if (input.start_offset !== undefined) {
        searchStart = Math.min(input.start_offset, localRom.romBytes.length);
      } else if (input.start_address !== undefined) {
        const parsedStart = parseHexAddressBigInt(
          "search_rom_strings",
          "start_address",
          input.start_address,
        );
        if (!parsedStart.ok) return parsedStart;
        const resolved = localRom.toFileOffset(parsedStart.value);
        if (resolved !== null) {
          searchStart = Math.min(resolved, localRom.romBytes.length);
        }
      }
      const searchEnd =
        input.end_offset !== undefined
          ? Math.min(input.end_offset, localRom.romBytes.length)
          : localRom.romBytes.length;

      // Count every match in the range (native indexOf) while collecting
      // only this page, starting at the cursor's file offset.
      const pageStart = Math.max(searchStart, pageCursor);
      const foundOffsets: number[] = [];
      let totalMatches = 0;
      let nextCursor: string | null = null;
      let scanAt = searchStart;
      while (scanAt + needle.length <= searchEnd) {
        const idx = localRom.romBytes.indexOf(needle, scanAt);
        if (idx === -1 || idx + needle.length > searchEnd) break;
        totalMatches++;
        if (idx >= pageStart) {
          if (foundOffsets.length < input.max_results) {
            foundOffsets.push(idx);
          } else if (nextCursor === null) {
            nextCursor = String(idx);
          }
        }
        scanAt = idx + 1;
      }
      const truncated = nextCursor !== null;

      const pendingMatches = [];
      for (const fileOffset of foundOffsets) {
        const address =
          localRom.toVirtualAddress(fileOffset) ??
          `0x${fileOffset.toString(16)}`;
        const buf = localRom.romBytes.subarray(
          fileOffset,
          Math.min(localRom.romBytes.length, fileOffset + 128),
        );
        const decoded = decodeRomStringFromBytes(
          buf,
          input.encoding,
          terminatorByte,
          customTable,
        );
        const text = decoded.decoded.length > 0 ? decoded.decoded : input.query;
        const bytesHex =
          decoded.decoded.length > 0
            ? decoded.rawHex.replace(/\s+/gu, "").toLowerCase()
            : needle.toString("hex");
        const byteLength =
          decoded.decoded.length > 0 ? decoded.byteLength : needle.length;
        const terminated =
          terminatorByte !== null
            ? decoded.byteLength < buf.length || buf.includes(terminatorByte)
            : decoded.byteLength < buf.length;
        const textTruncated =
          !terminated && fileOffset + buf.length < localRom.romBytes.length;
        pendingMatches.push({
          address,
          file_offset: fileOffset,
          encoding: input.encoding,
          text,
          ...(textTruncated ? { text_truncated: true } : {}),
          ...(input.include_hex ? { bytes_hex: bytesHex } : {}),
          byte_length: byteLength,
          terminated,
        });
      }
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
        truncated,
        next_cursor: nextCursor,
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
          );
          if (decoded.decoded.length > 0) {
            text = decoded.decoded;
            bytesHex = decoded.rawHex.replace(/\s+/gu, "").toLowerCase();
            byteLength = decoded.byteLength;
            terminated =
              terminatorByte !== null
                ? decoded.byteLength < buf.length ||
                  buf.includes(terminatorByte)
                : decoded.byteLength < buf.length;
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
    let startOffset = input.start_offset ?? 0;
    let baseAddrBigInt = BigInt(startOffset);
    if (input.start_offset === undefined && input.start_address !== undefined) {
      const parsedAddr = parseHexAddressBigInt(
        "search_rom_strings",
        "start_address",
        input.start_address,
      );
      if (!parsedAddr.ok) return parsedAddr;
      baseAddrBigInt = parsedAddr.value;
      const resolved = localRom.toFileOffset(parsedAddr.value);
      if (resolved === null) {
        return err(
          new AnalysisInputError("search_rom_strings", {
            userMessage: `start_address ${input.start_address} does not map to a file offset in this ROM.`,
          }),
        );
      }
      startOffset = resolved;
    } else if (input.start_offset !== undefined) {
      const resolvedVaddr = localRom.toVirtualAddress(input.start_offset);
      if (resolvedVaddr !== null) {
        baseAddrBigInt = BigInt(resolvedVaddr);
      }
    }

    const scanLength =
      input.end_offset !== undefined
        ? Math.max(0, input.end_offset - startOffset)
        : input.length;
    const slice = localRom.romBytes.subarray(
      Math.min(startOffset, localRom.romBytes.length),
      Math.min(localRom.romBytes.length, startOffset + scanLength),
    );
    const probed = extractRomStringsFromBuffer({
      bytes: slice,
      baseAddress: baseAddrBigInt,
      encoding: input.encoding,
      minLength: input.min_length,
      terminatorByte,
      customTable,
      limit: input.max_results + 1,
      includeRawHex: input.include_hex,
      startOffset: pageCursor,
    });
    const rangeTruncated = probed.length > input.max_results;
    const extracted = rangeTruncated
      ? probed.slice(0, input.max_results)
      : probed;
    const rangeNextCursor = rangeTruncated
      ? String(probed[input.max_results]!.offsetInBuffer)
      : null;

    const sliceMayContinue =
      startOffset + slice.length < localRom.romBytes.length;
    const pendingMatches = extracted.map((item) => {
      const fileOffset = startOffset + item.offsetInBuffer;
      return {
        address: localRom.toVirtualAddress(fileOffset) ?? item.address,
        file_offset: fileOffset,
        encoding: input.encoding,
        text: item.decoded,
        ...(extractedTextTruncated(
          slice,
          item.offsetInBuffer,
          item.byteLength,
          terminatorByte,
          sliceMayContinue,
        )
          ? { text_truncated: true }
          : {}),
        ...(input.include_hex
          ? { bytes_hex: item.rawHex.replace(/\s+/gu, "").toLowerCase() }
          : {}),
        byte_length: item.byteLength,
        terminated: true,
      };
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
      truncated: rangeTruncated,
      next_cursor: rangeNextCursor,
    });
  }

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
  const probed = extractRomStringsFromBuffer({
    bytes: buffer,
    baseAddress: baseAddrResult.value,
    encoding: input.encoding,
    minLength: input.min_length,
    terminatorByte,
    customTable,
    limit: input.max_results + 1,
    includeRawHex: input.include_hex,
    startOffset: pageCursor,
  });
  const rangeTruncated = probed.length > input.max_results;
  const extracted = rangeTruncated
    ? probed.slice(0, input.max_results)
    : probed;
  const rangeNextCursor = rangeTruncated
    ? String(probed[input.max_results]!.offsetInBuffer)
    : null;

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
    address: item.address,
    file_offset: providerOffsets.get(item.address) ?? null,
    encoding: input.encoding,
    text: item.decoded,
    ...(extractedTextTruncated(
      buffer,
      item.offsetInBuffer,
      item.byteLength,
      terminatorByte,
      true,
    )
      ? { text_truncated: true }
      : {}),
    ...(input.include_hex
      ? { bytes_hex: item.rawHex.replace(/\s+/gu, "").toLowerCase() }
      : {}),
    byte_length: item.byteLength,
    terminated: true,
    xrefs: [...(providerXrefs.get(item.address) ?? [])],
  }));

  return ok({
    mode: "range_scan",
    encoding: input.encoding,
    encoded_query_pattern: null,
    matches,
    total_matches: matches.length,
    truncated: rangeTruncated,
    next_cursor: rangeNextCursor,
  });
};

export const executeScanPointerTable = async (
  analysis: AnalysisOperationPort,
  input: ScanPointerTableInput,
  signal?: AbortSignal,
  target?: BinaryTarget,
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

  const tableResult = await loadCustomTable(
    "scan_pointer_table",
    input.encoding,
    input.table_path,
    input.table_text,
  );
  if (!tableResult.ok) return tableResult;
  const customTable = tableResult.value;
  const localRom = await loadLocalRomContext(target);

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
        const targetAddrBigInt = baseAddrResult.value + rawValue;
        const targetAddress = `0x${targetAddrBigInt.toString(16)}`;
        const rawPointer = `0x${rawValue.toString(16).padStart(pointerWidth * 2, "0")}`;
        const targetFileOffset = localRom.toFileOffset(
          targetAddrBigInt,
          entryFileOffset,
        );

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
            const decoded = decodeRomStringFromBytes(
              targetBuf,
              input.encoding,
              terminatorByte,
              customTable,
            );
            previewText = decoded.decoded;
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

      const budgets = computePointerSlotBudgets(entries);
      const enrichedEntries = entries.map((entry, idx) => ({
        ...entry,
        allocated_budget_bytes: budgets[idx] ?? null,
      }));
      const wantsManuscript = input.include_manuscript || input.manuscript_only;
      // Manuscript text is decoded to its terminator (not the preview cap),
      // once per unique target.
      const fullByTarget = new Map<
        string,
        { text: string; byteLength: number; truncated: boolean }
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
          const decoded = decodeRomStringFromBytes(
            buf,
            input.encoding,
            terminatorByte,
            customTable,
          );
          fullByTarget.set(key, {
            text: decoded.decoded,
            byteLength: decoded.byteLength,
            truncated: decodeWindowTruncated(
              buf,
              decoded.byteLength,
              terminatorByte,
              off + buf.length < localRom.romBytes.length,
            ),
          });
        }
      }
      const manuscriptRecords = wantsManuscript
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
                ko: "",
              };
            }),
          )
        : undefined;

      return ok({
        table_address: `0x${tableAddrBigInt.toString(16)}`,
        table_file_offset: tableFileOffset,
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
    }
  }

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
    const decoded = decodeRomStringFromBytes(
      targetBuf,
      input.encoding,
      terminatorByte,
      customTable,
    );
    return {
      text: decoded.decoded,
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
    { text: string; byteLength: number; truncated: boolean }
  >();
  if (wantsManuscript) {
    const readFull = async (
      targetAddress: string,
    ): Promise<{
      text: string;
      byteLength: number;
      truncated: boolean;
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
      const decoded = decodeRomStringFromBytes(
        buf,
        input.encoding,
        terminatorByte,
        customTable,
      );
      return {
        text: decoded.decoded,
        byteLength: decoded.byteLength,
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

const isLikelyValidDecodedTarget = (
  bytes: Uint8Array,
  encoding: RomTextEncoding,
  terminatorByte: number | null,
  minStringLength: number,
  customTable?: CustomCharTable,
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
  target?: BinaryTarget,
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

  const tableResult = await loadCustomTable(
    "discover_pointer_tables",
    input.encoding,
    input.table_path,
    input.table_text,
  );
  if (!tableResult.ok) return tableResult;
  const customTable = tableResult.value;
  const localRom = await loadLocalRomContext(target);

  let romBuffer: Uint8Array;
  let scanStartOffset = 0;
  let scanEndOffset = 0;
  let toFileOffset: (vaddr: bigint, entryFileOffset?: number) => number | null;
  let toVirtualAddress: (fileOffset: number) => string | null;

  if (localRom !== undefined) {
    romBuffer = localRom.romBytes;
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
  const targetCache = new Map<
    number,
    {
      readonly valid: boolean;
      readonly text: string;
      readonly byteLength: number;
    }
  >();

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
    const res = isLikelyValidDecodedTarget(
      romBuffer.subarray(
        targetFileOffset,
        Math.min(romBuffer.length, targetFileOffset + 96),
      ),
      input.encoding,
      terminatorByte,
      input.min_string_length,
      customTable,
    );
    targetCache.set(targetFileOffset, res);
    return res;
  };

  const discoveredTables = [];
  const stepAlignment = pointerWidth === 4 ? 2 : 1;
  let cursor = scanStartOffset;

  while (
    cursor + input.min_entries * stride <= scanEndOffset &&
    discoveredTables.length < input.max_tables
  ) {
    const runEntries: {
      readonly entryFileOffset: number;
      readonly entryAddress: string;
      readonly targetAddress: string;
      readonly targetFileOffset: number;
      readonly text: string;
      readonly byteLength: number;
    }[] = [];

    let probeOffset = cursor;
    while (
      probeOffset + pointerWidth <= scanEndOffset &&
      runEntries.length < 512
    ) {
      const rawVal = readPointerValue(
        romBuffer,
        probeOffset,
        pointerWidth,
        endian,
      );
      if (rawVal === 0n) break;
      const targetAddrBigInt = baseAddrResult.value + rawVal;
      const targetFileOffset = toFileOffset(targetAddrBigInt, probeOffset);
      if (targetFileOffset === null) break;
      const checked = checkTargetOffset(targetFileOffset);
      if (!checked.valid) break;
      const entryAddress =
        toVirtualAddress(probeOffset) ?? `0x${probeOffset.toString(16)}`;
      runEntries.push({
        entryFileOffset: probeOffset,
        entryAddress,
        targetAddress: `0x${targetAddrBigInt.toString(16)}`,
        targetFileOffset,
        text: checked.text,
        byteLength: checked.byteLength,
      });
      probeOffset += stride;
    }

    const uniqueTargets = new Set(runEntries.map((e) => e.targetFileOffset))
      .size;
    if (runEntries.length >= input.min_entries && uniqueTargets >= 2) {
      const tableFileOffset = cursor;
      const tableAddress =
        toVirtualAddress(tableFileOffset) ??
        `0x${tableFileOffset.toString(16)}`;
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
          entry_address: e.entryAddress,
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
      });
      cursor = probeOffset;
      continue;
    }

    cursor += stepAlignment;
  }

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
    base_address: `0x${baseAddrResult.value.toString(16)}`,
    stride,
    bytes_scanned: Math.max(0, scanEndOffset - scanStartOffset),
    tables: discoveredTables,
    total_tables: discoveredTables.length,
  });
};

export const executeFindCodeCaves = async (
  analysis: AnalysisOperationPort,
  input: FindCodeCavesInput,
  signal?: AbortSignal,
  target?: BinaryTarget,
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
          target !== undefined && isConsoleBinaryTarget(target)
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
  });
};
