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
  findCodeCavesInSlice,
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
  let romBytes: Buffer;
  try {
    romBytes = await readFile(target.path);
  } catch {
    return undefined;
  }
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

      const foundOffsets: number[] = [];
      let truncated = false;
      let cursor = searchStart;
      while (cursor + needle.length <= searchEnd) {
        const idx = localRom.romBytes.indexOf(needle, cursor);
        if (idx === -1 || idx + needle.length > searchEnd) break;
        if (foundOffsets.length >= input.max_results) {
          truncated = true;
          break;
        }
        foundOffsets.push(idx);
        cursor = idx + 1;
      }

      const matches = [];
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
        const xrefs = await resolveOptionalXrefs(
          analysis,
          address,
          input.resolve_xrefs,
          signal,
        );
        matches.push({
          address,
          file_offset: fileOffset,
          encoding: input.encoding,
          text,
          bytes_hex: bytesHex,
          byte_length: byteLength,
          terminated,
          xrefs,
        });
      }

      return ok({
        mode: "query_search",
        encoding: input.encoding,
        encoded_query_pattern: pattern,
        matches,
        total_matches: matches.length,
        truncated,
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

    const matches = [];
    for (const item of parsedSearch.data.matches.slice(0, input.max_results)) {
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

      const fileOffset = input.resolve_xrefs
        ? await resolveOptionalFileOffset(analysis, item.address, signal)
        : null;
      const xrefs = await resolveOptionalXrefs(
        analysis,
        item.address,
        input.resolve_xrefs,
        signal,
      );

      matches.push({
        address: item.address,
        file_offset: fileOffset,
        encoding: input.encoding,
        text,
        bytes_hex: bytesHex,
        byte_length: byteLength,
        terminated,
        xrefs,
      });
    }

    return ok({
      mode: "query_search",
      encoding: input.encoding,
      encoded_query_pattern: pattern,
      matches,
      total_matches: matches.length,
      truncated: !parsedSearch.data.complete,
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
    const extracted = extractRomStringsFromBuffer({
      bytes: slice,
      baseAddress: baseAddrBigInt,
      encoding: input.encoding,
      minLength: input.min_length,
      terminatorByte,
      customTable,
      limit: input.max_results,
    });

    const matches = [];
    for (const item of extracted) {
      const fileOffset = startOffset + item.offsetInBuffer;
      const address = localRom.toVirtualAddress(fileOffset) ?? item.address;
      const xrefs = await resolveOptionalXrefs(
        analysis,
        address,
        input.resolve_xrefs,
        signal,
      );
      matches.push({
        address,
        file_offset: fileOffset,
        encoding: input.encoding,
        text: item.decoded,
        bytes_hex: item.rawHex.replace(/\s+/gu, "").toLowerCase(),
        byte_length: item.byteLength,
        terminated: true,
        xrefs,
      });
    }

    return ok({
      mode: "range_scan",
      encoding: input.encoding,
      encoded_query_pattern: null,
      matches,
      total_matches: matches.length,
      truncated: matches.length >= input.max_results,
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
  const extracted = extractRomStringsFromBuffer({
    bytes: buffer,
    baseAddress: baseAddrResult.value,
    encoding: input.encoding,
    minLength: input.min_length,
    terminatorByte,
    customTable,
    limit: input.max_results,
  });

  const matches = [];
  for (const item of extracted) {
    const fileOffset = input.resolve_xrefs
      ? await resolveOptionalFileOffset(analysis, item.address, signal)
      : null;
    const xrefs = await resolveOptionalXrefs(
      analysis,
      item.address,
      input.resolve_xrefs,
      signal,
    );
    matches.push({
      address: item.address,
      file_offset: fileOffset,
      encoding: input.encoding,
      text: item.decoded,
      bytes_hex: item.rawHex.replace(/\s+/gu, "").toLowerCase(),
      byte_length: item.byteLength,
      terminated: true,
      xrefs,
    });
  }

  return ok({
    mode: "range_scan",
    encoding: input.encoding,
    encoded_query_pattern: null,
    matches,
    total_matches: matches.length,
    truncated: matches.length >= input.max_results,
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
        Math.min(localRom.romBytes.length, tableFileOffset + totalBytesToRead),
      );
      const entries = [];

      for (let index = 0; index < input.count; index += 1) {
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
            previewBytesHex = decoded.rawHex.replace(/\s+/gu, "").toLowerCase();
            previewByteLength = decoded.byteLength;
          }
        }

        const entryXrefs = await resolveOptionalXrefs(
          analysis,
          entryAddress,
          input.resolve_xrefs,
          signal,
        );
        const targetXrefs = await resolveOptionalXrefs(
          analysis,
          targetAddress,
          input.resolve_xrefs,
          signal,
        );

        entries.push({
          index,
          entry_address: entryAddress,
          entry_file_offset: entryFileOffset,
          raw_pointer: rawPointer,
          target_address: targetAddress,
          target_file_offset: targetFileOffset,
          preview_text: previewText,
          preview_bytes_hex: previewBytesHex,
          preview_byte_length: previewByteLength,
          entry_xrefs: entryXrefs,
          target_xrefs: targetXrefs,
        });
      }

      const budgets = computePointerSlotBudgets(entries);
      const enrichedEntries = entries.map((entry, idx) => ({
        ...entry,
        allocated_budget_bytes: budgets[idx] ?? null,
      }));
      const manuscriptRecords = input.include_manuscript
        ? enrichedEntries.map((entry) => ({
            id: `ptr_${entry.index.toString().padStart(4, "0")}`,
            index: entry.index,
            pointer_address: entry.entry_address,
            pointer_file_offset: entry.entry_file_offset,
            target_address: entry.target_address,
            target_file_offset: entry.target_file_offset,
            byte_length: entry.preview_byte_length,
            max_bytes: entry.allocated_budget_bytes,
            jp: entry.preview_text ?? "",
            ko: "",
          }))
        : undefined;

      return ok({
        table_address: `0x${tableAddrBigInt.toString(16)}`,
        table_file_offset: tableFileOffset,
        pointer_size: pointerWidth,
        endian,
        base_address: `0x${baseAddrResult.value.toString(16)}`,
        stride,
        encoding: input.encoding,
        entries: enrichedEntries,
        entries_scanned: enrichedEntries.length,
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

  const readRes = await callOperation(
    analysis,
    "read_bytes",
    { address: addressStr, length: totalBytesToRead },
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
  const entries = [];

  for (let index = 0; index < input.count; index += 1) {
    const byteOffset = index * stride;
    if (byteOffset + pointerWidth > tableBuffer.length) break;

    const entryAddrBigInt = tableAddrResult.value + BigInt(byteOffset);
    const entryAddress = `0x${entryAddrBigInt.toString(16)}`;
    const rawValue = readPointerValue(
      tableBuffer,
      byteOffset,
      pointerWidth,
      endian,
    );
    const targetAddress = `0x${(baseAddrResult.value + rawValue).toString(16)}`;
    const rawPointer = `0x${rawValue.toString(16).padStart(pointerWidth * 2, "0")}`;

    const entryFileOffset = input.resolve_xrefs
      ? await resolveOptionalFileOffset(analysis, entryAddress, signal)
      : null;
    const targetFileOffset = await resolveOptionalFileOffset(
      analysis,
      targetAddress,
      signal,
    );

    let previewText: string | null = null;
    let previewBytesHex: string | null = null;
    let previewByteLength: number | null = null;

    if (input.preview_bytes > 0) {
      const targetRead = await callOperation(
        analysis,
        "read_bytes",
        { address: targetAddress, length: input.preview_bytes },
        signal,
      );
      if (targetRead.ok) {
        const parsedTargetRead = readBytesResponseSchema.safeParse(
          targetRead.value,
        );
        if (
          parsedTargetRead.success &&
          parsedTargetRead.data.bytes_hex.length > 0
        ) {
          const targetBuf = Buffer.from(parsedTargetRead.data.bytes_hex, "hex");
          const decoded = decodeRomStringFromBytes(
            targetBuf,
            input.encoding,
            terminatorByte,
            customTable,
          );
          previewText = decoded.decoded;
          previewBytesHex = decoded.rawHex.replace(/\s+/gu, "").toLowerCase();
          previewByteLength = decoded.byteLength;
        }
      }
    }

    const entryXrefs = await resolveOptionalXrefs(
      analysis,
      entryAddress,
      input.resolve_xrefs,
      signal,
    );
    const targetXrefs = await resolveOptionalXrefs(
      analysis,
      targetAddress,
      input.resolve_xrefs,
      signal,
    );

    entries.push({
      index,
      entry_address: entryAddress,
      entry_file_offset: entryFileOffset,
      raw_pointer: rawPointer,
      target_address: targetAddress,
      target_file_offset: targetFileOffset,
      preview_text: previewText,
      preview_bytes_hex: previewBytesHex,
      preview_byte_length: previewByteLength,
      entry_xrefs: entryXrefs,
      target_xrefs: targetXrefs,
    });
  }

  const budgets = computePointerSlotBudgets(entries);
  const enrichedEntries = entries.map((entry, idx) => ({
    ...entry,
    allocated_budget_bytes: budgets[idx] ?? null,
  }));
  const manuscriptRecords = input.include_manuscript
    ? enrichedEntries.map((entry) => ({
        id: `ptr_${entry.index.toString().padStart(4, "0")}`,
        index: entry.index,
        pointer_address: entry.entry_address,
        pointer_file_offset: entry.entry_file_offset,
        target_address: entry.target_address,
        target_file_offset: entry.target_file_offset,
        byte_length: entry.preview_byte_length,
        max_bytes: entry.allocated_budget_bytes,
        jp: entry.preview_text ?? "",
        ko: "",
      }))
    : undefined;

  return ok({
    table_address: `0x${tableAddrResult.value.toString(16)}`,
    pointer_size: pointerWidth,
    endian,
    base_address: `0x${baseAddrResult.value.toString(16)}`,
    stride,
    encoding: input.encoding,
    entries: enrichedEntries,
    entries_scanned: enrichedEntries.length,
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
      customTable?.decodeByLength.get(1)?.has("00") === true &&
      !customTable.endTokens.has("00")
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
      const tableXrefs = await resolveOptionalXrefs(
        analysis,
        tableAddress,
        input.resolve_xrefs,
        signal,
      );
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
        table_xrefs: tableXrefs,
        samples,
      });
      cursor = probeOffset;
      continue;
    }

    cursor += stepAlignment;
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
        const found = findCodeCavesInSlice({
          bytes: romBytes.subarray(start, end),
          sliceFileOffset: start,
          regionName: map.name,
          executable: map.executable,
          minSize: input.min_size,
          alignment: input.alignment,
          fillByte: input.fill_byte,
          toVirtualAddress: (fo) =>
            `0x${(mapStartVaddr + BigInt(fo - start)).toString(16)}`,
        });
        rawCaves.push(...found);
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
      const found = findCodeCavesInSlice({
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
      });
      rawCaves.push(...found);
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
    const found = findCodeCavesInSlice({
      bytes: buffer,
      sliceFileOffset: 0,
      regionName: null,
      executable: true,
      minSize: input.min_size,
      alignment: input.alignment,
      fillByte: input.fill_byte,
      toVirtualAddress: (fo) => `0x${(baseAddr + BigInt(fo)).toString(16)}`,
    });
    for (const cave of found) {
      const fileOffset = input.resolve_xrefs
        ? await resolveOptionalFileOffset(analysis, cave.address, signal)
        : null;
      rawCaves.push({
        ...cave,
        file_offset: fileOffset,
      });
    }
  }

  rawCaves.sort(
    (a, b) =>
      b.byte_length - a.byte_length ||
      (a.file_offset ?? 0) - (b.file_offset ?? 0),
  );

  const selected = rawCaves.slice(0, input.max_results);
  const caves = [];
  for (const item of selected) {
    const xrefs = await resolveOptionalXrefs(
      analysis,
      item.address,
      input.resolve_xrefs,
      signal,
    );
    caves.push({
      ...item,
      xrefs,
    });
  }

  return ok({
    min_size: input.min_size,
    alignment: input.alignment,
    caves,
    total_caves: caves.length,
  });
};
