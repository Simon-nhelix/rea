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
  decodeRomStringFromBytes,
  encodeRomQueryString,
  extractRomStringsFromBuffer,
  formatHexPattern,
  parseCustomCharTable,
  readPointerValue,
  type CustomCharTable,
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
): EnhancedResult => {
  const tableResult = await loadCustomTable(
    "search_rom_strings",
    input.encoding,
    input.table_path,
    input.table_text,
  );
  if (!tableResult.ok) return tableResult;
  const customTable = tableResult.value;

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
            0x00,
            customTable,
          );
          if (decoded.decoded.length > 0) {
            text = decoded.decoded;
            bytesHex = decoded.rawHex.replace(/\s+/gu, "").toLowerCase();
            byteLength = decoded.byteLength;
            terminated = decoded.byteLength < buf.length || buf.includes(0x00);
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

  if (input.start_address === undefined) {
    return err(
      new AnalysisInputError("search_rom_strings", {
        userMessage:
          "Provide either query (to search encoded bytes across ROM) or start_address (to scan a memory range).",
      }),
    );
  }

  const baseAddrResult = parseHexAddressBigInt(
    "search_rom_strings",
    "start_address",
    input.start_address,
  );
  if (!baseAddrResult.ok) return baseAddrResult;

  const readRes = await callOperation(
    analysis,
    "read_bytes",
    { address: input.start_address, length: input.length },
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
    terminatorByte: 0x00,
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
): EnhancedResult => {
  const tableAddrResult = parseHexAddressBigInt(
    "scan_pointer_table",
    "address",
    input.address,
  );
  if (!tableAddrResult.ok) return tableAddrResult;

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

  const totalBytesToRead = input.count * stride;
  const readRes = await callOperation(
    analysis,
    "read_bytes",
    { address: input.address, length: totalBytesToRead },
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
  const pointerWidth = input.pointer_size;
  const endian = input.endian;

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
            0x00,
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

  return ok({
    table_address: `0x${tableAddrResult.value.toString(16)}`,
    pointer_size: pointerWidth,
    endian,
    base_address: `0x${baseAddrResult.value.toString(16)}`,
    stride,
    encoding: input.encoding,
    entries,
    entries_scanned: entries.length,
  });
};
