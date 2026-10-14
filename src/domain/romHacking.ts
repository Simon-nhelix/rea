import { z } from "zod";
import { err, ok, type Result } from "./result.js";

/** Supported ROM text encodings for localization and string extraction. */
export const ROM_TEXT_ENCODINGS = [
  "sjis",
  "cp932",
  "euc-jp",
  "utf-8",
  "utf8",
  "utf-16le",
  "utf16le",
  "utf-16be",
  "utf16be",
  "ascii",
  "tbl",
] as const;

export type RomTextEncoding = (typeof ROM_TEXT_ENCODINGS)[number];

export type CanonicalRomTextEncoding =
  | "sjis"
  | "cp932"
  | "euc-jp"
  | "utf-8"
  | "utf-16le"
  | "utf-16be"
  | "ascii"
  | "tbl";

export const normalizeRomTextEncoding = (
  encoding: RomTextEncoding,
): CanonicalRomTextEncoding => {
  switch (encoding) {
    case "utf8":
      return "utf-8";
    case "utf16le":
      return "utf-16le";
    case "utf16be":
      return "utf-16be";
    default:
      return encoding;
  }
};

export const romTextEncodingSchema = z.enum(ROM_TEXT_ENCODINGS);

/** Parsed custom .tbl character mapping table for ROM hacking. */
export interface CustomCharTable {
  readonly decodeByLength: ReadonlyMap<number, ReadonlyMap<string, string>>;
  readonly maxByteLength: number;
  readonly encodeMap: ReadonlyMap<string, Uint8Array>;
  readonly maxTokenLength: number;
  readonly endTokens: ReadonlySet<string>;
}

/** Parse a standard ROM hacking .tbl character table (e.g. "8140= ", "00=[END]"). */
export const parseCustomCharTable = (
  text: string,
): Result<CustomCharTable, string> => {
  const decodeByLength = new Map<number, Map<string, string>>();
  const encodeMap = new Map<string, Uint8Array>();
  const endTokens = new Set<string>();
  let maxByteLength = 1;
  let maxTokenLength = 1;

  const lines = text.split(/\r?\n/u);
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i] ?? "";
    const trimmed = rawLine.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) {
      continue;
    }
    const eqIndex = rawLine.indexOf("=");
    if (eqIndex <= 0) {
      return err(`Invalid .tbl entry at line ${i + 1}: missing '=' separator`);
    }
    let lhs = rawLine.slice(0, eqIndex).trim();
    const rhs = rawLine.slice(eqIndex + 1).replace(/\r$/u, "");
    let isEndMarker = false;
    if (lhs.startsWith("/") || lhs.startsWith("*")) {
      isEndMarker = true;
      lhs = lhs.slice(1).trim();
    }
    if (
      lhs.length === 0 ||
      lhs.length % 2 !== 0 ||
      !/^[0-9a-fA-F]+$/u.test(lhs)
    ) {
      return err(
        `Invalid .tbl hex sequence at line ${i + 1}: '${lhs}' must be an even number of hex digits`,
      );
    }
    const hexKey = lhs.toLowerCase();
    const byteLen = hexKey.length / 2;
    const bytes = new Uint8Array(byteLen);
    for (let b = 0; b < byteLen; b++) {
      bytes[b] = Number.parseInt(hexKey.slice(b * 2, b * 2 + 2), 16);
    }
    const value = rhs === "" && isEndMarker ? "[END]" : rhs;
    let bucket = decodeByLength.get(byteLen);
    if (bucket === undefined) {
      bucket = new Map<string, string>();
      decodeByLength.set(byteLen, bucket);
    }
    bucket.set(hexKey, value);
    if (byteLen > maxByteLength) maxByteLength = byteLen;
    if (value.length > 0 && !encodeMap.has(value)) {
      encodeMap.set(value, bytes);
      if (value.length > maxTokenLength) maxTokenLength = value.length;
    }
    if (isEndMarker) {
      endTokens.add(hexKey);
    }
  }

  if (decodeByLength.size === 0) {
    return err("Custom .tbl character table contains no valid byte mappings");
  }

  return ok({
    decodeByLength,
    maxByteLength,
    encodeMap,
    maxTokenLength,
    endTokens,
  });
};

let cachedSjisEncodeMap: Map<string, Uint8Array> | undefined;
let cachedEucJpEncodeMap: Map<string, Uint8Array> | undefined;

const getSjisEncodeMap = (): Map<string, Uint8Array> => {
  if (cachedSjisEncodeMap !== undefined) return cachedSjisEncodeMap;
  const decoder = new TextDecoder("shift-jis", { fatal: true });
  const map = new Map<string, Uint8Array>();
  // Single-byte ASCII & half-width katakana
  for (let b = 0x20; b <= 0xdf; b++) {
    if (b > 0x7e && b < 0xa1) continue;
    try {
      const char = decoder.decode(Uint8Array.of(b));
      if (!map.has(char)) map.set(char, Uint8Array.of(b));
    } catch {
      // skip unmapped byte
    }
  }
  // Double-byte Shift-JIS / CP932 lead & trail ranges
  const leadRanges: readonly (readonly [number, number])[] = [
    [0x81, 0x9f],
    [0xe0, 0xfc],
  ];
  for (const [leadStart, leadEnd] of leadRanges) {
    for (let lead = leadStart; lead <= leadEnd; lead++) {
      for (let trail = 0x40; trail <= 0xfc; trail++) {
        if (trail === 0x7f) continue;
        try {
          const bytes = Uint8Array.of(lead, trail);
          const char = decoder.decode(bytes);
          if (char.length === 1 && !map.has(char)) {
            map.set(char, bytes);
          }
        } catch {
          // skip unmapped pair
        }
      }
    }
  }
  cachedSjisEncodeMap = map;
  return map;
};

const getEucJpEncodeMap = (): Map<string, Uint8Array> => {
  if (cachedEucJpEncodeMap !== undefined) return cachedEucJpEncodeMap;
  const decoder = new TextDecoder("euc-jp", { fatal: true });
  const map = new Map<string, Uint8Array>();
  for (let b = 0x20; b <= 0x7e; b++) {
    map.set(String.fromCharCode(b), Uint8Array.of(b));
  }
  for (let trail = 0xa1; trail <= 0xdf; trail++) {
    try {
      const bytes = Uint8Array.of(0x8e, trail);
      const char = decoder.decode(bytes);
      if (!map.has(char)) map.set(char, bytes);
    } catch {
      // skip
    }
  }
  for (let lead = 0xa1; lead <= 0xfe; lead++) {
    for (let trail = 0xa1; trail <= 0xfe; trail++) {
      try {
        const bytes = Uint8Array.of(lead, trail);
        const char = decoder.decode(bytes);
        if (char.length === 1 && !map.has(char)) {
          map.set(char, bytes);
        }
      } catch {
        // skip
      }
    }
  }
  cachedEucJpEncodeMap = map;
  return map;
};

/** Encode a search query string into target ROM bytes using the selected encoding or .tbl. */
export const encodeRomQueryString = (
  query: string,
  encoding: RomTextEncoding,
  customTable?: CustomCharTable,
): Result<Uint8Array, string> => {
  if (query.length === 0) {
    return err("Query string must not be empty");
  }
  const canonical = normalizeRomTextEncoding(encoding);
  switch (canonical) {
    case "utf-8":
      return ok(new TextEncoder().encode(query));
    case "ascii": {
      const out = new Uint8Array(query.length);
      for (let i = 0; i < query.length; i++) {
        const code = query.charCodeAt(i);
        if (code < 0x20 || code > 0x7e) {
          return err(
            `Character '${query[i] ?? ""}' is outside printable ASCII (0x20..0x7E)`,
          );
        }
        out[i] = code;
      }
      return ok(out);
    }
    case "utf-16le":
    case "utf-16be": {
      const out = new Uint8Array(query.length * 2);
      for (let i = 0; i < query.length; i++) {
        const code = query.charCodeAt(i);
        if (canonical === "utf-16le") {
          out[i * 2] = code & 0xff;
          out[i * 2 + 1] = (code >>> 8) & 0xff;
        } else {
          out[i * 2] = (code >>> 8) & 0xff;
          out[i * 2 + 1] = code & 0xff;
        }
      }
      return ok(out);
    }
    case "sjis":
    case "cp932": {
      const map = getSjisEncodeMap();
      const chunks: number[] = [];
      for (const char of query) {
        const encoded = map.get(char);
        if (encoded === undefined) {
          return err(
            `Character '${char}' cannot be encoded in Shift-JIS/CP932`,
          );
        }
        for (const b of encoded) chunks.push(b);
      }
      return ok(Uint8Array.from(chunks));
    }
    case "euc-jp": {
      const map = getEucJpEncodeMap();
      const chunks: number[] = [];
      for (const char of query) {
        const encoded = map.get(char);
        if (encoded === undefined) {
          return err(`Character '${char}' cannot be encoded in EUC-JP`);
        }
        for (const b of encoded) chunks.push(b);
      }
      return ok(Uint8Array.from(chunks));
    }
    case "tbl": {
      if (customTable === undefined) {
        return err(
          "Encoding 'tbl' requires table_text or table_path with valid .tbl mappings",
        );
      }
      const chunks: number[] = [];
      let pos = 0;
      while (pos < query.length) {
        let matchedBytes: Uint8Array | undefined;
        let matchedLen = 0;
        const maxTry = Math.min(customTable.maxTokenLength, query.length - pos);
        for (let len = maxTry; len >= 1; len--) {
          const candidate = query.slice(pos, pos + len);
          const bytes = customTable.encodeMap.get(candidate);
          if (bytes !== undefined) {
            matchedBytes = bytes;
            matchedLen = len;
            break;
          }
        }
        if (matchedBytes === undefined) {
          return err(
            `Substring starting at '${query.slice(pos, pos + 4)}' has no mapping in the provided .tbl table`,
          );
        }
        for (const b of matchedBytes) chunks.push(b);
        pos += matchedLen;
      }
      return ok(Uint8Array.from(chunks));
    }
  }
};

/** Format a Uint8Array as space-separated hex byte pairs for search_bytes or display. */
export const formatHexPattern = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" ");

/** Decode a single ROM string from a byte buffer up to a terminator byte or invalid sequence. */
export const decodeRomStringFromBytes = (
  bytes: Uint8Array,
  encoding: RomTextEncoding,
  terminatorByte: number | null = 0x00,
  customTable?: CustomCharTable,
): {
  readonly decoded: string;
  readonly byteLength: number;
  readonly rawHex: string;
} => {
  const canonical = normalizeRomTextEncoding(encoding);
  if (canonical === "tbl" && customTable !== undefined) {
    let pos = 0;
    const parts: string[] = [];
    while (pos < bytes.length) {
      let matchedText: string | undefined;
      let matchedLen = 0;
      let hitEndToken = false;
      const maxLen = Math.min(customTable.maxByteLength, bytes.length - pos);
      for (let len = maxLen; len >= 1; len--) {
        const bucket = customTable.decodeByLength.get(len);
        if (bucket === undefined) continue;
        let hexKey = "";
        for (let k = 0; k < len; k++) {
          hexKey += (bytes[pos + k] ?? 0).toString(16).padStart(2, "0");
        }
        const found = bucket.get(hexKey);
        if (found !== undefined) {
          matchedText = found;
          matchedLen = len;
          hitEndToken = customTable.endTokens.has(hexKey);
          break;
        }
      }
      if (
        terminatorByte !== null &&
        bytes[pos] === terminatorByte &&
        (matchedText === undefined || (terminatorByte !== 0x00 && !hitEndToken))
      ) {
        pos += 1;
        break;
      }
      if (matchedText === undefined) break;
      parts.push(matchedText);
      pos += matchedLen;
      if (hitEndToken) break;
    }
    const slice = bytes.subarray(0, Math.max(pos, 1));
    return {
      decoded: parts.join(""),
      byteLength: slice.length,
      rawHex: formatHexPattern(slice),
    };
  }

  if (canonical === "utf-16le" || canonical === "utf-16be") {
    let end = bytes.length - (bytes.length % 2);
    let foundTerminator = false;
    if (terminatorByte !== null) {
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        if (bytes[i] === terminatorByte && bytes[i + 1] === terminatorByte) {
          end = i;
          foundTerminator = true;
          break;
        }
      }
    }
    const content = bytes.subarray(0, end);
    const decoder = new TextDecoder(canonical, { fatal: false });
    const consumed = bytes.subarray(
      0,
      foundTerminator ? Math.min(end + 2, bytes.length) : end,
    );
    return {
      decoded: decoder.decode(content),
      byteLength: consumed.length,
      rawHex: formatHexPattern(consumed),
    };
  }

  let end = bytes.length;
  let foundTerminator = false;
  if (terminatorByte !== null) {
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === terminatorByte) {
        end = i;
        foundTerminator = true;
        break;
      }
    }
  }
  const content = bytes.subarray(0, end);
  const consumed = bytes.subarray(
    0,
    foundTerminator ? Math.min(end + 1, bytes.length) : end,
  );
  const decoderLabel =
    canonical === "sjis" || canonical === "cp932"
      ? "shift-jis"
      : canonical === "euc-jp"
        ? "euc-jp"
        : "utf-8";
  const decoder = new TextDecoder(decoderLabel, { fatal: false });
  return {
    decoded: decoder.decode(content),
    byteLength: consumed.length,
    rawHex: formatHexPattern(consumed),
  };
};

/** Scan a buffer for valid contiguous strings in the requested ROM encoding. */
export const extractRomStringsFromBuffer = (input: {
  readonly bytes: Uint8Array;
  readonly baseAddress: bigint;
  readonly encoding: RomTextEncoding;
  readonly minLength: number;
  readonly terminatorByte: number | null;
  readonly customTable?: CustomCharTable | undefined;
  readonly limit: number;
}): readonly {
  readonly offsetInBuffer: number;
  readonly address: string;
  readonly decoded: string;
  readonly byteLength: number;
  readonly rawHex: string;
}[] => {
  const {
    bytes,
    baseAddress,
    encoding,
    minLength,
    terminatorByte,
    customTable,
    limit,
  } = input;
  const canonical = normalizeRomTextEncoding(encoding);
  const results: {
    readonly offsetInBuffer: number;
    readonly address: string;
    readonly decoded: string;
    readonly byteLength: number;
    readonly rawHex: string;
  }[] = [];

  const sjisDecoder =
    canonical === "sjis" || canonical === "cp932"
      ? new TextDecoder("shift-jis", { fatal: true })
      : canonical === "euc-jp"
        ? new TextDecoder("euc-jp", { fatal: true })
        : undefined;

  const tblMapsZero =
    canonical === "tbl" &&
    customTable !== undefined &&
    customTable.decodeByLength.get(1)?.has("00") === true &&
    !customTable.endTokens.has("00");

  let cursor = 0;
  while (cursor < bytes.length && results.length < limit) {
    if (
      terminatorByte !== null &&
      bytes[cursor] === terminatorByte &&
      !(tblMapsZero && terminatorByte === 0x00)
    ) {
      cursor++;
      continue;
    }

    if (canonical === "tbl" && customTable !== undefined) {
      let pos = cursor;
      const chars: string[] = [];
      while (pos < bytes.length) {
        let matchedText: string | undefined;
        let matchedLen = 0;
        let hitEnd = false;
        const maxLen = Math.min(customTable.maxByteLength, bytes.length - pos);
        for (let len = maxLen; len >= 1; len--) {
          const bucket = customTable.decodeByLength.get(len);
          if (bucket === undefined) continue;
          let hexKey = "";
          for (let k = 0; k < len; k++) {
            hexKey += (bytes[pos + k] ?? 0).toString(16).padStart(2, "0");
          }
          const found = bucket.get(hexKey);
          if (found !== undefined) {
            matchedText = found;
            matchedLen = len;
            hitEnd = customTable.endTokens.has(hexKey);
            break;
          }
        }
        if (
          terminatorByte !== null &&
          bytes[pos] === terminatorByte &&
          (matchedText === undefined || (terminatorByte !== 0x00 && !hitEnd))
        ) {
          pos++;
          break;
        }
        if (matchedText === undefined) break;
        chars.push(matchedText);
        pos += matchedLen;
        if (hitEnd) break;
      }
      if (chars.length >= minLength) {
        const slice = bytes.subarray(cursor, pos);
        results.push({
          offsetInBuffer: cursor,
          address: `0x${(baseAddress + BigInt(cursor)).toString(16)}`,
          decoded: chars.join(""),
          byteLength: slice.length,
          rawHex: formatHexPattern(slice),
        });
        cursor = pos;
        continue;
      }
      cursor++;
      continue;
    }

    if (sjisDecoder !== undefined) {
      let pos = cursor;
      const chars: string[] = [];
      let multibyteCount = 0;
      while (pos < bytes.length) {
        const b0 = bytes[pos] ?? 0;
        if (terminatorByte !== null && b0 === terminatorByte) {
          pos++;
          break;
        }
        if (canonical === "sjis" || canonical === "cp932") {
          const isLead =
            (b0 >= 0x81 && b0 <= 0x9f) || (b0 >= 0xe0 && b0 <= 0xfc);
          if (isLead && pos + 1 < bytes.length) {
            const b1 = bytes[pos + 1] ?? 0;
            const isTrail = b1 >= 0x40 && b1 <= 0xfc && b1 !== 0x7f;
            if (isTrail) {
              try {
                const ch = sjisDecoder.decode(bytes.subarray(pos, pos + 2));
                chars.push(ch);
                multibyteCount++;
                pos += 2;
                continue;
              } catch {
                break;
              }
            }
            break;
          }
          if ((b0 >= 0x20 && b0 <= 0x7e) || (b0 >= 0xa1 && b0 <= 0xdf)) {
            try {
              chars.push(sjisDecoder.decode(bytes.subarray(pos, pos + 1)));
              if (b0 >= 0xa1) multibyteCount++;
              pos += 1;
              continue;
            } catch {
              break;
            }
          }
          break;
        } else {
          // euc-jp
          if (b0 >= 0xa1 && b0 <= 0xfe && pos + 1 < bytes.length) {
            const b1 = bytes[pos + 1] ?? 0;
            if (b1 >= 0xa1 && b1 <= 0xfe) {
              try {
                chars.push(sjisDecoder.decode(bytes.subarray(pos, pos + 2)));
                multibyteCount++;
                pos += 2;
                continue;
              } catch {
                break;
              }
            }
            break;
          }
          if (b0 >= 0x20 && b0 <= 0x7e) {
            chars.push(String.fromCharCode(b0));
            pos += 1;
            continue;
          }
          break;
        }
      }
      if (chars.length >= minLength && multibyteCount > 0) {
        const slice = bytes.subarray(cursor, pos);
        results.push({
          offsetInBuffer: cursor,
          address: `0x${(baseAddress + BigInt(cursor)).toString(16)}`,
          decoded: chars.join(""),
          byteLength: slice.length,
          rawHex: formatHexPattern(slice),
        });
        cursor = pos;
        continue;
      }
      cursor++;
      continue;
    }

    // ASCII / UTF-8 printable run
    let pos = cursor;
    while (pos < bytes.length) {
      const b = bytes[pos] ?? 0;
      if (terminatorByte !== null && b === terminatorByte) {
        pos++;
        break;
      }
      if (b >= 0x20 && b <= 0x7e) {
        pos++;
        continue;
      }
      break;
    }
    const charLen =
      terminatorByte !== null &&
      pos > cursor &&
      bytes[pos - 1] === terminatorByte
        ? pos - 1 - cursor
        : pos - cursor;
    if (charLen >= minLength) {
      const slice = bytes.subarray(cursor, pos);
      const decoded = decodeRomStringFromBytes(
        slice,
        canonical,
        terminatorByte,
      ).decoded;
      results.push({
        offsetInBuffer: cursor,
        address: `0x${(baseAddress + BigInt(cursor)).toString(16)}`,
        decoded,
        byteLength: slice.length,
        rawHex: formatHexPattern(slice),
      });
      cursor = pos;
      continue;
    }
    cursor++;
  }

  return results;
};

/** Decode a single pointer entry of 2, 3, or 4 bytes with endianness and base address. */
export const readPointerValue = (
  bytes: Uint8Array,
  offset: number,
  width: 2 | 3 | 4,
  endianness: "little" | "big",
): bigint => {
  if (endianness === "little") {
    let val = 0n;
    for (let i = 0; i < width; i++) {
      val |= BigInt(bytes[offset + i] ?? 0) << BigInt(i * 8);
    }
    return val;
  }
  let val = 0n;
  for (let i = 0; i < width; i++) {
    val = (val << 8n) | BigInt(bytes[offset + i] ?? 0);
  }
  return val;
};

export const searchRomStringsInputSchema = z.strictObject({
  query: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Literal text to encode and search in ROM memory (e.g. Japanese Shift-JIS, EUC-JP, UTF-8, or custom .tbl text). Omit when scanning an explicit address or file-offset range.",
    ),
  encoding: z
    .enum(ROM_TEXT_ENCODINGS)
    .default("sjis")
    .describe(
      "Character encoding used to encode the query and decode matched ROM bytes.",
    ),
  table_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional path to a custom .tbl character mapping file (HEX=CHAR per line).",
    ),
  table_text: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional inline .tbl character mapping rules (HEX=CHAR per line).",
    ),
  start_address: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional start address (hex, e.g. 0x08000000). Required when query and start_offset are omitted to scan a memory region.",
    ),
  start_offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe(
      "Optional starting ROM file offset in bytes (alternative to start_address).",
    ),
  end_offset: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe(
      "Optional ending ROM file offset in bytes (exclusive; alternative to length).",
    ),
  length: z
    .number()
    .int()
    .min(1)
    .max(16_777_216)
    .default(4096)
    .describe(
      "Byte length to scan when extracting strings from start_address or start_offset without a query.",
    ),
  min_length: z
    .number()
    .int()
    .min(1)
    .max(256)
    .default(2)
    .describe(
      "Minimum decoded character count when scanning an address range without a query.",
    ),
  terminator_byte: z
    .number()
    .int()
    .min(0)
    .max(255)
    .nullable()
    .default(0x00)
    .describe(
      "String terminator byte (0x00..0xFF, e.g. 0x00 or 0xFF), or null to rely only on .tbl end tokens.",
    ),
  max_results: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(50)
    .describe("Maximum number of string matches to return."),
  resolve_xrefs: z
    .boolean()
    .default(true)
    .describe(
      "Resolve incoming cross-references and ROM file offsets for each matched string.",
    ),
});

export type SearchRomStringsInput = z.output<
  typeof searchRomStringsInputSchema
>;

export const romStringMatchSchema = z.strictObject({
  address: z.string(),
  file_offset: z.number().int().min(0).nullable(),
  encoding: z.enum(ROM_TEXT_ENCODINGS),
  text: z.string(),
  bytes_hex: z.string(),
  byte_length: z.number().int().min(0),
  terminated: z.boolean(),
  xrefs: z.array(z.string()),
});

export const searchRomStringsResultSchema = z.strictObject({
  mode: z.enum(["query_search", "range_scan"]),
  encoding: z.enum(ROM_TEXT_ENCODINGS),
  encoded_query_pattern: z.string().nullable(),
  matches: z.array(romStringMatchSchema),
  total_matches: z.number().int().min(0),
  truncated: z.boolean(),
});

export const scanPointerTableInputSchema = z.strictObject({
  address: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Starting virtual address of the pointer table (e.g. 0x08100000). Optional when table_offset is provided.",
    ),
  table_offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe(
      "Starting ROM file offset of the pointer table in bytes (alternative to address).",
    ),
  count: z
    .number()
    .int()
    .min(1)
    .max(512)
    .default(32)
    .describe("Number of pointer table entries to read."),
  pointer_size: z
    .union([z.literal(2), z.literal(3), z.literal(4)])
    .default(4)
    .describe("Pointer width in bytes: 2 (16-bit), 3 (24-bit), or 4 (32-bit)."),
  endian: z
    .enum(["little", "big"])
    .default("little")
    .describe("Pointer byte order."),
  base_address: z
    .string()
    .default("0x0")
    .describe(
      "Base address added to each raw pointer value (e.g. 0x08000000 for 16-bit relative offsets).",
    ),
  stride: z
    .number()
    .int()
    .min(1)
    .max(64)
    .optional()
    .describe(
      "Bytes per table entry when entries are interleaved with metadata; defaults to pointer_size.",
    ),
  encoding: z
    .enum(ROM_TEXT_ENCODINGS)
    .default("sjis")
    .describe("Text encoding used to decode target string previews."),
  table_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional path to a custom .tbl character mapping file (HEX=CHAR per line).",
    ),
  table_text: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional inline .tbl character mapping rules (HEX=CHAR per line).",
    ),
  terminator_byte: z
    .number()
    .int()
    .min(0)
    .max(255)
    .nullable()
    .default(0x00)
    .describe(
      "String terminator byte (0x00..0xFF) used when decoding target string previews, or null for .tbl end tokens only.",
    ),
  preview_bytes: z
    .number()
    .int()
    .min(0)
    .max(256)
    .default(64)
    .describe(
      "Number of bytes to read at each pointer target to decode a text preview (0 disables preview).",
    ),
  resolve_xrefs: z
    .boolean()
    .default(true)
    .describe(
      "Resolve incoming cross-references to each pointer table slot and target address.",
    ),
  include_manuscript: z
    .boolean()
    .default(false)
    .describe(
      "Emit locbatch.py-compatible manuscript records (id, pointer_offset, target_offset, max_bytes, jp, ko) alongside pointer entries.",
    ),
});

export type ScanPointerTableInput = z.output<
  typeof scanPointerTableInputSchema
>;

export const pointerTableEntrySchema = z.strictObject({
  index: z.number().int().min(0),
  entry_address: z.string(),
  entry_file_offset: z.number().int().min(0).nullable(),
  raw_pointer: z.string(),
  target_address: z.string(),
  target_file_offset: z.number().int().min(0).nullable(),
  preview_text: z.string().nullable(),
  preview_bytes_hex: z.string().nullable(),
  preview_byte_length: z.number().int().min(0).nullable(),
  allocated_budget_bytes: z.number().int().min(0).nullable().optional(),
  entry_xrefs: z.array(z.string()),
  target_xrefs: z.array(z.string()),
});

export const manuscriptRecordSchema = z.strictObject({
  id: z.string(),
  index: z.number().int().min(0),
  pointer_address: z.string(),
  pointer_file_offset: z.number().int().min(0).nullable(),
  target_address: z.string(),
  target_file_offset: z.number().int().min(0).nullable(),
  byte_length: z.number().int().min(0).nullable(),
  max_bytes: z.number().int().min(0).nullable(),
  jp: z.string(),
  ko: z.string(),
});

export const scanPointerTableResultSchema = z.strictObject({
  table_address: z.string(),
  table_file_offset: z.number().int().min(0).nullable().optional(),
  pointer_size: z.union([z.literal(2), z.literal(3), z.literal(4)]),
  endian: z.enum(["little", "big"]),
  base_address: z.string(),
  stride: z.number().int().min(1),
  encoding: z.enum(ROM_TEXT_ENCODINGS),
  entries: z.array(pointerTableEntrySchema),
  entries_scanned: z.number().int().min(0),
  manuscript_records: z.array(manuscriptRecordSchema).optional(),
});

/**
 * Compute per-entry in-place byte budgets (distance to the next higher target offset
 * within the same string block, up to 4096 bytes; falls back to preview_byte_length).
 */
export const computePointerSlotBudgets = (
  entries: readonly {
    readonly target_file_offset: number | null;
    readonly target_address: string;
    readonly preview_byte_length: number | null;
  }[],
): readonly (number | null)[] => {
  const useFileOffsets = entries.some((e) => e.target_file_offset !== null);
  const coords = entries.map((e) => {
    if (useFileOffsets) return e.target_file_offset;
    try {
      return Number(BigInt(e.target_address));
    } catch {
      return null;
    }
  });
  const sortedUnique = Array.from(
    new Set(coords.filter((c): c is number => c !== null && c >= 0)),
  ).sort((a, b) => a - b);

  const nextCoordMap = new Map<number, number>();
  for (let i = 0; i + 1 < sortedUnique.length; i++) {
    const curr = sortedUnique[i]!;
    const next = sortedUnique[i + 1]!;
    const delta = next - curr;
    if (delta > 0 && delta <= 4096) {
      nextCoordMap.set(curr, delta);
    }
  }

  return entries.map((entry, idx) => {
    const coord = coords[idx] ?? null;
    if (coord !== null) {
      const budget = nextCoordMap.get(coord);
      if (budget !== undefined) return budget;
    }
    return entry.preview_byte_length;
  });
};

export const discoverPointerTablesInputSchema = z.strictObject({
  start_address: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional starting virtual address (hex) to scan for candidate pointer tables.",
    ),
  start_offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe(
      "Optional starting ROM file offset in bytes to scan for candidate pointer tables.",
    ),
  end_offset: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe(
      "Optional ending ROM file offset in bytes (exclusive) for pointer table discovery.",
    ),
  length: z
    .number()
    .int()
    .min(16)
    .max(16_777_216)
    .default(262_144)
    .describe(
      "Maximum byte length to scan when end_offset is not specified (default 256 KiB).",
    ),
  pointer_size: z
    .union([z.literal(2), z.literal(3), z.literal(4)])
    .default(4)
    .describe("Pointer width in bytes: 2 (16-bit), 3 (24-bit), or 4 (32-bit)."),
  endian: z
    .enum(["little", "big"])
    .default("little")
    .describe("Pointer byte order."),
  base_address: z
    .string()
    .default("0x0")
    .describe(
      "Base address added to each raw pointer value (e.g. 0x08000000 for 16-bit relative offsets).",
    ),
  stride: z
    .number()
    .int()
    .min(1)
    .max(64)
    .optional()
    .describe("Bytes per table entry; defaults to pointer_size."),
  min_entries: z
    .number()
    .int()
    .min(2)
    .max(256)
    .default(4)
    .describe(
      "Minimum consecutive valid string pointers required to report a candidate pointer table.",
    ),
  encoding: z
    .enum(ROM_TEXT_ENCODINGS)
    .default("sjis")
    .describe("Character encoding used to validate and decode target strings."),
  table_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional path to a custom .tbl character mapping file (HEX=CHAR per line).",
    ),
  table_text: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional inline .tbl character mapping rules (HEX=CHAR per line).",
    ),
  terminator_byte: z
    .number()
    .int()
    .min(0)
    .max(255)
    .nullable()
    .default(0x00)
    .describe("String terminator byte (0x00..0xFF) or null."),
  min_string_length: z
    .number()
    .int()
    .min(1)
    .max(64)
    .default(2)
    .describe(
      "Minimum decoded character length at a pointer target to consider it a valid string.",
    ),
  max_tables: z
    .number()
    .int()
    .min(1)
    .max(100)
    .default(20)
    .describe("Maximum number of candidate pointer tables to return."),
  sample_entries: z
    .number()
    .int()
    .min(1)
    .max(16)
    .default(3)
    .describe("Number of sample entries to include per discovered table."),
  resolve_xrefs: z
    .boolean()
    .default(false)
    .describe(
      "Resolve incoming cross-references to each discovered table's starting address.",
    ),
});

export type DiscoverPointerTablesInput = z.output<
  typeof discoverPointerTablesInputSchema
>;

export const discoveredPointerSampleSchema = z.strictObject({
  index: z.number().int().min(0),
  entry_address: z.string(),
  target_address: z.string(),
  target_file_offset: z.number().int().min(0).nullable(),
  preview_text: z.string(),
  byte_length: z.number().int().min(0),
  allocated_budget_bytes: z.number().int().min(0).nullable(),
});

export const discoveredPointerTableSchema = z.strictObject({
  table_address: z.string(),
  table_file_offset: z.number().int().min(0).nullable(),
  entry_count: z.number().int().min(2),
  unique_targets: z.number().int().min(1),
  pointer_size: z.union([z.literal(2), z.literal(3), z.literal(4)]),
  stride: z.number().int().min(1),
  min_string_bytes: z.number().int().min(0),
  max_string_bytes: z.number().int().min(0),
  avg_string_bytes: z.number().min(0),
  table_xrefs: z.array(z.string()),
  samples: z.array(discoveredPointerSampleSchema),
});

export const discoverPointerTablesResultSchema = z.strictObject({
  encoding: z.enum(ROM_TEXT_ENCODINGS),
  pointer_size: z.union([z.literal(2), z.literal(3), z.literal(4)]),
  endian: z.enum(["little", "big"]),
  base_address: z.string(),
  stride: z.number().int().min(1),
  bytes_scanned: z.number().int().min(0),
  tables: z.array(discoveredPointerTableSchema),
  total_tables: z.number().int().min(0),
});

export const findCodeCavesInputSchema = z.strictObject({
  min_size: z
    .number()
    .int()
    .min(16)
    .max(1_048_576)
    .default(64)
    .describe(
      "Minimum contiguous byte length required to report a code/data cave (default 64 bytes).",
    ),
  fill_byte: z
    .number()
    .int()
    .min(0)
    .max(255)
    .optional()
    .describe(
      "Optional specific padding byte to match (e.g. 0x00 or 0xFF). When omitted, scans for contiguous runs of either 0x00 or 0xFF.",
    ),
  alignment: z
    .union([
      z.literal(1),
      z.literal(2),
      z.literal(4),
      z.literal(8),
      z.literal(16),
      z.literal(32),
    ])
    .default(4)
    .describe(
      "Address/offset alignment boundary for reported cave start addresses (default 4).",
    ),
  start_address: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional starting virtual address (hex) when scanning via provider.",
    ),
  start_offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("Optional starting ROM file offset in bytes."),
  end_offset: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe("Optional ending ROM file offset in bytes (exclusive)."),
  length: z
    .number()
    .int()
    .min(16)
    .max(16_777_216)
    .default(262_144)
    .describe(
      "Bytes to scan when reading via provider without local ROM file.",
    ),
  executable_only: z
    .boolean()
    .default(false)
    .describe(
      "Restrict scan to executable mapped segments when console ROM mappings are known.",
    ),
  max_results: z
    .number()
    .int()
    .min(1)
    .max(200)
    .default(32)
    .describe(
      "Maximum number of candidate code caves to return, sorted largest first.",
    ),
  resolve_xrefs: z
    .boolean()
    .default(false)
    .describe(
      "Check incoming cross-references to each cave start address via the analysis provider.",
    ),
});

export type FindCodeCavesInput = z.output<typeof findCodeCavesInputSchema>;

export const codeCaveEntrySchema = z.strictObject({
  address: z.string(),
  file_offset: z.number().int().min(0).nullable(),
  byte_length: z.number().int().min(1),
  fill_byte: z.string(),
  region_name: z.string().nullable(),
  executable: z.boolean(),
  xrefs: z.array(z.string()),
});

export const findCodeCavesResultSchema = z.strictObject({
  min_size: z.number().int().min(16),
  alignment: z.number().int().min(1),
  caves: z.array(codeCaveEntrySchema),
  total_caves: z.number().int().min(0),
});

/** Scan a byte slice for contiguous runs of 0x00 or 0xFF (or explicit fillByte) aligned to `alignment`. */
export const findCodeCavesInSlice = (input: {
  readonly bytes: Uint8Array;
  readonly sliceFileOffset: number;
  readonly regionName: string | null;
  readonly executable: boolean;
  readonly minSize: number;
  readonly alignment: number;
  readonly fillByte?: number | undefined;
  readonly toVirtualAddress: (fileOffset: number) => string | null;
}): readonly {
  readonly address: string;
  readonly file_offset: number;
  readonly byte_length: number;
  readonly fill_byte: string;
  readonly region_name: string | null;
  readonly executable: boolean;
}[] => {
  const {
    bytes,
    sliceFileOffset,
    regionName,
    executable,
    minSize,
    alignment,
    fillByte,
    toVirtualAddress,
  } = input;
  const caves: {
    readonly address: string;
    readonly file_offset: number;
    readonly byte_length: number;
    readonly fill_byte: string;
    readonly region_name: string | null;
    readonly executable: boolean;
  }[] = [];

  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i]!;
    const matchesFill =
      fillByte !== undefined ? b === fillByte : b === 0x00 || b === 0xff;
    if (!matchesFill) {
      i++;
      continue;
    }
    let end = i + 1;
    while (end < bytes.length && bytes[end] === b) {
      end++;
    }
    const rawStartFileOffset = sliceFileOffset + i;
    const rawEndFileOffset = sliceFileOffset + end;
    const remainder = rawStartFileOffset % alignment;
    const alignedStartFileOffset =
      remainder === 0
        ? rawStartFileOffset
        : rawStartFileOffset + (alignment - remainder);
    const alignedLength = rawEndFileOffset - alignedStartFileOffset;
    if (alignedLength >= minSize) {
      const address =
        toVirtualAddress(alignedStartFileOffset) ??
        `0x${alignedStartFileOffset.toString(16)}`;
      caves.push({
        address,
        file_offset: alignedStartFileOffset,
        byte_length: alignedLength,
        fill_byte: `0x${b.toString(16).padStart(2, "0")}`,
        region_name: regionName,
        executable,
      });
    }
    i = end;
  }

  return caves;
};
