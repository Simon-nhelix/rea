import { z } from "zod";
import { err, ok, type Result } from "./result.js";
import {
  decodeRomTextWithControlCodes,
  matchRomControlCodeAt,
  romControlCodeFields,
  type RomControlCodeTable,
  type RomTextWithControlCodes,
  romControlCodeUseSchema,
  withTerminatorAsEndCode,
  withWordFormatControlCodes,
} from "./romControlCodes.js";
import {
  findOrphanStringsInPointerGaps,
  inferredBaseCandidateSchema,
  inferOverlayLoadAddress,
  orphanStringEntrySchema,
  type InferredBaseCandidate,
} from "./romLoadAddressInference.js";
import {
  getSjisDoubleByteDecodeTable,
  getSjisEncodeMap,
} from "./shiftJisTables.js";
import {
  measureRomText,
  NO_ROM_TEXT_FILTERS,
  romTextFiltersActive,
  romTextPassesFilters,
  type RomTextFilters,
} from "./romTextQuality.js";
import { DATA_TRACK_MODES, type DataTrackMode } from "./discImage.js";
import { pointerTableCoverageSchema } from "./romPointerSegments.js";

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
  "sjis-le16",
  "sjis-swap16",
  "tile-le16",
  "tile-be16",
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
  | "tbl"
  | "sjis-le16"
  | "tile-le16"
  | "tile-be16";

/** Encodings whose text unit is one 16-bit word (scanned per word parity). */
export const WORD_ROM_TEXT_ENCODINGS = [
  "sjis-le16",
  "tile-le16",
  "tile-be16",
] as const;
type WordRomTextEncoding = (typeof WORD_ROM_TEXT_ENCODINGS)[number];

export const isWordRomTextEncoding = (
  encoding: RomTextEncoding,
): encoding is WordRomTextEncoding =>
  (WORD_ROM_TEXT_ENCODINGS as readonly string[]).includes(
    encoding === "sjis-swap16" ? "sjis-le16" : encoding,
  );

/** Encodings that decode through a caller-supplied character table. */
export const requiresRomCharTable = (encoding: RomTextEncoding): boolean =>
  encoding === "tbl" || encoding === "tile-le16" || encoding === "tile-be16";

/**
 * Resolved interpretation of 16-bit text words. `sjis-le16` stores a two-byte
 * Shift-JIS code as a little-endian word (bytes C7 82 = code 82C7 = 「ど」).
 * `tile-le16`/`tile-be16` store tilemap words: `word & mask` is a tile index
 * looked up in the character table and the remaining bits are attributes
 * (palette, flips, priority).
 */
export interface RomWordFormat {
  readonly encoding: WordRomTextEncoding;
  readonly littleEndian: boolean;
  /** Word value that ends a string, or null for none. */
  readonly terminatorWord: number | null;
  /** Word value decoded as "\n" inside a string, or null for none. */
  readonly newlineWord: number | null;
  readonly tile?: {
    readonly mask: number;
    /** Required attribute bits, or null to require one consistent value per string. */
    readonly attribute: number | null;
    readonly characters: ReadonlyMap<number, string>;
  };
}

/** Default PC Engine BAT layout: 12-bit tile index, palette in bits 12..15. */
export const DEFAULT_TILE_MASK = 0x0fff;

/**
 * Normalize word-format options once at the request boundary. Byte encodings
 * reject word options instead of silently ignoring them; without
 * terminator_word, the terminator byte doubled (00 00 by default) ends words.
 */
export const resolveRomWordFormat = (input: {
  readonly encoding: RomTextEncoding;
  readonly terminatorByte: number | null;
  readonly terminatorWord?: number | null | undefined;
  readonly newlineWord?: number | undefined;
  readonly tileMask?: number | undefined;
  readonly tileAttribute?: number | null | undefined;
  readonly customTable?: CustomCharTable | undefined;
}): Result<RomWordFormat | undefined, string> => {
  const encoding = normalizeRomTextEncoding(input.encoding);
  if (!isWordRomTextEncoding(encoding)) {
    if (
      input.terminatorWord !== undefined ||
      input.newlineWord !== undefined ||
      input.tileMask !== undefined ||
      input.tileAttribute !== undefined
    )
      return err(
        "terminator_word, newline_word, tile_mask and tile_attribute apply only to the 16-bit word encodings sjis-le16, tile-le16 and tile-be16",
      );
    return ok(undefined);
  }
  const terminatorWord =
    input.terminatorWord !== undefined
      ? input.terminatorWord
      : input.terminatorByte === null
        ? null
        : input.terminatorByte * 0x101;
  const newlineWord = input.newlineWord ?? null;
  if (newlineWord !== null && newlineWord === terminatorWord)
    return err("newline_word must differ from the terminator word");
  if (encoding === "sjis-le16") {
    if (input.tileMask !== undefined || input.tileAttribute !== undefined)
      return err("tile_mask and tile_attribute apply only to tile encodings");
    return ok({ encoding, littleEndian: true, terminatorWord, newlineWord });
  }
  const mask = input.tileMask ?? DEFAULT_TILE_MASK;
  if (mask === 0 || mask > 0xffff)
    return err("tile_mask must select 1..16 bits of the 16-bit word");
  const attribute = input.tileAttribute ?? null;
  if (attribute !== null && (attribute & mask) !== 0)
    return err("tile_attribute must not overlap tile_mask bits");
  const table = input.customTable;
  if (table === undefined)
    return err(
      `Encoding '${encoding}' requires table_path or table_text mapping tile indexes to text`,
    );
  if (table.endTokens.size > 0)
    return err(
      "Tile tables map tile indexes only; use terminator_word instead of .tbl end markers",
    );
  const characters = new Map<number, string>();
  for (const [length, bucket] of table.decodeByLength) {
    if (length > 2)
      return err("Tile table keys must be 1- or 2-byte tile indexes");
    for (const [key, text] of bucket) {
      const tile = Number(key);
      if ((tile & ~mask) !== 0)
        return err(
          `Tile table key 0x${tile.toString(16)} has bits outside tile_mask 0x${mask.toString(16)}`,
        );
      characters.set(tile, text);
    }
  }
  return ok({
    encoding,
    littleEndian: encoding === "tile-le16",
    terminatorWord,
    newlineWord,
    tile: { mask, attribute, characters },
  });
};

const readWord = (
  bytes: Uint8Array,
  at: number,
  littleEndian: boolean,
): number =>
  littleEndian
    ? (bytes[at] ?? 0) | ((bytes[at + 1] ?? 0) << 8)
    : ((bytes[at] ?? 0) << 8) | (bytes[at + 1] ?? 0);

/** Decode one non-control word; group is the attribute value strings keep constant. */
const decodeTextWord = (
  word: number,
  format: RomWordFormat,
): { readonly text: string; readonly group: number } | undefined => {
  if (format.tile === undefined) {
    const text = getSjisDoubleByteDecodeTable()[word];
    return text === undefined ? undefined : { text, group: 0 };
  }
  const { mask, attribute, characters } = format.tile;
  const group = word & ~mask & 0xffff;
  if (attribute !== null && group !== attribute) return undefined;
  const text = characters.get(word & mask);
  return text === undefined ? undefined : { text, group };
};

/** Decode one string of words from the start of `bytes`. */
const decodeWordString = (
  bytes: Uint8Array,
  format: RomWordFormat,
): { readonly text: string; readonly byteLength: number } => {
  const parts: string[] = [];
  let group: number | undefined;
  let pos = 0;
  while (pos + 1 < bytes.length) {
    const word = readWord(bytes, pos, format.littleEndian);
    if (word === format.terminatorWord) {
      pos += 2;
      break;
    }
    if (word === format.newlineWord) {
      parts.push("\n");
      pos += 2;
      continue;
    }
    const decoded = decodeTextWord(word, format);
    if (decoded === undefined) break;
    if (group !== undefined && decoded.group !== group) break;
    group = decoded.group;
    parts.push(decoded.text);
    pos += 2;
  }
  return { text: parts.join(""), byteLength: pos };
};

const encodeWordQuery = (
  query: string,
  format: RomWordFormat,
): Result<Uint8Array, string> => {
  const words: number[] = [];
  if (format.tile === undefined) {
    const map = getSjisEncodeMap();
    for (const char of query) {
      if (char === "\n" && format.newlineWord !== null) {
        words.push(format.newlineWord);
        continue;
      }
      const encoded = map.get(char);
      if (encoded?.length !== 2)
        return err(
          `Character '${char}' has no two-byte Shift-JIS code for sjis-le16`,
        );
      words.push(((encoded[0] ?? 0) << 8) | (encoded[1] ?? 0));
    }
  } else {
    const { attribute, characters } = format.tile;
    if (attribute === null)
      return err("Query search with a tile encoding requires tile_attribute");
    const tiles = new Map<string, number>();
    let longest = 1;
    for (const [tile, text] of characters) {
      if (text.length === 0 || tiles.has(text)) continue;
      tiles.set(text, tile);
      longest = Math.max(longest, text.length);
    }
    let pos = 0;
    while (pos < query.length) {
      if (query[pos] === "\n" && format.newlineWord !== null) {
        words.push(format.newlineWord);
        pos++;
        continue;
      }
      let matched = false;
      for (let len = Math.min(longest, query.length - pos); len >= 1; len--) {
        const tile = tiles.get(query.slice(pos, pos + len));
        if (tile === undefined) continue;
        words.push(attribute | tile);
        pos += len;
        matched = true;
        break;
      }
      if (!matched)
        return err(
          `Substring starting at '${query.slice(pos, pos + 4)}' has no tile in the provided table`,
        );
    }
  }
  const out = new Uint8Array(words.length * 2);
  words.forEach((word, i) => {
    out[i * 2] = format.littleEndian ? word & 0xff : word >>> 8;
    out[i * 2 + 1] = format.littleEndian ? word >>> 8 : word & 0xff;
  });
  return ok(out);
};

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
    case "sjis-swap16":
      return "sjis-le16";
    default:
      return encoding;
  }
};

/** Packed .tbl byte-sequence key: number for up to 6 bytes, bigint beyond. */
export type TblByteKey = number | bigint;

const tblByteKey = (
  bytes: Uint8Array,
  pos: number,
  len: number,
): TblByteKey => {
  if (len <= 6) {
    let key = 0;
    for (let k = 0; k < len; k++) key = key * 256 + (bytes[pos + k] ?? 0);
    return key;
  }
  let key = 0n;
  for (let k = 0; k < len; k++) key = (key << 8n) | BigInt(bytes[pos + k] ?? 0);
  return key;
};

/** Parsed custom .tbl character mapping table for ROM hacking. */
export interface CustomCharTable {
  readonly decodeByLength: ReadonlyMap<number, ReadonlyMap<TblByteKey, string>>;
  readonly maxByteLength: number;
  readonly encodeMap: ReadonlyMap<string, Uint8Array>;
  readonly maxTokenLength: number;
  readonly endTokens: ReadonlySet<TblByteKey>;
}

/** Parse a standard ROM hacking .tbl character table (e.g. "8140= ", "00=[END]"). */
export const parseCustomCharTable = (
  text: string,
): Result<CustomCharTable, string> => {
  const decodeByLength = new Map<number, Map<TblByteKey, string>>();
  const encodeMap = new Map<string, Uint8Array>();
  const endTokens = new Set<TblByteKey>();
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
    const byteKey = tblByteKey(bytes, 0, byteLen);
    const value = rhs === "" && isEndMarker ? "[END]" : rhs;
    let bucket = decodeByLength.get(byteLen);
    if (bucket === undefined) {
      bucket = new Map<TblByteKey, string>();
      decodeByLength.set(byteLen, bucket);
    }
    bucket.set(byteKey, value);
    if (byteLen > maxByteLength) maxByteLength = byteLen;
    if (value.length > 0 && !encodeMap.has(value)) {
      encodeMap.set(value, bytes);
      if (value.length > maxTokenLength) maxTokenLength = value.length;
    }
    if (isEndMarker) {
      endTokens.add(byteKey);
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

let cachedEucJpEncodeMap: Map<string, Uint8Array> | undefined;

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
  words?: RomWordFormat,
): Result<Uint8Array, string> => {
  if (query.length === 0) {
    return err("Query string must not be empty");
  }
  const canonical = normalizeRomTextEncoding(encoding);
  switch (canonical) {
    case "sjis-le16":
    case "tile-le16":
    case "tile-be16": {
      let format = words;
      if (format === undefined) {
        const resolved = resolveRomWordFormat({
          encoding,
          terminatorByte: 0x00,
          customTable,
        });
        if (!resolved.ok) return err(resolved.error);
        format = resolved.value;
      }
      return format === undefined
        ? err(`Encoding '${canonical}' has no word format`)
        : encodeWordQuery(query, format);
    }
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

const HEX_BYTE: readonly string[] = Array.from({ length: 256 }, (_, b) =>
  b.toString(16).padStart(2, "0"),
);

/** Format a Uint8Array as space-separated hex byte pairs for search_bytes or display. */
export const formatHexPattern = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => HEX_BYTE[b]!).join(" ");

/** Decode a single ROM string from a byte buffer up to a terminator byte or invalid sequence. */
export const decodeRomStringFromBytes = (
  bytes: Uint8Array,
  encoding: RomTextEncoding,
  terminatorByte: number | null = 0x00,
  customTable?: CustomCharTable,
  words?: RomWordFormat,
): {
  readonly decoded: string;
  readonly byteLength: number;
  readonly rawHex: string;
} => {
  const canonical = normalizeRomTextEncoding(encoding);
  if (isWordRomTextEncoding(canonical)) {
    let format = words;
    if (format === undefined) {
      const resolved = resolveRomWordFormat({
        encoding: canonical,
        terminatorByte,
        customTable,
      });
      format = resolved.ok ? resolved.value : undefined;
    }
    const decoded =
      format === undefined
        ? { text: "", byteLength: 0 }
        : decodeWordString(bytes, format);
    const slice = bytes.subarray(0, decoded.byteLength);
    return {
      decoded: decoded.text,
      byteLength: slice.length,
      rawHex: formatHexPattern(slice),
    };
  }
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
        const byteKey = tblByteKey(bytes, pos, len);
        const found = bucket.get(byteKey);
        if (found !== undefined) {
          matchedText = found;
          matchedLen = len;
          hitEndToken = customTable.endTokens.has(byteKey);
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

/**
 * Decode one ROM string with declared control codes held apart from the glyph
 * runs, so argument bytes are never read as text and line breaks are visible.
 */
export const decodeRomStringWithControlCodes = (
  bytes: Uint8Array,
  encoding: RomTextEncoding,
  terminatorByte: number | null,
  customTable: CustomCharTable | undefined,
  codes: RomControlCodeTable,
  words?: RomWordFormat | undefined,
): RomTextWithControlCodes => {
  const canonical = normalizeRomTextEncoding(encoding);
  if (isWordRomTextEncoding(canonical)) {
    const format =
      words ??
      (() => {
        const res = resolveRomWordFormat({
          encoding: canonical,
          terminatorByte,
          customTable,
        });
        return res.ok ? res.value : undefined;
      })();
    const effectiveCodes =
      format !== undefined ? withWordFormatControlCodes(codes, format) : codes;
    return decodeRomTextWithControlCodes(
      bytes,
      effectiveCodes,
      (run) =>
        decodeRomStringFromBytes(
          run,
          canonical,
          null,
          customTable,
          format === undefined
            ? undefined
            : { ...format, terminatorWord: null },
        ).decoded,
      2,
    );
  }
  return decodeRomTextWithControlCodes(
    bytes,
    withTerminatorAsEndCode(codes, terminatorByte),
    // Each run already ends at a code or the buffer, so no terminator applies.
    (run) => decodeRomStringFromBytes(run, encoding, null, customTable).decoded,
  );
};

/** Re-export so result builders need one import for a code occurrence. */
export type { RomTextWithControlCodes, InferredBaseCandidate };
export {
  inferOverlayLoadAddress,
  findOrphanStringsInPointerGaps,
  inferredBaseCandidateSchema,
  orphanStringEntrySchema,
};

/** Which word alignments a 16-bit word scan examines, by absolute offset. */
export const ROM_WORD_PARITIES = ["both", "even", "odd"] as const;
export type RomWordParity = (typeof ROM_WORD_PARITIES)[number];

/**
 * Where a range scan restarts so it reproduces the same string boundaries.
 * Byte scans restart at one buffer offset. Word scans keep one pending run
 * start per absolute parity (index 0 = even, 1 = odd; null = finished or not
 * scanned), because strings of the two alignments interleave.
 */
export type RomScanResume =
  | { readonly kind: "byte"; readonly offset: number }
  | {
      readonly kind: "word";
      readonly heads: readonly [number | null, number | null];
    };

/** Opaque cursor text for a resume point. */
export const formatRomScanCursor = (resume: RomScanResume): string =>
  resume.kind === "byte"
    ? String(resume.offset)
    : `w${resume.heads.map((head) => (head === null ? "-" : String(head))).join(".")}`;

/**
 * Parse a cursor produced by formatRomScanCursor for the same scan. Word
 * cursors must name run starts of the right parity inside the buffer.
 */
export const parseRomScanCursor = (
  cursor: string,
  scan: {
    readonly word: boolean;
    readonly bufferLength: number;
    readonly parityOrigin: number;
  },
): Result<RomScanResume, string> => {
  const invalid = err(
    "Invalid cursor: pass back the next_cursor value from the previous identical call.",
  );
  const text = cursor.trim();
  if (!scan.word) {
    if (!/^\d+$/u.test(text)) return invalid;
    const offset = Number(text);
    return Number.isSafeInteger(offset)
      ? ok({ kind: "byte", offset })
      : invalid;
  }
  const match = /^w(\d+|-)\.(\d+|-)$/u.exec(text);
  if (match === null) return invalid;
  const heads: (number | null)[] = [];
  for (const [parity, raw] of [match[1], match[2]].entries()) {
    if (raw === "-" || raw === undefined) {
      heads.push(null);
      continue;
    }
    const head = Number(raw);
    if (
      !Number.isSafeInteger(head) ||
      head > scan.bufferLength ||
      (scan.parityOrigin + head) % 2 !== parity
    )
      return invalid;
    heads.push(head);
  }
  return ok({ kind: "word", heads: [heads[0] ?? null, heads[1] ?? null] });
};

/** One string found by a range scan. */
export interface ScannedRomString {
  readonly offsetInBuffer: number;
  readonly address: string;
  readonly decoded: string;
  readonly byteLength: number;
  readonly rawHex: string;
  /** Whether the string ended at its terminator (byte, word or .tbl end token). */
  readonly terminated: boolean;
  /** text_score, present when requested or when filters need it. */
  readonly score?: number;
  /** Control-code display metadata when controlCodes was supplied. */
  readonly display?: RomTextWithControlCodes | undefined;
  /** Restart point that yields this string first. */
  readonly resume: RomScanResume;
}

export interface RomStringScanInput {
  readonly bytes: Uint8Array;
  readonly baseAddress: bigint;
  readonly encoding: RomTextEncoding;
  readonly minLength: number;
  readonly terminatorByte: number | null;
  readonly customTable?: CustomCharTable | undefined;
  /** Required for word encodings; resolved by resolveRomWordFormat. */
  readonly words?: RomWordFormat | undefined;
  /** Optional control-code table so inline codes and operand bytes do not split strings. */
  readonly controlCodes?: RomControlCodeTable | undefined;
  /** When false, rawHex is "" and no hex formatting is paid per string. */
  readonly includeRawHex?: boolean | undefined;
  /** Buffer offset to start scanning from. */
  readonly startOffset?: number | undefined;
  /** Restart point from a previous page; overrides startOffset. */
  readonly resume?: RomScanResume | undefined;
  readonly filters?: RomTextFilters | undefined;
  /** Report text_score on every string. */
  readonly measure?: boolean | undefined;
  /** Keep only strings that ended at their terminator. */
  readonly requireTerminator?: boolean | undefined;
  readonly wordParity?: RomWordParity | undefined;
  /** Absolute offset of bytes[0], which fixes word parity. */
  readonly parityOrigin?: number | undefined;
}

interface RawScannedString {
  readonly offsetInBuffer: number;
  readonly decoded: string;
  readonly byteLength: number;
  readonly terminated: boolean;
  readonly display?: RomTextWithControlCodes | undefined;
}

/**
 * Lazily scan a buffer for strings. Boundaries depend only on the bytes and
 * the format: filters and requireTerminator drop strings after segmentation,
 * so restarting at any yielded `resume` reproduces the same later strings.
 */
export function* scanRomStrings(
  input: RomStringScanInput,
): Generator<ScannedRomString, void, undefined> {
  const filters = input.filters ?? NO_ROM_TEXT_FILTERS;
  const needsMeasure = input.measure === true || romTextFiltersActive(filters);
  const accept = (
    raw: RawScannedString,
    resume: RomScanResume,
  ): ScannedRomString | undefined => {
    if (input.requireTerminator === true && !raw.terminated) return undefined;
    let score: number | undefined;
    if (needsMeasure) {
      const measured = measureRomText(raw.decoded);
      if (!romTextPassesFilters(measured, filters)) return undefined;
      score = measured.score;
    }
    const slice = input.bytes.subarray(
      raw.offsetInBuffer,
      raw.offsetInBuffer + raw.byteLength,
    );
    return {
      offsetInBuffer: raw.offsetInBuffer,
      address: `0x${(input.baseAddress + BigInt(raw.offsetInBuffer)).toString(16)}`,
      decoded: raw.decoded,
      byteLength: raw.byteLength,
      rawHex: input.includeRawHex === false ? "" : formatHexPattern(slice),
      terminated: raw.terminated,
      ...(input.measure === true && score !== undefined ? { score } : {}),
      ...(raw.display !== undefined ? { display: raw.display } : {}),
      resume,
    };
  };

  if (isWordRomTextEncoding(normalizeRomTextEncoding(input.encoding))) {
    const format = input.words;
    if (format === undefined) return;
    yield* scanWordStrings(input, format, accept);
    return;
  }
  const start =
    input.resume?.kind === "byte" ? input.resume.offset : input.startOffset;
  for (const raw of scanByteStrings(input, start, filters.fullwidthOnly)) {
    const accepted = accept(raw, {
      kind: "byte",
      offset: raw.offsetInBuffer,
    });
    if (accepted !== undefined) yield accepted;
  }
}

function* scanWordStrings(
  input: RomStringScanInput,
  format: RomWordFormat,
  accept: (
    raw: RawScannedString,
    resume: RomScanResume,
  ) => ScannedRomString | undefined,
): Generator<ScannedRomString, void, undefined> {
  const { bytes } = input;
  const origin = input.parityOrigin ?? 0;
  const parity = input.wordParity ?? "both";
  const begin = Math.min(
    Math.max(0, Math.floor(input.startOffset ?? 0)),
    bytes.length,
  );
  const startFor = (absoluteParity: 0 | 1): number | null => {
    if (
      (parity === "even" && absoluteParity === 1) ||
      (parity === "odd" && absoluteParity === 0)
    )
      return null;
    if (input.resume?.kind === "word")
      return input.resume.heads[absoluteParity];
    return (origin + begin) % 2 === absoluteParity ? begin : begin + 1;
  };
  const streams = ([0, 1] as const).map((absoluteParity) => {
    const at = startFor(absoluteParity);
    if (at === null) return undefined;
    const runs = scanWordRuns(
      bytes,
      at,
      format,
      input.minLength,
      input.controlCodes,
    );
    return (function* () {
      for (const raw of runs) {
        // The resume head is filled in by the merge below.
        const accepted = accept(raw, { kind: "word", heads: [null, null] });
        if (accepted !== undefined) yield accepted;
      }
    })();
  });
  const heads = streams.map((stream) => stream?.next());
  for (;;) {
    let pick: 0 | 1 | undefined;
    for (const k of [0, 1] as const) {
      const head = heads[k];
      if (head === undefined || head.done === true) continue;
      const other = pick === undefined ? undefined : heads[pick];
      if (
        other === undefined ||
        other.done === true ||
        head.value.offsetInBuffer < other.value.offsetInBuffer
      )
        pick = k;
    }
    if (pick === undefined) return;
    const headOffset = (k: 0 | 1): number | null => {
      const head = heads[k];
      return head === undefined || head.done === true
        ? null
        : head.value.offsetInBuffer;
    };
    const current = heads[pick] as IteratorYieldResult<ScannedRomString>;
    yield {
      ...current.value,
      resume: { kind: "word", heads: [headOffset(0), headOffset(1)] },
    };
    heads[pick] = streams[pick]?.next();
  }
}

/** Runs of text words of one alignment, starting at a run start `at`. */
function* scanWordRuns(
  bytes: Uint8Array,
  at: number,
  format: RomWordFormat,
  minLength: number,
  controlCodes?: RomControlCodeTable | undefined,
): Generator<RawScannedString, void, undefined> {
  let pos = at;
  while (pos + 1 < bytes.length) {
    const runStart = pos;
    const parts: string[] = [];
    let characters = 0;
    let group: number | undefined;
    let terminated = false;
    let groupChanged = false;
    let usedControlCodes = false;
    while (pos + 1 < bytes.length) {
      if (characters > 0 && controlCodes !== undefined) {
        const ctrl = matchRomControlCodeAt(bytes, pos, controlCodes);
        if (ctrl !== undefined) {
          const totalBytes = ctrl.bytes.length + ctrl.argumentBytes;
          if (pos + totalBytes > bytes.length) break;
          pos += totalBytes;
          usedControlCodes = true;
          if (ctrl.role === "end") {
            terminated = true;
            break;
          }
          if (ctrl.role === "line-break" || ctrl.role === "page-break") {
            parts.push("\n");
          }
          continue;
        }
      }
      const word = readWord(bytes, pos, format.littleEndian);
      if (word === format.terminatorWord) {
        pos += 2;
        terminated = true;
        break;
      }
      if (word === format.newlineWord) {
        parts.push("\n");
        pos += 2;
        continue;
      }
      const decoded = decodeTextWord(word, format);
      if (decoded === undefined) break;
      if (group !== undefined && decoded.group !== group) {
        groupChanged = true;
        break;
      }
      group = decoded.group;
      parts.push(decoded.text);
      characters++;
      pos += 2;
    }
    if (characters >= minLength) {
      if (controlCodes !== undefined) {
        const withCodes = decodeRomStringWithControlCodes(
          bytes.subarray(runStart, pos),
          format.encoding,
          null,
          undefined,
          controlCodes,
          format,
        );
        yield {
          offsetInBuffer: runStart,
          decoded: withCodes.text,
          byteLength: pos - runStart,
          terminated,
          display: withCodes,
        };
      } else {
        yield {
          offsetInBuffer: runStart,
          decoded: parts.join(""),
          byteLength: pos - runStart,
          terminated,
        };
      }
    }
    if (characters < minLength && usedControlCodes) {
      pos = runStart + 2;
      continue;
    }
    // A word with another attribute starts the next run; any other stop word
    // (not text, not a control word) cannot start one.
    if (!terminated && !groupChanged && pos + 1 < bytes.length) pos += 2;
  }
}

/** Byte-encoding segmentation (Shift-JIS, EUC-JP, .tbl, ASCII/UTF-8). */
function* scanByteStrings(
  input: RomStringScanInput,
  startOffset: number | undefined,
  fullwidthOnly: boolean,
): Generator<RawScannedString, void, undefined> {
  const { bytes, minLength, terminatorByte, customTable, controlCodes } = input;
  const canonical = normalizeRomTextEncoding(input.encoding);
  const sjisDecoder =
    canonical === "sjis" || canonical === "cp932"
      ? new TextDecoder("shift-jis", { fatal: true })
      : canonical === "euc-jp"
        ? new TextDecoder("euc-jp", { fatal: true })
        : undefined;

  const tblMapsZero =
    canonical === "tbl" &&
    customTable !== undefined &&
    customTable.decodeByLength.get(1)?.has(0) === true &&
    !customTable.endTokens.has(0);

  const isSjisFamily = canonical === "sjis" || canonical === "cp932";
  const unitLengthAt = (at: number): number => {
    const b0 = bytes[at] ?? 0;
    if (isSjisFamily) {
      const isLead = (b0 >= 0x81 && b0 <= 0x9f) || (b0 >= 0xe0 && b0 <= 0xfc);
      if (isLead) {
        if (at + 1 >= bytes.length) return 0;
        const b1 = bytes[at + 1] ?? 0;
        return b1 >= 0x40 && b1 <= 0xfc && b1 !== 0x7f ? 2 : 0;
      }
      if (fullwidthOnly) return 0;
      return (b0 >= 0x20 && b0 <= 0x7e) || (b0 >= 0xa1 && b0 <= 0xdf) ? 1 : 0;
    }
    if (b0 >= 0xa1 && b0 <= 0xfe) {
      if (at + 1 >= bytes.length) return 0;
      const b1 = bytes[at + 1] ?? 0;
      return b1 >= 0xa1 && b1 <= 0xfe ? 2 : 0;
    }
    if (fullwidthOnly) return 0;
    return b0 >= 0x20 && b0 <= 0x7e ? 1 : 0;
  };
  const isMultibyteUnit = (at: number, unitLength: number): boolean =>
    unitLength === 2 || (isSjisFamily && (bytes[at] ?? 0) >= 0xa1);

  let cursor = Math.min(
    Math.max(0, Math.floor(startOffset ?? 0)),
    bytes.length,
  );
  while (cursor < bytes.length) {
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
      let terminated = false;
      while (pos < bytes.length) {
        if (chars.length > 0 && controlCodes !== undefined) {
          const ctrl = matchRomControlCodeAt(bytes, pos, controlCodes);
          if (ctrl !== undefined) {
            const totalBytes = ctrl.bytes.length + ctrl.argumentBytes;
            if (pos + totalBytes > bytes.length) break;
            pos += totalBytes;
            if (ctrl.role === "end") {
              terminated = true;
              break;
            }
            if (ctrl.role === "line-break" || ctrl.role === "page-break") {
              chars.push("\n");
            }
            continue;
          }
        }
        let matchedText: string | undefined;
        let matchedLen = 0;
        let hitEnd = false;
        const maxLen = Math.min(customTable.maxByteLength, bytes.length - pos);
        for (let len = maxLen; len >= 1; len--) {
          const bucket = customTable.decodeByLength.get(len);
          if (bucket === undefined) continue;
          const byteKey = tblByteKey(bytes, pos, len);
          const found = bucket.get(byteKey);
          if (found !== undefined) {
            matchedText = found;
            matchedLen = len;
            hitEnd = customTable.endTokens.has(byteKey);
            break;
          }
        }
        if (
          terminatorByte !== null &&
          bytes[pos] === terminatorByte &&
          (matchedText === undefined || (terminatorByte !== 0x00 && !hitEnd))
        ) {
          pos++;
          terminated = true;
          break;
        }
        if (matchedText === undefined) break;
        chars.push(matchedText);
        pos += matchedLen;
        if (hitEnd) {
          terminated = true;
          break;
        }
      }
      if (chars.length >= minLength) {
        if (controlCodes !== undefined) {
          const withCodes = decodeRomStringWithControlCodes(
            bytes.subarray(cursor, pos),
            canonical,
            terminatorByte,
            customTable,
            controlCodes,
          );
          yield {
            offsetInBuffer: cursor,
            decoded: withCodes.text,
            byteLength: pos - cursor,
            terminated,
            display: withCodes,
          };
        } else {
          yield {
            offsetInBuffer: cursor,
            decoded: chars.join(""),
            byteLength: pos - cursor,
            terminated,
          };
        }
        cursor = pos;
        continue;
      }
      cursor++;
      continue;
    }

    if (sjisDecoder !== undefined) {
      let pos = cursor;
      let charCount = 0;
      let multibyteCount = 0;
      let terminated = false;
      let usedControlCodes = false;
      while (pos < bytes.length) {
        if (charCount > 0 && controlCodes !== undefined) {
          const ctrl = matchRomControlCodeAt(bytes, pos, controlCodes);
          if (ctrl !== undefined) {
            const totalBytes = ctrl.bytes.length + ctrl.argumentBytes;
            if (pos + totalBytes > bytes.length) break;
            pos += totalBytes;
            usedControlCodes = true;
            if (ctrl.role === "end") {
              terminated = true;
              break;
            }
            continue;
          }
        }
        const b0 = bytes[pos] ?? 0;
        if (terminatorByte !== null && b0 === terminatorByte) {
          pos++;
          terminated = true;
          break;
        }
        const unitLength = unitLengthAt(pos);
        if (unitLength === 0) break;
        if (controlCodes !== undefined) {
          try {
            sjisDecoder.decode(bytes.subarray(pos, pos + unitLength));
          } catch {
            break;
          }
        }
        if (isMultibyteUnit(pos, unitLength)) multibyteCount++;
        charCount++;
        pos += unitLength;
      }
      if (charCount >= minLength && multibyteCount > 0) {
        if (controlCodes !== undefined) {
          const withCodes = decodeRomStringWithControlCodes(
            bytes.subarray(cursor, pos),
            canonical,
            terminatorByte,
            customTable,
            controlCodes,
          );
          yield {
            offsetInBuffer: cursor,
            decoded: withCodes.text,
            byteLength: pos - cursor,
            terminated,
            display: withCodes,
          };
          cursor = Math.max(pos, cursor + 1);
          continue;
        }
        const contentEnd = terminated ? pos - 1 : pos;
        let decoded: string | undefined;
        let acceptedEnd = pos;
        let acceptedTerminated = terminated;
        try {
          decoded = sjisDecoder.decode(bytes.subarray(cursor, contentEnd));
        } catch {
          const parts: string[] = [];
          let prefixChars = 0;
          let prefixMultibyte = 0;
          let scan = cursor;
          while (scan < contentEnd) {
            const unitLength = unitLengthAt(scan);
            if (unitLength === 0) break;
            try {
              parts.push(
                sjisDecoder.decode(bytes.subarray(scan, scan + unitLength)),
              );
            } catch {
              break;
            }
            if (isMultibyteUnit(scan, unitLength)) prefixMultibyte++;
            prefixChars++;
            scan += unitLength;
          }
          if (prefixChars >= minLength && prefixMultibyte > 0) {
            decoded = parts.join("");
            acceptedEnd = scan;
            acceptedTerminated = false;
          }
        }
        if (decoded !== undefined) {
          yield {
            offsetInBuffer: cursor,
            decoded,
            byteLength: acceptedEnd - cursor,
            terminated: acceptedTerminated,
          };
          cursor = Math.max(acceptedEnd, cursor + 1);
          continue;
        }
      }
      cursor = usedControlCodes ? cursor + 1 : Math.max(pos, cursor + 1);
      continue;
    }

    // ASCII / UTF-8 printable run
    let pos = cursor;
    let charLen = 0;
    let terminated = false;
    let usedControlCodes = false;
    while (pos < bytes.length) {
      if (charLen > 0 && controlCodes !== undefined) {
        const ctrl = matchRomControlCodeAt(bytes, pos, controlCodes);
        if (ctrl !== undefined) {
          const totalBytes = ctrl.bytes.length + ctrl.argumentBytes;
          if (pos + totalBytes > bytes.length) break;
          pos += totalBytes;
          usedControlCodes = true;
          if (ctrl.role === "end") {
            terminated = true;
            break;
          }
          continue;
        }
      }
      const b = bytes[pos] ?? 0;
      if (terminatorByte !== null && b === terminatorByte) {
        pos++;
        terminated = true;
        break;
      }
      if (b >= 0x20 && b <= 0x7e) {
        charLen++;
        pos++;
        continue;
      }
      break;
    }
    if (charLen >= minLength) {
      const slice = bytes.subarray(cursor, pos);
      if (controlCodes !== undefined) {
        const withCodes = decodeRomStringWithControlCodes(
          slice,
          canonical,
          terminatorByte,
          customTable,
          controlCodes,
        );
        yield {
          offsetInBuffer: cursor,
          decoded: withCodes.text,
          byteLength: slice.length,
          terminated,
          display: withCodes,
        };
      } else {
        yield {
          offsetInBuffer: cursor,
          decoded: decodeRomStringFromBytes(slice, canonical, terminatorByte)
            .decoded,
          byteLength: slice.length,
          terminated,
        };
      }
      cursor = pos;
      continue;
    }
    // A rejected printable run's suffixes are shorter, so jump past it.
    cursor = usedControlCodes ? cursor + 1 : Math.max(pos, cursor + 1);
  }
}

/** Scan a buffer for valid contiguous strings in the requested ROM encoding. */
export const extractRomStringsFromBuffer = (
  input: RomStringScanInput & { readonly limit: number },
): readonly ScannedRomString[] => {
  const results: ScannedRomString[] = [];
  if (input.limit <= 0) return results;
  for (const found of scanRomStrings(input)) {
    results.push(found);
    if (results.length >= input.limit) break;
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
  // Width is at most 4 bytes, so the value is exact in a double; convert once.
  let val = 0;
  if (endianness === "little") {
    for (let i = width - 1; i >= 0; i--) {
      val = val * 256 + (bytes[offset + i] ?? 0);
    }
  } else {
    for (let i = 0; i < width; i++) {
      val = val * 256 + (bytes[offset + i] ?? 0);
    }
  }
  return BigInt(val);
};

/** Word-encoding options shared by every ROM text tool. */
const romWordFormatFields = {
  terminator_word: z
    .number()
    .int()
    .min(0)
    .max(0xffff)
    .nullable()
    .optional()
    .describe(
      "16-bit word ending a string in sjis-le16/tile-le16/tile-be16 (e.g. 0xFFFF); default terminator_byte doubled; null for none.",
    ),
  newline_word: z
    .number()
    .int()
    .min(0)
    .max(0xffff)
    .optional()
    .describe(
      "16-bit word decoded as a line break inside word-encoded strings (e.g. 0xFFFE).",
    ),
  tile_mask: z
    .number()
    .int()
    .min(1)
    .max(0xffff)
    .optional()
    .describe(
      "Tile-index bits of tile-le16/tile-be16 words (default 0x0FFF, PC Engine BAT); table keys are tile indexes.",
    ),
  tile_attribute: z
    .number()
    .int()
    .min(0)
    .max(0xffff)
    .nullable()
    .optional()
    .describe(
      "Required non-tile bits of tilemap words (e.g. 0xF000 = palette 15); omit to accept one consistent value per string.",
    ),
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
    .default(false)
    .describe(
      "Resolve incoming cross-references for each matched string via the disassembler (opt-in; file offsets are always resolved). Default false keeps local ROM scans provider-free.",
    ),
  include_hex: z
    .boolean()
    .default(false)
    .describe(
      "Include each match's raw bytes as hex (bytes_hex). Default false omits it to keep results compact; byte_length is always reported.",
    ),
  ...romWordFormatFields,
  word_parity: z
    .enum(ROM_WORD_PARITIES)
    .default("both")
    .describe(
      "File-offset alignments a word-encoding range scan examines; strings may start at odd offsets.",
    ),
  fullwidth_only: z
    .boolean()
    .default(false)
    .describe(
      "Range scan: treat single-byte characters (ASCII, half-width kana) as non-text.",
    ),
  min_kana: z
    .number()
    .int()
    .min(0)
    .max(256)
    .default(0)
    .describe("Range scan: minimum full-width hiragana/katakana per string."),
  max_level2_kanji_ratio: z
    .number()
    .min(0)
    .max(1)
    .optional()
    .describe(
      "Range scan: maximum share of JIS level-2 kanji among a string's kanji (data noise is often level 2).",
    ),
  min_text_score: z
    .number()
    .min(0)
    .max(1)
    .optional()
    .describe(
      "Range scan: minimum heuristic text_score (0..1; kana and punctuation high, rare symbols low).",
    ),
  include_score: z
    .boolean()
    .default(false)
    .describe("Range scan: report text_score on each match."),
  require_terminator: z
    .boolean()
    .default(false)
    .describe(
      "Range scan: keep only strings that end at their terminator byte/word.",
    ),
  dedupe: z
    .boolean()
    .default(false)
    .describe(
      "Range scan: return each distinct byte string once with occurrences (every file offset) over the whole range.",
    ),
  cursor: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Opaque continuation token from a previous identical call's next_cursor; resumes after the last returned match.",
    ),
  ...romControlCodeFields,
});

export type SearchRomStringsInput = z.output<
  typeof searchRomStringsInputSchema
>;

/** Disc layout behind a `disc-image` byte source (JSON-shaped). */
export type RomDiscSourceDescription = {
  readonly track: number;
  readonly track_mode: DataTrackMode;
  readonly image_path: string;
  readonly image_sha256: string;
  readonly first_lba: number;
  readonly sectors: number;
  readonly raw_sector_bytes: number;
  readonly user_data_offset: number;
  readonly first_sector_in_image: number;
  readonly header_mismatched_sectors: number;
  readonly first_mismatched_sector: number | null;
  readonly other_data_tracks: number[];
};

/** Result `source` block; validated by romByteSourceSchema. */
export type RomByteSourceDescription = {
  readonly mode: "data" | "disc-image";
  readonly reason: "requested" | "format_not_recognized";
  readonly byte_length: number;
  readonly sector_size?: number;
  /** Dump byte permutation undone while reading; file offsets are unchanged. */
  readonly byte_swap_undone?: 16 | 32;
  readonly disc?: RomDiscSourceDescription;
};

/**
 * How a local file was read when it was not admitted as an executable or ROM:
 * plain file bytes, or the user data of a cue sheet's first data track.
 */
export const romByteSourceSchema = z.strictObject({
  mode: z.enum(["data", "disc-image"]),
  reason: z.enum(["requested", "format_not_recognized"]),
  byte_length: z.number().int().min(0),
  /** User-data sector size; file offsets divide into sectors of this size. */
  sector_size: z.number().int().min(1).optional(),
  /** Dump byte permutation undone while reading; file offsets are unchanged. */
  byte_swap_undone: z.union([z.literal(16), z.literal(32)]).optional(),
  disc: z
    .strictObject({
      track: z.number().int().min(1),
      track_mode: z.enum(DATA_TRACK_MODES),
      image_path: z.string(),
      image_sha256: z.string(),
      first_lba: z.number().int().min(0),
      sectors: z.number().int().min(0),
      raw_sector_bytes: z.number().int().min(1),
      user_data_offset: z.number().int().min(0),
      first_sector_in_image: z.number().int().min(0),
      header_mismatched_sectors: z.number().int().min(0),
      first_mismatched_sector: z.number().int().min(0).nullable(),
      other_data_tracks: z.array(z.number().int().min(1)),
    })
    .optional(),
});

export const romStringMatchSchema = z.strictObject({
  address: z.string(),
  file_offset: z.number().int().min(0).nullable(),
  /** Track-relative user-data sector (the .iso sector number). */
  sector: z.number().int().min(0).optional(),
  offset_in_sector: z.number().int().min(0).optional(),
  /** Absolute disc LBA of `sector`, when the cue sheet establishes it. */
  lba: z.number().int().min(0).optional(),
  encoding: z.enum(ROM_TEXT_ENCODINGS),
  text: z.string(),
  text_truncated: z.boolean().optional(),
  text_score: z.number().min(0).max(1).optional(),
  lines: z.array(z.string()).optional(),
  character_length: z.number().int().min(0).optional(),
  longest_line_characters: z.number().int().min(0).optional(),
  control_codes: z.array(romControlCodeUseSchema).optional(),
  bytes_hex: z.string().optional(),
  byte_length: z.number().int().min(0),
  terminated: z.boolean(),
  /** With dedupe: file offsets of every copy, in order, including this one. */
  occurrences: z.array(z.number().int().min(0)).optional(),
  xrefs: z.array(z.string()),
});

export const searchRomStringsResultSchema = z.strictObject({
  mode: z.enum(["query_search", "range_scan"]),
  encoding: z.enum(ROM_TEXT_ENCODINGS),
  encoded_query_pattern: z.string().nullable(),
  matches: z.array(romStringMatchSchema),
  total_matches: z.number().int().min(0),
  truncated: z.boolean(),
  next_cursor: z.string().nullable().optional(),
  source: romByteSourceSchema.optional(),
});

/** How raw pointer values become file offsets (shared by the pointer tools). */
export const POINTER_BASE_MODES = ["address", "segment"] as const;

const pointerSegmentFields = {
  base_mode: z
    .enum(POINTER_BASE_MODES)
    .optional()
    .describe(
      "How raw pointer values become file offsets: address = base_address + value through the target's address space; segment = segment start file offset + value (overlay-relative offsets). Defaults to segment when a segment field is set, otherwise address.",
    ),
  segment_start: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe(
      "File offset of the segment (overlay block) the pointer values are relative to.",
    ),
  segment_length: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe(
      "Segment byte length; pointer values at or past it are invalid. Required with base_mode segment.",
    ),
};

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
    .max(16_384)
    .default(32)
    .describe("Number of pointer table entries to read."),
  start_index: z
    .number()
    .int()
    .min(0)
    .default(0)
    .describe(
      "First entry index to read (for paging tables larger than count); entry and manuscript indexes stay global across pages.",
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
  ...pointerSegmentFields,
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
  ...romWordFormatFields,
  resolve_xrefs: z
    .boolean()
    .default(false)
    .describe(
      "Resolve incoming cross-references to each pointer table slot and target address via the disassembler (opt-in; file offsets are always resolved). Default false keeps local ROM scans provider-free.",
    ),
  include_manuscript: z
    .boolean()
    .default(false)
    .describe(
      "Emit locbatch.py-compatible manuscript records (id, pointer_offset, target_offset, max_bytes, jp, ko) alongside pointer entries.",
    ),
  include_hex: z
    .boolean()
    .default(false)
    .describe(
      "Include each preview's raw bytes as hex (preview_bytes_hex). Default false reports null there to keep results compact; preview_byte_length is always reported.",
    ),
  manuscript_only: z
    .boolean()
    .default(false)
    .describe(
      "Emit manuscript records and suppress pointer entries (entries is empty, entries_scanned still reports the scanned count). Implies include_manuscript.",
    ),
  include_orphan_strings: z
    .boolean()
    .optional()
    .describe(
      "Scan gaps between sorted pointer targets for unreferenced strings. Discovered starts cut preceding slot budgets; include_manuscript also emits origin: orphan records with null pointer fields. Examines gaps up to 4096 bytes and stops at undecodable data; not exhaustive script coverage.",
    ),
  ...romControlCodeFields,
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
  preview_truncated: z.boolean().optional(),
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
  truncated: z.boolean().optional(),
  also_referenced_by: z.array(z.number().int().min(0)).optional(),
  lines: z.array(z.string()).optional(),
  character_length: z.number().int().min(0).optional(),
  longest_line_characters: z.number().int().min(0).optional(),
  control_codes: z.array(romControlCodeUseSchema).optional(),
  ko: z.string(),
});

const orphanManuscriptRecordSchema = manuscriptRecordSchema
  .omit({
    index: true,
    pointer_address: true,
    pointer_file_offset: true,
    also_referenced_by: true,
  })
  .extend({
    origin: z.literal("orphan"),
    pointer_address: z.null(),
    pointer_file_offset: z.null(),
    after_entry_index: z.number().int().min(0),
    gap_index: z.number().int().min(0),
  });
const extractedManuscriptRecordSchema = z.union([
  manuscriptRecordSchema,
  orphanManuscriptRecordSchema,
]);
export type ManuscriptRecord = z.output<typeof extractedManuscriptRecordSchema>;

export const scanPointerTableResultSchema = z.strictObject({
  table_address: z.string(),
  table_file_offset: z.number().int().min(0).nullable().optional(),
  pointer_size: z.union([z.literal(2), z.literal(3), z.literal(4)]),
  endian: z.enum(["little", "big"]),
  base_address: z.string(),
  base_mode: z.enum(POINTER_BASE_MODES).optional(),
  segment_start: z.number().int().min(0).optional(),
  segment_length: z.number().int().min(1).optional(),
  stride: z.number().int().min(1),
  encoding: z.enum(ROM_TEXT_ENCODINGS),
  entries: z.array(pointerTableEntrySchema),
  entries_scanned: z.number().int().min(0),
  start_index: z.number().int().min(0).optional(),
  next_start_index: z.number().int().min(0).optional(),
  manuscript_records: z.array(extractedManuscriptRecordSchema).optional(),
  /** Unreferenced strings discovered in gaps between sorted pointer targets when include_orphan_strings is true. */
  orphan_strings: z.array(orphanStringEntrySchema).optional(),
  /** Whether the scanned entries cover their string region (local bytes with a terminator). */
  coverage: pointerTableCoverageSchema.nullable().optional(),
  source: romByteSourceSchema.optional(),
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
      "Base address added to each raw pointer value (e.g. 0x08000000 for 16-bit relative offsets), or the RAM load base address of an overlay.",
    ),
  infer_base_address: z
    .boolean()
    .optional()
    .describe(
      "Automatically infer candidate RAM load base addresses for headerless overlays/binaries by matching pointer table deltas to string start offsets. When base_address is 0x0, uses the best inferred base address.",
    ),
  stride: z
    .number()
    .int()
    .min(1)
    .max(64)
    .optional()
    .describe("Bytes per table entry; defaults to pointer_size."),
  ...pointerSegmentFields,
  segment_align: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe(
      "Try every multiple of this file offset as the segment start (e.g. 2048 for overlays loaded from disc sectors); each table must lie inside its segment and reports the start that fits. Use instead of segment_start.",
    ),
  target_after_terminator: z
    .boolean()
    .default(false)
    .describe(
      "Accept only sentence starts as targets: the previous byte/word is the terminator, or the target is the segment start, or the string begins exactly where the table ends. Empty strings (a lone terminator) count; a table still needs two distinct non-empty targets.",
    ),
  min_coverage: z
    .number()
    .min(0)
    .max(1)
    .optional()
    .describe(
      "Keep only tables whose coverage ratio reaches this value (1 = every string start in the table's region is an entry target); needs a terminator. A rejected run does not hide a table that starts inside it.",
    ),
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
    .max(1000)
    .default(20)
    .describe(
      "Maximum number of candidate pointer tables to return; truncated and next_start_offset report where to resume.",
    ),
  sample_entries: z
    .number()
    .int()
    .min(1)
    .max(16)
    .default(3)
    .describe("Number of sample entries to include per discovered table."),
  ...romWordFormatFields,
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
  /** Segment start the entries are relative to (base_mode segment). */
  segment_start: z.number().int().min(0).optional(),
  /** Whether the table covers its string region (needs a terminator). */
  coverage: pointerTableCoverageSchema.nullable().optional(),
});

export const discoverPointerTablesResultSchema = z.strictObject({
  encoding: z.enum(ROM_TEXT_ENCODINGS),
  pointer_size: z.union([z.literal(2), z.literal(3), z.literal(4)]),
  endian: z.enum(["little", "big"]),
  base_address: z.string(),
  inferred_base_address: z.string().nullable().optional(),
  inferred_base_candidates: z.array(inferredBaseCandidateSchema).optional(),
  stride: z.number().int().min(1),
  bytes_scanned: z.number().int().min(0),
  base_mode: z.enum(POINTER_BASE_MODES).optional(),
  segment_start: z.number().int().min(0).optional(),
  segment_length: z.number().int().min(1).optional(),
  segment_align: z.number().int().min(1).optional(),
  target_after_terminator: z.boolean().optional(),
  min_coverage: z.number().min(0).max(1).optional(),
  tables: z.array(discoveredPointerTableSchema),
  total_tables: z.number().int().min(0),
  /** max_tables was reached before the end of the range. */
  truncated: z.boolean().optional(),
  /** File offset to pass as start_offset to continue a truncated scan. */
  next_start_offset: z.number().int().min(0).optional(),
  source: romByteSourceSchema.optional(),
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
  source: romByteSourceSchema.optional(),
});

/** Scan a byte slice for contiguous runs of 0x00 or 0xFF (or explicit fillByte) aligned to `alignment`. */
export interface CodeCaveSliceEntry {
  readonly address: string;
  readonly file_offset: number;
  readonly byte_length: number;
  readonly fill_byte: string;
  readonly region_name: string | null;
  readonly executable: boolean;
}

const compareCodeCaves = (
  a: CodeCaveSliceEntry,
  b: CodeCaveSliceEntry,
): number => b.byte_length - a.byte_length || a.file_offset - b.file_offset;

/** Top-K variant: counts every cave while retaining only the largest `limit`. */
export const findCodeCavesInSliceTopK = (input: {
  readonly bytes: Uint8Array;
  readonly sliceFileOffset: number;
  readonly regionName: string | null;
  readonly executable: boolean;
  readonly minSize: number;
  readonly alignment: number;
  readonly fillByte?: number | undefined;
  readonly toVirtualAddress: (fileOffset: number) => string | null;
  readonly limit?: number | undefined;
}): {
  readonly caves: readonly CodeCaveSliceEntry[];
  readonly total: number;
} => {
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
  const limit =
    input.limit === undefined
      ? Number.POSITIVE_INFINITY
      : Math.max(0, Math.floor(input.limit));
  const caves: CodeCaveSliceEntry[] = [];
  let total = 0;
  const trimToLimit = (): void => {
    if (caves.length <= limit) return;
    caves.sort(compareCodeCaves);
    caves.length = limit;
  };

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
      total++;
      const address =
        toVirtualAddress(alignedStartFileOffset) ??
        `0x${alignedStartFileOffset.toString(16)}`;
      caves.push({
        address,
        file_offset: alignedStartFileOffset,
        byte_length: alignedLength,
        fill_byte: `0x${HEX_BYTE[b]!}`,
        region_name: regionName,
        executable,
      });
      if (caves.length > limit * 2) trimToLimit();
    }
    i = end;
  }

  trimToLimit();
  return { caves, total };
};

export const findCodeCavesInSlice = (
  input: Parameters<typeof findCodeCavesInSliceTopK>[0],
): readonly CodeCaveSliceEntry[] => findCodeCavesInSliceTopK(input).caves;
