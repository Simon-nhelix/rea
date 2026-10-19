import { z } from "zod";

import { err, ok, type Result } from "./result.js";

/**
 * In-string control codes. Console dialogue is rarely plain text: a line in
 * the ROM mixes glyph bytes with codes that break the line, pause, pick a
 * colour, or name a speaker, and many of those codes carry argument bytes.
 *
 * Those arguments are raw values, not glyphs. A decoder that does not know a
 * code's argument count reads them as text, and an argument that happens to
 * equal the terminator ends the string early, so both the manuscript text and
 * its byte budget come out wrong. Control codes are game-specific, so the
 * caller declares them; nothing here is inferred from the bytes.
 */

/** How a declared code affects the text around it. */
export const ROM_CONTROL_CODE_ROLES = [
  "plain",
  "line-break",
  "page-break",
  "end",
] as const;

export type RomControlCodeRole = (typeof ROM_CONTROL_CODE_ROLES)[number];

export const romControlCodeSchema = z.strictObject({
  hex: z
    .string()
    .min(2)
    .describe(
      "The code's own bytes as hex, e.g. 0A, FF, or FFFE for a 16-bit code. Longest declared match wins.",
    ),
  name: z
    .string()
    .min(1)
    .max(32)
    .describe(
      "Label used in decoded text as {NAME}, so a translator can keep the code in place.",
    ),
  argument_bytes: z
    .number()
    .int()
    .min(0)
    .max(16)
    .default(0)
    .describe(
      "Raw bytes that follow the code and are not glyphs. They are skipped, never decoded, so an argument equal to the terminator no longer ends the string.",
    ),
  role: z
    .enum(ROM_CONTROL_CODE_ROLES)
    .default("plain")
    .describe(
      "plain keeps the code inside the current line; line-break and page-break start a new line (page-break also a new page); end stops the string there.",
    ),
});

export type RomControlCodeInput = z.output<typeof romControlCodeSchema>;

/** A declaration list as a config file or CLI flag carries it. */
export const romControlCodeDeclarationsSchema = z
  .array(romControlCodeSchema)
  .max(256);

export const romControlCodeFields = {
  control_codes: z
    .array(romControlCodeSchema)
    .max(256)
    .optional()
    .describe(
      "Declared in-string control codes. Supplying them splits decoded text into lines, counts characters without codes, and skips argument bytes. Omitted means every byte is treated as glyph data.",
    ),
} as const;

/** A declared code with its bytes parsed once, at the owning boundary. */
export interface RomControlCode {
  readonly bytes: Uint8Array;
  readonly name: string;
  readonly argumentBytes: number;
  readonly role: RomControlCodeRole;
  /**
   * Declared codes are part of the string a translator reads and reinserts, so
   * they appear as {NAME} and in the reported occurrences. The terminator is
   * not part of the string, only its end, so it stays out of both.
   */
  readonly reported: boolean;
}

/** Declared codes indexed for longest-match lookup by their first byte. */
export interface RomControlCodeTable {
  readonly codes: ReadonlyArray<RomControlCode>;
  readonly byFirstByte: ReadonlyMap<number, ReadonlyArray<RomControlCode>>;
  readonly maxByteLength: number;
}

const parseHexBytes = (hex: string): Result<Uint8Array, string> => {
  const compact = hex.replaceAll(/[\s_]/gu, "");
  if (compact.length === 0) return err("control code hex is empty");
  if (compact.length % 2 !== 0)
    return err(`control code hex ${hex} needs whole bytes`);
  if (!/^[0-9a-fA-F]+$/u.test(compact))
    return err(`control code hex ${hex} is not hexadecimal`);
  const bytes = new Uint8Array(compact.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = Number.parseInt(compact.slice(i * 2, i * 2 + 2), 16);
  return ok(bytes);
};

/**
 * Validate declared codes and index them. Two codes with the same bytes are
 * rejected rather than silently shadowed, because which one applied would
 * change both the decoded text and the byte count.
 */
export const parseRomControlCodes = (
  declared: ReadonlyArray<RomControlCodeInput>,
): Result<RomControlCodeTable, string> => {
  const codes: RomControlCode[] = [];
  const seen = new Map<string, string>();
  for (const entry of declared) {
    const parsed = parseHexBytes(entry.hex);
    if (!parsed.ok) return parsed;
    const key = Array.from(parsed.value, (b) => b.toString(16).padStart(2, "0"))
      .join("")
      .toLowerCase();
    const prior = seen.get(key);
    if (prior !== undefined)
      return err(
        `control codes ${prior} and ${entry.name} declare the same bytes ${entry.hex}`,
      );
    seen.set(key, entry.name);
    codes.push({
      bytes: parsed.value,
      name: entry.name,
      argumentBytes: entry.argument_bytes,
      role: entry.role,
      reported: true,
    });
  }
  const byFirstByte = new Map<number, RomControlCode[]>();
  let maxByteLength = 0;
  for (const code of codes) {
    const first = code.bytes[0];
    if (first === undefined) continue;
    const bucket = byFirstByte.get(first);
    if (bucket === undefined) byFirstByte.set(first, [code]);
    else bucket.push(code);
    maxByteLength = Math.max(maxByteLength, code.bytes.length);
  }
  // Longest declared match wins, so FFFE is found before a shorter FF.
  for (const bucket of byFirstByte.values())
    bucket.sort((a, b) => b.bytes.length - a.bytes.length);
  return ok({ codes, byFirstByte, maxByteLength });
};

export const matchRomControlCodeAt = (
  bytes: Uint8Array,
  at: number,
  table: RomControlCodeTable,
): RomControlCode | undefined => {
  const first = bytes[at];
  if (first === undefined) return undefined;
  const bucket = table.byFirstByte.get(first);
  if (bucket === undefined) return undefined;
  for (const code of bucket) {
    if (at + code.bytes.length > bytes.length) continue;
    let same = true;
    for (let i = 1; i < code.bytes.length; i++) {
      if (bytes[at + i] !== code.bytes[i]) {
        same = false;
        break;
      }
    }
    if (same) return code;
  }
  return undefined;
};

/** One stretch of glyph bytes, or one declared code with its raw arguments. */
export type RomTextSegment =
  | { readonly kind: "text"; readonly offset: number; readonly length: number }
  | {
      readonly kind: "code";
      readonly offset: number;
      readonly length: number;
      readonly code: RomControlCode;
      readonly argumentsHex: string;
      readonly argumentsTruncated: boolean;
    };

/** Why segmentation stopped, which decides whether a budget is trustworthy. */
export type RomTextStop = "end-code" | "buffer-end";

export interface RomTextSegments {
  readonly segments: ReadonlyArray<RomTextSegment>;
  /** Bytes consumed, including the ending code and every argument byte. */
  readonly byteLength: number;
  readonly stop: RomTextStop;
}

/**
 * Split a buffer into glyph runs and declared codes. Nothing is decoded here;
 * the caller's own text decoder owns that, and this owns code boundaries.
 */
export const segmentRomTextByControlCodes = (
  bytes: Uint8Array,
  table: RomControlCodeTable,
  stepBytes = 1,
): RomTextSegments => {
  const segments: RomTextSegment[] = [];
  let textStart = 0;
  let pos = 0;
  const flushText = (until: number): void => {
    if (until > textStart)
      segments.push({
        kind: "text",
        offset: textStart,
        length: until - textStart,
      });
  };
  while (pos < bytes.length) {
    const code = matchRomControlCodeAt(bytes, pos, table);
    if (code === undefined) {
      pos += stepBytes;
      continue;
    }
    flushText(pos);
    const argumentStart = pos + code.bytes.length;
    const available = Math.max(0, bytes.length - argumentStart);
    const argumentLength = Math.min(code.argumentBytes, available);
    const argumentBytes = bytes.subarray(
      argumentStart,
      argumentStart + argumentLength,
    );
    segments.push({
      kind: "code",
      offset: pos,
      length: code.bytes.length + argumentLength,
      code,
      argumentsHex: Array.from(argumentBytes, (b) =>
        b.toString(16).padStart(2, "0"),
      ).join(""),
      argumentsTruncated: argumentLength < code.argumentBytes,
    });
    pos = argumentStart + argumentLength;
    textStart = pos;
    if (code.role === "end")
      return { segments, byteLength: pos, stop: "end-code" };
  }
  flushText(bytes.length);
  return { segments, byteLength: bytes.length, stop: "buffer-end" };
};

/** Serialized occurrence contract shared by search, pointer and orphan results. */
export const romControlCodeUseSchema = z.strictObject({
  name: z.string(),
  offset: z.number().int().min(0),
  byte_length: z.number().int().min(0),
  arguments_hex: z.string(),
  arguments_truncated: z.boolean().optional(),
});

/** One code occurrence, reported so a reinsertion keeps it byte-for-byte. */
export interface RomControlCodeUse {
  readonly name: string;
  readonly offset: number;
  readonly byte_length: number;
  readonly arguments_hex: string;
  readonly arguments_truncated?: boolean;
}

export interface RomTextWithControlCodes {
  /** Full text with each code written as {NAME}, in ROM order. */
  readonly text: string;
  /** Text per line, split at line-break and page-break codes. */
  readonly lines: ReadonlyArray<string>;
  /** Pages, each a run of lines, split at page-break codes. */
  readonly pages: ReadonlyArray<ReadonlyArray<string>>;
  /** Decoded characters, counting no code and no argument byte. */
  readonly character_length: number;
  /** Characters on the longest line, for a width budget. */
  readonly longest_line_characters: number;
  readonly byte_length: number;
  readonly control_codes: ReadonlyArray<RomControlCodeUse>;
  readonly stop: RomTextStop;
}

/**
 * Decode one string that mixes glyphs and declared codes. `decodeText` is the
 * caller's encoding-specific decoder for a run of glyph bytes; this function
 * owns only where those runs begin and end.
 */
export const decodeRomTextWithControlCodes = (
  bytes: Uint8Array,
  table: RomControlCodeTable,
  decodeText: (run: Uint8Array) => string,
  stepBytes = 1,
): RomTextWithControlCodes => {
  const { segments, byteLength, stop } = segmentRomTextByControlCodes(
    bytes,
    table,
    stepBytes,
  );
  const parts: string[] = [];
  const uses: RomControlCodeUse[] = [];
  const pages: string[][] = [[]];
  let line = "";
  let characters = 0;
  let longest = 0;
  let lineCharacters = 0;
  const endLine = (startPage: boolean): void => {
    const current = pages.at(-1);
    current?.push(line);
    longest = Math.max(longest, lineCharacters);
    line = "";
    lineCharacters = 0;
    if (startPage) pages.push([]);
  };
  for (const segment of segments) {
    if (segment.kind === "text") {
      const decoded = decodeText(
        bytes.subarray(segment.offset, segment.offset + segment.length),
      );
      parts.push(decoded);
      line += decoded;
      const count = [...decoded].length;
      characters += count;
      lineCharacters += count;
      continue;
    }
    const label = `{${segment.code.name}}`;
    if (segment.code.reported) {
      parts.push(label);
      uses.push({
        name: segment.code.name,
        offset: segment.offset,
        byte_length: segment.length,
        arguments_hex: segment.argumentsHex,
        ...(segment.argumentsTruncated ? { arguments_truncated: true } : {}),
      });
    }
    if (segment.code.role === "line-break") {
      if (!segment.code.reported) parts.push("\n");
      endLine(false);
    } else if (segment.code.role === "page-break") endLine(true);
    else if (segment.code.reported) line += label;
  }
  endLine(false);
  // A trailing break leaves an empty final page; an empty string keeps one
  // empty line so line counts stay comparable across records.
  const filledPages = pages.filter(
    (page, index) => page.length > 0 || index === 0,
  );
  return {
    text: parts.join(""),
    lines: filledPages.flat(),
    pages: filledPages,
    character_length: characters,
    longest_line_characters: longest,
    byte_length: byteLength,
    control_codes: uses,
    stop,
  };
};

/**
 * Treat the string terminator as an end code, so one pass over the bytes finds
 * both the codes and the string end. A declared code with the same bytes wins,
 * because the caller's declaration states what that byte means in this game.
 */
export const withTerminatorAsEndCode = (
  table: RomControlCodeTable,
  terminatorByte: number | null,
  name = "terminator",
): RomControlCodeTable => {
  if (terminatorByte === null) return table;
  const existing = table.byFirstByte.get(terminatorByte);
  if (existing?.some((code) => code.bytes.length === 1) === true) return table;
  const terminator: RomControlCode = {
    bytes: Uint8Array.of(terminatorByte),
    name,
    argumentBytes: 0,
    role: "end",
    reported: false,
  };
  const byFirstByte = new Map<number, ReadonlyArray<RomControlCode>>(
    table.byFirstByte,
  );
  // Longer declared codes starting with this byte keep their precedence.
  byFirstByte.set(terminatorByte, [...(existing ?? []), terminator]);
  return {
    codes: [...table.codes, terminator],
    byFirstByte,
    maxByteLength: Math.max(table.maxByteLength, 1),
  };
};

/**
 * Treat a 16-bit terminator_word as an unreported end code when scanning
 * 16-bit word encodings (sjis-le16, tile-le16, tile-be16).
 */
const withWordCode = (
  table: RomControlCodeTable,
  word: number | null,
  littleEndian: boolean,
  name: string,
  role: RomControlCodeRole,
): RomControlCodeTable => {
  if (word === null) return table;
  const b0 = littleEndian ? word & 0xff : (word >>> 8) & 0xff;
  const b1 = littleEndian ? (word >>> 8) & 0xff : word & 0xff;
  const existing = table.byFirstByte.get(b0);
  if (
    existing?.some(
      (code) =>
        code.bytes.length === 2 && code.bytes[0] === b0 && code.bytes[1] === b1,
    ) === true
  )
    return table;
  const terminator: RomControlCode = {
    bytes: Uint8Array.of(b0, b1),
    name,
    argumentBytes: 0,
    role,
    reported: false,
  };
  const byFirstByte = new Map<number, ReadonlyArray<RomControlCode>>(
    table.byFirstByte,
  );
  const bucket = [...(existing ?? []), terminator].sort(
    (a, b) => b.bytes.length - a.bytes.length,
  );
  byFirstByte.set(b0, bucket);
  return {
    codes: [...table.codes, terminator],
    byFirstByte,
    maxByteLength: Math.max(table.maxByteLength, 2),
  };
};

/** Word terminators and newlines share the same token boundaries as declared codes. */
export const withWordFormatControlCodes = (
  table: RomControlCodeTable,
  format: {
    readonly terminatorWord: number | null;
    readonly newlineWord: number | null;
    readonly littleEndian: boolean;
  },
): RomControlCodeTable =>
  withWordCode(
    withWordCode(
      table,
      format.terminatorWord,
      format.littleEndian,
      "terminator",
      "end",
    ),
    format.newlineWord,
    format.littleEndian,
    "newline",
    "line-break",
  );
