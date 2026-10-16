import { z } from "zod";

/**
 * Overlay-relative pointer tables. Many disc games load a block of sectors
 * (an overlay) into one RAM window and store string pointers as offsets from
 * the block start, not as CPU addresses. A pointer table is then valid only
 * against the block it was loaded with, and the same block often sits on the
 * disc many times.
 */

/** A string-ending unit: one byte, or one 16-bit word. */
export type RomTerminatorUnit =
  | { readonly size: 1; readonly value: number }
  | {
      readonly size: 2;
      readonly value: number;
      readonly littleEndian: boolean;
    };

const unitAt = (
  bytes: Uint8Array,
  at: number,
  unit: RomTerminatorUnit,
): number => {
  if (unit.size === 1) return bytes[at] ?? -1;
  if (at + 1 >= bytes.length) return -1;
  const first = bytes[at] ?? 0;
  const second = bytes[at + 1] ?? 0;
  return unit.littleEndian ? first | (second << 8) : (first << 8) | second;
};

/** Pointer value of 2, 3, or 4 bytes as a number (exact for these widths). */
export const readPointerNumber = (
  bytes: Uint8Array,
  offset: number,
  width: 2 | 3 | 4,
  endianness: "little" | "big",
): number => {
  let value = 0;
  if (endianness === "little") {
    for (let i = width - 1; i >= 0; i--)
      value = value * 256 + (bytes[offset + i] ?? 0);
  } else {
    for (let i = 0; i < width; i++)
      value = value * 256 + (bytes[offset + i] ?? 0);
  }
  return value;
};

/** markSentenceStarts value: a string starts here. */
export const SENTENCE_START = 1;
/** markSentenceStarts value: an empty string (a lone terminator) starts here. */
export const EMPTY_SENTENCE_START = 2;

/**
 * Mark sentence starts: offsets whose previous unit is a terminator. A start
 * whose own unit is also a terminator is an empty string (tables point at
 * empty placeholder strings; padding looks the same, so callers decide).
 * Offsets of any parity are marked, since word strings may start at odd file
 * offsets.
 */
export const markSentenceStarts = (
  bytes: Uint8Array,
  unit: RomTerminatorUnit,
): Uint8Array => {
  const marks = new Uint8Array(bytes.length);
  const size = unit.size;
  for (let at = size; at + size <= bytes.length; at++) {
    if (unitAt(bytes, at - size, unit) === unit.value)
      marks[at] =
        unitAt(bytes, at, unit) === unit.value
          ? EMPTY_SENTENCE_START
          : SENTENCE_START;
  }
  return marks;
};

/** True when the unit at `at` is the terminator (an empty string starts there). */
export const isTerminatorAt = (
  bytes: Uint8Array,
  at: number,
  unit: RomTerminatorUnit,
): boolean => unitAt(bytes, at, unit) === unit.value;

/** End offset (just after the terminator) of the string at `at`, or null. */
export const terminatedStringEnd = (
  bytes: Uint8Array,
  at: number,
  unit: RomTerminatorUnit,
  limit = 4096,
): number | null => {
  const stop = Math.min(bytes.length, at + limit);
  for (let pos = at; pos + unit.size <= stop; pos += unit.size) {
    if (unitAt(bytes, pos, unit) === unit.value) return pos + unit.size;
  }
  return null;
};

const MAX_UNREFERENCED_SAMPLES = 16;
const MAX_COVERAGE_STRINGS = 100_000;

export const pointerTableCoverageSchema = z.strictObject({
  /** First byte of the string region: the lowest pointer target. */
  region_start: z.number().int().min(0),
  /** End of the region: the end (after its terminator) of the farthest target string. */
  region_end: z.number().int().min(0),
  /** The region starts right where the table ends. */
  adjacent_to_table: z.boolean(),
  /** Strings walked terminator to terminator through the region (pointed-at empty strings included). */
  strings: z.number().int().min(0),
  referenced_strings: z.number().int().min(0),
  unreferenced_strings: z.number().int().min(0),
  /**
   * referenced_strings / (strings + targets_inside_strings +
   * unreached_targets): the share of the string starts in the region (walked,
   * pointed at mid-string, or past a stopped walk) that the table points at
   * and the walk confirmed; 0 when none.
   */
  ratio: z.number().min(0).max(1),
  /** Every walked string is a target, no target is mid-string, and the walk ended exactly at region_end. */
  complete: z.boolean(),
  /** File offsets of the first strings no entry points to. */
  unreferenced_offsets: z.array(z.number().int().min(0)),
  /** Targets that fall inside a walked string (shared suffixes) rather than at its start. */
  targets_inside_strings: z.number().int().min(0),
  /** Bytes of terminator units between strings that no entry points at (padding). */
  padding_bytes: z.number().int().min(0),
  /** Offset where no terminator was found, or null when the walk finished. */
  walk_stopped_at: z.number().int().min(0).nullable(),
  /** Distinct targets at or after walk_stopped_at, which the walk could not confirm. */
  unreached_targets: z.number().int().min(0),
});

export type PointerTableCoverage = z.output<typeof pointerTableCoverageSchema>;

/**
 * Does a table cover its whole string region? The region runs from the lowest
 * target to the end of the farthest target string. The walk steps from string
 * to string by terminators and counts strings no entry points to. A table that
 * owns a region (all text of a block found only through the table) is
 * `complete`; a table that picks a few strings out of shared text is not.
 */
export const measurePointerTableCoverage = (input: {
  readonly bytes: Uint8Array;
  readonly unit: RomTerminatorUnit;
  /** Target file offsets of the table entries (duplicates allowed). */
  readonly targets: readonly number[];
  /** File offset just past the last table entry. */
  readonly tableEnd: number;
}): PointerTableCoverage | null => {
  const { bytes, unit } = input;
  const targets = [
    ...new Set(input.targets.filter((t) => t >= 0 && t < bytes.length)),
  ].sort((a, b) => a - b);
  const first = targets[0];
  if (first === undefined) return null;
  let regionEnd = first;
  for (const target of targets) {
    const end = terminatedStringEnd(bytes, target, unit);
    if (end !== null && end > regionEnd) regionEnd = end;
  }
  const targetSet = new Set(targets);
  const unreferencedOffsets: number[] = [];
  let strings = 0;
  let referenced = 0;
  let unreferenced = 0;
  let padding = 0;
  let walkStoppedAt: number | null = null;
  let insideStrings = 0;
  let pos = first;
  let nextTarget = 0;
  while (pos < regionEnd) {
    let spanEnd: number;
    if (unitAt(bytes, pos, unit) === unit.value) {
      // A lone terminator: an empty string when an entry points at it,
      // padding otherwise.
      spanEnd = pos + unit.size;
      if (targetSet.has(pos)) {
        strings++;
        referenced++;
      } else {
        padding += unit.size;
      }
    } else {
      const end = terminatedStringEnd(bytes, pos, unit);
      if (end === null || strings >= MAX_COVERAGE_STRINGS) {
        walkStoppedAt = pos;
        break;
      }
      spanEnd = end;
      strings++;
      if (targetSet.has(pos)) {
        referenced++;
      } else {
        unreferenced++;
        if (unreferencedOffsets.length < MAX_UNREFERENCED_SAMPLES)
          unreferencedOffsets.push(pos);
      }
    }
    while (nextTarget < targets.length && targets[nextTarget]! < spanEnd) {
      if (targets[nextTarget] !== pos) insideStrings++;
      nextTarget++;
    }
    pos = spanEnd;
  }
  const unreached = targets.length - nextTarget;
  const seen = strings + insideStrings + unreached;
  return {
    region_start: first,
    region_end: regionEnd,
    adjacent_to_table: first === input.tableEnd,
    strings,
    referenced_strings: referenced,
    unreferenced_strings: unreferenced,
    ratio: seen === 0 ? 0 : Math.round((referenced / seen) * 1e4) / 1e4,
    complete:
      walkStoppedAt === null &&
      pos === regionEnd &&
      unreferenced === 0 &&
      insideStrings === 0 &&
      strings > 0,
    unreferenced_offsets: unreferencedOffsets,
    targets_inside_strings: insideStrings,
    padding_bytes: padding,
    walk_stopped_at: walkStoppedAt,
    unreached_targets: unreached,
  };
};

/** How raw pointer values become file offsets. */
export type PointerBase =
  /** base_address + value, mapped through the target's address space. */
  | { readonly mode: "address" }
  /** segment start + value, for one explicit segment. */
  | {
      readonly mode: "segment";
      readonly start: number;
      readonly length: number;
    }
  /** segment start + value, trying every aligned segment start. */
  | {
      readonly mode: "segment";
      readonly align: number;
      readonly length: number;
    };

/** Parse a CLI segment "<start>:<length>" (decimal or 0x hex). */
export const parseSegmentSpec = (
  text: string,
): { readonly start: number; readonly length: number } | undefined => {
  const match = /^\s*(0x[0-9a-f]+|\d+)\s*:\s*(0x[0-9a-f]+|\d+)\s*$/iu.exec(
    text,
  );
  if (match === null) return undefined;
  const start = Number(match[1]);
  const length = Number(match[2]);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length))
    return undefined;
  if (length < 1) return undefined;
  return { start, length };
};
