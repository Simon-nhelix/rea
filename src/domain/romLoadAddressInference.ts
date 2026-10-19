import { z } from "zod";
import { readPointerNumber } from "./romPointerSegments.js";

export const inferredBaseCandidateSchema = z.strictObject({
  base_address: z.string(),
  table_count: z.number().int().min(1),
  table_entries: z.number().int().min(2),
  unique_targets: z.number().int().min(2),
  alignment: z.number().int().min(1),
  confidence: z.enum(["high", "medium", "low"]),
});

export type InferredBaseCandidate = {
  readonly base_address: string;
  readonly table_count: number;
  readonly table_entries: number;
  readonly unique_targets: number;
  readonly alignment: number;
  readonly confidence: "high" | "medium" | "low";
};

export const orphanStringEntrySchema = z.strictObject({
  after_entry_index: z.number().int().min(0),
  gap_index: z.number().int().min(0),
  address: z.string(),
  file_offset: z.number().int().min(0),
  byte_length: z.number().int().min(1),
  allocated_budget_bytes: z.number().int().min(1),
  text: z.string(),
  bytes_hex: z.string().optional(),
  lines: z.array(z.string()).optional(),
  character_length: z.number().int().min(0).optional(),
  longest_line_characters: z.number().int().min(0).optional(),
});

export type OrphanStringEntry = {
  readonly after_entry_index: number;
  readonly gap_index: number;
  readonly address: string;
  readonly file_offset: number;
  readonly byte_length: number;
  readonly allocated_budget_bytes: number;
  readonly text: string;
  readonly bytes_hex?: string;
  readonly lines?: string[];
  readonly character_length?: number;
  readonly longest_line_characters?: number;
};

const alignmentOf = (base: number): number => {
  if (base === 0) return 0x10000;
  const lowBit = base & -base;
  return lowBit > 0 ? lowBit : 1;
};

/**
 * Infer candidate RAM load base addresses for a headerless overlay or raw binary
 * by matching adjacent pointer slot differences against valid string-start deltas
 * and verifying candidate bases against full pointer-table runs.
 */
export const inferOverlayLoadAddress = (input: {
  readonly bytes: Uint8Array;
  readonly scanStartOffset: number;
  readonly scanEndOffset: number;
  readonly pointerSize: 2 | 3 | 4;
  readonly endian: "little" | "big";
  readonly stride: number;
  readonly minEntries: number;
  readonly sentenceStarts?: Uint8Array | undefined;
  readonly isValidStringStart: (fileOffset: number) => boolean;
}): InferredBaseCandidate[] => {
  const {
    bytes,
    scanStartOffset,
    scanEndOffset,
    pointerSize,
    endian,
    stride,
    minEntries,
    sentenceStarts,
    isValidStringStart,
  } = input;
  const fileLength = bytes.length;
  if (
    fileLength < 16 ||
    scanEndOffset - scanStartOffset < minEntries * stride
  ) {
    return [];
  }

  // 1. Collect valid string start offsets in [0, fileLength).
  const stringStarts: number[] = [];
  const validStartSet = new Set<number>();
  const MAX_STRING_STARTS = 8192;
  for (
    let off = 0;
    off < fileLength && stringStarts.length < MAX_STRING_STARTS;
    off++
  ) {
    if (sentenceStarts !== undefined && off > 0 && sentenceStarts[off] === 0) {
      continue;
    }
    if (isValidStringStart(off)) {
      stringStarts.push(off);
      validStartSet.add(off);
    }
  }
  if (stringStarts.length < 2) return [];

  // 2. Index string-start deltas (s_{k+d} - s_k for d in 1..4, delta <= 4096).
  const deltaToStarts = new Map<number, number[]>();
  for (let i = 0; i < stringStarts.length; i++) {
    const s0 = stringStarts[i]!;
    for (let d = 1; d <= 4 && i + d < stringStarts.length; d++) {
      const s1 = stringStarts[i + d]!;
      const delta = s1 - s0;
      if (delta <= 0 || delta > 4096) continue;
      let list = deltaToStarts.get(delta);
      if (list === undefined) {
        list = [];
        deltaToStarts.set(delta, list);
      }
      if (list.length < 32) list.push(s0);
    }
  }

  // 3. Scan adjacent pointer slots and accumulate votes for candidate bases B = P0 - s0.
  const baseVotes = new Map<number, number>();
  const step = pointerSize === 4 ? 2 : 1;
  const maxPointerVal = 256 ** pointerSize - 1;
  for (
    let off = scanStartOffset;
    off + stride + pointerSize <= scanEndOffset;
    off += step
  ) {
    const p0 = readPointerNumber(bytes, off, pointerSize, endian);
    if (p0 === 0 || p0 === maxPointerVal || p0 < fileLength) continue;
    const p1 = readPointerNumber(bytes, off + stride, pointerSize, endian);
    const delta = p1 - p0;
    if (delta <= 0 || delta > 4096) continue;
    const matchingStarts = deltaToStarts.get(delta);
    if (matchingStarts === undefined) continue;
    for (const s0 of matchingStarts) {
      const base = p0 - s0;
      if (base <= 0 || p1 - base >= fileLength) continue;
      // Require at least 2-byte alignment for 16/24/32-bit console load bases.
      if (base % 2 !== 0) continue;
      baseVotes.set(base, (baseVotes.get(base) ?? 0) + 1);
    }
  }

  if (baseVotes.size === 0) return [];

  // 4. Verify top voted bases by counting actual pointer runs of length >= minEntries.
  const topBases = [...baseVotes.entries()]
    .sort(
      (a, b) =>
        b[1] - a[1] || alignmentOf(b[0]) - alignmentOf(a[0]) || a[0] - b[0],
    )
    .slice(0, 16)
    .map(([base]) => base);

  const verified: InferredBaseCandidate[] = [];
  for (const base of topBases) {
    let tableCount = 0;
    let tableEntries = 0;
    const uniqueTargets = new Set<number>();
    let cursor = scanStartOffset;
    while (cursor + minEntries * stride <= scanEndOffset) {
      let runLen = 0;
      const runUnique = new Set<number>();
      let probe = cursor;
      while (probe + pointerSize <= scanEndOffset && runLen < 4096) {
        const raw = readPointerNumber(bytes, probe, pointerSize, endian);
        const targetOff = raw - base;
        if (
          targetOff < 0 ||
          targetOff >= fileLength ||
          !validStartSet.has(targetOff)
        ) {
          break;
        }
        runLen++;
        runUnique.add(targetOff);
        probe += stride;
      }
      if (runLen >= minEntries && runUnique.size >= 2) {
        tableCount++;
        tableEntries += runLen;
        for (const t of runUnique) uniqueTargets.add(t);
        cursor = probe;
      } else {
        cursor += step;
      }
    }
    if (tableCount > 0 && uniqueTargets.size >= 2) {
      const alignment = alignmentOf(base);
      const confidence: "high" | "medium" | "low" =
        (tableEntries >= 8 && uniqueTargets.size >= 4 && alignment >= 16) ||
        (tableCount >= 2 && uniqueTargets.size >= 4)
          ? "high"
          : tableEntries >= minEntries && uniqueTargets.size >= 2
            ? "medium"
            : "low";
      verified.push({
        base_address: `0x${base.toString(16)}`,
        table_count: tableCount,
        table_entries: tableEntries,
        unique_targets: uniqueTargets.size,
        alignment,
        confidence,
      });
    }
  }

  verified.sort(
    (a, b) =>
      b.table_entries - a.table_entries ||
      b.unique_targets - a.unique_targets ||
      b.alignment - a.alignment,
  );
  return verified.slice(0, 5);
};

/**
 * Scan gaps between consecutive pointer targets [target_end, next_target)
 * to discover unreferenced ("orphan") strings such as follow-up dialogue pages
 * or inline choice branches that lack their own pointer table slot.
 */
export const findOrphanStringsInPointerGaps = (input: {
  readonly bytes: Uint8Array;
  readonly entries: readonly {
    readonly index: number;
    readonly target_file_offset: number | null;
  }[];
  readonly unitSize: number;
  readonly isPaddingAt: (offset: number) => boolean;
  readonly decodeAt: (slice: Uint8Array) => {
    readonly text: string;
    readonly byteLength: number;
    readonly rawHex: string;
    readonly terminated: boolean;
    readonly lines?: readonly string[];
    readonly characterLength?: number;
    readonly longestLineCharacters?: number;
  } | null;
  readonly toVirtualAddress: (fileOffset: number) => string | null;
  readonly includeHex: boolean;
}): OrphanStringEntry[] => {
  const {
    bytes,
    entries,
    unitSize,
    isPaddingAt,
    decodeAt,
    toVirtualAddress,
    includeHex,
  } = input;

  // Map each unique target_file_offset to the first entry index that references it.
  const firstEntryByTarget = new Map<number, number>();
  for (const entry of entries) {
    const off = entry.target_file_offset;
    if (off !== null && off >= 0 && off < bytes.length) {
      if (!firstEntryByTarget.has(off)) {
        firstEntryByTarget.set(off, entry.index);
      }
    }
  }
  const sortedTargets = [...firstEntryByTarget.keys()].sort((a, b) => a - b);
  const orphans: OrphanStringEntry[] = [];

  for (let i = 0; i + 1 < sortedTargets.length; i++) {
    const currTarget = sortedTargets[i]!;
    const nextTarget = sortedTargets[i + 1]!;
    const delta = nextTarget - currTarget;
    if (delta <= 0 || delta > 4096) continue;

    const primarySlice = bytes.subarray(currTarget, nextTarget);
    const primary = decodeAt(primarySlice);
    if (primary === null || primary.byteLength <= 0) continue;

    let cursor = currTarget + primary.byteLength;
    const gapOrphans: {
      readonly fileOffset: number;
      readonly byteLength: number;
      readonly text: string;
      readonly rawHex: string;
      readonly lines?: readonly string[];
      readonly characterLength?: number;
      readonly longestLineCharacters?: number;
    }[] = [];

    while (cursor < nextTarget) {
      while (cursor + unitSize <= nextTarget && isPaddingAt(cursor)) {
        cursor += unitSize;
      }
      if (cursor >= nextTarget) break;
      const candidate = decodeAt(bytes.subarray(cursor, nextTarget));
      if (
        candidate === null ||
        candidate.byteLength <= 0 ||
        !candidate.terminated ||
        candidate.text.trim().length === 0
      ) {
        break;
      }
      gapOrphans.push({
        fileOffset: cursor,
        byteLength: candidate.byteLength,
        text: candidate.text,
        rawHex: candidate.rawHex,
        ...(candidate.lines === undefined ? {} : { lines: candidate.lines }),
        ...(candidate.characterLength === undefined
          ? {}
          : { characterLength: candidate.characterLength }),
        ...(candidate.longestLineCharacters === undefined
          ? {}
          : { longestLineCharacters: candidate.longestLineCharacters }),
      });
      cursor += candidate.byteLength;
    }

    const afterEntryIndex = firstEntryByTarget.get(currTarget)!;
    for (let g = 0; g < gapOrphans.length; g++) {
      const item = gapOrphans[g]!;
      const nextStop =
        g + 1 < gapOrphans.length ? gapOrphans[g + 1]!.fileOffset : nextTarget;
      const address =
        toVirtualAddress(item.fileOffset) ??
        `0x${item.fileOffset.toString(16)}`;
      orphans.push({
        after_entry_index: afterEntryIndex,
        gap_index: g,
        address,
        file_offset: item.fileOffset,
        byte_length: item.byteLength,
        allocated_budget_bytes: Math.max(
          item.byteLength,
          nextStop - item.fileOffset,
        ),
        text: item.text,
        ...(includeHex
          ? { bytes_hex: item.rawHex.replace(/\s+/gu, "").toLowerCase() }
          : {}),
        ...(item.lines === undefined ? {} : { lines: [...item.lines] }),
        ...(item.characterLength === undefined
          ? {}
          : { character_length: item.characterLength }),
        ...(item.longestLineCharacters === undefined
          ? {}
          : { longest_line_characters: item.longestLineCharacters }),
      });
    }
  }

  return orphans;
};
