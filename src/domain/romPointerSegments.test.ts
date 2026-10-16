import { describe, expect, it } from "vitest";
import {
  EMPTY_SENTENCE_START,
  markSentenceStarts,
  measurePointerTableCoverage,
  parseSegmentSpec,
  readPointerNumber,
  SENTENCE_START,
  terminatedStringEnd,
  type RomTerminatorUnit,
} from "./romPointerSegments.js";

const WORD: RomTerminatorUnit = { size: 2, value: 0xffff, littleEndian: true };
const BYTE: RomTerminatorUnit = { size: 1, value: 0x00 };

/** Little-endian 16-bit words. */
const le16 = (...words: number[]): Uint8Array =>
  Uint8Array.from(words.flatMap((word) => [word & 0xff, word >>> 8]));

describe("overlay pointer helpers", () => {
  it("reads 2/3/4-byte pointers in both byte orders", () => {
    const bytes = Uint8Array.from([0x12, 0x34, 0x56, 0x78]);
    expect(readPointerNumber(bytes, 0, 2, "little")).toBe(0x3412);
    expect(readPointerNumber(bytes, 0, 2, "big")).toBe(0x1234);
    expect(readPointerNumber(bytes, 1, 3, "little")).toBe(0x785634);
    expect(readPointerNumber(bytes, 0, 4, "big")).toBe(0x12345678);
  });

  it("marks starts after a terminator, at any parity, and empty strings", () => {
    // [FFFF][どう FFFF][FFFF][x] then an odd-offset start after FFFF.
    const bytes = Uint8Array.from([
      ...le16(0xffff, 0x82c7, 0x82a4, 0xffff, 0xffff, 0x82cd),
      0x00,
      ...le16(0xffff, 0x82a2),
    ]);
    const marks = markSentenceStarts(bytes, WORD);
    expect(marks[2]).toBe(SENTENCE_START);
    expect(marks[8]).toBe(EMPTY_SENTENCE_START);
    expect(marks[10]).toBe(SENTENCE_START);
    expect(marks[15]).toBe(SENTENCE_START);
    expect(marks[4]).toBe(0);
    const text = Uint8Array.from([0x41, 0x00, 0x42, 0x00, 0x00, 0x43]);
    expect([...markSentenceStarts(text, BYTE)]).toEqual([0, 0, 1, 0, 2, 1]);
  });

  it("finds the end of a terminated string within a limit", () => {
    const bytes = le16(0x82c7, 0xfffe, 0x82a4, 0xffff, 0x82cd);
    expect(terminatedStringEnd(bytes, 0, WORD)).toBe(8);
    expect(terminatedStringEnd(bytes, 8, WORD)).toBeNull();
    expect(terminatedStringEnd(bytes, 0, WORD, 4)).toBeNull();
  });

  it("parses <start>:<length> segments", () => {
    expect(parseSegmentSpec("0x19800:0xD800")).toEqual({
      start: 0x19800,
      length: 0xd800,
    });
    expect(parseSegmentSpec(" 2048 : 65536 ")).toEqual({
      start: 2048,
      length: 65536,
    });
    expect(parseSegmentSpec("0x10:0")).toBeUndefined();
    expect(parseSegmentSpec("0x10")).toBeUndefined();
    expect(parseSegmentSpec("-1:2")).toBeUndefined();
  });
});

describe("pointer table coverage", () => {
  // Table (2 entries) at 0, then strings: A @4, B @10, empty @16, C @18.
  const region = Uint8Array.from([
    ...le16(0x0004, 0x000a),
    ...le16(0x82c7, 0x82a4, 0xffff),
    ...le16(0x82a9, 0x82c8, 0xffff),
    ...le16(0xffff),
    ...le16(0x82cd, 0xffff),
  ]);

  it("reports a table that owns its whole region", () => {
    expect(
      measurePointerTableCoverage({
        bytes: region,
        unit: WORD,
        targets: [4, 10, 16, 18, 4],
        tableEnd: 4,
      }),
    ).toMatchObject({
      region_start: 4,
      region_end: 22,
      adjacent_to_table: true,
      strings: 4,
      referenced_strings: 4,
      ratio: 1,
      complete: true,
      padding_bytes: 0,
      unreached_targets: 0,
    });
  });

  it("lists strings the table skips and counts unreferenced padding", () => {
    expect(
      measurePointerTableCoverage({
        bytes: region,
        unit: WORD,
        targets: [4, 18],
        tableEnd: 4,
      }),
    ).toMatchObject({
      strings: 3,
      referenced_strings: 2,
      unreferenced_strings: 1,
      unreferenced_offsets: [10],
      padding_bytes: 2,
      ratio: 0.6667,
      complete: false,
    });
  });

  it("penalizes mid-string targets and targets past a stopped walk", () => {
    expect(
      measurePointerTableCoverage({
        bytes: region,
        unit: WORD,
        targets: [4, 6],
        tableEnd: 0,
      }),
    ).toMatchObject({
      adjacent_to_table: false,
      strings: 1,
      targets_inside_strings: 1,
      ratio: 0.5,
      complete: false,
    });
    // A target whose string never ends is not confirmed.
    const open = Uint8Array.from([...region, ...le16(0x82a2, 0x82a2)]);
    expect(
      measurePointerTableCoverage({
        bytes: open,
        unit: WORD,
        targets: [18, 22],
        tableEnd: 0,
      }),
    ).toMatchObject({
      region_end: 22,
      strings: 1,
      walk_stopped_at: null,
      unreached_targets: 1,
      ratio: 0.5,
    });
    // No terminator within 4096 bytes after A: the walk stops before C.
    const junk = Uint8Array.from([
      ...le16(0x0000, 0x0000),
      ...le16(0x82c7, 0x82a4, 0xffff),
      ...le16(...Array<number>(2100).fill(0x82a2), 0xffff),
      ...le16(0x82cd, 0xffff),
    ]);
    expect(
      measurePointerTableCoverage({
        bytes: junk,
        unit: WORD,
        targets: [4, 4212],
        tableEnd: 4,
      }),
    ).toMatchObject({
      region_end: 4216,
      strings: 1,
      referenced_strings: 1,
      walk_stopped_at: 10,
      unreached_targets: 1,
      ratio: 0.5,
      complete: false,
    });
  });

  it("returns null without targets inside the bytes", () => {
    expect(
      measurePointerTableCoverage({
        bytes: region,
        unit: WORD,
        targets: [999],
        tableEnd: 0,
      }),
    ).toBeNull();
  });
});
