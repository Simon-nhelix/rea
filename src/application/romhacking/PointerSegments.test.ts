import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { JsonValue } from "../../domain/jsonValue.js";
import { runLocalRomTool } from "./LocalRomCommands.js";
import type { LocalRomToolName } from "./LocalRomToolNames.js";

/** sjis-le16 words: どう = 82C7 82A4 stored as C7 82 A4 82. */
const le16 = (...words: number[]): number[] =>
  words.flatMap((word) => [word & 0xff, word >>> 8]);

const SECTOR = 0x800;

/**
 * One overlay block, pointers relative to its start:
 *   +0x00 header [2000 0010 000C 000C 000C 002E]
 *   +0x0C table  [0016 001C 0026 0028 0016]
 *   +0x16 どう FFFF, +0x1C かな FFFE よ FFFF, +0x26 FFFF (empty), +0x28 はい FFFF
 * The first entry points right past the table (no terminator before it).
 */
const overlay = (): number[] => [
  ...le16(0x2000, 0x0010, 0x000c, 0x000c, 0x000c, 0x002e),
  ...le16(0x0016, 0x001c, 0x0026, 0x0028, 0x0016),
  ...le16(0x82c7, 0x82a4, 0xffff),
  ...le16(0x82a9, 0x82c8, 0xfffe, 0x82e6, 0xffff),
  ...le16(0xffff),
  ...le16(0x82cd, 0x82a2, 0xffff),
];

/**
 * Sector 1 and 5: the overlay. Sector 3: 1024 identical words 0028, which
 * point at はい of sector 1 (a sentence start) and must not form a table.
 */
const disc = (): Uint8Array => {
  const bytes = new Uint8Array(SECTOR * 7);
  bytes.set(overlay(), SECTOR);
  bytes.set(overlay(), SECTOR * 5);
  bytes.set(le16(...Array<number>(SECTOR / 2).fill(0x0028)), SECTOR * 3);
  return bytes;
};

/**
 * A table whose fourth entry points inside かな…, and one that skips a
 * string of its region:
 *   0x00 table A [0010 0016 0020 0018 0010]   (0x18 = な, mid-string)
 *   0x0A 0000 0000 FFFF
 *   0x10 どう FFFF, 0x16 かな FFFE よ FFFF, 0x20 はい FFFF
 *   0x40 table B [0046 0052 0058]             (skips かな at 0x4C)
 *   0x46 どう FFFF, 0x4C かな FFFF, 0x52 はい FFFF, 0x58 よ FFFF
 */
const mixed = (): Uint8Array => {
  const bytes = new Uint8Array(SECTOR);
  bytes.set(
    [
      ...le16(0x0010, 0x0016, 0x0020, 0x0018, 0x0010),
      ...le16(0x0000, 0x0000, 0xffff),
      ...le16(0x82c7, 0x82a4, 0xffff),
      ...le16(0x82a9, 0x82c8, 0xfffe, 0x82e6, 0xffff),
      ...le16(0x82cd, 0x82a2, 0xffff),
    ],
    0,
  );
  bytes.set(
    [
      ...le16(0x0046, 0x0052, 0x0058),
      ...le16(0x82c7, 0x82a4, 0xffff),
      ...le16(0x82a9, 0x82c8, 0xffff),
      ...le16(0x82cd, 0x82a2, 0xffff),
      ...le16(0x82e6, 0xffff),
    ],
    0x40,
  );
  return bytes;
};

let root: string;
const signal = new AbortController().signal;
const WORDS = {
  encoding: "sjis-le16",
  terminator_word: 0xffff,
  newline_word: 0xfffe,
  min_string_length: 1,
  min_entries: 3,
};

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "rea-pointer-segments-"));
  await writeFile(join(root, "disc.iso"), disc());
  await writeFile(join(root, "mixed.bin"), mixed());
});
afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

const run = async (
  file: string,
  tool: LocalRomToolName,
  arguments_: Readonly<Record<string, JsonValue>>,
) => {
  const result = await runLocalRomTool({
    path: join(root, file),
    tool,
    arguments: arguments_,
    signal,
    localBytes: true,
  });
  if (result === undefined) throw new Error("local run expected");
  return result;
};

type Table = {
  table_file_offset: number;
  entry_count: number;
  segment_start?: number;
  samples: { target_file_offset: number; preview_text: string }[];
  coverage: {
    region_start: number;
    region_end: number;
    adjacent_to_table: boolean;
    strings: number;
    referenced_strings: number;
    ratio: number;
    complete: boolean;
    unreferenced_offsets: number[];
  } | null;
};

const tables = async (
  file: string,
  arguments_: Readonly<Record<string, JsonValue>>,
): Promise<Table[]> => {
  const result = await run(file, "discover_pointer_tables", arguments_);
  if (!result.ok) throw new Error(result.error.message);
  return (result.value.result as { tables: Table[] }).tables;
};

describe("discover_pointer_tables with segment-relative pointers", () => {
  it("reads values as offsets from one explicit segment", async () => {
    const found = await tables("disc.iso", {
      ...WORDS,
      pointer_size: 2,
      segment_start: SECTOR,
      segment_length: SECTOR,
      target_after_terminator: true,
      sample_entries: 5,
    });
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({
      table_file_offset: SECTOR + 0x0c,
      entry_count: 5,
      segment_start: SECTOR,
      samples: [
        { target_file_offset: SECTOR + 0x16, preview_text: "どう" },
        { target_file_offset: SECTOR + 0x1c, preview_text: "かな\nよ" },
        { target_file_offset: SECTOR + 0x26, preview_text: "" },
        { target_file_offset: SECTOR + 0x28, preview_text: "はい" },
        { target_file_offset: SECTOR + 0x16 },
      ],
      coverage: {
        region_start: SECTOR + 0x16,
        region_end: SECTOR + 0x2e,
        adjacent_to_table: true,
        strings: 4,
        referenced_strings: 4,
        ratio: 1,
        complete: true,
      },
    });
  });

  it("tries every aligned segment start and keeps each copy's own start", async () => {
    const result = await run("disc.iso", "discover_pointer_tables", {
      ...WORDS,
      pointer_size: 2,
      segment_align: SECTOR,
      segment_length: SECTOR * 4,
      target_after_terminator: true,
      min_coverage: 1,
      start_offset: 0,
      end_offset: SECTOR * 7,
    });
    if (!result.ok) throw new Error(result.error.message);
    expect(result.value.result).toMatchObject({
      base_mode: "segment",
      segment_align: SECTOR,
      segment_length: SECTOR * 4,
      target_after_terminator: true,
      min_coverage: 1,
      total_tables: 2,
      truncated: false,
      tables: [
        { table_file_offset: SECTOR + 0x0c, segment_start: SECTOR },
        { table_file_offset: SECTOR * 5 + 0x0c, segment_start: SECTOR * 5 },
      ],
    });
  });

  it("pages with next_start_offset when max_tables is reached", async () => {
    const result = await run("disc.iso", "discover_pointer_tables", {
      ...WORDS,
      pointer_size: 2,
      segment_align: SECTOR,
      segment_length: SECTOR * 4,
      target_after_terminator: true,
      start_offset: 0,
      end_offset: SECTOR * 7,
      max_tables: 1,
    });
    if (!result.ok) throw new Error(result.error.message);
    expect(result.value.result).toMatchObject({
      total_tables: 1,
      truncated: true,
      next_start_offset: SECTOR + 0x16,
    });
    const rest = await tables("disc.iso", {
      ...WORDS,
      pointer_size: 2,
      segment_align: SECTOR,
      segment_length: SECTOR * 4,
      target_after_terminator: true,
      start_offset: SECTOR + 0x16,
      end_offset: SECTOR * 7,
    });
    expect(rest.map((table) => table.table_file_offset)).toEqual([
      SECTOR * 5 + 0x0c,
    ]);
  });

  it("stops a table at a mid-string target only with target_after_terminator", async () => {
    const base = { ...WORDS, pointer_size: 2, start_offset: 0, length: 0x40 };
    const loose = await tables("mixed.bin", base);
    expect(loose[0]).toMatchObject({ table_file_offset: 0, entry_count: 5 });
    const strict = await tables("mixed.bin", {
      ...base,
      target_after_terminator: true,
    });
    expect(strict[0]).toMatchObject({
      table_file_offset: 0,
      entry_count: 3,
      coverage: { complete: true, adjacent_to_table: false },
    });
  });

  it("reports and filters tables that skip strings of their region", async () => {
    const base = {
      ...WORDS,
      pointer_size: 2,
      start_offset: 0x40,
      length: 0x40,
      target_after_terminator: true,
    };
    const kept = await tables("mixed.bin", base);
    expect(kept[0]).toMatchObject({
      table_file_offset: 0x40,
      entry_count: 3,
      coverage: {
        adjacent_to_table: true,
        strings: 4,
        referenced_strings: 3,
        ratio: 0.75,
        complete: false,
        unreferenced_offsets: [0x4c],
      },
    });
    expect(await tables("mixed.bin", { ...base, min_coverage: 1 })).toEqual([]);
  });
});

describe("discover_pointer_tables segment options", () => {
  it("rejects inconsistent segment options", async () => {
    const cases: [Record<string, JsonValue>, RegExp][] = [
      [{ base_mode: "segment", segment_start: 0 }, /segment_length/u],
      [
        { base_mode: "address", segment_start: 0, segment_length: 16 },
        /only to base_mode segment/u,
      ],
      [
        { segment_start: 0, segment_length: 16, base_address: "0x8000" },
        /base_address applies only/u,
      ],
      [
        { segment_start: 0, segment_align: 16, segment_length: 16 },
        /not both/u,
      ],
      [{ base_mode: "segment", segment_length: 16 }, /segment_start/u],
      [
        { target_after_terminator: true, terminator_word: null },
        /needs a terminator/u,
      ],
      [{ min_coverage: 1, terminator_word: null }, /min_coverage needs/u],
    ];
    for (const [extra, message] of cases) {
      const result = await run("mixed.bin", "discover_pointer_tables", {
        ...WORDS,
        pointer_size: 2,
        ...extra,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.userMessage).toMatch(message);
    }
  });
});

describe("scan_pointer_table with segment-relative pointers", () => {
  it("resolves entries against the segment and reports coverage", async () => {
    const result = await run("disc.iso", "scan_pointer_table", {
      encoding: "sjis-le16",
      terminator_word: 0xffff,
      newline_word: 0xfffe,
      pointer_size: 2,
      table_offset: SECTOR * 5 + 0x0c,
      count: 6,
      segment_start: SECTOR * 5,
      segment_length: SECTOR,
    });
    if (!result.ok) throw new Error(result.error.message);
    const data = result.value.result as {
      base_mode: string;
      segment_start: number;
      entries: {
        target_file_offset: number | null;
        preview_text: string | null;
      }[];
      coverage: { complete: boolean; strings: number; ratio: number };
    };
    expect(data.base_mode).toBe("segment");
    expect(data.segment_start).toBe(SECTOR * 5);
    expect(data.entries.map((entry) => entry.target_file_offset)).toEqual([
      SECTOR * 5 + 0x16,
      SECTOR * 5 + 0x1c,
      SECTOR * 5 + 0x26,
      SECTOR * 5 + 0x28,
      SECTOR * 5 + 0x16,
      // どう (82C7) as a value is past the 0x800-byte segment.
      null,
    ]);
    expect(data.entries[1]?.preview_text).toBe("かな\nよ");
    expect(data.coverage).toMatchObject({ strings: 4, ratio: 1 });
  });
});
