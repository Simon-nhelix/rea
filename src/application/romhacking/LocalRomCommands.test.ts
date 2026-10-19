import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runLocalRomTool } from "./LocalRomCommands.js";
import { inspectDiscImage } from "./LocalByteSource.js";

/** sjis-le16 words, e.g. どう = 82C7 82A4 stored as C7 82 A4 82. */
const le16 = (...words: number[]): number[] =>
  words.flatMap((word) => [word & 0xff, word >>> 8]);
const DOU = le16(0x82c7, 0x82a4, 0xffff);
const KANA = le16(0x82a9, 0x82c8, 0xfffe, 0x82e6, 0xffff);

const RAW = 2352;
const USER = 2048;

const ascii = (bytes: Uint8Array, text: string, at: number): void =>
  bytes.set(new TextEncoder().encode(text), at);

/** Two data sectors: 0 = text, 1 = PC Engine IPL record. */
const userSectors = (): Uint8Array => {
  const data = new Uint8Array(USER * 3);
  data.set(DOU, 0x10);
  data.set(DOU, USER + 0x400);
  data.set(KANA, USER * 2 + 0x21);
  const ipl = data.subarray(USER, USER * 2);
  ipl.set([0x00, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30], 0);
  ascii(ipl, "PC Engine CD-ROM SYSTEM", 0x20);
  ascii(ipl, "TEST GAME", 0x6a);
  return data;
};

const modeOneTrack = (pregap: number, user: Uint8Array): Uint8Array => {
  const sectors = user.length / USER;
  const track = new Uint8Array((pregap + sectors) * RAW);
  for (let i = 0; i < sectors; i++) {
    const base = (pregap + i) * RAW;
    track.set([0x00, ...Array<number>(10).fill(0xff), 0x00], base);
    track[base + 15] = 1;
    track.set(user.subarray(i * USER, (i + 1) * USER), base + 16);
  }
  return track;
};

let root: string;
const signal = new AbortController().signal;
const searchArguments = {
  encoding: "sjis-le16",
  terminator_word: 0xffff,
  newline_word: 0xfffe,
  min_length: 1,
  start_offset: 0,
  length: USER * 3,
  require_terminator: true,
};

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "rea-local-rom-"));
  const user = userSectors();
  await writeFile(join(root, "game.iso"), user);
  // Not a recognized executable or ROM header.
  await writeFile(
    join(root, "blob.dat"),
    Uint8Array.from([0x13, 0x37, ...DOU, 0x00, ...KANA]),
  );
  await writeFile(join(root, "game (Track 01).bin"), new Uint8Array(10 * RAW));
  await writeFile(join(root, "game (Track 02).bin"), modeOneTrack(2, user));
  await writeFile(
    join(root, "game.cue"),
    [
      'FILE "game (Track 01).bin" BINARY',
      "  TRACK 01 AUDIO",
      "    INDEX 01 00:00:00",
      'FILE "game (Track 02).bin" BINARY',
      "  TRACK 02 MODE1/2352",
      "    INDEX 00 00:00:00",
      "    INDEX 01 00:00:02",
    ].join("\n"),
  );
});
afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("mapped raw and disc reads", () => {
  it("reads GDI data after its declared file offset", async () => {
    const track = join(root, "offset-track.bin");
    const user = new Uint8Array(USER * 2);
    user.set(DOU, USER + 0x10);
    await writeFile(track, modeOneTrack(0, user));
    const descriptor = join(root, "offset.gdi");
    await writeFile(descriptor, `1\n3 45000 4 2352 offset-track.bin 2352\n`);
    const result = await runLocalRomTool({
      path: descriptor,
      tool: "search_rom_strings",
      arguments: { ...searchArguments, length: USER },
      signal,
      localBytes: true,
    });
    expect(result?.ok).toBe(true);
    if (!result?.ok) return;
    expect(result.value.result).toMatchObject({
      matches: [{ file_offset: 0x10, lba: 45000, text: "どう" }],
      source: {
        disc: {
          sectors: 1,
          first_sector_in_image: 1,
          header_mismatched_sectors: 0,
        },
      },
    });
  });

  it.each([
    { base: "0x0", raw: 0x20, width: 2 },
    { base: "0x08000000", raw: 0x20, width: 2 },
    { base: "0x0", raw: 0x08000020, width: 4 },
  ])(
    "preserves pointer base $base with raw pointer $raw separately from the image load address",
    async ({ base, raw, width }) => {
      const bytes = Buffer.alloc(128);
      bytes.writeUInt32LE(raw);
      bytes.write("OK\0", 0x20, "ascii");
      const path = join(root, `raw-${base}-${raw}.bin`);
      await writeFile(path, bytes);
      const result = await runLocalRomTool({
        path,
        tool: "scan_pointer_table",
        arguments: {
          table_offset: 0,
          count: 1,
          pointer_size: width,
          base_address: base,
          encoding: "ascii",
          resolve_xrefs: false,
        },
        signal,
        localBytes: false,
        formatHint: "raw-binary",
        architecture: "arm",
        loadAddress: "0x08000000",
        entryPoint: "0x08000000",
      });
      expect(result?.ok).toBe(true);
      if (!result?.ok) return;
      expect(result.value.result).toMatchObject({
        base_address: `0x${BigInt(base).toString(16)}`,
        table_address: "0x8000000",
        entries: [
          {
            entry_address: "0x8000000",
            target_address: "0x8000020",
            target_file_offset: 0x20,
            preview_text: "OK",
          },
        ],
      });
    },
  );
});

describe("local byte sources for ROM text tools", () => {
  it("falls back to plain bytes when the format is not recognized", async () => {
    const run = await runLocalRomTool({
      path: join(root, "blob.dat"),
      tool: "search_rom_strings",
      arguments: {
        query: "どう",
        encoding: "sjis-le16",
        terminator_word: 0xffff,
      },
      signal,
      localBytes: false,
    });
    expect(run?.ok).toBe(true);
    if (run === undefined || !run.ok) return;
    expect(run.value.subject).toMatchObject({ format: "file" });
    expect(run.value.limitations.join(" ")).toContain("not recognized");
    expect(run.value.result).toMatchObject({
      mode: "query_search",
      matches: [{ file_offset: 2, text: "どう", terminated: true }],
      source: { mode: "data", reason: "format_not_recognized" },
    });
  });

  it("reads a cue sheet's data track and reports sectors and LBAs", async () => {
    const run = await runLocalRomTool({
      path: join(root, "game.cue"),
      tool: "search_rom_strings",
      arguments: searchArguments,
      signal,
      localBytes: true,
    });
    expect(run?.ok).toBe(true);
    if (run === undefined || !run.ok) return;
    expect(run.value.result).toMatchObject({
      mode: "range_scan",
      matches: [
        { file_offset: 0x10, sector: 0, offset_in_sector: 0x10, lba: 12 },
        {
          file_offset: USER + 0x400,
          sector: 1,
          offset_in_sector: 0x400,
          lba: 13,
        },
        {
          file_offset: USER * 2 + 0x21,
          sector: 2,
          offset_in_sector: 0x21,
          lba: 14,
          text: "かな\nよ",
        },
      ],
      source: {
        mode: "disc-image",
        reason: "requested",
        sector_size: 2048,
        disc: {
          track: 2,
          // Track 01 holds 10 sectors; INDEX 01 is 2 sectors into Track 02.
          first_lba: 12,
          sectors: 3,
          first_sector_in_image: 2,
          header_mismatched_sectors: 0,
        },
      },
    });
  });

  it("groups identical strings with every occurrence", async () => {
    const run = await runLocalRomTool({
      path: join(root, "game.iso"),
      tool: "search_rom_strings",
      arguments: { ...searchArguments, dedupe: true, include_score: true },
      signal,
      localBytes: true,
    });
    expect(run?.ok).toBe(true);
    if (run === undefined || !run.ok) return;
    const result = run.value.result as {
      matches: { text: string; occurrences: number[]; text_score: number }[];
    };
    expect(
      result.matches.map((match) => [match.text, match.occurrences]),
    ).toEqual([
      ["どう", [0x10, USER + 0x400]],
      ["かな\nよ", [USER * 2 + 0x21]],
    ]);
    expect(result.matches[0]?.text_score).toBe(1);
  });
});

describe("local byte source exports and inspection", () => {
  it("exports every match as JSON Lines and refuses to overwrite silently", async () => {
    const output = join(root, "strings.jsonl");
    const exportRun = (overwrite: boolean) =>
      runLocalRomTool({
        path: join(root, "game.iso"),
        tool: "search_rom_strings",
        arguments: {
          encoding: "sjis-le16",
          terminator_word: 0xffff,
          newline_word: 0xfffe,
          min_length: 1,
          require_terminator: true,
        },
        signal,
        localBytes: true,
        exportTo: { path: output, overwrite },
      });
    const first = await exportRun(false);
    expect(first?.ok).toBe(true);
    if (first === undefined || !first.ok) return;
    expect(first.value.result).toMatchObject({
      mode: "range_scan",
      range: { start_offset: 0, end_offset: USER * 3 },
      output: { path: output, format: "jsonl", records: 3 },
    });
    const lines = (await readFile(output, "utf8")).trim().split("\n");
    expect(lines.map((line) => JSON.parse(line).file_offset)).toEqual([
      0x10,
      USER + 0x400,
      USER * 2 + 0x21,
    ]);
    const again = await exportRun(false);
    expect(again?.ok).toBe(false);
    const replaced = await exportRun(true);
    expect(replaced?.ok).toBe(true);
  });

  it("runs pointer and cave tools on plain bytes with file-offset addresses", async () => {
    const caves = await runLocalRomTool({
      path: join(root, "game.iso"),
      tool: "find_code_caves",
      arguments: { min_size: 512, fill_byte: 0, max_results: 1 },
      signal,
      localBytes: true,
    });
    expect(caves?.ok).toBe(true);
    if (caves === undefined || !caves.ok) return;
    expect(caves.value.result).toMatchObject({
      caves: [{ region_name: "DATA", executable: true }],
      source: { mode: "data", sector_size: 2048 },
    });
  });

  it("parses the PC Engine IPL from a cue sheet or an .iso", async () => {
    for (const name of ["game.cue", "game.iso"]) {
      const inspected = await inspectDiscImage(join(root, name));
      expect(inspected.ok).toBe(true);
      if (!inspected.ok) return;
      expect(inspected.value.result.pce_cd_ipl).toMatchObject({
        iplblk: 2,
        iplsta: "0x3000",
        program_name: "TEST GAME",
      });
    }
    const blob = await inspectDiscImage(join(root, "blob.dat"));
    expect(blob.ok).toBe(false);
  });

  it("exports scan_pointer_table manuscript records as JSON Lines", async () => {
    const ptrBin = new Uint8Array(0x30);
    ptrBin.set([0x10, 0x00, 0x20, 0x00], 0x00);
    ptrBin.set([...DOU], 0x10);
    ptrBin.set([...KANA], 0x20);
    const ptrPath = join(root, "ptr.bin");
    const outPath = join(root, "ptr-manuscript.jsonl");
    await writeFile(ptrPath, ptrBin);

    const exported = await runLocalRomTool({
      path: ptrPath,
      tool: "scan_pointer_table",
      arguments: {
        table_offset: 0,
        count: 2,
        pointer_size: 2,
        endian: "little",
        encoding: "sjis-swap16",
        terminator_word: 0xffff,
        newline_word: 0xfffe,
        manuscript_only: true,
      },
      signal,
      localBytes: true,
      exportTo: { path: outPath, overwrite: true },
    });
    expect(exported?.ok).toBe(true);
    if (exported === undefined || !exported.ok) return;
    expect(exported.value.result).toMatchObject({
      entries_scanned: 2,
      output: { path: outPath, format: "jsonl", records: 2 },
    });
    const rows = (await readFile(outPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { id: string; jp: string });
    expect(rows.map((r) => [r.id, r.jp])).toEqual([
      ["ptr_0000", "どう"],
      ["ptr_0001", "かな\nよ"],
    ]);
  });
});
