import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { iso9660Fixture } from "../../fixtures/iso9660.js";

cliTest(
  "exports orphan manuscript text without overlapping budgets and preserves neighboring text on readback",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-rom-orphan-cli-");
    const environment = {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
    };
    const path = join(root, "dialogue.dat");
    const bytes = Buffer.alloc(128);
    bytes.writeUInt16LE(0x20, 0);
    bytes.writeUInt16LE(0x40, 2);
    bytes.write("AA\0BB\0", 0x20, "ascii");
    bytes.write("CC\0", 0x40, "ascii");
    await writeFile(path, bytes);
    const args = [
      "scan-pointer-table",
      path,
      "--target-format",
      "data",
      "--table-offset",
      "0",
      "--count",
      "2",
      "--pointer-size",
      "2",
      "--encoding",
      "ascii",
      "--include-manuscript",
      "--include-orphan-strings",
      "--no-resolve-xrefs",
    ];
    const output = join(root, "manuscript.jsonl");
    const exported = await cli.run({
      arguments: [...args, "--output", output, "--json"],
      environment,
    });
    expect(exported.exitCode).toBe(0);
    expect(exported.json).toMatchObject({
      normalized_result: { entries_scanned: 2, output: { records: 3 } },
    });
    const records = (await readFile(output, "utf8"))
      .trim()
      .split("\n")
      .map(
        (line) =>
          JSON.parse(line) as {
            id: string;
            jp: string;
            max_bytes: number;
            target_file_offset: number;
          },
      );
    expect(records.map((r) => r.jp)).toEqual(["AA", "CC", "BB"]);
    expect(records[0]?.max_bytes).toBe(3);
    expect(records[2]).toMatchObject({
      id: "orphan_00000023",
      origin: "orphan",
      pointer_address: null,
      pointer_file_offset: null,
      after_entry_index: 0,
      target_file_offset: 0x23,
    });
    // A fixture-local insertion consumes only the reported first slot, preserving the orphan bytes.
    Buffer.from("KO\0", "ascii").copy(bytes, records[0]!.target_file_offset);
    await writeFile(path, bytes);
    const readback = await cli.run({
      arguments: [...args, "--json"],
      environment,
    });
    expect(readback.exitCode).toBe(0);
    expect(readback.json).toMatchObject({
      normalized_result: {
        manuscript_records: [
          { jp: "KO", max_bytes: 3 },
          { jp: "CC" },
          { id: "orphan_00000023", jp: "BB" },
        ],
      },
    });
  },
);

cliTest(
  "resolves ISO metadata and absolute LBAs through a data track after audio",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-disc-metadata-cli-");
    const environment = {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
    };
    await writeFile(join(root, "audio.bin"), Buffer.alloc(100 * 2352));
    await writeFile(join(root, "data.iso"), iso9660Fixture({ nested: true }));
    const path = join(root, "disc.cue");
    await writeFile(
      path,
      'FILE "audio.bin" BINARY\nTRACK 01 AUDIO\nINDEX 01 00:00:00\nFILE "data.iso" BINARY\nTRACK 02 MODE1/2048\nINDEX 01 00:00:00\n',
    );
    const result = await cli.run({
      arguments: [
        "inspect-disc-image",
        path,
        "--resolve-lba",
        "120",
        "--resolve-lba",
        "122",
        "--resolve-lba",
        "127",
        "--resolve-lba",
        "20",
        "--json",
      ],
      environment,
    });
    expect(result.exitCode).toBe(0);
    expect(result.json).toMatchObject({
      normalized_result: {
        iso9660: { allocation_coverage: "complete" },
        system_cnf: { boot_path: "/MAIN.EXE" },
        resolved_locations: [
          { lba: 120, file_path: "/SYSTEM.CNF" },
          { lba: 122, region: "iso9660_metadata" },
          { lba: 127, region: "unallocated_gap" },
          { region: "out_of_range" },
        ],
      },
    });
  },
);

/** sjis-le16 「どう」 + FFFF, then 「かな」 FFFE 「よ」 FFFF at an odd offset. */
const DISC_TEXT = Buffer.from("c782a482ffff00a982c882feffe682ffff", "hex");

cliTest(
  "reads unrecognized files as plain bytes and streams every match to JSON Lines",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-rom-data-cli-");
    const environment = {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
    };
    const image = Buffer.alloc(4096);
    DISC_TEXT.copy(image, 0x10);
    DISC_TEXT.copy(image, 0x810);
    const path = join(root, "track.iso");
    await writeFile(path, image);

    const page = await cli.run({
      arguments: [
        "search-rom-strings",
        path,
        "--encoding",
        "sjis-le16",
        "--terminator-word",
        "0xFFFF",
        "--newline-word",
        "0xFFFE",
        "--min-length",
        "1",
        "--start-offset",
        "0",
        "--length",
        "4096",
        "--dedupe",
        "--json",
      ],
      environment,
    });
    expect(page.exitCode).toBe(0);
    expect(page.json).toMatchObject({
      subject: { format: "file" },
      normalized_result: {
        mode: "range_scan",
        matches: [
          {
            text: "どう",
            sector: 0,
            offset_in_sector: 0x10,
            occurrences: [0x10, 0x810],
          },
          { text: "かな\nよ", occurrences: [0x17, 0x817] },
        ],
        source: { mode: "data", reason: "format_not_recognized" },
      },
    });

    const output = join(root, "strings.jsonl");
    const exported = await cli.run({
      arguments: [
        "search-rom-strings",
        path,
        "--target-format",
        "data",
        "--encoding",
        "sjis-le16",
        "--terminator-word",
        "0xFFFF",
        "--newline-word",
        "0xFFFE",
        "--min-length",
        "1",
        "--output",
        output,
        "--json",
      ],
      environment,
    });
    expect(exported.exitCode).toBe(0);
    expect(exported.json).toMatchObject({
      normalized_result: {
        source: { mode: "data", reason: "requested" },
        output: { path: output, format: "jsonl", records: 4 },
      },
    });
    const records = (await readFile(output, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { file_offset: number });
    expect(records.map((record) => record.file_offset)).toEqual([
      0x10, 0x17, 0x810, 0x817,
    ]);

    const inspected = await cli.run({
      arguments: ["inspect-disc-image", path, "--json"],
      environment,
    });
    expect(inspected.exitCode).toBe(0);
    expect(inspected.json).toMatchObject({
      operation: "inspect_disc_image",
      normalized_result: {
        source: { mode: "data", sector_size: 2048 },
        pce_cd_ipl: null,
      },
    });
  },
);

/** Words at sector 1: header, table of offsets from the sector start, strings. */
const OVERLAY = Buffer.from(
  [
    0x2000, 0x0010, 0x000c, 0x000c, 0x000c, 0x002e, 0x0016, 0x001c, 0x0026,
    0x0028, 0x0016, 0x82c7, 0x82a4, 0xffff, 0x82a9, 0x82c8, 0xfffe, 0x82e6,
    0xffff, 0xffff, 0x82cd, 0x82a2, 0xffff,
  ].flatMap((word) => [word & 0xff, word >>> 8]),
);

cliTest(
  "finds and scans pointer tables relative to an overlay segment",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-rom-segment-cli-");
    const environment = {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
    };
    const image = Buffer.alloc(0x1800);
    OVERLAY.copy(image, 0x800);
    const path = join(root, "overlay.iso");
    await writeFile(path, image);
    const text = [
      "--pointer-size",
      "2",
      "--encoding",
      "sjis-le16",
      "--terminator-word",
      "0xFFFF",
      "--newline-word",
      "0xFFFE",
    ];
    const discover = [
      "discover-pointer-tables",
      path,
      ...text,
      "--min-string-length",
      "1",
      "--min-entries",
      "3",
      "--target-after-terminator",
    ];
    const table = {
      table_file_offset: 0x80c,
      entry_count: 5,
      segment_start: 0x800,
      coverage: { adjacent_to_table: true, complete: true, ratio: 1 },
    };

    const single = await cli.run({
      arguments: [...discover, "--segment", "0x800:0x800", "--json"],
      environment,
    });
    expect(single.exitCode).toBe(0);
    expect(single.json).toMatchObject({
      normalized_result: {
        base_mode: "segment",
        segment_start: 0x800,
        segment_length: 0x800,
        tables: [table],
      },
    });

    const aligned = await cli.run({
      arguments: [
        ...discover,
        "--segment-align",
        "2048",
        "--segment-length",
        "0x1000",
        "--min-coverage",
        "1",
        "--start-offset",
        "0",
        "--end-offset",
        "0x1800",
        "--json",
      ],
      environment,
    });
    expect(aligned.exitCode).toBe(0);
    expect(aligned.json).toMatchObject({
      normalized_result: { segment_align: 2048, tables: [table] },
    });

    const scanned = await cli.run({
      arguments: [
        "scan-pointer-table",
        path,
        ...text,
        "--table-offset",
        "0x80c",
        "--count",
        "5",
        "--segment",
        "0x800:0x800",
        "--json",
      ],
      environment,
    });
    expect(scanned.exitCode).toBe(0);
    expect(scanned.json).toMatchObject({
      normalized_result: {
        base_mode: "segment",
        entries: [
          { target_file_offset: 0x816, preview_text: "どう" },
          { target_file_offset: 0x81c, preview_text: "かな\nよ" },
          { target_file_offset: 0x826, preview_text: "" },
          { target_file_offset: 0x828, preview_text: "はい" },
          { target_file_offset: 0x816 },
        ],
        coverage: { strings: 4, complete: true },
      },
    });

    const conflicting = await cli.run({
      arguments: [
        ...discover,
        "--segment",
        "0x800:0x800",
        "--segment-length",
        "16",
        "--json",
      ],
      environment,
    });
    expect(conflicting.exitCode).not.toBe(0);
    expect(JSON.stringify(conflicting.json)).toContain("--segment-align");
  },
);

/**
 * あ 1B 00 い 0A う 00 at 0x10, か 00 at 0x20, pointers to both at 0x00.
 * The {COLOR} argument is the terminator byte, so only a declared argument
 * count keeps the string whole.
 */
const CODED_DIALOGUE = (): Buffer => {
  const bytes = Buffer.alloc(0x30);
  Buffer.from("10002000", "hex").copy(bytes, 0x00);
  Buffer.from("82a01b0082a20a82a400", "hex").copy(bytes, 0x10);
  Buffer.from("82a900", "hex").copy(bytes, 0x20);
  return bytes;
};

cliTest(
  "declares in-string control codes from a file or inline, and refuses both at once",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-rom-codes-cli-");
    const environment = {
      HOME: root,
      XDG_CONFIG_HOME: root,
      XDG_CACHE_HOME: root,
    };
    const path = join(root, "dialogue.bin");
    await writeFile(path, CODED_DIALOGUE());
    const codesPath = join(root, "codes.json");
    await writeFile(
      codesPath,
      JSON.stringify([
        { hex: "1B", name: "COLOR", argument_bytes: 1 },
        { hex: "0A", name: "LINE", role: "line-break" },
      ]),
    );
    const base = [
      "scan-pointer-table",
      path,
      "--table-offset",
      "0",
      "--count",
      "2",
      "--pointer-size",
      "2",
      "--manuscript-only",
      "--json",
    ];

    const plain = await cli.run({ arguments: base, environment });
    expect(plain.exitCode).toBe(0);
    expect(plain.json).toMatchObject({
      normalized_result: {
        manuscript_records: [
          { index: 0, byte_length: 4 },
          { index: 1, jp: "か" },
        ],
      },
    });

    const declared = await cli.run({
      arguments: [...base, "--control-codes", codesPath],
      environment,
    });
    expect(declared.exitCode).toBe(0);
    expect(declared.json).toMatchObject({
      normalized_result: {
        manuscript_records: [
          {
            index: 0,
            jp: "あ{COLOR}い{LINE}う",
            byte_length: 10,
            max_bytes: 16,
            lines: ["あ{COLOR}い", "う"],
            character_length: 3,
            longest_line_characters: 2,
          },
          { index: 1, jp: "か", lines: ["か"] },
        ],
      },
    });

    const inline = await cli.run({
      arguments: [
        ...base,
        "--control-codes-json",
        '[{"hex":"0A","name":"LINE","role":"line-break"}]',
      ],
      environment,
    });
    expect(inline.exitCode).toBe(0);
    expect(inline.json).toMatchObject({
      normalized_result: {
        manuscript_records: [
          { index: 0, byte_length: 4 },
          { index: 1, jp: "か" },
        ],
      },
    });

    const both = await cli.run({
      arguments: [
        ...base,
        "--control-codes",
        codesPath,
        "--control-codes-json",
        "[]",
      ],
      environment,
    });
    expect(both.exitCode).not.toBe(0);
    expect(JSON.stringify(both.json)).toContain("not both");

    const missing = await cli.run({
      arguments: [...base, "--control-codes", join(root, "absent.json")],
      environment,
    });
    expect(missing.exitCode).not.toBe(0);
    expect(JSON.stringify(missing.json)).toContain("could not read");
  },
);
