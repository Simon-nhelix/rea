import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  executeDiscoverPointerTables,
  executeFindCodeCaves,
  executeScanPointerTable,
  executeSearchRomStrings,
} from "./RomHackingTools.js";
import { ok } from "../../domain/result.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import {
  createAnalysisExecution,
  type AnalysisOperationPort,
} from "../AnalysisProvider.js";

const mockProvider = {
  id: "ghidra",
  name: "Ghidra",
  version: "11.3.2",
} as const;

describe("RomHackingTools workflows", () => {
  it("executes search_rom_strings in query_search mode and resolves file_offset + xrefs", async () => {
    const mockAnalysis: AnalysisOperationPort = {
      execute: async (operation, args) => {
        if (operation === "search_bytes") {
          return ok(
            createAnalysisExecution(
              {
                matches: [{ address: "0x08002000", procedure: null }],
                complete: true,
              },
              mockProvider,
            ),
          );
        }
        if (operation === "read_bytes") {
          return ok(
            createAnalysisExecution(
              {
                address: String(args.address),
                requested_bytes: 128,
                returned_bytes: 5,
                bytes_hex: "97458ed200",
                complete: true,
              },
              mockProvider,
            ),
          );
        }
        if (operation === "address_to_file_offset") {
          return ok(
            createAnalysisExecution(
              {
                address: String(args.address),
                file_offset: 0x2000,
              },
              mockProvider,
            ),
          );
        }
        if (operation === "xrefs") {
          return ok(createAnalysisExecution(["0x08000410"], mockProvider));
        }
        return ok(createAnalysisExecution({}, mockProvider));
      },
    };

    const result = await executeSearchRomStrings(mockAnalysis, {
      query: "勇者",
      encoding: "sjis",
      length: 4096,
      min_length: 2,
      terminator_byte: 0x00,
      max_results: 10,
      resolve_xrefs: true,
      include_hex: true,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toEqual({
      mode: "query_search",
      encoding: "sjis",
      encoded_query_pattern: "97 45 8E D2",
      matches: [
        {
          address: "0x08002000",
          file_offset: 0x2000,
          encoding: "sjis",
          text: "勇者",
          bytes_hex: "97458ed200",
          byte_length: 5,
          terminated: true,
          xrefs: ["0x08000410"],
        },
      ],
      total_matches: 1,
      truncated: false,
      next_cursor: null,
    });
  });
});

describe("RomHackingTools scan_pointer_table", () => {
  it("executes scan_pointer_table and decodes target string previews, budgets, and manuscript records", async () => {
    const mockAnalysis: AnalysisOperationPort = {
      execute: async (operation, args) => {
        if (operation === "read_bytes") {
          if (args.address === "0x08001000") {
            return ok(
              createAnalysisExecution(
                {
                  address: "0x08001000",
                  requested_bytes: 8,
                  returned_bytes: 8,
                  bytes_hex: "0020000810200008",
                  complete: true,
                },
                mockProvider,
              ),
            );
          }
          return ok(
            createAnalysisExecution(
              {
                address: String(args.address),
                requested_bytes: 64,
                returned_bytes: 5,
                bytes_hex: "97458ed200",
                complete: true,
              },
              mockProvider,
            ),
          );
        }
        if (operation === "address_to_file_offset") {
          return ok(
            createAnalysisExecution(
              {
                address: String(args.address),
                file_offset: args.address === "0x8002000" ? 0x2000 : 0x2010,
              },
              mockProvider,
            ),
          );
        }
        if (operation === "xrefs") {
          return ok(createAnalysisExecution(["0x08000100"], mockProvider));
        }
        return ok(createAnalysisExecution({}, mockProvider));
      },
    };

    const result = await executeScanPointerTable(mockAnalysis, {
      address: "0x08001000",
      count: 2,
      start_index: 0,
      pointer_size: 4,
      endian: "little",
      base_address: "0x0",
      encoding: "sjis",
      terminator_byte: 0x00,
      preview_bytes: 64,
      resolve_xrefs: true,
      include_manuscript: true,
      include_hex: false,
      manuscript_only: false,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const data = result.value as {
      entries_scanned: number;
      entries: Array<{
        target_address: string;
        target_file_offset: number;
        preview_text: string;
        allocated_budget_bytes: number | null;
      }>;
      manuscript_records?: Array<{
        id: string;
        max_bytes: number | null;
        jp: string;
      }>;
    };
    expect(data.entries_scanned).toBe(2);
    expect(data.entries[0]?.target_address).toBe("0x8002000");
    expect(data.entries[0]?.target_file_offset).toBe(0x2000);
    expect(data.entries[0]?.preview_text).toBe("勇者");
    expect(data.entries[0]?.allocated_budget_bytes).toBe(16);
    expect(data.manuscript_records?.[0]?.id).toBe("ptr_0000");
    expect(data.manuscript_records?.[0]?.max_bytes).toBe(16);
    expect(data.manuscript_records?.[0]?.jp).toBe("勇者");
  });
});

describe("RomHackingTools discovery and caves", () => {
  it("executes discover_pointer_tables and find_code_caves against provider read_bytes", async () => {
    // Build a 128-byte image at 0x08000000:
    // 0x00..0x0F: 4 x 32-bit LE pointers to 0x08000020, 0x08000026, 0x0800002C, 0x08000032
    // 0x20..0x37: 4 Shift-JIS strings ("勇者\0\0", "魔法\0\0", "戦士\0\0", "僧侶\0\0")
    // 0x40..0x7F: 64 bytes of 0xFF padding cave
    const buf = Buffer.alloc(128, 0);
    buf.writeUInt32LE(0x08000020, 0);
    buf.writeUInt32LE(0x08000026, 4);
    buf.writeUInt32LE(0x0800002c, 8);
    buf.writeUInt32LE(0x08000032, 12);
    Buffer.from([0x97, 0x45, 0x8e, 0xd2, 0x00]).copy(buf, 0x20); // 勇者
    Buffer.from([0x96, 0x82, 0x96, 0x40, 0x00]).copy(buf, 0x26); // 魔法
    Buffer.from([0x90, 0xed, 0x8e, 0x6d, 0x00]).copy(buf, 0x2c); // 戦士
    Buffer.from([0x97, 0x45, 0x8e, 0xd2, 0x00]).copy(buf, 0x32); // 勇者
    buf.fill(0xff, 0x40, 0x80);

    const mockAnalysis: AnalysisOperationPort = {
      execute: async (operation) => {
        if (operation === "read_bytes") {
          return ok(
            createAnalysisExecution(
              {
                address: "0x08000000",
                requested_bytes: 128,
                returned_bytes: 128,
                bytes_hex: buf.toString("hex"),
                complete: true,
              },
              mockProvider,
            ),
          );
        }
        return ok(createAnalysisExecution([], mockProvider));
      },
    };

    const discovered = await executeDiscoverPointerTables(mockAnalysis, {
      start_address: "0x08000000",
      length: 128,
      pointer_size: 4,
      endian: "little",
      base_address: "0x0",
      min_entries: 3,
      encoding: "sjis",
      terminator_byte: 0x00,
      min_string_length: 2,
      max_tables: 10,
      sample_entries: 3,
      resolve_xrefs: false,
    });
    expect(discovered.ok).toBe(true);
    if (!discovered.ok) return;
    const discData = discovered.value as {
      total_tables: number;
      tables: Array<{ table_address: string; entry_count: number }>;
    };
    expect(discData.total_tables).toBe(1);
    expect(discData.tables[0]?.table_address).toBe("0x8000000");
    expect(discData.tables[0]?.entry_count).toBe(4);

    const caves = await executeFindCodeCaves(mockAnalysis, {
      start_address: "0x08000000",
      length: 128,
      min_size: 32,
      alignment: 4,
      executable_only: false,
      max_results: 10,
      resolve_xrefs: false,
    });
    expect(caves.ok).toBe(true);
    if (!caves.ok) return;
    const caveData = caves.value as {
      total_caves: number;
      caves: Array<{ address: string; byte_length: number; fill_byte: string }>;
    };
    expect(caveData.total_caves).toBe(1);
    expect(caveData.caves[0]?.address).toBe("0x8000040");
    expect(caveData.caves[0]?.byte_length).toBe(64);
    expect(caveData.caves[0]?.fill_byte).toBe("0xff");
  });
});

const localRomFixture: {
  dir: string;
  target: BinaryTarget | undefined;
  providerCalls: number;
} = { dir: "", target: undefined, providerCalls: 0 };

const countingAnalysis: AnalysisOperationPort = {
  execute: async () => {
    localRomFixture.providerCalls++;
    return ok(createAnalysisExecution({}, mockProvider));
  },
};

const ensureLocalRom = async (): Promise<BinaryTarget> => {
  if (localRomFixture.target !== undefined) return localRomFixture.target;
  const rom = Buffer.alloc(0x400, 0);
  // Pointer table at 0x00: 0x100, 0x110, 0x100 (shared), 0x120, 0x200
  rom.writeUInt32LE(0x100, 0);
  rom.writeUInt32LE(0x110, 4);
  rom.writeUInt32LE(0x100, 8);
  rom.writeUInt32LE(0x120, 12);
  rom.writeUInt32LE(0x200, 16);
  Buffer.from([0x97, 0x45, 0x8e, 0xd2, 0x00]).copy(rom, 0x100); // 勇者
  Buffer.from([0x96, 0x82, 0x96, 0x40, 0x00]).copy(rom, 0x110); // 魔法
  Buffer.from([0x90, 0xed, 0x8e, 0x6d, 0x00]).copy(rom, 0x120); // 戦士
  const longString = Buffer.alloc(41, 0);
  for (let i = 0; i < 10; i++) {
    Buffer.from([0x97, 0x45, 0x8e, 0xd2]).copy(longString, i * 4);
  }
  longString.copy(rom, 0x200); // 勇者 x10 + NUL

  localRomFixture.dir = await mkdtemp(join(tmpdir(), "rea-rom-"));
  const romPath = join(localRomFixture.dir, "test.bin");
  await writeFile(romPath, rom);
  localRomFixture.target = {
    path: romPath,
    sha256: "a".repeat(64),
    kind: "executable",
    format: "raw-binary",
    architecture: "arm",
    availableArchitectures: ["arm"],
    entryPoint: "0x0",
    entryPointSource: "0x0",
  };
  return localRomFixture.target;
};

const cleanupLocalRom = async (): Promise<void> => {
  await rm(localRomFixture.dir, { recursive: true, force: true });
  localRomFixture.target = undefined;
  localRomFixture.dir = "";
};

describe("RomHackingTools Mode A local ROM search", () => {
  let target: BinaryTarget;
  beforeAll(async () => {
    target = await ensureLocalRom();
  });
  afterAll(cleanupLocalRom);

  it("searches locally with zero provider calls and omits hex by default", async () => {
    localRomFixture.providerCalls = 0;
    const result = await executeSearchRomStrings(
      countingAnalysis,
      {
        query: "魔法",
        encoding: "sjis",
        length: 4096,
        min_length: 2,
        terminator_byte: 0x00,
        max_results: 10,
        resolve_xrefs: false,
        include_hex: false,
      },
      undefined,
      target,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(localRomFixture.providerCalls).toBe(0);
    const data = result.value as {
      total_matches: number;
      truncated: boolean;
      next_cursor: string | null;
      matches: Array<Record<string, unknown>>;
    };
    expect(data.total_matches).toBe(1);
    expect(data.truncated).toBe(false);
    expect(data.next_cursor).toBeNull();
    expect(data.matches[0]?.file_offset).toBe(0x110);
    expect(data.matches[0]?.text).toBe("魔法");
    expect(data.matches[0]).not.toHaveProperty("bytes_hex");
  });

  it("pages range_scan with an exact truncated probe and cursor", async () => {
    localRomFixture.providerCalls = 0;
    const pageInput = {
      encoding: "sjis" as const,
      start_offset: 0x100,
      length: 0x30,
      min_length: 2,
      terminator_byte: 0x00,
      max_results: 2,
      resolve_xrefs: false,
      include_hex: false,
    };
    const first = await executeSearchRomStrings(
      countingAnalysis,
      pageInput,
      undefined,
      target,
    );
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const firstData = first.value as {
      truncated: boolean;
      next_cursor: string | null;
      matches: Array<{ text: string }>;
    };
    expect(firstData.matches.map((m) => m.text)).toEqual(["勇者", "魔法"]);
    expect(firstData.truncated).toBe(true);
    expect(firstData.next_cursor).toBe("32");

    const second = await executeSearchRomStrings(
      countingAnalysis,
      { ...pageInput, cursor: firstData.next_cursor ?? undefined },
      undefined,
      target,
    );
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    const secondData = second.value as typeof firstData;
    expect(secondData.matches.map((m) => m.text)).toEqual(["戦士"]);
    expect(secondData.truncated).toBe(false);
    expect(secondData.next_cursor).toBeNull();
    expect(localRomFixture.providerCalls).toBe(0);
  });
});

describe("RomHackingTools Mode A local pointer scan", () => {
  let target: BinaryTarget;
  beforeAll(async () => {
    target = await ensureLocalRom();
  });
  afterAll(cleanupLocalRom);

  it("pages pointer scans with global indexes and deduped full manuscript", async () => {
    localRomFixture.providerCalls = 0;
    const baseInput = {
      table_offset: 0,
      pointer_size: 4 as const,
      endian: "little" as const,
      base_address: "0x0",
      encoding: "sjis" as const,
      terminator_byte: 0x00,
      preview_bytes: 8,
      resolve_xrefs: false,
      include_hex: false,
    };
    const firstPage = await executeScanPointerTable(
      countingAnalysis,
      {
        ...baseInput,
        count: 3,
        start_index: 0,
        include_manuscript: false,
        manuscript_only: true,
      },
      undefined,
      target,
    );
    expect(firstPage.ok).toBe(true);
    if (!firstPage.ok) return;
    const firstData = firstPage.value as {
      entries: unknown[];
      entries_scanned: number;
      next_start_index: number;
      manuscript_records: Array<{
        id: string;
        jp: string;
        also_referenced_by?: number[];
      }>;
    };
    expect(firstData.entries).toEqual([]);
    expect(firstData.entries_scanned).toBe(3);
    expect(firstData.next_start_index).toBe(3);
    expect(firstData.manuscript_records.map((r) => r.id)).toEqual([
      "ptr_0000",
      "ptr_0001",
    ]);
    expect(firstData.manuscript_records[0]?.also_referenced_by).toEqual([2]);

    const secondPage = await executeScanPointerTable(
      countingAnalysis,
      {
        ...baseInput,
        count: 2,
        start_index: firstData.next_start_index,
        include_manuscript: true,
        manuscript_only: false,
      },
      undefined,
      target,
    );
    expect(secondPage.ok).toBe(true);
    if (!secondPage.ok) return;
    const secondData = secondPage.value as {
      entries: Array<{
        index: number;
        preview_text: string | null;
        preview_truncated?: boolean;
      }>;
      manuscript_records: Array<{
        id: string;
        jp: string;
        byte_length: number | null;
        truncated?: boolean;
      }>;
    };
    expect(secondData.entries.map((e) => e.index)).toEqual([3, 4]);
    expect(secondData.entries[1]?.preview_truncated).toBe(true);
    expect(secondData.manuscript_records.map((r) => r.id)).toEqual([
      "ptr_0003",
      "ptr_0004",
    ]);
    // Manuscript decodes to the terminator, beyond the 8-byte preview cap.
    expect(secondData.manuscript_records[1]?.jp).toBe("勇者".repeat(10));
    expect(secondData.manuscript_records[1]?.byte_length).toBe(41);
    expect(secondData.manuscript_records[1]?.truncated).toBeUndefined();
    expect(localRomFixture.providerCalls).toBe(0);
  });
});

describe("RomHackingTools provider batching", () => {
  it("resolves offsets and previews once per unique address", async () => {
    const offsetCalls: string[] = [];
    const previewReads: string[] = [];
    let xrefCalls = 0;
    const mockAnalysis: AnalysisOperationPort = {
      execute: async (operation, args) => {
        if (operation === "read_bytes") {
          if (args.address === "0x08001000") {
            return ok(
              createAnalysisExecution(
                {
                  address: "0x08001000",
                  requested_bytes: 12,
                  returned_bytes: 12,
                  bytes_hex: "002000080020000810200008",
                  complete: true,
                },
                mockProvider,
              ),
            );
          }
          previewReads.push(String(args.address));
          return ok(
            createAnalysisExecution(
              {
                address: String(args.address),
                requested_bytes: 64,
                returned_bytes: 5,
                bytes_hex: "97458ed200",
                complete: true,
              },
              mockProvider,
            ),
          );
        }
        if (operation === "address_to_file_offset") {
          offsetCalls.push(String(args.address));
          return ok(
            createAnalysisExecution(
              { address: String(args.address), file_offset: 0x2000 },
              mockProvider,
            ),
          );
        }
        if (operation === "xrefs") xrefCalls++;
        return ok(createAnalysisExecution({}, mockProvider));
      },
    };

    const result = await executeScanPointerTable(mockAnalysis, {
      address: "0x08001000",
      count: 3,
      start_index: 0,
      pointer_size: 4,
      endian: "little",
      base_address: "0x0",
      encoding: "sjis",
      terminator_byte: 0x00,
      preview_bytes: 64,
      resolve_xrefs: false,
      include_manuscript: false,
      include_hex: false,
      manuscript_only: false,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // 3 entry addresses + 2 unique targets (0x8002000 shared by two slots).
    expect(offsetCalls).toHaveLength(5);
    expect(new Set(offsetCalls).size).toBe(5);
    expect(previewReads).toHaveLength(2);
    expect(xrefCalls).toBe(0);
    const data = result.value as {
      entries: Array<{ entry_file_offset: number | null }>;
    };
    // File offsets resolve even though xrefs are opt-in and disabled.
    expect(data.entries[0]?.entry_file_offset).toBe(0x2000);
  });
});

describe("RomHackingTools provider search cursor", () => {
  it("passes the provider cursor through verbatim across pages", async () => {
    const seenCursors: unknown[] = [];
    const mockAnalysis: AnalysisOperationPort = {
      execute: async (operation, args) => {
        if (operation === "search_bytes") {
          seenCursors.push(args.cursor);
          const secondPage = args.cursor === "bind:0x8002000";
          return ok(
            createAnalysisExecution(
              {
                matches: [
                  { address: secondPage ? "0x08003000" : "0x08002000" },
                ],
                complete: secondPage,
                next_cursor: secondPage ? null : "bind:0x8002000",
              },
              mockProvider,
            ),
          );
        }
        if (operation === "read_bytes") {
          return ok(
            createAnalysisExecution(
              {
                address: String(args.address),
                requested_bytes: 128,
                returned_bytes: 5,
                bytes_hex: "97458ed200",
                complete: true,
              },
              mockProvider,
            ),
          );
        }
        if (operation === "address_to_file_offset") {
          return ok(
            createAnalysisExecution(
              { address: String(args.address), file_offset: 0x2000 },
              mockProvider,
            ),
          );
        }
        return ok(createAnalysisExecution({}, mockProvider));
      },
    };
    const baseInput = {
      query: "勇者",
      encoding: "sjis" as const,
      length: 4096,
      min_length: 2,
      terminator_byte: 0x00,
      max_results: 1,
      resolve_xrefs: false,
      include_hex: false,
    };
    const first = await executeSearchRomStrings(mockAnalysis, baseInput);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const firstData = first.value as {
      truncated: boolean;
      next_cursor: string | null;
    };
    expect(firstData.truncated).toBe(true);
    expect(firstData.next_cursor).toBe("bind:0x8002000");

    const second = await executeSearchRomStrings(mockAnalysis, {
      ...baseInput,
      cursor: firstData.next_cursor ?? undefined,
    });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    const secondData = second.value as typeof firstData;
    expect(secondData.truncated).toBe(false);
    expect(secondData.next_cursor).toBeNull();
    expect(seenCursors).toEqual([undefined, "bind:0x8002000"]);
  });
});
