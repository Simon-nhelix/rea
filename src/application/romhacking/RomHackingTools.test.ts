import { describe, expect, it } from "vitest";
import {
  executeDiscoverPointerTables,
  executeFindCodeCaves,
  executeScanPointerTable,
  executeSearchRomStrings,
} from "./RomHackingTools.js";
import { ok } from "../../domain/result.js";
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
      pointer_size: 4,
      endian: "little",
      base_address: "0x0",
      encoding: "sjis",
      terminator_byte: 0x00,
      preview_bytes: 64,
      resolve_xrefs: true,
      include_manuscript: true,
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
