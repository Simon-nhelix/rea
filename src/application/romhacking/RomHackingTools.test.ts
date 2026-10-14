import { describe, expect, it } from "vitest";
import {
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

  it("executes scan_pointer_table and decodes target string previews", async () => {
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
      preview_bytes: 64,
      resolve_xrefs: true,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const data = result.value as {
      entries_scanned: number;
      entries: Array<{
        target_address: string;
        target_file_offset: number;
        preview_text: string;
      }>;
    };
    expect(data.entries_scanned).toBe(2);
    expect(data.entries[0]?.target_address).toBe("0x8002000");
    expect(data.entries[0]?.target_file_offset).toBe(0x2000);
    expect(data.entries[0]?.preview_text).toBe("勇者");
  });
});
