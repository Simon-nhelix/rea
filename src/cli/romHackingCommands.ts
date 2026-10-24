import { readFile } from "node:fs/promises";

import { z } from "incur";
import type { Logger } from "pino";

import type { DirectAnalysis } from "../composition/directAnalysis.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { executableFormatHintSchema } from "../domain/dosCom.js";
import {
  POINTER_BASE_MODES,
  ROM_TEXT_ENCODINGS,
  ROM_WORD_PARITIES,
} from "../domain/romHacking.js";
import { parseSegmentSpec } from "../domain/romPointerSegments.js";
import {
  romControlCodeDeclarationsSchema,
  type RomControlCodeInput,
} from "../domain/romControlCodes.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { inspectDiscImage } from "../application/romhacking/LocalByteSource.js";
import { REA_WORKFLOW_PROVIDER } from "../domain/investigationProviders.js";
import { createEvidence } from "../domain/evidence.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  directAnalysisOptionsFromCli,
  nativeOpenOptionFields,
  type NativeOpenCliFlags,
} from "./options.js";
import type { CliInstance } from "./types.js";

/** `--target-format` for ROM text tools: native formats plus plain `data` bytes. */
const romOpenOptionFields = {
  ...nativeOpenOptionFields,
  "target-format": z
    .enum([...executableFormatHintSchema.options, "data"])
    .optional()
    .describe(
      "Explicit format; 'data' reads the file as plain bytes (a .cue sheet as its first data track's user data); omission detects the format and falls back to data when it is not recognized",
    ),
};

type RomOpenCliFlags = Omit<NativeOpenCliFlags, "target-format"> & {
  readonly "target-format"?:
    | NativeOpenCliFlags["target-format"]
    | "data"
    | undefined;
};

/** Map ROM CLI flags to one-shot options; `data` selects plain local bytes. */
const romAnalysisOptionsFromCli = (
  logger: Logger,
  options: RomOpenCliFlags,
  stringExport?: { readonly path: string; readonly overwrite: boolean },
) => {
  const format = options["target-format"];
  const base = directAnalysisOptionsFromCli(logger, {
    ...options,
    "target-format": format === "data" ? undefined : format,
  });
  return {
    ...base,
    ...(format === "data" ? { localBytes: true } : {}),
    ...(stringExport === undefined ? {} : { stringExport }),
  };
};

/** 16-bit word options shared by the ROM text commands. */
const romWordFormatOptions = {
  terminatorWord: z
    .number()
    .int()
    .min(0)
    .max(0xffff)
    .optional()
    .describe(
      "String-ending word for sjis-le16/tile-le16/tile-be16 (e.g. 0xFFFF; default terminator byte doubled)",
    ),
  newlineWord: z
    .number()
    .int()
    .min(0)
    .max(0xffff)
    .optional()
    .describe("Word decoded as a line break in word encodings (e.g. 0xFFFE)"),
  tileMask: z
    .number()
    .int()
    .min(1)
    .max(0xffff)
    .optional()
    .describe("Tile-index bits of tile-le16/tile-be16 words (default 0x0FFF)"),
  tileAttribute: z
    .number()
    .int()
    .min(0)
    .max(0xffff)
    .optional()
    .describe(
      "Required non-tile bits of tilemap words (e.g. 0xF000); omit for one consistent value per string",
    ),
};

const romWordFormatArguments = (options: {
  readonly terminatorWord?: number | undefined;
  readonly newlineWord?: number | undefined;
  readonly tileMask?: number | undefined;
  readonly tileAttribute?: number | undefined;
}) => ({
  ...(options.terminatorWord === undefined
    ? {}
    : { terminator_word: options.terminatorWord }),
  ...(options.newlineWord === undefined
    ? {}
    : { newline_word: options.newlineWord }),
  ...(options.tileMask === undefined ? {} : { tile_mask: options.tileMask }),
  ...(options.tileAttribute === undefined
    ? {}
    : { tile_attribute: options.tileAttribute }),
});

/** `--base-mode` and `--segment` shared by the pointer table commands. */
const pointerSegmentOptions = {
  baseMode: z
    .enum(POINTER_BASE_MODES)
    .optional()
    .describe(
      "address: base address + value; segment: segment start file offset + value (overlay-relative offsets). Default: segment when a segment option is given",
    ),
  segment: z
    .string()
    .regex(/^\s*(0x[0-9a-f]+|\d+)\s*:\s*(0x[0-9a-f]+|\d+)\s*$/iu)
    .optional()
    .describe(
      "Segment (overlay block) the pointer values are relative to, as <start>:<length> file offsets (e.g. 0x19800:0xD800)",
    ),
};

/** Map --base-mode/--segment(/--segment-align/--segment-length) to tool input. */
/**
 * Read declared control codes from a JSON file or an inline flag. Both state
 * the same list, so giving two sources at once would leave which one applies
 * unresolved and is refused.
 */
const readControlCodeDeclarations = async (
  operation: string,
  options: {
    readonly controlCodes?: string | undefined;
    readonly controlCodesJson?: string | undefined;
  },
): Promise<ReadonlyArray<RomControlCodeInput> | undefined> => {
  const file = options.controlCodes;
  const inline = options.controlCodesJson;
  const fail = (message: string): never => {
    throw new AnalysisInputError(operation, undefined, [
      { path: ["control_codes"], reason: "invalid_value", message },
    ]);
  };
  if (file === undefined && inline === undefined) return undefined;
  if (file !== undefined && inline !== undefined)
    fail(
      "Declare control codes with --control-codes or --control-codes-json, not both.",
    );
  let source = inline;
  if (source === undefined && file !== undefined) {
    try {
      source = await readFile(file, "utf8");
    } catch (cause) {
      fail(
        `--control-codes could not read ${file}: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    }
  }
  let value: unknown;
  try {
    value = JSON.parse(source ?? "");
  } catch (cause) {
    fail(
      `Control code declarations are not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  const parsed = romControlCodeDeclarationsSchema.safeParse(value);
  if (!parsed.success)
    fail(
      `Control code declarations are invalid: ${parsed.error.issues
        .map((issue) => `${issue.path.join(".") || "[]"}: ${issue.message}`)
        .join("; ")}`,
    );
  return parsed.success ? parsed.data : undefined;
};

const pointerSegmentArguments = (
  operation: string,
  options: {
    readonly baseMode?: (typeof POINTER_BASE_MODES)[number] | undefined;
    readonly segment?: string | undefined;
    readonly segmentAlign?: number | undefined;
    readonly segmentLength?: number | undefined;
  },
) => {
  const segment =
    options.segment === undefined
      ? undefined
      : parseSegmentSpec(options.segment);
  const fail = (message: string): never => {
    throw new AnalysisInputError(operation, undefined, [
      { path: ["segment"], reason: "invalid_value", message },
    ]);
  };
  if (options.segment !== undefined && segment === undefined)
    fail("--segment expects <start>:<length> with a length of at least 1.");
  if (segment !== undefined && options.segmentLength !== undefined)
    fail(
      "--segment already gives the length; --segment-length goes with --segment-align.",
    );
  return {
    ...(options.baseMode === undefined ? {} : { base_mode: options.baseMode }),
    ...(segment === undefined
      ? {}
      : { segment_start: segment.start, segment_length: segment.length }),
    ...(options.segmentAlign === undefined
      ? {}
      : { segment_align: options.segmentAlign }),
    ...(options.segmentLength === undefined
      ? {}
      : { segment_length: options.segmentLength }),
  };
};

export const registerRomHackingCommands = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.searchRomStrings, {
    description:
      "Search or scan console ROM memory for Shift-JIS, EUC-JP, UTF, ASCII, or custom .tbl text",
    args: z.object({
      path: z.string().describe("Console ROM or executable path"),
    }),
    options: z.object({
      query: z
        .string()
        .min(1)
        .optional()
        .describe("Text query to encode and search across ROM memory"),
      encoding: z
        .enum(ROM_TEXT_ENCODINGS)
        .default("sjis")
        .describe("Character encoding for query and decoded results"),
      tablePath: z
        .string()
        .min(1)
        .optional()
        .describe("Path to custom .tbl character mapping file"),
      tblPath: z.string().min(1).optional().describe("Alias for --table-path"),
      tableText: z
        .string()
        .min(1)
        .optional()
        .describe("Inline .tbl character mapping rules"),
      tblText: z.string().min(1).optional().describe("Alias for --table-text"),
      startAddress: z
        .string()
        .min(1)
        .optional()
        .describe("Start address (hex) for range scan or bounded query search"),
      startOffset: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Starting ROM file offset in bytes"),
      endOffset: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe("Ending ROM file offset in bytes (exclusive)"),
      length: z
        .number()
        .int()
        .min(1)
        .max(16_777_216)
        .default(4096)
        .describe(
          "Bytes to scan when startAddress/startOffset is used without query",
        ),
      minLength: z
        .number()
        .int()
        .min(1)
        .max(256)
        .default(2)
        .describe("Minimum decoded character count for range scan"),
      terminatorByte: z
        .number()
        .int()
        .min(0)
        .max(255)
        .optional()
        .describe("String terminator byte (0..255, default 0)"),
      maxResults: z
        .number()
        .int()
        .min(1)
        .max(200)
        .default(50)
        .describe("Maximum number of string matches to return"),
      resolveXrefs: z
        .boolean()
        .default(false)
        .describe(
          "Resolve incoming cross-references via the disassembler (opt-in; default false uses the local ROM fast path)",
        ),
      includeXrefs: z
        .boolean()
        .optional()
        .describe("Alias for --resolve-xrefs"),
      includeHex: z
        .boolean()
        .default(false)
        .describe("Include each match's raw bytes as hex (bytes_hex)"),
      cursor: z
        .string()
        .min(1)
        .optional()
        .describe(
          "next_cursor from a previous identical call to resume paging",
        ),
      ...romWordFormatOptions,
      wordParity: z
        .enum(ROM_WORD_PARITIES)
        .default("both")
        .describe("Word alignments a word-encoding range scan examines"),
      fullwidthOnly: z
        .boolean()
        .default(false)
        .describe("Range scan: single-byte characters end a string"),
      minKana: z
        .number()
        .int()
        .min(0)
        .max(256)
        .default(0)
        .describe("Range scan: minimum full-width kana per string"),
      maxLevel2KanjiRatio: z
        .number()
        .min(0)
        .max(1)
        .optional()
        .describe("Range scan: maximum JIS level-2 share of a string's kanji"),
      minTextScore: z
        .number()
        .min(0)
        .max(1)
        .optional()
        .describe("Range scan: minimum heuristic text_score (0..1)"),
      includeScore: z
        .boolean()
        .default(false)
        .describe("Range scan: report text_score on each match"),
      requireTerminator: z
        .boolean()
        .default(false)
        .describe("Range scan: keep only strings ended by their terminator"),
      dedupe: z
        .boolean()
        .default(false)
        .describe(
          "Range scan: one record per distinct byte string with every offset in occurrences",
        ),
      controlCodes: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Path to a JSON array declaring in-string control codes ({hex, name, argument_bytes, role})",
        ),
      controlCodesJson: z
        .string()
        .min(1)
        .optional()
        .describe("Inline JSON array declaring in-string control codes"),
      output: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Write every match as JSON Lines to this file without page or result limits; scans the whole file unless a query, start or end offset selects a range (start..end-offset, or start+length)",
        ),
      overwrite: z
        .boolean()
        .default(false)
        .describe("Replace an existing --output file"),
      ...romOpenOptionFields,
    }),
    run: ({ args, options }) => {
      const resolvedTablePath = options.tablePath ?? options.tblPath;
      const resolvedTableText = options.tableText ?? options.tblText;
      const resolvedXrefs = options.includeXrefs ?? options.resolveXrefs;
      return logCliCommand(logger, CLI_COMMANDS.searchRomStrings, async () => {
        const controlCodes = await readControlCodeDeclarations(
          CLI_COMMANDS.searchRomStrings,
          options,
        );
        return runDirectAnalysis(
          args.path,
          "search_rom_strings",
          {
            ...(options.query === undefined ? {} : { query: options.query }),
            encoding: options.encoding,
            ...(resolvedTablePath === undefined
              ? {}
              : { table_path: resolvedTablePath }),
            ...(resolvedTableText === undefined
              ? {}
              : { table_text: resolvedTableText }),
            ...(options.startAddress === undefined
              ? {}
              : { start_address: options.startAddress }),
            ...(options.startOffset === undefined
              ? {}
              : { start_offset: options.startOffset }),
            ...(options.endOffset === undefined
              ? {}
              : { end_offset: options.endOffset }),
            length: options.length,
            min_length: options.minLength,
            ...(options.terminatorByte === undefined
              ? {}
              : { terminator_byte: options.terminatorByte }),
            max_results: options.maxResults,
            resolve_xrefs: resolvedXrefs,
            include_hex: options.includeHex,
            ...(options.cursor === undefined ? {} : { cursor: options.cursor }),
            ...romWordFormatArguments(options),
            word_parity: options.wordParity,
            fullwidth_only: options.fullwidthOnly,
            min_kana: options.minKana,
            ...(options.maxLevel2KanjiRatio === undefined
              ? {}
              : { max_level2_kanji_ratio: options.maxLevel2KanjiRatio }),
            ...(options.minTextScore === undefined
              ? {}
              : { min_text_score: options.minTextScore }),
            include_score: options.includeScore,
            require_terminator: options.requireTerminator,
            dedupe: options.dedupe,
            ...(controlCodes === undefined
              ? {}
              : { control_codes: controlCodes.map((code) => ({ ...code })) }),
          },
          romAnalysisOptionsFromCli(
            logger,
            options,
            options.output === undefined
              ? undefined
              : { path: options.output, overwrite: options.overwrite },
          ),
        );
      });
    },
  });

  cli.command(CLI_COMMANDS.scanPointerTable, {
    description:
      "Scan a 16/24/32-bit pointer table in console ROM or executable memory with string previews and xrefs",
    args: z.object({
      path: z.string().describe("Console ROM or executable path"),
      address: z
        .string()
        .optional()
        .describe(
          "Pointer table start address (hex); optional if --table-offset is set",
        ),
    }),
    options: z.object({
      tableOffset: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Pointer table starting ROM file offset in bytes"),
      count: z
        .number()
        .int()
        .min(1)
        .max(16_384)
        .default(32)
        .describe("Number of pointer table entries to read"),
      startIndex: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("First entry index to read (paging; indexes stay global)"),
      pointerSize: z
        .number()
        .int()
        .min(2)
        .max(4)
        .default(4)
        .describe("Pointer width in bytes (2, 3, or 4)"),
      endian: z
        .enum(["little", "big"])
        .default("little")
        .describe("Pointer byte order"),
      baseAddress: z
        .string()
        .default("0x0")
        .describe("Base address added to each raw pointer value"),
      stride: z
        .number()
        .int()
        .min(1)
        .max(64)
        .optional()
        .describe("Bytes per table entry (defaults to pointerSize)"),
      encoding: z
        .enum(ROM_TEXT_ENCODINGS)
        .default("sjis")
        .describe("Text encoding used to decode target string previews"),
      tablePath: z
        .string()
        .min(1)
        .optional()
        .describe("Path to custom .tbl character mapping file"),
      tblPath: z.string().min(1).optional().describe("Alias for --table-path"),
      tableText: z
        .string()
        .min(1)
        .optional()
        .describe("Inline .tbl character mapping rules"),
      tblText: z.string().min(1).optional().describe("Alias for --table-text"),
      controlCodes: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Path to a JSON array declaring in-string control codes ({hex, name, argument_bytes, role})",
        ),
      controlCodesJson: z
        .string()
        .min(1)
        .optional()
        .describe("Inline JSON array declaring in-string control codes"),
      terminatorByte: z
        .number()
        .int()
        .min(0)
        .max(255)
        .optional()
        .describe("String terminator byte (0..255, default 0)"),
      previewBytes: z
        .number()
        .int()
        .min(0)
        .max(256)
        .default(64)
        .describe("Bytes to read at each target address for string preview"),
      resolveXrefs: z
        .boolean()
        .default(false)
        .describe(
          "Resolve incoming cross-references via the disassembler (opt-in; default false uses the local ROM fast path)",
        ),
      includeXrefs: z
        .boolean()
        .optional()
        .describe("Alias for --resolve-xrefs"),
      includeManuscript: z
        .boolean()
        .default(false)
        .describe("Emit locbatch.py-compatible manuscript records"),
      includeHex: z
        .boolean()
        .default(false)
        .describe(
          "Include each preview's raw bytes as hex (preview_bytes_hex)",
        ),
      manuscriptOnly: z
        .boolean()
        .default(false)
        .describe(
          "Emit manuscript records and suppress pointer entries (implies --include-manuscript)",
        ),
      includeOrphanStrings: z
        .boolean()
        .default(false)
        .describe(
          "Scan gaps between sorted pointer targets for valid unreferenced strings (e.g. follow-up dialogue pages or inline choice text)",
        ),
      output: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Write every scanned pointer entry (or manuscript record when --include-manuscript/--manuscript-only is set) as JSON Lines to this file",
        ),
      overwrite: z
        .boolean()
        .default(false)
        .describe("Replace an existing --output file"),
      ...pointerSegmentOptions,
      ...romWordFormatOptions,
      ...romOpenOptionFields,
    }),
    run: ({ args, options }) => {
      const resolvedTablePath = options.tablePath ?? options.tblPath;
      const resolvedTableText = options.tableText ?? options.tblText;
      const resolvedXrefs = options.includeXrefs ?? options.resolveXrefs;
      // Declarations are read inside the logged command so a bad file or an
      // ambiguous pair of flags is reported like any other input error.
      return logCliCommand(logger, CLI_COMMANDS.scanPointerTable, async () => {
        const controlCodes = await readControlCodeDeclarations(
          CLI_COMMANDS.scanPointerTable,
          options,
        );
        return runDirectAnalysis(
          args.path,
          "scan_pointer_table",
          {
            ...pointerSegmentArguments("scan_pointer_table", options),
            ...(args.address === undefined ? {} : { address: args.address }),
            ...(options.tableOffset === undefined
              ? {}
              : { table_offset: options.tableOffset }),
            count: options.count,
            start_index: options.startIndex,
            pointer_size: options.pointerSize as 2 | 3 | 4,
            endian: options.endian,
            base_address: options.baseAddress,
            ...(options.stride === undefined ? {} : { stride: options.stride }),
            encoding: options.encoding,
            ...(resolvedTablePath === undefined
              ? {}
              : { table_path: resolvedTablePath }),
            ...(resolvedTableText === undefined
              ? {}
              : { table_text: resolvedTableText }),
            ...(options.terminatorByte === undefined
              ? {}
              : { terminator_byte: options.terminatorByte }),
            preview_bytes: options.previewBytes,
            resolve_xrefs: resolvedXrefs,
            include_manuscript: options.includeManuscript,
            include_hex: options.includeHex,
            manuscript_only: options.manuscriptOnly,
            include_orphan_strings: options.includeOrphanStrings,
            ...(controlCodes === undefined
              ? {}
              : { control_codes: controlCodes.map((code) => ({ ...code })) }),
            ...romWordFormatArguments(options),
          },
          romAnalysisOptionsFromCli(
            logger,
            options,
            options.output === undefined
              ? undefined
              : { path: options.output, overwrite: options.overwrite },
          ),
        );
      });
    },
  });

  cli.command(CLI_COMMANDS.discoverPointerTables, {
    description:
      "Automatically discover candidate string pointer tables in console ROM or executable memory",
    args: z.object({
      path: z.string().describe("Console ROM or executable path"),
    }),
    options: z.object({
      startAddress: z
        .string()
        .min(1)
        .optional()
        .describe("Starting virtual address (hex) to scan"),
      startOffset: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Starting ROM file offset in bytes"),
      endOffset: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe("Ending ROM file offset in bytes (exclusive)"),
      length: z
        .number()
        .int()
        .min(16)
        .max(16_777_216)
        .default(262_144)
        .describe("Maximum byte length to scan when endOffset is omitted"),
      pointerSize: z
        .number()
        .int()
        .min(2)
        .max(4)
        .default(4)
        .describe("Pointer width in bytes (2, 3, or 4)"),
      endian: z
        .enum(["little", "big"])
        .default("little")
        .describe("Pointer byte order"),
      baseAddress: z
        .string()
        .default("0x0")
        .describe("Base address added to each raw pointer value"),
      inferBaseAddress: z
        .boolean()
        .default(false)
        .describe(
          "Automatically infer candidate RAM load base addresses for headerless overlays/binaries from pointer-to-string deltas",
        ),
      inferLoadAddress: z
        .boolean()
        .optional()
        .describe("Alias for --infer-base-address"),
      stride: z
        .number()
        .int()
        .min(1)
        .max(64)
        .optional()
        .describe("Bytes per table entry (defaults to pointerSize)"),
      minEntries: z
        .number()
        .int()
        .min(2)
        .max(256)
        .default(4)
        .describe("Minimum consecutive valid string pointers per table"),
      encoding: z
        .enum(ROM_TEXT_ENCODINGS)
        .default("sjis")
        .describe("Text encoding used to validate target strings"),
      tablePath: z
        .string()
        .min(1)
        .optional()
        .describe("Path to custom .tbl character mapping file"),
      tblPath: z.string().min(1).optional().describe("Alias for --table-path"),
      tableText: z
        .string()
        .min(1)
        .optional()
        .describe("Inline .tbl character mapping rules"),
      tblText: z.string().min(1).optional().describe("Alias for --table-text"),
      terminatorByte: z
        .number()
        .int()
        .min(0)
        .max(255)
        .optional()
        .describe("String terminator byte (0..255, default 0)"),
      minStringLength: z
        .number()
        .int()
        .min(1)
        .max(64)
        .default(2)
        .describe("Minimum decoded characters at pointer target"),
      maxTables: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(20)
        .describe(
          "Maximum number of candidate tables to return (next_start_offset resumes a truncated scan)",
        ),
      sampleEntries: z
        .number()
        .int()
        .min(1)
        .max(16)
        .default(3)
        .describe("Number of sample entries per discovered table"),
      resolveXrefs: z
        .boolean()
        .default(false)
        .describe("Resolve incoming cross-references to table start addresses"),
      includeXrefs: z
        .boolean()
        .optional()
        .describe("Alias for --resolve-xrefs"),
      ...pointerSegmentOptions,
      segmentAlign: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe(
          "Try every multiple of this file offset as the segment start (e.g. 2048 for disc sectors); needs --segment-length",
        ),
      segmentLength: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe(
          "Segment byte length for --segment-align (e.g. 0x10000 for 16-bit offsets)",
        ),
      targetAfterTerminator: z
        .boolean()
        .default(false)
        .describe(
          "Accept only sentence starts as targets: after a terminator byte/word, the segment start, or right where the table ends",
        ),
      minCoverage: z
        .number()
        .min(0)
        .max(1)
        .optional()
        .describe(
          "Keep only tables whose coverage ratio reaches this value (1 = every string start in the region is a target)",
        ),
      ...romWordFormatOptions,
      ...romOpenOptionFields,
    }),
    run: ({ args, options }) => {
      const resolvedTablePath = options.tablePath ?? options.tblPath;
      const resolvedTableText = options.tableText ?? options.tblText;
      const resolvedXrefs = options.includeXrefs ?? options.resolveXrefs;
      const resolvedInferBase =
        options.inferLoadAddress ?? options.inferBaseAddress;
      return logCliCommand(logger, CLI_COMMANDS.discoverPointerTables, () =>
        runDirectAnalysis(
          args.path,
          "discover_pointer_tables",
          {
            ...pointerSegmentArguments("discover_pointer_tables", options),
            target_after_terminator: options.targetAfterTerminator,
            ...(options.minCoverage === undefined
              ? {}
              : { min_coverage: options.minCoverage }),
            ...(options.startAddress === undefined
              ? {}
              : { start_address: options.startAddress }),
            ...(options.startOffset === undefined
              ? {}
              : { start_offset: options.startOffset }),
            ...(options.endOffset === undefined
              ? {}
              : { end_offset: options.endOffset }),
            length: options.length,
            pointer_size: options.pointerSize as 2 | 3 | 4,
            endian: options.endian,
            base_address: options.baseAddress,
            infer_base_address: resolvedInferBase,
            ...(options.stride === undefined ? {} : { stride: options.stride }),
            min_entries: options.minEntries,
            encoding: options.encoding,
            ...(resolvedTablePath === undefined
              ? {}
              : { table_path: resolvedTablePath }),
            ...(resolvedTableText === undefined
              ? {}
              : { table_text: resolvedTableText }),
            ...(options.terminatorByte === undefined
              ? {}
              : { terminator_byte: options.terminatorByte }),
            min_string_length: options.minStringLength,
            max_tables: options.maxTables,
            sample_entries: options.sampleEntries,
            resolve_xrefs: resolvedXrefs,
            ...romWordFormatArguments(options),
          },
          romAnalysisOptionsFromCli(logger, options),
        ),
      );
    },
  });

  cli.command(CLI_COMMANDS.findCodeCaves, {
    description:
      "Find contiguous padding caves (0x00/0xFF) in console ROM or executable segments for font hooks and relocated text",
    args: z.object({
      path: z.string().describe("Console ROM or executable path"),
    }),
    options: z.object({
      minSize: z
        .number()
        .int()
        .min(16)
        .max(1_048_576)
        .default(64)
        .describe("Minimum cave byte length (default 64)"),
      fillByte: z
        .number()
        .int()
        .min(0)
        .max(255)
        .optional()
        .describe(
          "Specific padding byte (e.g. 0 or 255); omit to scan both 0x00 and 0xFF",
        ),
      alignment: z
        .number()
        .int()
        .min(1)
        .max(32)
        .default(4)
        .describe(
          "Cave start alignment boundary (1, 2, 4, 8, 16, or 32; default 4)",
        ),
      startAddress: z
        .string()
        .min(1)
        .optional()
        .describe("Starting virtual address (hex)"),
      startOffset: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Starting ROM file offset in bytes"),
      endOffset: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe("Ending ROM file offset in bytes (exclusive)"),
      length: z
        .number()
        .int()
        .min(16)
        .max(16_777_216)
        .default(262_144)
        .describe("Bytes to scan when reading via provider"),
      executableOnly: z
        .boolean()
        .default(false)
        .describe("Restrict scan to executable mapped segments"),
      maxResults: z
        .number()
        .int()
        .min(1)
        .max(200)
        .default(32)
        .describe("Maximum number of candidate caves to return"),
      resolveXrefs: z
        .boolean()
        .default(false)
        .describe("Check incoming cross-references to cave start addresses"),
      includeXrefs: z
        .boolean()
        .optional()
        .describe("Alias for --resolve-xrefs"),
      ...romOpenOptionFields,
    }),
    run: ({ args, options }) => {
      const resolvedXrefs = options.includeXrefs ?? options.resolveXrefs;
      return logCliCommand(logger, CLI_COMMANDS.findCodeCaves, () =>
        runDirectAnalysis(
          args.path,
          "find_code_caves",
          {
            min_size: options.minSize,
            ...(options.fillByte === undefined
              ? {}
              : { fill_byte: options.fillByte }),
            alignment: options.alignment as 1 | 2 | 4 | 8 | 16 | 32,
            ...(options.startAddress === undefined
              ? {}
              : { start_address: options.startAddress }),
            ...(options.startOffset === undefined
              ? {}
              : { start_offset: options.startOffset }),
            ...(options.endOffset === undefined
              ? {}
              : { end_offset: options.endOffset }),
            length: options.length,
            executable_only: options.executableOnly,
            max_results: options.maxResults,
            resolve_xrefs: resolvedXrefs,
          },
          romAnalysisOptionsFromCli(logger, options),
        ),
      );
    },
  });
};

/** `inspect-disc-image`: cue/gdi/iso/bin data-track layout, boot headers, ISO9660 tree, and free gaps. */
export const registerDiscImageCommand = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectDiscImage, {
    description:
      "Inspect a .cue, .gdi, 2048-byte-sector .iso, or 2352-byte-sector .bin disc image: data-track layout, boot headers (PC Engine IPL, Sega IP.BIN, PlayStation SYSTEM.CNF), ISO9660 directory tree, unallocated gaps, and LBA/offset-to-file resolution",
    args: z.object({
      path: z
        .string()
        .describe(".cue, .gdi, .iso, or raw 2352-byte-sector .bin path"),
    }),
    options: z.object({
      resolveLba: z
        .array(z.coerce.number().int().min(0))
        .optional()
        .describe(
          "Resolve one or more LBAs to their containing ISO9660 file or disc region",
        ),
      resolveOffset: z
        .array(z.coerce.number().int().min(0))
        .optional()
        .describe(
          "Resolve one or more 2048-byte user-data offsets to their containing ISO9660 file or disc region",
        ),
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectDiscImage, async () => {
        const inspected = await inspectDiscImage(args.path, {
          ...(options.resolveLba === undefined
            ? {}
            : { resolveLbas: options.resolveLba }),
          ...(options.resolveOffset === undefined
            ? {}
            : { resolveOffsets: options.resolveOffset }),
        });
        if (!inspected.ok)
          return {
            error: "Analysis failed",
            ...projectAnalysisError(inspected.error),
          };
        return createEvidence(inspected.value.subject, REA_WORKFLOW_PROVIDER, {
          operation: "inspect_disc_image",
          parameters: {
            path: args.path,
            ...(options.resolveLba === undefined
              ? {}
              : { resolve_lba: options.resolveLba }),
            ...(options.resolveOffset === undefined
              ? {}
              : { resolve_offset: options.resolveOffset }),
          },
          result: inspected.value.result,
          confidence: "observed",
          limitations: [
            "Reads cue/gdi FILE/TRACK/INDEX placement and sector headers; EDC/ECC is not verified.",
            "pce_cd_ipl, sega_ip_bin, system_cnf, and iso9660 are populated only when their respective headers or descriptors are present.",
          ],
        });
      }),
  });
};
