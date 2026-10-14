import { z } from "incur";

import type { DirectAnalysis } from "../composition/directAnalysis.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import {
  directAnalysisOptionsFromCli,
  nativeOpenOptionFields,
} from "./options.js";
import type { CliInstance } from "./types.js";

/** Register native load-image, memory, and annotation CLI commands. */
export const registerCoreNativeCommands = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  registerAnnotationCommand(cli, logger, runDirectAnalysis);
  cli.command(CLI_COMMANDS.searchBytes, {
    description: "Find masked byte patterns in initialized provider memory",
    args: z.object({
      path: z.string().describe("Local executable path"),
      pattern: z.string().describe("Hexadecimal byte pairs with ?? wildcards"),
    }),
    options: z.object({
      mask: z.string().optional().describe("Equal-length hexadecimal bit mask"),
      start: z.string().optional().describe("Inclusive start address"),
      end: z.string().optional().describe("Inclusive end address"),
      cursor: z
        .string()
        .optional()
        .describe("Continuation from the same query's next_cursor"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(100)
        .describe("Maximum matches on this page"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.searchBytes, () =>
        runDirectAnalysis(
          args.path,
          "search_bytes",
          {
            pattern: args.pattern,
            limit: options.limit,
            ...(options.mask === undefined ? {} : { mask: options.mask }),
            ...(options.start === undefined ? {} : { start: options.start }),
            ...(options.end === undefined ? {} : { end: options.end }),
            ...(options.cursor === undefined ? {} : { cursor: options.cursor }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.inspectNativeLoadImage, {
    description:
      "Verify loaded native bytes, source mappings, relocations and entry",
    args: z.object({ path: z.string().describe("Local executable path") }),
    options: z.object({
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectNativeLoadImage, () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_load_image",
          {},
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.readBytes, {
    description: "Read exact provider memory bytes at one analysis address",
    args: z.object({
      path: z.string().describe("Local executable path"),
      address: z.string().describe("Exact provider memory address"),
    }),
    options: z.object({
      length: z
        .number()
        .int()
        .min(1)
        .default(256)
        .describe("Requested byte count"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.readBytes, () =>
        runDirectAnalysis(
          args.path,
          "read_bytes",
          { address: args.address, length: options.length },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.addressToFileOffset, {
    description: "Resolve an analysis address to its original file byte offset",
    args: z.object({
      path: z.string().describe("Local executable path"),
      address: z.string().describe("Exact provider memory address"),
    }),
    options: z.object({
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.addressToFileOffset, () =>
        runDirectAnalysis(
          args.path,
          "address_to_file_offset",
          { address: args.address },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.traceNativeValues, {
    description: "Trace bounded native def-use and call dependencies",
    args: z.object({
      path: z.string().describe("Local native executable or app path"),
      procedure: z
        .string()
        .describe("Explicit native procedure symbol or address"),
    }),
    options: z.object({
      maxDepth: z
        .number()
        .int()
        .min(0)
        .max(16)
        .default(3)
        .describe("Maximum call traversal depth"),
      maxFunctions: z
        .number()
        .int()
        .min(1)
        .max(64)
        .default(16)
        .describe("Maximum function decompilations"),
      maxCallSites: z
        .number()
        .int()
        .min(1)
        .max(4096)
        .default(256)
        .describe("Maximum static call-site resolutions"),
      maxNodes: z
        .number()
        .int()
        .min(1)
        .max(20000)
        .default(5000)
        .describe("Maximum retained graph nodes"),
      maxEdges: z
        .number()
        .int()
        .min(1)
        .max(40000)
        .default(10000)
        .describe("Maximum retained graph edges"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("First graph node index"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(5000)
        .default(1000)
        .describe("Maximum nodes on this page"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.traceNativeValues, () =>
        runDirectAnalysis(
          args.path,
          "trace_native_values",
          {
            procedure: args.procedure,
            max_depth: options.maxDepth,
            max_functions: options.maxFunctions,
            max_call_sites: options.maxCallSites,
            max_nodes: options.maxNodes,
            max_edges: options.maxEdges,
            offset: options.offset,
            limit: options.limit,
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.inspectNativeDataType, {
    description: "Inspect one recovered database type or typed data object",
    args: z.object({
      path: z.string().describe("Local native executable or app path"),
    }),
    options: z.object({
      type: z.string().optional().describe("Exact database type category path"),
      address: z.string().optional().describe("Exact native address"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectNativeDataType, () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_data_type",
          {
            ...(options.type === undefined ? {} : { type: options.type }),
            ...(options.address === undefined
              ? {}
              : { address: options.address }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
  for (const [command, operation] of [
    [CLI_COMMANDS.inspectNativeInstruction, "inspect_native_instruction"],
    [CLI_COMMANDS.resolveNativeCallTargets, "resolve_native_call_targets"],
  ] as const) {
    cli.command(command, {
      description:
        operation === "inspect_native_instruction"
          ? "Inspect one native instruction with decoded operand facts"
          : "Resolve one static native call site",
      args: z.object({
        path: z.string().describe("Local native executable or app path"),
        address: z.string().describe("Exact native address"),
      }),
      options: z.object({
        ...nativeOpenOptionFields,
      }),
      run: ({ args, options }) =>
        logCliCommand(logger, command, () =>
          runDirectAnalysis(
            args.path,
            operation,
            { address: args.address },
            directAnalysisOptionsFromCli(logger, options),
          ),
        ),
    });
  }
  registerNativeApiCommand(cli, logger, runDirectAnalysis);
  registerNativeUiActionCommand(cli, logger, runDirectAnalysis);
  registerNativeDispatchMetadataCommand(cli, logger, runDirectAnalysis);
  registerRomHackingCommands(cli, logger, runDirectAnalysis);
};

import { ROM_TEXT_ENCODINGS } from "../domain/romHacking.js";

const registerRomHackingCommands = (
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
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) => {
      const resolvedTablePath = options.tablePath ?? options.tblPath;
      const resolvedTableText = options.tableText ?? options.tblText;
      const resolvedXrefs = options.includeXrefs ?? options.resolveXrefs;
      return logCliCommand(logger, CLI_COMMANDS.searchRomStrings, () =>
        runDirectAnalysis(
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
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      );
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
        .max(512)
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
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) => {
      const resolvedTablePath = options.tablePath ?? options.tblPath;
      const resolvedTableText = options.tableText ?? options.tblText;
      const resolvedXrefs = options.includeXrefs ?? options.resolveXrefs;
      return logCliCommand(logger, CLI_COMMANDS.scanPointerTable, () =>
        runDirectAnalysis(
          args.path,
          "scan_pointer_table",
          {
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
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      );
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
        .max(100)
        .default(20)
        .describe("Maximum number of candidate tables to return"),
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
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) => {
      const resolvedTablePath = options.tablePath ?? options.tblPath;
      const resolvedTableText = options.tableText ?? options.tblText;
      const resolvedXrefs = options.includeXrefs ?? options.resolveXrefs;
      return logCliCommand(logger, CLI_COMMANDS.discoverPointerTables, () =>
        runDirectAnalysis(
          args.path,
          "discover_pointer_tables",
          {
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
          },
          directAnalysisOptionsFromCli(logger, options),
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
      ...nativeOpenOptionFields,
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
          directAnalysisOptionsFromCli(logger, options),
        ),
      );
    },
  });
};

const registerNativeDispatchMetadataCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectNativeDispatchMetadata, {
    description: "Inspect typed Objective-C and Swift dispatch metadata",
    args: z.object({
      path: z.string().describe("Target path used to bind the result evidence"),
    }),
    options: z.object({
      maxRecords: z
        .number()
        .int()
        .min(1)
        .max(20_000)
        .default(5_000)
        .describe("Maximum symbol records to inspect"),
      snapshot: z
        .string()
        .min(1)
        .optional()
        .describe("Load or update the local analysis snapshot"),
      ...nativeOpenOptionFields,
    }),
    run: async ({ args, options }) =>
      logCliCommand(logger, "inspect-native-dispatch-metadata", () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_dispatch_metadata",
          { max_records: options.maxRecords },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerNativeUiActionCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.traceNativeUiAction, {
    description:
      "Trace a compiled UI action selector to its native handler and direct callees",
    args: z.object({
      path: z.string().describe("Target path used to bind the result evidence"),
      action: z
        .string()
        .min(1)
        .describe(
          "A unique compiled UI action selector or interface object ID",
        ),
    }),
    options: z.object({
      maxDepth: z
        .number()
        .int()
        .min(0)
        .max(32)
        .default(8)
        .describe("Maximum relationship depth"),
      maxNodes: z
        .number()
        .int()
        .min(1)
        .max(2_000)
        .default(250)
        .describe("Maximum returned graph nodes"),
      maxEdges: z
        .number()
        .int()
        .min(1)
        .max(5_000)
        .default(500)
        .describe("Maximum returned graph edges"),
      ...nativeOpenOptionFields,
    }),
    run: async ({ args, options }) =>
      logCliCommand(logger, "trace-native-ui-action", () =>
        runDirectAnalysis(
          args.path,
          "trace_native_ui_action",
          {
            action: args.action,
            max_depth: options.maxDepth,
            max_nodes: options.maxNodes,
            max_edges: options.maxEdges,
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerNativeApiCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.inspectNativeApi, {
    description: "Reconstruct one native function API boundary with evidence",
    args: z.object({
      path: z.string().describe("App or program path"),
      address: z.string().describe("Procedure name or address"),
    }),
    options: z.object({
      snapshot: z
        .string()
        .min(1)
        .optional()
        .describe("Load and update a local analysis snapshot"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, "inspect-native-api", () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_api",
          { procedure: args.address },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};

const registerAnnotationCommand = (
  cli: CliInstance,
  logger: Logger,
  runDirectAnalysis: DirectAnalysis["runDirectAnalysis"],
): void => {
  cli.command(CLI_COMMANDS.annotateNativeFunction, {
    description: "Edit function annotations and return refreshed analysis",
    args: z.object({
      path: z.string().describe("Local executable path"),
      procedure: z
        .string()
        .describe("Exact function entry address or unique name"),
    }),
    options: z.object({
      name: z.string().min(1).optional().describe("Analyst function name"),
      comment: z
        .string()
        .optional()
        .describe("Regular entry comment; empty text clears it"),
      "inline-comment": z
        .string()
        .optional()
        .describe("Inline entry comment; empty text clears it"),
      ...nativeOpenOptionFields,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.annotateNativeFunction, () =>
        runDirectAnalysis(
          args.path,
          "annotate_native_function",
          {
            procedure: args.procedure,
            ...(options.name === undefined ? {} : { name: options.name }),
            ...(options.comment === undefined
              ? {}
              : { comment: options.comment }),
            ...(options["inline-comment"] === undefined
              ? {}
              : { inline_comment: options["inline-comment"] }),
          },
          directAnalysisOptionsFromCli(logger, options),
        ),
      ),
  });
};
