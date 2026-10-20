import { createHash, randomUUID } from "node:crypto";
import { link, open, rename, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import type { AnalysisOperationPort } from "../AnalysisProvider.js";
import { parseBinaryTarget } from "../BinaryTargetResolver.js";
import { enhancedInputSchemas } from "../../contracts/enhancedInputs.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  isConsoleBinaryTarget,
  type BinaryArchitecture,
  type BinaryTarget,
} from "../../domain/binaryTargetTypes.js";
import { BinaryTargetError } from "../../domain/configurationErrors.js";
import type { ExecutableFormatHint } from "../../domain/dosCom.js";
import type { EvidenceSubjectTarget } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  localByteSourceSubject,
  openLocalByteSource,
  type LocalByteSource,
} from "./LocalByteSource.js";
import {
  executeDiscoverPointerTables,
  executeFindCodeCaves,
  executeScanPointerTable,
  executeSearchRomStrings,
  exportScanPointerTable,
  exportSearchRomStrings,
} from "./RomHackingTools.js";
import type { LocalRomToolName } from "./LocalRomToolNames.js";

/** Where JSON Lines records of a file export go. */
export interface RomStringExportTarget {
  readonly path: string;
  readonly overwrite: boolean;
}

/** A completed local run: the subject it read, its result, and its limits. */
export interface LocalRomRun {
  readonly subject: BinaryTarget | EvidenceSubjectTarget;
  readonly result: JsonValue;
  readonly limitations: readonly string[];
}

const providerFree: AnalysisOperationPort = {
  execute: (operation) =>
    Promise.resolve(
      err(
        new AnalysisInputError(operation, {
          userMessage:
            "Provider operation is unavailable during local ROM fast-path execution.",
        }),
      ),
    ),
};

const executeOnLocalTarget = async (
  tool: LocalRomToolName,
  arguments_: Readonly<Record<string, JsonValue>>,
  target: BinaryTarget | LocalByteSource,
  signal: AbortSignal,
): Promise<Result<JsonValue, AnalysisError>> => {
  switch (tool) {
    case "search_rom_strings": {
      const parsed =
        enhancedInputSchemas.search_rom_strings.safeParse(arguments_);
      if (!parsed.success) return invalidInput(tool, parsed.error);
      return executeSearchRomStrings(providerFree, parsed.data, signal, target);
    }
    case "scan_pointer_table": {
      const parsed =
        enhancedInputSchemas.scan_pointer_table.safeParse(arguments_);
      if (!parsed.success) return invalidInput(tool, parsed.error);
      return executeScanPointerTable(providerFree, parsed.data, signal, target);
    }
    case "discover_pointer_tables": {
      const parsed =
        enhancedInputSchemas.discover_pointer_tables.safeParse(arguments_);
      if (!parsed.success) return invalidInput(tool, parsed.error);
      return executeDiscoverPointerTables(
        providerFree,
        parsed.data,
        signal,
        target,
      );
    }
    case "find_code_caves": {
      const parsed = enhancedInputSchemas.find_code_caves.safeParse(arguments_);
      if (!parsed.success) return invalidInput(tool, parsed.error);
      return executeFindCodeCaves(providerFree, parsed.data, signal, target);
    }
  }
};

const invalidInput = (
  tool: string,
  error: { readonly message: string },
): Result<never, AnalysisError> =>
  err(new AnalysisInputError(tool, { userMessage: error.message }));

const LOCAL_BYTES_LIMITATION =
  "Read as plain local bytes (no executable or console admission): addresses are file offsets and no disassembler was used.";
const UNRECOGNIZED_FORMAT_LIMITATION =
  "The file format was not recognized, so it was read as plain local bytes; pass --target-format to choose an interpretation.";
const ROM_FAST_PATH_LIMITATION =
  "Executed directly on local ROM bytes with resolve_xrefs=false (disassembler session skipped).";

/**
 * Run a ROM text tool on local bytes. Returns undefined when the target needs
 * a provider session instead (an admitted target that is not a ROM or raw
 * binary). `localBytes` reads the file as plain bytes without admission; an
 * unrecognized format falls back to that mode unless a format was chosen.
 */
export const runLocalRomTool = async (input: {
  readonly path: string;
  readonly tool: LocalRomToolName;
  readonly arguments: Readonly<Record<string, JsonValue>>;
  readonly signal: AbortSignal;
  readonly localBytes: boolean;
  readonly formatHint?: ExecutableFormatHint | undefined;
  readonly architecture?: BinaryArchitecture | undefined;
  readonly entryPoint?: string | undefined;
  readonly loadAddress?: string | undefined;
  readonly exportTo?: RomStringExportTarget | undefined;
}): Promise<Result<LocalRomRun, AnalysisError> | undefined> => {
  let target: BinaryTarget | LocalByteSource;
  const limitations: string[] = [];
  if (input.localBytes) {
    const source = await openLocalByteSource(
      input.tool,
      input.path,
      "requested",
    );
    if (!source.ok) return source;
    target = source.value;
    limitations.push(LOCAL_BYTES_LIMITATION);
  } else {
    const parsed = await parseBinaryTarget(input.path, {
      signal: input.signal,
      ...(input.formatHint === undefined
        ? {}
        : { formatHint: input.formatHint }),
      ...(input.architecture === undefined
        ? {}
        : { architecture: input.architecture }),
      ...(input.entryPoint === undefined
        ? {}
        : { entryPoint: input.entryPoint }),
      ...(input.loadAddress === undefined
        ? {}
        : { loadAddress: input.loadAddress }),
    });
    if (parsed.ok) {
      if (
        parsed.value.kind !== "executable" ||
        (!isConsoleBinaryTarget(parsed.value) &&
          parsed.value.format !== "raw-binary")
      )
        return input.exportTo === undefined
          ? undefined
          : err(
              new AnalysisInputError(input.tool, {
                userMessage:
                  "File export needs a console ROM, raw binary, or data file (--target-format data).",
              }),
            );
      target = parsed.value;
      limitations.push(ROM_FAST_PATH_LIMITATION);
      if (
        isConsoleBinaryTarget(parsed.value) &&
        parsed.value.consoleRom.fileByteSwap !== undefined
      ) {
        limitations.push(
          "Byteswapped or little-endian dump normalized to native big-endian bytes for scanning; reported file offsets and digests identify the original dump.",
        );
      }
    } else if (
      input.formatHint === undefined &&
      parsed.error instanceof BinaryTargetError &&
      parsed.error.constraint === "file_format_rejected"
    ) {
      const source = await openLocalByteSource(
        input.tool,
        input.path,
        "format_not_recognized",
      );
      if (!source.ok) return source;
      target = source.value;
      limitations.push(UNRECOGNIZED_FORMAT_LIMITATION, LOCAL_BYTES_LIMITATION);
    } else {
      return parsed;
    }
  }
  const subject =
    target.kind === "local-bytes" ? localByteSourceSubject(target) : target;

  if (input.exportTo !== undefined) {
    const exportTarget = target;
    if (input.tool === "search_rom_strings") {
      const parsed = enhancedInputSchemas.search_rom_strings.safeParse(
        input.arguments,
      );
      if (!parsed.success) return invalidInput(input.tool, parsed.error);
      const written = await writeJsonLinesFile(input.exportTo, (write) =>
        exportSearchRomStrings(parsed.data, exportTarget, write, input.signal),
      );
      if (!written.ok) return written;
      return ok({
        subject,
        result: { ...written.value.summary, output: written.value.output },
        limitations,
      });
    }
    if (input.tool === "scan_pointer_table") {
      const parsed = enhancedInputSchemas.scan_pointer_table.safeParse(
        input.arguments,
      );
      if (!parsed.success) return invalidInput(input.tool, parsed.error);
      const written = await writeJsonLinesFile(input.exportTo, (write) =>
        exportScanPointerTable(parsed.data, exportTarget, write, input.signal),
      );
      if (!written.ok) return written;
      return ok({
        subject,
        result: { ...written.value.summary, output: written.value.output },
        limitations,
      });
    }
    return err(
      new AnalysisInputError(input.tool, {
        userMessage:
          "File export is available for search_rom_strings and scan_pointer_table only.",
      }),
    );
  }

  const result = await executeOnLocalTarget(
    input.tool,
    input.arguments,
    target,
    input.signal,
  );
  return result.ok
    ? ok({ subject, result: result.value, limitations })
    : result;
};

/** Facts about the JSON Lines file a run wrote. */
export type JsonLinesFileOutput = {
  readonly path: string;
  readonly format: "jsonl";
  readonly records: number;
  readonly bytes: number;
  readonly sha256: string;
};

const FLUSH_BYTES = 1 << 16;

/**
 * Write records as JSON Lines to a staged file beside `target.path`, then
 * publish it: rename when overwriting, otherwise a hard link that fails if the
 * path already exists. The staged file is removed on any failure.
 */
const writeJsonLinesFile = async <
  Summary extends Readonly<Record<string, JsonValue>>,
>(
  target: RomStringExportTarget,
  produce: (
    write: (record: Readonly<Record<string, JsonValue>>) => Promise<void>,
  ) => Promise<Result<Summary, AnalysisError>>,
): Promise<
  Result<
    { readonly summary: Summary; readonly output: JsonLinesFileOutput },
    AnalysisError
  >
> => {
  const operation = "search_rom_strings";
  const finalPath = isAbsolute(target.path)
    ? target.path
    : resolve(target.path);
  const stagedPath = join(
    dirname(finalPath),
    `.${basename(finalPath)}.${randomUUID()}.tmp`,
  );
  const failure = (userMessage: string, cause?: unknown) =>
    err(
      new AnalysisInputError(operation, {
        userMessage,
        ...(cause === undefined ? {} : { cause }),
      }),
    );
  let file: FileHandle;
  try {
    file = await open(stagedPath, "wx");
  } catch (cause) {
    return failure(`Cannot create output beside ${finalPath}`, cause);
  }
  let fileOpen = true;
  const hash = createHash("sha256");
  let pending: string[] = [];
  let pendingBytes = 0;
  let bytes = 0;
  let records = 0;
  const flush = async (): Promise<void> => {
    if (pending.length === 0) return;
    const chunk = Buffer.from(pending.join(""), "utf8");
    pending = [];
    pendingBytes = 0;
    hash.update(chunk);
    bytes += chunk.length;
    await file.write(chunk);
  };
  let published = false;
  try {
    const produced = await produce(async (record) => {
      const line = `${JSON.stringify(record)}\n`;
      pending.push(line);
      pendingBytes += line.length;
      records++;
      if (pendingBytes >= FLUSH_BYTES) await flush();
    });
    if (!produced.ok) return produced;
    await flush();
    await file.sync();
    fileOpen = false;
    await file.close();
    if (target.overwrite) {
      await rename(stagedPath, finalPath);
    } else {
      try {
        await link(stagedPath, finalPath);
      } catch (cause) {
        return failure(
          `${finalPath} already exists or cannot be created; pass --overwrite to replace it`,
          cause,
        );
      }
      await unlink(stagedPath);
    }
    published = true;
    return ok({
      summary: produced.value,
      output: {
        path: finalPath,
        format: "jsonl",
        records,
        bytes,
        sha256: hash.digest("hex"),
      },
    });
  } catch (cause) {
    return failure(`Failed to write ${finalPath}`, cause);
  } finally {
    if (fileOpen) await file.close().catch(() => undefined);
    if (!published) await unlink(stagedPath).catch(() => undefined);
  }
};
