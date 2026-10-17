import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  CODE_REFERENCE_LIMITATIONS,
  findCodeReferencesInputSchema,
  findCodeReferencesResultSchema,
  formatAddress32,
  overlappingRegions,
  parseAddress32,
  ROM_CODE_REFERENCE_PROVIDER_IDENTITY,
  scanMipsRegion,
  type CodeReference,
  type CodeReferenceKind,
  type FindCodeReferencesResult,
} from "../../domain/romCodeReferences.js";

const OPERATION = "find_code_references";
const MAX_FILE_BYTES = 256 * 1024 * 1024;
const PSX_HEADER_BYTES = 0x800;

interface LoadedRegion {
  readonly path: string;
  readonly bytes: Uint8Array;
  readonly sha256: string;
  readonly loadAddress: number;
  readonly loadAddressSource: "ps-x-exe-header" | "caller";
  readonly fileOffset: number;
  readonly length: number;
  readonly notes: readonly string[];
}

/** Locate a file's loadable region: PS-X EXE header, or caller load address. */
const locateRegion = (
  path: string,
  bytes: Uint8Array,
  explicit: number | undefined,
): Result<Omit<LoadedRegion, "sha256" | "path" | "bytes">, AnalysisError> => {
  if (explicit !== undefined)
    return ok({
      loadAddress: explicit,
      loadAddressSource: "caller",
      fileOffset: 0,
      length: bytes.length,
      notes: [],
    });
  const magic = Buffer.from(bytes.subarray(0, 8)).toString("latin1");
  if (magic !== "PS-X EXE" || bytes.length < PSX_HEADER_BYTES)
    return err(
      new AnalysisInputError(OPERATION, {
        userMessage: `${path} has no PS-X EXE header; give its load address as files[].load_address (CLI: --file ${path}:0x800D61D8).`,
      }),
    );
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const textAddress = view.getUint32(0x18, true);
  const declared = view.getUint32(0x1c, true);
  const available = bytes.length - PSX_HEADER_BYTES;
  const length = Math.min(declared, available);
  return ok({
    loadAddress: textAddress,
    loadAddressSource: "ps-x-exe-header",
    fileOffset: PSX_HEADER_BYTES,
    length,
    notes:
      declared > available
        ? [
            `${path}: PS-X EXE header declares ${declared} text bytes but only ${available} follow the header; scanned ${available}.`,
          ]
        : [],
  });
};

/** Abort state read through a function so narrowing never outlives an await. */
const isAborted = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;

interface Tally {
  readonly references: CodeReference[];
  readonly perFile: number[];
  readonly counts: {
    total: number;
    call: number;
    jump: number;
    address_pair: number;
    pointer_word: number;
  }[];
  readonly byFile: Map<string, number>[];
  total: number;
}

interface NamedTarget {
  readonly address: number;
  readonly length: number;
  readonly name: string | null;
}

/** Scan every region; counts stay exact while the listed references are capped. */
const tallyReferences = (
  regions: readonly LoadedRegion[],
  targets: readonly NamedTarget[],
  kinds: ReadonlySet<CodeReferenceKind>,
  maxReferences: number,
): Tally => {
  const tally: Tally = {
    references: [],
    perFile: [],
    counts: targets.map(() => ({
      total: 0,
      call: 0,
      jump: 0,
      address_pair: 0,
      pointer_word: 0,
    })),
    byFile: targets.map(() => new Map<string, number>()),
    total: 0,
  };
  for (const region of regions) {
    const found = scanMipsRegion(
      {
        file: region.path,
        bytes: region.bytes,
        fileOffset: region.fileOffset,
        length: region.length,
        address: region.loadAddress,
      },
      targets,
      kinds,
    );
    tally.perFile.push(found.length);
    for (const hit of found) {
      const target = targets[hit.targetIndex];
      const counts = tally.counts[hit.targetIndex];
      const files = tally.byFile[hit.targetIndex];
      if (target === undefined || counts === undefined || files === undefined)
        continue;
      counts.total++;
      counts[hit.kind]++;
      tally.total++;
      files.set(region.path, (files.get(region.path) ?? 0) + 1);
      if (tally.references.length < maxReferences)
        tally.references.push({
          kind: hit.kind,
          file: region.path,
          file_offset: hit.fileOffset,
          address: formatAddress32(hit.address),
          instruction: hit.instruction,
          bytes: hit.bytes,
          register: hit.register,
          target_address: formatAddress32(hit.targetAddress),
          target: formatAddress32(target.address),
          offset_in_target: hit.targetAddress - target.address,
          source_lui_address:
            hit.sourceLuiAddress === null
              ? null
              : formatAddress32(hit.sourceLuiAddress),
        });
    }
  }
  return tally;
};

const buildResult = (
  architecture: "mips-le",
  regions: readonly LoadedRegion[],
  targets: readonly NamedTarget[],
  tally: Tally,
): FindCodeReferencesResult => ({
  architecture,
  files: regions.map((region, index) => ({
    path: region.path,
    sha256: region.sha256,
    size: region.bytes.length,
    load_address: formatAddress32(region.loadAddress),
    load_address_source: region.loadAddressSource,
    scanned_file_offset: region.fileOffset,
    scanned_bytes: region.length,
    region_end_address: formatAddress32(region.loadAddress + region.length),
    references: tally.perFile[index] ?? 0,
  })),
  overlapping_files: overlappingRegions(
    regions.map((region) => ({
      file: region.path,
      address: region.loadAddress,
      length: region.length,
    })),
  ),
  summary: targets.map((target, index) => {
    const counts = tally.counts[index] ?? {
      total: 0,
      call: 0,
      jump: 0,
      address_pair: 0,
      pointer_word: 0,
    };
    return {
      target: formatAddress32(target.address),
      length: target.length,
      name: target.name,
      counts,
      by_file: [...(tally.byFile[index] ?? new Map<string, number>())].map(
        ([file, count]) => ({ file, count }),
      ),
      verdict:
        counts.total === 0
          ? "0 references found in the supplied files (static scan; see limitations)"
          : `${counts.total} references found`,
    };
  }),
  references: tally.references,
  total_references: tally.total,
  truncated: tally.total > tally.references.length,
});

/** Find references to addresses across several MIPS code files. */
export class CodeReferenceService {
  /** Nothing is held between calls. */
  close(): Promise<void> {
    return Promise.resolve();
  }

  async find(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const signal = options?.signal;
    if (isAborted(signal)) return err(new AnalysisCancelledError(OPERATION));
    const parsed = findCodeReferencesInputSchema.safeParse(rawInput);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, parsed.error.issues, rawInput, {
          cause: parsed.error,
        }),
      );
    const input = parsed.data;
    const relative = input.files.find((file) => !isAbsolute(file.path));
    if (relative !== undefined)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["files"],
            reason: "invalid_format",
            message: `Expected an absolute filesystem path, got ${relative.path}.`,
          },
        ]),
      );

    const regions: LoadedRegion[] = [];
    for (const file of input.files) {
      if (isAborted(signal)) return err(new AnalysisCancelledError(OPERATION));
      const loaded = await this.#load(file.path, file.load_address);
      if (!loaded.ok) return loaded;
      regions.push(loaded.value);
    }

    const targets = input.targets.map((target) => ({
      address: parseAddress32(target.address) ?? 0,
      length: target.length,
      name: target.name ?? null,
    }));
    const kinds = new Set<CodeReferenceKind>(
      input.kinds ?? ["call", "jump", "address_pair", "pointer_word"],
    );
    const tally = tallyReferences(
      regions,
      targets,
      kinds,
      input.max_references,
    );
    const result = buildResult(input.architecture, regions, targets, tally);
    const validated = findCodeReferencesResultSchema.parse(result);
    return ok(
      createEvidence(undefined, ROM_CODE_REFERENCE_PROVIDER_IDENTITY, {
        operation: OPERATION,
        parameters: {
          files: input.files.map((file) => ({
            path: file.path,
            load_address: file.load_address ?? null,
          })),
          targets: input.targets.map((target) => ({
            address: target.address,
            length: target.length,
            name: target.name ?? null,
          })),
          architecture: input.architecture,
          kinds: [...kinds],
          max_references: input.max_references,
        },
        result: jsonValueSchema.parse(validated),
        confidence: "derived",
        subjectUnavailableReason: `Evidence covers ${regions.length} file(s); each file's SHA-256 is in result.files.`,
        locations: regions.map((region) => ({
          kind: "artifact-path" as const,
          path: region.path,
        })),
        limitations: [
          ...CODE_REFERENCE_LIMITATIONS,
          ...regions.flatMap((region) => region.notes),
        ],
      }),
    );
  }

  async #load(
    path: string,
    loadAddress: string | undefined,
  ): Promise<Result<LoadedRegion, AnalysisError>> {
    let bytes: Uint8Array;
    try {
      const info = await stat(path);
      if (!info.isFile() || info.size > MAX_FILE_BYTES)
        return err(
          new AnalysisInputError(OPERATION, {
            userMessage: `${path} is not a regular file of at most ${MAX_FILE_BYTES} bytes.`,
          }),
        );
      bytes = await readFile(path);
    } catch (cause) {
      return err(
        new AnalysisInputError(OPERATION, {
          userMessage: `Cannot read ${path}.`,
          cause,
        }),
      );
    }
    const located = locateRegion(
      path,
      bytes,
      loadAddress === undefined ? undefined : parseAddress32(loadAddress),
    );
    if (!located.ok) return located;
    return ok({
      path,
      bytes,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      ...located.value,
    });
  }
}
