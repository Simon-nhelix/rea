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
import { jsonValueSchema, type JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  findCodeReferencesInputSchema,
  findCodeReferencesResultSchema,
  formatAddress32,
  parseAddress32,
  ROM_CODE_REFERENCE_PROVIDER_IDENTITY,
  scanCodeRegion,
  type CodeReference,
  type CodeReferenceArchitecture,
  type CodeReferenceKind,
  type FindCodeReferencesInput,
  type FindCodeReferencesResult,
  type LoadAddressSource,
} from "../../domain/romCodeReferences.js";
import { codeReferenceLimitations } from "../../domain/romCodeReferenceLimitations.js";
import { overlappingRegions } from "../../domain/romCodeReferenceRegions.js";
import { findGpInitializer } from "../../domain/romGpInitializer.js";
import { admitConsoleTarget } from "../../domain/consoleRom.js";

const OPERATION = "find_code_references";
const MAX_FILE_BYTES = 256 * 1024 * 1024;
const PSX_HEADER_BYTES = 0x800;

interface LoadedRegion {
  readonly path: string;
  readonly bytes: Uint8Array;
  readonly sha256: string;
  readonly loadAddress: number;
  readonly loadAddressSource: LoadAddressSource;
  readonly fileOffset: number;
  readonly length: number;
  readonly notes: readonly string[];
  readonly useGp: boolean;
}

type RegionCoordinate = Omit<
  LoadedRegion,
  "sha256" | "path" | "bytes" | "useGp"
>;

/** Locate all loadable regions of a file: PS-X EXE, multi-PT_LOAD ELF32, MWo3, console headers, or caller load address. */
const locateRegions = (
  path: string,
  bytes: Uint8Array,
  explicit: number | undefined,
  architecture: CodeReferenceArchitecture,
): Result<readonly RegionCoordinate[], AnalysisError> => {
  if (explicit !== undefined)
    return ok([
      {
        loadAddress: explicit,
        loadAddressSource: "caller",
        fileOffset: 0,
        length: bytes.length,
        notes: [],
      },
    ]);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = Buffer.from(bytes.subarray(0, 8)).toString("latin1");
  if (magic === "PS-X EXE" && bytes.length >= PSX_HEADER_BYTES) {
    const textAddress = view.getUint32(0x18, true);
    const declared = view.getUint32(0x1c, true);
    const available = bytes.length - PSX_HEADER_BYTES;
    const length = Math.min(declared, available);
    return ok([
      {
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
      },
    ]);
  }
  // 32-bit ELF (MIPS, SuperH, or ARM): collect ALL PT_LOAD segments with p_filesz > 0
  if (
    bytes.length >= 0x34 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46 &&
    bytes[4] === 1 &&
    (bytes[5] === 1 || bytes[5] === 2)
  ) {
    const little = bytes[5] === 1;
    const phOff = view.getUint32(0x1c, little);
    const phEntSize = view.getUint16(0x2a, little);
    const phNum = view.getUint16(0x2c, little);
    const segments: RegionCoordinate[] = [];
    if (phOff > 0 && phEntSize >= 32 && phNum > 0 && phNum <= 1024) {
      for (let i = 0; i < phNum; i++) {
        const off = phOff + i * phEntSize;
        if (off + 32 > bytes.length) break;
        const pType = view.getUint32(off, little);
        if (pType !== 1) continue; // PT_LOAD
        const pOffset = view.getUint32(off + 0x04, little);
        const pVaddr = view.getUint32(off + 0x08, little);
        const pFilesz = view.getUint32(off + 0x10, little);
        if (pFilesz === 0 || pOffset >= bytes.length) continue;
        const available = bytes.length - pOffset;
        const length = Math.min(pFilesz, available);
        segments.push({
          loadAddress: pVaddr,
          loadAddressSource: "elf32-le-header",
          fileOffset: pOffset,
          length,
          notes:
            pFilesz > available
              ? [
                  `${path}: ELF PT_LOAD declares ${pFilesz} bytes at 0x${pOffset.toString(16)} but only ${available} are available; scanned ${available}.`,
                ]
              : [],
        });
      }
    }
    if (segments.length > 0) return ok(segments);
  }
  // CodeWarrior PS2 'MWo3' overlay (0x40-byte header placed at base loadAddress)
  if (
    bytes.length >= 0x40 &&
    bytes[0] === 0x4d &&
    bytes[1] === 0x57 &&
    bytes[2] === 0x6f &&
    bytes[3] === 0x33
  ) {
    const baseAddress = view.getUint32(0x08, true);
    const textSize = view.getUint32(0x0c, true);
    const dataSize = view.getUint32(0x10, true);
    const declared = textSize + dataSize;
    const available = bytes.length - 0x40;
    const length = Math.min(declared, available);
    return ok([
      {
        loadAddress: (baseAddress + 0x40) >>> 0,
        loadAddressSource: "mwo3-header",
        fileOffset: 0x40,
        length,
        notes:
          declared > available
            ? [
                `${path}: MWo3 header declares ${declared} payload bytes but only ${available} follow the 0x40-byte header; scanned ${available}.`,
              ]
            : [],
      },
    ]);
  }
  // Sega Saturn IP.BIN ("SEGA SEGASATURN ")
  if (
    bytes.length >= 0x100 &&
    Buffer.from(bytes.subarray(0, 16)).toString("latin1") === "SEGA SEGASATURN "
  ) {
    return ok([
      {
        loadAddress: 0x06002000,
        loadAddressSource: "sega-ip-header",
        fileOffset: 0,
        length: bytes.length,
        notes: [],
      },
    ]);
  }
  // NES iNES header ("NES\x1a")
  if (
    bytes.length > 16 &&
    bytes[0] === 0x4e &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x53 &&
    bytes[3] === 0x1a
  ) {
    const admitted = admitConsoleTarget({
      format: "nes",
      headerBytes: Buffer.from(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      ),
      fileBytes: bytes.length,
    });
    if (!admitted.ok)
      return err(
        new AnalysisInputError(OPERATION, {
          userMessage: admitted.error.reason,
        }),
      );
    return ok(
      admitted.value.fileMappings
        .filter((mapping) => mapping.executable)
        .map((mapping) => ({
          loadAddress: Number(BigInt(mapping.virtualAddress)),
          loadAddressSource: "ines-header" as const,
          fileOffset: mapping.fileOffset,
          length: mapping.byteLength,
          notes: [
            `${path}: NES scan uses admitted PRG bank windows and mirrors; runtime mapper changes and unmapped banks are not resolved.`,
          ],
        })),
    );
  }
  // GBA ROM (0x08000000) when arm-le / thumb-le or .gba
  if (
    (architecture === "arm-le" ||
      architecture === "thumb-le" ||
      path.toLowerCase().endsWith(".gba")) &&
    bytes.length >= 0xc0 &&
    bytes[0xb2] === 0x96
  ) {
    return ok([
      {
        loadAddress: 0x08000000,
        loadAddressSource: "gba-rom-header",
        fileOffset: 0,
        length: bytes.length,
        notes: [],
      },
    ]);
  }
  return err(
    new AnalysisInputError(OPERATION, {
      userMessage: `${path} has no PS-X EXE, ELF32-LE, or MWo3 header; give its load address as files[].load_address (CLI: --file ${path}:0x800D61D8).`,
    }),
  );
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
    gp_relative: number;
  }[];
  readonly byFile: Map<string, number>[];
  total: number;
}

interface GpResolution {
  readonly value: number | undefined;
  readonly source: "caller" | "auto" | null;
  readonly file: string | null;
  readonly address?: number;
  readonly fileOffset?: number;
}

/** The caller's $gp, else the first lui/addiu $gp initializer in the files. */
const resolveGp = (
  explicit: string | undefined,
  enabled: boolean,
  architecture: CodeReferenceArchitecture,
  regions: readonly LoadedRegion[],
): GpResolution => {
  if (!enabled || architecture !== "mips-le")
    return { value: undefined, source: null, file: null };
  const given = explicit === undefined ? undefined : parseAddress32(explicit);
  if (given !== undefined)
    return { value: given, source: "caller", file: null };
  for (const region of regions) {
    if (!region.useGp) continue;
    const found = findGpInitializer({
      bytes: region.bytes,
      fileOffset: region.fileOffset,
      length: region.length,
      address: region.loadAddress,
    });
    if (found !== undefined)
      return {
        value: found.value,
        source: "auto",
        file: region.path,
        address: found.address,
        fileOffset: found.fileOffset,
      };
  }
  return { value: undefined, source: null, file: null };
};

interface NamedTarget {
  readonly address: number;
  readonly length: number;
  readonly name: string | null;
}

/** Scan every region; counts stay exact while the listed references are capped. */
const tallyReferences = (
  regions: readonly LoadedRegion[],
  targets: readonly NamedTarget[],
  options: {
    readonly architecture: CodeReferenceArchitecture;
    readonly kinds: ReadonlySet<CodeReferenceKind>;
    readonly maxReferences: number;
    readonly gp: number | undefined;
    readonly resolveCallArguments: boolean;
    readonly includeCallerSignatures: boolean;
  },
): Tally => {
  const {
    architecture,
    kinds,
    maxReferences,
    gp,
    resolveCallArguments,
    includeCallerSignatures,
  } = options;
  const tally: Tally = {
    references: [],
    perFile: [],
    counts: targets.map(() => ({
      total: 0,
      call: 0,
      jump: 0,
      address_pair: 0,
      pointer_word: 0,
      gp_relative: 0,
    })),
    byFile: targets.map(() => new Map<string, number>()),
    total: 0,
  };
  for (const region of regions) {
    const found = scanCodeRegion(
      architecture,
      {
        file: region.path,
        bytes: region.bytes,
        fileOffset: region.fileOffset,
        length: region.length,
        address: region.loadAddress,
        gp: region.useGp ? gp : undefined,
      },
      targets,
      kinds,
      { resolveCallArguments, includeCallerSignatures },
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
          ...(hit.callArguments === undefined
            ? {}
            : { call_arguments: hit.callArguments }),
          ...(hit.callerSignature === undefined
            ? {}
            : { caller_signature: hit.callerSignature }),
        });
    }
  }
  return tally;
};

const evidenceParameters = (
  input: FindCodeReferencesInput,
  kinds: ReadonlySet<CodeReferenceKind>,
): Record<string, JsonValue> => ({
  files: input.files.map((file) => ({
    path: file.path,
    load_address: file.load_address ?? null,
    use_gp: file.use_gp,
  })),
  targets: input.targets.map((target) => ({
    address: target.address,
    length: target.length,
    name: target.name ?? null,
  })),
  architecture: input.architecture,
  gp: input.gp ?? null,
  gp_relative: input.gp_relative,
  resolve_call_arguments: input.resolve_call_arguments,
  include_caller_signatures: input.include_caller_signatures,
  kinds: [...kinds],
  max_references: input.max_references,
});

const gpReport = (gp: GpResolution) => ({
  value: gp.value === undefined ? null : formatAddress32(gp.value),
  source: gp.source,
  file: gp.file,
  address: gp.address === undefined ? null : formatAddress32(gp.address),
  file_offset: gp.fileOffset ?? null,
});

const buildResult = (
  regions: readonly LoadedRegion[],
  targets: readonly NamedTarget[],
  tally: Tally,
  header: {
    readonly architecture: CodeReferenceArchitecture;
    readonly gp: GpResolution;
  },
): FindCodeReferencesResult => ({
  architecture: header.architecture,
  gp: gpReport(header.gp),
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
      gp_relative: 0,
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

/** Find references to addresses across several code files. */
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
      const loaded = await this.#load(
        file.path,
        file.load_address,
        file.use_gp,
        input.architecture,
      );
      if (!loaded.ok) return loaded;
      regions.push(...loaded.value);
    }

    const targets = input.targets.map((target) => ({
      address: parseAddress32(target.address) ?? 0,
      length: target.length,
      name: target.name ?? null,
    }));
    const kinds = new Set<CodeReferenceKind>(
      input.kinds ?? [
        "call",
        "jump",
        "address_pair",
        "gp_relative",
        "pointer_word",
      ],
    );
    const gp = resolveGp(
      input.gp,
      input.gp_relative,
      input.architecture,
      regions,
    );
    const tally = tallyReferences(regions, targets, {
      architecture: input.architecture,
      kinds,
      maxReferences: input.max_references,
      gp: gp.value,
      resolveCallArguments: input.resolve_call_arguments,
      includeCallerSignatures: input.include_caller_signatures,
    });
    const result = buildResult(regions, targets, tally, {
      architecture: input.architecture,
      gp,
    });
    const validated = findCodeReferencesResultSchema.parse(result);
    return ok(
      createEvidence(undefined, ROM_CODE_REFERENCE_PROVIDER_IDENTITY, {
        operation: OPERATION,
        parameters: evidenceParameters(input, kinds),
        result: jsonValueSchema.parse(validated),
        confidence: "derived",
        subjectUnavailableReason: `Evidence covers ${regions.length} region(s) across ${input.files.length} file(s); each region's SHA-256 is in result.files.`,
        locations: input.files.map((file) => ({
          kind: "artifact-path" as const,
          path: file.path,
        })),
        limitations: [
          ...codeReferenceLimitations(input.architecture),
          ...regions.flatMap((region) => region.notes),
          ...(gp.source === "auto"
            ? [
                `$gp ${formatAddress32(gp.value ?? 0)} was inferred from the lui/addiu pair at ${formatAddress32(gp.address ?? 0)} in ${gp.file ?? ""} and applied to every file with use_gp; pass gp to override.`,
              ]
            : []),
          ...(input.architecture === "mips-le" &&
          input.gp_relative &&
          gp.value === undefined
            ? [
                "No $gp value was given or found, so gp_relative references were skipped.",
              ]
            : []),
        ],
      }),
    );
  }

  async #load(
    path: string,
    loadAddress: string | undefined,
    useGp: boolean,
    architecture: CodeReferenceArchitecture,
  ): Promise<Result<readonly LoadedRegion[], AnalysisError>> {
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
    const located = locateRegions(
      path,
      bytes,
      loadAddress === undefined ? undefined : parseAddress32(loadAddress),
      architecture,
    );
    if (!located.ok) return located;
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    return ok(
      located.value.map((region) => ({
        path,
        bytes,
        sha256,
        useGp,
        ...region,
      })),
    );
  }
}
