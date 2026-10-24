import type { FileHandle } from "node:fs/promises";
import type {
  BinaryArchitecture,
  UniversalMachOSlice,
} from "../domain/binaryTargetTypes.js";
import {
  readFatContainerHeader,
  readMachoHeaderPrefixFacts,
  validateFatSlice,
} from "../domain/apple/machoContainer.js";
import { MACHO_CPU_TYPES } from "../domain/apple/machoTargetSelection.js";
import { AnalysisArtifactChangedError } from "../domain/analysisErrorCore.js";
import { assertArtifactReadActive } from "../artifacts/ArtifactFileOperation.js";

/** Exact source range selected by the target resolver, never a second CPU choice. */
export interface GhidraUniversalSlice extends UniversalMachOSlice {
  readonly architecture: BinaryArchitecture;
}

/** Verify the committed range against the owned container and its embedded header. */
export const validateGhidraUniversalSlice = async (
  source: FileHandle,
  sourcePath: string,
  fileSize: bigint,
  slice: GhidraUniversalSlice,
  signal?: AbortSignal,
): Promise<void> => {
  const fail = (reason: string): never => {
    throw new AnalysisArtifactChangedError("open_binary", sourcePath, reason);
  };
  if (
    !Number.isSafeInteger(slice.offset) ||
    !Number.isSafeInteger(slice.size) ||
    slice.offset < 0 ||
    slice.size < 12 ||
    BigInt(slice.offset) + BigInt(slice.size) > fileSize ||
    fileSize > BigInt(Number.MAX_SAFE_INTEGER)
  )
    fail("The selected universal Mach-O slice has an invalid source range");
  const read = async (position: number, length: number) => {
    assertArtifactReadActive(signal);
    const bytes = Buffer.alloc(length);
    const observed = await source.read(bytes, 0, length, position);
    assertArtifactReadActive(signal);
    return bytes.subarray(0, observed.bytesRead);
  };
  let table = readFatContainerHeader(await read(0, 8), Number(fileSize));
  if (table.state === "needs-data")
    table = readFatContainerHeader(
      await read(0, table.requiredBytes),
      Number(fileSize),
    );
  if (table.state !== "parsed")
    return fail(
      "The universal Mach-O architecture table is unavailable or malformed",
    );
  const declared = table.slices.find(
    (entry) => entry.offset === slice.offset && entry.size === slice.size,
  );
  if (declared === undefined)
    return fail(
      "The selected slice no longer matches the universal Mach-O table",
    );
  const header = readMachoHeaderPrefixFacts(await read(slice.offset, 12));
  const cpus: Partial<Record<BinaryArchitecture, number>> = MACHO_CPU_TYPES;
  if (
    header.identity === null ||
    header.identity.cpuType !== cpus[slice.architecture]
  )
    return fail(
      "The selected Mach-O slice does not match the committed CPU family",
    );
  const rejected = validateFatSlice(
    declared,
    Number(fileSize),
    table.tableEnd,
    header.identity,
  );
  if (rejected !== null) fail(rejected);
};
