import {
  validateGhidraUniversalSlice,
  type GhidraUniversalSlice,
} from "./GhidraUniversalSlice.js";
import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { extname, join } from "node:path";
import {
  withArtifactRegularFile,
  withArtifactFileHandle,
  assertArtifactReadActive,
  mapArtifactFileFailure,
} from "../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { readArtifactFileChunks } from "../artifacts/readArtifactFileChunks.js";
import {
  NonRegularFileReadError,
  sameRegularFileState,
} from "../filesystem/RegularFile.js";

import type { JsonValue } from "../domain/jsonValue.js";
import {
  AnalysisArtifactChangedError,
  AnalysisAccessDeniedError,
} from "../domain/analysisErrorCore.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  WindowsSnapshotCancelledError,
  windowsPrivateRuntime,
} from "../windows/WindowsPrivateRuntime.js";

/** Immutable target copy admitted to one ephemeral Ghidra import. */
export interface GhidraTargetSnapshot {
  readonly path: string;
  readonly sha256: string;
  readonly admission?: JsonValue;
  readonly importedSha256?: string;
}

/** Copy one target and require its bytes to match the parsed target identity. */
export const createGhidraTargetSnapshot = async (
  sourcePath: string,
  runtimeRoot: string,
  expectedSha256: string,
  options: {
    readonly universalSlice?: GhidraUniversalSlice;
    readonly signal?: AbortSignal;
    readonly platform?: NodeJS.Platform;
    readonly resourceScope?: ArtifactResourceScope;
  } = {},
): Promise<GhidraTargetSnapshot> => {
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256))
    throw new TypeError("Ghidra target SHA-256 commitment is invalid");
  const slice = options.universalSlice;
  if (slice !== undefined && (options.platform ?? process.platform) === "win32")
    throw new TypeError(
      "Windows Ghidra P0 does not admit universal Mach-O extraction",
    );
  const suffix = slice === undefined ? safeExtension(sourcePath) : ".macho";
  const snapshotPath = join(
    runtimeRoot,
    `target-${expectedSha256.slice(0, 12)}${suffix}`,
  );
  if ((options.platform ?? process.platform) === "win32") {
    const observed = await windowsPrivateRuntime(runtimeRoot)
      .snapshot(
        sourcePath,
        `target-${expectedSha256.slice(0, 12)}${suffix}`,
        options.signal,
      )
      .catch((cause: unknown) => {
        if (cause instanceof WindowsSnapshotCancelledError)
          throw new ArtifactReaderFailure("cancelled", cause.message, {
            cause,
            cancellation: { reason: cause.reason },
          });
        throw cause;
      });
    if (observed.sha256 !== expectedSha256)
      throw new AnalysisArtifactChangedError(
        "open_binary",
        sourcePath,
        `Ghidra target snapshot digest mismatch: expected ${expectedSha256}, observed ${observed.sha256}`,
      );
    return {
      path: snapshotPath,
      sha256: observed.sha256,
      admission: { source: observed.source, snapshot: observed.snapshot },
    };
  }
  const resources = options.resourceScope ?? new ArtifactResourceScope();
  try {
    return await resources.run(() =>
      withArtifactRegularFile(
        sourcePath,
        resources,
        options.signal,
        async (source) => {
          const initial = await source.stat({ bigint: true });
          assertArtifactReadActive(options.signal);
          if (slice !== undefined)
            await validateGhidraUniversalSlice(
              source,
              sourcePath,
              initial.size,
              slice,
              options.signal,
            );
          return await withArtifactFileHandle(
            snapshotPath,
            await open(snapshotPath, "wx", 0o600),
            resources,
            options.signal,
            async (destination) => {
              await destination.chmod(0o600);
              const hash = createHash("sha256");
              const importedHash =
                slice === undefined ? undefined : createHash("sha256");
              let position = 0n;
              let copied = 0;
              const input = readArtifactFileChunks(source, {
                end: initial.size,
                signal: options.signal,
              });
              for await (const chunk of input) {
                assertArtifactReadActive(options.signal);
                // writeFile completes the entire supplied chunk at the current
                // descriptor offset. Only this owner closes either descriptor.
                hash.update(chunk);
                const start =
                  slice === undefined
                    ? 0
                    : Number(
                        BigInt(slice.offset) > position
                          ? BigInt(slice.offset) - position
                          : 0n,
                      );
                const end =
                  slice === undefined
                    ? chunk.length
                    : Number(
                        BigInt(slice.offset) + BigInt(slice.size) - position,
                      );
                const selected = chunk.subarray(
                  Math.min(start, chunk.length),
                  Math.max(0, Math.min(end, chunk.length)),
                );
                if (selected.length > 0) {
                  await destination.writeFile(selected);
                  importedHash?.update(selected);
                  copied += selected.length;
                }
                position += BigInt(chunk.length);
                assertArtifactReadActive(options.signal);
              }
              const coverage = input.readCoverage();
              const observed = hash.digest("hex");
              const after = await source.stat({ bigint: true });
              if (
                coverage.kind !== "complete" ||
                coverage.bytes !== initial.size ||
                !sameRegularFileState(initial, after) ||
                observed !== expectedSha256 ||
                (slice !== undefined && copied !== slice.size)
              )
                throw new AnalysisArtifactChangedError(
                  "open_binary",
                  sourcePath,
                  `Ghidra target snapshot digest or source identity changed: expected ${expectedSha256}, observed ${observed}`,
                );
              assertArtifactReadActive(options.signal);
              return {
                path: snapshotPath,
                sha256: observed,
                ...(importedHash === undefined
                  ? {}
                  : { importedSha256: importedHash.digest("hex") }),
              };
            },
          );
        },
        "follow",
      ),
    );
  } catch (cause: unknown) {
    // The private runtime owns partial snapshot entries. Its owner removes the
    // tree after every retained descriptor settles; do not unlink a raw name.
    throw mapArtifactFileFailure(cause, classifySnapshotFailure);
  }
};

const classifySnapshotFailure = (cause: unknown): unknown => {
  if (cause instanceof NonRegularFileReadError)
    return new AnalysisArtifactChangedError(
      "open_binary",
      cause.path,
      "The selected Ghidra source is no longer a regular file",
      { cause },
    );
  if (!(cause instanceof Error) || !("code" in cause)) return cause;
  const path =
    "path" in cause && typeof cause.path === "string"
      ? cause.path
      : "Ghidra snapshot file";
  if (cause.code === "EACCES" || cause.code === "EPERM")
    return new AnalysisAccessDeniedError("open_binary", path, cause.code, {
      cause,
    });
  if (
    cause.code === "ENOENT" ||
    cause.code === "ENOTDIR" ||
    cause.code === "ELOOP"
  )
    return new AnalysisArtifactChangedError(
      "open_binary",
      path,
      `The selected Ghidra file could not be opened (${cause.code})`,
      { cause },
    );
  return cause;
};

const safeExtension = (path: string): string => {
  const extension = extname(path);
  return /^\.[A-Za-z0-9]{1,12}$/u.test(extension) ? extension : ".bin";
};
