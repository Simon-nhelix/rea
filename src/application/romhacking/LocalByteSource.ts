import { createHash } from "node:crypto";
import { constants as bufferConstants } from "node:buffer";
import { readFile, realpath, stat } from "node:fs/promises";
import { basename, dirname, extname, isAbsolute, resolve } from "node:path";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  CD_USER_DATA_BYTES,
  extractDataTrackUserData,
  parseCueSheet,
  parsePceCdIpl,
  resolveFirstDataTrack,
  type DataTrackLayout,
  type PceCdIpl,
} from "../../domain/discImage.js";
import type { EvidenceSubjectTarget } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { RomByteSourceDescription } from "../../domain/romHacking.js";

export type { RomByteSourceDescription };

/**
 * A local file read as plain bytes for ROM text tools, without executable or
 * console admission: file offsets are the only coordinates. A cue sheet is
 * read as the concatenated 2048-byte user data of its first data track.
 */
export interface LocalByteSource {
  readonly kind: "local-bytes";
  /** The caller-selected file (data file or cue sheet). */
  readonly path: string;
  readonly sha256: string;
  /** Bytes the tools scan: the file, or the data track's user data. */
  readonly bytes: Buffer;
  readonly description: RomByteSourceDescription;
  /** Every TRACK of a cue sheet source, as declared. */
  readonly cueTracks?: readonly CueTrackSummary[];
}

export type CueTrackSummary = {
  readonly track: number;
  readonly mode: string;
  readonly file: string;
};

export const isLocalByteSource = (target: unknown): target is LocalByteSource =>
  typeof target === "object" &&
  target !== null &&
  "kind" in target &&
  target.kind === "local-bytes";

/** Evidence identity of the caller-selected file. */
export const localByteSourceSubject = (
  source: LocalByteSource,
): EvidenceSubjectTarget => ({
  path: source.path,
  sha256: source.sha256,
  format: "file",
});

/** Sector coordinates of one offset, when the source has sectors. */
export const locateLocalByteOffset = (
  source: LocalByteSource,
  offset: number,
):
  | {
      readonly sector: number;
      readonly offset_in_sector: number;
      readonly lba?: number;
    }
  | undefined => {
  const size = source.description.sector_size;
  if (size === undefined) return undefined;
  const sector = Math.floor(offset / size);
  const disc = source.description.disc;
  return {
    sector,
    offset_in_sector: offset % size,
    ...(disc === undefined ? {} : { lba: disc.first_lba + sector }),
  };
};

const MAX_CUE_SHEET_BYTES = 1024 * 1024;

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

const inputError = (
  operation: string,
  userMessage: string,
  cause?: unknown,
): AnalysisInputError =>
  new AnalysisInputError(operation, {
    userMessage,
    ...(cause === undefined ? {} : { cause }),
  });

const readWholeFile = async (
  operation: string,
  path: string,
): Promise<Result<Buffer, AnalysisError>> => {
  try {
    const metadata = await stat(path);
    if (!metadata.isFile())
      return err(inputError(operation, `${path} is not a regular file`));
    if (metadata.size > bufferConstants.MAX_LENGTH)
      return err(
        inputError(
          operation,
          `${path} is ${metadata.size} bytes, larger than one in-memory buffer`,
        ),
      );
    return ok(await readFile(path));
  } catch (cause) {
    return err(inputError(operation, `Failed to read ${path}`, cause));
  }
};

const resolveCallerPath = async (
  operation: string,
  path: string,
): Promise<Result<string, AnalysisError>> => {
  try {
    return ok(await realpath(isAbsolute(path) ? path : resolve(path)));
  } catch (cause) {
    return err(inputError(operation, `Cannot open ${path}`, cause));
  }
};

/** A cue sheet resolved to its first data track's user data. */
export interface DiscImageRead {
  readonly cuePath: string;
  readonly cueSha256: string;
  readonly imagePath: string;
  readonly imageSha256: string;
  readonly layout: DataTrackLayout;
  readonly userData: Buffer;
  readonly mismatchedSectors: number;
  readonly firstMismatchedSector: number | null;
  readonly tracks: readonly CueTrackSummary[];
}

/** Read a cue sheet and project its first data track onto 2048-byte user data. */
export const readCueDataTrack = async (
  operation: string,
  cuePath: string,
): Promise<Result<DiscImageRead, AnalysisError>> => {
  let cueBytes: Buffer;
  try {
    if ((await stat(cuePath)).size > MAX_CUE_SHEET_BYTES)
      return err(
        inputError(operation, `Cue sheet ${cuePath} is larger than 1 MiB`),
      );
    cueBytes = await readFile(cuePath);
  } catch (cause) {
    return err(inputError(operation, `Failed to read ${cuePath}`, cause));
  }
  const sheet = parseCueSheet(cueBytes.toString("utf8"));
  if (!sheet.ok)
    return err(inputError(operation, `${cuePath}: ${sheet.error}`));
  const cueDirectory = dirname(cuePath);
  const filePath = (name: string): string =>
    isAbsolute(name) ? name : resolve(cueDirectory, name);
  const sizes = new Map<string, number>();
  for (const file of sheet.value.files) {
    try {
      sizes.set(file.name, (await stat(filePath(file.name))).size);
    } catch (cause) {
      return err(
        inputError(
          operation,
          `Cue FILE "${file.name}" was not found next to ${basename(cuePath)}`,
          cause,
        ),
      );
    }
  }
  const layout = resolveFirstDataTrack(sheet.value, sizes);
  if (!layout.ok)
    return err(inputError(operation, `${cuePath}: ${layout.error}`));
  const imagePath = filePath(layout.value.fileName);
  const image = await readWholeFile(operation, imagePath);
  if (!image.ok) return image;
  const start = layout.value.firstSectorInFile * layout.value.rawSectorBytes;
  const userData = extractDataTrackUserData(
    image.value.subarray(
      start,
      start + layout.value.sectorCount * layout.value.rawSectorBytes,
    ),
    layout.value,
  );
  return ok({
    cuePath,
    cueSha256: sha256(cueBytes),
    imagePath,
    imageSha256: sha256(image.value),
    layout: layout.value,
    userData: userData.bytes,
    mismatchedSectors: userData.mismatchedSectors,
    firstMismatchedSector: userData.firstMismatchedSector,
    tracks: sheet.value.files.flatMap((file) =>
      file.tracks.map((entry) => ({
        track: entry.number,
        mode: entry.mode,
        file: file.name,
      })),
    ),
  });
};

const isCuePath = (path: string): boolean =>
  extname(path).toLowerCase() === ".cue";

/** Whether a plain file is laid out in 2048-byte user-data sectors (.iso). */
const hasIsoSectors = (path: string, length: number): boolean =>
  extname(path).toLowerCase() === ".iso" &&
  length > 0 &&
  length % CD_USER_DATA_BYTES === 0;

/**
 * Open a local file for ROM text tools without format admission. `.cue` files
 * become their first data track's user data; other files are read as-is.
 */
export const openLocalByteSource = async (
  operation: string,
  path: string,
  reason: RomByteSourceDescription["reason"],
): Promise<Result<LocalByteSource, AnalysisError>> => {
  const resolved = await resolveCallerPath(operation, path);
  if (!resolved.ok) return resolved;
  const canonical = resolved.value;
  if (isCuePath(canonical)) {
    const disc = await readCueDataTrack(operation, canonical);
    if (!disc.ok) return disc;
    const { layout } = disc.value;
    return ok({
      kind: "local-bytes",
      path: canonical,
      sha256: disc.value.cueSha256,
      bytes: disc.value.userData,
      description: {
        mode: "disc-image",
        reason,
        byte_length: disc.value.userData.length,
        sector_size: CD_USER_DATA_BYTES,
        disc: {
          track: layout.track,
          track_mode: layout.mode,
          image_path: disc.value.imagePath,
          image_sha256: disc.value.imageSha256,
          first_lba: layout.firstLba,
          sectors: layout.sectorCount,
          raw_sector_bytes: layout.rawSectorBytes,
          user_data_offset: layout.userDataOffset,
          first_sector_in_image: layout.firstSectorInFile,
          header_mismatched_sectors: disc.value.mismatchedSectors,
          first_mismatched_sector: disc.value.firstMismatchedSector,
          other_data_tracks: [...layout.otherDataTracks],
        },
      },
      cueTracks: disc.value.tracks,
    });
  }
  const bytes = await readWholeFile(operation, canonical);
  if (!bytes.ok) return bytes;
  return ok({
    kind: "local-bytes",
    path: canonical,
    sha256: sha256(bytes.value),
    bytes: bytes.value,
    description: {
      mode: "data",
      reason,
      byte_length: bytes.value.length,
      ...(hasIsoSectors(canonical, bytes.value.length)
        ? { sector_size: CD_USER_DATA_BYTES }
        : {}),
    },
  });
};

/** Disc-image facts for `inspect-disc-image`: layout plus a PC Engine CD IPL. */
export const inspectDiscImage = async (
  path: string,
): Promise<
  Result<
    {
      readonly subject: EvidenceSubjectTarget;
      readonly result: {
        readonly source: RomByteSourceDescription;
        readonly tracks?: CueTrackSummary[];
        readonly pce_cd_ipl: PceCdIpl | null;
      };
    },
    AnalysisError
  >
> => {
  const operation = "inspect_disc_image";
  const source = await openLocalByteSource(operation, path, "requested");
  if (!source.ok) return source;
  const { bytes, description } = source.value;
  if (description.sector_size === undefined)
    return err(
      inputError(
        operation,
        "inspect-disc-image reads .cue sheets or .iso files made of 2048-byte sectors",
      ),
    );
  // The PC Engine IPL record is sector 1 of the data track; sector 0 holds
  // the copyright notice.
  const ipl = parsePceCdIpl(
    bytes.subarray(CD_USER_DATA_BYTES, CD_USER_DATA_BYTES * 2),
    1,
  );
  const tracks =
    source.value.cueTracks === undefined
      ? undefined
      : [...source.value.cueTracks];
  return ok({
    subject: localByteSourceSubject(source.value),
    result: {
      source: description,
      ...(tracks === undefined ? {} : { tracks }),
      pce_cd_ipl: ipl ?? null,
    },
  });
};
