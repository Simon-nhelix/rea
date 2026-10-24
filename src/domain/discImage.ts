import { err, ok, type Result } from "./result.js";

/** CD frames (sectors) per second in a cue sheet MM:SS:FF time. */
const FRAMES_PER_SECOND = 75;
/** Bytes of one raw CD sector as stored by BINARY cue files. */
export const RAW_CD_SECTOR_BYTES = 2352;
/** User-data bytes of one Mode 1 or Mode 2 Form 1 sector. */
export const CD_USER_DATA_BYTES = 2048;

/** Data-track sector layouts this reader can project onto 2048-byte user data. */
export const DATA_TRACK_MODES = [
  "MODE1/2048",
  "MODE1/2352",
  "MODE2/2352",
] as const;
export type DataTrackMode = (typeof DATA_TRACK_MODES)[number];

/** One TRACK entry exactly as declared by the cue sheet. */
export interface CueTrack {
  readonly number: number;
  /** Declared mode, e.g. AUDIO or MODE1/2352. */
  readonly mode: string;
  /** INDEX number → frame offset from the start of this track's FILE. */
  readonly indexes: ReadonlyMap<number, number>;
  /** PREGAP frames that are not stored in any FILE. */
  readonly pregapFrames: number;
}

/** One FILE entry and the tracks stored in it. */
export interface CueFile {
  /** File name as written in the cue sheet (relative to the cue directory). */
  readonly name: string;
  readonly type: string;
  readonly tracks: readonly CueTrack[];
}

export interface CueSheet {
  readonly files: readonly CueFile[];
}

const parseCueTime = (raw: string): number | undefined => {
  const match = /^(\d{1,3}):(\d{2}):(\d{2})$/u.exec(raw);
  if (match === null) return undefined;
  const seconds = Number(match[2]);
  const frames = Number(match[3]);
  if (seconds >= 60 || frames >= FRAMES_PER_SECOND) return undefined;
  return (Number(match[1]) * 60 + seconds) * FRAMES_PER_SECOND + frames;
};

/** Split one cue line into tokens, keeping double-quoted names intact. */
const cueTokens = (line: string): string[] => {
  const tokens: string[] = [];
  const pattern = /"([^"]*)"|(\S+)/gu;
  for (const match of line.matchAll(pattern)) {
    tokens.push(match[1] ?? match[2] ?? "");
  }
  return tokens;
};

/** Parse the FILE/TRACK/INDEX/PREGAP structure of a CDRWIN cue sheet. */
export const parseCueSheet = (text: string): Result<CueSheet, string> => {
  const files: { name: string; type: string; tracks: CueTrack[] }[] = [];
  let track:
    | {
        number: number;
        mode: string;
        indexes: Map<number, number>;
        pregapFrames: number;
      }
    | undefined;
  const flushTrack = (): void => {
    if (track === undefined) return;
    files.at(-1)?.tracks.push(track);
    track = undefined;
  };
  const lines = text.replace(/^﻿/u, "").split(/\r?\n/u);
  for (let i = 0; i < lines.length; i++) {
    const tokens = cueTokens(lines[i] ?? "");
    const keyword = tokens[0]?.toUpperCase();
    if (keyword === undefined) continue;
    const at = `line ${i + 1}`;
    switch (keyword) {
      case "FILE": {
        flushTrack();
        if (tokens.length < 3 || (tokens[1] ?? "").length === 0)
          return err(`Invalid FILE entry at ${at}`);
        files.push({
          name: tokens[1] ?? "",
          type: (tokens[2] ?? "").toUpperCase(),
          tracks: [],
        });
        break;
      }
      case "TRACK": {
        flushTrack();
        const number = Number(tokens[1]);
        if (files.length === 0)
          return err(`TRACK before any FILE entry at ${at}`);
        if (!Number.isInteger(number) || number < 1 || number > 99)
          return err(`Invalid TRACK number at ${at}`);
        track = {
          number,
          mode: (tokens[2] ?? "").toUpperCase(),
          indexes: new Map(),
          pregapFrames: 0,
        };
        break;
      }
      case "INDEX": {
        if (track === undefined)
          return err(`INDEX outside a TRACK entry at ${at}`);
        const index = Number(tokens[1]);
        const frames = parseCueTime(tokens[2] ?? "");
        if (!Number.isInteger(index) || index < 0 || index > 99)
          return err(`Invalid INDEX number at ${at}`);
        if (frames === undefined) return err(`Invalid INDEX time at ${at}`);
        track.indexes.set(index, frames);
        break;
      }
      case "PREGAP": {
        if (track === undefined)
          return err(`PREGAP outside a TRACK entry at ${at}`);
        const frames = parseCueTime(tokens[1] ?? "");
        if (frames === undefined) return err(`Invalid PREGAP time at ${at}`);
        track.pregapFrames = frames;
        break;
      }
      default:
        // CATALOG, REM, FLAGS, TITLE, ISRC, POSTGAP and similar metadata
        // do not change sector placement read by this parser.
        break;
    }
  }
  flushTrack();
  if (files.length === 0) return err("Cue sheet declares no FILE entries");
  for (const file of files) {
    for (const entry of file.tracks) {
      if (!entry.indexes.has(1))
        return err(`TRACK ${entry.number} has no INDEX 01`);
    }
  }
  return ok({ files });
};

const rawSectorBytes = (mode: string): number | undefined => {
  if (mode === "AUDIO") return RAW_CD_SECTOR_BYTES;
  const match = /^MODE[12]\/(\d+)$/u.exec(mode);
  return match === null ? undefined : Number(match[1]);
};

/** Location of one selected data track inside its FILE and on the disc. */
export interface DataTrackLayout {
  readonly track: number;
  readonly mode: DataTrackMode;
  /** Cue FILE name holding the track. */
  readonly fileName: string;
  readonly rawSectorBytes: number;
  /** Byte offset of user data inside each raw sector. */
  readonly userDataOffset: number;
  /** Sector index of INDEX 01 inside the FILE. */
  readonly firstSectorInFile: number;
  /** Sectors from INDEX 01 to the end of the track. */
  readonly sectorCount: number;
  /** Absolute disc LBA of INDEX 01 (LBA 0 = MSF 00:02:00). */
  readonly firstLba: number;
  /** Other data tracks in the sheet, which this layout does not cover. */
  readonly otherDataTracks: readonly number[];
}

/**
 * Select the first data track and locate its INDEX 01 on the disc. `fileBytes`
 * holds the size of every FILE so multi-file sheets can derive absolute LBAs.
 */
export const resolveFirstDataTrack = (
  sheet: CueSheet,
  fileBytes: ReadonlyMap<string, number>,
): Result<DataTrackLayout, string> => {
  let fileStartLba = 0;
  let pregapTotal = 0;
  let selected: DataTrackLayout | undefined;
  const otherDataTracks: number[] = [];
  for (const file of sheet.files) {
    const size = fileBytes.get(file.name);
    if (size === undefined)
      return err(`Size of cue FILE "${file.name}" is unknown`);
    const firstTrack = file.tracks[0];
    const fileSectorBytes =
      firstTrack === undefined ? undefined : rawSectorBytes(firstTrack.mode);
    if (fileSectorBytes === undefined)
      return err(`Unsupported track mode in cue FILE "${file.name}"`);
    for (const [position, entry] of file.tracks.entries()) {
      pregapTotal += entry.pregapFrames;
      if (entry.mode === "AUDIO") continue;
      if (selected !== undefined) {
        otherDataTracks.push(entry.number);
        continue;
      }
      if (!(DATA_TRACK_MODES as readonly string[]).includes(entry.mode))
        return err(
          `Data TRACK ${entry.number} uses unsupported mode ${entry.mode}; supported: ${DATA_TRACK_MODES.join(", ")}`,
        );
      const mode = entry.mode as DataTrackMode;
      const sectorBytes = rawSectorBytes(mode)!;
      if (sectorBytes !== fileSectorBytes)
        return err(
          `TRACK ${entry.number} mixes sector sizes inside FILE "${file.name}"`,
        );
      if (size % sectorBytes !== 0)
        return err(
          `FILE "${file.name}" size ${size} is not a multiple of ${sectorBytes}-byte sectors`,
        );
      const first = entry.indexes.get(1)!;
      const next = file.tracks[position + 1];
      const fileSectors = size / sectorBytes;
      const end =
        next === undefined
          ? fileSectors
          : (next.indexes.get(0) ?? next.indexes.get(1)!);
      if (first >= end)
        return err(`TRACK ${entry.number} has no sectors after INDEX 01`);
      selected = {
        track: entry.number,
        mode,
        fileName: file.name,
        rawSectorBytes: sectorBytes,
        userDataOffset:
          mode === "MODE1/2352" ? 16 : mode === "MODE2/2352" ? 24 : 0,
        firstSectorInFile: first,
        sectorCount: end - first,
        firstLba: fileStartLba + pregapTotal + first,
        otherDataTracks,
      };
    }
    fileStartLba += size / fileSectorBytes;
  }
  return selected === undefined
    ? err("Cue sheet declares no data track")
    : ok(selected);
};

const SYNC = Uint8Array.of(
  0x00,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0x00,
);

/** User data of a data track plus sectors whose header did not match its mode. */
export interface DataTrackUserData {
  readonly bytes: Buffer;
  /** Sectors (track-relative) whose sync, mode byte or form did not match. */
  readonly mismatchedSectors: number;
  readonly firstMismatchedSector: number | null;
}

/**
 * Concatenate the 2048-byte user data of every track sector. `trackBytes`
 * starts at the track's INDEX 01 sector. Raw sectors are checked for the sync
 * pattern and mode byte; Mode 2 Form 2 sectors have no 2048-byte user area
 * and are reported as mismatched.
 */
export const extractDataTrackUserData = (
  trackBytes: Uint8Array,
  layout: Pick<
    DataTrackLayout,
    "mode" | "rawSectorBytes" | "userDataOffset" | "sectorCount"
  >,
): DataTrackUserData => {
  const out = Buffer.alloc(layout.sectorCount * CD_USER_DATA_BYTES);
  let mismatchedSectors = 0;
  let firstMismatchedSector: number | null = null;
  const expectedMode =
    layout.mode === "MODE1/2352" ? 1 : layout.mode === "MODE2/2352" ? 2 : 0;
  for (let sector = 0; sector < layout.sectorCount; sector++) {
    const base = sector * layout.rawSectorBytes;
    if (expectedMode !== 0) {
      let matches = trackBytes[base + 15] === expectedMode;
      for (let i = 0; matches && i < SYNC.length; i++)
        matches = trackBytes[base + i] === SYNC[i];
      // Mode 2 subheader submode bit 5 selects Form 2 (2324-byte user area).
      if (matches && expectedMode === 2)
        matches = ((trackBytes[base + 18] ?? 0) & 0x20) === 0;
      if (!matches) {
        mismatchedSectors++;
        firstMismatchedSector ??= sector;
      }
    }
    const start = base + layout.userDataOffset;
    out.set(
      trackBytes.subarray(start, start + CD_USER_DATA_BYTES),
      sector * CD_USER_DATA_BYTES,
    );
  }
  return { bytes: out, mismatchedSectors, firstMismatchedSector };
};

/** PC Engine CD-ROM² IPL information record (system card boot record). */
export type PceCdIpl = {
  readonly sector: number;
  /** IPLBLK: first sector of the boot program (track-relative). */
  readonly iplblk: number;
  /** IPLBLN: boot program length in sectors. */
  readonly iplbln: number;
  /** IPLSTA: CPU load address. */
  readonly iplsta: string;
  /** IPLJMP: CPU execution address. */
  readonly ipljmp: string;
  /** IPLMPR2..IPLMPR6: bank numbers mapped before the jump. */
  readonly mpr2_6: string[];
  readonly openmode: number;
  readonly grpblk: number;
  readonly grpbln: number;
  readonly grpadr: string;
  readonly adpblk: number;
  readonly adpbln: number;
  readonly adprate: number;
  readonly system_id: string;
  readonly copyright: string;
  readonly program_name: string;
  /** Byte range of the boot program inside the track's user data. */
  readonly boot_program: {
    readonly first_sector: number;
    readonly sectors: number;
    readonly user_data_offset: number;
    readonly byte_length: number;
  };
};

export const PCE_CD_SYSTEM_ID = "PC Engine CD-ROM SYSTEM";

const hex = (value: number, digits: number): string =>
  `0x${value.toString(16).padStart(digits, "0")}`;

const asciiField = (bytes: Uint8Array, start: number, end: number): string => {
  let text = "";
  for (let i = start; i < end; i++) {
    const b = bytes[i] ?? 0;
    if (b === 0) break;
    text += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "?";
  }
  return text.trimEnd();
};

/**
 * Parse the PC Engine CD IPL record from one 2048-byte user-data sector.
 * Returns undefined unless the record carries the system ID at +0x20.
 */
export const parsePceCdIpl = (
  sectorBytes: Uint8Array,
  sector: number,
): PceCdIpl | undefined => {
  if (sectorBytes.length < 0x80) return undefined;
  if (asciiField(sectorBytes, 0x20, 0x38) !== PCE_CD_SYSTEM_ID)
    return undefined;
  const b = (i: number): number => sectorBytes[i] ?? 0;
  const be24 = (i: number): number => (b(i) << 16) | (b(i + 1) << 8) | b(i + 2);
  const le16 = (i: number): number => b(i) | (b(i + 1) << 8);
  const iplblk = be24(0x00);
  const iplbln = b(0x03);
  return {
    sector,
    iplblk,
    iplbln,
    iplsta: hex(le16(0x04), 4),
    ipljmp: hex(le16(0x06), 4),
    mpr2_6: [0x08, 0x09, 0x0a, 0x0b, 0x0c].map((i) => hex(b(i), 2)),
    openmode: b(0x0d),
    grpblk: be24(0x0e),
    grpbln: b(0x11),
    grpadr: hex(le16(0x12), 4),
    adpblk: be24(0x14),
    adpbln: b(0x17),
    adprate: b(0x18),
    system_id: PCE_CD_SYSTEM_ID,
    copyright: asciiField(sectorBytes, 0x38, 0x6a),
    program_name: asciiField(sectorBytes, 0x6a, 0x7a),
    boot_program: {
      first_sector: iplblk,
      sectors: iplbln,
      user_data_offset: iplblk * CD_USER_DATA_BYTES,
      byte_length: iplbln * CD_USER_DATA_BYTES,
    },
  };
};

/** One track line in a Dreamcast .gdi disc descriptor. */
export interface GdiTrack {
  readonly number: number;
  readonly startLba: number;
  readonly trackType: number;
  readonly sectorSize: number;
  readonly fileName: string;
  readonly offset: number;
}

export interface GdiSheet {
  readonly tracks: readonly GdiTrack[];
}

/** Parse a Dreamcast .gdi sheet. */
export const parseGdiSheet = (text: string): Result<GdiSheet, string> => {
  const lines = text
    .replace(/^\uFEFF/u, "")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (lines.length < 2) return err("GDI sheet has no track entries");
  const declaredCount = Number(lines[0]);
  if (!Number.isInteger(declaredCount) || declaredCount < 1)
    return err("GDI sheet header is not a valid track count");
  const tracks: GdiTrack[] = [];
  for (let i = 1; i < lines.length; i++) {
    const tokens = cueTokens(lines[i] ?? "");
    if (tokens.length < 6)
      return err(`Invalid GDI track entry at line ${i + 1}`);
    const number = Number(tokens[0]);
    const startLba = Number(tokens[1]);
    const trackType = Number(tokens[2]);
    const sectorSize = Number(tokens[3]);
    const fileName = tokens[4] ?? "";
    const offset = Number(tokens[5]);
    if (
      !Number.isInteger(number) ||
      number < 1 ||
      number > 99 ||
      tracks.some((t) => t.number === number) ||
      !Number.isInteger(startLba) ||
      startLba < 0 ||
      (trackType !== 0 && trackType !== 4) ||
      (sectorSize !== CD_USER_DATA_BYTES &&
        sectorSize !== RAW_CD_SECTOR_BYTES) ||
      fileName.length === 0 ||
      !Number.isSafeInteger(offset) ||
      offset < 0
    )
      return err(`Invalid GDI track fields at line ${i + 1}`);
    tracks.push({
      number,
      startLba,
      trackType,
      sectorSize,
      fileName,
      offset,
    });
  }
  return tracks.length !== declaredCount
    ? err("GDI track count does not match the declared track entries")
    : ok({ tracks });
};

/** Select the primary data track (preferring the Dreamcast high-density area at LBA 45000). */
export const resolveGdiDataTrack = (
  sheet: GdiSheet,
  fileBytes: ReadonlyMap<string, number>,
): Result<DataTrackLayout, string> => {
  const dataTracks = sheet.tracks.filter((t) => t.trackType === 4);
  if (dataTracks.length === 0) return err("GDI sheet declares no data track");
  const selected =
    dataTracks.find((t) => t.startLba >= 45000) ?? dataTracks[0]!;
  const size = fileBytes.get(selected.fileName);
  if (size === undefined)
    return err(`Size of GDI track file "${selected.fileName}" is unknown`);
  if (selected.offset % selected.sectorSize !== 0)
    return err("GDI track file offsets must be sector-aligned for this reader");
  if (selected.offset >= size)
    return err(
      `GDI track file "${selected.fileName}" has no data after offset ${selected.offset}`,
    );
  if ((size - selected.offset) % selected.sectorSize !== 0)
    return err(
      `GDI track file "${selected.fileName}" data after offset ${selected.offset} is not a multiple of ${selected.sectorSize}-byte sectors`,
    );
  const mode: DataTrackMode =
    selected.sectorSize === RAW_CD_SECTOR_BYTES ? "MODE1/2352" : "MODE1/2048";
  return ok({
    track: selected.number,
    mode,
    fileName: selected.fileName,
    rawSectorBytes: selected.sectorSize,
    userDataOffset: selected.sectorSize === RAW_CD_SECTOR_BYTES ? 16 : 0,
    firstSectorInFile: selected.offset / selected.sectorSize,
    sectorCount: (size - selected.offset) / selected.sectorSize,
    firstLba: selected.startLba,
    otherDataTracks: dataTracks
      .filter((t) => t.number !== selected.number)
      .map((t) => t.number),
  });
};

/** Auto-detect a raw 2352-byte Mode 1 or Mode 2 Form 1 .bin image from sector 0's sync header. */
export const detectRawSectorLayout = (
  fileName: string,
  bytes: Uint8Array,
): DataTrackLayout | undefined => {
  if (
    bytes.length < RAW_CD_SECTOR_BYTES ||
    bytes.length % RAW_CD_SECTOR_BYTES !== 0
  )
    return undefined;
  for (let i = 0; i < SYNC.length; i++) {
    if (bytes[i] !== SYNC[i]) return undefined;
  }
  const modeByte = bytes[15];
  if (modeByte !== 1 && modeByte !== 2) return undefined;
  const mode: DataTrackMode = modeByte === 1 ? "MODE1/2352" : "MODE2/2352";
  return {
    track: 1,
    mode,
    fileName,
    rawSectorBytes: RAW_CD_SECTOR_BYTES,
    userDataOffset: modeByte === 1 ? 16 : 24,
    firstSectorInFile: 0,
    sectorCount: bytes.length / RAW_CD_SECTOR_BYTES,
    firstLba: 0,
    otherDataTracks: [],
  };
};

export {
  parseIso9660FileSystem,
  parsePlayStationSystemCnf,
  parseSegaIpBin,
  resolveDiscLocations,
  type DiscResolvedLocation,
  type Iso9660FileSystem,
  type PlayStationSystemCnf,
  type SegaIpBin,
} from "./iso9660.js";
