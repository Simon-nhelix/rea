import { CD_USER_DATA_BYTES } from "./discImage.js";

export type SegaIpBin = {
  readonly platform: "saturn" | "dreamcast" | "sega-cd";
  readonly hardware_id: string;
  readonly maker_id: string;
  readonly product_number: string;
  readonly version: string;
  readonly release_date: string;
  readonly device_info: string;
  readonly area_symbols: string;
  readonly peripherals: string;
  readonly title: string;
  readonly boot_filename: string | null;
  readonly first_read_address: string | null;
};

export type PlayStationSystemCnf = {
  readonly platform: "ps1" | "ps2";
  readonly boot_raw: string;
  readonly boot_path: string;
  readonly version: string | null;
  readonly vmode: string | null;
  readonly tcb: string | null;
  readonly event: string | null;
  readonly stack: string | null;
};

export type Iso9660FileEntry = {
  readonly path: string;
  readonly extent_lba: number;
  readonly track_sector: number;
  readonly user_data_offset: number;
  readonly size: number;
  readonly sectors: number;
};

export type Iso9660UnallocatedGap = {
  readonly start_lba: number;
  readonly end_lba: number;
  readonly start_sector: number;
  readonly sectors: number;
  readonly byte_length: number;
  readonly user_data_offset: number;
  readonly after_file: string | null;
  readonly before_file: string | null;
};

export type Iso9660FileSystem = {
  readonly system_id: string;
  readonly volume_id: string;
  readonly publisher_id: string;
  readonly data_preparer_id: string;
  readonly application_id: string;
  readonly volume_space_sectors: number;
  readonly base_lba: number;
  readonly files: Iso9660FileEntry[];
  readonly unallocated_gaps: Iso9660UnallocatedGap[];
};

export type DiscResolvedLocation = {
  readonly query_kind: "lba" | "user_data_offset";
  readonly query_value: number;
  readonly lba: number;
  readonly track_sector: number;
  readonly offset_in_sector: number;
  readonly user_data_offset: number;
  readonly region:
    | "system_area"
    | "iso9660_metadata"
    | "file"
    | "unallocated_gap"
    | "out_of_range";
  readonly file_path: string | null;
  readonly offset_in_file: number | null;
  readonly file_extent_lba: number | null;
  readonly file_size: number | null;
};

const asciiField = (bytes: Uint8Array, start: number, end: number): string => {
  let text = "";
  for (let i = start; i < end && i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    if (b === 0) break;
    text += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : " ";
  }
  return text.trim();
};

const readLe32 = (bytes: Uint8Array, offset: number): number =>
  ((bytes[offset] ?? 0) |
    ((bytes[offset + 1] ?? 0) << 8) |
    ((bytes[offset + 2] ?? 0) << 16) |
    ((bytes[offset + 3] ?? 0) << 24)) >>>
  0;

const readBe32 = (bytes: Uint8Array, offset: number): number =>
  (((bytes[offset] ?? 0) << 24) |
    ((bytes[offset + 1] ?? 0) << 16) |
    ((bytes[offset + 2] ?? 0) << 8) |
    (bytes[offset + 3] ?? 0)) >>>
  0;

const hex32 = (value: number): string =>
  `0x${(value >>> 0).toString(16).padStart(8, "0")}`;

/** Parse a Sega Saturn, Dreamcast, or Sega CD IP.BIN header from sector 0. */
export const parseSegaIpBin = (sector0: Uint8Array): SegaIpBin | undefined => {
  if (sector0.length < 0x100) return undefined;
  const hw = asciiField(sector0, 0x00, 0x10);
  if (hw === "SEGA SEGASATURN") {
    const firstRead = readBe32(sector0, 0xf0);
    return {
      platform: "saturn",
      hardware_id: hw,
      maker_id: asciiField(sector0, 0x10, 0x20),
      product_number: asciiField(sector0, 0x20, 0x2a),
      version: asciiField(sector0, 0x2a, 0x30),
      release_date: asciiField(sector0, 0x30, 0x38),
      device_info: asciiField(sector0, 0x38, 0x40),
      area_symbols: asciiField(sector0, 0x40, 0x4a),
      peripherals: asciiField(sector0, 0x50, 0x60),
      title: asciiField(sector0, 0x60, 0xd0),
      boot_filename: null,
      first_read_address: firstRead === 0 ? null : hex32(firstRead),
    };
  }
  if (hw === "SEGA SEGAKATANA") {
    const bootFile = asciiField(sector0, 0x60, 0x70);
    return {
      platform: "dreamcast",
      hardware_id: hw,
      maker_id: asciiField(sector0, 0x10, 0x20),
      device_info: asciiField(sector0, 0x20, 0x30),
      area_symbols: asciiField(sector0, 0x30, 0x38),
      peripherals: asciiField(sector0, 0x38, 0x40),
      product_number: asciiField(sector0, 0x40, 0x4a),
      version: asciiField(sector0, 0x4a, 0x50),
      release_date: asciiField(sector0, 0x50, 0x60),
      boot_filename: bootFile.length > 0 ? bootFile : null,
      title: asciiField(sector0, 0x80, 0x100),
      first_read_address: "0x8c010000",
    };
  }
  if (hw === "SEGA DISCSYSTEM" || hw === "SEGA MEGA DRIVE") {
    return {
      platform: "sega-cd",
      hardware_id: hw,
      maker_id: asciiField(sector0, 0x110, 0x120),
      product_number: asciiField(sector0, 0x180, 0x18e),
      version: "",
      release_date: asciiField(sector0, 0x118, 0x120),
      device_info: "",
      area_symbols: asciiField(sector0, 0x1f0, 0x200),
      peripherals: asciiField(sector0, 0x190, 0x1a0),
      title: asciiField(sector0, 0x120, 0x150),
      boot_filename: null,
      first_read_address: null,
    };
  }
  return undefined;
};

const normalizeDiscBootPath = (raw: string): string => {
  const withoutScheme = raw
    .replace(/^cdrom0?:\s*/iu, "")
    .replace(/;1$/u, "")
    .replaceAll("\\", "/")
    .trim();
  return withoutScheme.startsWith("/") ? withoutScheme : `/${withoutScheme}`;
};

/** Parse a PlayStation 1 or PlayStation 2 SYSTEM.CNF text file. */
export const parsePlayStationSystemCnf = (
  text: string,
): PlayStationSystemCnf | undefined => {
  const entries = new Map<string, string>();
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#") || line.startsWith(";"))
      continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim().toUpperCase();
    const val = line.slice(eq + 1).trim();
    if (key.length > 0 && val.length > 0) entries.set(key, val);
  }
  const boot2 = entries.get("BOOT2");
  const boot1 = entries.get("BOOT");
  const bootRaw = boot2 ?? boot1;
  if (bootRaw === undefined) return undefined;
  return {
    platform: boot2 !== undefined ? "ps2" : "ps1",
    boot_raw: bootRaw,
    boot_path: normalizeDiscBootPath(bootRaw),
    version: entries.get("VER") ?? null,
    vmode: entries.get("VMODE") ?? null,
    tcb: entries.get("TCB") ?? null,
    event: entries.get("EVENT") ?? null,
    stack: entries.get("STACK") ?? null,
  };
};

const MAX_ISO_FILES = 16_384;
const MAX_ISO_DIRS = 2_048;

interface DirQueueItem {
  readonly path: string;
  readonly extentLba: number;
  readonly byteLength: number;
}

const walkIsoDirectories = (
  userData: Uint8Array,
  totalSectors: number,
  baseLba: number,
  rootLba: number,
  rootSize: number,
): Iso9660FileEntry[] => {
  const files: Iso9660FileEntry[] = [];
  const visitedDirs = new Set<number>([rootLba]);
  const queue: DirQueueItem[] = [
    { path: "", extentLba: rootLba, byteLength: rootSize },
  ];
  while (queue.length > 0 && files.length < MAX_ISO_FILES) {
    const current = queue.shift()!;
    const startSector = current.extentLba - baseLba;
    const sectorCount = Math.ceil(current.byteLength / CD_USER_DATA_BYTES);
    if (startSector < 0 || startSector + sectorCount > totalSectors) continue;
    for (let s = 0; s < sectorCount; s++) {
      const sectorOffset = (startSector + s) * CD_USER_DATA_BYTES;
      const sectorEnd = Math.min(
        sectorOffset + CD_USER_DATA_BYTES,
        startSector * CD_USER_DATA_BYTES + current.byteLength,
      );
      let pos = sectorOffset;
      while (pos < sectorEnd && files.length < MAX_ISO_FILES) {
        const recLen = userData[pos] ?? 0;
        if (recLen === 0) break;
        if (pos + recLen > sectorEnd || recLen < 34) break;
        const extentLba = readLe32(userData, pos + 2);
        const dataLen = readLe32(userData, pos + 10);
        const flags = userData[pos + 25] ?? 0;
        const nameLen = userData[pos + 32] ?? 0;
        if (pos + 33 + nameLen <= pos + recLen && nameLen > 0) {
          const firstByte = userData[pos + 33] ?? 0;
          const isDotOrDotDot =
            nameLen === 1 && (firstByte === 0 || firstByte === 1);
          if (!isDotOrDotDot) {
            const rawName = Buffer.from(
              userData.subarray(pos + 33, pos + 33 + nameLen),
            )
              .toString("latin1")
              .replace(/;\d+$/u, "");
            const fullPath = `${current.path}/${rawName}`;
            const isDirectory = (flags & 0x02) !== 0;
            if (isDirectory) {
              if (
                !visitedDirs.has(extentLba) &&
                visitedDirs.size < MAX_ISO_DIRS
              ) {
                visitedDirs.add(extentLba);
                queue.push({
                  path: fullPath,
                  extentLba,
                  byteLength: dataLen,
                });
              }
            } else {
              const trackSector = extentLba - baseLba;
              const sectors = Math.max(
                0,
                Math.ceil(dataLen / CD_USER_DATA_BYTES),
              );
              if (trackSector >= 0 && trackSector <= totalSectors) {
                files.push({
                  path: fullPath,
                  extent_lba: extentLba,
                  track_sector: trackSector,
                  user_data_offset: trackSector * CD_USER_DATA_BYTES,
                  size: dataLen,
                  sectors,
                });
              }
            }
          }
        }
        pos += recLen;
      }
    }
  }
  return files.sort(
    (a, b) => a.extent_lba - b.extent_lba || a.path.localeCompare(b.path),
  );
};

const computeUnallocatedGaps = (
  files: readonly Iso9660FileEntry[],
  baseLba: number,
  totalSectors: number,
): Iso9660UnallocatedGap[] => {
  const gaps: Iso9660UnallocatedGap[] = [];
  if (files.length === 0) return gaps;
  const trackEndLba = baseLba + totalSectors;
  let cursorLba = files[0]!.extent_lba;
  let lastFilePath: string | null = null;
  for (const file of files) {
    if (file.extent_lba > cursorLba) {
      const startSector = cursorLba - baseLba;
      const sectors = file.extent_lba - cursorLba;
      gaps.push({
        start_lba: cursorLba,
        end_lba: file.extent_lba - 1,
        start_sector: startSector,
        sectors,
        byte_length: sectors * CD_USER_DATA_BYTES,
        user_data_offset: startSector * CD_USER_DATA_BYTES,
        after_file: lastFilePath,
        before_file: file.path,
      });
    }
    const fileEnd = file.extent_lba + Math.max(1, file.sectors);
    if (fileEnd > cursorLba) {
      cursorLba = fileEnd;
      lastFilePath = file.path;
    }
  }
  if (cursorLba < trackEndLba) {
    const startSector = cursorLba - baseLba;
    const sectors = trackEndLba - cursorLba;
    gaps.push({
      start_lba: cursorLba,
      end_lba: trackEndLba - 1,
      start_sector: startSector,
      sectors,
      byte_length: sectors * CD_USER_DATA_BYTES,
      user_data_offset: startSector * CD_USER_DATA_BYTES,
      after_file: lastFilePath,
      before_file: null,
    });
  }
  return gaps;
};

/** Parse ISO9660 Primary Volume Descriptor, directory tree, and free sector gaps. */
export const parseIso9660FileSystem = (
  userData: Uint8Array,
  firstLba = 0,
): Iso9660FileSystem | undefined => {
  const totalSectors = Math.floor(userData.length / CD_USER_DATA_BYTES);
  if (totalSectors <= 16) return undefined;
  const pvdOffset = 16 * CD_USER_DATA_BYTES;
  if (
    userData[pvdOffset] !== 1 ||
    asciiField(userData, pvdOffset + 1, pvdOffset + 6) !== "CD001"
  )
    return undefined;
  const volumeSpaceSectors = readLe32(userData, pvdOffset + 80);
  const rootRecordOffset = pvdOffset + 156;
  const rootExtentLba = readLe32(userData, rootRecordOffset + 2);
  const rootSizeBytes = readLe32(userData, rootRecordOffset + 10);
  // Determine whether directory extent LBAs are 0-based relative to the image
  // or offset by the track's absolute firstLba (e.g. Dreamcast LBA 45000).
  const baseLba =
    firstLba > 0 &&
    rootExtentLba >= firstLba &&
    rootExtentLba - firstLba < totalSectors
      ? firstLba
      : 0;
  const files = walkIsoDirectories(
    userData,
    totalSectors,
    baseLba,
    rootExtentLba,
    rootSizeBytes,
  );
  return {
    system_id: asciiField(userData, pvdOffset + 8, pvdOffset + 40),
    volume_id: asciiField(userData, pvdOffset + 40, pvdOffset + 72),
    publisher_id: asciiField(userData, pvdOffset + 318, pvdOffset + 446),
    data_preparer_id: asciiField(userData, pvdOffset + 446, pvdOffset + 574),
    application_id: asciiField(userData, pvdOffset + 574, pvdOffset + 702),
    volume_space_sectors: volumeSpaceSectors,
    base_lba: baseLba,
    files,
    unallocated_gaps: computeUnallocatedGaps(files, baseLba, totalSectors),
  };
};

/** Resolve LBAs and user-data byte offsets to ISO9660 files or disc regions. */
export const resolveDiscLocations = (options: {
  readonly userDataLength: number;
  readonly firstLba: number;
  readonly iso9660: Iso9660FileSystem | null;
  readonly lbas?: readonly number[];
  readonly offsets?: readonly number[];
}): DiscResolvedLocation[] => {
  const totalSectors = Math.floor(options.userDataLength / CD_USER_DATA_BYTES);
  const baseLba = options.iso9660?.base_lba ?? options.firstLba;
  const classify = (
    queryKind: "lba" | "user_data_offset",
    queryValue: number,
    trackSector: number,
    offsetInSector: number,
  ): DiscResolvedLocation => {
    const lba = baseLba + trackSector;
    const userDataOffset = trackSector * CD_USER_DATA_BYTES + offsetInSector;
    if (trackSector < 0 || trackSector >= totalSectors) {
      return {
        query_kind: queryKind,
        query_value: queryValue,
        lba,
        track_sector: trackSector,
        offset_in_sector: offsetInSector,
        user_data_offset: userDataOffset,
        region: "out_of_range",
        file_path: null,
        offset_in_file: null,
        file_extent_lba: null,
        file_size: null,
      };
    }
    if (trackSector < 16) {
      return {
        query_kind: queryKind,
        query_value: queryValue,
        lba,
        track_sector: trackSector,
        offset_in_sector: offsetInSector,
        user_data_offset: userDataOffset,
        region: "system_area",
        file_path: null,
        offset_in_file: null,
        file_extent_lba: null,
        file_size: null,
      };
    }
    const hit = options.iso9660?.files.find(
      (f) =>
        trackSector >= f.track_sector &&
        trackSector < f.track_sector + Math.max(1, f.sectors),
    );
    if (hit !== undefined) {
      const offsetInFile = userDataOffset - hit.user_data_offset;
      return {
        query_kind: queryKind,
        query_value: queryValue,
        lba,
        track_sector: trackSector,
        offset_in_sector: offsetInSector,
        user_data_offset: userDataOffset,
        region: "file",
        file_path: hit.path,
        offset_in_file: offsetInFile,
        file_extent_lba: hit.extent_lba,
        file_size: hit.size,
      };
    }
    const inGap = options.iso9660?.unallocated_gaps.some(
      (g) =>
        trackSector >= g.start_sector &&
        trackSector < g.start_sector + g.sectors,
    );
    return {
      query_kind: queryKind,
      query_value: queryValue,
      lba,
      track_sector: trackSector,
      offset_in_sector: offsetInSector,
      user_data_offset: userDataOffset,
      region: inGap ? "unallocated_gap" : "iso9660_metadata",
      file_path: null,
      offset_in_file: null,
      file_extent_lba: null,
      file_size: null,
    };
  };
  const results: DiscResolvedLocation[] = [];
  for (const lba of options.lbas ?? []) {
    const trackSector =
      lba >= baseLba && lba - baseLba < totalSectors ? lba - baseLba : lba;
    results.push(classify("lba", lba, trackSector, 0));
  }
  for (const offset of options.offsets ?? []) {
    const trackSector = Math.floor(offset / CD_USER_DATA_BYTES);
    const offsetInSector =
      ((offset % CD_USER_DATA_BYTES) + CD_USER_DATA_BYTES) % CD_USER_DATA_BYTES;
    results.push(
      classify("user_data_offset", offset, trackSector, offsetInSector),
    );
  }
  return results;
};
