import { describe, expect, it } from "vitest";
import { iso9660Fixture } from "../../tests/fixtures/iso9660.js";
import {
  CD_USER_DATA_BYTES,
  detectRawSectorLayout,
  extractDataTrackUserData,
  parseCueSheet,
  parseGdiSheet,
  parseIso9660FileSystem,
  parsePceCdIpl,
  parsePlayStationSystemCnf,
  parseSegaIpBin,
  RAW_CD_SECTOR_BYTES,
  resolveDiscLocations,
  resolveFirstDataTrack,
  resolveGdiDataTrack,
} from "./discImage.js";

/** Redump-style multi-file sheet: audio track 1, data track 2 with a pregap. */
const MULTI_FILE_CUE = [
  "CATALOG 0000000000000",
  'FILE "Game (Track 01).bin" BINARY',
  "  TRACK 01 AUDIO",
  "    INDEX 01 00:00:00",
  'FILE "Game (Track 02).bin" BINARY',
  "  TRACK 02 MODE1/2352",
  "    INDEX 00 00:00:00",
  "    INDEX 01 00:02:74",
  'FILE "Game (Track 03).bin" BINARY',
  "  TRACK 03 MODE1/2352",
  "    INDEX 01 00:00:00",
].join("\r\n");

const modeOneSector = (lba: number, fill: number): Uint8Array => {
  const sector = new Uint8Array(RAW_CD_SECTOR_BYTES);
  sector.set([0x00, ...Array<number>(10).fill(0xff), 0x00], 0);
  const msf = lba + 150;
  const bcd = (value: number): number =>
    ((Math.floor(value / 10) << 4) | (value % 10)) & 0xff;
  sector[12] = bcd(Math.floor(msf / 4500));
  sector[13] = bcd(Math.floor(msf / 75) % 60);
  sector[14] = bcd(msf % 75);
  sector[15] = 1;
  sector.fill(fill, 16, 16 + CD_USER_DATA_BYTES);
  return sector;
};

describe("cue sheet layout", () => {
  it("locates the first data track's INDEX 01 as an absolute LBA", () => {
    const sheet = parseCueSheet(MULTI_FILE_CUE);
    expect(sheet.ok).toBe(true);
    if (!sheet.ok) return;
    expect(sheet.value.files.map((file) => file.name)).toEqual([
      "Game (Track 01).bin",
      "Game (Track 02).bin",
      "Game (Track 03).bin",
    ]);
    const layout = resolveFirstDataTrack(
      sheet.value,
      new Map([
        ["Game (Track 01).bin", 1911 * RAW_CD_SECTOR_BYTES],
        ["Game (Track 02).bin", 23002 * RAW_CD_SECTOR_BYTES],
        ["Game (Track 03).bin", 10 * RAW_CD_SECTOR_BYTES],
      ]),
    );
    expect(layout).toEqual({
      ok: true,
      value: {
        track: 2,
        mode: "MODE1/2352",
        fileName: "Game (Track 02).bin",
        rawSectorBytes: 2352,
        userDataOffset: 16,
        // INDEX 01 00:02:74 = 2 * 75 + 74 frames into the file.
        firstSectorInFile: 224,
        sectorCount: 23002 - 224,
        firstLba: 1911 + 224,
        otherDataTracks: [3],
      },
    });
  });

  it("ends a single-file track at the next track's INDEX 00 and counts PREGAP", () => {
    const sheet = parseCueSheet(
      [
        'FILE "disc.bin" BINARY',
        "  TRACK 01 AUDIO",
        "    INDEX 01 00:00:00",
        "  TRACK 02 MODE1/2048",
        "    PREGAP 00:02:00",
        "    INDEX 01 00:01:00",
        "  TRACK 03 AUDIO",
        "    INDEX 00 00:01:50",
        "    INDEX 01 00:01:60",
      ].join("\n"),
    );
    expect(sheet.ok).toBe(true);
    if (!sheet.ok) return;
    const layout = resolveFirstDataTrack(
      sheet.value,
      new Map([["disc.bin", 200 * 2048]]),
    );
    expect(layout.ok).toBe(false);
    if (layout.ok) return;
    expect(layout.error).toContain("mixes sector sizes");

    const audioFree = parseCueSheet(
      [
        'FILE "data.iso" BINARY',
        "  TRACK 01 MODE1/2048",
        "    INDEX 01 00:00:00",
        "  TRACK 02 MODE1/2048",
        "    PREGAP 00:02:00",
        "    INDEX 00 00:01:00",
        "    INDEX 01 00:01:10",
      ].join("\n"),
    );
    expect(audioFree.ok).toBe(true);
    if (!audioFree.ok) return;
    const first = resolveFirstDataTrack(
      audioFree.value,
      new Map([["data.iso", 300 * 2048]]),
    );
    expect(first.ok && first.value).toMatchObject({
      track: 1,
      firstSectorInFile: 0,
      sectorCount: 75,
      firstLba: 0,
      otherDataTracks: [2],
    });
  });

  it("rejects malformed sheets and unsupported data modes", () => {
    expect(parseCueSheet("TRACK 01 AUDIO").ok).toBe(false);
    expect(parseCueSheet('FILE "a.bin" BINARY\n  TRACK 01 AUDIO\n').ok).toBe(
      false,
    );
    expect(
      parseCueSheet(
        'FILE "a.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:61:00',
      ).ok,
    ).toBe(false);
    const cdi = parseCueSheet(
      'FILE "a.bin" BINARY\n  TRACK 01 CDI/2352\n    INDEX 01 00:00:00',
    );
    expect(cdi.ok).toBe(true);
    if (!cdi.ok) return;
    const layout = resolveFirstDataTrack(
      cdi.value,
      new Map([["a.bin", 2352 * 4]]),
    );
    expect(layout.ok).toBe(false);
  });
});

describe("data track user data", () => {
  it("concatenates Mode 1 user data and counts sectors with bad headers", () => {
    const raw = new Uint8Array(RAW_CD_SECTOR_BYTES * 3);
    raw.set(modeOneSector(100, 0x11), 0);
    raw.set(modeOneSector(101, 0x22), RAW_CD_SECTOR_BYTES);
    // A zero-filled sector has no sync pattern.
    const user = extractDataTrackUserData(raw, {
      mode: "MODE1/2352",
      rawSectorBytes: RAW_CD_SECTOR_BYTES,
      userDataOffset: 16,
      sectorCount: 3,
    });
    expect(user.bytes.length).toBe(3 * CD_USER_DATA_BYTES);
    expect(user.bytes[0]).toBe(0x11);
    expect(user.bytes[CD_USER_DATA_BYTES - 1]).toBe(0x11);
    expect(user.bytes[CD_USER_DATA_BYTES]).toBe(0x22);
    expect(user.mismatchedSectors).toBe(1);
    expect(user.firstMismatchedSector).toBe(2);
  });
});

describe("PC Engine CD IPL record", () => {
  it("parses the boot record fields from sector 1", () => {
    const sector = new Uint8Array(CD_USER_DATA_BYTES);
    sector.set([0x00, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0x30], 0);
    sector.set([0x00, 0x01, 0x02, 0x03, 0x04], 0x08);
    const ascii = (text: string, at: number): void =>
      sector.set(new TextEncoder().encode(text), at);
    ascii("PC Engine CD-ROM SYSTEM", 0x20);
    ascii("Copyright HUDSON SOFT / NEC Home Electronics,Ltd.", 0x38);
    ascii("LODOSS 2        ", 0x6a);
    expect(parsePceCdIpl(sector, 1)).toMatchObject({
      sector: 1,
      iplblk: 2,
      iplbln: 1,
      iplsta: "0x3000",
      ipljmp: "0x3000",
      mpr2_6: ["0x00", "0x01", "0x02", "0x03", "0x04"],
      program_name: "LODOSS 2",
      copyright: "Copyright HUDSON SOFT / NEC Home Electronics,Ltd.",
      boot_program: {
        first_sector: 2,
        sectors: 1,
        user_data_offset: 4096,
        byte_length: 2048,
      },
    });
    expect(parsePceCdIpl(new Uint8Array(CD_USER_DATA_BYTES), 1)).toBe(
      undefined,
    );
  });
});

describe("Dreamcast GDI, raw sector detection, IP.BIN, SYSTEM.CNF, and ISO9660", () => {
  it("honors a GDI track file offset and rejects ambiguous or malformed placement", () => {
    const parsed = parseGdiSheet("1\n3 45000 4 2352 track.bin 2352");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(
      resolveGdiDataTrack(parsed.value, new Map([["track.bin", 3 * 2352]])),
    ).toMatchObject({
      ok: true,
      value: { firstSectorInFile: 1, sectorCount: 2 },
    });
    expect(
      resolveGdiDataTrack(parsed.value, new Map([["track.bin", 2352]])).ok,
    ).toBe(false);
    expect(parseGdiSheet("2\n3 45000 4 2352 track.bin 0").ok).toBe(false);
    expect(parseGdiSheet("1\n3 45000 4 2352 track.bin -1").ok).toBe(false);
    const unaligned = parseGdiSheet("1\n3 45000 4 2352 track.bin 1");
    if (unaligned.ok)
      expect(
        resolveGdiDataTrack(unaligned.value, new Map([["track.bin", 3 * 2352]]))
          .ok,
      ).toBe(false);
  });
  it("parses Dreamcast .gdi sheets and selects the high-density data track", () => {
    const gdiText = [
      "3",
      "1 0 4 2352 track01.bin 0",
      "2 450 0 2352 track02.raw 0",
      '3 45000 4 2048 "track03.iso" 0',
    ].join("\n");
    const parsed = parseGdiSheet(gdiText);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const layout = resolveGdiDataTrack(
      parsed.value,
      new Map([
        ["track01.bin", 300 * 2352],
        ["track03.iso", 100 * 2048],
      ]),
    );
    expect(layout).toEqual({
      ok: true,
      value: {
        track: 3,
        mode: "MODE1/2048",
        fileName: "track03.iso",
        rawSectorBytes: 2048,
        userDataOffset: 0,
        firstSectorInFile: 0,
        sectorCount: 100,
        firstLba: 45000,
        otherDataTracks: [1],
      },
    });
  });

  it("auto-detects raw 2352-byte Mode 1 sectors", () => {
    const raw = modeOneSector(0, 0xaa);
    expect(detectRawSectorLayout("track.bin", raw)).toMatchObject({
      track: 1,
      mode: "MODE1/2352",
      rawSectorBytes: 2352,
      userDataOffset: 16,
      sectorCount: 1,
    });
    expect(detectRawSectorLayout("track.bin", new Uint8Array(2352))).toBe(
      undefined,
    );
  });

  it("parses Sega Saturn and Dreamcast IP.BIN headers and PlayStation SYSTEM.CNF", () => {
    const saturn = new Uint8Array(2048);
    const enc = (text: string, at: number) =>
      saturn.set(new TextEncoder().encode(text), at);
    enc("SEGA SEGASATURN ", 0x00);
    enc("SEGA ENTERPRISES", 0x10);
    enc("GS-9123   ", 0x20);
    enc("V1.000", 0x2a);
    enc("19970718", 0x30);
    enc("CD-1/1  ", 0x38);
    enc("J         ", 0x40);
    enc("J               ", 0x50);
    enc("MAGIC KNIGHT RAYEARTH", 0x60);
    saturn.set([0x06, 0x00, 0x40, 0x00], 0xf0);
    expect(parseSegaIpBin(saturn)).toMatchObject({
      platform: "saturn",
      product_number: "GS-9123",
      version: "V1.000",
      title: "MAGIC KNIGHT RAYEARTH",
      first_read_address: "0x06004000",
    });

    const dc = new Uint8Array(2048);
    const encDc = (text: string, at: number) =>
      dc.set(new TextEncoder().encode(text), at);
    encDc("SEGA SEGAKATANA ", 0x00);
    encDc("SEGA ENTERPRISES", 0x10);
    encDc("1234 GD-ROM1/1  ", 0x20);
    encDc("JUE     ", 0x30);
    encDc("0799A10 ", 0x38);
    encDc("HDR-0078  ", 0x40);
    encDc("V1.002", 0x4a);
    encDc("20000525        ", 0x50);
    encDc("1ST_READ.BIN    ", 0x60);
    encDc("SEGA ENTERPRISES", 0x70);
    encDc("RENT A HERO NO.1", 0x80);
    expect(parseSegaIpBin(dc)).toMatchObject({
      platform: "dreamcast",
      product_number: "HDR-0078",
      boot_filename: "1ST_READ.BIN",
      title: "RENT A HERO NO.1",
      first_read_address: "0x8c010000",
    });

    expect(
      parsePlayStationSystemCnf(
        "BOOT2 = cdrom0:\\SLPS_250.88;1\r\nVER = 1.01\r\nVMODE = NTSC\r\n",
      ),
    ).toEqual({
      platform: "ps2",
      boot_raw: "cdrom0:\\SLPS_250.88;1",
      boot_path: "/SLPS_250.88",
      version: "1.01",
      vmode: "NTSC",
      tcb: null,
      event: null,
      stack: null,
    });
  });
});

describe("ISO9660 file system and LBA/offset resolution", () => {
  it("reserves directory and both path table extents between files", () => {
    const image = iso9660Fixture({ nested: true });
    const iso = parseIso9660FileSystem(image)!;
    expect(iso.allocation_coverage).toBe("complete");
    expect(iso.files.map((f) => f.path)).toContain("/TEXT/DIALOG.BIN");
    const locations = resolveDiscLocations({
      userDataLength: image.length,
      firstLba: 0,
      iso9660: iso,
      lbas: [21, 22, 23, 27],
    });
    expect(locations.map((l) => l.region)).toEqual([
      "iso9660_metadata",
      "iso9660_metadata",
      "iso9660_metadata",
      "unallocated_gap",
    ]);
  });

  it.each(["directory", "descriptor", "file extent"])(
    "retains partial facts without reporting free space after an invalid %s",
    (failure) => {
      const image = iso9660Fixture();
      if (failure === "directory") image[18 * 2048] = 1;
      else if (failure === "descriptor") image[17 * 2048] = 0;
      else image.writeUInt32LE(29, 18 * 2048 + 68 + 46 + 2); // MAIN.EXE extends beyond the volume.
      const iso = parseIso9660FileSystem(image)!;
      expect(iso.allocation_coverage).toBe("partial");
      expect(iso.unallocated_gaps).toEqual([]);
      expect(iso.limitations.length).toBeGreaterThan(1);
    },
  );

  it.each([
    [0, 12],
    [0, 100],
    [45000, 45000],
  ])(
    "separates ISO extent base %i from absolute disc origin %i",
    (extentBase, firstLba) => {
      const image = iso9660Fixture({ extentBase });
      const iso = parseIso9660FileSystem(image, firstLba)!;
      const locations = resolveDiscLocations({
        userDataLength: image.length,
        firstLba,
        iso9660: iso,
        lbas: [firstLba + 20, 20],
        offsets: [20 * 2048],
      });
      expect(locations[0]).toMatchObject({
        lba: firstLba + 20,
        track_sector: 20,
        file_path: "/SYSTEM.CNF",
      });
      expect(locations[1]?.file_path).toBeNull();
      expect(locations[2]).toMatchObject({
        lba: firstLba + 20,
        file_path: "/SYSTEM.CNF",
      });
      expect(iso.unallocated_gaps[0]?.start_lba).toBe(firstLba + 22);
    },
  );

  it("retains an ambiguous ISO extent origin as unknown", () => {
    const image = iso9660Fixture();
    image.copy(image, 6 * 2048, 18 * 2048, 19 * 2048);
    const iso = parseIso9660FileSystem(image, 12)!;
    expect(iso).toMatchObject({
      base_lba: null,
      extent_base_candidates: [0, 12],
      allocation_coverage: "partial",
      files: [],
      unallocated_gaps: [],
    });
  });
  it("parses ISO9660 PVD, directory records, unallocated gaps, and LBA/offset locations", () => {
    const image = iso9660Fixture();

    const iso = parseIso9660FileSystem(image, 0);
    expect(iso).toMatchObject({
      system_id: "PLAYSTATION",
      volume_id: "TEST_DISC",
      volume_space_sectors: 30,
      files: [
        {
          path: "/SYSTEM.CNF",
          extent_lba: 20,
          track_sector: 20,
          size: 42,
          sectors: 1,
        },
        {
          path: "/MAIN.EXE",
          extent_lba: 24,
          track_sector: 24,
          size: 3000,
          sectors: 2,
        },
      ],
      unallocated_gaps: [
        {
          start_lba: 22,
          end_lba: 23,
          sectors: 2,
          after_file: "/SYSTEM.CNF",
          before_file: "/MAIN.EXE",
        },
        {
          start_lba: 26,
          end_lba: 29,
          sectors: 4,
          after_file: "/MAIN.EXE",
          before_file: null,
        },
      ],
    });

    const locations = resolveDiscLocations({
      userDataLength: image.length,
      firstLba: 0,
      iso9660: iso ?? null,
      lbas: [20, 22],
      offsets: [24 * CD_USER_DATA_BYTES + 0x120],
    });
    expect(locations).toMatchObject([
      {
        query_kind: "lba",
        query_value: 20,
        region: "file",
        file_path: "/SYSTEM.CNF",
        offset_in_file: 0,
      },
      {
        query_kind: "lba",
        query_value: 22,
        region: "unallocated_gap",
        file_path: null,
      },
      {
        query_kind: "user_data_offset",
        query_value: 24 * CD_USER_DATA_BYTES + 0x120,
        region: "file",
        file_path: "/MAIN.EXE",
        offset_in_file: 0x120,
      },
    ]);
  });
});
