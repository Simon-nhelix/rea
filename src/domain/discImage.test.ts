import { describe, expect, it } from "vitest";
import {
  CD_USER_DATA_BYTES,
  extractDataTrackUserData,
  parseCueSheet,
  parsePceCdIpl,
  RAW_CD_SECTOR_BYTES,
  resolveFirstDataTrack,
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
