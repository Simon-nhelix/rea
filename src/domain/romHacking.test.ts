import { describe, expect, it } from "vitest";
import {
  computePointerSlotBudgets,
  decodeRomStringFromBytes,
  encodeRomQueryString,
  extractRomStringsFromBuffer,
  findCodeCavesInSlice,
  findCodeCavesInSliceTopK,
  formatHexPattern,
  formatRomScanCursor,
  normalizeRomTextEncoding,
  parseCustomCharTable,
  parseRomScanCursor,
  readPointerValue,
  resolveRomWordFormat,
  scanPointerTableInputSchema,
  scanRomStrings,
  searchRomStringsInputSchema,
} from "./romHacking.js";
import { NO_ROM_TEXT_FILTERS } from "./romTextQuality.js";

describe("romHacking input defaults", () => {
  it("defaults to provider-free Mode A with compact output", () => {
    const search = searchRomStringsInputSchema.parse({ query: "勇者" });
    expect(search.resolve_xrefs).toBe(false);
    expect(search.include_hex).toBe(false);
    expect(search.cursor).toBeUndefined();

    const scan = scanPointerTableInputSchema.parse({ table_offset: 0 });
    expect(scan.resolve_xrefs).toBe(false);
    expect(scan.include_hex).toBe(false);
    expect(scan.manuscript_only).toBe(false);
    expect(scan.start_index).toBe(0);
  });
});

describe("romHacking domain primitives", () => {
  it("encodes and decodes Shift-JIS (sjis) Japanese strings and encoding aliases", () => {
    expect(normalizeRomTextEncoding("utf8")).toBe("utf-8");
    expect(normalizeRomTextEncoding("utf16le")).toBe("utf-16le");
    expect(normalizeRomTextEncoding("utf16be")).toBe("utf-16be");

    // "勇者" in Shift-JIS: 勇 = 0x97 0x45, 者 = 0x8e 0xd2
    const encoded = encodeRomQueryString("勇者", "sjis");
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    expect(formatHexPattern(encoded.value).toUpperCase()).toBe("97 45 8E D2");

    const bytes = Buffer.from([0x97, 0x45, 0x8e, 0xd2, 0x00, 0xff]);
    const decoded = decodeRomStringFromBytes(bytes, "sjis", 0x00);
    expect(decoded.decoded).toBe("勇者");
    expect(decoded.byteLength).toBe(5);
  });

  it("parses custom .tbl files with multi-byte tokens, 00 character mapping, and control codes", () => {
    const tblResult = parseCustomCharTable(
      [
        "# Sample RPG Korean/Japanese table where 00 is a space and /FF is END",
        "00= ",
        "8140=　",
        "9001=용",
        "9002=사",
        "FE=<BR>",
        "/FF=<END>",
      ].join("\n"),
    );
    expect(tblResult.ok).toBe(true);
    if (!tblResult.ok) return;

    const encoded = encodeRomQueryString("용 사<BR>", "tbl", tblResult.value);
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    expect(formatHexPattern(encoded.value).toUpperCase()).toBe(
      "90 01 00 90 02 FE",
    );

    const bytes = Buffer.from([0x90, 0x01, 0x00, 0x90, 0x02, 0xfe, 0xff]);
    const decoded = decodeRomStringFromBytes(
      bytes,
      "tbl",
      0x00,
      tblResult.value,
    );
    expect(decoded.decoded).toBe("용 사<BR><END>");
  });

  it("extracts multiple Shift-JIS strings from a buffer with addresses", () => {
    // Two null-terminated Shift-JIS strings at 0x08001000
    const buf = Buffer.from([
      0x97,
      0x45,
      0x8e,
      0xd2,
      0x00, // "勇者\0"
      0x00,
      0x96,
      0x82,
      0x96,
      0x40,
      0x00, // "魔法\0"
    ]);
    const extracted = extractRomStringsFromBuffer({
      bytes: buf,
      baseAddress: 0x08001000n,
      encoding: "sjis",
      minLength: 2,
      terminatorByte: 0x00,
      limit: 10,
    });
    expect(extracted).toHaveLength(2);
    expect(extracted[0]?.address).toBe("0x8001000");
    expect(extracted[0]?.decoded).toBe("勇者");
    expect(extracted[1]?.address).toBe("0x8001006");
    expect(extracted[1]?.decoded).toBe("魔法");
  });

  it("scans large ASCII padding before a Shift-JIS string in one pass", () => {
    const buf = Buffer.alloc(0x40000 + 6, 0x20);
    buf[0x40000] = 0x00;
    Buffer.from([0x97, 0x45, 0x8e, 0xd2, 0x00]).copy(buf, 0x40001);
    const start = performance.now();
    const extracted = extractRomStringsFromBuffer({
      bytes: buf,
      baseAddress: 0x08000000n,
      encoding: "sjis",
      minLength: 2,
      terminatorByte: 0x00,
      limit: 10,
    });
    // The previous cursor++ re-scan was O(n^2) here (16 KiB alone took >10s).
    expect(performance.now() - start).toBeLessThan(2000);
    expect(extracted).toHaveLength(1);
    expect(extracted[0]?.offsetInBuffer).toBe(0x40001);
    expect(extracted[0]?.decoded).toBe("勇者");
  });

  it("extracts EUC-JP strings and can skip raw hex formatting", () => {
    // "勇者" in EUC-JP: 勇 = 0xCD 0xA6, 者 = 0xBC 0xD4
    const buf = Buffer.from([0xcd, 0xa6, 0xbc, 0xd4, 0x00]);
    const extracted = extractRomStringsFromBuffer({
      bytes: buf,
      baseAddress: 0n,
      encoding: "euc-jp",
      minLength: 2,
      terminatorByte: 0x00,
      limit: 10,
      includeRawHex: false,
    });
    expect(extracted).toHaveLength(1);
    expect(extracted[0]?.decoded).toBe("勇者");
    expect(extracted[0]?.rawHex).toBe("");
  });

  it("reads 16-bit, 24-bit, and 32-bit pointers", () => {
    const buf = Buffer.from([
      0x34, 0x12, 0x56, 0x34, 0x12, 0x00, 0x20, 0x00, 0x08,
    ]);
    const p16 = readPointerValue(buf, 0, 2, "little");
    expect(`0x${(0x08000000n + p16).toString(16)}`).toBe("0x8001234");

    const p24 = readPointerValue(buf, 2, 3, "little");
    expect(`0x${(0xc00000n + p24).toString(16)}`).toBe("0xd23456");

    const p32 = readPointerValue(buf, 5, 4, "little");
    expect(`0x${p32.toString(16)}`).toBe("0x8002000");
  });
});

describe("romHacking budgets and code caves", () => {
  it("computes pointer slot budgets and finds aligned code caves", () => {
    const budgets = computePointerSlotBudgets([
      {
        target_file_offset: 0x1000,
        target_address: "0x8001000",
        preview_byte_length: 8,
      },
      {
        target_file_offset: 0x1010,
        target_address: "0x8001010",
        preview_byte_length: 6,
      },
    ]);
    expect(budgets).toEqual([16, 6]);

    const romSlice = Buffer.alloc(128, 0x11);
    romSlice.fill(0xff, 10, 90); // 80 bytes of 0xFF starting at offset 10 -> aligned to 12, length 78
    const caves = findCodeCavesInSlice({
      bytes: romSlice,
      sliceFileOffset: 0x2000,
      regionName: "ROM",
      executable: true,
      minSize: 64,
      alignment: 4,
      toVirtualAddress: (fo) => `0x${(0x08000000 + fo).toString(16)}`,
    });
    expect(caves).toEqual([
      {
        address: "0x800200c",
        file_offset: 0x200c,
        byte_length: 78,
        fill_byte: "0xff",
        region_name: "ROM",
        executable: true,
      },
    ]);
  });

  it("keeps only top-K caves while counting every cave", () => {
    const romSlice = Buffer.alloc(256, 0x11);
    romSlice.fill(0xff, 0, 32);
    romSlice.fill(0x00, 64, 160);
    romSlice.fill(0xff, 192, 240);
    const top = findCodeCavesInSliceTopK({
      bytes: romSlice,
      sliceFileOffset: 0,
      regionName: "ROM",
      executable: true,
      minSize: 16,
      alignment: 1,
      toVirtualAddress: (fo) => `0x${fo.toString(16)}`,
      limit: 2,
    });
    expect(top.total).toBe(3);
    expect(top.caves.map((cave) => cave.byte_length)).toEqual([96, 48]);
  });
});

describe("16-bit word encodings", () => {
  /** sjis-le16 words: どう = 82C7 82A4 stored as C7 82 A4 82. */
  const le16 = (...words: number[]): number[] =>
    words.flatMap((word) => [word & 0xff, word >>> 8]);
  const lodossFormat = () => {
    const format = resolveRomWordFormat({
      encoding: "sjis-le16",
      terminatorByte: 0x00,
      terminatorWord: 0xffff,
      newlineWord: 0xfffe,
    });
    if (!format.ok || format.value === undefined)
      throw new Error("format did not resolve");
    return format.value;
  };

  it("encodes and decodes byte-swapped Shift-JIS words with control words", () => {
    const words = lodossFormat();
    const encoded = encodeRomQueryString(
      "どう\nか",
      "sjis-le16",
      undefined,
      words,
    );
    expect(encoded.ok && formatHexPattern(encoded.value)).toBe(
      "c7 82 a4 82 fe ff a9 82",
    );
    const bytes = Uint8Array.from([
      ...le16(0x82c7, 0x82a4, 0xfffe, 0x82a9, 0xffff),
      0x41,
    ]);
    expect(
      decodeRomStringFromBytes(bytes, "sjis-le16", 0x00, undefined, words),
    ).toMatchObject({ decoded: "どう\nか", byteLength: 10 });
    // Single-byte characters have no word form.
    expect(encodeRomQueryString("A", "sjis-le16", undefined, words).ok).toBe(
      false,
    );
  });

  it("scans both word parities and resumes pages without changing boundaries", () => {
    const words = lodossFormat();
    // Even-aligned 「どう」 at 0, odd-aligned 「かな」 at 7, even 「よ」 at 14.
    const bytes = Uint8Array.from([
      ...le16(0x82c7, 0x82a4, 0xffff),
      0x00,
      ...le16(0x82a9, 0x82c8, 0xffff),
      0x00,
      ...le16(0x82e6, 0xffff),
    ]);
    const scan = {
      bytes,
      baseAddress: 0n,
      encoding: "sjis-le16" as const,
      minLength: 1,
      terminatorByte: 0x00,
      words,
      includeRawHex: false,
      requireTerminator: true,
    };
    const all = [...scanRomStrings(scan)];
    expect(all.map((item) => [item.offsetInBuffer, item.decoded])).toEqual([
      [0, "どう"],
      [7, "かな"],
      [14, "よ"],
    ]);
    expect(all.every((item) => item.terminated)).toBe(true);
    expect(
      [...scanRomStrings({ ...scan, wordParity: "even" })].map(
        (item) => item.decoded,
      ),
    ).toEqual(["どう", "よ"]);

    // Page 1 = first item; page 2 resumes from the second item's cursor.
    const cursor = formatRomScanCursor(all[1]!.resume);
    expect(cursor).toBe("w14.7");
    const resume = parseRomScanCursor(cursor, {
      word: true,
      bufferLength: bytes.length,
      parityOrigin: 0,
    });
    expect(resume.ok).toBe(true);
    if (!resume.ok) return;
    expect(
      [...scanRomStrings({ ...scan, resume: resume.value })].map(
        (item) => item.decoded,
      ),
    ).toEqual(["かな", "よ"]);
    // A head whose parity does not match is rejected.
    expect(
      parseRomScanCursor("w7.14", {
        word: true,
        bufferLength: bytes.length,
        parityOrigin: 0,
      }).ok,
    ).toBe(false);
  });
});

describe("tilemap word encodings", () => {
  it("decodes tilemap words through a tile table with attribute rules", () => {
    const table = parseCustomCharTable("0110=0\n0111=1\n0170=ア\n0171=イ");
    expect(table.ok).toBe(true);
    if (!table.ok) return;
    const anyAttribute = resolveRomWordFormat({
      encoding: "tile-le16",
      terminatorByte: 0x00,
      customTable: table.value,
    });
    expect(anyAttribute.ok).toBe(true);
    if (!anyAttribute.ok || anyAttribute.value === undefined) return;
    // F170 F171 0000 | E110 F111 0000: the second string changes palette.
    const bytes = Uint8Array.from([
      0x70, 0xf1, 0x71, 0xf1, 0x00, 0x00, 0x10, 0xe1, 0x11, 0xf1, 0x00, 0x00,
    ]);
    const found = [
      ...scanRomStrings({
        bytes,
        baseAddress: 0n,
        encoding: "tile-le16",
        minLength: 1,
        terminatorByte: 0x00,
        words: anyAttribute.value,
        wordParity: "even",
      }),
    ];
    expect(
      found.map((item) => [item.offsetInBuffer, item.decoded, item.terminated]),
    ).toEqual([
      [0, "アイ", true],
      [6, "0", false],
      [8, "1", true],
    ]);
    const fixed = resolveRomWordFormat({
      encoding: "tile-le16",
      terminatorByte: 0x00,
      tileAttribute: 0xf000,
      customTable: table.value,
    });
    if (!fixed.ok || fixed.value === undefined) throw new Error("no format");
    const query = encodeRomQueryString(
      "アイ",
      "tile-le16",
      table.value,
      fixed.value,
    );
    expect(query.ok && formatHexPattern(query.value)).toBe("70 f1 71 f1");
  });

  it("rejects word options that do not apply to the chosen encoding", () => {
    expect(
      resolveRomWordFormat({
        encoding: "sjis",
        terminatorByte: 0x00,
        terminatorWord: 0xffff,
      }).ok,
    ).toBe(false);
    expect(
      resolveRomWordFormat({
        encoding: "sjis-le16",
        terminatorByte: 0x00,
        terminatorWord: 0xffff,
        newlineWord: 0xffff,
      }).ok,
    ).toBe(false);
    expect(
      resolveRomWordFormat({ encoding: "tile-be16", terminatorByte: 0x00 }).ok,
    ).toBe(false);
    const table = parseCustomCharTable("1110=x");
    if (!table.ok) throw new Error("table");
    // Key 0x1110 has bits outside the default 12-bit tile mask.
    expect(
      resolveRomWordFormat({
        encoding: "tile-be16",
        terminatorByte: 0x00,
        customTable: table.value,
      }).ok,
    ).toBe(false);
  });
});

describe("range-scan noise filters", () => {
  it("lets fullwidth_only split ASCII noise away from Shift-JIS text", () => {
    // "mT" + 「勇者」 + NUL: without the filter the noise prefix sticks.
    const bytes = Uint8Array.from([0x6d, 0x54, 0x97, 0x45, 0x8e, 0xd2, 0x00]);
    const scan = {
      bytes,
      baseAddress: 0n,
      encoding: "sjis" as const,
      minLength: 2,
      terminatorByte: 0x00,
    };
    expect([...scanRomStrings(scan)].map((item) => item.decoded)).toEqual([
      "mT勇者",
    ]);
    const filtered = [
      ...scanRomStrings({
        ...scan,
        filters: { ...NO_ROM_TEXT_FILTERS, fullwidthOnly: true },
        measure: true,
      }),
    ];
    expect(filtered.map((item) => [item.offsetInBuffer, item.decoded])).toEqual(
      [[2, "勇者"]],
    );
    expect(filtered[0]?.score).toBeGreaterThan(0.7);
  });
});
