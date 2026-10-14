import { describe, expect, it } from "vitest";
import {
  decodeRomStringFromBytes,
  encodeRomQueryString,
  extractRomStringsFromBuffer,
  formatHexPattern,
  parseCustomCharTable,
  readPointerValue,
} from "./romHacking.js";

describe("romHacking domain primitives", () => {
  it("encodes and decodes Shift-JIS (sjis) Japanese strings", () => {
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

  it("parses custom .tbl files with multi-byte tokens and control codes", () => {
    const tblResult = parseCustomCharTable(
      [
        "# Sample RPG Korean/Japanese table",
        "8140= ",
        "9001=용",
        "9002=사",
        "FE=<BR>",
        "/FF=<END>",
      ].join("\n"),
    );
    expect(tblResult.ok).toBe(true);
    if (!tblResult.ok) return;

    const encoded = encodeRomQueryString("용사<BR>", "tbl", tblResult.value);
    expect(encoded.ok).toBe(true);
    if (!encoded.ok) return;
    expect(formatHexPattern(encoded.value).toUpperCase()).toBe(
      "90 01 90 02 FE",
    );

    const bytes = Buffer.from([0x90, 0x01, 0x90, 0x02, 0xfe, 0xff]);
    const decoded = decodeRomStringFromBytes(
      bytes,
      "tbl",
      0x00,
      tblResult.value,
    );
    expect(decoded.decoded).toBe("용사<BR><END>");
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
