import { describe, expect, it } from "vitest";

import {
  decodeRomTextWithControlCodes,
  parseRomControlCodes,
  romControlCodeSchema,
  segmentRomTextByControlCodes,
  type RomControlCodeInput,
  type RomGlyphReader,
} from "./romControlCodes.js";

/** One code as a caller writes it, before the schema applies its defaults. */
interface CodeDeclaration {
  readonly hex: string;
  readonly name: string;
  readonly argument_bytes?: number;
  readonly role?: "plain" | "line-break" | "page-break" | "end";
}

/** Declare codes the way a caller does, through the public schema. */
const declare = (
  ...codes: ReadonlyArray<CodeDeclaration>
): RomControlCodeInput[] =>
  codes.map((code) => romControlCodeSchema.parse(code));

const table = (...codes: ReadonlyArray<CodeDeclaration>) => {
  const parsed = parseRomControlCodes(declare(...codes));
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
};

/** One ASCII letter per byte, so a run's text is readable in assertions. */
const ascii = (run: Uint8Array): string => new TextDecoder("ascii").decode(run);

describe("control code declarations", () => {
  it("rejects hex that is not whole bytes and rejects duplicate codes", () => {
    // One hex digit cannot name a byte, so the schema refuses it at the edge.
    expect(
      romControlCodeSchema.safeParse({ hex: "A", name: "BAD" }).success,
    ).toBe(false);
    const odd = parseRomControlCodes(declare({ hex: "ABC", name: "BAD" }));
    expect(odd.ok).toBe(false);
    if (!odd.ok) expect(odd.error).toContain("whole bytes");
    const notHex = parseRomControlCodes(declare({ hex: "ZZ", name: "BAD" }));
    expect(notHex.ok).toBe(false);
    const duplicate = parseRomControlCodes(
      declare({ hex: "0A", name: "LINE" }, { hex: "0a", name: "BREAK" }),
    );
    expect(duplicate.ok).toBe(false);
    if (!duplicate.ok) expect(duplicate.error).toContain("same bytes");
  });

  it("prefers the longest declared code at one offset", () => {
    const codes = table(
      { hex: "FF", name: "END", role: "end" },
      { hex: "FFFE", name: "LINE", role: "line-break" },
    );
    const bytes = Uint8Array.from([0x41, 0xff, 0xfe, 0x42]);
    const { segments, stop } = segmentRomTextByControlCodes(bytes, codes);
    expect(segments.map((s) => s.kind)).toEqual(["text", "code", "text"]);
    expect(segments[1]).toMatchObject({ kind: "code", length: 2 });
    expect(stop).toBe("buffer-end");
  });
});

describe("decoding text that mixes glyphs and codes", () => {
  it("skips argument bytes so an argument equal to the terminator keeps the string", () => {
    // {COLOR 00} sits mid-line; its 00 argument is the terminator value.
    const codes = table({ hex: "1B", name: "COLOR", argument_bytes: 1 });
    const bytes = Uint8Array.from([0x41, 0x1b, 0x00, 0x42, 0x43]);
    const decoded = decodeRomTextWithControlCodes(bytes, codes, ascii);
    expect(decoded.text).toBe("A{COLOR}BC");
    expect(decoded.character_length).toBe(3);
    expect(decoded.byte_length).toBe(5);
    expect(decoded.control_codes).toEqual([
      { name: "COLOR", offset: 1, byte_length: 2, arguments_hex: "00" },
    ]);
  });

  it("splits lines and pages, and counts the longest line", () => {
    const codes = table(
      { hex: "0A", name: "LINE", role: "line-break" },
      { hex: "0C", name: "PAGE", role: "page-break" },
    );
    const bytes = Uint8Array.from([
      0x41, 0x42, 0x0a, 0x43, 0x44, 0x45, 0x0c, 0x46,
    ]);
    const decoded = decodeRomTextWithControlCodes(bytes, codes, ascii);
    expect(decoded.lines).toEqual(["AB", "CDE", "F"]);
    expect(decoded.pages).toEqual([["AB", "CDE"], ["F"]]);
    expect(decoded.longest_line_characters).toBe(3);
    expect(decoded.character_length).toBe(6);
  });

  it("stops at an end code and reports the bytes it consumed", () => {
    const codes = table(
      { hex: "FF", name: "END", role: "end" },
      { hex: "0A", name: "LINE", role: "line-break" },
    );
    const bytes = Uint8Array.from([0x41, 0xff, 0x42, 0x43]);
    const decoded = decodeRomTextWithControlCodes(bytes, codes, ascii);
    expect(decoded.text).toBe("A{END}");
    expect(decoded.byte_length).toBe(2);
    expect(decoded.stop).toBe("end-code");
    expect(decoded.lines).toEqual(["A{END}"]);
  });

  it("reports a code whose arguments run past the buffer", () => {
    const codes = table({ hex: "1B", name: "WAIT", argument_bytes: 2 });
    const bytes = Uint8Array.from([0x41, 0x1b, 0x05]);
    const decoded = decodeRomTextWithControlCodes(bytes, codes, ascii);
    expect(decoded.control_codes).toEqual([
      {
        name: "WAIT",
        offset: 1,
        byte_length: 2,
        arguments_hex: "05",
        arguments_truncated: true,
      },
    ]);
    expect(decoded.byte_length).toBe(3);
  });

  it("keeps one empty line for an empty string", () => {
    const codes = table({ hex: "0A", name: "LINE", role: "line-break" });
    const decoded = decodeRomTextWithControlCodes(
      new Uint8Array(0),
      codes,
      ascii,
    );
    expect(decoded.lines).toEqual([""]);
    expect(decoded.character_length).toBe(0);
    expect(decoded.byte_length).toBe(0);
  });

  it("counts one character per code point, not per UTF-16 unit", () => {
    const codes = table({ hex: "0A", name: "LINE", role: "line-break" });
    const bytes = Uint8Array.from([0x01, 0x0a, 0x02]);
    const decoded = decodeRomTextWithControlCodes(bytes, codes, (run) =>
      run[0] === 0x01 ? "ゆうしゃ" : "𩸽",
    );
    expect(decoded.lines).toEqual(["ゆうしゃ", "𩸽"]);
    expect(decoded.character_length).toBe(5);
    expect(decoded.longest_line_characters).toBe(4);
  });
});

/** One byte per glyph, ending at `terminator`, as a byte encoding reports it. */
const endingAt =
  (terminator: number): RomGlyphReader =>
  (bytes, at) =>
    bytes[at] === terminator
      ? { kind: "terminator", length: 1 }
      : { kind: "glyph", length: 1 };

describe("glyph boundaries from the encoding owner", () => {
  it("ends at the terminator, and a declared code of the same byte wins", () => {
    const ended = decodeRomTextWithControlCodes(
      Uint8Array.from([0x41, 0x00, 0x42]),
      table(),
      ascii,
      endingAt(0x00),
    );
    // The terminator ends the string without appearing inside it.
    expect(ended.text).toBe("A");
    expect(ended.control_codes).toEqual([]);
    expect(ended.byte_length).toBe(2);
    expect(ended.stop).toBe("end-code");

    // The game uses 00 as a line break and FF to end; 00 must not end here.
    const kept = decodeRomTextWithControlCodes(
      Uint8Array.from([0x41, 0x00, 0x42]),
      table({ hex: "00", name: "LINE", role: "line-break" }),
      ascii,
      endingAt(0x00),
    );
    expect(kept.lines).toEqual(["A", "B"]);
    expect(kept.stop).toBe("buffer-end");
  });

  it("keeps a longer declared code ahead of the terminator byte", () => {
    const decoded = decodeRomTextWithControlCodes(
      Uint8Array.from([0x41, 0xff, 0xfe, 0x42, 0xff, 0x43]),
      table({ hex: "FFFE", name: "LINE", role: "line-break" }),
      ascii,
      endingAt(0xff),
    );
    expect(decoded.lines).toEqual(["A", "B"]);
    expect(decoded.byte_length).toBe(5);
    expect(decoded.stop).toBe("end-code");
  });

  it("matches codes only between glyphs and stops after an end glyph", () => {
    // 82 F1 is one two-byte glyph; F1 alone is a declared code.
    const twoByte: RomGlyphReader = (bytes, at) =>
      bytes[at] === 0x82
        ? { kind: "glyph", length: 2 }
        : bytes[at] === 0xee
          ? { kind: "end-glyph", length: 1 }
          : { kind: "glyph", length: 1 };
    const { segments, byteLength, stop } = segmentRomTextByControlCodes(
      Uint8Array.from([0x82, 0xf1, 0xf1, 0x05, 0x41, 0xee, 0x42]),
      table({ hex: "F1", name: "COLOR", argument_bytes: 1 }),
      twoByte,
    );
    expect(segments).toMatchObject([
      { kind: "text", offset: 0, length: 2 },
      { kind: "code", offset: 2, length: 2, argumentsHex: "05" },
      { kind: "text", offset: 4, length: 2 },
    ]);
    expect(byteLength).toBe(6);
    expect(stop).toBe("end-code");
  });
});
