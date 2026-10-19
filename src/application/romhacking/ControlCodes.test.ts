import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { JsonValue } from "../../domain/jsonValue.js";
import { runLocalRomTool } from "./LocalRomCommands.js";

/**
 * A dialogue table whose strings carry control codes. The first string holds
 * {COLOR 00}: its argument equals the terminator, so a decoder that does not
 * know the argument count stops after the first glyph and reports a short
 * string with a wrong byte length.
 *
 *   0x00 table [0010 0020]            pointers, 2 bytes, little endian
 *   0x10 あ 1B 00 い 0A う 00         = あ{COLOR}い{LINE}う
 *   0x20 か 00
 */
const dialogue = (): Uint8Array => {
  const bytes = new Uint8Array(0x30);
  bytes.set([0x10, 0x00, 0x20, 0x00], 0x00);
  bytes.set([0x82, 0xa0, 0x1b, 0x00, 0x82, 0xa2, 0x0a, 0x82, 0xa4, 0x00], 0x10);
  bytes.set([0x82, 0xa9, 0x00], 0x20);
  return bytes;
};

/** The same bytes read as 16-bit words, where control_codes do not apply. */
const words = (): Uint8Array => dialogue();

const signal = new AbortController().signal;
let root = "";

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "rea-control-codes-"));
  await writeFile(join(root, "dialogue.bin"), dialogue());
  await writeFile(join(root, "words.bin"), words());
});
afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

const scan = async (
  file: string,
  arguments_: Readonly<Record<string, JsonValue>>,
) => {
  const result = await runLocalRomTool({
    path: join(root, file),
    tool: "scan_pointer_table",
    arguments: arguments_,
    signal,
    localBytes: true,
  });
  if (result === undefined) throw new Error("local run expected");
  return result;
};

type Manuscript = {
  jp: string;
  byte_length: number | null;
  max_bytes: number | null;
  lines?: string[];
  character_length?: number;
  longest_line_characters?: number;
  control_codes?: ReadonlyArray<Record<string, unknown>>;
};

const manuscripts = (value: unknown): Manuscript[] =>
  (value as { manuscript_records?: Manuscript[] }).manuscript_records ?? [];

const BASE = {
  table_offset: 0,
  count: 2,
  pointer_size: 2,
  endian: "little",
  encoding: "sjis",
  terminator_byte: 0,
  manuscript_only: true,
} as const;

const CODES = [
  { hex: "1B", name: "COLOR", argument_bytes: 1 },
  { hex: "0A", name: "LINE", role: "line-break" },
] as const;

describe("scan_pointer_table with declared control codes", () => {
  it("stops early without declarations, so the argument byte ends the string", async () => {
    const result = await scan("dialogue.bin", { ...BASE });
    if (!result.ok) throw result.error;
    const [first] = manuscripts(result.value.result);
    // あ 1B then the 00 argument read as the terminator: four bytes of ten.
    expect(first?.byte_length).toBe(4);
    expect(first?.lines).toBeUndefined();
    expect(first?.character_length).toBeUndefined();
  });

  it("reads the whole string, splits lines, and counts characters", async () => {
    const result = await scan("dialogue.bin", {
      ...BASE,
      control_codes: [...CODES],
    });
    if (!result.ok) throw result.error;
    const records = manuscripts(result.value.result);
    expect(records[0]?.jp).toBe("あ{COLOR}い{LINE}う");
    expect(records[0]?.byte_length).toBe(10);
    expect(records[0]?.max_bytes).toBe(16);
    expect(records[0]?.lines).toEqual(["あ{COLOR}い", "う"]);
    expect(records[0]?.character_length).toBe(3);
    expect(records[0]?.longest_line_characters).toBe(2);
    expect(records[0]?.control_codes).toEqual([
      { name: "COLOR", offset: 2, byte_length: 2, arguments_hex: "00" },
      { name: "LINE", offset: 6, byte_length: 1, arguments_hex: "" },
    ]);
    // A string with no code keeps the plain fields and reports no code.
    expect(records[1]?.jp).toBe("か");
    expect(records[1]?.lines).toEqual(["か"]);
    expect(records[1]?.control_codes).toBeUndefined();
  });

  it("refuses odd-byte control code declarations in 16-bit word encodings", async () => {
    const result = await scan("words.bin", {
      ...BASE,
      encoding: "sjis-le16",
      terminator_word: 0xffff,
      control_codes: [...CODES],
    });
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error.userMessage).toContain("even byte lengths");
  });

  it("decodes 16-bit word encodings (sjis-swap16) with word-aligned control codes", async () => {
    // 0x00 table [0010 0020]
    // 0x10 あ(0x82A0 -> LE 0xA0 0x82) {WAIT: 0x01FF, arg 0x0000} い(0x82A2 -> LE 0xA2 0x82) END(0xFFFF)
    // 0x20 か(0x82A9 -> LE 0xA9 0x82) END(0xFFFF)
    const swapBuf = new Uint8Array(0x30);
    swapBuf.set([0x10, 0x00, 0x20, 0x00], 0x00);
    swapBuf.set(
      [0xa0, 0x82, 0xff, 0x01, 0x00, 0x00, 0xa2, 0x82, 0xff, 0xff],
      0x10,
    );
    swapBuf.set([0xa9, 0x82, 0xff, 0xff], 0x20);
    await writeFile(join(root, "swap16.bin"), swapBuf);

    const result = await scan("swap16.bin", {
      ...BASE,
      encoding: "sjis-swap16",
      terminator_word: 0xffff,
      control_codes: [{ hex: "FF 01", name: "WAIT", argument_bytes: 2 }],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const records = manuscripts(result.value.result);
    expect(records[0]?.jp).toBe("あ{WAIT}い");
    expect(records[0]?.byte_length).toBe(10);
    expect(records[0]?.character_length).toBe(2);
    expect(records[0]?.control_codes).toEqual([
      { name: "WAIT", offset: 2, byte_length: 4, arguments_hex: "0000" },
    ]);
    expect(records[1]?.jp).toBe("か");
  });

  it("refuses two declarations of the same bytes", async () => {
    const result = await scan("dialogue.bin", {
      ...BASE,
      control_codes: [
        { hex: "0A", name: "LINE", role: "line-break" },
        { hex: "0A", name: "BREAK" },
      ],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.userMessage).toContain("same bytes");
  });
});
