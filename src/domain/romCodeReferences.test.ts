import { describe, expect, it } from "vitest";
import {
  overlappingRegions,
  parseAddress32,
  scanMipsRegion,
  type CodeReferenceKind,
} from "./romCodeReferences.js";

const ALL: ReadonlySet<CodeReferenceKind> = new Set([
  "call",
  "jump",
  "address_pair",
  "pointer_word",
]);

const R = { zero: 0, at: 1, v0: 2, v1: 3, a0: 4, a1: 5, t0: 8, s0: 16, ra: 31 };
const i = (op: number, rs: number, rt: number, imm: number): number =>
  ((op << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)) >>> 0;
const lui = (rt: number, imm: number) => i(0x0f, 0, rt, imm);
const addiu = (rt: number, rs: number, imm: number) => i(9, rs, rt, imm);
const ori = (rt: number, rs: number, imm: number) => i(0x0d, rs, rt, imm);
const lw = (rt: number, off: number, rs: number) => i(0x23, rs, rt, off);
const lhu = (rt: number, off: number, rs: number) => i(0x25, rs, rt, off);
const sb = (rt: number, off: number, rs: number) => i(0x28, rs, rt, off);
const jal = (target: number) =>
  ((3 << 26) | ((target >>> 2) & 0x03ffffff)) >>> 0;
const j = (target: number) => ((2 << 26) | ((target >>> 2) & 0x03ffffff)) >>> 0;
const jr = (rs: number) => ((rs << 21) | 8) >>> 0;
const nop = 0;

const bytesOf = (words: readonly number[]): Uint8Array => {
  const out = new Uint8Array(words.length * 4);
  const view = new DataView(out.buffer);
  words.forEach((word, index) => view.setUint32(index * 4, word, true));
  return out;
};

const scan = (
  words: readonly number[],
  address: number,
  targets: readonly { address: number; length: number }[],
) => {
  const bytes = bytesOf(words);
  return scanMipsRegion(
    { file: "f", bytes, fileOffset: 0, length: bytes.length, address },
    targets,
    ALL,
  );
};
const one = (address: number, length = 1) => [{ address, length }];

describe("parseAddress32", () => {
  it("accepts hex with or without 0x and rejects the rest", () => {
    expect(parseAddress32("0x800CBCE8")).toBe(0x800cbce8);
    expect(parseAddress32("800cbce8")).toBe(0x800cbce8);
    expect(parseAddress32("0x1800CBCE8")).toBeUndefined();
    expect(parseAddress32("xyz")).toBeUndefined();
  });
});

describe("scanMipsRegion", () => {
  it("finds jal and j targets using the upper bits of PC+4", () => {
    const hits = scan(
      [jal(0x800cba44), nop, j(0x800cba44), nop],
      0x80010000,
      one(0x800cba44),
    );
    expect(hits.map((h) => [h.kind, h.instruction, h.address])).toEqual([
      ["call", "jal 0x800cba44", 0x80010000],
      ["jump", "j 0x800cba44", 0x80010008],
    ]);
  });

  it("resolves the 256MB segment from the instruction's own region", () => {
    // Same bytes at a KSEG0 pc target 0x80..., at a KUSEG pc target 0x00...
    const word = jal(0x0010_0000);
    expect(scan([word, nop], 0x80000000, one(0x80100000))).toHaveLength(1);
    expect(scan([word, nop], 0x00000000, one(0x00100000))).toHaveLength(1);
    expect(scan([word, nop], 0x80000000, one(0x00100000))).toHaveLength(0);
  });

  it("pairs lui with a sign-extended addiu", () => {
    // 0x800D0000 + (-0x2E8) = 0x800CFD18
    const hits = scan(
      [lui(R.a0, 0x800d), addiu(R.a0, R.a0, -0x2e8), nop],
      0x80100000,
      one(0x800cfd18),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      kind: "address_pair",
      instruction: "addiu a0, a0, -0x2e8",
      register: "a0",
      targetAddress: 0x800cfd18,
      sourceLuiAddress: 0x80100000,
    });
  });

  it("does not sign-extend ori and does not match the wrong half", () => {
    const words = [lui(R.v0, 0x800c), ori(R.v0, R.v0, 0xf2d2)];
    expect(scan(words, 0x80100000, one(0x800cf2d2))).toHaveLength(1);
    expect(scan(words, 0x80100000, one(0x800bf2d2))).toHaveLength(0);
  });

  it("reports load and store address formation with the exact address", () => {
    const words = [
      lui(R.v0, 0x800d),
      lhu(R.v1, -0xd2e, R.v0),
      sb(R.v1, -0xd2d, R.v0),
    ];
    const hits = scan(words, 0x80100000, [
      { address: 0x800cf2d2, length: 1 },
      { address: 0x800cf2d3, length: 1 },
    ]);
    expect(hits.map((h) => [h.targetIndex, h.instruction])).toEqual([
      [0, "lhu v1, -0xd2e(v0)"],
      [1, "sb v1, -0xd2d(v0)"],
    ]);
  });

  it("matches addresses in the middle of a range", () => {
    const hits = scan(
      [lui(R.a0, 0x800d), addiu(R.a0, R.a0, 0x6590)],
      0x80100000,
      one(0x800d6500, 0x100),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.targetAddress).toBe(0x800d6590);
  });

  it("stops tracking a register once it is overwritten", () => {
    const words = [
      lui(R.v0, 0x800d),
      lw(R.v0, 0, R.a1), // v0 overwritten by a load
      lw(R.v1, -0xd2e, R.v0),
    ];
    expect(scan(words, 0x80100000, one(0x800cf2d2))).toHaveLength(0);
    // A different register does not disturb tracking.
    const kept = [lui(R.v0, 0x800d), lw(R.v1, 0, R.a1), lw(R.v1, -0xd2e, R.v0)];
    expect(scan(kept, 0x80100000, one(0x800cf2d2))).toHaveLength(1);
  });

  it("forgets constants at function end and across calls", () => {
    const afterReturn = [
      lui(R.v0, 0x800d),
      jr(R.ra),
      nop,
      lw(R.v1, -0xd2e, R.v0),
    ];
    expect(scan(afterReturn, 0x80100000, one(0x800cf2d2))).toHaveLength(0);
    const afterCall = [
      lui(R.v0, 0x800d),
      jal(0x80200000),
      nop,
      lw(R.v1, -0xd2e, R.v0),
    ];
    expect(scan(afterCall, 0x80100000, one(0x800cf2d2))).toHaveLength(0);
    // Saved registers survive a call.
    const saved = [
      lui(R.s0, 0x800d),
      jal(0x80200000),
      nop,
      lw(R.v1, -0xd2e, R.s0),
    ];
    expect(scan(saved, 0x80100000, one(0x800cf2d2))).toHaveLength(1);
  });

  it("follows a formed base register to a field offset once", () => {
    const words = [
      lui(R.a0, 0x800d),
      addiu(R.a0, R.a0, -0xd34), // 0x800CF2CC
      lw(R.v0, 0, R.a0), // same address as the addiu: not reported twice
      lhu(R.v1, 6, R.a0), // 0x800CF2D2
    ];
    expect(scan(words, 0x80100000, one(0x800cf2cc))).toHaveLength(1);
    const field = scan(words, 0x80100000, one(0x800cf2d2));
    expect(field).toHaveLength(1);
    expect(field[0]?.instruction).toBe("lhu v1, 0x6(a0)");
  });

  it("finds aligned pointer words, not unaligned ones", () => {
    const bytes = new Uint8Array(16);
    new DataView(bytes.buffer).setUint32(4, 0x800d6590, true);
    const aligned = scanMipsRegion(
      { file: "f", bytes, fileOffset: 0, length: 16, address: 0x800fcf00 },
      one(0x800d6590),
      ALL,
    );
    expect(aligned.map((h) => [h.kind, h.address, h.bytes])).toEqual([
      ["pointer_word", 0x800fcf04, "90 65 0d 80"],
    ]);
    const shifted = scanMipsRegion(
      { file: "f", bytes, fileOffset: 0, length: 16, address: 0x800fcf01 },
      one(0x800d6590),
      ALL,
    );
    expect(shifted).toHaveLength(0);
  });

  it("honors the kind filter and the scanned region", () => {
    const bytes = bytesOf([jal(0x800cba44), nop, 0x800cba44, nop]);
    const only = scanMipsRegion(
      { file: "f", bytes, fileOffset: 0, length: 16, address: 0x80100000 },
      one(0x800cba44),
      new Set<CodeReferenceKind>(["pointer_word"]),
    );
    expect(only.map((h) => h.kind)).toEqual(["pointer_word"]);
    const clipped = scanMipsRegion(
      { file: "f", bytes, fileOffset: 8, length: 4, address: 0x80100008 },
      one(0x800cba44),
      ALL,
    );
    expect(clipped.map((h) => h.fileOffset)).toEqual([8]);
  });
});

describe("overlappingRegions", () => {
  it("groups files that share addresses", () => {
    expect(
      overlappingRegions([
        { file: "a", address: 0x800d61d8, length: 100 },
        { file: "b", address: 0x800d61d8, length: 50 },
        { file: "c", address: 0x80200000, length: 10 },
      ]),
    ).toEqual([["a", "b"]]);
  });
});
