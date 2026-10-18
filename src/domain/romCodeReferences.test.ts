import { describe, expect, it } from "vitest";
import {
  parseAddress32,
  scanMipsRegion,
  type CodeReferenceKind,
} from "./romCodeReferences.js";
import { overlappingRegions } from "./romCodeReferenceRegions.js";
import { findGpInitializer } from "./romGpInitializer.js";

const ALL: ReadonlySet<CodeReferenceKind> = new Set([
  "call",
  "jump",
  "address_pair",
  "gp_relative",
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

describe("gp-relative references", () => {
  const GP = 0x8005c1a8;
  const gpScan = (words: readonly number[], targets = one(0x8005c4b0)) => {
    const bytes = bytesOf(words);
    return scanMipsRegion(
      {
        file: "f",
        bytes,
        fileOffset: 0,
        length: bytes.length,
        address: 0x80010000,
        gp: GP,
      },
      targets,
      ALL,
    );
  };
  const GPR = 28;

  it("computes gp plus the sign-extended offset", () => {
    const hits = gpScan([lw(R.v1, 0x308, GPR), i(0x2b, GPR, R.v0, 0x308)]);
    expect(hits.map((h) => [h.kind, h.instruction, h.targetAddress])).toEqual([
      ["gp_relative", "lw v1, 0x308(gp)", 0x8005c4b0],
      ["gp_relative", "sw v0, 0x308(gp)", 0x8005c4b0],
    ]);
    expect(gpScan([lw(R.v1, -0x10, GPR)], one(GP - 0x10))).toHaveLength(1);
  });

  it("reports addiu from gp and follows the formed base", () => {
    const hits = gpScan(
      [addiu(R.a0, GPR, 0x300), lhu(R.v0, 8, R.a0)],
      one(0x8005c4a8),
    );
    expect(hits.map((h) => [h.kind, h.instruction])).toEqual([
      ["gp_relative", "addiu a0, gp, 0x300"],
    ]);
    const field = gpScan(
      [addiu(R.a0, GPR, 0x300), lhu(R.v0, 8, R.a0)],
      one(0x8005c4b0),
    );
    expect(field.map((h) => [h.kind, h.instruction])).toEqual([
      ["address_pair", "lhu v0, 0x8(a0)"],
    ]);
  });

  it("is off without a gp value", () => {
    const bytes = bytesOf([lw(R.v1, 0x308, GPR)]);
    expect(
      scanMipsRegion(
        { file: "f", bytes, fileOffset: 0, length: 4, address: 0x80010000 },
        one(0x8005c4b0),
        ALL,
      ),
    ).toHaveLength(0);
  });

  it("stops tracking when a function rewrites gp, and restores at the next function", () => {
    const words = [
      lui(GPR, 0x8001),
      lw(R.v1, 0x308, GPR), // gp now 0x80010000: not the global gp
      jr(R.ra),
      nop,
      lw(R.v1, 0x308, GPR), // new function: global gp again
    ];
    expect(gpScan(words).map((h) => h.address)).toEqual([0x80010010]);
    const restored = [
      lui(GPR, 0x8006),
      addiu(GPR, GPR, -0x3e58),
      lw(R.v1, 0x308, GPR),
    ];
    expect(gpScan(restored)).toHaveLength(1);
    const clobbered = [lw(GPR, 0, R.a0), lw(R.v1, 0x308, GPR)];
    expect(gpScan(clobbered)).toHaveLength(0);
  });

  it("finds the lui/addiu or lui/daddiu gp initializer", () => {
    const daddiu = (rt: number, rs: number, imm: number) =>
      i(0x19, rs, rt, imm);
    const bytes = bytesOf([
      nop,
      lui(GPR, 0x8006),
      nop,
      addiu(GPR, GPR, -0x3e58),
    ]);
    expect(
      findGpInitializer({
        bytes,
        fileOffset: 0,
        length: 16,
        address: 0x80010000,
      }),
    ).toEqual({ value: GP, address: 0x80010004, fileOffset: 4 });

    const r5900Bytes = bytesOf([lui(GPR, 0x0052), daddiu(GPR, GPR, -0x1200)]);
    expect(
      findGpInitializer({
        bytes: r5900Bytes,
        fileOffset: 0,
        length: 8,
        address: 0x00100100,
      }),
    ).toEqual({ value: 0x0051ee00, address: 0x00100100, fileOffset: 0 });
  });

  it("pairs lui with R5900 daddiu, daddu move, and ld/sd/lq/sq accesses", () => {
    const daddiu = (rt: number, rs: number, imm: number) =>
      i(0x19, rs, rt, imm);
    const dadduMove = (rd: number, rs: number) =>
      ((rs << 21) | (rd << 11) | 0x2d) >>> 0;
    const ld = (rt: number, off: number, rs: number) => i(0x37, rs, rt, off);
    const sq = (rt: number, off: number, rs: number) => i(0x1f, rs, rt, off);
    const hits = scan(
      [
        lui(R.v0, 0x0045),
        dadduMove(R.a0, R.v0),
        daddiu(R.a0, R.a0, 0x1234),
        ld(R.v1, 0x10, R.a0),
        sq(R.v1, 0x20, R.a0),
      ],
      0x00100000,
      [
        { address: 0x00451234, length: 1 },
        { address: 0x00451244, length: 1 },
        { address: 0x00451254, length: 1 },
      ],
    );
    expect(hits.map((h) => [h.targetIndex, h.instruction])).toEqual([
      [0, "daddiu a0, a0, 0x1234"],
      [1, "ld v1, 0x10(a0)"],
      [2, "sq v1, 0x20(a0)"],
    ]);
  });

  it("tracks indexed array base across lui + addu/daddu + load/store", () => {
    const addu = (rd: number, rs: number, rt: number) =>
      ((rs << 21) | (rt << 16) | (rd << 11) | 0x21) >>> 0;
    const hits = scan(
      [
        lui(R.at, 0x004b),
        addu(R.at, R.at, R.v0), // $at = 0x004b0000 + index ($v0)
        lw(R.v0, 0x5430, R.at), // loads from 0x004b5430 + index
      ],
      0x00100000,
      one(0x004b5430),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      kind: "address_pair",
      instruction: "lw v0, 0x5430(at)",
      targetAddress: 0x004b5430,
      sourceLuiAddress: 0x00100000,
    });
  });
});
