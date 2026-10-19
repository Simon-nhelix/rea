import { describe, expect, it } from "vitest";
import {
  parseAddress32,
  scanCodeRegion,
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
});

describe("R5900, indexed base, and call argument resolution", () => {
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

  it("resolves call arguments (including delay-slot setup) and caller signatures", () => {
    const bytes = bytesOf([
      lui(R.a0, 0x800d),
      addiu(R.a1, R.zero, 42),
      jal(0x800cba44),
      addiu(R.a0, R.a0, 0x1234), // delay slot completes $a0 = 0x800d1234
    ]);
    const hits = scanMipsRegion(
      {
        file: "f",
        bytes,
        fileOffset: 0,
        length: bytes.length,
        address: 0x80010000,
        resolveCallArguments: true,
        includeCallerSignatures: true,
      },
      one(0x800cba44),
      ALL,
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.callArguments).toEqual({
      a0: "0x800d1234",
      a1: "0x0000002a",
    });
    expect(hits[0]?.callerSignature).toBeTypeOf("string");
    expect(hits[0]?.callerSignature?.length).toBeGreaterThanOrEqual(16);
  });
});

describe("call argument provenance", () => {
  it.each([{ slot: [] }, { slot: [lw(R.a0, 0, R.zero)] }])(
    "does not retain pre-delay MIPS arguments when the slot is absent or overwrites them",
    ({ slot }) => {
      const bytes = bytesOf([addiu(R.a0, R.zero, 1), jal(0x800cba44), ...slot]);
      const hits = scanMipsRegion(
        {
          file: "f",
          bytes,
          fileOffset: 0,
          length: bytes.length,
          address: 0x80010000,
        },
        one(0x800cba44),
        ALL,
        { resolveCallArguments: true },
      );
      expect(
        hits.find((h) => h.kind === "call")?.callArguments,
      ).toBeUndefined();
    },
  );
  it.each([
    ["e401b001e40200090009", "0x00000002"],
    ["e401b001644200090009", undefined],
    ["e401b001", undefined],
  ])(
    "snapshots SuperH arguments after an available delay slot (%s)",
    (hex, value) => {
      const bytes = Buffer.from(hex, "hex");
      const hits = scanCodeRegion(
        "sh2-be",
        {
          file: "f",
          bytes,
          fileOffset: 0,
          length: bytes.length,
          address: 0x1000,
        },
        [{ address: 0x1008, length: 1 }],
        ALL,
        { resolveCallArguments: true },
      );
      expect(hits.find((h) => h.kind === "call")?.callArguments?.r4).toBe(
        value,
      );
    },
  );

  it.each([
    ["0120013000f000f800bf", "0x00000002"],
    ["0120086800f000f800bf", undefined],
  ])(
    "updates or forgets overwritten Thumb argument constants (%s)",
    (hex, value) => {
      const bytes = Buffer.from(hex, "hex");
      const hits = scanCodeRegion(
        "thumb-le",
        {
          file: "f",
          bytes,
          fileOffset: 0,
          length: bytes.length,
          address: 0x1000,
        },
        [{ address: 0x1008, length: 1 }],
        ALL,
        { resolveCallArguments: true },
      );
      expect(hits.find((h) => h.kind === "call")?.callArguments?.r0).toBe(
        value,
      );
    },
  );

  it.each([0xe0810002, 0x13a00002])(
    "forgets ARM constants after an unmodelled or conditional write (%i)",
    (write) => {
      const bytes = bytesOf([0xe3a00001, write, 0xeb000000]);
      const hits = scanCodeRegion(
        "arm-le",
        {
          file: "f",
          bytes,
          fileOffset: 0,
          length: bytes.length,
          address: 0x1000,
        },
        [{ address: 0x1010, length: 1 }],
        ALL,
        { resolveCallArguments: true },
      );
      expect(
        hits.find((h) => h.kind === "call")?.callArguments,
      ).toBeUndefined();
    },
  );

  it("forgets a SuperH indirect callee overwritten by an unknown memory load", () => {
    const bytes = Buffer.from("d0026002400b00090000000000002000", "hex");
    const hits = scanCodeRegion(
      "sh2-be",
      {
        file: "f",
        bytes,
        fileOffset: 0,
        length: bytes.length,
        address: 0x1000,
      },
      [{ address: 0x2000, length: 1 }],
      ALL,
    );
    expect(hits.some((h) => h.kind === "call")).toBe(false);
  });
});

describe("multi-architecture scanCodeRegion", () => {
  it("scans SuperH sh2-be mov.l @(disp,PC) literal pool loads, jsr @Rn, and bsr", () => {
    // PC at 0x06004000:
    // 0x06004000: D402 -> mov.l @(8, PC), r4  (pool at (0x06004000 & ~3) + 4 + 8 = 0x0600400C)
    // 0x06004002: D003 -> mov.l @(12, PC), r0 (pool at (0x06004002 & ~3) + 4 + 12 = 0x06004010)
    // 0x06004004: 400B -> jsr @r0
    // 0x06004006: 0009 -> nop
    // 0x06004008: B004 -> bsr 0x06004014 (PC + 4 + 4*2 = 0x06004014)
    // 0x0600400A: 0009 -> nop
    // 0x0600400C: 0x06050000 (string pointer)
    // 0x06004010: 0x06012340 (callee function)
    const buf = Buffer.alloc(0x18, 0);
    buf.writeUInt16BE(0xd402, 0x00);
    buf.writeUInt16BE(0xd003, 0x02);
    buf.writeUInt16BE(0x400b, 0x04);
    buf.writeUInt16BE(0x0009, 0x06);
    buf.writeUInt16BE(0xb004, 0x08);
    buf.writeUInt16BE(0x0009, 0x0a);
    buf.writeUInt32BE(0x06050000, 0x0c);
    buf.writeUInt32BE(0x06012340, 0x10);

    const hits = scanCodeRegion(
      "sh2-be",
      {
        file: "0.BIN",
        bytes: new Uint8Array(buf),
        fileOffset: 0,
        length: buf.length,
        address: 0x06004000,
        resolveCallArguments: true,
      },
      [
        { address: 0x06050000, length: 1 },
        { address: 0x06012340, length: 1 },
        { address: 0x06004014, length: 1 },
      ],
      ALL,
    );
    expect(
      hits.map((h) => [h.kind, h.address, h.targetAddress]),
    ).toContainEqual(["address_pair", 0x06004000, 0x06050000]);
    const jsrHit = hits.find(
      (h) => h.kind === "call" && h.address === 0x06004004,
    );
    expect(jsrHit?.targetAddress).toBe(0x06012340);
    expect(jsrHit?.callArguments).toEqual({ r4: "0x06050000" });
    expect(
      hits.some((h) => h.kind === "call" && h.targetAddress === 0x06004014),
    ).toBe(true);
  });

  it("scans 65816 jsl, jml, and 24-bit long loads", () => {
    // 0x808000: 22 40 81 C0 -> jsl $c08140
    // 0x808004: 5C 00 90 C0 -> jml $c09000
    // 0x808008: AF 10 20 7E -> lda.l $7e2010
    const bytes = new Uint8Array([
      0x22, 0x40, 0x81, 0xc0, 0x5c, 0x00, 0x90, 0xc0, 0xaf, 0x10, 0x20, 0x7e,
    ]);
    const hits = scanCodeRegion(
      "65816",
      {
        file: "rom.sfc",
        bytes,
        fileOffset: 0,
        length: bytes.length,
        address: 0x808000,
      },
      [
        { address: 0xc08140, length: 1 },
        { address: 0xc09000, length: 1 },
        { address: 0x7e2010, length: 1 },
      ],
      ALL,
    );
    expect(hits.map((h) => [h.kind, h.instruction, h.targetAddress])).toEqual([
      ["call", "jsl 0xc08140", 0xc08140],
      ["jump", "jml 0xc09000", 0xc09000],
      ["address_pair", "lda.l 0x7e2010", 0x7e2010],
    ]);
  });

  it("scans HuC6280 block transfer (tii) and jsr", () => {
    // 0x4000: 73 00 90 00 30 40 00 -> tii 0x9000, 0x3000, 0x0040
    // 0x4007: 20 80 45 -> jsr 0x4580
    const bytes = new Uint8Array([
      0x73, 0x00, 0x90, 0x00, 0x30, 0x40, 0x00, 0x20, 0x80, 0x45,
    ]);
    const hits = scanCodeRegion(
      "huc6280",
      {
        file: "pce.bin",
        bytes,
        fileOffset: 0,
        length: bytes.length,
        address: 0x4000,
      },
      [
        { address: 0x9000, length: 1 },
        { address: 0x4580, length: 1 },
      ],
      ALL,
    );
    expect(hits.map((h) => [h.kind, h.instruction, h.targetAddress])).toEqual([
      ["address_pair", "tii 0x9000, 0x3000, 0x0040", 0x9000],
      ["call", "jsr 0x4580", 0x4580],
    ]);
  });

  it("scans Thumb-LE ldr Rd, [pc, #imm] literal pools and 32-bit bl calls", () => {
    // 0x08000100: 4801 -> ldr r0, [pc, #0x4] -> pool at (0x08000100 + 4) & ~3 + 4 = 0x08000108
    // 0x08000102: F000 F802 -> bl 0x0800010A
    // 0x08000106: 0000 -> nop
    // 0x08000108: 0x08054320 (literal pool entry)
    const buf = Buffer.alloc(12, 0);
    buf.writeUInt16LE(0x4801, 0);
    buf.writeUInt16LE(0xf000, 2);
    buf.writeUInt16LE(0xf802, 4);
    buf.writeUInt16LE(0x0000, 6);
    buf.writeUInt32LE(0x08054320, 8);
    const hits = scanCodeRegion(
      "thumb-le",
      {
        file: "rom.gba",
        bytes: new Uint8Array(buf),
        fileOffset: 0,
        length: buf.length,
        address: 0x08000100,
        resolveCallArguments: true,
      },
      [
        { address: 0x08054320, length: 1 },
        { address: 0x0800010a, length: 1 },
      ],
      ALL,
    );
    expect(
      hits.some(
        (h) => h.kind === "address_pair" && h.targetAddress === 0x08054320,
      ),
    ).toBe(true);
    const blHit = hits.find(
      (h) => h.kind === "call" && h.targetAddress === 0x0800010a,
    );
    expect(blHit?.callArguments).toEqual({ r0: "0x08054320" });
  });
});
