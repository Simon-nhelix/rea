import { z } from "zod";

/**
 * Static search for references to addresses inside MIPS little-endian code and
 * data files (PS1 R3000; PS2/PSP use the same encoding for the instructions
 * decoded here). Pure byte logic: file access and Evidence live elsewhere.
 */

const HEX_ADDRESS = /^(?:0[xX])?[0-9a-fA-F]{1,8}$/u;

/** Parse a 32-bit address written as hex, with or without 0x. */
export const parseAddress32 = (text: string): number | undefined =>
  HEX_ADDRESS.test(text.trim())
    ? Number.parseInt(text.trim().replace(/^0[xX]/u, ""), 16)
    : undefined;

const addressSchema = z
  .string()
  .refine((text) => parseAddress32(text) !== undefined, {
    message: "Expected a 32-bit hexadecimal address such as 0x800CBCE8.",
  });

/** Evidence provider identity of the multi-file reference scanner. */
export const ROM_CODE_REFERENCE_PROVIDER_IDENTITY = {
  id: "rom-code-references",
  name: "REA MIPS code reference scanner",
  version: null,
} as const;

export const codeReferenceKindSchema = z.enum([
  "call",
  "jump",
  "address_pair",
  "gp_relative",
  "pointer_word",
]);
export type CodeReferenceKind = z.infer<typeof codeReferenceKindSchema>;

export const codeReferenceFileInputSchema = z.strictObject({
  path: z.string().min(1).describe("Absolute path of a code or data file."),
  use_gp: z
    .boolean()
    .default(true)
    .describe("Apply gp-relative reference detection to this file."),
  load_address: addressSchema
    .optional()
    .describe(
      "Virtual address of the file's first byte. Required for headerless overlays; a PS-X EXE header supplies it (text address, data from file offset 0x800). An explicit value makes the whole file one raw region.",
    ),
});

export const codeReferenceTargetInputSchema = z.strictObject({
  address: addressSchema.describe("Target virtual address (start of a range)."),
  length: z
    .number()
    .int()
    .min(1)
    .max(0x1000_0000)
    .default(1)
    .describe(
      "Byte length of the target; 1 matches one address, larger values match every address inside, such as a whole string table.",
    ),
  name: z.string().min(1).max(200).optional().describe("Optional label."),
});

export const findCodeReferencesInputSchema = z.strictObject({
  files: z
    .array(codeReferenceFileInputSchema)
    .min(1)
    .max(256)
    .describe("Code files (main executable and overlays) to scan."),
  targets: z
    .array(codeReferenceTargetInputSchema)
    .min(1)
    .max(1024)
    .describe("Addresses or address ranges to find references to."),
  architecture: z
    .enum(["mips-le"])
    .default("mips-le")
    .describe("Instruction set. mips-le covers PS1, and PS2/PSP basic MIPS."),
  gp: addressSchema
    .optional()
    .describe(
      "Value of $gp for gp_relative references (base 28 plus signed offset). When omitted it is found automatically from the first lui $gp + addiu/ori $gp pair in the files.",
    ),
  gp_relative: z
    .boolean()
    .default(true)
    .describe("Set false to skip gp_relative detection entirely."),
  kinds: z
    .array(codeReferenceKindSchema)
    .min(1)
    .optional()
    .describe("Reference kinds to report; default all five."),
  max_references: z
    .number()
    .int()
    .min(1)
    .max(20_000)
    .default(500)
    .describe(
      "Maximum references returned; counts in summary stay exact beyond it.",
    ),
});

export type FindCodeReferencesInput = z.output<
  typeof findCodeReferencesInputSchema
>;

const countsSchema = z.strictObject({
  total: z.number().int().min(0),
  call: z.number().int().min(0),
  jump: z.number().int().min(0),
  address_pair: z.number().int().min(0),
  gp_relative: z.number().int().min(0),
  pointer_word: z.number().int().min(0),
});

export const codeReferenceSchema = z.strictObject({
  kind: codeReferenceKindSchema,
  file: z.string(),
  file_offset: z.number().int().min(0),
  address: z.string(),
  instruction: z.string().nullable(),
  bytes: z.string(),
  register: z.string().nullable(),
  target_address: z.string(),
  target: z.string(),
  offset_in_target: z.number().int().min(0),
  source_lui_address: z.string().nullable(),
});

export const findCodeReferencesResultSchema = z.strictObject({
  architecture: z.literal("mips-le"),
  files: z.array(
    z.strictObject({
      path: z.string(),
      sha256: z.string(),
      size: z.number().int().min(0),
      load_address: z.string(),
      load_address_source: z.enum(["ps-x-exe-header", "caller"]),
      scanned_file_offset: z.number().int().min(0),
      scanned_bytes: z.number().int().min(0),
      region_end_address: z.string(),
      references: z.number().int().min(0),
    }),
  ),
  gp: z.strictObject({
    value: z.string().nullable(),
    source: z.enum(["caller", "auto"]).nullable(),
    file: z.string().nullable(),
    address: z.string().nullable(),
    file_offset: z.number().int().min(0).nullable(),
  }),
  overlapping_files: z.array(z.array(z.string())),
  summary: z.array(
    z.strictObject({
      target: z.string(),
      length: z.number().int().min(1),
      name: z.string().nullable(),
      counts: countsSchema,
      by_file: z.array(
        z.strictObject({ file: z.string(), count: z.number().int().min(1) }),
      ),
      verdict: z.string(),
    }),
  ),
  references: z.array(codeReferenceSchema),
  total_references: z.number().int().min(0),
  truncated: z.boolean(),
});

export type CodeReference = z.output<typeof codeReferenceSchema>;
export type FindCodeReferencesResult = z.output<
  typeof findCodeReferencesResultSchema
>;

// ---------------------------------------------------------------- scanner

/** MIPS o32 register names. */
const REGISTERS = [
  "zero",
  "at",
  "v0",
  "v1",
  "a0",
  "a1",
  "a2",
  "a3",
  "t0",
  "t1",
  "t2",
  "t3",
  "t4",
  "t5",
  "t6",
  "t7",
  "s0",
  "s1",
  "s2",
  "s3",
  "s4",
  "s5",
  "s6",
  "s7",
  "t8",
  "t9",
  "k0",
  "k1",
  "gp",
  "sp",
  "fp",
  "ra",
] as const;

const LOAD_STORE_NAMES: ReadonlyMap<number, string> = new Map([
  [0x20, "lb"],
  [0x21, "lh"],
  [0x22, "lwl"],
  [0x23, "lw"],
  [0x24, "lbu"],
  [0x25, "lhu"],
  [0x26, "lwr"],
  [0x28, "sb"],
  [0x29, "sh"],
  [0x2a, "swl"],
  [0x2b, "sw"],
  [0x2e, "swr"],
  [0x32, "lwc2"],
  [0x3a, "swc2"],
]);
/** Loads that write the GPR in rt. */
const GPR_LOADS: ReadonlySet<number> = new Set([
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
]);

const hex = (value: number): string =>
  `0x${(value >>> 0).toString(16).padStart(8, "0")}`;
const signedHex = (value: number): string =>
  value < 0 ? `-0x${(-value).toString(16)}` : `0x${value.toString(16)}`;
const reg = (index: number): string => REGISTERS[index] ?? `r${index}`;
const signExtend16 = (value: number): number => (value << 16) >> 16;

interface Target {
  readonly start: number;
  readonly length: number;
  readonly index: number;
}

/** A known register constant and how it was formed. */
interface RegisterValue {
  readonly value: number;
  readonly derived: boolean;
  /** The value is the configured $gp. */
  readonly gp: boolean;
  readonly luiAddress: number | undefined;
}

/** Region of one file: bytes [fileOffset, fileOffset+length) load at `address`. */
export interface ScanRegion {
  readonly file: string;
  readonly bytes: Uint8Array;
  readonly fileOffset: number;
  readonly length: number;
  readonly address: number;
  /** Known $gp value, enabling gp_relative references. */
  readonly gp?: number | undefined;
}

export interface ScanTarget {
  readonly address: number;
  readonly length: number;
}

export interface RawReference {
  readonly kind: CodeReferenceKind;
  readonly fileOffset: number;
  readonly address: number;
  readonly instruction: string | null;
  readonly bytes: string;
  readonly register: string | null;
  readonly targetAddress: number;
  readonly targetIndex: number;
  readonly sourceLuiAddress: number | null;
}

const bytesOf = (word: number): string =>
  [0, 8, 16, 24]
    .map((shift) => ((word >>> shift) & 0xff).toString(16).padStart(2, "0"))
    .join(" ");

interface Effect {
  readonly next?: "call" | "reset";
  readonly dest?: number;
  readonly value?: RegisterValue;
}

interface Hit {
  readonly kind: CodeReferenceKind;
  readonly instruction: string | null;
  readonly register: string | null;
  readonly formed: number;
  readonly target: Target;
  readonly lui?: RegisterValue | undefined;
}

type Emit = (hit: Hit) => void;

interface Decoded {
  readonly word: number;
  readonly pc: number;
  readonly fileOffset: number;
  readonly op: number;
  readonly rs: number;
  readonly rt: number;
  readonly rd: number;
  readonly imm: number;
  readonly simm: number;
}

interface Scanner {
  readonly regs: (RegisterValue | undefined)[];
  readonly gp: number | undefined;
  readonly findTarget: (address: number) => Target | undefined;
  readonly emit: Emit;
}

const decode = (word: number, pc: number, fileOffset: number): Decoded => ({
  word,
  pc,
  fileOffset,
  op: word >>> 26,
  rs: (word >>> 21) & 31,
  rt: (word >>> 16) & 31,
  rd: (word >>> 11) & 31,
  imm: word & 0xffff,
  simm: signExtend16(word & 0xffff),
});

const jumpEffect = (scanner: Scanner, d: Decoded): Effect => {
  const destination =
    (((d.pc + 4) & 0xf0000000) | ((d.word & 0x03ffffff) << 2)) >>> 0;
  const isCall = d.op === 3;
  const target = scanner.findTarget(destination);
  if (target !== undefined)
    scanner.emit({
      kind: isCall ? "call" : "jump",
      instruction: `${isCall ? "jal" : "j"} ${hex(destination)}`,
      register: null,
      formed: destination,
      target,
    });
  return isCall ? { next: "call", dest: 31 } : { next: "reset" };
};

const immediateEffect = (scanner: Scanner, d: Decoded): Effect => {
  if (d.op === 0x0f)
    return {
      dest: d.rt,
      value: {
        value: (d.imm << 16) >>> 0,
        derived: false,
        gp: false,
        luiAddress: d.pc,
      },
    };
  const base = scanner.regs[d.rs];
  if (base === undefined) return { dest: d.rt };
  const isOri = d.op === 0x0d;
  const formed = (isOri ? base.value | d.imm : base.value + d.simm) >>> 0;
  const text = isOri
    ? `ori ${reg(d.rt)}, ${reg(d.rs)}, 0x${d.imm.toString(16)}`
    : `${d.op === 9 ? "addiu" : "addi"} ${reg(d.rt)}, ${reg(d.rs)}, ${signedHex(d.simm)}`;
  const target = scanner.findTarget(formed);
  if (target !== undefined)
    scanner.emit({
      kind: base.gp ? "gp_relative" : "address_pair",
      instruction: text,
      register: reg(d.rs),
      formed,
      target,
      lui: base,
    });
  // Re-forming the configured $gp in $gp itself keeps gp tracking alive.
  const restoresGp = d.rt === 28 && formed === scanner.gp;
  return {
    dest: d.rt,
    value: {
      ...base,
      value: formed,
      derived: !restoresGp,
      gp: restoresGp,
    },
  };
};

const memoryEffect = (scanner: Scanner, d: Decoded): Effect => {
  const base = scanner.regs[d.rs];
  // An access at offset 0 of a register formed by addiu/ori repeats the
  // address already reported for that instruction.
  if (base !== undefined && !(base.derived && d.simm === 0)) {
    const formed = (base.value + d.simm) >>> 0;
    const target = scanner.findTarget(formed);
    if (target !== undefined)
      scanner.emit({
        kind: base.gp ? "gp_relative" : "address_pair",
        instruction: `${LOAD_STORE_NAMES.get(d.op) ?? "mem"} ${reg(d.rt)}, ${signedHex(d.simm)}(${reg(d.rs)})`,
        register: reg(d.rs),
        formed,
        target,
        lui: base,
      });
  }
  return GPR_LOADS.has(d.op) ? { dest: d.rt } : {};
};

/** Opcode 0 funct values that write no general register. */
const NO_RESULT_FUNCT: ReadonlySet<number> = new Set([
  0x0c, 0x0d, 0x11, 0x13, 0x18, 0x19, 0x1a, 0x1b,
]);

const specialEffect = (scanner: Scanner, d: Decoded): Effect => {
  const funct = d.word & 63;
  if (funct === 8) return { next: "reset" }; // jr
  if (funct === 9) return { next: "call", dest: d.rd }; // jalr
  if (NO_RESULT_FUNCT.has(funct)) return {};
  const isMove = (funct === 0x21 || funct === 0x25) && d.rt === 0;
  const moved = isMove ? scanner.regs[d.rs] : undefined;
  return moved === undefined ? { dest: d.rd } : { dest: d.rd, value: moved };
};

const otherEffect = (d: Decoded): Effect => {
  if (d.op === 1 && (d.rt === 0x10 || d.rt === 0x11))
    return { next: "call", dest: 31 }; // bltzal / bgezal
  if (d.op === 4 && d.rs === 0 && d.rt === 0) return { next: "reset" }; // b
  if ((d.op === 0x10 || d.op === 0x12) && (d.rs === 0 || d.rs === 2))
    return { dest: d.rt }; // mfc0 / mfc2 / cfc2
  if (d.op >= 0x0a && d.op <= 0x0e) return { dest: d.rt }; // slti.. xori
  return {};
};

const effectOf = (scanner: Scanner, d: Decoded): Effect => {
  if (d.op === 2 || d.op === 3) return jumpEffect(scanner, d);
  if (d.op === 0x0f || d.op === 8 || d.op === 9 || d.op === 0x0d)
    return immediateEffect(scanner, d);
  if (LOAD_STORE_NAMES.has(d.op)) return memoryEffect(scanner, d);
  if (d.op === 0) return specialEffect(scanner, d);
  return otherEffect(d);
};

/** Call-clobbered registers: at, v0-v1, a0-a3, t0-t9 and ra. */
const CALLER_SAVED = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 31,
];

/** Scan one region and return every reference to any target, in file order. */
export const scanMipsRegion = (
  region: ScanRegion,
  scanTargets: readonly ScanTarget[],
  kinds: ReadonlySet<CodeReferenceKind>,
): RawReference[] => {
  const targets: Target[] = scanTargets.map((target, index) => ({
    start: target.address >>> 0,
    length: target.length,
    index,
  }));
  if (targets.length === 0) return [];
  const minStart = Math.min(...targets.map((t) => t.start));
  const maxEnd = Math.max(...targets.map((t) => t.start + t.length));
  const findTarget = (address: number): Target | undefined =>
    address < minStart || address >= maxEnd
      ? undefined
      : targets.find((t) => address >= t.start && address < t.start + t.length);

  const results: RawReference[] = [];
  const view = new DataView(
    region.bytes.buffer,
    region.bytes.byteOffset,
    region.bytes.byteLength,
  );
  const regs = Array.from<RegisterValue | undefined>({ length: 32 });
  const gpValue: RegisterValue | undefined =
    region.gp === undefined
      ? undefined
      : {
          value: region.gp >>> 0,
          derived: false,
          gp: true,
          luiAddress: undefined,
        };
  regs[28] = gpValue;
  let current: Decoded | undefined;
  const emit: Emit = ({ kind, instruction, register, formed, target, lui }) => {
    if (!kinds.has(kind) || current === undefined) return;
    results.push({
      kind,
      fileOffset: current.fileOffset,
      address: current.pc,
      instruction,
      bytes: bytesOf(current.word),
      register,
      targetAddress: formed >>> 0,
      targetIndex: target.index,
      sourceLuiAddress: lui?.luiAddress ?? null,
    });
  };
  const scanner: Scanner = { regs, gp: region.gp, findTarget, emit };

  let pending: "call" | "reset" | undefined;
  let inDelaySlot = false;
  // Word alignment follows the virtual address, not the file offset.
  const skip = (4 - (region.address % 4)) % 4;
  for (let rel = skip; rel + 4 <= region.length; rel += 4) {
    const fileOffset = region.fileOffset + rel;
    const word = view.getUint32(fileOffset, true);
    current = decode(word, (region.address + rel) >>> 0, fileOffset);

    // Aligned pointer words: any 32-bit value equal to a target address.
    const wordTarget = findTarget(word);
    if (wordTarget !== undefined)
      emit({
        kind: "pointer_word",
        instruction: null,
        register: null,
        formed: word,
        target: wordTarget,
      });

    const effect = effectOf(scanner, current);
    if (effect.dest !== undefined && effect.dest !== 0)
      regs[effect.dest] = effect.value;

    if (inDelaySlot) {
      if (pending === "call") for (const r of CALLER_SAVED) regs[r] = undefined;
      else {
        regs.fill(undefined);
        regs[28] = gpValue; // a new function starts with the global $gp
      }
      pending = undefined;
      inDelaySlot = false;
    }
    if (effect.next !== undefined) {
      pending = effect.next;
      inDelaySlot = true;
    }
  }
  return results;
};

export const formatAddress32 = hex;
