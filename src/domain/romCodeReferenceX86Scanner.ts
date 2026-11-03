import type {
  CodeReferenceKind,
  RawReference,
  ScanOptions,
  ScanRegion,
  ScanTarget,
} from "./romCodeReferences.js";
import { dosFarPointerLinearAddress } from "./dosRealModeImage.js";
import {
  callerSignatureAt,
  formatBytes,
  makeTargetFinder,
} from "./romCodeReferenceArchScanners.js";

/**
 * Byte-sweep reference scanner for x86 DOS programs. `x86-32` reads flat
 * 32-bit operands (DOS extender LE/LX after fixups); `x86-16` reads real-mode
 * operands as linear addresses: near data offsets through the region's data
 * segment, far pointers as segment * 16 + offset. Every byte offset is decoded
 * as a possible instruction start, so a hit is a candidate, not a proven
 * instruction boundary.
 */

const REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const REG16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"];

/** Opcodes followed by a ModRM byte whose memory operand may hold an address. */
const MODRM_OPS: ReadonlyMap<number, string> = new Map([
  [0x00, "add"],
  [0x01, "add"],
  [0x02, "add"],
  [0x03, "add"],
  [0x08, "or"],
  [0x09, "or"],
  [0x0a, "or"],
  [0x0b, "or"],
  [0x20, "and"],
  [0x21, "and"],
  [0x22, "and"],
  [0x23, "and"],
  [0x28, "sub"],
  [0x29, "sub"],
  [0x2a, "sub"],
  [0x2b, "sub"],
  [0x30, "xor"],
  [0x31, "xor"],
  [0x32, "xor"],
  [0x33, "xor"],
  [0x38, "cmp"],
  [0x39, "cmp"],
  [0x3a, "cmp"],
  [0x3b, "cmp"],
  [0x80, "alu"],
  [0x81, "alu"],
  [0x83, "alu"],
  [0x84, "test"],
  [0x85, "test"],
  [0x86, "xchg"],
  [0x87, "xchg"],
  [0x88, "mov"],
  [0x89, "mov"],
  [0x8a, "mov"],
  [0x8b, "mov"],
  [0x8d, "lea"],
  [0xc6, "mov"],
  [0xc7, "mov"],
  [0xf6, "grp3"],
  [0xf7, "grp3"],
  [0xfe, "grp4"],
  [0xff, "grp5"],
]);
const MODRM_0F_OPS: ReadonlyMap<number, string> = new Map([
  [0xb6, "movzx"],
  [0xb7, "movzx"],
  [0xbe, "movsx"],
  [0xbf, "movsx"],
]);
const GRP5 = ["inc", "dec", "call", "call far", "jmp", "jmp far", "push", "?"];

const hexAddress = (value: number): string => `0x${(value >>> 0).toString(16)}`;

/** Memory operand of a ModRM byte: displacement position, width and absoluteness. */
interface ModRmOperand {
  /** Bytes from the ModRM byte to the end of SIB and displacement. */
  readonly length: number;
  /** Offset of a full-width displacement from the ModRM byte, if present. */
  readonly displacementAt?: number;
  readonly absolute: boolean;
  readonly reg: number;
}

const decodeModRm = (
  bytes: Uint8Array,
  at: number,
  wide: boolean,
): ModRmOperand => {
  const modrm = bytes[at] ?? 0;
  const mod = modrm >>> 6;
  const reg = (modrm >>> 3) & 7;
  const rm = modrm & 7;
  if (mod === 3) return { length: 1, absolute: false, reg };
  if (!wide) {
    if (mod === 0 && rm === 6)
      return { length: 3, displacementAt: 1, absolute: true, reg };
    // [bp+...] forms address the stack segment, not data.
    const stack = rm === 2 || rm === 3 || rm === 6;
    if (mod === 2)
      return stack
        ? { length: 3, absolute: false, reg }
        : { length: 3, displacementAt: 1, absolute: false, reg };
    return { length: mod === 1 ? 2 : 1, absolute: false, reg };
  }
  const hasSib = rm === 4;
  const sibBase = (bytes[at + 1] ?? 0) & 7;
  const base = hasSib ? 2 : 1;
  if (mod === 0 && (hasSib ? sibBase === 5 : rm === 5))
    return {
      length: base + 4,
      displacementAt: base,
      absolute: !hasSib || ((bytes[at + 1] ?? 0) >>> 3) % 8 === 4,
      reg,
    };
  if (mod === 2) {
    // [ebp+disp32] and [esp+disp32] are stack frame slots.
    const baseRegister = hasSib ? sibBase : rm;
    return baseRegister === 4 || baseRegister === 5
      ? { length: base + 4, absolute: false, reg }
      : { length: base + 4, displacementAt: base, absolute: false, reg };
  }
  return { length: base + (mod === 1 ? 1 : 0), absolute: false, reg };
};

/** Immediate width after the operand, for opcodes whose immediate may be an address. */
const immediateWidth = (op: number, wide: boolean): number =>
  op === 0xc7 || op === 0x81 ? (wide ? 4 : 2) : 0;

/** File offsets of the region's 4-byte-aligned address words. */
const alignedOffsets = (region: ScanRegion): number[] => {
  const offsets: number[] = [];
  const first = region.fileOffset + ((4 - (region.address % 4)) % 4);
  for (let at = first; at + 4 <= region.fileOffset + region.length; at += 4)
    offsets.push(at);
  return offsets;
};

/** Scan an x86 region for call, jump, operand and pointer references. */
export const scanX86Region = (
  region: ScanRegion,
  scanTargets: readonly ScanTarget[],
  kinds: ReadonlySet<CodeReferenceKind>,
  wide: boolean,
  options?: ScanOptions,
): RawReference[] => {
  const findTarget = makeTargetFinder(scanTargets);
  const bytes = region.bytes;
  const results: RawReference[] = [];
  const operandWidth = wide ? 4 : 2;
  const dataBase = region.dataSegmentBase;
  /** File offsets of operands already reported by an instruction. */
  const operandOffsets = new Set<number>();
  const regionEnd = region.fileOffset + region.length;
  const read = (offset: number, width: number): number | undefined => {
    if (offset < region.fileOffset || offset + width > regionEnd)
      return undefined;
    let value = 0;
    for (let i = width - 1; i >= 0; i--)
      value = value * 256 + (bytes[offset + i] ?? 0);
    return value;
  };
  /** Linear address named by an operand value. */
  const operandAddress = (value: number): number | undefined =>
    wide ? value : dataBase === undefined ? undefined : dataBase + value;
  const push = (
    kind: CodeReferenceKind,
    fileOffset: number,
    instructionBytes: number,
    instruction: string,
    register: string | null,
    targetAddress: number,
    operandOffset: number | null,
  ): void => {
    const target = findTarget(targetAddress);
    if (target === undefined || !kinds.has(kind)) return;
    if (operandOffset !== null) operandOffsets.add(operandOffset);
    results.push({
      kind,
      fileOffset,
      address: region.address + (fileOffset - region.fileOffset),
      instruction,
      bytes: formatBytes(bytes, fileOffset, instructionBytes),
      register,
      targetAddress: targetAddress >>> 0,
      targetIndex: target.index,
      sourceLuiAddress: null,
      ...(options?.includeCallerSignatures
        ? {
            callerSignature: callerSignatureAt(
              bytes,
              fileOffset,
              region.fileOffset,
              region.length,
            ),
          }
        : {}),
    });
  };
  const executable = region.executable !== false;

  for (let at = region.fileOffset; executable && at < regionEnd; at++) {
    const op = bytes[at] ?? 0;
    const pc = region.address + (at - region.fileOffset);
    const regs = wide ? REG32 : REG16;
    if (op === 0xe8 || op === 0xe9) {
      const rel = read(at + 1, operandWidth);
      if (rel === undefined) continue;
      const signed = wide ? rel | 0 : (rel << 16) >> 16;
      const destination = (pc + 1 + operandWidth + signed) >>> 0;
      push(
        op === 0xe8 ? "call" : "jump",
        at,
        1 + operandWidth,
        `${op === 0xe8 ? "call" : "jmp"} ${hexAddress(destination)}`,
        null,
        destination,
        null,
      );
    } else if (op === 0x0f && ((bytes[at + 1] ?? 0) & 0xf0) === 0x80) {
      const rel = read(at + 2, operandWidth);
      if (rel === undefined) continue;
      const signed = wide ? rel | 0 : (rel << 16) >> 16;
      const destination = (pc + 2 + operandWidth + signed) >>> 0;
      push(
        "jump",
        at,
        2 + operandWidth,
        `jcc ${hexAddress(destination)}`,
        null,
        destination,
        null,
      );
    } else if (!wide && (op === 0x9a || op === 0xea)) {
      const far = read(at + 1, 4);
      if (far === undefined) continue;
      const destination = dosFarPointerLinearAddress(far);
      push(
        op === 0x9a ? "call" : "jump",
        at,
        5,
        `${op === 0x9a ? "call" : "jmp"} far ${(far >>> 16).toString(16)}:${(far & 0xffff).toString(16)}`,
        null,
        destination,
        at + 1,
      );
    } else if (op >= 0xb8 && op <= 0xbf) {
      const value = read(at + 1, operandWidth);
      const address = value === undefined ? undefined : operandAddress(value);
      if (address === undefined) continue;
      const register = regs[op - 0xb8]!;
      push(
        "address_pair",
        at,
        1 + operandWidth,
        `mov ${register}, ${hexAddress(value!)}`,
        register,
        address,
        at + 1,
      );
    } else if (op === 0x68) {
      const value = read(at + 1, operandWidth);
      const address = value === undefined ? undefined : operandAddress(value);
      if (address === undefined) continue;
      push(
        "address_pair",
        at,
        1 + operandWidth,
        `push ${hexAddress(value!)}`,
        null,
        address,
        at + 1,
      );
    } else if (op >= 0xa0 && op <= 0xa3) {
      const value = read(at + 1, operandWidth);
      const address = value === undefined ? undefined : operandAddress(value);
      if (address === undefined) continue;
      const accumulator = op % 2 === 0 ? "al" : wide ? "eax" : "ax";
      const memory = `[${hexAddress(value!)}]`;
      push(
        "address_pair",
        at,
        1 + operandWidth,
        op < 0xa2
          ? `mov ${accumulator}, ${memory}`
          : `mov ${memory}, ${accumulator}`,
        accumulator,
        address,
        at + 1,
      );
    } else {
      const twoByte = op === 0x0f;
      const name = twoByte
        ? MODRM_0F_OPS.get(bytes[at + 1] ?? 0)
        : MODRM_OPS.get(op);
      if (name === undefined) continue;
      const modrmAt = at + (twoByte ? 2 : 1);
      if (modrmAt >= regionEnd) continue;
      const operand = decodeModRm(bytes, modrmAt, wide);
      const mnemonic = name === "grp5" ? GRP5[operand.reg]! : name;
      const immediateAt = modrmAt + operand.length;
      const instructionBytes =
        immediateAt -
        at +
        immediateWidth(op, wide) +
        (op === 0xc6 || op === 0x80 || op === 0x83 ? 1 : 0);
      if (operand.displacementAt !== undefined) {
        const displacementAt = modrmAt + operand.displacementAt;
        const value = read(displacementAt, operandWidth);
        const address = value === undefined ? undefined : operandAddress(value);
        if (address !== undefined)
          push(
            "address_pair",
            at,
            instructionBytes,
            `${mnemonic} [${operand.absolute ? "" : "reg+"}${hexAddress(value!)}]`,
            null,
            address,
            displacementAt,
          );
      }
      const width = immediateWidth(op, wide);
      if (width > 0) {
        const value = read(immediateAt, width);
        const address = value === undefined ? undefined : operandAddress(value);
        if (address !== undefined)
          push(
            "address_pair",
            at,
            instructionBytes,
            `${mnemonic} [..], ${hexAddress(value!)}`,
            null,
            address,
            immediateAt,
          );
      }
    }
  }

  if (kinds.has("pointer_word")) {
    const width = 4;
    const decodePointer = (value: number): number =>
      wide ? value : dosFarPointerLinearAddress(value);
    const sites =
      region.pointerSites ??
      (wide
        ? alignedOffsets(region)
        : // A real-mode far pointer without a relocation is not recognizable.
          []);
    for (const at of sites) {
      if (operandOffsets.has(at)) continue;
      const value = read(at, width);
      if (value === undefined) continue;
      push(
        "pointer_word",
        at,
        width,
        wide
          ? `dd ${hexAddress(value)}`
          : `dd ${(value >>> 16).toString(16)}:${(value & 0xffff).toString(16)}`,
        null,
        decodePointer(value),
        null,
      );
    }
  }
  return results;
};
