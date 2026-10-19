import type {
  CodeReferenceArchitecture,
  CodeReferenceKind,
  RawReference,
  ScanOptions,
  ScanRegion,
  ScanTarget,
} from "./romCodeReferences.js";

interface Target {
  readonly start: number;
  readonly length: number;
  readonly index: number;
}

const hex32 = (value: number): string =>
  `0x${(value >>> 0).toString(16).padStart(8, "0")}`;

const hex16 = (value: number): string =>
  `0x${(value & 0xffff).toString(16).padStart(4, "0")}`;

const hex24 = (value: number): string =>
  `0x${(value & 0xffffff).toString(16).padStart(6, "0")}`;

const formatBytes = (
  bytes: Uint8Array,
  offset: number,
  length: number,
): string => {
  const parts: string[] = [];
  for (let i = 0; i < length && offset + i < bytes.length; i++) {
    parts.push((bytes[offset + i] ?? 0).toString(16).padStart(2, "0"));
  }
  return parts.join(" ");
};

export const callerSignatureAt = (
  bytes: Uint8Array,
  fileOffset: number,
  regionOffset: number,
  regionLength: number,
): string => {
  const start = Math.max(regionOffset, fileOffset - 8);
  const end = Math.min(regionOffset + regionLength, fileOffset + 16);
  const hexParts: string[] = [];
  for (let i = start; i < end && i < bytes.length; i++) {
    hexParts.push((bytes[i] ?? 0).toString(16).padStart(2, "0"));
  }
  return hexParts.join("");
};

const makeTargetFinder = (scanTargets: readonly ScanTarget[]) => {
  const targets: Target[] = scanTargets.map((target, index) => ({
    start: target.address >>> 0,
    length: target.length,
    index,
  }));
  if (targets.length === 0) return () => undefined;
  const minStart = Math.min(...targets.map((t) => t.start));
  const maxEnd = Math.max(...targets.map((t) => t.start + t.length));
  return (address: number): Target | undefined => {
    const unsigned = address >>> 0;
    if (unsigned < minStart || unsigned >= maxEnd) return undefined;
    return targets.find(
      (t) => unsigned >= t.start && unsigned < t.start + t.length,
    );
  };
};

interface ShRegVal {
  readonly value: number;
  readonly poolAddress: number | null;
}

const signExtend8 = (v: number): number => (v << 24) >> 24;
const signExtend12 = (v: number): number => (v << 20) >> 20;

const snapshotArgs = (
  regs: readonly (ShRegVal | undefined)[],
  indices: readonly number[],
  prefix: string,
): Record<string, string> | undefined => {
  const out: Record<string, string> = {};
  let any = false;
  for (const idx of indices) {
    const val = regs[idx];
    if (val !== undefined) {
      out[`${prefix}${idx}`] = hex32(val.value);
      any = true;
    }
  }
  return any ? out : undefined;
};

/** Scan a SuperH region (`sh2-be` for Saturn, `sh4-le` for Dreamcast). */
export const scanSuperHRegion = (
  region: ScanRegion,
  scanTargets: readonly ScanTarget[],
  kinds: ReadonlySet<CodeReferenceKind>,
  littleEndian: boolean,
  options?: ScanOptions,
): RawReference[] => {
  const findTarget = makeTargetFinder(scanTargets);
  const results: RawReference[] = [];
  const view = new DataView(
    region.bytes.buffer,
    region.bytes.byteOffset,
    region.bytes.byteLength,
  );
  const regs = Array.from<ShRegVal | undefined>({ length: 16 });
  const pushHit = (hit: Omit<RawReference, "callerSignature">) => {
    if (!kinds.has(hit.kind)) return;
    results.push({
      ...hit,
      ...(options?.includeCallerSignatures
        ? {
            callerSignature: callerSignatureAt(
              region.bytes,
              hit.fileOffset,
              region.fileOffset,
              region.length,
            ),
          }
        : {}),
    });
  };
  let pendingDelay: "call" | "reset" | undefined;
  const skip = region.address % 2;
  for (let rel = skip; rel + 2 <= region.length; rel += 2) {
    const fileOffset = region.fileOffset + rel;
    const pc = (region.address + rel) >>> 0;
    if (pc % 4 === 0 && rel + 4 <= region.length) {
      const word = view.getUint32(fileOffset, littleEndian);
      const wordTarget = findTarget(word);
      if (wordTarget !== undefined) {
        pushHit({
          kind: "pointer_word",
          fileOffset,
          address: pc,
          instruction: null,
          bytes: formatBytes(region.bytes, fileOffset, 4),
          register: null,
          targetAddress: word,
          targetIndex: wordTarget.index,
          sourceLuiAddress: null,
        });
      }
    }
    const insn = view.getUint16(fileOffset, littleEndian);
    const insnBytes = formatBytes(region.bytes, fileOffset, 2);
    const top4 = (insn >>> 12) & 0xf;
    const rn = (insn >>> 8) & 0xf;
    const rm = (insn >>> 4) & 0xf;
    let nextDelay: "call" | "reset" | undefined;

    if (top4 === 0xd) {
      // mov.l @(disp, PC), Rn
      const disp = insn & 0xff;
      const poolPc = (((pc + 4) & ~3) + disp * 4) >>> 0;
      const poolRel = poolPc - region.address;
      if (poolRel >= 0 && poolRel + 4 <= region.length) {
        const lit = view.getUint32(region.fileOffset + poolRel, littleEndian);
        regs[rn] = { value: lit, poolAddress: poolPc };
        const t = findTarget(lit);
        if (t !== undefined) {
          pushHit({
            kind: "address_pair",
            fileOffset,
            address: pc,
            instruction: `mov.l @(${hex32(poolPc)}, pc), r${rn}`,
            bytes: insnBytes,
            register: `r${rn}`,
            targetAddress: lit,
            targetIndex: t.index,
            sourceLuiAddress: poolPc,
          });
        }
      } else {
        regs[rn] = undefined;
      }
    } else if (top4 === 0x9) {
      // mov.w @(disp, PC), Rn
      const disp = insn & 0xff;
      const poolPc = (pc + 4 + disp * 2) >>> 0;
      const poolRel = poolPc - region.address;
      if (poolRel >= 0 && poolRel + 2 <= region.length) {
        const lit =
          view.getInt16(region.fileOffset + poolRel, littleEndian) >>> 0;
        regs[rn] = { value: lit, poolAddress: poolPc };
      } else {
        regs[rn] = undefined;
      }
    } else if (top4 === 0xe) {
      // mov #imm8, Rn
      regs[rn] = { value: signExtend8(insn & 0xff) >>> 0, poolAddress: null };
    } else if (top4 === 0x7) {
      // add #imm8, Rn
      const base = regs[rn];
      if (base !== undefined) {
        const formed = (base.value + signExtend8(insn & 0xff)) >>> 0;
        regs[rn] = { value: formed, poolAddress: base.poolAddress };
        const t = findTarget(formed);
        if (t !== undefined) {
          pushHit({
            kind: "address_pair",
            fileOffset,
            address: pc,
            instruction: `add #${signExtend8(insn & 0xff)}, r${rn}`,
            bytes: insnBytes,
            register: `r${rn}`,
            targetAddress: formed,
            targetIndex: t.index,
            sourceLuiAddress: base.poolAddress,
          });
        }
      }
    } else if (top4 === 0x6 && (insn & 0xf) === 3) {
      // mov Rm, Rn
      regs[rn] = regs[rm];
    } else if (top4 === 0xb || top4 === 0xa) {
      // bsr / bra label12
      const isCall = top4 === 0xb;
      const dest = (pc + 4 + signExtend12(insn & 0xfff) * 2) >>> 0;
      const t = findTarget(dest);
      if (t !== undefined) {
        const callArguments =
          isCall && options?.resolveCallArguments
            ? snapshotArgs(regs, [4, 5, 6, 7], "r")
            : undefined;
        pushHit({
          kind: isCall ? "call" : "jump",
          fileOffset,
          address: pc,
          instruction: `${isCall ? "bsr" : "bra"} ${hex32(dest)}`,
          bytes: insnBytes,
          register: null,
          targetAddress: dest,
          targetIndex: t.index,
          sourceLuiAddress: null,
          ...(callArguments === undefined ? {} : { callArguments }),
        });
      }
      nextDelay = isCall ? "call" : "reset";
    } else if (
      top4 === 0x4 &&
      ((insn & 0xff) === 0x0b || (insn & 0xff) === 0x2b)
    ) {
      // jsr @Rn / jmp @Rn
      const isCall = (insn & 0xff) === 0x0b;
      const targetReg = regs[rn];
      if (targetReg !== undefined) {
        const t = findTarget(targetReg.value);
        if (t !== undefined) {
          const callArguments =
            isCall && options?.resolveCallArguments
              ? snapshotArgs(regs, [4, 5, 6, 7], "r")
              : undefined;
          pushHit({
            kind: isCall ? "call" : "jump",
            fileOffset,
            address: pc,
            instruction: `${isCall ? "jsr" : "jmp"} @r${rn}`,
            bytes: insnBytes,
            register: `r${rn}`,
            targetAddress: targetReg.value,
            targetIndex: t.index,
            sourceLuiAddress: targetReg.poolAddress,
            ...(callArguments === undefined ? {} : { callArguments }),
          });
        }
      }
      nextDelay = isCall ? "call" : "reset";
    } else if (insn === 0x000b) {
      // rts
      nextDelay = "reset";
    }

    if (pendingDelay !== undefined) {
      if (pendingDelay === "call") {
        for (let r = 0; r <= 7; r++) regs[r] = undefined;
      } else {
        regs.fill(undefined);
      }
      pendingDelay = undefined;
    }
    if (nextDelay !== undefined) pendingDelay = nextDelay;
  }
  return results;
};

const SNES_LONG_LOAD_STORE: ReadonlyMap<number, string> = new Map([
  [0xaf, "lda.l"],
  [0xbf, "lda.l"],
  [0x8f, "sta.l"],
  [0x9f, "sta.l"],
  [0xcf, "cmp.l"],
  [0xdf, "cmp.l"],
]);

/** Scan a 65816 (SNES) code region for 24-bit JSL/JML/LDA.l/STA.l and 16-bit JSR/JMP references. */
export const scan65816Region = (
  region: ScanRegion,
  scanTargets: readonly ScanTarget[],
  kinds: ReadonlySet<CodeReferenceKind>,
  options?: ScanOptions,
): RawReference[] => {
  const findTarget = makeTargetFinder(scanTargets);
  const results: RawReference[] = [];
  const bytes = region.bytes;
  for (let rel = 0; rel < region.length; rel++) {
    const fileOffset = region.fileOffset + rel;
    const pc = (region.address + rel) >>> 0;
    const op = bytes[fileOffset] ?? 0;

    if ((op === 0x22 || op === 0x5c) && rel + 4 <= region.length) {
      // JSL / JML 24-bit
      const isCall = op === 0x22;
      const dest =
        ((bytes[fileOffset + 1] ?? 0) |
          ((bytes[fileOffset + 2] ?? 0) << 8) |
          ((bytes[fileOffset + 3] ?? 0) << 16)) >>>
        0;
      const t = findTarget(dest);
      if (t !== undefined && kinds.has(isCall ? "call" : "jump")) {
        results.push({
          kind: isCall ? "call" : "jump",
          fileOffset,
          address: pc,
          instruction: `${isCall ? "jsl" : "jml"} ${hex24(dest)}`,
          bytes: formatBytes(bytes, fileOffset, 4),
          register: null,
          targetAddress: dest,
          targetIndex: t.index,
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
      }
    } else if (SNES_LONG_LOAD_STORE.has(op) && rel + 4 <= region.length) {
      const dest =
        ((bytes[fileOffset + 1] ?? 0) |
          ((bytes[fileOffset + 2] ?? 0) << 8) |
          ((bytes[fileOffset + 3] ?? 0) << 16)) >>>
        0;
      const t = findTarget(dest);
      if (t !== undefined && kinds.has("address_pair")) {
        const mnemonic = SNES_LONG_LOAD_STORE.get(op) ?? "mem.l";
        const indexed = op === 0xbf || op === 0x9f || op === 0xdf ? ",x" : "";
        results.push({
          kind: "address_pair",
          fileOffset,
          address: pc,
          instruction: `${mnemonic} ${hex24(dest)}${indexed}`,
          bytes: formatBytes(bytes, fileOffset, 4),
          register: null,
          targetAddress: dest,
          targetIndex: t.index,
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
      }
    } else if ((op === 0x20 || op === 0x4c) && rel + 3 <= region.length) {
      // JSR / JMP 16-bit within current program bank
      const isCall = op === 0x20;
      const addr16 =
        (bytes[fileOffset + 1] ?? 0) | ((bytes[fileOffset + 2] ?? 0) << 8);
      const bank = pc & 0xff0000;
      const dest = (bank | addr16) >>> 0;
      const t = findTarget(dest) ?? findTarget(addr16);
      if (t !== undefined && kinds.has(isCall ? "call" : "jump")) {
        const matchedAddr = findTarget(dest) !== undefined ? dest : addr16;
        results.push({
          kind: isCall ? "call" : "jump",
          fileOffset,
          address: pc,
          instruction: `${isCall ? "jsr" : "jmp"} ${hex16(addr16)}`,
          bytes: formatBytes(bytes, fileOffset, 3),
          register: null,
          targetAddress: matchedAddr,
          targetIndex: t.index,
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
      }
    }
  }
  return results;
};

const MOS6502_ABS_OPS: ReadonlyMap<number, string> = new Map([
  [0xad, "lda"],
  [0xbd, "lda.x"],
  [0xb9, "lda.y"],
  [0xae, "ldx"],
  [0xbe, "ldx.y"],
  [0xac, "ldy"],
  [0xbc, "ldy.x"],
  [0x8d, "sta"],
  [0x9d, "sta.x"],
  [0x99, "sta.y"],
  [0x8e, "stx"],
  [0x8c, "sty"],
  [0xcd, "cmp"],
  [0xdd, "cmp.x"],
  [0xd9, "cmp.y"],
  [0xec, "cpx"],
  [0xcc, "cpy"],
  [0x2c, "bit"],
  [0xee, "inc"],
  [0xce, "dec"],
]);

const HUC6280_BLOCK_OPS: ReadonlyMap<number, string> = new Map([
  [0x73, "tii"],
  [0xc3, "tdd"],
  [0xd3, "tin"],
  [0xe3, "tia"],
  [0xf3, "tai"],
]);

/** Scan a 6502 (NES) or HuC6280 (PC Engine) region. */
export const scan6502Region = (
  region: ScanRegion,
  scanTargets: readonly ScanTarget[],
  kinds: ReadonlySet<CodeReferenceKind>,
  isHuC6280: boolean,
  options?: ScanOptions,
): RawReference[] => {
  const findTarget = makeTargetFinder(scanTargets);
  const results: RawReference[] = [];
  const bytes = region.bytes;
  for (let rel = 0; rel < region.length; rel++) {
    const fileOffset = region.fileOffset + rel;
    const pc = (region.address + rel) >>> 0;
    const op = bytes[fileOffset] ?? 0;

    if (isHuC6280 && HUC6280_BLOCK_OPS.has(op) && rel + 7 <= region.length) {
      const mnemonic = HUC6280_BLOCK_OPS.get(op)!;
      const src =
        (bytes[fileOffset + 1] ?? 0) | ((bytes[fileOffset + 2] ?? 0) << 8);
      const dst =
        (bytes[fileOffset + 3] ?? 0) | ((bytes[fileOffset + 4] ?? 0) << 8);
      const len =
        (bytes[fileOffset + 5] ?? 0) | ((bytes[fileOffset + 6] ?? 0) << 8);
      for (const candidate of [src, dst]) {
        const t = findTarget(candidate);
        if (t !== undefined && kinds.has("address_pair")) {
          results.push({
            kind: "address_pair",
            fileOffset,
            address: pc,
            instruction: `${mnemonic} ${hex16(src)}, ${hex16(dst)}, ${hex16(len)}`,
            bytes: formatBytes(bytes, fileOffset, 7),
            register: null,
            targetAddress: candidate,
            targetIndex: t.index,
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
        }
      }
      continue;
    }

    if ((op === 0x20 || op === 0x4c) && rel + 3 <= region.length) {
      const isCall = op === 0x20;
      const dest =
        (bytes[fileOffset + 1] ?? 0) | ((bytes[fileOffset + 2] ?? 0) << 8);
      const t = findTarget(dest);
      if (t !== undefined && kinds.has(isCall ? "call" : "jump")) {
        results.push({
          kind: isCall ? "call" : "jump",
          fileOffset,
          address: pc,
          instruction: `${isCall ? "jsr" : "jmp"} ${hex16(dest)}`,
          bytes: formatBytes(bytes, fileOffset, 3),
          register: null,
          targetAddress: dest,
          targetIndex: t.index,
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
      }
    } else if (MOS6502_ABS_OPS.has(op) && rel + 3 <= region.length) {
      const dest =
        (bytes[fileOffset + 1] ?? 0) | ((bytes[fileOffset + 2] ?? 0) << 8);
      const t = findTarget(dest);
      if (t !== undefined && kinds.has("address_pair")) {
        const mnemonic = MOS6502_ABS_OPS.get(op)!;
        results.push({
          kind: "address_pair",
          fileOffset,
          address: pc,
          instruction: `${mnemonic} ${hex16(dest)}`,
          bytes: formatBytes(bytes, fileOffset, 3),
          register: null,
          targetAddress: dest,
          targetIndex: t.index,
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
      }
    }
  }
  return results;
};

const signExtend24 = (v: number): number => (v << 8) >> 8;

/** Scan an ARM32 little-endian (`arm-le`) or Thumb little-endian (`thumb-le`) region. */
export const scanArmOrThumbRegion = (
  region: ScanRegion,
  scanTargets: readonly ScanTarget[],
  kinds: ReadonlySet<CodeReferenceKind>,
  isThumb: boolean,
  options?: ScanOptions,
): RawReference[] => {
  const findTarget = makeTargetFinder(scanTargets);
  const results: RawReference[] = [];
  const view = new DataView(
    region.bytes.buffer,
    region.bytes.byteOffset,
    region.bytes.byteLength,
  );
  const regs = Array.from<ShRegVal | undefined>({ length: 16 });
  const pushHit = (hit: Omit<RawReference, "callerSignature">) => {
    if (!kinds.has(hit.kind)) return;
    results.push({
      ...hit,
      ...(options?.includeCallerSignatures
        ? {
            callerSignature: callerSignatureAt(
              region.bytes,
              hit.fileOffset,
              region.fileOffset,
              region.length,
            ),
          }
        : {}),
    });
  };

  if (!isThumb) {
    const skip = (4 - (region.address % 4)) % 4;
    for (let rel = skip; rel + 4 <= region.length; rel += 4) {
      const fileOffset = region.fileOffset + rel;
      const pc = (region.address + rel) >>> 0;
      const word = view.getUint32(fileOffset, true);
      const wordTarget = findTarget(word);
      if (wordTarget !== undefined) {
        pushHit({
          kind: "pointer_word",
          fileOffset,
          address: pc,
          instruction: null,
          bytes: formatBytes(region.bytes, fileOffset, 4),
          register: null,
          targetAddress: word,
          targetIndex: wordTarget.index,
          sourceLuiAddress: null,
        });
      }
      const cond = (word >>> 28) & 0xf;
      if (cond === 0xf) continue;
      if (((word >>> 25) & 0x7) === 0b101) {
        const isLink = ((word >>> 24) & 1) === 1;
        const dest = (pc + 8 + (signExtend24(word & 0xffffff) << 2)) >>> 0;
        const t = findTarget(dest);
        if (t !== undefined) {
          const callArguments =
            isLink && options?.resolveCallArguments
              ? snapshotArgs(regs, [0, 1, 2, 3], "r")
              : undefined;
          pushHit({
            kind: isLink ? "call" : "jump",
            fileOffset,
            address: pc,
            instruction: `${isLink ? "bl" : "b"} ${hex32(dest)}`,
            bytes: formatBytes(region.bytes, fileOffset, 4),
            register: null,
            targetAddress: dest,
            targetIndex: t.index,
            sourceLuiAddress: null,
            ...(callArguments === undefined ? {} : { callArguments }),
          });
        }
        if (isLink) {
          for (let r = 0; r <= 3; r++) regs[r] = undefined;
        }
      } else if ((word & 0x0f7f0000) === 0x051f0000) {
        // LDR Rd, [PC, #±imm12]
        const up = ((word >>> 23) & 1) === 1;
        const rd = (word >>> 12) & 0xf;
        const imm12 = word & 0xfff;
        const poolPc = (pc + 8 + (up ? imm12 : -imm12)) >>> 0;
        const poolRel = poolPc - region.address;
        if (poolRel >= 0 && poolRel + 4 <= region.length) {
          const lit = view.getUint32(region.fileOffset + poolRel, true);
          regs[rd] = { value: lit, poolAddress: poolPc };
          const t = findTarget(lit);
          if (t !== undefined) {
            pushHit({
              kind: "address_pair",
              fileOffset,
              address: pc,
              instruction: `ldr r${rd}, [pc, #${up ? "" : "-"}0x${imm12.toString(16)}]`,
              bytes: formatBytes(region.bytes, fileOffset, 4),
              register: `r${rd}`,
              targetAddress: lit,
              targetIndex: t.index,
              sourceLuiAddress: poolPc,
            });
          }
        }
      }
    }
    return results;
  }

  // Thumb little-endian (16-bit instructions, 32-bit BL pair)
  const skip = region.address % 2;
  for (let rel = skip; rel + 2 <= region.length; rel += 2) {
    const fileOffset = region.fileOffset + rel;
    const pc = (region.address + rel) >>> 0;
    if (pc % 4 === 0 && rel + 4 <= region.length) {
      const word = view.getUint32(fileOffset, true);
      const wordTarget = findTarget(word);
      if (wordTarget !== undefined) {
        pushHit({
          kind: "pointer_word",
          fileOffset,
          address: pc,
          instruction: null,
          bytes: formatBytes(region.bytes, fileOffset, 4),
          register: null,
          targetAddress: word,
          targetIndex: wordTarget.index,
          sourceLuiAddress: null,
        });
      }
    }
    const hw1 = view.getUint16(fileOffset, true);
    if ((hw1 & 0xf800) === 0xf000 && rel + 4 <= region.length) {
      const hw2 = view.getUint16(fileOffset + 2, true);
      if ((hw2 & 0xf800) === 0xf800 || (hw2 & 0xf800) === 0xe800) {
        const hi = ((hw1 & 0x7ff) << 21) >> 9; // sign-extended 11-bit shifted by 12
        const lo = (hw2 & 0x7ff) << 1;
        const dest = (pc + 4 + hi + lo) >>> 0;
        const t = findTarget(dest);
        if (t !== undefined) {
          const callArguments = options?.resolveCallArguments
            ? snapshotArgs(regs, [0, 1, 2, 3], "r")
            : undefined;
          pushHit({
            kind: "call",
            fileOffset,
            address: pc,
            instruction: `bl ${hex32(dest)}`,
            bytes: formatBytes(region.bytes, fileOffset, 4),
            register: null,
            targetAddress: dest,
            targetIndex: t.index,
            sourceLuiAddress: null,
            ...(callArguments === undefined ? {} : { callArguments }),
          });
        }
        for (let r = 0; r <= 3; r++) regs[r] = undefined;
      }
    } else if ((hw1 & 0xf800) === 0x4800) {
      // LDR Rd, [PC, #imm8*4]
      const rd = (hw1 >>> 8) & 7;
      const imm8 = hw1 & 0xff;
      const poolPc = (((pc + 4) & ~3) + imm8 * 4) >>> 0;
      const poolRel = poolPc - region.address;
      if (poolRel >= 0 && poolRel + 4 <= region.length) {
        const lit = view.getUint32(region.fileOffset + poolRel, true);
        regs[rd] = { value: lit, poolAddress: poolPc };
        const t = findTarget(lit);
        if (t !== undefined) {
          pushHit({
            kind: "address_pair",
            fileOffset,
            address: pc,
            instruction: `ldr r${rd}, [pc, #0x${(imm8 * 4).toString(16)}]`,
            bytes: formatBytes(region.bytes, fileOffset, 2),
            register: `r${rd}`,
            targetAddress: lit,
            targetIndex: t.index,
            sourceLuiAddress: poolPc,
          });
        }
      }
    } else if ((hw1 & 0xf800) === 0x2000) {
      // MOV Rd, #imm8
      const rd = (hw1 >>> 8) & 7;
      regs[rd] = { value: hw1 & 0xff, poolAddress: null };
    }
  }
  return results;
};

export const scanArchitectureRegion = (
  architecture: Exclude<CodeReferenceArchitecture, "mips-le">,
  region: ScanRegion,
  scanTargets: readonly ScanTarget[],
  kinds: ReadonlySet<CodeReferenceKind>,
  options?: ScanOptions,
): RawReference[] => {
  switch (architecture) {
    case "sh2-be":
      return scanSuperHRegion(region, scanTargets, kinds, false, options);
    case "sh4-le":
      return scanSuperHRegion(region, scanTargets, kinds, true, options);
    case "65816":
      return scan65816Region(region, scanTargets, kinds, options);
    case "6502":
      return scan6502Region(region, scanTargets, kinds, false, options);
    case "huc6280":
      return scan6502Region(region, scanTargets, kinds, true, options);
    case "arm-le":
      return scanArmOrThumbRegion(region, scanTargets, kinds, false, options);
    case "thumb-le":
      return scanArmOrThumbRegion(region, scanTargets, kinds, true, options);
  }
};
