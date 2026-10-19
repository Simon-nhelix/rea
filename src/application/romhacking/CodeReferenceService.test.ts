import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CodeReferenceService } from "./CodeReferenceService.js";
import { findCodeReferencesResultSchema } from "../../domain/romCodeReferences.js";
import {
  parseFileSpec,
  parseTargetSpec,
} from "../../cli/codeReferenceCommands.js";

const words = (list: readonly number[]): Buffer => {
  const out = Buffer.alloc(list.length * 4);
  list.forEach((word, index) => out.writeUInt32LE(word >>> 0, index * 4));
  return out;
};
const jal = (target: number) =>
  ((3 << 26) | ((target >>> 2) & 0x03ffffff)) >>> 0;
const lui = (rt: number, imm: number) =>
  ((0x0f << 26) | (rt << 16) | imm) >>> 0;
const lhu = (rt: number, off: number, rs: number) =>
  ((0x25 << 26) | (rs << 21) | (rt << 16) | (off & 0xffff)) >>> 0;

const psxExe = (textAddress: number, body: Buffer): Buffer => {
  const header = Buffer.alloc(0x800);
  header.write("PS-X EXE", 0, "latin1");
  header.writeUInt32LE(textAddress, 0x18);
  header.writeUInt32LE(body.length, 0x1c);
  return Buffer.concat([header, body]);
};

let directory = "";
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), "rea-code-refs-"));
});
afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

const resultOf = (evidence: {
  normalized_result: unknown;
}): ReturnType<typeof findCodeReferencesResultSchema.parse> =>
  findCodeReferencesResultSchema.parse(evidence.normalized_result);

describe("CodeReferenceService", () => {
  it("scans a PS-X EXE and a headerless overlay with their own load addresses", async () => {
    const exe = join(directory, "MAIN.EXE");
    const overlay = join(directory, "OVL.BIN");
    await writeFile(
      exe,
      psxExe(
        0x80010000,
        words([0, 0, lui(2, 0x800d), lhu(3, -0xd2e & 0xffff, 2)]),
      ),
    );
    await writeFile(overlay, words([jal(0x800cba44), 0, 0x800d6590]));
    const result = await new CodeReferenceService().find({
      files: [{ path: exe }, { path: overlay, load_address: "0x800D61D8" }],
      targets: [
        { address: "0x800CBA44" },
        { address: "0x800CBCE8" },
        { address: "0x800CF2D2" },
        { address: "0x800D6590" },
      ],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const report = resultOf(result.value);
    expect(
      report.files.map((f) => [f.load_address, f.load_address_source]),
    ).toEqual([
      ["0x80010000", "ps-x-exe-header"],
      ["0x800d61d8", "caller"],
    ]);
    expect(report.files[0]?.scanned_file_offset).toBe(0x800);
    expect(
      report.summary.map((s) => [
        s.target,
        s.counts.total,
        s.verdict.slice(0, 12),
      ]),
    ).toEqual([
      ["0x800cba44", 1, "1 references"],
      ["0x800cbce8", 0, "0 references"],
      ["0x800cf2d2", 1, "1 references"],
      ["0x800d6590", 1, "1 references"],
    ]);
    const kinds = report.references.map((r) => [
      r.kind,
      r.file.endsWith("OVL.BIN"),
    ]);
    expect(kinds).toContainEqual(["address_pair", false]);
    expect(kinds).toContainEqual(["call", true]);
    expect(kinds).toContainEqual(["pointer_word", true]);
    expect(report.references.find((r) => r.kind === "call")).toMatchObject({
      file_offset: 0,
      address: "0x800d61d8",
    });
    expect(result.value.limitations.join("\n")).toContain("jr jump-table");
  });

  it("reports overlays that share a load address and truncates only the list", async () => {
    const a = join(directory, "A.BIN");
    const b = join(directory, "B.BIN");
    await writeFile(a, words([jal(0x80100000), 0, jal(0x80100000), 0]));
    await writeFile(b, words([jal(0x80100000), 0]));
    const result = await new CodeReferenceService().find({
      files: [
        { path: a, load_address: "0x800D61D8" },
        { path: b, load_address: "0x800D61D8" },
      ],
      targets: [{ address: "0x80100000" }],
      max_references: 1,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const report = resultOf(result.value);
    expect(report.overlapping_files).toEqual([[a, b]]);
    expect(report.total_references).toBe(3);
    expect(report.references).toHaveLength(1);
    expect(report.truncated).toBe(true);
    expect(report.summary[0]?.by_file.map((f) => f.count)).toEqual([2, 1]);
  });

  it("rejects a headerless file without a load address", async () => {
    const file = join(directory, "RAW.BIN");
    await writeFile(file, words([0, 0]));
    const result = await new CodeReferenceService().find({
      files: [{ path: file }],
      targets: [{ address: "0x80100000" }],
    });
    expect(result.ok).toBe(false);
  });

  it("rejects relative paths and invalid addresses", async () => {
    const service = new CodeReferenceService();
    expect(
      (
        await service.find({
          files: [{ path: "rel.bin", load_address: "0x80000000" }],
          targets: [{ address: "0x80100000" }],
        })
      ).ok,
    ).toBe(false);
    expect(
      (
        await service.find({
          files: [{ path: join(directory, "x"), load_address: "0x80000000" }],
          targets: [{ address: "nope" }],
        })
      ).ok,
    ).toBe(false);
  });
});

describe("gp-relative references", () => {
  const gpLui = lui(28, 0x8006);
  const gpAddiu =
    ((9 << 26) | (28 << 21) | (28 << 16) | (-0x3e58 & 0xffff)) >>> 0;
  const lwGp = ((0x23 << 26) | (28 << 21) | (3 << 16) | 0x308) >>> 0;

  it("infers gp from the first initializer and applies it to overlays", async () => {
    const exe = join(directory, "MAIN.EXE");
    const overlay = join(directory, "OVL.BIN");
    await writeFile(exe, psxExe(0x80010000, words([gpLui, gpAddiu, 0])));
    await writeFile(overlay, words([lwGp, 0]));
    const service = new CodeReferenceService();
    const run = (extra: Record<string, unknown>) =>
      service.find({
        files: [{ path: exe }, { path: overlay, load_address: "0x800D61D8" }],
        targets: [{ address: "0x8005C4B0" }],
        ...extra,
      });
    const auto = await run({});
    expect(auto.ok).toBe(true);
    if (!auto.ok) return;
    const report = resultOf(auto.value);
    expect(report.gp).toMatchObject({
      value: "0x8005c1a8",
      source: "auto",
      address: "0x80010000",
    });
    expect(report.summary[0]?.counts.gp_relative).toBe(1);
    expect(report.references[0]).toMatchObject({
      kind: "gp_relative",
      target_address: "0x8005c4b0",
    });

    const off = await run({ gp_relative: false });
    if (!off.ok) throw new Error("expected ok");
    expect(resultOf(off.value).summary[0]?.counts.total).toBe(0);

    const fileOff = await service.find({
      files: [
        { path: exe },
        { path: overlay, load_address: "0x800D61D8", use_gp: false },
      ],
      targets: [{ address: "0x8005C4B0" }],
    });
    if (!fileOff.ok) throw new Error("expected ok");
    expect(resultOf(fileOff.value).summary[0]?.counts.total).toBe(0);

    const given = await service.find({
      files: [{ path: overlay, load_address: "0x800D61D8" }],
      targets: [{ address: "0x8005C4B0" }],
      gp: "0x8005C1A8",
    });
    if (!given.ok) throw new Error("expected ok");
    expect(resultOf(given.value).gp.source).toBe("caller");
    expect(resultOf(given.value).summary[0]?.counts.gp_relative).toBe(1);
  });

  it("states that gp_relative was skipped when no gp is known", async () => {
    const overlay = join(directory, "OVL.BIN");
    await writeFile(overlay, words([lwGp, 0]));
    const result = await new CodeReferenceService().find({
      files: [{ path: overlay, load_address: "0x800D61D8" }],
      targets: [{ address: "0x8005C4B0" }],
    });
    if (!result.ok) throw new Error("expected ok");
    expect(resultOf(result.value).gp.value).toBeNull();
    expect(result.value.limitations.join("\n")).toContain(
      "gp_relative references were skipped",
    );
  });
});

describe("CLI spec parsing", () => {
  it("splits PATH:0xADDR and ADDR+LENGTH", () => {
    expect(parseFileSpec("/g/OVL/SNMP.BIN:0x800D61D8")).toEqual({
      path: "/g/OVL/SNMP.BIN",
      load_address: "0x800D61D8",
    });
    expect(parseFileSpec("/g/SLPS_026.36")).toEqual({ path: "/g/SLPS_026.36" });
    expect(parseTargetSpec("0x800D6590+64")).toEqual({
      address: "0x800D6590",
      length: 64,
    });
    expect(parseTargetSpec("0x800CBCE8")).toEqual({ address: "0x800CBCE8" });
  });

  it("auto-detects MIPS ELF32-LE PT_LOAD and CodeWarrior MWo3 overlay headers", async () => {
    const elfPath = join(directory, "SLPS_255.37");
    const mwo3Path = join(directory, "STG_000.BIN");
    const daddiu = (rt: number, rs: number, imm: number) =>
      ((0x19 << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)) >>> 0;

    // Build minimal ELF32-LE MIPS executable with PT_LOAD at offset 0x80 -> vaddr 0x00100000
    const elfHeader = Buffer.alloc(0x80, 0);
    elfHeader.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
    elfHeader.writeUInt16LE(2, 0x10);
    elfHeader.writeUInt16LE(8, 0x12);
    elfHeader.writeUInt32LE(0x34, 0x1c);
    elfHeader.writeUInt16LE(32, 0x2a);
    elfHeader.writeUInt16LE(1, 0x2c);
    elfHeader.writeUInt32LE(1, 0x34); // PT_LOAD
    elfHeader.writeUInt32LE(0x80, 0x38); // p_offset
    elfHeader.writeUInt32LE(0x00100000, 0x3c); // p_vaddr
    elfHeader.writeUInt32LE(8, 0x44); // p_filesz
    await writeFile(
      elfPath,
      Buffer.concat([elfHeader, words([lui(4, 0x0045), daddiu(4, 4, 0x1234)])]),
    );

    // Build minimal MWo3 overlay loaded at 0x00814e00 (code starts at +0x40 -> 0x00814e40)
    const mwo3Header = Buffer.alloc(0x40, 0);
    mwo3Header.write("MWo3", 0, "ascii");
    mwo3Header.writeUInt32LE(0x00814e00, 0x08);
    mwo3Header.writeUInt32LE(8, 0x0c); // textSize = 8
    mwo3Header.writeUInt32LE(4, 0x10); // dataSize = 4
    await writeFile(
      mwo3Path,
      Buffer.concat([mwo3Header, words([jal(0x00100000), 0, 0x00451234])]),
    );

    const res = await new CodeReferenceService().find({
      files: [{ path: elfPath }, { path: mwo3Path }],
      targets: [{ address: "0x00451234" }, { address: "0x00100000" }],
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const report = resultOf(res.value);
    expect(
      report.files.map((f) => [f.load_address, f.load_address_source]),
    ).toEqual([
      ["0x00100000", "elf32-le-header"],
      ["0x00814e40", "mwo3-header"],
    ]);
    expect(report.total_references).toBe(3);
  });

  it("scans all PT_LOAD segments in a multi-segment ELF32-LE and resolves call arguments", async () => {
    const elfPath = join(directory, "MULTI_SEG.ELF");
    const addiu = (rt: number, rs: number, imm: number) =>
      ((9 << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)) >>> 0;

    // ELF header + 2 program headers (0x34 + 64 = 0x74; pad to 0x100)
    const header = Buffer.alloc(0x100, 0);
    header.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
    header.writeUInt16LE(2, 0x10);
    header.writeUInt16LE(8, 0x12);
    header.writeUInt32LE(0x34, 0x1c); // e_phoff
    header.writeUInt16LE(32, 0x2a); // e_phentsize
    header.writeUInt16LE(2, 0x2c); // e_phnum = 2
    // Segment 0 (.text): offset 0x100, vaddr 0x00100000, filesz 16
    header.writeUInt32LE(1, 0x34);
    header.writeUInt32LE(0x100, 0x38);
    header.writeUInt32LE(0x00100000, 0x3c);
    header.writeUInt32LE(16, 0x44);
    // Segment 1 (.data): offset 0x110, vaddr 0x00450000, filesz 8
    header.writeUInt32LE(1, 0x54);
    header.writeUInt32LE(0x110, 0x58);
    header.writeUInt32LE(0x00450000, 0x5c);
    header.writeUInt32LE(8, 0x64);

    const seg0 = words([
      lui(4, 0x0045),
      addiu(4, 4, 0x0004),
      jal(0x00100500),
      0,
    ]);
    const seg1 = words([0x00100500, 0xdeadbeef]);
    await writeFile(elfPath, Buffer.concat([header, seg0, seg1]));

    const res = await new CodeReferenceService().find({
      files: [{ path: elfPath }],
      targets: [{ address: "0x00100500" }],
      resolve_call_arguments: true,
      include_caller_signatures: true,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const report = resultOf(res.value);
    // Both PT_LOAD segments are scanned: jal in seg0 and pointer_word in seg1!
    expect(report.files).toHaveLength(2);
    expect(report.total_references).toBe(2);
    const callHit = report.references.find((r) => r.kind === "call");
    const ptrHit = report.references.find((r) => r.kind === "pointer_word");
    expect(callHit?.call_arguments).toEqual({ a0: "0x00450004" });
    expect(callHit?.caller_signature).toBeTypeOf("string");
    expect(ptrHit?.address).toBe("0x00450000");
  });
});
