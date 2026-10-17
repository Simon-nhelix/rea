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
});
