import { describe, expect, it } from "vitest";

import {
  analysisSnapshotSchema,
  snapshotTarget,
} from "../../domain/analysisSnapshot.js";
import type {
  BinaryTarget,
  ConsoleBinaryTarget,
} from "../../domain/binaryTargetTypes.js";
import type {
  ConsoleArchitecture,
  ConsoleTargetFormat,
} from "../../domain/consoleRom.js";
import { executableFormatHintSchema } from "../../domain/dosCom.js";
import { createEvidence, parseEvidence } from "../../domain/evidence.js";
import {
  createImmutableEvidenceBundle,
  parseEvidenceBundle,
} from "../../domain/evidenceBundle.js";
import { binaryTargetSummary } from "./BinaryTargetSummary.js";

/**
 * One admitted target per format. A format added to `BinaryTarget` fails
 * compilation here until it has a fixture, and the cases below then require
 * every vocabulary that persists or projects targets to accept it. This guards
 * the failure class of #7290 until target formats have a single owner.
 */
type TargetFixtures = {
  readonly [Format in BinaryTarget["format"]]: BinaryTarget & {
    readonly format: Format;
  };
};

const identity = { path: "/fixture/target", sha256: "a".repeat(64) } as const;
const archive = { ...identity, kind: "archive" } as const;
const artifact = { ...identity, kind: "artifact" } as const;

const consoleTarget = <Format extends ConsoleTargetFormat>(
  format: Format,
  architecture: ConsoleArchitecture,
): ConsoleBinaryTarget & { readonly format: Format } => ({
  ...identity,
  kind: "executable",
  format,
  architecture,
  availableArchitectures: [architecture],
  entryPoint: "0x1000",
  entryPointSource: "0x1000",
  consoleRom: {
    format,
    architecture,
    ghidraLanguageId: "fixture",
    compilerSpecId: "default",
    loader: "BinaryLoader",
    loadBase: "0x1000",
    entryPoint: "0x1000",
    entryPointSource: "0x1000",
    fileMappings: [],
    memoryRegions: [],
    romMetadata: {},
  },
});

const TARGETS: TargetFixtures = {
  "mach-o": {
    ...identity,
    kind: "executable",
    format: "mach-o",
    architecture: "arm64",
    availableArchitectures: ["arm64"],
  },
  "mach-o-universal": {
    ...identity,
    kind: "executable",
    format: "mach-o-universal",
    architecture: "arm64",
    availableArchitectures: ["x86_64", "arm64"],
    universalSlice: { offset: 0x4000, size: 0x4000 },
  },
  elf: {
    ...identity,
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  },
  pe: {
    ...identity,
    kind: "executable",
    format: "pe",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
    executableRole: "application",
    managed: false,
  },
  "dos-mz": {
    ...identity,
    kind: "executable",
    format: "dos-mz",
    architecture: "x86",
    availableArchitectures: ["x86"],
  },
  "dos-com": {
    ...identity,
    kind: "executable",
    format: "dos-com",
    architecture: "x86",
    availableArchitectures: ["x86"],
  },
  // A raw-only family: detected formats must not admit it.
  "raw-binary": {
    ...identity,
    kind: "executable",
    format: "raw-binary",
    architecture: "m68k",
    availableArchitectures: ["m68k"],
    entryPoint: "0x1000",
    entryPointSource: "0x1000",
    loadAddress: "0x1000",
    loadAddressSource: "0x1000",
  },
  "gamecube-dol": {
    ...identity,
    kind: "executable",
    format: "gamecube-dol",
    architecture: "powerpc",
    availableArchitectures: ["powerpc"],
    byteOrder: "big",
    bits: 32,
    entryPoint: "0x80003100",
    entryPointSource: "dol-header",
    dol: {
      sections: [],
      bss: { address: 0, size: 0 },
      bssOverlaps: [],
      bssGaps: [],
      entryPoint: 0x8000_3100,
    },
  },
  "analysis-database": {
    ...identity,
    kind: "database",
    format: "analysis-database",
  },
  zip: { ...archive, format: "zip" },
  ipa: { ...archive, format: "ipa" },
  apk: { ...archive, format: "apk" },
  msix: { ...archive, format: "msix" },
  appx: { ...archive, format: "appx" },
  hap: { ...archive, format: "hap" },
  hsp: { ...archive, format: "hsp" },
  "app-pack": { ...archive, format: "app-pack" },
  asar: { ...archive, format: "asar" },
  ines: { ...archive, format: "ines" },
  "godot-pck": { ...archive, format: "godot-pck" },
  unityfs: { ...archive, format: "unityfs" },
  uimage: { ...archive, format: "uimage" },
  uf2: { ...archive, format: "uf2" },
  dfuse: { ...archive, format: "dfuse" },
  dmg: { ...archive, format: "dmg" },
  pkg: { ...archive, format: "pkg" },
  "intel-hex": { ...archive, format: "intel-hex" },
  srec: { ...archive, format: "srec" },
  "esp-image": { ...archive, format: "esp-image" },
  "esp-flash-image": {
    ...archive,
    format: "esp-flash-image",
    espFlash: { selected: true, flashOffset: null, partitionTableOffset: null },
  },
  gba: consoleTarget("gba", "arm"),
  "psx-exe": consoleTarget("psx-exe", "r3000"),
  "ps2-elf": consoleTarget("ps2-elf", "r5900"),
  psp: consoleTarget("psp", "allegrex"),
  ps3: consoleTarget("ps3", "cell-ppu"),
  xbox: consoleTarget("xbox", "xenon"),
  "dc-bin": consoleTarget("dc-bin", "sh4"),
  saturn: consoleTarget("saturn", "sh2"),
  nds: consoleTarget("nds", "arm"),
  md: consoleTarget("md", "68000"),
  pce: consoleTarget("pce", "6502"),
  "gc-dol": consoleTarget("gc-dol", "gekko"),
  snes: consoleTarget("snes", "65816"),
  nes: consoleTarget("nes", "6502"),
  gb: consoleTarget("gb", "sm83"),
  wsc: consoleTarget("wsc", "x86"),
  n64: consoleTarget("n64", "r4300"),
  "dos-le": consoleTarget("dos-le", "x86"),
  fit: { ...archive, format: "fit" },
  plist: { ...artifact, format: "plist" },
  javascript: { ...artifact, format: "javascript" },
  "source-map": { ...artifact, format: "source-map" },
};

const provider = { id: "fixture", name: "Fixture", version: "1" } as const;
const roundTrip = (value: unknown): unknown =>
  JSON.parse(JSON.stringify(value));

describe("target format vocabularies", () => {
  it.each(Object.values(TARGETS))(
    "persists and projects $format targets",
    (target) => {
      const evidence = createEvidence(target, provider, {
        operation: "fixture",
        parameters: {},
        result: { observed: true },
      });
      expect(parseEvidence(roundTrip(evidence)).subject).toMatchObject({
        format: target.format,
        architecture: target.architecture ?? null,
      });
      const bundle = createImmutableEvidenceBundle([evidence]);
      expect(parseEvidenceBundle(roundTrip(bundle)).artifacts).toEqual([
        {
          digest: { sha256: target.sha256 },
          format: target.format,
          architecture: target.architecture ?? null,
        },
      ]);
      expect(
        analysisSnapshotSchema.shape.target.parse(
          roundTrip(snapshotTarget(target)),
        ),
      ).toMatchObject({ format: target.format, kind: target.kind });
      expect(binaryTargetSummary(target)).toMatchObject({
        format: target.format,
        kind: target.kind,
      });
    },
  );

  it.each(executableFormatHintSchema.options)(
    "admits the caller-selected %s hint only as its own target format",
    (hint) => {
      // An ESP flash dump is the one caller-selected format read as an archive.
      expect(TARGETS[hint]).toMatchObject({
        format: hint,
        kind: hint === "esp-flash-image" ? "archive" : "executable",
      });
    },
  );
});
