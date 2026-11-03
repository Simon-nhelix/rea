import { describe, expect, it } from "vitest";
import {
  DOS_REAL_MODE_LOAD_SEGMENT,
  dosFarPointerLinearAddress,
  dosRealModeFileOffset,
  dosRealModeLinearAddress,
  dosRealModeRelocatedFileBytes,
  parseDosRealModeImage,
} from "./dosRealModeImage.js";
import { sampleMzProgram } from "../../tests/fixtures/dos/realMode.js";

describe("DOS real-mode load coordinates", () => {
  it("places an MZ load module at segment 0x1000 and relocates segment words", () => {
    const file = sampleMzProgram(Buffer.from("OVERLAY"));
    const parsed = parseDosRealModeImage("dos-mz", file);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const image = parsed.value;
    expect(image).toMatchObject({
      loadSegment: DOS_REAL_MODE_LOAD_SEGMENT,
      moduleFileOffset: 0x30,
      moduleBytes: 0x140,
      moduleLinearAddress: 0x10000,
      entry: { segment: 0x1000, offset: 0, linearAddress: 0x10000 },
      overlayBytes: 7,
    });
    expect(image.relocations[0]).toEqual({
      fileOffset: 0x31,
      linearAddress: 0x10001,
    });
    // Header and overlay bytes have no address.
    expect(dosRealModeLinearAddress(image, 0x10)).toBeNull();
    expect(dosRealModeLinearAddress(image, file.length - 1)).toBeNull();
    expect(dosRealModeFileOffset(image, 0x10100)).toBe(0x130);
    expect(dosRealModeLinearAddress(image, 0x130)).toBe(0x10100);

    const loaded = dosRealModeRelocatedFileBytes(file, image);
    expect(loaded.readUInt16LE(0x31)).toBe(0x1010);
    const far = loaded.readUInt32LE(0x130 + 0x24);
    expect(far >>> 16).toBe(0x1010);
    expect(dosFarPointerLinearAddress(far)).toBe(0x10108);
    // The source buffer keeps module-relative segment words.
    expect(file.readUInt16LE(0x31)).toBe(0x10);
  });

  it("places a COM image after the program segment prefix", () => {
    const file = Buffer.from([0xb4, 0x09, 0xcd, 0x21, 0xc3]);
    const parsed = parseDosRealModeImage("dos-com", file);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.moduleLinearAddress).toBe(0x10100);
    expect(dosRealModeFileOffset(parsed.value, 0x10102)).toBe(2);
    expect(dosRealModeFileOffset(parsed.value, 0x10000)).toBeNull();
  });
});
