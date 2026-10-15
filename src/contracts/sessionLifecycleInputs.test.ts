import { describe, expect, it } from "vitest";

import { openBinaryInputSchema } from "./sessionLifecycleInputs.js";

describe("open_binary raw-binary input contract", () => {
  it("accepts header detection without architecture", () => {
    expect(
      openBinaryInputSchema.safeParse({ path: "/tmp/fixture.bin" }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/legacy.com",
        format: "dos-com",
      }).success,
    ).toBe(true);
  });
  it("accepts raw-binary with architecture and entry", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(true);
  });
  it("rejects raw-binary without architecture or entry", () => {
    const parsed = openBinaryInputSchema.safeParse({
      path: "/tmp/ecu.bin",
      format: "raw-binary",
    });
    expect(parsed.success).toBe(false);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
      }).success,
    ).toBe(false);
  });
  it("rejects architecture without format=raw-binary", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(false);
  });
});

it("accepts separate raw HuC6280 load/entry and rejects load addresses on console targets", () => {
  expect(
    openBinaryInputSchema.safeParse({
      path: "/fixture/memory.bin",
      format: "raw-binary",
      architecture: "huc6280",
      load_address: "0x4000",
      entry_point: "0x6286",
    }).success,
  ).toBe(true);
  expect(
    openBinaryInputSchema.safeParse({
      path: "/fixture/game.pce",
      format: "pce",
      load_address: "0x4000",
    }).success,
  ).toBe(false);
});
