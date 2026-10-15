/** Self-authored HuCard for bounded romlab/Ghidra CPU comparisons. */
export const pcePrimitiveCases = [
  { id: "t-adc", hex: "f46900", count: 2, a: 0x55, p: 1, memory: "7f" },
  { id: "t-and", hex: "f4290f", count: 2, a: 0x55, memory: "f0" },
  { id: "t-eor", hex: "f449ff", count: 2, a: 0x55, memory: "80" },
  { id: "t-ora", hex: "f40980", count: 2, a: 0x55, memory: "01" },
  { id: "t-sbc", hex: "f4e901", count: 2, a: 0x55, p: 1, memory: "80" },
  { id: "t-consumed", hex: "f4ea6901", count: 3, a: 0x55, memory: "7f" },
  { id: "decimal-adc", hex: "6900", count: 1, a: 0x99, p: 0x49 },
  { id: "decimal-sbc", hex: "e901", count: 1, a: 0, p: 0x49 },
  { id: "trb", hex: "1410", count: 1, a: 0xc0, memory: "c0" },
  { id: "tsb", hex: "0410", count: 1, a: 0x80, memory: "00" },
  { id: "bit-immediate", hex: "8900", count: 1, a: 0xff, p: 0xc0 },
  { id: "cla", hex: "62", count: 1, a: 0xff, p: 0xc1 },
  { id: "tii-overlap", hex: "73102011200300", count: 1, memory: "11223344" },
  { id: "tdd", hex: "c3132023200300", count: 1, memory: "11223344" },
  { id: "tin", hex: "d3102020200300", count: 1, memory: "11223344" },
  { id: "tia", hex: "e3102020200300", count: 1, memory: "11223344" },
  { id: "tai", hex: "f3102020200300", count: 1, memory: "11223344" },
].map((item, index) => ({
  address: 0xe100 + index * 0x20,
  a: 0,
  x: 0x10,
  y: 0,
  p: 0,
  ...item,
}));

export function createPcePrimitiveFixture() {
  const rom = Buffer.alloc(0x2000, 0xea);
  // SEI; CLD; LDX #$ff; TXS; map IO and RAM; idle at $e00d.
  Buffer.from("78d8a2ff9aa9ff5301a9f8530280fe", "hex").copy(rom);
  for (const test of pcePrimitiveCases) {
    const code = Buffer.from(`${test.hex}80fe`, "hex");
    code.copy(rom, test.address - 0xe000);
  }
  for (let offset = 0x1ff6; offset < 0x2000; offset += 2)
    rom.writeUInt16LE(0xe000, offset);
  return rom;
}
