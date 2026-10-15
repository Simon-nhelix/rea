/** Self-authored LoROM: a real call, a data load, and opcode-shaped non-code. */
export function createSnesXrefFixture() {
  const rom = Buffer.alloc(0x8000, 0xff);
  // CLC; XCE; REP #$30; JSL $808100; BRA to itself.
  Buffer.from("18fbc2302200818080fe", "hex").copy(rom);
  Buffer.from("af0082806b", "hex").copy(rom, 0x100); // LDA.l $808200; RTL
  rom.write("HELLO_LOCALIZATION\0", 0x200, "ascii");
  rom.write("SECOND_STRING\0", 0x220, "ascii");
  rom.write("THIRD_STRING\0", 0x240, "ascii");
  Buffer.from("22008180", "hex").copy(rom, 0x300); // data, not an executed call
  Buffer.from("008280208280408280", "hex").copy(rom, 0x400);
  rom.fill(0x20, 0x7fc0, 0x7fd5);
  rom.write("REA STATIC XREF TEST", 0x7fc0, "ascii");
  rom[0x7fd5] = 0x20;
  rom.writeUInt16LE(0xffff, 0x7fdc);
  rom.writeUInt16LE(0x0000, 0x7fde);
  rom.writeUInt16LE(0x8000, 0x7ffc);
  return rom;
}
