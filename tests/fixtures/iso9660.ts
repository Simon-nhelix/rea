/** Independent ISO9660 fixture with optional directory/path-table allocations between files. */
export const iso9660Fixture = (
  options: { extentBase?: number; nested?: boolean } = {},
): Buffer => {
  const image = Buffer.alloc(30 * 2048);
  const base = options.extentBase ?? 0;
  const descriptor = 16 * 2048;
  image[descriptor] = 1;
  image.write("CD001", descriptor + 1, "ascii");
  image[descriptor + 6] = 1;
  image.write("PLAYSTATION", descriptor + 8, "ascii");
  image.write("TEST_DISC", descriptor + 40, "ascii");
  image.writeUInt32LE(30, descriptor + 80);
  image.writeUInt32BE(30, descriptor + 84);
  image[17 * 2048] = 255;
  image.write("CD001", 17 * 2048 + 1, "ascii");
  image[17 * 2048 + 6] = 1;
  const entry = (
    pos: number,
    sector: number,
    size: number,
    flags: number,
    name: string,
  ): number => {
    const bytes = Buffer.from(name, "latin1");
    const length = 33 + bytes.length + (bytes.length % 2 === 0 ? 1 : 0);
    image[pos] = length;
    image.writeUInt32LE(base + sector, pos + 2);
    image.writeUInt32BE(base + sector, pos + 6);
    image.writeUInt32LE(size, pos + 10);
    image.writeUInt32BE(size, pos + 14);
    image[pos + 25] = flags;
    image.writeUInt16LE(1, pos + 28);
    image.writeUInt16BE(1, pos + 30);
    image[pos + 32] = bytes.length;
    bytes.copy(image, pos + 33);
    return pos + length;
  };
  entry(descriptor + 156, 18, 2048, 2, "\x00");
  let cursor = entry(18 * 2048, 18, 2048, 2, "\x00");
  cursor = entry(cursor, 18, 2048, 2, "\x01");
  cursor = entry(cursor, 20, 42, 0, "SYSTEM.CNF;1");
  cursor = entry(cursor, 24, 3000, 0, "MAIN.EXE;1");
  image.write("BOOT = cdrom:\\MAIN.EXE;1\r\n", 20 * 2048, "ascii");
  if (options.nested) {
    entry(cursor, 22, 2048, 2, "TEXT");
    cursor = entry(22 * 2048, 22, 2048, 2, "\x00");
    cursor = entry(cursor, 18, 2048, 2, "\x01");
    entry(cursor, 26, 2048, 0, "DIALOG.BIN;1");
  }
  const pathSize = options.nested ? 22 : 10;
  const littleSector = options.nested ? 21 : 19;
  const bigSector = options.nested ? 23 : 21;
  image.writeUInt32LE(pathSize, descriptor + 132);
  image.writeUInt32BE(pathSize, descriptor + 136);
  image.writeUInt32LE(base + littleSector, descriptor + 140);
  image.writeUInt32BE(base + bigSector, descriptor + 148);
  for (const [sector, bigEndian] of [
    [littleSector, false],
    [bigSector, true],
  ] as const) {
    const start = sector * 2048;
    image[start] = 1;
    if (options.nested) image[start + 10] = 4;
    if (bigEndian) {
      image.writeUInt32BE(base + 18, start + 2);
      image.writeUInt16BE(1, start + 6);
      if (options.nested) {
        image.writeUInt32BE(base + 22, start + 12);
        image.writeUInt16BE(1, start + 16);
      }
    } else {
      image.writeUInt32LE(base + 18, start + 2);
      image.writeUInt16LE(1, start + 6);
      if (options.nested) {
        image.writeUInt32LE(base + 22, start + 12);
        image.writeUInt16LE(1, start + 16);
      }
    }
    if (options.nested) image.write("TEXT", start + 18, "ascii");
  }
  return image;
};
