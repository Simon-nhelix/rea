/** A `lui $gp` + `addiu/ori $gp, $gp` initializer found in a region. */
export interface GpInitializer {
  readonly value: number;
  readonly address: number;
  readonly fileOffset: number;
}

/** First `lui $gp, X` followed within four words by addiu/ori $gp, $gp, Y. */
export const findGpInitializer = (region: {
  readonly bytes: Uint8Array;
  readonly fileOffset: number;
  readonly length: number;
  readonly address: number;
}): GpInitializer | undefined => {
  const view = new DataView(
    region.bytes.buffer,
    region.bytes.byteOffset,
    region.bytes.byteLength,
  );
  const skip = (4 - (region.address % 4)) % 4;
  for (let rel = skip; rel + 4 <= region.length; rel += 4) {
    const word = view.getUint32(region.fileOffset + rel, true);
    if (word >>> 26 !== 0x0f || ((word >>> 16) & 31) !== 28) continue;
    const high = (word & 0xffff) << 16;
    for (let k = 1; k <= 4 && rel + 4 * (k + 1) <= region.length; k++) {
      const next = view.getUint32(region.fileOffset + rel + 4 * k, true);
      const op = next >>> 26;
      const sameGp = ((next >>> 21) & 31) === 28 && ((next >>> 16) & 31) === 28;
      if (!sameGp || (op !== 9 && op !== 0x0d)) continue;
      const low = next & 0xffff;
      return {
        value: (op === 0x0d ? high | low : high + ((low << 16) >> 16)) >>> 0,
        address: (region.address + rel) >>> 0,
        fileOffset: region.fileOffset + rel,
      };
    }
  }
  return undefined;
};
