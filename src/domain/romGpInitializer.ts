/** A `lui $gp` + `addiu/ori $gp, $gp` initializer found in a region. */
export interface GpInitializer {
  readonly value: number;
  readonly address: number;
  readonly fileOffset: number;
}

/**
 * First `lui $gp, X` followed within four words by `addiu/daddiu/ori $gp, $gp, Y`,
 * or PS2 crt0 `lui $r, X` + `addiu/daddiu/ori $r, $r, Y` + `move $gp, $r`.
 */
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
    if (word >>> 26 !== 0x0f || ((word >>> 21) & 31) !== 0) continue;
    const rt = (word >>> 16) & 31;
    const high = (word & 0xffff) << 16;
    if (rt === 28) {
      for (let k = 1; k <= 4 && rel + 4 * (k + 1) <= region.length; k++) {
        const next = view.getUint32(region.fileOffset + rel + 4 * k, true);
        const op = next >>> 26;
        const sameGp =
          ((next >>> 21) & 31) === 28 && ((next >>> 16) & 31) === 28;
        if (!sameGp || (op !== 9 && op !== 0x19 && op !== 0x0d)) continue;
        const low = next & 0xffff;
        return {
          value: (op === 0x0d ? high | low : high + ((low << 16) >> 16)) >>> 0,
          address: (region.address + rel) >>> 0,
          fileOffset: region.fileOffset + rel,
        };
      }
    } else if (rt !== 0) {
      // PS2 crt0 pattern: lui $r, hi ... addiu/daddiu/ori $r, $r, lo ... move $gp, $r
      let formed: number | undefined;
      for (let k = 1; k <= 12 && rel + 4 * (k + 1) <= region.length; k++) {
        const next = view.getUint32(region.fileOffset + rel + 4 * k, true);
        const op = next >>> 26;
        const nrs = (next >>> 21) & 31;
        const nrt = (next >>> 16) & 31;
        const nrd = (next >>> 11) & 31;
        const funct = next & 63;
        if (
          formed === undefined &&
          nrs === rt &&
          nrt === rt &&
          (op === 9 || op === 0x19 || op === 0x0d)
        ) {
          const low = next & 0xffff;
          formed =
            (op === 0x0d ? high | low : high + ((low << 16) >> 16)) >>> 0;
          continue;
        }
        if (
          formed !== undefined &&
          op === 0 &&
          nrs === rt &&
          nrt === 0 &&
          nrd === 28 &&
          (funct === 0x21 || funct === 0x25 || funct === 0x2d)
        ) {
          return {
            value: formed,
            address: (region.address + rel) >>> 0,
            fileOffset: region.fileOffset + rel,
          };
        }
        // Stop tracking if $r is overwritten before moving to $gp
        if (
          (op === 0 && nrd === rt) ||
          (op !== 0 && nrt === rt && !(nrs === rt && formed !== undefined))
        ) {
          break;
        }
      }
    }
  }
  return undefined;
};
