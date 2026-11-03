/**
 * Synthetic DOS real-mode programs for scanner tests. The MZ program has a
 * 32-byte header, a code segment at paragraph 0 and a data segment at
 * paragraph 0x10 (module offset 0x100). Segment words in the file are
 * relative to the load module; the relocation table lists each of them.
 */

export interface MzProgramOptions {
  /** Module bytes (code and data) placed after the header. */
  readonly module: Uint8Array;
  /** Module offsets of segment words the loader relocates. */
  readonly relocations: readonly number[];
  readonly entrySegment?: number;
  readonly entryOffset?: number;
  /** Bytes appended after the load module (an overlay). */
  readonly overlay?: Uint8Array;
}

export const buildMzProgram = (options: MzProgramOptions): Buffer => {
  const relocationTable = 0x1c;
  const headerBytes =
    Math.ceil((relocationTable + options.relocations.length * 4) / 16) * 16;
  const imageBytes = headerBytes + options.module.length;
  const header = Buffer.alloc(headerBytes);
  header.write("MZ", 0, "latin1");
  header.writeUInt16LE(imageBytes % 512, 2);
  header.writeUInt16LE(Math.ceil(imageBytes / 512), 4);
  header.writeUInt16LE(options.relocations.length, 6);
  header.writeUInt16LE(headerBytes / 16, 8);
  header.writeUInt16LE(0xffff, 0x0c);
  header.writeUInt16LE(options.entryOffset ?? 0, 0x14);
  header.writeUInt16LE(options.entrySegment ?? 0, 0x16);
  header.writeUInt16LE(relocationTable, 0x18);
  options.relocations.forEach((moduleOffset, index) => {
    // Express each site as segment:offset with the smallest offset.
    header.writeUInt16LE(moduleOffset % 16, relocationTable + index * 4);
    header.writeUInt16LE(
      Math.floor(moduleOffset / 16),
      relocationTable + index * 4 + 2,
    );
  });
  return Buffer.concat([
    header,
    Buffer.from(options.module),
    Buffer.from(options.overlay ?? new Uint8Array()),
  ]);
};

/** Data segment paragraph inside the sample module. */
export const SAMPLE_DATA_PARAGRAPH = 0x10;

/**
 * mov ax,seg data / mov ds,ax / mov dx,offset hello / call far menu, with
 * "HELLO$", "BYE$" and "MENU$" in the data segment, a far pointer table at
 * data:0x20 and a near pointer table at data:0x30.
 */
export const sampleMzProgram = (overlay?: Uint8Array): Buffer => {
  const module = Buffer.alloc(0x140, 0x90);
  // 0x00: mov ax, seg data        (relocated word at 0x01)
  module.set([0xb8, SAMPLE_DATA_PARAGRAPH, 0x00], 0x00);
  // 0x03: mov ds, ax
  module.set([0x8e, 0xd8], 0x03);
  // 0x05: mov dx, offset hello
  module.set([0xba, 0x00, 0x00], 0x05);
  // 0x08: call far 0000:0040      (relocated segment word at 0x0b)
  module.set([0x9a, 0x40, 0x00, 0x00, 0x00], 0x08);
  // 0x0d: mov ax, 4c00h ; int 21h
  module.set([0xb8, 0x00, 0x4c, 0xcd, 0x21], 0x0d);
  module[0x40] = 0xcb; // retf
  const data = SAMPLE_DATA_PARAGRAPH * 16;
  module.write("HELLO$", data + 0x00, "latin1");
  module.write("BYE$\0", data + 0x08, "latin1");
  module.write("MENU$\0", data + 0x10, "latin1");
  module.fill(0, data + 0x16, data + 0x20);
  // Far pointers (offset, segment) to the three strings.
  [0x00, 0x08, 0x10].forEach((offset, index) => {
    module.writeUInt16LE(offset, data + 0x20 + index * 4);
    module.writeUInt16LE(SAMPLE_DATA_PARAGRAPH, data + 0x22 + index * 4);
  });
  // Near pointers (offsets in the data segment).
  [0x00, 0x08, 0x10].forEach((offset, index) => {
    module.writeUInt16LE(offset, data + 0x30 + index * 2);
  });
  return buildMzProgram({
    module,
    relocations: [0x01, 0x0b, data + 0x22, data + 0x26, data + 0x2a],
    ...(overlay === undefined ? {} : { overlay }),
  });
};
