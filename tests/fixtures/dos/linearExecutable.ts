/**
 * Synthetic DOS extender LE/LX executables for parser, admission and scanner
 * tests. Layout follows Watcom wlink: MZ stub, LE/LX header at e_lfanew,
 * object table, page map, fixup page table, fixup records, then data pages at
 * an absolute file offset. Fixup sites hold zero bytes in the file.
 */

export interface FixtureFixup {
  /** Offset of the source field inside its object. */
  readonly sourceOffset: number;
  /** 0x07 offset32, 0x08 relative32, 0x05 offset16, 0x06 pointer16_32. */
  readonly sourceType: number;
  readonly targetObject: number;
  readonly targetOffset: number;
}

export interface FixtureObject {
  readonly base: number;
  /** Virtual size; defaults to the byte length. */
  readonly virtualSize?: number;
  readonly bytes: Uint8Array;
  readonly executable: boolean;
  readonly writable: boolean;
  readonly fixups?: readonly FixtureFixup[];
}

export interface LinearFixtureOptions {
  readonly signature?: "LE" | "LX";
  readonly pageSize?: number;
  readonly objects: readonly FixtureObject[];
  readonly entryObject: number;
  readonly entryOffset: number;
  /**
   * Prefix the program with a second "extender" MZ image and leave e_lfanew
   * of the first stub at zero, as a bound extender stub does.
   */
  readonly bound?: boolean;
}

const mzStub = (imageBytes: number, lfanew: number): Buffer => {
  const stub = Buffer.alloc(Math.max(imageBytes, 0x40));
  stub.write("MZ", 0, "latin1");
  stub.writeUInt16LE(imageBytes % 512, 2);
  stub.writeUInt16LE(Math.ceil(imageBytes / 512), 4);
  stub.writeUInt16LE(0, 6);
  stub.writeUInt16LE(4, 8); // 64-byte header
  stub.writeUInt16LE(0x40, 24);
  stub.writeUInt32LE(lfanew, 0x3c);
  // mov ax,4c01h ; int 21h
  Buffer.from([0xb8, 0x01, 0x4c, 0xcd, 0x21]).copy(stub, 0x40);
  return stub;
};

export const buildLinearExecutable = (
  options: LinearFixtureOptions,
): Buffer => {
  const signature = options.signature ?? "LE";
  const pageSize = options.pageSize ?? 0x1000;
  const objects = options.objects;
  const pagesOf = (object: FixtureObject) =>
    Math.ceil(object.bytes.length / pageSize);
  const totalPages = objects.reduce((sum, o) => sum + pagesOf(o), 0);

  const stubBytes = 0x80;
  const headerSize = 0xc4;
  const objectTable = headerSize;
  const pageMap = objectTable + objects.length * 24;
  const mapEntry = signature === "LE" ? 4 : 8;
  const fixupPageTable = pageMap + totalPages * mapEntry;
  // Fixup records per logical page.
  const pageRecords: Buffer[] = [];
  objects.forEach((object) => {
    const pages = pagesOf(object);
    for (let page = 0; page < pages; page++) {
      const records: Buffer[] = [];
      for (const fixup of object.fixups ?? []) {
        const pageStart = page * pageSize;
        if (
          fixup.sourceOffset < pageStart ||
          fixup.sourceOffset >= pageStart + pageSize
        )
          continue;
        const wide = fixup.targetOffset > 0xffff;
        const record = Buffer.alloc(wide ? 9 : 7);
        record[0] = fixup.sourceType;
        record[1] = wide ? 0x10 : 0x00;
        record.writeInt16LE(fixup.sourceOffset - pageStart, 2);
        record[4] = fixup.targetObject;
        if (wide) record.writeUInt32LE(fixup.targetOffset, 5);
        else record.writeUInt16LE(fixup.targetOffset, 5);
        records.push(record);
      }
      pageRecords.push(Buffer.concat(records));
    }
  });
  const fixupRecordTable = fixupPageTable + (totalPages + 1) * 4;
  const recordsLength = pageRecords.reduce((s, r) => s + r.length, 0);
  const tablesEnd = fixupRecordTable + recordsLength;
  const program = stubBytes;
  const headerAt = program;
  const dataPages = Math.ceil((headerAt + tablesEnd) / 16) * 16;
  const lastPageBytes =
    objects.length === 0
      ? 0
      : objects[objects.length - 1]!.bytes.length % pageSize || pageSize;

  const file = Buffer.alloc(dataPages + totalPages * pageSize);
  mzStub(stubBytes, headerAt).copy(file, 0);
  const header = file.subarray(headerAt);
  header.write(signature, 0, "latin1");
  header.writeUInt16LE(2, 0x08); // 386
  header.writeUInt16LE(1, 0x0a);
  header.writeUInt32LE(totalPages, 0x14);
  header.writeUInt32LE(options.entryObject, 0x18);
  header.writeUInt32LE(options.entryOffset, 0x1c);
  header.writeUInt32LE(objects.length, 0x20);
  header.writeUInt32LE(0x100, 0x24);
  header.writeUInt32LE(pageSize, 0x28);
  header.writeUInt32LE(signature === "LE" ? lastPageBytes : 0, 0x2c);
  header.writeUInt32LE(tablesEnd - fixupPageTable, 0x30);
  header.writeUInt32LE(fixupPageTable - headerSize, 0x38);
  header.writeUInt32LE(objectTable, 0x40);
  header.writeUInt32LE(objects.length, 0x44);
  header.writeUInt32LE(pageMap, 0x48);
  header.writeUInt32LE(fixupPageTable, 0x68);
  header.writeUInt32LE(fixupRecordTable, 0x6c);
  header.writeUInt32LE(dataPages, 0x80);

  let logical = 1;
  let filePage = 0;
  let recordOffset = 0;
  objects.forEach((object, index) => {
    const entry = header.subarray(objectTable + index * 24);
    const pages = pagesOf(object);
    entry.writeUInt32LE(object.virtualSize ?? object.bytes.length, 0);
    entry.writeUInt32LE(object.base, 4);
    entry.writeUInt32LE(
      0x1 |
        (object.writable ? 0x2 : 0) |
        (object.executable ? 0x4 : 0) |
        0x2000,
      8,
    );
    entry.writeUInt32LE(logical, 12);
    entry.writeUInt32LE(pages, 16);
    for (let page = 0; page < pages; page++) {
      const map = header.subarray(pageMap + (logical - 1) * mapEntry);
      const physical = filePage + 1;
      if (signature === "LE") {
        map[0] = (physical >> 16) & 0xff;
        map[1] = (physical >> 8) & 0xff;
        map[2] = physical & 0xff;
        map[3] = 0;
      } else {
        map.writeUInt32LE(filePage * pageSize, 0);
        map.writeUInt16LE(
          Math.min(pageSize, object.bytes.length - page * pageSize),
          4,
        );
        map.writeUInt16LE(0, 6);
      }
      header.writeUInt32LE(recordOffset, fixupPageTable + (logical - 1) * 4);
      const records = pageRecords[logical - 1]!;
      records.copy(header, fixupRecordTable + recordOffset);
      recordOffset += records.length;
      Buffer.from(
        object.bytes.subarray(page * pageSize, (page + 1) * pageSize),
      ).copy(file, dataPages + filePage * pageSize);
      logical++;
      filePage++;
    }
  });
  header.writeUInt32LE(recordOffset, fixupPageTable + totalPages * 4);
  const trimmed = file.subarray(
    0,
    dataPages + (totalPages - 1) * pageSize + lastPageBytes,
  );
  if (!options.bound) return Buffer.from(trimmed);
  // A bound extender: its own MZ image first, e_lfanew zero, then the program.
  const extender = mzStub(0x200, 0);
  return Buffer.concat([extender, trimmed]);
};

/** Strings, a pointer table and code that references them through fixups. */
export const sampleLinearProgram = (
  options: Partial<LinearFixtureOptions> = {},
): Buffer => {
  const code = Buffer.alloc(0x40, 0x90);
  // 0x00: mov eax, offset hello      (fixup at 0x01)
  code.set([0xb8, 0, 0, 0, 0], 0x00);
  // 0x05: push offset bye            (fixup at 0x06)
  code.set([0x68, 0, 0, 0, 0], 0x05);
  // 0x0a: mov esi, [table + ebx*4]   (fixup at 0x0d)
  code.set([0x8b, 0x34, 0x9d, 0, 0, 0, 0], 0x0a);
  // 0x11: call near 0x20 in the same object (no fixup)
  code.set([0xe8, 0x0a, 0, 0, 0], 0x11);
  // 0x16: ret
  code[0x16] = 0xc3;
  code[0x20] = 0xc3;
  const data = Buffer.alloc(0x40);
  data.write("HELLO\0", 0x00, "latin1");
  data.write("BYE\0", 0x08, "latin1");
  data.write("MENU\0", 0x10, "latin1");
  // Pointer table at 0x20: zero bytes in the file, filled by fixups.
  return buildLinearExecutable({
    objects: [
      {
        base: 0x10000,
        bytes: code,
        executable: true,
        writable: false,
        fixups: [
          {
            sourceOffset: 0x01,
            sourceType: 0x07,
            targetObject: 2,
            targetOffset: 0x00,
          },
          {
            sourceOffset: 0x06,
            sourceType: 0x07,
            targetObject: 2,
            targetOffset: 0x08,
          },
          {
            sourceOffset: 0x0d,
            sourceType: 0x07,
            targetObject: 2,
            targetOffset: 0x20,
          },
        ],
      },
      {
        base: 0x20000,
        virtualSize: 0x2000,
        bytes: data,
        executable: false,
        writable: true,
        fixups: [
          {
            sourceOffset: 0x20,
            sourceType: 0x07,
            targetObject: 2,
            targetOffset: 0x00,
          },
          {
            sourceOffset: 0x24,
            sourceType: 0x07,
            targetObject: 2,
            targetOffset: 0x08,
          },
          {
            sourceOffset: 0x28,
            sourceType: 0x07,
            targetObject: 2,
            targetOffset: 0x10,
          },
        ],
      },
    ],
    entryObject: 1,
    entryOffset: 0,
    ...options,
  });
};
